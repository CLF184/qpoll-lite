package com.qpoll.lite;

import java.util.ArrayList;
import java.util.List;

public final class PrechargeTest {
    private static final byte[] OK = PanelProtocol.hex("9000");
    private static final byte[] INFO = PanelProtocol.hex(
            "A007F0C72006000228A10700120030FFFFFFB10102B20114B30100C004201EA001C10401020304D107012000000000009000");
    private static final byte[] IMAGE = new byte[PanelProtocol.IMAGE_BYTES];

    private static final class Session implements PanelProtocol.Control, PanelProtocol.Transport {
        final PanelProtocol protocol = new PanelProtocol(this, this);
        final List<String> commands = new ArrayList<>();
        final List<String> events = new ArrayList<>();
        long time;
        long firstCommandAt = -1;
        long refreshAt = -1;
        long cancelAt = Long.MAX_VALUE;

        public long now() { return time; }
        public void sleep(long ms) { time += ms; }
        public void check() throws InterruptedException {
            if (time >= cancelAt) throw new InterruptedException("cancelled");
        }
        public void event(String kind, String message) { events.add(kind + "|" + message); }
        public byte[] exchange(byte[] command, int timeout) {
            if (firstCommandAt < 0) firstCommandAt = time;
            if ((command[1] & 255) == 0xD4) refreshAt = time;
            commands.add(PanelProtocol.toHex(command));
            return (command[1] & 255) == 0xD1 ? INFO : OK;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        for (boolean officialCheck : new boolean[]{false, true}) {
            Session baseline = new Session();
            require(baseline.protocol.write(IMAGE, officialCheck), "baseline refresh");
            for (int chargeMs : new int[]{0, 1000, 15000, 30000}) {
                Session session = new Session();
                require(session.protocol.write(IMAGE, officialCheck, chargeMs), "refresh after charging");
                require(session.commands.equals(baseline.commands), "identical APDUs in both check modes");
                require(session.firstCommandAt == 1000 + chargeMs, "charging precedes the first D1");
                require(session.time == baseline.time + chargeMs, "only charge time is added");
                int start = session.events.indexOf("WAIT|charging|0|" + chargeMs);
                int done = session.events.indexOf("WAIT_DONE|charging|" + chargeMs);
                int checking = session.events.indexOf("STAGE|checking|读取并校验屏幕规格");
                require(chargeMs == 0 ? start == -1 && done == -1 : start >= 0 && start < done && done < checking,
                        "charging timer starts and ends before D1 and is skipped at zero");
            }
        }

        for (int invalid : new int[]{-1, 30001}) {
            Session session = new Session();
            try {
                session.protocol.write(IMAGE, false, invalid);
                throw new AssertionError("invalid charge accepted");
            } catch (IllegalArgumentException expected) {
                require(session.commands.isEmpty() && session.time == 0, "invalid charge stops before waiting or APDUs");
            }
        }

        Session cancelled = new Session();
        cancelled.cancelAt = 550;
        try {
            cancelled.protocol.write(IMAGE, false, 30000);
            throw new AssertionError("charging continued after cancellation");
        } catch (InterruptedException expected) {
            require(cancelled.commands.isEmpty() && cancelled.time == 600, "charge cancellation stops before APDUs");
            require(!cancelled.events.contains("WAIT_DONE|charging|30000"), "cancelled charge is not reported complete");
        }
        System.out.println("PASS: pre-charge boundaries, event order, unchanged APDUs and cancellation");

        for (boolean officialCheck : new boolean[]{false, true}) {
            Session baseline = new Session();
            baseline.protocol.write(IMAGE, officialCheck, 0);
            require(baseline.time - baseline.refreshAt == (officialCheck ? 0 : 20000), "default hold duration");
            for (int seconds : new int[]{0, 1, 20, 60}) {
                Session session = new Session();
                session.protocol.write(IMAGE, officialCheck, 3000, seconds);
                require(session.commands.equals(baseline.commands), "hold duration does not change APDUs");
                require(session.refreshAt == baseline.refreshAt + 3000, "hold is independent of pre-charge");
                require(session.time - session.refreshAt == (officialCheck ? 0 : seconds * 1000L), "selected hold duration");
                long ticks = session.events.stream().filter(event -> event.startsWith("HOLD|")).count();
                require(ticks == (officialCheck ? 0 : seconds), "hold countdown runs only in quick mode");
                require(session.events.stream().anyMatch(event -> event.startsWith("HOLD_DONE|")) == !officialCheck,
                        "quick mode ends with the visual confirmation prompt");
            }
        }

        for (int invalid : new int[]{-1, 61}) {
            Session session = new Session();
            try {
                session.protocol.write(IMAGE, false, 0, invalid);
                throw new AssertionError("invalid hold accepted");
            } catch (IllegalArgumentException expected) {
                require(session.commands.isEmpty() && session.time == 0, "invalid hold stops before APDUs");
            }
        }

        Session stoppedHold = new Session();
        stoppedHold.cancelAt = 1250;
        try {
            stoppedHold.protocol.write(IMAGE, false, 0, 60);
            throw new AssertionError("refresh hold continued after cancellation");
        } catch (InterruptedException expected) {
            require(expected.getMessage().contains("目视确认"), "cancellation reports unverified refresh");
            require(stoppedHold.refreshAt == 1000 && stoppedHold.time == 1300, "hold checks for cancellation every 100 ms");
            require(stoppedHold.commands.get(stoppedHold.commands.size() - 1).startsWith("F0D4"), "D4 remains the last APDU");
            require(stoppedHold.events.stream().noneMatch(event -> event.startsWith("HOLD_DONE|")), "cancelled hold is not complete");
        }
        System.out.println("PASS: selectable post-refresh hold, quick-mode scope and bounded cancellation");

        Session defaultPackets = new Session();
        defaultPackets.protocol.write(IMAGE, false, 0);
        int total = 0;
        for (String event : defaultPackets.events)
            if (event.startsWith("PROGRESS|")) {
                String[] fields = event.split("\\|", 4);
                total = Integer.parseInt(fields[2]);
            }
        require(total > 0, "transfer packet count");

        int every = 10, seconds = 1;
        Session packetCharge = new Session();
        packetCharge.protocol.write(IMAGE, false, 0, 20, every, seconds);
        int pauses = (total - 1) / every;
        require(packetCharge.commands.equals(defaultPackets.commands), "packet charge does not change APDUs");
        require(packetCharge.time - defaultPackets.time == pauses * seconds * 1000L,
                "packet charge inserts the configured pauses");
        long chargeEvents = packetCharge.events.stream().filter(event -> event.startsWith("PACKET_CHARGE|")).count();
        long doneEvents = packetCharge.events.stream().filter(event -> event.startsWith("PACKET_CHARGE_DONE|")).count();
        require(chargeEvents == pauses && doneEvents == pauses, "packet charge events match pause count");

        for (int[] invalid : new int[][]{{-1, 1}, {477, 1}, {10, -1}, {10, 6}, {1, 5}}) {
            Session session = new Session();
            try {
                session.protocol.write(IMAGE, false, 0, 20, invalid[0], invalid[1]);
                throw new AssertionError("invalid packet charge accepted: " + invalid[0] + "/" + invalid[1]);
            } catch (IllegalArgumentException expected) {
                require(session.commands.isEmpty() && session.time == 0, "invalid packet charge stops before APDUs");
            }
        }

        Session cancelledPacket = new Session();
        cancelledPacket.cancelAt = 2500;
        try {
            cancelledPacket.protocol.write(IMAGE, false, 0, 20, 10, 5);
            throw new AssertionError("packet charge continued after cancellation");
        } catch (InterruptedException expected) {
            require(expected.getMessage() != null, "packet charge propagates cancellation");
            require(cancelledPacket.commands.stream().noneMatch(command -> command.startsWith("F0D4")),
                    "cancelled packet charge never reaches D4");
            require(cancelledPacket.events.stream().noneMatch(event -> event.startsWith("PACKET_CHARGE_DONE|")),
                    "cancelled packet charge is not reported complete");
        }
        System.out.println("PASS: packet-charge interval, bounds and cancellation");

        Session preD4 = new Session();
        preD4.protocol.write(IMAGE, false, 0, 20, 10, 0, 0);
        require(preD4.commands.equals(defaultPackets.commands), "pre-D4 hold does not change APDUs");
        require(preD4.refreshAt - defaultPackets.refreshAt == 10000, "D4 is sent after the configured hold");
        require(preD4.time - defaultPackets.time == 10000, "pre-D4 hold adds only the configured seconds");
        require(preD4.events.stream().anyMatch(event -> event.startsWith("PRE_D4_HOLD|")), "pre-D4 hold is reported");
        require(preD4.events.stream().anyMatch(event -> event.startsWith("PRE_D4_HOLD_DONE|")),
                "pre-D4 hold completion is reported");

        Session combined = new Session();
        combined.protocol.write(IMAGE, false, 0, 20, 5, 10, 1);
        require(combined.time - defaultPackets.time == 5000 + ((total - 1) / 10) * 1000,
                "pre-D4 hold and packet charge compose");

        for (int invalid : new int[]{-1, 61}) {
            Session session = new Session();
            try {
                session.protocol.write(IMAGE, false, 0, 20, invalid, 0, 0);
                throw new AssertionError("invalid pre-D4 hold accepted: " + invalid);
            } catch (IllegalArgumentException expected) {
                require(session.commands.isEmpty() && session.time == 0, "invalid pre-D4 hold stops before APDUs");
            }
        }

        Session cancelledPreD4 = new Session();
        cancelledPreD4.cancelAt = 2500;
        try {
            cancelledPreD4.protocol.write(IMAGE, false, 0, 20, 10, 0, 0);
            throw new AssertionError("pre-D4 hold continued after cancellation");
        } catch (InterruptedException expected) {
            require(cancelledPreD4.commands.stream().noneMatch(command -> command.startsWith("F0D4")),
                    "cancelled pre-D4 hold never reaches D4");
            require(cancelledPreD4.events.stream().noneMatch(event -> event.startsWith("PRE_D4_HOLD_DONE|")),
                    "cancelled pre-D4 hold is not reported complete");
        }
        System.out.println("PASS: pre-D4 hold duration, composition and bounded cancellation");
    }
}
