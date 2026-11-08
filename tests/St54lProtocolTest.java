package com.qpoll.lite;

import dev.inknfclab.DeviceSupport;
import dev.inknfclab.Protocol;

public final class St54lProtocolTest {
    private static final byte[] INFO = PanelProtocol.hex(
            "A007F0C72006000228A10700120030FFFFFFB10102B20114B30100C004201EA001C10401020304D107012000000000009000");

    private static final class Probe implements PanelProtocol.Control, PanelProtocol.Transport {
        private long now;
        private int attempts;
        private final boolean alwaysFail;

        Probe(boolean alwaysFail) { this.alwaysFail = alwaysFail; }
        public long now() { return now; }
        public void sleep(long ms) { now += ms; }
        public void check() { }
        public void event(String kind, String message) { }
        public byte[] exchange(byte[] command, int timeoutMs) {
            if ((command[1] & 255) != 0xD1) throw new AssertionError("Unexpected APDU");
            return ++attempts < 3 || alwaysFail ? PanelProtocol.hex("6403") : INFO;
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        require(DeviceSupport.verifiedRootProfile("haotian", 37), "haotian Android 17 helper enabled");
        require(!DeviceSupport.verifiedRootProfile("haotian", 36), "haotian Android 16 helper excluded");
        require(!DeviceSupport.verifiedRootProfile("dada", 37), "unported device excluded");
        require("012A020A7A".equals(Protocol.hex(Protocol.polling7A())), "upstream ST54L 7A frame");
        Probe st = new Probe(false);
        new PanelProtocol(st, st, true).identify();
        require(st.attempts == 3 && st.now == 2600, "ST54L retries D1 twice at 800 ms intervals");
        for (boolean retry : new boolean[]{false, true}) {
            Probe failing = new Probe(true);
            try {
                new PanelProtocol(failing, failing, retry).identify();
                throw new AssertionError("Rejected D1 accepted");
            } catch (IllegalArgumentException expected) {
                require(failing.attempts == (retry ? 3 : 1), "D1 retry is bounded and ST54L-only");
            }
        }
        System.out.println("PASS: ST54L device gate, 7A payload and scoped D1 retry");
    }
}
