package dev.inknfclab;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class NciTrace {
    private static final Pattern LINE = Pattern.compile("\\(#([0-9A-Fa-f]+)\\) LL ([RrTt])x ([0-9A-Fa-f ]+)$");
    private String identifier;
    private String direction;
    private StringBuilder pending;

    public String accept(String line) {
        Matcher match = LINE.matcher(line.trim());
        if (!match.find()) return null;
        if (Character.isUpperCase(match.group(2).charAt(0)) || pending == null || !match.group(1).equals(identifier)) {
            identifier = match.group(1);
            direction = match.group(2).equalsIgnoreCase("R") ? "NFCC→主机" : "主机→NFCC";
            pending = new StringBuilder();
        }
        pending.append(match.group(3).replace(" ", "").toUpperCase(Locale.ROOT));
        if (pending.length() < 6) return null;
        int size = (Integer.parseInt(pending.substring(4, 6), 16) + 3) * 2;
        if (pending.length() < size) return null;
        String packet = pending.toString();
        pending = null;
        if (packet.length() != size) return direction + " 长度异常 RAW=" + packet;
        return direction + " " + describe(packet) + " RAW=" + packet;
    }

    public static String describe(String packet) {
        if (packet.startsWith("6F02")) return "ST 固件调试通知（未解码，不能据此判定板子回复）";
        if (packet.startsWith("6103")) return "RF_DISCOVER_NTF（发现目标）";
        if (packet.startsWith("6105")) return "RF_INTF_ACTIVATED_NTF（射频接口激活）";
        if (packet.startsWith("6107")) return "RF_FIELD_INFO_NTF（射频场状态）";
        if (packet.startsWith("6008")) return "CORE_INTERFACE_ERROR_NTF（接口错误）";
        if (packet.startsWith("6007")) return "CORE_GENERIC_ERROR_NTF";
        int type = Integer.parseInt(packet.substring(0, 2), 16) >> 5;
        return type == 0 ? "NCI DATA（主机/控制器数据，不保证是原始射频帧）" : "NCI 控制消息";
    }
}
