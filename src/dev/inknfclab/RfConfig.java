package dev.inknfclab;

import java.util.Arrays;

public final class RfConfig {
    public static final int LENGTH = 196;

    public static void validateDelta(int delta) {
        if (delta != -1 && delta != 0 && delta != 1 && delta != 2)
            throw new IllegalArgumentException("仅允许原厂 APC 相对档 -1、0、+1、+2");
    }

    public static byte[] parse(int parameter, byte[] response) {
        if (parameter < 2 || parameter > 4 || response.length != LENGTH + 3
                || response[0] != 1 || response[1] != parameter || (response[2] & 255) != LENGTH)
            throw new IllegalArgumentException("不支持的 ST54L RF 配置响应");
        byte[] configuration = Arrays.copyOfRange(response, 3, response.length);
        validate(configuration);
        return configuration;
    }

    public static void validate(byte[] configuration) {
        if (configuration.length != LENGTH || configuration[0] != 0x44 || configuration[1] != 0
                || ((configuration[2] & 255) | ((configuration[3] & 255) << 8)) != crc(configuration))
            throw new IllegalArgumentException("RF 配置布局或 CRC 不匹配，拒绝写入");
    }

    public static byte[] adjust(byte[] original, int delta) {
        validateDelta(delta);
        validate(original);
        byte[] adjusted = original.clone();
        if (delta == 0) return adjusted;
        for (int offset : new int[]{4, 100}) {
            int word = readWord(original, offset);
            int first = Math.max(2, Math.min(21, ((word >>> 11) & 31) + delta));
            int second = Math.max(2, Math.min(21, ((word >>> 27) & 31) + delta));
            word = (word & ~((31 << 11) | (31 << 27))) | (first << 11) | (second << 27);
            for (int index = 0; index < 4; index++) adjusted[offset + index] = (byte) (word >>> (index * 8));
        }
        int checksum = crc(adjusted);
        adjusted[2] = (byte) checksum;
        adjusted[3] = (byte) (checksum >>> 8);
        return adjusted;
    }

    public static String values(byte[] configuration) {
        validate(configuration);
        int first = readWord(configuration, 4);
        int second = readWord(configuration, 100);
        return ((first >>> 11) & 31) + "/" + ((first >>> 27) & 31)
                + "/" + ((second >>> 11) & 31) + "/" + ((second >>> 27) & 31);
    }

    private static int readWord(byte[] configuration, int offset) {
        return (configuration[offset] & 255) | ((configuration[offset + 1] & 255) << 8)
                | ((configuration[offset + 2] & 255) << 16) | ((configuration[offset + 3] & 255) << 24);
    }

    private static int crc(byte[] configuration) {
        int checksum = 39236;
        for (int offset = 4; offset < configuration.length; offset++) {
            checksum ^= (configuration[offset] & 255) << 8;
            for (int bit = 0; bit < 8; bit++)
                checksum = ((checksum << 1) ^ ((checksum & 32768) != 0 ? 4129 : 0)) & 65535;
        }
        return checksum;
    }
}
