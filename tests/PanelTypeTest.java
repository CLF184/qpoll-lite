package com.qpoll.lite;

import java.util.Arrays;
import java.util.Random;

public final class PanelTypeTest {
    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        int width = PanelProtocol.WIDTH;
        int height = PanelProtocol.HEIGHT;
        int stride = height / 4;
        byte[] codes = new byte[width * height];
        Random random = new Random(615297);
        for (int i = 0; i < codes.length; i++) codes[i] = (byte) random.nextInt(4);
        byte[] original = codes.clone();
        byte[] linear = PanelProtocol.packCodes(codes, width, height);
        require(Arrays.equals(linear, PanelType.A1.pack(codes)), "A1 keeps the factory row order");
        require(Arrays.equals(PanelProtocol.mapA0Rows(linear), PanelType.A0.pack(codes)),
                "A0 interleaves the factory rows once");

        for (PanelType type : PanelType.values()) {
            require(PanelType.parse(type.name()) == type, "Selection resolves to " + type);
            byte[] packed = type.pack(codes);
            int[] preview = type.preview(packed);
            for (int i = 0; i < codes.length; i++) {
                if (preview[i] != ImageRaster.color(codes[i]))
                    throw new AssertionError(type + " preview mismatch at pixel " + i);
            }
            for (boolean topDown : new boolean[]{false, true}) {
                byte[] wire = PanelType.forScan(packed, topDown);
                for (int row = 0; row < width; row++) {
                    int sourceRow = type == PanelType.A1 ? row
                            : (row % 2 == 0 ? row / 2 : width - 1 - row / 2);
                    int x = width - 1 - sourceRow;
                    if (type == PanelType.A0X) x = (x + width / 2) % width;
                    for (int block = 0; block < stride; block++) {
                        int expected = 0;
                        for (int pixel = 0; pixel < 4; pixel++) {
                            int y = block * 4 + pixel;
                            if (!topDown) y = height - 1 - y;
                            expected = (expected << 2) | codes[y * width + x];
                        }
                        if ((wire[row * stride + block] & 255) != expected)
                            throw new AssertionError(type + " wire mismatch at row " + row
                                    + ", block " + block + ", topDown=" + topDown);
                    }
                }
            }
        }
        require(Arrays.equals(codes, original), "Packing preserves source pixels");
        System.out.println("PASS: A1/A0/A0X preview and full-frame bytes in both scan directions");
    }
}
