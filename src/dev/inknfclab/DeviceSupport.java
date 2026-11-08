package dev.inknfclab;

public final class DeviceSupport {
    public static boolean verifiedRootProfile(String device, int sdk) {
        return sdk == 37 && ("pudding".equals(device) || "haotian".equals(device));
    }

    public static boolean useRoot(String device, int sdk, boolean hasNfc, boolean standardOnly) {
        return hasNfc && !standardOnly && verifiedRootProfile(device, sdk);
    }

    public static String summary(String device, int sdk, boolean hasNfc) {
        if (!hasNfc) return "无 NFC 硬件：可选图与预览，不支持手机刷屏。";
        if ("haotian".equals(device) && verifiedRootProfile(device, sdk)) return "小米 15 Pro / Android 17：需要配套 ST54L 模块与 Root 授权。";
        if (verifiedRootProfile(device, sdk)) return "小米 17 / Android 17：有已验证的 ST54L Root 7A 配置；仍需原机固件接口与授权。";
        if ("dada".equals(device)) return "小米 15：已支持标准 ISO-DEP 路径，7-bit 7A 唤醒与 MIFARE 补丁尚待真机适配。";
        return "标准 ISO-DEP 路径：不请求 Root；仅在系统能发现并连接驱动板时可读写，不能保证 7A 唤醒。";
    }

    private DeviceSupport() {}
}
