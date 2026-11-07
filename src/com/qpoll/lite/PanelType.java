package com.qpoll.lite;

/** Huawei JD79665AA panel variants; selection is physical, never inferred from D1. */
public enum PanelType {
    A0, A1, A0X;
    public static PanelType parse(String value) {
        if("A0".equals(value))return A0;
        if("A1".equals(value))return A1;
        if("A0X".equals(value))return A0X;
        throw new IllegalArgumentException("请先选择屏幕类型 A0、A1 或 A0X");
    }
    public byte[] pack(byte[] codes) {
        byte[] linear=PanelProtocol.packCodes(codes,PanelProtocol.WIDTH,PanelProtocol.HEIGHT);
        if(this==A1)return linear;
        return PanelProtocol.mapA0Rows(this==A0X?swapHalves(linear):linear);
    }
    private static byte[] swapHalves(byte[] linear) {
        // Each packed column is contiguous. Exchange both 276-column halves before A0 interleaving.
        int half=linear.length/2;
        byte[] out=new byte[linear.length];
        System.arraycopy(linear,half,out,0,half);
        System.arraycopy(linear,0,out,half,half);
        return out;
    }
    private byte[] unpack(byte[] packed) {
        if(packed.length!=PanelProtocol.IMAGE_BYTES)throw new IllegalArgumentException("屏幕数据长度错误");
        if(this==A1)return packed;
        byte[] linear=new byte[packed.length];
        final int rows=PanelProtocol.WIDTH,stride=PanelProtocol.HEIGHT/4;
        for(int row=0;row<rows;row++) {
            int source=row<rows/2?2*row:2*rows-1-2*row;
            System.arraycopy(packed,source*stride,linear,row*stride,stride);
        }
        return this==A0X?swapHalves(linear):linear;
    }
    public int[] preview(byte[] packed) {
        return ImageRaster.preview(unpack(packed),PanelProtocol.WIDTH,PanelProtocol.HEIGHT);
    }
    /** Stored scan 00 uses bottom-up pixels; scan 01 uses top-down pixels in each row. */
    public static byte[] forScan(byte[] packed,boolean topDown) {
        if(packed.length!=PanelProtocol.IMAGE_BYTES)throw new IllegalArgumentException("屏幕数据长度错误");
        if(!topDown)return packed.clone();
        int stride=PanelProtocol.HEIGHT/4;byte[] out=new byte[packed.length];
        for(int row=0;row<PanelProtocol.WIDTH;row++)for(int i=0;i<stride;i++) {
            int b=packed[row*stride+stride-1-i]&255;
            out[row*stride+i]=(byte)(((b&3)<<6)|((b&12)<<2)|((b&48)>>2)|((b&192)>>6));
        }
        return out;
    }
}
