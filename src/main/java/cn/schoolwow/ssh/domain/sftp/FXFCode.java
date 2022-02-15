package cn.schoolwow.ssh.domain.sftp;

/**
 * SFTP协议FXF常量定义
 */
public enum FXFCode {
    SSH_FXF_READ(0x00000001),
    SSH_FXF_WRITE(0x00000002),
    SSH_FXF_APPEND(0x00000004),
    SSH_FXF_CREAT(0x00000008),
    SSH_FXF_TRUNC(0x00000010),
    SSH_FXF_EXCL(0x00000020);

    public int value;

    FXFCode(int value) {
        this.value = (byte) value;
    }

    public static FXFCode getFXFCode(int value){
        for(FXFCode fxfCode: FXFCode.values()){
            if(fxfCode.value==value){
                return fxfCode;
            }
        }
        throw new IllegalArgumentException("不支持的FXFCode!value:"+value);
    }
}