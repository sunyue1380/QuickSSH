package cn.schoolwow.ssh.domain.sftp;

/**
 * 文件属性掩码
 * */
public enum FILEXFERCode {
    SSH_FILEXFER_ATTR_SIZE(0x00000001),
    SSH_FILEXFER_ATTR_UIDGID(0x00000002),
    SSH_FILEXFER_ATTR_PERMISSIONS(0x00000004),
    SSH_FILEXFER_ATTR_ACMODTIME(0x00000008),
    SSH_FILEXFER_ATTR_EXTENDED(0x80000000);

    public int value;

    FILEXFERCode(int value) {
        this.value = (byte) value;
    }

    public static FILEXFERCode getFILEXFERCode(int value){
        for(FILEXFERCode filexferCode: FILEXFERCode.values()){
            if(filexferCode.value==value){
                return filexferCode;
            }
        }
        throw new IllegalArgumentException("不支持的FILEXFERCode!value:"+value);
    }
}