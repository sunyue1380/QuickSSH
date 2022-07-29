package cn.schoolwow.ssh.domain.exception;

public class SFTPException extends RuntimeException {
    /**错误编码*/
    private int errorCode;

    /**编码说明*/
    private String message;

    /**错误描述*/
    private String description;

    public SFTPException(String message){
        super(message);
    }

    public SFTPException(int errorCode, String description) {
        this("SFTP协议异常!错误编码:"+errorCode+",错误描述:"+description);
        this.errorCode = errorCode;
        this.description = description;
        switch (errorCode){
            case 1:{message = "SSH_FX_EOF";}break;
            case 2:{message = "SSH_FX_NO_SUCH_FILE";}break;
            case 3:{message = "SSH_FX_PERMISSION_DENIED";}break;
            case 4:{message = "SSH_FX_FAILURE";}break;
            case 5:{message = "SSH_FX_BAD_MESSAGE";}break;
            case 6:{message = "SSH_FX_NO_CONNECTION";}break;
            case 7:{message = "SSH_FX_CONNECTION_LOST";}break;
            case 8:{message = "SSH_FX_OP_UNSUPPORTED";}break;
            default:{
                throw new IllegalArgumentException("未定义错误编码!错误编码:"+errorCode);
            }
        }
    }

    public int getErrorCode() {
        return errorCode;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public String getDescription() {
        return description;
    }
}