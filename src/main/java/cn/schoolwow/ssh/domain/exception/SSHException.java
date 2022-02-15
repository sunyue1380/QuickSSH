package cn.schoolwow.ssh.domain.exception;

/**SSH操作失败*/
public class SSHException extends RuntimeException{
    public SSHException(String msg){
        super(msg);
    }

    public SSHException(Exception e){
        super(e);
    }
}