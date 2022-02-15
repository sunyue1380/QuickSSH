package cn.schoolwow.ssh;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.handler.Handler;
import cn.schoolwow.ssh.handler.KexExchangeHandler;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.channel.SFTPChannel;
import cn.schoolwow.ssh.layer.channel.SessionChannel;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.IOException;

public class SSHClient {
    private Logger logger = LoggerFactory.getLogger(SSHClient.class);

    private SSHSession sshSession;

    public SSHClient(SSHSession sshSession) throws IOException {
        this.sshSession = sshSession;
        Handler handler = new KexExchangeHandler();
        while(null!=handler){
            try {
                handler = handler.handle(sshSession);
            } catch (Exception e) {
                e.printStackTrace();
                disconnect();
                break;
            }
        }
    }

    /**获取session频道*/
    public String exec(String command) throws IOException {
        return new SessionChannel(sshSession).exec(command);
    }

    /**获取sftp频道*/
    public SFTPChannel sftp() throws IOException {
        return new SFTPChannel(sshSession);
    }

    /**断开连接*/
    public void disconnect() throws IOException {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_DISCONNECT.value);
        sos.writeInt(4);
        sos.writeSSHString(new SSHString("SSH_DISCONNECT_RESERVED"));
        sos.writeInt(0);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
    }
}