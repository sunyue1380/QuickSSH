package cn.schoolwow.ssh;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.handler.Handler;
import cn.schoolwow.ssh.handler.KexExchangeHandler;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.channel.ExecChannel;
import cn.schoolwow.ssh.layer.channel.LocalForwardChannel;
import cn.schoolwow.ssh.layer.channel.RemoteForwardChannel;
import cn.schoolwow.ssh.layer.channel.SFTPChannel;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class SSHClient {
    private Logger logger = LoggerFactory.getLogger(SSHClient.class);

    private SSHSession sshSession;

    public SSHClient(SSHSession sshSession) throws IOException {
        this.sshSession = sshSession;
        Handler handler = new KexExchangeHandler();
        while (null != handler) {
            try {
                handler = handler.handle(sshSession);
            } catch (Exception e) {
                e.printStackTrace();
                break;
            }
        }
    }

    public SSHSession sshSession() {
        return this.sshSession;
    }

    /**
     * 获取session频道
     */
    public String exec(String command) throws IOException {
        return new ExecChannel(sshSession, this).exec(command);
    }

    /**
     * 获取sftp频道
     */
    public SFTPChannel sftpChannel() throws IOException {
        return new SFTPChannel(sshSession, this);
    }

    /**
     * 本地端口转发
     */
    public LocalForwardChannel localForwardChannel() throws IOException {
        return new LocalForwardChannel(sshSession, this);
    }

    /**
     * 远程端口转发
     */
    public RemoteForwardChannel remoteForwardChannel() throws IOException {
        return new RemoteForwardChannel(sshSession, this);
    }

    /**
     * 会话是否断开
     */
    public boolean isClosed() {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        try {
            sos.writeByte(SSHMessageCode.SSH_MSG_GLOBAL_REQUEST.value);
            sos.writeSSHString(new SSHString("keepalive@openssh.com"));
            sos.writeBoolean(true);
            sshSession.writeSSHProtocolPayload(sos.toByteArray());
            sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_REQUEST_SUCCESS,SSHMessageCode.SSH_MSG_REQUEST_FAILURE);
            return false;
        } catch (IOException e) {
            logger.warn("[会话已关闭]原因:{}, id:{}", e.getMessage(), SSHUtil.byteArrayToHex(sshSession.sessionId));
            return true;
        }
    }

    /**
     * 断开连接
     */
    public void disconnect() throws IOException {
        if (!isClosed()) {
            SSHOutputStream sos = new SSHOutputStreamImpl();
            sos.writeByte(SSHMessageCode.SSH_MSG_DISCONNECT.value);
            sos.writeInt(4);
            sos.writeSSHString(new SSHString("SSH_DISCONNECT_RESERVED"));
            sos.writeInt(0);
            sshSession.writeSSHProtocolPayload(sos.toByteArray());
            logger.debug("[断开会话]会话id:{}", SSHUtil.byteArrayToHex(sshSession.sessionId));
        } else {
            logger.debug("[断开会话]该会话已经断开!");
        }
    }
}