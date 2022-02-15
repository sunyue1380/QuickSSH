package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;

import java.io.IOException;

public class SessionChannel extends AbstracatChannel {

    public SessionChannel(SSHSession sshSession) throws IOException {
        super(sshSession);
    }

    /**
     * 执行shell命令
     * @param command shell命令
     * */
    public String exec(String command) throws IOException {
        openSessionChannel();
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_REQUEST.value);
        sos.writeInt(recipientChannel);
        sos.writeSSHString(new SSHString("exec"));
        sos.writeBoolean(true);
        sos.writeSSHString(new SSHString(command));
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        checkWantReply();
        SSHString data = null;
        if(SSHMessageCode.SSH_MSG_CHANNEL_DATA.equals(sshSession.peekSSHMessageCode())){
            data = readChannelData();
        }
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_REQUEST);
        sshSession.checkExitStatus(payload);
        closeChannel();
        if(null==data){
            return null;
        }
        return new String(data.value,0,data.value.length-1,data.charset);
    }

    private void openSessionChannel() throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_OPEN.value);
        sos.writeSSHString(new SSHString("session"));
        sos.writeInt(senderChannel);
        sos.writeInt(0x100000);
        sos.writeInt(0x4000);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        checkChannelOpen();
    }
}