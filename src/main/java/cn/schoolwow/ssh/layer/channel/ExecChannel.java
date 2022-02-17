package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;

import java.io.IOException;

public class ExecChannel extends AbstractChannel{

    public ExecChannel(SSHSession sshSession) {
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
        checkChannelRequestWantReply();

        SSHString data = null;
        byte[] payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_DATA,SSHMessageCode.SSH_MSG_CHANNEL_REQUEST);
        if(payload[0]==SSHMessageCode.SSH_MSG_CHANNEL_DATA.value){
            SSHInputStream sis = new SSHInputStreamImpl(payload);
            sis.skipBytes(5);
            data = sis.readSSHString();
        }else{
            SSHUtil.checkExitStatus(payload);
        }
        closeChannel();
        if(null==data){
            return null;
        }
        return new String(data.value,0,data.value.length-1,data.charset);
    }
}