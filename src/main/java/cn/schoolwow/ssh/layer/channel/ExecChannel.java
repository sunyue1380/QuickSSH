package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.SSHClient;
import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class ExecChannel extends AbstractChannel {
    private Logger logger = LoggerFactory.getLogger(ExecChannel.class);

    public ExecChannel(SSHSession sshSession, SSHClient sshClient) {
        super(sshSession, sshClient);
    }

    /**
     * 执行shell命令
     *
     * @param command shell命令
     */
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
        byte[] payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_DATA, SSHMessageCode.SSH_MSG_CHANNEL_EXTENDED_DATA, SSHMessageCode.SSH_MSG_CHANNEL_REQUEST);
        StringBuilder extendDataBuilder = new StringBuilder();
        while (payload[0] == SSHMessageCode.SSH_MSG_CHANNEL_EXTENDED_DATA.value) {
            int length = SSHUtil.byteArray2Int(payload, 9, 4);
            extendDataBuilder.append(new String(payload, 13, length));
            payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_DATA, SSHMessageCode.SSH_MSG_CHANNEL_EXTENDED_DATA, SSHMessageCode.SSH_MSG_CHANNEL_REQUEST);
        }
        if (extendDataBuilder.length() > 0) {
            logger.debug("[接收扩展数据]{}", extendDataBuilder.toString());
        }
        if (payload[0] == SSHMessageCode.SSH_MSG_CHANNEL_DATA.value) {
            SSHInputStream sis = new SSHInputStreamImpl(payload);
            sis.skipBytes(5);
            data = sis.readSSHString();
        } else {
            SSHUtil.checkExitStatus(payload,extendDataBuilder.toString());
        }
        closeChannel();
        if (null == data) {
            return null;
        }
        return new String(data.value, 0, data.value.length - 1, data.charset);
    }
}