package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

//TODO 考虑多个频道时  不同频道的返回顺序困难乱序，需要考虑,但相同频道的请求肯定是先后顺序
public class AbstracatChannel {
    private Logger logger = LoggerFactory.getLogger(AbstracatChannel.class);

    /**SSH会话信息*/
    protected SSHSession sshSession;

    /**客户端频道编号*/
    protected int senderChannel;

    /**服务端频道编号*/
    protected int recipientChannel;

    protected SSHOutputStream sos = new SSHOutputStreamImpl();

    public AbstracatChannel(SSHSession sshSession) {
        this.sshSession = sshSession;
        this.senderChannel = sshSession.senderChannel++;
    }

    /**关闭频道*/
    public void closeChannel() throws IOException {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_CLOSE.value);
        sos.writeInt(this.recipientChannel);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());

        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_CLOSE);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        int recipientChannel = sis.readInt();
        checkRecipientChannel(recipientChannel);
        logger.debug("[关闭频道]本地频道id:{},对端频道id:{}",recipientChannel, this.recipientChannel);
    }

    /**读取频道数据*/
    protected SSHString readChannelData() throws IOException {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_DATA);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        checkRecipientChannel(sis.readInt());
        SSHString data = sis.readSSHString();
        return data;
    }

    /**写入频道数据*/
    protected void writeChannelData(byte[] data) throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_DATA.value);
        sos.writeInt(recipientChannel);
        sos.writeSSHString(new SSHString(data));
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
    }

    /**检查频道是否正常打开*/
    protected void checkChannelOpen() throws IOException {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,SSHMessageCode.SSH_MSG_CHANNEL_OPEN_FAILURE);
        SSHMessageCode sshMessageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        switch (sshMessageCode){
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:{
                int recipientChannel = sis.readInt();
                this.recipientChannel = sis.readInt();
                logger.debug("[打开频道成功]本地频道id:{},对端频道id:{}",recipientChannel, this.recipientChannel);
            }break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:{
                int recipientChannel = sis.readInt();
                int reasonCode = sis.readInt();
                String description = sis.readSSHString().toString();
                if(null==description||description.isEmpty()){
                    switch (reasonCode){
                        case 1:{description = "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED";}break;
                        case 2:{description = "SSH_OPEN_CONNECT_FAILED";}break;
                        case 3:{description = "SSH_OPEN_UNKNOWN_CHANNEL_TYPE";}break;
                        case 4:{description = "SSH_OPEN_RESOURCE_SHORTAGE";}break;
                        default:{
                            throw new SSHException("无法识别的创建频道错误编码!编码:"+reasonCode);
                        }
                    }
                }
                throw new SSHException("打开频道失败!本地频道id:"+recipientChannel+"对端频道编号:"+this.recipientChannel+",错误编号:"+reasonCode+",错误描述:"+description);
            }
        }
    }

    /**检查操作是否成功*/
    protected void checkWantReply() throws IOException {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_SUCCESS,SSHMessageCode.SSH_MSG_CHANNEL_FAILURE);
        int recipientChannel = SSHUtil.byteArray2Int(payload,1,4);
        checkRecipientChannel(recipientChannel);
        SSHMessageCode sshMessageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        switch (sshMessageCode){
            case SSH_MSG_CHANNEL_SUCCESS:{}break;
            case SSH_MSG_CHANNEL_FAILURE:{
                throw new SSHException("SSH操作失败!本地频道id:"+recipientChannel+",对端频道id:"+this.recipientChannel);
            }
        }
    }

    /**检查频道id是否正确*/
    protected void checkRecipientChannel(int recipientChannel) throws IOException {
        if(recipientChannel!=this.senderChannel){
            throw new SSHException("接收频道数据失败!频道编号不一致!预期编号:"+this.senderChannel+",实际编号:"+recipientChannel);
        }
    }
}