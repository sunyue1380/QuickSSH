package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.SSHClient;
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

import java.io.Closeable;
import java.io.IOException;

public class AbstractChannel implements Closeable {
    private Logger logger = LoggerFactory.getLogger(AbstractChannel.class);

    /**
     * SSH会话信息
     */
    protected SSHSession sshSession;

    /**
     * 客户端频道编号
     */
    protected int senderChannel;

    /**
     * 服务端频道编号
     */
    protected int recipientChannel;

    /**
     * 最大包大小(32kb)
     * */
    protected int maximumPacketSize = 32*1024;

    /**
     * 初始窗口大小
     * */
    protected int initialWindowSize = 64*maximumPacketSize;

    /**
     * 输出报文缓存
     */
    protected SSHOutputStream sos = new SSHOutputStreamImpl();

    /**
     * 关联SSH客户端
     */
    protected SSHClient sshClient;

    /**
     * 频道是否关闭
     */
    private volatile boolean channelClosed;

    public AbstractChannel(SSHSession sshSession, SSHClient sshClient) {
        this.sshSession = sshSession;
        this.sshClient = sshClient;
    }

    /**
     * 调整窗口大小
     * @param bytesToAdd 要增加的字节数
     */
    public void adjustWindowSize(int bytesToAdd) throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_WINDOW_ADJUST.value);
        sos.writeInt(recipientChannel);
        sos.writeInt(bytesToAdd);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
    }

    /**
     * 频道是否关闭
     */
    public boolean isChannelClosed() {
        return channelClosed;
    }

    /**
     * 获取关联SSH客户端
     */
    public SSHClient getSSHClient() {
        return sshClient;
    }

    /**
     * 创建session频道
     */
    protected void openSessionChannel() throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_OPEN.value);
        sos.writeSSHString(new SSHString("session"));
        senderChannel = sshSession.senderChannel.getAndIncrement();
        sos.writeInt(senderChannel);
        sos.writeInt(initialWindowSize);
        sos.writeInt(maximumPacketSize);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        synchronized (sshSession){
            checkChannelOpen(senderChannel);
            logger.debug("[打开频道成功]本地频道id:{},对端频道id:{}", senderChannel, recipientChannel);
        }
    }

    /**
     * 读取频道数据
     */
    protected SSHString readChannelData() throws IOException {
        byte[] payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_DATA, SSHMessageCode.SSH_MSG_CHANNEL_EOF, SSHMessageCode.SSH_MSG_CHANNEL_CLOSE);
        if (payload[0] == SSHMessageCode.SSH_MSG_CHANNEL_EOF.value) {
            return null;
        }
        if (payload[0] == SSHMessageCode.SSH_MSG_CHANNEL_CLOSE.value) {
            channelClosed = true;
            throw new SSHException("服务端主动关闭频道!本地频道id:" + senderChannel + ",对端频道id:" + recipientChannel);
        }
        int length = SSHUtil.byteArray2Int(payload, 5, 4);
        byte[] data = new byte[length];
        System.arraycopy(payload, 9, data, 0, data.length);
        return new SSHString(data);
    }

    /**
     * 写入频道数据
     */
    protected void writeChannelData(byte[] data) throws IOException {
        writeChannelData(data, 0, data.length);
    }

    /**
     * 写入频道数据
     */
    protected void writeChannelData(byte[] data, int offset, int length) throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_DATA.value);
        sos.writeInt(recipientChannel);
        sos.writeInt(length);
        sos.write(data, offset, length);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
    }

    /**
     * 检查频道是否正常打开
     */
    protected void checkChannelOpen(int senderChannel) throws IOException {
        byte[] payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, SSHMessageCode.SSH_MSG_CHANNEL_OPEN_FAILURE);
        SSHMessageCode sshMessageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        switch (sshMessageCode) {
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: {
                this.senderChannel = sis.readInt();
                this.recipientChannel = sis.readInt();
            }
            break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE: {
                sis.skipBytes(4);
                int reasonCode = sis.readInt();

                String reasonCodeDescription = null;
                switch (reasonCode) {
                    case 1: {
                        reasonCodeDescription = "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED";
                    }
                    break;
                    case 2: {
                        reasonCodeDescription = "SSH_OPEN_CONNECT_FAILED";
                    }
                    break;
                    case 3: {
                        reasonCodeDescription = "SSH_OPEN_UNKNOWN_CHANNEL_TYPE";
                    }
                    break;
                    case 4: {
                        reasonCodeDescription = "SSH_OPEN_RESOURCE_SHORTAGE";
                    }
                    break;
                    default: {
                        throw new SSHException("无法识别的创建频道错误编码!编码:" + reasonCode);
                    }
                }
                String description = sis.readSSHString().toString();
                throw new SSHException("打开频道失败!本地频道id:" + recipientChannel + ",对端频道编号:" + this.recipientChannel + ",错误编号:" + reasonCodeDescription + ",错误描述:" + description);
            }
        }
    }

    /**
     * 检查操作是否成功
     */
    protected void checkGlobalRequestWantReply() throws IOException {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_REQUEST_SUCCESS, SSHMessageCode.SSH_MSG_REQUEST_FAILURE);
        SSHMessageCode sshMessageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        switch (sshMessageCode) {
            case SSH_MSG_CHANNEL_SUCCESS: {
            }
            break;
            case SSH_MSG_CHANNEL_FAILURE: {
                throw new SSHException("SSH全局请求操作失败!");
            }
        }
    }

    /**
     * 检查操作是否成功
     */
    protected void checkChannelRequestWantReply() throws IOException {
        byte[] payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_WINDOW_ADJUST, SSHMessageCode.SSH_MSG_CHANNEL_SUCCESS, SSHMessageCode.SSH_MSG_CHANNEL_FAILURE);
        SSHMessageCode sshMessageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        if(SSHMessageCode.SSH_MSG_CHANNEL_WINDOW_ADJUST.equals(sshMessageCode)){
            int bytesToAdd = SSHUtil.byteArray2Int(payload,5,4);
            initialWindowSize = initialWindowSize + bytesToAdd;
            payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_SUCCESS, SSHMessageCode.SSH_MSG_CHANNEL_FAILURE);
            sshMessageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        }
        switch (sshMessageCode) {
            case SSH_MSG_CHANNEL_SUCCESS: {}break;
            case SSH_MSG_CHANNEL_FAILURE: {
                throw new SSHException("SSH频道请求操作失败!本地频道id:" + senderChannel + ",对端频道id:" + recipientChannel);
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (!channelClosed) {
            SSHOutputStream sos = new SSHOutputStreamImpl();
            sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_CLOSE.value);
            sos.writeInt(recipientChannel);
            sshSession.writeSSHProtocolPayload(sos.toByteArray());

            byte[] payload = sshSession.readChannelPayload(senderChannel, SSHMessageCode.SSH_MSG_CHANNEL_CLOSE);
            logger.debug("[关闭频道]本地频道id:{},对端频道id:{}", senderChannel, recipientChannel);
            channelClosed = true;
        } else {
            logger.debug("[关闭频道]该频道已经关闭!");
        }
    }
}