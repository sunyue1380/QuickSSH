package cn.schoolwow.ssh.layer;

import cn.schoolwow.ssh.domain.QuickSSHConfig;
import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.kex.SSHKexAlgorithmNegotitation;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;

public class SSHSession {
    private Logger logger = LoggerFactory.getLogger(SSHSession.class);

    /**
     * 输入流
     */
    public SSHInputStream sis;

    /**
     * 套接字
     */
    public Socket socket;

    /**
     * 配置信息
     */
    public QuickSSHConfig quickSSHConfig;

    /**
     * 协商算法实现类
     */
    public SSHKexAlgorithmNegotitation sshKexAlgorithmNegotitation = new SSHKexAlgorithmNegotitation();

    /**
     * 频道id
     */
    public volatile int senderChannel = 1000;

    /**
     * 会话id
     */
    public byte[] sessionId;

    /**
     * 客户端会话序号
     */
    private volatile int clientSequenceNumber = 0;

    /**
     * 服务端会话序号
     */
    private volatile int serverSequenceNumber = 0;

    /**
     * SSH消息缓存
     * */
    private Queue<byte[]> sshMessageCache = new LinkedList<>();

    public SSHSession(Socket socket, QuickSSHConfig quickSSHConfig) throws IOException {
        this.sis = new SSHInputStreamImpl(socket.getInputStream());
        this.socket = socket;
        this.quickSSHConfig = quickSSHConfig;
    }

    /**
     * 查看下个SSH消息类型
     * @return SSH消息类型
     */
    public SSHMessageCode peekSSHMessageCode() throws IOException {
        byte[] payload = doReadSSHProtocolPayload();
        sshMessageCache.add(payload);
        return SSHMessageCode.getSSHMessageCode(payload[0]);
    }

    /**
     * 读取SSH协议包负载数据
     * @param sshMessageCodes 预期读取的消息类型
     *
     * @return SSH协议负载数据
     */
    public byte[] readSSHProtocolPayload(SSHMessageCode... sshMessageCodes) throws IOException {
        byte[] payload = doReadSSHProtocolPayload();
        while(true){
            for(SSHMessageCode sshMessageCode:sshMessageCodes){
                if(sshMessageCode.value==payload[0]){
                    return payload;
                }
            }
            SSHInputStream sis = new SSHInputStreamImpl(payload);
            SSHMessageCode sshMessageCode = SSHMessageCode.getSSHMessageCode(sis.read());
            switch (sshMessageCode){
                case SSH_MSG_GLOBAL_REQUEST:{
                    String requestName = sis.readSSHString().toString();
                    boolean wantReply = sis.readBoolean();
                    logger.debug("[接收全局消息]消息类型:SSH_MSG_GLOBAL_REQUEST, 请求名称:{}, 是否需要回复:{}",requestName,wantReply);
                    if(wantReply){
                        logger.debug("[处理全局消息]发送SSH_MSG_REQUEST_FAILURE消息");
                        writeSSHProtocolPayload(new byte[]{(byte) SSHMessageCode.SSH_MSG_REQUEST_FAILURE.value});
                    }
                }break;
                case SSH_MSG_CHANNEL_REQUEST:{
                    checkExitStatus(payload);
                }break;
                case SSH_MSG_USERAUTH_BANNER:{
                    logger.debug("[服务端Banner消息]{}", sis.readSSHString().toString());
                }break;
                case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                case SSH_MSG_CHANNEL_EOF:{
                    logger.debug("[忽略SSH消息]消息类型:{}", sshMessageCode.name());
                };break;
                case SSH_MSG_CHANNEL_EXTENDED_DATA:{
                    int recipientChannel = sis.readInt();
                    int dataTypeCode = sis.readInt();
                    SSHString data = sis.readSSHString();
                    logger.debug("[接收频道扩展消息]消息类型:SSH_MSG_CHANNEL_EXTENDED_DATA,本地频道id:{}, 扩展类型:{}, 数据:{}", recipientChannel, dataTypeCode, data);
                };break;
                case SSH_MSG_DISCONNECT:{
                    int reasonCode = sis.readInt();
                    String description = sis.readSSHString().toString();
                    if (null == description || description.isEmpty()) {
                        switch (reasonCode) {
                            case 1: { description = "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT"; }break;
                            case 2: { description = "SSH_DISCONNECT_PROTOCOL_ERROR"; }break;
                            case 3: { description = "SSH_DISCONNECT_KEY_EXCHANGE_FAILED"; }break;
                            case 4: { description = "SSH_DISCONNECT_RESERVED"; }break;
                            case 5: { description = "SSH_DISCONNECT_MAC_ERROR"; }break;
                            case 6: { description = "SSH_DISCONNECT_COMPRESSION_ERROR"; }break;
                            case 7: { description = "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE"; }break;
                            case 8: { description = "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED"; }break;
                            case 9: { description = "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE"; }break;
                            case 10: { description = "SSH_DISCONNECT_CONNECTION_LOST"; }break;
                            case 11: { description = "SSH_DISCONNECT_BY_APPLICATION"; }break;
                            case 12: { description = "SSH_DISCONNECT_TOO_MANY_CONNECTIONS"; }break;
                            case 13: { description = "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER"; }break;
                            case 14: { description = "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE"; }break;
                            case 15: { description = "SSH_DISCONNECT_ILLEGAL_USER_NAME"; }break;
                        }
                    }
                    throw new SSHException("服务端断开连接消息!错误码:" + reasonCode + ",描述:" + description);
                }
                default:{
                    logger.warn("[无法处理非预期SSH消息]消息类型:{}", sshMessageCode.name());
                    throw new SSHException("无法处理非预期SSH消息!消息类型:"+sshMessageCode);
                }
            }
            payload = doReadSSHProtocolPayload();
        }
    }

    /**
     * 写入SSH协议包负载数据
     *
     * @param payload SSH协议负载数据
     */
    public void writeSSHProtocolPayload(byte[] payload) throws IOException {
        if (null != sshKexAlgorithmNegotitation.compress) {
            payload = sshKexAlgorithmNegotitation.compress.compress(payload);
        }
        byte paddingLength;
        if (null == sshKexAlgorithmNegotitation.c2sCipher) {
            paddingLength = (byte) getPaddingLength(8, payload.length);
        } else {
            paddingLength = (byte) getPaddingLength(sshKexAlgorithmNegotitation.c2sCipher.getBlockSize(), payload.length);
        }
        byte[] randomPadding = new byte[paddingLength];
        new SecureRandom().nextBytes(randomPadding);

        int packageLength = payload.length + paddingLength + 1;
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeInt(packageLength);
        sos.writeByte(paddingLength);
        sos.write(payload);
        sos.write(randomPadding);
        byte[] sshProtocolBytes = sos.toByteArray();
        sos.reset();
        if (null == sshKexAlgorithmNegotitation.c2sCipher) {
            logger.trace("[发送SSH未加密消息报文]总大小:{}, 原始报文:{}, 包序号:{}",
                    sshProtocolBytes.length,
                    SSHUtil.byteArrayToHex(sshProtocolBytes),
                    clientSequenceNumber
            );
            sos.write(sshProtocolBytes);
        } else {
            sshKexAlgorithmNegotitation.c2sMac.update(SSHUtil.int2ByteArray(clientSequenceNumber));
            sshKexAlgorithmNegotitation.c2sMac.update(sshProtocolBytes);
            byte[] mac = sshKexAlgorithmNegotitation.c2sMac.doFinal();
            byte[] encryptedSSHProtocolBytes = new byte[sshProtocolBytes.length];
            try {
                sshKexAlgorithmNegotitation.c2sCipher.update(sshProtocolBytes, 0, sshProtocolBytes.length, encryptedSSHProtocolBytes, 0);
            } catch (ShortBufferException e) {
                e.printStackTrace();
            }
            logger.trace("[发送SSH加密消息报文]总大小:{}, 原始报文:{}, 加密后报文:{}, 包序号:{}, MAC:{}",
                    encryptedSSHProtocolBytes.length + mac.length,
                    SSHUtil.byteArrayToHex(sshProtocolBytes) + "[" + sshProtocolBytes.length + "]",
                    SSHUtil.byteArrayToHex(encryptedSSHProtocolBytes) + "[" + encryptedSSHProtocolBytes.length + "]",
                    clientSequenceNumber,
                    SSHUtil.byteArrayToHex(mac) + "[" + mac.length + "]"
            );
            sos.write(encryptedSSHProtocolBytes);
            sos.write(mac);
        }
        socket.getOutputStream().write(sos.toByteArray());
        socket.getOutputStream().flush();
        if (clientSequenceNumber == Integer.MAX_VALUE) {
            clientSequenceNumber = 0;
        } else {
            clientSequenceNumber++;
        }
    }

    /**检查返回码*/
    public void checkExitStatus(byte[] payload) throws IOException {
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        int recipientChannel = sis.readInt();
        String type = sis.readSSHString().toString();
        if(null==type||type.isEmpty()){
            throw new SSHException("无法处理服务端SSH_MSG_CHANNEL_REQUEST消息!类型值为空!");
        }
        switch (type){
            case "exit-status":{
                sis.readBoolean();
                int exitStatus = sis.readInt();
                if(exitStatus!=0){
                    throw new SSHException("命令执行失败!返回状态码:"+exitStatus);
                }
            }break;
            case "exit-signal":{
                sis.readBoolean();
                SSHString signalName = sis.readSSHString();
                boolean coreDumped = sis.readBoolean();
                SSHString errorMessage = sis.readSSHString();
                throw new SSHException("命令执行失败!返回信号名称:"+signalName+",描述信息:"+errorMessage);
            }
            case "signal":{
                sis.readBoolean();
                SSHString signalName = sis.readSSHString();
                throw new SSHException("命令执行失败!返回信号名称:"+signalName);
            }
            default:{
                throw new SSHException("无法处理服务端SSH_MSG_CHANNEL_REQUEST消息!类型:"+type);
            }
        }
    }

    /**
     * 读取SSH协议包负载数据
     *
     * @return SSH协议负载数据
     */
    private byte[] doReadSSHProtocolPayload() throws IOException {
        if(!sshMessageCache.isEmpty()){
            return sshMessageCache.remove();
        }
        //记录原始字节数组
        ByteArrayOutputStream sshProtocolBytesBaos = new ByteArrayOutputStream();
        //读取第一个块,获取包大小
        int firstBlockSize = (null == sshKexAlgorithmNegotitation.s2cCipher ? 8 : sshKexAlgorithmNegotitation.s2cCipher.getBlockSize());
        byte[] firstBlock = new byte[firstBlockSize];
        sis.read(firstBlock);
        logger.trace("[读取SSH协议包第一个块]大小:{},内容:{}", firstBlock.length, Arrays.toString(firstBlock));
        sshProtocolBytesBaos.write(firstBlock);
        if (null != sshKexAlgorithmNegotitation.s2cCipher) {
            firstBlock = sshKexAlgorithmNegotitation.s2cCipher.update(firstBlock);
            logger.trace("[SSH协议包第一个块解密后]大小:{},内容:{}", firstBlock.length, Arrays.toString(firstBlock));
        }
        //获取包大小
        int packageLength = SSHUtil.byteArray2Int(firstBlock, 0, 4);
        logger.trace("[SSH协议包大小]计算总长度:{}",packageLength);
        //根据包大小获取剩余字节
        byte[] remainPackageBytes = new byte[packageLength - (firstBlockSize - 4)];
        if (remainPackageBytes.length > 0) {
            logger.trace("[SSH协议包大小]已读取字节大小:{},剩余读取字节大小:{}", firstBlockSize - 4, remainPackageBytes.length);
            sis.read(remainPackageBytes);
            sshProtocolBytesBaos.write(remainPackageBytes);
            if (null != sshKexAlgorithmNegotitation.s2cCipher) {
                remainPackageBytes = sshKexAlgorithmNegotitation.s2cCipher.update(remainPackageBytes);
            }
        }
        byte[] resolveBytes = new byte[firstBlockSize + remainPackageBytes.length];
        System.arraycopy(firstBlock, 0, resolveBytes, 0, firstBlockSize);
        if (remainPackageBytes.length > 0) {
            System.arraycopy(remainPackageBytes, 0, resolveBytes, firstBlockSize, remainPackageBytes.length);
        }
        byte[] sshProtocolBytes = sshProtocolBytesBaos.toByteArray();
        if (null == sshKexAlgorithmNegotitation.s2cMac) {
            logger.trace("[接收SSH未加密消息报文]总大小:{}, 原始报文:{}, 包序号:{}",
                    sshProtocolBytes.length,
                    SSHUtil.byteArrayToHex(sshProtocolBytes),
                    serverSequenceNumber);
            resolveBytes = sshProtocolBytes;
        } else {
            byte[] mac = new byte[sshKexAlgorithmNegotitation.s2cMac.getMacLength()];
            sis.read(mac);
            logger.trace("[接收SSH加密消息报文]总大小:{}, 原始报文:{}, 解密后报文:{}, 包序号:{}, MAC:{}",
                    sshProtocolBytes.length + mac.length,
                    SSHUtil.byteArrayToHex(sshProtocolBytes) + "[" + sshProtocolBytes.length + "]",
                    SSHUtil.byteArrayToHex(resolveBytes) + "[" + resolveBytes.length + "]",
                    serverSequenceNumber,
                    SSHUtil.byteArrayToHex(mac) + "[" + mac.length + "]");
            //校验mac
            sshKexAlgorithmNegotitation.s2cMac.update(SSHUtil.int2ByteArray(serverSequenceNumber));
            sshKexAlgorithmNegotitation.s2cMac.update(resolveBytes);
            byte[] verifyMac = sshKexAlgorithmNegotitation.s2cMac.doFinal();
            if (!Arrays.equals(mac, verifyMac)) {
                logger.warn("[服务端Mac校验失败]期望mac:{},实际mac:{}", SSHUtil.byteArrayToHex(mac), SSHUtil.byteArrayToHex(verifyMac));
                throw new SSHException("服务端Mac校验失败!");
            }
        }

        byte paddingLength = resolveBytes[4];
        byte[] payload = new byte[packageLength - paddingLength - 1];
        System.arraycopy(resolveBytes, 5, payload, 0, payload.length);
        if (null != sshKexAlgorithmNegotitation.compress) {
            payload = sshKexAlgorithmNegotitation.compress.decompress(payload);
        }
        if (serverSequenceNumber == Integer.MAX_VALUE) {
            serverSequenceNumber = 0;
        } else {
            serverSequenceNumber++;
        }
        return payload;
    }

    /**
     * 设置填充字节长度
     */
    private int getPaddingLength(int multiple, int playloadLength) {
        for (int i = 4; i < 128; i++) {
            int sum = 4 + 1 + playloadLength + i;
            if (sum % multiple == 0) {
                return i;
            }
        }
        throw new IllegalArgumentException("设置随机填充字节数组失败!");
    }
}