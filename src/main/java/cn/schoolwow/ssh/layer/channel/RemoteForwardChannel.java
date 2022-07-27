package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.SSHClient;
import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * 远程端口转发
 */
public class RemoteForwardChannel extends AbstractChannel {
    private Logger logger = LoggerFactory.getLogger(RemoteForwardChannel.class);

    /**
     * 远程端口转发列表
     */
    private List<Integer> remoteForwardPortList = new ArrayList<>();

    public RemoteForwardChannel(SSHSession sshSession, SSHClient sshClient) {
        super(sshSession, sshClient);
        sshSession.quickSSHConfig.remoteForwardChannelThreadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Math.max(4,Runtime.getRuntime().availableProcessors()));
    }

    /**
     * 开启远程端口转发
     *
     * @param remoteForwardPort 远程转发端口
     * @param localAddress      访问本地主机地址
     * @param localPort         访问本地主机端口
     */
    public void remoteForward(int remoteForwardPort, String localAddress, int localPort) throws IOException {
        sshSession.quickSSHConfig.remoteForwardChannelThreadPoolExecutor.execute(new RemoteForwardChannelThread(remoteForwardPort, localAddress, localPort));
    }

    @Override
    public void closeChannel() throws IOException {
        for (Integer remoteForwardPort : remoteForwardPortList) {
            sos.reset();
            sos.writeByte(SSHMessageCode.SSH_MSG_GLOBAL_REQUEST.value);
            sos.writeSSHString(new SSHString("cancel-tcpip-forward"));
            sos.writeBoolean(true);
            sos.writeSSHString(new SSHString("0.0.0.0"));
            sos.writeInt(remoteForwardPort);
            sshSession.writeSSHProtocolPayload(sos.toByteArray());
            checkGlobalRequestWantReply();
            logger.debug("[取消服务端端口转发]服务端转发端口:{}", remoteForwardPort);
        }
        sshSession.quickSSHConfig.remoteForwardChannelThreadPoolExecutor.shutdownNow();
    }

    /**
     * 接收远程端口转发频道请求
     */
    private void receiveRemoteForwardChannel(int remoteForwardPort) throws IOException {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_OPEN);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        String requestType = sis.readSSHString().toString();
        if (!"forwarded-tcpip".equalsIgnoreCase(requestType)) {
            throw new SSHException("远程端口转发接收频道类型不匹配!预期类型:forwarded-tcpip,实际类型:" + requestType);
        }
        this.recipientChannel = sis.readInt();
        sis.skipBytes(8);
        SSHString connectedAddress = sis.readSSHString();
        int connectedPort = sis.readInt();
        if (remoteForwardPort != connectedPort) {
            throw new SSHException("远程端口转发接收频道端口不匹配!预期端口:" + remoteForwardPort + ",实际端口:" + connectedPort);
        }
        SSHString originatorAddress = sis.readSSHString();
        int originatorPort = sis.readInt();

        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.value);
        sos.writeInt(recipientChannel);
        this.senderChannel = sshSession.recipientChannel++;
        sos.writeInt(this.senderChannel);
        sos.writeInt(0x100000);
        sos.writeInt(0x100000);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        logger.debug("[接收远程端口转发请求]远程转发地址:{},端口:{},本地端口:{},本地频道id:{},对端频道id:{}", connectedAddress, connectedPort, originatorPort, senderChannel, recipientChannel);
    }

    /**
     * 请求TCP/IP协议转发
     */
    private void requestForward(int remoteForwardPort) throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_GLOBAL_REQUEST.value);
        sos.writeSSHString(new SSHString("tcpip-forward"));
        sos.writeBoolean(true);
        //远程端口转发只能在转发机器本地监听
        sos.writeSSHString(new SSHString("127.0.0.1"));
        sos.writeInt(remoteForwardPort);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_REQUEST_SUCCESS);
        remoteForwardPortList.add(remoteForwardPort);
    }

    /**远程转发线程*/
    private class RemoteForwardChannelThread implements Runnable {
        /**
         * 远程主机监听端口
         */
        private int remoteForwardPort;

        /**
         * 本地IP地址
         */
        private String localAddress;

        /**
         * 本地IP端口
         */
        private int localPort;

        public RemoteForwardChannelThread(int remoteForwardPort, String localAddress, int localPort) {
            this.remoteForwardPort = remoteForwardPort;
            this.localAddress = localAddress;
            this.localPort = localPort;
        }

        @Override
        public void run() {
            logger.debug("[开启远程端口转发]远程端口:{}, 本地主机地址:{}, 本地端口:{}", remoteForwardPort, localAddress, localPort);
            try {
                requestForward(remoteForwardPort);
                RemoteForwardChannel remoteForwardChannel = new RemoteForwardChannel(sshSession, sshClient);
                while(true){
                    remoteForwardChannel.receiveRemoteForwardChannel(remoteForwardPort);
                    sshSession.quickSSHConfig.remoteForwardChannelThreadPoolExecutor.execute(()->{
                        Socket socket = new Socket();
                        try {
                            socket.connect(new InetSocketAddress(localAddress, localPort),5000);
                        } catch (IOException e) {
                            e.printStackTrace();
                            return;
                        }
                        //开启远程端口数据监听线程
                        sshSession.quickSSHConfig.remoteForwardChannelThreadPoolExecutor.execute(() -> {
                            try {
                                while (true) {
                                    SSHString data = remoteForwardChannel.readChannelData();
                                    if (null == data) {
                                        socket.close();
                                        break;
                                    } else {
                                        socket.getOutputStream().write(data.value);
                                        socket.getOutputStream().flush();
                                    }
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            } finally {
                                try {
                                    remoteForwardChannel.closeChannel();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                        //开启本地端口数据监听线程
                        sshSession.quickSSHConfig.remoteForwardChannelThreadPoolExecutor.execute(() -> {
                            byte[] buffer = new byte[8192];
                            int length = 0;
                            try {
                                while(!remoteForwardChannel.isChannelClosed()){
                                    while ((length = socket.getInputStream().read(buffer, 0, buffer.length)) != -1) {
                                        remoteForwardChannel.writeChannelData(buffer, 0, length);
                                    }
                                }
                            } catch (IOException e) {
                                e.printStackTrace();
                            }finally {
                                try {
                                    socket.close();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    });
                }
            }catch (IOException e){
                e.printStackTrace();
            }
        }
    }
}