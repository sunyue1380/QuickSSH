package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.SSHClient;
import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * 本地端口转发
 */
public class LocalForwardChannel extends AbstractChannel {
    private Logger logger = LoggerFactory.getLogger(LocalForwardChannel.class);

    public LocalForwardChannel(SSHSession sshSession, SSHClient sshClient) {
        super(sshSession, sshClient);
        sshSession.quickSSHConfig.localForwardChannelThreadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Math.max(4,Runtime.getRuntime().availableProcessors()));
    }

    /**
     * 开启本地端口转发
     *
     * @param localPort     本地监听端口
     * @param remoteAddress 转发到远程主机地址
     * @param remotePort    转发到远程主机端口
     */
    public void localForward(int localPort, String remoteAddress, int remotePort) throws IOException {
        sshSession.quickSSHConfig.localForwardChannelThreadPoolExecutor.execute(new LocalForwardChannelThread(localPort, remoteAddress, remotePort));
    }

    @Override
    public void close() throws IOException {
        sshSession.quickSSHConfig.localForwardChannelThreadPoolExecutor.shutdownNow();
    }

    /**
     * 创建本地端口转发频道
     * @param connectAddress 远程IP地址
     * @param connectPort 远程IP地址端口
     * @param originatorAddress 本地IP地址
     * @param originatorPort 本地IP地址端口
     */
    private void openLocalForwardChannel(String connectAddress, int connectPort, String originatorAddress, int originatorPort) throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_OPEN.value);
        sos.writeSSHString(new SSHString("direct-tcpip"));
        int senderChannel = sshSession.senderChannel++;
        sos.writeInt(senderChannel);
        sos.writeInt(0x100000);
        sos.writeInt(0x100000);
        sos.writeSSHString(new SSHString(connectAddress));
        sos.writeInt(connectPort);
        sos.writeSSHString(new SSHString(originatorAddress));
        sos.writeInt(originatorPort);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        checkChannelOpen(senderChannel);
        logger.debug("[打开本地端口转发频道成功]转发到远程地址:{},端口:{},本地频道id:{},对端频道id:{}", connectAddress, connectPort, senderChannel, recipientChannel);
    }

    /**本地转发线程*/
    private class LocalForwardChannelThread implements Runnable {
        /**
         * 本地端口
         */
        private int localPort;

        /**
         * 远程主机地址
         */
        private String remoteAddress;

        /**
         * 远程主机端口
         */
        private int remotePort;

        public LocalForwardChannelThread(int localPort, String remoteAddress, int remotePort) {
            this.localPort = localPort;
            this.remoteAddress = remoteAddress;
            this.remotePort = remotePort;
        }

        @Override
        public void run() {
            logger.debug("[开启本地端口转发]本地端口:{}, 远程主机地址:{}, 远程端口:{}", localPort, remoteAddress, remotePort);
            try {
                ServerSocket serverSocket = new ServerSocket(localPort);
                while (true) {
                    Socket socket = serverSocket.accept();
                    logger.trace("[接收到本地请求]{}", socket);
                    LocalForwardChannel localForwardChannel = new LocalForwardChannel(sshSession, sshClient);
                    try {
                        localForwardChannel.openLocalForwardChannel(remoteAddress, remotePort, socket.getInetAddress().getHostAddress(), socket.getLocalPort());
                    } catch (IOException e) {
                        e.printStackTrace();
                        return;
                    }
                    //启动本地端口数据监听线程
                    sshSession.quickSSHConfig.localForwardChannelThreadPoolExecutor.execute(()->{
                        byte[] buffer = new byte[8192];
                        int length = 0;
                        try {
                            while ((length = socket.getInputStream().read(buffer, 0, buffer.length)) != -1) {
                                localForwardChannel.writeChannelData(buffer, 0, length);
                            }
                            socket.shutdownInput();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } finally {
                            try {
                                localForwardChannel.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                    });

                    //启动远程主机端口数据监听线程
                    sshSession.quickSSHConfig.localForwardChannelThreadPoolExecutor.execute(() -> {
                        while (socket.isConnected()&&!socket.isOutputShutdown()&&!socket.isClosed()) {
                            try {
                                SSHString data = localForwardChannel.readChannelData();
                                if (null != data) {
                                    socket.getOutputStream().write(data.value);
                                    socket.getOutputStream().flush();
                                }else{
                                    break;
                                }
                            }catch (IOException e){
                                e.printStackTrace();
                            }
                        }
                        try {
                            socket.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}