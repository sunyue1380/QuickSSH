package cn.schoolwow.ssh.layer.channel;

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

/**本地端口转发*/
public class LocalForwardChannel extends AbstractChannel{
    private Logger logger = LoggerFactory.getLogger(LocalForwardChannel.class);

    /**本地端口转发线程池*/
    private ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    public LocalForwardChannel(SSHSession sshSession) {
        super(sshSession);
    }

    /**
     * 开启本地端口转发
     * @param localPort 本地监听端口
     * @param remoteAddress 转发到远程主机地址
     * @param remotePort 转发到远程主机端口
     * */
    public void localForward(int localPort, String remoteAddress, int remotePort) throws IOException {
        threadPoolExecutor.execute(()->{
            try {
                logger.debug("[开启本地端口转发]本地端口:{}, 远程主机地址:{}, 远程端口:{}", localPort, remoteAddress, remotePort);
                ServerSocket serverSocket = new ServerSocket(localPort);
                while(true){
                    Socket socket = serverSocket.accept();
                    threadPoolExecutor.execute(()->{
                        LocalForwardChannel localForwardChannel = new LocalForwardChannel(sshSession);
                        try {
                            localForwardChannel.openLocalForwardChannel(remoteAddress,remotePort,socket.getInetAddress().getHostAddress(),socket.getLocalPort());
                            threadPoolExecutor.execute(()->{
                                byte[] buffer = new byte[8192];
                                int length = 0;
                                try {
                                    while((length=socket.getInputStream().read(buffer,0,buffer.length))!=-1){
                                        localForwardChannel.writeChannelData(buffer,0,length);
                                    }
                                    socket.shutdownInput();
                                }catch (IOException e){
                                    e.printStackTrace();
                                }finally {
                                    try {
                                        localForwardChannel.closeChannel();
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }
                            });
                            threadPoolExecutor.execute(()->{
                                try {
                                    while(!socket.isOutputShutdown()){
                                        SSHString data = localForwardChannel.readChannelData();
                                        if(null!=data){
                                            socket.getOutputStream().write(data.value);
                                            socket.getOutputStream().flush();
                                        }else if(socket.isInputShutdown()){
                                            socket.shutdownOutput();
                                        }
                                    }
                                }catch (IOException e){
                                    e.printStackTrace();
                                }
                            });
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    /**关闭本地端口转发*/
    public void cancelLocalForward() throws IOException {
        threadPoolExecutor.shutdownNow();
    }

    /**创建本地端口转发频道*/
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
}