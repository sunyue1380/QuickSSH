package cn.schoolwow.ssh.layer.channel;

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

/**远程端口转发*/
public class RemoteForwardChannel extends AbstractChannel{
    private Logger logger = LoggerFactory.getLogger(RemoteForwardChannel.class);
    /**远程端口转发线程池*/
    private ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());

    /**远程端口转发列表*/
    private List<Integer> remoteForwardPortList = new ArrayList<>();

    public RemoteForwardChannel(SSHSession sshSession) {
        super(sshSession);
    }

    /**
     * 开启远程端口转发
     * @param remoteForwardPort 远程转发端口
     * @param localAddress 访问本地主机地址
     * @param localPort 访问本地主机端口
     * */
    public void remoteForward(int remoteForwardPort, String localAddress, int localPort) throws IOException {
        logger.debug("[开启远程端口转发]远程端口:{}, 本地主机地址:{}, 本地端口:{}", remoteForwardPort, localAddress, localPort);
        requestForward(remoteForwardPort);
        threadPoolExecutor.execute(()->{
            RemoteForwardChannel remoteForwardChannel = new RemoteForwardChannel(sshSession);
            try {
                remoteForwardChannel.receiveRemoteForwardChannel(remoteForwardPort);
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress(localAddress,localPort));
                threadPoolExecutor.execute(()->{
                    try {
                        while(!socket.isOutputShutdown()){
                            SSHString data = remoteForwardChannel.readChannelData();
                            if(null==data){
                                socket.shutdownOutput();
                            }else{
                                socket.getOutputStream().write(data.value);
                                socket.getOutputStream().flush();
                            }
                        }
                    }catch (IOException e){
                        e.printStackTrace();
                    }finally {
                        try {
                            remoteForwardChannel.closeChannel();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                });
                threadPoolExecutor.execute(()->{
                    byte[] buffer = new byte[8192];
                    int length = 0;
                    try {
                        while((length=socket.getInputStream().read(buffer,0,buffer.length))!=-1){
                            remoteForwardChannel.writeChannelData(buffer,0,length);
                        }
                        socket.shutdownInput();
                    }catch (IOException e){
                        e.printStackTrace();
                    }
                });
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }

    /**关闭远程端口转发*/
    public void cancelRemoteForward() throws IOException {
        cancelRequestForward();
        threadPoolExecutor.shutdownNow();
    }

    /**接收远程端口转发频道请求*/
    private void receiveRemoteForwardChannel(int remoteForwardPort) throws IOException {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_CHANNEL_OPEN);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        String requestType = sis.readSSHString().toString();
        if(!"forwarded-tcpip".equalsIgnoreCase(requestType)){
            throw new SSHException("远程端口转发接收频道类型不匹配!预期类型:forwarded-tcpip,实际类型:"+requestType);
        }
        this.recipientChannel = sis.readInt();
        sis.skipBytes(8);
        SSHString connectedAddress = sis.readSSHString();
        int connectedPort = sis.readInt();
        if(remoteForwardPort!=connectedPort){
            throw new SSHException("远程端口转发接收频道端口不匹配!预期端口"+remoteForwardPort+",实际端口:"+connectedPort);
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
        logger.debug("[接收远程转发频道成功]远程转发地址:{},端口:{},本地频道id:{},对端频道id:{}", connectedAddress, connectedPort, senderChannel, recipientChannel);
    }

    /**
     * 请求TCP/IP协议转发
     * */
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

    /**
     * 取消TCP/IP协议转发
     * @param port  服务端绑定端口
     * */
    private void cancelRequestForward() throws IOException {
        for(Integer remoteForwardPort:remoteForwardPortList){
            sos.reset();
            sos.writeByte(SSHMessageCode.SSH_MSG_GLOBAL_REQUEST.value);
            sos.writeSSHString(new SSHString("cancel-tcpip-forward"));
            sos.writeBoolean(true);
            sos.writeSSHString(new SSHString("0.0.0.0"));
            sos.writeInt(remoteForwardPort);
            sshSession.writeSSHProtocolPayload(sos.toByteArray());
            checkGlobalRequestWantReply();
            logger.debug("[取消服务端端口转发]服务端转发端口:{}",remoteForwardPort);
        }
    }
}