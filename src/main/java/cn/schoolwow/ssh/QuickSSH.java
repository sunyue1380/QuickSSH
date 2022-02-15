package cn.schoolwow.ssh;

import cn.schoolwow.ssh.domain.QuickSSHConfig;
import cn.schoolwow.ssh.domain.kex.SSHClientSupportAlgorithm;
import cn.schoolwow.ssh.layer.SSHSession;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class QuickSSH {
    private QuickSSHConfig quickSSHConfig = new QuickSSHConfig();

    public static QuickSSH newInstance(){
        return new QuickSSH();
    }

    public QuickSSH host(String host){
        quickSSHConfig.host = host;
        return this;
    }

    public QuickSSH port(int port){
        quickSSHConfig.port = port;
        return this;
    }

    /**指定用户名*/
    public QuickSSH username(String username){
        quickSSHConfig.username = username;
        return this;
    }

    /**指定publickey方式登录的私钥文件路径*/
    public QuickSSH publickey(String publickeyFilePath){
        quickSSHConfig.publickeyFilePath = Paths.get(publickeyFilePath);
        if(Files.notExists(quickSSHConfig.publickeyFilePath)){
            throw new RuntimeException("私钥文件不存在!文件路径:"+publickeyFilePath);
        }
        return this;
    }

    /**指定publickey方式登录的私钥文件路径和私钥短语*/
    public QuickSSH publickey(String publickeyFilePath, String passphrase){
        quickSSHConfig.publickeyFilePath = Paths.get(publickeyFilePath);
        if(Files.notExists(quickSSHConfig.publickeyFilePath)){
            throw new RuntimeException("私钥文件不存在!文件路径:"+publickeyFilePath);
        }
        quickSSHConfig.passphrase = passphrase.getBytes(StandardCharsets.UTF_8);
        return this;
    }

    /**指定password方式登录的用户密码*/
    public QuickSSH password(String password){
        quickSSHConfig.password = password;
        return this;
    }

    /**指定连接超时时间(ms)*/
    public QuickSSH timeout(int timeout){
        quickSSHConfig.timeout = timeout;
        return this;
    }

    /**指定客户端支持算法*/
    public QuickSSH sshClientSupportAlgorithm(SSHClientSupportAlgorithm sshClientSupportAlgorithm){
        quickSSHConfig.sshClientSupportAlgorithm = sshClientSupportAlgorithm;
        return this;
    }

    public SSHClient build() throws IOException {
        if(null==quickSSHConfig.sshClientSupportAlgorithm){
            quickSSHConfig.sshClientSupportAlgorithm = new SSHClientSupportAlgorithm();
        }
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(quickSSHConfig.host,quickSSHConfig.port),quickSSHConfig.timeout);
        SSHSession sshSession = new SSHSession(socket, quickSSHConfig);
        return new SSHClient(sshSession);
    }
}
