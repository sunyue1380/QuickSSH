package cn.schoolwow.ssh.domain;

import cn.schoolwow.ssh.domain.kex.SSHClientSupportAlgorithm;

import java.nio.file.Path;
import java.util.concurrent.ThreadPoolExecutor;

public class QuickSSHConfig {
    /**主机IP地址*/
    public String host;

    /**ssh端口*/
    public int port = 22;

    /**用户名*/
    public String username;

    /**publickey方式登录文件地址*/
    public Path publickeyFilePath;

    /**publickey方式登录文件短语*/
    public byte[] passphrase;

    /**用户密码*/
    public String password;

    /**连接超时时间(默认10秒)*/
    public int timeout = 10000;

    /**客户端支持算法*/
    public SSHClientSupportAlgorithm sshClientSupportAlgorithm;

    @Override
    public String toString() {
        return "{"
                + "主机IP地址:" + host + ","
                + "ssh端口:" + port + ","
                + "用户名:" + username + ","
                + "密码:" + password
                + "}";
    }
}
