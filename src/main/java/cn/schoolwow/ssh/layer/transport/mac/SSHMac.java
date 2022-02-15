package cn.schoolwow.ssh.layer.transport.mac;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithm;

import javax.crypto.Mac;

public interface SSHMac extends SSHAlgorithm {
    /**
     * 获取客户端消息认证码算法
     * @param algorithmName 消息认证码算法
     * @param macKey 密钥
     * */
    Mac getMac(byte[] macKey) throws Exception;

    /**
     * 返回密钥长度
     * @param algorithmName 算法名称
     * */
    int getKeySize();
}