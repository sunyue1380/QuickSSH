package cn.schoolwow.ssh.layer.transport.encrypt;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithm;

import javax.crypto.Cipher;

/**SSH加密算法*/
public interface SSHCipher extends SSHAlgorithm {
    /**
     * 初始化客户端加密算法
     * @param c2sIV 客户端加密向量
     * @param c2sKey 客户端加密密钥
     * */
    Cipher getClientCipher(byte[] c2sIv, byte[] c2sKey) throws Exception;

    /**
     * 初始化服务端解密算法
     * @param s2cIV 服务端加密向量
     * @param s2cKey 服务端加密密钥
     * */
    Cipher getServerCipher(byte[] s2cIv, byte[] s2cKey) throws Exception;

    /**
     * 返回密钥长度
     * */
    int getKeySize();
}