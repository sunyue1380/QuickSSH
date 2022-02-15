package cn.schoolwow.ssh.layer.transport.publickey;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithm;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SSHHostKey extends SSHAlgorithm {
    /**
     * 格式化公钥
     * */
    byte[] formatPublicKey(PublicKey publicKey) throws Exception;

    /**
     * 解析公钥字节数组
     * */
    PublicKey parsePublicKey(byte[] hostKey) throws Exception;

    /**
     * 私钥加签
     * @param data 内容
     * @param privateKey 私钥
     * */
    byte[] sign(byte[] data, PrivateKey privateKey) throws Exception;

    /**
     * 公钥验签
     * @param data 内容
     * @param sign 签名
     * @param publicKey 公钥
     * */
    boolean verify(byte[] data, byte[] sign, PublicKey publicKey) throws Exception;
}