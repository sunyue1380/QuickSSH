package cn.schoolwow.ssh.domain.kex;

import java.math.BigInteger;
import java.security.MessageDigest;

/**密钥交换输出结果*/
public class KexResult {
    /**共享密钥k*/
    public BigInteger K;

    /**哈希算法*/
    public MessageDigest messageDigest;

    /**hostKey字节数组*/
    public byte[] hostKey;

    /**H的签名*/
    public byte[] signatureOfH;

    /**H哈希之前拼接字节数组*/
    public byte[] concatenationOfH;
}