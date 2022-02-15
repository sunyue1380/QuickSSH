package cn.schoolwow.ssh.domain.kex;

import cn.schoolwow.ssh.layer.transport.compress.Compress;
import cn.schoolwow.ssh.layer.transport.encrypt.SSHCipher;
import cn.schoolwow.ssh.layer.transport.kex.Kex;
import cn.schoolwow.ssh.layer.transport.mac.SSHMac;
import cn.schoolwow.ssh.layer.transport.publickey.SSHHostKey;

import javax.crypto.Cipher;
import javax.crypto.Mac;

/**密钥交换阶段算法协商*/
public class SSHKexAlgorithmNegotitation {
    /**密钥交换算法实现*/
    public Kex kex;

    /**hostkey算法*/
    public SSHHostKey sshHostKey;

    /**加解密实现类*/
    public SSHCipher sshCipher;

    /**客户端加密*/
    public Cipher c2sCipher;

    /**服务端加密*/
    public Cipher s2cCipher;

    /**消息认证码实现类*/
    public SSHMac sshMac;

    /**客户端消息认证码*/
    public Mac c2sMac;

    /**服务端消息认证码*/
    public Mac s2cMac;

    /**压缩算法*/
    public Compress compress;
}