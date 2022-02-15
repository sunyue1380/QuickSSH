package cn.schoolwow.ssh.domain.kex;

import cn.schoolwow.ssh.layer.transport.compress.Compress;
import cn.schoolwow.ssh.layer.transport.compress.NoneCompress;
import cn.schoolwow.ssh.layer.transport.encrypt.AESCipher;
import cn.schoolwow.ssh.layer.transport.encrypt.SSHCipher;
import cn.schoolwow.ssh.layer.transport.encrypt.TripleDESWithCBCCipher;
import cn.schoolwow.ssh.layer.transport.kex.DiffieHellmanExchangeKex;
import cn.schoolwow.ssh.layer.transport.kex.DiffieHellmanKex;
import cn.schoolwow.ssh.layer.transport.kex.Kex;
import cn.schoolwow.ssh.layer.transport.mac.HMacSHA1Mac;
import cn.schoolwow.ssh.layer.transport.mac.HMacSHA256Mac;
import cn.schoolwow.ssh.layer.transport.mac.HMacSHA512Mac;
import cn.schoolwow.ssh.layer.transport.mac.SSHMac;
import cn.schoolwow.ssh.layer.transport.publickey.RSAHostKey;
import cn.schoolwow.ssh.layer.transport.publickey.SSHHostKey;

import java.util.ArrayList;
import java.util.List;

/**客户端支持算法*/
public class SSHClientSupportAlgorithm {
    /**支持的密钥交换算法*/
    public List<Kex> kexList = new ArrayList<>();

    /**PublicKey算法*/
    public List<SSHHostKey> hostKeyList = new ArrayList<>();

    /**支持的加密算法*/
    public List<SSHCipher> cipherList = new ArrayList<>();

    /**支持的消息认证算法*/
    public List<SSHMac> macList = new ArrayList<>();

    /**支持的压缩算法*/
    public List<Compress> compressList = new ArrayList<>();

    {
        kexList.add(new DiffieHellmanExchangeKex());
        kexList.add(new DiffieHellmanKex());

        hostKeyList.add(new RSAHostKey());

        cipherList.add(new AESCipher());
        cipherList.add(new TripleDESWithCBCCipher());

        macList.add(new HMacSHA1Mac());
        macList.add(new HMacSHA256Mac());
        macList.add(new HMacSHA512Mac());

        compressList.add(new NoneCompress());
    }
}