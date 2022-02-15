package cn.schoolwow.ssh.layer.transport.kex;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.kex.KexResult;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;
import cn.schoolwow.ssh.layer.transport.digest.SSHDigest;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

public class DiffieHellmanExchangeKex extends SSHAlgorithmImpl implements Kex {
    private Logger logger = LoggerFactory.getLogger(DiffieHellmanExchangeKex.class);

    @Override
    public KexResult exchange(String V_C, String V_S, byte[] I_C, byte[] I_S, SSHSession sshSession) throws Exception {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        //客户端请求服务端生成素数
        int min = 1024, n = 2048, max = 4096;
        sos.writeByte(SSHMessageCode.SSH_MSG_KEX_DH_GEX_REQUEST.value);
        sos.writeInt(min);
        sos.writeInt(n);
        sos.writeInt(max);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());

        //接收服务端生成的p和g
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_KEX_DH_GEX_GROUP);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        BigInteger p = sis.readMPInt();
        BigInteger g = sis.readMPInt();

        //随机生成本地私钥x，然后生成对应的公钥e
        DHParameterSpec dhParameterSpec = new DHParameterSpec(p, g);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(dhParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        //获取公钥e
        DHPublicKey dhPublicKey = (DHPublicKey) keyPair.getPublic();
        BigInteger e = dhPublicKey.getY();

        //发送客户端公钥
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_KEX_DH_GEX_INIT.value);
        sos.writeMPInt(e);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());

        //接收服务端返回报文
        payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_KEX_DH_GEX_REPLY);
        sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        SSHString hostKey = sis.readSSHString();
        BigInteger f = sis.readMPInt();
        SSHString signatureOfH = sis.readSSHString();

        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(f, p, g);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverDHPublicKey = keyFactory.generatePublic(dhPublicKeySpec);
        keyAgreement.doPhase(serverDHPublicKey, true);
        byte[] secretBytes = keyAgreement.generateSecret();
        BigInteger K = new BigInteger(1,secretBytes);
        if(K.bitLength()<=0){
            throw new SSHException("K值bitLength长度为0");
        }

        sos.reset();
        sos.writeSSHString(new SSHString(V_C));
        sos.writeSSHString(new SSHString(V_S));
        sos.writeSSHString(new SSHString(I_C));
        sos.writeSSHString(new SSHString(I_S));
        sos.writeSSHString(hostKey);
        sos.writeInt(min);
        sos.writeInt(n);
        sos.writeInt(max);
        sos.writeMPInt(p);
        sos.writeMPInt(g);
        sos.writeMPInt(e);
        sos.writeMPInt(f);
        sos.writeMPInt(K);

        KexResult kexResult = new KexResult();
        kexResult.hostKey = hostKey.value;
        kexResult.concatenationOfH = sos.toByteArray();
        kexResult.K = K;
        kexResult.signatureOfH = signatureOfH.value;
        String digestName = algorithmName.substring(algorithmName.lastIndexOf("-") + 1);
        kexResult.messageDigest = SSHDigest.getDigest(digestName).getMessageDigest();
        return kexResult;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1"};
    }
}