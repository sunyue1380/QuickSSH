package cn.schoolwow.ssh.layer.transport.publickey;

import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

public class RSAHostKey extends SSHAlgorithmImpl implements SSHHostKey {
    @Override
    public byte[] formatPublicKey(PublicKey publicKey) throws Exception {
        RSAPublicKey rsaPublicKey = (java.security.interfaces.RSAPublicKey) publicKey;
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeSSHString(new SSHString("ssh-rsa"));
        sos.writeMPInt(rsaPublicKey.getPublicExponent());
        sos.writeMPInt(rsaPublicKey.getModulus());
        return sos.toByteArray();
    }

    @Override
    public PublicKey parsePublicKey(byte[] hostKey) throws Exception {
        SSHInputStream sis = new SSHInputStreamImpl(hostKey);
        SSHString type = sis.readSSHString();
        if(!"ssh-rsa".equals(type.toString())){
            throw new SSHException("解析公钥字节数组失败!期望值:ssh-rsa,实际值:"+type.toString());
        }
        BigInteger exponent = sis.readMPInt();
        BigInteger modulus = sis.readMPInt();
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1WithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] sign = signature.sign();
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeSSHString(new SSHString("ssh-rsa"));
        sos.writeSSHString(new SSHString(sign));
        return sos.toByteArray();
    }

    @Override
    public boolean verify(byte[] data, byte[] sign, PublicKey publicKey) throws Exception {
        SSHInputStream sis = new SSHInputStreamImpl(sign);
        SSHString rsaString = sis.readSSHString();
        if(!"ssh-rsa".equals(rsaString.toString())){
            throw new SSHException("ssh-rsa格式验签失败!");
        }
        sign = sis.readSSHString().value;
        Signature signature = Signature.getInstance("SHA1WithRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sign);
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"ssh-rsa"};
    }
}