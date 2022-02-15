package cn.schoolwow.ssh.layer.transport.encrypt;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class TripleDESWithCBCCipher extends SSHAlgorithmImpl implements SSHCipher {

    @Override
    public Cipher getClientCipher(byte[] c2sIv, byte[] c2sKey) throws Exception{
        DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(c2sKey);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = secretKeyFactory.generateSecret(deSedeKeySpec);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(c2sIv,0,16);
        Cipher encryptCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return encryptCipher;
    }

    @Override
    public Cipher getServerCipher(byte[] s2cIv, byte[] s2cKey) throws Exception{
        DESedeKeySpec deSedeKeySpec = new DESedeKeySpec(s2cKey);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DESede");
        SecretKey secretKey = secretKeyFactory.generateSecret(deSedeKeySpec);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(s2cIv,0,16);
        Cipher descryptCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        descryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        return descryptCipher;
    }

    @Override
    public int getKeySize() {
        return 16;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"3des-cbc"};
    }
}