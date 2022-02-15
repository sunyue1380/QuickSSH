package cn.schoolwow.ssh.layer.transport.encrypt;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher extends SSHAlgorithmImpl implements SSHCipher {
    @Override
    public Cipher getClientCipher(byte[] c2sIv, byte[] c2sKey) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(c2sKey,0, getKeySize(), "AES");
        Cipher encryptCipher = Cipher.getInstance("AES/"+getMode(algorithmName)+"/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(c2sIv,0,16);
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return encryptCipher;
    }

    @Override
    public Cipher getServerCipher(byte[] s2cIv, byte[] s2cKey) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(s2cKey,0, getKeySize(), "AES");
        Cipher descryptCipher = Cipher.getInstance("AES/"+getMode(algorithmName)+"/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(s2cIv,0,16);
        descryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return descryptCipher;
    }

    @Override
    public int getKeySize() {
        return Integer.parseInt(algorithmName.substring(3,algorithmName.indexOf("-")))/8;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc"};
    }

    private String getMode(String encryptAlgorithmName){
        if(encryptAlgorithmName.contains("@openssh.com")){
            encryptAlgorithmName = encryptAlgorithmName.substring(0,encryptAlgorithmName.indexOf("@openssh.com"));
        }
        String mode = encryptAlgorithmName.substring(encryptAlgorithmName.lastIndexOf("-")+1).toUpperCase();
        return mode.toUpperCase();
    }
}