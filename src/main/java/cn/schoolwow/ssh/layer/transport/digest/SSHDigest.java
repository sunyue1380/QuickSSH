package cn.schoolwow.ssh.layer.transport.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**消息摘要算法*/
public enum SSHDigest {
    MD5,
    SHA1,
    SHA256,
    SHA384,
    SHA512;

    public MessageDigest getMessageDigest() throws NoSuchAlgorithmException {
        MessageDigest messageDigest;
        switch (this){
            case MD5:{
                messageDigest = MessageDigest.getInstance("MD5");
            }break;
            case SHA1:{
                messageDigest = MessageDigest.getInstance("SHA");
            }break;
            case SHA256:{
                messageDigest = MessageDigest.getInstance("SHA-256");
            }break;
            case SHA384:{
                messageDigest = MessageDigest.getInstance("SHA-384");
            }break;
            case SHA512:{
                messageDigest = MessageDigest.getInstance("SHA-512");
            }break;
            default:{
                throw new IllegalArgumentException("不支持的算法!");
            }
        }
        return messageDigest;
    }

    public static SSHDigest getDigest(String digestName){
        for(SSHDigest digest: SSHDigest.values()){
            if(digest.name().equalsIgnoreCase(digestName)){
                return digest;
            }
        }
        throw new IllegalArgumentException("不支持的摘要算法!算法名称:"+digestName);
    }
}