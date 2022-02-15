package cn.schoolwow.ssh.layer.transport.mac;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMacSHA1Mac extends SSHAlgorithmImpl implements SSHMac {
    @Override
    public Mac getMac(byte[] macKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(macKey,0, 20,"HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(secretKey);
        return mac;
    }

    @Override
    public int getKeySize() {
        return 20;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"hmac-sha1"};
    }
}