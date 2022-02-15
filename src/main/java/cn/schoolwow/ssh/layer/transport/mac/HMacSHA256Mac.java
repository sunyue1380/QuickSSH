package cn.schoolwow.ssh.layer.transport.mac;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMacSHA256Mac extends SSHAlgorithmImpl implements SSHMac {
    @Override
    public Mac getMac(byte[] macKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(macKey,0,32,"HmacSHA256");
        Mac serverMac = Mac.getInstance("HmacSHA256");
        serverMac.init(secretKey);
        return serverMac;
    }

    @Override
    public int getKeySize() {
        return 32;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"hmac-sha2-256"};
    }
}