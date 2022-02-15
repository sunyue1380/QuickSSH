package cn.schoolwow.ssh.layer.transport.mac;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMacSHA512Mac extends SSHAlgorithmImpl implements SSHMac {
    @Override
    public Mac getMac(byte[] macKey) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(macKey,0, 64,"HmacSHA512");
        Mac serverMac = Mac.getInstance("HmacSHA512");
        serverMac.init(secretKey);
        return serverMac;
    }

    @Override
    public int getKeySize() {
        return 64;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"hmac-sha2-512"};
    }
}