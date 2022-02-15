package cn.schoolwow.ssh.layer.transport.compress;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;

public class NoneCompress extends SSHAlgorithmImpl implements Compress{
    @Override
    public byte[] compress(byte[] data) {
        return data;
    }

    @Override
    public byte[] decompress(byte[] data) {
        return data;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"none"};
    }
}