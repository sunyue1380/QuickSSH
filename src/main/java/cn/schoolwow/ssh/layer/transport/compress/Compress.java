package cn.schoolwow.ssh.layer.transport.compress;

import cn.schoolwow.ssh.layer.transport.SSHAlgorithm;

/**SSH压缩算法*/
public interface Compress extends SSHAlgorithm {
    /**
     * 压缩数据
     * */
    byte[] compress(byte[] data);

    /**
     * 解压缩数据
     * */
    byte[] decompress(byte[] data);
}