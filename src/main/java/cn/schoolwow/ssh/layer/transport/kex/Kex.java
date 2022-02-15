package cn.schoolwow.ssh.layer.transport.kex;

import cn.schoolwow.ssh.domain.kex.KexResult;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.transport.SSHAlgorithm;

/**密钥交换算法*/
public interface Kex extends SSHAlgorithm {
    /**
     * 交换密钥
     * @param V_C 客户端版本
     * @param V_S 服务端版本
     * @param I_C 客户端算法交换报文
     * @param I_S 服务端算法交换报文
     * @param sshSession SSH会话
     * */
    KexResult exchange(String V_C, String V_S, byte[] I_C, byte[] I_S, SSHSession sshSession) throws Exception;
}