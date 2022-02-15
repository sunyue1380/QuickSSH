package cn.schoolwow.ssh.handler;

import cn.schoolwow.ssh.layer.SSHSession;

public interface Handler {
    /**
     * 处理方法
     * @param sshSession SSH会话
     * @return 下一个处理器
     * */
    Handler handle(SSHSession sshSession) throws Exception;
}