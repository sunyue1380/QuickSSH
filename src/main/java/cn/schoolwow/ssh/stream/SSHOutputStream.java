package cn.schoolwow.ssh.stream;

import cn.schoolwow.ssh.domain.stream.SSHString;

import java.io.DataOutput;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public interface SSHOutputStream extends DataOutput{
    /**
     * 写入一行
     * */
    public void writeLine(String line) throws IOException;

    /**
     * 写入多精度整形
     * */
    public void writeMPInt(BigInteger e) throws IOException;

    /**
     * 写入字符串类型
     * */
    public void writeSSHString(SSHString sshString) throws IOException;

    /**
     * 写入字符串类型
     * */
    public void writeNameList(List<String> nameList) throws IOException;

    /**
     * 刷新缓冲区
     * */
    public void flush() throws IOException;

    /**
     * 重置大小
     * */
    public void reset();

    /**
     * 已写入大小
     * */
    public int size();

    /**
     * 转换成字节数组
     * */
    public byte[] toByteArray();
}