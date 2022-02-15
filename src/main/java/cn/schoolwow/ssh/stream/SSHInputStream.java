package cn.schoolwow.ssh.stream;

import cn.schoolwow.ssh.domain.stream.DistinguishedEncodingRule;
import cn.schoolwow.ssh.domain.stream.SSHString;

import java.io.DataInput;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public interface SSHInputStream extends DataInput {
    /**
     * 剩余读取字节数
     * */
    int available() throws IOException;

    /**
     * 读取一个字节
     * */
    int read() throws IOException;

    /**
     * 读取指定长度的字节数组
     * */
    int read(byte b[]) throws IOException;

    /**
     * 读取指定长度和偏移的字节数组
     * */
    int read(byte b[], int off, int len) throws IOException;

    /**
     * 读取一个字节
     * */
    public int[] readBitByte() throws IOException;

    /**
     * 读取指定个数字节
     * */
    public int[] readBitBytes(int byteLength) throws IOException;

    /**
     * 读取MPInt类型
     * */
    public BigInteger readMPInt() throws IOException;

    /**
     * 读取字符串类型
     * */
    public SSHString readSSHString() throws IOException;

    /**
     * 读取名称列表类型
     * */
    public List<String> readNameList() throws IOException;

    /**
     * 读取DER格式
     * */
    public DistinguishedEncodingRule readDER() throws IOException;
}