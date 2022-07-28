package cn.schoolwow.ssh.stream;

import cn.schoolwow.ssh.domain.stream.DERClass;
import cn.schoolwow.ssh.domain.stream.DistinguishedEncodingRule;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.util.SSHUtil;

import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class SSHInputStreamImpl implements SSHInputStream {
    private DataInputStream dis;
    private BufferedReader br;

    public SSHInputStreamImpl(byte[] bytes){
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        this.dis = new DataInputStream(bais);
        this.br = new BufferedReader(new InputStreamReader(bais));
    }

    public SSHInputStreamImpl(InputStream in){
        this.dis = new DataInputStream(in);
        this.br = new BufferedReader(new InputStreamReader(in));
    }

    @Override
    public int available() throws IOException {
        return dis.available();
    }

    @Override
    public int read() throws IOException {
        return dis.read();
    }

    @Override
    public int read(byte[] b) throws IOException {
        int length = 0;
        while(length<b.length){
            length += dis.read(b, length, b.length-length);
        }
        if(length!=b.length){
            throw new IOException("读取字节数组失败！期望读取长度:" + b.length + ",实际读取长度:" + length);
        }
        return length;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int length = 0;
        while(length<b.length){
            length += dis.read(b, length + off, b.length - length - off);
        }
        if(length!=len){
            throw new IOException("读取字节数组失败！期望读取长度:" + len + ",实际读取长度:" + length);
        }
        return length;
    }

    @Override
    public int[] readBitByte() throws IOException{
        return readBitBytes(1);
    }

    @Override
    public int[] readBitBytes(int byteLength) throws IOException{
        int[] bits = new int[byteLength*8];
        for(int i=0;i<byteLength;i++){
            int b = dis.read();
            if(b==-1){
                throw new IOException("输入流读取到末尾了!");
            }
            for(int j=0;j<8;j++){
                int n = 0x01<<(7-j);
                int result = b&n;
                bits[i*8+j] = (result==n?1:0);
            }
        }
        return bits;
    }

    @Override
    public BigInteger readMPInt() throws IOException{
        int length = readInt();
        if(length==0){
            return null;
        }
        byte[] bytes = new byte[length];
        int bytesOfRead = dis.read(bytes);
        if(bytesOfRead!=bytes.length){
            throw new IOException("读取指定长度字节失败!期望字节长度:" + bytes.length + ",当前字节长度:" + bytesOfRead);
        }
        BigInteger bigInteger = new BigInteger(bytes);
        if(!Arrays.equals(bytes,bigInteger.toByteArray())){
            throw new IOException("Mpint类型转后前后不一致!期望字节数组:"+Arrays.toString(bytes)+",实际字节数组:"+Arrays.toString(bigInteger.toByteArray()));
        }
        return bigInteger;
    }

    @Override
    public SSHString readSSHString() throws IOException{
        SSHString sshString = new SSHString();
        int length = readInt();
        if(length>0){
            sshString.value = new byte[length];
            int bytesOfRead = read(sshString.value);
            if(bytesOfRead!=length){
                throw new IOException("读取指定长度字节失败!期望字节长度:" + length + ",当前字节长度:" + bytesOfRead);
            }
        }
        return sshString;
    }

    @Override
    public List<String> readNameList() throws IOException {
        SSHString sshString = readSSHString();
        if(null==sshString.value||sshString.value.length==0){
            return null;
        }
        String name = new String(sshString.value);
        return Arrays.asList(name.split(",",-1));
    }

    @Override
    public DistinguishedEncodingRule readDER() throws IOException {
        DistinguishedEncodingRule distinguishedEncodingRule = new DistinguishedEncodingRule();
        int[] bits = readBitByte();
        if(bits[0]==0){
            if(bits[1]==0){
                distinguishedEncodingRule.derClass = DERClass.COMMON;
            }else{
                distinguishedEncodingRule.derClass = DERClass.CUSTOM;
            }
        }else{
            if(bits[1]==0){
                distinguishedEncodingRule.derClass = DERClass.CONTEXT;
            }else{
                distinguishedEncodingRule.derClass = DERClass.PRIVATE;
            }
        }
        distinguishedEncodingRule.structureType = bits[2]==1;
        distinguishedEncodingRule.tagNumber = SSHUtil.getBitValue(bits,3,7);
        bits = readBitByte();
        int length = SSHUtil.getBitValue(bits,1,7);
        if(bits[0]==1){
            byte[] lengthBytes = new byte[length];
            read(lengthBytes);
            length = 0;
            for(int i=0;i<lengthBytes.length;i++){
                length += (lengthBytes[i]&0xFF) << ((lengthBytes.length-i-1)*8);
            }
        }
        distinguishedEncodingRule.contentLength = length;
        distinguishedEncodingRule.content = new byte[distinguishedEncodingRule.contentLength];
        read(distinguishedEncodingRule.content);
        return distinguishedEncodingRule;
    }

    @Override
    public void readFully(byte[] b) throws IOException {
        dis.readFully(b);
    }

    @Override
    public void readFully(byte[] b, int off, int len) throws IOException {
        dis.readFully(b,off,len);
    }

    @Override
    public int skipBytes(int n) throws IOException {
        return dis.skipBytes(n);
    }

    @Override
    public boolean readBoolean() throws IOException {
        return dis.readBoolean();
    }

    @Override
    public byte readByte() throws IOException {
        return dis.readByte();
    }

    @Override
    public int readUnsignedByte() throws IOException {
        return dis.readUnsignedByte();
    }

    @Override
    public short readShort() throws IOException {
        return dis.readShort();
    }

    @Override
    public int readUnsignedShort() throws IOException {
        return dis.readUnsignedShort();
    }

    @Override
    public char readChar() throws IOException {
        return dis.readChar();
    }

    @Override
    public int readInt() throws IOException {
        return dis.readInt();
    }

    @Override
    public long readLong() throws IOException {
        return dis.readLong();
    }

    @Override
    public float readFloat() throws IOException {
        return dis.readFloat();
    }

    @Override
    public double readDouble() throws IOException {
        return dis.readDouble();
    }

    @Override
    public String readLine() throws IOException {
        return br.readLine();
    }

    @Override
    public String readUTF() throws IOException {
        return dis.readUTF();
    }
}