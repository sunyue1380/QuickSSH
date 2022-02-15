package cn.schoolwow.ssh.stream;

import cn.schoolwow.ssh.domain.stream.SSHString;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public class SSHOutputStreamImpl implements SSHOutputStream {
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private DataOutputStream dos = new DataOutputStream(baos);

    public SSHOutputStreamImpl(){

    }

    @Override
    public void writeLine(String line) throws IOException {
        baos.write((line+"\r\n").getBytes());
    }

    @Override
    public void writeMPInt(BigInteger e) throws IOException {
        byte[] bytes = e.toByteArray();
        writeInt(bytes.length);
        write(bytes);
    }

    @Override
    public void writeSSHString(SSHString sshString) throws IOException {
        if(null==sshString||null==sshString.value||sshString.value.length==0){
            writeInt(0);
        }else{
            writeInt(sshString.value.length);
            write(sshString.value);
        }
    }

    @Override
    public void writeNameList(List<String> nameList) throws IOException {
        if(null==nameList||nameList.isEmpty()){
            writeInt(0);
        }else{
            StringBuilder builder = new StringBuilder();
            for(String name:nameList){
                builder.append(name+",");
            }
            builder.deleteCharAt(builder.length()-1);
            writeSSHString(new SSHString(builder.toString()));
        }
    }

    @Override
    public void flush() throws IOException {
        baos.flush();
    }

    @Override
    public void reset() {
        baos.reset();
    }

    @Override
    public int size() {
        return baos.size();
    }

    @Override
    public byte[] toByteArray() {
        return baos.toByteArray();
    }

    @Override
    public void write(int b) throws IOException {
        dos.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        dos.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        dos.write(b,off,len);
    }

    @Override
    public void writeBoolean(boolean v) throws IOException {
        dos.writeBoolean(v);
    }

    @Override
    public void writeByte(int v) throws IOException {
        dos.writeByte(v);
    }

    @Override
    public void writeShort(int v) throws IOException {
        dos.writeShort(v);
    }

    @Override
    public void writeChar(int v) throws IOException {
        dos.writeChar(v);
    }

    @Override
    public void writeInt(int v) throws IOException {
        dos.writeInt(v);
    }

    @Override
    public void writeLong(long v) throws IOException {
        dos.writeLong(v);
    }

    @Override
    public void writeFloat(float v) throws IOException {
        dos.writeFloat(v);
    }

    @Override
    public void writeDouble(double v) throws IOException {
        dos.writeDouble(v);
    }

    @Override
    public void writeBytes(String s) throws IOException {
        dos.writeBytes(s);
    }

    @Override
    public void writeChars(String s) throws IOException {
        dos.writeChars(s);
    }

    @Override
    public void writeUTF(String s) throws IOException {
        dos.writeUTF(s);
    }
}