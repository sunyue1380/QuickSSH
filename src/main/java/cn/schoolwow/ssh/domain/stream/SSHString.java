package cn.schoolwow.ssh.domain.stream;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**SSH协议字符串类型*/
public class SSHString {
    /**编码格式*/
    public Charset charset = StandardCharsets.UTF_8;

    /**字节数组*/
    public byte[] value;

    public SSHString(){

    }

    public SSHString(byte[] value){
        if(null!=value){
            this.value = value;
        }
    }

    public SSHString(String value){
        if(null!=value){
            this.value = value.getBytes(charset);
        }
    }

    public SSHString(String value, Charset charset){
        this.charset = charset;
        if(null!=value){
            this.value = value.getBytes(charset);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SSHString sshString = (SSHString) o;
        return Arrays.equals(value, sshString.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }

    @Override
    public String toString(){
        if(null==value){
            return null;
        }
        return new String(value,charset);
    }
}