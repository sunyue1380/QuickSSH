package cn.schoolwow.ssh.util;

import org.junit.Test;

public class SSHUtilTest {

    @Test
    public void int2ByteArray() {
        byte[] s = new byte[]{0,0,3,-24};
        System.out.println(SSHUtil.byteArray2Int(s));
    }
}