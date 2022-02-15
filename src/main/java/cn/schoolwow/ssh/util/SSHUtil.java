package cn.schoolwow.ssh.util;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.layer.SSHSession;

import java.io.IOException;

public class SSHUtil {
    public static void readAllSSHMessage(SSHSession sshSession) throws IOException {
        while(true){
            byte[] payload = sshSession.readSSHProtocolPayload();
            System.out.println("接收SSH消息:"+ SSHMessageCode.getSSHMessageCode(payload[0]));
        }
    }

    /**int转字节数组*/
    public static byte[] int2ByteArray(int value){
        byte[] intBytes = new byte[4];
        intBytes[0] = (byte) (value>>>24);
        intBytes[1] = (byte) (value>>>16);
        intBytes[2] = (byte) (value>>>8);
        intBytes[3] = (byte) value;
        return intBytes;
    }

    /**字节数组转int*/
    public static int byteArray2Int(byte[] bytes){
        return byteArray2Int(bytes,0,bytes.length);
    }

    /**字节数组转int*/
    public static int byteArray2Int(byte[] bytes, int offset, int length){
        int intValue = 0;
        for(int i=offset;i<offset+length;i++){
            intValue += (bytes[i]&0xFF) << ((offset+length-i-1)*8);
        }
        return intValue;
    }

    /**
     * 字节数组转十六进制
     */
    public static String byteArrayToHex(byte[] bytes) {
        if(null==bytes||bytes.length==0){
            return "null";
        }
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString().toUpperCase();
    }

    /**
     * 十六进制字符串转字节数组
     */
    public static byte[] hexToByteArray(String hex) {
        if(null==hex||hex.isEmpty()){
            return null;
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0, j = 0; j < result.length; i += 2,j++) {
            result[j] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }

    /**获取二进制位值，前闭后闭*/
    public static int getBitValue(int[] bits, int startIndex, int endIndex){
        if(startIndex<0||endIndex<0){
            throw new IllegalArgumentException("startIndex和endIndex必须大于0!");
        }
        if(startIndex>endIndex){
            throw new IllegalArgumentException("startIndex必须小于等于end!");
        }
        if(startIndex==endIndex){
            return bits[startIndex];
        }
        int v = 0;
        int length = endIndex-startIndex;
        for(int i=startIndex;i<=endIndex;i++){
            v = v | (bits[i]<<(length-(i-startIndex)));
        }
        if(v>(0x01<<(length+1))){
            StringBuilder builder = new StringBuilder();
            for(int b:bits){
                builder.append(b);
            }
            throw new IllegalArgumentException("数据解析失败!当前计算值:"+v+",当前数组:"+builder.toString()+",开始索引:"+startIndex+",结束索引:"+endIndex);
        }
        return v;
    }
}