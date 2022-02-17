package cn.schoolwow.ssh.util;

import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;

import java.io.IOException;

public class SSHUtil {
    /**检查返回码*/
    public static void checkExitStatus(byte[] payload) throws IOException {
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(5);
        String type = sis.readSSHString().toString();
        if(null==type||type.isEmpty()){
            throw new SSHException("无法处理服务端SSH_MSG_CHANNEL_REQUEST消息!类型值为空!");
        }
        switch (type){
            case "exit-status":{
                sis.readBoolean();
                int exitStatus = sis.readInt();
                if(exitStatus!=0){
                    throw new SSHException("命令执行失败!返回状态码:"+exitStatus);
                }
            }break;
            case "exit-signal":{
                sis.readBoolean();
                SSHString signalName = sis.readSSHString();
                boolean coreDumped = sis.readBoolean();
                SSHString errorMessage = sis.readSSHString();
                throw new SSHException("命令执行失败!返回信号名称:"+signalName+",描述信息:"+errorMessage);
            }
            case "signal":{
                sis.readBoolean();
                SSHString signalName = sis.readSSHString();
                throw new SSHException("命令执行失败!返回信号名称:"+signalName);
            }
            default:{
                throw new SSHException("无法处理服务端SSH_MSG_CHANNEL_REQUEST消息!类型:"+type);
            }
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