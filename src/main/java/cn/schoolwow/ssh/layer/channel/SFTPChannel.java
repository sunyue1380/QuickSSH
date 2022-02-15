package cn.schoolwow.ssh.layer.channel;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SFTPException;
import cn.schoolwow.ssh.domain.sftp.*;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SFTPChannel extends AbstracatChannel {
    private Logger logger = LoggerFactory.getLogger(SFTPChannel.class);

    private volatile int fxpId = 0;

    public SFTPChannel(SSHSession sshSession) throws IOException {
        super(sshSession);
        openSessionChannel();
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_REQUEST.value);
        sos.writeInt(recipientChannel);
        sos.writeSSHString(new SSHString("subsystem"));
        sos.writeBoolean(true);
        sos.writeSSHString(new SSHString("sftp"));
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        checkWantReply();

        //获取SFTP协议版本号
        sos.reset();
        sos.writeInt(5);
        sos.writeByte(FXPCode.SSH_FXP_INIT.value);
        sos.writeInt(3);
        logger.debug("[发送SFTP协议客户端版本号]{}",3);
        writeChannelData(sos.toByteArray());
        byte[] data = readChannelData().value;
        if(data[4]!=FXPCode.SSH_FXP_VERSION.value){
            throw new SFTPException("SFTP协议初始化失败!预期类型值:"+FXPCode.SSH_FXP_VERSION.value+",实际类型值:"+data[4]);
        }
        int version = SSHUtil.byteArray2Int(data,5,4);
        logger.debug("[接收SFTP协议服务端版本号]{}",version);
    }

    /**
     * 获取文件信息
     * @param path 文件路径
     * */
    public SFTPFileAttribute getSFTPFileAttribute(String path) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        writeFXP(FXPCode.SSH_FXP_STAT);
        SFTPFileAttribute sftpFileAttribute = handleSSH_FXP_ATTRS();
        return sftpFileAttribute;
    }

    /**
     * 设置文件属性
     * @param path 文件路径
     * @param sftpFileAttribute 文件属性(根据flag掩码设置属性，具体参阅draft-ietf-secsh-filexfer-01.txt第5章节)
     * */
    public void setSFTPFileAttribute(String path, SFTPFileAttribute sftpFileAttribute) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_SIZE.value)!=0){
            sos.writeLong(sftpFileAttribute.size);
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_UIDGID.value)!=0){
            sos.writeInt(sftpFileAttribute.uid);
            sos.writeInt(sftpFileAttribute.gid);
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_PERMISSIONS.value)!=0){
            sos.writeInt(sftpFileAttribute.permissions);
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_ACMODTIME.value)!=0){
            sos.writeInt(sftpFileAttribute.atime);
            sos.writeInt(sftpFileAttribute.mtime);
        }
        writeFXP(FXPCode.SSH_FXP_SETSTAT);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**
     * 读取文件
     * @param path 文件路径
     * */
    public byte[] readFile(String path) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        sos.writeInt(FXFCode.SSH_FXF_READ.value);
        sos.writeInt(0);
        writeFXP(FXPCode.SSH_FXP_OPEN);
        SSHString handle = handleSSH_FXP_HANDLE();
        try {
            sos.reset();
            sos.writeSSHString(handle);
            writeFXP(FXPCode.SSH_FXP_FSTAT);
            SFTPFileAttribute sftpFileAttribute = handleSSH_FXP_ATTRS();
            sos.reset();
            sos.writeSSHString(handle);
            sos.writeLong(0);
            sos.writeInt((int) sftpFileAttribute.size);
            writeFXP(FXPCode.SSH_FXP_READ);
            SSHString data = handleSSH_FXP_DATA();
            return data.value;
        }catch (IOException e){
            throw e;
        }finally {
            closeHandle(handle);
        }
    }

    /**
     * 读取文件
     * @param path 文件路径
     * @param offset 文件偏移
     * @param len 读取长度
     * */
    public byte[] readFile(String path, long offset, int len) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        sos.writeInt(FXFCode.SSH_FXF_READ.value);
        sos.writeInt(0);
        writeFXP(FXPCode.SSH_FXP_OPEN);
        SSHString handle = handleSSH_FXP_HANDLE();
        try {
            sos.reset();
            sos.writeSSHString(handle);
            sos.writeLong(offset);
            sos.writeInt(len);
            writeFXP(FXPCode.SSH_FXP_READ);
            SSHString data = handleSSH_FXP_DATA();
            return data.value;
        }catch (IOException e){
            throw e;
        }finally {
            closeHandle(handle);
        }
    }

    /**
     * 写入文件
     * @param path 文件路径
     * @param data 写入数据
     * @return 返回状态码
     * */
    public void writeFile(String path, byte[] data) throws IOException {
        writeFile(path,0,data);
    }

    /**
     * 写入文件
     * @param path 文件路径
     * @param offset 文件偏移
     * @param data 写入数据
     * @return 返回状态码
     * */
    public void writeFile(String path, long offset, byte[] data) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        sos.writeInt(FXFCode.SSH_FXF_CREAT.value|FXFCode.SSH_FXF_WRITE.value);
        sos.writeInt(FILEXFERCode.SSH_FILEXFER_ATTR_SIZE.value);
        sos.writeLong(data.length);
        writeFXP(FXPCode.SSH_FXP_OPEN);
        SSHString handle = handleSSH_FXP_HANDLE();
        try {
            sos.reset();
            sos.writeSSHString(handle);
            sos.writeLong(offset);
            sos.writeSSHString(new SSHString(data));
            writeFXP(FXPCode.SSH_FXP_WRITE);
            readFXP(FXPCode.SSH_FXP_STATUS);
        }catch (IOException e){
            throw e;
        }finally {
            closeHandle(handle);
        }
    }

    /**
     * 追加文件
     * @param path 文件路径
     * @param data 追加数据
     * @return 返回状态码
     * */
    public void appendFile(String path, byte[] data) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        sos.writeInt(FXFCode.SSH_FXF_WRITE.value|FXFCode.SSH_FXF_CREAT.value);
        sos.writeInt(0);
        writeFXP(FXPCode.SSH_FXP_OPEN);
        SSHString handle = handleSSH_FXP_HANDLE();
        try {
            sos.reset();
            sos.writeSSHString(handle);
            writeFXP(FXPCode.SSH_FXP_FSTAT);
            SFTPFileAttribute sftpFileAttribute = handleSSH_FXP_ATTRS();
            sos.reset();
            sos.writeSSHString(handle);
            sos.writeLong(sftpFileAttribute.size);
            sos.writeSSHString(new SSHString(data));
            writeFXP(FXPCode.SSH_FXP_WRITE);
            readFXP(FXPCode.SSH_FXP_STATUS);
        }catch (IOException e){
            throw e;
        }finally {
            closeHandle(handle);
        }
    }

    /**
     * 删除文件
     * @param path 文件路径
     * @return 返回状态码
     * */
    public void deleteFile(String path) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        writeFXP(FXPCode.SSH_FXP_REMOVE);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**
     * 重命名文件(文件夹)
     * @param oldPath 原文件路径
     * @param newPath 新文件路径
     * @return 返回状态码
     * */
    public void rename(String oldPath, String newPath) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(oldPath));
        sos.writeSSHString(new SSHString(newPath));
        writeFXP(FXPCode.SSH_FXP_RENAME);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**
     * 创建文件夹
     * @param path 文件夹路径
     * @return 返回状态码
     * */
    public void createDirectory(String path) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        sos.writeInt(0);
        writeFXP(FXPCode.SSH_FXP_MKDIR);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**
     * 扫描文件夹
     * @param path 文件夹路径
     * */
    public List<SFTPFile> scanDirectory(String path) throws IOException{
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        writeFXP(FXPCode.SSH_FXP_OPENDIR);
        SSHString handle = handleSSH_FXP_HANDLE();
        sos.reset();
        sos.writeSSHString(handle);
        writeFXP(FXPCode.SSH_FXP_READDIR);
        List<SFTPFile> sftpFileList = handleSSH_FXP_NAME();
        closeHandle(handle);
        return sftpFileList;
    }

    /**
     * 删除文件夹
     * <p>以下情况会导致删除文件夹失败</p>
     * <ul>
     *     <li>文件夹路径不存在</li>
     *     <li>文件夹非空</li>
     *     <li>指定路径为文件</li>
     * </ul>
     * @param path 文件夹路径
     * @return 返回状态码
     * */
    public void deleteDirectory(String path) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        sos.writeInt(0);
        writeFXP(FXPCode.SSH_FXP_RMDIR);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**
     * 读取符号连接
     * @param symbolicLinkPath 符号链接路径
     * @return 符号链接实际路径
     * */
    public String readSymbolicLinkPath(String symbolicLinkPath) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(symbolicLinkPath));
        writeFXP(FXPCode.SSH_FXP_READLINK);
        List<SFTPFile> sftpFileList = handleSSH_FXP_NAME();
        if(sftpFileList.isEmpty()){
            return null;
        }
        return sftpFileList.get(0).fileName;
    }

    /**
     * 创建符号连接
     * @param symbolicLinkPath 符号链接路径
     * @param targetPath 符号链接指向路径
     * @return 符号链接实际路径
     * */
    public void createSymbolicLinkPath(String symbolicLinkPath, String targetPath) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(symbolicLinkPath));
        sos.writeSSHString(new SSHString(targetPath));
        writeFXP(FXPCode.SSH_FXP_SYMLINK);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**
     * 获取真实路径(例如输入..,返回上级目录)
     * @param path 文件路径
     * */
    public String canonicalize(String path) throws IOException {
        sos.reset();
        sos.writeSSHString(new SSHString(path));
        writeFXP(FXPCode.SSH_FXP_REALPATH);
        List<SFTPFile> sftpFileList = handleSSH_FXP_NAME();
        if(sftpFileList.isEmpty()){
            return null;
        }
        return sftpFileList.get(0).fileName;
    }

    /**处理SSH_FXP_HANDLE响应*/
    private SSHString handleSSH_FXP_HANDLE() throws IOException {
        SSHInputStream sis = readFXP(FXPCode.SSH_FXP_HANDLE);
        return sis.readSSHString();
    }

    /**处理SSH_FXP_HANDLE响应*/
    private SSHString handleSSH_FXP_DATA() throws IOException {
        SSHInputStream sis = readFXP(FXPCode.SSH_FXP_DATA);
        return sis.readSSHString();
    }

    /**处理handleSSH_FXP_NAME响应*/
    private List<SFTPFile> handleSSH_FXP_NAME() throws IOException {
        SSHInputStream sis = readFXP(FXPCode.SSH_FXP_NAME);
        int count = sis.readInt();
        List<SFTPFile> sftpFileList = new ArrayList<>(count);
        for(int i=0;i<count;i++){
            SFTPFile sftpFile = new SFTPFile();
            sftpFile.fileName = sis.readSSHString().toString();
            sftpFile.longName = sis.readSSHString().toString();
            sftpFile.attribute = getSFTPFileAttribute(sis);
            if(".".equals(sftpFile.fileName)||"..".equals(sftpFile.fileName)){
                //跳过当前目录和上级目录
                continue;
            }
            sftpFileList.add(sftpFile);
        }
        return sftpFileList;
    }

    /**处理handleSSH_FXP_ATTRS响应*/
    private SFTPFileAttribute handleSSH_FXP_ATTRS() throws IOException {
        SSHInputStream sis = readFXP(FXPCode.SSH_FXP_ATTRS);
        return getSFTPFileAttribute(sis);
    }

    /**获取SFTP文件*/
    private SFTPFileAttribute getSFTPFileAttribute(SSHInputStream sis) throws IOException{
        SFTPFileAttribute sftpFileAttribute = new SFTPFileAttribute();
        sftpFileAttribute.flags = sis.readInt();
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_SIZE.value)!=0){
            sftpFileAttribute.size = sis.readLong();
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_UIDGID.value)!=0){
            sftpFileAttribute.uid = sis.readInt();
            sftpFileAttribute.gid = sis.readInt();
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_PERMISSIONS.value)!=0){
            sftpFileAttribute.permissions = sis.readInt();
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_ACMODTIME.value)!=0){
            sftpFileAttribute.atime = sis.readInt();
            sftpFileAttribute.mtime = sis.readInt();
        }
        if((sftpFileAttribute.flags&FILEXFERCode.SSH_FILEXFER_ATTR_EXTENDED.value)!=0){
            int extendedCount = sis.readInt();
            for(int j=0;j<extendedCount;j++){
                sis.readSSHString();//extended_type
                sis.readSSHString();//extended_data
            }
        }
        return sftpFileAttribute;
    }

    /**关闭文件句柄*/
    private void closeHandle(SSHString handle) throws IOException {
        sos.reset();
        sos.writeSSHString(handle);
        writeFXP(FXPCode.SSH_FXP_CLOSE);
        readFXP(FXPCode.SSH_FXP_STATUS);
    }

    /**发送FXP消息*/
    private SSHInputStream readFXP(FXPCode expectFXPType) throws IOException {
        byte[] data = readChannelData().value;
        FXPCode fxpCode = FXPCode.getFXPCode(data[4]);
        int fxpId = SSHUtil.byteArray2Int(data,5,4);
        logger.trace("[接收FXP消息]id:{}, 类型:{}", fxpId, fxpCode);
        while(fxpId!=this.fxpId&&!expectFXPType.equals(fxpCode)){
            logger.warn("[接收非预期SFTP消息]预期id:{}, 实际id:{}, 预期类型:{}, 实际类型:{}", this.fxpId, fxpId, expectFXPType, fxpCode);
            data = readChannelData().value;
            fxpCode = FXPCode.getFXPCode(data[4]);
            fxpId = SSHUtil.byteArray2Int(data,5,4);
            logger.trace("[接收FXP消息]id:{}, 类型:{}", fxpId, fxpCode);
        }
        SSHInputStream sis = new SSHInputStreamImpl(data);
        sis.skipBytes(9);
        if(FXPCode.SSH_FXP_STATUS.equals(fxpCode)){
            int errorCode = sis.readInt();
            if(errorCode==0){
                return sis;
            }
            String description = sis.readSSHString().toString();
            throw new SFTPException(errorCode, description);
        }
        return sis;
    }

    /**发送FXP消息*/
    private void writeFXP(FXPCode fxpCode) throws IOException {
        byte[] data = sos.toByteArray();
        sos.reset();
        sos.writeInt(data.length+5);
        sos.writeByte(fxpCode.value);
        sos.writeInt(++fxpId);
        sos.write(data);
        writeChannelData(sos.toByteArray());
        logger.trace("[发送FXP消息]id:{}, 类型:{}",this.fxpId, fxpCode);
    }

    private void openSessionChannel() throws IOException {
        sos.reset();
        sos.writeByte(SSHMessageCode.SSH_MSG_CHANNEL_OPEN.value);
        sos.writeSSHString(new SSHString("session"));
        sos.writeInt(senderChannel);
        sos.writeInt(0x100000);
        sos.writeInt(0x4000);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
        checkChannelOpen();
    }
}