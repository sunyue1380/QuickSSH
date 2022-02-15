package cn.schoolwow.ssh.domain.sftp;

public class SFTPFile {
    /**文件名*/
    public String fileName;

    /**扩展名*/
    public String longName;

    /**文件属性*/
    public SFTPFileAttribute attribute;

    @Override
    public String toString() {
        return "{"
                + "文件名:" + fileName + ","
                + "扩展名:" + longName + ","
                + "文件属性:" + attribute
                + "}";
    }
}