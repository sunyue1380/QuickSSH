package cn.schoolwow.ssh.domain.sftp;

public class SFTPFile {
    /**文件名*/
    public String fileName;

    /**扩展名*/
    public String longName;

    /**文件属性*/
    public SFTPFileAttribute attribute;

    /**是否为文件夹*/
    public boolean isDirectory(){
        return longName.charAt(0)=='d';
    }

    /**是否为文件*/
    public boolean isFile(){
        return longName.charAt(0)=='-';
    }

    /**是否为符号链接*/
    public boolean isSymbolicLink(){
        return longName.charAt(0)=='l';
    }

    @Override
    public String toString() {
        return "{"
                + "文件名:" + fileName + ","
                + "扩展名:" + longName + ","
                + "文件属性:" + attribute
                + "}";
    }
}