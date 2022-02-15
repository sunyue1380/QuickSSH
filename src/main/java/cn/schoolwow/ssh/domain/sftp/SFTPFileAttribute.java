package cn.schoolwow.ssh.domain.sftp;

public class SFTPFileAttribute {
    /**属性标志*/
    public int flags;

    /**文件大小*/
    public long size;

    /**uid*/
    public int uid;

    /**gid*/
    public int gid;

    /**权限*/
    public int permissions;

    /**创建时间*/
    public int atime;

    /**修改时间*/
    public int mtime;

    @Override
    public String toString() {
        return "{"
                + "属性标志:" + Integer.toBinaryString(flags) + ","
                + "文件大小:" + size + ","
                + "uid:" + uid + ","
                + "gid:" + gid + ","
                + "权限:" + permissions + ","
                + "创建时间:" + atime + ","
                + "修改时间:" + mtime
                + "}";
    }
}