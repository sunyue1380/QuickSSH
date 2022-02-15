package cn.schoolwow.ssh;

import cn.schoolwow.ssh.domain.sftp.SFTPFile;
import cn.schoolwow.ssh.domain.sftp.SFTPFileAttribute;
import cn.schoolwow.ssh.layer.channel.SFTPChannel;
import cn.schoolwow.ssh.layer.channel.SessionChannel;
import org.aeonbits.owner.ConfigCache;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class QuickSSHTest {
    private static Account account = ConfigCache.getOrCreate(Account.class);

    @Test
    public void passwordAuthenticationTest() throws IOException {
        QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
    }

    @Test
    public void publickeyAuthenticationTest() throws IOException {
        QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .publickey(System.getProperty("user.dir") + "/" + account.publickeyFilePath(),account.publickeyPassphrase())
                .build();
    }

    @Test
    public void sessionChannelTest() throws IOException {
        SSHClient sshClient = QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
        Assert.assertEquals("/root",sshClient.exec("pwd"));
        Assert.assertEquals("root",sshClient.exec("echo $USER"));
        sshClient.disconnect();
    }

    @Test
    public void sftp() throws IOException {
        SSHClient sshClient = QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
        String directory = "/opt/sftp";
        sshClient.exec("rm -R " + directory + " && mkdir -p " + directory + "/");

        SFTPChannel sftpChannel = sshClient.sftp();
        sftpChannel.createDirectory(directory + "/aa");
        List<SFTPFile> sftpFileList = sftpChannel.scanDirectory(directory+"");
        Assert.assertEquals(sftpFileList.size(),1);
        Assert.assertEquals("aa",sftpFileList.get(0).fileName);

        sftpChannel.writeFile(directory+"/bb","hello,world!".getBytes(StandardCharsets.UTF_8));
        byte[] data = sftpChannel.readFile(directory+"/bb");
        Assert.assertEquals("hello,world!",new String(data,StandardCharsets.UTF_8));
        sftpChannel.appendFile(directory+"/bb","sftp".getBytes(StandardCharsets.UTF_8));
        data = sftpChannel.readFile(directory+"/bb");
        Assert.assertEquals("hello,world!sftp", new String(data,StandardCharsets.UTF_8));
        data = sftpChannel.readFile(directory+"/bb",1,4);
        Assert.assertEquals("ello",new String(data,StandardCharsets.UTF_8));

        sftpChannel.deleteDirectory(directory+"/aa");
        sftpFileList = sftpChannel.scanDirectory(directory+"");
        Assert.assertEquals(sftpFileList.size(),1);
        Assert.assertEquals("bb",sftpFileList.get(0).fileName);

        String realPath = sftpChannel.canonicalize(".");
        Assert.assertEquals("/root",realPath);

        sftpChannel.rename(directory+"/bb",directory+"/cc");
        sftpFileList = sftpChannel.scanDirectory(directory+"");
        Assert.assertEquals(sftpFileList.size(),1);
        Assert.assertEquals("cc", sftpFileList.get(0).fileName);

        SFTPFileAttribute sftpFileAttribute = sftpChannel.getSFTPFileAttribute(directory+"/cc");
        Assert.assertEquals("hello,world!sftp".length(), sftpFileAttribute.size);

        sftpChannel.createSymbolicLinkPath(directory+"/cc",directory+"/dd");
        String symbolicPath = sftpChannel.readSymbolicLinkPath(directory+"/dd");
        Assert.assertEquals(directory+"/cc", symbolicPath);

        sftpChannel.closeChannel();
        sshClient.disconnect();
    }
}