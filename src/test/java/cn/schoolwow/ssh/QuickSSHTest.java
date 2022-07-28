package cn.schoolwow.ssh;

import cn.schoolwow.ssh.domain.sftp.SFTPFile;
import cn.schoolwow.ssh.domain.sftp.SFTPFileAttribute;
import cn.schoolwow.ssh.layer.channel.LocalForwardChannel;
import cn.schoolwow.ssh.layer.channel.RemoteForwardChannel;
import cn.schoolwow.ssh.layer.channel.SFTPChannel;
import org.aeonbits.owner.ConfigCache;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

public class QuickSSHTest {
    private static Logger logger = LoggerFactory.getLogger(QuickSSHTest.class);
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
                .publickey(System.getProperty("user.dir") + "/" + account.publickeyFilePath(), account.publickeyPassphrase())
                .build();
    }

    @Test
    public void exec() throws IOException {
        SSHClient sshClient = QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
        Assert.assertEquals("/root", sshClient.exec("pwd"));
        Assert.assertEquals("root", sshClient.exec("echo $USER"));
        sshClient.close();
    }

    @Test
    public void sftpChannel() throws IOException {
        SSHClient sshClient = QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
        String directory = "/opt/sftp";
        sshClient.exec("rm -R " + directory + "; mkdir -p " + directory + "/");

        SFTPChannel sftpChannel = sshClient.sftpChannel();
        sftpChannel.createDirectory(directory + "/aa");
        List<SFTPFile> sftpFileList = sftpChannel.scanDirectory(directory + "");
        Assert.assertEquals(sftpFileList.size(), 1);
        Assert.assertEquals("aa", sftpFileList.get(0).fileName);

        sftpChannel.writeFile(directory + "/bb", "hello,world!".getBytes(StandardCharsets.UTF_8));
        byte[] data = sftpChannel.readFile(directory + "/bb");
        Assert.assertEquals("hello,world!", new String(data, StandardCharsets.UTF_8));
        sftpChannel.appendFile(directory + "/bb", "sftp".getBytes(StandardCharsets.UTF_8));
        data = sftpChannel.readFile(directory + "/bb");
        Assert.assertEquals("hello,world!sftp", new String(data, StandardCharsets.UTF_8));
        data = sftpChannel.readFile(directory + "/bb", 1, 4);
        Assert.assertEquals("ello", new String(data, StandardCharsets.UTF_8));

        sftpChannel.deleteDirectory(directory + "/aa");
        sftpFileList = sftpChannel.scanDirectory(directory + "");
        Assert.assertEquals(sftpFileList.size(), 1);
        Assert.assertEquals("bb", sftpFileList.get(0).fileName);

        String realPath = sftpChannel.canonicalize(".");
        Assert.assertEquals("/root", realPath);

        sftpChannel.rename(directory + "/bb", directory + "/cc");
        sftpFileList = sftpChannel.scanDirectory(directory + "");
        Assert.assertEquals(sftpFileList.size(), 1);
        Assert.assertEquals("cc", sftpFileList.get(0).fileName);

        SFTPFileAttribute sftpFileAttribute = sftpChannel.getSFTPFileAttribute(directory + "/cc");
        Assert.assertEquals("hello,world!sftp".length(), sftpFileAttribute.size);

        sftpChannel.createSymbolicLinkPath(directory + "/cc", directory + "/dd");
        String symbolicPath = sftpChannel.readSymbolicLinkPath(directory + "/dd");
        Assert.assertEquals(directory + "/cc", symbolicPath);

        sftpChannel.close();
        sshClient.exec("rm -R " + directory);
        sshClient.close();
    }

    @Test
    public void localForwardChannel() throws IOException, InterruptedException {
        SSHClient sshClient = QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
        LocalForwardChannel localForwardChannel = sshClient.localForwardChannel();
        localForwardChannel.localForward(9999, "0.0.0.0", 80);
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress("127.0.0.1", 9999));
        String request = "GET / HTTP/1.1\r\n" +
                "Host: 127.0.0.1:9999\r\n" +
                "Connection: Close\r\n" +
                "Cache-Control: max-age=0\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n\r\n";
        socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().flush();
        socket.shutdownOutput();
        logger.info("[发送请求数据]\n{}", request);
        Scanner scanner = new Scanner(socket.getInputStream());
        StringBuilder builder = new StringBuilder();
        while (scanner.hasNextLine()) {
            builder.append(scanner.nextLine()+"\r\n");
        }
        scanner.close();
        logger.info("[接收响应数据]\n{}", builder.toString());
        localForwardChannel.close();
    }

    @Test
    public void remoteForwardChannel() throws IOException {
        SSHClient sshClient = QuickSSH.newInstance()
                .host(account.host())
                .port(account.port())
                .username(account.username())
                .password(account.password())
                .build();
        RemoteForwardChannel remoteForwardChannel = sshClient.remoteForwardChannel();
        int remoteForwardPort = 10000, localPort = 8080;
        remoteForwardChannel.remoteForward(remoteForwardPort, "127.0.0.1", localPort);
        System.out.println("请在远程机器本地(127.0.0.1)访问"+remoteForwardPort+"端口,该请求会转发至本机的"+localPort+"端口!");
        try {
            Thread.sleep(4000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        remoteForwardChannel.close();
    }
}