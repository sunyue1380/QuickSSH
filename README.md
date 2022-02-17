# QuickSSH

纯Java实现SSH协议

# 快速入门

* 导入QuickSSH

```xml
<dependency>
  <groupId>cn.schoolwow</groupId>
  <artifactId>QuickSSH</artifactId>
  <version>{最新版本}</version>
</dependency>
```

> [QuickSSH最新版本查询](https://search.maven.org/search?q=a:QuickSSH)

* 构建SSHClient

```java
//密码方式登录
SSHClient client = QuickSSH.newInstance()
        .host("127.0.0.1")
        .port(22)
        .username("root")
        .password("123456")
        .build();
//公钥文件方式登录
SSHClient client = QuickSSH.newInstance()
        .host("127.0.0.1")
        .port(22)
        .username("root")
        //目前仅支持rsa类型
        .publickey("/path/to/id_rsa", "passphrase")
        .build();
//执行exec命令
String resut = sshClient.exec("pwd");
//获取sftp命令
SFTPChannel sftpChannel = sshClient.sftp();
sftpChannel.xxxxxx();
//1.0.1版本新增本地端口转发和远程端口转发
LocalForwardChannel localForwardChannel = sshClient.localForwardChannel();
//访问本机9999端口，系统会将发往9999端口的数据转发到服务器的80端口
localForwardChannel.localForward(9999,"0.0.0.0",80);

RemoteForwardChannel remoteForwardChannel = sshClient.remoteForwardChannel();
//访问远程机器的本机10000端口，系统会将数据转发到本机的80端口
remoteForwardChannel.remoteForward(10000,"127.0.0.1",80);
System.out.println("请在远程机器本地(127.0.0.1)访问10000端口,该请求会转发至本机的80端口!");
```

# 反馈

若有问题请提交Issue或者发送邮件到648823596@qq.com

# 开源协议
本软件使用[LGPL](http://www.gnu.org/licenses/lgpl-3.0-standalone.html)开源协议!