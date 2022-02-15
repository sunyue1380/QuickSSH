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
```

# 反馈

若有问题请提交Issue或者发送邮件到648823596@qq.com

# 开源协议
本软件使用[LGPL](http://www.gnu.org/licenses/lgpl-3.0-standalone.html)开源协议!