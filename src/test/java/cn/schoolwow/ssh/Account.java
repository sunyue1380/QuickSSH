package cn.schoolwow.ssh;

import org.aeonbits.owner.Config;

@Config.DisableFeature(Config.DisableableFeature.PARAMETER_FORMATTING)
@Config.Sources({"file:${user.dir}/account.properties"})
public interface Account extends Config {
    @Key("ssh.host")
    String host();

    @Key("ssh.port")
    @DefaultValue("22")
    int port();

    @Key("ssh.username")
    @DefaultValue("root")
    String username();

    @Key("ssh.password")
    String password();

    @Key("ssh.publickey.filepath")
    String publickeyFilePath();

    @Key("ssh.publickey.passphrase")
    @DefaultValue("")
    String publickeyPassphrase();
}