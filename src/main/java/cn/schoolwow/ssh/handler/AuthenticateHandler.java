package cn.schoolwow.ssh.handler;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.stream.DistinguishedEncodingRule;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.transport.digest.SSHDigest;
import cn.schoolwow.ssh.layer.transport.encrypt.AESCipher;
import cn.schoolwow.ssh.layer.transport.publickey.RSAHostKey;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;

public class AuthenticateHandler implements Handler{
    private Logger logger = LoggerFactory.getLogger(AuthenticateHandler.class);

    @Override
    public Handler handle(SSHSession sshSession) throws Exception {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        //请求服务
        {
            sos.writeByte(SSHMessageCode.SSH_MSG_SERVICE_REQUEST.value);
            sos.writeSSHString(new SSHString("ssh-userauth"));
            sshSession.writeSSHProtocolPayload(sos.toByteArray());
            byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_SERVICE_ACCEPT);
            SSHInputStream sis = new SSHInputStreamImpl(payload);
            sis.skipBytes(1);
            SSHString serverServiceName = sis.readSSHString();
            if(!"ssh-userauth".equals(serverServiceName.toString())){
                throw new IllegalArgumentException("服务名称不匹配!期望名称:ssh-userauth,实际名称:"+serverServiceName);
            }
        }
        //探测服务端允许的认证类型
        {
            sos.reset();
            sos.writeByte(SSHMessageCode.SSH_MSG_USERAUTH_REQUEST.value);
            sos.writeSSHString(new SSHString(sshSession.quickSSHConfig.username));
            sos.writeSSHString(new SSHString("ssh-connection"));
            sos.writeSSHString(new SSHString("none"));
            sshSession.writeSSHProtocolPayload(sos.toByteArray());

            byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_USERAUTH_FAILURE);
            SSHInputStream sis = new SSHInputStreamImpl(payload);
            sis.skipBytes(1);
            List<String> authenticationList = sis.readNameList();
            logger.debug("[服务端支持认证类型]{}",authenticationList);
        }
        if(null!=sshSession.quickSSHConfig.publickeyFilePath){
            loginByPublicKey(sshSession);
        }else if(null!=sshSession.quickSSHConfig.password){
            loginByPassword(sshSession);
        }else{
            throw new IllegalArgumentException("请指定登录方式!");
        }
        handleAuth(sshSession);
        return null;
    }

    /**PublicKey登录*/
    public void loginByPublicKey(SSHSession sshSession) throws Exception {
        logger.info("[SSH公钥方式登录]用户名:{},文件地址:{}", sshSession.quickSSHConfig.username,sshSession.quickSSHConfig.publickeyFilePath);
        //解密私钥文件
        String prefix = "-----BEGIN RSA PRIVATE KEY-----";
        String suffix = "-----END RSA PRIVATE KEY-----";
        String content = new String(Files.readAllBytes(sshSession.quickSSHConfig.publickeyFilePath), StandardCharsets.UTF_8);
        if(!content.startsWith(prefix)&&!content.endsWith(suffix)){
            throw new SSHException("目前仅支持RSA私钥格式文件!");
        }
        byte[] privateKeyBytes = null;
        //判断私钥是否加密
        String dekPrefix = "DEK-Info: AES-128-CBC,";
        if(content.contains(dekPrefix)){
            int beginIndex = content.indexOf(dekPrefix)+dekPrefix.length();
            byte[] iv = SSHUtil.hexToByteArray(content.substring(beginIndex,beginIndex+32));
            String privateKeyContent = content.substring(beginIndex + 34,content.indexOf(suffix));
            privateKeyContent = privateKeyContent.replace("\n","");
            logger.trace("[私钥文件base64编码]{}",privateKeyContent);
            privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);

            AESCipher aesCipher = new AESCipher();
            aesCipher.algorithmName = "aes128-cbc";
            byte[] aesKey = new byte[sshSession.quickSSHConfig.passphrase.length+8];
            System.arraycopy(sshSession.quickSSHConfig.passphrase,0,aesKey,0,sshSession.quickSSHConfig.passphrase.length);
            System.arraycopy(iv,0,aesKey,sshSession.quickSSHConfig.passphrase.length,8);
            aesKey = SSHDigest.MD5.getMessageDigest().digest(aesKey);
            Cipher cipher = aesCipher.getServerCipher(iv, aesKey);
            privateKeyBytes = cipher.doFinal(privateKeyBytes);
        }else{
            String privateKeyContent = content.substring(prefix.length()+1,content.indexOf(suffix));
            privateKeyBytes = Base64.getDecoder().decode(privateKeyContent);
        }

        //解码私钥文件
        SSHInputStream sis = new SSHInputStreamImpl(privateKeyBytes);
        DistinguishedEncodingRule sequenceDER = sis.readDER();
        sis = new SSHInputStreamImpl(sequenceDER.content);
        
        DistinguishedEncodingRule versionDER = sis.readDER();
        logger.trace("[私钥文件版本号]{}", new BigInteger(versionDER.content).intValue());

        DistinguishedEncodingRule modulusDER = sis.readDER();
        logger.trace("[私钥文件modulus]{}", SSHUtil.byteArrayToHex(modulusDER.content));
        BigInteger modulus = new BigInteger(modulusDER.content);

        DistinguishedEncodingRule publicExponentDER = sis.readDER();
        logger.trace("[私钥文件publicExponent]{}",SSHUtil.byteArrayToHex(publicExponentDER.content));
        BigInteger e = new BigInteger(publicExponentDER.content);

        DistinguishedEncodingRule privateExponentDER = sis.readDER();
        logger.trace("[私钥文件privateExponent]{}",SSHUtil.byteArrayToHex(privateExponentDER.content));
        BigInteger d = new BigInteger(privateExponentDER.content);

        DistinguishedEncodingRule prime1DER = sis.readDER();
        logger.trace("[私钥文件prime1]{}",SSHUtil.byteArrayToHex(prime1DER.content));
        BigInteger p = new BigInteger(prime1DER.content);

        DistinguishedEncodingRule prime2DER = sis.readDER();
        logger.trace("[私钥文件prime2]{}",SSHUtil.byteArrayToHex(prime2DER.content));
        BigInteger q = new BigInteger(prime2DER.content);

        DistinguishedEncodingRule exponent1DER = sis.readDER();
        logger.trace("[私钥文件exponent1]{}",SSHUtil.byteArrayToHex(exponent1DER.content));
        BigInteger exponent1 = new BigInteger(exponent1DER.content);

        DistinguishedEncodingRule exponent2DER = sis.readDER();
        logger.trace("[私钥文件exponent2]{}",SSHUtil.byteArrayToHex(exponent2DER.content));
        BigInteger exponent2 = new BigInteger(exponent2DER.content);

        DistinguishedEncodingRule coefficientDER = sis.readDER();
        logger.trace("[私钥文件coefficient]{}",SSHUtil.byteArrayToHex(coefficientDER.content));
        BigInteger coefficient = new BigInteger(coefficientDER.content);

        //执行校验
        if(!exponent1.equals(d.mod(p.subtract(BigInteger.ONE)))){
            throw new SSHException("私钥文件校验失败!校验 exponent1 = d mod (p-1)失败!");
        }
        if(!exponent2.equals(d.mod(q.subtract(BigInteger.ONE)))){
            throw new SSHException("私钥文件校验失败!校验 exponent2 = d mod (q-1)失败!");
        }
        //TODO 剩余校验函数 coefficient = q^(-1) mod p

        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_USERAUTH_REQUEST.value);
        sos.writeSSHString(new SSHString(sshSession.quickSSHConfig.username));
        sos.writeSSHString(new SSHString("ssh-connection"));
        sos.writeSSHString(new SSHString("publickey"));
        sos.writeBoolean(true);
        sos.writeSSHString(new SSHString("ssh-rsa"));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, e);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
        RSAHostKey rsaHostKey = new RSAHostKey();
        byte[] publicKeyBlob = rsaHostKey.formatPublicKey(rsaPublicKey);
        logger.trace("[RSA私钥文件公钥Base64编码]{}",Base64.getEncoder().encodeToString(publicKeyBlob));
        sos.writeSSHString(new SSHString(publicKeyBlob));
        byte[] commonBytes = sos.toByteArray();

        //生成签名内容
        sos.reset();
        sos.writeSSHString(new SSHString(sshSession.sessionId));
        sos.write(commonBytes);
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, d);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(rsaPrivateKeySpec);
        byte[] sign = rsaHostKey.sign(sos.toByteArray(),rsaPrivateKey);
        sos.reset();

        sos.write(commonBytes);
        sos.writeSSHString(new SSHString(sign));
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
    }

    /**密码登录*/
    public void loginByPassword(SSHSession sshSession) throws IOException {
        logger.info("[SSH密码方式登录]用户名:{},密码:{}",sshSession.quickSSHConfig.username,sshSession.quickSSHConfig.password);
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_USERAUTH_REQUEST.value);
        sos.writeSSHString(new SSHString(sshSession.quickSSHConfig.username));
        sos.writeSSHString(new SSHString("ssh-connection"));
        sos.writeSSHString(new SSHString("password"));
        sos.writeBoolean(false);
        sos.writeSSHString(new SSHString(sshSession.quickSSHConfig.password));
        sshSession.writeSSHProtocolPayload(sos.toByteArray());
    }

    private void handleAuth(SSHSession sshSession) throws Exception {
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,SSHMessageCode.SSH_MSG_USERAUTH_SUCCESS,SSHMessageCode.SSH_MSG_USERAUTH_FAILURE);
        SSHMessageCode messageCode = SSHMessageCode.getSSHMessageCode(payload[0]);
        switch (messageCode){
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:{
                throw new UnsupportedOperationException("密码过期！服务端要求设置新密码！该操作目前不支持！");
            }
            case SSH_MSG_USERAUTH_SUCCESS:{
                logger.debug("[密码认证成功]");
            }break;
            case SSH_MSG_USERAUTH_FAILURE:{
                boolean partialSuccess = payload[payload.length-1]>0;
                if(partialSuccess){
                    logger.info("[密码认证失败]密码已经改变，但是需要进一步认证");
                }else{
                    logger.info("[密码认证失败]密码没有改变");
                }
                throw new SSHException("登录认证失败!");
            }
        }
    }
}