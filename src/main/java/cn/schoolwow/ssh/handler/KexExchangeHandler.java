package cn.schoolwow.ssh.handler;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.kex.KexResult;
import cn.schoolwow.ssh.domain.kex.SSHClientSupportAlgorithm;
import cn.schoolwow.ssh.domain.kex.SSHKexAlgorithmNegotitation;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.transport.SSHAlgorithm;
import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;
import cn.schoolwow.ssh.layer.transport.compress.Compress;
import cn.schoolwow.ssh.layer.transport.encrypt.SSHCipher;
import cn.schoolwow.ssh.layer.transport.kex.Kex;
import cn.schoolwow.ssh.layer.transport.mac.SSHMac;
import cn.schoolwow.ssh.layer.transport.publickey.SSHHostKey;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**SSH密钥交换阶段*/
public class KexExchangeHandler implements Handler{
    private Logger logger = LoggerFactory.getLogger(KexExchangeHandler.class);

    @Override
    public Handler handle(SSHSession sshSession) throws Exception {
        String V_C = "SSH-2.0-QuickSSH-1.0";
        //发送版本号和接收版本号
        sshSession.socket.getOutputStream().write((V_C+"\r\n").getBytes(StandardCharsets.UTF_8));
        sshSession.socket.getOutputStream().flush();
        logger.trace("[发送客户端版本号]{}", V_C);
        String V_S = sshSession.sis.readLine();
        logger.trace("[获取服务端版本号]{}", V_S);

        //发送算法协商报文
        byte[] clientKexInitPayload = getClientKexInit(sshSession.quickSSHConfig.sshClientSupportAlgorithm);
        sshSession.writeSSHProtocolPayload(clientKexInitPayload);
        byte[] serverKexInitPayload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_KEXINIT);
        matchAlgorithmNameList(serverKexInitPayload,sshSession.sshKexAlgorithmNegotitation,sshSession.quickSSHConfig.sshClientSupportAlgorithm);

        //进行密钥交换
        KexResult kexResult = sshSession.sshKexAlgorithmNegotitation.kex.exchange(V_C,V_S,clientKexInitPayload,serverKexInitPayload,sshSession);
        //验签
        byte[] H = kexResult.messageDigest.digest(kexResult.concatenationOfH);
        PublicKey publicKey = sshSession.sshKexAlgorithmNegotitation.sshHostKey.parsePublicKey(kexResult.hostKey);
        if(!sshSession.sshKexAlgorithmNegotitation.sshHostKey.verify(H, kexResult.signatureOfH, publicKey)){
            throw new IllegalArgumentException("签名校验失败!");
        }

        if(null==sshSession.sessionId){
            sshSession.sessionId = H;
        }

        sshSession.writeSSHProtocolPayload(new byte[]{(byte) SSHMessageCode.SSH_MSG_NEWKEYS.value});
        sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_NEWKEYS);

        //设置算法密钥
        setAlgorithmKey(kexResult.K, H, kexResult.messageDigest, sshSession.sessionId, sshSession.sshKexAlgorithmNegotitation);
        return new AuthenticateHandler();
    }

    /**设置算法密钥*/
    private void setAlgorithmKey(BigInteger K, byte[] H, MessageDigest messageDigest, byte[] sessionId, SSHKexAlgorithmNegotitation sshAlgorithmNegotitation) throws Exception{
        int cipherKeySize = sshAlgorithmNegotitation.sshCipher.getKeySize();
        logger.debug("[加解密密钥预期长度]算法名称:{}, 预期长度:{}, 摘要算法长度:{}", ((SSHAlgorithmImpl)sshAlgorithmNegotitation.sshCipher).algorithmName,cipherKeySize,messageDigest.getDigestLength());

        //计算密钥并匹配算法实现
        byte[] c2sIv = calculateKey(cipherKeySize, K, H, messageDigest, sessionId,'A');
        byte[] s2cIv = calculateKey(cipherKeySize, K, H, messageDigest, sessionId,'B');
        byte[] c2sCipherKey = calculateKey(cipherKeySize, K, H, messageDigest, sessionId, 'C');
        byte[] s2cCipherKey = calculateKey(cipherKeySize, K, H, messageDigest, sessionId, 'D');
        sshAlgorithmNegotitation.c2sCipher = sshAlgorithmNegotitation.sshCipher.getClientCipher(c2sIv, c2sCipherKey);
        sshAlgorithmNegotitation.s2cCipher = sshAlgorithmNegotitation.sshCipher.getServerCipher(s2cIv, s2cCipherKey);

        int macKeySize = sshAlgorithmNegotitation.sshMac.getKeySize();
        logger.debug("[消息认证码算法长度]算法名称:{}, 预期长度:{}, 摘要算法长度:{}",((SSHAlgorithmImpl)sshAlgorithmNegotitation.sshMac).algorithmName,macKeySize,messageDigest.getDigestLength());
        byte[] c2sMacKey = calculateKey(macKeySize, K, H, messageDigest, sessionId, 'E');
        byte[] s2cMacKey = calculateKey(macKeySize, K, H, messageDigest, sessionId, 'F');
        sshAlgorithmNegotitation.c2sMac = sshAlgorithmNegotitation.sshMac.getMac(c2sMacKey);
        sshAlgorithmNegotitation.s2cMac = sshAlgorithmNegotitation.sshMac.getMac(s2cMacKey);

        logger.debug("[生成算法密钥]客户端向量:{},客户端密钥:{},服务端向量:{},服务端密钥:{},客户端消息认证密钥:{},服务端消息认证密钥:{}",
                SSHUtil.byteArrayToHex(c2sIv) + "["+c2sIv.length+"]",
                SSHUtil.byteArrayToHex(c2sCipherKey) + "["+c2sCipherKey.length+"]",
                SSHUtil.byteArrayToHex(s2cIv) + "["+s2cIv.length+"]",
                SSHUtil.byteArrayToHex(s2cCipherKey) + "["+s2cCipherKey.length+"]",
                SSHUtil.byteArrayToHex(c2sMacKey) + "["+c2sMacKey.length+"]",
                SSHUtil.byteArrayToHex(s2cMacKey) + "["+s2cMacKey.length+"]"
        );
    }

    /**
     * 计算密钥
     * @param keyLength 密钥长度
     * @param kexResult 密钥交换结果
     * @param sessionId 会话id
     * @param char x 指定字符
     * */
    private byte[] calculateKey(int keyLength, BigInteger K, byte[] H, MessageDigest messageDigest, byte[] sessionId, char x) throws Exception {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeMPInt(K);
        sos.write(H);
        sos.write(x);
        sos.write(sessionId);
        byte[] key = messageDigest.digest(sos.toByteArray());
        if(key.length<keyLength){
            int retryTimes = 10;
            byte[] roundKey = new byte[key.length];
            System.arraycopy(key,0,roundKey,0,key.length);
            while(key.length<keyLength&&retryTimes>=0){
                sos.reset();
                sos.writeMPInt(K);
                sos.write(H);
                sos.write(roundKey);
                roundKey = messageDigest.digest(sos.toByteArray());
                sos.reset();
                sos.write(key);
                sos.write(roundKey);
                key = sos.toByteArray();
                logger.trace("[密钥长度不够]重复计算密钥.期望最小长度:{},当前长度:{}",keyLength,key.length);
                retryTimes--;
            }
        }
        if(key.length>keyLength){
            byte[] trimKey = new byte[keyLength];
            System.arraycopy(key,0,trimKey,0,keyLength);
            key = trimKey;
        }
        return key;
    }

    /**
     * 匹配客户端和服务端的算法列表
     * @param serverKexInitPayload 服务端KEX_INIT报文
     * @param sshClientSupportAlgorithm 客户端匹配协商算法
     * @param sshClientSupportAlgorithm 客户端支持算法
     * */
    private void matchAlgorithmNameList(byte[] serverKexInitPayload, SSHKexAlgorithmNegotitation sshKexAlgorithmNegotitation, SSHClientSupportAlgorithm sshClientSupportAlgorithm) throws IOException {
        SSHInputStream sis = new SSHInputStreamImpl(serverKexInitPayload);
        sis.skipBytes(17);
        List<String> serverKexNameList = sis.readNameList();
        logger.trace("[服务端支持密钥算法]{}",serverKexNameList);
        sshKexAlgorithmNegotitation.kex = (Kex) matchAlgorithm(sshClientSupportAlgorithm.kexList, serverKexNameList,"密钥协商算法交换失败！");
        List<String> serverHostKeyNameList = sis.readNameList();
        logger.trace("[服务端支持HostKey算法]{}",serverKexNameList);
        sshKexAlgorithmNegotitation.sshHostKey = (SSHHostKey) matchAlgorithm(sshClientSupportAlgorithm.hostKeyList, serverHostKeyNameList,"HostKey算法交换失败！");
        List<String> serverCipherNameList = sis.readNameList();sis.readNameList();
        logger.trace("[服务端支持加密算法]{}",serverCipherNameList);
        sshKexAlgorithmNegotitation.sshCipher = (SSHCipher) matchAlgorithm(sshClientSupportAlgorithm.cipherList, serverCipherNameList,"加密算法协商失败！");
        List<String> serverMacNameList = sis.readNameList();sis.readNameList();
        logger.trace("[服务端支持消息认证算法]{}",serverMacNameList);
        sshKexAlgorithmNegotitation.sshMac = (SSHMac) matchAlgorithm(sshClientSupportAlgorithm.macList, serverMacNameList,"消息摘要算法协商失败！");
        List<String> serverCompressNameList = sis.readNameList();sis.readNameList();
        logger.trace("服务端支持压缩算法]{}",serverCompressNameList);
        sshKexAlgorithmNegotitation.compress = (Compress) matchAlgorithm(sshClientSupportAlgorithm.compressList, serverCompressNameList,"压缩算法协商失败！");
        logger.debug("[匹配协商算法]密钥交换算法:{},HostKey算法:{},加密算法:{},消息摘要算法:{},压缩算法:{}",
                ((SSHAlgorithmImpl)sshKexAlgorithmNegotitation.kex).algorithmName,
                ((SSHAlgorithmImpl)sshKexAlgorithmNegotitation.sshHostKey).algorithmName,
                ((SSHAlgorithmImpl)sshKexAlgorithmNegotitation.sshCipher).algorithmName,
                ((SSHAlgorithmImpl)sshKexAlgorithmNegotitation.sshMac).algorithmName,
                ((SSHAlgorithmImpl)sshKexAlgorithmNegotitation.compress).algorithmName
        );
    }

    /**匹配算法*/
    private SSHAlgorithm matchAlgorithm(List<? extends SSHAlgorithm> clientSSHAlgorithmList, List<String> serverAlgorithmNameList, String message){
        for(SSHAlgorithm clientAlgorithm:clientSSHAlgorithmList){
            for(String serverAlgorithmName:serverAlgorithmNameList){
                if(clientAlgorithm.matchAlgorithm(serverAlgorithmName)){
                    return clientAlgorithm;
                }
            }
        }
        throw new SSHException(message);
    }

    /**生成KEX_INIT负载数据*/
    private byte[] getClientKexInit(SSHClientSupportAlgorithm sshClientSupportAlgorithmList) throws IOException {
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_KEXINIT.value);
        byte[] cookie = new byte[16];
        new SecureRandom().nextBytes(cookie);
        sos.write(cookie);
        List<String> kexNameList = mergeAlgorithmNameList(sshClientSupportAlgorithmList.kexList);
        sos.writeNameList(kexNameList);
        logger.trace("[客户端支持密钥算法]{}",kexNameList);
        List<String> hostkeyNameList = mergeAlgorithmNameList(sshClientSupportAlgorithmList.hostKeyList);
        sos.writeNameList(hostkeyNameList);
        logger.trace("[客户端支持HostKey算法]{}",kexNameList);
        List<String> cipherNameList = mergeAlgorithmNameList(sshClientSupportAlgorithmList.cipherList);
        sos.writeNameList(cipherNameList);sos.writeNameList(cipherNameList);
        logger.trace("[客户端支持加密算法]{}",cipherNameList);
        List<String> macNameList = mergeAlgorithmNameList(sshClientSupportAlgorithmList.macList);
        sos.writeNameList(macNameList);sos.writeNameList(macNameList);
        logger.trace("[客户端支持消息认证算法]{}",macNameList);
        List<String> compressNameList = mergeAlgorithmNameList(sshClientSupportAlgorithmList.compressList);
        sos.writeNameList(compressNameList);sos.writeNameList(compressNameList);
        logger.trace("[客户端支持压缩算法]{}",macNameList);
        sos.writeInt(0);sos.writeInt(0);
        sos.writeBoolean(false);
        sos.writeInt(0);
        return sos.toByteArray();
    }

    /**合并算法名称列表*/
    private List<String> mergeAlgorithmNameList(List<? extends SSHAlgorithm> sshAlgorithmList){
        List<String> array = new ArrayList<>();
        for(SSHAlgorithm sshAlgorithm:sshAlgorithmList){
            array.addAll(Arrays.asList(sshAlgorithm.algorithmNameList()));
        }
        return array;
    }
}