package cn.schoolwow.ssh.layer.transport.kex;

import cn.schoolwow.ssh.domain.SSHMessageCode;
import cn.schoolwow.ssh.domain.exception.SSHException;
import cn.schoolwow.ssh.domain.kex.KexResult;
import cn.schoolwow.ssh.domain.stream.SSHString;
import cn.schoolwow.ssh.layer.SSHSession;
import cn.schoolwow.ssh.layer.transport.SSHAlgorithmImpl;
import cn.schoolwow.ssh.layer.transport.digest.SSHDigest;
import cn.schoolwow.ssh.stream.SSHInputStream;
import cn.schoolwow.ssh.stream.SSHInputStreamImpl;
import cn.schoolwow.ssh.stream.SSHOutputStream;
import cn.schoolwow.ssh.stream.SSHOutputStreamImpl;
import cn.schoolwow.ssh.util.SSHUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Scanner;

public class DiffieHellmanKex extends SSHAlgorithmImpl implements Kex {
    private Logger logger = LoggerFactory.getLogger(DiffieHellmanKex.class);

    @Override
    public KexResult exchange(String V_C, String V_S, byte[] I_C, byte[] I_S, SSHSession sshSession) throws Exception {
        int groupNumber = Integer.parseInt(algorithmName.substring(algorithmName.indexOf("-group") + "-group".length(), algorithmName.lastIndexOf("-")));
        logger.trace("[哈夫曼密钥交换组编号]groupNumber:{}", groupNumber);

        //生成大素数p
        BigInteger p = getP(groupNumber);

        //生成大素数的原根
        BigInteger g = getG();

        //随机生成本地私钥x，然后生成对应的公钥e
        DHParameterSpec dhParameterSpec = new DHParameterSpec(p, g);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(dhParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());

        //获取公钥e
        DHPublicKey dhPublicKey = (DHPublicKey) keyPair.getPublic();
        BigInteger e = dhPublicKey.getY();

        //发送客户端公钥
        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_KEXDH_INIT.value);
        sos.writeMPInt(e);
        sshSession.writeSSHProtocolPayload(sos.toByteArray());

        //接收服务端返回报文
        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_KEXDH_REPLY);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        SSHString hostKey = sis.readSSHString();
        BigInteger f = sis.readMPInt();
        SSHString signatureOfH = sis.readSSHString();

        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(f, p, g);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverDHPublicKey = keyFactory.generatePublic(dhPublicKeySpec);

        keyAgreement.doPhase(serverDHPublicKey, true);
        byte[] secretBytes = keyAgreement.generateSecret();
        BigInteger K = new BigInteger(1,secretBytes);
        if(K.bitLength()<=0){
            throw new SSHException("K值bitLength长度为0");
        }

        //拼接签名内容
        sos.reset();
        sos.writeSSHString(new SSHString(V_C));
        sos.writeSSHString(new SSHString(V_S));
        sos.writeSSHString(new SSHString(I_C));
        sos.writeSSHString(new SSHString(I_S));
        sos.writeSSHString(hostKey);
        sos.writeMPInt(e);
        sos.writeMPInt(f);
        sos.writeMPInt(K);

        KexResult kexResult = new KexResult();
        kexResult.hostKey = hostKey.value;
        kexResult.concatenationOfH = sos.toByteArray();
        kexResult.K = K;
        kexResult.signatureOfH = signatureOfH.value;
        String digestName = algorithmName.substring(algorithmName.lastIndexOf("-") + 1);
        kexResult.messageDigest = SSHDigest.getDigest(digestName).getMessageDigest();
        return kexResult;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"diffie-hellman-group14-sha1", "diffie-hellman-group14-sha256" , "diffie-hellman-group15-sha512", "diffie-hellman-group16-sha512", "diffie-hellman-group17-sha512", "diffie-hellman-group18-sha512"};
    }

    /**获取底底数*/
    private BigInteger getG() {
        return new BigInteger(new byte[]{
                (byte) 0x02
        });
    }

    /**获取大素数*/
    private BigInteger getP(int number) {
        InputStream inputStream = ClassLoader.getSystemResourceAsStream("dhg/group" + number + ".prime");
        StringBuilder builder = new StringBuilder();
        Scanner scanner = new Scanner(inputStream);
        while (scanner.hasNextLine()) {
            builder.append(scanner.nextLine());
        }
        String hex = builder.toString().replaceAll("\\s+", "");
        byte[] bytes = SSHUtil.hexToByteArray("00" + hex);
        return new BigInteger(1,bytes);
    }
}