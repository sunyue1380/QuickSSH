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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

public class EllipticCurveDiffieHellmanKex extends SSHAlgorithmImpl implements Kex {
    private Logger logger = LoggerFactory.getLogger(EllipticCurveDiffieHellmanKex.class);

    @Override
    public KexResult exchange(String V_C, String V_S, byte[] I_C, byte[] I_S, SSHSession sshSession) throws Exception {
        int size = Integer.parseInt(algorithmName.substring(algorithmName.length()-3));
        ECGenParameterSpec ecsp = null;
        switch (size){
            case 256:{ecsp = new ECGenParameterSpec("secp256r1");}break;
            case 384:{ecsp = new ECGenParameterSpec("secp384r1");}break;
            case 521:{ecsp = new ECGenParameterSpec("secp521r1");}break;
            default:{
                throw new IllegalArgumentException("不支持的EDCH算法大小!值大小:"+size);
            }
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECPublicKey ecPublicKey = null;
        ECPrivateKey ecPrivateKey = null;
        ECParameterSpec ecParameterSpec = null;

        SSHString clientEphemeralPublicKey = null;
        for(int i=0;i<1000;i++){
            keyPairGenerator.initialize(ecsp);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            ecPublicKey = (ECPublicKey)keyPair.getPublic();
            ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();
            ecParameterSpec = ecPublicKey.getParams();
            ECPoint w = ecPublicKey.getW();
            byte[] r = w.getAffineX().toByteArray();
            byte[] s = w.getAffineY().toByteArray();
            if(r.length!=s.length){
                continue;
            }
            if((size==256&&r.length==32)
                    ||(size==384&&r.length==48)
                    ||(size==521&&r.length==66)
            ){
                byte[] qc = new byte[1 + r.length + s.length];
                qc[0] = 0x04;
                System.arraycopy(r, 0, qc, 1, r.length);
                System.arraycopy(s, 0, qc, 1 + r.length, s.length);
                clientEphemeralPublicKey = new SSHString(qc);
                break;
            }
        }
        if(null==clientEphemeralPublicKey){
            throw new SSHException("EDCH算法生成r和s数组失败!");
        }

        SSHOutputStream sos = new SSHOutputStreamImpl();
        sos.writeByte(SSHMessageCode.SSH_MSG_KEX_ECDH_INIT.value);
        sos.writeSSHString(clientEphemeralPublicKey);

        byte[] payload = sshSession.readSSHProtocolPayload(SSHMessageCode.SSH_MSG_KEX_ECDH_REPLY);
        SSHInputStream sis = new SSHInputStreamImpl(payload);
        sis.skipBytes(1);
        SSHString hostKey = sis.readSSHString();
        SSHString serverEphemeralPublicKey = sis.readSSHString();
        SSHString signatureOfH = sis.readSSHString();

        BigInteger K = getSharedSecret(serverEphemeralPublicKey,ecPublicKey,ecPrivateKey);
        if(K.bitLength()<=0){
            throw new IllegalArgumentException("K值bitLength长度为0");
        }

        //拼接签名内容
        sos.reset();
        sos.writeSSHString(new SSHString(V_C));
        sos.writeSSHString(new SSHString(V_S));
        sos.writeSSHString(new SSHString(I_C));
        sos.writeSSHString(new SSHString(I_S));
        sos.writeSSHString(hostKey);
        sos.writeSSHString(clientEphemeralPublicKey);
        sos.writeSSHString(serverEphemeralPublicKey);
        sos.writeMPInt(K);
        MessageDigest messageDigest = SSHDigest.getDigest("SHA"+size).getMessageDigest();
        byte[] H = messageDigest.digest(sos.toByteArray());

        //验签
        PublicKey publicKey = sshSession.sshKexAlgorithmNegotitation.sshHostKey.parsePublicKey(hostKey.value);
        if(!sshSession.sshKexAlgorithmNegotitation.sshHostKey.verify(H, signatureOfH.value, publicKey)){
            throw new IllegalArgumentException("签名校验失败!");
        }

        KexResult kexResult = new KexResult();
        kexResult.hostKey = hostKey.value;
        kexResult.concatenationOfH = sos.toByteArray();
        kexResult.K = K;
        kexResult.signatureOfH = signatureOfH.value;
        kexResult.messageDigest = SSHDigest.getDigest("SHA"+size).getMessageDigest();
        return kexResult;
    }

    @Override
    public String[] algorithmNameList() {
        return new String[]{"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"};
    }

    /**生成共享密钥*/
    private BigInteger getSharedSecret(SSHString serverEphemeralPublicKey, ECPublicKey ecPublicKey, ECPrivateKey ecPrivateKey) throws Exception{
        byte[] value = serverEphemeralPublicKey.value;
        int startIndex = 0;
        while(value[startIndex]!=0x04){
            startIndex++;
        }
        startIndex++;
        byte[] r = new byte[(value.length-startIndex)/2];
        byte[] s = new byte[r.length];
        System.arraycopy(value,startIndex,r,0,r.length);
        System.arraycopy(value,startIndex + r.length,s,0,s.length);
        BigInteger x = new BigInteger(1,r);
        BigInteger y = new BigInteger(1,s);
        //第一步,校验 Q != O
        ECPoint w = new ECPoint(x,y);
        if(ECPoint.POINT_INFINITY.equals(w)){
            throw new SSHException("EDCH算法服务端公钥校验失败!Q != O");
        }
        //第二歩,校验xQ和yQ
        ECParameterSpec ecParameterSpec = ecPublicKey.getParams();
        {
            EllipticCurve ellipticCurve = ecParameterSpec.getCurve();
            BigInteger p = ((ECFieldFp)ellipticCurve.getField()).getP();
            BigInteger pSub1 = p.subtract(BigInteger.ONE);
            if(!(x.compareTo(pSub1)<=0&&y.compareTo(pSub1)<=0)){
                throw new SSHException("EDCH算法服务端公钥校验失败!xQ和yQ不在[0,p-1]的区间内");
            }
            BigInteger z = x.multiply(ellipticCurve.getA()).add(ellipticCurve.getB()).add(x.modPow(BigInteger.valueOf(3),p)).mod(p);
            BigInteger yPower2 = y.modPow(BigInteger.valueOf(2),p);
            if(!(yPower2.equals(z))){
                throw new SSHException("EDCH算法服务端公钥校验失败!公式不匹配!y^2 = x^3 + x*a + b (mod p)");
            }
        }
        //第三歩,校验 nQ = O. 但目前JCE未提供点操作方法,暂未实现

        //生成共享密钥
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, ecParameterSpec);
        PublicKey publicKey = keyFactory.generatePublic(ecPublicKeySpec);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
        keyAgreement.init(ecPrivateKey);
        keyAgreement.doPhase(publicKey, true);
        return new BigInteger(keyAgreement.generateSecret());
    }
}