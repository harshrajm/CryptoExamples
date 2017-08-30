package TestEC;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by Administrator on 29-08-2017.
 */
public class ECCSignature {
    public static byte[] iv = new SecureRandom().generateSeed(16);

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg;
        kpg = (KeyPairGenerator) KeyPairGenerator.getInstance("EC",new BouncyCastleProvider());

        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("sect163k1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        KeyPair kp2 = kpg.genKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();
        PrivateKey privKey2 = kp2.getPrivate();
        PublicKey pubKey2 = kp2.getPublic();

        System.out.println(privKey.toString());
        System.out.println(pubKey.toString());

        System.out.println(privKey2.toString());
        System.out.println(pubKey2.toString());

        Signature ecdsa;
        ecdsa = Signature.getInstance("SHA1withECDSA",new BouncyCastleProvider());
        ecdsa.initSign(privKey);

        String text = "In teaching others we teach ourselves";
        System.out.println("Text: " + text);
        byte[] baText = text.getBytes("UTF-8");

        ecdsa.update(baText);
        byte[] baSignature = ecdsa.sign();
        System.out.println("Signature: 0x" + (new BigInteger(1, baSignature).toString(16)).toUpperCase());

        Signature signature;
        signature = Signature.getInstance("SHA1withECDSA",new BouncyCastleProvider());
        signature.initVerify(pubKey);
        signature.update(baText);
        boolean result = signature.verify(baSignature);
        System.out.println("Valid: " + result);
        System.out.println("-----------------");

        SecretKey secretKeyA = generateSharedSecret(privKey,
                pubKey2);
        SecretKey secretKeyB = generateSharedSecret(privKey2,
                pubKey);
        String cipherText = encryptString(secretKeyA, "This message will get Encrypted");

        System.out.println(cipherText);

    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey,
                                                 PublicKey publicKey) {
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);

            SecretKey key = keyAgreement.generateSecret("AES");
            return key;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptString(SecretKey key, String plainText) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", new BouncyCastleProvider());
            byte[] plainTextBytes = plainText.getBytes("UTF-8");
            byte[] cipherText;
            System.out.println(key);
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
            int encryptLength = cipher.update(plainTextBytes, 0,
                    plainTextBytes.length, cipherText, 0);
            encryptLength += cipher.doFinal(cipherText, encryptLength);

            return bytesToHex(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789ABCDEF";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }


}
