import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Administrator on 28-08-2017.
 */

public class GenerateKeys {



    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {



        ECCurve curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
        ECParameterSpec ecSpec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
        KeyPairGenerator g = (KeyPairGenerator) KeyPairGenerator.getInstance("ECDSA", new BouncyCastleProvider());
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();

        KeyFactory fact = KeyFactory.getInstance("ECDSA", new BouncyCastleProvider());
        PublicKey publicKey = fact.generatePublic(new X509EncodedKeySpec(pair.getPublic().getEncoded()));
        PrivateKey privateKey = fact.generatePrivate(new PKCS8EncodedKeySpec(pair.getPrivate().getEncoded()));
        System.out.println(publicKey.getFormat());

        System.out.println(publicKey);
        System.out.println(privateKey.getFormat());

        System.out.println(privateKey);

       //gk = new GenerateKeys(256);

        GenerateKeys gk = new GenerateKeys();

        gk.writeToFile("KeyPair/publicKey", publicKey.getEncoded());

        gk.writeToFile("KeyPair/privateKey", privateKey.getEncoded());


    }


    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }
}
