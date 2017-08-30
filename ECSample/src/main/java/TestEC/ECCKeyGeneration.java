package TestEC;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.KeyPairGenerator;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

/**
 * Created by Administrator on 29-08-2017.
 */
public class ECCKeyGeneration {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg;
        kpg = (KeyPairGenerator) KeyPairGenerator.getInstance("EC",new BouncyCastleProvider());
        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("secp192r1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        PrivateKey privKey = kp.getPrivate();
        PublicKey pubKey = kp.getPublic();

        System.out.println(privKey.toString());
        System.out.println(pubKey.toString());
    }

}
