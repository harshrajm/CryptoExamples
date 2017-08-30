/**
 * Created by Administrator on 28-08-2017.
 */

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class GenerateKeys {

    private KeyPairGenerator keyGen;
    private KeyPair pair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public GenerateKeys(int keylength) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.keyGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
        this.keyGen.initialize(keylength);
    }

    public void createKeys()  {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
        System.out.println(privateKey.getFormat());
        System.out.println("private Key : "+privateKey);
        System.out.println(publicKey.getFormat());
        System.out.println("public Key : "+publicKey);

    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public static void main(String[] args) {


        GenerateKeys gk;
        try {
            gk = new GenerateKeys(1024);
            //gk = new GenerateKeys(256);


            gk.createKeys();
            gk.writeToFile("KeyPair/publicKey", gk.getPublicKey().getEncoded());
            System.out.println("-----"+gk.getPublicKey().getEncoded());
            gk.writeToFile("KeyPair/privateKey", gk.getPrivateKey().getEncoded());

        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
        }
        catch (NoSuchProviderException e){
            System.err.println(e.getMessage());
        }
        catch (IOException e) {
            System.err.println(e.getMessage());
        }

    }

}
