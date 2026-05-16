package part2.ECDH;

import java.security.*;
import java.security.spec.*;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

public class CryptoUtils {

    public static KeyPair generateECDSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public static byte[] sign(PrivateKey priv, byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(priv);
        sig.update(data);
        return sig.sign();
    }

    public static boolean verify(PublicKey pub, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(pub);
        sig.update(data);
        return sig.verify(signature);
    }

    public static KeyPair generateECDHKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public static byte[] deriveSharedSecret(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    public static PublicKey decodePublicKey(byte[] encoded) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static byte[] hmacDF(byte[] key, byte[] data, int size) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");

        byte[] salt = new byte[32];
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(key);

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));

        byte[] res = new byte[size];
        byte[] previous = new byte[0];

        int offset = 0;
        byte counter = 1;

        while (offset < size) {
            mac.reset();

            mac.update(previous);
            mac.update(data);
            mac.update(counter);

            previous = mac.doFinal();

            int remainder = size - offset;
            int length = Math.min(previous.length, remainder);

            System.arraycopy(previous, 0, res, offset, length);
            offset += length;
            counter++;
        }

        return res;
    }
}
