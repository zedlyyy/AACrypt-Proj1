package part1.cipherSuites;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ChaCha20Poly1305Suite implements Ciphersuite {
    
    private static final int NONCE_SIZE = 12;

    public ChaCha20Poly1305Suite() {}
    

    public byte[] encrypt(byte[] data, SecretKey passwordKey, long seqNum) throws Exception {
        SecretKeySpec key = new SecretKeySpec(passwordKey.getEncoded(), "ChaCha20-Poly1305");

        byte[] nonce = new byte[NONCE_SIZE];
        new SecureRandom().nextBytes(nonce);

        IvParameterSpec param = new IvParameterSpec(nonce);
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.ENCRYPT_MODE, key, param);

        byte[] seqBytes = ByteBuffer.allocate(8).putLong(seqNum).array();

        cipher.updateAAD(seqBytes);

        byte[] cipherText = cipher.doFinal(data);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(nonce);
        output.write(cipherText);

        return output.toByteArray();
    }

    public byte[] decrypt(byte[] data, SecretKey passwordKey, long seqNum) throws Exception {
        if (data.length < NONCE_SIZE)
            throw new IllegalArgumentException("Encrypted data too short");

        byte[] nonce = Arrays.copyOfRange(data, 0, NONCE_SIZE);
        byte[] cipherText = Arrays.copyOfRange(data, NONCE_SIZE, data.length);

        IvParameterSpec param = new IvParameterSpec(nonce);
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, param);

        byte[] seqBytes = ByteBuffer.allocate(8).putLong(seqNum).array();

        cipher.updateAAD(seqBytes);

        return cipher.doFinal(cipherText);
    }
    
}
