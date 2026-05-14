package part1.cipherSuites;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesGcmSuite implements Ciphersuite {

    public AesGcmSuite() {}

    public byte[] encrypt(byte[] data, SecretKey movieKey, long seqNum) throws Exception {
        SecretKeySpec key = new SecretKeySpec(movieKey.getEncoded(), "AES");
        
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] seqBytes = ByteBuffer.allocate(8).putLong(seqNum).array();

        cipher.updateAAD(seqBytes);

        byte[] cipherText = cipher.doFinal(data);

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherText.length);
        buffer.put(iv);
        buffer.put(cipherText);
        return buffer.array();
    }

    public byte[] decrypt(byte[] data, SecretKey movieKey, long seqNum) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);

        byte[] iv = new byte[12];
        byteBuffer.get(iv);

        byte[] seqBytes = ByteBuffer.allocate(8).putLong(seqNum).array();

        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, movieKey, gcmSpec);

        cipher.updateAAD(seqBytes);

        return cipher.doFinal(cipherText);
    }
    
}
