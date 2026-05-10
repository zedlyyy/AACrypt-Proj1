package cipherSuites;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCtrHmacSuite implements Ciphersuite {

    private SecretKey macKey;

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public AesCtrHmacSuite(SecretKey macKey) {
        this.macKey = macKey;
    }

    public byte[] encrypt(byte[] data, SecretKey passwordKey) throws Exception {
        SecretKeySpec cipherKey = new SecretKeySpec(passwordKey.getEncoded(), "AES");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivSpec);

        byte[] cipherText = cipher.doFinal(data);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        mac.update(iv);
        mac.update(cipherText);
        byte[] macResult = mac.doFinal();

        ByteBuffer buffer = ByteBuffer.allocate(iv.length + cipherText.length + macResult.length);
        buffer.put(iv);
        buffer.put(cipherText);
        buffer.put(macResult);

        return buffer.array();
    }

    public byte[] decrypt(byte[] encryptedData, SecretKey passwordKey) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

        byte[] iv = new byte[16];
        byteBuffer.get(iv);
        int macLength = 32;
        if (encryptedData.length < 16 + macLength)
            throw new IllegalArgumentException("Encrypted packet too short");
        byte[] cipherText = new byte[byteBuffer.remaining() - macLength];
        byteBuffer.get(cipherText);

        byte[] macReceived = new byte[macLength];
        byteBuffer.get(macReceived);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        mac.update(iv);
        mac.update(cipherText);
        byte[] macResult = mac.doFinal();

        if (!MessageDigest.isEqual(macReceived, macResult))
            throw new SecurityException("MAC verification failed.");

        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, passwordKey, ivSpec);

        return cipher.doFinal(cipherText);
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hex[j * 2] = HEX_ARRAY[v >>> 4];
            hex[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hex);
    }

}
