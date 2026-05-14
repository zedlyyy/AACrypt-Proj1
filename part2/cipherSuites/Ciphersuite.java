package part2.cipherSuites;

import javax.crypto.SecretKey;

public interface Ciphersuite {
    
    public byte[] encrypt(byte[] data, SecretKey movieKey, long seqNum) throws Exception;

    public byte[] decrypt(byte[] data, SecretKey movieKey, long seqNum) throws Exception;
}
