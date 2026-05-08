package cipherSuites;

import javax.crypto.SecretKey;

public class ChaCha20Poly1305Suite implements Ciphersuite {
    
    public ChaCha20Poly1305Suite() {}
    

    public byte[] encrypt(byte[] data, SecretKey movieKey) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'encrypt'");
    }

    public byte[] decrypt(byte[] data, SecretKey movieKey) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'decrypt'");
    }
    
}
