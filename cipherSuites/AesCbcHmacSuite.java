package cipherSuites;

import javax.crypto.SecretKey;

public class AesCbcHmacSuite implements Ciphersuite {
    
    public AesCbcHmacSuite() {}

    @Override
    public byte[] encrypt(byte[] data, SecretKey movieKey) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'encrypt'");
    }

    @Override
    public byte[] decrypt(byte[] data, SecretKey movieKey) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'decrypt'");
    }

}