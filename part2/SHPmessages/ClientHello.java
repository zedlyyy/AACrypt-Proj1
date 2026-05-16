package part2.SHPmessages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.channels.IllegalSelectorException;
import java.util.ArrayList;
import java.util.List;

public class ClientHello {

    private String movie_name;
    private byte[] certificate;
    private byte[] client_pub_ECDH_key;
    private byte[] signature;
    private byte[] nonce;
    private List<String> cipher_suites;
    
    public ClientHello(String movie_name, byte[] certificate, byte[] client_pub_ECDH_key, byte[] signature, byte[] nonce, List<String> cipher_suites){
        this.movie_name = movie_name;
        this.certificate = certificate;
        this.client_pub_ECDH_key = client_pub_ECDH_key;
        this.signature = signature;
        this.nonce = nonce;
        this.cipher_suites = cipher_suites;
    }

    public byte[] serializeData() throws IOException{

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        DataOutputStream dos = new DataOutputStream(baos);

        byte[] movie_bytes = movie_name.getBytes();
        dos.writeInt(movie_bytes.length);
        dos.write(movie_bytes);

        dos.writeInt(certificate.length);
        dos.write(certificate);

        dos.writeInt(client_pub_ECDH_key.length);
        dos.write(client_pub_ECDH_key);

        dos.writeInt(nonce.length);
        dos.write(nonce);

        dos.writeInt(cipher_suites.size());

        for( String suite : cipher_suites ){

            byte[] suiteBytes = suite.getBytes();

            dos.writeInt(suiteBytes.length);
            dos.write(suiteBytes);
        }

        dos.flush();

        return baos.toByteArray();
    }

    public byte[] serializeWithSignature() throws IOException{
        
        if(signature == null) {
            throw new IllegalStateException("Signature not set");
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        DataOutputStream dos = new DataOutputStream(baos);

        dos.write(serializeData());

        dos.writeInt(signature.length);
        dos.write(signature);

        dos.flush();

        return baos.toByteArray();
    }

    public static ClientHello deserialize(byte[] data) throws IOException{
        
        ByteArrayInputStream bais = new ByteArrayInputStream(data);

        DataInputStream dis = new DataInputStream(bais);
        
        int movie_len = dis.readInt();
        byte[] movie_bytes = new byte[movie_len];
        dis.readFully(movie_bytes);
        String movie_name = new String(movie_bytes);

        int cert_len = dis.readInt();
        byte[] encoded_certificate = new byte[cert_len];
        dis.readFully(encoded_certificate);
        
        int ECDH_len = dis.readInt();
        byte[] encoded_ECDH_public_key = new byte[ECDH_len];
        dis.readFully(encoded_ECDH_public_key);

        int nonce_len = dis.readInt();
        byte[] nonce = new byte[nonce_len];
        dis.readFully(nonce);

        int suite_count = dis.readInt();
        List<String> cipherSuites = new ArrayList<>();
        
        for (int i = 0; i < suite_count; i++) {
            
            int suite_len = dis.readInt();
            byte[] suite_bytes = new byte[suite_len];
            dis.readFully(suite_bytes);
            String suite = new String(suite_bytes);

            cipherSuites.add(suite);
        }

        int sig_len = dis.readInt();
        byte[] signature = new byte[sig_len];
        dis.readFully(signature);

        
        return new ClientHello(movie_name, encoded_certificate, encoded_ECDH_public_key, signature, nonce, cipherSuites);
    }

    public String getMovieName() {
    return movie_name;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public byte[] getClient_pub_ECDH_key() {
        return client_pub_ECDH_key;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public List<String> getCipherSuites() {
        return cipher_suites;
    }

    public void setMovie_name(String movie_name) {
        this.movie_name = movie_name;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public void setClient_pub_ECDH_key(byte[] client_pub_ECDH_key) {
        this.client_pub_ECDH_key = client_pub_ECDH_key;
    }  

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public void setCipher_suites(List<String> cipher_suites) {
        this.cipher_suites = cipher_suites;
    }

}
