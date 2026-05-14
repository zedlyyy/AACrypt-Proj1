package part2.SHPmessages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;


public class ServerHello {

    private byte[] certificate;
    private byte[] server_pub_ECDH_key;
    private byte[] signature;
    private byte[] server_nonce;
    private byte[] client_nonce_response;
    private String selected_cipher_suite;


    public ServerHello(byte[] certificate, byte[] server_pub_ECDH_key, byte[] signature, byte[] server_nonce, byte[] client_nonce_response, String selected_cipher_suite){
        this.certificate = certificate;
        this.server_pub_ECDH_key = server_pub_ECDH_key;
        this.signature = signature;
        this.server_nonce = server_nonce;
        this.client_nonce_response = client_nonce_response;
        this.selected_cipher_suite = selected_cipher_suite;
    }

    public byte[] serializeData() throws IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(certificate.length);
        dos.write(certificate);

        dos.writeInt(server_pub_ECDH_key.length);
        dos.write(server_pub_ECDH_key);

        dos.writeInt(server_nonce.length);
        dos.write(server_nonce);

        dos.writeInt(client_nonce_response.length);
        dos.write(client_nonce_response);

        byte[] suiteBytes = selected_cipher_suite.getBytes();
        dos.writeInt(suiteBytes.length);
        dos.write(suiteBytes);

        dos.flush();

        return baos.toByteArray();
    }

     public byte[] serializeWithSignature() throws IOException {

        if (signature == null) {
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

    public static ServerHello deserialize(byte[] data) throws IOException {

        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bais);

        int cert_len = dis.readInt();
        byte[] certificate = new byte[cert_len];
        dis.readFully(certificate);

        int ecdh_len = dis.readInt();
        byte[] server_pub_ECDH_key = new byte[ecdh_len];
        dis.readFully(server_pub_ECDH_key);

        int nonce_len = dis.readInt();
        byte[] server_nonce = new byte[nonce_len];
        dis.readFully(server_nonce);

        int response_len = dis.readInt();
        byte[] client_nonce_response = new byte[response_len];
        dis.readFully(client_nonce_response);

        int suite_len = dis.readInt();
        byte[] suite_bytes = new byte[suite_len];
        dis.readFully(suite_bytes);
        String selected_cipher_suite = new String(suite_bytes);

        int sig_len = dis.readInt();
        byte[] signature = new byte[sig_len];
        dis.readFully(signature);

        return new ServerHello(certificate, server_pub_ECDH_key, signature, server_nonce, client_nonce_response, selected_cipher_suite);
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public byte[] getServer_pub_ECDH_key() {
        return server_pub_ECDH_key;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getServer_nonce() {
        return server_nonce;
    }

    public byte[] getClient_nonce_response() {
        return client_nonce_response;
    }

    public String getSelected_cipher_suite() {
        return selected_cipher_suite;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

}
