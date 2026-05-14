package part2.ECDH;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Client {

    public static void main(String[] args) throws Exception {

        KeyPair clientIdentity = CryptoUtils.generateECDSAKeyPair();

        Socket socket = new Socket("localhost", 9999);
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // 1. Receive server data
        byte[] serverPub = new byte[in.readInt()];
        in.readFully(serverPub);

        byte[] serverSig = new byte[in.readInt()];
        in.readFully(serverSig);

        byte[] serverIdPubBytes = new byte[in.readInt()];
        in.readFully(serverIdPubBytes);

        PublicKey serverIdPub = CryptoUtils.decodePublicKey(serverIdPubBytes);

        // Verify server signature
        if (!CryptoUtils.verify(serverIdPub, serverPub, serverSig)) {
            throw new SecurityException("Server authentication failed");
        }

        // 2. Generate client ECDH
        KeyPair clientECDH = CryptoUtils.generateECDHKeyPair();

        byte[] clientPub = clientECDH.getPublic().getEncoded();
        byte[] clientSig = CryptoUtils.sign(clientIdentity.getPrivate(), clientPub);

        // Send client data
        out.writeInt(clientPub.length);
        out.write(clientPub);

        out.writeInt(clientSig.length);
        out.write(clientSig);

        byte[] clientIdPub = clientIdentity.getPublic().getEncoded();
        out.writeInt(clientIdPub.length);
        out.write(clientIdPub);

        // 3. Derive shared secret
        PublicKey serverECDHPub = CryptoUtils.decodePublicKey(serverPub);

        byte[] sharedSecret = CryptoUtils.deriveSharedSecret(
                clientECDH.getPrivate(), serverECDHPub);

        System.out.println("Shared Secret: " + Base64.getEncoder().encodeToString(sharedSecret));

	// Then is possible to derive keys, nonces, initialization vectors, etc
	// from the obtained shared secret obtained in the DH agreement
        socket.close();
    }
}
