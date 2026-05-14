package part2.ECDH;

import java.net.*;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Server {

    public static void main(String[] args) throws Exception {

        KeyPair serverIdentity = CryptoUtils.generateECDSAKeyPair();

        ServerSocket serverSocket = new ServerSocket(9999);
        System.out.println("Server listening...");

        Socket socket = serverSocket.accept();
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // 1. Generate ephemeral ECDH
        KeyPair serverECDH = CryptoUtils.generateECDHKeyPair();

        byte[] serverPub = serverECDH.getPublic().getEncoded();
        byte[] signature = CryptoUtils.sign(serverIdentity.getPrivate(), serverPub);

        // Send server ECDH pub + signature + identity pub
        out.writeInt(serverPub.length);
        out.write(serverPub);

        out.writeInt(signature.length);
        out.write(signature);

        byte[] serverIdPub = serverIdentity.getPublic().getEncoded();
        out.writeInt(serverIdPub.length);
        out.write(serverIdPub);

        // 2. Receive client data
        byte[] clientPub = new byte[in.readInt()];
        in.readFully(clientPub);

        byte[] clientSig = new byte[in.readInt()];
        in.readFully(clientSig);

        byte[] clientIdPubBytes = new byte[in.readInt()];
        in.readFully(clientIdPubBytes);

        PublicKey clientIdPub = CryptoUtils.decodePublicKey(clientIdPubBytes);

        // Verify client signature
        if (!CryptoUtils.verify(clientIdPub, clientPub, clientSig)) {
            throw new SecurityException("Client authentication failed");
        }

        PublicKey clientECDHPub = CryptoUtils.decodePublicKey(clientPub);

        byte[] sharedSecret = CryptoUtils.deriveSharedSecret(
                serverECDH.getPrivate(), clientECDHPub);

        System.out.println("Shared Secret: " + Base64.getEncoder().encodeToString(sharedSecret));

        // Then is possible to derive keys, nonces, initialization vectors, etc        // from the obtained shared secret obtained in the DH agreement   

        socket.close();
        serverSocket.close();
    }
}
