package part2.ECDH;

import java.net.*;
import java.io.*;
import java.security.*;

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

        socket.close();
        serverSocket.close();
    }
}
