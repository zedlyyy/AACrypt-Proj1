package part2.UDPproxy;

import java.io.ByteArrayInputStream;

/* hjUDPproxy, 20/Mar/18
 *
 * This is a very simple (transparent) UDP proxy
 * The proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.util.Scanner;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import part2.SHPmessages.*;
import part2.ECDH.*;
import part2.cipherSuites.AesCbcHmacSuite;
import part2.cipherSuites.AesCtrHmacSuite;
import part2.cipherSuites.AesGcmSuite;
import part2.cipherSuites.ChaCha20Poly1305Suite;
import part2.cipherSuites.Ciphersuite;

class hjUDPproxy {

    private static final int MAX_PACKET_SIZE = 8192;
    private static final byte START_TYPE = 1;
    private static final byte DATA_TYPE = 2;
    private static final byte END_TYPE = 3;
    private static final byte ERROR_TYPE = 4;
    private static final String KEYSTORE_PATH = "part2/UDPproxy/proxy-keystore.p12";
    private static final String TRUSTSTORE_PATH = "part2/UDPproxy/proxy-truststore.p12";

    private static PrivateKey client_ECDH_PrivateKey;
    private static byte[] client_nonce;

    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    // @SuppressWarnings("unused")
    public static void main(String[] args) throws Exception {
        InputStream config = new FileInputStream("part2/UDPproxy/config.properties");
        // InputStream crypto_config = new FileInputStream("cryptoconfig.properties");
        Scanner scanner = new Scanner(System.in);

        Properties config_properties = new Properties();
        // Properties cryptoconfig_properties = new Properties();
        config_properties.load(config);
        // cryptoconfig_properties.load(crypto_config);

        String remote = config_properties.getProperty("remote");
        String proxy = config_properties.getProperty("proxy");
        String destination = config_properties.getProperty("localdelivery");
        String available_films = config_properties.getProperty("available_films");

        String[] films_list = available_films.split(",");

        SocketAddress serverSocketAddress = parseSocketAddress(remote);

        String movie = selectMovie(scanner, films_list, serverSocketAddress);
        String ciphersuite_selected = startSHPclient(movie, serverSocketAddress);
        movieTransmissionToLocal(proxy, destination, ciphersuite_selected);

    }

    private static String startSHPclient(String movie, SocketAddress serverSocketAddress) throws Exception {
        DatagramSocket socket = new DatagramSocket();

        byte[] client_hello_messsage = buildClientHelloMessage(movie);
        sendSHPclientHelloMessage(client_hello_messsage, serverSocketAddress, socket);

        byte[] serverHelloBytes = receiveServerHello(socket);
        ServerHello sh = ServerHello.deserialize(serverHelloBytes);
        verifyServerHello(sh);
        deriveSessionKey(sh);

        socket.close();

        return sh.getSelected_cipher_suite();
    }

    private static void sendSHPclientHelloMessage(byte[] client_hello_messsage, SocketAddress serverSocketAddress,
            DatagramSocket socket) throws IOException {

        DatagramPacket packet = new DatagramPacket(client_hello_messsage, client_hello_messsage.length,
                serverSocketAddress);
        socket.send(packet);
    }

    private static byte[] receiveServerHello(DatagramSocket socket) throws IOException {
        byte[] buffer = new byte[8192];

        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        socket.receive(packet);

        return Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
    }

    private static void verifyServerHello(ServerHello sh) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        Certificate serverCert = factory.generateCertificate(new ByteArrayInputStream(sh.getCertificate()));

        KeyStore store = loadKeyStore(TRUSTSTORE_PATH, "pedrodiogo".toCharArray());

        if (!isCertificateTrusted(serverCert, store))
            throw new Exception("Server certificate not trusted.");

        PublicKey serverPub = serverCert.getPublicKey();
        boolean valid = CryptoUtils.verify(serverPub, sh.serializeData(), sh.getSignature());

        if (!valid)
            throw new Exception("Invalid signature.");

        byte[] nonce = computeNonceResponse(client_nonce);

        if (!Arrays.equals(nonce, sh.getClient_nonce_response()))
            throw new Exception("Client nonce does not match.");

        List<String> ciphersuites = Arrays.asList("AES/CTR/NoPadding", "AES/CBC/PKCS5Padding", "ChaCha20-Poly1305",
                "AES/GCM/NoPadding");
        if (!ciphersuites.contains(sh.getSelected_cipher_suite()))
            throw new Exception("Ciphersuite selected is not possible.");

        System.out.println("ServerHello was successfully received!");
    }

    private static void deriveSessionKey(ServerHello sh) throws Exception {
        PublicKey serverECDHPub = CryptoUtils.decodePublicKey(sh.getServer_pub_ECDH_key());

        byte[] sharedSecret = CryptoUtils.deriveSharedSecret(client_ECDH_PrivateKey, serverECDHPub);

        String cipher = sh.getSelected_cipher_suite();

        int keySize = cipher.contains("ChaCha20") ? 32 : 16;

        String algorithm = cipher.contains("ChaCha20") ? "ChaCha20" : "AES";

        byte[] encryptionKeyBytes = CryptoUtils.hmacDF(sharedSecret, "encryption".getBytes(), keySize);
        encryptionKey = new SecretKeySpec(encryptionKeyBytes, algorithm);
        System.out.println("Encryption key: " + Base64.getEncoder().encodeToString(encryptionKeyBytes));

        byte[] macKeyBytes = CryptoUtils.hmacDF(sharedSecret, "mac".getBytes(), 32);
        macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");
        System.out.println("Mac key: " + Base64.getEncoder().encodeToString(macKeyBytes));
    }

    private static byte[] buildClientHelloMessage(String movie) throws Exception {

        char[] key_store_pass = "pedrodiogo".toCharArray();
        String alias = "proxy";

        KeyStore proxy_key_store = loadKeyStore(KEYSTORE_PATH, key_store_pass);

        PrivateKey proxy_private_key = loadPrivateKey(proxy_key_store, alias, key_store_pass);

        byte[] proxy_certificate = loadCertificateBytes(proxy_key_store, alias);

        KeyPair ECDH_key_pair = CryptoUtils.generateECDHKeyPair();
        client_ECDH_PrivateKey = ECDH_key_pair.getPrivate();

        byte[] encoded_ECDH_public_key = ECDH_key_pair.getPublic().getEncoded();

        byte[] nonce = generateNonce();
        client_nonce = nonce;

        List<String> supported_cipher_suites = null;
        switch (movie) {
            case "cars.dat":
                supported_cipher_suites = List.of("AES/CTR/NoPadding", "AES/CBC/PKCS5Padding");
                break;
            case "monsters.dat":
                supported_cipher_suites = List.of("ChaCha20-Poly1305", "AES/GCM/NoPadding");
                break;
            default:
                System.out.println("MOVIE NOT AVAILABLE");
                System.exit(1);
        }

        ClientHello ch = new ClientHello(movie, proxy_certificate, encoded_ECDH_public_key, null, nonce,
                supported_cipher_suites);

        byte[] data_to_sign = ch.serializeData();

        byte[] signature = CryptoUtils.sign(proxy_private_key, data_to_sign);

        ch.setSignature(signature);

        byte[] final_message = ch.serializeWithSignature();

        return final_message;
    }

    private static String selectMovie(Scanner scanner, String[] films_list,
            SocketAddress serverSocketAddress) throws IOException {
        System.out.println("Select one movie from the following list: ");

        for (String movie : films_list) {
            System.out.println("> " + movie);
        }

        String movie_selected = scanner.nextLine();

        return movie_selected;
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    private static void movieTransmissionToLocal(String proxy, String destination,
            String ciphersuite_selected) throws Exception {

        SocketAddress inSocketAddress = parseSocketAddress(proxy);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destination.split(",")).map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        DatagramSocket inSocket = new DatagramSocket(inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] in_packet_buffer = new byte[MAX_PACKET_SIZE];

        long lastSeq = -1;

        boolean streaming = true;
        while (streaming) {
            DatagramPacket inPacket = new DatagramPacket(in_packet_buffer, in_packet_buffer.length);
            inSocket.receive(inPacket);

            System.out.println("Packet successfully received from server.");

            ByteBuffer bb = ByteBuffer.wrap(inPacket.getData(), 0, inPacket.getLength());

            byte type = bb.get();
            byte version = bb.get();
            long seqNum = bb.getLong();
            int length = bb.getInt();

            byte[] payload = new byte[length];
            bb.get(payload);

            switch (type) {
                case START_TYPE:
                    System.out.println("> PROTOCOL VERSION: " + version);
                    System.out.println("> Starting streaming now !");
                    break;
                case DATA_TYPE:
                    if (seqNum <= lastSeq) {
                        System.out.println("Packet was discarded.");
                        break;
                    }

                    lastSeq = seqNum;
                    sendFrame(payload, outSocketAddressSet, outSocket, ciphersuite_selected, seqNum);
                    break;
                case END_TYPE:
                    streaming = false;
                    inSocket.close();
                    System.out.println("\n> Stream has ended !");
                    break;
                case ERROR_TYPE:
                    System.out.println("AN ERROR HAS OCCURRED !");
                    System.exit(1);
                default:
                    System.out.println("> Packet type not defined !!");
                    break;
            }
        }
    }

    private static void sendFrame(byte[] payload, Set<SocketAddress> outSocketAddressSet, DatagramSocket outSocket,
            String ciphersuite_selected,
            long seqNum)
            throws Exception {

        Ciphersuite cipher = null;

        switch (ciphersuite_selected) {
            case "AES/CTR/NoPadding":
                cipher = new AesCtrHmacSuite(macKey);
                break;
            case "AES/CBC/PKCS5Padding":
                cipher = new AesCbcHmacSuite(macKey);
                break;
            case "ChaCha20-Poly1305":
                cipher = new ChaCha20Poly1305Suite();
                break;
            case "AES/GCM/NoPadding":
                cipher = new AesGcmSuite();
                break;
            default:
                break;
        }

        byte[] payload_decrypted = cipher.decrypt(payload, encryptionKey, seqNum);

        for (SocketAddress outSocketAddress : outSocketAddressSet) {
            outSocket.send(new DatagramPacket(payload_decrypted, payload_decrypted.length, outSocketAddress));
        }
    }

    private static KeyStore loadKeyStore(String path, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");

        try (FileInputStream fis = new FileInputStream(path)) {
            ks.load(fis, password);
        }

        return ks;
    }

    private static PrivateKey loadPrivateKey(KeyStore ks, String alias, char[] keyPassword) throws Exception {

        return (PrivateKey) ks.getKey(alias, keyPassword);
    }

    private static byte[] loadCertificateBytes(KeyStore ks, String alias) throws Exception {

        Certificate cert = ks.getCertificate(alias);

        if (cert == null) {
            throw new IllegalArgumentException("Certificate not found for alias: " + alias);
        }

        return cert.getEncoded();
    }

    private static byte[] generateNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static boolean isCertificateTrusted(Certificate receivedCert, KeyStore trustStore) throws Exception {
        String alias = trustStore.getCertificateAlias(receivedCert);

        return alias != null;
    }

    private static byte[] computeNonceResponse(
            byte[] serverNonce) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        return md.digest(serverNonce);
    }

}
