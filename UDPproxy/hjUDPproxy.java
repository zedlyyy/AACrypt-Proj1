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
import java.net.MulticastSocket;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import cipherSuites.AesCbcHmacSuite;
import cipherSuites.AesCtrHmacSuite;
import cipherSuites.AesGcmSuite;
import cipherSuites.ChaCha20Poly1305Suite;
import cipherSuites.Ciphersuite;

class hjUDPproxy {

    private static final int MAX_PACKET_SIZE = 8192;
    private static final byte START_TYPE = 1;
    private static final byte DATA_TYPE = 2;
    private static final byte END_TYPE = 3;
    private static final byte ERROR_TYPE = 4;

    // @SuppressWarnings("unused")
    public static void main(String[] args) throws Exception {
        InputStream config = new FileInputStream("UDPproxy/config.properties");
        InputStream crypto_config = new FileInputStream("cryptoconfig.properties");
        Scanner scanner = new Scanner(System.in);

        if (config == null || crypto_config == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }

        Properties config_properties = new Properties();
        Properties cryptoconfig_properties = new Properties();
        config_properties.load(config);
        cryptoconfig_properties.load(crypto_config);
        String remote = config_properties.getProperty("remote");
        String proxy = config_properties.getProperty("proxy");
        String destination = config_properties.getProperty("localdelivery");
        String available_films = config_properties.getProperty("available_films");

        String[] films_list = available_films.split(",");

        SocketAddress serverSocketAddress = parseSocketAddress(remote);

        String movieAndCiphersuite = selectMovieAndCipherSuite(scanner, films_list, serverSocketAddress);
        movieTransmissionToLocal(proxy, destination, movieAndCiphersuite, cryptoconfig_properties);

    }

    private static String selectMovieAndCipherSuite(Scanner scanner, String[] films_list,
            SocketAddress serverSocketAddress) throws IOException {
        System.out.println("Select one movie from the following list: ");

        for (String movie : films_list) {
            System.out.println("> " + movie);
        }

        String movie_selected = scanner.nextLine();
        String ciphersuite_selected = "";

        switch (movie_selected) {
            case "cars.dat":
                System.out.println("Select one ciphersuite from the following list: ");
                System.out.println("1 - " + "AES/CTR/NoPadding");
                System.out.println("2 - " + "AES/CBC/PKCS5Padding");

                ciphersuite_selected = scanner.nextLine();
                if (ciphersuite_selected.equals("1"))
                    ciphersuite_selected = "AES/CTR/NoPadding";
                else if (ciphersuite_selected.equals("2"))
                    ciphersuite_selected = "AES/CBC/PKCS5Padding";
                else
                    System.out.println("Ciphersuite selection failed.");

                break;
            case "monsters.dat":
                System.out.println("Select one ciphersuite from the following list: ");
                System.out.println("1 - " + "ChaCha20-Poly1305");
                System.out.println("2 - " + "AES/GCM/NoPadding");

                ciphersuite_selected = scanner.nextLine();
                if (ciphersuite_selected.equals("1"))
                    ciphersuite_selected = "ChaCha20-Poly1305";
                else if (ciphersuite_selected.equals("2"))
                    ciphersuite_selected = "AES/GCM/NoPadding";
                else
                    System.out.println("Ciphersuite selection failed.");
                break;
            default:
                System.out.println("MOVIE NOT AVAILABLE");
                System.exit(1);
        }
        scanner.close();

        String info = movie_selected + "," + ciphersuite_selected;
        byte[] data = info.getBytes();

        DatagramPacket packet = new DatagramPacket(data, data.length, serverSocketAddress);

        DatagramSocket s = new DatagramSocket();
        s.send(packet);

        s.close();

        return info;
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    private static void movieTransmissionToLocal(String proxy, String destination, String movieAndCiphersuite,
            Properties cryptoconfig_properties) throws Exception {

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
                    sendFrame(payload, outSocketAddressSet, outSocket, movieAndCiphersuite, cryptoconfig_properties, seqNum);
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
            String movieAndCiphersuite, Properties cryptoconfig_properties, long seqNum)
            throws Exception {
        System.out.print(".");

        Ciphersuite cipher = null;
        String cipherNum = "0";
        String movieKey = "";

        String keyHex = "";
        byte[] keyBytes = null;
        SecretKey macKey = null;

        String[] info = movieAndCiphersuite.split(",");
        String movie_selected = info[0];
        String ciphersuite_selected = info[1];

        switch (ciphersuite_selected) {
            case "AES/CTR/NoPadding":
                cipherNum = "1";
                keyHex = cryptoconfig_properties.getProperty(movie_selected + ".mackey" + cipherNum);
                keyBytes = hexToBytes(keyHex);
                macKey = new SecretKeySpec(keyBytes, "HmacSHA256");
                cipher = new AesCtrHmacSuite(macKey);
                break;
            case "AES/CBC/PKCS5Padding":
                cipherNum = "2";
                keyHex = cryptoconfig_properties.getProperty(movie_selected + ".mackey" + cipherNum);
                keyBytes = hexToBytes(keyHex);
                macKey = new SecretKeySpec(keyBytes, "HmacSHA256");
                cipher = new AesCbcHmacSuite(macKey);
                break;
            case "ChaCha20-Poly1305":
                cipher = new ChaCha20Poly1305Suite();
                cipherNum = "1";
                break;
            case "AES/GCM/NoPadding":
                cipher = new AesGcmSuite();
                cipherNum = "2";
                break;
            default:
                break;
        }

        if (ciphersuite_selected.contains("AES"))
            movieKey = "AES";
        else if (ciphersuite_selected.contains("ChaCha20"))
            movieKey = "ChaCha20";
        else
            throw new IllegalArgumentException("Unsupported algorithm");

        keyHex = cryptoconfig_properties.getProperty(movie_selected + ".key" + cipherNum);
        keyBytes = hexToBytes(keyHex);
        SecretKey key = new SecretKeySpec(keyBytes, movieKey);

        byte[] payload_decrypted = cipher.decrypt(payload, key, seqNum);

        for (SocketAddress outSocketAddress : outSocketAddressSet) {
            outSocket.send(new DatagramPacket(payload_decrypted, payload_decrypted.length, outSocketAddress));
        }
    }

    private static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string");
        }

        byte[] bytes = new byte[hex.length() / 2];

        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(
                    hex.substring(2 * i, 2 * i + 2),
                    16);
        }

        return bytes;
    }

}
