package part2.StreamServer;

/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
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

class hjStreamServer {

	private static final int SERVER_PORT = 8888;
	private static final int PROXY_PORT = 9999;
	private static final String FILMS_FOLDER = "StreamServer/movies/";
	private static final String KEYSTORE_PATH = "part2/StreamServer/server-truststore.p12";
	private static final byte PROTOCOL_VERSION = 1;
	private static final int HEADER_SIZE = 14;
	private static final byte START_TYPE = 1;
	private static final byte DATA_TYPE = 2;
	private static final byte END_TYPE = 3;
	private static final byte ERROR_TYPE = 4;

	static public void main(String[] args) throws Exception {
		if (args.length != 1) {
			System.out.println("Erro, usar: mySend <ip-multicast-address>");
			System.out.println("        or: mySend <ip-unicast-address>");
			System.exit(-1);
		}

		Scanner scanner = new Scanner(System.in);
		String hostname = args[0];

		DatagramSocket s = new DatagramSocket(SERVER_PORT);

		//String movie_selected = movieSelected(s);

		String[] ciphersuite_and_movie = startSHPserver(s, scanner);
		
		String ciphersuite_selected = ciphersuite_and_movie[0];
		String movie_selected = ciphersuite_and_movie[1];

		
		startTransmission(movie_selected, ciphersuite_selected, hostname, PROXY_PORT);
		movieTransmissionToProxy(movie_selected, ciphersuite_selected, hostname, PROXY_PORT);
		endTransmission(movie_selected, ciphersuite_selected, hostname, PROXY_PORT);

	}

	private static String[] startSHPserver(DatagramSocket s, Scanner scanner) throws Exception {
		byte[] client_message_byte = receiveSHPclientHelloMessage(s);

		ClientHello ch = ClientHello.deserialize(client_message_byte);
		clientHelloVerification(ch);
		String cipher_selected = selectCiphersuite(ch.getCipherSuites(), scanner);

		System.out.println("TODO");
		return null;
	}

	private static String selectCiphersuite(List<String> cipher_suites, Scanner scanner) {
		System.out.println("Select one Ciphersuite from the following list: ");

        for (int i = 1; i <= cipher_suites.size(); i++) {
            System.out.println(i + " - " + cipher_suites.get(i-1));
        }

        String choise_selected = scanner.nextLine();
		String ciphersuite_selected = "";
		if (choise_selected.equals("1"))
                ciphersuite_selected = cipher_suites.get(0);
            else if (ciphersuite_selected.equals("2"))
                ciphersuite_selected = cipher_suites.get(1);
            else
                System.out.println("Ciphersuite selection failed.");
		
		return ciphersuite_selected;
	}

	private static void clientHelloVerification(ClientHello ch) throws Exception {
		
		CertificateFactory cf = CertificateFactory.getInstance("X.509");

    	Certificate clientCert = cf.generateCertificate( new ByteArrayInputStream(ch.getCertificate()));

		KeyStore serverTrustStore = loadKeyStore(KEYSTORE_PATH, "pedrodiogo".toCharArray());

		if (!isCertificateTrusted(clientCert, serverTrustStore)) {
        	throw new SecurityException("Client certificate is not trusted");
    	}

		PublicKey clientPublicKey = clientCert.getPublicKey();

		boolean validSignature = CryptoUtils.verify(clientPublicKey, ch.serializeData(), ch.getSignature());

		if (!validSignature) {
        	throw new SecurityException("Invalid ClientHello signature");
    	}

		System.out.println("ClientHello accepted.");
    	System.out.println("Requested movie: " + ch.getMovie_name());

	}

	private static byte[] receiveSHPclientHelloMessage(DatagramSocket s) throws IOException {
		System.out.println("Waiting for proxy connection ...");
		byte[] buffer = new byte[8192];

    	DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

    	s.receive(packet);

    	return Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
	}

	private static void startTransmission(String movie, String ciphersuite, String hostname, int proxyPort) throws Exception {

		DatagramPacket packet = buildRTSSPPacket(START_TYPE, 0, hostname, proxyPort, null,
				movie, ciphersuite, 0);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();

	}

	private static void movieTransmissionToProxy(String movie, String ciphersuite, String hostname, int proxy_port) throws Exception {

		int size;
		int csize = 0;
		int count = 0;
		long time;

		byte[] frame_buffer = new byte[4096];

		try (
				DataInputStream g = new DataInputStream(new FileInputStream(FILMS_FOLDER + movie));
				DatagramSocket s = new DatagramSocket()) {
			long t0 = System.nanoTime();
			long q0 = 0;
			long seqNum = 0;

			while (g.available() > 0) {

				size = g.readShort();
				csize = csize + size;
				seqNum++;

				time = g.readLong();

				if (count == 0)
					q0 = time;
				count += 1;

				g.readFully(frame_buffer, 0, size);

				DatagramPacket p = buildRTSSPPacket(DATA_TYPE, size, hostname, proxy_port, frame_buffer, movie, ciphersuite, seqNum);

				long t = System.nanoTime();

				Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

				s.send(p);

				System.out.print(":");
			}

			long tend = System.nanoTime();

			System.out.println();
			System.out.println("DONE! \nTotal frames sent: " + count);

			long duration = (tend - t0) / 1000000000;

			System.out.println("Movie duration " + duration + " s");

			if (duration > 0) {
				System.out.println("Throughput " + count / duration + " fps");
				System.out.println("Throughput " + (8 * csize / duration) / 1000 + " Kbps");
			}

		} catch (FileNotFoundException e) {
			internalError(hostname, proxy_port, movie, ciphersuite);
		}
	}

	private static DatagramPacket buildRTSSPPacket(byte data_type, int payload_size, String hostname, int port,
			byte[] payload, String movie, String ciphersuite, long seqNum) throws Exception {

		InetSocketAddress addr = new InetSocketAddress(hostname, port);

		byte[] true_payload;

		if (payload == null)
			true_payload = new byte[0];
		else
			true_payload = Arrays.copyOf(payload, payload_size);

		byte[] encrypted_payload = payloadEncryption(true_payload, movie, ciphersuite, seqNum);
		ByteBuffer bb = ByteBuffer.allocate(HEADER_SIZE + encrypted_payload.length);
		int encrypted_payload_size = encrypted_payload.length;

		// HEADER CONTENT
		bb.put(data_type);
		bb.put(PROTOCOL_VERSION);
		bb.putLong(seqNum);
		bb.putInt(encrypted_payload_size);
		bb.put(encrypted_payload, 0, encrypted_payload_size);

		byte[] packet_buffer = bb.array();

		return new DatagramPacket(packet_buffer, packet_buffer.length, addr);
	}

	private static byte[] payloadEncryption(byte[] payload, String movie,
			String ciphersuite_selected, long seqNum)
			throws Exception {
		Ciphersuite cipher = null;
		String cipherNum = "0";
		String movieKey = "";
		String keyHex = "";
		byte[] keyBytes = null;
		SecretKey macKey = null;

		switch (ciphersuite_selected) {
			case "AES/CTR/NoPadding":
				cipherNum = "1";
				//keyHex = cryptoconfig_properties.getProperty(movie + ".mackey" + cipherNum);
				keyBytes = hexToBytes(keyHex);
				macKey = new SecretKeySpec(keyBytes, "HmacSHA256");
				cipher = new AesCtrHmacSuite(macKey);
				break;
			case "AES/CBC/PKCS5Padding":
				cipherNum = "2";
				//keyHex = cryptoconfig_properties.getProperty(movie + ".mackey" + cipherNum);
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

		//keyHex = cryptoconfig_properties.getProperty(movie + ".key" + cipherNum);
		keyBytes = hexToBytes(keyHex);
		SecretKey key = new SecretKeySpec(keyBytes, movieKey);

		return cipher.encrypt(payload, key, seqNum);
	}

	private static void endTransmission(String movie, String ciphersuite, String hostname, int proxyPort) throws Exception {

		DatagramPacket packet = buildRTSSPPacket(END_TYPE, 0, hostname, proxyPort, null,
				movie, ciphersuite, 0);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();
	}

	private static void internalError(String hostname, int proxyPort, String movie, String ciphersuite) throws Exception {

		DatagramPacket packet = buildRTSSPPacket(ERROR_TYPE, 0, hostname, proxyPort, null,
				movie, ciphersuite, -1);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();
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


}
