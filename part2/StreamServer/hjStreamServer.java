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
import java.util.Base64;
import java.util.List;
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
	private static final String FILMS_FOLDER = "part2/StreamServer/movies/";
	private static final String KEYSTORE_PATH = "part2/StreamServer/server-truststore.p12";
	private static PrivateKey server_ECDH_PrivateKey;
	private static byte[] server_nonce;
	private static SecretKey macKey;
	private static SecretKey encryptionKey;
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

		// String movie_selected = movieSelected(s);

		String[] ciphersuite_and_movie = startSHPserver(s, scanner);

		String ciphersuite_selected = ciphersuite_and_movie[0];
		String movie_selected = ciphersuite_and_movie[1];

		startTransmission(movie_selected, ciphersuite_selected, hostname, PROXY_PORT);
		movieTransmissionToProxy(movie_selected, ciphersuite_selected, hostname, PROXY_PORT);
		endTransmission(movie_selected, ciphersuite_selected, hostname, PROXY_PORT);

	}

	private static String[] startSHPserver(DatagramSocket s, Scanner scanner) throws Exception {
		DatagramPacket chPacket = receiveSHPclientHelloMessage(s);

		byte[] client_message_byte = Arrays.copyOfRange(chPacket.getData(), chPacket.getOffset(),
				chPacket.getOffset() + chPacket.getLength());

		ClientHello ch = ClientHello.deserialize(client_message_byte);
		clientHelloVerification(ch);
		String cipher_selected = selectCiphersuite(ch.getCipherSuites(), scanner);

		KeyPair serverECDH = CryptoUtils.generateECDHKeyPair();
		server_ECDH_PrivateKey = serverECDH.getPrivate();

		byte[] server_hello_message = buildServerHelloMessage(cipher_selected, ch, serverECDH);
		sendServerHelloMessage(server_hello_message, s, chPacket.getSocketAddress());

		PublicKey clientECDHPublicKey = CryptoUtils.decodePublicKey(ch.getClient_pub_ECDH_key());
		byte[] sharedSecret = CryptoUtils.deriveSharedSecret(server_ECDH_PrivateKey, clientECDHPublicKey);

		int keySize = cipher_selected.contains("ChaCha20") ? 32 : 16;

		String algorithm = cipher_selected.contains("ChaCha20") ? "ChaCha20" : "AES";

		byte[] encryptionKey_bytes = CryptoUtils.hmacDF(sharedSecret, "encryption".getBytes(), keySize);
		encryptionKey = new SecretKeySpec(encryptionKey_bytes, algorithm);
		System.out.println("Encryption key: " + Base64.getEncoder().encodeToString(encryptionKey_bytes));

		byte[] macKey_bytes = CryptoUtils.hmacDF(sharedSecret, "mac".getBytes(), 32);
		macKey = new SecretKeySpec(macKey_bytes, "HmacSHA256");
		System.out.println("Mac key: " + Base64.getEncoder().encodeToString(macKey_bytes));

		return new String[] { cipher_selected, ch.getMovieName() };
	}

	private static void sendServerHelloMessage(byte[] server_hello_message, DatagramSocket s,
			SocketAddress clientAddress) throws IOException {

		DatagramPacket packet = new DatagramPacket(server_hello_message, server_hello_message.length, clientAddress);
		s.send(packet);
	}

	private static byte[] buildServerHelloMessage(String cipher_selected, ClientHello ch, KeyPair serverECDH)
			throws Exception {

		char[] key_store_pass = "pedrodiogo".toCharArray();
		String alias = "server";

		KeyStore server_key_store = loadKeyStore("part2/StreamServer/server-keystore.p12", "pedrodiogo".toCharArray());

		PrivateKey server_private_key = loadPrivateKey(server_key_store, alias, key_store_pass);

		byte[] server_certificate = loadCertificateBytes(server_key_store, alias);

		byte[] encoded_ECDH_public_key = serverECDH.getPublic().getEncoded();

		byte[] nonce = generateNonce();
		server_nonce = nonce;

		byte[] client_nonce_response = computeNonceResponse(ch.getNonce());

		ServerHello sh = new ServerHello(server_certificate, encoded_ECDH_public_key, null, server_nonce,
				client_nonce_response, cipher_selected);

		byte[] dataToSign = sh.serializeData();
		byte[] signature = CryptoUtils.sign(server_private_key, dataToSign);
		sh.setSignature(signature);

		byte[] server_hello_message = sh.serializeWithSignature();

		return server_hello_message;

	}

	private static String selectCiphersuite(List<String> cipher_suites, Scanner scanner) throws Exception {
		System.out.println("Select one Ciphersuite from the following list: ");

		for (int i = 1; i <= cipher_suites.size(); i++) {
			System.out.println(i + " - " + cipher_suites.get(i - 1));
		}

		String choice_selected = scanner.nextLine();

		if (choice_selected.equals("1"))
			return cipher_suites.get(0);
		else if (choice_selected.equals("2"))
			return cipher_suites.get(1);
		else
			throw new Exception("Ciphersuite selection failed.");
	}

	private static void clientHelloVerification(ClientHello ch) throws Exception {

		CertificateFactory cf = CertificateFactory.getInstance("X.509");

		Certificate clientCert = cf.generateCertificate(new ByteArrayInputStream(ch.getCertificate()));

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
		System.out.println("Requested movie: " + ch.getMovieName());

	}

	private static DatagramPacket receiveSHPclientHelloMessage(DatagramSocket s) throws IOException {
		System.out.println("Waiting for proxy connection ...");
		byte[] buffer = new byte[8192];

		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

		s.receive(packet);

		return packet;
	}

	private static void startTransmission(String movie, String ciphersuite, String hostname, int proxyPort)
			throws Exception {

		DatagramPacket packet = buildRTSSPPacket(START_TYPE, 0, hostname, proxyPort, null,
				movie, ciphersuite, 0);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();

	}

	private static void movieTransmissionToProxy(String movie, String ciphersuite, String hostname, int proxy_port)
			throws Exception {

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

				DatagramPacket p = buildRTSSPPacket(DATA_TYPE, size, hostname, proxy_port, frame_buffer, movie,
						ciphersuite, seqNum);

				long t = System.nanoTime();

				Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

				System.out.println("Sending frame seq=" + seqNum);
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
			e.printStackTrace();
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
		return cipher.encrypt(payload, encryptionKey, seqNum);
	}

	private static void endTransmission(String movie, String ciphersuite, String hostname, int proxyPort)
			throws Exception {

		DatagramPacket packet = buildRTSSPPacket(END_TYPE, 0, hostname, proxyPort, null,
				movie, ciphersuite, 0);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();
	}

	private static void internalError(String hostname, int proxyPort, String movie, String ciphersuite)
			throws Exception {

		DatagramPacket packet = buildRTSSPPacket(ERROR_TYPE, 0, hostname, proxyPort, null,
				movie, ciphersuite, -1);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();
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
			byte[] clientNonce) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		return md.digest(clientNonce);
	}

}
