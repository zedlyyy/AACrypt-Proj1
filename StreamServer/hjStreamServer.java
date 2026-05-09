/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Properties;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

import cipherSuites.AesCbcHmacSuite;
import cipherSuites.AesCtrHmacSuite;
import cipherSuites.AesGcmSuite;
import cipherSuites.ChaCha20Poly1305Suite;
import cipherSuites.Ciphersuite;

class hjStreamServer {

	private static final int SERVER_PORT = 8888;
	private static final int PROXY_PORT = 9999;
	private static final String FILMS_FOLDER = "StreamServer/movies/";
	private static final byte PROTOCOL_VERSION = 1;
	private static final int HEADER_SIZE = 6;
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

		String hostname = args[0];
		InputStream crypto_config = new FileInputStream("cryptoconfig.properties");

		Properties cryptoconfig_properties = new Properties();
		cryptoconfig_properties.load(crypto_config);

		String[] info = initialInfo();

		String movie_selected = info[0];
		String ciphersuite_selected = info[1];
		startTransmission(movie_selected, ciphersuite_selected, hostname, PROXY_PORT, cryptoconfig_properties);
		movieTransmissionToProxy(movie_selected, ciphersuite_selected, hostname, PROXY_PORT, cryptoconfig_properties);
		endTransmission(movie_selected, ciphersuite_selected, hostname, PROXY_PORT, cryptoconfig_properties);

	}

	private static void startTransmission(String movie, String ciphersuite, String hostname, int proxyPort,
			Properties cryptoconfig_properties) throws Exception {

		DatagramPacket packet = buildRTSSPPacket(START_TYPE, 0, hostname, proxyPort, null, cryptoconfig_properties,
				movie, ciphersuite);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();

	}

	// Method to receive the movie name from the proxy
	private static String[] initialInfo() throws IOException {

		DatagramSocket s = new DatagramSocket(SERVER_PORT);
		byte[] buffer = new byte[1024];

		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

		System.out.println("Waiting for movie request from proxy...");

		s.receive(packet);

		String[] info = new String(packet.getData(), 0, packet.getLength()).trim().split(",");

		s.close();

		return info;
	}

	private static void movieTransmissionToProxy(String movie, String ciphersuite, String hostname, int proxy_port,
			Properties cryptoconfig_properties) throws Exception {

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

			while (g.available() > 0) {

				size = g.readShort();
				csize = csize + size;

				time = g.readLong();

				if (count == 0)
					q0 = time;
				count += 1;

				g.readFully(frame_buffer, 0, size);

				DatagramPacket p = buildRTSSPPacket(DATA_TYPE, size, hostname, proxy_port, frame_buffer,
						cryptoconfig_properties, movie, ciphersuite);

				long t = System.nanoTime();

				Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

				s.send(p);

				System.out.print(":");
			}

			long tend = System.nanoTime();

			System.out.println();
			System.out.println("DONE! all frames sent: " + count);

			long duration = (tend - t0) / 1000000000;

			System.out.println("Movie duration " + duration + " s");

			if (duration > 0) {
				System.out.println("Throughput " + count / duration + " fps");
				System.out.println("Throughput " + (8 * csize / duration) / 1000 + " Kbps");
			}

		} catch (FileNotFoundException e) {
			internalError(hostname, proxy_port, movie, ciphersuite, cryptoconfig_properties);
		}
	}

	private static DatagramPacket buildRTSSPPacket(byte data_type, int payload_size, String hostname, int port,
			byte[] payload, Properties cryptoconfig_properties, String movie, String ciphersuite) throws Exception {

		InetSocketAddress addr = new InetSocketAddress(hostname, port);

		byte[] true_payload;

		if (payload == null)
			true_payload = new byte[0];
		else
			true_payload = Arrays.copyOf(payload, payload_size);

		byte[] encrypted_payload = payloadEncryption(true_payload, cryptoconfig_properties, movie, ciphersuite);
		ByteBuffer bb = ByteBuffer.allocate(HEADER_SIZE + encrypted_payload.length);
		int encrypted_payload_size = encrypted_payload.length;

		// HEADER CONTENT
		bb.put(data_type);
		bb.put(PROTOCOL_VERSION);
		bb.putInt(encrypted_payload_size);
		bb.put(encrypted_payload, 0, encrypted_payload_size);

		byte[] packet_buffer = bb.array();

		return new DatagramPacket(packet_buffer, packet_buffer.length, addr);
	}

	private static byte[] payloadEncryption(byte[] payload, Properties cryptoconfig_properties, String movie, String ciphersuite_selected)
			throws Exception {
		Ciphersuite cipher = null;
		String cipherNum = "0";
		String movieKey = "";

		switch (ciphersuite_selected) {
			case "AES/CTR/NoPadding":
				cipher = new AesCtrHmacSuite();
				cipherNum = "1";
				break;
			case "AES/CBC/PKCS5Padding":
				cipher = new AesCbcHmacSuite();
				cipherNum = "2";
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

		String keyHex = cryptoconfig_properties.getProperty(movie + ".key" + cipherNum);
		byte[] keyBytes = hexToBytes(keyHex);
		SecretKey key = new SecretKeySpec(keyBytes, movieKey);

		return cipher.encrypt(payload, key);
	}

	private static void endTransmission(String movie, String ciphersuite, String hostname, int proxyPort,
			Properties cryptoconfig_properties) throws Exception {

		DatagramPacket packet = buildRTSSPPacket(END_TYPE, 0, hostname, proxyPort, null, cryptoconfig_properties,
				movie, ciphersuite);

		DatagramSocket s = new DatagramSocket();
		s.send(packet);

		s.close();
	}

	private static void internalError(String hostname, int proxyPort, String movie, String ciphersuite, Properties cryptoconfig_properties)
			throws Exception {

		DatagramPacket packet = buildRTSSPPacket(ERROR_TYPE, 0, hostname, proxyPort, null, cryptoconfig_properties,
				movie, ciphersuite);

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

}
