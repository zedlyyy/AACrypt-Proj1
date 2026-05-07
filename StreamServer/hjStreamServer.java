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

class hjStreamServer {

	private static final int SERVER_PORT 	= 8888;
	private static final int PROXY_PORT 	= 9999;
	private static final String FILMS_FOLDER = "movies/";
	private static final byte PROTOCOL_VERSION = 1;
	private static final int HEADER_SIZE	= 6;
	private static final byte START_TYPE	= 1;
	private static final byte DATA_TYPE		= 2; 
	private static final byte END_TYPE		= 3;
	private static final byte ERROR_TYPE	= 4;
	private static final int IV_SIZE		= 16;


	static public void main( String []args ) throws Exception {
	    if (args.length != 1) {
            System.out.println("Erro, usar: mySend <ip-multicast-address>");
	        System.out.println("        or: mySend <ip-unicast-address>");
	        System.exit(-1);
        }	
		
		String hostname = args[0];
		InputStream crypto_config   = new FileInputStream("../cryptoconfig.properties");

		Properties cryptoconfig_properties  = new Properties();
		cryptoconfig_properties.load(crypto_config);

		String movie_selected = receiveMovie();
		startTransmission(movie_selected, hostname, PROXY_PORT, cryptoconfig_properties);
		movieTransmissionToProxy(movie_selected, hostname, PROXY_PORT, cryptoconfig_properties);
		endTransmission(movie_selected, hostname, PROXY_PORT, cryptoconfig_properties);

	}

	private static void startTransmission(String movie, String hostname, int proxyPort, Properties cryptoconfig_properties) throws IOException {

        DatagramPacket packet = buildRTSSPPacket(START_TYPE, 0, hostname, proxyPort, null, cryptoconfig_properties, movie);

        DatagramSocket s = new DatagramSocket();
        s.send(packet);

        s.close();

	}

	//Method to receive the movie name from the proxy
	private static String receiveMovie() throws IOException {

		DatagramSocket s = new DatagramSocket(SERVER_PORT);
		byte[] buffer = new byte[1024];

		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

		System.out.println("Waiting for movie request from proxy...");

		s.receive(packet);

		String movie_name = new String(packet.getData(), 0, packet.getLength()).trim();

		s.close();

		String movie_file_path = FILMS_FOLDER + movie_name;

		return movie_file_path;	
	}

	private static void movieTransmissionToProxy(String movie, String hostname, int proxy_port, Properties cryptoconfig_properties) throws IOException, InterruptedException {

    int size;
    int csize = 0;
    int count = 0;
    long time;

    byte[] frame_buffer = new byte[4096];

    try (
        DataInputStream g = new DataInputStream(new FileInputStream(movie));
        DatagramSocket s = new DatagramSocket()	
    )	{
        long t0 = System.nanoTime();
        long q0 = 0;

        while (g.available() > 0) {

            size = g.readShort();
            csize = csize + size;

            time = g.readLong();

            if (count == 0) q0 = time;
            count += 1;

            g.readFully(frame_buffer, 0, size);

            DatagramPacket p = buildRTSSPPacket(DATA_TYPE, size, hostname, proxy_port, frame_buffer, cryptoconfig_properties, movie);

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
			internalError(hostname, proxy_port, movie, cryptoconfig_properties);
		}
	}


	private static DatagramPacket buildRTSSPPacket(byte data_type, int payload_size, String hostname, int port, byte[] payload, Properties cryptoconfig_properties, String movie) {
		
		InetSocketAddress addr = new InetSocketAddress(hostname, port);


		// COULD HAVE NULL PAYLOADS (FOR NOW)
		//	if(payload_size > 0 && payload != null){
		//		byte[] payload_encrypted = payloadEncryption(payload);
		//		bb.put(payload, 0, payload_size);
		//	} 

		// START AND END MESSAGES NOT INCLUDED (YET)
		// RIGHT NOW THEY HAVE NULL PAYLOADS WHICH RESULTS IN AN EXCEPTION

		byte[] true_payload = Arrays.copyOf(payload, payload_size);

		byte[] encrypted_payload = payloadEncryption(true_payload, cryptoconfig_properties, movie);
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

	//Vamos ter que talvez perguntar ao user que tipo the cipher suite quer usar para a stream, algo do tipo:
	//"Que ciphersuite quer utilizar (escolha um número)?""
	//> 1 - AES/CTR/NoPadding
	//> 2 - AES/CBC/PKCS5Padding
	//Só vão exister duas opções pois cada filme só tem duas ciphersuites diferentes.
	private static byte[] payloadEncryption(byte[] payload, Properties cryptoconfig_properties, String movie) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("Unimplemented method 'payloadEncryption'");
	}

	private static void endTransmission(String movie, String hostname, int proxyPort, Properties cryptoconfig_properties) throws IOException {
		
		DatagramPacket packet = buildRTSSPPacket(END_TYPE, 0, hostname, proxyPort, null, cryptoconfig_properties, movie);

        DatagramSocket s = new DatagramSocket();
        s.send(packet);

        s.close();
	}

	private static void internalError(String hostname, int proxyPort, String movie, Properties cryptoconfig_properties) throws IOException {
		
		DatagramPacket packet = buildRTSSPPacket(ERROR_TYPE, 0, hostname, proxyPort, null, cryptoconfig_properties, movie);

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
				16
			);
		}

		return bytes;
	}

}



