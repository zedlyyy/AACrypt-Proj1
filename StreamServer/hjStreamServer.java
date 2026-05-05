/*
* hjStreamServer.java 
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.*;

class hjStreamServer {

	private static int SERVER_PORT 	= 8888;
	private static int PROXY_PORT 	= 9999;
	private static String FILMS_FOLDER = "movies/";
	static public void main( String []args ) throws Exception {
	    if (args.length != 1) {
            System.out.println("Erro, usar: mySend <ip-multicast-address>");
	        System.out.println("        or: mySend <ip-unicast-address>");
	        System.exit(-1);
        }		
		String movie_selected = receiveMovie();
		movieTransmissionToProxy(movie_selected, args[0], PROXY_PORT);

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

	private static void movieTransmissionToProxy(String movie, String hostname, int port) throws IOException, InterruptedException{
		int size;
		int csize = 0;
		int count = 0;
 		long time;
		DataInputStream g = new DataInputStream( new FileInputStream(movie) );
		byte[] buff = new byte[4096];

		DatagramSocket s = new DatagramSocket();
		InetSocketAddress addr = new InetSocketAddress( hostname, port);
		DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
		long t0 = System.nanoTime(); // Ref. time 
		long q0 = 0;

		// Each frame has:
		// Short size || Long Timestamp || byte[] EncodedMP4Frame

		while ( g.available() > 0 ) {
		    
		    size = g.readShort(); // size of the frame
		    csize=csize+size;
		    time = g.readLong();  // timestamp of the frame
			if ( count == 0 ) q0 = time; // ref. time in the stream
			count += 1;
			g.readFully(buff, 0, size );
			p.setData(buff, 0, size );
			p.setSocketAddress( addr );

			long t = System.nanoTime(); // what time is it?

			// Decision about the right time to transmit
			Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000));
		   
		    // send datagram (udp packet) w/ payload frame)
			// Frames sent in clear (no encryption)

			s.send(p); 

	        // Just for awareness ... (debug)

			System.out.print( ":" );
		}

		long tend = System.nanoTime(); // "The end" time 
        System.out.println();
		System.out.println("DONE! all frames sent: "+ count);

		long duration=(tend-t0)/1000000000;
		System.out.println("Movie duration "+ duration + " s");
		System.out.println("Throughput "+ count/duration + " fps");
     	System.out.println("Throughput "+ (8*(csize)/duration)/1000 + " Kbps");

	}
}



