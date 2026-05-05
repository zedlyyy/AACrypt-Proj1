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
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

class hjUDPproxy {
    @SuppressWarnings("unused")
    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("config.properties");
        Scanner scanner = new Scanner(System.in);
        
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        
        Properties properties = new Properties();
        properties.load(inputStream);
	    String remote =             properties.getProperty("remote");
        String proxy =              properties.getProperty("proxy");
        String destination =        properties.getProperty("localdelivery");
        String available_films =    properties.getProperty("available_films");
        
        String[] films_list = available_films.split(",");

        SocketAddress serverSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destination.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

        selectMovie(scanner, films_list, serverSocketAddress);
        movieTransmissionToLocal(proxy, destination);

    }

    private static void selectMovie(Scanner scanner, String[] films_list, SocketAddress serverSocketAddress) throws IOException {
        System.out.println("Select one movie from the following list: ");
        
        for (String movie : films_list){
            System.out.println("> " + movie);
        }

        String movie_selected = scanner.nextLine();
        scanner.close();

        byte[] data = movie_selected.getBytes();

        DatagramPacket packet = new DatagramPacket(data, data.length, serverSocketAddress);

        DatagramSocket s = new DatagramSocket();
        s.send(packet);

        s.close();
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }

    private static void movieTransmissionToLocal(String proxy, String destination) throws IOException {

        SocketAddress inSocketAddress = parseSocketAddress(proxy);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destination.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

	    DatagramSocket inSocket = new DatagramSocket(inSocketAddress); 
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];
       
        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
 	        inSocket.receive(inPacket); 

            System.out.print(".");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
              outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
            }
        }
    }
}
