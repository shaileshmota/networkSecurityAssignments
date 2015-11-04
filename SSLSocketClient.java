import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class SSLSocketClient {


	
	  public static void main(String[] args) throws Exception {
		  String urlString = args[0];//(args.length == 1) ?args[0] : "http://www.verisign.com/index.html";
		  URL url = new URL(urlString);
		  int port = Integer.valueOf(args[1]);//args[1];
			    Security.addProvider(
			      new com.sun.net.ssl.internal.ssl.Provider());
			    //tcp connect to any server e.g. google.com, 443
			    SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
			     
			    SSLSocket socket;
				try {
					socket = (SSLSocket)factory.createSocket(url.getHost(), port);
					System.out.println("Creating a SSL Socket For "+url.getHost()+" on port "+port);
					SSLSession ss = socket.getSession();
			        // tls handshake
			        socket.startHandshake(); // start the handshake
			        System.out.println("Handshake Done");
			        javax.security.cert.X509Certificate[] cert =ss.getPeerCertificateChain();
			        //X509Certificate cert=certificates[c];
			        //System.out.println(" Client certificate " + (c + 1) + ":");
			        for (int i=0; i< cert.length; i++){
			        System.out.println("********Certificate START*******" );
			        System.out.println("  Subject DN: " + cert[i].getSubjectDN());
			        System.out.println("  Subject DN: " + cert[i].getSubjectDN());
			        System.out.println("  Signature Algorithm: " + cert[i].getSigAlgName());
			        System.out.println("  Valid from: " + cert[i].getNotBefore());
			        System.out.println("  Valid until: " + cert[i].getNotAfter());
			        System.out.println("  Issuer: " + cert[i].getIssuerDN());
			        System.out.println("********Certificate END*******" );
			        
			        }
			        
				} catch (IOException io) {
					// can be tcp connect or handshake failed.
					io.printStackTrace();
				}
			    
			    
			    
		        
		        
		        // PrintWriter out = new PrintWriter(
			    //    new OutputStreamWriter(
			  //        socket.getOutputStream()));
			   // out.println("GET " + urlString + " HTTP/1.1");
			  //  out.println();
			//    out.flush();

			 //   BufferedReader in = new BufferedReader(
			//      new InputStreamReader(
			//      socket.getInputStream()));

			//    String line;

			  //  while ((line = in.readLine()) != null) {
			//      System.out.println(line);
			//    }

			 //   out.close();
			 //   in.close();
	  }	
}
