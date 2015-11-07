import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.cert.CertificateExpiredException;


public class SSLSocketClient {


	private static boolean isValid(X509Certificate cert,javax.security.cert.X509Certificate certRoot){
		  try {
		    cert.verify(certRoot.getPublicKey());
		  }
		 catch (  Exception e) {
		    return false;
		  }
		  return true;
		}
	//one function to validate all certificates
	//validate 
	//The certificate validity period is checked against the current time provided by the verifier’s system clock.
	//
	//private void validate
	  public static void main(String[] args) throws Exception {
		  String urlString = args[0].toString();
		   int port = Integer.valueOf(args[1]);//args[1];
			    Security.addProvider(
			      new com.sun.net.ssl.internal.ssl.Provider());
			    //tcp connect to any server e.g. google.com, 443  
			    //to do user will enter www.google.com make it https://www.google.com
			    SSLSocketFactory factory = (SSLSocketFactory)SSLSocketFactory.getDefault();
                //root certificate variable
		        javax.security.cert.X509Certificate certRoot =null;

			    SSLSocket socket;
			    //javax.security.cert.X509Certificate[] cert;
				try {
					//tcp connect
					socket = (SSLSocket)factory.createSocket(urlString, port);
				    SSLSession ss = socket.getSession();
			        // tls handshake
			        socket.startHandshake();
			        System.out.println("Handshake Done");
			        javax.security.cert.X509Certificate[] cert =ss.getPeerCertificateChain();
			        certRoot = cert[cert.length-1];
			        for (int i=cert.length-1; i>= 0; i--){
			        // print as mentioned in the assignment
			        System.out.println("Certificate issuer:");
			        System.out.println("--Organization Name/Unit:" + cert[i].getIssuerDN());
			        System.out.println("Certificate subject:");
			        System.out.println("--Organization Name:" + cert[i].getSubjectDN());
			        System.out.println("===");
			       
			        //verify validity of all certificates based on current date
			        try {
						cert[i].checkValidity(new Date());
					} catch (CertificateExpiredException ce) {
						ce.printStackTrace();
					}
			        // check issuer with subject except root issuer.
			        	if(i!=0){
			        		if(cert[i].getSubjectDN().equals(cert[i-1].getIssuerDN())){
			        	    System.out.print("\n \n IssuerDN matches with SubjectDN for this certificate! \n \n");
			        		}
			        	}
			        
			        }
			        
				} catch (IOException io) {
					// can be tcp connect or handshake failed.
					io.printStackTrace();
				}
				 //read all the trusted CA from java keystore
				 // Load the JDK's cacerts keystore file
				 // verify public key of the root certificate
		            String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
		            FileInputStream is = new FileInputStream(filename);
		            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		            String password = "changeit";
		            keystore.load(is, password.toCharArray());

		            // This class retrieves the most-trusted CAs from the keystore
		            PKIXParameters params = new PKIXParameters(keystore);

		            // Get the set of trust anchors, which contain the most-trusted CA certificates
		            Iterator it = params.getTrustAnchors().iterator();
		            while( it.hasNext() ) {
		                TrustAnchor ta = (TrustAnchor)it.next();
		                // Get certificate
		                X509Certificate cert = ta.getTrustedCert();
		                //if (certRoot.verify(cert.getPublicKey()))
		               // System.out.println("PRINTING JAVA CERTS");
		                //System.out.println(cert);
		                //System.out.println("Verifying public key of the root CA....");
		                //verify only public key of the root
		                if(isValid(cert,certRoot)){
		                	System.out.println("Verified!!!!!");//cert.verify(certRoot.getPublicKey());
		                }
		            }
			    

	  }	
}
