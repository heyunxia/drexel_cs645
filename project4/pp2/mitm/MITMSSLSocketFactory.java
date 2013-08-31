//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

package mitm;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.KeyManager;
import java.math.BigInteger;
import java.security.cert.*;
import java.util.Arrays;
import java.util.Collections;
/**
 * MITMSSLSocketFactory is used to create SSL sockets.
 *
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 *
 */
public final class MITMSSLSocketFactory implements MITMSocketFactory
{
    final ServerSocketFactory m_serverSocketFactory;
    final SocketFactory m_clientSocketFactory;
    final SSLContext m_sslContext;

    public KeyStore ks = null;

    /*
     *
     * We can't install our own TrustManagerFactory without messing
     * with the security properties file. Hence we create our own
     * SSLContext and initialise it. Passing null as the keystore
     * parameter to SSLContext.init() results in a empty keystore
     * being used, as does passing the key manager array obtain from
     * keyManagerFactory.getInstance().getKeyManagers(). To pick up
     * the "default" keystore system properties, we have to read them
     * explicitly. UGLY, but necessary so we understand the expected
     * properties.
     *
     */

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a fixed CA certificate
     */
    public MITMSSLSocketFactory()
	throws IOException,GeneralSecurityException
    {
	m_sslContext = SSLContext.getInstance("SSL");

	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	final KeyStore keyStore;

	if (keyStoreFile != null) {
	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

	    this.ks = keyStore;
	} else {
	    keyStore = null;
	}

	keyManagerFactory.init(keyStore, keyStorePassword);

	m_sslContext.init(keyManagerFactory.getKeyManagers(),
			  new TrustManager[] { new TrustEveryone() },
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }

    public MITMSSLSocketFactory(String issuerAlias)
	throws IOException,GeneralSecurityException
    {
	m_sslContext = SSLContext.getInstance("SSL");

	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	final KeyStore keyStore;

	if (keyStoreFile != null) {
	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

	    this.ks = keyStore;
	} else {
	    keyStore = null;
	}

	keyManagerFactory.init(keyStore, keyStorePassword);

        TrustManager [] tms = new TrustManager[1];



        tms[0] = new OnlyTrustYourself((X509Certificate)
                                       this.ks.getCertificate(issuerAlias));

	m_sslContext.init(keyManagerFactory.getKeyManagers(),
			  tms,
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }


    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a dynamically generated server certificate
     * that contains the specified common name.
     */
    public MITMSSLSocketFactory(String remoteCN, BigInteger serialno)
	throws IOException,GeneralSecurityException, Exception
    {

	m_sslContext = SSLContext.getInstance("SSL");

	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	final KeyStore keyStore;

	if (keyStoreFile != null) {
	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

	    this.ks = keyStore;
	} else {
	    keyStore = null;
	}

        try {

            System.out.println("in try");
            OnTheFlyCertGenerator certGen = new OnTheFlyCertGenerator(this.ks);

            certGen.create(remoteCN, serialno);

            assert keyStore.containsAlias(certGen.CERT_ALAIS) == true;
        }
        catch (Exception e){
            System.out.println("Caught exception " + e);
            throw(e);

        }

	keyManagerFactory.init(keyStore, keyStorePassword);

        KeyManager km = new HackerKeyManager(OnTheFlyCertGenerator.CERT_ALAIS,
                                             keyStore,
                                             keyStorePassword);

        KeyManager[] kms = new KeyManager[1];

        kms[0] = km;

	m_sslContext.init(kms,
			  new TrustManager[] { new TrustEveryone() },
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory();
    }

    public final ServerSocket createServerSocket(String localHost,
						 int localPort,
						 int timeout)
	throws IOException
    {
	final SSLServerSocket socket =
	    (SSLServerSocket)m_serverSocketFactory.createServerSocket(
		localPort, 50, InetAddress.getByName(localHost));

	socket.setSoTimeout(timeout);

	socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

	return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)
	throws IOException
    {
	final SSLSocket socket =
	    (SSLSocket)m_clientSocketFactory.createSocket(remoteHost,
							  remotePort);

	socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

	socket.startHandshake();

	return socket;
    }

    /**
     * We're carrying out a MITM attack, we don't care whether the cert
     * chains are trusted or not ;-)
     *
     */
    private static class TrustEveryone implements X509TrustManager
    {
	public void checkClientTrusted(X509Certificate[] chain,
				       String authenticationType) {
	}

	public void checkServerTrusted(X509Certificate[] chain,
				       String authenticationType) {
	}

	public X509Certificate[] getAcceptedIssuers()
	{
	    return null;
	}
    }

    private class OnlyTrustYourself implements X509TrustManager
    {

        private X509Certificate[] acceptedIssuers = new X509Certificate[1];

        public OnlyTrustYourself(X509Certificate issuer){
            this.acceptedIssuers[0] = issuer;
        }

	public void checkClientTrusted(X509Certificate[] chain,
				       String authenticationType)
            throws CertificateException{
            // modified from
            // http://www.javadocexamples.com/java_source/com/waterken/url/httpsy/Handler.java.html

            try {
                    CertPath path = CertificateFactory.getInstance("X.509").
                        generateCertPath(Arrays.asList(chain));
                    TrustAnchor ta = new TrustAnchor(chain[chain.length - 1], null);
                    PKIXParameters params = new PKIXParameters(Collections.singleton(ta));
                    params.setRevocationEnabled(false);
                    CertPathValidator.getInstance("PKIX").validate(path, params);
                }

            catch(Exception e) {
                    throw (CertificateException)new CertificateException().initCause(e);
            }

	}

	public void checkServerTrusted(X509Certificate[] chain,
				       String authenticationType)
            throws CertificateException{

            throw new CertificateException("Should not be using this for server auth");
	}

	public X509Certificate[] getAcceptedIssuers()
	{
	    return this.acceptedIssuers;
	}
    }
}
