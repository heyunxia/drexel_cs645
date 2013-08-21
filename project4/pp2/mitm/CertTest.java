package mitm;

import org.junit.*;
import static org.junit.Assert.*;
import mitm.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

public class CertTest {

    public static final String KEY_STORE = "keystore.jks";

    public OnTheFlyCertGenerator certGen;

    private KeyStore ks;

    @Before
    public void setUp() throws Exception{
        this.ks = KeyStore.getInstance(KeyStore.getDefaultType());

        // get user password and file input stream

        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(KEY_STORE);
            this.ks.load(fis, OnTheFlyCertGenerator.KEY_STORE_PASS.toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        this.certGen = new OnTheFlyCertGenerator(this.ks);
    }


    @Test
    public void test_getRemoteCert() throws Exception{
        URL url = new URL("https://www.yahoo.com");

        ServerConnection con = new ServerConnection(url);

        X509Certificate serverCert = (X509Certificate) con.getServerCert();

        X500Principal serverDN =  serverCert.getSubjectX500Principal();

        assertNotNull("remote cert", serverCert);

        X509Certificate fakeCert = this.certGen.create(serverDN.getName(), serverCert.getSerialNumber());

        // test that the common name from the server cert is the new
        // cert

        X500Principal fakeDN = fakeCert.getSubjectX500Principal();

        assertTrue(fakeDN.equals(serverDN));

        assertTrue(fakeCert.getSerialNumber().equals(serverCert.getSerialNumber() ));

        try {
            fakeCert.verify(this.certGen.getIssuerPublicKey());
        } catch (Exception e){
            fail();
        }

        assertTrue(this.ks.containsAlias(OnTheFlyCertGenerator.CERT_ALAIS));
    }

}
