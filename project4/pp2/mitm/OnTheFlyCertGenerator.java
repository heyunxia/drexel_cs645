/**
 * OnTheFlyCertGenerator.java
 */
package mitm;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.x509.*;
import iaik.x509.extensions.*;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;


public class OnTheFlyCertGenerator
{

    private KeyStore keyStore;
    private X509Certificate cert;
    private java.security.cert.X509Certificate caCert;
    private PrivateKey caKey;
    private PublicKey caPubKey;

    private DateFormat formatter = new SimpleDateFormat("d-MMM-yyyy,HH:mm:ss aaa");

    public static final String CA_ALIAS = "selfsigned";
    public static final String KEY_STORE_PASS = "password";
    public static final String CERT_ALAIS = "fakecert";

    public OnTheFlyCertGenerator(KeyStore ks)
        throws KeyStoreException,
               NoSuchAlgorithmException,
               UnrecoverableKeyException
    {

        assert ks != null;

        this.keyStore = ks;


        this.cert = new X509Certificate();
        this.caCert = (java.security.cert.X509Certificate) ks.getCertificate(CA_ALIAS);

        this.caKey = (PrivateKey) ks.getKey(CA_ALIAS,
                                            KEY_STORE_PASS.toCharArray());

        this.caPubKey = this.caCert.getPublicKey();


    }
    public java.security.cert.X509Certificate create(String remoteCN, BigInteger serial) throws
        Exception

    {

        this.setIssuerDN();
        this.setSubjectDN(remoteCN);
        this.setPublicKey();

        this.cert.setSerialNumber(serial);

        this.cert.setValidNotBefore( this.createNotBefore() );

        this.cert.setValidNotAfter( this.createNotAfter() );

        this.cert.setSignatureAlgorithm( this.createAlgID() );

        //Add extensions
        this.cert.addExtension(this.createEKU());

        //Very last thing to do is Sign.  Can't touch this after it's
        //signed otherwise the signature will not be valid

        this.cert.sign(this.createAlgID(), this.caKey);

        this.updateKeyStore();

        return this.cert;
    }

    private void setIssuerDN() throws Exception{
        sun.security.x509.X500Name  issuerDN =
            (sun.security.x509.X500Name) this.caCert.getIssuerDN();

        this.cert.setIssuerDN(new Name(issuerDN.getEncoded()));

    }

    private void setSubjectDN(String remoteCN) throws Exception{

        X500Principal name = new X500Principal(remoteCN);
        this.cert.setSubjectDN(new Name(name.getEncoded()));

    }

    private void setPublicKey() throws Exception{
        // So this is a major hack.  We are re-using the public /
        // private key pair of the ca certificate.
        this.cert.setPublicKey(this.caCert.getPublicKey());
    }
    private Date createNotBefore() throws ParseException{
        String notBefore = "13-Mar-1980,03:00:00 AM";

        return this.formatter.parse(notBefore);
    }

    private Date createNotAfter() throws ParseException{
        String notBefore = "13-Mar-2030,03:00:00 AM";

        return this.formatter.parse(notBefore);
    }



    private V3Extension createEKU(){
        return new ExtendedKeyUsage(ExtendedKeyUsage.serverAuth);
    }

    private AlgorithmID createAlgID(){
        return new AlgorithmID(this.caCert.getSigAlgOID(),
                               this.caCert.getSigAlgName());
    }


    public PublicKey getIssuerPublicKey() {
        return this.caPubKey;
    }

    private void updateKeyStore() throws KeyStoreException{
        Certificate[] certs = new Certificate[2];

        certs[0] = this.cert;
        certs[1] = this.caCert;

        KeyStore.Entry newEntry = new KeyStore.PrivateKeyEntry(this.caKey,
                                                               certs);


        this.keyStore.setEntry(CERT_ALAIS,
                               newEntry,
                               new KeyStore.PasswordProtection(KEY_STORE_PASS.toCharArray()));
    }
}
