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
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.security.auth.x500.X500Principal;


public class OnTheFlyCertGenerator
{

    private KeyStore keyStore;
    private java.security.cert.X509Certificate targetCert;
    private X509Certificate cert;
    private java.security.cert.X509Certificate caCert;
    private PrivateKey caKey;

    private DateFormat formatter = new SimpleDateFormat("d-MMM-yyyy,HH:mm:ss aaa");

    public static final String CA_ALIAS = "selfsigned";
    public static final String KEY_STORE_PASS = "password";


    public OnTheFlyCertGenerator(KeyStore ks)
        throws KeyStoreException,
               NoSuchAlgorithmException,
               UnrecoverableKeyException
    {

        this.keyStore = ks;


        this.cert = new X509Certificate();
        this.caCert = (java.security.cert.X509Certificate) ks.getCertificate(CA_ALIAS);

        this.caKey = (PrivateKey) ks.getKey(CA_ALIAS,
                                            KEY_STORE_PASS.toCharArray());


    }
    public java.security.cert.X509Certificate create(Certificate target) throws
        Exception

    {

        this.targetCert = (java.security.cert.X509Certificate) target;

        this.setIssuerDN();
        this.setSubjectDN();
        this.setPublicKey();

        this.cert.setSerialNumber(this.targetCert.getSerialNumber());

        this.cert.setValidNotBefore( this.createNotBefore() );

        this.cert.setValidNotAfter( this.createNotAfter() );

        this.cert.setSignatureAlgorithm( this.createAlgID() );

        //Add extensions
        this.cert.addExtension(this.createEKU());

        //Very last thing to do is Sign.  Can't touch this after it's
        //signed otherwise the signature will not be valid

        this.cert.sign(this.createAlgID(), this.caKey);

        return this.cert;
    }

    private void setIssuerDN() throws Exception{
        sun.security.x509.X500Name  issuerDN =
            (sun.security.x509.X500Name) this.caCert.getIssuerDN();

        this.cert.setIssuerDN(new Name(issuerDN.getEncoded()));

    }

    private void setSubjectDN() throws Exception{
        sun.security.x509.X500Name  subjectDN =
            (sun.security.x509.X500Name) this.targetCert.getSubjectDN();

        this.cert.setSubjectDN(new Name(subjectDN.getEncoded()));

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

    private Principal createSubjectDN(){

        return this.targetCert.getSubjectX500Principal();
    }

    private V3Extension createEKU(){
        return new ExtendedKeyUsage(ExtendedKeyUsage.serverAuth);
    }

    private AlgorithmID createAlgID(){
        return new AlgorithmID(this.caCert.getSigAlgOID(),
                               this.caCert.getSigAlgName());
    }



}
