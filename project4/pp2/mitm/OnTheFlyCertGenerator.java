/**
 * OnTheFlyCertGenerator.java
 */
package mitm;

import iaik.asn1.structures.AlgorithmID;
import iaik.x509.*;
import iaik.x509.extensions.*;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.security.auth.x500.X500Principal;


public class OnTheFlyCertGenerator implements CertGenerator
{

    private KeyStore keyStore;
    private String commonName = "";
    private X509Certificate cert;
    private X509Certificate caCert;
    private PrivateKey caKey;

    private DateFormat formatter = new SimpleDateFormat("d-MMM-yyyy,HH:mm:ss aaa");

    private static final String CA_ALIAS = "selfsigned";
    private static final String KEY_STORE_PASS = "password";


    private void init(String cn, KeyStore ks) throws KeyStoreException,
                                                     NoSuchAlgorithmException,
                                                     UnrecoverableKeyException
    {

        this.keyStore = ks;
        this.commonName = cn;

        this.cert = new X509Certificate();
        this.caCert = (X509Certificate) ks.getCertificate(CA_ALIAS);

        this.caKey = (PrivateKey) ks.getKey(CA_ALIAS,
                                            KEY_STORE_PASS.toCharArray());


    }
    public X509Certificate create(String cn, KeyStore ks) throws
        KeyStoreException, ParseException, X509ExtensionException,
        NoSuchAlgorithmException, UnrecoverableKeyException,
        InvalidKeyException, CertificateException
    {

        this.init(cn,ks);


        this.cert.setIssuerDN(this.caCert.getIssuerDN());
        //TODO set the public key.  Either create one or cheat and
        //re-use the CA's
        //this.cert.setPublicKey()

        // Serial number can be the same since the tuple is (issuer,
        // serial) and this is a different issuer
        this.cert.setSerialNumber(this.caCert.getSerialNumber());

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

    private Date createNotBefore() throws ParseException{
        String notBefore = "13-Mar-1980,03:00:00 AM";

        return this.formatter.parse(notBefore);
    }

    private Date createNotAfter() throws ParseException{
        String notBefore = "13-Mar-2030,03:00:00 AM";

        return this.formatter.parse(notBefore);
    }

    private Principal createSubjectDN(){

        return new X500Principal("CNN=" + this.commonName);
    }

    private V3Extension createEKU(){
        return new ExtendedKeyUsage(ExtendedKeyUsage.serverAuth);
    }

    private AlgorithmID createAlgID(){
        return new AlgorithmID(this.caCert.getSigAlgOID(),
                               this.caCert.getSigAlgName());
    }

}
