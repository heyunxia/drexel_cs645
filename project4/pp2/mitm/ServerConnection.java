package mitm;

import java.net.MalformedURLException;
import java.net.URL;

import java.io.*;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.Certificate;
import javax.security.auth.x500.X500Principal;
import javax.net.ssl.SSLSocket;
import java.math.BigInteger;
import javax.net.ssl.SSLSession;

import mitm.*;


public class ServerConnection {

    private HttpsURLConnection con;
    private String commonName;
    private BigInteger serialNo;

    public ServerConnection(URL url) throws MalformedURLException, IOException {
        this.con = (HttpsURLConnection) url.openConnection();

        this.con.connect();
    }

    public ServerConnection(SSLSocket socket) throws SSLPeerUnverifiedException{
        X509Certificate cert = (X509Certificate)
            socket.getSession().getPeerCertificates()[0];

        this.commonName = cert.getSubjectX500Principal().getName();
        this.serialNo = cert.getSerialNumber();

    }

    public String getCommonName(){
        return this.commonName;
    }

    public BigInteger getSerialNumber(){
        return this.serialNo;
    }

    public Certificate getServerCert() throws SSLPeerUnverifiedException{

        Certificate[] certs = con.getServerCertificates();

        //the peer cert is first
        return certs[0];

    }

    public HttpsURLConnection getConnection(){
        return this.con;
    }
}
