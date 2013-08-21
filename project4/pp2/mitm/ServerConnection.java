package mitm;

import java.net.MalformedURLException;
import java.net.URL;

import java.io.*;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.security.cert.Certificate;
import javax.security.auth.x500.X500Principal;


public class ServerConnection {

    private HttpsURLConnection con;

    public ServerConnection(URL url) throws MalformedURLException, IOException {
        this.con = (HttpsURLConnection) url.openConnection();

        this.con.connect();
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
