package mitm;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

public class HackerKeyManager implements X509KeyManager{


    private String alias;
    private KeyStore ks;
    private char[] password;

    public HackerKeyManager(String alias, KeyStore ks, char[] pass)
    {

        this.alias = alias;
        this.ks = ks;
        this.password = pass;

    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers,
            Socket socket)
    {
        return null;
    }


    public String chooseServerAlias(String keyType, Principal[] issuers,
            Socket socket)
    {
        System.out.println("Returning alias: " + this.alias);
        return this.alias;
    }

    public X509Certificate[] getCertificateChain(String alias)
    {
        try {
            X509Certificate[] certs = (X509Certificate[]) this.ks.getCertificateChain(alias);

            return certs;
        }
        catch (Exception e){
            System.out.println(e);

            return null;
        }
    }

    public String[] getClientAliases(String keyType, Principal[] issuers)
    {
        return null;
    }

    public PrivateKey getPrivateKey(String alias)
    {
        try {
            PrivateKey k = (PrivateKey) this.ks.getKey(alias, this.password);
            return k;
        }
        catch (Exception e){
            System.out.println(e);
            return null;
        }
    }

    public String[] getServerAliases(String keyType, Principal[] issuers)
    {
        String[] aliases = new String[1];
        aliases[0] = this.alias;
        return aliases;
    }

}
