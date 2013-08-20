package mitm;

import java.security.KeyStore;
import iaik.x509.X509Certificate;
import java.security.KeyStoreException;

public interface CertGenerator {

    public X509Certificate create(String commonName, KeyStore ks)
        throws Exception;

}
