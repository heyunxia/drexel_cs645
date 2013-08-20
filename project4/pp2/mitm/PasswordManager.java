/**
 * PasswordManager.java
 */
package mitm;

import java.security.MessageDigest;
import java.security.Security;
import java.security.*;

public class PasswordManager
{

    private static final String SALT = "drexelcs645salt";

    public byte[] hashPassword(String password) throws NoSuchAlgorithmException
    {
        String passwordWithSalt = password + SALT;
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");    
        byte[] passwordBytes = passwordWithSalt.getBytes();
        byte[] passwordHash = sha256Digest.digest(passwordBytes);
        return passwordHash;
    }

}
