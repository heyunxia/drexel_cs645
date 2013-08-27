package mitm;

import org.junit.*;
import static org.junit.Assert.*;
import java.security.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.math.BigInteger;

public class PasswordWriterTest
{

    private static IPasswordManager manager = new EncryptedFileBasedPasswordManager();
    private static String userName = "Eve";
    private static String goodPassword = "EveHacker1Password6785";
    private static String badPassword = "BadPassword";
    private static Charset ENCODING_TYPE = StandardCharsets.US_ASCII;

    public static void main(String[] args) throws Exception
    {

	String publicSalt = PasswordWriter.getPublicSalt();
	manager.addUser(userName,publicSalt,goodPassword);
	// Check if the password words
	System.out.println("Good password authenticates: "+manager.authenticate(userName,publicSalt, goodPassword));

	// Check that bad password doesn't work
	System.out.println("Authenticate with bad password returns: "+manager.authenticate(userName,publicSalt, badPassword));

    }

}
