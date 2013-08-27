package mitm;

import org.junit.*;
import static org.junit.Assert.*;
import java.security.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.math.BigInteger;

/* Note: this test assumes the presence of a userNames.dat file containing Joe and 23456 */
public class PasswordWriterTest
{

    private static IPasswordManager manager = new EncryptedFileBasedPasswordManager();
    private static String userName = "Joe";
    private static String goodPassword = "23456";
    private static String badPassword = "BadPassword";
    private static Charset ENCODING_TYPE = StandardCharsets.US_ASCII;

    public static void main(String[] args) throws Exception
    {

	// Check if the password words
	System.out.println("Good password authenticates: "+manager.authenticate(userName, goodPassword));

	// Check that bad password doesn't work
	System.out.println("Authenticate with bad password returns: "+manager.authenticate(userName, badPassword));

    }

}
