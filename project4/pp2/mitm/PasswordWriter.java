package mitm;

import org.junit.*;
import static org.junit.Assert.*;

public class PasswordWriter
{

    private static IPasswordManager manager = new EncryptedFileBasedPasswordManager();
    private static String userName = "Eve";
    private static String goodPassword = "EveHacker1Password6785";
    private static String badPassword = "BadPassword";
    
    @Before
    public void AddUser_NoError() throws Exception
    {
        manager.addUser(userName,goodPassword);
    }
 
    @Test
    public void TestCorrectPasswordWorks() throws Exception
    {
	Assert.assertEquals(manager.authenticate(userName,goodPassword),true);
    }

    @Test
    public void TestIncorrectPasswordReturnsFalseAuthentication() throws Exception
    {
	Assert.assertEquals(manager.authenticate(userName,badPassword),false);
    }
    

    public static void main(String[] args) throws Exception
    {

	// Check if the password words
	System.out.println("Good password authenticates: "+manager.authenticate(userName,goodPassword));

	// Check that bad password doesn't work
	System.out.println("Authenticate with bad password returns: "+manager.authenticate(userName,badPassword));

    }

}
