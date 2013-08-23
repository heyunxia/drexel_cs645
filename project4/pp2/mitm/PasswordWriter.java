package mitm;

public class PasswordWriter
{

    public static void main(String[] args) throws Exception
    {

	String userName = "Eve";
	String goodPassword = "EveHacker1Password6785";
	String badPassword = "BadPassword";

        IPasswordManager manager = new EncryptedFileBasedPasswordManager();
//        manager.addUser(userName,goodPassword);

	// Check if the password words
	System.out.println("Good password authenticates: "+manager.authenticate(userName,goodPassword));

	// Check that bad password doesn't work
	System.out.println("Authenticate with bad password returns: "+manager.authenticate(userName,badPassword));

    }

}
