/**
 * PasswordManager.java
 */
package mitm;

import java.security.MessageDigest;
import java.security.Security;
import java.security.*;
import java.io.*;
import java.util.Arrays;

public class PasswordManager
{

    private static final String SALT = "drexelcs645salt";
    private static final String PASS_FILE_NAME = "passwords.txt";
    private static int HASH_LEN_IN_BYTES = 32; 
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException
    {
        String passwordWithSalt = password + SALT;
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");    
        byte[] passwordBytes = passwordWithSalt.getBytes();
        byte[] passwordHash = sha256Digest.digest(passwordBytes);
        return passwordHash;
    }

    public void addUser(String userName, String password) throws FileNotFoundException, NoSuchAlgorithmException, IOException
    {
        DataOutputStream out = new DataOutputStream(new FileOutputStream(PASS_FILE_NAME,true));
        
        out.writeUTF(userName);
        byte[] hashedPassword = hashPassword(password);
        out.write(hashedPassword,0,hashedPassword.length);
        
        out.close();
    }

    public boolean authenticate(String userName, String password) throws IOException, NoSuchAlgorithmException
    {
	DataInputStream in = new DataInputStream(new FileInputStream(PASS_FILE_NAME));

	// Read the stored data
	String readUserName = in.readUTF();
	byte[] readPasswordHash = new byte[HASH_LEN_IN_BYTES]; // 256 bit = 32 bytes
	in.read(readPasswordHash,0,HASH_LEN_IN_BYTES);

	if(readUserName.equals(userName))
	{
	// Compare password hashes
	    if(Arrays.equals(readPasswordHash, hashPassword(password)))
	    {
		return true;
	    }
	}

	return false;

    }

}
