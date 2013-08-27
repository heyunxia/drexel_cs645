package mitm;

import org.junit.*;
import static org.junit.Assert.*;
import java.security.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.math.BigInteger;

public class PasswordWriter
{

    private static IPasswordManager manager = new EncryptedFileBasedPasswordManager();
    private static Charset ENCODING_TYPE = StandardCharsets.US_ASCII;

    private static void printUsage()
    {
	System.err.println("1 parameter required, with -filePath paramer"); 
    }

    public static String getPublicSalt()
    {
	SecureRandom randomGenerator = new SecureRandom();
	String randomSalt = new String(new BigInteger(130, randomGenerator).toString(32));
	System.out.println("Random salt is: "+randomSalt);
	return randomSalt;
    }

    public static void main(String[] args) throws Exception
    {

	// Parse arguments

	String passwordFilePath = null; 
	for(int i = 0; i < args.length; i++)
	{
	    if(args[i].equals("-filePath"))
	    {
		passwordFilePath = args[++i];
	    }
	}

	if(args.length < 2 || passwordFilePath == null)
	{
	    printUsage();
	    System.exit(1);
	}

	// Read in the desired user names/passwords from the file

	BufferedReader br = null;
	String line = "";
	String fieldSeparator = ",";
	try
	{
	    br = new BufferedReader(new FileReader(passwordFilePath));
	    int lineNum = 0;
	    while(( line = br.readLine() ) != null)
	    {
		lineNum++;
		String[] parsedLine = line.split(fieldSeparator);
		if(parsedLine.length != 2) 
		{
		    throw new IllegalArgumentException("All input lines must be in the form userName,desiredPassword, error at line: "+lineNum);
		}
		String userName = parsedLine[0];
		String desiredPassword = parsedLine[1];
		String publicSalt = getPublicSalt();
		// Add the user

		manager.addUser(userName,publicSalt,desiredPassword);	

	    }
	}
	catch(FileNotFoundException e)
	{
	    e.printStackTrace();
	}
	catch(IOException e)
	{
	    e.printStackTrace();
	}
	finally
	{
	    if (br != null)
	    {
		try
		{
		    br.close();
		}
		catch(IOException e)
		{
		    e.printStackTrace();
		}
	    }
	}
    }

}
