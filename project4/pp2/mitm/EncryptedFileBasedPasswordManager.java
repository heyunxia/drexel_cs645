/**
 * PasswordManager.java
 */
package mitm;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;
import iaik.security.mac.*;


public class EncryptedFileBasedPasswordManager implements IPasswordManager
{

    private static final String[] PEPPERS = { "a87dnhf37tld","*&GgBsQ@1%^1","98dj&76dGtvl","akcHbtVt3980","2kd&5Ht']+=1"} ;
    private static String CRYPTO_ALGORITHM = "DESede";
    private static String CRYPTO_TRANSFORM = "DESede/CBC/PKCS5Padding";
    private static int MAX_FILE_LEN = 40960;
    private static String PASSWORD_FILE_NAME = "adminUsers.dat";
    private static int HASH_LEN_IN_BYTES = 32;
    private static String ENCODING = "UTF8";
    private static String HMAC_TYPE = "HMACSHA256";
    private static int HMAC_LEN_IN_BYTES = 32;

    private static String _keyString = "drexelcs645secretEncryptionKey332#(!)*@(@#@)(*@#";
    private static byte[] _keyBytes;
    private static byte[] IVBYTES = {55,23,11,67,19,12,66,46};
    private static Cipher _cipher;
    private static SecretKey _secretKey;
    private static IvParameterSpec _IVParameterSpec;

    public EncryptedFileBasedPasswordManager()
    {
	try {
	    _keyBytes = _keyString.getBytes(ENCODING);
	    _secretKey = getDesEdeKey();
	    _cipher = Cipher.getInstance(CRYPTO_TRANSFORM);
	    _IVParameterSpec = new IvParameterSpec(IVBYTES);

	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println("NoSuchAlgorithmException: "+e);
	}
	catch (NoSuchPaddingException e) {
	    System.out.println("NoSuchPaddingException: "+e);
	}
	catch (UnsupportedEncodingException e) {
	    System.out.println("UnsupportedEncodingException: "+e);
	}
    }


    private SecretKey getDesEdeKey() {
	SecretKey secretKey = null;
	try {
	    DESedeKeySpec keySpec = new DESedeKeySpec(_keyBytes);
	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CRYPTO_ALGORITHM);
	    secretKey = keyFactory.generateSecret(keySpec);
	}
	catch(NoSuchAlgorithmException e) {
	    System.out.println("NoSuchAlgorithmException: "+e);
	}
	catch(InvalidKeySpecException e) {
	    System.out.println("InvalidKeySpecException: "+e);
	}
	catch(InvalidKeyException e) {
	    System.out.println("InvalidKeyException: "+e);
	}
	return secretKey;
    }
    public byte[] hashPassword(String password, String publicSalt, String pepper)
    {
        byte[] passwordHash = null;
        try {
            String passwordWithSalts = password + publicSalt + pepper;
            MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
            byte[] passwordBytes = passwordWithSalts.getBytes();
            passwordHash = sha256Digest.digest(passwordBytes);

        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return passwordHash;
    }

    public String getPepper()
    {
        SecureRandom random = new SecureRandom();
        int pepperIdx = Math.abs(random.nextInt()) % PEPPERS.length;
        String pepper = PEPPERS[pepperIdx];
        return pepper;
    }

    public void addUser(String userName, String publicSalt, String password, DataOutputStream out)
    {
        try
        {
            // Write user name, salt, and password hash. Don't write out the secret salt (pepper), but use it to compute the hash
            out.writeUTF(userName);
            out.writeUTF(publicSalt);
            String pepper = getPepper();
            byte[] hashedPassword = hashPassword(password,publicSalt, pepper);
            out.write(hashedPassword,0,hashedPassword.length);
        }
        catch(IOException e)
        {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private byte[] getHmacBytes(byte[] encryptedBytes) throws NoSuchAlgorithmException, InvalidKeyException {
            Mac hmac = Mac.getInstance(HMAC_TYPE);
            hmac.init(_secretKey);
            byte[] mac_bytes = hmac.doFinal(encryptedBytes);
            return mac_bytes;
    }

    public void generateEncryptedFile(ByteArrayOutputStream byteStream)
    {
        try {
            byte[] writeBytes = byteStream.toByteArray();

            // Encrypt the password file
            _cipher.init(Cipher.ENCRYPT_MODE,_secretKey,_IVParameterSpec);
            byte[] encrypted = _cipher.doFinal(writeBytes);
            System.out.println("Encrypted length is: "+encrypted.length);

            // Prepend an HMAC
            byte[] mac_bytes = getHmacBytes(encrypted);
            System.out.println("Mac length is: "+mac_bytes.length);

            byte[] combinedBytes = Arrays.copyOf(mac_bytes,encrypted.length+mac_bytes.length);
            System.arraycopy(encrypted,0,combinedBytes,mac_bytes.length,encrypted.length);
            System.out.println("Combined length is: "+combinedBytes.length);

            FileOutputStream fileOut = new FileOutputStream(PASSWORD_FILE_NAME);
            fileOut.write(combinedBytes);
            fileOut.close();
        }
        catch(IOException|InvalidKeyException|IllegalBlockSizeException|BadPaddingException|InvalidAlgorithmParameterException|NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public byte[] getFileBytes() throws FileNotFoundException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException
    {
	File encryptedFile = new File(PASSWORD_FILE_NAME);
	byte[] fileContents = new byte[(int) encryptedFile.length()];
	FileInputStream fileIn = new FileInputStream(encryptedFile);
	fileIn.read(fileContents);
	fileIn.close();
	return fileContents;
    }

    public boolean authenticate(String userName, String password) throws IOException, NoSuchAlgorithmException, FileNotFoundException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException
    {
	byte[] fileContents = getFileBytes();
	System.out.println("Length is: "+fileContents.length);
	System.out.println("BlockSize: "+_cipher.getBlockSize());

    // Strip off the HMAC bytes. Validate that they equal a newly-calculated HMAC, indicating
    // the file has not been altered
    byte[] hmacBytes = Arrays.copyOfRange(fileContents,0,HMAC_LEN_IN_BYTES);
    System.out.println("Read hmac length is: "+hmacBytes.length);
    byte[] encryptedContents = Arrays.copyOfRange(fileContents,HMAC_LEN_IN_BYTES,fileContents.length);
    System.out.println("Read encrypted length is: "+encryptedContents.length);
    byte[] calculatedHmacBytes = getHmacBytes(encryptedContents);

    if(!Arrays.equals(hmacBytes,calculatedHmacBytes)) {
        System.err.println("Prepended HMAC has incorrect value, aborting");
        System.exit(1);
    }

	// Decrypt the file
	_cipher.init(Cipher.DECRYPT_MODE, _secretKey, _IVParameterSpec);
	byte[] decryptedBytes = _cipher.doFinal(encryptedContents);

	 DataInputStream in = new DataInputStream(new ByteArrayInputStream(decryptedBytes));

	// Read the stored data (in the order userName, publicSalt, passwordHash)
	String readUserName = in.readUTF();
	String readPublicSalt = in.readUTF();
	System.out.println("Read from file name: "+readUserName);
	byte[] readPasswordHash = new byte[HASH_LEN_IN_BYTES]; // 256 bit = 32 bytes

	in.read(readPasswordHash,0,HASH_LEN_IN_BYTES);

	if(readUserName.equals(userName))
	{

	    for(String pepper : PEPPERS) {
	// Compare password hashes
		if(Arrays.equals(readPasswordHash, hashPassword(password, readPublicSalt, pepper)))
		{
		    return true;
		}
	    }
	}

	return false;

    }

}
