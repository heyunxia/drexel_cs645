/**
 * PasswordManager.java
 */
package mitm;

import java.security.MessageDigest;
import java.security.Security;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

public class EncryptedFileBasedPasswordManager implements IPasswordManager
{

    private static final String SALT = "drexelcs645salt";
    private static final String PASS_FILE_NAME = "passwords.txt";
    private static int HASH_LEN_IN_BYTES = 32;
    private static String CRYPTO_ALGORITHM = "DESede";
    private static String CRYPTO_TRANSFORM = "DESede/CBC/PKCS5Padding";
    private static byte[] KEY = "This is a test DESede key".getBytes(); // {'1','2','3','4','5','6','7','8','9','0','1','2','3','4','5','6'};
    private static Cipher _cipher;
    private static SecretKey _secretKey;
    private static IvParameterSpec _IVParameterSpec;
    private static int MAX_FILE_LEN = 8192;
    private static String PASSWORD_FILE_NAME = "adminUsers.dat";

    public EncryptedFileBasedPasswordManager()
    {
	try {
	    _secretKey = getDesEdeKey();
	    _cipher = Cipher.getInstance(CRYPTO_TRANSFORM);
	    byte[] ivSpecBytes = new byte[_cipher.getBlockSize()];
	    new SecureRandom().nextBytes(ivSpecBytes);
	    _IVParameterSpec = new IvParameterSpec(ivSpecBytes);
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println("NoSuchAlgorithmException: "+e);
	}
	catch (NoSuchPaddingException e) {
	    System.out.println("NoSuchPaddingException: "+e);
	}
    }


    private SecretKey getDesEdeKey() {
	SecretKey secretKey = null;
	try {
	    DESedeKeySpec keySpec = new DESedeKeySpec(KEY);
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
    public byte[] hashPassword(String password) throws NoSuchAlgorithmException
    {
        String passwordWithSalt = password + SALT;
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");    
        byte[] passwordBytes = passwordWithSalt.getBytes();
        byte[] passwordHash = sha256Digest.digest(passwordBytes);
        return passwordHash;
    }

    public void addUser(String userName, String password) throws FileNotFoundException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException
    {

	ByteArrayOutputStream byteStream = new ByteArrayOutputStream();	
	DataOutputStream out = new DataOutputStream(byteStream);
	out.writeUTF(userName);
	byte[] hashedPassword = hashPassword(password);
	out.write(hashedPassword,0,hashedPassword.length);
	
	byte[] writeBytes = byteStream.toByteArray();

	_cipher.init(Cipher.ENCRYPT_MODE,_secretKey,_IVParameterSpec);
	byte[] encrypted = _cipher.doFinal(writeBytes);
	FileOutputStream fileOut = new FileOutputStream(PASSWORD_FILE_NAME);
	fileOut.write(encrypted);
	fileOut.close();
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

    public void encryptFile() throws FileNotFoundException, InvalidKeyException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, InvalidAlgorithmParameterException
    {
	_cipher.init(Cipher.ENCRYPT_MODE, _secretKey, _IVParameterSpec);
	byte[] fileContents = getFileBytes();
	byte[] fileContentsPadded = Arrays.copyOf(fileContents,160);
	System.out.println("Padded print size is: "+fileContentsPadded.length);
	byte[] encryptedBytes = _cipher.doFinal(fileContentsPadded);
	FileOutputStream out = new FileOutputStream(PASS_FILE_NAME);
	out.write(encryptedBytes);
    }

    public boolean authenticate(String userName, String password) throws IOException, NoSuchAlgorithmException, FileNotFoundException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException
    {
	byte[] fileContents = getFileBytes();
	System.out.println("Length is: "+fileContents.length);
	System.out.println("BlockSize: "+_cipher.getBlockSize());

	// Decrypt the file
	_cipher.init(Cipher.DECRYPT_MODE, _secretKey, _IVParameterSpec);
	byte[] decryptedBytes = _cipher.doFinal(fileContents);

	 DataInputStream in = new DataInputStream(new ByteArrayInputStream(decryptedBytes));
	
	// Read the stored data
	String readUserName = in.readUTF();
	System.out.println("Read from file name: "+readUserName);
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
