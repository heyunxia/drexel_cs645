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
    
    private static final String SALT = "drexelcs645saltas213)(*)@(#&@(*HDWDJ";
    private static String CRYPTO_ALGORITHM = "DESede";
    private static String CRYPTO_TRANSFORM = "DESede/CBC/PKCS5Padding";
    private static int MAX_FILE_LEN = 40960;
    private static String PASSWORD_FILE_NAME = "adminUsers.dat";
    private static int HASH_LEN_IN_BYTES = 32;
    private static String ENCODING = "UTF8";
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
    public byte[] hashPassword(String password, String publicSalt) throws NoSuchAlgorithmException
    {
        String passwordWithSalts = password + publicSalt + SALT;
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");    
        byte[] passwordBytes = passwordWithSalts.getBytes();
        byte[] passwordHash = sha256Digest.digest(passwordBytes);
        return passwordHash;
    }

    public void addUser(String userName, String publicSalt, String password) throws FileNotFoundException, NoSuchAlgorithmException, IOException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException
    {

	ByteArrayOutputStream byteStream = new ByteArrayOutputStream();	
	DataOutputStream out = new DataOutputStream(byteStream);

	// Write user name, salt, and password hash
	out.writeUTF(userName);
	out.writeUTF(publicSalt);

	byte[] hashedPassword = hashPassword(password,publicSalt);
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
	FileOutputStream out = new FileOutputStream(PASSWORD_FILE_NAME);
	out.write(encryptedBytes);
    }

    public boolean authenticate(String userName, String publicSalt, String password) throws IOException, NoSuchAlgorithmException, FileNotFoundException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException
    {
	byte[] fileContents = getFileBytes();
	System.out.println("Length is: "+fileContents.length);
	System.out.println("BlockSize: "+_cipher.getBlockSize());

	// Decrypt the file
	_cipher.init(Cipher.DECRYPT_MODE, _secretKey, _IVParameterSpec);
	byte[] decryptedBytes = _cipher.doFinal(fileContents);

	 DataInputStream in = new DataInputStream(new ByteArrayInputStream(decryptedBytes));
	
	// Read the stored data (in the order userName, publicSalt, passwordHash)
	String readUserName = in.readUTF();
	String readPublicSalt = in.readUTF();
	System.out.println("Read from file name: "+readUserName);
	byte[] readPasswordHash = new byte[HASH_LEN_IN_BYTES]; // 256 bit = 32 bytes
	
	in.read(readPasswordHash,0,HASH_LEN_IN_BYTES);

	if(readUserName.equals(userName))
	{
	// Compare password hashes
	    if(Arrays.equals(readPasswordHash, hashPassword(password, readPublicSalt)))
	    {
		return true;
	    }
	}

	return false;

    }

}
