import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import static java.lang.System.out;
import static java.nio.file.Files.readAllBytes;
import static java.nio.file.Paths.get;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.File;
import java.io.FileWriter;

public class AES {
  static String IV = "AAAAAAAAAAAAAAAA";
  public static void main(String [] args) {
    try {

      String plaintext = new String(readAllBytes(get("plaintext.txt")));
      String encryptionKey = new String(readAllBytes(get("key.txt")));
	  System.out.println("==========AES==========");
      System.out.println("plain:   " + plaintext);

      byte[] cipher = encrypt(plaintext, encryptionKey);
	  File file = new File("cipher.txt");
	  FileWriter fileWriter = new FileWriter(file);
      System.out.print("cipher:  ");
      for (int i=0; i<cipher.length; i++)
	  {

		fileWriter.write(new Integer(cipher[i]));  
        System.out.print(new Integer(cipher[i])+" ");
	  }
	  fileWriter.flush();
	  fileWriter.close();
        System.out.println("");

      String decrypted = decrypt(cipher, encryptionKey);
      Files.write(Paths.get("textout.txt"), decrypted.getBytes()); 
      System.out.println("decrypt: " + decrypted);
	  
	  
    } catch (Exception e) {
      e.printStackTrace();
    } 
  }
//////////////encrypt//////////////////////////////////////////////////////////////////////
  public static byte[] encrypt(String plainText, String encryptionKey) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return cipher.doFinal(plainText.getBytes("UTF-8"));
  }

/////////////decrypt//////////////////////////////////////////////////////////////////////
  public static String decrypt(byte[] cipherText, String encryptionKey) throws Exception{
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
    cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return new String(cipher.doFinal(cipherText),"UTF-8");
  }
}