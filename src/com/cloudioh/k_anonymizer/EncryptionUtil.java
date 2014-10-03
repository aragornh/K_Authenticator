package com.cloudioh.k_anonymizer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class EncryptionUtil {

	private static final String TOKEN_HEADER = "K-Anonymizer:";
	
	/**
	 * String to hold name of the encryption algorithm.
	 */
	public static final String ALGORITHM = "RSA";

	/**
	 * String to hold name of the public key file.
	 */
	public static final String PUBLIC_KEY_FILE = "/public.key";
	
	
	/**
	 * Encrypt the plain text using public key.
	 * 
	 * @param text
	 *            : original plain text
	 * @param key
	 *            :The public key
	 * @return Encrypted text
	 * @throws java.lang.Exception
	 */
	public static byte[] encrypt(String text, Key key) throws Exception {
		byte[] cipherText = null;
		// get an RSA cipher object and print the provider
		final Cipher cipher = Cipher.getInstance(ALGORITHM);
		// encrypt the plain text using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text.getBytes());

		return cipherText;
	}

	/**
	 * Decrypt text using private key.
	 * 
	 * @param text
	 *            :encrypted text
	 * @param key
	 *            :The private key
	 * @return plain text
	 * @throws java.lang.Exception
	 */
	public static String decrypt(byte[] text, Key key) throws Exception {
		byte[] dectyptedText = null;
		final Cipher cipher = Cipher.getInstance(ALGORITHM);

		// decrypt the text using the private key
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedText = cipher.doFinal(text);

		return new String(dectyptedText);
	}

	static private PublicKey publicKey = null;

	public static boolean verifyCert(byte[] cert){
		String token;
		try {
			token = decrypt(cert, publicKey);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
		return token.startsWith(TOKEN_HEADER);
	}
	

	public static void init() throws FileNotFoundException, IOException,
			ClassNotFoundException {
		
		// Encrypt the string using the public key
		ObjectInputStream publicKeyIn = new ObjectInputStream(
				EncryptionUtil.class.getResourceAsStream(PUBLIC_KEY_FILE));
		publicKey = (PublicKey) publicKeyIn.readObject();
		publicKeyIn.close();
	}

	/**
	 * Test the EncryptionUtil
	 */
	public static void main(String[] args) {

		try {
			init();
			
			String certStr = "RTOQqR2+XSepF+pj2L24/ilAUOsmHHyq4dMUox9cMmBhC8UizPOeaGQCP1PwMxMWemT27sOCxFYxFgO7SbxOdVOaXDUrCGTNZ2/m6VgKXbMqeaRfRW5PJQ2mKMVLLtOQhacw+RUVR401xvqBgsOtERmExQWlhpRCWEmDFFqpAsafl9WK/dgaQbglyRgnqFIPK820/qv6hAWGyAc/0CLN3BO9SwBZJye8x6WtWgUHbUgP0aBRTg0KSK2gAToHBuhDij4+6WWMkuMPrh6Rl0O2ro1y8+SyINVJcN1anbYUx0bHLemgBi74K6gGrcoYuazFXpUPdT+71oi2XCXZtAqP1w==";
			byte[] cert = Base64Coder.decode(certStr);
			boolean ret = EncryptionUtil.verifyCert(cert);
			System.out.println("verification result:" + ret);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
