import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
1. KeyPair generation

keytool -genkeypair -rfc -keyalg rsa -keysize [keysize] -keystore [keystore file name]
        -storetype pkcs12 -storepass [keystore password] -validity 365 -alias [alias]
        -dname CN=alice
ex) keytool -genkeypair -rfc -keyalg rsa -keysize 2048 -keystore aliceKeystore.p12 -storetype pkcs12 -storepass storepass -validity 365 -alias alice -dname CN=alice

2. Extract public key as X.509 certificate as base64 encoding

keytool -exportcert -rfc -keystore [keystore file name] -storetype pkcs12
        -storepass [keystore password] -alias [alice] -file [x.509 certificate file name]
ex) keytool -exportcert -rfc -keystore aliceKeystore.p12 -storetype pkcs12 -storepass storepass
        -alias alice -file alice.crt

*/
public class RsaEncDec {

	static File mKeyFile = null;
	static File mTargetFile = null;

	public static void main(String[] args) {
		if (args.length < 3) {
			System.out.println("Invalid arguments.");
			printHowToUseAndExit();
		}

		if (!("enc".equals(args[0]) || "dec".equals(args[0]))) {
			System.out.println("Invalid first argument. It should be [enc|dec]");
			printHowToUseAndExit();
		}

		mKeyFile = new File(args[1]);
		if (!mKeyFile.exists()) {
			System.out.println(args[1] + " does not exist.");
			printHowToUseAndExit();
		}

		mTargetFile = new File(args[2]);
		if (!mTargetFile.exists()) {
			System.out.println(args[2] + " does not exist.");
			printHowToUseAndExit();
		}

		try {
			if ("enc".equals(args[0])) {
				if (!encryptRsa()) {
					printHowToUseAndExit();
				}
			}

			if ("dec".equals(args[0])) {
				if (args.length != 4) {
					System.out.println("Store pass is required for decryption");
					printHowToUseAndExit();
				}
				if (!decryptRsa(args[3])) {
					printHowToUseAndExit();
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			printHowToUseAndExit();
		}
		System.out.println("Done.");
	}

	private static void printHowToUseAndExit() {
		System.out.println("How to Use: \njava RsaEncDec [enc|dec] [pkcs12|cert] " +
				"[plaintext|ciphertext] {storepass}");
		System.exit(0);
	}

	private static boolean decryptRsa(String storePass) throws IOException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException {

		byte[] cipherBytes = Files.readAllBytes(mTargetFile.toPath());
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		FileInputStream fis = new FileInputStream(mKeyFile);
		keystore.load(fis, storePass.toCharArray());
		PrivateKey privKey = (PrivateKey) keystore.getKey("alice", "storepass".toCharArray());

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decryptedBytes = cipher.doFinal(cipherBytes);

		return writeFile(decryptedBytes, "rsaDecryptedOutput");
	}

	private static boolean writeFile(byte[] data, String fileName) throws IOException {
		File output = new File(fileName);
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(data);
		fos.close();
		return true;
	}

	private static boolean encryptRsa() throws CertificateException, IOException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		FileInputStream fis = new FileInputStream(mKeyFile);
		X509Certificate cert = (X509Certificate)certFactory.generateCertificate(fis);
		PublicKey pubKey = cert.getPublicKey();
		byte[] plainBytes = Files.readAllBytes(mTargetFile.toPath());

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] cipherBytes = cipher.doFinal(plainBytes);

		return writeFile(cipherBytes, "rsaEncryptedOutput");
	}
}
