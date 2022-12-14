package etf.openpgp.tl180410dra180333d.messages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import etf.openpgp.tl180410dra180333d.keys.KeyUtils;

/**
 * Klasa koja obezbedjuje operacije prilikom slanja i prijema poruke koristeci
 * PGP protokol
 */
public class MessagePgpOperations {

	/**
	 * Operacija koja potpicuje poruku(niz bajtova)
	 * 
	 * @param dataToBeSigned - poruka za potpisivanje
	 * @param signKey - privatni kljuc koji se koristi za potpisivanje
	 * @param passphrase   - lozinka za zastitu privatnog kljuca koji se koristi za
	 *                     potpisivanje
	 * @return potpisana poruka(niz bajtova)
	 * @throws PGPException
	 * @throws IOException
	 */
	public static byte[] sign(byte[] dataToBeSigned, PGPSecretKey signKey, String passphrase)
			throws PGPException, IOException {

		PGPPrivateKey signPrivateKey = signKey.extractPrivateKey(
				new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));

		int signAlgorithm = signKey.getPublicKey().getAlgorithm();
		int signKeySize = signKey.getPublicKey().getBitStrength();

		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		BCPGOutputStream bcpgOutputStream = new BCPGOutputStream(byteOutputStream);

		PGPSignatureGenerator pgpSignatureGenerator = new PGPSignatureGenerator(
				new JcaPGPContentSignerBuilder(signAlgorithm, KeyUtils.getHashAlgorithmTag(signAlgorithm, signKeySize))
						.setProvider("BC"));

		pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signPrivateKey);
		pgpSignatureGenerator.generateOnePassVersion(false).encode(bcpgOutputStream);

		PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
		OutputStream outputStream = pgpLiteralDataGenerator.open(bcpgOutputStream, PGPLiteralData.BINARY, "_CONSOLE",
				dataToBeSigned.length, new Date());

		for (byte dataByte : dataToBeSigned) {
			outputStream.write(dataByte);
			pgpSignatureGenerator.update(dataByte);
		}

		pgpLiteralDataGenerator.close();
		pgpSignatureGenerator.generate().encode(bcpgOutputStream);
		byteOutputStream.close();
		bcpgOutputStream.close();
		outputStream.close();

		return byteOutputStream.toByteArray();
	}

	/**
	 * Operacija za sifrovanje poruke( niza bajtova)
	 * 
	 * @param bytesToBeEncrypted - poruka za sifrovanje
	 * @param encryptionKey - javni kljuc koji se koristi za sifrovanje
	 * @param symetricEncryptionAlgorithm - identifikator simetricnog algoritma koji se koristi pri sifrovanju
	 * @param bytesInPgpLiteralDataFormat - da li je poruka vec u PGP formatu
	 * @return sifrovana poruka( niz bajtova)
	 * @throws IOException
	 * @throws PGPException
	 */
	public static byte[] encrypt(byte[] bytesToBeEncrypted, PGPPublicKey encryptionKey, int symetricEncryptionAlgorithm, boolean bytesInPgpLiteralDataFormat)
			throws IOException, PGPException {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

		PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(symetricEncryptionAlgorithm).setWithIntegrityPacket(true)
						.setSecureRandom(new SecureRandom()).setProvider("BC"));

		pgpEncryptedDataGenerator
				.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BC"));

		OutputStream encryptedOutputStream = pgpEncryptedDataGenerator.open(byteOutputStream,
				new byte[1<<16]);
		
		if(bytesInPgpLiteralDataFormat) {
			encryptedOutputStream.write(bytesToBeEncrypted);
		}
		else {
	        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
	        
	        OutputStream pgpLiteralDataGeneratorOutputStream = pgpLiteralDataGenerator.open(
	        		encryptedOutputStream, PGPLiteralData.BINARY,
	                PGPLiteralData.CONSOLE, bytesToBeEncrypted.length, new Date());
	        
	        pgpLiteralDataGeneratorOutputStream.write(bytesToBeEncrypted);
	        
	        pgpLiteralDataGeneratorOutputStream.close();
		}
		
		

		encryptedOutputStream.close();
		byteOutputStream.close();

		return byteOutputStream.toByteArray();
	}

	/**
	 * Operacija za zipovanje poruke( niza bajtova)
	 * 
	 * @param bytesToBeZiped - niz bajtova za kompresiju(poruka pre
	 *               kompresije)
	 * @param bytesInPgpLiteralDataFormat - da li je poruka vec u PGP formatu
	 * @return kompresovana poruka( niz bajtova) u ZIP formatu
	 * @throws IOException
	 */
	public static byte[] zip(byte[] bytesToBeZiped, boolean bytesInPgpLiteralDataFormat) throws IOException {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

		PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(
				PGPCompressedDataGenerator.ZIP);

		OutputStream compressedOutputStream = pgpCompressedDataGenerator.open(byteOutputStream);
		
		if(bytesInPgpLiteralDataFormat) {
			compressedOutputStream.write(bytesToBeZiped);
		}
		else {
	        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
	        OutputStream pgpLiteralDataGeneratorOutputStream = pgpLiteralDataGenerator.open(
	        		compressedOutputStream, PGPLiteralData.BINARY,
	                PGPLiteralData.CONSOLE, bytesToBeZiped.length, new Date());
	        
	        pgpLiteralDataGeneratorOutputStream.write(bytesToBeZiped);
	        pgpLiteralDataGeneratorOutputStream.close();
		}

		compressedOutputStream.close();
		byteOutputStream.close();

		return byteOutputStream.toByteArray();
	}

	/**
	 * Operacija za konverziju poruke( niza bajtova) u radix64 format
	 * 
	 * @param bytesToBeConvertedIntoRadix64 - niz bajtova za
	 *               konverziju(poruka pre konverzije)
	 * @param bytesInPgpLiteralDataFormat - da li je poruka vec u PGP formatu
	 * @return konvertovana poruka( niz bajtova) u radix64 format
	 * @throws IOException
	 */
	public static byte[] convertToRadix64(byte[] bytesToBeConvertedIntoRadix64, boolean bytesInPgpLiteralDataFormat) throws IOException {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();

		ArmoredOutputStream radix64OutputStream = new ArmoredOutputStream(byteOutputStream);

		if(bytesInPgpLiteralDataFormat) {
			radix64OutputStream.write(bytesToBeConvertedIntoRadix64);
		}
		else {
	        PGPLiteralDataGenerator pgpLiteralDataGenerator = new PGPLiteralDataGenerator();
	        OutputStream pgpLiteralDataGeneratorOutputStream = pgpLiteralDataGenerator.open(
	        		radix64OutputStream, PGPLiteralData.BINARY,
	                PGPLiteralData.CONSOLE, bytesToBeConvertedIntoRadix64.length, new Date());
	        
	        pgpLiteralDataGeneratorOutputStream.write(bytesToBeConvertedIntoRadix64);
	        pgpLiteralDataGeneratorOutputStream.close();
		}

		radix64OutputStream.close();
		byteOutputStream.close();

		return byteOutputStream.toByteArray();
	}

	/**
	 * metoda koja vrsi dekompresiju poruke
	 * 
	 * @param bytesToBeUnzipped
	 * @return dekompresovana poruka
	 */
	public static byte[] unzip(byte[] bytesToBeUnzipped) {
		JcaPGPObjectFactory factory = new JcaPGPObjectFactory(bytesToBeUnzipped);
		try {
			Object object = factory.nextObject();
			if (object instanceof PGPCompressedData) {
				PGPCompressedData compressedData = (PGPCompressedData) object;
				return compressedData.getDataStream().readAllBytes();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
		}

		return bytesToBeUnzipped;
	}

	/**
	 * metoda koja konvertuje podatke iz radix64 formata u 8-bitni binarni tok
	 * 
	 * @param bytesToBeConvertedIntoRadix64
	 * @return konvertovani podaci
	 */
	public static byte[] convertFromRadix64ToByteStream(byte[] bytesToBeConvertedIntoRadix64) {
		InputStream inputData = new ByteArrayInputStream(bytesToBeConvertedIntoRadix64);
		byte[] returnBytes;
		try {
			returnBytes = PGPUtil.getDecoderStream(inputData).readAllBytes();
		} catch (IOException e) {
			return null;
		}
		return returnBytes;
	}

	/**
	 * metoda koja proverava da li je poruka enkriptovana
	 * 
	 * @param data - tok bajtova koji se ispituje
	 * @return true/false
	 */
	public static boolean isEncryptedMessage(byte[] data) {

		JcaPGPObjectFactory factory = new JcaPGPObjectFactory(data);
		try {
			if (factory.nextObject() instanceof PGPEncryptedDataList) {
				return true;
			}

		} catch (IOException e) {
		}

		return false;

	}

}
