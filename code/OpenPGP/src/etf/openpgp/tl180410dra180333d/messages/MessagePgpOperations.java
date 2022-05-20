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
 * Klasa koja obezbedjuje operacije prilikom slanja i prijema poruke koristeci PGP protokol
 */
public class MessagePgpOperations {

	/**
	 * Operacija koja potpicuje poruku(niz bajtova)
	 * @param byte[] dataToBeSigned - poruka za potpisivanje
	 * @param PGPSecretKey signKey - privatni kljuc koji se koristi za potpisivanje
	 * @param passphrase - lozinka za zastitu privatnog kljuca koji se koristi za potpisivanje
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
	 * @param byte[] bytesToBeEncrypted - poruka za sifrovanje
	 * @param PGPPublicKey encryptionKey - javni kljuc koji se koristi za sifrovanje
	 * @param int symetricEncryptionAlgorithm - identifikator simetricnog algoritma koji se koristi pri sifrovanju
	 * @return sifrovana poruka( niz bajtova)
	 * @throws IOException
	 * @throws PGPException
	 */
	public static byte[] encrypt(byte[] bytesToBeEncrypted, PGPPublicKey encryptionKey, int symetricEncryptionAlgorithm) throws IOException, PGPException {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		
		PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(symetricEncryptionAlgorithm).setWithIntegrityPacket(true)
				.setSecureRandom(new SecureRandom()).setProvider("BC"));
		
		pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey)
    			.setProvider("BC"));
		
        OutputStream encryptedOutputStream = pgpEncryptedDataGenerator.open(byteOutputStream, bytesToBeEncrypted.length);
        encryptedOutputStream.write(bytesToBeEncrypted);
        
        encryptedOutputStream.close();
        byteOutputStream.close();
        
        return byteOutputStream.toByteArray();
	}

	/**
	 * Operacija za zipovanje poruke( niza bajtova)
	 * @param byte[] bytesToBeZiped - niz bajtova za kompresiju(poruka pre kompresije)
	 * @return kompresovana poruka( niz bajtova) u ZIP formatu
	 * @throws IOException
	 */
	public static byte[] zip(byte[] bytesToBeZiped) throws IOException {
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		
		PGPCompressedDataGenerator pgpCompressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
		
		OutputStream compressedOutputStream = pgpCompressedDataGenerator.open(byteOutputStream);
		compressedOutputStream.write(bytesToBeZiped);
		
		compressedOutputStream.close();
		byteOutputStream.close();
		
		return byteOutputStream.toByteArray();
	}
	
	/**
	 * Operacija za konverziju poruke( niza bajtova) u radix64 format
	 * @param byte[] bytesToBeConvertedIntoRadix64 - niz bajtova za konverziju(poruka pre konverzije)
	 * @return kkonvertovana poruka( niz bajtova) u radix64 format
	 * @throws IOException
	 */
	public static byte[] convertToRadix64(byte[] bytesToBeConvertedIntoRadix64) throws IOException{
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        
        ArmoredOutputStream radix64OutputStream = new ArmoredOutputStream(byteOutputStream);
        
        radix64OutputStream.write(bytesToBeConvertedIntoRadix64);
        
        radix64OutputStream.close();
        byteOutputStream.close();
        
        return byteOutputStream.toByteArray();
	}

	public static byte[] verifySign(byte[] dateToBeVerified) {
		return dateToBeVerified;	
	}
	public static byte[] unzip(byte [] bytesToBeUnzipped) {
		JcaPGPObjectFactory factory = new JcaPGPObjectFactory(bytesToBeUnzipped);
		try {
			Object object = factory.nextObject();
			if (object instanceof PGPCompressedData) {
				PGPCompressedData compressedData = (PGPCompressedData) object;
				return compressedData.getDataStream().readAllBytes();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return bytesToBeUnzipped;		
	}
	public static byte[] decrypt(byte[] bytesToBeDecrypted) {
		return null;		
	}
	
	public static byte[] convertFromRadix64ToByteStream(byte[] bytesToBeConvertedIntoRadix64){
        InputStream inputData = new ByteArrayInputStream(bytesToBeConvertedIntoRadix64);
		byte[] returnBytes;
		try {
			returnBytes = PGPUtil.getDecoderStream(inputData).readAllBytes();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
        return returnBytes;
	}

	public static boolean isEncryptedMessage(byte [] data) {
		
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
