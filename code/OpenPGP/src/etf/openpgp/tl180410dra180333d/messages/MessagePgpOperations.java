package etf.openpgp.tl180410dra180333d.messages;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import etf.openpgp.tl180410dra180333d.keys.KeyUtils;

public class MessagePgpOperations {

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

	

}
