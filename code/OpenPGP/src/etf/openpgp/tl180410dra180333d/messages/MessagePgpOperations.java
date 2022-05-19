package etf.openpgp.tl180410dra180333d.messages;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

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
				new JcaPGPContentSignerBuilder(signAlgorithm, KeyUtils.getHashAlgorithmTag(signAlgorithm, signKeySize)).setProvider("BC"));

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

	public static void zip() {

	}

}
