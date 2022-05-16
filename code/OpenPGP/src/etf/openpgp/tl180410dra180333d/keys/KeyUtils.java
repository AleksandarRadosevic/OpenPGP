package etf.openpgp.tl180410dra180333d.keys;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class KeyUtils {
	private PGPSecretKeyRingCollection privateKeyRingCollection;
	private PGPPublicKeyRingCollection publicKeyRingCollection;
	private static final String privateKeyRingCollectionPath = "./data/private_key_ring_collection.asc";
	private static final String publicKeyRingCollectionPath = "./data/public_key_ring_collection.asc";

	public boolean generatePrivateRingKey(String userId, String signAlgorithm, String encryptionAlgorithm,
			String passphrase) {

		PGPSecretKeyRing privateKeyRing = null;

		// DSA Key generation for sign
		PGPKeyPair dsaKeyPair = null;

		try {
			KeyPairGenerator dsaKeyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
			int dsaKeySize = Integer.parseInt(signAlgorithm.split(" ")[1]);

			dsaKeyPairGenerator.initialize(dsaKeySize);
			KeyPair keyPair = dsaKeyPairGenerator.generateKeyPair();
			dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, keyPair, new Date());

		} catch (NoSuchAlgorithmException | PGPException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		// El Gamal Key generation for encryption
		PGPKeyPair elGamalKeyPair = null;

		try {
			KeyPairGenerator elGamalKeyPairGenerator = KeyPairGenerator.getInstance("ElGamal", "BC");
			int elGamalKeySize = Integer.parseInt(encryptionAlgorithm.split(" ")[1]);

			elGamalKeyPairGenerator.initialize(elGamalKeySize);
			KeyPair keyPair = elGamalKeyPairGenerator.generateKeyPair();
			elGamalKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, keyPair, new Date());

		} catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		try {

			PGPDigestCalculator hash = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

			PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
					dsaKeyPair, userId, hash, null, null,
					new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
					new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, hash).setProvider("BC")
							.build(passphrase.toCharArray()));

			// add subkey for encryption
			keyRingGenerator.addSubKey(elGamalKeyPair);
			privateKeyRing = keyRingGenerator.generateSecretKeyRing();
			return savePrivateKeyRing(privateKeyRing);
			
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	private boolean savePrivateKeyRing(PGPSecretKeyRing privateKeyRing) {
		try (OutputStream securedOutputStream = new ArmoredOutputStream(
				new FileOutputStream(KeyUtils.privateKeyRingCollectionPath))) {
			this.privateKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(this.privateKeyRingCollection,
					privateKeyRing);
			this.privateKeyRingCollection.encode(securedOutputStream);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
}
