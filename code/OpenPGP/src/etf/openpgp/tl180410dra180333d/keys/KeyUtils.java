package etf.openpgp.tl180410dra180333d.keys;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import etf.openpgp.tl180410dra180333d.Application;
import etf.openpgp.tl180410dra180333d.keys.OperationResult.IMPORT_OPERATION_RESULT;

public class KeyUtils {
	private static final String packageRootPath = "./src/etf/openpgp/tl180410dra180333d/";
	private final File privateKeyRingCollectionFile = new File(
			KeyUtils.packageRootPath + "/data/private_key_ring_collection.asc");
	private final File publicKeyRingCollectionFile = new File(
			KeyUtils.packageRootPath + "/data/public_key_ring_collection.asc");

	private PGPSecretKeyRingCollection privateKeyRingCollection;
	private PGPPublicKeyRingCollection publicKeyRingCollection;

	private Application application = null;

	public KeyUtils(Application application) {
		try {
			this.publicKeyRingCollection = new PGPPublicKeyRingCollection(new LinkedList<>());
			this.privateKeyRingCollection = new PGPSecretKeyRingCollection(new LinkedList<>());
			this.application = application;

			this.loadKeyRingCollections();
			this.application.update_privateKeyRingTableModel(this.privateKeyRingCollection);
			this.application.update_publicKeyRingTableModel(this.publicKeyRingCollection);

		} catch (IOException e) {
			e.printStackTrace();
		} catch (PGPException e) {
			e.printStackTrace();
		}
	}

	private void loadKeyRingCollections() {
		try {
			this.privateKeyRingCollection = new PGPSecretKeyRingCollection(
					new ArmoredInputStream(new FileInputStream(this.privateKeyRingCollectionFile)),
					new JcaKeyFingerprintCalculator());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (PGPException e) {
			e.printStackTrace();
		}

		try {
			this.publicKeyRingCollection = new PGPPublicKeyRingCollection(
					new ArmoredInputStream(new FileInputStream(this.publicKeyRingCollectionFile)),
					new JcaKeyFingerprintCalculator());
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (PGPException e) {
			e.printStackTrace();
		}

	}

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

			PGPDigestCalculator hashCalculator = new JcaPGPDigestCalculatorProviderBuilder().build()
					.get(HashAlgorithmTags.SHA1);
			PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
					dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256); // we must change this because
																							// DSA 2048 requires 256
																							// sign
			PBESecretKeyEncryptor privateKeyEncriptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128,
					hashCalculator).setProvider("BC").build(passphrase.toCharArray());

			// null values are used for PGPSignatureSubpacketVector fields (additional
			// information about issuer, expiration date, flags etc.)
			// we don't set expiration date for our sertificate
			PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
					dsaKeyPair, userId, hashCalculator, null, null, signerBuilder, privateKeyEncriptor);

			keyRingGenerator.addSubKey(elGamalKeyPair); // add subkey for encryption
			privateKeyRing = keyRingGenerator.generateSecretKeyRing(); // private key ring is created and should be
																		// saved private key ring collection

			this.privateKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(this.privateKeyRingCollection,
					privateKeyRing);

			return this.savePrivateKeyRing();

		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return false;
	}

	private boolean savePrivateKeyRing() {
		try {
			this.privateKeyRingCollectionFile.createNewFile();// create file if it doesn't exist
		} catch (IOException e1) {
			e1.printStackTrace();
			return false;
		}
		try (OutputStream securedOutputStream = new ArmoredOutputStream(
				new FileOutputStream(this.privateKeyRingCollectionFile, false))) {
			this.privateKeyRingCollection.encode(securedOutputStream);
			this.application.update_privateKeyRingTableModel(privateKeyRingCollection);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	private boolean savePublicKeyRing() {
		try {
			this.publicKeyRingCollectionFile.createNewFile();// create file if it doesn't exist
		} catch (IOException e1) {
			e1.printStackTrace();
			return false;
		}
		try (OutputStream securedOutputStream = new ArmoredOutputStream(
				new FileOutputStream(this.publicKeyRingCollectionFile, false))) {
			this.publicKeyRingCollection.encode(securedOutputStream);
			this.application.update_publicKeyRingTableModel(this.publicKeyRingCollection);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	// private key ring operations start

	public boolean deletePrivateKeyRing(long privateKeyRingId, String passphrase) {
		try {
			PGPSecretKeyRing privateKeyRing = this.privateKeyRingCollection.getSecretKeyRing(privateKeyRingId);
			Iterator<PGPSecretKey> privateKeyIterator = privateKeyRing.getSecretKeys();

			// we are sure that we have dsa and elgamal keys in privateKeyRing
			PGPSecretKey signKey = privateKeyIterator.next();

			// check passphrase
			signKey.extractPrivateKey(
					new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));

			this.privateKeyRingCollection = PGPSecretKeyRingCollection
					.removeSecretKeyRing(this.privateKeyRingCollection, privateKeyRing);
			this.savePrivateKeyRing();
		} catch (PGPException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			JOptionPane.showMessageDialog(new JFrame(), "Incorrect passphrase for private key or key is missing!",
					"Error - incorrect passphrase or key is missing", JOptionPane.ERROR_MESSAGE);
			return false;
		}
		return true;
	}

	public boolean exportPrivateKeyRing(long keyId) {
		PGPSecretKeyRing secretKeyRing;
		try {
			secretKeyRing = this.privateKeyRingCollection.getSecretKeyRing(keyId);
			String pathToSave = packageRootPath + "/data/private_key_exported/PrivateKeyRing" + (new Date()).getTime()
					+ ".asc";
			File fileToSave = new File(pathToSave);

			try {
				fileToSave.createNewFile();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return false;
			}
			try (OutputStream securedOutputStream = new ArmoredOutputStream(new FileOutputStream(fileToSave))) {
				secretKeyRing.encode(securedOutputStream);
				return true;
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		} catch (PGPException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return false;
	}

	public IMPORT_OPERATION_RESULT importPrivateKeyRing(File file) {
		try (InputStream inputStream = new ArmoredInputStream(new FileInputStream(file.toString()))) {
			PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(inputStream, new JcaKeyFingerprintCalculator());
			this.privateKeyRingCollection = PGPSecretKeyRingCollection.addSecretKeyRing(privateKeyRingCollection,
					secretKeyRing);
			boolean ret = this.savePrivateKeyRing();
			if (ret) {
				return IMPORT_OPERATION_RESULT.SUCCESS;
			}
		} catch (IllegalArgumentException e) {
			return IMPORT_OPERATION_RESULT.KEY_EXISTS;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return IMPORT_OPERATION_RESULT.FAILURE;
	}

	// private key ring operations end

	// public key rings operations start
	public boolean deletePublicKeyRing(long publicKeyRingId) {
		try {
			PGPPublicKeyRing publicKeyRing = this.publicKeyRingCollection.getPublicKeyRing(publicKeyRingId);
			Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();

			// we are sure that we have dsa and elgamal keys in privateKeyRing
			PGPPublicKey signKey = publicKeyIterator.next();

			// check passphrase
			
			this.publicKeyRingCollection = PGPPublicKeyRingCollection
					.removePublicKeyRing(this.publicKeyRingCollection, publicKeyRing);
			this.savePublicKeyRing();
		} catch (PGPException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			JOptionPane.showMessageDialog(new JFrame(), "Incorrect passphrase for private key or key is missing!",
					"Error - incorrect passphrase or key is missing", JOptionPane.ERROR_MESSAGE);
			return false;
		}
		return true;
		
	}

	public IMPORT_OPERATION_RESULT importPublicKeyRing(File file) {
		try (InputStream inputStream = new ArmoredInputStream(new FileInputStream(file.toString()))) {
			PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(inputStream, new JcaKeyFingerprintCalculator());
			this.publicKeyRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRingCollection,
					publicKeyRing);
			boolean ret = this.savePublicKeyRing();
			if (ret) {
				return IMPORT_OPERATION_RESULT.SUCCESS;
			}
		} catch (IllegalArgumentException e) {
			return IMPORT_OPERATION_RESULT.KEY_EXISTS;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return IMPORT_OPERATION_RESULT.FAILURE;
	}

	public boolean exportPublicKeyRing(long keyId) {
		PGPPublicKeyRing publicKeyRing;
		try {
			publicKeyRing = this.publicKeyRingCollection.getPublicKeyRing(keyId);
			String pathToSave = packageRootPath + "/data/public_key_exported/PublicKeyRing" + (new Date()).getTime()
					+ ".asc";
			File fileToSave = new File(pathToSave);

			try {
				fileToSave.createNewFile();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return false;
			}
			try (OutputStream securedOutputStream = new ArmoredOutputStream(new FileOutputStream(fileToSave))) {
				publicKeyRing.encode(securedOutputStream);
				return true;
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		} catch (PGPException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		return false;
	}

	// public key rings operations end

}
