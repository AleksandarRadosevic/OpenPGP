package etf.openpgp.tl180410dra180333d.messages;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.swing.JOptionPane;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import etf.openpgp.tl180410dra180333d.Application;

public class MessageSenderForm {

	private Application application;

	private File sourceFile = null;
	private String destinationPath = null;

	private PGPSecretKey signKey = null;
	private String passphrase = null;

	private List<PGPPublicKey> encryptionKeys = null;
	private String symmetricKeyAlgorithm = null;
	private boolean radix64 = false;
	private boolean zip = false;

	public MessageSenderForm(Application application) {
		this.application = application;
	}

	public File getSourceFile() {
		return sourceFile;
	}

	public void setSourceFile(File sourceFile) {
		this.sourceFile = sourceFile;
	}

	public String getDestinationPath() {
		return destinationPath;
	}

	public void setDestinationPath(String destination) {
		this.destinationPath = destination;
	}

	public void setAuthenticationKey(String authenticationKeySelected) {
		String[] authenticationKeySelectedParts = authenticationKeySelected.split(" ");
		long authenticationKeyId = new BigInteger(
				authenticationKeySelectedParts[authenticationKeySelectedParts.length - 1], 16).longValue();

		try {
			PGPSecretKeyRing privateKeyRing = this.application.getKeyUtils()
					.getPgpPrivateKeyRingById(authenticationKeyId);
			Iterator<PGPSecretKey> iteratorPrivateKeyRing = privateKeyRing.getSecretKeys();
			if (iteratorPrivateKeyRing.hasNext()) {
				this.signKey = iteratorPrivateKeyRing.next(); // key for sign is first
			}
		} catch (PGPException e) {
			e.printStackTrace();
			this.signKey = null;
		}
	}

	public void setEncryptionKeys(Vector<String> encryptionKeyStrings) {
		List<PGPPublicKey> encriptionPublicKeyList = new ArrayList<>();

		for (String encriptionKeyString : encryptionKeyStrings) {
			String[] encriptionKeyStringParts = encriptionKeyString.split(" ");
			long encriptionKeyId = new BigInteger(encriptionKeyStringParts[encriptionKeyStringParts.length - 1], 16)
					.longValue();

			try {
				PGPPublicKeyRing publicKeyRing = this.application.getKeyUtils()
						.getPgpPublicKeyRingById(encriptionKeyId);
				Iterator<PGPPublicKey> iteratorPublicKeyRing = publicKeyRing.getPublicKeys();

				// sign public key is first in public key ring - skip it
				if (!iteratorPublicKeyRing.hasNext()) {
					return;
				}
				iteratorPublicKeyRing.next();

				// encription public key is second in public key ring
				if (!iteratorPublicKeyRing.hasNext()) {
					return;
				}
				encriptionPublicKeyList.add(iteratorPublicKeyRing.next());

			} catch (PGPException e) {
				e.printStackTrace();
				this.encryptionKeys = null;
				return;
			}
		}
		this.encryptionKeys = encriptionPublicKeyList;
	}

	public String getSymmetricKeyAlgorithm() {
		return symmetricKeyAlgorithm;
	}

	public void setSymmetricKeyAlgorithm(String symmetricKeyAlgorithm) {
		this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
	}

	public boolean isRadix64() {
		return radix64;
	}

	public void setRadix64(boolean radix64) {
		this.radix64 = radix64;
	}

	public boolean isZip() {
		return zip;
	}

	public void setZip(boolean zip) {
		this.zip = zip;
	}

	/**
	 * 
	 * @return null if form is valid else error message
	 */
	private String isValid() {
		if (this.sourceFile == null)
			return "Source file is missing!";
		if (this.destinationPath == null)
			return "Destination path is missing!";
		if((this.symmetricKeyAlgorithm!=null)&&this.encryptionKeys.size()==0) {
			return "Public key for session key encryption must be selected!";
		}
		if (this.signKey != null) {
			// check passphrase
			this.passphrase = JOptionPane.showInputDialog(this.application,
					"Enter passphrase to encript private sign key: ");
			if (this.passphrase == null || this.passphrase.length() == 0) {
				this.passphrase = null; // just to be sure that it is null
				return "Passphrase is required!";
			}
			try {
				this.signKey.extractPrivateKey(
						new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));
			} catch (PGPException e) {
				return "Passphrase is not correct!";
			}
		}
		return null;
	}

	/**
	 * 
	 * @return null if form is valid else error message
	 */
	public String sendMessage() {
		String validMessageError = this.isValid();
		if (validMessageError != null) {
			return validMessageError;
		}

		byte[] message = null;

		try {
			message = Files.readAllBytes(this.sourceFile.toPath());
		} catch (Exception e) {
			return "Source file can not be read!";
		}
		int iterationCount = 1;
		if (this.encryptionKeys != null && this.encryptionKeys.size() > 0) {
			iterationCount = this.encryptionKeys.size();
		}

		for (int iteration = 0; iteration < iterationCount; iteration++) {

			PGPPublicKey iterationPublicKeyForSessionKeyEncryption = null;
			if (this.encryptionKeys.size() > iteration) {
				iterationPublicKeyForSessionKeyEncryption = this.encryptionKeys.get(iteration);
			}
			String sentMessageName = "S" + String.valueOf(iteration)+"_"+(new Date().getTime())+"_"+sourceFile.getName() + ".gpg";
			try (FileOutputStream fileOutputStream = new FileOutputStream(
					this.destinationPath + "\\" + sentMessageName)) {

				// message should be authenticated - signed if signKey is selected
				if (this.signKey != null) {
					message = MessagePgpOperations.sign(message, this.signKey, this.passphrase);
				}

				// message should be encrypted if encryption key for session key encryption is
				// selected
				if (iterationPublicKeyForSessionKeyEncryption != null) {
					message = MessagePgpOperations.encrypt(message, iterationPublicKeyForSessionKeyEncryption,
							MessageSenderForm.getSymetricAlgorithmIntValue(this.symmetricKeyAlgorithm));
				}

				fileOutputStream.write(message);

				JOptionPane.showMessageDialog(this.application, "Poruka:" + sentMessageName+ " je poslata!");
			} catch (PGPException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return null;
	}

	public static int getSymetricAlgorithmIntValue(String symetricAlgorithm) {
		return ("3DES".equals(symetricAlgorithm)) ? SymmetricKeyAlgorithmTags.TRIPLE_DES
				: SymmetricKeyAlgorithmTags.AES_128;
	}

}
