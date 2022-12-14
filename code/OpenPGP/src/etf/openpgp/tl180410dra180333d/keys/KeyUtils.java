package etf.openpgp.tl180410dra180333d.keys;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
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

/**
 * Pomocna klasa koja pruza podrsku za rad sa kljucevima: generisanje, uvoz, izvoz, brisanje itd.
 */
public class KeyUtils {

	private final File privateKeyRingCollectionFile = new File(
			Application.packageRootPath + "/data/private_key_ring_collection.asc");
	private final File publicKeyRingCollectionFile = new File(
			Application.packageRootPath + "/data/public_key_ring_collection.asc");

	private PGPSecretKeyRingCollection privateKeyRingCollection;
	private PGPPublicKeyRingCollection publicKeyRingCollection;

	private Application application = null;
	
	/**
	 * Konstruktor koji kao parametar ima aplikaciju u kojoj je neophodno azurirati prikaz kada se model prstenova u ovoj klasi promeni.
	 * U okviru konstruktora se inicijalizuje model prstenova kljuceva podacima koji se cuvaju na disku, ako postoje.
	 * @param application
	 */
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

	/**
	 * Metoda koja sluzi za generisanje jednog privatnog para kljuca(potpisivanje, sifrovanje)
	 * @param userId - id vlasnika kljuca
	 * @param signAlgorithm - algoritam koji se koristi za potpisivanje
	 * @param encryptionAlgorithm - algoritam koji se koristi za sifrovanje kljuca sesije
	 * @param passphrase - zastitna lozinka za privatni kljuc(koristi se njen hes za zastitu privatnog kljuca)
	 * @return vrednost boolean(logickog) tipa koja prestavlja uspesnost operacije
	 */
	public boolean generatePrivateRingKey(String userId, String signAlgorithm, String encryptionAlgorithm,
			String passphrase) {

		PGPSecretKeyRing privateKeyRing = null;

		// DSA Key generation for sign
		int dsaKeySize = Integer.parseInt(signAlgorithm.split(" ")[1]);
		PGPKeyPair dsaKeyPair = this.generateDSAKeyPair(dsaKeySize);
		if(dsaKeyPair == null) {
			return false;
		}

		// El Gamal Key generation for encryption
		int elGamalKeySize = Integer.parseInt(encryptionAlgorithm.split(" ")[1]);
		PGPKeyPair elGamalKeyPair = this.generateElGamalKeyPair(elGamalKeySize);
		if(elGamalKeyPair == null) {
			return false;
		}

		try {

			PGPDigestCalculator hashCalculator = new JcaPGPDigestCalculatorProviderBuilder().build()
					.get(HashAlgorithmTags.SHA1);
			PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
					dsaKeyPair.getPublicKey().getAlgorithm(), KeyUtils.getHashAlgorithmTag(signAlgorithm)); // we must change this because DSA 2048 requires 256-bit as sign length
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
	
	private PGPKeyPair generateDSAKeyPair(int keySize) {
		PGPKeyPair dsaKeyPair = null;
		try {
			KeyPairGenerator dsaKeyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
			dsaKeyPairGenerator.initialize(keySize);
			
			KeyPair keyPair = dsaKeyPairGenerator.generateKeyPair();
			dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, keyPair, new Date());

		} catch (NoSuchAlgorithmException | PGPException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		return dsaKeyPair;
	}
	
	private PGPKeyPair generateElGamalKeyPair(int keySize) {
		PGPKeyPair elGamalKeyPair = null;
		try {
			KeyPairGenerator elGamalKeyPairGenerator = KeyPairGenerator.getInstance("ElGamal", "BC");
			if(keySize <= 2048) {
				elGamalKeyPairGenerator.initialize(keySize);
			}
			else {
				BigInteger primeModulous = KeyUtils.getPrime4096();
				BigInteger baseGenerator = KeyUtils.getBaseGenerator();
				ElGamalParameterSpec paramSpecs = new ElGamalParameterSpec(primeModulous, baseGenerator);
				elGamalKeyPairGenerator.initialize(paramSpecs);
			}
			KeyPair keyPair = elGamalKeyPairGenerator.generateKeyPair();
			elGamalKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, keyPair, new Date());
		} catch (NoSuchAlgorithmException | NoSuchProviderException | PGPException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return elGamalKeyPair;
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

	/**
	 * Metoda koja sluzi za brisanje para kljuceva iz privatnog prstena kljuceva
	 * @param privateKeyRingId - id kljuca za potpisivanje predstavlja id kljuca jednog tog para u kolekciji (ring in collection ring)
	 * @param passphrase - lozinka kojom se stiti privatni kljuc
	 * @return vrednost boolean(logickog) tipa koja prestavlja uspesnost operacije 
	 */
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

	/**
	 * Metoda koja sluzi da se izveze par kljuceva( potpisivanje, sifrovanje) iz privatnog prstena kljuceva
	 * @param keyId - id kljuca za potpisivanje predstavlja id kljuca jednog tog para u kolekciji (ring in collection ring)
	 * @param userId - id vlasnika kljuca (prosledjuje se zbog imenovanja fajla) /moglo je da se dogvati i iz samog para kljuceva( potpisivanje, sifrovanje)/
	 * @param selectedExportPath -putanja za cuvanje .asc fajla na disku
	 * @return vrednost boolean(logickog) tipa koja prestavlja uspesnost operacije
	 */
	public boolean exportPrivateKeyRing(long keyId, String userId, String selectedExportPath) {
		PGPSecretKeyRing secretKeyRing;
		boolean onlyPublic = false;
		
		// check if user want to export only a public keys from private key ring
		String[] exportPrivateKeyRingOptions = {"private + public", "public"};

		Object selected = JOptionPane.showInputDialog(this.application, "Choose option for exporting key ring:", "Selection", JOptionPane.DEFAULT_OPTION, null, exportPrivateKeyRingOptions, "0");
		if (selected != null ){//null if the user cancels. 
		    String selectedString = selected.toString();
		    if(selectedString.equals(exportPrivateKeyRingOptions[1])) {
		    	onlyPublic = true;
		    }
		}else{
		    return false;
		}
		
		try {
			secretKeyRing = this.privateKeyRingCollection.getSecretKeyRing(keyId);
			
			String pathToSave = null;
			if(selectedExportPath!=null && selectedExportPath.length()>0) {
				pathToSave = selectedExportPath+"\\";
			}
			else {
				pathToSave = Application.packageRootPath + "/data/private_key_exported/";
			}
			if(onlyPublic) {
				pathToSave += "Public_"+userId+"_";
			}
			else {
				pathToSave += "Private_"+userId+"_";
			}
			pathToSave = pathToSave + (new Date()).getTime()+ ".asc";
			File fileToSave = new File(pathToSave);

			try {
				fileToSave.createNewFile();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				return false;
			}
			try (OutputStream securedOutputStream = new ArmoredOutputStream(new FileOutputStream(fileToSave))) {
				if(onlyPublic) {
					PGPPublicKeyRing publicKeyRing = KeyUtils.convertFromPGPPrivateToPublicKeyRing(secretKeyRing);
					publicKeyRing.encode(securedOutputStream);
				}
				else {
					secretKeyRing.encode(securedOutputStream);
				}
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

	/**
	 * Metoda za uvoz para kljuceva( sifrovanje, potpisivanje) u prsten privatnih kljuceva
	 * @param file - .asc fajl iz koga se uvozi
	 * @return IMPORT_OPERATION_RESULT - ishod operacije (nabrojivi tip)
	 */
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
			//e.printStackTrace();
			
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return IMPORT_OPERATION_RESULT.FAILURE;
	}

	/**
	 * Metoda koja sluzi za brisanje para kljuceva iz javnog prstena kljuceva
	 * @param publicKeyRingId - id kljuca za potpisivanje predstavlja id kljuca jednog tog para u kolekciji (ring in collection ring)
	 * @return vrednost boolean(logickog) tipa koja prestavlja uspesnost operacije 
	 */
	public boolean deletePublicKeyRing(long publicKeyRingId) {
		try {
			PGPPublicKeyRing publicKeyRing = this.publicKeyRingCollection.getPublicKeyRing(publicKeyRingId);			
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

	/**
	 * Metoda za uvoz para kljuceva( sifrovanje, potpisivanje) u prsten javnih kljuceva
	 * @param file - .asc fajl iz koga se uvozi
	 * @return IMPORT_OPERATION_RESULT - ishod operacije (nabrojivi tip)
	 */
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
			//e.printStackTrace();
		}
		return IMPORT_OPERATION_RESULT.FAILURE;
	}

	/**
	 * Metoda koja sluzi da se izveze par kljuceva( potpisivanje, sifrovanje) iz javnog prstena kljuceva
	 * @param keyId - id kljuca za potpisivanje predstavlja id kljuca jednog tog para u kolekciji (ring in collection ring)
	 * @param userId - id vlasnika kljuca (prosledjuje se zbog imenovanja fajla) /moglo je da se dogvati i iz samog para kljuceva( potpisivanje, sifrovanje)/
	 * @param selectedExportPath -putanja za cuvanje .asc fajla na disku
	 * @return vrednost boolean(logickog) tipa koja prestavlja uspesnost operacije
	 */
	public boolean exportPublicKeyRing(long keyId, String userId, String selectedExportPath) {
		PGPPublicKeyRing publicKeyRing;
		try {
			publicKeyRing = this.publicKeyRingCollection.getPublicKeyRing(keyId);
			
			String pathToSave = null;
			if(selectedExportPath!=null && selectedExportPath.length()>0) {
				pathToSave = selectedExportPath + "\\Public_"+userId+"_";
			}
			else {
				pathToSave = Application.packageRootPath + "/data/public_key_exported/Public_"+userId+"_";
			}
			pathToSave = pathToSave + (new Date()).getTime()+ ".asc";
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

	
    /**
     * Parametar preuzet iz RFC3526
     * 
     * Prime number is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3996 pi] + 240904 }
     * 
     * @return prost moduo za 4096 bit MODP grupu
     */
    private static final BigInteger getPrime4096() {
            StringBuilder sb = new StringBuilder();
            sb.append("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1");
            sb.append("29024E088A67CC74020BBEA63B139B22514A08798E3404DD");
            sb.append("EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245");
            sb.append("E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED");
            sb.append("EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D");
            sb.append("C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F");
            sb.append("83655D23DCA3AD961C62F356208552BB9ED529077096966D");
            sb.append("670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B");
            sb.append("E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9");
            sb.append("DE2BCBF6955817183995497CEA956AE515D2261898FA0510");
            sb.append("15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64");
            sb.append("ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7");
            sb.append("ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B");
            sb.append("F12FFA06D98A0864D87602733EC86A64521F2B18177B200C");
            sb.append("BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31");
            sb.append("43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7");
            sb.append("88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA");
            sb.append("2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6");
            sb.append("287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED");
            sb.append("1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9");
            sb.append("93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199");
            sb.append("FFFFFFFFFFFFFFFF");
            return new BigInteger(sb.toString(), 16);
    }
    
    /**
     * Parametar preuzet iz RFC3526
     * 
     * @return generator za 4096 bit MODP grupu
     */
    private static final BigInteger getBaseGenerator() {
        return new BigInteger("2", 16);
    }
    
    /**
     * Metoda za dohvatanje para kljuceva(potpisivanje, sifrovanje) iz kolekcije prstena privatnih kljuceva
     * @param keyId - id para kljuceva (id kljuca za potpisivanje)
     * @return par kljuceva(potpisivanje, sifrovanje) iz kolekcije prstena privatnih kljuceva
     * @throws PGPException
     */
    public PGPSecretKeyRing getPgpPrivateKeyRingById(long keyId) throws PGPException {
    	return this.privateKeyRingCollection.getSecretKeyRing(keyId);
    }
    
    /**
     * Metoda za dohvatanje para kljuceva(potpisivanje, sifrovanje) iz kolekcije prstena javnih kljuceva
     * @param keyId - id para kljuceva (id kljuca za potpisivanje)
     * @return par kljuceva(potpisivanje, sifrovanje) iz kolekcije prstena javnih kljuceva
     * @throws PGPException
     */
    public PGPPublicKeyRing getPgpPublicKeyRingById(long keyId) throws PGPException {
    	return this.publicKeyRingCollection.getPublicKeyRing(keyId);
    }
    
    /**
     * Staticka metoda koja vraca informaciju o tome koji je hash algoritam potrebno koristit za generisanje potpisa na osnovu algoritma kojim se hes sifruje
     * @param signAlgorithm - algoritam i velicina kljuca koji se koriste za potpisivanje (npr. DSA 2048)
     * @return hes algoritam tag algoritma koji treba da se koristi za formiranje hes-a
     */
	public static int getHashAlgorithmTag(String signAlgorithm) {
		if("DSA 2048".equals(signAlgorithm)) {
			return HashAlgorithmTags.SHA256;
		}
		return HashAlgorithmTags.SHA1;
	}
	
    /**
     * Staticka metoda koja vraca informaciju o tome koji je hash algoritam potrebno koristit za generisanje potpisa na osnovu algoritma kojim se hes sifruje
     * @param signAlgorithm - algoritam koji koristi kljuc za potpisivanje(npr. dsa)
     * @param keySize - velicina kljuca
     * @return hes algoritam tag algoritma koji treba da se koristi za formiranje hes-a
     */
	public static int getHashAlgorithmTag(int signAlgorithm, int keySize) {
		if((signAlgorithm == PGPPublicKey.DSA) && (keySize==2048)) {
			return HashAlgorithmTags.SHA256;
		}
		return HashAlgorithmTags.SHA1;
	}
	
	/**
	 * Na osnovu kljuceva u privatnom prstenu formira prsten javnih kluceva
	 * @param privateKeyRing
	 * @return PGPPublicKeyRing
	 */
	public static PGPPublicKeyRing convertFromPGPPrivateToPublicKeyRing(PGPSecretKeyRing privateKeyRing) {
		List<PGPPublicKey> publicKeyList = new LinkedList<>();
		Iterator<PGPPublicKey> iteratorPublicKeysInPrivateRing = privateKeyRing.getPublicKeys();
	    while (iteratorPublicKeysInPrivateRing.hasNext()) {
	        PGPPublicKey pub = iteratorPublicKeysInPrivateRing.next();
	        publicKeyList.add(pub);
	    }
	    PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(publicKeyList);
	    return publicKeyRing;
	}

}
