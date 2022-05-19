package etf.openpgp.tl180410dra180333d.messages;

import java.io.File;
import java.util.Vector;

public class MessageSenderForm {

	private File sourceFile = null;
	private String destinationPath = null;
	private String authenticationKey = null;
	private Vector<String>encryptionKeys=null;
	private String symmetricKeyAlgorithm = null;
	private boolean radix64 = false;
	private boolean zip = false;
	
	public MessageSenderForm() {
		// TODO Auto-generated constructor stub
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
	public String getAuthenticationKey() {
		return authenticationKey;
	}
	public void setAuthenticationKey(String authenticationKey) {
		this.authenticationKey = authenticationKey;
	}
	public Vector<String> getEncryptionKeys() {
		return encryptionKeys;
	}
	public void setEncryptionKeys(Vector<String> encryptionKeys) {
		this.encryptionKeys = encryptionKeys;
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
	public String isValid() {
		if (this.sourceFile == null)
			return "Source file is missing";
		if (this.destinationPath == null) 
			return "Destination path is missing";
		
		return null;
	}




}
