package etf.openpgp.tl180410dra180333d.messages;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.UIManager;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.Bytes;

import etf.openpgp.tl180410dra180333d.Application;

public class MessageReceiver {
	private Application application = null;
	private String author = null;
	private int encryptionAlgorithm = 0;
	private byte[] finalMessage = null;
	private boolean radixUsed = false;
	private boolean zipUsed = false;
	
	/**
	 * funkcija koja kreira objekat za citanje poruke
	 * @param application - aplikacija za koju pravimo gui za primanje poruke
	 */
	public MessageReceiver(Application application) {
		this.application = application;
	}

	/**
	 * metoda koja inicijalizuje panel za primanje poruke
	 * @param receiverMessagePanel
	 */
	public void initializeApplicationPanel(JPanel receiverMessagePanel) {
		receiverMessagePanel.setLayout(new BorderLayout());
		// header
		JPanel header = new JPanel();
		JLabel jlHeader = new JLabel("Receive file");
		jlHeader.setFont(new Font("Courier", Font.BOLD, 20));
		header.add(jlHeader);
		receiverMessagePanel.add(header, BorderLayout.NORTH);
		// end header
		// center

		JPanel centerPanel = new JPanel(new GridLayout(1, 2));

		JButton jbtnChooseDestination = new JButton("Choose");
		JLabel jlblChooseDestination = new JLabel("Choose file to read");

		centerPanel.add(jlblChooseDestination);
		centerPanel.add(jbtnChooseDestination);
		receiverMessagePanel.add(centerPanel, BorderLayout.CENTER);

		centerPanel.setBorder(BorderFactory.createEmptyBorder(150, 150, 350, 150));

		jbtnChooseDestination.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser(Application.dataRootPath);
				fileChooser.setDialogTitle("Select message");
				int result = fileChooser.showOpenDialog(application);
				if (result == JFileChooser.APPROVE_OPTION) {
					File fileToRead = fileChooser.getSelectedFile();
					readFile(fileToRead);
//					messageSenderForm.setSourceFile(fileChooser.getSelectedFile());
//					String selectedMessageFilePath = selectedFile.getAbsolutePath();
//					jlSourceFileSelected.setText(selectedFile.getName());
				}

			}
		});

	}

	/**
	 * metoda koja cita kriptovanu poruku
	 * @param file - fajl koji se cita
	 */
	public void readFile(File file) {
		byte[] dataForReading = null;
		try {
			FileInputStream fileInputStream = new FileInputStream(file);
			String str = file.toString();
			str = str.substring(str.lastIndexOf('.'), str.length());
			if (!str.equals(".gpg")) {
				JOptionPane.showMessageDialog(application, "Message is not in openPGP format!", "Decryption error",
						JOptionPane.ERROR_MESSAGE);
				return;
			}

			dataForReading = fileInputStream.readAllBytes();
			fileInputStream.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}

		// convert from radix64 to byte stream data
		byte [] tempData = dataForReading;
		dataForReading = MessagePgpOperations.convertFromRadix64ToByteStream(dataForReading);
		if (dataForReading == null) {
			JOptionPane.showMessageDialog(application,
					"Message is not in correct format or someone has changed encrypted message!", "Decryption error",
					JOptionPane.ERROR_MESSAGE);
			return;
		}
		
		if (tempData.length>dataForReading.length) {
			this.radixUsed = true;
		}
		// radix64 finished
		// decryption

		boolean ret = MessagePgpOperations.isEncryptedMessage(dataForReading);
		if (ret) {
			// enter passphrase
			String passphrase = JOptionPane.showInputDialog(application,
					"Enter passphrase to get private key for decyption");
			Object obj = null;
			try {
				// JcaPGPObjectFactory class for reading PGP object stream

				obj = new JcaPGPObjectFactory(dataForReading).nextObject();

				PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) obj;
				Iterator<PGPEncryptedData> encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();

				PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();
				long keyId = encryptedData.getKeyID();
				PGPSecretKeyRing secretKeyRing = application.getKeyUtils().getPgpPrivateKeyRingById(keyId);
				PGPSecretKey pgpSecretKey = secretKeyRing.getSecretKey(keyId);
				PGPPrivateKey privateKey = pgpSecretKey.extractPrivateKey(
						new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray()));

				PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
						.setProvider("BC").build(privateKey);
				encryptionAlgorithm = encryptedData.getSymmetricAlgorithm(decryptorFactory);

				dataForReading = encryptedData.getDataStream(decryptorFactory).readAllBytes();
			} catch (IOException e) {
				JOptionPane.showMessageDialog(application, "You don't have secret key to decrypt message!",
						"Decryption error", JOptionPane.ERROR_MESSAGE);
				return;
			} catch (PGPException e) {
				// secret key doesn't exists!
				JOptionPane.showMessageDialog(application, "You don't have secret key to decrypt message!",
						"Decryption error", JOptionPane.ERROR_MESSAGE);
				return;
			}
			// decryption finished
		}

		// unzip start
		tempData = dataForReading;
		dataForReading = MessagePgpOperations.unzip(dataForReading);
		if (!dataForReading.equals(tempData)) {
			this.zipUsed = true;
		}
		// unzip end

		// verify sign start

		try {
			Object objectToVerifySign = new JcaPGPObjectFactory(dataForReading).nextObject();
			if (objectToVerifySign instanceof PGPOnePassSignatureList) {
				PGPOnePassSignatureList signatureList = (PGPOnePassSignatureList) objectToVerifySign;
				PGPOnePassSignature signatureToVerify = signatureList.get(0);
				long signatureKeyId = signatureToVerify.getKeyID();
				PGPPublicKeyRing publicKeyRing = this.application.getKeyUtils().getPgpPublicKeyRingById(signatureKeyId);
				if (publicKeyRing == null)
					throw new NullPointerException();
				PGPPublicKey key = publicKeyRing.getPublicKey(signatureKeyId);
				StringBuilder stringBuilder = new StringBuilder();
				for (Iterator<String> iterator = key.getUserIDs(); iterator.hasNext();) {
					String str = (String) iterator.next();
					stringBuilder.append(str);
				}
				this.author = new String(stringBuilder);
				JcaPGPObjectFactory factory = new JcaPGPObjectFactory(dataForReading);
				factory.nextObject();
				PGPLiteralData data = (PGPLiteralData) factory.nextObject();
				this.finalMessage = data.getInputStream().readAllBytes();
				showInfo();
				saveMessage(file);
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NullPointerException e) {
			JOptionPane.showMessageDialog(application, "You don't have secret key to verify signature!",
					"Decryption error", JOptionPane.ERROR_MESSAGE);
			return;
		}
		// verify sign end

	}

	private void saveMessage(File file) {
		String str = file.getAbsolutePath();
		String fileName = file.getName();
		String nameAndExtension = fileName.substring(0, fileName.lastIndexOf('.'));

		JFileChooser choose_where_to_export = new JFileChooser(Application.dataRootPath);
		choose_where_to_export.setDialogTitle("Select message destination");
		choose_where_to_export.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		int ret = choose_where_to_export.showDialog(this.application, "Save");
		Path path = null;
		if (ret == JFileChooser.APPROVE_OPTION) {
			path = Paths.get(choose_where_to_export.getSelectedFile().getAbsolutePath());
		} else {
			return;
		}

		File outputFile = new File(path.toString() + "\\" + nameAndExtension);
		try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
			outputStream.write(finalMessage);
			JOptionPane.showMessageDialog(this.application, "Message Successfully saved", "Success",
					JOptionPane.INFORMATION_MESSAGE);
			// open file
			Desktop desktop = null;
			if (Desktop.isDesktopSupported()) {
				desktop = Desktop.getDesktop();
			}
			desktop.open(new File(path.toString() + "\\" + nameAndExtension));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void showInfo() {
		// change color
		Color defaultColor = UIManager.getColor("Panel.background");
		UIManager UI = new UIManager();

		UI.put("OptionPane.background", new Color(0x80ffbf));
		UI.put("Panel.background", new Color(0x80ffbf));

		JPanel jPanelInfo = new JPanel(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.weightx = 1;
		c.weighty = 1;
		c.fill = GridBagConstraints.HORIZONTAL;

		c.gridy = 0;
		c.gridx = 0;
		c.gridwidth = 2;
		int top = 5;
		int left = 10;
		int bottom = 5;
		int right = 10;
		// add header
		c.insets = new Insets(top, left, bottom, right);
		JLabel lblHeader = new JLabel("Message Received");
		jPanelInfo.add(lblHeader, c);

		// add author
		c.gridwidth = 1;
		c.gridy = 1;
		JLabel jlblText = new JLabel("Author:");
		jPanelInfo.add(jlblText, c);

		c.gridx = 1;
		JLabel jlblAuthor = new JLabel(author);
		jPanelInfo.add(jlblAuthor, c);

		
		// add symmetric algorithm used
		c.gridy = 2;
		c.gridx = 0;
		JLabel jlblAlgorithmText = new JLabel("Symmetric algorithm used:");
		jPanelInfo.add(jlblAlgorithmText, c);

		c.gridx = 1;
		JLabel jlblAlgorithm = null;
		if (encryptionAlgorithm == 2)
			jlblAlgorithm = new JLabel("3DES");
		else if (encryptionAlgorithm == 7)
			jlblAlgorithm = new JLabel("AES 128");
		else {
			jlblAlgorithm = new JLabel("/");
		}
		jPanelInfo.add(jlblAlgorithm, c);

		
		// add radix64 info
		c.gridy = 3;
		c.gridx = 0;
		JLabel jlblRadix64Text = new JLabel("Radix64 used:");
		jPanelInfo.add(jlblRadix64Text, c);

		c.gridx = 1;
		JLabel jlblRadix64 = null;
		if (this.radixUsed)
			jlblRadix64 = new JLabel("yes");
		else 
			jlblRadix64 = new JLabel("no");
		
		jPanelInfo.add(jlblRadix64, c);

		
		// add zip info
		c.gridy = 4;
		c.gridx = 0;
		JLabel jlblZipText = new JLabel("Zip used:");
		jPanelInfo.add(jlblZipText, c);

		c.gridx = 1;
		JLabel jlblZip = null;
		if (this.zipUsed)
			jlblZip = new JLabel("yes");
		else 
			jlblZip = new JLabel("no");
		
		jPanelInfo.add(jlblZip, c);
		
		
		
		
		JOptionPane.showConfirmDialog(this.application, jPanelInfo, "Message info: ", JOptionPane.OK_CANCEL_OPTION,
				JOptionPane.PLAIN_MESSAGE);

		// return old color
		UI.put("OptionPane.background", defaultColor);
		UI.put("Panel.background", defaultColor);
		
		this.radixUsed = false;
		this.zipUsed = false;
		
	}

}
