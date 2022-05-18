package etf.openpgp.tl180410dra180333d;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.math.BigInteger;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableModel;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import etf.openpgp.tl180410dra180333d.keys.KeyUtils;
import etf.openpgp.tl180410dra180333d.keys.OperationResult;
import etf.openpgp.tl180410dra180333d.keys.OperationResult.IMPORT_OPERATION_RESULT;

/**
 * 
 * Glavna klasa koja pokrece aplikaciju.
 * 
 */
public class Application extends JFrame {

	private static final String[] asymmetricEncryptionAlgorithms = { "ElGamal 1024", "ElGamal 2048", "ElGamal 4096" };
	private static final String[] asymmetricSignAlgorithms = { "DSA 1024", "DSA 2048" };

	private DefaultTableModel privateKeyRingTableModel = null;
	private DefaultTableModel publicKeyRingTableModel = null;
	private KeyUtils keyUtils = null;

	public Application() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		this.setTitle("OpenPGP App");
		this.setSize(1080, 720);

		this.initialization();

		this.keyUtils = new KeyUtils(this);
		this.setVisible(true);

		// when user close program on X
		this.addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				dispose();
			}
		});
	}

	/**
	 * Inicijalizacija GUI-a aplikacije.
	 */
	private void initialization() {

		/**** INICIJALIZACIJA TABOVA *********/
		JTabbedPane tabPane = new JTabbedPane();

		JPanel privateKeyRingPanel = new JPanel();
		this.initialize_privateKeyRingPanel(privateKeyRingPanel);

		JPanel publicKeyRingPanel = new JPanel();
		this.initialize_publicKeyRingPanel(publicKeyRingPanel);

		JPanel sendMessagePanel = new JPanel();
		this.initialize_sendMessagePanel(sendMessagePanel);

		JPanel receiveMessagePanel = new JPanel();
		this.initialize_receiveMessagePanel(receiveMessagePanel);

		tabPane.add("Prsten privatnih kljuceva", privateKeyRingPanel);
		tabPane.add("Prsten javnih kljuceva", publicKeyRingPanel);
		tabPane.add("Slanje poruke", sendMessagePanel);
		tabPane.add("Prijem poruke", receiveMessagePanel);

		this.add(tabPane);
	}

	private void initialize_privateKeyRingPanel(JPanel privateKeyRingPanel) {
		// User ID = Name (Email)
		privateKeyRingPanel.setLayout(new BorderLayout());

		JPanel jpAddNewPrivateRingKeyForm = create_addNewPrivateRingKeyForm();
		privateKeyRingPanel.add(jpAddNewPrivateRingKeyForm, BorderLayout.NORTH);

		JPanel jpControls = new JPanel();

		// begin
		// panel for showing import button, export button, delete button

		jpControls.setLayout(new GridBagLayout());
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
		c.insets = new Insets(top, left, bottom, right);
		JButton deletePrivateKeyRingButton = new JButton("DELETE SELECTED KEY FROM PRIVATE KEY RING");
		jpControls.add(deletePrivateKeyRingButton, c);

		c.gridwidth = 1;
		c.gridy = 1;
		JButton exportPrivateKeyRingButton = new JButton("EXPORT SELECTED KEY FROM PRIVATE KEY RING");
		jpControls.add(exportPrivateKeyRingButton, c);

		c.gridx = 1;
		JButton importPrivateKeyRingButton = new JButton("IMPORT KEY TO PRIVATE KEY RING");
		jpControls.add(importPrivateKeyRingButton, c);

		// panel for showing import button, export button, delete button
		// end

		privateKeyRingPanel.add(jpControls, BorderLayout.SOUTH);

		String[] columnLabels = { "Timestamp", "User ID", "Sign Key ID" };
		this.privateKeyRingTableModel = this.initialize_keyRingTable(privateKeyRingPanel, columnLabels,
				deletePrivateKeyRingButton, exportPrivateKeyRingButton, importPrivateKeyRingButton);
	}

	private void initialize_publicKeyRingPanel(JPanel publicKeyRingPanel) {

		publicKeyRingPanel.setLayout(new BorderLayout());

		// begin
		// panel for showing import button, export button, delete button

		JPanel jpControls = new JPanel();
		jpControls.setLayout(new GridBagLayout());

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
		c.insets = new Insets(top, left, bottom, right);
		JButton deletePublicKeyRingButton = new JButton("DELETE SELECTED KEY FROM PUBLIC KEY RING");
		jpControls.add(deletePublicKeyRingButton, c);

		c.gridwidth = 1;
		c.gridy = 1;

		JButton exportPublicKeyRingButton = new JButton("EXPORT SELECTED KEY FROM PUBLIC KEY RING");
		jpControls.add(exportPublicKeyRingButton, c);

		c.gridx = 1;
		JButton importPublicKeyRingButton = new JButton("IMPORT KEY TO PUBLIC RING");
		jpControls.add(importPublicKeyRingButton, c);

		// end panel

		publicKeyRingPanel.add(jpControls, BorderLayout.SOUTH);

		String[] columnLabels = { "Timestamp", "User ID", "Key ID" };
		this.publicKeyRingTableModel = this.initialize_keyRingTable(publicKeyRingPanel, columnLabels,
				deletePublicKeyRingButton, exportPublicKeyRingButton, importPublicKeyRingButton);

	}

	private DefaultTableModel initialize_keyRingTable(JPanel keyRingPanel, String[] columnLabels,
			JButton deleteKeyRingButton, JButton exportKeyRingButton, JButton importKeyRingButton) {

		JTable jtKeyRingTable = new JTable();
		jtKeyRingTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
		// jtKeyRingTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		DefaultTableModel keyRingTableModel = (DefaultTableModel) jtKeyRingTable.getModel();
		keyRingTableModel.setColumnIdentifiers(columnLabels);

		jtKeyRingTable.getTableHeader().setFont(new Font(Font.MONOSPACED, Font.BOLD + Font.ITALIC, 12));
		jtKeyRingTable.getTableHeader().setOpaque(false);
		jtKeyRingTable.getTableHeader().setBackground(new Color(32, 136, 203));
		jtKeyRingTable.getTableHeader().setForeground(new Color(255, 255, 255));
		jtKeyRingTable.setRowHeight(25);
		jtKeyRingTable.setAutoResizeMode(JTable.AUTO_RESIZE_NEXT_COLUMN);
		JScrollPane scrollPane = new JScrollPane(jtKeyRingTable, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
				JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		keyRingPanel.add(scrollPane, BorderLayout.CENTER);

		deleteKeyRingButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent arg0) {
				// check for selected row first
				if (jtKeyRingTable.getSelectedRow() != -1) {
					// remove selected row from the model

					String keyIdStr = (String) keyRingTableModel.getValueAt(jtKeyRingTable.getSelectedRow(), 2);
					long keyId = new BigInteger(keyIdStr, 16).longValue();
					deletePrivateKeyRing(keyId);
				}
			}
		});

		exportKeyRingButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent arg0) {
				// check for selected row first
				if (jtKeyRingTable.getSelectedRow() != -1) {

					String keyIdStr = (String) keyRingTableModel.getValueAt(jtKeyRingTable.getSelectedRow(), 2);
					long keyId = new BigInteger(keyIdStr, 16).longValue();
					exportPrivateKeyRing(keyId);
				}
			}
		});

		importKeyRingButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				importPrivateKeyRing();
			}
		});
		return keyRingTableModel;
	}

	private void initialize_sendMessagePanel(JPanel sendMessagePanel) {

	}

	private void initialize_receiveMessagePanel(JPanel receiveMessagePanel) {

	}

	private JPanel create_addNewPrivateRingKeyForm() {

		JPanel jpAddNewKeyRingForm = new JPanel();
		jpAddNewKeyRingForm.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.weightx = 1;
		c.weighty = 1;
		c.fill = GridBagConstraints.HORIZONTAL;

		int top = 5;
		int left = 10;
		int bottom = 5;
		int right = 10;
		c.insets = new Insets(top, left, bottom, right);

		JLabel jlName = new JLabel("Name: ");
		JLabel jlEmail = new JLabel("Email: ");
		JLabel jlSignAlgorithm = new JLabel("Select Sign Algorithm");
		JLabel jlEncryptionAlgorithm = new JLabel("Select Encryption Algorithm");

		JTextField jtfName = new JTextField();
		JTextField jtfEmail = new JTextField();
		JComboBox<String> jcbSignAlgorithm = new JComboBox<>(asymmetricSignAlgorithms);
		JComboBox<String> jcbEncryptionAlgorithm = new JComboBox<>(asymmetricEncryptionAlgorithms);

		JButton jbAddNewKey = new JButton("Add New Key");

		jbAddNewKey.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				String name = jtfName.getText();
				String email = jtfEmail.getText();
				String signAlgorithm = (String) jcbSignAlgorithm.getSelectedItem();
				String encryptionAlgorithm = (String) jcbEncryptionAlgorithm.getSelectedItem();
				boolean ret = insertNewPrivateKeyRing(name, email, signAlgorithm, encryptionAlgorithm);
				if (!ret) {
					JOptionPane.showMessageDialog(new JFrame(),
							"Nije uspelo dodavanje kljuca, sva polja su obavezna kao i passphrase za cuvanje privatnog kljuca!",
							"Greska pri dodavanju kljuca", JOptionPane.ERROR_MESSAGE);
				}
			}
		});

		c.gridwidth = 1;
		c.gridheight = 1;

		// first row
		c.gridy = 0;

		// add name to layout
		c.gridx = 0;
		jpAddNewKeyRingForm.add(jlName, c);
		c.gridx = 1;
		jpAddNewKeyRingForm.add(jtfName, c);

		// add email label to layout
		c.gridx = 2;
		jpAddNewKeyRingForm.add(jlEmail, c);
		c.gridx = 3;
		jpAddNewKeyRingForm.add(jtfEmail, c);

		// first row
		c.gridy = 1;

		// add sign algorithm label to layout
		c.gridx = 0;
		jpAddNewKeyRingForm.add(jlSignAlgorithm, c);
		c.gridx = 1;
		jpAddNewKeyRingForm.add(jcbSignAlgorithm, c);

		// add sign algorithm label to layout
		c.gridx = 2;
		jpAddNewKeyRingForm.add(jlEncryptionAlgorithm, c);
		c.gridx = 3;
		jpAddNewKeyRingForm.add(jcbEncryptionAlgorithm, c);

		// add button for adding new key
		top = 10;
		left = 50;
		bottom = 10;
		right = 10;
		c.insets = new Insets(top, left, bottom, right);

		c.gridy = 2;
		c.gridx = 2;
		c.gridwidth = 2;
		c.gridheight = 2;
		jpAddNewKeyRingForm.add(jbAddNewKey, c);

		return jpAddNewKeyRingForm;
	}

	private boolean insertNewPrivateKeyRing(String name, String email, String signAlgorithm,
			String encryptionAlgorithm) {
		if (name == null || name.length() == 0)
			return false;

		if (email == null || email.length() == 0)
			return false;

		if (signAlgorithm == null || signAlgorithm.length() == 0)
			return false;

		if (encryptionAlgorithm == null || encryptionAlgorithm.length() == 0)
			return false;

		String passphrase = JOptionPane.showInputDialog(new JFrame(), "Enter passphrase to protect your private key");
		if (passphrase == null || passphrase.length() == 0) {
			return false;
		}
		// identity => name <email>
		return this.keyUtils.generatePrivateRingKey(name + " <" + email + ">", signAlgorithm, encryptionAlgorithm,
				passphrase);

	}

	public void update_privateKeyRingTableModel(PGPSecretKeyRingCollection privateKeyRingCollection) {
		this.privateKeyRingTableModel.setRowCount(0); // clear table model

		Iterator<PGPSecretKeyRing> privateKeyRingIterator = privateKeyRingCollection.getKeyRings();

		while (privateKeyRingIterator.hasNext()) {
			PGPSecretKeyRing privateKeyRing = privateKeyRingIterator.next();

			Iterator<PGPSecretKey> privateKeyIterator = privateKeyRing.getSecretKeys();
			

			// we are sure that we have two keys in ring, one for sign and one for
			// encryption
			if (!privateKeyIterator.hasNext()) {
				System.err.println("U prstenu privatnog kljuca nema kljuca za potpisivanje!");
				break;
			}
			PGPSecretKey signKey = privateKeyIterator.next();

			if (!privateKeyIterator.hasNext()) {
				System.err.println("U prstenu privatnog kljuca nema kljuca za enkripciju!");
				break;
			}
			PGPSecretKey encryptionKey = privateKeyIterator.next();

			long singnKeyId = signKey.getKeyID(); // this key id is used to be shown in key ring table
			// long encriptionKeyId = encryptionKey.getKeyID();

			String keyOwner = signKey.getUserIDs().next();

			Date creationDate = signKey.getPublicKey().getCreationTime();

			String[] privateKeyRingTableRow = new String[] { creationDate.toString(), keyOwner,
					String.format("%016x", singnKeyId).toUpperCase() };

			this.privateKeyRingTableModel.addRow(privateKeyRingTableRow);
		}

	}

	public void update_publicKeyRingTableModel(PGPPublicKeyRingCollection publicKeyRingCollection) {
		this.publicKeyRingTableModel.setRowCount(0); // clear table model

		Iterator<PGPPublicKeyRing> publicKeyRingIterator = publicKeyRingCollection.getKeyRings();

		while (publicKeyRingIterator.hasNext()) {
			PGPPublicKeyRing publicKeyRing = publicKeyRingIterator.next();

			Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();

			// we are sure that we have two keys in ring, one for sign and one for
			// encryption
			if (!publicKeyIterator.hasNext()) {
				System.err.println("U prstenu javnog kljuca nema kljuca za potpisivanje!");
				break;
			}
			PGPPublicKey signKey = publicKeyIterator.next();

			if (!publicKeyIterator.hasNext()) {
				System.err.println("U prstenu javnog kljuca nema kljuca za enkripciju!");
				break;
			}
			PGPPublicKey encryptionKey = publicKeyIterator.next();

			long singnKeyId = signKey.getKeyID(); // this key id is used to be shown in key ring table
			// long encriptionKeyId = encryptionKey.getKeyID();

			String keyOwner = signKey.getUserIDs().next();

			Date creationDate = signKey.getCreationTime();

			String[] publicKeyRingTableRow = new String[] { creationDate.toString(), keyOwner,
					String.format("%016x", singnKeyId).toUpperCase() };

			this.publicKeyRingTableModel.addRow(publicKeyRingTableRow);
		}

	}

	private void deletePrivateKeyRing(long keyId) {
		String passphrase = JOptionPane.showInputDialog(new JFrame(),
				"Enter passphrase used to protect your private key");
		if (passphrase == null || passphrase.length() == 0) {
			JOptionPane.showMessageDialog(new JFrame(),
					"Key from private key ring collection can't be deleted without passphrase!",
					"Error - key can't be deleted", JOptionPane.ERROR_MESSAGE);
			return;
		}
		boolean ret = this.keyUtils.deletePrivateKeyRing(keyId, passphrase);
		if (!ret) {
			JOptionPane.showMessageDialog(new JFrame(), "Key isn't deletes!", "Delete error",
					JOptionPane.ERROR_MESSAGE);
		} else {
			JOptionPane.showMessageDialog(new JFrame(), "Selected key is deleted!", "Success",
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void exportPrivateKeyRing(long keyId) {
		boolean ret = keyUtils.exportPrivateKeyRing(keyId);
		if (!ret) {
			JOptionPane.showMessageDialog(new JFrame(), "Exporting key is not successful!", "Export error",
					JOptionPane.ERROR_MESSAGE);
		} else {
			JOptionPane.showMessageDialog(new JFrame(), "Exporting key is successful!", "Success",
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private void importPrivateKeyRing() {
		JFileChooser fileChooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
		fileChooser.setDialogTitle("Import file");
		fileChooser.setFileFilter(new FileNameExtensionFilter("Asc files", "asc"));
		int result = fileChooser.showOpenDialog(this);
		if (result == fileChooser.APPROVE_OPTION) {
			File selectedFile = fileChooser.getSelectedFile();

			// check extension of file

			String fileName = selectedFile.toString();
			int index = fileName.lastIndexOf('.');
			if (index > 0) {
				String extension = fileName.substring(index + 1);
				if (extension.equals("asc")) {
					OperationResult.IMPORT_OPERATION_RESULT ret = keyUtils.importPrivateKeyRing(selectedFile);
					if (ret == IMPORT_OPERATION_RESULT.SUCCESS) {
						JOptionPane.showMessageDialog(new JFrame(), "Importing file is successful!", "Success",
								JOptionPane.INFORMATION_MESSAGE);
						return;
					} else if (ret == IMPORT_OPERATION_RESULT.KEY_EXISTS) {
						
						JOptionPane.showMessageDialog(new JFrame(), "Key Ring already exists in table!", "Duplicate error",
								JOptionPane.ERROR_MESSAGE);
						return;
					}
				} else {
					JOptionPane.showMessageDialog(new JFrame(), "File extension must be asc!", "Extension error",
							JOptionPane.ERROR_MESSAGE);
					return;
				}
			}
		} else if (result != fileChooser.CANCEL_OPTION) {
			JOptionPane.showMessageDialog(new JFrame(), "Importing key is not successful!", "Import error",
					JOptionPane.ERROR_MESSAGE);
		}

	}

	public static void main(String[] args) {
		Application app = new Application();
	}
}
