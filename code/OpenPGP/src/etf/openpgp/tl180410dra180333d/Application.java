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

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

import etf.openpgp.tl180410dra180333d.keys.KeyUtils;

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
	private KeyUtils keyUtils = new KeyUtils();

	public Application() {
		this.setTitle("OpenPGP App");
		this.setSize(1080, 720);

		this.initialization();

		this.setVisible(true);
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

		JButton deletePrivateKeyRingButton = new JButton("DELETE SELECTED PRIVATE KEY RING");
		privateKeyRingPanel.add(deletePrivateKeyRingButton, BorderLayout.SOUTH);

		String[] columnLabels = { "Timestamp", "User ID", "Key ID", "Public Key", "Encrypted Private Key" };
		this.privateKeyRingTableModel = this.initialize_keyRingTable(privateKeyRingPanel, columnLabels,
				deletePrivateKeyRingButton);

		this.privateKeyRingTableModel.addRow(
				new String[] { "16/05/2022 17:04", "ralt", "ABCD-1234", "ABCD-EFGH-IJKL-MNOP-QRST", "potg4das13cxzz" });
		this.privateKeyRingTableModel.addRow(
				new String[] { "16/05/2022 17:05", "ralt", "ABCD-1234", "ABCD-EFGH-IJKL-MNOP-QRST", "potg4das13cxzz" });
		this.privateKeyRingTableModel.addRow(
				new String[] { "16/05/2022 17:06", "ralt", "ABCD-1234", "ABCD-EFGH-IJKL-MNOP-QRST", "potg4das13cxzz" });
	}

	private void initialize_publicKeyRingPanel(JPanel publicKeyRingPanel) {

		publicKeyRingPanel.setLayout(new BorderLayout());

		JButton deletePublicKeyRingButton = new JButton("DELETE SELECTED PUBLIC KEY RING");
		publicKeyRingPanel.add(deletePublicKeyRingButton, BorderLayout.SOUTH);

		String[] columnLabels = { "Timestamp", "User ID", "Key ID", "Public Key" };
		this.publicKeyRingTableModel = this.initialize_keyRingTable(publicKeyRingPanel, columnLabels,
				deletePublicKeyRingButton);

		this.publicKeyRingTableModel
				.addRow(new String[] { "16/05/2022 17:04", "ralt", "ABCD-1234", "ABCD-EFGH-IJKL-MNOP-QRST" });
		this.publicKeyRingTableModel
				.addRow(new String[] { "16/05/2022 17:05", "ralt", "ABCD-1234", "ABCD-EFGH-IJKL-MNOP-QRST" });
		this.publicKeyRingTableModel
				.addRow(new String[] { "16/05/2022 17:06", "ralt", "ABCD-1234", "ABCD-EFGH-IJKL-MNOP-QRST" });
	}

	private DefaultTableModel initialize_keyRingTable(JPanel keyRingPanel, String[] columnLabels,
			JButton deleteKeyRingButton) {

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
					keyRingTableModel.removeRow(jtKeyRingTable.getSelectedRow());
				}
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
					JOptionPane.showMessageDialog(new JFrame(), "Nije uspelo dodavanje kljuca, sva polja su obavezna!",
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
		
		
		return this.keyUtils.generatePrivateRingKey(name+" ("+ email+")", signAlgorithm, encryptionAlgorithm,"passphrase");

	}

	public static void main(String[] args) {
		Application app = new Application();
	}
}
