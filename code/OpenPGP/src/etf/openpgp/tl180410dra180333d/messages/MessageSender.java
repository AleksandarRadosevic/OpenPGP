package etf.openpgp.tl180410dra180333d.messages;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.filechooser.FileNameExtensionFilter;

import etf.openpgp.tl180410dra180333d.Application;

/**
 * Klasa za upravljanje GUI-jem slanja poruke.
 */
public class MessageSender {
	private Application application;
	private JComboBox<String> jcomboAutenticationKeys;
	private JList<String> jlistEncryptionKeys;
	private MessageSenderForm messageSenderForm;
	
	private File selectedMessageFile = null;
	private Path messageDestinationPath = null;

	/**
	 * @param Application application - aplikacija za koju pravimo gui za slanje.
	 */
	public MessageSender(Application application) {
		this.application = application;
		messageSenderForm = new MessageSenderForm(this.application);
	}
	
	/**
	 * Metoda za inicijalizaciju GUI-ja za slanje
	 * @param JPanel sendMessagePanel - panel u aplikaciji koji inicijalizujemo
	 */
	public void initializeApplicationPanel(JPanel sendMessagePanel) {
		sendMessagePanel.setLayout(new BorderLayout());

		JPanel sendMessageFormPanel = new JPanel();
		sendMessageFormPanel.setLayout(new GridLayout(9,2,5,5));
		
		// header 
		JLabel jlHeader = new JLabel("Send message");
		jlHeader.setFont(new Font("Courier", Font.BOLD, 20));
		JPanel headerPanel = new JPanel();
		headerPanel.add(jlHeader);
		sendMessagePanel.add(headerPanel,BorderLayout.NORTH);
		
		
		// selection source file
		JLabel jlSourceFile = new JLabel("Choose file for sending");
		JButton jbtnSourceFile = new JButton("Choose");
		sendMessageFormPanel.add(jlSourceFile);
		sendMessageFormPanel.add(jbtnSourceFile);
		
		// selection source file selected
		JLabel jlSourceFileSelected = new JLabel("No selected source file (required).");
		sendMessageFormPanel.add(new JLabel("Message file name: ", SwingConstants.CENTER));
		sendMessageFormPanel.add(jlSourceFileSelected);
		
		jbtnSourceFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser(Application.dataRootPath);
				fileChooser.setDialogTitle("Select message");
				int result = fileChooser.showOpenDialog(application);
				if (result == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fileChooser.getSelectedFile();
					messageSenderForm.setSourceFile(fileChooser.getSelectedFile());
					String selectedMessageFilePath = selectedFile.getAbsolutePath();
					jlSourceFileSelected.setText(selectedFile.getName());
				}
			}
		});
		

		
		// selection destination
		JLabel jlDestination = new JLabel("Choose destination");
		JButton jbtnDestination = new JButton("Choose");
		sendMessageFormPanel.add(jlDestination);
		sendMessageFormPanel.add(jbtnDestination);
		
		// selected destination path
		JLabel jlDestinationSelected = new JLabel("No selected destination (required).");
		sendMessageFormPanel.add(new JLabel("Selected destination: ", SwingConstants.CENTER));
		sendMessageFormPanel.add(jlDestinationSelected);
		
		jbtnDestination.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Path path = MessageSender.this.selectDestinationDialog();
				jlDestinationSelected.setText(path.toString());
				messageSenderForm.setDestinationPath(path.toString());
			}
		});
		
		// autentication 
		JLabel jlAutentication = new JLabel("Choose autentication key");
		jcomboAutenticationKeys = new JComboBox<>();
		
		sendMessageFormPanel.add(jlAutentication);
		sendMessageFormPanel.add(jcomboAutenticationKeys);
				
		
		// keys for session key encryption
		JLabel jlEncryptionKeys = new JLabel("Choose encryption keys (required if encryption algorithm is selected)");
		jlistEncryptionKeys = new JList<>();
		jlistEncryptionKeys.setVisibleRowCount(5);
		jlistEncryptionKeys.setEnabled(false);
		
		JScrollPane jscEncryptionKeys = new JScrollPane(jlistEncryptionKeys);
		// added to panel after symmetric algorithm selection
		
		// choose symmetric algorithm
		JLabel jlAlgorithm = new JLabel("Choose symmetric key algorithm for encryption (Optional)");
		String [] symmetricAlgorithms = new String[Application.symmetricAlgorithms.length+1];
		System.arraycopy(new String[] {null}, 0, symmetricAlgorithms, 0, 1);
	    System.arraycopy(Application.symmetricAlgorithms, 0, symmetricAlgorithms, 1, Application.symmetricAlgorithms.length);
		JComboBox<String>jcomboAlgorithm = new JComboBox<>(symmetricAlgorithms);
		
		
		jcomboAlgorithm.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				String selectedSymmetricAlgorithm = (String) jcomboAlgorithm.getSelectedItem();
				if(selectedSymmetricAlgorithm==null) {
					jlistEncryptionKeys.clearSelection();
					jlistEncryptionKeys.setEnabled(false);
				}
				else {
					jlistEncryptionKeys.setEnabled(true);
				}
			}
		});

		sendMessageFormPanel.add(jlAlgorithm);
		sendMessageFormPanel.add(jcomboAlgorithm);
		
		sendMessageFormPanel.add(jlEncryptionKeys);
		sendMessageFormPanel.add(jscEncryptionKeys);
		
		// radix 64 optional
		JLabel jlRadix64 = new JLabel("Do you want radix64 conversion?");
		JCheckBox jcRadix64 = new JCheckBox("(Optional)");
		sendMessageFormPanel.add(jlRadix64);
		sendMessageFormPanel.add(jcRadix64);
		
		JLabel jlZip = new JLabel("Do you want Zip compression?");
		JCheckBox jcZip = new JCheckBox("(Optional)");
		sendMessageFormPanel.add(jlZip);
		sendMessageFormPanel.add(jcZip);
		
		
		sendMessageFormPanel.setBorder(BorderFactory.createEmptyBorder(50, 130, 60, 130));

		sendMessagePanel.add(sendMessageFormPanel,BorderLayout.CENTER);
		JPanel jpControlsSendMessageForm = new JPanel(new GridLayout(1,2));
		
		JButton jbtnCancel = new JButton("Cancel");
		jbtnCancel.setBackground(new Color(0xff6666));
		jpControlsSendMessageForm.add(jbtnCancel);
		
		JButton jbtnSend = new JButton("Send");
		jbtnSend.setBackground(new Color(0x80ffbf));
		jpControlsSendMessageForm.add(jbtnSend);
		
		sendMessagePanel.add(jpControlsSendMessageForm,BorderLayout.SOUTH);
		
		jbtnSend.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				messageSenderForm.setAuthenticationKey((String) jcomboAutenticationKeys.getSelectedItem());	
				messageSenderForm.setEncryptionKeys(new Vector<>(jlistEncryptionKeys.getSelectedValuesList()));
				messageSenderForm.setSymmetricKeyAlgorithm((String) jcomboAlgorithm.getSelectedItem());
				messageSenderForm.setRadix64(jcRadix64.isSelected());
				messageSenderForm.setZip(jcZip.isSelected());
				String sendMessageError = messageSenderForm.sendMessage();
				if (sendMessageError!=null) {
					JOptionPane.showMessageDialog(application,
							sendMessageError,
							"Error - Send operation failed", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		
		jbtnCancel.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				jlSourceFileSelected.setText("No selected source file (required).");
				jlDestinationSelected.setText("No selected destination (required).");
				jcomboAutenticationKeys.setSelectedIndex(0);
				jcomboAlgorithm.setSelectedIndex(0);
				jlistEncryptionKeys.clearSelection();
				jcRadix64.setSelected(false);
				jcZip.setSelected(false);
				messageSenderForm = new MessageSenderForm(MessageSender.this.application);
			}
		});
	}
	
	/**
	 * Metoda za dohvatanje combobox-a koji sadrzi kljuceve za autentikaciju
	 * @return combobox koji sadrzi kljuceve za autentikaciju
	 */
	public JComboBox<String> getJcomboAutenticationKeys() {
		return jcomboAutenticationKeys;
	}

	/**
	 * Metoda za dohvatanje JList-e koja sadrzi kljuceve za sifrovanje kljuca sesije
	 * @return JList-a koja sadrzi kljuceve za sifrovanje kljuca sesije
	 */
	public JList<String> getJlistEncryptionKeys() {
		return jlistEncryptionKeys;
	}
	
	
	private Path selectDestinationDialog() {
		JFileChooser choose_where_to_export = new JFileChooser(Application.dataRootPath);
		choose_where_to_export.setDialogTitle("Select message destination");
		choose_where_to_export.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		int ret = choose_where_to_export.showDialog(this.application, "Save");
		if (ret == JFileChooser.APPROVE_OPTION) {
			Path path = Paths.get(choose_where_to_export.getSelectedFile().getAbsolutePath());
			return path;
		}
		return null;
	}
	
	
}
