package etf.openpgp.tl180410dra180333d.messages;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import etf.openpgp.tl180410dra180333d.Application;

public class MessageSender {
	private Application application;
	private JComboBox<String> jcomboAutenticationKeys;
	private JList<String> jlistEncryptionKeys;

	public MessageSender(Application application) {
		this.application = application;
	}
	
	public void initializeApplicationPanel(JPanel sendMessagePanel) {
		sendMessagePanel.setLayout(new BorderLayout());

		JPanel sendMessageFormPanel = new JPanel();
		sendMessageFormPanel.setLayout(new GridLayout(7,2,5,5));
		// header 
		JLabel jlHeader = new JLabel("Send message");
		JPanel headerPanel = new JPanel();
		headerPanel.add(jlHeader);
		sendMessagePanel.add(headerPanel,BorderLayout.NORTH);
		
		
		// selection source file
		JLabel jlSourceFile = new JLabel("Choose file for sending");
		JButton jbtnSourceFile = new JButton("Choose");
		sendMessageFormPanel.add(jlSourceFile);
		sendMessageFormPanel.add(jbtnSourceFile);
		
		// selection destination
		JLabel jlDestination = new JLabel("Choose destination");
		JButton jbtnDestination = new JButton("Choose");
		sendMessageFormPanel.add(jlDestination);
		sendMessageFormPanel.add(jbtnDestination);
		
		// autentication 
		JLabel jlAutentication = new JLabel("Choose autentication key (Optional)");
		jcomboAutenticationKeys = new JComboBox<>();
		
		sendMessageFormPanel.add(jlAutentication);
		sendMessageFormPanel.add(jcomboAutenticationKeys);
				
		// keys for encryption
		JLabel jlEncryptionKeys = new JLabel("Choose encryption keys (Optional)");
		jlistEncryptionKeys = new JList<>();
		jlistEncryptionKeys.setVisibleRowCount(5);
		
		JScrollPane jscEncryptionKeys = new JScrollPane(jlistEncryptionKeys);
		
		
		sendMessageFormPanel.add(jlEncryptionKeys);
		sendMessageFormPanel.add(jscEncryptionKeys);
		
				
		// choose symmetric algorithm
		JLabel jlAlgorithm = new JLabel("Choose symmetric key algorithm");
		JComboBox<String>jcomboAlgorithm = new JComboBox<>(Application.symmetricAlgorithms);
		sendMessageFormPanel.add(jlAlgorithm);
		sendMessageFormPanel.add(jcomboAlgorithm);
		
		// radix 64 optional
		JLabel jlRadix64 = new JLabel("Do you want radix64 conversion?");
		JCheckBox jcRadix64 = new JCheckBox();
		sendMessageFormPanel.add(jlRadix64);
		sendMessageFormPanel.add(jcRadix64);
		
		JLabel jlZip = new JLabel("Do you want Zip compression?");
		JCheckBox jcZip = new JCheckBox();
		sendMessageFormPanel.add(jlZip);
		sendMessageFormPanel.add(jcZip);
		
		
		sendMessageFormPanel.setBorder(BorderFactory.createEmptyBorder(50, 150, 60, 150));

		sendMessagePanel.add(sendMessageFormPanel,BorderLayout.CENTER);
		JPanel jpButtonSend = new JPanel(new GridLayout(1,1));
		JButton jbtnSend = new JButton("Send");
		jbtnSend.setSize(sendMessagePanel.getWidth(),150);
		jbtnSend.setBackground(new Color(0x80ffbf));
		jpButtonSend.add(jbtnSend);
		
		sendMessagePanel.add(jpButtonSend,BorderLayout.SOUTH);
	}

	public JComboBox<String> getJcomboAutenticationKeys() {
		return jcomboAutenticationKeys;
	}

	public JList<String> getJlistEncryptionKeys() {
		return jlistEncryptionKeys;
	}
	
	
}
