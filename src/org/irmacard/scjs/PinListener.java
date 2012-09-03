package org.irmacard.scjs;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import org.irmacard.chvservice.IPinVerificationListener;

public class PinListener implements IPinVerificationListener {
	SmartCardJS scjs;
	
	public PinListener(SmartCardJS scjs) {
		this.scjs = scjs;
	}

	@Override
	public String userPinRequest(Integer nr_tries_left) {
		String pinText = "The server requests to authenticate your identity, enter PIN";
		
		if(nr_tries_left != null) {
			pinText += " (" + nr_tries_left + " tries left):";
		} else {
			pinText += ":";
		}
		
        String pinString = "";
        boolean valid = false;
        
		JPasswordField pinField = new JPasswordField(4);
		JLabel lab = new JLabel(pinText);

		JPanel panel = new JPanel();
		panel.setLayout(new GridBagLayout());

		GridBagConstraints cc = new GridBagConstraints();
		cc.anchor = GridBagConstraints.WEST;
		cc.insets = new Insets(10, 10, 10, 10);
		cc.gridx = 0;
		cc.gridy = 0;

		panel.add(lab, cc);
		cc.gridy++;
		panel.add(pinField, cc);
		
		while (!valid) {
			// ask for pin, inform the user
			int result = JOptionPane.showConfirmDialog(null, panel, "PIN",
					JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);

			pinString = new String(pinField.getPassword());
			
			if (result != 0) {
				// User pressed cancel;
				lab.setText("<html><font color=\"red\">Please enter a pin</font><br />"
						+ pinText + "</html>");
			} else if (pinString.length() != 4) {
				lab.setText("<html><font color=\"red\">Pin should be 4 digits</font><br />"
						+ pinText + "</html>");
			} else {
				valid = true;
			}
		}

        return pinString;
	}

	@Override
	public void pinPadPinRequired(Integer nr_tries_left) {
		scjs.emit(new Signal(scjs, "pin-pad-pin-required"));
	}

	@Override
	public void pinPadPinEntered() {
		scjs.emit(new Signal(scjs, "pin-pad-pin-entered"));
	}

}
