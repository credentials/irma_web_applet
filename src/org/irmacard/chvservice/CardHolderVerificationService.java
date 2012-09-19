/* 
 * This file is part of the SCUBA smart card framework.
 * 
 * SCUBA is free software: you can redistribute it and/or modify it under the 
 * terms of the GNU General Public License as published by the Free Software 
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 * 
 * SCUBA is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more 
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * SCUBA. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Inspired by the work of Clemens Orthacker (clemens.orthacker@iaik.tugraz.at)
 * for MOCCA (Modular Open Citizen Card Architecture, released under the 
 * Apache 2.0 license).
 *
 * Copyright (C) 2012 The SCUBA team.
 * 
 * $Id: CardHolderVerificationService.java 184 2012-09-04 21:17:15Z pimvullers $
 */

package org.irmacard.chvservice;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Vector;

import net.sourceforge.scuba.util.Hex;

import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.CommandAPDU;
import net.sourceforge.scuba.smartcards.ICommandAPDU;
import net.sourceforge.scuba.smartcards.IResponseAPDU;
import net.sourceforge.scuba.smartcards.ResponseAPDU;
import net.sourceforge.scuba.smartcards.TerminalCardService;

/**
 * CardService which provides functionality to perform card holder verification
 * based on PIN codes.
 * 
 * @author Pim Vullers (p.vullers@cs.ru.nl)
 * @author Wouter Lueks (w.lueks@cs.ru.nl)
 * 
 * @version $Revision: 184 $
 */
public class CardHolderVerificationService extends CardService {

	private static final long serialVersionUID = -7992986822145276115L;

	public static final int PIN_ENTRY_POLLING_INTERVAL = 10;
	public static final int PIN_OK = 1000;

	protected static final String[] FEATURES = new String[]{
		"NO_FEATURE",
		"FEATURE_VERIFY_PIN_START",
		"FEATURE_VERIFY_PIN_FINISH",
		"FEATURE_MODIFY_PIN_START",
		"FEATURE_MODIFY_PIN_FINISH",
		"FEATURE_GET_KEY_PRESSED",
		"FEATURE_VERIFY_PIN_DIRECT",
		"FEATURE_MODIFY_PIN_DIRECT",
		"FEATURE_MCT_READER_DIRECT",
		"FEATURE_MCT_UNIVERSAL",
		"FEATURE_IFD_PIN_PROPERTIES",
		"FEATURE_ABORT",
		"FEATURE_SET_SPE_MESSAGE",
		"FEATURE_VERIFY_PIN_DIRECT_APP_ID",
		"FEATURE_MODIFY_PIN_DIRECT_APP_ID",
		"FEATURE_WRITE_DISPLAY",
		"FEATURE_GET_KEY",
		"FEATURE_IFD_DISPLAY_PROPERTIES",
		"FEATURE_GET_TLV_PROPERTIES",
		"FEATURE_CCID_ESC_COMMAND"
	};

	protected static final Byte FEATURE_VERIFY_PIN_START = new Byte((byte) 0x01);
	protected static final Byte FEATURE_VERIFY_PIN_FINISH = new Byte((byte) 0x02);
	protected static final Byte FEATURE_MODIFY_PIN_START = new Byte((byte) 0x03);
	protected static final Byte FEATURE_MODIFY_PIN_FINISH = new Byte((byte) 0x04);
	protected static final Byte FEATURE_GET_KEY_PRESSED = new Byte((byte) 0x05);
	protected static final Byte FEATURE_VERIFY_PIN_DIRECT = new Byte((byte) 0x06);
	protected static final Byte FEATURE_MODIFY_PIN_DIRECT = new Byte((byte) 0x07);
	protected static final Byte FEATURE_MCT_READER_DIRECT = new Byte((byte) 0x08);
	protected static final Byte FEATURE_MCT_UNIVERSAL = new Byte((byte) 0x09);
	protected static final Byte FEATURE_IFD_PIN_PROPERTIES = new Byte((byte) 0x0a);
	protected static final Byte FEATURE_ABORT = new Byte((byte) 0x0b);
	protected static final Byte FEATURE_SET_SPE_MESSAGE = new Byte((byte) 0x0c);
	protected static final Byte FEATURE_VERIFY_PIN_DIRECT_APP_ID = new Byte((byte) 0x0d);
	protected static final Byte FEATURE_MODIFY_PIN_DIRECT_APP_ID = new Byte((byte) 0x0e);
	protected static final Byte FEATURE_WRITE_DISPLAY = new Byte((byte) 0x0f);
	protected static final Byte FEATURE_GET_KEY = new Byte((byte) 0x10);
	protected static final Byte FEATURE_IFD_DISPLAY_PROPERTIES = new Byte((byte) 0x11);
	protected static final Byte FEATURE_GET_TLV_PROPERTIES = new Byte((byte) 0x12);
	protected static final Byte FEATURE_CCID_ESC_COMMAND = new Byte((byte) 0x13);

    protected byte bEntryValidationCondition = 0x02;  // validation key pressed
    protected byte bTimeOut = 0x3c;                   // 60sec (= max on ReinerSCT)
    protected byte bTimeOut2 = 0x00;                  // default (attention with SCM)
    protected byte wPINMaxExtraDigitMin = 0x00;       // min pin length zero digits
    protected byte wPINMaxExtraDigitMax = 0x04;       // max pin length 12 digits
    protected byte bInsertionOffsetOld = 0x00;        // Insertion position offset in bytes for the current PIN (beginning of APDU data)
    protected byte bInsertionOffsetNew = wPINMaxExtraDigitMax; // Insertion position offset in bytes for the new PIN (after max length of first pin)
    protected byte bNumberMessage = 0x01;
    protected byte bConfirmPIN = 0x03;
    
	/**
	 * supported features and respective control codes
	 */
	protected HashMap<Byte, Integer> features;
	protected boolean VERIFY = false;
	protected boolean VERIFY_DIRECT = false;
	protected boolean MODIFY = false;
	protected boolean MODIFY_DIRECT = false;

    private TerminalCardService service;
	private List<IPinVerificationListener> pinCallbacks = new Vector<IPinVerificationListener>();
	
	/* Invariant: when no false PIN was entered in the last attempt
	 * value is null. Otherwise equal to the number of tries left.
	 */
	private Integer nrTriesLeft = null;

	public CardHolderVerificationService(TerminalCardService service) {
		this.service = service;
		queryFeatures();
		if (VERIFY || VERIFY_DIRECT || MODIFY || MODIFY_DIRECT) {
			setupReader();
		}
	}

	/**
	 * Adds a new listener
	 * @param cb The listener to add
	 */
	public void addPinVerificationListener(IPinVerificationListener cb) {
		pinCallbacks.add(cb);
	}

	/**
	 * Removes a listener
	 * @param cb The listener to remove
	 */
	public void removePinVerificationListener(IPinVerificationListener cb) {
		pinCallbacks.remove(cb);
	}

	public void open() throws CardServiceException {
		service.open();
	}

	public boolean isOpen() {
		return service.isOpen();
	}

	public IResponseAPDU transmit(ICommandAPDU capdu)
	throws CardServiceException {
		return service.transmit(capdu);
	}

	public void close() {
		service.close();
	}

    public IResponseAPDU verify()
    throws CardServiceException {
    	
    	while (true) {
    		IResponseAPDU response = null;
    		if (VERIFY || VERIFY_DIRECT) {
    			response = verifyPinUsingPinpad();
    		} else {
    			response = verifyPinUsingDialog();
    		}

    		if (response.getSW() == 0x9000) {
    			nrTriesLeft = null;    		
    			return response;
    		} else if ((response.getSW() & 0xFFF0) == 0x63C0) {
    			nrTriesLeft = response.getSW() & 0x000F;
    			if (nrTriesLeft > 0) {
    				continue;
    			}
    		}

    		processResponseAPDU(response);
    	}
    }

    private void processResponseAPDU(IResponseAPDU response)
    throws CardServiceException {
		String msg;
		switch (response.getSW()) {
			case 0x6400:
				msg = "SPE operation timed out.";
				break;
			case 0x6401:
				msg = "SPE operation was cancelled by the 'Cancel' button.";
				break;
			case 0x6403:
				msg = "User entered too short or too long PIN regarding MIN/MAX PIN length.";
	    		break;
			case 0x6480:
				msg = "SPE operation was aborted by the 'Cancel' operation at the host system.";
	    		break;
			case 0x6b80:
				msg = "Invalid parameter in passed structure.";
				break;
			case 0x63C0:
				msg = "No more tries left.";
    		default:
    			msg = "Unknown error.";
    			break;
		}
		
		throw new CardServiceException("PIN verification failed: " + Hex.toHexString(response.getBytes()) + "(" + msg + ")");
    }
    
    private IResponseAPDU verifyPinUsingDialog()
    throws CardServiceException {
    	String pinString = null;

		for (IPinVerificationListener l : pinCallbacks) {
			pinString = l.userPinRequest(nrTriesLeft);
		}
        
        return service.transmit(
        		new CommandAPDU(0, 0x20, 0, 0, pinString.getBytes()));
    }

    private IResponseAPDU verifyPinUsingPinpad() 
    throws CardServiceException {
    	byte[] PIN_VERIFY = createPINVerifyStructure();

        IResponseAPDU response = null;
        if (VERIFY_DIRECT) {
    		for (IPinVerificationListener l : pinCallbacks) {
    			l.pinPadPinRequired(nrTriesLeft);
    		}

            response = VERIFY_PIN_DIRECT(PIN_VERIFY);
            
    		for (IPinVerificationListener l : pinCallbacks) {
    			l.pinPadPinEntered();
    		}
        } else {
        	response = verifyPin(PIN_VERIFY);
        } 

		return response;
    }

    public IResponseAPDU modify()
    throws CardServiceException {
    	
    	while (true) {
    		IResponseAPDU response = null;
    		if (MODIFY || MODIFY_DIRECT) {
    			response = modifyPinUsingPinpad();
    		} else {
    			response = modifyPinUsingDialog();
    		}

    		if (response.getSW() == 0x9000) {
    			nrTriesLeft = null;    		
    			return response;
    		} else if ((response.getSW() & 0xFFF0) == 0x63C0) {
    			nrTriesLeft = response.getSW() & 0x000F;
    			if (nrTriesLeft > 0) {
    				continue;
    			}
    		}
    		
    		processResponseAPDU(response);
    	}
    }

    private IResponseAPDU modifyPinUsingDialog()
    throws CardServiceException {
    	byte[] pinOld = null, pinNew = null;

		for (IPinVerificationListener l : pinCallbacks) {
			// TODO: fix for pin modification
			pinOld = l.userPinRequest(nrTriesLeft).getBytes();
			pinNew = l.userPinRequest(null).getBytes();
		}
        
		byte[] pinData = new byte[pinOld.length + pinNew.length];
		System.arraycopy(pinOld, 0, pinData, 0, pinOld.length);
		System.arraycopy(pinNew, 0, pinData, pinOld.length, pinNew.length);
        return service.transmit(new CommandAPDU(0, 0x24, 0, 0, pinData));
    }

    public IResponseAPDU modifyPinUsingPinpad()
    throws CardServiceException {
        byte[] PIN_MODIFY = createPINModifyStructure();
      
        IResponseAPDU response = null;
        if (MODIFY_DIRECT) {
        	for (IPinVerificationListener l : pinCallbacks) {
        		l.pinPadPinRequired(nrTriesLeft);
        	}

        	response = MODIFY_PIN_DIRECT(PIN_MODIFY);
        
        	for (IPinVerificationListener l : pinCallbacks) {
        		l.pinPadPinEntered();
        	}
        } else {
        	response = modifyPin(PIN_MODIFY);
        }
        
        return response;
    }


    private static int SCARD_CTL_CODE(int code) {
        int ioctl;
        String os_name = System.getProperty("os.name").toLowerCase();
        if (os_name.indexOf("windows") > -1) {
            ioctl = (0x31 << 16 | (code) << 2);
        } else {
            ioctl = 0x42000000 + (code);
        }
        return ioctl;
    }

    static int IOCTL_GET_FEATURE_REQUEST = SCARD_CTL_CODE(3400);

    protected void setupReader() {

        String name = service.getTerminal().getName().toLowerCase();
        if (name != null) {
          name = name.toLowerCase();
          //ReinerSCT: http://support.reiner-sct.de/downloads/LINUX
          //           http://www.linux-club.de/viewtopic.php?f=61&t=101287&start=0
          //old: REINER SCT CyberJack 00 00
          //new (CCID): 0C4B/0300 Reiner-SCT cyberJack pinpad(a) 00 00
          //Snow Leopard: Reiner-SCT cyberJack pinpad(a) 00 00
          //display: REINER SCT CyberJack 00 00
          if(name.startsWith("gemplus gempc pinpad") || name.startsWith("gemalto gempc pinpad")) {
              // win7(microsoft driver) GemPlus USB GemPC Pinpad Smartcardreader 0 -> no pinpad
              // win7(gemalto4.0.7.5) Gemalto GemPC Pinpad USB Smart Card Read 0 -> transmitControlCommand failed (0x7a)
              //     (same with timeouts set to 0000 and 3c0f)
              // winXP (verify failed, sw=d2(ecard) sw=92(acos), cf. wiki):
              // winXP (without setting wPINMax: sw=6b:80)
              // linux (ok): Gemplus GemPC Pinpad 00 00
              /*
               * Gemplus Pinpad - VERIFY_PIN_DIRECT (42330006)
               * [00:00:89:47:04:0c:00
               * :02:01:09:04:00:00:00:00:0d:00:00:00:00:20:00
               * :01:08:20:ff:ff:ff:ff:ff:ff:ff] Linux(?):
               * transmitControlCommand() failed:
               * sun.security.smartcardio.PCSCException: SCARD_E_NOT_TRANSACTED
               * Win7: [6b:80] - VERIFY_PIN_DIRECT (42330006)
               * [00:00:89:47:04:08:04
               * :02:01:09:04:00:00:00:00:0d:00:00:00:00:20:00
               * :01:08:20:ff:ff:ff:ff:ff:ff:ff] Linux(?): response [64:00]
               * (18154msec) Win7 (mit bTimeOut 0x3c): [00:40:02:90:00:d2]
               */
            if (System.getProperty("os.name").toLowerCase().contains("windows")) {
//                  log.trace("Disabling direct pin entry as workaround for Windows");
              VERIFY_DIRECT = false;
              MODIFY_DIRECT = false;
            }
//                log.trace("Setting custom wPINMaxExtraDigitH (0x04) for {}.", name);
            wPINMaxExtraDigitMin = 0x04;
//                log.trace("Setting custom wPINMaxExtraDigitL (0x08) for {}.", name);
            wPINMaxExtraDigitMax = 0x08;
          } else if (name.startsWith("omnikey cardman 3621")) {
//                log.trace("Setting custom wPINMaxExtraDigitH (0x01) for {}.", name);
            wPINMaxExtraDigitMin = 0x01;
          } else if (name.startsWith("scm spr 532") || name.startsWith("scm microsystems inc. sprx32 usb smart card reader")) {
//                log.trace("Setting custom bTimeOut (0x3c) for {}.", name);
            bTimeOut = 0x3c;
//                log.trace("Setting custom bTimeOut2 (0x0f) for {}.", name);
            bTimeOut2 = 0x0f;
            // SCM SPR 532 (60200DC5) 00 00
            /*
             * VERIFY_PIN_DIRECT (42330006)
             * [00:00:89:47:04:0c:00:02:01:09:04:00:
             * 00:00:00:0d:00:00:00:00:20:00:01:08:20:ff:ff:ff:ff:ff:ff:ff]
             * transmitControlCommand() failed:
             * sun.security.smartcardio.PCSCException: SCARD_E_NOT_TRANSACTED
             * VERIFY_PIN_DIRECT (42330006)
             * [00:00:89:47:04:0c:01:02:01:09:04:00:
             * 00:00:00:0d:00:00:00:00:20:00:01:08:20:ff:ff:ff:ff:ff:ff:ff]
             * response [64:00] (15543msec)
             */
            if (System.getProperty("os.name").toLowerCase().indexOf("windows") < 0) {
                wPINMaxExtraDigitMin = 0x01;
            }
        } else if (name.startsWith("cherry smartboard xx44")) {
//                log.trace("Setting custom wPINMaxExtraDigitH (0x01) for {}.", name);
            wPINMaxExtraDigitMin = 0x01;
            if (System.getProperty("os.name").toLowerCase().indexOf("windows") < 0) {
                wPINMaxExtraDigitMin = 0x01;
            }
          } else if (name.startsWith("cherry gmbh smartterminal st-2xxx")) {
            // Win: Cherry GmbH SmartTerminal ST-2xxx 0
            // Linux(?): Cherry SmartTerminal ST-2XXX (21121010102014) 00 00
//                log.trace("Setting custom bTimeOut (0x3c) for {}.", name);
            bTimeOut = 0x3c;
//                log.trace("Setting custom bTimeOut2 (0x0f) for {}.", name);
            bTimeOut2 = 0x0f;
            // Cherry SmartTerminal ST-2XXX (21121010102014) 00 00
            /*
             * VERIFY_PIN_DIRECT (42330006)
             * [00:00:89:47:04:0c:00:02:01:09:04:00:
             * 00:00:00:0d:00:00:00:00:20:00:01:08:20:ff:ff:ff:ff:ff:ff:ff]
             * transmitControlCommand() failed:
             * sun.security.smartcardio.PCSCException: SCARD_E_NOT_TRANSACTED
             * VERIFY_PIN_DIRECT (42330006)
             * [00:00:89:47:04:0c:01:02:01:09:04:00:
             * 00:00:00:0d:00:00:00:00:20:00:01:08:20:ff:ff:ff:ff:ff:ff:ff]
             * response [64:00] (15358msec)
             */
            if (System.getProperty("os.name").toLowerCase().indexOf("windows") < 0) {
                wPINMaxExtraDigitMin = 0x01;
            }
          }
        }
    }

	protected void queryFeatures() {
		features = new HashMap<Byte, Integer>();

		try {
			byte[] response = service.transmitControlCommand(
					IOCTL_GET_FEATURE_REQUEST, new byte[0]);

			for (int i = 0; i < response.length; i += 6) {
				Byte feature = new Byte(response[i]);
				Integer ioctl = new Integer((0xff & response[i + 2]) << 24)
						| ((0xff & response[i + 3]) << 16)
						| ((0xff & response[i + 4]) << 8) 
						| (0xff & response[i + 5]);
				features.put(feature, ioctl);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
        if (features.containsKey(FEATURE_VERIFY_PIN_START) &&
            features.containsKey(FEATURE_GET_KEY_PRESSED) &&
            features.containsKey(FEATURE_VERIFY_PIN_FINISH)) {
        	VERIFY = true;
        }
        if (features.containsKey(FEATURE_MODIFY_PIN_START) &&
            features.containsKey(FEATURE_GET_KEY_PRESSED) &&
            features.containsKey(FEATURE_MODIFY_PIN_FINISH)) {
        	MODIFY = true;
        }
        if (features.containsKey(FEATURE_VERIFY_PIN_DIRECT)) {
        	VERIFY_DIRECT = true;
        }
        if (features.containsKey(FEATURE_MODIFY_PIN_DIRECT)) {
        	MODIFY_DIRECT = true;
        }
	}

	private IResponseAPDU VERIFY_PIN_DIRECT(byte[] PIN_VERIFY) 
	throws CardServiceException {
		int ioctl = features.get(FEATURE_VERIFY_PIN_DIRECT);
	    return new ResponseAPDU(
	    		service.transmitControlCommand(ioctl, PIN_VERIFY));
	}
	
	private void VERIFY_PIN_START(byte[] PIN_VERIFY) 
	throws CardServiceException {
	    int ioctl = features.get(FEATURE_VERIFY_PIN_START);
	    byte[] response = service.transmitControlCommand(ioctl, PIN_VERIFY);
	    if (response != null && response.length > 0) {
	    	if (response[0] == (byte) 0x57) {
	    		throw new CardServiceException("Invalid parameter in PIN_VERIFY structure.");
	    	} else {
	    		throw new CardServiceException("Unexpected response to VERIFY_PIN_START: " + Hex.toHexString(response));
	    	}
	    }
	}
	
	private byte GET_KEY_PRESSED() 
	throws CardServiceException {
	    int ioctl = features.get(FEATURE_GET_KEY_PRESSED);
	    byte[] response = service.transmitControlCommand(ioctl, new byte[0]);
	    if (response != null && response.length == 1) {
	    	return response[0];
	    }

	    throw new CardServiceException("Unexpected response to GET_KEY_PRESSED: " + Hex.toHexString(response));
	}
	
	private IResponseAPDU VERIFY_PIN_FINISH() 
	throws CardServiceException {
		int ioctl = features.get(FEATURE_VERIFY_PIN_FINISH);
		byte[] resp = service.transmitControlCommand(ioctl, new byte[0]);
		if (resp != null && resp.length == 2) {
		  return new ResponseAPDU(resp);
		}
		
		throw new CardServiceException("Unexpected response to VERIFY_PIN_FINISH: " + Hex.toHexString(resp));
	}

	private IResponseAPDU verifyPin(byte[] PIN_VERIFY) 
	throws CardServiceException {
	    VERIFY_PIN_START(PIN_VERIFY);

	    byte resp;
	    do {
	      resp = GET_KEY_PRESSED();
	      if (resp == (byte) 0x00) {
	        synchronized(this) {
	          try {
	            wait(PIN_ENTRY_POLLING_INTERVAL);
	          } catch (InterruptedException ex) {
//	            log.error("interrupted in VERIFY_PIN");
	          }
	        }
	      } else if (resp == (byte) 0x0d) {
//	        log.trace("GET_KEY_PRESSED: 0x0d (user confirmed)");
	        break;
	      } else if (resp == (byte) 0x2b) {
//	        log.trace("GET_KEY_PRESSED: 0x2b (user entered valid key 0-9)");
//	        pinGUI.validKeyPressed();
	      } else if (resp == (byte) 0x1b) {
//	        log.trace("GET_KEY_PRESSED: 0x1b (user cancelled VERIFY_PIN via cancel button)");
	        break; // returns 0x6401
	      } else if (resp == (byte) 0x08) {
//	        log.trace("GET_KEY_PRESSED: 0x08 (user pressed correction/backspace button)");
//	        pinGUI.correctionButtonPressed();
	      } else if (resp == (byte) 0x0e) {
//	        log.trace("GET_KEY_PRESSED: 0x0e (timeout occured)");
	        break; // return 0x6400
	      } else if (resp == (byte) 0x40) {
//	        log.trace("GET_KEY_PRESSED: 0x40 (PIN_Operation_Aborted)");
	        throw new CardServiceException("PIN_Operation_Aborted (0x40)");
	      } else if (resp == (byte) 0x0a) {
//	        log.trace("GET_KEY_PRESSED: 0x0a (all keys cleared");
//	        pinGUI.allKeysCleared();
	      } else {
	        throw new CardServiceException("Unexpected response to GET_KEY_PRESSED: " + Integer.toHexString(resp));
	      }
	    } while (true);

	    return VERIFY_PIN_FINISH();
	  }

	private IResponseAPDU MODIFY_PIN_DIRECT(byte[] PIN_MODIFY)
	throws CardServiceException {
		int ioctl = features.get(FEATURE_MODIFY_PIN_DIRECT);
		return new ResponseAPDU(
				service.transmitControlCommand(ioctl, PIN_MODIFY));
	}

	private void MODIFY_PIN_START(byte[] PIN_MODIFY)
	throws CardServiceException {

		int ioctl = features.get(FEATURE_MODIFY_PIN_START);
		byte[] response = service.transmitControlCommand(ioctl, PIN_MODIFY);
		if (response != null && response.length > 0) {
			if (response[0] == (byte) 0x57) {
		        throw new CardServiceException(
		        		"Invalid parameter in PIN_MODIFY structure.");
		    } else {
		        throw new CardServiceException(
		        		"Unexpected response to MODIFY_PIN_START: " + 
		        			Hex.toHexString(response));
		    }
		}
	}

	private IResponseAPDU MODIFY_PIN_FINISH()
	throws CardServiceException {
		int ioctl = features.get(FEATURE_MODIFY_PIN_FINISH);
		byte[] response = service.transmitControlCommand(ioctl, new byte[0]);
	    if (response != null && response.length == 2) {
	      return new ResponseAPDU(response);
	    }
	    throw new CardServiceException(
	    		"Unexpected response to MODIFY_PIN_FINISH: " +
	    			Hex.toHexString(response));
	}

	/**
	 * does not display the first pin dialog (enterCurrentPIN or enterNewPIN, depends on bConfirmPIN),
	 * since this is easier to do in calling modify()
	 */
	private IResponseAPDU modifyPin(byte[] PIN_MODIFY) 
	throws CardServiceException {

		byte pinConfirmations = (byte) 0x00; //b0: new pin not entered (0) / entered (1)
											 //b1: current pin not entered (0) / entered (1)
		byte bConfirmPIN = PIN_MODIFY[9];

		MODIFY_PIN_START(PIN_MODIFY);

		byte resp;
		while (true) {
			resp = GET_KEY_PRESSED();
			if (resp == (byte) 0x00) {
				synchronized(this) {
					try {
						wait(PIN_ENTRY_POLLING_INTERVAL);
					} catch (InterruptedException ex) {}
				}
			} else if (resp == (byte) 0x0d) {			
//				log.debug("GET_KEY_PRESSED: 0x0d (user confirmed)");
				if (pinConfirmations == bConfirmPIN) {
					break;
				} else if ((bConfirmPIN & (byte) 0x02) == 0 ||
						(pinConfirmations & (byte) 0x02) == (byte) 0x02) {
					// no current pin entry or current pin entry already performed
					if ((pinConfirmations & (byte) 0x01) == 0) {
						// new pin
						pinConfirmations |= (byte) 0x01;
//						pinGUI.confirmNewPIN(pINSpec);
					} // else: new pin confirmed
				} else {
					// current pin entry
					pinConfirmations |= (byte) 0x02;
//					pinGUI.enterNewPIN(pINSpec);
				}
			} else if (resp == (byte) 0x2b) {
//		        log.trace("GET_KEY_PRESSED: 0x2b (user entered valid key 0-9)");
//				pinGUI.validKeyPressed();
			} else if (resp == (byte) 0x1b) {
//		        log.trace("GET_KEY_PRESSED: 0x1b (user cancelled VERIFY_PIN via cancel button)");
				break; // returns 0x6401
			} else if (resp == (byte) 0x08) {
//		        log.trace("GET_KEY_PRESSED: 0x08 (user pressed correction/backspace button)");
//				pinGUI.correctionButtonPressed();
			} else if (resp == (byte) 0x0e) {
//		        log.trace("GET_KEY_PRESSED: 0x0e (timeout occured)");
				break; // return 0x6400
			} else if (resp == (byte) 0x40) {
//		        log.trace("GET_KEY_PRESSED: 0x40 (PIN_Operation_Aborted)");
				throw new CardServiceException("PIN_Operation_Aborted (0x40)");
			} else if (resp == (byte) 0x0a) {
//		        log.trace("GET_KEY_PRESSED: 0x0a (all keys cleared");
//				pinGUI.allKeysCleared();
			} else {
				throw new CardServiceException("Unexpected response to GET_KEY_PRESSED: " + Integer.toHexString(resp));
			}
		}

//		pinGUI.finish();
		
		return MODIFY_PIN_FINISH();
	}

    protected byte[] createPINVerifyStructure() {

        // VerifyAPDUSpec apduSpec = new VerifyAPDUSpec(
        byte[] apdu = new byte[] { (byte) 0x00, (byte) 0x20, (byte) 0x00,
                (byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00 };
        // 1, VerifyAPDUSpec.PIN_FORMAT_BCD, 7, 4, 4);

        ByteArrayOutputStream s = new ByteArrayOutputStream();
        // bTimeOut
        s.write(bTimeOut);
        // bTimeOut2
        s.write(bTimeOut2);
        // bmFormatString [10001001 0x89]
        s.write(0x82);
//        s.write(1 << 7 // system unit = byte
//                | (0xF & 1) << 3 // apduSpec.getPinPosition() (0001 ... pin 1
//                                 // byte after format)
//                | (0x1 & 0 << 2) // apduSpec.getPinJustification() (0 ... left
//                                 // justify)
//                | (0x3 & 1)); // apduSpec.getPinFormat() (01 ... BCD)
        // bmPINBlockString [01000111 0x47]
        s.write(0x04);
//        s.write((0xF & 4) << 4 // apduSpec.getPinLengthSize() (0100 ... 4 bit
//                               // pin length)
//                | (0xF & 7)); // apduSpec.getPinLength() (0111 ... 7 bytes pin
//                              // block size)
        // bmPINLengthFormat [00000100 0x04]
        s.write(0x00);
//        s.write(// system unit = bit
//        (0xF & 4)); // apduSpec.getPinLengthPos() (00000100 ... pin length
//                    // position 4 bits)
        // wPINMaxExtraDigit (little endian) [0x0c 0x00]
        s.write(wPINMaxExtraDigitMax); // max PIN length
        s.write(wPINMaxExtraDigitMin); // min PIN length
        // bEntryValidationCondition [0x02]
        s.write(bEntryValidationCondition);
        // bNumberMessage
        s.write(0x01);
        // wLangId [0x04 0x09 english, little endian]
        s.write(0x04);
        s.write(0x09);
        // bMsgIndex
        s.write(0x01);
        // bTeoPrologue
        s.write(0x00);
        s.write(0x00);
        s.write(0x00);
        // ulDataLength
        s.write(apdu.length);
        s.write(0x00);
        s.write(0x00);
        s.write(0x00);
        // abData
        try {
            s.write(apdu);
        } catch (IOException e) {
            // As we are dealing with ByteArrayOutputStreams no exception is to
            // be
            // expected.
            throw new RuntimeException(e);
        }

        return s.toByteArray();
    }

    protected byte[] createPINModifyStructure() {

        byte[] apdu = new byte[] { (byte) 0x00, (byte) 0x24, (byte) 0x00,
                (byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00 };

        ByteArrayOutputStream s = new ByteArrayOutputStream();
        s.write(bTimeOut);
        s.write(bTimeOut2);
        // bmFormatString [10001001 0x89]
        s.write(0x82);
//        s.write(1 << 7 // system unit = byte
//                | (0xF & 1) << 3 // apduSpec.getPinPosition() (0001 ... pin 1
//                                 // byte after format)
//                | (0x1 & 0 << 2) // apduSpec.getPinJustification() (0 ... left
//                                 // justify)
//                | (0x3 & 1)); // apduSpec.getPinFormat() (01 ... BCD)
        // bmPINBlockString [01000111 0x47]
        s.write(0x04);
//        s.write((0xF & 4) << 4 // apduSpec.getPinLengthSize() (0100 ... 4 bit
//                               // pin length)
//                | (0xF & 7)); // apduSpec.getPinLength() (0111 ... 7 bytes pin
//                              // block size)
        // bmPINLengthFormat [00000100 0x04]
        s.write(0x00);
        s.write(bInsertionOffsetOld);
        s.write(bInsertionOffsetNew);
//        s.write(// system unit = bit
//        (0xF & 4)); // apduSpec.getPinLengthPos() (00000100 ... pin length
//                    // position 4 bits)
        // wPINMaxExtraDigit (little endian) [0x0c 0x00]
        s.write(wPINMaxExtraDigitMax); // max PIN length
        s.write(wPINMaxExtraDigitMin); // min PIN length
        s.write(bConfirmPIN);
        // bEntryValidationCondition [0x02]
        s.write(bEntryValidationCondition);
        // bNumberMessage
        s.write(0x03);
        // wLangId [0x04 0x09 english, little endian]
        s.write(0x04);
        s.write(0x09);
        // bMsgIndex1
        s.write(0x00);
        // bMsgIndex2
        s.write(0x01);
        // bMsgIndex3
        s.write(0x02);
        // bTeoPrologue
        s.write(0x00);
        s.write(0x00);
        s.write(0x00);
        // ulDataLength
        s.write(apdu.length);
        s.write(0x00);
        s.write(0x00);
        s.write(0x00);
        // abData
        try {
            s.write(apdu);
        } catch (IOException e) {
            // As we are dealing with ByteArrayOutputStreams no exception is to
            // be expected.
            throw new RuntimeException(e);
        }

        return s.toByteArray();
    }
}
