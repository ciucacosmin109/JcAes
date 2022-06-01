/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package com.marius.jc.aes;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacardx.annotations.*;
import javacardx.crypto.Cipher;

import static com.marius.jc.aes.JcAesAppletStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "com.marius.jc.aes"),
	    @StringDef(name = "AppletName", value = "JcAesApplet")},
	    // Insert your strings here 
	name = "JcAesAppletStrings")
public class JcAesApplet extends Applet {

	// code of CLA byte in the command APDU header
	final static byte SUPPORTED_CLA = (byte) 0x90;
	
	// codes of INS byte in the command APDU header
	final static byte INIT_ENCRYPT = (byte) 0xA1;
	final static byte INIT_DECRYPT = (byte) 0xA2;
	final static byte UPDATE = (byte) 0xB1;
	final static byte DOFINAL = (byte) 0xB2;
	
	// embedded key
    final static byte[] key = new byte[] { 
		(byte) 0xF4, (byte) 0xA0, (byte) 0xC1, (byte) 0x40, (byte) 0x03, (byte) 0x04,
		(byte) 0xA4, (byte) 0xF9, (byte) 0x34, (byte) 0x14, (byte) 0x1F, (byte) 0x94,
		(byte) 0xA3, (byte) 0x44, (byte) 0x14, (byte) 0xA5,
    };

    final static short DATA_OFFSET = (short) ISO7816.OFFSET_CDATA;
    
	AESKey aesKey;
    Cipher cipherAES;
    static byte a[];
    byte cipherMode;
    
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JcAesApplet(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected JcAesApplet(byte bArray[], short bOffset, byte bLength) {

        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); // ALG_AES_BLOCK_128_CBC_NOPAD
        a = new byte[ (short) 128];

        aesKey.setKey(key, (short) 0);
        register();
    }

    /** 
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
    	// APDU object carries a byte array (buffer) to transfer incoming and outgoing APDU header
		// and data bytes between card and CAD

		// At this point, only the first header bytes
		// [CLA, INS, P1, P2, Lc] are available in the APDU buffer.
		// The interface javacard.framework.ISO7816 declares constants to denote the offset of
		// these bytes in the APDU buffer

    	byte[] buffer = apdu.getBuffer();
		buffer[ISO7816.OFFSET_CLA] = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xFC);

		if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)))
			return;
		if (selectingApplet()) {
			return;
		}
		
		// verify the reset of commands have the
		// correct CLA byte, which specifies the
		// command structure
		if (buffer[ISO7816.OFFSET_CLA] != SUPPORTED_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		switch (buffer[ISO7816.OFFSET_INS]) { 
		case INIT_ENCRYPT:
			cipherMode = Cipher.MODE_ENCRYPT;
			cipherAES.init(aesKey, cipherMode);
			return;
		case INIT_DECRYPT:
			cipherMode = Cipher.MODE_DECRYPT;
			cipherAES.init(aesKey, cipherMode);
			return;
		case UPDATE:
			update(apdu);
			return;
		case DOFINAL:
			dofinal(apdu);
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
    }
    
	private void update(APDU apdu) {
		
        byte buffer[] = apdu.getBuffer();

		// Lc byte denotes the number of bytes in the
		// data field of the command APDU
		//byte numBytes = buffer[ISO7816.OFFSET_LC];
		
		// indicate that this APDU has incoming data and receive data starting from the offset
		// ISO7816.OFFSET_CDATA following the 5 header bytes.
        short incomingLength = (short) (apdu.setIncomingAndReceive());
        if (incomingLength != 16) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		cipherAES.update(buffer, (short) DATA_OFFSET, incomingLength, a, (short) 0);

		apdu.setOutgoing();
		apdu.setOutgoingLength(incomingLength);
		apdu.sendBytesLong(a, (short) 0, (short) incomingLength);
		
	}

	private void dofinal(APDU apdu) {
		
		byte buffer[] = apdu.getBuffer();
		
		short incomingLength = (short) (apdu.setIncomingAndReceive());
		if (incomingLength > 16)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		cipherAES.doFinal(buffer, (short) DATA_OFFSET, incomingLength, a, (short) 0);
		
		apdu.setOutgoing();
		apdu.setOutgoingLength(incomingLength); 
		apdu.sendBytesLong(a, (short) 0, incomingLength);
		
	}
}
