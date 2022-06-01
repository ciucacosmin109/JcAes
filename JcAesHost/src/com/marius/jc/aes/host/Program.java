package com.marius.jc.aes.host;

import com.sun.javacard.apduio.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import javax.management.InvalidAttributeValueException;

public class Program {

	// Config
	public static final byte ALLOWED_CLA_BYTE = (byte) 0x90;
	
	public static final byte INIT_ENCRYPT_BYTE = (byte) 0xA1;
	public static final byte INIT_DECRYPT_BYTE = (byte) 0xA2;
	
	public static final byte UPDATE_BYTE = (byte) 0xB1;
	public static final byte DOFINAL_BYTE = (byte) 0xB2;

	public static final byte BLOCK_SIZE = (byte) 0x10; // 16 bytes

	// Commands
	public static Apdu getSelectApdu() { 
		// SELECT
		// APDU|CLA: 00, INS: a4, P1: 04, P2: 00, Lc: 07, a1, a2, a3, a4, a5, 02, 01
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{
    		(byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00
        };
        byte[] data1 = new byte[] {
        		(byte)0xA1, (byte)0xA2, (byte)0xA3, (byte)0xA4, (byte)0xA5, 
        		(byte)0x01, (byte)0x01};
        apdu.setDataIn(data1, 7);
        
        return apdu;
	}
	public static Apdu getInitApdu(byte mode) { 
		// INIT
		// APDU|CLA: 90(ALLOWED_CLA_BYTE), INS: a1/a2(mode), P1: 00, P2: 00
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{
    		ALLOWED_CLA_BYTE, mode, (byte)0x00, (byte)0x00
        };
        
        return apdu;
	}
	public static Apdu getUpdateApdu(byte mode, byte[] data) 
		throws InvalidAttributeValueException 
	{ 
		if(data.length != BLOCK_SIZE) {
			throw new InvalidAttributeValueException("data != " + BLOCK_SIZE);
		}
		// UPDATE/DOFINAL
		// APDU|CLA: 90(ALLOWED_CLA_BYTE), INS: b1/b2(mode), P1: 00, P2: 00, 
		// Lc: 10[16], [1], [2], [3], .... [16]
        Apdu apdu = new Apdu();
        apdu.command = new byte[]{
    		ALLOWED_CLA_BYTE, mode, (byte)0x00, (byte)0x00,
        };
        apdu.setDataIn(data, data.length);
        apdu.setLe(16);
        
        return apdu;
	}
	
	// Program
	public static void main(String[] args) {

		try {
			// Connect
			System.out.print("Connecting ... ");
			Socket sock = new Socket("localhost", 9025);
			InputStream is = sock.getInputStream();
			OutputStream os = sock.getOutputStream();
			CadClientInterface cad = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, is, os);
			System.out.println("Ok");
			
			System.out.print("Power up ... ");
			byte[] ATR = cad.powerUp();
			System.out.println("Ok");
			System.out.println();
			
			// Select
			System.out.println("Selecting applet ... ");
			Apdu selectApdu = getSelectApdu();
			cad.exchangeApdu(selectApdu);
			System.out.println(selectApdu);
			System.out.println();

			// Init encrypt
			System.out.println("Switching to encryption ... ");
			Apdu encApdu = getInitApdu(INIT_ENCRYPT_BYTE);
			cad.exchangeApdu(encApdu);
			System.out.println(encApdu);
			System.out.println();
			
			// Read file and encrypt
			{
				Path originalFilePath = Paths.get("file.txt");
				byte[] originalFileData = Files.readAllBytes(originalFilePath);
				byte[] encryptedFileData = new byte[(short)(Math.ceil(originalFileData.length/16.f) * 16)];

				// for each set of bytes
				byte paddingSize = (byte)(16 - originalFileData.length % 16); 
				for(int i = 0; i < originalFileData.length; i += 16) {
					byte[] _16bytes = Arrays.copyOfRange(originalFileData, i, i + 16);
					//Apdu apdu2 = getUpdateApdu(UPDATE_BYTE, _16bytes); 
					Apdu apdu2 = getUpdateApdu(
						i + 16 >= originalFileData.length ? DOFINAL_BYTE : UPDATE_BYTE, 
						_16bytes
					);
					cad.exchangeApdu(apdu2);
					System.out.println(apdu2);
					byte[] _16bytesEncrypted = Arrays.copyOfRange(apdu2.getDataOut(), 0, 16);
	
					//System.out.println(bytesToHex(_16bytes));
					//System.out.println(bytesToHex(_16bytesEncrypted));
					
					for(int j = i; j < i + 16; j++) {
						encryptedFileData[j] = _16bytesEncrypted[j-i];
					}
				}
	
				// write result
				Path encryptedFilePath = Paths.get("file.txt.enc");
				Files.write(encryptedFilePath, new byte[] { paddingSize });
				Files.write(encryptedFilePath, encryptedFileData, StandardOpenOption.APPEND);
			}
			// Init decrypt
			System.out.println();
			System.out.println("Switching to decryption ... ");
			Apdu decApdu = getInitApdu(INIT_DECRYPT_BYTE);
			cad.exchangeApdu(decApdu);
			System.out.println(decApdu);
			System.out.println();

			// Read file and decrypt
			{
				Path encFilePath = Paths.get("file.txt.enc");
				byte[] encFileData = Files.readAllBytes(encFilePath);
				
				// remove the first byte (padding size)
				byte paddingSize = encFileData[0];
				encFileData = Arrays.copyOfRange(encFileData, 1, encFileData.length);
				byte[] resultFileData = new byte[encFileData.length - paddingSize];
				
				// for each set of bytes
				for(int i = 0; i < encFileData.length; i += 16) {
					byte[] _16bytes = Arrays.copyOfRange(encFileData, i, i + 16);
					Apdu apdu2 = getUpdateApdu(
						i + 16 >= encFileData.length ? DOFINAL_BYTE : UPDATE_BYTE, 
						_16bytes
					);
					cad.exchangeApdu(apdu2);
					System.out.println(apdu2);
					byte[] _16bytesDecrypted = Arrays.copyOfRange(apdu2.getDataOut(), 0, 16);

					//System.out.println(bytesToHex(_16bytes));
					//System.out.println(bytesToHex(_16bytesDecrypted));
					
					for(int j = i; j < i + 16 && j < resultFileData.length; j++) {
						resultFileData[j] = _16bytesDecrypted[j-i];
					}
				}

				// write result
				Path encryptedFilePath = Paths.get("file.txt.dec"); 
				Files.write(encryptedFilePath, resultFileData);
			}
			
			// Done :D
			System.out.println("\nDone :D");
		    cad.powerDown();
		} catch (Exception e) {
			System.out.println("Exception Occurred");
			e.printStackTrace();
		}
	}

}
