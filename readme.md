# Description

This project contains a java card applet for smart cards that will encrypt bytes using AES (128bits) in CBC mode.
There is also a host application written in java that will interact with the smart card.
The host will encrypt/decrypt files by transfering the bytes to the javacard to be processed.

# Setup and run

1. Sample_Device -> Properties
2. Select output file for EEPROM
3. Start the device
4. Run the generated scripts from apdu_scripts: cap, create and select
5. Stop the device 

6. Sample_Device -> Properties
7. Move the output file to input file for EEPROM
8. Disable the console (last checkbox)

9. Start the device
10. Run the Host
11. The file.txt from the project root will be encrypted to file.txt.enc 
and then file.txt.enc will be decrypted into file.txt.dec

# Notes

- 'testJcAesApplet.script' was used for testing without a host.

# Tools

- Eclipse jee 2021
- Jcc 310