//Main file for Riscure Pinata Board rev3.0
//Riscure 2014, 2015, 2016, 2017, 2018, 2019
//
//Code revision: 	3.2 -- 20190808v1
//
//IMPORTANT:
//Presence of hardware crypto engine is defined via the Makefile
//Whether to include PQC algorithms (and exclude classic ciphers) is also decided via the Makefile
//
//Changelog from code revision 3.2 from 3.1
//
// Added Kyber512 key encapsulation cryptosystem.
//
//Changelog from code revision 3.1 from 3.0
//
// Added Dilithium3 sign-verify cryptosystem.
//
//Changelog from code revision 3.0 from v2.3
//
// Added ANSSI protected AES implementation from https://github.com/ANSSI-FR/SecAESSTM32 (BSD license, check LICENSE file in ansiiAES folder)
// TODO: ANSSI aes Implementation seems broken; need to check why sometimes it yields wrong results (best guess is asm stack handling issues & thumb2 alignment crap).
// Likely fix: use the functions from affine_aes.h/c directly and avoid all the anssi crappy code. Decryption seems especially broken
//
// Things that work and are tested in 3.0:
// Added TEA and XTEA encryption/decryption algorithm implementations
// Modified code of password check (double check), so that it is harder to bypass the double check with a single glitch
// Placed end of trigger at the end of password check functions to make the trigger duration more stable
// Added dummy operations countermeasures for DES and AES
// Added a new command for computing MD5 hash of a message (up to 16 bytes) with the HW crypto engine
//
//Changelog from code revision 2.3 from v2.2
//
// Added a ECC25519 scalar multiplication implementation
// Added RSA SFM protected implementation as well as helper functions
//
//Changelog from code revision 2.2 from v2.1
// Added SM4 textbook software implementation (code (C) Odzhan) and OpenSSL SM4 software implementation
// Added DES with initial random delay to force the use of static alignment of the trace
// Bumped FW version to 2.2
//
//Changelog for code revision 2.1 from v1.0:
// Disabled SysTick system timer for cleaner SCA traces (less time jitter, no big spikes every 1ms)
// Added byte-wise copy of a 16-byte array SRAM-SRAM (for Key-loading Template Analysis)
// Added more crypto implementations: SW TDES, SW AES256 curious implementation from Internet, RSA-512 S&M always (SFM, straight forward method)
// Added software AES with trigger pin disabled and a SPI transfer before crypto start (for triggering on SPI bus)
// Added commands for computing HMAC-SHA1 and SHA1 for boards with the HW crypto engine
// Added a new command for checking which Pinata Software Version is programmed on the board
// Added command to request STM32F4 chip UID
// Board now replies zeroes (without trigger signal) if HW crypto/hash command is sent to Pinata board without HW crypto/hash engine
// Added clock source switching commands
// Added clock speed switching commands
// Added commands for FI on password check (single and double check strategies) and infinite loop
// Fixed a stack smash when running AES key schedule on AES T-tables implementation
// Added command to ask for a random number from the TRNG
// Added software DES and AES with a double check for Advanced FI (DFA) purposes
// Added crypto with textbook SW countermeasures: DES with Random delays or S-box shuffling; AES with masking, random delays or S-box shuffling


#include "main.h"
#include "io.h"

#ifdef VARIANT_PQC
#include "dilithium/wrapper.h"
#include "kyber512/wrapper.h"
#endif

//Local functions
void init();
void usart_init();
void oled_init();
void setBypass();
void setPLL();

#ifndef VARIANT_PQC

//Variables, constants and structures
const uint8_t defaultKeyDES[8] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef };
const uint8_t defaultKeyTDES[24] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ,0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef }; //Default is TDES in 2key mode, DESkey1==DESkey3
const uint8_t defaultKeyAES[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
const uint8_t defaultKeyAES256[32] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
									   0xda, 0xba, 0xda, 0xba, 0xd0, 0x00, 0x00, 0xc0, 0x00, 0x01, 0xc0, 0xff, 0xee, 0x55, 0xde, 0xad };
const uint8_t defaultKeySM4[16] = { 0x52, 0x69, 0x73, 0x63, 0x75, 0x72, 0x65, 0x43, 0x68, 0x69, 0x6e, 0x61, 0x32, 0x30, 0x31, 0x37 };
const uint8_t defaultKeyPRESENT80[10] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x80, 0x08 };
const uint8_t defaultKeyPRESENT128[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
const int bootLoopCount=168000;
const uint8_t OLED_bootNormalScreen[] =   { 'B','o','o','t',' ','c','h','e','c','k',' ','o','k',' ',' ',' ',' ',' ',' ',' ',' '};
const uint8_t OLED_bootGlitchedScreen[] = { 'B','o','o','t',' ','c','h','e','c','k',' ','g','l','i','t','c','h','e','d','!','!'};
const uint8_t OLED_initScreen[] = { 'P','i','n','a','t','a',' ','B','o','a','r','d',' ','3','.','2',' ',' ',' ',' ',' ','(','c',')','R','i','s','c','u','r','e',' ','2','0','1','8'};
const uint8_t defaultPasswd[] = {0x02,0x06,0x02,0x08};
const uint32_t defaultKeyTEAXTEA[]={0xcafebabe,0xdeadbeef,0x00010203,0x04050607};
const uint8_t AUTH_OK=0xA5;

#endif // VARIANT_PQC

//rxBuffer is the USART buffer
uint8_t rxBuffer[RXBUFFERLENGTH] = {};
const uint8_t zeros[20]={'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
const uint8_t glitched[] = { 0xFA, 0xCC };
const uint8_t cmdByteIsWrong[] = { 'B','a','d','C','m','d','\n',0x00};
const uint8_t codeVersion[] = { 'V','e','r',' ','3','.','2',0x00};

volatile uint8_t usbSerialEnabled=0;
volatile int busyWait1;
volatile uint8_t clockspeed=168;
volatile uint8_t clockSource=0;

unsigned char etxBuf[256] ={};

// Set GPIO Pin 2 to high.
#define BEGIN_INTERESTING_STUFF GPIOC->BSRRL = GPIO_Pin_2

// Set GPIO Pin 2 to low.
#define END_INTERESTING_STUFF GPIOC->BSRRH = GPIO_Pin_2

#ifdef VARIANT_PQC
DilithiumState dilithium;
Kyber512State kyber512;
#endif

////////////////////////////////////////////////////
//MAIN FUNCTION: entry point for the board program//
////////////////////////////////////////////////////
int main(void) {
	uint8_t cmd;
	uint8_t tmp;

#ifndef VARIANT_PQC

	int payload_len, i, glitchedBoot, authenticated, counter=0;
	ErrorStatus cryptoCompletedOK=ERROR;
	//We will need ROUNDS + 1 keys to be generated by the key schedule (multiplied by 4 because we can only store 32 bits at a time).
	uint32_t keyScheduleAES[(MAXAESROUNDS + 1) * 4] = { };
	uint8_t keyDES[8];
	uint8_t keyTDES[24];
	uint8_t keyAES[16];
	uint8_t keyLoadingAES[16];
	uint8_t keyAES256[32];
	uint8_t keySM4[16];
	uint8_t password[4];
	uint8_t keyPRESENT80[10];
	uint8_t keyPRESENT128[16];
	aes256_context ctx;
	sm4_ctx ctx_sm4;
	SM4_KEY ctx_sm4_ossl;
	uint32_t keyTEAXTEA[4];
	uint32_t teaxteaInOut[2];
	//ANSSI AES support structures
	//volatile STRUCT_AES aes_struct,aes_struct_2; //Allocated another structure just in case there is some ASM overflow (seems like it)
	//volatile uint8_t randoms_keyScheduling[20];
	//volatile uint8_t randoms_AESoperations[20];

#endif // VARIANT_PQC

	//Set up the system clocks
	SystemInit();
	//Initialize peripherals and select IO interface
	init();

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;

	// If no jumper between PA9, VBUS
	if(!usbSerialEnabled) {
		// Enable USART3 in port gpioC (Pins PC10 TxD,PC11 RxD)
		usart_init();
	}

	// Optional peripherals: enable SPI and GPIO pins for OLED display
	oled_init();
	oled_clear();

#ifndef VARIANT_PQC

	// Initialize & load default cryptographic keys from FLASH memory
	// Load RSACRT parameters
	rsa_crt_init();
	// Load RSASFM parameters
	rsa_sfm_init();
	// Load default keys for DES, TDES, AES from non volatile memory
	for (i = 0; i < 8; i++) keyDES[i] = defaultKeyDES[i];
	for (i = 0; i < 24; i++) keyTDES[i] = defaultKeyTDES[i];
	for (i = 0; i < 16; i++) keyAES[i] = defaultKeyAES[i];
	for (i = 0; i < 4; i++) password[i] = defaultPasswd[i];

	//Loop for trivial Boot glitching; display boot screen with glitched status
	//PC1 can be used as trigger pin for boot glitching
	GPIOC->BSRRL = GPIO_Pin_1; //PC1 3.3V

	glitchedBoot=0;
	authenticated=0;
	for (counter=0;counter<bootLoopCount;){
		counter++;
	}

	GPIOC->BSRRH = GPIO_Pin_1; //PC1 0V
	//Mock-up of security check: counter in a loop
	if (counter != bootLoopCount) {
		glitchedBoot = 1;
	}

	if (glitchedBoot) {
		oled_sendchars(21,OLED_bootGlitchedScreen);
	} else {
		oled_sendchars(21,OLED_bootNormalScreen);
	}
	oled_sendchars(36,OLED_initScreen);

	//Ver 2.0 and later: init code updates after initial code (to keep similar timing for boot glitching from code version 1.0)
	for (i = 0; i < 32; i++) keyAES256[i] = defaultKeyAES256[i];
	aes256_init(&ctx,keyAES256); //Prepare AES key schedule for software AES256
	for (i = 0; i < 16; i++) keySM4[i] = defaultKeySM4[i];
	for (i = 0; i < 4; i++) keyTEAXTEA[i] = defaultKeyTEAXTEA[i];

#endif

	//////////////////////
	//MAIN FUNCTION LOOP//
	//////////////////////

	while (1) {
		cmd=0;
		tmp=0;

#ifndef VARIANT_PQC

		//Main loop variable (re)initialization
		for (i = 0; i < RXBUFFERLENGTH; i++) rxBuffer[i] = 0; //Zero the rxBuffer
		for (i = 0; i < MAXAESROUNDS; i++) keyScheduleAES[i] = 0; //Zero the AES key schedule (T-tables AES implementation)
		payload_len = 0x0000; //RSA: Length of the ciphertext; init to zero, expected values for 1024bit RSA=128byte, 512bit RSA=64byte
		teaxteaInOut[0]=0x00000000;teaxteaInOut[1]=0x00000000;

#endif // VARIANT_PQC

		//Main processing section: select and execute cipher&mode
		get_char(&cmd);
		switch (cmd) {
			/////////Software crypto commands/////////

#ifdef VARIANT_PQC

			case CMD_SW_DILITHIUM_GET_VARIANT:
				// Return the response.
				send_char(getDilithiumAlgorithmVariant());
				break;

			case CMD_SW_DILITHIUM_SET_PUBLIC_AND_PRIVATE_KEY: {
				// Receive the input parameters and handle the request.
				get_bytes(DILITHIUM_PUBLIC_KEY_SIZE, DilithiumState_getPublicKey(&dilithium));
				get_bytes(DILITHIUM_PRIVATE_KEY_SIZE, DilithiumState_getPrivateKey(&dilithium));

				// Return the response.
				send_char(0);
				break;
			}

			case CMD_SW_DILITHIUM_VERIFY: {
				// Receive the input parameters.
				uint8_t* signedMessageBuffer = DilithiumState_getScratchPad(&dilithium);
				get_bytes(DILITHIUM_SIGNED_MESSAGE_SIZE, signedMessageBuffer);

				// Handle the request.
				BEGIN_INTERESTING_STUFF;
				int result = DilithiumState_verify(&dilithium, signedMessageBuffer);
				END_INTERESTING_STUFF;

				// Return the response.
				send_char(result == 0 ? 0 : 1);
				break;	
			}

			case CMD_SW_DILITHIUM_SIGN: {
				// Receive the input parameters.
				uint8_t* signedMessageBuffer = DilithiumState_getScratchPad(&dilithium);
				get_bytes(DILITHIUM_MESSAGE_SIZE, signedMessageBuffer + DILITHIUM_SIGNATURE_SIZE);

				// Handle the request.
				BEGIN_INTERESTING_STUFF;
				int result = DilithiumState_sign(&dilithium, signedMessageBuffer, signedMessageBuffer + DILITHIUM_SIGNATURE_SIZE);
				END_INTERESTING_STUFF;

				if (result == 0) {
					// OK: The message is now signed, let's send the signature of the message back.
					send_char(0);
					send_bytes(DILITHIUM_SIGNATURE_SIZE, signedMessageBuffer);
				} else {
					// ERROR: Signing the message failed.
					send_char(1);
				}
				break;
			}

			case CMD_SW_DILITHIUM_GET_KEY_SIZES: {
				const uint16_t publicKeySize = DILITHIUM_PUBLIC_KEY_SIZE;
				const uint16_t privateKeySize = DILITHIUM_PRIVATE_KEY_SIZE;
				// Send the response; MUST be in little-endian order!
				send_bytes(sizeof(publicKeySize), (const uint8_t*)&publicKeySize);
				send_bytes(sizeof(privateKeySize), (const uint8_t*)&privateKeySize);
				break;
			}

			case CMD_SW_DILITHIUM_NTT: {
				int32_t polynomialBuffer[DILITHIUM_N];
				// Receive the polynomial coefficients.
				get_bytes(sizeof(int32_t)*DILITHIUM_N, (uint8_t*)polynomialBuffer);
				BEGIN_INTERESTING_STUFF;
				Dilithium_ntt(polynomialBuffer);
				END_INTERESTING_STUFF;
				// No reply is sent.
				break;
			}

			case CMD_SW_KYBER512_SET_PUBLIC_AND_PRIVATE_KEY: {
				// Receive the input parameters and handle the request.
				get_bytes(KYBER512_PUBLIC_KEY_SIZE, Kyber512State_getPublicKey(&kyber512));
				get_bytes(KYBER512_PRIVATE_KEY_SIZE, Kyber512State_getPrivateKey(&kyber512));
				// Return the response.
				send_char(0);
				break;
			}

			case CMD_SW_KYBER512_GENERATE: {
				// Generate a shared secret and an accompanying key encapsulation message.
				BEGIN_INTERESTING_STUFF;
				int result = Kyber512State_generate(&kyber512);
				END_INTERESTING_STUFF;
				if (result == 0) {
					// OK: The shared secret is now generated and encapsulated, let's send that back.
					send_char(0);
					send_bytes(KYBER512_SHARED_SECRET_SIZE, Kyber512State_getSharedSecretBuffer(&kyber512));
					send_bytes(KYBER512_CIPHERTEXT_SIZE, Kyber512State_getKeyEncapsulationMessageBuffer(&kyber512));
				} else {
					// ERROR: Generation failed.
					send_char(1);
				}
				break;
			}

			case CMD_SW_KYBER512_DEC: {
				// Receive the key encapsulation message that we are supposed to decode.
				get_bytes(KYBER512_CIPHERTEXT_SIZE, Kyber512State_getKeyEncapsulationMessageBuffer(&kyber512));
				memset(Kyber512State_getSharedSecretBuffer(&kyber512), 0, KYBER512_SHARED_SECRET_SIZE);
				// Decode the key encapsulation message into a shared secret.
				BEGIN_INTERESTING_STUFF;
				int result = Kyber512State_decode(&kyber512);
				END_INTERESTING_STUFF;
				if (result == 0) {
					// OK: The shared secret is decoded, let's send that back.
					send_char(0);
					send_bytes(KYBER512_SHARED_SECRET_SIZE, Kyber512State_getSharedSecretBuffer(&kyber512));
				} else {
					// ERROR: Decoding the shared secret failed.
					send_char(1);
				}
				break;
			}

			case CMD_SW_KYBER512_GET_KEY_SIZES: {
				const uint16_t publicKeySize = KYBER512_PUBLIC_KEY_SIZE;
				const uint16_t privateKeySize = KYBER512_PRIVATE_KEY_SIZE;
				// Send the response; MUST be in little-endian order!
				send_bytes(sizeof(publicKeySize), (const uint8_t*)&publicKeySize);
				send_bytes(sizeof(privateKeySize), (const uint8_t*)&privateKeySize);
				break;
			}

#else // VARIANT_PQC

			//Software DES - encrypt
			case CMD_SWDES_ENC:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				BEGIN_INTERESTING_STUFF;
				des(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software DES - decrypt
			case CMD_SWDES_DEC:
				get_bytes(8, rxBuffer); // Receive DES ciphertext
				BEGIN_INTERESTING_STUFF;
				des(keyDES, rxBuffer, DECRYPT); // Perform software DES decryption
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // TransmiDt back plaintext via UART
				break;

			//Software TDES - encrypt
			case CMD_SWTDES_ENC:
				get_bytes(8, rxBuffer); // Receive TDES plaintext
				BEGIN_INTERESTING_STUFF;
				des(keyTDES,   rxBuffer, ENCRYPT); // Perform software DES encryption, key1
				des(keyTDES+8, rxBuffer, DECRYPT); // Perform software DES decryption, key2
				des(keyTDES+16,rxBuffer, ENCRYPT); // Perform software DES encryption, key3
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software TDES - decrypt
			case CMD_SWTDES_DEC:
				get_bytes(8, rxBuffer); // Receive TDES ciphertext
				BEGIN_INTERESTING_STUFF;
				des(keyTDES,   rxBuffer, DECRYPT); // Perform software DES decryption, key1
				des(keyTDES+8, rxBuffer, ENCRYPT); // Perform software DES encryption, key2
				des(keyTDES+16,rxBuffer, DECRYPT); // Perform software DES decryption, key3
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back plaintext via UART
				break;

			//Software AES128 - encrypt
			case CMD_SWAES128_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES128 - encrypt with SPI transmission at beginning, NO TRIGGER ON PC2
			case CMD_SWAES128SPI_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				//4 byte SPI transmission to simulate access to e.g. external FLASH; sending 0xDECAFFED
				send_OLEDcmd_SPI(0xDE);
				send_OLEDcmd_SPI(0xCA);
				send_OLEDcmd_SPI(0xFF);
				send_OLEDcmd_SPI(0xED);
				AES128_ECB_encrypt_noTrigger(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES);
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES128 - decrypt
			case CMD_SWAES128_DEC:
				get_bytes(16, rxBuffer); // Receive AES ciphertext
				AES128_ECB_decrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				break;
			/*
			//Software AES128 ANSSI masked implementation, random numbers from TRNG - encrypt
			case CMD_ANSSIAES128_ENC:
				get_bytes(16, rxBuffer); // Receive AES plain
				RNG_Enable();
				fillBufferWithRandomNumbers(19, randoms_AESoperations);
				fillBufferWithRandomNumbers(19, randoms_keyScheduling);
				RNG_Disable();
				//Implementation seems broken; sometimes outputs wrong ciphertexts (which is weird)
				tmp32=anssiaes(MODE_KEYINIT|MODE_AESINIT_ENC|MODE_RANDOM_AES_EXT|MODE_RANDOM_KEY_EXT, &aes_struct, keyAES, 0, 0, randoms_AESoperations, randoms_keyScheduling);
				tmp32|=anssiaes(MODE_ENC, &aes_struct, 0, rxBuffer, rxBuffer + AES128LENGTHINBYTES, 0, 0);
				if(tmp32!=NO_ERROR){
					send_bytes(16, zeros); // Error: transmit zeroes
				}
				else {
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				}

				break;

			//Software AES128 ANSSI masked implementation, random numbers from TRNG - decrypt
			case CMD_ANSSIAES128_DEC:
				get_bytes(16, rxBuffer); // Receive AES ciphertext
				RNG_Enable();
				fillBufferWithRandomNumbers(19, randoms_AESoperations);
				fillBufferWithRandomNumbers(19, randoms_keyScheduling);
				RNG_Disable();
				//Implementation seems broken
				tmp32=anssiaes(MODE_KEYINIT|MODE_AESINIT_DEC|MODE_RANDOM_AES_EXT|MODE_RANDOM_KEY_EXT, &aes_struct, keyAES, 0, 0, randoms_AESoperations, randoms_keyScheduling);
				tmp32|=anssiaes(MODE_DEC, &aes_struct, 0, rxBuffer, rxBuffer + AES128LENGTHINBYTES, 0, 0);
				if(tmp32!=NO_ERROR){
					send_bytes(16, zeros); // Error: transmit zeroes
				}
				else {
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				}
				break;
			*/
			//Software AES256 - encrypt
			case CMD_SWAES256_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				BEGIN_INTERESTING_STUFF;
				aes256_encrypt_ecb(&ctx, rxBuffer); // Perform software AES256 encryption
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software AES256 - decrypt
			case CMD_SWAES256_DEC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				BEGIN_INTERESTING_STUFF;
				aes256_decrypt_ecb(&ctx, rxBuffer); // Perform software AES256 encryption
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software SM4 - encrypt
			case CMD_SWSM4_ENC:
				get_bytes(16, rxBuffer); // Receive SM4 plaintext
				sm4_setkey(&ctx_sm4, keySM4, SM4_ENCRYPT); //Configure SM4 key schedule for encryption
				BEGIN_INTERESTING_STUFF;
				sm4_encrypt(&ctx_sm4,rxBuffer); //Perform SM4 crypto
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software SM4 - decrypt
			case CMD_SWSM4_DEC:
				get_bytes(16, rxBuffer); // Receive SM4 ciphertext
				sm4_setkey(&ctx_sm4, keySM4, SM4_DECRYPT); //Configure SM4 key schedule for decryption
				BEGIN_INTERESTING_STUFF;
				sm4_encrypt(&ctx_sm4,rxBuffer); //Perform SM4 crypto
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer); // Transmit back plaintext via UART
				break;

			//Software SM4 OpenSSL implementation- encrypt
			case CMD_SWSM4OSSL_ENC:
				get_bytes(16, rxBuffer); // Receive SM4 plaintext
				SM4_set_key(keySM4, &ctx_sm4_ossl); //Configure SM4 key schedule
				BEGIN_INTERESTING_STUFF;
				SM4_encrypt(rxBuffer,rxBuffer+SM4_BLOCK_SIZE,&ctx_sm4_ossl); //Perform SM4 encryption (openSSL code)
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer+SM4_BLOCK_SIZE); // Transmit back ciphertext via UART
				break;

			//Software SM4 OpenSSL implementation - decrypt
			case CMD_SWSM4OSSL_DEC:
				get_bytes(16, rxBuffer); // Receive SM4 plaintext
				SM4_set_key(keySM4, &ctx_sm4_ossl); //Configure SM4 key schedule
				BEGIN_INTERESTING_STUFF;
				SM4_decrypt(rxBuffer,rxBuffer+SM4_BLOCK_SIZE,&ctx_sm4_ossl); //Perform SM4 decryption (openSSL code)
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer+SM4_BLOCK_SIZE); // Transmit back ciphertext via UART
				break;

			//Software DES - encrypt with misalignment at beginning of trigger (to practice static align)
			case CMD_SWDES_ENC_MISALIGNED:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				BEGIN_INTERESTING_STUFF;
				desMisaligned(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			case CMD_SWAES128_ENC_MISALIGNED:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_misaligned(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software DES - encrypt with dummy rounds
			case CMD_SWDES_ENC_DUMMYROUNDS:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				BEGIN_INTERESTING_STUFF;
				desDummy(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			case CMD_SWAES128_ENC_DUMMYROUNDS:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_dummy(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			case CMD_SWTEA_ENC:
				get_bytes(8, rxBuffer); // Receive TEA plaintext
				teaxteaInOut[0]= rxBuffer[3] | (rxBuffer[2] << 8) | (rxBuffer[1] << 16) | (rxBuffer[0] << 24);
				teaxteaInOut[1]= rxBuffer[7] | (rxBuffer[6] << 8) | (rxBuffer[5] << 16) | (rxBuffer[4] << 24);
				BEGIN_INTERESTING_STUFF;
				tea_encrypt(teaxteaInOut,keyTEAXTEA); //32 rounds (32 cycles as named in TEA)
				END_INTERESTING_STUFF;
				send_char((teaxteaInOut[0]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[0]>>16)&0x000000FF);
				send_char((teaxteaInOut[0]>> 8)&0x000000FF);
				send_char( teaxteaInOut[0]     &0x000000FF);
				send_char((teaxteaInOut[1]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[1]>>16)&0x000000FF);
				send_char((teaxteaInOut[1]>> 8)&0x000000FF);
				send_char( teaxteaInOut[1]     &0x000000FF);
				break;

			case CMD_SWTEA_DEC:
				get_bytes(8, rxBuffer); // Receive TEA plaintext
				teaxteaInOut[0]= rxBuffer[3] | (rxBuffer[2] << 8) | (rxBuffer[1] << 16) | (rxBuffer[0] << 24);
				teaxteaInOut[1]= rxBuffer[7] | (rxBuffer[6] << 8) | (rxBuffer[5] << 16) | (rxBuffer[4] << 24);
				BEGIN_INTERESTING_STUFF;
				tea_decrypt(teaxteaInOut,keyTEAXTEA); //32 rounds (32 cycles as named in TEA)
				END_INTERESTING_STUFF;
				send_char((teaxteaInOut[0]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[0]>>16)&0x000000FF);
				send_char((teaxteaInOut[0]>> 8)&0x000000FF);
				send_char( teaxteaInOut[0]     &0x000000FF);
				send_char((teaxteaInOut[1]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[1]>>16)&0x000000FF);
				send_char((teaxteaInOut[1]>> 8)&0x000000FF);
				send_char( teaxteaInOut[1]     &0x000000FF);
				break;

			case CMD_SWXTEA_ENC:
				get_bytes(8, rxBuffer); // Receive TEA plaintext
				teaxteaInOut[0]= rxBuffer[3] | (rxBuffer[2] << 8) | (rxBuffer[1] << 16) | (rxBuffer[0] << 24);
				teaxteaInOut[1]= rxBuffer[7] | (rxBuffer[6] << 8) | (rxBuffer[5] << 16) | (rxBuffer[4] << 24);
				BEGIN_INTERESTING_STUFF;
				xtea_encrypt(teaxteaInOut,keyTEAXTEA); //32 rounds (32 cycles as named in TEA)
				END_INTERESTING_STUFF;
				send_char((teaxteaInOut[0]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[0]>>16)&0x000000FF);
				send_char((teaxteaInOut[0]>> 8)&0x000000FF);
				send_char( teaxteaInOut[0]     &0x000000FF);
				send_char((teaxteaInOut[1]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[1]>>16)&0x000000FF);
				send_char((teaxteaInOut[1]>> 8)&0x000000FF);
				send_char( teaxteaInOut[1]     &0x000000FF);
				break;

			case CMD_SWXTEA_DEC:
				get_bytes(8, rxBuffer); // Receive TEA plaintext
				teaxteaInOut[0]= rxBuffer[3] | (rxBuffer[2] << 8) | (rxBuffer[1] << 16) | (rxBuffer[0] << 24);
				teaxteaInOut[1]= rxBuffer[7] | (rxBuffer[6] << 8) | (rxBuffer[5] << 16) | (rxBuffer[4] << 24);
				BEGIN_INTERESTING_STUFF;
				xtea_decrypt(teaxteaInOut,keyTEAXTEA); //32 rounds (32 cycles as named in TEA)
				END_INTERESTING_STUFF;
				send_char((teaxteaInOut[0]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[0]>>16)&0x000000FF);
				send_char((teaxteaInOut[0]>> 8)&0x000000FF);
				send_char( teaxteaInOut[0]     &0x000000FF);
				send_char((teaxteaInOut[1]>>24)&0x000000FF); //MSB first
				send_char((teaxteaInOut[1]>>16)&0x000000FF);
				send_char((teaxteaInOut[1]>> 8)&0x000000FF);
				send_char( teaxteaInOut[1]     &0x000000FF);
				break;

			/////Software crypto with countermeasures //////
			//Software DES - encrypt with Random S-box order
			case CMD_SWDES_ENC_RND_SBOX:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				BEGIN_INTERESTING_STUFF;
				desRandomSboxes(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software DES - encrypt with Random delays
			case CMD_SWDES_ENC_RND_DELAYS:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				BEGIN_INTERESTING_STUFF;
				desRandomDelays(keyDES, rxBuffer, ENCRYPT,2); // Perform software DES encryption
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software masked AES128 - encrypt
			case CMD_SWAES128_ENC_MASKED:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				mAES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software masked AES128 - decrypt
			case CMD_SWAES128_DEC_MASKED:
				get_bytes(16, rxBuffer); // Receive AES ciphertext
				mAES128_ECB_decrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				break;

			//Software AES128 - random delays
			case CMD_SWAES128_ENC_RNDDELAYS:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_rndDelays(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES128 - random sbox order
			case CMD_SWAES128_ENC_RNDSBOX:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_rndSbox(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			// RSA-CRT 1024bit decryption, textbook style (non-time constant)
			case CMD_RSACRT1024_DEC:
				if (cmd == 0) { //Legacy support of RLV protocol
					get_char(&cmd);
				}
				get_char(&tmp); // Receive payload length, expect MSByte first
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				//Receive payload_len bytes from the USART (truncating plaintext length if too long)
				get_bytes(payload_len, rxBuffer);
				if (payload_len > RXBUFFERLENGTH) {
					payload_len = RXBUFFERLENGTH;
				}
				input_cipher_text(payload_len); // Fill the cipher text buffer "c" with incoming data bytes, assuming MSByte first and 32-bit alignment
				rsa_crt_decrypt(); // Start RSA CRT procedure, Trigger signal toggling contained within the call
				send_clear_text(); // Send content of clear text buffer "m" back to Host PC, MSByte first 32-bit alignment
				break;

			//Software AES(Ttables implementation) - encrypt
			case CMD_SWAES128TTABLES_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				rijndaelSetupEncrypt(keyScheduleAES, keyAES, 128); //Prepare AES key schedule
				BEGIN_INTERESTING_STUFF;
				rijndaelEncrypt(keyScheduleAES, 10, rxBuffer, rxBuffer + AES128LENGTHINBYTES); // Perform software AES encryption
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES(Ttables implementation) - decrypt
			case CMD_SWAES128TTABLES_DEC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				rijndaelSetupDecrypt(keyScheduleAES, keyAES, 128); //Prepare AES key schedule
				BEGIN_INTERESTING_STUFF;
				rijndaelDecrypt(keyScheduleAES, 10, rxBuffer, rxBuffer + AES128LENGTHINBYTES); // Perform software AES decryption
				END_INTERESTING_STUFF;
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				break;

			//Software RSA-512 SFM commands
			case CMD_RSASFM_GET_HARDCODED_KEY:
				rsa_sfm_send_hardcoded_key();
				break;
			case CMD_RSASFM_SET_D:
				get_char(&tmp);		// Receive payload length, expect MSByte first
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				//Receive payload_len bytes from the USART (truncating plaintext length if too long)
				if(payload_len>RXBUFFERLENGTH){
					payload_len=RXBUFFERLENGTH;
				}
				get_bytes(payload_len,rxBuffer);
				input_external_exponent(payload_len);
				send_char(cmd);
				break;
			case CMD_RSASFM_DEC:
				get_char(&tmp);		// Receive payload length, expect MSByte first
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				//Receive payload_len bytes from the USART (truncating plaintext length if too long)
				if(payload_len>RXBUFFERLENGTH){
					payload_len=RXBUFFERLENGTH;
				}
				get_bytes(payload_len,rxBuffer);
				input_cipher_text(payload_len);	// Fill the cipher text buffer "c" with incoming data bytes, assuming MSByte first and 32-bit alignment
				rsa_sfm_decrypt();
				send_clear_text();
				break;
			case CMD_RSASFM_SET_KEY_GENERATION_METHOD:
				get_char(&tmp);
				rsa_sfm_set_key_generation_method(tmp);
				send_char(tmp);
				break;
			case CMD_RSASFM_SET_IMPLEMENTATION:
				get_char(&tmp);
				rsa_sfm_set_implementation_method(tmp);
				send_char(tmp);
				break;

			//ECC Curve 25519 commands
			case CMD_ECC25519_SCALAR_MULT:
				ecsm(rxBuffer);
				break;

			//PRESENT
			case CMD_PRESENT80_ENC:
				get_bytes(8, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				present80_encrypt(rxBuffer, keyPRESENT80, rxBuffer + 8);
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer + 8);
				break;
			case CMD_PRESENT80_DEC:
				get_bytes(8, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				present80_decrypt(rxBuffer, keyPRESENT80, rxBuffer + 8);
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer + 8);
				break;
			case CMD_PRESENT128_ENC:
				get_bytes(8, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				present128_encrypt(rxBuffer, keyPRESENT128, rxBuffer + 8);
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer + 8);
				break;
			case CMD_PRESENT128_DEC:
				get_bytes(8, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				present128_decrypt(rxBuffer, keyPRESENT128, rxBuffer + 8);
				END_INTERESTING_STUFF;
				send_bytes(8, rxBuffer + 8);
				break;

#endif // VARIANT_PQC

			/////////Hardware crypto commands/////////

#ifndef HW_CRYPTO_PRESENT

			//Fallback for Pinata boards without HW crypto processor: board will reply zeroes without any trigger instead of BADCMD to quickly identify the issue
			case CMD_HWAES128_ENC:
			case CMD_HWAES128_DEC:
			case CMD_HWAES256_ENC:
			case CMD_HWAES256_DEC:
				get_bytes(16, rxBuffer);
				//HW crypto is not supported: send zeroes back
				send_bytes(16, zeros);
				break;
			case CMD_HWDES_ENC:
			case CMD_HWDES_DEC:
			case CMD_HWTDES_ENC:
			case CMD_HWTDES_DEC:
				get_bytes(8, rxBuffer);
				//HW crypto is not supported: send zeroes back
				send_bytes(8, zeros);
				break;
			case CMD_SHA1_HASH:
				get_bytes(sizeof(uint32_t), rxBuffer);
				get_bytes(16, rxBuffer);
				//HW hashing is not supported: send zeroes back
				send_bytes(20, zeros);
				break;
			case CMD_HMAC_SHA1:
				get_bytes(sizeof(uint32_t), rxBuffer);
				get_bytes(20, rxBuffer);
				//HW hashing is not supported: send zeroes back
				send_bytes(20, zeros);
				break;
			case CMD_MD5_HASH:
				{
				uint8_t len=0;
				// Length of message to hash, up to 16 bytes
				get_bytes(1, rxBuffer);
				len=rxBuffer[0];
				if(len>0x10){
					len=0x10;
				}
				//Read message up to 16 bytes
				get_bytes(len, rxBuffer);
				}
				send_bytes(16, zeros);
				break;

#endif

#ifdef HW_CRYPTO_PRESENT

			//Hardware AES128 - encrypt
			case CMD_HWAES128_ENC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_ENCRYPT, keyAES, 128,	rxBuffer, (uint32_t) AES128LENGTHINBYTES, rxBuffer + AES128LENGTHINBYTES);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware AES128 - decrypt
			case CMD_HWAES128_DEC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_DECRYPT, keyAES, 128,	rxBuffer, (uint32_t) AES128LENGTHINBYTES, rxBuffer + AES128LENGTHINBYTES);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware AES256 - encrypt
			case CMD_HWAES256_ENC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_ENCRYPT, keyAES256, 256,	rxBuffer, (uint32_t) 16, rxBuffer + 16);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + 16);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware AES256 - decrypt
			case CMD_HWAES256_DEC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_DECRYPT, keyAES256, 256,	rxBuffer, (uint32_t) 16, rxBuffer + 16);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + 16);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware DES - encrypt
			case CMD_HWDES_ENC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_DES_ECB(MODE_ENCRYPT,keyDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;

			//Hardware DES - decrypt
			case CMD_HWDES_DEC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_DES_ECB(MODE_DECRYPT,keyDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;

			//Hardware TDES - encrypt
			case CMD_HWTDES_ENC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_TDES_ECB(MODE_ENCRYPT,keyTDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;

			//Hardware TDES - decrypt
			case CMD_HWTDES_DEC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_TDES_ECB(MODE_DECRYPT,keyTDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;


				//Hardware HMAC SHA1 (key is the same as the TDES key)
			case CMD_HMAC_SHA1:
				{
				get_bytes(sizeof(uint32_t), rxBuffer);
				uint32_t rxBuffer32 = (uint32_t)rxBuffer;
				uint32_t iterations = __REV(*(uint32_t*)rxBuffer32);

				get_bytes(20, rxBuffer);
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
				// 24 byte key used is the same as the TDES key!!
				cryptoCompletedOK = HMAC_SHA1(keyTDES, sizeof(keyTDES), rxBuffer+sizeof(uint32_t), 20, rxBuffer+24, iterations);
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);

				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(20, rxBuffer+24);
				} else {
					send_bytes(20, zeros);
				}
				}
				break;

				//Hardware SHA1
			case CMD_SHA1_HASH:
				{
				// Length of message to hash fixed to 16 bytes
				get_bytes(sizeof(uint32_t), rxBuffer);
				uint32_t rxBuffer32 = (uint32_t)rxBuffer;
				uint32_t iterations = __REV(*(uint32_t*)rxBuffer32);

				get_bytes(16, rxBuffer);

				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
				BEGIN_INTERESTING_STUFF;
				cryptoCompletedOK = HASH_SHA1(rxBuffer+sizeof(uint32_t), 16, rxBuffer+20, iterations);
				END_INTERESTING_STUFF;
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);

				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(20, rxBuffer+20);
				} else {
					send_bytes(20, zeros);
				}
				}
				break;

				//Hardware MD5 (up to 16 bytes)
				//CMD format: CMD_MD5_HASH (1 byte) + message length (1 byte, possible values 0x01 to 0x10) + message
				//output: 16 byte hash
			case CMD_MD5_HASH:
				{
				uint8_t len=0;
				// Length of message to hash, up to 16 bytes
				get_bytes(1, rxBuffer);
				len=rxBuffer[0];
				if(len>0x10){
					len=0x10;
				}
				//Read message up to 16 bytes
				get_bytes(len, rxBuffer);

				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
				BEGIN_INTERESTING_STUFF;
				cryptoCompletedOK = HASH_MD5(rxBuffer,len, rxBuffer+16);
				END_INTERESTING_STUFF;
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);

				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer+16);
				} else {
					send_bytes(16, zeros);
				}
				}
				break;

#endif
			//////Cryptographic keys management//////

#ifndef VARIANT_PQC

			//TDES key change
			case CMD_TDES_KEYCHANGE:
				get_bytes(24, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 24; i++) keyTDES[i] = rxBuffer[i];
				END_INTERESTING_STUFF;
				send_bytes(24,keyTDES);
				break;

			//DES key change
			case CMD_DES_KEYCHANGE:
				get_bytes(8, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 8; i++) keyDES[i] = rxBuffer[i];
				END_INTERESTING_STUFF;
				send_bytes(8,keyDES);
				break;

			//TEA / XTEA key change
			case CMD_TEA_XTEA_KEYCHANGE:
				get_bytes(16, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 4; i++){ //Copy input key to keyArray swapping endianness on-the-fly
					keyTEAXTEA[i] = rxBuffer[4*i+3] | (rxBuffer[4*i+2] << 8) | (rxBuffer[4*i+1] << 16) | (rxBuffer[4*i+0] << 24);
				}
				END_INTERESTING_STUFF;
				send_char((keyTEAXTEA[0]>>24)&0x000000FF); //MSB first
				send_char((keyTEAXTEA[0]>>16)&0x000000FF);
				send_char((keyTEAXTEA[0]>> 8)&0x000000FF);
				send_char( keyTEAXTEA[0]     &0x000000FF);
				send_char((keyTEAXTEA[1]>>24)&0x000000FF); //MSB first
				send_char((keyTEAXTEA[1]>>16)&0x000000FF);
				send_char((keyTEAXTEA[1]>> 8)&0x000000FF);
				send_char( keyTEAXTEA[1]     &0x000000FF);
				send_char((keyTEAXTEA[2]>>24)&0x000000FF); //MSB first
				send_char((keyTEAXTEA[2]>>16)&0x000000FF);
				send_char((keyTEAXTEA[2]>> 8)&0x000000FF);
				send_char( keyTEAXTEA[2]     &0x000000FF);
				send_char((keyTEAXTEA[3]>>24)&0x000000FF); //MSB first
				send_char((keyTEAXTEA[3]>>16)&0x000000FF);
				send_char((keyTEAXTEA[3]>> 8)&0x000000FF);
				send_char( keyTEAXTEA[3]     &0x000000FF);
				break;

			//AES128 key change
			case CMD_AES128_KEYCHANGE:
				get_bytes(16, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 16; i++) keyAES[i] = rxBuffer[i];
				END_INTERESTING_STUFF;
				send_bytes(16,keyAES);
				break;

			//AES256 key change
			case CMD_AES256_KEYCHANGE:
				get_bytes(32, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 32; i++) keyAES256[i] = rxBuffer[i];
				//Recompute again aes256 key schedule
				aes256_init(&ctx,keyAES256); //Prepare AES key schedule for software AES256
				END_INTERESTING_STUFF;
				send_bytes(32,keyAES256);
				break;

			//Password change (4 bytes long, used for password check commands & FI)
			case CMD_PWD_CHANGE:
				authenticated=0;
				get_bytes(4, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 4; i++) password[i] = rxBuffer[i];
				END_INTERESTING_STUFF;
				send_bytes(4,password);
				break;

			//SM4 key change
			case CMD_SM4_KEYCHANGE:
				get_bytes(16, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				for (i = 0; i < 16; i++) keySM4[i] = rxBuffer[i];
				END_INTERESTING_STUFF;
				send_bytes(16,keySM4);
				break;


			/////Template analysis commands/////

			//Software key copy (byte-wise)
			case CMD_SOFTWARE_KEY_COPY:
				get_bytes(16, rxBuffer); // Receive AES128 key (16 byte)
				for (i = 0; i < 16; i++) keyLoadingAES[i] = 0; //Initialize key array
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on PC2 for key loading
				busyWait1=0;
				while (busyWait1 < 500) busyWait1++; //For avoiding ringing on GPIO toggling

				//Key copy, byte-wise, with a delay between key bytes copy to make it even more evident where key copy happens
				keyLoadingAES[0] = rxBuffer[0];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[1] = rxBuffer[1];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[2] = rxBuffer[2];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[3] = rxBuffer[3];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[4] = rxBuffer[4];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[5] = rxBuffer[5];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[6] = rxBuffer[6];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[7] = rxBuffer[7];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[8] = rxBuffer[8];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[9] = rxBuffer[9];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[10] = rxBuffer[10];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[11] = rxBuffer[11];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[12] = rxBuffer[12];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[13] = rxBuffer[13];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[14] = rxBuffer[14];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[15] = rxBuffer[15];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				//End of key-copy

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off PC2 end of key loading
				send_bytes(16, keyLoadingAES); // Transmit back loaded key via UART
				break;


			/////Fault Injection commands/////

			//Infinite loop for FI (has a NOP sled after the infinite loop)
			case CMD_INFINITE_FI_LOOP:
				BEGIN_INTERESTING_STUFF;
				while (1) {
					oled_sendchar('.');
					busyWait1 = 0;
					while (busyWait1 < 84459459) busyWait1++; //Roughly 0.5 seconds @ 168MHz
					oled_sendchar(' ');
					busyWait1 = 0;
					while (busyWait1 < 84459459) busyWait1++; //Roughly 0.5 seconds @ 168MHz
				}
				//Small NOP sled
				__asm __volatile__("mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						);
				END_INTERESTING_STUFF;
				send_char('G');send_char('l');send_char('i');send_char('t');send_char('c');send_char('e');send_char('d');send_char('!');
				break;

			//Loop test command for FI
			case CMD_LOOP_TEST_FI: {
				volatile int upCounter = 0;
				payload_len = 0;
				get_char(&tmp); // Receive payload length, expect MSByte first, 16bit counter max
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				BEGIN_INTERESTING_STUFF;
				while (payload_len) {
					payload_len--;
					upCounter++;
				}
				END_INTERESTING_STUFF;
				send_char(0xA5);
				send_char((payload_len>>8)&0x000000FF); //MSB first
				send_char( payload_len    &0x000000FF);
				send_char((upCounter>>8)  &0x000000FF);
				send_char( upCounter      &0x000000FF);
				send_char(0xA5);
				break;
			}

			//Password check - single check for Fault Injection
			case CMD_SINGLE_PWD_CHECK_FI: {
				volatile int charsOK = 0;
				authenticated = 0;
				get_bytes(4, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				//Small delay to have a bit of time between trigger to glitch
				__asm __volatile__("mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						);
				for (i = 0;i < 4; i++) {
					if (rxBuffer[i] == password[i]) {
						charsOK = charsOK + 1;
					}
				}
				if (charsOK == 4) {
					authenticated=AUTH_OK;
					send_char(0x90);send_char(0x00);
				} else {
					send_char(0x69);send_char(0x86);
				}
				END_INTERESTING_STUFF;
				break;
			}

			//Password check - double check for Fault Injection
			case CMD_DOUBLE_PWD_CHECK_FI: {
				volatile int charsOK = 11; //Changed the default value of zero to make it a bit harder to glitch
				authenticated = 0;
				get_bytes(4, rxBuffer);
				BEGIN_INTERESTING_STUFF;
				//Small delay to have a bit of time between trigger to glitch
				__asm __volatile__("mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						);
				for (i = 0; i < 4; i++) {
					if (rxBuffer[i] == password[i]) {
						charsOK = charsOK + 11;
					}
				}
				if (charsOK == 55) {
					//Spacing to avoid that a single glitch does not bypass the two checks
					__asm __volatile__("mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							);

					if ( ((*(uint32_t*)(rxBuffer))^(*(uint32_t*)(password))) != 0) { //Second check is a different one (uses a XOR of the 2 passwords of 4 chars)
						authenticated=0;
						send_char(0x69);send_char(0x86);
					} else {
						authenticated=AUTH_OK;
						send_char(0x90);send_char(0x00);
					}
				} else {
					send_char(0x69);send_char(0x00);
				}
				END_INTERESTING_STUFF;
				break;
			}

			//Software DES encryption with a double check (for Advanced FI DFA scenarios)
			case CMD_SWDES_ENCRYPT_DOUBLECHECK:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				//Copy the plaintext twice to perform two encryptions
				for(i=0;i<8;i++){
					rxBuffer[8+i]=rxBuffer[i];
				}
				BEGIN_INTERESTING_STUFF;
				des(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				des(keyDES, rxBuffer+8, ENCRYPT); // Perform second software DES encryption
				END_INTERESTING_STUFF;
				//Compare the two encrypted texts; if same, transmit them, otherwise send nothing
				if(memcmp(rxBuffer,rxBuffer+8, (unsigned int) 8)==0){
					send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				}
				else{
					//Do not transmit anything
				}
				break;

			//AES128 SW encryption with a double check (for Advanced FI DFA scenarios)
			case CMD_SWAES128_ENCRYPT_DOUBLECHECK:{
				uint8_t decrypted_input[16];
				get_bytes(16, rxBuffer); // Receive AES plaintext
				rijndaelSetupDecrypt(keyScheduleAES, keyAES, 128); //Prepare T-Tables AES key schedule for double check

				//Encrypt with textbook AES128 for easing the glitch
				AES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				//Decrypt with T-Tables AES for speed
				rijndaelDecrypt(keyScheduleAES, 10, rxBuffer + AES128LENGTHINBYTES, decrypted_input); // Perform software AES decryption

				//If decrypted txt is the same as the original txt, send the ciphertext; otherwise send nothing
				if(memcmp(decrypted_input, rxBuffer, (unsigned int) 16)==0){
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				}
				else{
					//Do not transmit anything
				}
				break;
			}

			///// TRNG //////
			case CMD_GET_RANDOM_FROM_TRNG:{
				volatile uint32_t randomNumber;
				RNG_Enable();
				//Get a random number
				BEGIN_INTERESTING_STUFF;
				while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
				randomNumber=RNG_GetRandomNumber();
				END_INTERESTING_STUFF;
				RNG_Disable();
				send_char((randomNumber>>24)&0x000000FF); //MSB first
				send_char((randomNumber>>16)&0x000000FF);
				send_char((randomNumber>> 8)&0x000000FF);
				send_char( randomNumber     &0x000000FF);
				break;
				}

			//Send stm32f4 chip UID via I/O interface
			case CMD_UID_VIA_IO:
				BEGIN_INTERESTING_STUFF;
				uint32_t uidBlock1 = STM32F4ID[0];
				uint32_t uidBlock2 = STM32F4ID[1];
				uint32_t uidBlock3 = STM32F4ID[2];
				END_INTERESTING_STUFF;
				send_char((uidBlock1>>24)&0x000000FF); //MSB first
				send_char((uidBlock1>>16)&0x000000FF);
				send_char((uidBlock1>> 8)&0x000000FF);
				send_char( uidBlock1     &0x000000FF);
				send_char((uidBlock2>>24)&0x000000FF); //MSB first
				send_char((uidBlock2>>16)&0x000000FF);
				send_char((uidBlock2>> 8)&0x000000FF);
				send_char( uidBlock2     &0x000000FF);
				send_char((uidBlock3>>24)&0x000000FF); //MSB first
				send_char((uidBlock3>>16)&0x000000FF);
				send_char((uidBlock3>> 8)&0x000000FF);
				send_char( uidBlock3     &0x000000FF);
				break;

#endif // VARIANT_PQC

			//Code version command: returns code version string (8 bytes, "Ver x.x" ASCII encoded) on code revision 2.0 or higher, "BadCmd" on code revision 1.0
			case CMD_GET_CODE_REV:
				send_bytes(8, codeVersion);
				break;

			//Change clock speed on-the-fly and restart peripherals; predefined speeds are 16, 30, 84 and 168MHz. If parameter is not in this list, speed will be set to 168MHz by default.
			case CMD_CHANGE_CLK_SPEED:
				get_char(&tmp);
				setClockSpeed(tmp);
				send_char(clockspeed);
				break;

			//Change clock source to external. The argument specifies whether the clock is used directly (value = 0), or through the PLL (value != 0)
			case CMD_SET_EXTERNAL_CLOCK:
				get_char(&tmp);
				setExternalClock(tmp);
				send_char(clockSource);
				break;

			//Unknown command byte: return error or 4 times (0x90 0x00) if board was glitched during boot or an hex sequence if authenticated is set to AUTH_OK
			default:

#ifdef VARIANT_PQC
				send_bytes(8, cmdByteIsWrong);
				break;

#else
				BEGIN_INTERESTING_STUFF;
				if (glitchedBoot) {
					for (i = 0; i < 4; i++){
						send_char(0x90);
						send_char(0x00);
					}
				}
				else if(authenticated==AUTH_OK){ //This will be the answer if the authenticated flag is set to AUTH_OK
					send_char(0xC0);
					send_char(0xBF);
					send_char(0xEF);
					send_char(0xEE);
					send_char(0xBA);
					send_char(0xDB);
					send_char(0xAB);
					send_char(0xEE);
				}
				else{
					send_bytes(8, cmdByteIsWrong);
				}
				END_INTERESTING_STUFF;
				break;

#endif // VARIANT_PQC

		}
	}

	//If we glitch the board out of the main loop, it will end up here (target will loop forever sending bytes 0xFA, 0xCC)
	while (1) {
		send_bytes(2, glitched);
	}
	return 0;
}

////////////////////////////////////////////////////
//            END OF MAIN FUNCTION                //
////////////////////////////////////////////////////



///////////////////////////
//FUNCTION IMPLEMENTATION//
///////////////////////////

//init(): system initialization, pin configuration and system tick configuration for timers
void init() {
	/* STM32F4 GPIO ports */

	GPIO_InitTypeDef GPPortA,GPPortC,GPPortF, GPPortH;

	//PA9: IO configuration pin. Jumper between VBUS, PA9
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOA, ENABLE);
	GPPortA.GPIO_Pin =  GPIO_Pin_9;
	GPPortA.GPIO_Mode = GPIO_Mode_IN;
	GPPortA.GPIO_OType = GPIO_OType_PP;
	GPPortA.GPIO_Speed = GPIO_Speed_50MHz;
	GPPortA.GPIO_PuPd = GPIO_PuPd_DOWN;
	GPIO_Init(GPIOA, &GPPortA);

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, ENABLE);
	GPPortF.GPIO_Pin = GPIO_Pin_2 | GPIO_Pin_4 | GPIO_Pin_5 | GPIO_Pin_6 | GPIO_Pin_8| GPIO_Pin_9;
	GPPortF.GPIO_Mode = GPIO_Mode_OUT;
	GPPortF.GPIO_OType = GPIO_OType_PP;
	GPPortF.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortF.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOF, &GPPortF);

	//DEFAULT TRIGGER PIN IS PC2; utility functions defined in stm32f4xx_gpio.c in functions set_trigger() and clear_trigger() functions
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
	GPPortC.GPIO_Pin = GPIO_Pin_1 | GPIO_Pin_2;
	GPPortC.GPIO_Mode = GPIO_Mode_OUT;
	GPPortC.GPIO_OType = GPIO_OType_PP;
	GPPortC.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortC.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOC, &GPPortC);

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, ENABLE);
	GPPortH.GPIO_Pin = GPIO_Pin_2 | GPIO_Pin_3;
	GPPortH.GPIO_Mode = GPIO_Mode_OUT;
	GPPortH.GPIO_OType = GPIO_OType_PP;
	GPPortH.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortH.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOH, &GPPortH);
	/* Setup SysTick or crash */
	if (SysTick_Config(SystemCoreClock / 1000)) {
		CrashGracefully();
	}

	/* Enable CRYP clock for hardware crypto; */
#ifdef HW_CRYPTO_PRESENT
	RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_CRYP, ENABLE);
#endif

	/* Setup USB virtual COM port if enabled; otherwise disable as it generates noise in the power lines */
	usbSerialEnabled = GPIO_ReadInputDataBit(GPIOA, GPIO_Pin_9);
	if (usbSerialEnabled) {
	USBD_Init(&USB_OTG_dev_main,
			USB_OTG_FS_CORE_ID,
			&USR_desc,
			&USBD_CDC_cb,
			&USR_cb);
	}

}

//usart_init: configures the usart3 interface
void usart_init(void) {
	/* USART3 configured as follows:
	 - BaudRate = 115200 baud
	 - Word Length = 8 Bits
	 - One Stop Bit
	 - No parity
	 - Hardware flow control disabled (RTS and CTS signals)
	 - Receive and transmit enabled
	 - PC10 TX pin, PC11 RX pin
	 */
	GPIO_InitTypeDef GPIO_InitStructure;
	USART_InitTypeDef USART_InitStructure;

	/* Enable GPIO clock */
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);

	/* Enable UART clock */
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);

	/* Connect PXx to USARTx_Tx*/
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource10, GPIO_AF_USART3);

	/* Connect PXx to USARTx_Rx*/
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource11, GPIO_AF_USART3);

	/* Configure USART Tx as alternate function  */
	GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;

	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_Init(GPIOC, &GPIO_InitStructure);

	/* Configure USART Rx as alternate function  */
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_11;
	GPIO_Init(GPIOC, &GPIO_InitStructure);

	USART_InitStructure.USART_BaudRate = 115200;
	USART_InitStructure.USART_WordLength = USART_WordLength_8b;
	USART_InitStructure.USART_StopBits = USART_StopBits_1;
	USART_InitStructure.USART_Parity = USART_Parity_No;
	USART_InitStructure.USART_HardwareFlowControl =
			USART_HardwareFlowControl_None;
	USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;

	/* USART configuration */
	USART_Init(USART3, &USART_InitStructure);

	/* Enable USART */
	USART_Cmd(USART3, ENABLE);

}

//oled_init: configures the SPI2 interface with associated GPIO pins for SS, data/cmd# and reset lines
void oled_init(){
	/* Pins used by SPI2 & GPIOs for SSD1306 OLED display
	 * PB13 = SCK == blue wire to SSD1306 OLED display
	 * PB14 = MISO == nc
	 * PB15 = MOSI == green wire to SSD1306 OLED display
	 * PF4  = SS == white wire to SSD1306 OLED display
	 * PF5 = data/cmd# line of SSD1306 OLED display == yellow wire to SSD1306 OLED display
	 * PF8 = reset line of SSD1306 OLED display == orange wire to SSD1306 OLED display
	 *
	 */
	//Enable clock for GPIO pins for SPI
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOB, ENABLE);

	GPIO_InitTypeDef GPIO_InitStruct;
	GPIO_InitStruct.GPIO_Pin = GPIO_Pin_13 | GPIO_Pin_14|GPIO_Pin_15;
	GPIO_InitStruct.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStruct.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStruct.GPIO_Speed = GPIO_Speed_100MHz;
	GPIO_InitStruct.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_Init(GPIOB, &GPIO_InitStruct);

	RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);
	SPI_InitTypeDef SPI_InitTypeDefStruct;

	SPI_InitTypeDefStruct.SPI_BaudRatePrescaler = SPI_BaudRatePrescaler_2; //APB1 bus speed=(168/4)=42MHz; SPI speed with prescaler 2-> (42/4)=21MHz
	SPI_InitTypeDefStruct.SPI_Direction = SPI_Direction_1Line_Tx;
	SPI_InitTypeDefStruct.SPI_Mode = SPI_Mode_Master;
	SPI_InitTypeDefStruct.SPI_DataSize = SPI_DataSize_8b;
	SPI_InitTypeDefStruct.SPI_NSS = SPI_NSS_Soft;
	SPI_InitTypeDefStruct.SPI_FirstBit = SPI_FirstBit_MSB;
	SPI_InitTypeDefStruct.SPI_CPOL = SPI_CPOL_Low;
	SPI_InitTypeDefStruct.SPI_CPHA = SPI_CPHA_1Edge;
	// connect SPI1 pins to SPI alternate function
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource13 , GPIO_AF_SPI2);
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource14, GPIO_AF_SPI2);
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource15 , GPIO_AF_SPI2);
	SPI_Init(SPI2, &SPI_InitTypeDefStruct);
	SPI_Cmd(SPI2, ENABLE);

	//SPI interface and GPIO pins are configured: reset the OLED display
	oled_reset();
}

//////Interrupt Handlers/////////

void SysTick_Handler(void) {
	ticker++;
	if (downTicker > 0) {
		downTicker--;
	}
}
//Debugging: Hard error management
void HardFault_Handler(void) {CrashGracefully();}
void MemManage_Handler(void) {CrashGracefully();}
void BusFault_Handler(void) {CrashGracefully();}
void UsageFault_Handler(void) {CrashGracefully();}


////////I/O utility functions (UART, serial over USB)////////////

//System functions: disable/enable

//Wrapper functions for UART / serial over USB
//get_bytes: get an amount of nbytes bytes from IO interface into byte array ba
void get_bytes(uint32_t nbytes, uint8_t* ba) {
	if (usbSerialEnabled) {
		get_bytes_usb(nbytes,ba);
	} else {
		get_bytes_uart(nbytes,ba);
	}
}

//send_bytes: send an amount of nbytes bytes from byte array ba via IO interface
void send_bytes(uint32_t nbytes, const uint8_t *ba) {
	if (usbSerialEnabled) {
		send_bytes_usb(nbytes,ba);
	} else {
		send_bytes_uart(nbytes,ba);
	}
}

//get_char: receive a byte via IO interface
void get_char(uint8_t *ch) {
	if (usbSerialEnabled) {
		get_char_usb(ch);
	} else {
		get_char_uart(ch);
	}
}

// read_char: receive a byte via IO interface
uint8_t read_char() {
	uint8_t result;
	get_char(&result);
	return result;
}

//send_char: send a byte via IO interface
void send_char(uint8_t ch) {
	if (usbSerialEnabled) {
		send_char_usb(ch);
	} else {
		send_char_uart(ch);
	}
}

//UART IO
//get_bytes: get an amount of nbytes bytes from uart into byte array ba
void get_bytes_uart(uint32_t nbytes, uint8_t *ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		while ((USART3->SR & USART_SR_RXNE) == 0);

		ba[i] = (uint8_t) USART_ReceiveData(USART3);
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via uart
void send_bytes_uart(uint32_t nbytes, const uint8_t *ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		while (!(USART3->SR & USART_SR_TXE));

		USART_SendData(USART3, ba[i]);
	}
}

//get_char: receive a byte via uart
void get_char_uart(uint8_t *ch) {
	while ((USART3->SR & USART_SR_RXNE) == 0);

	*ch = (uint8_t) USART_ReceiveData(USART3);
}

//send_char: send a byte via uart
void send_char_uart(uint8_t ch) {
	while (!(USART3->SR & USART_SR_TXE));

	USART_SendData(USART3, ch);
}

//Serial over USB communication functions
//get_bytes: get an amount of nbytes bytes into byte array ba via usb com port
void get_bytes_usb(uint32_t nbytes, uint8_t *ba) {
	int i;
	uint8_t tmp;
	for (i = 0; i < nbytes; i++) {
		tmp = 0;
		while (!VCP_get_char(&tmp));

		ba[i] = tmp;
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via usb com port
void send_bytes_usb(uint32_t nbytes, const uint8_t *ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		VCP_put_char(ba[i]);
	}

}
//get_char: receive a byte over usb com port
void get_char_usb(uint8_t *ch) {
	uint8_t tmp=0;
	while (!VCP_get_char(&tmp));

	*ch = tmp;
}
//send_char: send a byte over usb com port
void send_char_usb(uint8_t ch) {
	VCP_put_char(ch);
}

//USB IRQ handlers
void OTG_FS_IRQHandler(void)
{
	if (usbSerialEnabled) {
		USBD_OTG_ISR_Handler (&USB_OTG_dev_main);
	}
}

void OTG_FS_WKUP_IRQHandler(void)
{
	if (usbSerialEnabled) {
		if (USB_OTG_dev_main.cfg.low_power) {
			*(uint32_t *)(0xE000ED10) &= 0xFFFFFFF9;
			SystemInit();
			USB_OTG_UngateClock(&USB_OTG_dev_main);
		}
		EXTI_ClearITPendingBit(EXTI_Line18);
	}
}

/////Debug functions for your own code (e.g. RSA implementations)////////
void readByteFromInputBuffer(uint8_t *ch, int* charIdx) {
	*ch = rxBuffer[*charIdx];
	(*charIdx)++;
}

void CrashGracefully(void) {
	//Put anything you would like here to happen on a hard fault
	GPIOF->BSRRH = GPIO_Pin_6; //Example handler: PF6 enabled
}

/////Clock handling functions////////

//// Functions to change on-the-fly the clockspeed; supported speeds: 30, 84 and 168MHz ////
void setClockSpeed(uint8_t speed) {
	uint16_t timeout;

	// Enable HSI clock and switch to it while we mess with the PLLs
	RCC->CR |= RCC_CR_HSION;
	timeout = 0xFFFF;
	while (!(RCC->CR & RCC_CR_HSIRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSI;

	//Disable PLL, reconfigure settings, enable again PLL
	RCC->CR &= ~RCC_CR_PLLON;
	switch (speed) {	//PLLs config: HSE as ext. clk source, plls values for M,N,P,Q
		case 30:
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 240, 8, 5); clockspeed=30;
			break;
		case 84:
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 4, 7); clockspeed=84;
			break;
		case 168:
		default: //If incorrect value, we also set speed to 168MHz and return that clockspeed is 168MHz
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 2, 7);clockspeed=168;
			break;
	}
	RCC->CR |= RCC_CR_PLLON;

	//Wait for PLL and switch back to it
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_PLLRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_PLL;

	//Update system core clockspeed for peripherals to set configurations properly
	SystemCoreClockUpdate();

	//Reinitialize peripherals because changing the RCC_PLLConfig has messed up all the clocking
	init();
	if (!usbSerialEnabled) {
		usart_init();
	}

	clockSource = (RCC->CFGR & RCC_CFGR_SWS) >> 2;

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}

//switch clock to external clock supply
void setExternalClock(uint8_t source) {
	uint16_t timeout;

	// Enable HSI clock and switch to it while we mess with the PLLs
	RCC->CR |= RCC_CR_HSION;
	timeout = 0xFFFF;
	while (!(RCC->CR & RCC_CR_HSIRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSI;

	//Disable PLL and HSE
	RCC->CR &= ~RCC_CR_PLLON;
	RCC->CR &= ~RCC_CR_HSEON;

	setBypass();
	clockspeed = 8;
	if (source != 0) {
		setPLL();
		clockspeed = 168;
	}

	//Update system core clock speed for peripherals to set configurations properly
	SystemCoreClockUpdate();

	//Reinitialize peripherals because changing the clock source has messed up all the clocking
	init();
	if (!usbSerialEnabled) {
		usart_init();
	}

	clockSource = (RCC->CFGR & RCC_CFGR_SWS) >> 2;

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}


//Function to bypass the internal clock system with an external clock source
void setBypass() {
	uint16_t timeout;

	//Enable HSE bypass
	RCC->CR |= RCC_CR_HSEBYP;
	//Enable HSE
	RCC->CR |= RCC_CR_HSEON;

	//Wait for HSE and set it as the clock source
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_HSERDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSE;
}


//Function to reconfigure the internal PLLs
void setPLL() {
	uint16_t timeout;

	//disable PLL
	RCC->CR &= ~RCC_CR_PLLON;
	//reconfigure settings for 168 MHz
	RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 2, 7);
	//re-enable PLL
	RCC->CR |= RCC_CR_PLLON;

	//Wait for PLL and set it as the clock source
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_PLLRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_PLL;
}


//Disable peripheral clocks for RSA implementation
void disable_clocks() {
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, DISABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, DISABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, DISABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, DISABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, DISABLE);
}

//Enable peripheral clocks for RSA implementation
void enable_clocks() {
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
}

void fillBufferWithRandomNumbers(uint32_t nbytes, uint8_t* ba){
	uint32_t randomNumber;
	uint32_t i;
	for(i=0;i<nbytes;i+=4){
		//Get a random number
		while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
		randomNumber= RNG_GetRandomNumber();
		ba[i]=((randomNumber>>24)&0x000000FF); //MSB first
		if((i+1)<nbytes){
			ba[i+1]=((randomNumber>>16)&0x000000FF);
		}
		if((i+2)<nbytes){
			ba[i+2]=((randomNumber>>8)&0x000000FF);
		}
		if((i+3)<nbytes){
			ba[i+3]=(randomNumber&0x000000FF);
		}
	}
	//Extra check so that byte 19 is not zeroes (otherwise anssi aes breaks!!)
	if(nbytes>18){
		if(ba[18]==0x00){
			while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
			randomNumber= RNG_GetRandomNumber();
			ba[18]=(randomNumber&0x000000FF);
		}
	}

}
