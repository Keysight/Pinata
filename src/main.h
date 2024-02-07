#ifndef __PINATABOARD_H
#define __PINATABOARD_H

#if defined(HW_CRYPTO_PRESENT) && defined(VARIANT_PQC)
#error this combination of firmware capabilities is not supported
#endif

/////////////////////////////
//SYSTEM / CRYPTO LIBRARIES//
/////////////////////////////

//STM32F4 libraries
#include "stm32f4xx_conf.h"
#include "stm32f4xx.h"
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_exti.h"
#include "stm32f4xx_usart.h"
#include "stm32f4xx_spi.h"
#include "stm32f4xx_hash.h"

//USB libraries
#include "usbd_cdc_core.h"
#include "usbd_usr.h"
#include "usbd_desc.h"
#include "usbd_cdc_vcp.h"
#include "usb_dcd_int.h"

//Crypto libraries - software implementations
#ifndef VARIANT_PQC
#include "rsa/rsa.h"
#include "rsacrt/rsacrt.h"
#include "ecc/ecc.h"
#include "swDES/des.h"
#include "swAES/aes.h"
#include "swmAES/maes.h"
#include "swAES_Ttables/rijndael.h"
#include "swAES256/aes256.h"
#include "sm4/sm4.h"
#include "tea/tea.h"
#include "present/present.h"
#include "dilithium/wrapper.h"
#endif

//ANSSI AES - see https://github.com/ANSSI-FR/SecAESSTM32
//#include "ansiiAES/aaes.h"

//Crypto libraries - hardware implementations
#ifdef HW_CRYPTO_PRESENT
#include "stm32f4xx_cryp.h"
#endif

//SSD1306 defines & functions for OLED display
#include "ssd1306.h"

//TRNG
#include "stm32f4xx_rng.h"
#include "rng.h"

// tickers
#include "tickers.h"

// support functions
#include "debug.h"
#include "support.h"
#include "io.h"

//builtins
#include <string.h>


//Definitions for crypto operations
#define RXBUFFERLENGTH 168 //USART rx buffer for rsa plaintext, up to 168 byte
#define AES128LENGTHINBYTES 16 //128 bit == 16byte
#define MAXAESROUNDS 14 //AES256 does 14 rounds, AES 128 does 10 rounds

// Useful definitions
#define STM32F4ID ((uint32_t *)0x1FFF7A10) //Address for reading the STM32F4 unique chip ID (UID)
#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

//Pinata board crypto command bytes definition

/// Set the public and private key for the Kyber512 crypto-system.
/// The public and private key MUST be valid. No validation is
/// done by the Pinata.
///
/// Expected Input:
///   public key bytes of size KYBER512_PUBLIC_KEY_SIZE, followed by
///   private key bytes of size KYBER512_PRIVATE_KEY_SIZE.
///
/// Output:
///   One byte; the byte is always zero.
#define CMD_SW_KYBER512_SET_PUBLIC_AND_PRIVATE_KEY 0x02

/// Get the public and private key sizes.
///
/// Expected Input:
///   None
///
/// Output:
///   16-bit unsigned integer in little endian order that contains the public key size, followed by
///   16-bit unsigned integer in little endian order that contains the private key size
#define CMD_SW_KYBER512_GET_KEY_SIZES 0x03

/// Generate a shared secret, as well as an accompanying key encapsulation
/// message (the ciphertext) that is to be sent over a hypothetical public
/// channel.
///
/// The shared secret is and key encapsulation mesage are generated using the
/// public key that was set via the command
/// CMD_SW_KYBER512_SET_PUBLIC_AND_PRIVATE_KEY.
///
/// Expected Input:
///   None
///
/// Output:
///   If generation succeeded, returns a single byte with value 0, followed by
///   shared secret bytes of size KYBER512_SHARED_SECRET_SIZE, followed by
///   key encapsulation message (the ciphertext) of size KYBER512_CIPHERTEXT_SIZE
///
///   If generation failed, returns a single byte with value 1.
#define CMD_SW_KYBER512_GENERATE 0x04

/// Decrypt a key encapsulation message into a shared secret.
///
/// The shared secret is decrypted using the private key that was set via
/// CMD_SW_KYBER512_SET_PUBLIC_AND_PRIVATE_KEY.
///
/// Expected Input:
///   key encapsulation message (the ciphertext) of size KYBER512_CIPHERTEXT_SIZE
///
/// Output:
///   shared secret bytes of size KYBER512_SHARED_SECRET_SIZE
#define CMD_SW_KYBER512_DEC 0x05

#define CMD_SWDES_ENC 0x44
#define CMD_SWDES_DEC 0x45
#define CMD_SWTDES_ENC 0x46
#define CMD_SWTDES_DEC 0x47
#define CMD_SWAES128_ENC 0xAE
#define CMD_SWAES128_DEC 0xEA
#define CMD_SWAES128SPI_ENC 0xCE
#define CMD_SWAES256_ENC 0x60
#define CMD_SWAES256_DEC 0x61
#define CMD_SWDES_ENC_RND_DELAYS 0x4A
#define CMD_SWDES_ENC_RND_SBOX 0x4B
#define CMD_SWAES128_ENC_MASKED 0x73
#define CMD_SWAES128_DEC_MASKED 0x83
#define CMD_SWAES128_ENC_RNDDELAYS 0x75
#define CMD_SWAES128_ENC_RNDSBOX 0x85
#define CMD_SWSM4_ENC 0x54
#define CMD_SWSM4_DEC 0x55

#define CMD_SWSM4OSSL_ENC 0x64
#define CMD_SWSM4OSSL_DEC 0x65
#define CMD_SWTEA_ENC 0x6C
#define CMD_SWTEA_DEC 0x6D
#define CMD_SWXTEA_ENC 0x6E
#define CMD_SWXTEA_DEC 0x6F

/// Return the Dilithium algorithm variant used in this implementation.
/// The variant is one of the identifiers 1, 2, 3 or 4.
///
/// Expected Input:
///   None
///
/// Output:
///   A single byte whose value is the Dilithium variant.
#define CMD_SW_DILITHIUM_GET_VARIANT 0x90

/// Set the public and private key for the Dilithium crypto-system.
/// The public and private key MUST be valid. No validation is
/// done by the Pinata.
///
/// Expected Input:
///   public key bytes of size DILITHIUM_PUBLIC_KEY_SIZE, followed by
///   private key bytes of size DILITHIUM_PRIVATE_KEY_SIZE.
///
/// Output:
///   One byte; the byte is always zero.
#define CMD_SW_DILITHIUM_SET_PUBLIC_AND_PRIVATE_KEY 0x91

/// Verify a signed message, using the public key provided via
/// CMD_SW_DILITHIUM_SET_PUBLIC_AND_PRIVATE_KEY.
///
/// Expected Input:
///   Signature of length DILITHIUM_SIGNATURE_SIZE, followed by
///   Message of length PINATA_DILITHIUM_MESSAGE_LENGTH
///
///   (in other words, a "signed message" of size PINATA_DILITHIUM_SIGNED_MESSAGE_SIZE).
///
/// Output:
///   One byte; the byte is 0 if the signature of the message is valid,
///   non-zero otherwise.
#define CMD_SW_DILITHIUM_VERIFY 0x92

/// Sign a message, using the private key provided via
/// CMD_SW_DILITHIUM_SET_PUBLIC_AND_PRIVATE_KEY.
///
/// Expected Input:
///   message of length PINATA_DILITHIUM_MESSAGE_LENGTH bytes.
///
/// Output:
///   Signature of the message. The signature has size DILITHIUM_SIGNATURE_SIZE.
#define CMD_SW_DILITHIUM_SIGN 0x93

/// Get the public and private key sizes.
///
/// Expected Input:
///   None
///
/// Output:
///   16-bit unsigned integer in little endian order that contains the public key size, followed by
///   16-bit unsigned integer in little endian order that contains the private key size
#define CMD_SW_DILITHIUM_GET_KEY_SIZES 0x94

#define CMD_SWDES_ENC_MISALIGNED 0x14
#define CMD_SWAES128_ENC_MISALIGNED 0x1E
#define CMD_SWDES_ENC_DUMMYROUNDS 0x15
#define CMD_SWAES128_ENC_DUMMYROUNDS 0x1F

#define CMD_RSACRT1024_DEC 0xAA
#define CMD_RSASFM_DEC 0xDF
#define CMD_RSASFM_GET_LAST_KEY 0xDA
#define CMD_RSASFM_GET_HARDCODED_KEY 0xD8
#define CMD_RSASFM_SET_D 0xDB
#define CMD_RSASFM_SET_KEY_GENERATION_METHOD 0xDC
#define CMD_RSASFM_SET_IMPLEMENTATION 0xD9

#define CMD_ECC25519_SCALAR_MULT 0xEC

#define CMD_PRESENT80_ENC 0x95
#define CMD_PRESENT80_DEC 0x96
#define CMD_PRESENT128_ENC 0x97
#define CMD_PRESENT128_DEC 0x98

#define CMD_SWAES128TTABLES_ENC 0x41
#define CMD_SWAES128TTABLES_DEC 0x50

#define CMD_HWDES_ENC 0xBE
#define CMD_HWDES_DEC 0xEF
#define CMD_HWTDES_ENC 0xC0
#define CMD_HWTDES_DEC 0x01
#define CMD_HWAES128_ENC 0xCA
#define CMD_HWAES128_DEC 0xFE
#define CMD_HWAES256_ENC 0x7A
#define CMD_HWAES256_DEC 0x7E
#define CMD_HMAC_SHA1 0x4C
#define CMD_SHA1_HASH 0x27
#define CMD_MD5_HASH 0x28

#define CMD_CRYPTOLOOP 0xB1

#define CMD_GET_RANDOM_FROM_TRNG 0x11

#define CMD_TDES_KEYCHANGE 0xC7
#define CMD_DES_KEYCHANGE 0xD7
#define CMD_AES128_KEYCHANGE 0xE7
#define CMD_AES256_KEYCHANGE 0xF7
#define CMD_SM4_KEYCHANGE 0x57
#define CMD_TEA_XTEA_KEYCHANGE 0x67

#define CMD_SOFTWARE_KEY_COPY 0x38
#define CMD_INFINITE_FI_LOOP 0x99
#define CMD_LOOP_TEST_FI 0xDD
#define CMD_SINGLE_PWD_CHECK_FI 0xA2
#define CMD_DOUBLE_PWD_CHECK_FI 0xA7
#define CMD_PWD_CHANGE 0xA5
#define CMD_SWAES128_ENCRYPT_DOUBLECHECK 0x88
#define CMD_SWDES_ENCRYPT_DOUBLECHECK 0x29

#define CMD_OLED_TEST 0x30
#define CMD_UID_VIA_IO 0x1D
#define CMD_GET_CODE_REV 0xF1
#define CMD_CHANGE_CLK_SPEED 0xF2
#define CMD_SET_EXTERNAL_CLOCK 0xF3


#define CMD_UNKNOWN 0xFF

//extern STRUCT_AES aes_struct;

// USB data must be 4 byte aligned if DMA is enabled. This macro handles the alignment, if necessary
__ALIGN_BEGIN USB_OTG_CORE_HANDLE  USB_OTG_dev_main __ALIGN_END;

//Additional helper functions
void fillBufferWithRandomNumbers(uint32_t nbytes, uint8_t* ba);

// Implicit declarations
void setExternalClock(uint8_t source);
void setClockSpeed(uint8_t speed);

#endif
