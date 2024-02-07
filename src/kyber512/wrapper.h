#ifndef _KYBER512_WRAPPER_H_
#define _KYBER512_WRAPPER_H_

#include <stdint.h>
#include <stddef.h>

#define KYBER512_PUBLIC_KEY_SIZE 800
#define KYBER512_PRIVATE_KEY_SIZE 1632
#define KYBER512_SHARED_SECRET_SIZE 32
#define KYBER512_CIPHERTEXT_SIZE 768

/**
 * Simple object-oriented wrapper around the various Dilithium functions.
 * All "methods" start with the prefix "Kyber512State_".
 */
typedef struct Kyber512State_t {
	uint8_t m_publicKey[KYBER512_PUBLIC_KEY_SIZE];
	uint8_t m_privateKey[KYBER512_PRIVATE_KEY_SIZE];
	uint8_t m_sharedSecretBuffer[KYBER512_SHARED_SECRET_SIZE];
	uint8_t m_keyEncapsulationMessageBuffer[KYBER512_CIPHERTEXT_SIZE];
} Kyber512State;

/**
 * Get or set the private key bytes. The buffer returned by this method has
 * size KYBER512_PRIVATE_KEY_SIZE.
 */
uint8_t* Kyber512State_getPrivateKey(Kyber512State* self);

/**
 * Get or set the public key bytes. The buffer returned by this method has size
 * KYBER512_PUBLIC_KEY_SIZE.
 */
uint8_t* Kyber512State_getPublicKey(Kyber512State* self);

/**
 * Get or set the shared secret. The buffer returned by this method has size
 * KYBER512_SHARED_SECRET_SIZE.
 */
uint8_t* Kyber512State_getSharedSecretBuffer(Kyber512State* self);

/**
 * Get or set the key encapsulation message. The buffer returned by this method
 * has size KYBER512_CIPHERTEXT_SIZE.
 */
uint8_t* Kyber512State_getKeyEncapsulationMessageBuffer(Kyber512State* self);

/**
 * Generate a shared secret, as well as an accompanying key encapsulation
 * message (the ciphertext) that is to be sent over a hypothetical public
 * channel.
 * 
 * The generated shared secret can be retrieved via the
 * Kyber512State_getSharedSecretBuffer method.
 * 
 * The key encapsulation message can be retrieved via the
 * Kyber512State_getKeyEncapsulationMessageBuffer method.
 */
int Kyber512State_generate(Kyber512State* self);

/**
 * Decode the key encapsulation message into a shared secret, using the
 * key encapsulation message that was written to the buffer pointed to by
 * Kyber512State_getKeyEncapsulationMessageBuffer.
 * 
 * The shared secret can be retrieved via the
 * Kyber512State_getSharedSecretBuffer method.
 */
int Kyber512State_decode(Kyber512State* self);

#endif // _KYBER512_WRAPPER_H_
