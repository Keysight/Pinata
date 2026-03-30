#ifndef _MLKEM_WRAPPER_H_
#define _MLKEM_WRAPPER_H_

#include <stdint.h>
#include <stddef.h>

#define MLKEM_PUBLIC_KEY_SIZE 800
#define MLKEM_PRIVATE_KEY_SIZE 1632
#define MLKEM_SHARED_SECRET_SIZE 32
#define MLKEM_CIPHERTEXT_SIZE 768

/**
 * Simple object-oriented wrapper around the various Dilithium functions.
 * All "methods" start with the prefix "MlKemState_".
 */
typedef struct MlKemState_t {
	uint8_t m_publicKey[MLKEM_PUBLIC_KEY_SIZE];
	uint8_t m_privateKey[MLKEM_PRIVATE_KEY_SIZE];
	uint8_t m_sharedSecretBuffer[MLKEM_SHARED_SECRET_SIZE];
	uint8_t m_keyEncapsulationMessageBuffer[MLKEM_CIPHERTEXT_SIZE];
} MlKemState;

/**
 * Get or set the private key bytes. The buffer returned by this method has
 * size MLKEM_PRIVATE_KEY_SIZE.
 */
uint8_t* MlKemState_getPrivateKey(MlKemState* self);

/**
 * Get or set the public key bytes. The buffer returned by this method has size
 * MLKEM_PUBLIC_KEY_SIZE.
 */
uint8_t* MlKemState_getPublicKey(MlKemState* self);

/**
 * Get or set the shared secret. The buffer returned by this method has size
 * MLKEM_SHARED_SECRET_SIZE.
 */
uint8_t* MlKemState_getSharedSecretBuffer(MlKemState* self);

/**
 * Get or set the key encapsulation message. The buffer returned by this method
 * has size MLKEM_CIPHERTEXT_SIZE.
 */
uint8_t* MlKemState_getKeyEncapsulationMessageBuffer(MlKemState* self);

/**
 * Generate a shared secret, as well as an accompanying key encapsulation
 * message (the ciphertext) that is to be sent over a hypothetical public
 * channel.
 * 
 * The generated shared secret can be retrieved via the
 * MlKemState_getSharedSecretBuffer method.
 * 
 * The key encapsulation message can be retrieved via the
 * MlKemState_getKeyEncapsulationMessageBuffer method.
 */
int MlKemState_generate(MlKemState* self);

/**
 * Decode the key encapsulation message into a shared secret, using the
 * key encapsulation message that was written to the buffer pointed to by
 * MlKemState_getKeyEncapsulationMessageBuffer.
 * 
 * The shared secret can be retrieved via the
 * MlKemState_getSharedSecretBuffer method.
 */
int MlKemState_decode(MlKemState* self);

#endif // _MLKEM_WRAPPER_H_
