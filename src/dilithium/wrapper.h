#ifndef _DILITHIUM_WRAPPER_H_
#define _DILITHIUM_WRAPPER_H_

#include <stdint.h>
#include <stddef.h>

#define DILITHIUM_PUBLIC_KEY_SIZE 1952
#define DILITHIUM_PRIVATE_KEY_SIZE 4016
#define DILITHIUM_SIGNATURE_SIZE 3293
#define DILITHIUM_MESSAGE_SIZE 16
#define DILITHIUM_SIGNED_MESSAGE_SIZE (DILITHIUM_SIGNATURE_SIZE + DILITHIUM_MESSAGE_SIZE)

/**
 * @brief      Get the dilithium algorithm variant. There are a few variants and
 *             only one of them is implemented.
 *
 * @return     The dilithium algorithm variant.
 */
int getDilithiumAlgorithmVariant();

/**
 * Simple object-oriented wrapper around the various Dilithium functions.
 * All "methods" start with the prefix "DilithiumState_".
 */
typedef struct DilithiumState_t {
	uint8_t m_pk[DILITHIUM_PUBLIC_KEY_SIZE];
	uint8_t m_sk[DILITHIUM_PRIVATE_KEY_SIZE];
    uint8_t m_scratchpad[DILITHIUM_SIGNED_MESSAGE_SIZE];
} DilithiumState;

/**
 * @brief      Get the private key bytes.
 *
 * @param[in]  self  The object
 *
 * @return     The private key bytes.
 */
uint8_t* DilithiumState_getPrivateKey(DilithiumState* self);

/**
 * @brief      Get the public key bytes.
 *
 * @param[in]  self  The object
 *
 * @return     The public key bytes.
 */
uint8_t* DilithiumState_getPublicKey(DilithiumState* self);

/**
 * @brief      Get the "scratch pad" for message storage, signature storage.
 *
 * @param      self  The object
 *
 * @return     Pointer to the scratch pad.
 */
uint8_t* DilithiumState_getScratchPad(DilithiumState* self);

/**
 * @brief      Verify a signed message.
 *
 * @param[in]  self           The object
 * @param[in]  signature      Buffer of the signed message. This buffer MUST have
 *                            length DILITHIUM_SIGNATURE_SIZE + DILITHIUM_MESSAGE_SIZE.
 *
 * @return     0 when verification passes, non-zero otherwise.
 */
int DilithiumState_verify(const DilithiumState* self, uint8_t *signedMessage);

/**
 * @brief      Sign a message.
 *
 * @param[in]  self           The object
 * @param[out] signature      Buffer where the signature will be placed in. This
 *                            buffer MUST have length DILITHIUM_SIGNATURE_SIZE.
 * @param[in]  message        Buffer of the message to be signed. This buffer MUST
 *                            have length DILITHIUM_MESSAGE_SIZE.
 *
 * @return     0 when signing succeeds, non-zero otherwise.
 */
int DilithiumState_sign(const DilithiumState* self, uint8_t* signature, const uint8_t* message);

#endif // _DILITHIUM_WRAPPER_H_
