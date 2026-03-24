#ifndef _MLDSA_WRAPPER_H_
#define _MLDSA_WRAPPER_H_

#include <stdint.h>
#include <stddef.h>

#define MLDSA_PUBLIC_KEY_SIZE 1952
#define MLDSA_PRIVATE_KEY_SIZE 4032
#define MLDSA_SIGNATURE_SIZE 3309
#define MLDSA_MESSAGE_SIZE 16
#define MLDSA_N 256
#define MLDSA_SIGNED_MESSAGE_SIZE (MLDSA_SIGNATURE_SIZE + MLDSA_MESSAGE_SIZE)

/**
 * @brief      Get the dilithium algorithm variant. There are a few variants and
 *             only one of them is implemented.
 *
 * @return     The dilithium algorithm variant.
 */
int getMlDsaAlgorithmVariant();

/**
 * Simple object-oriented wrapper around the various MlDsa functions.
 * All "methods" start with the prefix "MlDsaState_".
 */
typedef struct MlDsaState_t {
	uint8_t m_pk[MLDSA_PUBLIC_KEY_SIZE];
	uint8_t m_sk[MLDSA_PRIVATE_KEY_SIZE];
    uint8_t m_scratchpad[MLDSA_SIGNED_MESSAGE_SIZE];
} MlDsaState;

/**
 * @brief      Get the private key bytes.
 *
 * @param[in]  self  The object
 *
 * @return     The private key bytes.
 */
uint8_t* MlDsaState_getPrivateKey(MlDsaState* self);

/**
 * @brief      Get the public key bytes.
 *
 * @param[in]  self  The object
 *
 * @return     The public key bytes.
 */
uint8_t* MlDsaState_getPublicKey(MlDsaState* self);

/**
 * @brief      Get the "scratch pad" for message storage, signature storage.
 *
 * @param      self  The object
 *
 * @return     Pointer to the scratch pad.
 */
uint8_t* MlDsaState_getScratchPad(MlDsaState* self);

/**
 * @brief      Verify a signed message.
 *
 * @param[in]  self           The object
 * @param[in]  signature      Buffer of the signed message. This buffer MUST have
 *                            length MLDSA_SIGNATURE_SIZE + MLDSA_MESSAGE_SIZE.
 *
 * @return     0 when verification passes, non-zero otherwise.
 */
int MlDsaState_verify(const MlDsaState* self, uint8_t *signedMessage);

/**
 * @brief      Sign a message.
 *
 * @param[in]  self           The object
 * @param[out] signature      Buffer where the signature will be placed in. This
 *                            buffer MUST have length MLDSA_SIGNATURE_SIZE.
 * @param[in]  message        Buffer of the message to be signed. This buffer MUST
 *                            have length MLDSA_MESSAGE_SIZE.
 *
 * @return     0 when signing succeeds, non-zero otherwise.
 */
int MlDsaState_sign(const MlDsaState* self, uint8_t* signature, const uint8_t* message);

///
/// @brief        Perform a forward NTT.
///
/// @param[inout] coefficients  Buffer of polynomial coefficients in integer
///                             domain. The computation is done in-place, and
///                             this array contains the coefficients in the
///                             frequency domain after this function returns.
///
int MlDsa_ntt(uint32_t *coefficients);

#endif // _MLDSA_WRAPPER_H_
