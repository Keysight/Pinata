#include "wrapper.h"

// These includes MUST stay private to wrapper.c,
// otherwise we pollute the global namespace with equally named,
// but totally different files (api.h / param.h)
#include <params.h> // include is located in pqm4 source tree
#include <api.h>    // include is located in pqm4 source tree
#include <sign.h>   // include is located in pqm4 source tree
#include <poly.h>   // include is located in pqm4 source tree

#if MLDSA_PUBLIC_KEY_SIZE != CRYPTO_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if MLDSA_PRIVATE_KEY_SIZE != CRYPTO_SECRETKEYBYTES
#error invalid private key size, update me!
#endif
#if MLDSA_SIGNATURE_SIZE != CRYPTO_BYTES
#error invalid signature size, update me!
#endif
#if MLDSA_N != N
#error invalid N, update me!
#endif

int getMlDsaAlgorithmVariant() {
	return DILITHIUM_MODE;
}

uint8_t* MlDsaState_getPrivateKey(MlDsaState* self) {
	return self->m_sk;
}

uint8_t* MlDsaState_getPublicKey(MlDsaState* self) {
	return self->m_pk;
}

uint8_t* MlDsaState_getScratchPad(MlDsaState* self) {
	return self->m_scratchpad;
}

int MlDsaState_verify(const MlDsaState* self, uint8_t *signedMessage) {
	size_t messageLength = MLDSA_MESSAGE_SIZE;
	return crypto_sign_open(signedMessage, &messageLength, signedMessage, MLDSA_SIGNED_MESSAGE_SIZE, self->m_pk);
}

int MlDsaState_sign(const MlDsaState* self, uint8_t* signature, const uint8_t* message) {
	size_t signatureSize = MLDSA_SIGNATURE_SIZE;
	return crypto_sign_signature(signature, &signatureSize, message, MLDSA_MESSAGE_SIZE, self->m_sk);
}

int MlDsa_ntt(uint32_t* coefficients) {
	poly* coeffs = (poly*)coefficients;
	poly_ntt(coeffs);
	return 0;
}
