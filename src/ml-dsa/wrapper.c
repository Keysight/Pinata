#include "./wrapper.h"
#include "./params.h"
#include "./api.h"
#include "./sign.h"
#include "./poly.h"
#include <string.h>

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

int getMldsaAlgorithmVariant() {
	return MLDSA_MODE;
}

uint8_t* MldsaState_getPrivateKey(MldsaState* self) {
	return self->m_sk;
}

uint8_t* MldsaState_getPublicKey(MldsaState* self) {
	return self->m_pk;
}

uint8_t* MldsaState_getScratchPad(MldsaState* self) {
	return self->m_scratchpad;
}

int MldsaState_verify(const MldsaState* self, uint8_t *signedMessage) {
	size_t messageLength = MLDSA_MESSAGE_SIZE;
	return crypto_sign_open(signedMessage, &messageLength, signedMessage, MLDSA_SIGNED_MESSAGE_SIZE, self->m_pk);
}

int MldsaState_sign(const MldsaState* self, uint8_t* signature, const uint8_t* message) {
	size_t signatureSize = MLDSA_SIGNATURE_SIZE;
	return crypto_sign_signature(signature, &signatureSize, message, MLDSA_MESSAGE_SIZE, self->m_sk);
}

int Mldsa_ntt(uint32_t* coefficients) {
	poly* coeffs = (poly*)coefficients;
	poly_ntt(coeffs);
	return 0;
}
