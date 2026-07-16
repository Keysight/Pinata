#include "wrapper.h"

// These includes MUST stay private to wrapper.c,
// otherwise we pollute the global namespace with equally named,
// but totally different files (api.h / param.h)
#include <params.h>  // include is located in pqm4 source tree
#include <api.h>     // include is located in pqm4 source tree

#if MLKEM_PUBLIC_KEY_SIZE != KYBER_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if MLKEM_PRIVATE_KEY_SIZE != KYBER_SECRETKEYBYTES
#error invalid private key size, update me!
#endif
#if MLKEM_SHARED_SECRET_SIZE != KYBER_SSBYTES
#error invalid shared secret size, update me!
#endif
#if MLKEM_CIPHERTEXT_SIZE != KYBER_CIPHERTEXTBYTES
#error invalid key encapsulation message size, update me!
#endif

uint8_t* MlKemState_getPrivateKey(MlKemState* self) {
	return self->m_privateKey;
}

uint8_t* MlKemState_getPublicKey(MlKemState* self) {
	return self->m_publicKey;
}

uint8_t* MlKemState_getSharedSecretBuffer(MlKemState* self) {
	return self->m_sharedSecretBuffer;
}

uint8_t* MlKemState_getKeyEncapsulationMessageBuffer(MlKemState* self) {
	return self->m_keyEncapsulationMessageBuffer;
}

int MlKemState_generate(MlKemState* self) {
	return crypto_kem_enc(
		self->m_keyEncapsulationMessageBuffer,
		self->m_sharedSecretBuffer,
		self->m_publicKey
	);
}

int MlKemState_decode(MlKemState* self) {
	return crypto_kem_dec(
		self->m_sharedSecretBuffer,
		self->m_keyEncapsulationMessageBuffer,
		self->m_privateKey
	);
}
