#include "./wrapper.h"
#include "./params.h"
#include "./api.h"

#if KYBER512_PUBLIC_KEY_SIZE != KYBER_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if KYBER512_PRIVATE_KEY_SIZE != KYBER_SECRETKEYBYTES
#error invalid private key size, update me!
#endif
#if KYBER512_SHARED_SECRET_SIZE != KYBER_SSBYTES
#error invalid shared secret size, update me!
#endif
#if KYBER512_CIPHERTEXT_SIZE != KYBER_CIPHERTEXTBYTES
#error invalid key encapsulation message size, update me!
#endif

uint8_t* Kyber512State_getPrivateKey(Kyber512State* self) {
	return self->m_privateKey;
}

uint8_t* Kyber512State_getPublicKey(Kyber512State* self) {
	return self->m_publicKey;
}

uint8_t* Kyber512State_getSharedSecretBuffer(Kyber512State* self) {
	return self->m_sharedSecretBuffer;
}

uint8_t* Kyber512State_getKeyEncapsulationMessageBuffer(Kyber512State* self) {
	return self->m_keyEncapsulationMessageBuffer;
}

int Kyber512State_generate(Kyber512State* self) {
	return crypto_kem_enc(
		self->m_keyEncapsulationMessageBuffer,
		self->m_sharedSecretBuffer,
		self->m_publicKey
	);
}

int Kyber512State_decode(Kyber512State* self) {
	return crypto_kem_dec(
		self->m_sharedSecretBuffer,
		self->m_keyEncapsulationMessageBuffer,
		self->m_privateKey
	);
}
