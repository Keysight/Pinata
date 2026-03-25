#include "TestBase.hpp"
#include <array>
#include <gtest/gtest.h>
#include <openssl/rand.h>

extern "C" {
#include "crypto_kem/ml-kem-512/clean/api.h"
#include "crypto_sign/ml-dsa-65/clean/api.h"
}

#define MLDSA_PUBLIC_KEY_SIZE 1952
#define MLDSA_PRIVATE_KEY_SIZE 4032
#define MLDSA_SIGNATURE_SIZE 3309
#define MLDSA_MESSAGE_SIZE 16
#define MLDSA_N 256
#define MLDSA_SIGNED_MESSAGE_SIZE (MLDSA_SIGNATURE_SIZE + MLDSA_MESSAGE_SIZE)

#define MLKEM_PUBLIC_KEY_SIZE 800
#define MLKEM_PRIVATE_KEY_SIZE 1632
#define MLKEM_SHARED_SECRET_SIZE 32
#define MLKEM_CIPHERTEXT_SIZE 768

#if DILITHIUM_PUBLIC_KEY_SIZE != PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if DILITHIUM_PRIVATE_KEY_SIZE != PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES
#error invalid private key size, update me!
#endif
#if DILITHIUM_SIGNATURE_SIZE != PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES
#error invalid signature size, update me!
#endif

#if defined(MODE) && !defined(DILITHIUM_MODE)
#define DILITHIUM_MODE MODE
#endif

#if MLKEM_PUBLIC_KEY_SIZE != PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if MLKEM_PRIVATE_KEY_SIZE != PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES
#error invalid secret key size, update me!
#endif
#if MLKEM_SHARED_SECRET_SIZE != PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#error invalid secret size, update me!
#endif

class PqcFirmware : public TestBase {
    void SetUp() override {
        if (Environment::getInstance().getFirmwareVariant() != FirmwareVariant::PostQuantum) {
            GTEST_SKIP();
        }
    }
};

TEST_F(PqcFirmware, DilithiumLevel3) {
    std::array<unsigned char, MLDSA_PUBLIC_KEY_SIZE> publicKey;
    std::array<unsigned char, MLDSA_PRIVATE_KEY_SIZE> privateKey;
    std::array<unsigned char, MLDSA_MESSAGE_SIZE> message;
    std::array<unsigned char, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + MLDSA_MESSAGE_SIZE> pinataSignedMessage;
    std::array<unsigned char, PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + MLDSA_MESSAGE_SIZE> referenceSignedMessage;

    // Ensure the mode is the same
    std::cerr << "asserting security level\n";
    ASSERT_EQ(mClient.dilithiumGetSecurityLevel(), 3);

    // Ensure public and private key sizes match
    std::cerr << "checking key sizes\n";
    const auto [pinataPublicKeySize, pinataPrivateKeySize] = mClient.dilithiumGetKeySizes();
    ASSERT_EQ(pinataPublicKeySize, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    ASSERT_EQ(pinataPrivateKeySize, PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES);

    // Generate a public/private key pair with the reference X86 implementation
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(publicKey.data(), privateKey.data());

    // Tell the pinata to use this public/private key pair for signing with Dilithium3
    std::cerr << "setup public/private key pair\n";
    mClient.dilithiumSetPublicPrivateKeyPair(publicKey.data(), publicKey.size(), privateKey.data(), privateKey.size());

    // Prepare the random message
    std::fill(pinataSignedMessage.begin(), pinataSignedMessage.end(), (unsigned char)0);
    RAND_bytes(message.data(), message.size());

    // Sign the fuzzed message on pinata
    std::cerr << "sign message\n";
    mClient.dilithiumSign(message.data(), message.size(), pinataSignedMessage.data(),
                          PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);

    // Concatenate the signature and the fuzzed message together to obtain a "signed message"
    ASSERT_EQ(pinataSignedMessage.size(), PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES + message.size());
    std::copy(message.begin(), message.end(), pinataSignedMessage.data() + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES);

    // The message should be at the end of the signed message buffer
    ASSERT_EQ(std::memcmp(pinataSignedMessage.data() + PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES, message.begin(), 16), 0);

    // Sign the fuzzed message with the X86 reference implementation.
    // The reference implementation doesn't use randomized signatures.
    unsigned long messageLength = static_cast<unsigned long>(pinataSignedMessage.size());
    PQCLEAN_MLDSA65_CLEAN_crypto_sign(referenceSignedMessage.data(), &messageLength, message.data(), message.size(),
                                         privateKey.data());
    ASSERT_EQ(messageLength, referenceSignedMessage.size());

    // Pinata sign --> Reference verify
    ASSERT_EQ(PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(pinataSignedMessage.data(), &messageLength,
                                                        pinataSignedMessage.data(), pinataSignedMessage.size(),
                                                        publicKey.data()),
              0);

    // Reference sign --> Pinata verify
    std::cerr << "verify message\n";
    ASSERT_TRUE(mClient.dilithiumVerify(referenceSignedMessage.data(), referenceSignedMessage.size()));
}

TEST_F(PqcFirmware, Kyber512) {
    std::array<unsigned char, MLKEM_PUBLIC_KEY_SIZE> publicKey;
    std::array<unsigned char, MLKEM_PRIVATE_KEY_SIZE> privateKey;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES> ssPinata;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES> ssRef;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES> ssPinataGenerateRefDecode;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES> ssRefGeneratePinataDecode;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES> ssRefGenerateRefDecode;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES> ssPinataGeneratePinataDecode;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES> ctPinata;
    std::array<unsigned char, PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES> ctRef;

    // Ensure public and private key sizes match
    std::cerr << "checking wether key sizes agree\n";
    const auto [pinataPublicKeySize, pinataPrivateKeySize] = mClient.kyber512GetKeySizes();
    ASSERT_EQ(pinataPublicKeySize, PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES);
    ASSERT_EQ(pinataPrivateKeySize, PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES);

    // Generate a public/private key pair with the reference X86 implementation
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(publicKey.data(), privateKey.data());

    // Tell the pinata to use this public/private key pair for encrypting shared secrets with kyber512.
    std::cerr << "setting public private key pair\n";
    mClient.kyber512SetPublicPrivateKeyPair(publicKey.data(), publicKey.size(), privateKey.data(), privateKey.size());

    // Zero out arrays
    std::fill(ssPinataGenerateRefDecode.begin(), ssPinataGenerateRefDecode.end(), (unsigned char)0);
    std::fill(ssRefGeneratePinataDecode.begin(), ssRefGeneratePinataDecode.end(), (unsigned char)0);
    std::fill(ssRefGenerateRefDecode.begin(), ssRefGenerateRefDecode.end(), (unsigned char)0);
    std::fill(ssPinataGeneratePinataDecode.begin(), ssPinataGeneratePinataDecode.end(), (unsigned char)0);

    // Generate a shared secret on Pinata
    std::cerr << "generating shared secret\n";
    mClient.kyber512Generate(ssPinata.data(), ssPinata.size(), ctPinata.data(), ctPinata.size());

    // Generate a shared secret with the reference implementation.
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ctRef.data(), ssRef.data(), publicKey.data());

    // Decode the Pinata ciphertext with ref impl
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ssPinataGenerateRefDecode.data(), ctPinata.data(), privateKey.data());

    // Decode the ref ciphertext with ref impl
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ssRefGenerateRefDecode.data(), ctRef.data(), privateKey.data());

    // Decode the Pinata ciphertext with Pinata impl
    std::cerr << "decoding shared secret\n";
    mClient.kyber512Decode(ctPinata.data(), ctPinata.size(), ssPinataGeneratePinataDecode.data(),
                           ssPinataGeneratePinataDecode.size());

    // Decode the ref ciphertext with Pinata impl
    std::cerr << "decoding shared secret (ref)\n";
    mClient.kyber512Decode(ctRef.data(), ctRef.size(), ssRefGeneratePinataDecode.data(),
                           ssRefGeneratePinataDecode.size());

    ASSERT_EQ(ssPinata, ssPinataGeneratePinataDecode);
    ASSERT_EQ(ssPinata, ssPinataGenerateRefDecode);
    ASSERT_EQ(ssRef, ssRefGenerateRefDecode);
    ASSERT_EQ(ssRef, ssRefGeneratePinataDecode);
}
