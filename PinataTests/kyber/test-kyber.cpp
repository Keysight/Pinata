#include "test-kyber.hpp"
#include <optional>


extern "C" {
#include "../PQClean/crypto_kem/kyber512/clean/api.h"
}

#if KYBER512_PUBLIC_KEY_SIZE != PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if KYBER512_PRIVATE_KEY_SIZE != PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES
#error invalid secret key size, update me!
#endif
#if KYBER512_SHARED_SECRET_SIZE != PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES
#error invalid secret size, update me!
#endif


KyberGlobalState::KyberGlobalState() {
    // Ensure we're talking to a modern Pinata
    std::cout << "reading pinata device version...\n";
    const auto [deviceMajorVersion, deviceMinorVersion] = pinata.getVersion();
    if (deviceMajorVersion != PinataVersionMajor) {
        throw std::runtime_error("expected pinata major version 3");
    }
    if (deviceMinorVersion != PinataVersionMinor) {
        throw std::runtime_error("expected pinata minor version 2");
    }

    // Ensure public and private key sizes match
    std::cout << "ensuring public and private key sizes agree\n";
    const auto [pinataPublicKeySize, pinataPrivateKeySize] = pinata.kyber512GetKeySizes();
    if (pinataPublicKeySize != PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        throw std::runtime_error("mismatching public key sizes (pinata: " + std::to_string(pinataPublicKeySize) +
                                 ", reference impl: " + std::to_string(PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES) + ")");
    }
    if (pinataPrivateKeySize != PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES) {
        throw std::runtime_error("mismatching private key sizes (pinata: " + std::to_string(pinataPrivateKeySize) +
                                 ", reference impl: " + std::to_string(PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES) + ")");
    }

    // Generate a public/private key pair with the reference X86 implementation
    PQCLEAN_KYBER512_CLEAN_crypto_kem_keypair(m_publicKey.data(), m_privateKey.data());

    // Tell the pinata to use this public/private key pair for encrypting shared secrets with kyber512.
    std::cout << "setting public and private key on Pinata (public key size: " << std::dec << PQCLEAN_KYBER512_CLEAN_CRYPTO_PUBLICKEYBYTES
              << ", private key size: " << PQCLEAN_KYBER512_CLEAN_CRYPTO_SECRETKEYBYTES << ")\n";
    pinata.kyber512SetPublicPrivateKeyPair(m_publicKey.data(), m_publicKey.size(), m_privateKey.data(), m_privateKey.size());
}

std::optional<KyberGlobalState> kg_state;

std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES> ssPinata;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES> ssRef;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES> ssPinataGenerateRefDecode;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES> ssRefGeneratePinataDecode;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES> ssRefGenerateRefDecode;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_BYTES> ssPinataGeneratePinataDecode;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES> ctPinata;
std::array<unsigned char, PQCLEAN_KYBER512_CLEAN_CRYPTO_CIPHERTEXTBYTES> ctRef;


extern "C" int TestKyberOneInput(const uint8_t *data, size_t size) {
    // ensure global state object is initialized
    if (!kg_state.has_value()) {
        std::cout << "setting up global state for kyber\n";
        kg_state.emplace();
        std::cout << "created state\n";
    }

    // Zero out arrays
    std::fill(ssPinataGenerateRefDecode.begin(), ssPinataGenerateRefDecode.end(), (unsigned char)0);
    std::fill(ssRefGeneratePinataDecode.begin(), ssRefGeneratePinataDecode.end(), (unsigned char)0);
    std::fill(ssRefGenerateRefDecode.begin(), ssRefGenerateRefDecode.end(), (unsigned char)0);
    std::fill(ssPinataGeneratePinataDecode.begin(), ssPinataGeneratePinataDecode.end(), (unsigned char)0);

    // Generate a shared secret on Pinata
    kg_state->pinata.kyber512Generate(ssPinata.data(), ssPinata.size(), ctPinata.data(), ctPinata.size());

    // Generate a shared secret with the reference implementation.
    PQCLEAN_KYBER512_CLEAN_crypto_kem_enc(ctRef.data(), ssRef.data(), kg_state->getPublicKey().data());

    std::cout << "shared secret (Pinata): " << ssPinata << '\n';
    std::cout << "ciphertext (Pinata):    " << ctPinata << '\n';

    // Decode the Pinata ciphertext with ref impl
    PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ssPinataGenerateRefDecode.data(), ctPinata.data(), kg_state->getPrivateKey().data());

    // Decode the ref ciphertext with ref impl
    PQCLEAN_KYBER512_CLEAN_crypto_kem_dec(ssRefGenerateRefDecode.data(), ctRef.data(), kg_state->getPrivateKey().data());

    // Decode the Pinata ciphertext with Pinata impl
    kg_state->pinata.kyber512Decode(ctPinata.data(), ctPinata.size(), ssPinataGeneratePinataDecode.data(), ssPinataGeneratePinataDecode.size());

    // Decode the ref ciphertext with Pinata impl
    kg_state->pinata.kyber512Decode(ctRef.data(), ctRef.size(), ssRefGeneratePinataDecode.data(), ssRefGeneratePinataDecode.size());

    assert(ssPinata == ssPinataGeneratePinataDecode);
    assert(ssPinata == ssPinataGenerateRefDecode);
    assert(ssRef == ssRefGenerateRefDecode);
    assert(ssRef == ssRefGeneratePinataDecode);
    return 0;
}
