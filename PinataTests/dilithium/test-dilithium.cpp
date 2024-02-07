#include "test-dilithium.hpp"
#include <optional>


extern "C" {
#include "../PQClean/crypto_sign/dilithium3/clean/api.h"
}

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


DilithiumGlobalState::DilithiumGlobalState() {
    // Ensure we're talking to a modern Pinata
    std::cout << "reading pinata device version...\n";
    const auto [deviceMajorVersion, deviceMinorVersion] = pinata.getVersion();
    if (deviceMajorVersion != PinataVersionMajor) {
        throw std::runtime_error("expected pinata major version 3");
    }
    if (deviceMinorVersion != PinataVersionMinor) {
        throw std::runtime_error("expected pinata minor version 2");
    }

    // Ensure the mode is the same
    std::cout << "ensuring dilithium modes agree\n";
    if (pinata.dilithiumGetSecurityLevel() != 3) {
        throw std::runtime_error("pinata dilithium mode is not equal to " + std::to_string(3));
    }

    // Ensure public and private key sizes match
    std::cout << "ensuring dilithium public and private key sizes agree\n";
    const auto [pinataPublicKeySize, pinataPrivateKeySize] = pinata.dilithiumGetKeySizes();
    if (pinataPublicKeySize != PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        throw std::runtime_error("mismatching public key sizes (pinata: " + std::to_string(pinataPublicKeySize) +
                                 ", reference impl: " + std::to_string(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES) + ")");
    }
    if (pinataPrivateKeySize != PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES) {
        throw std::runtime_error("mismatching private key sizes (pinata: " + std::to_string(pinataPrivateKeySize) +
                                 ", reference impl: " + std::to_string(PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES) + ")");
    }

    // Generate a public/private key pair with the reference X86 implementation
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(m_publicKey.data(), m_privateKey.data());

    // Tell the pinata to use this public/private key pair for signing with Dilithium3
    std::cout << "setting public and private key on Pinata (public key size: " << std::dec << PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES
              << ", private key size: " << PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES << ")\n";
    pinata.dilithiumSetPublicPrivateKeyPair(m_publicKey.data(), m_publicKey.size(), m_privateKey.data(), m_privateKey.size());
}

std::optional<DilithiumGlobalState> dg_state;

std::array<unsigned char, DILITHIUM_MESSAGE_SIZE> message;
std::array<unsigned char, PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES + DILITHIUM_MESSAGE_SIZE> pinataSignedMessage;
std::array<unsigned char, PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES + DILITHIUM_MESSAGE_SIZE> referenceSignedMessage;


extern "C" int TestDilithiumOneInput(const uint8_t *data, size_t size) {

    // ensure global state object is initialized
    if (!dg_state.has_value()) {
        std::cout << "setting up global state\n";
        dg_state.emplace();
        std::cout << "created state\n";
    }

    // Prepare the fuzzed message
    std::fill(pinataSignedMessage.begin(), pinataSignedMessage.end(), (unsigned char)0);
    std::fill(message.begin(), message.end(), (unsigned char)0);
    std::copy(data, data + std::min(message.size(), size), message.begin());
    std::cout << "message: " << message << '\n';

    // Sign the fuzzed message on pinata
    dg_state->pinata.dilithiumSign(message.data(), message.size(), pinataSignedMessage.data(), PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES);
    // Concatenate the signature and the fuzzed message together to obtain a "signed message"
    assert(pinataSignedMessage.size() == PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES + message.size());

    std::copy(message.begin(), message.end(), pinataSignedMessage.data() + PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES);
    // The message should be at the end of the signed message buffer
    assert(std::memcmp(pinataSignedMessage.data() + PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES, message.begin(), 16) == 0);
    
    // Sign the fuzzed message with the X86 reference implementation.
    // The reference implementation doesn't use randomized signatures.
    unsigned long messageLength = static_cast<unsigned long>(pinataSignedMessage.size());
    PQCLEAN_DILITHIUM3_CLEAN_crypto_sign(referenceSignedMessage.data(), &messageLength, message.data(), message.size(),
                              dg_state->getPrivateKey().data());
    
    assert(messageLength == referenceSignedMessage.size());

    // Pinata sign --> Reference verify
    assert(PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_open(pinataSignedMessage.data(), &messageLength, pinataSignedMessage.data(),
                                          pinataSignedMessage.size(), dg_state->getPublicKey().data()) == 0);
    
    // Reference sign --> Pinata verify
    assert(dg_state->pinata.dilithiumVerify(referenceSignedMessage.data(), referenceSignedMessage.size()));

    return 0;
}
