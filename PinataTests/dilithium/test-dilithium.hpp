#pragma once


#include <boost/algorithm/string/join.hpp>
#include "../utilities/common.hpp"


#define DILITHIUM_PUBLIC_KEY_SIZE 1952
#define DILITHIUM_PRIVATE_KEY_SIZE 4016
#define DILITHIUM_SIGNATURE_SIZE 3293
#define DILITHIUM_MESSAGE_SIZE 16
#define DILITHIUM_SIGNED_MESSAGE_SIZE (DILITHIUM_SIGNATURE_SIZE + DILITHIUM_MESSAGE_SIZE)


class DilithiumGlobalState {
public:
    DilithiumGlobalState();
    const std::array<unsigned char, DILITHIUM_PUBLIC_KEY_SIZE>& getPublicKey() const noexcept { return m_publicKey; }
    const std::array<unsigned char, DILITHIUM_PRIVATE_KEY_SIZE>& getPrivateKey() const noexcept { return m_privateKey; }
    PinataClient pinata;

private:
    std::array<unsigned char, DILITHIUM_PUBLIC_KEY_SIZE> m_publicKey;
    std::array<unsigned char, DILITHIUM_PRIVATE_KEY_SIZE> m_privateKey;
};

extern "C" int TestDilithiumOneInput(const uint8_t* data, size_t size);