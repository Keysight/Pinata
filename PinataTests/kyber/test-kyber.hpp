#pragma once

#include <boost/algorithm/hex.hpp>
#include "../utilities/common.hpp"

#define KYBER512_PUBLIC_KEY_SIZE 800
#define KYBER512_PRIVATE_KEY_SIZE 1632
#define KYBER512_SHARED_SECRET_SIZE 32
#define KYBER512_CIPHERTEXT_SIZE 768

class KyberGlobalState {
  public:
    KyberGlobalState();
    const std::array<unsigned char, KYBER512_PUBLIC_KEY_SIZE> &getPublicKey() const noexcept { return m_publicKey; }
    const std::array<unsigned char, KYBER512_PRIVATE_KEY_SIZE> &getPrivateKey() const noexcept { return m_privateKey; }
    PinataClient pinata;

  private:
    std::array<unsigned char, KYBER512_PUBLIC_KEY_SIZE> m_publicKey;
    std::array<unsigned char, KYBER512_PRIVATE_KEY_SIZE> m_privateKey;
};

extern "C" int TestKyberOneInput(const uint8_t *data, size_t size);
