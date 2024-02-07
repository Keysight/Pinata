#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/serial_port.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/endian/conversion.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <array>
#include <cstdlib>
#include <cstring>
#include <stdint.h>

const char* getSerialPortFilePath();

constexpr const uint8_t PinataVersionMajor = 3;
constexpr const uint8_t PinataVersionMinor = 2;

extern const uint8_t defaultKeyDES[8];
extern const uint8_t defaultKeyAES[16];
extern const uint8_t defaultKeyTDES[24];
extern const uint8_t defaultKeyAES[16];
extern const uint8_t defaultKeyAES256[32];
extern const uint8_t defaultKeySM4[16];
extern const uint8_t defaultKeyPRESENT80[10];
extern const uint8_t defaultKeyPRESENT128[16];

class PinataClient {
public:
    PinataClient();
    PinataClient(const char* serialPortFile);

    std::pair<int, int> getVersion();
    std::pair<int, int> dilithiumGetKeySizes();
    uint8_t dilithiumGetSecurityLevel();
    void dilithiumSetPublicPrivateKeyPair(const uint8_t* publicKey, size_t publicKeySize, const uint8_t* privateKey, size_t privateKeySize);
    void dilithiumSign(const uint8_t* messageBuffer, size_t messageBufferSize, uint8_t* signedMessageBuffer, size_t signedMessageBufferSize);
    bool dilithiumVerify(const uint8_t* signatureBuffer, size_t signatureBufferSize);
    std::pair<int, int> kyber512GetKeySizes();
    void kyber512SetPublicPrivateKeyPair(const uint8_t* publicKey, size_t publicKeySize, const uint8_t* privateKey, size_t privateKeySize);
    void kyber512Generate(uint8_t* sharedSecretBuffer, size_t sharedSecretBufferSize, uint8_t* keyEncapsulationMessageBuffer, size_t keyEncapsulationMessageBufferSize);
    void kyber512Decode(const uint8_t* keyEncapsulationMessageBuffer, size_t keyEncapsulationMessageBufferSize, uint8_t* sharedSecretBuffer, size_t sharedSecretBufferSize);
    
    void doSymmetricCipherRequest(const uint8_t cmd, const uint8_t* input, const size_t inputSize, uint8_t* output,const size_t outputSize);
    void SWDESEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void SWDESDecrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    void SWTDESEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void SWTDESDecrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    
    void AES128SWEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES128SWDecrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES128SWEncryptNoTrigger(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES128TTablesSWEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES128TTablesSWDecrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    
    void AES256SWEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES256SWDecrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    void AES128MaskingSWEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES128MaskingSWDecrypt(const uint8_t* ciphertext, uint8_t* plaintext);
    void AES128SWRndDelaysEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);
    void AES128SWRndSBoxEncrypt(const uint8_t* plaintext, uint8_t* ciphertext);


private:
    boost::asio::io_context m_context;
    boost::asio::serial_port m_port;

    void command(uint8_t cmd);

    template <class T> void write(const T* array, const size_t size) {
        boost::asio::write(m_port, boost::asio::buffer(array, sizeof(T) * size), boost::asio::transfer_exactly(sizeof(T) * size));
    }

    void read(uint8_t *data, size_t size);

    template <class T> T readNumber() {
        T result;
        read(reinterpret_cast<uint8_t*>(&result), sizeof(result));
        return boost::endian::little_to_native(result);
    }
};

template <class T, size_t N> std::ostream &operator<<(std::ostream &os, const std::array<T, N> &arr) {
    for (size_t i = 0; i != arr.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)arr[i];
        if (i + 1 != arr.size()) {
            std::cout << ':';
        }
    }
    return os;
}
