#include "common.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/impl/read.hpp>
#include <boost/asio/serial_port.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <boost/date_time/time_defs.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <cstring>
#include <numeric>
#include <openssl/bio.h>
#include <stdexcept>
#include <termios.h>
#include <unistd.h>

constexpr const size_t PINATA_DILITHIUM_MESSAGE_LENGTH = 16;
constexpr const size_t PINATA_KYBER512_SHARED_SECRET_LENGTH = 32;

const uint8_t CMD_GET_CODE_REV = 0xF1;
const uint8_t CMD_HWAES128_ENC = 0xCA;

const uint8_t CMD_SW_DILITHIUM_GET_VARIANT = 0x90;
const uint8_t CMD_SW_DILITHIUM_SET_PUBLIC_AND_PRIVATE_KEY = 0x91;
const uint8_t CMD_SW_DILITHIUM_VERIFY = 0x92;
const uint8_t CMD_SW_DILITHIUM_SIGN = 0x93;
const uint8_t CMD_SW_DILITHIUM_GET_KEY_SIZES = 0x94;

const uint8_t CMD_SW_KYBER512_SET_PUBLIC_AND_PRIVATE_KEY = 0x02;
const uint8_t CMD_SW_KYBER512_GET_KEY_SIZES = 0x03;
const uint8_t CMD_SW_KYBER512_GENERATE = 0x04;
const uint8_t CMD_SW_KYBER512_DEC = 0x05;

const uint8_t CMD_SWDES_ENC = 0x44;
const uint8_t CMD_SWDES_DEC = 0x45;
const uint8_t CMD_SWTDES_ENC = 0x46;
const uint8_t CMD_SWTDES_DEC = 0x47;
const uint8_t CMD_SWAES128_ENC = 0xAE;
const uint8_t CMD_SWAES128_DEC = 0xEA;
const uint8_t CMD_SWAES128SPI_ENC = 0xCE;
const uint8_t CMD_SWAES128TTABLES_ENC = 0x41;
const uint8_t CMD_SWAES128TTABLES_DEC = 0x50;
const uint8_t CMD_SWAES256_ENC = 0x60;
const uint8_t CMD_SWAES256_DEC = 0x61;
const uint8_t CMD_SWDES_ENC_RND_SBOX = 0x4B;
const uint8_t CMD_SWAES128_ENC_MASKED = 0x73;
const uint8_t CMD_SWAES128_DEC_MASKED = 0x83;
const uint8_t CMD_SWAES128_ENC_RNDDELAYS = 0x75;
const uint8_t CMD_SWAES128_ENC_RNDSBOX = 0x85;

const uint8_t DESLENGTHINBYTES = 8; // 64 bit == 8byte
const uint8_t AESBLOCKSIZE = 16;    // 128 bit == 16byte

const uint8_t defaultKeyDES[8] = {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef};
const uint8_t defaultKeyTDES[24] = {
    0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef}; // Default is TDES in 2key mode, DESkey1==DESkey3
const uint8_t defaultKeyAES[16] = {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef,
                                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
const uint8_t defaultKeyAES256[32] = {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02,
                                      0x03, 0x04, 0x05, 0x06, 0x07, 0xda, 0xba, 0xda, 0xba, 0xd0, 0x00,
                                      0x00, 0xc0, 0x00, 0x01, 0xc0, 0xff, 0xee, 0x55, 0xde, 0xad};

const char *getSerialPortFilePath() {
    const char *serialPortFilePath = std::getenv("SERIAL_PORT");
    if (serialPortFilePath == nullptr) {
        throw std::logic_error("SERIAL_PORT environment variable not defined; define it to point to "
                               "the serial port of the Pinata");
    }
    return serialPortFilePath;
}

PinataClient::PinataClient() : PinataClient(getSerialPortFilePath()) {}

PinataClient::PinataClient(const char *serialPortFile) : m_port(m_context, serialPortFile) {
    m_port.set_option(boost::asio::serial_port::baud_rate(115200));
    m_port.set_option(boost::asio::serial_port::character_size(boost::asio::serial_port::character_size(8)));
    m_port.set_option(boost::asio::serial_port::parity(boost::asio::serial_port::parity::none));
    m_port.set_option(boost::asio::serial_port::stop_bits(boost::asio::serial_port::stop_bits::one));
    m_port.set_option(boost::asio::serial_port::flow_control(boost::asio::serial_port::flow_control::none));
}

std::pair<int, int> PinataClient::getVersion() {
    command(CMD_GET_CODE_REV);
    std::array<char, 8> result;
    read((uint8_t *)result.data(), result.size());
    return std::make_pair(result[4] - '0', result[6] - '0');
}

FirmwareVariant PinataClient::determineFirmwareVariant() {
    // Detect it via this command. It will return "BadCmd\n" when dealing with a classic or hw variant.
    command(CMD_SW_DILITHIUM_GET_VARIANT);
    uint8_t byte;
    read(&byte, sizeof(byte));
    // If we're dealing with a PQC variant then this should return the number "3".
    if (byte == 3) {
        return FirmwareVariant::PostQuantum;
    } else if (byte != 'B') {
        throw std::runtime_error("unexpected return value");
    }
    // We're not dealing with a PQC variant so the device is trying to send "BadCmd\n" instead.
    // Flush the remaining seven bytes out of the read buffer.
    char badCommand[7];
    read((uint8_t *)badCommand, std::size(badCommand));
    if (std::strcmp(badCommand, "adCmd\n") != 0) {
        throw std::runtime_error("unexpected return value");
    }
    // At this point we are either dealing with classic firmware with or without hardware support.
    // To determine whether we have hardware support, we will request an AES hardware encryption.
    // If the payload is all zeroes, we will assume that we are dealing with non-HW support.
    command(CMD_HWAES128_ENC);
    std::array<uint8_t, 16> buffer;
    std::iota(std::begin(buffer), std::end(buffer), 1);
    write(buffer.data(), std::size(buffer));
    read(buffer.data(), std::size(buffer));
    for (uint8_t byte : buffer) {
        // Zeroes as ASCII characters.
        if (byte != '0') {
            return FirmwareVariant::Hardware;
        }
    }
    return FirmwareVariant::Classic;
}

uint8_t PinataClient::dilithiumGetSecurityLevel() {
    command(CMD_SW_DILITHIUM_GET_VARIANT);
    return readNumber<uint8_t>();
}

std::pair<int, int> PinataClient::dilithiumGetKeySizes() {
    command(CMD_SW_DILITHIUM_GET_KEY_SIZES);
    const uint16_t publicKeySize = readNumber<uint16_t>();
    const uint16_t privateKeySize = readNumber<uint16_t>();
    return std::make_pair(publicKeySize, privateKeySize);
}

void PinataClient::dilithiumSetPublicPrivateKeyPair(const uint8_t *publicKey, size_t publicKeySize,
                                                    const uint8_t *privateKey, size_t privateKeySize) {
    command(CMD_SW_DILITHIUM_SET_PUBLIC_AND_PRIVATE_KEY);
    write(publicKey, publicKeySize);
    write(privateKey, privateKeySize);
    if (readNumber<uint8_t>() != 0) {
        throw std::runtime_error("failed to set public/private key pair");
    }
}

void PinataClient::dilithiumSign(const uint8_t *messageBuffer, size_t messageBufferSize, uint8_t *signedMessageBuffer,
                                 size_t signedMessageBufferSize) {
    command(CMD_SW_DILITHIUM_SIGN);
    write(messageBuffer, messageBufferSize);
    if (readNumber<uint8_t>() != 0) {
        throw std::runtime_error("pinata failed to sign this message");
    }
    read(signedMessageBuffer, signedMessageBufferSize);
}

bool PinataClient::dilithiumVerify(const uint8_t *signatureBuffer, size_t signatureBufferSize) {
    command(CMD_SW_DILITHIUM_VERIFY);
    write(signatureBuffer, signatureBufferSize);
    return readNumber<uint8_t>() == 0;
}

std::pair<int, int> PinataClient::kyber512GetKeySizes() {
    command(CMD_SW_KYBER512_GET_KEY_SIZES);
    const uint16_t publicKeySize = readNumber<uint16_t>();
    const uint16_t privateKeySize = readNumber<uint16_t>();
    return std::make_pair(publicKeySize, privateKeySize);
}

void PinataClient::kyber512SetPublicPrivateKeyPair(const uint8_t *publicKey, size_t publicKeySize,
                                                   const uint8_t *privateKey, size_t privateKeySize) {
    command(CMD_SW_KYBER512_SET_PUBLIC_AND_PRIVATE_KEY);
    write(publicKey, publicKeySize);
    write(privateKey, privateKeySize);
    if (readNumber<uint8_t>() != 0) {
        throw std::runtime_error("failed to set public/private key pair");
    }
}

void PinataClient::kyber512Generate(uint8_t *sharedSecretBuffer, size_t sharedSecretBufferSize,
                                    uint8_t *keyEncapsulationMessageBuffer, size_t keyEncapsulationMessageBufferSize) {
    command(CMD_SW_KYBER512_GENERATE);
    if (readNumber<uint8_t>() != 0) {
        throw std::runtime_error("failed to generate shared secret");
    }
    read(sharedSecretBuffer, sharedSecretBufferSize);
    read(keyEncapsulationMessageBuffer, keyEncapsulationMessageBufferSize);
}

void PinataClient::kyber512Decode(const uint8_t *keyEncapsulationMessageBuffer,
                                  size_t keyEncapsulationMessageBufferSize, uint8_t *sharedSecretBuffer,
                                  size_t sharedSecretBufferSize) {
    command(CMD_SW_KYBER512_DEC);
    write(keyEncapsulationMessageBuffer, keyEncapsulationMessageBufferSize);
    if (readNumber<uint8_t>() != 0) {
        throw std::runtime_error("failed to decode shared secret");
    }
    read(sharedSecretBuffer, sharedSecretBufferSize);
}

void PinataClient::doSymmetricCipherRequest(const uint8_t cmd, const uint8_t *input, const size_t inputSize,
                                            uint8_t *output, const size_t outputSize) {
    command(cmd);
    write(input, inputSize);
    read(output, outputSize);
}

void PinataClient::AES128SWEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES128_ENC, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::AES128SWDecrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
    doSymmetricCipherRequest(CMD_SWAES128_DEC, ciphertext, AESBLOCKSIZE, plaintext, AESBLOCKSIZE);
}

void PinataClient::AES128SWEncryptNoTrigger(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES128SPI_ENC, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::AES128TTablesSWEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES128TTABLES_ENC, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::AES128TTablesSWDecrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
    doSymmetricCipherRequest(CMD_SWAES128TTABLES_DEC, ciphertext, AESBLOCKSIZE, plaintext, AESBLOCKSIZE);
}

void PinataClient::AES256SWEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES256_ENC, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::AES256SWDecrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
    doSymmetricCipherRequest(CMD_SWAES256_DEC, ciphertext, AESBLOCKSIZE, plaintext, AESBLOCKSIZE);
}

void PinataClient::AES128MaskingSWEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES128_ENC_MASKED, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::AES128MaskingSWDecrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
    doSymmetricCipherRequest(CMD_SWAES128_DEC_MASKED, ciphertext, AESBLOCKSIZE, plaintext, AESBLOCKSIZE);
}

void PinataClient::AES128SWRndDelaysEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES128_ENC_RNDDELAYS, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::AES128SWRndSBoxEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWAES128_ENC_RNDSBOX, plaintext, AESBLOCKSIZE, ciphertext, AESBLOCKSIZE);
}

void PinataClient::SWDESEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWDES_ENC, plaintext, DESLENGTHINBYTES, ciphertext, DESLENGTHINBYTES);
}

void PinataClient::SWDESDecrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
    doSymmetricCipherRequest(CMD_SWDES_DEC, ciphertext, DESLENGTHINBYTES, plaintext, DESLENGTHINBYTES);
}

void PinataClient::SWTDESEncrypt(const uint8_t *plaintext, uint8_t *ciphertext) {
    doSymmetricCipherRequest(CMD_SWTDES_ENC, plaintext, DESLENGTHINBYTES, ciphertext, DESLENGTHINBYTES);
}

void PinataClient::SWTDESDecrypt(const uint8_t *ciphertext, uint8_t *plaintext) {
    doSymmetricCipherRequest(CMD_SWTDES_DEC, ciphertext, DESLENGTHINBYTES, plaintext, DESLENGTHINBYTES);
}

void PinataClient::command(uint8_t cmd) {
    boost::asio::write(m_port, boost::asio::buffer(&cmd, sizeof(cmd)), boost::asio::transfer_at_least(sizeof(cmd)));
}

void PinataClient::read(uint8_t *data, size_t size) {
    boost::system::error_code ec;
    // set up a deadline timer for a 3-second timeout
    boost::asio::deadline_timer timeout(m_context);
    timeout.expires_from_now(boost::posix_time::seconds(3));
    timeout.async_wait([this](const boost::system::error_code &error) {
        if (error != boost::asio::error::operation_aborted) {
            m_port.cancel();
        }
    });

    boost::asio::async_read(m_port, boost::asio::mutable_buffer(data, size),
                            [&timeout, &ec](const boost::system::error_code &error, std::size_t bytes_transferred) {
                                if (!error) {
                                    timeout.cancel();
                                } else {
                                    ec = error;
                                }
                            });
    m_context.run();
    m_context.restart();
    if (ec) {
        throw boost::system::system_error(ec);
    }
}
