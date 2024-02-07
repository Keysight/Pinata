#include "TestBase.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using AesBlock = std::array<uint8_t, 16>;
using DesBlock = std::array<uint8_t, 8>;

class ClassicFirmware : public TestBase {

  protected:
    uint8_t pt_16bytes[16];
    uint8_t pt_8bytes[8];
    uint8_t ct_16bytes[16];
    uint8_t ct_8bytes[8];

    ClassicFirmware() {
        RAND_bytes(pt_16bytes, 16);
        RAND_bytes(ct_16bytes, 16);
        RAND_bytes(pt_8bytes, 8);
        RAND_bytes(ct_8bytes, 8);
    }

    void SetUp() override {
        const FirmwareVariant variant = Environment::getInstance().getFirmwareVariant();
        if (variant != FirmwareVariant::Hardware && variant != FirmwareVariant::Classic) {
            GTEST_SKIP();
        }
    }

    AesBlock AES128_ecb_encrypt(uint8_t pt[16], const uint8_t key[16]) {
        AesBlock ct_ref;
        int ct_ref_size;
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("Error initializing AES 128 reference implementation encryption");
        }
        if (1 != EVP_EncryptUpdate(ctx.get(), ct_ref.data(), &ct_ref_size, pt, 16)) {
            throw std::runtime_error("Error updating AES 128 reference implementation encryption");
        }
        return ct_ref;
    }

    AesBlock AES128_ecb_decrypt(uint8_t ct[16], const uint8_t key[16]) {
        AesBlock pt_ref;
        int pt_ref_size;
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("Error initializing AES 128 reference implementation decryption");
        }
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
        if (1 != EVP_DecryptUpdate(ctx.get(), pt_ref.data(), &pt_ref_size, ct, 16)) {
            throw std::runtime_error("Error in updating AES 128 reference implementation decryption");
        }
        return pt_ref;
    }

    AesBlock AES256_ecb_encrypt(uint8_t pt[16], const uint8_t key[32]) {
        AesBlock ct_ref;
        int ct_ref_size;
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("Error initializing AES 256 reference implementation encryption");
        }
        if (1 != EVP_EncryptUpdate(ctx.get(), ct_ref.data(), &ct_ref_size, pt, 16)) {
            throw std::runtime_error("Error updating AES 256 reference implementation encryption");
        }
        return ct_ref;
    }

    AesBlock AES256_ecb_decrypt(uint8_t ct[16], const uint8_t key[32]) {
        AesBlock pt_ref;
        int pt_ref_size;
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("Error initializing AES 256 reference implementation decryption");
        }
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
        if (1 != EVP_DecryptUpdate(ctx.get(), pt_ref.data(), &pt_ref_size, ct, 16)) {
            throw std::runtime_error("Error updating AES 256 reference implementation decryption");
        }
        return pt_ref;
    }

    DesBlock DES_ecb_ref_encrypt(uint8_t pt[8], const uint8_t key[8]) {
        DesBlock ct_ref;
        DES_key_schedule keySchedule;
        DES_set_key(reinterpret_cast<const_DES_cblock *>(const_cast<uint8_t *>(key)), &keySchedule);
        DES_ecb_encrypt(reinterpret_cast<const_DES_cblock *>(pt), reinterpret_cast<const_DES_cblock *>(ct_ref.data()),
                        &keySchedule, DES_ENCRYPT);
        return ct_ref;
    }

    DesBlock DES_ecb_ref_decrypt(uint8_t ct[8], const uint8_t key[8]) {
        DesBlock pt_ref;
        DES_key_schedule keySchedule;
        DES_set_key(reinterpret_cast<const_DES_cblock *>(const_cast<uint8_t *>(key)), &keySchedule);
        DES_ecb_encrypt(reinterpret_cast<const_DES_cblock *>(ct), reinterpret_cast<const_DES_cblock *>(pt_ref.data()),
                        &keySchedule, DES_DECRYPT);
        return pt_ref;
    }

    DesBlock TDES_ecb_ref_encrypt(uint8_t pt[8], const uint8_t key[24]) {
        DesBlock ct_ref;
        int ct_ref_size;
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
        if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_des_ede_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("Error initializing Triple DES reference implementation encryption");
        }
        if (1 != EVP_EncryptUpdate(ctx.get(), ct_ref.data(), &ct_ref_size, pt, 8)) {
            throw std::runtime_error("Error updating Triple Des reference implementation encryption");
        }
        return ct_ref;
    }

    DesBlock TDES_ecb_ref_decrypt(uint8_t ct[8], const uint8_t key[24]) {
        DesBlock pt_ref;
        int pt_ref_size;
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
        if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_des_ede_ecb(), NULL, key, NULL)) {
            throw std::runtime_error("Error initializing Triple DES reference implementation decryption");
        }
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
        if (1 != EVP_DecryptUpdate(ctx.get(), pt_ref.data(), &pt_ref_size, ct, 8)) {
            throw std::runtime_error("Error updating Triple DES reference implementation decryption");
        }
        return pt_ref;
    }
};

TEST_F(ClassicFirmware, test128AESSWEncrypt) {
    AesBlock ct_ref;
    ct_ref = AES128_ecb_encrypt(pt_16bytes, defaultKeyAES);
    AesBlock ct_pinata;
    mClient.AES128SWEncrypt(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, test128AESSWDecrypt) {
    AesBlock pt_ref;
    pt_ref = AES128_ecb_decrypt(ct_16bytes, defaultKeyAES);
    AesBlock pt_pinata;
    mClient.AES128SWDecrypt(ct_16bytes, pt_pinata.data());

    EXPECT_EQ(pt_ref, pt_pinata);
}

TEST_F(ClassicFirmware, test128AESSWNoTrigger) {
    AesBlock ct_ref;
    ct_ref = AES128_ecb_encrypt(pt_16bytes, defaultKeyAES);
    AesBlock ct_pinata;
    mClient.AES128SWEncryptNoTrigger(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, test128AESTTablesEncrypt) {
    AesBlock ct_ref;
    ct_ref = AES128_ecb_encrypt(pt_16bytes, defaultKeyAES);
    AesBlock ct_pinata;
    mClient.AES128TTablesSWEncrypt(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, test128AESTTablesDecrypt) {
    AesBlock pt_ref;
    pt_ref = AES128_ecb_decrypt(ct_16bytes, defaultKeyAES);
    AesBlock pt_pinata;
    mClient.AES128TTablesSWDecrypt(ct_16bytes, pt_pinata.data());
    EXPECT_EQ(pt_ref, pt_pinata);
}

TEST_F(ClassicFirmware, testAES256SWEncrypt) {
    AesBlock ct_ref;
    ct_ref = AES256_ecb_encrypt(pt_16bytes, defaultKeyAES256);
    AesBlock ct_pinata;
    mClient.AES256SWEncrypt(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, testAES256SWDecrypt) {
    AesBlock pt_ref;
    pt_ref = AES256_ecb_decrypt(ct_16bytes, defaultKeyAES256);
    AesBlock pt_pinata;
    mClient.AES256SWDecrypt(ct_16bytes, pt_pinata.data());
    EXPECT_EQ(pt_ref, pt_pinata);
}

TEST_F(ClassicFirmware, testAES128MaskingEncrypt) {
    AesBlock ct_ref;
    ct_ref = AES128_ecb_encrypt(pt_16bytes, defaultKeyAES);
    AesBlock ct_pinata;
    mClient.AES128MaskingSWEncrypt(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, testAES128MaskingDecrypt) {
    AesBlock pt_ref;
    pt_ref = AES128_ecb_decrypt(ct_16bytes, defaultKeyAES);
    AesBlock pt_pinata;
    mClient.AES128MaskingSWDecrypt(ct_16bytes, pt_pinata.data());
    EXPECT_EQ(pt_ref, pt_pinata);
}

TEST_F(ClassicFirmware, testAES128SWRndDelaysEncrypt) {
    AesBlock ct_ref;
    ct_ref = AES128_ecb_encrypt(pt_16bytes, defaultKeyAES);
    AesBlock ct_pinata;
    mClient.AES128SWRndDelaysEncrypt(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, testAES128SWRndSBoxEncrypt) {
    AesBlock ct_ref;
    ct_ref = AES128_ecb_encrypt(pt_16bytes, defaultKeyAES);
    AesBlock ct_pinata;
    mClient.AES128SWRndSBoxEncrypt(pt_16bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, testDESSWEncrypt) {
    DesBlock ct_ref;
    ct_ref = DES_ecb_ref_encrypt(pt_8bytes, defaultKeyDES);
    DesBlock ct_pinata;
    mClient.SWDESEncrypt(pt_8bytes, ct_pinata.data());
    EXPECT_EQ(ct_ref, ct_pinata);
}

TEST_F(ClassicFirmware, testDESSWDecrypt) {
    DesBlock pt_ref;
    pt_ref = DES_ecb_ref_decrypt(ct_8bytes, defaultKeyDES);
    DesBlock pt_pinata;
    mClient.SWDESDecrypt(ct_8bytes, pt_pinata.data());
    EXPECT_EQ(pt_ref, pt_pinata);
}

TEST_F(ClassicFirmware, testTDESSWEncrypt) {
    DesBlock pt_ref;
    pt_ref = TDES_ecb_ref_decrypt(ct_8bytes, defaultKeyTDES);
    DesBlock pt_pinata;
    mClient.SWTDESDecrypt(ct_8bytes, pt_pinata.data());
    EXPECT_EQ(pt_ref, pt_pinata);
}
