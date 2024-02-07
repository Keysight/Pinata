#include "TestBase.hpp"
#include <gtest/gtest.h>

class HardwareFirmware : public TestBase {
    void SetUp() override {
        if (Environment::getInstance().getFirmwareVariant() != FirmwareVariant::Hardware) {
            GTEST_SKIP();
        }
    }
};

TEST_F(HardwareFirmware, AES) {
    // TODO
    ASSERT_TRUE(true);
}
