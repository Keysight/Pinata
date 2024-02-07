#include "Environment.hpp"
#include <gtest/gtest.h>

int main(int argc, char **argv) {
    ::testing::AddGlobalTestEnvironment(new Environment);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
