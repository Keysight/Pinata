#pragma once

#include "Environment.hpp"
#include <gtest/gtest.h>

class TestBase : public ::testing::Test {

  protected:
    PinataClient &mClient;

    TestBase() : mClient(Environment::getInstance().getClient()) {}
};
