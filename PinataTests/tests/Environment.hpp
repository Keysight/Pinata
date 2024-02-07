#pragma once

#include "../utilities/common.hpp"
#include <gtest/gtest.h>
#include <optional>

/// Global gtest environment to maintain a connection to a Pinata device.
class Environment : public ::testing::Environment {
  private:
    std::optional<PinataClient> mClient;
    int mClientVersionMajor = 0;
    int mClientVersionMinor = 0;
    static Environment *gInstance;

  public:
    Environment() noexcept;
    Environment(const Environment &) = delete;
    Environment(Environment &&) = delete;
    Environment &operator=(const Environment &) = delete;
    Environment &operator=(Environment &&) = delete;
    ~Environment() noexcept;

    /// Set up a connection to the Pinata device.
    void SetUp() override;

    /// Tear down the connection to the Pinata device.
    void TearDown() override;

    /// Get a reference to the global instance of this class.
    static Environment &getInstance() noexcept;

    /// Get a reference to the connection.
    PinataClient &getClient() noexcept;

    /// Get the client's major version number.
    int getClientVersionMajor() const noexcept { return mClientVersionMajor; }

    /// Get the client's minor version number.
    int getClientVersionMinor() const noexcept { return mClientVersionMinor; }
};
