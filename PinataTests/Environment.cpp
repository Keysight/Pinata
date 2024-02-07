#include "Environment.hpp"
#include <boost/system/system_error.hpp>
#include <cassert>
#include <iostream>

Environment *Environment::gInstance = nullptr;

Environment::Environment() noexcept {
    assert(gInstance == nullptr);
    gInstance = this;
}

Environment::~Environment() noexcept {
    assert(gInstance != nullptr);
    gInstance = nullptr;
}

Environment &Environment::getInstance() noexcept {
    assert(gInstance != nullptr);
    return *gInstance;
}

void Environment::SetUp() {
    assert(!mClient.has_value());
    mClient.emplace();
    try {
        std::tie(mClientVersionMajor, mClientVersionMinor) = mClient->getVersion();
    } catch (const boost::system::system_error &ex) {
        std::cerr
            << "Unable to retrieve the version information from the device. This is a sanity check to see "
               "whether communication with the device is working. If this step fails, most likely all other tests "
               "will start failing. So we stop here.\n";
        throw;
    }
    mFirmwareVariant = mClient->determineFirmwareVariant();
}

void Environment::TearDown() {
    assert(mClient.has_value());
    mClient.reset();
}

PinataClient &Environment::getClient() noexcept {
    assert(mClient.has_value());
    return *mClient;
}
