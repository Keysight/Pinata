#include "Environment.hpp"
#include <cassert>

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
}

void Environment::TearDown() {
    assert(mClient.has_value());
    mClient.reset();
}

PinataClient &Environment::getClient() noexcept {
    assert(mClient.has_value());
    return *mClient;
}
