cmake_minimum_required(VERSION 3.16)

if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.27)
    cmake_policy(SET CMP0144 NEW)
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.30)
        cmake_policy(SET CMP0167 NEW)
    endif()
endif()

project(PinataTests VERSION 3.3 LANGUAGES C CXX)

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(Boost REQUIRED)

include(FetchContent)
FetchContent_Declare(
    pqm4
    GIT_REPOSITORY https://github.com/mupq/pqm4.git
    # Keep this git hash the same as the one in src/CMakeLists.txt !
    GIT_TAG a24bb4b662016968c19f5e6a0719c9ad530f0286
)
FetchContent_MakeAvailable(pqm4)

# We can reuse the PQClean sources checked out by PQM4.
set(DILITHIUM "${pqm4_SOURCE_DIR}/mupq/pqclean/crypto_sign/ml-dsa-65/clean")
set(KYBER "${pqm4_SOURCE_DIR}/mupq/pqclean/crypto_kem/ml-kem-512/clean")
set(COMMON "${pqm4_SOURCE_DIR}/mupq/pqclean/common")

add_executable(PinataTests
    main.cpp
    Environment.cpp
    ClassicFirmware.cpp
    HardwareFirmware.cpp
    PqcFirmware.cpp
    common.cpp
    ${COMMON}/fips202.c
    ${COMMON}/randombytes.c
    ${COMMON}/aes.c
    ${DILITHIUM}/packing.c
    ${DILITHIUM}/ntt.c
    ${DILITHIUM}/poly.c
    ${DILITHIUM}/polyvec.c
    ${DILITHIUM}/reduce.c
    ${DILITHIUM}/rounding.c
    ${DILITHIUM}/sign.c
    ${DILITHIUM}/symmetric-shake.c
    ${KYBER}/indcpa.c
    ${KYBER}/polyvec.c
    ${KYBER}/reduce.c
    ${KYBER}/kem.c
    ${KYBER}/ntt.c
    ${KYBER}/cbd.c
    ${KYBER}/poly.c
    ${KYBER}/verify.c
    ${KYBER}/symmetric-shake.c
)

target_compile_features(PinataTests PRIVATE cxx_std_20)
target_include_directories(PinataTests PRIVATE "${pqm4_SOURCE_DIR}/mupq/pqclean/common")
set_source_files_properties(PqcFirmware.cpp PROPERTIES INCLUDE_DIRECTORIES "${pqm4_SOURCE_DIR}/mupq/pqclean")
target_link_libraries(PinataTests PRIVATE Boost::boost OpenSSL::Crypto GTest::GTest)

