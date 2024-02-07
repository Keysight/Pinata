cmake_minimum_required(VERSION 3.16)
project(PinataTests C CXX)

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(Boost REQUIRED)

set(DILITHIUM PQClean/crypto_sign/dilithium3/clean)
set(KYBER PQClean/crypto_kem/kyber512/clean)

add_executable(PinataTests
	main.cpp
	dilithium/test-dilithium.cpp
	kyber/test-kyber.cpp
	tests/Environment.cpp
	tests/PinataTests.cpp
	utilities/common.cpp
    #COMMON
    PQClean/common/fips202.c
    PQClean/common/randombytes.c
    PQClean/common/aes.c
    #DILITHIUM 
	${DILITHIUM}/packing.c
	${DILITHIUM}/ntt.c
	${DILITHIUM}/poly.c
	${DILITHIUM}/polyvec.c
	${DILITHIUM}/reduce.c
	${DILITHIUM}/rounding.c
	${DILITHIUM}/sign.c
	${DILITHIUM}/symmetric-shake.c
	#KYBER
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
target_include_directories(PinataTests PRIVATE PQClean/common)
target_link_libraries(PinataTests PRIVATE Boost::boost OpenSSL::Crypto GTest::GTest)
