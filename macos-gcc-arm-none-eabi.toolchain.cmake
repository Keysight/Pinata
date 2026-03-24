# Toolchain for gcc-arm-none-eabi on macOS
#
# Notes:
#
# 13.2.rel1: known working
# 14.2.rel1: errors with: Library not loaded: '/usr/local/opt/zstd/lib/libzstd.1.dylib'
#            reason: https://community.arm.com/support-forums/f/compilers-and-libraries-forum/56544/13-3-rel1-darwin-x86_64-was-built-linking-to-a-homebrew-libz-rather-than-the-system-libz
# 15.2.rel1: breaks at link time with error: Unknown destination type (ARM/Thumb)
#            reason: https://community.arm.com/support-forums/f/compilers-and-libraries-forum/57077/binutils-2-44-and-gcc-15-1-0---dangerous-relocation-unsupported-relocation-error-when-trying-to-build-u-boot

message(STATUS "PREFIX variable: ${PREFIX}")

set(CMAKE_C_COMPILER ${PREFIX}gcc)
set(CMAKE_CXX_COMPILER ${PREFIX}g++)
set(CMAKE_ASM_COMPILER ${PREFIX}gcc)
set(CMAKE_OBJCOPY ${PREFIX}objcopy)
set(CMAKE_NM ${PREFIX}nm)

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Compiler flags
set(CMAKE_C_FLAGS_INIT "-mcpu=cortex-m4 -mfloat-abi=softfp -mthumb -mfpu=fpv4-sp-d16 -ffunction-sections -fdata-sections")
set(CMAKE_ASM_FLAGS_INIT ${CMAKE_C_FLAGS_INIT})
set(CMAKE_CXX_FLAGS_INIT "${CMAKE_C_FLAGS_INIT}" CACHE STRING "" FORCE)

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS_INIT "-nostartfiles -Wl,--gc-sections -T${CMAKE_CURRENT_SOURCE_DIR}/arm-gcc-link.ld")
