# Toolchain for gcc-arm-none-eabi
set(PREFIX /usr/bin/arm-none-eabi-)
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
