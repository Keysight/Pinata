# Find programs that are used in flashing the firmware to the device.
find_program(DFU_SUFFIX dfu-suffix)
find_program(FLASHTOOL dfu-util)

if(NOT DFU_SUFFIX)
    message(STATUS "dfu-suffix was not found in $PATH, cannot create .dfu files")
endif()

if(NOT FLASHTOOL)
    message(STATUS "dfu-util was not found in $PATH, cannot flash device")
endif()

# Flashing parameters.
set(PINATA_PID DF11)
set(PINATA_VID 0483)
set(PINATA_DID 2200)
set(FLASH_TARGET_OFFSET 0x08000000)

option(RANDOM_SIGNING "Enable random signing for Dilithium cipher" OFF)

# Common lib
file(GLOB COMMON_SOURCE_FILES
    cmsis_lib/source/*.c
    cmsis_boot/*.c
    cmsis_boot/startup/*.c
    usb_lib/core/*.c
    usb_lib/cdc/*.c
    usb_lib/otg/*.c
    usb_conf/*.c
    ssd1306/*.c
    syscalls/*.c
)

list(APPEND COMMON_SOURCE_FILES rng.c tickers.c)

add_library(common OBJECT ${COMMON_SOURCE_FILES})
target_include_directories(common PUBLIC
    usb_conf
    ssd1306
    cmsis_boot
    cmsis_lib/include
    usb_lib/otg
    usb_lib/core
    usb_lib/cdc
    cmsis_lib
    cmsis
    .
)
target_compile_options(common PUBLIC -Werror)
target_compile_definitions(common PUBLIC STM32F4XX __FPU_USED USE_STDPERIPH_DRIVER HAVE_C99INCLUDES)

# List of target names
set(TARGETS classic hw pqc)

foreach(TARGET_NAME ${TARGETS})

    # Define an executable target for the current TARGET_NAME.
    string(TOUPPER ${TARGET_NAME} TARGET_NAME_UPPER)
    add_executable(${TARGET_NAME} main.c)
    target_link_libraries(${TARGET_NAME} PRIVATE common m gcc c)
    target_link_options(${TARGET_NAME} PRIVATE -Wl,-Map=${TARGET_NAME}.map)
    set_target_properties(${TARGET_NAME} PROPERTIES
        SUFFIX .elf
        ADDITIONAL_CLEAN_FILES ${TARGET_NAME}.map
    )

    # Define a target to print the binary object sizes.
    add_custom_target(${TARGET_NAME}_size
        DEPENDS ${TARGET_NAME}
        COMMAND ${CMAKE_NM} --size-sort --format=sysv $<TARGET_FILE:${TARGET_NAME}>
        COMMENT "Displaying size information for ${TARGET_NAME}.elf"
    )

    # Optionally define a target to create a .dfu file from a .bin file.
    if(DFU_SUFFIX)
        add_custom_command(
            OUTPUT ${TARGET_NAME}.dfu
            COMMAND ${CMAKE_OBJCOPY} -Obinary $<TARGET_FILE:${TARGET_NAME}> ${TARGET_NAME}.dfu
            COMMAND ${DFU_SUFFIX} -p ${PINATA_PID} -v ${PINATA_VID} -d ${PINATA_DID} -a ${TARGET_NAME}.dfu >/dev/null
            DEPENDS ${TARGET_NAME}
            COMMENT "Creating ${TARGET_NAME}.dfu from ${TARGET_NAME}"
        )
        add_custom_target(${TARGET_NAME}_dfu ALL DEPENDS ${TARGET_NAME}.dfu)
        set_target_properties(${TARGET_NAME}_dfu PROPERTIES ADDITIONAL_CLEAN_FILES ${TARGET_NAME}.dfu)

        # Install the .dfu file when installing.
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.dfu" DESTINATION .)

        # Optionally define a target to flash the device.
        if(FLASHTOOL)
            add_custom_target(${TARGET_NAME}_flash
                DEPENDS ${TARGET_NAME}_dfu
                COMMAND ${FLASHTOOL} -a 0 -s ${FLASH_TARGET_OFFSET} -D ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.dfu
                COMMENT "Flashing ${TARGET_NAME}.dfu to target"
            )
        endif()

    endif()

endforeach()

# Macro function to declare which files are supposed to be compiled.
# This macro function should be used in the various subdirectories relative to this directory.
macro(target_licensed_sources)
    get_filename_component(subdir ${CMAKE_CURRENT_LIST_DIR} NAME)
    if(NOT DEFINED PINATA_TARGETS_FOR_${subdir})
        message(SEND_ERROR "missing target names in variable PINATA_TARGETS_FOR_${subdir}")
        return()
    endif()
    foreach(TARGET ${PINATA_TARGETS_FOR_${subdir}})
        target_sources(${TARGET} PRIVATE ${ARGV})
    endforeach()
endmacro()

unset(PINATA_LICENSED_SUBDIRS)
set(PINATA_LICENSED_SUBDIRS "")

# Macro function to declare, for a given subdirectory:
#
# - what its license is,
# - what its informational website is,
# - what its source code origin is.
#
# This information is collected into lists. The lists are then iterated over
# at later stage to collect all information into a generated ThirdPartyLicenses.txt file.
#
macro(add_licensed_subdir SUBDIR TARGETS SPDX_LICENSE_IDENTIFIER WEBSITE SOURCE_ORIGIN)
    set(PINATA_TARGETS_FOR_${SUBDIR} ${TARGETS})
    set(PINATA_LICENSE_${SUBDIR} ${SPDX_LICENSE_IDENTIFIER})
    set(PINATA_ORIGIN_WEBSITE_${SUBDIR} ${WEBSITE})
    set(PINATA_ORIGIN_SOURCE_${SUBDIR} ${SOURCE_ORIGIN})
    add_subdirectory(${SUBDIR})
    list(APPEND PINATA_LICENSED_SUBDIRS ${SUBDIR})
endmacro()

#                   Subdirectory       Targets      SPDX License           Informational Website                                       Source Code Origin
add_licensed_subdir(swDES              "classic;hw" BSD-3-Clause-Clear     https://github.com/Riscure/Pinata                           https://github.com/Riscure/Pinata.git)
add_licensed_subdir(swAES              "classic;hw" BSD-3-Clause-Clear     https://github.com/Riscure/Pinata                           https://github.com/Riscure/Pinata.git)
add_licensed_subdir(swmAES             "classic;hw" BSD-3-Clause-Clear     https://github.com/Riscure/Pinata                           https://github.com/Riscure/Pinata.git)
add_licensed_subdir(rsa                "classic;hw" NOTFOUND               NOTFOUND                                                    NOTFOUND)
add_licensed_subdir(rsacrt             "classic;hw" NOTFOUND               NOTFOUND                                                    NOTFOUND)
add_licensed_subdir(sm4                "classic;hw" "BSD-3-Clause;OpenSSL" https://en.wikipedia.org/wiki/SM4_\(cipher\)                https://raw.githubusercontent.com/openssl/openssl/704e8090b4a789f52af07de9a3ebbe11db8e19f8/crypto/sm4/sm4.c)
add_licensed_subdir(swAES256           "classic;hw" MIT                    https://github.com/ilvn/aes256                              https://github.com/ilvn/aes256.git)
add_licensed_subdir(swAES_Ttables      "classic;hw" CC0-1.0                http://www.efgh.com/software/rijndael.htm                   http://www.efgh.com/software/rijndael.txt)
add_licensed_subdir(present            "classic;hw" BSD-3-Clause-Clear     https://github.com/Riscure/Pinata                           https://github.com/Riscure/Pinata.git)
add_licensed_subdir(bignum             "classic;hw" MPL-2.0                https://www.di-mgt.com.au/bigdigits.html                    NOTFOUND)
add_licensed_subdir(prng               "classic;hw" BSD-3-Clause-Clear     https://github.com/Riscure/Pinata                           https://github.com/Riscure/Pinata.git)
add_licensed_subdir(ecc                "classic;hw" BSD-3-Clause-Clear     https://github.com/Riscure/Pinata                           https://github.com/Riscure/Pinata.git)
add_licensed_subdir(curve25519_CortexM "classic;hw" CC0-1.0                https://munacl.cryptojedi.org/curve25519-cortexm0.shtml     https://munacl.cryptojedi.org/data/curve25519-cortexm0-20150813.tar.bz2)
add_licensed_subdir(pqm4common         pqc          CC0-1.0                https://github.com/mupq/pqm4                                https://github.com/mupq/pqm4.git)
add_licensed_subdir(dilithium          pqc          CC0-1.0                https://github.com/mupq/pqm4                                https://github.com/mupq/pqm4.git)
add_licensed_subdir(kyber512           pqc          CC0-1.0                https://github.com/mupq/pqm4                                https://github.com/mupq/pqm4.git)
#                   Subdirectory       Targets      SPDX License           Informational Website                                       Source Code Origin

add_licensed_subdir(
    tea
    "classic;hw"
    CC0-1.0
    "https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm#Reference_code;https://en.wikipedia.org/wiki/XTEA#Implementations"
    "https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm#Reference_code;https://en.wikipedia.org/wiki/XTEA#Implementations"
)

# Minor tweaks for the firmware targets.
target_compile_definitions(hw PRIVATE HW_CRYPTO_PRESENT)
target_include_directories(pqc PRIVATE pqm4common)
target_compile_definitions(pqc PRIVATE VARIANT_PQC $<$<BOOL:${RANDOM_SIGNING}>:DILITHIUM_RANDOMIZED_SIGNING>)

# After having collected all license information into lists, we now generate
# the notice file.
set(NOTICE_FILE "${CMAKE_CURRENT_BINARY_DIR}/ThirdPartyLicenses.txt")
message(STATUS "Writing ${CMAKE_CURRENT_BINARY_DIR}/ThirdPartyLicenses.txt")
file(REMOVE "${NOTICE_FILE}")
foreach(SUBDIR ${PINATA_LICENSED_SUBDIRS})
    file(APPEND "${NOTICE_FILE}" "subdir: ${SUBDIR}\n")
    file(APPEND "${NOTICE_FILE}" "license: ${PINATA_LICENSE_${SUBDIR}}\n")
    file(APPEND "${NOTICE_FILE}" "website: ${PINATA_ORIGIN_WEBSITE_${SUBDIR}}\n")
    file(APPEND "${NOTICE_FILE}" "origin: ${PINATA_ORIGIN_SOURCE_${SUBDIR}}\n\n")
endforeach()

# Install the notice file when installing, and install the .elf files.
install(FILES "${NOTICE_FILE}" DESTINATION .)
install(TARGETS ${TARGETS} DESTINATION .)
