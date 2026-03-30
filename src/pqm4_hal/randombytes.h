#pragma once

// This header file must be named "randombytes".
// The include directory of this header file should be added
// before the mupq include directory. This way, when
// a pqm4/mupq file includes the file "randombytes.h", it will
// include this file.

#include <stddef.h>
#include <stdint.h>

int randombytes(uint8_t *output, size_t n);
