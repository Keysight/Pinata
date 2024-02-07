#ifndef __ECC_H
#define __ECC_H

#include "bignum/bigdtypes.h"
#include "bignum/bigdigits.h"
#include <stdint.h>
#include "stm32f4xx.h"
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_conf.h"

#include "prng/prng.h"
#include "curve25519_CortexM/include/api.h"
#include "io.h"

#define CURVE25519_SCALAR_BYTES 32
#define CURVE25519_POINT_COMPRESSED_BYTES 32
#define PROJ_COORD_RE_RAND_TOTAL_RAND_BYTES (4 * 256)

void ecsm();


#endif
