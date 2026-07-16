#include "randombytes.h"
#include "../rng.h" // implement pqm randombytes in terms of our own random functions
#include <string.h>

static uint32_t rng_get_random_internal() {
    while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
    return RNG_GetRandomNumber();
}

int randombytes(uint8_t *output, size_t n) {
    uint32_t randomness;
    RNG_Enable();
    while (n >= sizeof(uint32_t)) {
        randomness = rng_get_random_internal();
        memcpy(output, &randomness, sizeof(uint32_t));
        n -= sizeof(uint32_t);
        output += sizeof(uint32_t);
    }
    if (n > 0) {
        randomness = rng_get_random_internal();
        memcpy(output, &randomness, n);
    }
    RNG_Disable();
    return 0;
}
