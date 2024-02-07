#include "rng.h"
#include <string.h>

void RNG_Enable(void) {
    RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, ENABLE);
    /* RNG Peripheral enable */
    RNG_Cmd(ENABLE);
}

void RNG_Disable(void) {
    RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, DISABLE);
}

static uint32_t rng_get_random_internal() {
    while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
    return RNG_GetRandomNumber();
}

static uint32_t rng_get_random_blocking() {
    uint32_t bytes;
    RNG_Enable();
    bytes = rng_get_random_internal();
    RNG_Disable();
}

void randombytes(char* data, size_t size) {
    uint32_t randomness;
    RNG_Enable();
    while (size >= sizeof(uint32_t)) {
        randomness = rng_get_random_internal();
        memcpy(data, &randomness, sizeof(uint32_t));
        size -= sizeof(uint32_t);
        data += sizeof(uint32_t);
    }
    if (size > 0) {
        randomness = rng_get_random_internal();
        memcpy(data, &randomness, size);
    }
    RNG_Disable();
}
