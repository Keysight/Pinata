#include "rng.h"

void RNG_Enable(void) {
    RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, ENABLE);
    /* RNG Peripheral enable */
    RNG_Cmd(ENABLE);
}

void RNG_Disable(void) {
    RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, DISABLE);
}
