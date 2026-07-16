#ifndef PINATABOARD_RNG_H
#define PINATABOARD_RNG_H

#include "stm32f4xx_rng.h"
#include "stm32f4xx_rcc.h"
#include <stddef.h>

void RNG_Enable(void);
void RNG_Disable(void);

#endif //PINATABOARD_RNG_H
