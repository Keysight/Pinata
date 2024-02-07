#ifndef __RSACRT_H
#define __RSACRT_H

#include "bignum/bigdtypes.h"
#include "bignum/bigdigits.h"
#include <stdint.h>
#include "stm32f4xx.h"
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_conf.h"
#include "io.h"

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

typedef struct private_key_t private_key_t;

void load_bytearray_crt(DIGIT_T * out, const uint8_t * in, uint16_t len) ;
void rsa_crt_init(void) ;
void rsa_crt_decrypt(void);
size_t max_digits_of_input_crt(void);
void input_cipher_text_crt(uint32_t len);
void send_clear_text_crt(void);
void readFromCharArray_crt(uint8_t *ch);

#endif