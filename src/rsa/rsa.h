#ifndef __RSA_H
#define __RSA_H

#include "bignum/bigdtypes.h"
#include "bignum/bigdigits.h"
#include <stdint.h>
#include "stm32f4xx.h"
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_conf.h"
#include "io.h"
#include "support.h"

#ifndef PI
#define PI 3.141592654
#endif


#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

typedef enum key_management_method_t {
	KEY_PASSED_TO_THE_TARGET,
	KEY_HARDCODED_ON_TARGET,
	RANDOM_MASKING_ON_TARGET /* This method is not tested, and is only left as an example */
} key_management_method_t;

typedef struct private_key_t private_key_t;
typedef struct rsa_sfm_private_key_t rsa_sfm_private_key_t;

void load_bytearray(DIGIT_T * out, const uint8_t * in, uint16_t len) ;
void rsa_init(void) ;
void rsa_crt_decrypt(void);
void rsa_sfm_init(void) ;
void rsa_sfm_decrypt(void);
size_t max_digits_of_input(void);
size_t max_digits_of_input_sfm(void);
void input_cipher_text(uint32_t len);
void send_clear_text(void);
void readFromCharArray(uint8_t *ch);
void rsa_sfm_send_hardcoded_key(void);
void rsa_sfm_set_implementation_method(uint8_t method);
void rsa_sfm_set_key_generation_method(uint8_t method);
void input_external_exponent(uint32_t len);

#endif
