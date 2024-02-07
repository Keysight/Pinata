#include <string.h>
#include "prng.h"
#include "../io.h"

//STM32F4 libraries
#include "stm32f4xx_conf.h"
#include "stm32f4xx.h"
#include "stm32f4xx_cryp.h" //Crypto libraries - hardware implementations

//
// Global PRNG context
//
prng_ctx_t g_prng_ctx;

void receive_prng_seed(prng_seed_t *p_prng_seed)
{
	get_bytes(16, p_prng_seed->aes_ctr_key);
	get_bytes(16, p_prng_seed->aes_ctr_iv);
}

void prng_init(prng_ctx_t *ctx, prng_seed_t *prng_seed, int n_bytes_to_generate)
{
	uint8_t zeros[PRNG_AES_CTR_128_MAX_BYTES_TO_GENERATE];
	memset(zeros, 0, PRNG_AES_CTR_128_MAX_BYTES_TO_GENERATE);
	memset(ctx, 0, sizeof(prng_ctx_t));


	ErrorStatus status = CRYP_AES_CTR(MODE_ENCRYPT,
										prng_seed->aes_ctr_iv,
										prng_seed->aes_ctr_key, PRNG_AES_CTR_128_KEYSIZE_LEN_BITS,
										zeros, n_bytes_to_generate,
										ctx->rand_bytes);



	ctx->n_rand_bytes_generated = n_bytes_to_generate;
	ctx->i_next_rand_byte = 0;
}

void prng_get_bytes(prng_ctx_t *ctx, uint8_t *out_buf, int n_bytes)
{
	int i;

	// Copy to the output buffer
	for (i = 0; i < n_bytes; i++)
	{
		out_buf[i] = ctx->rand_bytes[ ctx->i_next_rand_byte++ ];
	}
}

