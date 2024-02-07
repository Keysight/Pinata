#ifndef _PRNG_H_
#define _PRNG_H_

#include <stdint.h>

#define PRNG_AES_CTR_128_SEED_LEN_BYTES	32  // len(aes key) + len(iv)
#define PRNG_AES_CTR_128_KEYSIZE_LEN_BYTES	16
#define PRNG_AES_CTR_128_KEYSIZE_LEN_BITS	128
#define PRNG_AES_CTR_128_MAX_BYTES_TO_GENERATE (4 * 256) // 1024B = 1KB (32 bits per ECSM iteration)

typedef struct {
	uint8_t aes_ctr_key[16];
	uint8_t aes_ctr_iv[16];
} prng_seed_t;

typedef struct {
	uint8_t rand_bytes[PRNG_AES_CTR_128_MAX_BYTES_TO_GENERATE];
	uint16_t n_rand_bytes_generated;
	uint16_t i_next_rand_byte;
} prng_ctx_t;

//
// PRNG API
//
void prng_init(prng_ctx_t *ctx, prng_seed_t *prng_seed, int n_bytes_to_generate);
void prng_get_bytes(prng_ctx_t *ctx, uint8_t *out_buf, int n_bytes);
void receive_prng_seed(prng_seed_t *p_prng_seed);

//
// Global PRNG context
//
extern prng_ctx_t g_prng_ctx;

#endif //_PRNG_H_
