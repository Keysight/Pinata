#include "ecc.h"

void ecsm(uint8_t *rxBuffer) {
	int t_start, t_end;
	int t_elapsed_ms;
	t_start = t_end = 0;
	t_elapsed_ms = 0;
	prng_seed_t prng_seed;

	// receive PRNG seed
	receive_prng_seed(&prng_seed);

	prng_init(&g_prng_ctx, &prng_seed, PROJ_COORD_RE_RAND_TOTAL_RAND_BYTES);

	uint8_t *k = rxBuffer;
	uint8_t *P = k + CURVE25519_SCALAR_BYTES;
	uint8_t *R = P + CURVE25519_POINT_COMPRESSED_BYTES;

	// Receive ECSM scalar k
	get_bytes(CURVE25519_SCALAR_BYTES, k);

	// Receive ECSM input point P
	get_bytes(CURVE25519_POINT_COMPRESSED_BYTES, P);

	GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
	// Compute ECSM: R := [k] P
	crypto_scalarmult_curve25519_rand_proj_coords(R, k, P);
	GPIOC->BSRRH = GPIO_Pin_2; //Trigger off

	// Send ECSM output point R to host PC
	send_bytes(CURVE25519_POINT_COMPRESSED_BYTES, R);

}
