#include "present.h"
#include <stdio.h>
#include <stdint.h>

static uint8_t rk[32][8];

static const uint8_t PERMUTATION[64] = {
		0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
		4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
		8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
		12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};
static const uint8_t INVERSE_PERMUTATION[64] = {
		0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c,
		0x01, 0x05, 0x09, 0x0d, 0x11, 0x15, 0x19, 0x1d, 0x21, 0x25, 0x29, 0x2d, 0x31, 0x35, 0x39, 0x3d,
		0x02, 0x06, 0x0a, 0x0e, 0x12, 0x16, 0x1a, 0x1e, 0x22, 0x26, 0x2a, 0x2e, 0x32, 0x36, 0x3a, 0x3e,
		0x03, 0x07, 0x0b, 0x0f, 0x13, 0x17, 0x1b, 0x1f, 0x23, 0x27, 0x2b, 0x2f, 0x33, 0x37, 0x3b, 0x3f
};
static const uint8_t NUM_ROUNDS = 32;
static const uint8_t INVERSE_SBOX[16] = {
		0x05, 0x0E, 0x0F, 0x08, 0x0C, 0x01, 0x02, 0x0D, 0x0B, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0A
};
static const uint8_t SBOX[16] = {
		0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02
};

static void add_round_key(uint8_t* in, uint8_t round, uint8_t* out) {
	uint8_t k;
	for (k = 0; k < 8; k++) {
		out[k] = in[k] ^ rk[round][k];
	}
}

static void sub_bytes(uint8_t* in, uint8_t* out) {
	uint8_t k;
	for (k = 0; k < 8; k++) {
		out[k] = SBOX[in[k] & 0xF] & 0xF;
		out[k] |= SBOX[in[k] >> 4] << 4;
	}
}

static void inv_sub_bytes(uint8_t* in, uint8_t* out) {
	uint8_t k;
	for (k = 0; k < 8; k++) {
		out[k] = INVERSE_SBOX[in[k] & 0xF] & 0xF;
		out[k] |= INVERSE_SBOX[in[k] >> 4] << 4;
	}
}

static void permute(uint8_t* in, uint8_t* out) {
	uint8_t k, bit;
	for (k = 0; k < 8; k++) {
		for (bit = 0; bit < 8; bit++) {
			uint8_t newIndex = PERMUTATION[k * 8 + bit];
			uint8_t byteIndex = newIndex / 8;
			uint8_t bitIndex = 7 - (newIndex % 8);
			uint8_t mask = ~(1 << bitIndex);
			out[byteIndex] = (out[byteIndex] & mask) | (((in[k] >> (7 - bit)) & 1) << bitIndex);
		}
	}
}

static void inv_permute(uint8_t* in, uint8_t* out) {
	uint8_t k, bit;
	for (k = 0; k < 8; k++) {
		for (bit = 0; bit < 8; bit++) {
			uint8_t newIndex = INVERSE_PERMUTATION[k * 8 + bit];
			uint8_t byteIndex = newIndex / 8;
			uint8_t bitIndex = 7 - (newIndex % 8);
			uint8_t mask = ~(1 << bitIndex);
			out[byteIndex] = (out[byteIndex] & mask) | (((in[k] >> (7 - bit)) & 1) << bitIndex);
		}
	}
}

static void key_schedule(uint8_t* key, uint8_t keylen) {
	uint8_t k, round, byte;
	uint8_t temp[16];			//enough room for any key
	uint8_t temp_key[16];		//enough room for any key

	for (k = 0; k < 8; k++) {
		rk[0][k] = key[k];
	}

	for (k = 0; k < keylen; k++) {
		temp_key[k] = key[k];
		temp[k] = 0;
	}

	for (round = 1; round < 32; round++) {
		//leftshift by 61
		for (byte = 0; byte < keylen; byte++) {
			uint8_t byte_shift = (7 + byte) % keylen;		//61 / 8 - byte
			uint8_t bit_shift = 5;			                //61 % 8
			temp[byte] = temp_key[byte_shift] << bit_shift;
			temp[byte] |= (temp_key[(byte_shift + 1) % keylen] >> (8 - bit_shift)) & 0x1F;
		}

		//sbox, xor round_num
		if (keylen == 10) {
			temp[0] = (SBOX[temp[0] >> 4] << 4) | (temp[0] & 0xF);
			temp[7] = (temp[7] & 0xF0) | (temp[7] ^ (round >> 1) & 0x0F);
			temp[8] = (temp[8] & 0x7F) | (temp[8] ^ (round << 7) & 0x80);
		}
		else {
			temp[0] = (SBOX[temp[0] >> 4] << 4) | (SBOX[temp[0] & 0xF]);
			temp[7] = (temp[7] & 0xF8) | (temp[7] ^ (round >> 2) & 0x07);
			temp[8] = (temp[8] & 0x3F) | (temp[8] ^ (round << 6) & 0xC0);
		}

		for (k = 0; k < keylen; k++) {
			temp_key[k] = temp[k];
		}
		for (k = 0; k < 8; k++) {
			rk[round][k] = temp[k];
		}
	}
}

void present80_encrypt(uint8_t* input, uint8_t* key, uint8_t* out) {
	uint8_t round;
	uint8_t temp[8];

	key_schedule(key, 10);

	add_round_key(input, 0, out);
	for (round = 1; round < 32; round++) {
		sub_bytes(out, temp);
		permute(temp, out);
		add_round_key(out, round, out);
	}
}

void present80_decrypt(uint8_t* input, uint8_t* key, uint8_t* out) {
	uint8_t round;
	uint8_t k;
	uint8_t temp[8];

	key_schedule(key, 10);

	for (k = 0; k < 8; k++) {
		temp[k] = input[k];
	}
	for (round = 31; round > 0; round--) {
		add_round_key(temp, round, temp);
		inv_permute(temp, out);
		inv_sub_bytes(out, temp);
	}
	add_round_key(temp, 0, out);
}

void present128_encrypt(uint8_t* input, uint8_t* key, uint8_t* out) {
	uint8_t round;
	uint8_t temp[8];

	key_schedule(key, 16);

	add_round_key(input, 0, out);
	for (round = 1; round < 32; round++) {
		sub_bytes(out, temp);
		permute(temp, out);
		add_round_key(out, round, out);
	}
}

void present128_decrypt(uint8_t* input, uint8_t* key, uint8_t* out) {
	uint8_t round;
	uint8_t k;
	uint8_t temp[8];

	key_schedule(key, 16);

	for (k = 0; k < 8; k++) {
		temp[k] = input[k];
	}
	for (round = 31; round > 0; round--) {
		add_round_key(temp, round, temp);
		inv_permute(temp, out);
		inv_sub_bytes(out, temp);
	}
	add_round_key(temp, 0, out);
}
