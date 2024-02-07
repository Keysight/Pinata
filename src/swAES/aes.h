#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

void AES128_ECB_encrypt(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_decrypt(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_encrypt_noTrigger(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_encrypt_misaligned(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_encrypt_dummy(uint8_t* input, uint8_t* key, uint8_t *output);
uint8_t addDummyOp(uint8_t remainingDummyRounds);

#endif //_AES_H_
