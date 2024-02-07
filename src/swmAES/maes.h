#ifndef _MAES_H_
#define _MAES_H_

#include <stdint.h>

void mAES128_ECB_encrypt(uint8_t* input, uint8_t* key, uint8_t *output);
void mAES128_ECB_decrypt(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_encrypt_rndDelays(uint8_t* input, uint8_t* key, uint8_t *output);
void AES128_ECB_encrypt_rndSbox(uint8_t* input, uint8_t* key, uint8_t *output);

#endif //_MAES_H_
