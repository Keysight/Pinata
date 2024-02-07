#ifndef _PRESENT_H_
#define _PRESENT_H_

#include <stdint.h>

void present80_encrypt(uint8_t* input, uint8_t* key, uint8_t* output);
void present80_decrypt(uint8_t* input, uint8_t* key, uint8_t* output);
void present128_encrypt(uint8_t* input, uint8_t* key, uint8_t* output);
void present128_decrypt(uint8_t* input, uint8_t* key, uint8_t* output);

#endif //_PRESENT_H
