#include <stdint.h>

void tea_encrypt(uint32_t* v, uint32_t* k);
void tea_decrypt(uint32_t* v, uint32_t* k);
void xtea_encrypt(uint32_t* v, uint32_t* k);
void xtea_decrypt(uint32_t* v, uint32_t* k);
void swap_endianness(uint8_t* array);
