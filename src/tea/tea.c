#include <stdint.h>
#include "tea.h"

// From: https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
// From: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm#Reference_code

void tea_encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;
    uint32_t delta=0x9e3779b9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i < 32; i++) {
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }
    v[0]=v0; v[1]=v1;
}

void tea_decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;
    uint32_t delta=0x9e3779b9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i<32; i++) {
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }
    v[0]=v0; v[1]=v1;
}

// From: https://www.cix.co.uk/~klockstone/xtea.pdf
// From: https://en.wikipedia.org/wiki/XTEA#Implementations

void xtea_encrypt(uint32_t* v, uint32_t* k) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void xtea_decrypt(uint32_t* v, uint32_t* k) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*32;
    for (i=0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void swap_endianness(uint8_t* array){
	uint8_t i,t1,t2,t3,t4;
	t1 = array[0];
	t2 = array[1];
	t3 = array[2];
	t4 = array[3];
	array[0]=t4;
	array[1]=t3;
	array[2]=t2;
	array[3]=t1;

	}


