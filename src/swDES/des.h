#include <stddef.h>

typedef enum {
	ENCRYPT,
	DECRYPT
} DES_MODE;

typedef unsigned char uint8_t;

/*** Local functions for this DES implementation ***/
void ip(unsigned char []);
void fp(unsigned char []);
void shiftLeft(unsigned char[]);
void shiftRight(unsigned char[]);
void pc1(unsigned char[]);
void pc2(unsigned char[],unsigned char[]);
void makeMask(unsigned char [], unsigned char []);
uint8_t take_6_bits(unsigned char [], uint8_t );
void xor(unsigned char [],unsigned char [],uint8_t);
void E(unsigned char[],unsigned char[]);
uint8_t parity_check(unsigned char[]);
void do_p_n_xor(uint8_t sbox,unsigned char S_out[]);
void do_p_n_xor_dummy(uint8_t sbox,unsigned char S_out[]);
void des(unsigned char key[] , unsigned char data[], DES_MODE mode);
void desRandomDelays(unsigned char key[] , unsigned char data[], DES_MODE mode, unsigned char painLevel);
void desRandomSboxes(unsigned char key[] , unsigned char data[], DES_MODE mode);
void randomDelay(unsigned char painLevel);
void desMisaligned(unsigned char key[] , unsigned char data[], DES_MODE mode);
void desDummy(unsigned char key[] , unsigned char data[], DES_MODE mode);
uint8_t addDummy(uint8_t remainingDummyRounds);
