#ifndef _MAES_C_
#define _MAES_C_


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include "maes.h"
#include "stm32f4xx.h" //For GPIO pins addressing (trigger signal)
#include "stm32f4xx_gpio.h"//For GPIO pins addressing (trigger signal)
#include "stm32f4xx_rng.h"
#include "rng.h"

#define NO_CM 0x00
#define RANDOM_DELAYS 0x01  
#define RANDOM_SBOX 0x02    
#define MASKED_SBOX 0x04

#define MAX_CM RANDOM_DELAYS|RANDOM_SBOX|MASKED_SBOX

#define NROUNDS 10

uint8_t pick_rand();
void sbox_lookup(uint8_t [][4],uint8_t *);
void key_schedule(uint8_t *,uint8_t);
void inv_key_schedule(uint8_t *, uint8_t);
void mix_columns(uint8_t [][4]);
void inv_mix_columns(uint8_t [][4]);
void shift_rows(uint8_t [][4], int);
void key_addition(uint8_t [][4], uint8_t [][4]);
void set_state(uint8_t [][4], uint8_t *);
void get_state(uint8_t *, uint8_t [][4]);
uint8_t mul(uint8_t, uint8_t );
void make_mask(uint8_t *, uint8_t *, uint8_t, uint8_t );
void rndDelay(uint8_t);
void sbox_mask(uint8_t *, uint8_t *, uint8_t, uint8_t );

uint8_t shifts[4][2]={ {0,0},{1,3},{2,2},{3,1} };
uint8_t rcon[30] = { 0x01,0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91 };

/*** MASKED_SBOX Sbox ***/

uint8_t Smasked[256];
uint8_t cmflags=MASKED_SBOX; //Countermeasures flags; masking is enabled by default
uint8_t row_offset=0,col_offset=0;

/*** Local functions for the RNG ***/
unsigned char pick_rnd();

/*** RNG global arrays ***/

unsigned char seed[16];
unsigned char rkey[16];
unsigned char aeskey[16];
unsigned char auth_key[16];

unsigned char ee_dummy;

// S-Box
uint8_t S[] =
{
		99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118,
		202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
		183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21,
		4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117,
		9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
		83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207,
		208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,
		81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210,
		205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115,
		96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
		224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121,
		231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8,
		186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138,
		112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158,
		225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
		140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22,
};

uint8_t Si[]  = {
		82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
		124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
		84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
		8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
		114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
		108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
		144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
		208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
		58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
		150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
		71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
		252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
		31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
		96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
		160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
		23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125,
};

uint8_t Logtable[]  = {
		0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3,
		100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193,
		125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120,
		101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142,
		150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56,
		102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16,
		126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186,
		43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87,
		175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,
		44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160,
		127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183,
		204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157,
		151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,
		83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171,
		68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165,
		103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7,
};

uint8_t Alogtable[]  = {
		1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,
		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170,
		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49,
		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,
		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136,
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154,
		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163,
		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160,
		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65,
		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117,
		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202,
		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14,
		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23,
		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1,
};

//Masks for the data masking implementation
unsigned char mask1[4],mask2[4];
uint8_t pgm_read_byte (uint8_t *in)
{
	return *in;
}

void make_mask(uint8_t *Sm, uint8_t *So, uint8_t mask_in, uint8_t mask_out){
	uint8_t i;
	for ( i = 0; i < 255; i++ ) {
		Sm[i ^ mask_in] = (pgm_read_byte(So+i) ^ mask_out);
	}
	Sm[i ^ mask_in] = (pgm_read_byte(So+i) ^ mask_out);


}

void array_copy (uint8_t *out, uint8_t *in, int len)
{
	int i = 0;
	for (i=0; i<len; i++)
	{
		out[i] = in[i];
	}
}

//Masked AES
void maes_encrypt(uint8_t *a, uint8_t *key){
	uint8_t r;
	uint8_t d[4][4];
	uint8_t k[4][4];
	uint8_t roundkey[16];
	uint8_t i,j;

	array_copy(roundkey,key,16);
	//Masks
	uint8_t mask1=0,mask2=0;
	uint8_t m1[4][4]; //This is the state mask before mixColumns
	uint8_t m2[4][4]; //state mask after mixColumns


	mask1 = pick_rand();
	mask2 = pick_rand();

	for(i=0;i<4;i++) {
		for(j=0;j<4;j++)
		{
			m2[i][j]=m1[i][j]=pick_rand();
		}
	}

	sbox_mask(Smasked,S,mask1,mask2);

	//Apply mixColumns to mask2
	mix_columns(m2);

	set_state(d,a);
	set_state(k,roundkey);

	for(i=0;i<4;i++){
		for(j=0;j<4;j++){

			d[i][j] ^= m2[i][j];
			k[i][j] ^= m2[i][j] ^ mask1;
		}
	}


	//And apply masks everywhere
	set_state(d,a);
	set_state(k,roundkey);

	for(i=0;i<4;i++) {
			for(j=0;j<4;j++) {
					d[i][j] ^= m2[i][j];
					k[i][j] ^= m2[i][j] ^ mask1;
			}
	}

	// Round key addition
	key_addition(d,k);
	for(r=1;r<NROUNDS;r++)
	{

		sbox_lookup(d, Smasked);
		shift_rows(d,0);

		for(i=0;i<4;i++){
			for(j=0;j<4;j++){
				d[i][j] ^= m1[i][j] ^ mask2;
			}
		}

		mix_columns(d);
		key_schedule(roundkey,r);
		set_state(k,roundkey);

		for (i = 0; i<4; i++) {
			for (j = 0; j<4; j++) {
				k[i][j] ^= m2[i][j] ^ mask1;
			}
		}

		key_addition(d,k);
	}

	//final round without mix_columns
	sbox_lookup(d, Smasked);
	shift_rows(d,0);
	key_schedule(roundkey,r);
	set_state(k,roundkey);

	for (i = 0; i<4; i++){
		for (j = 0; j<4; j++){
			k[i][j] ^= mask2;
		}
	}


	key_addition(d,k);
	get_state(a,d);
	return;
}

//AES with configurable countermeasures
void aes_encrypt(uint8_t *a, uint8_t *key){
	uint8_t r;
	uint8_t d[4][4];
	uint8_t k[4][4];
	uint8_t roundkey[16];
	uint8_t i,j;

	//Reset index for RNG
	row_offset=col_offset=0;

	array_copy(roundkey,key,16);
	//Masks
	uint8_t mask1=0,mask2=0;
	uint8_t m1[4][4]; //This is the state mask before mixColumns
	uint8_t m2[4][4]; //state mask after mixColumns

	if(cmflags & MASKED_SBOX){

		mask1 = pick_rand();

		mask2 = pick_rand();

		for(i=0;i<4;i++)
			for(j=0;j<4;j++)
				m2[i][j]=m1[i][j]=pick_rand();

		//Recalculate S-boxes

		make_mask(Smasked,S,mask1,mask2);
		//Apply mixColumns to mask2
		mix_columns(m2);
	}

	//And apply masks everywhere

	set_state(d,a);
	set_state(k,roundkey);

	if(cmflags & MASKED_SBOX){
		for(i=0;i<4;i++)
			for(j=0;j<4;j++){
				d[i][j] ^= m2[i][j];
				k[i][j] ^= m2[i][j] ^ mask1;
			}
	}

	/* Initial round only keyAddition
	   with first round key = encryption key */

	key_addition(d,k);
	//Now NROUNDS-1 ordinary NROUNDS
	for(r=1;r<NROUNDS;r++){

		if(cmflags& RANDOM_SBOX){
			row_offset = pick_rand();
			col_offset = row_offset & 0x03;
			row_offset = ((row_offset)>>2)&0x03;
		}

		GPIOC->BSRRL = GPIO_Pin_1;
		sbox_lookup(d,(cmflags&MASKED_SBOX)? Smasked:S);
		GPIOC->BSRRH = GPIO_Pin_1;

		shift_rows(d,0);

		if(cmflags & MASKED_SBOX){
			for(i=0;i<4;i++)
				for(j=0;j<4;j++){
					d[i][j] ^= m1[i][j] ^ mask2;
				}
		}

		mix_columns(d);
		key_schedule(roundkey,r);
		set_state(k,roundkey);

		if(cmflags & MASKED_SBOX){
			for (i = 0; i<4; i++)
				for (j = 0; j<4; j++) {
					k[i][j] ^= m2[i][j] ^ mask1;
				}
		}

		key_addition(d,k);
	}

	//And the final round without mix_columns
	sbox_lookup(d,(cmflags&MASKED_SBOX)? Smasked:S);
	shift_rows(d,0);
	key_schedule(roundkey,r);
	set_state(k,roundkey);
	if(cmflags & MASKED_SBOX){
		for (i = 0; i<4; i++)
			for (j = 0; j<4; j++)
				k[i][j] ^= mask2;
	}

	key_addition(d,k);
	get_state(a,d);
	return;
}

//Only masked AES decrypt (no rnd delays or rnd order of sboxes)
void maes_decrypt(uint8_t *a, uint8_t *key){
	uint8_t r;
	uint8_t i,j;

	uint8_t mask1=0,mask2=0;
	uint8_t m1[4][4]; //This is the state mask before mixColumns
	uint8_t m2[4][4]; //state mask after mixColumns

	uint8_t d[4][4];
	uint8_t k[4][4];

	set_state(d,a);
	set_state(k,key);


	//Prepare masks
	mask1=pick_rand();
	mask2=pick_rand();
	sbox_mask(Smasked, Si ,mask1, mask2);

	for (i=0; i<4; i++) {
		for (j=0; j<4;j++) {
				m2[i][j] = m1[i][j]=pick_rand();
		}
	}
	inv_mix_columns(m2);

	//Prepare key for inverse scheduling by running the full direct schedule
	for(i=1;i<=10;i++)
	  key_schedule(key,i);

	set_state(k,key);


	//Now mask data and key so that after addition mask1 masks everything
	for (i = 0; i<4; i++) {
		for (j = 0; j<4; j++) {
				d[i][j] ^= m1[i][j];
				k[i][j] ^= m1[i][j] ^ mask1;
		}
	}

	key_addition(d,k);
	sbox_lookup(d, Smasked);
	shift_rows(d,1);


	for(r = NROUNDS-1; r > 0; r--) {

		inv_key_schedule(key,r);
		set_state(k,key);

		for (i = 0; i<4; i++){
			for (j = 0; j<4; j++) {
					k[i][j] ^= m1[i][j] ^ mask2;
			}
		}


		key_addition(d,k);
		inv_mix_columns(d);

		//Re-mask so that mask1 masks state
		for(i=0;i<4;i++) {
			for(j=0;j<4;j++) {
				d[i][j]^=m2[i][j]^mask1;
			}
		}

		sbox_lookup(d, Smasked);
		shift_rows(d,1);
	}
	inv_key_schedule(key,r);
	set_state(k,key);

	for (i = 0; i<4; i++) {
		for (j = 0; j<4; j++) {
			k[i][j] ^= mask2;
		}
	}

	key_addition(d,k);
	get_state(a,d);

}


/** Performs sbox lookups for encryption and decryption.
 *  This function already takes care of random delays
 *  and S-box lookup shuffling.
 */


void sbox_lookup(uint8_t a[][4], uint8_t *myS){
	uint8_t i,j;

	for(i=0;i<4;i++)
		for(j=0;j<4;j++){
			if(cmflags & RANDOM_DELAYS){
				rndDelay(2);
			}
			a[(i+row_offset)&0x03][(j+col_offset)&0x03]= (cmflags & MASKED_SBOX)? myS[a[(i+row_offset)&0x03][(j+col_offset)&0x03]]: pgm_read_byte(myS+a[(i+row_offset)&0x03][(j+col_offset)&0x03]);
		}
}

void key_schedule(uint8_t *key, uint8_t i){
	//	static uint8_t i=1;
	uint8_t j;
	//Copy, rotate and apply S-box to the previous key bytes
	uint8_t tmp[4] = {pgm_read_byte(S+key[13]),pgm_read_byte(S+key[14]),pgm_read_byte(S+key[15]),pgm_read_byte(S+key[12])};


	//finish key schedule core
	tmp[0] ^= rcon[i-1];
	i++;;

	// XOR tmp with 4 initial bytes of previous key
	key[0] ^=tmp[0];
	key[1] ^= tmp[1];
	key[2] ^= tmp[2];
	key[3] ^= tmp[3];

	for(j=0;j<12;j++)
		key[4+j]^=key[j];
}

void inv_key_schedule(uint8_t k[], uint8_t r ){
	uint8_t i;

	for( i = 12; i > 0; i -= 4 ){
		k[i + 0] ^= k[i - 4];
		k[i + 1] ^= k[i - 3];
		k[i + 2] ^= k[i - 2];
		k[i + 3] ^= k[i - 1];
	}
	// XOR with rotate and rcon
	k[0] ^= (S[k[13]]) ^ rcon[r];
	k[1] ^= (S[k[14]]);
	k[2] ^= (S[k[15]]);
	k[3] ^= (S[k[12]]);
}

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

// MixColumns function mixes the columns of the state matrix
void mix_columns(uint8_t state[][4])
{
	int i;
	unsigned char Tmp,Tm,t;
	for(i=0;i<4;i++)
	{
		t=state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i] ;
		Tm = state[0][i] ^ state[1][i] ; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp ;
		Tm = state[1][i] ^ state[2][i] ; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp ;
		Tm = state[2][i] ^ state[3][i] ; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp ;
		Tm = state[3][i] ^ t ; Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp ;
	}
}
// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
uint8_t Multiply(uint8_t x, uint8_t y)
{
	return (((y & 1) * x) ^
			((y>>1 & 1) * xtime(x)) ^
			((y>>2 & 1) * xtime(xtime(x))) ^
			((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
			((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}
#else
#define Multiply(x, y)                                \
		(  ((y & 1) * x) ^                              \
				((y>>1 & 1) * xtime(x)) ^                       \
				((y>>2 & 1) * xtime(xtime(x))) ^                \
				((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
				((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
void inv_mix_columns(uint8_t state[][4])
{
  int i;
  uint8_t a,b,c,d;
  for(i=0;i<4;++i)
  {
    a = (state)[0][i];
    b = (state)[1][i];
    c = (state)[2][i];
    d = (state)[3][i];

    (state)[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (state)[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (state)[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (state)[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);

  }
}

void shift_rows(uint8_t a[][4],int mode){
	uint8_t tmp[4];
	uint8_t i,j;

	for(i=0;i<4;i++){
		for(j=0;j<4;j++){
			tmp[(j+col_offset)&0x03] = a[(i+row_offset)&0x03][ (j+col_offset+shifts[(i+row_offset)&0x03][mode]) % 4];
		}
		for(j=0;j<4;j++){
			a[(i+row_offset)&0x03][(j+col_offset)&0x03]=tmp[(j+col_offset)&0x03];
		}
	}
}
void key_addition(uint8_t a[][4], uint8_t key[][4]){
	uint8_t i,j;
	for(i=0;i<4;i++)
		for(j=0;j<4;j++){
			a[i][j]^=key[i][j];
		}
}

void set_state(uint8_t d[][4],uint8_t *a){
	uint8_t i,j;
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			d[i][j] = a[i+4*j];
}

void get_state(uint8_t *a, uint8_t d[][4]){
	uint8_t i,j;
	for(i=0;i<4;i++)
		for(j=0;j<4;j++)
			a[i+4*j]=d[i][j];

}

uint8_t pick_rand(){
	unsigned char ret;
	RNG_Enable();
	while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET)
	{}
	ret=(uint8_t) (RNG_GetRandomNumber() & 0xFF);
	RNG_Disable();
	return ret;
}

void sbox_mask(uint8_t* Sm, uint8_t* So, uint8_t mask_in, uint8_t mask_out)
{
	int i;
	for ( i = 0; i < 256; i++ ){
		Sm[i ^ mask_in] = So [i] ^ mask_out;

	}
}

void rndDelay(uint8_t painLevel){
	uint32_t randomNumber;
	RNG_Enable();
	do{
		//Get a random number
		while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
		randomNumber= RNG_GetRandomNumber();
	} while((randomNumber%painLevel)!=0);
	RNG_Disable();
}

static void BlockCopy(uint8_t* output, uint8_t* input)
{
  uint8_t i;
  for (i=0;i<16;++i)
  {
    output[i] = input[i];
  }
}

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

void mAES128_ECB_encrypt(uint8_t* input, uint8_t* key, uint8_t *output)
{
	cmflags=MASKED_SBOX;
	// The next function call encrypts the PlainText with the Key using AES algorithm.
	GPIOC->BSRRL = GPIO_Pin_2; // Trigger goes high in pin PC2
	maes_encrypt(input, key);
	GPIOC->BSRRH = GPIO_Pin_2; // Trigger goes low in pin PC2
	array_copy(output,input,16);

}

void mAES128_ECB_decrypt(uint8_t* input, uint8_t* key, uint8_t *output)
{
	BlockCopy(output, input);
	GPIOC->BSRRL = GPIO_Pin_2; // Trigger goes high in pin PC2
	maes_decrypt(input, key);
	GPIOC->BSRRH = GPIO_Pin_2; // Trigger goes low in pin PC2
	array_copy(output,input,16);
}

void AES128_ECB_encrypt_rndDelays(uint8_t* input, uint8_t* key, uint8_t *output)
{
	cmflags=RANDOM_DELAYS;
	// The next function call encrypts the PlainText with the Key using AES algorithm.
	GPIOC->BSRRL = GPIO_Pin_2; // Trigger goes high in pin PC2
	aes_encrypt(input, key);
	GPIOC->BSRRH = GPIO_Pin_2; // Trigger goes low in pin PC2
	array_copy(output,input,16);
}

void AES128_ECB_encrypt_rndSbox(uint8_t* input, uint8_t* key, uint8_t *output)
{
	cmflags=RANDOM_SBOX;
	// The next function call encrypts the PlainText with the Key using AES algorithm.
	GPIOC->BSRRL = GPIO_Pin_2; // Trigger goes high in pin PC2
	aes_encrypt(input, key);
	GPIOC->BSRRH = GPIO_Pin_2; // Trigger goes low in pin PC2
	array_copy(output,input,16);
}

#endif //_MAES_C_
