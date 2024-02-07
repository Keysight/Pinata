#include <stdlib.h>
#include "des.h"
#include "stm32f4xx_rng.h"
#include "rng.h"

/**
 *  Software DES implementation with software countermeasures
 */


/*** Global variables DES-related ***/

	unsigned char k[7];
	unsigned char l[4];
	unsigned char r[4];
	unsigned char kd[7];
    unsigned char ld[4];
	unsigned char rd[4];


	uint8_t rounds=16;

/*** DES original SBoxes ***/

	// S-Box 1
static unsigned char S1[]  =
    { 0xe, 0x0, 0x4, 0xf, 0xd, 0x7, 0x1, 0x4, 0x2, 0xe, 0xf, 0x2, 0xb, 0xd, 0x8, 0x1,
      0x3, 0xa, 0xa, 0x6, 0x6, 0xc, 0xc, 0xb, 0x5, 0x9, 0x9, 0x5, 0x0, 0x3, 0x7, 0x8,
      0x4, 0xf, 0x1, 0xc, 0xe, 0x8, 0x8, 0x2, 0xd, 0x4, 0x6, 0x9, 0x2, 0x1, 0xb, 0x7,
      0xf, 0x5, 0xc, 0xb, 0x9, 0x3, 0x7, 0xe, 0x3, 0xa, 0xa, 0x0, 0x5, 0x6, 0x0, 0xd};

	// S-Box 2
static unsigned char S2[]  =
    { 0xf, 0x3, 0x1, 0xd, 0x8, 0x4, 0xe, 0x7, 0x6, 0xf, 0xb, 0x2, 0x3, 0x8, 0x4, 0xe,
      0x9, 0xc, 0x7, 0x0, 0x2, 0x1, 0xd, 0xa, 0xc, 0x6, 0x0, 0x9, 0x5, 0xb, 0xa, 0x5,
      0x0, 0xd, 0xe, 0x8, 0x7, 0xa, 0xb, 0x1, 0xa, 0x3, 0x4, 0xf, 0xd, 0x4, 0x1, 0x2,
      0x5, 0xb, 0x8, 0x6, 0xc, 0x7, 0x6, 0xc, 0x9, 0x0, 0x3, 0x5, 0x2, 0xe, 0xf, 0x9
};
	// S-Box 3
static unsigned char S3[]  =
    { 0xa, 0xd, 0x0, 0x7, 0x9, 0x0, 0xe, 0x9, 0x6, 0x3, 0x3, 0x4, 0xf, 0x6, 0x5, 0xa,
      0x1, 0x2, 0xd, 0x8, 0xc, 0x5, 0x7, 0xe, 0xb, 0xc, 0x4, 0xb, 0x2, 0xf, 0x8, 0x1,
      0xd, 0x1, 0x6, 0xa, 0x4, 0xd, 0x9, 0x0, 0x8, 0x6, 0xf, 0x9, 0x3, 0x8, 0x0, 0x7,
      0xb, 0x4, 0x1, 0xf, 0x2, 0xe, 0xc, 0x3, 0x5, 0xb, 0xa, 0x5, 0xe, 0x2, 0x7, 0xc
};
	// S-Box 4
static unsigned char S4[]  =
    { 0x7, 0xd, 0xd, 0x8, 0xe, 0xb, 0x3, 0x5, 0x0, 0x6, 0x6, 0xf, 0x9, 0x0, 0xa, 0x3,
      0x1, 0x4, 0x2, 0x7, 0x8, 0x2, 0x5, 0xc, 0xb, 0x1, 0xc, 0xa, 0x4, 0xe, 0xf, 0x9,
      0xa, 0x3, 0x6, 0xf, 0x9, 0x0, 0x0, 0x6, 0xc, 0xa, 0xb, 0x1, 0x7, 0xd, 0xd, 0x8,
      0xf, 0x9, 0x1, 0x4, 0x3, 0x5, 0xe, 0xb, 0x5, 0xc, 0x2, 0x7, 0x8, 0x2, 0x4, 0xe
};

	// S-Box 5
static unsigned char S5[]  =
    { 0x2, 0xe, 0xc, 0xb, 0x4, 0x2, 0x1, 0xc, 0x7, 0x4, 0xa, 0x7, 0xb, 0xd, 0x6, 0x1,
      0x8, 0x5, 0x5, 0x0, 0x3, 0xf, 0xf, 0xa, 0xd, 0x3, 0x0, 0x9, 0xe, 0x8, 0x9, 0x6,
      0x4, 0xb, 0x2, 0x8, 0x1, 0xc, 0xb, 0x7, 0xa, 0x1, 0xd, 0xe, 0x7, 0x2, 0x8, 0xd,
      0xf, 0x6, 0x9, 0xf, 0xc, 0x0, 0x5, 0x9, 0x6, 0xa, 0x3, 0x4, 0x0, 0x5, 0xe, 0x3
};

	// S-Box 6
static unsigned char S6[]  =
    { 0xc, 0xa, 0x1, 0xf, 0xa, 0x4, 0xf, 0x2, 0x9, 0x7, 0x2, 0xc, 0x6, 0x9, 0x8, 0x5,
      0x0, 0x6, 0xd, 0x1, 0x3, 0xd, 0x4, 0xe, 0xe, 0x0, 0x7, 0xb, 0x5, 0x3, 0xb, 0x8,
      0x9, 0x4, 0xe, 0x3, 0xf, 0x2, 0x5, 0xc, 0x2, 0x9, 0x8, 0x5, 0xc, 0xf, 0x3, 0xa,
      0x7, 0xb, 0x0, 0xe, 0x4, 0x1, 0xa, 0x7, 0x1, 0x6, 0xd, 0x0, 0xb, 0x8, 0x6, 0xd
};

	// S-Box 7
static unsigned char S7[]  =
    { 0x4, 0xd, 0xb, 0x0, 0x2, 0xb, 0xe, 0x7, 0xf, 0x4, 0x0, 0x9, 0x8, 0x1, 0xd, 0xa,
      0x3, 0xe, 0xc, 0x3, 0x9, 0x5, 0x7, 0xc, 0x5, 0x2, 0xa, 0xf, 0x6, 0x8, 0x1, 0x6,
      0x1, 0x6, 0x4, 0xb, 0xb, 0xd, 0xd, 0x8, 0xc, 0x1, 0x3, 0x4, 0x7, 0xa, 0xe, 0x7,
      0xa, 0x9, 0xf, 0x5, 0x6, 0x0, 0x8, 0xf, 0x0, 0xe, 0x5, 0x2, 0x9, 0x3, 0x2, 0xc
};
	// S-Box 8

static unsigned char S8[]  =
    { 0xd, 0x1, 0x2, 0xf, 0x8, 0xd, 0x4, 0x8, 0x6, 0xa, 0xf, 0x3, 0xb, 0x7, 0x1, 0x4,
      0xa, 0xc, 0x9, 0x5, 0x3, 0x6, 0xe, 0xb, 0x5, 0x0, 0x0, 0xe, 0xc, 0x9, 0x7, 0x2,
      0x7, 0x2, 0xb, 0x1, 0x4, 0xe, 0x1, 0x7, 0x9, 0x4, 0xc, 0xa, 0xe, 0x8, 0x2, 0xd,
      0x0, 0xf, 0x6, 0xc, 0xa, 0x9, 0xd, 0x0, 0xf, 0x3, 0x3, 0x5, 0x5, 0x6, 0x8, 0xb
};



//Helper array to S-boxes to easily access them in a loop
unsigned char * Sbox[] = { S1,S2,S3,S4,S5,S6,S7,S8 };

//Masks for the data masking implementation
unsigned char mask1_des[4],mask2_des[4];

uint8_t take_6_bits(unsigned char b[], uint8_t init){
		 uint8_t mask=0xFC;
         uint8_t mask1_des,mask2_des,result,offset;

         uint8_t idx=init/8;
         offset=init%8;

         mask1_des=mask >> (offset );
         mask2_des = mask << ( 8-offset);
         result= (b[idx] & mask1_des)<<offset;

         if(mask2_des!=0)
           result |= (b[idx+1] & mask2_des) >> (8-offset);

        result = result >> 2;
        return result;
}

void xor(unsigned char dst[],unsigned char src[], uint8_t length){
	uint8_t i;
	for(i=0;i<length;i++)
		dst[i]^=src[i];
}

/*** This function performs DES encryption of data using the key k */
void des(unsigned char key[] , unsigned char data[], DES_MODE mode){
	uint8_t LS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	uint8_t round_ctr; //round counter, 'round' identifier reserved ( round function )

	unsigned char i;
	uint8_t E_out[6],S_out[8];
	unsigned char *used_key = key;

	//round data mixed with round key
	unsigned char a[6];

	// left and right halves

	// permute data
	ip( data );//,l,r);

	// permute key
	pc1( used_key );//, k );

	// encryption 16 rounds
	for ( round_ctr = 0; round_ctr < 16; round_ctr++) {

		if (mode == ENCRYPT) {
			shiftLeft(k);
			if (LS[round_ctr] > 1)
				shiftLeft(k);
		}

		pc2(k,a);

		if(mode==DECRYPT){
			shiftRight(k);
			if (LS[15-round_ctr] > 1)
				shiftRight(k);
		}

		// Er + xor

		E(r,E_out);
		xor(a,E_out,6);

		for(i=0;i<8;i++){
			S_out[i] = Sbox[i][take_6_bits(a,6*i)];
			do_p_n_xor(i,S_out);
		}

		for(i=0;i<4;i++){
			uint8_t tmp;
			tmp=l[i];
			l[i]=r[i];
			r[i]=tmp;
		}

	}

	fp(data);
}

/*** This function performs DES encryption of data using the key k, adds dummyRounds up to amountOfDummyRounds (defined as local variable, 5 by default) */
void desDummy(unsigned char key[] , unsigned char data[], DES_MODE mode){
	uint8_t LS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	uint8_t round_ctr; //round counter, 'round' identifier reserved ( round function )
	uint8_t amountOfDummyRounds=16;
	uint8_t dummy1 =0; uint8_t dummy2=0; uint8_t dummy3=0; //dummy variables to compensate for dummy operations in real rounds

	unsigned char i;
	uint8_t E_out[6],S_out[8];
	uint8_t E_outd[6],S_outd[8]; //dummy
	unsigned char *used_key = key;

	//round data mixed with round key
	unsigned char a[6];
	unsigned char ad[6]; //dummy

	// left and right halves

	// permute data
	ip( data );//,l,r);

	// permute key
	pc1( used_key );//, k );

	// encryption 16 rounds, will use dummy data for some rounds (up to amountOfDummyRounds)
	for ( round_ctr = 0; round_ctr < 16; ) {
		if(addDummy(amountOfDummyRounds)){
			//Dummy round (all variables end in d)
			if (mode == ENCRYPT) {
				shiftLeft(kd);
				if (LS[round_ctr] > 1)
					shiftLeft(kd);
			}

			pc2(kd,ad);

			if(mode==DECRYPT){
				shiftRight(kd);
				if (LS[15-round_ctr] > 1)
					shiftRight(kd);
			}

			// Er + xor

			E(rd,E_outd);
			xor(ad,E_outd,6);

			for(i=0;i<8;i++){
				S_outd[i] = Sbox[i][take_6_bits(ad,6*i)];
				do_p_n_xor_dummy(i,S_outd);
			}

			for(i=0;i<4;i++){
				uint8_t tmpd;
				tmpd=ld[i];
				ld[i]=rd[i];
				rd[i]=tmpd;
			}
			amountOfDummyRounds--; //Subtract 1 to amount of dummy rounds to add.
		}
		//Real round
		else{
			if (mode == ENCRYPT) {
				shiftLeft(k);
				if (LS[round_ctr] > 1)
					shiftLeft(k);
			}

			pc2(k,a);

			if(mode==DECRYPT){
				shiftRight(k);
				if (LS[15-round_ctr] > 1)
					shiftRight(k);
			}

			// Er + xor

			E(r,E_out);
			xor(a,E_out,6);

			for(i=0;i<8;i++){
				S_out[i] = Sbox[i][take_6_bits(a,6*i)];
				do_p_n_xor(i,S_out);
			}

			for(i=0;i<4;i++){
				uint8_t tmp;
				tmp=l[i];
				l[i]=r[i];
				r[i]=tmp;
			}

			round_ctr++;
		}
	}
	for ( ;amountOfDummyRounds>0; amountOfDummyRounds--) {
		//Dummy round (all variables end in d)
		if (mode == ENCRYPT) {
			shiftLeft(kd);
			if (LS[round_ctr] > 1)
				shiftLeft(kd);
		}

		pc2(kd,ad);

		if(mode==DECRYPT){
			shiftRight(kd);
			if (LS[15-round_ctr] > 1)
				shiftRight(kd);
		}

		// Er + xor

		E(rd,E_outd);
		xor(ad,E_outd,6);

		for(i=0;i<8;i++){
			S_outd[i] = Sbox[i][take_6_bits(ad,6*i)];
			do_p_n_xor_dummy(i,S_outd);
		}

		for(i=0;i<4;i++){
			uint8_t tmpd;
			tmpd=ld[i];
			ld[i]=rd[i];
			rd[i]=tmpd;
		}

	}

	fp(data);

}

void desMisaligned(unsigned char key[] , unsigned char data[], DES_MODE mode){
	randomDelay(3);
	des(key, data, ENCRYPT);
}


/*** This function performs DES encryption of data using the key k */
void desRandomSboxes(unsigned char key[] , unsigned char data[], DES_MODE mode){
	uint8_t LS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	uint8_t round_ctr; //round counter, 'round' identifier reserved ( round function )

	unsigned char i;
	uint8_t E_out[6],S_out[8];
	unsigned char *used_key = key;

	//round data mixed with round key
	unsigned char a[6];

	uint8_t currSbox=0;

	//Get a random number
	RNG_Enable();
	while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
	currSbox=(uint8_t) (RNG_GetRandomNumber() & 0x07);
	RNG_Disable();

	// left and right halves

	// permute data
	ip( data );//,l,r);

    // permute key
	pc1( used_key );//, k );

	// encryption 16 rounds
	for ( round_ctr = 0; round_ctr < 16; round_ctr++) {

		if (mode == ENCRYPT) {
			shiftLeft(k);
			if (LS[round_ctr] > 1)
				shiftLeft(k);
		}

		pc2(k,a);

		if(mode==DECRYPT){
			shiftRight(k);
				if (LS[15-round_ctr] > 1)
				 shiftRight(k);
		}

		// Er + xor

		E(r,E_out);
		xor(a,E_out,6);

		for(i=0;i<8;i++){
			S_out[currSbox] = Sbox[currSbox][take_6_bits(a,6*currSbox)];
			do_p_n_xor(currSbox,S_out);
			currSbox = (currSbox+1) & 0x07;
		}

		for(i=0;i<4;i++){
			uint8_t tmp;
			tmp=l[i];
			l[i]=r[i];
			r[i]=tmp;
		}

	}

	fp(data);
}

/*** This function performs DES encryption of data using the key k */
void desRandomDelays(unsigned char key[] , unsigned char data[], DES_MODE mode, unsigned char painLevel){

	uint8_t LS[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	uint8_t round_ctr; //round counter, 'round' identifier reserved ( round function )

	unsigned char i;
	uint8_t E_out[6],S_out[8];
	unsigned char *used_key = key;

	//round data mixed with round key
	unsigned char a[6];

	// left and right halves

	// permute data
	ip( data );//,l,r);

	// permute key
	pc1( used_key );//, k );

	// encryption 16 rounds
	for ( round_ctr = 0; round_ctr < 16; round_ctr++) {

		if (mode == ENCRYPT) {
			shiftLeft(k);
			if (LS[round_ctr] > 1)
				shiftLeft(k);
		}

		pc2(k,a);

		if(mode==DECRYPT){
			shiftRight(k);
			if (LS[15-round_ctr] > 1)
				shiftRight(k);
		}

		// Er + xor

		E(r,E_out);
		xor(a,E_out,6);

		for(i=0;i<8;i++){
			randomDelay(painLevel); //Random delays in Sboxes only
			S_out[i] = Sbox[i][take_6_bits(a,6*i)];
			do_p_n_xor(i,S_out);
		}

		for(i=0;i<4;i++){
			//randomDelay(painLevel); //Random delays in round out; uncomment to enable
			uint8_t tmp;
			tmp=l[i];
			l[i]=r[i];
			r[i]=tmp;
		}

	}

	fp(data);

}


void do_p_n_xor(uint8_t sbox,unsigned char S_out[]){
     switch(sbox){
       case 0:
            l[1]^=((S_out[0] & 0x08)<<4);
            l[2]^=((S_out[0] & 0x04) << 5)| (S_out[0] & 0x02);
            l[3]^=((S_out[0] & 0x01) <<1);
            break;
       case 1:
            l[0]^=((S_out[1] & 0x2) << 5);
            l[1]^=(S_out[1]&0x08);
            l[2]^=((S_out[1] & 0x1) << 6);
            l[3]^=((S_out[1] & 0x4) << 2);
            break;
       case 2:
            l[0]^=((S_out[2] & 0x01) << 2);
            l[1]^=((S_out[2] & 0x04) >> 2);
            l[2]^=((S_out[2] & 0x08) >> 3);
            l[3]^=((S_out[2] & 0x02)<<1);
            break;
       case 3:
            l[0]^=((S_out[3] & 0x1) << 7);
            l[1]^=((S_out[3] & 0x2) << 5);
            l[2]^=((S_out[3] & 0x4) << 2);
            l[3]^=(S_out[3] & 0x8)<<3;
            break;
       case 4:
            l[0]^= ((S_out[4]&0x01)<<5)|((S_out[4] & 0x08) >> 3);
            l[1]^=(S_out[4] & 0x04);
            l[3]^=((S_out[4] & 0x02)<<6);
            break;
       case 5:
            l[0]^=((S_out[5]&0x08)<<1);
            l[1]^=((S_out[5] & 0x2) << 4);
            l[2]^=((S_out[5] & 0x1) << 5);
            l[3]^=((S_out[5] & 0x4) << 1);
            break;
       case 6:
            l[0]^=((S_out[6] & 0x01) << 1);
            l[1]^=((S_out[6] & 0x04) << 2);
            l[2]^=((S_out[6] & 0x02) <<1);
            l[3]^=((S_out[6] & 0x08) >> 3);
            break;
       case 7:
            l[0]^=(S_out[7] & 0x8);
            l[1]^=(S_out[7] & 0x2);
            l[2]^=((S_out[7] & 0x1) << 3);
            l[3]^=((S_out[7] & 0x4) << 3);
            break;
       }
}

void do_p_n_xor_dummy(uint8_t sbox,unsigned char S_out[]){
     switch(sbox){
       case 0:
            ld[1]^=((S_out[0] & 0x08)<<4);
            ld[2]^=((S_out[0] & 0x04) << 5)| (S_out[0] & 0x02);
            ld[3]^=((S_out[0] & 0x01) <<1);
            break;
       case 1:
            ld[0]^=((S_out[1] & 0x2) << 5);
            ld[1]^=(S_out[1]&0x08);
            ld[2]^=((S_out[1] & 0x1) << 6);
            ld[3]^=((S_out[1] & 0x4) << 2);
            break;
       case 2:
            ld[0]^=((S_out[2] & 0x01) << 2);
            ld[1]^=((S_out[2] & 0x04) >> 2);
            ld[2]^=((S_out[2] & 0x08) >> 3);
            ld[3]^=((S_out[2] & 0x02)<<1);
            break;
       case 3:
            ld[0]^=((S_out[3] & 0x1) << 7);
            ld[1]^=((S_out[3] & 0x2) << 5);
            ld[2]^=((S_out[3] & 0x4) << 2);
            ld[3]^=(S_out[3] & 0x8)<<3;
            break;
       case 4:
            ld[0]^= ((S_out[4]&0x01)<<5)|((S_out[4] & 0x08) >> 3);
            ld[1]^=(S_out[4] & 0x04);
            ld[3]^=((S_out[4] & 0x02)<<6);
            break;
       case 5:
            ld[0]^=((S_out[5]&0x08)<<1);
            ld[1]^=((S_out[5] & 0x2) << 4);
            ld[2]^=((S_out[5] & 0x1) << 5);
            ld[3]^=((S_out[5] & 0x4) << 1);
            break;
       case 6:
            ld[0]^=((S_out[6] & 0x01) << 1);
            ld[1]^=((S_out[6] & 0x04) << 2);
            ld[2]^=((S_out[6] & 0x02) <<1);
            ld[3]^=((S_out[6] & 0x08) >> 3);
            break;
       case 7:
            ld[0]^=(S_out[7] & 0x8);
            ld[1]^=(S_out[7] & 0x2);
            ld[2]^=((S_out[7] & 0x1) << 3);
            ld[3]^=((S_out[7] & 0x4) << 3);
            break;
       }
}


void E(unsigned char in[],unsigned char out[]){
	out[0]=( (((in[3] & 0x1) << 7) | ((in[0] & 0xf8) >> 1) | ((in[0] & 0x18) >> 3)) );
	out[1]= ((((in[0] & 0x7) << 5) | ((in[1] & 0x80) >> 3) | ((in[0] & 0x1) << 3) | ((in[1] & 0xe0) >> 5)) );
	out[2]= ((((in[1] & 0x18) << 3) | ((in[1] & 0x1f) << 1) | ((in[2] & 0x80) >> 7)));
	out[3]= ((((in[1] & 0x1) << 7) | ((in[2] & 0xf8) >> 1) | ((in[2] & 0x18) >> 3))) ;
	out[4]= (((in[2] & 0x7) << 5) | ((in[3] & 0x80) >> 3) | ((in[2] & 0x1) << 3) | ((in[3] & 0xe0) >> 5)) ;
	out[5]= (((in[3] & 0x18) << 3) | ((in[3] & 0x1f) << 1) | ((in[0] & 0x80) >> 7));

}

 void ip( unsigned char in[] ){
	uint8_t i;

	l[0]=l[1]=l[2]=l[3]=r[0]=r[1]=r[2]=r[3]=0;

	for(i=0;i<8;i++){

		if( i< 2 ){
			l[0]=l[0]| ( ( in[7-i] & 0x40)<< (1-i) ) ;
			r[3] |= (in[i] & 0x02) >> (1-i);
		}else{
			l[0]=l[0]| ( ( in[7-i] & 0x40 ) >> (i-1) );
			r[3]|= (in[i] & 0x02) << (i-1);
		}

		if( i<4 ){
			l[1]|= ( ( in[7-i] & 0x10)<< (3-i) ) ;
			r[2]|= ( in[i] & 0x08 ) >> (3-i);
		} else {
			l[1]|= ( ( in[7-i] & 0x10 ) >> (i-3) );
			r[2]|= ( ( in[i] & 0x08 ) << (i-3) );
		}

		if( i<6 ){
			l[2]|= ( ( in[7-i] & 0x04)<< (5-i) ) ;
			r[1] |= ( ( in[i] & 0x20) >> (5-i) ) ;
		} else {
			l[2]|= ( ( in[7-i] & 0x04 ) >> (i-5) );
			r[1] |= ( ( in[i] & 0x20) << (i-5) ) ;
		}

		l[3] |= ( in[i] & 0x01 ) << i ;

		r[0] |= (in[7-i] & 0x80 ) >> i ;

	}

}

   void fp( unsigned char out[]){
	out[0] = (((l[0] & 0x1) << 7) | ((r[0] & 0x1) << 6) | ((l[1] & 0x1) << 5) | ((r[1] & 0x1) << 4) |
			 ((l[2] & 0x1) << 3) | ((r[2] & 0x1) << 2) | ((l[3] & 0x1) << 1) | (r[3] & 0x1));
    out[1] = (((l[0] & 0x2) << 6) | ((r[0] & 0x2) << 5) | ((l[1] & 0x2) << 4) | ((r[1] & 0x2) << 3) |
			 ((l[2] & 0x2) << 2) | ((r[2] & 0x2) << 1) | (l[3] & 0x2) | ((r[3] & 0x2) >> 1));
    out[2] = (((l[0] & 0x4) << 5) | ((r[0] & 0x4) << 4) | ((l[1] & 0x4) << 3) | ((r[1]& 0x4) << 2) |
			 ((l[2] & 0x4) << 1) | (r[2] & 0x4) | ((l[3] & 0x4) >> 1) | ((r[3] & 0x4) >> 2));
    out[3] = (((l[0] & 0x8) << 4) | ((r[0] & 0x8) << 3) | ((l[1] & 0x8) << 2) | ((r[1] & 0x8) << 1) |
			 (l[2] & 0x8) | ((r[2] & 0x8) >> 1) | ((l[3] & 0x8) >> 2) | ((r[3] & 0x8) >> 3));
    out[4] = (((l[0] & 0x10) << 3) | ((r[0] & 0x10) << 2) | ((l[1] & 0x10) << 1) | (r[1] & 0x10) |
			 ((l[2] & 0x10) >> 1) | ((r[2] & 0x10) >> 2) | ((l[3] & 0x10) >> 3) | ((r[3] & 0x10) >> 4));
    out[5] = (((l[0] & 0x20) << 2) | ((r[0] & 0x20) << 1) | (l[1] & 0x20) | ((r[1] & 0x20) >> 1) |
			 ((l[2] & 0x20) >> 2) | ((r[2] & 0x20) >> 3) | ((l[3] & 0x20) >> 4) | ((r[3] & 0x20) >> 5));
    out[6] = (((l[0] & 0x40) << 1) | (r[0] & 0x40) | ((l[1] & 0x40) >> 1) | ((r[1] & 0x40) >> 2) |
			 ((l[2] & 0x40) >> 3) | ((r[2] & 0x40) >> 4) | ((l[3] & 0x40) >> 5) | ((r[3] & 0x40) >> 6));
    out[7] = ((l[0] & 0x80) | ((r[0] & 0x80) >> 1) | ((l[1] & 0x80) >> 2) | ((r[1] & 0x80) >> 3) |
			 ((l[2] & 0x80) >> 4) | ((r[2] & 0x80) >> 5) | ((l[3] & 0x80) >> 6) | ((r[3] & 0x80) >> 7));

}

void pc1( unsigned char in[]){
    k[0] = ((in[7] & 0x80) | ((in[6] & 0x80) >> 1) | ((in[5] & 0x80) >> 2) | ((in[4] & 0x80) >> 3) |
		 ((in[3] & 0x80) >> 4) | ((in[2] & 0x80) >> 5) | ((in[1] & 0x80) >> 6) | ((in[0] & 0x80) >> 7));
    k[1] = (((in[7] & 0x40) << 1) | (in[6] & 0x40) | ((in[5] & 0x40) >> 1) | ((in[4] & 0x40) >> 2) |
		 ((in[3] & 0x40) >> 3) | ((in[2] & 0x40) >> 4) | ((in[1] & 0x40) >> 5) | ((in[0] & 0x40) >> 6));
    k[2] = (((in[7] & 0x20) << 2) | ((in[6] & 0x20) << 1) | (in[5] & 0x20) | ((in[4] & 0x20) >> 1) |
		 ((in[3] & 0x20) >> 2) | ((in[2] & 0x20) >> 3) | ((in[1] & 0x20) >> 4) | ((in[0] & 0x20) >> 5));
    k[3] = (((in[7] & 0x10) << 3) | (((in[6] & 0x10) | (in[7] & 0x2)) << 2) | (((in[5] & 0x10) |
		 (in[6] & 0x2)) << 1) | ((in[4] & 0x10) | (in[5] & 0x2)) | ((in[4] & 0x2) >> 1));
    k[4] = (((in[3] & 0x2) << 6) | ((in[2] & 0x2) << 5) | ((in[1] & 0x2) << 4) | ((in[0] & 0x2) << 3) |
		 ((in[7] & 0x4) << 1) | (in[6] & 0x4) | ((in[5] & 0x4) >> 1) | ((in[4] & 0x4) >> 2));
    k[5] = (((in[3] & 0x4) << 5) | ((in[2] & 0x4) << 4) | ((in[1] & 0x4) << 3) | ((in[0] & 0x4) << 2) |
		 (in[7] & 0x8) | ((in[6] & 0x8) >> 1) | ((in[5] & 0x8) >> 2) | ((in[4] & 0x8) >> 3));
    k[6] = (((in[3] & 0x8) << 4) | ((in[2] & 0x8) << 3) | ((in[1] & 0x8) << 2) | ((in[0] & 0x8) << 1) |
		 ((in[3] & 0x10) >> 1) | ((in[2] & 0x10) >> 2) | ((in[1] & 0x10) >> 3) | ((in[0] & 0x10) >> 4));
}


void pc2(unsigned char in[], unsigned char out[]){
	out[0] = (((in[1] & 0x4) << 5) | (((in[2] & 0x80) | (in[0] & 0x8)) >> 1) | (in[1] & 0x20) |
			((in[2] & 0x1) << 4) | (((in[0] & 0xa0) | (in[3] & 0x10)) >> 4));

    out[1] = (((in[1] & 0x2) << 6) | ((in[0] & 0x4) << 4) | ((in[2] & 0xa) << 2) | ((in[1] & 0x40) >> 2) |
			(((in[2] & 0x20) | (in[1] & 0x10)) >> 3) | ((in[0] & 0x10) >> 4));
    out[2] = (((in[3] & 0x40) << 1) | ((in[0] & 0x1) << 6) | ((in[1] & 0x1) << 5) | ((in[0] & 0x2) << 3) |
			(((in[3] & 0x20) | (in[2] & 0x10) | (in[1] & 0x8)) >> 2) | ((in[0] & 0x40) >> 6));
    out[3] = (((in[5] & 0x80) | (in[4] & 0x1)) | (((in[6] & 0x10) | (in[5] & 0x2)) << 2) | ((in[3] & 0x2) << 4) |
			(((in[4] & 0x8) | (in[6] & 0x2)) << 1) | ((in[3] & 0x4) >> 1));
    out[4] = (((in[6] & 0x20) << 2) | ((in[5] & 0x8) << 3) | ((in[4] & 0x80) >> 2) | ((in[5] & 0x1) << 4) |
			((in[5] & 0x10) >> 1) | ((in[6] & 0x80) >> 5) | ((in[4] & 0x2) | (in[6] & 0x1)));
    out[5] = (((in[4] & 0x40) << 1) | (((in[6] & 0x8) | (in[5] & 0x4)) << 3) | (((in[5] & 0x40) | (in[4] & 0x10) |
			(in[3] & 0x8)) >> 2) | ((in[6] & 0x40) >> 3) | (in[3] & 0x1));
}
  // do a key rotation to the left
void shiftLeft(unsigned char k[]){
   unsigned char c0,c,c1;

    c0 = ((k[0] >> 3) & 0x10);

    c = (((k[1] >> 4) >> 3) & 1);
    k[0] = ((k[0] << 1) | c);
    c = (((k[2] >> 4) >> 3) & 1);
    k[1] = ((k[1] << 1) | c);
    c = (((k[3] >> 4) >> 3) & 1);
    k[2] = ((k[2] << 1) | c);
    c = (((k[4] >> 4) >> 3) & 1);
    c1 = ((k[3] >> 3) & 1);
    k[3] = (((k[3] << 1) & 0xEF) | c | c0);
    c = (((k[5] >> 4) >> 3) & 1);
    k[4] = ((k[4] << 1) | c);
    c = (((k[6] >> 4) >> 3) & 1);
    k[5] = ((k[5] << 1) | c);
    k[6] = ((k[6] << 1) | c1);

}

void shiftRight( unsigned char k[]){
     unsigned char c0= (k[6] & 0x01)<<3;
     unsigned char c = (k[3] & 0x10)<<3;

     k[6] = (k[6] >> 1) | ( (k[5] & 0x01)<<7 );
     k[5] = ( k[5] >> 1 ) | ( (k[4] & 0x01)<<7 );
     k[4] = ( k[4] >> 1 ) | ( (k[3] & 0x01)<<7 );
     k[3] = ( k[3] >> 1 & 0xF7 ) | c0 | ((k[2] & 0x01)<<7 );
     k[2] = ( k[2] >> 1 ) | ( (k[1] & 0x01)<<7 );
     k[1] = ( k[1] >> 1 ) | ( (k[0] & 0x01)<<7 );
     k[0] = ( k[0] >> 1 ) | c;

}

void randomDelay(unsigned char painLevel){
	uint32_t randomNumber;
	RNG_Enable();
	do{
		//Get a random number
		while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
		randomNumber= RNG_GetRandomNumber();
	} while((randomNumber%painLevel)!=0);
	RNG_Disable();
}


//We add a dummy round if
uint8_t addDummy(uint8_t remainingDummyRounds){
	uint32_t randomNumber;
	uint8_t doDummyRound=0;
	uint8_t safetycheck=0;
	RNG_Enable();
	//Get a random number
	while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
	randomNumber= RNG_GetRandomNumber();
	RNG_Disable();
	//Dirty check for if number of remainingDummyRounds underflowed
	safetycheck--;
	if(remainingDummyRounds==safetycheck){
		remainingDummyRounds=0;
	}
	if(((randomNumber%2)!=0) && remainingDummyRounds>0){
		doDummyRound=1;
	}
	return doDummyRound;
}
