/**
  Copyright (C) 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stdlib.h>

#define SM4_ROUNDS 32

#define SM4_ENCRYPT 1
#define SM4_DECRYPT 0
   
#define XCHG(x, y) (t) = (x); (x) = (y); (y) = (t);

#define U8V(v) ((uint8_t)(v) & 0xFF)
#define U16V(v) ((uint16_t)(v) & 0xFFFF)
#define U32V(v) ((uint32_t)(v) & 0xFFFFFFFF)
#define U64V(v) ((uint64_t)(v) & 0xFFFFFFFFFFFFFFFF)

#define ROTL8(v, n) \
  (U8V((v) << (n)) | ((v) >> (8 - (n))))

#define ROTL16(v, n) \
  (U16V((v) << (n)) | ((v) >> (16 - (n))))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTL64(v, n) \
  (U64V((v) << (n)) | ((v) >> (64 - (n))))

#define ROTR8(v, n) ROTL8(v, 8 - (n))
#define ROTR16(v, n) ROTL16(v, 16 - (n))
#define ROTR32(v, n) ROTL32(v, 32 - (n))
#define ROTR64(v, n) ROTL64(v, 64 - (n))

#define SWAP16(v) \
  ROTL16(v, 8)

#define SWAP32(v) \
  ((ROTL32(v,  8) & 0x00FF00FF) | \
(ROTL32(v, 24) & 0xFF00FF00))

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  32

typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

// 32-bit type
typedef union {
    uint8_t  b[4];
    uint32_t w;
} w32_t;

// 128-bit type
typedef union {
    uint8_t  b[16];
    uint32_t w[4];
} w128_t;
   
typedef struct sm4_ctx_t {
    uint32_t rk[SM4_ROUNDS];
} sm4_ctx;

#ifdef __cplusplus
extern "C" {
#endif

void sm4_setkey(sm4_ctx*,const void*, int);


void sm4_encrypt(sm4_ctx*,void*);

//OpenSSL functions
int SM4_set_key(const uint8_t *key, SM4_KEY *ks);
void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);


#ifdef __cplusplus  
}
#endif

#endif
