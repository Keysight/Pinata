#ifndef VECTOR_H
#define VECTOR_H

#include <stdint.h>
#include "params.h"

#define asm_reduce32 MLDSA_NAMESPACE(asm_reduce32)
void asm_reduce32(int32_t a[N]);
#define asm_caddq MLDSA_NAMESPACE(asm_caddq)
void asm_caddq(int32_t a[N]);
#define asm_freeze MLDSA_NAMESPACE(asm_freeze)
void asm_freeze(int32_t a[N]);
#define asm_rej_uniform MLDSA_NAMESPACE(asm_rej_uniform)
unsigned int asm_rej_uniform(int32_t *a,
                         unsigned int len,
                         const unsigned char *buf,
                         unsigned int buflen);
#endif
