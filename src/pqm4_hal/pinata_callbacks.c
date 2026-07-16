#include "pinata_callbacks.h"
#include <stddef.h>

PINATA_PATCH_mldsa_sign_start_callback_t PINATA_PATCH_mldsa_start_callback = NULL;
PINATA_PATCH_mldsa_sign_finish_callback_t PINATA_PATCH_mldsa_finish_callback = NULL;

PINATA_PATCH_mldsa_sign_start_callback_t PINATA_PATCH_mldsa_set_sign_start_callback(PINATA_PATCH_mldsa_sign_start_callback_t f) {
	PINATA_PATCH_mldsa_sign_start_callback_t old = PINATA_PATCH_mldsa_start_callback;
	PINATA_PATCH_mldsa_start_callback = f;
	return old;
}

PINATA_PATCH_mldsa_sign_finish_callback_t PINATA_PATCH_mldsa_set_sign_finish_callback(PINATA_PATCH_mldsa_sign_finish_callback_t f) {
	PINATA_PATCH_mldsa_sign_finish_callback_t old = PINATA_PATCH_mldsa_finish_callback;
	PINATA_PATCH_mldsa_finish_callback = f;
	return old;
}
