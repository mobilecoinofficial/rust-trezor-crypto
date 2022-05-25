
// ed25519-donna base header
#include "ed25519.h"

// Test data via `ed25519-donna/test.c` and `ed25519-donna/regression.h`
typedef struct  {
	unsigned char sk[32], pk[32], sig[64];
	const char *m;
} test_data_t;

test_data_t test_dataset[] = {
#include "regression.h"
};

// Extensions, ported from trezor donna
// TODO(@ryankurte): not in upstream donna, where do these -come- from?!

void ed25519_publickey_ext(const ed25519_secret_key sk, const ed25519_secret_key skext, ed25519_public_key pk);

void ed25519_sign_ext(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key skext, const ed25519_public_key pk, ed25519_signature RS);

void curve25519_scalarmult(curved25519_key mypublic, const curved25519_key secret, const curved25519_key basepoint);

#if 0

void ed25519_publickey_keccak(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_keccak(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);
void ed25519_sign_keccak(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int ed25519_scalarmult_keccak(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);

#endif
