
// Donna project base headers
#include <stdint.h>

#define DONNA_INLINE
#undef ALIGN
#define ALIGN(x) __attribute__((aligned(x)))

#include "ed25519.h"
#include "curve25519.h"
#include "curve25519-donna-32bit.h"

// Extensions, ported from trezor donna
// TODO(@ryankurte): not in upstream donna, where do these -come- from?!

void ed25519_publickey_ext(const ed25519_secret_key sk, const ed25519_secret_key skext, ed25519_public_key pk);

void ed25519_sign_ext(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key skext, const ed25519_public_key pk, ed25519_signature RS);

void curve25519_scalarmult(curved25519_key mypublic, const curved25519_key secret, const curved25519_key basepoint);



void ed25519_publickey_keccak(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_keccak(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign_keccak(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int ed25519_scalarmult_keccak(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);


void ed25519_publickey_sha3(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_sha3(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign_sha3(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int ed25519_scalarmult_sha3(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);


typedef struct ge25519_t {
	bignum25519 x, y, z, t;
} ge25519;

typedef struct ge25519_p1p1_t {
	bignum25519 x, y, z, t;
} ge25519_p1p1;

typedef struct ge25519_niels_t {
	bignum25519 ysubx, xaddy, t2d;
} ge25519_niels;

typedef struct ge25519_pniels_t {
	bignum25519 ysubx, xaddy, z, t2d;
} ge25519_pniels;

typedef uint32_t bignum256modm_element_t;

typedef bignum256modm_element_t bignum256modm[9];
