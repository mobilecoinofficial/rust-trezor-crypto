
// Donna project base headers
#include <stdint.h>

#include "ed25519-donna.h"
#include "ed25519.h"

#include "curve25519.h"
//#include "curve25519-donna-32bit.h"


// Extensions, ported from trezor donna
// TODO(@ryankurte): not in upstream donna, where do these -come- from?!

void ed25519_publickey_ext(const ed25519_secret_key sk, const ed25519_secret_key skext, ed25519_public_key pk);

void ed25519_sign_ext(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key skext, const ed25519_public_key pk, ed25519_signature RS);

void curve25519_scalarmult(curved25519_key mypublic, const curved25519_key secret, const curved25519_key basepoint);



// Keccak parallel impl
void ed25519_publickey_keccak(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_keccak(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign_keccak(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int curved25519_scalarmult_basepoint_keccak(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);


// Sha3 parallel impl
void ed25519_publickey_sha3(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_sha3(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign_sha3(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int curved25519_scalarmult_basepoint_sha3(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);

