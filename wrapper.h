
#include <stdint.h>
#include <stdlib.h>

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef unsigned char curved25519_key[32];

// Default donna functions
void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int ed25519_sign_open_batch(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);

void curved25519_scalarmult_basepoint(ed25519_public_key res, const ed25519_secret_key sk);


// Extensions, ported from trezor donna

void ed25519_publickey_ext(const ed25519_secret_key sk, const ed25519_secret_key skext, ed25519_public_key pk);

void ed25519_sign_ext(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key skext, const ed25519_public_key pk, ed25519_signature RS);

/// Scalar multiplication with the provided basepoint
void curve25519_scalarmult(curved25519_key mypublic, const curved25519_key secret, const curved25519_key basepoint);



// Keccak donna impl
void ed25519_publickey_keccak(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_keccak(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign_keccak(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

void curved25519_scalarmult_basepoint_keccak(ed25519_public_key res, const ed25519_secret_key sk);


// Sha3 donna impl
void ed25519_publickey_sha3(const ed25519_secret_key sk, ed25519_public_key pk);

int ed25519_sign_open_sha3(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);

void ed25519_sign_sha3(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

void curved25519_scalarmult_basepoint_sha3(ed25519_public_key res, const ed25519_secret_key sk);


// Keccak512 hasher impl

// keccak512_ctx_t context object size must match rust object
// which _should_ be consistent with `repr(C)` but, is not ideal...
// TODO: work out whether there is a better way to propagate this..?
const size_t KECCAK512_CTX_SIZE = 280;

typedef uint8_t keccak512_ctx_t[KECCAK512_CTX_SIZE];

void keccak512_init(keccak512_ctx_t* ctx);
void keccak512_update(keccak512_ctx_t* ctx, const unsigned char *in, size_t inlen);
void keccak512_finalize(keccak512_ctx_t* ctx, uint8_t *md);

void keccak512_hash(const unsigned char *in, size_t inlen, char* hash);


// Sha3 hasher impl

// sha3_512_ctx_t context object size must match rust object
// which _should_ be consistent with `repr(C)` but, is not ideal...
// TODO: work out whether there is a better way to propagate this..?
const size_t SHA3_512_CTX_SIZE = 280;

typedef uint8_t sha3_512_ctx_t[SHA3_512_CTX_SIZE];

void sha3_512_init(sha3_512_ctx_t* ctx);
void sha3_512_update(sha3_512_ctx_t* ctx, const unsigned char *in, size_t inlen);
void sha3_512_finalize(sha3_512_ctx_t* ctx, uint8_t *md);

void sha3_512_hash(const unsigned char *in, size_t inlen, char* hash);
