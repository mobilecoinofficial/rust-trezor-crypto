// Generate SHA3 version of donna APIs

//#include "ed25519-sha3_.h"
//#include "ed25519-hash-custom-sha3_.h"

#define ED25519_SUFFIX _donna_sha3

#include <stdlib.h>
#include <stdint.h>

// Provide a sha3 hasher to this instance

#define ed25519_hash_context sha3_512_ctx_t
#define ed25519_hash_init(ctx)              sha3_512_init(ctx)
#define ed25519_hash_update(ctx, in, inlen) sha3_512_update((ctx), (in), (inlen))
#define ed25519_hash_final(ctx, hash)       sha3_512_finalize((ctx), (hash))
#define ed25519_hash(hash, in, inlen)       sha3_512_hash((in), (inlen), (hash))

// Size must match generated rust type...
// TODO: work out a better way?
typedef uint8_t sha3_512_ctx_t[280];

void sha3_512_init(sha3_512_ctx_t* ctx);
void sha3_512_update(sha3_512_ctx_t* ctx, const unsigned char *in, size_t inlen);
void sha3_512_finalize(sha3_512_ctx_t* ctx, uint8_t *md);

void sha3_512_hash(const unsigned char *in, size_t inlen, char* hash);


#include "ed25519.c"

// Replacement fn to avoid errors from passing `pk` and `sk`
void ed25519_sign2_donna_sha3(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, ed25519_signature sig) {
	ed25519_public_key pk = { 0 };
	ed25519_publickey_donna_sha3(sk, pk);
	ed25519_sign_donna_sha3(m, mlen, sk, pk, sig);
}

#undef ED25519_SUFFIX
