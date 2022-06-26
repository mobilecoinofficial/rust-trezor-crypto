// Generate Keccak version of donna APIs

//#include "ed25519-keccak.h"
//#include "ed25519-hash-custom-keccak.h"

#define ED25519_SUFFIX _keccak

#include <stdlib.h>
#include <stdint.h>

// Provide a keccak hasher to this instance

#define ed25519_hash_context keccak512_ctx_t
#define ed25519_hash_init(ctx)              keccak512_init(ctx)
#define ed25519_hash_update(ctx, in, inlen) keccak512_update((ctx), (in), (inlen))
#define ed25519_hash_final(ctx, hash)       keccak512_finalize((ctx), (hash))
#define ed25519_hash(hash, in, inlen)       keccak512_hash((in), (inlen), (hash))

// Size must match generated rust type...
// TODO: work out a better way?
typedef uint8_t keccak512_ctx_t[280];

void keccak512_init(keccak512_ctx_t* ctx);
void keccak512_update(keccak512_ctx_t* ctx, const unsigned char *in, size_t inlen);
void keccak512_finalize(keccak512_ctx_t* ctx, uint8_t *md);

void keccak512_hash(const unsigned char *in, size_t inlen, char* hash);


#include "ed25519.c"

#undef ED25519_SUFFIX