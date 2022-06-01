// Generate Keccak version of donna APIs

//#include "ed25519-keccak.h"
//#include "ed25519-hash-custom-keccak.h"

#define ED25519_SUFFIX _keccak

// TODO: provide a keccak hasher to this instance

#define ed25519_hash_context SHA3_CTX
#define ed25519_hash_init(ctx) keccak_512_Init(ctx)
#define ed25519_hash_update(ctx, in, inlen) keccak_Update((ctx), (in), (inlen))
#define ed25519_hash_final(ctx, hash) keccak_Final((ctx), (hash))
#define ed25519_hash(hash, in, inlen) keccak_512((in), (inlen), (hash))

#include "ed25519.c"

#undef ED25519_SUFFIX
