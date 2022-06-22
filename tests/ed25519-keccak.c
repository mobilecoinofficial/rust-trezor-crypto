// Generate Keccak version of donna APIs

//#include "ed25519-keccak.h"
//#include "ed25519-hash-custom-keccak.h"

#define ED25519_SUFFIX _keccak

#define ED25519_CUSTOMHASH

// TODO: provide a keccak hasher to this instance

#define ed25519_hash_context KECCAK_CTX
#define ed25519_hash_init(ctx)              keccak_init(ctx)
#define ed25519_hash_update(ctx, in, inlen) keccak_update((ctx), (in), (inlen))
#define ed25519_hash_final(ctx, hash)       keccak_finish((ctx), (hash))
#define ed25519_hash(hash, in, inlen)       keccak((in), (inlen), (hash), (512))


#include "keccak.h"

#include "ed25519.c"

#undef ED25519_SUFFIX
