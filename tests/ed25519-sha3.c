// Generate SHA3 version of donna APIs

//#include "ed25519-keccak.h"
//#include "ed25519-hash-custom-keccak.h"

#define ED25519_SUFFIX _sha3

// TODO: provide a sha3 hasher to this instance

#include "ed25519.c"

#undef ED25519_SUFFIX
