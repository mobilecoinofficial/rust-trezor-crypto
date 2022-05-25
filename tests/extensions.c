//! ed25519-donna extensions
//! TODO(@ryankurte): find the canonical source of these functions...
//! and/or refactor to remove the need for these in the trezor fw?

#include <stdint.h>

#include "ed25519.h"
#include "ed25519-donna.h"
#include "ed25519-hash.h"

static void memzero(void* target, size_t len) {
    for (int i=0; i<len; i++) {
        ((uint8_t*)target)[i] = 0;
    }
}

static void
ed25519_hram(hash_512bits hram, const ed25519_signature RS, const ed25519_public_key pk, const unsigned char *m, size_t mlen) {
	ed25519_hash_context ctx;
	ed25519_hash_init(&ctx);
	ed25519_hash_update(&ctx, RS, 32);
	ed25519_hash_update(&ctx, pk, 32);
	ed25519_hash_update(&ctx, m, mlen);
	ed25519_hash_final(&ctx, hram);
}

void ed25519_publickey_ext (const ed25519_secret_key sk, const ed25519_secret_key skext, ed25519_public_key pk) {
	bignum256modm a = {0};
	ge25519 ALIGN(16) A;
	hash_512bits extsk = {0};

	/* we don't stretch the key through hashing first since its already 64 bytes */

	memcpy(extsk, sk, 32);
	memcpy(extsk+32, skext, 32);
	expand256_modm(a, extsk, 32);
	memzero(&extsk, sizeof(extsk));
	ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
	memzero(&a, sizeof(a));
	ge25519_pack(pk, &A);
}

void ed25519_sign_ext (const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key skext, const ed25519_public_key pk, ed25519_signature RS) {
	ed25519_hash_context ctx;
	bignum256modm r = {0}, S = {0}, a = {0};
	ge25519 ALIGN(16) R = {0};
	hash_512bits extsk = {0}, hashr = {0}, hram = {0};

	/* we don't stretch the key through hashing first since its already 64 bytes */

	memcpy(extsk, sk, 32);
	memcpy(extsk+32, skext, 32);


	/* r = H(aExt[32..64], m) */
	ed25519_hash_init(&ctx);
	ed25519_hash_update(&ctx, extsk + 32, 32);
	ed25519_hash_update(&ctx, m, mlen);
	ed25519_hash_final(&ctx, hashr);
	expand256_modm(r, hashr, 64);
	memzero(&hashr, sizeof(hashr));

	/* R = rB */
	ge25519_scalarmult_base_niels(&R, ge25519_niels_base_multiples, r);
	ge25519_pack(RS, &R);

	/* S = H(R,A,m).. */
	ed25519_hram(hram, RS, pk, m, mlen);
	expand256_modm(S, hram, 64);

	/* S = H(R,A,m)a */
	expand256_modm(a, extsk, 32);
	memzero(&extsk, sizeof(extsk));
	mul256_modm(S, S, a);
	memzero(&a, sizeof(a));

	/* S = (r + H(R,A,m)a) */
	add256_modm(S, S, r);
	memzero(&r, sizeof(r));

	/* S = (r + H(R,A,m)a) mod L */
	contract256_modm(RS + 32, S);
}


// TODO(@ryankurte): work out how to usefully test this
void curve25519_scalarmult(curved25519_key mypublic, const curved25519_key secret, const curved25519_key basepoint) {
	curved25519_key e = {0};
	size_t i = 0;

#if 0
	for (i = 0;i < 32;++i) e[i] = secret[i];
	e[0] &= 0xf8;
	e[31] &= 0x7f;
	e[31] |= 0x40;
	curve25519_scalarmult_donna(mypublic, e, basepoint);
	memzero(&e, sizeof(e));
#endif
}
