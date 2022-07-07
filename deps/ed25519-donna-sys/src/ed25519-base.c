//! ed25519-donna extensions
//! TODO(@ryankurte): find the canonical source of these functions...
//! and/or refactor to remove the need for these in the trezor fw?

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#define ED25519_SUFFIX _donna

// Define base functions with _donna suffix
#include "ed25519.c"


static void memzero(void* target, size_t len) {
    for (int i=0; i<len; i++) {
        ((uint8_t*)target)[i] = 0;
    }
}

void ed25519_publickey_ext_donna(const ed25519_secret_key sk, const ed25519_secret_key skext, ed25519_public_key pk) {
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

void ed25519_sign2_donna(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, ed25519_signature sig) {
	ed25519_public_key pk = { 0 };
	ed25519_publickey_donna(sk, pk);
	ed25519_sign_donna(m, mlen, sk, pk, sig);
}

void ed25519_sign_ext_donna(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key skext, const ed25519_public_key pk, ed25519_signature RS) {
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
void curve25519_scalarmult_donna(curved25519_key mypublic, const curved25519_key secret, const curved25519_key basepoint) {
	curved25519_key e = {0};
	size_t i = 0;

	for (i = 0;i < 32;++i) e[i] = secret[i];
	e[0] &= 0xf8;
	e[31] &= 0x7f;
	e[31] |= 0x40;
	curve25519_scalarmult_donna(mypublic, e, basepoint);
	memzero(&e, sizeof(e));

#if 0
	for (i = 0;i < 32;++i) e[i] = secret[i];
	e[0] &= 0xf8;
	e[31] &= 0x7f;
	e[31] |= 0x40;
	curve25519_scalarmult_donna(mypublic, e, basepoint);
	memzero(&e, sizeof(e));
#endif
}


int ed25519_cosi_combine_publickeys_donna(ed25519_public_key res, const ed25519_public_key *pks, size_t n) {
	size_t i = 0;
	ge25519 P = {0};
	ge25519_pniels sump = {0};
	ge25519_p1p1 sump1 = {0};

	if (n == 1) {
		memcpy(res, pks, sizeof(ed25519_public_key));
		return 0;
	}
	if (!ge25519_unpack_negative_vartime(&P, pks[i++])) {
		return -1;
	}
	ge25519_full_to_pniels(&sump, &P);
	while (i < n - 1) {
		if (!ge25519_unpack_negative_vartime(&P, pks[i++])) {
			return -1;
		}
		ge25519_pnielsadd(&sump, &P, &sump);
	}
	if (!ge25519_unpack_negative_vartime(&P, pks[i++])) {
		return -1;
	}
	ge25519_pnielsadd_p1p1(&sump1, &P, &sump, 0);
	ge25519_p1p1_to_partial(&P, &sump1);
	curve25519_neg(P.x, P.x);
	ge25519_pack(res, &P);
	return 0;
}

void ed25519_cosi_combine_signatures(ed25519_signature res, const ed25519_public_key R, const ed25519_signature *sigs, size_t n) {
	bignum256modm s = {0}, t = {0};
	size_t i = 0;

	expand256_modm(s, sigs[i++], 32);
	while (i < n) {
		expand256_modm(t, sigs[i++], 32);
		add256_modm(s, s, t);
	}
	memcpy(res, R, 32);
	contract256_modm(res + 32, s);
}

void print_buff_u8(const char* prefix, const uint8_t* buff, size_t len) {
	printf("%s: [", prefix);
	for(int i=0; i<len; i++) {
		printf("%02x%s", buff[i], i == (len - 1) ? "" : ", ");
	}
	printf("]\r\n");
}

void print_buff_u32(const char* prefix, const uint32_t* buff, size_t len) {
	printf("%s: [", prefix);
	for(int i=0; i<len; i++) {
		printf("%08x%s", buff[i], i == (len - 1) ? "" : ", ");
	}
	printf("]\r\n");
}

void ed25519_cosi_sign (const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_secret_key nonce, const ed25519_public_key R, const ed25519_public_key pk, ed25519_signature sig) {
	bignum256modm r = {0}, S = {0}, a = {0};
	hash_512bits extsk = {0}, extnonce = {0}, hram = {0};

	ed25519_extsk(extsk, sk);
	ed25519_extsk(extnonce, nonce);

	//print_buff_u8("DONNA EXTSK", extsk, 64);
	//print_buff_u8("DONNA EXTNONCE", extnonce, 64);

	/* r = nonce */
	expand256_modm(r, extnonce, 32);
	memzero(&extnonce, sizeof(extnonce));

	print_buff_u32("DONNA R", r, 9);

	/* S = H(R,A,m).. */
	ed25519_hram(hram, R, pk, m, mlen);
	expand256_modm(S, hram, 64);

	print_buff_u32("DONNA S", S, 9);

	//print_buff_u8("DONNA H", hram, 64);

	/* S = H(R,A,m)a */
	expand256_modm(a, extsk, 32);
	memzero(&extsk, sizeof(extsk));

	//print_buff_u32("DONNA SK", a, 9);

	mul256_modm(S, S, a);
	memzero(&a, sizeof(a));

	/* S = (r + H(R,A,m)a) */
	add256_modm(S, S, r);
	memzero(&r, sizeof(r));

	/* S = (r + H(R,A,m)a) mod L */
	contract256_modm(sig, S);
}


#undef ED25519_SUFFIX
