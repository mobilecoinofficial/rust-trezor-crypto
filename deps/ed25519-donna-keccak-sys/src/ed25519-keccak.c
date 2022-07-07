// Generate Keccak version of donna APIs

//#include "ed25519-keccak.h"
//#include "ed25519-hash-custom-keccak.h"

#define ED25519_SUFFIX _donna_keccak

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

// Replacement fn to avoid errors from passing `pk` and `sk`
void ed25519_sign2_donna_keccak(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, ed25519_signature sig) {
	ed25519_public_key pk = { 0 };
	ed25519_publickey_donna_keccak(sk, pk);
	ed25519_sign_donna_keccak(m, mlen, sk, pk, sig);
}

static void ge25519_cmove_stride4b(long * r, long * p, long * pos, long * n, int stride) {
  long x0=p[0], x1=p[1], x2=p[2], x3=p[3], y0 = 0, y1 = 0, y2 = 0, y3 = 0;
  for(p+=stride; p<n; p+=stride) {
    volatile int flag=(p==pos);
    y0 = p[0];
    y1 = p[1];
    y2 = p[2];
    y3 = p[3];
    x0 = flag ? y0 : x0;
    x1 = flag ? y1 : x1;
    x2 = flag ? y2 : x2;
    x3 = flag ? y3 : x3;
  }
  r[0] = x0;
  r[1] = x1;
  r[2] = x2;
  r[3] = x3;
}

static void ge25519_move_conditional_pniels_array(ge25519_pniels * r, const ge25519_pniels * p, int pos, int n) {
  size_t i = 0;
  for(i=0; i<sizeof(ge25519_pniels)/sizeof(long); i+=4) {
    ge25519_cmove_stride4b(((long*)r)+i,
			   ((long*)p)+i,
			   ((long*)(p+pos))+i,
			   ((long*)(p+n))+i,
			   sizeof(ge25519_pniels)/sizeof(long));
  }
}

/* computes [s1]p1, constant time */
void ge25519_scalarmult_donna_keccak(ge25519 *r, const ge25519 *p1, const bignum256modm s1) {
	signed char slide1[64] = {0};
	ge25519_pniels pre1[9] = {0};
	ge25519_pniels pre = {0};
	ge25519 d1 = {0};
	ge25519_p1p1 t = {0};
	int32_t i = 0;

	contract256_window4_modm(slide1, s1);

	ge25519_full_to_pniels(pre1+1, p1);
	ge25519_double(&d1, p1);

	/* set neutral */
	memset(r, 0, sizeof(ge25519));
	r->y[0] = 1;
	r->z[0] = 1;
    
	ge25519_full_to_pniels(pre1, r);

	ge25519_full_to_pniels(pre1+2, &d1);
	for (i = 1; i < 7; i++) {
		ge25519_pnielsadd(&pre1[i+2], &d1, &pre1[i]);
	}

	for (i = 63; i >= 0; i--) {
		int k=abs(slide1[i]);
		ge25519_double_partial(r, r);
		ge25519_double_partial(r, r);
		ge25519_double_partial(r, r);
		ge25519_double_p1p1(&t, r);
		ge25519_move_conditional_pniels_array(&pre, pre1, k, 9);
		ge25519_p1p1_to_full(r, &t);
		ge25519_pnielsadd_p1p1(&t, r, &pre, (unsigned char)slide1[i] >> 7);
		ge25519_p1p1_to_partial(r, &t);
	}
	curve25519_mul(r->t, t.x, t.y);
    memset(slide1, 0, sizeof(slide1));
}

int ed25519_scalarmult_donna_keccak(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk) {
	bignum256modm a = { 0 };
    bignum256modm zero = { 0 };
	ge25519 ALIGN(16) A, P;
	hash_512bits extsk = {0};

	ed25519_extsk(extsk, sk);
	expand256_modm(a, extsk, 32);
	memset(&extsk, 0, sizeof(extsk));

	if (!ge25519_unpack_negative_vartime(&P, pk)) {
		return -1;
	}

	ge25519_scalarmult_donna_keccak(&A, &P, a);

	memset(&a, 0, sizeof(a));
	curve25519_neg(A.x, A.x);
	ge25519_pack(res, &A);
	return 0;
}

#undef ED25519_SUFFIX
