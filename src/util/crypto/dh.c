/* inc */
#include <assert.h>
#include <stdio.h>
#include "lib.h"
#include "api.h"

#include "ffa.h"
#include "eca.h"
#include "enc.h"
#include "smu.h"

/* Return the generator. */
int crypto_dh_generator(unsigned char *pk) {
	__m128i px0, px1, pl0, pl1;
	px0 = _mm_set_epi64x(0x9D1932CB5FA5B9BF, 0x5BE5F4EB93D8712A);
	px1 = _mm_set_epi64x(0x25F2F29FCBDEC78E, 0x47E70D2DCA8C7210);
	pl0 = _mm_set_epi64x(0x25BE90C01E0E9B06, 0x97FBBBBFEB3A8AB4);
	pl1 = _mm_set_epi64x(0x0B3834B048C217C1, 0x1A1764D658204447);
	_mm_store_si128((__m128i *) & pk[0], px0);
	_mm_store_si128((__m128i *) & pk[16], px1);
	_mm_store_si128((__m128i *) & pk[32], pl0);
	_mm_store_si128((__m128i *) & pk[48], pl1);
	return 0;
}

/* Key pair generation. */
int crypto_dh_gls254prot_opt_keypair(unsigned char *pk, unsigned char *sk) {
	__m128i px0, px1, pl0, pl1;

	/* Mask top bits to reduce scalar modulo order. */
	sk[31] &= 0x1F;

	/* generator */
	px0 = _mm_set_epi64x(0x9D1932CB5FA5B9BF, 0x5BE5F4EB93D8712A);
	px1 = _mm_set_epi64x(0x25F2F29FCBDEC78E, 0x47E70D2DCA8C7210);
	pl0 = _mm_set_epi64x(0x25BE90C01E0E9B06, 0x97FBBBBFEB3A8AB4);
	pl1 = _mm_set_epi64x(0x0B3834B048C217C1, 0x1A1764D658204447);

	/* Scalar multiplication. */
	smu_5nf_dna_ltr(&px0, &px1, &pl0, &pl1, px0, px1, pl0, pl1,
			(uint64_t *) sk);

	/* Write the result. */
	ec_enc(pk, px0, px1, pl0, pl1);
	return 0;
}

/* Shared secret computation. */
int crypto_dh_gls254prot_opt(unsigned char *out, unsigned char *pk,
		unsigned char *sk) {
	__m128i px0, px1, pl0, pl1;

	sk[31] &= 0x1F;

	ec_dec(&px0, &px1, &pl0, &pl1, pk);

	smu_5nf_dna_ltr(&px0, &px1, &pl0, &pl1, px0, px1, pl0, pl1,
			(uint64_t *) sk);
	ec_enc(out, px0, px1, pl0, pl1);

	return 0;
}

/* Shared secret computation. */
int crypto_dh_gls254prot_var(unsigned char *out, unsigned char *pk,
		unsigned char *sk) {
	__m128i px0, px1, pl0, pl1;

	sk[31] &= 0x1F;

	ec_dec(&px0, &px1, &pl0, &pl1, pk);

	smu_5nf_dna_var(&px0, &px1, &pl0, &pl1, px0, px1, pl0, pl1,
			(uint64_t *) sk);
	ec_enc(out, px0, px1, pl0, pl1);

	return 0;
}

int crypto_dh_gls254prot_hash(unsigned char *out, unsigned char *sk) {
	__m128i x0, x1, l0, l1, z0, z1, u0, u1;
	__m128i _x0, _x1, _l0, _l1;
	sk[31] &= 0x7F;
	u0 = _mm_loadu_si128((__m128i *) & sk[0]);
	u1 = _mm_loadu_si128((__m128i *) & sk[16]);
	ec_sw(&x0, &x1, &l0, &l1, u0, u1);
	ec_sw(&_x0, &_x1, &_l0, &_l1, u1, u0);
	eca_add_mma(&x0, &x1, &l0, &l1, &z0, &z1, x0, x1, l0, l1, _x0, _x1, _l0, _l1);
	eca_dbl_ful(&x0, &x1, &l0, &l1, &z0, &z1, x0, x1, l0, l1, z0, z1);

        low_inv(&z0, &z1, z0, z1);
        low_mul(&x0, &x1, x0, x1, z0, z1);
        low_mul(&l0, &l1, l0, l1, z0, z1);
        low_red_127_063_000(x0, x1, z0);
        low_red_127_063_000(l0, l1, z0);
        ec_enc(out, x0, x1, l0, l1);
	return 0;
}

int crypto_dh_gls254prot_two(unsigned char *r, unsigned char *p,
		unsigned char *k, unsigned char *q, unsigned char *l) {
	__m128i px0, px1, pl0, pl1;
	__m128i qx0, qx1, ql0, ql1;
	__m128i rx0, rx1, rl0, rl1;

	k[31] &= 0x1F;
	l[31] &= 0x1F;

	ec_dec(&px0, &px1, &pl0, &pl1, p);
	ec_dec(&qx0, &qx1, &ql0, &ql1, q);

	smu_two_5nf_dna_ltr(&rx0, &rx1, &rl0, &rl1, px0, px1, pl0, pl1,
			(uint64_t *) k, qx0, qx1, ql0, ql1, (uint64_t *) l);

	ec_enc(r, rx0, rx1, rl0, rl1);
	return 0;
}

#ifdef MAIN

#include <assert.h>
#include <string.h>
#include "bench.h"
#include "bench.c"

static void ec_test() {
	uint8_t p[64], q[64];
	unsigned long long int u[4];
	__m128i x0, x1, l0, l1;
	for (int i = 0; i < 4; i++) {
		__builtin_ia32_rdrand64_step(&u[i]);
	}
	l0 = _mm_loadu_si128((__m128i *) u);
	l1 = _mm_loadu_si128((__m128i *) (u + 2));
	ec_sw(&x0, &x1, &l0, &l1, l0, l1);
	assert(ec_ok(x0, x1, l0, l1) == 1);
	/* Multiply by cofactor. */
	eca_dbl_aff(&x0, &x1, &l0, &l1, x0, x1, l0, l1);
	ec_enc(p, x0, x1, l0, l1);
	assert(ec_dec(&x0, &x1, &l0, &l1, p));

	crypto_dh_gls254prot_opt_keypair(p, (unsigned char*)u);
	assert(ec_dec(&x0, &x1, &l0, &l1, p));
	crypto_dh_gls254prot_opt(p, p, (unsigned char *)u);
	assert(ec_dec(&x0, &x1, &l0, &l1, p));
	ec_enc(q, x0, x1, l0, l1);
	assert(memcmp(p, q, 32) == 0);
	crypto_dh_gls254prot_opt(p, p, (unsigned char *)u);
	crypto_dh_gls254prot_var(q, q, (unsigned char *)u);
	assert(memcmp(p, q, 32) == 0);
	memset(p, 0, sizeof(p));
	assert(ec_dec(&x0, &x1, &l0, &l1, p) == 0);
	assert(ec_ok(x0, x1, l0, l1) == 0);
}

static void dh_test() {
	uint8_t pa[64], pb[64], k1[32], k2[32];
	unsigned long long int sa[4], sb[4];

	for (int i = 0; i < 4; i++) {
		__builtin_ia32_rdrand64_step(&sa[i]);
		__builtin_ia32_rdrand64_step(&sb[i]);
	}

	crypto_dh_gls254prot_opt_keypair(pa, (unsigned char *)sa);
	crypto_dh_gls254prot_opt_keypair(pb, (unsigned char *)sb);
	crypto_dh_gls254prot_opt(k1, pa, (unsigned char *)sb);
	crypto_dh_gls254prot_opt(k2, pb, (unsigned char *)sa);
	assert(memcmp(k1, k2, 32) == 0);
}

static void two_test() {
	uint8_t p[64], q[64], r[64], t[64];
	unsigned long long int k[4], l[4];
	__m128i px0, px1, pl0, pl1;
	__m128i qx0, qx1, ql0, ql1;
	__m128i rx0, rx1, rl0, rl1, rz0, rz1;

	for (int i = 0; i < 4; i++) {
		__builtin_ia32_rdrand64_step(&k[i]);
		__builtin_ia32_rdrand64_step(&l[i]);
	}
	/* Generate random points. */
	crypto_dh_gls254prot_opt_keypair(p, (unsigned char *)k);
	crypto_dh_gls254prot_opt_keypair(q, (unsigned char *)l);

	/* Compute T = lP + kQ. */
	crypto_dh_gls254prot_two(t, p, (unsigned char *)k, q, (unsigned char *)l);
	ec_dec(&px0, &px1, &pl0, &pl1, t);
	assert(ec_ok(px0, px1, pl0, pl1) == 1);

	crypto_dh_gls254prot_opt(p, p, (unsigned char *)k);
	crypto_dh_gls254prot_opt(q, q, (unsigned char *)l);
	ec_dec(&px0, &px1, &pl0, &pl1, p);
	ec_dec(&qx0, &qx1, &ql0, &ql1, q);
	assert(ec_ok(px0, px1, pl0, pl1) == 1);
	assert(ec_ok(qx0, qx1, ql0, ql1) == 1);

	eca_add_mma(&rx0, &rx1, &rl0, &rl1, &rz0, &rz1, px0, px1, pl0, pl1, qx0,
			qx1, ql0, ql1);
	low_inv(&rz0, &rz1, rz0, rz1);
	low_mul(&rx0, &rx1, rx0, rx1, rz0, rz1);
	low_mul(&rl0, &rl1, rl0, rl1, rz0, rz1);
	low_red_127_063_000(rx0, rx1, rz0);
	low_red_127_063_000(rl0, rl1, rz0);
	ec_enc(r, rx0, rx1, rl0, rl1);
	assert(memcmp(r, t, 32) == 0);
}

void bench() {
	uint8_t p[64], q[64];
	unsigned long long int u[4], l[4];
	__m128i x0, x1, l0, l1;

	BENCH_BEGIN("ec_sw") {
		for (int i = 0; i < 4; i++) {
			__builtin_ia32_rdrand64_step(&u[i]);
		}
		l0 = _mm_loadu_si128((__m128i *) u);
		l1 = _mm_loadu_si128((__m128i *) (u + 2));
		BENCH_ADD(ec_sw(&x0, &x1, &l0, &l1, l0, l1));
	} BENCH_END;

	BENCH_BEGIN("crypto_dh_gls254prot_opt_keypair") {
		for (int i = 0; i < 4; i++) {
			__builtin_ia32_rdrand64_step(&u[i]);
		}
		BENCH_ADD(crypto_dh_gls254prot_opt_keypair(p, (unsigned char *)u));
	} BENCH_END;

	BENCH_BEGIN("crypto_dh_gls254prot_opt") {
		for (int i = 0; i < 4; i++) {
			__builtin_ia32_rdrand64_step(&u[i]);
		}
		BENCH_ADD(crypto_dh_gls254prot_opt(p, p, (unsigned char *)u));
	} BENCH_END;

	BENCH_BEGIN("crypto_dh_gls254prot_var") {
		for (int i = 0; i < 4; i++) {
			__builtin_ia32_rdrand64_step(&u[i]);
		}
		BENCH_ADD(crypto_dh_gls254prot_var(q, p, (unsigned char *)u));
	} BENCH_END;

	BENCH_BEGIN("crypto_dh_gls254prot_two") {
		for (int i = 0; i < 4; i++) {
			__builtin_ia32_rdrand64_step(&u[i]);
			__builtin_ia32_rdrand64_step(&l[i]);
		}
		BENCH_ADD(crypto_dh_gls254prot_two(p, p, (unsigned char *)u, q, (unsigned char *)l));
	} BENCH_END;
}

int main(int argc, char const *argv[]) {
	ec_ell_pre();
	for (int i = 0; i < 10000; i++) {
		ec_test();
		dh_test();
		two_test();
	}

	printf("PASS!\n");

	bench();
	return 0;
}

#endif
