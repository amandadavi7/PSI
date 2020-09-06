#include <string.h>

#define T1 	0
#define T2 	1
#define T3 	2
#define Tneg1 	3
#define Tneg2	4
#define Tneg3	5
#define Tc2	6
#define Tc3	7
#define Tci2	8
#define Tci3	9

static __m128i t[10][2];

void ec_ell_pre() {
	__m128i _t[2], ONE = _mm_set_epi64x(0x0, 0x1);
	unsigned long long seed = 0x8000001;
	int i;

	_t[0] = _mm_set_epi64x(0x0, seed);
	_t[1] = _mm_setzero_si128();

	/* t1 = t/(1 + t + t^2). */
	low_sqr(&t[T1][0], &t[T1][1], _t[0], _t[1]);
	t[T1][0] = _mm_xor_si128(t[T1][0], _t[0]);
	t[T1][1] = _mm_xor_si128(t[T1][1], _t[1]);
	t[T1][0] = _mm_xor_si128(t[T1][0], ONE);
	low_inv(&t[T1][0], &t[T1][1], t[T1][0], t[T1][1]);
	/* t2 = (1 + t)/(1 + t + t^2). */
	_t[0] = _mm_xor_si128(_t[0], ONE);
	low_mul(&t[T2][0], &t[T2][1], t[T1][0], t[T1][1], _t[0], _t[1]);
	_t[0] = _mm_xor_si128(_t[0], ONE);
	low_mul(&t[T1][0], &t[T1][1], t[T1][0], t[T1][1], _t[0], _t[1]);
	/* t3 = t(1 + t)/(1 + t + t^2). */
	low_mul(&t[T3][0], &t[T3][1], t[T2][0], t[T2][1], _t[0], _t[1]);

	low_inv(&t[Tneg1][0], &t[Tneg1][1], t[T1][0], t[T1][1]);
	low_inv(&t[Tneg2][0], &t[Tneg2][1], t[T2][0], t[T2][1]);
	low_inv(&t[Tneg3][0], &t[Tneg3][1], t[T3][0], t[T3][1]);

	low_mul(&t[Tc2][0], &t[Tc2][1], t[T1][0], t[T1][1], t[Tneg2][0],
			t[Tneg2][1]);
	low_mul(&t[Tc3][0], &t[Tc3][1], t[T1][0], t[T1][1], t[Tneg3][0],
			t[Tneg3][1]);

	low_inv(&t[Tci2][0], &t[Tci2][1], t[Tc2][0], t[Tc2][1]);
	low_sqr(&t[Tci2][0], &t[Tci2][1], t[Tci2][0], t[Tci2][1]);

	low_inv(&t[Tci3][0], &t[Tci3][1], t[Tc3][0], t[Tc3][1]);
	low_sqr(&t[Tci3][0], &t[Tci3][1], t[Tci3][0], t[Tci3][1]);
}

static void ec_sw(__m128i *x0, __m128i *x1, __m128i *l0, __m128i *l1, __m128i u0,
		__m128i u1) {
	int j;
	__m128i _t, c0, c1, ci0, ci1, _x[3][2], _xn0, _xn1, h0, h1;
	__m128i ONE = _mm_set_epi64x(0x1, 0x0);
	uint64_t tr[2];

	/* c = u^2 + u + a. */
	low_sqr(&c0, &c1, u0, u1);
	c0 = _mm_xor_si128(c0, u0);
	c1 = _mm_xor_si128(c1, u1);
	c0 = _mm_xor_si128(c0, ONE);

	/* c_inv = 1/c */
	low_inv(&ci0, &ci1, c0, c1);

	for (j = 0; j < 3; j++) {
		if (j == 2) {
			_x[2][0] = _mm_xor_si128(_x[0][0], _x[1][0]);
			_x[2][1] = _mm_xor_si128(_x[0][1], _x[1][1]);
			_x[2][0] = _mm_xor_si128(_x[2][0], c0);
			_x[2][1] = _mm_xor_si128(_x[2][1], c1);
		} else {
			low_mul(&_x[j][0], &_x[j][1], t[j][0], t[j][1], c0, c1);
		}
		low_mul(&_xn0, &_xn1, t[Tneg1 + j][0], t[Tneg1 + j][1], ci0, ci1);
		low_sqr(&h0, &h1, _xn0, _xn1);
		low_mul_fq1(&h0, &h1, h0, h1, _mm_set_epi64x(0x0, 0x8000001));
		h0 = _mm_xor_si128(h0, _x[j][0]);
		h1 = _mm_xor_si128(h1, _x[j][1]);
		h0 = _mm_xor_si128(h0, ONE);
		low_red_127_063_000(h0, h1, _t);
		_mm_store_si128((__m128i *) tr, h0);
		if ((tr[1] & 1) == 0) {
			*x0 = _x[j][0];
			*x1 = _x[j][1];
			low_htr(l0, l1, h0, h1);
			*l0 = _mm_xor_si128(*l0, *x0);
			*l1 = _mm_xor_si128(*l1, *x1);
			break;
		}
	}
}

static int ec_ok(__m128i x0, __m128i x1, __m128i l0, __m128i l1) {
	uint64_t u[4], v[4];
	__m128i x20, x21, l20, l21, ONE = _mm_set_epi64x(0x1, 0x0);;

	/* x^2 */
	low_sqr(&x20, &x21, x0, x1);
	/* x^2(l^2 + l + a) */
	low_sqr(&l20, &l21, l0, l1);
	l20 = _mm_xor_si128(l20, l0);
	l21 = _mm_xor_si128(l21, l1);
	l20 = _mm_xor_si128(l20, ONE);
	low_mul(&l20, &l21, l20, l21, x20, x21);
	/* x^4 + b */
	low_sqr(&x20, &x21, x20, x21);
	ONE = _mm_set_epi64x(0x0, 0x8000001);
	x20 = _mm_xor_si128(x20, ONE);
	low_red_127_063_000(l20, l21, ONE);
	low_red_127_063_000(x20, x21, ONE);
	_mm_store_si128((__m128i *) u, l20);
	_mm_store_si128((__m128i *) (u + 2), l21);
	_mm_store_si128((__m128i *) v, x20);
	_mm_store_si128((__m128i *) (v + 2), x21);
	return (memcmp(u, v, 4 * sizeof(uint64_t)) == 0);
}

static void ec_enc(unsigned char *p, __m128i x0, __m128i x1, __m128i l0, __m128i l1) {
	/* Write the results. */
	_mm_store_si128((__m128i *) &p[0], x0);
	_mm_store_si128((__m128i *) &p[16], x1);

#ifdef COMPRESSION
	uint64_t u[2] = { 0 };
	_mm_store_si128((__m128i *) u, l0);
	p[23] |= (u[0] & 1) << 7;
	p[31] |= (u[1] & 1) << 7;
#else
	_mm_store_si128((__m128i *) &p[32], l0);
	_mm_store_si128((__m128i *) &p[48], l1);
#endif
}

static int ec_dec(__m128i *x0, __m128i *x1, __m128i *l0, __m128i *l1, uint8_t *p) {
	__m128i zero = _mm_setzero_si128();
#ifdef COMPRESSION
	__m128i t0, t1, u0, u1;
	uint8_t tr0 = p[23] >> 7;
	uint8_t tr1 = p[31] >> 7;
	uint64_t u[2] = { 0 };

	p[23] &= 0x7F;
	p[31] &= 0x7F;
	*x0 = _mm_loadu_si128((__m128i *) &p[0]);
	*x1 = _mm_loadu_si128((__m128i *) &p[16]);
	if (_mm_movemask_epi8(_mm_cmpeq_epi32(*x0,zero)) == 0xFFFF && _mm_movemask_epi8(_mm_cmpeq_epi32(*x1,zero)) == 0xFFFF)  {
		return 0;
	}
	p[23] |= (tr0) << 7;
	p[31] |= (tr1) << 7;

	low_sqr(&u0, &u1, *x0, *x1);
	low_inv_var(&t0, &t1, u0, u1);
	low_mul_fq1(&t0, &t1, t0, t1, _mm_set_epi64x(0x0, 0x8000001));
	t0 = _mm_xor_si128(t0, u0);
	t1 = _mm_xor_si128(t1, u1);
	t0 = _mm_xor_si128(t0, _mm_set_epi64x(0x1, 0x0));
	low_htr(l0, l1, t0, t1);
	_mm_store_si128((__m128i *)u, *l0);
	if ((u[0] & 1) != tr0) {
		*l0 = _mm_xor_si128(*l0, _mm_set_epi64x(0x0, 0x1));
	}
	if ((u[1] & 1) != tr1) {
		*l0 = _mm_xor_si128(*l0, _mm_set_epi64x(0x1, 0x0));
	}
#else
	*x0 = _mm_loadu_si128((__m128i *) &p[ 0]);
	*x1 = _mm_loadu_si128((__m128i *) &p[16]);
	if (_mm_movemask_epi8(_mm_cmpeq_epi32(*x0,zero)) == 0xFFFF && _mm_movemask_epi8(_mm_cmpeq_epi32(*x1,zero)) == 0xFFFF)  {
		return 0;
	}
	*l0 = _mm_loadu_si128((__m128i *) &p[32]);
	*l1 = _mm_loadu_si128((__m128i *) &p[48]);
#endif
	return ec_ok(*x0, *x1, *l0, *l1);
}
