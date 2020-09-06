/* finite field arithmetic */

/* modular reduction */
/* [F_q^2] general reduction modulo X^128 + X^64 + X */
#define low_red_128_064_001(op0,op1,op2,op3,tp0,tp1,re0,re1)\
    tp0 = _mm_xor_si128(op2, op3);\
    tp1 = _mm_xor_si128(tp0, _mm_srli_epi64(op3, 63));\
    tp1 = _mm_slli_epi64(tp1, 1);\
    re0 = _mm_xor_si128(op0, tp1);\
    re1 = _mm_xor_si128(tp0, op1);\
    re1 = _mm_xor_si128(re1, _mm_slli_epi64(op3, 1));\
    re1 = _mm_xor_si128(re1, _mm_srli_epi64(op2, 63));

/* [F_q^2] mult x Fq reduction modulo X^128 + X^64 + X */
#define low_red_128_064_001_fq1(op0,op1,op2,tp0,re0,re1)\
    tp0 = _mm_slli_epi64(op2, 1);\
    re0 = _mm_xor_si128(op0, tp0);\
    re1 = _mm_xor_si128(op2, op1);\
    re1 = _mm_xor_si128(re1, _mm_srli_epi64(op2, 63));

/* [F_q^2] squaring reduction modulo X^128 + X^64 + X */
#define low_red_128_064_001_sqr(op0,op1,op2,op3,tp0,tp1,re0,re1)\
    tp0 = _mm_xor_si128(op2, op3);\
    tp1 = _mm_slli_epi64(tp0, 1);\
    re0 = _mm_xor_si128(op0, tp1);\
    re1 = _mm_xor_si128(tp0, op1);\
    re1 = _mm_xor_si128(re1, _mm_slli_epi64(op3, 1));

/* [F_q^2] reduction of a 128-bit polynomial modulo X^127 + X^63 + 1 */
#define low_red_127_063_000(op0,op1,tp0)\
    tp0 = _mm_srli_epi64(op1, 63);\
    op0 = _mm_xor_si128(op0, tp0);\
    tp0 = _mm_slli_epi64(tp0, 63);\
    op0 = _mm_xor_si128(op0, tp0);\
    op1 = _mm_xor_si128(op1, tp0);

/* [F_q  ] general reduction modulo X^128 + X^64 + X */
#define low_red_128_064_001_bas(op0,op1,tp0,tp1,tp2,re0)\
    tp0 = _mm_alignr_epi8(op1, op1, 8);\
    tp1 = _mm_xor_si128(op1, tp0);\
    tp2 = _mm_srli_epi64(op1, 63);\
    tp1 = _mm_xor_si128(tp1, tp2);\
    tp2 = _mm_unpackhi_epi64(tp1, op1);\
    tp2 = _mm_slli_epi64(tp2, 1);\
    tp1 = _mm_slli_si128(tp1, 8);\
    tp1 = _mm_xor_si128(tp1, tp2);\
    re0 = _mm_xor_si128(op0, tp1);

/* [F_q  ] squaring reduction modulo X^128 + X^64 + X */
#define low_red_128_064_001_sqr_bas(op0,op1,tp0,tp1,re0)\
    tp0 = _mm_alignr_epi8(op1, op1, 8);\
    tp0 = _mm_xor_si128(tp0, op1);\
    tp1 = _mm_unpackhi_epi64(tp0, op1);\
    tp1 = _mm_slli_epi64(tp1, 1);\
    tp0 = _mm_slli_si128(tp0, 8);\
    tp0 = _mm_xor_si128(tp0, tp1);\
    re0 = _mm_xor_si128(op0, tp0);

/* multiplication */
/* [F_q^2] karatsuba algorithm step (middle term addition is not included) */
#define low_kts_stp(op0,op1,op2,op3,op4,op5,re0,re1,re2,ord)\
    re0 = _mm_clmulepi64_si128(op0, op1, ord);\
    re1 = _mm_clmulepi64_si128(op2, op3, ord);\
    re2 = _mm_clmulepi64_si128(op4, op5, ord);\
    re1 = _mm_xor_si128(re1, re0);\
    re1 = _mm_xor_si128(re1, re2);

/* [F_q^2] Karatsuba multiplication */
void low_mul(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01,
		__m128i op10, __m128i op11) {
	/* var */
	__m128i a00, a01, a02;
	__m128i k00, k01, k02;
	__m128i r00, r01, r02, r10, r11, r12, r20, r21, r22;
	__m128i rbe, rga;
	__m128i dal, dbe, dga, dde, dt0, dt1;

	/* karatsuba: pre */
	/* high level: (b_0 + b_1) | (a_0 + a_1) (LO) > a00 */
	a00 = _mm_unpacklo_epi64(op00, op10);
	a01 = _mm_unpackhi_epi64(op00, op10);
	a00 = _mm_xor_si128(a00, a01);

	/* high level: (b_0 + b_1) | (a_0 + a_1) (HI) > a01 */
	a01 = _mm_unpacklo_epi64(op01, op11);
	a02 = _mm_unpackhi_epi64(op01, op11);
	a01 = _mm_xor_si128(a01, a02);

	/* low level: (a_0 + a_1) */
	k00 = _mm_xor_si128(op00, op01);
	k01 = _mm_xor_si128(a00, a01);
	k02 = _mm_xor_si128(op10, op11);

	/* partial karatsuba multiplication */
	low_kts_stp(op00, op10, k00, k02, op01, op11, r00, r01, r02, 0x00);	/* a0xb0 */
	low_kts_stp(a00, a00, k01, k01, a01, a01, r10, r11, r12, 0x01);	/* (a0+a1) x (b0+b1) */
	low_kts_stp(op00, op10, k00, k02, op01, op11, r20, r21, r22, 0x11);	/* a1xb1 */

	/* karatsuba: final sum (the middle term is computed separately, and then reorganized) */
	/* imaginary part */
	r10 = _mm_xor_si128(r10, r00);	/* low term */
	r11 = _mm_xor_si128(r11, r01);	/* middle term */
	r12 = _mm_xor_si128(r12, r02);	/* high term */

	/* real part */
	r00 = _mm_xor_si128(r20, r00);	/* low term */
	r01 = _mm_xor_si128(r21, r01);	/* middle term */
	r02 = _mm_xor_si128(r22, r02);	/* high term */

	rbe = _mm_unpacklo_epi64(r01, r11);
	rga = _mm_unpackhi_epi64(r01, r11);

	/* reduction: pre */
	dal = _mm_unpacklo_epi64(r00, r10);
	dbe = _mm_unpackhi_epi64(r00, r10);
	dga = _mm_unpacklo_epi64(r02, r12);
	dde = _mm_unpackhi_epi64(r02, r12);

	/* karatsuba: final sum (middle term is added to the result values) */
	dbe = _mm_xor_si128(dbe, rbe);
	dga = _mm_xor_si128(dga, rga);

	/* reduction */
	low_red_128_064_001(dal, dbe, dga, dde, dt0, dt1, *re_0, *re_1);

	/* end */
	return;
}

/* [F_q^2] multiplication by (1 + u) */
void low_mul_01u(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i t00, t01;

	/* multiplication */
	/* (a0 + a1u) * (1 + u) = (a0 + a1) + a0u */
	t00 = _mm_slli_si128(op00, 8);
	t01 = _mm_slli_si128(op01, 8);

	*re_0 = _mm_xor_si128(op00, t00);
	*re_1 = _mm_xor_si128(op01, t01);

	*re_0 = _mm_alignr_epi8(*re_0, *re_0, 8);
	*re_1 = _mm_alignr_epi8(*re_1, *re_1, 8);

	/* end */
	return;
}

/* [F_q^2] multiplication by (0 + u) */
void low_mul_00u(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i t00, t01;

	/* multiplication */
	/* (a0 + a1u) * (0 + u) = a1 + (a0 + a1)u */
	t00 = _mm_srli_si128(op00, 8);
	t01 = _mm_srli_si128(op01, 8);

	*re_0 = _mm_xor_si128(op00, t00);
	*re_1 = _mm_xor_si128(op01, t01);

	*re_0 = _mm_alignr_epi8(*re_0, *re_0, 8);
	*re_1 = _mm_alignr_epi8(*re_1, *re_1, 8);

	/* end */
	return;
}

/* [F_q^2] multiplication by (x^27 + u) */
void low_mul_027(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i l01, r00;
	__m128i alp, bet, gam;
	__m128i t00, t01;

	/* multiplication */
	alp = _mm_slli_epi64(op00, 27);
	l01 = _mm_slli_epi64(op01, 27);

	r00 = _mm_srli_epi64(op00, 37);
	gam = _mm_srli_epi64(op01, 37);

	bet = _mm_xor_si128(l01, r00);

	/* reduction */
	*re_1 = _mm_xor_si128(bet, gam);
	gam = _mm_slli_epi64(gam, 1);
	*re_0 = _mm_xor_si128(alp, gam);

	/* end */
	return;
}

/* [F_q^2] multiplication by (x^27 + u) */
void low_mul_27u(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i l01, r00;
	__m128i alp, bet, gam;
	__m128i t00, t01;

	/* multiplication */
	alp = _mm_slli_epi64(op00, 27);
	l01 = _mm_slli_epi64(op01, 27);

	r00 = _mm_srli_epi64(op00, 37);
	gam = _mm_srli_epi64(op01, 37);

	bet = _mm_xor_si128(l01, r00);

	/* reduction */
	bet = _mm_xor_si128(bet, gam);
	gam = _mm_slli_epi64(gam, 1);
	alp = _mm_xor_si128(alp, gam);

	/* final multiplication */
	t00 = _mm_srli_si128(op00, 8);
	t01 = _mm_srli_si128(op01, 8);

	t00 = _mm_xor_si128(t00, op00);
	t01 = _mm_xor_si128(t01, op01);

	t00 = _mm_alignr_epi8(t00, t00, 8);
	t01 = _mm_alignr_epi8(t01, t01, 8);

	*re_0 = _mm_xor_si128(t00, alp);
	*re_1 = _mm_xor_si128(t01, bet);

	/* end */
	return;
}

/* [F_q^2] multiplication by (b \in Fq) */
void low_mul_fq1(__m128i * c_00, __m128i * c_01, __m128i a_00, __m128i a_01,
		__m128i b_00) {
	/* var */
	__m128i re00, re01, im00, im01;
	__m128i real, rebe, rega, rede;
	__m128i tmp0;

	/* multiplication */
	re00 = _mm_clmulepi64_si128(a_00, b_00, 0x00);
	re01 = _mm_clmulepi64_si128(a_01, b_00, 0x00);
	im00 = _mm_clmulepi64_si128(a_00, b_00, 0x01);
	im01 = _mm_clmulepi64_si128(a_01, b_00, 0x01);

	/* reduction: pre */
	real = _mm_unpacklo_epi64(re00, im00);
	rebe = _mm_unpackhi_epi64(re00, im00);
	rega = _mm_unpacklo_epi64(re01, im01);
	rede = _mm_unpackhi_epi64(re01, im01);

	/* multiplication: post */
	rebe = _mm_xor_si128(rebe, rega);
	rega = rede;

	/* reduction */
	low_red_128_064_001_fq1(real, rebe, rega, tmp0, *c_00, *c_01);

	/* end */
	return;
}

/* [F_q  ] Karatsuba multiplication */
void low_mul_bas(__m128i * re_0, __m128i op00, __m128i op10) {
	/* var */
	__m128i a00, a01, a02;
	__m128i k00, k01, k02;
	__m128i sal, sbe;

	/* karatsuba: pre */
	a00 = _mm_unpacklo_epi64(op00, op10);
	a01 = _mm_unpackhi_epi64(op00, op10);
	a00 = _mm_xor_si128(a00, a01);

	/* karatsuba */
	k00 = _mm_clmulepi64_si128(op00, op10, 0x00);
	k01 = _mm_clmulepi64_si128(a00, a00, 0x10);
	k02 = _mm_clmulepi64_si128(op00, op10, 0x11);
	k01 = _mm_xor_si128(k01, k00);
	k01 = _mm_xor_si128(k01, k02);

	/* katatsuba: post */
	sal = _mm_xor_si128(k00, _mm_slli_si128(k01, 8));
	sbe = _mm_xor_si128(k02, _mm_srli_si128(k01, 8));

	/* reduction */
	low_red_128_064_001_bas(sal, sbe, a00, a01, a02, *re_0);

	/* end */
	return;
}

/* squaring */
/* [F_q^2] squaring */
void low_sqr(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i a00, a01;
	__m128i sal, sbe, sga, sde, st0, st1;
	__m128i dt0, dt1;

	/* pre */
	a00 = _mm_shuffle_epi32(op00, 0xD8);
	a01 = _mm_shuffle_epi32(op01, 0xD8);

	/* squaring */
	sal = _mm_clmulepi64_si128(a00, a00, 0x00);
	sbe = _mm_clmulepi64_si128(a00, a00, 0x11);
	sga = _mm_clmulepi64_si128(a01, a01, 0x00);
	sde = _mm_clmulepi64_si128(a01, a01, 0x11);

	/* reduce */
	low_red_128_064_001_sqr(sal, sbe, sga, sde, st0, st1, *re_0, *re_1);

	/* squaring: final sum */
	st0 = _mm_srli_si128(*re_0, 8);
	st1 = _mm_srli_si128(*re_1, 8);
	*re_0 = _mm_xor_si128(*re_0, st0);
	*re_1 = _mm_xor_si128(*re_1, st1);

	/* end */
	return;
}

/* [F_q  ] squaring */
void low_sqr_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i sal, sbe;
	__m128i t00, t01;

	/* squaring */
	sal = _mm_clmulepi64_si128(op00, op00, 0x00);
	sbe = _mm_clmulepi64_si128(op00, op00, 0x11);

	/* reduce */
	low_red_128_064_001_sqr_bas(sal, sbe, t00, t01, *re_0);

	/* end */
	return;
}

#define low_sqr_003_stp(fir)\
    sal = _mm_clmulepi64_si128(fir, fir, 0x00);\
    sbe = _mm_clmulepi64_si128(fir, fir, 0x11);\
    low_red_128_064_001_sqr_bas(sal,sbe,t00,t01,*re_0);\
    sal = _mm_clmulepi64_si128(*re_0, *re_0, 0x00);\
    sbe = _mm_clmulepi64_si128(*re_0, *re_0, 0x11);\
    low_red_128_064_001_sqr_bas(sal,sbe,t00,t01,*re_0);\
    sal = _mm_clmulepi64_si128(*re_0, *re_0, 0x00);\
    sbe = _mm_clmulepi64_si128(*re_0, *re_0, 0x11);\
    low_red_128_064_001_sqr_bas(sal,sbe,t00,t01,*re_0);

/* [F_q  ] three squarings */
void low_sqr_003_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i sal, sbe;
	__m128i t00, t01;

	/* squarings */
	low_sqr_003_stp(op00);

	/* end */
	return;
}

/* [F_q  ] six squarings */
void low_sqr_006_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i sal, sbe;
	__m128i t00, t01;

	/* squarings */
	low_sqr_003_stp(op00);
	low_sqr_003_stp(*re_0);		/* 006 */

	/* end */
	return;
}

/* [F_q  ] fifteen squarings */
void low_sqr_015_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i sal, sbe;
	__m128i t00, t01;

	/* squarings */
	low_sqr_003_stp(op00);
	low_sqr_003_stp(*re_0);		/* 006 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 012 */
	low_sqr_003_stp(*re_0);		/* 015 */

	/* end */
	return;
}

/* [F_q  ] thirty squarings */
void low_sqr_030_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i sal, sbe;
	__m128i t00, t01;

	/* squarings */
	low_sqr_003_stp(op00);
	low_sqr_003_stp(*re_0);		/* 006 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 012 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 018 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 024 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 030 */

	/* end */
	return;
}

/* [F_q  ] sixty-three squarings */
void low_sqr_063_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i sal, sbe;
	__m128i t00, t01;

	/* squarings */
	low_sqr_003_stp(op00);
	low_sqr_003_stp(*re_0);		/* 006 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 012 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 018 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 024 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 030 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 036 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 042 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 048 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 054 */
	low_sqr_003_stp(*re_0);
	low_sqr_003_stp(*re_0);		/* 060 */
	low_sqr_003_stp(*re_0);		/* 063 */

	/* end */
	return;
}

#include "sqr_tbl.inc"

//MULTI SQUARING F_2^127 (6x)
void low_sqr06(__m128i *b, __m128i _a) {
	__m128i r0;
	uint64_t *p, a[2];
	int i;

    _mm_store_si128((__m128i *)a, _a);
	r0 = _mm_setzero_si128();

	for (i=0;i<16;i++) {
		p = tbl_sqr06[i][(a[0]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));

		p = tbl_sqr06[i+16][(a[1]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
	}

    *b = r0;
}

//MULTI SQUARING F_2^127 (12x)
void low_sqr12(__m128i *b, __m128i _a) {
    __m128i r0;
	uint64_t *p, a[2];
	int i;

    _mm_store_si128((__m128i *)a, _a);
	r0 = _mm_setzero_si128();

	for (i=0;i<16;i++) {
		p = tbl_sqr12[i][(a[0]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));

		p = tbl_sqr12[i+16][(a[1]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
	}

    *b = r0;
}

//MULTI SQUARING F_2^127 (24x)
void low_sqr24(__m128i *b, __m128i _a) {
    __m128i r0;
	uint64_t *p, a[2];
	int i;

    _mm_store_si128((__m128i *)a, _a);
	r0 = _mm_setzero_si128();

	for (i=0;i<16;i++) {
		p = tbl_sqr24[i][(a[0]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));

		p = tbl_sqr24[i+16][(a[1]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
	}

    *b = r0;
}

//MULTI SQUARING F_2^127 (48x)
void low_sqr48(__m128i *b, __m128i _a) {
    __m128i r0;
	uint64_t *p, a[2];
	int i;

    _mm_store_si128((__m128i *)a, _a);
	r0 = _mm_setzero_si128();

	for (i=0;i<16;i++) {
		p = tbl_sqr48[i][(a[0]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));

		p = tbl_sqr48[i+16][(a[1]>>(4*i))&0x0F];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
	}

	 *b = r0;
}

void low_inv_tbl(__m128i *_b, __m128i a) {
	__m128i tmp, b, a2_6, a2_24;

	//a^(2^2-2) * a = a^(2^2-1)
	low_sqr_bas(&b, a);
	low_mul_bas(&b, b, a);

	//a^(2^3-2) * a = a^(2^3-1)
	low_sqr_bas(&b, b);
	low_mul_bas(&b, b, a);

	//a^(2^6-2^3) * a^(2^3-1) = a^(2^6-1)
    low_sqr_003_bas(&a2_6, b);	/* 003 > 006 */
	low_mul_bas(&a2_6, a2_6, b);

	//a^(2^12-2^6) * a^(2^6-1) = a^(2^12-1)
	//low_sqi(b, a2_6, 6);
	low_sqr06(&b, a2_6);
	low_mul_bas(&b, b, a2_6);

	//a^(2^24-2^12) * a^(2^12-1) = a^(2^24-1)
	low_sqr12(&a2_24, b);
	low_mul_bas(&a2_24, a2_24, b);

	//a^(2^48-2^24) * a^(2^24-1) = a^(2^48-1)
	low_sqr24(&b, a2_24);
	low_mul_bas(&b, b, a2_24);

	//a^(2^96-2^48) * a^(2^48-1) = a^(2^96-1)
	low_sqr48(&tmp, b);
	low_mul_bas(&b, tmp, b);

	//a^(2^120-2^24) * a^(2^24-1) = a^(2^120-1)
	low_sqr24(&b, b);
	low_mul_bas(&b, b, a2_24);

	//a^(2^126-2^6) * a^(2^6-1) = a^(2^126-1)
	//low_sqi(b, b, 6);
	low_sqr06(&b, b);
	low_mul_bas(&b, b, a2_6);

	//a^(2^127-2)
	low_sqr_bas(_b, b);
}

/* [F_q^2] inversion */
void low_inv_var(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i are, aim, cre, cim;
	__m128i t00, t01, t02;

	/* inversion: pre */
	are = _mm_unpacklo_epi64(op00, op01);
	aim = _mm_unpackhi_epi64(op00, op01);

	/* inversion */
	t00 = _mm_xor_si128(are, aim);	/* t00 = a_r + a_i */
	low_mul_bas(&t01, are, aim);	/* t01 = a_r * a_i */
	low_sqr_bas(&t02, t00);		/* t02 = (a_r + a_i)^2 */
	t01 = _mm_xor_si128(t01, t02);	/* t = a_r * a_i + (a_r + a_i)^2 */

	low_inv_tbl(&t01, t01);		/* t = t^-1 */

	low_mul_bas(&cre, t00, t01);	/* c_r = (a_r + a_i) * t */
	low_mul_bas(&cim, aim, t01);	/* c_i = a_i * t */

	/* inversion: post */
	*re_0 = _mm_unpacklo_epi64(cre, cim);
	*re_1 = _mm_unpackhi_epi64(cre, cim);

	/* end */
	return;
}

/* inversion */
/* [F_q  ] inversion */
void low_inv_bas(__m128i * re_0, __m128i op00) {
	/* var */
	__m128i a00, a01, a03;

	/* itoh-tsujii: 1-2-3-6-12-15-30-60-63-126 */
	low_sqr_bas(&a01, op00);	/* 001 > 002 */
	low_mul_bas(&a00, a01, op00);

	low_sqr_bas(&a01, a00);		/* 002 > 003 */
	low_mul_bas(&a03, a01, op00);

	low_sqr_003_bas(&a01, a03);	/* 003 > 006 */
	low_mul_bas(&a00, a01, a03);

	low_sqr_006_bas(&a01, a00);	/* 006 > 012 */
	low_mul_bas(&a00, a01, a00);

	low_sqr_003_bas(&a01, a00);	/* 012 > 015 */
	low_mul_bas(&a00, a01, a03);

	low_sqr_015_bas(&a01, a00);	/* 015 > 030 */
	low_mul_bas(&a00, a01, a00);

	low_sqr_030_bas(&a01, a00);	/* 030 > 060 */
	low_mul_bas(&a00, a01, a00);

	low_sqr_003_bas(&a01, a00);	/* 060 > 063 */
	low_mul_bas(&a00, a01, a03);

	low_sqr_063_bas(&a01, a00);	/* 063 > 126 */
	low_mul_bas(&a00, a01, a00);

	low_sqr_bas(re_0, a00);		/* 126 > 127 */

	/* end */
	return;
}

/* [F_q^2] inversion */
void low_inv(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	/* var */
	__m128i are, aim, cre, cim;
	__m128i t00, t01, t02;

	/* inversion: pre */
	are = _mm_unpacklo_epi64(op00, op01);
	aim = _mm_unpackhi_epi64(op00, op01);

	/* inversion */
	t00 = _mm_xor_si128(are, aim);	/* t00 = a_r + a_i */
	low_mul_bas(&t01, are, aim);	/* t01 = a_r * a_i */
	low_sqr_bas(&t02, t00);		/* t02 = (a_r + a_i)^2 */
	t01 = _mm_xor_si128(t01, t02);	/* t = a_r * a_i + (a_r + a_i)^2 */

	low_inv_bas(&t01, t01);		/* t = t^-1 */

	low_mul_bas(&cre, t00, t01);	/* c_r = (a_r + a_i) * t */
	low_mul_bas(&cim, aim, t01);	/* c_i = a_i * t */

	/* inversion: post */
	*re_0 = _mm_unpacklo_epi64(cre, cim);
	*re_1 = _mm_unpackhi_epi64(cre, cim);

	/* end */
	return;
}

void low_sqrt(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	__m128i a0, aL, aH, uu0, uu1, vv0, vv1;
	__m128i ma, mb;
	uint64_t uu[2], vv[2];

	__m128i perm =
			_mm_set_epi32(0x0F0D0B09, 0x07050301, 0x0E0C0A08, 0x06040200);
	__m128i sqrtL =
			_mm_set_epi32(0x33322322, 0x31302120, 0x13120302, 0x11100100);
	__m128i sqrtH =
			_mm_set_epi32(0xCCC88C88, 0xC4C08480, 0x4C480C08, 0x44400400);
	__m128i maskL =
			_mm_set_epi32(0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F, 0x0F0F0F0F);
	__m128i maskH =
			_mm_set_epi32(0xF0F0F0F0, 0xF0F0F0F0, 0xF0F0F0F0, 0xF0F0F0F0);

	/* inversion: pre */
	ma = _mm_unpacklo_epi64(op00, op01);
	mb = _mm_unpackhi_epi64(op00, op01);
	ma = _mm_xor_si128(ma, mb);

	//Extraction of even (ae0) and odd (ao0) bits
	uu0 = _mm_shuffle_epi8(ma, perm);

	uu1 = _mm_and_si128(uu0, maskL);
	vv1 = _mm_and_si128(uu0, maskH);
	vv1 = _mm_srli_epi64(vv1, 4);

	uu1 = _mm_shuffle_epi8(sqrtL, uu1);
	vv1 = _mm_shuffle_epi8(sqrtH, vv1);

	uu0 = _mm_xor_si128(uu1, vv1);

	uu1 = _mm_and_si128(uu0, maskL);
	vv1 = _mm_and_si128(uu0, maskH);

	//Extraction of even (ae0) and odd (ao0) bits
	a0 = _mm_shuffle_epi8(mb, perm);

	aL = _mm_and_si128(a0, maskL);
	aH = _mm_and_si128(a0, maskH);
	aH = _mm_srli_epi64(aH, 4);

	aL = _mm_shuffle_epi8(sqrtL, aL);
	aH = _mm_shuffle_epi8(sqrtH, aH);

	a0 = _mm_xor_si128(aL, aH);

	aL = _mm_and_si128(a0, maskL);
	aH = _mm_and_si128(a0, maskH);

	//Multiplication of odd vector to constant value sqrt(x)
	//sqrt(x) = x^64 + x^32
	uu0 = _mm_unpacklo_epi64(uu1, aL);
	uu1 = _mm_unpackhi_epi64(uu1, aL);
	vv0 = _mm_unpacklo_epi64(vv1, aH);
	vv1 = _mm_unpackhi_epi64(vv1, aH);

	uu1 = _mm_slli_epi64(uu1, 4);
	vv0 = _mm_srli_epi64(vv0, 4);

	uu0 = _mm_xor_si128(uu0, uu1);
	vv0 = _mm_xor_si128(vv0, vv1);

	uu0 = _mm_xor_si128(uu0, _mm_slli_epi64(vv0, 32));	//b2b0
	vv0 = _mm_xor_si128(vv0, _mm_srli_epi64(vv0, 32));	//b3b1

	*re_0 = _mm_unpacklo_epi64(uu0, vv0);
	*re_1 = _mm_unpackhi_epi64(uu0, vv0);
}

#include "htr_tbl.inc"

/* half-trace in F_{q} */
void low_htr_tbl(__m128i *b, __m128i _a) {
	int i;
	uint64_t *p, a[2];
	uint8_t *tmp0, *tmp1;
	uint64_t a0_h, tmp;
    __m128i r0;

    _mm_store_si128((__m128i *)a, _a);
	a0_h = a[0] >> 32;
	tmp = _pdep_u64(a0_h, 0x5555555555555555);
	tmp = a[1] ^ tmp;

	//accumulator initialization
	a0_h = a0_h << 32;
	r0 = _mm_set_epi64x(0, a0_h);

	//window-8 pointer
	tmp0 = (uint8_t *) &a[0];
	tmp1 = (uint8_t *) &tmp;

	//look-up table
	for (i=0;i<4;i++) {
		p = tbl_htr[i][*tmp0++];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
		p = tbl_htr[i+8][*tmp1++];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
	}

	for (i=4;i<8;i++) {
		p = tbl_htr[i+8][*tmp1++];
		r0 = _mm_xor_si128(r0, *(__m128i *)(p));
	}

	*b = r0;
}

void low_htr(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
	__m128i ma, a0, a1, b0, b1;

	a0 = _mm_unpacklo_epi64(op00, op01);
	a1 = _mm_unpackhi_epi64(op00, op01);

	low_htr_tbl(&b1, a1);
	ma = _mm_xor_si128(a0, b1);
	ma = _mm_xor_si128(ma, a1);
	low_htr_tbl(&b0, ma);
	b1 = _mm_xor_si128(b1, _mm_and_si128(ma, _mm_set_epi64x(0, 1)));

	*re_0 = _mm_unpacklo_epi64(b0, b1);
	*re_1 = _mm_unpackhi_epi64(b0, b1);
}

void low_htr_bas(__m128i * b, __m128i a) {
	int i, j;
	__m128i t, _b;

	t = a;
	_b = a;

	for (i = 1; i <= (127 - 1) / 2; i++) {
		low_sqr_bas(&_b, _b);
		low_sqr_bas(&_b, _b);
		_b = _mm_xor_si128(_b, t);
	}
	*b = _b;
}

void low_htr_const(__m128i * re_0, __m128i * re_1, __m128i op00, __m128i op01) {
    __m128i ma, a0, a1, b0, b1;

	a0 = _mm_unpacklo_epi64(op00, op01);
	a1 = _mm_unpackhi_epi64(op00, op01);

	low_htr_bas(&b1, a1);
	ma = _mm_xor_si128(a0, b1);
	ma = _mm_xor_si128(ma, a1);
	low_htr_bas(&b0, ma);
	b1 = _mm_xor_si128(b1, _mm_and_si128(ma, _mm_set_epi64x(0, 1)));

	*re_0 = _mm_unpacklo_epi64(b0, b1);
	*re_1 = _mm_unpackhi_epi64(b0, b1);
}

void low_out(__m128i a0, __m128i a1) {
    uint64_t t[4];
    __m128i r;

    low_red_127_063_000(a0, a1, r);
    _mm_store_si128((__m128i *)(t+0), a0);
    _mm_store_si128((__m128i *)(t+2), a1);

    printf("0x%.16lX%.16lX, ", t[2], t[0]);
    printf("0x%.16lX%.16lX\n", t[3], t[1]);
}
