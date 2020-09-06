/* scalar multiplication */

/* regular recoding */
#define LOOP_SIZE 32
#define MASK 0x1F
#define M 16
#define SHR 4
#define SHL 60

/* 128-bit integer subtraction */
#define smu_sub_128(c0, c1, a0, a1)\
    asm ("subq %2, %0 \n\t"\
         "sbbq %3, %1"\
    : "+r" (c0), "+r" (c1)\
    : "r" (a0), "r" (a1) : "cc"\
    );

/* 128-bit integer addition */
#define smu_add_128(c0, c1, a0, a1)\
    asm ("addq %2, %0 \n\t"\
         "adcq %3, %1"\
    : "+r" (c0), "+r" (c1)\
    : "r" (a0), "r" (a1) : "cc"\
    );

/* regular recoding of a 127-bit integer */
void smu_reg_rec(int8_t *dig, uint64_t * k00) {
	/* var */
	int64_t ki, sig, i;

	/* main loop */
	for (i = 0; i < LOOP_SIZE; i++) {
		ki = k00[0] & MASK;
		ki = ki - M;
		dig[i] = ki & 0xFF;

		sig = ki >> 63;
		smu_sub_128(k00[0], k00[1], ki, sig);

		k00[0] = k00[0] >> SHR;
		k00[0] = k00[0] ^ (k00[1] << SHL);
		k00[1] = k00[1] >> SHR;
	}
	dig[LOOP_SIZE] = k00[0] & 0xFF;

	/* end */
	return;
}

typedef unsigned int uint128_t __attribute__((mode(TI)));

/* schoolbook multiplication (4 x 1) 64-bit words */
#define SCHBOOK_4x1(h, c, a, b)\
    h = ((uint128_t) a*b[0]);\
    c[0] = h; c[1] = h >> 64;\
    h = ((uint128_t) a*b[1]);\
    c[2] = h; c[3] = h >> 64;\
    h = ((uint128_t) a*b[2]);\
    c[4] = h; c[5] = h >> 64;\
    h = ((uint128_t) a*b[3]);\
    c[6] = h; c[7] = h >> 64;

/* schoolbook addition (4 x 1) 64-bit words
 * result on MSW c[7] | c[5] | c[3] | c[1] | c[0] LSW */
#define SCHBOOK_SUM_4x1(c)\
    asm ("addq %4, %0 \n\t"\
         "adcq %5, %1 \n\t"\
         "adcq %6, %2 \n\t"\
         "adcq $0, %3 \n\t"\
    : "+r" (c[1]), "+r" (c[3]), "+r" (c[5]), "+r" (c[7])\
    : "r" (c[2]), "r" (c[4]), "r" (c[6])\
    );

/* schoolbook addition (4 x 1) 64-bit words
 * result on MSW c[7] | c[5] | c[3] | c[1] | c[0] LSW */
#define SCHBOOK_SUM_4x4(c, k)\
    asm ("addq %4, %0 \n\t"\
         "adcq %5, %1 \n\t"\
         "adcq %6, %2 \n\t"\
         "adcq %7, %3 \n\t"\
    : "+r" (c[1]), "+r" (c[3]), "+r" (c[5]), "+r" (c[7])\
    : "r" (k[0]), "r" (k[1]), "r" (k[2]), "r" (k[3])\
    );


/* 128-bit addition with carry */
#define SUM_128(c0, c1, a0, a1)\
    asm ("addq %2, %0 \n\t"\
         "adcq %3, %1"\
    : "+r" (c0), "+r" (c1)\
    : "r" (a0), "r" (a1) : "cc"\
    );

/* 128-bit subtraction with carry */
#define SUB_128(c0, c1, a0, a1)\
    asm ("subq %2, %0 \n\t"\
         "sbbq %3, %1"\
    : "+r" (c0), "+r" (c1)\
    : "r" (a0), "r" (a1) : "cc"\
    );

/* 192-bit addition with carry */
#define SUM_192(c0, c1, c2, a0, a1, a2)\
    asm ("addq %3, %0 \n\t"\
         "adcq %4, %1 \n\t"\
         "adcq %5, %2"\
    : "+r" (c0), "+r" (c1), "+r" (c2)\
    : "m" (a0), "m" (a1), "m" (a2) : "cc"\
    );

/* 192-bit subtraction with carry */
#define SUB_192(c0, c1, c2, a0, a1, a2)\
    asm ("subq %3, %0 \n\t"\
         "sbbq %4, %1 \n\t"\
         "sbbq %5, %2"\
    : "+r" (c0), "+r" (c1), "+r" (c2)\
    : "m" (a0), "m" (a1), "m" (a2) : "cc"\
    );

/* 256-bit addition with carry */
#define SUM_256(c0, c1, c2, c3, a0, a1, a2, a3)\
    asm ("addq %4, %0 \n\t"\
         "adcq %5, %1 \n\t"\
         "adcq %6, %2 \n\t"\
         "adcq %7, %3"\
    : "+r" (c0), "+r" (c1), "+r" (c2), "+r" (c3)\
    : "m" (a0), "m" (a1), "m" (a2), "m" (a3) : "cc"\
    );

/* 256-bit subtraction with carry */
#define SUB_256(c0, c1, c2, c3, a0, a1, a2, a3)\
    asm ("subq %4, %0 \n\t"\
         "sbbq %5, %1 \n\t"\
         "sbbq %6, %2 \n\t"\
         "sbbq %7, %3"\
    : "+r" (c0), "+r" (c1), "+r" (c2), "+r" (c3)\
    : "m" (a0), "m" (a1), "m" (a2), "m" (a3) : "cc"\
    );

/* PROTECTED DIRECT RECODING (k -> k1, k2)
 * Method described in http://cacr.uwaterloo.ca/techreports/2012/cacr2012-24.pdf (Sec. 3.2) */
void gls_recoding(uint64_t k[], uint64_t k1[], uint64_t k2[], int *k1neg,
		int *k2neg) {
	//const uint64_t BETA_22 = 0xD792EA76691524E3; /* "t" term of #E = t^2 - (q-1)^2 */
	/* WEIER */ const uint64_t BETA_22[2] = { 0x38cd186180b532d3, 0x1 };
	/* "t" term of #E = t^2 - (q-1)^2 */
	///* HUFF */ const uint64_t BETA_22 = 0X2826AEC5683DD7BF;
	const uint64_t ALL_ZERO = 0;

	uint128_t reg_128;	/* 128-bit "register" */

	uint64_t tmp[8], sign;
	uint64_t result_4x1[8];
	uint64_t b1[2], b1_times_t[3], b2, b2_times_t[2];

	/* b1 (-k div 2^127) */
	b1[1] = (k[3] << 1) | (k[2] >> 63);
	b1[0] = (k[2] << 1) | (k[1] >> 63);

	/* b2 (k*BETA_22 div 2^254) */
	SCHBOOK_4x1(reg_128, result_4x1, BETA_22[0], k);
	SCHBOOK_SUM_4x1(result_4x1);
	SCHBOOK_SUM_4x4(result_4x1, k);
	b2 = (result_4x1[5] >> 62) | (result_4x1[7] << 2);

	//round
	b1[0] = b1[0] + ((k[1] >> 62) & 0x1);
	b2 = b2 + ((result_4x1[5] >> 61) & 0x1);

	/* b1*t */
	reg_128 = ((uint128_t) BETA_22[0] * b1[0]);	// + ((uint128_t)b1[0] << 64);
	b1_times_t[0] = reg_128;
	b1_times_t[1] = reg_128 >> 64;
	reg_128 = ((uint128_t) BETA_22[0] * b1[1]);
	b1_times_t[2] = reg_128 >> 64;
	SUM_128(b1_times_t[1], b1_times_t[2], (uint64_t) reg_128, ALL_ZERO);
	SUM_128(b1_times_t[1], b1_times_t[2], (uint64_t) b1[0], b1[1]);

	/* b2*t */
	reg_128 = ((uint128_t) BETA_22[0] * b2) + ((uint128_t) b2 << 64);
	b2_times_t[0] = reg_128;
	b2_times_t[1] = reg_128 >> 64;

	/** k1 computation */

	/* b1 */
	tmp[0] = b1[0];
	tmp[1] = b1[1];
	tmp[2] = 0;
	tmp[3] = 0;

	/* b1 + k */
	SUM_256(tmp[0], tmp[1], tmp[2], tmp[3], k[0], k[1], k[2], k[3]);

	/* b1*q (q = 2^127) */
	tmp[4] = 0;
	tmp[5] = b1[0] << 63;
	tmp[6] = b1[0] >> 1 | b1[1] << 63;
	tmp[7] = b1[1] >> 1;

	/* b1*q + b2*t */
	SUM_256(tmp[4], tmp[5], tmp[6], tmp[7], b2_times_t[0], b2_times_t[1],
			ALL_ZERO, ALL_ZERO);

	/* k1 sign (0 for positive, 1 for negative) */
	sign = (tmp[6] > tmp[2]) | ((tmp[6] == tmp[2]) & (tmp[5] > tmp[1]));

	/* final subtraction */
	SUB_256(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5], tmp[6], tmp[7]);

	/* Two's complement (if necessary) */
	tmp[0] = tmp[0] ^ (ALL_ZERO - sign);
	tmp[1] = tmp[1] ^ (ALL_ZERO - sign);
	SUM_128(tmp[0], tmp[1], sign, ALL_ZERO);

	/* output */
	*k1neg = (int)sign;
	k1[0] = tmp[0];
	k1[1] = tmp[1];

	/** k2 computation */

	/* b1t + b2 */
	tmp[0] = b1_times_t[0];
	tmp[1] = b1_times_t[1];
	tmp[2] = b1_times_t[2];

	SUM_192(tmp[0], tmp[1], tmp[2], b2, ALL_ZERO, ALL_ZERO);

	/* b2*q (q = 2^127) */
	tmp[3] = 0;
	tmp[4] = b2 << 63;
	tmp[5] = b2 >> 1;

	/* k2 sign (0 for positive, 1 for negative) */
	sign = (tmp[5] > tmp[2]) | ((tmp[5] == tmp[2]) & (tmp[4] > tmp[1]));

	/* final subtraction */
	SUB_192(tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);

	/* Two's complement (if necessary) */
	tmp[0] = tmp[0] ^ (ALL_ZERO - sign);
	tmp[1] = tmp[1] ^ (ALL_ZERO - sign);
	SUM_128(tmp[0], tmp[1], sign, ALL_ZERO);

	/* output */
	*k2neg = (int)sign ^ 1;
	k2[0] = tmp[0];
	k2[1] = tmp[1];
}


/* 5-NAF pre-computation */
void smu_pre_5nf(__m128i * ppx0, __m128i * ppx1,
		__m128i * ppl0, __m128i * ppl1,
		__m128i * ppz0, __m128i * ppz1,
		__m128i px0, __m128i px1, __m128i pl0, __m128i pl1) {
	/* var */
	__m128i ONE, ml00;
	__m128i zin0[8], zin1[8];
	__m128i tmp0[5], tmp1[5];

	/* init */
	ONE = _mm_set_epi64x(0x0, 0x1);
	ml00 = _mm_xor_si128(pl0, ONE);

	/* pre-computation */
	/* P1 */
	ppx0[0] = px0;
	ppx1[0] = px1;
	ppl0[0] = pl0;
	ppl1[0] = pl1;

	/* P3 */
	eca_add_dbl(&ppx0[1], &ppx1[1], &ppl0[1], &ppl1[1], &ppz0[1], &ppz1[1],
			px0, px1, pl0, pl1, px0, px1, pl0, pl1);

	/* P5 and P7 */
	eca_add_sub_dbl(&ppx0[2], &ppx1[2], &ppl0[2], &ppl1[2], &ppz0[2], &ppz1[2],
			&ppx0[3], &ppx1[3], &ppl0[3], &ppl1[3], &ppz0[3], &ppz1[3],
			ppx0[1], ppx1[1], ppl0[1], ppl1[1], ppz0[1], ppz1[1],
			px0, px1, pl0, pl1);

	/* P9 and P11 */
	eca_add_sub_dbl(&ppx0[4], &ppx1[4], &ppl0[4], &ppl1[4], &ppz0[4], &ppz1[4],
			&ppx0[5], &ppx1[5], &ppl0[5], &ppl1[5], &ppz0[5], &ppz1[5],
			ppx0[2], ppx1[2], ppl0[2], ppl1[2], ppz0[2], ppz1[2],
			px0, px1, pl0, pl1);

	/* P9 and P11 */
	eca_add_sub_dbl(&ppx0[6], &ppx1[6], &ppl0[6], &ppl1[6], &ppz0[6], &ppz1[6],
			&ppx0[7], &ppx1[7], &ppl0[7], &ppl1[7], &ppz0[7], &ppz1[7],
			ppx0[3], ppx1[3], ppl0[3], ppl1[3], ppz0[3], ppz1[3],
			px0, px1, pl0, pl1);

	/* inversion: montgomery`s trick */
	/* part I */
	low_mul(&tmp0[0], &tmp1[0], ppz0[1], ppz1[1], ppz0[2], ppz1[2]);
	low_mul(&tmp0[1], &tmp1[1], tmp0[0], tmp1[0], ppz0[3], ppz1[3]);
	low_mul(&tmp0[2], &tmp1[2], tmp0[1], tmp1[1], ppz0[4], ppz1[4]);
	low_mul(&tmp0[3], &tmp1[3], tmp0[2], tmp1[2], ppz0[5], ppz1[5]);
	low_mul(&tmp0[4], &tmp1[4], tmp0[3], tmp1[3], ppz0[6], ppz1[6]);
	low_mul(&zin0[0], &zin1[0], tmp0[4], tmp1[4], ppz0[7], ppz1[7]);

	/* part II */
	low_inv(&zin0[0], &zin1[0], zin0[0], zin1[0]);

	/* part III */
	low_mul(&zin0[7], &zin1[7], zin0[0], zin1[0], tmp0[4], tmp1[4]);
	low_mul(&zin0[0], &zin1[0], zin0[0], zin1[0], ppz0[7], ppz1[7]);
	low_mul(&zin0[6], &zin1[6], zin0[0], zin1[0], tmp0[3], tmp1[3]);
	low_mul(&zin0[0], &zin1[0], zin0[0], zin1[0], ppz0[6], ppz1[6]);
	low_mul(&zin0[5], &zin1[5], zin0[0], zin1[0], tmp0[2], tmp1[2]);
	low_mul(&zin0[0], &zin1[0], zin0[0], zin1[0], ppz0[5], ppz1[5]);
	low_mul(&zin0[4], &zin1[4], zin0[0], zin1[0], tmp0[1], tmp1[1]);
	low_mul(&zin0[0], &zin1[0], zin0[0], zin1[0], ppz0[4], ppz1[4]);
	low_mul(&zin0[3], &zin1[3], zin0[0], zin1[0], tmp0[0], tmp1[0]);
	low_mul(&zin0[0], &zin1[0], zin0[0], zin1[0], ppz0[3], ppz1[3]);
	low_mul(&zin0[1], &zin1[1], zin0[0], zin1[0], ppz0[2], ppz1[2]);
	low_mul(&zin0[2], &zin1[2], zin0[0], zin1[0], ppz0[1], ppz1[1]);

	/* to affine */
	low_mul(&ppx0[1], &ppx1[1], ppx0[1], ppx1[1], zin0[1], zin1[1]);
	low_mul(&ppl0[1], &ppl1[1], ppl0[1], ppl1[1], zin0[1], zin1[1]);
	low_mul(&ppx0[2], &ppx1[2], ppx0[2], ppx1[2], zin0[2], zin1[2]);
	low_mul(&ppl0[2], &ppl1[2], ppl0[2], ppl1[2], zin0[2], zin1[2]);
	low_mul(&ppx0[3], &ppx1[3], ppx0[3], ppx1[3], zin0[3], zin1[3]);
	low_mul(&ppl0[3], &ppl1[3], ppl0[3], ppl1[3], zin0[3], zin1[3]);
	low_mul(&ppx0[4], &ppx1[4], ppx0[4], ppx1[4], zin0[4], zin1[4]);
	low_mul(&ppl0[4], &ppl1[4], ppl0[4], ppl1[4], zin0[4], zin1[4]);
	low_mul(&ppx0[5], &ppx1[5], ppx0[5], ppx1[5], zin0[5], zin1[5]);
	low_mul(&ppl0[5], &ppl1[5], ppl0[5], ppl1[5], zin0[5], zin1[5]);
	low_mul(&ppx0[6], &ppx1[6], ppx0[6], ppx1[6], zin0[6], zin1[6]);
	low_mul(&ppl0[6], &ppl1[6], ppl0[6], ppl1[6], zin0[6], zin1[6]);
	low_mul(&ppx0[7], &ppx1[7], ppx0[7], ppx1[7], zin0[7], zin1[7]);
	low_mul(&ppl0[7], &ppl1[7], ppl0[7], ppl1[7], zin0[7], zin1[7]);

	/* end */
	return;
}

/* retrieve digit sign (sig) and absolute value (abs) */
#define smu_get_flg(vec,idx,msk,abs,sig)\
    msk = vec[idx] >> 7;\
    abs = vec[idx];\
    sig = abs >> 63;\
    abs = ((abs ^ msk) + sig) >> 1;

/* GLS endomorphism */
#define smu_psi_end(ox00,ox01,ol00,ol01,ix00,ix01,il00,il01,ONE)\
    ox00 = _mm_srli_si128(ix00, 8);\
    ox00 = _mm_xor_si128(ox00, ix00);\
    ox01 = _mm_srli_si128(ix01, 8);\
    ox01 = _mm_xor_si128(ox01, ix01);\
    ol00 = _mm_srli_si128(il00, 8);\
    ol00 = _mm_xor_si128(ol00, il00);\
    ol01 = _mm_srli_si128(il01, 8);\
    ol01 = _mm_xor_si128(ol01, il01);\
    ol00 = _mm_xor_si128(ol00, ONE);

/* linar pass algorithm */
#define smu_lps(dst0, dst1, msk0, msk1, src)\
    dst0 = _mm_setzero_si128();\
    dst1 = _mm_setzero_si128();\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[0], msk0[0]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[0], msk1[0]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[1], msk0[1]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[1], msk1[1]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[2], msk0[2]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[2], msk1[2]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[3], msk0[3]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[3], msk1[3]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[4], msk0[4]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[4], msk1[4]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[5], msk0[5]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[5], msk1[5]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[6], msk0[6]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[6], msk1[6]));\
    dst0 = _mm_xor_si128(dst0, _mm_and_si128(src[7], msk0[7]));\
    dst1 = _mm_xor_si128(dst1, _mm_and_si128(src[7], msk1[7]));

	/* protected 5-NAF double-and-add left-to-right scalar multiplication */
void smu_5nf_dna_ltr(__m128i * qx0, __m128i * qx1,
		__m128i * ql0, __m128i * ql1,
		__m128i px0, __m128i px1, __m128i pl0, __m128i pl1, uint64_t * k) {
	/* var */
	int8_t dg0[33], dg1[33];
	int i, j;
	uint64_t sig0, sig1, abs0, abs1, msk;
	uint64_t k0[2], k1[2], evk0, evk1, ZERO;
	int k0neg, k1neg;
	__m128i ONE;
	__m128i ppx0[8], ppl0[8], ppz0[8], ppx1[8], ppl1[8], ppz1[8];
	__m128i a0x0, a0x1, a0l0, a0l1;
	__m128i a1x0, a1x1, a1l0, a1l1, e1x0, e1x1, e1l0, e1l1;
	__m128i msk0[8], msk1[8], cmp[8], dig0, dig1, ssgn;
	__m128i sig_sse, msk_sse, one;
	__m128i qfx0[2], qfx1[2], qfl0[2], qfl1[2], qfz0[2], qfz1[2], qz0, qz1;

	/* init */
	ONE = _mm_set_epi64x(0x1, 0x1);
	cmp[0] = _mm_setzero_si128();
	for (j = 1; j < 8; j++) {
		cmp[j] = _mm_add_epi64(cmp[j - 1], ONE);
	}

	/* regular recoding */
	gls_recoding(k, k0, k1, &k0neg, &k1neg);

	evk0 = k0[0] & 0x1;
	evk1 = k1[0] & 0x1;
	evk0 = 1 - evk0;
	evk1 = 1 - evk1;
	ZERO = 0x0;
	smu_add_128(k0[0], k0[1], evk0, ZERO);
	smu_add_128(k1[0], k1[1], evk1, ZERO);

	smu_reg_rec(&dg0[0], &k0[0]);
	smu_reg_rec(&dg1[0], &k1[0]);

	/* pre computation */
	smu_pre_5nf(&ppx0[0], &ppx1[0], &ppl0[0], &ppl1[0], &ppz0[0], &ppz1[0],
			px0, px1, pl0, pl1);

	/* first iteration */
	/* digit */
	smu_get_flg(dg0, 32, msk, abs0, sig0);
	smu_get_flg(dg1, 32, msk, abs1, sig1);

	/* add k0 digit */
	ssgn = _mm_set_epi64x(0x0, sig0 ^ k0neg);
	*qx0 = ppx0[0];
	*qx1 = ppx1[0];
	*ql0 = _mm_xor_si128(ppl0[0], ssgn);
	*ql1 = ppl1[0];

	a1x0 = ppx0[0];
	a1x1 = ppx1[0];
	a1l0 = ppl0[0];
	a1l1 = ppl1[0];

	/* add k1 digit */
	ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
	a1l0 = _mm_xor_si128(a1l0, ssgn);
	smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
	eca_add_mma(qx0, qx1, ql0, ql1, &qz0, &qz1, *qx0, *qx1, *ql0, *ql1,
			e1x0, e1x1, e1l0, e1l1);

	/* main loop */
	for (i = 31; i >= 0; i--) {
		/* point doubling */
		eca_dbl_ful(qx0, qx1, ql0, ql1, &qz0, &qz1,
				*qx0, *qx1, *ql0, *ql1, qz0, qz1);

		eca_dbl_ful(qx0, qx1, ql0, ql1, &qz0, &qz1,
				*qx0, *qx1, *ql0, *ql1, qz0, qz1);

		eca_dbl_ful(qx0, qx1, ql0, ql1, &qz0, &qz1,
				*qx0, *qx1, *ql0, *ql1, qz0, qz1);

		/* digit */
		smu_get_flg(dg0, i, msk, abs0, sig0);
		smu_get_flg(dg1, i, msk, abs1, sig1);

		/* linear pass */
		dig0 = _mm_set_epi64x(abs0, abs0);
		dig1 = _mm_set_epi64x(abs1, abs1);
		for (j = 0; j < 8; j++) {
			msk0[j] = _mm_cmpeq_epi64(cmp[j], dig0);
			msk1[j] = _mm_cmpeq_epi64(cmp[j], dig1);
		}
		smu_lps(a0x0, a1x0, msk0, msk1, ppx0);
		smu_lps(a0x1, a1x1, msk0, msk1, ppx1);
		smu_lps(a0l0, a1l0, msk0, msk1, ppl0);
		smu_lps(a0l1, a1l1, msk0, msk1, ppl1);

		/* add k0, k1 digits */
		ssgn = _mm_set_epi64x(0x0, sig0 ^ k0neg);
		a0l0 = _mm_xor_si128(a0l0, ssgn);
		smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
		ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
		e1l0 = _mm_xor_si128(e1l0, ssgn);
		eca_add_add_dbl(qx0, qx1, ql0, ql1, &qz0, &qz1,
				*qx0, *qx1, *ql0, *ql1, qz0, qz1,
				a0x0, a0x1, a0l0, a0l1, e1x0, e1x1, e1l0, e1l1);
	}

	/* subtract P, if necessary */
	qfx0[0] = *qx0;
	qfx1[0] = *qx1;
	qfl0[0] = *ql0;
	qfl1[0] = *ql1;
	qfz0[0] = qz0;
	qfz1[0] = qz1;

	eca_add_mix(&qfx0[1], &qfx1[1], &qfl0[1], &qfl1[1], &qfz0[1], &qfz1[1],
			*qx0, *qx1, *ql0, *ql1, qz0, qz1,
			ppx0[0], ppx1[0], _mm_xor_si128(ppl0[0], _mm_set_epi64x(0x0,
							0x1 ^ k0neg)), ppl1[0]);

	sig_sse = _mm_set_epi64x(evk0, evk0);
	msk_sse = _mm_setzero_si128();
	msk_sse = _mm_sub_epi64(msk_sse, sig_sse);

	*qx0 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfx0[0]),
			_mm_and_si128(msk_sse, qfx0[1]));
	*qx1 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfx1[0]),
			_mm_and_si128(msk_sse, qfx1[1]));
	*ql0 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfl0[0]),
			_mm_and_si128(msk_sse, qfl0[1]));
	*ql1 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfl1[0]),
			_mm_and_si128(msk_sse, qfl1[1]));
	qz0 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfz0[0]),
			_mm_and_si128(msk_sse, qfz0[1]));
	qz1 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfz1[0]),
			_mm_and_si128(msk_sse, qfz1[1]));

	/* subtract psi(P), if necessary */
	smu_psi_end(ppx0[1], ppx1[1], ppl0[1], ppl1[1], ppx0[0], ppx1[0], ppl0[0],
			ppl1[0], ONE);

	qfx0[0] = *qx0;
	qfx1[0] = *qx1;
	qfl0[0] = *ql0;
	qfl1[0] = *ql1;
	qfz0[0] = qz0;
	qfz1[0] = qz1;

	eca_add_mix(&qfx0[1], &qfx1[1], &qfl0[1], &qfl1[1], &qfz0[1], &qfz1[1],
			*qx0, *qx1, *ql0, *ql1, qz0, qz1,
			ppx0[1], ppx1[1], _mm_xor_si128(ppl0[1], _mm_set_epi64x(0x0,
							0x1 ^ k1neg)), ppl1[1]);

	sig_sse = _mm_set_epi64x(evk1, evk1);
	msk_sse = _mm_setzero_si128();
	msk_sse = _mm_sub_epi64(msk_sse, sig_sse);

	*qx0 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfx0[0]),
			_mm_and_si128(msk_sse, qfx0[1]));
	*qx1 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfx1[0]),
			_mm_and_si128(msk_sse, qfx1[1]));
	*ql0 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfl0[0]),
			_mm_and_si128(msk_sse, qfl0[1]));
	*ql1 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfl1[0]),
			_mm_and_si128(msk_sse, qfl1[1]));
	qz0 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfz0[0]),
			_mm_and_si128(msk_sse, qfz0[1]));
	qz1 = _mm_xor_si128(_mm_andnot_si128(msk_sse, qfz1[0]),
			_mm_and_si128(msk_sse, qfz1[1]));

	/* end */
	/* to afffine */
	low_inv(&qz0, &qz1, qz0, qz1);
	low_mul(qx0, qx1, *qx0, *qx1, qz0, qz1);
	low_mul(ql0, ql1, *ql0, *ql1, qz0, qz1);

	/* final reduction */
	low_red_127_063_000(*qx0, *qx1, ONE);
	low_red_127_063_000(*ql0, *ql1, ONE);

	return;
}

#define SUMX64(c,a,b,cr)\
    c = a + b + cr;\
    cr = (c < a);

#define SUBX64(c,a,b,bw)\
    c = a - b - bw;\
    bw = (c > a);

void scmul_5wnaf(int8_t *kwnaf, int *len, uint64_t k[2]) {
	uint64_t num[2], sum[2];
	int idx, mod;
    uint8_t tmp;
	int8_t tbl4NAF[16] =
			{ 1, 3, 5, 7, 9, 11, 13, 15, -15, -13, -11, -9, -7, -5, -3, -1 };

	num[0] = k[0];
	num[1] = k[1];
	idx = 0;

	while (num[0] | num[1]) {
		if (num[0] & 0x1) {
			//odd number
			mod = num[0] & 0x1F;
			tmp = tbl4NAF[mod / 2];
			kwnaf[idx++] = tmp;

			if (tmp >= 128) {
				tmp = 256 - tmp;
				sum[0] = num[0] + tmp;
				sum[1] = num[1] + (sum[0] < tmp);
			} else {
				sum[0] = num[0] - tmp;
				sum[1] = num[1] - (sum[0] > num[0]);
			}

			num[0] = (sum[0] >> 1) ^ (sum[1] << 63);
			num[1] = (sum[1] >> 1);
		} else {
			//even number
			kwnaf[idx++] = 0;

			num[0] = (num[0] >> 1) ^ (num[1] << 63);
			num[1] = (num[1] >> 1);
		}
	}
	*len = idx;
}

/* protected 5-NAF double-and-add left-to-right scalar multiplication */
void smu_5nf_dna_var(__m128i * qx0, __m128i * qx1, __m128i * ql0, __m128i * ql1,
		__m128i px0, __m128i px1, __m128i pl0, __m128i pl1, uint64_t * k) {
	/* var */
	int8_t dg0[129] = { 0 }, dg1[129] = { 0 };
	int i, j, len0, len1, k0neg, k1neg;
	uint64_t sig0, sig1, abs0, abs1, msk, k0[2], k1[2];
	__m128i ONE = _mm_set_epi64x(0x1, 0x1);
	__m128i ppx0[8], ppl0[8], ppz0[8], ppx1[8], ppl1[8], ppz1[8];
	__m128i a0x0, a0x1, a0l0, a0l1, ssgn;
	__m128i a1x0, a1x1, a1l0, a1l1, e1x0, e1x1, e1l0, e1l1;
	__m128i qz0, qz1;

	/* regular recoding */
	gls_recoding(k, k0, k1, &k0neg, &k1neg);
	scmul_5wnaf(dg0, &len0, k0);
	scmul_5wnaf(dg1, &len1, k1);
	len0--;
	len1--;

	/* pre computation */
	smu_pre_5nf(&ppx0[0], &ppx1[0], &ppl0[0], &ppl1[0], &ppz0[0], &ppz1[0],
			px0, px1, pl0, pl1);

	if (len0 >= len1) {
		smu_get_flg(dg0, len0, msk, abs0, sig0);
		ssgn = _mm_set_epi64x(0x0, sig0 ^ k0neg);
		*qx0 = ppx0[abs0];
		*qx1 = ppx1[abs0];
		*ql0 = _mm_xor_si128(ppl0[abs0], ssgn);
		*ql1 = ppl1[abs0];
	} else {
		smu_get_flg(dg1, len1, msk, abs1, sig1);
		ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
		a1x0 = ppx0[abs1];
		a1x1 = ppx1[abs1];
		a1l0 = _mm_xor_si128(ppl0[abs1], ssgn);
		a1l1 = ppl1[abs1];
		smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
		*qx0 = e1x0;
		*qx1 = e1x1;
		*ql0 = e1l0;
		*ql1 = e1l1;
	}

	qz0 = _mm_set_epi64x(0x0, 0x1);
	qz1 = _mm_setzero_si128();

	if (len0 == len1) {
		smu_get_flg(dg1, len1, msk, abs1, sig1);
		ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
		a1x0 = ppx0[abs1];
		a1x1 = ppx1[abs1];
		a1l0 = _mm_xor_si128(ppl0[abs1], ssgn);
		a1l1 = ppl1[abs1];
		smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
		eca_add_mma(qx0, qx1, ql0, ql1, &qz0, &qz1, *qx0, *qx1, *ql0, *ql1,
				e1x0, e1x1, e1l0, e1l1);
	}

	len0 = (len0 > len1) ? len0 : len1;

	for (i = len0 - 1; i >= 0; i--) {
		/* point doubling */
		eca_dbl_ful(qx0, qx1, ql0, ql1, &qz0, &qz1,
				*qx0, *qx1, *ql0, *ql1, qz0, qz1);

		if (dg0[i]) {
			smu_get_flg(dg0, i, msk, abs0, sig0);
			ssgn = _mm_set_epi64x(0x0, sig0 ^ k0neg);
			a0x0 = ppx0[abs0];
			a0x1 = ppx1[abs0];
			a0l0 = _mm_xor_si128(ppl0[abs0], ssgn);
			a0l1 = ppl1[abs0];
			eca_add_mix(qx0, qx1, ql0, ql1, &qz0, &qz1, *qx0, *qx1, *ql0, *ql1,
					qz0, qz1, a0x0, a0x1, a0l0, a0l1);
		}

		if (dg1[i]) {
			smu_get_flg(dg1, i, msk, abs1, sig1);
			ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
			a1x0 = ppx0[abs1];
			a1x1 = ppx1[abs1];
			a1l0 = _mm_xor_si128(ppl0[abs1], ssgn);
			a1l1 = ppl1[abs1];
			smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
			eca_add_mix(qx0, qx1, ql0, ql1, &qz0, &qz1, *qx0, *qx1, *ql0, *ql1,
					qz0, qz1, e1x0, e1x1, e1l0, e1l1);
		}
	}

	/* to afffine */
	low_inv_var(&qz0, &qz1, qz0, qz1);
	low_mul(qx0, qx1, *qx0, *qx1, qz0, qz1);
	low_mul(ql0, ql1, *ql0, *ql1, qz0, qz1);

	/* final reduction */
	low_red_127_063_000(*qx0, *qx1, ONE);
	low_red_127_063_000(*ql0, *ql1, ONE);
}

/* protected 5-NAF double-and-add left-to-right scalar multiplication */
void smu_two_5nf_dna_ltr(__m128i * rx0, __m128i * rx1, __m128i * rl0,
		__m128i * rl1, __m128i px0, __m128i px1, __m128i pl0, __m128i pl1,
		uint64_t * k, __m128i qx0, __m128i qx1, __m128i ql0, __m128i ql1,
		uint64_t * l) {
	/* var */
	int8_t dg0[129] = { 0 }, dg1[129] = { 0 };
	int8_t dg2[129] = { 0 }, dg3[129] = { 0 };
	int i, j, len0, len1, len2, len3, k0neg, k1neg, l0neg, l1neg, max;
	uint64_t sig0, sig1, abs0, abs1, msk, k0[2], k1[2], l0[2], l1[2];
	__m128i ONE = _mm_set_epi64x(0x1, 0x1);
	__m128i ppx0[8], ppl0[8], ppz0[8], ppx1[8], ppl1[8], ppz1[8];
	__m128i qqx0[8], qql0[8], qqz0[8], qqx1[8], qql1[8], qqz1[8];
	__m128i a0x0, a0x1, a0l0, a0l1, ssgn;
	__m128i a1x0, a1x1, a1l0, a1l1, e1x0, e1x1, e1l0, e1l1;
	__m128i rz0, rz1;

	/* regular recoding */
	gls_recoding(k, k0, k1, &k0neg, &k1neg);
	scmul_5wnaf(dg0, &len0, k0);
	scmul_5wnaf(dg1, &len1, k1);
	len0--;
	len1--;
	gls_recoding(l, l0, l1, &l0neg, &l1neg);
	scmul_5wnaf(dg2, &len2, l0);
	scmul_5wnaf(dg3, &len3, l1);
	len2--;
	len3--;

	/* pre computation */
	smu_pre_5nf(&ppx0[0], &ppx1[0], &ppl0[0], &ppl1[0], &ppz0[0], &ppz1[0],
			px0, px1, pl0, pl1);
	smu_pre_5nf(&qqx0[0], &qqx1[0], &qql0[0], &qql1[0], &qqz0[0], &qqz1[0],
			qx0, qx1, ql0, ql1);

	rz0 = _mm_set_epi64x(0x0, 0x1);
	rz1 = _mm_setzero_si128();

	max = (len0 > len1) ? len0 : len1;
	max = (max > len2) ? max : len2;
	max = (max > len3) ? max : len3;

	if (max == len0) {
		smu_get_flg(dg0, len0, msk, abs0, sig0);
		ssgn = _mm_set_epi64x(0x0, sig0 ^ k0neg);
		*rx0 = ppx0[abs0];
		*rx1 = ppx1[abs0];
		*rl0 = _mm_xor_si128(ppl0[abs0], ssgn);
		*rl1 = ppl1[abs0];
	}

	if (max == len1) {
		smu_get_flg(dg1, len1, msk, abs1, sig1);
		ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
		a1x0 = ppx0[abs1];
		a1x1 = ppx1[abs1];
		a1l0 = _mm_xor_si128(ppl0[abs1], ssgn);
		a1l1 = ppl1[abs1];
		smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
		if (max == len0) {
			eca_add_mma(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					e1x0, e1x1, e1l0, e1l1);
		} else {
			*rx0 = e1x0;
			*rx1 = e1x1;
			*rl0 = e1l0;
			*rl1 = e1l1;
		}
	}

	if (max == len2) {
		smu_get_flg(dg2, len2, msk, abs0, sig0);
		ssgn = _mm_set_epi64x(0x0, sig0 ^ l0neg);
		a0x0 = qqx0[abs0];
		a0x1 = qqx1[abs0];
		a0l0 = _mm_xor_si128(qql0[abs0], ssgn);
		a0l1 = qql1[abs0];
		if (max == len1 || max == len0) {
			eca_add_mix(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					rz0, rz1, a0x0, a0x1, a0l0, a0l1);
		} else {
			*rx0 = a0x0;
			*rx1 = a0x1;
			*rl0 = a0l0;
			*rl1 = a0l1;
		}
	}

	if (max == len3) {
		smu_get_flg(dg3, len3, msk, abs1, sig1);
		ssgn = _mm_set_epi64x(0x0, sig1 ^ l1neg);
		a1x0 = qqx0[abs1];
		a1x1 = qqx1[abs1];
		a1l0 = _mm_xor_si128(qql0[abs1], ssgn);
		a1l1 = qql1[abs1];
		smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
		if (max == len2 || max == len1 || max == len0) {
			eca_add_mix(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					rz0, rz1, e1x0, e1x1, e1l0, e1l1);
		} else {
			*rx0 = e1x0;
			*rx1 = e1x1;
			*rl0 = e1l0;
			*rl1 = e1l1;
		}
	}

	for (i = max - 1; i >= 0; i--) {
		/* point doubling */
		eca_dbl_ful(rx0, rx1, rl0, rl1, &rz0, &rz1,
				*rx0, *rx1, *rl0, *rl1, rz0, rz1);

		if (dg0[i]) {
			smu_get_flg(dg0, i, msk, abs0, sig0);
			ssgn = _mm_set_epi64x(0x0, sig0 ^ k0neg);
			a0x0 = ppx0[abs0];
			a0x1 = ppx1[abs0];
			a0l0 = _mm_xor_si128(ppl0[abs0], ssgn);
			a0l1 = ppl1[abs0];
			eca_add_mix(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					rz0, rz1, a0x0, a0x1, a0l0, a0l1);
		}

		if (dg1[i]) {
			smu_get_flg(dg1, i, msk, abs1, sig1);
			ssgn = _mm_set_epi64x(0x0, sig1 ^ k1neg);
			a1x0 = ppx0[abs1];
			a1x1 = ppx1[abs1];
			a1l0 = _mm_xor_si128(ppl0[abs1], ssgn);
			a1l1 = ppl1[abs1];
			smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
			eca_add_mix(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					rz0, rz1, e1x0, e1x1, e1l0, e1l1);
		}

		if (dg2[i]) {
			smu_get_flg(dg2, i, msk, abs0, sig0);
			ssgn = _mm_set_epi64x(0x0, sig0 ^ l0neg);
			a0x0 = qqx0[abs0];
			a0x1 = qqx1[abs0];
			a0l0 = _mm_xor_si128(qql0[abs0], ssgn);
			a0l1 = qql1[abs0];
			eca_add_mix(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					rz0, rz1, a0x0, a0x1, a0l0, a0l1);
		}

		if (dg3[i]) {
			smu_get_flg(dg3, i, msk, abs1, sig1);
			ssgn = _mm_set_epi64x(0x0, sig1 ^ l1neg);
			a1x0 = qqx0[abs1];
			a1x1 = qqx1[abs1];
			a1l0 = _mm_xor_si128(qql0[abs1], ssgn);
			a1l1 = qql1[abs1];
			smu_psi_end(e1x0, e1x1, e1l0, e1l1, a1x0, a1x1, a1l0, a1l1, ONE);
			eca_add_mix(rx0, rx1, rl0, rl1, &rz0, &rz1, *rx0, *rx1, *rl0, *rl1,
					rz0, rz1, e1x0, e1x1, e1l0, e1l1);
		}
	}

	/* to afffine */
	low_inv_var(&rz0, &rz1, rz0, rz1);
	low_mul(rx0, rx1, *rx0, *rx1, rz0, rz1);
	low_mul(rl0, rl1, *rl0, *rl1, rz0, rz1);

	/* final reduction */
	low_red_127_063_000(*rx0, *rx1, ONE);
	low_red_127_063_000(*rl0, *rl1, ONE);
}
