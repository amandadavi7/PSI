/* elliptic curve arithmetic */

/* [p > p] full doubling alternative */
void eca_dbl_ful(__m128i *rx0, __m128i *rx1,
                 __m128i *rl0, __m128i *rl1,
                 __m128i *rz0, __m128i *rz1,
                 __m128i px0, __m128i px1,
                 __m128i pl0, __m128i pl1,
                 __m128i pz0, __m128i pz1) {
    /* var */
    __m128i b0, b1, c0, c1, t0, t1;
    __m128i x0, x1;

    /* point doubling */
    /* B */
    low_sqr(&b0, &b1, pz0, pz1);
    /* C */
    c0 = _mm_xor_si128(pl0, px0); c1 = _mm_xor_si128(pl1, px1);
    low_sqr(&c0, &c1, c0, c1);
    /* T */
    t0 = _mm_xor_si128(pl0, pz0); t1 = _mm_xor_si128(pl1, pz1);
    low_mul(&t0, &t1, t0, t1, pl0, pl1);
    low_mul_00u(&x0, &x1, b0, b1);
    t0 = _mm_xor_si128(t0, x0); t1 = _mm_xor_si128(t1, x1);

    /* rx */
    low_sqr(rx0, rx1, t0, t1);
    /* rz */
    low_mul(rz0, rz1, t0, t1, b0, b1);
    /* rl */
    *rl0 = _mm_xor_si128(c0, t0); *rl1 = _mm_xor_si128(c1, t1);
    *rl0 = _mm_xor_si128(*rl0, b0); *rl1 = _mm_xor_si128(*rl1, b1);
    low_mul(rl0, rl1, *rl0, *rl1, c0, c1);
    low_sqr(&x0, &x1, b0, b1);
    low_mul_27u(&x0, &x1, x0, x1);
    x0 = _mm_xor_si128(x0, *rx0); x1 = _mm_xor_si128(x1, *rx1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);
    low_mul_01u(&x0, &x1, *rz0, *rz1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);

    /* end */
    return;
}

/* [p > p] full doubling alternative */
void eca_dbl_aff(__m128i *rx0, __m128i *rx1,
                 __m128i *rl0, __m128i *rl1,
                 __m128i px0, __m128i px1,
                 __m128i pl0, __m128i pl1) {
    /* var */
    __m128i t0, t1, x0, x1;

    /* point doubling */
    /* rz */
    low_sqr(&t0, &t1, pl0, pl1);
    t0 = _mm_xor_si128(t0, pl0);
    t0 = _mm_xor_si128(t0, _mm_set_epi64x(0x1, 0x0));
    t1 = _mm_xor_si128(t1, pl1);
    /* rx */
    low_sqr(rx0, rx1, t0, t1);
    /* rl */
    low_sqr(&x0, &x1, px0, px1);
    *rl0 = _mm_xor_si128(x0, *rx0); *rl1 = _mm_xor_si128(x1, *rx1);
    low_mul(&x0, &x1, t0, t1, pl0, pl1);
    x0 = _mm_xor_si128(x0, t0); x1 = _mm_xor_si128(x1, t1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);
    low_inv_var(&t0, &t1, t0, t1);
	low_mul(rx0, rx1, *rx0, *rx1, t0, t1);
	low_mul(rl0, rl1, *rl0, *rl1, t0, t1);
	low_red_127_063_000(*rx0, *rx1, t0);
	low_red_127_063_000(*rl0, *rl1, t0);
}

/* [pp> p] full addition */
void eca_add_ful(__m128i *rx0, __m128i *rx1,
                 __m128i *rl0, __m128i *rl1,
                 __m128i *rz0, __m128i *rz1,
                 __m128i px0, __m128i px1,
                 __m128i pl0, __m128i pl1,
                 __m128i pz0, __m128i pz1,
                 __m128i qx0, __m128i qx1,
                 __m128i ql0, __m128i ql1,
                 __m128i qz0, __m128i qz1) {
    /* var */
    __m128i a0, a1, b0, b1, c0, c1, d0, d1;
    __m128i s0, s1, t0, t1;
    __m128i x0, x1;

    /* point addition */
    /* S */
    low_mul(&s0, &s1, px0, px1, qz0, qz1);
    /* T */
    low_mul(&t0, &t1, qx0, qx1, pz0, pz1);

    /* A */
    low_mul(&a0, &a1, pl0, pl1, qz0, qz1);
    low_mul(&x0, &x1, ql0, ql1, pz0, pz1);
    a0 = _mm_xor_si128(a0, x0); a1 = _mm_xor_si128(a1, x1);
    /* B */
    b0 = _mm_xor_si128(s0, t0); b1 = _mm_xor_si128(s1, t1);
    low_sqr(&b0, &b1, b0, b1);
    /* C */
    low_mul(&c0, &c1, a0, a1, t0, t1);
    /* D */
    low_mul(&d0, &d1, a0, a1, b0, b1);
    low_mul(&d0, &d1, d0, d1, qz0, qz1);

    /* rx */
    low_mul(rx0, rx1, a0, a1, s0, s1);
    low_mul(rx0, rx1, *rx0, *rx1, c0, c1);
    /* rl */
    *rl0 = _mm_xor_si128(b0, c0); *rl1 = _mm_xor_si128(b1, c1);
    low_sqr(rl0, rl1, *rl0, *rl1);
    x0 = _mm_xor_si128(pl0, pz0); x1 = _mm_xor_si128(pl1, pz1);
    low_mul(&x0, &x1, x0, x1, d0, d1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);
    /* rz */
    low_mul(rz0, rz1, d0, d1, pz0, pz1);
}

/* [pm> p] mixed addition */
void eca_add_mix(__m128i *rx0, __m128i *rx1,
                 __m128i *rl0, __m128i *rl1,
                 __m128i *rz0, __m128i *rz1,
                 __m128i px0, __m128i px1,
                 __m128i pl0, __m128i pl1,
                 __m128i pz0, __m128i pz1,
                 __m128i qx0, __m128i qx1,
                 __m128i ql0, __m128i ql1) {
    /* var */
    __m128i a0, a1, b0, b1, c0, c1, d0, d1;
    __m128i t0, t1, x0, x1;

    /* point addition */
    /* T */
    low_mul(&t0, &t1, qx0, qx1, pz0, pz1);

    /* A */
    low_mul(&a0, &a1, ql0, ql1, pz0, pz1);
    a0 = _mm_xor_si128(a0, pl0); a1 = _mm_xor_si128(a1, pl1);
    /* B */
    b0 = _mm_xor_si128(px0, t0); b1 = _mm_xor_si128(px1, t1);
    low_sqr(&b0, &b1, b0, b1);
    /* C */
    low_mul(&c0, &c1, a0, a1, t0, t1);
    /* D */
    low_mul(&d0, &d1, a0, a1, b0, b1);

    /* rx */
    low_mul(rx0, rx1, a0, a1, c0, c1);
    low_mul(rx0, rx1, *rx0, *rx1, px0, px1);
    /* rl */
    *rl0 = _mm_xor_si128(c0, b0); *rl1 = _mm_xor_si128(c1, b1);
    low_sqr(rl0, rl1, *rl0, *rl1);
    x0 = _mm_xor_si128(pl0, pz0); x1 = _mm_xor_si128(pl1, pz1);
    low_mul(&x0, &x1, x0, x1, d0, d1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);
    /* rz */
    low_mul(rz0, rz1, d0, d1, pz0, pz1);

    /* end */
    return;
}

/* [mm> p] mixed-mixed addition */
void eca_add_mma(__m128i *rx0, __m128i *rx1,
                 __m128i *rl0, __m128i *rl1,
                 __m128i *rz0, __m128i *rz1,
                 __m128i px0, __m128i px1,
                 __m128i pl0, __m128i pl1,
                 __m128i qx0, __m128i qx1,
                 __m128i ql0, __m128i ql1) {
    /* var */
    __m128i a0, a1, b0, b1, c0, c1;
    __m128i x0, x1;

    /* point addition */
    /* A */
    a0 = _mm_xor_si128(pl0, ql0); a1 = _mm_xor_si128(pl1, ql1);
    /* B */
    b0 = _mm_xor_si128(px0, qx0); b1 = _mm_xor_si128(px1, qx1);
    low_sqr(&b0, &b1, b0, b1);
    /* C */
    low_mul(&c0, &c1, a0, a1, qx0, qx1);

    /* rz */
    low_mul(rz0, rz1, a0, a1, b0, b1);
    /* rx */
    low_mul(rx0, rx1, c0, c1, a0, a1);
    low_mul(rx0, rx1, *rx0, *rx1, px0, px1);
    /* rl */
    *rl0 = _mm_xor_si128(c0, b0); *rl1 = _mm_xor_si128(c1, b1);
    low_sqr(rl0, rl1, *rl0, *rl1);
    low_mul(&x0, &x1, *rz0, *rz1, pl0, pl1);
    x0 = _mm_xor_si128(x0, *rz0); x1 = _mm_xor_si128(x1, *rz1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);

    /* end */
    return;
}

/* [mm> p] doubling-and-mixed-addition */
void eca_add_dbl(__m128i *rx0, __m128i *rx1,
                     __m128i *rl0, __m128i *rl1,
                     __m128i *rz0, __m128i *rz1,
                     __m128i px0, __m128i px1,
                     __m128i pl0, __m128i pl1,
                     __m128i qx0, __m128i qx1,
                     __m128i ql0, __m128i ql1) {
    /* var */
    __m128i d0, d1, e0, e1;
    __m128i t0, t1, a0, a1, b0, b1;
    __m128i x0, x1;
    __m128i ONE;

    /* init */
    ONE = _mm_set_epi64x(0x0, 0x1);

    /* D */
    low_sqr(&d0, &d1, pl0, pl1);
    /* E */
    e0 = _mm_xor_si128(ql0, ONE); e1 = ql1;

    /* T */
    ONE = _mm_slli_si128(ONE, 8);
    t0 = _mm_xor_si128(d0, pl0); t1 = _mm_xor_si128(d1, pl1);
    t0 = _mm_xor_si128(t0, ONE);
    /* A */
    low_sqr(&a0, &a1, px0, px1);
    x0 = _mm_xor_si128(d0, e0); x1 = _mm_xor_si128(d1, e1);
    x0 = _mm_xor_si128(x0, ONE);
    low_mul(&x0, &x1, x0, x1, t0, t1);
    a0 = _mm_xor_si128(a0, x0); a1 = _mm_xor_si128(a1, x1);
    /* B */
    b0 = _mm_xor_si128(qx0, t0); b1 = _mm_xor_si128(qx1, t1);
    low_sqr(&b0, &b1, b0, b1);

    /* rx */
    low_sqr(rx0, rx1, a0, a1);
    low_mul(rx0, rx1, *rx0, *rx1, qx0, qx1);
    /* rz */
    low_mul(rz0, rz1, a0, a1, b0, b1);
    /* rl */
    *rl0 = _mm_xor_si128(a0, b0); *rl1 = _mm_xor_si128(a1, b1);
    low_sqr(rl0, rl1, *rl0, *rl1);
    low_mul(rl0, rl1, *rl0, *rl1, t0, t1);
    low_mul(&x0, &x1, e0, e1, *rz0, *rz1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);

    /* end */
    return;
}

/* [pm> p] doubling-and-addition-subtraction */
void eca_add_sub_dbl(__m128i *rx0, __m128i *rx1,
                    __m128i *rl0, __m128i *rl1,
                    __m128i *rz0, __m128i *rz1,
                    __m128i *sx0, __m128i *sx1,
                    __m128i *sl0, __m128i *sl1,
                    __m128i *sz0, __m128i *sz1,
                    __m128i px0, __m128i px1,
                    __m128i pl0, __m128i pl1,
                    __m128i pz0, __m128i pz1,
                    __m128i qx0, __m128i qx1,
                    __m128i ql0, __m128i ql1) {
    /* var */
    __m128i d0, d1, e0, e1, f0, f1, s0, s1;
    __m128i t0, t1, a0, a1, b0, b1;
    __m128i x0, x1;
    __m128i ONE;

    /* init */
    ONE = _mm_set_epi64x(0x0, 0x1);

    /* point doubling-and-addition */
    /* D */
    low_sqr(&d0, &d1, pl0, pl1);
    /* E */
    low_sqr(&e0, &e1, pz0, pz1);
    /* S */
    low_mul(&s0, &s1, qx0, qx1, e0, e1);

    /* T */
    low_mul(&t0, &t1, pl0, pl1, pz0, pz1);
    t0 = _mm_xor_si128(t0, d0); t1 = _mm_xor_si128(t1, d1);
    low_mul_00u(&x0, &x1, e0, e1);
    t0 = _mm_xor_si128(t0, x0); t1 = _mm_xor_si128(t1, x1);
    /* A */
    low_sqr(&a0, &a1, px0, px1);
    low_mul(&a0, &a1, a0, a1, e0, e1);
    ONE = _mm_slli_si128(ONE, 8);
    x0 = _mm_xor_si128(ql0, ONE); x1 = ql1;
    low_mul(&x0, &x1, x0, x1, e0, e1);
    x0 = _mm_xor_si128(x0, d0); x1 = _mm_xor_si128(x1, d1);
    low_mul(&x0, &x1, x0, x1, t0, t1);
    a0 = _mm_xor_si128(a0, x0); a1 = _mm_xor_si128(a1, x1);
    /* B */
    b0 = _mm_xor_si128(s0, t0); b1 = _mm_xor_si128(s1, t1);
    low_sqr(&b0, &b1, b0, b1);

    /* rx */
    low_sqr(rx0, rx1, a0, a1);
    low_mul(rx0, rx1, *rx0, *rx1, s0, s1);
    /* rz */
    low_mul(&f0, &f1, b0, b1, e0, e1);
    low_mul(rz0, rz1, a0, a1, f0, f1);
    /* rl */
    *rl0 = _mm_xor_si128(a0, b0); *rl1 = _mm_xor_si128(a1, b1);
    low_sqr(rl0, rl1, *rl0, *rl1);
    low_mul(rl0, rl1, *rl0, *rl1, t0, t1);
    low_mul(&x0, &x1, ql0, ql1, *rz0, *rz1);
    *rl0 = _mm_xor_si128(*rl0, x0); *rl1 = _mm_xor_si128(*rl1, x1);

    /* init */
    ONE = _mm_set_epi64x(0x0, 0x1);

    /* A' */
    low_mul(&x0, &x1, t0, t1, e0, e1);
    a0 = _mm_xor_si128(a0, x0); a1 = _mm_xor_si128(a1, x1);
    /* sx */
    low_sqr(sx0, sx1, a0, a1);
    low_mul(sx0, sx1, *sx0, *sx1, s0, s1);
    /* sz */
    low_mul(sz0, sz1, a0, a1, f0, f1);
    /* sl */
    *sl0 = _mm_xor_si128(a0, b0); *sl1 = _mm_xor_si128(a1, b1);
    low_sqr(sl0, sl1, *sl0, *sl1);
    low_mul(sl0, sl1, *sl0, *sl1, t0, t1);
    low_mul(&x0, &x1, _mm_xor_si128(ql0, ONE), ql1, *sz0, *sz1);
    *sl0 = _mm_xor_si128(*sl0, x0); *sl1 = _mm_xor_si128(*sl1, x1);

    /* end */
    return;
}

/* [pm> p] doubling-and-addition-addition */
void eca_add_add_dbl(__m128i *rx0, __m128i *rx1,
                 __m128i *rl0, __m128i *rl1,
                 __m128i *rz0, __m128i *rz1,
                 __m128i px0, __m128i px1,
                 __m128i pl0, __m128i pl1,
                 __m128i pz0, __m128i pz1,
                 __m128i qx0, __m128i qx1,
                 __m128i ql0, __m128i ql1,
                 __m128i sx0, __m128i sx1,
                 __m128i sl0, __m128i sl1) {
    /* var */
    __m128i d0, d1, e0, e1, f0, f1, s0, s1;
    __m128i t0, t1, a0, a1, b0, b1, c0, c1;
    __m128i x0, x1;
    __m128i ONE;

    /* init */
    ONE = _mm_set_epi64x(0x0, 0x1);

    /* point doubling-and-addition */
    /* D */
    low_sqr(&d0, &d1, pl0, pl1);
    /* E */
    low_sqr(&e0, &e1, pz0, pz1);
    /* F */
    f0 = _mm_xor_si128(ql0, ONE); f1 = ql1;
    /* S */
    low_mul(&s0, &s1, qx0, qx1, e0, e1);

    /* T */
    low_mul(&t0, &t1, pl0, pl1, pz0, pz1);
    t0 = _mm_xor_si128(t0, d0); t1 = _mm_xor_si128(t1, d1);
    low_mul_00u(&x0, &x1, e0, e1);
    t0 = _mm_xor_si128(t0, x0); t1 = _mm_xor_si128(t1, x1);
    /* A */
    low_sqr(&a0, &a1, px0, px1);
    low_mul(&a0, &a1, a0, a1, e0, e1);
    x0 = _mm_xor_si128(f0, _mm_slli_si128(ONE, 8)); x1 = f1;
    low_mul(&x0, &x1, x0, x1, e0, e1);
    x0 = _mm_xor_si128(x0, d0); x1 = _mm_xor_si128(x1, d1);
    low_mul(&x0, &x1, x0, x1, t0, t1);
    a0 = _mm_xor_si128(a0, x0); a1 = _mm_xor_si128(a1, x1);
    /* B */
    b0 = _mm_xor_si128(s0, t0); b1 = _mm_xor_si128(s1, t1);
    low_sqr(&b0, &b1, b0, b1);

    /* rx */
    low_sqr(rx0, rx1, a0, a1);
    low_mul(rx0, rx1, *rx0, *rx1, s0, s1);
    /* rz */
    low_mul(rz0, rz1, a0, a1, b0, b1);
    low_mul(rz0, rz1, *rz0, *rz1, e0, e1);
    /* rl */
    *rl0 = _mm_xor_si128(a0, b0); *rl1 = _mm_xor_si128(a1, b1);
    low_sqr(rl0, rl1, *rl0, *rl1);
    low_mul(rl0, rl1, *rl0, *rl1, t0, t1);
    f0 = _mm_xor_si128(sl0, f0); f1 = _mm_xor_si128(sl1, f1);
    low_mul(&x0, &x1, f0, f1, *rz0, *rz1);
    a0 = _mm_xor_si128(*rl0, x0); a1 = _mm_xor_si128(*rl1, x1);

    /* point addition */
    /* T */
    low_mul(&t0, &t1, sx0, sx1, *rz0, *rz1);

    /* A */
    /* B */
    b0 = _mm_xor_si128(*rx0, t0); b1 = _mm_xor_si128(*rx1, t1);
    low_sqr(&b0, &b1, b0, b1);
    /* C */
    low_mul(&x0, &x1, a0, a1, t0, t1);
    /* D */
    low_mul(&d0, &d1, a0, a1, b0, b1);

    /* rx */
    low_mul(&c0, &c1, a0, a1, *rx0, *rx1);
    low_mul(rx0, rx1, x0, x1, c0, c1);
    /* rz */
    low_mul(rz0, rz1, d0, d1, *rz0, *rz1);
    /* rl */
    c0 = _mm_xor_si128(c0, b0); c1 = _mm_xor_si128(c1, b1);
    low_sqr(&c0, &c1, c0, c1);
    x0 = _mm_xor_si128(sl0, ONE); x1 = sl1;
    low_mul(&x0, &x1, x0, x1, *rz0, *rz1);
    *rl0 = _mm_xor_si128(c0, x0); *rl1 = _mm_xor_si128(c1, x1);

    /* end */
    return;
}
