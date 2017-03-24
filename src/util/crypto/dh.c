/* inc */
#include "lib.h"
#include "api.h"

#include "ffa.h"
#include "eca.h"
#include "smu.h"

int crypto_dh_generator(unsigned char *pk) {
    __m128i px0, px1, pl0, pl1;
   px0 = _mm_set_epi64x(0x9D1932CB5FA5B9BF, 0x5BE5F4EB93D8712A);
   px1 = _mm_set_epi64x(0x25F2F29FCBDEC78E, 0x47E70D2DCA8C7210);
   pl0 = _mm_set_epi64x(0x25BE90C01E0E9B06, 0x97FBBBBFEB3A8AB4);
   pl1 = _mm_set_epi64x(0x0B3834B048C217C1, 0x1A1764D658204447);
   _mm_store_si128((__m128i *) &pk[0], px0);
   _mm_store_si128((__m128i *) &pk[16], px1);
   _mm_store_si128((__m128i *) &pk[32], pl0);
   _mm_store_si128((__m128i *) &pk[48], pl1);
}

/* key pair generation */
int crypto_dh_gls254prot_opt_keypair(unsigned char *pk, unsigned char *sk) {
    /* var */
    __m128i px0, px1, pl0, pl1;
    __m128i qx0, qx1, ql0, ql1, qz0, qz1;

    /* ini */
    sk[31] = sk[31] & 0x1F;

    /* generator */
    px0 = _mm_set_epi64x(0x9D1932CB5FA5B9BF, 0x5BE5F4EB93D8712A);
    px1 = _mm_set_epi64x(0x25F2F29FCBDEC78E, 0x47E70D2DCA8C7210);
    pl0 = _mm_set_epi64x(0x25BE90C01E0E9B06, 0x97FBBBBFEB3A8AB4);
    pl1 = _mm_set_epi64x(0x0B3834B048C217C1, 0x1A1764D658204447);

    /* man */
    smu_5nf_dna_ltr(&qx0, &qx1, &ql0, &ql1, &qz0, &qz1, 
                    px0, px1, pl0, pl1, (uint64_t*)sk);

    /* end */
    _mm_store_si128((__m128i *) &pk[0], qx0);
    _mm_store_si128((__m128i *) &pk[16], qx1);
    _mm_store_si128((__m128i *) &pk[32], ql0);
    _mm_store_si128((__m128i *) &pk[48], ql1);

    return 0; 
}

/* shared secret establishment */
int crypto_dh_gls254prot_opt(unsigned char *out, unsigned char *pk, unsigned char *sk) {
    /* var */
    __m128i px0, px1, pl0, pl1;
    __m128i qx0, qx1, ql0, ql1, qz0, qz1;

    sk[31] = sk[31] & 0x1F;
    
    /* ini */
#ifdef COMPRESSION
    __m128i x20, x21;
    int tr0 = pk[23] >> 7;
    int tr1 = pk[31] >> 7;
    uint64_t u[2] = { 0 };
    uint64_t p[4];
    pk[23] &= 0x7F;
    pk[31] &= 0x7F;
    px0 = _mm_loadu_si128((__m128i *) &pk[0]);
    px1 = _mm_loadu_si128((__m128i *) &pk[16]);
    _mm_store_si128((__m128i *) p, px0);
    _mm_store_si128((__m128i *) (p+2), px1);
    //printf("decpx 0x%lX%016lX, 0x%lX%016lX\n", p[2], p[0], p[3], p[1]);
    low_sqr(&x20, &x21, px0, px1);
    low_inv(&px0, &px1, x20, x21);
    low_mul_fq1(&px0, &px1, px0, px1, _mm_set_epi64x(0x0, 0x8000001));
    x20 = _mm_xor_si128(x20, px0);
    x21 = _mm_xor_si128(x21, px1);
    x20 = _mm_xor_si128(x20, _mm_set_epi64x(0x1, 0x0));
    low_htr(&pl0, &pl1, x20, x21);
    _mm_store_si128((__m128i *)u, pl0);
    if ((u[0] & 1) != tr0) {
        pl0 = _mm_xor_si128(pl0, _mm_set_epi64x(0x0, 0x1));
    }
    if ((u[1] & 1) != tr1) {
        pl0 = _mm_xor_si128(pl0, _mm_set_epi64x(0x1, 0x0));
    }
    px0 = _mm_loadu_si128((__m128i *) &pk[0]);
    px1 = _mm_loadu_si128((__m128i *) &pk[16]);
    _mm_store_si128((__m128i *) p, px0);
    _mm_store_si128((__m128i *) (p+2), px1);
    _mm_store_si128((__m128i *) p, pl0);
    _mm_store_si128((__m128i *) (p+2), pl1);
    //printf("decpl 0x%lX%016lX, 0x%lX%016lX\n", p[2], p[0], p[3], p[1]);
#else
    px0 = _mm_loadu_si128((__m128i *) &pk[0]);
    px1 = _mm_loadu_si128((__m128i *) &pk[16]);
    pl0 = _mm_loadu_si128((__m128i *) &pk[32]);
    pl1 = _mm_loadu_si128((__m128i *) &pk[48]);
#endif
    
    /* man */
    smu_5nf_dna_ltr(&qx0, &qx1, &ql0, &ql1, &qz0, &qz1,
                    px0, px1, pl0, pl1, (uint64_t*)sk);

    /* end */
    _mm_store_si128((__m128i *) &out[0], qx0);
    _mm_store_si128((__m128i *) &out[16], qx1);
    _mm_store_si128((__m128i *) p, qx0);
    _mm_store_si128((__m128i *) (p+2), qx1);
    //printf("resux 0x%lX%016lX, 0x%lX%016lX\n", p[2], p[0], p[3], p[1]);
    _mm_store_si128((__m128i *) p, ql0);
    _mm_store_si128((__m128i *) (p+2), ql1);
    //printf("resul 0x%lX%016lX, 0x%lX%016lX\n", p[2], p[0], p[3], p[1]);
    
#ifdef COMPRESSION
    _mm_store_si128((__m128i *)u, ql0);
    out[31] |= (u[1] & 1) << 7;
#else
    _mm_store_si128((__m128i *) &out[32], ql0);
    _mm_store_si128((__m128i *) &out[48], ql1);
#endif

    return 0;
}

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
	
	low_mul(&t[Tc2][0], &t[Tc2][1], t[T1][0], t[T1][1], t[Tneg2][0], t[Tneg2][1]);
	low_mul(&t[Tc3][0], &t[Tc3][1], t[T1][0], t[T1][1], t[Tneg3][0], t[Tneg3][1]);
	
	low_inv(&t[Tci2][0], &t[Tci2][1], t[Tc2][0], t[Tc2][1]);
	low_sqr(&t[Tci2][0], &t[Tci2][1], t[Tci2][0], t[Tci2][1]);
	
	low_inv(&t[Tci3][0], &t[Tci3][1], t[Tc3][0], t[Tc3][1]);
	low_sqr(&t[Tci3][0], &t[Tci3][1], t[Tci3][0], t[Tci3][1]);
}

void ec_sw(__m128i *x0, __m128i *x1, __m128i *l0, __m128i *l1, __m128i u0, __m128i u1) {
	int j;
        __m128i _t, c0, c1, ci0, ci1, _x[3][2], _xn0, _xn1, h0, h1, ONE = _mm_set_epi64x(0x1, 0x0);
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
                        low_red_127_063_000(*x0, *x1, _t);
                        low_red_127_063_000(*l0, *l1, _t);
                        uint64_t p[4];
                        /*uint64_t p[4];
                        _mm_store_si128((__m128i *) p, *l0);
                        _mm_store_si128((__m128i *) (p+2), *l1);
                        printf("AQUI 0x%lX%016lX, 0x%lX%016lX\n", p[2], p[0], p[3], p[1]);
                        exit(0);                        */
                        break;
		}
	}
}

void ec_test() {
    unsigned long long int u[4], v[4];
    __m128i x0, x1, l0, l1, u0, u1, x20, x21, l20, l21, ONE = _mm_set_epi64x(0x1, 0x0);
    ec_ell_pre();
    for (int i = 0; i < 4; i++) {
        __builtin_ia32_rdrand64_step(&u[i]);
    }
    //u[0] = u[1] = u[2] = u[3] = 0x8000001;
    u0 = _mm_loadu_si128((__m128i *)u);
    u1 = _mm_loadu_si128((__m128i *)(u+2));
    ec_sw(&x0, &x1, &l0, &l1, u0, u1);
    /* x^2 */
    low_sqr(&x20, &x21, x0, x1);
    /* l^2 + l + a */
    low_sqr(&l20, &l21, l0, l1);
    l20 = _mm_xor_si128(l20, l0);
    l21 = _mm_xor_si128(l21, l1);
    l20 = _mm_xor_si128(l20, ONE);
    low_mul(&l20, &l21, l20, l21, x20, x21);
    low_sqr(&x20, &x21, x20, x21);
    ONE = _mm_set_epi64x(0x0, 0x8000001);
    x20 = _mm_xor_si128(x20, ONE);
    low_red_127_063_000(l20, l21, ONE);
    low_red_127_063_000(x20, x21, ONE);
    _mm_store_si128((__m128i *) u, l20);
    _mm_store_si128((__m128i *) (u+2), l21);
    _mm_store_si128((__m128i *) v, x20);
    _mm_store_si128((__m128i *) (v+2), x21);
    printf("AQUI 0x%lX%016lX, 0x%lX%016lX\n", u[2], u[0], u[3], u[1]);
    printf("AQUI 0x%lX%016lX, 0x%lX%016lX\n", v[2], v[0], v[3], v[1]);
    exit(0);
}

int crypto_dh_gls254prot_hash(unsigned char *out, unsigned char *sk) {
    __m128i x0, x1, l0, l1, u0, u1;
    sk[31] &= 0x7F;
    u0 = _mm_loadu_si128((__m128i *)sk);
    u1 = _mm_loadu_si128((__m128i *)(sk+16));
    ec_sw(&x0, &x1, &l0, &l1, u0, u1);
    _mm_store_si128((__m128i *) out, x0);
    _mm_store_si128((__m128i *) (out+16), x1);
#ifdef COMPRESSION
    uint64_t tr[2] = { 0 };
    _mm_store_si128((__m128i *) tr, l0);
    out[23] |= (tr[0] & 1) << 7;
    out[31] |= (tr[1] & 1) << 7;
    uint64_t p[4];
    _mm_store_si128((__m128i *) p, x0);
    _mm_store_si128((__m128i *) (p+2), x1);
    //printf("hashx 0x%lX%016lX, 0x%lX%016lX\n", p[2], p[0], p[3], p[1]);
    _mm_store_si128((__m128i *) p, l0);
    _mm_store_si128((__m128i *) (p+2), l1);
     //printf("hashl 0x%lX%016lX, 0x%lX%016lX tr %d %X\n", p[2], p[0], p[3], p[1], tr[1] & 1, out[31]);
#else
    _mm_store_si128((__m128i *) &out[32], l0);
    _mm_store_si128((__m128i *) &out[48], l1);
#endif
}
