/*
 * ecc-pk-crypto.cpp
 *
 *  Created on: Jul 11, 2014
 *      Author: mzohner
 */

#define GLS254
//#define DEBUG_ECC
#define COMPRESSION

#include "ecc-pk-crypto.h"
#include "api.h"
#include "dh.c"

char *ecx163 = (char *) "2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8";
char *ecy163 = (char *) "289070fb05d38ff58321f2e800536d538ccdaa3d9";
char *ecq163 = (char *) "4000000000000000000020108A2E0CC0D99F8A5EF";

char *ecx233 = (char *) "17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126";
char *ecy233 = (char *) "1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3";
char *ecq233 = (char *) "8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF";

char *ecx254 = (char *) "9D1932CB5FA5B9BF5BE5F4EB93D8712A25F2F29FCBDEC78E47E70D2DCA8C7210";
char *ecl254 = (char *) "25BE90C01E0E9B0697FBBBBFEB3A8AB40B3834B048C217C11A1764D658204447";
char *ecq254 = (char *) "200000000000000000000000000000003f1a47dedc1a1dad3cbde37cf43a8cf5";

char *ecx283 = (char *) "503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836";
char *ecy283 = (char *) "1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259";
char *ecq283 = (char *) "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61";

void reverse(uint8_t arr[], int count)
{
   uint8_t temp;
   for (int i = 0; i < count/2; ++i)
   {
      temp = arr[i];
      arr[i] = arr[count-i-1];
      arr[count-i-1] = temp;
   }
}

//Just for tests
char *s_exp = (char *) "200000000000000000000000000000003f1a47dedc1a1dad3cbde37cf43a8cf4";

void ecc_field::init(seclvl sp, uint8_t* seed) {

	miracl *mip = mirsys(sp.ecckcbits, 2);
	fparams = (ecc_fparams*) malloc(sizeof(ecc_fparams));
	secparam = sp;

	//miracl *mip=mirsys(MR_ROUNDUP(abs(163),4),16);
	char *ecp = NULL, *ecb = NULL, *ecx = ecx163, *ecy = ecy163, *ecq = ecq163;

//Just for test	-----------
	char *exp = s_exp;
//-------------------------	

	fparams->BB = new Big();
	fparams->BA = new Big();
	fparams->BP = new Big();
	
	fparams->server_exp = new Big;
	
//	cout << "BB: " << *fparams->BB << endl;	
//	cout << "BA: " << *fparams->BA << endl;
//	cout << "BP: " << *fparams->BP << endl;

// The ecq = ecq163/233/283 was put to print the order of the group
	
	#ifdef GLS254

	ecx = ecx254;	ecy = ecl254;	fparams->m = 254;	fparams->a = 127;
	fparams->b = 63;fparams->c = 0;	*fparams->BA = 0; 	fparams->secparam = LT.ecckcbits; ecq=ecq254;
	secparam.ecckcbits = 252;
        ec_ell_pre();

        #ifdef COMPRESSION
	fe_bytelen = ceil_divide(secparam.ecckcbits,8);
        #else
        fe_bytelen = ceil_divide(secparam.ecckcbits,8) * 2;
        #endif
        
	#else

	if(secparam.ecckcbits == ST.ecckcbits) {
		ecx = ecx163;	ecy = ecy163;	fparams->m = 163;	fparams->a = 7;
		fparams->b = 6;	fparams->c = 3;	*fparams->BA = 1;	fparams->secparam = ST.ecckcbits; ecq=ecq163;
	} else if(secparam.ecckcbits == MT.ecckcbits) {
		ecx = ecx233;	ecy = ecy233;	fparams->m = 233;	fparams->a = 74;
		fparams->b = 0;	fparams->c = 0;	*fparams->BA = 0;	fparams->secparam = MT.ecckcbits; ecq=ecq233;
	} else if(secparam.ecckcbits == LT.ecckcbits) {
		ecx = ecx283;	ecy = ecy283;	fparams->m = 283;	fparams->a = 12;
		fparams->b = 7; fparams->c = 5;	*fparams->BA = 0; 	fparams->secparam = LT.ecckcbits; ecq=ecq283;
	} else { //Long term security
		ecx = ecx283;	ecy = ecy283;	fparams->m = 283;	fparams->a = 12;
		fparams->b = 7;	fparams->c = 5;	*fparams->BA = 0; fparams->secparam = LT.ecckcbits; ecq=ecq283;
	}

	//For ECC, a coordinate is transferred as well as a 1/-1
	fe_bytelen = ceil_divide(secparam.ecckcbits,8) + 1;

	#endif

	//seed the miracl rnd generator
	irand((long)(*seed));

	//Change the base to read in the parameters
	mip->IOBASE = 16;
	*fparams->BB = 1;

	ecurve2_init(fparams->m, fparams->a, fparams->b, fparams->c,
			fparams->BA->getbig(), fparams->BB->getbig(), false, MR_BEST);

	fparams->X = new Big();
	fparams->Y = new Big();
	fparams->order = new Big();
	*fparams->X = ecx;
	*fparams->Y = ecy;
	*fparams->order = ecq;

//Just for tests -----------------	
	//*fparams->server_exp = exp;
//---------------------------------
	
	mip->IOBASE = 16;
//	cout << "BB: " << *fparams->BB << endl;	
//	cout << "BA: " << *fparams->BA << endl;
//	cout << "Order: " << *fparams->order << endl;
}

ecc_field::~ecc_field(){
	delete fparams->Y;
	delete fparams->X;
	delete fparams->BA;
	delete fparams->BB;
	delete fparams->BP;
	delete fparams->order;
//	delete fparams->server_exp;

	free(fparams);

	mirexit();
}

num* ecc_field::get_num() {
	return new ecc_num(this);
}

num* ecc_field::get_order() {
	return new ecc_num(this, fparams->order);
}

// Just for tests--------------------------------------
num* ecc_field::get_server_exp() {
	return new ecc_num(this, fparams->server_exp);
}
//--------------------------------------------------

num* ecc_field::get_rnd_num(uint32_t bitlen) {
	Big ele;
	if(bitlen == 0) {
		bitlen = secparam.ecckcbits;
	}
	ele = rand(bitlen, 2);
	return new ecc_num(this, &ele);
}

// Just for tests--------------------------------------
num* ecc_field::get_rnd_num_1() {
	Big ele;
	ele = (Big)1;
	return new ecc_num(this, &ele);
}
//--------------------------------------------------

fe* ecc_field::get_fe() {
	return new ecc_fe(this);
}

fe* ecc_field::get_rnd_fe(uint32_t bitlen) {
	return sample_random_point();
}

fe* ecc_field::get_generator() {
	if (fparams->m == 254) {
                exit(0);
		/*unsigned char pk[64] = { 0 };
		crypto_dh_generator(pk);
		ecc_fe *point = new ecc_fe(this);
		point->set(pk);*/
	} else {
		EC2 g = EC2(*fparams->X, *fparams->Y);
		return new ecc_fe(this, &g);
	}
}

fe* ecc_field::get_rnd_generator() {
	return sample_random_point();
}

brickexp* ecc_field::get_brick(fe* gen) {
	return new ecc_brickexp(gen, fparams);
}

uint32_t ecc_field::get_size() {
	return secparam.ecckcbits;
}

fe* ecc_field::sample_random_point() {
	if (fparams->m == 254) {
		cout << "Get generator" << endl;
	} else {
		Big bigtmp;
		EC2 point;
		uint32_t itmp = rand()%2;
		do
		{
			bigtmp = rand(secparam.symbits, 2);
			point = EC2(bigtmp, itmp);
		}
		while (point_at_infinity(point.get_point()));
		return new ecc_fe(this, &point);
	}
}

ecc_fe::ecc_fe(ecc_field* fld) {
	field = fld;
	init();
}

ecc_fe::ecc_fe(ecc_field* fld, EC2* src) {
	field = fld;
	init();
	*val = *src;
}

ecc_fe::~ecc_fe() {
	delete val;
}

void ecc_fe::set(fe* src) {
	*val = *fe2ec2(src);
}

void ecc_fe::set(unsigned char src[64]) {
	memcpy(point, src, sizeof(point));
}

EC2* ecc_fe::get_val() {
	return val;
}

void ecc_fe::set_mul(fe* a, fe* b) {
	cout << "set_mul" << endl;
	set(a);
	(*val)+=(*fe2ec2(b));
}

void ecc_fe::set_pow(fe* b, num* e) {
#ifdef GLS254
#ifdef DEBUG_ECC
	Big x, y;
	reverse(((ecc_fe *)b)->point, 32);
	reverse(((ecc_fe *)b)->point+32, 32);
        bytes_to_big (32, (const char *)((ecc_fe *)b)->point, x.getbig());
        bytes_to_big (32, (const char *)((ecc_fe *)b)->point+32, y.getbig());
	cout << "x in pow: " << x << endl;
	cout << "y in pow: " << y << endl;
	reverse(((ecc_fe *)b)->point, 32);
	reverse(((ecc_fe *)b)->point+32, 32);
	cout << "_pow: " << *num2Big(e) << endl;
#endif

	uint8_t p[64] = { 0 };
	uint8_t sk[32] = { 0 };
	big_to_bytes(32, num2Big(e)->getbig(), (char*) sk, true);
	reverse(sk, 32);
	crypto_dh_gls254prot_opt(point, ((ecc_fe *)b)->point, sk);

#ifdef DEBUG_ECC
	reverse(p, 32);
	reverse(p+32, 32);
        bytes_to_big (32, (const char*) p, x.getbig());
        bytes_to_big (32, (const char*) p+32, y.getbig());
	reverse(p, 32);
	reverse(p+32, 32);
	cout << "x in pow: " << x << endl;
	cout << "y in pow: " << y << endl;
#endif

#else
	set(b);
	(*val)*=(*num2Big(e));
#endif
}

void ecc_fe::set_div(fe* a, fe* b) {
	cout << "set_div" << endl;
	set(a);
	(*val)-=(*fe2ec2(b));
}

void ecc_fe::set_double_pow_mul(fe* b1, num* e1, fe* b2, num* e2) {
	ecurve2_mult2(num2Big(e1)->getbig(), fe2ec2(b1)->get_point(), num2Big(e2)->getbig(), fe2ec2(b2)->get_point(), val->get_point());
}

void ecc_fe::import_from_bytes(uint8_t* buf) {
#ifdef GLS254
	memcpy(point, buf, sizeof(point));
#else
	byte_to_point(val, field->fe_byte_size(), buf);
#endif
}

//export and pad all leading zeros
void ecc_fe::export_to_bytes(uint8_t* buf) {
#ifdef GLS254
	memcpy(buf, point, sizeof(point));
#else
	point_to_byte(buf, field->fe_byte_size(), val);
#endif
}

void ecc_fe::sample_fe_from_bytes(uint8_t* buf, uint32_t bytelen) {
	#ifdef GLS254

	memset(point, 0, sizeof(point));
	if (bytelen == 32) {
		reverse(buf, 32);
		crypto_dh_gls254prot_hash(point, buf);
	} else {
		cout << "Invalid scalar!" << endl;
		exit(0);
	}
#ifdef DEBUG_ECC
	Big pow;
	bytes_to_big (bytelen, (const char *)buf, pow.getbig());
	cout << "pow: " << pow << endl;
	Big x, y;
	reverse(point, 32);
	reverse(point+32, 32);
	bytes_to_big (32, (const char*) point, x.getbig());
	bytes_to_big (32, (const char*) point+32, y.getbig());
	cout << "x in sample: " << x << endl;
	cout << "y in sample: " << y << endl;
	reverse(point, 32);
	reverse(point+32, 32);
#endif
	
	#else

	EC2 point;
	Big bigtmp;
	uint8_t tmpbuf[bytelen + 1];
	memcpy(tmpbuf+1, buf, bytelen);
	bytes_to_big (bytelen, (const char*) tmpbuf, bigtmp.getbig());
	premult(bigtmp.getbig(), MAXMSGSAMPLE, bigtmp.getbig());
	for(int i = 0; i < MAXMSGSAMPLE; i++)
	{
		point = EC2(bigtmp, 0);
		if(!point_at_infinity(point.get_point())) {
			*val = 4*point;
			return;
		}
		point = EC2(bigtmp, 1);
		if(!point_at_infinity(point.get_point())) {
			*val = 4*point;
			return;
		}
		incr(bigtmp.getbig(), 1, bigtmp.getbig());
	}
	cerr << "Error while sampling point, exiting!" << endl;
	exit(0);

	#endif
}

ecc_num::ecc_num(ecc_field* fld) {
	field = fld;
	val = new Big();
}

ecc_num::ecc_num(ecc_field* fld, Big* src) {
	field = fld;
	val = new Big();
	copy(src->getbig(), val->getbig());
}

ecc_num::~ecc_num() {
	delete val;
}

Big* ecc_num::get_val() {
	return val;
}

void ecc_num::set(num* src) {
	copy(((ecc_num*) src)->get_val()->getbig(), val->getbig());
}

void ecc_num::set_si(int32_t src) {
	convert(src, val->getbig());
}

void ecc_num::set_add(num* a, num* b) {
	add(((ecc_num*) a)->get_val()->getbig(), ((ecc_num*) b)->get_val()->getbig(), val->getbig());
}

void ecc_num::set_mul(num* a, num* b) {
	multiply(((ecc_num*) a)->get_val()->getbig(), ((ecc_num*) b)->get_val()->getbig(), val->getbig());
}

void ecc_num::set_inv(num** x, num* n, num** w, uint32_t qtd) {
	Big *x1 = new Big[qtd];
	Big *w1 = new Big[qtd];

	for(int i = 0; i<qtd; i++){
	    x1[i] = *((ecc_num*) x[i])->get_val();
	}

	multi_inverse(qtd, x1, *num2Big(n), w1);
	
	for(int i = 0; i<qtd; i++){
	    w[i] = (num*) new ecc_num ( this->field, &w1[i]);
	}

	delete[] x1;
	delete[] w1;	
}

// Just for tests--------------------------------------
void ecc_num::set_inv_1(num** x, num* n, num** w) {

	Big inv = (Big)1;
        inv = inverse(*((ecc_num*)x[0])->get_val(), *num2Big(n));
	w[0] = (num*) new ecc_num (this->field, &inv);
}
//--------------------------------------------------

void ecc_num::import_from_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	bytes_to_big (field_size_bytes, (const char*) buf, val->getbig());
}

//export and pad all leading zeros
void ecc_num::export_to_bytes(uint8_t* buf, uint32_t field_size_bytes) {
	big_to_bytes ((int32_t) field_size_bytes, val->getbig(), (char*) buf, true);
}


// ecc_brickexp methods
ecc_brickexp::ecc_brickexp(fe* point, ecc_fparams* fparams) {
	Big x, y;
	fe2ec2(point)->getxy(x, y);
	ebrick2_init(&br, x.getbig(), y.getbig(), fparams->BA->getbig(), fparams->BB->getbig(),
			fparams->m, fparams->a, fparams->b, fparams->c, 8, fparams->secparam);
}

void ecc_brickexp::pow(fe* result, num* e)
{
	Big xtmp, ytmp;
	mul2_brick(&br, num2Big(e)->getbig(), xtmp.getbig(), ytmp.getbig());
	*fe2ec2(result) = EC2(xtmp, ytmp);
}

// general methods

void byte_to_point(EC2 *point, uint32_t field_size_bytes, uint8_t* pBufIdx) {
	uint32_t itmp;
	Big bigtmp;
	itmp = (uint32_t) (pBufIdx[0]);

	bytes_to_big(field_size_bytes-1, (const char*) (pBufIdx + 1), bigtmp.getbig());
	*point = EC2(bigtmp, itmp);
}

void point_to_byte(uint8_t* pBufIdx, uint32_t field_size_bytes, EC2* point) {
	uint32_t itmp;
	Big bigtmp;
	//compress to x-point and y-bit and convert to byte array
	itmp = point->get(bigtmp);

	//first store the y-bit
	pBufIdx[0] = (uint8_t) (itmp & 0x01);

	//then store the x-coordinate (sec-param/8 byte size)
	big_to_bytes(field_size_bytes-1, bigtmp.getbig(), (char*) pBufIdx+1, true);

}
