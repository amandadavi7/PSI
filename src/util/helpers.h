/*
 * helpers.h
 *
 *  Created on: May 20, 2015
 *      Author: mzohner
 *  Last modification: Dezember 12, 2017
 * 	Author: Amanda
 */

#ifndef HELPERS_H_
#define HELPERS_H_

#include "socket.h"
#include "typedefs.h"
#include "crypto/crypto.h"
#include "thread.h"
#include <glib.h>

#include "../util/cuckoo_filter/cuckoofilter.h"
#include "../util/cuckoo_filter/itemfilter.h"
#include "../util/cuckoo_filter/singletable.h"

//#define DEBUG_DH                     // Print when the operations are starting, like "Encryption assymetric task started..."
//#define TIMING_OPERATION             // Print the time of the operation in the protocols, like the time waste to send and receive data or to do the hash
//#define PRINT_EXP                    // Print the exponents and in some cases the points of the curve. It is not print the points correctly
//#define TIMING_INDIVIDUAL_EXPO       // Print the individual time of each exponentiation
//#define PRINT_HASHES                 // Print the HASHES
//#define PRINT_INTERSECTION           // Print the values from the intersection.
//#define TIMING_DH_INVERSE            // Print the time to compute the inverser of all exponents
//#define CYCLES		       // Print the amount of cycles of the exponentiation operation
#define BASIC_PROTOCOLS             // Must be used when you want to execute the protocols 0, 1, 2 and 6. For execute the protocol 3, 4 and 5 this option must be commented
//#define MASKBYTELEN 	               // Define the size of the hash function output. Must be used just to execute the protocols 0, 1, 2, 6
//#define PREPROCESSING		       // Preprocessing phase for the Baldi and our optimized protocol. Must be used just to execute the protocols 3 and 4
//#define OPTIMIZED_PROTOCOLS   // Must be used only you want to execute the protocol 3 (Baldi with database) and 5 (our optimized protocol). Mus be used after executing at least once the preprocessing phase

#define PRECISION 4

struct element_ctx {
	uint32_t nelements;
	union {
		uint32_t fixedbytelen;
		uint32_t* varbytelens;
	};
	union {
		uint8_t* input1d;
		uint8_t** input2d;
	};
	uint32_t outbytelen;
	uint8_t* output;
	uint32_t* perm;
	uint32_t startelement;
	uint32_t endelement;

	bool hasvarbytelen;
};

struct sym_ctx {
	crypto* symcrypt;
	uint8_t* keydata;
};

struct asym_ctx {
	num* exponent;
	pk_crypto* field;
	bool sample;
	num** v_exponent;
	num* orde;
};

struct task_ctx {
	element_ctx eles;
	union {
		sym_ctx sctx;
		asym_ctx actx;
	};
};

struct snd_ctx {
	uint8_t* snd_buf;
	uint32_t snd_bytes;
	CSocket* sock;
};

//return cycle counts as a 64-bit unsigned integer
static unsigned long cycles(void) {
	unsigned int hi, lo;
	asm (
		"cpuid\n\t"/*serialize*/
		"rdtsc\n\t"/*read the clock*/
		"mov %%edx, %0\n\t"
		"mov %%eax, %1\n\t"
		: "=r" (hi), "=r" (lo):: "%rax", "%rbx", "%rcx", "%rdx"
	);
	return ((unsigned long long) lo) | (((unsigned long long) hi) << 32);
}

static uint32_t exchange_information(uint32_t myneles, uint32_t mybytelen, uint32_t mysecparam, uint32_t mynthreads,
		uint32_t myprotocol, CSocket& sock) {

	uint32_t pneles, pbytelen, psecparam, pnthreads, pprotocol;
	//Send own values
	sock.Send(&myneles, sizeof(uint32_t));
	sock.Send(&mybytelen, sizeof(uint32_t));
	sock.Send(&mysecparam, sizeof(uint32_t));
	sock.Send(&mynthreads, sizeof(uint32_t));
	sock.Send(&myprotocol, sizeof(uint32_t));

	//Receive partner values
	sock.Receive(&pneles, sizeof(uint32_t));
	sock.Receive(&pbytelen, sizeof(uint32_t));
	sock.Receive(&psecparam, sizeof(uint32_t));
	sock.Receive(&pnthreads, sizeof(uint32_t));
	sock.Receive(&pprotocol, sizeof(uint32_t));

	//Assert
	assert(mybytelen == pbytelen);
	assert(mysecparam == psecparam);
	assert(mynthreads == pnthreads);
	assert(myprotocol == pprotocol);

	return pneles;
}

static void create_result_from_matches_var_bitlen(uint8_t*** result, uint32_t** resbytelens, uint32_t* inbytelens,
		uint8_t** inputs, uint32_t* matches, uint32_t intersect_size) {
	uint32_t i;

	*result = (uint8_t**) malloc(sizeof(uint8_t*) * intersect_size);
	*resbytelens = (uint32_t*) malloc(sizeof(uint32_t) * intersect_size);

	std::sort(matches, matches+intersect_size);

	for(i = 0; i < intersect_size; i++) {
//		cout << "matches[" << i << "]: " << matches[i]  << '\n';
		(*resbytelens)[i] = inbytelens[matches[i]];
		(*result)[i] = (uint8_t*) malloc((*resbytelens)[i]);
		memcpy((*result)[i], inputs[matches[i]], (*resbytelens)[i]);
	}
}

static void create_result_from_matches_fixed_bitlen(uint8_t** result, uint32_t inbytelen, uint8_t* inputs, uint32_t* matches,
		uint32_t intersect_size) {
	uint32_t i;
	*result = (uint8_t*) malloc(inbytelen * intersect_size);

	std::sort(matches, matches+intersect_size);

	for(i = 0; i < intersect_size; i++) {
		memcpy(*(result) + i * inbytelen, inputs + matches[i] * inbytelen, inbytelen);
	}
}

static void *asym_encrypt(void* context) {
#ifdef DEBUG_DH
	cout << "------------------------------------------------------------" << '\n';
	cout << "****Encryption assymetric task started with equal alpha (asym_encrypt)****" << '\n';
#endif
	pk_crypto* field = ((task_ctx*) context)->actx.field;
	element_ctx electx = ((task_ctx*) context)->eles;
	num* exp = ((task_ctx*) context)->actx.exponent;
	fe* tmpfe = field->get_fe();
	uint8_t *inptr=electx.input1d, *outptr=electx.output;
	uint32_t i;
	timeval t_start, t_end;

#ifdef CYCLES
	uint64_t sum_cycle = 0;
#endif

	for(i = 0; i < electx.nelements; i++, inptr+=electx.fixedbytelen, outptr+=electx.outbytelen) {
		if(((task_ctx*) context)->actx.sample) {
			tmpfe->sample_fe_from_bytes(inptr, electx.fixedbytelen);
		} else {
			tmpfe->import_from_bytes(inptr);
		}

#ifdef PRINT_EXP
		cout <<"Exponent and the points of the curve before exponentiation"<<'\n';
		exp->print();
		tmpfe->print();
#endif

#ifdef CYCLES
		uint64_t cycle = cycles();
#endif

#ifdef TIMING_INDIVIDUAL_EXPO
	gettimeofday(&t_start, NULL);
#endif

		tmpfe->set_pow(tmpfe, exp);

#ifdef TIMING_INDIVIDUAL_EXPO
		gettimeofday(&t_end, NULL);
		cout << "Time for the exponentiation " << i << ":\t" << fixed << std::setprecision(5) << getMillies(t_start, t_end) << " ms" << '\n';
#endif

#ifdef CYCLES
		cycle = cycles() - cycle;
		sum_cycle = sum_cycle + cycle;
#endif

#ifdef PRINT_EXP

		cout <<"Exponent and the points of the curve after exponentiation"<<'\n';
		tmpfe->print();
		exp->print();
#endif
		tmpfe->export_to_bytes(outptr);

	}

#ifdef CYCLES
	cout << "Cycle (sum_cycle/qtd of elements): " << sum_cycle/electx.nelements << '\n';
#endif

#ifdef DEBUG_DH
	cout << "****Encryption assymetric task finished with equal alpha****" << '\n';
	cout << "------------------------------------------------------------"<<'\n';
#endif
	delete tmpfe;
	return 0;
}

static void *asym_encrypt_d(void* context) {
#ifdef DEBUG_DH
	cout << "------------------------------------------------------------"<<'\n';
	cout << "*****Encryption assymetric task started with different alpha (asym_encrypt_d)****" << '\n';
#endif
	pk_crypto* field = ((task_ctx*) context)->actx.field;
	element_ctx electx = ((task_ctx*) context)->eles;
	num** e = (num**)malloc(electx.nelements*sizeof(num*));
	num* tmpnum = field->get_num();
	fe* tmpfe = field->get_fe();
	uint8_t *inptr=electx.input1d, *outptr=electx.output;
	uint32_t i;

	timeval t_start, t_end;

#ifdef CYCLES
	uint64_t sum_cycle = 0;
#endif

#ifdef PRINT_EXP
	cout <<"Exponent before of the inverse: "<<'\n';
#endif
	for (int i=0; i < electx.nelements; i++){
		e[i] = ((task_ctx*) context)->actx.v_exponent[i];
#ifdef PRINT_EXP
		e[i]->print();
#endif
	}

#ifdef PRINT_EXP
	cout <<'\n';
#endif

	for(i = 0; i < electx.nelements; i++, inptr+=electx.fixedbytelen, outptr+=electx.outbytelen) {
		if(((task_ctx*) context)->actx.sample) {
			tmpfe->sample_fe_from_bytes(inptr, electx.fixedbytelen);
		} else {
			tmpfe->import_from_bytes(inptr);
		}

#ifdef PRINT_EXP
		cout <<"Exponent and the points of the curve before exponentiation: "<<'\n';
		e[i]->print();
		tmpfe->print();
#endif

#ifdef CYCLES
		uint64_t cycle = cycles();
#endif

#ifdef TIMING_INDIVIDUAL_EXPO
		gettimeofday(&t_start, NULL);
#endif
 		tmpfe->set_pow(tmpfe, e[i]);

#ifdef TIMING_INDIVIDUAL_EXPO
		gettimeofday(&t_end, NULL);
		cout << "Time for the exponentiation " << i << ":\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end) << " ms" << '\n';
#endif

#ifdef CYCLES
		cycle = cycles() - cycle;
		sum_cycle = sum_cycle + cycle;
#endif

#ifdef PRINT_EXP
		cout <<"Exponent and the points of the curve after exponentiation: "<<'\n';
		e[i]->print();
		tmpfe->print();
#endif
		tmpfe->export_to_bytes(outptr);
	}

#ifdef CYCLES
	cout << "Cycle (sum_cycle/qtd of elements): " << sum_cycle/electx.nelements << '\n';;
#endif

#ifdef DEBUG_DH
	cout << "****Encryption assymetric task finished with different alpha****" << '\n';
	cout << "------------------------------------------------------------"<<'\n';
#endif

	free(e);
	delete tmpnum;
	delete tmpfe;

	return 0;
}

static void *asym_encrypt_inverse(void* context) {
#ifdef DEBUG_DH
	cout << "------------------------------------------------------------"<<'\n';
	cout << "*****Encryption assymetric task started with the inverse (asym_encrypt_inverse)****" << '\n';
#endif
	pk_crypto* field = ((task_ctx*) context)->actx.field;
	element_ctx electx = ((task_ctx*) context)->eles;
	num** inv = (num**)malloc(electx.nelements*sizeof(num*));
	num** exp = (num**)malloc(electx.nelements*sizeof(num*));
	num* tmpor = field->get_order();
	num* tmpnum = field->get_num();
	fe* tmpfe = field->get_fe();
	uint8_t *inptr=electx.input1d, *outptr=electx.output;
	uint32_t i;

	timeval t_start, t_end;

#ifdef CYCLES
	uint64_t sum_cycle = 0;
#endif

#ifdef PRINT_EXP
	cout <<"Exponent before of the inverse: "<<'\n';
#endif
	for (int i=0; i < electx.nelements;i++){
		exp[i] = ((task_ctx*) context)->actx.v_exponent[i];

#ifdef PRINT_EXP
		exp[i]->print();
#endif
	}

#ifdef PRINT_EXP
	cout<<'\n';
#endif

#ifdef TIMING_DH_INVERSE
	gettimeofday(&t_start, NULL);
#endif
	tmpnum->set_inv(exp,tmpor,inv, electx.nelements);

#ifdef TIMING_DH_INVERSE
	gettimeofday(&t_end, NULL);
	cout << "Time to computation the inverse: \t" << fixed << std::setprecision(2) << getMillies(t_start, t_end) << " ms" << '\n';
#endif

	for(i = 0; i < electx.nelements; i++, inptr+=electx.fixedbytelen, outptr+=electx.outbytelen) {
		if(((task_ctx*) context)->actx.sample) {
			tmpfe->sample_fe_from_bytes(inptr, electx.fixedbytelen);
		} else {
			tmpfe->import_from_bytes(inptr);
		}

#ifdef PRINT_EXP
		cout <<"Exponent and the points of the curve before exponentiation"<<'\n';
		inv[i]->print();
		tmpfe->print();
#endif

#ifdef CYCLES
		uint64_t cycle = cycles();
#endif

#ifdef TIMING_INDIVIDUAL_EXPO
		gettimeofday(&t_start, NULL);
#endif
		tmpfe->set_pow(tmpfe, inv[i]);

#ifdef TIMING_INDIVIDUAL_EXPO
		gettimeofday(&t_end, NULL);
		cout << "Time for the exponentiation (inverse) " << i << ":\t" << fixed << std::setprecision(2) << getMillies(t_start, t_end) << " ms" << '\n';
#endif

#ifdef CYCLES
 		cycle = cycles() - cycle;
		sum_cycle = sum_cycle + cycle;
#endif

#ifdef PRINT_EXP
		cout << "Exponent and the points of the curve after exponentiation"<<'\n';
		inv[i]->print();
		tmpfe->print();
#endif
		tmpfe->export_to_bytes(outptr);
	}

#ifdef CYCLES
	cout << "Cycle (sum_cycle/qtd of elements): " << sum_cycle/electx.nelements << '\n';;
#endif

#ifdef DEBUG_DH
	cout << "****Encryption assymetric task finished with the inverse****" << '\n';
	cout << "------------------------------------------------------------"<<'\n';
#endif
	for(i=0;i<electx.nelements;i++)
		  delete inv[i];
	delete tmpor;
	delete tmpnum;
	delete tmpfe;

	free(exp);
	free(inv);

	return 0;
}

static void *sym_encrypt(void* context) {
#ifdef DEBUG_DH
	cout << "Hashing symmetric thread started..." << '\n';
#endif
	sym_ctx hdata = ((task_ctx*) context)->sctx;
	element_ctx electx = ((task_ctx*) context)->eles;

	crypto* crypt_env = hdata.symcrypt;

	AES_KEY_CTX aes_key;
	//cout << "initializing key" << '\n';
	crypt_env->init_aes_key(&aes_key, hdata.keydata);
	//cout << "initialized key" << '\n';

	uint8_t* aes_buf = (uint8_t*) malloc(AES_BYTES);
	uint32_t* perm = electx.perm;
	uint32_t i;

	if(electx.hasvarbytelen) {
		uint8_t **inptr = electx.input2d;
		for(i = electx.startelement; i < electx.endelement; i++) {
			//crypt_env->hash(electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr[i], electx.varbytelens[i]);
			//cout << "encrypting i = " << i << ", perm = " << perm [i] << ", outbytelen = " << electx.outbytelen << '\n';
			crypt_env->encrypt(&aes_key, aes_buf, inptr[i], electx.varbytelens[i]);
			memcpy(electx.output+perm[i]*electx.outbytelen, aes_buf, electx.outbytelen);
		}
	} else {
		uint8_t *inptr = electx.input1d;
		for(i = electx.startelement; i < electx.endelement; i++, inptr+=electx.fixedbytelen) {
			//crypt_env->hash(&aes_key, electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr, electx.fixedbytelen);
			crypt_env->encrypt(&aes_key, aes_buf, inptr, electx.fixedbytelen);
			memcpy(electx.output+perm[i]*electx.outbytelen, aes_buf, electx.outbytelen);
		}
	}

	//cout << "Returning" << '\n';
	//free(aes_buf);
	return 0;
}

static void *psi_hashing_function(void* context) {
#ifdef DEBUG_DH
	cout << "Hashing thread started..." << '\n';
#endif
	sym_ctx hdata = ((task_ctx*) context)->sctx;
	element_ctx electx = ((task_ctx*) context)->eles;

	crypto* crypt_env = hdata.symcrypt;

	uint32_t* perm = electx.perm;
	uint32_t i;
	uint8_t* tmphashbuf = (uint8_t*) malloc(crypt_env->get_hash_bytes());

	if(electx.hasvarbytelen) {
		uint8_t **inptr = electx.input2d;
		for(i = electx.startelement; i < electx.endelement; i++) {
			crypt_env->hash(electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr[i], electx.varbytelens[i], tmphashbuf);
		}
	} else {
		uint8_t *inptr = electx.input1d;
		for(i = electx.startelement; i < electx.endelement; i++, inptr+=electx.fixedbytelen) {
			crypt_env->hash(electx.output+perm[i]*electx.outbytelen, electx.outbytelen, inptr, electx.fixedbytelen, tmphashbuf);
		}
	}
	free(tmphashbuf);
	return 0;
}

static void *send_data(void* context) {
	snd_ctx *ctx = (snd_ctx*) context;
	ctx->sock->Send(ctx->snd_buf, ctx->snd_bytes);
	return 0;
}

//Apparently OT+Hashing don't use this function
static void snd_and_rcv(uint8_t* snd_buf, uint32_t snd_bytes, uint8_t* rcv_buf, uint32_t rcv_bytes, CSocket* sock) {
	pthread_t snd_task;
	bool created, joined;
	snd_ctx ctx;
	//Start new sender thread
	ctx.sock = sock;
	ctx.snd_buf = snd_buf;
	ctx.snd_bytes = snd_bytes;
	created = !pthread_create(&snd_task, NULL, send_data, (void*) &(ctx));

	//receive
	sock->Receive(rcv_buf, rcv_bytes);
	assert(created);

	joined = !pthread_join(snd_task, NULL);
	assert(joined);
}

static void run_task(uint32_t nthreads, task_ctx context, void* (*func)(void*) ) {
	task_ctx* contexts = (task_ctx*) malloc(sizeof(task_ctx) * nthreads);
	pthread_t* threads = (pthread_t*) malloc(sizeof(pthread_t) * nthreads);
	uint32_t i, neles_thread, electr, neles_cur;
	bool created, joined;

	neles_thread = ceil_divide(context.eles.nelements, nthreads);
	for(i = 0, electr = 0; i < nthreads; i++) {
		neles_cur = min(context.eles.nelements - electr, neles_thread);
		memcpy(contexts + i, &context, sizeof(task_ctx));
		contexts[i].eles.nelements = neles_cur;
		contexts[i].eles.startelement = electr;
		contexts[i].eles.endelement = electr + neles_cur;
		electr += neles_cur;
	}

	for(i = 0; i < nthreads; i++) {
		created = !pthread_create(threads + i, NULL, func, (void*) &(contexts[i]));
	}

	assert(created);http://www.globo.com/

	for(i = 0; i < nthreads; i++) {
		joined = !pthread_join(threads[i], NULL);
	}

	assert(joined);

	free(threads);
	free(contexts);
}

static uint32_t find_intersection(uint8_t* hashes, uint32_t neles, uint8_t* phashes, uint32_t pneles,
		uint32_t hashbytelen, uint32_t* perm, uint32_t* matches) {

 /*This is return falso positive elements

	uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint64_t *tmpval, tmpkey = 0;
	uint32_t mapbytelen = min((uint32_t) hashbytelen, (uint32_t) sizeof(uint64_t));
	uint32_t size_intersect, i, intersect_ctr=0, inserted=0;
	uint32_t count = hashbytelen * neles, aux;

//	cout << "hashbytelen: " <<hashbytelen << "\n" << "mapbytelen: " <<hashbytelen << "\n";

	for(i = 0; i < neles; i++) {
		invperm[perm[i]] = i;
	}

#ifdef PRINT_HASHES
	cout << "c_hashes within of find_intersection" << '\n';
	count =  hashbytelen * neles;
	aux = hashbytelen;
	for(i = 0; i<count ; i++){
		if (i == aux){
		    aux = aux + hashbytelen;
		    cout<< '\n';
		}
		printf("%02x", (hashes[i]));
	}
	cout << '\n';

	cout << "server_database within of find_intersection" << '\n';

	count =  hashbytelen * pneles;
	aux = hashbytelen;
	for(i = 0; i<count ; i++){
		if (i == aux){
		    aux = aux + hashbytelen;
		    cout<< '\n';
		}
		printf("%02x", (phashes[i]));
	}
	cout << '\n';
#endif

	GHashTable *map= g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
	for(i = 0; i < neles; i++) {
		memcpy(&tmpkey, hashes + i*hashbytelen, mapbytelen);
		if(g_hash_table_insert(map,(void*) &tmpkey, &(invperm[i]))){
		      inserted++;
		}
	}

	for(i = 0, intersect_ctr = 0; i < pneles; i++) {
		memcpy(&tmpkey, phashes+ i*hashbytelen, mapbytelen);
		if(g_hash_table_lookup_extended(map, (void*) &tmpkey, NULL, (void**) &tmpval)) {
			matches[intersect_ctr] = tmpval[0];
			intersect_ctr++;
//			cout << "Intersect" << intersect_ctr << "\n";
			assert(intersect_ctr <= min(neles, pneles));
		}
	}

	size_intersect = intersect_ctr;

	free(invperm);
	return size_intersect;
*/
//Cuckoo filter is slower than the approach above
	uint32_t size_intersect, i, j, intersect_size_aux=0, intersect_ctr=0;

	cuckoofilter::CuckooFilter<ItemFilter, 32> filter_hashes(neles);

	ItemFilter** buffer_filter_c = new ItemFilter*[neles];

	for(i=0;i<neles;i++)
		 buffer_filter_c[i] = new ItemFilter(&hashes[i*hashbytelen], hashbytelen);

	for(i=0;i<neles;i++) {
		cuckoofilter::Status status = filter_hashes.AddPSI(buffer_filter_c[i]->GetHashFilter(hashbytelen));
		if ( status != cuckoofilter::Ok)
			 cout<< "Problem in add here: \n"<< status<< "\n";
	}

	for(i=0;i<neles;i++)
		delete buffer_filter_c[i];

	delete[] buffer_filter_c;

//	std::cout << "Info: "<< filter_hashes.Info() << std::endl;

	ItemFilter** buffer_filter_s = new ItemFilter*[pneles];

	for(i=0;i<pneles;i++)
	      buffer_filter_s[i] = new ItemFilter(&phashes[i*hashbytelen],hashbytelen);

	for (i = 0; i < pneles; i++) {
	      if (filter_hashes.ContainPSI(buffer_filter_s[i]->GetHashFilter(hashbytelen)) == cuckoofilter::Ok){
		    matches[intersect_ctr] = i;
		    intersect_ctr++;
		    intersect_size_aux++;
	      }
	}

	size_intersect = intersect_size_aux;

	for(i=0;i<pneles;i++)
	      delete buffer_filter_s[i];

	delete[] buffer_filter_s;

	return size_intersect;
}
#endif /* HELPERS_H_*/
