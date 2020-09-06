/*
 * dh_generate_couting_quotient_filter.cpp
 *
 *  Created on: May 30, 2018
 *      Author: Amanda
 */

#include "dh_generate_counting_quotient_filter.h"

void dhgenerate_counting_quotient_filter(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;

	dhgenerate_counting_quotient_filter(role, neles, pneles, ectx, crypt_env, sock, ntasks, cardinality, ftype);

}

void dhgenerate_counting_quotient_filter(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;

	dhgenerate_counting_quotient_filter(role, neles, pneles, ectx, crypt_env, sock, ntasks, cardinality, ftype);

}

void dhgenerate_counting_quotient_filter(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, bool cardinality, field_type ftype) {

	uint32_t hash_bytes = crypt_env->get_hash_bytes(), fe_bytes, num_byte, aux, count;
	pk_crypto* field = crypt_env->gen_field(ftype);
	num* exponent;
	CSocket* tmpsock = sock;
	fe_bytes = field->fe_byte_size();
	num_byte = field->num_byte_size();
	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint8_t* s_encrypted_eles, *f_s_hashes, *client_waiting, *server_finish, *server_data_rcv_metadata, *server_data_rcv_remainder, *snd_filter;
	uint8_t buffer[num_byte];
	uint64_t i, qbits, nhashbits, nslots;
    __uint128_t hash_s;
	uint64_t key_count = 1;

	FILE* arq, *arq_key;

	QF qf;

	timeval t_start, t_end, t_start1, t_end1, t_start2, t_end2;

	cout << ".....................COUNTING QUOTIENT FILTER.........................." << endl;

	if(role == SERVER){

#ifndef SEND_CQF

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start1, NULL);
	      gettimeofday(&t_start, NULL);
          gettimeofday(&t_start2, NULL);
#endif
	      crypt_env->gen_rnd_perm(perm, neles);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the random permutation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif
	      f_s_hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

	      /* Hash elements */
	      ectx.eles.output = f_s_hashes;
	      ectx.eles.nelements = neles;
	      ectx.eles.outbytelen = hash_bytes;
	      ectx.eles.perm = perm;
	      ectx.sctx.symcrypt = crypt_env;

#ifdef DEBUG
	      cout << "Hashing elements" << endl;
#endif

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif

	      run_task(ntasks, ectx, psi_hashing_function);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the first hash (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

#ifdef PRINT_HASHES
	      cout << "First server hash" << endl;
	      count =  neles * hash_bytes;
	      aux = hash_bytes;
	      for(i = 0; i<count; i++){
		    if (i == aux){
			  aux = aux + hash_bytes;
			  cout<< endl;
		    }
		    printf("%02x", (f_s_hashes[i]));
	      }
	      cout << endl;
#endif

#ifdef NEW_KEY
	      exponent = field->get_rnd_num();
	      exponent->export_to_bytes(buffer, num_byte);

	      arq_key = fopen("key.txt", "wb");

	      if(arq_key == NULL){
             cout << "Key opening problem" << endl;
             exit(1);
	      }

	      uint32_t qtdkey = fwrite(buffer, 1, num_byte, arq_key);

	      if(qtdkey != num_byte)
             cout<<"Key writting problem" << endl;

	      fclose(arq_key);
#endif

#ifndef NEW_KEY
	      arq_key = fopen("key.txt", "rb");
	      if(arq_key == NULL){
		    cout << "Key opening problem" << endl;
		    exit(1);
	      }

	      uint32_t qtdkey_r;

	      qtdkey_r = fread(buffer, 1, num_byte, arq_key);

	      exponent = new ecc_num((ecc_field*)field);
	      exponent->import_from_bytes(buffer, num_byte);

	      if (qtdkey_r !=num_byte){
		      cout << "Key reading problem" << endl;
		      cout << "qtdkey_r value: " << qtdkey_r << endl;
	      }

	      fclose(arq_key);

#endif
          s_encrypted_eles = (uint8_t*) malloc(sizeof(uint8_t) * neles * fe_bytes);

	      /* Encrypt elements */
	      ectx.eles.input1d = f_s_hashes;
	      ectx.eles.fixedbytelen = hash_bytes;
	      ectx.eles.nelements = neles;
	      ectx.eles.outbytelen = fe_bytes;
	      ectx.eles.output = s_encrypted_eles;
	      ectx.actx.exponent = exponent;
	      ectx.eles.hasvarbytelen = false;
	      ectx.actx.field = field;
	      ectx.actx.sample = true;

#ifdef DEBUG
	      cout << "Hash and encrypting my elements" << endl;
#endif

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
          
	      run_task(ntasks, ectx, asym_encrypt_var);

   	      delete exponent;

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the first exponentiation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

          free(f_s_hashes);
          free(perm);
          
#ifndef ADD

          qbits = ceil_log2(neles);

          if(neles >= (1ULL << qbits))
            qbits = qbits + 1;

          nhashbits = qbits + 54;
  	      nslots = (1ULL << qbits);

	      if (!qf_malloc(&qf, nslots, nhashbits, 0, QF_HASH_DEFAULT, 0)) {
            fprintf(stderr, "Can't allocate CQF.\n");
		    abort();
	      }

	      printf("\nFilter informations: \n");

	      qf_set_auto_resize(&qf, true);
	      qf_dump_metadata(&qf);

	      printf("Load factor before insertion: %lf\n", load_factor(&qf));

#endif
          char filename[] = "cqf.cqf";

#ifdef ADD

#ifdef TIMING_OPERATION
          gettimeofday(&t_start2, NULL);
#endif

	      fprintf(stdout, "Reading the CQF from disk.\n");
	      qf_deserialize(&qf, filename);

#ifdef TIMING_OPERATION
          gettimeofday(&t_end2, NULL);
          cout << "Time for the server read the CQF from the file: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start2, t_end2) << "ms" << endl;
#endif

	      printf("\nFilter informations: \n");
	      qf_dump_metadata(&qf);
	      printf("Size in megabytes: %lf\n", (double) qf.metadata->total_size_in_bytes_plus_metadada/1024/1024);
	      printf("Size in bytes: %lu\n\n", qf.metadata->total_size_in_bytes_plus_metadada);
#endif
	      /* Insert keys in the CQF */
	      for (i = 0; i < neles; i++) {
		     hash_s = MurmurHash3_x64_128_1(&s_encrypted_eles[i*fe_bytes],fe_bytes,0);              
                int ret = qf_insert(&qf, hash_s, 0, key_count, QF_NO_LOCK);
                if (ret < 0) {
                    fprintf(stderr, "failed insertion for key: %lx %lx %d.\n", (uint64_t)(hash_s >> 64), (uint64_t)hash_s, 50);
                    if (ret == QF_NO_SPACE)
                        fprintf(stderr, "CQF is full.\n");
                    else if (ret == QF_COULDNT_LOCK)
                        fprintf(stderr, "TRY_ONCE_LOCK failed.\n");
                    else
                        fprintf(stderr, "Does not recognise return value.\n");
                        abort();
                }
	      }
	      
          free(s_encrypted_eles);

	      qf_dump_metadata(&qf);

	      printf("Load factor after insert: %lf\n", load_factor(&qf));
	      printf("Size in megabytes: %lf\n", (double) qf.metadata->total_size_in_bytes_plus_metadada/1024/1024);
	      printf("Size in bytes: %lu\n\n", qf.metadata->total_size_in_bytes_plus_metadada);

#ifndef GENERATE_AND_SEND

#ifdef TIMING_OPERATION
          gettimeofday(&t_start2, NULL);
#endif

          fprintf(stdout, "Serializing the CQF to disk.\n");

	      uint64_t total_size = qf_serialize(&qf, filename);

	      if (total_size < sizeof(qfmetadata) + qf.metadata->total_size_in_bytes) {
       	     fprintf(stderr, "CQF serialization failed.\n");
             abort();
	      }


#ifdef TIMING_OPERATION
          gettimeofday(&t_end2, NULL);
          cout << "Time for the server write the CQF in the file: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start2, t_end2) << "ms" << endl;
#endif

// I need to send something to the client for she waiting
	      uint8_t server_fin_aux = 1;
	      server_finish = &server_fin_aux;
	      snd_and_rcv(server_finish, 1, NULL, 0, tmpsock);
#endif

#endif

#ifdef SEND_CQF

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
	      gettimeofday(&t_start1, NULL);
#endif

          char filename[] = "cqf.cqf";
	      fprintf(stdout, "Reading the CQF from disk (SEND_CQF).\n");
          qf_deserialize(&qf, filename);
	      
          printf("\nFilter informations: \n");
	      qf_dump_metadata(&qf);
	      printf("Size in megabytes: %lf\n", (double) qf.metadata->total_size_in_bytes_plus_metadada/1024/1024);
          printf("Size in bytes: %lu\n\n", qf.metadata->total_size_in_bytes_plus_metadada);
#endif

#if defined SEND_CQF || defined GENERATE_AND_SEND

	      write_mem(&qf, &snd_filter);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end1, NULL);
	      cout << "Time for the server computation without sending: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start1, t_end1) << "ms" << endl;
	      gettimeofday(&t_start, NULL);
#endif

	      snd_and_rcv_64(snd_filter, sizeof(qfmetadata), NULL, 0, tmpsock);
      	  snd_and_rcv_64(snd_filter + sizeof(qfmetadata), qf.metadata->total_size_in_bytes, NULL, 0, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server to send the filter CQF: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif
	      free(snd_filter);
#endif
	      qf_free(&qf);
	}

	else{

#if !defined SEND_CQF && !defined GENERATE_AND_SEND
          client_waiting = (uint8_t*)malloc(sizeof(uint8_t));
	      snd_and_rcv(NULL, 0, client_waiting, sizeof(uint8_t), tmpsock);
#endif

#if defined SEND_CQF || defined GENERATE_AND_SEND

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
          cout << "Starting to receive the CQF: \t" <<endl;
#endif
	      server_data_rcv_metadata = (uint8_t*)malloc(sizeof(qfmetadata));

	      snd_and_rcv_64(NULL, 0, server_data_rcv_metadata, sizeof(qfmetadata), tmpsock);

	      qfmetadata* aux_metadata =  (qfmetadata*) server_data_rcv_metadata; 
	      server_data_rcv_remainder = (uint8_t*)malloc(aux_metadata->total_size_in_bytes);
	      snd_and_rcv_64(NULL, 0, server_data_rcv_remainder, aux_metadata->total_size_in_bytes, tmpsock);

	      read_mem(&qf, server_data_rcv_metadata, server_data_rcv_remainder);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the client to receive the filter CQF: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

#ifdef TIMING_OPERATION
	     gettimeofday(&t_start, NULL);
#endif

#ifdef GENERATE_AND_SEND
	     char filename[] = "cqf.cqf";
#else
         char filename[] = "cqf_sended.cqf";
#endif
	     fprintf(stdout, "Serializing the CQF to disk.\n");

	     uint64_t total_size = qf_serialize(&qf, filename);

	     if (total_size < sizeof(qfmetadata) + qf.metadata->total_size_in_bytes) {
           fprintf(stderr, "CQF serialization failed.\n");
		   abort();
	     }

#ifdef TIMING_OPERATION
	     gettimeofday(&t_end, NULL);
	     cout <<"Time for write the filter on the file: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

	     free(server_data_rcv_metadata);
	     free(server_data_rcv_remainder);

#endif
	  }
#ifdef DEBUG
	  cout << "Free-ing allocated memory" << endl;
#endif

	delete field;

}

uint64_t MurmurHash64A_1 (const void * key, int len, unsigned int seed )
{
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

	const uint64_t * data = (const uint64_t *)key;
	const uint64_t * end = data + (len/8);

	while(data != end)
	{
		uint64_t k = *data++;

		k *= m; 
		k ^= k >> r; 
		k *= m; 

		h ^= k;
		h *= m; 
	}

	const unsigned char * data2 = (const unsigned char*)data;

	switch(len & 7)
	{
		case 7: h ^= (uint64_t)data2[6] << 48;
		case 6: h ^= (uint64_t)data2[5] << 40;
		case 5: h ^= (uint64_t)data2[4] << 32;
		case 4: h ^= (uint64_t)data2[3] << 24;
		case 3: h ^= (uint64_t)data2[2] << 16;
		case 2: h ^= (uint64_t)data2[1] << 8;
		case 1: h ^= (uint64_t)data2[0];
						h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}

#define	FORCE_INLINE inline __attribute__((always_inline))

uint64_t rotl64 ( uint64_t x, int8_t r )
{
    return (x << r) | (x >> (64 - r));
}

FORCE_INLINE uint64_t getblock64 ( const uint64_t * p, int i )
{
    return p[i];
}

#define ROTL64(x,y)	rotl64(x,y)
#define BIG_CONSTANT(x) (x##LLU)

FORCE_INLINE uint64_t fmix64 ( uint64_t k )
{
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;

    return k;
}

__uint128_t MurmurHash3_x64_128_1 ( const void * key, const int len, const uint32_t seed)
{
    const uint8_t * data = (const uint8_t*)key;
    const int nblocks = len / 16;

    uint64_t h1 = seed;
    uint64_t h2 = seed;

    const uint64_t c1 = BIG_CONSTANT(0x87c37b91114253d5);
    const uint64_t c2 = BIG_CONSTANT(0x4cf5ad432745937f);

    //----------
    // body

    const uint64_t * blocks = (const uint64_t *)(data);

    for(int i = 0; i < nblocks; i++)
    {
        uint64_t k1 = getblock64(blocks,i*2+0);
        uint64_t k2 = getblock64(blocks,i*2+1);

        k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;

        h1 = ROTL64(h1,27); h1 += h2; h1 = h1*5+0x52dce729;

        k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

        h2 = ROTL64(h2,31); h2 += h1; h2 = h2*5+0x38495ab5;
    }

    //----------
    // tail

    const uint8_t * tail = (const uint8_t*)(data + nblocks*16);

    uint64_t k1 = 0;
    uint64_t k2 = 0;

    switch(len & 15)
    {
    case 15: k2 ^= ((uint64_t)tail[14]) << 48;
    case 14: k2 ^= ((uint64_t)tail[13]) << 40;
    case 13: k2 ^= ((uint64_t)tail[12]) << 32;
    case 12: k2 ^= ((uint64_t)tail[11]) << 24;
    case 11: k2 ^= ((uint64_t)tail[10]) << 16;
    case 10: k2 ^= ((uint64_t)tail[ 9]) << 8;
    case  9: k2 ^= ((uint64_t)tail[ 8]) << 0;
            k2 *= c2; k2  = ROTL64(k2,33); k2 *= c1; h2 ^= k2;

    case  8: k1 ^= ((uint64_t)tail[ 7]) << 56;
    case  7: k1 ^= ((uint64_t)tail[ 6]) << 48;
    case  6: k1 ^= ((uint64_t)tail[ 5]) << 40;
    case  5: k1 ^= ((uint64_t)tail[ 4]) << 32;
    case  4: k1 ^= ((uint64_t)tail[ 3]) << 24;
    case  3: k1 ^= ((uint64_t)tail[ 2]) << 16;
    case  2: k1 ^= ((uint64_t)tail[ 1]) << 8;
    case  1: k1 ^= ((uint64_t)tail[ 0]) << 0;
            k1 *= c1; k1  = ROTL64(k1,31); k1 *= c2; h1 ^= k1;
    };

    //----------
    // finalization

    h1 ^= len; h2 ^= len;

    h1 += h2;
    h2 += h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 += h2;
    h2 += h1;

    __uint128_t r = ((__uint128_t)h2 << 64) ^ h1;
    return r;
}
