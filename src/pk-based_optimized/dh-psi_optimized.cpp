/*
 * dh-psi_optimized.cpp
 *
 *  Created on: May 26, 2017
 *      Author: Amanda
 */
#include "dh-psi_optimized.h"

uint32_t dhpsi_optimized(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = dhpsi_optimized(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches, cardinality, ftype);

	create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t dhpsi_optimized(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = dhpsi_optimized(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches, cardinality, ftype);

	create_result_from_matches_fixed_bitlen(result, elebytelen, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t dhpsi_optimized(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, uint32_t* matches, bool cardinality, field_type ftype) {

	uint32_t i, hash_bytes = crypt_env->get_hash_bytes(), intersect_size, fe_bytes, sndbufsize, rcvbufsize, num_byte, aux, count, intersect_size_aux=0, intersect_ctr=0;
	//task_ctx ectx;
	pk_crypto* field = crypt_env->gen_field(ftype);
	num* exponent;
	num** exponent_aux;
	CSocket* tmpsock = sock;
	fe_bytes = field->fe_byte_size();
	num_byte = field->num_byte_size();
	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t* cardinality_perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
    uint32_t* invperm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint8_t* c_encrypted_eles, *s_peles, *c_eles, *f_s_hashes, *f_c_hashes, *server_data_send;
	uint8_t buffer[num_byte];

	FILE* arq, *arq_key;

	timeval t_start, t_end;

	cout << ".....................DH_OPTIMIZED.........................." << endl;

	/* Generate a random permutation for the elements */

	if(role == SERVER){
	      exponent_aux = (num**)malloc(pneles*sizeof(num*));
	}
	else{
	      exponent_aux = (num**)malloc(neles*sizeof(num*));
	}

	if(role == CLIENT){

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      crypt_env->gen_rnd_perm(perm, neles);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the random permutation (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

	      uint8_t* f_c_hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

	      /* Hash elements */
	      ectx.eles.output = f_c_hashes;
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
	      cout << "Time for the first hash (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

#ifdef PRINT_HASHES
	      cout << "First client hash" << endl;
	      count =  neles * hash_bytes;
	      aux = hash_bytes;

	      for(i = 0; i<count; i++){
		    if (i == aux){
			  aux = aux + hash_bytes;
			  cout<< endl;
		    }
		    printf("%02x", (f_c_hashes[i]));
	      }
	      cout << endl;
#endif

	      c_encrypted_eles = (uint8_t*) malloc(sizeof(uint8_t) * neles * fe_bytes);

	      ectx.eles.input1d = f_c_hashes;
	      ectx.eles.fixedbytelen = hash_bytes;
	      ectx.eles.nelements = neles;
	      ectx.eles.outbytelen = fe_bytes;
	      ectx.eles.output = c_encrypted_eles;
	      ectx.actx.v_exponent = (num**)malloc(neles*sizeof(num*));
	      ectx.eles.hasvarbytelen = false;
	      ectx.actx.field = field;
	      ectx.actx.sample = true;

#ifdef TIMING_OPERATION
	gettimeofday(&t_start, NULL);
#endif
	      for(i=0; i<neles;i++){
			exponent_aux[i] = field->get_rnd_num();
			ectx.actx.v_exponent[i] = exponent_aux[i];
	      }

	      run_task(ntasks, ectx, asym_encrypt_d);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the first exponentiation (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;

	      free(f_c_hashes);

	      gettimeofday(&t_start, NULL);
#endif
  	      snd_and_rcv(c_encrypted_eles, neles * fe_bytes, NULL, 0, tmpsock);

#ifdef TIMING_OPERATION
             gettimeofday(&t_end, NULL);
             cout << "Time for the client send {a_1, ..., a_j}: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif
	}

	/* removing the exponent */
	ectx.eles.fixedbytelen = fe_bytes;
	ectx.eles.outbytelen = fe_bytes;
	ectx.eles.hasvarbytelen = false;
	ectx.actx.field = field;
	ectx.actx.sample = false;

	if(role == SERVER){

	      s_peles = (uint8_t*) malloc(sizeof(uint8_t) * pneles * fe_bytes);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
              snd_and_rcv(NULL, 0, s_peles, pneles * fe_bytes, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server receive {a_1, ..., a_j}: \t " << fixed  << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" <<  endl;
#endif

	      arq_key = fopen("key.txt", "rb");
	      if(arq_key == NULL){
		    cout << "Key opening problem" << endl;
		    return 0;
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

              ectx.eles.input1d = s_peles;
              ectx.eles.nelements = pneles;
	      ectx.eles.output = s_peles;
	      ectx.actx.exponent = exponent;

#ifdef TIMING_OPERATION
              gettimeofday(&t_start, NULL);
#endif
	      run_task(ntasks, ectx, asym_encrypt);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the second exponentiation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

	      sndbufsize = pneles * fe_bytes;

#ifdef TIMING_OPERATION
              gettimeofday(&t_start, NULL);
#endif
	      snd_and_rcv(s_peles, sndbufsize, NULL, 0, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server to send {a'_1, ..., a'_j}: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif
	}
	else{

	      rcvbufsize = neles * fe_bytes;
	      c_eles = (uint8_t*) malloc(sizeof(uint8_t) * neles * fe_bytes);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      snd_and_rcv(NULL, 0, c_eles, rcvbufsize, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the client to receive {a'_1, ..., a'_j}: \t" << fixed << std::setprecision(PRECISION)<< getMillies(t_start, t_end) << "ms" <<  endl;
#endif
	      ectx.eles.input1d = c_eles;
	      ectx.eles.nelements = neles;
	      ectx.eles.output = c_eles;

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      for(i=0; i<neles;i++)
		     ectx.actx.v_exponent[i] = exponent_aux[i];

	      run_task(ntasks, ectx, asym_encrypt_inverse);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the second exponentiation -- Inverse (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

	      if(cardinality) {
		    crypt_env->gen_rnd_perm(cardinality_perm, neles);
	      } else {
		    for(i = 0; i < neles; i++)
			cardinality_perm[i] = i;
	      }

/* We don't need to comput the client second hash because we do this to make the filter
#ifdef MASKBYTELEN

	hash_bytes = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
#else
	hash_bytes = crypt_env->get_hash_bytes();
#endif
	      c_hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

	      ectx.eles.input1d = c_eles;
	      ectx.eles.output = c_hashes;
	      ectx.eles.nelements = neles;
	      ectx.eles.fixedbytelen= fe_bytes;
	      ectx.eles.outbytelen = hash_bytes;
	      ectx.eles.hasvarbytelen = false;
	      ectx.eles.perm = cardinality_perm;
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
	cout << "Time for the second hash (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

#ifdef PRINT_HASHES
              cout << "Second client hash" << endl;
	      count =  neles * hash_bytes;
	      aux = hash_bytes;

	      for(i = 0; i<count ; i++){
		    if (i == aux){
			  aux = aux + hash_bytes;
			  cout<< endl;
		    }
		    printf("%02x", (c_hashes[i]));
	      }
		  cout << endl;
#endif
*/
	}

	if(role == SERVER) {
		intersect_size = 0;

		free(s_peles);
		delete exponent;

	} else {

#ifdef TIMING_OPERATION
	    	gettimeofday(&t_start, NULL);
#endif
		ItemFilter** buffer_filter = new ItemFilter*[neles];

		cuckoofilter::CuckooFilter<ItemFilter, 16> filter_hashes(pneles);

		arq = fopen("filter", "rb");

		if(arq == NULL){
		      std::cout << "Filter opening problem" << std::endl;
		      exit(1);
		}

		filter_hashes.ReadFile(arq);
		fclose(arq);

#ifdef TIMING_OPERATION
	    	gettimeofday(&t_end, NULL);
	    	cout << "Time for read data from the database: \t"<< fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
	        gettimeofday(&t_start, NULL);
#endif
		for(i=0;i<neles;i++)
		    buffer_filter[i] = new ItemFilter(&c_eles[i*fe_bytes],fe_bytes);

#ifdef TIMING_OPERATION
	    	gettimeofday(&t_start, NULL);
#endif

        for(i = 0; i < neles; i++)
            invperm[perm[i]] = i;

		for (i = 0; i < neles; i++) {
		      if (filter_hashes.ContainPSI(buffer_filter[i]->GetHashFilter(fe_bytes)) == cuckoofilter::Ok){
			    matches[intersect_ctr] = invperm[i];
			    intersect_ctr++;
			    intersect_size_aux++;
		      }    
		}

		intersect_size = intersect_size_aux;

#ifdef TIMING_OPERATION
	       gettimeofday(&t_end, NULL);
               cout << "Time for found intersection: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end)  << "ms" <<  endl;
#endif
		for(i=0; i<neles; i++){
		      delete exponent_aux[i];
		      delete buffer_filter[i];
		}

		delete[] buffer_filter;

		free(c_encrypted_eles);
		free(c_eles);
		free(ectx.actx.v_exponent);
		free(exponent_aux);
	}

#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif

	delete field;

	free(perm);
	free(cardinality_perm);
    free(invperm);

	return intersect_size;
}
