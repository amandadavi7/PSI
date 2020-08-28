/*
 * dh-psi_gattaca.cpp
 *
 *  Created on: May 26, 2017
 *      Author: Amanda
 */

#include "dh-psi_gattaca.h"

uint32_t dhpsi_gattaca(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = dhpsi_gattaca(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches, cardinality, ftype);

	create_result_from_matches_var_bitlen(result, resbytelens, elebytelens, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t dhpsi_gattaca(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;
	uint32_t* matches = (uint32_t*) malloc(sizeof(uint32_t) * min(neles, pneles));

	uint32_t intersect_size = dhpsi_gattaca(role, neles, pneles, ectx, crypt_env, sock, ntasks, matches, cardinality, ftype);

	create_result_from_matches_fixed_bitlen(result, elebytelen, elements, matches, intersect_size);

	free(matches);

	return intersect_size;
}

uint32_t dhpsi_gattaca(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, uint32_t* matches, bool cardinality, field_type ftype) {

	uint32_t i, hash_bytes = crypt_env->get_hash_bytes(), intersect_size, fe_bytes, sndbufsize, rcvbufsize, num_byte, aux, count;
	//task_ctx ectx;
	pk_crypto* field = crypt_env->gen_field(ftype);
	num* exponent; 
	num** exponent_aux;
	CSocket* tmpsock = sock;
	fe_bytes = field->fe_byte_size();
	num_byte = field->num_byte_size();
	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t* cardinality_perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint8_t* c_encrypted_eles, *s_hashes, *c_hashes, *s_encrypted_eles, * s_peles, *c_eles, *f_s_hashes, *f_c_hashes, *server_data_rcv;
	uint8_t buffer[num_byte];
	FILE* arq, *arq_key;

	timeval t_start, t_end, t_start1, t_end1;

	cout << ".....................DH_gattaca.........................." << endl;

	if(role == SERVER){

#ifdef PREPROCESSING

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start1, NULL);
#endif

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      crypt_env->gen_rnd_perm(perm, neles);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the random permutation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif
	      uint8_t* f_s_hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

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

	      exponent = field->get_rnd_num();
	      exponent->export_to_bytes(buffer, num_byte);

	      arq_key = fopen("key_gattaca", "wb");

	      if(arq_key == NULL){
		    cout << "Key opening problem" << endl;
		exit(1);
	      }

	      uint32_t qtdkey = fwrite(buffer, num_byte ,1, arq_key);

	      if(qtdkey != 1){
		  cout<<"Key writting problem" << endl;
	      }

	      fclose(arq_key);

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

	      run_task(ntasks, ectx, asym_encrypt);

	      delete exponent;

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the first exponentiation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif
	      free(f_s_hashes);

	      if(cardinality) {
		    crypt_env->gen_rnd_perm(cardinality_perm, neles);
	      } else {
		    for(i=0; i < neles; i++)
			  cardinality_perm[i] = i;
	      }

#ifdef MASKBYTELEN
	      hash_bytes = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
#else
	      hash_bytes = crypt_env->get_hash_bytes();
#endif

	      s_hashes = (uint8_t*) malloc(sizeof(uint8_t) * neles * hash_bytes);

	      ectx.eles.input1d = s_encrypted_eles;
	      ectx.eles.output = s_hashes;
	      ectx.eles.fixedbytelen= fe_bytes;
	      ectx.eles.outbytelen = hash_bytes;
	      ectx.eles.hasvarbytelen = false;
	      ectx.eles.perm = cardinality_perm;
	      ectx.sctx.symcrypt = crypt_env;

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      run_task(ntasks, ectx, psi_hashing_function);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the second hash (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

#ifdef PRINT_HASHES
	      count =  neles * hash_bytes;
	      aux = hash_bytes;
	      cout << "Second server hash" << endl;

	      for(i = 0; i<count ; i++){
		    if (i == aux){
			  aux = aux + hash_bytes;
			  cout<< endl;
		    }
		    printf("%02x", (s_hashes[i]));
	      }
	      cout << endl;
#endif

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end1, NULL);
	      cout << "Time for the server computation without sending: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start1, t_end1) << "ms" << endl; 
#endif

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif

      	      snd_and_rcv(s_hashes, neles * hash_bytes, NULL, NULL, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server to send H(H(x)^{alpha}): \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif


#endif //PREPROCESSING

#ifdef OPTIMIZED_PROTOCOLS

	      s_peles = (uint8_t*) malloc(sizeof(uint8_t) * pneles * fe_bytes);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif

	      snd_and_rcv(NULL, NULL, s_peles, pneles * fe_bytes, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server to receive a_i: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

	      arq_key = fopen("key_gattaca", "rb");
	      if(arq_key == NULL){
		    cout << "Key opening problem" << endl;
		    return 0;
	      }

	      uint32_t qtdkey_r;

	      qtdkey_r = fread(buffer, 1, num_byte, arq_key);

	      exponent = new ecc_num((ecc_field*)field);
	      exponent->import_from_bytes(buffer, num_byte);

	      if (qtdkey_r !=num_byte){
		      cout << "qtdkey_r value: " << qtdkey_r << endl;
		      cout << "Key reading problem" << endl;
	      }

	      fclose(arq_key);

              ectx.eles.input1d = s_peles;
              ectx.eles.nelements = pneles;
	      ectx.eles.output = s_peles;
	      ectx.actx.exponent = exponent;
	      ectx.eles.fixedbytelen = fe_bytes;
	      ectx.eles.outbytelen = fe_bytes;
	      ectx.eles.hasvarbytelen = false;
	      ectx.actx.field = field;
	      ectx.actx.sample = false;

#ifdef TIMING_OPERATION
              gettimeofday(&t_start, NULL);
#endif
	      run_task(ntasks, ectx, asym_encrypt);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the second exponentiation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif
	      delete exponent;

	      sndbufsize = pneles * fe_bytes;

#ifdef TIMING_OPERATION
              gettimeofday(&t_start, NULL);
#endif
	      snd_and_rcv(s_peles, sndbufsize, NULL, 0, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server to send a'_i: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

#endif

	}
	else{

#ifdef OPTIMIZED_PROTOCOLS

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      crypt_env->gen_rnd_perm(perm, neles);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the random permutation (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

	      hash_bytes = crypt_env->get_hash_bytes();

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

	      exponent_aux = (num**)malloc(neles*sizeof(num*));
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

	      for(i=0; i<neles;i++){
			exponent_aux[i] = field->get_rnd_num();
			ectx.actx.v_exponent[i] = exponent_aux[i];
	      }

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      run_task(ntasks, ectx, asym_encrypt_d);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the first exponentiation (client):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif
	      free(f_c_hashes);

#ifdef MASKBYTELEN
	      hash_bytes = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
#else
	      hash_bytes = crypt_env->get_hash_bytes();
#endif

              server_data_rcv =  (uint8_t*) malloc(sizeof(uint8_t) * pneles * hash_bytes);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif

      	      snd_and_rcv(c_encrypted_eles, neles * fe_bytes, NULL, 0, tmpsock);
//	      snd_and_rcv(c_encrypted_eles, neles * fe_bytes, server_data_rcv, pneles * hash_bytes, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
//     	      cout << "Time for the client to receive the database (ts_i) and to send (H(r_i))^Ri: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
	      cout << "Time for the client to send (H(r_i))^Ri: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

#endif

#ifdef PREPROCESSING

#ifdef MASKBYTELEN
	      hash_bytes = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
#else
	      hash_bytes = crypt_env->get_hash_bytes();
#endif

	      server_data_rcv =  (uint8_t*) malloc(sizeof(uint8_t) * pneles * hash_bytes);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      snd_and_rcv(NULL, 0, server_data_rcv, pneles * hash_bytes, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the client to receive the database (ts_i): \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

	      arq = fopen("database_gattaca", "wb");

	      if(arq == NULL){
		cout << "Database opening problem" << endl;
		exit(1);
	      }

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif
	      uint32_t total = fwrite(server_data_rcv, hash_bytes ,pneles, arq);

#ifdef TIMING_OPERATION
	     gettimeofday(&t_end, NULL);
	     cout <<"Time for write the base on the file: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif
	      if(pneles != total){
		  cout<< "Database writting problem" << endl;
	      }

	      fclose(arq);

#endif

#ifdef OPTIMIZED_PROTOCOLS

	     rcvbufsize = neles * fe_bytes;
	     c_eles = (uint8_t*) malloc(sizeof(uint8_t) * neles * fe_bytes);

#ifdef TIMING_OPERATION
	     gettimeofday(&t_start, NULL);
#endif
	     snd_and_rcv(NULL, 0, c_eles, rcvbufsize, tmpsock);

#ifdef TIMING_OPERATION
	     gettimeofday(&t_end, NULL);
	     cout << "Time for the client to receive a'_i: \t" << fixed << std::setprecision(PRECISION)<< getMillies(t_start, t_end) << "ms" <<  endl;
#endif
	     ectx.eles.input1d = c_eles;
	     ectx.eles.nelements = neles;
	     ectx.eles.output = c_eles;
	     ectx.eles.fixedbytelen = fe_bytes;
	     ectx.eles.outbytelen = fe_bytes;
	     ectx.eles.hasvarbytelen = false;
	     ectx.actx.field = field;
	     ectx.actx.sample = false;

#ifdef TIMING_OPERATION
	     gettimeofday(&t_start, NULL);
#endif
	     for(i=0; i<neles;i++){
		  ectx.actx.v_exponent[i] = exponent_aux[i];
	     }

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
	}

	if(role == SERVER) {
	     intersect_size = 0;
	     free(s_encrypted_eles);
	     free(s_hashes);
	     free(s_peles);
	} else {

#ifdef MASKBYTELEN
	     hash_bytes = ceil_divide(crypt_env->get_seclvl().statbits + ceil_log2(neles) + ceil_log2(pneles), 8);
#else
	     hash_bytes = crypt_env->get_hash_bytes();
#endif

	     server_data_rcv = (uint8_t*) malloc(sizeof(uint8_t) * pneles * hash_bytes);

	     arq = fopen("database_gattaca", "rb");

	     if(arq == NULL){
		  cout << "Database opening problem" << endl;
		  return 0;
	     }

	     uint32_t output_count;
#ifdef TIMING_DH
	     gettimeofday(&t_start, NULL);
#endif

	     output_count = fread(server_data_rcv, hash_bytes, pneles, arq);

#ifdef TIMING_DH
	      gettimeofday(&t_end, NULL);
	      cout << "Time for read data from  the file: \t"<< fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif
	      if (output_count !=pneles){
		    cout << "output_count: " << output_count << " and pneles: " << pneles << endl;
		    cout << "Database reading problem" << endl;
	      }

	      fclose(arq);

#ifdef TIMING_OPERATION
	     gettimeofday(&t_start, NULL);
#endif
		   intersect_size = find_intersection(c_hashes, neles, server_data_rcv, pneles, hash_bytes, perm, matches);

#ifdef TIMING_OPERATION
	     gettimeofday(&t_end, NULL);
	     cout << "Time for found the intersection: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

	     for(i=0;i<neles;i++){
		  delete ectx.actx.v_exponent[i];
	     }

	     free(c_encrypted_eles);
	     free(c_eles);
	     free(c_hashes);
	     free(server_data_rcv);
	     free(exponent_aux);
	     free(ectx.actx.v_exponent);
#endif
	}

	delete field;

#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif
	free(perm);
	free(cardinality_perm);

	return intersect_size;
}
