/*
 * dh_generate_filter.cpp
 *
 *  Created on: May 30, 2017
 *      Author: Amanda
 */
#include "dh_generate_filter.h"

void dhgenerate_filter(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input2d = elements;
	ectx.eles.varbytelens = elebytelens;
	ectx.eles.hasvarbytelen = true;

	dhgenerate_filter(role, neles, pneles, ectx, crypt_env, sock, ntasks, cardinality, ftype);

}


void dhgenerate_filter(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality, field_type ftype) {
	task_ctx ectx;
	ectx.eles.input1d = elements;
	ectx.eles.fixedbytelen = elebytelen;
	ectx.eles.hasvarbytelen = false;

	dhgenerate_filter(role, neles, pneles, ectx, crypt_env, sock, ntasks, cardinality, ftype);

}

void dhgenerate_filter(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, bool cardinality, field_type ftype) {


	uint32_t i, hash_bytes = crypt_env->get_hash_bytes(), fe_bytes, num_byte, aux, count, size_filter;
	pk_crypto* field = crypt_env->gen_field(ftype);
	num* exponent;
	CSocket* tmpsock = sock;
	fe_bytes = field->fe_byte_size();
	num_byte = field->num_byte_size();
	uint32_t* perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint32_t* cardinality_perm = (uint32_t*) malloc(sizeof(uint32_t) * neles);
	uint8_t* s_encrypted_eles, *f_s_hashes, *server_data_rcv, *snd_filter;
	uint8_t buffer[num_byte];
	FILE* arq, *arq_key;

	timeval t_start, t_end, t_start1, t_end1;

	cout << ".....................FILTER.........................." << endl;

	if(role == SERVER){
	      size_filter = neles;
	}else{
	      size_filter = pneles;
	}

	cuckoofilter::CuckooFilter<ItemFilter, 16> filter_hashes(size_filter);

//	std::cout << "Info: "<< filter_hashes.Info() << std::endl;

	if(role == SERVER){

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start1, NULL);
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

	      arq_key = fopen("key.txt", "wb");

	      if(arq_key == NULL){
		cout << "Key opening problem" << endl;
		exit(1);
	      }

	      uint32_t qtdkey = fwrite(buffer, 1, num_byte, arq_key);

	      if(qtdkey != num_byte){
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

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the first exponentiation (server):\t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << " ms" << endl;
#endif

	      if(cardinality) {
		    crypt_env->gen_rnd_perm(cardinality_perm, neles);
	      } else {
		    for(i=0; i < neles; i++)
			  cardinality_perm[i] = i;
	      }

	      ItemFilter** buffer_filter = new ItemFilter*[neles];

	      for(i=0;i<neles;i++)
		    buffer_filter[i] = new ItemFilter(&s_encrypted_eles[i*fe_bytes], fe_bytes);

	      for(i=0;i<neles;i++) {
		    cuckoofilter::Status status = filter_hashes.AddPSI(buffer_filter[i]->GetHashFilter(fe_bytes));
		    if ( status != cuckoofilter::Ok)
			  cout<< "Problem in add: \n"<< status<< "\n";
	      }

	      filter_hashes.WriteMem(&snd_filter);

	      std::cout << "Info: "<< filter_hashes.Info() << std::endl;

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end1, NULL);
	      cout << "Time for the server computation without sending: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start1, t_end1) << "ms" << endl;
	      gettimeofday(&t_start, NULL);
#endif

	      snd_and_rcv(snd_filter, filter_hashes.SizeInBytes(), NULL, 0, tmpsock);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the server to send the filter CF: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

	      for(i=0;i<neles;i++)
		    delete buffer_filter[i];
	      delete [] buffer_filter;

	      delete exponent;

	      free(f_s_hashes);
	      free(s_encrypted_eles);
	      free(snd_filter);
	}
	else{

	      server_data_rcv = (uint8_t*)malloc(filter_hashes.SizeInBytes());

#ifdef TIMING_OPERATION
	      gettimeofday(&t_start, NULL);
#endif

	      snd_and_rcv(NULL, 0, server_data_rcv, filter_hashes.SizeInBytes(), tmpsock);

	      filter_hashes.ReadMem(&server_data_rcv);

#ifdef TIMING_OPERATION
	      gettimeofday(&t_end, NULL);
	      cout << "Time for the client to receive the filter CF: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif

#ifdef TIMING_OPERATION

	     gettimeofday(&t_start, NULL);
#endif
	     arq = fopen("filter", "wb");

	     if(arq == NULL){
	       cout << "Filter writting problem" << endl;
	       exit(1);
	     }

	     filter_hashes.WriteFile(arq);

	     fclose(arq);

	     free(server_data_rcv);

#ifdef TIMING_OPERATION
	     gettimeofday(&t_end, NULL);
	     cout <<"Time for write the filter on the file: \t" << fixed << std::setprecision(PRECISION) << getMillies(t_start, t_end) << "ms" << endl;
#endif
	  }

#ifdef DEBUG
	cout << "Free-ing allocated memory" << endl;
#endif
	delete field;

	free(perm);
	free(cardinality_perm);
}
