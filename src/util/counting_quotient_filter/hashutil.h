/*
 * ============================================================================
 *
 *        Authors:  Prashant Pandey <ppandey@cs.stonybrook.edu>
 *                  Rob Johnson <robj@vmware.com>  
 *
 *        Last modification: August 12, 2020
 * 	      Author: Amanda 
 *
 * ============================================================================
 */

#ifndef _HASHUTIL_H_
#define _HASHUTIL_H_

#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t MurmurHash64B ( const void * key, int len, unsigned int seed );
uint64_t MurmurHash64A ( const void * key, int len, unsigned int seed );
__uint128_t MurmurHash3_x64_128 ( const void * key, const int len, const uint32_t seed);


uint64_t hash_64(uint64_t key, uint64_t mask);
uint64_t hash_64i(uint64_t key, uint64_t mask);

__uint128_t hash_128(__uint128_t key, __uint128_t mask);
__uint128_t hash_128i(__uint128_t key, __uint128_t mask);

#endif  // #ifndef _HASHUTIL_H_


