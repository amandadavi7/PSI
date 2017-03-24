/*
 * dh_generate_filter.h
 *
 *  Created on: May 30, 2017
 *      Author: Amanda
 */

#ifndef GENERATE_FILTER_H_
#define GENERATE_FILTER_H_

#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include <glib.h>
#include "../util/helpers.h"

#include "../util/cuckoo_filter/cuckoofilter.h"

#include <cassert>
#include <cmath>
#include <iostream>
#include <vector>
#include "../util/cuckoo_filter/itemfilter.h"
#include "../util/cuckoo_filter/singletable.h"

#define PRECISION 4

void dhgenerate_filter(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality=false, field_type ftype=ECC_FIELD);

void dhgenerate_filter(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality=false,
		field_type ftype=ECC_FIELD);


void dhgenerate_filter(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, bool cardinality=false, field_type ftype=ECC_FIELD);


#endif /* GENERATE_FILTER_H_ */
