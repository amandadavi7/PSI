/*
 * dh-psi_optimized.h
 *
 *  Created on: May 26, 2017
 *      Author: Amanda
 */

#ifndef DH_PSI_OPTIMIZED_H_
#define DH_PSI_OPTIMIZED_H_

#include "../util/typedefs.h"
#include "../util/connection.h"
#include "../util/crypto/crypto.h"
#include "../util/crypto/pk-crypto.h"
#include "../util/helpers.h"
#include "../util/cuckoo_filter/cuckoofilter.h"
#include "../util/cuckoo_filter/itemfilter.h"
#include "../util/cuckoo_filter/singletable.h"

#include <glib.h>
#include <cassert>
#include <cmath>
#include <iostream>
#include <vector>

uint32_t dhpsi_optimized(role_type role, uint32_t neles, uint32_t pneles, uint32_t* elebytelens, uint8_t** elements,
		uint8_t*** result, uint32_t** resbytelens, crypto* crypt_env, CSocket* sock, uint32_t ntasks,
		bool cardinality=false, field_type ftype=ECC_FIELD);

uint32_t dhpsi_optimized(role_type role, uint32_t neles, uint32_t pneles, uint32_t elebytelen, uint8_t* elements,
		uint8_t** result, crypto* crypt_env, CSocket* sock, uint32_t ntasks, bool cardinality=false,
		field_type ftype=ECC_FIELD);

uint32_t dhpsi_optimized(role_type role, uint32_t neles, uint32_t pneles, task_ctx ectx, crypto* crypt_env, CSocket* sock,
		uint32_t ntasks, uint32_t* matches, bool cardinality=false, field_type ftype=ECC_FIELD);


#endif /* DH_PSI_OPTIMIZED_H_ */
