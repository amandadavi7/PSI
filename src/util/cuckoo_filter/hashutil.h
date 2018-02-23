/* -*- Mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _HASHUTIL_H_
#define _HASHUTIL_H_

#include <sys/types.h>
#include <string>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>



namespace cuckoofilter {
    class HashUtil {
    public:
        // Bob Jenkins Hash
        static uint32_t BobHash(const void *buf, size_t length, uint32_t seed = 0);
        static uint32_t BobHash(const std::string &s, uint32_t seed = 0);

        // Bob Jenkins Hash that returns two indices in one call
        // Useful for Cuckoo hashing, power of two choices, etc.
        // Use idx1 before idx2, when possible. idx1 and idx2 should be initialized to seeds.
        static void BobHash(const void *buf, size_t length, uint32_t *idx1,  uint32_t *idx2);
        static void BobHash(const std::string &s, uint32_t *idx1,  uint32_t *idx2);

        // MurmurHash2
        static uint32_t MurmurHash(const void *buf, size_t length, uint32_t seed = 0);
        static uint32_t MurmurHash(const std::string &s, uint32_t seed = 0);


        // SuperFastHash
        static uint32_t SuperFastHash(const void *buf, size_t len);
        static uint32_t SuperFastHash(const std::string &s);

        // Null hash (shift and mask)
        static uint32_t NullHash(const void* buf, size_t length, uint32_t shiftbytes);

        // Wrappers for MD5 and SHA1 hashing using EVP
        static std::string MD5Hash(const char* inbuf, size_t in_length);
        static std::string SHA1Hash(const char* inbuf, size_t in_length);

        // See Martin Dietzfelbinger, "Universal hashing and k-wise independent random
        // variables via integer arithmetic without primes".
        static uint64_t TwoIndependentMultiplyShift(uint64_t key) {
          const uint64_t SEED[4] = {
              0x818c3f78ull, 0x672f4a3aull, 0xabd04d69ull, 0x12b51f95ull};
          const unsigned __int128 m =
              *reinterpret_cast<const unsigned __int128 *>(&SEED[0]);
          const unsigned __int128 a =
              *reinterpret_cast<const unsigned __int128 *>(&SEED[2]);
          return (a + m * key) >> 64;
        }

    private:
        HashUtil();
    };
}

#endif  // #ifndef _HASHUTIL_H_


