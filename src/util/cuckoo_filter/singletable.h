/* -*- Mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _SINGLE_TABLE_H_
#define _SINGLE_TABLE_H_

#include <sstream>
#include <xmmintrin.h>
#include <assert.h>

#include "printutil.h"
#include "bitsutil.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>

namespace cuckoofilter {

    // the most naive table implementation: one huge bit array
    template <size_t bits_per_tag>
    class SingleTable {
        static const size_t tags_per_bucket  = 3;
        static const size_t bytes_per_bucket = (bits_per_tag * tags_per_bucket + 7) >> 3;

        struct Bucket {
            char bits_[bytes_per_bucket];
        } __attribute__((__packed__));

        // using a pointer adds one more indirection
        Bucket *buckets_;

    public:
        static const uint32_t TAGMASK = (1ULL << bits_per_tag) - 1;
        size_t num_buckets;

        explicit
        SingleTable(size_t num) {
            num_buckets = num;
            buckets_ = new Bucket[num_buckets];
            CleanupTags();
        }

        ~SingleTable() {
            delete [] buckets_;
        }
       
	inline void WriteFile(FILE* arq){
	  
	     uint32_t total;	  
	     for (size_t i =0; i<num_buckets; i++){
		  total = fwrite(buckets_[i].bits_, 1, bytes_per_bucket, arq);
		  if(bytes_per_bucket != total)
			std::cout<<"Writting problem" << std::endl;
	    }  
	}
		       
	inline void ReadFile(FILE* arq){
	  
	     uint32_t total;	         
	     for (size_t i =0; i<num_buckets; i++){   
		  total = fread(buckets_[i].bits_, 1, bytes_per_bucket, arq);
		  if(bytes_per_bucket != total)
			std::cout<<"Reading problem" << std::endl;
	     } 	    	    
	}
	
	inline void WriteMem(uint8_t** buffer){
	  
	     *buffer = (uint8_t*)malloc(SizeInBytes());
	     for (size_t i =0; i<num_buckets; i++)
		  memcpy(&(*buffer)[i*bytes_per_bucket], buckets_[i].bits_, bytes_per_bucket);      	    
	}
	
	
	inline void ReadMem(uint8_t** buffer){
	  
	     for (size_t i =0; i<num_buckets; i++){
		  memcpy( buckets_[i].bits_, &(*buffer)[i*bytes_per_bucket], bytes_per_bucket);      	    
	    }
	}


        void CleanupTags() { memset(buckets_, 0, bytes_per_bucket * num_buckets); } // Preenche todas as entradas da buckets com 0

        size_t SizeInBytes() const { return bytes_per_bucket * num_buckets; }

        size_t SizeInTags() const { return tags_per_bucket * num_buckets; }

        std::string Info() const  {
            std::stringstream ss;
            ss << "SingleHashtable with tag size: " << bits_per_tag << " bits \n";
            ss << "\t\tAssociativity: " << tags_per_bucket << "\n";
            ss << "\t\tTotal # of rows: " << num_buckets << "\n";
            ss << "\t\tTotal # slots: " << SizeInTags() << "\n";
            return ss.str();
        }

        // read tag from pos(i,j)
        inline uint32_t ReadTag(const size_t i, const size_t j) const {
            const char *p = buckets_[i].bits_;
            uint32_t tag;
            /* following code only works for little-endian */
            if (bits_per_tag == 2) {
                tag = *((uint8_t*) p) >> (j * 2);
            }
            else if (bits_per_tag == 4) {
                p += (j >> 1);
                tag = *((uint8_t*) p) >> ((j & 1) << 2);
            }
            else if (bits_per_tag == 8) {
                p += j;
                tag = *((uint8_t*) p);
            }
            else if (bits_per_tag == 12) {
                p += j + (j >> 1);
                tag = *((uint16_t*) p) >> ((j & 1) << 2);
            }
            else if (bits_per_tag == 16) {
                p += (j << 1);
                tag = *((uint16_t*) p);
            }
            else if (bits_per_tag == 32) {
                tag = ((uint32_t*) p)[j];
            }
            return tag & TAGMASK;
        }

        // write tag to pos(i,j)
        inline void  WriteTag(const size_t i, const size_t j, const uint32_t t) {
            char *p = buckets_[i].bits_;
            uint32_t tag = t & TAGMASK;
	    	    
            if (bits_per_tag == 2) {
                *((uint8_t*) p) |= tag << (2*j);
            }
            else if (bits_per_tag == 4) {
                p += (j >> 1);
                if ( (j & 1) == 0) {
                    *((uint8_t*) p)  &= 0xf0;
                    *((uint8_t*) p)  |= tag;
                }
                else {
                    *((uint8_t*) p)  &= 0x0f;
                    *((uint8_t*) p)  |= (tag << 4);
                }
            }
            else if (bits_per_tag == 8) {
                ((uint8_t*) p)[j] =  tag;
            }
            else if (bits_per_tag == 12 ) {
                p += (j + (j >> 1));
                if ( (j & 1) == 0) {
                    ((uint16_t*) p)[0] &= 0xf000;
                    ((uint16_t*) p)[0] |= tag;
//		    std::cout << "Deu: "<< ((uint16_t*) p)[0]  << std::endl;

                }
                else {
                    ((uint16_t*) p)[0] &= 0x000f;
                    ((uint16_t*) p)[0] |= (tag << 4);
                }
            }
            else if (bits_per_tag == 16) {
                ((uint16_t*) p)[j] = tag;
            }
            else if (bits_per_tag == 32) {
                ((uint32_t*) p)[j] = tag;
            }

            return;
        }

        inline bool FindTagInBuckets(const size_t i1,
                                     const size_t i2,
                                     const uint32_t tag) const {
            const char* p1 = buckets_[i1].bits_;
            const char* p2 = buckets_[i2].bits_;

            uint64_t v1 =  *((uint64_t*) p1);
            uint64_t v2 =  *((uint64_t*) p2);

            // caution: unaligned access & assuming little endian
            if (bits_per_tag == 4 && tags_per_bucket == 4) {
                return hasvalue4(v1, tag) || hasvalue4(v2, tag);
            }
            else if (bits_per_tag == 8 && tags_per_bucket == 4) {
                return hasvalue8(v1, tag) || hasvalue8(v2, tag);
            }
            else if (bits_per_tag == 12 && tags_per_bucket == 4) {
                return hasvalue12(v1, tag) || hasvalue12(v2, tag);
            }
            else if (bits_per_tag == 16 && tags_per_bucket == 4) {
                return hasvalue16(v1, tag) || hasvalue16(v2, tag);
            }
            else {
                for (size_t j = 0; j < tags_per_bucket; j++ ){
                    if ((ReadTag(i1, j) == tag) || (ReadTag(i2,j) == tag))
                        return true;
                }
                return false;
            }

        }

        inline bool  FindTagInBucket(const size_t i,  const uint32_t tag) const {
            // caution: unaligned access & assuming little endian
            if (bits_per_tag == 4 && tags_per_bucket == 4) {
                const char* p = buckets_[i].bits_;
                uint64_t v = *(uint64_t*)p; // uint16_t may suffice
                return hasvalue4(v, tag);
            }
            else if (bits_per_tag == 8 && tags_per_bucket == 4) {
                const char* p = buckets_[i].bits_;
                uint64_t v = *(uint64_t*)p; // uint32_t may suffice
                return hasvalue8(v, tag);
            }
            else if (bits_per_tag == 12 && tags_per_bucket == 4) {
                const char* p = buckets_[i].bits_;
                uint64_t v = *(uint64_t*)p;
                return hasvalue12(v, tag);
            }
            else if (bits_per_tag == 16 && tags_per_bucket == 4) {
                const char* p = buckets_[i].bits_;
                uint64_t v = *(uint64_t*)p;
                return hasvalue16(v, tag);
            }
            else {
                for (size_t j = 0; j < tags_per_bucket; j++ ){
                    if (ReadTag(i, j) == tag)
                        return true;
                }
                return false;
            }
        }// FindTagInBucket

        inline  bool  DeleteTagFromBucket(const size_t i,  const uint32_t tag) {
            for (size_t j = 0; j < tags_per_bucket; j++ ){
                if (ReadTag(i, j) == tag) {
                    assert (FindTagInBucket(i, tag) == true);
                    WriteTag(i, j, 0);
                    return true;
                }
            }
            return false;
        }// DeleteTagFromBucket

        inline  bool  InsertTagToBucket(const size_t i,  const uint32_t tag,
                                         const bool kickout, uint32_t& oldtag) {
            for (size_t j = 0; j < tags_per_bucket; j++ ){
                if (ReadTag(i, j) == 0) {
                    WriteTag(i, j, tag);
                    return true;
                }
            }
            if (kickout) {
                size_t r = rand() % tags_per_bucket;
                oldtag = ReadTag(i, r);
                WriteTag(i, r, tag);
            }
            return false;
        }// InsertTagToBucket


        inline size_t NumTagsInBucket(const size_t i) {
            size_t num = 0;
            for (size_t j = 0; j < tags_per_bucket; j++ ){
                if (ReadTag(i, j) != 0) {
                    num ++;
                }
            }
            return num;
        } // NumTagsInBucket

    };// SingleTable
}

#endif // #ifndef _SINGLE_TABLE_H_
