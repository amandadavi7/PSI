/*
 * itemserver.cpp
 *
 *  Created on: May 26, 2017
 *      Author: Amanda
 */

#include "itemfilter.h"
#include "cuckoofilter.h"

#include <iostream>
#include <stdlib.h>

using namespace std;

ItemFilter::ItemFilter(uint8_t* copy, uint8_t len)
{
    this->vector_hash = new uint8_t [len];
    for(uint8_t i = 0; i<len; i++){
	  vector_hash[i] = copy[i];	
      }	
}

ItemFilter::~ItemFilter()
{
  delete[] this->vector_hash;
}

uint64_t ItemFilter::GetHashFilter(uint8_t len)
{
  
    uint64_t low = cuckoofilter::HashUtil::SuperFastHash(this->vector_hash,len/2);
    uint64_t high = cuckoofilter::HashUtil::SuperFastHash(this->vector_hash+len/2,len/2);
    
    return high<<32 | low;
}

void ItemFilter::ReadHash(FILE* arq, uint8_t len)
{
    uint32_t qtdkey_r;
    
    qtdkey_r = fread(this->vector_hash, 1, len, arq);	

    if (qtdkey_r != len){
	  cout << "Qtdkey_r: " << qtdkey_r << endl;
	  cout << "Read_hash problem" << endl;
    }
}

void ItemFilter::PrintHash(uint8_t len)
{
    for(uint8_t i = 0; i<len ; i++)
	  printf("%02x", vector_hash[i]);	
    cout << endl;      
}