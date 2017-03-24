/*
 * itemserver.h
 *
 *  Created on: May 26, 2017
 *      Author: Amanda
 */

#ifndef ITEMFILTER_H
#define ITEMFILTER_H

#include <stdint.h>
#include <stdio.h>

class ItemFilter
{
public:
  
  uint8_t* vector_hash;
  
  void ReadHash(FILE* arq, uint8_t len);
  void PrintHash(uint8_t len);
  uint64_t GetHashFilter(uint8_t len); 
  
ItemFilter(uint8_t* copy, uint8_t len);
~ItemFilter();
};

#endif // ITEMFILTER_H
