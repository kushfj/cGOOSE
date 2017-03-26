/**
 * Copyright (c) 2015, Nishchal Kush, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided;
 *   - Redistributions of source code must retain the copyright information,
 *     this list of conditions, and the following disclaimer.
 *   - Redistributions in binary form must reproduce the copyright information, 
 *     this list of conditions, and the following disclaimer in the 
 *     documentation and/or other materials provided with the distribution.
 *   - Neither the name of the author (Nishchal Kush) nor the names of any
 *     other contributors may be used to endorse or promote products derived 
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 * $Revision$
 * $Author$
 */
#ifndef _UTILS_H_
#define _UTILS_H_


#include <stdio.h>
#include <stdlib.h>


/**
 * Macro to invoke free on the pointer, it is assumed that the pointer was
 * returned (RET) from the MALLOC macro
 *
 * @param PTR the pointer to memory to free
 */
#define FREE(PTR) \
do \
{ \
  if (PTR) \
  { \
    free(PTR); \
  } \
} \
while (0)


/**
 * Macro to invoke malloc and check that memory is allocated. If memory
 * allocation fails, then exit the program.
 *
 * @param ret  the address of memory allocated if malloc is successful, else
 *             unchanged
 * @param type  the type of memory to cast, e.g., int, float, uint8_t, etc.
 * @param size  the size_t of memory to allocate
 */
#define MALLOC(RET, TYPE, MEM_SIZE) \
do \
{ \
  if (MEM_SIZE <= 0) \
  { \
    RET = NULL; \
  } \
  else if (NULL == (RET = (TYPE *)malloc(MEM_SIZE))) \
  { \
    fprintf(stderr, "ERROR: unable to allocate memory\n"); \
    fflush(stderr); \
    exit(EXIT_FAILURE); \
  } \
} \
while (0)



/** 
 * Function to output the specified buffer as hexadecimal values to stdout
 *
 * @param data	- void * pointer to the data to dump
 * @param len	- unsigned int representing the length of the data
 */
void hex_dump(const void *data, const unsigned int len);

/** 
 * Function to return the actual number of bytes used by an unsigned 32-bit 
 * integer
 *
 * @param num	- uint32_t integer
 * @return uint8_t	- the maximum number of bytes needed to represent the 
 * 			specified number.
 */
uint8_t num_bytes_for_ui32(const uint32_t num);

/**
 * Function to print value as hexadecimal hardware MAC address
 *
 * @param mac - pointer to hardware mac address
 */
void print_mac(const uint8_t *mac);

/** 
 * Function to return a uint32_t value representing the reversed order of 
 * bytes for the specified uint32_t number.
 *
 * @param num	- uint32_t integer
 * @return uint32_t	- the value with reversed byte order of the specified 
 * 			number
 */
uint32_t reverse_ui32(uint32_t num);


/**
 * Function to reverse the bytes stored at a source location into the
 * destination location. The source and destination locations must not overlap
 * The destination location is over-written with bytes from the source location
 * in reverse order, or left unchanged if num_bytes is 0.
 *
 * @param src pointer to the source location
 * @param dst pointer to the destination location, must be initialised and
 *             capable of storing num_bytes and not overlapping the source 
 *             location
 * @param num_bytes number of bytes to reverse
 */
void reverse_bytes(uint8_t *src, uint8_t *dst, size_t num_bytes);

/** 
 * Function to convert the time value specified as a long into into a 4-byte 
 * value. The 4-byte value is put into the buffer specified.
 *
 * @param tv	- long int representing the time value
 * @param addr	- pointer to the buffer to add the octets to
 */
void time_to_bytes(const long int tv, uint8_t *addr);

/** 
 * Function to convert the time value and quality struct specified as a 
 * timevalq_t into an 8-byte value. The 8-byte value is put into the buffer 
 * specified.
 *
 * @param t	- timevalq_t struct representing the time and quality
 * @param addr	- pointer to the buffer to add the octets to
 */
void timevalq_to_bytes(const timevalq_t *t, uint8_t *addr);

/** 
 * Function to convert the number specified as a uint32_t into bytes. The 
 * bytes are put into the buffer specified.
 *
 * @param num	- uint32_t representing the number
 * @param addr	- pointer to the buffer to add the octets to
 */
uint8_t ui32_to_bytes(const uint32_t num, uint8_t *addr);

#endif /* _UTILS_H_ */
