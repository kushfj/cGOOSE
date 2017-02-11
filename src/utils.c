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
#include "types.h"
#include "utils.h"

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>


/*
 * Constants
 */

/** Byte mask used to extract individual bytes from a 32-bit value by performing 
 * a bit-wise AND with this mask
 */
static const long int BYTE_MASK[4] = { 0xff, 0xff00, 0xff0000, 0xff000000 };


/*
 * Function definitions
 */

void hex_dump(const void *data, const unsigned int len) {
  /* Check paramaters */
  if ( data == 0 ) {
    fprintf(stderr, "cannot dump null data.\n");
    return;
  }

  /* Declare local variables */
  unsigned int i = 0;                                        /* Loop index */
  unsigned char buffer[17] = {0};/* Buffer to hold a line of data as ASCII */
  unsigned char *dat = (unsigned char *)data; /* Pointer to data as a byte */

  /* Iteratre through the data */
  for(i=0; i<len; i++) {
    if ((i % 16) == 0) {
      /* Dump the ASCII buffer if it's not the first time */
      if (i != 0) fprintf( stdout, " %s\n", buffer); 
      /* Dump the offset */
      fprintf( stdout, "%04x:   ", i );             
    }

    /* Dump the hex value */
    fprintf( stdout, "%02x ", dat[i] );

    /* Add the ASCII value to the buffer if ASCII, else use '.' to 
     * represent data */
    if (dat[i] >= 0x20 && dat[i] <= 0x7e ) {
      buffer[i%16] = dat[i];
    } else {
      buffer[i%16] = '.';
    }

    /* Append a null terminator in-case we need to dump the ASCII */
    buffer[(i%16)+1] = '\0';
  }

  /* Add padding if hex dump num full, and do final dump of ASCII buffer */
  while ((i % 16) != 0) {
    i++;
    fprintf( stdout, "   " );
  }
  fprintf( stdout, " %s\n", buffer);
}


uint8_t num_bytes_for_ui32(const uint32_t num) {
  /* Check paramater */
  if ( num == 0 ) {
    return 1;
  }

  /* Declare local variables */
  uint8_t numBytes = 0;
  uint32_t val = num;

  /* Shift out byte at a time and count bytes */
  do {
    val >>= 8;
    numBytes++;
  } while( val );

  return numBytes;  
}


uint32_t reverse_ui32(uint32_t num) {
  /* Check paramater */
  if (num == 0) {
    return 0;
  }

  /* Declare local variables */
  uint32_t reversed = 0;

  reversed = ((num >> 24) & BYTE_MASK[0])  /* Move octet 3 to octet 0 */
            |((num << 8 ) & BYTE_MASK[2])  /* Move octet 1 to octet 2 */
            |((num >> 8 ) & BYTE_MASK[1])  /* Move octet 2 to octet 1 */
            |((num << 24) & BYTE_MASK[3]); /* Move octet 0 to octet 3 */

  return reversed;
}


void time_to_bytes(const long int tv, uint8_t *addr) {
  /* Check paramater */
  if (addr == 0) {
    return;
  }

  /* Declare local variables */
  unsigned int i; /* Loop index */

  /* Convert to bytes and append to address */
  for(i = 0; i < 4; i++ ) {
    addr[i] = (tv & BYTE_MASK[i]) >> (8*i);
  }
  return;
}


void timevalq_to_bytes(const timevalq_t *t, uint8_t *addr) {
  /* Check paramaters */
  if (addr == 0) {
    return;
  }

  /* The UTCTime is encoded into 64-bit (8-bytes). The first 32-bits are the
   * seconds-of-century (SOC) and the last 32-bits are meant to include the
   * 24-bit fractions-of-second (FRACSEC) and 8-bit time quality. */
  time_to_bytes(t->timeval.tv_sec, addr );                            /* SOC */
  time_to_bytes(reverse_ui32(t->timeval.tv_usec/1000), addr+4);   /* FRACSEC */
  addr[7] = t->time_quality;/* Overwrite the last octet with the quality flag */
  return;
}


uint8_t ui32_to_bytes(const uint32_t num, uint8_t *addr) {
  /* Check paramater */
  if (addr == 0) {
    return 0;
  }

  /* Declare local variables */
  uint8_t num_bytes = num_bytes_for_ui32(num); /* Number of bytes used by num */
  unsigned int i = 0;                          /* Loop index */

  /* Convert to bytes and append to address */
  for(i = 0; i < num_bytes; i++) {
    addr[i] = (num & BYTE_MASK[i]) >> (8*i);
  }

  return num_bytes;
}
