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

#include "goose.h"
#include "utils.h"

#include <string.h>
#include <arpa/inet.h> 


/* 
 * Function Definitions 
 */

void encode_goose_frame(const goose_frame_t *goose_frame, uint8_t *encoded_data,
  uint16_t *encoded_len) 
{
  /* Check parameter */
  if (NULL == goose_frame || NULL == encoded_data) 
  {
    *encoded_len = 0;
    return;
  }
 
  /* Declare local variables */
  unsigned int offset = 0;                         /* Offset into the buffer */
  unsigned int len_offset = 0;      /* Mark offset in buffer for length byte */
  unsigned int data_len = 0;              /* Length of the GOOSE PDU element */
  uint8_t tag = 0x80;                               /* Tag used for PDU data */
  // TODO: rename to use buffer to encoded data
  uint8_t *buffer = encoded_data;       /* Buffer to contain the encoded data */

  /* Encode the ethernet header */
  data_len = sizeof(struct ether_header);
  memcpy(buffer, &(goose_frame->eth_hdr), data_len);
  offset += data_len;

  /* Encode the GOOSE header */
  data_len = sizeof(goose_header_t);
  memcpy(buffer+offset, &(goose_frame->goose_header), data_len);
  offset += data_len;

  /* Encode the GOOSE PDU */
  buffer[offset++] = GOOSE_PREAMBLE;                        /* Preamble 0x61 */
  len_offset = offset;             /* Mark the position to set the length at */
  buffer[offset++] = 0x0;        /* Temporarily assign zero GOOSE PDU length */

  buffer[offset++] = tag++; /* gocbref */
  data_len = strlen((const char *)(goose_frame->goose_pdu.gocbref));
  buffer[offset++] = (uint8_t)data_len;
  if (data_len != 0) 
  {
    memcpy(buffer+offset, goose_frame->goose_pdu.gocbref, data_len);
    offset += data_len;
  }

  buffer[offset++] = tag++; /* timeAllowedtoLive */
  buffer[offset++] = num_bytes_for_ui32(goose_frame->goose_pdu.timeAllowedtoLive);
  offset += ui32_to_bytes(goose_frame->goose_pdu.timeAllowedtoLive, (uint8_t *)(buffer+offset));

  buffer[offset++] = tag++; /* datSet */
  data_len = strlen((const char *)(goose_frame->goose_pdu.datSet));
  buffer[offset++] = (uint8_t)data_len;
  if (data_len != 0) 
  {
    memcpy(buffer+offset, goose_frame->goose_pdu.datSet, data_len);
    offset += data_len;
  }

  buffer[offset++] = tag++; /* goID (optional) */
  data_len = strlen((const char *)(goose_frame->goose_pdu.goID));
  buffer[offset++] = (uint8_t)data_len;
  if (data_len != 0) 
  {
    memcpy(buffer+offset, goose_frame->goose_pdu.goID, data_len);
    offset += data_len;
  }

  buffer[offset++] = tag++; /* t */
  buffer[offset++] = 0x8; 
  timevalq_to_bytes(goose_frame->goose_pdu.t, (uint8_t *)(buffer+offset));
  offset += 0x8;

  buffer[offset++] = tag++; /* stNum */
  buffer[offset++] = num_bytes_for_ui32(goose_frame->goose_pdu.stNum);
  offset += ui32_to_bytes(goose_frame->goose_pdu.stNum, (uint8_t *)(buffer+offset));

  buffer[offset++] = tag++; /* sqNum */
  buffer[offset++] = num_bytes_for_ui32(goose_frame->goose_pdu.sqNum);
  offset += ui32_to_bytes(goose_frame->goose_pdu.sqNum, (uint8_t *)(buffer+offset));

  buffer[offset++] = tag++; /* test */
  buffer[offset++] = 0x1;
  buffer[offset++] = goose_frame->goose_pdu.test;

  buffer[offset++] = tag++; /* confRev */
  buffer[offset++] = num_bytes_for_ui32(goose_frame->goose_pdu.confRev);
  offset += ui32_to_bytes(goose_frame->goose_pdu.confRev, (uint8_t *)(buffer+offset));

  buffer[offset++] = tag++; /* ndsCom */
  buffer[offset++] = 0x1;
  buffer[offset++] = goose_frame->goose_pdu.ndsCom;

  buffer[offset++] = tag++; /* numDatSetEntries */
  buffer[offset++] = num_bytes_for_ui32(goose_frame->goose_pdu.numDatSetEntries);
  offset += ui32_to_bytes(goose_frame->goose_pdu.numDatSetEntries, (uint8_t *)(buffer+offset));

  /* allData */
  /* TODO: Implement this */
  /* security (optional) */
  /* TODO: Implement this */

  /* Update the GOOSE PDU length */
  /* TODO: There is a bug here in the calculation of the length */
  buffer[len_offset] = ((offset - len_offset));

  /* Update the encoded buffer length */ 
  *encoded_len = offset;
  return;
}


uint16_t *get_res1(goose_frame_t *goose_frame)
{
  /* Check parameters */
  if (NULL == goose_frame)
  {
    return (uint16_t *)NULL;
  }

  /* Return the reserved field from the header in the frame */
  return &(goose_frame->goose_header.res1);
}


void print_goose_pdu_elem_str(uint8_t *goose_pdu_elem)
{
  /* Check parameters */
  if (NULL == goose_pdu_elem)
  {
    return;
  }

  /* Declare local variables */
  uint8_t *len_ptr = 0;        /* Pointer to the ASN.1 length of the element */
  uint8_t *val_ptr = 0;               /* Pointer to the value of the element */
  uint8_t *tmp_val_ptr = 0;             /* Pointer to new string for element */

  /* Process and print the element */
  len_ptr = goose_pdu_elem + 1;  /* Get length, magic 1 skips ASN.1 tag byte */
  val_ptr = len_ptr + 1;       /* Get value, magic 1 skips ASN.1 length byte */
  MALLOC(tmp_val_ptr, uint8_t, ((*len_ptr)+1)); /* Magic 1 is for extra '\0' */
  memcpy(tmp_val_ptr, val_ptr, (*len_ptr));
  tmp_val_ptr[(*len_ptr)] = '\0';      /* '\0' terminate to make it a string */
  fprintf(stdout, "%s", tmp_val_ptr);
  FREE(tmp_val_ptr);
}


/* TODO: consider replacing this with memcpy */
#define SET_MAC(WHICH, FRAME, MAC) \
do \
{ \
  /* Check parameters */ \
  if ( FRAME == 0 || MAC == 0 ) \
  { \
    return 0; \
  } \
\
  /* Declare variables */ \
  unsigned int i = 0; /* Temp variable used for array index */ \
\
  /* Copy the ethernet header into the GOOSE frame */ \
  for( i = 0; i < 6; i++ ) \
  { \
    WHICH = MAC[i]; \
  } \
\
  return 1; \
\
} \
while (0)


int set_dest_mac( goose_frame_t *goose_frame, const uint8_t *dmac ) 
{
  SET_MAC(goose_frame->eth_hdr.ether_dhost[i], goose_frame, dmac);

#if 0
  /* Check parameters */
  if ( goose_frame == 0 || dmac == 0 ) 
  {
    return 0;
  }

  /* Declare variables */
  unsigned int i = 0; /* Temp variable used for array index */

  /* Copy the ethernet header into the GOOSE frame */
  for( i = 0; i < 6; i++ ) 
  {
    goose_frame->eth_hdr.ether_dhost[i] = dmac[i];
  }
  
  return 1; 
#endif
}


int set_src_mac( goose_frame_t *goose_frame, const uint8_t *smac ) 
{
  SET_MAC(goose_frame->eth_hdr.ether_shost[i], goose_frame, smac);
#if 0
  /* Check parameters */
  if ( goose_frame == 0 || smac == 0 ) 
  {
    return 0;
  }

  /* Declare variables */
  unsigned int i = 0; /* Temp variable used for array index */

  /* Copy the ethernet header into the GOOSE frame */
  for( i = 0; i < 6; i++ ) 
  {
    goose_frame->eth_hdr.ether_shost[i] = smac[i];
  }
  
  return 1; 
#endif
}


int verify_protected_checksum(goose_frame_t *goose_frame)
{
  /* Check parameters */
  if (NULL == goose_frame)
  {
    return -2;
  }

  /* Declare local variables */
  uint8_t *calc_hmac = 0; /* Pointer to the bytes containing the computed 
                             checksum */
  uint8_t *msg_hmac = 0; /* Pointer to the bytes containing the protected 
                            checksum */
  unsigned int hmac_len = 0; /* Length of the checksum values to compare */

  /* Compute the protected checksum for the GOOSE frame */
  // TODO: here!
  /* Get the protected checksum value from the GOOSE frame */

  /* Compare and return the result */
  return memcmp((const void *)calc_hmac, (const void *)msg_hmac, (size_t)hmac_len);
}
