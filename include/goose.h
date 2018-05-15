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
#ifndef _GOOSE_H_
#define _GOOSE_H_

#include "types.h"

#include <net/ethernet.h>
#include <sys/time.h>

/** Tag Protocol Identifier (TPID) for 802.1Q VLAN
 */
static const uint16_t GOOSE_TPID=0x8100;

/** GOOSE PDU preamble (See: IEC61850-8-1 Annex A)
 */
static const uint8_t GOOSE_PREAMBLE=0x61;


/** Ethertype for IEC61850-8-1 GOOSE frames
 */
static const uint16_t ETHER_GOOSE=0x88b8;


/** Ethertype for IEC61850-8-1 GSE management frames
 */
static const uint16_t ETHER_GSE=0x88b9;


/** Ethertype for IEC61850-9-2 Sampled values frames
 */
static const uint16_t ETHER_SMV=0x88ba;


/** Maximum size of an ethernet frame
 */
#if 0
static const uint16_t MAX_FRAME_SIZE=1518;
#else
#define MAX_FRAME_SIZE 1518
#endif


/** GOOSE Header
 */
typedef struct _goose_header_t_ {
  #if 0
  uint16_t ethertype; /* GOOSE Ethertype */
  #endif
  uint16_t appid;     /* APPId */
  uint16_t len;       /* Length */
  uint16_t res1;      /* Reserved 1 */
  uint16_t res2;      /* Reserved 2 */
} goose_header_t;


/** GOOSE Protocol Data Unit (PDU)
 */
typedef struct _goose_pdu_t_ {
  uint8_t *gocbref;           /* gocbref */
  uint32_t timeAllowedtoLive; /* timeAllowedtoLive */
  uint8_t *datSet;            /* datSet */
  uint8_t *goID;              /* goID (optional) */
  timevalq_t *t;              /* t */
  uint32_t stNum;             /* stNum */
  uint32_t sqNum;             /* sqNum */
  uint8_t test;               /* test */
  uint32_t confRev;           /* confRev */
  uint8_t ndsCom;             /* ndsCom */
  uint32_t numDatSetEntries;  /* numDatSetEntries */
  uint8_t *allData;           /* allData */
  uint8_t *security;          /* security (optional) */
} goose_pdu_t;


/** GOOSE Ethernet Frame
 */
typedef struct _goose_frame_t_ {
  struct ether_header eth_hdr; /* Ethernet header */
  goose_header_t goose_header; /* GOOSE header */
  goose_pdu_t goose_pdu;       /* GOOSE PDU */
} goose_frame_t;


/*
 * Function Prototypes
 */

/** Function to big-endian encode the GOOSE frame into the encoded_data buffer 
 * and populate the encoded_length variable with the number of bytes in the 
 * populated buffer. If the GOOSE frame or the buffer are NULL then encoded 
 * length is reset to 0, else the GOOSE frame is ASN.1 encoded into the encoded 
 * data buffer and the encoded_length value updated appropriately. 
 *
 * @param goose_frame	- pointer to the GOOSE frame struct to be encoded
 * @param encoded_data	- pointer to the buffer to store the ASN.1 encoded bytes
 * @param encoded_len	- pointer to memory to hold the length of the encoded 
 * 			bytes
 */
void encode_goose_frame(const goose_frame_t *goose_frame, uint8_t *encoded_data, 
  uint16_t *encoded_len );

/**
 * Function to return a pointer to the Reserve 1 field in the GOOSE header for 
 * the GOOSE frame specified. If the GOOSE frame is not specified (NULL) then 
 * NULL is returned
 *
 * @param goose_frame	- pointer to the GOOSE frame
 */
uint16_t *get_res1(goose_frame_t *goose_frame);

/**
 * Function to display a GOOSE PDU string element to stdout. If the GOOSE PDU 
 * element is not specified, then the function returns, else the ASN.1 tag and 
 * length values are extracted from the element and the value displayed as a 
 * string to stdout.
 *
 * @param goose_pdu_elem	- pointer to ASN.1 encoded GOOSE PDU string 
 * 				element
 */
void print_goose_pdu_elem_str(uint8_t *goose_pdu_elem);

/**
 * Function to set the destination EUI hardware address on the GOOSE frame to 
 * the specified value. If the GOOSE frame or value is not set then 0 is 
 * returned, else the destination address is set and 1 is returned
 *
 * @param goose_frame	- pointer to the GOOSE frame to be updated
 * @param dmac	- pointer to the hardware address to set to
 * @return int	- 1 if address is updated, else 0
 */
int set_dest_mac( goose_frame_t *goose_frame, const uint8_t *dmac );

/**
 * Function to set the source EUI hardware address on the GOOSE frame to 
 * the specified value. If the GOOSE frame or value is not set then 0 is 
 * returned, else the source address is set and 1 is returned
 *
 * @param goose_frame	- pointer to the GOOSE frame to be updated
 * @param smac	- pointer to the hardware address to set to
 * @return int	- 1 if address is updated, else 0
 */
int set_src_mac( goose_frame_t *goose_frame, const uint8_t *smac );

/**
 * Function to verify if the protected checksum for the GOOSE frame is correct.
 *
 * @param goose_frame	- pointer to the GOOSE frame to verify
 * @param int	- returns -2 if the GOOSE frame is not specified, else 0 if the 
 *		computed protected checksum is the same as the protected 
 *		checksum supplied with the GOOSE frame, second, else less than 
 *		or greater than zero if computed protected checksum is matched 
 * 		relative to the protected checksum supplied with the GOOSE 
 *		frame address.
 */
int verify_protected_checksum(goose_frame_t *goose_frame);

#endif /* _GOOSE_H_ */
