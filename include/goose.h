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

void encode_goose_frame( goose_frame_t *goose_frame, uint8_t *encoded_data, 
  uint16_t *encoded_len );

int set_dest_mac( goose_frame_t *goose_frame, const uint8_t *dmac );

int set_src_mac( goose_frame_t *goose_frame, const uint8_t *smac );

#endif /* _GOOSE_H_ */
