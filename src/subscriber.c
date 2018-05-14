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
#include "subscriber.h"
#include "types.h"
#include "utils.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <string.h>





/*
 * Constants
 */


/**
 * Simple GOOSE packet handler callback function. If the packet is a GOOSE frame 
 * and is for the subscribed hardware MAC address then the GOOSE is printed to 
 * stdout in human-readable format
 */
void goose_handler_print(u_char *args, const struct pcap_pkthdr *header, 
 const u_char *packet) 
{
  /* Check parameters */
  if (NULL == header || NULL == packet)
  {
    fprintf(stderr, "ERROR: invalid parameters\n"); 
    fflush(stderr);
    return;
  }

  /* Declare local variables */
  int len = 0;             /* Variable to hold number of bytes read off wire */
  struct ether_header *eth_hdr = NULL;         /* Pointer to ethernet header */
  goose_header_t *goose_hdr = NULL;               /* Pointer to GOOSE header */
  uint8_t *goose_pdu_ptr = NULL;               /* Pointer into the GOOSE PDU */
  uint8_t *goose_pdu_elem_ptr = NULL;   /* Temp pointer to GOOSE PDU element */
  uint8_t *len_ptr = NULL;         /* Pointer to length of GOOSE PDU element */
  //uint8_t *val_ptr = NULL;          /* Pointer to value of GOOSE PDU element */
  //uint8_t *tmp_val_ptr = NULL;    /* Temp Pointer to reversed bytes of value */

  /* Initialise variables */
  len = header->len; /* Get number of bytes */
  if (0 == len) {
    fprintf(stderr, "ERROR: frame length zero\n"); 
    fflush(stderr);
    return;
  }

  /* Get ethernet frame */
  eth_hdr = (struct ether_header *)packet; 

  /* Determine type of ethernet frame */
  switch (ntohs(eth_hdr->ether_type)) {
    /* Process VLAN encapsulated frame */
    /* Process GOOSE frame */
    case 0x88b8:
      fprintf(stdout, "-- GOOSE FRAME START --\n"); 

      /* Print ethernet header */
      fprintf(stdout, "Ethernet\n");
      fprintf(stdout, "dst: "); print_mac(eth_hdr->ether_dhost);
      fprintf(stdout, "\nsrc: "); print_mac(eth_hdr->ether_shost);
      fprintf(stdout, "\ntype: 0x%04x\n", ntohs(eth_hdr->ether_type)); 

      /* Print GOOSE header */
      fprintf(stdout, "GOOSE\n");
      goose_hdr = (goose_header_t *)(packet + sizeof(struct ether_header));
      fprintf(stdout, "\tappid:\t\t0x%04x\n", ntohs(goose_hdr->appid)); 
      fprintf(stdout, "\tlen:\t\t%hu\n", ntohs(goose_hdr->len)); 
      fprintf(stdout, "\tres1:\t\t0x%04x\n", ntohs(goose_hdr->res1)); 
      fprintf(stdout, "\tres2:\t\t0x%04x\n", ntohs(goose_hdr->res2)); 

      /* Print GOOSE PDU */
      fprintf(stdout, "\tgoosePDU\n");
      goose_pdu_ptr = (((uint8_t *)goose_hdr) + sizeof(goose_header_t));

      /* Get first GOOSE PDU element, note that the Magic 2 is because we want 
       * to skip the preamble and the PDU length */
      goose_pdu_elem_ptr = goose_pdu_ptr + 2;

      /* Print gocbRef */
      // TODO: Implement better handling for multi-byte lengths
      len_ptr = goose_pdu_elem_ptr + 1; 
      fprintf(stdout, "\t\tgocbref: "); 
      print_goose_pdu_elem_str(goose_pdu_elem_ptr);
      fprintf(stdout, "\n");
      /* Magic 2 is 1 byte for tag and 1 byte for length */
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print timeAllowedtoLive */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\ttatL: "); 
      fprintf(stdout, "[to be implemented]");
      fprintf(stdout, "\n");
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print datSet */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\tdatSet: "); 
      print_goose_pdu_elem_str(goose_pdu_elem_ptr);
      fprintf(stdout, "\n");
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print goID */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\tgoID: "); 
      print_goose_pdu_elem_str(goose_pdu_elem_ptr);
      fprintf(stdout, "\n");
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print t */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\tt: "); 
      fprintf(stdout, "[to be implemented]");
      fprintf(stdout, "\n");
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print stNum */
      len_ptr = goose_pdu_elem_ptr + 1;
      //fprintf(stdout, "\t\tstNum: %hu\n", ntohs(goose_pdu_elem_ptr+2)); 
      fprintf(stdout, "\t\tstNum: ");
      switch (*len_ptr)
      {
        case 1:
          fprintf(stdout, "%hu", (*(len_ptr+1)));
          break;
        default:
          fprintf(stdout, "[undefined]");
      }
      fprintf(stdout, "\n");
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print sqNum */
      len_ptr = goose_pdu_elem_ptr + 1;
      //fprintf(stdout, "\t\tsqNum: %hu\n", ntohs(goose_pdu_elem_ptr+2)); 
      fprintf(stdout, "\t\tsqNum: ");
      switch (*len_ptr)
      {
        case 1:
          fprintf(stdout, "%hu", (*(len_ptr+1)));
          break;
        default:
          fprintf(stdout, "[undefined]");
      }
      fprintf(stdout, "\n");
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print test */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "test: %s\n", ((*goose_pdu_elem_ptr) ? "true" : "false")); 
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print confRev */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\tconfrev: %d\n", goose_pdu_elem_ptr[2]); 
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print ndsCom */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\tndsCom: %s\n", ((*goose_pdu_elem_ptr) ? "true" : "false")); 
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      /* Print numDatSetEntries */
      len_ptr = goose_pdu_elem_ptr + 1;
      fprintf(stdout, "\t\tnumEntires: %d\n", goose_pdu_elem_ptr[2]); 
      goose_pdu_elem_ptr = goose_pdu_elem_ptr + (*len_ptr) + 2;

      fprintf(stdout, "-- GOOSE FRAME END --\n"); 
      break;
    /* Ignore all other frames */
    default:
      break;
  }

  fflush(stdout);
  return; /* Done handling frame */
}



/**
 * Function to subscribe to the hardware MAC address on a packet capture 
 * descriptor and pass on the read frame to a GOOSE message handler for a 
 * specific number of message, or indefenitely if the count is 0
 *
 * @param mac_ptr	pointer to hardware MAC address
 * @param pcap_ptr	pointer to packet capture descriptor
 * @paran count	int representing count of frames to process or forever if 0
 * @returns int	-1 on error, -2 if the break callback is invoked, else 0 

 */
int subscribe(uint8_t *mac_ptr, pcap_t *pcap_ptr, int count, 
 pcap_handler goose_handler) 
{
  /* Check paramaters */
  if (NULL == mac_ptr) {
    fprintf(stderr, "ERROR: MAC address not initialised\n");
    return -1;
  }

  if (NULL == pcap_ptr) {
    fprintf(stderr, "ERROR: interface not initialised\n");
    return -1;
  }

  /* Clamp count value to zero */
  if (count < 0)
  {
    count = 0;
  }

  /* Declare local variables */
  int ret = 0; /* Variable to hold return value from function calls */

  /* Decode the GOOSE frame received */
  /* DEBUG */ printf("waiting for packets\n");
  ret = pcap_loop(pcap_ptr, count, goose_handler, (u_char *)mac_ptr);

  /* Check return value */
  if (-2  == ret) {
    /* pcap_loopbreak called */
    fprintf(stderr, "ERROR: pcap_loopbreak called\n");
  } else if (-1  == ret) {
    /* error while reading frame */
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(pcap_ptr));
  }

  /* Done */
  fflush(stderr);
  return ret;
}
