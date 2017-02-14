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





/*
 * Constants
 */


/**
 * TODO: Complete implementation
 */
void goose_handler_print(u_char *args, const struct pcap_pkthdr *header, 
 const u_char *packet) 
{
  /* TODO: Delete me */
  fprintf(stdout, "goose_handler_print\n"); 

  /* Declare local variables */
  int len = 0;             /* Variable to hold number of bytes read off wire */
  struct ether_header *eth_hdr = 0;            /* Pointer to ethernet header */

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
    case (int)ETHER_GOOSE:
      fprintf(stdout, "ethernet frame\n"); 
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
int subscriber(uint8_t *mac_ptr, pcap_t *pcap_ptr, int count, 
 pcap_handler *goose_handler) 
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

  /* Declare local variables */
  int ret = 0; /* Variable to hold return value from function calls */

  /* Decode the GOOSE frame received */
  ret = pcap_loop(pcap_ptr, count, goose_handler, (u_char *)NULL);

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
