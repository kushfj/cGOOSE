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
#include "publisher.h"
#include "types.h"
#include "utils.h"

#include <pcap.h>





/*
 * Constants
 */





int publish(goose_frame_t *goose_frame_ptr, pcap_t *pcap_ptr) {
  /* Check paramaters */
  if (NULL == goose_frame_ptr) {
    fprintf(stderr, "ERROR: GOOSE frame not initialised\n");
    return -1;
  }

  if (NULL == pcap_ptr) {
    fprintf(stderr, "ERROR: interface not initialised\n");
    return -1;
  }

  /* Declare local variables */
  int bytes_published = -1;  /* Number of bytes written to network interface */
  uint8_t buff[MAX_FRAME_SIZE] = {0};     /* Buffer to hold the encoded data */
  uint16_t len = 0;                          /* Length of the encoded buffer */

  /* Update timestamp on frame */
  gettimeofday(&(goose_frame_ptr->goose_pdu.t->timeval), NULL);

  /* Encode the GOOSE frame for transmission */
  encode_goose_frame(goose_frame_ptr, (uint8_t *)&buff, &len);
  if (len == 0) /* Check if the frame was encoded */
  { 
    fprintf( stderr, "ERROR: could not encode GOOSE frame\n" );
    return -1;
  }

  bytes_published = pcap_inject(pcap_ptr, (const void *)&buff, (size_t)len);
  if (bytes_published == -1) {
    fprintf(stderr, "ERROR: could not inject frame\n");
    return -1;
  } else {
    hex_dump(buff, len);
    fprintf(stdout, "%d bytes published\n", bytes_published);
  }

  /* Done */
  return 0;
}
