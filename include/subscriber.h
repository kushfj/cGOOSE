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

#ifndef _SUBSCRIBER_H_
#define _SUBSCRIBER_H_

#include "goose.h"
#include <pcap.h>





/*
 * Function prototypes
 */


/**
 * Simple GOOSE packet handler callback function. If the packet is a GOOSE frame 
 * and is for the subscribed hardware MAC address then the GOOSE is printed to 
 * stdout in human-readable format
 *
 * @param arg	- pointer to bytes containing arguments to the packet handler
 * @param header	- pointer to the packet capture header
 * @param packet	- pointer to bytes containing the actual frame.
 */
void goose_handler_print(u_char *args, const struct pcap_pkthdr *header, 
 const u_char *packet); 

/**
 * Function to subscribe to the hardware MAC address on a packet capture 
 * descriptor and pass on the read frame to a GOOSE message handler for a 
 * specific number of message, or indefenitely if the count is 0
 *
 * @param mac_ptr       pointer to hardware MAC address
 * @param pcap_ptr      pointer to packet capture descriptor
 * @paran count int representing count of frames to process or forever if 0
 * @returns int -1 on error, -2 if the break callback is invoked, else 0 
 */

int subscribe(uint8_t *mac_ptr, pcap_t *pcap_ptr, int count, 
 pcap_handler goose_handler);

#endif /* _SUBSCRIBER_H_ */
