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
#include "publisher.h"
#include "subscriber.h"

#include <errno.h>
#include <stdint.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>





/* TODO
 * - Macro for output, i.e. debug, warn, error
 */

/*
 * Macro to print message associated with specified ERRNO along with a user
 * specified message
 *
 * @param en	ERRNO value
 * @param emsg	user specified error message
 */
#define HANDLE_ERRNO(en, emsg) \
  do { \
    errno = en; \
    perror(emsg); \
  } while (0)



/*
 * Constants
 */

/** Version of goose_ping utility
 */
static const char VER[]="0.1a";

/** The network interface in promiscuous mode.
 * 1 = promiscuous
 * 0 = not promiscuous
 */
static const int PROMISC=1; 

/** The network interface read timeout in milliseconds
 */
static const int TIMEOUT=1000;

/** The number of inut triggers to use in testing. The test pass criteria 
 * stripulates the use of 1000 input triggers.
 */
//static const int NUM_TRIGGERS=1000;
static const int NUM_TRIGGERS=10;



/*
 * Function prototypes
 */

/** Function to start a subscribe to GOOSE frames. The routine logs the 
 * timestamp of the time the GOOSE frame was received.
 *
 * @param args  void * pointer to the arguments struct which specifies the 
 *              pcap_t *, uint8_t publisher MAC address, the count of
 *              the number of frames to subscribe to, pcap_handler * to handle 
 *              the subscribed GOOSE frames, and u_char * pointer to user 
 *              arguments
 */
void *goose_pong(void *args);

/** Function to prepare a test GOOSE frame with the specified stNum and inject
 * the frame. The routine logs the timestamp prior to publishing the GOOSE 
 * frame.
 * 
 * @param pcap_ptr	void * pointer to packet capture handler to use.
 * @param goose_frame_ptr	void * pointer to the goose frame to inject.
 * @param stNum_ptr	void * pointer to the status number to inject.
 * @return int	return 0 for success, or -1 for failure.
 */
int goose_ping(void *pcap, void *goose_frame, void *stNum);

/** Function to print the usage information for the goose_ping utility
 */
void print_usage();



/*
 * Global variables
 */

//static uint32_t stNum = 0; /* Global status number */

/* Structure defined to specify the arguments supplied to the call back 
 * function. The structure is defined to simplify the passing if multiple 
 * arguments
 */
typedef struct _recv_args_t
{
  pcap_t *pcap;          /* Pointer to PCAP handle for network interface */
  uint8_t from[6];       /* MAC address to subscribe to */
  int count;             /* Count of number of frames to receive */
  pcap_handler handler;  /* Call back routine to handle frame */
  u_char *user;          /* Pointer to user argument */
} recv_args_t;

/** 
 * The GOOSE messaging transfer time is specified in PArt 5 of the IEC 61850 
 * technical specification. The transfer time is the sum of the publishing 
 * time, the communications network transmission time, and the subscribing time 
 * between a publishing and subscribing function block. This is expressed 
 * mathematically as;
 * 
 * t = ta + tb + tc
 * where;
 *   t  : is the total transfer time.
 *   ta : is the publishing time.
 *   tb : is the communications network transmission time.
 *   tc : is the subscribing time.
 *
 * The publishing time is the time taken for a communications processor to 
 * formulate a GOOSE message from an IED application and transmitting it out 
 * the physical communications network interface on the IED.
 * 
 * The subscribing time is the time taken for a communications processor to 
 * receive a GOOSE frame from the physical communications network interface, 
 * process the frame and make it available to an IED application.
 *
 * The standard prescribes the total transfer time to be a quarter of a power
 * cycle. Therefore in a 60Hz power system, such as those used in the Australian 
 * electrical power grid, the transfer time shall be 4ms.
 *
 * If we consider a communications network where the transmission time is 
 * negligible and may be ignored, i.e. where tb is 0ms, then the transfer time 
 * shall be a sum of the publishing and subscribing times. In such a system the
 * average publishing and/or subscribing time shall be no greater than 0.5 times 
 * the transfer time. 
 * 
 * The application of any security mechanisms to provide security services such 
 * as confidentiality, integrity or authentication must not increase the 
 * publishing nor subscribing such that the transfer time exceeds the prescribed 
 * limits.
 *
 * One of the easiest methods for evaluating an IED is the use of the ping-pong 
 * approach. The method requires the device under test (DUT) to publish a GOOSE
 * frame and a subscribing IED shall publish its own GOOSE frame upon receipt 
 * of the initial GOOSE frame. The approach is efficient since it allows the 
 * evaluation to verify the subscribing time (Tc) and the publishing time (Ta)
 * without requiring external inputs and/or triggers.
*/
int main(int argc, char *argv[]) 
{
  /* Check paramaters */
  if (argc != 2) 
  {
    print_usage();
    return -1;
  }

  /* Declare local variables */
  pthread_t recv_thread = NULL;         /* Thread struct to receiving thread */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};                  /* PCAP error buffer */
  pcap_t *pcap = NULL;               /* PCAP handle to the network interface */
  int thread_return = 0;         /* Variable to hold the thread return codes */
  int i = 0;          /* Loop index and temporary variable for return values */
  recv_args_t args = {0};    /* Arguments struct used to pass data to thread */
  goose_frame_t goose_frame;      /* The GOOSE frame to write to the network */
  uint8_t dmac[6] = { 0x8, 0x93, 0x01, 0x3e, 0x10, 0x73 };       /* Dest MAC */
  uint8_t smac[6] = { 0x8, 0x93, 0x01, 0x3e, 0x10, 0x73 };        /* Src MAC */
  uint8_t gocbref[] = "GE_N60CTRL/LLN0$GO$gcb03"; /* Control block reference */
  uint8_t datSet[] = "GE_N60CTRL/LLN0$GOOSE3";                   /* Data set */
  uint8_t goid[] = "GE_N60_GOOSE1";                              /* GOOSE Id */
  timevalq_t t =                                      /* Timestamp structure */
  {
    .timeval.tv_sec = 0,
    .timeval.tv_usec = 0,
    .time_quality = 0
  };

  /* Initialise time struct */
  gettimeofday(&t.timeval, NULL);                  
  t.time_quality = TIME_CLOCK_NOT_SYNCED | TIME_ACCURACY_UNSPECIFIED;

  /* Prepare the GOOSE message */
  set_dest_mac(&goose_frame, (const uint8_t *)&dmac);
  set_src_mac(&goose_frame, (const uint8_t *)&smac);
  goose_frame.eth_hdr.ether_type = htons(ETHER_GOOSE);

  /* Initialise GOOSE Header */
  goose_frame.goose_header.appid = htons(0x0);
  goose_frame.goose_header.len = htons(0x86); /* TODO: Calculate this */
  goose_frame.goose_header.res1 = htons(0x0);
  goose_frame.goose_header.res2 = htons(0x0);

  /* Initialise GOOSE PDU */
  goose_frame.goose_pdu.gocbref = (uint8_t *)&gocbref; /* gocbref */
  goose_frame.goose_pdu.timeAllowedtoLive = 2000;      /* timeAllowedtoLive */
  goose_frame.goose_pdu.datSet = (uint8_t *)&datSet;   /* datSet */
  goose_frame.goose_pdu.goID = (uint8_t *)&goid;       /* goID (optional) */
  goose_frame.goose_pdu.t = &t;                        /* t */
  goose_frame.goose_pdu.stNum = 0;                     /* stNum */
  goose_frame.goose_pdu.sqNum = 1;                     /* sqNum */
  goose_frame.goose_pdu.test = 0;                      /* test */
  goose_frame.goose_pdu.confRev = 1;                   /* confRev */
  goose_frame.goose_pdu.ndsCom = 0;                    /* ndsCom */
  goose_frame.goose_pdu.numDatSetEntries = 0;          /* numDatSetEntries */
  goose_frame.goose_pdu.allData = 0;                   /* allData */
  goose_frame.goose_pdu.security = 0;                  /* security (optional) */

  /* Open the network interface specified for capture */
  errbuf[0] = '\0'; /* NULL terminate the buffer */
  /* BUFSIZ is defined in pcap.h */
  pcap = pcap_open_live(argv[1], BUFSIZ, PROMISC, TIMEOUT, (char *)&errbuf);
  if (NULL == pcap) /* Check if packet capture handle was obtained */
  {
    fprintf(stderr, "ERROR: could not open %s - %s\n", argv[1], errbuf);
    fflush(stderr);
    exit(EXIT_FAILURE);
  } 
  else if (strlen(errbuf) > 0) /* Check if any warning were raised */
  {
    fprintf(stderr, "WARN: warning when opening %s - %s\n", argv[1], errbuf);
  }

  /* Report header */
  fprintf(stdout, "stNum,\tsent/recv,\ttimestamp\n");

  /* Set-up arguments to pass to receiver thread */
  args.pcap = pcap;                                  /* Pointer to interface */
  /* TODO: memcpy  args.from = */                             /* VM eth0 MAC */
  args.count = NUM_TRIGGERS;         /* Count of number of frames to receive */
  args.handler = goose_handler_print;       /* GOOSE handler in subscriber.h */
  args.user = NULL;                             /* Pointer to user arguments */

  /* Set-up receive thread */
  thread_return = pthread_create(&recv_thread, (pthread_attr_t *)NULL, 
   (void *)(&goose_pong), (void *)&args);
  if (thread_return)
  {
    HANDLE_ERRNO(errno, "main.pthread_create");
    exit(EXIT_FAILURE);
  }

  /* Publish GOOSE frames */
  for(i = 0; i < NUM_TRIGGERS; i++ )
  {
    //goose_ping((void *)pcap, (void *)&goose_frame, (void *)&stNum);
    publish( &goose_frame, pcap );
  }

  /* Wait for all threads to complete before main continues */
  i = 0; /* Initialise return value */
  i = pthread_join(recv_thread, NULL);
  if (i) {
    fprintf(stderr, "ERROR: could not join thread %d:%s\n", i, strerror(i));
  }
 
  /* Close the network interface */ 
  pcap_close(pcap);

  /* Block until all threads finish then exit */
  //pthread_exit(NULL);

  /* Done */
  fflush(stderr);
  exit(EXIT_SUCCESS);
} /* main */



/*
 * Function definition
 */

void *goose_pong(void *args)
{
  /* Check paramaters */
  if (NULL == args) {
    fprintf(stderr, "ERROR: args invalid\n");
    fflush(stderr);
    return NULL;
  }

  /* Declare local variables */
  int read_result = 0;                     /* Return result of pcap_loop read */
  recv_args_t *recv_args = (recv_args_t *)args;   /* Cast void* to recv_args* */

  /* Receive frames */
  printf("count: %d\n", recv_args->count); // DEBUG
#if 0
  read_result = pcap_loop(recv_args->pcap, recv_args->count, recv_args->handler, 
   recv_args->user);
#endif
  if (read_result == 0) {
    fprintf(stdout, "Done processing %d frames\n", recv_args->count);
  }
  else if (read_result == -1) {
    fprintf(stderr, "Processing terminated. Unknown error\n");
  }
  else if (read_result == -2) {
    fprintf(stderr, "Processing terminated. pcap_breakloop() called\n");
  }

  /* Done */
  fflush(stdout);
  fflush(stderr);
  return NULL;
}

int goose_ping(void *pcap_ptr, void *goose_frame_ptr, void *stNum_ptr)
{
  /* Check paramaters */
  if (pcap_ptr == NULL)
  {
    fprintf(stderr, "ERROR: pcap_ptr invalid\n");
    fflush(stderr);
    return -1;
  }
  else if (goose_frame_ptr == NULL)
  {
    fprintf(stderr, "ERROR: goose_frame_ptr invalid\n");
    fflush(stderr);
    return -1;
  }
  else if (stNum_ptr == NULL )
  {
    fprintf(stderr, "ERROR: stNum_ptr invalid\n");
    fflush(stderr);
    return -1;
  }

  /* Declare local variables */
  int bytes_written = -1;    /* Number of bytes written to network interface */
  /* Get the GOOSE frame */
  goose_frame_t goose_frame = *((goose_frame_t *)goose_frame_ptr); 
  uint8_t buff[MAX_FRAME_SIZE] = {0};     /* Buffer to hold the encoded data */
  struct timeval timestamp = {0};                               /* Timestamp */
  uint16_t len = 0;                          /* Length of the encoded buffer */

  /* Update the stNum in the GOOSE frame */
  goose_frame.goose_pdu.stNum = *((uint32_t *)stNum_ptr); /* stNum */

  /* Encode the GOOSE frame for transmission */
  encode_goose_frame(&goose_frame, (uint8_t *)&buff, &len);
  if (len == 0) /* Check if the frame was encoded */
  { 
    fprintf(stderr, "ERROR: could not encode GOOSE frame\n");
    fflush(stderr);
    return -1;
  }

  /* Report sent time in report format, stNum, S/R, timestamp */
  gettimeofday(&timestamp, NULL);
  fprintf(stdout, "stNum,\tsent/recv,\ttimestamp\n");
  fprintf(stdout, "%lu,\tS,\t%ld.%06ld\n", *((unsigned long *)stNum_ptr), 
   timestamp.tv_sec, timestamp.tv_usec);

  /* Inject the frame */
  bytes_written = pcap_inject((pcap_t *)pcap_ptr, (const void *)&buff, (size_t)len);
  if (bytes_written == -1) {
    fprintf(stderr, "ERROR: could not inject frame\n");
    pcap_close((pcap_t *)pcap_ptr);
    fflush(stdout);
    fflush(stderr);
    return -1;
  } else {
    hex_dump(buff, len);
    fprintf(stdout, "%d bytes written\n", bytes_written);
  }

  /* Done */
  fflush(stdout);
  fflush(stderr);
  return 0;
}


void print_usage() 
{
  fprintf(stdout, "goose_ping, version %s\n\n", VER);
  fprintf(stdout, "usage: goose_ping iface\n\n");
  fprintf(stdout, "  iface : network interface to use\n");
  fflush(stdout);
  return;
}
