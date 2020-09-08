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
#include <semaphore.h>
#include <signal.h>
#include <stdint.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>

// DEBUG
#include <unistd.h>





/* TODO
 * - Macro for output, i.e. debug, warn, error
 */

/*
 * Macro to print message associated with specified ERRNO along with a user
 * specified message
 *
 * @param EN	ERRNO value
 * @param EMSG	user specified error message
 */
#define HANDLE_ERRNO(EN, EMSG) \
do \
{ \
  errno = EN; \
  perror(EMSG); \
} \
while (0)



/*
 * Constants
 */

/** 
 * Version of goose_ping utility
 */
static const char VER[]="0.1a";

/** 
 * The network interface in promiscuous mode.
 * 1 = promiscuous
 * 0 = not promiscuous
 */
static const int PROMISC=1; 

/** 
 * The network interface read timeout in milliseconds
 */
static const int TIMEOUT=5000;

/** 
 * The number of input triggers to use in testing. The test pass criteria 
 * stripulates the use of 1000 input triggers.
 */
//#define NUM_TRIGGERS=1000;
#define NUM_TRIGGERS 10

/**
 * Array of time values for send and receive times.
 */
static struct timeval SEND_TIMES[NUM_TRIGGERS];
static struct timeval RECV_TIMES[NUM_TRIGGERS];

/**
 * Count of number of GOOSE frames sent and received, used to track the send 
 * and receive times
 */
static unsigned int num_sent = 0;
static unsigned int num_recv = 0;



/*
 * Function prototypes
 */

/** 
 * Function to start a subscribe to GOOSE frames. The routine logs the 
 * timestamp of the time the GOOSE frame was received.
 *
 * @param args  void * pointer to the arguments struct which specifies the 
 *              pcap_t *, uint8_t publisher MAC address, the count of
 *              the number of frames to subscribe to, pcap_handler * to handle 
 *              the subscribed GOOSE frames, and u_char * pointer to user 
 *              arguments
 */
void *goose_pong(void *args);

/**
 * Function to handle a subscribed GOOSE frame to confirm its a subscribed 
 * GOOSE frame and updates the received time data
 */
void goose_pong_handler(u_char *args, const struct pcap_pkthdr *header,
 const u_char *packet);

/** 
 * Function to prepare a test GOOSE frame with the specified stNum and inject
 * the frame. The routine logs the timestamp prior to publishing the GOOSE 
 * frame.
 * 
 * @param pcap_ptr	void * pointer to packet capture handler to use.
 * @param goose_frame_ptr	void * pointer to the goose frame to inject.
 * @param stNum_ptr	void * pointer to the status number to inject.
 * @return int	return 0 for success, or -1 for failure.
 */
//int goose_ping(void *pcap, void *goose_frame, void *stNum);

/**
 * Function to print the time difference between the send and receive times 
 * for the frames
 */
void print_times(void);

/** 
 * Function to print the usage information for the goose_ping utility
 */
void print_usage(void);

/**
 * Function to gracefully exit the program 
 *
 * @param sig int for the signal number
 * @return void
 */
void signal_handler(int sig);


/**
 * Function used for testing of the subscriber. Dummy function which does not 
 * do anything, simple returns
 */
void dummy_goose_handler(u_char *args, const struct pcap_pkthdr *header, 
 const u_char *packet);




/*
 * Global variables
 */

static sem_t SUB_MUTEX; /** Mutex used to ensure that subscriber is started */

/* Structure defined to specify the arguments supplied to the call back 
 * function. The structure is defined to simplify the passing if multiple 
 * arguments
 */
typedef struct _recv_args_t
{
  char *iface;          /* Pointer to interface name */
  uint8_t from[6];      /* MAC address to subscribe to */
  int count;            /* Count of number of frames to receive */
  pcap_handler handler; /* Call back routine to handle frame */
  u_char *user;         /* Pointer to user argument */
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
  pthread_t recv_thread;                /* Thread struct to receiving thread */
  struct sigaction signal_action;                     /* Sigaction structure */
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
  struct timeval tv = {0};           /* Temporary variable to hold send time */

  /* Initialise sigaction structure */
  memset(&signal_action, 0, sizeof(struct sigaction));
  signal_action.sa_handler = &signal_handler;

  /* Set signal handler */
  if (-1 == sigaction(SIGINT, &signal_action, (struct sigaction *)NULL))
  {
    fprintf(stderr, "[!] unable to register signal handler\n");
    HANDLE_ERRNO(errno, "main.sigaction");
    fflush(stderr);
    exit(EXIT_FAILURE);
  }

  /* Initialise time struct */
  gettimeofday(&t.timeval, NULL);                  
  t.time_quality = TIME_CLOCK_NOT_SYNCED | TIME_ACCURACY_UNSPECIFIED;

  /* Initialise mutex */
  i = sem_init( &SUB_MUTEX, 0, 0);
  if (i)
  {
    HANDLE_ERRNO(errno, "main.sem_init");
    exit(EXIT_FAILURE);
  }

  /* Prepare the GOOSE message */
  set_dest_mac(&goose_frame, (const uint8_t *)&dmac);
  set_src_mac(&goose_frame, (const uint8_t *)&smac);
  goose_frame.eth_hdr.ether_type = htons(ETHER_GOOSE);

  /* Initialise GOOSE Header */
  goose_frame.goose_header.appid = htons(0x0);
  goose_frame.goose_header.len = htons(0x6B); /* TODO: Calculate this */
  goose_frame.goose_header.res1 = htons(0x0);
  goose_frame.goose_header.res2 = htons(0x0);

  /* Initialise GOOSE PDU */
  goose_frame.goose_pdu.gocbref = (uint8_t *)&gocbref; /* gocbref */
  goose_frame.goose_pdu.timeAllowedtoLive = 2000;      /* timeAllowedtoLive */
  goose_frame.goose_pdu.datSet = (uint8_t *)&datSet;   /* datSet */
  goose_frame.goose_pdu.goID = (uint8_t *)&goid;       /* goID (optional) */
  goose_frame.goose_pdu.t = &t;                        /* t */
  goose_frame.goose_pdu.stNum = 0;                     /* stNum */
  goose_frame.goose_pdu.sqNum = 0;                     /* sqNum */
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
    fprintf(stderr, "[!] could not open pcap (%s - %s)\n", argv[1], errbuf);
    fflush(stderr);
    exit(EXIT_FAILURE);
  } 
  else if (strlen(errbuf) > 0) /* Check if any warning were raised */
  {
    fprintf(stderr, "[!] warning when opening pcap (%s - %s)\n", 
     argv[1], errbuf);
  }

  /* Set-up arguments to pass to receiver thread */
  args.iface = argv[1];                              /* Pointer to interface */
  memcpy(&(args.from), &smac, 6 * sizeof(uint8_t));      /* Set hardware MAC */
  args.count = NUM_TRIGGERS;         /* Count of number of frames to receive */
  //args.handler = dummy_goose_handler;       /* GOOSE handler in subscriber.h */
  args.handler = goose_pong_handler;       /* GOOSE handler in subscriber.h */
  args.user = NULL;                             /* Pointer to user arguments */

  /* Start the receiving (subscriber) thread */
  /* DEBUG */ printf("[-] creating subscriber thread\n");
  thread_return = pthread_create(&recv_thread, (pthread_attr_t *)NULL, 
   &goose_pong, (void *)&args);
  if (thread_return)
  {
    HANDLE_ERRNO(errno, "main.pthread_create");
    exit(EXIT_FAILURE);
  }

  /* DEBUG */ printf("[-] starting publisher\n");
  /* Wait for the subscriber to start and then continue with the sending 
   * (publisher) main thread */
  sem_wait(&SUB_MUTEX); /* Wait for the subscriber to be started */
#if 0
  i = sleep(5);         /* Sleep to ensure subscriber is ready */
  if (i)
  {
    fprintf(stdout, "[!] sleep remaining (%u)\n", i);
  }
#endif

  for(i = 0; i < NUM_TRIGGERS; i++ )
  {
    /* Get send time */
    if (gettimeofday(&tv, NULL)) 
    {
      HANDLE_ERRNO(errno, "main.gettimeofday"); /* Print error and continue */
    }
    else
    {
      memcpy(&SEND_TIMES[num_sent++], &tv, sizeof(struct timeval));
    }

    /* Increment sequence number like a valid GOOSE frame */
    goose_frame.goose_pdu.sqNum += 1; /* sqNum */

    /* Publish GOOSE frames */
    publish( &goose_frame, pcap );
    /* DEBUG */ printf("[.] published (%u)\n", num_sent);
  }
  /* DEBUG */ printf("[+] finished publishing\n");
  /* Wait for all threads or timeout to occur before main continues */
  i = 0; /* Initialise return value */
  i = pthread_join(recv_thread, NULL);
  if (i) 
  {
    fprintf(stderr, "[!] could not join thread (%d:%s)\n", i, strerror(i));
  }

  /* DEBUG */ printf("[+] finished run\n");
  print_times();
 
  /* Close the network interface */ 
  pcap_close(pcap);

  /* Block until all threads finish then exit */
  /* DEBUG */ printf("[-] waiting for threats to finish\n");
  pthread_exit(NULL);

  /* Done */
  fflush(stdout);
  fflush(stderr);
  exit(EXIT_SUCCESS);
} /* main */



/*
 * Function definition
 */

void *goose_pong(void *args)
{
  /* Check paramaters */
  if (NULL == args) 
  {
    fprintf(stderr, "[!] args invalid\n");
    fflush(stderr);
    return NULL;
  }

  /* Declare local variables */
  int read_result = 0;                     /* Return result of subscribe call */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};                   /* PCAP error buffer */
  recv_args_t *recv_args = (recv_args_t *)args;   /* Cast void* to recv_args* */
  pcap_t *pcap = NULL;                    /* Pointer to packet capture handle */

  /* Initialise error buffer */
  errbuf[0] = '\0'; /* Null terminate error buffer */

  /* Attempt to open the interface for capture */
  pcap = pcap_open_live((const char *)recv_args->iface, BUFSIZ, PROMISC, 
   TIMEOUT, (char *)&errbuf);
  if (NULL == pcap) /* Check if packet capture handle was obtained */
  {
    fprintf(stderr, "[!] could not open pcap (%s - %s)\n", recv_args->iface, 
     errbuf);
    fflush(stderr);
    // TODO: Return something meaningful
    return NULL;
  } 
  else if (strlen(errbuf) > 0) /* Check if any warning were raised */
  {
    fprintf(stderr, "[!] warning when opening pcap (%s - %s)\n", 
     recv_args->iface, errbuf);
    // TODO: Return something meaningful
    return NULL;
  }

  /* Receive frames */
  sem_post(&SUB_MUTEX); /* Ready to receive GOOSE frames */
  /* DEBUG */ printf("[-] starting subscriber\n");
  read_result = subscribe(recv_args->from, pcap, recv_args->count,
   recv_args->handler);
  if (read_result == 0) 
  {
    fprintf(stdout, "[+] done processing %d frames\n", recv_args->count);
  }
  else if (read_result == -1) 
  {
    fprintf(stderr, "[-] processing terminated. unknown error\n");
  }
  else if (read_result == -2) 
  {
    fprintf(stderr, "[-] processing terminated. pcap_breakloop() called\n");
  } 
  else 
  {
    pcap_close(pcap);
    // TODO: Return something meaningful on success
    return NULL;
  }

  /* Close the network interface */ 
  pcap_close(pcap);

  /* Done */
  fflush(stdout);
  fflush(stderr);
  // TODO: Return something meaningful on failure
  return NULL;
}


void dummy_goose_handler(u_char *args, const struct pcap_pkthdr *header, 
 const u_char *packet)
{
  /* Check parametets */
  if (NULL == args || NULL == header || NULL == packet)
  {
    /* Output failure */
    printf("!");
  }

  /* Pretend that frame is processed correctly and output success */
  printf(".");
  return;
}


void goose_pong_handler(u_char *args, const struct pcap_pkthdr *header,
 const u_char *packet) 
{
  /* Check parameters */
  if (NULL == header || NULL == packet)
  {
    fprintf(stderr, "[!] invalid parameters\n"); 
    fflush(stderr);
    return;
  }

  /* Declare local variables */
  int len = 0;             /* Variable to hold number of bytes read off wire */
  struct ether_header *eth_hdr = NULL;         /* Pointer to ethernet header */
  uint16_t *res1 = 0;                     /* Pointer to the Reserver 1 field */
  struct timeval tv = {0};           /* Temporary variable to hold send time */

  /* Initialise variables */
  len = header->len; /* Get number of bytes */
  if (0 == len) 
  {
    fprintf(stderr, "[!] frame length zero\n"); 
    fflush(stderr);
    return;
  }

  /* Get ethernet frame */
  eth_hdr = (struct ether_header *)packet;

  /* Determine type of ethernet frame */
  switch (ntohs(eth_hdr->ether_type)) 
  {
    /* Process VLAN encapsulated frame */
    /* Process GOOSE frame */
    case 0x88b8:
      /* Check if the subscriber MAC matches */
      if (0 != compare_mac((uint8_t *)eth_hdr->ether_shost, (uint8_t *)args))
      {
        break;
      }

      /* Check if a protected checksum is present */
      res1 = get_res1((goose_frame_t *)packet);
      if (0 != res1)
      {
        /* We using the most significant bit of the reserved 1 field to 
           indicate that a protected checksum is present */
        if (0x80 == (0x80 | (*res1))) 
        {
          /* Check if the protected checksum is correct */
          if (0 != verify_protected_checksum((goose_frame_t *)packet))
          {
            /* TODO: maybe log error, but we just working on timing of checks */
          }
        }
      }

      /* OK - ready for processing so get recv time */
      if (gettimeofday(&tv, NULL)) 
      {
        HANDLE_ERRNO(errno, "goose_pong_handler.gettimeofday"); /* Print error and continue */
      }
      else
      {
        memcpy(&RECV_TIMES[num_recv++], &tv, sizeof(struct timeval));
      }

      /* DEBUG */ printf("[.] received (%u)\n", num_recv);
       
      break;
    /* Ignore all other frames */
    default:
      break;
  }

  fflush(stdout);
  return; /* Done handling frame */
}


void print_times(void)
{
  int i = 0;                 /* Temporary variable as loop index */
  struct timeval s_tv = {0}; /* Temporary variable to hold send time */
  struct timeval r_tv = {0}; /* Temporary variable to hold receive time */

  for(i = 0; i < NUM_TRIGGERS; i++ )
  {
    memcpy(&r_tv, &RECV_TIMES[i], sizeof(struct timeval));
    memcpy(&s_tv, &SEND_TIMES[i], sizeof(struct timeval));
    printf("%u - rtt: %ld us\n", i+1, ((r_tv.tv_sec - s_tv.tv_sec)*1000000L + r_tv.tv_usec) - s_tv.tv_usec); 
  }
}


void print_usage(void) 
{
  fprintf(stdout, "goose_ping, version %s\n\n", VER);
  fprintf(stdout, "usage: goose_ping iface\n\n");
  fprintf(stdout, "  iface : network interface to use\n");
  fflush(stdout);
  return;
}


void signal_handler(int sig)
{
  /* Check parameter - should never happen */
  if (sig < 1 || sig > NSIG)
  {
    fprintf(stderr, "[!] invalid signal - %d\n", sig);
  }
  else
  {
    /* Print signal details */
    fprintf(stdout, "\n[-] caught signal (%d:%s), exiting!\n", 
     sig, strsignal(sig));
    /* TODO: Implement closing of pcap handlers, free memory, etc. */
  }

  fflush(stderr);
  fflush(stdout);
  exit(EXIT_FAILURE);
}
