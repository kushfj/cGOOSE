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
#ifndef _TYPES_H_
#define _TYPES_H_

#include <stdint.h>
#include <sys/time.h>

/* 
 * Define constants
 */

/* Constants relating to the timestamp value as specified in IEC61850-8-1 p.28
 * The actual time quality is specified in IEC61850-7-2 pp.14-15
 *
 * ---------------------------------------------------------------------------
 * | Bit | Meaning                   | Valid values
 * ------+---------------------------+----------------------------------------
 * | 0   | Leap second known         | 0x0 - 0x1
 * ------+---------------------------+----------------------------------------
 * | 1   | Clock failure             | 0x0 - 0x1
 * ------+---------------------------+----------------------------------------
 * | 2   | Clock not synchronised    | 0x0 - 0x1
 * ------+---------------------------+----------------------------------------
 * | 3-7 | Time accuracy of FRACSEC  | 0x0 - 0x18 (1-bit to 24-bits accuracy)
 * |     |                           | 0x1F       (accuracy unspecified)
 * ---------------------------------------------------------------------------
 * 	
 */

/** Flag used to indicate that the time source of the sending decide is not 
 * synchronised with the external UTC source
 */
static const uint8_t TIME_CLOCK_NOT_SYNCED     = 0x20;

/** Flag used to indicate that the time source of the sending device is 
 * unreliable.
 */
static const uint8_t TIME_CLOCK_FAILURE        = 0x40;

/** flag used to indicate that value of the seconds-of-century (SOC) taken into 
 * account all leap seconds. This is the most significant bit of the quality 
 * octet
 */
static const uint8_t TIME_LEAP_SECS_KNOWN      = 0x80;

/** Flag used to indicate the accuracy class of the time source of the sending 
 * device relative to the external UTC source. This flag is used to represent 
 * the number of significant bits in the fraction-of-second (FRACSEC) value.
 */
static const uint8_t TIME_ACCURACY_UNSPECIFIED = 0x1f;


typedef struct _str_t_ { 
  uint32_t len; /* Number of octets in the string */
  uint8_t *str; /* Pointer to the actial string */
} str_t;


/** Structure to store the timestamp type, i.e. the timestamp time value as well 
 * as information about the synchronisation of an internal time with an external 
 * time source as specified in IEC61850-7-2 pp.13-15.
 */
typedef struct _timevalq_t_ {
  /* Actual struct timeval containing the seconds and microseconds */
  struct timeval timeval; 
  /* Time quality bits (See:IEC61850-8-1 p.28) */
  uint8_t time_quality;   
} timevalq_t;

#endif
