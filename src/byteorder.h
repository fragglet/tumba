/*
 * Copyright (c) 1992-1998 Andrew Tridgell
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Macros for machine independent short and int manipulation

SVAL(buf,pos) - extract a 2 byte SMB value
IVAL(buf,pos) - extract a 4 byte SMB value
SVALS(buf,pos) signed version of SVAL()
IVALS(buf,pos) signed version of IVAL()

SSVAL(buf,pos,val) - put a 2 byte SMB value into a buffer
SIVAL(buf,pos,val) - put a 4 byte SMB value into a buffer
SSVALS(buf,pos,val) - signed version of SSVAL()
SIVALS(buf,pos,val) - signed version of SIVAL()

RSVAL(buf,pos) - like SVAL() but for NMB byte ordering
RIVAL(buf,pos) - like IVAL() but for NMB byte ordering
RSSVAL(buf,pos,val) - like SSVAL() but for NMB ordering
RSIVAL(buf,pos,val) - like SIVAL() but for NMB ordering
*/

#undef CAREFUL_ALIGNMENT

/* we know that the 386 can handle misalignment and has the "right"
   byteorder */
#ifdef __i386__
#define CAREFUL_ALIGNMENT 0
#endif

#ifndef CAREFUL_ALIGNMENT
#define CAREFUL_ALIGNMENT 1
#endif

#define CVAL(buf, pos)       (((unsigned char *) (buf))[pos])
#define PVAL(buf, pos)       ((unsigned) CVAL(buf, pos))
#define SCVAL(buf, pos, val) (CVAL(buf, pos) = (val))

#if CAREFUL_ALIGNMENT

#define SVAL(buf, pos) (PVAL(buf, pos) | PVAL(buf, (pos) + 1) << 8)
#define IVAL(buf, pos) (SVAL(buf, pos) | SVAL(buf, (pos) + 2) << 16)
#define SSVALX(buf, pos, val)                                                  \
	(CVAL(buf, pos) = (val) & 0xFF, CVAL(buf, pos + 1) = (val) >> 8)
#define SIVALX(buf, pos, val)                                                  \
	(SSVALX(buf, pos, val & 0xFFFF), SSVALX(buf, pos + 2, val >> 16))
#define SVALS(buf, pos)       ((int16_t) SVAL(buf, pos))
#define IVALS(buf, pos)       ((int32_t) IVAL(buf, pos))
#define SSVAL(buf, pos, val)  SSVALX((buf), (pos), ((uint16_t) (val)))
#define SIVAL(buf, pos, val)  SIVALX((buf), (pos), ((uint32_t) (val)))
#define SSVALS(buf, pos, val) SSVALX((buf), (pos), ((int16_t) (val)))
#define SIVALS(buf, pos, val) SIVALX((buf), (pos), ((int32_t) (val)))

#else

/* this handles things for architectures like the 386 that can handle
   alignment errors */

/* get single value from an SMB buffer */
#define SVAL(buf, pos)        (*(uint16_t *) ((char *) (buf) + (pos)))
#define IVAL(buf, pos)        (*(uint32_t *) ((char *) (buf) + (pos)))
#define SVALS(buf, pos)       (*(int16_t *) ((char *) (buf) + (pos)))
#define IVALS(buf, pos)       (*(int32_t *) ((char *) (buf) + (pos)))

/* store single value in an SMB buffer */
#define SSVAL(buf, pos, val)  SVAL(buf, pos) = ((uint16_t) (val))
#define SIVAL(buf, pos, val)  IVAL(buf, pos) = ((uint32_t) (val))
#define SSVALS(buf, pos, val) SVALS(buf, pos) = ((int16_t) (val))
#define SIVALS(buf, pos, val) IVALS(buf, pos) = ((int32_t) (val))

#endif

/* now the reverse routines - these are used in nmb packets (mostly) */
#define SREV(x) ((((x) & 0xFF) << 8) | (((x) >> 8) & 0xFF))
#define IREV(x) ((SREV(x) << 16) | (SREV((x) >> 16)))

#define RSVAL(buf, pos)       SREV(SVAL(buf, pos))
#define RIVAL(buf, pos)       IREV(IVAL(buf, pos))
#define RSSVAL(buf, pos, val) SSVAL(buf, pos, SREV(val))
#define RSIVAL(buf, pos, val) SIVAL(buf, pos, IREV(val))
