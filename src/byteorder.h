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

/*
   This file implements macros for machine independent short and
   int manipulation

Here is a description of this file that I emailed to the samba list once:

> I am confused about the way that byteorder.h works in Samba. I have
> looked at it, and I would have thought that you might make a distinction
> between LE and BE machines, but you only seem to distinguish between 386
> and all other architectures.
>
> Can you give me a clue?

sure.

The distinction between 386 and other architectures is only there as
an optimisation. You can take it out completely and it will make no
difference. The routines (macros) in byteorder.h are totally byteorder
independent. The 386 optimsation just takes advantage of the fact that
the x86 processors don't care about alignment, so we don't have to
align ints on int boundaries etc. If there are other processors out
there that aren't alignment sensitive then you could also define
CAREFUL_ALIGNMENT=0 on those processors as well.

Ok, now to the macros themselves. I'll take a simple example, say we
want to extract a 2 byte integer from a SMB packet and put it into a
type called uint16_t that is in the local machines byte order, and you
want to do it with only the assumption that uint16_t is _at_least_ 16
bits long (this last condition is very important for architectures
that don't have any int types that are 2 bytes long)

You do this:

#define CVAL(buf,pos) (((unsigned char *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)CVAL(buf,pos))
#define SVAL(buf,pos) (PVAL(buf,pos)|PVAL(buf,(pos)+1)<<8)

then to extract a uint16_t value at offset 25 in a buffer you do this:

char *buffer = foo_bar();
uint16_t xx = SVAL(buffer,25);

We are using the byteoder independence of the ANSI C bitshifts to do
the work. A good optimising compiler should turn this into efficient
code, especially if it happens to have the right byteorder :-)

I know these macros can be made a bit tidier by removing some of the
casts, but you need to look at byteorder.h as a whole to see the
reasoning behind them. byteorder.h defines the following macros:

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

it also defines lots of intermediate macros, just ignore those :-)

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
/*
   WARNING: This section is dependent on the length of int16_t and int32_t
   being correct
*/

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
