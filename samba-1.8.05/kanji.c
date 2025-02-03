/* 
   Unix SMB/Netbios implementation.
   Version 1.8.
   Copyright (C) Andrew Tridgell 1992,1993,1994
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   Adding for Japanese language by <fujita@ainix.isac.co.jp> 1994.9.5
*/
#define _KANJI_C_

#ifdef KANJI
#include "includes.h"
#include "kanji.h"

/*
 search string S2 from S1
 S1 contain SHIFT JIS chars.
*/
char *
sj_strstr (const char *s1, const char *s2)
{
    register int len = strlen ((char *) s2);
    if (!*s2) 
	return (char *) s1;
    for (;*s1;) {
	if (*s1 == *s2) {
	    if (strncmp (s1, s2, len) == 0)
		return (char *) s1;
	}
	if (is_shift_jis (*s1)) {
	    s1 += 2;
	} else {
	    s1++;
	}
    }
    return 0;
}

/*
 Search char C from beginning of S.
 S contain SHIFT JIS chars.
*/
char *
sj_strchr (const char *s, int c)
{
    for (; *s; ) {
	if (*s == c)
	    return (char *) s;
	if (is_shift_jis (*s)) {
	    s += 2;
	} else {
	    s++;
	}
    }
    return 0;
}

/*
 Search char C end of S.
 S contain SHIFT JIS chars.
*/
char *
sj_strrchr (const char *s, int c)
{
    register char *q;

    for (q = 0; *s; ) {
	if (*s == c) {
	    q = (char *) s;
	}
	if (is_shift_jis (*s)) {
	    s += 2;
	} else {
	    s++;
	}
    }
    return q;
}

/* convesion buffer */
static char cvtbuf[1024];

int
euc2sjis (register int hi, register int lo)
{
    if (hi & 1)
	return ((hi / 2 + (hi < 0xdf ? 0x31 : 0x71)) << 8) |
	    (lo - (lo >= 0xe0 ? 0x60 : 0x61));
    else
	return ((hi / 2 + (hi < 0xdf ? 0x30 : 0x70)) << 8) | (lo - 2);
}

int
sjis2euc (register int hi, register int lo)
{
    if (lo >= 0x9f)
	return ((hi * 2 - (hi >= 0xe0 ? 0xe0 : 0x60)) << 8) | (lo + 2);
    else
	return ((hi * 2 - (hi >= 0xe0 ? 0xe1 : 0x61)) << 8) |
	    (lo + (lo >= 0x7f ? 0x60 : 0x61));
}

/*
 Convert FROM contain SHIFT JIS codes to EUC codes
 return converted buffer
 */
char *
sj_to_euc (const char *from)
{
    register char *out;

    for (out = cvtbuf; *from;) {
	if (is_shift_jis (*from)) {
	    int code = sjis2euc ((int) from[0] & 0xff, (int) from[1] & 0xff);
	    *out++ = (code >> 8) & 0xff;
	    *out++ = code;
	    from += 2;
	} else if (is_kana (*from)) {
	    *out++ = euc_kana;
	    *out++ = *from++;
	} else {
	    *out++ = *from++;
	}
    }
    *out = 0;
    return cvtbuf;
}

/*
 Convert FROM contain EUC codes to SHIFT JIS codes
 return converted buffer
*/
char *
euc_to_sj (const char *from)
{
    register char *out;

    for (out = cvtbuf; *from; ) {
	if (is_euc (*from)) {
	    int code = euc2sjis ((int) from[0] & 0xff, (int) from[1] & 0xff);
	    *out++ = (code >> 8) & 0xff;
	    *out++ = code;
	    from += 2;
	} else if (is_euc_kana (*from)) {
	    *out++ = from[1];
	    from += 2;
	} else {
	    *out++ = *from++;
	}
    }
    *out = 0;
    return cvtbuf;
}
#else 
int kanji_dummy_procedure(void)
{return 0;}
#endif /* KANJI */
