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
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../src/byteorder.h"
#include "smb.h"

/* we have two time standards - local and GMT. */
#define LOCAL_TO_GMT 1
#define GMT_TO_LOCAL -1

int LOGLEVEL = 1;

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;

pstring debugf = DEBUGFILE;

/*******************************************************************
write an debug message on the debugfile. The first arg is the debuglevel.
********************************************************************/
int Debug1(char *format_str, ...)
{
	va_list ap;

	if (!dbf) {
		dbf = fopen(debugf, "w");
		if (dbf)
			setbuf(dbf, NULL);
		else
			return 0;
	}

	va_start(ap, format_str);

	vfprintf(dbf, format_str, ap);

	fflush(dbf);

	va_end(ap);
	return 0;
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
	while (*s) {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void smb_setlen(char *buf, int len)
{
	SSVAL(buf, 2, len);

	/*
	  CVAL(buf,3) = len & 0xFF;
	  CVAL(buf,2) = (len >> 8) & 0xFF;
	*/
	CVAL(buf, 4) = 0xFF;
	CVAL(buf, 5) = 'S';
	CVAL(buf, 6) = 'M';
	CVAL(buf, 7) = 'B';

	if (len >= (1 << 16))
		CVAL(buf, 1) |= 1;
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int set_message(char *buf, int num_words, int num_bytes, bool zero)
{
	if (zero)
		memset(buf + smb_size, 0, num_words * 2 + num_bytes);
	CVAL(buf, smb_wct) = num_words;
	RSSVAL(buf, smb_vwv + num_words * 2, num_bytes);
	smb_setlen(buf, smb_size + num_words * 2 + num_bytes - 4);
	return smb_size + num_words * 2 + num_bytes;
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
static int smb_buf_ofs(char *buf)
{
	return smb_size + CVAL(buf, smb_wct) * 2;
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
char *smb_buf(char *buf)
{
	return buf + smb_buf_ofs(buf);
}

/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len(char *s)
{
	unsigned char c = *(unsigned char *) s;
	if ((c & 0xC0) == 0xC0)
		return 2;
	return strlen(s) + 1;
}
