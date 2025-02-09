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

int DEBUGLEVEL = 1;

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

int extra_time_offset = 0;

/****************************************************************************
return the difference between local and GMT time
****************************************************************************/
int TimeDiff(void)
{
	static bool initialised = false;
	static int timediff = 0;

	if (!initialised) {
		/* There are four ways of getting the time difference between
		   GMT and local time. Use the following defines to decide which
		   your system can handle */
#ifdef HAVE_GETTIMEOFDAY
		struct timeval tv;
		struct timezone tz;

		gettimeofday(&tv, &tz);
		timediff = 60 * tz.tz_minuteswest;
#else
		time_t t = time(NULL);

#ifdef HAVE_TIMELOCAL
		timediff = timelocal(gmtime(&t)) - t;
#else
#ifdef HAVE_TIMEZONE
		localtime(&t);
		timediff = timezone;
#else
		timediff = -(localtime(&t)->tm_gmtoff);
#endif
#endif
#endif
		DEBUG(3, ("timediff=%d\n", timediff));
		initialised = true;
	}

	return timediff + (extra_time_offset * 60);
}

/****************************************************************************
try to optimise the localtime call, it can be quite expenive on some machines
timemul is normally LOCAL_TO_GMT, GMT_TO_LOCAL or 0
****************************************************************************/
struct tm *LocalTime(time_t *t, int timemul)
{
	time_t t2 = *t;

	t2 += timemul * TimeDiff();

	return gmtime(&t2);
}

/****************************************************************************
  return the date and time as a string
****************************************************************************/
char *timestring(void)
{
	static char TimeBuf[100];
	time_t t;
	t = time(NULL);
	strftime(TimeBuf, 100, "%D %T", LocalTime(&t, GMT_TO_LOCAL));
	return TimeBuf;
}

/****************************************************************************
line strncpy but always null terminates. Make sure there is room!
****************************************************************************/
char *StrnCpy(char *dest, char *src, int n)
{
	char *d = dest;
	while (n-- && (*d++ = *src++))
		;
	*d = 0;
	return dest;
}

/****************************************************************************
interpret the weird netbios "name"
****************************************************************************/
void name_interpret(char *in, char *out)
{

	int len = (*in++) / 2;
	while (len--) {
		*out = ((in[0] - 'A') << 4) + (in[1] - 'A');
		in += 2;
		out++;
	}
	*out = 0;
	/* Handle any scope names */
	while (*in) {
		*out++ = '.'; /* Scope names are separated by periods */
		len = *(unsigned char *) in++;
		StrnCpy(out, in, len);
		out += len;
		*out = 0;
		in += len;
	}
}

/*******************************************************************
  convert a string to lower case
********************************************************************/
void strlower(char *s)
{
	while (*s) {
		if (isupper(*s))
			*s = tolower(*s);
		s++;
	}
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

/*******************************************************************
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf, int n)
{
	while (n--)
		buf += strlen(buf) + 1;
	return buf;
}

/****************************************************************************
find a pointer to a netbios name
****************************************************************************/
char *name_ptr(char *buf, int ofs)
{
	unsigned char c = *(unsigned char *) (buf + ofs);

	if ((c & 0xC0) == 0xC0) {
		uint16_t l;
		char *p = (char *) &l;
		memcpy(&l, buf + ofs, 2);
		p[0] &= ~0xC0;
		l = RSVAL(p, 0);
		DEBUG(5,
		      ("name ptr to pos %d from %d is %s\n", l, ofs, buf + l));
		return buf + l;
	} else
		return buf + ofs;
}

/****************************************************************************
extract a netbios name from a buf
****************************************************************************/
void name_extract(char *buf, int ofs, char *name)
{
	strcpy(name, "");
	name_interpret(name_ptr(buf, ofs), name);
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

/****************************************************************************
substitute a string for a pattern in another string. Make sure there is
enough room!

This routine looks for pattern in s and replaces it with
insert. It may do multiple replacements.

return true if a substitution was done.
****************************************************************************/
bool string_sub(char *s, char *pattern, char *insert)
{
	bool ret = false;
	char *p;
	int ls = strlen(s);
	int lp = strlen(pattern);
	int li = strlen(insert);

	if (!*pattern)
		return false;

	while (lp <= ls && (p = strstr(s, pattern))) {
		ret = true;
		memmove(p + li, p + lp, ls + 1 - (PTR_DIFF(p, s) + lp));
		memcpy(p, insert, li);
		s = p + li;
		ls = strlen(s);
	}
	return ret;
}

/****************************************************************************
get my own name and IP
****************************************************************************/
bool get_myname(char *myname)
{
	struct hostent *hp;
	pstring myhostname = "";

	/* get my host name */
	if (gethostname(myhostname, sizeof(myhostname)) == -1) {
		DEBUG(0, ("gethostname failed\n"));
		return false;
	}

	/* get host info */
	if ((hp = Get_Hostbyname(myhostname)) == 0) {
		DEBUG(0, ("Get_Hostbyname: Unknown host %s.\n", myhostname));
		return false;
	}

	if (myname) {
		/* split off any parts after an initial . */
		char *p = strchr(myhostname, '.');
		if (p)
			*p = 0;

		strcpy(myname, myhostname);
	}

	return true;
}

/****************************************************************************
a wrapper for gethostbyname() that tries with all lower and all upper case
if the initial name fails
****************************************************************************/
struct hostent *Get_Hostbyname(char *name)
{
	char *name2 = strdup(name);
	struct hostent *ret;

	if (!name2) {
		DEBUG(0,
		      ("Memory allocation error in Get_Hostbyname! panic\n"));
		exit(0);
	}

	ret = gethostbyname(name2);
	if (ret != NULL) {
		free(name2);
		return ret;
	}

	/* try with all lowercase */
	strlower(name2);
	ret = gethostbyname(name2);
	if (ret != NULL) {
		free(name2);
		return ret;
	}

	/* try with all uppercase */
	strupper(name2);
	ret = gethostbyname(name2);
	if (ret != NULL) {
		free(name2);
		return ret;
	}

	/* nothing works :-( */
	free(name2);
	return NULL;
}
