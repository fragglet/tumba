/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   time handling functions
   Copyright (C) Andrew Tridgell 1992-1998

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

#include "timefunc.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <time.h>

#include "byteorder.h"
#include "smb.h"
#include "util.h"

struct tm;

/*
  This stuff was largely rewritten by Paul Eggert <eggert@twinsun.com>
  in May 1996
  */

static int serverzone = 0;

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef TIME_T_MIN
#define TIME_T_MIN                                                             \
	((time_t) 0 < (time_t) -1                                              \
	     ? (time_t) 0                                                      \
	     : ~(time_t) 0 << (sizeof(time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX (~(time_t) 0 - TIME_T_MIN)
#endif

#define TM_YEAR_BASE 1900

/*******************************************************************
yield the difference between *A and *B, in seconds, ignoring leap seconds
********************************************************************/
static int tm_diff(struct tm *a, struct tm *b)
{
	int ay = a->tm_year + (TM_YEAR_BASE - 1);
	int by = b->tm_year + (TM_YEAR_BASE - 1);
	int intervening_leap_days =
	    (ay / 4 - by / 4) - (ay / 100 - by / 100) + (ay / 400 - by / 400);
	int years = ay - by;
	int days =
	    365 * years + intervening_leap_days + (a->tm_yday - b->tm_yday);
	int hours = 24 * days + (a->tm_hour - b->tm_hour);
	int minutes = 60 * hours + (a->tm_min - b->tm_min);
	int seconds = 60 * minutes + (a->tm_sec - b->tm_sec);

	return seconds;
}

/*******************************************************************
  return the UTC offset in seconds west of UTC, or 0 if it cannot be determined
  ******************************************************************/
int time_zone(time_t t)
{
	struct tm *tm = gmtime(&t);
	struct tm tm_utc;
	if (!tm)
		return 0;
	tm_utc = *tm;
	tm = localtime(&t);
	if (!tm)
		return 0;
	return tm_diff(&tm_utc, tm);
}

/*******************************************************************
init the time differences
********************************************************************/
void time_init(void)
{
	serverzone = time_zone(time(NULL));

	if ((serverzone % 60) != 0) {
		WARNING("WARNING: Your timezone is not a multiple of 1 "
		        "minute.\n");
	}

	DEBUG("Serverzone is %d\n", serverzone);
}

/****************************************************************************
  return the UTC offset in seconds west of UTC, adjusted for extra time
  offset, for a local time value.  If ut = lt + loc_time_diff(lt), then
  lt = ut - time_diff(ut), but the converse does not necessarily hold near
  daylight savings transitions because some local times are ambiguous.
  loc_time_diff(t) equals time_diff(t) except near daylight savings transitions.
  +**************************************************************************/
static int loc_time_diff(time_t lte)
{
	time_t lt = lte;
	int d = time_zone(lt);
	time_t t = lt + d;

	/* if overflow occurred, ignore all the adjustments so far */
	if ((lte < lt) | ((t < lt) ^ (d < 0)))
		t = lte;

	/* now t should be close enough to the true UTC to yield the right
	 * answer */
	return time_zone(t);
}

#define TIME_FIXUP_CONSTANT                                                    \
	(369.0 * 365.25 * 24 * 60 * 60 - (3.0 * 24 * 60 * 60 + 6.0 * 60 * 60))

/****************************************************************************
interpret an 8 byte "filetime" structure to a time_t
It's originally in "100ns units since jan 1st 1601"

It appears to be kludge-GMT (at least for file listings). This means
its the GMT you get by taking a localtime and adding the
serverzone. This is NOT the same as GMT in some cases. This routine
converts this to real GMT.
****************************************************************************/
time_t interpret_long_date(char *p)
{
	double d;
	time_t ret;
	uint32_t tlow, thigh;
	/* The next two lines are a fix needed for the
	   broken SCO compiler. JRA. */
	time_t l_time_min = TIME_T_MIN;
	time_t l_time_max = TIME_T_MAX;

	tlow = IVAL(p, 0);
	thigh = IVAL(p, 4);

	if (thigh == 0)
		return 0;

	d = ((double) thigh) * 4.0 * (double) (1 << 30);
	d += (tlow & 0xFFF00000);
	d *= 1.0e-7;

	/* now adjust by 369 years to make the secs since 1970 */
	d -= TIME_FIXUP_CONSTANT;

	if (!(l_time_min <= d && d <= l_time_max))
		return 0;

	ret = (time_t) (d + 0.5);

	/* this takes us from kludge-GMT to real GMT */
	ret -= serverzone;
	ret += loc_time_diff(ret);

	return ret;
}

/****************************************************************************
put a 8 byte filetime from a time_t
This takes real GMT as input and converts to kludge-GMT
****************************************************************************/
void put_long_date(char *p, time_t t)
{
	uint32_t tlow, thigh;
	double d;

	if (t == 0) {
		SIVAL(p, 0, 0);
		SIVAL(p, 4, 0);
		return;
	}

	/* this converts GMT to kludge-GMT */
	t -= loc_time_diff(t) - serverzone;

	d = (double) (t);

	d += TIME_FIXUP_CONSTANT;

	d *= 1.0e7;

	thigh = (uint32_t) (d * (1.0 / (4.0 * (double) (1 << 30))));
	tlow = (uint32_t) (d - ((double) thigh) * 4.0 * (double) (1 << 30));

	SIVAL(p, 0, tlow);
	SIVAL(p, 4, thigh);
}

/****************************************************************************
check if it's a null mtime
****************************************************************************/
bool null_mtime(time_t mtime)
{
	if (mtime == 0 || mtime == 0xFFFFFFFF || mtime == (time_t) -1)
		return true;
	return false;
}

/*******************************************************************
  create a 16 bit dos packed date
********************************************************************/
static uint16_t make_dos_date1(time_t unixdate, struct tm *t)
{
	uint16_t ret = 0;
	ret = (((unsigned) (t->tm_mon + 1)) >> 3) | ((t->tm_year - 80) << 1);
	ret =
	    ((ret & 0xFF) << 8) | (t->tm_mday | (((t->tm_mon + 1) & 0x7) << 5));
	return ret;
}

/*******************************************************************
  create a 16 bit dos packed time
********************************************************************/
static uint16_t make_dos_time1(time_t unixdate, struct tm *t)
{
	uint16_t ret = 0;
	ret = ((((unsigned) t->tm_min >> 3) & 0x7) |
	       (((unsigned) t->tm_hour) << 3));
	ret =
	    ((ret & 0xFF) << 8) | ((t->tm_sec / 2) | ((t->tm_min & 0x7) << 5));
	return ret;
}

/*******************************************************************
  create a 32 bit dos packed date/time from some parameters
  This takes a GMT time and returns a packed localtime structure
********************************************************************/
static uint32_t make_dos_date(time_t unixdate)
{
	struct tm *t;
	uint32_t ret = 0;

	t = localtime(&unixdate);
	if (!t)
		return 0xFFFFFFFF;

	ret = make_dos_date1(unixdate, t);
	ret = ((ret & 0xFFFF) << 16) | make_dos_time1(unixdate, t);

	return ret;
}

/*******************************************************************
put a dos date into a buffer (time/date format)
This takes GMT time and puts local time in the buffer
********************************************************************/
void put_dos_date(char *buf, int offset, time_t unixdate)
{
	uint32_t x = make_dos_date(unixdate);
	SIVAL(buf, offset, x);
}

/*******************************************************************
put a dos date into a buffer (date/time format)
This takes GMT time and puts local time in the buffer
********************************************************************/
void put_dos_date2(char *buf, int offset, time_t unixdate)
{
	uint32_t x = make_dos_date(unixdate);
	x = ((x & 0xFFFF) << 16) | ((x & 0xFFFF0000) >> 16);
	SIVAL(buf, offset, x);
}

/*******************************************************************
put a dos 32 bit "unix like" date into a buffer. This routine takes
GMT and converts it to LOCAL time before putting it (most SMBs assume
localtime for this sort of date)
********************************************************************/
void put_dos_date3(char *buf, int offset, time_t unixdate)
{
	if (!null_mtime(unixdate))
		unixdate -= time_zone(unixdate);
	SIVAL(buf, offset, unixdate);
}

/*******************************************************************
  interpret a 32 bit dos packed date/time to some parameters
********************************************************************/
static void interpret_dos_date(uint32_t date, int *year, int *month, int *day,
                               int *hour, int *minute, int *second)
{
	uint32_t p0, p1, p2, p3;

	p0 = date & 0xFF;
	p1 = ((date & 0xFF00) >> 8) & 0xFF;
	p2 = ((date & 0xFF0000) >> 16) & 0xFF;
	p3 = ((date & 0xFF000000) >> 24) & 0xFF;

	*second = 2 * (p0 & 0x1F);
	*minute = ((p0 >> 5) & 0xFF) + ((p1 & 0x7) << 3);
	*hour = (p1 >> 3) & 0xFF;
	*day = (p2 & 0x1F);
	*month = ((p2 >> 5) & 0xFF) + ((p3 & 0x1) << 3) - 1;
	*year = ((p3 >> 1) & 0xFF) + 80;
}

/*******************************************************************
  create a unix date (int GMT) from a dos date (which is actually in
  localtime)
********************************************************************/
static time_t make_unix_date(void *date_ptr)
{
	uint32_t dos_date = 0;
	struct tm t;
	time_t ret;

	dos_date = IVAL(date_ptr, 0);

	if (dos_date == 0)
		return 0;

	interpret_dos_date(dos_date, &t.tm_year, &t.tm_mon, &t.tm_mday,
	                   &t.tm_hour, &t.tm_min, &t.tm_sec);
	t.tm_isdst = -1;

	/* mktime() also does the local to GMT time conversion for us */
	ret = mktime(&t);

	return ret;
}

/*******************************************************************
like make_unix_date() but the words are reversed
********************************************************************/
time_t make_unix_date2(void *date_ptr)
{
	uint32_t x, x2;

	x = IVAL(date_ptr, 0);
	x2 = ((x & 0xFFFF) << 16) | ((x & 0xFFFF0000) >> 16);
	SIVAL(&x, 0, x2);

	return make_unix_date((void *) &x);
}

/*******************************************************************
  create a unix GMT date from a dos date in 32 bit "unix like" format
  these generally arrive as localtimes, with corresponding DST
  ******************************************************************/
time_t make_unix_date3(void *date_ptr)
{
	time_t t = IVAL(date_ptr, 0);
	if (!null_mtime(t))
		t += loc_time_diff(t);
	return t;
}

/****************************************************************************
  return the date and time as a string
****************************************************************************/
char *timestring(void)
{
	static fstring time_buf;
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);

	if (!tm)
		snprintf(time_buf, sizeof(time_buf),
		         "%ld seconds since the Epoch", (long) t);
	else
		strftime(time_buf, 100, "%Y/%m/%d %r", tm);
	return time_buf;
}

/****************************************************************************
  return the best approximation to a 'create time' under UNIX from a stat
  structure.
****************************************************************************/

time_t get_create_time(struct stat *st)
{
	time_t ret, ret1;

	ret = MIN(st->st_ctime, st->st_mtime);
	ret1 = MIN(ret, st->st_atime);

	if (ret1 != (time_t) 0)
		return ret1;

	/*
	 * One of ctime, mtime or atime was zero (probably atime).
	 * Just return MIN(ctime, mtime).
	 */
	return ret;
}
