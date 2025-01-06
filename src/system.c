/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba system utilities
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

#include "includes.h"

extern int DEBUGLEVEL;

/*******************************************************************
now for utime()
********************************************************************/
int sys_utime(char *fname, struct utimbuf *times)
{
	/* if the modtime is 0 or -1 then ignore the call and
	   return success */
	if (times->modtime == (time_t) 0 || times->modtime == (time_t) -1)
		return 0;

	/* if the access time is 0 or -1 then set it to the modtime */
	if (times->actime == (time_t) 0 || times->actime == (time_t) -1)
		times->actime = times->modtime;

	return utime(fname, times);
}

/* Different OSes have different versions of getxattr */
ssize_t sys_getxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	return getxattr(path, name, value, size);
}

/* Different OSes have different versions of setxattr */
ssize_t sys_setxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	return setxattr(path, name, value, size, 0);
}
