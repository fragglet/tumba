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

#include "system.h"

#include <stddef.h>
#include <sys/types.h>
#include <utime.h>

#include "guards.h" /* IWYU pragma: keep */

/* Now for utime() */
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

/* xattrs are system-specific: */
#ifdef linux

#include <sys/xattr.h>

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

#elif defined(__APPLE__)

#include <sys/xattr.h>

ssize_t sys_getxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	return getxattr(path, name, value, size, 0, 0);
}

ssize_t sys_setxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	return setxattr(path, name, value, size, 0, 0);
}

#elif defined(__FreeBSD__) || defined(__NetBSD__)

#include <sys/extattr.h>

/* Different OSes have different versions of getxattr */
ssize_t sys_getxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	/* TODO: Skip past the "user." prefix since namespace is specified
	   differently with the BSD API? */
	return extattr_get_file(path, EXTATTR_NAMESPACE_USER, name, value,
	                        size);
}

/* Different OSes have different versions of setxattr */
ssize_t sys_setxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	return extattr_set_file(path, EXTATTR_NAMESPACE_USER, name, value,
	                        size);
}

#else

#include <errno.h>
#warning No xattr support - DOS a/h/s file attributes will not be preserved!

/* Different OSes have different versions of getxattr */
ssize_t sys_getxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	errno = ENOSYS;
	return -1;
}

/* Different OSes have different versions of setxattr */
ssize_t sys_setxattr(const char *path, const char *name, void *value,
                     size_t size)
{
	errno = ENOSYS;
	return -1;
}

#endif
