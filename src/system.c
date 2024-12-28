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

/*
   The idea is that this file will eventually have wrappers around all
   important system calls in samba. The aims are:

   - to enable easier porting by putting OS dependent stuff in here

   - to allow for hooks into other "pseudo-filesystems"

   - to allow easier integration of things like the japanese extensions

   - to support the philosophy of Samba to expose the features of
     the OS within the SMB model. In general whatever file/printer/variable
     expansions/etc make sense to the OS should be acceptable to Samba.
*/

/*******************************************************************
this replaces the normal select() system call
return if some data has arrived on one of the file descriptors
return -1 means error
********************************************************************/
int sys_select(fd_set *fds, struct timeval *tval)
{
	struct timeval t2;
	int selrtn;

	do {
		if (tval)
			memcpy((void *) &t2, (void *) tval, sizeof(t2));
		errno = 0;
		selrtn =
		    select(255, SELECT_CAST fds, NULL, NULL, tval ? &t2 : NULL);
	} while (selrtn < 0 && errno == EINTR);

	return (selrtn);
}

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

/*********************************************************
for rename across filesystems Patch from Warren Birnbaum
<warrenb@hpcvscdp.cv.hp.com>
**********************************************************/

static int copy_reg(char *source, const char *dest)
{
	struct stat source_stats;
	int ifd;
	int ofd;
	char *buf;
	int len; /* Number of bytes read into `buf'. */

	lstat(source, &source_stats);
	if (!S_ISREG(source_stats.st_mode)) {
		return 1;
	}

	if (unlink(dest) && errno != ENOENT) {
		return 1;
	}

	if ((ifd = open(source, O_RDONLY, 0)) < 0) {
		return 1;
	}
	if ((ofd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
		close(ifd);
		return 1;
	}

	if ((buf = malloc(COPYBUF_SIZE)) == NULL) {
		close(ifd);
		close(ofd);
		unlink(dest);
		return 1;
	}

	while ((len = read(ifd, buf, COPYBUF_SIZE)) > 0) {
		if (write_data(ofd, buf, len) < 0) {
			close(ifd);
			close(ofd);
			unlink(dest);
			free(buf);
			return 1;
		}
	}
	free(buf);
	if (len < 0) {
		close(ifd);
		close(ofd);
		unlink(dest);
		return 1;
	}

	if (close(ifd) < 0) {
		close(ofd);
		return 1;
	}
	if (close(ofd) < 0) {
		return 1;
	}

	/* chown turns off set[ug]id bits for non-root,
	   so do the chmod last.  */

	/* Try to copy the old file's modtime and access time.  */
	{
		struct utimbuf tv;

		tv.actime = source_stats.st_atime;
		tv.modtime = source_stats.st_mtime;
		if (utime(dest, &tv)) {
			return 1;
		}
	}

	/* Try to preserve ownership.  For non-root it might fail, but that's
	   ok. But root probably wants to know, e.g. if NFS disallows it.  */
	if (chown(dest, source_stats.st_uid, source_stats.st_gid) &&
	    (errno != EPERM)) {
		return 1;
	}

	if (chmod(dest, source_stats.st_mode & 07777)) {
		return 1;
	}
	unlink(source);
	return 0;
}

/*******************************************************************
for rename()
********************************************************************/
int sys_rename(char *from, char *to)
{
	int rcode;
	pstring zfrom, zto;

	rcode = rename(from, to);

	if (errno == EXDEV) {
		/* Rename across filesystems needed. */
		rcode = copy_reg(zfrom, zto);
	}
	return rcode;
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
