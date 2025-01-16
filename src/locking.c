/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Locking functions
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

   Revision History:

   12 aug 96: Erik.Devriendt@te6.siemens.be
   added support for shared memory implementation of share mode locking

   May 1997. Jeremy Allison (jallison@whistle.com). Modified share mode
   locking to deal with multiple share modes per open file.

   September 1997. Jeremy Allison (jallison@whistle.com). Added oplock
   support.

*/

#include "includes.h"
extern int LOGLEVEL;
extern files_struct Files[];

static bool fcntl_lock(int fd, int op, uint32_t offset, uint32_t count,
                       int type)
{
	struct flock lock;
	int ret;
	uint32_t mask = ((unsigned) 1 << 31);
	int32_t s_count = (int32_t) count;   /* Signed count. */
	int32_t s_offset = (int32_t) offset; /* Signed offset. */

	/* interpret negative counts as large numbers */
	if (s_count < 0)
		s_count &= ~mask;

	/* no negative offsets */
	if (s_offset < 0)
		s_offset &= ~mask;

	/* count + offset must be in range */
	while ((s_offset < 0 || (s_offset + s_count < 0)) && mask) {
		s_offset &= ~mask;
		mask = mask >> 1;
	}

	offset = (uint32_t) s_offset;
	count = (uint32_t) s_count;

	LOG(8, ("fcntl_lock %d %d %d %d %d\n", fd, op, (int) offset,
	        (int) count, type));

	lock.l_type = type;
	lock.l_whence = SEEK_SET;
	lock.l_start = (int) offset;
	lock.l_len = (int) count;
	lock.l_pid = 0;

	errno = 0;

	ret = fcntl(fd, op, &lock);

	if (errno != 0)
		INFO("fcntl lock gave errno %d (%s)\n", errno, strerror(errno));

	/* a lock query */
	if (op == F_GETLK) {
		if ((ret != -1) && (lock.l_type != F_UNLCK) &&
		    (lock.l_pid != 0) && (lock.l_pid != getpid())) {
			INFO("fd %d is locked by pid %d\n", fd, lock.l_pid);
			return true;
		}

		/* it must be not locked or locked by me */
		return false;
	}

	/* a lock set or unset */
	if (ret == -1) {
		INFO("lock failed at offset %d count %d op %d type %d (%s)\n",
		     offset, count, op, type, strerror(errno));

		/* perhaps it doesn't support this sort of locking?? */
		if (errno == EINVAL) {
			INFO("locking not supported? returning true\n");
			return true;
		}

		return false;
	}

	/* everything went OK */
	LOG(8, ("Lock call successful\n"));

	return true;
}

/****************************************************************************
 Utility function to map a lock type correctly depending on the real open
 mode of a file.
****************************************************************************/

static int map_lock_type(files_struct *fsp, int lock_type)
{
	if ((lock_type == F_WRLCK) &&
	    (fsp->fd_ptr->real_open_flags == O_RDONLY)) {
		/*
		 * Many UNIX's cannot get a write lock on a file opened
		 * read-only. Win32 locking semantics allow this. Do the best we
		 * can and attempt a read-only lock.
		 */
		LOG(10, ("map_lock_type: Downgrading write lock to read due "
		         "to read-only file.\n"));
		return F_RDLCK;
	} else if ((lock_type == F_RDLCK) &&
	           (fsp->fd_ptr->real_open_flags == O_WRONLY)) {
		/*
		 * Ditto for read locks on write only files.
		 */
		LOG(10, ("map_lock_type: Changing read lock to write due to "
		         "write-only file.\n"));
		return F_WRLCK;
	}

	/*
	 * This return should be the most normal, as we attempt
	 * to always open files read/write.
	 */

	return lock_type;
}

/****************************************************************************
 Utility function called by locking requests.
****************************************************************************/

bool do_lock(int fnum, int cnum, uint32_t count, uint32_t offset, int lock_type,
             int *eclass, uint32_t *ecode)
{
	bool ok = false;
	files_struct *fsp = &Files[fnum];

	if (count == 0) {
		*eclass = ERRDOS;
		*ecode = ERRnoaccess;
		return false;
	}

	if (OPEN_FNUM(fnum) && fsp->can_lock && (fsp->cnum == cnum))
		ok = fcntl_lock(fsp->fd_ptr->fd, F_SETLK, offset, count,
		                map_lock_type(fsp, lock_type));

	if (!ok) {
		*eclass = ERRDOS;
		*ecode = ERRlock;
		return false;
	}
	return true; /* Got lock */
}

/****************************************************************************
 Utility function called by unlocking requests.
****************************************************************************/

bool do_unlock(int fnum, int cnum, uint32_t count, uint32_t offset, int *eclass,
               uint32_t *ecode)
{
	bool ok = false;
	files_struct *fsp = &Files[fnum];

	if (OPEN_FNUM(fnum) && fsp->can_lock && (fsp->cnum == cnum))
		ok = fcntl_lock(fsp->fd_ptr->fd, F_SETLK, offset, count,
		                F_UNLCK);

	if (!ok) {
		*eclass = ERRDOS;
		*ecode = ERRlock;
		return false;
	}
	return true; /* Did unlock */
}
