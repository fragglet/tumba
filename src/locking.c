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
extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

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
		DEBUG(10, ("map_lock_type: Downgrading write lock to read due "
		           "to read-only file.\n"));
		return F_RDLCK;
	} else if ((lock_type == F_RDLCK) &&
	           (fsp->fd_ptr->real_open_flags == O_WRONLY)) {
		/*
		 * Ditto for read locks on write only files.
		 */
		DEBUG(10, ("map_lock_type: Changing read lock to write due to "
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
