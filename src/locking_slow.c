/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   slow (lockfile) locking implementation
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

   October 1997 - split into separate file (tridge)
*/

#include "includes.h"
extern int DEBUGLEVEL;
extern connection_struct Connections[];
extern files_struct Files[];

/*
 * Locking file header lengths & offsets.
 */
#define SMF_VERSION_OFFSET 0
#define SMF_NUM_ENTRIES_OFFSET 4
#define SMF_FILENAME_LEN_OFFSET 8
#define SMF_HEADER_LENGTH 10

#define SMF_ENTRY_LENGTH 20

/*
 * Share mode record offsets.
 */

#define SME_SEC_OFFSET 0
#define SME_USEC_OFFSET 4
#define SME_SHAREMODE_OFFSET 8
#define SME_PID_OFFSET 12
#define SME_PORT_OFFSET 16
#define SME_OPLOCK_TYPE_OFFSET 18

/* we need world read for smbstatus to function correctly */
#ifdef SECURE_SHARE_MODES
#define SHARE_FILE_MODE 0600
#else
#define SHARE_FILE_MODE 0644
#endif

static int read_only;

/*******************************************************************
  name a share file
  ******************************************************************/
static BOOL share_name(int cnum, uint32 dev, uint32 inode, char *name)
{
	int len;
	pstrcpy(name, lp_lockdir());
	trim_string(name, "", "/");
	if (!*name)
		return (False);
	len = strlen(name);
	name += len;

	slprintf(name, sizeof(pstring) - len - 1, "/share.%u.%u", dev, inode);
	return (True);
}

/*******************************************************************
Force a share file to be deleted.
********************************************************************/
static int delete_share_file(int cnum, char *fname)
{
	if (read_only)
		return -1;

	/* the share file could be owned by anyone, so do this as root */
	become_root(False);

	if (unlink(fname) != 0) {
		DEBUG(0,
		      ("delete_share_file: Can't delete share file %s (%s)\n",
		       fname, strerror(errno)));
	} else {
		DEBUG(5, ("delete_share_file: Deleted share file %s\n", fname));
	}

	/* return to our previous privilage level */
	unbecome_root(False);

	return 0;
}

/*******************************************************************
  lock a share mode file.
  ******************************************************************/
BOOL lock_share_entry(int cnum, uint32 dev, uint32 inode, int *ptok)
{
	pstring fname;
	int fd;
	int ret = True;

	*ptok = (int) -1;

	if (!share_name(cnum, dev, inode, fname))
		return False;

	if (read_only)
		return True;

	/* we need to do this as root */
	become_root(False);

	{
		BOOL gotlock = False;
		/*
		 * There was a race condition in the original slow share mode
		 * code. A smbd could open a share mode file, and before getting
		 * the lock, another smbd could delete the last entry for
		 * the share mode file and delete the file entry from the
		 * directory. Thus this smbd would be left with a locked
		 * share mode fd attached to a file that no longer had a
		 * directory entry. Thus another smbd would think that
		 * there were no outstanding opens on the file. To fix
		 * this we now check we can do a stat() call on the filename
		 * before allowing the lock to proceed, and back out completely
		 * and try the open again if we cannot.
		 * Jeremy Allison (jallison@whistle.com).
		 */

		do {
			struct stat dummy_stat;

			fd = (int) open(
			    fname, read_only ? O_RDONLY : (O_RDWR | O_CREAT),
			    SHARE_FILE_MODE);

			if (fd < 0) {
				DEBUG(0, ("ERROR lock_share_entry: failed to "
				          "open share file %s. Error was %s\n",
				          fname, strerror(errno)));
				ret = False;
				break;
			}

			/* At this point we have an open fd to the share mode
			  file. Lock the first byte exclusively to signify a
			  lock. */
			if (fcntl_lock(fd, F_SETLKW, 0, 1, F_WRLCK) == False) {
				DEBUG(0, ("ERROR lock_share_entry: fcntl_lock "
				          "on file %s failed with %s\n",
				          fname, strerror(errno)));
				close(fd);
				ret = False;
				break;
			}

			/*
			 * If we cannot stat the filename, the file was deleted
			 * between the open and the lock call. Back out and try
			 * again.
			 */

			if (stat(fname, &dummy_stat) != 0) {
				DEBUG(2, ("lock_share_entry: Re-issuing open "
				          "on %s to fix race. Error was %s\n",
				          fname, strerror(errno)));
				close(fd);
			} else
				gotlock = True;
		} while (!gotlock);

		/*
		 * We have to come here if any of the above calls fail
		 * as we don't want to return and leave ourselves running
		 * as root !
		 */
	}

	*ptok = (int) fd;

	/* return to our previous privilage level */
	unbecome_root(False);

	return ret;
}

/*******************************************************************
  unlock a share mode file.
  ******************************************************************/
BOOL unlock_share_entry(int cnum, uint32 dev, uint32 inode, int token)
{
	int fd = (int) token;
	int ret = True;
	struct stat sb;
	pstring fname;

	if (read_only)
		return True;

	/* Fix for zero length share files from
	   Gerald Werner <wernerg@mfldclin.edu> */

	share_name(cnum, dev, inode, fname);

	/* get the share mode file size */
	if (fstat((int) token, &sb) != 0) {
		DEBUG(0, ("ERROR: unlock_share_entry: Failed to do stat on "
		          "share file %s (%s)\n",
		          fname, strerror(errno)));
		sb.st_size = 1;
		ret = False;
	}

	/* If the file was zero length, we must delete before
	   doing the unlock to avoid a race condition (see
	   the code in lock_share_mode_entry for details.
	 */

	/* remove the share file if zero length */
	if (sb.st_size == 0)
		delete_share_file(cnum, fname);

	/* token is the fd of the open share mode file. */
	/* Unlock the first byte. */
	if (fcntl_lock(fd, F_SETLKW, 0, 1, F_UNLCK) == False) {
		DEBUG(0,
		      ("ERROR unlock_share_entry: fcntl_lock failed with %s\n",
		       strerror(errno)));
		ret = False;
	}

	close(fd);
	return ret;
}

/*******************************************************************
  initialize the slow share_mode management
  ******************************************************************/
BOOL locking_init(int ronly)
{
	read_only = ronly;

	if (!directory_exist(lp_lockdir(), NULL)) {
		if (!read_only)
			mkdir(lp_lockdir(), 0755);
		if (!directory_exist(lp_lockdir(), NULL))
			return False;
	}

	return True;
}
