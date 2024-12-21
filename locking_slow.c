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
  deinitialize share_mode management
  ******************************************************************/
static BOOL slow_stop_share_mode_mgmt(void)
{
	return True;
}

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
static BOOL slow_lock_share_entry(int cnum, uint32 dev, uint32 inode, int *ptok)
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
static BOOL slow_unlock_share_entry(int cnum, uint32 dev, uint32 inode,
                                    int token)
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
Read a share file into a buffer.
********************************************************************/
static int read_share_file(int cnum, int fd, char *fname, char **out,
                           BOOL *p_new_file)
{
	struct stat sb;
	char *buf;
	int size;

	*out = 0;
	*p_new_file = False;

	if (fstat(fd, &sb) != 0) {
		DEBUG(0, ("ERROR: read_share_file: Failed to do stat on share "
		          "file %s (%s)\n",
		          fname, strerror(errno)));
		return -1;
	}

	if (sb.st_size == 0) {
		*p_new_file = True;
		return 0;
	}

	/* Allocate space for the file */
	if ((buf = (char *) malloc(sb.st_size)) == NULL) {
		DEBUG(0, ("read_share_file: malloc for file size %d fail !\n",
		          sb.st_size));
		return -1;
	}

	if (lseek(fd, 0, SEEK_SET) != 0) {
		DEBUG(0,
		      ("ERROR: read_share_file: Failed to reset position to 0 \
for share file %s (%s)\n",
		       fname, strerror(errno)));
		if (buf)
			free(buf);
		return -1;
	}

	if (read(fd, buf, sb.st_size) != sb.st_size) {
		DEBUG(0, ("ERROR: read_share_file: Failed to read share file "
		          "%s (%s)\n",
		          fname, strerror(errno)));
		if (buf)
			free(buf);
		return -1;
	}

	if (IVAL(buf, SMF_VERSION_OFFSET) != LOCKING_VERSION) {
		DEBUG(0,
		      ("ERROR: read_share_file: share file %s has incorrect \
locking version (was %d, should be %d).\n",
		       fname, IVAL(buf, SMF_VERSION_OFFSET), LOCKING_VERSION));
		if (buf)
			free(buf);
		delete_share_file(cnum, fname);
		return -1;
	}

	/* Sanity check for file contents */
	size = sb.st_size;
	size -= SMF_HEADER_LENGTH; /* Remove the header */

	/* Remove the filename component. */
	size -= SVAL(buf, SMF_FILENAME_LEN_OFFSET);

	/* The remaining size must be a multiple of SMF_ENTRY_LENGTH - error if
	 * not. */
	if ((size % SMF_ENTRY_LENGTH) != 0) {
		DEBUG(
		    0,
		    ("ERROR: read_share_file: share file %s is an incorrect length - \
deleting it.\n",
		     fname));
		if (buf)
			free(buf);
		delete_share_file(cnum, fname);
		return -1;
	}

	*out = buf;
	return 0;
}

/*******************************************************************
Remove an oplock port and mode entry from a share mode.
********************************************************************/
static BOOL slow_remove_share_oplock(int fnum, int token)
{
	pstring fname;
	int fd = (int) token;
	char *buf = 0;
	char *base = 0;
	int num_entries;
	int fsize;
	int i;
	files_struct *fs_p = &Files[fnum];
	int pid;
	BOOL found = False;
	BOOL new_file;

	share_name(fs_p->cnum, fs_p->fd_ptr->dev, fs_p->fd_ptr->inode, fname);

	if (read_share_file(fs_p->cnum, fd, fname, &buf, &new_file) != 0) {
		DEBUG(0, ("ERROR: remove_share_oplock: Failed to read share "
		          "file %s\n",
		          fname));
		return False;
	}

	if (new_file == True) {
		DEBUG(
		    0,
		    ("ERROR: remove_share_oplock: share file %s is new (size zero), \
deleting it.\n",
		     fname));
		delete_share_file(fs_p->cnum, fname);
		return False;
	}

	num_entries = IVAL(buf, SMF_NUM_ENTRIES_OFFSET);

	DEBUG(
	    5,
	    ("remove_share_oplock: share file %s has %d share mode entries.\n",
	     fname, num_entries));

	/* PARANOIA TEST */
	if (num_entries < 0) {
		DEBUG(
		    0,
		    ("PANIC ERROR:remove_share_oplock: num_share_mode_entries < 0 (%d) \
for share file %s\n",
		     num_entries, fname));
		return False;
	}

	if (num_entries == 0) {
		/* No entries - just delete the file. */
		DEBUG(0, ("remove_share_oplock: share file %s has no share "
		          "mode entries - deleting.\n",
		          fname));
		if (buf)
			free(buf);
		delete_share_file(fs_p->cnum, fname);
		return False;
	}

	pid = getpid();

	/* Go through the entries looking for the particular one
	   we have set - remove the oplock settings on it.
	*/

	base = buf + SMF_HEADER_LENGTH + SVAL(buf, SMF_FILENAME_LEN_OFFSET);

	for (i = 0; i < num_entries; i++) {
		char *p = base + (i * SMF_ENTRY_LENGTH);

		if ((IVAL(p, SME_SEC_OFFSET) != fs_p->open_time.tv_sec) ||
		    (IVAL(p, SME_USEC_OFFSET) != fs_p->open_time.tv_usec) ||
		    (IVAL(p, SME_SHAREMODE_OFFSET) != fs_p->share_mode) ||
		    (IVAL(p, SME_PID_OFFSET) != pid))
			continue;

		DEBUG(
		    5,
		    ("remove_share_oplock: clearing oplock on entry number %d (of %d) \
from the share file %s\n",
		     i, num_entries, fname));

		SSVAL(p, SME_PORT_OFFSET, 0);
		SSVAL(p, SME_OPLOCK_TYPE_OFFSET, 0);
		found = True;
		break;
	}

	if (!found) {
		DEBUG(
		    0,
		    ("remove_share_oplock: entry not found in share file %s\n",
		     fname));
		if (buf)
			free(buf);
		return False;
	}

	/* Re-write the file - and truncate it at the correct point. */
	if (lseek(fd, 0, SEEK_SET) != 0) {
		DEBUG(0,
		      ("ERROR: remove_share_oplock: lseek failed to reset to \
position 0 for share mode file %s (%s)\n",
		       fname, strerror(errno)));
		if (buf)
			free(buf);
		return False;
	}

	fsize = (base - buf) + (SMF_ENTRY_LENGTH * num_entries);
	if (write(fd, buf, fsize) != fsize) {
		DEBUG(0,
		      ("ERROR: remove_share_oplock: failed to re-write share \
mode file %s (%s)\n",
		       fname, strerror(errno)));
		if (buf)
			free(buf);
		return False;
	}

	return True;
}

static struct share_ops share_ops = {
    slow_stop_share_mode_mgmt, slow_lock_share_entry, slow_unlock_share_entry,
    slow_remove_share_oplock,
};

/*******************************************************************
  initialize the slow share_mode management
  ******************************************************************/
struct share_ops *locking_slow_init(int ronly)
{

	read_only = ronly;

	if (!directory_exist(lp_lockdir(), NULL)) {
		if (!read_only)
			mkdir(lp_lockdir(), 0755);
		if (!directory_exist(lp_lockdir(), NULL))
			return NULL;
	}

	return &share_ops;
}
