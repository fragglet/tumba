/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
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
#include "trans2.h"

#define DOSATTRIB_NAME "user.DOSATTRIB"

#define MAX_MUX 50
#define MANGLED_STACK_SIZE 200

pstring servicesf = CONFIGFILE;
extern pstring debugf;
extern fstring myworkgroup;

char *InBuffer = NULL;
char *OutBuffer = NULL;
char *last_inbuf = NULL;

int am_parent = 1;
int atexit_set = 0;

/* the last message the was processed */
int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() smb_fn_name(last_message)

extern pstring scope;
extern int DEBUGLEVEL;
extern int case_default;
extern bool case_sensitive;
extern bool short_case_preserve;
time_t smb_last_time = (time_t) 0;

extern int smb_read_error;

connection_struct Connections[MAX_CONNECTIONS];
files_struct Files[MAX_OPEN_FILES];

/*
 * Indirection for file fd's. Needed as POSIX locking
 * is based on file/process, not fd/process.
 */
file_fd_struct FileFd[MAX_OPEN_FILES];
int max_file_fd_used = 0;

extern int Protocol;

/*
 * Size of data we can send to client. Set
 *  by the client for all protocols above CORE.
 *  Set by us for CORE protocol.
 */
int max_send = BUFFER_SIZE;
/*
 * Size of the data we can receive. Set by us.
 * Can be modified by the max xmit parameter.
 */
int max_recv = BUFFER_SIZE;

/* a fnum to use when chaining */
int chain_fnum = -1;

/* number of open connections */
static int num_connections_open = 0;

extern fstring remote_machine;

extern pstring OriginalDir;

/* these can be set by some functions to override the error codes */
int unix_ERR_class = SMB_SUCCESS;
int unix_ERR_code = 0;

extern int extra_time_offset;

extern pstring myhostname;

static int find_free_connection(int hash);

/* for readability... */
#define IS_DOS_READONLY(test_mode) (((test_mode) & aRONLY) != 0)
#define IS_DOS_DIR(test_mode) (((test_mode) & aDIR) != 0)
#define IS_DOS_ARCHIVE(test_mode) (((test_mode) & aARCH) != 0)
#define IS_DOS_SYSTEM(test_mode) (((test_mode) & aSYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode) (((test_mode) & aHIDDEN) != 0)

/****************************************************************************
  when exiting, take the whole family
****************************************************************************/
void *dflt_sig(void)
{
	exit_server("caught signal");
	return 0; /* Keep -Wall happy :-) */
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/
void killkids(void)
{
	if (am_parent)
		kill(0, SIGTERM);
}

/****************************************************************************
  change a dos mode to a unix mode
    base permission for files:
         everybody gets read bit set
         dos readonly is represented in unix by removing everyone's write bit
         Then apply create mask, then add force bits.
    base permission for directories:
         dos directory is represented in unix by unix's dir bit and the exec bit
         Then apply create mask, then add force bits.

  IMPORTANT NOTE: this function will not convert the s, h, or a attributes;
  they are read and written separately using {read,write}_dosattrib below.
****************************************************************************/
mode_t unix_mode(int cnum, int dosmode)
{
	mode_t result = (S_IRUSR | S_IRGRP | S_IROTH);

	if (!IS_DOS_READONLY(dosmode))
		result |= (S_IWUSR | S_IWGRP | S_IWOTH);

	if (IS_DOS_DIR(dosmode)) {
		/* We never make directories read only for the owner as under
		   DOS a user can always create a file in a read-only directory.
		 */
		result |= (S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH | S_IWUSR);
		/* Apply directory mask */
		result &= lp_dir_mode(SNUM(cnum));
		/* Add in force bits */
		result |= lp_force_dir_mode(SNUM(cnum));
	} else {
		/* Apply mode mask */
		result &= lp_create_mode(SNUM(cnum));
		/* Add in force bits */
		result |= lp_force_create_mode(SNUM(cnum));
	}
	return (result);
}

int read_dosattrib(const char *path)
{
	char buf[5];
	ssize_t nbytes;

	nbytes = sys_getxattr(path, DOSATTRIB_NAME, buf, sizeof(buf));
	if (nbytes < 3 || nbytes > 4) {
		return 0;
	}
	buf[nbytes] = '\0';

	if (strncmp(buf, "0x", 2) != 0) {
		/* TODO: Maybe support newer versions */
		return 0;
	}

	return strtol(buf + 2, NULL, 16) & (aARCH|aSYSTEM|aHIDDEN);
}

void write_dosattrib(const char *path, int attrib)
{
	char buf[5];

	snprintf(buf, sizeof(buf), "0x%02x", attrib);
	sys_setxattr(path, DOSATTRIB_NAME, buf, strlen(buf));
}

/****************************************************************************
  change a unix mode to a dos mode
****************************************************************************/
int dos_mode(int cnum, char *path, struct stat *sbuf)
{
	int result = 0;
	extern struct current_user current_user;

	DEBUG(8, ("dos_mode: %d %s\n", cnum, path));

	if (CAN_WRITE(cnum)) {
		if (!((sbuf->st_mode & S_IWOTH) ||
		      ((sbuf->st_mode & S_IWUSR) &&
		       current_user.uid == sbuf->st_uid))) {
			result |= aRONLY;
		}
	} else if ((sbuf->st_mode & S_IWUSR) == 0) {
		result |= aRONLY;
	}

	result = read_dosattrib(path);

	if (S_ISDIR(sbuf->st_mode))
		result = aDIR | (result & aRONLY);

	/* hide files with a name starting with a . */
	if (lp_hide_dot_files(SNUM(cnum))) {
		char *p = strrchr(path, '/');
		if (p)
			p++;
		else
			p = path;

		if (p[0] == '.' && p[1] != '.' && p[1] != 0)
			result |= aHIDDEN;
	}

	DEBUG(8, ("dos_mode returning "));

	if (result & aHIDDEN)
		DEBUG(8, ("h"));
	if (result & aRONLY)
		DEBUG(8, ("r"));
	if (result & aSYSTEM)
		DEBUG(8, ("s"));
	if (result & aDIR)
		DEBUG(8, ("d"));
	if (result & aARCH)
		DEBUG(8, ("a"));

	DEBUG(8, ("\n"));

	return (result);
}

/*******************************************************************
chmod a file - but preserve some bits
********************************************************************/
int dos_chmod(int cnum, char *fname, int dosmode, struct stat *st)
{
	struct stat st1;
	int mask = 0;
	int tmp;
	int unixmode;

	if (!st) {
		st = &st1;
		if (stat(fname, st))
			return (-1);
	}

	if (S_ISDIR(st->st_mode))
		dosmode |= aDIR;

	if (dos_mode(cnum, fname, st) == dosmode)
		return (0);

	unixmode = unix_mode(cnum, dosmode);

	/* preserve the s bits */
	mask |= (S_ISUID | S_ISGID);

	/* preserve the t bit */
#ifdef S_ISVTX
	mask |= S_ISVTX;
#endif
	write_dosattrib(fname, dosmode);

	unixmode |= (st->st_mode & mask);

	/* if we previously had any r bits set then leave them alone */
	if ((tmp = st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH))) {
		unixmode &= ~(S_IRUSR | S_IRGRP | S_IROTH);
		unixmode |= tmp;
	}

	/* if we previously had any w bits set then leave them alone
	 if the new mode is not rdonly */
	if (!IS_DOS_READONLY(dosmode) &&
	    (tmp = st->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))) {
		unixmode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
		unixmode |= tmp;
	}

	return (chmod(fname, unixmode));
}

/*******************************************************************
Wrapper around sys_utime that possibly allows DOS semantics rather
than POSIX.
*******************************************************************/

int file_utime(int cnum, char *fname, struct utimbuf *times)
{
	extern struct current_user current_user;
	struct stat sb;
	int ret = -1;

	errno = 0;

	if (sys_utime(fname, times) == 0)
		return 0;

	if ((errno != EPERM) && (errno != EACCES))
		return -1;

	if (!lp_dos_filetimes(SNUM(cnum)))
		return -1;

	/* We have permission (given by the Samba admin) to
	   break POSIX semantics and allow a user to change
	   the time on a file they don't own but can write to
	   (as DOS does).
	 */

	if (stat(fname, &sb) != 0)
		return -1;

	/* Check if we have write access. */
	if (CAN_WRITE(cnum)) {
		if (((sb.st_mode & S_IWOTH) ||
		     ((sb.st_mode & S_IWUSR) &&
		      current_user.uid == sb.st_uid))) {
			/* We are allowed to become root and change the
			 * filetime. */
			become_root(false);
			ret = sys_utime(fname, times);
			unbecome_root(false);
		}
	}

	return ret;
}

/*******************************************************************
Change a filetime - possibly allowing DOS semantics.
*******************************************************************/

bool set_filetime(int cnum, char *fname, time_t mtime)
{
	struct utimbuf times;

	if (null_mtime(mtime))
		return (true);

	times.modtime = times.actime = mtime;

	if (file_utime(cnum, fname, &times)) {
		DEBUG(4, ("set_filetime(%s) failed: %s\n", fname,
		          strerror(errno)));
	}

	return (true);
}

/****************************************************************************
check if two filenames are equal

this needs to be careful about whether we are case sensitive
****************************************************************************/
static bool fname_equal(char *name1, char *name2)
{
	int l1 = strlen(name1);
	int l2 = strlen(name2);

	/* handle filenames ending in a single dot */
	if (l1 - l2 == 1 && name1[l1 - 1] == '.' && lp_strip_dot()) {
		bool ret;
		name1[l1 - 1] = 0;
		ret = fname_equal(name1, name2);
		name1[l1 - 1] = '.';
		return (ret);
	}

	if (l2 - l1 == 1 && name2[l2 - 1] == '.' && lp_strip_dot()) {
		bool ret;
		name2[l2 - 1] = 0;
		ret = fname_equal(name1, name2);
		name2[l2 - 1] = '.';
		return (ret);
	}

	/* now normal filename handling */
	if (case_sensitive)
		return (strcmp(name1, name2) == 0);

	return (strequal(name1, name2));
}

/****************************************************************************
mangle the 2nd name and check if it is then equal to the first name
****************************************************************************/
static bool mangled_equal(char *name1, char *name2)
{
	pstring tmpname;

	if (is_8_3(name2, true))
		return (false);

	pstrcpy(tmpname, name2);
	mangle_name_83(tmpname, sizeof(pstring) - 1);

	return (strequal(name1, tmpname));
}

/****************************************************************************
scan a directory to find a filename, matching without case sensitivity

If the name looks like a mangled name then try via the mangling functions
****************************************************************************/
static bool scan_directory(char *path, char *name, int cnum, bool docache)
{
	void *cur_dir;
	char *dname;
	bool mangled;
	pstring name2;

	mangled = is_mangled(name);

	/* handle null paths */
	if (*path == 0)
		path = ".";

	if (docache && (dname = DirCacheCheck(path, name, SNUM(cnum)))) {
		pstrcpy(name, dname);
		return (true);
	}

	/*
	 * The incoming name can be mangled, and if we de-mangle it
	 * here it will not compare correctly against the filename (name2)
	 * read from the directory and then mangled by the name_map_mangle()
	 * call. We need to mangle both names or neither.
	 * (JRA).
	 */
	if (mangled)
		mangled = !check_mangled_stack(name);

	/* open the directory */
	if (!(cur_dir = OpenDir(cnum, path))) {
		DEBUG(3, ("scan dir didn't open dir [%s]\n", path));
		return (false);
	}

	/* now scan for matching names */
	while ((dname = ReadDirName(cur_dir))) {
		if (*dname == '.' &&
		    (strequal(dname, ".") || strequal(dname, "..")))
			continue;

		pstrcpy(name2, dname);
		name_map_mangle(name2, false, SNUM(cnum));

		if ((mangled && mangled_equal(name, name2)) ||
		    fname_equal(name, name2)) {
			/* we've found the file, change it's name and return */
			if (docache)
				DirCacheAdd(path, name, dname, SNUM(cnum));
			pstrcpy(name, dname);
			CloseDir(cur_dir);
			return (true);
		}
	}

	CloseDir(cur_dir);
	return (false);
}

/****************************************************************************
This routine is called to convert names from the dos namespace to unix
namespace. It needs to handle any case conversions, mangling, format
changes etc.

We assume that we have already done a chdir() to the right "root" directory
for this service.

The function will return false if some part of the name except for the last
part cannot be resolved

If the saved_last_component != 0, then the unmodified last component
of the pathname is returned there. This is used in an exceptional
case in reply_mv (so far). If saved_last_component == 0 then nothing
is returned there.

The bad_path arg is set to true if the filename walk failed. This is
used to pick the correct error code to return between ENOENT and ENOTDIR
as Windows applications depend on ERRbadpath being returned if a component
of a pathname does not exist.
****************************************************************************/
bool unix_convert(char *name, int cnum, pstring saved_last_component,
                  bool *bad_path)
{
	struct stat st;
	char *start, *end;
	pstring dirpath;
	int saved_errno;

	*dirpath = 0;
	*bad_path = false;

	if (saved_last_component)
		*saved_last_component = 0;

	/* convert to basic unix format - removing \ chars and cleaning it up */
	unix_format(name);
	unix_clean_name(name);

	/* names must be relative to the root of the service - trim any leading
	 /. also trim trailing /'s */
	trim_string(name, "/", "/");

	/*
	 * Ensure saved_last_component is valid even if file exists.
	 */
	if (saved_last_component) {
		end = strrchr(name, '/');
		if (end)
			pstrcpy(saved_last_component, end + 1);
		else
			pstrcpy(saved_last_component, name);
	}

	if (!case_sensitive && is_8_3(name, false) && !short_case_preserve)
		strnorm(name);

	/* stat the name - if it exists then we are all done! */
	if (stat(name, &st) == 0)
		return (true);

	saved_errno = errno;

	DEBUG(5, ("unix_convert(%s,%d)\n", name, cnum));

	/* a special case - if we don't have any mangling chars and are case
	   sensitive then searching won't help */
	if (case_sensitive && !is_mangled(name) && !lp_strip_dot() &&
	    saved_errno != ENOENT)
		return (false);

	/* now we need to recursively match the name against the real
	   directory structure */

	start = name;
	while (strncmp(start, "./", 2) == 0)
		start += 2;

	/* now match each part of the path name separately, trying the names
	   as is first, then trying to scan the directory for matching names */
	for (; start; start = (end ? end + 1 : (char *) NULL)) {
		/* pinpoint the end of this section of the filename */
		end = strchr(start, '/');

		/* chop the name at this point */
		if (end)
			*end = 0;

		if (saved_last_component != 0)
			pstrcpy(saved_last_component, end ? end + 1 : start);

		/* check if the name exists up to this point */
		if (stat(name, &st) == 0) {
			/* it exists. it must either be a directory or this must
			   be the last part of the path for it to be OK */
			if (end && !(st.st_mode & S_IFDIR)) {
				/* an intermediate part of the name isn't a
				 * directory */
				DEBUG(5, ("Not a dir %s\n", start));
				*end = '/';
				return (false);
			}
		} else {
			pstring rest;

			*rest = 0;

			/* remember the rest of the pathname so it can be
			   restored later */
			if (end)
				pstrcpy(rest, end + 1);

			/* try to find this part of the path in the directory */
			if (strchr(start, '?') || strchr(start, '*') ||
			    !scan_directory(dirpath, start, cnum,
			                    end ? true : false)) {
				if (end) {
					/* an intermediate part of the name
					 * can't be found */
					DEBUG(5, ("Intermediate not found %s\n",
					          start));
					*end = '/';
					/* We need to return the fact that the
					   intermediate name resolution failed.
					   This is used to return an error of
					   ERRbadpath rather than ERRbadfile.
					   Some Windows applications depend on
					   the difference between these two
					   errors.
					 */
					*bad_path = true;
					return (false);
				}

				/* just the last part of the name doesn't exist
				 */

				/* check on the mangled stack to see if we can
				   recover the base of the filename */
				if (is_mangled(start))
					check_mangled_stack(start);

				DEBUG(5, ("New file %s\n", start));
				return (true);
			}

			/* restore the rest of the string */
			if (end) {
				pstrcpy(start + strlen(start) + 1, rest);
				end = start + strlen(start);
			}
		}

		/* add to the dirpath that we have resolved so far */
		if (*dirpath)
			pstrcat(dirpath, "/");
		pstrcat(dirpath, start);

		/* restore the / that we wiped out earlier */
		if (end)
			*end = '/';
	}

	/* the name has been resolved */
	DEBUG(5, ("conversion finished %s\n", name));
	return (true);
}

/****************************************************************************
  return number of 1K blocks available on a path and total number
****************************************************************************/
int disk_free(char *path, int *bsize, int *dfree, int *dsize)
{
	/* Don't bother. We always say it's a 1GiB disk with 512MiB free.
	   Disks nowadays are so large that it would probably overflow the
	   value anyway. */
	*bsize = 32768;
	*dfree = (512 * 1024 * 1024) / *bsize;
	*dsize = (1024 * 1024 * 1024) / *bsize;
	return 0;
}

/****************************************************************************
wrap it to get filenames right
****************************************************************************/
int sys_disk_free(char *path, int *bsize, int *dfree, int *dsize)
{
	return disk_free(path, bsize, dfree, dsize);
}

/****************************************************************************
check a filename - possibly caling reducename

This is called by every routine before it allows an operation on a filename.
It does any final confirmation necessary to ensure that the filename is
a valid one for the user to access.
****************************************************************************/
bool check_name(char *name, int cnum)
{
	bool ret;

	errno = 0;

	ret = reduce_name(name, Connections[cnum].connectpath,
	                  lp_widelinks(SNUM(cnum)));

	/* Check if we are allowing users to follow symlinks */
	/* Patch from David Clerc <David.Clerc@cui.unige.ch>
	   University of Geneva */
	if (!lp_symlinks(SNUM(cnum))) {
		struct stat statbuf;
		if ((lstat(name, &statbuf) != -1) &&
		    (S_ISLNK(statbuf.st_mode))) {
			DEBUG(3, ("check_name: denied: file path name %s is a "
			          "symlink\n",
			          name));
			ret = 0;
		}
	}

	if (!ret)
		DEBUG(5, ("check_name on %s failed\n", name));

	return (ret);
}

/****************************************************************************
check a filename - possibly caling reducename
****************************************************************************/
static void check_for_pipe(char *fname)
{
	/* special case of pipe opens */
	char s[10];
	StrnCpy(s, fname, 9);
	strlower(s);
	if (strstr(s, "pipe/")) {
		DEBUG(3, ("Rejecting named pipe open for %s\n", fname));
		unix_ERR_class = ERRSRV;
		unix_ERR_code = ERRaccess;
	}
}

/****************************************************************************
fd support routines - attempt to do a open
****************************************************************************/
static int fd_attempt_open(char *fname, int flags, int mode)
{
	int fd = open(fname, flags, mode);

	/* Fix for files ending in '.' */
	if ((fd == -1) && (errno == ENOENT) && (strchr(fname, '.') == NULL)) {
		pstrcat(fname, ".");
		fd = open(fname, flags, mode);
	}

	if ((fd == -1) && (errno == ENAMETOOLONG)) {
		int max_len;
		char *p = strrchr(fname, '/');

		if (p == fname) /* name is "/xxx" */
		{
			max_len = pathconf("/", _PC_NAME_MAX);
			p++;
		} else if ((p == NULL) || (p == fname)) {
			p = fname;
			max_len = pathconf(".", _PC_NAME_MAX);
		} else {
			*p = '\0';
			max_len = pathconf(fname, _PC_NAME_MAX);
			*p = '/';
			p++;
		}
		if (strlen(p) > max_len) {
			char tmp = p[max_len];

			p[max_len] = '\0';
			if ((fd = open(fname, flags, mode)) == -1)
				p[max_len] = tmp;
		}
	}
	return fd;
}

/****************************************************************************
fd support routines - attempt to find an already open file by dev
and inode - increments the ref_count of the returned file_fd_struct *.
****************************************************************************/
static file_fd_struct *fd_get_already_open(struct stat *sbuf)
{
	int i;
	file_fd_struct *fd_ptr;

	if (sbuf == 0)
		return 0;

	for (i = 0; i <= max_file_fd_used; i++) {
		fd_ptr = &FileFd[i];
		if ((fd_ptr->ref_count > 0) &&
		    (((uint32_t) sbuf->st_dev) == fd_ptr->dev) &&
		    (((uint32_t) sbuf->st_ino) == fd_ptr->inode)) {
			fd_ptr->ref_count++;
			DEBUG(3, ("Re-used file_fd_struct %d, dev = %x, inode "
			          "= %x, ref_count = %d\n",
			          i, fd_ptr->dev, fd_ptr->inode,
			          fd_ptr->ref_count));
			return fd_ptr;
		}
	}
	return 0;
}

/****************************************************************************
fd support routines - attempt to find a empty slot in the FileFd array.
Increments the ref_count of the returned entry.
****************************************************************************/
static file_fd_struct *fd_get_new(void)
{
	extern struct current_user current_user;
	int i;
	file_fd_struct *fd_ptr;

	for (i = 0; i < MAX_OPEN_FILES; i++) {
		fd_ptr = &FileFd[i];
		if (fd_ptr->ref_count == 0) {
			fd_ptr->dev = (uint32_t) -1;
			fd_ptr->inode = (uint32_t) -1;
			fd_ptr->fd = -1;
			fd_ptr->fd_readonly = -1;
			fd_ptr->fd_writeonly = -1;
			fd_ptr->real_open_flags = -1;
			fd_ptr->ref_count++;
			/* Increment max used counter if neccessary, cuts down
			   on search time when re-using */
			if (i > max_file_fd_used)
				max_file_fd_used = i;
			DEBUG(3, ("Allocated new file_fd_struct %d, dev = %x, "
			          "inode = %x\n",
			          i, fd_ptr->dev, fd_ptr->inode));
			return fd_ptr;
		}
	}
	DEBUG(1, ("ERROR! Out of file_fd structures - perhaps increase "
	          "MAX_OPEN_FILES?\n"));
	return 0;
}

/****************************************************************************
fd support routines - attempt to re-open an already open fd as O_RDWR.
Save the already open fd (we cannot close due to POSIX file locking braindamage.
****************************************************************************/
static void fd_attempt_reopen(char *fname, int mode, file_fd_struct *fd_ptr)
{
	int fd = open(fname, O_RDWR, mode);

	if (fd == -1)
		return;

	if (fd_ptr->real_open_flags == O_RDONLY)
		fd_ptr->fd_readonly = fd_ptr->fd;
	if (fd_ptr->real_open_flags == O_WRONLY)
		fd_ptr->fd_writeonly = fd_ptr->fd;

	fd_ptr->fd = fd;
	fd_ptr->real_open_flags = O_RDWR;
}

/****************************************************************************
fd support routines - attempt to close the file referenced by this fd.
Decrements the ref_count and returns it.
****************************************************************************/
static int fd_attempt_close(file_fd_struct *fd_ptr)
{
	extern struct current_user current_user;

	DEBUG(3, ("fd_attempt_close on file_fd_struct %d, fd = %d, dev = %x, "
	          "inode = %x, open_flags = %d, ref_count = %d.\n",
	          fd_ptr - &FileFd[0], fd_ptr->fd, fd_ptr->dev, fd_ptr->inode,
	          fd_ptr->real_open_flags, fd_ptr->ref_count));
	if (fd_ptr->ref_count > 0) {
		fd_ptr->ref_count--;
		if (fd_ptr->ref_count == 0) {
			if (fd_ptr->fd != -1)
				close(fd_ptr->fd);
			if (fd_ptr->fd_readonly != -1)
				close(fd_ptr->fd_readonly);
			if (fd_ptr->fd_writeonly != -1)
				close(fd_ptr->fd_writeonly);
			fd_ptr->fd = -1;
			fd_ptr->fd_readonly = -1;
			fd_ptr->fd_writeonly = -1;
			fd_ptr->real_open_flags = -1;
			fd_ptr->dev = (uint32_t) -1;
			fd_ptr->inode = (uint32_t) -1;
		}
	}
	return fd_ptr->ref_count;
}

/****************************************************************************
open a file
****************************************************************************/
static void open_file(int fnum, int cnum, char *fname1, int flags, int mode,
                      struct stat *sbuf)
{
	extern struct current_user current_user;
	pstring fname;
	struct stat statbuf;
	file_fd_struct *fd_ptr;
	files_struct *fsp = &Files[fnum];
	int accmode = (flags & (O_RDONLY | O_WRONLY | O_RDWR));

	fsp->open = false;
	fsp->fd_ptr = 0;
	errno = EPERM;

	pstrcpy(fname, fname1);

	/* check permissions */

	/*
	 * This code was changed after seeing a client open request
	 * containing the open mode of (DENY_WRITE/read-only) with
	 * the 'create if not exist' bit set. The previous code
	 * would fail to open the file read only on a read-only share
	 * as it was checking the flags parameter  directly against O_RDONLY,
	 * this was failing as the flags parameter was set to O_RDONLY|O_CREAT.
	 * JRA.
	 */

	if (!CAN_WRITE(cnum)) {
		/* It's a read-only share - fail if we wanted to write. */
		if (accmode != O_RDONLY) {
			DEBUG(3, ("Permission denied opening %s\n", fname));
			check_for_pipe(fname);
			return;
		} else if (flags & O_CREAT) {
			/* We don't want to write - but we must make sure that
			   O_CREAT doesn't create the file if we have write
			   access into the directory.
			 */
			flags &= ~O_CREAT;
		}
	}

	/*
	  if (flags == O_WRONLY)
	    DEBUG(3,("Bug in client? Set O_WRONLY without O_CREAT\n"));
	*/

	/*
	 * Ensure we have a valid struct stat so we can search the
	 * open fd table.
	 */
	if (sbuf == 0) {
		if (stat(fname, &statbuf) < 0) {
			if (errno != ENOENT) {
				DEBUG(3, ("Error doing stat on file %s (%s)\n",
				          fname, strerror(errno)));

				check_for_pipe(fname);
				return;
			}
			sbuf = 0;
		} else {
			sbuf = &statbuf;
		}
	}

	/*
	 * Check to see if we have this file already
	 * open. If we do, just use the already open fd and increment the
	 * reference count (fd_get_already_open increments the ref_count).
	 */
	if ((fd_ptr = fd_get_already_open(sbuf)) != 0) {
		/*
		 * File was already open.
		 */

		/*
		 * Check it wasn't open for exclusive use.
		 */
		if ((flags & O_CREAT) && (flags & O_EXCL)) {
			fd_ptr->ref_count--;
			errno = EEXIST;
			return;
		}

		/*
		 * If not opened O_RDWR try
		 * and do that here - a chmod may have been done
		 * between the last open and now.
		 */
		if (fd_ptr->real_open_flags != O_RDWR)
			fd_attempt_reopen(fname, mode, fd_ptr);

		/*
		 * Ensure that if we wanted write access
		 * it has been opened for write, and if we wanted read it
		 * was open for read.
		 */
		if (((accmode == O_WRONLY) &&
		     (fd_ptr->real_open_flags == O_RDONLY)) ||
		    ((accmode == O_RDONLY) &&
		     (fd_ptr->real_open_flags == O_WRONLY)) ||
		    ((accmode == O_RDWR) &&
		     (fd_ptr->real_open_flags != O_RDWR))) {
			DEBUG(3, ("Error opening (already open for flags=%d) "
			          "file %s (%s) (flags=%d)\n",
			          fd_ptr->real_open_flags, fname,
			          strerror(EACCES), flags));
			check_for_pipe(fname);
			fd_ptr->ref_count--;
			return;
		}

	} else {
		int open_flags;
		/* We need to allocate a new file_fd_struct (this increments the
		   ref_count). */
		if ((fd_ptr = fd_get_new()) == 0)
			return;
		/*
		 * Whatever the requested flags, attempt read/write access,
		 * as we don't know what flags future file opens may require.
		 * If this fails, try again with the required flags.
		 * Even if we open read/write when only read access was
		 * requested the setting of the can_write flag in
		 * the file_struct will protect us from errant
		 * write requests. We never need to worry about O_APPEND
		 * as this is not set anywhere in Samba.
		 */
		fd_ptr->real_open_flags = O_RDWR;
		/* Set the flags as needed without the read/write modes. */
		open_flags = flags & ~(O_RDWR | O_WRONLY | O_RDONLY);
		fd_ptr->fd = fd_attempt_open(fname, open_flags | O_RDWR, mode);
		/*
		 * On some systems opening a file for R/W access on a read only
		 * filesystems sets errno to EROFS.
		 */
#ifdef EROFS
		if ((fd_ptr->fd == -1) &&
		    ((errno == EACCES) || (errno == EROFS))) {
#else  /* No EROFS */
		if ((fd_ptr->fd == -1) && (errno == EACCES)) {
#endif /* EROFS */
			if (accmode != O_RDWR) {
				fd_ptr->fd = fd_attempt_open(
				    fname, open_flags | accmode, mode);
				fd_ptr->real_open_flags = accmode;
			}
		}
	}

	if (fd_ptr->fd < 0) {
		DEBUG(3, ("Error opening file %s (%s) (flags=%d)\n", fname,
		          strerror(errno), flags));
		/* Ensure the ref_count is decremented. */
		fd_attempt_close(fd_ptr);
		check_for_pipe(fname);
		return;
	}

	if (fd_ptr->fd >= 0) {
		if (sbuf == 0) {
			/* Do the fstat */
			if (fstat(fd_ptr->fd, &statbuf) == -1) {
				/* Error - backout !! */
				DEBUG(3, ("Error doing fstat on fd %d, file %s "
				          "(%s)\n",
				          fd_ptr->fd, fname, strerror(errno)));
				/* Ensure the ref_count is decremented. */
				fd_attempt_close(fd_ptr);
				return;
			}
			sbuf = &statbuf;
		}

		/* Set the correct entries in fd_ptr. */
		fd_ptr->dev = (uint32_t) sbuf->st_dev;
		fd_ptr->inode = (uint32_t) sbuf->st_ino;

		fsp->fd_ptr = fd_ptr;
		Connections[cnum].num_files_open++;
		fsp->mode = sbuf->st_mode;
		gettimeofday(&fsp->open_time, NULL);
		fsp->size = 0;
		fsp->pos = -1;
		fsp->open = true;
		fsp->mmap_ptr = NULL;
		fsp->mmap_size = 0;
		fsp->can_lock = true;
		fsp->can_read = ((flags & O_WRONLY) == 0);
		fsp->can_write = ((flags & (O_WRONLY | O_RDWR)) != 0);
		fsp->share_mode = 0;
		fsp->modified = false;
		fsp->cnum = cnum;
		string_set(&fsp->name, fname);
		fsp->wbmpx_ptr = NULL;

		DEBUG(2, ("%s %s opened file %s read=%s write=%s (numopen=%d "
		          "fnum=%d)\n",
		          timestring(), Connections[cnum].user, fname,
		          BOOLSTR(fsp->can_read), BOOLSTR(fsp->can_write),
		          Connections[cnum].num_files_open, fnum));
	}

#if USE_MMAP
	/* mmap it if read-only */
	if (!fsp->can_write) {
		fsp->mmap_size = file_size(fname);
		fsp->mmap_ptr = (char *) mmap(NULL, fsp->mmap_size, PROT_READ,
		                              MAP_SHARED, fsp->fd_ptr->fd, 0);

		if (fsp->mmap_ptr == (char *) -1 || !fsp->mmap_ptr) {
			DEBUG(3, ("Failed to mmap() %s - %s\n", fname,
			          strerror(errno)));
			fsp->mmap_ptr = NULL;
		}
	}
#endif
}

/****************************************************************************
close a file - possibly invalidating the read prediction

If normal_close is 1 then this came from a normal SMBclose (or equivalent)
operation otherwise it came as the result of some other operation such as
the closing of the connection. In the latter case printing and
magic scripts are not run
****************************************************************************/
void close_file(int fnum, bool normal_close)
{
	files_struct *fs_p = &Files[fnum];
	int cnum = fs_p->cnum;

	Files[fnum].reserved = false;

	fs_p->open = false;
	Connections[cnum].num_files_open--;
	if (fs_p->wbmpx_ptr) {
		free((char *) fs_p->wbmpx_ptr);
		fs_p->wbmpx_ptr = NULL;
	}

#if USE_MMAP
	if (fs_p->mmap_ptr) {
		munmap(fs_p->mmap_ptr, fs_p->mmap_size);
		fs_p->mmap_ptr = NULL;
	}
#endif

	fd_attempt_close(fs_p->fd_ptr);

	DEBUG(2, ("%s %s closed file %s (numopen=%d)\n", timestring(),
	          Connections[cnum].user, fs_p->name,
	          Connections[cnum].num_files_open));

	if (fs_p->name) {
		string_free(&fs_p->name);
	}

	/* we will catch bugs faster by zeroing this structure */
	memset(fs_p, 0, sizeof(*fs_p));
}

/****************************************************************************
  C. Hoch 11/22/95
  Helper for open_file_shared.
  Truncate a file after checking locking; close file if locked.
  **************************************************************************/
static void truncate_unless_locked(int fnum, int cnum, int token,
                                   bool *share_locked)
{
	if (Files[fnum].can_write) {
		if (is_locked(fnum, cnum, 0x3FFFFFFF, 0, F_WRLCK)) {
			close_file(fnum, false);
			/* Share mode no longer locked. */
			*share_locked = false;
			errno = EACCES;
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRlock;
		} else
			ftruncate(Files[fnum].fd_ptr->fd, 0);
	}
}

/****************************************************************************
open a file with a share mode
****************************************************************************/
void open_file_shared(int fnum, int cnum, char *fname, int share_mode, int ofun,
                      int dosmode, int *Access, int *action)
{
	files_struct *fs_p = &Files[fnum];
	int flags = 0;
	int flags2 = 0;
	int deny_mode = (share_mode >> 4) & 7;
	int unixmode;
	struct stat sbuf;
	bool file_existed = file_exist(fname, &sbuf);
	bool share_locked = false;
	bool fcbopen = false;
	int token;

	fs_p->open = false;
	fs_p->fd_ptr = 0;

	/* this is for OS/2 EAs - try and say we don't support them */
	if (strstr(fname, ".+,;=[].")) {
		unix_ERR_class = ERRDOS;
		unix_ERR_code = ERRcannotopen;

		return;
	}

	if ((ofun & 0x3) == 0 && file_existed) {
		errno = EEXIST;
		return;
	}

	if (ofun & 0x10)
		flags2 |= O_CREAT;
	if ((ofun & 0x3) == 2)
		flags2 |= O_TRUNC;

	/* note that we ignore the append flag as
	   append does not mean the same thing under dos and unix */

	switch (share_mode & 0xF) {
	case 1:
		flags = O_WRONLY;
		break;
	case 0xF:
		fcbopen = true;
		flags = O_RDWR;
		break;
	case 2:
		flags = O_RDWR;
		break;
	default:
		flags = O_RDONLY;
		break;
	}

	if (flags != O_RDONLY && file_existed &&
	    (!CAN_WRITE(cnum) ||
	     IS_DOS_READONLY(dos_mode(cnum, fname, &sbuf)))) {
		if (!fcbopen) {
			errno = EACCES;
			return;
		}
		flags = O_RDONLY;
	}

	if (deny_mode > DENY_NONE && deny_mode != DENY_FCB) {
		DEBUG(2,
		      ("Invalid deny mode %d on file %s\n", deny_mode, fname));
		errno = EINVAL;
		return;
	}

	if (deny_mode == DENY_FCB)
		deny_mode = DENY_DOS;

	unixmode = unix_mode(cnum, dosmode);
	DEBUG(4, ("calling open_file with flags=0x%X flags2=0x%X mode=0%o\n",
	          flags, flags2, unixmode));

	open_file(fnum, cnum, fname, flags | (flags2 & ~(O_TRUNC)), unixmode,
	          file_existed ? &sbuf : 0);
	if (!fs_p->open && flags == O_RDWR && errno != ENOENT && fcbopen) {
		flags = O_RDONLY;
		open_file(fnum, cnum, fname, flags, unixmode,
		          file_existed ? &sbuf : 0);
	}

	if (fs_p->open) {
		int open_mode = 0;
		switch (flags) {
		case O_RDWR:
			open_mode = 2;
			break;
		case O_WRONLY:
			open_mode = 1;
			break;
		default:
			open_mode = 0;
			break;
		}

		/* When creating a new file, we save the DOS attributes */
		if (!file_existed || (flags & (O_CREAT|O_TRUNC)) != 0) {
			write_dosattrib(fname, dosmode);
		}

		fs_p->share_mode = (deny_mode << 4) | open_mode;

		if (Access)
			(*Access) = open_mode;

		if (action) {
			if (file_existed && !(flags2 & O_TRUNC))
				*action = 1;
			if (!file_existed)
				*action = 2;
			if (file_existed && (flags2 & O_TRUNC))
				*action = 3;
		}

		if ((flags2 & O_TRUNC) && file_existed)
			truncate_unless_locked(fnum, cnum, token,
			                       &share_locked);
	}
}

/****************************************************************************
seek a file. Try to avoid the seek if possible
****************************************************************************/
int seek_file(int fnum, uint32_t pos)
{
	uint32_t offset = 0;

	Files[fnum].pos =
	    (int) (lseek(Files[fnum].fd_ptr->fd, pos + offset, SEEK_SET) -
	           offset);
	return (Files[fnum].pos);
}

/****************************************************************************
read from a file
****************************************************************************/
int read_file(int fnum, char *data, uint32_t pos, int n)
{
	int ret = 0, readret;

#if USE_MMAP
	if (Files[fnum].mmap_ptr) {
		int num = (Files[fnum].mmap_size > pos)
		            ? (Files[fnum].mmap_size - pos)
		            : -1;
		num = MIN(n, num);
		if (num > 0) {
			memcpy(data, Files[fnum].mmap_ptr + pos, num);
			data += num;
			pos += num;
			n -= num;
			ret += num;
		}
	}
#endif

	if (n <= 0)
		return (ret);

	if (seek_file(fnum, pos) != pos) {
		DEBUG(3, ("Failed to seek to %d\n", pos));
		return (ret);
	}

	if (n > 0) {
		readret = read(Files[fnum].fd_ptr->fd, data, n);
		if (readret > 0)
			ret += readret;
	}

	return (ret);
}

/****************************************************************************
write to a file
****************************************************************************/
int write_file(int fnum, char *data, int n)
{
	if (!Files[fnum].can_write) {
		errno = EPERM;
		return (0);
	}

	if (!Files[fnum].modified) {
		struct stat st;
		Files[fnum].modified = true;
		if (fstat(Files[fnum].fd_ptr->fd, &st) == 0) {
			int dosmode =
			    dos_mode(Files[fnum].cnum, Files[fnum].name, &st);
			if (!IS_DOS_ARCHIVE(dosmode)) {
				dos_chmod(Files[fnum].cnum, Files[fnum].name,
				          dosmode | aARCH, &st);
			}
		}
	}

	return (write_data(Files[fnum].fd_ptr->fd, data, n));
}

/****************************************************************************
load parameters specific to a connection/service
****************************************************************************/
bool become_service(int cnum, bool do_chdir)
{
	static int last_cnum = -1;
	int snum;

	if (!OPEN_CNUM(cnum)) {
		last_cnum = -1;
		return (false);
	}

	Connections[cnum].lastused = smb_last_time;

	snum = SNUM(cnum);

	if (do_chdir && ChDir(Connections[cnum].connectpath) != 0 &&
	    ChDir(Connections[cnum].origpath) != 0) {
		DEBUG(0, ("%s chdir (%s) failed cnum=%d\n", timestring(),
		          Connections[cnum].connectpath, cnum));
		return (false);
	}

	if (cnum == last_cnum)
		return (true);

	last_cnum = cnum;

	case_default = lp_defaultcase(snum);
	short_case_preserve = lp_shortpreservecase(snum);
	case_sensitive = lp_casesensitive(snum);
	return (true);
}

/****************************************************************************
  find a service entry
****************************************************************************/
int find_service(char *service)
{
	int iService;

	string_sub(service, "\\", "/");

	iService = lp_servicenumber(service);

	if (iService >= 0)
		if (!VALID_SNUM(iService)) {
			DEBUG(0,
			      ("Invalid snum %d for %s\n", iService, service));
			iService = -1;
		}

	if (iService < 0)
		DEBUG(3,
		      ("find_service() failed to find service %s\n", service));

	return (iService);
}

/****************************************************************************
  create an error packet from a cached error.
****************************************************************************/
int cached_error_packet(char *inbuf, char *outbuf, int fnum, int line)
{
	write_bmpx_struct *wbmpx = Files[fnum].wbmpx_ptr;

	int32_t eclass = wbmpx->wr_errclass;
	int32_t err = wbmpx->wr_error;

	/* We can now delete the auxiliary struct */
	free((char *) wbmpx);
	Files[fnum].wbmpx_ptr = NULL;
	return error_packet(inbuf, outbuf, eclass, err, line);
}

struct {
	int unixerror;
	int smbclass;
	int smbcode;
} unix_smb_errmap[] = {
    {EPERM, ERRDOS, ERRnoaccess},     {EACCES, ERRDOS, ERRnoaccess},
    {ENOENT, ERRDOS, ERRbadfile},     {ENOTDIR, ERRDOS, ERRbadpath},
    {EIO, ERRHRD, ERRgeneral},        {EBADF, ERRSRV, ERRsrverror},
    {EINVAL, ERRSRV, ERRsrverror},    {EEXIST, ERRDOS, ERRfilexists},
    {ENFILE, ERRDOS, ERRnofids},      {EMFILE, ERRDOS, ERRnofids},
    {ENOSPC, ERRHRD, ERRdiskfull},
#ifdef EDQUOT
    {EDQUOT, ERRHRD, ERRdiskfull},
#endif
#ifdef ENOTEMPTY
    {ENOTEMPTY, ERRDOS, ERRnoaccess},
#endif
#ifdef EXDEV
    {EXDEV, ERRDOS, ERRdiffdevice},
#endif
    {EROFS, ERRHRD, ERRnowrite},      {0, 0, 0}};

/****************************************************************************
  create an error packet from errno
****************************************************************************/
int unix_error_packet(char *inbuf, char *outbuf, int def_class,
                      uint32_t def_code, int line)
{
	int eclass = def_class;
	int ecode = def_code;
	int i = 0;

	if (unix_ERR_class != SMB_SUCCESS) {
		eclass = unix_ERR_class;
		ecode = unix_ERR_code;
		unix_ERR_class = SMB_SUCCESS;
		unix_ERR_code = 0;
	} else {
		while (unix_smb_errmap[i].smbclass != 0) {
			if (unix_smb_errmap[i].unixerror == errno) {
				eclass = unix_smb_errmap[i].smbclass;
				ecode = unix_smb_errmap[i].smbcode;
				break;
			}
			i++;
		}
	}

	return (error_packet(inbuf, outbuf, eclass, ecode, line));
}

/****************************************************************************
  create an error packet. Normally called using the ERROR() macro
****************************************************************************/
int error_packet(char *inbuf, char *outbuf, int error_class,
                 uint32_t error_code, int line)
{
	int outsize = set_message(outbuf, 0, 0, true);

	CVAL(outbuf, smb_rcls) = error_class;
	SSVAL(outbuf, smb_err, error_code);

	DEBUG(3, ("%s error packet at line %d cmd=%d (%s) eclass=%d ecode=%d\n",
	          timestring(), line, (int) CVAL(inbuf, smb_com),
	          smb_fn_name(CVAL(inbuf, smb_com)), error_class, error_code));

	if (errno != 0)
		DEBUG(3, ("error string = %s\n", strerror(errno)));

	return (outsize);
}

#ifndef SIGCLD_IGNORE
/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static int sig_cld(void)
{
	static int depth = 0;
	if (depth != 0) {
		DEBUG(0, ("ERROR: Recursion in sig_cld? Perhaps you need "
		          "`#define USE_WAITPID'?\n"));
		depth = 0;
		return (0);
	}
	depth++;

	BlockSignals(true, SIGCLD);
	DEBUG(5, ("got SIGCLD\n"));

#ifdef USE_WAITPID
	while (waitpid((pid_t) -1, (int *) NULL, WNOHANG) > 0)
		;
#endif

	/* Stop zombies */
	/* Stevens, Adv. Unix Prog. says that on system V you must call
	   wait before reinstalling the signal handler, because the kernel
	   calls the handler from within the signal-call when there is a
	   child that has exited. This would lead to an infinite recursion
	   if done vice versa. */

#ifndef DONT_REINSTALL_SIG
#ifdef SIGCLD_IGNORE
	signal(SIGCLD, SIG_IGN);
#else
	signal(SIGCLD, SIGNAL_CAST sig_cld);
#endif
#endif

#ifndef USE_WAITPID
	while (wait3(WAIT3_CAST1 NULL, WNOHANG, WAIT3_CAST2 NULL) > 0)
		;
#endif
	depth--;
	BlockSignals(false, SIGCLD);
	return 0;
}
#endif

/****************************************************************************
  this is called when the client exits abruptly
  **************************************************************************/
static int sig_pipe(void)
{
	BlockSignals(true, SIGPIPE);

	exit_server("Got sigpipe\n");
	return (0);
}

static void set_keepalive_option(int fd)
{
	int enabled = 1;
	int ret =
	    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(int));

	if (ret != 0) {
		DEBUG(0, ("Failed to set keepalive option"));
	}
}

/****************************************************************************
  open the socket communication
****************************************************************************/
static bool open_sockets(bool is_daemon, int port)
{
	extern int Client;

	if (is_daemon) {
		int server_socket;

		/* Stop zombies */
#ifdef SIGCLD_IGNORE
		signal(SIGCLD, SIG_IGN);
#else
		signal(SIGCLD, SIGNAL_CAST sig_cld);
#endif

		if (atexit_set == 0)
			atexit(killkids);

		/* open an incoming socket */
		server_socket = open_socket_in(
		    SOCK_STREAM, port, 0, interpret_addr(lp_socket_address()));
		if (server_socket == -1)
			return (false);

		/* ready to listen */
		if (listen(server_socket, 5) == -1) {
			DEBUG(0,
			      ("open_sockets: listen: %s\n", strerror(errno)));
			close(server_socket);
			return false;
		}

		/* now accept incoming connections - forking a new process
		   for each incoming connection */
		DEBUG(2, ("waiting for a connection\n"));
		while (1) {
			fd_set listen_set;
			int num;
			struct sockaddr addr;
			socklen_t in_addrlen = sizeof(addr);

			FD_ZERO(&listen_set);
			FD_SET(server_socket, &listen_set);

			num = sys_select(&listen_set, NULL);

			if (num == -1 && errno == EINTR)
				continue;

			if (!FD_ISSET(server_socket, &listen_set)) {
				continue;
			}

			Client = accept(server_socket, &addr, &in_addrlen);

			if (Client == -1 && errno == EINTR)
				continue;

			if (Client == -1) {
				DEBUG(0, ("open_sockets: accept: %s\n",
				          strerror(errno)));
				continue;
			}

			signal(SIGPIPE, SIGNAL_CAST sig_pipe);
			signal(SIGCLD, SIGNAL_CAST SIG_DFL);
			if (Client != -1 && fork() == 0) {
				/* Child code ... */

				signal(SIGPIPE, SIGNAL_CAST sig_pipe);
				signal(SIGCLD, SIGNAL_CAST SIG_DFL);

				/* close the listening socket */
				close(server_socket);

				/* close our standard file descriptors */
				close_low_fds();
				am_parent = 0;

				set_keepalive_option(Client);

				/* Reset global variables in util.c so
				   that client substitutions will be done
				   correctly in the process. */
				reset_globals_after_fork();
				return true;
			}
			close(Client); /* The parent doesn't need this socket */

			/*
			 * Force parent to check log size after spawning child.
			 * Fix from klausr@ITAP.Physik.Uni-Stuttgart.De. The
			 * parent smbd will log to logserver.smb. It writes
			 * only two messages for each child started/finished.
			 * But each child writes, say, 50 messages also in
			 * logserver.smb, begining with the debug_count of the
			 * parent, before the child opens its own log file
			 * logserver.client. In a worst case scenario the size
			 * of logserver.smb would be checked after about
			 * 50*50=2500 messages (ca. 100kb).
			 */
			force_check_log_size();
		}
	} /* end if is_daemon */
	else {
		/* Started from inetd. fd 0 is the socket. */
		/* We will abort gracefully when the client or remote system
		   goes away */
#ifndef NO_SIGNAL_TEST
		signal(SIGPIPE, SIGNAL_CAST sig_pipe);
#endif
		Client = dup(0);

		/* close our standard file descriptors */
		close_low_fds();

		set_keepalive_option(Client);
	}

	return true;
}

/****************************************************************************
  process an smb from the client - split out from the process() code so
  it can be used by the oplock break code.
****************************************************************************/

static void process_smb(char *inbuf, char *outbuf)
{
	extern int Client;
	static int trans_num;
	int msg_type = CVAL(inbuf, 0);
	int32_t len = smb_len(inbuf);
	int nread = len + 4;

	DEBUG(6, ("got message type 0x%x of len 0x%x\n", msg_type, len));
	DEBUG(3, ("%s Transaction %d of length %d\n", timestring(), trans_num,
	          nread));

	if (msg_type == 0)
		show_msg(inbuf);
	else if (msg_type == 0x85)
		return; /* Keepalive packet. */

	nread = construct_reply(inbuf, outbuf, nread, max_send);

	if (nread > 0) {
		if (CVAL(outbuf, 0) == 0)
			show_msg(outbuf);

		if (nread != smb_len(outbuf) + 4) {
			DEBUG(0,
			      ("ERROR: Invalid message response size! %d %d\n",
			       nread, smb_len(outbuf)));
		} else
			send_smb(Client, outbuf);
	}
	trans_num++;
}

/****************************************************************************
Get the next SMB packet, doing the local message processing automatically.
****************************************************************************/

bool receive_next_smb(int smbfd, char *inbuf, int bufsize, int timeout)
{
	bool got_smb = false;
	bool ret;

	do {
		ret = receive_message_or_smb(smbfd, inbuf, bufsize, timeout,
		                             &got_smb);

		if (ret && (CVAL(inbuf, 0) == 0x85)) {
			/* Keepalive packet. */
			got_smb = false;
		}

	} while (ret && !got_smb);

	return ret;
}

/****************************************************************************
check if a snum is in use
****************************************************************************/
bool snum_used(int snum)
{
	int i;
	for (i = 0; i < MAX_CONNECTIONS; i++)
		if (OPEN_CNUM(i) && (SNUM(i) == snum))
			return (true);
	return (false);
}

/****************************************************************************
  reload the services file
  **************************************************************************/
bool reload_services(bool test)
{
	bool ret;

	if (lp_loaded()) {
		pstring fname;
		pstrcpy(fname, lp_configfile());
		if (file_exist(fname, NULL) && !strcsequal(fname, servicesf)) {
			pstrcpy(servicesf, fname);
			test = false;
		}
	}

	reopen_logs();

	if (test && !lp_file_list_changed())
		return (true);

	lp_killunused(snum_used);

	ret = lp_load(servicesf);

	/* perhaps the config filename is now set */
	if (!test)
		reload_services(true);

	reopen_logs();

	{
		extern int Client;
		if (Client != -1) {
			set_keepalive_option(Client);
		}
	}

	reset_mangled_stack(MANGLED_STACK_SIZE);

	/* this forces service parameters to be flushed */
	become_service(-1, true);

	return (ret);
}

/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static bool reload_after_sighup = false;

static int sig_hup(void)
{
	BlockSignals(true, SIGHUP);
	DEBUG(0, ("Got SIGHUP\n"));

	/*
	 * Fix from <branko.cibej@hermes.si> here.
	 * We used to reload in the signal handler - this
	 * is a *BIG* no-no.
	 */

	reload_after_sighup = true;
#ifndef DONT_REINSTALL_SIG
	signal(SIGHUP, SIGNAL_CAST sig_hup);
#endif
	BlockSignals(false, SIGHUP);
	return (0);
}

/****************************************************************************
  make a connection to a service
****************************************************************************/
int make_connection(char *service, char *dev)
{
	char *user = lp_guestaccount(-1);
	int cnum;
	int snum;
	struct passwd *pass = NULL;
	connection_struct *pcon;

	strlower(service);

	snum = find_service(service);
	if (snum < 0) {
		if (strequal(service, "IPC$")) {
			DEBUG(3,
			      ("%s refusing IPC connection\n", timestring()));
			return (-3);
		}

		DEBUG(0, ("%s %s (%s) couldn't find service %s\n", timestring(),
		          remote_machine, client_addr(), service));
		return (-2);
	}
	if (!lp_snum_ok(snum)) {
		return (-4);
	}

	/* you can only connect to the IPC$ service as an ipc device */
	if (strequal(service, "IPC$")) {
		pstrcpy(dev, "IPC");
	} else if (*dev == '?' || !*dev) {
		pstrcpy(dev, "A:");
	}

	/* if the request is as a printer and you can't print then refuse */
	strupper(dev);
	if (strncmp(dev, "LPT", 3) == 0) {
		DEBUG(1, ("Attempt to connect to non-printer as a printer\n"));
		return (-6);
	}

	cnum = find_free_connection(str_checksum(service) + str_checksum(user));
	if (cnum < 0) {
		DEBUG(0, ("%s couldn't find free connection\n", timestring()));
		return (-1);
	}

	pcon = &Connections[cnum];
	bzero((char *) pcon, sizeof(*pcon));

	/* find out some info about the user */
	pass = Get_Pwnam(user, true);

	if (pass == NULL) {
		DEBUG(0, ("%s couldn't find account %s\n", timestring(), user));
		return (-7);
	}

	pcon->read_only = lp_readonly(snum);
	pcon->ipc = strncmp(dev, "IPC", 3) == 0;
	pcon->uid = pass->pw_uid;
	pcon->gid = pass->pw_gid;
	pcon->num_files_open = 0;
	pcon->lastused = time(NULL);
	pcon->service = snum;
	pcon->used = true;
	pcon->dirptr = NULL;
	string_set(&pcon->dirpath, "");
	string_set(&pcon->user, user);

	{
		pstring s;
		pstrcpy(s, lp_pathname(snum));
		standard_sub(cnum, s);
		string_set(&pcon->connectpath, s);
		DEBUG(3, ("Connect path is %s\n", s));
	}

	pcon->open = true;

	if (!become_user(&Connections[cnum], cnum)) {
		DEBUG(0, ("Can't become connected user!\n"));
		pcon->open = false;
		return (-1);
	}

	if (ChDir(pcon->connectpath) != 0) {
		DEBUG(0, ("Can't change directory to %s (%s)\n",
		          pcon->connectpath, strerror(errno)));
		pcon->open = false;
		unbecome_user();
		return (-5);
	}

	string_set(&pcon->origpath, pcon->connectpath);

#if SOFTLINK_OPTIMISATION
	/* resolve any soft links early */
	{
		pstring s;
		pstrcpy(s, pcon->connectpath);
		GetWd(s);
		string_set(&pcon->connectpath, s);
		ChDir(pcon->connectpath);
	}
#endif

	num_connections_open++;

	/* we've finished with the sensitive stuff */
	unbecome_user();

	{
		DEBUG(1, ("%s %s (%s) connect to service %s as user %s "
		          "(uid=%d,gid=%d) (pid %d)\n",
		          timestring(), remote_machine, client_addr(),
		          lp_servicename(SNUM(cnum)), user, pcon->uid,
		          pcon->gid, (int) getpid()));
	}

	return (cnum);
}

/****************************************************************************
  find first available file slot
****************************************************************************/
int find_free_file(void)
{
	int i;
	static int first_file;

	/* we want to give out file handles differently on each new
	   connection because of a common bug in MS clients where they try to
	   reuse a file descriptor from an earlier smb connection. This code
	   increases the chance that the errant client will get an error rather
	   than causing corruption */
	if (first_file == 0) {
		first_file = (getpid() ^ (int) time(NULL)) % MAX_OPEN_FILES;
		if (first_file == 0)
			first_file = 1;
	}

	if (first_file >= MAX_OPEN_FILES)
		first_file = 1;

	for (i = first_file; i < MAX_OPEN_FILES; i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i + 1;
			Files[i].reserved = true;
			return (i);
		}

	/* returning a file handle of 0 is a bad idea - so we start at 1 */
	for (i = 1; i < first_file; i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i + 1;
			Files[i].reserved = true;
			return (i);
		}

	DEBUG(1, ("ERROR! Out of file structures - perhaps increase "
	          "MAX_OPEN_FILES?\n"));
	return (-1);
}

/****************************************************************************
  find first available connection slot, starting from a random position.
The randomisation stops problems with the server dieing and clients
thinking the server is still available.
****************************************************************************/
static int find_free_connection(int hash)
{
	int i;
	bool used = false;
	hash = (hash % (MAX_CONNECTIONS - 2)) + 1;

again:

	for (i = hash + 1; i != hash;) {
		if (!Connections[i].open && Connections[i].used == used) {
			DEBUG(3, ("found free connection number %d\n", i));
			return (i);
		}
		i++;
		if (i == MAX_CONNECTIONS)
			i = 1;
	}

	if (!used) {
		used = !used;
		goto again;
	}

	DEBUG(1, ("ERROR! Out of connection structures\n"));
	return (-1);
}

/****************************************************************************
reply for the core protocol
****************************************************************************/
int reply_corep(char *outbuf)
{
	int outsize = set_message(outbuf, 1, 0, true);

	Protocol = PROTOCOL_CORE;

	return outsize;
}

/****************************************************************************
reply for the coreplus protocol
****************************************************************************/
int reply_coreplus(char *outbuf)
{
	int raw = (lp_readraw() ? 1 : 0) | (lp_writeraw() ? 2 : 0);
	int outsize = set_message(outbuf, 13, 0, true);
	SSVAL(outbuf, smb_vwv5, raw); /* tell redirector we support
	                                 readbraw and writebraw (possibly) */
	CVAL(outbuf, smb_flg) =
	    0x81; /* Reply, SMBlockread, SMBwritelock supported */
	SSVAL(outbuf, smb_vwv1, 0x1); /* user level security, don't encrypt */

	Protocol = PROTOCOL_COREPLUS;

	return outsize;
}

/****************************************************************************
reply for the lanman 1.0 protocol
****************************************************************************/
int reply_lanman1(char *outbuf)
{
	int raw = (lp_readraw() ? 1 : 0) | (lp_writeraw() ? 2 : 0);
	int secword = 0;
	time_t t = time(NULL);

	set_message(outbuf, 13, 0, true);
	SSVAL(outbuf, smb_vwv1, secword);

	Protocol = PROTOCOL_LANMAN1;

	CVAL(outbuf, smb_flg) =
	    0x81; /* Reply, SMBlockread, SMBwritelock supported */
	SSVAL(outbuf, smb_vwv2, max_recv);
	SSVAL(outbuf, smb_vwv3, MAX_MUX);
	SSVAL(outbuf, smb_vwv4, 1);
	SSVAL(outbuf, smb_vwv5, raw); /* tell redirector we support
	                                 readbraw writebraw (possibly) */
	SIVAL(outbuf, smb_vwv6, getpid());
	SSVAL(outbuf, smb_vwv10, TimeDiff(t) / 60);

	put_dos_date(outbuf, smb_vwv8, t);

	return (smb_len(outbuf) + 4);
}

/****************************************************************************
reply for the lanman 2.0 protocol
****************************************************************************/
int reply_lanman2(char *outbuf)
{
	int raw = (lp_readraw() ? 1 : 0) | (lp_writeraw() ? 2 : 0);
	int secword = 0;
	time_t t = time(NULL);
	char crypt_len = 0;

	set_message(outbuf, 13, crypt_len, true);
	SSVAL(outbuf, smb_vwv1, secword);
	SIVAL(outbuf, smb_vwv6, getpid());

	Protocol = PROTOCOL_LANMAN2;

	CVAL(outbuf, smb_flg) =
	    0x81; /* Reply, SMBlockread, SMBwritelock supported */
	SSVAL(outbuf, smb_vwv2, max_recv);
	SSVAL(outbuf, smb_vwv3, MAX_MUX);
	SSVAL(outbuf, smb_vwv4, 1);
	SSVAL(outbuf, smb_vwv5, raw); /* readbraw and/or writebraw */
	SSVAL(outbuf, smb_vwv10, TimeDiff(t) / 60);
	put_dos_date(outbuf, smb_vwv8, t);

	return (smb_len(outbuf) + 4);
}

/****************************************************************************
reply for the nt protocol
****************************************************************************/
int reply_nt1(char *outbuf)
{
	/* dual names + lock_and_read + nt SMBs + remote API calls */
	int capabilities = CAP_NT_FIND | CAP_LOCK_AND_READ;
	/*
	  other valid capabilities which we may support at some time...
	                     CAP_LARGE_FILES|CAP_NT_SMBS|CAP_RPC_REMOTE_APIS;
	                     CAP_LARGE_READX|CAP_STATUS32|CAP_LEVEL_II_OPLOCKS;
	 */

	int secword = 0;
	time_t t = time(NULL);
	int data_len;
	char crypt_len = 0;

	if (lp_readraw() && lp_writeraw()) {
		capabilities |= CAP_RAW_MODE;
	}

	/* decide where (if) to put the encryption challenge, and
	   follow it with the OEM'd domain name
	 */
	data_len = crypt_len + strlen(myworkgroup) + 1;

	set_message(outbuf, 17, data_len, true);
	pstrcpy(smb_buf(outbuf) + crypt_len, myworkgroup);

	CVAL(outbuf, smb_vwv1) = secword;
	SSVALS(outbuf, smb_vwv16 + 1, crypt_len);

	Protocol = PROTOCOL_NT1;

	SSVAL(outbuf, smb_vwv1 + 1, MAX_MUX);
	SSVAL(outbuf, smb_vwv2 + 1, 1);            /* num vcs */
	SIVAL(outbuf, smb_vwv3 + 1, 0xffff);       /* max buffer. LOTS! */
	SIVAL(outbuf, smb_vwv5 + 1, 0xffff);       /* raw size. LOTS! */
	SIVAL(outbuf, smb_vwv7 + 1, getpid());     /* session key */
	SIVAL(outbuf, smb_vwv9 + 1, capabilities); /* capabilities */
	put_long_date(outbuf + smb_vwv11 + 1, t);
	SSVALS(outbuf, smb_vwv15 + 1, TimeDiff(t) / 60);
	SSVAL(outbuf, smb_vwv17,
	      data_len); /* length of challenge+domain strings */

	return (smb_len(outbuf) + 4);
}

/* these are the protocol lists used for auto architecture detection:

WinNT 3.51:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

Win95:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [MICROSOFT NETWORKS 1.03]
protocol [LANMAN1.0]
protocol [Windows for Workgroups 3.1a]
protocol [LM1.2X002]
protocol [LANMAN2.1]
protocol [NT LM 0.12]

OS/2:
protocol [PC NETWORK PROGRAM 1.0]
protocol [XENIX CORE]
protocol [LANMAN1.0]
protocol [LM1.2X002]
protocol [LANMAN2.1]
*/

/*
  * Modified to recognize the architecture of the remote machine better.
  *
  * This appears to be the matrix of which protocol is used by which
  * MS product.
       Protocol                       WfWg    Win95   WinNT  OS/2
       PC NETWORK PROGRAM 1.0          1       1       1      1
       XENIX CORE                                      2      2
       MICROSOFT NETWORKS 3.0          2       2
       DOS LM1.2X002                   3       3
       MICROSOFT NETWORKS 1.03                         3
       DOS LANMAN2.1                   4       4
       LANMAN1.0                                       4      3
       Windows for Workgroups 3.1a     5       5       5
       LM1.2X002                                       6      4
       LANMAN2.1                                       7      5
       NT LM 0.12                              6       8
  *
  *  tim@fsg.com 09/29/95
  */

#define ARCH_WFWG 0x3 /* This is a fudge because WfWg is like Win95 */
#define ARCH_WIN95 0x2
#define ARCH_OS2 0xC /* Again OS/2 is like NT */
#define ARCH_WINNT 0x8
#define ARCH_SAMBA 0x10

#define ARCH_ALL 0x1F

/* List of supported protocols, most desired first */
struct {
	char *proto_name;
	char *short_name;
	int (*proto_reply_fn)(char *);
	int protocol_level;
} supported_protocols[] = {
    {"NT LANMAN 1.0", "NT1", reply_nt1, PROTOCOL_NT1},
    {"NT LM 0.12", "NT1", reply_nt1, PROTOCOL_NT1},
    {"LM1.2X002", "LANMAN2", reply_lanman2, PROTOCOL_LANMAN2},
    {"Samba", "LANMAN2", reply_lanman2, PROTOCOL_LANMAN2},
    {"DOS LM1.2X002", "LANMAN2", reply_lanman2, PROTOCOL_LANMAN2},
    {"LANMAN1.0", "LANMAN1", reply_lanman1, PROTOCOL_LANMAN1},
    {"MICROSOFT NETWORKS 3.0", "LANMAN1", reply_lanman1, PROTOCOL_LANMAN1},
    {"MICROSOFT NETWORKS 1.03", "COREPLUS", reply_coreplus, PROTOCOL_COREPLUS},
    {"PC NETWORK PROGRAM 1.0", "CORE", reply_corep, PROTOCOL_CORE},
    {NULL, NULL},
};

/****************************************************************************
  reply to a negprot
****************************************************************************/
static int reply_negprot(char *inbuf, char *outbuf, int size, int bufsize)
{
	int outsize = set_message(outbuf, 1, 0, true);
	int Index = 0;
	int choice = -1;
	int protocol;
	char *p;
	int bcc = SVAL(smb_buf(inbuf), -2);

	p = smb_buf(inbuf) + 1;
	while (p < (smb_buf(inbuf) + bcc)) {
		Index++;
		DEBUG(3, ("Requested protocol [%s]\n", p));
		p += strlen(p) + 2;
	}

	/* possibly reload - change of architecture */
	reload_services(true);

	/* Check for protocols, most desirable first */
	for (protocol = 0; supported_protocols[protocol].proto_name;
	     protocol++) {
		p = smb_buf(inbuf) + 1;
		Index = 0;
		while (p < (smb_buf(inbuf) + bcc)) {
			if (strequal(p,
			             supported_protocols[protocol].proto_name))
				choice = Index;
			Index++;
			p += strlen(p) + 2;
		}
		if (choice != -1)
			break;
	}

	SSVAL(outbuf, smb_vwv0, choice);
	if (choice != -1) {
		extern fstring remote_proto;
		fstrcpy(remote_proto, supported_protocols[protocol].short_name);
		reload_services(true);
		outsize = supported_protocols[protocol].proto_reply_fn(outbuf);
		DEBUG(3, ("Selected protocol %s\n",
		          supported_protocols[protocol].proto_name));
	} else {
		DEBUG(0, ("No protocol supported !\n"));
	}
	SSVAL(outbuf, smb_vwv0, choice);

	DEBUG(5, ("%s negprot index=%d\n", timestring(), choice));

	return (outsize);
}

/****************************************************************************
close all open files for a connection
****************************************************************************/
static void close_open_files(int cnum)
{
	int i;
	for (i = 0; i < MAX_OPEN_FILES; i++)
		if (Files[i].cnum == cnum && Files[i].open) {
			close_file(i, false);
		}
}

/****************************************************************************
close a cnum
****************************************************************************/
void close_cnum(int cnum)
{
	DirCacheFlush(SNUM(cnum));

	unbecome_user();

	if (!OPEN_CNUM(cnum)) {
		DEBUG(0, ("Can't close cnum %d\n", cnum));
		return;
	}

	DEBUG(1, ("%s %s (%s) closed connection to service %s\n", timestring(),
	          remote_machine, client_addr(), lp_servicename(SNUM(cnum))));

	close_open_files(cnum);
	dptr_closecnum(cnum);

	unbecome_user();

	Connections[cnum].open = false;
	num_connections_open--;

	string_set(&Connections[cnum].user, "");
	string_set(&Connections[cnum].dirpath, "");
	string_set(&Connections[cnum].connectpath, "");
}

#if DUMP_CORE
/*******************************************************************
prepare to dump a core file - carefully!
********************************************************************/
static bool dump_core(void)
{
	char *p;
	pstring dname;
	pstrcpy(dname, debugf);
	if ((p = strrchr(dname, '/')))
		*p = 0;
	pstrcat(dname, "/corefiles");
	mkdir(dname, 0700);
	chown(dname, getuid(), getgid());
	chmod(dname, 0700);
	if (chdir(dname))
		return (false);
	umask(~(0700));

#ifdef RLIMIT_CORE
	{
		struct rlimit rlp;
		getrlimit(RLIMIT_CORE, &rlp);
		rlp.rlim_cur = MAX(4 * 1024 * 1024, rlp.rlim_cur);
		setrlimit(RLIMIT_CORE, &rlp);
		getrlimit(RLIMIT_CORE, &rlp);
		DEBUG(3,
		      ("Core limits now %d %d\n", rlp.rlim_cur, rlp.rlim_max));
	}
#endif

	DEBUG(0, ("Dumping core in %s\n", dname));
	return (true);
}
#endif

/****************************************************************************
exit the server
****************************************************************************/
void exit_server(char *reason)
{
	static int firsttime = 1;
	int i;

	if (!firsttime)
		exit(0);
	firsttime = 0;

	unbecome_user();
	DEBUG(2, ("Closing connections\n"));
	for (i = 0; i < MAX_CONNECTIONS; i++)
		if (Connections[i].open)
			close_cnum(i);
	if (!reason) {
		int oldlevel = DEBUGLEVEL;
		DEBUGLEVEL = 10;
		DEBUG(0, ("Last message was %s\n", smb_fn_name(last_message)));
		if (last_inbuf)
			show_msg(last_inbuf);
		DEBUGLEVEL = oldlevel;
		DEBUG(0, ("===================================================="
		          "===========\n"));
#if DUMP_CORE
		if (dump_core())
			return;
#endif
	}

	DEBUG(3,
	      ("%s Server exit  (%s)\n", timestring(), reason ? reason : ""));
	exit(0);
}

/****************************************************************************
do some standard substitutions in a string
****************************************************************************/
void standard_sub(int cnum, char *str)
{
	if (VALID_CNUM(cnum)) {
		char *p, *s;

		for (s = str; (p = strchr(s, '%')) != NULL; s = p) {
			switch (*(p + 1)) {
			case 'H':
				string_sub(p, "%H", "/");
				break;
			case 'P':
				string_sub(p, "%P",
				           Connections[cnum].connectpath);
				break;
			case 'S':
				string_sub(
				    p, "%S",
				    lp_servicename(Connections[cnum].service));
				break;
			case 'g':
				string_sub(p, "%g",
				           gidtoname(Connections[cnum].gid));
				break;
			case 'u':
				string_sub(p, "%u", Connections[cnum].user);
				break;
			case '\0':
				p++;
				break; /* don't run off the end of the string */
			default:
				p += 2;
				break;
			}
		}
	}
	standard_sub_basic(str);
}

/*
These flags determine some of the permissions required to do an operation

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define AS_USER (1 << 0)
#define NEED_WRITE (1 << 1)
#define TIME_INIT (1 << 2)
#define CAN_IPC (1 << 3)
#define AS_GUEST (1 << 5)
#define QUEUE_IN_OPLOCK (1 << 6)

/*
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/

struct smb_message_struct {
	int code;
	char *name;
	int (*fn)(char *, char *, int, int);
	int flags;
#if PROFILING
	unsigned long time;
#endif
} smb_messages[] = {

    /* CORE PROTOCOL */

    {SMBnegprot, "SMBnegprot", reply_negprot, 0},
    {SMBtcon, "SMBtcon", reply_tcon, 0},
    {SMBtdis, "SMBtdis", reply_tdis, 0},
    {SMBexit, "SMBexit", reply_exit, 0},
    {SMBioctl, "SMBioctl", reply_ioctl, 0},
    {SMBecho, "SMBecho", reply_echo, 0},
    {SMBsesssetupX, "SMBsesssetupX", reply_sesssetup_and_X, 0},
    {SMBtconX, "SMBtconX", reply_tcon_and_X, 0},
    {SMBulogoffX, "SMBulogoffX", reply_ulogoffX,
     0}, /* ulogoff doesn't give a valid TID */
    {SMBgetatr, "SMBgetatr", reply_getatr, AS_USER},
    {SMBsetatr, "SMBsetatr", reply_setatr, AS_USER | NEED_WRITE},
    {SMBchkpth, "SMBchkpth", reply_chkpth, AS_USER},
    {SMBsearch, "SMBsearch", reply_search, AS_USER},
    {SMBopen, "SMBopen", reply_open, AS_USER | QUEUE_IN_OPLOCK},

    /* note that SMBmknew and SMBcreate are deliberately overloaded */
    {SMBcreate, "SMBcreate", reply_mknew, AS_USER},
    {SMBmknew, "SMBmknew", reply_mknew, AS_USER},

    {SMBunlink, "SMBunlink", reply_unlink,
     AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},
    {SMBread, "SMBread", reply_read, AS_USER},
    {SMBwrite, "SMBwrite", reply_write, AS_USER},
    {SMBclose, "SMBclose", reply_close, AS_USER | CAN_IPC},
    {SMBmkdir, "SMBmkdir", reply_mkdir, AS_USER | NEED_WRITE},
    {SMBrmdir, "SMBrmdir", reply_rmdir, AS_USER | NEED_WRITE},
    {SMBdskattr, "SMBdskattr", reply_dskattr, AS_USER},
    {SMBmv, "SMBmv", reply_mv, AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},

    /* this is a Pathworks specific call, allowing the
       changing of the root path */
    {pSETDIR, "pSETDIR", reply_setdir, AS_USER},

    {SMBlseek, "SMBlseek", reply_lseek, AS_USER},
    {SMBflush, "SMBflush", reply_flush, AS_USER},
    {SMBctemp, "SMBctemp", reply_ctemp, AS_USER | QUEUE_IN_OPLOCK},
    {SMBsplopen, "SMBsplopen", reply_printopen, AS_USER | QUEUE_IN_OPLOCK},
    {SMBsplclose, "SMBsplclose", reply_printclose, AS_USER},
    {SMBsplretq, "SMBsplretq", reply_printqueue, AS_USER | AS_GUEST},
    {SMBsplwr, "SMBsplwr", reply_printwrite, AS_USER},
    {SMBlock, "SMBlock", reply_lock, AS_USER},
    {SMBunlock, "SMBunlock", reply_unlock, AS_USER},

    /* CORE+ PROTOCOL FOLLOWS */

    {SMBreadbraw, "SMBreadbraw", reply_readbraw, AS_USER},
    {SMBwritebraw, "SMBwritebraw", reply_writebraw, AS_USER},
    {SMBwriteclose, "SMBwriteclose", reply_writeclose, AS_USER},
    {SMBlockread, "SMBlockread", reply_lockread, AS_USER},
    {SMBwriteunlock, "SMBwriteunlock", reply_writeunlock, AS_USER},

    /* LANMAN1.0 PROTOCOL FOLLOWS */

    {SMBreadBmpx, "SMBreadBmpx", reply_readbmpx, AS_USER},
    {SMBreadBs, "SMBreadBs", NULL, AS_USER},
    {SMBwriteBmpx, "SMBwriteBmpx", reply_writebmpx, AS_USER},
    {SMBwriteBs, "SMBwriteBs", reply_writebs, AS_USER},
    {SMBwritec, "SMBwritec", NULL, AS_USER},
    {SMBsetattrE, "SMBsetattrE", reply_setattrE, AS_USER | NEED_WRITE},
    {SMBgetattrE, "SMBgetattrE", reply_getattrE, AS_USER},
    {SMBtrans, "SMBtrans", reply_trans, AS_USER | CAN_IPC},
    {SMBtranss, "SMBtranss", NULL, AS_USER | CAN_IPC},
    {SMBioctls, "SMBioctls", NULL, AS_USER},
    {SMBcopy, "SMBcopy", reply_copy, AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},
    {SMBmove, "SMBmove", NULL, AS_USER | NEED_WRITE | QUEUE_IN_OPLOCK},

    {SMBopenX, "SMBopenX", reply_open_and_X,
     AS_USER | CAN_IPC | QUEUE_IN_OPLOCK},
    {SMBreadX, "SMBreadX", reply_read_and_X, AS_USER},
    {SMBwriteX, "SMBwriteX", reply_write_and_X, AS_USER},
    {SMBlockingX, "SMBlockingX", reply_lockingX, AS_USER},

    {SMBffirst, "SMBffirst", reply_search, AS_USER},
    {SMBfunique, "SMBfunique", reply_search, AS_USER},
    {SMBfclose, "SMBfclose", reply_fclose, AS_USER},

    /* LANMAN2.0 PROTOCOL FOLLOWS */
    {SMBfindnclose, "SMBfindnclose", reply_findnclose, AS_USER},
    {SMBfindclose, "SMBfindclose", reply_findclose, AS_USER},
    {SMBtrans2, "SMBtrans2", reply_trans2, AS_USER},
    {SMBtranss2, "SMBtranss2", reply_transs2, AS_USER},

    /* messaging routines */
    {SMBsends, "SMBsends", NULL, AS_GUEST},
    {SMBsendstrt, "SMBsendstrt", NULL, AS_GUEST},
    {SMBsendend, "SMBsendend", NULL, AS_GUEST},
    {SMBsendtxt, "SMBsendtxt", NULL, AS_GUEST},

    /* NON-IMPLEMENTED PARTS OF THE CORE PROTOCOL */

    {SMBsendb, "SMBsendb", NULL, AS_GUEST},
    {SMBfwdname, "SMBfwdname", NULL, AS_GUEST},
    {SMBcancelf, "SMBcancelf", NULL, AS_GUEST},
    {SMBgetmac, "SMBgetmac", NULL, AS_GUEST}};

/****************************************************************************
return a string containing the function name of a SMB command
****************************************************************************/
char *smb_fn_name(int type)
{
	static char *unknown_name = "SMBunknown";
	static int num_smb_messages =
	    sizeof(smb_messages) / sizeof(struct smb_message_struct);
	int match;

	for (match = 0; match < num_smb_messages; match++)
		if (smb_messages[match].code == type)
			break;

	if (match == num_smb_messages)
		return (unknown_name);

	return (smb_messages[match].name);
}

/****************************************************************************
do a switch on the message type, and return the response size
****************************************************************************/
static int switch_message(int type, char *inbuf, char *outbuf, int size,
                          int bufsize)
{
	static int pid = -1;
	int outsize = 0;
	static int num_smb_messages =
	    sizeof(smb_messages) / sizeof(struct smb_message_struct);
	int match;

#if PROFILING
	struct timeval msg_start_time;
	struct timeval msg_end_time;
	static unsigned long total_time = 0;

	getimeofday(&msg_start_time, NULL);
#endif

	if (pid == -1)
		pid = getpid();

	errno = 0;
	last_message = type;

	/* make sure this is an SMB packet */
	if (strncmp(smb_base(inbuf), "\377SMB", 4) != 0) {
		DEBUG(2, ("Non-SMB packet of length %d\n", smb_len(inbuf)));
		return (-1);
	}

	for (match = 0; match < num_smb_messages; match++)
		if (smb_messages[match].code == type)
			break;

	if (match == num_smb_messages) {
		DEBUG(0, ("Unknown message type %d!\n", type));
		outsize = reply_unknown(inbuf, outbuf);
	} else {
		DEBUG(3, ("switch message %s (pid %d)\n",
		          smb_messages[match].name, pid));

		if (smb_messages[match].fn) {
			int cnum = SVAL(inbuf, smb_tid);
			int flags = smb_messages[match].flags;
			/* Ensure this value is replaced in the incoming packet.
			 */
			SSVAL(inbuf, smb_uid, UID_FIELD_INVALID);

			/* does this protocol need to be run as root? */
			if (!(flags & AS_USER))
				unbecome_user();

			/* does this protocol need to be run as the connected
			 * user? */
			if ((flags & AS_USER) &&
			    !become_user(&Connections[cnum], cnum)) {
				if (flags & AS_GUEST)
					flags &= ~AS_USER;
				else
					return (ERROR(ERRSRV, ERRinvnid));
			}
			/* this code is to work around a bug is MS client 3
			   without introducing a security hole - it needs to be
			   able to do print queue checks as guest if it isn't
			   logged in properly */
			if (flags & AS_USER)
				flags &= ~AS_GUEST;

			/* does it need write permission? */
			if ((flags & NEED_WRITE) && !CAN_WRITE(cnum))
				return (ERROR(ERRSRV, ERRaccess));

			/* load service specific parameters */
			if (OPEN_CNUM(cnum) &&
			    !become_service(cnum,
			                    (flags & AS_USER) ? true : false))
				return (ERROR(ERRSRV, ERRaccess));

			/* does this protocol need to be run as guest? */
			if ((flags & AS_GUEST) && !become_guest())
				return (ERROR(ERRSRV, ERRaccess));

			last_inbuf = inbuf;

			outsize = smb_messages[match].fn(inbuf, outbuf, size,
			                                 bufsize);
		} else {
			outsize = reply_unknown(inbuf, outbuf);
		}
	}

#if PROFILING
	gettimeofday(&msg_end_time, NULL);
	if (!(smb_messages[match].flags & TIME_INIT)) {
		smb_messages[match].time = 0;
		smb_messages[match].flags |= TIME_INIT;
	}
	{
		unsigned long this_time =
		    (msg_end_time.tv_sec - msg_start_time.tv_sec) * 1e6 +
		    (msg_end_time.tv_usec - msg_start_time.tv_usec);
		smb_messages[match].time += this_time;
		total_time += this_time;
	}
	DEBUG(2, ("TIME %s  %d usecs   %g pct\n", smb_fn_name(type),
	          smb_messages[match].time,
	          (100.0 * smb_messages[match].time) / total_time));
#endif

	return (outsize);
}

/****************************************************************************
  construct a chained reply and add it to the already made reply
  **************************************************************************/
int chain_reply(char *inbuf, char *outbuf, int size, int bufsize)
{
	static char *orig_inbuf;
	static char *orig_outbuf;
	int smb_com1, smb_com2 = CVAL(inbuf, smb_vwv0);
	unsigned smb_off2 = SVAL(inbuf, smb_vwv1);
	char *inbuf2, *outbuf2;
	int outsize2;
	char inbuf_saved[smb_wct];
	char outbuf_saved[smb_wct];
	extern int chain_size;
	int wct = CVAL(outbuf, smb_wct);
	int outsize = smb_size + 2 * wct + SVAL(outbuf, smb_vwv0 + 2 * wct);

	/* maybe its not chained */
	if (smb_com2 == 0xFF) {
		CVAL(outbuf, smb_vwv0) = 0xFF;
		return outsize;
	}

	if (chain_size == 0) {
		/* this is the first part of the chain */
		orig_inbuf = inbuf;
		orig_outbuf = outbuf;
	}

	/* we need to tell the client where the next part of the reply will be
	 */
	SSVAL(outbuf, smb_vwv1, smb_offset(outbuf + outsize, outbuf));
	CVAL(outbuf, smb_vwv0) = smb_com2;

	/* remember how much the caller added to the chain, only counting stuff
	   after the parameter words */
	chain_size += outsize - smb_wct;

	/* work out pointers into the original packets. The
	   headers on these need to be filled in */
	inbuf2 = orig_inbuf + smb_off2 + 4 - smb_wct;
	outbuf2 = orig_outbuf + SVAL(outbuf, smb_vwv1) + 4 - smb_wct;

	/* remember the original command type */
	smb_com1 = CVAL(orig_inbuf, smb_com);

	/* save the data which will be overwritten by the new headers */
	memcpy(inbuf_saved, inbuf2, smb_wct);
	memcpy(outbuf_saved, outbuf2, smb_wct);

	/* give the new packet the same header as the last part of the SMB */
	memmove(inbuf2, inbuf, smb_wct);

	/* create the in buffer */
	CVAL(inbuf2, smb_com) = smb_com2;

	/* create the out buffer */
	bzero(outbuf2, smb_size);
	set_message(outbuf2, 0, 0, true);
	CVAL(outbuf2, smb_com) = CVAL(inbuf2, smb_com);

	memcpy(outbuf2 + 4, inbuf2 + 4, 4);
	CVAL(outbuf2, smb_rcls) = SMB_SUCCESS;
	CVAL(outbuf2, smb_reh) = 0;
	CVAL(outbuf2, smb_flg) =
	    0x80 | (CVAL(inbuf2, smb_flg) & 0x8); /* bit 7 set
	                                             means a reply */
	SSVAL(outbuf2, smb_flg2, 1); /* say we support long filenames */
	SSVAL(outbuf2, smb_err, SMB_SUCCESS);
	SSVAL(outbuf2, smb_tid, SVAL(inbuf2, smb_tid));
	SSVAL(outbuf2, smb_pid, SVAL(inbuf2, smb_pid));
	SSVAL(outbuf2, smb_uid, SVAL(inbuf2, smb_uid));
	SSVAL(outbuf2, smb_mid, SVAL(inbuf2, smb_mid));

	DEBUG(3, ("Chained message\n"));
	show_msg(inbuf2);

	/* process the request */
	outsize2 = switch_message(smb_com2, inbuf2, outbuf2, size - chain_size,
	                          bufsize - chain_size);

	/* copy the new reply and request headers over the old ones, but
	   preserve the smb_com field */
	memmove(orig_outbuf, outbuf2, smb_wct);
	CVAL(orig_outbuf, smb_com) = smb_com1;

	/* restore the saved data, being careful not to overwrite any
	 data from the reply header */
	memcpy(inbuf2, inbuf_saved, smb_wct);
	{
		int ofs = smb_wct - PTR_DIFF(outbuf2, orig_outbuf);
		if (ofs < 0)
			ofs = 0;
		memmove(outbuf2 + ofs, outbuf_saved + ofs, smb_wct - ofs);
	}

	return outsize2;
}

/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
int construct_reply(char *inbuf, char *outbuf, int size, int bufsize)
{
	int type = CVAL(inbuf, smb_com);
	int outsize = 0;
	int msg_type = CVAL(inbuf, 0);
	extern int chain_size;

	smb_last_time = time(NULL);

	chain_size = 0;
	chain_fnum = -1;

	bzero(outbuf, smb_size);

	if (msg_type != 0)
		return (reply_special(inbuf, outbuf));

	CVAL(outbuf, smb_com) = CVAL(inbuf, smb_com);
	set_message(outbuf, 0, 0, true);

	memcpy(outbuf + 4, inbuf + 4, 4);
	CVAL(outbuf, smb_rcls) = SMB_SUCCESS;
	CVAL(outbuf, smb_reh) = 0;
	CVAL(outbuf, smb_flg) =
	    0x80 | (CVAL(inbuf, smb_flg) & 0x8); /* bit 7 set
	                                         means a reply */
	SSVAL(outbuf, smb_flg2, 1); /* say we support long filenames */
	SSVAL(outbuf, smb_err, SMB_SUCCESS);
	SSVAL(outbuf, smb_tid, SVAL(inbuf, smb_tid));
	SSVAL(outbuf, smb_pid, SVAL(inbuf, smb_pid));
	SSVAL(outbuf, smb_uid, SVAL(inbuf, smb_uid));
	SSVAL(outbuf, smb_mid, SVAL(inbuf, smb_mid));

	outsize = switch_message(type, inbuf, outbuf, size, bufsize);

	outsize += chain_size;

	if (outsize > 4)
		smb_setlen(outbuf, outsize - 4);
	return (outsize);
}

/****************************************************************************
  process commands from the client
****************************************************************************/
static void process(void)
{
	extern int Client;

	InBuffer = (char *) malloc(BUFFER_SIZE + SAFETY_MARGIN);
	OutBuffer = (char *) malloc(BUFFER_SIZE + SAFETY_MARGIN);
	if ((InBuffer == NULL) || (OutBuffer == NULL))
		return;

	InBuffer += SMB_ALIGNMENT;
	OutBuffer += SMB_ALIGNMENT;

#if PRIME_NMBD
	DEBUG(3, ("priming nmbd\n"));
	{
		struct in_addr ip;
		ip = *interpret_addr2("localhost");
		if (ip.s_addr == 0) {
			ip = *interpret_addr2("127.0.0.1");
		}
		*OutBuffer = 0;
		send_one_packet(OutBuffer, 1, ip, NMB_PORT, SOCK_DGRAM);
	}
#endif

	/* re-initialise the timezone */
	TimeInit();

	while (true) {
		int deadtime = lp_deadtime() * 60;
		int counter;
		int service_load_counter = 0;
		bool got_smb = false;

		if (deadtime <= 0)
			deadtime = DEFAULT_SMBD_TIMEOUT;

		errno = 0;

		for (counter = SMBD_SELECT_LOOP;
		     !receive_message_or_smb(Client, InBuffer, BUFFER_SIZE,
		                             SMBD_SELECT_LOOP * 1000, &got_smb);
		     counter += SMBD_SELECT_LOOP) {
			int i;
			time_t t;
			bool allidle = true;

			if (counter > 365 * 3600) /* big number of seconds. */
			{
				counter = 0;
				service_load_counter = 0;
			}

			if (smb_read_error == READ_EOF) {
				DEBUG(3, ("end of file from client\n"));
				return;
			}

			if (smb_read_error == READ_ERROR) {
				DEBUG(3, ("receive_smb error (%s) exiting\n",
				          strerror(errno)));
				return;
			}

			t = time(NULL);

			/* become root again if waiting */
			unbecome_user();

			/* check for smb.conf reload */
			if (counter >=
			    service_load_counter + SMBD_RELOAD_CHECK) {
				service_load_counter = counter;

				/* reload services, if files have changed. */
				reload_services(true);
			}

			/*
			 * If reload_after_sighup == true then we got a SIGHUP
			 * and are being asked to reload. Fix from
			 * <branko.cibej@hermes.si>
			 */

			if (reload_after_sighup) {
				DEBUG(0, ("Reloading services after SIGHUP\n"));
				reload_services(false);
				reload_after_sighup = false;
			}

			/* automatic timeout if all connections are closed */
			if (num_connections_open == 0 &&
			    counter >= IDLE_CLOSED_TIMEOUT) {
				DEBUG(2, ("%s Closing idle connection\n",
				          timestring()));
				return;
			}

			/* check for connection timeouts */
			for (i = 0; i < MAX_CONNECTIONS; i++)
				if (Connections[i].open) {
					/* close dirptrs on connections that are
					 * idle */
					if ((t - Connections[i].lastused) >
					    DPTR_IDLE_TIMEOUT)
						dptr_idlecnum(i);

					if (Connections[i].num_files_open > 0 ||
					    (t - Connections[i].lastused) <
					        deadtime)
						allidle = false;
				}

			if (allidle && num_connections_open > 0) {
				DEBUG(2, ("%s Closing idle connection 2\n",
				          timestring()));
				return;
			}
		}

		if (got_smb)
			process_smb(InBuffer, OutBuffer);
	}
}

/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
static void init_structs(void)
{
	int i;
	get_myname(myhostname, NULL);

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		Connections[i].open = false;
		Connections[i].num_files_open = 0;
		Connections[i].lastused = 0;
		Connections[i].used = false;
		string_init(&Connections[i].user, "");
		string_init(&Connections[i].dirpath, "");
		string_init(&Connections[i].connectpath, "");
		string_init(&Connections[i].origpath, "");
	}

	for (i = 0; i < MAX_OPEN_FILES; i++) {
		Files[i].open = false;
		string_init(&Files[i].name, "");
	}

	for (i = 0; i < MAX_OPEN_FILES; i++) {
		file_fd_struct *fd_ptr = &FileFd[i];
		fd_ptr->ref_count = 0;
		fd_ptr->dev = (int32_t) -1;
		fd_ptr->inode = (int32_t) -1;
		fd_ptr->fd = -1;
		fd_ptr->fd_readonly = -1;
		fd_ptr->fd_writeonly = -1;
		fd_ptr->real_open_flags = -1;
	}

	init_dptrs();
}

/****************************************************************************
usage on the program
****************************************************************************/
static void usage(char *pname)
{
	DEBUG(0, ("Incorrect program usage - are you sure the command line is "
	          "correct?\n"));

	printf("Usage: %s [-D] [-p port] [-d debuglevel] [-l log basename] [-s "
	       "services file]\n",
	       pname);
	printf("Version %s\n", VERSION);
	printf("\t-D                    become a daemon\n");
	printf("\t-p port               listen on the specified port\n");
	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-l log basename.      Basename for log/debug files\n");
	printf("\t-s services file.     Filename of services file\n");
	printf("\t-P                    passive only\n");
	printf("\t-a                    overwrite log file, don't append\n");
	printf("\n");
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, char *argv[])
{
	extern bool append_log;
	/* shall I run as a daemon */
	bool is_daemon = false;
	int port = SMB_PORT;
	int opt;
	extern char *optarg;
	char pidFile[100];

	*pidFile = '\0';

#ifdef NEED_AUTH_PARAMETERS
	set_auth_parameters(argc, argv);
#endif

	append_log = true;

	TimeInit();

	pstrcpy(debugf, SMBLOGFILE);

	pstrcpy(remote_machine, "smb");

	setup_logging(argv[0], false);

	init_dos_char_table();

	/* make absolutely sure we run as root - to handle cases where people
	   are crazy enough to have it setuid */
#ifdef USE_SETRES
	setresuid(0, 0, 0);
#else
	setuid(0);
	seteuid(0);
	setuid(0);
	seteuid(0);
#endif

	fault_setup((void (*)(void *)) exit_server);
	signal(SIGTERM, SIGNAL_CAST dflt_sig);

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	umask(0);

	GetWd(OriginalDir);

	init_uid();

	/* this is for people who can't start the program correctly */
	while (argc > 1 && (*argv[1] != '-')) {
		argv++;
		argc--;
	}

	while ((opt = getopt(argc, argv, "O:i:l:s:d:Dp:hPaf:")) != EOF)
		switch (opt) {
		case 'f':
			strncpy(pidFile, optarg, sizeof(pidFile));
			break;
		case 'i':
			pstrcpy(scope, optarg);
			break;
		case 'P': {
			extern bool passive;
			passive = true;
		} break;
		case 's':
			pstrcpy(servicesf, optarg);
			break;
		case 'l':
			pstrcpy(debugf, optarg);
			break;
		case 'a': {
			extern bool append_log;
			append_log = !append_log;
		} break;
		case 'D':
			is_daemon = true;
			break;
		case 'd':
			if (*optarg == 'A')
				DEBUGLEVEL = 10000;
			else
				DEBUGLEVEL = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			usage(argv[0]);
			exit(1);
		}

	reopen_logs();

	DEBUG(2, ("%s smbd version %s started\n", timestring(), VERSION));
	DEBUG(2, ("Copyright Andrew Tridgell 1992-1997\n"));

#ifdef RLIMIT_NOFILE
	{
		struct rlimit rlp;
		getrlimit(RLIMIT_NOFILE, &rlp);
		/*
		 * Set the fd limit to be MAX_OPEN_FILES + 10 to account for the
		 * extra fd we need to read directories, as well as the log
		 * files and standard handles etc.
		 */
		rlp.rlim_cur = (MAX_OPEN_FILES + 10 > rlp.rlim_max)
		                 ? rlp.rlim_max
		                 : MAX_OPEN_FILES + 10;
		setrlimit(RLIMIT_NOFILE, &rlp);
		getrlimit(RLIMIT_NOFILE, &rlp);
		DEBUG(3, ("Maximum number of open files per session is %d\n",
		          rlp.rlim_cur));
	}
#endif

	DEBUG(2, ("uid=%d gid=%d euid=%d egid=%d\n", getuid(), getgid(),
	          geteuid(), getegid()));

	if (sizeof(uint16_t) < 2 || sizeof(uint32_t) < 4) {
		DEBUG(0, ("ERROR: Samba is not configured correctly for the "
		          "word size on your machine\n"));
		exit(1);
	}

	init_structs();

	if (!reload_services(false))
		return (-1);

	pstrcpy(myworkgroup, lp_workgroup());

#ifndef NO_SIGNAL_TEST
	signal(SIGHUP, SIGNAL_CAST sig_hup);
#endif

	/* Setup the signals that allow the debug log level
	   to by dynamically changed. */

	DEBUG(3, ("%s loaded services\n", timestring()));

	if (!is_daemon && !is_a_socket(0)) {
		DEBUG(0,
		      ("standard input is not a socket, assuming -D option\n"));
		is_daemon = true;
	}

	if (is_daemon) {
		DEBUG(3, ("%s becoming a daemon\n", timestring()));
		become_daemon();
	}

	if (*pidFile) {
		int fd;
		char buf[20];

		if ((fd = open(pidFile,
#ifdef O_NONBLOCK
		               O_NONBLOCK |
#endif
		                   O_CREAT | O_WRONLY | O_TRUNC,
		               0644)) < 0) {
			DEBUG(0, ("ERROR: can't open %s: %s\n", pidFile,
			          strerror(errno)));
			exit(1);
		}
		if (fcntl_lock(fd, F_SETLK, 0, 1, F_WRLCK) == false) {
			DEBUG(0, ("ERROR: smbd is already running\n"));
			exit(1);
		}
		slprintf(buf, sizeof(buf) - 1, "%u\n", (unsigned int) getpid());
		if (write(fd, buf, strlen(buf)) < 0) {
			DEBUG(0, ("ERROR: can't write to %s: %s\n", pidFile,
			          strerror(errno)));
			exit(1);
		}
		/* Leave pid file open & locked for the duration... */
	}

	if (!open_sockets(is_daemon, port))
		exit(1);

	/* possibly reload the services file. */
	reload_services(true);

	max_recv = MIN(lp_maxxmit(), BUFFER_SIZE);

	process();
	close_sockets();

	exit_server("normal exit");
	return (0);
}
