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

#define RUN_AS_USER    "nobody"
#define DOSATTRIB_NAME "user.DOSATTRIB"

#define MAX_MUX 50

extern pstring debugf;

static bool allow_public_connections = false;

static char *InBuffer = NULL;
static char *OutBuffer = NULL;
static char *last_inbuf = NULL;

static int am_parent = 1;

/* the last message the was processed */
static int last_message = -1;

/* a useful macro to debug the last message processed */
#define LAST_MESSAGE() smb_fn_name(last_message)

extern int DEBUGLEVEL;
static time_t smb_last_time = (time_t) 0;

extern int smb_read_error;
extern int Client;

connection_struct Connections[MAX_CONNECTIONS];
files_struct Files[MAX_OPEN_FILES];

/*
 * Indirection for file fd's. Needed as POSIX locking is based on file/process,
 * not fd/process. Context:
 * <https://www.samba.org/samba/news/articles/low_point/tale_two_stds_os2.html>
 * TODO: The 2024 POSIX spec now includes OFD locks, so this can be replaced
 */
static file_fd_struct FileFd[MAX_OPEN_FILES];
static int max_file_fd_used = 0;

extern int Protocol;

const char *workgroup = "WORKGROUP";
static const char *bind_addr = "0.0.0.0";

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

/* these can be set by some functions to override the error codes */
int unix_ERR_class = SMB_SUCCESS;
int unix_ERR_code = 0;

static int find_free_connection(int hash);

/* for readability... */
#define IS_DOS_READONLY(test_mode) (((test_mode) & aRONLY) != 0)
#define IS_DOS_DIR(test_mode)      (((test_mode) & aDIR) != 0)
#define IS_DOS_ARCHIVE(test_mode)  (((test_mode) & aARCH) != 0)
#define IS_DOS_SYSTEM(test_mode)   (((test_mode) & aSYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode)   (((test_mode) & aHIDDEN) != 0)

/****************************************************************************
  when exiting, take the whole family
****************************************************************************/
static void *dflt_sig(void)
{
	exit_server("caught signal");
	return 0; /* Keep -Wall happy :-) */
}

/****************************************************************************
  Send a SIGTERM to our process group.
*****************************************************************************/
static void killkids(void)
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

	/* Note: We set bits for owner, group and other; the user can override
	   this trivially by setting the program's umask */
	if (!IS_DOS_READONLY(dosmode))
		result |= (S_IWUSR | S_IWGRP | S_IWOTH);

	if (IS_DOS_DIR(dosmode)) {
		result |= S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH;
	}
	return result;
}

static int read_dosattrib(const char *path)
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

	return strtol(buf + 2, NULL, 16) & (aARCH | aSYSTEM | aHIDDEN);
}

static void write_dosattrib(const char *path, int attrib)
{
	struct stat st;
	char buf[5];
	int result, new_mode;

	snprintf(buf, sizeof(buf), "0x%02x", attrib);
	result = sys_setxattr(path, DOSATTRIB_NAME, buf, strlen(buf));
	if (result != 0) {
		DEBUG(8, ("setxattr on %s returned %d (errno=%d)\n", path,
		          result, errno));
	}
	if (result == 0 || errno != EACCES) {
		return;
	}

	DEBUG(8, ("permission denied setting DOSATTRIB on %s, "
	          "trying mode switch workaround\n",
	          path));
	/* We got permission denied trying to set the xattr. This may be
	   because the file is write-protected. So set the permissions to
	   allow writes and try again. */
	if (stat(path, &st) != 0) {
		DEBUG(8, ("failed to stat %s\n", path));
		return;
	}
	new_mode = st.st_mode | S_IWUSR;
	if (st.st_mode == new_mode) {
		/* We got permission denied for a different reason */
		DEBUG(8, ("failed to stat %s\n", path));
		return;
	}
	if (chmod(path, new_mode) != 0) {
		DEBUG(8, ("failed to chmod %s to %o\n", path, new_mode));
		return;
	}
	result = sys_setxattr(path, DOSATTRIB_NAME, buf, strlen(buf));
	if (result != 0) {
		DEBUG(8, ("setxattr on %s failed (second attempt)\n", path));
	} else {
		DEBUG(8, ("mode switch workaround succeeded\n"));
	}
	/* Change back to the old permissions */
	if (chmod(path, st.st_mode) != 0) {
		DEBUG(8, ("failed to chmod %s back to %o\n", path, st.st_mode));
	}
}

/****************************************************************************
  change a unix mode to a dos mode
****************************************************************************/
int dos_mode(int cnum, char *path, struct stat *sbuf)
{
	int result = 0;

	DEBUG(8, ("dos_mode: %d %s\n", cnum, path));

	if (CAN_WRITE(cnum)) {
		if ((sbuf->st_mode & S_IWOTH) == 0 &&
		    ((sbuf->st_mode & S_IWUSR) == 0 ||
		     geteuid() != sbuf->st_uid)) {
			result |= aRONLY;
		}
	} else if ((sbuf->st_mode & S_IWUSR) == 0) {
		result |= aRONLY;
	}

	result |= read_dosattrib(path);

	if (S_ISDIR(sbuf->st_mode))
		result = aDIR | (result & aRONLY);

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

	return result;
}

/*******************************************************************
chmod a file - but preserve some bits
********************************************************************/
int dos_chmod(int cnum, char *fname, int dosmode, struct stat *st)
{
	struct stat st1;
	int mask = 0;
	int unixmode, um;

	if (!st) {
		st = &st1;
		if (stat(fname, st))
			return -1;
	}

	if (S_ISDIR(st->st_mode))
		dosmode |= aDIR;

	if (dos_mode(cnum, fname, st) == dosmode)
		return 0;

	unixmode = unix_mode(cnum, dosmode);

	/* preserve the s bits */
	mask |= (S_ISUID | S_ISGID);

	/* preserve the t bit */
#ifdef S_ISVTX
	mask |= S_ISVTX;
#endif
	write_dosattrib(fname, dosmode);

	unixmode |= (st->st_mode & mask);

	/* unix_mode sets bits for owner, group and other, so apply the
	   process's umask like we do when creating a new file */
	um = umask(0);
	umask(um);
	unixmode &= ~um;

	/* if we previously had any r bits set then leave them alone */
	unixmode = (unixmode & ~(S_IRUSR | S_IRGRP | S_IROTH)) |
	           (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH));

	/* if we previously had any w bits set then leave them alone
	 if the new mode is not rdonly */
	if (!IS_DOS_READONLY(dosmode)) {
		unixmode = (unixmode & ~(S_IWUSR | S_IWGRP | S_IWOTH)) |
		           (st->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH));
	}

	return chmod(fname, unixmode);
}

/*******************************************************************
Change a filetime
*******************************************************************/
bool set_filetime(int cnum, char *fname, time_t mtime)
{
	struct utimbuf times;

	if (null_mtime(mtime))
		return true;

	times.modtime = times.actime = mtime;

	if (sys_utime(fname, &times) != 0) {
		DEBUG(4, ("set_filetime(%s) failed: %s\n", fname,
		          strerror(errno)));
	}

	return true;
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
		return ret;
	}

	if (l2 - l1 == 1 && name2[l2 - 1] == '.' && lp_strip_dot()) {
		bool ret;
		name2[l2 - 1] = 0;
		ret = fname_equal(name1, name2);
		name2[l2 - 1] = '.';
		return ret;
	}

	return strequal(name1, name2);
}

/****************************************************************************
mangle the 2nd name and check if it is then equal to the first name
****************************************************************************/
static bool mangled_equal(char *name1, char *name2)
{
	pstring tmpname;

	if (is_8_3(name2, true))
		return false;

	pstrcpy(tmpname, name2);
	mangle_name_83(tmpname, sizeof(pstring) - 1);

	return strequal(name1, tmpname);
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

	if (docache &&
	    (dname = dir_cache_check(path, name, CONN_SHARE(cnum)))) {
		pstrcpy(name, dname);
		return true;
	}

	/*
	 * The incoming name can be mangled, and if we de-mangle it
	 * here it will not compare correctly against the filename (name2)
	 * read from the directory and then mangled by the name_map_mangle()
	 * call. We need to mangle both names or neither.
	 * (JRA).
	 */

	/* open the directory */
	if (!(cur_dir = open_dir(cnum, path))) {
		DEBUG(3, ("scan dir didn't open dir [%s]\n", path));
		return false;
	}

	/* now scan for matching names */
	while ((dname = read_dir_name(cur_dir))) {
		if (*dname == '.' &&
		    (strequal(dname, ".") || strequal(dname, "..")))
			continue;

		pstrcpy(name2, dname);
		name_map_mangle(name2, false, CONN_SHARE(cnum));

		if ((mangled && mangled_equal(name, name2)) ||
		    fname_equal(name, name2)) {
			/* we've found the file, change it's name and return */
			if (docache)
				dir_cache_add(path, name, dname,
				              CONN_SHARE(cnum));
			pstrcpy(name, dname);
			close_dir(cur_dir);
			return true;
		}
	}

	close_dir(cur_dir);
	return false;
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

	if (is_8_3(name, false))
		strnorm(name);

	/* stat the name - if it exists then we are all done! */
	if (stat(name, &st) == 0)
		return true;

	DEBUG(5, ("unix_convert(%s,%d)\n", name, cnum));

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
				return false;
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
					return false;
				}

				/* just the last part of the name doesn't exist
				 */

				DEBUG(5, ("New file %s\n", start));
				return true;
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
	return true;
}

/****************************************************************************
  return number of 1K blocks available on a path and total number
****************************************************************************/
static int disk_free(char *path, int *bsize, int *dfree, int *dsize)
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

static bool path_within(const char *path, const char *top)
{
	size_t top_len = strlen(top);
	return strlen(path) >= top_len && strncmp(top, path, top_len) == 0 &&
	       (path[top_len] == '/' || path[top_len] == '\0');
}

static void set_parent_dir(char *parent, char *path)
{
	char *p;

	pstrcpy(parent, path);
	p = strrchr(parent, '/');
	if (p != NULL) {
		*p = '\0';
	} else {
		pstrcpy(parent, ".");
	}
}

/****************************************************************************
check a filename - possibly caling reducename

This is called by every routine before it allows an operation on a filename.
It does any final confirmation necessary to ensure that the filename is
a valid one for the user to access.
****************************************************************************/
bool check_name(char *name, int cnum)
{
	char *canon_path;
	const char *top = Connections[cnum].connectpath;
	char old_wd[PATH_MAX];
	bool success = false;

	if (CONN_SHARE(cnum) == ipc_service) {
		return true;
	}

	/* A weird corner case that is probably a bad idea, but ... */
	if (!strcmp(top, "/")) {
		return true;
	}
	if (getcwd(old_wd, sizeof(old_wd)) == NULL) {
		DEBUG(3,
		      ("check_name: denied: getcwd() errno=%d\n", top, errno));
		return false;
	}
	if (chdir(top) != 0) {
		DEBUG(3,
		      ("check_name: denied: chdir(%s) errno=%d\n", top, errno));
		return false;
	}

	/* TODO: There should maybe be an option to allow symlinks to certain
	   allow-listed directories. */

	/* To check it's a valid path, we check the realpath()-expanded
	   filename (with all symlinks removed) is either equal to the
	   top-level directory or is a subpath. This guarantees that it is
	   never possible to use a symlink to escape from the share dir. */
	canon_path = realpath(name, NULL);
	if (canon_path != NULL) {
		/* We have a path to a real file or directory. */
		success = path_within(canon_path, top);
		free(canon_path);
	} else if (errno == ENOENT) {
		pstring parent;

		/* The file doesn't exist, but we aren't done; for example,
		   "*.*" is used for directory listings. Check the enclosing
		   directory is valid. */
		set_parent_dir(parent, name);
		canon_path = realpath(parent, NULL);
		if (canon_path == NULL) {
			DEBUG(3,
			      ("check_name: realpath(%s) errno=%d (parent)\n",
			       parent, errno));
		}
		success = canon_path != NULL && path_within(canon_path, top);
		if (success) {
			DEBUG(3, ("check_name: no file %s but parent %s "
			          "within %s\n",
			          name, parent, top));
		}
		free(canon_path);
	}

	if (!success) {
		DEBUG(3, ("check_name: denied: %s not within %s subtree\n",
		          name, top));
	}

	if (chdir(old_wd) != 0) {
		DEBUG(3, ("check_name: ending chdir(%s) errno=%d\n", old_wd,
		          errno));
	}

	return success;
}

/****************************************************************************
check a filename - possibly caling reducename
****************************************************************************/
static void check_for_pipe(char *fname)
{
	/* special case of pipe opens */
	char s[10];
	strlcpy(s, fname, sizeof(s));
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
		fsp->can_lock = true;
		fsp->can_read = ((flags & O_WRONLY) == 0);
		fsp->can_write = ((flags & (O_WRONLY | O_RDWR)) != 0);
		fsp->share_mode = 0;
		fsp->modified = false;
		fsp->cnum = cnum;
		string_set(&fsp->name, fname);
		fsp->wbmpx_ptr = NULL;

		DEBUG(2, ("%s opened file %s read=%s write=%s (numopen=%d "
		          "fnum=%d)\n",
		          timestring(), fname, BOOLSTR(fsp->can_read),
		          BOOLSTR(fsp->can_write),
		          Connections[cnum].num_files_open, fnum));
	}
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
	free(fs_p->wbmpx_ptr);
	fs_p->wbmpx_ptr = NULL;

	fd_attempt_close(fs_p->fd_ptr);

	DEBUG(2, ("%s closed file %s (numopen=%d)\n", timestring(), fs_p->name,
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
		if (!file_existed || (flags & (O_CREAT | O_TRUNC)) != 0) {
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
	return Files[fnum].pos;
}

/****************************************************************************
read from a file
****************************************************************************/
int read_file(int fnum, char *data, uint32_t pos, int n)
{
	int ret = 0, readret;

	if (n <= 0)
		return ret;

	if (seek_file(fnum, pos) != pos) {
		DEBUG(3, ("Failed to seek to %d\n", pos));
		return ret;
	}

	if (n > 0) {
		readret = read(Files[fnum].fd_ptr->fd, data, n);
		if (readret > 0)
			ret += readret;
	}

	return ret;
}

/****************************************************************************
write to a file
****************************************************************************/
int write_file(int fnum, char *data, int n)
{
	if (!Files[fnum].can_write) {
		errno = EPERM;
		return 0;
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

	return write_data(Files[fnum].fd_ptr->fd, data, n);
}

/****************************************************************************
load parameters specific to a connection/service
****************************************************************************/
static bool become_service(int cnum)
{
	static int last_cnum = -1;

	if (!OPEN_CNUM(cnum)) {
		last_cnum = -1;
		return false;
	}

	Connections[cnum].lastused = smb_last_time;

	if (CONN_SHARE(cnum) != ipc_service &&
	    chdir(Connections[cnum].connectpath) != 0) {
		DEBUG(0, ("%s chdir (%s) failed cnum=%d\n", timestring(),
		          Connections[cnum].connectpath, cnum));
		return false;
	}

	if (cnum == last_cnum)
		return true;

	last_cnum = cnum;

	return true;
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

	return error_packet(inbuf, outbuf, eclass, ecode, line);
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

	return outsize;
}

/****************************************************************************
this prevents zombie child processes
****************************************************************************/
static int sigchld_handler(void)
{
	static int depth = 0;
	if (depth != 0) {
		DEBUG(0, ("ERROR: Recursion in sigchld_handler?"));
		depth = 0;
		return 0;
	}
	depth++;

	block_signals(true, SIGCHLD);
	DEBUG(5, ("got SIGCHLD\n"));

	while (waitpid((pid_t) -1, (int *) NULL, WNOHANG) > 0) {
	}

	/* Stop zombies */
	/* Stevens, Adv. Unix Prog. says that on system V you must call
	   wait before reinstalling the signal handler, because the kernel
	   calls the handler from within the signal-call when there is a
	   child that has exited. This would lead to an infinite recursion
	   if done vice versa. */
	signal(SIGCHLD, SIGNAL_CAST sigchld_handler);

	depth--;
	block_signals(false, SIGCHLD);
	return 0;
}

/****************************************************************************
  this is called when the client exits abruptly
  **************************************************************************/
static int sig_pipe(void)
{
	block_signals(true, SIGPIPE);

	exit_server("Got sigpipe\n");
	return 0;
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

/* Detect if we are running as root and if so, drop privileges and run as an
   unprivileged user instead. We shouldn't ever need to run as root (if
   someone is trying, they're doing it wrong), but it can make sense to start
   the service as root so that the privileged sockets can be opened first. */
static void drop_privileges(void)
{
	struct passwd *pw;

	/* Only drop privileges if we're running as root */
	if (getuid() != 0) {
		return;
	}

	pw = getpwnam(RUN_AS_USER);
	if (pw == NULL) {
		/* TODO: Should there be an option to override? */
		DEBUG(0, ("Failed to look up user %s, cowardly refusing "
		          "to run as root.\n",
		          RUN_AS_USER));
		exit(1);
	}

	DEBUG(0, ("Dropping privileges, running as user %s (uid=%d)\n",
	          RUN_AS_USER, pw->pw_uid));
	if (setgid(pw->pw_gid) != 0 || setegid(pw->pw_gid) != 0 ||
	    setuid(pw->pw_uid) != 0 || seteuid(pw->pw_uid) != 0) {
		DEBUG(0, ("Failed to drop privileges: %s\n", strerror(errno)));
		exit(1);
	}
}

static int open_server_socket(int type, int port, int dlevel,
                              in_addr_t socket_addr)
{
	struct sockaddr_in sock;
	int one = 1;
	int res;

	res = socket(AF_INET, SOCK_STREAM, 0);
	if (res == -1) {
		DEBUG(0, ("socket failed\n"));
		return -1;
	}

	setsockopt(res, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one));

	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	sock.sin_addr.s_addr = socket_addr;

	/* now we've got a socket - we need to bind it */
	if (bind(res, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		DEBUG(dlevel,
		      ("bind failed on port %d socket_addr=%s (%s)\n", port,
		       inet_ntoa(sock.sin_addr), strerror(errno)));
		close(res);

		return -1;
	}
	DEBUG(3, ("bind succeeded on port %d\n", port));

	return res;
}

/* is_private_peer checks if the connecting client comes either from a
 * localhost address or from one of the RFC 1918 private ranges. */
static bool is_private_peer(void)
{
	struct sockaddr_in sockin;
	socklen_t length = sizeof(sockin);
	int i;
	const struct {
		in_addr_t addr;
		int bits;
	} ranges[] = {
	    {inet_addr("10.0.0.0"), 8},
	    {inet_addr("192.168.0.0"), 16},
	    {inet_addr("172.16.0.0"), 20},
	    {inet_addr("127.0.0.1"), 8},
	};

	if (getpeername(Client, (struct sockaddr *) &sockin, &length) < 0) {
		DEBUG(0, ("is_private_peer: getpeername failed\n"));
		return false;
	}

	for (i = 0; i < sizeof(ranges) / sizeof(*ranges); i++) {
		in_addr_t mask = ~((1 << (32 - ranges[i].bits)) - 1);
		if ((ntohl(sockin.sin_addr.s_addr) & mask) ==
		    (ntohl(ranges[i].addr) & mask)) {
			return true;
		}
	}

	return false;
}

/****************************************************************************
  open the socket communication
****************************************************************************/
static bool open_sockets(int port)
{
	struct in_addr addr;
	int server_socket;

	/* Stop zombies */
	signal(SIGCHLD, SIGNAL_CAST sigchld_handler);

	atexit(killkids);

	/* open an incoming socket */
	if (inet_aton(bind_addr, &addr) == 0) {
		DEBUG(0, ("open_sockets: failed to parse bind address %s\n",
		bind_addr));
		return false;
	}
	server_socket = open_server_socket(SOCK_STREAM, port, 0, addr.s_addr);
	if (server_socket == -1) {
		return false;
	}

	drop_privileges();

	/* ready to listen */
	if (listen(server_socket, 5) == -1) {
		DEBUG(0, ("open_sockets: listen: %s\n", strerror(errno)));
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

		num = select(server_socket + 1, &listen_set, NULL, NULL, NULL);

		if (num < 0 && errno == EINTR) {
			continue;
		}

		if (!FD_ISSET(server_socket, &listen_set)) {
			continue;
		}

		Client = accept(server_socket, &addr, &in_addrlen);

		if (Client == -1 && errno == EINTR)
			continue;

		if (Client == -1) {
			DEBUG(0,
			      ("open_sockets: accept: %s\n", strerror(errno)));
			continue;
		}

		/* The BSD sockets API does not provide any way to reject TCP
		   connections, the best we can do is to accept the connection
		   and then immediately close it. By default we only allow
		   connections from local peers on the same private IP range. */
		if (!is_private_peer()) {
			if (!allow_public_connections) {
				DEBUG(0, ("open_sockets: rejecting connection from "
				          "public IP address %s\n",
				          client_addr()));
				close(Client);
				Client = -1;
				continue;
			}
			/* even if allowed, log a warning */
			DEBUG(0, ("open_sockets: warning: connection from "
			          "public IP address %s\n",
			          client_addr()));
		}

		if (fork() == 0) {

			/* only the parent catches SIGCHLD */
			signal(SIGPIPE, SIGNAL_CAST sig_pipe);
			signal(SIGCHLD, SIGNAL_CAST SIG_DFL);

			/* close the listening socket */
			close(server_socket);

			/* close our standard file descriptors */
			close_low_fds();
			am_parent = 0;

			set_keepalive_option(Client);

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

	return true;
}

/****************************************************************************
  read an smb from a fd. Note that the buffer *MUST* be of size
  BUFFER_SIZE+SAFETY_MARGIN.
  The timeout is in milli seconds.

  This function will return on a
  receipt of a session keepalive packet.
****************************************************************************/
static bool receive_smb(int fd, char *buffer, int timeout)
{
	int len, ret;

	smb_read_error = 0;

	bzero(buffer, smb_size + 100);

	len = read_smb_length_return_keepalive(fd, buffer, timeout);
	if (len < 0)
		return false;

	if (len > BUFFER_SIZE) {
		DEBUG(0, ("Invalid packet length! (%d bytes).\n", len));
		if (len > BUFFER_SIZE + (SAFETY_MARGIN / 2))
			exit(1);
	}

	if (len > 0) {
		ret = read_data(fd, buffer + 4, len);
		if (ret != len) {
			smb_read_error = READ_ERROR;
			return false;
		}
	}
	return true;
}

/****************************************************************************
  Do a select on an two fd's - with timeout.

  If a local udp message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this first.

  If a pending smb message has been pushed onto the
  queue (this can only happen during oplock break
  processing) return this next.

  If the first smbfd is ready then read an smb from it.
  if the second (loopback UDP) fd is ready then read a message
  from it and setup the buffer header to identify the length
  and from address.
  Returns false on timeout or error.
  Else returns true.

The timeout is in milli seconds
****************************************************************************/
static bool receive_message_or_smb(int smbfd, char *buffer, int buffer_len,
                                   int timeout, bool *got_smb)
{
	fd_set fds;
	int selrtn;
	struct timeval to;

	smb_read_error = 0;

	*got_smb = false;

	do {
		FD_ZERO(&fds);
		FD_SET(smbfd, &fds);

		to.tv_sec = timeout / 1000;
		to.tv_usec = (timeout % 1000) * 1000;

		selrtn = select(smbfd + 1, &fds, NULL, NULL,
		                timeout > 0 ? &to : NULL);
	} while (selrtn < 0 && errno == EINTR);

	/* Check if error */
	if (selrtn == -1) {
		/* something is wrong. Maybe the socket is dead? */
		smb_read_error = READ_ERROR;
		return false;
	}

	/* Did we timeout ? */
	if (selrtn == 0) {
		smb_read_error = READ_TIMEOUT;
		return false;
	}

	if (FD_ISSET(smbfd, &fds)) {
		*got_smb = true;
		return receive_smb(smbfd, buffer, 0);
	} else {
		return false;
	}
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
this prevents zombie child processes
****************************************************************************/

static int sig_hup(void)
{
	block_signals(true, SIGHUP);
	DEBUG(0, ("Got SIGHUP\n"));

#ifndef DONT_REINSTALL_SIG
	signal(SIGHUP, SIGNAL_CAST sig_hup);
#endif
	block_signals(false, SIGHUP);
	return 0;
}

static bool dir_world_writeable(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0) {
		DEBUG(8,
		      ("failed to stat %s, assuming read-only share\n", path));
		return false;
	}

	/* Our way of configuring a share as read-only / writeable is to set
	   o+w permissions on the directory. Since we don't do any kind of user
	   authentication on shares, it's reasonable that any directory
	   writeable over smb is also writeable by local users */
	return S_ISDIR(st.st_mode) && (st.st_mode & S_IWOTH) != 0;
}

/****************************************************************************
  make a connection to a service
****************************************************************************/
int make_connection(char *service, char *dev)
{
	const struct share *share;
	int cnum;
	connection_struct *pcon;

	strlower(service);

	share = lookup_share(service);
	if (share == NULL) {
		if (strequal(service, "IPC$")) {
			DEBUG(3,
			      ("%s refusing IPC connection\n", timestring()));
			return -3;
		}

		DEBUG(0, ("%s (%s) couldn't find service %s\n", timestring(),
		          client_addr(), service));
		return -2;
	}

	/* you can only connect to the IPC$ service as an ipc device */
	if (share == ipc_service) {
		pstrcpy(dev, "IPC");
	} else if (*dev == '?' || !*dev) {
		pstrcpy(dev, "A:");
	}

	/* if the request is as a printer and you can't print then refuse */
	strupper(dev);
	if (strncmp(dev, "LPT", 3) == 0) {
		DEBUG(1, ("Attempt to connect to non-printer as a printer\n"));
		return -6;
	}

	cnum = find_free_connection(str_checksum(service));
	if (cnum < 0) {
		DEBUG(0, ("%s couldn't find free connection\n", timestring()));
		return -1;
	}

	pcon = &Connections[cnum];
	bzero((char *) pcon, sizeof(*pcon));

	pcon->read_only =
	    share == ipc_service || !dir_world_writeable(share->path);
	pcon->num_files_open = 0;
	pcon->lastused = time(NULL);
	pcon->share = share;
	pcon->used = true;
	pcon->dirptr = NULL;
	pcon->connectpath = NULL;
	string_set(&pcon->dirpath, "");

	if (share != ipc_service) {
		char *canon_path;
		pstring s;
		pstrcpy(s, share->path);
		/* Convert path to its canonical form (no ../ or symlinks,
		   etc.). This is important because check_name() does the same
		   thing and expects all files to be subpaths. */
		canon_path = realpath(s, NULL);
		if (canon_path == NULL) {
			DEBUG(3, ("realpath(%s) failed, errno=%d\n", s, errno));
			pcon->open = false;
			return -1;
		}
		string_set(&pcon->connectpath, canon_path);
		DEBUG(3, ("Connect path is %s\n", canon_path));
		free(canon_path);
	}

	pcon->open = true;

	if (share != ipc_service && chdir(pcon->connectpath) != 0) {
		DEBUG(0, ("Can't change directory to %s (%s)\n",
		          pcon->connectpath, strerror(errno)));
		pcon->open = false;
		return -5;
	}

	num_connections_open++;

	DEBUG(1, ("%s (%s) connect to service %s (pid %d)\n", timestring(),
	          client_addr(), CONN_SHARE(cnum)->name, (int) getpid()));

	return cnum;
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
			return i;
		}

	/* returning a file handle of 0 is a bad idea - so we start at 1 */
	for (i = 1; i < first_file; i++)
		if (!Files[i].open && !Files[i].reserved) {
			memset(&Files[i], 0, sizeof(Files[i]));
			first_file = i + 1;
			Files[i].reserved = true;
			return i;
		}

	DEBUG(1, ("ERROR! Out of file structures - perhaps increase "
	          "MAX_OPEN_FILES?\n"));
	return -1;
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
			return i;
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
	return -1;
}

/****************************************************************************
reply for the core protocol
****************************************************************************/
static int reply_corep(char *outbuf)
{
	int outsize = set_message(outbuf, 1, 0, true);

	Protocol = PROTOCOL_CORE;

	return outsize;
}

/****************************************************************************
reply for the coreplus protocol
****************************************************************************/
static int reply_coreplus(char *outbuf)
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
static int reply_lanman1(char *outbuf)
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
	SSVAL(outbuf, smb_vwv10, time_diff(t) / 60);

	put_dos_date(outbuf, smb_vwv8, t);

	return smb_len(outbuf) + 4;
}

/****************************************************************************
reply for the lanman 2.0 protocol
****************************************************************************/
static int reply_lanman2(char *outbuf)
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
	SSVAL(outbuf, smb_vwv10, time_diff(t) / 60);
	put_dos_date(outbuf, smb_vwv8, t);

	return smb_len(outbuf) + 4;
}

/****************************************************************************
reply for the nt protocol
****************************************************************************/
static int reply_nt1(char *outbuf)
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
	data_len = crypt_len + strlen(workgroup) + 1;

	set_message(outbuf, 17, data_len, true);
	pstrcpy(smb_buf(outbuf) + crypt_len, workgroup);

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
	SSVALS(outbuf, smb_vwv15 + 1, time_diff(t) / 60);
	SSVAL(outbuf, smb_vwv17,
	      data_len); /* length of challenge+domain strings */

	return smb_len(outbuf) + 4;
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

#define ARCH_WFWG  0x3 /* This is a fudge because WfWg is like Win95 */
#define ARCH_WIN95 0x2
#define ARCH_OS2   0xC /* Again OS/2 is like NT */
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
		outsize = supported_protocols[protocol].proto_reply_fn(outbuf);
		DEBUG(3, ("Selected protocol %s\n",
		          supported_protocols[protocol].proto_name));
	} else {
		DEBUG(0, ("No protocol supported !\n"));
	}
	SSVAL(outbuf, smb_vwv0, choice);

	DEBUG(5, ("%s negprot index=%d\n", timestring(), choice));

	return outsize;
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
	dir_cache_flush(CONN_SHARE(cnum));

	if (!OPEN_CNUM(cnum)) {
		DEBUG(0, ("Can't close cnum %d\n", cnum));
		return;
	}

	DEBUG(1, ("%s (%s) closed connection to service %s\n", timestring(),
	          client_addr(), CONN_SHARE(cnum)->name));

	close_open_files(cnum);
	dptr_closecnum(cnum);

	Connections[cnum].open = false;
	num_connections_open--;

	string_set(&Connections[cnum].dirpath, "");
	string_set(&Connections[cnum].connectpath, "");
}

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
	}

	DEBUG(3,
	      ("%s Server exit  (%s)\n", timestring(), reason ? reason : ""));
	exit(0);
}

/*
These flags determine some of the permissions required to do an operation

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define NEED_WRITE      (1 << 1)
#define TIME_INIT       (1 << 2)
#define ALLOWED_IN_IPC  (1 << 3)
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
    {SMBgetatr, "SMBgetatr", reply_getatr, 0},
    {SMBsetatr, "SMBsetatr", reply_setatr, NEED_WRITE},
    {SMBchkpth, "SMBchkpth", reply_chkpth, 0},
    {SMBsearch, "SMBsearch", reply_search, 0},
    {SMBopen, "SMBopen", reply_open, QUEUE_IN_OPLOCK},

    /* note that SMBmknew and SMBcreate are deliberately overloaded */
    {SMBcreate, "SMBcreate", reply_mknew, 0},
    {SMBmknew, "SMBmknew", reply_mknew, 0},

    {SMBunlink, "SMBunlink", reply_unlink, NEED_WRITE | QUEUE_IN_OPLOCK},
    {SMBread, "SMBread", reply_read, 0},
    {SMBwrite, "SMBwrite", reply_write, 0},
    {SMBclose, "SMBclose", reply_close, ALLOWED_IN_IPC},
    {SMBmkdir, "SMBmkdir", reply_mkdir, NEED_WRITE},
    {SMBrmdir, "SMBrmdir", reply_rmdir, NEED_WRITE},
    {SMBdskattr, "SMBdskattr", reply_dskattr, 0},
    {SMBmv, "SMBmv", reply_mv, NEED_WRITE | QUEUE_IN_OPLOCK},

    /* this is a Pathworks specific call, allowing the
       changing of the root path */
    {pSETDIR, "pSETDIR", reply_setdir, 0},

    {SMBlseek, "SMBlseek", reply_lseek, 0},
    {SMBflush, "SMBflush", reply_flush, 0},
    {SMBctemp, "SMBctemp", reply_ctemp, QUEUE_IN_OPLOCK},
    {SMBsplopen, "SMBsplopen", reply_printopen, QUEUE_IN_OPLOCK},
    {SMBsplclose, "SMBsplclose", reply_printclose, 0},
    {SMBsplretq, "SMBsplretq", reply_printqueue, 0},
    {SMBsplwr, "SMBsplwr", reply_printwrite, 0},
    {SMBlock, "SMBlock", reply_lock, 0},
    {SMBunlock, "SMBunlock", reply_unlock, 0},

    /* CORE+ PROTOCOL FOLLOWS */

    {SMBreadbraw, "SMBreadbraw", reply_readbraw, 0},
    {SMBwritebraw, "SMBwritebraw", reply_writebraw, 0},
    {SMBwriteclose, "SMBwriteclose", reply_writeclose, 0},
    {SMBlockread, "SMBlockread", reply_lockread, 0},
    {SMBwriteunlock, "SMBwriteunlock", reply_writeunlock, 0},

    /* LANMAN1.0 PROTOCOL FOLLOWS */

    {SMBreadBmpx, "SMBreadBmpx", reply_readbmpx, 0},
    {SMBreadBs, "SMBreadBs", NULL, 0},
    {SMBwriteBmpx, "SMBwriteBmpx", reply_writebmpx, 0},
    {SMBwriteBs, "SMBwriteBs", reply_writebs, 0},
    {SMBwritec, "SMBwritec", NULL, 0},
    {SMBsetattrE, "SMBsetattrE", reply_setattrE, NEED_WRITE},
    {SMBgetattrE, "SMBgetattrE", reply_getattrE, 0},
    {SMBtrans, "SMBtrans", reply_trans, ALLOWED_IN_IPC},
    {SMBtranss, "SMBtranss", NULL, ALLOWED_IN_IPC},
    {SMBioctls, "SMBioctls", NULL, 0},
    {SMBcopy, "SMBcopy", reply_copy, NEED_WRITE | QUEUE_IN_OPLOCK},
    {SMBmove, "SMBmove", NULL, NEED_WRITE | QUEUE_IN_OPLOCK},

    {SMBopenX, "SMBopenX", reply_open_and_X, ALLOWED_IN_IPC | QUEUE_IN_OPLOCK},
    {SMBreadX, "SMBreadX", reply_read_and_X, 0},
    {SMBwriteX, "SMBwriteX", reply_write_and_X, 0},
    {SMBlockingX, "SMBlockingX", reply_lockingX, 0},

    {SMBffirst, "SMBffirst", reply_search, 0},
    {SMBfunique, "SMBfunique", reply_search, 0},
    {SMBfclose, "SMBfclose", reply_fclose, 0},

    /* LANMAN2.0 PROTOCOL FOLLOWS */
    {SMBfindnclose, "SMBfindnclose", reply_findnclose, 0},
    {SMBfindclose, "SMBfindclose", reply_findclose, 0},
    {SMBtrans2, "SMBtrans2", reply_trans2, 0},
    {SMBtranss2, "SMBtranss2", reply_transs2, 0},

    /* messaging routines */
    {SMBsends, "SMBsends", NULL, 0},
    {SMBsendstrt, "SMBsendstrt", NULL, 0},
    {SMBsendend, "SMBsendend", NULL, 0},
    {SMBsendtxt, "SMBsendtxt", NULL, 0},

    /* NON-IMPLEMENTED PARTS OF THE CORE PROTOCOL */

    {SMBsendb, "SMBsendb", NULL, 0},
    {SMBfwdname, "SMBfwdname", NULL, 0},
    {SMBcancelf, "SMBcancelf", NULL, 0},
    {SMBgetmac, "SMBgetmac", NULL, 0}};

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
		return unknown_name;

	return smb_messages[match].name;
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
		return -1;
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

			/* does it need write permission? */
			if ((flags & NEED_WRITE) && !CAN_WRITE(cnum))
				return ERROR(ERRSRV, ERRaccess);

			/* load service specific parameters */
			if (OPEN_CNUM(cnum) && !become_service(cnum)) {
				return ERROR(ERRSRV, ERRaccess);
			}

			/* for the IPC service, only certain messages are
			 * allowed */
			if (OPEN_CNUM(cnum) && CONN_SHARE(cnum) == ipc_service &&
			    (flags & ALLOWED_IN_IPC) == 0) {
				return ERROR(ERRSRV, ERRaccess);
			}

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

	return outsize;
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
	int outsize2, ofs;
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
	ofs = smb_wct - PTR_DIFF(outbuf2, orig_outbuf);
	if (ofs < 0)
		ofs = 0;
	memmove(outbuf2 + ofs, outbuf_saved + ofs, smb_wct - ofs);

	return outsize2;
}

/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
static int construct_reply(char *inbuf, char *outbuf, int size, int bufsize)
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
		return reply_special(inbuf, outbuf);

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
	return outsize;
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
send a single packet to a port on another machine
****************************************************************************/
static bool send_one_packet(char *buf, int len, struct in_addr ip, int port,
                            int type)
{
	bool ret;
	int out_fd;
	struct sockaddr_in sock_out;

	/* create a socket to write to */
	out_fd = socket(AF_INET, type, 0);
	if (out_fd == -1) {
		DEBUG(0, ("socket failed"));
		return false;
	}

	/* set the address and port */
	bzero((char *) &sock_out, sizeof(sock_out));
	sock_out.sin_family = AF_INET;
	sock_out.sin_addr = ip;
	sock_out.sin_port = htons(port);

	if (DEBUGLEVEL > 0)
		DEBUG(3, ("sending a packet of len %d to (%s) on port %d of "
		          "type %s\n",
		          len, inet_ntoa(ip), port,
		          type == SOCK_DGRAM ? "DGRAM" : "STREAM"));

	/* send it */
	ret = (sendto(out_fd, buf, len, 0, (struct sockaddr *) &sock_out,
	              sizeof(sock_out)) >= 0);

	if (!ret)
		DEBUG(0, ("Packet send to %s(%d) failed ERRNO=%s\n",
		          inet_ntoa(ip), port, strerror(errno)));

	close(out_fd);
	return ret;
}

/****************************************************************************
  process commands from the client
****************************************************************************/
static void process(void)
{
	extern int Client;

	InBuffer = checked_malloc(BUFFER_SIZE + SAFETY_MARGIN);
	OutBuffer = checked_malloc(BUFFER_SIZE + SAFETY_MARGIN);

	InBuffer += SMB_ALIGNMENT;
	OutBuffer += SMB_ALIGNMENT;

#if PRIME_NMBD
	DEBUG(3, ("priming nmbd\n"));
	{
		struct in_addr ip = {htonl(INADDR_LOOPBACK)};
		*OutBuffer = 0;
		send_one_packet(OutBuffer, 1, ip, NMB_PORT, SOCK_DGRAM);
	}
#endif

	/* re-initialise the timezone */
	time_init();

	while (true) {
		int counter;
		bool got_smb = false;

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
					        DEFAULT_SMBD_TIMEOUT)
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

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		Connections[i].open = false;
		Connections[i].num_files_open = 0;
		Connections[i].lastused = 0;
		Connections[i].used = false;
		string_init(&Connections[i].dirpath, "");
		string_init(&Connections[i].connectpath, "");
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
static void usage(void)
{
	DEBUG(0, ("Incorrect program usage - are you sure the command line is "
	          "correct?\n"));

	printf("Rumba version " VERSION "\n"
	       "Usage: rumba_smbd [-a] [-W workgroup] [-p port] "
	       "[-d debuglevel] [-l log basename]\n"
	       "                  <path> [paths...]\n\n"
	       "   -a                allow connections from all addresses\n"
	       "   -b addr           bind to given address\n"
	       "   -p port           listen on the specified port\n"
	       "   -d debuglevel     set the debuglevel\n"
	       "   -l log basename.  basename for log/debug files\n"
	       "   -W workgroup      override workgroup name\n"
	       "\n");
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, char *argv[])
{
	int port = SMB_PORT;
	int opt;
	extern char *optarg;

#ifdef NEED_AUTH_PARAMETERS
	set_auth_parameters(argc, argv);
#endif

	time_init();

	pstrcpy(debugf, SMBLOGFILE);

	setup_logging(argv[0], false);

	init_dos_char_table();

	signal(SIGTERM, SIGNAL_CAST dflt_sig);

	while ((opt = getopt(argc, argv, "b:l:d:p:haW:")) != EOF) {
		switch (opt) {
		case 'a':
			allow_public_connections = true;
			break;
		case 'b':
			bind_addr = optarg;
			break;
		case 'l':
			pstrcpy(debugf, optarg);
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
			usage();
			exit(0);
			break;
		case 'W':
			workgroup = optarg;
			break;
		default:
			usage();
			exit(1);
		}
	}

	/* User must specify at least one path to share */
	if (optind == argc) {
		usage();
		exit(1);
	}

	for (opt = optind; opt < argc; ++opt) {
		add_share(argv[opt]);
	}

	add_ipc_service();

	reopen_logs();

	DEBUG(2, ("%s smbd version %s started\n", timestring(), VERSION));
	DEBUG(2, ("Copyright Andrew Tridgell 1992-1997\n"));

	DEBUG(2, ("uid=%d gid=%d euid=%d egid=%d\n", getuid(), getgid(),
	          geteuid(), getegid()));

	init_structs();

#ifndef NO_SIGNAL_TEST
	signal(SIGHUP, SIGNAL_CAST sig_hup);
#endif

	/* Setup the signals that allow the debug log level
	   to by dynamically changed. */

	DEBUG(3, ("%s loaded services\n", timestring()));

	if (!open_sockets(port))
		exit(1);

	drop_privileges();

	max_recv = MIN(lp_maxxmit(), BUFFER_SIZE);

	process();
	close_sockets();

	exit_server("normal exit");
	return 0;
}
