/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Directory handling routines
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

#include "dir.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "local.h"
#include "smb.h"
#include "byteorder.h"
#include "includes.h"
#include "mangle.h"
#include "server.h"
#include "util.h"

extern int LOGLEVEL;
extern struct service_connection Connections[];

/*
   This module implements directory related functions for Samba.
*/

static uint32_t dircounter = 0;

#define NUMDIRPTRS 256

static struct dptr_struct {
	int pid;
	int cnum;
	uint32_t lastused;
	void *ptr;
	bool valid;
	bool finished;
	bool expect_close;
	char *wcard;   /* Field only used for lanman2 trans2_findfirst/next
	                  searches */
	uint16_t attr; /* Field only used for lanman2 trans2_findfirst/next
	                searches */
	char *path;
} dirptrs[NUMDIRPTRS];

static int dptrs_open = 0;

/****************************************************************************
initialise the dir array
****************************************************************************/
void init_dptrs(void)
{
	static bool dptrs_init = false;
	int i;

	if (dptrs_init)
		return;
	for (i = 0; i < NUMDIRPTRS; i++) {
		dirptrs[i].valid = false;
		dirptrs[i].wcard = NULL;
		dirptrs[i].ptr = NULL;
		string_init(&dirptrs[i].path, "");
	}
	dptrs_init = true;
}

/****************************************************************************
idle a dptr - the directory is closed but the control info is kept
****************************************************************************/
static void dptr_idle(int key)
{
	if (dirptrs[key].valid && dirptrs[key].ptr) {
		DEBUG("Idling dptr key %d\n", key);
		dptrs_open--;
		close_dir(dirptrs[key].ptr);
		dirptrs[key].ptr = NULL;
	}
}

/****************************************************************************
idle the oldest dptr
****************************************************************************/
static void dptr_idleoldest(void)
{
	int i;
	uint32_t old = dircounter + 1;
	int oldi = -1;
	for (i = 0; i < NUMDIRPTRS; i++)
		if (dirptrs[i].valid && dirptrs[i].ptr &&
		    dirptrs[i].lastused < old) {
			old = dirptrs[i].lastused;
			oldi = i;
		}
	if (oldi != -1)
		dptr_idle(oldi);
	else
		ERROR("No dptrs available to idle??\n");
}

/****************************************************************************
get the dir ptr for a dir index
****************************************************************************/
static void *dptr_get(int key, uint32_t lastused)
{
	struct dptr_struct *dp = &dirptrs[key];

	if (dp->valid) {
		if (lastused)
			dp->lastused = lastused;
		if (!dp->ptr) {
			if (dptrs_open >= MAXDIR)
				dptr_idleoldest();
			DEBUG("Reopening dptr key %d\n", key);
			if ((dp->ptr = open_dir(dp->cnum, dp->path)))
				dptrs_open++;
		}
		return dp->ptr;
	}
	return NULL;
}

/****************************************************************************
get the dir path for a dir index
****************************************************************************/
char *dptr_path(int key)
{
	if (dirptrs[key].valid)
		return dirptrs[key].path;
	return NULL;
}

/****************************************************************************
get the dir wcard for a dir index (lanman2 specific)
****************************************************************************/
char *dptr_wcard(int key)
{
	if (dirptrs[key].valid)
		return dirptrs[key].wcard;
	return NULL;
}

/****************************************************************************
set the dir wcard for a dir index (lanman2 specific)
Returns 0 on ok, 1 on fail.
****************************************************************************/
bool dptr_set_wcard(int key, char *wcard)
{
	if (dirptrs[key].valid) {
		dirptrs[key].wcard = wcard;
		return true;
	}
	return false;
}

/****************************************************************************
set the dir attrib for a dir index (lanman2 specific)
Returns 0 on ok, 1 on fail.
****************************************************************************/
bool dptr_set_attr(int key, uint16_t attr)
{
	if (dirptrs[key].valid) {
		dirptrs[key].attr = attr;
		return true;
	}
	return false;
}

/****************************************************************************
get the dir attrib for a dir index (lanman2 specific)
****************************************************************************/
uint16_t dptr_attr(int key)
{
	if (dirptrs[key].valid)
		return dirptrs[key].attr;
	return 0;
}

/****************************************************************************
close a dptr
****************************************************************************/
void dptr_close(int key)
{
	/* OS/2 seems to use -1 to indicate "close all directories" */
	if (key == -1) {
		int i;
		for (i = 0; i < NUMDIRPTRS; i++)
			dptr_close(i);
		return;
	}

	if (key < 0 || key >= NUMDIRPTRS) {
		INFO("Invalid key %d given to dptr_close\n", key);
		return;
	}

	if (dirptrs[key].valid) {
		DEBUG("closing dptr key %d\n", key);
		if (dirptrs[key].ptr) {
			close_dir(dirptrs[key].ptr);
			dptrs_open--;
		}
		/* Lanman 2 specific code */
		free(dirptrs[key].wcard);
		dirptrs[key].valid = false;
		string_set(&dirptrs[key].path, "");
	}
}

/****************************************************************************
close all dptrs for a cnum
****************************************************************************/
void dptr_closecnum(int cnum)
{
	int i;
	for (i = 0; i < NUMDIRPTRS; i++)
		if (dirptrs[i].valid && dirptrs[i].cnum == cnum)
			dptr_close(i);
}

/****************************************************************************
idle all dptrs for a cnum
****************************************************************************/
void dptr_idlecnum(int cnum)
{
	int i;
	for (i = 0; i < NUMDIRPTRS; i++)
		if (dirptrs[i].valid && dirptrs[i].cnum == cnum &&
		    dirptrs[i].ptr)
			dptr_idle(i);
}

/****************************************************************************
close a dptr that matches a given path, only if it matches the pid also
****************************************************************************/
void dptr_closepath(char *path, int pid)
{
	int i;
	for (i = 0; i < NUMDIRPTRS; i++)
		if (dirptrs[i].valid && pid == dirptrs[i].pid &&
		    strequal(dirptrs[i].path, path))
			dptr_close(i);
}

/****************************************************************************
  start a directory listing
****************************************************************************/
static bool start_dir(int cnum, char *directory)
{
	DEBUG("start_dir cnum=%d dir=%s\n", cnum, directory);

	if (!check_name(directory, cnum))
		return false;

	if (!*directory)
		directory = ".";

	Connections[cnum].dirptr = open_dir(cnum, directory);
	if (Connections[cnum].dirptr) {
		dptrs_open++;
		string_set(&Connections[cnum].dirpath, directory);
		return true;
	}

	return false;
}

/****************************************************************************
create a new dir ptr
****************************************************************************/
int dptr_create(int cnum, char *path, bool expect_close, int pid)
{
	int i;
	uint32_t old;
	int oldi;

	if (!start_dir(cnum, path))
		return -2; /* Code to say use a unix error return code. */

	if (dptrs_open >= MAXDIR)
		dptr_idleoldest();

	for (i = 0; i < NUMDIRPTRS; i++)
		if (!dirptrs[i].valid)
			break;
	if (i == NUMDIRPTRS)
		i = -1;

	/* as a 2nd option, grab the oldest not marked for expect_close */
	if (i == -1) {
		old = dircounter + 1;
		oldi = -1;
		for (i = 0; i < NUMDIRPTRS; i++)
			if (!dirptrs[i].expect_close &&
			    dirptrs[i].lastused < old) {
				old = dirptrs[i].lastused;
				oldi = i;
			}
		i = oldi;
	}

	/* a 3rd option - grab the oldest one */
	if (i == -1) {
		old = dircounter + 1;
		oldi = -1;
		for (i = 0; i < NUMDIRPTRS; i++)
			if (dirptrs[i].lastused < old) {
				old = dirptrs[i].lastused;
				oldi = i;
			}
		i = oldi;
	}

	if (i == -1) {
		ERROR("Error - all dirptrs in use??\n");
		return -1;
	}

	if (dirptrs[i].valid)
		dptr_close(i);

	dirptrs[i].ptr = Connections[cnum].dirptr;
	string_set(&dirptrs[i].path, path);
	dirptrs[i].lastused = dircounter++;
	dirptrs[i].finished = false;
	dirptrs[i].cnum = cnum;
	dirptrs[i].pid = pid;
	dirptrs[i].expect_close = expect_close;
	dirptrs[i].wcard = NULL; /* Only used in lanman2 searches */
	dirptrs[i].attr = 0;     /* Only used in lanman2 searches */
	dirptrs[i].valid = true;

	DEBUG("creating new dirptr %d for path %s, expect_close = %d\n", i,
	      path, expect_close);

	return i;
}

#define DPTR_MASK ((uint32_t) (((uint32_t) 1) << 31))

/****************************************************************************
fill the 5 byte server reserved dptr field
****************************************************************************/
bool dptr_fill(char *buf1, unsigned int key)
{
	unsigned char *buf = (unsigned char *) buf1;
	void *p = dptr_get(key, 0);
	uint32_t offset;
	if (!p) {
		WARNING("filling null dirptr %d\n", key);
		return false;
	}
	offset = tell_dir(p);
	DEBUG("fill on key %d dirptr 0x%x now at %d\n", key, p, offset);
	buf[0] = key;
	SIVAL(buf, 1, offset | DPTR_MASK);
	return true;
}

/****************************************************************************
return true is the offset is at zero
****************************************************************************/
bool dptr_zero(char *buf)
{
	return (IVAL(buf, 1) & ~DPTR_MASK) == 0;
}

/****************************************************************************
fetch the dir ptr and seek it given the 5 byte server field
****************************************************************************/
void *dptr_fetch(char *buf, int *num)
{
	unsigned int key = *(unsigned char *) buf;
	void *p = dptr_get(key, dircounter++);
	uint32_t offset;
	if (!p) {
		INFO("fetched null dirptr %d\n", key);
		return NULL;
	}
	*num = key;
	offset = IVAL(buf, 1) & ~DPTR_MASK;
	seek_dir(p, offset);
	DEBUG("fetching dirptr %d for path %s at offset %d\n", key,
	      dptr_path(key), offset);
	return p;
}

/****************************************************************************
fetch the dir ptr.
****************************************************************************/
void *dptr_fetch_lanman2(int dptr_num)
{
	void *p = dptr_get(dptr_num, dircounter++);

	if (!p) {
		INFO("fetched null dirptr %d\n", dptr_num);
		return NULL;
	}
	DEBUG("fetching dirptr %d for path %s\n", dptr_num,
	      dptr_path(dptr_num));
	return p;
}

/****************************************************************************
check a filetype for being valid
****************************************************************************/
bool dir_check_ftype(int cnum, int mode, struct stat *st, int dirtype)
{
	if (((mode & ~dirtype) & (aHIDDEN | aSYSTEM | aDIR)) != 0)
		return false;
	return true;
}

/****************************************************************************
  get a directory entry
****************************************************************************/
bool get_dir_entry(int cnum, char *mask, int dirtype, char *fname, int *size,
                   int *mode, time_t *date)
{
	char *dname;
	bool found = false;
	struct stat sbuf;
	pstring path;
	pstring pathreal;
	bool isrootdir;
	pstring filename;
	bool needslash;

	*path = *pathreal = *filename = 0;

	isrootdir = (strequal(Connections[cnum].dirpath, "./") ||
	             strequal(Connections[cnum].dirpath, ".") ||
	             strequal(Connections[cnum].dirpath, "/"));

	needslash =
	    (Connections[cnum].dirpath[strlen(Connections[cnum].dirpath) - 1] !=
	     '/');

	if (!Connections[cnum].dirptr)
		return false;

	while (!found) {
		dname = read_dir_name(Connections[cnum].dirptr);

		DEBUG("readdir on dirptr 0x%x now at offset %d\n",
		      Connections[cnum].dirptr,
		      tell_dir(Connections[cnum].dirptr));

		if (dname == NULL)
			return false;

		pstrcpy(filename, dname);

		if (strcmp(filename, mask) != 0) {
			name_map_mangle(filename, true, CONN_SHARE(cnum));
			if (!mask_match(filename, mask, false)) {
				continue;
			}
		}

		if (isrootdir &&
		    (strequal(filename, "..") || strequal(filename, "."))) {
			continue;
		}

		pstrcpy(fname, filename);
		*path = 0;
		pstrcpy(path, Connections[cnum].dirpath);
		if (needslash)
			pstrcat(path, "/");
		pstrcpy(pathreal, path);
		pstrcat(path, fname);
		pstrcat(pathreal, dname);
		if (stat(pathreal, &sbuf) != 0) {
			DEBUG("Couldn't stat 1 [%s]\n", path);
			continue;
		}

		*mode = dos_mode(cnum, pathreal, &sbuf);

		if (!dir_check_ftype(cnum, *mode, &sbuf, dirtype)) {
			DEBUG("[%s] attribs didn't match %x\n", filename,
			      dirtype);
			continue;
		}

		*size = sbuf.st_size;
		*date = sbuf.st_mtime;

		DEBUG("get_dir_entry found %s fname=%s\n", pathreal, fname);

		found = true;
	}

	return found;
}

typedef struct {
	int pos;
	int numentries;
	int mallocsize;
	char *data;
	char *current;
} Dir;

/*******************************************************************
open a directory
********************************************************************/
void *open_dir(int cnum, char *name)
{
	Dir *dirp;
	struct dirent *de;
	DIR *d = opendir(name);
	int used = 0;

	if (d == NULL) {
		return NULL;
	}
	dirp = checked_malloc(sizeof(Dir));
	dirp->pos = dirp->numentries = dirp->mallocsize = 0;
	dirp->data = dirp->current = NULL;

	while ((de = readdir(d)) != NULL) {
		int l = strlen(de->d_name) + 1;

		if (used + l > dirp->mallocsize) {
			int s = MAX(used + l, used + 2000);
			dirp->data = checked_realloc(dirp->data, s);
			dirp->mallocsize = s;
			dirp->current = dirp->data;
		}
		pstrcpy(dirp->data + used, de->d_name);
		used += l;
		dirp->numentries++;
	}

	closedir(d);
	return (void *) dirp;
}

/*******************************************************************
close a directory
********************************************************************/
void close_dir(void *p)
{
	Dir *dirp = (Dir *) p;
	if (!dirp)
		return;
	free(dirp->data);
	free(dirp);
}

/*******************************************************************
read from a directory
********************************************************************/
char *read_dir_name(void *p)
{
	char *ret;
	Dir *dirp = (Dir *) p;

	if (!dirp || !dirp->current || dirp->pos >= dirp->numentries)
		return NULL;

	ret = dirp->current;
	dirp->current = skip_string(dirp->current, 1);
	dirp->pos++;

	return ret;
}

/*******************************************************************
seek a dir
********************************************************************/
bool seek_dir(void *p, int pos)
{
	Dir *dirp = (Dir *) p;

	if (!dirp)
		return false;

	if (pos < dirp->pos) {
		dirp->current = dirp->data;
		dirp->pos = 0;
	}

	while (dirp->pos < pos && read_dir_name(p))
		;

	return dirp->pos == pos;
}

/*******************************************************************
tell a dir position
********************************************************************/
int tell_dir(void *p)
{
	Dir *dirp = (Dir *) p;

	if (!dirp)
		return -1;

	return dirp->pos;
}

/* -------------------------------------------------------------------------- **
 * This section manages a global directory cache.
 * (It should probably be split into a separate module.  crh)
 * -------------------------------------------------------------------------- **
 */

typedef struct {
	char *path;
	char *name;
	char *dname;
	const struct share *share;
} dir_cache_entry;

static dir_cache_entry *dir_cache[DIRCACHESIZE];
static int dir_cache_head = 0, dir_cache_tail = 0;

/* ------------------------------------------------------------------------ **
 * Add an entry to the directory cache.
 * ------------------------------------------------------------------------ **/
void dir_cache_add(char *path, char *name, char *dname,
                   const struct share *share)
{
	int pathlen, namelen, new_head;
	dir_cache_entry *entry;

	/* Allocate the structure & string space in one go so that it can be
	 * freed in one call to free().
	 */
	pathlen =
	    strlen(path) + 1; /* Bytes required to store path (with nul). */
	namelen =
	    strlen(name) + 1; /* Bytes required to store name (with nul). */
	entry = checked_malloc(sizeof(dir_cache_entry) + pathlen + namelen +
	                       strlen(dname) + 1);

	/* Set pointers correctly and load values. */
	entry->path = pstrcpy((char *) &entry[1], path);
	entry->name = pstrcpy(&(entry->path[pathlen]), name);
	entry->dname = pstrcpy(&(entry->name[namelen]), dname);
	entry->share = share;

	/* Add the new entry to the cache. Free up an entry if needed. */
	new_head = (dir_cache_head + 1) % DIRCACHESIZE;
	if (new_head == dir_cache_tail) {
		free(dir_cache[dir_cache_tail]);
		dir_cache_tail = (dir_cache_tail + 1) % DIRCACHESIZE;
	}
	dir_cache[new_head] = entry;
	dir_cache_head = new_head;
	DEBUG("Added dir cache entry %s %s -> %s\n", path, name, dname);
}

/* ------------------------------------------------------------------------ **
 * Search for an entry to the directory cache.
 *
 *  Output: The dname string of the located entry, or NULL if the entry was
 *          not found.
 *
 *  Notes:  This uses a linear search, which is is okay because of
 *          the small size of the cache.
 * ------------------------------------------------------------------------ **
 */
char *dir_cache_check(char *path, char *name, const struct share *share)
{
	dir_cache_entry *entry;
	int idx;

	for (idx = dir_cache_head; idx != dir_cache_tail;
	     idx = (idx + DIRCACHESIZE - 1) % DIRCACHESIZE) {
		entry = dir_cache[idx];
		if (entry->share == share && 0 == strcmp(name, entry->name) &&
		    0 == strcmp(path, entry->path)) {
			DEBUG("Got dir cache hit on %s %s -> %s\n", path, name,
			      entry->dname);
			return entry->dname;
		}
	}

	return NULL;
}

/* ------------------------------------------------------------------------ **
 * Remove all cache entries which have a share that matches the input.
 * ------------------------------------------------------------------------ **/
void dir_cache_flush(const struct share *share)
{
	dir_cache_entry *entry;
	int idx, new_tail = dir_cache_head;

	for (idx = dir_cache_head; idx != dir_cache_tail;
	     idx = (idx + DIRCACHESIZE - 1) % DIRCACHESIZE) {
		entry = dir_cache[idx];
		dir_cache[idx] = NULL;

		if (entry->share == share) {
			free(entry);
		} else {
			dir_cache[new_tail] = entry;
			new_tail = (new_tail + DIRCACHESIZE - 1) % DIRCACHESIZE;
		}
	}

	dir_cache_tail = new_tail;
}

/* -------------------------------------------------------------------------- **
 * End of the section that manages the global directory cache.
 * -------------------------------------------------------------------------- **
 */
