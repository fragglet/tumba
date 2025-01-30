/*
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

#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "strfunc.h"

#define NMB_PORT   137
#define DGRAM_PORT 138
#define SMB_PORT   139

/* set these to define the limits of the server. NOTE These are on a
   per-client basis. Thus any one machine can't connect to more than
   MAX_CONNECTIONS services, but any number of machines may connect at
   one time. */
#define MAX_CONNECTIONS 127
#define MAX_OPEN_FILES  100

/* Macro to cache an error in a struct bmpx_data */
#define CACHE_ERROR_CODE(w, c, e)                                              \
	((w)->wr_errclass = (c), (w)->wr_error = (e), w->wr_discard = true, -1)
/* Macro to test if an error has been cached for this fnum */
#define HAS_CACHED_ERROR_CODE(fnum)                                            \
	(Files[(fnum)].open && Files[(fnum)].wbmpx_ptr &&                      \
	 Files[(fnum)].wbmpx_ptr->wr_discard)
/* Macro to turn the cached error into an error packet */
#define CACHED_ERROR_CODE(fnum)                                                \
	cached_error_packet(inbuf, outbuf, fnum, __LINE__)

#define ERROR_CODE(class, x) error_packet(inbuf, outbuf, class, x, __LINE__)

/* this is how errors are generated */
#define UNIX_ERROR_CODE(defclass, deferror)                                    \
	unix_error_packet(inbuf, outbuf, defclass, deferror, __LINE__)

/* these are useful macros for checking validity of handles */
#define VALID_FNUM(fnum) (((fnum) >= 0) && ((fnum) < MAX_OPEN_FILES))
#define OPEN_FNUM(fnum)  (VALID_FNUM(fnum) && Files[fnum].open)
#define VALID_CNUM(cnum) (((cnum) >= 0) && ((cnum) < MAX_CONNECTIONS))
#define OPEN_CNUM(cnum)  (VALID_CNUM(cnum) && Connections[cnum].open)
#define FNUM_OK(fnum, c) (OPEN_FNUM(fnum) && (c) == Files[fnum].cnum)

#define CHECK_FNUM(fnum, c)                                                    \
	if (!FNUM_OK(fnum, c))                                                 \
	return (ERROR_CODE(ERRDOS, ERRbadfid))
#define CHECK_READ(fnum)                                                       \
	if (!Files[fnum].can_read)                                             \
	return (ERROR_CODE(ERRDOS, ERRbadaccess))
#define CHECK_WRITE(fnum)                                                      \
	if (!Files[fnum].can_write)                                            \
	return (ERROR_CODE(ERRDOS, ERRbadaccess))
#define CHECK_ERROR(fnum)                                                      \
	if (HAS_CACHED_ERROR_CODE(fnum))                                       \
	return (CACHED_ERROR_CODE(fnum))

/* translates a connection number into a service number */
#define CONN_SHARE(cnum) (Connections[cnum].share)

/* access various service details */
#define CAN_WRITE(cnum) (OPEN_CNUM(cnum) && !Connections[cnum].read_only)

/* Structure used to indirect fd's from the struct open_file. Needed as POSIX
 * locking is based on file and process, not file descriptor and process. */
struct open_fd {
	uint16_t ref_count;
	uint32_t dev;
	uint32_t inode;
	int fd;
	int fd_readonly;
	int fd_writeonly;
	int real_open_flags;
};

/* Structure used when SMBwritebmpx is active */
struct bmpx_data {
	int wr_total_written; /* So we know when to discard this */
	int32_t wr_timeout;
	int32_t wr_errclass;
	int32_t wr_error; /* Cached errors */
	bool wr_mode;     /* write through mode) */
	bool wr_discard;  /* discard all further data */
};

struct open_file {
	int cnum;
	struct open_fd *fd_ptr;
	int pos;
	uint32_t size;
	int mode;
	struct bmpx_data *wbmpx_ptr;
	struct timeval open_time;
	bool open;
	bool can_lock;
	bool can_read;
	bool can_write;
	bool share_mode;
	bool modified;
	bool reserved;
	char *name;
};

struct service_connection {
	const struct share *share;
	void *dirptr;
	bool open;
	bool read_only;
	char *dirpath;
	char *connectpath;

	time_t lastused;
	bool used;
	int num_files_open;
};

extern const char *workgroup;
extern int chain_fnum;
extern int max_send;
extern int max_recv;
extern struct open_file Files[];
extern struct service_connection Connections[];

/* Integers used to override error codes.  */
extern int unix_ERR_class;
extern int unix_ERR_code;

mode_t unix_mode(int cnum, int dosmode);
int dos_mode(int cnum, char *path, struct stat *sbuf);
int dos_chmod(int cnum, char *fname, int dosmode, struct stat *st);
bool set_filetime(int cnum, char *fname, time_t mtime);
bool unix_convert(char *name, int cnum, pstring saved_last_component,
                  bool *bad_path);
int sys_disk_free(char *path, int *bsize, int *dfree, int *dsize);
bool check_name(char *name, int cnum);
void close_file(int fnum, bool normal_close);
void open_file_shared(int fnum, int cnum, char *fname, int share_mode, int ofun,
                      int mode, int *Access, int *action);
int seek_file(int fnum, uint32_t pos);
int read_file(int fnum, char *data, uint32_t pos, int n);
int write_file(int fnum, char *data, int n);
int cached_error_packet(char *inbuf, char *outbuf, int fnum, int line);
int unix_error_packet(char *inbuf, char *outbuf, int def_class,
                      uint32_t def_code, int line);
int error_packet(char *inbuf, char *outbuf, int error_class,
                 uint32_t error_code, int line);
bool receive_next_smb(int smbfd, char *inbuf, int bufsize, int timeout);
int make_connection(char *service, char *dev);
int find_free_file(void);
void close_cnum(int cnum);
void exit_server(char *reason);
char *smb_fn_name(int type);
int chain_reply(char *inbuf, char *outbuf, int size, int bufsize);
