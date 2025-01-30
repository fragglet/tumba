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

#include "smb.h"

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
