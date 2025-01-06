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

/*The following definitions come from  dir.c  */

void init_dptrs(void);
char *dptr_path(int key);
char *dptr_wcard(int key);
bool dptr_set_wcard(int key, char *wcard);
bool dptr_set_attr(int key, uint16_t attr);
uint16_t dptr_attr(int key);
void dptr_close(int key);
void dptr_closecnum(int cnum);
void dptr_idlecnum(int cnum);
void dptr_closepath(char *path, int pid);
int dptr_create(int cnum, char *path, bool expect_close, int pid);
bool dptr_fill(char *buf1, unsigned int key);
bool dptr_zero(char *buf);
void *dptr_fetch(char *buf, int *num);
void *dptr_fetch_lanman2(int dptr_num);
bool dir_check_ftype(int cnum, int mode, struct stat *st, int dirtype);
bool get_dir_entry(int cnum, char *mask, int dirtype, char *fname, int *size,
                   int *mode, time_t *date);
void *OpenDir(int cnum, char *name);
void CloseDir(void *p);
char *ReadDirName(void *p);
bool SeekDir(void *p, int pos);
int TellDir(void *p);
void DirCacheAdd(char *path, char *name, char *dname, const struct share *);
char *DirCacheCheck(char *path, char *name, const struct share *);
void DirCacheFlush(const struct share *);

/*The following definitions come from  ipc.c  */

int reply_trans(char *inbuf, char *outbuf, int size, int bufsize);

/*The following definitions come from  locking.c  */

bool do_lock(int fnum, int cnum, uint32_t count, uint32_t offset, int lock_type,
             int *eclass, uint32_t *ecode);
bool do_unlock(int fnum, int cnum, uint32_t count, uint32_t offset, int *eclass,
               uint32_t *ecode);
bool locking_end(void);

/*The following definitions come from  mangle.c  */

int str_checksum(char *s);
bool is_8_3(char *fname, bool check_case);
void reset_mangled_stack(int size);
bool check_mangled_stack(char *s);
bool is_mangled(char *s);
void mangle_name_83(char *s, int s_len);
void name_map_mangle(char *OutName, bool need83, const struct share *share);

/*The following definitions come from  reply.c  */

int reply_special(char *inbuf, char *outbuf);
int reply_tcon(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_tcon_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_unknown(char *inbuf, char *outbuf);
int reply_ioctl(char *inbuf, char *outbuf, int size, int bufsize);
int reply_sesssetup_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_chkpth(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_getatr(char *inbuf, char *outbuf, int in_size, int buffsize);
int reply_setatr(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_dskattr(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_search(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_fclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_open(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_open_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_ulogoffX(char *inbuf, char *outbuf, int length, int bufsize);
int reply_mknew(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_ctemp(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_unlink(char *inbuf, char *outbuf, int dum_size, int dum_bufsize);
int reply_readbraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_lockread(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_read(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_read_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_writebraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_writeunlock(char *inbuf, char *outbuf, int dum_size,
                      int dum_buffsize);
int reply_write(char *inbuf, char *outbuf, int dum1, int dum2);
int reply_write_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_lseek(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_flush(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_exit(char *inbuf, char *outbuf, int size, int bufsize);
int reply_close(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_writeclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_lock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_unlock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_tdis(char *inbuf, char *outbuf, int size, int bufsize);
int reply_echo(char *inbuf, char *outbuf, int size, int bufsize);
int reply_printopen(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_printclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_printqueue(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_printwrite(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_mkdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_rmdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_mv(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_copy(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_setdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_lockingX(char *inbuf, char *outbuf, int length, int bufsize);
int reply_readbmpx(char *inbuf, char *outbuf, int length, int bufsize);
int reply_writebmpx(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_writebs(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_setattrE(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_getattrE(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);

/*The following definitions come from  server.c  */

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

/*The following definitions come from shares.c  */

const struct share *lookup_share(const char *name);
const struct share *add_share(const char *path);
void add_ipc_service(void);
const struct share *get_share(unsigned int idx);
int shares_count(void);

/*The following definitions come from  slprintf.c  */

int vslprintf(char *str, int n, char *format, va_list ap);

/*The following definitions come from  system.c  */

int sys_select(fd_set *fds, struct timeval *tval);
int sys_select(fd_set *fds, struct timeval *tval);
int sys_utime(char *fname, struct utimbuf *times);
ssize_t sys_getxattr(const char *path, const char *name, void *value,
                     size_t size);
ssize_t sys_setxattr(const char *path, const char *name, void *value,
                     size_t size);

/*The following definitions come from  time.c  */

void TimeInit(void);
int TimeDiff(time_t t);
time_t interpret_long_date(char *p);
void put_long_date(char *p, time_t t);
bool null_mtime(time_t mtime);
void put_dos_date(char *buf, int offset, time_t unixdate);
void put_dos_date2(char *buf, int offset, time_t unixdate);
void put_dos_date3(char *buf, int offset, time_t unixdate);
time_t make_unix_date2(void *date_ptr);
time_t make_unix_date3(void *date_ptr);
char *timestring(void);
time_t get_create_time(struct stat *st);

/*The following definitions come from  trans2.c  */

void mask_convert(char *mask);
int reply_findclose(char *inbuf, char *outbuf, int length, int bufsize);
int reply_findnclose(char *inbuf, char *outbuf, int length, int bufsize);
int reply_transs2(char *inbuf, char *outbuf, int length, int bufsize);
int reply_trans2(char *inbuf, char *outbuf, int length, int bufsize);

/*The following definitions come from  util.c  */

void setup_logging(char *pname, bool interactive);
void reopen_logs(void);
void force_check_log_size(void);
void array_promote(char *array, int elsize, int element);
void close_sockets(void);
bool file_exist(char *fname, struct stat *sbuf);
bool directory_exist(char *dname, struct stat *st);
uint32_t file_size(char *file_name);
int isdoschar(int c);
void init_dos_char_table(void);
bool strequal(const char *s1, const char *s2);
bool strcsequal(char *s1, char *s2);
void strlower(char *s);
void strupper(char *s);
void strnorm(char *s);
bool strisnormal(char *s);
void unix_format(char *fname);
void show_msg(char *buf);
int smb_len(char *buf);
void _smb_setlen(char *buf, int len);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, bool zero);
int smb_buflen(char *buf);
char *smb_buf(char *buf);
int smb_offset(char *p, char *buf);
char *skip_string(char *buf, int n);
bool trim_string(char *s, char *front, char *back);
void unix_clean_name(char *s);
bool strhasupper(char *s);
void make_dir_struct(char *buf, char *mask, char *fname, unsigned int size,
                     int mode, time_t date);
void close_low_fds(void);
int read_data(int fd, char *buffer, int N);
int write_data(int fd, char *buffer, int N);
int transfer_file(int infd, int outfd, int n, char *header, int headlen,
                  int align);
int read_smb_length_return_keepalive(int fd, char *inbuf, int timeout);
int read_smb_length(int fd, char *inbuf, int timeout);
bool send_smb(int fd, char *buffer);
int name_extract(char *buf, int ofs, char *name);
int name_len(char *s);
bool send_one_packet(char *buf, int len, struct in_addr ip, int port, int type);
bool string_init(char **dest, char *src);
void string_free(char **s);
bool string_set(char **dest, char *src);
bool string_sub(char *s, char *pattern, char *insert);
bool mask_match(char *str, char *regexp, bool trans2);
void become_daemon(void);
int set_filelen(int fd, long len);
void *Realloc(void *p, int size);
const char *client_addr(void);
int PutUniCode(char *dst, char *src);
char *gidtoname(int gid);
void BlockSignals(bool block, int signum);
void ajt_panic(void);
char *readdirname(void *p);
char *safe_strcpy(char *dest, char *src, int dest_size);
char *safe_strcat(char *dest, char *src, int dest_size);
char *tab_depth(int depth);
