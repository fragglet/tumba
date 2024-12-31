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
void DirCacheAdd(char *path, char *name, char *dname, int snum);
char *DirCacheCheck(char *path, char *name, int snum);
void DirCacheFlush(int snum);

/*The following definitions come from  fault.c  */

void fault_setup(void (*fn)(void *));

/*The following definitions come from  interface.c  */

void load_interfaces(void);
int iface_count(void);
struct in_addr *iface_n_ip(int n);

/*The following definitions come from  ipc.c  */

int reply_trans(char *inbuf, char *outbuf, int size, int bufsize);

/*The following definitions come from  loadparm.c  */

char *lp_servicename(int);
char *lp_pathname(int);
char *lp_comment(int);
bool lp_casesensitive(int);
bool lp_shortpreservecase(int);
int lp_defaultcase(int);
int lp_add_service(char *pszService, int iDefaultService);
bool lp_file_list_changed(void);
bool lp_do_parameter(int snum, char *pszParmName, char *pszParmValue);
bool lp_snum_ok(int iService);
bool lp_loaded(void);
void lp_killunused(bool (*snumused)(int));
bool lp_load(char *pszFname);
int lp_numservices(void);
void lp_dump(FILE *f);
int lp_servicenumber(char *pszServiceName);

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
void name_map_mangle(char *OutName, bool need83, int snum);

/*The following definitions come from  params.c  */

bool pm_process(char *FileName, bool (*sfunc)(char *),
                bool (*pfunc)(char *, char *));

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

void *dflt_sig(void);
mode_t unix_mode(int cnum, int dosmode);
int dos_mode(int cnum, char *path, struct stat *sbuf);
int dos_chmod(int cnum, char *fname, int dosmode, struct stat *st);
bool set_filetime(int cnum, char *fname, time_t mtime);
bool unix_convert(char *name, int cnum, pstring saved_last_component,
                  bool *bad_path);
int disk_free(char *path, int *bsize, int *dfree, int *dsize);
int sys_disk_free(char *path, int *bsize, int *dfree, int *dsize);
bool check_name(char *name, int cnum);
void close_file(int fnum, bool normal_close);
void open_file_shared(int fnum, int cnum, char *fname, int share_mode, int ofun,
                      int mode, int *Access, int *action);
int seek_file(int fnum, uint32_t pos);
int read_file(int fnum, char *data, uint32_t pos, int n);
int write_file(int fnum, char *data, int n);
bool become_service(int cnum, bool do_chdir);
int find_service(char *service);
int cached_error_packet(char *inbuf, char *outbuf, int fnum, int line);
int read_dosattrib(const char *path);
void write_dosattrib(const char *path, int attrib);
int unix_error_packet(char *inbuf, char *outbuf, int def_class,
                      uint32_t def_code, int line);
int error_packet(char *inbuf, char *outbuf, int error_class,
                 uint32_t error_code, int line);
bool receive_next_smb(int smbfd, char *inbuf, int bufsize, int timeout);
bool snum_used(int snum);
bool reload_services(bool test);
int make_connection(char *service, char *dev);
int find_free_file(void);
int reply_corep(char *outbuf);
int reply_coreplus(char *outbuf);
int reply_lanman1(char *outbuf);
int reply_lanman2(char *outbuf);
int reply_nt1(char *outbuf);
void close_cnum(int cnum);
void exit_server(char *reason);
void standard_sub(int cnum, char *str);
char *smb_fn_name(int type);
int chain_reply(char *inbuf, char *outbuf, int size, int bufsize);
int construct_reply(char *inbuf, char *outbuf, int size, int bufsize);

/*The following definitions come from  slprintf.c  */

int vslprintf(char *str, int n, char *format, va_list ap);

/*The following definitions come from  system.c  */

int sys_select(fd_set *fds, struct timeval *tval);
int sys_select(fd_set *fds, struct timeval *tval);
int sys_utime(char *fname, struct utimbuf *times);
int sys_rename(char *from, char *to);
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
time_t make_unix_date(void *date_ptr);
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
char *tmpdir(void);
bool is_a_socket(int fd);
void array_promote(char *array, int elsize, int element);
void close_sockets(void);
char *StrnCpy(char *dest, char *src, int n);
bool file_exist(char *fname, struct stat *sbuf);
time_t file_modtime(char *fname);
bool directory_exist(char *dname, struct stat *st);
uint32_t file_size(char *file_name);
int isdoschar(int c);
void init_dos_char_table(void);
bool strequal(char *s1, char *s2);
bool strcsequal(char *s1, char *s2);
void strlower(char *s);
void strupper(char *s);
void strnorm(char *s);
bool strisnormal(char *s);
void string_replace(char *s, char oldc, char newc);
void unix_format(char *fname);
void show_msg(char *buf);
int smb_len(char *buf);
void _smb_setlen(char *buf, int len);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, bool zero);
int smb_numwords(char *buf);
int smb_buflen(char *buf);
int smb_buf_ofs(char *buf);
char *smb_buf(char *buf);
int smb_offset(char *p, char *buf);
char *skip_string(char *buf, int n);
bool trim_string(char *s, char *front, char *back);
void unix_clean_name(char *s);
bool strhasupper(char *s);
bool strhaslower(char *s);
int count_chars(char *s, char c);
void make_dir_struct(char *buf, char *mask, char *fname, unsigned int size,
                     int mode, time_t date);
void close_low_fds(void);
int write_socket(int fd, char *buf, int len);
int read_with_timeout(int fd, char *buf, int mincnt, int maxcnt, long time_out);
int read_data(int fd, char *buffer, int N);
int write_data(int fd, char *buffer, int N);
int transfer_file(int infd, int outfd, int n, char *header, int headlen,
                  int align);
int read_smb_length(int fd, char *inbuf, int timeout);
bool receive_smb(int fd, char *buffer, int timeout);
bool receive_message_or_smb(int smbfd, char *buffer, int buffer_len,
                            int timeout, bool *got_smb);
bool send_smb(int fd, char *buffer);
char *name_ptr(char *buf, int ofs);
int name_extract(char *buf, int ofs, char *name);
int name_len(char *s);
bool send_one_packet(char *buf, int len, struct in_addr ip, int port, int type);
bool string_init(char **dest, char *src);
void string_free(char **s);
bool string_set(char **dest, char *src);
bool string_sub(char *s, char *pattern, char *insert);
bool do_match(char *str, char *regexp, int case_sig);
bool mask_match(char *str, char *regexp, int case_sig, bool trans2);
void become_daemon(void);
int set_filelen(int fd, long len);
void *Realloc(void *p, int size);
bool get_myname(char *my_name, struct in_addr *ip);
int open_socket_in(int type, int port, int dlevel, uint32_t socket_addr);
uint32_t interpret_addr(char *str);
struct in_addr *interpret_addr2(char *str);
void reset_globals_after_fork(void);
char *client_addr(void);
void standard_sub_basic(char *str);
int PutUniCode(char *dst, char *src);
char *gidtoname(int gid);
void BlockSignals(bool block, int signum);
void ajt_panic(void);
char *readdirname(void *p);
bool fcntl_lock(int fd, int op, uint32_t offset, uint32_t count, int type);
char *safe_strcpy(char *dest, char *src, int maxlength);
char *safe_strcat(char *dest, char *src, int maxlength);
void print_asc(int level, unsigned char *buf, int len);
void dump_data(int level, char *buf1, int len);
char *tab_depth(int depth);
