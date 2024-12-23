/* This file is automatically generated with "make proto". DO NOT EDIT */

/*The following definitions come from  charcnv.c  */

char *unix2dos_format(char *str, BOOL overwrite);
char *dos2unix_format(char *str, BOOL overwrite);
void interpret_character_set(char *str);

/*The following definitions come from  charset.c  */

void charset_initialise(void);
void codepage_initialise(int client_codepage);
void add_char_string(char *s);

/*The following definitions come from  dir.c  */

void init_dptrs(void);
char *dptr_path(int key);
char *dptr_wcard(int key);
BOOL dptr_set_wcard(int key, char *wcard);
BOOL dptr_set_attr(int key, uint16 attr);
uint16 dptr_attr(int key);
void dptr_close(int key);
void dptr_closecnum(int cnum);
void dptr_idlecnum(int cnum);
void dptr_closepath(char *path, int pid);
int dptr_create(int cnum, char *path, BOOL expect_close, int pid);
BOOL dptr_fill(char *buf1, unsigned int key);
BOOL dptr_zero(char *buf);
void *dptr_fetch(char *buf, int *num);
void *dptr_fetch_lanman2(int dptr_num);
BOOL dir_check_ftype(int cnum, int mode, struct stat *st, int dirtype);
BOOL get_dir_entry(int cnum, char *mask, int dirtype, char *fname, int *size,
                   int *mode, time_t *date);
void *OpenDir(int cnum, char *name);
void CloseDir(void *p);
char *ReadDirName(void *p);
BOOL SeekDir(void *p, int pos);
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

/*The following definitions come from  kanji.c  */

void interpret_coding_system(char *str);
void initialize_multibyte_vectors(int client_codepage);

/*The following definitions come from  loadparm.c  */

char *lp_string(char *s);
char *lp_logfile(void);
char *lp_configfile(void);
char *lp_serverstring(void);
char *lp_lockdir(void);
char *lp_defaultservice(void);
char *lp_workgroup(void);
char *lp_character_set(void);
char *lp_socket_address(void);
BOOL lp_readbmpx(void);
BOOL lp_readraw(void);
BOOL lp_writeraw(void);
BOOL lp_strip_dot(void);
BOOL lp_syslog_only(void);
BOOL lp_time_server(void);
int lp_max_log_size(void);
int lp_maxxmit(void);
int lp_readsize(void);
int lp_deadtime(void);
int lp_syslog(void);
int lp_client_code_page(void);
char *lp_servicename(int);
char *lp_pathname(int);
char *lp_guestaccount(int);
char *lp_comment(int);
char *lp_volume(int);
char *lp_veto_oplocks(int);
BOOL lp_casesensitive(int);
BOOL lp_shortpreservecase(int);
BOOL lp_status(int);
BOOL lp_hide_dot_files(int);
BOOL lp_readonly(int);
BOOL lp_map_hidden(int);
BOOL lp_map_archive(int);
BOOL lp_locking(int);
BOOL lp_strict_locking(int);
BOOL lp_widelinks(int);
BOOL lp_symlinks(int);
BOOL lp_map_system(int);
BOOL lp_fake_oplocks(int);
BOOL lp_dos_filetimes(int);
int lp_create_mode(int);
int lp_force_create_mode(int);
int lp_dir_mode(int);
int lp_force_dir_mode(int);
int lp_max_connections(int);
int lp_defaultcase(int);
int lp_add_service(char *pszService, int iDefaultService);
BOOL lp_file_list_changed(void);
BOOL lp_do_parameter(int snum, char *pszParmName, char *pszParmValue);
int lp_next_parameter(int snum, int *i, char *label, char *value,
                      int allparameters);
BOOL lp_snum_ok(int iService);
BOOL lp_loaded(void);
void lp_killunused(BOOL (*snumused)(int));
BOOL lp_load(char *pszFname, BOOL global_only);
int lp_numservices(void);
void lp_dump(FILE *f);
int lp_servicenumber(char *pszServiceName);
char *volume_label(int snum);
void lp_rename_service(int snum, char *new_name);
void lp_remove_service(int snum);
void lp_copy_service(int snum, char *new_name);

/*The following definitions come from  locking.c  */

BOOL is_locked(int fnum, int cnum, uint32 count, uint32 offset, int lock_type);
BOOL do_lock(int fnum, int cnum, uint32 count, uint32 offset, int lock_type,
             int *eclass, uint32 *ecode);
BOOL do_unlock(int fnum, int cnum, uint32 count, uint32 offset, int *eclass,
               uint32 *ecode);
BOOL locking_end(void);

/*The following definitions come from  locking_slow.c  */

BOOL locking_init(int read_only);
BOOL lock_share_entry(int cnum, uint32 dev, uint32 inode, int *ptok);
BOOL unlock_share_entry(int cnum, uint32 dev, uint32 inode, int token);
BOOL remove_share_oplock(int fnum, int token);

/*The following definitions come from  mangle.c  */

int str_checksum(char *s);
BOOL is_8_3(char *fname, BOOL check_case);
void reset_mangled_stack(int size);
BOOL check_mangled_stack(char *s);
BOOL is_mangled(char *s);
void mangle_name_83(char *s, int s_len);
void name_map_mangle(char *OutName, BOOL need83, int snum);

/*The following definitions come from  params.c  */

BOOL pm_process(char *FileName, BOOL (*sfunc)(char *),
                BOOL (*pfunc)(char *, char *));

/*The following definitions come from  password.c  */

void add_session_user(char *user);

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
int file_utime(int cnum, char *fname, struct utimbuf *times);
BOOL set_filetime(int cnum, char *fname, time_t mtime);
BOOL unix_convert(char *name, int cnum, pstring saved_last_component,
                  BOOL *bad_path);
int disk_free(char *path, int *bsize, int *dfree, int *dsize);
int sys_disk_free(char *path, int *bsize, int *dfree, int *dsize);
BOOL check_name(char *name, int cnum);
void close_file(int fnum, BOOL normal_close);
void open_file_shared(int fnum, int cnum, char *fname, int share_mode, int ofun,
                      int mode, int oplock_request, int *Access, int *action);
int seek_file(int fnum, uint32 pos);
int read_file(int fnum, char *data, uint32 pos, int n);
int write_file(int fnum, char *data, int n);
BOOL become_service(int cnum, BOOL do_chdir);
int find_service(char *service);
int cached_error_packet(char *inbuf, char *outbuf, int fnum, int line);
int unix_error_packet(char *inbuf, char *outbuf, int def_class, uint32 def_code,
                      int line);
int error_packet(char *inbuf, char *outbuf, int error_class, uint32 error_code,
                 int line);
BOOL oplock_break(uint32 dev, uint32 inode, struct timeval *tval);
BOOL request_oplock_break(share_mode_entry *share_entry, uint32 dev,
                          uint32 inode);
BOOL receive_next_smb(int smbfd, int oplockfd, char *inbuf, int bufsize,
                      int timeout);
BOOL snum_used(int snum);
BOOL reload_services(BOOL test);
int make_connection(char *service, char *dev);
int find_free_file(void);
int reply_corep(char *outbuf);
int reply_coreplus(char *outbuf);
int reply_lanman1(char *outbuf);
int reply_lanman2(char *outbuf);
int reply_nt1(char *outbuf);
void close_cnum(int cnum);
BOOL yield_connection(int cnum, char *name, int max_connections);
BOOL claim_connection(int cnum, char *name, int max_connections, BOOL Clear);
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
int sys_unlink(char *fname);
int sys_open(char *fname, int flags, int mode);
DIR *sys_opendir(char *dname);
int sys_stat(char *fname, struct stat *sbuf);
int sys_waitpid(pid_t pid, int *status, int options);
int sys_lstat(char *fname, struct stat *sbuf);
int sys_mkdir(char *dname, int mode);
int sys_rmdir(char *dname);
int sys_chdir(char *dname);
int sys_utime(char *fname, struct utimbuf *times);
int sys_rename(char *from, char *to);
int sys_chmod(char *fname, int mode);
char *sys_getwd(char *s);
int sys_chown(char *fname, int uid, int gid);
int sys_chroot(char *dname);

/*The following definitions come from  time.c  */

void GetTimeOfDay(struct timeval *tval);
void TimeInit(void);
int TimeDiff(time_t t);
struct tm *LocalTime(time_t *t);
time_t interpret_long_date(char *p);
void put_long_date(char *p, time_t t);
BOOL null_mtime(time_t mtime);
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

/*The following definitions come from  uid.c  */

void init_uid(void);
BOOL become_guest(void);
BOOL become_user(connection_struct *conn, int cnum);
BOOL unbecome_user(void);
void become_root(BOOL save_dir);
void unbecome_root(BOOL restore_dir);

/*The following definitions come from  username.c  */

struct passwd *Get_Pwnam(char *user, BOOL allow_change);

/*The following definitions come from  util.c  */

void setup_logging(char *pname, BOOL interactive);
void reopen_logs(void);
void force_check_log_size(void);
char *tmpdir(void);
BOOL is_a_socket(int fd);
BOOL next_token(char **ptr, char *buff, char *sep);
void array_promote(char *array, int elsize, int element);
void close_sockets(void);
char *StrnCpy(char *dest, char *src, int n);
BOOL file_exist(char *fname, struct stat *sbuf);
time_t file_modtime(char *fname);
BOOL directory_exist(char *dname, struct stat *st);
uint32 file_size(char *file_name);
int StrCaseCmp(char *s, char *t);
BOOL strequal(char *s1, char *s2);
BOOL strcsequal(char *s1, char *s2);
void strlower(char *s);
void strupper(char *s);
void strnorm(char *s);
BOOL strisnormal(char *s);
void string_replace(char *s, char oldc, char newc);
void unix_format(char *fname);
void show_msg(char *buf);
int smb_len(char *buf);
void _smb_setlen(char *buf, int len);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, BOOL zero);
int smb_numwords(char *buf);
int smb_buflen(char *buf);
int smb_buf_ofs(char *buf);
char *smb_buf(char *buf);
int smb_offset(char *p, char *buf);
char *skip_string(char *buf, int n);
BOOL trim_string(char *s, char *front, char *back);
void unix_clean_name(char *s);
int ChDir(char *path);
char *GetWd(char *str);
BOOL reduce_name(char *s, char *dir, BOOL widelinks);
BOOL strhasupper(char *s);
BOOL strhaslower(char *s);
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
BOOL receive_smb(int fd, char *buffer, int timeout);
BOOL receive_local_message(int fd, char *buffer, int buffer_len, int timeout);
BOOL push_smb_message(char *buf, int msg_len);
BOOL receive_message_or_smb(int smbfd, int oplock_fd, char *buffer,
                            int buffer_len, int timeout, BOOL *got_smb);
BOOL send_smb(int fd, char *buffer);
char *name_ptr(char *buf, int ofs);
int name_extract(char *buf, int ofs, char *name);
int name_len(char *s);
BOOL send_one_packet(char *buf, int len, struct in_addr ip, int port, int type);
BOOL in_list(char *s, char *list, BOOL casesensitive);
BOOL string_init(char **dest, char *src);
void string_free(char **s);
BOOL string_set(char **dest, char *src);
BOOL string_sub(char *s, char *pattern, char *insert);
BOOL do_match(char *str, char *regexp, int case_sig);
BOOL mask_match(char *str, char *regexp, int case_sig, BOOL trans2);
void become_daemon(void);
int set_filelen(int fd, long len);
void *Realloc(void *p, int size);
BOOL get_myname(char *my_name, struct in_addr *ip);
int open_socket_in(int type, int port, int dlevel, uint32 socket_addr);
uint32 interpret_addr(char *str);
struct in_addr *interpret_addr2(char *str);
void reset_globals_after_fork(void);
char *client_addr(void);
void standard_sub_basic(char *str);
int PutUniCode(char *dst, char *src);
BOOL process_exists(int pid);
char *gidtoname(int gid);
void BlockSignals(BOOL block, int signum);
void ajt_panic(void);
char *readdirname(void *p);
BOOL is_in_path(char *name, name_compare_entry *namelist);
void set_namearray(name_compare_entry **ppname_array, char *namelist);
void free_namearray(name_compare_entry *name_array);
BOOL fcntl_lock(int fd, int op, uint32 offset, uint32 count, int type);
char *safe_strcpy(char *dest, char *src, int maxlength);
char *safe_strcat(char *dest, char *src, int maxlength);
void print_asc(int level, unsigned char *buf, int len);
void dump_data(int level, char *buf1, int len);
char *tab_depth(int depth);
