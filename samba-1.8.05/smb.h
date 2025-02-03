/*
   Unix SMB/Netbios implementation.
   Version 1.8.
   Copyright (C) Andrew Tridgell 1992,1993,1994

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
#ifndef _SMB_H
#define _SMB_H

#ifndef MAX_CONNECTIONS
#define MAX_CONNECTIONS 127
#endif

#ifndef MAX_OPEN_FILES
#define MAX_OPEN_FILES 50
#endif

#ifndef GUEST_ACCOUNT
#define GUEST_ACCOUNT "pcuser"
#endif

#define BUFFER_SIZE   (0xFFFF)
#define SAFETY_MARGIN 1024

#ifndef EXTERN
#define EXTERN extern
#endif

#define False             (0)
#define True              (1)
#define BOOLSTR(b)        ((b) ? "Yes" : "No")
#define BITSETB(ptr, bit) ((((char *) ptr)[0] & (1 << (bit))) != 0)
#define BITSETW(ptr, bit) ((SVAL(ptr, 0) & (1 << (bit))) != 0)
#define PTR_DIFF(p1, p2)  ((ptrdiff_t) (((char *) (p1)) - (char *) (p2)))

typedef int BOOL;

typedef short int16;
typedef int int32;
typedef unsigned short uint16;
typedef unsigned int uint32;

#ifndef DEF_CREATE_MASK
#define DEF_CREATE_MASK (0755)
#endif

#ifndef DEFAULT_PIPE_TIMEOUT
#define DEFAULT_PIPE_TIMEOUT 10000000 /* Ten seconds */
#endif

/* debugging code */
#define DEBUG(level, body) ((DEBUGLEVEL >= (level)) ? (Debug1 body) : 0)

/* these macros make access to the packet buffers easier. See also the
functions SSVAL() and SIVAL(). */
#define SIVAL(buf, pos, val) sival((char *) (buf), pos, val)
#define SSVAL(buf, pos, val) ssval((char *) (buf), pos, val)
#define IVAL(buf, pos)       ival((char *) (buf), pos)
#define SVAL(buf, pos)       sval((char *) buf, pos)

/* these are the signed versions */
#define SIVALS(buf, pos, val) sival_s((char *) (buf), pos, val)
#define SSVALS(buf, pos, val) ssval_s((char *) (buf), pos, val)
#define IVALS(buf, pos)       ival_s((char *) (buf), pos)
#define SVALS(buf, pos)       sval_s((char *) buf, pos)

#define PVAL(buf, pos, type) (*((type *) (((char *) buf) + pos)))
#define SCVAL(buf, pos, x)   PVAL(buf, pos, unsigned char) = (x)
#define CVAL(buf, pos)       PVAL(buf, pos, unsigned char)

#define BSWP(buf, len) object_byte_swap(buf, len)
#define SWP(buf, len)  (NeedSwap ? BSWP(buf, len) : ((void *) buf))

#define DIR_STRUCT_SIZE 43

/* these define all the command types recognised by the server - there
are lots of gaps so probably there are some rare commands that are not
implemented */

#define pSETDIR '\377'

/* these define the attribute byte as seen by DOS */
#define aRONLY  (1L << 0)
#define aHIDDEN (1L << 1)
#define aSYSTEM (1L << 2)
#define aVOLID  (1L << 3)
#define aDIR    (1L << 4)
#define aARCH   (1L << 5)

/* SMB X/Open error codes for the ERRdos error class */
#define ERRbadfunc              1  /* Invalid function (or system call) */
#define ERRbadfile              2  /* File not found (pathname error) */
#define ERRbadpath              3  /* Directory not found */
#define ERRnofids               4  /* Too many open files */
#define ERRnoaccess             5  /* Access denied */
#define ERRbadfid               6  /* Invalid fid */
#define ERRnomem                8  /* Out of memory */
#define ERRbadmem               9  /* Invalid memory block address */
#define ERRbadenv               10 /* Invalid environment */
#define ERRbadaccess            12 /* Invalid open mode */
#define ERRbaddata              13 /* Invalid data (only from ioctl call) */
#define ERRres                  14 /* reserved */
#define ERRbaddrive             15 /* Invalid drive */
#define ERRremcd                16 /* Attempt to delete current directory */
#define ERRdiffdevice           17 /* rename/move across different filesystems */
#define ERRnofiles              18 /* no more files found in file search */
#define ERRbadshare             32 /* Share mode on file conflict with open mode */
#define ERRlock                 33 /* Lock request conflicts with existing lock */
#define ERRfilexists            80  /* File in operation already exists */
#define ERRbadpipe              230 /* Named pipe invalid */
#define ERRpipebusy             231 /* All instances of pipe are busy */
#define ERRpipeclosing          232 /* named pipe close in progress */
#define ERRnotconnected         233 /* No process on other end of named pipe */
#define ERRmoredata             234 /* More data to be returned */
#define ERROR_EAS_DIDNT_FIT     275 /* Extended attributes didn't fit */
#define ERROR_EAS_NOT_SUPPORTED 282 /* Extended attributes not suppored */

/* here's a special one from observing NT */
#define ERRnoipc 66 /* don't support ipc */

/* Error codes for the ERRSRV class */

#define ERRerror       1   /* Non specific error code */
#define ERRbadpw       2   /* Bad password */
#define ERRbadtype     3   /* reserved */
#define ERRaccess      4   /* No permissions to do the requested operation */
#define ERRinvnid      5   /* tid invalid */
#define ERRinvnetname  6   /* Invalid servername */
#define ERRinvdevice   7   /* Invalid device */
#define ERRqfull       49  /* Print queue full */
#define ERRqtoobig     50  /* Queued item too big */
#define ERRinvpfid     52  /* Invalid print file in smb_fid */
#define ERRsmbcmd      64  /* Unrecognised command */
#define ERRsrverror    65  /* smb server internal error */
#define ERRfilespecs   67  /* fid and pathname invalid combination */
#define ERRbadlink     68  /* reserved */
#define ERRbadpermits  69  /* Access specified for a file is not valid */
#define ERRbadpid      70  /* reserved */
#define ERRsetattrmode 71  /* attribute mode invalid */
#define ERRpaused      81  /* Message server paused */
#define ERRmsgoff      82  /* Not receiving messages */
#define ERRnoroom      83  /* No room for message */
#define ERRrmuns       87  /* too many remote usernames */
#define ERRtimeout     88  /* operation timed out */
#define ERRnoresource  89  /* No resources currently available for request. */
#define ERRtoomanyuids 90  /* too many userids */
#define ERRbaduid      91  /* bad userid */
#define ERRuseMPX      250 /* temporarily unable to use raw mode, use MPX mode */
#define ERRuseSTD                                                              \
	251 /* temporarily unable to use raw mode, use standard mode */
#define ERRcontMPX   252 /* resume MPX mode */
#define ERRbadPW         /* reserved */
#define ERRnosupport 0xFFFF

/* Error codes for the ERRHRD class */

#define ERRnowrite     19 /* read only media */
#define ERRbadunit     20 /* Unknown device */
#define ERRnotready    21 /* Drive not ready */
#define ERRbadcmd      22 /* Unknown command */
#define ERRdata        23 /* Data (CRC) error */
#define ERRbadreq      24 /* Bad request structure length */
#define ERRseek        25
#define ERRbadmedia    26
#define ERRbadsector   27
#define ERRnopaper     28
#define ERRwrite       29 /* write fault */
#define ERRread        30 /* read fault */
#define ERRgeneral     31 /* General hardware failure */
#define ERRwrongdisk   34
#define ERRFCBunavail  35
#define ERRsharebufexc 36 /* share buffer exceeded */
#define ERRdiskfull    39

typedef char pstring[1024];
typedef char fstring[128];

typedef struct {
	int size;
	int mode;
	int uid;
	int gid;
	time_t mtime;
	time_t atime;
	time_t ctime;
	pstring name;
} file_info;

/* Structure used when SMBwritebmpx is active */
typedef struct {
	int wr_total_written; /* So we know when to discard this */
	int32 wr_timeout;
	int32 wr_errclass;
	int32 wr_error;  /* Cached errors */
	BOOL wr_mode;    /* write through mode) */
	BOOL wr_discard; /* discard all further data */
} write_bmpx_struct;

typedef struct {
	int cnum;
	int fd;
	int pos;
	char *mmap_ptr;
	int mmap_size;
	write_bmpx_struct *wbmpx_ptr;
	BOOL open;
	BOOL can_lock;
	BOOL read_only;
	BOOL print_file;
	pstring name;
} files_struct;

/* this is the structure used for the local netbios name table */
typedef struct {
	time_t start_time;
	int ttl;
	struct in_addr ip;
	struct in_addr master_ip;
	BOOL found_master;
	BOOL valid;
	BOOL subnet;
	char flags[10];
	unsigned char nb_flags;
	char name[100];
} name_struct;

typedef struct {
	int service;
	int connect_num;
	int uid;
	int gid;
	void *dirptr;
	BOOL open;
	BOOL printer;
	BOOL ipc;
	BOOL read_only;
	pstring dirpath;
	pstring connectpath;
	/* following groups stuff added by ih */
	int ngroups;
	gid_t *groups;
	int *igroups; /* an integer version - some OSes are broken :-( */
} connection_struct;

typedef struct {
	int uid;
	char *name;
	BOOL guest;
} user_struct;

typedef struct {
	BOOL have_saved_ids;
} machine_struct;

enum {
	LPQ_QUEUED,
	LPQ_PAUSED,
	LPQ_SPOOLING,
	LPQ_PRINTING
};

typedef struct {
	int job;
	int size;
	int status;
	time_t time;
	char user[30];
	char file[100];
} print_queue_struct;

/* this is used for smbstatus */
struct connect_record {
	int magic;
	int pid;
	int cnum;
	int uid;
	int gid;
	char name[24];
	char addr[24];
	char machine[128];
	time_t start;
};

/* these are useful macros for checking validity of handles */
#define VALID_FNUM(fnum) (((fnum) >= 0) && ((fnum) < MAX_OPEN_FILES))
#define OPEN_FNUM(fnum)  (VALID_FNUM(fnum) && Files[fnum].open)
#define VALID_CNUM(cnum) (((cnum) >= 0) && ((cnum) < MAX_CONNECTIONS))
#define OPEN_CNUM(cnum)  (VALID_CNUM(cnum) && Connections[cnum].open)
#define IS_IPC(cnum)     (VALID_CNUM(cnum) && Connections[cnum].ipc)

/* translates a connection number into a service number */
#define SNUM(cnum) (Connections[cnum].service)

/* access various service details */
#define GUEST              (lp_guestaccount())
#define HOME(cnum)         (lp_pathname(SNUM(cnum)))
#define PATH(snum)         (lp_pathname(snum))
#define USER(snum)         (lp_username(snum))
#define SERVICE(snum)      (lp_servicename(snum))
#define PRINTCAP           (lp_printcapname())
#define PRINTCOMMAND(snum) (lp_printcommand(snum))
#define PRINTERNAME(snum)  (lp_printername(snum))
#define CAN_WRITE(cnum)    (OPEN_CNUM(cnum) && !Connections[cnum].read_only)
#define VALID_SNUM(snum)   (lp_snum_ok(snum))
#define GUEST_OK(snum)     (VALID_SNUM(snum) && lp_guest_ok(snum))
#define GUEST_ONLY(snum)   (VALID_SNUM(snum) && lp_guest_only(snum))
#define CAN_SETDIR(snum)   (!lp_no_set_dir(snum))
#define CAN_PRINT(cnum)    (OPEN_CNUM(cnum) && lp_print_ok(SNUM(cnum)))
#define POSTSCRIPT(cnum)   (OPEN_CNUM(cnum) && lp_postscript(SNUM(cnum)))
#define MAP_HIDDEN(cnum)   (OPEN_CNUM(cnum) && lp_map_hidden(SNUM(cnum)))
#define MAP_SYSTEM(cnum)   (OPEN_CNUM(cnum) && lp_map_system(SNUM(cnum)))
#define CREATE_MODE(cnum)  (lp_create_mode(SNUM(cnum)))

/* the basic packet size, assuming no words or bytes */
#define smb_size 39

/* offsets into message for common items */
#define smb_com   8
#define smb_rcls  9
#define smb_reh   10
#define smb_err   11
#define smb_flg   13
#define smb_flg2  14
#define smb_reb   13
#define smb_tid   28
#define smb_pid   30
#define smb_uid   32
#define smb_mid   34
#define smb_wct   36
#define smb_vwv   37
#define smb_vwv0  37
#define smb_vwv1  39
#define smb_vwv2  41
#define smb_vwv3  43
#define smb_vwv4  45
#define smb_vwv5  47
#define smb_vwv6  49
#define smb_vwv7  51
#define smb_vwv8  53
#define smb_vwv9  55
#define smb_vwv10 57
#define smb_vwv11 59
#define smb_vwv12 61
#define smb_vwv13 63
#define smb_vwv14 65
#define smb_vwv15 67
#define smb_vwv16 69
#define smb_vwv17 71

/* the complete */
#define SMBmkdir    0x00 /* create directory */
#define SMBrmdir    0x01 /* delete directory */
#define SMBopen     0x02 /* open file */
#define SMBcreate   0x03 /* create file */
#define SMBclose    0x04 /* close file */
#define SMBflush    0x05 /* flush file */
#define SMBunlink   0x06 /* delete file */
#define SMBmv       0x07 /* rename file */
#define SMBgetatr   0x08 /* get file attributes */
#define SMBsetatr   0x09 /* set file attributes */
#define SMBread     0x0A /* read from file */
#define SMBwrite    0x0B /* write to file */
#define SMBlock     0x0C /* lock byte range */
#define SMBunlock   0x0D /* unlock byte range */
#define SMBctemp    0x0E /* create temporary file */
#define SMBmknew    0x0F /* make new file */
#define SMBchkpth   0x10 /* check directory path */
#define SMBexit     0x11 /* process exit */
#define SMBlseek    0x12 /* seek */
#define SMBtcon     0x70 /* tree connect */
#define SMBtconX    0x75 /* tree connect and X*/
#define SMBtdis     0x71 /* tree disconnect */
#define SMBnegprot  0x72 /* negotiate protocol */
#define SMBdskattr  0x80 /* get disk attributes */
#define SMBsearch   0x81 /* search directory */
#define SMBsplopen  0xC0 /* open print spool file */
#define SMBsplwr    0xC1 /* write to print spool file */
#define SMBsplclose 0xC2 /* close print spool file */
#define SMBsplretq  0xC3 /* return print queue */
#define SMBsends    0xD0 /* send single block message */
#define SMBsendb    0xD1 /* send broadcast message */
#define SMBfwdname  0xD2 /* forward user name */
#define SMBcancelf  0xD3 /* cancel forward */
#define SMBgetmac   0xD4 /* get machine name */
#define SMBsendstrt 0xD5 /* send start of multi-block message */
#define SMBsendend  0xD6 /* send end of multi-block message */
#define SMBsendtxt  0xD7 /* send text of multi-block message */

/* Core+ protocol */
#define SMBlockread    0x13 /* Lock a range and read */
#define SMBwriteunlock 0x14 /* Unlock a range then write */
#define SMBreadbraw    0x1a /* read a block of data with no smb header */
#define SMBwritebraw   0x1d /* write a block of data with no smb header */
#define SMBwritec      0x20 /* secondary write request */
#define SMBwriteclose  0x2c /* write a file then close it */

/* dos extended protocol */
#define SMBreadBraw   0x1A /* read block raw */
#define SMBreadBmpx   0x1B /* read block multiplexed */
#define SMBreadBs     0x1C /* read block (secondary response) */
#define SMBwriteBraw  0x1D /* write block raw */
#define SMBwriteBmpx  0x1E /* write block multiplexed */
#define SMBwriteBs    0x1F /* write block (secondary request) */
#define SMBwriteC     0x20 /* write complete response */
#define SMBsetattrE   0x22 /* set file attributes expanded */
#define SMBgetattrE   0x23 /* get file attributes expanded */
#define SMBlockingX   0x24 /* lock/unlock byte ranges and X */
#define SMBtrans      0x25 /* transaction - name, bytes in/out */
#define SMBtranss     0x26 /* transaction (secondary request/response) */
#define SMBioctl      0x27 /* IOCTL */
#define SMBioctls     0x28 /* IOCTL  (secondary request/response) */
#define SMBcopy       0x29 /* copy */
#define SMBmove       0x2A /* move */
#define SMBecho       0x2B /* echo */
#define SMBopenX      0x2D /* open and X */
#define SMBreadX      0x2E /* read and X */
#define SMBwriteX     0x2F /* write and X */
#define SMBsesssetupX 0x73 /* Session Set Up & X (including User Logon) */
#define SMBtconX      0x75 /* tree connect and X */
#define SMBffirst     0x82 /* find first */
#define SMBfunique    0x83 /* find unique */
#define SMBfclose     0x84 /* find close */
#define SMBinvalid    0xFE /* invalid command */

/* Extended 2.0 protocol */
#define SMBtrans2     0x32 /* TRANS2 protocol set */
#define SMBtranss2    0x33 /* TRANS2 protocol set, secondary command */
#define SMBfindclose  0x34 /* Terminate a TRANSACT2_FINDFIRST */
#define SMBfindnclose 0x35 /* Terminate a TRANSACT2_FINDNOTIFYFIRST */
#define SMBulogoffX   0x74 /* user logoff */

/* these are the TRANS2 sub commands */
#define TRANSACT2_OPEN            0
#define TRANSACT2_FINDFIRST       1
#define TRANSACT2_FINDNEXT        2
#define TRANSACT2_QFSINFO         3
#define TRANSACT2_SETFSINFO       4
#define TRANSACT2_QPATHINFO       5
#define TRANSACT2_SETPATHINFO     6
#define TRANSACT2_QFILEINFO       7
#define TRANSACT2_SETFILEINFO     8
#define TRANSACT2_FSCTL           9
#define TRANSACT2_IOCTL           10
#define TRANSACT2_FINDNOTIFYFIRST 11
#define TRANSACT2_FINDNOTIFYNEXT  12
#define TRANSACT2_MKDIR           13

/* these are the trans2 sub fields for primary requests */
#define smb_tpscnt  smb_vwv0
#define smb_tdscnt  smb_vwv1
#define smb_mprcnt  smb_vwv2
#define smb_mdrcnt  smb_vwv3
#define smb_msrcnt  smb_vwv4
#define smb_flags   smb_vwv5
#define smb_timeout smb_vwv6
#define smb_pscnt   smb_vwv9
#define smb_psoff   smb_vwv10
#define smb_dscnt   smb_vwv11
#define smb_dsoff   smb_vwv12
#define smb_suwcnt  smb_vwv13
#define smb_setup   smb_vwv14
#define smb_setup0  smb_setup
#define smb_setup1  (smb_setup + 2)
#define smb_setup2  (smb_setup + 4)

/* these are for the secondary requests */
#define smb_spscnt  smb_vwv2
#define smb_spsoff  smb_vwv3
#define smb_spsdisp smb_vwv4
#define smb_sdscnt  smb_vwv5
#define smb_sdsoff  smb_vwv6
#define smb_sdsdisp smb_vwv7
#define smb_sfid    smb_vwv8

/* and these for responses */
#define smb_tprcnt smb_vwv0
#define smb_tdrcnt smb_vwv1
#define smb_prcnt  smb_vwv3
#define smb_proff  smb_vwv4
#define smb_prdisp smb_vwv5
#define smb_drcnt  smb_vwv6
#define smb_droff  smb_vwv7
#define smb_drdisp smb_vwv8

/* where to find the base of the SMB packet proper */
#define smb_base(buf) ((buf) + 4)

#define SUCCESS 0    /* The request was successful. */
#define ERRDOS  0x01 /*  Error is from the core DOS operating system set. */
#define ERRSRV  0x02 /* Error is generated by the server network file          \
	                manager.*/
#define ERRHRD  0x03 /* Error is an hardware error. */
#define ERRCMD  0xFF /* Command was not in the "SMB" format. */

#ifdef USE_DIRECT
#define DIRECT direct
#else
#define DIRECT dirent
#endif

/* structure used to hold the incoming hosts info */
struct from_host {
	char *name;              /* host name */
	char *addr;              /* host address */
	struct sockaddr_in *sin; /* their side of the link */
};

/* and a few prototypes */
char *fgets_slash(char *s, int maxlen, FILE *f);
int read_udp_socket(int fd, char *buf, int len);
void exit_server(void);
BOOL process_exists(int pid);
int lockfread(void *p, int pos, int size, int n, FILE *f);
BOOL chgpasswd(char *name, char *oldpass, char *newpass);
void push_mangled_name(char *s);
void array_promote(char *array, int elsize, int element);
void string_replace(char *s, char old, char new);
BOOL user_in_list(char *user, char *list);
BOOL string_sub(char *s, char *pattern, char *insert);
char *StrnCpy(char *dest, char *src, int n);
char *validated_username(int vuid);
BOOL set_user_password(char *user, char *oldpass, char *newpass);
char *skip_string(char *buf, int n);
BOOL is_locked(int fnum, int cnum, uint32 count, uint32 offset);
int read_file(int fnum, char *data, int pos, int mincnt, int maxcnt,
              int timeout, BOOL exact);
BOOL do_lock(int fnum, int cnum, uint32 count, uint32 offset, int *eclass,
             uint32 *ecode);
int seek_file(int fnum, int pos);
BOOL do_unlock(int fnum, int cnum, uint32 count, uint32 offset, int *eclass,
               uint32 *ecode);
int get_printqueue(int snum, print_queue_struct **queue);
int sig_cld();
int find_free_connection(void);
void parse_connect(char *buf, char *service, char *user, char *password,
                   char *dev);
int make_connection(char *service, char *user, char *password, char *dev,
                    int vuid);
void *dptr_get(int key);
char *dptr_path(int key);
char *dptr_wcard(int key);
int dptr_set_wcard(int key, char *wcard);
int dptr_set_attr(int key, uint16 attr);
uint16 dptr_attr(int key);
void dptr_promote(int key);
void dptr_demote(int key);
void dptr_close(int key);
void dptr_closepath(char *path, int pid);
int dptr_create(void *p, char *path, BOOL expect_close, int pid);
BOOL dptr_fill(char *buf, unsigned int key);
BOOL dptr_zero(char *buf);
void *dptr_fetch(char *buf, int *num);
void *dptr_fetch_lanman2(char *params, int dptr_num);
BOOL get_dir_entry(int cnum, char *mask, int dirtype, char *fname, int *size,
                   int *mode, time_t *date, BOOL check_descend);
void open_file(int fnum, int cnum, char *fname, int flags, int mode);
void close_open_files(int cnum);
void close_file(int fnum);
int reply_trans2(char *inbuf, char *outbuf, int length, int bufsize);
int reply_trans(char *inbuf, char *outbuf);
char *ufc_crypt(char *key, char *salt);
BOOL authorise_login(int snum, char *user, char *password, BOOL *guest,
                     int vuid);
void add_session_user(char *user);
int valid_uid(int uid);
BOOL password_ok(char *user, char *password, struct passwd *pwd);
void register_uid(int uid, char *name, BOOL guest);
BOOL string_combinations(char *s, int offset, BOOL (*fn)(), int N);
BOOL fromhost(int sock, struct from_host *f);
BOOL strhasupper(char *s);
BOOL strhaslower(char *s);
void disk_free(char *path, int *bsize, int *dfree, int *dsize);
int unix_error_packet(char *inbuf, char *outbuf, int def_class, uint32 def_code,
                      int line);
time_t make_unix_date2(void *date_ptr);
int cached_error_packet(char *inbuf, char *outbuf, int fnum, int line);
BOOL start_dir(int cnum, char *directory);
mode_t unix_mode(int cnum, int dosmode);
BOOL check_name(char *name, int cnum);
int error_packet(char *inbuf, char *outbuf, int error_class, uint32 error_code,
                 int line);
int find_free_file(void);
void unix_convert(char *name, int cnum);
void unix_convert_lanman2(char *s, char *home, BOOL case_is_sig);
int call_trans2findfirst(char *inbuf, char *outbuf, int bufsize, int cnum,
                         char **pparams, char **ppdata);
int call_trans2qfsinfo(char *inbuf, char *outbuf, int length, int bufsize,
                       int cnum, char **pparams, char **ppdata);
int call_trans2findnext(char *inbuf, char *outbuf, int length, int bufsize,
                        int cnum, char **pparams, char **ppdata);
void print_file(int fnum);
void check_magic(int fnum, int cnum);
int read_smb_length(int fd, char *inbuf, int timeout);
int read_predict(int fd, int offset, char *buf, int num);
void invalidate_read_prediction(int fd);
void do_read_prediction();
BOOL claim_connection(int cnum, char *name, int max_connections, BOOL Clear);
BOOL yield_connection(int cnum, char *name, int max_connections);
BOOL fcntl_lock(int fd, int op, int offset, int count, int type);
int count_chars(char *s, char c);
int smbrun(char *);
void unix_convert_83(char *s, char *home, BOOL mangle, char *MangledMap);
BOOL name_convert(char *OutName, char *InName, BOOL mangle, char *MangledNames);
struct hostent *Get_Hostbyname(char *name);
struct passwd *Get_Pwnam(char *user);
void Abort(void);
void safe_memcpy(void *dest, void *src, int size);
void *Realloc(void *p, int size);
void send_logout(char *inbuf, char *outbuf);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, BOOL zero);
void name_interpret(char *in, char *out);
BOOL check_access(int snum);
BOOL in_group(gid_t group, int current_gid, int ngroups, int *groups);
void *object_byte_swap(void *obj, int size);
void ssval(char *buf, int pos, uint16 val);
void sival(char *buf, int pos, uint32 val);
uint32 ival(char *buf, int pos);
uint16 sval(char *, int);
void ssval_s(char *buf, int pos, int16 val);
void sival_s(char *buf, int pos, int32 val);
int32 ival_s(char *buf, int pos);
int16 sval_s(char *, int);
BOOL string_set(char **dest, char *src);
BOOL string_init(char **dest, char *src);
void string_free(char **s);
char *attrib_string(int mode);
int do_long_dir(char *inbuf, char *outbuf, char *Mask, int attribute,
                void (*fn)(), BOOL recurse_dir);
int do_short_dir(char *inbuf, char *outbuf, char *Mask, int attribute,
                 void (*fn)(), BOOL recurse_dir);
void do_dir(char *inbuf, char *outbuf, char *Mask, int attribute, void (*fn)(),
            BOOL recurse_dir);
void unix_format(char *fname);
BOOL directory_exist(char *dname);
void make_dir_struct(char *buf, char *mask, char *fname, unsigned int size,
                     int mode, time_t date);
BOOL in_list(char *s, char *list, BOOL case_sensitive);
void strupper(char *s);
BOOL file_exist(char *fname);
int read_with_timeout(int fd, char *buf, int mincnt, int maxcnt, long time_out,
                      BOOL exact);
int write_socket(int fd, char *buf, int len);
void close_sockets(void);
int write_with_timeout(int fd, char *buf, int length, long time_out);
BOOL send_smb(char *buffer);
BOOL read_data(int fd, char *buffer, int N);
int smb_len(char *buf);
BOOL receive_smb(char *buffer, int timeout);
void show_msg(char *buf);
BOOL big_endian(void);
BOOL become_user(int cnum);
BOOL unbecome_user(void);
void become_daemon(void);
BOOL reduce_name(char *s, char *dir, BOOL widelinks);
void strlower(char *s);
void strnorm(char *s);
char *smb_buf();
char *smb_trans2_param(char *buf);
char *smb_trans2_data(char *buf);
BOOL strequal(char *, char *);
BOOL mask_match(char *, char *, BOOL, BOOL, BOOL);
int dos_mode(int, char *, struct stat *);
char *timestring();
BOOL ip_equal(struct in_addr *ip1, struct in_addr *ip2);
BOOL send_packet(char *buf, int len, struct in_addr *ip, int port, int type);
char *get_home_dir(char *);
int set_filelen(int fd, long len);
void put_dos_date(char *buf, int offset, time_t unixdate);
void put_dos_date2(char *buf, int offset, time_t unixdate);
uint16 make_dos_time1(time_t unixdate);
uint16 make_dos_date1(time_t unixdate);
uint32 make_dos_date(time_t);
uint32 make_dos_date2(time_t);
int lp_keepalive(void);
int name_len(char *s);
void dos_clean_name(char *s);
void unix_clean_name(char *s);
time_t make_unix_date(void *date_ptr);
void trim_string(char *s, char *front, char *back);
int byte_checksum(char *buf, int len);
BOOL yesno(char *p);
uint32 file_size(char *file_name);
void dos_format(char *fname);
char *GetWd(char *s);
int name_mangle(char *in, char *out);
int name_len(char *s);
BOOL name_equal(char *s1, char *s2);
void show_nmb(char *inbuf);
int nmb_len(char *buf);
void create_mangled_stack(int size);
BOOL receive_nmb(char *buffer, int timeout);
void name_extract(char *buf, int ofs, char *name);
BOOL name_query(char *inbuf, char *outbuf, char *name, struct in_addr to_ip,
                struct in_addr *ip, int maxtime, void (*fn)());
BOOL name_status(char *inbuf, char *outbuf, char *name);
void get_broadcast(struct in_addr *if_ipaddr, struct in_addr *if_bcast,
                   struct in_addr *if_nmask);
BOOL allow_access(char *deny_list, char *allow_list, struct from_host *client);
#ifdef __STDC__
int Debug1(char *, ...);
#else
int Debug1();
#endif
BOOL check_hosts_equiv(char *user);
char *validate_group(char *group, char *password, int snum);
int chain_reply(int type, char *inbuf, char *inbuf2, char *outbuf,
                char *outbuf2, int size, int bufsize);
void close_cnum(int cnum);
char *smb_errstr(char *inbuf);
struct tm *LocalTime(time_t *t, int);
time_t TimeLocal(struct tm *tm, int);
int TimeDiff(void);
void replacestr(char *str1, char *str2, int start, int n);
void openstr(char *s, int start, int n);
void closestr(char *s, int start, int n);
BOOL set_filetime(char *fname, time_t mtime);
char *dirname_dos(char *path, char *buf);
char *filename_dos(char *path, char *buf);
BOOL get_myname(char *myname, struct in_addr *ip);
BOOL ip_equal(struct in_addr *ip1, struct in_addr *ip2);
void expand_mask(char *Mask, BOOL);
BOOL sane_unix_date(time_t unixdate);
time_t start_of_month(void);
void log_out(char *buffer, int len);
BOOL register_name(name_struct *name, struct in_addr *destip, void (*)());
char *smb_fn_name(int cnum);
int construct_datagram(char *, int, int, int, struct in_addr *, int, char *,
                       char *);
void get_machine_info(void);
int open_socket_in(int type, int port);
int open_socket_out(struct in_addr *addr, int port);
int read_max_udp(int fd, char *buffer, int bufsize, int maxtime);
void log_in(char *buffer, int len);
int interpret_protocol(char *str, int def);
int interpret_security(char *str, int def);
int ChDir(char *path);
int smb_buflen(char *buf);
int interpret_short_filename(char *p, file_info *finfo);
int interpret_long_filename(int level, char *p, file_info *finfo);
unsigned long interpret_addr(char *str);
void mangle_name_83(char *s, char *MangledMap);
void *dptr_get(int);
char *dptr_path(int);
char *dptr_wcard(int);
int dptr_set_wcard(int, char *);
int dptr_set_attr(int, uint16);
void *dptr_fetch_lanman2(char *, int);
uint16 dptr_attr(int);
void dptr_promote(int);
void dptr_demote(int);
void dptr_close(int);
void dptr_closepath(char *, int);
int dptr_create(void *, char *, BOOL, int);
BOOL lp_casesignames(void);
#ifdef NOSTRDUP
char *strdup(char *s);
#endif
#ifdef REPLACE_STRLEN
int Strlen(char *);
#endif
#ifdef REPLACE_STRSTR
char *Strstr(char *s, char *p);
#endif

#ifdef SUN
struct DIRECT *readdir();
char *strcpy();
int fprintf();
#endif

#ifdef STRING_DEBUG
#define strcpy  mystrcpy
#define strchr  mystrchr
#define strrchr mystrrchr
#define strlen  mystrlen
#define strncpy mystrncpy
#define strcat  mystrcat
#define memcpy  mymemcpy
#define memset  mymemset
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef ABS
#define ABS(a) ((a) > 0 ? (a) : (-(a)))
#endif

#ifndef SIGNAL_CAST
#define SIGNAL_CAST
#endif

#ifndef SELECT_CAST
#define SELECT_CAST
#endif

/* Some POSIX definitions for those without */

#ifndef S_IFDIR
#define S_IFDIR 0x4000
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode) ((mode & 0xF000) == S_IFDIR)
#endif
#ifndef S_IRWXU
#define S_IRWXU 00700 /* read, write, execute: owner */
#endif
#ifndef S_IRUSR
#define S_IRUSR 00400 /* read permission: owner */
#endif
#ifndef S_IWUSR
#define S_IWUSR 00200 /* write permission: owner */
#endif
#ifndef S_IXUSR
#define S_IXUSR 00100 /* execute permission: owner */
#endif
#ifndef S_IRWXG
#define S_IRWXG 00070 /* read, write, execute: group */
#endif
#ifndef S_IRGRP
#define S_IRGRP 00040 /* read permission: group */
#endif
#ifndef S_IWGRP
#define S_IWGRP 00020 /* write permission: group */
#endif
#ifndef S_IXGRP
#define S_IXGRP 00010 /* execute permission: group */
#endif
#ifndef S_IRWXO
#define S_IRWXO 00007 /* read, write, execute: other */
#endif
#ifndef S_IROTH
#define S_IROTH 00004 /* read permission: other */
#endif
#ifndef S_IWOTH
#define S_IWOTH 00002 /* write permission: other */
#endif
#ifndef S_IXOTH
#define S_IXOTH 00001 /* execute permission: other */
#endif

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets */
enum protocol_types {
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1
};

/* security levels */
enum security_types {
	SEC_SHARE,
	SEC_USER
};

/* case handling */
enum case_handling {
	CASE_LOWER,
	CASE_UPPER
};

/* Macros to get at offsets within smb_lkrng and smb_unlkrng
   structures. We cannot define these as actual structures
   due to possible differences in structure packing
   on different machines/compilers. */

#define SMB_LPID_OFFSET(indx)  (10 * (indx))
#define SMB_LKOFF_OFFSET(indx) (2 + (10 * (indx)))
#define SMB_LKLEN_OFFSET(indx) (6 + (10 * (indx)))

/* Macro to cache an error in a write_bmpx_struct */
#define CACHE_ERROR(w, c, e)                                                   \
	((w)->wr_errclass = (c), (w)->wr_error = (e), w->wr_discard = True, -1)
/* Macro to test if an error has been cached for this fnum */
#define HAS_CACHED_ERROR(fnum)                                                 \
	(Files[(fnum)].open && Files[(fnum)].wbmpx_ptr &&                      \
	 Files[(fnum)].wbmpx_ptr->wr_discard)
/* Macro to turn the cached error into an error packet */
#define CACHED_ERROR(fnum) cached_error_packet(inbuf, outbuf, fnum, __LINE__)

/* these are the datagram types */
#define DGRAM_DIRECT_UNIQUE 0x10

#define ERROR(class, x) error_packet(inbuf, outbuf, class, x, __LINE__)

/* this is how errors are generated */
#define UNIXERROR(defclass, deferror)                                          \
	unix_error_packet(inbuf, outbuf, defclass, deferror, __LINE__)

#endif
/* _SMB_H */
