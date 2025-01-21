/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) John H Terpstra 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton 1998

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

#define BUFFER_SIZE   (0xFFFF)
#define SAFETY_MARGIN 1024

#define NMB_PORT   137
#define DGRAM_PORT 138
#define SMB_PORT   139

#define BOOLSTR(b)        ((b) ? "Yes" : "No")
#define BITSETB(ptr, bit) ((((char *) ptr)[0] & (1 << (bit))) != 0)
#define BITSETW(ptr, bit) ((SVAL(ptr, 0) & (1 << (bit))) != 0)
#define PTR_DIFF(p1, p2)  ((ptrdiff_t) (((char *) (p1)) - (char *) (p2)))

/* limiting size of ipc replies */
#define REALLOC(ptr, size) checked_realloc(ptr, MAX((size), 4 * 1024))

/* how long to wait for secondary SMB packets (milli-seconds) */
#define SMB_SECONDARY_WAIT (60 * 1000)

/* logging interface */
#define LOG(level, ...)                                                        \
	do {                                                                   \
		if (LOGLEVEL >= (level)) {                                     \
			log_output(level, __VA_ARGS__);                        \
		}                                                              \
	} while (0)

#define ERROR(...)   LOG(0, __VA_ARGS__)
#define WARNING(...) LOG(1, __VA_ARGS__)
#define NOTICE(...)  LOG(2, __VA_ARGS__)
#define INFO(...)    LOG(3, __VA_ARGS__)
#define DEBUG(...)   LOG(4, __VA_ARGS__)

/* this defines the error codes that receive_smb can put in smb_read_error */
#define READ_TIMEOUT 1
#define READ_EOF     2
#define READ_ERROR   3

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

/* deny modes */
#define DENY_DOS   0
#define DENY_ALL   1
#define DENY_WRITE 2
#define DENY_READ  3
#define DENY_NONE  4
#define DENY_FCB   7

/* share types */
#define STYPE_DISKTREE 0          /* Disk drive */
#define STYPE_PRINTQ   1          /* Spooler queue */
#define STYPE_DEVICE   2          /* Serial device */
#define STYPE_IPC      3          /* Interprocess communication (IPC) */
#define STYPE_HIDDEN   0x80000000 /* share is a hidden one (ends with $) */

/* SMB X/Open error codes for the ERRdos error class */
#define ERRbadfunc              1 /* Invalid function (or system call) */
#define ERRbadfile              2 /* File not found (pathname error) */
#define ERRbadpath              3 /* Directory not found */
#define ERRnofids               4 /* Too many open files */
#define ERRnoaccess             5 /* Access denied */
#define ERRbadfid               6 /* Invalid fid */
/* We should never return this error. We handle memory allocation failures as
   a fatal error, in which case the program aborts. */
/*#define ERRnomem                8*/ /* Out of memory */
#define ERRbadmem               9     /* Invalid memory block address */
#define ERRbadenv               10    /* Invalid environment */
#define ERRbadaccess            12    /* Invalid open mode */
#define ERRbaddata              13    /* Invalid data (only from ioctl call) */
#define ERRres                  14    /* reserved */
#define ERRbaddrive             15    /* Invalid drive */
#define ERRremcd                16    /* Attempt to delete current directory */
#define ERRdiffdevice           17 /* rename/move across different filesystems */
#define ERRnofiles              18 /* no more files found in file search */
#define ERRbadshare             32 /* Share mode on file conflict with open mode */
#define ERRlock                 33 /* Lock request conflicts with existing lock */
#define ERRfilexists            80  /* File in operation already exists */
#define ERRcannotopen           110 /* Cannot open the file specified */
#define ERRunknownlevel         124
#define ERRbadpipe              230 /* Named pipe invalid */
#define ERRpipebusy             231 /* All instances of pipe are busy */
#define ERRpipeclosing          232 /* named pipe close in progress */
#define ERRnotconnected         233 /* No process on other end of named pipe */
#define ERRmoredata             234 /* More data to be returned */
#define ERRbaddirectory         267 /* Invalid directory name in a path. */
#define ERROR_EAS_DIDNT_FIT     275 /* Extended attributes didn't fit */
#define ERROR_EAS_NOT_SUPPORTED 282 /* Extended attributes not supported */
#define ERRunknownipc           2142

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
#define ERRcontMPX    252 /* resume MPX mode */
#define ERRbadPW          /* reserved */
#define ERRnosupport  0xFFFF
#define ERRunknownsmb 22 /* from NT 3.5 response */

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

/* Structure used when SMBwritebmpx is active */
struct bmpx_data {
	int wr_total_written; /* So we know when to discard this */
	int32_t wr_timeout;
	int32_t wr_errclass;
	int32_t wr_error; /* Cached errors */
	bool wr_mode;     /* write through mode) */
	bool wr_discard;  /* discard all further data */
};

/*
 * Structure used to indirect fd's from the struct open_file.
 * Needed as POSIX locking is based on file and process, not
 * file descriptor and process.
 */

struct open_fd {
	uint16_t ref_count;
	uint32_t dev;
	uint32_t inode;
	int fd;
	int fd_readonly;
	int fd_writeonly;
	int real_open_flags;
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

struct share {
	char *name;
	char *path;
	char *description;
};

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

/* NT SMB extensions. */
#define SMBnttrans   0xA0 /* NT transact */
#define SMBnttranss  0xA1 /* NT transact secondary */
#define SMBntcreateX 0xA2 /* NT create and X */
#define SMBntcancel  0xA4 /* NT cancel */

/* These are the TRANS2 sub commands */
#define TRANSACT2_OPEN                     0
#define TRANSACT2_FINDFIRST                1
#define TRANSACT2_FINDNEXT                 2
#define TRANSACT2_QFSINFO                  3
#define TRANSACT2_SETFSINFO                4
#define TRANSACT2_QPATHINFO                5
#define TRANSACT2_SETPATHINFO              6
#define TRANSACT2_QFILEINFO                7
#define TRANSACT2_SETFILEINFO              8
#define TRANSACT2_FSCTL                    9
#define TRANSACT2_IOCTL                    0xA
#define TRANSACT2_FINDNOTIFYFIRST          0xB
#define TRANSACT2_FINDNOTIFYNEXT           0xC
#define TRANSACT2_MKDIR                    0xD
#define TRANSACT2_SESSION_SETUP            0xE
#define TRANSACT2_GET_DFS_REFERRAL         0x10
#define TRANSACT2_REPORT_DFS_INCONSISTANCY 0x11

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
#define smb_base(buf) (((char *) (buf)) + 4)

#define SMB_SUCCESS 0    /* The request was successful. */
#define ERRDOS      0x01 /*  Error is from the core DOS operating system set. */
#define ERRSRV                                                                 \
	0x02        /* Error is generated by the server network file           \
	               manager.*/
#define ERRHRD 0x03 /* Error is an hardware error. */
#define ERRCMD 0xFF /* Command was not in the "SMB" format. */

int log_output(int level, char *, ...);

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef SIGNAL_CAST
#define SIGNAL_CAST
#endif

/* these are used in NetServerEnum to choose what to receive */
#define SV_TYPE_WORKSTATION       0x00000001
#define SV_TYPE_SERVER            0x00000002
#define SV_TYPE_SQLSERVER         0x00000004
#define SV_TYPE_DOMAIN_CTRL       0x00000008
#define SV_TYPE_DOMAIN_BAKCTRL    0x00000010
#define SV_TYPE_TIME_SOURCE       0x00000020
#define SV_TYPE_AFP               0x00000040
#define SV_TYPE_NOVELL            0x00000080
#define SV_TYPE_DOMAIN_MEMBER     0x00000100
#define SV_TYPE_PRINTQ_SERVER     0x00000200
#define SV_TYPE_DIALIN_SERVER     0x00000400
#define SV_TYPE_SERVER_UNIX       0x00000800
#define SV_TYPE_NT                0x00001000
#define SV_TYPE_WFW               0x00002000
#define SV_TYPE_SERVER_MFPN       0x00004000
#define SV_TYPE_SERVER_NT         0x00008000
#define SV_TYPE_POTENTIAL_BROWSER 0x00010000
#define SV_TYPE_BACKUP_BROWSER    0x00020000
#define SV_TYPE_MASTER_BROWSER    0x00040000
#define SV_TYPE_DOMAIN_MASTER     0x00080000
#define SV_TYPE_SERVER_OSF        0x00100000
#define SV_TYPE_SERVER_VMS        0x00200000
#define SV_TYPE_WIN95_PLUS        0x00400000
#define SV_TYPE_ALTERNATE_XPORT   0x20000000
#define SV_TYPE_LOCAL_LIST_ONLY   0x40000000
#define SV_TYPE_DOMAIN_ENUM       0x80000000
#define SV_TYPE_ALL               0xFFFFFFFF

/* what server type are we currently  - JHT Says we ARE 4.20 */
/* this was set by JHT in liaison with Jeremy Allison early 1997 */
/* setting to 4.20 at same time as announcing ourselves as NT Server */
/* History: */
/* Version 4.0 - never made public */
/* Version 4.10 - New to 1.9.16p2, lost in space 1.9.16p3 to 1.9.16p9 */
/*		- Reappeared in 1.9.16p11 with fixed smbd services */
/* Version 4.20 - To indicate that nmbd and browsing now works better */

#define DEFAULT_MAJOR_VERSION 0x04
#define DEFAULT_MINOR_VERSION 0x02

/* Capabilities.  see ftp.microsoft.com/developr/drg/cifs/cifs/cifs4.txt */

#define CAP_RAW_MODE         0x0001
#define CAP_MPX_MODE         0x0002
#define CAP_UNICODE          0x0004
#define CAP_LARGE_FILES      0x0008
#define CAP_NT_SMBS          0x0010
#define CAP_RPC_REMOTE_APIS  0x0020
#define CAP_STATUS32         0x0040
#define CAP_LEVEL_II_OPLOCKS 0x0080
#define CAP_LOCK_AND_READ    0x0100
#define CAP_NT_FIND          0x0200
#define CAP_DFS              0x1000
#define CAP_LARGE_READX      0x4000

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

/* Macros to get at offsets within smb_lkrng and smb_unlkrng
   structures. We cannot define these as actual structures
   due to possible differences in structure packing
   on different machines/compilers. */
#define SMB_LKOFF_OFFSET(indx) (2 + (10 * (indx)))
#define SMB_LKLEN_OFFSET(indx) (6 + (10 * (indx)))

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

#define ROUNDUP(x, g) (((x) + ((g) - 1)) & ~((g) - 1))

/*
 * Global value meaing that the smb_uid field should be
 * ingored (in share level security and protocol level == CORE)
 */

#define UID_FIELD_INVALID 0

/*
 * Integers used to override error codes.
 */
extern int unix_ERR_class;
extern int unix_ERR_code;

/***************************************************************
 OPLOCK section.
****************************************************************/

/* Lock types. */
#define LOCKING_ANDX_SHARED_LOCK     0x1
#define LOCKING_ANDX_OPLOCK_RELEASE  0x2
#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x4
#define LOCKING_ANDX_CANCEL_LOCK     0x8
#define LOCKING_ANDX_LARGE_FILES     0x10

/***************************************************************
 End of OPLOCK section.
****************************************************************/

extern const struct share *ipc_service;

extern char client_addr[32];

#endif /* _SMB_H */
/* _SMB_H */
