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

#include "../src/byteorder.h"

#define BUFFER_SIZE (0xFFFF)

#define PTR_DIFF(p1, p2) ((ptrdiff_t) (((char *) (p1)) - (char *) (p2)))

/* debugging code */
#define DEBUG(level, body) ((DEBUGLEVEL >= (level)) ? (Debug1 body) : 0)

typedef char pstring[1024];
typedef char fstring[128];

/* access various service details */
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

/* and a few prototypes */
bool string_sub(char *s, char *pattern, char *insert);
char *skip_string(char *buf, int n);
int find_free_connection(void);
void close_file(int fnum);
char *ufc_crypt(char *key, char *salt);
bool strhasupper(char *s);
bool strhaslower(char *s);
bool check_name(char *name, int cnum);
struct hostent *Get_Hostbyname(char *name);
void Abort(void);
void safe_memcpy(void *dest, void *src, int size);
void *Realloc(void *p, int size);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, bool zero);
void name_interpret(char *in, char *out);
void strupper(char *s);
bool file_exist(char *fname);
int read_with_timeout(int fd, char *buf, int mincnt, int maxcnt,
                      int32_t time_out, bool exact);
int write_socket(int fd, char *buf, int len);
int write_with_timeout(int fd, char *buf, int length, int32_t time_out);
bool send_smb(char *buffer);
bool read_data(int fd, char *buffer, int N);
int smb_len(char *buf);
bool receive_smb(char *buffer, int timeout);
void show_msg(char *buf);
void become_daemon(void);
void strlower(char *s);
void strnorm(char *s);
char *smb_buf();
bool strequal(char *, char *);
char *timestring();
bool send_packet(char *buf, int len, struct in_addr *ip, int port, int type);
int name_len(char *s);
uint32_t file_size(char *file_name);
void dos_format(char *fname);
char *GetWd(char *s);
int name_mangle(char *in, char *out);
int name_len(char *s);
void show_nmb(char *inbuf);
void create_mangled_stack(int size);
void name_extract(char *buf, int ofs, char *name);
#ifdef __STDC__
int Debug1(char *, ...);
#else
int Debug1();
#endif
struct tm *LocalTime(time_t *t, int);
time_t TimeLocal(struct tm *tm, int);
int TimeDiff(void);
void replacestr(char *str1, char *str2, int start, int n);
void openstr(char *s, int start, int n);
void closestr(char *s, int start, int n);
bool set_filetime(char *fname, time_t mtime);
bool get_myname(char *myname);
bool ip_equal(struct in_addr *ip1, struct in_addr *ip2);
char *smb_fn_name(int cnum);
int open_socket_in(int type, int port);
int open_socket_out(struct in_addr *addr, int port);
uint32_t interpret_addr(char *str);

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

#endif
/* _SMB_H */
