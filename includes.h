#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1998
   
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
/*
   This file does all the #includes's. This makes it easier to
   port to a new unix. Hopefully a port will only have to edit the Makefile
   and add a section for the new unix below.
*/



/* the first OS dependent section is to setup what includes will be used.
   the main OS dependent section comes later on 
*/

















#if (defined(SHADOW_PWD)||defined(OSF1_ENH_SEC)||defined(SecureWare)||defined(PWDAUTH))
#define PASSWORD_LENGTH 16
#endif

/* here is the general includes section - with some ifdefs generated 
   by the previous section 
*/
#include "local.h"
#include <stdio.h>
#ifdef POSIX_STDLIBH
#include <posix/stdlib.h>
#else
#include <stdlib.h>
#endif
#include <ctype.h>
#include <time.h>
#ifndef NO_UTIMEH
#include <utime.h>
#endif
#include <sys/types.h>


#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stddef.h>
#ifdef POSIX_H
#include <posix/utime.h>
#include <bsd/sys/time.h>
#include <bsd/netinet/in.h>
#else
#include <sys/time.h>
#include <netinet/in.h>
#endif 
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <grp.h>
#ifndef NO_RESOURCEH
#include <sys/resource.h>
#endif
#ifndef NO_SYSMOUNTH
#include <sys/mount.h>
#endif
#include <pwd.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifndef NO_UNISTDH
#include <unistd.h>
#endif
#include <sys/wait.h>
#ifdef SYSSTREAMH
#include <sys/stream.h>
#endif
#ifndef NO_NETIFH
#ifdef POSIX_H
#include <bsd/net/if.h>
#else
#include <net/if.h>
#endif
#endif

#if defined(GETPWANAM)
#include <sys/types.h>
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif

#if defined(SHADOW_PWD) && !defined(NETBSD) && !defined(FreeBSD) && !defined(CONVEX) && !defined(__OpenBSD__)
#include <shadow.h>
#endif

#ifdef SYSLOG
#include <syslog.h>
#endif



/***************************************************************************
Here come some platform specific sections
***************************************************************************/


#ifdef LINUX
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#ifdef GLIBC2
#define _LINUX_C_LIB_VERSION_MAJOR     6
#include <termios.h>
#include <rpcsvc/ypclnt.h>
#include <crypt.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#endif
#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif /* QSORT_CAST */
#define SIGNAL_CAST (__sighandler_t)
#define USE_GETCWD
#define USE_SETSID
#define HAVE_BZERO
#define HAVE_MEMMOVE
#define HAVE_VSNPRINTF
#define USE_SIGPROCMASK
#define USE_WAITPID
#if 0
/* SETFS disabled until we can check on some bug reports */
#if _LINUX_C_LIB_VERSION_MAJOR >= 5
#define USE_SETFS
#endif
#endif
#ifdef SHADOW_PWD
#if _LINUX_C_LIB_VERSION_MAJOR < 5
#ifndef crypt
#define crypt pw_encrypt
#endif
#endif
#endif
#endif























#ifdef NETBSD 
#ifdef NetBSD1_3
#include <string.h>
#ifdef ALLOW_CHANGE_PASSWORD
#include <termios.h>
#endif /* ALLOW_CHANGE_PASSWORD */
#else /* NetBSD1_3 */
#include <strings.h>
#endif /* NetBSD1_3 */
#include <netinet/tcp.h>
#include <netinet/in_systm.h> 
#include <netinet/ip.h> 
/* you may not need this */
#define NO_GETSPNAM
#define SIGNAL_CAST (void (*)())
#define USE_DIRECT
#define REPLACE_INNETGR
#endif 



#ifdef FreeBSD
#include <arpa/inet.h>
#include <strings.h>
#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <termios.h>
#if __FreeBSD__ >= 3
#include <dirent.h>
#else
#define USE_DIRECT
#endif
#define SIGNAL_CAST (void (*)(int))
#define USE_SETVBUF
#define USE_SETSID
#define USE_GETCWD
#define USE_WAITPID
#define HAVE_MEMMOVE
#define HAVE_BZERO
#define HAVE_GETTIMEOFDAY
#define HAVE_PATHCONF
#define HAVE_GETGRNAM 1
#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif /* QSORT_CAST */
#if !defined(O_SYNC)
#if defined(O_FSYNC)
#define O_SYNC O_FSYNC
#else /* defined(O_FSYNC) */
#define O_SYNC 0
#endif /* defined(O_FSYNC) */
#endif /* !defined(O_SYNC) */
#define HAVE_VSNPRINTF
#endif /* FreeBSD */

#ifdef __OpenBSD__
#include <strings.h>
#include <netinet/tcp.h>
#define NO_GETSPNAM
#define SIGNAL_CAST (void (*)())
#define USE_DIRECT
#define REPLACE_INNETGR
#define HAVE_BZERO
#define HAVE_PATHCONF
#define HAVE_GETGRNAM 1
#define HAVE_GETTIMEOFDAY
#define HAVE_MEMMOVE
#define USE_GETCWD
#define USE_SETSID
#endif 





















/* Definitions for RiscIX */

























/* For UnixWare 2.x's ia_uinfo routines. (tangent@cyberport.com) */


/*******************************************************************
end of the platform specific sections
********************************************************************/

#if defined(USE_MMAP) || defined(FAST_SHARE_MODES)
#include <sys/mman.h>
#endif


#ifdef REPLACE_GETPASS
extern char    *getsmbpass(char *);
#define getpass(s) getsmbpass(s)
#endif

#ifdef REPLACE_INNETGR
#define innetgr(group,host,user,dom) InNetGr(group,host,user,dom)
#endif

#ifndef FD_SETSIZE
#define FD_SETSIZE 255
#endif

#ifndef __STDC__
#define const
#endif

/* Now for some other grungy stuff */
#if defined(NO_GETSPNAM) && !defined(QNX)
struct spwd { /* fake shadow password structure */
       char *sp_pwdp;
};
#endif



#ifdef USE_DIRECT
#include <sys/dir.h>
#endif

/* some unixes have ENOTTY instead of TIOCNOTTY */
#ifndef TIOCNOTTY
#ifdef ENOTTY
#define TIOCNOTTY ENOTTY
#endif
#endif

#ifndef SIGHUP
#define SIGHUP 1
#endif

/* if undefined then use bsd or sysv printing */
#ifndef DEFAULT_PRINTING
#define DEFAULT_PRINTING PRINT_BSD
#endif

/* This defines the name of the printcap file. It is MOST UNLIKELY that
   this will change BUT! Specifying a file with the format of a printcap
   file but containing only a subset of the printers actually in your real 
   printcap file is a quick-n-dirty way to allow dynamic access to a subset
   of available printers.
*/
#ifndef PRINTCAP_NAME
#define PRINTCAP_NAME "/etc/printcap"
#endif


#ifdef AFS_AUTH
#include <afs/stds.h>
#include <afs/kautils.h>
#endif

#ifdef DFS_AUTH
#include <dce/dce_error.h>
#include <dce/sec_login.h>
#endif

#ifdef KRB5_AUTH
#include <krb5.h>
#endif

#ifdef KRB4_AUTH
#include <krb.h>
#endif

#ifdef NO_UTIMBUF
struct utimbuf {
  time_t actime;
  time_t modtime;
};
#endif

#ifdef NO_STRERROR
#ifndef strerror
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif
#endif

#ifndef perror
#define perror(m) printf("%s: %s\n",m,strerror(errno))
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#include "version.h"
#include "smb.h"
#include "nameserv.h"
#include "ubiqx/ubi_dLinkList.h"

#include "byteorder.h"

#include "kanji.h"
#include "charset.h"

#ifndef MAXCODEPAGELINES
#define MAXCODEPAGELINES 256
#endif

/***** automatically generated prototypes *****/
#include "proto.h"



#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#ifndef S_ISREG
#define S_ISREG(x) ((S_IFREG & (x))!=0)
#endif

#ifndef S_ISDIR
#define S_ISDIR(x) ((S_IFDIR & (x))!=0)
#endif

#if !defined(S_ISLNK) && defined(S_IFLNK)
#define S_ISLNK(x) ((S_IFLNK & (x))!=0)
#endif

#ifdef UFC_CRYPT
#define crypt ufc_crypt
#endif

#ifdef REPLACE_STRLEN
#define strlen(s) Strlen(s)
#endif

#ifdef REPLACE_STRSTR
#define strstr(s,p) Strstr(s,p)
#endif

#ifdef REPLACE_MKTIME
#define mktime(t) Mktime(t)
#endif

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 128
#endif

#ifndef EDQUOT
#define EDQUOT ENOSPC
#endif


#ifndef SOL_TCP
#define SOL_TCP 6
#endif

/* default to using ftruncate workaround as this is safer than assuming
it works and getting lots of bug reports */
#ifndef FTRUNCATE_CAN_EXTEND
#define FTRUNCATE_CAN_EXTEND 0
#endif

/* maybe this unix doesn't separate RD and WR locks? */
#ifndef F_RDLCK
#define F_RDLCK F_WRLCK
#endif

#ifndef ENOTSOCK
#define ENOTSOCK EINVAL
#endif

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif 

#ifndef MAP_FILE
#define MAP_FILE 0
#endif


#ifndef WAIT3_CAST2
#define WAIT3_CAST2 (struct rusage *)
#endif

#ifndef WAIT3_CAST1
#define WAIT3_CAST1 (int *)
#endif

#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(void *, void *))
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif /* INADDR_LOOPBACK */

/* this is a rough check to see if this machine has a lstat() call.
   it is not guaranteed to work */
#if !defined(S_ISLNK)
#define lstat stat
#endif

/* Not all systems declare ERRNO in errno.h... and some systems #define it! */
#ifndef errno
extern int errno;
#endif 


#ifdef NO_EID
#define geteuid() getuid()
#define getegid() getgid()
#define seteuid(x) setuid(x)
#define setegid(x) setgid(x)
#endif



#ifdef NOSTRCASECMP
#define strcasecmp(s1,s2) StrCaseCmp(s1,s2)
#define strncasecmp(s1,s2,n) StrnCaseCmp(s1,s2,n)
#endif

#ifdef strcpy
#undef strcpy
#endif /* strcpy */
#define strcpy(dest,src) __ERROR__XX__NEVER_USE_STRCPY___;
   
#ifdef strcat
#undef strcat
#endif /* strcat */
#define strcat(dest,src) __ERROR__XX__NEVER_USE_STRCAT___;
   
#ifdef sprintf
#undef sprintf
#endif /* sprintf */
#define sprintf __ERROR__XX__NEVER_USE_SPRINTF__;

#define pstrcpy(d,s) safe_strcpy((d),(s),sizeof(pstring)-1)
#define pstrcat(d,s) safe_strcat((d),(s),sizeof(pstring)-1)
#define fstrcpy(d,s) safe_strcpy((d),(s),sizeof(fstring)-1)
#define fstrcat(d,s) safe_strcat((d),(s),sizeof(fstring)-1)

#if MEM_MAN
#include "mem_man/mem_man.h"
#endif

#endif
