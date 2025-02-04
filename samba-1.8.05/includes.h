#include <stdio.h>
#ifdef MIPS
#include <posix/stdlib.h>
#else
#include <stdlib.h>
#endif /* MIPS */
#include <ctype.h>
#include <time.h>
#if (!(defined(sun386) || defined(NEXT2) || defined(NEXT3_0) ||                \
       defined(APOLLO) || defined(MIPS)))
#include <utime.h>
#endif
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifdef MIPS
#include <bsd/netinet/in.h>
#include <bsd/sys/time.h>
#include <posix/utime.h>
#else
#include <netinet/in.h>
#include <sys/time.h>
#endif /* MIPS */
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#ifndef APOLLO
#include <sys/mount.h>
#endif
#include <pwd.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#if !defined(NEXT3_0) && !defined(APOLLO)
#include <unistd.h>
#endif
#include <sys/wait.h>
#ifdef CLIX /* need rusage structure */
#include <sys/resource.h>
#endif /* end CLIX */
#ifdef ISC
#include <sys/stream.h>
#endif
#ifdef MIPS
#include <bsd/net/if.h>
#else
#include <net/if.h>
#endif

#if USE_MMAP
#include <sys/mman.h>
#endif

#if defined(GETPWANAM)
#include <pwdadj.h>
#include <sys/audit.h>
#include <sys/label.h>
#include <sys/types.h>
#endif

#if defined(SHADOW_PWD) && !defined(NETBSD)
#include <shadow.h>
#endif

#ifdef LINUX
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <sys/vfs.h>
#define SIGNAL_CAST (__sighandler_t)
#define HAVE_TIMEZONE
#define HAVE_SYSCONF 1
#define USE_GETCWD
#endif

#ifdef SUN
#define HAVE_TIMELOCAL
#include <errno.h>
#include <string.h>
#include <sys/acct.h>
#include <sys/dirent.h>
#include <sys/vfs.h>
#ifndef sun386
#include <utime.h>
#endif
#include <signal.h>
#include <sys/wait.h>
#ifdef sun386
/* Things we need to change for sun386i */
#define NO_STRFTIME
#ifdef PWDAUTH
#undef PWDAUTH
#endif
#define strerror strerror
struct utimbuf {
	time_t actime;
	time_t modtime;
};
typedef unsigned short mode_t;
#endif
#ifndef strerror
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif
#endif

#ifdef SOLARIS
#include <dirent.h>
#include <string.h>
#include <sys/acct.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#define HAVE_TIMEZONE
#define SIGNAL_CAST (void (*)(int))
#define SYSV
#define USE_WAITPID
#define REPLACE_STRLEN
#define USE_STATVFS
#define USE_GETCWD
#endif

#ifdef SGI
#include <signal.h>
#include <string.h>
#include <sys/statfs.h>
#define SYSV
#define SIGNAL_CAST (void (*)())
#define STATFS4
#endif

#ifdef MIPS
#include <bsd/net/soioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/termio.h>
#include <sys/wait.h>
#define SIGNAL_CAST (void (*)())
typedef int mode_t;
extern struct group *getgrnam();
extern struct passwd *getpwnam();
#define HAVE_TIMEZONE
#define STATFS4
#ifndef strerror
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif /* ! strerror */
#define REPLACE_STRSTR
#endif /* MIPS */

#ifdef DGUX
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <termios.h>
#define SYSV
#define USE_WAITPID
#define HAVE_TIMEZONE
#define SIGNAL_CAST (void (*)(int))
#define USE_STATVFS
#define USE_GETCWD
#endif

#ifdef SVR4
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/dir.h>
#include <sys/filio.h>
#include <sys/sockio.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <termios.h>
#define SYSV
#define USE_WAITPID
#define HAVE_TIMEZONE
#define SIGNAL_CAST (void (*)(int))
#define USE_STATVFS
#define USE_GETCWD
#endif

#ifdef ULTRIX
#include <nfs/nfs_clnt.h>
#include <nfs/vfs.h>
#include <strings.h>
#ifdef ULTRIX_AUTH
#include <auth.h>
#endif
char *getwd(char *);
#define GID_TYPE int
#define NOSTRDUP
#ifdef __STDC__
#define SIGNAL_CAST (void (*)(int))
#endif
#endif

#ifdef OSF1
#include <dirent.h>
#include <strings.h>
char *getwd(char *);
#define STATFS3
#define USE_F_FSIZE
#ifdef OSF1_ENH_SEC
#include <prot.h>
#include <pwd.h>
#include <sys/security.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* OSF1_ENH_SEC */
#endif

#ifdef CLIX
#include <dirent.h>
#define SIGNAL_CAST (void (*)())
#include <sys/fcntl.h>
#include <sys/statfs.h>
#define HAVE_TIMEZONE
#include <string.h>
#define NO_EID
#define USE_WAITPID
#define STATFS4
#define NO_FSYNC
#define USE_GETCWD
#define USE_SETSID
#define NO_INITGROUPS
#endif /* CLIX */

#ifdef BSDI
#include <string.h>
#define USE_F_FSIZE
#endif

#ifdef NETBSD
#include <strings.h>
/* you may not need this */
#define NO_GETSPNAM
#define SIGNAL_CAST (void (*)())
#endif

#ifdef FreeBSD
#include <strings.h>
#define SIGNAL_CAST (void (*)())
#define GID_TYPE    int
#endif

#ifdef AIX
#include <dirent.h>
#include <strings.h>
#include <sys/dir.h>
#include <sys/id.h>
#include <sys/priv.h>
#include <sys/select.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#define HAVE_TIMEZONE
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)())
#endif

#ifdef HPUX
#include <dirent.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/vfs.h>
#define SIGNAL_CAST (void (*)(__harg))
#define SELECT_CAST (int *)
#define HAVE_TIMEZONE
#define SYSV
#define USE_WAITPID
#define WAIT3_CAST2 (int *)
#define USE_GETCWD
#define USE_SETSID
#define USE_SETRES
#endif

#ifdef SEQUENT
char *strchr();
char *strrchr();
typedef int mode_t;
#define SEEK_SET 0
#endif

#ifdef NEXT
#include <dirent.h>
#include <strings.h>
#include <sys/dir.h>
#include <sys/vfs.h>
#define bzero(b, len) memset(b, 0, len)
#include <libc.h>
#define NOSTRDUP
#define USE_WAITPID
#define NO_STRFTIME
#define USE_GETCWD
#define WAIT3_CAST1 (union wait *)
#endif

#ifdef NEXT2
#include <dirent.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/vfs.h>
#define bzero(b, len) memset(b, 0, len)
#define mode_t        int
struct utimbuf {
	time_t actime;
	time_t modtime;
};
#include <libc.h>
#define NOSTRDUP
#define USE_DIRECT
#define USE_WAITPID
#endif

#ifdef NEXT3_0
#include <strings.h>
#include <sys/dir.h>
#include <sys/vfs.h>
#define bzero(b, len) memset(b, 0, len)
struct utimbuf {
	time_t actime;
	time_t modtime;
};
#include <libc.h>
#define NOSTRDUP
#define USE_DIRECT
#define mode_t int
#endif

#ifdef APOLLO
#include <fcntl.h>
#include <string.h>
#include <sys/statfs.h>
struct utimbuf {
	time_t actime;
	time_t modtime;
};
#define USE_DIRECT
#define USE_GETCWD
#define SIGNAL_CAST     (void (*)())
#define HAVE_FCNTL_LOCK 0

#define HAVE_GETTIMEOFDAY
#define STATFS4
/* Define Posix stat flags if needed */
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_ISREG
#define S_ISREG(mode) ((mode & 0xF000) == S_IFDIR)
#endif

#endif

#ifdef SCO
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/statfs.h>
#include <sys/stropts.h>
#ifdef NETGROUP
#include <rpcsvc/ypclnt.h>
#endif
#ifdef SecureWare
#include <prot.h>
#include <sys/audit.h>
#include <sys/security.h>
#define crypt bigcrypt
#endif
#define ftruncate(f, l) syscall(0x0a28, f, l)
#define HAVE_TIMEZONE
#define SIGNAL_CAST (void (*)(int))
#define USE_WAITPID
#define USE_GETCWD
#define USE_SETSID
#define USE_IFREQ
#define STATFS4
#define NO_FSYNC
#define NO_INITGROUPS
#endif

#ifdef ISC
#include <dirent.h>
#include <fcntl.h>
#include <net/errno.h>
#include <string.h>
#include <stropts.h>
#include <sys/dir.h>
#include <sys/sioctl.h>
#include <sys/statfs.h>
#define FIONREAD FIORDCHK
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
#define USE_GETCWD
#define USE_SETSID
#define USE_IFREQ
#define NO_FTRUNCATE
#define STATFS4
#define NO_FSYNC
#define HAVE_TIMEZONE
#endif

#ifdef KANJI
#ifndef _KANJI_C_
#include "kanji.h"
#endif /* _KANJI_C_ */
#endif /* KANJI */

#ifdef NO_GETSPNAM
struct spwd { /* fake shadow password structure */
	char *sp_pwdp;
};
struct spwd *getspnam(char *username); /* fake shadow password routine */
#endif

#ifdef USE_DIRECT
#include <sys/dir.h>
#endif

/* this unix might use int for gid_t (eg: Ultrix) */
#ifndef GID_TYPE
#define GID_TYPE gid_t
#endif

#include "smb.h"
#include "version.h"

#ifdef UFC_CRYPT
#define crypt ufc_crypt
#endif

#ifdef REPLACE_STRLEN
#define strlen(s) Strlen(s)
#endif

#ifdef REPLACE_STRSTR
#define strstr(s, p) Strstr(s, p)
#endif

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 128
#endif

#ifndef EDQUOT
#define EDQUOT ENOSPC
#endif

#ifndef HAVE_SYSCONF
#define HAVE_SYSCONF 0
#endif

#ifndef HAVE_GETGRNAM
#define HAVE_GETGRNAM 1
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

#ifndef HAVE_FCNTL_LOCK
#define HAVE_FCNTL_LOCK 1
#endif

#ifndef WAIT3_CAST2
#define WAIT3_CAST2 (struct rusage *)
#endif

#ifndef WAIT3_CAST1
#define WAIT3_CAST1 (int *)
#endif

#ifdef NO_EID
#define geteuid()  getuid()
#define getegid()  getgid()
#define seteuid(x) setuid(x)
#define setegid(x) setgid(x)
#endif

#if (HAVE_FCNTL_LOCK == 0)
/* since there is no locking available, system includes  */
/* for DomainOS 10.4 do not contain any of the following */
/* #define's. So, to satisfy the compiler, add these     */
/* #define's, although they arn't really necessary.      */
#define F_GETLK 0
#define F_SETLK 0
#define F_WRLCK 0
#define F_UNLCK 0
#endif /* HAVE_FCNTL_LOCK == 0 */

/* possibly wrap the malloc calls */
#if WRAP_MALLOC

/* undo the old malloc def if necessary */
#ifdef malloc
#define xx_old_malloc malloc
#undef malloc
#endif

#define malloc(size) malloc_wrapped(size, __FILE__, __LINE__)

/* undo the old realloc def if necessary */
#ifdef realloc
#define xx_old_realloc realloc
#undef realloc
#endif

#define realloc(ptr, size) realloc_wrapped(ptr, size, __FILE__, __LINE__)

/* undo the old free def if necessary */
#ifdef free
#define xx_old_free free
#undef free
#endif

#define free(ptr) free_wrapped(ptr, __FILE__, __LINE__)

/* and the malloc prototypes */
void *malloc_wrapped(int, char *, int);
void *realloc_wrapped(void *, int, char *, int);
void free_wrapped(void *, char *, int);

#endif
