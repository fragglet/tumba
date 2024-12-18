#include "local.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <utime.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <pwd.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <unistd.h>
#include <sys/wait.h>
#include <net/if.h>

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
#endif

#ifdef SUN
#define HAVE_TIMELOCAL
#include <dirent.h>
#include <sys/acct.h>
#include <sys/vfs.h>
#include <string.h>
#include <errno.h>
#include <utime.h>
#include <sys/wait.h>
#include <signal.h>
#ifdef sun386
/* Things we need to change for sun386i */
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
#include <sys/fcntl.h>
#include <dirent.h>
#include <sys/acct.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <sys/filio.h>
#include <string.h>
#define HAVE_TIMEZONE
#define SIGNAL_CAST (void (*)(int))
#define SYSV
#define REPLACE_STRLEN
#endif

#ifdef SVR4
#include <string.h>
#include <sys/dir.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/filio.h>
#include <fcntl.h>
#include <sys/sockio.h>
#include <termios.h>
#define SYSV
#endif

#ifdef ULTRIX
#include <strings.h>
#include <nfs/nfs_clnt.h>
#include <nfs/vfs.h>
char *getwd(char *);
#define NOSTRDUP
#endif

#ifdef OSF1
#include <strings.h>
#include <dirent.h>
char *getwd(char *);
#endif

#ifdef BSDI

#endif

#ifdef NETBSD
#include <strings.h>
#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif 

struct spwd { /* fake shadow password structure */
       char *sp_pwdp;
};
struct spwd *getspnam(char *username); /* fake shadow password routine */
#endif 


#ifdef FreeBSD
#include <strings.h>
#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif 
#endif 


#ifdef AIX
#include <strings.h>
#include <sys/dir.h>
#include <sys/select.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#define HAVE_TIMEZONE
#endif

#ifdef HPUX
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <sys/types.h>
#define SIGNAL_CAST (void (*)(__harg))
#define SELECT_CAST (int *)
#define HAVE_TIMEZONE
#endif

#ifdef SEQUENT
char *strchr();
char *strrchr();
typedef int mode_t;
#define SEEK_SET 0
#endif

#ifdef NEXT
#include <strings.h>
#include <sys/dir.h>
#include <dirent.h>
#include <sys/vfs.h>
#define bzero(b,len) memset(b,0,len)
#include <libc.h>
#define NOSTRDUP
#endif


#ifdef ISC
#include <sys/stream.h>
#include <net/errno.h>
#include <string.h>
#include <sys/dir.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <sys/sioctl.h>
#include <termio.h>
#define NORECVFROM
#define FIONREAD FIORDCHK
#define SYSV
#define SIGNAL_CAST (void (*)(int))
#endif


#ifdef USE_DIRECT
#include <sys/dir.h>
#endif

#include "version.h"
#include "smb.h"

#ifdef REPLACE_STRLEN
#define strlen(s) Strlen(s)
#endif
