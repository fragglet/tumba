#include "local.h"
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

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
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/acct.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <utime.h>
#ifndef strerror
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif
#endif

#ifdef OSF1
#include <dirent.h>
#include <strings.h>
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
#include <dirent.h>
#include <strings.h>
#include <sys/dir.h>
#include <sys/select.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#define HAVE_TIMEZONE
#endif

#ifdef SEQUENT
char *strchr();
char *strrchr();
typedef int mode_t;
#define SEEK_SET 0
#endif

#ifdef USE_DIRECT
#include <sys/dir.h>
#endif

#include "smb.h"
#include "version.h"

#ifdef REPLACE_STRLEN
#define strlen(s) Strlen(s)
#endif
