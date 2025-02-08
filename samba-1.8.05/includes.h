#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <pwd.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <net/if.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <sys/vfs.h>
#define SIGNAL_CAST (__sighandler_t)
#define HAVE_TIMEZONE
#define HAVE_SYSCONF 1
#define USE_GETCWD

#include "smb.h"
#include "version.h"

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
