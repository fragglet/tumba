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
