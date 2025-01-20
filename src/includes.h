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

#include "local.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <utime.h>
#include <fcntl.h>

#include <errno.h>
#include <grp.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <string.h>
#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif /* QSORT_CAST */
#define SIGNAL_CAST (void (*)(int))
#define USE_GETCWD
#define USE_SETSID
#define USE_SIGPROCMASK
#define USE_WAITPID

#ifndef FD_SETSIZE
#define FD_SETSIZE 255
#endif

/* xattrs are system-specific: */
#ifdef linux

#include <sys/xattr.h>
#define XATTR_API_LINUX

#elif defined(__FreeBSD__) || defined(__NetBSD__)

#include <sys/extattr.h>
#define XATTR_API_BSD

#else

#define XATTR_API_NONE

#endif

/* some unixes have ENOTTY instead of TIOCNOTTY */
#ifndef TIOCNOTTY
#ifdef ENOTTY
#define TIOCNOTTY ENOTTY
#endif
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#include "smb.h"
#include "version.h"

#include "byteorder.h"

#ifndef MAXCODEPAGELINES
#define MAXCODEPAGELINES 256
#endif

/***** automatically generated prototypes *****/
#include "config.h"
#include "proto.h"

#ifndef EDQUOT
#define EDQUOT ENOSPC
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
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

#ifdef strcpy
#undef strcpy
#endif /* strcpy */
#define strcpy(dest, src) __ERROR__XX__NEVER_USE_STRCPY___;

#ifdef strcat
#undef strcat
#endif /* strcat */
#define strcat(dest, src) __ERROR__XX__NEVER_USE_STRCAT___;

#ifdef sprintf
#undef sprintf
#endif /* sprintf */
#define sprintf __ERROR__XX__NEVER_USE_SPRINTF__;

#define malloc(x)     __ERROR__XX_NEVER_USE_MALLOC__;
#define realloc(x, y) __ERROR__XX_NEVER_USE_REALLOC__;
#define calloc(x, y)  __ERROR__XX_NEVER_USE_CALLOC__;
#define strdup(x)     __ERROR__XX_NEVER_USE_STRDUP__;

#define pstrcpy(d, s) safe_strcpy((d), (s), sizeof(pstring))
#define pstrcat(d, s) safe_strcat((d), (s), sizeof(pstring))
#define fstrcpy(d, s) safe_strcpy((d), (s), sizeof(fstring))
#define fstrcat(d, s) safe_strcat((d), (s), sizeof(fstring))

#define checked_malloc(bytes) checked_realloc(NULL, bytes)

/* TODO: Remove these once their addition to glibc is less recent */
size_t strlcat(char *, const char *, size_t);
size_t strlcpy(char *, const char *, size_t);

#endif
