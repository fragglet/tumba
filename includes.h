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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#ifndef NO_UTIMEH
#include <utime.h>
#endif
#include <sys/types.h>

#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <net/if.h>

#ifdef SYSLOG
#include <syslog.h>
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/vfs.h>
#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif /* QSORT_CAST */
#define SIGNAL_CAST (__sighandler_t)
#define USE_GETCWD
#define USE_SETSID
#define USE_SIGPROCMASK
#define USE_WAITPID

#ifndef FD_SETSIZE
#define FD_SETSIZE 255
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

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#include "smb.h"
#include "version.h"

#include "ubiqx/ubi_dLinkList.h"

#include "byteorder.h"

#include "charset.h"
#include "kanji.h"

#ifndef MAXCODEPAGELINES
#define MAXCODEPAGELINES 256
#endif

/***** automatically generated prototypes *****/
#include "proto.h"

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

#ifndef SIGCLD
#define SIGCLD SIGCHLD
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

#define pstrcpy(d, s) safe_strcpy((d), (s), sizeof(pstring) - 1)
#define pstrcat(d, s) safe_strcat((d), (s), sizeof(pstring) - 1)
#define fstrcpy(d, s) safe_strcpy((d), (s), sizeof(fstring) - 1)
#define fstrcat(d, s) safe_strcat((d), (s), sizeof(fstring) - 1)

#endif
