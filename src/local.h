/* Copyright (C) 1995-1998 Samba-Team */
/* Copyright (C) 1998 John H Terpstra <jht@aquasoft.com.au> */

/* local definitions for file server */
#ifndef _LOCAL_H
#define _LOCAL_H

/* define what facility to use for syslog */
#ifndef SYSLOG_FACILITY
#define SYSLOG_FACILITY LOG_DAEMON
#endif

/* set these to define the limits of the server. NOTE These are on a
   per-client basis. Thus any one machine can't connect to more than
   MAX_CONNECTIONS services, but any number of machines may connect at
   one time. */
#define MAX_CONNECTIONS 127
#define MAX_OPEN_FILES  100

/* max number of directories open at once */
/* note that with the new directory code this no longer requires a
   file handle per directory, but large numbers do use more memory */
#define MAXDIR 64

/* shall filenames with illegal chars in them get mangled in long
   filename listings? */
#define MANGLE_LONG_FILENAMES

/* define this if you want to stop spoofing with .. and soft links
   NOTE: This also slows down the server considerably */
#define REDUCE_PATHS

/* the size of the directory cache */
#define DIRCACHESIZE 20

/* what type of filesystem do we want this to show up as in a NT file
   manager window? */
#define FSTYPE_STRING "Samba"

/* do you want smbd to send a 1 byte packet to nmbd to trigger it to start
   when smbd starts? */
#ifndef PRIME_NMBD
#define PRIME_NMBD 1
#endif

/* the following control timings of various actions. Don't change
   them unless you know what you are doing. These are all in seconds */
#define DEFAULT_SMBD_TIMEOUT  (60 * 60 * 24 * 7)
#define IDLE_CLOSED_TIMEOUT   (60)
#define DPTR_IDLE_TIMEOUT     (120)
#define SMBD_SELECT_LOOP      (10)
#define REGISTRATION_INTERVAL (10 * 60)

/* the following are in milliseconds */
#define LOCK_RETRY_TIMEOUT (100)

#define SMB_ALIGNMENT 1

#endif
