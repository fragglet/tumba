/* local definitions for file server */
#ifndef _LOCAL_H
#define _LOCAL_H

/* This defines the section name in the configuration file that will contain */
/* global parameters - that is, parameters relating to the whole server, not */
/* just services. This name is then reserved, and may not be used as a       */
/* a service name. It will default to "global" if not defined here.          */
#define GLOBAL_NAME "global"

/* set these to define the limits of the server. NOTE These are on a
   per-client basis. Thus any one machine can't connect to more than
   MAX_CONNECTIONS services, but any number of machines may connect at
   one time. */
#define MAX_CONNECTIONS 25
#define MAX_OPEN_FILES 50

/* max number of directories open at once */
#define MAXDIR 20

/* we need a suitable unsigned 2 byte and 1 byte int  */
#define WORD unsigned short
#ifndef BYTE
#define BYTE unsigned char
#endif

#define WORDMAX 0xFFFF


/* define this if you want to stop spoofing with .. and soft links
   NOTE: This also slows down the server considerably */
#define REDUCE_PATHS

/* define this to replace the string functions with debugging ones */
/* #define STRING_DEBUG */


#endif
