/*
 * Copyright (c) 1992-1998 Andrew Tridgell
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "version.h"

// The following were config options, but have been replaced with inline
// functions that return constants. The function comments are from the manpage
// for smb.conf.

// This options allows you to override the name of the Samba log file (also
// known as the debug file).
static inline char *lp_logfile(void)
{
	return "";
}

// This controls what string will show up in the printer comment box in print
// manager and next to the IPC connection in "net view".
static inline char *lp_serverstring(void)
{
	return "Rumba " VERSION;
}

// This parameter controls whether or not the server will support raw reads
// when transferring data to clients.
static inline bool lp_readraw(void)
{
	return true;
}

// This parameter controls whether or not the server will support raw writes
// when transferring data from clients.
static inline bool lp_writeraw(void)
{
	return true;
}

// This is a boolean that controls whether to strip trailing dots off UNIX
// filenames. This helps with some CDROMs that have filenames ending in a
// single dot.
static inline bool lp_strip_dot(void)
{
	return false;
}

// This option controls the maximum packet size that will be negotiated by
// Samba. The default is 65535, which is the maximum.
static inline int lp_maxxmit(void)
{
	return 65535;
}

// The option "read size" affects the overlap of disk reads/writes with network
// reads/writes.
static inline int lp_readsize(void)
{
	return 16 * 1024;
}
