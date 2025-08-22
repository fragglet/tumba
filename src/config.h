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

// This is a boolean that controls whether to strip trailing dots off UNIX
// filenames. This helps with some CDROMs that have filenames ending in a
// single dot.
static inline bool lp_strip_dot(void)
{
	return false;
}
