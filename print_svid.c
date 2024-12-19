/*
 * Copyright (C) 1997-1998 by Norm Jacobs, Colorado Springs, Colorado, USA
 * Copyright (C) 1997-1998 by Sun Microsystem, Inc.
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This module implements support for gathering and comparing available
 * printer information on a SVID or XPG4 compliant system.  It does this
 * through the use of the SVID/XPG4 command "lpstat(1)".
 *
 * The expectations is that execution of the command "lpstat -v" will
 * generate responses in the form of:
 *
 *	device for serial: /dev/term/b
 *	system for fax: server
 *	system for color: server (as printer chroma)
 */


#include "includes.h"
#include "smb.h"

/* this keeps fussy compilers happy */
 void print_svid_dummy(void) {}
