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

#endif
