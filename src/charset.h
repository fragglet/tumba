/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set handling
   Copyright (C) Andrew Tridgell 1992-1998

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

#ifndef CHARSET_C

extern void add_char_string(char *s);
extern void charset_initialise(void);

/* this is used to determine if a character is safe to use in
   something that may be put on a command line */
#define issafe(c) (isalnum((c & 0xff)) || strchr("-._", c))
#endif

/* Dynamic codepage files defines. */

/* Version id for dynamically loadable codepage files. */
#define CODEPAGE_FILE_VERSION_ID 0x1
/* Version 1 codepage file header size. */
#define CODEPAGE_HEADER_SIZE 8
/* Offsets for codepage file header entries. */
#define CODEPAGE_VERSION_OFFSET 0
#define CODEPAGE_CLIENT_CODEPAGE_OFFSET 2
#define CODEPAGE_LENGTH_OFFSET 4
