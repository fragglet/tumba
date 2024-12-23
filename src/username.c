/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Username handling
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

#include "includes.h"
extern int DEBUGLEVEL;

/****************************************************************************
internals of Get_Pwnam wrapper
****************************************************************************/
static struct passwd *_Get_Pwnam(char *s)
{
	struct passwd *ret;

	ret = getpwnam(s);
	if (ret) {
#ifdef GETPWANAM
		struct passwd_adjunct *pwret;
		pwret = getpwanam(s);
		if (pwret) {
			free(ret->pw_passwd);
			ret->pw_passwd = pwret->pwa_passwd;
		}
#endif
	}

	return (ret);
}

/****************************************************************************
a wrapper for getpwnam() that tries with all lower and all upper case
if the initial name fails. Also tried with first letter capitalised
Note that this changes user!
****************************************************************************/
struct passwd *Get_Pwnam(char *user, BOOL allow_change)
{
	return _Get_Pwnam(user);
}
