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
get a users home directory. tries as-is then lower case
****************************************************************************/
char *get_home_dir(char *user)
{
	static struct passwd *pass;

	pass = Get_Pwnam(user, False);

	if (!pass)
		return (NULL);
	return (pass->pw_dir);
}

/*******************************************************************
map a username from a dos name to a unix name by looking in the username
map
********************************************************************/
BOOL map_username(char *user)
{
	static BOOL initialised = False;
	static fstring last_from, last_to;
	FILE *f;
	char *s;
	pstring buf;
	char *mapfile = lp_username_map();
	BOOL mapped_user = False;

	if (!*mapfile)
		return False;

	if (!*user)
		return False;

	if (!initialised) {
		*last_from = *last_to = 0;
		initialised = True;
	}

	if (strequal(user, last_to))
		return False;

	if (strequal(user, last_from)) {
		DEBUG(3, ("Mapped user %s to %s\n", user, last_to));
		fstrcpy(user, last_to);
		return True;
	}

	f = fopen(mapfile, "r");
	if (!f) {
		DEBUG(0, ("can't open username map %s\n", mapfile));
		return False;
	}

	DEBUG(4, ("Scanning username map %s\n", mapfile));

	while ((s = fgets_slash(buf, sizeof(buf), f)) != NULL) {
		char *unixname = s;
		char *dosname = strchr(unixname, '=');
		BOOL return_if_mapped = False;

		if (!dosname)
			continue;
		*dosname++ = 0;

		while (isspace(*unixname))
			unixname++;
		if ('!' == *unixname) {
			return_if_mapped = True;
			unixname++;
			while (*unixname && isspace(*unixname))
				unixname++;
		}

		if (!*unixname || strchr("#;", *unixname))
			continue;

		{
			int l = strlen(unixname);
			while (l && isspace(unixname[l - 1])) {
				unixname[l - 1] = 0;
				l--;
			}
		}

		if (strchr(dosname, '*') || user_in_list(user, dosname)) {
			DEBUG(3, ("Mapped user %s to %s\n", user, unixname));
			mapped_user = True;
			fstrcpy(last_from, user);
			sscanf(unixname, "%s", user);
			fstrcpy(last_to, user);
			if (return_if_mapped) {
				fclose(f);
				return True;
			}
		}
	}

	fclose(f);

	/*
	 * Setup the last_from and last_to as an optimization so
	 * that we don't scan the file again for the same user.
	 */
	fstrcpy(last_from, user);
	fstrcpy(last_to, user);

	return mapped_user;
}

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
	return _Get_Pwnam(lp_guestaccount(-1));
}

/****************************************************************************
check if a user is in a UNIX user list
****************************************************************************/
static BOOL user_in_group_list(char *user, char *gname)
{
	struct group *gptr;
	char **member;
	struct passwd *pass = Get_Pwnam(user, False);

	if (pass) {
		gptr = getgrgid(pass->pw_gid);
		if (gptr && strequal(gptr->gr_name, gname))
			return (True);
	}

	gptr = (struct group *) getgrnam(gname);

	if (gptr) {
		member = gptr->gr_mem;
		while (member && *member) {
			if (strequal(*member, user))
				return (True);
			member++;
		}
	}
	return False;
}

/****************************************************************************
check if a user is in a user list - can check combinations of UNIX
and netgroup lists.
****************************************************************************/
BOOL user_in_list(char *user, char *list)
{
	pstring tok;
	char *p = list;

	while (next_token(&p, tok, LIST_SEP)) {
		/*
		 * Check raw username.
		 */
		if (strequal(user, tok))
			return (True);

		/*
		 * Now check to see if any combination
		 * of UNIX and netgroups has been specified.
		 */

		if (*tok == '@') {
			/*
			 * Old behaviour. Check netgroup list
			 * followed by UNIX list.
			 */
			if (user_in_group_list(user, &tok[1]))
				return True;
		} else if (*tok == '+') {
			if (tok[1] == '&') {
				/*
				 * Search UNIX list followed by netgroup.
				 */
				if (user_in_group_list(user, &tok[2]))
					return True;
			} else {
				/*
				 * Just search UNIX list.
				 */
				if (user_in_group_list(user, &tok[1]))
					return True;
			}
		} else if (*tok == '&') {
			if (tok[1] == '&') {
				/*
				 * Search netgroup list followed by UNIX list.
				 */
				if (user_in_group_list(user, &tok[2]))
					return True;
			}
		}
	}
	return (False);
}
