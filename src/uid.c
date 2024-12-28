/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   uid/user handling
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

static int initial_uid;
static int initial_gid;

/* what user is current? */
struct current_user current_user;

pstring OriginalDir;

/****************************************************************************
initialise the uid routines
****************************************************************************/
void init_uid(void)
{
	initial_uid = current_user.uid = geteuid();
	initial_gid = current_user.gid = getegid();

	if (initial_gid != 0 && initial_uid == 0) {
		setgid(0);
		setegid(0);
	}

	initial_uid = geteuid();
	initial_gid = getegid();

	current_user.cnum = -1;

	chdir(OriginalDir);
}

/****************************************************************************
  become the specified uid
****************************************************************************/
static bool become_uid(int uid)
{
	if (initial_uid != 0)
		return (true);

	if (uid == -1 || uid == 65535) {
		DEBUG(1, ("WARNING: using uid %d is a security risk\n", uid));
	}

#ifdef USE_SETRES
	if (setresuid(-1, uid, -1) != 0)
#elif defined(USE_SETFS)
	if (setfsuid(uid) != 0)
#else
	if ((seteuid(uid) != 0) && (setuid(uid) != 0))
#endif
	{
		DEBUG(0, ("Couldn't set uid %d currently set to (%d,%d)\n", uid,
		          getuid(), geteuid()));
		if (uid > 32000)
			DEBUG(0, ("Looks like your OS doesn't like high uid "
			          "values - try using a different account\n"));
		return (false);
	}

	if (((uid == -1) || (uid == 65535)) && geteuid() != uid) {
		DEBUG(0, ("Invalid uid -1. perhaps you have a account with uid "
		          "65535?\n"));
		return (false);
	}

	current_user.uid = uid;

	return (true);
}

/****************************************************************************
  become the specified gid
****************************************************************************/
static bool become_gid(int gid)
{
	if (initial_uid != 0)
		return (true);

	if (gid == -1 || gid == 65535) {
		DEBUG(1, ("WARNING: using gid %d is a security risk\n", gid));
	}

#ifdef USE_SETRES
	if (setresgid(-1, gid, -1) != 0)
#elif defined(USE_SETFS)
	if (setfsgid(gid) != 0)
#else
	if (setgid(gid) != 0)
#endif
	{
		DEBUG(0, ("Couldn't set gid %d currently set to (%d,%d)\n", gid,
		          getgid(), getegid()));
		if (gid > 32000)
			DEBUG(0, ("Looks like your OS doesn't like high gid "
			          "values - try using a different account\n"));
		return (false);
	}

	current_user.gid = gid;

	return (true);
}

/****************************************************************************
  become the specified uid and gid
****************************************************************************/
static bool become_id(int uid, int gid)
{
	return (become_gid(gid) && become_uid(uid));
}

/****************************************************************************
become the guest user
****************************************************************************/
bool become_guest(void)
{
	bool ret;
	static struct passwd *pass = NULL;

	if (initial_uid != 0)
		return (true);

	if (!pass)
		pass = Get_Pwnam(lp_guestaccount(-1), true);
	if (!pass)
		return (false);

	ret = become_id(pass->pw_uid, pass->pw_gid);

	if (!ret)
		DEBUG(1, ("Failed to become guest. Invalid guest account?\n"));

	current_user.cnum = -2;

	return (ret);
}

/****************************************************************************
  become the user of a connection number
****************************************************************************/
bool become_user(connection_struct *conn, int cnum)
{
	int gid;
	int uid;

	if ((current_user.cnum == cnum) && (current_user.uid == conn->uid)) {
		DEBUG(4, ("Skipping become_user - already user\n"));
		return (true);
	}

	unbecome_user();

	if (!(VALID_CNUM(cnum) && conn->open)) {
		DEBUG(2, ("Connection %d not open\n", cnum));
		return (false);
	}

	{
		uid = conn->uid;
		gid = conn->gid;
	}

	if (initial_uid == 0) {
		if (!become_gid(gid))
			return (false);

		if (!become_uid(uid))
			return (false);
	}

	current_user.cnum = cnum;

	DEBUG(5, ("become_user uid=(%d,%d) gid=(%d,%d)\n", getuid(), geteuid(),
	          getgid(), getegid()));

	return (true);
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
bool unbecome_user(void)
{
	if (current_user.cnum == -1)
		return (false);

	chdir(OriginalDir);

	if (initial_uid == 0) {
		if (seteuid(initial_uid) != 0)
			setuid(initial_uid);
		setgid(initial_gid);
	}
	if (geteuid() != initial_uid) {
		DEBUG(0,
		      ("Warning: You appear to have a trapdoor uid system\n"));
		initial_uid = geteuid();
	}
	if (getegid() != initial_gid) {
		DEBUG(0,
		      ("Warning: You appear to have a trapdoor gid system\n"));
		initial_gid = getegid();
	}

	current_user.uid = initial_uid;
	current_user.gid = initial_gid;

	if (chdir(OriginalDir) != 0)
		DEBUG(0, ("%s chdir(%s) failed in unbecome_user\n",
		          timestring(), OriginalDir));

	DEBUG(5, ("unbecome_user now uid=(%d,%d) gid=(%d,%d)\n", getuid(),
	          geteuid(), getgid(), getegid()));

	current_user.cnum = -1;

	return (true);
}
