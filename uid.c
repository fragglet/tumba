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
	current_user.vuid = UID_FIELD_INVALID;

	ChDir(OriginalDir);
}

/****************************************************************************
  become the specified uid
****************************************************************************/
static BOOL become_uid(int uid)
{
	if (initial_uid != 0)
		return (True);

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
		return (False);
	}

	if (((uid == -1) || (uid == 65535)) && geteuid() != uid) {
		DEBUG(0, ("Invalid uid -1. perhaps you have a account with uid "
		          "65535?\n"));
		return (False);
	}

	current_user.uid = uid;

	return (True);
}

/****************************************************************************
  become the specified gid
****************************************************************************/
static BOOL become_gid(int gid)
{
	if (initial_uid != 0)
		return (True);

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
		return (False);
	}

	current_user.gid = gid;

	return (True);
}

/****************************************************************************
  become the specified uid and gid
****************************************************************************/
static BOOL become_id(int uid, int gid)
{
	return (become_gid(gid) && become_uid(uid));
}

/****************************************************************************
become the guest user
****************************************************************************/
BOOL become_guest(void)
{
	BOOL ret;
	static struct passwd *pass = NULL;

	if (initial_uid != 0)
		return (True);

	if (!pass)
		pass = Get_Pwnam(lp_guestaccount(-1), True);
	if (!pass)
		return (False);

	ret = become_id(pass->pw_uid, pass->pw_gid);

	if (!ret)
		DEBUG(1, ("Failed to become guest. Invalid guest account?\n"));

	current_user.cnum = -2;
	current_user.vuid = UID_FIELD_INVALID;

	return (ret);
}

/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_user(connection_struct *conn, int cnum, uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);
	int snum, gid;
	int uid;

	/*
	 * We need a separate check in security=share mode due to vuid
	 * always being UID_FIELD_INVALID. If we don't do this then
	 * in share mode security we are *always* changing uid's between
	 * SMB's - this hurts performance - Badly.
	 */

	if ((current_user.cnum == cnum) &&
	    (current_user.uid == conn->uid)) {
		DEBUG(4, ("Skipping become_user - already user\n"));
		return (True);
	} else if ((current_user.cnum == cnum) && (vuser != 0) &&
	           (current_user.vuid == vuid) &&
	           (current_user.uid == vuser->uid)) {
		DEBUG(4, ("Skipping become_user - already user\n"));
		return (True);
	}

	unbecome_user();

	if (!(VALID_CNUM(cnum) && conn->open)) {
		DEBUG(2, ("Connection %d not open\n", cnum));
		return (False);
	}

	snum = conn->service;

	{
		uid = conn->uid;
		gid = conn->gid;
		current_user.groups = conn->groups;
		current_user.igroups = conn->igroups;
		current_user.ngroups = conn->ngroups;
		current_user.attrs = conn->attrs;
	}

	if (initial_uid == 0) {
		if (!become_gid(gid))
			return (False);

		if (!become_uid(uid))
			return (False);
	}

	current_user.cnum = cnum;
	current_user.vuid = vuid;

	DEBUG(5, ("become_user uid=(%d,%d) gid=(%d,%d)\n", getuid(), geteuid(),
	          getgid(), getegid()));

	return (True);
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
BOOL unbecome_user(void)
{
	if (current_user.cnum == -1)
		return (False);

	ChDir(OriginalDir);

	if (initial_uid == 0) {
#ifdef USE_SETRES
		setresuid(-1, getuid(), -1);
		setresgid(-1, getgid(), -1);
#elif defined(USE_SETFS)
		setfsuid(initial_uid);
		setfsgid(initial_gid);
#else
		if (seteuid(initial_uid) != 0)
			setuid(initial_uid);
		setgid(initial_gid);
#endif
	}
#ifdef NO_EID
	if (initial_uid == 0)
		DEBUG(2, ("Running with no EID\n"));
	initial_uid = getuid();
	initial_gid = getgid();
#else
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
#endif

	current_user.uid = initial_uid;
	current_user.gid = initial_gid;

	if (ChDir(OriginalDir) != 0)
		DEBUG(0, ("%s chdir(%s) failed in unbecome_user\n",
		          timestring(), OriginalDir));

	DEBUG(5, ("unbecome_user now uid=(%d,%d) gid=(%d,%d)\n", getuid(),
	          geteuid(), getgid(), getegid()));

	current_user.cnum = -1;
	current_user.vuid = UID_FIELD_INVALID;

	return (True);
}

static struct current_user current_user_saved;
static int become_root_depth;
static pstring become_root_dir;

/****************************************************************************
This is used when we need to do a privilaged operation (such as mucking
with share mode files) and temporarily need root access to do it. This
call should always be paired with an unbecome_root() call immediately
after the operation

Set save_dir if you also need to save/restore the CWD
****************************************************************************/
void become_root(BOOL save_dir)
{
	if (become_root_depth) {
		DEBUG(0, ("ERROR: become root depth is non zero\n"));
	}
	if (save_dir)
		GetWd(become_root_dir);

	current_user_saved = current_user;
	become_root_depth = 1;

	become_uid(0);
	become_gid(0);
}

/****************************************************************************
When the privilaged operation is over call this

Set save_dir if you also need to save/restore the CWD
****************************************************************************/
void unbecome_root(BOOL restore_dir)
{
	if (become_root_depth != 1) {
		DEBUG(0, ("ERROR: unbecome root depth is %d\n",
		          become_root_depth));
	}

	/* we might have done a become_user() while running as root,
	   if we have then become root again in order to become
	   non root! */
	if (current_user.uid != 0) {
		become_uid(0);
	}

	/* restore our gid first */
	if (!become_gid(current_user_saved.gid)) {
		DEBUG(0, ("ERROR: Failed to restore gid\n"));
		exit_server("Failed to restore gid");
	}

#ifndef NO_SETGROUPS
	if (current_user_saved.ngroups > 0) {
		if (setgroups(current_user_saved.ngroups,
		              current_user_saved.groups) < 0)
			DEBUG(0, ("ERROR: setgroups call failed!\n"));
	}
#endif

	/* now restore our uid */
	if (!become_uid(current_user_saved.uid)) {
		DEBUG(0, ("ERROR: Failed to restore uid\n"));
		exit_server("Failed to restore uid");
	}

	if (restore_dir)
		ChDir(become_root_dir);

	current_user = current_user_saved;

	become_root_depth = 0;
}
