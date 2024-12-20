/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
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
extern int Protocol;

/* users from session setup */
static pstring session_users = "";

/* Data to do lanman1/2 password challenge. */
static unsigned char saved_challenge[8];
static BOOL challenge_sent = False;

/*******************************************************************
Get the next challenge value - no repeats.
********************************************************************/
void generate_next_challenge(char *challenge)
{
	unsigned char buf[16];
	static int counter = 0;
	struct timeval tval;
	int v1, v2;

	/* get a sort-of random number */
	GetTimeOfDay(&tval);
	v1 = (counter++) + getpid() + tval.tv_sec;
	v2 = (counter++) * getpid() + tval.tv_usec;
	SIVAL(challenge, 0, v1);
	SIVAL(challenge, 4, v2);

	/* mash it up with md4 */
	mdfour(buf, (unsigned char *) challenge, 8);

	memcpy(saved_challenge, buf, 8);
	memcpy(challenge, buf, 8);
	challenge_sent = True;
}

/*******************************************************************
set the last challenge sent, usually from a password server
********************************************************************/
BOOL set_challenge(char *challenge)
{
	memcpy(saved_challenge, challenge, 8);
	challenge_sent = True;
	return (True);
}

/* this holds info on user ids that are already validated for this VC */
static user_struct *validated_users = NULL;
static int num_validated_users = 0;

/****************************************************************************
check if a uid has been validated, and return an pointer to the user_struct
if it has. NULL if not. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
user_struct *get_valid_user_struct(uint16 vuid)
{
	if (vuid == UID_FIELD_INVALID)
		return NULL;
	vuid -= VUID_OFFSET;
	if ((vuid >= (uint16) num_validated_users) ||
	    (validated_users[vuid].uid == -1) ||
	    (validated_users[vuid].gid == -1))
		return NULL;
	return &validated_users[vuid];
}

/****************************************************************************
invalidate a uid
****************************************************************************/
void invalidate_vuid(uint16 vuid)
{
	user_struct *vuser = get_valid_user_struct(vuid);

	if (vuser == NULL)
		return;

	vuser->uid = -1;
	vuser->gid = -1;

	vuser->n_sids = 0;

	/* same number of igroups as groups as attrs */
	vuser->n_groups = 0;

	if (vuser->groups && (vuser->groups != (gid_t *) vuser->igroups))
		free(vuser->groups);

	if (vuser->igroups)
		free(vuser->igroups);
	if (vuser->attrs)
		free(vuser->attrs);
	if (vuser->sids)
		free(vuser->sids);

	vuser->attrs = NULL;
	vuser->sids = NULL;
	vuser->igroups = NULL;
	vuser->groups = NULL;
}

/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given. vuid is biased by an offset. This allows us to
tell random client vuid's (normally zero) from valid vuids.
****************************************************************************/
uint16 register_vuid(int uid, int gid, char *unix_name, char *requested_name,
                     BOOL guest)
{
	return UID_FIELD_INVALID;
}

/****************************************************************************
add a name to the session users list
****************************************************************************/
void add_session_user(char *user)
{
	fstring suser;
	StrnCpy(suser, user, sizeof(suser) - 1);

	if (!Get_Pwnam(suser, True))
		return;

	if (suser && *suser && !in_list(suser, session_users, False)) {
		if (strlen(suser) + strlen(session_users) + 2 >=
		    sizeof(pstring))
			DEBUG(1, ("Too many session users??\n"));
		else {
			pstrcat(session_users, " ");
			pstrcat(session_users, suser);
		}
	}
}

/****************************************************************************
read the a hosts.equiv or .rhosts file and check if it
allows this user from this machine
****************************************************************************/
static BOOL check_user_equiv(char *user, char *remote, char *equiv_file)
{
	pstring buf;
	int plus_allowed = 1;
	char *file_host;
	char *file_user;
	FILE *fp = fopen(equiv_file, "r");
	DEBUG(5, ("check_user_equiv %s %s %s\n", user, remote, equiv_file));
	if (!fp)
		return False;
	while (fgets(buf, sizeof(buf), fp)) {
		trim_string(buf, " ", " ");

		if (buf[0] != '#' && buf[0] != '\n') {
			BOOL is_group = False;
			int plus = 1;
			char *bp = buf;
			if (strcmp(buf, "NO_PLUS\n") == 0) {
				DEBUG(6, ("check_user_equiv NO_PLUS\n"));
				plus_allowed = 0;
			} else {
				if (buf[0] == '+') {
					bp++;
					if (*bp == '\n' && plus_allowed) {
						/* a bare plus means everbody
						 * allowed */
						DEBUG(6,
						      ("check_user_equiv "
						       "everybody allowed\n"));
						fclose(fp);
						return True;
					}
				} else if (buf[0] == '-') {
					bp++;
					plus = 0;
				}
				if (*bp == '@') {
					is_group = True;
					bp++;
				}
				file_host = strtok(bp, " \t\n");
				file_user = strtok(NULL, " \t\n");
				DEBUG(7, ("check_user_equiv %s %s\n",
				          file_host ? file_host : "(null)",
				          file_user ? file_user : "(null)"));
				if (file_host && *file_host) {
					BOOL host_ok = False;

					if (is_group) {
						DEBUG(
						    1,
						    ("Netgroups not configured "
						     "- add -DNETGROUP and "
						     "recompile\n"));
						continue;
					}

					/* is it this host */
					/* the fact that remote has come from a
					 * call of gethostbyaddr means that it
					 * may have the fully qualified domain
					 * name so we could look up the file
					 * version to get it into a canonical
					 * form, but I would rather just type it
					 * in full in the equiv file
					 */
					if (!host_ok && !is_group &&
					    strequal(remote, file_host))
						host_ok = True;

					if (!host_ok)
						continue;

					/* is it this user */
					if (file_user == 0 ||
					    strequal(user, file_user)) {
						fclose(fp);
						DEBUG(5, ("check_user_equiv "
						          "matched %s%s %s\n",
						          (plus ? "+" : "-"),
						          file_host,
						          (file_user ? file_user
						                     : "")));
						return (plus ? True : False);
					}
				}
			}
		}
	}
	fclose(fp);
	return False;
}

/****************************************************************************
check for a possible hosts equiv or rhosts entry for the user
****************************************************************************/
BOOL check_hosts_equiv(char *user)
{
	char *fname = NULL;
	pstring rhostsfile;
	struct passwd *pass = Get_Pwnam(user, True);

	if (!pass)
		return (False);

	fname = lp_hosts_equiv();

	/* note: don't allow hosts.equiv on root */
	if (fname && *fname && (pass->pw_uid != 0)) {
		if (check_user_equiv(user, client_name(), fname))
			return (True);
	}

	if (lp_use_rhosts()) {
		char *home = get_home_dir(user);
		if (home) {
			slprintf(rhostsfile, sizeof(rhostsfile) - 1,
			         "%s/.rhosts", home);
			if (check_user_equiv(user, client_name(), rhostsfile))
				return (True);
		}
	}

	return (False);
}

static struct cli_state cli;

/****************************************************************************
return the client state structure
****************************************************************************/
struct cli_state *server_client(void)
{
	return &cli;
}
