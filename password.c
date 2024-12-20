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
	user_struct *vuser;
	struct passwd *pwfile; /* for getting real name from passwd file */

	/* Ensure no vuid gets registered in share level security. */
	if (lp_security() == SEC_SHARE)
		return UID_FIELD_INVALID;

#if 0
  /*
   * After observing MS-Exchange services writing to a Samba share
   * I belive this code is incorrect. Each service does its own
   * sessionsetup_and_X for the same user, and as each service shuts
   * down, it does a user_logoff_and_X. As we are consolidating multiple
   * sessionsetup_and_X's onto the same vuid here, when the first service
   * shuts down, it invalidates all the open files for the other services.
   * Hence I am removing this code and forcing each sessionsetup_and_X
   * to get a new vuid.
   * Jeremy Allison. (jallison@whistle.com).
   */

  int i;
  for(i = 0; i < num_validated_users; i++) {
    vuser = &validated_users[i];
    if ( vuser->uid == uid )
      return (uint16)(i + VUID_OFFSET); /* User already validated */
  }
#endif

	validated_users = (user_struct *) Realloc(
	    validated_users, sizeof(user_struct) * (num_validated_users + 1));

	if (!validated_users) {
		DEBUG(0, ("Failed to realloc users struct!\n"));
		num_validated_users = 0;
		return UID_FIELD_INVALID;
	}

	vuser = &validated_users[num_validated_users];
	num_validated_users++;

	vuser->uid = uid;
	vuser->gid = gid;
	vuser->guest = guest;
	fstrcpy(vuser->name, unix_name);
	fstrcpy(vuser->requested_name, requested_name);

	vuser->n_sids = 0;
	vuser->sids = NULL;

	vuser->n_groups = 0;
	vuser->groups = NULL;
	vuser->igroups = NULL;
	vuser->attrs = NULL;

	/* Find all the groups this uid is in and store them.
	   Used by become_user() */
	setup_groups(unix_name, uid, gid, &vuser->n_groups, &vuser->igroups,
	             &vuser->groups, &vuser->attrs);

	DEBUG(3, ("uid %d registered to name %s\n", uid, unix_name));

	DEBUG(3, ("Clearing default real name\n"));
	fstrcpy(vuser->real_name, "<Full Name>\0");
	if (lp_unix_realname()) {
		if ((pwfile = getpwnam(vuser->name)) != NULL) {
			DEBUG(3, ("User name: %s\tReal name: %s\n", vuser->name,
			          pwfile->pw_gecos));
			fstrcpy(vuser->real_name, pwfile->pw_gecos);
		}
	}

	return (uint16) ((num_validated_users - 1) + VUID_OFFSET);
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
check if a username/password is OK
****************************************************************************/
BOOL password_ok(char *user, char *password, int pwlen, struct passwd *pwd)
{
	return (True);
}

/****************************************************************************
check if a username is valid
****************************************************************************/
BOOL user_ok(char *user, int snum)
{
	return True;
}

/****************************************************************************
validate a group username entry. Return the username or NULL
****************************************************************************/
static char *validate_group(char *group, char *password, int pwlen, int snum)
{
#ifdef NETGROUP
	{
		char *host, *user, *domain;
		setnetgrent(group);
		while (getnetgrent(&host, &user, &domain)) {
			if (user) {
				if (user_ok(user, snum) &&
				    password_ok(user, password, pwlen, NULL)) {
					endnetgrent();
					return (user);
				}
			}
		}
		endnetgrent();
	}
#endif

	{
		struct group *gptr = (struct group *) getgrnam(group);
		char **member;
		if (gptr) {
			member = gptr->gr_mem;
			while (member && *member) {
				static fstring name;
				fstrcpy(name, *member);
				if (user_ok(name, snum) &&
				    password_ok(name, password, pwlen, NULL))
					return (&name[0]);
				member++;
			}
#ifdef GROUP_CHECK_PWENT
			{
				struct passwd *pwd;
				static fstring tm;

				setpwent();
				while (pwd = getpwent()) {
					if (*(pwd->pw_passwd) &&
					    pwd->pw_gid == gptr->gr_gid) {
						/* This Entry have PASSWORD and
						 * same GID then check pwd */
						if (password_ok(NULL, password,
						                pwlen, pwd)) {
							fstrcpy(tm,
							        pwd->pw_name);
							endpwent();
							return tm;
						}
					}
				}
				endpwent();
			}
#endif /* GROUP_CHECK_PWENT */
		}
	}
	return (NULL);
}

/****************************************************************************
check for authority to login to a service with a given username/password
****************************************************************************/
BOOL authorise_login(int snum, char *user, char *password, int pwlen,
                     BOOL *guest, BOOL *force, uint16 vuid)
{
	BOOL ok = False;

#if DEBUG_PASSWORD
	DEBUG(100,
	      ("checking authorisation on user=%s pass=%s\n", user, password));
#endif

	/* we only support guest */
	{
		fstring guestname;
		StrnCpy(guestname, lp_guestaccount(snum),
		        sizeof(guestname) - 1);
		if (Get_Pwnam(guestname, True)) {
			pstrcpy(user, guestname);
			ok = True;
			DEBUG(3, ("ACCEPTED: guest account and guest ok\n"));
		} else
			DEBUG(0, ("Invalid guest account %s??\n", guestname));
		*guest = True;
		*force = True;
	}

	if (ok && !user_ok(user, snum)) {
		DEBUG(0, ("rejected invalid user %s\n", user));
		ok = False;
	}

	return (ok);
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

#ifdef NETGROUP
					if (is_group) {
						static char *mydomain = NULL;
						if (!mydomain)
							yp_get_default_domain(
							    &mydomain);
						if (mydomain &&
						    innetgr(file_host, remote,
						            user, mydomain))
							host_ok = True;
					}
#else
					if (is_group) {
						DEBUG(
						    1,
						    ("Netgroups not configured "
						     "- add -DNETGROUP and "
						     "recompile\n"));
						continue;
					}
#endif

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

/****************************************************************************
support for server level security
****************************************************************************/
struct cli_state *server_cryptkey(void)
{
	fstring desthost;
	struct in_addr dest_ip;
	extern fstring local_machine;
	char *p;

	if (!cli_initialise(&cli))
		return NULL;

	for (p = strtok(lp_passwordserver(), LIST_SEP); p;
	     p = strtok(NULL, LIST_SEP)) {
		fstrcpy(desthost, p);
		standard_sub_basic(desthost);
		strupper(desthost);

		if (!resolve_name(desthost, &dest_ip)) {
			DEBUG(
			    1,
			    ("server_cryptkey: Can't resolve address for %s\n",
			     p));
			continue;
		}

		if (ismyip(dest_ip)) {
			DEBUG(1, ("Password server loop - disabling password "
			          "server %s\n",
			          p));
			continue;
		}

		if (cli_connect(&cli, desthost, &dest_ip)) {
			DEBUG(3, ("connected to password server %s\n", p));
			break;
		}
	}

	if (!p) {
		DEBUG(1, ("password server not available\n"));
		cli_shutdown(&cli);
		return NULL;
	}

	if (!cli_session_request(&cli, desthost, 0x20, local_machine)) {
		DEBUG(1, ("%s rejected the session\n", desthost));
		cli_shutdown(&cli);
		return NULL;
	}

	DEBUG(3, ("got session\n"));

	if (!cli_negprot(&cli)) {
		DEBUG(1, ("%s rejected the negprot\n", desthost));
		cli_shutdown(&cli);
		return NULL;
	}

	if (cli.protocol < PROTOCOL_LANMAN2 || !(cli.sec_mode & 1)) {
		DEBUG(1, ("%s isn't in user level security mode\n", desthost));
		cli_shutdown(&cli);
		return NULL;
	}

	DEBUG(3, ("password server OK\n"));

	return &cli;
}

/****************************************************************************
validate a password with the password server
****************************************************************************/
BOOL server_validate(char *user, char *domain, char *pass, int passlen,
                     char *ntpass, int ntpasslen)
{
	extern fstring local_machine;
	static unsigned char badpass[24];

	if (!cli.initialised) {
		DEBUG(1,
		      ("password server %s is not connected\n", cli.desthost));
		return (False);
	}

	if (badpass[0] == 0) {
		memset(badpass, 0x1f, sizeof(badpass));
	}

	if ((passlen == sizeof(badpass)) && !memcmp(badpass, pass, passlen)) {
		/* Very unlikely, our random bad password is the same as the
		   users password. */
		memset(badpass, badpass[0] + 1, sizeof(badpass));
	}

	/*
	 * Attempt a session setup with a totally incorrect password.
	 * If this succeeds with the guest bit *NOT* set then the password
	 * server is broken and is not correctly setting the guest bit. We
	 * need to detect this as some versions of NT4.x are broken. JRA.
	 */

	if (cli_session_setup(&cli, user, (char *) badpass, sizeof(badpass),
	                      (char *) badpass, sizeof(badpass), domain)) {
		if ((SVAL(cli.inbuf, smb_vwv2) & 1) == 0) {
			DEBUG(
			    0,
			    ("server_validate: password server %s allows users as non-guest \
with a bad password.\n",
			     cli.desthost));
			DEBUG(
			    0,
			    ("server_validate: This is broken (and insecure) behaviour. Please do not \
use this machine as the password server.\n"));
			cli_ulogoff(&cli);
			return False;
		}
		cli_ulogoff(&cli);
	}

	/*
	 * Now we know the password server will correctly set the guest bit, or
	 * is not guest enabled, we can try with the real password.
	 */

	if (!cli_session_setup(&cli, user, pass, passlen, ntpass, ntpasslen,
	                       domain)) {
		DEBUG(1, ("password server %s rejected the password\n",
		          cli.desthost));
		return False;
	}

	/* if logged in as guest then reject */
	if ((SVAL(cli.inbuf, smb_vwv2) & 1) != 0) {
		DEBUG(0, ("password server %s gave us guest only\n",
		          cli.desthost));
		return (False);
	}

	/*
	 * This patch from Rob Nielsen <ran@adc.com> makes doing
	 * the NetWksaUserLogon a dynamic, rather than compile-time
	 * parameter, defaulting to on. This is somewhat dangerous
	 * as it allows people to turn off this neccessary check,
	 * but so many people have had problems with this that I
	 * think it is a neccessary change. JRA.
	 */

	if (lp_net_wksta_user_logon()) {
		DEBUG(3, ("trying NetWkstaUserLogon with password server %s\n",
		          cli.desthost));
		if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
			DEBUG(0, ("password server %s refused IPC$ connect\n",
			          cli.desthost));
			return False;
		}

		if (!cli_NetWkstaUserLogon(&cli, user, local_machine)) {
			DEBUG(0,
			      ("password server %s failed NetWkstaUserLogon\n",
			       cli.desthost));
			cli_tdis(&cli);
			return False;
		}

		if (cli.privilages == 0) {
			DEBUG(0, ("password server %s gave guest privilages\n",
			          cli.desthost));
			cli_tdis(&cli);
			return False;
		}

		if (!strequal(cli.eff_name, user)) {
			DEBUG(
			    0,
			    ("password server %s gave different username %s\n",
			     cli.desthost, cli.eff_name));
			cli_tdis(&cli);
			return False;
		}
		cli_tdis(&cli);
	} else {
		DEBUG(3,
		      ("skipping NetWkstaUserLogon with password server %s\n",
		       cli.desthost));
	}

	DEBUG(3, ("password server %s accepted the password\n", cli.desthost));

	cli_ulogoff(&cli);

	return (True);
}
