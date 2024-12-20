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
