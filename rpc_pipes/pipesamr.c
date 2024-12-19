
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "../includes.h"
#include "../trans2.h"
#include "../nterr.h"

extern int DEBUGLEVEL;

#ifdef NTDOMAIN

/*******************************************************************
 samr_reply_unknown_1
 ********************************************************************/
static int samr_reply_close(SAMR_Q_CLOSE *q_u,
				char *q, char *base)
{
	SAMR_R_CLOSE r_u;

	/* set up the SAMR unknown_1 response */
	bzero(&(r_u.pol.data), POL_HND_SIZE);

	/* close the policy handle */
	if (close_lsa_policy_hnd(&(q_u->pol)))
	{
		r_u.status = 0;
	}
	else
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_INVALID;
	}

	DEBUG(5,("samr_unknown_1: %d\n", __LINE__));

	/* store the response in the SMB stream */
	q = samr_io_r_close(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_unknown_1: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_close
 ********************************************************************/
static void api_samr_close( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SAMR_Q_CLOSE q_u;

	/* grab the samr unknown 1 */
	samr_io_q_close(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = samr_reply_close(&q_u, *rdata + 0x18, *rdata);
}


/*******************************************************************
 samr_reply_open_secret
 ********************************************************************/
static int samr_reply_open_secret(SAMR_Q_OPEN_SECRET *q_u,
				char *q, char *base)
{
	SAMR_R_OPEN_SECRET r_u;

	r_u.status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !open_lsa_policy_hnd(&(r_u.pol)))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_lsa_policy_samr_sid(&(r_u.pol), &(q_u->dom_sid)))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(5,("samr_open_secret: %d\n", __LINE__));
/*
	make_samr_r_open_secret(&r_u, q_u->open_policy, my_name, domain, status);
*/
	/* store the response in the SMB stream */
	q = samr_io_r_open_secret(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_open_secret: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_open_secret
 ********************************************************************/
static void api_samr_open_secret( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SAMR_Q_OPEN_SECRET q_u;

	/* grab the samr open */
	samr_io_q_open_secret(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = samr_reply_open_secret(&q_u, *rdata + 0x18, *rdata);
}


/*******************************************************************
 samr_reply_lookup_rids
 ********************************************************************/
static int samr_reply_lookup_rids(SAMR_Q_LOOKUP_RIDS *q_u,
				char *q, char *base)
{
	struct smb_passwd *smb_pass;
	fstring mach_acct;

	uint32 lookup_rid = 0;
	uint32 status     = 0;

	SAMR_R_LOOKUP_RIDS r_u;

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	fstrcpy(mach_acct, unistrn2(q_u->uni_mach_acct.buffer,
	                            q_u->uni_mach_acct.uni_str_len));

	/* lkclXXXX SHOULD use name_to_rid() here! */
	{
		/* find the machine account */
		become_root(True);
		smb_pass = get_smbpwd_entry(mach_acct, 0);
		unbecome_root(True);

		if (smb_pass == NULL)
		{
			/* machine account doesn't exist: say so */
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
			lookup_rid = 0;
		}
		else
		{
			status = 0;
			lookup_rid = smb_pass->smb_userid;
		}
	}

	make_samr_r_lookup_rids(&r_u, 1, lookup_rid, status);

	/* store the response in the SMB stream */
	q = samr_io_r_lookup_rids(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_lookup_rids
 ********************************************************************/
static void api_samr_lookup_rids( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SAMR_Q_LOOKUP_RIDS q_u;

	/* grab the samr unknown 11 */
	samr_io_q_lookup_rids(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = samr_reply_lookup_rids(&q_u, *rdata + 0x18, *rdata);
}


/*******************************************************************
 samr_reply_unknown_22
 ********************************************************************/
static int samr_reply_unknown_22(SAMR_Q_UNKNOWN_22 *q_u,
				char *q, char *base,
				int status)
{
	SAMR_R_UNKNOWN_22 r_u;

	/* set up the SAMR unknown_22 response */
	bzero(&(r_u.pol.data), POL_HND_SIZE);

	r_u.status = 0x0;

	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !open_lsa_policy_hnd(&(r_u.pol)))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(5,("samr_unknown_22: %d\n", __LINE__));

	/* store the response in the SMB stream */
	q = samr_io_r_unknown_22(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_unknown_22: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_unknown_22
 ********************************************************************/
static void api_samr_unknown_22( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SAMR_Q_UNKNOWN_22 q_u;

	/* grab the samr unknown 22 */
	samr_io_q_unknown_22(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = samr_reply_unknown_22(&q_u, *rdata + 0x18, *rdata, 0x0);
}


/*******************************************************************
 samr_reply_unknown_24
 ********************************************************************/
static int samr_reply_unknown_24(SAMR_Q_UNKNOWN_24 *q_u,
				char *q, char *base,
				int status)
{
	SAMR_R_UNKNOWN_24 r_u;
	NTTIME expire;

	DEBUG(5,("samr_unknown_24: %d\n", __LINE__));

	expire.low  = 0xffffffff;
	expire.high = 0x7fffffff;

	make_samr_r_unknown_24(&r_u, q_u->unknown_0,
				&expire, "BROOKFIELDS$", 0x03ef, 0x0);

	/* store the response in the SMB stream */
	q = samr_io_r_unknown_24(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_unknown_24: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_unknown_24
 ********************************************************************/
static void api_samr_unknown_24( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SAMR_Q_UNKNOWN_24 q_u;

	/* grab the samr unknown 24 */
	samr_io_q_unknown_24(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = samr_reply_unknown_24(&q_u, *rdata + 0x18, *rdata, 0x0);
}


/*******************************************************************
 samr_reply_unknown_32
 ********************************************************************/
static int samr_reply_unknown_32(SAMR_Q_UNKNOWN_32 *q_u,
				char *q, char *base,
				int status)
{
	int i;
	SAMR_R_UNKNOWN_32 r_u;

	/* set up the SAMR unknown_32 response */
	bzero(&(r_u.pol.data), POL_HND_SIZE);
	if (status == 0)
	{
		for (i = 4; i < POL_HND_SIZE; i++)
		{
			r_u.pol.data[i] = i+1;
		}
	}

	r_u.unknown_0 = 0x00000030;
	r_u.padding   = 0x0;
	r_u.status = status;

	DEBUG(5,("samr_unknown_32: %d\n", __LINE__));
/*
	make_samr_r_unknown_32(&r_u, q_u->unknown_32, my_name, domain, status);
*/
	/* store the response in the SMB stream */
	q = samr_io_r_unknown_32(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_unknown_32: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_unknown_32
 ********************************************************************/
static void api_samr_unknown_32( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	uint32 status = 0;
	struct smb_passwd *smb_pass;
	fstring mach_acct;

	SAMR_Q_UNKNOWN_32 q_u;

	/* grab the samr unknown 32 */
	samr_io_q_unknown_32(True, &q_u, data + 0x18, data, 4, 0);

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	fstrcpy(mach_acct, unistrn2(q_u.uni_mach_acct.buffer,
	                            q_u.uni_mach_acct.uni_str_len));

	become_root(True);
	smb_pass = get_smbpwd_entry(mach_acct, 0);
	unbecome_root(True);

	if (smb_pass != NULL)
	{
		/* machine account exists: say so */
		status = 0xC0000000 | NT_STATUS_USER_EXISTS;
	}
	else
	{
		/* this could cause trouble... */
		status = 0;
	}

	/* construct reply. */
	*rdata_len = samr_reply_unknown_32(&q_u, *rdata + 0x18, *rdata, status);
}


/*******************************************************************
 samr_reply_open_policy
 ********************************************************************/
static int samr_reply_open_policy(SAMR_Q_OPEN_POLICY *q_u,
				char *q, char *base)
{
	SAMR_R_OPEN_POLICY r_u;

	/* set up the SAMR open_policy response */

	r_u.status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !open_lsa_policy_hnd(&(r_u.pol)))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_lsa_policy_samr_pol_status(&(r_u.pol), q_u->unknown_0))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(5,("samr_open_policy: %d\n", __LINE__));
/*
	make_samr_r_open_policy(&r_u, q_u->unknown_0, my_name, domain, status);
*/
	/* store the response in the SMB stream */
	q = samr_io_r_open_policy(False, &r_u, q, base, 4, 0);

	DEBUG(5,("samr_open_policy: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_samr_open_policy
 ********************************************************************/
static void api_samr_open_policy( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	SAMR_Q_OPEN_POLICY q_u;

	/* grab the samr open policy */
	samr_io_q_open_policy(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = samr_reply_open_policy(&q_u, *rdata + 0x18, *rdata);
}


/*******************************************************************
 receives a samr pipe and responds.
 ********************************************************************/
BOOL api_samrTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
	RPC_HDR_RR hdr;

	if (data == NULL)
	{
		DEBUG(2,("api_samrTNP: NULL data received\n"));
		return False;
	}

	smb_io_rpc_hdr_rr(True, &hdr, data, data, 4, 0);

	DEBUG(4,("samr TransactNamedPipe op %x\n",hdr.opnum));

	switch (hdr.opnum)
	{
		case SAMR_CLOSE:
		{
			api_samr_close( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		case SAMR_OPEN_SECRET:
		{
			api_samr_open_secret( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		case SAMR_LOOKUP_RIDS:
		{
			api_samr_lookup_rids( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		case 0x22:
		{
			api_samr_unknown_22( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		case 0x24:
		{
			api_samr_unknown_24( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		case 0x32:
		{
			api_samr_unknown_32( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		case SAMR_OPEN_POLICY:
		{
			api_samr_open_policy( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		default:
		{
			DEBUG(4, ("samr, unknown code: %lx\n", hdr.opnum));
			break;
		}
	}

	return(True);
}

#endif
