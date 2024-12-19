
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
 make_r_wks_unknown_0
 ********************************************************************/
static void make_wks_r_unknown_0(WKS_R_UNKNOWN_0 *r_u,
				uint32 unknown_0,
				char *my_name, char *domain_name,
				int status)  
{
	DEBUG(5,("make_wks_r_unknown_0: %d\n", __LINE__));

	r_u->unknown_0 = unknown_0;  /* same as in request */
	r_u->ptr_1     = 1;          /* pointer 1 */
	r_u->unknown_1 = 0x00001f4;  /* 0x0000 01f4 - unknown */
	r_u->ptr_srv_name = 1;       /* pointer to server name */
	r_u->ptr_dom_name = 1;       /* pointer to domain name */
	r_u->unknown_2 = 4;          /* 4 - unknown */
	r_u->unknown_3 = 0;          /* 0 - unknown */

	make_unistr2(&r_u->uni_srv_name, my_name    , strlen(my_name    ));
	make_unistr2(&r_u->uni_dom_name, domain_name, strlen(domain_name));

	r_u->status       = status;
}

/*******************************************************************
 wks_reply_unknown_0
 ********************************************************************/
static int wks_reply_unknown_0(WKS_Q_UNKNOWN_0 *q_u,
				char *q, char *base,
				int status)
{
	WKS_R_UNKNOWN_0 r_u;

	extern pstring myname;
	pstring my_name;
	pstring domain;

	get_myname(myname, NULL);
	pstrcpy (my_name, myname);
	strupper(my_name);

	pstrcpy (domain , lp_workgroup());
	strupper(domain);

	DEBUG(5,("wks_unknown_0: %d\n", __LINE__));
	make_wks_r_unknown_0(&r_u, q_u->unknown_0, my_name, domain, status);

	/* store the response in the SMB stream */
	q = wks_io_r_unknown_0(False, &r_u, q, base, 4, 0);

	DEBUG(5,("wks_unknown_0: %d\n", __LINE__));

	/* return length of SMB data stored */
	return PTR_DIFF(q, base);
}

/*******************************************************************
 api_wks_unknown_0
 ********************************************************************/
static void api_wks_unknown_0( char *param, char *data,
                                    char **rdata, int *rdata_len )
{
	WKS_Q_UNKNOWN_0 q_u;

	/* grab the net share enum */
	wks_io_q_unknown_0(True, &q_u, data + 0x18, data, 4, 0);

	/* construct reply.  always indicate success */
	*rdata_len = wks_reply_unknown_0(&q_u, *rdata + 0x18, *rdata, 0x0);
}


/*******************************************************************
 receives a wkssvc pipe and responds.
 ********************************************************************/
BOOL api_wkssvcTNP(int cnum,int uid, char *param,char *data,
		     int mdrcnt,int mprcnt,
		     char **rdata,char **rparam,
		     int *rdata_len,int *rparam_len)
{
	RPC_HDR_RR hdr;

	if (data == NULL)
	{
		DEBUG(2,("api_wkssvcTNP: NULL data received\n"));
		return False;
	}

	smb_io_rpc_hdr_rr(True, &hdr, data, data, 4, 0);

	DEBUG(4,("wkssvc TransactNamedPipe op %x\n",hdr.opnum));

	switch (hdr.opnum)
	{
		case 0:
		{
			api_wks_unknown_0( param, data, rdata, rdata_len);
			create_rpc_reply(hdr.hdr.call_id, *rdata, *rdata_len);
			break;
		}
		default:
		{
			DEBUG(4, ("wkssvc, unknown code: %lx\n", hdr.opnum));
			break;
		}
	}

	return(True);
}

#endif
