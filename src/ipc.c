/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Inter-process communication and named pipe handling
   Copyright (C) Andrew Tridgell 1992-1998

   SMB Version handling
   Copyright (C) John H Terpstra 1995-1998

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
/*
   This file handles the named pipe and mailslot calls
   in the SMBtrans protocol
   */

#include "includes.h"

extern int DEBUGLEVEL;
extern int max_send;
extern files_struct Files[];
extern connection_struct Connections[];

extern fstring local_machine;
extern const char *workgroup;

#define NERR_Success      0
#define NERR_notsupported 50

#define NERR_BASE        (2100)
#define NERR_BufTooSmall (NERR_BASE + 23)
#define ERROR_MORE_DATA  234

#define ACCESS_READ   0x01
#define ACCESS_WRITE  0x02
#define ACCESS_CREATE 0x04

#define SHPWLEN 8 /* share password length */

extern int Client;
extern int smb_read_error;

static bool api_Unsupported(int cnum, char *param, char *data, int mdrcnt,
                            int mprcnt, char **rdata, char **rparam,
                            int *rdata_len, int *rparam_len);
static bool api_TooSmall(int cnum, char *param, char *data, int mdrcnt,
                         int mprcnt, char **rdata, char **rparam,
                         int *rdata_len, int *rparam_len);

static int copy_and_advance(char **dst, char *src, int *n)
{
	int l;
	if (!src || !dst || !n || !(*dst))
		return 0;
	strlcpy(*dst, src, *n + 1);
	l = strlen(*dst) + 1;
	(*dst) += l;
	(*n) -= l;
	return l;
}

/*******************************************************************
  check a API string for validity when we only need to check the prefix
  ******************************************************************/
static bool prefix_ok(char *str, char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

/****************************************************************************
  send a trans reply
  ****************************************************************************/
static void send_trans_reply(char *outbuf, char *data, char *param,
                             uint16_t *setup, int ldata, int lparam, int lsetup)
{
	int i;
	int this_ldata, this_lparam;
	int tot_data = 0, tot_param = 0;
	int align;

	this_lparam = MIN(
	    lparam, max_send - (500 + lsetup * sizeof(uint16_t))); /* hack */
	this_ldata = MIN(
	    ldata, max_send - (500 + lsetup * sizeof(uint16_t) + this_lparam));

#ifdef CONFUSE_NETMONITOR_MSRPC_DECODING
	/* if you don't want Net Monitor to decode your packets, do this!!! */
	align = ((this_lparam + 1) % 4);
#else
	align = (this_lparam % 4);
#endif

	set_message(outbuf, 10 + lsetup, align + this_ldata + this_lparam,
	            true);
	if (this_lparam)
		memcpy(smb_buf(outbuf), param, this_lparam);
	if (this_ldata)
		memcpy(smb_buf(outbuf) + this_lparam + align, data, this_ldata);

	SSVAL(outbuf, smb_vwv0, lparam);
	SSVAL(outbuf, smb_vwv1, ldata);
	SSVAL(outbuf, smb_vwv3, this_lparam);
	SSVAL(outbuf, smb_vwv4, smb_offset(smb_buf(outbuf), outbuf));
	SSVAL(outbuf, smb_vwv5, 0);
	SSVAL(outbuf, smb_vwv6, this_ldata);
	SSVAL(outbuf, smb_vwv7,
	      smb_offset(smb_buf(outbuf) + this_lparam + align, outbuf));
	SSVAL(outbuf, smb_vwv8, 0);
	SSVAL(outbuf, smb_vwv9, lsetup);
	for (i = 0; i < lsetup; i++)
		SSVAL(outbuf, smb_vwv10 + i * sizeof(uint16_t), setup[i]);

	show_msg(outbuf);
	send_smb(Client, outbuf);

	tot_data = this_ldata;
	tot_param = this_lparam;

	while (tot_data < ldata || tot_param < lparam) {
		this_lparam =
		    MIN(lparam - tot_param, max_send - 500); /* hack */
		this_ldata =
		    MIN(ldata - tot_data, max_send - (500 + this_lparam));

		align = (this_lparam % 4);

		set_message(outbuf, 10, this_ldata + this_lparam + align,
		            false);
		if (this_lparam)
			memcpy(smb_buf(outbuf), param + tot_param, this_lparam);
		if (this_ldata)
			memcpy(smb_buf(outbuf) + this_lparam + align,
			       data + tot_data, this_ldata);

		SSVAL(outbuf, smb_vwv3, this_lparam);
		SSVAL(outbuf, smb_vwv4, smb_offset(smb_buf(outbuf), outbuf));
		SSVAL(outbuf, smb_vwv5, tot_param);
		SSVAL(outbuf, smb_vwv6, this_ldata);
		SSVAL(
		    outbuf, smb_vwv7,
		    smb_offset(smb_buf(outbuf) + this_lparam + align, outbuf));
		SSVAL(outbuf, smb_vwv8, tot_data);
		SSVAL(outbuf, smb_vwv9, 0);

		show_msg(outbuf);
		send_smb(Client, outbuf);

		tot_data += this_ldata;
		tot_param += this_lparam;
	}
}

/****************************************************************************
  get info level for a server list query
  ****************************************************************************/
static bool check_server_info(int uLevel, char *id)
{
	switch (uLevel) {
	case 0:
		if (strcmp(id, "B16") != 0)
			return false;
		break;
	case 1:
		if (strcmp(id, "B16BBDz") != 0)
			return false;
		break;
	default:
		return false;
	}
	return true;
}

/****************************************************************************
  view list of servers available (or possibly domains).
  ****************************************************************************/
static bool api_RNetServerEnum(int cnum, char *param, char *data, int mdrcnt,
                               int mprcnt, char **rdata, char **rparam,
                               int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);

	p += 8;

	if (!prefix_ok(str1, "WrLehD"))
		return false;
	if (!check_server_info(uLevel, str2))
		return false;

	*rdata_len = 0;

	// We answer the request but don't care about other servers.
	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, 0);
	SSVAL(*rparam, 6, 0);

	DEBUG(3, ("NetServerEnum\n"));

	return true;
}

/****************************************************************************
  get info about a share
  ****************************************************************************/
static bool check_share_info(int uLevel, char *id)
{
	switch (uLevel) {
	case 0:
		if (strcmp(id, "B13") != 0)
			return false;
		break;
	case 1:
		if (strcmp(id, "B13BWz") != 0)
			return false;
		break;
	case 2:
		if (strcmp(id, "B13BWzWWWzB9B") != 0)
			return false;
		break;
	case 91:
		if (strcmp(id, "B13BWzWWWzB9BB9BWzWWzWW") != 0)
			return false;
		break;
	default:
		return false;
	}
	return true;
}

static int fill_share_info(int cnum, const struct share *share, int uLevel,
                           char **buf, int *buflen, char **stringbuf,
                           int *stringspace, char *baseaddr)
{
	int struct_len;
	char *p;
	char *p2;
	int l2;
	int len;

	switch (uLevel) {
	case 0:
		struct_len = 13;
		break;
	case 1:
		struct_len = 20;
		break;
	case 2:
		struct_len = 40;
		break;
	case 91:
		struct_len = 68;
		break;
	default:
		return -1;
	}

	if (!buf) {
		len = 0;
		if (uLevel > 0)
			len += strlen(share->description) + 1;
		if (uLevel > 1)
			len += strlen(share->path) + 1;
		if (buflen)
			*buflen = struct_len;
		if (stringspace)
			*stringspace = len;
		return struct_len + len;
	}

	len = struct_len;
	p = *buf;
	if ((*buflen) < struct_len)
		return -1;
	if (stringbuf) {
		p2 = *stringbuf;
		l2 = *stringspace;
	} else {
		p2 = p + struct_len;
		l2 = (*buflen) - struct_len;
	}
	if (!baseaddr)
		baseaddr = p;

	strlcpy(p, share->name, 14);

	if (uLevel > 0) {
		int type;
		CVAL(p, 13) = 0;
		type = STYPE_DISKTREE;
		if (strequal("IPC$", share->name))
			type = STYPE_IPC;
		SSVAL(p, 14, type); /* device type */
		SIVAL(p, 16, PTR_DIFF(p2, baseaddr));
		len += copy_and_advance(&p2, share->description, &l2);
	}

	if (uLevel > 1) {
		SSVAL(p, 20,
		      ACCESS_READ | ACCESS_WRITE |
		          ACCESS_CREATE);             /* permissions */
		SSVALS(p, 22, -1);                    /* max uses */
		SSVAL(p, 24, 1);                      /* current uses */
		SIVAL(p, 26, PTR_DIFF(p2, baseaddr)); /* local pathname */
		len += copy_and_advance(&p2, share->path, &l2);
		memset(p + 30, 0,
		       SHPWLEN + 2); /* passwd (reserved), pad field */
	}

	if (uLevel > 2) {
		memset(p + 40, 0, SHPWLEN + 2);
		SSVAL(p, 50, 0);
		SIVAL(p, 52, 0);
		SSVAL(p, 56, 0);
		SSVAL(p, 58, 0);
		SIVAL(p, 60, 0);
		SSVAL(p, 64, 0);
		SSVAL(p, 66, 0);
	}

	if (stringbuf) {
		(*buf) = p + struct_len;
		(*buflen) -= struct_len;
		(*stringbuf) = p2;
		(*stringspace) = l2;
	} else {
		(*buf) = p2;
		(*buflen) -= len;
	}
	return len;
}

static bool api_RNetShareGetInfo(int cnum, char *param, char *data, int mdrcnt,
                                 int mprcnt, char **rdata, char **rparam,
                                 int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *netname = skip_string(str2, 1);
	char *p = skip_string(netname, 1);
	int uLevel = SVAL(p, 0);
	const struct share *share = lookup_share(netname);

	if (share == NULL) {
		return false;
	}

	/* check it's a supported varient */
	if (!prefix_ok(str1, "zWrLh"))
		return false;
	if (!check_share_info(uLevel, str2))
		return false;

	*rdata = REALLOC(*rdata, mdrcnt);
	p = *rdata;
	*rdata_len = fill_share_info(cnum, share, uLevel, &p, &mdrcnt, 0, 0, 0);
	if (*rdata_len < 0)
		return false;

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0); /* converter word */
	SSVAL(*rparam, 4, *rdata_len);

	return true;
}

/****************************************************************************
  view list of shares available
  ****************************************************************************/
static bool api_RNetShareEnum(int cnum, char *param, char *data, int mdrcnt,
                              int mprcnt, char **rdata, char **rparam,
                              int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	int buf_len = SVAL(p, 2);
	char *p2;
	int total = 0, counted = 0;
	bool missed = false;
	int i;
	int data_len, fixed_len, string_len;
	int f_len = 0, s_len = 0;

	if (!prefix_ok(str1, "WrLeh"))
		return false;
	if (!check_share_info(uLevel, str2))
		return false;

	data_len = fixed_len = string_len = 0;
	for (i = 0; i < shares_count(); i++) {
		const struct share *s = get_share(i);
		total++;
		data_len +=
		    fill_share_info(cnum, s, uLevel, 0, &f_len, 0, &s_len, 0);
		if (data_len <= buf_len) {
			counted++;
			fixed_len += f_len;
			string_len += s_len;
		} else {
			missed = true;
		}
	}
	*rdata_len = fixed_len + string_len;
	*rdata = REALLOC(*rdata, *rdata_len);
	memset(*rdata, 0, *rdata_len);

	p2 = (*rdata) + fixed_len; /* auxillery data (strings) will go here */
	p = *rdata;
	f_len = fixed_len;
	s_len = string_len;
	for (i = 0; i < shares_count(); i++) {
		const struct share *s = get_share(i);
		if (fill_share_info(cnum, s, uLevel, &p, &f_len, &p2, &s_len,
		                    *rdata) < 0) {
			break;
		}
	}

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, missed ? ERROR_MORE_DATA : NERR_Success);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, shares_count());
	SSVAL(*rparam, 6, total);

	DEBUG(3, ("RNetShareEnum gave %d entries of %d (%d %d %d %d)\n",
	          shares_count(), total, uLevel, buf_len, *rdata_len, mdrcnt));
	return true;
}

/****************************************************************************
  get info about the server
  ****************************************************************************/
static bool api_RNetServerGetInfo(int cnum, char *param, char *data, int mdrcnt,
                                  int mprcnt, char **rdata, char **rparam,
                                  int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	char *p2;
	int struct_len;

	DEBUG(4, ("NetServerGetInfo level %d\n", uLevel));

	/* check it's a supported varient */
	if (!prefix_ok(str1, "WrLh"))
		return false;
	switch (uLevel) {
	case 0:
		if (strcmp(str2, "B16") != 0)
			return false;
		struct_len = 16;
		break;
	case 1:
		if (strcmp(str2, "B16BBDz") != 0)
			return false;
		struct_len = 26;
		break;
	case 2:
		if (strcmp(
		        str2,
		        "B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWWWWz") !=
		    0)
			return false;
		struct_len = 134;
		break;
	case 3:
		if (strcmp(str2, "B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWW"
		                 "WWzDWz") != 0)
			return false;
		struct_len = 144;
		break;
	case 20:
		if (strcmp(str2, "DN") != 0)
			return false;
		struct_len = 6;
		break;
	case 50:
		if (strcmp(str2, "B16BBDzWWzzz") != 0)
			return false;
		struct_len = 42;
		break;
	default:
		return false;
	}

	*rdata_len = mdrcnt;
	*rdata = REALLOC(*rdata, *rdata_len);

	p = *rdata;
	p2 = p + struct_len;
	if (uLevel != 20) {
		strlcpy(p, local_machine, 17);
		strupper(p);
	}
	p += 16;
	if (uLevel > 0) {
		SCVAL(p, 0, DEFAULT_MAJOR_VERSION);
		SCVAL(p, 1, DEFAULT_MINOR_VERSION);
		SIVAL(p, 2, SV_TYPE_WIN95_PLUS);

		if (mdrcnt == struct_len) {
			SIVAL(p, 6, 0);
		} else {
			pstring comment;
			pstrcpy(comment, lp_serverstring());
			SIVAL(p, 6, PTR_DIFF(p2, *rdata));
			strlcpy(p2, comment, MAX(mdrcnt - struct_len, 0) + 1);
			p2 = skip_string(p2, 1);
		}
	}
	if (uLevel > 1) {
		return false; /* not yet implemented */
	}

	*rdata_len = PTR_DIFF(p2, *rdata);

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0); /* converter word */
	SSVAL(*rparam, 4, *rdata_len);

	return true;
}

/****************************************************************************
  get info about the server
  ****************************************************************************/
static bool api_NetWkstaGetInfo(int cnum, char *param, char *data, int mdrcnt,
                                int mprcnt, char **rdata, char **rparam,
                                int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	char *p2;
	int level = SVAL(p, 0);

	DEBUG(4, ("NetWkstaGetInfo level %d\n", level));

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);

	/* check it's a supported varient */
	if (!(level == 10 && strcsequal(str1, "WrLh") &&
	      strcsequal(str2, "zzzBBzz")))
		return false;

	*rdata_len = mdrcnt + 1024;
	*rdata = REALLOC(*rdata, *rdata_len);

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0); /* converter word */

	p = *rdata;
	p2 = p + 22;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata)); /* host name */
	pstrcpy(p2, local_machine);
	strupper(p2);
	p2 = skip_string(p2, 1);
	p += 4;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata));
	pstrcpy(p2, "user");
	p2 = skip_string(p2, 1);
	p += 4;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata)); /* login domain */
	pstrcpy(p2, workgroup);
	strupper(p2);
	p2 = skip_string(p2, 1);
	p += 4;

	SCVAL(p, 0, DEFAULT_MAJOR_VERSION); /* system version - e.g 4 in 4.1 */
	SCVAL(p, 1, DEFAULT_MINOR_VERSION); /* system version - e.g .1 in 4.1 */
	p += 2;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata));
	pstrcpy(p2, workgroup); /* don't know.  login domain?? */
	p2 = skip_string(p2, 1);
	p += 4;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata)); /* don't know */
	pstrcpy(p2, "");
	p2 = skip_string(p2, 1);
	p += 4;

	*rdata_len = PTR_DIFF(p2, *rdata);

	SSVAL(*rparam, 4, *rdata_len);

	return true;
}

/****************************************************************************
  the buffer was too small
  ****************************************************************************/
static bool api_TooSmall(int cnum, char *param, char *data, int mdrcnt,
                         int mprcnt, char **rdata, char **rparam,
                         int *rdata_len, int *rparam_len)
{
	*rparam_len = MIN(*rparam_len, mprcnt);
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_BufTooSmall);

	DEBUG(3, ("Supplied buffer too small in API command\n"));

	return true;
}

/****************************************************************************
  the request is not supported
  ****************************************************************************/
static bool api_Unsupported(int cnum, char *param, char *data, int mdrcnt,
                            int mprcnt, char **rdata, char **rparam,
                            int *rdata_len, int *rparam_len)
{
	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_notsupported);
	SSVAL(*rparam, 2, 0); /* converter word */

	DEBUG(3, ("Unsupported API command\n"));

	return true;
}

struct {
	char *name;
	int id;
	bool (*fn)(int, char *, char *, int, int, char **, char **, int *,
	           int *);
	int flags;
} api_commands[] = {{"RNetShareEnum", 0, api_RNetShareEnum, 0},
                    {"RNetShareGetInfo", 1, api_RNetShareGetInfo, 0},
                    {"RNetServerGetInfo", 13, api_RNetServerGetInfo, 0},
                    {"NetWkstaGetInfo", 63, api_NetWkstaGetInfo, 0},
                    {"NetServerEnum", 104, api_RNetServerEnum, 0},
                    {NULL, -1, api_Unsupported, 0}};

/****************************************************************************
  handle remote api calls
  ****************************************************************************/
static int api_reply(int cnum, char *outbuf, char *data, char *params,
                     int tdscnt, int tpscnt, int mdrcnt, int mprcnt)
{
	int api_command = SVAL(params, 0);
	char *rdata = NULL;
	char *rparam = NULL;
	int rdata_len = 0;
	int rparam_len = 0;
	bool reply = false;
	int i;

	DEBUG(3, ("Got API command %d of form <%s> <%s> "
	          "(tdscnt=%d,tpscnt=%d,mdrcnt=%d,mprcnt=%d)\n",
	          api_command, params + 2, skip_string(params + 2, 1), tdscnt,
	          tpscnt, mdrcnt, mprcnt));

	for (i = 0; api_commands[i].name; i++)
		if (api_commands[i].id == api_command && api_commands[i].fn) {
			DEBUG(3, ("Doing %s\n", api_commands[i].name));
			break;
		}

	rdata = checked_malloc(1024);
	bzero(rdata, 1024);
	rparam = checked_malloc(1024);
	bzero(rparam, 1024);

	reply = api_commands[i].fn(cnum, params, data, mdrcnt, mprcnt, &rdata,
	                           &rparam, &rdata_len, &rparam_len);

	if (rdata_len > mdrcnt || rparam_len > mprcnt) {
		reply = api_TooSmall(cnum, params, data, mdrcnt, mprcnt, &rdata,
		                     &rparam, &rdata_len, &rparam_len);
	}

	/* if we get false back then it's actually unsupported */
	if (!reply)
		api_Unsupported(cnum, params, data, mdrcnt, mprcnt, &rdata,
		                &rparam, &rdata_len, &rparam_len);

	/* now send the reply */
	send_trans_reply(outbuf, rdata, rparam, NULL, rdata_len, rparam_len, 0);

	free(rdata);
	free(rparam);

	return -1;
}

/****************************************************************************
  handle named pipe commands
  ****************************************************************************/
static int named_pipe(int cnum, char *outbuf, char *name, uint16_t *setup,
                      char *data, char *params, int suwcnt, int tdscnt,
                      int tpscnt, int msrcnt, int mdrcnt, int mprcnt)
{
	DEBUG(3, ("named pipe command on <%s> name\n", name));

	if (strequal(name, "LANMAN")) {
		return api_reply(cnum, outbuf, data, params, tdscnt, tpscnt,
		                 mdrcnt, mprcnt);
	}
	if (setup) {
		DEBUG(3, ("unknown named pipe: setup 0x%X setup1=%d\n",
		          (int) setup[0], (int) setup[1]));
	}

	return 0;
}

/****************************************************************************
  reply to a SMBtrans
  ****************************************************************************/
int reply_trans(char *inbuf, char *outbuf, int size, int bufsize)
{
	fstring name;

	char *data = NULL, *params = NULL;
	uint16_t *setup = NULL;

	int outsize = 0;
	int cnum = SVAL(inbuf, smb_tid);
	int tpscnt = SVAL(inbuf, smb_vwv0);
	int tdscnt = SVAL(inbuf, smb_vwv1);
	int mprcnt = SVAL(inbuf, smb_vwv2);
	int mdrcnt = SVAL(inbuf, smb_vwv3);
	int msrcnt = CVAL(inbuf, smb_vwv4);
	bool close_on_completion = BITSETW(inbuf + smb_vwv5, 0);
	bool one_way = BITSETW(inbuf + smb_vwv5, 1);
	int pscnt = SVAL(inbuf, smb_vwv9);
	int psoff = SVAL(inbuf, smb_vwv10);
	int dscnt = SVAL(inbuf, smb_vwv11);
	int dsoff = SVAL(inbuf, smb_vwv12);
	int suwcnt = CVAL(inbuf, smb_vwv13);

	bzero(name, sizeof(name));
	fstrcpy(name, smb_buf(inbuf));

	if (dscnt > tdscnt || pscnt > tpscnt) {
		exit_server("invalid trans parameters\n");
	}

	if (tdscnt) {
		data = checked_malloc(tdscnt);
		memcpy(data, smb_base(inbuf) + dsoff, dscnt);
	}
	if (tpscnt) {
		params = checked_malloc(tpscnt);
		memcpy(params, smb_base(inbuf) + psoff, pscnt);
	}

	if (suwcnt) {
		int i;
		setup = checked_calloc(suwcnt, sizeof(*setup));
		for (i = 0; i < suwcnt; i++)
			setup[i] =
			    SVAL(inbuf, smb_vwv14 + i * sizeof(uint16_t));
	}

	if (pscnt < tpscnt || dscnt < tdscnt) {
		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		outsize = set_message(outbuf, 0, 0, true);
		show_msg(outbuf);
		send_smb(Client, outbuf);
	}

	/* receive the rest of the trans packet */
	while (pscnt < tpscnt || dscnt < tdscnt) {
		bool ret;
		int pcnt, poff, dcnt, doff, pdisp, ddisp;

		ret = receive_next_smb(Client, inbuf, bufsize,
		                       SMB_SECONDARY_WAIT);

		if ((ret && (CVAL(inbuf, smb_com) != SMBtrans)) || !ret) {
			if (ret)
				DEBUG(0, ("reply_trans: Invalid secondary "
				          "trans packet\n"));
			else
				DEBUG(0, ("reply_trans: %s in getting "
				          "secondary trans response.\n",
				          (smb_read_error == READ_ERROR)
				              ? "error"
				              : "timeout"));
			free(params);
			free(data);
			free(setup);
			return ERROR(ERRSRV, ERRerror);
		}

		show_msg(inbuf);

		tpscnt = SVAL(inbuf, smb_vwv0);
		tdscnt = SVAL(inbuf, smb_vwv1);

		pcnt = SVAL(inbuf, smb_vwv2);
		poff = SVAL(inbuf, smb_vwv3);
		pdisp = SVAL(inbuf, smb_vwv4);

		dcnt = SVAL(inbuf, smb_vwv5);
		doff = SVAL(inbuf, smb_vwv6);
		ddisp = SVAL(inbuf, smb_vwv7);

		pscnt += pcnt;
		dscnt += dcnt;

		if (dscnt > tdscnt || pscnt > tpscnt) {
			exit_server("invalid trans parameters\n");
		}

		if (pcnt)
			memcpy(params + pdisp, smb_base(inbuf) + poff, pcnt);
		if (dcnt)
			memcpy(data + ddisp, smb_base(inbuf) + doff, dcnt);
	}

	DEBUG(3, ("trans <%s> data=%d params=%d setup=%d\n", name, tdscnt,
	          tpscnt, suwcnt));

	if (strncmp(name, "\\PIPE\\", strlen("\\PIPE\\")) == 0) {
		DEBUG(5, ("calling named_pipe\n"));
		outsize = named_pipe(cnum, outbuf, name + strlen("\\PIPE\\"),
		                     setup, data, params, suwcnt, tdscnt,
		                     tpscnt, msrcnt, mdrcnt, mprcnt);
	} else {
		DEBUG(3, ("invalid pipe name\n"));
		outsize = 0;
	}

	free(data);
	free(params);
	free(setup);

	if (close_on_completion)
		close_cnum(cnum);

	if (one_way)
		return -1;

	if (outsize == 0)
		return ERROR(ERRSRV, ERRnosupport);

	return outsize;
}
