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

#ifdef CHECK_TYPES
#undef CHECK_TYPES
#endif
#define CHECK_TYPES 0

extern int DEBUGLEVEL;
extern int max_send;
extern files_struct Files[];
extern connection_struct Connections[];

extern fstring local_machine;
extern fstring myworkgroup;

#define NERR_Success 0
#define NERR_badpass 86
#define NERR_notsupported 50

#define NERR_BASE (2100)
#define NERR_BufTooSmall (NERR_BASE + 23)
#define NERR_JobNotFound (NERR_BASE + 51)
#define NERR_DestNotFound (NERR_BASE + 52)
#define ERROR_INVALID_LEVEL 124
#define ERROR_MORE_DATA 234

#define ACCESS_READ 0x01
#define ACCESS_WRITE 0x02
#define ACCESS_CREATE 0x04

#define SHPWLEN 8 /* share password length */
#define NNLEN 12  /* 8.3 net name length */
#define SNLEN 15  /* service name length */
#define QNLEN 12  /* queue name maximum length */

extern int Client;
extern int oplock_sock;
extern int smb_read_error;

static BOOL api_Unsupported(int cnum, char *param, char *data,
                            int mdrcnt, int mprcnt, char **rdata, char **rparam,
                            int *rdata_len, int *rparam_len);
static BOOL api_TooSmall(int cnum, char *param, char *data,
                         int mdrcnt, int mprcnt, char **rdata, char **rparam,
                         int *rdata_len, int *rparam_len);

static int CopyExpanded(int cnum, int snum, char **dst, char *src, int *n)
{
	pstring buf;
	int l;

	if (!src || !dst || !n || !(*dst))
		return (0);

	StrnCpy(buf, src, sizeof(buf) / 2);
	string_sub(buf, "%S", lp_servicename(snum));
	standard_sub(cnum, buf);
	StrnCpy(*dst, buf, *n);
	l = strlen(*dst) + 1;
	(*dst) += l;
	(*n) -= l;
	return l;
}

static int CopyAndAdvance(char **dst, char *src, int *n)
{
	int l;
	if (!src || !dst || !n || !(*dst))
		return (0);
	StrnCpy(*dst, src, *n);
	l = strlen(*dst) + 1;
	(*dst) += l;
	(*n) -= l;
	return l;
}

static int StrlenExpanded(int cnum, int snum, char *s)
{
	pstring buf;
	if (!s)
		return (0);
	StrnCpy(buf, s, sizeof(buf) / 2);
	string_sub(buf, "%S", lp_servicename(snum));
	standard_sub(cnum, buf);
	return strlen(buf) + 1;
}

/*******************************************************************
  check a API string for validity when we only need to check the prefix
  ******************************************************************/
static BOOL prefix_ok(char *str, char *prefix)
{
	return (strncmp(str, prefix, strlen(prefix)) == 0);
}

/****************************************************************************
  send a trans reply
  ****************************************************************************/
static void send_trans_reply(char *outbuf, char *data, char *param,
                             uint16 *setup, int ldata, int lparam, int lsetup)
{
	int i;
	int this_ldata, this_lparam;
	int tot_data = 0, tot_param = 0;
	int align;

	this_lparam =
	    MIN(lparam, max_send - (500 + lsetup * SIZEOFWORD)); /* hack */
	this_ldata =
	    MIN(ldata, max_send - (500 + lsetup * SIZEOFWORD + this_lparam));

#ifdef CONFUSE_NETMONITOR_MSRPC_DECODING
	/* if you don't want Net Monitor to decode your packets, do this!!! */
	align = ((this_lparam + 1) % 4);
#else
	align = (this_lparam % 4);
#endif

	set_message(outbuf, 10 + lsetup, align + this_ldata + this_lparam,
	            True);
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
		SSVAL(outbuf, smb_vwv10 + i * SIZEOFWORD, setup[i]);

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
		            False);
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
static BOOL check_server_info(int uLevel, char *id)
{
	switch (uLevel) {
	case 0:
		if (strcmp(id, "B16") != 0)
			return False;
		break;
	case 1:
		if (strcmp(id, "B16BBDz") != 0)
			return False;
		break;
	default:
		return False;
	}
	return True;
}

struct srv_info_struct {
	fstring name;
	uint32 type;
	fstring comment;
	fstring domain;
	BOOL server_added;
};

/*******************************************************************
  get server info lists from the files saved by nmbd. Return the
  number of entries
  ******************************************************************/
static int get_server_info(uint32 servertype, struct srv_info_struct **servers,
                           char *domain)
{
	FILE *f;
	pstring fname;
	int count = 0;
	int alloced = 0;
	pstring line;
	BOOL local_list_only;

	pstrcpy(fname, lp_lockdir());
	trim_string(fname, NULL, "/");
	pstrcat(fname, "/");
	pstrcat(fname, SERVER_LIST);

	f = fopen(fname, "r");

	if (!f) {
		DEBUG(4, ("Can't open %s - %s\n", fname, strerror(errno)));
		return (0);
	}

	/* request for everything is code for request all servers */
	if (servertype == SV_TYPE_ALL)
		servertype &= ~(SV_TYPE_DOMAIN_ENUM | SV_TYPE_LOCAL_LIST_ONLY);

	local_list_only = (servertype & SV_TYPE_LOCAL_LIST_ONLY);

	DEBUG(4, ("Servertype search: %8x\n", servertype));

	while (!feof(f)) {
		fstring stype;
		struct srv_info_struct *s;
		char *ptr = line;
		BOOL ok = True;
		*ptr = 0;

		fgets(line, sizeof(line) - 1, f);
		if (!*line)
			continue;

		if (count == alloced) {
			alloced += 10;
			(*servers) = (struct srv_info_struct *) Realloc(
			    *servers, sizeof(**servers) * alloced);
			if (!(*servers))
				return (0);
			bzero((char *) ((*servers) + count),
			      sizeof(**servers) * (alloced - count));
		}
		s = &(*servers)[count];

		if (!next_token(&ptr, s->name, NULL))
			continue;
		if (!next_token(&ptr, stype, NULL))
			continue;
		if (!next_token(&ptr, s->comment, NULL))
			continue;
		if (!next_token(&ptr, s->domain, NULL)) {
			/* this allows us to cope with an old nmbd */
			pstrcpy(s->domain, myworkgroup);
		}

		if (sscanf(stype, "%X", &s->type) != 1) {
			DEBUG(4, ("r:host file "));
			ok = False;
		}

		/* Filter the servers/domains we return based on what was asked
		 * for. */

		/* Check to see if we are being asked for a local list only. */
		if (local_list_only &&
		    ((s->type & SV_TYPE_LOCAL_LIST_ONLY) == 0)) {
			DEBUG(4, ("r: local list only"));
			ok = False;
		}

		/* doesn't match up: don't want it */
		if (!(servertype & s->type)) {
			DEBUG(4, ("r:serv type "));
			ok = False;
		}

		if ((servertype & SV_TYPE_DOMAIN_ENUM) !=
		    (s->type & SV_TYPE_DOMAIN_ENUM)) {
			DEBUG(4, ("s: dom mismatch "));
			ok = False;
		}

		if (!strequal(domain, s->domain) &&
		    !(servertype & SV_TYPE_DOMAIN_ENUM)) {
			ok = False;
		}

		/* We should never return a server type with a
		 * SV_TYPE_LOCAL_LIST_ONLY set. */
		s->type &= ~SV_TYPE_LOCAL_LIST_ONLY;

		if (ok) {
			DEBUG(4, ("**SV** %20s %8x %25s %15s\n", s->name,
			          s->type, s->comment, s->domain));

			s->server_added = True;
			count++;
		} else {
			DEBUG(4, ("%20s %8x %25s %15s\n", s->name, s->type,
			          s->comment, s->domain));
		}
	}

	fclose(f);
	return (count);
}

/*******************************************************************
  fill in a server info structure
  ******************************************************************/
static int fill_srv_info(struct srv_info_struct *service, int uLevel,
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
		struct_len = 16;
		break;
	case 1:
		struct_len = 26;
		break;
	default:
		return -1;
	}

	if (!buf) {
		len = 0;
		switch (uLevel) {
		case 1:
			len = strlen(service->comment) + 1;
			break;
		}

		if (buflen)
			*buflen = struct_len;
		if (stringspace)
			*stringspace = len;
		return struct_len + len;
	}

	len = struct_len;
	p = *buf;
	if (*buflen < struct_len)
		return -1;
	if (stringbuf) {
		p2 = *stringbuf;
		l2 = *stringspace;
	} else {
		p2 = p + struct_len;
		l2 = *buflen - struct_len;
	}
	if (!baseaddr)
		baseaddr = p;

	switch (uLevel) {
	case 0:
		StrnCpy(p, service->name, 15);
		break;

	case 1:
		StrnCpy(p, service->name, 15);
		SIVAL(p, 18, service->type);
		SIVAL(p, 22, PTR_DIFF(p2, baseaddr));
		len += CopyAndAdvance(&p2, service->comment, &l2);
		break;
	}

	if (stringbuf) {
		*buf = p + struct_len;
		*buflen -= struct_len;
		*stringbuf = p2;
		*stringspace = l2;
	} else {
		*buf = p2;
		*buflen -= len;
	}
	return len;
}

static BOOL srv_comp(struct srv_info_struct *s1, struct srv_info_struct *s2)
{
	return (strcmp(s1->name, s2->name));
}

/****************************************************************************
  view list of servers available (or possibly domains). The info is
  extracted from lists saved by nmbd on the local host
  ****************************************************************************/
static BOOL api_RNetServerEnum(int cnum, char *param, char *data,
                               int mdrcnt, int mprcnt, char **rdata,
                               char **rparam, int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	int buf_len = SVAL(p, 2);
	uint32 servertype = IVAL(p, 4);
	char *p2;
	int data_len, fixed_len, string_len;
	int f_len = 0, s_len = 0;
	struct srv_info_struct *servers = NULL;
	int counted = 0, total = 0;
	int i, missed;
	fstring domain;
	BOOL domain_request;
	BOOL local_request;

	/* If someone sets all the bits they don't really mean to set
	   DOMAIN_ENUM and LOCAL_LIST_ONLY, they just want all the
	   known servers. */

	if (servertype == SV_TYPE_ALL)
		servertype &= ~(SV_TYPE_DOMAIN_ENUM | SV_TYPE_LOCAL_LIST_ONLY);

	/* If someone sets SV_TYPE_LOCAL_LIST_ONLY but hasn't set
	   any other bit (they may just set this bit on it's own) they
	   want all the locally seen servers. However this bit can be
	   set on its own so set the requested servers to be
	   ALL - DOMAIN_ENUM. */

	if ((servertype & SV_TYPE_LOCAL_LIST_ONLY) &&
	    !(servertype & SV_TYPE_DOMAIN_ENUM))
		servertype = SV_TYPE_ALL & ~(SV_TYPE_DOMAIN_ENUM);

	domain_request = ((servertype & SV_TYPE_DOMAIN_ENUM) != 0);
	local_request = ((servertype & SV_TYPE_LOCAL_LIST_ONLY) != 0);

	p += 8;

	if (!prefix_ok(str1, "WrLehD"))
		return False;
	if (!check_server_info(uLevel, str2))
		return False;

	DEBUG(4, ("server request level: %s %8x ", str2, servertype));
	DEBUG(4, ("domains_req:%s ", BOOLSTR(domain_request)));
	DEBUG(4, ("local_only:%s\n", BOOLSTR(local_request)));

	if (strcmp(str1, "WrLehDz") == 0) {
		StrnCpy(domain, p, sizeof(fstring) - 1);
	} else {
		StrnCpy(domain, myworkgroup, sizeof(fstring) - 1);
	}

	total = get_server_info(servertype, &servers, domain);

	data_len = fixed_len = string_len = 0;
	missed = 0;

	qsort(servers, total, sizeof(servers[0]), QSORT_CAST srv_comp);

	{
		char *lastname = NULL;

		for (i = 0; i < total; i++) {
			struct srv_info_struct *s = &servers[i];
			if (lastname && strequal(lastname, s->name))
				continue;
			lastname = s->name;
			data_len +=
			    fill_srv_info(s, uLevel, 0, &f_len, 0, &s_len, 0);
			DEBUG(4, ("fill_srv_info %20s %8x %25s %15s\n", s->name,
			          s->type, s->comment, s->domain));

			if (data_len <= buf_len) {
				counted++;
				fixed_len += f_len;
				string_len += s_len;
			} else {
				missed++;
			}
		}
	}

	*rdata_len = fixed_len + string_len;
	*rdata = REALLOC(*rdata, *rdata_len);
	bzero(*rdata, *rdata_len);

	p2 = (*rdata) + fixed_len; /* auxilliary data (strings) will go here */
	p = *rdata;
	f_len = fixed_len;
	s_len = string_len;

	{
		char *lastname = NULL;
		int count2 = counted;
		for (i = 0; i < total && count2; i++) {
			struct srv_info_struct *s = &servers[i];
			if (lastname && strequal(lastname, s->name))
				continue;
			lastname = s->name;
			fill_srv_info(s, uLevel, &p, &f_len, &p2, &s_len,
			              *rdata);
			DEBUG(4, ("fill_srv_info %20s %8x %25s %15s\n", s->name,
			          s->type, s->comment, s->domain));
			count2--;
		}
	}

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, (missed == 0 ? NERR_Success : ERROR_MORE_DATA));
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, counted);
	SSVAL(*rparam, 6, counted + missed);

	if (servers)
		free(servers);

	DEBUG(3, ("NetServerEnum domain = %s uLevel=%d counted=%d total=%d\n",
	          domain, uLevel, counted, counted + missed));

	return (True);
}

/****************************************************************************
  get info about a share
  ****************************************************************************/
static BOOL check_share_info(int uLevel, char *id)
{
	switch (uLevel) {
	case 0:
		if (strcmp(id, "B13") != 0)
			return False;
		break;
	case 1:
		if (strcmp(id, "B13BWz") != 0)
			return False;
		break;
	case 2:
		if (strcmp(id, "B13BWzWWWzB9B") != 0)
			return False;
		break;
	case 91:
		if (strcmp(id, "B13BWzWWWzB9BB9BWzWWzWW") != 0)
			return False;
		break;
	default:
		return False;
	}
	return True;
}

static int fill_share_info(int cnum, int snum, int uLevel, char **buf,
                           int *buflen, char **stringbuf, int *stringspace,
                           char *baseaddr)
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
			len += StrlenExpanded(cnum, snum, lp_comment(snum));
		if (uLevel > 1)
			len += strlen(lp_pathname(snum)) + 1;
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

	StrnCpy(p, lp_servicename(snum), 13);

	if (uLevel > 0) {
		int type;
		CVAL(p, 13) = 0;
		type = STYPE_DISKTREE;
		if (strequal("IPC$", lp_servicename(snum)))
			type = STYPE_IPC;
		SSVAL(p, 14, type); /* device type */
		SIVAL(p, 16, PTR_DIFF(p2, baseaddr));
		len += CopyExpanded(cnum, snum, &p2, lp_comment(snum), &l2);
	}

	if (uLevel > 1) {
		SSVAL(p, 20,
		      ACCESS_READ | ACCESS_WRITE |
		          ACCESS_CREATE);             /* permissions */
		SSVALS(p, 22, -1);                    /* max uses */
		SSVAL(p, 24, 1);                      /* current uses */
		SIVAL(p, 26, PTR_DIFF(p2, baseaddr)); /* local pathname */
		len += CopyAndAdvance(&p2, lp_pathname(snum), &l2);
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

static BOOL api_RNetShareGetInfo(int cnum, char *param, char *data,
                                 int mdrcnt, int mprcnt, char **rdata,
                                 char **rparam, int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *netname = skip_string(str2, 1);
	char *p = skip_string(netname, 1);
	int uLevel = SVAL(p, 0);
	int snum = find_service(netname);

	if (snum < 0)
		return False;

	/* check it's a supported varient */
	if (!prefix_ok(str1, "zWrLh"))
		return False;
	if (!check_share_info(uLevel, str2))
		return False;

	*rdata = REALLOC(*rdata, mdrcnt);
	p = *rdata;
	*rdata_len = fill_share_info(cnum, snum, uLevel, &p, &mdrcnt, 0, 0, 0);
	if (*rdata_len < 0)
		return False;

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0); /* converter word */
	SSVAL(*rparam, 4, *rdata_len);

	return (True);
}

/****************************************************************************
  view list of shares available
  ****************************************************************************/
static BOOL api_RNetShareEnum(int cnum, char *param, char *data,
                              int mdrcnt, int mprcnt, char **rdata,
                              char **rparam, int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	int uLevel = SVAL(p, 0);
	int buf_len = SVAL(p, 2);
	char *p2;
	int count = lp_numservices();
	int total = 0, counted = 0;
	BOOL missed = False;
	int i;
	int data_len, fixed_len, string_len;
	int f_len = 0, s_len = 0;

	if (!prefix_ok(str1, "WrLeh"))
		return False;
	if (!check_share_info(uLevel, str2))
		return False;

	data_len = fixed_len = string_len = 0;
	for (i = 0; i < count; i++)
		if (lp_browseable(i) && lp_snum_ok(i)) {
			total++;
			data_len += fill_share_info(cnum, i, uLevel, 0, &f_len,
			                            0, &s_len, 0);
			if (data_len <= buf_len) {
				counted++;
				fixed_len += f_len;
				string_len += s_len;
			} else
				missed = True;
		}
	*rdata_len = fixed_len + string_len;
	*rdata = REALLOC(*rdata, *rdata_len);
	memset(*rdata, 0, *rdata_len);

	p2 = (*rdata) + fixed_len; /* auxillery data (strings) will go here */
	p = *rdata;
	f_len = fixed_len;
	s_len = string_len;
	for (i = 0; i < count; i++)
		if (lp_browseable(i) && lp_snum_ok(i))
			if (fill_share_info(cnum, i, uLevel, &p, &f_len, &p2,
			                    &s_len, *rdata) < 0)
				break;

	*rparam_len = 8;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, missed ? ERROR_MORE_DATA : NERR_Success);
	SSVAL(*rparam, 2, 0);
	SSVAL(*rparam, 4, counted);
	SSVAL(*rparam, 6, total);

	DEBUG(3, ("RNetShareEnum gave %d entries of %d (%d %d %d %d)\n",
	          counted, total, uLevel, buf_len, *rdata_len, mdrcnt));
	return (True);
}

/****************************************************************************
  get the time of day info
  ****************************************************************************/
static BOOL api_NetRemoteTOD(int cnum, char *param, char *data,
                             int mdrcnt, int mprcnt, char **rdata,
                             char **rparam, int *rdata_len, int *rparam_len)
{
	char *p;
	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 21;
	*rdata = REALLOC(*rdata, *rdata_len);

	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0); /* converter word */

	p = *rdata;

	{
		struct tm *t;
		time_t unixdate = time(NULL);

		put_dos_date3(p, 0,
		              unixdate); /* this is the time that is looked at
		                            by NT in a "net time" operation,
		                            it seems to ignore the one below */

		/* the client expects to get localtime, not GMT, in this bit
		   (I think, this needs testing) */
		t = LocalTime(&unixdate);

		SIVAL(p, 4, 0); /* msecs ? */
		CVAL(p, 8) = t->tm_hour;
		CVAL(p, 9) = t->tm_min;
		CVAL(p, 10) = t->tm_sec;
		CVAL(p, 11) = 0; /* hundredths of seconds */
		SSVALS(p, 12,
		       TimeDiff(unixdate) /
		           60);      /* timezone in minutes from GMT */
		SSVAL(p, 14, 10000); /* timer interval in 0.0001 of sec */
		CVAL(p, 16) = t->tm_mday;
		CVAL(p, 17) = t->tm_mon + 1;
		SSVAL(p, 18, 1900 + t->tm_year);
		CVAL(p, 20) = t->tm_wday;
	}

	return (True);
}

/****************************************************************************
  get info about the server
  ****************************************************************************/
static BOOL api_RNetServerGetInfo(int cnum, char *param,
                                  char *data, int mdrcnt, int mprcnt,
                                  char **rdata, char **rparam, int *rdata_len,
                                  int *rparam_len)
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
		return False;
	switch (uLevel) {
	case 0:
		if (strcmp(str2, "B16") != 0)
			return False;
		struct_len = 16;
		break;
	case 1:
		if (strcmp(str2, "B16BBDz") != 0)
			return False;
		struct_len = 26;
		break;
	case 2:
		if (strcmp(
		        str2,
		        "B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWWWWz") !=
		    0)
			return False;
		struct_len = 134;
		break;
	case 3:
		if (strcmp(str2, "B16BBDzDDDWWzWWWWWWWBB21zWWWWWWWWWWWWWWWWWWWW"
		                 "WWzDWz") != 0)
			return False;
		struct_len = 144;
		break;
	case 20:
		if (strcmp(str2, "DN") != 0)
			return False;
		struct_len = 6;
		break;
	case 50:
		if (strcmp(str2, "B16BBDzWWzzz") != 0)
			return False;
		struct_len = 42;
		break;
	default:
		return False;
	}

	*rdata_len = mdrcnt;
	*rdata = REALLOC(*rdata, *rdata_len);

	p = *rdata;
	p2 = p + struct_len;
	if (uLevel != 20) {
		StrnCpy(p, local_machine, 16);
		strupper(p);
	}
	p += 16;
	if (uLevel > 0) {
		struct srv_info_struct *servers = NULL;
		int i, count;
		pstring comment;
		uint32 servertype = SV_TYPE_WIN95_PLUS;

		pstrcpy(comment, lp_serverstring());

		if ((count = get_server_info(SV_TYPE_ALL, &servers,
		                             myworkgroup)) > 0) {
			for (i = 0; i < count; i++)
				if (strequal(servers[i].name, local_machine)) {
					servertype = servers[i].type;
					pstrcpy(comment, servers[i].comment);
				}
		}
		if (servers)
			free(servers);

		SCVAL(p, 0, DEFAULT_MAJOR_VERSION);
		SCVAL(p, 1, DEFAULT_MINOR_VERSION);
		SIVAL(p, 2, servertype);

		if (mdrcnt == struct_len) {
			SIVAL(p, 6, 0);
		} else {
			SIVAL(p, 6, PTR_DIFF(p2, *rdata));
			standard_sub(cnum, comment);
			StrnCpy(p2, comment, MAX(mdrcnt - struct_len, 0));
			p2 = skip_string(p2, 1);
		}
	}
	if (uLevel > 1) {
		return False; /* not yet implemented */
	}

	*rdata_len = PTR_DIFF(p2, *rdata);

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);
	SSVAL(*rparam, 0, NERR_Success);
	SSVAL(*rparam, 2, 0); /* converter word */
	SSVAL(*rparam, 4, *rdata_len);

	return (True);
}

/****************************************************************************
  get info about the server
  ****************************************************************************/
static BOOL api_NetWkstaGetInfo(int cnum, char *param, char *data,
                                int mdrcnt, int mprcnt, char **rdata,
                                char **rparam, int *rdata_len, int *rparam_len)
{
	char *str1 = param + 2;
	char *str2 = skip_string(str1, 1);
	char *p = skip_string(str2, 1);
	char *p2;
	extern pstring sesssetup_user;
	int level = SVAL(p, 0);

	DEBUG(4, ("NetWkstaGetInfo level %d\n", level));

	*rparam_len = 6;
	*rparam = REALLOC(*rparam, *rparam_len);

	/* check it's a supported varient */
	if (!(level == 10 && strcsequal(str1, "WrLh") &&
	      strcsequal(str2, "zzzBBzz")))
		return (False);

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
	pstrcpy(p2, sesssetup_user);
	p2 = skip_string(p2, 1);
	p += 4;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata)); /* login domain */
	pstrcpy(p2, myworkgroup);
	strupper(p2);
	p2 = skip_string(p2, 1);
	p += 4;

	SCVAL(p, 0,
	      DEFAULT_MAJOR_VERSION); /* system version - e.g 4 in 4.1 */
	SCVAL(p, 1,
	      DEFAULT_MINOR_VERSION); /* system version - e.g .1 in 4.1 */
	p += 2;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata));
	pstrcpy(p2, myworkgroup); /* don't know.  login domain?? */
	p2 = skip_string(p2, 1);
	p += 4;

	SIVAL(p, 0, PTR_DIFF(p2, *rdata)); /* don't know */
	pstrcpy(p2, "");
	p2 = skip_string(p2, 1);
	p += 4;

	*rdata_len = PTR_DIFF(p2, *rdata);

	SSVAL(*rparam, 4, *rdata_len);

	return (True);
}

/****************************************************************************
  the buffer was too small
  ****************************************************************************/
static BOOL api_TooSmall(int cnum, char *param, char *data,
                         int mdrcnt, int mprcnt, char **rdata, char **rparam,
                         int *rdata_len, int *rparam_len)
{
	*rparam_len = MIN(*rparam_len, mprcnt);
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_BufTooSmall);

	DEBUG(3, ("Supplied buffer too small in API command\n"));

	return (True);
}

/****************************************************************************
  the request is not supported
  ****************************************************************************/
static BOOL api_Unsupported(int cnum, char *param, char *data,
                            int mdrcnt, int mprcnt, char **rdata, char **rparam,
                            int *rdata_len, int *rparam_len)
{
	*rparam_len = 4;
	*rparam = REALLOC(*rparam, *rparam_len);

	*rdata_len = 0;

	SSVAL(*rparam, 0, NERR_notsupported);
	SSVAL(*rparam, 2, 0); /* converter word */

	DEBUG(3, ("Unsupported API command\n"));

	return (True);
}

struct {
	char *name;
	int id;
	BOOL (*fn)(int, char *, char *, int, int, char **, char **,
	           int *, int *);
	int flags;
} api_commands[] = {{"RNetShareEnum", 0, api_RNetShareEnum, 0},
                    {"RNetShareGetInfo", 1, api_RNetShareGetInfo, 0},
                    {"RNetServerGetInfo", 13, api_RNetServerGetInfo, 0},
                    {"NetWkstaGetInfo", 63, api_NetWkstaGetInfo, 0},
                    {"NetRemoteTOD", 91, api_NetRemoteTOD, 0},
                    {"NetServerEnum", 104, api_RNetServerEnum, 0},
                    {NULL, -1, api_Unsupported, 0}};

/****************************************************************************
  handle remote api calls
  ****************************************************************************/
static int api_reply(int cnum, char *outbuf, char *data,
                     char *params, int tdscnt, int tpscnt, int mdrcnt,
                     int mprcnt)
{
	int api_command = SVAL(params, 0);
	char *rdata = NULL;
	char *rparam = NULL;
	int rdata_len = 0;
	int rparam_len = 0;
	BOOL reply = False;
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

	rdata = (char *) malloc(1024);
	if (rdata)
		bzero(rdata, 1024);
	rparam = (char *) malloc(1024);
	if (rparam)
		bzero(rparam, 1024);

	reply = api_commands[i].fn(cnum, params, data, mdrcnt, mprcnt,
	                           &rdata, &rparam, &rdata_len, &rparam_len);

	if (rdata_len > mdrcnt || rparam_len > mprcnt) {
		reply = api_TooSmall(cnum, params, data, mdrcnt, mprcnt,
		                     &rdata, &rparam, &rdata_len, &rparam_len);
	}

	/* if we get False back then it's actually unsupported */
	if (!reply)
		api_Unsupported(cnum, params, data, mdrcnt, mprcnt,
		                &rdata, &rparam, &rdata_len, &rparam_len);

	/* now send the reply */
	send_trans_reply(outbuf, rdata, rparam, NULL, rdata_len, rparam_len, 0);

	if (rdata)
		free(rdata);
	if (rparam)
		free(rparam);

	return (-1);
}

/****************************************************************************
  handle named pipe commands
  ****************************************************************************/
static int named_pipe(int cnum, char *outbuf, char *name,
                      uint16 *setup, char *data, char *params, int suwcnt,
                      int tdscnt, int tpscnt, int msrcnt, int mdrcnt,
                      int mprcnt)
{
	DEBUG(3, ("named pipe command on <%s> name\n", name));

	if (strequal(name, "LANMAN")) {
		return api_reply(cnum, outbuf, data, params, tdscnt,
		                 tpscnt, mdrcnt, mprcnt);
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
	uint16 *setup = NULL;

	int outsize = 0;
	int cnum = SVAL(inbuf, smb_tid);
	int tpscnt = SVAL(inbuf, smb_vwv0);
	int tdscnt = SVAL(inbuf, smb_vwv1);
	int mprcnt = SVAL(inbuf, smb_vwv2);
	int mdrcnt = SVAL(inbuf, smb_vwv3);
	int msrcnt = CVAL(inbuf, smb_vwv4);
	BOOL close_on_completion = BITSETW(inbuf + smb_vwv5, 0);
	BOOL one_way = BITSETW(inbuf + smb_vwv5, 1);
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
		data = (char *) malloc(tdscnt);
		memcpy(data, smb_base(inbuf) + dsoff, dscnt);
	}
	if (tpscnt) {
		params = (char *) malloc(tpscnt);
		memcpy(params, smb_base(inbuf) + psoff, pscnt);
	}

	if (suwcnt) {
		int i;
		setup = (uint16 *) malloc(suwcnt * sizeof(setup[0]));
		for (i = 0; i < suwcnt; i++)
			setup[i] = SVAL(inbuf, smb_vwv14 + i * SIZEOFWORD);
	}

	if (pscnt < tpscnt || dscnt < tdscnt) {
		/* We need to send an interim response then receive the rest
		   of the parameter/data bytes */
		outsize = set_message(outbuf, 0, 0, True);
		show_msg(outbuf);
		send_smb(Client, outbuf);
	}

	/* receive the rest of the trans packet */
	while (pscnt < tpscnt || dscnt < tdscnt) {
		BOOL ret;
		int pcnt, poff, dcnt, doff, pdisp, ddisp;

		ret = receive_next_smb(Client, oplock_sock, inbuf, bufsize,
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
			if (params)
				free(params);
			if (data)
				free(data);
			if (setup)
				free(setup);
			return (ERROR(ERRSRV, ERRerror));
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
		outsize = named_pipe(
		    cnum, outbuf, name + strlen("\\PIPE\\"), setup, data,
		    params, suwcnt, tdscnt, tpscnt, msrcnt, mdrcnt, mprcnt);
	} else {
		DEBUG(3, ("invalid pipe name\n"));
		outsize = 0;
	}

	if (data)
		free(data);
	if (params)
		free(params);
	if (setup)
		free(setup);

	if (close_on_completion)
		close_cnum(cnum);

	if (one_way)
		return (-1);

	if (outsize == 0)
		return (ERROR(ERRSRV, ERRnosupport));

	return (outsize);
}
