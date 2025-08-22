/*
 * Copyright (c) 1992-1998 Andrew Tridgell
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

/* This file handles most of the reply_ calls that the server
   makes to handle specific protocols */

#include "reply.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "byteorder.h"
#include "dir.h"
#include "guards.h" /* IWYU pragma: keep */
#include "locking.h"
#include "mangle.h"
#include "server.h"
#include "shares.h"
#include "smb.h"
#include "strfunc.h"
#include "system.h"
#include "timefunc.h"
#include "trans2.h"
#include "util.h"
#include "version.h"

/* this macro should always be used to extract an fnum (smb_fid) from
a packet to ensure chaining works correctly */
#define GETFNUM(buf, where) (chain_fnum != -1 ? chain_fnum : SVAL(buf, where))

/****************************************************************************
  reply to an special message
****************************************************************************/
int reply_special(char *inbuf, char *outbuf)
{
	int outsize = 4;
	int msg_type = CVAL(inbuf, 0);
	int msg_flags = CVAL(inbuf, 1);
	pstring name1, name2;
	int len;
	char name_type = 0;

	*name1 = *name2 = 0;

	smb_setlen(outbuf, 0);

	switch (msg_type) {
	case 0x81: /* session request */
		CVAL(outbuf, 0) = 0x82;
		CVAL(outbuf, 3) = 0;
		if (name_len(inbuf + 4) > 50 ||
		    name_len(inbuf + 4 + name_len(inbuf + 4)) > 50) {
			ERROR("Invalid name length in session request\n");
			return 0;
		}
		name_extract(inbuf, 4, name1);
		name_extract(inbuf, 4 + name_len(inbuf + 4), name2);
		DEBUG("netbios connect: name1=%s name2=%s\n", name1, name2);

		fstrcpy(local_machine, name1);
		len = strlen(local_machine);
		if (len == 16) {
			name_type = local_machine[15];
			local_machine[15] = 0;
		}
		trim_string(local_machine, " ", " ");
		strlower(local_machine);

		if (name_type == 'R') {
			/* We are being asked for a pathworks session ---
			   no thanks! */
			CVAL(outbuf, 0) = 0x83;
			break;
		}

		break;

	case 0x89: /* session keepalive request
	              (some old clients produce this?) */
		CVAL(outbuf, 0) = 0x85;
		CVAL(outbuf, 3) = 0;
		break;

	case 0x82: /* positive session response */
	case 0x83: /* negative session response */
	case 0x84: /* retarget session response */
		ERROR("Unexpected session response\n");
		break;

	case 0x85: /* session keepalive */
	default:
		return 0;
	}

	DEBUG("init msg_type=0x%x msg_flags=0x%x\n", msg_type, msg_flags);

	return outsize;
}

/*******************************************************************
work out what error to give to a failed connection
********************************************************************/
static int connection_error(char *inbuf, char *outbuf, int connection_num)
{
	switch (connection_num) {
	case -8:
		return ERROR_CODE(ERRSRV, ERRnoresource);
	case -7:
		return ERROR_CODE(ERRSRV, ERRbaduid);
	case -6:
		return ERROR_CODE(ERRSRV, ERRinvdevice);
	case -5:
		return ERROR_CODE(ERRSRV, ERRinvnetname);
	case -4:
		return ERROR_CODE(ERRSRV, ERRaccess);
	case -3:
		return ERROR_CODE(ERRDOS, ERRnoipc);
	case -2:
		return ERROR_CODE(ERRSRV, ERRinvnetname);
	}
	return ERROR_CODE(ERRSRV, ERRbadpw);
}

/****************************************************************************
  parse a share descriptor string
****************************************************************************/
static void parse_connect(char *p, char *service, char *dev)
{
	char *p2;

	DEBUG("parsing connect string %s\n", p);

	p2 = strrchr(p, '\\');
	if (p2 == NULL)
		fstrcpy(service, p);
	else
		fstrcpy(service, p2 + 1);

	p += strlen(p) + 2;

	/* Skip password */
	p += strlen(p) + 2;

	fstrcpy(dev, p);

	p = strchr(service, '%');
	if (p != NULL) {
		*p = 0;
	}
}

/****************************************************************************
  reply to a tcon
****************************************************************************/
int reply_tcon(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring service;
	pstring dev;
	int connection_num;
	int outsize = 0;

	*service = *dev = 0;

	parse_connect(smb_buf(inbuf) + 1, service, dev);

	connection_num = make_connection(service, dev);

	if (connection_num < 0)
		return connection_error(inbuf, outbuf, connection_num);

	outsize = set_message(outbuf, 2, 0, true);
	SSVAL(outbuf, smb_vwv0, BUFFER_SIZE);
	SSVAL(outbuf, smb_vwv1, connection_num);
	SSVAL(outbuf, smb_tid, connection_num);

	DEBUG("service=%s cnum=%d\n", service, connection_num);

	return outsize;
}

/****************************************************************************
  reply to a tcon and X
****************************************************************************/
int reply_tcon_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	pstring service;
	pstring devicename;
	int connection_num;
	int passlen = SVAL(inbuf, smb_vwv3);
	char *path, *p;

	*service = *devicename = 0;

	/* we might have to close an old one */
	if ((SVAL(inbuf, smb_vwv2) & 0x1) != 0)
		close_cnum(SVAL(inbuf, smb_tid));

	path = smb_buf(inbuf) + passlen;

	fstrcpy(service, path + 2);
	p = strchr(service, '\\');
	if (!p)
		return ERROR_CODE(ERRSRV, ERRinvnetname);
	*p = 0;
	fstrcpy(service, p + 1);
	p = strchr(service, '%');
	if (p) {
		*p++ = 0;
	}
	strlcpy(devicename, path + strlen(path) + 1, 7);
	DEBUG("Got device type %s\n", devicename);

	connection_num = make_connection(service, devicename);

	if (connection_num < 0)
		return connection_error(inbuf, outbuf, connection_num);

	if (Protocol < PROTOCOL_NT1) {
		set_message(outbuf, 2, strlen(devicename) + 1, true);
		pstrcpy(smb_buf(outbuf), devicename);
	} else {
		char *fsname = "SAMBA";
		char *p;

		set_message(outbuf, 3, 3, true);

		p = smb_buf(outbuf);
		pstrcpy(p, devicename);
		p = skip_string(p, 1); /* device name */
		pstrcpy(p, fsname);
		p = skip_string(p, 1); /* filesystem type e.g NTFS */

		set_message(outbuf, 3, PTR_DIFF(p, smb_buf(outbuf)), false);

		SSVAL(outbuf, smb_vwv2, 0x0); /* optional support */
	}

	DEBUG("service=%s cnum=%d\n", service, connection_num);

	/* set the incoming and outgoing tid to the just created one */
	SSVAL(inbuf, smb_tid, connection_num);
	SSVAL(outbuf, smb_tid, connection_num);

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to an unknown type
****************************************************************************/
int reply_unknown(char *inbuf, char *outbuf)
{
	int cnum;
	int type;
	cnum = SVAL(inbuf, smb_tid);
	type = CVAL(inbuf, smb_com);

	ERROR("unknown command type (%s): cnum=%d type=%d (0x%X)\n",
	      smb_fn_name(type), cnum, type, type);

	return ERROR_CODE(ERRSRV, ERRunknownsmb);
}

/****************************************************************************
  reply to an ioctl
****************************************************************************/
int reply_ioctl(char *inbuf, char *outbuf, int size, int bufsize)
{
	DEBUG("ignoring ioctl\n");
	return ERROR_CODE(ERRSRV, ERRnosupport);
}

/****************************************************************************
reply to a session setup command
****************************************************************************/
int reply_sesssetup_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	int smb_bufsize;
	pstring smb_apasswd;
	pstring smb_ntpasswd;
	bool computer_id = false;
	static bool done_sesssetup = false;

	*smb_apasswd = 0;
	*smb_ntpasswd = 0;

	smb_bufsize = SVAL(inbuf, smb_vwv2);

	/* it's ok - setup a reply */
	if (Protocol < PROTOCOL_NT1) {
		set_message(outbuf, 3, 0, true);
	} else {
		char *p;
		set_message(outbuf, 3, 3, true);
		p = smb_buf(outbuf);
		pstrcpy(p, "Unix");
		p = skip_string(p, 1);
		pstrcpy(p, "Tumba ");
		pstrcat(p, VERSION);
		p = skip_string(p, 1);
		pstrcpy(p, workgroup);
		p = skip_string(p, 1);
		set_message(outbuf, 3, PTR_DIFF(p, smb_buf(outbuf)), false);
		/* perhaps grab OS version here?? */
	}

	if (!computer_id)
		SSVAL(outbuf, smb_vwv2, 1);

	SSVAL(outbuf, smb_uid, UID_FIELD_INVALID);
	SSVAL(inbuf, smb_uid, UID_FIELD_INVALID);

	if (!done_sesssetup)
		max_send = MIN(max_send, smb_bufsize);

	DEBUG("Client requested max send size of %d\n", max_send);

	done_sesssetup = true;

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a chkpth
****************************************************************************/
int reply_chkpth(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	int cnum, mode;
	pstring name;
	bool ok = false;
	bool bad_path = false;

	cnum = SVAL(inbuf, smb_tid);

	pstrcpy(name, smb_buf(inbuf) + 1);
	unix_convert(name, cnum, 0, &bad_path);

	mode = SVAL(inbuf, smb_vwv0);

	if (check_name(name, cnum))
		ok = directory_exist(name, NULL);

	if (!ok) {
		/* We special case this - as when a Windows machine
		   is parsing a path is steps through the components
		   one at a time - if a component fails it expects
		   ERRbadpath, not ERRbadfile.
		 */
		if (errno == ENOENT) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}

		return UNIX_ERROR_CODE(ERRDOS, ERRbadpath);
	}

	outsize = set_message(outbuf, 0, 0, true);

	DEBUG("name=%s cnum=%d mode=%d\n", name, cnum, mode);

	return outsize;
}

/****************************************************************************
  reply to a getatr
****************************************************************************/
int reply_getatr(char *inbuf, char *outbuf, int in_size, int buffsize)
{
	pstring fname;
	int cnum;
	int outsize = 0;
	struct stat sbuf;
	bool ok = false;
	int mode = 0;
	uint32_t size = 0;
	time_t mtime = 0;
	bool bad_path = false;

	cnum = SVAL(inbuf, smb_tid);

	pstrcpy(fname, smb_buf(inbuf) + 1);
	unix_convert(fname, cnum, 0, &bad_path);

	/* dos smetimes asks for a stat of "" - it returns a "hidden directory"
	   under WfWg - weird! */
	if (!*fname) {
		mode = aHIDDEN | aDIR;
		if (!CAN_WRITE(cnum))
			mode |= aRONLY;
		size = 0;
		mtime = 0;
		ok = true;
	} else if (check_name(fname, cnum)) {
		if (stat(fname, &sbuf) == 0) {
			mode = dos_mode(cnum, fname, &sbuf);
			size = sbuf.st_size;
			mtime = sbuf.st_mtime;
			if (mode & aDIR)
				size = 0;
			ok = true;
		} else
			DEBUG("stat of %s failed (%s)\n", fname,
			      strerror(errno));
	}

	if (!ok) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}

		return UNIX_ERROR_CODE(ERRDOS, ERRbadfile);
	}

	outsize = set_message(outbuf, 10, 0, true);

	SSVAL(outbuf, smb_vwv0, mode);
	put_dos_date3(outbuf, smb_vwv1, mtime);
	SIVAL(outbuf, smb_vwv3, size);

	if (Protocol >= PROTOCOL_NT1) {
		uint16_t flg2 = SVAL(outbuf, smb_flg2);
		if (!is_8_3(fname, true))
			SSVAL(outbuf, smb_flg2, flg2 | 0x40); /* IS_LONG_NAME */
	}

	DEBUG("name=%s mode=%d size=%d\n", fname, mode, size);

	return outsize;
}

/****************************************************************************
  reply to a setatr
****************************************************************************/
int reply_setatr(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int cnum;
	int outsize = 0;
	bool ok = false;
	int mode;
	time_t mtime;
	bool bad_path = false;

	cnum = SVAL(inbuf, smb_tid);

	pstrcpy(fname, smb_buf(inbuf) + 1);
	unix_convert(fname, cnum, 0, &bad_path);

	mode = SVAL(inbuf, smb_vwv0);
	mtime = make_unix_date3(inbuf + smb_vwv1);

	if (directory_exist(fname, NULL))
		mode |= aDIR;
	if (check_name(fname, cnum))
		ok = (dos_chmod(cnum, fname, mode, NULL) == 0);
	if (ok)
		ok = set_filetime(cnum, fname, mtime);

	if (!ok) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}

		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	outsize = set_message(outbuf, 0, 0, true);

	DEBUG("name=%s mode=%d\n", fname, mode);

	return outsize;
}

/****************************************************************************
  reply to a dskattr
****************************************************************************/
int reply_dskattr(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum;
	int outsize = 0;
	int dfree, dsize, bsize;

	cnum = SVAL(inbuf, smb_tid);

	sys_disk_free(".", &bsize, &dfree, &dsize);

	outsize = set_message(outbuf, 5, 0, true);

	SSVAL(outbuf, smb_vwv0, dsize);
	SSVAL(outbuf, smb_vwv1, bsize / 512);
	SSVAL(outbuf, smb_vwv2, 512);
	SSVAL(outbuf, smb_vwv3, dfree);

	DEBUG("cnum=%d dfree=%d\n", cnum, dfree);

	return outsize;
}

/****************************************************************************
  make a dir struct
****************************************************************************/
static void make_dir_struct(char *buf, char *mask, char *fname,
                            unsigned int size, int mode, time_t date)
{
	char *p;
	pstring mask2;

	pstrcpy(mask2, mask);

	if ((mode & aDIR) != 0)
		size = 0;

	memset(buf + 1, ' ', 11);
	if ((p = strchr(mask2, '.')) != NULL) {
		*p = 0;
		memcpy(buf + 1, mask2, MIN(strlen(mask2), 8));
		memcpy(buf + 9, p + 1, MIN(strlen(p + 1), 3));
		*p = '.';
	} else
		memcpy(buf + 1, mask2, MIN(strlen(mask2), 11));

	bzero(buf + 21, DIR_STRUCT_SIZE - 21);
	CVAL(buf, 21) = mode;
	put_dos_date(buf, 22, date);
	SSVAL(buf, 26, size & 0xFFFF);
	SSVAL(buf, 28, size >> 16);
	strlcpy(buf + 30, fname, 13);
	strupper(buf + 30);
	DEBUG("put name [%s] into dir struct\n", buf + 30);
}

/****************************************************************************
  reply to a search
  Can be called from SMBsearch, SMBffirst or SMBfunique.
****************************************************************************/
int reply_search(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring mask;
	pstring directory;
	pstring fname;
	int size, mode;
	time_t date;
	int dirtype;
	int cnum;
	int outsize = 0;
	int numentries = 0;
	bool finished = false;
	int maxentries;
	int i;
	char *p;
	bool ok = false;
	int status_len;
	char *path;
	char status[21];
	int dptr_num = -1;
	bool expect_close = false;
	bool can_open = true;
	bool bad_path = false;

	*mask = *directory = *fname = 0;

	/* If we were called as SMBffirst then we must expect close. */
	if (CVAL(inbuf, smb_com) == SMBffirst)
		expect_close = true;

	cnum = SVAL(inbuf, smb_tid);

	outsize = set_message(outbuf, 1, 3, true);
	maxentries = SVAL(inbuf, smb_vwv0);
	dirtype = SVAL(inbuf, smb_vwv1);
	path = smb_buf(inbuf) + 1;
	status_len = SVAL(smb_buf(inbuf), 3 + strlen(path));

	/* dirtype &= ~aDIR; */

	DEBUG("path=%s status_len=%d\n", path, status_len);

	if (status_len == 0) {
		pstring dir2;

		pstrcpy(directory, smb_buf(inbuf) + 1);
		pstrcpy(dir2, smb_buf(inbuf) + 1);
		unix_convert(directory, cnum, 0, &bad_path);
		unix_format(dir2);

		if (!check_name(directory, cnum))
			can_open = false;

		p = strrchr(dir2, '/');
		if (p == NULL) {
			pstrcpy(mask, dir2);
			*dir2 = 0;
		} else {
			*p = 0;
			pstrcpy(mask, p + 1);
		}

		p = strrchr(directory, '/');
		if (!p)
			*directory = 0;
		else
			*p = 0;

		if (strlen(directory) == 0)
			pstrcpy(directory, "./");
		bzero(status, 21);
		CVAL(status, 0) = dirtype;
	} else {
		memcpy(status, smb_buf(inbuf) + 1 + strlen(path) + 4, 21);
		memcpy(mask, status + 1, 11);
		mask[11] = 0;
		dirtype = CVAL(status, 0) & 0x1F;
		Connections[cnum].dirptr = dptr_fetch(status + 12, &dptr_num);
		if (!Connections[cnum].dirptr)
			goto search_empty;
		string_set(&Connections[cnum].dirpath, dptr_path(dptr_num));
		strnorm(mask);
	}

	/* turn strings of spaces into a . */
	trim_string(mask, NULL, " ");
	if ((p = strrchr(mask, ' '))) {
		fstring ext;
		fstrcpy(ext, p + 1);
		*p = 0;
		trim_string(mask, NULL, " ");
		pstrcat(mask, ".");
		pstrcat(mask, ext);
	}

	/* Convert the formatted mask. (This code lives in trans2.c) */
	mask_convert(mask);

	for (p = mask; *p != '\0'; ++p) {
		if (*p != '?' && *p != '*' && !isdoschar(*p)) {
			DEBUG("Invalid char [%c] in search mask?\n", *p);
			*p = '?';
		}
	}

	if (!strchr(mask, '.') && strlen(mask) > 8) {
		fstring tmp;
		fstrcpy(tmp, &mask[8]);
		mask[8] = '.';
		mask[9] = 0;
		pstrcat(mask, tmp);
	}

	DEBUG("mask=%s directory=%s\n", mask, directory);

	if (can_open) {
		p = smb_buf(outbuf) + 3;

		ok = true;

		if (status_len == 0) {
			dptr_num = dptr_create(cnum, directory, expect_close,
			                       SVAL(inbuf, smb_pid));
			if (dptr_num < 0) {
				if (dptr_num == -2) {
					if (errno == ENOENT && bad_path) {
						unix_ERR_class = ERRDOS;
						unix_ERR_code = ERRbadpath;
					}
					return UNIX_ERROR_CODE(ERRDOS,
					                       ERRnofids);
				}
				return ERROR_CODE(ERRDOS, ERRnofids);
			}
		}

		DEBUG("dptr_num is %d\n", dptr_num);

		if (ok) {
			if ((dirtype & 0x1F) == aVOLID) {
				memcpy(p, status, 21);
				make_dir_struct(p, "???????????",
				                CONN_SHARE(cnum)->name, 0,
				                aVOLID, 0);
				dptr_fill(p + 12, dptr_num);
				if (dptr_zero(p + 12) && status_len == 0)
					numentries = 1;
				else
					numentries = 0;
			} else {
				for (i = numentries;
				     i < maxentries && !finished; i++) {
					/* check to make sure we have room in
					 * the buffer */
					if (PTR_DIFF(p, outbuf) +
					        DIR_STRUCT_SIZE >
					    BUFFER_SIZE) {
						break;
					}
					finished = !get_dir_entry(
					    cnum, mask, dirtype, fname, &size,
					    &mode, &date);
					if (!finished) {
						memcpy(p, status, 21);
						make_dir_struct(p, mask, fname,
						                size, mode,
						                date);
						dptr_fill(p + 12, dptr_num);
						numentries++;
					}
					p += DIR_STRUCT_SIZE;
				}
			}
		}
	}

search_empty:

	if (numentries == 0 || !ok) {
		CVAL(outbuf, smb_rcls) = ERRDOS;
		SSVAL(outbuf, smb_err, ERRnofiles);
	}

	/* If we were called as SMBffirst with smb_search_id == NULL
	   and no entries were found then return error and close dirptr
	   (X/Open spec) */

	if (ok && expect_close && numentries == 0 && status_len == 0) {
		CVAL(outbuf, smb_rcls) = ERRDOS;
		SSVAL(outbuf, smb_err, ERRnofiles);
		/* Also close the dptr - we know it's gone */
		dptr_close(dptr_num);
	}

	/* If we were called as SMBfunique, then we can close the dirptr now !
	 */
	if (dptr_num >= 0 && CVAL(inbuf, smb_com) == SMBfunique)
		dptr_close(dptr_num);

	SSVAL(outbuf, smb_vwv0, numentries);
	SSVAL(outbuf, smb_vwv1, 3 + numentries * DIR_STRUCT_SIZE);
	CVAL(smb_buf(outbuf), 0) = 5;
	SSVAL(smb_buf(outbuf), 1, numentries * DIR_STRUCT_SIZE);

	if (Protocol >= PROTOCOL_NT1) {
		uint16_t flg2 = SVAL(outbuf, smb_flg2);
		SSVAL(outbuf, smb_flg2, flg2 | 0x40); /* IS_LONG_NAME */
	}

	outsize += DIR_STRUCT_SIZE * numentries;
	smb_setlen(outbuf, outsize - 4);

	if (!*directory && dptr_path(dptr_num))
		snprintf(directory, sizeof(directory), "(%s)",
		         dptr_path(dptr_num));

	DEBUG("%s mask=%s path=%s cnum=%d dtype=%d nument=%d of %d\n",
	      smb_fn_name(CVAL(inbuf, smb_com)), mask, directory, cnum, dirtype,
	      numentries, maxentries);

	return outsize;
}

/****************************************************************************
  reply to a fclose (stop directory search)
****************************************************************************/
int reply_fclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum;
	int outsize = 0;
	int status_len;
	char *path;
	char status[21];
	int dptr_num = -1;

	cnum = SVAL(inbuf, smb_tid);

	outsize = set_message(outbuf, 1, 0, true);
	path = smb_buf(inbuf) + 1;
	status_len = SVAL(smb_buf(inbuf), 3 + strlen(path));

	if (status_len == 0)
		return ERROR_CODE(ERRSRV, ERRsrverror);

	memcpy(status, smb_buf(inbuf) + 1 + strlen(path) + 4, 21);

	if (dptr_fetch(status + 12, &dptr_num)) {
		/*  Close the dptr - we know it's gone */
		dptr_close(dptr_num);
	}

	SSVAL(outbuf, smb_vwv0, 0);

	DEBUG("search close cnum=%d\n", cnum);

	return outsize;
}

/****************************************************************************
  reply to an open
****************************************************************************/
int reply_open(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int cnum;
	int fnum = -1;
	int outsize = 0;
	int fmode = 0;
	int share_mode;
	int size = 0;
	time_t mtime = 0;
	int rmode = 0;
	struct stat sbuf;
	bool bad_path = false;
	struct open_file *fsp;

	cnum = SVAL(inbuf, smb_tid);

	share_mode = SVAL(inbuf, smb_vwv0);

	pstrcpy(fname, smb_buf(inbuf) + 1);
	unix_convert(fname, cnum, 0, &bad_path);

	fnum = find_free_file();
	if (fnum < 0)
		return ERROR_CODE(ERRSRV, ERRnofids);

	if (!check_name(fname, cnum)) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	open_file_shared(fnum, cnum, fname, share_mode, 3, aARCH, &rmode, NULL);

	fsp = &Files[fnum];

	if (!fsp->open) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	if (fstat(fsp->fd_ptr->fd, &sbuf) != 0) {
		close_file(fnum, false);
		return ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	size = sbuf.st_size;
	fmode = dos_mode(cnum, fname, &sbuf);
	mtime = sbuf.st_mtime;

	if (fmode & aDIR) {
		DEBUG("attempt to open a directory %s\n", fname);
		close_file(fnum, false);
		return ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	outsize = set_message(outbuf, 7, 0, true);
	SSVAL(outbuf, smb_vwv0, fnum);
	SSVAL(outbuf, smb_vwv1, fmode);
	put_dos_date3(outbuf, smb_vwv2, mtime);
	SIVAL(outbuf, smb_vwv4, size);
	SSVAL(outbuf, smb_vwv6, rmode);
	/* Note we grant no oplocks. See comment in reply_open_and_X() */

	return outsize;
}

/****************************************************************************
  reply to an open and X
****************************************************************************/
int reply_open_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	pstring fname;
	int cnum = SVAL(inbuf, smb_tid);
	int fnum = -1;
	int smb_mode = SVAL(inbuf, smb_vwv3);
	int smb_attr = SVAL(inbuf, smb_vwv5);
	int smb_ofun = SVAL(inbuf, smb_vwv8);
	int size = 0, fmode = 0, mtime = 0, rmode = 0;
	struct stat sbuf;
	int smb_action = 0;
	bool bad_path = false;
	struct open_file *fsp;

	/* XXXX we need to handle passed times, sattr and flags */

	pstrcpy(fname, smb_buf(inbuf));
	unix_convert(fname, cnum, 0, &bad_path);

	/* NT uses named pipes to do browsing (opens PIPE/srvsvc). We don't
	   support this, but if we send the "invalid device" error back, it
	   will fall back to the LANMAN approach instead. However, it does
	   introduce a brief pause. */
	if (CONN_SHARE(cnum) == ipc_service) {
		WARNING("Tried to open IPC %s\n", fname);
		return ERROR_CODE(ERRSRV, ERRinvdevice);
	}

	fnum = find_free_file();
	if (fnum < 0)
		return ERROR_CODE(ERRSRV, ERRnofids);

	if (!check_name(fname, cnum)) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	open_file_shared(fnum, cnum, fname, smb_mode, smb_ofun,
	                 smb_attr | aARCH, &rmode, &smb_action);

	fsp = &Files[fnum];

	if (!fsp->open) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	if (fstat(fsp->fd_ptr->fd, &sbuf) != 0) {
		close_file(fnum, false);
		return ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	size = sbuf.st_size;
	fmode = dos_mode(cnum, fname, &sbuf);
	mtime = sbuf.st_mtime;
	if (fmode & aDIR) {
		close_file(fnum, false);
		return ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	/* The Samba version of this function had code to handle oplock
	   requests. We don't support oplocks and just grant no oplock requests,
	   which is compliant according to the CIFS draft spec:

	   > Versions of the CIFS file sharing protocol including and newer
	   > than the "LANMAN1.0" dialect support oplocks. (Note, however, that
	   > an implementation, even of these later dialects, can implement
	   > oplocks trivially by always refusing to grant them.)

	   TODO: We can improve performance by granting a fake lock if the
	   underlying filesystem is read-only (like a CD-ROM), or if we're
	   feeling a bit bolder, if the file is read-only.
	 */

	set_message(outbuf, 15, 0, true);
	SSVAL(outbuf, smb_vwv2, fnum);
	SSVAL(outbuf, smb_vwv3, fmode);
	put_dos_date3(outbuf, smb_vwv4, mtime);
	SIVAL(outbuf, smb_vwv6, size);
	SSVAL(outbuf, smb_vwv8, rmode);
	SSVAL(outbuf, smb_vwv11, smb_action);

	chain_fnum = fnum;

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a SMBulogoffX
****************************************************************************/
int reply_ulogoffX(char *inbuf, char *outbuf, int length, int bufsize)
{
	set_message(outbuf, 2, 0, true);

	DEBUG("\n");

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a mknew or a create
****************************************************************************/
int reply_mknew(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	int cnum, com;
	int fnum = -1;
	int outsize = 0;
	int createmode;
	int ofun = 0;
	bool bad_path = false;
	struct open_file *fsp;

	com = SVAL(inbuf, smb_com);
	cnum = SVAL(inbuf, smb_tid);

	createmode = SVAL(inbuf, smb_vwv0);
	pstrcpy(fname, smb_buf(inbuf) + 1);
	unix_convert(fname, cnum, 0, &bad_path);

	if (createmode & aVOLID) {
		ERROR("Attempt to create file (%s) with volid set - please "
		      "report this\n",
		      fname);
	}

	fnum = find_free_file();
	if (fnum < 0)
		return ERROR_CODE(ERRSRV, ERRnofids);

	if (!check_name(fname, cnum)) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	if (com == SMBmknew) {
		/* We should fail if file exists. */
		ofun = 0x10;
	} else {
		/* SMBcreate - Create if file doesn't exist, truncate if it
		 * does. */
		ofun = 0x12;
	}

	/* Open file in dos compatibility share mode. */
	open_file_shared(fnum, cnum, fname, (DENY_FCB << 4) | 0xF, ofun,
	                 createmode, NULL, NULL);

	fsp = &Files[fnum];

	if (!fsp->open) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	outsize = set_message(outbuf, 1, 0, true);
	SSVAL(outbuf, smb_vwv0, fnum);
	/* Note we grant no oplocks. See comment in reply_open_and_X() */

	DEBUG("new file %s\n", fname);
	DEBUG("fname=%s fd=%d fnum=%d cnum=%d dmode=%d\n", fname,
	      Files[fnum].fd_ptr->fd, fnum, cnum, createmode);

	return outsize;
}

/****************************************************************************
  reply to a create temporary file
****************************************************************************/
int reply_ctemp(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring fname;
	pstring fname2;
	int cnum;
	int fnum = -1;
	int outsize = 0;
	int createmode;
	bool bad_path = false;
	struct open_file *fsp;

	cnum = SVAL(inbuf, smb_tid);
	createmode = SVAL(inbuf, smb_vwv0);
	pstrcpy(fname, smb_buf(inbuf) + 1);
	pstrcat(fname, "/TMXXXXXX");
	unix_convert(fname, cnum, 0, &bad_path);

	fnum = find_free_file();
	if (fnum < 0)
		return ERROR_CODE(ERRSRV, ERRnofids);

	if (!check_name(fname, cnum)) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	pstrcpy(fname2, (char *) mktemp(fname));

	/* Open file in dos compatibility share mode. */
	/* We should fail if file exists. */
	open_file_shared(fnum, cnum, fname2, (DENY_FCB << 4) | 0xF, 0x10,
	                 createmode, NULL, NULL);

	fsp = &Files[fnum];

	if (!fsp->open) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		Files[fnum].reserved = false;
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	outsize = set_message(outbuf, 1, 2 + strlen(fname2), true);
	SSVAL(outbuf, smb_vwv0, fnum);
	CVAL(smb_buf(outbuf), 0) = 4;
	pstrcpy(smb_buf(outbuf) + 1, fname2);

	/* Note we grant no oplocks. See comment in reply_open_and_X() */

	DEBUG("created temp file %s\n", fname2);
	DEBUG("fname=%s fd=%d fnum=%d cnum=%d dmode=%d\n", fname2,
	      Files[fnum].fd_ptr->fd, fnum, cnum, createmode);

	return outsize;
}

/*******************************************************************
check if a user is allowed to delete a file
********************************************************************/
static bool can_delete(char *fname, int cnum, int dirtype)
{
	struct stat sbuf;
	int fmode;

	if (!CAN_WRITE(cnum))
		return false;

	if (lstat(fname, &sbuf) != 0)
		return false;
	fmode = dos_mode(cnum, fname, &sbuf);
	if (fmode & aDIR)
		return false;
	if ((fmode & ~dirtype) & (aHIDDEN | aSYSTEM))
		return false;
	return true;
}

/****************************************************************************
  reply to a unlink
****************************************************************************/
int reply_unlink(char *inbuf, char *outbuf, int dum_size, int dum_bufsize)
{
	int outsize = 0;
	pstring name;
	int cnum;
	int dirtype;
	pstring directory;
	pstring mask;
	char *p;
	int count = 0;
	int error = ERRnoaccess;
	bool has_wild;
	bool exists = false;
	bool bad_path = false;

	*directory = *mask = 0;

	cnum = SVAL(inbuf, smb_tid);
	dirtype = SVAL(inbuf, smb_vwv0);

	pstrcpy(name, smb_buf(inbuf) + 1);

	DEBUG("name=%s\n", name);

	unix_convert(name, cnum, 0, &bad_path);

	p = strrchr(name, '/');
	if (!p) {
		pstrcpy(directory, "./");
		pstrcpy(mask, name);
	} else {
		*p = 0;
		pstrcpy(directory, name);
		pstrcpy(mask, p + 1);
	}

	has_wild = strchr(mask, '*') || strchr(mask, '?');

	if (!has_wild) {
		pstrcat(directory, "/");
		pstrcat(directory, mask);
		if (can_delete(directory, cnum, dirtype) && !unlink(directory))
			count++;
		if (!count)
			exists = file_exist(directory, NULL);
	} else {
		void *dirptr = NULL;
		char *dname;

		if (check_name(directory, cnum))
			dirptr = open_dir(cnum, directory);

		/* XXXX the CIFS spec says that if bit0 of the flags2 field is
		   set then the pattern matches against the long name, otherwise
		   the short name We don't implement this yet XXXX
		   */

		if (dirptr) {
			error = ERRbadfile;

			if (strequal(mask, "????????.???"))
				pstrcpy(mask, "*");

			while ((dname = read_dir_name(dirptr))) {
				pstring fname;
				pstrcpy(fname, dname);

				if (!mask_match(fname, mask, false)) {
					continue;
				}

				error = ERRnoaccess;
				snprintf(fname, sizeof(fname), "%s/%s",
				         directory, dname);
				if (!can_delete(fname, cnum, dirtype))
					continue;
				if (!unlink(fname))
					count++;
				DEBUG("doing unlink on %s\n", fname);
			}
			close_dir(dirptr);
		}
	}

	if (count == 0) {
		if (exists)
			return ERROR_CODE(ERRDOS, error);
		else {
			if (errno == ENOENT && bad_path) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			return UNIX_ERROR_CODE(ERRDOS, error);
		}
	}

	outsize = set_message(outbuf, 0, 0, true);

	return outsize;
}

/****************************************************************************
transfer some data between two fd's
****************************************************************************/
static int transfer_file(int infd, int outfd, int n, char *header, int headlen,
                         int align)
{
	static char *buf = NULL;
	static int size = 0;
	char *buf1, *abuf;
	int total = 0;

	DEBUG("n=%d (head=%d)\n", n, headlen);

	if (size == 0) {
		size = 16 * 1024;
	}

	while (!buf && size > 0) {
		buf = (char *) checked_realloc(buf, size + 8);
		if (!buf)
			size /= 2;
	}

	if (!buf) {
		ERROR("Can't allocate transfer buffer!\n");
		exit(1);
	}

	abuf = buf + (align % 8);

	if (header)
		n += headlen;

	while (n > 0) {
		int s = MIN(n, size);
		int ret, ret2 = 0;

		ret = 0;

		if (header && headlen >= MIN(s, 1024)) {
			buf1 = header;
			s = headlen;
			ret = headlen;
			headlen = 0;
			header = NULL;
		} else {
			buf1 = abuf;
		}

		if (header && headlen > 0) {
			ret = MIN(headlen, size);
			memcpy(buf1, header, ret);
			headlen -= ret;
			header += ret;
			if (headlen <= 0)
				header = NULL;
		}

		if (s > ret)
			ret += read(infd, buf1 + ret, s - ret);

		if (ret > 0) {
			ret2 =
			    (outfd >= 0 ? write_data(outfd, buf1, ret) : ret);
			if (ret2 > 0)
				total += ret2;
			/* if we can't write then dump excess data */
			if (ret2 != ret)
				transfer_file(infd, -1, n - (ret + headlen),
				              NULL, 0, 0);
		}
		if (ret <= 0 || ret2 != ret)
			return total;
		n -= ret;
	}
	return total;
}

/****************************************************************************
   reply to a readbraw (core+ protocol)
****************************************************************************/
int reply_readbraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, maxcount, mincount, fnum;
	int nread = 0, size, sizeneeded;
	uint32_t startpos;
	char *header = outbuf;
	int ret = 0;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	startpos = IVAL(inbuf, smb_vwv1);
	maxcount = SVAL(inbuf, smb_vwv3);
	mincount = SVAL(inbuf, smb_vwv4);

	/* ensure we don't overrun the packet size */
	maxcount = MIN(65535, maxcount);
	maxcount = MAX(mincount, maxcount);

	if (!FNUM_OK(fnum, cnum) || !Files[fnum].can_read) {
		DEBUG("fnum %d not open in readbraw - cache prime?\n", fnum);
		_smb_setlen(header, 0);
		transfer_file(0, Client, 0, header, 4, 0);
		return -1;
	}

	size = Files[fnum].size;
	sizeneeded = startpos + maxcount;

	if (size < sizeneeded) {
		struct stat st;
		if (fstat(Files[fnum].fd_ptr->fd, &st) == 0)
			size = st.st_size;
		if (!Files[fnum].can_write)
			Files[fnum].size = size;
	}

	nread = MIN(maxcount, (int) (size - startpos));

	if (nread < mincount)
		nread = 0;

	DEBUG("fnum=%d cnum=%d start=%d max=%d min=%d nread=%d\n", fnum, cnum,
	      startpos, maxcount, mincount, nread);

	ret = read_file(fnum, header + 4, startpos, nread);
	if (ret < mincount)
		ret = 0;

	_smb_setlen(header, ret);
	transfer_file(0, Client, 0, header, 4 + ret, 0);

	DEBUG("finished\n");
	return -1;
}

/****************************************************************************
  reply to a lockread (core+ protocol)
****************************************************************************/
int reply_lockread(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, fnum;
	int nread = -1;
	char *data;
	int outsize = 0;
	uint32_t startpos, numtoread;
	int eclass;
	uint32_t ecode;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_READ(fnum);
	CHECK_ERROR(fnum);

	numtoread = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv2);

	outsize = set_message(outbuf, 5, 3, true);
	numtoread = MIN(BUFFER_SIZE - outsize, numtoread);
	data = smb_buf(outbuf) + 3;

	if (!do_lock(fnum, cnum, numtoread, startpos, F_RDLCK, &eclass, &ecode))
		return ERROR_CODE(eclass, ecode);

	nread = read_file(fnum, data, startpos, numtoread);

	if (nread < 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	outsize += nread;
	SSVAL(outbuf, smb_vwv0, nread);
	SSVAL(outbuf, smb_vwv5, nread + 3);
	SSVAL(smb_buf(outbuf), 1, nread);

	DEBUG("fnum=%d cnum=%d num=%d nread=%d\n", fnum, cnum, numtoread,
	      nread);

	return outsize;
}

/****************************************************************************
  reply to a read
****************************************************************************/
int reply_read(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, numtoread, fnum;
	int nread = 0;
	char *data;
	uint32_t startpos;
	int outsize = 0;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_READ(fnum);
	CHECK_ERROR(fnum);

	numtoread = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv2);

	outsize = set_message(outbuf, 5, 3, true);
	numtoread = MIN(BUFFER_SIZE - outsize, numtoread);
	data = smb_buf(outbuf) + 3;

	if (numtoread > 0)
		nread = read_file(fnum, data, startpos, numtoread);

	if (nread < 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	outsize += nread;
	SSVAL(outbuf, smb_vwv0, nread);
	SSVAL(outbuf, smb_vwv5, nread + 3);
	CVAL(smb_buf(outbuf), 0) = 1;
	SSVAL(smb_buf(outbuf), 1, nread);

	DEBUG("fnum=%d cnum=%d num=%d nread=%d\n", fnum, cnum, numtoread,
	      nread);

	return outsize;
}

/****************************************************************************
  reply to a read and X
****************************************************************************/
int reply_read_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	int fnum = GETFNUM(inbuf, smb_vwv2);
	uint32_t smb_offs = IVAL(inbuf, smb_vwv3);
	int smb_maxcnt = SVAL(inbuf, smb_vwv5);
	int smb_mincnt = SVAL(inbuf, smb_vwv6);
	int cnum;
	int nread = -1;
	char *data;

	cnum = SVAL(inbuf, smb_tid);

	CHECK_FNUM(fnum, cnum);
	CHECK_READ(fnum);
	CHECK_ERROR(fnum);

	set_message(outbuf, 12, 0, true);
	data = smb_buf(outbuf);

	nread = read_file(fnum, data, smb_offs, smb_maxcnt);

	if (nread < 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	SSVAL(outbuf, smb_vwv5, nread);
	SSVAL(outbuf, smb_vwv6, smb_offset(data, outbuf));
	SSVAL(smb_buf(outbuf), -2, nread);

	DEBUG("fnum=%d cnum=%d min=%d max=%d nread=%d\n", fnum, cnum,
	      smb_mincnt, smb_maxcnt, nread);

	chain_fnum = fnum;

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a writebraw (core+ or LANMAN1.0 protocol)
****************************************************************************/
int reply_writebraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int nwritten = 0;
	int total_written = 0;
	int numtowrite = 0;
	int cnum, fnum;
	int outsize = 0;
	long startpos;
	char *data = NULL;
	bool write_through;
	int tcount;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);
	CHECK_ERROR(fnum);

	tcount = IVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv3);
	write_through = (SVAL(inbuf, smb_vwv7) & 1) != 0;

	/* We have to deal with slightly different formats depending
	   on whether we are using the core+ or lanman1.0 protocol */
	if (Protocol <= PROTOCOL_COREPLUS) {
		numtowrite = SVAL(smb_buf(inbuf), -2);
		data = smb_buf(inbuf);
	} else {
		numtowrite = SVAL(inbuf, smb_vwv10);
		data = smb_base(inbuf) + SVAL(inbuf, smb_vwv11);
	}

	/* force the error type */
	CVAL(inbuf, smb_com) = SMBwritec;
	CVAL(outbuf, smb_com) = SMBwritec;

	if (seek_file(fnum, startpos) != startpos)
		ERROR("couldn't seek to %ld in writebraw\n", startpos);

	if (numtowrite > 0)
		nwritten = write_file(fnum, data, numtowrite);

	DEBUG("fnum=%d cnum=%d start=%ld num=%d wrote=%d sync=%d\n", fnum, cnum,
	      startpos, numtowrite, nwritten, write_through);

	if (nwritten < numtowrite)
		return UNIX_ERROR_CODE(ERRHRD, ERRdiskfull);

	total_written = nwritten;

	/* Return a message to the redirector to tell it
	   to send more bytes */
	CVAL(outbuf, smb_com) = SMBwritebraw;
	SSVALS(outbuf, smb_vwv0, -1);
	outsize =
	    set_message(outbuf, Protocol > PROTOCOL_COREPLUS ? 1 : 0, 0, true);
	send_smb(Client, outbuf);

	/* Now read the raw data into the buffer and write it */
	if (read_smb_length(Client, inbuf, SMB_SECONDARY_WAIT) == -1) {
		exit_server("secondary writebraw failed");
	}

	/* Even though this is not an smb message, smb_len
	   returns the generic length of an smb message */
	numtowrite = smb_len(inbuf);

	if (tcount > nwritten + numtowrite) {
		DEBUG("Client overestimated the write %d %d %d\n", tcount,
		      nwritten, numtowrite);
	}

	nwritten = transfer_file(Client, Files[fnum].fd_ptr->fd, numtowrite,
	                         NULL, 0, startpos + nwritten);
	total_written += nwritten;

	/* Set up outbuf to return the correct return */
	outsize = set_message(outbuf, 1, 0, true);
	CVAL(outbuf, smb_com) = SMBwritec;
	SSVAL(outbuf, smb_vwv0, total_written);

	if (nwritten < numtowrite) {
		CVAL(outbuf, smb_rcls) = ERRHRD;
		SSVAL(outbuf, smb_err, ERRdiskfull);
	}

	DEBUG("fnum=%d cnum=%d start=%ld num=%d wrote=%d\n", fnum, cnum,
	      startpos, numtowrite, total_written);

	/* we won't return a status if write through is not selected - this
	   follows what WfWg does */
	if (!write_through && total_written == tcount)
		return -1;

	return outsize;
}

/****************************************************************************
  reply to a writeunlock (core+)
****************************************************************************/
int reply_writeunlock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, fnum;
	int nwritten = -1;
	int outsize = 0;
	char *data;
	uint32_t numtowrite, startpos;
	int eclass;
	uint32_t ecode;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);
	CHECK_ERROR(fnum);

	numtowrite = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv2);
	data = smb_buf(inbuf) + 3;

	seek_file(fnum, startpos);

	/* The special X/Open SMB protocol handling of
	   zero length writes is *NOT* done for
	   this call */
	if (numtowrite == 0)
		nwritten = 0;
	else
		nwritten = write_file(fnum, data, numtowrite);

	if ((nwritten == 0 && numtowrite != 0) || nwritten < 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	if (!do_unlock(fnum, cnum, numtowrite, startpos, &eclass, &ecode))
		return ERROR_CODE(eclass, ecode);

	outsize = set_message(outbuf, 1, 0, true);

	SSVAL(outbuf, smb_vwv0, nwritten);

	DEBUG("fnum=%d cnum=%d num=%d wrote=%d\n", fnum, cnum, numtowrite,
	      nwritten);

	return outsize;
}

/****************************************************************************
  reply to a write
****************************************************************************/
int reply_write(char *inbuf, char *outbuf, int dum1, int dum2)
{
	int cnum, numtowrite, fnum;
	int nwritten = -1;
	int outsize = 0;
	int startpos;
	char *data;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);
	CHECK_ERROR(fnum);

	numtowrite = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv2);
	data = smb_buf(inbuf) + 3;

	seek_file(fnum, startpos);

	/* X/Open SMB protocol says that if smb_vwv1 is
	   zero then the file size should be extended or
	   truncated to the size given in smb_vwv[2-3] */
	if (numtowrite != 0) {
		nwritten = write_file(fnum, data, numtowrite);
	} else {
		nwritten = ftruncate(Files[fnum].fd_ptr->fd, startpos);
	}

	if ((nwritten == 0 && numtowrite != 0) || nwritten < 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	outsize = set_message(outbuf, 1, 0, true);

	SSVAL(outbuf, smb_vwv0, nwritten);

	if (nwritten < numtowrite) {
		CVAL(outbuf, smb_rcls) = ERRHRD;
		SSVAL(outbuf, smb_err, ERRdiskfull);
	}

	DEBUG("fnum=%d cnum=%d num=%d wrote=%d\n", fnum, cnum, numtowrite,
	      nwritten);

	return outsize;
}

/****************************************************************************
  reply to a write and X
****************************************************************************/
int reply_write_and_X(char *inbuf, char *outbuf, int length, int bufsize)
{
	int fnum = GETFNUM(inbuf, smb_vwv2);
	uint32_t smb_offs = IVAL(inbuf, smb_vwv3);
	int smb_dsize = SVAL(inbuf, smb_vwv10);
	int smb_doff = SVAL(inbuf, smb_vwv11);
	int cnum;
	int nwritten = -1;
	char *data;

	cnum = SVAL(inbuf, smb_tid);

	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);
	CHECK_ERROR(fnum);

	data = smb_base(inbuf) + smb_doff;

	seek_file(fnum, smb_offs);

	/* X/Open SMB protocol says that, unlike SMBwrite
	   if the length is zero then NO truncation is
	   done, just a write of zero. To truncate a file,
	   use SMBwrite. */
	if (smb_dsize == 0)
		nwritten = 0;
	else
		nwritten = write_file(fnum, data, smb_dsize);

	if ((nwritten == 0 && smb_dsize != 0) || nwritten < 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	set_message(outbuf, 6, 0, true);

	SSVAL(outbuf, smb_vwv2, nwritten);

	if (nwritten < smb_dsize) {
		CVAL(outbuf, smb_rcls) = ERRHRD;
		SSVAL(outbuf, smb_err, ERRdiskfull);
	}

	DEBUG("fnum=%d cnum=%d num=%d wrote=%d\n", fnum, cnum, smb_dsize,
	      nwritten);

	chain_fnum = fnum;

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a lseek
****************************************************************************/
int reply_lseek(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, fnum;
	uint32_t startpos;
	int32_t res = -1;
	int mode, umode;
	int outsize = 0;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_ERROR(fnum);

	mode = SVAL(inbuf, smb_vwv1) & 3;
	startpos = IVAL(inbuf, smb_vwv2);

	switch (mode & 3) {
	case 0:
		umode = SEEK_SET;
		break;
	case 1:
		umode = SEEK_CUR;
		break;
	case 2:
		umode = SEEK_END;
		break;
	default:
		umode = SEEK_SET;
		break;
	}

	res = lseek(Files[fnum].fd_ptr->fd, startpos, umode);
	Files[fnum].pos = res;

	outsize = set_message(outbuf, 2, 0, true);
	SIVALS(outbuf, smb_vwv0, res);

	DEBUG("fnum=%d cnum=%d ofs=%d mode=%d\n", fnum, cnum, startpos, mode);

	return outsize;
}

/****************************************************************************
  reply to a flush
****************************************************************************/
int reply_flush(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, fnum;
	int outsize = set_message(outbuf, 0, 0, true);

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	if (fnum != 0xFFFF) {
		CHECK_FNUM(fnum, cnum);
		CHECK_ERROR(fnum);
	}

	DEBUG("fnum=%d\n", fnum);
	return outsize;
}

/****************************************************************************
  reply to a exit
****************************************************************************/
int reply_exit(char *inbuf, char *outbuf, int size, int bufsize)
{
	int outsize = set_message(outbuf, 0, 0, true);
	DEBUG("\n");

	return outsize;
}

/****************************************************************************
  reply to a close
****************************************************************************/
int reply_close(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int fnum, cnum;
	int outsize = 0;
	time_t mtime;
	int32_t eclass = 0, err = 0;

	outsize = set_message(outbuf, 0, 0, true);

	cnum = SVAL(inbuf, smb_tid);

	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);

	if (HAS_CACHED_ERROR_CODE(fnum)) {
		eclass = Files[fnum].wbmpx_ptr->wr_errclass;
		err = Files[fnum].wbmpx_ptr->wr_error;
	}

	mtime = make_unix_date3(inbuf + smb_vwv1);

	/* try and set the date */
	set_filetime(cnum, Files[fnum].name, mtime);

	DEBUG("fd=%d fnum=%d cnum=%d (numopen=%d)\n", Files[fnum].fd_ptr->fd,
	      fnum, cnum, Connections[cnum].num_files_open);

	close_file(fnum, true);

	/* We have a cached error */
	if (eclass || err)
		return ERROR_CODE(eclass, err);

	return outsize;
}

/****************************************************************************
  reply to a writeclose (Core+ protocol)
****************************************************************************/
int reply_writeclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, numtowrite, fnum;
	int nwritten = -1;
	int outsize = 0;
	int startpos;
	char *data;
	time_t mtime;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);
	CHECK_ERROR(fnum);

	numtowrite = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv2);
	mtime = make_unix_date3(inbuf + smb_vwv4);
	data = smb_buf(inbuf) + 1;

	seek_file(fnum, startpos);

	nwritten = write_file(fnum, data, numtowrite);

	set_filetime(cnum, Files[fnum].name, mtime);

	DEBUG("fnum=%d cnum=%d num=%d wrote=%d (numopen=%d)\n", fnum, cnum,
	      numtowrite, nwritten, Connections[cnum].num_files_open);

	close_file(fnum, true);

	if (nwritten <= 0)
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	outsize = set_message(outbuf, 1, 0, true);

	SSVAL(outbuf, smb_vwv0, nwritten);
	return outsize;
}

/****************************************************************************
  reply to a lock
****************************************************************************/
int reply_lock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int fnum, cnum;
	int outsize = set_message(outbuf, 0, 0, true);
	uint32_t count, offset;
	int eclass;
	uint32_t ecode;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_ERROR(fnum);

	count = IVAL(inbuf, smb_vwv1);
	offset = IVAL(inbuf, smb_vwv3);

	DEBUG("fd=%d fnum=%d cnum=%d ofs=%d cnt=%d\n", Files[fnum].fd_ptr->fd,
	      fnum, cnum, offset, count);

	if (!do_lock(fnum, cnum, count, offset, F_WRLCK, &eclass, &ecode))
		return ERROR_CODE(eclass, ecode);

	return outsize;
}

/****************************************************************************
  reply to a unlock
****************************************************************************/
int reply_unlock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int fnum, cnum;
	int outsize = set_message(outbuf, 0, 0, true);
	uint32_t count, offset;
	int eclass;
	uint32_t ecode;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_ERROR(fnum);

	count = IVAL(inbuf, smb_vwv1);
	offset = IVAL(inbuf, smb_vwv3);

	if (!do_unlock(fnum, cnum, count, offset, &eclass, &ecode))
		return ERROR_CODE(eclass, ecode);

	DEBUG("fd=%d fnum=%d cnum=%d ofs=%d cnt=%d\n", Files[fnum].fd_ptr->fd,
	      fnum, cnum, offset, count);

	return outsize;
}

/****************************************************************************
  reply to a tdis
****************************************************************************/
int reply_tdis(char *inbuf, char *outbuf, int size, int bufsize)
{
	int cnum;
	int outsize = set_message(outbuf, 0, 0, true);

	cnum = SVAL(inbuf, smb_tid);

	if (!OPEN_CNUM(cnum)) {
		DEBUG("Invalid cnum in tdis (%d)\n", cnum);
		return ERROR_CODE(ERRSRV, ERRinvnid);
	}

	Connections[cnum].used = false;

	close_cnum(cnum);

	DEBUG("cnum=%d\n", cnum);

	return outsize;
}

/****************************************************************************
  reply to a echo
****************************************************************************/
int reply_echo(char *inbuf, char *outbuf, int size, int bufsize)
{
	int cnum;
	int smb_reverb = SVAL(inbuf, smb_vwv0);
	int seq_num;
	int data_len = smb_buflen(inbuf);
	int outsize = set_message(outbuf, 1, data_len, true);

	cnum = SVAL(inbuf, smb_tid);

	/* According to the latest CIFS spec we shouldn't
	   care what the TID is.
	 */

	/* copy any incoming data back out */
	if (data_len > 0)
		memcpy(smb_buf(outbuf), smb_buf(inbuf), data_len);

	if (smb_reverb > 100) {
		ERROR("large reverb (%d)?? Setting to 100\n", smb_reverb);
		smb_reverb = 100;
	}

	for (seq_num = 1; seq_num <= smb_reverb; seq_num++) {
		SSVAL(outbuf, smb_vwv0, seq_num);

		smb_setlen(outbuf, outsize - 4);

		send_smb(Client, outbuf);
	}

	DEBUG("reverb=%d cnum=%d\n", smb_reverb, cnum);

	return -1;
}

/****************************************************************************
  reply to a printopen
****************************************************************************/
int reply_printopen(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	return ERROR_CODE(ERRDOS, ERRnoaccess);
}

/****************************************************************************
  reply to a printclose
****************************************************************************/
int reply_printclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	return ERROR_CODE(ERRDOS, ERRnoaccess);
}

/****************************************************************************
  reply to a printqueue
****************************************************************************/
int reply_printqueue(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	return ERROR_CODE(ERRDOS, ERRnoaccess);
}

/****************************************************************************
  reply to a printwrite
****************************************************************************/
int reply_printwrite(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	return ERROR_CODE(ERRDOS, ERRnoaccess);
}

/****************************************************************************
  reply to a mkdir
****************************************************************************/
int reply_mkdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring directory;
	int cnum;
	int outsize, ret = -1;
	bool bad_path = false;

	pstrcpy(directory, smb_buf(inbuf) + 1);
	cnum = SVAL(inbuf, smb_tid);
	unix_convert(directory, cnum, 0, &bad_path);

	if (check_name(directory, cnum))
		ret = mkdir(directory, unix_mode(cnum, aDIR));

	if (ret < 0) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);
	}

	outsize = set_message(outbuf, 0, 0, true);

	DEBUG("directory=%s cnum=%d ret=%d\n", directory, cnum, ret);

	return outsize;
}

/****************************************************************************
  reply to a rmdir
****************************************************************************/
int reply_rmdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	pstring directory;
	int cnum;
	int outsize = 0;
	bool ok = false;
	bool bad_path = false;

	cnum = SVAL(inbuf, smb_tid);
	pstrcpy(directory, smb_buf(inbuf) + 1);
	unix_convert(directory, cnum, 0, &bad_path);

	if (check_name(directory, cnum)) {

		dptr_closepath(directory, SVAL(inbuf, smb_pid));
		ok = (rmdir(directory) == 0);
		if (!ok)
			DEBUG("couldn't remove directory %s : %s\n", directory,
			      strerror(errno));
	}

	if (!ok) {
		if (errno == ENOENT && bad_path) {
			unix_ERR_class = ERRDOS;
			unix_ERR_code = ERRbadpath;
		}
		return UNIX_ERROR_CODE(ERRDOS, ERRbadpath);
	}

	outsize = set_message(outbuf, 0, 0, true);

	DEBUG("directory=%s\n", directory);

	return outsize;
}

/*******************************************************************
resolve wildcards in a filename rename
********************************************************************/
static bool resolve_wildcards(char *name1, char *name2)
{
	fstring root1, root2;
	fstring ext1, ext2;
	char *p, *p2;

	name1 = strrchr(name1, '/');
	name2 = strrchr(name2, '/');

	if (!name1 || !name2)
		return false;

	fstrcpy(root1, name1);
	fstrcpy(root2, name2);
	p = strrchr(root1, '.');
	if (p) {
		*p = 0;
		fstrcpy(ext1, p + 1);
	} else {
		fstrcpy(ext1, "");
	}
	p = strrchr(root2, '.');
	if (p) {
		*p = 0;
		fstrcpy(ext2, p + 1);
	} else {
		fstrcpy(ext2, "");
	}

	p = root1;
	p2 = root2;
	while (*p2) {
		if (*p2 == '?') {
			*p2 = *p;
			p2++;
		} else {
			p2++;
		}
		if (*p)
			p++;
	}

	p = ext1;
	p2 = ext2;
	while (*p2) {
		if (*p2 == '?') {
			*p2 = *p;
			p2++;
		} else {
			p2++;
		}
		if (*p)
			p++;
	}

	fstrcpy(name2, root2);
	if (ext2[0]) {
		fstrcat(name2, ".");
		fstrcat(name2, ext2);
	}

	return true;
}

/*******************************************************************
check if a user is allowed to rename a file
********************************************************************/
static bool can_rename(char *fname, int cnum)
{
	struct stat sbuf;

	if (!CAN_WRITE(cnum))
		return false;

	if (lstat(fname, &sbuf) != 0)
		return false;

	return true;
}

/****************************************************************************
  reply to a mv
****************************************************************************/
int reply_mv(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	int cnum;
	pstring directory;
	pstring mask, newname;
	pstring newname_last_component;
	char *p;
	int count = 0;
	int error = ERRnoaccess;
	bool has_wild;
	bool exists = false;
	bool bad_path1 = false;
	bool bad_path2 = false;

	*directory = *mask = 0;

	cnum = SVAL(inbuf, smb_tid);

	pstrcpy(name, smb_buf(inbuf) + 1);
	pstrcpy(newname, smb_buf(inbuf) + 3 + strlen(name));

	DEBUG("%s -> %s\n", name, newname);

	unix_convert(name, cnum, 0, &bad_path1);
	unix_convert(newname, cnum, newname_last_component, &bad_path2);

	/*
	 * Split the old name into directory and last component
	 * strings. Note that unix_convert may have stripped off a
	 * leading ./ from both name and newname if the rename is
	 * at the root of the share. We need to make sure either both
	 * name and newname contain a / character or neither of them do
	 * as this is checked in resolve_wildcards().
	 */

	p = strrchr(name, '/');
	if (!p) {
		pstrcpy(directory, ".");
		pstrcpy(mask, name);
	} else {
		*p = 0;
		pstrcpy(directory, name);
		pstrcpy(mask, p + 1);
		*p = '/'; /* Replace needed for exceptional test below. */
	}

	has_wild = strchr(mask, '*') || strchr(mask, '?');

	if (!has_wild) {
		bool is_short_name = is_8_3(name, true);

		/* Add a terminating '/' to the directory name. */
		pstrcat(directory, "/");
		pstrcat(directory, mask);

		/* Ensure newname contains a '/' also */
		if (strrchr(newname, '/') == 0) {
			pstring tmpstr;

			pstrcpy(tmpstr, "./");
			pstrcat(tmpstr, newname);
			pstrcpy(newname, tmpstr);
		}

		DEBUG("directory=%s, newname=%s, newname_last_component=%s, "
		      "is_8_3=%d\n",
		      directory, newname, newname_last_component,
		      is_short_name);

		/*
		 * Check for special case with case preserving and not
		 * case sensitive, if directory and newname are identical,
		 * and the old last component differs from the original
		 * last component only by case, then we should allow
		 * the rename (user is trying to change the case of the
		 * filename).
		 */
		if (!is_short_name && strcsequal(directory, newname)) {
			pstring newname_modified_last_component;

			/*
			 * Get the last component of the modified name.
			 * Note that we guarantee that newname contains a '/'
			 * character above.
			 */
			p = strrchr(newname, '/');
			pstrcpy(newname_modified_last_component, p + 1);

			if (strcsequal(newname_modified_last_component,
			               newname_last_component) == false) {
				/*
				 * Replace the modified last component with
				 * the original.
				 */
				pstrcpy(p + 1, newname_last_component);
			}
		}

		if (resolve_wildcards(directory, newname) &&
		    can_rename(directory, cnum) && !file_exist(newname, NULL) &&
		    rename(directory, newname) == 0) {
			count++;
		}

		DEBUG("%s doing rename on %s -> %s\n",
		      (count != 0) ? "succeeded" : "failed", directory,
		      newname);

		if (!count)
			exists = file_exist(directory, NULL);
		if (!count && exists && file_exist(newname, NULL)) {
			exists = true;
			error = 183;
		}
	} else {
		void *dirptr = NULL;
		char *dname;
		pstring destname;

		if (check_name(directory, cnum))
			dirptr = open_dir(cnum, directory);

		if (dirptr) {
			error = ERRbadfile;

			if (strequal(mask, "????????.???"))
				pstrcpy(mask, "*");

			while ((dname = read_dir_name(dirptr))) {
				pstring fname;
				pstrcpy(fname, dname);

				if (!mask_match(fname, mask, false)) {
					continue;
				}

				error = ERRnoaccess;
				snprintf(fname, sizeof(fname), "%s/%s",
				         directory, dname);
				if (!can_rename(fname, cnum)) {
					DEBUG("rename %s refused\n", fname);
					continue;
				}
				pstrcpy(destname, newname);

				if (!resolve_wildcards(fname, destname)) {
					DEBUG(
					    "resolve_wildcards %s %s failed\n",
					    fname, destname);
					continue;
				}

				if (file_exist(destname, NULL)) {
					DEBUG("file_exist %s\n", destname);
					error = 183;
					continue;
				}
				if (rename(fname, destname) == 0) {
					count++;
				}
				DEBUG("doing rename on %s -> %s\n", fname,
				      destname);
			}
			close_dir(dirptr);
		}
	}

	if (count == 0) {
		if (exists)
			return ERROR_CODE(ERRDOS, error);
		else {
			if (errno == ENOENT && (bad_path1 || bad_path2)) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			return UNIX_ERROR_CODE(ERRDOS, error);
		}
	}

	outsize = set_message(outbuf, 0, 0, true);

	return outsize;
}

/*******************************************************************
  copy a file as part of a reply_copy
  ******************************************************************/
static bool copy_file(char *src, char *dest1, int cnum, int ofun, int count,
                      bool target_is_directory)
{
	int Access, action;
	struct stat st;
	int ret = 0;
	int fnum1, fnum2;
	pstring dest;

	pstrcpy(dest, dest1);
	if (target_is_directory) {
		char *p = strrchr(src, '/');
		if (p)
			p++;
		else
			p = src;
		pstrcat(dest, "/");
		pstrcat(dest, p);
	}

	if (!file_exist(src, &st))
		return false;

	fnum1 = find_free_file();
	if (fnum1 < 0)
		return false;
	open_file_shared(fnum1, cnum, src, (DENY_NONE << 4), 1, 0, &Access,
	                 &action);

	if (!Files[fnum1].open) {
		Files[fnum1].reserved = false;
		return false;
	}

	if (!target_is_directory && count)
		ofun = 1;

	fnum2 = find_free_file();
	if (fnum2 < 0) {
		close_file(fnum1, false);
		return false;
	}
	open_file_shared(fnum2, cnum, dest, (DENY_NONE << 4) | 1, ofun,
	                 st.st_mode, &Access, &action);

	if (!Files[fnum2].open) {
		close_file(fnum1, false);
		Files[fnum2].reserved = false;
		return false;
	}

	if ((ofun & 3) == 1) {
		lseek(Files[fnum2].fd_ptr->fd, 0, SEEK_END);
	}

	if (st.st_size)
		ret = transfer_file(Files[fnum1].fd_ptr->fd,
		                    Files[fnum2].fd_ptr->fd, st.st_size, NULL,
		                    0, 0);

	close_file(fnum1, false);
	close_file(fnum2, false);

	return ret == st.st_size;
}

/****************************************************************************
  reply to a file copy.
  ****************************************************************************/
int reply_copy(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int outsize = 0;
	pstring name;
	int cnum;
	pstring directory;
	pstring mask, newname;
	char *p;
	int count = 0;
	int error = ERRnoaccess;
	bool has_wild;
	bool exists = false;
	int tid2 = SVAL(inbuf, smb_vwv0);
	int ofun = SVAL(inbuf, smb_vwv1);
	int flags = SVAL(inbuf, smb_vwv2);
	bool target_is_directory = false;
	bool bad_path1 = false;
	bool bad_path2 = false;

	*directory = *mask = 0;

	cnum = SVAL(inbuf, smb_tid);

	pstrcpy(name, smb_buf(inbuf));
	pstrcpy(newname, smb_buf(inbuf) + 1 + strlen(name));

	DEBUG("%s -> %s\n", name, newname);

	if (tid2 != cnum) {
		/* can't currently handle inter share copies XXXX */
		DEBUG("Rejecting inter-share copy\n");
		return ERROR_CODE(ERRSRV, ERRinvdevice);
	}

	unix_convert(name, cnum, 0, &bad_path1);
	unix_convert(newname, cnum, 0, &bad_path2);

	target_is_directory = directory_exist(newname, NULL);

	if ((flags & 1) && target_is_directory) {
		return ERROR_CODE(ERRDOS, ERRbadfile);
	}

	if ((flags & 2) && !target_is_directory) {
		return ERROR_CODE(ERRDOS, ERRbadpath);
	}

	if ((flags & (1 << 5)) && directory_exist(name, NULL)) {
		/* wants a tree copy! XXXX */
		DEBUG("Rejecting tree copy\n");
		return ERROR_CODE(ERRSRV, ERRerror);
	}

	p = strrchr(name, '/');
	if (!p) {
		pstrcpy(directory, "./");
		pstrcpy(mask, name);
	} else {
		*p = 0;
		pstrcpy(directory, name);
		pstrcpy(mask, p + 1);
	}

	has_wild = strchr(mask, '*') || strchr(mask, '?');

	if (!has_wild) {
		pstrcat(directory, "/");
		pstrcat(directory, mask);
		if (resolve_wildcards(directory, newname) &&
		    copy_file(directory, newname, cnum, ofun, count,
		              target_is_directory))
			count++;
		if (!count)
			exists = file_exist(directory, NULL);
	} else {
		void *dirptr = NULL;
		char *dname;
		pstring destname;

		if (check_name(directory, cnum))
			dirptr = open_dir(cnum, directory);

		if (dirptr) {
			error = ERRbadfile;

			if (strequal(mask, "????????.???"))
				pstrcpy(mask, "*");

			while ((dname = read_dir_name(dirptr))) {
				pstring fname;
				pstrcpy(fname, dname);

				if (!mask_match(fname, mask, false)) {
					continue;
				}

				error = ERRnoaccess;
				snprintf(fname, sizeof(fname), "%s/%s",
				         directory, dname);
				pstrcpy(destname, newname);
				if (resolve_wildcards(fname, destname) &&
				    copy_file(directory, newname, cnum, ofun,
				              count, target_is_directory))
					count++;
				DEBUG("doing copy on %s -> %s\n", fname,
				      destname);
			}
			close_dir(dirptr);
		}
	}

	if (count == 0) {
		if (exists)
			return ERROR_CODE(ERRDOS, error);
		else {
			if (errno == ENOENT && (bad_path1 || bad_path2)) {
				unix_ERR_class = ERRDOS;
				unix_ERR_code = ERRbadpath;
			}
			return UNIX_ERROR_CODE(ERRDOS, error);
		}
	}

	outsize = set_message(outbuf, 1, 0, true);
	SSVAL(outbuf, smb_vwv0, count);

	return outsize;
}

/****************************************************************************
  reply to a setdir
****************************************************************************/
int reply_setdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum = SVAL(inbuf, smb_tid);

	DEBUG("not supported cnum=%d\n", cnum);

	return ERROR_CODE(ERRDOS, ERRnoaccess);
}

/****************************************************************************
  reply to a lockingX request
****************************************************************************/
int reply_lockingX(char *inbuf, char *outbuf, int length, int bufsize)
{
	int fnum = GETFNUM(inbuf, smb_vwv2);
	unsigned char locktype = CVAL(inbuf, smb_vwv3);
	uint16_t num_ulocks = SVAL(inbuf, smb_vwv6);
	uint16_t num_locks = SVAL(inbuf, smb_vwv7);
	uint32_t count, offset;

	int cnum;
	int i;
	char *data;
	uint32_t ecode = 0, dummy2;
	int eclass = 0, dummy1;

	cnum = SVAL(inbuf, smb_tid);

	CHECK_FNUM(fnum, cnum);
	CHECK_ERROR(fnum);

	data = smb_buf(inbuf);

	/* Check if this is an oplock break on a file
	   we have granted an oplock on.
	 */
	if (locktype & LOCKING_ANDX_OPLOCK_RELEASE) {
		DEBUG("oplock break reply from client for "
		      "fnum = %d. no oplock granted as not supported.\n",
		      fnum);
		return ERROR_CODE(ERRDOS, ERRlock);
	}

	/* Data now points at the beginning of the list
	   of smb_unlkrng structs */
	for (i = 0; i < (int) num_ulocks; i++) {
		count = IVAL(data, SMB_LKLEN_OFFSET(i));
		offset = IVAL(data, SMB_LKOFF_OFFSET(i));
		if (!do_unlock(fnum, cnum, count, offset, &eclass, &ecode))
			return ERROR_CODE(eclass, ecode);
	}

	/* Now do any requested locks */
	data += 10 * num_ulocks;
	/* Data now points at the beginning of the list
	   of smb_lkrng structs */
	for (i = 0; i < (int) num_locks; i++) {
		count = IVAL(data, SMB_LKLEN_OFFSET(i));
		offset = IVAL(data, SMB_LKOFF_OFFSET(i));
		if (!do_lock(fnum, cnum, count, offset,
		             (locktype & 1) ? F_RDLCK : F_WRLCK, &eclass,
		             &ecode))
			break;
	}

	/* If any of the above locks failed, then we must unlock
	   all of the previous locks (X/Open spec). */
	if (i != num_locks && num_locks != 0) {
		for (; i >= 0; i--) {
			count = IVAL(data, SMB_LKLEN_OFFSET(i));
			offset = IVAL(data, SMB_LKOFF_OFFSET(i));
			do_unlock(fnum, cnum, count, offset, &dummy1, &dummy2);
		}
		return ERROR_CODE(eclass, ecode);
	}

	set_message(outbuf, 2, 0, true);

	DEBUG("fnum=%d cnum=%d type=%d num_locks=%d num_ulocks=%d\n", fnum,
	      cnum, (unsigned int) locktype, num_locks, num_ulocks);

	chain_fnum = fnum;

	return chain_reply(inbuf, outbuf, length, bufsize);
}

/****************************************************************************
  reply to a SMBreadbmpx (read block multiplex) request
****************************************************************************/
int reply_readbmpx(char *inbuf, char *outbuf, int length, int bufsize)
{
	return ERROR_CODE(ERRSRV, ERRuseSTD);
}

/****************************************************************************
  reply to a SMBwritebmpx (write block multiplex primary) request
****************************************************************************/
int reply_writebmpx(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, numtowrite, fnum;
	int nwritten = -1;
	int outsize = 0;
	uint32_t startpos;
	int tcount, write_through, smb_doff;
	char *data;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);
	CHECK_ERROR(fnum);

	tcount = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv3);
	write_through = (SVAL(inbuf, smb_vwv7) & 1) != 0;
	numtowrite = SVAL(inbuf, smb_vwv10);
	smb_doff = SVAL(inbuf, smb_vwv11);

	data = smb_base(inbuf) + smb_doff;

	/* If this fails we need to send an SMBwriteC response,
	   not an SMBwritebmpx - set this up now so we don't forget */
	CVAL(outbuf, smb_com) = SMBwritec;

	seek_file(fnum, startpos);
	nwritten = write_file(fnum, data, numtowrite);

	if (nwritten < numtowrite)
		return UNIX_ERROR_CODE(ERRHRD, ERRdiskfull);

	/* If the maximum to be written to this file
	   is greater than what we just wrote then set
	   up a secondary struct to be attached to this
	   fd, we will use this to cache error messages etc. */
	if (tcount > nwritten) {
		struct bmpx_data *wbms;
		if (Files[fnum].wbmpx_ptr != NULL)
			wbms =
			    Files[fnum].wbmpx_ptr; /* Use an existing struct */
		else
			wbms = checked_malloc(sizeof(struct bmpx_data));
		wbms->wr_mode = write_through;
		wbms->wr_discard = false; /* No errors yet */
		wbms->wr_total_written = nwritten;
		wbms->wr_errclass = 0;
		wbms->wr_error = 0;
		Files[fnum].wbmpx_ptr = wbms;
	}

	/* We are returning successfully, set the message type back to
	   SMBwritebmpx */
	CVAL(outbuf, smb_com) = SMBwriteBmpx;

	outsize = set_message(outbuf, 1, 0, true);

	SSVALS(outbuf, smb_vwv0, -1); /* We don't support smb_remaining */

	DEBUG("fnum=%d cnum=%d num=%d wrote=%d\n", fnum, cnum, numtowrite,
	      nwritten);

	if (write_through && tcount == nwritten) {
		/* we need to send both a primary and a secondary response */
		smb_setlen(outbuf, outsize - 4);
		send_smb(Client, outbuf);

		/* now the secondary */
		outsize = set_message(outbuf, 1, 0, true);
		CVAL(outbuf, smb_com) = SMBwritec;
		SSVAL(outbuf, smb_vwv0, nwritten);
	}

	return outsize;
}

/****************************************************************************
  reply to a SMBwritebs (write block multiplex secondary) request
****************************************************************************/
int reply_writebs(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, numtowrite, fnum;
	int nwritten = -1;
	int outsize = 0;
	int32_t startpos;
	int tcount, write_through, smb_doff;
	char *data;
	struct bmpx_data *wbms;
	bool send_response = false;

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);
	CHECK_FNUM(fnum, cnum);
	CHECK_WRITE(fnum);

	tcount = SVAL(inbuf, smb_vwv1);
	startpos = IVAL(inbuf, smb_vwv2);
	numtowrite = SVAL(inbuf, smb_vwv6);
	smb_doff = SVAL(inbuf, smb_vwv7);

	data = smb_base(inbuf) + smb_doff;

	/* We need to send an SMBwriteC response, not an SMBwritebs */
	CVAL(outbuf, smb_com) = SMBwritec;

	/* This fd should have an auxiliary struct attached,
	   check that it does */
	wbms = Files[fnum].wbmpx_ptr;
	if (!wbms)
		return -1;

	/* If write through is set we can return errors, else we must
	   cache them */
	write_through = wbms->wr_mode;

	/* Check for an earlier error */
	if (wbms->wr_discard)
		return -1; /* Just discard the packet */

	seek_file(fnum, startpos);
	nwritten = write_file(fnum, data, numtowrite);

	if (nwritten < numtowrite) {
		if (write_through) {
			/* We are returning an error - we can delete the aux
			 * struct */
			free(wbms);
			Files[fnum].wbmpx_ptr = NULL;
			return ERROR_CODE(ERRHRD, ERRdiskfull);
		}
		return CACHE_ERROR_CODE(wbms, ERRHRD, ERRdiskfull);
	}

	/* Increment the total written, if this matches tcount
	   we can discard the auxiliary struct (hurrah !) and return a writeC */
	wbms->wr_total_written += nwritten;
	if (wbms->wr_total_written >= tcount) {
		if (write_through) {
			outsize = set_message(outbuf, 1, 0, true);
			SSVAL(outbuf, smb_vwv0, wbms->wr_total_written);
			send_response = true;
		}

		free(wbms);
		Files[fnum].wbmpx_ptr = NULL;
	}

	if (send_response)
		return outsize;

	return -1;
}

/****************************************************************************
  reply to a SMBsetattrE
****************************************************************************/
int reply_setattrE(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, fnum;
	struct utimbuf unix_times;
	int outsize = 0;

	outsize = set_message(outbuf, 0, 0, true);

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_ERROR(fnum);

	/* Convert the DOS times into unix times. Ignore create
	   time as UNIX can't set this.
	   */
	unix_times.actime = make_unix_date2(inbuf + smb_vwv3);
	unix_times.modtime = make_unix_date2(inbuf + smb_vwv5);

	/*
	 * Patch from Ray Frush <frush@engr.colostate.edu>
	 * Sometimes times are sent as zero - ignore them.
	 */

	if (unix_times.actime == 0 && unix_times.modtime == 0) {
		/* Ignore request */
		DEBUG("fnum=%d cnum=%d ignoring zero request - "
		      "not setting timestamps of 0\n",
		      fnum, cnum);
		return outsize;
	} else if (unix_times.actime != 0 && unix_times.modtime == 0) {
		/* set modify time = to access time if modify time was 0 */
		unix_times.modtime = unix_times.actime;
	}

	/* Set the date on this file */
	if (sys_utime(Files[fnum].name, &unix_times) != 0)
		return ERROR_CODE(ERRDOS, ERRnoaccess);

	DEBUG("fnum=%d cnum=%d actime=%ld modtime=%ld\n", fnum, cnum,
	      (long) unix_times.actime, (long) unix_times.modtime);

	return outsize;
}

/****************************************************************************
  reply to a SMBgetattrE
****************************************************************************/
int reply_getattrE(char *inbuf, char *outbuf, int dum_size, int dum_buffsize)
{
	int cnum, fnum;
	struct stat sbuf;
	int outsize = 0;
	int mode;

	outsize = set_message(outbuf, 11, 0, true);

	cnum = SVAL(inbuf, smb_tid);
	fnum = GETFNUM(inbuf, smb_vwv0);

	CHECK_FNUM(fnum, cnum);
	CHECK_ERROR(fnum);

	/* Do an fstat on this file */
	if (fstat(Files[fnum].fd_ptr->fd, &sbuf))
		return UNIX_ERROR_CODE(ERRDOS, ERRnoaccess);

	mode = dos_mode(cnum, Files[fnum].name, &sbuf);

	/* Convert the times into dos times. Set create
	   date to be last modify date as UNIX doesn't save
	   this */
	put_dos_date2(outbuf, smb_vwv0, get_create_time(&sbuf));
	put_dos_date2(outbuf, smb_vwv2, sbuf.st_atime);
	put_dos_date2(outbuf, smb_vwv4, sbuf.st_mtime);
	if (mode & aDIR) {
		SIVAL(outbuf, smb_vwv6, 0);
		SIVAL(outbuf, smb_vwv8, 0);
	} else {
		SIVAL(outbuf, smb_vwv6, sbuf.st_size);
		SIVAL(outbuf, smb_vwv8, ROUNDUP(sbuf.st_size, 1024));
	}
	SSVAL(outbuf, smb_vwv10, mode);

	DEBUG("fnum=%d cnum=%d\n", fnum, cnum);

	return outsize;
}
