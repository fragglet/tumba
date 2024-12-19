
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

extern int DEBUGLEVEL;

#ifdef NTDOMAIN

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* wks_io_q_unknown_0(BOOL io, WKS_Q_UNKNOWN_0 *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x wks_io_q_unknown_0\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("ptr_srv_name", depth, base, io, q, q_u->ptr_srv_name); q += 4;
	q = smb_io_unistr2(io, &(q_u->uni_srv_name), q, base, align, depth); 

	q = align_offset(q, base, align);

	DBG_RW_IVAL("unknown_0   ", depth, base, io, q, q_u->unknown_0   ); q += 4;
	DBG_RW_IVAL("unknown_1   ", depth, base, io, q, q_u->unknown_1   ); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* wks_io_r_unknown_0(BOOL io, WKS_R_UNKNOWN_0 *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x wks_io_r_unknown_0\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("unknown_0   ", depth, base, io, q, r_u->unknown_0   ); q += 4; /* 64 - unknown */
	DBG_RW_IVAL("ptr_1       ", depth, base, io, q, r_u->ptr_1       ); q += 4; /* pointer 1 */
	DBG_RW_IVAL("unknown_1   ", depth, base, io, q, r_u->unknown_1   ); q += 4; /* 0x0000 01f4 - unknown */
	DBG_RW_IVAL("ptr_srv_name", depth, base, io, q, r_u->ptr_srv_name); q += 4; /* pointer to server name */
	DBG_RW_IVAL("ptr_dom_name", depth, base, io, q, r_u->ptr_dom_name); q += 4; /* pointer to domain name */
	DBG_RW_IVAL("unknown_2   ", depth, base, io, q, r_u->unknown_2   ); q += 4; /* 4 - unknown */
	DBG_RW_IVAL("unknown_3   ", depth, base, io, q, r_u->unknown_3   ); q += 4; /* 0 - unknown */

	q = smb_io_unistr2(io, &(r_u->uni_srv_name), q, base, align, depth); 
	q = align_offset(q, base, align);

	q = smb_io_unistr2(io, &(r_u->uni_dom_name), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("status        ", depth, base, io, q, r_u->status); q += 4;

	return q;
}

#if 0
/*******************************************************************
reads or writes a structure.
********************************************************************/
 char* lsa_io_(BOOL io, *, char *q, char *base, int align, int depth)
{
	if (== NULL) return NULL;

	q = align_offset(q, base, align);
	
	DBG_RW_IVAL("", depth, base, io, q, ); q += 4;

	return q;
}
#endif

#endif
