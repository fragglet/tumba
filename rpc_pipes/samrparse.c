
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
char* samr_io_q_close(BOOL io, SAMR_Q_CLOSE *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_unknown_1\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(q_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_close(BOOL io, SAMR_R_CLOSE *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_unknown_1\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(r_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_q_open_secret(BOOL io, SAMR_Q_OPEN_SECRET *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_open_secret\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(q_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("unknown_0", depth, base, io, q, q_u->unknown_0); q += 4;

	q = smb_io_dom_sid(io, &(q_u->dom_sid), q, base, align, depth); 
	q = align_offset(q, base, align);

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_open_secret(BOOL io, SAMR_R_OPEN_SECRET *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_open_secret\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(r_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_q_lookup_rids(BOOL io, SAMR_Q_LOOKUP_RIDS *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_lookup_rids\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(q_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("num_rids1", depth, base, io, q, q_u->num_rids1); q += 4;
	DBG_RW_IVAL("rid      ", depth, base, io, q, q_u->rid      ); q += 4;
	DBG_RW_IVAL("ptr      ", depth, base, io, q, q_u->ptr      ); q += 4;
	DBG_RW_IVAL("num_rids2", depth, base, io, q, q_u->num_rids2); q += 4;

	q = smb_io_unihdr (io, &(q_u->hdr_mach_acct), q, base, align, depth); 
	q = smb_io_unistr2(io, &(q_u->uni_mach_acct), q, base, align, depth); 

	q = align_offset(q, base, align);

	return q;
}


/*******************************************************************
makes a SAMR_R_LOOKUP_RIDS structure.
********************************************************************/
void make_samr_r_lookup_rids(SAMR_R_LOOKUP_RIDS *r_u,
		uint32 num_rids, uint32 rid, uint32 status)
{
	if (r_u == NULL) return;

	DEBUG(5,("make_samr_r_lookup_rids\n"));

	r_u->num_entries  = num_rids;
	r_u->undoc_buffer = 0x156488;
	r_u->num_entries2 = num_rids;

	make_dom_rid3(&(r_u->dom_rid[0]), rid);

	r_u->num_entries3 = num_rids;

	r_u->status = status;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_lookup_rids(BOOL io, SAMR_R_LOOKUP_RIDS *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_lookup_rids\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("num_entries ", depth, base, io, q, r_u->num_entries ); q += 4;
	DBG_RW_IVAL("undoc_buffer", depth, base, io, q, r_u->undoc_buffer); q += 4;
	DBG_RW_IVAL("num_entries2", depth, base, io, q, r_u->num_entries2); q += 4;

	q = smb_io_dom_rid3(io, &(r_u->dom_rid[0]), q, base, align, depth);

	DBG_RW_IVAL("num_entries3", depth, base, io, q, r_u->num_entries3); q += 4;

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_q_unknown_22(BOOL io, SAMR_Q_UNKNOWN_22 *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_unknown_22\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(q_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("unknown_id_0", depth, base, io, q, q_u->unknown_id_0); q += 4;

	q = align_offset(q, base, align);

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_unknown_22(BOOL io, SAMR_R_UNKNOWN_22 *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_unknown_22\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(r_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_q_unknown_24(BOOL io, SAMR_Q_UNKNOWN_24 *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_unknown_24\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(q_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_SVAL("unknown_0", depth, base, io, q, q_u->unknown_0); q += 2; /* 0x0015 or 0x0011 */

	q = align_offset(q, base, align);

	return q;
}

/*******************************************************************
makes a SAMR_R_UNKNOWN_24 structure.
********************************************************************/
void make_samr_r_unknown_24(SAMR_R_UNKNOWN_24 *r_u,
				uint16 unknown_0, NTTIME *expiry, char *mach_acct,
				uint32 unknown_id_0, uint32 status)
				
{
	int len_mach_acct;
	if (r_u == NULL || mach_acct == NULL) return;

	DEBUG(5,("make_samr_r_unknown_24\n"));

	len_mach_acct = strlen(mach_acct);

	r_u->ptr          = 1;            /* pointer */
	r_u->unknown_0    = unknown_0;    /* 0x0015 or 0x0011 - 16 bit unknown */
	r_u->unknown_1    = 0x8b73;       /* 0x8b73 - 16 bit unknown */
	bzero(r_u->padding_0, sizeof(r_u->padding_0)); /* 0 - padding 16 bytes */
	memcpy(&(r_u->expiry),expiry, sizeof(r_u->expiry)); /* expiry time or something? */
	bzero(r_u->padding_1, sizeof(r_u->padding_1)); /* 0 - padding 24 bytes */

	make_uni_hdr(&(r_u->hdr_mach_acct), len_mach_acct, len_mach_acct, 4);  /* unicode header for machine account */
	r_u->padding_2 = 0;               /* 0 - padding 4 bytes */

	r_u->ptr_1        = 1;            /* pointer */
	bzero(r_u->padding_3, sizeof(r_u->padding_3)); /* 0 - padding 32 bytes */
	r_u->padding_4    = 0;            /* 0 - padding 4 bytes */

	r_u->ptr_2        = 1;            /* pointer */
	r_u->padding_5    = 0;            /* 0 - padding 4 bytes */

	r_u->ptr_3        = 1;          /* pointer */
	bzero(r_u->padding_6, sizeof(r_u->padding_6)); /* 0 - padding 32 bytes */

	r_u->unknown_id_0 = unknown_id_0; /* unknown id associated with pol hnd */
	r_u->unknown_2    = 0x201;        /* 0x0201      - 16 bit unknown */
	r_u->unknown_3    = 0x00000080;   /* 0x0000 0080 - 32 bit unknown */
	r_u->unknown_4    = 0x003f;       /* 0x003f      - 16 bit unknown */
	r_u->unknown_5    = 0x003c;       /* 0x003c      - 16 bit unknown */

	bzero(r_u->padding_7, sizeof(r_u->padding_7)); /* 0 - padding 16 bytes */
	r_u->padding_8    = 0;            /* 0 - padding 4 bytes */
	
	make_unistr2(&(r_u->uni_mach_acct), mach_acct, len_mach_acct);  /* unicode string for machine account */

	bzero(r_u->padding_9, sizeof(r_u->padding_9)); /* 0 - padding 48 bytes */

	r_u->status = status;         /* return status */
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_unknown_24(BOOL io, SAMR_R_UNKNOWN_24 *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_unknown_24\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("ptr         ", depth, base, io, q, r_u->ptr         ); q += 4;
	DBG_RW_SVAL("unknown_0   ", depth, base, io, q, r_u->unknown_0   ); q += 2;
	DBG_RW_SVAL("unknown_1   ", depth, base, io, q, r_u->unknown_1   ); q += 2;
	DBG_RW_PCVAL(False, "padding_0   ", depth, base, io, q, r_u->padding_0   , sizeof(r_u->padding_0)); q += sizeof(r_u->padding_0);

	q = smb_io_time(io, &(r_u->expiry), q, base, align, depth); 
	DBG_RW_PCVAL(False, "padding_1   ", depth, base, io, q, r_u->padding_1   , sizeof(r_u->padding_1)); q += sizeof(r_u->padding_1);

	q = smb_io_unihdr (io, &(r_u->hdr_mach_acct), q, base, align, depth); 
	DBG_RW_IVAL("padding_2   ", depth, base, io, q, r_u->padding_2   ); q += 4;

	DBG_RW_IVAL("ptr_1       ", depth, base, io, q, r_u->ptr_1       ); q += 4;
	DBG_RW_PCVAL(False, "padding_3   ", depth, base, io, q, r_u->padding_3   , sizeof(r_u->padding_3)); q += sizeof(r_u->padding_3);
	DBG_RW_IVAL("padding_4   ", depth, base, io, q, r_u->padding_4   ); q += 4;

	DBG_RW_IVAL("ptr_2       ", depth, base, io, q, r_u->ptr_2       ); q += 4;
	DBG_RW_IVAL("padding_5   ", depth, base, io, q, r_u->padding_5   ); q += 4;

	DBG_RW_IVAL("ptr_3       ", depth, base, io, q, r_u->ptr_3       ); q += 4;
	DBG_RW_PCVAL(False, "padding_6   ", depth, base, io, q, r_u->padding_6   , sizeof(r_u->padding_6)); q += sizeof(r_u->padding_6);

	DBG_RW_IVAL("unknown_id_0", depth, base, io, q, r_u->unknown_id_0); q += 4;
	DBG_RW_SVAL("unknown_2   ", depth, base, io, q, r_u->unknown_2   ); q += 2;
	DBG_RW_IVAL("unknown_3   ", depth, base, io, q, r_u->unknown_3   ); q += 4;
	DBG_RW_SVAL("unknown_4   ", depth, base, io, q, r_u->unknown_4   ); q += 2;
	DBG_RW_SVAL("unknown_5   ", depth, base, io, q, r_u->unknown_5   ); q += 2;

	DBG_RW_PCVAL(False, "padding_7   ", depth, base, io, q, r_u->padding_7   , sizeof(r_u->padding_7)); q += sizeof(r_u->padding_7);
	DBG_RW_IVAL("padding_8   ", depth, base, io, q, r_u->padding_8   ); q += 4;
	
	q = smb_io_unistr2(io, &(r_u->uni_mach_acct), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_PCVAL(False, "padding_9   ", depth, base, io, q, r_u->padding_9   , sizeof(r_u->padding_9)); q += sizeof(r_u->padding_9);

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

	return q;
}


/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_q_unknown_32(BOOL io, SAMR_Q_UNKNOWN_32 *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_unknown_32\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(q_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	q = smb_io_unihdr (io, &(q_u->hdr_mach_acct), q, base, align, depth); 
	q = smb_io_unistr2(io, &(q_u->uni_mach_acct), q, base, align, depth); 

	q = align_offset(q, base, align);

	DBG_RW_IVAL("unknown_0", depth, base, io, q, q_u->unknown_0); q += 4;
	DBG_RW_SVAL("unknown_1", depth, base, io, q, q_u->unknown_1); q += 2;
	DBG_RW_SVAL("unknown_2", depth, base, io, q, q_u->unknown_2); q += 2;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_unknown_32(BOOL io, SAMR_R_UNKNOWN_32 *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_unknown_32\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(r_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_q_open_policy(BOOL io, SAMR_Q_OPEN_POLICY *q_u, char *q, char *base, int align, int depth)
{
	if (q_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_q_open_policy\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	DBG_RW_IVAL("ptr_srv_name", depth, base, io, q, q_u->ptr_srv_name); q += 4;
	q = smb_io_unistr2(io, &(q_u->uni_srv_name), q, base, align, depth); 

	q = align_offset(q, base, align);

	DBG_RW_IVAL("unknown_0   ", depth, base, io, q, q_u->unknown_0   ); q += 4;

	return q;
}

/*******************************************************************
reads or writes a structure.
********************************************************************/
char* samr_io_r_open_policy(BOOL io, SAMR_R_OPEN_POLICY *r_u, char *q, char *base, int align, int depth)
{
	if (r_u == NULL) return NULL;

	DEBUG(5,("%s%04x samr_io_r_open_policy\n", tab_depth(depth), PTR_DIFF(q, base)));
	depth++;

	q = align_offset(q, base, align);

	q = smb_io_pol_hnd(io, &(r_u->pol), q, base, align, depth); 
	q = align_offset(q, base, align);

	DBG_RW_IVAL("status", depth, base, io, q, r_u->status); q += 4;

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
