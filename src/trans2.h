/*
 * Copyright (c) 1992-1998 Andrew Tridgell
 * Copyright (c) 1994-1998 Jeremy Allison
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef _TRANS2_H_
#define _TRANS2_H_

#include <stddef.h>
#include <sys/param.h>

/* Define the structures needed for the trans2 calls. */

/* For DosFindFirst/DosFindNext - level 1 */
#define l1_fdateCreation   0
#define l1_fdateLastAccess 4
#define l1_fdateLastWrite  8
#define l1_cbFile          12
#define l1_cbFileAlloc     16
#define l1_attrFile        20
#define l1_cchName         22
#define l1_achName         23

/* For DosFindFirst/DosFindNext - level 2 */
#define l2_fdateCreation   0
#define l2_fdateLastAccess 4
#define l2_fdateLastWrite  8
#define l2_cbFile          12
#define l2_cbFileAlloc     16
#define l2_attrFile        20
#define l2_cbList          22
#define l2_cchName         26
#define l2_achName         27

/* For DosQFSInfo/DosSetFSInfo - level 1 */
#define l1_idFileSystem 0
#define l1_cSectorUnit  4
#define l1_cUnit        8
#define l1_cUnitAvail   12
#define l1_cbSector     16

/* For DosQFSInfo/DosSetFSInfo - level 2 */
#define l2_vol_fdateCreation 0
#define l2_vol_cch           4
#define l2_vol_szVolLabel    5

#define SMB_INFO_STANDARD            1
#define SMB_INFO_QUERY_EA_SIZE       2
#define SMB_INFO_QUERY_EAS_FROM_LIST 3
#define SMB_INFO_QUERY_ALL_EAS       4
#define SMB_INFO_IS_NAME_VALID       6

#define SMB_INFO_ALLOCATION         0x001
#define SMB_INFO_VOLUME             0x002
#define SMB_QUERY_FS_LABEL_INFO     0x101
#define SMB_QUERY_FS_VOLUME_INFO    0x102
#define SMB_QUERY_FS_SIZE_INFO      0x103
#define SMB_QUERY_FS_DEVICE_INFO    0x104
#define SMB_QUERY_FS_ATTRIBUTE_INFO 0x105

#define SMB_QUERY_FILE_BASIC_INFO      0x101
#define SMB_QUERY_FILE_STANDARD_INFO   0x102
#define SMB_QUERY_FILE_EA_INFO         0x103
#define SMB_QUERY_FILE_NAME_INFO       0x104
#define SMB_QUERY_FILE_ALLOCATION_INFO 0x105
#define SMB_QUERY_FILE_END_OF_FILEINFO 0x106
#define SMB_QUERY_FILE_ALL_INFO        0x107
#define SMB_QUERY_FILE_ALT_NAME_INFO   0x108
#define SMB_QUERY_FILE_STREAM_INFO     0x109

#define SMB_FIND_FILE_DIRECTORY_INFO      0x101
#define SMB_FIND_FILE_FULL_DIRECTORY_INFO 0x102
#define SMB_FIND_FILE_NAMES_INFO          0x103
#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO 0x104

#define SMB_SET_FILE_BASIC_INFO       0x101
#define SMB_SET_FILE_DISPOSITION_INFO 0x102
#define SMB_SET_FILE_ALLOCATION_INFO  0x103
#define SMB_SET_FILE_END_OF_FILE_INFO 0x104

#define DIRLEN_GUESS (45 + MAX(l1_achName, l2_achName))

/* NT uses a FILE_ATTRIBUTE_NORMAL when no other attributes are set. */
#define NT_FILE_ATTRIBUTE_NORMAL 0x80

void mask_convert(char *mask);
int reply_findclose(char *inbuf, char *outbuf, size_t inbuf_len,
                    size_t outbuf_len);
int reply_findnclose(char *inbuf, char *outbuf, size_t inbuf_len,
                     size_t outbuf_len);
int reply_transs2(char *inbuf, char *outbuf, size_t inbuf_len,
                  size_t outbuf_len);
int reply_trans2(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);

#endif
