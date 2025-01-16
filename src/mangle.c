/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Name mangling
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

extern int LOGLEVEL;

/****************************************************************************
 * Provide a checksum on a string
 *
 *  Input:  s - the nul-terminated character string for which the checksum
 *              will be calculated.
 *  Output: The checksum value calculated for s.
 *
 ****************************************************************************/
int str_checksum(char *s)
{
	int res = 0;
	int c;
	int i = 0;

	while (*s) {
		c = *s;
		res ^= (c << (i % 15)) ^ (c >> (15 - (i % 15)));
		s++;
		i++;
	}
	return res;
}

/****************************************************************************
return true if a name is a special msdos reserved name
****************************************************************************/
static bool is_reserved_msdos(char *fname)
{
	char upperFname[13];
	char *p;

	strlcpy(upperFname, fname, sizeof(upperFname));

	/* lpt1.txt and con.txt etc are also illegal */
	p = strchr(upperFname, '.');
	if (p)
		*p = '\0';
	strupper(upperFname);
	if ((strcmp(upperFname, "CLOCK$") == 0) ||
	    (strcmp(upperFname, "CON") == 0) ||
	    (strcmp(upperFname, "AUX") == 0) ||
	    (strcmp(upperFname, "COM1") == 0) ||
	    (strcmp(upperFname, "COM2") == 0) ||
	    (strcmp(upperFname, "COM3") == 0) ||
	    (strcmp(upperFname, "COM4") == 0) ||
	    (strcmp(upperFname, "LPT1") == 0) ||
	    (strcmp(upperFname, "LPT2") == 0) ||
	    (strcmp(upperFname, "LPT3") == 0) ||
	    (strcmp(upperFname, "NUL") == 0) ||
	    (strcmp(upperFname, "PRN") == 0))
		return true;

	return false;
}

/****************************************************************************
return true if a name is in 8.3 dos format
****************************************************************************/
bool is_8_3(char *fname, bool check_case)
{
	int len;
	char *dot_pos, *p;
	char *slash_pos = strrchr(fname, '/');
	int l;

	if (slash_pos)
		fname = slash_pos + 1;
	len = strlen(fname);

	DEBUG("checking %s for 8.3\n", fname);

	/* can't be longer than 12 chars */
	if (len == 0 || len > 12)
		return false;

	/* can't be an MS-DOS Special file such as lpt1 or even lpt1.txt */
	if (is_reserved_msdos(fname))
		return false;

	/* can't contain invalid dos chars */
	dot_pos = 0;
	for (p = fname; *p != '\0'; ++p) {
		if (*p == '.' && !dot_pos)
			dot_pos = (char *) p;
		if (!isdoschar(*p))
			return false;
	}

	/* no dot and less than 9 means OK */
	if (dot_pos == NULL)
		return len <= 8;

	l = PTR_DIFF(dot_pos, fname);

	/* base must be at least 1 char except special cases . and .. */
	if (l == 0)
		return strcmp(fname, ".") == 0 || strcmp(fname, "..") == 0;

	/* base can't be greater than 8 */
	if (l > 8)
		return false;

	if (lp_strip_dot() && len - l == 1 && !strchr(dot_pos + 1, '.')) {
		*dot_pos = 0;
		return true;
	}

	/* extension must be between 1 and 3 */
	if ((len - l < 2) || (len - l > 4))
		return false;

	/* extension can't have a dot */
	if (strchr(dot_pos + 1, '.'))
		return false;

	/* must be in 8.3 format */
	return true;
}

/* this is the magic char used for mangling */
#define MAGIC_CHAR '~'

/****************************************************************************
return true if the name could be a mangled name
****************************************************************************/
bool is_mangled(char *s)
{
	char *m = strchr(s, MAGIC_CHAR);

	if (!m)
		return false;

	/* we use two base 36 chars before the extension */
	if (m[1] == '.' || m[1] == 0 || m[2] == '.' || m[2] == 0 ||
	    (m[3] != '.' && m[3] != 0))
		return is_mangled(m + 1);

	/* it could be */
	return true;
}

/****************************************************************************
return a base 36 character. v must be from 0 to 35.
****************************************************************************/
static char base36(unsigned int v)
{
	static char basechars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	return basechars[v % 36];
}

/****************************************************************************
do the actual mangling to 8.3 format
****************************************************************************/
void mangle_name_83(char *s, int s_len)
{
	int csum = str_checksum(s);
	char *p;
	char extension[4];
	char base[9];
	int baselen = 0;
	int extlen = 0;

	extension[0] = 0;
	base[0] = 0;

	p = strrchr(s, '.');
	if (p && (strlen(p + 1) < (size_t) 4)) {
		bool all_normal = (strisnormal(p + 1)); /* XXXXXXXXX */

		if (all_normal && p[1] != 0) {
			*p = 0;
			csum = str_checksum(s);
			*p = '.';
		}
	}

	strupper(s);

	DEBUG("Mangling name %s to ", s);

	if (p) {
		if (p == s)
			fstrcpy(extension, "___");
		else {
			*p++ = 0;
			while (*p && extlen < 3) {
				if (isdoschar(*p) && *p != '.')
					extension[extlen++] = p[0];
				p++;
			}
			extension[extlen] = 0;
		}
	}

	p = s;

	while (*p && baselen < 5) {
		if (isdoschar(*p) && *p != '.')
			base[baselen++] = p[0];
		p++;
	}
	base[baselen] = 0;

	csum = csum % (36 * 36);

	slprintf(s, s_len - 1, "%s%c%c%c", base, MAGIC_CHAR, base36(csum / 36),
	         base36(csum % 36));

	if (*extension) {
		fstrcat(s, ".");
		fstrcat(s, extension);
	}
	DEBUG("%s\n", s);
}

/*******************************************************************
  work out if a name is illegal, even for long names
  ******************************************************************/
static bool illegal_name(char *name)
{
	static unsigned char illegal[256];
	static bool initialised = false;
	unsigned char *s;

	if (!initialised) {
		char *ill = "*\\/?<>|\":";
		initialised = true;

		bzero((char *) illegal, 256);
		for (s = (unsigned char *) ill; *s; s++)
			illegal[*s] = true;
	}

	for (s = (unsigned char *) name; *s;) {
		if (illegal[*s])
			return true;
		else
			s++;
	}

	return false;
}

/****************************************************************************
convert a filename to DOS format. return true if successful.
****************************************************************************/
void name_map_mangle(char *OutName, bool need83, const struct share *share)
{
#ifdef MANGLE_LONG_FILENAMES
	if (!need83 && illegal_name(OutName))
		need83 = true;
#endif

	/* check if it's already in 8.3 format */
	if (need83 && !is_8_3(OutName, true)) {
		/* mangle it into 8.3 */
		mangle_name_83(OutName, sizeof(pstring) - 1);
	}
}
