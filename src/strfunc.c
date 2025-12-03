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

#include "strfunc.h"

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "byteorder.h"
#include "guards.h" /* IWYU pragma: keep */
#include "smb.h"
#include "util.h"

static uint8_t valid_dos_chars[32];

void init_dos_char_table(void)
{
	int i;

#ifdef LC_ALL
	/* include <locale.h> if available for OS */
	/* we take only standard 7-bit ASCII definitions from ctype */
	setlocale(LC_ALL, "C");
#endif

	memset(valid_dos_chars, 0, sizeof(valid_dos_chars));

	for (i = 0; i <= 127; i++) {
		if (isalnum((char) i) ||
		    strchr("._^$~!#%&-{}()@'`", (char) i)) {
			valid_dos_chars[i / 8] |= 1 << (i % 8);
		}
	}
}

int isdoschar(int c)
{
	unsigned int bit;
	c &= 0xff;
	bit = c % 8;
	return (valid_dos_chars[c / 8] & (1 << bit)) != 0;
}

bool strequal(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;

	return strcasecmp(s1, s2) == 0;
}

bool strcsequal(char *s1, char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;

	return strcmp(s1, s2) == 0;
}

void strlower(char *s)
{
	for (; *s != '\0'; ++s) {
		*s = tolower(*s);
	}
}

void strupper(char *s)
{
	for (; *s != '\0'; ++s) {
		*s = toupper(*s);
	}
}

/* Convert a string to "normal" form */
void strnorm(char *s)
{
	strlower(s);
}

/* Check if a string is in "normal" case */
bool strisnormal(char *s)
{
	return !strhasupper(s);
}

static void string_replace(char *s, char oldc, char newc)
{
	while (*s) {
		if (oldc == *s)
			*s = newc;
		s++;
	}
}

/* Make a file into unix format */
void unix_format(char *fname)
{
	pstring namecopy;
	string_replace(fname, '\\', '/');

	if (*fname == '/') {
		pstrcpy(namecopy, fname);
		pstrcpy(fname, ".");
		pstrcat(fname, namecopy);
	}
}

/* Skip past a string in a buffer */
char *skip_string(char *buf)
{
	return buf + strlen(buf) + 1;
}

/* Trim the specified elements off the front and back of a string */
bool trim_string(char *s, char *front, char *back)
{
	bool ret = false;
	while (front && *front && strncmp(s, front, strlen(front)) == 0) {
		char *p = s;
		ret = true;
		while (1) {
			if (!(*p = p[strlen(front)]))
				break;
			p++;
		}
	}
	while (back && *back && strlen(s) >= strlen(back) &&
	       strncmp(s + strlen(s) - strlen(back), back, strlen(back)) == 0) {
		ret = true;
		s[strlen(s) - strlen(back)] = 0;
	}
	return ret;
}

/* Reduce a file name, removing .. elements. */
void unix_clean_name(char *s)
{
	char *p = NULL;

	DEBUG("s=%s\n", s);

	/* remove any double slashes */
	string_sub(s, "//", "/");

	/* Remove leading ./ characters */
	if (strncmp(s, "./", 2) == 0) {
		trim_string(s, "./", NULL);
		if (*s == 0)
			pstrcpy(s, "./");
	}

	while ((p = strstr(s, "/../")) != NULL) {
		pstring s1;

		*p = 0;
		pstrcpy(s1, p + 3);

		if ((p = strrchr(s, '/')) != NULL)
			*p = 0;
		else
			*s = 0;
		pstrcat(s, s1);
	}

	trim_string(s, NULL, "/..");
}

/* Does a string have any uppercase chars in it? */
bool strhasupper(char *s)
{
	while (*s) {
		if (isupper(*s))
			return true;
		s++;
	}
	return false;
}

/* Interpret the weird netbios "name". Return the name type */
static int name_interpret(char *in, char *out)
{
	int ret;
	int len = (*in++) / 2;

	*out = 0;

	if (len > 30 || len < 1)
		return 0;

	while (len--) {
		if (in[0] < 'A' || in[0] > 'P' || in[1] < 'A' || in[1] > 'P') {
			*out = 0;
			return 0;
		}
		*out = ((in[0] - 'A') << 4) + (in[1] - 'A');
		in += 2;
		out++;
	}
	*out = 0;
	ret = out[-1];

	return ret;
}

/* Find a pointer to a netbios name */
static char *name_ptr(char *buf, int ofs)
{
	unsigned char c = *(unsigned char *) (buf + ofs);

	if ((c & 0xC0) == 0xC0) {
		uint16_t l;
		char p[2];
		memcpy(p, buf + ofs, 2);
		p[0] &= ~0xC0;
		l = RSVAL(p, 0);
		DEBUG("to pos %d from %d is %s\n", l, ofs, buf + l);
		return buf + l;
	} else
		return buf + ofs;
}

/* Extract a netbios name from a buf */
int name_extract(char *buf, int ofs, char *name)
{
	char *p = name_ptr(buf, ofs);
	int d = PTR_DIFF(p, buf + ofs);
	pstrcpy(name, "");
	if (d < -50 || d > 50)
		return 0;
	return name_interpret(p, name);
}

/* Return the total storage length of a mangled name */
int name_len(char *s)
{
	int len;

	/* If the two high bits of the byte are set, return 2. */
	if (0xC0 == (*(unsigned char *) s & 0xC0))
		return 2;

	/* Add up the length bytes. */
	for (len = 1; *s; s += (*s) + 1) {
		len += *s + 1;
	}

	return len;
}

/* Set a string value, deallocating any existing value */
void string_set(char **dest, char *src)
{
	free(*dest);
	*dest = checked_strdup(src);
}

/*
Substitute a string for a pattern in another string. Make sure there is
enough room!

This routine looks for pattern in s and replaces it with
insert. It may do multiple replacements.

return true if a substitution was done.
*/
bool string_sub(char *s, char *pattern, char *insert)
{
	bool ret = false;
	char *p;
	int ls, lp, li;

	if (!insert || !pattern || !s)
		return false;

	ls = strlen(s);
	lp = strlen(pattern);
	li = strlen(insert);

	if (!*pattern)
		return false;

	while (lp <= ls && (p = strstr(s, pattern))) {
		ret = true;
		memmove(p + li, p + lp, ls + 1 - (PTR_DIFF(p, s) + lp));
		memcpy(p, insert, li);
		s = p + li;
		ls = strlen(s);
	}
	return ret;
}

/* Recursive routine that is called by mask_match. Does the actual matching.
 * Returns true if matched, false if failed. */
static bool do_match(char *str, char *regexp)
{
	char *p;

	for (p = regexp; *p && *str;) {
		switch (*p) {
		case '?':
			str++;
			p++;
			break;

		case '*':
			/* Look for a character matching
			   the one after the '*' */
			p++;
			if (!*p)
				return true; /* Automatic match */
			while (*str) {
				while (*str && toupper(*p) != toupper(*str)) {
					str++;
				}
				/* Now eat all characters that match, as
				   we want the *last* character to match. */
				while (*str && toupper(*p) == toupper(*str)) {
					str++;
				}
				str--; /* We've eaten the match char after the
				          '*' */
				if (do_match(str, p)) {
					return true;
				}
				if (!*str) {
					return false;
				} else {
					str++;
				}
			}
			return false;

		default:
			if (toupper(*str) != toupper(*p)) {
				return false;
			}
			str++, p++;
			break;
		}
	}

	if (!*p && !*str)
		return true;

	if (!*p && str[0] == '.' && str[1] == 0) {
		return true;
	}

	if (!*str && *p == '?') {
		while (*p == '?')
			p++;
		return !*p;
	}

	if (!*str && *p == '*' && p[1] == '\0') {
		return true;
	}

	return false;
}

/* Find the number of chars in a string */
static int count_chars(char *s, char c)
{
	int count = 0;

	while (*s) {
		if (*s == c)
			count++;
		s++;
	}
	return count;
}

/*
 * Routine to match a given string with a regexp - uses
 * simplified regexp that takes * and ? only. Case can be
 * significant or not.
 * The 8.3 handling was rewritten by Ums Harald <Harald.Ums@pro-sieben.de>
 */
bool mask_match(char *str, char *regexp, bool trans2)
{
	char *p;
	pstring t_pattern, t_filename, te_pattern, te_filename;
	fstring ebase, eext, sbase, sext;

	bool matched = false;

	/* Make local copies of str and regexp */
	pstrcpy(t_pattern, regexp);
	pstrcpy(t_filename, str);

	/* Remove any *? and ** as they are meaningless */
	string_sub(t_pattern, "*?", "*");
	string_sub(t_pattern, "**", "*");

	if (strequal(t_pattern, "*"))
		return true;

	DEBUG("str=<%s> regexp=<%s>\n", t_filename, t_pattern);

	if (trans2) {
		/*
		 * Match each component of the regexp, split up by '.'
		 * characters.
		 */
		char *fp, *rp, *cp2, *cp1;
		bool last_wcard_was_star = false;
		int num_path_components, num_regexp_components;

		pstrcpy(te_pattern, t_pattern);
		pstrcpy(te_filename, t_filename);
		/*
		 * Remove multiple "*." patterns.
		 */
		string_sub(te_pattern, "*.*.", "*.");
		num_regexp_components = count_chars(te_pattern, '.');
		num_path_components = count_chars(te_filename, '.');

		/*
		 * Check for special 'hack' case of "DIR a*z". - needs to match
		 * a.b.c...z
		 */
		if (num_regexp_components == 0)
			matched = do_match(te_filename, te_pattern);
		else {
			for (cp1 = te_pattern, cp2 = te_filename; cp1;) {
				fp = strchr(cp2, '.');
				if (fp)
					*fp = '\0';
				rp = strchr(cp1, '.');
				if (rp)
					*rp = '\0';

				if (cp1[strlen(cp1) - 1] == '*')
					last_wcard_was_star = true;
				else
					last_wcard_was_star = false;

				if (!do_match(cp2, cp1)) {
					break;
				}

				cp1 = rp ? rp + 1 : NULL;
				cp2 = fp ? fp + 1 : "";

				if (last_wcard_was_star ||
				    (cp1 != NULL && *cp1 == '*')) {
					/* Eat the extra path components. */
					int i;

					for (i = 0;
					     i < num_path_components -
					             num_regexp_components;
					     i++) {
						fp = strchr(cp2, '.');
						if (fp)
							*fp = '\0';

						if (cp1 != NULL &&
						    do_match(cp2, cp1)) {
							cp2 = fp ? fp + 1 : "";
							break;
						}
						cp2 = fp ? fp + 1 : "";
					}
					num_path_components -= i;
				}
			}
			if (cp1 == NULL &&
			    (*cp2 == '\0' || last_wcard_was_star))
				matched = true;
		}
	} else {

		/* -------------------------------------------------
		 * Behaviour of Win95
		 * for 8.3 filenames and 8.3 Wildcards
		 * -------------------------------------------------
		 */
		if (strequal(t_filename, ".")) {
			/*
			 *  Patterns:  *.*  *. ?. ?  are valid
			 *
			 */
			if (strequal(t_pattern, "*.*") ||
			    strequal(t_pattern, "*.") ||
			    strequal(t_pattern, "?.") ||
			    strequal(t_pattern, "?"))
				matched = true;
		} else if (strequal(t_filename, "..")) {
			/*
			 *  Patterns:  *.*  *. ?. ? *.? are valid
			 *
			 */
			if (strequal(t_pattern, "*.*") ||
			    strequal(t_pattern, "*.") ||
			    strequal(t_pattern, "?.") ||
			    strequal(t_pattern, "?") ||
			    strequal(t_pattern, "*.?") ||
			    strequal(t_pattern, "?.*"))
				matched = true;
		} else {

			if ((p = strrchr(t_pattern, '.'))) {
				/*
				 * Wildcard has a suffix.
				 */
				*p = 0;
				fstrcpy(ebase, t_pattern);
				if (p[1]) {
					fstrcpy(eext, p + 1);
				} else {
					/* pattern ends in DOT: treat as if
					 * there is no DOT */
					*eext = 0;
					if (strequal(ebase, "*"))
						return true;
				}
			} else {
				/*
				 * No suffix for wildcard.
				 */
				fstrcpy(ebase, t_pattern);
				eext[0] = 0;
			}

			p = strrchr(t_filename, '.');
			if (p && p[1] == 0) {
				/*
				 * Filename has an extension of '.' only.
				 */
				*p = 0; /* nuke dot at end of string */
				p = 0;  /* and treat it as if there is no
				           extension */
			}

			if (p) {
				/*
				 * Filename has an extension.
				 */
				*p = 0;
				fstrcpy(sbase, t_filename);
				fstrcpy(sext, p + 1);
				if (*eext) {
					matched = do_match(sbase, ebase) &&
					          do_match(sext, eext);
				} else {
					/* pattern has no extension */
					/* Really: match complete filename with
					 * pattern ??? means exactly 3 chars */
					matched = do_match(str, ebase);
				}
			} else {
				/*
				 * Filename has no extension.
				 */
				fstrcpy(sbase, t_filename);
				fstrcpy(sext, "");
				if (*eext) {
					/* pattern has extension */
					matched = do_match(sbase, ebase) &&
					          do_match(sext, eext);
				} else {
					matched = do_match(sbase, ebase);
#ifdef EMULATE_WEIRD_W95_MATCHING
					/*
					 * Even Microsoft has some problems
					 * Behaviour Win95 -> local disk
					 * is different from Win95 -> smb drive
					 * from Nt 4.0 This branch would reflect
					 * the Win95 local disk behaviour
					 */
					if (!matched) {
						/* a? matches aa and a in w95 */
						fstrcat(sbase, ".");
						matched =
						    do_match(sbase, ebase);
					}
#endif
				}
			}
		}
	}

	DEBUG("returning %d\n", matched);

	return matched;
}

/* Write a string in unicoode format */
int put_unicode(char *dst, char *src)
{
	int ret = 0;
	while (*src) {
		dst[ret++] = src[0];
		dst[ret++] = 0;
		src++;
	}
	dst[ret++] = 0;
	dst[ret++] = 0;
	return ret;
}

/* Safe string copy into a known length string. dest_size is the size of the
 * destination buffer */
char *safe_strcpy(char *dest, const char *src, int dest_size)
{
	size_t len;

	if (!src) {
		strlcpy(dest, "", dest_size);
		return dest;
	}

	len = strlcpy(dest, src, dest_size);
	if (len > dest_size - 1) {
		ERROR("ERROR: string overflow by %d in safe_strcpy [%.50s]\n",
		      (int) (len - dest_size + 1), src);
	}

	return dest;
}

/* Safe string cat into a string. dest_size is the size of the destination
 * buffer */
char *safe_strcat(char *dest, const char *src, int dest_size)
{
	size_t len;

	if (src == NULL) {
		return dest;
	}

	len = strlcat(dest, src, dest_size);
	if (len > dest_size - 1) {
		ERROR("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
		      (int) (len - dest_size + 1), src);
	}

	return dest;
}
