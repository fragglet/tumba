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

#include <stdbool.h>
#include <stddef.h>

#define pstrcpy(d, s) safe_strcpy((d), (s), sizeof(pstring))
#define pstrcat(d, s) safe_strcat((d), (s), sizeof(pstring))
#define fstrcpy(d, s) safe_strcpy((d), (s), sizeof(fstring))
#define fstrcat(d, s) safe_strcat((d), (s), sizeof(fstring))

typedef char pstring[1024];
typedef char fstring[128];

int isdoschar(int c);
void init_dos_char_table(void);
bool strequal(const char *s1, const char *s2);
bool strcsequal(char *s1, char *s2);
void strlower(char *s);
void strupper(char *s);
void strnorm(char *s);
bool strisnormal(char *s);
void unix_format(char *fname);
char *skip_string(char *buf, int n);
bool trim_string(char *s, char *front, char *back);
void unix_clean_name(char *s);
bool strhasupper(char *s);
int name_extract(char *buf, int ofs, char *name);
int name_len(char *s);
void string_set(char **dest, char *src);
bool string_sub(char *s, char *pattern, char *insert);
bool mask_match(char *str, char *regexp, bool trans2);
int put_unicode(char *dst, char *src);
char *safe_strcpy(char *dest, const char *src, int dest_size);
char *safe_strcat(char *dest, const char *src, int dest_size);

/* TODO: Remove these once their addition to glibc is less recent */
size_t strlcat(char *, const char *, size_t);
size_t strlcpy(char *, const char *, size_t);
