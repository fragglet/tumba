/*
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

#include <stdbool.h>

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
bool string_init(char **dest, char *src);
void string_free(char **s);
bool string_set(char **dest, char *src);
bool string_sub(char *s, char *pattern, char *insert);
bool mask_match(char *str, char *regexp, bool trans2);
int put_unicode(char *dst, char *src);
char *safe_strcpy(char *dest, const char *src, int dest_size);
char *safe_strcat(char *dest, const char *src, int dest_size);
char *tab_depth(int depth);
