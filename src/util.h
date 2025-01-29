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
#include <stddef.h>
#include <stdint.h>

struct stat;

void setup_logging(char *pname);
void reopen_logs(void);
bool file_exist(char *fname, struct stat *sbuf);
bool directory_exist(char *dname, struct stat *st);
uint32_t file_size(char *file_name);
int isdoschar(int c);
void init_dos_char_table(void);
bool strequal(const char *s1, const char *s2);
bool strcsequal(char *s1, char *s2);
void strlower(char *s);
void strupper(char *s);
void strnorm(char *s);
bool strisnormal(char *s);
void unix_format(char *fname);
void show_msg(char *buf);
int smb_len(char *buf);
void _smb_setlen(char *buf, int len);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, bool zero);
int smb_buflen(char *buf);
char *smb_buf(char *buf);
int smb_offset(char *p, char *buf);
char *skip_string(char *buf, int n);
bool trim_string(char *s, char *front, char *back);
void unix_clean_name(char *s);
bool strhasupper(char *s);
void close_low_fds(void);
int read_data(int fd, char *buffer, int N);
int write_data(int fd, char *buffer, int N);
int read_smb_length_return_keepalive(int fd, char *inbuf, int timeout);
int read_smb_length(int fd, char *inbuf, int timeout);
bool send_smb(int fd, char *buffer);
int name_extract(char *buf, int ofs, char *name);
int name_len(char *s);
bool string_init(char **dest, char *src);
void string_free(char **s);
bool string_set(char **dest, char *src);
bool string_sub(char *s, char *pattern, char *insert);
bool mask_match(char *str, char *regexp, bool trans2);
void *checked_realloc(void *p, size_t bytes);
void *checked_calloc(size_t nmemb, size_t size);
char *checked_strdup(const char *s);
const char *get_peer_addr(int fd);
int put_unicode(char *dst, char *src);
char *gidtoname(int gid);
void block_signals(bool block, int signum);
void ajt_panic(void);
char *safe_strcpy(char *dest, const char *src, int dest_size);
char *safe_strcat(char *dest, const char *src, int dest_size);
char *tab_depth(int depth);
