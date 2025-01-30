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

#include "smb.h"

/* logging interface */
#define LOG(level, ...)                                                        \
	do {                                                                   \
		if (LOGLEVEL >= (level)) {                                     \
			log_output(level, __VA_ARGS__);                        \
		}                                                              \
	} while (0)

#define ERROR(...)   LOG(0, __VA_ARGS__)
#define WARNING(...) LOG(1, __VA_ARGS__)
#define NOTICE(...)  LOG(2, __VA_ARGS__)
#define INFO(...)    LOG(3, __VA_ARGS__)
#define DEBUG(...)   LOG(4, __VA_ARGS__)

struct stat;

extern int Client;
extern int smb_read_error;
extern fstring local_machine;
extern int LOGLEVEL;
extern int Protocol;
extern int chain_size;
extern pstring debugf;
extern char client_addr[32];

void setup_logging(char *pname);
int log_output(int level, char *, ...);
void reopen_logs(void);
bool file_exist(char *fname, struct stat *sbuf);
bool directory_exist(char *dname, struct stat *st);
uint32_t file_size(char *file_name);
void show_msg(char *buf);
int smb_len(char *buf);
void _smb_setlen(char *buf, int len);
void smb_setlen(char *buf, int len);
int set_message(char *buf, int num_words, int num_bytes, bool zero);
int smb_buflen(char *buf);
char *smb_buf(char *buf);
int smb_offset(char *p, char *buf);
void close_low_fds(void);
int read_data(int fd, char *buffer, int N);
int write_data(int fd, char *buffer, int N);
int read_smb_length_return_keepalive(int fd, char *inbuf, int timeout);
int read_smb_length(int fd, char *inbuf, int timeout);
bool send_smb(int fd, char *buffer);
void *checked_realloc(void *p, size_t bytes);
void *checked_calloc(size_t nmemb, size_t size);
char *checked_strdup(const char *s);
char *gidtoname(int gid);
void block_signals(bool block, int signum);
void ajt_panic(void);
