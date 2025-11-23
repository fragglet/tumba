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
#include <stdint.h>

#include "strfunc.h"

#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(x, y) __attribute__((format(printf, x, y)))
#else
#define PRINTF_ATTRIBUTE(x, y)
#endif

/* logging interface */
#define LOG(funcname, linenum, level, ...)                                     \
	do {                                                                   \
		if (LOGLEVEL >= (level)) {                                     \
			log_output(funcname, linenum, level, __VA_ARGS__);     \
		}                                                              \
	} while (0)

#define ERROR(...)   LOG(0, 0, 0, __VA_ARGS__)
#define WARNING(...) LOG(0, 0, 1, __VA_ARGS__)
#define NOTICE(...)  LOG(0, 0, 2, __VA_ARGS__)
#define INFO(...)    LOG(0, 0, 3, __VA_ARGS__)
#define DEBUG(...)   LOG(__func__, __LINE__, 4, __VA_ARGS__)
#define DEBUG_(...)  LOG(0, 0, 4, __VA_ARGS__)

/* limiting size of ipc replies */
#define REALLOC(ptr, size) checked_realloc(ptr, MAX((size), 4 * 1024))

#define checked_malloc(bytes) checked_realloc(NULL, bytes)
#define arrlen(x)             (sizeof(x) / sizeof(*(x)))

struct stat;

extern int Client;
extern int smb_read_error;
extern fstring local_machine;
extern int LOGLEVEL;
extern int Protocol;
extern int chain_size;
extern char client_addr[32];

void setup_logging(char *pname);
void open_log_file(const char *filename);
int log_output(const char *funcname, int linenum, int level, char *format_str,
               ...) PRINTF_ATTRIBUTE(4, 5);
bool file_exist(char *fname, struct stat *sbuf);
bool directory_exist(char *dname, struct stat *st);
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
void block_signals(bool block, int signum);
