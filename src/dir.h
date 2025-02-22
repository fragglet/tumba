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
#include <stdint.h>
#include <time.h>

struct share;
struct stat;

void init_dptrs(void);
char *dptr_path(int key);
char *dptr_wcard(int key);
bool dptr_set_wcard(int key, char *wcard);
bool dptr_set_attr(int key, uint16_t attr);
uint16_t dptr_attr(int key);
void dptr_close(int key);
void dptr_closecnum(int cnum);
void dptr_idlecnum(int cnum);
void dptr_closepath(char *path, int pid);
int dptr_create(int cnum, char *path, bool expect_close, int pid);
bool dptr_fill(char *buf1, unsigned int key);
bool dptr_zero(char *buf);
void *dptr_fetch(char *buf, int *num);
void *dptr_fetch_lanman2(int dptr_num);
bool dir_check_ftype(int cnum, int mode, struct stat *st, int dirtype);
bool get_dir_entry(int cnum, char *mask, int dirtype, char *fname, int *size,
                   int *mode, time_t *date);
void *open_dir(int cnum, char *name);
void close_dir(void *p);
char *read_dir_name(void *p);
bool seek_dir(void *p, int pos);
int tell_dir(void *p);
void dir_cache_add(char *path, char *name, char *dname, const struct share *);
char *dir_cache_check(char *path, char *name, const struct share *);
void dir_cache_flush(const struct share *);
