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
#include <time.h>

struct stat;

void time_init(void);
int time_zone(time_t t);
time_t interpret_long_date(char *p);
void put_long_date(char *p, time_t t);
bool null_mtime(time_t mtime);
void put_dos_date(char *buf, int offset, time_t unixdate);
void put_dos_date2(char *buf, int offset, time_t unixdate);
void put_dos_date3(char *buf, int offset, time_t unixdate);
time_t make_unix_date2(void *date_ptr);
time_t make_unix_date3(void *date_ptr);
char *timestring(void);
time_t get_create_time(struct stat *st);
