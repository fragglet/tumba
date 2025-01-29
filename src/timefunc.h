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
