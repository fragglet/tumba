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

#include <stddef.h>
#include <sys/types.h>

struct utimbuf;

int sys_utime(char *fname, struct utimbuf *times);
ssize_t sys_getxattr(const char *path, const char *name, void *value,
                     size_t size);
ssize_t sys_setxattr(const char *path, const char *name, void *value,
                     size_t size);
