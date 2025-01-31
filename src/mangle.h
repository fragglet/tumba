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

struct share;

int str_checksum(char *s);
bool is_8_3(char *fname, bool check_case);
bool is_mangled(char *s);
void mangle_name_83(char *s, int s_len);
void name_map_mangle(char *OutName, bool need83, const struct share *share);
