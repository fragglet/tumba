/*
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#define IPC_SHARE_NAME "IPC$"

struct share {
	char *name;
	char *path;
	char *description;
};

extern const struct share *ipc_service;

const struct share *lookup_share(const char *name);
const struct share *add_share(const char *path);
void add_ipc_service(void);
const struct share *get_share(unsigned int idx);
int shares_count(void);
