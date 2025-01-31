/*
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "shares.h"

#include <assert.h>
#include <libgen.h>
#include <stddef.h>

#include "guards.h" /* IWYU pragma: keep */
#include "strfunc.h"
#include "util.h"

#define IPC_NAME "IPC$"

static struct share *shares;
static int num_shares;
const struct share *ipc_service;

int shares_count(void)
{
	return num_shares;
}

const struct share *lookup_share(const char *name)
{
	int i;

	for (i = 0; i < num_shares; i++) {
		if (strequal(shares[i].name, name)) {
			return &shares[i];
		}
	}

	return NULL;
}

static struct share *_add_share(void)
{
	struct share *result;
	shares = checked_realloc(shares, (num_shares + 1) * sizeof(*shares));

	result = &shares[num_shares];
	++num_shares;

	return result;
}

const struct share *add_share(const char *path)
{
	struct share *result;
	char *name = basename((char *) path);

	assert(lookup_share(name) == NULL);

	result = _add_share();
	result->name = checked_strdup(name);
	assert(result->name != NULL);
	result->path = checked_strdup(path);
	assert(result->path != NULL);
	result->description = checked_strdup(path);
	assert(result->path != NULL);

	return result;
}

void add_ipc_service(void)
{
	struct share *ipc;

	assert(lookup_share(IPC_NAME) == NULL);

	ipc = _add_share();
	ipc->name = IPC_NAME;
	ipc->description = "IPC service";

	ipc_service = ipc;
}

const struct share *get_share(unsigned int idx)
{
	if (idx >= num_shares) {
		return NULL;
	}

	return &shares[idx];
}
