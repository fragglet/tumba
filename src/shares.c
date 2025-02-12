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
#include <ctype.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guards.h" /* IWYU pragma: keep */
#include "strfunc.h"
#include "util.h"

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

static bool valid_share_name_char(char c)
{
	return isalnum(c) || c == '_' || c == '-';
}

static char *share_name_for_path(const char *path)
{
	char *base = basename((char *) path);
	int i;

	/* A special case that is probably a bad idea: */
	if (!strcmp(base, "/")) {
		base = checked_strdup("root");
	} else {
		base = checked_strdup(base);
	}

	/* Squash any unusual characters: */
	for (i = 0; base[i] != '\0'; ++i) {
		if (!valid_share_name_char(base[i])) {
			base[i] = '_';
		}
	}

	/* The happy case: */
	if (lookup_share(base) == NULL) {
		return base;
	}

	/* Find an alternative name: */
	for (i = 2;; ++i) {
		fstring result;
		snprintf(result, sizeof(result), "%s_%d", base, i);
		if (lookup_share(result) == NULL) {
			free(base);
			return checked_strdup(result);
		}
	}
}

const struct share *add_share(const char *path)
{
	char *share_name = share_name_for_path(path);
	struct share *result;

	result = _add_share();
	result->name = share_name;
	result->path = checked_strdup(path);
	result->description = checked_strdup(path);

	INFO("Sharing path %s as share name %s\n", result->path, result->name);
	return result;
}

void add_ipc_service(void)
{
	struct share *ipc;

	assert(lookup_share(IPC_SHARE_NAME) == NULL);

	ipc = _add_share();
	ipc->name = IPC_SHARE_NAME;
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
