/*
   Copyright (C) 2025 Simon Howard

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

#include <stdlib.h>
#include <assert.h>
#include <libgen.h>

#include "includes.h"
#include "smb.h"

static struct share *shares;
static int num_shares;

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

const struct share *add_share(const char *path)
{
	struct share *result;
	char *name = basename((char *) path);

	assert(lookup_share(name) == NULL);

	shares = realloc(shares, (num_shares + 1) * sizeof(*shares));
	assert(shares != NULL);

	result = &shares[num_shares];
	++num_shares;

	result->name = strdup(name);
	assert(result->name != NULL);
	result->path = strdup(path);
	assert(result->path != NULL);
	result->description = strdup(path);
	assert(result->path != NULL);

	return result;
}

const struct share *get_share(unsigned int idx)
{
	if (idx >= num_shares) {
		return NULL;
	}

	return &shares[idx];
}
