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

#ifndef GUARDS_H
#define GUARDS_H

/* This file defines guard #define macros to prevent use of dangerous
   functions. */

/* Do not use; use pstrcpy, fstrcpy, strlcpy instead */
#ifdef strcpy
#undef strcpy
#endif
#define strcpy(dest, src) __ERROR__XX__NEVER_USE_STRCPY___

/* Do not use; use pstrcat, fstrcat, strlcat instead */
#ifdef strcat
#undef strcat
#endif
#define strcat(dest, src) __ERROR__XX__NEVER_USE_STRCAT___

/* Do not use; use snprintf instead */
#ifdef sprintf
#undef sprintf
#endif
#define sprintf __ERROR__XX__NEVER_USE_SPRINTF__

/* Do not use; use checked_malloc instead */
#ifdef malloc
#undef malloc
#endif
#define malloc(x) __ERROR__XX_NEVER_USE_MALLOC__

/* Do not use; use checked_realloc instead */
#ifdef realloc
#undef realloc
#endif
#define realloc(x, y) __ERROR__XX_NEVER_USE_REALLOC__

/* Do not use; use checked_calloc instead */
#ifdef calloc
#undef calloc
#endif
#define calloc(x, y) __ERROR__XX_NEVER_USE_CALLOC__

/* Do not use; use checked_strdup instead */
#ifdef strdup
#undef strdup
#endif
#define strdup(x) __ERROR__XX_NEVER_USE_STRDUP__

#endif
