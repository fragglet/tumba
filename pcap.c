/* 
   Unix SMB/Netbios implementation.
   Version 1.5.
   Copyright (C) Karl Auer 1993,1994
   
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

/*
 *  Parse printcap file.
 *
 *  This module does exactly one thing - it looks into the printcap file
 *  and tells callers if a specified string appears as a printer name.
 *
 *  The way this module looks at the printcap file is very simplistic.
 *  Firstly, only the local printcap file is inspected (no searching
 *  of NIS databases etc). Secondly, it is assumed that printer name
 *  entries contain at least one vertical bar symbol ('|'). Entries
 *  without such a symbol are ignored.
 *
 *  Method:
 *  1 Read printcap a character at a time until we see a non-whitespace
 *    character. If it is a hash symbol, read and discard characters until
 *    and including EOL. Treat '\' as whitespace. If EOF encountered, return
 *    FALSE.
 *
 *  2 Collect all characters into a single string until a colon or bar
 *    is encountered. If '\' is encountered, read and discard characters
 *    until and including EOL. If newline or EOF encountered, treat as a 
 *    colon.
 *
 *  3 Provided that a bar has been seen, compare the resulting string (less
 *    leading and trailing whitespace) to the target string. If it matches,
 *    stop searching and return True. Otherwise discard the string and the
 *    colon or bar and go to step 1.
 *
 *  4 Return False.
 *    
 *
 *  Opening a pipe for "lpc status" and reading that would probably 
 *  be pretty effective. Code to do this already exists in the freely
 *  distributable PCNFS server code.
 */

#include "includes.h"

#include "smb.h"
#include "loadparm.h"
#include "pcap.h"

/* maximum string to parse from printcap */
#define MAX_COLLECT 256

/* these things terminate a field in printcap (for our purposes, anyway)*/
#define IS_TERM(c) ((c) == EOF || (c) == ':' || (c) == '|')

/* local prototypes */
static int read_until_nonwhite(FILE *pfile);
static void read_until_eol(FILE *pfile);
static char *collect_string(FILE *pfile);


/***************************************************************************
Read passed file until a non-whitespace character is encountered. Return the
character, or EOF on error/EOF. The character is pushed back on the stream.
***************************************************************************/
static int read_until_nonwhite(FILE *pfile)
{
   int c;

   do
      c = getc(pfile);
   while (isspace(c) && (c != EOF));  /* end do */

   if (c != EOF)
     ungetc(c, pfile);
   else
     if (ferror(pfile))
         Debug(0, "Read error on printcap file!\n");

   return (c);
}

/***************************************************************************
Read passed file until end of line.
***************************************************************************/
static void read_until_eol(FILE *pfile)
{
   int c;

   do
      c = getc(pfile);
   while ((c != '\n') && (c != EOF));  /* end do */

   if (c == EOF)
     if (ferror(pfile))
         Debug(0, "Read error on printcap file!\n");
}

/***************************************************************************
Collect a string from the passed file. Remember '\' and discard from and
including it if EOL encountered before non-whitespace. Ie., treat '\' as
a continuation charactare, but only if it is the last non-whitespace
character on a line. There is an arbitrary limit on the length of a 
collected string. Collection continues until EOF, a colon, a vertical bar
or a non-continued newline is encountered, whereupon the terminating 
character is discarded, and leading and trailing spaces removed from the 
collected string.
Rather simple-mindedly, this routine only returns strings that either end
with or begin with a vertical bar.

Return a pointer to the collected string. If this function returns NULL, 
then an error occurred and has been logged. If it returns an empty string,
then a normal EOF has been encountered. Empty fields are logged for 
information.

Warnings:

The returned string is stored statically - each call to this function 
destroys the previously collected string.

A static boolean is used to keep track of whether bar symbols have been
encountered.

The logic concerning bBarSeen is deceptive! Be careful if modifying it.
PLEASE keep the comments up to date if you do - for all our sakes...
***************************************************************************/
static char *collect_string(FILE *pfile)
{
   static char szBuf[MAX_COLLECT + 1];
   static BOOL bBarSeen = False;

   int iSlashOffset;
   int iNonwhiteOffset;
   BOOL bError;
   BOOL bSlash;
   int i;
   int c;

   bError = False;
   iNonwhiteOffset = 0;
   i = 0;
   do
   {
      /* get a character. If it's a terminator AND we've already seen a bar, */
      /* OR the terminator is a bar, stop collecting. If it's a bar, set the */
      /* "bar seen" flag for next time. If it's not a bar and we haven't seen*/
      /* one, empty the string and start collecting from scratch. */
      c = getc(pfile);
      if (IS_TERM(c))
      {
         /* If we've seen a bar already we break to inspect this string. */
         /* first we set the "bar seen" flag according to the terminator.*/
         if (bBarSeen)
	 {
            bBarSeen = (c == '|');
            break;
	 }

         /* if we HAVEN'T already seen a bar, check whether the current */
         /* terminator is a bar. If it is, break to inspect the string. */
         bBarSeen = (c == '|');
         if (bBarSeen)
            break;

         /* if we haven't already seen a bar AND the current terminator */
         /* isn't a bar, chuck this string and loop to collect another. */
         i = iNonwhiteOffset = 0;
         continue;
      }

      /* if it's a slash, remember where it was and that we saw it */
      if (c == '\\')
      {
         iSlashOffset = i;
         bSlash = True;
      }

      /* if it's a newline and we've seen nothing but whitespace since */
      /* a slash, discard the newline and everything after the slash.  */
      /* Otherwise, treat the newline as a terminator. */
      if (c == '\n')
         if (bSlash)
         {
            /* discard back to the offset of the slash */
            i = iSlashOffset;
            bSlash = False;
            continue;
	 }
         else
            break;

      /* if we see non-whitespace after a slash, treat the slash as an */
      /* ordinary character. We note the offset of this non-whitespace */
      /* character so that we can truncate back to it when the string  */
      /* has been collected. */
      if (!isspace(c))
      {
         iNonwhiteOffset = i;
         bSlash = False;
      }

      /* Finally, collect the character. Issue a debug warning if the   */
      /* collected string is truncated, and treat as an ERROR. We don't */
      /* want it to accidentally match something else! */
      if (i < MAX_COLLECT)
         szBuf[i++] = c;
      else
      {
         Debug(0, "String too long while searching printcap (\"%s\"\n", szBuf);
         bError = True;
         break;
      }
   }
   while (!bError);  /* end do */

   /* Check that no file error occurred. */
   if (c == EOF)
      if (ferror(pfile))
      {
         Debug(0, "Read error on printcap file!\n");
         bError = True;
      }

   /* If no errors have occurred, return the string after terminating it. */
   /* Otherwise, return NULL. */
   if (!bError)
   {
      /* Make sure string is properly terminated. Remember to add one */
      /* to the nonwhite offset, or we will wipe the last character  */
      /* of the string.*/
      iNonwhiteOffset++;
      if (iNonwhiteOffset < i)
         i = iNonwhiteOffset;
      szBuf[i] = '\0';
      if (i < 1)
         Debug(3, "Empty printer name field in printcap (warning only).\n");
#if 0
      else
         Debug(3, "collect_string() returning: \"%s\"\n", szBuf);
#endif
      return (szBuf);
   }

   return (NULL);
}

/***************************************************************************
Scan printcap file pszPrintcapname for a printer called pszPrintername. 
Return True if found, else False. Returns False on error, too, after logging 
the error at level 0. For generality, the printcap name may be passed - if
passed as NULL, the configuration will be queried for the name.
***************************************************************************/
BOOL pcap_printername_ok(char *pszPrintername, char *pszPrintcapname)
{
   BOOL bRetval;
   FILE *pfile;
   char *psz;
   int c;

   bRetval = False;
   if (pszPrintername == NULL || pszPrintername[0] == '\0')
   {
      Debug(0, "Attempt to locate null printername! Internal error?\n");
      return (bRetval);
   }

   /* only go looking if no printcap name supplied */
   if ((psz = pszPrintcapname) == NULL || psz[0] == '\0')
      if (((psz = lp_printcapname()) == NULL) || (psz[0] == '\0'))
      {
         Debug(0, "No printcap file name configured!\n");
         return (bRetval);
      }

   if ((pfile = fopen(psz, "rt")) == NULL)
      Debug(0, "Unable to open printcap file %s for read!\n", psz);
   else   
   {
      while (!feof(pfile))
      {
         /* discard spaces and newlines etc. */
         c = read_until_nonwhite(pfile);
         if (c == EOF)
            break;
         
         /* discard comment lines too */
         if (c == '#')
	 {
            read_until_eol(pfile);
            continue;
	 }

         /* collect a string for comparison */
         psz = collect_string(pfile);
         if (psz == NULL)
	 {
            Debug(0, "Error parsing printcap file %s!\n", psz);
            break;
	 }

         /* stop on first match */
         if (strcmp(pszPrintername, psz) == 0)
         {
            bRetval = True;
            break;
	 }
      }  /* end while */

      fclose(pfile);
   }

   return (bRetval);
}
