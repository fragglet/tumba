/*
This module is an adaption of code from the tcpd-1.4 package written
by Wietse Venema, Eindhoven University of Technology, The Netherlands.

The code is used here with permission.

The code has been considerably changed from the original. Bug reports
should be sent to samba-bugs@samba.anu.edu.au
*/

#include "includes.h"

#define ALLOW_PURE_ADDRESSES

extern int DEBUGLEVEL;

#ifndef INADDR_NONE
#define INADDR_NONE ((uint32) ~0)
#endif

#define Good True
#define Bad False

/* Delimiters for lists of daemons or clients. */

static char sep[] = ", \t";

/* Constants to be used in assignments only, not in comparisons... */

#define YES 1
#define NO 0
#define FAIL (-1)

/* Forward declarations. */
static int string_match(char *tok, char *s);
static int masked_match(char *tok, char *slash, char *s);

/* Size of logical line buffer. */
#define BUFLEN 2048

/* return true if access should be allowed to a service*/
BOOL check_access(int snum)
{
	return True;
}

/* string_match - match string against token */
static int string_match(char *tok, char *s)
{
	int tok_len;
	int str_len;
	char *cut;

	/*
	 * Return YES if a token has the magic value "ALL". Return FAIL if the
	 * token is "FAIL". If the token starts with a "." (domain name), return
	 * YES if it matches the last fields of the string. If the token has the
	 * magic value "LOCAL", return YES if the string does not contain a "."
	 * character. If the token ends on a "." (network number), return YES if
	 * it matches the first fields of the string. If the token begins with a
	 * "@" (netgroup name), return YES if the string is a (host) member of
	 * the netgroup. Return YES if the token fully matches the string. If
	 * the token is a netnumber/netmask pair, return YES if the address is a
	 * member of the specified subnet.
	 */

	if (tok[0] == '.') { /* domain: match last fields */
		if ((str_len = strlen(s)) > (tok_len = strlen(tok)) &&
		    strcasecmp(tok, s + str_len - tok_len) == 0)
			return (YES);
	} else if (tok[0] == '@') { /* netgroup: look it up */
		DEBUG(0, ("access: netgroup support is not configured\n"));
		return (NO);
	} else if (strcasecmp(tok, "ALL") == 0) { /* all: match any */
		return (YES);
	} else if (strcasecmp(tok, "FAIL") == 0) { /* fail: match any */
		return (FAIL);
	} else if (strcasecmp(tok, "LOCAL") == 0) { /* local: no dots */
		if (strchr(s, '.') == 0 && strcasecmp(s, "unknown") != 0)
			return (YES);
	} else if (!strcasecmp(tok, s)) { /* match host name or address */
		return (YES);
	} else if (tok[(tok_len = strlen(tok)) - 1] == '.') { /* network */
		if (strncmp(tok, s, tok_len) == 0)
			return (YES);
	} else if ((cut = strchr(tok, '/')) != 0) { /* netnumber/netmask */
		if (isdigit(s[0]) && masked_match(tok, cut, s))
			return (YES);
	}
	return (NO);
}

/* masked_match - match address against netnumber/netmask */
static int masked_match(char *tok, char *slash, char *s)
{
	uint32 net;
	uint32 mask;
	uint32 addr;

	if ((addr = interpret_addr(s)) == INADDR_NONE)
		return (NO);
	*slash = 0;
	net = interpret_addr(tok);
	*slash = '/';
	if (net == INADDR_NONE ||
	    (mask = interpret_addr(slash + 1)) == INADDR_NONE) {
		DEBUG(0, ("access: bad net/mask access control: %s", tok));
		return (NO);
	}
	return ((addr & mask) == net);
}
