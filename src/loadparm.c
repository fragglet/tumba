/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Parameter loading functions
   Copyright (C) Karl Auer 1993-1998

   Largely re-written by Andrew Tridgell, September 1994

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
 *  Load parameters.
 *
 *  This module provides suitable callback functions for the params
 *  module. It builds the internal table of service details which is
 *  then used by the rest of the server.
 *
 * To add a parameter:
 *
 * 1) add it to the global or service structure definition
 * 2) add it to the parm_table
 * 3) add it to the list of available functions (eg: using FN_GLOBAL_STRING())
 * 4) If it's a global then initialise it in init_globals. If a local
 *    (ie. service) parameter then initialise it in the sDefault structure
 *
 *
 * Notes:
 *   The configuration file is processed sequentially for speed. It is NOT
 *   accessed randomly as happens in 'real' Windows. For this reason, there
 *   is a fair bit of sequence-dependent code here - ie., code which assumes
 *   that certain things happen before others. In particular, the code which
 *   happens at the boundary between sections is delicately poised, so be
 *   careful!
 *
 */

#include "includes.h"

bool bLoaded = false;

extern int DEBUGLEVEL;
extern pstring myname;

/* some helpful bits */
#define pSERVICE(i) ServicePtrs[i]
#define iSERVICE(i) (*pSERVICE(i))
#define LP_SNUM_OK(iService)                                                   \
	(((iService) >= 0) && ((iService) < iNumServices) &&                   \
	 iSERVICE(iService).valid)
#define VALID(i) iSERVICE(i).valid

/* these are the types of parameter we have */
typedef enum {
	P_BOOL,
	P_BOOLREV,
	P_CHAR,
	P_INTEGER,
	P_OCTAL,
	P_STRING,
	P_USTRING,
	P_GSTRING,
	P_UGSTRING,
	P_ENUM
} parm_type;

typedef enum {
	P_LOCAL,
	P_NONE
} parm_class;

extern int extra_time_offset;

/*
 * This structure describes a single service.
 */
typedef struct {
	bool valid;
	char *szService;
	char *szPath;
	char *szCopy;
	char *comment;
	int iCreate_mask;
	int iCreate_force_mode;
	int iDir_mask;
	int iDir_force_mode;
	int iDefaultCase;
	bool bCaseSensitive;
	bool bShortCasePreserve;
	char dummy[3]; /* for alignment */
} service;

/* This is a default service used to prime a services structure */
static service sDefault = {
    true,       /* valid */
    NULL,       /* szService */
    NULL,       /* szPath */
    NULL,       /* szCopy */
    NULL,       /* comment */
    0744,       /* iCreate_mask */
    0000,       /* iCreate_force_mode */
    0755,       /* iDir_mask */
    0000,       /* iDir_force_mode */
    CASE_LOWER, /* iDefaultCase */
    false,      /* case sensitive */
    false,      /* short case preserve */
    ""          /* dummy */
};

/* local variables */
static service **ServicePtrs = NULL;
static int iNumServices = 0;
static int iServiceIndex = 0;

#define NUMPARAMETERS (sizeof(parm_table) / sizeof(struct parm_struct))

struct enum_list {
	int value;
	char *name;
};

static struct enum_list enum_case[] = {
    {CASE_LOWER, "lower"}, {CASE_UPPER, "upper"}, {-1, NULL}};

static struct parm_struct {
	char *label;
	parm_type type;
	parm_class class;
	void *ptr;
	bool (*special)(char *, char **);
	struct enum_list *enum_list;
} parm_table[] = {
    {"-valid", P_BOOL, P_LOCAL, &sDefault.valid, NULL, NULL},
    {"comment", P_STRING, P_LOCAL, &sDefault.comment, NULL, NULL},
    {"default case", P_ENUM, P_LOCAL, &sDefault.iDefaultCase, NULL, enum_case},
    {"case sensitive", P_BOOL, P_LOCAL, &sDefault.bCaseSensitive, NULL, NULL},
    {"casesignames", P_BOOL, P_LOCAL, &sDefault.bCaseSensitive, NULL, NULL},
    {"short preserve case", P_BOOL, P_LOCAL, &sDefault.bShortCasePreserve, NULL,
     NULL},
    {"path", P_STRING, P_LOCAL, &sDefault.szPath, NULL, NULL},
    {"directory", P_STRING, P_LOCAL, &sDefault.szPath, NULL, NULL},

    {NULL, P_BOOL, P_NONE, NULL, NULL, NULL}};

/***************************************************************************
Initialise the global parameter structure.
***************************************************************************/
static void init_globals(void)
{
	static bool done_init = false;

	if (!done_init) {
		int i;

		for (i = 0; parm_table[i].label; i++)
			if ((parm_table[i].type == P_STRING ||
			     parm_table[i].type == P_USTRING) &&
			    parm_table[i].ptr)
				string_init(parm_table[i].ptr, "");


		done_init = true;
	}
}

/******************************************************************* a
convenience routine to grab string parameters into a rotating buffer,
and run standard_sub_basic on them. The buffers can be written to by
callers without affecting the source string.
********************************************************************/
char *lp_string(char *s)
{
	static char *bufs[10];
	static int next = 0;
	char *ret;
	int len = s ? strlen(s) : 0;

	/* the +100 is for some substitution room */
	bufs[next] = realloc(bufs[next], len + 100);
	ret = &bufs[next][0];

	next = (next + 1) % 10;

	if (s == NULL) {
		ret[0] = '\0';
	} else {
		memcpy(ret, s, len + 1);
	}

	trim_string(ret, "\"", "\"");

	return ret;
}

/*
   In this section all the functions that are used to access the
   parameters from the rest of the program are defined
*/

#define FN_LOCAL_STRING(fn_name, val)                                          \
	char *fn_name(int i)                                                   \
	{                                                                      \
		return (lp_string((LP_SNUM_OK(i) && pSERVICE(i)->val)          \
		                      ? pSERVICE(i)->val                       \
		                      : sDefault.val));                        \
	}
#define FN_LOCAL_BOOL(fn_name, val)                                            \
	bool fn_name(int i)                                                    \
	{                                                                      \
		return (LP_SNUM_OK(i) ? pSERVICE(i)->val : sDefault.val);      \
	}
#define FN_LOCAL_CHAR(fn_name, val)                                            \
	char fn_name(int i)                                                    \
	{                                                                      \
		return (LP_SNUM_OK(i) ? pSERVICE(i)->val : sDefault.val);      \
	}
#define FN_LOCAL_INTEGER(fn_name, val)                                         \
	int fn_name(int i)                                                     \
	{                                                                      \
		return (LP_SNUM_OK(i) ? pSERVICE(i)->val : sDefault.val);      \
	}

FN_LOCAL_STRING(lp_servicename, szService)
FN_LOCAL_STRING(lp_pathname, szPath)
FN_LOCAL_STRING(lp_comment, comment)

FN_LOCAL_BOOL(lp_casesensitive, bCaseSensitive)
FN_LOCAL_BOOL(lp_shortpreservecase, bShortCasePreserve)

FN_LOCAL_INTEGER(lp_defaultcase, iDefaultCase)

/* local prototypes */
static int strwicmp(char *psz1, char *psz2);
static int map_parameter(char *pszParmName);
static bool set_boolean(bool *pb, char *pszParmValue);
static int getservicebyname(char *pszServiceName);
static void copy_service(service *pserviceDest, service *pserviceSource);
static bool service_ok(int iService);
static bool do_parameter(char *pszParmName, char *pszParmValue);
static bool do_section(char *pszSectionName);

/***************************************************************************
initialise a service to the defaults
***************************************************************************/
static void init_service(service *pservice)
{
	bzero((char *) pservice, sizeof(service));
	copy_service(pservice, &sDefault);
}

/***************************************************************************
free the dynamically allocated parts of a service struct
***************************************************************************/
static void free_service(service *pservice)
{
	int i;
	if (!pservice)
		return;

	if (pservice->szService)
		DEBUG(5, ("free_service: Freeing service %s\n",
		          pservice->szService));

	string_free(&pservice->szService);

	for (i = 0; parm_table[i].label; i++)
		if ((parm_table[i].type == P_STRING ||
		     parm_table[i].type == P_USTRING) &&
		    parm_table[i].class == P_LOCAL)
			string_free(
			    (char **) (((char *) pservice) +
			               PTR_DIFF(parm_table[i].ptr, &sDefault)));
}

/***************************************************************************
add a new service to the services array initialising it with the given
service
***************************************************************************/
static int add_a_service(service *pservice, char *name)
{
	int i;
	service tservice;
	int num_to_alloc = iNumServices + 1;

	tservice = *pservice;

	/* it might already exist */
	if (name) {
		i = getservicebyname(name);
		if (i >= 0)
			return (i);
	}

	/* find an invalid one */
	for (i = 0; i < iNumServices; i++)
		if (!pSERVICE(i)->valid)
			break;

	/* if not, then create one */
	if (i == iNumServices) {
		ServicePtrs = (service **) Realloc(
		    ServicePtrs, sizeof(service *) * num_to_alloc);
		if (ServicePtrs)
			pSERVICE(iNumServices) =
			    (service *) malloc(sizeof(service));

		if (!ServicePtrs || !pSERVICE(iNumServices))
			return (-1);

		iNumServices++;
	} else
		free_service(pSERVICE(i));

	pSERVICE(i)->valid = true;

	init_service(pSERVICE(i));
	copy_service(pSERVICE(i), &tservice);
	if (name)
		string_set(&iSERVICE(i).szService, name);

	return (i);
}

/***************************************************************************
add a new service, based on an old one
***************************************************************************/
int lp_add_service(char *pszService, int iDefaultService)
{
	return (add_a_service(pSERVICE(iDefaultService), pszService));
}

/***************************************************************************
add the IPC service
***************************************************************************/
static bool lp_add_ipc(void)
{
	pstring comment;
	int i = add_a_service(&sDefault, "IPC$");

	if (i < 0)
		return (false);

	slprintf(comment, sizeof(comment), "IPC Service (%s)",
	         lp_serverstring());

	string_set(&iSERVICE(i).szPath, tmpdir());
	string_set(&iSERVICE(i).comment, comment);

	DEBUG(3, ("adding IPC service\n"));

	return (true);
}

/***************************************************************************
Do a case-insensitive, whitespace-ignoring string compare.
***************************************************************************/
static int strwicmp(char *psz1, char *psz2)
{
	/* if BOTH strings are NULL, return TRUE, if ONE is NULL return */
	/* appropriate value. */
	if (psz1 == psz2)
		return (0);
	else if (psz1 == NULL)
		return (-1);
	else if (psz2 == NULL)
		return (1);

	/* sync the strings on first non-whitespace */
	while (1) {
		while (isspace(*psz1))
			psz1++;
		while (isspace(*psz2))
			psz2++;
		if (toupper(*psz1) != toupper(*psz2) || *psz1 == '\0' ||
		    *psz2 == '\0')
			break;
		psz1++;
		psz2++;
	}
	return (*psz1 - *psz2);
}

/***************************************************************************
Map a parameter's string representation to something we can use.
Returns false if the parameter string is not recognised, else TRUE.
***************************************************************************/
static int map_parameter(char *pszParmName)
{
	int iIndex;

	if (*pszParmName == '-')
		return (-1);

	for (iIndex = 0; parm_table[iIndex].label; iIndex++)
		if (strwicmp(parm_table[iIndex].label, pszParmName) == 0)
			return (iIndex);

	DEBUG(0, ("Unknown parameter encountered: \"%s\"\n", pszParmName));
	return (-1);
}

/***************************************************************************
Set a boolean variable from the text value stored in the passed string.
Returns true in success, false if the passed string does not correctly
represent a boolean.
***************************************************************************/
static bool set_boolean(bool *pb, char *pszParmValue)
{
	bool bRetval;

	bRetval = true;
	if (strwicmp(pszParmValue, "yes") == 0 ||
	    strwicmp(pszParmValue, "true") == 0 ||
	    strwicmp(pszParmValue, "1") == 0)
		*pb = true;
	else if (strwicmp(pszParmValue, "no") == 0 ||
	         strwicmp(pszParmValue, "false") == 0 ||
	         strwicmp(pszParmValue, "0") == 0)
		*pb = false;
	else {
		DEBUG(0,
		      ("Badly formed boolean in configuration file: \"%s\".\n",
		       pszParmValue));
		bRetval = false;
	}
	return (bRetval);
}

/***************************************************************************
Find a service by name. Otherwise works like get_service.
***************************************************************************/
static int getservicebyname(char *pszServiceName)
{
	int iService;

	for (iService = iNumServices - 1; iService >= 0; iService--)
		if (VALID(iService) && strwicmp(iSERVICE(iService).szService,
		                                pszServiceName) == 0) {
			break;
		}

	return (iService);
}

/***************************************************************************
Copy a service structure to another
***************************************************************************/
static void copy_service(service *pserviceDest, service *pserviceSource)
{
	int i;

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].ptr && parm_table[i].class == P_LOCAL) {
			void *def_ptr = parm_table[i].ptr;
			void *src_ptr = ((char *) pserviceSource) +
			                PTR_DIFF(def_ptr, &sDefault);
			void *dest_ptr = ((char *) pserviceDest) +
			                 PTR_DIFF(def_ptr, &sDefault);

			switch (parm_table[i].type) {
			case P_BOOL:
			case P_BOOLREV:
				*(bool *) dest_ptr = *(bool *) src_ptr;
				break;

			case P_INTEGER:
			case P_ENUM:
			case P_OCTAL:
				*(int *) dest_ptr = *(int *) src_ptr;
				break;

			case P_CHAR:
				*(char *) dest_ptr = *(char *) src_ptr;
				break;

			case P_STRING:
				string_set(dest_ptr, *(char **) src_ptr);
				break;

			case P_USTRING:
				string_set(dest_ptr, *(char **) src_ptr);
				strupper(*(char **) dest_ptr);
				break;
			default:
				break;
			}
		}
}

/***************************************************************************
Check a service for consistency. Return false if the service is in any way
incomplete or faulty, else true.
***************************************************************************/
static bool service_ok(int iService)
{
	bool bRetval;

	bRetval = true;
	if (iSERVICE(iService).szService[0] == '\0') {
		DEBUG(0,
		      ("The following message indicates an internal error:\n"));
		DEBUG(0, ("No service name in service entry.\n"));
		bRetval = false;
	}

	if (iSERVICE(iService).szPath[0] == '\0') {
		DEBUG(0, ("No path in service %s - using %s\n",
		          iSERVICE(iService).szService, tmpdir()));
		string_set(&iSERVICE(iService).szPath, tmpdir());
	}

	return (bRetval);
}

static struct file_lists {
	struct file_lists *next;
	char *name;
	time_t modtime;
} *file_lists = NULL;

/*******************************************************************
keep a linked list of all config files so we know when one has changed
it's date and needs to be reloaded
********************************************************************/
static void add_to_file_list(char *fname)
{
	struct file_lists *f = file_lists;

	while (f) {
		if (f->name && !strcmp(f->name, fname))
			break;
		f = f->next;
	}

	if (!f) {
		f = (struct file_lists *) malloc(sizeof(file_lists[0]));
		if (!f)
			return;
		f->next = file_lists;
		f->name = strdup(fname);
		if (!f->name) {
			free(f);
			return;
		}
		file_lists = f;
	}

	{
		pstring n2;
		pstrcpy(n2, fname);
		f->modtime = file_modtime(n2);
	}
}

/*******************************************************************
check if a config file has changed date
********************************************************************/
bool lp_file_list_changed(void)
{
	struct file_lists *f = file_lists;
	DEBUG(6, ("lp_file_list_changed()\n"));

	while (f) {
		pstring n2;
		time_t mod_time;

		pstrcpy(n2, f->name);

		DEBUG(6, ("file %s -> %s  last mod_time: %s\n", f->name, n2,
		          ctime(&f->modtime)));

		mod_time = file_modtime(n2);

		if (f->modtime != mod_time) {
			DEBUG(6,
			      ("file %s modified: %s\n", n2, ctime(&mod_time)));
			f->modtime = mod_time;
			return (true);
		}
		f = f->next;
	}
	return (false);
}

/***************************************************************************
Process a parameter for a particular service number. If snum < 0
then assume we are in the globals
***************************************************************************/
bool lp_do_parameter(int snum, char *pszParmName, char *pszParmValue)
{
	int parmnum, i;
	void *parm_ptr = NULL; /* where we are going to store the result */
	void *def_ptr = NULL;

	parmnum = map_parameter(pszParmName);

	if (parmnum < 0) {
		DEBUG(0, ("Ignoring unknown parameter \"%s\"\n", pszParmName));
		return (true);
	}

	def_ptr = parm_table[parmnum].ptr;

	parm_ptr = ((char *) pSERVICE(snum)) + PTR_DIFF(def_ptr, &sDefault);

	/* if it is a special case then go ahead */
	if (parm_table[parmnum].special) {
		parm_table[parmnum].special(pszParmValue, parm_ptr);
		return (true);
	}

	/* now switch on the type of variable it is */
	switch (parm_table[parmnum].type) {
	case P_BOOL:
		set_boolean(parm_ptr, pszParmValue);
		break;

	case P_BOOLREV:
		set_boolean(parm_ptr, pszParmValue);
		*(bool *) parm_ptr = !*(bool *) parm_ptr;
		break;

	case P_INTEGER:
		*(int *) parm_ptr = atoi(pszParmValue);
		break;

	case P_CHAR:
		*(char *) parm_ptr = *pszParmValue;
		break;

	case P_OCTAL:
		sscanf(pszParmValue, "%o", (int *) parm_ptr);
		break;

	case P_STRING:
		string_set(parm_ptr, pszParmValue);
		break;

	case P_USTRING:
		string_set(parm_ptr, pszParmValue);
		strupper(*(char **) parm_ptr);
		break;

	case P_GSTRING:
		pstrcpy((char *) parm_ptr, pszParmValue);
		break;

	case P_UGSTRING:
		pstrcpy((char *) parm_ptr, pszParmValue);
		strupper((char *) parm_ptr);
		break;

	case P_ENUM:
		for (i = 0; parm_table[parmnum].enum_list[i].name; i++) {
			if (strequal(pszParmValue,
			             parm_table[parmnum].enum_list[i].name)) {
				*(int *) parm_ptr =
				    parm_table[parmnum].enum_list[i].value;
				break;
			}
		}
		break;
	}

	return (true);
}

/***************************************************************************
Process a parameter.
***************************************************************************/
static bool do_parameter(char *pszParmName, char *pszParmValue)
{
	DEBUG(3, ("doing parameter %s = %s\n", pszParmName, pszParmValue));

	return lp_do_parameter(iServiceIndex, pszParmName, pszParmValue);
}

/***************************************************************************
print a parameter of the specified type
***************************************************************************/
static void print_parameter(struct parm_struct *p, void *ptr, FILE *f)
{
	int i;
	switch (p->type) {
	case P_ENUM:
		for (i = 0; p->enum_list[i].name; i++) {
			if (*(int *) ptr == p->enum_list[i].value) {
				fprintf(f, "%s", p->enum_list[i].name);
				break;
			}
		}
		break;

	case P_BOOL:
		fprintf(f, "%s", BOOLSTR(*(bool *) ptr));
		break;

	case P_BOOLREV:
		fprintf(f, "%s", BOOLSTR(!*(bool *) ptr));
		break;

	case P_INTEGER:
		fprintf(f, "%d", *(int *) ptr);
		break;

	case P_CHAR:
		fprintf(f, "%c", *(char *) ptr);
		break;

	case P_OCTAL:
		fprintf(f, "0%o", *(int *) ptr);
		break;

	case P_GSTRING:
	case P_UGSTRING:
		if ((char *) ptr)
			fprintf(f, "%s", (char *) ptr);
		break;

	case P_STRING:
	case P_USTRING:
		if (*(char **) ptr)
			fprintf(f, "%s", *(char **) ptr);
		break;
	}
}

/***************************************************************************
check if two parameters are equal
***************************************************************************/
static bool equal_parameter(parm_type type, void *ptr1, void *ptr2)
{
	switch (type) {
	case P_BOOL:
	case P_BOOLREV:
		return (*((bool *) ptr1) == *((bool *) ptr2));

	case P_INTEGER:
	case P_ENUM:
	case P_OCTAL:
		return (*((int *) ptr1) == *((int *) ptr2));

	case P_CHAR:
		return (*((char *) ptr1) == *((char *) ptr2));

	case P_GSTRING:
	case P_UGSTRING: {
		char *p1 = (char *) ptr1, *p2 = (char *) ptr2;
		if (p1 && !*p1)
			p1 = NULL;
		if (p2 && !*p2)
			p2 = NULL;
		return (p1 == p2 || strequal(p1, p2));
	}
	case P_STRING:
	case P_USTRING: {
		char *p1 = *(char **) ptr1, *p2 = *(char **) ptr2;
		if (p1 && !*p1)
			p1 = NULL;
		if (p2 && !*p2)
			p2 = NULL;
		return (p1 == p2 || strequal(p1, p2));
	}
	}
	return (false);
}

/***************************************************************************
Process a new section (service). At this stage all sections are services.
Later we'll have special sections that permit server parameters to be set.
Returns true on success, false on failure.
***************************************************************************/
static bool do_section(char *pszSectionName)
{
	bool bRetval;
	bRetval = false;

	/* if we have a current service, tidy it up before moving on */
	bRetval = true;

	if (iServiceIndex >= 0)
		bRetval = service_ok(iServiceIndex);

	/* if all is still well, move to the next record in the services array
	 */
	if (bRetval) {
		/* We put this here to avoid an odd message order if messages
		 * are */
		/* issued by the post-processing of a previous section. */
		DEBUG(2, ("Processing section \"[%s]\"\n", pszSectionName));

		if ((iServiceIndex = add_a_service(&sDefault, pszSectionName)) <
		    0) {
			DEBUG(0, ("Failed to add a new service\n"));
			return (false);
		}
	}

	return (bRetval);
}

/***************************************************************************
Display the contents of a single services record.
***************************************************************************/
static void dump_a_service(service *pService, FILE *f)
{
	int i;
	if (pService == &sDefault)
		fprintf(f, "\n\n# Default service parameters\n");
	else
		fprintf(f, "\n[%s]\n", pService->szService);

	for (i = 0; parm_table[i].label; i++)
		if (parm_table[i].class == P_LOCAL && parm_table[i].ptr &&
		    (*parm_table[i].label != '-') &&
		    (i == 0 || (parm_table[i].ptr != parm_table[i - 1].ptr))) {
			int pdiff = PTR_DIFF(parm_table[i].ptr, &sDefault);

			if (pService == &sDefault ||
			    !equal_parameter(parm_table[i].type,
			                     ((char *) pService) + pdiff,
			                     ((char *) &sDefault) + pdiff)) {
				fprintf(f, "\t%s = ", parm_table[i].label);
				print_parameter(&parm_table[i],
				                ((char *) pService) + pdiff, f);
				fprintf(f, "\n");
			}
		}
}

/***************************************************************************
Return TRUE if the passed service number is within range.
***************************************************************************/
bool lp_snum_ok(int iService)
{
	return LP_SNUM_OK(iService);
}

/***************************************************************************
have we loaded a services file yet?
***************************************************************************/
bool lp_loaded(void)
{
	return (bLoaded);
}

/***************************************************************************
unload unused services
***************************************************************************/
void lp_killunused(bool (*snumused)(int))
{
	int i;
	for (i = 0; i < iNumServices; i++)
		if (VALID(i) && (!snumused || !snumused(i))) {
			iSERVICE(i).valid = false;
			free_service(pSERVICE(i));
		}
}

/***************************************************************************
Load the services array from the services file. Return true on success,
false on failure.
***************************************************************************/
bool lp_load(char *pszFname)
{
	pstring n2;
	bool bRetval;

	add_to_file_list(pszFname);

	bRetval = false;

	init_globals();

	pstrcpy(n2, pszFname);

	/* We get sections first, so have to start 'behind' to make up */
	iServiceIndex = -1;
	bRetval = pm_process(n2, do_section, do_parameter);

	/* finish up the last section */
	DEBUG(3, ("pm_process() returned %s\n", BOOLSTR(bRetval)));
	if (bRetval)
		if (iServiceIndex >= 0)
			bRetval = service_ok(iServiceIndex);

	lp_add_ipc();

	bLoaded = true;

	return (bRetval);
}

/***************************************************************************
return the max number of services
***************************************************************************/
int lp_numservices(void)
{
	return (iNumServices);
}

/***************************************************************************
Display the contents of the services array in human-readable form.
***************************************************************************/
void lp_dump(FILE *f)
{
	int iService;

	dump_a_service(&sDefault, f);

	for (iService = 0; iService < iNumServices; iService++) {
		if (VALID(iService)) {
			if (iSERVICE(iService).szService[0] == '\0')
				break;
			dump_a_service(pSERVICE(iService), f);
		}
	}
}

/***************************************************************************
Return the number of the service with the given name, or -1 if it doesn't
exist. Note that this is a DIFFERENT ANIMAL from the internal function
getservicebyname()! This works ONLY if all services have been loaded, and
does not copy the found service.
***************************************************************************/
int lp_servicenumber(char *pszServiceName)
{
	int iService;

	for (iService = iNumServices - 1; iService >= 0; iService--)
		if (VALID(iService) &&
		    strequal(lp_servicename(iService), pszServiceName))
			break;

	if (iService < 0)
		DEBUG(7,
		      ("lp_servicenumber: couldn't find %s\n", pszServiceName));

	return (iService);
}
