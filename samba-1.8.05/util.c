/* 
   Unix SMB/Netbios implementation.
   Version 1.8.
   Copyright (C) Andrew Tridgell 1992,1993,1994
   
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

#include "includes.h"

pstring scope = "";

int DEBUGLEVEL = 1;

BOOL passive = False;

int Protocol = PROTOCOL_COREPLUS;


/* a default finfo structure to ensure all fields are sensible */
file_info def_finfo = {-1,0,0,0,0,0,0,""};

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;
FILE *login=NULL;
FILE *logout=NULL;

/* the client file descriptor */
int Client = 0;

/* info on the client */
struct from_host Client_info=
{"UNKNOWN","0.0.0.0",NULL};

/* the last IP received from */
struct in_addr lastip;

/* the last port received from */
int lastport=0;

/* my IP, the broadcast IP and the Netmask */
struct in_addr myip;
struct in_addr bcast_ip;
struct in_addr Netmask;

int trans_num = 0;

/* this is set to true on a big_endian machine (like a sun sparcstation)
this means that all shorts and ints must be byte swapped before being
put in the buffer */
BOOL NeedSwap=False;

/*
   case handling on filenames 
*/
int case_sensitivity = CASE_LOWER;


/* this structure is used to hold information about the machine that 
   the program is running on */
machine_struct machine_info;

BOOL casesignames = False; /* Placed here to allow client to link without 
			      including loadparms.o. Set by reply_lanman2;
			   */

pstring debugf = DEBUGFILE;

/*******************************************************************
write an debug message on the debugfile. The first arg is the debuglevel.
********************************************************************/
#ifdef __STDC__
int Debug1(char *format_str, ...)
{
#else
int Debug1(va_alist)
va_dcl
{
  char *format_str;
#endif
  va_list ap;
  
  if (!dbf) 
    {
      	dbf = fopen(debugf,"w");
	if (dbf)
	  setbuf(dbf,NULL);
	else
	  return(0);
    }

  
#ifdef __STDC__
  va_start(ap, format_str);
#else
  va_start(ap);
  format_str = va_arg(ap,char *);
#endif

  vfprintf(dbf,format_str,ap);

  fflush(dbf);

  va_end(ap);
  return(0);
}


#ifdef STRING_DEBUG
#define LONG_LEN (sizeof(pstring)/3)
int mystrlen(char *s)
{
  int n=0;
  while (*s++)
    n++;
  if (n > LONG_LEN)
    DEBUG(0,("ERROR: long string\n"));
  return n;
}

char *mystrchr(char *s,char c)
{
if (strlen(s) > LONG_LEN)
  DEBUG(0,("ERROR: long string\n"));
while (*s)
  {
    if (*s == c) break;
    s++;
  }
if (*s == c)
  return s;
else
  return NULL;
}


char *mystrrchr(char *s,char c)
{
char *s2;
if (strlen(s) > LONG_LEN)
  DEBUG(0,("ERROR: long string\n"));

s2 = s + strlen(s);

while (s != s2)
  {
    if (*s2 == c) break;
    s2--;
  }
if (*s2 == c)
  return s2;
else
  return NULL;
}

char *mystrcpy(char *d,char *s)
{
  if (strlen(s) > LONG_LEN)
    DEBUG(0,("ERROR: long string\n"));
  while ((*d++  = *s++));
}

char *mystrncpy(char *d,char *s,int n)
{
  if (strlen(s) > LONG_LEN)
    DEBUG(0,("ERROR: long string\n"));
  while ((*d++  = *s++) && n--);
}

char *mystrcat(char *d,char *s)
{
  if (strlen(s) > LONG_LEN || strlen(d)>LONG_LEN)
    DEBUG(0,("ERROR: long string\n"));
  d+=strlen(d);
  while ((*d++  = *s++));
}

void mymemcpy(char *d,char *s,int n)
{
if (n > LONG_LEN)
  DEBUG(0,("ERROR: long copy\n"));
while (n--)
  *d++ = *s++;
}

void mymemset(char *d,char c,int n)
{
if (n > LONG_LEN)
  DEBUG(0,("ERROR: long set\n"));
while (n--)
  *d++ = c;
}
#endif


int extra_time_offset = 0;

/****************************************************************************
return the difference between local and GMT time
****************************************************************************/
int TimeDiff(void)
{
  static BOOL initialised = False;
  static int timediff = 0;

  if (!initialised)
    {
      /* There are four ways of getting the time difference between GMT and
	 local time. Use the following defines to decide which your system
	 can handle */
#ifdef HAVE_GETTIMEOFDAY
      struct timeval tv;
      struct timezone tz;

      gettimeofday(&tv, &tz);
      timediff = 60 * tz.tz_minuteswest;
#else
      time_t t=time(NULL);

#ifdef HAVE_TIMELOCAL
      timediff = timelocal(gmtime(&t)) - t;
#else
#ifdef HAVE_TIMEZONE
      localtime(&t);
      timediff = timezone;
#else
      timediff = - (localtime(&t)->tm_gmtoff);
#endif
#endif
#endif
      DEBUG(3,("timediff=%d\n",timediff));
      initialised = True;
    }

return(timediff + (extra_time_offset*60));
}


/****************************************************************************
try to optimise the timelocal call, it can be quite expenive on some machines
****************************************************************************/
time_t TimeLocal(struct tm *tm,int timemul)
{
#ifdef sun386
  return(timelocal(tm) + timemul * TimeDiff());
#else
  return(mktime(tm) + timemul * TimeDiff());
#endif
}

/****************************************************************************
try to optimise the localtime call, it can be quite expenive on some machines
timemul is normally LOCAL_TO_GMT, GMT_TO_LOCAL or 0
****************************************************************************/
struct tm *LocalTime(time_t *t,int timemul)
{
  time_t t2 = *t;

  t2 += timemul * TimeDiff();

  return(gmtime(&t2));
}


/*******************************************************************
safely copies memory, ensuring no overlap problems.
********************************************************************/
void safe_memcpy(void *dest,void *src,int size)
{
  /* do the copy in chunks of size difference. This relies on the 
     capability of pointer comparison. */

  int difference = ABS((char *)dest - (char *)src);
 
  if (difference == 0 || size <= 0)
    return;
 
  if (difference >= size) /* no overlap problem */
    {
      memcpy(dest,src,size);
      return;
    }

  if (dest > src) /* copy the last chunks first */
    {
      char *this_dest=dest;
      char *this_src=src;
      this_dest += size - difference;
      this_src += size - difference;
      while (size>0)
	{
	  memcpy(this_dest,this_src,difference);
	  this_dest -= difference;
	  this_src -= difference;
	  size -= difference;
	}
    }
  else
    { /* copy from the front */
      char *this_dest=dest;
      char *this_src=src;
      while (size>0)
	{
	  memcpy(this_dest,this_src,difference);
	  this_dest += difference;
	  this_src += difference;
	  size -= difference;
	}
    }
}

/****************************************************************************
prompte a dptr (to make it recently used)
****************************************************************************/
void array_promote(char *array,int elsize,int element)
{
  char *p;
  if (element == 0)
    return;

  p = (char *)malloc(elsize);

  if (!p)
    {
      DEBUG(5,("Ahh! Can't malloc\n"));
      return;
    }
  memcpy(p,array + element * elsize, elsize);
  safe_memcpy(array + elsize,array,elsize*element);
  memcpy(array,p,elsize);
  free(p);
}
	
/****************************************************************************
  close the socket communication
****************************************************************************/
void close_sockets(void )
{
  extern int Client;
  close(Client);
  Client = 0;
}

/****************************************************************************
  return the date and time as a string
****************************************************************************/
char *timestring(void )
{
  static char TimeBuf[100];
  time_t t;
  t = time(NULL);
#ifdef NO_STRFTIME
  strcpy(TimeBuf, asctime(LocalTime(&t,GMT_TO_LOCAL)));
#else
#ifdef CLIX
  strftime(TimeBuf,100,"%m/%d/%y %I:%M:%S %p",LocalTime(&t,GMT_TO_LOCAL));
#else
#ifdef AMPM
  strftime(TimeBuf,100,"%D %r",LocalTime(&t,GMT_TO_LOCAL));
#else
  strftime(TimeBuf,100,"%D %T",LocalTime(&t,GMT_TO_LOCAL));
#endif
#endif /* CLIX */
#endif
  return(TimeBuf);
}

/****************************************************************************
determine whether we are in the specified group
****************************************************************************/
BOOL in_group(gid_t group, int current_gid, int ngroups, int *groups)
{
  int i;

  if (group == current_gid) return(True);

  for (i=0;i<ngroups;i++)
    if (group == groups[i])
      return(True);

  return(False);
}

/****************************************************************************
line strncpy but always null terminates. Make sure there is room!
****************************************************************************/
char *StrnCpy(char *dest,char *src,int n)
{
  char *d = dest;
  while (n-- && (*d++ = *src++)) ;
  *d = 0;
  return(dest);
}


/****************************************************************************
interpret the weird netbios "name"
****************************************************************************/
void name_interpret(char *in,char *out)
{

int len = (*in++) / 2;
while (len--)
  {
    *out = ((in[0]-'A')<<4) + (in[1]-'A');
    in += 2;
    out++;
  }
*out = 0;
/* Handle any scope names */
while(*in) 
  {
  *out++ = '.'; /* Scope names are separated by periods */
  len = *(unsigned char *)in++;
  StrnCpy(out, in, len);
  out += len;
  *out=0;
  in += len;
  }
}

/****************************************************************************
mangle a name into netbios format
****************************************************************************/
int name_mangle(char *In,char *Out)
{
  char *in = (char *)In;
  char *out = (char *)Out;
  char *p, *label;
  int len = 2*strlen((char *)in);
  int pad = 0;

  if (len/2 < 16)
    pad = 16 - (len/2);

  *out++ = 2*(strlen((char *)in) + pad);
  while (*in)
    {
      out[0] = (in[0]>>4) + 'A';
      out[1] = (in[0] & 0xF) + 'A';
      in++;
      out+=2;
    }
  
  while (pad--)
    {
      out[0] = 'C';
      out[1] = 'A';
      out+=2;
    }
  
  label = scope;
  while (*label)
    {
      p = strchr(label, '.');
      if (p == 0)
	p = label + strlen(label);
      *out++ = p - label;
      memcpy(out, label, p - label);
      out += p - label;
      label += p - label + (*p == '.');
    }
  *out = 0;
  return(name_len(Out));
}

/*******************************************************************
  byte swap an object - the byte order of the object is reversed
********************************************************************/
void *object_byte_swap(void *obj,int size)
{
  int i;
  char c;
  char *p1 = (char *)obj;
  char *p2 = p1 + size - 1;
  
  size /= 2;
  
  for (i=0;i<size;i++)
    {
      c = *p1;
      *p1 = *p2;
      *p2 = c;
      p1++;
      p2--;
    }
  return(obj);
}

/****************************************************************************
  byte swap a uint16
****************************************************************************/
uint16 uint16_byte_swap(uint16 x)
{
  uint16 res;
  res = x;
  SWP(&res,sizeof(res));
  return(res);
}

/****************************************************************************
  byte swap a uint32
****************************************************************************/
uint32 uint32_byte_swap(uint32 x)
{
  uint32 res;
  res = x;
  SWP(&res,sizeof(res));
  return(res);
}

/*******************************************************************
  turn the last component of a name into a case independent form.
  (Used for lanman2 case independent filename support).
********************************************************************/
void find_case_independent_name(char *name)
{
  void *dirptr;
  struct DIRECT *dptr;
  pstring dir_to_search = "";
  char *search_name;
  char *p;

  /* Ensure name doesn't end in '/' */
  while(*(p = &name[strlen(name)-1]) == '/')
    *p = '\0';

  if((p = strrchr(name,'/'))==NULL)
     {
       strcpy(dir_to_search,".");
       search_name = name;
     }
  else
     {
       StrnCpy(dir_to_search,name,p-name);
       search_name = p+1;
     }

  DEBUG(3,("make_case_independent name - searching for %s in %s\n",name,dir_to_search));

  dirptr = (void *)opendir(dir_to_search);
  
  if (!dirptr)
    return;

  dptr = readdir(dirptr);
  while (dptr)
    {
      if (strequal(dptr->d_name,search_name))
	{
	  DEBUG(3,("find_case_independent_name - replacing %s with %s\n",search_name,dptr->d_name));
	  memcpy(search_name,dptr->d_name,strlen(dptr->d_name));
	  closedir(dirptr);
	  return;
	}
      dptr = readdir(dirptr);
    }
  
  /* didn't find it */
  closedir(dirptr);
  return;
}

/*******************************************************************
  check if a file exists
********************************************************************/
BOOL file_exist(char *fname)
{
  struct stat st;
  
  if((Protocol >= PROTOCOL_LANMAN2) && casesignames)
    { /* We could use unix_convert_lanman2 here but find_case...
	 is a big optimization if this has already been done 
	 (ie. we only need to seach for the last component) */
      find_case_independent_name(fname);
    }

  if (stat(fname,&st) != 0) 
    return(False);

#if (defined(NEXT2) || defined(NEXT3_0))
  if ((S_IFREG & st.st_mode)>0)
    return(True);
  else
    return(False);
#else
  return(S_ISREG(st.st_mode));
#endif
}

/*******************************************************************
  check if a directory exists
********************************************************************/
BOOL directory_exist(char *dname)
{
  struct stat st;

  if((Protocol >= PROTOCOL_LANMAN2) && casesignames)
    { /* We could use unix_convert_lanman2 here but find_case...
	 is a big optimization if this has already been done 
	 (ie. we only need to seach for the last component) */
      find_case_independent_name(dname);
    }

  if (stat(dname,&st) != 0) 
    return(False);

#if (defined(NEXT2) || defined(NEXT3_0))
  if ((S_IFDIR & st.st_mode)>0)
    return(True);
  else
    return(False);
#else
  return(S_ISDIR(st.st_mode));
#endif
}

/*******************************************************************
returns the size in bytes of the named file
********************************************************************/
uint32 file_size(char *file_name)
{
  struct stat buf;
  buf.st_size = 0;
  stat(file_name,&buf);
  return(buf.st_size);
}

/*******************************************************************
  create a 16 bit dos packed date
********************************************************************/
uint16 make_dos_date1(time_t unixdate)
{
  uint16 ret;
  unsigned char *p;
  struct tm *t;

  t = LocalTime(&unixdate,GMT_TO_LOCAL);
  p = (unsigned char *)&ret;
  p[0] = t->tm_mday | (((t->tm_mon+1) & 0x7) << 5);
  p[1] = (((unsigned)(t->tm_mon+1)) >> 3) | ((t->tm_year-80) << 1);
  return(ret);
}

/*******************************************************************
  create a 16 bit dos packed time
********************************************************************/
uint16 make_dos_time1(time_t unixdate)
{
  uint16 ret;
  unsigned char *p = (unsigned char *)&ret;
  struct tm *t = LocalTime(&unixdate,GMT_TO_LOCAL);

  p[0] = (t->tm_sec/2) | ((t->tm_min & 0x7) << 5);
  p[1] = ((((unsigned)t->tm_min >> 3)&0x7) | (((unsigned)t->tm_hour) << 3));

  return(ret);
}

/*******************************************************************
  create a 32 bit dos packed date/time from some parameters
********************************************************************/
uint32 make_dos_date(time_t unixdate)
{
  uint32 ret;
  uint16 *v = (uint16 *)&ret;

  *v++ = make_dos_time1(unixdate);
  *v = make_dos_date1(unixdate);

  return(ret);
}

/*******************************************************************
  create a 32 bit dos packed date/time from some parameters
********************************************************************/
uint32 make_dos_date2(time_t unixdate)
{
  uint32 ret;
  uint16 *v = (uint16 *)&ret;

  *v++ = make_dos_date1(unixdate);
  *v = make_dos_time1(unixdate);

  return(ret);
}

/*******************************************************************
put a dos date into a buffer (time/date format)
********************************************************************/
void put_dos_date(char *buf,int offset,time_t unixdate)
{
  uint32 x = make_dos_date(unixdate);
  memcpy(buf+offset,(char *)&x,sizeof(x));
}

/*******************************************************************
put a dos date into a buffer (date/time format)
********************************************************************/
void put_dos_date2(char *buf,int offset,time_t unixdate)
{
  uint32 x = make_dos_date2(unixdate);
  memcpy(buf+offset,(char *)&x,sizeof(x));
}


/*******************************************************************
  interpret a 32 bit dos packed date/time to some parameters
********************************************************************/
void interpret_dos_date(uint32 date,int *year,int *month,int *day,int *hour,int *minute,int *second)
{
  unsigned char *p = (unsigned char *)&date;

  *second = 2*(p[0] & 0x1F);
  *minute = (p[0]>>5) + ((p[1]&0x7)<<3);
  *hour = (p[1]>>3);
  *day = p[2]&0x1F;
  *month = (p[2]>>5) + ((p[3]&0x1)<<3) - 1;
  *year = (p[3]>>1) + 80;
}

/*******************************************************************
  create a unix date from a dos date
********************************************************************/
time_t make_unix_date(void *date_ptr)
{
  uint32 dos_date;
  struct tm t;

  memcpy(&dos_date,date_ptr,4);

  if (dos_date == 0) return(0);
  
  interpret_dos_date(dos_date,&t.tm_year,&t.tm_mon,
		     &t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec);
  t.tm_wday = 1;
  t.tm_yday = 1;
  t.tm_isdst = 0;
/*  DEBUG(4,("year=%d month=%d day=%d hr=%d min=%d sec=%d\n",t.tm_year,t.tm_mon,
	 t.tm_mday,t.tm_hour,t.tm_sec)); */
  return (TimeLocal(&t,GMT_TO_LOCAL));
}

/*******************************************************************
  create a unix date from a dos date
********************************************************************/
time_t make_unix_date2(void *date_ptr)
{
  uint32 dos_date;
  struct tm t;
  unsigned char *p = (unsigned char *)&dos_date;
  unsigned char c;

  memcpy(&dos_date,date_ptr,4);

  if (dos_date == 0) return(0); 

  c = p[0];
  p[0] = p[2];
  p[2] = c;
  c = p[1];
  p[1] = p[3];
  p[3] = c;

  
  interpret_dos_date(dos_date,&t.tm_year,&t.tm_mon,
		     &t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec);
  t.tm_wday = 1;
  t.tm_yday = 1;
  t.tm_isdst = 0;
  DEBUG(4,("year=%d month=%d day=%d hr=%d min=%d sec=%d\n",t.tm_year,t.tm_mon,
	 t.tm_mday,t.tm_hour,t.tm_sec));
  return (TimeLocal(&t,GMT_TO_LOCAL));
}


/*******************************************************************
return a string representing an attribute for a file
********************************************************************/
char *attrib_string(int mode)
{
  static char attrstr[10];

  attrstr[0] = 0;

  if (mode & aVOLID) strcat(attrstr,"V");
  if (mode & aDIR) strcat(attrstr,"D");
  if (mode & aARCH) strcat(attrstr,"A");
  if (mode & aHIDDEN) strcat(attrstr,"H");
  if (mode & aSYSTEM) strcat(attrstr,"S");
  if (mode & aRONLY) strcat(attrstr,"R");	  

  return(attrstr);
}


/*******************************************************************
  true if the machine is big endian
********************************************************************/
BOOL big_endian(void )
{
  int x = 2;
  char *s;
  s = (char *)&x;
  return(s[0] == 0);
}

/*******************************************************************
  compare 2 strings 
********************************************************************/
BOOL strequal(char *s1,char *s2)
{
  if (!s1 || !s2) return(False);
  
  return(strcasecmp(s1,s2)==0);
}


/*******************************************************************
  convert a string to lower case
********************************************************************/
void strlower(char *s)
{
  while (*s)
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (isupper(*s))
		*s = tolower(*s);
	    s++;
	}
#else
      if (isupper(*s))
	  *s = tolower(*s);
      s++;
#endif /* KANJI */
    }
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
  while (*s)
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (islower(*s))
		*s = toupper(*s);
	    s++;
	}
#else
      if (islower(*s))
	*s = toupper(*s);
      s++;
#endif
    }
}

/*******************************************************************
  convert a string to "normal" form
********************************************************************/
void strnorm(char *s)
{
  if (case_sensitivity == CASE_UPPER)
    strupper(s);
  else
    strlower(s);
}


/****************************************************************************
  string replace
****************************************************************************/
void string_replace(char *s,char old,char new)
{
  while (*s)
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (old == *s)
		*s = new;
	    s++;
	}
#else
      if (old == *s)
	*s = new;
      s++;
#endif /* KANJI */
    }
}

/****************************************************************************
  make a file into unix format
****************************************************************************/
void unix_format(char *fname)
{
  pstring namecopy="";
  string_replace(fname,'\\','/');

  if (*fname == '/')
    {
      strcpy(namecopy,fname);
      strcpy(fname,".");
      strcat(fname,namecopy);
    }  
}

/****************************************************************************
  make a file into dos format
****************************************************************************/
void dos_format(char *fname)
{
  string_replace(fname,'/','\\');
}


/****************************************************************************
  set a value at buf[pos] to integer val
****************************************************************************/
void sival(char *buf,int pos,uint32 val)
{
  SWP(&val,sizeof(val));
  memcpy(buf + pos,(char *)&val,sizeof(val));
}

/****************************************************************************
  set a value at buf[pos] to int16 val
****************************************************************************/
void ssval(char *buf,int pos,uint16 val)
{
  SWP(&val,sizeof(val));
  memcpy(buf + pos,(char *)&val,sizeof(int16));
}

/****************************************************************************
  get a 32 bit integer value
****************************************************************************/
uint32 ival(char *buf,int pos)
{
  uint32 val;
  memcpy((char *)&val,buf + pos,sizeof(int));
  SWP(&val,sizeof(val));
  return(val);
}


/****************************************************************************
  get a int16 value
****************************************************************************/
uint16 sval(char *buf,int pos)
{
  uint16 val;
  memcpy((char *)&val,buf + pos,sizeof(uint16));
  SWP(&val,sizeof(val));
  return(val);
}


/****************************************************************************
  set a value at buf[pos] to signed integer val
****************************************************************************/
void sival_s(char *buf,int pos,int32 val)
{
  SWP(&val,sizeof(val));
  memcpy(buf + pos,(char *)&val,sizeof(val));
}

/****************************************************************************
  set a value at buf[pos] to signed int16 val
****************************************************************************/
void ssval_s(char *buf,int pos,int16 val)
{
  SWP(&val,sizeof(val));
  memcpy(buf + pos,(char *)&val,sizeof(int16));
}

/****************************************************************************
  get a 32 bit integer value
****************************************************************************/
int32 ival_s(char *buf,int pos)
{
  int32 val;
  memcpy((char *)&val,buf + pos,sizeof(int32));
  SWP(&val,sizeof(val));
  return(val);
}


/****************************************************************************
  get a int16 value
****************************************************************************/
int16 sval_s(char *buf,int pos)
{
  int16 val;
  memcpy((char *)&val,buf + pos,sizeof(int16));
  SWP(&val,sizeof(val));
  return(val);
}


/*******************************************************************
  show a smb message structure
********************************************************************/
void show_msg(char *buf)
{
  int i;
  DEBUG(3,("size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%d\nsmb_flg=%d\nsmb_flg2=%d\n",
	  smb_len(buf),
	  (int)CVAL(buf,smb_com),
	  (int)CVAL(buf,smb_rcls),
	  (int)CVAL(buf,smb_reh),
	  (int)SVAL(buf,smb_err),
	  (int)CVAL(buf,smb_flg),
	  (int)CVAL(buf,smb_flg2)));
  DEBUG(3,("smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
	  (int)SVAL(buf,smb_tid),
	  (int)SVAL(buf,smb_pid),
	  (int)SVAL(buf,smb_uid),
	  (int)SVAL(buf,smb_mid),
	  (int)CVAL(buf,smb_wct)));
  for (i=0;i<(int)CVAL(buf,smb_wct);i++)
    DEBUG(3,("smb_vwv[%d]=%d (0x%X)\n",i,
	  SVAL(buf,smb_vwv+2*i),SVAL(buf,smb_vwv+2*i)));
  DEBUG(3,("smb_bcc=%d\n",(int)SVAL(buf,smb_vwv+2*(CVAL(buf,smb_wct)))));
}

/*******************************************************************
  return the length of an smb packet
********************************************************************/
int smb_len(char *buf)
{
  int msg_flags = CVAL(buf,1);
  uint16 len = SVAL(buf,2);
  BSWP(&len,2);

  if (msg_flags & 1)
    len += 1<<16;

  return len;
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void smb_setlen(char *buf,int len)
{
  SSVAL(buf,2,len);
  BSWP(buf+2,2);

/*
  CVAL(buf,3) = len & 0xFF;
  CVAL(buf,2) = (len >> 8) & 0xFF;
*/
  CVAL(buf,4) = 0xFF;
  CVAL(buf,5) = 'S';
  CVAL(buf,6) = 'M';
  CVAL(buf,7) = 'B';


  if (len >= (1 << 16))
    CVAL(buf,1) |= 1;
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int set_message(char *buf,int num_words,int num_bytes,BOOL zero)
{
  if (zero)
    memset(buf + smb_size,0,num_words*2 + num_bytes);
  CVAL(buf,smb_wct) = num_words;
  SSVAL(buf,smb_vwv + num_words*sizeof(WORD),num_bytes);  
  smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
  return (smb_size + num_words*2 + num_bytes);
}

/*******************************************************************
return the number of smb words
********************************************************************/
int smb_numwords(char *buf)
{
  return (CVAL(buf,smb_wct));
}

/*******************************************************************
return the size of the smb_buf region of a message
********************************************************************/
int smb_buflen(char *buf)
{
  return(SVAL(buf,smb_vwv0 + smb_numwords(buf)*2));
}

/*******************************************************************
trim the specified elements off the front and back of a string
********************************************************************/
void trim_string(char *s,char *front,char *back)
{
  while (front && *front && strncmp(s,front,strlen(front)) == 0)
    {
      char *p = s;
      while (1)
	{
	  if (!(*p = p[strlen(front)]))
	    break;
	  p++;
	}
    }
  
  while (back && *back && (strncmp(s+strlen(s)-strlen(back),back,strlen(back))==0))
    s[strlen(s)-strlen(back)] = 0;
}


/*******************************************************************
reduce a file name, removing .. elements.
********************************************************************/
void dos_clean_name(char *s)
{
  char *p=NULL;

  DEBUG(3,("dos_clean_name [%s]\n",s));

  /* remove any double slashes */
  string_sub(s, "\\\\", "\\");

  while ((p = strstr(s,"\\..")) != NULL)
    {
      pstring s1;

      *p = 0;
      strcpy(s1,p+3);

      if ((p=strrchr(s,'\\')) != NULL)
	*p = 0;
      else
	*s = 0;
      strcat(s,s1);
    }  

  string_sub(s, "\\.\\", "\\");
}

/*******************************************************************
reduce a file name, removing .. elements. 
********************************************************************/
void unix_clean_name(char *s)
{
  char *p=NULL;

  DEBUG(3,("unix_clean_name [%s]\n",s));

  /* remove any double slashes */
  string_sub(s, "//","/");

  while ((p = strstr(s,"/..")) != NULL)
    {
      pstring s1;

      *p = 0;
      strcpy(s1,p+3);

      if ((p=strrchr(s,'/')) != NULL)
	*p = 0;
      else
	*s = 0;
      strcat(s,s1);
    }  
}


/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
int smb_buf_ofs(char *buf)
{
  return (smb_size + CVAL(buf,smb_wct)*2);
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
char *smb_buf(char *buf)
{
  return (buf + smb_buf_ofs(buf));
}


/*******************************************************************
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf,int n)
{
  while (n--)
    buf += strlen(buf) + 1;
  return(buf);
}


/*******************************************************************
a wrapper for the normal chdir() function
********************************************************************/
int ChDir(char *path)
{
  DEBUG(3,("chdir to %s\n",path));
  return(chdir(path));
}


/* Linked list structures for a caching GetWd function. */
#define MAX_GETWDCACHE (100)
#define MAGIC (0xABCD)
#define GETWD_PARANOID 1

struct ino_list
{
  int magic;
  struct ino_list *next;
  struct ino_list *back;
  ino_t inode;
  dev_t dev;
  int first;
  int count;
  int weight;
  char *text;
};

static int total_count = 0;

static struct ino_list ino_head =
{ MAGIC, NULL, NULL, (ino_t)0, (dev_t)0, 0, 0, 1 << 8, NULL };

/*******************************************************************
  return the absolute current directory path. A dumb version.
********************************************************************/
char *Dumb_GetWd(char *s)
{
#ifdef USE_GETCWD
    return ((char *)getcwd(s,sizeof(pstring)));
#else
    return ((char *)getwd(s));
#endif
}

BOOL use_getwd_cache = False;

/*******************************************************************
  return the absolute current directory path
********************************************************************/
char *GetWd(char *s)
{
  pstring wd="";
  struct stat st, st2;
  int i;
  struct ino_list *ino_p, *ino_tmp;

  if (!use_getwd_cache)
    return(Dumb_GetWd(s));

#define DISABLE_CACHE {DEBUG(0,("PLEASE REPORT THIS ERROR!\n"));use_getwd_cache=False;return(Dumb_GetWd(s));}

  /*  Get the inode of the current directory, if this doesn't work we're
      in trouble :-) */

  if (stat(".",&st) == -1) 
    {
      DEBUG(0,("Very strange, couldn't stat \".\"\n"));
      return(NULL);
    }

  /*  First a bit of housekeeping, we want to avoid 'total_count' overflowing
      and going negative. This would cause havoc with the weighting calculations
      used to keep the most commonly used directories near the top of the list.
      As it is only used in a relative manner, if it gets too large divide it,
      and the values it's used with, by two. */

  if (total_count >= 10000)
    {
      total_count /= 2;
      for (ino_p = ino_head.next; ino_p; ino_p = ino_p->next)
	{
          ino_p->first /= 2;
          ino_p->count /= 2;
	}
    }
  
  /*  Check whether I have this inode already. This is done with a simple
      linear search, hash tables anybody?
      The code works by getting the inode (and device number) of the 
      current directory and looking it up in it's list. First time through
      it will not find a match so fall back on getcwd/getwd but add the
      information to the list. Subsequent times through that match will
      be found and the directory name returned - although only after the
      sanity check of getting the inode and device of that directory and
      seeing if they agree with the stat of the current directory.
   
      Q: will this work with NFS/RFS/something-else-FS mounted filesystems?
      
      It's a linear search but the code tries to keep it sensible by moving
      the most commonly used entries at the head of the list. */

  i = 0;
  for (ino_p = ino_head.next; ino_p; ino_p = ino_p->next)
    {
      
#if GETWD_PARANOID
      if (ino_p->magic != MAGIC)
	{
	  DEBUG(0,("Hmm, funny magic number\n"));
	  DISABLE_CACHE;
	}
      if (ino_p->back)
	{
          if (ino_p->back->next != ino_p)
	    {
	      DEBUG(0,("Hmm, back/next links inconsistant\n"));
	      DISABLE_CACHE;
	    }
          if (ino_p->back->back && ino_p->back->back->next->next != ino_p)
	    {
	      DEBUG(0,("Hmm, back/back/next/next links inconsistant\n"));
	      DISABLE_CACHE;
	    }
	}
#endif

      /*  Calculate a weight for the entry and gradually sift less used ones
	  down the list by swapping. Note that the swapping disconnects the
	  backpointers so don't expect to run back up the list. We keep a
	  fair amount of granularity in the 'weight' value to avoid excessive
	  swapping of elements.. it is, after all, only a guide.. */
      
      ino_p->weight = (ino_p->count << 8) / (total_count - ino_p->first);
      
#if GETWD_PARANOID
      if (ino_p->weight > (1 << 8))
	{
	  DEBUG(0,("Weight too high for %s, %d\n",ino_p->text, ino_p->weight));
	  DISABLE_CACHE;
	}
#endif

      if (ino_p->back && ino_p->weight > ino_p->back->weight)
	{
          DEBUG(4,("swap %s (%d) and %s (%d)\n",
		   ino_p->text,ino_p->weight,ino_p->back->text,
		   ino_p->back->weight));
          ino_tmp = ino_p->back;
	  
#if GETWD_PARANOID
          if (ino_tmp->back == NULL)
	    {
	      DEBUG(0,("Oh dear, Backpointer NULL\n"));
	      DISABLE_CACHE;
	    }
          else if (ino_tmp->back->magic != MAGIC)
	    {
	      DEBUG(0,("Hmm, funny magic number looking back\n"));
	      DISABLE_CACHE;
	    }
#endif

          ino_tmp->back->next = ino_p;
          ino_tmp->next = ino_p->next;
          ino_p->next = ino_tmp;
          ino_p->back = NULL;
	}

      /*  If we have found an entry with a matching inode and dev number
	  then find the inode number for the directory in the cached string.
	  If this agrees with that returned by the stat for the current
	  directory then all is o.k. (but make sure it is a directory all
	  the same...) */
      
      if (st.st_ino == ino_p->inode &&
	  st.st_dev == ino_p->dev)
	{
          if (stat(ino_p->text,&st2) == 0)
	    {
	      if (st.st_ino == st2.st_ino &&
		  st.st_dev == st2.st_dev &&
		  (st2.st_mode & S_IFMT) == S_IFDIR)
                {
		  total_count++;
		  ino_p->count++;
		  DEBUG(3,("Found cached GetWd %s [%d, %d]\n",
			   ino_p->text, i, ino_p->weight));
		  strcpy (s, ino_p->text);
		  return (s);
                }

	      /*  If the inode is different then something's changed, scrub 
		  the entry and start from scratch. */

	      else
                {
		  DEBUG(3,("cached string %s bad\n",ino_p->text));
		  ino_tmp = ino_p->back;
		  ino_tmp->next = ino_p->next;
		  free (ino_p->text);
		  free (ino_p);
		  ino_p = ino_tmp;
                }
	    }
	}
      
      /*  Set up a temporary backpointer, this will not be maintained when
	  elements are swapped so should not be relied on long term. It helps
	  however for immediate views back up the list. */

      i++;
      if (ino_p->next)
	ino_p->next->back = ino_p;
      else
	break;
      
      /*  Skip out of the loop if at the end of the list leaving ino_p 
	  referring to the last element. */
      
    }

  /*  We don't have the information to hand so rely on traditional methods.
      The very slow getcwd, which spawns a process on some systems, or the
      not quite so bad getwd. */

#ifdef USE_GETCWD
  if (getcwd(wd,sizeof(wd)) == NULL)
    {
      DEBUG(0,("Getcwd failed, errno %d\n",errno));
      return (NULL);
    }
#else
  if (!getwd(wd))
    {
      DEBUG(0,("Getwd failed, errno %d\n",errno));
      return (NULL);
    }
#endif

  DEBUG(3,("GetWd %s, inode %d, dev %x\n",wd,(int)st.st_ino,(int)st.st_dev));

  /*  We'll prepend the new entry, prepending it means that it is at the head
      of the list for the next request - working on the principle that these
      lookups seldom come alone. */
  
  if (i > MAX_GETWDCACHE && ino_p)
    {
      free (ino_p->text);
      ino_p->back->next = NULL;
    }
  else if ((ino_p = (struct ino_list *)malloc (sizeof (struct ino_list))) == NULL)
    {
      DEBUG(0,("Oh dear, malloc failed extending list of directories\n"));
      strcpy (s, wd);
      return (s);
    }
  ino_p->magic = MAGIC;
  ino_p->next = ino_head.next;
  ino_p->back = &ino_head;
  ino_head.next = ino_p;
  
  /*  copy the inode number and directory name into the entry. */
  
  ino_p->inode = st.st_ino;
  ino_p->dev = st.st_dev;
  ino_p->first = total_count++;
  ino_p->count = 1;
  ino_p->weight = 0;
  if ((ino_p->text = (char *)malloc (strlen(wd)+1)) == NULL)
    {
      DEBUG(0,("Oh dear, malloc failed extending list of directories\n"));
      ino_head.next = ino_p->next;
      free (ino_p);
      strcpy (s, wd);
      return (s);
    }
  strcpy (ino_p->text,wd);
  
  strcpy (s, wd);
  return (s);
}


/*******************************************************************
reduce a file name, removing .. elements and checking that 
it is below dir in the heirachy. This uses GwtWd() and so must be run
on the system that has the referenced file system.

widelinks are allowed if widelinks is true
********************************************************************/
BOOL reduce_name(char *s,char *dir,BOOL widelinks)
{
#ifndef REDUCE_PATHS
  return True;
#else
  pstring dir2="";
  pstring wd="";
  pstring basename="";
  pstring newname="";
  char *p=NULL;
  BOOL relative = (*s != '/');

  if (widelinks)
    {
      unix_clean_name(s);
      /* can't have a leading .. */
      if (strncmp(s,"..",2) == 0)
	{
	  DEBUG(3,("Illegal file name? (%s)\n",s));
	  return(False);
	}
      return(True);
    }
  
  DEBUG(3,("reduce_name [%s] [%s]\n",s,dir));

  /* remove any double slashes */
  string_sub(s,"//","/");

  if (!GetWd(wd))
    {
      DEBUG(0,("couldn't getwd for %s %s\n",s,dir));
      return(False);
    }

  if (ChDir(dir) != 0)
    {
      DEBUG(0,("couldn't chdir to %s\n",dir));
      return(False);
    }

  if (!GetWd(dir2))
    {
      DEBUG(0,("couldn't getwd for %s\n",dir));
      ChDir(wd);
      return(False);
    }

  strcpy(basename,s);
  p = strrchr(basename,'/');

    if (p && (p != basename))
      {
	*p = 0;
	if (strcmp(p+1,".")==0)
	  p[1]=0;
	if (strcmp(p+1,"..")==0)
	  *p = '/';
      }

  if (ChDir(basename) != 0)
    {
      ChDir(wd);
      DEBUG(3,("couldn't chdir for %s %s basename=%s\n",s,dir,basename));
      return(False);
    }

  if (!GetWd(newname))
    {
      ChDir(wd);
      DEBUG(2,("couldn't get wd for %s %s\n",s,dir2));
      return(False);
    }

  if (p && (p != basename))
    {
      strcat(newname,"/");
      strcat(newname,p+1);
    }

  {
    int l = strlen(dir2);    
    if (dir2[l-1] == '/')
      l--;

    if (strncmp(newname,dir2,l) != 0)
      {
	ChDir(wd);
	DEBUG(2,("Bad access attempt? s=%s dir=%s newname=%s l=%d\n",s,dir2,newname,l));
	return(False);
      }

    if (relative)
      {
	if (newname[l] == '/')
	  strcpy(s,newname + l + 1);
	else
	  strcpy(s,newname+l);
      }
    else
      strcpy(s,newname);
  }

  ChDir(wd);

  if (strlen(s) == 0)
    strcpy(s,"./");

  DEBUG(3,("reduced to %s\n",s));
  return(True);
#endif
}

/****************************************************************************
expand some *s 
****************************************************************************/
void expand_one(char *Mask,int len)
{
  char *p1;
  while ((p1 = strchr(Mask,'*')) != NULL)
    {
      int lfill = (len+1) - strlen(Mask);
      int l1= (p1 - Mask);
      pstring tmp="";
      strcpy(tmp,Mask);  
      memset(tmp+l1,'?',lfill);
      strcpy(tmp + l1 + lfill,Mask + l1 + 1);	
      strcpy(Mask,tmp);      
    }
}

/****************************************************************************
expand a wildcard expression, replacing *s with ?s
****************************************************************************/
void expand_mask(char *Mask,BOOL doext)
{
  pstring mbeg="",mext="";
  pstring dirpart="";
  pstring filepart="";
  BOOL hasdot = False;
  char *p1;
  BOOL absolute = (*Mask == '\\');

  /* parse the directory and filename */
  if (strchr(Mask,'\\'))
    dirname_dos(Mask,dirpart);

  filename_dos(Mask,filepart);

  strcpy(mbeg,filepart);
  if ((p1 = strchr(mbeg,'.')) != NULL)
    {
      hasdot = True;
      *p1 = 0;
      p1++;
      strcpy(mext,p1);
    }
  else
    {
      strcpy(mext,"");
      if (strlen(mbeg) > 8)
	{
	  strcpy(mext,mbeg + 8);
	  mbeg[8] = 0;
	}
    }

  if (*mbeg == 0)
    strcpy(mbeg,"????????");
  if ((*mext == 0) && doext && !hasdot)
    strcpy(mext,"???");

  /* expand *'s */
  expand_one(mbeg,8);
  if (*mext)
    expand_one(mext,3);

  strcpy(Mask,dirpart);
  if (*dirpart || absolute) strcat(Mask,"\\");
  strcat(Mask,mbeg);
  strcat(Mask,".");
  strcat(Mask,mext);

  DEBUG(6,("Mask expanded to [%s]\n",Mask));
}  


/****************************************************************************
does a string have any uppercase chars in it?
****************************************************************************/
BOOL strhasupper(char *s)
{
  while (*s) 
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (isupper(*s)) return(True);
	    s++;
	}
#else 
      if (isupper(*s)) return(True);
      s++;
#endif /* KANJI */
    }
  return(False);
}

/****************************************************************************
does a string have any lowercase chars in it?
****************************************************************************/
BOOL strhaslower(char *s)
{
  while (*s) 
    {
#ifdef KANJI
	if (is_shift_jis (*s)) {
	    s += 2;
	} else if (is_kana (*s)) {
	    s++;
	} else {
	    if (islower(*s)) return(True);
	    s++;
	}
#else 
      if (islower(*s)) return(True);
      s++;
#endif /* KANJI */
    }
  return(False);
}

/****************************************************************************
find the number of chars in a string
****************************************************************************/
int count_chars(char *s,char c)
{
  int count=0;
  while (*s) 
    {
      if (*s == c)
	count++;
      s++;
    }
  return(count);
}


/****************************************************************************
Search for a name in a directory in a case independent way.
Returns 0 if found and places new name in matchname, 1 and name
placed in matchname otherwise.
****************************************************************************/
int search_lanman2(char *dir_to_search, char *name, char *matchname, int flags)
{
  void *dirptr;
  struct DIRECT *dptr;

  DEBUG(3,("search_lanman2 - searching for %s in %s\n",name,dir_to_search));

  dirptr = (void *)opendir(dir_to_search);

  if (!dirptr)
    return 1;

  dptr = readdir(dirptr);
  while (dptr)
    {
      if (strequal(dptr->d_name,name))
	{
	  pstring fullpath = "";
	  struct stat st;

	  /* Check name matches with required flags */
	  strcpy(fullpath,dir_to_search);
	  if(fullpath[strlen(fullpath)-1] != '/')
	    strcat(fullpath,"/");
	  strcat(fullpath,dptr->d_name);
	  stat(fullpath, &st);
	  if(st.st_mode & flags)
	    {
	      strcpy(matchname, dptr->d_name);
	      DEBUG(3,("search_lanman2 - replacing %s with %s\n",name,matchname));
	      closedir(dirptr);
	      return 0;
	    }
	}
      dptr = readdir(dirptr);
    }
  
  /* didn't find it */
  strcpy(matchname, name);
  closedir(dirptr);
  return 1;
}

/****************************************************************************
convert a lanman2 name to a unix name - possibly checking case
****************************************************************************/
void unix_convert_lanman2(char *s,char *home,BOOL case_is_sig)
{
  char *p, *tnp;
  pstring tmpname = "";
  pstring name = "";
  pstring dir_to_search = "";
  pstring matching_name = "";

  unix_format(s);

  if(case_is_sig)
    return; /* We can use unix case dependent names */

  DEBUG(5,("Converting name %s to lanman2 name (home=%s)\n",s,home));

  strcpy(tmpname,s);
  unix_clean_name(tmpname);

  /* We must go through the directories given
     in the name, looking for a case insensitive match. */
  
  tnp = tmpname;
  /* Optimization to stop searching for ./././ at the
     start of tmpname */
  while(strncmp(tnp,"./",2)==0)
    tnp += 2;
  while((p  = strchr(tnp,'/')))
    {
      StrnCpy(name, tnp, p - tnp);

      if(tnp == tmpname)
	strcpy(dir_to_search,".");
      else
	StrnCpy(dir_to_search, tmpname, tnp - tmpname);

      /* Open the directory theoretically containing the
	 directory 'name' and search for a case independent
	 version of it */
      if(search_lanman2(dir_to_search, name, matching_name, S_IFDIR))
	{
	  /* If we didn't find it then we may as well quit */
	  strcpy(s,tmpname);
	  
	  DEBUG(5,("search_lanman2 fail : Converted to lanman2 name %s\n",s));

	  return;
	}

      /* Replace the incorrect case version of the
	 name with the correct on in the directory */
      memcpy(tnp, matching_name, strlen(matching_name));

      tnp = p + 1;
    }

  /* Here tnp is pointing at the last component of the name or at '\0' */
  if(*tnp)
    {
      StrnCpy(dir_to_search, tmpname, tnp - tmpname);

      if(0==search_lanman2(dir_to_search, tnp, matching_name, S_IFDIR|S_IFREG))
	memcpy(tnp,matching_name,strlen(matching_name));
    }
  strcpy(s,tmpname);

  DEBUG(5,("Converted to lanman2 name %s\n",s));

}

/****************************************************************************
  see if a name matches a mask. The mask takes the form of several characters,
  with ? being a wild card.
****************************************************************************/
BOOL mask_match(char *Name,char *Mask,BOOL dodots,BOOL case_sensitive, BOOL doext)
{
  char *p1,*p2;
  pstring nbeg=""; /* beginning of name */
  pstring next=""; /* extension of name */
  pstring mext=""; /* extension of mask */
  pstring mbeg=""; /* beg of mask */  
  pstring name,mask;
  BOOL hasdot=False;

  DEBUG(3,("mmatch [%s] [%s] %d\n",Name,Mask,dodots));

  if (strcmp(Name,Mask) == 0)
    return(True);

  strcpy(name,Name);
  strcpy(mask,Mask);

  if (!case_sensitive)
    {
      strlower(name);
      strlower(mask);
    }

  strcpy(mbeg,mask);
  if ((p1 = strchr(mbeg,'.')) != NULL)
    {
      hasdot = True;
      *p1 = 0;
      p1++;
      strcpy(mext,p1);
    }
  else
    {
      strcpy(mext,"");
      if (strlen(mbeg) > 8)
	{
	  strcpy(mext,mbeg + 8);
	  mbeg[8] = 0;
	}
    }

  if (*mbeg == 0)
    strcpy(mbeg,"????????");
  if (*mext == 0 && doext && !hasdot)
    strcpy(mext,"???");

  /* expand *'s */
  expand_one(mbeg,8);
  if (*mext)
    expand_one(mext,3);
  
  /* a couple of special cases */
  if (strequal(name,".") || strequal(name,".."))
    return(dodots && strequal(mbeg,"????????") && strequal(mext,"???"));

  if (strequal(mbeg,"????????") && strequal(mext,"???"))
    return(True);

  strcpy(nbeg,name);
  if ((p1 = strchr(nbeg,'.')) != NULL)
    {
      *p1 = 0;
      p1++;
      strcpy(next,p1);
      if (strchr(next,'.')) /* can't have two .s in a name */
	return(False);
    }
  else
    strcpy(next,"");

  /* strip trailing spaces */
  string_replace(nbeg,' ',0);  
  string_replace(mbeg,' ',0);  
  string_replace(next,' ',0);  
  string_replace(mext,' ',0);  
  
  if (strlen(nbeg) == 0) return(False);
  if (strlen(mbeg) == 0) return(False);
  if (strlen(nbeg) > 8) return(False);
  if (strlen(next) > 3) return(False);
  if (strlen(mbeg) > 8) return(False);
  if (strlen(mext) > 3) return(False);
  if (strlen(nbeg) > strlen(mbeg)) return(False);
  if (strlen(next) > strlen(mext)) return(False);
  
  /* only accept lowercase names */
  p1 = name;
#ifdef KANJI
  while (*p1) {
      if (is_shift_jis (*p1)) {
	  p1 += 2;
      } else if (is_kana (*p1)) {
	  p1++;
      } else {
	  if (isupper(*p1++)) return(False);
      }
  }
#else 
  while (*p1) 
    if (isupper(*p1++)) return(False);
#endif /* KANJI */

  DEBUG(3,("Matching [%8.8s.%3.3s] to [%8.8s.%3.3s]\n",nbeg,next,mbeg,mext));
  
  p1 = nbeg;
  p2 = mbeg;
  while (*p2)
    {
      if ((*p2 != '?') && (*p1 != *p2)) 
	return(False);
      p2++;
      if (*p1) p1++;
    }
  
  p1 = next;
  p2 = mext;
  while (*p2)
    {
      if ((*p2 != '?') && (*p1 != *p2)) 
	return(False);
      p2++;
      if (*p1) p1++;
    }

  DEBUG(3,("Matched correctly\n"));

  return(True);
}


/****************************************************************************
  make a dir struct
****************************************************************************/
void make_dir_struct(char *buf,char *mask,char *fname,unsigned int size,int mode,time_t date)
{  
  char *p;
  pstring mask2="";

  strcpy(mask2,mask);

  if ((mode & aDIR) != 0)
    size = 0;

  memset(buf+1,' ',11);
  if ((p = strchr(mask2,'.')) != NULL)
    {
      *p = 0;
      memcpy(buf+1,mask2,MIN(strlen(mask2),8));
      memcpy(buf+9,p+1,MIN(strlen(p+1),3));
      *p = '.';
    }
  else
    memcpy(buf+1,mask2,MIN(strlen(mask2),11));

  memset(buf+21,0,DIR_STRUCT_SIZE-21);
  CVAL(buf,21) = mode;
  put_dos_date(buf,22,date);
  SSVAL(buf,26,size & 0xFFFF);
  SSVAL(buf,28,size >> 16);
  StrnCpy(buf+30,fname,12);
  strupper(buf+30);
}


/****************************************************************************
log a packet to logout
****************************************************************************/
void log_out(char *buffer,int len)
{
  if (logout)
    {
      fprintf(logout,"\n%s Transaction %d (%d)\n",timestring(),trans_num++,len);
      fwrite(buffer,len,1,logout);
      fflush(logout);
    }      
  DEBUG(7,("logged %d bytes out\n",len));
}

/****************************************************************************
log a packet to login
****************************************************************************/
void log_in(char *buffer,int len)
{
  if (login)
    {
      fprintf(login,"\n%s Transaction %d (%d)\n",timestring(),trans_num++,len);
      fwrite(buffer,len,1,login);
      fflush(login);
    }      
  DEBUG(7,("logged %d bytes in\n",len));
}

/****************************************************************************
write to a socket
****************************************************************************/
int write_socket(int fd,char *buf,int len)
{
  int ret=0;

  if (passive)
    return(len);
  DEBUG(6,("write_socket(%d,%d)\n",fd,len));
  ret = write(fd,buf,len);
      
  DEBUG(4,("write_socket(%d,%d) gave %d\n",fd,len,ret));
  return(ret);
}

/****************************************************************************
read from a socket
****************************************************************************/
int read_udp_socket(int fd,char *buf,int len)
{
  /* #define NORECVFROM */
#ifdef NORECVFROM
  return(read(fd,buf,len));
#else
  int ret;
  struct sockaddr sock;
  int socklen;
  
  socklen = sizeof(sock);
  memset((char *)&sock, 0, socklen);
  memset((char *)&lastip, 0, sizeof(lastip));
  ret = recvfrom(fd,buf,len,0,&sock,&socklen);
  if (ret <= 0)
    {
      DEBUG(2,("read socket failed. ERRNO=%d\n",errno));
      return(0);
    }

  lastip = *(struct in_addr *) &sock.sa_data[2];
  lastport = ntohs(((struct sockaddr_in *)&sock)->sin_port);
  if (DEBUGLEVEL > 0)
    DEBUG(3,("read %d bytes\n",ret));

  return(ret);
#endif
}

/****************************************************************************
Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
else
if SYSV use O_NDELAY
if BSD use FNDELAY
****************************************************************************/
int set_blocking(int fd, BOOL set)
{
int val;
#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

  if((val = fcntl(fd, F_GETFL, 0))==-1)
	return -1;
  if(set) /* Turn blocking on - ie. clear nonblock flag */
	val &= ~FLAG_TO_SET;
  else
    val |= FLAG_TO_SET;
  return fcntl( fd, F_SETFL, val);
#undef FLAG_TO_SET
}


/****************************************************************************
Calculate the difference in timeout values. Return 1 if val1 > val2,
0 if val1 == val2, -1 if val1 < val2. Stores result in retval. retval
may be == val1 or val2
****************************************************************************/
int tval_sub( struct timeval *retval, struct timeval *val1, struct timeval *val2)
{
	long usecdiff = val1->tv_usec - val2->tv_usec;
	long secdiff = val1->tv_sec - val2->tv_sec;
	if(usecdiff < 0) {
		usecdiff = 1000000 + usecdiff;
		secdiff--;
	}
	retval->tv_sec = secdiff;
	retval->tv_usec = usecdiff;
	if(secdiff < 0)
		return -1;
	if(secdiff > 0)
		return 1;
	return (usecdiff < 0 ) ? -1 : ((usecdiff > 0 ) ? 1 : 0);
}

/****************************************************************************
read data from a device with a timout in msec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
****************************************************************************/
int read_with_timeout(int fd,char *buf,int mincnt,int maxcnt,long time_out,BOOL exact)
{
  fd_set fds;
  int selrtn;
  int readret;
  int nread = 0;
  struct timeval timeout, tval1, tval2, tvaldiff;
  struct timezone tz;

  /* just checking .... */
  if (maxcnt <= 0) return(0);

  if(time_out == -2)
    time_out = DEFAULT_PIPE_TIMEOUT;

  /* Blocking read */
  if(time_out < 0) {
    return read(fd, buf, maxcnt);
  }
  
  /* Non blocking read */
  if(time_out == 0) {
    set_blocking(fd, False);
    nread = read(fd, buf, maxcnt);
    if(nread == -1 && errno == EWOULDBLOCK)
      nread = 0;
    set_blocking(fd,True);
    return nread;
  }

  /* Most difficult - timeout read */
  /* If this is ever called on a disk file and 
	 mincnt is greater then the filesize then
	 system performance will suffer severely as 
	 select always return true on disk files */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000;
  timeout.tv_usec = 1000 * (time_out % 1000);

  /* As most UNIXes don't modify the value of timeout
     when they return from select we need to get the timeofday (in usec)
     now, and also after the select returns so we know
     how much time has elapsed */

  if (exact)
    gettimeofday( &tval1, &tz);
  nread = 0; /* Number of bytes we have read */

  for(;;) 
    {
      
      FD_ZERO(&fds);
      FD_SET(fd,&fds);
      
      do {    
	selrtn = select(255,SELECT_CAST &fds,NULL,NULL,&timeout);
      } 
      while( selrtn < 0  &&  errno == EINTR );
      
      /* Check if error */
      if(selrtn == -1)
	return -1;
      
      /* Did we timeout ? */
      if (selrtn == 0 )
	break; /* Yes */
      
      readret = read( fd, buf+nread, maxcnt-nread);
      if(readret == -1)
	return -1;

      if (readret == 0)
	break;
      
      nread += readret;
      
      /* If we have read more than mincnt then return */
      if( nread >= mincnt )
	break;

      /* We need to do another select - but first reduce the
	 time_out by the amount of time already elapsed - if
	 this is less than zero then return */
      if (exact)
	{
	  gettimeofday( &tval2, &tz);
	  (void)tval_sub( &tvaldiff, &tval2, &tval1);
      
	  if( tval_sub( &timeout, &timeout, &tvaldiff) <= 0) 
	    {
	      /* We timed out */
	      break;
	    }
	}
      
      /* Save the time of day as we need to do the select 
	 again (saves a system call)*/
      tval1 = tval2;
    }

  /* Return the number we got */
  return(nread);
}

/****************************************************************************
read data from the client. Maxtime is in 10ths of a sec
****************************************************************************/
int read_max_udp(int fd,char *buffer,int bufsize,int maxtime)
{
  fd_set fds;
  int selrtn;
  int nread;
  struct timeval timeout;
 
  FD_ZERO(&fds);
  FD_SET(fd,&fds);

  timeout.tv_sec = maxtime / 10;
  timeout.tv_usec = (maxtime % 10) * 100000;

  do {    
    if (maxtime > 0)
      selrtn = select(255,SELECT_CAST &fds,NULL,NULL,&timeout);
    else
      selrtn = select(255,SELECT_CAST &fds,NULL,NULL,NULL);
  } 
  while( selrtn < 0  &&  errno == EINTR );


  if (!FD_ISSET(fd,&fds))
    return 0;

  nread = read_udp_socket(fd, buffer, bufsize);

  /* return the number got */
  return(nread);
}

/****************************************************************************
write data to a device with a timout in msec.
****************************************************************************/
int write_with_timeout(int fd, char *buf, int length, long time_out)
{
  fd_set fds;
  int selrtn;
  int nwritten = 0;
  int writeret;
  struct timeval timeout, tval1, tval2, tvaldiff;
  struct timezone tz;
 
  if(time_out == -2)
    time_out = DEFAULT_PIPE_TIMEOUT;

  /* Blocking write */
  if(time_out == -1) {
    return write(fd, buf, length);
  }
  
  /* Non blocking write */
  if(time_out == 0) {
    set_blocking(fd, False);
    nwritten = write(fd, buf, length);
    if( nwritten == -1 && errno == EWOULDBLOCK)
      nwritten = 0;
    set_blocking(fd,True);
    return nwritten;
  }

  /* Most difficult - timeout write */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000;
  timeout.tv_usec = 1000*(time_out % 1000);

  /* As most UNIXes don't modify the value of timeout
     when they return from select we need to get the timeofday (in usec)
     now, and also after the select returns so we know
     how much time has elapsed */

  gettimeofday( &tval1, &tz);
  nwritten = 0; /* Number of bytes we have written */

  for(;;) {

    FD_ZERO(&fds);
    FD_SET(fd,&fds);

    /* Wait with timeout until we can write */
    do {    
      selrtn = select(255,NULL,SELECT_CAST &fds,NULL,&timeout);
    } 
    while( selrtn < 0  &&  errno == EINTR );

    /* Check if error */
    if(selrtn == -1)
      return -1;

    /* Did we timeout ? */
    if (selrtn == 0 )
      break; /* Yes */

    /* Set the fd nonblocking and write as much as we can */
    set_blocking(fd, False);
    writeret = write( fd, buf+nwritten, length-nwritten );
    set_blocking(fd,True);
    if(writeret == -1)
      return -1;
    nwritten += writeret;

    /* If we have written more than length then return */
    if( nwritten >= length )
	  break;

    /* We need to do another select - but first reduce the
	 time_out by the amount of time already elapsed - if
	 this is less than zero then return */
    gettimeofday( &tval2, &tz);
    (void)tval_sub( &tvaldiff, &tval2, &tval1);

    if( tval_sub( &timeout, &timeout, &tvaldiff) <= 0) {
	  /* We timed out */
	  break;
    }
    
    /* Save the time of day as we need to do the 
       select again (saves a system call)*/
    tval1 = tval2;
  }
  /* Return the number we got */
  return(nwritten);
}


/****************************************************************************
send a keepalive packet (rfc1002)
****************************************************************************/
BOOL send_keepalive(void)
{
  unsigned char buf[4];
  int nwritten = 0;

  buf[0] = 0x85;
  buf[1] = buf[2] = buf[3] = 0;

  while (nwritten < 4)
    {
      int ret = write_socket(Client,(char *)&buf[nwritten],4 - nwritten);
      if (ret <= 0)
	return(False);
      nwritten += ret;
    }
  return(True);
}

int keepalive = 0;


/****************************************************************************
  read data from the client, reading exactly N bytes. 
****************************************************************************/
BOOL read_data(int fd,char *buffer,int N)
{
  int maxtime = keepalive;
  int  nready;
  int nread = 0;  
 
  if (maxtime > 0)
    {
      fd_set fds;
      int selrtn;
      struct timeval timeout;
      
      FD_ZERO(&fds);
      FD_SET(fd,&fds);
            
      timeout.tv_sec = maxtime;
      timeout.tv_usec = 0;
      
      while ((selrtn = select(255,SELECT_CAST &fds,NULL,NULL,&timeout)) == 0)
	{
	  DEBUG(6,("Sending keepalive\n"));
	  if (!send_keepalive())
	    {
	      DEBUG(0,("keepalive failed!\n"));
	      return(False);
	    }
	  timeout.tv_sec = maxtime;
	  timeout.tv_usec = 0;
	  FD_ZERO(&fds);
	  FD_SET(fd,&fds);            
	}
    }

  while (nread < N)
    {
      nready = read(fd,buffer + nread,N - nread);
      if (nready <= 0)
	return False;
      nread += nready;
    }
  return True;
}


/* variables used by the read prediction module */
int rp_fd = -1;
int rp_offset = 0;
int rp_length = 0;
int rp_alloced = 0;
int rp_predict_fd = -1;
int rp_predict_offset = 0;
int rp_predict_length = 0;
int rp_timeout = 5;
time_t rp_time = 0;
char *rp_buffer = NULL;


/****************************************************************************
handle read prediction on a file
****************************************************************************/
int read_predict(int fd,int offset,char *buf,int num)
{
  int ret = 0;
  int possible = rp_length - (offset - rp_offset);

  possible = MIN(possible,num);

  /* give data if possible */
  if (fd == rp_fd && 
      offset >= rp_offset && 
      possible>0 &&
      time(NULL)-rp_time < rp_timeout)
    {
      ret = possible;
      memcpy(buf,rp_buffer + (offset-rp_offset),possible);
      DEBUG(5,("read-prediction gave %d bytes\n",ret));
    }

  /* prepare the next prediction */
  rp_predict_fd = fd;
  rp_predict_offset = offset + num;
  rp_predict_length = num;

  return(ret);
}

/****************************************************************************
pre-read some data
****************************************************************************/
void do_read_prediction()
{
  if (rp_predict_fd == -1) 
    return;

  rp_fd = rp_predict_fd;
  rp_offset = rp_predict_offset;
  rp_length = 0;

  rp_predict_fd = -1;

  if (rp_predict_length > rp_alloced)
    {
      rp_buffer = Realloc(rp_buffer,rp_predict_length);
      rp_alloced = rp_predict_length;
      if (!rp_buffer)
	{
	  DEBUG(0,("can't allocate read-prediction buffer\n"));
	  rp_alloced = 0;
	  return;
	}
    }

  if (lseek(rp_fd,0,SEEK_CUR) != rp_offset && lseek(rp_fd,rp_offset,SEEK_SET) != rp_offset)
    return;

  rp_length = read(rp_fd,rp_buffer,rp_predict_length);
  rp_time = time(NULL);
  if (rp_length < 0)
    rp_length = 0;
}

/****************************************************************************
invalidate read-prediction on a fd
****************************************************************************/
void invalidate_read_prediction(int fd)
{
 if (rp_fd == fd) 
   rp_fd = -1;
 if (rp_predict_fd == fd)
   rp_predict_fd = -1;
}


/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
possibly store the result in the buffer
****************************************************************************/
int read_smb_length(int fd,char *inbuf,int timeout)
{
  char *buffer;
  char buf[4];
  int len=0, msg_type;
  BOOL ok=False;

  if (inbuf)
    buffer = inbuf;
  else
    buffer = buf;

  while (!ok)
    {
      if (timeout > 0)
	ok = (read_with_timeout(fd,buffer,4,4,timeout,False) == 4);
      else
	ok = read_data(fd,buffer,4);

      if (!ok)
	{
	  if (timeout>0)
	    {
	      DEBUG(6,("client timeout (timeout was %d)\n", timeout));
	      return(-1);
	    }
	  else
	    {
	      DEBUG(6,("couldn't read from client\n"));
	      exit(1);
	    }
	}

      len = smb_len(buffer);
      msg_type = CVAL(buffer,0);

      if (msg_type == 0x85) 
	{
	  DEBUG(5,( "Got keepalive packet\n"));
	  ok = False;
	}
    }

  return(len);
}



/****************************************************************************
  read an smb from a fd and return it's length
The timeout is in micro seconds
****************************************************************************/
BOOL receive_smb(char *buffer,int timeout)
{
  int len;
  int fd = Client;
  BOOL ok;

  memset(buffer,0,smb_size + 100);

  len = read_smb_length(fd,buffer,timeout);
  if (len == -1)
    return(False);

  if (len > BUFFER_SIZE)
    {
      DEBUG(0,("Invalid packet length! (%d bytes)\n",len));
      if (len > BUFFER_SIZE + (SAFETY_MARGIN/2))
	exit(0);
    }

  ok = read_data(fd,buffer+4,len);

  if (!ok)
    {
      DEBUG(0,("couldn't read %d bytes from client\n",len));
      close_sockets();
      exit(1);
    }

  log_in(buffer,len+4);
  return(True);
}


/****************************************************************************
  send an smb to a fd 
****************************************************************************/
BOOL send_smb(char *buffer)
{
  int fd = Client;
  int len;
  int ret,nwritten=0;
  len = smb_len(buffer) + 4;

  log_out(buffer,len);

  while (nwritten < len)
    {
      ret = write_socket(fd,buffer+nwritten,len - nwritten);
      if (ret <= 0)
	{
	  DEBUG(0,("Error writing %d bytes to client. %d. Exiting\n",len,ret));
          close_sockets();
	  exit(1);
	}
      nwritten += ret;
    }


  return True;
}


/****************************************************************************
word out the length of a nmb message
****************************************************************************/
int nmb_len(char *buf)
{
int i;
int ret = 12;
char *p = buf;
int qdcount = SVAL(buf,4);
int ancount = SVAL(buf,6);
int nscount = SVAL(buf,8);
int arcount = SVAL(buf,10);

/* check for insane qdcount values? */
if (qdcount > 100 || qdcount < 0)
  {
    DEBUG(6,("Invalid qdcount? qdcount=%d\n",qdcount));
    return(0);
  }

for (i=0;i<qdcount;i++)
  {
    p = buf + ret;
    ret += name_len(p) + 4;
  }

for (i=0;i<(ancount + nscount + arcount);i++)
  {
    int rdlength;
    p = buf + ret;
    ret += name_len(p) + 8;
    p = buf + ret;
    rdlength = SVAL(p,0);
    ret += rdlength + 2;
  }

return(ret);
}


int nmb_recv_len = 0;

/****************************************************************************
receive a name message
****************************************************************************/
BOOL receive_nmb(char *buffer,int timeout)
{
  int ret = read_max_udp(Client,buffer,BUFFER_SIZE,timeout);

  nmb_recv_len = ret;

  if (ret < 0)
    {
      DEBUG(0,("No bytes from client\n"));
      close_sockets();
      exit(0);
    }
  
  if (ret <= 1)
    return False;

  log_in(buffer,ret);

  DEBUG(3,("received packet from (%s) nmb_len=%d len=%d\n",
	inet_ntoa(lastip),nmb_len(buffer),ret));

  return(True);
}


/****************************************************************************
send a name message
****************************************************************************/
BOOL send_nmb(char *buf, int len, struct in_addr *ip)
{
  BOOL ret;
  struct sockaddr_in sock_out;
  int one=1;

#if 1
  /* allow broadcasts on it */
  setsockopt(Client,SOL_SOCKET,SO_BROADCAST,(char *)&one,sizeof(one));
#endif
		  
  /* set the address and port */
  memset((char *)&sock_out, 0, sizeof(sock_out));
  memcpy((char *)&sock_out.sin_addr,(char *)ip, 4);
  sock_out.sin_port = htons( 137 );
  sock_out.sin_family = AF_INET;
  
  /* log the packet */
  log_out(buf,len);

  if (DEBUGLEVEL > 0)
    DEBUG(3,("sending a packet of len %d to (%s) on port 137 of type DGRAM\n",
	  len,inet_ntoa(*ip)));
	
  /* send it */
  ret = (sendto(Client,buf,len,0,(struct sockaddr *)&sock_out,sizeof(sock_out)) >= 0);

  if (!ret)
    DEBUG(0,("Send packet failed. ERRNO=%d\n",errno));

  return(ret);
}


/****************************************************************************
find a pointer to a netbios name
****************************************************************************/
char *name_ptr(char *buf,int ofs)
{
  unsigned char c = *(unsigned char *)(buf+ofs);

  if ((c & 0xC0) == 0xC0)
    {
      uint16 l;
      char *p = (char *)&l;
      memcpy((char *)&l,buf+ofs,2);
      p[0] &= ~0xC0;
      l = SVAL(p,0);
      DEBUG(5,("name ptr to pos %d from %d is %s\n",l,ofs,buf+l));
      return(buf + l);
    }
  else
    return(buf+ofs);
}  

/****************************************************************************
extract a netbios name from a buf
****************************************************************************/
void name_extract(char *buf,int ofs,char *name)
{
  strcpy(name,"");
  name_interpret(name_ptr(buf,ofs),name);
}  
  


/****************************************************************************
show a nmb message
****************************************************************************/
void show_nmb(char *inbuf)
{
  int i,l;
  int name_trn_id = SVAL(inbuf,0);
  int opcode = (CVAL(inbuf,2) >> 3) & 0xF;
  int nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
  int rcode = CVAL(inbuf,3) & 0xF;
  int qdcount = SVAL(inbuf,4);
  int ancount = SVAL(inbuf,6);
  int nscount = SVAL(inbuf,8);
  int arcount = SVAL(inbuf,10);
  char name[100];

  DEBUG(3,("\nPACKET INTERPRETATION\n"));

#if 0
  if (dbf)
    fwrite(inbuf,1,nmb_len(inbuf),dbf);
  DEBUG(0,("\n"));
#endif

  if (opcode == 5 && ((nm_flags & ~1) == 0x10) && rcode == 0)
    DEBUG(3,("NAME REGISTRATION REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast"));

  if (opcode == 5 && ((nm_flags & ~1) == 0x00) && rcode == 0)
    DEBUG(3,("NAME OVERWRITE REQUEST AND DEMAND (%s)\n",nm_flags&1?"Broadcast":"Unicast"));
  
  if (opcode == 9 && ((nm_flags & ~1) == 0x00) && rcode == 0)
    DEBUG(3,("NAME REFRESH REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast"));
  
  if (opcode == 5 && nm_flags == 0x58 && rcode == 0)
    DEBUG(3,("POSITIVE NAME REGISTRATION RESPONSE\n"));
  
  if (opcode == 5 && nm_flags == 0x58 && rcode != 0 && rcode != 7)
    DEBUG(3,("NEGATIVE NAME REGISTRATION RESPONSE\n"));
  
  if (opcode == 5 && nm_flags == 0x50 && rcode == 0)
    DEBUG(3,("END-NODE CHALLENGE REGISTRATION RESPONSE\n"));
  
  if (opcode == 5 && nm_flags == 0x58 && rcode != 0 && rcode == 7)
    DEBUG(3,("NAME CONFLICT DEMAND\n"));
  
  if (opcode == 6 && (nm_flags&~1) == 0x00 && rcode == 0)
    DEBUG(3,("NAME RELEASE REQUEST & DEMAND (%s)\n",nm_flags&1?"Broadcast":"Unicast"));
  
  if (opcode == 6 && (nm_flags&~1) == 0x40 && rcode == 0)
    DEBUG(3,("POSITIVE NAME RELEASE RESPONSE\n"));
  
  if (opcode == 6 && (nm_flags&~1) == 0x40 && rcode != 0)
    DEBUG(3,("NEGATIVE NAME RELEASE RESPONSE\n"));
  
  if (opcode == 0 && (nm_flags&~1) == 0x10 && rcode == 0)
    DEBUG(3,("NAME QUERY REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast"));
  
  if (opcode == 0 && (nm_flags&~0x28) == 0x50 && rcode == 0)
    DEBUG(3,("POSITIVE NAME QUERY RESPONSE\n"));
  
  if (opcode == 0 && (nm_flags&~0x08) == 0x50 && rcode != 0)
    DEBUG(3,("NEGATIVE NAME QUERY RESPONSE\n"));
  
  if (opcode == 0 && nm_flags == 0x10 && rcode == 0)
    DEBUG(3,("REDIRECT NAME QUERY RESPONSE\n"));

  if (opcode == 7 && nm_flags == 0x80 && rcode == 0)
    DEBUG(3,("WAIT FOR ACKNOWLEDGEMENT RESPONSE\n"));
  
  if (opcode == 0 && (nm_flags&~1) == 0x00 && rcode == 0)
    DEBUG(3,("NODE STATUS REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast"));

  if (opcode == 0 && nm_flags == 0x40 && rcode == 0)
    DEBUG(3,("NODE STATUS RESPONSE\n"));
  
  
  DEBUG(3,("name_trn_id=0x%x\nopcode=0x%x\nnm_flags=0x%x\nrcode=0x%x\n",
	name_trn_id,opcode,nm_flags,rcode));
  DEBUG(3,("qdcount=%d\nancount=%d\nnscount=%d\narcount=%d\n",
	qdcount,ancount,nscount,arcount));

  l = 12;
  for (i=0;i<qdcount;i++)
    {
      int type,class;
      DEBUG(3,("QUESTION %d\n",i));
      name_extract(inbuf,l,name);
      l += name_len(inbuf+l);
      type = SVAL(inbuf+l,0);
      class = SVAL(inbuf+l,2);
      l += 4;
      DEBUG(3,("\t%s\n\ttype=0x%x\n\tclass=0x%x\n",name,type,class));
    }

  for (i=0;i<(ancount + nscount + arcount);i++)
    {
      int type,class,ttl,rdlength;
      DEBUG(3,("RESOURCE %d\n",i));
      name_extract(inbuf,l,name);
      l += name_len(inbuf + l);
      type = SVAL(inbuf+l,0);
      class = SVAL(inbuf+l,2);
      ttl = IVAL(inbuf+l,4);
      rdlength = SVAL(inbuf+l,8);
      l += 10 + rdlength;
      DEBUG(3,("\t%s\n\ttype=0x%x\n\tclass=0x%x\n",name,type,class));
      DEBUG(3,("\tttl=%d\n\trdlength=%d\n",ttl,rdlength));
    }

  DEBUG(3,("\n"));
  
}

/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len(char *s)
{
  unsigned char c = *(unsigned char *)s;
  if ((c & 0xC0) == 0xC0)
    return(2);
  return(strlen(s) + 1);
}

/****************************************************************************
send a single packet to a port on another machine
****************************************************************************/
BOOL send_packet(char *buf,int len,struct in_addr *ip,int port,int type)
{
  BOOL ret;
  int out_fd;
  struct sockaddr_in sock_out;
  int one=1;

  if (passive)
    return(True);

  /* create a socket to write to */
  out_fd = socket(AF_INET, type, 0);
  if (out_fd == -1) 
    {
      DEBUG(0,("socket failed"));
      return False;
    }
#if 1
  /* allow broadcasts on it */
  setsockopt(out_fd,SOL_SOCKET,SO_BROADCAST,(char *)&one,sizeof(one));
#endif
		  
  /* set the address and port */
  memset((char *)&sock_out, 0, sizeof(sock_out));
  memcpy((char *)&sock_out.sin_addr,(char *)ip, 4);
  sock_out.sin_port = htons( port );
  sock_out.sin_family = AF_INET;
  
  /* log the packet */
  log_out(buf,len);

  if (DEBUGLEVEL > 0)
    DEBUG(3,("sending a packet of len %d to (%s) on port %d of type %s\n",
	  len,inet_ntoa(*ip),port,type==SOCK_DGRAM?"DGRAM":"STREAM"));
	
  /* send it */
  ret = (sendto(out_fd,buf,len,0,(struct sockaddr *)&sock_out,sizeof(sock_out)) >= 0);

  if (!ret)
    DEBUG(0,("Send packet failed. ERRNO=%d\n",errno));

  close(out_fd);
  return(ret);
}


/****************************************************************************
check if a string is part of a list
****************************************************************************/
BOOL in_list(char *s,char *list,BOOL case_sensitive)
{
  char *listcopy;
  char *t;

  if (!list) return(False);

  listcopy = strdup(list);
  if (!listcopy)
    return(False);

  for (t=strtok(listcopy,LIST_SEP); t; t = strtok(NULL,LIST_SEP))
    {
      if (case_sensitive)
	{
	  if (strcmp(t,s) == 0)
	    {
	      free(listcopy);
	      return(True);
	    }
	}
      else
	{
	  if (strcasecmp(t,s) == 0)
	    {
	      free(listcopy);
	      return(True);
	    }
	}
    }
  free(listcopy);
  return(False);
}

/* this is used to prevent lots of mallocs of size 1 */
char *null_string = NULL;

/****************************************************************************
set a string value, allocing the space for the string
****************************************************************************/
BOOL string_init(char **dest,char *src)
{
  int l;
  if (!src)     
    src = "";

  l = strlen(src);

  if (l == 0)
    {
      if (!null_string)
	{
	  null_string = (char *)malloc(1);
	  *null_string = 0;
	}
      *dest = null_string;
    }
  else
    {
      *dest = (char *)malloc(l+1);
      strcpy(*dest,src);
    }
  return(True);
}

/****************************************************************************
free a string value
****************************************************************************/
void string_free(char **s)
{
  if (!s || !(*s)) return;
  if (*s == null_string)
    *s = NULL;
  if (*s) free(*s);
  *s = NULL;
}

/****************************************************************************
set a string value, allocing the space for the string, and deallocating any 
existing space
****************************************************************************/
BOOL string_set(char **dest,char *src)
{
  string_free(dest);

  return(string_init(dest,src));
}

/****************************************************************************
substitute a string for a pattern in another string. Make sure there is 
enough room!

This routine looks for pattern in s and replaces it with 
insert. It may do multiple replacements.

return True if a substitution was done.
****************************************************************************/
BOOL string_sub(char *s,char *pattern,char *insert)
{
  BOOL ret = False;
  char *p;
  int ls = strlen(s);
  int lp = strlen(pattern);
  int li = strlen(insert);

  if (!*pattern) return(False);

  while (lp <= ls && (p = strstr(s,pattern)))
    {
      ret = True;
      safe_memcpy(p+li,p+lp,ls + 1 - (PTR_DIFF(p,s) + lp));
      memcpy(p,insert,li);
      s = p + li;
      ls = strlen(s);
    }
  return(ret);
}

/****************************************************************************
get a users home directory. tries as-is then lower case
****************************************************************************/
char *get_home_dir(char *user)
{
  static struct passwd *pass;

  pass = Get_Pwnam(user);

  if (!pass) return(NULL);
  return(pass->pw_dir);      
}


/****************************************************************************
become a daemon, discarding the controlling terminal
****************************************************************************/
void become_daemon(void)
{
#ifndef NO_FORK_DEBUG
  if (fork())
    exit(0);

  /* detach from the terminal */
#ifdef LINUX
  setpgrp();
#endif

#ifdef USE_SETSID
  setsid();
#else
  {
    int i = open("/dev/tty", O_RDWR);
    if (i >= 0) 
      {
	ioctl(i, (int) TIOCNOTTY, (char *)0);      
	close(i);
      }
  }
#endif
#endif
}

/****************************************************************************
calculate the default netmask for an address
****************************************************************************/
static void default_netmask(struct in_addr *inm, struct in_addr *iad)
{
  unsigned long ad = ntohl(iad->s_addr);
  unsigned long nm;
  /*
  ** Guess a netmask based on the class of the IP address given.
  */
  if ( (ad & 0x80000000) == 0 ) {
    /* class A address */
    nm = 0xFF000000;
  } else if ( (ad & 0xC0000000) == 0x80000000 ) {
    /* class B address */
    nm = 0xFFFF0000;
  } else if ( (ad & 0xE0000000) == 0xC0000000 ) {
    /* class C address */
    nm = 0xFFFFFF00;
  }  else {
    /* class D or E; netmask doesn't make much sense */
    nm =  0;
  }
  inm->s_addr = htonl(nm);
}

/****************************************************************************
  get the broadcast address for our address 
(troyer@saifr00.ateng.az.honeywell.com)
****************************************************************************/
void get_broadcast (struct in_addr *if_ipaddr,
                    struct in_addr *if_bcast,
                    struct in_addr *if_nmask)
{
  int sock = -1;               /* AF_INET raw socket desc */
  char buff[1024];
  struct ifreq *ifr;
  int i;

#ifdef USE_IFREQ
  struct ifreq ifreq;
  struct strioctl strioctl;
  struct ifconf *ifc;
#else
  struct ifconf ifc;
#endif

  /* get a default netmask and broadcast */
  default_netmask(if_nmask, if_ipaddr);
  {
    unsigned long ip = ntohl(if_ipaddr->s_addr);
    unsigned long nm = ntohl(if_nmask->s_addr);
    ip &= nm;                           /* mask down to our network number */
    ip |= ( 0x00FFFFFF & ~nm );         /* insert 1s in host field         */
    if_bcast->s_addr = htonl(ip);
  }
  
  
  /* Create a socket to the INET kernel. */
#if USE_SOCKRAW
  if ((sock = socket(AF_INET, SOCK_RAW, PF_INET )) < 0)
#else
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0 )) < 0)
#endif
      {
        DEBUG(0,( "Unable to open socket to get broadcast address\n"));
        return;
      }
  
  /* Get a list of the configures interfaces */
#ifdef USE_IFREQ
  ifc = (struct ifconf *)buff;
  ifc->ifc_len = BUFSIZ - sizeof(struct ifconf);
  strioctl.ic_cmd = SIOCGIFCONF;
  strioctl.ic_dp  = (char *)ifc;
  strioctl.ic_len = sizeof(buff);
  if (ioctl(sock, I_STR, &strioctl) < 0)
    {
      DEBUG(0,( "I_STR/SIOCGIFCONF: %s\n", strerror(errno)));
      return;
    }
  ifr = (struct ifreq *)ifc->ifc_req;
  
  /* Loop through interfaces, looking for given IP address */
  for (i = ifc->ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
#else
    ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
    {
      DEBUG(0,( "SIOCGIFCONF: %s\n", strerror(errno)));
      return;
    }
  ifr = ifc.ifc_req;
  
  /* Loop through interfaces, looking for given IP address */
  for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
#endif
    {
      DEBUG(3,("Interface: %s  IP addr: %s\n", ifr->ifr_name,
            inet_ntoa((*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr)));
      if (if_ipaddr->s_addr ==
	  (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr)
	break;
    }
  
  if (i < 0)
    {
      DEBUG(0,("No interface found for address %s\n", inet_ntoa(*if_ipaddr)));
      return;
    }
  
  /* Get the broadcast address from the kernel */
#ifdef USE_IFREQ
  ifreq = *ifr;
  
  strioctl.ic_cmd = SIOCGIFBRDADDR;
  strioctl.ic_dp  = (char *)&ifreq;
  strioctl.ic_len = sizeof(struct ifreq);
  if (ioctl(sock, I_STR, &strioctl) < 0)
    DEBUG(0,( "Failed I_STR/SIOCGIFBRDADDR: %s\n", strerror(errno)));
  else
    *if_bcast = ((struct sockaddr_in *)&ifreq.ifr_broadaddr)->sin_addr;
#else
  if (ioctl(sock, SIOCGIFBRDADDR, ifr) < 0)
    DEBUG(0,("SIOCGIFBRDADDR failed\n"));
  else
    *if_bcast = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;
#endif
  
  /* Get the netmask address from the kernel */
#ifdef USE_IFREQ
  ifreq = *ifr;
  
  strioctl.ic_cmd = SIOCGIFNETMASK;
  strioctl.ic_dp  = (char *)&ifreq;
  strioctl.ic_len = sizeof(struct ifreq);
  if (ioctl(sock, I_STR, &strioctl) < 0)
    DEBUG(0,( "Failed I_STR/SIOCGIFNETMASK: %s\n", strerror(errno)));
  else
    *if_nmask = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr;
#else
  if (ioctl(sock, SIOCGIFNETMASK, ifr) < 0)
    DEBUG(0,("SIOCGIFNETMASK failed\n"));
  else
    *if_nmask = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;
#endif
  
  /* Close up shop */
  (void) close(sock);
  
  DEBUG(2,("Broadcast address for %s = %s\n", ifr->ifr_name,
        inet_ntoa(*if_bcast)));
  DEBUG(2,("Netmask for %s = %s\n", ifr->ifr_name,
        inet_ntoa(*if_nmask)));
  
  return;
}  /* get_broadcast */


/****************************************************************************
  true if two netbios names are equal
****************************************************************************/
BOOL name_equal(char *s1,char *s2)
{
  char *p1, *p2;
  while (*s1 && *s2 && (*s1!=' ') && (*s2!=' ')) {
    p1 = s1;
    p2 = s2; /* toupper has side effects as a macro */
    if (toupper(*p1) != toupper(*p2))
      return(False);
    s1++;
    s2++;
  }
  if ((*s1 == 0 || *s1 == ' ') && (*s2 == 0 || *s2 == ' '))    
    return(True);  
  else
    return(False);
}


/****************************************************************************
do a netbios name query to find someones IP
****************************************************************************/
BOOL name_query(char *inbuf,char *outbuf,char *name,
		struct in_addr to_ip,struct in_addr *ip,int maxtime,
		void (*fn)())
{
  static uint16 name_trn_id = 0x6242;
  char *p;
  BOOL saved_swap = NeedSwap;
  BOOL found = False;
  time_t start_time = time(NULL);
  time_t this_time = start_time;

  NeedSwap = !big_endian();

  DEBUG(2,("Querying name %s\n",name));

  name_trn_id += getpid() % 100;
  name_trn_id = (name_trn_id % 0x7FFF);

  SSVAL(outbuf,0,name_trn_id);
  CVAL(outbuf,2) = 0x1;
  CVAL(outbuf,3) = (1<<4) | 0x0;
  SSVAL(outbuf,4,1);
  SSVAL(outbuf,6,0);
  SSVAL(outbuf,8,0);
  SSVAL(outbuf,10,0);  
  p = outbuf+12;
  name_mangle(name,p);
  p += name_len(p);
  SSVAL(p,0,0x20);
  SSVAL(p,2,0x1);
  p += 4;

  DEBUG(2,("Sending name query for %s\n",name));

  show_nmb(outbuf);
  if (!send_nmb(outbuf,nmb_len(outbuf), &to_ip))
    {
      NeedSwap = saved_swap;
      return False;
    }

  while (!found && this_time - start_time <= maxtime)
    {
      this_time = time(NULL);

      if (receive_nmb(inbuf,1))
	{     
	  int rec_name_trn_id = SVAL(inbuf,0);
	  int opcode = (CVAL(inbuf,2) >> 3) & 0xF;
	  int nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
	  int rcode = CVAL(inbuf,3) & 0xF;
	  show_nmb(inbuf);

	  /* is it a positive response to our request? */
	  if ((rec_name_trn_id == name_trn_id) && 
	      opcode == 0 && (nm_flags&~0x28) == 0x50 && rcode == 0)
	    {
	      found = True;
	      DEBUG(2,("Got a positive name query response from %s\n",
		       inet_ntoa(lastip)));
	      memcpy((char *)ip,inbuf + 12 + name_len(inbuf+12) + 12,4);
	    }
	  else
	    {
	      if (fn)
		fn(inbuf,outbuf+nmb_len(outbuf));
	    }
	}
    }
  NeedSwap = saved_swap;
  return(found);
}

/****************************************************************************
do a netbios name status to a host
****************************************************************************/
BOOL name_status(char *inbuf,char *outbuf,char *name)
{
  int maxtime = 5;
  static uint16 name_trn_id = 0x4262;
  char *p;
  BOOL saved_swap = NeedSwap;
  BOOL found = False;
  time_t start_time = time(NULL);
  time_t this_time = start_time;

  NeedSwap = !big_endian();

  DEBUG(1,("Querying status of name %s\n",name));

  name_trn_id += getpid() % 100;
  name_trn_id = (name_trn_id % 10000);

  SSVAL(outbuf,0,name_trn_id);
  CVAL(outbuf,2) = 0;
  CVAL(outbuf,3) = (1<<4) | 0x0;
  SSVAL(outbuf,4,1);
  SSVAL(outbuf,6,0);
  SSVAL(outbuf,8,0);
  SSVAL(outbuf,10,0);  
  p = outbuf+12;
  name_mangle(name,p);
  p += name_len(p);
  SSVAL(p,0,0x21);
  SSVAL(p,2,0x1);
  p += 4;

  DEBUG(2,("Sending name status query for %s\n",name));

  show_nmb(outbuf);
  if (!send_nmb(outbuf,nmb_len(outbuf), &bcast_ip))
    {
      NeedSwap = saved_swap;
      return False;
    }

  while (!found && this_time - start_time <= maxtime)
    {
      this_time = time(NULL);

      if (receive_nmb(inbuf,1))
	{
	  int rec_name_trn_id = SVAL(inbuf,0);
	  int opcode = (CVAL(inbuf,2) >> 3) & 0xF;
	  int nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
	  int rcode = CVAL(inbuf,3) & 0xF;
	  show_nmb(inbuf);

	  /* is it a positive response to our request? */
	  if ((rec_name_trn_id == name_trn_id) && 
	      (opcode == 0 && nm_flags == 0x40 && rcode == 0))
	    {
	      char *p = inbuf + 12 + name_len(inbuf+12) + 10;
	      int num_names = CVAL(p,0);
	      found = True;
	      DEBUG(0,("Got a positive node status response from %s\n",
		       inet_ntoa(lastip)));

	      DEBUG(0,("received %d names\n",num_names));
	      p += 1;
	      while (num_names--)
		{
		  char qname[100];
		  char flags[20]="";
		  strcpy(qname,p);
		  p += 16;
		  if (p[0] & 0x80) strcat(flags,"<GROUP> ");
		  if (p[0] & 0x60 == 0) strcat(flags,"B ");
		  if (p[0] & 0x60 == 1) strcat(flags,"P ");
		  if (p[0] & 0x60 == 2) strcat(flags,"M ");
		  if (p[0] & 0x60 == 3) strcat(flags,"_ ");
		  if (p[0] & 0x10) strcat(flags,"<DEREGISTERING> ");
		  if (p[0] & 0x08) strcat(flags,"<CONFLICT> ");
		  if (p[0] & 0x04) strcat(flags,"<ACTIVE> ");
		  if (p[0] & 0x02) strcat(flags,"<PERMANENT> ");
		  
		  DEBUG(0,("\t%s\t%s\n",qname,flags));
		  p+=2;
		}
	    }
	}
    }

  if (!found)
    DEBUG(0,("No response (this is not unusual)\n"));
  NeedSwap = saved_swap;
  return(found);
}


/****************************************************************************
put up a yes/no prompt
****************************************************************************/
BOOL yesno(char *p)
{
  pstring ans;
  printf("%s",p);

  if (!fgets(ans,sizeof(ans)-1,stdin))
    return(False);

  if (*ans == 'y' || *ans == 'Y')
    return(True);

  return(False);
}

/****************************************************************************
read a line from a file with possible \ continuation chars. 
Blanks at the start or end of a line are stripped.
The string will be allocated if s2 is NULL
****************************************************************************/
char *fgets_slash(char *s2,int maxlen,FILE *f)
{
  char *s=s2;
  int len = 0;
  int c;
  BOOL start_of_line = True;

  if (feof(f))
    return(NULL);

  if (!s2)
    {
      maxlen = MIN(maxlen,8);
      s = (char *)Realloc(s,maxlen);
    }

  if (!s || maxlen < 2) return(NULL);

  *s = 0;

  while (len < maxlen-1)
    {
      c = getc(f);
      switch (c)
	{
	case '\r':
	  break;
	case '\n':
	  while (len > 0 && s[len-1] == ' ')
	    {
	      s[--len] = 0;
	    }
	  if (len > 0 && s[len-1] == '\\')
	    {
	      s[--len] = 0;
	      start_of_line = True;
	      break;
	    }
	  return(s);
	case EOF:
	  if (len <= 0 && !s2) 
	    free(s);
	  return(len>0?s:NULL);
	case ' ':
	  if (start_of_line)
	    break;
	default:
	  start_of_line = False;
	  s[len++] = c;
	  s[len] = 0;
	}
      if (!s2 && len > maxlen-3)
	{
	  maxlen *= 2;
	  s = (char *)Realloc(s,maxlen);
	  if (!s) return(NULL);
	}
    }
  return(s);
}



/****************************************************************************
set the length of a file from a filedescriptor.
Returns 0 on success, -1 on failure.
****************************************************************************/
int set_filelen(int fd, long len)
{
/* According to W. R. Stevens advanced UNIX prog. Pure 4.3 BSD cannot
   extend a file with ftruncate. Provide alternate implementation
   for this */

#if FTRUNCATE_CAN_EXTEND
  return ftruncate(fd, len);
#else
  struct stat st;
  char c = 0;
  long currpos = lseek(fd, 0L, SEEK_CUR);

  if(currpos < 0)
    return -1;
  /* Do an fstat to see if the file is longer than
     the requested size (call ftruncate),
     or shorter, in which case seek to len - 1 and write 1
     byte of zero */
  if(fstat(fd, &st)<0)
    return -1;

  if(st.st_size == len)
    return 0;
  if(st.st_size > len)
    return ftruncate(fd, len);

  if(lseek(fd, len-1, SEEK_SET) != len -1)
    return -1;
  if(write(fd, &c, 1)!=1)
    return -1;
  /* Seek to where we were */
  lseek(fd, currpos, SEEK_SET);
  return 0;
#endif
}


/****************************************************************************
return the byte checksum of some data
****************************************************************************/
int byte_checksum(char *buf,int len)
{
  unsigned char *p = (unsigned char *)buf;
  int ret = 0;
  while (len--)
    ret += *p++;
  return(ret);
}

/* some useful string operations. */

/**************************************************************************
Replace n characters in str1 with str2, starting at offset start in str1.
If strlen(str2) is greater than n, it is up to the caller to ensure that 
there is enough space in str1.
**************************************************************************/
void replacestr(char *str1, char *str2, int start, int n)
{
   int  len;
   char *tstr;

   len = strlen(str2);
   tstr = str1;

   if (len < n)                /* ie., closing up the string */
      closestr(str1, start, n - len);
   else
      if (len > n)             /* ie., opening up the string */
         openstr(str1, start, len - n);

   str1 += start;
   while (*str2)
      *str1++ = *str2++;
}

/***********************************************************************
Open a gap in s, n chars wide at offset start.
***********************************************************************/
void openstr(char *s, int start, int n)
{
   char *src;
   char *dest;
   char *tptr;
   int  len;

   if (n > 0)
      if ((tptr = s) != NULL)
      {
         len = strlen(s);
         if (start >= 0 && start < len)
         {
            s += start;
            src = s + len;
            dest = src + n;
            while (src != s)
               *dest-- = *src--;
            *dest = *src;
         }
      }
}

/***********************************************************************
Close up s by n chars, at offset start.
***********************************************************************/
void closestr(char *s, int start, int n)
{
   char *src;
   char *dest;
   int  len;

   if (n > 0)
      if ((src = dest = s) != NULL)
      {
         len = strlen(s);
         if (start >= 0 && start < len - n)
         {
            src += start + n;
            dest += start;
  
            while (*src)
               *dest++ = *src++;
            *dest = '\0';
         }
      }
}


/****************************************************************************
apply a function to upper/lower case combinations
of a string and return true if one of them returns true.
try up to N uppercase letters.
offset is the first char to try and change (start with 0)
it assumes the string starts lowercased
****************************************************************************/
BOOL string_combinations(char *s,int offset,BOOL (*fn)(),int N)
{
  int len = strlen(s);
  int i;
  if (N <= 0 || offset >= len)
    return(fn(s));
  for (i=offset;i<len;i++)
    {      
      char c = s[i];
      if (string_combinations(s,i+1,fn,N-1))
	return(True);
      if (islower(c))
	s[i] = toupper(c);
      if (string_combinations(s,i+1,fn,N-1))
	return(True);
      s[i] = c;
    }
  return(False);
}


/****************************************************************************
apply a function to all upper/lower case combinations
of a string and return true if one of them returns true.
Don't try more than 2^N combinations
****************************************************************************/
BOOL string_combinations_all(char *s,BOOL (*fn)(),int N)
{
  int limit;
  int j,i;

  N = MIN(N,strlen(s));
  limit = (1<<N);

  for (i=0;i<limit;i++)
    {
      for (j=0;j<N;j++)
	{
	  if (i & (1<<j))
	    {
	      if (islower(s[j]))
		s[j] = toupper(s[j]);
	    }
	  else
	    {
	      if (isupper(s[j]))
		s[j] = tolower(s[j]);
	    }
	}
      if (fn(s))
	return(True);
    }
  return(False);
}
      

#ifdef HPUX
/****************************************************************************
this is a version of setbuffer() for those machines that only have setvbuf
****************************************************************************/
void setbuffer(FILE *f,char *buf,int bufsize)
{
  setvbuf(f,buf,_IOFBF,bufsize);
}
#endif


/****************************************************************************
parse out a directory name from a path name. Assumes dos style filenames.
****************************************************************************/
char *dirname_dos(char *path,char *buf)
{
  char *p = strrchr(path,'\\');

  if (!p)
    strcpy(buf,path);
  else
    {
      *p = 0;
      strcpy(buf,path);
      *p = '\\';
    }

  return(buf);
}


/****************************************************************************
parse out a filename from a path name. Assumes dos style filenames.
****************************************************************************/
char *filename_dos(char *path,char *buf)
{
  char *p = strrchr(path,'\\');

  if (!p)
    strcpy(buf,path);
  else
    strcpy(buf,p+1);

  return(buf);
}


struct
{
  int thresh;
  int count;
  int tsize;
  int time;
}
time_stats[] = {
  {0,0,0,0},
  {1,0,0,0},
  {5,0,0,0},
  {10,0,0,0},
  {50,0,0,0},
  {200,0,0,0},
  {500,0,0,0},
  {-1,0,0,0}};


/****************************************************************************
stats recording
****************************************************************************/
void stats_record(int size,int t)
{
  int bin=1;

  while (time_stats[bin].thresh != -1)
    {
      if (size/1024 < time_stats[bin].thresh)
	break;
      bin++;
    }

  bin--;

  time_stats[bin].time += t;
  time_stats[bin].tsize += size;
  time_stats[bin].count++;
}

/****************************************************************************
stats reporting
****************************************************************************/
void stats_report(void)
{
  int bin=0;
  while (time_stats[bin].thresh != -1)
    {
      if (time_stats[bin].count > 0) 
	DEBUG(0,("More than %3dk (%d)   %6d times    %g secs. %g k/sec\n",
	      time_stats[bin].thresh,
	      time_stats[bin].tsize/(1024*time_stats[bin].count),
	      time_stats[bin].count,time_stats[bin].time/1.0e6,
	      (time_stats[bin].tsize/1024.0)/(time_stats[bin].time/1.0e6)));
      bin++;
    }    
}

/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p,int size)
{
  void *ret=NULL;
  if (!p)
    ret = (void *)malloc(size);
  else
    ret = (void *)realloc(p,size);

  if (!ret)
    DEBUG(0,("Memory allocation error: failed to expand to %d bytes\n",size));

  return(ret);
}


/****************************************************************************
check if it's a null mtime
****************************************************************************/
BOOL null_mtime(time_t mtime)
{
  if (mtime == 0 || mtime == 0xFFFFFFFF)
    return(True);
  return(False);
}


/****************************************************************************
set the time on a file
****************************************************************************/
BOOL set_filetime(char *fname,time_t mtime)
{
  struct utimbuf times;

  if (null_mtime(mtime)) return(True);

  times.modtime = times.actime = mtime;

  return(utime(fname,&times) == 0);
}


#ifdef NOSTRDUP
/****************************************************************************
duplicate a string
****************************************************************************/
char *strdup(char *s)
{
  char *ret = NULL;
  if (!s) return(NULL);
  ret = (char *)malloc(strlen(s)+1);
  if (!ret) return(NULL);
  strcpy(ret,s);
  return(ret);
}
#endif


/****************************************************************************
  Signal handler for SIGPIPE (write on a disconnected socket) 
****************************************************************************/
void Abort(void )
{
  DEBUG(0,("Abort called. Probably got SIGPIPE\n"));
  exit(1);
}


#ifdef REPLACE_STRLEN
/****************************************************************************
a replacement strlen() that returns int for solaris
****************************************************************************/
int Strlen(char *s)
{
  int ret=0;
  if (!s) return(0);
  while (*s++) ret++;
  return(ret);
}
#endif


/****************************************************************************
return a time at the start of the current month
****************************************************************************/
time_t start_of_month(void)
{
  time_t t = time(NULL);
  struct tm *t2;
  
  t2 = gmtime(&t);
  
  t2->tm_mday = 1;
  t2->tm_hour = 0;
  t2->tm_min = 0;
  t2->tm_sec = 0;
  
#ifdef sun386
  return(timelocal(t2));
#else
  return(mktime(t2));
#endif
}


/*******************************************************************
  check for a sane unix date
********************************************************************/
BOOL sane_unix_date(time_t unixdate)
{
  struct tm t,today;
  time_t t_today = time(NULL);
  
  t = *(LocalTime(&unixdate,LOCAL_TO_GMT));
  today = *(LocalTime(&t_today,LOCAL_TO_GMT));
  
  if (t.tm_year < 80)
    return(False);
  
  if (t.tm_year >  today.tm_year)
    return(False);
  
  if (t.tm_year == today.tm_year &&
      t.tm_mon > today.tm_mon)
    return(False);
  
  
  if (t.tm_year == today.tm_year &&
      t.tm_mon == today.tm_mon &&
      t.tm_mday > (today.tm_mday+1))
    return(False);
  
  return(True);
}



#ifdef NO_FTRUNCATE
 /*******************************************************************
ftruncate for operating systems that don't have it
********************************************************************/
int ftruncate(int f,long l)
{
      struct  flock   fl;

      fl.l_whence = 0;
      fl.l_len = 0;
      fl.l_start = l;
      fl.l_type = F_WRLCK;
      return fcntl(f, F_FREESP, &fl);
}
#endif


/****************************************************************************
register a netbios name on the net.
****************************************************************************/
BOOL register_name(name_struct *name,struct in_addr *destip,void (*fn)())
{
  int count;
  char *p;
  char *inbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  char *outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
  BOOL saved_swap = NeedSwap;
  static uint16 name_trn_id = 0;

  if (name_trn_id == 0) name_trn_id = getpid() + (time(NULL) % 1000);

  NeedSwap = !big_endian();

  if ((inbuf == NULL) || (outbuf == NULL)) 
    {
      NeedSwap = saved_swap;
      return False;
    }

  name_trn_id++;

  DEBUG(1,("Registering name %s (%s) nb_flags=0x%x\n",
	name->name, inet_ntoa(name->ip) ,name->nb_flags));

  SSVAL(outbuf,0,name_trn_id);
  CVAL(outbuf,2) = (0x5<<3) | 0x1;
  CVAL(outbuf,3) = (1<<4) | 0x0;
  SSVAL(outbuf,4,1);
  SSVAL(outbuf,6,0);
  SSVAL(outbuf,8,0);
  SSVAL(outbuf,10,1);  
  p = outbuf+12;
  name_mangle(name->name,p);
  p += name_len(p);
  SSVAL(p,0,0x20);
  SSVAL(p,2,0x1);
  p += 4;
  CVAL(p,0) = 0xC0;
  CVAL(p,1) = 12;
  p += 2;
  SSVAL(p,0,0x20);
  SSVAL(p,2,0x1);
  SIVAL(p,4,0); /* my own ttl */
  SSVAL(p,8,6);
  CVAL(p,10) = name->nb_flags;
  CVAL(p,11) = 0;
  p += 12;
  memcpy(p,(char *)&(name->ip),4);
  p += 4;

  count = 3;
  while (count--)
    {
      DEBUG(3,("Sending reg request for %s at (%s)\n",
	    name->name,inet_ntoa(name->ip)));


      show_nmb(outbuf);
      if (!send_nmb(outbuf,nmb_len(outbuf),destip))
	{
	  free(inbuf);free(outbuf);
	  NeedSwap = saved_swap;
	  return False;
	}

      if (receive_nmb(inbuf,3))
	{
          int rec_name_trn_id = SVAL(inbuf,0);
	  int opcode = CVAL(inbuf,2) >> 3;
	  int nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
	  int rcode = CVAL(inbuf,3) & 0xF;

	  /* is it a negative response to our request? */
	  if ((rec_name_trn_id == name_trn_id) && 
              (opcode == 21 && nm_flags == 0x58 && rcode != 0 && rcode != 7))
	    {
	      char qname[100];
	      name_extract(inbuf,12,qname);
	      if (name_equal(qname,name->name))
		{
		  DEBUG(0,("Someone (%s) gave us a negative name regregistration response!\n",
			inet_ntoa(lastip)));
		  free(inbuf);free(outbuf);
		  NeedSwap = saved_swap;
		  return False;
		}
	      else
		{
		  DEBUG(0,("%s gave negative name regregistration for %s??\n",
			inet_ntoa(lastip),qname));
		}		  
	    }	  
	  
	  /* it's something else - process it anyway, unless we are running
	   as a daemon. This is necessary as we may have been started by a 
	   name query of our name arriving on port 137 (often happens) */
	  if (fn)
	    {
	      show_nmb(inbuf);
	      fn(inbuf,outbuf + nmb_len(outbuf));
	    }
	}
    }

  /* increment the packet id */
  name_trn_id++;

  /* don't demand on groups */
  if ((name->nb_flags & 0x80) != 0)
    {
      free(inbuf);free(outbuf);
      NeedSwap = saved_swap;
      return(True);
    }

  /* no negative replies, send a demand */
  p = outbuf;
  SSVAL(outbuf,0,name_trn_id);
  CVAL(outbuf,2) = (0x5<<3);
  CVAL(outbuf,3) = (1<<4) | 0x0;
  SSVAL(outbuf,4,1);
  SSVAL(outbuf,6,0);
  SSVAL(outbuf,8,0);
  SSVAL(outbuf,10,1);  
  p = outbuf+12;
  name_mangle(name->name,p);
  p += name_len(p);
  SSVAL(p,0,0x20);
  SSVAL(p,2,0x1);
  p += 4;
  CVAL(p,0) = 0xC0;
  CVAL(p,1) = 12;
  p += 2;
  SSVAL(p,0,0x20);
  SSVAL(p,2,0x1);
  SIVAL(p,4,0); /* my own ttl */
  SSVAL(p,8,6);
  CVAL(p,10) = name->nb_flags;
  CVAL(p,11) = 0;
  p += 12;
  memcpy(p,(char *)&(name->ip),4);
  p += 4;
  
  DEBUG(3,("Sending reg demand for %s at (%s)\n",
	name->name,inet_ntoa(name->ip)));

  show_nmb(outbuf);

  {
    BOOL ret = send_nmb(outbuf,nmb_len(outbuf),destip);

    free(inbuf);free(outbuf);
  
    NeedSwap = saved_swap;
    return(ret);
  }
}


/****************************************************************************
get my own name and IP
****************************************************************************/
BOOL get_myname(char *myname,struct in_addr *ip)
{
  struct hostent *hp;
  pstring myhostname="";

  /* get my host name */
  if (gethostname(myhostname, sizeof(myhostname)) == -1) 
    {
      DEBUG(0,("gethostname failed\n"));
      return False;
    } 

  /* get host info */
  if ((hp = Get_Hostbyname(myhostname)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host %s.\n",myhostname));
      return False;
    }

  if (myname)
    {
      /* split off any parts after an initial . */
      char *p = strchr(myhostname,'.');
      if (p) *p = 0;

      strcpy(myname,myhostname);
    }

  if (ip)
    memcpy((char *)ip,(char *)hp->h_addr,4);

  return(True);
}


/****************************************************************************
true if two IP addresses are equal
****************************************************************************/
BOOL ip_equal(struct in_addr *ip1,struct in_addr *ip2)
{
  char *p1=(char *)ip1;
  char *p2=(char *)ip2;
  int l = sizeof(*ip1);
  while (l--)
    if (*p1++ != *p2++)
      return(False);
  return(True);
}


/****************************************************************************
get info about the machine and OS
****************************************************************************/
void get_machine_info(void)
{
#if !HAVE_SYSCONF

  /* assume it doesn't have saved uids and gids */
  machine_info.have_saved_ids = False;

#else

  machine_info.have_saved_ids = (sysconf(_POSIX_SAVED_IDS) == 1);

#endif

  DEBUG(3,("Sysconfig:\n"));
  DEBUG(3,("\tsaved_ids = %d\n",machine_info.have_saved_ids));
  DEBUG(3,("\n"));
}


/****************************************************************************
construct a netbios datagram. The length of the construct is returned
****************************************************************************/
int construct_datagram(char *buffer, int data_len, int msg_type, int flags, 
		       struct in_addr *source_ip, int source_port, 
		       char *source_name, char *dest_name)
{
  static int dgm_id = -1;
  int dgm_length = data_len;
  char *p;
  BOOL saved_swap = NeedSwap;
  NeedSwap = !big_endian();

  /* initialise the datagram id */
  if (dgm_id < 0)
    dgm_id = (getpid() * 10) % 16000;

  CVAL(buffer,0) = msg_type;
  CVAL(buffer,1) = flags | 0x2; /* first fragment */
  SSVAL(buffer,2,dgm_id++);
  memcpy(buffer + 4,(char *)source_ip,4);
  SSVAL(buffer,8,source_port);
  SSVAL(buffer,12,0);
  p = buffer + 14;
  name_mangle(source_name,p);
  dgm_length += name_len(p);
  p += name_len(p);
  name_mangle(dest_name,p);
  dgm_length += name_len(p);
  p += name_len(p);
  SSVAL(buffer,10,dgm_length);
  
  NeedSwap = saved_swap;

  return((int)(p - buffer));
}


/****************************************************************************
open a socket of the specified type, port and address for incoming data
****************************************************************************/
int open_socket_in(int type, int port)
{
  struct hostent *hp;
  struct sockaddr_in sock;
  pstring host_name;
  int res;

  /* get my host name */
  if (gethostname(host_name, sizeof(host_name)) == -1) 
    { DEBUG(0,("gethostname failed\n")); return -1; } 

  /* get host info */
  if ((hp = Get_Hostbyname(host_name)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",host_name));
      return -1;
    }
  
  memset((char *)&sock, 0, sizeof(sock));
  memcpy((char *)&sock.sin_addr,(char *)hp->h_addr, hp->h_length);
  sock.sin_port = htons( port );
  sock.sin_family = hp->h_addrtype;
  sock.sin_addr.s_addr = INADDR_ANY;
  res = socket(hp->h_addrtype, type, 0);
  if (res == -1) 
    { DEBUG(0,("socket failed\n")); return -1; }

#ifdef SO_REUSEADDR
  {
    int one = 1;
    if (setsockopt(res, SOL_SOCKET, SO_REUSEADDR,(char *)&one, sizeof(one)) == -1)
      { DEBUG(3,("setsockopt(REUSEADDR) failed - ignored\n")); }
  }
#endif
  
  /* now we've got a socket - we need to bind it */
  if (bind(res, (struct sockaddr * ) &sock,sizeof(sock)) < 0) 
    { 
      if (port < 1000)
	DEBUG(0,("bind failed on port %d\n",port)); 
      close(res); 

      if (port >= 1000 && port < 9000)
	return(open_socket_in(type,port+1));

      return(-1); 
    }
  DEBUG(1,("bind succeeded on port %d\n",port));

  return res;
}


/****************************************************************************
create an outgoing socket
****************************************************************************/
int open_socket_out(struct in_addr *addr, int port )
{
  struct sockaddr_in sock_out;
  int res;

  /* create a socket to write to */
  res = socket(PF_INET, SOCK_STREAM, 0);
  if (res == -1) 
    { DEBUG(0,("socket error\n")); return -1; }
  
  memset((char *)&sock_out, 0, sizeof(sock_out));
  memcpy((char *)&sock_out.sin_addr,(char *)addr,4);
  
  sock_out.sin_port = htons( port );
  sock_out.sin_family = PF_INET;

  DEBUG(3,("Connecting to %s at port %d\n",inet_ntoa(*addr),port));
  
  /* and connect it to the destination */
  if (connect(res,(struct sockaddr *)&sock_out,sizeof(sock_out))<0)
    { DEBUG(0,("connect error: %s\n",strerror(errno))); close(res); return -1; }

  return res;
}


/****************************************************************************
interpret a protocol description string, with a default
****************************************************************************/
int interpret_protocol(char *str,int def)
{
  if (strequal(str,"NT1"))
    return(PROTOCOL_NT1);
  if (strequal(str,"LANMAN2"))
    return(PROTOCOL_LANMAN2);
  if (strequal(str,"LANMAN1"))
    return(PROTOCOL_LANMAN1);
  if (strequal(str,"CORE"))
    return(PROTOCOL_CORE);
  if (strequal(str,"COREPLUS"))
    return(PROTOCOL_COREPLUS);
  if (strequal(str,"CORE+"))
    return(PROTOCOL_COREPLUS);
  
  DEBUG(0,("Unrecognised protocol level %s\n",str));
  
  return(def);
}

/****************************************************************************
interpret a security level
****************************************************************************/
int interpret_security(char *str,int def)
{
  if (strequal(str,"USER"))
    return(SEC_USER);
  if (strequal(str,"SHARE"))
    return(SEC_SHARE);
  
  DEBUG(0,("Unrecognised security level %s\n",str));
  
  return(def);
}


/****************************************************************************
interpret an internet address or name into an IP address in 4 byte form
****************************************************************************/
unsigned long interpret_addr(char *str)
{
  struct hostent *hp;
  unsigned long res;

  /* if it's in the form of an IP address then get the lib to interpret it */
  if (isdigit(str[0]))
    return(inet_addr(str));

  /* otherwise assume it's a network name of some sort and use Get_Hostbyname */
  if ((hp = Get_Hostbyname(str)) == 0) 
    {
      DEBUG(0,( "Get_Hostbyname: Unknown host. %s\n",str));
      return 0;
    }

  memcpy((char *)&res,(char *)hp->h_addr,sizeof(res));
  return(res);
}

/****************************************************************************
interpret an 8 byte "filetime" structure to a time_t
It's originally in "100ns units since jan 1st 1601"
****************************************************************************/
time_t interpret_filetime(char *p)
{
  double d;

  /* use double precision arithmetic */

  /* this gives us seconds since jan 1st 1601 (approx) */
  d = (IVAL(p,4)*256.0 + CVAL(p,3)) * (1.0e-7 * (1<<24));
 
  /* now adjust by 369 years to make the secs since 1970 */
  d -= 369.0*365.25*24*60*60;

  /* and a fudge factor as we got it wrong by a few days */
  d += (3*24*60*60 - 60*60 + 2);

  return((time_t)d);
}

/****************************************************************************
interpret a short filename structure
The length of the structure is returned
****************************************************************************/
int interpret_short_filename(char *p,file_info *finfo)
{
  finfo->mode = CVAL(p,21);

  finfo->mtime = finfo->atime = finfo->ctime = make_unix_date(p+22);
  finfo->size = SVAL(p,26) + (SVAL(p,28)<<16);
  strcpy(finfo->name,p+30);
  
  return(DIR_STRUCT_SIZE);
}

/****************************************************************************
interpret a long filename structure - this is mostly guesses at the moment
The length of the structure is returned
The structure of a long filename depends on the info level. 260 is used
by NT and 2 is used by OS/2
****************************************************************************/
int interpret_long_filename(int level,char *p,file_info *finfo)
{
  if (finfo)
    *finfo = def_finfo;

  switch (level)
    {
    case 260: /* NT uses this, but also accepts 2 */
      if (finfo)
	{
	  strcpy(finfo->name,p+94);
	  finfo->size = IVAL(p,40);
	  finfo->mode = CVAL(p,56);
	  finfo->mtime = interpret_filetime(p+24); 
	}
      return(SVAL(p,0));

    case 2: /* this is what OS/2 uses */
      if (finfo)
	{
	  strcpy(finfo->name,p+31);
	  finfo->size = IVAL(p,16);
	  finfo->mode = CVAL(p,24);
	  finfo->atime = make_unix_date2(p+8);
	  finfo->mtime = make_unix_date2(p+12);
	}
      return(32 + CVAL(p,30));

    case 1: /* OS/2 understands this */
      if (finfo)
	{
	  strcpy(finfo->name,p+27);
	  finfo->size = IVAL(p,16);
	  finfo->mode = CVAL(p,24);
	  finfo->ctime = make_unix_date2(p+4);
	  finfo->atime = make_unix_date2(p+8);
	  finfo->mtime = make_unix_date2(p+12);
	}
      return(28 + CVAL(p,26));
    }

  DEBUG(1,("Unknown long filename format %d\n",level));
  return(SVAL(p,0));
}


/****************************************************************************
run a command via system() using smbrun
****************************************************************************/
int smbrun(char *cmd)
{
  int ret;
  pstring syscmd;

  if (getuid() == geteuid() && getgid() == getegid())
    return(system(cmd));

#ifndef SMBRUN
  DEBUG(0,("WARNING - can't find smbrun! is your Makefile OK?\n"));
  return(-1);
#endif

  sprintf(syscmd,"%s \"%s\"",SMBRUN,cmd);

  DEBUG(5,("smbrun - running %s ",syscmd));
  ret = system(syscmd);
  DEBUG(5,("gave %d\n",ret));
  return(ret);
}

/****************************************************************************
internals of Get_Pwnam wrapper
****************************************************************************/
struct passwd *_Get_Pwnam(char *s)
{
  struct passwd *ret;

  ret = getpwnam(s);
  if (ret)
    {
#ifdef GETPWANAM
      struct passwd_adjunct *pwret;
      pwret = getpwanam(s);
      if (pwret)
	{
	  free(ret->pw_passwd);
	  ret->pw_passwd = pwret->pwa_passwd;
	}
#endif
    }

  return(ret);
}


/****************************************************************************
a wrapper for getpwnam() that tries with all lower and all upper case 
if the initial name fails. Also tried with first letter capitalised
Note that this changes user!
****************************************************************************/
struct passwd *Get_Pwnam(char *user)
{
  fstring user2;

  struct passwd *ret;  

  if (!user || !(*user))
    return(NULL);

  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  strcpy(user2,user);

  strlower(user);
  ret = _Get_Pwnam(user);
  if (ret)  return(ret);

  strupper(user);
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* try with first letter capitalised */
  if (strlen(user) > 1)
    strlower(user+1);  
  ret = _Get_Pwnam(user);
  if (ret) return(ret);

  /* restore the original name */
  strcpy(user,user2);

  return(NULL);
}

/****************************************************************************
a wrapper for gethostbyname() that tries with all lower and all upper case 
if the initial name fails
****************************************************************************/
struct hostent *Get_Hostbyname(char *name)
{
  char *name2 = strdup(name);
  struct hostent *ret;

  if (!name2)
    {
      DEBUG(0,("Memory allocation error in Get_Hostbyname! panic\n"));
      exit(0);
    }

  ret = gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all lowercase */
  strlower(name2);
  ret = gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }

  /* try with all uppercase */
  strupper(name2);
  ret = gethostbyname(name2);
  if (ret != NULL)
    {
      free(name2);
      return(ret);
    }
  
  /* nothing works :-( */
  free(name2);
  return(NULL);
}


/****************************************************************************
simple routines to do connection counting
****************************************************************************/
BOOL fcntl_lock(int fd,int op,int offset,int count,int type)
{
#if HAVE_FCNTL_LOCK
  struct flock lock;
  int ret;
  unsigned long mask = ((unsigned)1<<31);

  /* interpret negative counts as large numbers */
  if (count < 0)
    count &= ~mask;

  /* no negative offsets */
  offset &= ~mask;

  /* count + offset must be in range */
  while ((offset < 0 || (offset + count < 0)) && mask)
    {
      offset &= ~mask;
      mask = mask >> 1;
    }

  DEBUG(5,("fcntl_lock %d %d %d %d %d\n",fd,op,offset,count,type));

  lock.l_type = type;
  lock.l_whence = SEEK_SET;
  lock.l_start = offset;
  lock.l_len = count;
  lock.l_pid = 0;

  errno = 0;

  ret = fcntl(fd,op,&lock);

  if (errno != 0)
    DEBUG(3,("fcntl lock gave errno %d (%s)\n",errno,strerror(errno)));

  /* a lock query */
  if (op == F_GETLK)
    {
      if ((ret != -1) &&
	  (lock.l_type != F_UNLCK) && 
	  (lock.l_pid != 0) && 
	  (lock.l_pid != getpid()))
	{
	  DEBUG(3,("fd %d is locked by pid %d\n",fd,lock.l_pid));
	  return(True);
	}

      /* it must be not locked or locked by me */
      return(False);
    }

  /* a lock set or unset */
  if (ret == -1)
    {
      DEBUG(3,("lock failed at offset %d count %d op %d type %d (%s)\n",
	       offset,count,op,type,strerror(errno)));

      /* perhaps it doesn't support this sort of locking?? */
      if (errno == EINVAL)
	{
	  DEBUG(3,("locking not supported? returning True\n"));
	  return(True);
	}

      return(False);
    }

  /* everything went OK */
  DEBUG(5,("Lock call successful\n"));

  return(True);
#else
  return(False);
#endif
}

/****************************************************************************
try to get a write lock
****************************************************************************/
BOOL try_lock(int fd,int offset,int count)
{
  int tries = 3;
  while (tries--)
    {
      if (fcntl_lock(fd,F_SETLK,offset,count,F_WRLCK))
	return(True);

      sleep(1);
    }
  return(False);
}


/****************************************************************************
check if a process exists. Does this work on all unixes?
****************************************************************************/
BOOL process_exists(int pid)
{
  return(pid == getpid() || kill(pid,0) == 0);
}

/****************************************************************************
locking fread
****************************************************************************/
int lockfread(void *p,int pos,int size,int n,FILE *f)
{
  int ret;

  if (fseek(f,pos,SEEK_SET) != 0)
    {
      DEBUG(3,("lockfread couldn't seek to %d\n",pos));
      return(0);
    }

  if (!try_lock(fileno(f),pos,size*n))
    {
      DEBUG(3,("lockfread couldn't lock\n"));
      return(0);
    }

  ret = fread(p,size,n,f);

  fcntl_lock(fileno(f),F_SETLK,pos,size*n,F_UNLCK);
  return(ret);
}



#if (defined(SecureWare) && defined(SCO))
/* This is needed due to needing the nap() function but we don't want
   to include the Xenix libraries since that will break other things...
   BTW: system call # 0x0c28 is the same as calling nap() */
long nap(long milliseconds) {
  return syscall(0x0c28, milliseconds);
}
#endif

#ifdef NO_INITGROUPS
#include <sys/types.h>
#include <limits.h>
#include <grp.h>

#ifndef NULL
#define NULL (void *)0
#endif

/****************************************************************************
 some systems don't have an initgroups call 
****************************************************************************/
void initgroups(name,id)
char *name;
GID_TYPE id;
{
  GID_TYPE  grouplst[NGROUPS_MAX];
  int    i;
  struct group *g;
  char   *gr;

  grouplst[0] = id;
  i = 1;
  while (i < NGROUPS_MAX && 
	 ((g = (struct group *)getgrent()) != (struct group *)NULL)) 
    {
      if (g->gr_gid == id)
	continue;
      gr = g->gr_mem[0];
      while (gr && (*gr != (char)NULL)) {
	if (strcmp(name,gr) == 0) {
	  grouplst[i] = g->gr_gid;
	  i++;
	  gr = (char *)NULL;
	  break;
	}
	gr++;
      }
    }
  endgrent();
  setgroups(i,grouplst);
}
#endif


#if WRAP_MALLOC

/* undo the wrapping temporarily */
#undef malloc
#undef realloc
#undef free

/****************************************************************************
wrapper for malloc() to catch memory errors
****************************************************************************/
void *malloc_wrapped(int size,char *file,int line)
{
#ifdef xx_old_malloc
  void *res = xx_old_malloc(size);
#else
  void *res = malloc(size);
#endif
  DEBUG(3,("Malloc called from %s(%d) with size=%d gave ptr=0x%X\n",
	file,line,
	size,(unsigned int)res));
  return(res);
}

/****************************************************************************
wrapper for realloc() to catch memory errors
****************************************************************************/
void *realloc_wrapped(void *ptr,int size,char *file,int line)
{
#ifdef xx_old_realloc
  void *res = xx_old_realloc(ptr,size);
#else
  void *res = realloc(ptr,size);
#endif
  DEBUG(3,("Realloc\n"));
  DEBUG(3,("free called from %s(%d) with ptr=0x%X\n",
	file,line,
	(unsigned int)ptr));
  DEBUG(3,("Malloc called from %s(%d) with size=%d gave ptr=0x%X\n",
	file,line,
	size,(unsigned int)res));
  return(res);
}

/****************************************************************************
wrapper for free() to catch memory errors
****************************************************************************/
void free_wrapped(void *ptr,char *file,int line)
{
#ifdef xx_old_free
  xx_old_free(ptr);
#else
  free(ptr);
#endif
  DEBUG(3,("free called from %s(%d) with ptr=0x%X\n",
	file,line,(unsigned int)ptr));
  return;
}

/* and re-do the define for spots lower in this file */
#define malloc(size) malloc_wrapped(size,__FILE__,__LINE__)
#define realloc(ptr,size) realloc_wrapped(ptr,size,__FILE__,__LINE__)
#define free(ptr) free_wrapped(ptr,__FILE__,__LINE__)

#endif

#ifdef REPLACE_STRSTR
/****************************************************************************
Mips version of strstr doesn't seem to work correctly.
There is a #define in includes.h to redirect calls to this function.
****************************************************************************/
char *Strstr(char *s, char *p)
{
	int len = strlen(p);

	while ( *s != '\0' ) {
		if ( strncmp(s, p, len) == 0 )
		return s;
		s++;
	}

	return NULL;
}
#endif /* REPLACE_STRSTR */
