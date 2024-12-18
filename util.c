/* 
   Unix SMB/Netbios implementation.
   Version 1.5.
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

int DEBUGLEVEL = 0;

BOOL passive = False;

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

/* my IP, the broadcast IP and the Netmask */
struct in_addr myip;
struct in_addr bcast_ip;
struct in_addr Netmask;

int trans_num = 0;

/* this is set to true on a big_endian machine (like a sun sparcstation)
this means that all shorts and ints must be byte swapped before being
put in the buffer */
BOOL NeedSwap=False;

/*******************************************************************
write an debug message on the debugfile. The first arg is the debuglevel.
********************************************************************/
#ifdef __STDC__
void Debug(int debug_level, char *format_str, ...)
{
#else
void Debug(va_alist)
va_dcl
{
  int debug_level;
  char *format_str;
#endif

  va_list ap;
  
  if (!dbf) return;
  
#ifdef __STDC__
  va_start(ap, format_str);
#else
  va_start(ap);
  debug_level = va_arg(ap,int);
  format_str = va_arg(ap,char *);
#endif


  if (DEBUGLEVEL >= debug_level)
    {
      vfprintf(dbf,format_str,ap);
      fflush(dbf);
    }
  va_end(ap);
}


#ifdef STRING_DEBUG
#define LONG_LEN (sizeof(pstring)/3)
int mystrlen(char *s)
{
  int n=0;
  while (*s++)
    n++;
  if (n > LONG_LEN)
    Debug(0,"ERROR: long string\n");
  return n;
}

char *mystrchr(char *s,char c)
{
if (strlen(s) > LONG_LEN)
  Debug(0,"ERROR: long string\n");
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
  Debug(0,"ERROR: long string\n");

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
    Debug(0,"ERROR: long string\n");
  while ((*d++  = *s++));
}

char *mystrncpy(char *d,char *s,int n)
{
  if (strlen(s) > LONG_LEN)
    Debug(0,"ERROR: long string\n");
  while ((*d++  = *s++) && n--);
}

char *mystrcat(char *d,char *s)
{
  if (strlen(s) > LONG_LEN || strlen(d)>LONG_LEN)
    Debug(0,"ERROR: long string\n");
  d+=strlen(d);
  while ((*d++  = *s++));
}

void mymemcpy(char *d,char *s,int n)
{
if (n > LONG_LEN)
  Debug(0,"ERROR: long copy\n");
while (n--)
  *d++ = *s++;
}

void mymemset(char *d,char c,int n)
{
if (n > LONG_LEN)
  Debug(0,"ERROR: long set\n");
while (n--)
  *d++ = c;
}
#endif

/****************************************************************************
return the difference between local and GMT time
****************************************************************************/
int TimeDiff(void)
{
  static BOOL initialised = False;
  static int timediff = 0;

  if (!initialised)
    {
      time_t t=time(NULL);

/* There are three ways of getting the time difference between GMT and
   local time. Use the following defines to decide which your system
   can handle */
#ifdef HAVE_TIMELOCAL
      timediff = timelocal(gmtime(&t)) - t;
#else
#ifdef HAVE_TIMEZONE
      localtime(&t);
      timediff = timezone;
#else
      timediff = localtime(&t)->tm_gmtoff;
#endif
#endif
      Debug(3,"timediff=%d\n",timediff);
      initialised = True;
    }

return(timediff);
}

/****************************************************************************
try to optimise the timelocal call, it can be quite expenive on some machines
****************************************************************************/
time_t TimeLocal(struct tm *tm)
{
  return(mktime(tm) - TimeDiff());
}

/****************************************************************************
try to optimise the localtime call, it can be quite expenive on some machines
****************************************************************************/
struct tm *LocalTime(time_t *t)
{
  time_t t2 = *t;

  t2 += TimeDiff();

  return(gmtime(&t2));
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
exchange real and effective uids 
****************************************************************************/
void exchange_uids(void )
{
  if (geteuid() == 0 || getuid() == 0)
    {
      if (setreuid (geteuid (), getuid ()) ||
	  setregid (getegid (), getgid ()))
	{
	  Debug(0,"Cannot exchange real/effective uid or gid!\n");
      	  close_sockets();
	  exit(1);
	}
    }
}  

/****************************************************************************
  return the date and time as a string
****************************************************************************/
char *timestring(void )
{
  static char TimeBuf[100];
  time_t t;
  t = time(NULL);
  strftime(TimeBuf,100,"%D %r",LocalTime(&t));
  return(TimeBuf);
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
  strncpy(out, in, len);
  out += len;
  *out=0;
  in += len;
  }
}

/****************************************************************************
mangle a name into netbios format
****************************************************************************/
void name_mangle(char *In,char *Out)
{
  unsigned char *in = (unsigned char *)In;
  unsigned char *out = (unsigned char *)Out;
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
  
  *out = 0;
}

/*******************************************************************
  byte swap an object - the byte order of the object is reversed
********************************************************************/
void object_byte_swap(void *obj,int size)
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
}

/****************************************************************************
  byte swap a uint16
****************************************************************************/
uint16 uint16_byte_swap(uint16 x)
{
  uint16 res;
  res = x;
  object_byte_swap(&res,sizeof(res));
  return(res);
}

/****************************************************************************
  byte swap a uint32
****************************************************************************/
uint32 uint32_byte_swap(uint32 x)
{
  uint32 res;
  res = x;
  object_byte_swap(&res,sizeof(res));
  return(res);
}

/*******************************************************************
  check if a file exists
********************************************************************/
BOOL file_exist(char *fname)
{
  struct stat st;
  if (stat(fname,&st) != 0) 
    return(False);
  
  return(S_ISREG(st.st_mode));
}

/*******************************************************************
  check if a directory exists
********************************************************************/
BOOL directory_exist(char *dname)
{
  struct stat st;
  if (stat(dname,&st) != 0) 
    return(False);
  
  return(S_ISDIR(st.st_mode));
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
  create a 32 bit dos packed date/time from some parameters
********************************************************************/
uint32 make_dos_date(time_t unixdate)
{
  int32 ret;
  unsigned char *p;
  struct tm *t;

  t = LocalTime(&unixdate);
  p = (unsigned char *)&ret;
  p[0] = (t->tm_sec/2) + ((t->tm_min & 0x7) << 5);
  p[1] = (t->tm_min >> 3) + (t->tm_hour << 3);
  p[2] = t->tm_mday + (((t->tm_mon+1) & 0x7) << 5);
  p[3] = ((t->tm_mon+1) >> 3) + ((t->tm_year-80) << 1);

  return(ret);
}

/*******************************************************************
  create a 32 bit dos packed date/time from some parameters
********************************************************************/
uint32 make_dos_date2(time_t unixdate)
{
  int32 ret;
  unsigned char *p;
  struct tm *t;

  t = LocalTime(&unixdate);
  p = (unsigned char *)&ret;
  p[2] = (t->tm_sec/2) + ((t->tm_min & 0x7) << 5);
  p[3] = (t->tm_min >> 3) + (t->tm_hour << 3);
  p[0] = t->tm_mday + (((t->tm_mon+1) & 0x7) << 5);
  p[1] = ((t->tm_mon+1) >> 3) + ((t->tm_year-80) << 1);

  Debug(5,"yr=%d mon=%d hr=%d sec=%d\n",t->tm_year,t->tm_mon,t->tm_hour,t->tm_sec);

  return(ret);
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
time_t make_unix_date(uint32 dos_date)
{
  struct tm t;

  if (dos_date == 0) return(0);
  
  interpret_dos_date(dos_date,&t.tm_year,&t.tm_mon,
		     &t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec);
  t.tm_wday = 1;
  t.tm_yday = 1;
  t.tm_isdst = 0;
/*  Debug(4,"year=%d month=%d day=%d hr=%d min=%d sec=%d\n",t.tm_year,t.tm_mon,
	 t.tm_mday,t.tm_hour,t.tm_sec); */
  return (TimeLocal(&t));
}

/*******************************************************************
  create a unix date from a dos date
********************************************************************/
time_t make_unix_date2(uint32 dos_date)
{
  struct tm t;
  unsigned char *p = (unsigned char *)&dos_date;
  unsigned char c;

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
  Debug(4,"year=%d month=%d day=%d hr=%d min=%d sec=%d\n",t.tm_year,t.tm_mon,
	 t.tm_mday,t.tm_hour,t.tm_sec);
  return (TimeLocal(&t));
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
      *s = tolower(*s);
      s++;
    }
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
  while (*s)
    {
      *s = toupper(*s);
      s++;
    }
}

/****************************************************************************
  string replace
****************************************************************************/
void string_replace(char *s,char old,char new)
{
  while (*s)
    {
      if (old == *s)
	*s = new;
      s++;
    }
}

/****************************************************************************
  make a file into unix format
****************************************************************************/
void unix_format(char *fname)
{
  pstring namecopy="";
  string_replace(fname,'\\','/');
#if 0
  strlower(fname);
#endif
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
  val = ISWP(val);
  memcpy(buf + pos,(char *)&val,sizeof(val));
}

/****************************************************************************
  set a value at buf[pos] to int16 val
****************************************************************************/
void ssval(char *buf,int pos,uint16 val)
{
  val = SSWP(val);
  memcpy(buf + pos,(char *)&val,sizeof(int16));
}

/****************************************************************************
  get a 32 bit integer value
****************************************************************************/
uint32 ival(char *buf,int pos)
{
  uint32 res;
  memcpy((char *)&res,buf + pos,sizeof(int));
  res = ISWP(res);
  return(res);
}


/****************************************************************************
  get a int16 value
****************************************************************************/
uint16 sval(char *buf,int pos)
{
  uint16 res;
  memcpy((char *)&res,buf + pos,sizeof(uint16));
  res = SSWP(res);
  return(res);
}


/*******************************************************************
  show a smb message structure
********************************************************************/
void show_msg(char *buf)
{
  int i;
  Debug(3,"size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%d\n",
	  smb_len(buf),
	  (int)CVAL(buf,smb_com),
	  (int)CVAL(buf,smb_rcls),
	  (int)CVAL(buf,smb_reh),
	  (int)SVAL(buf,smb_err));
  Debug(3,"smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
	  (int)SVAL(buf,smb_tid),
	  (int)SVAL(buf,smb_pid),
	  (int)SVAL(buf,smb_uid),
	  (int)SVAL(buf,smb_mid),
	  (int)CVAL(buf,smb_wct));
  for (i=0;i<(int)CVAL(buf,smb_wct);i++)
    Debug(3,"smb_vwv[%d]=%d (0x%X)\n",i,
	  SVAL(buf,smb_vwv+2*i),SVAL(buf,smb_vwv+2*i));
  Debug(3,"smb_bcc=%d\n",(int)SVAL(buf,smb_vwv+2*(CVAL(buf,smb_wct))));
}

/*******************************************************************
  return the length of an smb packet
********************************************************************/
int smb_len(char *buf)
{
  int msg_flags = CVAL(buf,1);
  int len = (CVAL(buf,2) << 8) + CVAL(buf,3);

  if (msg_flags & 1)
    len += 1<<16;

  return len;
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void smb_setlen(char *buf,int len)
{
  CVAL(buf,3) = len & 0xFF;
  CVAL(buf,2) = (len >> 8) & 0xFF;
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
int set_message(char *buf,int num_words,int num_bytes)
{
  memset(buf + smb_size,0,num_words*2 + num_bytes);
  CVAL(buf,smb_wct) = num_words;
  SSVAL(buf,smb_vwv + num_words*sizeof(WORD),num_bytes);  
  smb_setlen(buf,smb_size + num_words*2 + num_bytes - 4);
  return (smb_size + num_words*2 + num_bytes);
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
reduce a file name, removing .. elements. This assumes dos \ format
********************************************************************/
void clean_name(char *s)
{
  char *p=NULL;

  Debug(3,"clean_name [%s]\n",s);

  /* remove any double slashes */
  while ((p = strstr(s,"\\\\")) != NULL)
    {
      while (*p)
	{
	  p[0] = p[1];
	  p++;
	}
    }

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

  while ((p = strstr(s,"\\.")) != NULL)
    {
      while (*(p+1))
	{
	  p[0] = p[2];
	  p++;
	}
    }  

}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
char *smb_buf(char *buf)
{
  return (buf + smb_size + CVAL(buf,smb_wct)*2);
}

/*******************************************************************
return the absolute current directory path
********************************************************************/
char *GetWd(char *s)
{
#if (defined(LINUX) || defined(SOLARIS) || defined(SVR4) || \
     defined(HPUX) || defined(NEXT) || defined(ISC))
  return((char *)getcwd(s,sizeof(pstring)));
#else
  return((char *)getwd(s));
#endif
}



/*******************************************************************
reduce a file name, removing .. elements and checking that 
it is below dir in the heirachy. This uses GwtWd() and so must be run
on the system that has the referenced file system
********************************************************************/
BOOL reduce_name(char *s,char *dir)
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
  
  Debug(3,"reduce_name [%s] [%s]\n",s,dir);

#if 0
  trim_string(s,"./","/");
#endif

  /* remove any double slashes */
  while ((p = strstr(s,"//")) != NULL)
    {
      while (*p)
	{
	  p[0] = p[1];
	  p++;
	}
    }

  if (!GetWd(wd))
    {
      Debug(0,"couldn't getwd for %s %s\n",s,dir);
      return(False);
    }

  if (chdir(dir) != 0)
    {
      Debug(0,"couldn't chdir to %s\n",dir);
      return(False);
    }

  if (!GetWd(dir2))
    {
      Debug(0,"couldn't getwd for %s\n",dir);
      chdir(wd);
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

  if (chdir(basename) != 0)
    {
      chdir(wd);
      Debug(3,"couldn't chdir for %s %s basename=%s\n",s,dir,basename);
      return(False);
    }

  if (!GetWd(newname))
    {
      chdir(wd);
      Debug(2,"couldn't get wd for %s %s\n",s,dir2);
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
	chdir(wd);
	Debug(2,"Bad access attempt? s=%s dir=%s newname=%s l=%d\n",s,dir2,newname,l);
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

  chdir(wd);

  if (strlen(s) == 0)
    strcpy(s,"./");

  Debug(3,"reduced to %s\n",s);
  return(True);
#endif
}


/****************************************************************************
expand a wildcard expression, replacing *s with ?s
****************************************************************************/
void expand_mask(char *Mask)
{
  pstring mbeg,mext;
  pstring dirpart="";
  pstring filepart="";
  char *p1;
  BOOL absolute = (*Mask == '\\');

  /* parse the directory and filename */
  if (strchr(Mask,'\\'))
    dirname_dos(Mask,dirpart);

  filename_dos(Mask,filepart);

  strcpy(mbeg,filepart);
  if ((p1 = strchr(mbeg,'.')) != NULL)
    {*p1 = 0;p1++;strcpy(mext,p1);}
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
  if (*mext == 0)
    strcpy(mext,"???");

  /* expand *'s */
  while ((p1 = strchr(mbeg,'*')) != NULL)
    {
      int lfill = 9 - strlen(mbeg);
      int l1= (p1 - mbeg);
      int i;
      pstring tmp="";
      strcpy(tmp,mbeg);      
      for (i=0;i<lfill;i++)
	tmp[l1 + i] = '?';
      strcpy(tmp + l1 + lfill,mbeg + l1 + 1);	
      strcpy(mbeg,tmp);      
    }
  while ((p1 = strchr(mext,'*')) != NULL)
    {
      int lfill = 4 - strlen(mext);
      int l1= (p1 - mext);
      int i;
      pstring tmp="";
      strcpy(tmp,mext);      
      for (i=0;i<lfill;i++)
	tmp[l1 + i] = '?';
      strcpy(tmp + l1 + lfill,mext + l1 + 1);	
      strcpy(mext,tmp);
    }

  strcpy(Mask,dirpart);
  if (*dirpart || absolute) strcat(Mask,"\\");
  strcat(Mask,mbeg);
  strcat(Mask,".");
  strcat(Mask,mext);

  Debug(6,"Mask expanded to [%s]\n",Mask);

}  


/****************************************************************************
  see if a name matches a mask. The mask takes the form of several characters,
  with ? being a wild card.
****************************************************************************/
BOOL mask_match(char *Name,char *Mask,BOOL dodots,BOOL case_sensitive)
{
  char *p1,*p2;
  pstring nbeg=""; /* beginning of name */
  pstring next=""; /* extension of name */
  pstring mext=""; /* extension of mask */
  pstring mbeg=""; /* beg of mask */  
  pstring name,mask;

  Debug(3,"mmatch [%s] [%s] %d\n",name,mask,dodots);

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
  if (*mext == 0)
    strcpy(mext,"???");

  /* expand *'s */
  while ((p1 = strchr(mbeg,'*')) != NULL)
    {
      int lfill = 9 - strlen(mbeg);
      int l1= (p1 - mbeg);
      int i;
      pstring tmp="";
      strcpy(tmp,mbeg);      
      for (i=0;i<lfill;i++)
	tmp[l1 + i] = '?';
      strcpy(tmp + l1 + lfill,mbeg + l1 + 1);	
      strcpy(mbeg,tmp);      
    }
  while ((p1 = strchr(mext,'*')) != NULL)
    {
      int lfill = 4 - strlen(mext);
      int l1= (p1 - mext);
      int i;
      pstring tmp="";
      strcpy(tmp,mext);      
      for (i=0;i<lfill;i++)
	tmp[l1 + i] = '?';
      strcpy(tmp + l1 + lfill,mext + l1 + 1);	
      strcpy(mext,tmp);
    }
  
  /* a couple of special cases */
  if (strequal(name,".") || strequal(name,".."))
    return(dodots && strequal(mbeg,"????????") && strequal(mext,"???"));
  
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
  while (*p1) 
    if (isupper(*p1++)) return(False);

  Debug(3,"Matching [%8.8s.%3.3s] to [%8.8s.%3.3s]\n",nbeg,next,mbeg,mext);
  
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
  return(True);
}


/****************************************************************************
  make a dir struct
****************************************************************************/
void make_dir_struct(char *buf,char *mask,char *fname,unsigned int size,int mode,time_t date)
{  
  uint32 dos_date;
  char *p;
  pstring mask2="";

  strcpy(mask2,mask);

  if ((mode & aDIR) != 0)
    size = 0;

  if ((p = strchr(mask2,'.')) != NULL)
    {
      *p = 0;
      strcpy(buf+1,mask2);
      memset(buf+1+strlen(mask2),' ',8-strlen(mask2));
      strncpy(buf+9,p+1,3);
      *p = '.';
    }
  else
    {
      memset(buf+1,' ',11);
      memcpy(buf+1,mask2,MIN(strlen(mask2),11));
    }

  memset(buf+21,0,DIR_STRUCT_SIZE-21);
  dos_date = make_dos_date(date);
  CVAL(buf,21) = mode;
  memcpy(buf+22,&dos_date,sizeof(dos_date));
  SSVAL(buf,26,size & 0xFFFF);
  SSVAL(buf,28,size >> 16);
  strncpy(buf+30,fname,12);
  buf[30+12] = 0;
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
}

/****************************************************************************
write to a socket
****************************************************************************/
int write_socket(int fd,char *buf,int len)
{
if (passive)
  return(len);
return(write(fd,buf,len));
}

/****************************************************************************
read from a socket
****************************************************************************/
int read_socket(int fd,char *buf,int len)
{
  /* #define NORECVFROM */
#ifdef NORECVFROM
  return(read(fd,buf,len));
#else
  int ret;
  struct sockaddr sock;
  int socklen;
  
  socklen = sizeof(sock);
  memset(&sock, 0, socklen);
  memset(&lastip, 0, sizeof(lastip));
  ret = recvfrom(fd,buf,len,0,&sock,&socklen);
  if (ret <= 0)
    Debug(0,"read socket failed. ERRNO=%d\n",errno);
  else
    {
      lastip = *(struct in_addr *) &sock.sa_data[2];
      if (DEBUGLEVEL > 0)
	Debug(3,"read %d bytes\n",ret);
    }
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
#define FLAG_TO_SET FNDELAY
#endif

  if((val = fcntl(fd, F_GETFL, 0))==-1)
	return -1;
  if(set) /* Turn blocking on */
    val |= FLAG_TO_SET;
  else
	val &= ~FLAG_TO_SET;
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
read data from a device with a timout in usec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
****************************************************************************/
int read_with_timeout(int fd,char *buf,int mincnt,int maxcnt, long time_out)
{
  fd_set fds;
  int selrtn;
  int nready, readret;
  int nread = 0;
  struct timeval timeout, tval1, tval2, tvaldiff;
  struct timezone tz;

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
      return 0;
    set_blocking(fd,True);
    return nread;
  }

  /* Most difficult - timeout read */
  /* If this is ever called on a disk file and 
	 mincnt is greater then the filesize then
	 system performance will suffer severely as 
	 select always return true on disk files */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000000;
  timeout.tv_usec = time_out % 1000000;

  /* As most UNIXes don't modify the value of timeout
     when they return from select we need to get the timeofday (in usec)
     now, and also after the select returns so we know
     how much time has elapsed */

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

    /* Query the system how many bytes are ready to be read */
    nready = 0;
    readret = ioctl(fd, FIONREAD, &nready);
 
    if((readret == 0) && nready ) {
      /* Read all that is available */
      readret = read( fd, buf+nread, nready < maxcnt-nread ?
		     nready : maxcnt-nread );
	  if(readret == -1)
		return -1;
      nread += readret;
    }

    /* If we have read more than mincnt then return */
    if( nread >= mincnt )
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
int read_max_data(int fd,char *buffer,int bufsize,int maxtime)
{
  fd_set fds;
  int selrtn;
  int  nready;
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

  /* Query the system how many bytes are ready to be read */
  ioctl(fd, FIONREAD, &nready);

  /* Only try to get the smaller of nready and BUFSIZE */
  nread = read_socket(fd, buffer, nready < bufsize ? nready : bufsize);

  /* return the number got */
  return(nread);
}

/****************************************************************************
write data to a device with a timout in usec.
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
      return 0;
    set_blocking(fd,True);
    return nwritten;
  }

  /* Most difficult - timeout write */

  /* Set initial timeout */
  timeout.tv_sec = time_out / 1000000;
  timeout.tv_usec = time_out % 1000000;

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

/****************************************************************************
  read data from the client, reading exactly N bytes. 
****************************************************************************/
BOOL read_data(int fd,char *buffer,int N)
{
  int  nready;
  int nread = 0;  
  int maxtime = lp_keepalive();
 
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
	  Debug(6,"Sending keepalive\n");
	  if (!send_keepalive())
	    {
	      Debug(0,"keepalive failed!\n");
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
      nready = read_socket(fd,buffer + nread,N - nread);
      if (nready <= 0)
	return False;
      nread += nready;
    }
  return True;
}


/****************************************************************************
  read an smb from a fd and return it's length
The timeout is in micro seconds
****************************************************************************/
int receive_smb(char *buffer,int timeout)
{
  int len, msg_type;
  int fd = Client;
  BOOL ok;

  memset(buffer,0,smb_size + 100);

 again:

  if (timeout > 0)
    ok = (read_with_timeout(fd,buffer,4,4,timeout) == 4);
  else
    ok = read_data(fd,buffer,4);

  if (!ok)
    {
      Debug(0,"couldn't read from client (or timeout)\n");
      close_sockets();
      exit(1);
    }

  len = smb_len(buffer);
  msg_type = CVAL(buffer,0);
  if(len == 0 && msg_type == 0x85) {
    Debug(5, "Got keepalive packet\n");
    goto again;
  }

  if (timeout > 0)
    ok = (read_with_timeout(fd,buffer + 4,len,len,timeout) == len);
  else
    ok = read_data(fd,buffer+4,len);

  if (!ok)
    {
      Debug(0,"couldn't read %d bytes from client (or timeout)\n",len);
      close_sockets();
      exit(1);
    }

  log_in(buffer,len+4);
  return(len + 4);
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

  while (nwritten < len)
    {
      ret = write_socket(fd,buffer+nwritten,len - nwritten);
      if (ret <= 0)
	{
	  Debug(0,"Error writing %d bytes to client. %d. Exiting\n",len,ret);
          close_sockets();
	  exit(1);
	}
      nwritten += ret;
    }

  log_out(buffer,len);

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


/****************************************************************************
receive a name message
****************************************************************************/
BOOL receive_nmb(char *buffer,int timeout)
{
  int ret = read_max_data(Client,buffer,BUFFER_SIZE,timeout);

  if (ret < 0)
    {
      Debug(0,"No bytes from client\n");
      close_sockets();
      exit(0);
    }

  if (ret == 0)
    return False;

  log_in(buffer,ret);

  Debug(3,"nmb_len=%d len=%d\n",nmb_len(buffer),ret);

  return(True);
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
      memcpy(&l,buf+ofs,2);
      p[0] &= ~0xC0;
      l = SVAL(p,0);
      Debug(5,"name ptr to pos %d from %d is %s\n",l,ofs,buf+l);
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

  Debug(3,"\nPACKET INTERPRETATION\n");

#if 0
  if (dbf)
    fwrite(inbuf,1,nmb_len(inbuf),dbf);
  Debug(0,"\n");
#endif

  if (opcode == 5 && ((nm_flags & ~1) == 0x10) && rcode == 0)
    Debug(3,"NAME REGISTRATION REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast");

  if (opcode == 5 && ((nm_flags & ~1) == 0x00) && rcode == 0)
    Debug(3,"NAME OVERWRITE REQUEST AND DEMAND (%s)\n",nm_flags&1?"Broadcast":"Unicast");
  
  if (opcode == 9 && ((nm_flags & ~1) == 0x00) && rcode == 0)
    Debug(3,"NAME REFRESH REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast");
  
  if (opcode == 5 && nm_flags == 0x58 && rcode == 0)
    Debug(3,"POSITIVE NAME REGISTRATION RESPONSE\n");
  
  if (opcode == 5 && nm_flags == 0x58 && rcode != 0 && rcode != 7)
    Debug(3,"NEGATIVE NAME REGISTRATION RESPONSE\n");
  
  if (opcode == 5 && nm_flags == 0x50 && rcode == 0)
    Debug(3,"END-NODE CHALLENGE REGISTRATION RESPONSE\n");
  
  if (opcode == 5 && nm_flags == 0x58 && rcode != 0 && rcode == 7)
    Debug(3,"NAME CONFLICT DEMAND\n");
  
  if (opcode == 6 && (nm_flags&~1) == 0x00 && rcode == 0)
    Debug(3,"NAME RELEASE REQUEST & DEMAND (%s)\n",nm_flags&1?"Broadcast":"Unicast");
  
  if (opcode == 6 && (nm_flags&~1) == 0x40 && rcode == 0)
    Debug(3,"POSITIVE NAME RELEASE RESPONSE\n");
  
  if (opcode == 6 && (nm_flags&~1) == 0x40 && rcode != 0)
    Debug(3,"NEGATIVE NAME RELEASE RESPONSE\n");
  
  if (opcode == 0 && (nm_flags&~1) == 0x10 && rcode == 0)
    Debug(3,"NAME QUERY REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast");
  
  if (opcode == 0 && (nm_flags&~0x28) == 0x50 && rcode == 0)
    Debug(3,"POSITIVE NAME QUERY RESPONSE\n");
  
  if (opcode == 0 && (nm_flags&~0x08) == 0x50 && rcode != 0)
    Debug(3,"NEGATIVE NAME QUERY RESPONSE\n");
  
  if (opcode == 0 && nm_flags == 0x10 && rcode == 0)
    Debug(3,"REDIRECT NAME QUERY RESPONSE\n");

  if (opcode == 7 && nm_flags == 0x80 && rcode == 0)
    Debug(3,"WAIT FOR ACKNOWLEDGEMENT RESPONSE\n");
  
  if (opcode == 0 && (nm_flags&~1) == 0x00 && rcode == 0)
    Debug(3,"NODE STATUS REQUEST (%s)\n",nm_flags&1?"Broadcast":"Unicast");

  if (opcode == 0 && nm_flags == 0x80 && rcode == 0)
    Debug(3,"NODE STATUS RESPONSE\n");
  
  
  Debug(3,"name_trn_id=0x%x\nopcode=0x%x\nnm_flags=0x%x\nrcode=0x%x\n",
	name_trn_id,opcode,nm_flags,rcode);
  Debug(3,"qdcount=%d\nancount=%d\nnscount=%d\narcount=%d\n",
	qdcount,ancount,nscount,arcount);

  l = 12;
  for (i=0;i<qdcount;i++)
    {
      int type,class;
      Debug(3,"QUESTION %d\n",i);
      name_extract(inbuf,l,name);
      l += name_len(inbuf+l);
      type = SVAL(inbuf+l,0);
      class = SVAL(inbuf+l,2);
      l += 4;
      Debug(3,"\t%s\n\ttype=0x%x\n\tclass=0x%x\n",name,type,class);
    }

  for (i=0;i<(ancount + nscount + arcount);i++)
    {
      int type,class,ttl,rdlength;
      Debug(3,"RESOURCE %d\n",i);
      name_extract(inbuf,l,name);
      l += name_len(inbuf + l);
      type = SVAL(inbuf+l,0);
      class = SVAL(inbuf+l,2);
      ttl = IVAL(inbuf+l,4);
      rdlength = SVAL(inbuf+l,8);
      l += 10 + rdlength;
      Debug(3,"\t%s\n\ttype=0x%x\n\tclass=0x%x\n",name,type,class);
      Debug(3,"\tttl=%d\n\trdlength=%d\n",ttl,rdlength);
    }

  Debug(3,"\n");
  
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
      Debug(0,"socket failed");
      return False;
    }
#if 1
  /* allow broadcasts on it */
  setsockopt(out_fd,SOL_SOCKET,SO_BROADCAST,(char *)&one,sizeof(one));
#endif
		  
  /* set the address and port */
  memset(&sock_out, 0, sizeof(sock_out));
  memcpy(&sock_out.sin_addr, ip, 4);
  sock_out.sin_port = htons( port );
  sock_out.sin_family = AF_INET;
  
  /* log the packet */
  log_out(buf,len);

  if (DEBUGLEVEL > 0)
    Debug(3,"sending a packet of len %d to (%s) on port %d of type %s\n",
	  len,inet_ntoa(*ip),port,type==SOCK_DGRAM?"DGRAM":"STREAM");
	
  /* send it */
  ret = (sendto(out_fd,buf,len,0,(struct sockaddr *)&sock_out,sizeof(sock_out)) >= 0);

  if (!ret)
    Debug(0,"Send packet failed. ERRNO=%d\n",errno);

  close(out_fd);
  return(ret);
}


/****************************************************************************
check if a string is part of a list
****************************************************************************/
BOOL in_list(char *s,char *list,BOOL case_sensitive)
{
  pstring listcopy;
  char *t;

  if (!list) return(False);

  strncpy(listcopy,list,sizeof(listcopy));
  
  t = strtok(listcopy," \t,");
  while (t)
    {
      if (case_sensitive)
	{
	  if (strcmp(t,s) == 0)
	    return(True);
	}
      else
	{
	  if (strcasecmp(t,s) == 0)
	    return(True);
	}

      t = strtok(NULL," \t,");
    }
  return(False);
}


/****************************************************************************
set a string value, allocing the space for the string
****************************************************************************/
BOOL string_init(char **dest,char *src)
{
  if (!src) 
    {
      Debug(0,"null src in string_init\n");
      return(False);
    }

  *dest = (char *)malloc(strlen(src)+1);

  strcpy(*dest,src);
  return(True);
}

/****************************************************************************
free a string value
****************************************************************************/
void string_free(char **s)
{
  if (*s) free(*s);
  *s = NULL;
}

/****************************************************************************
set a string value, allocing the space for the string, and deallocating any 
existing space
****************************************************************************/
BOOL string_set(char **dest,char *src)
{
  if (!src) return(False);

  string_free(dest);

  return(string_init(dest,src));
}

/****************************************************************************
get a users home directory. tries as-is then lower case
****************************************************************************/
char *get_home_dir(char *user)
{
  static struct passwd *pass;
  pstring user2;

  strcpy(user2,user);

  pass = getpwnam(user2);
  if (!pass) 
    {
      strlower(user2);
      pass = getpwnam(user2);
    }

  if (!pass) return(NULL);
  return(pass->pw_dir);      
}


/****************************************************************************
become a daemon, discarding the controlling terminal
****************************************************************************/
void become_daemon(void)
{
#ifndef NO_FORK_DEBUG
  int i;
  if (fork())
    exit(0);

  /* detach from the terminal */
#ifdef LINUX
  setpgrp();
#endif

  i = open("/dev/tty", O_RDWR);
  if (i >= 0) 
    {
      ioctl(i, (int) TIOCNOTTY, (char *)0);      
      close(i);
    }
#endif
}


/****************************************************************************
get the broadcast address for our address (troyer@saifr00.ateng.az.honeywell.com)
****************************************************************************/
BOOL get_broadcast(struct in_addr *if_ipaddr, struct in_addr *if_bcast, struct in_addr *if_nmask)
{
  int sock = -1;               /* AF_INET raw socket desc */
  char buff[1024];
  struct ifconf ifc;
  struct ifreq *ifr;
  int i;
  
  /* Create a socket to the INET kernel. */
  if ((sock = socket(AF_INET, SOCK_RAW, PF_INET )) < 0)
    {
      Debug(0, "Unable to open socket to get broadcast address\n");
      return(False);
    }
  
  /* Get a list of the configures interfaces */
  ifc.ifc_len = sizeof(buff);
  ifc.ifc_buf = buff;
  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
    {
      Debug(0, "SIOCGIFCONF: %s\n", strerror(errno));
      return(False);
    }
  
  /* Loop through interfaces, looking for given IP address */
  ifr = ifc.ifc_req;
  for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
    {
      Debug(3,"Interface: %s  IP addr: %s\n", ifr->ifr_name,
	    inet_ntoa((*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr));
      if (if_ipaddr->s_addr == (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr)
        break;
    }
  if (i < 0)
    {
      Debug(0,"No interface found for address %s\n", inet_ntoa(*if_ipaddr));
      return(False);
    }
  
  /* Get the broadcast address from the kernel */
  if (ioctl(sock, SIOCGIFBRDADDR, ifr) < 0)
    {
      Debug(0,"SIOCGIFBRDADDR failed\n");
      return(False);
    }
  *if_bcast = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;


  /* Get the netmask address from the kernel */
  if (ioctl(sock, SIOCGIFNETMASK, ifr) < 0)
    {
      Debug(0,"SIOCGIFNETMASK failed\n");
      return(False);
    }
  *if_nmask = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr;
  
  /* Close up shop */
  (void) close(sock);
  
  Debug(2,"Broadcast address for %s = %s\n", ifr->ifr_name,
	inet_ntoa(*if_bcast));
  Debug(2,"Netmask for %s = %s\n", ifr->ifr_name,
	inet_ntoa(*if_nmask));
  return(True); 
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
  return(True);  
}


/****************************************************************************
do a netbios name query to find someones IP
****************************************************************************/
BOOL name_query(char *inbuf,char *outbuf,char *name,struct in_addr *ip)
{
  int count;
  static uint16 name_trn_id = 0x6242;
  char *p;
  BOOL saved_swap = NeedSwap;

  NeedSwap = !big_endian();

  Debug(2,"Querying name %s\n",name);

  SSVAL(outbuf,0,name_trn_id++);
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

  count = 3;
  while (count--)
    {
      Debug(2,"Sending name query for %s\n",name);

      show_nmb(outbuf);
      if (!send_packet(outbuf,nmb_len(outbuf),&bcast_ip,137,SOCK_DGRAM))
	{
	  NeedSwap = saved_swap;
	  return False;
	}

      if (receive_nmb(inbuf,count==1?20:5))
	{
	  int rec_name_trn_id = SVAL(inbuf,0);
	  int opcode = (CVAL(inbuf,2) >> 3) & 0xF;
	  int nm_flags = ((CVAL(inbuf,2) & 0x7) << 4) + (CVAL(inbuf,3)>>4);
	  int rcode = CVAL(inbuf,3) & 0xF;
	  show_nmb(inbuf);

	  /* is it a positive response to our request? */
	  if ((rec_name_trn_id = name_trn_id) && 
	      opcode == 0 && (nm_flags&~0x28) == 0x50 && rcode == 0)
	    {
	      char qname[100];
	      name_extract(inbuf,12,qname);
	      if (name_equal(qname,name))
		{
		  Debug(0,"Someone (%s) gave us a positive name query response\n",
			inet_ntoa(lastip));
		  memcpy(ip,inbuf + 12 + name_len(inbuf+12) + 12,4);
		  NeedSwap = saved_swap;
		  return(True);
		}
	    }	  
	}
    }
  NeedSwap = saved_swap;
  return(False);
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
set the length of a file from a filedescriptor.
Returns 0 on success, -1 on failure.
****************************************************************************/
int set_filelen(int fd, long len)
{
/* According to W. R. Stevens advanced UNIX prog. Pure 4.3 BSD cannot
   extend a file with ftruncate. Provide alternate implementation
   for this */

#ifndef FTRUNCATE_CANT_EXTEND
  return ftruncate(fd, len);
#else
  struct stat st;
  char c = 0;
  long currpos = lseek(fd, 0L, SEEK_SET);

  if(currpos < 0)
    return -1;
  /* Do an fstat to see if the file is longer than
     the requested size (call ftruncate),
     or shorter, in which case seek to len - 1 and write 1
     byte of zero */
  if(fstat(fd, &st)<0)
    return -1;

  if(st.st_size == len)
    return;
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

#ifdef NETBSD
/* a fake shadow password routine which just fills a fake spwd struct
 * with the sp_pwdp field. (sreiz@aie.nl)
 */
struct spwd *getspnam(char *username) /* fake shadow password routine */
{
       FILE *f;
       char line[1024];
       static char pw[20];
       static struct spwd static_spwd;

       static_spwd.sp_pwdp=0;
       if (!(f=fopen("/etc/master.passwd", "r")))
               return 0;
       while (fgets(line, 1024, f)) {
               if (!strncmp(line, username, strlen(username)) &&
                line[strlen(username)]==':') { /* found entry */
                       char *p, *q;

                       p=line+strlen(username)+1;
                       if (q=strchr(p, ':')) {
                               *q=0;
                               if (q-p+1>20)
                                       break;
                               strcpy(pw, p);
                               static_spwd.sp_pwdp=pw;
                       }
                       break;
               }
       }
       fclose(f);
       if (static_spwd.sp_pwdp)
               return &static_spwd;
       return 0;
}
#endif


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
check if a username/password is OK
****************************************************************************/
BOOL password_ok(char *user,char *password)
{
  BOOL pwok = False;
  char salt[10];
#ifdef SHADOW_PWD
  struct spwd *spass = NULL;
#endif
  struct passwd *pass = NULL;

  pass = getpwnam(user);
  if (!pass)
    {
      strlower(user);
      pass = getpwnam(user);
    }

  if (!pass) 
    {
      Debug(0,"Couldn't find user %s\n",user);
      return(False);
    }

#ifdef PWDAUTH
  pwok = (pwdauth(user,password) == 0);
  if (!pwok)
    {
      strlower(password);
      pwok = (pwdauth(user,password) == 0);
    }	      
  return(pwok);
#endif

#ifdef SHADOW_PWD
  spass = getspnam(user);
  if (spass && spass->sp_pwdp)
    pass->pw_passwd = spass->sp_pwdp;
#endif
  strncpy(salt,pass->pw_passwd,2);
  salt[2] = 0;
  pwok = (strcmp(crypt(password,salt),pass->pw_passwd) == 0);
  if (!pwok)
    {
      strlower(password);
      pwok = (strcmp(crypt(password,salt),pass->pw_passwd) == 0);
    }	      

  return(pwok);
}





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
	Debug(0,"More than %3dk (%d)   %6d times    %g secs. %g k/sec\n",
	      time_stats[bin].thresh,
	      time_stats[bin].tsize/(1024*time_stats[bin].count),
	      time_stats[bin].count,time_stats[bin].time/1.0e6,
	      (time_stats[bin].tsize/1024.0)/(time_stats[bin].time/1.0e6));
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
    ret = realloc(p,size);

  if (!ret)
    Debug(0,"Memoory allocation error: failed to expand to %d bytes\n",size);

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
  Debug(0,"Abort called. Probably got SIGPIPE\n");
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
  
  return(mktime(t2) - TimeDiff());
}


/*******************************************************************
  check for a sane unix date
********************************************************************/
BOOL sane_unix_date(time_t unixdate)
{
  struct tm t,today;
  time_t t_today = time(NULL);
  
  t = *(LocalTime(&unixdate));
  today = *(LocalTime(&t_today));
  
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





/****************************************************************************
register a netbios name on the net.
****************************************************************************/
BOOL register_name(name_struct *name,struct in_addr *destip,void (*fn)())
{
  int count;
  char *p;
  char *inbuf = (char *)malloc(BUFFER_SIZE);
  char *outbuf = (char *)malloc(BUFFER_SIZE);
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

  Debug(1,"Registering name %s (%s) nb_flags=0x%x\n",
	name->name, inet_ntoa(name->ip) ,name->nb_flags);

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
  memcpy(p,&(name->ip),4);
  p += 4;

  count = 3;
  while (count--)
    {
      Debug(3,"Sending reg request for %s at (%s)\n",
	    name->name,inet_ntoa(name->ip));


      show_nmb(outbuf);
      if (!send_packet(outbuf,nmb_len(outbuf),destip,137,SOCK_DGRAM))
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
              (opcode == 5 && nm_flags == 0x58 && rcode != 0 && rcode != 7))
	    {
	      char qname[100];
	      name_extract(inbuf,12,qname);
	      if (name_equal(qname,name->name))
		{
		  Debug(0,"Someone (%s) gave us a negative name regregistration response!\n",
			inet_ntoa(lastip));
		  free(inbuf);free(outbuf);
		  NeedSwap = saved_swap;
		  return False;
		}
	      else
		{
		  Debug(0,"%s gave negative name regregistration for %s??\n",
			inet_ntoa(lastip),qname);
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
  memcpy(p,&(name->ip),4);
  p += 4;
  
  Debug(3,"Sending reg demand for %s at (%s)\n",
	name->name,inet_ntoa(name->ip));

  show_nmb(outbuf);

  {
    BOOL ret = send_packet(outbuf,nmb_len(outbuf),destip,137,SOCK_DGRAM);

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
  pstring myhostname;

  /* get my host name */
  if (gethostname(myhostname, sizeof(myhostname)) == -1) 
    {
      Debug(0,"gethostname failed\n");
      return False;
    } 
  
  /* get host info */
  if ((hp = gethostbyname(myhostname)) == 0) 
    {
      Debug(0, "Gethostbyname: Unknown host %s.\n",myhostname);
      return False;
    }

  if (myname)
    {
      strcpy(myname,myhostname);
      strupper(myname);
    }

  if (ip)
    memcpy(ip,hp->h_addr,4);

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


