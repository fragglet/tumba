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
#include "loadparm.h"
#include "pcap.h"

/* default to not LANMAN1 */
#ifndef LANMAN1
#define LANMAN1 0
#endif

pstring servicesf = SERVICES;
pstring debugf = DEBUGFILE;

BOOL append_log = True;

char *InBuffer = NULL;
char *OutBuffer = NULL;

int initial_uid = 0;
int initial_gid = 0;

extern BOOL NeedSwap;

connection_struct Connections[MAX_CONNECTIONS];
files_struct Files[MAX_OPEN_FILES];

/* local prototype */
static char *build_print_command(int snum, char *syscmd, char *filename);

int Protocol = PROT_CORE;

int maxxmit = BUFFER_SIZE;

int chain_size = 0;

/* a fnum to use when chaining */
int chain_fnum = -1;

/* total number of open files */
int num_files_open = 0;

extern struct in_addr myip;

/****************************************************************************
  change a dos mode to a unix mode
****************************************************************************/
mode_t unix_mode(int cnum,int dosmode)
{
  mode_t result = 0444;
  
  if ((dosmode & aRONLY) == 0)
    result |= (S_IWUSR | S_IWGRP | S_IWOTH);

  if ((dosmode & aDIR) != 0)
    result |= (S_IFDIR | S_IXUSR | S_IXGRP | S_IXOTH);

  if ((dosmode & aARCH) != 0)
    result |= S_IXUSR;

  if (MAP_SYSTEM(cnum) && ((dosmode & aSYSTEM) != 0))
    result |= S_IXGRP;

  if (MAP_HIDDEN(cnum) && ((dosmode & aHIDDEN) != 0))
    result |= S_IXOTH;  

  result &= CREATE_MODE(cnum);
  return(result);
}


/****************************************************************************
  change a unix mode to a dos mode
****************************************************************************/
int dos_mode(int cnum,char *path,mode_t unixmode)
{
  int result = 0;
  

  /* need to exchange because access() uses real uid, argggh */
  exchange_uids();

  if (access(path,W_OK))
    result |= aRONLY;

  exchange_uids();

  if ((unixmode & S_IXUSR) != 0)
    result |= aARCH;

  if (MAP_SYSTEM(cnum) && ((unixmode & S_IXGRP) != 0))
    result |= aSYSTEM;

  if (MAP_HIDDEN(cnum) && ((unixmode & S_IXOTH) != 0))
    result |= aHIDDEN;   
  
  if (S_ISDIR(unixmode))
    result = aDIR;
  
  return(result);
}


struct dptr_struct
{
  BOOL valid;
  int key;
  pstring path;
  void *ptr;
}
dirptrs[MAXDIR];

BOOL dptrs_init=False;
int next_key = 1;

/****************************************************************************
initialise the dir array
****************************************************************************/
void init_dptrs(void)
{
  int i;
  if (dptrs_init) return;
  for (i=0;i<MAXDIR;i++)
    dirptrs[i].valid = False;
  dptrs_init = True;
}

/****************************************************************************
get the dir ptr for a dir index
****************************************************************************/
void *dptr_get(int key)
{
  int i;
  for (i=0;i<MAXDIR;i++)
    if (dirptrs[i].valid && dirptrs[i].key == key)
      return(dirptrs[i].ptr);
  return(NULL);
}

/****************************************************************************
get the dir path for a dir index
****************************************************************************/
char *dptr_path(int key)
{
  int i;
  for (i=0;i<MAXDIR;i++)
    if (dirptrs[i].valid && dirptrs[i].key == key)
      return(dirptrs[i].path);
  return(NULL);
}

/****************************************************************************
check a key
****************************************************************************/
BOOL key_ok(int key)
{
  int i;
  for (i=0;i<MAXDIR;i++)
    if (dirptrs[i].valid && dirptrs[i].key == key)
      return(True);
  return(False);
}

/****************************************************************************
prompte a dptr (to make it recently used)
****************************************************************************/
void dptr_promote(int key)
{
  int i;
  for (i=0;i<MAXDIR;i++)
    if (dirptrs[i].valid && dirptrs[i].key == key)
      {
	struct dptr_struct d;
	int j;
	d = dirptrs[i];
	for (j=i;j>0;j--)
	  dirptrs[j] = dirptrs[j-1];
	dirptrs[0] = d;
	return;
      }
}


/****************************************************************************
demote a dptr (to make it likely to get closed)
****************************************************************************/
void dptr_demote(int key)
{
  int i;
  for (i=0;i<MAXDIR;i++)
    if (dirptrs[i].valid && dirptrs[i].key == key)
      {
	struct dptr_struct d;
	int j;
	d = dirptrs[i];
	for (j=i;j<(MAXDIR-1) && dirptrs[j].valid;j++)
	  dirptrs[j] = dirptrs[j+1];
	dirptrs[j] = d;
	return;
      }
}


/****************************************************************************
find a free key
****************************************************************************/
int find_key(int start)
{
  int key;

  for (key=start;key<256;key++)
    if (!key_ok(key))
      return(key);

  for (key=1;key<start;key++)
    if (!key_ok(key))
      return(key);

  Debug(0,"ERROR: Out of dirptr keys!\n");
  return 1;
}       
  

/****************************************************************************
close a dptr
****************************************************************************/
void dptr_close(int key)
{
  int i;
  for (i=0;i<MAXDIR;i++)
    if (dirptrs[i].valid && dirptrs[i].key == key)
      {
	if (dirptrs[i].ptr)
	  closedir(dirptrs[i].ptr);
	dirptrs[i].valid = False;
	next_key = key+1;
	if (next_key > 255) next_key = 1;
	return;
      }
}

/****************************************************************************
create a new dir ptr
****************************************************************************/
int dptr_create(void *p,char *path)
{
  int i,key;
  for (i=0;i<MAXDIR;i++)
    if (!dirptrs[i].valid)
      break;

  if (i == MAXDIR)
    {
      i = MAXDIR - 1;
      dptr_close(dirptrs[i].key);
    }

  dirptrs[i].ptr = p;
  strcpy(dirptrs[i].path,path);
  key = find_key(next_key);
  dirptrs[i].key = key;
  dirptrs[i].valid = True;

  dptr_promote(key);

  Debug(3,"creating new dirptr %d (0x%x) for path %s\n",key,p,path);  

  return(key);
}

/****************************************************************************
fill the 5 byte server reserved dptr field
****************************************************************************/
BOOL dptr_fill(char *buf,unsigned int key)
{
  void *p = dptr_get(key);
  int offset;
  if (!p)
    {
      Debug(3,"filling null dirptr %d\n",key);
      return(False);
    }
  offset = telldir(p);
  Debug(3,"fill on dirptr 0x%x now at %d\n",p,offset);
  buf[0] = key;
  memcpy(buf+1,&offset,4);
  Debug(3,"filled dirptr %d at offset %d\n",key,offset);
  return(True);
}

/****************************************************************************
return True is the offset is at zero
****************************************************************************/
BOOL dptr_zero(char *buf)
{
  int offset;
  memcpy(&offset,buf+1,4);
  return (offset == 0);
}

/****************************************************************************
fetch the dir ptr and seek it given the 5 byte server field
****************************************************************************/
void *dptr_fetch(char *buf,int *num)
{
  unsigned int key = *(unsigned char *)buf;
  void *p = dptr_get(key);
  int offset;
  if (!p)
    {
      Debug(3,"fetched null dirptr %d\n",key);
      return(NULL);
    }
  *num = key;
  memcpy(&offset,buf+1,4);
  seekdir(p,offset);
  dptr_promote(key);
  Debug(3,"fetching dirptr %d for path %s\n",key,dptr_path(key));
  return(p);
}


/****************************************************************************
  start a directory listing
****************************************************************************/
BOOL start_dir(int cnum,char *directory)
{
  Debug(2,"start_dir cnum=%d dir=%s\n",cnum,directory);

  if (!reduce_name(directory,HOME(cnum)))
    return(False);
  
  Connections[cnum].dirptr = (void *)opendir(directory);

  strncpy(Connections[cnum].dirpath,directory,sizeof(pstring));
  
  return(Connections[cnum].dirptr != NULL);
}

/****************************************************************************
  get a directory entry
****************************************************************************/
BOOL get_dir_entry(int cnum,char *mask,int dirtype,char *fname,int *size,int *mode,time_t *date,BOOL check_descend)
{
  struct DIRECT *dptr;
  
  BOOL found = False;
  struct stat sbuf;
  pstring path="";
  BOOL isrootdir;
  
  isrootdir = (strequal(Connections[cnum].dirpath,"./") ||
	       strequal(Connections[cnum].dirpath,"."));
  
  if (!Connections[cnum].dirptr)
    return(False);
  
  while (!found)
    {
      
      dptr = readdir(Connections[cnum].dirptr);

      Debug(3,"readdir on dirptr 0x%x now at offset %d\n",
	    Connections[cnum].dirptr,telldir(Connections[cnum].dirptr));
      
      if (dptr == NULL) 
	return(False);
      
      if (mask_match(dptr->d_name,mask,!isrootdir,True))
	{
	  strcpy(fname,dptr->d_name);
#if 0
	  /* possibly convert the name to a msdos name */
	  hash_name(fname);
#endif
	  strcpy(path,Connections[cnum].dirpath);
	  strcat(path,"/");
	  strcat(path,fname);
	  if (stat(path,&sbuf) != 0) 
	    {
	      Debug(5,"Couldn't stat 1 [%s]\n",path);
	      continue;
	    }

	  if (check_descend &&
	      !strequal(fname,".") && !strequal(fname,".."))
	    continue;
	  
	  *mode = dos_mode(cnum,path,sbuf.st_mode);
	  
	  if (((*mode & ~dirtype) & (aHIDDEN | aSYSTEM | aDIR)) != 0)
	    {	      
	      Debug(5,"[%s] attribs didn't match %x\n",dptr->d_name,dirtype);
	      continue;
	    }
	  *size = sbuf.st_size;
	  *date = sbuf.st_mtime;
	  
	  found = True;
	}
      else
	{
	  Debug(5,"[%s] didn't match [%s]\n",dptr->d_name,mask);
	}
    }

  return(found);
}

static int old_umask = 0755;

/****************************************************************************
  become the user of a connection number
****************************************************************************/
BOOL become_user(int cnum)
{
  if (!OPEN_CNUM(cnum))
    {
      Debug(0,"ERROR: Connection %d not open\n",cnum);
      return(False);
    }
  
  if (initial_uid == 0)
    {
      if (setegid(Connections[cnum].gid) != 0)
	{
	  Debug(0,"Couldn't set uid\n");
	  return(False);
	}
  
      if (seteuid(Connections[cnum].uid) != 0)
	{
	  Debug(0,"Couldn't set uid\n");
	  return(False);
	}
    }
  
  if (chdir(Connections[cnum].connectpath) != 0)
    {
      Debug(0,"%s chdir (%s) failed cnum=%d\n",timestring(),Connections[cnum].connectpath,cnum);
      
      return(False);
    }
  
  old_umask = umask(0);

  return(True);
}

/****************************************************************************
  unbecome the user of a connection number
****************************************************************************/
BOOL unbecome_user(void )
{

  umask(old_umask);

  if (initial_uid == 0)
    {
      seteuid(getuid());
      setegid(getgid());
    }

  if (chdir("/") != 0)
    Debug(0,"%s chdir / failed\n",timestring());  
  
  return(True);
}

/****************************************************************************
  find a service entry
****************************************************************************/
int find_service(char *service)
{
   int iService;

   iService = lp_servicenumber(service);

   /* now handle the special case of a home directory */
   if (iService < 0)
   {
      char *phome_dir = get_home_dir(service);
      Debug(3,"checking for home directory %s gave %s\n",service,
	    phome_dir?phome_dir:"(NULL)");
      if (phome_dir)
      {   
	 int iHomeService;
	 if ((iHomeService = lp_servicenumber(HOMES_NAME)) >= 0)
	 {
	    lp_add_home(service,iHomeService,phome_dir);
	    iService = lp_servicenumber(service);
	 }
      }
   }

   if (iService >= 0)
      if (!VALID_SNUM(iService))
      {
         Debug(0,"Invalid snum %d for %s\n",iService,service);
	 iService = -1;
      }

   if (iService < 0)
      Debug(3,"find_service() failed to find service %s\n", service);

   return (iService);
}

/* this holds info on user ids that are already validated for this VC */
user_struct *validated_users = NULL;
int num_validated_users = 0;

/****************************************************************************
check if a uid has been validated, and return an index if it has. -1 if not
****************************************************************************/
int valid_uid(int uid)
{
  int i;
  for (i=0;i<num_validated_users;i++)
    if (validated_users[i].uid == uid)
      {
	Debug(3,"valid uid %d mapped to vuid %d\n",uid,i);
	return(i);
      }
  return(-1);
}

/****************************************************************************
register a uid/name pair as being valid and that a valid password
has been given.
****************************************************************************/
void register_uid(int uid,char *name,BOOL guest)
{
  if (valid_uid(uid) >= 0)
    return;
  if (!validated_users)
    validated_users = (user_struct *)malloc(sizeof(user_struct));
  else
    validated_users = (user_struct *)realloc(validated_users,
					     sizeof(user_struct)*
					     (num_validated_users+1));

  if (!validated_users)
    {
      Debug(0,"Failed to realloc users struct!\n");
      return;
    }

  validated_users[num_validated_users].uid = uid;
  validated_users[num_validated_users].guest = guest;
  validated_users[num_validated_users].name = strdup(name);    

  Debug(3,"uid %d registered to name %s\n",uid,name);
  
  num_validated_users++;
}


/****************************************************************************
  find first available connection slot
****************************************************************************/
int find_free_connection(void )
{
  int i;
  for (i=1;i<MAX_CONNECTIONS;i++)
    if (!Connections[i].open) 
      return(i);
  return(-1);
}

/****************************************************************************
  find first available file slot
****************************************************************************/
int find_free_file(void )
{
  int i;
  for (i=0;i<MAX_OPEN_FILES;i++)
    if (!Files[i].open) 
      return(i);
  return(-1);
}

/****************************************************************************
  make a connection to a service
****************************************************************************/
int make_connection(char *service,char *user,char *password,int vuid)
{
  int cnum;
  int snum;
  struct passwd *pass = NULL;
  BOOL guest = False;

  if (vuid >= 0)
    {
      strcpy(user,validated_users[vuid].name);
      guest = validated_users[vuid].guest;
    }
  
  strlower(user);
  strlower(service);

  snum = find_service(service);
  if (snum < 0)
    {
      Debug(0,"%s couldn't find service %s\n",timestring(),service);
      
      return(-1);
    }

  if (guest && !GUEST_OK(snum))
    {
      Debug(1,"%s no guest access to service %s\n",timestring(),service);
      return(-1);
    }

  if (*user == 0)
    strcpy(user, USER(snum));
  
  cnum = find_free_connection();
  if (cnum < 0)
    {
      Debug(0,"%s couldn't find free connection\n",timestring());
      
      return(-1);
    }

  pass = getpwnam(user);
  if (!pass)
    {
      strlower(user);
      pass = getpwnam(user);
    }

  if (pass == NULL)
    {
      Debug(0,"%s couldn't find account %s\n",timestring(),user); 
      return(-1);
    }
  

  if (vuid < 0)
    {
      if (!(GUEST_OK(snum) && (*password == 0)))
	{
	  if (!password_ok(user,password))
	    {
	      Debug(0,"%s invalid password for user %s\n",timestring(),user);
	      return -1;
	    }
	}
    }

  if (!check_access(snum))
    return(-1);
  
  Connections[cnum].uid = pass->pw_uid;
  Connections[cnum].gid = pass->pw_gid;
  Connections[cnum].connect_num = cnum;
  Connections[cnum].service = snum;
  Connections[cnum].dirptr = NULL;
  Connections[cnum].dirpath[0] = 0;
  strcpy(Connections[cnum].connectpath, PATH(snum));
  Connections[cnum].open = True;

  {
    extern struct from_host Client_info;
    Debug(1,"%s (%s) has opened a connection to service %s as user %s\n",
	  Client_info.name,Client_info.addr,service,user);
  }

  return(cnum);
}


/****************************************************************************
this prevents zombie child processes
****************************************************************************/
int sig_cld()
{

  /* Stop zombies */
  /* Stevens, Adv. Unix Prog. says that on system V you must call
     wait before reinstalling the signal handler, because the kernel
     calls the handler from within the signal-call when there is a
     child that has exited. This would lead to an infinite recursion
     if done vice versa. */
        
  signal(SIGCLD, SIGNAL_CAST sig_cld);


  while (wait3((int *)NULL, WNOHANG, (struct rusage *)NULL) > 0);
  return 0;
}

/****************************************************************************
  open the socket communication
****************************************************************************/
BOOL open_sockets(BOOL daemon,int port)
{
  extern int Client;
  int type, optlen;

  /* Check if we need to open a new socket by doing
     a harmless socket option on fd 0. If this fails
     we need to create one. */
  
  if (!daemon && 
      (getsockopt(0, SOL_SOCKET, SO_TYPE, (char *)&type, &optlen)==-1) &&
      (errno == ENOTSOCK))
    {
      Debug(0,"standard input is not a socket, will create a socket\n");
      daemon = True;
    }

  if (daemon)
    {
      struct sockaddr addr;
      struct sockaddr_in sock;
      char host_name[100];
      struct hostent *hp;
      int in_addrlen = sizeof(addr);
      int s;
      int sockopt = 1;
      
      /* get my host name */
      if (gethostname(host_name, sizeof(host_name)) == -1) 
	{
	  perror("gethostname");
	  return False;
	} 
  
      /* get host info */
      if ((hp = gethostbyname(host_name)) == 0) 
	{
	  Debug(0, "Gethostbyname: Unknown host.\n");
	  return False;
	}
 
      /* Stop zombies */
      signal(SIGCLD, SIGNAL_CAST sig_cld);
 
      memset(&sock, 0, sizeof(sock));
      memcpy(&sock.sin_addr, hp->h_addr, hp->h_length);
      sock.sin_port = htons( port );
      sock.sin_family = hp->h_addrtype;
      sock.sin_addr.s_addr = INADDR_ANY;
      s = socket(hp->h_addrtype, SOCK_STREAM, 0);
      if (s == -1) 
	{
	  perror("socket");
	  return False;
	}
      if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int)))
	{
	  perror("Error in setting socket option");
	  close(s);
	  return False;
	}

      /* now we've got a socket - we need to bind it */
      if (bind(s, (struct sockaddr * ) &sock,sizeof(sock)) < 0)
	{
	  perror("bind");
	  close(s);
	  return False;
	}
  
      /* ready to listen */
      if (listen(s, 5) == -1) 
	{
	  perror("listen");
	  close(s);
	  return False;
	}
  
  
      /* now accept incoming connections - forking a new process
	 for each incoming connection */
      Debug(2,"waiting for a connection\n");
      while ((Client = accept(s,&addr,&in_addrlen)))
	{
	  if (Client == -1 && errno == EINTR)
	    continue;

	  if (Client == -1)
	    {
	      perror("accept");
	      return False;
	    }

#ifdef NO_FORK_DEBUG
	  return True;
#else
	  if (Client != -1 && fork()==0)
	    {
	      signal(SIGPIPE, SIGNAL_CAST Abort);
	      signal(SIGCLD, SIGNAL_CAST SIG_DFL);

	      /* now set appropriate socket options */
	      {
		int one=1;
		setsockopt(Client,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one));
	      }
	      return True; 
	    }
          close(Client); /* The parent doesn't need this socket */
#endif
	}
      close(s);
      return False;
    }
  else
    {
      /* We will abort gracefully when the client or remote system 
	 goes away */
      signal(SIGPIPE, SIGNAL_CAST Abort);
      Client = 0;
    }

  /* now set appropriate socket options */
  {
    int one=1;
    setsockopt(Client,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one));
  }

  return True;
}

/****************************************************************************
  utility function called by unlocking requests
****************************************************************************/
static int do_unlock( fnum, cnum, count, offset, eclass, ecode)
int fnum, cnum; /* Fileid, user */
uint32 count, offset;
int *eclass;
uint32 *ecode;
{
  BOOL ok = False;

  if (Files[fnum].can_lock && become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(Files[fnum].fd,offset,SEEK_SET);
	  if (lockf(Files[fnum].fd,F_ULOCK,count) == 0)
	    ok = True;
	}
      unbecome_user();
    }

  if (!ok) {
    *eclass = ERRDOS;
    *ecode = ERRlock;
    return -1;
  }
  return 0; /* Did unlock */
}

/****************************************************************************
  utility function called by locking requests
****************************************************************************/
static int do_lock( fnum, cnum, count, offset, eclass, ecode)
int fnum, cnum; /* Fileid, user */
uint32 count, offset;
int *eclass;
uint32 *ecode;
{
  BOOL ok = False;

  if (count == 0) {
    *eclass = ERRDOS;
    *ecode = eACCESS_DENIED;
    return -1;
  }

  if (Files[fnum].can_lock && become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(Files[fnum].fd,offset,SEEK_SET);
	  if (lockf(Files[fnum].fd,F_TLOCK,count) == 0)
	    ok = True;
	}
      unbecome_user();
    }

  if (!ok) {
    *eclass = ERRDOS;
    *ecode = ERRlock;
    return -1;
  }
  return 0; /* Got lock */
}

/****************************************************************************
  reply to an special message 
****************************************************************************/
int reply_special(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = 4;
  int msg_type = CVAL(inbuf,0);
  int msg_flags = CVAL(inbuf,1);
  pstring name1="";
  pstring name2="";

  switch (msg_type)
    {
    case 0x81: /* session request */
      CVAL(outbuf,0) = 0x82;
      CVAL(outbuf,3) = 0;
      name_interpret(inbuf + 4,name1);
      name_interpret(inbuf + 5 + strlen(inbuf + 4),name2);
      Debug(2,"connect name1=%s name2=%s\n",name1,name2);      
      break;
    case 0x85: /* session keepalive */
    default:
      return 0;
    }
  
  Debug(2,"%s init msg_type=0x%x msg_flags=0x%x\n",timestring(),msg_type,msg_flags);
  
  smb_setlen(outbuf,0);
  return(outsize);
}

/****************************************************************************
  create an error packet with dos error code enum.
****************************************************************************/
int error_packet(char *inbuf,char *outbuf,int error_class,uint32 error_code,int line)
{
  int outsize = set_message(outbuf,0,0);
  int cmd;
  cmd = CVAL(inbuf,smb_com);
  
  CVAL(outbuf,smb_rcls) = error_class;
  SSVAL(outbuf,smb_err,error_code);  
  
  Debug(2,"%s error packet at line %d cmd=%d enum=%d\n",timestring(),line,(int)CVAL(inbuf,smb_com),error_code);
  
  return(outsize);
}

/****************************************************************************
reply for the core protocol
****************************************************************************/
int reply_corep(char *outbuf, int choice)
{
  int outsize = set_message(outbuf,1,0);

  Protocol = PROT_CORE;

  return outsize;
}

/****************************************************************************
reply for the coreplus protocol
****************************************************************************/
int reply_coreplus(char *outbuf, int choice)
{
  int outsize = set_message(outbuf,13,0);
  SSVAL(outbuf,smb_vwv5,0x3); /* tell redirector we support
				 readbraw and writebraw */
  CVAL(outbuf,smb_reb) = 0x81; /* Reply, SMBlockread, SMBwritelock supported */
#ifdef TESTING
  SSVAL(outbuf,smb_vwv1,0x1); /* user level security, don't encrypt */	
#endif

  Protocol = PROT_COREPLUS;

  return outsize;
}


/****************************************************************************
reply for the lanman 1.0 protocol
****************************************************************************/
int reply_lanman1(char *outbuf, int choice)
{
  uint32 ourtime;
  uint16 *p = (uint16 *)&ourtime;

  int outsize = set_message(outbuf,13,0);
  CVAL(outbuf,smb_reb) = 0x81; /* Reply, SMBlockread, SMBwritelock supported */
  SSVAL(outbuf,smb_vwv1,0x1); /* user level security, don't encrypt */	
  SSVAL(outbuf,smb_vwv2,lp_maxxmit());
  SSVAL(outbuf,smb_vwv3,0);
  SSVAL(outbuf,smb_vwv4,0);
  SSVAL(outbuf,smb_vwv5,0x3); /* tell redirector we support
				 readbraw and writebraw */
  SIVAL(outbuf,smb_vwv6,getpid());
  ourtime = make_dos_date(time(NULL));
  SSVAL(outbuf,smb_vwv8,p[0]);
  SSVAL(outbuf,smb_vwv9,p[1]);
  SSVAL(outbuf,smb_vwv10, TimeDiff() / 60 );

  Protocol = PROT_LANMAN1;

  return outsize;
}

/* List of supported protocols, most desired first */
struct {
  char *proto_name;
  int (*proto_reply_fn)(char *, int);
} supported_protocols[] = {
#if LANMAN1
  {"LANMAN1.0", reply_lanman1 },
  {"MICROSOFT NETWORKS 3.0", reply_lanman1 },
#endif
  {"MICROSOFT NETWORKS 1.03", reply_coreplus },/* core+ protocol */
  {"PC NETWORK PROGRAM 1.0", reply_corep}, /* core protocol */
  {NULL,NULL},
};

/****************************************************************************
  reply to a negprot
****************************************************************************/
int reply_negprot(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = set_message(outbuf,1,0);
  int index;
  int choice=-1;
  int protocol;
  char *p;
  int bcc = SVAL(smb_buf(inbuf),-2);

  /* Check for protocols, most desirable first */
  for (protocol = 0; supported_protocols[protocol].proto_name; protocol++)
    {
      p = smb_buf(inbuf)+1;
      index = 0;
      while (p < (smb_buf(inbuf) + bcc))
	{ 
	  Debug(2,"protocol [%s]\n",p);
	  if (strequal(p,supported_protocols[protocol].proto_name))
	    choice = index;
	  index++;
	  p += strlen(p) + 2;
	}
      if(choice != -1)
	break;
    }
  
  SSVAL(outbuf,smb_vwv0,choice);
  if(choice != -1)
    {
      outsize = supported_protocols[protocol].proto_reply_fn(outbuf,choice);
      Debug(2,"Chose protocol %s\n",supported_protocols[protocol].proto_name);
    }
  else {
    Debug(0,"No protocol supported !\n");
  }

#if 0
  {
    uint32 ddate = make_dos_date(time(NULL));
    memcpy(outbuf+smb_vwv8,&ddate,sizeof(ddate));
  }
#endif
  
  Debug(2,"%s negprot index=%d\n",timestring(),choice);

  return(outsize);
}

/****************************************************************************
  parse a connect packet
****************************************************************************/
void parse_connect(char *buf,char *service,char *user,char *password)
{
  char *p = smb_buf(buf) + 1;
  char *p2;
  
  p2 = strrchr(p,'\\');
  if (p2 == NULL)
    strcpy(service,p);
  else
    strcpy(service,p2+1);
  
  p += strlen(p) + 2;
  
  strcpy(password,p);
  
  *user = 0;
  p = strchr(service,'%');
  if (p != NULL)
    {
      *p = 0;
      strcpy(user,p+1);
    }
}

/****************************************************************************
  reply to a tcon
****************************************************************************/
int reply_tcon(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring service="";
  pstring user="";
  pstring password="";
  int connection_num;
  int outsize;
  int uid = SVAL(inbuf,smb_uid);
  int vuid;

  vuid = valid_uid(uid);
  
  parse_connect(inbuf,service,user,password);

  connection_num = make_connection(service,user,password,vuid);
  
  if (connection_num < 0)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,2,0);
  SSVAL(outbuf,smb_vwv0,MIN(lp_maxxmit(),BUFFER_SIZE)-4);
  SSVAL(outbuf,smb_vwv1,connection_num);
  SSVAL(outbuf,smb_tid,connection_num);
  
  Debug(2,"%s tcon service=%s user=%s cnum=%d\n",timestring(),service,user,connection_num);
  
  return(outsize);
}


/****************************************************************************
  reply to a tcon and X
****************************************************************************/
int reply_tcon_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring service="";
  pstring user="";
  pstring password="";
  int connection_num;
  int outsize;
  int uid = SVAL(inbuf,smb_uid);
  int vuid;
  int smb_com2 = SVAL(inbuf,smb_vwv0);
  int smb_off2 = SVAL(inbuf,smb_vwv1);

  /* we might have to close an old one */
  if ((SVAL(inbuf,smb_vwv2) & 0x1) != 0)
    close_cnum(SVAL(inbuf,smb_tid));
  
  vuid = valid_uid(uid);
  
  parse_connect(inbuf,service,user,password);

  connection_num = make_connection(service,user,password,vuid);
  
  if (connection_num < 0)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,2,3);
  
  Debug(2,"%s tconX service=%s user=%s cnum=%d\n",timestring(),service,user,connection_num);
  
  /* set the incoming and outgoing tid to the just created one */
  SSVAL(inbuf,smb_tid,connection_num);
  SSVAL(outbuf,smb_tid,connection_num);

  CVAL(outbuf,smb_vwv0) = smb_com2;
  SSVAL(outbuf,smb_vwv1,(chain_size + outsize)-4);

  strcpy(smb_buf(outbuf),"A:");

  if (smb_com2 != 0xFF)
    outsize += chain_reply(smb_com2,inbuf,inbuf+smb_off2+4,
			   outbuf,outbuf+outsize,
			   length,bufsize);

  return(outsize);
}

/****************************************************************************
  reply to an unknown type
****************************************************************************/
int reply_unknown(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  int type;
  cnum = SVAL(inbuf,smb_tid);
  type = CVAL(inbuf,smb_com);
  
  Debug(0,"%s unknown command type: cnum=%d type=%d (0x%X)\n",timestring(),
	cnum,type,type);
  
  return(ERROR(ERRSRV,ERRnosupport));
}


/****************************************************************************
reply to a session setup command
****************************************************************************/
int reply_sesssetup_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize;
  int sess_uid;
  int   smb_com2;
  int   smb_off2;       
  int   smb_bufsize;    
  int   smb_mpxmax;     
  int   smb_vc_num;     
  uint32   smb_sesskey;    
  int   smb_apasslen;   
  pstring smb_apasswd="";
  pstring smb_aname="";    
  BOOL guest=False;
  
  sess_uid = SVAL(inbuf,smb_uid);
  smb_com2 = CVAL(inbuf,smb_vwv0);
  smb_off2 = SVAL(inbuf,smb_vwv1);
  smb_bufsize = SVAL(inbuf,smb_vwv2);
  smb_mpxmax = SVAL(inbuf,smb_vwv3);
  smb_vc_num = SVAL(inbuf,smb_vwv4);
  smb_sesskey = IVAL(inbuf,smb_vwv5);
  smb_apasslen = SVAL(inbuf,smb_vwv7);

  strncpy(smb_apasswd,smb_buf(inbuf),smb_apasslen);
  strncpy(smb_aname,smb_buf(inbuf)+smb_apasslen,sizeof(smb_aname));

  Debug(2,"sesssetupX:name=[%s]\n",smb_aname);

  if (strequal(smb_aname,lp_guestaccount()) && (*smb_apasswd == 0))
    guest = True;
  
  /* now check if it's a valid username/password */
  if (!guest && !password_ok(smb_aname,smb_apasswd))
    return(ERROR(ERRSRV,ERRbadpw));

  /* it's ok - setup a reply */
  outsize = set_message(outbuf,3,0);

  CVAL(outbuf,smb_vwv0) = smb_com2;
  SSVAL(outbuf,smb_vwv1,(chain_size+outsize)-4);

  if (guest)
    SSVAL(outbuf,smb_vwv2,1);


  /* register the name and uid as being validated, so further connections
     to a uid can get through without a password, on the same VC */
  register_uid(SVAL(inbuf,smb_uid),smb_aname,guest);
  
  if (smb_com2 != 0xFF)
    outsize += chain_reply(smb_com2,inbuf,inbuf+smb_off2+4,
			   outbuf,outbuf+outsize,
			   length,bufsize);

  maxxmit = MIN(lp_maxxmit(),smb_bufsize);

  return(outsize);
}

/****************************************************************************
  reply to a chkpth
****************************************************************************/
int reply_chkpth(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize;
  int cnum,mode;
  pstring name="";
  BOOL ok = False;
  int len;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  
  strcpy(name,smb_buf(inbuf) + 1);
  unix_format(name);
  strlower(name);
  mode = SVAL(inbuf,smb_vwv0);
  len = strlen(name);
  
  if (become_user(cnum))
    {
      if (reduce_name(name,HOME(cnum)))
	ok = directory_exist(name);
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRDOS,ERRbadpath));
  
  outsize = set_message(outbuf,0,0);
  
  Debug(2,"%s chkpth %s cnum=%d mode=%d\n",timestring(),name,cnum,mode);
  
  return(outsize);
}

/****************************************************************************
  reply to a getatr
****************************************************************************/
int reply_getatr(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname="";
  int cnum;
  int outsize;
  struct stat sbuf;
  BOOL ok = False;
  int mode;
  uint32 size;
  time_t mtime;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  
  strcpy(fname,smb_buf(inbuf) + 1);
  unix_format(fname);
  strlower(fname);

  if (become_user(cnum))
    {
      if (reduce_name(fname,HOME(cnum)))
	if (stat(fname,&sbuf) == 0)
	  {
	    mode = dos_mode(cnum,fname,sbuf.st_mode);
	    size = sbuf.st_size;
	    mtime = sbuf.st_mtime;
	    ok = True;
	  }
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRDOS,ERRbadfile));
  
  outsize = set_message(outbuf,10,0);

  SSVAL(outbuf,smb_vwv0,mode);
  SSVAL(outbuf,smb_vwv1,mtime&0xFFFF);
  SSVAL(outbuf,smb_vwv2,mtime>>16);
  SSVAL(outbuf,smb_vwv3,(size & 0xFFFF));
  SSVAL(outbuf,smb_vwv4,(size >> 16));
  
  Debug(2,"%s getatr name=%s mode=%d size=%d\n",timestring(),fname,mode,size);
  
  return(outsize);
}

/****************************************************************************
  reply to a setatr
****************************************************************************/
int reply_setatr(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname="";
  int cnum;
  int outsize;
  BOOL ok=False;
  int mode;
  time_t mtime;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  
  strcpy(fname,smb_buf(inbuf) + 1);
  unix_format(fname);
  strlower(fname);

  mode = SVAL(inbuf,smb_vwv0);
  mtime = SVAL(inbuf,smb_vwv1) | (SVAL(inbuf,smb_vwv2) << 16);
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRSRV,ERRaccess));
  
  if (become_user(cnum))
    {
      if (reduce_name(fname,HOME(cnum)))
	ok =  (chmod(fname,unix_mode(cnum,mode)) == 0);
      if (ok)
	ok = set_filetime(fname,mtime);
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,0,0);
  
  Debug(2,"%s setatr name=%s mode=%d\n",timestring(),fname,mode);
  
  return(outsize);
}


/****************************************************************************
  return number of 1K blocks available on a path and total number 
****************************************************************************/
void disk_free(char *path,int *bsize,int *dfree,int *dsize)
{
  struct statfs fs;

  if (statfs(path,&fs) != 0)
    {
      *bsize = 0;
      *dfree = 0;
      *dsize = 0;
    }
  else
    {
      *bsize = fs.f_bsize;
      *dfree = fs.f_bavail;
      *dsize = fs.f_blocks;
    }
  
  /* normalise for DOS usage */
  while (*dfree > WORDMAX || *dsize > WORDMAX) {
    *dfree /= 2;
    *dsize /= 2;
    *bsize *= 2;
  }


}

/****************************************************************************
  reply to a dskattr
****************************************************************************/
int reply_dskattr(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  int outsize;
  int dfree,dsize,bsize;
  BOOL ok=False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  
  if (become_user(cnum))
    {
      disk_free("./",&bsize,&dfree,&dsize);
      ok = True;
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRSRV,ERRaccess));
  
  outsize = set_message(outbuf,5,0);
  
  SSVAL(outbuf,smb_vwv0,dsize);
  SSVAL(outbuf,smb_vwv1,1);
  SSVAL(outbuf,smb_vwv2,bsize);
  SSVAL(outbuf,smb_vwv3,dfree);
  
  Debug(2,"%s dskattr cnum=%d dfree=%d\n",timestring(),cnum,dfree);
  
  return(outsize);
}


/****************************************************************************
  reply to a search
****************************************************************************/
int reply_search(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring mask="";
  pstring directory="";
  pstring fname="";
  int size,mode;
  time_t date;
  int dirtype;
  int cnum;
  int outsize;
  int numentries = 0;
  BOOL finished = False;
  int maxentries;
  int i;
  char *p;
  BOOL ok = False;
  int status_len;
  char *path;
  char status[21];
  int dptr_num=-1;
  BOOL check_descend = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  outsize = set_message(outbuf,1,3);
  maxentries = SVAL(inbuf,smb_vwv0); 
  dirtype = SVAL(inbuf,smb_vwv1);
  path = smb_buf(inbuf) + 1;
  status_len = SVAL(smb_buf(inbuf),3 + strlen(path));

  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  
  /* dirtype &= ~aDIR; */
  
  Debug(2,"path=%s status_len=%d\n",path,status_len);

  
  if (status_len == 0)
    {
      strcpy(directory,smb_buf(inbuf)+1);
      unix_format(directory);
      strlower(directory);
      p = strrchr(directory,'/');
      if (p == NULL) 
	{strcpy(mask,directory);*directory = 0;}
      else
	{*p = 0;strcpy(mask,p+1);}
      if (strlen(directory) == 0)
	strcpy(directory,"./");
      strlower(mask);
      memset(status,0,21);
      CVAL(status,0) = dirtype;
    }
  else
    {
      memcpy(status,smb_buf(inbuf) + 1 + strlen(path) + 4,21);
      memcpy(mask,status+1,11);
      mask[11] = 0;
      Connections[cnum].dirptr = dptr_fetch(status+12,&dptr_num);      
      dirtype = CVAL(status,0) & 0x1F;
      if (!Connections[cnum].dirptr)
	return(ERROR(ERRDOS,eNO_MORE_FILES));
      strncpy(Connections[cnum].dirpath,dptr_path(dptr_num),sizeof(pstring));
      strlower(mask);
    }
  

  Debug(2,"mask=%s directory=%s\n",mask,directory);
  CVAL(smb_buf(outbuf),0) = 5;
  
  if (become_user(cnum))
    {
      char *p = smb_buf(outbuf) + 3;
      
      ok = True;
      
      if (status_len == 0)
	{
	  if (!start_dir(cnum,directory))
	    ok = False;
	  else
	    dptr_num = dptr_create(Connections[cnum].dirptr,directory);
	}

      Debug(3,"dptr_num is %d\n",dptr_num);

      if (ok)
	{
	  if ((dirtype & aVOLID) != 0)
	    {	  
	      memcpy(p,status,21);
	      make_dir_struct(p,"???????????",SERVICE(SNUM(cnum)),0,aVOLID,0);
	      dptr_fill(p+12,dptr_num);
	      if (dptr_zero(p+12))
		numentries = 1;
	      else
		numentries = 0;
	    }
	  else
	    {
	      if (in_list(Connections[cnum].dirpath,
			  lp_dontdescend(SNUM(cnum)),True))
		check_descend = True;

	      for (i=0;(i<maxentries) && !finished;i++)
		{
		  finished = 
		    !get_dir_entry(cnum,mask,dirtype,fname,&size,&mode,&date,check_descend);
		  if (!finished)
		    {
		      strupper(fname);
		      memcpy(p,status,21);
		      make_dir_struct(p,mask,fname,size,mode,date);
		      dptr_fill(p+12,dptr_num);
		      numentries++;
		    }
		  p += DIR_STRUCT_SIZE;
		}
	    }
	}
      unbecome_user();
    }
#if 1
  if ((numentries == 0 && status_len != 0) || !ok)
#else
    if (finished || !ok)
#endif
      {
	CVAL(outbuf,smb_rcls) = ERRDOS;
	SSVAL(outbuf,smb_err,eNO_MORE_FILES);
	if (dptr_num >= 0)
	  dptr_demote(dptr_num);
      }

  SSVAL(outbuf,smb_vwv0,numentries);
  SSVAL(outbuf,smb_vwv1,3 + numentries * DIR_STRUCT_SIZE);
  CVAL(smb_buf(outbuf),0) = 5;
  SSVAL(smb_buf(outbuf),1,numentries*DIR_STRUCT_SIZE);
  
  outsize += DIR_STRUCT_SIZE*numentries;
  smb_setlen(outbuf,outsize - 4);
  
  Debug(2,"%s search mask=%s directory=%s cnum=%d dirtype=%d numentries=%d\n",timestring(),mask,directory,cnum,dirtype,numentries);

  return(outsize);
}


/****************************************************************************
  reply to an open
****************************************************************************/
int reply_open(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname="";
  int cnum;
  int fnum = -1;
  int outsize;
  int mode,share,fmode,attribute;
  int openmode = 0;
  BOOL ok = False;
  int size = 0;
  time_t mtime;
  int unixmode;
  int rmode;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  share = SVAL(inbuf,smb_vwv0);
  mode = share & 0xF;
#if 0
  attribute = SVAL(inbuf,smb_vwv1);
#else
  /* X/Open says to ignore this */
  attribute = aARCH;
#endif
  strcpy(fname,smb_buf(inbuf)+1);
  unix_format(fname);
  strlower(fname);
  
  rmode = mode;

  switch (mode)
    {
    case 0: 
      openmode = O_RDONLY; 
      break;
    case 1: 
      openmode = O_WRONLY; 
      break;
    case 0xF: 
      mode = 2;      
    case 2: 
      openmode = O_RDWR; 
      break;
    default:
      rmode = 0;
      openmode = O_RDONLY;
      break;
    }
  
  
  if ((openmode != O_RDONLY) && !CAN_WRITE(cnum))
    return(ERROR(ERRSRV,ERRaccess));
  
  if (become_user(cnum))
    {
      ok = True;
      fnum = find_free_file();

      if (!reduce_name(fname,HOME(cnum)))
	  ok = False;      

      if (fnum >= 0 && ok)
	{
#if 0
	  /* X/Open says fail if doesn't exist ?? even for WRONLY ?? */
	  if (openmode != O_RDONLY) openmode |= O_CREAT;
#endif
	  unixmode = unix_mode(cnum,attribute);

	  Files[fnum].fd = open(fname,openmode,unixmode);
	  if (Files[fnum].fd >= 0)
	    {
	      struct stat sbuf;
	      if (fstat(Files[fnum].fd,&sbuf) == 0)
		{
		  size = sbuf.st_size;
		  fmode = dos_mode(cnum,fname,sbuf.st_mode);
		  mtime = sbuf.st_mtime + TimeDiff();
		  if (fmode & aDIR)
		    {
		      close(Files[fnum].fd);
		      ok = False;
		    }
		}	      
	      if (ok)
		{
		  num_files_open++;
		  Files[fnum].open = True;
		  Files[fnum].can_lock = (openmode != O_RDONLY);
		  Files[fnum].read_only = (openmode == O_RDONLY);
		  Files[fnum].cnum = cnum;
		  strcpy(Files[fnum].name,fname);
		}
	    }
	  else
	    fnum = -1;
	}
      unbecome_user();
    }
  
  /* XXXX need to give right error code - could be permission denied */
  if ((fnum < 0) || !ok)
    return(ERROR(ERRDOS,eFILE_NOT_FOUND));
  
  outsize = set_message(outbuf,7,0);
  SSVAL(outbuf,smb_vwv0,fnum);
  SSVAL(outbuf,smb_vwv1,fmode);
  SIVAL(outbuf,smb_vwv2,mtime);
  SIVAL(outbuf,smb_vwv4,size);
  SSVAL(outbuf,smb_vwv6,rmode);
  
  
  Debug(2,"%s open %s fd=%d fnum=%d cnum=%d mode=%d omode=%d (numopen=%d)\n",timestring(),fname,Files[fnum].fd,fnum,cnum,mode,openmode,num_files_open);
  
  return(outsize);
}


/****************************************************************************
  reply to an open and X
****************************************************************************/
int reply_open_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname="";
  int cnum = SVAL(inbuf,smb_tid);
  int fnum = -1;
  int outsize;
  int openmode = 0;
  BOOL ok = False;
  int smb_com2 = CVAL(inbuf,smb_vwv0);
  int smb_off2 = SVAL(inbuf,smb_vwv1);
  int smb_mode = SVAL(inbuf,smb_vwv3);
  int smb_attr = SVAL(inbuf,smb_vwv5);
#if 0
  int smb_flags = SVAL(inbuf,smb_vwv2);
  int smb_sattr = SVAL(inbuf,smb_vwv4); 
  uint32 smb_time = IVAL(inbuf,smb_vwv6);
#endif
  int smb_ofun = SVAL(inbuf,smb_vwv8);
  BOOL file_existed = False;
  int unixmode;
  int size,fmode,mtime,rmode;


  Debug(3,"open inbuf = %d\n",(int)inbuf);

  /* XXXX we need to handle passed times, sattr and flags */

  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  strcpy(fname,smb_buf(inbuf));
  unix_format(fname);
  strlower(fname);
  
  rmode = smb_mode & 0x7;

  switch (smb_mode & 0x7)
    {
    case 0:       
      openmode = O_RDONLY; 
      break;
    case 1: 
      openmode = O_WRONLY; 
      break;
    case 0x7: 
    case 2: 
      rmode = 2;
      openmode = O_RDWR; 
      break;
    case 3:  /* map execute to read */
      openmode = O_RDONLY; 
      break;
    default:
      rmode = 0;
      openmode = O_RDONLY;
      break;
    }
  
  
  if ((openmode != O_RDONLY) && !CAN_WRITE(cnum))
    return(ERROR(ERRSRV,ERRaccess));

  /* now add create and trunc bits */
  if (smb_ofun & 0x10)
    openmode |= O_CREAT;
  if ((smb_ofun & 0x3) == 2)
    openmode |= O_TRUNC;
  
  if (become_user(cnum))
    {
      ok = True;
      fnum = find_free_file();

      if (!reduce_name(fname,HOME(cnum)))
	  ok = False;      

      if (fnum >= 0 && ok)
	{
	  unixmode = unix_mode(cnum,smb_attr);

	  Files[fnum].fd = -1;

	  file_existed = file_exist(fname);

	  if ((smb_ofun & 0x3) == 0 && file_existed)
	    {
	      unbecome_user();	      
	      return(ERROR(ERRDOS,ERRbadfile));
	    }

	  Files[fnum].fd = open(fname,openmode,unixmode);
	  if (Files[fnum].fd >= 0)
	    {
	      struct stat sbuf;
	      if (fstat(Files[fnum].fd,&sbuf) == 0)
		{
		  size = sbuf.st_size;
		  fmode = dos_mode(cnum,fname,sbuf.st_mode);
		  mtime = sbuf.st_mtime;
		  if (fmode & aDIR)
		    {
		      close(Files[fnum].fd);
		      ok = False;
		    }
		}	 
	      if (ok)
		{
		  num_files_open++;
		  Files[fnum].open = True;
		  Files[fnum].can_lock = (openmode != O_RDONLY);
		  Files[fnum].read_only = (openmode == O_RDONLY);
		  Files[fnum].cnum = cnum;
		  strcpy(Files[fnum].name,fname);
		}
	    }
	  else
	    fnum = -1;
	}
      unbecome_user();
    }
  
  if ((fnum < 0) || !ok)
    return(ERROR(ERRDOS,eFILE_NOT_FOUND));
  
  outsize = set_message(outbuf,15,0);
  CVAL(outbuf,smb_vwv0) = smb_com2;
  SSVAL(outbuf,smb_vwv1,(chain_size+outsize)-4);
  SSVAL(outbuf,smb_vwv2,fnum);
  SSVAL(outbuf,smb_vwv3,fmode);
  SIVAL(outbuf,smb_vwv4,mtime);
  SIVAL(outbuf,smb_vwv6,size);
  SSVAL(outbuf,smb_vwv8,rmode);

  if (file_existed && !(openmode & O_TRUNC))
    SSVAL(outbuf,smb_vwv11,1);
  if (!file_existed)
    SSVAL(outbuf,smb_vwv11,2);
  if (file_existed && (openmode & O_TRUNC))
    SSVAL(outbuf,smb_vwv11,3);

  Debug(2,"%s openX %s fd=%d fnum=%d cnum=%d mode=%d omode=%d (numopen=%d)\n",
	timestring(),fname,Files[fnum].fd,fnum,cnum,
	smb_mode,openmode,num_files_open);

  chain_fnum = fnum;

  if (smb_com2 != 0xFF)
    outsize += chain_reply(smb_com2,inbuf,inbuf+smb_off2+4,
			   outbuf,outbuf+outsize,
			   length,bufsize);

  chain_fnum = -1;
  
  return(outsize);
}



/****************************************************************************
  reply to a mknew
****************************************************************************/
int reply_mknew(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname="";
  int cnum,com;
  int fnum = -1;
  int outsize;
  int createmode;
  
  mode_t unixmode;
  BOOL ok = False;
  
  com = SVAL(inbuf,smb_com);
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  createmode = SVAL(inbuf,smb_vwv0);
  strcpy(fname,smb_buf(inbuf)+1);
  unix_format(fname);
  strlower(fname);

  if (createmode & aVOLID)
    {
      Debug(0,"Attempt to create file (%s) with volid set - please report this\n",fname);
    }
  
  unixmode = unix_mode(cnum,createmode);
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRSRV,ERRaccess));
  
  if (become_user(cnum))
    {
      if (com == SMBmknew && file_exist(fname))
	return(ERROR(ERRDOS,eACCESS_DENIED));
      ok = True;
      fnum = find_free_file();

      if (!reduce_name(fname,HOME(cnum)))
	  ok = False;      

      if (fnum >= 0 && ok)
	{
	  Files[fnum].fd = open(fname,O_RDWR | O_CREAT | O_TRUNC,unixmode);
	  if (Files[fnum].fd >= 0)
	    {
	      num_files_open++;
	      Files[fnum].open = True;
	      Files[fnum].can_lock = True;
	      Files[fnum].read_only = False;
	      Files[fnum].cnum = cnum;
	      strcpy(Files[fnum].name,fname);
	    }
	  else
	    fnum = -1;
	}
      unbecome_user();
    }
  
  if (!ok || (fnum < 0))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,1,0);
  SSVAL(outbuf,smb_vwv0,fnum);
  
  Debug(2,"%s mknew %s fd=%d fnum=%d cnum=%d dmode=%d umode=%o\n",timestring(),fname,Files[fnum].fd,fnum,cnum,createmode,unixmode);
  
  return(outsize);
}

/****************************************************************************
  reply to a create temporary file
****************************************************************************/
int reply_ctemp(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring fname="";
  pstring fname2="";
  int cnum;
  int fnum = -1;
  int outsize;
  int createmode;
  
  mode_t unixmode;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  createmode = SVAL(inbuf,smb_vwv0);
  sprintf(fname,"%s/TMXXXXXX",smb_buf(inbuf)+1);
  unix_format(fname);
  strlower(fname);
  
  unixmode = unix_mode(cnum,createmode);
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      ok = True;
      fnum = find_free_file();

      if (!reduce_name(fname,HOME(cnum)))
	  ok = False;      

      if (fnum >= 0 && ok)
	{
	  strcpy(fname2,mktemp(fname));
	  Files[fnum].fd = creat(fname2,unixmode);
	  if (Files[fnum].fd >= 0)
	    {
	      num_files_open++;
	      Files[fnum].open = True;
	      Files[fnum].cnum = cnum;
	      strcpy(Files[fnum].name,fname2);
	    }
	  else
	    fnum = -1;
	}
      unbecome_user();
    }
  
  if (!ok || (fnum < 0))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,1,2 + strlen(fname2));
  SSVAL(outbuf,smb_vwv0,fnum);
  CVAL(smb_buf(outbuf),0) = 4;
  strcpy(smb_buf(outbuf) + 1,fname2);
  
  Debug(2,"%s ctemp %s fd=%d fnum=%d cnum=%d dmode=%d umode=%o\n",timestring(),fname2,Files[fnum].fd,fnum,cnum,createmode,unixmode);
  
  return(outsize);
}


/****************************************************************************
  reply to a unlink
****************************************************************************/
int reply_unlink(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize;
  pstring name="";
  BOOL isrootdir;
  int cnum;
  int dirtype;
  pstring directory="";
  pstring mask="";
  char *p;
  int count=0;
  
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  dirtype = SVAL(inbuf,smb_vwv0);
  
  strcpy(name,smb_buf(inbuf) + 1);
  unix_format(name);
  strlower(name);

  p = strrchr(name,'/');
  if (!p)
    {
      strcpy(directory,"./");
      strncpy(mask,name,20);
    }
  else
    {
      *p = 0;
      strcpy(directory,name);
      strcpy(mask,p+1);
    }

  isrootdir = (strequal(directory,"./") ||
	       strequal(directory,"."));
  
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      void *dirptr = NULL;
      struct DIRECT *dptr;

      if (reduce_name(directory,HOME(cnum)))
	dirptr = (void *)opendir(directory);

      if (dirptr)
	{
	  ok = True;
	  while ((dptr = readdir(dirptr)))
	    {
	      pstring fname="";
	      int fmode;

	      if (mask_match(dptr->d_name,mask,!isrootdir,True))
		{
		  struct stat sbuf;
		  sprintf(fname,"%s/%s",directory,dptr->d_name);
		  if (stat(fname,&sbuf) != 0) continue;
		  fmode = dos_mode(cnum,fname,sbuf.st_mode);
		  if ((fmode & aDIR) != 0) continue;
		  if ((fmode & aRONLY) != 0) continue;
		  if (((fmode & ~dirtype) & (aHIDDEN | aSYSTEM)) != 0)
		    continue;		  
		  unlink(fname);
		  count++;
		}		
	    }
	  closedir(dirptr);
	}
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));

  if (count == 0)
    return(ERROR(ERRDOS,ERRbadfile));

  outsize = set_message(outbuf,0,0);
  
  return(outsize);
}

/****************************************************************************
   reply to a readbraw (core+ protocol)
****************************************************************************/
int reply_readbraw(char *inbuf, char *outbuf, int length, int bufsize)
{
  extern int Client;
  int cnum,maxcount,mincount,timeout,fnum;
  BOOL nonblocking = False;
  int nread = -1;
  int ret=0, nwritten;
  int startpos;
  BOOL ok = False;
  char read_buf[4+65535];
 
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  fnum = SVAL(inbuf,smb_vwv0);
  startpos = SVAL(inbuf,smb_vwv1) + (SVAL(inbuf,smb_vwv2) << 16);
  maxcount = SVAL(inbuf,smb_vwv3);
  mincount = SVAL(inbuf,smb_vwv4);
  timeout = SVAL(inbuf,smb_vwv5);
  if(timeout == 0)
    nonblocking = True;
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(Files[fnum].fd,startpos,SEEK_SET);
	  if(!Files[fnum].can_lock ||
	    lockf(Files[fnum].fd,F_TEST,maxcount)==0 )
	    {
	      nread = read_with_timeout(Files[fnum].fd,
					&read_buf[4],mincount, maxcount,
					(long)timeout);
	      ok = True;
	    }
	}
      unbecome_user();
    }
  
  
  Debug(2,"%s readbraw fnum=%d cnum=%d max=%d min=%d timeout=%d nread=%d\n",timestring(),fnum,cnum,
	maxcount,mincount,timeout,nread);
  
  if ((nread < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  /* Set up a return message and send it directly to the SMB redirector.
	 Return -1 to signal no reply should be sent */
  /* Set up the Netbios message header */
  CVAL(read_buf,0) = 0;
  CVAL(read_buf,1) = 0;
  CVAL(read_buf,2) = (nread >> 8) & 0xFF;
  CVAL(read_buf,3) = nread & 0xFF;
  if (nread >= (1 << 16))
    CVAL(read_buf,1) |= 1;

  nread += 4; /* Include header */
  nwritten = 0;

  while (nwritten < nread)
    {
    ret = write_socket(Client,read_buf+nwritten,nread - nwritten);
    if (ret <= 0)
      {
      Debug(0,"Error writing %d bytes to client. %d. Exiting\n",nread-nwritten,ret);
      close_sockets();
      exit(1);
      }
    nwritten += ret;
  }

  return -1;
}

/****************************************************************************
  reply to a lockread (core+ protocol)
****************************************************************************/
int reply_lockread(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,fnum;
  int nread = -1;
  char *data;
  int outsize;
  uint32 startpos, numtoread;
  int eclass;
  uint32 ecode;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);
  numtoread = SVAL(inbuf,smb_vwv1);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  
  outsize = set_message(outbuf,5,3);
  numtoread = MIN(bufsize-outsize,numtoread);
  data = smb_buf(outbuf) + 3;
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
		{
  		if(do_lock( fnum, cnum, numtoread, startpos, &eclass, &ecode))
	    	return (ERROR(eclass,ecode));
	  	lseek(Files[fnum].fd,startpos,SEEK_SET);
      	nread = read(Files[fnum].fd,data,numtoread);
	  	ok = True;	  
		}
      unbecome_user();
    }
  
  if ((nread < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize += nread;
  SSVAL(outbuf,smb_vwv0,nread);
  SSVAL(outbuf,smb_vwv5,nread+3);
  SSVAL(smb_buf(outbuf),1,nread);
  
  Debug(2,"%s lockread fnum=%d cnum=%d num=%d nread=%d\n",timestring(),fnum,cnum,numtoread,nread);
  
  return(outsize);
}

/****************************************************************************
  reply to a read
****************************************************************************/
int reply_read(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,numtoread,fnum;
  int nread = -1;
  char *data;
  int startpos;
  int outsize;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);
  numtoread = SVAL(inbuf,smb_vwv1);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  
  outsize = set_message(outbuf,5,3);
  numtoread = MIN(bufsize-outsize,numtoread);
  data = smb_buf(outbuf) + 3;
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(Files[fnum].fd,startpos,SEEK_SET);
	  if (!Files[fnum].can_lock ||
	      lockf(Files[fnum].fd,F_TEST,numtoread) == 0)
	    {
	      nread = read(Files[fnum].fd,data,numtoread);
	      ok = True;
	    }
	}
      unbecome_user();
    }
  
  
  if ((nread < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize += nread;
  SSVAL(outbuf,smb_vwv0,nread);
  SSVAL(outbuf,smb_vwv5,nread+3);
  SSVAL(smb_buf(outbuf),1,nread);
  
  Debug(2,"%s read fnum=%d cnum=%d num=%d nread=%d\n",timestring(),fnum,cnum,numtoread,nread);
  
  return(outsize);
}


/****************************************************************************
  reply to a read and X
****************************************************************************/
int reply_read_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int smb_com2 = CVAL(inbuf,smb_vwv0);
  int smb_off2 = SVAL(inbuf,smb_vwv1);
  int smb_fid = SVAL(inbuf,smb_vwv2);
  uint32 smb_offset = IVAL(inbuf,smb_vwv3);
  int smb_maxcnt = SVAL(inbuf,smb_vwv5);
  int smb_mincnt = SVAL(inbuf,smb_vwv6);
#if 0
  uint32 smb_timeout = SVAL(inbuf,smb_vwv7);
#endif
  int cnum;
  int nread = -1;
  char *data;
  int outsize;
  BOOL ok = False;

  if (chain_fnum >= 0)
    smb_fid = chain_fnum;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  outsize = set_message(outbuf,12,0);
  data = smb_buf(outbuf);
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(smb_fid) && (Files[smb_fid].cnum == cnum))
	{
	  lseek(Files[smb_fid].fd,smb_offset,SEEK_SET);
	  if (!Files[smb_fid].can_lock ||
	      lockf(Files[smb_fid].fd,F_TEST,smb_maxcnt) == 0)
	    {
	      nread = read(Files[smb_fid].fd,data,smb_maxcnt);
	      ok = True;
	    }
	}
      unbecome_user();
    }
  
  
  if ((nread < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize += nread;
  CVAL(outbuf,smb_vwv0) = smb_com2;
  SSVAL(outbuf,smb_vwv1,(outsize+chain_size)-4);
  SSVAL(outbuf,smb_vwv5,nread);
  SSVAL(outbuf,smb_vwv6,(int)(data - ((outbuf-chain_size)+4)));
  SSVAL(smb_buf(outbuf),-2,nread);
  
  Debug(2,"%s readX fnum=%d cnum=%d min=%d max=%d nread=%d com2=%d off2=%d\n",
	timestring(),smb_fid,cnum,
	smb_mincnt,smb_maxcnt,nread,smb_com2,smb_off2);

  chain_fnum = smb_fid;

  if (smb_com2 != 0xFF)
    outsize += chain_reply(smb_com2,inbuf,inbuf+smb_off2+4,
			   outbuf,outbuf+outsize,
			   length,bufsize);
  
  chain_fnum = -1;
  
  return(outsize);
}

/****************************************************************************
  reply to a writebraw (core+ or LANMAN1.0 protocol)
****************************************************************************/
int reply_writebraw(char *inbuf,char *outbuf,int length,int bufsize)
{
  extern int Client;
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  long total_written = 0;
  int outsize = 0;
  long startpos, timeout;
  char *data;
  char read_buf[65536];
  BOOL ok = False;
  BOOL write_through;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  fnum = SVAL(inbuf,smb_vwv0);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  timeout = SVAL(inbuf,smb_vwv5) + (SVAL(inbuf,smb_vwv6) << 16);
  write_through = SVAL(inbuf,smb_vwv7) & 1;

  /* We have to deal with slightly different formats depending
     on whether we are using the core+ or lanman1.0 protocol */
  if(Protocol == PROT_COREPLUS) {
    numtowrite = SVAL(smb_buf(inbuf),-2);
    /* NB there is no length field here */
    data = smb_buf(inbuf);
  } else { /* LANMAN1.0 Protocol */
    numtowrite = SVAL(inbuf,smb_vwv10);
    data = inbuf + 4 + SVAL(inbuf, smb_vwv11);
  }
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(Files[fnum].fd,startpos,SEEK_SET);
	  if (!Files[fnum].can_lock ||
	      lockf(Files[fnum].fd,F_TEST,numtowrite) == 0)
	    {
	      nwritten = write_with_timeout(Files[fnum].fd,
					    data,numtowrite,
					    timeout);
	      if(write_through)
		fsync(Files[fnum].fd);
	      ok = True;
	    }
  
	  Debug(2,"%s writebraw message 1 fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,numtowrite,nwritten);

	  if ((nwritten <= 0) || !ok) {
	    unbecome_user();
	    return(ERROR(ERRDOS,eACCESS_DENIED));
	  }

	  total_written = nwritten;

	  /* Return a message to the redirector to tell it
	     to send more bytes */
	  outsize = set_message(outbuf,0,0);
	  smb_setlen(outbuf, outsize-4);
	  send_smb(outbuf);

	  /* Now read the raw data into the buffer and write it */
	  if(!read_data(Client,read_buf,4)) {
	    Debug(0,"Failed to read length of secondary writebraw\n");
	    close_sockets();
	    exit(1);
	  }
	  /* Even though this is not an smb message, smb_len
	     returns the generic length of an smb message */
	  numtowrite = smb_len(read_buf);
	  if(!read_data(Client,read_buf,numtowrite)) {
	    Debug(0,"Failed to read data in secondary writebraw\n");
	    close_sockets();
	    exit(1);
	  }


	  /* Set up outbuf to return the correct type of error message */
	  CVAL(outbuf,smb_com) = SMBwritec;
	  outsize = set_message(outbuf,1,0);
	  SSVAL(outbuf,smb_vwv0,total_written);

	  nwritten = 0;

	  /* Try and lock the new range */
	  if (!Files[fnum].can_lock ||
	      lockf(Files[fnum].fd,F_TEST,numtowrite) == 0)
	    {
	      nwritten = write_with_timeout(Files[fnum].fd,
					    data,numtowrite,
					    timeout);
	      if(write_through)
		fsync(Files[fnum].fd);
	      ok = True;
	    }
	  if ((nwritten <= 0) || !ok) {
	    unbecome_user();
	    return(ERROR(ERRDOS,eACCESS_DENIED));
	  }

	  total_written += nwritten;
	  SSVAL(outbuf,smb_vwv0,total_written);
	}
      unbecome_user();
    }

  /* We have to deal with slightly different formats depending
     on whether we are using the core+ or lanman1.0 protocol */
  if(Protocol == PROT_COREPLUS) {
    outsize = set_message(outbuf,0,0);
  } else { /* LANMAN1.0 Protocol */
    outsize = set_message(outbuf,1,0);
    SSVAL(outbuf,smb_vwv0,-1);  /* We don't support smb_remaining */
  }
  return(outsize);
}

/****************************************************************************
  reply to a writeunlock (core+)
****************************************************************************/
int reply_writeunlock(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,fnum;
  int nwritten = -1;
  int outsize;
  int fd;
  char *data;
  uint32 numtowrite,startpos;
  int eclass;
  uint32 ecode;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);
  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  data = smb_buf(inbuf) + 3;
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  fd = Files[fnum].fd;

  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(fd,startpos,SEEK_SET);
	  if (!Files[fnum].can_lock ||
	      lockf(fd,F_TEST,numtowrite) == 0)
	    {
	      /* The special X/Open SMB protocol handling of
			 zero length writes is *NOT* done for
			 this call */
	      if(numtowrite == 0)
			nwritten = 0;
	      else
			nwritten = write(fd,data,numtowrite);
	      ok = True;
	    }
	}
      unbecome_user();
    }
  
  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));

  if(do_unlock(fnum, cnum, numtowrite, startpos, &eclass, &ecode))
    return (ERROR(eclass,ecode));

  outsize = set_message(outbuf,1,0);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  
  Debug(2,"%s writeunlock fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,numtowrite,nwritten);
  
  return(outsize);
}

/****************************************************************************
  reply to a write
****************************************************************************/
int reply_write(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  int outsize;
  int startpos;
  int fd;
  char *data;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);
  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  data = smb_buf(inbuf) + 3;
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  fd = Files[fnum].fd;

  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(fd,startpos,SEEK_SET);
	  if (!Files[fnum].can_lock ||
	      lockf(fd,F_TEST,numtowrite) == 0)
	    {
	      /* X/Open SMB protocol says that if smb_vwv1 is
		 zero then the file size should be extended or
		 truncated to the size given in smb_vwv[2-3] */
	      if(numtowrite == 0)
		nwritten = set_filelen(fd, startpos);
	      else
		nwritten = write(fd,data,numtowrite);
	      ok = True;
	    }
	}
      unbecome_user();
    }
  
  if(((nwritten == 0) && (numtowrite != 0))||(nwritten < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));

  outsize = set_message(outbuf,1,0);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  
  Debug(2,"%s write fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,numtowrite,nwritten);
  
  return(outsize);
}


/****************************************************************************
  reply to a write and X
****************************************************************************/
int reply_write_and_X(char *inbuf,char *outbuf,int length,int bufsize)
{
  int smb_com2 = CVAL(inbuf,smb_vwv0);
  int smb_off2 = SVAL(inbuf,smb_vwv1);
  int fnum = SVAL(inbuf,smb_vwv2);
  uint32 smb_offset = IVAL(inbuf,smb_vwv3);
  int smb_dsize = SVAL(inbuf,smb_vwv10);
  int smb_doff = SVAL(inbuf,smb_vwv11);

  int cnum;
  int nwritten = -1;
  int outsize;
  int fd;
  char *data;
  BOOL ok = False;
  
  if (chain_fnum >= 0)
    fnum = chain_fnum;

  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  data = inbuf + 4 + smb_doff;
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  fd = Files[fnum].fd;

  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(fd,smb_offset,SEEK_SET);
	  if (!Files[fnum].can_lock ||
	      lockf(fd,F_TEST,smb_dsize) == 0)
	    {
	      /* X/Open SMB protocol says that, unlike SMBwrite
		 if the length is zero then NO truncation is
		 done, just a write of zero. To truncate a file,
		 use SMBwrite. */
	      if(smb_dsize == 0)
		nwritten = 0;
	      else
		nwritten = write(fd,data,smb_dsize);
	      ok = True;
	    }
	}
      unbecome_user();
    }
  
  if(((nwritten == 0) && (smb_dsize != 0))||(nwritten < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));

  outsize = set_message(outbuf,6,0);
  
  CVAL(outbuf,smb_vwv0) = smb_com2;
  SSVAL(outbuf,smb_vwv1,(outsize+chain_size)-4);
  SSVAL(outbuf,smb_vwv2,nwritten);
  
  Debug(2,"%s writeX fnum=%d cnum=%d num=%d wrote=%d\n",timestring(),fnum,cnum,smb_dsize,nwritten);

  chain_fnum = fnum;

  if (smb_com2 != 0xFF)
    outsize += chain_reply(smb_com2,inbuf,inbuf+smb_off2+4,
			   outbuf,outbuf+outsize,
			   length,bufsize);
  
  chain_fnum = -1;
  
  return(outsize);
}



/****************************************************************************
  reply to a lseek
****************************************************************************/
int reply_lseek(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,fnum;
  uint32 startpos;
  int32 res=-1;
  int mode;
  int outsize;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);
  mode = SVAL(inbuf,smb_vwv1);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	res = lseek(Files[fnum].fd,startpos,mode);
      ok = True;
      unbecome_user();
    }
  
  
  if ((res < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,2,0);
  SSVAL(outbuf,smb_vwv0,res & 0xFFFF);
  SSVAL(outbuf,smb_vwv1,res >> 16);
  
  Debug(2,"%s lseek fnum=%d cnum=%d pos=%d\n",timestring(),fnum,cnum,startpos);
  
  return(outsize);
}


/****************************************************************************
  reply to a flush
****************************************************************************/
int reply_flush(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = set_message(outbuf,0,0);
  Debug(2,"%s flush\n",timestring());
  
  return(outsize);
}

/****************************************************************************
  reply to a exit
****************************************************************************/
int reply_exit(char *inbuf,char *outbuf,int length,int bufsize)
{
  int outsize = set_message(outbuf,0,0);
  Debug(2,"%s exit\n",timestring());
  
  return(outsize);
}

/****************************************************************************
  reply to a close
****************************************************************************/
int reply_close(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum,cnum;
  int ret=0;
  int outsize;
  BOOL ok = False;  
  time_t mtime;

  outsize = set_message(outbuf,0,0);

  {
    FILE *ff = fopen("/tmp/jnk.close","w");
    if (ff)
      {
	fwrite(inbuf,1,100,ff);
	fclose(ff);
      }
    else
      Debug(3,"open jnk\n");
  }

  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  fnum = SVAL(inbuf,smb_vwv0);
  mtime = IVAL(inbuf,smb_vwv1);

  if (chain_fnum >= 0)
    fnum = chain_fnum;

  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  ret = close(Files[fnum].fd);

	  /* try and set the date */
	  if (!Files[fnum].read_only)
	    set_filetime(Files[fnum].name,mtime);

	  num_files_open--;
	  Files[fnum].open = False;
	  ok = True;
	}
      unbecome_user();
    }
  
  if ((ret < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  

  Debug(2,"%s close fd=%d fnum=%d cnum=%d ret=%d (numopen=%d)\n",
	timestring(),Files[fnum].fd,fnum,cnum,ret,num_files_open);
  
  return(outsize);
}


/****************************************************************************
  reply to a writeclose (Core+ protocol)
****************************************************************************/
int reply_writeclose(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,numtowrite,fnum;
  int nwritten = -1;
  int outsize;
  int startpos;
  char *data;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);
  numtowrite = SVAL(inbuf,smb_vwv1);
  startpos = SVAL(inbuf,smb_vwv2) + (SVAL(inbuf,smb_vwv3) << 16);
  data = smb_buf(inbuf) + 1;
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      if (OPEN_FNUM(fnum) && (Files[fnum].cnum == cnum))
	{
	  lseek(Files[fnum].fd,startpos,SEEK_SET);
	  if (!Files[fnum].can_lock ||
	      lockf(Files[fnum].fd,F_TEST,numtowrite) == 0)
	    {
	      nwritten = write(Files[fnum].fd,data,numtowrite);
	      ok = True;
	    }
	  close(Files[fnum].fd);
	  num_files_open--;
	  Files[fnum].open = False;
	}
      unbecome_user();
    }
  
  Debug(2,"%s writeclose fnum=%d cnum=%d num=%d wrote=%d (numopen=%d)\n",
	timestring(),fnum,cnum,numtowrite,nwritten,num_files_open);
  
  if ((nwritten <= 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,1,0);
  
  SSVAL(outbuf,smb_vwv0,nwritten);
  return(outsize);
}

/****************************************************************************
  reply to a lock
****************************************************************************/
int reply_lock(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0);
  uint32 count,offset;
  int eclass;
  uint32 ecode;

  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);

  count = SVAL(inbuf,smb_vwv1) | (SVAL(inbuf,smb_vwv2) << 16);
  offset = SVAL(inbuf,smb_vwv3) | (SVAL(inbuf,smb_vwv4) << 16);

  if(do_lock( fnum, cnum, count, offset, &eclass, &ecode))
    return (ERROR(eclass,ecode));

  Debug(2,"%s lock fd=%d fnum=%d cnum=%d ofs=%d cnt=%d\n",timestring(),Files[fnum].fd,fnum,cnum,offset,count);
  
  return(outsize);
}

/****************************************************************************
  reply to a unlock
****************************************************************************/
int reply_unlock(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum,cnum;
  int outsize = set_message(outbuf,0,0);
  uint32 count,offset;
  int eclass;
  uint32 ecode;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);

  count = SVAL(inbuf,smb_vwv1) | (SVAL(inbuf,smb_vwv2) << 16);
  offset = SVAL(inbuf,smb_vwv3) | (SVAL(inbuf,smb_vwv4) << 16);

  if(do_unlock(fnum, cnum, count, offset, &eclass, &ecode))
    return (ERROR(eclass,ecode));

  Debug(2,"%s unlock fd=%d fnum=%d cnum=%d ofs=%d cnt=%d\n",timestring(),Files[fnum].fd,fnum,cnum,offset,count);
  
  return(outsize);
}

/****************************************************************************
close all open files for a connection
****************************************************************************/
void close_open_files(int cnum)
{
  int i;
  for (i=0;i<MAX_OPEN_FILES;i++)
    if( Files[i].cnum == cnum && Files[i].open == True) {
      close(Files[i].fd);
      num_files_open--;
      Files[i].open = False;
      Files[i].cnum = -1;
    }
}



/****************************************************************************
close a cnum
****************************************************************************/
void close_cnum(int cnum)
{
  extern struct from_host Client_info;

  if (!OPEN_CNUM(cnum))
    {
      Debug(0,"Can't close cnum %d\n",cnum);
      return;
    }

  Debug(1,"%s (%s) has closed a connection to service %s\n",
	Client_info.name,Client_info.addr,lp_servicename(SNUM(cnum)));

  close_open_files(cnum);
  Connections[cnum].open = False;
}

/****************************************************************************
  reply to a tdis
****************************************************************************/
int reply_tdis(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  int outsize = set_message(outbuf,0,0);
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  close_cnum(cnum);
  
  Debug(2,"%s tdis cnum=%d\n",timestring(),cnum);

  return outsize;
}

/****************************************************************************
  reply to a printopen
****************************************************************************/
int reply_printopen(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  /* not supported */
  return(ERROR(ERRDOS,eACCESS_DENIED));
}

/****************************************************************************
  reply to a printclose
****************************************************************************/
int reply_printclose(char *inbuf,char *outbuf,int length,int bufsize)
{
  int fnum,cnum;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  fnum = SVAL(inbuf,smb_vwv0);

  /* not supported */
  return(ERROR(ERRDOS,eACCESS_DENIED));
}

/****************************************************************************
  reply to a printqueue
****************************************************************************/
int reply_printqueue(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  /* not supported */
  return(ERROR(ERRDOS,eACCESS_DENIED));
}

/****************************************************************************
  reply to a printwrite
****************************************************************************/
int reply_printwrite(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  /* not supported */
  return(ERROR(ERRDOS,eACCESS_DENIED));
}


/****************************************************************************
  reply to a mkdir
****************************************************************************/
int reply_mkdir(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring directory="";
  int cnum;
  int outsize,ret=-1;
  BOOL ok = False;
  
  strcpy(directory,smb_buf(inbuf) + 1);
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  unix_format(directory);
  strlower(directory);
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      if (reduce_name(directory,HOME(cnum)))
	ret = mkdir(directory,unix_mode(cnum,aDIR));
      ok = True;
      unbecome_user();
    }
  
  if ((ret < 0) || !ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,0,0);
  
  Debug(2,"%s mkdir %s cnum=%d ret=%d\n",timestring(),directory,cnum,ret);
  
  return(outsize);
}

/****************************************************************************
  reply to a rmdir
****************************************************************************/
int reply_rmdir(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring directory="";
  int cnum;
  int outsize;
  BOOL ok = False;
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  strcpy(directory,smb_buf(inbuf) + 1);
  unix_format(directory);
  strlower(directory);
  
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      if (reduce_name(directory,HOME(cnum)))
	ok = (rmdir(directory) == 0);
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRDOS,eINVALID_PATH));
  
  outsize = set_message(outbuf,0,0);
  
  Debug(2,"%s rmdir %s\n",timestring(),directory);
  
  return(outsize);
}

/****************************************************************************
  reply to a mv
****************************************************************************/
int reply_mv(char *inbuf,char *outbuf,int length,int bufsize)
{
  pstring oldname="";
  pstring newname="";
  int cnum;
  int outsize;
  BOOL ok = False;
  
  strcpy(oldname,smb_buf(inbuf) + 1);
  strcpy(newname,smb_buf(inbuf) + 3 + strlen(oldname));
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  unix_format(oldname);
  strlower(oldname); 
  unix_format(newname);
  strlower(newname); 
  
  if (!CAN_WRITE(cnum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  if (become_user(cnum))
    {
      if (reduce_name(oldname,HOME(cnum)) && reduce_name(newname,HOME(cnum)))
	ok = (rename(oldname,newname) == 0);
      unbecome_user();
    }
  
  if (!ok)
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  outsize = set_message(outbuf,0,0);
  
  Debug(2,"%s mv %s to %s cnum=%d\n",timestring(),oldname,newname,cnum);
  
  return(outsize);
}

/****************************************************************************
  reply to a setdir
****************************************************************************/
int reply_setdir(char *inbuf,char *outbuf,int length,int bufsize)
{
  int cnum,snum;
  int outsize;
  BOOL ok = False;
  pstring newdir="";
  
  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));
  
  snum = Connections[cnum].service;
  if (!CAN_SETDIR(snum))
    return(ERROR(ERRDOS,eACCESS_DENIED));
  
  strcpy(newdir,smb_buf(inbuf) + 1);
  strlower(newdir);
  
  if (strlen(newdir) == 0)
    ok = True;
  else
    {
      ok = directory_exist(newdir);
      if (ok)
	strcpy(Connections[cnum].connectpath,newdir);
    }
  
  if (!ok)
    return(ERROR(ERRDOS,eINVALID_PATH));
  
  outsize = set_message(outbuf,0,0);
  CVAL(outbuf,smb_reh) = CVAL(inbuf,smb_reh);
  
  Debug(2,"%s setdir %s cnum=%d\n",timestring(),newdir,cnum);
  
  return(outsize);
}

/****************************************************************************
  reply to a lockingX request
****************************************************************************/
int reply_lockingX(char *inbuf,char *outbuf,int length,int bufsize)
{
  int smb_com2 = CVAL(inbuf,smb_vwv0);
  int smb_off2 = SVAL(inbuf,smb_vwv1);
  int fnum = SVAL(inbuf,smb_vwv2);
#if 0
  uint16 locktype = SVAL(inbuf,smb_vwv3);
  uint32 timeout = IVAL(inbuf,smb_vwv4);
#endif
  uint16 num_locks = SVAL(inbuf,smb_vwv6);
  uint16 num_ulocks = SVAL(inbuf,smb_vwv7);

  int cnum;
  int i;
  char *data;
  uint32 eclass, ecode, dummy;
  int outsize;

  if (chain_fnum >= 0)
    fnum = chain_fnum;

  cnum = SVAL(inbuf,smb_tid);
  if (!OPEN_CNUM(cnum))
    return(ERROR(ERRSRV,ERRinvnid));

  data = smb_buf(inbuf);
  /* Data now points at the beginning of the list
     of smb_unlkrng structs */
  for(i = 0; i < num_ulocks; i++) {
    if(do_unlock(fnum,cnum,SMB_LKLEN(data,i),SMB_LKOFF(data,i),
		 &eclass, &ecode))
      return ERROR(eclass,ecode);
  }

  /* Now do any requested locks */
  data += 10*num_ulocks;
  /* Data now points at the beginning of the list
     of smb_lkrng structs */
  for(i = 0; i < num_locks; i++) {
    if(do_lock(fnum,cnum,SMB_LKLEN(data,i),SMB_LKOFF(data,i),
		 &eclass, &ecode))
      break;
  }

  /* If any of the above locks failed, then we must unlock
     all of the previous locks (X/Open spec). */
  if(i != num_locks) {
    for(; i >= 0; i--) {
      do_unlock(fnum,cnum,SMB_LKLEN(data,i),SMB_LKOFF(data,i),
		 &dummy,&dummy);
    }
    return ERROR(eclass,ecode);
  }

  outsize = set_message(outbuf,2,0);
  
  CVAL(outbuf,smb_vwv0) = smb_com2;
  SSVAL(outbuf,smb_vwv1,(outsize+chain_size)-4);
  
  Debug(2,"%s lockingX fnum=%d cnum=%d num_locks=%d num_ulocks=%d\n",
	timestring(),fnum,cnum,num_locks,num_ulocks);

  chain_fnum = fnum;

  if (smb_com2 != 0xFF)
    outsize += chain_reply(smb_com2,inbuf,inbuf+smb_off2+4,
			   outbuf,outbuf+outsize,
			   length,bufsize);
  
  chain_fnum = -1;
  
  return(outsize);
}


/* 
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/
struct smb_message_struct
{
  int code;
  char *name;
  int (*fn)();
}
 smb_messages[] = {

    /* CORE PROTOCOL */

   {SMBnegprot,"SMBnegprot",reply_negprot},
   {SMBgetatr,"SMBgetatr",reply_getatr},
   {SMBsetatr,"SMBsetatr",reply_setatr},
   {SMBtcon,"SMBtcon",reply_tcon},
   {SMBchkpth,"SMBchkpth",reply_chkpth},
   {SMBsearch,"SMBsearch",reply_search},
   {SMBopen,"SMBopen",reply_open},

   /* note that SMBmknew and SMBcreate are deliberately overloaded */   
   {SMBcreate,"SMBcreate",reply_mknew},
   {SMBmknew,"SMBmknew",reply_mknew}, 

   {SMBunlink,"SMBunlink",reply_unlink},
   {SMBread,"SMBread",reply_read},
   {SMBwrite,"SMBwrite",reply_write},
   {SMBclose,"SMBclose",reply_close},
   {SMBtdis,"SMBtdis",reply_tdis},
   {SMBmkdir,"SMBmkdir",reply_mkdir},
   {SMBrmdir,"SMBrmdir",reply_rmdir},
   {SMBdskattr,"SMBdskattr",reply_dskattr},
   {SMBmv,"SMBmv",reply_mv},

   /* this is a Pathworks specific call, allowing the 
      changing of the root path */
   {pSETDIR,"pSETDIR",reply_setdir}, 

   {SMBlseek,"SMBlseek",reply_lseek},
   {SMBflush,"SMBflush",reply_flush},
   {SMBctemp,"SMBctemp",reply_ctemp},
   {SMBexit,"SMBexit",reply_exit},
   {SMBsplopen,"SMBsplopen",reply_printopen},
   {SMBsplclose,"SMBsplclose",reply_printclose},
   {SMBsplretq,"SMBsplretq",reply_printqueue},
   {SMBsplwr,"SMBsplwr",reply_printwrite},
   {SMBlock,"SMBlock",reply_lock},
   {SMBunlock,"SMBunlock",reply_unlock},
   
   /* CORE+ PROTOCOL FOLLOWS */
   
   {SMBreadbraw,"SMBreadbraw",reply_readbraw},
   {SMBwritebraw,"SMBwritebraw",reply_writebraw},
   {SMBwriteclose,"SMBwriteclose",reply_writeclose},
   {SMBlockread,"SMBlockread",reply_lockread},
   {SMBwriteunlock,"SMBwriteunlock",reply_writeunlock},
   
   /* LANMAN1.0 PROTOCOL FOLLOWS */
   
   {SMBreadBmpx,"SMBreadBmpx",NULL},
   {SMBreadBs,"SMBreadBs",NULL},
   {SMBwriteBmpx,"SMBwriteBmpx",NULL},
   {SMBwriteBs,"SMBwriteBs",NULL},
   {SMBwritec,"SMBwritec",NULL},
   {SMBsetattrE,"SMBsetattrE",NULL},
   {SMBgetattrE,"SMBgetattrE",NULL},
   {SMBtrans,"SMBtrans",NULL},
   {SMBtranss,"SMBtranss",NULL},
   {SMBioctl,"SMBioctl",NULL},
   {SMBioctls,"SMBioctls",NULL},
   {SMBcopy,"SMBcopy",NULL},
   {SMBmove,"SMBmove",NULL},
   
   {SMBecho,"SMBecho",reply_unknown},
   {SMBopenX,"SMBopenX",reply_open_and_X},
   {SMBreadX,"SMBreadX",reply_read_and_X},
   {SMBwriteX,"SMBwriteX",reply_write_and_X},
   {SMBsesssetupX,"SMBsesssetupX",reply_sesssetup_and_X},
   {SMBtconX,"SMBtconX",reply_tcon_and_X},
   {SMBlockingX,"SMBlockingX",reply_lockingX},
   
   {SMBffirst,"SMBffirst",NULL},
   {SMBfunique,"SMBfunique",NULL},
   {SMBfclose,"SMBfclose",NULL},
   
   /* NON-IMPLEMENTED PARTS OF THE CORE PROTOCOL */
   
   {SMBsends,"SMBsends",NULL},
   {SMBsendb,"SMBsendb",NULL},
   {SMBfwdname,"SMBfwdname",NULL},
   {SMBcancelf,"SMBcancelf",NULL},
   {SMBgetmac,"SMBgetmac",NULL},
   {SMBsendstrt,"SMBsendstrt",NULL},
   {SMBsendend,"SMBsendend",NULL},
   {SMBsendtxt,"SMBsendtxt",NULL},
 };


/****************************************************************************
doa switch on the message type, and return the response size
****************************************************************************/
int switch_message(int type,char *inbuf,char *outbuf,int size,int bufsize)
{
  int outsize;
  static int num_smb_messages = 
    sizeof(smb_messages) / sizeof(struct smb_message_struct);
  int match;

  for (match=0;match<num_smb_messages;match++)
    if (smb_messages[match].code == type)
      break;

  if (match == num_smb_messages)
    {
      Debug(0,"Unknown message type %d!\n",type);
      outsize = reply_unknown(inbuf,outbuf,size,bufsize);
    }
  else
    {
      Debug(3,"switch message %s\n",smb_messages[match].name);
      if (smb_messages[match].fn)
	outsize = smb_messages[match].fn(inbuf,outbuf,size,bufsize);
      else
	outsize = reply_unknown(inbuf,outbuf,size,bufsize);
    }

  return(outsize);
}


/****************************************************************************
construct a chained reply and add it to the already made reply

inbuf points to the original message start.
inbuf2 points to the smb_wct part of the secondary message
type is the type of the secondary message
outbuf points to the original outbuffer
outbuf2 points to the smb_wct field of the new outbuffer
size is the total length of the incoming message (from inbuf1)
bufsize is the total buffer size

return how many bytes were added to the response
****************************************************************************/
int chain_reply(int type,char *inbuf,char *inbuf2,char *outbuf,char *outbuf2,int size,int bufsize)
{
  int outsize;
  char *ibuf,*obuf;
  static int chain_size_in = 0;
  static BOOL in_chain = False;
  static char *last_inbuf=NULL,*last_outbuf=NULL;
  BOOL was_inchain = in_chain;

  chain_size += ((int)outbuf2 - (int)outbuf) - smb_wct;
  if (was_inchain)
    {
      inbuf = last_inbuf;
      outbuf = last_outbuf;
    }
  else
    chain_size_in = 0;

  in_chain = True;
  last_inbuf = inbuf;
  last_outbuf = outbuf;


  inbuf2 -= chain_size_in;

  chain_size_in += ((int)inbuf2 - (int)inbuf) - smb_wct;


  /* allocate some space for the in and out buffers of the chained message */
  ibuf = (char *)malloc(size);
  obuf = (char *)malloc(bufsize);

  if (!ibuf || !obuf)
    {
      Debug(0,"Out of memory in chain reply\n");
      return(ERROR(ERRSRV,ERRnoresource));
    }

  /* create the in buffer */
  memcpy(ibuf,inbuf,smb_wct);
  memcpy(ibuf+smb_wct,inbuf2,size-(int)(inbuf2-inbuf));
  CVAL(ibuf,smb_com) = type;

  /* create the out buffer */
  memset(obuf,0,smb_size);

  CVAL(obuf,smb_com) = CVAL(ibuf,smb_com);
  set_message(obuf,0,0);
  
  memcpy(obuf+4,ibuf+4,4);
  CVAL(obuf,smb_rcls) = SUCCESS;
  CVAL(obuf,smb_reh) = 0;
  CVAL(obuf,smb_reb) = 0x80; /* bit 7 set means a reply */
  SSVAL(obuf,smb_err,SUCCESS);
  SSVAL(obuf,smb_tid,SVAL(inbuf,smb_tid));
  SSVAL(obuf,smb_pid,SVAL(inbuf,smb_pid));
  SSVAL(obuf,smb_uid,SVAL(inbuf,smb_uid));
  SSVAL(obuf,smb_mid,SVAL(inbuf,smb_mid));

  /* process the request */
  outsize = switch_message(type,ibuf,obuf,
			   (size+smb_wct)-(int)(inbuf2-inbuf),
			   bufsize);
 
  /* copy the new reply header over the old one, but preserve 
     the smb_com field */
  memcpy(outbuf+smb_com+1,obuf+smb_com+1,smb_wct-(smb_com+1));

  /* and copy the data from the reply to the right spot */
  memcpy(outbuf2,obuf+smb_wct,outsize - smb_wct);

  /* free the allocated buffers */
  if (ibuf) free(ibuf);
  if (obuf) free(obuf);

  in_chain = was_inchain;

  /* return how much extra has been added to the packet */
  return(outsize - smb_wct);
}



/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
int construct_reply(char *inbuf,char *outbuf,int size,int bufsize)
{
  int type = CVAL(inbuf,smb_com);
  int outsize;
  int msg_type = CVAL(inbuf,0);

  chain_size = 0;
  
  if (msg_type != 0)
    return(reply_special(inbuf,outbuf,size,bufsize));
  
  memset(outbuf,0,smb_size);

  CVAL(outbuf,smb_com) = CVAL(inbuf,smb_com);
  set_message(outbuf,0,0);
  
  memcpy(outbuf+4,inbuf+4,4);
  CVAL(outbuf,smb_rcls) = SUCCESS;
  CVAL(outbuf,smb_reh) = 0;
  CVAL(outbuf,smb_reb) = 0x80; /* bit 7 set means a reply */
  SSVAL(outbuf,smb_err,SUCCESS);
  SSVAL(outbuf,smb_tid,SVAL(inbuf,smb_tid));
  SSVAL(outbuf,smb_pid,SVAL(inbuf,smb_pid));
  SSVAL(outbuf,smb_uid,SVAL(inbuf,smb_uid));
  SSVAL(outbuf,smb_mid,SVAL(inbuf,smb_mid));

  outsize = switch_message(type,inbuf,outbuf,size,bufsize);
 
  if(outsize != -1)
    smb_setlen(outbuf,outsize - 4);
  return(outsize);
}


/****************************************************************************
  process commands from the client
****************************************************************************/
void process(void )
{
  extern int Client;
  static int trans_num = 0;
  int nread;
  int deadtime = lp_deadtime()*60*1000*1000; /* the deadtime is in seconds */
  
  InBuffer = (char *)malloc(BUFFER_SIZE);
  OutBuffer = (char *)malloc(BUFFER_SIZE);
  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return;
  
  while (True)
    {
      int32 len;      
      int msg_type;
      int msg_flags;
      int type;

      if (!receive_smb(InBuffer,(num_files_open == 0?deadtime:0)))	
	return;
      
      msg_type = CVAL(InBuffer,0);
      msg_flags = CVAL(InBuffer,1);
      type = CVAL(InBuffer,smb_com);

      len = smb_len(InBuffer);

      Debug(2,"got message type 0x%x of len 0x%x\n",msg_type,len);

      nread = len + 4;
      
      Debug(2,"%s Transaction %d\n",timestring(),trans_num);

      if (msg_type == 0)
	show_msg(InBuffer);

      nread = construct_reply(InBuffer,OutBuffer,nread,MIN(BUFFER_SIZE,lp_maxxmit()));
      
      if(nread != -1) {
        if (CVAL(OutBuffer,0) == 0)
	  show_msg(OutBuffer);
	
        if (nread != smb_len(OutBuffer) + 4) {
	  Debug(0,"Invalid message response size! %d %d\n",
		nread,
		smb_len(OutBuffer));
        }
        send_smb(OutBuffer);
      }
      trans_num++;

      /* If we got a tree disconnect, see if this was the
	 last one in use, if so - exit */
      if(type == SMBtdis) {
	int i;
	for(i=0;i<MAX_CONNECTIONS;i++)
	  if(Connections[i].open) 
	    break; /* Stay in loop */
	if(i != MAX_CONNECTIONS)
	  continue;
	/* There are no more connections open - shut down this socket
	   and terminate */
	shutdown(Client,2);
	return;
      }
    }
}


/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
void init_structs(void )
{
  int i;

  for (i=0;i<MAX_CONNECTIONS;i++)
    Connections[i].open = False;
  for (i=0;i<MAX_OPEN_FILES;i++)
    Files[i].open = False;

  num_files_open=0;

  init_dptrs();
}

/****************************************************************************
usage on the program
****************************************************************************/
void usage(char *pname)
{
  printf("Usage: %s [-D] [-p port] [-d debuglevel] [-l log basename] [-s services file]\n",pname);
  printf("\t-D                    become a daemon\n");
  printf("\t-p port               listen on the specified port\n");
  printf("\t-d debuglevel         set the debuglevel\n");
  printf("\t-l log basename.      Basename for log/debug files\n");
  printf("\t-s services file.     Filename of services file\n");
  printf("\t-P                    passive only\n");
  printf("\t-a                    overwrite log file, don't append\n");
  printf("\n");
}


/****************************************************************************
  main program
****************************************************************************/
int main(int argc,char *argv[])
{
  BOOL daemon = False;
  int port = 139;
  int opt;
  extern FILE *dbf;
  extern int DEBUGLEVEL;
  extern char *optarg;

  initial_uid = geteuid();
  initial_gid = getegid();

  while ((opt = getopt (argc, argv, "l:s:d:Dp:hPa")) != EOF)
    switch (opt)
      {
      case 'P':
	{
	  extern BOOL passive;
	  passive = True;
	}
	break;	
      case 's':
	strcpy(servicesf,optarg);
	break;
      case 'l':
	strcpy(debugf,optarg);
	break;
      case 'a':
	append_log = !append_log;
	break;
      case 'D':
	daemon = True;
	break;
      case 'd':
	DEBUGLEVEL = atoi(optarg);
	break;
      case 'p':
	port = atoi(optarg);
	break;
      case 'h':
	usage(argv[0]);
	exit(0);
	break;
      default:
	usage(argv[0]);
	exit(1);
      }

  
  NeedSwap = big_endian();
  
  if (DEBUGLEVEL > 2)
    {
      extern FILE *login,*logout;
      pstring fname="";
      sprintf(fname,"%s.in",debugf);
      login = fopen(fname,"w"); 
      sprintf(fname,"%s.out",debugf);
      logout = fopen(fname,"w");
    }
  
  if (DEBUGLEVEL > 0)
    {
      pstring fname="";
      sprintf(fname,"%s.debug",debugf);      
      if (append_log)
	dbf = fopen(fname,"a");
      else
	dbf = fopen(fname,"w");
      setbuf(dbf,NULL);
      Debug(1,"%s smbserver version %s started\n",timestring(),VERSION);
      Debug(1,"Copyright Andrew Tridgell 1992,1993,1994\n");
    }
  
  init_structs();
  
  if (!lp_load(servicesf))
    return(-1);	
  
  if (DEBUGLEVEL > 1)
    Debug(3,"%s loaded services\n",timestring());

  if (daemon)
    {
      Debug(3,"%s becoming a daemon\n",timestring());
      become_daemon();
    }

  if (open_sockets(daemon,port))
    {
      /* reload the services file. It might have changed (if a daemon) */
      if (daemon && !lp_load(servicesf))
	return(-1);	

      if (lp_rootdir())
	{
	  chroot(lp_rootdir());
  
	  if (DEBUGLEVEL > 1)
	    Debug(2,"%s changed root to %s\n",timestring(),lp_rootdir());
	}

      maxxmit = lp_maxxmit();

      process();
      close_sockets();
    }
  fclose(dbf);
  return(0);
}

