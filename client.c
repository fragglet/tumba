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


/* default to using LANMAN1 */
#ifndef LANMAN1
#define LANMAN1 1
#endif


pstring cur_dir = "\\";
pstring cd_path = "";
pstring service;
pstring desthost;
pstring myname = "";
pstring password = "";
pstring username="";
BOOL got_pass = False;
BOOL connect_as_printer = False;

extern struct in_addr myip;

pstring debugf = DEBUGFILE;


char *InBuffer = NULL;
char *OutBuffer = NULL;
int cnum = 0;
int pid = 0;
int gid = 0;
int uid = 0;
int mid = 0;
int myumask = 0755;

int max_xmit = BUFFER_SIZE;

extern BOOL NeedSwap;

BOOL prompt = True;

int printmode = 1;

BOOL recurse = False;
BOOL lowercase = False;

BOOL have_ip = False;

struct in_addr dest_ip;

#define SEPARATORS " \t\n\r"

BOOL abort_mget = True;

int Protocol = PROT_CORE;

BOOL readbraw_supported = False;
BOOL writebraw_supported = False;

time_t servertime = 0;

pstring fileselection = "";

file_info def_finfo = {"",-1,0,0,0,0,0,0};

/****************************************************************************
setup basics in a outgoing packet
****************************************************************************/
void setup_pkt(char *outbuf)
{
  SSVAL(outbuf,smb_pid,pid);
  SSVAL(outbuf,smb_uid,uid);
  SSVAL(outbuf,smb_mid,mid);
  if (Protocol > PROT_CORE)
    {
      CVAL(outbuf,smb_flg) = 0x8;
      SSVAL(outbuf,smb_flg2,0x3);
    }
}


/****************************************************************************
  show an finfo struct
****************************************************************************/
void show_finfo(file_info *finfo)
{
  Debug(3,"name=%s\nmode=0x%x\nsize=%d\n",
	finfo->name,
	finfo->mode,
	finfo->size);
  Debug(3,"mtime=%s",asctime(LocalTime(&finfo->mtime)));
  Debug(3,"atime=%s",asctime(LocalTime(&finfo->atime)));
  Debug(3,"ctime=%s",asctime(LocalTime(&finfo->ctime)));

  Debug(3,"%x %x %x\n",finfo->mtime,finfo->atime,finfo->ctime);
}



/****************************************************************************
check for existance of a dir
****************************************************************************/
BOOL chkpath(char *path,BOOL report)
{
  pstring inbuf,outbuf;
  char *p;

  memset(outbuf,0,smb_size);
  set_message(outbuf,0,4 + strlen(path));
  CVAL(outbuf,smb_com) = SMBchkpth;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  strcpy(p,path);

  send_smb(outbuf);
  receive_smb(inbuf,0);

  return(CVAL(inbuf,smb_rcls) == 0);
}


/****************************************************************************
change directory
****************************************************************************/
void cmd_cd(char *inbuf,char *outbuf )
{
  char *p;
  pstring saved_dir;

  p = strtok(NULL,SEPARATORS);
  if (p)
    {
      pstring dname;
      
      /* Save the current directory in case the
	 new directory is invalid */
      strcpy(saved_dir, cur_dir);
      if (*p == '\\')
	strcpy(cur_dir,p);
      else
	strcat(cur_dir,p);
      clean_name(cur_dir);
      strcpy(dname,cur_dir);
      strcat(cur_dir,"\\");
      clean_name(cur_dir);

      if (!strequal(cur_dir,"\\"))
	if (!chkpath(dname,True))
	  strcpy(cur_dir,saved_dir);
    }
  else
    Debug(0,"Current directory is %s\n",cur_dir);
  strcpy(cd_path,cur_dir);
}


/****************************************************************************
do a directory listing, calling fn on each file found
****************************************************************************/
void do_dir(char *inbuf,char *outbuf,char *Mask,int attribute,void (*fn)(),BOOL recurse_dir)
{
  char *p;
  int received = 0;
  BOOL first = True;
  char status[21];
  int num_asked = (max_xmit - 100)/DIR_STRUCT_SIZE;
  int num_received = 0;
  char *dirlist = NULL;
  pstring mask;

  strcpy(mask,Mask);
  expand_mask(mask);
  
  while (1)
    {
      memset(outbuf,0,smb_size);
      if (first)	
	set_message(outbuf,2,5 + strlen(mask));
      else
	set_message(outbuf,2,5 + 21);

      CVAL(outbuf,smb_com) = SMBsearch;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,num_asked);
      SSVAL(outbuf,smb_vwv1,attribute);
  
      p = smb_buf(outbuf);
      *p++ = 4;
      
      if (first)
	strcpy(p,mask);
      else
	strcpy(p,"");
      p += strlen(p) + 1;
      
      *p++ = 5;
      if (first)
	SSVAL(p,0,0);
      else
	{
	  SSVAL(p,0,21);
	  p += 2;
	  memcpy(p,status,21);
	}

      send_smb(outbuf);
      receive_smb(inbuf,0);
      first = False;

      received = SVAL(inbuf,smb_vwv0);

      Debug(5,"dir received %d\n",received);

      Debug(6,"errstr=%s\n",smb_errstr(inbuf));

      if (received <= 0) break;

      dirlist = Realloc(dirlist,(num_received + received)*DIR_STRUCT_SIZE);

      if (!dirlist) 
	return;


      p = smb_buf(inbuf) + 3;

      memcpy(dirlist+num_received*DIR_STRUCT_SIZE,
	     p,received*DIR_STRUCT_SIZE);

      memcpy(status,p + ((received-1)*DIR_STRUCT_SIZE),21);

      num_received += received;

      if (CVAL(inbuf,smb_rcls) != 0) break;
    }

  received = num_received;
  p = dirlist;

  while (received--)
    {
      file_info finfo = def_finfo;
      uint32 Date;
      char attrstr[10]="";
      
      finfo.mode = CVAL(p,21);
      memcpy(&Date,p+22,4);
      finfo.mtime = make_unix_date(Date);
#ifdef EXTENDED
      finfo.atime = make_unix_date(Date);
      finfo.ctime = make_unix_date(Date);
#endif
      finfo.size = SVAL(p,26) + (SVAL(p,28)<<16);
      strcpy(finfo.name,p+30);
      
      if (finfo.mode & aDIR) strcat(attrstr,"D");
      if (finfo.mode & aARCH) strcat(attrstr,"A");
      if (finfo.mode & aHIDDEN) strcat(attrstr,"H");
      if (finfo.mode & aSYSTEM) strcat(attrstr,"S");
      if (finfo.mode & aRONLY) strcat(attrstr,"R");	  
      if (!sane_unix_date(finfo.mtime))
 	strcat(attrstr,"I");
      
      if (!((finfo.mode & aDIR) == 0 && *fileselection && 
 	    !mask_match(finfo.name,fileselection,False,False)) &&
 	  !(recurse_dir && (strequal(finfo.name,".") || 
 			    strequal(finfo.name,".."))))
  	{
 	  if (recurse_dir && (finfo.mode & aDIR))
 	    {
 	      pstring mask2;
 	      pstring sav_dir;
 	      strcpy(sav_dir,cur_dir);
 	      strcat(cur_dir,finfo.name);
 	      strcat(cur_dir,"\\");
 	      strcpy(mask2,cur_dir);
 	      strcat(mask2,"*.*");
 	      do_dir(inbuf,outbuf,mask2,attribute,fn,True);
 	      strcpy(cur_dir,sav_dir);
 	    }
  	  else
 	    {
 	      if (fn)
 		fn(&finfo);
 	      else
		Debug(0,"%20.20s%7.7s%10d  %s",
 		      finfo.name,
 		      attrstr,
 		      finfo.size,
 		      asctime(LocalTime(&finfo.mtime)));
 	    }
	}
      p += DIR_STRUCT_SIZE;
    }
  if (dirlist) free(dirlist);
}


/****************************************************************************
get a directory listing
****************************************************************************/
void cmd_dir(char *inbuf,char *outbuf)
{
  int attribute = aDIR | aSYSTEM | aHIDDEN;
  pstring mask;
  char *p;

  strcpy(mask,cur_dir);
  if(mask[strlen(mask)-1]!='\\')
    strcat(mask,"\\");

  p = strtok(NULL,SEPARATORS);
  if (p)
    {
      if (*p == '\\')
	strcpy(mask,p);
      else
	strcat(mask,p);
    }
  else
    strcat(mask,"*.*");

  do_dir(inbuf,outbuf,mask,attribute,NULL,False);
}


/****************************************************************************
get a file from rname to lname
****************************************************************************/
void do_get(char *rname,char *lname)
{
  int handle,fnum;
  uint32 nread=0;
  char *p;
  BOOL newhandle = False;
  char *inbuf,*outbuf;
  file_info finfo = def_finfo;

#ifdef STATS
  struct timeval tp_start,tp_end;
#endif

#ifdef STATS
  gettimeofday(&tp_start,NULL);
#endif


  if (lowercase)
    strlower(lname);


  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);

  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return;
    }

  memset(outbuf,0,smb_size);
  set_message(outbuf,2,2 + strlen(rname));

  CVAL(outbuf,smb_com) = SMBopen;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  SSVAL(outbuf,smb_vwv1,0);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,rname);
  clean_name(rname);

      if(!strcmp(lname,"-"))
	handle = fileno(stdout);
      else 
	{
	  handle = creat(lname,0644);
	  newhandle = True;
	}
      if (handle < 0)
	{
	  Debug(0,"Error opening local file %s\n",lname);
	  free(inbuf);free(outbuf);
	  return;
	}

  send_smb(outbuf);
  receive_smb(inbuf,0);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s opening remote file %s\n",smb_errstr(inbuf),rname);
      if(newhandle)
	close(handle);
      free(inbuf);free(outbuf);
      return;
    }

  strcpy(finfo.name,rname);
  finfo.mode = SVAL(inbuf,smb_vwv1);
  finfo.size = IVAL(inbuf,smb_vwv4);
  finfo.mtime = IVAL(inbuf,smb_vwv2);
  finfo.atime = finfo.ctime = finfo.mtime;
  
  Debug(3,"file %s attrib 0x%X\n",finfo.name,finfo.mode);

  fnum = SVAL(inbuf,smb_vwv0);

      Debug(2,"getting file %s of size %d bytes as %s\n",
	    finfo.name,
	    finfo.size,
	    lname);


#if 0
  if (Protocol > PROT_CORE)
    {
	  memset(outbuf,0,smb_size);
	  set_message(outbuf,1,0);
	  CVAL(outbuf,smb_com) = SMBgetattrE;
	  SSVAL(outbuf,smb_tid,cnum);
	  setup_pkt(outbuf);
	  SSVAL(outbuf,smb_vwv0,fnum);

	  send_smb(outbuf);
	  receive_smb(inbuf,0);
      
	  if (CVAL(inbuf,smb_rcls) == 0)
	    {
	      uint32 ddate;
#ifdef EXTENDED
	      finfo.ctime = make_unix_date2(ddate);
	      memcpy(&ddate,inbuf+smb_vwv0,sizeof(ddate));	      
	      finfo.atime = make_unix_date2(ddate);
	      memcpy(&ddate,inbuf+smb_vwv2,sizeof(ddate));	      
#endif
	      finfo.mtime = make_unix_date2(ddate);
	      memcpy(&ddate,inbuf+smb_vwv4,sizeof(ddate));	      
	    }
	  else
	    Debug(3,"Couldn't get extended dates\n");
    }
#endif

  while (nread < finfo.size)
    {
      char *dataptr;
      int datalen;
      
      Debug(3,"nread=%d\n",nread);

      if (readbraw_supported)
	{
	  extern int Client;
	  memset(outbuf,0,smb_size);
	  set_message(outbuf,8,0);
	  CVAL(outbuf,smb_com) = SMBreadbraw;
	  SSVAL(outbuf,smb_tid,cnum);
	  setup_pkt(outbuf);

	  SSVAL(outbuf,smb_vwv0,fnum);
	  SIVAL(outbuf,smb_vwv1,nread);
	  SSVAL(outbuf,smb_vwv3,MIN(finfo.size-nread,BUFFER_SIZE-4));
	  SSVAL(outbuf,smb_vwv4,0);
	  SIVAL(outbuf,smb_vwv5,1000);
	  send_smb(outbuf);

	  /* Now read the raw data into the buffer and write it */	  
	  if(!read_data(Client,inbuf,4)) {
	    Debug(0,"Failed to read length in readbraw\n");	    
	    exit(1);
	  }

	  /* Even though this is not an smb message, smb_len
	     returns the generic length of an smb message */
	  datalen = smb_len(inbuf);
	  if(!read_data(Client,inbuf,datalen)) {
	    Debug(0,"Failed to read data in readbraw\n");
	    exit(1);
	  }

	  dataptr = inbuf;
	  
	}
      else
	{
	  memset(outbuf,0,smb_size);
	  set_message(outbuf,5,0);
	  CVAL(outbuf,smb_com) = SMBread;
	  SSVAL(outbuf,smb_tid,cnum);
	  setup_pkt(outbuf);

	  SSVAL(outbuf,smb_vwv0,fnum);
	  SSVAL(outbuf,smb_vwv1,MIN(max_xmit-200,finfo.size - nread));
	  SSVAL(outbuf,smb_vwv2,nread & 0xFFFF);
	  SSVAL(outbuf,smb_vwv3,nread >> 16);
	  SSVAL(outbuf,smb_vwv4,finfo.size - nread);

	  send_smb(outbuf);
	  receive_smb(inbuf,0);

	  if (CVAL(inbuf,smb_rcls) != 0)
	    {
	      Debug(0,"Error %s reading remote file\n",smb_errstr(inbuf));
	      break;
	    }

	  datalen = SVAL(inbuf,smb_vwv0);
	  dataptr = smb_buf(inbuf) + 3;
	}
 
	if (write(handle,dataptr,datalen) != datalen)
	  {
	    Debug(0,"Error writing local file\n");
	    break;
	  }
      
      nread += datalen;
      if (nread == 0) 
	{
	  Debug(0,"Error reading file %s. Got 0 bytes\n",rname);
	  break;
	}
    }


  memset(outbuf,0,smb_size);
  set_message(outbuf,3,0);
  CVAL(outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);
  SIVAL(outbuf,smb_vwv1,finfo.mtime);

  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"Error %s closing remote file\n",smb_errstr(inbuf));
      if(newhandle)
	close(handle);
      free(inbuf);free(outbuf);
      return;
    }

  if(newhandle)
    close(handle);

#ifdef STATS
  gettimeofday(&tp_end,NULL);
  stats_record(finfo.size,
	       (tp_end.tv_sec - tp_start.tv_sec)*1000000 +
	       (tp_end.tv_usec - tp_start.tv_usec));	       
#endif


  free(inbuf);free(outbuf);
}

/****************************************************************************
get a file from rname to lname
****************************************************************************/
void do_small_get(char *Rname,char *Lname,file_info *finfo)
{
#define CHAIN_CLOSE 0
  int handle;
  char *p;
  BOOL newhandle = False;
  char *inbuf,*outbuf;
  pstring rname,lname;
  char *outbuf2;
#if CHAIN_CLOSE
  char *outbuf3;
#endif

#ifdef STATS
  struct timeval tp_start,tp_end;
#endif

#ifdef STATS
  gettimeofday(&tp_start,NULL);
#endif

  strcpy(rname,Rname);
  strcpy(lname,Lname);

  if (lowercase)
    strlower(lname);


  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);

  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return;
    }

  if (finfo->size > 0)
    {
      memset(outbuf,0,smb_size);
      set_message(outbuf,15,1 + strlen(rname));
      
      CVAL(outbuf,smb_com) = SMBopenX;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);
      CVAL(outbuf,smb_vwv0) = SMBreadX;
      SSVAL(outbuf,smb_vwv3,0);
      SSVAL(outbuf,smb_vwv8,1);
      SSVAL(outbuf,smb_vwv5,aSYSTEM | aHIDDEN);
      
      p = smb_buf(outbuf);
      strcpy(p,rname);
      p += strlen(rname)+1;
      clean_name(rname);
      
#if 1
      SSVAL(outbuf,smb_vwv1,((int)p-(int)outbuf)-4);
      
      /* now setup the readX */
      outbuf2 = p - smb_wct;
      memset(p,0,2 + (11+4+10)*sizeof(WORD));
      CVAL(outbuf2,smb_vwv0 - 1) = 10;
#if CHAIN_CLOSE
      CVAL(outbuf2,smb_vwv0) = SMBclose;
      SSVAL(outbuf2,smb_vwv1,SVAL(outbuf,smb_vwv1) + 1 + 11*sizeof(WORD));
#else
      CVAL(outbuf2,smb_vwv0) = 0xFF;
#endif
      SSVAL(outbuf2,smb_vwv5,finfo->size);
      SSVAL(outbuf2,smb_vwv6,finfo->size);
      SSVAL(outbuf2,smb_vwv9,finfo->size);
      
#if CHAIN_CLOSE
      /* and setup the close */
      outbuf3 = outbuf2 + 1 + 11*sizeof(WORD);
      CVAL(outbuf3,smb_vwv0 - 1) = 3;
      SSVAL(outbuf3,smb_vwv0,0);
      SSVAL(outbuf3,smb_vwv1,0);
      SSVAL(outbuf3,smb_vwv2,0);
      SSVAL(outbuf3,smb_vwv3,0);
#endif
      
      /* now set the total packet length */
#if CHAIN_CLOSE
      smb_setlen(outbuf,smb_len(outbuf)+2+((11+4)*sizeof(WORD)));
#else
      smb_setlen(outbuf,smb_len(outbuf)+1+(11*sizeof(WORD)));
#endif
#endif
      send_smb(outbuf);
      receive_smb(inbuf,0);
      
      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  Debug(0,"Chained get failed: %s\n",smb_errstr(inbuf));
#if 1
	  do_get(Rname,Lname);
#endif
	  return;
	}
    }

      if(!strcmp(lname,"-"))
	handle = fileno(stdout);
      else 
	{
	  handle = creat(lname,0644);
	  newhandle = True;
	}
      if (handle < 0)
	{
	  Debug(0,"Error opening local file %s\n",lname);
	  free(inbuf);free(outbuf);
	  return;
	}

      Debug(2,"getting file %s of size %d bytes as %s\n",rname,
	    finfo->size,lname);


  if (finfo->size > 0)
    {
      int datalen = finfo->size;
      char *dataptr = (inbuf+4) + SVAL(inbuf,smb_vwv1);
      dataptr += 1+(CVAL(dataptr,0)+1)*sizeof(WORD);
      dataptr += (SVAL(dataptr,-2) - finfo->size);
      
	if (write(handle,dataptr,datalen) != datalen)
	  {
	    Debug(0,"Error writing local file\n");
	  }    
    }    
  

#if !CHAIN_CLOSE
  if (finfo->size > 0)
    {
      memset(outbuf,0,smb_size);
      set_message(outbuf,3,0);
      CVAL(outbuf,smb_com) = SMBclose;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);
      
      SSVAL(outbuf,smb_vwv0,SVAL(inbuf,smb_vwv2));
      SSVAL(outbuf,smb_vwv1,0);
      SSVAL(outbuf,smb_vwv2,0);
      
      send_smb(outbuf);
      receive_smb(inbuf,0);
      
      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  Debug(0,"Error %s closing remote file\n",smb_errstr(inbuf));
	  if(newhandle)
	    close(handle);
	  free(inbuf);free(outbuf);
	  return;
	}
    }
#endif

  if(newhandle)
    close(handle);

#ifdef STATS
  gettimeofday(&tp_end,NULL);
  stats_record(finfo->size,
	       (tp_end.tv_sec - tp_start.tv_sec)*1000000 +
	       (tp_end.tv_usec - tp_start.tv_usec));	       
#endif

  Debug(2,"Small get succeeded\n");

  free(inbuf);free(outbuf);
}


/****************************************************************************
get a file
****************************************************************************/
void cmd_get(void)
{
  pstring lname;
  pstring rname;
  char *p;

  strcpy(rname,cur_dir);
  strcat(rname,"\\");

  p = strtok(NULL,SEPARATORS);
  if (!p)
    {
      Debug(0,"get <filename>\n");
      return;
    }
  strcat(rname,p); 
  clean_name(rname);
  strcpy(lname,p);

  p = strtok(NULL,SEPARATORS);
  if (p)
    strcpy(lname,p);      

  do_get(rname,lname);
}


/****************************************************************************
do a mget operation on one file
****************************************************************************/
void do_mget(file_info *finfo)
{
  pstring rname;
  pstring quest;

  if (strequal(finfo->name,".") || strequal(finfo->name,".."))
    return;

  if (abort_mget)
    {
      Debug(0,"mget aborted\n");
      return;
    }

  if (finfo->mode & aDIR)
    sprintf(quest,"Get directory %s? ",finfo->name);
  else
    sprintf(quest,"Get file %s? ",finfo->name);

  if (prompt && !yesno(quest)) return;

  if (finfo->mode & aDIR)
    {
      pstring saved_curdir;
      pstring mget_mask;
      char *inbuf,*outbuf;

      inbuf = (char *)malloc(BUFFER_SIZE);
      outbuf = (char *)malloc(BUFFER_SIZE);

      if (!inbuf || !outbuf)
	{
	  Debug(0,"out of memory\n");
	  return;
	}

      strcpy(saved_curdir,cur_dir);

      strcat(cur_dir,finfo->name);
      strcat(cur_dir,"\\");

      unix_format(finfo->name);
	{
	  if (!directory_exist(finfo->name) && mkdir(finfo->name,0777) != 0) 
	    {
	      Debug(0,"failed to create directory %s\n",finfo->name);
	      strcpy(cur_dir,saved_curdir);
	      free(inbuf);free(outbuf);
	      return;
	    }

	  if (chdir(finfo->name) != 0)
	    {
	      Debug(0,"failed to chdir to directory %s\n",finfo->name);
	      strcpy(cur_dir,saved_curdir);
	      free(inbuf);free(outbuf);
	      return;
	    }
	}       

      strcpy(mget_mask,cur_dir);
      strcat(mget_mask,"*.*");
      
      do_dir((char *)inbuf,(char *)outbuf,
	     mget_mask,aSYSTEM | aHIDDEN | aDIR,do_mget,False);
	chdir("..");
      strcpy(cur_dir,saved_curdir);
      free(inbuf);free(outbuf);
    }
  else
    {
      strcpy(rname,cur_dir);
      strcat(rname,finfo->name);
#ifdef SMALL_GETS      
      if (Protocol > PROT_CORE &&
	  finfo->size < (max_xmit-(2*smb_size + 
				   (15+10+3)*sizeof(WORD) +
				   strlen(finfo->name) + 300)))
	do_small_get(rname,finfo->name,finfo);
      else
#endif
	do_get(rname,finfo->name);
    }
}


/****************************************************************************
do a mget command
****************************************************************************/
void cmd_mget(char *inbuf,char *outbuf)
{
  int attribute = aSYSTEM | aHIDDEN;
  pstring mget_mask="";
  char *p;

  if (recurse)
    attribute |= aDIR;

  abort_mget = False;

  while ((p = strtok(NULL,SEPARATORS)))
    {
      strcpy(mget_mask,cur_dir);
      if(mget_mask[strlen(mget_mask)-1]!='\\')
	strcat(mget_mask,"\\");

      if (*p == '\\')
	strcpy(mget_mask,p);
      else
	strcat(mget_mask,p);
    }

  do_dir((char *)inbuf,(char *)outbuf,mget_mask,attribute,do_mget,False);
}

/****************************************************************************
make a directory of name "name"
****************************************************************************/
BOOL do_mkdir(char *name)
{
  char *p;
  char *inbuf,*outbuf;

  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);

  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return False;
    }

  memset(outbuf,0,smb_size);
  set_message(outbuf,0,2 + strlen(name));
  
  CVAL(outbuf,smb_com) = SMBmkdir;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,name);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s making remote directory %s\n",
	    smb_errstr(inbuf),name);
      free(inbuf);free(outbuf);
      return(False);
    }

  free(inbuf);free(outbuf);
  return(True);
}


/****************************************************************************
set the attributes and date of a file
****************************************************************************/
BOOL do_setattr(file_info *finfo)
{
  char *p;
  char *inbuf,*outbuf;
  pstring name;

  strcpy(name,finfo->name);
  strcpy(finfo->name,"\\");
  strcat(finfo->name,name);

  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);

  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return False;
    }

  memset(outbuf,0,smb_size);
  set_message(outbuf,8,4 + strlen(finfo->name));
  CVAL(outbuf,smb_com) = SMBsetatr;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,finfo->mode);
  SIVAL(outbuf,smb_vwv1,finfo->mtime); 
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,finfo->name);
  p += (strlen(finfo->name)+1);
  
  *p++ = 4;
  *p++ = 0;

  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s setting attributes on file %s\n",
	    smb_errstr(inbuf),finfo->name);
      free(inbuf);free(outbuf);
      return(False);
    }

  free(inbuf);free(outbuf);
  return(True);
}


/****************************************************************************
make a directory
****************************************************************************/
void cmd_mkdir(char *inbuf,char *outbuf)
{
  pstring mask;
  char *p;
  
  strcpy(mask,cur_dir);

  p = strtok(NULL,SEPARATORS);
  if (!p)
    {
      if (!recurse)
	Debug(0,"mkdir <dirname>\n");
      return;
    }
  strcat(mask,p);

  if (recurse)
    {
      pstring ddir;
      pstring ddir2 = "";
      strcpy(ddir,mask);
      trim_string(ddir,".",NULL);
      p = strtok(ddir,"/\\");
      while (p)
	{
	  strcat(ddir2,p);
	  if (!chkpath(ddir2,False))
	    {		  
	      do_mkdir(ddir2);
	    }
	  strcat(ddir2,"\\");
	  p = strtok(NULL,"/\\");
	}	 
    }
  else
    do_mkdir(mask);
}

/****************************************************************************
put a single file
****************************************************************************/
void do_put(char *rname,char *lname,file_info *finfo)
{
  int fnum;
  FILE *f;
  int nread=0;
  char *p;
  char *inbuf,*outbuf;

  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);

  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return;
    }

  
  memset(outbuf,0,smb_size);
  set_message(outbuf,3,2 + strlen(rname));
  
  CVAL(outbuf,smb_com) = SMBcreate;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,finfo->mode);
  SIVAL(outbuf,smb_vwv1,finfo->mtime);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,rname);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s opening remote file %s\n",smb_errstr(inbuf),rname);
      free(inbuf);free(outbuf);
      return;
    }

    f = fopen(lname,"r");

  if (!f)
    {
      Debug(0,"Error opening local file %s\n",lname);
      free(inbuf);free(outbuf);
      return;
    }

  
  fnum = SVAL(inbuf,smb_vwv0);
  if (finfo->size < 0)
    finfo->size = file_size(lname);
  
  Debug(1,"putting file %s of size %d bytes as %s\n",lname,finfo->size,rname);
  
  while (nread < finfo->size)
    {
      int n = MIN(max_xmit-200,finfo->size - nread);
  
      memset(outbuf,0,smb_size);
      set_message(outbuf,5,n + 3);
      CVAL(outbuf,smb_com) = SMBwrite;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,fnum);
      SSVAL(outbuf,smb_vwv1,n);
      SSVAL(outbuf,smb_vwv2,nread & 0xFFFF);
      SSVAL(outbuf,smb_vwv3,nread >> 16);
      SSVAL(outbuf,smb_vwv4,finfo->size - nread);
      CVAL(smb_buf(outbuf),0) = 1;
      SSVAL(smb_buf(outbuf),1,n);

      if (fread(smb_buf(outbuf)+3,1,n,f) != n)
	{
	  Debug(0,"Error reading local file\n");
	  break;
	}	  

      send_smb(outbuf);
      receive_smb(inbuf,0);

      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  Debug(0,"%s writing remote file\n",smb_errstr(inbuf));
	  break;
	}

      
      if (n != SVAL(inbuf,smb_vwv0))
	{
	  Debug(0,"Error: only wrote %d bytes\n",nread + SVAL(inbuf,smb_vwv0));
	  break;
	}

      nread += n;
    }

#if 0
  memset(outbuf,0,smb_size);
  set_message(outbuf,7,0);
  CVAL(outbuf,smb_com) = SMBsetattrE;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);

  {
    uint32 ddate;
#ifdef EXTENDED
    ddate = make_dos_date2(finfo->ctime);
    memcpy(outbuf+smb_vwv1,&ddate,sizeof(ddate));
    ddate = make_dos_date2(finfo->atime);
    memcpy(outbuf+smb_vwv3,&ddate,sizeof(ddate));
#endif
    ddate = make_dos_date2(finfo->mtime);
    memcpy(outbuf+smb_vwv5,&ddate,sizeof(ddate));
  }

  send_smb(outbuf);
  receive_smb(inbuf,0);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s setting dates on file\n",smb_errstr(inbuf));
    }
#endif

  memset(outbuf,0,smb_size);
  set_message(outbuf,3,0);
  CVAL(outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);
  SIVAL(outbuf,smb_vwv1,finfo->mtime);

  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s closing remote file %s\n",smb_errstr(inbuf),rname);
	fclose(f);
      free(inbuf);free(outbuf);
      return;
    }


    fclose(f);
  free(inbuf);free(outbuf);
}

 
/****************************************************************************
  fudge a single file
****************************************************************************/
void do_fudge(file_info *finfo)
{
  int fnum;
  char *p;
  char *inbuf,*outbuf;
  time_t old_mtime;
  static time_t sane_date = 0;
  
  {
    pstring n2;
    strcpy(n2,finfo->name);
    strcpy(finfo->name,cur_dir);
    strcat(finfo->name,n2);
  }
  
  if (sane_date == 0)
    {
      sane_date = start_of_month();
    }
  
  if (sane_unix_date(finfo->mtime))
    return;
  
  Debug(2,"Fixing insane date on file %s %s",finfo->name,
 	asctime(LocalTime(&finfo->mtime)));
  
  finfo->mtime = sane_date;
  
  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);
  
  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return;
    }
  
  memset(outbuf,0,smb_size);
  set_message(outbuf,2,2 + strlen(finfo->name));
  
  CVAL(outbuf,smb_com) = SMBopen;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,0);
  SSVAL(outbuf,smb_vwv1,0);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,finfo->name);
  clean_name(finfo->name);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"Error %s opening remote file %s\n",smb_errstr(inbuf),
 	    finfo->name);
      free(inbuf);free(outbuf);
      return;
    }
  
  fnum = SVAL(inbuf,smb_vwv0);
  old_mtime = IVAL(inbuf,smb_vwv2);
  
  if (sane_unix_date(old_mtime))
    {
      finfo->mtime = old_mtime;
      Debug(2,"Already sane date on file %s %s",finfo->name,
 	    asctime(LocalTime(&finfo->mtime)));
    }
  
  memset(outbuf,0,smb_size);
  set_message(outbuf,3,0);
  CVAL(outbuf,smb_com) = SMBclose;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);
  
  SSVAL(outbuf,smb_vwv0,fnum);
  SIVAL(outbuf,smb_vwv1,finfo->mtime);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"Error %s closing remote file\n",smb_errstr(inbuf));
      free(inbuf);free(outbuf);
      return;
    }
  
  free(inbuf);free(outbuf);
}

/****************************************************************************
  fudge dates
  ****************************************************************************/
void cmd_fudge(char *inbuf,char *outbuf)
{
  int attribute = aDIR | aSYSTEM | aHIDDEN;
  pstring mask;
  char *p;
  
  strcpy(mask,cur_dir);
  if(mask[strlen(mask)-1]!='\\')
    strcat(mask,"\\");
  
  p = strtok(NULL,SEPARATORS);
  if (p)
    {
      if (*p == '\\')
 	strcpy(mask,p);
      else
 	strcat(mask,p);
    }
  else
    strcat(mask,"*.*");
  
  do_dir(inbuf,outbuf,mask,attribute,do_fudge,recurse);
}

 

/****************************************************************************
put a file
****************************************************************************/
void cmd_put(void)
{
  pstring lname;
  pstring rname;
  char *p;
  file_info finfo = def_finfo;
  
  strcpy(rname,cur_dir);
  strcat(rname,"\\");
  
  p = strtok(NULL,SEPARATORS);
  if (!p)
    {
      Debug(0,"put <filename>\n");
      return;
    }
  strcpy(lname,p);
  
  p = strtok(NULL,SEPARATORS);
  if (p)
    strcat(rname,p);      
  else
    strcat(rname,lname);

  clean_name(rname);

  do_put(rname,lname,&finfo);
}

/****************************************************************************
seek in a directory/file list until you get something that doesn't start with
the specified name
****************************************************************************/
BOOL seek_list(FILE *f,char *name)
{
  pstring s;
  while (!feof(f))
    {
      if (fscanf(f,"%s",s) != 1) return(False);
      trim_string(s,"./",NULL);
      if (strncmp(s,name,strlen(name)) != 0)
	{
	  strcpy(name,s);
	  return(True);
	}
    }
      
  return(False);
}


/****************************************************************************
set the file selection mask
****************************************************************************/
void cmd_select(void)
{
  char *p = strtok(NULL,SEPARATORS);
  if (p)
    strcpy(fileselection,p);
  else
    strcpy(fileselection,"");
}


/****************************************************************************
mput some files
****************************************************************************/
void cmd_mput(void)
{
  pstring lname;
  pstring rname;
  file_info finfo = def_finfo;

  char *p;
  
  while ((p = strtok(NULL,SEPARATORS)))
    {
      pstring cmd;
      pstring tmpnam;
      FILE *f;
      
      sprintf(tmpnam,"/tmp/ls.smb.%d",getpid());
      if (recurse)
	sprintf(cmd,"find . -name \"%s\" -print > %s",p,tmpnam);
      else
	sprintf(cmd,"/bin/ls %s > %s",p,tmpnam);
      system(cmd);

      f = fopen(tmpnam,"r");
      if (!f) continue;

      while (!feof(f))
	{
	  pstring quest;

	  if (fscanf(f,"%s",lname) != 1) break;
	  trim_string(lname,"./",NULL);

	again:

	  /* check if it's a directory */
	  if (directory_exist(lname))
	    {
	      if (!recurse) continue;
	      sprintf(quest,"Put directory %s? ",lname);
	      if (prompt && !yesno(quest)) 
		{
		  strcat(lname,"/");
		  if (!seek_list(f,lname))
		    break;
		  goto again;		    
		}
	      
	      strcpy(rname,cur_dir);
	      strcat(rname,lname);
	      if (!do_mkdir(rname))
		{
		  strcat(lname,"/");
		  if (!seek_list(f,lname))
		    break;
		  goto again;		    		  
		}

	      continue;
	    }
	  else
	    {
	      sprintf(quest,"Put file %s? ",lname);
	      if (prompt && !yesno(quest)) continue;

	      strcpy(rname,cur_dir);
	      strcat(rname,lname);
	    }
	  dos_format(rname);
	  do_put(rname,lname,&finfo);
	}
      fclose(f);
      unlink(tmpnam);
    }
}


/****************************************************************************
print a file
****************************************************************************/
void cmd_print(char *inbuf,char *outbuf )
{
  int fnum;
  FILE *f = NULL;
  uint32 nread=0;
  pstring lname;
  pstring rname;
  char *p;

  p = strtok(NULL,SEPARATORS);
  if (!p)
    {
      Debug(0,"print <filename>\n");
      return;
    }
  strcpy(lname,p);

  strcpy(rname,lname);
  p = strrchr(rname,'/');
  if (p)
    {
      pstring tname;
      strcpy(tname,p+1);
      strcpy(rname,tname);
    }

  if (strlen(rname) > 14)
    rname[14] = 0;

  if (strequal(lname,"-"))
    {
      f = stdin;
      strcpy(rname,"stdin");
    }
  
  clean_name(rname);

  memset(outbuf,0,smb_size);
  set_message(outbuf,2,2 + strlen(rname));
  
  CVAL(outbuf,smb_com) = SMBsplopen;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  SSVAL(outbuf,smb_vwv1,printmode);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,rname);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s opening printer for %s\n",smb_errstr(inbuf),rname);
      return;
    }
  
  if (!f)
    f = fopen(lname,"r");
  if (!f)
    {
      Debug(0,"Error opening local file %s\n",lname);
      return;
    }

  
  fnum = SVAL(inbuf,smb_vwv0);
  
  Debug(1,"printing file %s as %s\n",lname,rname);
  
  while (!feof(f))
    {
      int n;
  
      memset(outbuf,0,smb_size);
      set_message(outbuf,1,3);

      /* for some strange reason the OS/2 print server can't handle large
	 packets when printing. weird */
      n = MIN(1024,max_xmit-(smb_len(outbuf)+4));

#if 0
      if (first)
	{
	  n = 0;
	  first = False;
	}
      else
#endif
	{
	  n = fread(smb_buf(outbuf)+3,1,n,f);
	  if (n <= 0) 
	    {
	      Debug(0,"read gave %d\n",n);
	      break;
	    }
	}

      smb_setlen(outbuf,smb_len(outbuf) + n);

      CVAL(outbuf,smb_com) = SMBsplwr;
      SSVAL(outbuf,smb_tid,cnum);
      setup_pkt(outbuf);

      SSVAL(outbuf,smb_vwv0,fnum);
      SSVAL(outbuf,smb_vwv1,n+3);
      CVAL(smb_buf(outbuf),0) = 1;
      SSVAL(smb_buf(outbuf),1,n);

      send_smb(outbuf);
      receive_smb(inbuf,0);

      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  Debug(0,"%s printing remote file\n",smb_errstr(inbuf));
	  break;
	}

      nread += n;
    }

  Debug(2,"%d bytes printed\n",nread);

  memset(outbuf,0,smb_size);
  set_message(outbuf,1,0);
  CVAL(outbuf,smb_com) = SMBsplclose;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,fnum);

  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s closing print file\n",smb_errstr(inbuf));
      if (f != stdin)
	fclose(f);
      return;
    }

  if (f != stdin)
    fclose(f);
}


/****************************************************************************
delete some files
****************************************************************************/
void do_del(file_info *finfo)
{
  char *p;
  char *inbuf,*outbuf;
  pstring mask;

  strcpy(mask,cur_dir);
  strcat(mask,finfo->name);

  if (finfo->mode & aDIR) 
    return;

  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);
  
  if (!inbuf || !outbuf)
    {
      Debug(0,"out of memory\n");
      return;
    }

  memset(outbuf,0,smb_size);
  set_message(outbuf,1,2 + strlen(mask));
  
  CVAL(outbuf,smb_com) = SMBunlink;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  SSVAL(outbuf,smb_vwv0,0);
  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,mask);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    Debug(0,"%s deleting remote file %s\n",smb_errstr(inbuf),mask);

  free(inbuf);free(outbuf);
  
}


/****************************************************************************
try and browse available connections on a host
****************************************************************************/
void browse_host(char *name)
{
#if 1
  char *inbuf,*outbuf;
  char *p;

  inbuf = (char *)malloc(BUFFER_SIZE);
  outbuf = (char *)malloc(BUFFER_SIZE);

  memset(outbuf,0,177);

  strupper(name);

  if (!have_ip)
    {
      struct hostent *hp;

      if ((hp = gethostbyname(name)) == 0) 
	{
	  Debug(0,"Gethostbyname: Unknown host %s.\n",name);
	  return;
	}

      memcpy(&dest_ip,hp->h_addr,4);
    }

  /* begin constructing the packet, I don't have a spec for this so
     one example will have to do, with a lot of magic numbers */
  CVAL(outbuf,0) = 021;
  CVAL(outbuf,1) = 02;
  CVAL(outbuf,2) = 00;
  CVAL(outbuf,3) = 0112;
  CVAL(outbuf,4) = 0226;
  CVAL(outbuf,5) = 0313;
  CVAL(outbuf,6) = 017;
  CVAL(outbuf,7) = 0124;
  CVAL(outbuf,8) = 00;
  CVAL(outbuf,9) = 0212;
  CVAL(outbuf,10) = 00;
  CVAL(outbuf,11) = 0243;
  CVAL(outbuf,12) = 00;
  CVAL(outbuf,13) = 00;

  p = outbuf + 14;
  name_mangle(myname,p);
  p += name_len(p);
  name_mangle(name,p);
  p += name_len(p);

  strcat(p,"\377SMB%");

  p = outbuf + 106;

  strcat(p,"ÿÿÅƒÿÿ");

  CVAL(outbuf,117) = 07;
  CVAL(outbuf,125) = 02;
  CVAL(outbuf,135) = 0126;
  CVAL(outbuf,137) = 07;
  CVAL(outbuf,139) = 'X';
  CVAL(outbuf,141) = 3;
  CVAL(outbuf,143) = 1;
  CVAL(outbuf,147) = 02;
  CVAL(outbuf,149) = 032;

  p = outbuf + 151;

  strcat(p,"\\MAILSLOT\\BROWSE");

  p += strlen(p) + 1;

  strcat(p,"S 	");
  CVAL(outbuf,176) = 1;

  log_out(outbuf,177);  

  send_packet(outbuf,177,&dest_ip,138,SOCK_DGRAM);
#endif
}



/****************************************************************************
delete some files
****************************************************************************/
void cmd_del(char *inbuf,char *outbuf )
{
  pstring mask;
  char *p;
  int attribute = aSYSTEM | aHIDDEN;

  if (recurse)
    attribute |= aDIR;
  
  strcpy(mask,cur_dir);
  
  p = strtok(NULL,SEPARATORS);
  if (!p)
    {
      Debug(0,"del <filename>\n");
      return;
    }
  strcat(mask,p);

  do_dir((char *)inbuf,(char *)outbuf,mask,attribute,do_del,False);
}


/****************************************************************************
remove a directory
****************************************************************************/
void cmd_rmdir(char *inbuf,char *outbuf )
{
  pstring mask;
  char *p;
  
  strcpy(mask,cur_dir);
  
  p = strtok(NULL,SEPARATORS);
  if (!p)
    {
      Debug(0,"rmdir <dirname>\n");
      return;
    }
  strcat(mask,p);


  memset(outbuf,0,smb_size);
  set_message(outbuf,0,2 + strlen(mask));
  
  CVAL(outbuf,smb_com) = SMBrmdir;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  
  p = smb_buf(outbuf);
  *p++ = 4;      
  strcpy(p,mask);
  
  send_smb(outbuf);
  receive_smb(inbuf,0);
  
  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"%s removing remote directory file %s\n",smb_errstr(inbuf),mask);
      return;
    }
  
}

/****************************************************************************
toggle the prompt flag
****************************************************************************/
void cmd_prompt(void)
{
  prompt = !prompt;
  Debug(2,"prompting is now %s\n",prompt?"on":"off");
}

/****************************************************************************
toggle the lowercaseflag
****************************************************************************/
void cmd_lowercase(void)
{
  lowercase = !lowercase;
  Debug(2,"filename lowercasing is now %s\n",lowercase?"on":"off");
}




/****************************************************************************
toggle the recurse flag
****************************************************************************/
void cmd_recurse(void)
{
  recurse = !recurse;
  Debug(2,"directory recursion is now %s\n",recurse?"on":"off");
}


/****************************************************************************
do a printmode command
****************************************************************************/
void cmd_printmode(void)
{
  char *p;
  pstring mode;

  p = strtok(NULL,SEPARATORS);
  if (p)
    {
      if (strequal(p,"text"))
	printmode = 0;      
      else
	{
	  if (strequal(p,"graphics"))
	    printmode = 1;
	  else
	    printmode = atoi(p);
	}
    }

  switch(printmode)
    {
    case 0: 
      strcpy(mode,"text");
      break;
    case 1: 
      strcpy(mode,"graphics");
      break;
    default: 
      sprintf(mode,"%d",printmode);
      break;
    }

  Debug(2,"the printmode is now %s\n",mode);
}

/****************************************************************************
do the lcd command
****************************************************************************/
void cmd_lcd(void)
{
  char *p;
  pstring d;

  p = strtok(NULL,SEPARATORS);
  if (p)
    chdir(p);
  Debug(2,"the local directory is now %s\n",GetWd(d));
}


/****************************************************************************
send a login command
****************************************************************************/
BOOL send_login(char *inbuf,char *outbuf )
{
  struct {
    int prot;
    char *name;
  }
  prots[] = 
    {
      {PROT_CORE,"PC NETWORK PROGRAM 1.0"},
      {PROT_COREPLUS,"MICROSOFT NETWORKS 1.03"},
#if LANMAN1
      {PROT_LANMAN1,"MICROSOFT NETWORKS 3.0"},
      {PROT_LANMAN1,"LANMAN1.0"},
#if 0
      {PROT_LANMAN1,"XENIX CORE"},
      {PROT_LANMAN1,"LM1.2X002"},
#endif
#endif
      {-1,NULL}
    };
  char *pass = NULL;  
  pstring dev = "A:";
  char *p;
  int len = 4;
  int numprots;

  if (connect_as_printer)
    strcpy(dev,"LPT1:");

  /* send a session request (RFC 8002) */
  CVAL(outbuf,0) = 0x81;

  /* put in the destination name */
  p = outbuf+len;
  name_mangle(desthost,p);
  len += name_len(p);

  /* and my name */
  p = outbuf+len;
  name_mangle(myname,p);
  len += name_len(p);

  /* setup the packet length */
  /* We can't use smb_setlen here as it assumes a data
     packet and will trample over the name data we have copied
     in (by adding 0xFF 'S' 'M' 'B' at offsets 4 - 7 */
  CVAL(outbuf,3) = len & 0xFF;
  CVAL(outbuf,2) = (len >> 8) & 0xFF;
  if (len >= (1 << 16))
    CVAL(outbuf,1) |= 1;

  send_smb(outbuf);
  receive_smb(inbuf,0);
 
  if (CVAL(inbuf,0) != 0x82)
    {
      Debug(0,"Session request failed (%d) with myname=%s destname=%s\n",
	    CVAL(inbuf,0),myname,desthost);
      return(False);
    }      

  memset(outbuf,0,smb_size);

  /* setup the protocol strings */
  {
    int plength;
    char *p;

    for (numprots=0,plength=0;prots[numprots].name;numprots++)
      plength += strlen(prots[numprots].name)+2;
    
    set_message(outbuf,0,plength);

    p = smb_buf(outbuf);
    for (numprots=0;prots[numprots].name;numprots++)
      {
	*p++ = 2;
	strcpy(p,prots[numprots].name);
	p += strlen(p) + 1;
      }
  }

  CVAL(outbuf,smb_com) = SMBnegprot;
  setup_pkt(outbuf);

  CVAL(smb_buf(outbuf),0) = 2;

  send_smb(outbuf);
  receive_smb(inbuf,0);

  if (CVAL(inbuf,smb_rcls) != 0 || ((int)SVAL(inbuf,smb_vwv0) >= numprots))
    {
      Debug(0,"SMBnegprot failed. myname=%s destname=%s - %s \n",
	    myname,desthost,smb_errstr(inbuf));
      return(False);
    }

  max_xmit = MIN(max_xmit,(int)SVAL(inbuf,smb_vwv2));

  Debug(3,"Sec mode %d\n",SVAL(inbuf,smb_vwv1));
  Debug(3,"max xmt %d\n",SVAL(inbuf,smb_vwv2));
  Debug(3,"max mux %d\n",SVAL(inbuf,smb_vwv3));
  Debug(3,"max vcs %d\n",SVAL(inbuf,smb_vwv4));
  Debug(3,"max blk %d\n",SVAL(inbuf,smb_vwv5));
  Debug(3,"time zone %d\n",SVAL(inbuf,smb_vwv10));

  memcpy(&servertime,inbuf+smb_vwv8,sizeof(servertime));
  servertime = make_unix_date(servertime);

  Debug(3,"Got %d byte crypt key\n",strlen(smb_buf(inbuf)));

  Debug(1,"Server time is %s\n",asctime(LocalTime(&servertime)));

  Debug(3,"Chose protocol [%s]\n",prots[SVAL(inbuf,smb_vwv0)].name);
  Protocol = prots[SVAL(inbuf,smb_vwv0)].prot;
  if (Protocol >= PROT_COREPLUS)
    {
      readbraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x1) != 0);
      writebraw_supported = ((SVAL(inbuf,smb_vwv5) & 0x2) != 0);
    }

  if (got_pass)
    pass = password;
  else
    pass = getpass("Password: ");

  if (Protocol >= PROT_LANMAN1)
    {
      /* send a session setup command */
      memset(outbuf,0,smb_size);
      set_message(outbuf,10,2 + strlen(username) + strlen(pass));
      CVAL(outbuf,smb_com) = SMBsesssetupX;
      setup_pkt(outbuf);

      CVAL(outbuf,smb_vwv0) = 0xFF;
      SSVAL(outbuf,smb_vwv2,max_xmit);
      SSVAL(outbuf,smb_vwv3,1);
      SSVAL(outbuf,smb_vwv4,1);
      SSVAL(outbuf,smb_vwv7,strlen(pass)+1);
      p = smb_buf(outbuf);
      strcpy(p,pass);
      p += strlen(pass)+1;
      strcpy(p,username);

      send_smb(outbuf);
      receive_smb(inbuf,0);      

      if (CVAL(inbuf,smb_rcls) != 0)
	{
	  Debug(0,"Session setup failed for username=%s myname=%s destname=%s   %s\n",
		username,myname,desthost,smb_errstr(inbuf));
	  return(False);
	}
    }

  /* now we've got a connection - send a tcon message */
  memset(outbuf,0,smb_size);
#if 0
  if (Protocol >= PROT_LANMAN1)
    strcpy(pass,"");
#endif

 again:
  set_message(outbuf,0,6 + strlen(service) + strlen(pass) + strlen(dev));
  CVAL(outbuf,smb_com) = SMBtcon;
  setup_pkt(outbuf);

  p = smb_buf(outbuf);
  *p++ = 4;
  strcpy(p,service);
  p += strlen(p) + 1;
  *p++ = 4;
  strcpy(p,pass);
  p += strlen(p) + 1;
  *p++ = 4;
  strcpy(p,dev);

  send_smb(outbuf);
  receive_smb(inbuf,0);

  /* trying again with a blank password */
  if (CVAL(inbuf,smb_rcls) != 0 && 
      strlen(pass) > 0 && 
      Protocol >= PROT_LANMAN1)
    {
      strcpy(pass,"");
      goto again;
    }  

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"SMBtcon failed. %s\n",smb_errstr(inbuf));
      return(False);
    }
  

  max_xmit = SVAL(inbuf,smb_vwv0);
  max_xmit = MIN(max_xmit,BUFFER_SIZE-4);
  if (max_xmit <= 0)
    max_xmit = BUFFER_SIZE - 4;

  cnum = SVAL(inbuf,smb_vwv1);

  Debug(3,"Connected with cnum=%d max_xmit=%d\n",cnum,max_xmit);

  /* wipe out the password from memory */
  if (got_pass)
    memset(password,0,strlen(password));

  return True;

}


/****************************************************************************
send a logout command
****************************************************************************/
void send_logout(char *inbuf,char *outbuf )
{
  set_message(outbuf,0,0);

  CVAL(outbuf,smb_com) = SMBtdis;
  SSVAL(outbuf,smb_tid,cnum);
  setup_pkt(outbuf);

  send_smb(outbuf);
  receive_smb(inbuf,0);

  if (CVAL(inbuf,smb_rcls) != 0)
    {
      Debug(0,"SMBtdis failed %s\n",smb_errstr(inbuf));
    }
#ifdef STATS
  stats_report();
#endif
  exit(0);
}



void cmd_help();

/* This defines the commands supported by this client */
struct
{
  char *name;
  void (*fn)();
  char *description;
} commands[] = 
{
  {"ls",cmd_dir,"<mask> list the contents of the current directory"},
  {"dir",cmd_dir,"<mask> list the contents of the current directory"},
  {"lcd",cmd_lcd,"[directory] change/report the local current working directory"},
  {"cd",cmd_cd,"[directory] change/report the remote directory"},
  {"get",cmd_get,"<remote name> [local name] get a file"},
  {"mget",cmd_mget,"<mask> get all the matching files"},
  {"put",cmd_put,"<local name> [remote name] put a file"},
  {"mput",cmd_mput,"<mask> put all matching files"},
  {"mask",cmd_select,"<mask> mask all filenames against this"},
  {"del",cmd_del,"<mask> delete all matching files"},
  {"rm",cmd_del,"<mask> delete all matching files"},
  {"mkdir",cmd_mkdir,"<directory> make a directory"},
  {"md",cmd_mkdir,"<directory> make a directory"},
  {"rmdir",cmd_rmdir,"<directory> remove a directory"},
  {"rd",cmd_rmdir,"<directory> remove a directory"},
  {"prompt",cmd_prompt,"toggle prompting for filenames for mget and mput"},  
  {"recurse",cmd_recurse,"toggle directory recursion for mget and mput"},  
  {"lowercase",cmd_lowercase,"toggle lowercasing of filenames for get"},  
  {"print",cmd_print,"<file name> print a file"},
  {"printmode",cmd_printmode,"<graphics or text> set the print mode"},
  {"quit",send_logout,"logoff the server"},
  {"exit",send_logout,"logoff the server"},
  {"help",cmd_help,"[command] give help on a command"},
  {"?",cmd_help,"[command] give help on a command"},
  {"",NULL}
};

/****************************************************************************
help
****************************************************************************/
void cmd_help(void)
{
  int i=0;
  char *p;

  p = strtok(NULL,SEPARATORS);
  if (p)
    {
      while (commands[i].fn)
	{
	  if (strequal(commands[i].name,p))	  
	    Debug(0,"HELP %s:\n\t%s\n\n",commands[i].name,commands[i].description);
	  i++;
	}
    }
  else
    while (commands[i].fn)
      {
	Debug(0,"%s\n",commands[i].name);
	i++;
      }
}

/****************************************************************************
open the client sockets
****************************************************************************/
BOOL open_sockets(int port )
{
  struct sockaddr_in sock_out;
  char *host;
  pstring service2;
  extern int Client;

  strupper(service);

  strcpy(service2,service);
  host = strtok(service2,"\\/");
  strcpy(desthost,host);
  if (*myname == 0)
    {
      get_myname(myname,NULL);
      strupper(myname);
    }

  if (!have_ip)
    {
      struct hostent *hp;

      if ((hp = gethostbyname(host)) == 0) 
	{
	  Debug(0,"Gethostbyname: Unknown host %s.\n",host);
	  return False;
	}

      memcpy(&dest_ip,hp->h_addr,4);
    }

  /* create a socket to write to */
  Client = socket(PF_INET, SOCK_STREAM, 0);
  if (Client == -1) 
    {
      Debug(0,"socket error\n");
      return False;
    }
  
  memset(&sock_out, 0, sizeof(sock_out));
  memcpy(&sock_out.sin_addr, &dest_ip,4);
  
  sock_out.sin_port = htons( port );
  sock_out.sin_family = PF_INET;
  
  /* and connect it to the destination */
  if (connect(Client,(struct sockaddr *)&sock_out,sizeof(sock_out))<0)
    {
      Debug(0,"connect error\n");
      close(Client);
      return False;
    }

  {
    int one=1;
    setsockopt(Client,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one));
  }

  return True;
}

/****************************************************************************
wait for keyboard activity, smallowing network packets
****************************************************************************/
void wait_keyboard(char *buffer)
{
  fd_set fds;
  int selrtn;
  struct timeval timeout;

  while (1) 
    {
      extern int Client;
      FD_ZERO(&fds);
      FD_SET(Client,&fds);
      FD_SET(fileno(stdin),&fds);

      do 
	{
	  timeout.tv_sec = 20;
	  timeout.tv_usec = 0;
	  selrtn = select(255,SELECT_CAST &fds,NULL,NULL,&timeout);
	}
      while(selrtn < 0 && errno == EINTR);

      if (FD_ISSET(fileno(stdin),&fds))
	return;

      if (FD_ISSET(Client,&fds))
	receive_smb(buffer,0);

      chkpath("\\",False);
    }

}


/****************************************************************************
try and register my own netbios name with a unicast
****************************************************************************/
void register_myname(void)
{
  name_struct name;

  name.valid = True;
  strcpy(name.name,myname);
  strupper(name.name);
  strcpy(name.flags,"");
  name.ip = myip;
  name.ttl = 0;
  name.nb_flags = 0;

  register_name(&name,&dest_ip,NULL);
}


/****************************************************************************
  process commands from the client
****************************************************************************/
void process(void )
{
  pstring line;

  InBuffer = (char *)malloc(BUFFER_SIZE);
  OutBuffer = (char *)malloc(BUFFER_SIZE);
  if ((InBuffer == NULL) || (OutBuffer == NULL)) 
    return;
  
  memset(OutBuffer,0,smb_size);

  register_myname();

  if (!send_login(InBuffer,OutBuffer))
    return;

  while (!feof(stdin))
    {
      char *tok;
      int i;
      BOOL found = False;

      memset(OutBuffer,0,smb_size);

      /* display a prompt */
      Debug(1,"smb: %s> ", cur_dir);

      wait_keyboard(InBuffer);

      /* and get a response */
      if (!fgets(line,1000,stdin))
	break;

      /* and get the first part of the command */
      tok = strtok(line,SEPARATORS);
      
      i = 0;
      while (commands[i].fn != NULL)
	{
	  if (strequal(commands[i].name,tok))
	    {
	      found = True;
	      commands[i].fn(InBuffer,OutBuffer);
	    }
	  i++;
	}
      if (!found && tok)
	Debug(0,"%s: command not found\n",tok);
    }
  
  memset(OutBuffer,0,smb_size);
  send_logout(InBuffer,OutBuffer);
}


/****************************************************************************
usage on the program
****************************************************************************/
void usage(char *pname)
{
  Debug(0,"Usage: %s service <password> [-p port] [-d debuglevel] [-l log]\n",pname);
  Debug(0,"\t-p port               listen on the specified port\n");
  Debug(0,"\t-d debuglevel         set the debuglevel\n");
  Debug(0,"\t-l log basename.      Basename for log/debug files\n");
  Debug(0,"\t-n netbios name.      Use this name as my netbios name\n");
  Debug(0,"\t-N                    don't ask for a password\n");
  Debug(0,"\t-P                    connect to service as a printer\n");
  Debug(0,"\t-I dest IP            use this IP to connect to\n");
  Debug(0,"\t-E                    write messages to stderr instead of stdout\n");
  Debug(0,"\t-U username           set the network username\n");
  Debug(0,"\n");
}



/****************************************************************************
  main program
****************************************************************************/
int main(int argc,char *argv[])
{
  int port = 139;
  int opt;
  extern FILE *dbf;
  extern int DEBUGLEVEL;
  extern char *optarg;
  pstring query_host="";

  DEBUGLEVEL = 2;
  dbf = stdout;

  pid = getpid();
  uid = getuid();
  gid = getgid();
  myumask = umask(0);
  umask(myumask);

  if (getenv("USER"))
    {
      strcpy(username,getenv("USER"));
      strupper(username);
    }

  if (*username == 0 && getenv("LOGNAME"))
    {
      strcpy(username,getenv("LOGNAME"));
      strupper(username);
    }

  if (argc < 2)
    {
      usage(argv[0]);
      exit(0);
    }
  
  if (*argv[1] == '-')
    strcpy(service,"");  
  else
    {
      strcpy(service,argv[1]);  
      argc--;
      argv++;
    }

  if (argc > 1 && (*argv[1] != '-'))
    {
      got_pass = True;
      strcpy(password,argv[1]);  
      memset(argv[1],'X',strlen(argv[1]));
      argc--;
      argv++;
    }

  while ((opt = getopt (argc, argv, "Nn:d:Pp:l:hI:EB:U:Q:")) != EOF)
    switch (opt)
      {
      case 'Q':
	strcpy(query_host,optarg);
	break;
      case 'U':
	{
	  char *p;
	strcpy(username,optarg);
	if ((p=strchr(username,'%')))
	  {
	    *p = 0;
	    strcpy(password,p+1);
	    got_pass = True;
	    memset(strchr(optarg,'%')+1,'X',strlen(password));
	  }
	}
	    
	break;
      case 'E':
	dbf = stderr;
	break;
      case 'I':
	{
	  unsigned long a = inet_addr(optarg);
	  memcpy(&dest_ip,&a,sizeof(a));
	  have_ip = True;
	}
	break;
      case 'n':
	strcpy(myname,optarg);
	break;
      case 'N':
	got_pass = True;
	break;
      case 'P':
	connect_as_printer = True;
	break;
      case 'd':
	DEBUGLEVEL = atoi(optarg);
	break;
      case 'l':
	strcpy(debugf,optarg);
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
  
  Debug(3,"%s client started\n",timestring());

  if (DEBUGLEVEL > 2)
    {
      extern FILE *login,*logout;
      pstring fname;
      sprintf(fname,"%s.client.in",debugf);
      login = fopen(fname,"w"); 
      sprintf(fname,"%s.client.out",debugf);
      logout = fopen(fname,"w");
    }

#if 0
  /* Read the broadcast address from the interface */
  get_broadcast(&myip,&bcast_ip,&Netmask);
#endif

  get_myname(*myname?NULL:myname,&myip);  
  
  if (*query_host)
    {
      browse_host(query_host);
      return(0);
    }

  if (open_sockets(port))
    {
      process();
      close_sockets();
    }
  return(0);
}


#ifndef _LOADPARM_H
/* This is a dummy lp_keepalive() for the client only */
int lp_keepalive()
{
return(0);
}
#endif


/* error code stuff - put together by Merik Karman
   merik@blackadder.dsh.oz.au */

typedef struct
{
  char *name;
  int code;
  char *message;
} err_code_struct;

/* Dos Error Messages */
err_code_struct dos_msgs[] = {
  {"ERRbadfunc",1,"Invalid function."},
  {"ERRbadfile",2,"File not found."},
  {"ERRbadpath",3,"Directory invalid."},
  {"ERRnofids",4,"No file descriptors available"},
  {"ERRnoaccess",5,"Access denied."},
  {"ERRbadfid",6,"Invalid file handle."},
  {"ERRbadmcb",7,"Memory control blocks destroyed."},
  {"ERRnomem",8,"Insufficient server memory to perform the requested function."},
  {"ERRbadmem",9,"Invalid memory block address."},
  {"ERRbadenv",10,"Invalid environment."},
  {"ERRbadformat",11,"Invalid format."},
  {"ERRbadaccess",12,"Invalid open mode."},
  {"ERRbaddata",13,"Invalid data."},
  {"ERR",14,"reserved."},
  {"ERRbaddrive",15,"Invalid drive specified."},
  {"ERRremcd",16,"A Delete Directory request attempted  to  remove  the  server's  current directory."},
  {"ERRdiffdevice",17,"Not same device."},
  {"ERRnofiles",18,"A File Search command can find no more files matching the specified criteria."},
  {"ERRbadshare",32,"The sharing mode specified for an Open conflicts with existing  FIDs  on the file."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an  invalid mode,  or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRfilexists",80,"The file named in a Create Directory, Make  New  File  or  Link  request already exists."},
  {"ERRbadpipe",230,"Pipe invalid."},
  {"ERRpipebusy",231,"All instances of the requested pipe are busy."},
  {"ERRpipeclosing",232,"Pipe close in progress."},
  {"ERRnotconnected",233,"No process on other end of pipe."},
  {"ERRmoredata",234,"There is more data to be returned."},
  {NULL,-1,NULL}};

/* Server Error Messages */
err_code_struct server_msgs[] = {
  {"ERRerror",1,"Non-specific error code."},
  {"ERRbadpw",2,"Bad password - name/password pair in a Tree Connect or Session Setup are invalid."},
  {"ERRbadtype",3,"reserved."},
  {"ERRaccess",4,"The requester does not have  the  necessary  access  rights  within  the specified  context for the requested function. The context is defined by the TID or the UID."},
  {"ERRinvnid",5,"The tree ID (TID) specified in a command was invalid."},
  {"ERRinvnetname",6,"Invalid network name in tree connect."},
  {"ERRinvdevice",7,"Invalid device - printer request made to non-printer connection or  non-printer request made to printer connection."},
  {"ERRqfull",49,"Print queue full (files) -- returned by open print file."},
  {"ERRqtoobig",50,"Print queue full -- no space."},
  {"ERRqeof",51,"EOF on print queue dump."},
  {"ERRinvpfid",52,"Invalid print file FID."},
  {"ERRsmbcmd",64,"The server did not recognize the command received."},
  {"ERRsrverror",65,"The server encountered an internal error, e.g., system file unavailable."},
  {"ERRfilespecs",67,"The file handle (FID) and pathname parameters contained an invalid  combination of values."},
  {"ERRreserved",68,"reserved."},
  {"ERRbadpermits",69,"The access permissions specified for a file or directory are not a valid combination.  The server cannot set the requested attribute."},
  {"ERRreserved",70,"reserved."},
  {"ERRsetattrmode",71,"The attribute mode in the Set File Attribute request is invalid."},
  {"ERRpaused",81,"Server is paused. (reserved for messaging)"},
  {"ERRmsgoff",82,"Not receiving messages. (reserved for messaging)."},
  {"ERRnoroom",83,"No room to buffer message. (reserved for messaging)."},
  {"ERRrmuns",87,"Too many remote user names. (reserved for messaging)."},
  {"ERRtimeout",88,"Operation timed out."},
  {"ERRnoresource",89,"No resources currently available for request."},
  {"ERRtoomanyuids",90,"Too many UIDs active on this session."},
  {"ERRbaduid",91,"The UID is not known as a valid ID on this session."},
  {"ERRusempx",250,"Temp unable to support Raw, use MPX mode."},
  {"ERRusestd",251,"Temp unable to support Raw, use standard read/write."},
  {"ERRcontmpx",252,"Continue in MPX mode."},
  {"ERRreserved",253,"reserved."},
  {"ERRreserved",254,"reserved."},
  {"ERRnosupport",0xFFFF,"Function not supported."},
  {NULL,-1,NULL}};

/* Hard Error Messages */
err_code_struct hard_msgs[] = {
  {"ERRnowrite",19,"Attempt to write on write-protected diskette."},
  {"ERRbadunit",20,"Unknown unit."},
  {"ERRnotready",21,"Drive not ready."},
  {"ERRbadcmd",22,"Unknown command."},
  {"ERRdata",23,"Data error (CRC)."},
  {"ERRbadreq",24,"Bad request structure length."},
  {"ERRseek",25 ,"Seek error."},
  {"ERRbadmedia",26,"Unknown media type."},
  {"ERRbadsector",27,"Sector not found."},
  {"ERRnopaper",28,"Printer out of paper."},
  {"ERRwrite",29,"Write fault."},
  {"ERRread",30,"Read fault."},
  {"ERRgeneral",31,"General failure."},
  {"ERRbadshare",32,"A open conflicts with an existing open."},
  {"ERRlock",33,"A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process."},
  {"ERRwrongdisk",34,"The wrong disk was found in a drive."},
  {"ERRFCBUnavail",35,"No FCBs are available to process request."},
  {"ERRsharebufexc",36,"A sharing buffer has been exceeded."},
  {NULL,-1,NULL}};


struct
{
  int code;
  char *class;
  err_code_struct *err_msgs;
} err_classes[] = { 
  {0,"SUCCESS",NULL},
  {0x01,"ERRDOS",dos_msgs},
  {0x02,"ERRSRV",server_msgs},
  {0x03,"ERRHRD",hard_msgs},
  {0x04,"ERRXOS",NULL},
  {0xE1,"ERRRMX1",NULL},
  {0xE2,"ERRRMX2",NULL},
  {0xE3,"ERRRMX3",NULL},
  {0xFF,"ERRCMD",NULL},
  {-1,NULL,NULL}};


/****************************************************************************
return a SMB error string from a SMB buffer
****************************************************************************/
char *smb_errstr(char *inbuf)
{
  static pstring ret;
  int class = CVAL(inbuf,smb_rcls);
  int num = SVAL(inbuf,smb_err);
  int i,j;

  for (i=0;err_classes[i].class;i++)
    if (err_classes[i].code == class)
      {
	if (err_classes[i].err_msgs)
	  {
	    err_code_struct *err = err_classes[i].err_msgs;
	    for (j=0;err[j].name;j++)
	      if (num == err[j].code)
		{
		  extern int DEBUGLEVEL;
		  if (DEBUGLEVEL > 0)
		    sprintf(ret,"%s - %s (%s)",err_classes[i].class,
			    err[j].name,err[j].message);
		  else
		    sprintf(ret,"%s - %s",err_classes[i].class,err[j].name);
		  return ret;
		}
	  }

	sprintf(ret,"%s - %d",err_classes[i].class,num);
	return ret;
      }
  
  sprintf(ret,"ERROR: Unknown error (%d,%d)",class,num);
  return(ret);
}
