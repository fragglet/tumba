#ifdef QUOTAS
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   support for quotas
   Copyright (C) Andrew Tridgell 1992-1998
   
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
 * This is one of the most system dependent parts of Samba, and its
 * done a litle differently. Each system has its own way of doing 
 * things :-(
 */

#include "includes.h"

extern int DEBUGLEVEL;

#ifdef LINUX

#include <sys/types.h>
#include <asm/types.h>
#include <sys/quota.h>

#include <mntent.h>
#include <linux/unistd.h>

_syscall4(int, quotactl, int, cmd, const char *, special, int, id, caddr_t, addr);

/****************************************************************************
try to get the disk space from disk quotas (LINUX version)
****************************************************************************/

BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  uid_t euser_id;
  int r;
  struct dqblk D;
  struct stat S;
  FILE *fp;
  struct mntent *mnt;
  int devno;
  int found;
  
  /* find the block device file */
  
  if ( stat(path, &S) == -1 ) {
    return(False) ;
  }

  devno = S.st_dev ;
  
  fp = setmntent(MOUNTED,"r");
  found = False ;
  
  while ((mnt = getmntent(fp))) {
    if ( stat(mnt->mnt_dir,&S) == -1 )
      continue ;
    if (S.st_dev == devno) {
      found = True ;
      break ;
    }
  }
  endmntent(fp) ;
  
  if (!found) {
      return(False);
    }

  euser_id=geteuid();
  seteuid(0);  
  r=quotactl(QCMD(Q_GETQUOTA,USRQUOTA), mnt->mnt_fsname, euser_id, (caddr_t)&D);
      seteuid(euser_id);

  /* Use softlimit to determine disk space, except when it has been exceeded */
  *bsize = 1024;
  if (r)
    {
      if (errno == EDQUOT) 
       {
         *dfree =0;
         *dsize =D.dqb_curblocks;
         return (True);
    }
      else return(False);
  }
  /* Use softlimit to determine disk space, except when it has been exceeded */
  if (
      (D.dqb_bsoftlimit && D.dqb_curblocks>=D.dqb_bsoftlimit) ||
      (D.dqb_bhardlimit && D.dqb_curblocks>=D.dqb_bhardlimit) ||
      (D.dqb_isoftlimit && D.dqb_curinodes>=D.dqb_isoftlimit) ||
      (D.dqb_ihardlimit && D.dqb_curinodes>=D.dqb_ihardlimit)
     )
    {
      *dfree = 0;
      *dsize = D.dqb_curblocks;
    }
  else if (D.dqb_bsoftlimit==0 && D.dqb_bhardlimit==0)
    {
      return(False);
    }
  else {
    if (D.dqb_bsoftlimit == 0)
      D.dqb_bsoftlimit = D.dqb_bhardlimit;
    *dfree = D.dqb_bsoftlimit - D.dqb_curblocks;
    *dsize = D.dqb_bsoftlimit;
  }
  return (True);
}

#elif defined(CRAY)

#include <sys/quota.h>
#include <mntent.h>

/****************************************************************************
try to get the disk space from disk quotas (CRAY VERSION)
****************************************************************************/
BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  struct mntent *mnt;
  FILE *fd;
  struct stat sbuf;
  dev_t devno ;
  static dev_t devno_cached = 0 ;
  static pstring name;
  struct q_request request ;
  struct qf_header header ;
  static int quota_default = 0 ;
  int found ;
  
  if ( stat(path,&sbuf) == -1 )
    return(False) ;
  
  devno = sbuf.st_dev ;
  
  if ( devno != devno_cached ) {
    
    devno_cached = devno ;
    
    if ((fd = setmntent(KMTAB)) == NULL)
      return(False) ;
    
    found = False ;
    
    while ((mnt = getmntent(fd)) != NULL) {
      
      if ( stat(mnt->mnt_dir,&sbuf) == -1 )
	continue ;
      
      if (sbuf.st_dev == devno) {
	
	found = True ;
	break ;
	
      }
      
    }
    
    pstrcpy(name,mnt->mnt_dir) ;
    endmntent(fd) ;
    
    if ( ! found )
      return(False) ;
  }
  
  request.qf_magic = QF_MAGIC ;
  request.qf_entry.id = geteuid() ;
  
  if (quotactl(name, Q_GETQUOTA, &request) == -1)
    return(False) ;
  
  if ( ! request.user )
    return(False) ;
  
  if ( request.qf_entry.user_q.f_quota == QFV_DEFAULT ) {
    
    if ( ! quota_default ) {
      
      if ( quotactl(name, Q_GETHEADER, &header) == -1 )
	return(False) ;
      else
	quota_default = header.user_h.def_fq ;
    }
    
    *dfree = quota_default ;
    
  }else if ( request.qf_entry.user_q.f_quota == QFV_PREVENT ) {
    
    *dfree = 0 ;
    
  }else{
    
    *dfree = request.qf_entry.user_q.f_quota ;
    
  }
  
  *dsize = request.qf_entry.user_q.f_use ;
  
  if ( *dfree )
    *dfree -= *dsize ;
  
  if ( *dfree < 0 )
    *dfree = 0 ;
  
  *bsize = 4096 ;  /* Cray blocksize */
  
  return(True) ;
  
}


#else

#if    defined(__FreeBSD__) || defined(__OpenBSD__)
#include <ufs/ufs/quota.h>
#include <machine/param.h>
#else /* !__FreeBSD__ && !AIX && !__OpenBSD__ */
#include <sys/quota.h>
#include <devnm.h>
#endif

/****************************************************************************
try to get the disk space from disk quotas - default version
****************************************************************************/
BOOL disk_quotas(char *path, int *bsize, int *dfree, int *dsize)
{
  uid_t euser_id;
  int r;
  struct dqblk D;
#if !defined(__FreeBSD__) && !defined(AIX) && !defined(__OpenBSD__)
  char dev_disk[256];
  struct stat S;
  /* find the block device file */
  if ((stat(path, &S)<0) ||
      (devnm(S_IFBLK, S.st_dev, dev_disk, 256, 0)<0)) return (False);
#endif

  euser_id = geteuid();

#ifdef USE_SETRES
  {
    uid_t user_id;

    /* for HPUX, real uid must be same as euid to execute quotactl for euid */
    user_id = getuid();
    setresuid(euser_id,-1,-1);
    r=quotactl(Q_GETQUOTA, dev_disk, euser_id, &D);
    if (setresuid(user_id,-1,-1))
      DEBUG(5,("Unable to reset uid to %d\n", user_id));
  }
#else /* USE_SETRES */
#if defined(__FreeBSD__) || defined(__OpenBSD__)
  {
    /* FreeBSD patches from Marty Moll <martym@arbor.edu> */
    uid_t user_id;
    gid_t egrp_id;
 
    /* Need to be root to get quotas in FreeBSD */
    user_id = getuid();
    egrp_id = getegid();
    setuid(0);
    seteuid(0);
    r= quotactl(path,QCMD(Q_GETQUOTA,USRQUOTA),euser_id,(char *) &D);

    /* As FreeBSD has group quotas, if getting the user
       quota fails, try getting the group instead. */
    if (r)
      r= quotactl(path,QCMD(Q_GETQUOTA,GRPQUOTA),egrp_id,(char *) &D);
    setuid(user_id);
    seteuid(euser_id);
  }
#else /* !__FreeBSD__ && !AIX && !__OpenBSD__ */
  r=quotactl(Q_GETQUOTA, dev_disk, euser_id, &D);
#endif /* !__FreeBSD__ && !AIX && !__OpenBSD__ */
#endif /* USE_SETRES */

  /* Use softlimit to determine disk space, except when it has been exceeded */
#if defined(__FreeBSD__) || defined(__OpenBSD__)
  *bsize = DEV_BSIZE;
#else /* !__FreeBSD__ && !__OpenBSD__ */
  *bsize = 1024;
#endif /*!__FreeBSD__ && !__OpenBSD__ */

  if (r)
    {
      if (errno == EDQUOT) 
	{
 	  *dfree =0;
 	  *dsize =D.dqb_curblocks;
 	  return (True);
	}
      else return(False);
    }
  if (D.dqb_bsoftlimit==0)
    return(False);
  /* Use softlimit to determine disk space, except when it has been exceeded */
  if ((D.dqb_curblocks>D.dqb_bsoftlimit)
#if !defined(__FreeBSD__) && !defined(__OpenBSD__)
||((D.dqb_curfiles>D.dqb_fsoftlimit) && (D.dqb_fsoftlimit != 0))
#endif
    ) {
      *dfree = 0;
      *dsize = D.dqb_curblocks;
    }
  else {
    *dfree = D.dqb_bsoftlimit - D.dqb_curblocks;
    *dsize = D.dqb_bsoftlimit;
  }
  return (True);
}

#endif

#else
/* this keeps fussy compilers happy */
 void quotas_dummy(void) {}
#endif /* QUOTAS */

