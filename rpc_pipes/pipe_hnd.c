
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "../includes.h"


#define	PIPE		"\\PIPE\\"
#define	PIPELEN		strlen(PIPE)

extern int DEBUGLEVEL;
static int chain_pnum = -1;

#ifndef MAX_OPEN_PIPES
#define MAX_OPEN_PIPES 50
#endif

#define PIPE_HANDLE_OFFSET 0x800

static struct
{
  int cnum;
  BOOL open; /* open connection */
  uint16 device_state;
  fstring name;

} Pipes[MAX_OPEN_PIPES];

#define VALID_PNUM(pnum)   (((pnum) >= 0) && ((pnum) < MAX_OPEN_PIPES))
#define OPEN_PNUM(pnum)    (VALID_PNUM(pnum) && Pipes[pnum].open)
#define PNUM_OK(pnum,c) (OPEN_PNUM(pnum) && (c)==Pipes[pnum].cnum)


/****************************************************************************
  reset pipe chain handle number
****************************************************************************/
void reset_chain_pnum(void)
{
	chain_pnum = -1;
}

/****************************************************************************
  initialise pipe handle states...
****************************************************************************/
void init_rpc_pipe_hnd(void)
{
	int i;
	/* we start at 1 here for an obscure reason I can't now remember,
	but I think is important :-) */
	for (i = 1; i < MAX_OPEN_PIPES; i++)
	{
		Pipes[i].open = False;
	}

	return;
}

/****************************************************************************
  find first available file slot
****************************************************************************/
int open_rpc_pipe_hnd(char *pipe_name, int cnum)
{
	int i;
	/* we start at 1 here for an obscure reason I can't now remember,
	but I think is important :-) */
	for (i = 1; i < MAX_OPEN_PIPES; i++)
	{
		if (!Pipes[i].open)
		{
			Pipes[i].open = True;
			Pipes[i].device_state = 0;
			Pipes[i].cnum = cnum;
			fstrcpy(Pipes[i].name, pipe_name);

			DEBUG(4,("Opened pipe %s with handle %x\n",
			           pipe_name, i + PIPE_HANDLE_OFFSET));

			chain_pnum = i;

			return(i);
		}
	}

	DEBUG(1,("ERROR! Out of pipe structures - perhaps increase MAX_OPEN_PIPES?\n"));

	return(-1);
}

/****************************************************************************
  gets the name of a pipe
****************************************************************************/
char *get_rpc_pipe_hnd_name(int pnum)
{
	DEBUG(6,("get_pipe_name: "));

	if (VALID_PNUM(pnum - PIPE_HANDLE_OFFSET))
	{
		DEBUG(6,("name: %s cnum: %d open: %s ",
		          Pipes[pnum - PIPE_HANDLE_OFFSET].name,
		          Pipes[pnum - PIPE_HANDLE_OFFSET].cnum,
		          BOOLSTR(Pipes[pnum - PIPE_HANDLE_OFFSET].open)));
	}
	if (OPEN_PNUM(pnum - PIPE_HANDLE_OFFSET))
	{
		DEBUG(6,("OK\n"));
		return Pipes[pnum - PIPE_HANDLE_OFFSET].name;
	}
	else
	{
		DEBUG(6,("NOT\n"));
		return NULL;
	}
}

/****************************************************************************
  set device state on a pipe.  exactly what this is for is unknown...
****************************************************************************/
BOOL set_rpc_pipe_hnd_state(int pnum, int cnum, uint16 device_state)
{
  /* mapping is PIPE_HANDLE_OFFSET up... */

  if (PNUM_OK(pnum-PIPE_HANDLE_OFFSET, cnum))
  {
    DEBUG(3,("%s Setting pipe device state=%x on pipe name %s pnum=%x cnum=%d\n",
	   timestring(), device_state,
       Pipes[pnum-PIPE_HANDLE_OFFSET].name, pnum,cnum));
  
    Pipes[pnum-PIPE_HANDLE_OFFSET].device_state = device_state;
    return True;
  }
  else
  {
    DEBUG(3,("%s Error setting pipe device state=%x (pnum=%x cnum=%d)\n",
	   timestring(), device_state, pnum, cnum));
    return False;
  }
}

/****************************************************************************
  close an rpc pipe
****************************************************************************/
BOOL close_rpc_pipe_hnd(int pnum, int cnum)
{
  /* mapping is PIPE_HANDLE_OFFSET up... */

  if (PNUM_OK(pnum-PIPE_HANDLE_OFFSET,cnum))
  {
    DEBUG(3,("%s Closed pipe name %s pnum=%x cnum=%d\n",
	   timestring(),Pipes[pnum-PIPE_HANDLE_OFFSET].name, pnum,cnum));
  
    Pipes[pnum-PIPE_HANDLE_OFFSET].open = False;
    return True;
  }
  else
  {
    DEBUG(3,("%s Error closing pipe pnum=%x cnum=%d\n",
	   timestring(),pnum, cnum));
    return False;
  }
}

/****************************************************************************
  close an rpc pipe
****************************************************************************/
int get_rpc_pipe_num(char *buf, int where)
{
	return (chain_pnum != -1 ? chain_pnum : SVAL(buf,where));
}

