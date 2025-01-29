/*
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

int reply_special(char *inbuf, char *outbuf);
int reply_tcon(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_tcon_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_unknown(char *inbuf, char *outbuf);
int reply_ioctl(char *inbuf, char *outbuf, int size, int bufsize);
int reply_sesssetup_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_chkpth(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_getatr(char *inbuf, char *outbuf, int in_size, int buffsize);
int reply_setatr(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_dskattr(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_search(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_fclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_open(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_open_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_ulogoffX(char *inbuf, char *outbuf, int length, int bufsize);
int reply_mknew(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_ctemp(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_unlink(char *inbuf, char *outbuf, int dum_size, int dum_bufsize);
int reply_readbraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_lockread(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_read(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_read_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_writebraw(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_writeunlock(char *inbuf, char *outbuf, int dum_size,
                      int dum_buffsize);
int reply_write(char *inbuf, char *outbuf, int dum1, int dum2);
int reply_write_and_X(char *inbuf, char *outbuf, int length, int bufsize);
int reply_lseek(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_flush(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_exit(char *inbuf, char *outbuf, int size, int bufsize);
int reply_close(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_writeclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_lock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_unlock(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_tdis(char *inbuf, char *outbuf, int size, int bufsize);
int reply_echo(char *inbuf, char *outbuf, int size, int bufsize);
int reply_printopen(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_printclose(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_printqueue(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_printwrite(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_mkdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_rmdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_mv(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_copy(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_setdir(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_lockingX(char *inbuf, char *outbuf, int length, int bufsize);
int reply_readbmpx(char *inbuf, char *outbuf, int length, int bufsize);
int reply_writebmpx(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_writebs(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_setattrE(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
int reply_getattrE(char *inbuf, char *outbuf, int dum_size, int dum_buffsize);
