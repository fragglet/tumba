/*
 * Copyright (c) 1992-1998 Andrew Tridgell
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stddef.h>

int reply_special(char *inbuf, char *outbuf);
int reply_tcon(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_tcon_and_X(char *inbuf, char *outbuf, size_t inbuf_len,
                     size_t outbuf_len);
int reply_unknown(char *inbuf, char *outbuf);
int reply_ioctl(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_sesssetup_and_X(char *inbuf, char *outbuf, size_t inbuf_len,
                          size_t outbuf_len);
int reply_chkpth(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_getatr(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_setatr(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_dskattr(char *inbuf, char *outbuf, size_t inbuf_len,
                  size_t outbuf_len);
int reply_search(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_fclose(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_open(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_open_and_X(char *inbuf, char *outbuf, size_t inbuf_len,
                     size_t outbuf_len);
int reply_ulogoffX(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
int reply_mknew(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_ctemp(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_unlink(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_readbraw(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
int reply_lockread(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
int reply_read(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_read_and_X(char *inbuf, char *outbuf, size_t inbuf_len,
                     size_t outbuf_len);
int reply_writebraw(char *inbuf, char *outbuf, size_t inbuf_len,
                    size_t outbuf_len);
int reply_writeunlock(char *inbuf, char *outbuf, size_t inbuf_len,
                      size_t outbuf_len);
int reply_write(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_write_and_X(char *inbuf, char *outbuf, size_t inbuf_len,
                      size_t outbuf_len);
int reply_lseek(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_flush(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_exit(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_close(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_writeclose(char *inbuf, char *outbuf, size_t inbuf_len,
                     size_t outbuf_len);
int reply_lock(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_unlock(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_tdis(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_echo(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_printfn(char *inbuf, char *outbuf, size_t inbuf_len,
                  size_t outbuf_len);
int reply_mkdir(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_rmdir(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_mv(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_copy(char *inbuf, char *outbuf, size_t inbuf_len, size_t outbuf_len);
int reply_setdir(char *inbuf, char *outbuf, size_t inbuf_len,
                 size_t outbuf_len);
int reply_lockingX(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
int reply_readbmpx(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
int reply_writebmpx(char *inbuf, char *outbuf, size_t inbuf_len,
                    size_t outbuf_len);
int reply_writebs(char *inbuf, char *outbuf, size_t inbuf_len,
                  size_t outbuf_len);
int reply_setattrE(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
int reply_getattrE(char *inbuf, char *outbuf, size_t inbuf_len,
                   size_t outbuf_len);
