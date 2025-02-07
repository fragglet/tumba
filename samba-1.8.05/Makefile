###########################################################################
# Makefile for Samba SMB client/server for unix
# Copyright Andrew Tridgell 1992,1993,1994
###########################################################################

# Add any optimisation or debugging flags here
FLAGS1 = -O -Wall
LIBS1 = 

# If you have the gcc compiler then use it, otherwise any ansi-C compiler
# under SunOS you might try the sun acc compiler.
CC = gcc

# set these to where to find various files
# These can be overridden by command line switches (see smbd(8))
# or in smb.conf (see smb.conf(5))
FLAGS2 = -DDEBUGFILE=\"/usr/local/samba/log\"

# Use this for Linux without shadow passwords
FLAGSM = -DLINUX
LIBSM = 

######################################################################
# DON'T EDIT BELOW THIS LINE
######################################################################
CFLAGS = $(FLAGS1) $(FLAGS2) $(FLAGS3) $(FLAGS4) $(FLAGS5) $(FLAGS6) $(FLAGS7) $(FLAGSM) $(FLAGSS)
LIBS = $(LIBS1) $(LIBSM)

FIND_UNUSED_CODE = 1

ifdef FIND_UNUSED_CODE
CFLAGS += -ffunction-sections -fdata-sections
LIBS += -Wl,--gc-sections -Wl,--print-gc-sections
endif

PROGS = nmbd

all : $(PROGS)

nmbd: nameserv.o util.o
	$(CC) $(CFLAGS) -o nmbd nameserv.o util.o $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f core *.o *~ smbd smbrun smbclient nmbd testparm testprns smbstatus

