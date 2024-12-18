###########################################################################
# Makefile for netbios client/server for unix
# Copyright Andrew Tridgell 1992,1993
###########################################################################

# The base manpages directory to put the man pages in
# Note: $(MANDIR)/man1, $(MANDIR)/man5 and $(MANDIR)/man8 must exist.
MANDIR = /usr/local/man

# The directory to put the executables in
INSTALLDIR = /home/nimbus/tridge/server

# The permissions to give the server executables
INSTALLPERMS_S = 0755

# The permissions to give the client and test executables
INSTALLPERMS_C = 0755

# Add -DLANMAN1=1 if you want LANMAN1 in the server (not recommended).
# It will be in the client by default. If you don't want it in the client
# use -DLANMAN1=0. It is recommended that you keep it in the client.
FLAGS1 = 
LIBS1 = 

# If you have the gcc compiler then use it, otherwise any ansi-C compiler
CC = gcc

# set these to where to find various files
# These can be overridden by command line switches (see smbserver(8))
FLAGS2 = -DDEBUGFILE=\"/home/nimbus/tridge/server/log\"
FLAGS3 = -DSERVICES=\"/home/nimbus/tridge/server/smb.conf\"

# set this to the name of the default account, which is the one
# to use when no username or password is specified.  This can be overridden
# in the runtime configuration file (see smb.conf(5))
FLAGS4 = -DGUEST_ACCOUNT=\"tridge\"

# what mode mask to use when creating files and directories
# This can be overridden in the runtime configuration file (see smb.conf(5))
FLAGS5 = -DDEF_CREATE_MASK=0755

# Use this for Linux without shadow passwords
FLAGSM = -DLINUX
LIBSM = -lcrypt

CFLAGS = $(FLAGS1) $(FLAGS2) $(FLAGS3) $(FLAGS4) $(FLAGS5) $(FLAGSM)
LIBS = $(LIBS1) $(LIBSM)

all: smbserver nmbserver testparm

INCLUDES = local.h includes.h smb.h loadparm.h params.h

smbserver: server.o util.o loadparm.o params.o access.o
	$(CC) $(CFLAGS) -o smbserver server.o util.o loadparm.o params.o \
                        access.o $(LIBS)

nmbserver: nameserv.o util.o
	$(CC) $(CFLAGS) -o nmbserver nameserv.o util.o $(LIBS)

testparm: testparm.o util.o loadparm.o params.o access.o
	$(CC) $(CFLAGS) -o testparm testparm.o util.o loadparm.o params.o \
                        access.o $(LIBS)

install: installman installbin

installbin:
	cp smbserver nmbserver testparm $(INSTALLDIR)
	chmod $(INSTALLPERMS_S) $(INSTALLDIR)/smbserver
	chmod $(INSTALLPERMS_S) $(INSTALLDIR)/nmbserver
	chmod $(INSTALLPERMS_C) $(INSTALLDIR)/testparm

installman:
	cp *.1 $(MANDIR)/man1
	cp *.5 $(MANDIR)/man5
	cp *.8 $(MANDIR)/man8
	chmod u=rw,go=r $(MANDIR)/man1/testparm.1
	chmod u=rw,go=r $(MANDIR)/man5/smb.conf.5
	chmod u=rw,go=r $(MANDIR)/man8/smbserver.8
	chmod u=rw,go=r $(MANDIR)/man8/nmbserver.8
	
source:
	tar cfv sources.tar COPYING README Makefile announce bugs change-log \
                            smb.conf.sample \
                            *.c *.h

.c.o:
	$(CC) $(CFLAGS) -c $<

%.o: $(INCLUDES)

clean:
	rm -f *.o *~ *.tar smbserver nmbserver testparm
