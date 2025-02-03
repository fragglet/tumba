###########################################################################
# Makefile for Samba SMB client/server for unix
# Copyright Andrew Tridgell 1992,1993,1994
###########################################################################

# The base manpages directory to put the man pages in
# Note: $(MANDIR)/man1, $(MANDIR)/man5 and $(MANDIR)/man8 must exist.
MANDIR = /usr/local/man

# The directory to put the executables in
INSTALLDIR = /usr/local/samba

# The permissions to give the executables
INSTALLPERMS = 0755

# Add any optimisation or debugging flags here
FLAGS1 = -O
LIBS1 = 

# If you have the gcc compiler then use it, otherwise any ansi-C compiler
# under SunOS you might try the sun acc compiler.
CC = gcc

# set these to where to find various files
# These can be overridden by command line switches (see smbd(8))
# or in smb.conf (see smb.conf(5))
FLAGS2 = -DDEBUGFILE=\"/usr/local/samba/log\"
FLAGS3 = -DSERVICES=\"/usr/local/samba/smb.conf\"
FLAGS4 = -DLMHOSTS=\"/usr/local/samba/lmhosts\"
FLAGS5 = -DLOCKDIR=\"/usr/local/samba/locks\"

# set this to the name of the default account, which is the one
# to use when no username or password is specified.  This can be overridden
# in the runtime configuration file (see smb.conf(5))
# NOTE: The account "nobody" may not be a good one as
# on many unixes it may not be able to print. Thus you
# might have to create a separate guest account that can print.
FLAGS6 = -DGUEST_ACCOUNT=\"nobody\"

# what mode mask to use when creating files and directories
# This can be overridden in the runtime configuration file (see smb.conf(5))
FLAGS7 = -DDEF_CREATE_MASK=0755

# where you are going to have the smbrun binary. This defaults to the 
# install directory. This binary is needed for correct printing
# and magic script execution. This should be an absolute path!
SMBRUN = $(INSTALLDIR)/smbrun

#####################################
# WHICH OPERATING SYSTEM?
# UNCOMMENT ONE OF THE SECTIONS BELOW
# MAKE SURE ONLY *ONE* IS UNCOMMENTED
#
# The following are additional flags that may apply
#   -DNETGROUP if your machine supports yp netgroups
#   -DSHADOW_PWD if you are using shadow passwords
#   -DPWDAUTH if your library has a pwdauth() call
#   -DGETPWANAM if you wish to use getpwanam() instead of pwdauth()
#   -DUFC_CRYPT if you want the fast crypt routine
#   -DALLOW_CHANGE_PASSWORD if you want users to be bale to set their password
#                           remotely (experimental)
#                            
#    NOTE: GETPWANAM & PWDAUTH are mutually exclusive, if you
#          Define one, you should NOT define the other.
#####################################

# This is for SUNOS. Note that you cannot use Suns "cc" compiler
# as it's not an Ansi-C compiler. Get gcc or acc. You also
# might need the -DGETPWANAM (or -DPWDAUTH) flag if you
# use an adjunct password map. GETPWANAM is much faster.
# FLAGSM = -DSUN
# LIBSM =   

# Use this for Linux with shadow passwords
# FLAGSM = -DLINUX -DSHADOW_PWD
# LIBSM = -lshadow

# Use this for Linux without shadow passwords
# FLAGSM = -DLINUX
# LIBSM = 

# This is for SOLARIS (add -DSOLARIS2_2 if using 2.2)
# FLAGSM = -DSOLARIS -DSHADOW_PWD -DNETGROUP -DBSD_COMP
# LIBSM = -lsocket -lnsl

# This is for SVR4
# FLAGSM = -DSVR4 -DSHADOW_PWD
# LIBSM = -lsocket -lnsl -lc -L/usr/ucblib -lucb

# This is for ULTRIX. Add -DULTRIX_AUTH for Ultrix enhanced security.
# FLAGSM = -DULTRIX -DUSE_DIRECT
# LIBSM =   

# This is for OSF1 (Alpha)
# FLAGSM = -DOSF1
# LIBSM =

# This is for OSF1 (Alpha) V2.0 Enhanced Security 
# contributed by Udo Linauer <ul@eacpc4.tuwien.ac.at>
# FLAGSM = -DOSF1 -DOSF1_ENH_SEC
# LIBSM = -lsecurity

# This is for AIX
# FLAGSM = -DAIX
# LIBSM =   

# This is for BSDI (tomh@metrics.com)
# FLAGSM = -DBSDI -DUSE_DIRECT
# LIBSM =   

# This is for NetBSD. Add -DNETBSD_1_0 if you are using 1.0
# FLAGSM = -DNETBSD -DUSE_DIRECT -DSHADOW_PWD
# LIBSM = -lcrypt 

# This is for SEQUENT. Can someone test this please?
# FLAGSM = -DSEQUENT -DPWDAUTH -DUSE_DIRECT
# LIBSM =   

# This is for HP-UX. Note that some systems don't like the -Aa switch.
# FLAGSM = -DHPUX -Aa -D_HPUX_SOURCE -D_POSIX_SOURCE
# LIBSM = 

# This is for SGI.
# FOR SGI IRIX 4.x.x, use the following line
# FLAGSM = -DSGI -DUSE_DIRECT -DHAVE_TIMEZONE
# LIBSM =

# FOR SGI IRIX 5.x.x, use this line instead
# FLAGSM = -DSGI -DSHADOW_PWD -DUSE_DIRECT -DHAVE_TIMEZONE
# LIBSM =

# This is for FreeBSD
# FLAGSM = -DFreeBSD -DUSE_DIRECT
# LIBSM = -lcrypt 

# This is for NeXT. Note that versions of NeXT less than 3.2 
# don't properly support posix, so they may present problems
# FLAGSM = -DNEXT -posix
# LIBSM = 

# This is for NeXT OS 2.x - Brad Greer 5/7/94
# No Posix, use 'cc' for C compiler (CC above).
# FLAGSM = -DNEXT2 
# LIBSM = 

# This is for NeXT OS 3.0 - Brad Greer 5/7/94
# No Posix, use 'cc' for C compiler (CC above).
#FLAGSM = -DNEXT3_0
#LIBSM = 

# This is for ISC SVR3V4
# FLAGSM = -posix -D_SYSV3 -fpcc-struct-return -DISC -DSHADOW_PWD
# LIBSM = -lsec -lcrypt -linet

#Note: The SCO entries require the libcrypt library. You can get it via
#anonymous ftp from ftp.sco.com:/SLS/lng225b.* or ftp.uu.net:/vendors/sco
#
# Use this for SCO with shadow passwords. Tested on "Open enterprise 3.0"
# SCO changes from Heinz Mauelshagen (mauelsha@ez.da.telekom.de)
# FLAGSM = -DSCO -DSHADOW_PWD -DNETGROUP
# LIBSM = -lyp -lrpc -lyp -lsec -lsocket -lcrypt_i -lintl

# Use this for SCO with shadow passwords, without YP.
# Tested on "Open Enterprise Server 3.0" (John Owens john@micros.com)
# Also, use "CC = cc" above.
# FLAGSM = -DSCO -DSHADOW_PWD
# LIBSM = -lsec -lsocket -lcrypt_i

# Use this for SCO with TCB passwords (default).
# Tested on "Open enterprise 3.0". Contributed by lance@fox.com.
# CC     = cc
# FLAGSM = -DSCO -DSecureWare
# LIBSM  = -lprot_s -lcrypt -lsocket -lm -lc_s

# This is for intergraph. (contributed by cjkiick@flinx.b11.ingr.com)
# FLAGSM = -DCLIX
# LIBSM = -lbsd


# This is for DGUX. Contributed by ross@augie.insci.com (ross andrus)
# FLAGSM = -DDGUX 
# LIBSM  = 

# This is for Apollo Domain/OS sr10.3 (systype = BSD4.3)
# Added 1994-07-08 Stephen C. Steel <steve@qv3donald.LeidenUniv.nl>
# additional patches by jmi@csd.cri.dk (John Mills)
# you may need the "-A ansi" switch to cc
# FLAGSM = -DAPOLLO -D_INCLUDE_BSD_SOURCE -D_INCLUDE_XOPEN_SOURCE
# LIBSM =


######################################################################
# DON'T EDIT BELOW THIS LINE
######################################################################
FLAGSS = -DSMBRUN=\"$(SMBRUN)\" 
CFLAGS = $(FLAGS1) $(FLAGS2) $(FLAGS3) $(FLAGS4) $(FLAGS5) $(FLAGS6) $(FLAGS7) $(FLAGSM) $(FLAGSS)
LIBS = $(LIBS1) $(LIBSM)

PROGS = smbd smbclient nmbd testparm testprns smbrun smbstatus

all : CHECK $(PROGS)

CHECK :
	@if [ "$(FLAGSM)" = "" ];  then \
		echo "You forgot to uncomment an OS type in the Makefile"; \
		exit 1; \
	fi; exit 0

INCLUDES1 = version.h local.h includes.h smb.h loadparm.h params.h 
INCLUDES2 = pcap.h trans2.h reply.h
INCLUDES = $(INCLUDES1) $(INCLUDES2)

SMBDOBJ1 = server.o util.o loadparm.o params.o access.o pcap.o trans2.o 
SMBDOBJ2 = password.o ufc.o kanji.o ipc.o reply.o mangle.o chgpasswd.o
SMBDOBJ = $(SMBDOBJ1) $(SMBDOBJ2) 

smbd: $(SMBDOBJ)
	$(CC) $(CFLAGS) -o smbd $(SMBDOBJ) $(LIBS)

smbrun: smbrun.o
	$(CC) $(CFLAGS) -o smbrun smbrun.o $(LIBS)

nmbd: nameserv.o util.o
	$(CC) $(CFLAGS) -o nmbd nameserv.o util.o kanji.o $(LIBS)

smbclient: client.o util.o kanji.o
	$(CC) $(CFLAGS) -o smbclient client.o util.o kanji.o $(LIBS)

smbstatus: status.o util.o kanji.o
	$(CC) $(CFLAGS) -o smbstatus status.o util.o kanji.o $(LIBS)

testparm: testparm.o util.o loadparm.o params.o access.o pcap.o kanji.o
	$(CC) $(CFLAGS) -o testparm testparm.o util.o loadparm.o params.o \
                        access.o pcap.o kanji.o $(LIBS)

testprns: testprns.o loadparm.o params.o util.o pcap.o
	$(CC) $(CFLAGS) -o testprns testprns.o loadparm.o params.o util.o \
                        pcap.o kanji.o $(LIBS)

install: installbin installman

installbin: all
	@echo
	@echo "IGNORE ANY \"File exists\" MESSAGES FROM THIS COMMAND"
	-mkdir $(INSTALLDIR)
	@echo
	@echo "IGNORE ANY \"No such file\" MESSAGES FROM THESE COMMANDS"
	-for i in $(PROGS); do \
		mv $(INSTALLDIR)/$$i $(INSTALLDIR)/$$i.old ; \
	done
	@echo
	@echo "INSTALLING IN "$(INSTALLDIR)
	for i in $(PROGS); do \
		cp $$i $(INSTALLDIR)/$$i ; \
		chmod $(INSTALLPERMS) $(INSTALLDIR)/$$i ; \
	done
	@echo
	@echo "INSTALLATION COMPLETE. TO REVERT TO THE PREVIOUS VERSION"
	@echo "USE \"make revert\""

# revert to the previously installed version
revert:
	@echo 
	@echo "REVERTING TO PREVIOUS VERSION"
	for i in $(PROGS); do \
		mv $(INSTALLDIR)/$$i $(INSTALLDIR)/$$i.new ; \
		mv $(INSTALLDIR)/$$i.old $(INSTALLDIR)/$$i ; \
		rm -f $(INSTALLDIR)/$$i.new ; \
	done


installman:
	@echo
	@echo "INSTALLING MANUAL PAGES"
	cp *.1 $(MANDIR)/man1
	cp *.5 $(MANDIR)/man5
	cp *.8 $(MANDIR)/man8
	chmod u=rw,go=r $(MANDIR)/man1/smbstatus.1
	chmod u=rw,go=r $(MANDIR)/man1/smbclient.1
	chmod u=rw,go=r $(MANDIR)/man1/smbrun.1
	chmod u=rw,go=r $(MANDIR)/man1/testparm.1
	chmod u=rw,go=r $(MANDIR)/man1/testprns.1
	chmod u=rw,go=r $(MANDIR)/man5/smb.conf.5
	chmod u=rw,go=r $(MANDIR)/man8/smbd.8
	chmod u=rw,go=r $(MANDIR)/man8/nmbd.8
	
source:
	tar cfv sources.tar COPYING README THANKS \
                            Makefile announce bugs change-log \
                            history smb.conf.sample \
                            *.c *.h *.[158]

.c.o: $(INCLUDES)
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm -f core *.o *~ smbd smbrun smbclient nmbd testparm testprns smbstatus

