
# The base directory for all samba files
PREFIX = /usr/local/samba

SHAREDIR = $(PREFIX)/share
LIBDIR = $(PREFIX)/lib

CODEPAGEDIR = $(LIBDIR)/samba/codepages

# the default group you want your machine to appear in for browsing.
WORKGROUP = WORKGROUP

CONFIGFILE = /etc/rumba_smbd.conf
SMBLOGFILE = /var/log/rumba_smbd.log

DEFINES = -DCODEPAGEDIR=\"$(CODEPAGEDIR)\" \
          -DWORKGROUP=\"$(WORKGROUP)\" \
          -DCONFIGFILE=\"$(CONFIGFILE)\" \
          -DSMBLOGFILE=\"$(SMBLOGFILE)\"

CFLAGS = -MMD $(DEFINES)

OBJECTS = \
	charcnv.o            \
	charset.o            \
	dir.o                \
	fault.o              \
	ipc.o                \
	kanji.o              \
	loadparm.o           \
	locking.o            \
	locking_slow.o       \
	mangle.o             \
	params.o             \
	password.o           \
	reply.o              \
	server.o             \
	slprintf.o           \
	system.o             \
	time.o               \
	trans2.o             \
	uid.o                \
	username.o           \
	util.o

DEPS = $(patsubst %.o,%.d,$(OBJECTS))

rumba_smbd: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) rumba_smbd $(DEPS)

-include $(DEPS)
