
# The base directory for all samba files
PREFIX = /usr/local

SHAREDIR = $(PREFIX)/share
LIBDIR = $(PREFIX)/lib

# the default group you want your machine to appear in for browsing.
WORKGROUP = WORKGROUP

CONFIGFILE = /etc/rumba_smbd.conf
SMBLOGFILE = /var/log/rumba_smbd.log

DEFINES = -DWORKGROUP=\"$(WORKGROUP)\" \
          -DCONFIGFILE=\"$(CONFIGFILE)\" \
          -DSMBLOGFILE=\"$(SMBLOGFILE)\"

CFLAGS = -MMD -Wall $(DEFINES)

OBJECTS = \
	dir.o                \
	fault.o              \
	ipc.o                \
	loadparm.o           \
	locking.o            \
	mangle.o             \
	params.o             \
	reply.o              \
	server.o             \
	slprintf.o           \
	strlcat.o            \
	strlcpy.o            \
	system.o             \
	time.o               \
	trans2.o             \
	util.o

DEPS = $(patsubst %.o,%.d,$(OBJECTS))

all: rumba_smbd

rumba_smbd: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) rumba_smbd $(DEPS)

format:
	clang-format -i *.[ch]

.PHONY: clean format all

-include $(DEPS)
