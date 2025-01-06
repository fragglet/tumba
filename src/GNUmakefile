
# The base directory for all samba files
PREFIX = /usr/local

SHAREDIR = $(PREFIX)/share
LIBDIR = $(PREFIX)/lib

SMBLOGFILE = /var/log/rumba_smbd.log

DEFINES = -DSMBLOGFILE=\"$(SMBLOGFILE)\"

CFLAGS = -MMD -Wall $(DEFINES)
LDFLAGS =

ifdef FIND_UNUSED_CODE
CFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections -Wl,--print-gc-sections
endif

OBJECTS = \
	dir.o                \
	ipc.o                \
	locking.o            \
	mangle.o             \
	reply.o              \
	server.o             \
	shares.o             \
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
