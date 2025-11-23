
DESTDIR =
PREFIX = /usr/local
MANPATH = $(PREFIX)/share/man
DATADIR = /var/tumba

PUBLIC_SHARE = $(DESTDIR)$(DATADIR)/public
READONLY_SHARE = $(DESTDIR)$(DATADIR)/readonly

DEFINES = -D_FORTIFY_SOURCE=1

IWYU = iwyu
IWYU_FLAGS = --error --mapping_file=.iwyu-overrides.imp
IWYU_TRANSFORMED_FLAGS = $(patsubst %,-Xiwyu %,$(IWYU_FLAGS))

CFLAGS = -O2 -MMD -Wall $(DEFINES)
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
	strfunc.o            \
	strlcat.o            \
	strlcpy.o            \
	system.o             \
	timefunc.o           \
	trans2.o             \
	util.o

NMBD_OBJECTS = \
	nameserv.o           \
	strfunc.o            \
	timefunc.o           \
	util.o

DEPS = $(patsubst %.o,%.d,$(OBJECTS) $(NMBD_OBJECTS))

all: tumba_smbd tumba_nmbd

tumba_smbd: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@

tumba_nmbd: $(NMBD_OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(NMBD_OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) $(NMBD_OBJECTS) tumba_smbd tumba_nmbd $(DEPS)

format:
	clang-format -i *.[ch]

$(PUBLIC_SHARE):
	mkdir -m 777 -p $@
	install -m 666 doc-public.txt $@/README.txt

$(READONLY_SHARE):
	mkdir -m 755 -p $@
	install -m 644 doc-readonly.txt $@/README.txt

install: $(PUBLIC_SHARE) $(READONLY_SHARE) tumba_smbd tumba_nmbd
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 755 tumba_smbd $(DESTDIR)$(PREFIX)/bin/tumba_smbd
	install -m 755 tumba_nmbd $(DESTDIR)$(PREFIX)/bin/tumba_nmbd
	mkdir -p $(DESTDIR)$(PREFIX)/lib/systemd/system
	install -m 644 tumba_smbd.service $(DESTDIR)$(PREFIX)/lib/systemd/system/tumba_smbd.service
	install -m 644 tumba_nmbd.service $(DESTDIR)$(PREFIX)/lib/systemd/system/tumba_nmbd.service
	mkdir -m 755 -p $(DESTDIR)$(MANPATH)/man8
	install tumba_smbd.8 $(DESTDIR)$(MANPATH)/man8/tumba_smbd.8
	install tumba_nmbd.8 $(DESTDIR)$(MANPATH)/man8/tumba_nmbd.8

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/tumba_smbd
	rm -f $(DESTDIR)$(PREFIX)/bin/tumba_nmbd
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/tumba_smbd.service
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/tumba_nmbd.service
	rm -f $(DESTDIR)$(MANPATH)/man8/tumba_smbd.8
	rm -f $(DESTDIR)$(MANPATH)/man8/tumba_nmbd.8
	@echo
	@echo "*** NOTE: The $(DESTDIR)$(DATADIR) directory that contains the"
	@echo "*** default shares has not been deleted. You may want to delete"
	@echo "*** that manually."
	@echo

fixincludes:
	for d in $(patsubst %.o,%.c,$(OBJECTS) $(NMBD_OBJECTS)); do \
		$(IWYU) $(IWYU_TRANSFORMED_FLAGS) 2>&1 $$d | fix_include; \
	done

.PHONY: clean format all install

-include $(DEPS)
