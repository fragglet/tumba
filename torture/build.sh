#!/usr/bin/env bash
#
# TODO: This should eventually be a Github Action CI test

set -eu

if [ ! -e z ]; then
	mkdir -p z
	ln -s $(which python2) z/python
fi

export PATH="$PWD/z:$PATH" CFLAGS="-fpermissive"

cd samba
sed -i "s/HAVE_BSD_MD5_H/disabled_BSD_MD5_H/" lib/crypto/md5.h
./configure --disable-python \
            --without-ad-dc \
            --without-acl-support \
            --without-systemd \
            --without-gettext \
            --without-ads \
            --without-pam \
            --without-ntvfs-fileserver  \
            --without-quotas \
            --without-dmapi  \
            --without-libarchive  \
            --without-sendfile-support \
            --without-gpgme \
            --without-syslog \
            --without-ldap
make "${@:-smbtorture3}"
