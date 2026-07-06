#!/bin/sh
#
# This script is invoked by make after `make install` completes, to give the
# user some useful messaging.

# Our current messages are only useful to people who are using Linux distros
# that use systemd for service management.
if ! pidof systemd >/dev/null 2>&1; then
	exit 0
fi

echo "*** Service files for systemd have been installed; to start Tumba, run:"
echo "***     systemctl start tumba_smbd tumba_nmbd"
echo "***"

if pidof smbd nmbd >/dev/null 2>&1; then
	echo "*** However, Samba services are running; you should probably" \
	     "stop them first:"
	echo "***     systemctl stop smbd nmbd"
	echo "***"
fi
