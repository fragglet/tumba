#!/bin/sh
if [ x"$1" = x"" ]; then
cat << EOF
=====================================================================
You forgot to uncomment a host type and flags in the Makefile. If your
host type does not appear in the Makefile then choose one that you
think is similar and once you have it working then add a new host type
to the Makefile and includes.h. Please also send us the output of the
command "uname" on your system so this can be automated at some future
time. 

samba-bugs@samba.anu.edu.au
=====================================================================
EOF
exit 1
fi

exit 0
