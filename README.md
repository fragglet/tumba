**Rumba** is a stripped-down fork of a very old version of
[Samba](https://en.wikipedia.org/wiki/Samba_software), for retro computing
purposes.

Recent versions of Samba have removed support for the old protocols used in the
Windows 3.x and 9x days. This is a completely understandable move for them to
make; however, it means that there's no longer a way for vintage Windows
machines to connect to Samba shares. Since the SMB protocol is Win9x's native
file sharing protocol, it's useful to have an alternative that does support
these old versions.

This intentionally does *not* include all of Samba's features. In particular
the following are not supported:

 * Authentication/password-restricted shares (public only)
 * Per-user shares
 * Printer sharing
