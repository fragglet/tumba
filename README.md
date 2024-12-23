**Rumba** is a stripped-down fork of a very old version of
[Samba](https://en.wikipedia.org/wiki/Samba_software), for retro computing
purposes.

Recent versions of Samba have removed support for the old protocols used in the
Windows 3.x and 9x days. This is a completely understandable move for the
project to have made; however, it does mean that there's no longer a way for
vintage Windows machines to connect to Samba shares. Since the SMB protocol is
Win9x's native file sharing protocol, it's useful to have an alternative that
does support these old versions.

This is heavily stripped back and intentionally does *not* include all of
Samba's features. The goal is to make something simple and easy to set up that
hopefully requires minimal maintenance. In particular the following are not
supported:

 * Authentication/password-restricted shares (all shares are public)
 * Per-user home directory shares
 * Printer sharing
 * NIS, automount, and any of Samba's more obscure bells and whistles you may
   have used in the past.

There is also (currently) no implementation of nmbd here, which you will need
to get a working setup. You can just use the normal Samba version of nmbd.

**This is based on a very old version of Samba, and there may be bugs or security
issues hiding in here that have since been fixed in mainline Samba. This is
purely for fun and personal use by hobbyists and retro enthusiasts. You should
*not* use this for anything serious or mission critical. You have been warned.**
