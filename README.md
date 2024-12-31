**Rumba** is a stripped-down fork of a very old version of
[Samba](https://en.wikipedia.org/wiki/Samba_software), for retro computing
purposes.

Recent versions of Samba have
[removed support](https://www.theregister.com/2019/07/09/samba_sans_one_smb1/)
for the older SMBv1 protocol used in the
Windows 3.x and 9x days. This is absolutely the right move for the
project to have made; however, it does mean that there's no longer an easy
way to share files with vintage Windows machines. Since SMBv1 is
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

## Tested with

* Windows 3.11, 95, 98
* Windows NT 3.51, 4
* Windows 2000, XP
* OS/2 Warp 4.52
* Samba (smbclient; recent versions of Samba still support connecting to old shares)

## FAQ

* **Why is there no support for password protected shares?** The old SMBv1 protocol
  is very insecure, especially earlier versions. I made a deliberate decision not to
  give the illusion of security that passwords would imply. Other methods such
  as firewalls can be used to restrict access to shares if desired, though if
  something is being shared that's important enough to *need* password protection,
  you should be using a different protocol.

* **Why remove all the features of Samba?** Partly to make it a smaller and simpler
  codebase, partly to intentionally deter any use of the project for serious use cases.
  There are probably people out there still needing to use SMBv1 for various reasons
  and I do **not** want to end up supporting a full fork of Samba and its many, many
  features. This aims to do one thing and do it well, which is to share files with old
  machines.
