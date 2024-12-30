
// The following were config options, but have been replaced with inline
// functions that return constants. The function comments are from the manpage
// for smb.conf.

// This options allows you to override the name of the Samba log file (also
// known as the debug file).
static inline char *lp_logfile(void)
{
	return "";
}

// This allows you to override the config file to use, instead of the default
// (usually smb.conf).
static inline char *lp_configfile(void)
{
	return "";
}

// This controls what string will show up in the printer comment box in print
// manager and next to the IPC connection in "net view".
static inline char *lp_serverstring(void)
{
	return "Rumba " VERSION;
}

// This controls what workgroup your server will appear to be in when queried
// by clients.
static inline char *lp_workgroup(void)
{
	return WORKGROUP;
}

// This option allows you to control what address Samba will listen for
// connections on.
static inline char *lp_socket_address(void)
{
	return "0.0.0.0";
}

// This parameter controls whether or not the server will support raw reads
// when transferring data to clients.
static inline bool lp_readraw(void)
{
	return true;
}

// This parameter controls whether or not the server will support raw writes
// when transferring data from clients.
static inline bool lp_writeraw(void)
{
	return true;
}

// This is a boolean that controls whether to strip trailing dots off UNIX
// filenames. This helps with some CDROMs that have filenames ending in a
// single dot.
static inline bool lp_strip_dot(void)
{
	return false;
}

// If this parameter is set then Samba debug messages are logged into the
// system syslog only, and not to the debug log files.
static inline bool lp_syslog_only(void)
{
	return false;
}

// This option (an integer in kilobytes) specifies the max size the log file
// should grow to. Samba periodically checks the size and if it is exceeded it
// will rename the file, adding a .old extension.
static inline int lp_max_log_size(void)
{
	return 5000;
}

// This option controls the maximum packet size that will be negotiated by
// Samba. The default is 65535, which is the maximum.
static inline int lp_maxxmit(void)
{
	return 65535;
}

// The option "read size" affects the overlap of disk reads/writes with network
// reads/writes.
static inline int lp_readsize(void)
{
	return 16 * 1024;
}

// This parameter maps how Samba debug messages are logged onto the system
// syslog logging levels.
static inline int lp_syslog(void)
{
	return 1;
}
