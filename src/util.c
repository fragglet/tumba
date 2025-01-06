/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

static uint8_t valid_dos_chars[32];

int DEBUGLEVEL = 1;

int Protocol = PROTOCOL_COREPLUS;

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;

/* the client file descriptor */
int Client = -1;

/* this is used by the chaining code */
int chain_size = 0;

pstring debugf = "";
int syslog_level;

fstring local_machine = "";

fstring myworkgroup = "";

int smb_read_error = 0;

static bool stdout_logging = false;

/*******************************************************************
  get ready for syslog stuff
  ******************************************************************/
void setup_logging(char *pname, bool interactive)
{
	if (!interactive) {
		char *p = strrchr(pname, '/');
		if (p)
			pname = p + 1;
		openlog(pname, LOG_PID, SYSLOG_FACILITY);
	}
	if (interactive) {
		stdout_logging = true;
		dbf = stdout;
	}
}

bool append_log = false;

/****************************************************************************
reopen the log files
****************************************************************************/
void reopen_logs(void)
{
	pstring fname;

	if (DEBUGLEVEL > 0) {
		pstrcpy(fname, debugf);
		if (strlen(lp_logfile()) > 0) {
			pstrcpy(fname, lp_logfile());
		}

		if (!strcsequal(fname, debugf) || !dbf ||
		    !file_exist(debugf, NULL)) {
			int oldumask = umask(022);
			pstrcpy(debugf, fname);
			if (dbf)
				fclose(dbf);
			if (append_log)
				dbf = fopen(debugf, "a");
			else
				dbf = fopen(debugf, "w");
			/*
			 * Fix from klausr@ITAP.Physik.Uni-Stuttgart.De
			 * to fix problem where smbd's that generate less
			 * than 100 messages keep growing the log.
			 */
			force_check_log_size();
			if (dbf)
				setbuf(dbf, NULL);
			umask(oldumask);
		}
	} else {
		if (dbf) {
			fclose(dbf);
			dbf = NULL;
		}
	}
}

/*******************************************************************
 Number of debug messages that have been output.
 Used to check log size.
********************************************************************/

static int debug_count = 0;

/*******************************************************************
 Force a check of the log size.
********************************************************************/

void force_check_log_size(void)
{
	debug_count = 100;
}

/*******************************************************************
 Check if the log has grown too big
********************************************************************/

static void check_log_size(void)
{
	int maxlog;
	struct stat st;

	if (debug_count++ < 100 || getuid() != 0)
		return;

	maxlog = lp_max_log_size() * 1024;
	if (!dbf || maxlog <= 0)
		return;

	if (fstat(fileno(dbf), &st) == 0 && st.st_size > maxlog) {
		fclose(dbf);
		dbf = NULL;
		reopen_logs();
		if (dbf && file_size(debugf) > maxlog) {
			pstring name;
			fclose(dbf);
			dbf = NULL;
			slprintf(name, sizeof(name) - 1, "%s.old", debugf);
			rename(debugf, name);
			reopen_logs();
		}
	}
	debug_count = 0;
}

/*******************************************************************
write an debug message on the debugfile. This is called by the DEBUG
macro
********************************************************************/
int Debug1(char *format_str, ...)
{
	va_list ap;
	int old_errno = errno;

	if (stdout_logging) {
		va_start(ap, format_str);
		vfprintf(dbf, format_str, ap);
		va_end(ap);
		errno = old_errno;
		return 0;
	}

	if (!dbf) {
		int oldumask = umask(022);
		if (append_log)
			dbf = fopen(debugf, "a");
		else
			dbf = fopen(debugf, "w");
		umask(oldumask);
		if (dbf) {
			setbuf(dbf, NULL);
		} else {
			errno = old_errno;
			return 0;
		}
	}

	if (syslog_level < lp_syslog()) {
		/*
		 * map debug levels to syslog() priorities
		 * note that not all DEBUG(0, ...) calls are
		 * necessarily errors
		 */
		static int priority_map[] = {
		    LOG_ERR,     /* 0 */
		    LOG_WARNING, /* 1 */
		    LOG_NOTICE,  /* 2 */
		    LOG_INFO,    /* 3 */
		};
		int priority;
		pstring msgbuf;

		if (syslog_level >=
		        sizeof(priority_map) / sizeof(priority_map[0]) ||
		    syslog_level < 0)
			priority = LOG_DEBUG;
		else
			priority = priority_map[syslog_level];

		va_start(ap, format_str);
		vslprintf(msgbuf, sizeof(msgbuf) - 1, format_str, ap);
		va_end(ap);

		msgbuf[255] = '\0';
		syslog(priority, "%s", msgbuf);
	}

	va_start(ap, format_str);
	vfprintf(dbf, format_str, ap);
	va_end(ap);
	fflush(dbf);

	check_log_size();

	errno = old_errno;

	return 0;
}

/****************************************************************************
prompte a dptr (to make it recently used)
****************************************************************************/
void array_promote(char *array, int elsize, int element)
{
	char *p;
	if (element == 0)
		return;

	p = (char *) malloc(elsize);

	if (!p) {
		DEBUG(5, ("Ahh! Can't malloc\n"));
		return;
	}
	memcpy(p, array + element * elsize, elsize);
	memmove(array + elsize, array, elsize * element);
	memcpy(array, p, elsize);
	free(p);
}

/****************************************************************************
  close the socket communication
****************************************************************************/
void close_sockets(void)
{
	close(Client);
	Client = 0;
}

/****************************************************************************
interpret the weird netbios "name". Return the name type
****************************************************************************/
static int name_interpret(char *in, char *out)
{
	int ret;
	int len = (*in++) / 2;

	*out = 0;

	if (len > 30 || len < 1)
		return 0;

	while (len--) {
		if (in[0] < 'A' || in[0] > 'P' || in[1] < 'A' || in[1] > 'P') {
			*out = 0;
			return 0;
		}
		*out = ((in[0] - 'A') << 4) + (in[1] - 'A');
		in += 2;
		out++;
	}
	*out = 0;
	ret = out[-1];

#ifdef NETBIOS_SCOPE
	/* Handle any scope names */
	while (*in) {
		*out++ = '.'; /* Scope names are separated by periods */
		len = *(unsigned char *) in++;
		strlcpy(out, in, len + 1);
		out += len;
		*out = 0;
		in += len;
	}
#endif
	return ret;
}

/*******************************************************************
  check if a file exists
********************************************************************/
bool file_exist(char *fname, struct stat *sbuf)
{
	struct stat st;
	if (!sbuf)
		sbuf = &st;

	if (stat(fname, sbuf) != 0)
		return false;

	return S_ISREG(sbuf->st_mode);
}

/*******************************************************************
  check if a directory exists
********************************************************************/
bool directory_exist(char *dname, struct stat *st)
{
	struct stat st2;
	bool ret;

	if (!st)
		st = &st2;

	if (stat(dname, st) != 0)
		return false;

	ret = S_ISDIR(st->st_mode);
	if (!ret)
		errno = ENOTDIR;
	return ret;
}

/*******************************************************************
returns the size in bytes of the named file
********************************************************************/
uint32_t file_size(char *file_name)
{
	struct stat buf;
	buf.st_size = 0;
	stat(file_name, &buf);
	return buf.st_size;
}

void init_dos_char_table(void)
{
	int i;

#ifdef LC_ALL
	/* include <locale.h> in includes.h if available for OS */
	/* we take only standard 7-bit ASCII definitions from ctype */
	setlocale(LC_ALL, "C");
#endif

	memset(valid_dos_chars, 0, sizeof(valid_dos_chars));

	for (i = 0; i <= 127; i++) {
		if (isalnum((char) i) ||
		    strchr("._^$~!#%&-{}()@'`", (char) i)) {
			valid_dos_chars[i / 8] |= 1 << (i % 8);
		}
	}
}

int isdoschar(int c)
{
	unsigned int bit;
	c &= 0xff;
	bit = c % 8;
	return (valid_dos_chars[c / 8] & (1 << bit)) != 0;
}

/*******************************************************************
  compare 2 strings
********************************************************************/
bool strequal(const char *s1, const char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;

	return strcasecmp(s1, s2) == 0;
}

/*******************************************************************
  compare 2 strings (case sensitive)
********************************************************************/
bool strcsequal(char *s1, char *s2)
{
	if (s1 == s2)
		return true;
	if (!s1 || !s2)
		return false;

	return strcmp(s1, s2) == 0;
}

/*******************************************************************
  convert a string to lower case
********************************************************************/
void strlower(char *s)
{
	while (*s) {
		if (isupper(*s))
			*s = tolower(*s);
		s++;
	}
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
	while (*s) {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

/*******************************************************************
  convert a string to "normal" form
********************************************************************/
void strnorm(char *s)
{
	strlower(s);
}

/*******************************************************************
check if a string is in "normal" case
********************************************************************/
bool strisnormal(char *s)
{
	return !strhasupper(s);
}

/****************************************************************************
  string replace
****************************************************************************/
static void string_replace(char *s, char oldc, char newc)
{
	while (*s) {
		if (oldc == *s)
			*s = newc;
		s++;
	}
}

/****************************************************************************
  make a file into unix format
****************************************************************************/
void unix_format(char *fname)
{
	pstring namecopy;
	string_replace(fname, '\\', '/');

	if (*fname == '/') {
		pstrcpy(namecopy, fname);
		pstrcpy(fname, ".");
		pstrcat(fname, namecopy);
	}
}

static void print_asc(int level, unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
		DEBUG(level, ("%c", isprint(buf[i]) ? buf[i] : '.'));
}

static void dump_data(int level, char *buf1, int len)
{
	unsigned char *buf = (unsigned char *) buf1;
	int i = 0;
	if (len <= 0)
		return;

	DEBUG(level, ("[%03X] ", i));
	for (i = 0; i < len;) {
		DEBUG(level, ("%02X ", (int) buf[i]));
		i++;
		if (i % 8 == 0)
			DEBUG(level, (" "));
		if (i % 16 == 0) {
			print_asc(level, &buf[i - 16], 8);
			DEBUG(level, (" "));
			print_asc(level, &buf[i - 8], 8);
			DEBUG(level, ("\n"));
			if (i < len)
				DEBUG(level, ("[%03X] ", i));
		}
	}
	if (i % 16) {
		int n;

		n = 16 - (i % 16);
		DEBUG(level, (" "));
		if (n > 8)
			DEBUG(level, (" "));
		while (n--)
			DEBUG(level, ("   "));

		n = MIN(8, i % 16);
		print_asc(level, &buf[i - (i % 16)], n);
		DEBUG(level, (" "));
		n = (i % 16) - n;
		if (n > 0)
			print_asc(level, &buf[i - n], n);
		DEBUG(level, ("\n"));
	}
}

/*******************************************************************
  show a smb message structure
********************************************************************/
void show_msg(char *buf)
{
	int i;
	int bcc = 0;

	if (DEBUGLEVEL < 5)
		return;

	DEBUG(5, ("size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%"
	          "d\nsmb_flg=%d\nsmb_flg2=%d\n",
	          smb_len(buf), (int) CVAL(buf, smb_com),
	          (int) CVAL(buf, smb_rcls), (int) CVAL(buf, smb_reh),
	          (int) SVAL(buf, smb_err), (int) CVAL(buf, smb_flg),
	          (int) SVAL(buf, smb_flg2)));
	DEBUG(5,
	      ("smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
	       (int) SVAL(buf, smb_tid), (int) SVAL(buf, smb_pid),
	       (int) SVAL(buf, smb_uid), (int) SVAL(buf, smb_mid),
	       (int) CVAL(buf, smb_wct)));

	for (i = 0; i < (int) CVAL(buf, smb_wct); i++)
		DEBUG(5,
		      ("smb_vwv[%d]=%d (0x%X)\n", i, SVAL(buf, smb_vwv + 2 * i),
		       SVAL(buf, smb_vwv + 2 * i)));

	bcc = (int) SVAL(buf, smb_vwv + 2 * (CVAL(buf, smb_wct)));
	DEBUG(5, ("smb_bcc=%d\n", bcc));

	if (DEBUGLEVEL < 10)
		return;

	dump_data(10, smb_buf(buf), MIN(bcc, 512));
}

/*******************************************************************
  return the length of an smb packet
********************************************************************/
int smb_len(char *buf)
{
	return PVAL(buf, 3) | (PVAL(buf, 2) << 8) | ((PVAL(buf, 1) & 1) << 16);
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void _smb_setlen(char *buf, int len)
{
	buf[0] = 0;
	buf[1] = (len & 0x10000) >> 16;
	buf[2] = (len & 0xFF00) >> 8;
	buf[3] = len & 0xFF;
}

/*******************************************************************
  set the length and marker of an smb packet
********************************************************************/
void smb_setlen(char *buf, int len)
{
	_smb_setlen(buf, len);

	CVAL(buf, 4) = 0xFF;
	CVAL(buf, 5) = 'S';
	CVAL(buf, 6) = 'M';
	CVAL(buf, 7) = 'B';
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int set_message(char *buf, int num_words, int num_bytes, bool zero)
{
	if (zero)
		bzero(buf + smb_size, num_words * 2 + num_bytes);
	CVAL(buf, smb_wct) = num_words;
	SSVAL(buf, smb_vwv + num_words * SIZEOFWORD, num_bytes);
	smb_setlen(buf, smb_size + num_words * 2 + num_bytes - 4);
	return smb_size + num_words * 2 + num_bytes;
}

/*******************************************************************
return the number of smb words
********************************************************************/
static int smb_numwords(char *buf)
{
	return CVAL(buf, smb_wct);
}

/*******************************************************************
return the size of the smb_buf region of a message
********************************************************************/
int smb_buflen(char *buf)
{
	return SVAL(buf, smb_vwv0 + smb_numwords(buf) * 2);
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
static int smb_buf_ofs(char *buf)
{
	return smb_size + CVAL(buf, smb_wct) * 2;
}

/*******************************************************************
  return a pointer to the smb_buf data area
********************************************************************/
char *smb_buf(char *buf)
{
	return buf + smb_buf_ofs(buf);
}

/*******************************************************************
return the SMB offset into an SMB buffer
********************************************************************/
int smb_offset(char *p, char *buf)
{
	return PTR_DIFF(p, buf + 4) + chain_size;
}

/*******************************************************************
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf, int n)
{
	while (n--)
		buf += strlen(buf) + 1;
	return buf;
}

/*******************************************************************
trim the specified elements off the front and back of a string
********************************************************************/
bool trim_string(char *s, char *front, char *back)
{
	bool ret = false;
	while (front && *front && strncmp(s, front, strlen(front)) == 0) {
		char *p = s;
		ret = true;
		while (1) {
			if (!(*p = p[strlen(front)]))
				break;
			p++;
		}
	}
	while (
	    back && *back && strlen(s) >= strlen(back) &&
	    (strncmp(s + strlen(s) - strlen(back), back, strlen(back)) == 0)) {
		ret = true;
		s[strlen(s) - strlen(back)] = 0;
	}
	return ret;
}

/*******************************************************************
reduce a file name, removing .. elements.
********************************************************************/
void unix_clean_name(char *s)
{
	char *p = NULL;

	DEBUG(3, ("unix_clean_name [%s]\n", s));

	/* remove any double slashes */
	string_sub(s, "//", "/");

	/* Remove leading ./ characters */
	if (strncmp(s, "./", 2) == 0) {
		trim_string(s, "./", NULL);
		if (*s == 0)
			pstrcpy(s, "./");
	}

	while ((p = strstr(s, "/../")) != NULL) {
		pstring s1;

		*p = 0;
		pstrcpy(s1, p + 3);

		if ((p = strrchr(s, '/')) != NULL)
			*p = 0;
		else
			*s = 0;
		pstrcat(s, s1);
	}

	trim_string(s, NULL, "/..");
}

/****************************************************************************
does a string have any uppercase chars in it?
****************************************************************************/
bool strhasupper(char *s)
{
	while (*s) {
		if (isupper(*s))
			return true;
		s++;
	}
	return false;
}

/****************************************************************************
find the number of chars in a string
****************************************************************************/
static int count_chars(char *s, char c)
{
	int count = 0;

	while (*s) {
		if (*s == c)
			count++;
		s++;
	}
	return count;
}

/****************************************************************************
  make a dir struct
****************************************************************************/
void make_dir_struct(char *buf, char *mask, char *fname, unsigned int size,
                     int mode, time_t date)
{
	char *p;
	pstring mask2;

	pstrcpy(mask2, mask);

	if ((mode & aDIR) != 0)
		size = 0;

	memset(buf + 1, ' ', 11);
	if ((p = strchr(mask2, '.')) != NULL) {
		*p = 0;
		memcpy(buf + 1, mask2, MIN(strlen(mask2), 8));
		memcpy(buf + 9, p + 1, MIN(strlen(p + 1), 3));
		*p = '.';
	} else
		memcpy(buf + 1, mask2, MIN(strlen(mask2), 11));

	bzero(buf + 21, DIR_STRUCT_SIZE - 21);
	CVAL(buf, 21) = mode;
	put_dos_date(buf, 22, date);
	SSVAL(buf, 26, size & 0xFFFF);
	SSVAL(buf, 28, size >> 16);
	strlcpy(buf + 30, fname, 13);
	strupper(buf + 30);
	DEBUG(8, ("put name [%s] into dir struct\n", buf + 30));
}

/*******************************************************************
close the low 3 fd's and open dev/null in their place
********************************************************************/
void close_low_fds(void)
{
	int fd;
	int i;
	close(0);
	close(1);
	close(2);
	/* try and use up these file descriptors, so silly
	   library routines writing to stdout etc won't cause havoc */
	for (i = 0; i < 3; i++) {
		fd = open("/dev/null", O_RDWR, 0);
		if (fd < 0)
			fd = open("/dev/null", O_WRONLY, 0);
		if (fd < 0) {
			DEBUG(0, ("Can't open /dev/null\n"));
			return;
		}
		if (fd != i) {
			DEBUG(0, ("Didn't get file descriptor %d\n", i));
			return;
		}
	}
}

/****************************************************************************
write to a socket
****************************************************************************/
static int write_socket(int fd, char *buf, int len)
{
	int ret = 0;

	DEBUG(6, ("write_socket(%d,%d)\n", fd, len));
	ret = write_data(fd, buf, len);

	DEBUG(6, ("write_socket(%d,%d) wrote %d\n", fd, len, ret));
	if (ret <= 0)
		DEBUG(0, ("write_socket: Error writing %d bytes to socket %d: "
		          "ERRNO = %s\n",
		          len, fd, strerror(errno)));

	return ret;
}

/****************************************************************************
read data from a device with a timout in msec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
****************************************************************************/
static int read_with_timeout(int fd, char *buf, int mincnt, int maxcnt,
                             long time_out)
{
	fd_set fds;
	int selrtn;
	int readret;
	int nread = 0;
	struct timeval timeout;

	/* just checking .... */
	if (maxcnt <= 0)
		return 0;

	smb_read_error = 0;

	/* Blocking read */
	if (time_out <= 0) {
		if (mincnt == 0)
			mincnt = maxcnt;

		while (nread < mincnt) {
			readret = read(fd, buf + nread, maxcnt - nread);
			if (readret == 0) {
				smb_read_error = READ_EOF;
				return -1;
			}

			if (readret == -1) {
				smb_read_error = READ_ERROR;
				return -1;
			}
			nread += readret;
		}
		return nread;
	}

	/* Most difficult - timeout read */
	/* If this is ever called on a disk file and
	       mincnt is greater then the filesize then
	       system performance will suffer severely as
	       select always return true on disk files */

	/* Set initial timeout */
	timeout.tv_sec = time_out / 1000;
	timeout.tv_usec = 1000 * (time_out % 1000);

	for (nread = 0; nread < mincnt;) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		selrtn = sys_select(&fds, &timeout);

		/* Check if error */
		if (selrtn == -1) {
			/* something is wrong. Maybe the socket is dead? */
			smb_read_error = READ_ERROR;
			return -1;
		}

		/* Did we timeout ? */
		if (selrtn == 0) {
			smb_read_error = READ_TIMEOUT;
			return -1;
		}

		readret = read(fd, buf + nread, maxcnt - nread);
		if (readret == 0) {
			/* we got EOF on the file descriptor */
			smb_read_error = READ_EOF;
			return -1;
		}

		if (readret == -1) {
			/* the descriptor is probably dead */
			smb_read_error = READ_ERROR;
			return -1;
		}

		nread += readret;
	}

	/* Return the number we got */
	return nread;
}

/****************************************************************************
  read data from the client, reading exactly N bytes.
****************************************************************************/
int read_data(int fd, char *buffer, int N)
{
	int ret;
	int total = 0;

	smb_read_error = 0;

	while (total < N) {
		ret = read(fd, buffer + total, N - total);
		if (ret == 0) {
			smb_read_error = READ_EOF;
			return 0;
		}
		if (ret == -1) {
			smb_read_error = READ_ERROR;
			return -1;
		}
		total += ret;
	}
	return total;
}

/****************************************************************************
  write data to a fd
****************************************************************************/
int write_data(int fd, char *buffer, int N)
{
	int total = 0;
	int ret;

	while (total < N) {
		ret = write(fd, buffer + total, N - total);

		if (ret == -1)
			return -1;
		if (ret == 0)
			return total;

		total += ret;
	}
	return total;
}

/****************************************************************************
transfer some data between two fd's
****************************************************************************/
int transfer_file(int infd, int outfd, int n, char *header, int headlen,
                  int align)
{
	static char *buf = NULL;
	static int size = 0;
	char *buf1, *abuf;
	int total = 0;

	DEBUG(4, ("transfer_file %d  (head=%d) called\n", n, headlen));

	if (size == 0) {
		size = lp_readsize();
		size = MAX(size, 1024);
	}

	while (!buf && size > 0) {
		buf = (char *) Realloc(buf, size + 8);
		if (!buf)
			size /= 2;
	}

	if (!buf) {
		DEBUG(0, ("Can't allocate transfer buffer!\n"));
		exit(1);
	}

	abuf = buf + (align % 8);

	if (header)
		n += headlen;

	while (n > 0) {
		int s = MIN(n, size);
		int ret, ret2 = 0;

		ret = 0;

		if (header && (headlen >= MIN(s, 1024))) {
			buf1 = header;
			s = headlen;
			ret = headlen;
			headlen = 0;
			header = NULL;
		} else {
			buf1 = abuf;
		}

		if (header && headlen > 0) {
			ret = MIN(headlen, size);
			memcpy(buf1, header, ret);
			headlen -= ret;
			header += ret;
			if (headlen <= 0)
				header = NULL;
		}

		if (s > ret)
			ret += read(infd, buf1 + ret, s - ret);

		if (ret > 0) {
			ret2 =
			    (outfd >= 0 ? write_data(outfd, buf1, ret) : ret);
			if (ret2 > 0)
				total += ret2;
			/* if we can't write then dump excess data */
			if (ret2 != ret)
				transfer_file(infd, -1, n - (ret + headlen),
				              NULL, 0, 0);
		}
		if (ret <= 0 || ret2 != ret)
			return total;
		n -= ret;
	}
	return total;
}

/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer
This version of the function will return a length of zero on receiving
a keepalive packet.
****************************************************************************/
int read_smb_length_return_keepalive(int fd, char *inbuf, int timeout)
{
	int len = 0, msg_type;
	bool ok = false;

	while (!ok) {
		if (timeout > 0)
			ok = (read_with_timeout(fd, inbuf, 4, 4, timeout) == 4);
		else
			ok = (read_data(fd, inbuf, 4) == 4);

		if (!ok)
			return -1;

		len = smb_len(inbuf);
		msg_type = CVAL(inbuf, 0);

		if (msg_type == 0x85)
			DEBUG(5, ("Got keepalive packet\n"));
	}

	DEBUG(10, ("got smb length of %d\n", len));

	return len;
}

/****************************************************************************
read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer. This version of the function will
never return a session keepalive (length of zero).
****************************************************************************/
int read_smb_length(int fd, char *inbuf, int timeout)
{
	int len;

	for (;;) {
		len = read_smb_length_return_keepalive(fd, inbuf, timeout);

		if (len < 0)
			return len;

		/* Ignore session keepalives. */
		if (CVAL(inbuf, 0) != 0x85)
			break;
	}

	return len;
}

/****************************************************************************
  send an smb to a fd
****************************************************************************/
bool send_smb(int fd, char *buffer)
{
	int len;
	int ret, nwritten = 0;
	len = smb_len(buffer) + 4;

	while (nwritten < len) {
		ret = write_socket(fd, buffer + nwritten, len - nwritten);
		if (ret <= 0) {
			DEBUG(
			    0,
			    ("Error writing %d bytes to client. %d. Exiting\n",
			     len, ret));
			close_sockets();
			exit(1);
		}
		nwritten += ret;
	}

	return true;
}

/****************************************************************************
find a pointer to a netbios name
****************************************************************************/
static char *name_ptr(char *buf, int ofs)
{
	unsigned char c = *(unsigned char *) (buf + ofs);

	if ((c & 0xC0) == 0xC0) {
		uint16_t l;
		char p[2];
		memcpy(p, buf + ofs, 2);
		p[0] &= ~0xC0;
		l = RSVAL(p, 0);
		DEBUG(5,
		      ("name ptr to pos %d from %d is %s\n", l, ofs, buf + l));
		return buf + l;
	} else
		return buf + ofs;
}

/****************************************************************************
extract a netbios name from a buf
****************************************************************************/
int name_extract(char *buf, int ofs, char *name)
{
	char *p = name_ptr(buf, ofs);
	int d = PTR_DIFF(p, buf + ofs);
	pstrcpy(name, "");
	if (d < -50 || d > 50)
		return 0;
	return name_interpret(p, name);
}

/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len(char *s)
{
	int len;

	/* If the two high bits of the byte are set, return 2. */
	if (0xC0 == (*(unsigned char *) s & 0xC0))
		return 2;

	/* Add up the length bytes. */
	for (len = 1; (*s); s += (*s) + 1) {
		len += *s + 1;
	}

	return len;
}

/****************************************************************************
send a single packet to a port on another machine
****************************************************************************/
bool send_one_packet(char *buf, int len, struct in_addr ip, int port, int type)
{
	bool ret;
	int out_fd;
	struct sockaddr_in sock_out;

	/* create a socket to write to */
	out_fd = socket(AF_INET, type, 0);
	if (out_fd == -1) {
		DEBUG(0, ("socket failed"));
		return false;
	}

	/* set the address and port */
	bzero((char *) &sock_out, sizeof(sock_out));
	sock_out.sin_family = AF_INET;
	sock_out.sin_addr = ip;
	sock_out.sin_port = htons(port);

	if (DEBUGLEVEL > 0)
		DEBUG(3, ("sending a packet of len %d to (%s) on port %d of "
		          "type %s\n",
		          len, inet_ntoa(ip), port,
		          type == SOCK_DGRAM ? "DGRAM" : "STREAM"));

	/* send it */
	ret = (sendto(out_fd, buf, len, 0, (struct sockaddr *) &sock_out,
	              sizeof(sock_out)) >= 0);

	if (!ret)
		DEBUG(0, ("Packet send to %s(%d) failed ERRNO=%s\n",
		          inet_ntoa(ip), port, strerror(errno)));

	close(out_fd);
	return ret;
}

/* this is used to prevent lots of mallocs of size 1 */
static char *null_string = NULL;

/****************************************************************************
set a string value, allocing the space for the string
****************************************************************************/
bool string_init(char **dest, char *src)
{
	int l;
	if (!src)
		src = "";

	l = strlen(src);

	if (l == 0) {
		if (!null_string)
			null_string = (char *) malloc(1);

		*null_string = 0;
		*dest = null_string;
	} else {
		(*dest) = (char *) malloc(l + 1);
		if ((*dest) == NULL) {
			DEBUG(0, ("Out of memory in string_init\n"));
			return false;
		}

		pstrcpy(*dest, src);
	}
	return true;
}

/****************************************************************************
free a string value
****************************************************************************/
void string_free(char **s)
{
	if (!s || !(*s))
		return;
	if (*s == null_string)
		*s = NULL;
	free(*s);
	*s = NULL;
}

/****************************************************************************
set a string value, allocing the space for the string, and deallocating any
existing space
****************************************************************************/
bool string_set(char **dest, char *src)
{
	string_free(dest);

	return string_init(dest, src);
}

/****************************************************************************
substitute a string for a pattern in another string. Make sure there is
enough room!

This routine looks for pattern in s and replaces it with
insert. It may do multiple replacements.

return true if a substitution was done.
****************************************************************************/
bool string_sub(char *s, char *pattern, char *insert)
{
	bool ret = false;
	char *p;
	int ls, lp, li;

	if (!insert || !pattern || !s)
		return false;

	ls = strlen(s);
	lp = strlen(pattern);
	li = strlen(insert);

	if (!*pattern)
		return false;

	while (lp <= ls && (p = strstr(s, pattern))) {
		ret = true;
		memmove(p + li, p + lp, ls + 1 - (PTR_DIFF(p, s) + lp));
		memcpy(p, insert, li);
		s = p + li;
		ls = strlen(s);
	}
	return ret;
}

/*********************************************************
 * Recursive routine that is called by mask_match.
 * Does the actual matching. Returns true if matched,
 * false if failed.
 *********************************************************/

static bool do_match(char *str, char *regexp)
{
	char *p;

	for (p = regexp; *p && *str;) {
		switch (*p) {
		case '?':
			str++;
			p++;
			break;

		case '*':
			/* Look for a character matching
			   the one after the '*' */
			p++;
			if (!*p)
				return true; /* Automatic match */
			while (*str) {
				while (*str && toupper(*p) != toupper(*str)) {
					str++;
				}
				/* Now eat all characters that match, as
				   we want the *last* character to match. */
				while (*str && toupper(*p) == toupper(*str)) {
					str++;
				}
				str--; /* We've eaten the match char after the
				          '*' */
				if (do_match(str, p)) {
					return true;
				}
				if (!*str) {
					return false;
				} else {
					str++;
				}
			}
			return false;

		default:
			if (toupper(*str) != toupper(*p)) {
				return false;
			}
			str++, p++;
			break;
		}
	}

	if (!*p && !*str)
		return true;

	if (!*p && str[0] == '.' && str[1] == 0) {
		return true;
	}

	if (!*str && *p == '?') {
		while (*p == '?')
			p++;
		return !*p;
	}

	if (!*str && (*p == '*' && p[1] == '\0')) {
		return true;
	}

	return false;
}

/*********************************************************
 * Routine to match a given string with a regexp - uses
 * simplified regexp that takes * and ? only. Case can be
 * significant or not.
 * The 8.3 handling was rewritten by Ums Harald <Harald.Ums@pro-sieben.de>
 *********************************************************/

bool mask_match(char *str, char *regexp, bool trans2)
{
	char *p;
	pstring t_pattern, t_filename, te_pattern, te_filename;
	fstring ebase, eext, sbase, sext;

	bool matched = false;

	/* Make local copies of str and regexp */
	pstrcpy(t_pattern, regexp);
	pstrcpy(t_filename, str);

	/* Remove any *? and ** as they are meaningless */
	string_sub(t_pattern, "*?", "*");
	string_sub(t_pattern, "**", "*");

	if (strequal(t_pattern, "*"))
		return true;

	DEBUG(8, ("mask_match str=<%s> regexp=<%s>\n", t_filename, t_pattern));

	if (trans2) {
		/*
		 * Match each component of the regexp, split up by '.'
		 * characters.
		 */
		char *fp, *rp, *cp2, *cp1;
		bool last_wcard_was_star = false;
		int num_path_components, num_regexp_components;

		pstrcpy(te_pattern, t_pattern);
		pstrcpy(te_filename, t_filename);
		/*
		 * Remove multiple "*." patterns.
		 */
		string_sub(te_pattern, "*.*.", "*.");
		num_regexp_components = count_chars(te_pattern, '.');
		num_path_components = count_chars(te_filename, '.');

		/*
		 * Check for special 'hack' case of "DIR a*z". - needs to match
		 * a.b.c...z
		 */
		if (num_regexp_components == 0)
			matched = do_match(te_filename, te_pattern);
		else {
			for (cp1 = te_pattern, cp2 = te_filename; cp1;) {
				fp = strchr(cp2, '.');
				if (fp)
					*fp = '\0';
				rp = strchr(cp1, '.');
				if (rp)
					*rp = '\0';

				if (cp1[strlen(cp1) - 1] == '*')
					last_wcard_was_star = true;
				else
					last_wcard_was_star = false;

				if (!do_match(cp2, cp1)) {
					break;
				}

				cp1 = rp ? rp + 1 : NULL;
				cp2 = fp ? fp + 1 : "";

				if (last_wcard_was_star ||
				    ((cp1 != NULL) && (*cp1 == '*'))) {
					/* Eat the extra path components. */
					int i;

					for (i = 0;
					     i < num_path_components -
					             num_regexp_components;
					     i++) {
						fp = strchr(cp2, '.');
						if (fp)
							*fp = '\0';

						if ((cp1 != NULL) &&
						    do_match(cp2, cp1)) {
							cp2 = fp ? fp + 1 : "";
							break;
						}
						cp2 = fp ? fp + 1 : "";
					}
					num_path_components -= i;
				}
			}
			if (cp1 == NULL &&
			    ((*cp2 == '\0') || last_wcard_was_star))
				matched = true;
		}
	} else {

		/* -------------------------------------------------
		 * Behaviour of Win95
		 * for 8.3 filenames and 8.3 Wildcards
		 * -------------------------------------------------
		 */
		if (strequal(t_filename, ".")) {
			/*
			 *  Patterns:  *.*  *. ?. ?  are valid
			 *
			 */
			if (strequal(t_pattern, "*.*") ||
			    strequal(t_pattern, "*.") ||
			    strequal(t_pattern, "?.") ||
			    strequal(t_pattern, "?"))
				matched = true;
		} else if (strequal(t_filename, "..")) {
			/*
			 *  Patterns:  *.*  *. ?. ? *.? are valid
			 *
			 */
			if (strequal(t_pattern, "*.*") ||
			    strequal(t_pattern, "*.") ||
			    strequal(t_pattern, "?.") ||
			    strequal(t_pattern, "?") ||
			    strequal(t_pattern, "*.?") ||
			    strequal(t_pattern, "?.*"))
				matched = true;
		} else {

			if ((p = strrchr(t_pattern, '.'))) {
				/*
				 * Wildcard has a suffix.
				 */
				*p = 0;
				fstrcpy(ebase, t_pattern);
				if (p[1]) {
					fstrcpy(eext, p + 1);
				} else {
					/* pattern ends in DOT: treat as if
					 * there is no DOT */
					*eext = 0;
					if (strequal(ebase, "*"))
						return true;
				}
			} else {
				/*
				 * No suffix for wildcard.
				 */
				fstrcpy(ebase, t_pattern);
				eext[0] = 0;
			}

			p = strrchr(t_filename, '.');
			if (p && (p[1] == 0)) {
				/*
				 * Filename has an extension of '.' only.
				 */
				*p = 0; /* nuke dot at end of string */
				p = 0;  /* and treat it as if there is no
				           extension */
			}

			if (p) {
				/*
				 * Filename has an extension.
				 */
				*p = 0;
				fstrcpy(sbase, t_filename);
				fstrcpy(sext, p + 1);
				if (*eext) {
					matched = do_match(sbase, ebase) &&
					          do_match(sext, eext);
				} else {
					/* pattern has no extension */
					/* Really: match complete filename with
					 * pattern ??? means exactly 3 chars */
					matched = do_match(str, ebase);
				}
			} else {
				/*
				 * Filename has no extension.
				 */
				fstrcpy(sbase, t_filename);
				fstrcpy(sext, "");
				if (*eext) {
					/* pattern has extension */
					matched = do_match(sbase, ebase) &&
					          do_match(sext, eext);
				} else {
					matched = do_match(sbase, ebase);
#ifdef EMULATE_WEIRD_W95_MATCHING
					/*
					 * Even Microsoft has some problems
					 * Behaviour Win95 -> local disk
					 * is different from Win95 -> smb drive
					 * from Nt 4.0 This branch would reflect
					 * the Win95 local disk behaviour
					 */
					if (!matched) {
						/* a? matches aa and a in w95 */
						fstrcat(sbase, ".");
						matched =
						    do_match(sbase, ebase);
					}
#endif
				}
			}
		}
	}

	DEBUG(8, ("mask_match returning %d\n", matched));

	return matched;
}

/****************************************************************************
become a daemon, discarding the controlling terminal
****************************************************************************/
void become_daemon(void)
{
#ifndef NO_FORK_DEBUG
	if (fork())
		exit(0);

	/* detach from the terminal */
#ifdef USE_SETSID
	setsid();
#else /* USE_SETSID */
#ifdef TIOCNOTTY
	{
		int i = open("/dev/tty", O_RDWR);
		if (i >= 0) {
			ioctl(i, (int) TIOCNOTTY, (char *) 0);
			close(i);
		}
	}
#endif /* TIOCNOTTY */
#endif /* USE_SETSID */
	/* Close fd's 0,1,2. Needed if started by rsh */
	close_low_fds();
#endif /* NO_FORK_DEBUG */
}

/****************************************************************************
expand a pointer to be a particular size
****************************************************************************/
void *Realloc(void *p, int size)
{
	void *ret = NULL;

	if (size == 0) {
		free(p);
		DEBUG(5, ("Realloc asked for 0 bytes\n"));
		return NULL;
	}

	ret = realloc(p, size);

	if (ret == NULL) {
		DEBUG(
		    0,
		    ("Memory allocation error: failed to expand to %d bytes\n",
		     size));
	}

	return ret;
}

/*******************************************************************
 return the IP addr of the client as a string
 ******************************************************************/
const char *client_addr(void)
{
	struct sockaddr_in sockin;
	socklen_t length = sizeof(sockin);

	if (Client == -1) {
		return "(no client)";
	}

	if (getpeername(Client, (struct sockaddr *) &sockin, &length) < 0) {
		DEBUG(0, ("getpeername failed\n"));
		return "(error getting peer address)";
	}

	return inet_ntoa(sockin.sin_addr);
}

/*******************************************************************
write a string in unicoode format
********************************************************************/
int PutUniCode(char *dst, char *src)
{
	int ret = 0;
	while (*src) {
		dst[ret++] = src[0];
		dst[ret++] = 0;
		src++;
	}
	dst[ret++] = 0;
	dst[ret++] = 0;
	return ret;
}

/*******************************************************************
block sigs
********************************************************************/
void BlockSignals(bool block, int signum)
{
#ifdef USE_SIGBLOCK
	int block_mask = sigmask(signum);
	static int oldmask = 0;
	if (block)
		oldmask = sigblock(block_mask);
	else
		sigsetmask(oldmask);
#elif defined(USE_SIGPROCMASK)
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, signum);
	sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &set, NULL);
#endif
}

/*******************************************************************
a readdir wrapper which just returns the file name
also return the inode number if requested
********************************************************************/
char *readdirname(void *p)
{
	static pstring buf;
	struct dirent *ptr;
	char *dname;

	if (!p)
		return NULL;

	ptr = (struct dirent *) readdir(p);
	if (!ptr)
		return NULL;

	dname = ptr->d_name;

	pstrcpy(buf, dname);
	return buf;
}

/*******************************************************************
safe string copy into a known length string
dest_size is the size of the destination buffer
********************************************************************/
char *safe_strcpy(char *dest, char *src, int dest_size)
{
	size_t len;

	if (!src) {
		strlcpy(dest, "", dest_size);
		return dest;
	}

	len = strlcpy(dest, src, dest_size);
	if (len > dest_size - 1) {
		DEBUG(0,
		      ("ERROR: string overflow by %d in safe_strcpy [%.50s]\n",
		       len - dest_size + 1, src));
	}

	return dest;
}

/*******************************************************************
safe string cat into a string
dest_size is the size of the destination buffer
********************************************************************/
char *safe_strcat(char *dest, char *src, int dest_size)
{
	size_t len;

	if (src == NULL) {
		return dest;
	}

	len = strlcat(dest, src, dest_size);
	if (len > dest_size - 1) {
		DEBUG(0,
		      ("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
		       len - dest_size + 1, src));
	}

	return dest;
}

char *tab_depth(int depth)
{
	static pstring spaces;
	memset(spaces, ' ', depth * 4);
	spaces[depth * 4] = 0;
	return spaces;
}
