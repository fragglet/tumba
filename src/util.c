/*
 * Copyright (c) 1992-1998 Andrew Tridgell
 * Copyright (c) 2025 Simon Howard
 *
 * You can redistribute and/or modify this program under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation, or any later version. This program is distributed WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "util.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#include "byteorder.h"
#include "guards.h" /* IWYU pragma: keep */
#include "smb.h"
#include "timefunc.h"

/* To which file do our syslog messages go? */
#define SYSLOG_FACILITY LOG_DAEMON

char client_addr[32] = "";

/* By default we log NOTICE messages and above ("normal, but significant,
 * condition"). This should give reasonable logging data without too much
 * logspam. */
int LOGLEVEL = 2;

int Protocol = PROTOCOL_COREPLUS;

/* If non-NULL, log messages will be written to this file. */
FILE *log_file = NULL;

/* the client file descriptor */
int Client = -1;

/* this is used by the chaining code */
int chain_size = 0;

fstring local_machine = "";

int smb_read_error = 0;

static bool log_start_of_line = true;

void setup_logging(char *pname)
{
	char *p = strrchr(pname, '/');
	if (p) {
		pname = p + 1;
	}
	openlog(pname, LOG_PID, SYSLOG_FACILITY);
}

static const int syslog_priority_map[] = {
    LOG_ERR,     /* 0 */
    LOG_WARNING, /* 1 */
    LOG_NOTICE,  /* 2 */
    LOG_INFO,    /* 3 */
};

static void syslog_output(int level, char *format_str, va_list ap)
{
	int priority = syslog_priority_map[level];
	pstring msgbuf;
	char *buf;
	size_t buf_len, n;

	buf = msgbuf;
	buf_len = sizeof(msgbuf);

	if (client_addr[0] != '\0') {
		snprintf(buf, buf_len, "[%s] ", client_addr);
		n = strlen(buf);
		buf += n;
		buf_len -= n;
	}

	vsnprintf(buf, buf_len, format_str, ap);

	msgbuf[255] = '\0';
	syslog(priority, "%s", msgbuf);
}

void open_log_file(const char *filename)
{
	if (!strcmp(filename, "-")) {
		log_file = stdout;
	} else {
		int oldumask = umask(022);
		log_file = fopen(filename, "a");
		umask(oldumask);

		// If we fail to open the log file, write the error message
		// to stderr (rather than using the ERROR macro) so that the
		// user gets to see the message.
		if (log_file == NULL) {
			STARTUP_ERROR("Failed to open log file '%s': %s\n",
			              filename, strerror(errno));
		}
	}

	// Don't buffer log output.
	setbuf(log_file, NULL);
}

/* Used for errors that occur during startup. Does not return. */
void startup_error(const char *funcname, char *format_str, ...)
{
	va_list ap;

	va_start(ap, format_str);
	fprintf(stderr, "[%s] ", funcname);
	vfprintf(stderr, format_str, ap);
	va_end(ap);
	exit(1);
}

/* Write a message to the log file. This is called by the LOG macro. */
int log_output(const char *funcname, int linenum, int level, char *format_str,
               ...)
{
	va_list ap;
	int old_errno = errno;
	size_t n;

	/* we do not pass debug messages to syslog */
	if (level < 4) {
		va_start(ap, format_str);
		syslog_output(level, format_str, ap);
		va_end(ap);
	}

	if (log_file == NULL) {
		return 0;
	}

	if (log_start_of_line) {
		log_start_of_line = false;
		fprintf(log_file, "%s ", timestring());

		if (client_addr[0] != '\0') {
			fprintf(log_file, "[%s] ", client_addr);
		}
		if (funcname != NULL) {
			fprintf(log_file, "%s (#%d): ", funcname, linenum);
		}
	}

	va_start(ap, format_str);
	vfprintf(log_file, format_str, ap);
	va_end(ap);
	fflush(log_file);

	n = strlen(format_str);
	if (n > 0 && format_str[strlen(format_str) - 1] == '\n') {
		log_start_of_line = true;
	}

	errno = old_errno;

	return 0;
}

/* Check if a file exists */
bool file_exist(char *fname, struct stat *sbuf)
{
	struct stat st;
	if (!sbuf)
		sbuf = &st;

	if (stat(fname, sbuf) != 0)
		return false;

	return S_ISREG(sbuf->st_mode);
}

/* Check if a directory exists */
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

static void print_asc(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		DEBUG_("%c", isprint(buf[i]) ? buf[i] : '.');
	}
}

static void dump_data(char *buf1, int len)
{
	unsigned char *buf = (unsigned char *) buf1;
	int i = 0;
	if (len <= 0)
		return;

	DEBUG_("[%03X] ", i);
	for (i = 0; i < len;) {
		DEBUG_("%02X ", (int) buf[i]);
		i++;
		if (i % 8 == 0)
			DEBUG_(" ");
		if (i % 16 == 0) {
			print_asc(&buf[i - 16], 8);
			DEBUG_(" ");
			print_asc(&buf[i - 8], 8);
			DEBUG_("\n");
			if (i < len)
				DEBUG_("[%03X] ", i);
		}
	}
	if (i % 16) {
		int n;

		n = 16 - (i % 16);
		DEBUG_(" ");
		if (n > 8)
			DEBUG_(" ");
		while (n--)
			DEBUG_("   ");

		n = MIN(8, i % 16);
		print_asc(&buf[i - (i % 16)], n);
		DEBUG_(" ");
		n = (i % 16) - n;
		if (n > 0)
			print_asc(&buf[i - n], n);
		DEBUG_("\n");
	}
}

/* Show a smb message structure */
void show_msg(char *buf)
{
	int i;
	int bcc = 0;

	if (LOGLEVEL < 5)
		return;

	DEBUG_("size=%d\nsmb_com=0x%x\nsmb_rcls=%d\nsmb_reh=%d\nsmb_err=%d\n"
	       "smb_flg=%d\nsmb_flg2=%d\n",
	       smb_len(buf), (int) CVAL(buf, smb_com),
	       (int) CVAL(buf, smb_rcls), (int) CVAL(buf, smb_reh),
	       (int) SVAL(buf, smb_err), (int) CVAL(buf, smb_flg),
	       (int) SVAL(buf, smb_flg2));
	DEBUG_("smb_tid=%d\nsmb_pid=%d\nsmb_uid=%d\nsmb_mid=%d\nsmt_wct=%d\n",
	       (int) SVAL(buf, smb_tid), (int) SVAL(buf, smb_pid),
	       (int) SVAL(buf, smb_uid), (int) SVAL(buf, smb_mid),
	       (int) CVAL(buf, smb_wct));

	for (i = 0; i < (int) CVAL(buf, smb_wct); i++)
		DEBUG_("smb_vwv[%d]=%d (0x%X)\n", i, SVAL(buf, smb_vwv + 2 * i),
		       SVAL(buf, smb_vwv + 2 * i));

	bcc = (int) SVAL(buf, smb_vwv + 2 * (CVAL(buf, smb_wct)));
	DEBUG_("smb_bcc=%d\n", bcc);

	if (LOGLEVEL < 10)
		return;

	dump_data(smb_buf(buf), MIN(bcc, 512));
}

/* Return the length of an smb packet */
int smb_len(char *buf)
{
	return PVAL(buf, 3) | (PVAL(buf, 2) << 8) | ((PVAL(buf, 1) & 1) << 16);
}

/* Set the length of an smb packet */
void _smb_setlen(char *buf, int len)
{
	buf[0] = 0;
	buf[1] = (len & 0x10000) >> 16;
	buf[2] = (len & 0xFF00) >> 8;
	buf[3] = len & 0xFF;
}

/* Set the length and marker of an smb packet */
void smb_setlen(char *buf, int len)
{
	_smb_setlen(buf, len);

	CVAL(buf, 4) = 0xFF;
	CVAL(buf, 5) = 'S';
	CVAL(buf, 6) = 'M';
	CVAL(buf, 7) = 'B';
}

/* Set up the word count and byte count for a smb message */
int set_message(char *buf, int num_words, int num_bytes, bool zero)
{
	if (zero)
		bzero(buf + smb_size, num_words * 2 + num_bytes);
	CVAL(buf, smb_wct) = num_words;
	SSVAL(buf, smb_vwv + num_words * sizeof(uint16_t), num_bytes);
	smb_setlen(buf, smb_size + num_words * 2 + num_bytes - 4);
	return smb_size + num_words * 2 + num_bytes;
}

/* Return the number of smb words */
static int smb_numwords(char *buf)
{
	return CVAL(buf, smb_wct);
}

/* Return the size of the smb_buf region of a message */
int smb_buflen(char *buf)
{
	return SVAL(buf, smb_vwv0 + smb_numwords(buf) * 2);
}

/* Return a pointer to the smb_buf data area */
static int smb_buf_ofs(char *buf)
{
	return smb_size + CVAL(buf, smb_wct) * 2;
}

/* Return a pointer to the smb_buf data area */
char *smb_buf(char *buf)
{
	return buf + smb_buf_ofs(buf);
}

/* Return the SMB offset into an SMB buffer */
int smb_offset(char *p, char *buf)
{
	return PTR_DIFF(p, buf + 4) + chain_size;
}

static void close_low_fd(int fd, int flags)
{
	int new_fd;

	close(fd);
	new_fd = open("/dev/null", flags, 0);
	if (new_fd < 0) {
		ERROR("Failed to reopen fd %d: %s\n", fd, strerror(errno));
		return;
	}
	if (new_fd != fd) {
		ERROR("Failed to reopen fd %d; got fd=%d\n", fd, new_fd);
		close(new_fd);
	}
}

/* Close the low 3 FDs and open /dev/null in their place */
void close_low_fds(void)
{
	close_low_fd(0, 0);
	close_low_fd(2, O_WRONLY);

	// Don't close stdout if we're using it for the log file output.
	if (log_file != stdout) {
		close_low_fd(1, O_WRONLY);
	}
}

static int write_socket(int fd, char *buf, int len)
{
	int ret = 0;

	DEBUG("fd=%d len=%d\n", fd, len);
	ret = write_data(fd, buf, len);

	DEBUG("wrote %d\n", ret);
	if (ret <= 0)
		ERROR("write_socket: Error writing %d bytes to socket %d: "
		      "ERRNO = %s\n",
		      len, fd, strerror(errno));

	return ret;
}

/*
Read data from a device with a timout in msec.
mincount = if timeout, minimum to read before returning
maxcount = number to be read.
*/
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

	for (nread = 0; nread < mincnt;) {
		do {
			FD_ZERO(&fds);
			FD_SET(fd, &fds);

			timeout.tv_sec = time_out / 1000;
			timeout.tv_usec = 1000 * (time_out % 1000);

			selrtn = select(fd + 1, &fds, NULL, NULL, &timeout);
		} while (selrtn < 0 && errno == EINTR);

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

/* Read data from the client, reading exactly N bytes. */
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

/*
Read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer
This version of the function will return a length of zero on receiving
a keepalive packet.
*/
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
			DEBUG("Got keepalive packet\n");
	}

	DEBUG("got smb length of %d\n", len);

	return len;
}

/*
Read 4 bytes of a smb packet and return the smb length of the packet
store the result in the buffer. This version of the function will
never return a session keepalive (length of zero).
*/
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

bool send_smb(int fd, char *buffer)
{
	int len;
	int ret, nwritten = 0;
	len = smb_len(buffer) + 4;

	while (nwritten < len) {
		ret = write_socket(fd, buffer + nwritten, len - nwritten);
		if (ret <= 0) {
			ERROR("Error writing %d bytes to client. %d. Exiting\n",
			      len, ret);
			exit(1);
		}
		nwritten += ret;
	}

	return true;
}

/* Checked result memory functions */
void *checked_realloc(void *p, size_t bytes)
{
	void *result = (realloc) (p, bytes);

	assert(result != NULL || bytes == 0);

	return result;
}

void *checked_calloc(size_t nmemb, size_t size)
{
	void *result = (calloc) (nmemb, size);

	assert(result != NULL || nmemb == 0 || size == 0);

	return result;
}

char *checked_strdup(const char *s)
{
	char *result = (strdup) (s);

	assert(result != NULL);

	return result;
}

void block_signals(bool block, int signum)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, signum);
	sigprocmask(block ? SIG_BLOCK : SIG_UNBLOCK, &set, NULL);
}
