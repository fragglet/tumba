/*
   Unix SMB/Netbios implementation.
   Version 1.8.
   Copyright (C) Andrew Tridgell 1992,1993,1994

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

pstring scope = "";

int DEBUGLEVEL = 1;

BOOL passive = False;

/* these are some file handles where debug info will be stored */
FILE *dbf = NULL;

/* the client file descriptor */
int Client = 0;

/* the last IP received from */
struct in_addr lastip;

/* the last port received from */
int lastport = 0;

/* my IP, the broadcast IP and the Netmask */
struct in_addr myip;
struct in_addr bcast_ip;
struct in_addr Netmask;

/* this is set to true on a big_endian machine (like a sun sparcstation)
this means that all shorts and ints must be byte swapped before being
put in the buffer */
BOOL NeedSwap = False;

/* this structure is used to hold information about the machine that
   the program is running on */
machine_struct machine_info;

pstring debugf = DEBUGFILE;

/*******************************************************************
write an debug message on the debugfile. The first arg is the debuglevel.
********************************************************************/
#ifdef __STDC__
int Debug1(char *format_str, ...)
{
#else
int Debug1(va_alist) va_dcl
{
	char *format_str;
#endif
	va_list ap;

	if (!dbf) {
		dbf = fopen(debugf, "w");
		if (dbf)
			setbuf(dbf, NULL);
		else
			return 0;
	}

#ifdef __STDC__
	va_start(ap, format_str);
#else
	va_start(ap);
	format_str = va_arg(ap, char *);
#endif

	vfprintf(dbf, format_str, ap);

	fflush(dbf);

	va_end(ap);
	return 0;
}

int extra_time_offset = 0;

/****************************************************************************
return the difference between local and GMT time
****************************************************************************/
int TimeDiff(void)
{
	static BOOL initialised = False;
	static int timediff = 0;

	if (!initialised) {
		/* There are four ways of getting the time difference between
		   GMT and local time. Use the following defines to decide which
		   your system can handle */
#ifdef HAVE_GETTIMEOFDAY
		struct timeval tv;
		struct timezone tz;

		gettimeofday(&tv, &tz);
		timediff = 60 * tz.tz_minuteswest;
#else
		time_t t = time(NULL);

#ifdef HAVE_TIMELOCAL
		timediff = timelocal(gmtime(&t)) - t;
#else
#ifdef HAVE_TIMEZONE
		localtime(&t);
		timediff = timezone;
#else
		timediff = -(localtime(&t)->tm_gmtoff);
#endif
#endif
#endif
		DEBUG(3, ("timediff=%d\n", timediff));
		initialised = True;
	}

	return timediff + (extra_time_offset * 60);
}

/****************************************************************************
try to optimise the localtime call, it can be quite expenive on some machines
timemul is normally LOCAL_TO_GMT, GMT_TO_LOCAL or 0
****************************************************************************/
struct tm *LocalTime(time_t *t, int timemul)
{
	time_t t2 = *t;

	t2 += timemul * TimeDiff();

	return gmtime(&t2);
}

/*******************************************************************
safely copies memory, ensuring no overlap problems.
********************************************************************/
void safe_memcpy(void *dest, void *src, int size)
{
	/* do the copy in chunks of size difference. This relies on the
	   capability of pointer comparison. */

	int difference = ABS((char *) dest - (char *) src);

	if (difference == 0 || size <= 0)
		return;

	if (difference >= size) /* no overlap problem */
	{
		memcpy(dest, src, size);
		return;
	}

	if (dest > src) /* copy the last chunks first */
	{
		char *this_dest = dest;
		char *this_src = src;
		this_dest += size - difference;
		this_src += size - difference;
		while (size > 0) {
			memcpy(this_dest, this_src, difference);
			this_dest -= difference;
			this_src -= difference;
			size -= difference;
		}
	} else { /* copy from the front */
		char *this_dest = dest;
		char *this_src = src;
		while (size > 0) {
			memcpy(this_dest, this_src, difference);
			this_dest += difference;
			this_src += difference;
			size -= difference;
		}
	}
}

/****************************************************************************
  close the socket communication
****************************************************************************/
void close_sockets(void)
{
	extern int Client;
	close(Client);
	Client = 0;
}

/****************************************************************************
  return the date and time as a string
****************************************************************************/
char *timestring(void)
{
	static char TimeBuf[100];
	time_t t;
	t = time(NULL);
#ifdef NO_STRFTIME
	strcpy(TimeBuf, asctime(LocalTime(&t, GMT_TO_LOCAL)));
#else
#ifdef CLIX
	strftime(TimeBuf, 100, "%m/%d/%y %I:%M:%S %p",
	         LocalTime(&t, GMT_TO_LOCAL));
#else
#ifdef AMPM
	strftime(TimeBuf, 100, "%D %r", LocalTime(&t, GMT_TO_LOCAL));
#else
	strftime(TimeBuf, 100, "%D %T", LocalTime(&t, GMT_TO_LOCAL));
#endif
#endif /* CLIX */
#endif
	return TimeBuf;
}

/****************************************************************************
line strncpy but always null terminates. Make sure there is room!
****************************************************************************/
char *StrnCpy(char *dest, char *src, int n)
{
	char *d = dest;
	while (n-- && (*d++ = *src++))
		;
	*d = 0;
	return dest;
}

/****************************************************************************
interpret the weird netbios "name"
****************************************************************************/
void name_interpret(char *in, char *out)
{

	int len = (*in++) / 2;
	while (len--) {
		*out = ((in[0] - 'A') << 4) + (in[1] - 'A');
		in += 2;
		out++;
	}
	*out = 0;
	/* Handle any scope names */
	while (*in) {
		*out++ = '.'; /* Scope names are separated by periods */
		len = *(unsigned char *) in++;
		StrnCpy(out, in, len);
		out += len;
		*out = 0;
		in += len;
	}
}

/****************************************************************************
mangle a name into netbios format
****************************************************************************/
int name_mangle(char *In, char *Out)
{
	char *in = (char *) In;
	char *out = (char *) Out;
	char *p, *label;
	int len = 2 * strlen((char *) in);
	int pad = 0;

	if (len / 2 < 16)
		pad = 16 - (len / 2);

	*out++ = 2 * (strlen((char *) in) + pad);
	while (*in) {
		out[0] = (in[0] >> 4) + 'A';
		out[1] = (in[0] & 0xF) + 'A';
		in++;
		out += 2;
	}

	while (pad--) {
		out[0] = 'C';
		out[1] = 'A';
		out += 2;
	}

	label = scope;
	while (*label) {
		p = strchr(label, '.');
		if (p == 0)
			p = label + strlen(label);
		*out++ = p - label;
		memcpy(out, label, p - label);
		out += p - label;
		label += p - label + (*p == '.');
	}
	*out = 0;
	return name_len(Out);
}

/*******************************************************************
  byte swap an object - the byte order of the object is reversed
********************************************************************/
void *object_byte_swap(void *obj, int size)
{
	int i;
	char c;
	char *p1 = (char *) obj;
	char *p2 = p1 + size - 1;

	size /= 2;

	for (i = 0; i < size; i++) {
		c = *p1;
		*p1 = *p2;
		*p2 = c;
		p1++;
		p2--;
	}
	return obj;
}

/*******************************************************************
  true if the machine is big endian
********************************************************************/
BOOL big_endian(void)
{
	int x = 2;
	char *s;
	s = (char *) &x;
	return s[0] == 0;
}

/*******************************************************************
  compare 2 strings
********************************************************************/
BOOL strequal(char *s1, char *s2)
{
	if (!s1 || !s2)
		return False;

	return strcasecmp(s1, s2) == 0;
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

/****************************************************************************
  set a value at buf[pos] to integer val
****************************************************************************/
void sival(char *buf, int pos, uint32 val)
{
	SWP(&val, sizeof(val));
	memcpy(buf + pos, (char *) &val, sizeof(val));
}

/****************************************************************************
  set a value at buf[pos] to int16 val
****************************************************************************/
void ssval(char *buf, int pos, uint16 val)
{
	SWP(&val, sizeof(val));
	memcpy(buf + pos, (char *) &val, sizeof(int16));
}

/****************************************************************************
  get a 32 bit integer value
****************************************************************************/
uint32 ival(char *buf, int pos)
{
	uint32 val;
	memcpy((char *) &val, buf + pos, sizeof(int));
	SWP(&val, sizeof(val));
	return val;
}

/****************************************************************************
  get a int16 value
****************************************************************************/
uint16 sval(char *buf, int pos)
{
	uint16 val;
	memcpy((char *) &val, buf + pos, sizeof(uint16));
	SWP(&val, sizeof(val));
	return val;
}

/*******************************************************************
  set the length of an smb packet
********************************************************************/
void smb_setlen(char *buf, int len)
{
	SSVAL(buf, 2, len);
	BSWP(buf + 2, 2);

	/*
	  CVAL(buf,3) = len & 0xFF;
	  CVAL(buf,2) = (len >> 8) & 0xFF;
	*/
	CVAL(buf, 4) = 0xFF;
	CVAL(buf, 5) = 'S';
	CVAL(buf, 6) = 'M';
	CVAL(buf, 7) = 'B';

	if (len >= (1 << 16))
		CVAL(buf, 1) |= 1;
}

/*******************************************************************
  setup the word count and byte count for a smb message
********************************************************************/
int set_message(char *buf, int num_words, int num_bytes, BOOL zero)
{
	if (zero)
		memset(buf + smb_size, 0, num_words * 2 + num_bytes);
	CVAL(buf, smb_wct) = num_words;
	SSVAL(buf, smb_vwv + num_words * sizeof(WORD), num_bytes);
	smb_setlen(buf, smb_size + num_words * 2 + num_bytes - 4);
	return smb_size + num_words * 2 + num_bytes;
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
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf, int n)
{
	while (n--)
		buf += strlen(buf) + 1;
	return buf;
}

/****************************************************************************
find a pointer to a netbios name
****************************************************************************/
char *name_ptr(char *buf, int ofs)
{
	unsigned char c = *(unsigned char *) (buf + ofs);

	if ((c & 0xC0) == 0xC0) {
		uint16 l;
		char *p = (char *) &l;
		memcpy((char *) &l, buf + ofs, 2);
		p[0] &= ~0xC0;
		l = SVAL(p, 0);
		DEBUG(5,
		      ("name ptr to pos %d from %d is %s\n", l, ofs, buf + l));
		return buf + l;
	} else
		return buf + ofs;
}

/****************************************************************************
extract a netbios name from a buf
****************************************************************************/
void name_extract(char *buf, int ofs, char *name)
{
	strcpy(name, "");
	name_interpret(name_ptr(buf, ofs), name);
}

/****************************************************************************
return the total storage length of a mangled name
****************************************************************************/
int name_len(char *s)
{
	unsigned char c = *(unsigned char *) s;
	if ((c & 0xC0) == 0xC0)
		return 2;
	return strlen(s) + 1;
}

/****************************************************************************
send a single packet to a port on another machine
****************************************************************************/
BOOL send_packet(char *buf, int len, struct in_addr *ip, int port, int type)
{
	BOOL ret;
	int out_fd;
	struct sockaddr_in sock_out;
	int one = 1;

	if (passive)
		return True;

	/* create a socket to write to */
	out_fd = socket(AF_INET, type, 0);
	if (out_fd == -1) {
		DEBUG(0, ("socket failed"));
		return False;
	}
#if 1
	/* allow broadcasts on it */
	setsockopt(out_fd, SOL_SOCKET, SO_BROADCAST, (char *) &one,
	           sizeof(one));
#endif

	/* set the address and port */
	memset((char *) &sock_out, 0, sizeof(sock_out));
	memcpy((char *) &sock_out.sin_addr, (char *) ip, 4);
	sock_out.sin_port = htons(port);
	sock_out.sin_family = AF_INET;

	if (DEBUGLEVEL > 0)
		DEBUG(3, ("sending a packet of len %d to (%s) on port %d of "
		          "type %s\n",
		          len, inet_ntoa(*ip), port,
		          type == SOCK_DGRAM ? "DGRAM" : "STREAM"));

	/* send it */
	ret = (sendto(out_fd, buf, len, 0, (struct sockaddr *) &sock_out,
	              sizeof(sock_out)) >= 0);

	if (!ret)
		DEBUG(0, ("Send packet failed. ERRNO=%d\n", errno));

	close(out_fd);
	return ret;
}

/****************************************************************************
substitute a string for a pattern in another string. Make sure there is
enough room!

This routine looks for pattern in s and replaces it with
insert. It may do multiple replacements.

return True if a substitution was done.
****************************************************************************/
BOOL string_sub(char *s, char *pattern, char *insert)
{
	BOOL ret = False;
	char *p;
	int ls = strlen(s);
	int lp = strlen(pattern);
	int li = strlen(insert);

	if (!*pattern)
		return False;

	while (lp <= ls && (p = strstr(s, pattern))) {
		ret = True;
		safe_memcpy(p + li, p + lp, ls + 1 - (PTR_DIFF(p, s) + lp));
		memcpy(p, insert, li);
		s = p + li;
		ls = strlen(s);
	}
	return ret;
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
#ifdef LINUX
	setpgrp();
#endif

#ifdef USE_SETSID
	setsid();
#else
	{
		int i = open("/dev/tty", O_RDWR);
		if (i >= 0) {
			ioctl(i, (int) TIOCNOTTY, (char *) 0);
			close(i);
		}
	}
#endif
#endif
}

/****************************************************************************
calculate the default netmask for an address
****************************************************************************/
static void default_netmask(struct in_addr *inm, struct in_addr *iad)
{
	unsigned long ad = ntohl(iad->s_addr);
	unsigned long nm;
	/*
	** Guess a netmask based on the class of the IP address given.
	*/
	if ((ad & 0x80000000) == 0) {
		/* class A address */
		nm = 0xFF000000;
	} else if ((ad & 0xC0000000) == 0x80000000) {
		/* class B address */
		nm = 0xFFFF0000;
	} else if ((ad & 0xE0000000) == 0xC0000000) {
		/* class C address */
		nm = 0xFFFFFF00;
	} else {
		/* class D or E; netmask doesn't make much sense */
		nm = 0;
	}
	inm->s_addr = htonl(nm);
}

/****************************************************************************
  get the broadcast address for our address
(troyer@saifr00.ateng.az.honeywell.com)
****************************************************************************/
void get_broadcast(struct in_addr *if_ipaddr, struct in_addr *if_bcast,
                   struct in_addr *if_nmask)
{
	int sock = -1; /* AF_INET raw socket desc */
	char buff[1024];
	struct ifreq *ifr;
	int i;

#ifdef USE_IFREQ
	struct ifreq ifreq;
	struct strioctl strioctl;
	struct ifconf *ifc;
#else
	struct ifconf ifc;
#endif

	/* get a default netmask and broadcast */
	default_netmask(if_nmask, if_ipaddr);
	{
		unsigned long ip = ntohl(if_ipaddr->s_addr);
		unsigned long nm = ntohl(if_nmask->s_addr);
		ip &= nm;                 /* mask down to our network number */
		ip |= (0x00FFFFFF & ~nm); /* insert 1s in host field         */
		if_bcast->s_addr = htonl(ip);
	}

	/* Create a socket to the INET kernel. */
#if USE_SOCKRAW
	if ((sock = socket(AF_INET, SOCK_RAW, PF_INET)) < 0)
#else
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
#endif
	{
		DEBUG(0, ("Unable to open socket to get broadcast address\n"));
		return;
	}

	/* Get a list of the configures interfaces */
#ifdef USE_IFREQ
	ifc = (struct ifconf *) buff;
	ifc->ifc_len = BUFSIZ - sizeof(struct ifconf);
	strioctl.ic_cmd = SIOCGIFCONF;
	strioctl.ic_dp = (char *) ifc;
	strioctl.ic_len = sizeof(buff);
	if (ioctl(sock, I_STR, &strioctl) < 0) {
		DEBUG(0, ("I_STR/SIOCGIFCONF: %s\n", strerror(errno)));
		return;
	}
	ifr = (struct ifreq *) ifc->ifc_req;

	/* Loop through interfaces, looking for given IP address */
	for (i = ifc->ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
#else
	ifc.ifc_len = sizeof(buff);
	ifc.ifc_buf = buff;
	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
		DEBUG(0, ("SIOCGIFCONF: %s\n", strerror(errno)));
		return;
	}
	ifr = ifc.ifc_req;

	/* Loop through interfaces, looking for given IP address */
	for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
#endif
	{
		DEBUG(3,
		      ("Interface: %s  IP addr: %s\n", ifr->ifr_name,
		       inet_ntoa(
		           (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr)));
		if (if_ipaddr->s_addr ==
		    (*(struct sockaddr_in *) &ifr->ifr_addr).sin_addr.s_addr)
			break;
	}

	if (i < 0) {
		DEBUG(0, ("No interface found for address %s\n",
		          inet_ntoa(*if_ipaddr)));
		return;
	}

	/* Get the broadcast address from the kernel */
#ifdef USE_IFREQ
	ifreq = *ifr;

	strioctl.ic_cmd = SIOCGIFBRDADDR;
	strioctl.ic_dp = (char *) &ifreq;
	strioctl.ic_len = sizeof(struct ifreq);
	if (ioctl(sock, I_STR, &strioctl) < 0)
		DEBUG(0,
		      ("Failed I_STR/SIOCGIFBRDADDR: %s\n", strerror(errno)));
	else
		*if_bcast =
		    ((struct sockaddr_in *) &ifreq.ifr_broadaddr)->sin_addr;
#else
	if (ioctl(sock, SIOCGIFBRDADDR, ifr) < 0)
		DEBUG(0, ("SIOCGIFBRDADDR failed\n"));
	else
		*if_bcast = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr;
#endif

	/* Get the netmask address from the kernel */
#ifdef USE_IFREQ
	ifreq = *ifr;

	strioctl.ic_cmd = SIOCGIFNETMASK;
	strioctl.ic_dp = (char *) &ifreq;
	strioctl.ic_len = sizeof(struct ifreq);
	if (ioctl(sock, I_STR, &strioctl) < 0)
		DEBUG(0,
		      ("Failed I_STR/SIOCGIFNETMASK: %s\n", strerror(errno)));
	else
		*if_nmask = ((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr;
#else
	if (ioctl(sock, SIOCGIFNETMASK, ifr) < 0)
		DEBUG(0, ("SIOCGIFNETMASK failed\n"));
	else
		*if_nmask = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr;
#endif

	/* Close up shop */
	(void) close(sock);

	DEBUG(2, ("Broadcast address for %s = %s\n", ifr->ifr_name,
	          inet_ntoa(*if_bcast)));
	DEBUG(2,
	      ("Netmask for %s = %s\n", ifr->ifr_name, inet_ntoa(*if_nmask)));

	return;
} /* get_broadcast */

/****************************************************************************
  Signal handler for SIGPIPE (write on a disconnected socket)
****************************************************************************/
void Abort(void)
{
	DEBUG(0, ("Abort called. Probably got SIGPIPE\n"));
	exit(1);
}

/****************************************************************************
get my own name and IP
****************************************************************************/
BOOL get_myname(char *myname, struct in_addr *ip)
{
	struct hostent *hp;
	pstring myhostname = "";

	/* get my host name */
	if (gethostname(myhostname, sizeof(myhostname)) == -1) {
		DEBUG(0, ("gethostname failed\n"));
		return False;
	}

	/* get host info */
	if ((hp = Get_Hostbyname(myhostname)) == 0) {
		DEBUG(0, ("Get_Hostbyname: Unknown host %s.\n", myhostname));
		return False;
	}

	if (myname) {
		/* split off any parts after an initial . */
		char *p = strchr(myhostname, '.');
		if (p)
			*p = 0;

		strcpy(myname, myhostname);
	}

	if (ip)
		memcpy((char *) ip, (char *) hp->h_addr, 4);

	return True;
}

/****************************************************************************
true if two IP addresses are equal
****************************************************************************/
BOOL ip_equal(struct in_addr *ip1, struct in_addr *ip2)
{
	char *p1 = (char *) ip1;
	char *p2 = (char *) ip2;
	int l = sizeof(*ip1);
	while (l--)
		if (*p1++ != *p2++)
			return False;
	return True;
}

/****************************************************************************
get info about the machine and OS
****************************************************************************/
void get_machine_info(void)
{
#if !HAVE_SYSCONF

	/* assume it doesn't have saved uids and gids */
	machine_info.have_saved_ids = False;

#else

	machine_info.have_saved_ids = (sysconf(_POSIX_SAVED_IDS) == 1);

#endif

	DEBUG(3, ("Sysconfig:\n"));
	DEBUG(3, ("\tsaved_ids = %d\n", machine_info.have_saved_ids));
	DEBUG(3, ("\n"));
}

/****************************************************************************
open a socket of the specified type, port and address for incoming data
****************************************************************************/
int open_socket_in(int type, int port)
{
	struct hostent *hp;
	struct sockaddr_in sock;
	pstring host_name;
	int res;

	/* get my host name */
	if (gethostname(host_name, sizeof(host_name)) == -1) {
		DEBUG(0, ("gethostname failed\n"));
		return -1;
	}

	/* get host info */
	if ((hp = Get_Hostbyname(host_name)) == 0) {
		DEBUG(0, ("Get_Hostbyname: Unknown host. %s\n", host_name));
		return -1;
	}

	memset((char *) &sock, 0, sizeof(sock));
	memcpy((char *) &sock.sin_addr, (char *) hp->h_addr, hp->h_length);
	sock.sin_port = htons(port);
	sock.sin_family = hp->h_addrtype;
	sock.sin_addr.s_addr = INADDR_ANY;
	res = socket(hp->h_addrtype, type, 0);
	if (res == -1) {
		DEBUG(0, ("socket failed\n"));
		return -1;
	}

#ifdef SO_REUSEADDR
	{
		int one = 1;
		if (setsockopt(res, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
		               sizeof(one)) == -1) {
			DEBUG(3, ("setsockopt(REUSEADDR) failed - ignored\n"));
		}
	}
#endif

	/* now we've got a socket - we need to bind it */
	if (bind(res, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
		if (port < 1000)
			DEBUG(0, ("bind failed on port %d\n", port));
		close(res);

		if (port >= 1000 && port < 9000)
			return open_socket_in(type, port + 1);

		return -1;
	}
	DEBUG(1, ("bind succeeded on port %d\n", port));

	return res;
}

/****************************************************************************
interpret an internet address or name into an IP address in 4 byte form
****************************************************************************/
unsigned long interpret_addr(char *str)
{
	struct hostent *hp;
	unsigned long res;

	/* if it's in the form of an IP address then get the lib to interpret it
	 */
	if (isdigit(str[0]))
		return inet_addr(str);

	/* otherwise assume it's a network name of some sort and use
	 * Get_Hostbyname */
	if ((hp = Get_Hostbyname(str)) == 0) {
		DEBUG(0, ("Get_Hostbyname: Unknown host. %s\n", str));
		return 0;
	}

	memcpy((char *) &res, (char *) hp->h_addr, sizeof(res));
	return res;
}

/****************************************************************************
a wrapper for gethostbyname() that tries with all lower and all upper case
if the initial name fails
****************************************************************************/
struct hostent *Get_Hostbyname(char *name)
{
	char *name2 = strdup(name);
	struct hostent *ret;

	if (!name2) {
		DEBUG(0,
		      ("Memory allocation error in Get_Hostbyname! panic\n"));
		exit(0);
	}

	ret = gethostbyname(name2);
	if (ret != NULL) {
		free(name2);
		return ret;
	}

	/* try with all lowercase */
	strlower(name2);
	ret = gethostbyname(name2);
	if (ret != NULL) {
		free(name2);
		return ret;
	}

	/* try with all uppercase */
	strupper(name2);
	ret = gethostbyname(name2);
	if (ret != NULL) {
		free(name2);
		return ret;
	}

	/* nothing works :-( */
	free(name2);
	return NULL;
}
