/*
   Unix SMB/Netbios implementation.
   Version 1.8.
   Copyright (C) Andrew Tridgell 1994

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

extern pstring debugf;
extern int DEBUGLEVEL;

char *InBuffer = NULL;
char *OutBuffer = NULL;

extern BOOL NeedSwap;
extern pstring scope;

BOOL reply_only = False;

extern struct in_addr lastip;
extern int lastport;
extern struct in_addr myip;
extern struct in_addr bcast_ip;
extern struct in_addr Netmask;
pstring myname = "";
pstring myhostname = "";
int myttl = 0;

int num_names = 0;
name_struct *names = NULL;

int Client_dgram = -1;
extern int Client;

#define NAMEVALID(i) names[i].valid
#define ISGROUP(i)   ((names[i].nb_flags & 0x80) != 0)
#define ISSUBNET(i)  (names[i].subnet)
#define ISNET(i)     (ISGROUP(i) || ISSUBNET(i))

void construct_reply(char *, char *);

/* are we running as a daemon ? */
BOOL is_daemon = False;

/* machine comment */
fstring comment = "";

/* die after this number of 10ths of seconds if no activity and not a daemon */
int idle_timeout = 1200;

void add_group_name(char *name);

BOOL got_bcast = False;
BOOL got_nmask = False;

/****************************************************************************
add a netbios name
****************************************************************************/
int add_name(void)
{
	int i;
	name_struct *n;

	for (i = 0; i < num_names; i++)
		if (!names[i].valid)
			return i;

	if (num_names == 0)
		n = (name_struct *) malloc(sizeof(name_struct));
	else
		n = (name_struct *) realloc(names, sizeof(name_struct) *
		                                       (num_names + 1));
	if (!n) {
		DEBUG(0, ("Can't malloc more names space!\n"));
		return -1;
	}
	n[num_names].valid = False;
	n[num_names].found_master = False;
	n[num_names].subnet = False;
	strcpy(n[num_names].name, "");
	strcpy(n[num_names].flags, "");
	n[num_names].ttl = 0;
	n[num_names].start_time = 0;
	n[num_names].nb_flags = 0;
	names = n;
	num_names++;
	return num_names - 1;
}

/****************************************************************************
  true if two netbios names are equal
****************************************************************************/
static BOOL name_equal(char *s1, char *s2)
{
	char *p1, *p2;
	while (*s1 && *s2 && (*s1 != ' ') && (*s2 != ' ')) {
		p1 = s1;
		p2 = s2; /* toupper has side effects as a macro */
		if (toupper(*p1) != toupper(*p2))
			return False;
		s1++;
		s2++;
	}
	if ((*s1 == 0 || *s1 == ' ') && (*s2 == 0 || *s2 == ' '))
		return True;
	else
		return False;
}

/****************************************************************************
find a name
****************************************************************************/
int find_name(char *s)
{
	int i;
	time_t t = time(NULL);

	for (i = 0; i < num_names; i++)
		if (names[i].valid) {
			if ((names[i].ttl > 0) &&
			    (t > (names[i].start_time + names[i].ttl)))
				names[i].valid = False;
			else {
				if (name_equal(s, names[i].name))
					return i;
			}
		}
	return -1;
}

/****************************************************************************
check names, and change any 0 IPs to myip
****************************************************************************/
void check_names(void)
{
	int i;
	int group_count = 0;

	for (i = 0; i < num_names; i++)
		if (ISNET(i))
			group_count++;

	if (group_count == 0)
		add_group_name("LANGROUP");

	for (i = 0; i < num_names; i++)
		if (names[i].valid &&
		    strequal((char *) inet_ntoa(names[i].ip), "0.0.0.0"))
			names[i].ip = (ISNET(i) ? bcast_ip : myip);
}

/****************************************************************************
dump a copy of the name table
****************************************************************************/
void dump_names(void)
{
	int i;
	DEBUG(3, ("Dump of local name table\n"));
	for (i = 0; i < num_names; i++)
		if (names[i].valid)
			DEBUG(3, ("%s %s %s %d 0x%X %s\n", names[i].name,
			          inet_ntoa(names[i].ip), names[i].flags,
			          names[i].ttl, names[i].nb_flags,
			          BOOLSTR(names[i].subnet)));
}

/****************************************************************************
add a netbios group name
****************************************************************************/
void add_group_name(char *name)
{
	int i = add_name();
	if (i < 0)
		return;

	strupper(name);
	memset((char *) &names[i].ip, 0, sizeof(names[i].ip));

	strcpy(names[i].name, name);
	strcpy(names[i].flags, "G");
	names[i].nb_flags |= 0x80;

	names[i].valid = True;
}

/****************************************************************************
read from a socket
****************************************************************************/
static int read_udp_socket(int fd, char *buf, int len)
{
	/* #define NORECVFROM */
#ifdef NORECVFROM
	return read(fd, buf, len);
#else
	int ret;
	struct sockaddr sock;
	int socklen;

	socklen = sizeof(sock);
	memset((char *) &sock, 0, socklen);
	memset((char *) &lastip, 0, sizeof(lastip));
	ret = recvfrom(fd, buf, len, 0, &sock, &socklen);
	if (ret <= 0) {
		DEBUG(2, ("read socket failed. ERRNO=%d\n", errno));
		return 0;
	}

	lastip = *(struct in_addr *) &sock.sa_data[2];
	lastport = ntohs(((struct sockaddr_in *) &sock)->sin_port);
	if (DEBUGLEVEL > 0)
		DEBUG(3, ("read %d bytes\n", ret));

	return ret;
#endif
}

/****************************************************************************
read data from the client. Maxtime is in 10ths of a sec
****************************************************************************/
static int read_max_udp(int fd, char *buffer, int bufsize, int maxtime)
{
	fd_set fds;
	int selrtn;
	int nread;
	struct timeval timeout;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	timeout.tv_sec = maxtime / 10;
	timeout.tv_usec = (maxtime % 10) * 100000;

	do {
		if (maxtime > 0)
			selrtn = select(255, SELECT_CAST & fds, NULL, NULL,
			                &timeout);
		else
			selrtn =
			    select(255, SELECT_CAST & fds, NULL, NULL, NULL);
	} while (selrtn < 0 && errno == EINTR);

	if (!FD_ISSET(fd, &fds))
		return 0;

	nread = read_udp_socket(fd, buffer, bufsize);

	/* return the number got */
	return nread;
}

/****************************************************************************
word out the length of a nmb message
****************************************************************************/
static int nmb_len(char *buf)
{
	int i;
	int ret = 12;
	char *p = buf;
	int qdcount = SVAL(buf, 4);
	int ancount = SVAL(buf, 6);
	int nscount = SVAL(buf, 8);
	int arcount = SVAL(buf, 10);

	/* check for insane qdcount values? */
	if (qdcount > 100 || qdcount < 0) {
		DEBUG(6, ("Invalid qdcount? qdcount=%d\n", qdcount));
		return 0;
	}

	for (i = 0; i < qdcount; i++) {
		p = buf + ret;
		ret += name_len(p) + 4;
	}

	for (i = 0; i < (ancount + nscount + arcount); i++) {
		int rdlength;
		p = buf + ret;
		ret += name_len(p) + 8;
		p = buf + ret;
		rdlength = SVAL(p, 0);
		ret += rdlength + 2;
	}

	return ret;
}

int nmb_recv_len = 0;

/****************************************************************************
receive a name message
****************************************************************************/
static BOOL receive_nmb(char *buffer, int timeout)
{
	int ret = read_max_udp(Client, buffer, BUFFER_SIZE, timeout);

	nmb_recv_len = ret;

	if (ret < 0) {
		DEBUG(0, ("No bytes from client\n"));
		close_sockets();
		exit(0);
	}

	if (ret <= 1)
		return False;

	DEBUG(3, ("received packet from (%s) nmb_len=%d len=%d\n",
	          inet_ntoa(lastip), nmb_len(buffer), ret));

	return True;
}

/****************************************************************************
send a name message
****************************************************************************/
static BOOL send_nmb(char *buf, int len, struct in_addr *ip)
{
	BOOL ret;
	struct sockaddr_in sock_out;
	int one = 1;

#if 1
	/* allow broadcasts on it */
	setsockopt(Client, SOL_SOCKET, SO_BROADCAST, (char *) &one,
	           sizeof(one));
#endif

	/* set the address and port */
	memset((char *) &sock_out, 0, sizeof(sock_out));
	memcpy((char *) &sock_out.sin_addr, (char *) ip, 4);
	sock_out.sin_port = htons(137);
	sock_out.sin_family = AF_INET;

	if (DEBUGLEVEL > 0)
		DEBUG(3, ("sending a packet of len %d to (%s) on port 137 of "
		          "type DGRAM\n",
		          len, inet_ntoa(*ip)));

	/* send it */
	ret = (sendto(Client, buf, len, 0, (struct sockaddr *) &sock_out,
	              sizeof(sock_out)) >= 0);

	if (!ret)
		DEBUG(0, ("Send packet failed. ERRNO=%d\n", errno));

	return ret;
}

/****************************************************************************
do a netbios name query to find someones IP
****************************************************************************/
static BOOL name_query(char *inbuf, char *outbuf, char *name, struct in_addr to_ip,
                       struct in_addr *ip, int maxtime, void (*fn)())
{
	static uint16 name_trn_id = 0x6242;
	char *p;
	BOOL saved_swap = NeedSwap;
	BOOL found = False;
	time_t start_time = time(NULL);
	time_t this_time = start_time;

	NeedSwap = !big_endian();

	DEBUG(2, ("Querying name %s\n", name));

	name_trn_id += getpid() % 100;
	name_trn_id = (name_trn_id % 0x7FFF);

	SSVAL(outbuf, 0, name_trn_id);
	CVAL(outbuf, 2) = 0x1;
	CVAL(outbuf, 3) = (1 << 4) | 0x0;
	SSVAL(outbuf, 4, 1);
	SSVAL(outbuf, 6, 0);
	SSVAL(outbuf, 8, 0);
	SSVAL(outbuf, 10, 0);
	p = outbuf + 12;
	name_mangle(name, p);
	p += name_len(p);
	SSVAL(p, 0, 0x20);
	SSVAL(p, 2, 0x1);
	p += 4;

	DEBUG(2, ("Sending name query for %s\n", name));

	if (!send_nmb(outbuf, nmb_len(outbuf), &to_ip)) {
		NeedSwap = saved_swap;
		return False;
	}

	while (!found && this_time - start_time <= maxtime) {
		this_time = time(NULL);

		if (receive_nmb(inbuf, 1)) {
			int rec_name_trn_id = SVAL(inbuf, 0);
			int opcode = (CVAL(inbuf, 2) >> 3) & 0xF;
			int nm_flags = ((CVAL(inbuf, 2) & 0x7) << 4) +
			               (CVAL(inbuf, 3) >> 4);
			int rcode = CVAL(inbuf, 3) & 0xF;

			/* is it a positive response to our request? */
			if ((rec_name_trn_id == name_trn_id) && opcode == 0 &&
			    (nm_flags & ~0x28) == 0x50 && rcode == 0) {
				found = True;
				DEBUG(2, ("Got a positive name query response "
				          "from %s\n",
				          inet_ntoa(lastip)));
				memcpy((char *) ip,
				       inbuf + 12 + name_len(inbuf + 12) + 12,
				       4);
			} else {
				if (fn)
					fn(inbuf, outbuf + nmb_len(outbuf));
			}
		}
	}
	NeedSwap = saved_swap;
	return found;
}

/****************************************************************************
reply to a reg request
****************************************************************************/
void reply_reg_request(char *inbuf, char *outbuf)
{
	int rec_name_trn_id = SVAL(inbuf, 0);
	char qname[100] = "";
	int ttl;
	char *p = inbuf;
	struct in_addr ip;
	int n = 0;
	unsigned char nb_flags;

	name_extract(inbuf, 12, qname);

	p += 12;
	p += name_len(p);
	p += 4;
	p += name_len(p);
	p += 4;
	ttl = IVAL(p, 0);
	nb_flags = CVAL(p, 6);
	p += 8;
	memcpy((char *) &ip, p, 4);

	DEBUG(2, ("Name registration request for %s (%s) nb_flags=0x%x\n",
	          qname, inet_ntoa(ip), nb_flags));

	/* if the name doesn't exist yet then don't respond */
	if ((n = find_name(qname)) < 0) {
		DEBUG(3, ("Name doesn't exist\n"));
		return;
	}

	/* if it's a group name then ignore it */
	if (ISNET(n)) {
		DEBUG(3, ("Group name - ignoring\n"));
		return;
	}

	/* if it's not my name then don't worry about it */
	if (!name_equal(myname, qname)) {
		DEBUG(3, ("Not my name\n"));
		return;
	}

	/* if it's my name and it's also my IP then don't worry about it */
	if (ip_equal(&ip, &myip)) {
		DEBUG(3, ("Is my IP\n"));
		return;
	}

	DEBUG(0,
	      ("Someones using my name (%s), sending negative reply\n", qname));

	/* Send a NEGATIVE REGISTRATION RESPONSE to protect our name */
	SSVAL(outbuf, 0, rec_name_trn_id);
	CVAL(outbuf, 2) = (1 << 7) | (0x5 << 3) | 0x5;
	CVAL(outbuf, 3) = (1 << 7) | 0x6;
	SSVAL(outbuf, 4, 0);
	SSVAL(outbuf, 6, 1);
	SSVAL(outbuf, 8, 0);
	SSVAL(outbuf, 10, 0);
	p = outbuf + 12;
	strcpy(p, inbuf + 12);
	p += name_len(p);
	SSVAL(p, 0, 0x20);
	SSVAL(p, 2, 0x1);
	SIVAL(p, 4, names[n].ttl);
	SSVAL(p, 8, 6);
	CVAL(p, 10) = nb_flags;
	CVAL(p, 11) = 0;
	p += 12;

	memcpy(p, (char *) &ip,
	       4); /* IP address of the name's owner (that's us) */
	p += 4;

	if (ip_equal(&ip, &bcast_ip)) {
		DEBUG(0, ("Not replying to broadcast address\n"));
		return;
	}

	send_packet(outbuf, nmb_len(outbuf), &ip, 137, SOCK_DGRAM);

	return;
}

/****************************************************************************
reply to a name query
****************************************************************************/
void reply_name_query(char *inbuf, char *outbuf)
{
	int rec_name_trn_id = SVAL(inbuf, 0);
	char qname[100] = "";
	char *p = inbuf;
	unsigned char nb_flags = 0;
	struct in_addr tmpip;
	struct in_addr retip;
	int i;

	name_extract(inbuf, 12, qname);

	DEBUG(2, ("(%s) querying name (%s)", inet_ntoa(lastip), qname));

	i = find_name(qname);

	if (i >= 0) {
		if (ISNET(i)) {
			DEBUG(2, (" - group name. No reply\n"));
			return;
		}

		retip = names[i].ip;
		nb_flags = names[i].nb_flags;
		DEBUG(2, (" sending positive reply\n"));
	} else {
		DEBUG(2, ("\n"));
		return;
	}

	/* Send a POSITIVE NAME QUERY RESPONSE */
	SSVAL(outbuf, 0, rec_name_trn_id);
	CVAL(outbuf, 2) = (1 << 7) | 0x5;
	CVAL(outbuf, 3) = 0;
	SSVAL(outbuf, 4, 0);
	SSVAL(outbuf, 6, 1);
	SSVAL(outbuf, 8, 0);
	SSVAL(outbuf, 10, 0);
	p = outbuf + 12;
	strcpy(p, inbuf + 12);
	p += name_len(p);
	SSVAL(p, 0, 0x20);
	SSVAL(p, 2, 0x1);
	SIVAL(p, 4, myttl);
	SSVAL(p, 8, 6);
	CVAL(p, 10) = nb_flags;
	CVAL(p, 11) = 0;
	p += 12;
	memcpy(p, (char *) &retip, 4);
	p += 4;

	tmpip = lastip;
	send_packet(outbuf, nmb_len(outbuf), &tmpip,
	            lastport > 0 ? lastport : 137, SOCK_DGRAM);

	return;
}

/****************************************************************************
reply to a name status query
****************************************************************************/
void reply_name_status(char *inbuf, char *outbuf)
{
	char qname[100] = "";

	name_extract(inbuf, 12, qname);

	DEBUG(2,
	      ("(%s) status query on name (%s)\n", inet_ntoa(lastip), qname));
}

/****************************************************************************
  construct a reply to the incoming packet
****************************************************************************/
void construct_reply(char *inbuf, char *outbuf)
{
	int opcode = CVAL(inbuf, 2) >> 3;
	int nm_flags = ((CVAL(inbuf, 2) & 0x7) << 4) + (CVAL(inbuf, 3) >> 4);
	int rcode = CVAL(inbuf, 3) & 0xF;

	if (opcode == 0x5 && (nm_flags & ~1) == 0x10 && rcode == 0)
		reply_reg_request(inbuf, outbuf);

	if (opcode == 0 && (nm_flags & ~1) == 0x10 && rcode == 0)
		reply_name_query(inbuf, outbuf);

	if (opcode == 0 && (nm_flags & ~1) == 0x00 && rcode == 0)
		reply_name_status(inbuf, outbuf);
}

/****************************************************************************
construct a host announcement unicast

Note that I don't know what half the numbers mean - I'm just using what I
saw another PC use :-)
****************************************************************************/
BOOL announce_host(char *outbuf, char *group, struct in_addr ip)
{
	BOOL oldswap = NeedSwap;
	char *p, *p2;
	char *gptr;

	DEBUG(2, ("Sending host announcement to %s for group %s\n",
	          inet_ntoa(ip), group));

	memset(outbuf, 0, 256);

	NeedSwap = !big_endian();

	CVAL(outbuf, 0) = 17;
	CVAL(outbuf, 1) = 2;
	SSVAL(outbuf, 2, time(NULL) % 10000 + 42);
	memcpy(outbuf + 4, &myip, 4);
	SSVAL(outbuf, 8, 138);
	SSVAL(outbuf, 10, 186 + strlen(comment) + 1);
	SSVAL(outbuf, 12, 0);

	p = outbuf + 14;

	p += name_mangle(myname, p);
	strcpy(p - 3, "AA");
	gptr = p;
	p += name_mangle(group, p);
	strcpy(p - 3, "BO");

	NeedSwap = big_endian();

	/* now setup the smb part */
	p -= 4;
	set_message(p, 17, 50 + strlen(comment) + 1, True);
	CVAL(p, smb_com) = SMBtrans;
	SSVAL(p, smb_vwv1, 33 + strlen(comment) + 1);
	SSVAL(p, smb_vwv11, 33 + strlen(comment) + 1);
	SSVAL(p, smb_vwv12, 86);
	SSVAL(p, smb_vwv13, 3);
	SSVAL(p, smb_vwv14, 1);
	SSVAL(p, smb_vwv15, 1);
	SSVAL(p, smb_vwv16, 2);
	SSVAL(p, smb_vwv17, 1);
	p2 = smb_buf(p);
	strcpy(p2, "\\MAILSLOT\\BROWSE");
	p2 = skip_string(p2, 1);

	CVAL(p2, 0) = 1;   /* host announce */
	CVAL(p2, 1) = 5;   /* announcement interval?? */
	CVAL(p2, 2) = 192; /* update count ?? */
	CVAL(p2, 3) = 39;
	SSVAL(p2, 4, 9);
	p2 += 6;
	strcpy(p2, myname);
	p2 += 16;
	CVAL(p2, 0) = 0;  /* major version (was 1) */
	CVAL(p2, 1) = 0;  /* minor version (was 51) */
	CVAL(p2, 2) = 3;  /* server and w'station */
	CVAL(p2, 3) = 11; /* unix + printq + domain member*/
	CVAL(p2, 4) = 0;
	CVAL(p2, 6) = 11;
	CVAL(p2, 7) = 3;
	CVAL(p2, 8) = 85;
	CVAL(p2, 9) = 170;
	p2 += 10;
	strcpy(p2, comment);

	p2 = gptr + name_mangle(group, gptr);
	strcpy(p2 - 3, "BO");

	NeedSwap = oldswap;

	return send_packet(outbuf, 200 + strlen(comment) + 1, &ip, 138,
	                   SOCK_DGRAM);
}

/****************************************************************************
a hook for browsing handling - called every 60 secs
****************************************************************************/
void do_browse_hook(char *inbuf, char *outbuf, BOOL force)
{
	static int announce_interval = 3;
	static int minute_counter = 3;
	static int master_interval = 4;
	static int master_count = 0;
	fstring name = "";
	int i;

	if (!force)
		minute_counter++;

	if (!force && minute_counter < announce_interval) {
		return;
	}

	minute_counter = 0;

	/* possibly reset our masters */
	if (!force && master_count++ >= master_interval) {
		master_count = 0;
		DEBUG(2, ("%s Redoing browse master ips\n", timestring()));
		for (i = 0; i < num_names; i++)
			names[i].found_master = False;
	}

	/* find the subnet masters */
	for (i = 0; i < num_names; i++)
		if (NAMEVALID(i) && ISNET(i) && !names[i].found_master) {
			struct in_addr new_master;

			sprintf(name, "%-15.15s%c", names[i].name, 0x1d);
			names[i].found_master =
			    name_query(inbuf, outbuf, name, names[i].ip,
			               &new_master, 3, construct_reply);
			if (!names[i].found_master) {
				DEBUG(1,
				      ("Failed to find a master "
				       "browser for %s using %s\n",
				       names[i].name, inet_ntoa(names[i].ip)));
				memset(&names[i].master_ip, 0, 4);
			} else {
				if (memcmp(&new_master, &names[i].master_ip,
				           4) == 0)
					DEBUG(2, ("Found master browser "
					          "for %s at %s\n",
					          names[i].name,
					          inet_ntoa(new_master)));
				else
					DEBUG(1, ("New master browser for "
					          "%s at %s\n",
					          names[i].name,
					          inet_ntoa(new_master)));
				names[i].master_ip = new_master;
			}
		}

	/* do our host announcements */
	for (i = 0; i < num_names; i++)
		if (NAMEVALID(i) && names[i].found_master)
			names[i].found_master = announce_host(
			    outbuf, names[i].name, names[i].master_ip);
}

/****************************************************************************
  construct a reply to the incoming dgram packet
****************************************************************************/
void construct_dgram_reply(char *inbuf, char *outbuf)
{
	static time_t last_time = 0;
	time_t t = time(NULL);
	if (t - last_time > 20) {
		DEBUG(3, ("Doing dgram reply to %s\n", inet_ntoa(lastip)));
		do_browse_hook(inbuf, outbuf, True);
	}
	last_time = t;
}

/****************************************************************************
  process commands from the client
****************************************************************************/
void process(void)
{
	static int trans_num = 0;
	time_t timer = 0;

	InBuffer = (char *) malloc(BUFFER_SIZE);
	OutBuffer = (char *) malloc(BUFFER_SIZE);
	if ((InBuffer == NULL) || (OutBuffer == NULL))
		return;

	while (True) {
		fd_set fds;
		int selrtn;
		struct timeval timeout;
		int nread;

		if (!timer || (time(NULL) - timer) > 60) {
			do_browse_hook(InBuffer, OutBuffer, False);
			timer = time(NULL);
		}

		FD_ZERO(&fds);
		FD_SET(Client, &fds);
		if (Client_dgram >= 0)
			FD_SET(Client_dgram, &fds);

		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		do {
			selrtn = select(255, SELECT_CAST & fds, NULL, NULL,
			                &timeout);
		} while (selrtn < 0 && errno == EINTR);

		if (Client_dgram >= 0 && FD_ISSET(Client_dgram, &fds)) {
			nread = read_udp_socket(Client_dgram, InBuffer,
			                        BUFFER_SIZE);
			if (nread > 0)
				construct_dgram_reply(InBuffer, OutBuffer);
		}

		if (!FD_ISSET(Client, &fds)) {
			continue;
		}

		nread = read_udp_socket(Client, InBuffer, BUFFER_SIZE);
		if (nread <= 0) {
			continue;
		}

		if (nmb_len(InBuffer) <= 0)
			continue;

		DEBUG(2, ("%s Transaction %d\n", timestring(), trans_num));

		construct_reply(InBuffer, OutBuffer);

		trans_num++;
	}
}

/****************************************************************************
  open the socket communication
****************************************************************************/
BOOL open_sockets(BOOL is_daemon, int port)
{
	struct hostent *hp;
	if (is_daemon) {
		/* get host info */
		if ((hp = Get_Hostbyname(myhostname)) == 0) {
			DEBUG(0, ("Get_Hostbyname: Unknown host. %s\n",
			          myhostname));
			return False;
		}

		Client = open_socket_in(SOCK_DGRAM, port);
		if (Client == -1)
			return False;

	} else {
		Client = 0;
	}

	Client_dgram = open_socket_in(SOCK_DGRAM, 138);

	/* We will abort gracefully when the client or remote system
	   goes away */
	signal(SIGPIPE, SIGNAL_CAST Abort);
	return True;
}

/****************************************************************************
  initialise connect, service and file structs
****************************************************************************/
BOOL init_structs(void)
{
	if (!get_myname(myhostname, &myip))
		return False;

	strupper(myhostname);

	/* Read the broadcast address from the interface */
	{
		struct in_addr ip1, ip2;
		if (!(got_bcast && got_nmask))
			get_broadcast(&myip, &ip1, &ip2);

		if (!got_bcast)
			bcast_ip = ip1;

		if (!got_nmask)
			Netmask = ip2;

		DEBUG(1, ("Using broadcast %s  ", inet_ntoa(bcast_ip)));
		DEBUG(1, ("netmask %s\n", inet_ntoa(Netmask)));
	}

	if (*myname == 0) {
		strcpy(myname, myhostname);
		strupper(myname);
	}

	if (find_name(myname) < 0) {
		int i = add_name();

		if (i < 0)
			return False;

		strcpy(names[i].name, myname);
		names[i].ip = myip;
		names[i].ttl = 0;
		names[i].nb_flags = 0;
		names[i].valid = True;
	} else
		DEBUG(3, ("Name %s already exists\n", myname));

	return True;
}

/****************************************************************************
usage on the program
****************************************************************************/
void usage(char *pname)
{
	DEBUG(0, ("Incorrect program usage - is the command line correct?\n"));

	printf("Usage: %s [-n name] [-B bcast address] [-D] [-p port] [-d "
	       "debuglevel] [-l log basename]\n",
	       pname);
	printf("Version %s\n", VERSION);
	printf("\t-D                    become a daemon\n");
	printf("\t-P                    passive only. don't respond\n");
	printf("\t-R                    only reply to queries, don't actively "
	       "send claims\n");
	printf("\t-p port               listen on the specified port\n");
	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-l log basename.      Basename for log/debug files\n");
	printf("\t-n netbiosname.       the netbios name to advertise for this "
	       "host\n");
	printf("\t-B broadcast address  the address to use for broadcasts\n");
	printf("\t-N netmask           the netmask to use for subnet "
	       "determination\n");
	printf("\t-G group name        add a group name to be part of\n");
	printf("\n");
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, char *argv[])
{
	int port = 137;
	int opt;
	extern FILE *dbf;
	extern char *optarg;

	sprintf(debugf, "%s.nmb.debug", DEBUGFILE);

	while ((opt = getopt(argc, argv, "C:i:B:N:Rn:l:d:Dp:hPSG:")) != EOF)
		switch (opt) {
		case 'C':
			strcpy(comment, optarg);
			break;
		case 'G':
			add_group_name(optarg);
			break;
		case 'B': {
			unsigned long a = interpret_addr(optarg);
			memcpy((char *) &bcast_ip, (char *) &a, sizeof(a));
			got_bcast = True;
		} break;
		case 'N': {
			unsigned long a = interpret_addr(optarg);
			memcpy((char *) &Netmask, (char *) &a, sizeof(a));
			got_nmask = True;
		} break;
		case 'n':
			strcpy(myname, optarg);
			break;
		case 'P': {
			extern BOOL passive;
			passive = True;
		} break;
		case 'R':
			reply_only = True;
			break;
		case 'l':
			sprintf(debugf, "%s.nmb.debug", optarg);
			break;
		case 'i':
			strcpy(scope, optarg);
			break;
		case 'D':
			is_daemon = True;
			break;
		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		default:
			usage(argv[0]);
			exit(1);
		}

	/* NOTE: This is the opposite of the smbd as name packets
	   seem to use the opposite byte order to smb packets */
	NeedSwap = !big_endian();

	DEBUG(1, ("%s netbios nameserver version %s started\n", timestring(),
	          VERSION));
	DEBUG(1, ("Copyright Andrew Tridgell 1994\n"));

	init_structs();

	if (!*comment)
		strcpy(comment, "Samba %v");
	string_sub(comment, "%v", VERSION);
	string_sub(comment, "%h", myhostname);

	check_names();

	DEBUG(3, ("Checked names\n"));

	dump_names();

	DEBUG(3, ("Dumped names\n"));

	if (is_daemon) {
		DEBUG(2, ("%s becoming a daemon\n", timestring()));
		become_daemon();
	}

	if (open_sockets(is_daemon, port)) {
		process();
		close_sockets();
	}
	if (dbf)
		fclose(dbf);
	return 0;
}
