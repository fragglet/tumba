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
BOOL browse = True;

BOOL always_reply = False;

/* shall I server DNS names as well ?? */
BOOL dns_serve = False;

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
void add_host_name(char *name, struct in_addr *ip);

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
delete a netbios name
****************************************************************************/
void del_name(int i)
{
	names[i].valid = False;
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

	/* add the magic __SAMBA__ name */
	add_host_name("__SAMBA__", &myip);

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
load a netbios hosts file
****************************************************************************/
void load_hosts_file(char *name)
{
	int i;
	FILE *f = fopen(name, "r");
	pstring line;
	if (!f) {
		DEBUG(2, ("Couldn't open hosts file %s\n", name));
		return;
	}

	while (!feof(f)) {
		if (!fgets_slash(line, sizeof(pstring), f))
			continue;

		if (*line == '#')
			continue;

		{
			pstring ip = "", name = "", flags = "";
			unsigned long a;
			int count = sscanf(line, "%s%s%s", ip, name, flags);
			if (count <= 0)
				continue;

			if (count > 0 && count < 2) {
				DEBUG(0,
				      ("Ill formed hosts line [%s]\n", line));
				continue;
			}

			i = add_name();
			if (i < 0) {
				fclose(f);
				return;
			}

			a = interpret_addr(ip);
			memcpy((char *) &names[i].ip, (char *) &a, sizeof(a));

			names[i].valid = True;

			strupper(name);
			strcpy(names[i].name, name);
			strcpy(names[i].flags, flags);
			if (strchr(flags, 'G'))
				names[i].nb_flags |= 0x80;
			if (strchr(flags, 'S'))
				names[i].subnet = True;
			if (strchr(flags, 'M') && !ISNET(i))
				strcpy(myname, name);
		}
	}

	fclose(f);
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
add a host name
****************************************************************************/
void add_host_name(char *name, struct in_addr *ip)
{
	int i = add_name();
	if (i < 0)
		return;

	names[i].ip = *ip;
	strcpy(names[i].name, name);
	strupper(names[i].name);
	names[i].valid = True;
	names[i].start_time = time(NULL);
	names[i].ttl = 0;
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

	show_nmb(outbuf);
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
		if (!dns_serve) {
			DEBUG(2, ("\n"));
			return;
		} else
		/* try a DNS query to get the IP */
		{
			struct hostent *hp;
			pstring hname;

			strcpy(hname, qname);
			trim_string(hname, " ", " ");
			trim_string(hname, ".", ".");

			if ((hp = Get_Hostbyname(hname)) == 0) {
				DEBUG(2, (": unknown name sending no reply\n"));
				return;
			}

			memcpy((char *) &retip, (char *) hp->h_addr,
			       sizeof(retip));

			/* If it is on the same subnet then don't send a reply
			   as it might confuse a client to receive a reply from
			   two hosts. */
			{
				unsigned int net1, net2, nmask, subnet1,
				    subnet2;

				nmask = *(unsigned int *) &Netmask;
				net1 = (*(unsigned int *) &myip);
				subnet1 = net1 & nmask;
				net2 = (*(unsigned int *) &retip);
				subnet2 = net2 & nmask;

				if (!always_reply)
					if ((net1 != net2) && /* it's not me! */
					    (subnet1 ==
					     subnet2)) /* ... but it's my subnet
					                */
					{
						DEBUG(2,
						      (" on same subnet (%s), "
						       "sending no reply\n",
						       inet_ntoa(retip)));
						return;
					}
			}
		}

		DEBUG(2, (" sending positive reply (%s)\n", inet_ntoa(retip)));

		/* add the name for future reference */
		add_host_name(qname, &retip);
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

	show_nmb(outbuf);

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
#if 0
  int rec_name_trn_id = SVAL(inbuf,0);
  char *p = inbuf;
  unsigned char nb_flags = 0;
  struct in_addr tmpip;
  struct in_addr retip;
  int i;
#endif

	name_extract(inbuf, 12, qname);

	DEBUG(2,
	      ("(%s) status query on name (%s)\n", inet_ntoa(lastip), qname));

#if 0
  i = find_name(qname);

  if (i < 0)
    return;
  
  /* Send a POSITIVE NAME STATUS RESPONSE */
  SSVAL(outbuf,0,rec_name_trn_id);
  CVAL(outbuf,2) = (1<<7) | (1<<2);
  CVAL(outbuf,3) = 0;
  SSVAL(outbuf,4,0);
  SSVAL(outbuf,6,1);
  SSVAL(outbuf,8,0);
  SSVAL(outbuf,10,0);  
  p = outbuf+12;
  strcpy(p,inbuf+12);
  p += name_len(p);
  SSVAL(p,0,0x21);
  SSVAL(p,2,0x1);
  SIVAL(p,4,0);
  SSVAL(p,8,6);


  show_nmb(outbuf);

  tmpip = lastip;
  send_packet(outbuf,nmb_len(outbuf),&tmpip,lastport>0?lastport:137,SOCK_DGRAM);
#endif

	return;
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

	if (minute_counter >= announce_interval || force) {
		minute_counter = 0;

		/* possibly reset our masters */
		if (!force && master_count++ >= master_interval) {
			master_count = 0;
			DEBUG(2,
			      ("%s Redoing browse master ips\n", timestring()));
			for (i = 0; i < num_names; i++)
				names[i].found_master = False;
		}

		/* find the subnet masters */
		for (i = 0; i < num_names; i++)
			if (NAMEVALID(i) && ISNET(i) &&
			    !names[i].found_master) {
				struct in_addr new_master;

				sprintf(name, "%-15.15s%c", names[i].name,
				        0x1d);
				names[i].found_master =
				    name_query(inbuf, outbuf, name, names[i].ip,
				               &new_master, 3, construct_reply);
				if (!names[i].found_master) {
					DEBUG(1, ("Failed to find a master "
					          "browser for %s using %s\n",
					          names[i].name,
					          inet_ntoa(names[i].ip)));
					memset(&names[i].master_ip, 0, 4);
				} else {
					if (memcmp(&new_master,
					           &names[i].master_ip, 4) == 0)
						DEBUG(2,
						      ("Found master browser "
						       "for %s at %s\n",
						       names[i].name,
						       inet_ntoa(new_master)));
					else
						DEBUG(1,
						      ("New master browser for "
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
void process(char *lookup)
{
	static int trans_num = 0;
	time_t timer = 0;

	InBuffer = (char *) malloc(BUFFER_SIZE);
	OutBuffer = (char *) malloc(BUFFER_SIZE);
	if ((InBuffer == NULL) || (OutBuffer == NULL))
		return;

	if (*lookup) {
		struct in_addr ip;
		if (name_query(InBuffer, OutBuffer, lookup, bcast_ip, &ip, 5,
		               NULL)) {
			printf("%s %s\n", inet_ntoa(ip), lookup);
			name_status(InBuffer, OutBuffer, lookup);
		} else
			printf("couldn't find name %s\n", lookup);
		return;
	}

#if 0
  if (is_daemon)
    register_groups();

  if (!reply_only && is_daemon)
    {
      int i = find_name(myname);
      if (i < 0 || !register_name(&names[i],&bcast_ip,is_daemon?NULL:construct_reply))
	{
	  DEBUG(0,("Failed to register my own name\n"));
	}
    }
#endif

	while (True) {
		if (browse) {
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
				selrtn = select(255, SELECT_CAST & fds, NULL,
				                NULL, &timeout);
			} while (selrtn < 0 && errno == EINTR);

			if (Client_dgram >= 0 && FD_ISSET(Client_dgram, &fds)) {
				nread = read_udp_socket(Client_dgram, InBuffer,
				                        BUFFER_SIZE);
				if (nread > 0)
					construct_dgram_reply(InBuffer,
					                      OutBuffer);
			}

			if (FD_ISSET(Client, &fds)) {
				nread = read_udp_socket(Client, InBuffer,
				                        BUFFER_SIZE);
				if (nread <= 0)
					continue;
			} else
				continue;
		} else {
			if (!receive_nmb(InBuffer,
			                 is_daemon ? 0 : idle_timeout))
				return;
		}

		if (nmb_len(InBuffer) <= 0)
			continue;

		if (DEBUGLEVEL > 2)
			show_nmb(InBuffer);

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
	printf("\t-L name              lookup this netbios name then exit\n");
	printf("\t-S                   serve queries via DNS if not on the "
	       "same subnet\n");
	printf("\t-A                   serve queries even if on the same "
	       "subnet\n");
	printf("\t-H hosts file        load a netbios hosts file\n");
	printf("\t-G group name        add a group name to be part of\n");
	printf("\t-b                   toggles browsing support (defaults to "
	       "on)\n");
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
	pstring lookup = "";
	pstring host_file = "";

	sprintf(debugf, "%s.nmb.debug", DEBUGFILE);

#ifdef LMHOSTS
	strcpy(host_file, LMHOSTS);
#endif

	while ((opt = getopt(argc, argv, "C:bAL:i:B:N:Rn:l:d:Dp:hPSH:G:")) !=
	       EOF)
		switch (opt) {
		case 'C':
			strcpy(comment, optarg);
			break;
		case 'G':
			add_group_name(optarg);
			break;
		case 'b':
			browse = !browse;
			break;
		case 'A':
			always_reply = True;
			dns_serve = True;
			break;
		case 'H':
			strcpy(host_file, optarg);
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
		case 'S':
			dns_serve = !dns_serve;
			break;
		case 'l':
			sprintf(debugf, "%s.nmb.debug", optarg);
			break;
		case 'i':
			strcpy(scope, optarg);
			break;
		case 'L':
			strcpy(lookup, optarg);
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

	if (*lookup)
		DEBUGLEVEL++;

	if (DEBUGLEVEL > 10) {
		extern FILE *login, *logout;
		pstring fname = "";
		sprintf(fname, "%s.in", debugf);
		login = fopen(fname, "w");
		sprintf(fname, "%s.out", debugf);
		logout = fopen(fname, "w");
	}

	if (*lookup) {
		if (dbf)
			fclose(dbf);
		dbf = stdout;
	}

	DEBUG(1, ("%s netbios nameserver version %s started\n", timestring(),
	          VERSION));
	DEBUG(1, ("Copyright Andrew Tridgell 1994\n"));

	if (*host_file) {
		load_hosts_file(host_file);
		DEBUG(3, ("Loaded hosts file\n"));
	}

	get_machine_info();

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

	if (open_sockets(is_daemon || *lookup, *lookup ? 8000 : port)) {
		process(lookup);
		close_sockets();
	}
	if (dbf)
		fclose(dbf);
	return 0;
}
