/*
   Unix SMB/Netbios implementation.
   Version 1.5.
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

pstring domain = "";

char *InBuffer = NULL;
char *OutBuffer = NULL;

extern BOOL NeedSwap;

BOOL reply_only = False;

/* shall I server DNS names as well ?? */
BOOL dns_serve = False;

extern struct in_addr lastip;
extern struct in_addr myip;
extern struct in_addr bcast_ip;
extern struct in_addr Netmask;
pstring myname = "";
pstring myhostname = "";
int myttl = 0;

int num_names = 0;
name_struct *names = NULL;

void construct_reply(char *, char *);

/* are we running as a daemon ? */
BOOL daemon_mode = False;

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
			return (i);

	if (num_names == 0)
		n = (name_struct *) malloc(sizeof(name_struct));
	else
		n = (name_struct *) realloc(names, sizeof(name_struct) *
		                                       (num_names + 1));
	if (!n) {
		Debug(0, "Can't malloc more names space!\n");
		return (-1);
	}
	n[num_names].valid = False;
	strcpy(n[num_names].name, "");
	strcpy(n[num_names].flags, "");
	n[num_names].ttl = 0;
	n[num_names].nb_flags = 0;
	names = n;
	num_names++;
	return (num_names - 1);
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
	for (i = 0; i < num_names; i++)
		if (names[i].valid && name_equal(s, names[i].name))
			return (i);
	return -1;
}

/****************************************************************************
check names, and change any 0 IPs to myip
****************************************************************************/
void check_names(void)
{
	int i;
	for (i = 0; i < num_names; i++)
		if (names[i].valid &&
		    strequal((char *) inet_ntoa(names[i].ip), "0.0.0.0"))
			names[i].ip = myip;
}

/****************************************************************************
dump a copy of the name table
****************************************************************************/
void dump_names(void)
{
	int i;
	Debug(3, "Dump of local name table\n");
	for (i = 0; i < num_names; i++)
		if (names[i].valid)
			Debug(3, "%s %s %s %d 0x%X\n", names[i].name,
			      inet_ntoa(names[i].ip), names[i].flags,
			      names[i].ttl, names[i].nb_flags);
}

/****************************************************************************
load a netbios hosts file
****************************************************************************/
void load_hosts_file(char *name)
{
	FILE *f = fopen(name, "r");
	pstring line;
	if (!f) {
		Debug(0, "Couldn't open hosts file %s\n", name);
		return;
	}

	while (!feof(f)) {
		int i;

		if (!fgets(line, sizeof(pstring), f))
			continue;

		if (*line == '#')
			continue;

		{
			pstring ip = "", name = "", flags = "";
			unsigned long a;
			int count = sscanf(line, "%s%s%s", ip, name, flags);
			if (count == 0)
				continue;

			if (count < 2) {
				Debug(0, "Ill formed hosts line [%s]\n", line);
				continue;
			}

			i = add_name();
			if (i < 0) {
				fclose(f);
				return;
			}

			if (!strchr("0123456789", *ip)) {
				struct hostent *hp;
				if ((hp = gethostbyname(ip)) == 0) {
					Debug(0,
					      "Couldn't make an IP from [%s]\n",
					      ip);
					continue;
				}
				memcpy(&names[i].ip, hp->h_addr,
				       sizeof(names[i].ip));
			} else {
				a = inet_addr(ip);
				memcpy(&names[i].ip, &a, sizeof(a));
			}

			strupper(name);
			strcpy(names[i].name, name);
			strcpy(names[i].flags, flags);
			if (strchr(flags, 'G'))
				names[i].nb_flags |= 0x80;

			names[i].valid = True;
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
	memset(&names[i].ip, 0, sizeof(names[i].ip));

	strcpy(names[i].name, name);
	strcpy(names[i].flags, "G");
	names[i].nb_flags |= 0x80;

	names[i].valid = True;
}

/****************************************************************************
register all group names
****************************************************************************/
void register_groups(void)
{
	int i;
	for (i = 0; i < num_names; i++)
		if (names[i].valid && (names[i].nb_flags & 0x80))
			register_name(&names[i], &bcast_ip,
			              daemon_mode ? NULL : construct_reply);
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
	memcpy(&ip, p, 4);

	Debug(2, "Name registration request for %s (%s) nb_flags=0x%x\n", qname,
	      inet_ntoa(ip), nb_flags);

	/* if the name doesn't exist yet then don't respond */
	if ((n = find_name(qname)) < 0) {
		Debug(3, "Name doesn't exist\n");
		return;
	}

	/* if it's a group name and being registered as a group then it's OK */
	if ((names[n].nb_flags & 0x80) && (nb_flags & 0x80)) {
		Debug(3, "Group re-registration\n");
		return;
	}

	/* if it's not my name then don't worry about it */
	if (!name_equal(myname, qname)) {
		Debug(3, "Not my name\n");
		return;
	}

	/* if it's my name and it's also my IP then don't worry about it */
	if (ip_equal(&ip, &myip)) {
		Debug(3, "Is my IP\n");
		return;
	}

	Debug(0, "Someones using my name (%s), sending negative reply\n",
	      qname);

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

	memcpy(p, &ip, 4); /* IP address of the name's owner (that's us) */
	p += 4;

	if (ip_equal(&ip, &bcast_ip)) {
		Debug(0, "Not replying to broadcast address\n");
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

	Debug(2, "(%s) querying name (%s)", inet_ntoa(lastip), qname);

	if ((i = find_name(qname)) >= 0) {
		retip = names[i].ip;
		nb_flags = names[i].nb_flags;
		Debug(2, " sending positive reply\n");
	} else {
		if (!dns_serve) {
			Debug(2, "\n");
			return;
		} else
		/* try a DNS query to get the IP */
		{
			struct hostent *hp;
			pstring hname;

			strcpy(hname, qname);
			trim_string(hname, " ", " ");

			if ((hp = gethostbyname(hname)) == 0) {
				Debug(2, ": unknown name sending no reply\n");
				return;
			}

			memcpy(&retip, hp->h_addr, sizeof(retip));

			/* If it is on the same subnet then don't send a reply
			   as it might confuse a client to receive a reply from
			   two hosts. */
			{
				unsigned int net1, net2, nmask;

				nmask = *(unsigned int *) &Netmask;
				net1 = (*(unsigned int *) &myip) & nmask;
				net2 = (*(unsigned int *) &retip) & nmask;

				if (net1 == net2) {
					Debug(2,
					      " on same subnet (%s), sending "
					      "no reply\n",
					      inet_ntoa(retip));
					return;
				}
			}
		}

		Debug(2, " sending positive reply (%s)\n", inet_ntoa(retip));
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
	memcpy(p, &retip, 4);
	p += 4;

	show_nmb(outbuf);

	tmpip = lastip;
	send_packet(outbuf, nmb_len(outbuf), &tmpip, 137, SOCK_DGRAM);

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
}

/****************************************************************************
  process commands from the client
****************************************************************************/
void process(char *lookup)
{
	static int trans_num = 0;

	InBuffer = (char *) malloc(BUFFER_SIZE);
	OutBuffer = (char *) malloc(BUFFER_SIZE);
	if ((InBuffer == NULL) || (OutBuffer == NULL))
		return;

	register_groups();

	if (!reply_only) {
		int i = find_name(myname);
		if (i < 0 ||
		    !register_name(&names[i], &bcast_ip,
		                   daemon_mode ? NULL : construct_reply)) {
			Debug(0, "Failed to register my own name\n");
			return;
		}
	}

	if (*lookup) {
		struct in_addr ip;
		if (name_query(InBuffer, OutBuffer, lookup, &ip))
			printf("%s %s\n", inet_ntoa(ip), lookup);
		else
			printf("couldn't find name %s\n", lookup);
		return;
	}

	while (True) {
		if (!receive_nmb(InBuffer, 0))
			return;

		show_nmb(InBuffer);

		Debug(2, "%s Transaction %d\n", timestring(), trans_num);

		construct_reply(InBuffer, OutBuffer);

		trans_num++;
	}
}

/****************************************************************************
  open the socket communication
****************************************************************************/
BOOL open_sockets(BOOL daemon, int port)
{
	extern int Client;
	if (daemon) {
		struct hostent *hp;
		struct sockaddr_in sock;

		/* get host info */
		if ((hp = gethostbyname(myhostname)) == 0) {
			Debug(0, "Gethostbyname: Unknown host. %s\n",
			      myhostname);
			return False;
		}

		memset(&sock, 0, sizeof(sock));
		memcpy(&sock.sin_addr, hp->h_addr, hp->h_length);
		sock.sin_port = htons(port);
		sock.sin_family = hp->h_addrtype;
		sock.sin_addr.s_addr = INADDR_ANY;
		Client = socket(hp->h_addrtype, SOCK_DGRAM, 0);
		if (Client == -1) {
			perror("socket");
			return False;
		}

		/* now we've got a socket - we need to bind it */
		if (bind(Client, (struct sockaddr *) &sock, sizeof(sock)) < 0) {
			perror("bind");
			close(Client);
			return False;
		}
	} else {
		Client = 0;
	}
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
		return (False);

	/* Read the broadcast address from the interface */
	{
		struct in_addr ip1, ip2;
		get_broadcast(&myip, &ip1, &ip2);

		if (!got_bcast)
			bcast_ip = ip1;

		if (!got_nmask)
			Netmask = ip2;
	}

	if (*myname == 0) {
		strcpy(myname, myhostname);
		strupper(myname);
	}

	if (find_name(myname) < 0) {
		int i = add_name();

		if (i < 0)
			return (False);

		strcpy(names[i].name, myname);
		names[i].ip = myip;
		names[i].ttl = 0;
		names[i].nb_flags = 0;
		names[i].valid = True;
	} else
		Debug(3, "Name %s already exists\n", myname);

	return True;
}

/****************************************************************************
usage on the program
****************************************************************************/
void usage(char *pname)
{
	printf("Usage: %s [-n name] [-B bcast address] [-D] [-p port] [-d "
	       "debuglevel] [-l log basename]\n",
	       pname);
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
	printf("\t-H hosts file        load a netbios hosts file\n");
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
	extern int DEBUGLEVEL;
	extern char *optarg;
	pstring lookup = "";

	while ((opt = getopt(argc, argv, "L:B:N:Rn:d:Dp:hPSH:G:")) != EOF)
		switch (opt) {
		case 'G':
			add_group_name(optarg);
			break;
		case 'H':
			load_hosts_file(optarg);
			break;
		case 'B': {
			unsigned long a = inet_addr(optarg);
			memcpy(&bcast_ip, &a, sizeof(a));
			got_bcast = True;
		} break;
		case 'N': {
			unsigned long a = inet_addr(optarg);
			memcpy(&Netmask, &a, sizeof(a));
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
			dns_serve = True;
			break;
		case 'L':
			strcpy(lookup, optarg);
			break;
		case 'D':
			daemon_mode = True;
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

	/* NOTE: This is the opposite of the smbserver as name packets
	   seem to use the opposite byte order to smb packets */
	NeedSwap = !big_endian();

	if (DEBUGLEVEL > 2) {
		extern FILE *login, *logout;
		login = fopen("nmb.in", "w");
		logout = fopen("nmb.out", "w");
	}

	if (DEBUGLEVEL > 0) {
		dbf = fopen("nmb.debug", "w");
		setbuf(dbf, NULL);
		Debug(1, "%s netbios nameserver version %s started\n",
		      timestring(), VERSION);
		Debug(1, "Copyright Andrew Tridgell 1992,1993,1994\n");
	}

	init_structs();
	check_names();
	dump_names();

	if (daemon_mode) {
		Debug(2, "%s becoming a daemon\n", timestring());
		become_daemon();
	}

	if (open_sockets(daemon_mode, port)) {
		process(lookup);
		close_sockets();
	}
	fclose(dbf);
	return (0);
}

#ifndef _LOADPARM_H
/* This is a dummy lp_keepalive() for the nameserver only */
int lp_keepalive()
{
	return (0);
}
#endif
