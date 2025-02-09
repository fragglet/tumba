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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../src/byteorder.h"
#include "smb.h"
#include "version.h"

#define SIGNAL_CAST     (void (*)(int))
#define UPDATE_INTERVAL 60

struct network_address {
	struct in_addr ip;
	struct in_addr netmask;
	struct in_addr bcast_ip;
};

extern pstring debugf;
extern int DEBUGLEVEL;

static uint8_t in_buffer[BUFFER_SIZE];

static struct sockaddr_in last_client;

pstring myname = "";
pstring mygroup = "WORKGROUP";
int myttl = 0;

static int server_sock = 0;

/* machine comment */
fstring comment = "";

static struct ifconf get_interfaces(int sock_fd)
{
	struct ifconf ifc;
	int old_len;

	memset(&ifc, 0, sizeof(ifc));
	ifc.ifc_ifcu.ifcu_req = NULL;
	ifc.ifc_len = 0;

	for (;;) {
		old_len = ifc.ifc_len;
		if (ioctl(sock_fd, SIOCGIFCONF, &ifc) < 0) {
			free(ifc.ifc_ifcu.ifcu_req);
			ifc.ifc_ifcu.ifcu_req = NULL;
			ifc.ifc_len = 0;
			return ifc;
		}

		if (ifc.ifc_len < old_len) {
			return ifc;
		}

		/* If the buffer was too small then the result is truncated,
		   and this is not considered an error. The actual size is
		   returned in ifc.ifc_len, so reallocate the buffer large
		   enough to get the full result.

		   Note that since we start with ifc_len = 0, this will always
		   happen at least once. */

		ifc.ifc_len *= 2;
		ifc.ifc_ifcu.ifcu_req =
		    realloc(ifc.ifc_ifcu.ifcu_req, ifc.ifc_len);
	}
}

#define addr(s) (((struct sockaddr_in *) (s))->sin_addr)
/* TODO: We should have a caching version of this function; the list is only
   likely to change infrequently. */
static struct network_address *get_addresses(int sock_fd, int *num_addrs)
{
	struct ifconf ifc = get_interfaces(sock_fd);
	struct network_address *result;
	struct ifreq *req;
	int i;

	if (ifc.ifc_len == 0) {
		free(ifc.ifc_ifcu.ifcu_req);
		return NULL;
	}

	result = calloc(ifc.ifc_len / sizeof(struct ifreq), sizeof(*result));

	*num_addrs = 0;
	for (i = 0; i * sizeof(struct ifreq) < ifc.ifc_len; ++i) {
		req = &ifc.ifc_ifcu.ifcu_req[i];
		if (req->ifr_addr.sa_family != AF_INET) {
			continue;
		}

		result[*num_addrs].ip = addr(&req->ifr_addr);

		/* In a strange API decision, most of struct ifreq's fields
		   are contained in a union, so you can only "see" one field
		   at a time, but you can switch between them using ioctls: */
		if (ioctl(sock_fd, SIOCGIFNETMASK, req) < 0) {
			DEBUG(0, ("Failed getting netmask for %s\n",
			          req->ifr_name));
			continue;
		}
		result[*num_addrs].netmask = addr(&req->ifr_netmask);

		if (ioctl(sock_fd, SIOCGIFBRDADDR, req) < 0) {
			DEBUG(0, ("Failed getting broadcast address for %s\n",
			          req->ifr_name));
			continue;
		}
		result[*num_addrs].bcast_ip = addr(&req->ifr_broadaddr);

		++*num_addrs;
	}

	free(ifc.ifc_ifcu.ifcu_req);
	return result;
}

/* true if two netbios names are equal */
static bool name_equal(char *s1, char *s2)
{
	char *p1, *p2;
	while (*s1 && *s2 && (*s1 != ' ') && (*s2 != ' ')) {
		p1 = s1;
		p2 = s2; /* toupper has side effects as a macro */
		if (toupper(*p1) != toupper(*p2))
			return false;
		s1++;
		s2++;
	}
	return (*s1 == 0 || *s1 == ' ') && (*s2 == 0 || *s2 == ' ');
}

static int read_udp_socket(int fd, uint8_t *buf, int len)
{
	int ret;
	socklen_t src_len = sizeof(last_client);

	ret = recvfrom(fd, buf, len, 0, (struct sockaddr *) &last_client,
	               &src_len);
	if (ret <= 0) {
		DEBUG(2, ("read socket failed. ERRNO=%d\n", errno));
		return 0;
	}

	DEBUG(5, ("read %d bytes\n", ret));

	return ret;
}

static int nmb_len(uint8_t *buf)
{
	int i;
	int ret = 12;
	uint8_t *p = buf;
	int qdcount = RSVAL(buf, 4);
	int ancount = RSVAL(buf, 6);
	int nscount = RSVAL(buf, 8);
	int arcount = RSVAL(buf, 10);

	/* check for insane qdcount values? */
	if (qdcount > 100 || qdcount < 0) {
		DEBUG(6, ("Invalid qdcount? qdcount=%d\n", qdcount));
		return 0;
	}

	for (i = 0; i < qdcount; i++) {
		p = buf + ret;
		ret += name_len((char *) p) + 4;
	}

	for (i = 0; i < (ancount + nscount + arcount); i++) {
		int rdlength;
		p = buf + ret;
		ret += name_len((char *) p) + 8;
		p = buf + ret;
		rdlength = RSVAL(p, 0);
		ret += rdlength + 2;
	}

	return ret;
}

static void close_sockets(void)
{
	close(server_sock);
	server_sock = 0;
}

/* Send a packet back to the client that sent the packet we are processing */
static void send_reply(void *buf, size_t buf_len)
{
	if (sendto(server_sock, buf, buf_len, 0,
	           (struct sockaddr *) &last_client, sizeof(last_client)) < 0) {
		DEBUG(0, ("Error sending reply: %s\n", strerror(errno)));
	}
}

static void reply_reg_request(uint8_t *inbuf, struct network_address *src_iface)
{
	uint8_t outbuf[BUFFER_SIZE];
	int rec_name_trn_id = RSVAL(inbuf, 0);
	char qname[100] = "";
	uint8_t *p = inbuf;
	struct in_addr ip;
	unsigned char nb_flags;

	name_extract((char *) inbuf, 12, qname);

	p += 12;
	p += name_len((char *) p);
	p += 4;
	p += name_len((char *) p);
	p += 4;
	nb_flags = CVAL(p, 6);
	p += 8;
	memcpy(&ip, p, 4);

	DEBUG(2, ("Name registration request for %s (%s) nb_flags=0x%x\n",
	          qname, inet_ntoa(ip), nb_flags));

	/* if it's not my name then don't worry about it */
	if (!name_equal(myname, qname)) {
		DEBUG(3, ("Not my name\n"));
		return;
	}

	/* if it's my name and it's also my IP then don't worry about it */
	if (ip.s_addr == src_iface->ip.s_addr) {
		DEBUG(3, ("Is my IP\n"));
		return;
	}

	DEBUG(0,
	      ("Someones using my name (%s), sending negative reply\n", qname));

	/* Send a NEGATIVE REGISTRATION RESPONSE to protect our name */
	RSSVAL(outbuf, 0, rec_name_trn_id);
	CVAL(outbuf, 2) = (1 << 7) | (0x5 << 3) | 0x5;
	CVAL(outbuf, 3) = (1 << 7) | 0x6;
	RSSVAL(outbuf, 4, 0);
	RSSVAL(outbuf, 6, 1);
	RSSVAL(outbuf, 8, 0);
	RSSVAL(outbuf, 10, 0);
	p = outbuf + 12;
	strcpy((char *) p, (char *) inbuf + 12);
	p += name_len((char *) p);
	RSSVAL(p, 0, 0x20);
	RSSVAL(p, 2, 0x1);
	RSIVAL(p, 4, 0);
	RSSVAL(p, 8, 6);
	CVAL(p, 10) = nb_flags;
	CVAL(p, 11) = 0;
	p += 12;

	memcpy(p, &ip, 4); /* IP address of the name's owner (that's us) */
	p += 4;

	if (ip.s_addr == src_iface->bcast_ip.s_addr) {
		DEBUG(0, ("Not replying to broadcast address\n"));
		return;
	}

	send_reply(outbuf, nmb_len(outbuf));
}

static void reply_name_query(uint8_t *inbuf, struct network_address *src_iface)
{
	uint8_t outbuf[BUFFER_SIZE];
	int rec_name_trn_id = RSVAL(inbuf, 0);
	char qname[100] = "";
	uint8_t *p = inbuf;

	name_extract((char *) inbuf, 12, qname);

	DEBUG(2, ("(%s) querying name (%s)", inet_ntoa(last_client.sin_addr),
	          qname));

	if (!name_equal(qname, myname)) {
		DEBUG(2, ("\n"));
		return;
	}

	/* Send a POSITIVE NAME QUERY RESPONSE */
	RSSVAL(outbuf, 0, rec_name_trn_id);
	CVAL(outbuf, 2) = (1 << 7) | 0x5;
	CVAL(outbuf, 3) = 0;
	RSSVAL(outbuf, 4, 0);
	RSSVAL(outbuf, 6, 1);
	RSSVAL(outbuf, 8, 0);
	RSSVAL(outbuf, 10, 0);
	p = outbuf + 12;
	strcpy((char *) p, (char *) inbuf + 12);
	p += name_len((char *) p);
	RSSVAL(p, 0, 0x20);
	RSSVAL(p, 2, 0x1);
	RSIVAL(p, 4, myttl);
	RSSVAL(p, 8, 6);
	CVAL(p, 10) = 0;  /* flags */
	CVAL(p, 11) = 0;
	p += 12;
	memcpy(p, &src_iface->ip, 4);
	p += 4;

	send_reply(outbuf, nmb_len(outbuf));
}

/* Choose which IP address to return to clients requesting our hostname. This
   may be different, depending on the interface on which it is received. */
static struct network_address *get_iface_addr(struct network_address *addrs,
                                              int num_addrs,
                                              struct in_addr *src)
{
	int i;

	DEBUG(3, ("Finding matching interface for src=%s: ", inet_ntoa(*src)));

	for (i = 0; i < num_addrs; ++i) {
		if ((addrs[i].ip.s_addr & addrs[i].netmask.s_addr) ==
		    (src->s_addr & addrs[i].netmask.s_addr)) {
			DEBUG(3, ("match for %s ", inet_ntoa(addrs[i].ip)));
			DEBUG(3, ("netmask %s\n", inet_ntoa(addrs[i].netmask)));
			return &addrs[i];
		}
	}
	DEBUG(3, ("none found.\n"));

	return NULL;
}

static void construct_reply(uint8_t *inbuf)
{
	int num_addrs = 0;
	struct network_address *addrs = get_addresses(server_sock, &num_addrs);
	struct network_address *src_iface =
	    get_iface_addr(addrs, num_addrs, &last_client.sin_addr);
	int opcode = CVAL(inbuf, 2) >> 3;
	int nm_flags = ((CVAL(inbuf, 2) & 0x7) << 4) + (CVAL(inbuf, 3) >> 4);
	int rcode = CVAL(inbuf, 3) & 0xF;

	/* We don't process packets unless we can match them to a local
	   interface. Note that this does mean we only ever respond to packets
	   from our local network segment, but this is good enough and probably
	   excludes a bunch of potential security issues anyway. */
	if (src_iface == NULL) {
		free(addrs);
		return;
	}

	if (opcode == 0x5 && (nm_flags & ~1) == 0x10 && rcode == 0)
		reply_reg_request(inbuf, src_iface);

	if (opcode == 0 && (nm_flags & ~1) == 0x10 && rcode == 0)
		reply_name_query(inbuf, src_iface);

	free(addrs);
}

/* mangle a name into netbios format */
static int name_mangle(char *in, char *Out)
{
	char *out = Out;
	int len = 2 * strlen(in);
	int pad = 0;

	if (len / 2 < 16)
		pad = 16 - (len / 2);

	*out++ = 2 * (strlen(in) + pad);
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

	*out = 0;
	return name_len(Out);
}

/*
construct and send a host announcement

Note that I don't know what half the numbers mean - I'm just using what I
saw another PC use :-)
*/
static bool announce_host(char *group, struct network_address *addr)
{
	uint8_t outbuf[BUFFER_SIZE];
	struct sockaddr_in send_addr;
	uint8_t *p, *p2;
	uint8_t *gptr;

	DEBUG(2, ("Sending host announcement to %s for group %s\n",
	          inet_ntoa(addr->bcast_ip), group));

	memset(outbuf, 0, 256);

	CVAL(outbuf, 0) = 17;
	CVAL(outbuf, 1) = 2;
	RSSVAL(outbuf, 2, time(NULL) % 10000 + 42);
	memcpy(outbuf + 4, &addr->ip, 4);
	RSSVAL(outbuf, 8, 138);
	RSSVAL(outbuf, 10, 186 + strlen(comment) + 1);
	RSSVAL(outbuf, 12, 0);

	p = outbuf + 14;

	p += name_mangle(myname, (char *) p);
	strcpy((char *) p - 3, "AA");
	gptr = p;
	p += name_mangle(group, (char *) p);
	strcpy((char *) p - 3, "BO");

	/* now setup the smb part */
	p -= 4;
	set_message((char *) p, 17, 50 + strlen(comment) + 1, true);
	CVAL(p, smb_com) = SMBtrans;
	SSVAL(p, smb_vwv1, 32 + strlen(comment) + 1);
	SSVAL(p, smb_vwv11, 32 + strlen(comment) + 1);
	SSVAL(p, smb_vwv12, 86);
	SSVAL(p, smb_vwv13, 3);
	SSVAL(p, smb_vwv14, 1);
	SSVAL(p, smb_vwv15, 1);
	SSVAL(p, smb_vwv16, 2);
	SSVAL(p, smb_vwv17, 1);
	p2 = (uint8_t *) smb_buf((char *) p);
	strcpy((char *) p2, "\\MAILSLOT\\BROWSE");
	p2 = (uint8_t *) skip_string((char *) p2, 1);

	CVAL(p2, 0) = 1;                      /* host announce */
	CVAL(p2, 1) = 5;                      /* update count */
	SIVAL(p2, 2, UPDATE_INTERVAL * 1000); /* update interval, in MS */
	p2 += 6;
	strcpy((char *) p2, myname);
	p2 += 16;
	CVAL(p2, 0) = 0; /* major version (was 1) */
	CVAL(p2, 1) = 0; /* minor version (was 51) */

	/* Server type. */
	SIVAL(p2, 2,
	      SV_TYPE_SERVER | SV_TYPE_SERVER_UNIX | SV_TYPE_TIME_SOURCE);

	CVAL(p2, 6) = 11;
	CVAL(p2, 7) = 3;
	CVAL(p2, 8) = 85;
	CVAL(p2, 9) = 170;
	p2 += 10;
	strcpy((char *) p2, comment);

	p2 = gptr + name_mangle(group, (char *) gptr);
	strcpy((char *) p2 - 3, "BO");

	memset(&send_addr, 0, sizeof(send_addr));
	send_addr.sin_family = AF_INET;
	send_addr.sin_port = htons(138);
	send_addr.sin_addr = addr->bcast_ip;

	return sendto(server_sock, outbuf, 200 + strlen(comment) + 1, 0,
	              (struct sockaddr *) &send_addr, sizeof(send_addr)) >= 0;
}

/* We send a periodic browser protocol announcement; this makes the server
   show up in "Network Neighborhood" and equivalents. */
static void do_browse_hook(void)
{
	int num_addrs = 0, i;
	struct network_address *addrs = get_addresses(server_sock, &num_addrs);

	/* We send to all broadcast addresses (since there may be multiple
	   interfaces we are listening on */
	for (i = 0; i < num_addrs; ++i) {
		announce_host(mygroup, &addrs[i]);
	}

	free(addrs);
}

static void process(void)
{
	time_t timer = 0;

	while (true) {
		fd_set fds;
		int selrtn;
		struct timeval timeout;
		int nread;

		if (!timer || (time(NULL) - timer) > UPDATE_INTERVAL) {
			do_browse_hook();
			timer = time(NULL);
		}

		FD_ZERO(&fds);
		FD_SET(server_sock, &fds);

		timeout.tv_sec = 10;
		timeout.tv_usec = 0;

		do {
			selrtn = select(255, SELECT_CAST & fds, NULL, NULL,
			                &timeout);
		} while (selrtn < 0 && errno == EINTR);

		if (FD_ISSET(server_sock, &fds)) {
			nread = read_udp_socket(server_sock, in_buffer,
			                        BUFFER_SIZE);
			if (nread > 0 && nmb_len(in_buffer) > 0) {
				construct_reply(in_buffer);
			}
		}
	}
}

static bool open_server_sock(struct in_addr bind_addr, int port)
{
	int one = 1;
	struct sockaddr_in bind_addr_in;

	server_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (server_sock == -1) {
		DEBUG(0, ("socket failed\n"));
		return false;
	}

	if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &one,
	               sizeof(one)) == -1) {
		DEBUG(3, ("setsockopt(REUSEADDR) failed - ignored\n"));
	}

	if (setsockopt(server_sock, SOL_SOCKET, SO_BROADCAST, &one,
	               sizeof(one)) == -1) {
		DEBUG(3, ("setsockopt(BROADCAST) failed - ignored\n"));
	}

	bind_addr_in.sin_family = AF_INET;
	bind_addr_in.sin_port = htons(port);
	bind_addr_in.sin_addr = bind_addr;

	if (bind(server_sock, (struct sockaddr *) &bind_addr_in,
	         sizeof(bind_addr_in)) < 0) {
		DEBUG(0, ("bind failed on port %d\n", port));
		close(server_sock);
		return false;
	}

	DEBUG(1,
	      ("bind successful for %s port %d\n", inet_ntoa(bind_addr), port));

	return true;
}

static void init_names(void)
{
	char hostname[HOST_NAME_MAX + 1];
	char *p;
	bool got_hostname;

	got_hostname = gethostname(hostname, sizeof(hostname)) == 0;

	if (strlen(myname) != 0) {
		/* User specified the hostname */
	} else if (!got_hostname) {
		perror("gethostname");
		fprintf(stderr, "Failed to get system hostname; you can "
			"specify it manually with -n hostname\n");
		exit(1);
	} else {
		strlcpy(myname, hostname, sizeof(myname));
		p = strchr(myname, '.');
		if (p != NULL) {
			*p = '\0';
		}
	}

	if (strlen(comment) == 0) {
		if (got_hostname) {
			strlcpy(comment, hostname, sizeof(comment));
			strlcat(comment, " ", sizeof(comment));
		}
		strlcat(comment, "(Tumba " VERSION ")", sizeof(comment));
	}

	strupper(myname);
	strupper(mygroup);

	DEBUG(2, ("Hostname: %s; Workgroup: %s\n", myname, mygroup));
}

static void usage(char *pname)
{
	DEBUG(0, ("Incorrect program usage - is the command line correct?\n"));

	printf("Usage: %s [-n name] [-b address] [-p port] [-d "
	       "debuglevel] [-l log basename]\n",
	       pname);
	printf("Version %s\n", VERSION);
	printf("\t-b addr               address to bind socket "
	       "(default 0.0.0.0)\n");
	printf("\t-p port               listen on the specified port\n");
	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-l log basename.      Basename for log/debug files\n");
	printf("\t-n netbiosname.       the netbios name to advertise for this "
	       "host\n");
	printf("\t-W workgroup          specify workgroup name\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	struct in_addr bind_addr = {INADDR_ANY};
	int port = 137;
	int opt;
	extern FILE *dbf;
	extern char *optarg;

	sprintf(debugf, "%s.nmb.debug", DEBUGFILE);

	while ((opt = getopt(argc, argv, "b:C:n:l:d:p:hSW:")) != EOF)
		switch (opt) {
		case 'b':
			if (!inet_aton(optarg, &bind_addr)) {
				fprintf(stderr,
				        "Failed to parse bind address "
				        "'%s'\n",
				        optarg);
				exit(1);
			}
			break;
		case 'C':
			strcpy(comment, optarg);
			break;
		case 'W':
			strcpy(mygroup, optarg);
			break;
		case 'n':
			strcpy(myname, optarg);
			break;
		case 'l':
			sprintf(debugf, "%s.nmb.debug", optarg);
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

	DEBUG(1, ("%s netbios nameserver version %s started\n", timestring(),
	          VERSION));
	DEBUG(1, ("Copyright Andrew Tridgell 1994\n"));

	init_names();

	if (open_server_sock(bind_addr, port)) {
		process();
		close_sockets();
	}
	if (dbf)
		fclose(dbf);
	return 0;
}
