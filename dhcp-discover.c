/*
 * dhcp_discover - send out a DHCP discover request and wait for replies
 * Author: Per Hallsmark <per@hallsmark.se>
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <libnet.h>
#include <pcap.h>

/* Our long options table */
#define OPTIONSTR "e:ghi:"
static struct option lot[] = {
	{"ethaddr",   1, NULL, 'e'},
	{"gPXE",      0, NULL, 'g'},
	{"help",      0, NULL, 'h'},
	{"interface", 1, NULL, 'i'},
	{NULL, 0, NULL, 0}
};

static uint32_t dhcp_xid = 0xdeadbeef;
static uint8_t enet_src[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
static char enet_intf[64] = "eth0";

static char ln_errbuf[LIBNET_ERRBUF_SIZE];
static char pc_errbuf[PCAP_ERRBUF_SIZE];

static uint8_t *options = NULL;

/* set this to simulate a gpxe client */
static uint8_t gpxe = 0;

/* DHCP Option Tag list
 * Label is a string
 * id is a one byte id
 * type is 0 for unknown.
 *         1 for strings.
 *         2 for IP/netmasks etc. Also covering lists of them.
 *         3 for byte integer.
 *         4 for dhcp message type.
 *         5 for time in seconds.
 */
static struct {
	char *label;
	uint8_t id;
	uint8_t type;
} dot[] = {
	"PAD             ", 0x00, 0,
	"SUBNETMASK      ", 0x01, 2,
	"TIMEOFFSET      ", 0x02, 0,
	"ROUTER          ", 0x03, 2,
	"TIMESERVER      ", 0x04, 2,
	"NAMESERVER      ", 0x05, 2,
	"DNS             ", 0x06, 2,
	"LOGSERV         ", 0x07, 2,
	"COOKIESERV      ", 0x08, 2,
	"LPRSERV         ", 0x09, 2,
	"IMPSERV         ", 0x0a, 2,
	"RESSERV         ", 0x0b, 2,
	"HOSTNAME        ", 0x0c, 1,
	"BOOTFILESIZE    ", 0x0d, 0,
	"DUMPFILE        ", 0x0e, 1,
	"DOMAINNAME      ", 0x0f, 1,
	"SWAPSERV        ", 0x10, 2,
	"ROOTPATH        ", 0x11, 1,
	"EXTENPATH       ", 0x12, 1,
	"IPFORWARD       ", 0x13, 0,
	"SRCROUTE        ", 0x14, 0,
	"POLICYFILTER    ", 0x15, 0,
	"MAXASMSIZE      ", 0x16, 0,
	"IPTTL           ", 0x17, 0,
	"MTUTIMEOUT      ", 0x18, 0,
	"MTUTABLE        ", 0x19, 0,
	"MTUSIZE         ", 0x1a, 0,
	"LOCALSUBNETS    ", 0x1b, 0,
	"BROADCASTADDR   ", 0x1c, 2,
	"DOMASKDISCOV    ", 0x1d, 0,
	"MASKSUPPLY      ", 0x1e, 0,
	"DOROUTEDISC     ", 0x1f, 0,
	"ROUTERSOLICIT   ", 0x20, 0,
	"STATICROUTE     ", 0x21, 0,
	"TRAILERENCAP    ", 0x22, 0,
	"ARPTIMEOUT      ", 0x23, 0,
	"ETHERENCAP      ", 0x24, 0,
	"TCPTTL          ", 0x25, 0,
	"TCPKEEPALIVE    ", 0x26, 0,
	"TCPALIVEGARBAGE ", 0x27, 0,
	"NISDOMAIN       ", 0x28, 0,
	"NISSERVERS      ", 0x29, 2,
	"NISTIMESERV     ", 0x2a, 2,
	"VENDSPECIFIC    ", 0x2b, 1,
	"NBNS            ", 0x2c, 0,
	"NBDD            ", 0x2d, 0,
	"NBTCPIP         ", 0x2e, 0,
	"NBTCPSCOPE      ", 0x2f, 0,
	"XFONT           ", 0x30, 0,
	"XDISPLAYMGR     ", 0x31, 0,
	"DISCOVERADDR    ", 0x32, 0,
	"LEASETIME       ", 0x33, 5,
	"OPTIONOVERLOAD  ", 0x34, 0,
	"MESSAGETYPE     ", 0x35, 4,
	"SERVIDENT       ", 0x36, 2,
	"PARAMREQUEST    ", 0x37, 0,
	"MESSAGE         ", 0x38, 0,
	"MAXMSGSIZE      ", 0x39, 0,
	"RENEWTIME       ", 0x3a, 5,
	"REBINDTIME      ", 0x3b, 5,
	"CLASSSID        ", 0x3c, 0,
	"CLIENTID        ", 0x3d, 0,
	"NISPLUSDOMAIN   ", 0x40, 0,
	"NISPLUSSERVERS  ", 0x41, 2,
	"MOBILEIPAGENT   ", 0x44, 0,
	"SMTPSERVER      ", 0x45, 2,
	"POP3SERVER      ", 0x46, 2,
	"NNTPSERVER      ", 0x47, 2,
	"WWWSERVER       ", 0x48, 2,
	"FINGERSERVER    ", 0x49, 2,
	"IRCSERVER       ", 0x4a, 2,
	"STSERVER        ", 0x4b, 2,
	"STDASERVER      ", 0x4c, 2,
	"USERCLASSINFO   ", 0x4d, 1,
	"END             ", 0xff, 0,
};

static void help(char *prog)
{
	fprintf(stderr, "Usage: %s <options>\n", prog);
	fprintf(stderr, "where options is amongst:\n");
	fprintf(stderr, "  -e,--ethaddr    set mac address to make dhcp request on, defaults to %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
		enet_src[0], enet_src[1], enet_src[2], enet_src[3], enet_src[4], enet_src[5]);
	fprintf(stderr, "  -g,--gPXE       enables gPXE behaviour\n");
	fprintf(stderr, "  -h,--help       show this little help\n");
	fprintf(stderr, "  -i,--interface  set interface to send dhcp request via, defaults to %s\n", enet_intf);
	exit(1);
}

static libnet_t *setup_libnet(char *intf)
{
	libnet_t *ln = NULL;

	ln = libnet_init(LIBNET_LINK, intf, ln_errbuf);
	if (!ln) {
		fprintf(stderr, "libnet_init() failed: %s", ln_errbuf);
		exit(EXIT_FAILURE);
	}

	return ln;
}

static pcap_t *setup_libpcap(char *intf, char *filter_string)
{
	pcap_t *pc = NULL;
	struct bpf_program filter_code;

	pc = pcap_open_live(intf, 1500, 1, 0, pc_errbuf);
	if (!pc) {
		fprintf(stderr, "pcap_open_live() failed: %s", pc_errbuf);
		exit(EXIT_FAILURE);
	}

	if (filter_string) {
		if (pcap_compile(pc, &filter_code, filter_string, 1, 0) == -1) {
			fprintf(stderr, "pcap_compile() failed: %s", pc_errbuf);
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(pc, &filter_code) == -1) {
			fprintf(stderr, "pcap_setfilter() failed: %s",
				pc_errbuf);
			exit(EXIT_FAILURE);
		}
	}

	return pc;
}

static int dhcp_discovery(libnet_t *ln, uint8_t *enet_src, uint32_t dhcp_xid)
{
	uint32_t options_len = 0;
	uint32_t options_ofs = 0;
	libnet_ptag_t eth;
	libnet_ptag_t ip;
	libnet_ptag_t udp;
	libnet_ptag_t dhcp;
	uint8_t enet_dst[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	uint8_t options_req[] = {
		LIBNET_DHCP_SUBNETMASK, LIBNET_DHCP_BROADCASTADDR,
		LIBNET_DHCP_ROUTER, LIBNET_DHCP_DOMAINNAME, LIBNET_DHCP_DNS,
		LIBNET_DHCP_HOSTNAME, LIBNET_DHCP_TIMEOFFSET
	};

	/* build DHCP Discovery options packet */
	options_len = 3;
	options = realloc(options, options_len);
	options[options_ofs++] = LIBNET_DHCP_MESSAGETYPE;
	options[options_ofs++] = 1;
	options[options_ofs++] = LIBNET_DHCP_MSGDISCOVER;

	/* we are going to request some parameters */
	options_len += sizeof(options_req) + 2;
	options = realloc(options, options_len);
	options[options_ofs++] = LIBNET_DHCP_PARAMREQUEST;
	options[options_ofs++] = sizeof(options_req);
	memcpy(options + options_ofs, options_req, sizeof(options_req));
	options_ofs += sizeof(options_req);

	/* gpxe client support */
	if (gpxe) {
		options_len += 6;
		options = realloc(options, options_len);
		options[options_ofs++] = 0x4d;
		options[options_ofs++] = 0x4;
		options[options_ofs++] = 'g';
		options[options_ofs++] = 'P';
		options[options_ofs++] = 'X';
		options[options_ofs++] = 'E';
	}

	/* end our options packet */
	options_len += 1;
	options = realloc(options, options_len);
	options[options_ofs++] = LIBNET_DHCP_END;

	if (options_len + LIBNET_DHCPV4_H < LIBNET_BOOTP_MIN_LEN) {
		options_len = LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H;
		options = realloc(options, options_len);
		memset(options + options_ofs, 0, options_len - options_ofs);
	}

	dhcp = libnet_build_dhcpv4(LIBNET_DHCP_REQUEST,
				   1, 6, 0,
				   dhcp_xid,
				   0, 0x8000, 0, 0, 0, 0,
				   enet_src,
				   NULL, NULL,
				   options, options_len,
				   ln, 0);

	udp = libnet_build_udp(68, 67,
			       LIBNET_UDP_H + LIBNET_DHCPV4_H + options_len,
			       0, NULL, 0, ln, 0);

	ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H +
			       LIBNET_DHCPV4_H + options_len,
			       0x10, 0, 0, 16, IPPROTO_UDP, 0, 0,
			       inet_addr("255.255.255.255"),
			       NULL, 0, ln, 0);

	eth = libnet_build_ethernet(enet_dst, enet_src, ETHERTYPE_IP,
				    NULL, 0, ln, 0);

	if (libnet_write(ln) == -1) {
		fprintf(stderr, "libnet_write: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	free(options);

	return 0;
}

static void dump_dhcp_packet(struct libnet_dhcpv4_hdr *dhcp_hdr)
{
	int i, entry;
	char opt_buf[1024];

	printf(" - beginning of dump -\n");
	printf("DHCP operation          : ");
	switch (dhcp_hdr->dhcp_opcode) {
	case LIBNET_DHCP_REQUEST:
		printf("request\n");
		break;
	case LIBNET_DHCP_REPLY:
		printf("reply\n");
		break;
	default:
		printf("unknown code 0x%x\n", dhcp_hdr->dhcp_opcode);
	}
	printf("Hardware type           : ");
	switch (dhcp_hdr->dhcp_htype) {
	case 1:
		printf("ethernet\n");
		break;
	default:
		printf("unknown code 0x%x\n", dhcp_hdr->dhcp_htype);
	}
	printf("Hardware address length : %d bytes\n", dhcp_hdr->dhcp_hlen);
	printf("Hop count               : %d\n", dhcp_hdr->dhcp_hopcount);
	printf("Transaction ID          : 0x%x\n", ntohl(dhcp_hdr->dhcp_xid));
	printf("Number of seconds       : %d\n", ntohs(dhcp_hdr->dhcp_secs));
	printf("Flags                   : 0x%x\n", ntohs(dhcp_hdr->dhcp_flags));
	printf("Client IP               : %s\n",
	       libnet_addr2name4(dhcp_hdr->dhcp_cip, LIBNET_DONT_RESOLVE));
	printf("Your IP                 : %s\n",
	       libnet_addr2name4(dhcp_hdr->dhcp_yip, LIBNET_DONT_RESOLVE));
	printf("Server IP               : %s\n",
	       libnet_addr2name4(dhcp_hdr->dhcp_sip, LIBNET_DONT_RESOLVE));
	printf("Gateway IP              : %s\n",
	       libnet_addr2name4(dhcp_hdr->dhcp_gip, LIBNET_DONT_RESOLVE));
	printf("Client hw addr          : ");
	for (i = 0; i < dhcp_hdr->dhcp_hlen; i++) {
		printf("%2.2x", dhcp_hdr->dhcp_chaddr[i]);
		if (dhcp_hdr->dhcp_hlen != (i + 1))
			printf(":");
	}
	printf("\n");
	printf("Server hostname         : %s\n", dhcp_hdr->dhcp_sname);
	printf("Boot filename           : %s\n", dhcp_hdr->dhcp_file);
	printf("Options\n");
	printf("  Magic header          : 0x%X (%s)\n",
	       ntohl(dhcp_hdr->dhcp_magic),
	       (ntohl(dhcp_hdr->dhcp_magic) == DHCP_MAGIC) ? "OK" : "Corrupt");

	options = (uint8_t *) ((intptr_t)(&(dhcp_hdr->dhcp_magic)) + 4);
	while ((*options != LIBNET_DHCP_END)) {
		/* find option entry in table */
		for (entry=0;
			(dot[entry].id != *options) && (dot[entry].id != 0xff);
			entry++) {
		}
		if (dot[entry].id == 0xff) {
			printf("parsed to end of tag list\n");
			break;
		}

		/* parse option value and print out accordingly */
		switch (dot[entry].type) {
		case 1:
			memset(opt_buf, 0, sizeof(opt_buf));
			strncpy(opt_buf, options + 2, *(options + 1));
			printf("  %16.16s      : %s\n", dot[entry].label,
			       opt_buf);
			break;
		case 2:
			for (i = 0; i < (*(options + 1)); i += 4) {
				printf("  %16.16s      : %s\n",
				       dot[entry].label,
				       libnet_addr2name4(*(uint32_t *)
							 (options + 2 + i),
							 LIBNET_DONT_RESOLVE));
			}
			break;
		case 4:
			printf("  Message type          : ");
			switch (dhcp_hdr->dhcp_opcode) {
			case LIBNET_DHCP_MSGDISCOVER:
				printf("discover\n");
				break;
			case LIBNET_DHCP_MSGOFFER:
				printf("offer\n");
				break;
			case LIBNET_DHCP_MSGREQUEST:
				printf("request\n");
				break;
			case LIBNET_DHCP_MSGDECLINE:
				printf("decline\n");
				break;
			case LIBNET_DHCP_MSGACK:
				printf("ack\n");
				break;
			case LIBNET_DHCP_MSGNACK:
				printf("nack\n");
				break;
			case LIBNET_DHCP_MSGRELEASE:
				printf("release\n");
				break;
			case LIBNET_DHCP_MSGINFORM:
				printf("inform\n");
				break;
			}
			break;
		case 5:
			printf("  %16.16s      : %u seconds\n",
			       dot[entry].label,
			       ntohl(*(uint32_t *) (options + 2)));
			break;
		case 0:
		default:
			printf("  Option 0x%X           : len %d\n",
			       *options, *(options + 1));
		}
		options += *(options + 1) + 2;
	}
	printf(" - end of dump -\n");
}

static int parse_dhcp_replies(pcap_t *pc, int max_timeout, uint32_t dhcp_xid)
{
	struct pcap_pkthdr pc_hdr;
	fd_set read_set;
	int status, pcap_fd, timed_out;
	struct timeval timeout;
	uint8_t *packet;
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ip_hdr;
	struct libnet_udp_hdr *udp_hdr;
	struct libnet_dhcpv4_hdr *dhcp_hdr;

	timeout.tv_sec = max_timeout;
	timeout.tv_usec = 0;
	pcap_fd = pcap_fileno(pc);
	FD_ZERO(&read_set);
	FD_SET(pcap_fd, &read_set);

	for (timed_out = 0; !timed_out;) {
		status = select(pcap_fd + 1, &read_set, 0, 0, &timeout);
		switch (status) {
		case -1:
			fprintf(stderr, "select() %s\n", strerror(errno));
			exit(EXIT_FAILURE);

		case 0:
			timed_out = 1;
			continue;

		default:
			if (FD_ISSET(pcap_fd, &read_set) == 0) {
				timed_out = 1;
				continue;
			}
		}
		packet = (uint8_t *) pcap_next(pc, &pc_hdr);
		if (packet == NULL) {
			continue;
		}
		eth_hdr = (struct libnet_ethernet_hdr *)(packet);
		ip_hdr = (struct libnet_ipv4_hdr *)(packet +
			sizeof(struct libnet_ethernet_hdr));
		udp_hdr = (struct libnet_udp_hdr *)(packet +
			sizeof(struct libnet_ethernet_hdr) +
			sizeof(struct libnet_ipv4_hdr));
		dhcp_hdr = (struct libnet_dhcpv4_hdr *)(packet +
			sizeof(struct libnet_ethernet_hdr) +
			sizeof(struct libnet_ipv4_hdr) +
			sizeof(struct libnet_udp_hdr));

		if (ntohl(dhcp_hdr->dhcp_xid) != dhcp_xid) {
			continue;
		}

		printf("\n");

		dump_dhcp_packet(dhcp_hdr);
	}
}

int main(int argc, char *argv[])
{
	int i, status, opt;

	/* libnet stuff */
	libnet_t *ln = NULL;

	/* libpcap stuff */
	pcap_t *pc = NULL;
	uint8_t filter_string[1024];

	/* TODO: add option parsing that sets enet_src, enet_intf etc */
	while ((opt = getopt_long(argc, argv, OPTIONSTR, lot, NULL)) != -1) {
		switch (opt) {
		case 'e':
			status = sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				&enet_src[0], &enet_src[1], &enet_src[2],
				&enet_src[3], &enet_src[4], &enet_src[5]);
			break;
		case 'g':
			gpxe = 1;
			break;
		case 'h':
			help(argv[0]);
			exit(1);
		case 'i':
			strcpy(enet_intf, optarg);
			break;
		}
	}

	printf("Ethernet hw addr to do discovery on : ");
	for (i = 0; i < 6; i++) {
		printf("%2.2x", enet_src[i]);
		if (i != 5) {
			printf(":");
		}
	}
	printf("\n");

	/* setup libnet */
	ln = setup_libnet(enet_intf);

	/* setup libpcap */
	sprintf(filter_string, "ether host ff:ff:ff:ff:ff:ff or "
		"ether host %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
		enet_src[0], enet_src[1], enet_src[2], enet_src[3],
		enet_src[4], enet_src[5], enet_src[6], enet_src[7]);
	pc = setup_libpcap(enet_intf, filter_string);

	/* send dhcp discovery message */
	status = dhcp_discovery(ln, enet_src, dhcp_xid);

	/* Now that we have sent the dhcp discovery, start probing for
	 * dhcp replies. We do this for 5 sec and print out results as
	 * we find them */
	status = parse_dhcp_replies(pc, 5, dhcp_xid);

	/* all done, pack up and go home */
	libnet_destroy(ln);
	pcap_close(pc);

	exit(0);
}
