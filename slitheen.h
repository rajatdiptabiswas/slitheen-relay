#ifndef _SLITHEEN_H_
#define _SLITHEEN_H_
#include <stdlib.h>
#include <netinet/in.h>
#include <pcap.h>

#define macaddr1 "00:25:90:5a:26:99"
#define macaddr2 "00:25:90:c9:5a:09"

//#define macaddr1 "08:00:27:0e:89:ea"
//#define macaddr2 "08:00:27:0e:89:ea"

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define ETHER_HEADER_LEN  2*ETHER_ADDR_LEN + 2

/* Definitions for parsing packet data */
struct ip_header {
	u_char versionihl;		/* Version >> 4 | IHL & 0x0f */
	u_char dscpecn;		/* DSCP >> 2 | ECN  & 0x03 */
	u_short len;		/* Total Length */
	u_short id;		/* Identification */
	u_short flagsoff;		/* Flags >> 13 | Fragment Offset & 0x1fff */
#define RF 0x8000		/* Reserved; must be zero */
#define DF 0x4000		/* Dont Fragment */
#define MF 0x2000		/* More Fragments */
	u_char ttl;		/* Time To Live */
	u_char proto;		/* Protocol */
	u_short chksum;		/* Header Checksum */
	struct in_addr src, dst; /* Source and Destination addresses */
};
#define IP_HEADER_LEN(ip)		(((ip)->versionihl) & 0x0f)*4

struct tcp_header {
	u_short src_port;	/* source port */
	u_short dst_port;	/* destination port */
	u_int sequence_num;		/* sequence number */
	u_int ack_num;		/* acknowledgement number */
	u_char offset_res_ns;	/*Data offset >> 4 |  res >> 1 | NS 0x01 */
	u_char flags;			/* Flags */
#define FIN 0x01
#define RST 0x04
	u_short win_size;		/* Window size*/
	u_short chksum;		/* Checksum */
	u_short urg;		/* Urgent pointer */
};
#define TCP_HEADER_LEN(tcp)		(((tcp)->offset_res_ns) >> 4)*4

struct tls_header {
	u_char type; /* Content Type */
#define CCS 0x14
#define ALERT   0x15
#define HS  0x16
#define APP 0x17
#define HB  0x18
	u_short version; /* Version */
	u_short len; /* Length */
	u_char msg; /* Message Type */
#define CLIENT_HELLO 0x01
#define FINISHED 0x14
};
#define RECORD_HEADER_LEN 5
#define CLIENT_HELLO_HEADER_LEN 6

struct packet_info {
	const struct ip_header *ip_hdr;
	struct tcp_header *tcp_hdr;
	const struct tls_header *record_hdr;

	uint32_t size_tcp_hdr;
	uint32_t size_ip_hdr;

	uint8_t *app_data;
	uint32_t app_data_len;
};

struct __attribute__((__packed__)) slitheen_header {
	uint64_t counter;
	uint16_t stream_id; /* determines which stream the data is from */
	uint16_t len;
	uint16_t garbage;
	uint16_t zeros;
};

#define SLITHEEN_HEADER_LEN 16

struct __attribute__((__packed__)) record_header {
	u_char type;
#define HS 0x16
	u_short version;
	u_short len;
};
#define RECORD_LEN(rec)		(htons(rec->len))

struct __attribute__((__packed__)) handshake_header {
	u_char type; /*Handshake message type */
	u_char len1;
	u_char len2;
	u_char len3;
};
#define HANDSHAKE_MESSAGE_LEN(hs)		(((hs)->len1) << 16)+(((hs)->len2) << 8)+ ((hs)->len3)
#define HANDSHAKE_HEADER_LEN 4

struct sniff_args {
	char *readdev;
	char *writedev;
	char *filter;
};

void got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);
void *sniff_packets(void *);
void process_packet(struct packet_info *info);
void extract_packet_headers(uint8_t *packet, struct packet_info *info);
struct packet_info *copy_packet_info(struct packet_info *src_info);

#endif /* _SLITHEEN_H_ */
