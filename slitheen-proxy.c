/* slitheen-proxy.c by Cecylia Bocovich */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <openssl/ssl.h>

#include "util.h"
#include "flow.h"
#include "slitheen.h"
#include "relay.h"
#include "crypto.h"
#include "cryptothread.h"

void usage(void){
	printf("Usage: slitheen-proxy [internal network interface] [NAT interface]\n");
}

int main(int argc, char *argv[]){
	pthread_t t1, t2;
	char *filter1 = ecalloc(1, 33);
	char *filter2 = ecalloc(1, 33);

	char *dev1 = NULL; /* Device that leads to the internal network */
	char *dev2 = NULL; /* Device that leads out to the world */

	struct sniff_args outbound;
	struct sniff_args inbound;

	if (argc != 3) { 
		usage();
		return(2);
	}
	dev1 = argv[1];
	dev2 = argv[2];

	snprintf(filter1, 33, "ether src host %s", macaddr1);
	snprintf(filter2, 33, "ether src host %s", macaddr2);

	if(init_tables()){
		exit(1);
	}
	if(init_session_cache()){
		exit(1);
	}
	init_crypto_locks();

	/* Create threads */
	outbound.readdev = dev1;
	outbound.writedev = dev2;
	outbound.filter = filter1;
	inbound.readdev = dev2;
	inbound.writedev = dev1;
	inbound.filter = filter2;
	pthread_create(&t1, NULL, sniff_packets, (void *) &outbound);
	pthread_create(&t2, NULL, sniff_packets, (void *) &inbound);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	pthread_exit(NULL);
	free(filter1);
	free(filter2);

	crypto_locks_cleanup();

	return(0);
}

void *sniff_packets(void *args){
	pcap_t *rd_handle;
	pcap_t *wr_handle;
	char rd_errbuf[BUFSIZ];
	char wr_errbuf[BUFSIZ];
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char *readdev, *writedev, *filter;
	struct sniff_args *arg_st = (struct sniff_args *) args;
	readdev = arg_st->readdev;
	writedev = arg_st->writedev;
	filter = arg_st->filter;

	if (pcap_lookupnet(readdev, &net, &mask, rd_errbuf) == -1){
		fprintf(stderr, "Can't get netmask for device %s\n", readdev);
		exit(2);
	}

	rd_handle = pcap_open_live(readdev, BUFSIZ, 1, 0, rd_errbuf);
	if (rd_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", readdev, rd_errbuf);
	}

	if(pcap_datalink(rd_handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s does not provide Ethernet headers - not supported\n", readdev);
		exit(2);
	}

	if(pcap_compile(rd_handle, &fp, filter, 0 , net) == -1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(rd_handle));
		exit(2);
	}

	if (pcap_setfilter(rd_handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(rd_handle));
		exit(2);
	}

	wr_handle = pcap_open_live(writedev, BUFSIZ, 1, 0, wr_errbuf);
	if (wr_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", writedev, wr_errbuf);
	}
	/*callback function*/
	pcap_loop(rd_handle, -1, got_packet, (unsigned char *) wr_handle);

	/*Sniff a packet*/
	pcap_close(rd_handle);

	return NULL;
}

/**
 * Runs when pcap_loop receives a packet from the specified interface
 * If the received packet is a tcp packet, processes it and then writes it back out
 * to the interface
 *
 */
void got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet){
	pcap_t *handle = (pcap_t *) args;

	struct packet_info *info = emalloc(sizeof(struct packet_info));
	uint8_t *tmp_packet = emalloc(header->len);
	//printf("Allocated %d bytes to %p\n", header->len, tmp_packet);
	memcpy(tmp_packet, packet, header->len);
	extract_packet_headers(tmp_packet, info);

	// Check to make sure it is a TCP packet 
	if((info->ip_hdr == NULL) || (info->tcp_hdr == NULL))
		goto end;

	process_packet(info);

end:
	if((pcap_inject(handle, tmp_packet, header->len)) < 0 ){
		fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
	}
#ifdef DEBUG
	fprintf(stderr, "injected the following packet:\n");
	for(int i=0; i< header->len; i++){
		fprintf(stderr, "%02x ", packet[i]);
	}
	fprintf(stderr, "\n");

	if((info->tcp_hdr != NULL) && (info->ip_hdr != NULL)){
	fprintf(stdout,"Injected packet: %x:%d > %x:%d\n", info->ip_hdr->src.s_addr, ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port));
	fprintf(stdout,"ID number: %u\n", htonl(info->ip_hdr->id));
	fprintf(stdout,"Sequence number: %u\n", htonl(info->tcp_hdr->sequence_num));
	fprintf(stdout,"Acknowledgement number: %u\n", htonl(info->tcp_hdr->ack_num));
	fflush(stdout);
	}
#endif
	free(info);//Note: don't free this while a thread is using it
	free(tmp_packet);

}

/* This function receives a full ip packet and then:
 * 	1) identifies the flow
 * 	2) adds the packet to the flow's data chain
 * 	3) updates the flow's state
 */
void process_packet(struct packet_info *info){


	/* Checks to see if this is a possibly tagged hello msg */
	if ((info->record_hdr != NULL) && (info->record_hdr->type == HS)){ /* This is a TLS handshake */
		check_handshake(info);
	}

	/* Now if flow is in table, update state */
	flow *observed;
	if((observed = check_flow(info)) != NULL){
	
		if(observed->application){
			replace_packet(observed, info);
		} else {

			/* Pass data to packet chain */
			add_packet(observed, info);
		}

		/* Update TCP state */
		if(info->tcp_hdr->flags & (FIN | RST) ){
			/* Remove flow from table, connection ended */
			remove_flow(observed);
		}

	}

}

/** This function extracts the ip, tcp, and tls record headers
 * 	from a received packet (if they exist), and put them in 
 * 	a packet_info struct
 * 	
 */
void extract_packet_headers(uint8_t *packet, struct packet_info *info){

	/* First fill in IP header */
	uint8_t *p = packet;
	p += ETHER_HEADER_LEN; //skip ethernet header
	info->ip_hdr = (struct ip_header*) p;
	info->size_ip_hdr = IP_HEADER_LEN(info->ip_hdr);
	
	/* Verify this is an IP packet */
	if( (info->ip_hdr->versionihl >>4) != 4){
		info->ip_hdr = NULL;
		info->size_ip_hdr = 0;
		info->tcp_hdr = NULL;
		info->size_tcp_hdr = 0;
		info->record_hdr = NULL;
		return;
	}

	/* If this is a TCP segment, fill in TCP header */
	if (info->ip_hdr->proto == IPPROTO_TCP){
		p += info->size_ip_hdr;	//skip IP header

		info->tcp_hdr = (struct tcp_header*) p;
		info->size_tcp_hdr = TCP_HEADER_LEN(info->tcp_hdr);
		p += info->size_tcp_hdr;
	} else {
		info->tcp_hdr = NULL;
		info->size_tcp_hdr = 0;
		info->record_hdr = NULL;
		return;
	}


	/* If the application data contains a TLS record, fill in hdr */
	info->app_data_len = htons(info->ip_hdr->len) - (info->size_ip_hdr + info->size_tcp_hdr);
	if(info->app_data_len > 0){
		info->app_data = p;
		info->record_hdr = (struct tls_header*) p;
		
		//check to see if this is a valid record
		if((info->record_hdr->type < 0x14) || (info->record_hdr->type > 0x18)){
			info->record_hdr = NULL;
		}

	} else {
		info->record_hdr = NULL;
		info->app_data = NULL;
	}

	return;

}

/** Copies a packet_info structure and returns a pointer to the duplicate.
 */
struct packet_info *copy_packet_info(struct packet_info *src_info){
	struct packet_info *dst_info = emalloc(sizeof(struct packet_info));

	dst_info->ip_hdr = src_info->ip_hdr;
	dst_info->tcp_hdr = src_info->tcp_hdr;

	dst_info->size_tcp_hdr = src_info->size_tcp_hdr;
	dst_info->size_ip_hdr = src_info->size_ip_hdr;

	dst_info->app_data = src_info->app_data;
	dst_info->app_data_len = src_info->app_data_len;

	return dst_info;
}


