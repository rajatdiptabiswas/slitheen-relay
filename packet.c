/* Name: packet.c 
 *
 * Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2017 Cecylia Bocovich (cbocovic@uwaterloo.ca)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 * 
 * If you modify this Program, or any covered work, by linking or combining
 * it with the OpenSSL library (or a modified version of that library), 
 * containing parts covered by the terms of the OpenSSL Licence and the
 * SSLeay license, the licensors of this Program grant you additional
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of the OpenSSL library used as well as that of the covered
 * work.
 */

#include <pcap.h>
#include "packet.h"
#include "util.h"

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


/*
 * Injects a packet back out the opposite interface
 */
void inject_packet(struct inject_args *iargs, const struct pcap_pkthdr *header, uint8_t *packet){
    pcap_t *handle = iargs->write_dev;

    //write back out to the MAC ADDR it came in on
    //memmove(packet, packet+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    //memcpy(packet+ETHER_ADDR_LEN, iargs->mac_addr, ETHER_ADDR_LEN);

    if((pcap_inject(handle, packet, header->len)) < 0 ){
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
        printf("Length: %d\n", header->len);
    }

#ifdef DEBUG_EXTRA
    fprintf(stderr, "injected the following packet:\n");
    for(int i=0; i< header->len; i++){
        fprintf(stderr, "%02x ", packet[i]);
    }
    fprintf(stderr, "\n");

#endif
    free(packet);
}
