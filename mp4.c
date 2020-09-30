/* Name: mp4.c
 *
 * This file contains functions for manipulating tagged flows.
 *
 * Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2018 Cecylia Bocovich (cbocovic@uwaterloo.ca)
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

#include <stdio.h>
#include <stdint.h>

#include "flow.h"
#include "mp4.h"

int32_t parse_mp4(flow *f, uint8_t *ptr, uint32_t len) {
    printf("in parse_mp4\n");

    uint8_t *p = ptr;
    int32_t remaining_len = len;

    uint32_t response_len = f->remaining_response_len;

    while (remaining_len) {
        switch (f->mp4_state) {
            case BOX_HEADER:
                if (remaining_len < 8) {
                    //TODO:right now this assumes we'll have the header + size
                    // but later we should make it work with just the header
                    printf("PARSE FAIL: too little len remaining\n");
                    return 1;
                }

                printf("box header:\n");
                for(int i = 0; i< 8; i++){
                    printf("%0x ", p[i]);
                }
                printf("| ");
                for(int i = 0; i< 20; i++){
                    printf("%0x ", p[i+8]);
                }
                printf("\n");

                struct mp4_box_hdr *header = (struct mp4_box_hdr *) p;
                uint64_t *largesize;

                uint16_t header_len = sizeof(struct mp4_box_hdr);
                p += sizeof(struct mp4_box_hdr);

                header->size = ntohl(header->size);

                if (header->size == 1) {
                    largesize = (uint64_t *) p;

                    p += sizeof(uint64_t);
                    header_len += sizeof(uint64_t);
                    
                    f->mp4_box_size = *largesize;

                } else if (header->size == 0) {
                    f->mp4_box_size = response_len;
                } else {
                    f->mp4_box_size = header->size;
                }
                
                if (header->type == 0x64697575) { // == 'uuid'
                    p += sizeof(uint8_t) * 16;
                    header_len += sizeof(uint8_t) * 16;
                } //Note: we don't actually care about extensions

                if (header->type == htonl(0x6d646174)) { // == 'mdat'
                    printf("replaced mdat box!\n");
                    //header->type = htonl(0x736c6966); // make the box type 'slif'
                }


                f->mp4_box_type = ntohl(header->type);
                printf("MP4 box type: %x\n", header->type);
                printf("MP4 box size: %d\n", header->size);

                remaining_len -= header_len;
                f->mp4_box_size -= header_len;

                f->mp4_state = PARSE_BOX;
                break;

            case PARSE_BOX: {
                uint32_t parse_len = (f->mp4_box_size <= remaining_len) ? 
                    f->mp4_box_size : remaining_len;

                switch (f->mp4_box_type) {
                    case 0x6d646174: //mdat

                        for (int i=0; i< parse_len; i++){
                            printf("%02x ", p[i]);
                        }
                        printf("\n");

                    default:
                        
                        p += parse_len;
                        remaining_len -= parse_len;
                        f->mp4_box_size -= parse_len;

                        if (f->mp4_box_size == 0) {
                            f->mp4_state = BOX_HEADER;
                        }
                        break;
                }
                break;
                            }

            default:
                printf("Ooops (mp4)\n");


        }

        printf("remaining length: %d\n", remaining_len);
    }

    return 0;

}
