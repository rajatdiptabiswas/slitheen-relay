/* Name: webm.c
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

#include "webm.h"
#include "flow.h"
#include "relay.h"

static uint64_t variable_length(uint8_t *p, uint8_t *int_length);
static uint32_t variable_header(uint8_t *p, uint8_t *int_length);

/**
 * Parses the webm content type
 *
 * Returns 0 on success 1 on failure
 */
int32_t parse_webm(flow *f, uint8_t *ptr, uint32_t len) {

    if(!f->webmstate){
        //make sure this is a webm resource
        return 1;
    }

    uint8_t *p = ptr;
    uint32_t remaining_len = len;

    while (remaining_len){
        switch (f->webmstate){
            uint8_t header_len, int_len;
            case WEBM_HEADER:
                if(remaining_len < 8){
                    //TODO:right now this assumes we'll have the header + size
                    // but later we should make it work with just the header
                    // also the size should be 8 bytes max
                    //this will be difficult to parse
                    printf("PARSE FAIL: too little len remaining\n");
                    return 1;
                }

                //Parse header:
                f->element_header = variable_header(p, &header_len);

                printf("Received header: %x | %lx \n", f->element_header, (long) *(p+header_len));

                if((f->element_header == 0xa3) &&
                        (remaining_len >= (SLITHEEN_HEADER_LEN + 9))){
                    //we want to replace this block
                    printf("Replaced simple block!\n");
                    p[0] = 0xef;
                }

                p += header_len;
                remaining_len -= header_len;

                //parse length of header
                f->remaining_element = variable_length(p, &int_len);

                p += int_len;
                remaining_len -= int_len;

                printf("element length: %lu\n", f->remaining_element);

                f->webmstate = PARSE_ELEMENT;

                break;
            case PARSE_ELEMENT:

                switch(f->element_header) {

                    case  0x18538067: //segment
                    case 0x1f43b675: //cluster
                    // do nothing. Move on to parsing sub-element
                    f->webmstate = WEBM_HEADER;

                    break;
                    case 0xa3: //simple block

                    f->webmstate = BLOCK_HEADER;

                    break;
                    default:
                    //we want to skip this element
                    f->webmstate = MID_ELEMENT;
                    break;

                }
                break;
            case MID_ELEMENT: {

                uint32_t parse_len = (f->remaining_element <= remaining_len) ?
                    f->remaining_element : remaining_len;

                if (f->element_header == 0xa3) {
                    //replace content

                    fill_with_downstream(f, p, parse_len);

/*
                    printf("Replaced data (%d bytes):\n", parse_len);
                    for(int i=0; i< parse_len; i++){
                        printf("%02x ", p[i]);
                    }
                    printf("\n");
*/
                }

                p += parse_len;
                remaining_len -= parse_len;
                f->remaining_element -= parse_len;

                if (f->remaining_element == 0) {
                    f->webmstate = WEBM_HEADER;
                }
                break;
            }
            case BLOCK_HEADER:
                //TODO: expand to handle lacing, non-simple blocks
                if(remaining_len < 4){
                    //TODO: fix this somehow
                    printf("PARSE FAIL: too little len remaining\n");
                    return 1;
                }

                p += 4;
                f->remaining_element -= 4;
                remaining_len -= 4;

                f->webmstate = MID_ELEMENT;

                break;
        }
    }

    printf("Remaining element: %lu\n", f->remaining_element);

    return 0;
}

static uint64_t variable_length(uint8_t *p, uint8_t *int_length){

    //first check for length of int
    uint8_t count = 1;
    uint32_t mask = 1 << 7;

    uint64_t len;

    while (count < 8) {
        if ((p[0] & mask) != 0) {
            break;
        }

        mask >>= 1;
        count += 1;
    }

    *int_length = count;

    //now calculate the integer
    len = p[0] & ~mask;

    for(int i=1; i< count; i++){
        len <<= 8;
        len |= p[i];
    }

    return len;
}

static uint32_t variable_header(uint8_t *p, uint8_t *int_length){

    //first check for length of int
    uint8_t count = 1;
    uint32_t mask = 1 << 7;

    uint32_t len;

    while (count < 4) {
        if ((p[0] & mask) != 0) {
            break;
        }

        mask >>= 1;
        count += 1;
    }

    *int_length = count;

    //now calculate the integer
    len = p[0];

    for(int i=1; i< count; i++){
        len <<= 8;
        len |= p[i];
    }

    return len;
}
