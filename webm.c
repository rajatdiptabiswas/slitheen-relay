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
            case BEGIN_ELEMENT:
                if(remaining_len < 8){
                    //this will be difficult to parse
                    //TODO: make this easier to deal with
                    printf("PARSE FAIL: too little len remaining\n");
                    return 1;
                }

                //The only elements we care about are:
                //  the segment header (0x18538067), and
                //  the cluster header (0x1f43b675).

                //Parse header:
                uint8_t header_len;
                uint32_t header = variable_header(p, &header_len);

                printf("Received header: %x\n", header);

                if (header == 0x18538067) {
                    // do nothing. Move on to parsing sub-element

                } else if (header == 0x1f43b675) {
                    f->webmstate = MEDIA;

                    //replace with slitheen header
                    p[0] = 0x16; //'SYN'
                    p[1] = 0x73; //'s'
                    p[2] = 0x6c; //'l'
                    p[3] = 0x69; //'i'

                } else {
                    //we want to skip this element
                    f->webmstate = MID_ELEMENT;
                }

                p += header_len;
                remaining_len -= header_len;

                //parse length of header
                uint8_t int_len;
                uint64_t element_len = variable_length(p, &int_len);

                p += int_len;
                remaining_len -= int_len;

                printf("element length: %lu\n", element_len);

                f->remaining_element = element_len;

                break;
            case MID_ELEMENT:
                //The initial sequence of bytes contains everything up to the media
                //segments

                if(f->remaining_element <= remaining_len){
                    //we have the entire element in this packet

                    p += f->remaining_element;
                    remaining_len -= f->remaining_element;

                    f->remaining_element = 0;
                    f->webmstate = BEGIN_ELEMENT;
                } else {
                    //still have more of this element to process

                    p += remaining_len;
                    f->remaining_element -= remaining_len;
                    remaining_len = 0;
                }

                break;
            case MEDIA:
                //We're replacing all of this element

                if(f->remaining_element <= remaining_len){
                    //we have the entire element in this packet

                    p += f->remaining_element;
                    remaining_len -= f->remaining_element;

                    f->remaining_element = 0;
                    f->webmstate = BEGIN_ELEMENT;
                } else {
                    //still have more of this element to process

                    p += remaining_len;
                    f->remaining_element -= remaining_len;
                    remaining_len = 0;
                }

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
