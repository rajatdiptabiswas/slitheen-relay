/* Name: http.c
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
#include <string.h>
#include <openssl/rand.h>

#include "http.h"
#include "flow.h"
#include "relay.h"
#include "crypto.h"
#include "util.h"
#include "webm.h"

static int32_t parse_http_header(flow *f, uint8_t *data, uint32_t length);
static void reset_resource(flow *f);

/** Processes an incoming record by extracting or changing information, 
 * and updates the HTTP state of the provided flow.
 *
 * Inputs:
 *      f: the flow corresponding to the received data
 *      record: a pointer to the application data of the decrypted packet that needs
 *              to be processed
 *      length: the length of the data to be processed
 */
int32_t parse_http(flow *f, uint8_t *ptr, uint32_t length){

    char *needle;

    DEBUG_MSG(DEBUG_DOWN, "Current state (flow %p): %x\n", f, f->http_state);
    DEBUG_MSG(DEBUG_DOWN, "Remaining record len: %d\n", length);

    uint8_t *p = ptr;
    uint32_t remaining_length = length;

    while(remaining_length > 0){
        switch(f->http_state){

            case PARSE_HEADER:
                {
                    int32_t header_len = parse_http_header(f, p, remaining_length);
                    if (header_len < 0) {//something went wrong, forfeit flow
                        remaining_length = 0;
                    } else {
                        p += header_len;
                        remaining_length -= header_len;
                    }
                    break;
                }

            case MID_CONTENT:
                //check if content is replaceable
                if(f->remaining_response_len > remaining_length){
                    if (f->content_type == WEBM) {
                        parse_webm(f, p, remaining_length);
                        if(f->remaining_response_len - remaining_length == 0){
                            fprintf(stderr, "quitting\n");
                        }
                    }

                    if(f->content_type == IMAGE){
                        fill_with_downstream(f, p, remaining_length);

                        DEBUG_MSG(DEBUG_DOWN, "Replaced leaf with:\n");
                        DEBUG_BYTES(DEBUG_DOWN, p, remaining_length);
                    }

                    f->remaining_response_len -= remaining_length;
                    p += remaining_length;

                    remaining_length = 0;
                } else {
                    if (f->content_type == WEBM) {
                        parse_webm(f, p, f->remaining_response_len);
                    }

                    if(f->content_type == IMAGE){
                        fill_with_downstream(f, p, remaining_length);

                        DEBUG_MSG(DEBUG_DOWN, "ERR: Replaced leaf with:\n");
                        DEBUG_BYTES(DEBUG_DOWN, p, remaining_length);
                    }
                    remaining_length -= f->remaining_response_len;
                    p += f->remaining_response_len;

                    DEBUG_MSG(DEBUG_DOWN, "Change state %x --> PARSE_HEADER (%p)\n", f->http_state, f);
                    f->http_state = PARSE_HEADER;
                    f->remaining_response_len = 0;
                }
                break;

            case BEGIN_CHUNK:
                {
                    int32_t chunk_size = strtol((const char *) p, NULL, 16);
                    DEBUG_MSG(DEBUG_DOWN, "BEGIN_CHUNK: chunk size is %d\n", chunk_size);
                    if(chunk_size == 0){
                        f->http_state = END_BODY;
                    } else {
                        f->http_state = MID_CHUNK;
                    }
                    f->remaining_response_len = chunk_size;
                    needle = strstr((const char *) p, "\r\n");
                    if(needle != NULL){
                        remaining_length -= ((uint8_t *) needle - p + 2);
                        p = (uint8_t *) needle + 2;
                    } else {
                        remaining_length = 0;
                        DEBUG_MSG(DEBUG_DOWN, "Error parsing in BEGIN_CHUNK, FORFEIT (%p)\n", f);
                        f->http_state = FORFEIT_REST;
                    }
                }
                break;

            case MID_CHUNK:
                if(f->remaining_response_len > remaining_length){
                    if (f->content_type == WEBM) {
                        parse_webm(f, p, remaining_length);
                        if(f->remaining_response_len - remaining_length == 0){
                            fprintf(stderr, "quitting\n");
                        }
                    }

                    if(f->content_type == IMAGE){
                        fill_with_downstream(f, p, remaining_length);

                        DEBUG_MSG(DEBUG_DOWN, "Replaced leaf with:\n");
                        DEBUG_BYTES(DEBUG_DOWN, p, remaining_length);
                    }
                    f->remaining_response_len -= remaining_length;
                    p += remaining_length;

                    remaining_length = 0;
                } else {
                    if(f->content_type == IMAGE){
                        fill_with_downstream(f, p, f->remaining_response_len);

                        DEBUG_MSG(DEBUG_DOWN, "Replaced leaf with:\n");
                        DEBUG_BYTES(DEBUG_DOWN, p, f->remaining_response_len);
                    }
                    remaining_length -= f->remaining_response_len;
                    p += f->remaining_response_len;
                    f->remaining_response_len = 0;
                    f->http_state = END_CHUNK;
                }
                break;

            case END_CHUNK:
                needle = strstr((const char *) p, "\r\n");
                if(needle != NULL){
                    f->http_state = BEGIN_CHUNK;
                    p += 2;
                    remaining_length -= 2;
                } else {
                    remaining_length = 0;
                    printf("Couldn't find end of chunk, sending to FORFEIT_REST (%p)\n", f);
                    f->http_state = FORFEIT_REST;
                }
                break;

            case END_BODY:
                needle = strstr((const char *) p, "\r\n");
                if(needle != NULL){
                    printf("Change state %x --> PARSE_HEADER (%p)\n", f->http_state, f);
                    f->http_state = PARSE_HEADER;
                    p += 2;
                    remaining_length -= 2;
                } else {
                    remaining_length = 0;
                    printf("Couldn't find end of body, sending to FORFEIT_REST (%p)\n", f);
                    f->http_state = FORFEIT_REST;
                }
                break;

            case FORFEIT_REST:

            case USE_REST:
                remaining_length = 0;
                break;

            default:
                break;

        }
    }
    return 1;
}

/** Parses the header of an HTTP resource and updates flow
 *
 */
static int32_t parse_http_header(flow *f, uint8_t *data, uint32_t length) {

    uint8_t *p = data;
    char *len_ptr;
    int32_t header_len = 0;

    /* Find and possibly replace content type */
    len_ptr = strstr((const char *) p, "Content-Type: ");
    if (len_ptr != NULL) { //check to see if content type is replaceable

        if (memcmp(len_ptr + sizeof("Content-Type: ") -1, "image", sizeof("image") -1) == 0) {

            f->content_type = IMAGE;
            printf("found image!\n");
            memcpy(len_ptr + 14, "sli/theen", 9);

            char *c = len_ptr + 14+9; //fill out remaining content type with whitespace
            while(c[0] != '\r'){
                c[0] = ' ';
                c++;
            }

            DEBUG_MSG(DEBUG_DOWN, "Found and replaced leaf header\n");

        } else if ( (memcmp(len_ptr + sizeof("Content-Type: ") -1,
                        "video/webm", sizeof("video/webm") -1) == 0) ||
                (memcmp(len_ptr + sizeof("Content-Type: ") -1,
                        "audio/webm", sizeof("audio/webm") -1) == 0)){

            printf("found webm!\n");
            f->content_type = WEBM; //Note: this is zero even though we're replacing it
            f->webmstate = WEBM_HEADER;

            /* Note: we only replace the content type for images, video and audo
             * resources and handled differently in the mozilla browser code
             */

        } else { //we haven't found a replaceable content type
            printf("Can't replace %.10s\n", len_ptr+ sizeof("Content-Type: ") -1);
            f->content_type = NOREPLACE;
        }
    }

    /* Check status code */
    //TODO: more cases for more status codes
    len_ptr = strstr((const char *) p, "304 Not Modified");
    if(len_ptr != NULL){
        //no message body, look for terminating string
        len_ptr = strstr((const char *) p, "\r\n\r\n");
        if(len_ptr != NULL){
            reset_resource(f);
            header_len = (((uint8_t *)len_ptr - p) + 4);
            p = (uint8_t *) len_ptr + 4;

            DEBUG_MSG(DEBUG_DOWN, "Found a 304 not modified, waiting for next header\n");
        } else {
            DEBUG_MSG(DEBUG_DOWN, "Missing end of header. Sending to FORFEIT_REST (%p)\n", f);
            f->http_state = FORFEIT_REST;
            header_len = -1;
        }
        return header_len;
    }

    //check for 200 OK message
    len_ptr = strstr((const char *) p, "200 OK");
    if(len_ptr == NULL){
        f->content_type = NOREPLACE;
    }

    /* Look for length and encoding of resources */
    len_ptr = strstr((const char *) p, "Transfer-Encoding");
    if(len_ptr != NULL){
        printf("Transfer encoding\n");
        if(!memcmp(len_ptr + 19, "chunked", 7)){
            printf("Chunked\n");
            f->http_state_next = BEGIN_CHUNK;

        } else {// other encodings not yet implemented
            f->http_state_next = FORFEIT_REST;
        }
    } else {
        len_ptr = strstr((const char *) p, "Content-Length:");
        if(len_ptr != NULL){
            len_ptr += 15;
            f->remaining_response_len =
                strtol((const char *) len_ptr, NULL, 10);

            DEBUG_MSG(DEBUG_DOWN, "content-length: %d\n",
                    f->remaining_response_len);

            f->http_state_next = MID_CONTENT;
        }
    }

    /* Look for the end of the header */
    len_ptr = strstr((const char *) p, "\r\n\r\n");
    if(len_ptr != NULL){
        f->http_state = f->http_state_next;

        if (f->http_state == PARSE_HEADER) {
            printf("Reached end of header without a transfer encoding or content length\n");
            f->http_state = FORFEIT_REST;
        }

        header_len = (((uint8_t *)len_ptr - p) + 4);
        p = (uint8_t *) len_ptr + 4;
        printf("End of header. Next state is %x\n", f->http_state);

    } else {
        printf("header doesn't end in this packet\n");
        header_len = length;
    }

    return header_len;
}

static void reset_resource(flow *f){
    f->http_state = PARSE_HEADER;
    f->http_state_next = PARSE_HEADER;
    f->content_type = UNKNOWN;
    f->webmstate = 0;
}

/** Fills a given pointer with downstream data of the specified length. If no downstream data
 *  exists, pads it with garbage bytes. All downstream data is accompanied by a stream id and
 *  lengths of both the downstream data and garbage data
 *
 *  Inputs:
 *  	data: a pointer to where the downstream data should be entered
 *  	length: The length of the downstream data required
 *
 */
int fill_with_downstream(flow *f, uint8_t *data, int32_t length){

    uint8_t *p = data;
    int32_t remaining = length;
    struct slitheen_header *sl_hdr;

    data_queue *downstream_queue = f->downstream_queue;
    client *client_ptr = f->client_ptr;
/*
    FILE *fp;
    fp = fopen("replaced_data.out", "a");
    fprintf(fp, "%d\n", length);
    fclose(fp);
*/
    if(client_ptr == NULL){
        //printf("ERROR: no client\n");
        return 1;
    }


    //Fill as much as we can from the censored_queue
    //Note: need enough for the header and one block of data (16 byte IV, 16 byte
    //		block, 16 byte MAC) = header_len + 48.
    while((remaining > (SLITHEEN_HEADER_LEN + 64)) && downstream_queue != NULL && downstream_queue->first_block != NULL){

        //amount of data we'll actualy fill with (16 byte IV and 16 byte MAC)
        int32_t fill_amount = remaining - SLITHEEN_HEADER_LEN - 32;
        fill_amount -= fill_amount % 16; //rounded down to nearest block size

        sem_wait(&client_ptr->queue_lock);

        queue_block *first_block = downstream_queue->first_block;
        int32_t block_length = first_block->len;
        int32_t offset = first_block->offset;

        uint8_t *encrypted_data = p;
        sl_hdr = (struct slitheen_header *) p;
        sl_hdr->counter = ++(client_ptr->encryption_counter);
        sl_hdr->stream_id = first_block->stream_id;
        sl_hdr->len = 0x0000;
        sl_hdr->garbage = 0x0000;
        sl_hdr->zeros = 0x0000;
        p += SLITHEEN_HEADER_LEN;
        remaining -= SLITHEEN_HEADER_LEN;

        p += 16; //iv length
        remaining -= 16;


        if(block_length > offset + fill_amount){
            //use part of the block, update offset
            memcpy(p, first_block->data+offset, fill_amount);

            first_block->offset += fill_amount;
            p += fill_amount;
            sl_hdr->len = fill_amount;
            remaining -= fill_amount;

        } else {
            //use all of the block and free it
            memcpy(p, first_block->data+offset, block_length - offset);

            free(first_block->data);
            downstream_queue->first_block = first_block->next;
            free(first_block);

            p += (block_length - offset);
            sl_hdr->len = (block_length - offset);
            remaining -= (block_length - offset);
        }

        sem_post(&client_ptr->queue_lock);

        //pad to 16 bytes if necessary
        uint8_t padding = 0;
        if(sl_hdr->len %16){
            padding = 16 - (sl_hdr->len)%16;
            memset(p, padding, padding);
            remaining -= padding;
            p += padding;
        }

        p += 16;
        remaining -= 16;

        //fill rest of packet with padding, if needed
        //TODO: we can optimize this a bit, for now fixing 16 byte decryption problem
        if((remaining < SLITHEEN_HEADER_LEN) || (sl_hdr->len < 16)){
            RAND_bytes(p, remaining);
            sl_hdr->garbage = htons(remaining);
            p += remaining;
            remaining -= remaining;
        }

        int16_t data_len = sl_hdr->len;
        sl_hdr->len = htons(sl_hdr->len);

        //now encrypt
        super_encrypt(client_ptr, encrypted_data, data_len + padding);


        DEBUG_MSG(DEBUG_DOWN, "DWNSTRM: slitheen header: ");
        DEBUG_BYTES(DEBUG_DOWN, ((uint8_t *) sl_hdr), SLITHEEN_HEADER_LEN);
        DEBUG_MSG(DEBUG_DOWN, "Sending %d downstream bytes:", data_len);
        DEBUG_BYTES(DEBUG_DOWN, (((uint8_t *) sl_hdr) + SLITHEEN_HEADER_LEN), data_len+16+16);
    }
    //now, if we need more data, fill with garbage
    if(remaining >= SLITHEEN_HEADER_LEN ){

        sl_hdr = (struct slitheen_header *) p;
        sl_hdr->counter = 0x00;
        sl_hdr->stream_id = 0x00;
        remaining -= SLITHEEN_HEADER_LEN;
        sl_hdr->len = 0x00;
        sl_hdr->garbage = htons(remaining);
        sl_hdr->zeros = 0x0000;

        DEBUG_MSG(DEBUG_DOWN, "DWNSTRM: slitheen header: ");
        DEBUG_BYTES(DEBUG_DOWN, p, SLITHEEN_HEADER_LEN);

        //encrypt slitheen header
        super_encrypt(client_ptr, p, 0);

        p += SLITHEEN_HEADER_LEN;
        RAND_bytes(p, remaining);
    } else if(remaining > 0){
        //fill with random data
        RAND_bytes(p, remaining);
    }

    return 0;
}
