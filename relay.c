/* Name: relay.c
 *
 * This file contains code that the relay station runs once the TLS handshake for
 * a tagged flow has been completed.
 *
 * These functions will extract covert data from the header
 * of HTTP GET requests and insert downstream data into leaf resources
 *
 * It is also responsible for keeping track of the HTTP state of the flow
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "relay.h"
#include "packet.h"
#include "flow.h"
#include "crypto.h"
#include "util.h"
#include "http.h"

/* Data structures */
struct proxy_thread_data {
    uint8_t *initial_data;
    uint16_t initial_len;
    uint16_t stream_id;
    int32_t pipefd;
    stream_table *streams;
    data_queue *downstream_queue;
    client *client;
};

struct socks_req {
    uint8_t version;
    uint8_t cmd;
    uint8_t rsvd;
    uint8_t addr_type;
};

struct __attribute__((__packed__)) sl_up_hdr {
    uint16_t stream_id;
    uint16_t len;
};

typedef struct stream_st {
    uint16_t stream_id;
    int32_t pipefd;
    struct stream_st *next;
} stream;

typedef struct stream_table_st {
    stream *first;
} stream_table;

static int process_downstream(flow *f, int32_t offset, struct packet_info *info);
static int read_header(flow *f, struct packet_info *info);
static void *proxy_covert_site(void *data);

/** Called when a TLS application record is received for a
 *  tagged flow. Upstream packets will be checked for covert
 *  requests to censored sites, downstream packets will be
 *  replaced with data from the censored queue or with garbage
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	info: the processed received application packet
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int replace_packet(flow *f, struct packet_info *info){

    if (info == NULL || info->tcp_hdr == NULL){
        return 0;
    }

    DEBUG_MSG(DEBUG_PROXY, "Flow %p: %x:%d > %x:%d (%s)\n", f, info->ip_hdr->src.s_addr, ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port), (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? "incoming":"outgoing");
    DEBUG_MSG(DEBUG_PROXY, "ID number: %u\n", htonl(info->ip_hdr->id));
    DEBUG_MSG(DEBUG_PROXY, "Sequence number: %u\n", htonl(info->tcp_hdr->sequence_num));
    DEBUG_MSG(DEBUG_PROXY, "Acknowledgement number: %u\n", htonl(info->tcp_hdr->ack_num));

    if(info->app_data_len <= 0){
        return 0;
    }

    /* if outgoing, decrypt and look at header */
    if(info->ip_hdr->src.s_addr == f->src_ip.s_addr){
        read_header(f, info);
        return 0;
    } else {

        DEBUG_MSG(DEBUG_FLOW, "Current sequence number: %d\n", f->downstream_seq_num);
        DEBUG_MSG(DEBUG_FLOW, "Received sequence number: %d\n", htonl(info->tcp_hdr->sequence_num));

        uint32_t offset = htonl(info->tcp_hdr->sequence_num) - f->downstream_seq_num;
        if(offset == 0)
		f->downstream_seq_num += info->app_data_len;

	/* if incoming, replace with data from queue */
	if(process_downstream(f, offset, info)){
		return 1;
	}

    }
    return 0;

}

/** Reads the HTTP header of upstream data and searches for
 *  a covert request in an x-slitheen header. Sends this
 *  request to the indicated site and saves the response to
 *  the censored queue
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	info: the processed received packet
 *
 *  Ouput:
 *  	0 on success, 1 on failure
 */
static int read_header(flow *f, struct packet_info *info){
    uint8_t *p = info->app_data;

    if (info->tcp_hdr == NULL){
        return 0;
    }

    uint8_t *record_ptr = NULL;
    struct record_header *record_hdr;
    uint32_t record_length;
    if(f->upstream_remaining > 0){
        //check to see whether the previous record has finished
        if(f->upstream_remaining > info->app_data_len){
            //ignore entire packet for now
            queue_block *new_block = smalloc(sizeof(queue_block));

            uint8_t *block_data = smalloc(info->app_data_len);
            memcpy(block_data, p, info->app_data_len);

            new_block->len = info->app_data_len;
            new_block->offset = 0;
            new_block->data = block_data;
            new_block->next = NULL;
            //add block to upstream data chain
            if(f->upstream_queue == NULL){
                f->upstream_queue = new_block;
            } else {
                queue_block *last = f->upstream_queue;
                while(last->next != NULL){
                    last = last->next;
                }
                last->next = new_block;
            }

            f->upstream_remaining -= info->app_data_len;
            return 0;


        } else {
            //process what we have
            record_hdr = (struct record_header*) f->upstream_queue->data;
            record_length = RECORD_LEN(record_hdr);
            record_ptr = smalloc(record_length+ RECORD_HEADER_LEN);

            queue_block *current = f->upstream_queue;
            int32_t offset =0;
            while(f->upstream_queue != NULL){
                memcpy(record_ptr+offset, current->data, current->len);
                offset += current->len;
                free(current->data);
                f->upstream_queue = current->next;
                free(current);
                current = f->upstream_queue;
            }
            memcpy(record_ptr+offset, p, f->upstream_remaining);
            p = record_ptr;
            record_hdr = (struct record_header*) p;
            f->upstream_remaining = 0;
        }
    } else {
        //check to see if the new record is too long
        record_hdr = (struct record_header*) p;
        record_length = RECORD_LEN(record_hdr);
        if(record_length + RECORD_HEADER_LEN > info->app_data_len){

            //add info to upstream queue
            queue_block *new_block = smalloc(sizeof(queue_block));

            uint8_t *block_data = smalloc(info->app_data_len);

            memcpy(block_data, p, info->app_data_len);

            new_block->len = info->app_data_len;
            new_block->data = block_data;
            new_block->next = NULL;

            //add block to upstream queue
            if(f->upstream_queue == NULL){
                f->upstream_queue = new_block;
            } else {
                queue_block *last = f->upstream_queue;
                while(last->next != NULL){
                    last = last->next;
                }
                last->next = new_block;
            }

            f->upstream_remaining = record_length + RECORD_HEADER_LEN - new_block->len;
            return 0;
        }
    }

    p+= RECORD_HEADER_LEN;
    uint8_t *decrypted_data = smalloc(record_length);

    memcpy(decrypted_data, p, record_length);

    int32_t decrypted_len = encrypt(f, decrypted_data, decrypted_data, record_length, 0, record_hdr->type, 0, 0);
    if(decrypted_len<0){
        printf("US: decryption failed!\n");
        if(record_ptr != NULL)
            free(record_ptr);
        free(decrypted_data);
        return 0;
    }

    if(record_hdr->type == 0x15){
        DEBUG_MSG(DEBUG_UP, "received alert %x:%d > %x:%d (%s)\n", info->ip_hdr->src.s_addr, ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port), (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? "incoming":"outgoing");
        DEBUG_BYTES(DEBUG_UP, (decrypted_data + EVP_GCM_TLS_EXPLICIT_IV_LEN), decrypted_len);

        //TODO: re-encrypt and return
    }

    DEBUG_MSG(DEBUG_UP, "Upstream data: (%x:%d > %x:%d )\n",info->ip_hdr->src.s_addr,ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port));
    DEBUG_MSG(DEBUG_UP, "Data for flow %p:\n%s\n", f, decrypted_data+EVP_GCM_TLS_EXPLICIT_IV_LEN);
    DEBUG_MSG(DEBUG_UP, "Bytes for flow %p (%d bytes):\n", f, decrypted_len);
    DEBUG_BYTES(DEBUG_UP, (decrypted_data + EVP_GCM_TLS_EXPLICIT_IV_LEN), decrypted_len);

    /* search through decrypted data for x-ignore */
    char *header_ptr = strstr((const char *) decrypted_data+EVP_GCM_TLS_EXPLICIT_IV_LEN, "X-Slitheen");

    uint8_t *upstream_data;
    if(header_ptr == NULL){
        if(record_ptr != NULL)
            free(record_ptr);
        free(decrypted_data);

        return 0;
    }

    DEBUG_MSG(DEBUG_UP, "UPSTREAM: Found x-slitheen header\n");
    DEBUG_MSG(DEBUG_UP, "UPSTREAM Flow: %x:%d > %x:%d (%s)\n", info->ip_hdr->src.s_addr,ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port) ,(info->ip_hdr->src.s_addr != f->src_ip.s_addr)? "incoming":"outgoing");
    DEBUG_MSG(DEBUG_UP, "Sequence number: %d\n", ntohs(info->tcp_hdr->sequence_num));

    header_ptr += strlen("X-Slitheen: ");

    if(*header_ptr == '\r' || *header_ptr == '\0'){
        DEBUG_MSG(DEBUG_UP, "No messages\n");

        free(decrypted_data);
        return 0;
    }

    int32_t num_messages = 1;
    char *messages[50]; //TODO: grow this array
    messages[0] = header_ptr;
    char *c = header_ptr;
    while(*c != '\r' && *c != '\0'){
        if(*c == ' '){
            *c = '\0';
            messages[num_messages] = c+1;
            num_messages ++;
        }
        c++;
    }
    c++;
    *c = '\0';

    DEBUG_MSG(DEBUG_UP, "UPSTREAM: Found %d messages\n", num_messages);

    for(int i=0; i< num_messages; i++){
        char *message = messages[i];

        //b64 decode the data
        int32_t decode_len = strlen(message);
        if(message[decode_len-2] == '='){
            decode_len = decode_len*3/4 - 2;
        } else if(message[decode_len-1] == '='){
            decode_len = decode_len*3/4 - 1;
        } else {
            decode_len = decode_len*3/4;
        }

        upstream_data = smalloc(decode_len + 1);

        BIO *bio, *b64;
        bio = BIO_new_mem_buf(message, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        int32_t output_len = BIO_read(bio, upstream_data, strlen(message));

        BIO_free_all(bio);

        DEBUG_MSG(DEBUG_UP, "Decoded to get %d bytes:\n", output_len);
        DEBUG_BYTES(DEBUG_UP, upstream_data, output_len);

        p = upstream_data;

        if(i== 0){
            //this is the Slitheen ID
            DEBUG_MSG(DEBUG_UP, "Slitheen ID:");
            DEBUG_BYTES(DEBUG_UP, p, output_len);

            //find stream table or create new one
            client *last = clients->first;
            while(last != NULL){
                if(!memcmp(last->slitheen_id, p, output_len)){
                    f->downstream_queue = last->downstream_queue;
                    f->client_ptr = last; 
                    break;
                }
                last = last->next;
            }

            if(f->client_ptr == NULL){
                //create new client

                DEBUG_MSG(DEBUG_UP, "Creating a new client\n");
                client *new_client = smalloc(sizeof(client));

                memcpy(new_client->slitheen_id, p, output_len);
                new_client->streams = smalloc(sizeof(stream_table));

                new_client->streams->first = NULL;
                new_client->downstream_queue = smalloc(sizeof(data_queue));
                sem_init(&(new_client->queue_lock), 0, 1);

                new_client->downstream_queue->first_block = NULL;
                new_client->encryption_counter = 0;

                new_client->next = NULL;

                /* Now generate super encryption keys */
                generate_client_super_keys(new_client->slitheen_id, new_client);

                //add to client table
                if(clients->first == NULL){
                    clients->first = new_client;
                } else {
                    client *last = clients->first;
                    while(last->next != NULL){
                        last = last->next;
                    }
                    last->next = new_client;
                }

                //set f's stream table
                f->client_ptr = new_client;
                f->downstream_queue = new_client->downstream_queue;

            }

            free(upstream_data);
            continue;
        }

        while(output_len > 0){
            struct sl_up_hdr *sl_hdr = (struct sl_up_hdr *) p;
            uint16_t stream_id = sl_hdr->stream_id;
            uint16_t stream_len = ntohs(sl_hdr->len);

            p += sizeof(struct sl_up_hdr);
            output_len -= sizeof(struct sl_up_hdr);

            stream_table *streams = f->client_ptr->streams;

            //If a thread for this stream id exists, get the thread info and pipe data
            int32_t stream_pipe = -1;
            stream *last = streams->first;
            if(streams->first != NULL){
                if(last->stream_id == stream_id){
                    stream_pipe = last->pipefd;
                } else {
                    while(last->next != NULL){
                        last = last->next;
                        if(last->stream_id == stream_id){
                            stream_pipe = last->pipefd;
                            break;
                        }
                    }
                }
            }

            if(stream_pipe != -1){
                if(stream_len ==0){

                    DEBUG_MSG(DEBUG_UP, "Client closed. We are here\n");
                    close(stream_pipe);
                    break;
                }
                DEBUG_MSG(DEBUG_UP, "Found stream id %d\n", last->stream_id);
                DEBUG_MSG(DEBUG_UP, "Writing %d bytes to pipe\n", stream_len);

                int32_t bytes_sent = write(stream_pipe, p, stream_len);
                if(bytes_sent < 0){
                    printf("Error sending bytes to stream pipe\n");
                }

            } else if(stream_len > 0){

                /*Else, spawn a thread to handle the proxy to this site*/
                pthread_t proxy_thread;
                int32_t pipefd[2];
                if(pipe(pipefd) < 0){
                    printf("Error creating pipe\n");
                    free(decrypted_data);
                    if(record_ptr != NULL)
                        free(record_ptr);
                    return 1;
                }
                uint8_t *initial_data = smalloc(stream_len);
                memcpy(initial_data, p, stream_len);

                struct proxy_thread_data *thread_data =
                    smalloc(sizeof(struct proxy_thread_data));
                thread_data->initial_data = initial_data;
                thread_data->initial_len = stream_len;
                thread_data->stream_id = stream_id;
                thread_data->pipefd = pipefd[0];
                thread_data->downstream_queue = f->downstream_queue;
                thread_data->client = f->client_ptr;

                pthread_create(&proxy_thread, NULL, proxy_covert_site, (void *) thread_data);

                pthread_detach(proxy_thread);
                printf("Spawned thread for proxy\n");
                //add stream to table
                stream *new_stream = smalloc(sizeof(stream));
                new_stream->stream_id = stream_id;
                new_stream->pipefd = pipefd[1];
                new_stream->next = NULL;

                if(streams->first == NULL){
                    streams->first = new_stream;
                } else {
                    stream *last = streams->first;
                    while(last->next != NULL){
                        last = last->next;
                    }
                    last->next = new_stream;
                }

            } else{
                printf("Error, stream len 0\n");
                break;
            }
            output_len -= stream_len;
            p += stream_len;

        }
        free(upstream_data);
    }

    //save a reference to the proxy threads in a global table
    free(decrypted_data);
    if(record_ptr != NULL)
        free(record_ptr);

    return 0;

}

/** Called by spawned pthreads in read_header to send upstream
 *  data to the censored site and receive responses. Downstream
 *  data is stored in the slitheen id's downstream_queue. Function and
 *  thread will terminate when the client closes the connection
 *  to the covert destination
 *
 *  Input:
 *  	A struct that contains the following information:
 *  	- the tagged flow
 *  	- the initial upstream data + len (including connect request)
 *  	- the read end of the pipe
 *  	- the downstream queue for the client
 *
 */
static void *proxy_covert_site(void *data){

    struct proxy_thread_data *thread_data =
        (struct proxy_thread_data *) data;

    uint8_t *p = thread_data->initial_data;
    uint16_t data_len = thread_data->initial_len;
    uint16_t stream_id = thread_data->stream_id;

    int32_t bytes_sent;

    DEBUG_MSG(DEBUG_PROXY, "PROXY: created new thread for stream %d\n", stream_id);

    data_queue *downstream_queue = thread_data->downstream_queue;
    client *clnt = thread_data->client;
    stream_table *streams = clnt->streams;

    struct socks_req *clnt_req = (struct socks_req *) p;
    p += 4;
    data_len -= 4;

    int32_t handle = -1;

    //see if it's a connect request
    if(clnt_req->cmd != 0x01){
        DEBUG_MSG(DEBUG_PROXY, "PROXY: error not a connect request\n");
        goto err;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    uint8_t domain_len;

    switch(clnt_req->addr_type){
        case 0x01:
            //IPv4
            dest.sin_addr.s_addr = *((uint32_t*) p);
            p += 4;
            data_len -= 4;
            break;

        case 0x03:
            //domain name
            domain_len = p[0];
            p++;
            data_len --;
            uint8_t *domain_name = smalloc(domain_len+1);
            memcpy(domain_name, p, domain_len);
            domain_name[domain_len] = '\0';
            struct hostent *host;
            host = gethostbyname((const char *) domain_name);
            dest.sin_addr = *((struct in_addr *) host->h_addr);

            p += domain_len;
            data_len -= domain_len;
            free(domain_name);
            break;
        case 0x04:
            //IPv6
            printf("PROXY: error IPv6\n");
            goto err;//TODO: add IPv6 functionality
            break;
    }

    //now set the port
    dest.sin_port = *((uint16_t *) p);
    p += 2;
    data_len -= 2;

    handle = socket(AF_INET, SOCK_STREAM, 0);
    if(handle < 0){
        printf("PROXY: error creating socket\n");
        goto err;
    }

    struct sockaddr_in my_addr;
    socklen_t my_addr_len = sizeof(my_addr);

    int32_t error = connect (handle, (struct sockaddr *) &dest, sizeof (struct sockaddr));

    DEBUG_MSG(DEBUG_PROXY, "PROXY: Connected to covert site for stream %d\n", stream_id);

    if(error <0){
        goto err;
    }

    getsockname(handle, (struct sockaddr *) &my_addr, &my_addr_len);

    //see if there were extra upstream bytes
    if(data_len > 0){
        DEBUG_MSG(DEBUG_PROXY, "Data len is %d\n", data_len);
        DEBUG_BYTES(DEBUG_PROXY, p, data_len);

        bytes_sent = send(handle, p,
                data_len, 0);
        if( bytes_sent <= 0){
            goto err;
        }
    }

    uint8_t *buffer = smalloc(BUFSIZ);
    int32_t buffer_len = BUFSIZ;
    //now select on reading from the pipe and from the socket
    for(;;){
        fd_set readfds;
        fd_set writefds;

        int32_t nfds = (handle > thread_data->pipefd) ?
            handle +1 : thread_data->pipefd + 1;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        FD_SET(thread_data->pipefd, &readfds);
        FD_SET(handle, &readfds);
        FD_SET(handle, &writefds);

        if (select(nfds, &readfds, &writefds, NULL, NULL) < 0){
            printf("select error\n");
            break;
        }

        if(FD_ISSET(thread_data->pipefd, &readfds) && FD_ISSET(handle, &writefds)){
            //we have upstream data ready for writing

            int32_t bytes_read = read(thread_data->pipefd, buffer, buffer_len);

            if(bytes_read > 0){
                DEBUG_MSG(DEBUG_PROXY, "PROXY (id %d): read %d bytes from pipe\n", stream_id, bytes_read);
                DEBUG_BYTES(DEBUG_PROXY, buffer, bytes_read);

                bytes_sent = send(handle, buffer,
                        bytes_read, 0);
                if( bytes_sent <= 0){
                    DEBUG_MSG(DEBUG_PROXY, "Error sending bytes to covert site (stream %d)\n", stream_id);
                    break;
                } else if (bytes_sent < bytes_read){
                    DEBUG_MSG(DEBUG_PROXY, "Sent less bytes than read to covert site (stream %d)\n", stream_id);
                    break;
                }
            } else {
                //Client closed the connection, we can delete this stream from the downstream queue

                DEBUG_MSG(DEBUG_PROXY, "Deleting stream %d from the downstream queue\n", stream_id);

                sem_wait(&clnt->queue_lock);

                queue_block *last = downstream_queue->first_block;
                queue_block *prev = last;
                while(last != NULL){
                    if(last->stream_id == stream_id){
                        //remove block from queue
                        if(last == downstream_queue->first_block){
                            downstream_queue->first_block = last->next;
                            free(last->data);
                            free(last);
                            last = downstream_queue->first_block;
                            prev = last;
                        } else {
                            prev->next = last->next;
                            free(last->data);
                            free(last);
                            last = prev->next;
                        }
                    } else {
                        prev = last;
                        last = last->next;
                    }
                }

                sem_post(&clnt->queue_lock);
                DEBUG_MSG(DEBUG_PROXY, "Finished deleting from downstream queue\n");
                break;
            }

        }

        if (FD_ISSET(handle, &readfds)){
            //we have downstream data read for saving
            int32_t bytes_read;
            bytes_read = recv(handle, buffer, buffer_len, 0);
            if(bytes_read > 0){
                uint8_t *new_data = smalloc(bytes_read);
                memcpy(new_data, buffer, bytes_read);
                DEBUG_MSG(DEBUG_PROXY, "PROXY (id %d): read %d bytes from censored site\n",stream_id, bytes_read);
                DEBUG_BYTES(DEBUG_PROXY, buffer, bytes_read);

                //make a new queue block
                queue_block *new_block = smalloc(sizeof(queue_block));
                new_block->len = bytes_read;
                new_block->offset = 0;
                new_block->data = new_data;
                new_block->next = NULL;
                new_block->stream_id = stream_id;
                sem_wait(&clnt->queue_lock);
                if(downstream_queue->first_block == NULL){
                    downstream_queue->first_block = new_block;
                }
                else{
                    queue_block *last = downstream_queue->first_block;
                    while(last->next != NULL)
                        last = last->next;
                    last->next = new_block;
                }
                sem_post(&clnt->queue_lock);
            } else {
                DEBUG_MSG(DEBUG_PROXY, "PROXY (id %d): read %d bytes from censored site\n",stream_id, bytes_read);

                break;
            }

        }
    }

    DEBUG_MSG(DEBUG_PROXY, "Closing connection for stream %d\n", stream_id);
    //remove self from list
    stream *last = streams->first;
    stream *prev = last;
    if(streams->first != NULL){
        if(last->stream_id == stream_id){
            streams->first = last->next;
            free(last);
        } else {
            while(last->next != NULL){
                prev = last;
                last = last->next;
                if(last->stream_id == stream_id){
                    prev->next = last->next;
                    free(last);
                    break;
                }
            }
        }
    }
    if(thread_data->initial_data != NULL){
        free(thread_data->initial_data);
    }
    free(thread_data);
    free(buffer);
    close(handle);
    pthread_detach(pthread_self());
    pthread_exit(NULL);
    return 0;
err:
    //remove self from list
    last = streams->first;
    prev = last;
    if(streams->first != NULL){
        if(last->stream_id == stream_id){
            streams->first = last->next;
            free(last);
        } else {
            while(last->next != NULL){
                prev = last;
                last = last->next;
                if(last->stream_id == stream_id){
                    prev->next = last->next;
                    free(last);
                    break;
                }
            }
        }
    }
    if(thread_data->initial_data != NULL){
        free(thread_data->initial_data);
    }
    free(thread_data);
    if(handle > 0){
        close(handle);
    }
    pthread_detach(pthread_self());
    pthread_exit(NULL);
    return 0;
}

/** Replaces downstream record contents with data from the
 *  censored queue, padding with garbage bytes if no more
 *  censored data exists.
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	data: a pointer to the received packet's application
 *  		data
 *  	data_len: the length of the	packet's application data
 *  	offset: if the packet is misordered, the number of
 *  		application-level bytes in missing packets
 *
 *  Output:
 *  	Returns 0 on success
 */
static int process_downstream(flow *f, int32_t offset, struct packet_info *info){

    uint8_t *p = info->app_data;
    uint32_t remaining_packet_len = info->app_data_len;

    uint32_t partial_offset;
    uint32_t remaining_record_len, record_len;

    uint8_t partial = 0, false_tag = 0, changed = 0;

    uint8_t *record, *record_ptr;

    int32_t n;

    struct record_header *record_hdr;


    while(remaining_packet_len > 0){ //while bytes remain in the packet
        if(f->partial_record != NULL){
            partial = 1;
            remaining_record_len = f->partial_record_total_len - f->partial_record_len;
            if(remaining_record_len > remaining_packet_len){ //ignore entire packet

                partial_offset = f->partial_record_len;
                f->partial_record_len += remaining_packet_len;
                memcpy(f->partial_record+ partial_offset, p, remaining_packet_len);
                remaining_record_len = remaining_packet_len;
            } else { // finishing out this record

                partial_offset = f->partial_record_len;
                f->partial_record_len += remaining_record_len;
                memcpy(f->partial_record+ partial_offset, p, remaining_record_len);
            }

            record_len = remaining_record_len;

            //copy record to temporary ptr
            record_ptr = malloc(f->partial_record_len);
            memcpy(record_ptr, f->partial_record, f->partial_record_len);

        } else { //new record

            if(remaining_packet_len < RECORD_HEADER_LEN){
                DEBUG_MSG(DEBUG_DOWN, "partial record header: \n");
                DEBUG_BYTES(DEBUG_DOWN, p, remaining_packet_len);

                f->partial_record_header = smalloc(RECORD_HEADER_LEN);
                memcpy(f->partial_record_header, p, remaining_packet_len);
                f->partial_record_header_len = remaining_packet_len;
                remaining_packet_len -= remaining_packet_len;
                break;
            }


            if(f->partial_record_header_len > 0){
                memcpy(f->partial_record_header+ f->partial_record_header_len,
                        p, RECORD_HEADER_LEN - f->partial_record_header_len);
                record_hdr = (struct record_header *) f->partial_record_header;
            } else {

                record_hdr = (struct record_header*) p;
            }
            record_len = RECORD_LEN(record_hdr);

            DEBUG_MSG(DEBUG_DOWN, "Record:\n");
            DEBUG_BYTES(DEBUG_DOWN, ((uint8_t *) record_hdr), RECORD_HEADER_LEN);

            p += (RECORD_HEADER_LEN - f->partial_record_header_len);
            remaining_packet_len -= (RECORD_HEADER_LEN - f->partial_record_header_len);


            if(record_len > remaining_packet_len){
                partial = 1;

                f->partial_record = smalloc(record_len);
                f->partial_record_dec = smalloc(record_len);
                f->partial_record_total_len = record_len;
                f->partial_record_len = remaining_packet_len;
                partial_offset = 0;
                memcpy(f->partial_record, p, remaining_packet_len);
            }

            remaining_record_len = (record_len > remaining_packet_len) ? remaining_packet_len : record_len;
            record_len = remaining_record_len;
            //copy record to temporary ptr
            record_ptr = malloc(remaining_record_len);
            memcpy(record_ptr, p, remaining_record_len); //points to the beginning of record data
        }

        DEBUG_MSG(DEBUG_DOWN, "Received bytes (len %d)\n", remaining_record_len);
        DEBUG_BYTES(DEBUG_DOWN, p, remaining_record_len);

        record = p; // save location of original data
        p = record_ptr;


        if(partial){


            //if we now have all of the record, decrypt full thing and check tag
            if(f->partial_record_len == f->partial_record_total_len){

                DEBUG_MSG(DEBUG_DOWN, "Received full partial record (len=%d):\n", f->partial_record_len);
                DEBUG_BYTES(DEBUG_DOWN, record_ptr, f->partial_record_len);

                n = encrypt(f, record_ptr, record_ptr, f->partial_record_len, 1, 0x17, 0, 0);
                if(n <= 0){
                    free(f->partial_record_dec);
                    free(f->partial_record);
                    f->partial_record = NULL;
                    f->partial_record_dec = NULL;

                    f->partial_record_total_len = 0;
                    f->partial_record_len = 0;
                    free(record_ptr);
                    return 0; //TODO: goto err or return correctly
                }

            } else {

                //partially decrypt record
                n = partial_aes_gcm_tls_cipher(f, record_ptr, record_ptr, f->partial_record_len, 0, 0);
                if(n < 0){
                    //do something smarter here
                    printf("Decryption failed, forfeiting flow (len=%d)\n", f->partial_record_len);
                    if(f->partial_record_header_len > 0){
                        f->partial_record_header_len = 0;
                        free(f->partial_record_header);
                    }
                    free(record_ptr);
                    f->http_state = FORFEIT_REST;
                    return 0;//TODO: goto err to free record_ptr
                } else if (n == 0) { //we don't have the entire iv yet
                    memcpy(f->partial_record_dec, f->partial_record, f->partial_record_len);

                    free(record_ptr);
                    return 0;
                }

            }

            //copy already modified data
            memcpy(p, f->partial_record_dec, partial_offset);
            //now update pointer to past where we've already parsed
            if(partial_offset){
                p += partial_offset;
                if(n + EVP_GCM_TLS_EXPLICIT_IV_LEN >= partial_offset){
                    remaining_record_len = n + EVP_GCM_TLS_EXPLICIT_IV_LEN - partial_offset;
                } else {//only received last part of tag
                    remaining_record_len = 0;
                }
            } else {
                p += EVP_GCM_TLS_EXPLICIT_IV_LEN;
                remaining_record_len = n;
            }
        } else {

            //now decrypt the record
            n = encrypt(f, record_ptr, record_ptr, remaining_record_len, 1,
                    record_hdr->type, 0, 0);
            if(n <= 0){
                //do something smarter here
                printf("Decryption failed\n");
                if(f->partial_record_header_len > 0){
                    f->partial_record_header_len = 0;
                    free(f->partial_record_header);
                }
                free(record_ptr);
                return 0;//TODO goto an err to free record_ptr
            }

            p += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            remaining_record_len = n;
        }
        changed = 1;

        DEBUG_MSG(DEBUG_DOWN, "Decrypted new record:\n");
        DEBUG_BYTES(DEBUG_DOWN, (record_ptr + EVP_GCM_TLS_EXPLICIT_IV_LEN), n);
        DEBUG_MSG(DEBUG_DOWN, "Text:\n%s\n", record_ptr+EVP_GCM_TLS_EXPLICIT_IV_LEN);
        DEBUG_MSG(DEBUG_DOWN, "Parseable text:\n%s\n", p);


        parse_http(f, p, remaining_record_len);


        if(changed && (f->content_type != NOREPLACE)){
            DEBUG_MSG(DEBUG_DOWN, "Resource is now:\n");
            DEBUG_BYTES(DEBUG_DOWN, (record_ptr + EVP_GCM_TLS_EXPLICIT_IV_LEN), n);
            DEBUG_MSG(DEBUG_DOWN, "Text:\n%s\n", record_ptr+EVP_GCM_TLS_EXPLICIT_IV_LEN);
        }

        //partially encrypting data
        if(partial){

            //first copy plaintext to flow struct

            //if partial_offset <= EXPLICIT_IV_LEN, we've yet to copy the decrypted iv bytes
            if (partial_offset <= EVP_GCM_TLS_EXPLICIT_IV_LEN)
                memcpy(f->partial_record_dec, record_ptr, EVP_GCM_TLS_EXPLICIT_IV_LEN);

            if(n + EVP_GCM_TLS_EXPLICIT_IV_LEN >= partial_offset){
                memcpy(f->partial_record_dec + partial_offset, record_ptr+partial_offset, n + EVP_GCM_TLS_EXPLICIT_IV_LEN - partial_offset);
            } //otherwise, this packet contains only part of the tag

            n = partial_aes_gcm_tls_cipher(f, record_ptr, record_ptr, n+ EVP_GCM_TLS_EXPLICIT_IV_LEN, 0, 1);
            if(n < 0){
                printf("Partial decryption failed!\n");
                free(record_ptr);
                return 0;
            }

            DEBUG_MSG(DEBUG_DOWN, "Partially encrypted bytes:\n");
            DEBUG_BYTES(DEBUG_DOWN, record_ptr, n + EVP_GCM_TLS_EXPLICIT_IV_LEN);

            //if we received all of the partial packet, add tag and release it
            if (f->partial_record_len == f->partial_record_total_len){

                //compute tag
                partial_aes_gcm_tls_tag(f, record_ptr + n + EVP_GCM_TLS_EXPLICIT_IV_LEN);
                DEBUG_MSG(DEBUG_DOWN, "finished partial tag: (%d bytes)\n", EVP_GCM_TLS_TAG_LEN);
                DEBUG_BYTES(DEBUG_DOWN, (record_ptr + n + EVP_GCM_TLS_EXPLICIT_IV_LEN),
                        EVP_GCM_TLS_TAG_LEN);

                if(false_tag){//tag on original record was incorrect O.o add incorrect tag

                } else {//compute correct tag TODO: fill in

                }

                free(f->partial_record_dec);
                free(f->partial_record);
                f->partial_record = NULL;
                f->partial_record_dec = NULL;

                f->partial_record_total_len = 0;
                f->partial_record_len = 0;
                partial = 0;
            } else {
                //compute tag just to clear out ctx
                uint8_t *tag = smalloc(EVP_GCM_TLS_TAG_LEN);
                partial_aes_gcm_tls_tag(f, tag);
                free(tag);

            }
            p = record_ptr + partial_offset;

            partial_offset += n + EVP_GCM_TLS_EXPLICIT_IV_LEN - partial_offset;

        } else {
            if((n = encrypt(f, record_ptr, record_ptr, n + EVP_GCM_TLS_EXPLICIT_IV_LEN,
                            1, record_hdr->type, 1, 1)) < 0){
                printf("UH OH, failed to re-encrypt record\n");
                if(f->partial_record_header_len > 0){
                    f->partial_record_header_len = 0;
                    free(f->partial_record_header);
                }
                free(record_ptr);
                return 0;
            }

            DEBUG_MSG(DEBUG_DOWN, "Re-encrypted bytes:\n");
            DEBUG_BYTES(DEBUG_DOWN, record_ptr, n);

            p = record_ptr;
        }

        //Copy changed temporary data to original packet
        memcpy(record, p, record_len);

        p = record + record_len;
        remaining_packet_len -= record_len;
        if(f->partial_record_header_len > 0){
            f->partial_record_header_len = 0;
            free(f->partial_record_header);
        }

        free(record_ptr);//free temporary record

    }

    if(changed){
        tcp_checksum(info);
    }

    return 0;
}


/** Computes the TCP checksum of the data according to RFC 793
 *  sum all 16-bit words in the segment, pad the last word if
 *  needed
 *
 *  there is a pseudo-header prefixed to the segment and
 *  included in the checksum:
 *
 *         +--------+--------+--------+--------+
 *         |           Source Address          |
 *         +--------+--------+--------+--------+
 *         |         Destination Address       |
 *         +--------+--------+--------+--------+
 *         |  zero  |  PTCL  |    TCP Length   |
 *         +--------+--------+--------+--------+
 */
uint16_t tcp_checksum(struct packet_info *info){

    uint16_t tcp_length = info->app_data_len + info->size_tcp_hdr;
    struct in_addr src = info->ip_hdr->src;
    struct in_addr dst = info->ip_hdr->dst;
    uint8_t proto = IPPROTO_TCP;

    //set the checksum to zero
    info->tcp_hdr->chksum = 0;

    //sum pseudoheader
    uint32_t sum = (ntohl(src.s_addr)) >> 16;
    sum += (ntohl(src.s_addr)) &0xFFFF;
    sum += (ntohl(dst.s_addr)) >> 16;
    sum += (ntohl(dst.s_addr)) & 0xFFFF;
    sum += proto;
    sum += tcp_length;

    //sum tcp header (with zero-d checksum)
    uint8_t *p = (uint8_t *) info->tcp_hdr;
    for(int i=0; i < info->size_tcp_hdr; i+=2){
        sum += (uint16_t) ((p[i] << 8) + p[i+1]);
    }

    //now sum the application data
    p = info->app_data;
    for(int i=0; i< info->app_data_len-1; i+=2){
        sum += (uint16_t) ((p[i] << 8) + p[i+1]);
    }
    if(info->app_data_len %2 != 0){
        sum += (uint16_t) (p[info->app_data_len - 1]) << 8;
    }

    //now add most significant to last significant bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >>16;
    //now subtract from 0xFF
    sum = 0xFFFF - sum;

    //set chksum to calculated value
    info->tcp_hdr->chksum = ntohs(sum);
    return (uint16_t) sum;
}
