/* Name: flow.c
 *
 * This file contains functions for manipulating tagged flows. 
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
#include <pthread.h>
#include <errno.h>
#include <semaphore.h>
#include <string.h>

#include "flow.h"
#include "crypto.h"
#include "packet.h"
#include "relay.h"
#include "util.h"
#include "http.h"

/* Data structures */
typedef struct packet_chain_st {
    packet *first_packet;
    uint32_t expected_seq_num;
    uint32_t record_len;
    uint32_t remaining_record_len;
} packet_chain;

typedef struct session_cache_st {
    session *first_session;
    uint32_t length;
} session_cache;

typedef struct flow_entry_st {
    flow *f;
    struct flow_entry_st *next;
} flow_entry;

typedef struct flow_table_st {
    flow_entry *first_entry;
    int len;
} flow_table;

static flow_table *table;
static session_cache *sessions;
client_table *clients;

sem_t flow_table_lock;

#define TLS_HELLO_REQ 0x00
#define TLS_CLNT_HELLO 0x01
#define TLS_SERV_HELLO 0x02
#define TLS_NEW_SESS 0x04
#define TLS_CERT 0x0b
#define TLS_SRVR_KEYEX 0x0c
#define TLS_CERT_REQ 0x0d
#define TLS_SRVR_HELLO_DONE 0x0e
#define TLS_CERT_VERIFY 0x0f
#define TLS_CLNT_KEYEX 0x10
#define TLS_FINISHED 0x14
#define TLS_CERT_STATUS 0x16

static int update_flow(flow *f, uint8_t *record, uint8_t incoming);
static int verify_session_id(flow *f, uint8_t *hs);
static int check_extensions(flow *f, uint8_t *hs, uint32_t len);
static int verify_extensions(flow *f, uint8_t *hs, uint32_t len);
static int save_session_id(flow *f, uint8_t *hs);
static int save_session_ticket(flow *f, uint8_t *hs, uint32_t len);


/* Initialize the table of tagged flows */
int init_tables(void) {

    table = smalloc(sizeof(flow_table));
    table->first_entry = NULL;
    table->len = 0;

    sem_init(&flow_table_lock, 0, 1);

    clients = smalloc(sizeof(client_table));
    clients->first = NULL;
    printf("initialized downstream queue\n");

    return 0;
}


/* Add a new flow to the tagged flow table */
flow *add_flow(struct packet_info *info) {
    flow_entry *entry = smalloc(sizeof(flow_entry));

    flow *new_flow = smalloc(sizeof(flow));

    entry->f = new_flow;
    entry->next = NULL;

    new_flow->src_ip = info->ip_hdr->src;
    new_flow->dst_ip = info->ip_hdr->dst;
    new_flow->src_port = info->tcp_hdr->src_port;
    new_flow->dst_port = info->tcp_hdr->dst_port;

    new_flow->ref_ctr = 1;
    new_flow->removed = 0;

    new_flow->upstream_app_data = smalloc(sizeof(app_data_queue));
    new_flow->upstream_app_data->first_packet = NULL;
    new_flow->downstream_app_data = smalloc(sizeof(app_data_queue));
    new_flow->downstream_app_data->first_packet = NULL;

    new_flow->upstream_seq_num = ntohl(info->tcp_hdr->sequence_num);
    new_flow->downstream_seq_num = ntohl(info->tcp_hdr->ack_num);

    new_flow->us_frame_queue = smalloc(sizeof(frame_queue));
    new_flow->us_frame_queue->first_frame = NULL;
    new_flow->ds_frame_queue = smalloc(sizeof(frame_queue));
    new_flow->ds_frame_queue->first_frame = NULL;

    new_flow->downstream_queue=NULL;
    new_flow->client_ptr=NULL;

    sem_init(&(new_flow->flow_lock), 0, 1);
    new_flow->state = TLS_CLNT_HELLO;
    new_flow->in_encrypted = 0;
    new_flow->out_encrypted = 0;
    new_flow->application = 0;
    new_flow->stall = 0;
    new_flow->extended_master_secret = 0;
    new_flow->resume_session = 0;
    new_flow->current_session = NULL;

    new_flow->us_hs_queue = init_queue();
    new_flow->ds_hs_queue = init_queue();

    new_flow->us_packet_chain = smalloc(sizeof(packet_chain));
    new_flow->us_packet_chain->expected_seq_num = ntohl(info->tcp_hdr->sequence_num);
    new_flow->us_packet_chain->record_len = 0;
    new_flow->us_packet_chain->remaining_record_len = 0;
    new_flow->us_packet_chain->first_packet = NULL;

    new_flow->ds_packet_chain = smalloc(sizeof(packet_chain));
    new_flow->ds_packet_chain->expected_seq_num = ntohl(info->tcp_hdr->ack_num);
    new_flow->ds_packet_chain->record_len = 0;
    new_flow->ds_packet_chain->remaining_record_len = 0;
    new_flow->ds_packet_chain->first_packet = NULL;
    sem_init(&(new_flow->packet_chain_lock), 0, 1);

    new_flow->upstream_queue = NULL;
    new_flow->upstream_remaining = 0;
    sem_init(&(new_flow->upstream_queue_lock), 0, 1);
    new_flow->outbox = NULL;
    new_flow->outbox_len = 0;
    new_flow->outbox_offset = 0;
    new_flow->partial_record_header = NULL;
    new_flow->partial_record_header_len = 0;
    new_flow->partial_record = NULL;
    new_flow->partial_record_dec = NULL;
    new_flow->partial_record_len = 0;
    new_flow->partial_record_total_len = 0;
    new_flow->remaining_record_len = 0;
    new_flow->remaining_response_len = 0;
    new_flow->httpstate = PARSE_HEADER;
    new_flow->webmstate = 0;
    new_flow->remaining_element = 0;
    new_flow->element_header = 0;
    new_flow->replace_response = 0;

    new_flow->ecdh = NULL;
    new_flow->srvr_key = NULL;
    new_flow->dh = NULL;

    new_flow->hs_md_ctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(new_flow->hs_md_ctx, md, NULL);

    new_flow->cipher = NULL;
    new_flow->keyex_alg = 0;
    new_flow->clnt_read_ctx = NULL;
    new_flow->clnt_write_ctx = NULL;
    new_flow->srvr_read_ctx = NULL;
    new_flow->srvr_write_ctx = NULL;
    new_flow->gcm_ctx_out = NULL;
    new_flow->gcm_ctx_iv = NULL;
    new_flow->gcm_ctx_key = NULL;

    memset(new_flow->read_seq, 0, 8);
    memset(new_flow->write_seq, 0, 8);


    sem_wait(&flow_table_lock);
    flow_entry *last = table->first_entry;
    if(last == NULL){
        table->first_entry = entry;
    } else {
        for(int i=0; i< table->len-1; i++){
            last = last->next;
        }
        last->next = entry;
    }
    table->len ++;
    sem_post(&flow_table_lock);

    return new_flow;

}

/** Observes TLS handshake messages and updates the state of
 *  the flow
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	record: a complete TLS record
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
static int update_flow(flow *f, uint8_t *record, uint8_t incoming) {
    const struct record_header *record_hdr;
    const struct handshake_header *handshake_hdr;
    uint8_t *p;

    record_hdr = (struct record_header*) record;
    int record_len;

    record_len = RECORD_LEN(record_hdr)+RECORD_HEADER_LEN;

    switch(record_hdr->type){
        case HS:
            p = record;

            DEBUG_MSG(DEBUG_HS, "Received handshake packet  (%x:%d -> %x:%d) (incoming: %d)\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port), incoming);

            p += RECORD_HEADER_LEN;


            if((incoming && f->in_encrypted) || (!incoming && f->out_encrypted)){
                DEBUG_MSG(DEBUG_HS, "Decrypting finished (%d bytes) (%x:%d -> %x:%d) (incoming: %d)\n", record_len - RECORD_HEADER_LEN, f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port), incoming);

                DEBUG_BYTES(DEBUG_HS, record, record_len);

                int32_t n = encrypt(f, p, p, record_len - RECORD_HEADER_LEN, incoming, 0x16, 0, 0);
                if(n<=0){
                    printf("Error decrypting finished  (%x:%d -> %x:%d) (incoming: %d)\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port), incoming);
                    printf("record:\n");
                    for(int i=0; i< 12; i++){
                        printf("%02x ", p[i]);
                    }

                }

                DEBUG_MSG(DEBUG_HS, "Finished decrypted: (%x:%d -> %x:%d)\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));

                p += EVP_GCM_TLS_EXPLICIT_IV_LEN;

                DEBUG_BYTES(DEBUG_HS, p, n);

                if(p[0] != 0x14){
                    p[0] = 0x20; //trigger error
                }

                if(incoming){
                    f->in_encrypted = 2;
                } else {
                    f->out_encrypted = 2;
                }

            }
            handshake_hdr = (struct handshake_header*) p;
            f->state = handshake_hdr->type;

            switch(f->state){
                case TLS_CLNT_HELLO: 
                    DEBUG_MSG(DEBUG_HS, "Received tagged client hello (%x:%d -> %x:%d)\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));

                    if(check_extensions(f, p, HANDSHAKE_MESSAGE_LEN(handshake_hdr))){
                        fprintf(stderr, "Error checking session, might cause problems\n");
                    }

                    if(update_handshake_hash(f, p)){
                        fprintf(stderr, "Error updating finish has with CLNT_HELLO msg\n");
                        remove_flow(f);
                        goto err;
                    }

                    break;
                case TLS_SERV_HELLO:
                    DEBUG_MSG(DEBUG_HS, "Received server hello (%x:%d -> %x:%d)\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));

                    if(f->resume_session){
                        if(verify_session_id(f,p)){
                            DEBUG_MSG(DEBUG_HS, "Failed to verify session id\n");
                        }
                    } else {
                        if(save_session_id(f,p)){
                            DEBUG_MSG(DEBUG_HS, "Failed to save session id\n");
                        }
                    }

                    if(verify_extensions(f,p, HANDSHAKE_MESSAGE_LEN(handshake_hdr))){
                        DEBUG_MSG(DEBUG_HS, "Failed to verify extensions\n");
                    }

                    if(extract_server_random(f, p)){
                        DEBUG_MSG(DEBUG_HS, "Failed to extract server random nonce\n");
                        remove_flow(f);
                        goto err;
                    }
                    if(update_handshake_hash(f, p)){
                        DEBUG_MSG(DEBUG_HS, "Error updating finish has with CLNT_HELLO msg\n");
                        remove_flow(f);
                        goto err;
                    }
                    break;
                case TLS_NEW_SESS:
                    DEBUG_MSG(DEBUG_HS, "Received new session\n");

                    if(save_session_ticket(f, p, HANDSHAKE_MESSAGE_LEN(handshake_hdr))){
                        DEBUG_MSG(DEBUG_HS, "Failed to save session ticket\n");
                    }
                    break;
                case TLS_CERT:
                    DEBUG_MSG(DEBUG_HS, "Received cert\n");

                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }
                    break;
                case TLS_CERT_STATUS:
                    DEBUG_MSG(DEBUG_HS, "Received certificate status\n");

                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }
                    break;
                case TLS_SRVR_KEYEX:
                    DEBUG_MSG(DEBUG_HS, "Received server keyex\n");

                    if(extract_parameters(f, p)){
                        DEBUG_MSG(DEBUG_HS, "Error extracting params\n");
                        remove_flow(f);
                        goto err;
                    }

                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }

                    break;

                case TLS_CERT_REQ:
                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }
                    break;
                case TLS_SRVR_HELLO_DONE:
                    DEBUG_MSG(DEBUG_HS, "Received server hello done\n");

                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }
                    break;
                case TLS_CERT_VERIFY:
                    DEBUG_MSG(DEBUG_HS, "received cert verify\n");

                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }
                    break;

                case TLS_CLNT_KEYEX:
                    DEBUG_MSG(DEBUG_HS, "Received client key exchange\n");

                    if(update_handshake_hash(f, p)){
                        remove_flow(f);
                        goto err;
                    }
                    if(compute_master_secret(f)){
                        DEBUG_MSG(DEBUG_HS, "Error computing master secret\n");
                        remove_flow(f);
                        goto err;

                    }
                    break;
                case TLS_FINISHED:
                    DEBUG_MSG(DEBUG_HS, "Received finished (%d) (%x:%d -> %x:%d)\n", incoming, f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));

                    if((f->in_encrypted == 2) && (f->out_encrypted == 2)){
                        f->application = 1;
                        DEBUG_MSG(DEBUG_HS, "Handshake complete!\n");
                    }

                    if(!incoming) {
                        // We only care about incoming
                        // Finished messages
                        break;
                    }
                    if(mark_finished_hash(f, p)){
                        DEBUG_MSG(DEBUG_HS, "Error marking finished hash\n");
                        remove_flow(f);
                        goto err;
                    }

                    //re-encrypt finished message
                    int32_t n =  encrypt(f, record+RECORD_HEADER_LEN, record+RECORD_HEADER_LEN, record_len - (RECORD_HEADER_LEN+16), incoming, 0x16, 1, 1);

                    DEBUG_MSG(DEBUG_HS, "New finished ciphertext:\n");
                    DEBUG_BYTES(DEBUG_HS, record, record_len);

                    if(n<=0){
                        DEBUG_MSG(DEBUG_HS, "Error re-encrypting finished  (%x:%d -> %x:%d)\n", f->src_ip.s_addr, ntohs(f->src_port),
                                f->dst_ip.s_addr, ntohs(f->dst_port));
                    }

                    break;
                default:
                    DEBUG_MSG(DEBUG_HS, "Error: unrecognized hs message? (%x:%d -> %x:%d)...\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));
                    remove_flow(f);
                    goto err;
            }
            break;
        case APP:
            DEBUG_MSG(DEBUG_HS, "Application Data (%x:%d -> %x:%d)...\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));
            break;
        case CCS:
            DEBUG_MSG(DEBUG_HS, "CCS (%x:%d -> %x:%d) \n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));

            /*Initialize ciphers */
            if ((!f->in_encrypted) && (!f->out_encrypted)){
                if(init_ciphers(f)){
                    remove_flow(f);
                    goto err;
                }
            }

            if(incoming){
                f->in_encrypted = 1;
            } else {
                f->out_encrypted = 1;
            }

            break;
        case ALERT:
            p = record;
            p += RECORD_HEADER_LEN;
            if(((incoming) && (f->in_encrypted > 0)) || ((!incoming) && (f->out_encrypted > 0))){
                //decrypt alert
                int32_t n = encrypt(f, p, p, record_len - RECORD_HEADER_LEN, incoming, 0x15, 0, 0);
                if(n <= 0){
                    printf("Error decrypting Alert\n");
                }
                DEBUG_MSG(DEBUG_HS, "Decrypted alert:\n");
                DEBUG_BYTES(DEBUG_HS, p, n);

                p += EVP_GCM_TLS_EXPLICIT_IV_LEN;
            }
            DEBUG_MSG(DEBUG_HS, "Alert (%x:%d -> %x:%d) (%s) %02x %02x \n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port), (incoming) ? "incoming" : "outgoing", p[0], p[1]);

            //re-encrypt alert
            if(((incoming) && (f->in_encrypted > 0)) || ((!incoming) && (f->out_encrypted > 0))){
                int32_t n =  encrypt(f, record+RECORD_HEADER_LEN, record+RECORD_HEADER_LEN, record_len - (RECORD_HEADER_LEN+16), incoming, 0x15, 1, 1);
                if(n <= 0){
                    DEBUG_MSG(DEBUG_HS, "Error re-encrypting alert\n");
                }
            }

            break;
        case HB:
            DEBUG_MSG(DEBUG_HS, "Heartbeat\n");
            break;
        default:
            DEBUG_MSG(DEBUG_HS, "Error: Not a Record (%x:%d -> %x:%d)\n", f->src_ip.s_addr, ntohs(f->src_port), f->dst_ip.s_addr, ntohs(f->dst_port));
            remove_flow(f);
            goto err;
    }
    return 0;

err:
    return 1;
}

/** Removes the tagged flow from the flow table: happens when
 *  the station receives a TCP RST or FIN packet
 *
 *  Input:
 *  	index: the index into the flow table of the tagged flow
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int remove_flow(flow *f) {

    printf("Removed flow %p\n", f);

    sem_wait(&flow_table_lock);
    //decrement reference counter
    f->ref_ctr--;
    if(f->ref_ctr){ //if there are still references to f, wait to free it
        printf("Cannot free %p, still %d reference(s)\n", f, f->ref_ctr);
        f->removed = 1; 
        sem_post(&flow_table_lock);
        return 0;
    }

    if(f->removed)
        printf("Trying again to free\n");

    frame *first_frame = f->us_frame_queue->first_frame;
    while(first_frame != NULL){
        printf("Injecting delayed frame (seq = %u )\n", first_frame->seq_num);
        inject_packet(first_frame->iargs, first_frame->header, first_frame->packet);
        frame *tmp = first_frame->next;
        free(first_frame);
        first_frame = tmp;
    }
    free(f->us_frame_queue);

    first_frame = f->ds_frame_queue->first_frame;
    while(first_frame != NULL){
        printf("Injecting delayed frame (seq = %u )\n", first_frame->seq_num);
        inject_packet(first_frame->iargs, first_frame->header, first_frame->packet);
        frame *tmp = first_frame->next;
        free(first_frame);
        first_frame = tmp;
    }
    free(f->ds_frame_queue);

    //Empty application data queues
    packet *tmp = f->upstream_app_data->first_packet;
    while(tmp != NULL){
        f->upstream_app_data->first_packet = tmp->next;
        free(tmp->data);
        free(tmp);
        tmp = f->upstream_app_data->first_packet;
    }
    free(f->upstream_app_data);

    tmp = f->downstream_app_data->first_packet;
    while(tmp != NULL){
        f->downstream_app_data->first_packet = tmp->next;
        free(tmp->data);
        free(tmp);
        tmp = f->downstream_app_data->first_packet;
    }
    free(f->downstream_app_data);

    if(f->ds_hs_queue != NULL){
        remove_queue(f->ds_hs_queue);
    }
    if(f->us_hs_queue != NULL){
        remove_queue(f->us_hs_queue);
    }

    //free partial record headers
    if(f->partial_record_header_len > 0){
        f->partial_record_header_len = 0;
        free(f->partial_record_header);
    }

    if(f->partial_record_dec != NULL){
        free(f->partial_record_dec);
    }

    if(f->partial_record != NULL){
        free(f->partial_record);
    }

    //Clean up cipher ctxs
#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    EVP_MD_CTX_free(f->hs_md_ctx);
#else
    EVP_MD_CTX_cleanup(f->hs_md_ctx);
    if(f->hs_md_ctx != NULL){
        EVP_MD_CTX_destroy(f->hs_md_ctx);
    }
#endif
    if(f->clnt_read_ctx != NULL){
        EVP_CIPHER_CTX_cleanup(f->clnt_read_ctx);
        OPENSSL_free(f->clnt_read_ctx);
        f->clnt_read_ctx = NULL;
    }
    if(f->clnt_write_ctx != NULL){
        EVP_CIPHER_CTX_cleanup(f->clnt_write_ctx);
        OPENSSL_free(f->clnt_write_ctx);
        f->clnt_write_ctx = NULL;
    }
    if(f->srvr_read_ctx != NULL){
        EVP_CIPHER_CTX_free(f->srvr_read_ctx);
    }
    if(f->srvr_write_ctx != NULL){
        EVP_CIPHER_CTX_free(f->srvr_write_ctx);
    }

    if(f->ecdh != NULL){
        EC_KEY_free(f->ecdh);
    }

    if(f->gcm_ctx_out != NULL){
        CRYPTO_gcm128_release(f->gcm_ctx_out);
    }

    if(f->gcm_ctx_iv != NULL){
        free(f->gcm_ctx_iv);
    }

    if(f->gcm_ctx_key != NULL){
        free(f->gcm_ctx_key);
    }

    if(f->dh != NULL){
        DH_free(f->dh);
    }

    if(f->current_session != NULL && f->resume_session == 1){
        if( f->current_session->session_ticket != NULL){
            free(f->current_session->session_ticket);
        }
        free(f->current_session);
    }

    if(f->ds_packet_chain != NULL){
        packet *tmp = f->ds_packet_chain->first_packet;
        while(tmp != NULL){
            f->ds_packet_chain->first_packet = tmp->next;
            printf("Freed data %p\n", tmp->data);
            printf("Freed packet %p\n", tmp);
            free(tmp->data);
            free(tmp);
            tmp = f->ds_packet_chain->first_packet;
        }
    }
    free(f->ds_packet_chain);

    if(f->us_packet_chain != NULL){
        packet *tmp = f->us_packet_chain->first_packet;
        while(tmp != NULL){
            f->us_packet_chain->first_packet = tmp->next;
            printf("Freed data %p\n", tmp->data);
            printf("Freed packet %p\n", tmp);
            free(tmp->data);
            free(tmp);
            tmp = f->us_packet_chain->first_packet;
        }
    }
    free(f->us_packet_chain);

    if(f->upstream_queue != NULL){
        queue_block *tmp = f->upstream_queue;
        while(tmp != NULL){
            f->upstream_queue = tmp->next;
            printf("Freed data %p\n", tmp->data);
            printf("Freed packet %p\n", tmp);
            free(tmp->data);
            free(tmp);
            tmp = f->upstream_queue;
        }
    }

    flow_entry *entry = table->first_entry;
    if(entry->f == f){
        table->first_entry = entry->next;
        free(entry->f);
        free(entry);
        table->len --;
    } else {

        flow_entry *next;
        for(int i=0; i< table->len; i++){
            if(entry->next != NULL){
                next = entry->next;
            } else {
                printf("Flow not in table\n");
                break;
            }

            if(next->f == f){
                entry->next = next->next;
                free(next->f);
                free(next);
                table->len --;
                break;
            }

            entry = next;
        }
    }
    sem_post(&flow_table_lock);

    return 1;
}

/** Returns the index of a flow in the flow table if
 *  it exists, returns 0 if it is not present.
 *
 *  Inputs:
 *  	observed: details for the observed flow
 *
 *  Output:
 *  	flow struct from table or NULL if it doesn't exist
 */
flow *check_flow(struct packet_info *info){
    /* Loop through flows in table and see if it exists */
    int i;
    flow_entry *entry = table->first_entry;
    flow *candidate;
    flow *found = NULL;
    if(entry == NULL)
        return NULL;

    sem_wait(&flow_table_lock);
    /* Check first in this direction */
    for(i=0; i<table->len; i++){
        if(entry == NULL){
            printf("Error: entry is null\n");
            break;
        }
        candidate = entry->f;
        if(candidate->src_ip.s_addr == info->ip_hdr->src.s_addr){
            if(candidate->dst_ip.s_addr == info->ip_hdr->dst.s_addr){
                if(candidate->src_port == info->tcp_hdr->src_port){
                    if(candidate->dst_port == info->tcp_hdr->dst_port){
                        found = candidate;
                    }
                }
            }
        }
        entry = entry->next;
    }


    entry = table->first_entry;
    /* Then in the other direction */
    for(i=0; i<table->len; i++){
        if(entry == NULL){
            printf("Error: entry is null\n");
            break;
        }
        candidate = entry->f;
        if(candidate->src_ip.s_addr == info->ip_hdr->dst.s_addr){
            if(candidate->dst_ip.s_addr == info->ip_hdr->src.s_addr){
                if(candidate->src_port == info->tcp_hdr->dst_port){
                    if(candidate->dst_port == info->tcp_hdr->src_port){
                        found = candidate;
                    }
                }
            }
        }
        entry = entry->next;
    }

    if(found != NULL){
        found->ref_ctr++;
    }

    sem_post(&flow_table_lock);

    if(found != NULL && found->removed){
        remove_flow(found);
        found=NULL;
    }

    return found;
}

int init_session_cache(void){
    sessions = smalloc(sizeof(session_cache));

    sessions->length = 0;
    sessions->first_session = NULL;

    return 0;
}

/** Called from ServerHello, verifies that the session id returned matches
 *  the session id requested from the client hello
 *
 *  Input:
 *  	f: the tagged flow
 *  	hs: a pointer to the ServerHello message
 *
 *  Output:
 *  	0 if success, 1 if failed
 */
static int verify_session_id(flow *f, uint8_t *hs){

    if (f->current_session == NULL)
        return 1;

    //increment pointer to point to sessionid
    uint8_t *p = hs + HANDSHAKE_HEADER_LEN;
    p += 2; //skip version
    p += SSL3_RANDOM_SIZE; //skip random

    uint8_t id_len = (uint8_t) p[0];
    p ++;

    //check to see if it matches flow's session id set by ClientHello
    if(f->current_session->session_id_len > 0 && !memcmp(f->current_session->session_id, p, id_len)){
        //if it matched, update flow with master secret :D
        DEBUG_MSG(DEBUG_HS, "Session id matched!\n");

        session *last = sessions->first_session;
        int found = 0;
        for(int i=0; ((i<sessions->length) && (!found)); i++){

            if(!memcmp(last->session_id, f->current_session->session_id, id_len)){
                memcpy(f->master_secret, last->master_secret, SSL3_MASTER_SECRET_SIZE);
                found = 1;
            }
            last = last->next;
        }
        if((!found) && (f->current_session->session_ticket_len > 0)){
            last = sessions->first_session;
            for(int i=0; ((i<sessions->length) && (!found)); i++){
                if( (last->session_ticket != NULL) && (last->session_ticket_len == f->current_session->session_ticket_len)){
                    if(!memcmp(last->session_ticket, f->current_session->session_ticket, f->current_session->session_ticket_len)){
                        memcpy(f->master_secret, last->master_secret, SSL3_MASTER_SECRET_SIZE);
                        found = 1;

                        DEBUG_MSG(DEBUG_HS, "Found new session ticket (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
                        DEBUG_BYTES(DEBUG_HS, last->session_ticket, last->session_ticket_len);
                    }
                }
                last = last->next;
            }
        }

    } else if (f->current_session->session_id_len == 0){
        //search for session ticket in session cache
        printf("clnt session id was empty, looking for ticket\n");
        session *last = sessions->first_session;
        if(f->current_session->session_ticket_len > 0){
            last = sessions->first_session;
            for(int i=0; i<sessions->length; i++){
                if(last->session_ticket_len == f->current_session->session_ticket_len){
                    if(!memcmp(last->session_ticket, f->current_session->session_ticket, f->current_session->session_ticket_len)){
                        memcpy(f->master_secret, last->master_secret, SSL3_MASTER_SECRET_SIZE);

                        DEBUG_MSG(DEBUG_HS, "Found new session ticket (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
                        DEBUG_BYTES(DEBUG_HS, last->session_ticket, last->session_ticket_len);
                        break;
                    }
                }
                last = last->next;
            }
        }

    } else if (f->current_session->session_id_len > 0){
        //server refused resumption, save new session id
        DEBUG_MSG(DEBUG_HS, "session ids did not match, saving new id\n");
        save_session_id(f, p);
    }

    return 0;

}

/* Called from ClientHello. Checks to see if the session id len is > 0. If so,
 * saves sessionid for later verification. Also checks to see if a session
 * ticket is included as an extension.
 *
 *  Input:
 *  	f: the tagged flow
 *  	hs: a pointer to the ServerHello message
 *
 *  Output:
 *  	0 if success, 1 if failed
 */
static int check_extensions(flow *f, uint8_t *hs, uint32_t len){

    uint8_t *p = hs + HANDSHAKE_HEADER_LEN;
    p += 2; //skip version
    p += SSL3_RANDOM_SIZE; //skip random

    session *new_session = smalloc(sizeof(session));
    new_session->session_id_len = (uint8_t) p[0];
    new_session->session_ticket_len = 0;
    new_session->session_ticket = NULL;
    p  ++;

    if(new_session->session_id_len > 0){
        f->resume_session = 1;
        memcpy(new_session->session_id, p, new_session->session_id_len);
        new_session->next = NULL;

        DEBUG_MSG(DEBUG_HS, "Requested new session (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);

        DEBUG_MSG(DEBUG_HS, "session id: \n");
        DEBUG_BYTES(DEBUG_HS, p, new_session->session_id_len);

        f->current_session = new_session;
    }

    p += new_session->session_id_len;

    //check to see if there is a session ticket included

    //skip to extensions
    uint16_t ciphersuite_len = (p[0] << 8) + p[1];
    p += 2 + ciphersuite_len;
    uint8_t compress_meth_len = p[0];
    p += 1 + compress_meth_len;

    //search for SessionTicket TLS extension
    if(2 + SSL3_RANDOM_SIZE + new_session->session_id_len + 1 + 2 + ciphersuite_len + 1 + compress_meth_len > len){
        //no extension
        if(f->current_session == NULL)
            free(new_session);
        return 0;
    }
    uint16_t extensions_len = (p[0] << 8) + p[1];
    p += 2;
    while(extensions_len > 0){
        uint16_t type = (p[0] << 8) + p[1];
        p += 2;
        uint16_t ext_len = (p[0] << 8) + p[1];
        p += 2;
        if(type == 0x23){
            if(ext_len > 0){
                f->resume_session = 1;
                new_session->session_ticket_len = ext_len;
                new_session->session_ticket = scalloc(1, ext_len);
                memcpy(new_session->session_ticket, p, ext_len);
                f->current_session = new_session;
            }
        }
        if(type == 0x17){//Extended Master Secret
            f->extended_master_secret = 1;
        }
        p += ext_len;
        extensions_len -= (4 + ext_len);
    }

    if(!f->resume_session){
        free(new_session);
        f->stall = 0; //unstall the next packet
    }

    return 0;
}

/* Called from ServerHello. Cycles through extensions and verifies their use
 * in the flow.
 *
 *  Input:
 *  	f: the tagged flow
 *  	hs: a pointer to the ServerHello message
 *
 *  Output:
 *  	0 if success, 1 if failed
 */
static int verify_extensions(flow *f, uint8_t *hs, uint32_t len){

    uint8_t extended_master_secret = 0;
    uint32_t remaining_len = len;

    uint8_t *p = hs + HANDSHAKE_HEADER_LEN;

    p += 2; //skip version
    p += SSL3_RANDOM_SIZE; //skip random
    remaining_len -= (2 + SSL3_RANDOM_SIZE);

    remaining_len -= (uint8_t) p[0] + 1;
    p += (uint8_t) p[0] + 1; //skip session id

    p += 2; //skip cipher suite
    remaining_len -= 2;

    p ++; //skip compression method
    remaining_len --;

    if(remaining_len < 2){
        return 0;
    }

    //cycle through extensions
    uint16_t extensions_len = (p[0] << 8) + p[1];
    p += 2;
    while(extensions_len > 0){
        uint16_t type = (p[0] << 8) + p[1];
        p += 2;
        uint16_t ext_len = (p[0] << 8) + p[1];
        p += 2;

        if(type == 0x17){
            extended_master_secret = 1;
        }
        p += ext_len;
        extensions_len -= (4 + ext_len);
    }

    //Check to make sure both client and server included extension
    if(!f->extended_master_secret || !extended_master_secret){
        f->extended_master_secret = 0;
    } else {
        DEBUG_MSG(DEBUG_HS, "Extended master secret extension\n");
    }

    return 0;

}

/* Called from ServerHello during full handshake. Adds the session id to the
 * cache for later resumptions
 *
 *  Input:
 *  	f: the tagged flow
 *  	hs: a pointer to the ServerHello message
 *
 *  Output:
 *  	0 if success, 1 if failed
 */
static int save_session_id(flow *f, uint8_t *hs){

    //increment pointer to point to sessionid
    uint8_t *p = hs + HANDSHAKE_HEADER_LEN;
    p += 2; //skip version
    p += SSL3_RANDOM_SIZE; //skip random

    session *new_session = smalloc(sizeof(session));

    new_session->session_id_len = (uint8_t) p[0];
    if((new_session->session_id_len <= 0) || (new_session->session_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH)){
        //if this value is zero, the session is non-resumable or the
        //server will issue a NewSessionTicket handshake message
        free(new_session);
        return 0;
    }
    p++;
    memcpy(new_session->session_id, p, new_session->session_id_len);
    new_session->session_ticket_len = 0;
    new_session->session_ticket = NULL;
    new_session->next = NULL;

    if(f->current_session != NULL){
        free(f->current_session);
    }
    f->resume_session = 0;
    f->current_session = new_session;

    if(sessions->first_session == NULL){
        sessions->first_session = new_session;
        printf("First session id (%p->%p):", sessions, sessions->first_session);
        for(int i=0; i< new_session->session_id_len; i++){
            printf(" %02x", sessions->first_session->session_id[i]);
        }
        printf("\n");
    } else {
        session *last = sessions->first_session;

        for(int i=0; i< sessions->length -1; i++){
            if(last == NULL){
                printf("UH OH: last is null?\n");
                fflush(stdout);
            }
            last = last->next;
        }
        last->next = new_session;
    }

    sessions->length ++;

    DEBUG_MSG(DEBUG_HS, "Saved session id:");
    DEBUG_BYTES(DEBUG_HS, new_session->session_id, new_session->session_id_len);

    return 0;
}

/* Called from NewSessionTicket. Adds the session ticket to the
 * cache for later resumptions
 *
 *  Input:
 *  	f: the tagged flow
 *  	hs: a pointer to the ServerHello message
 *
 *  Output:
 *  	0 if success, 1 if failed
 */
int save_session_ticket(flow *f, uint8_t *hs, uint32_t len){

    DEBUG_MSG(DEBUG_HS, "TICKET HDR:");
    DEBUG_BYTES(DEBUG_HS, hs, HANDSHAKE_HEADER_LEN);

    uint8_t *p = hs + HANDSHAKE_HEADER_LEN;
    p += 4;
    session *new_session = scalloc(1, sizeof(session));

    new_session->session_id_len = 0;

    new_session->session_ticket_len = (p[0] << 8) + p[1];
    new_session->next = NULL;
    p += 2;

    uint8_t *ticket = smalloc(new_session->session_ticket_len);

    memcpy(ticket, p, new_session->session_ticket_len);
    new_session->session_ticket = ticket;
    memcpy(new_session->master_secret, f->master_secret, SSL3_MASTER_SECRET_SIZE);

    if(sessions->first_session == NULL){
        sessions->first_session = new_session;
    } else {
        session *last = sessions->first_session;

        for(int i=0; i< (sessions->length-1); i++){
            if(last == NULL){
                printf("UH OH: last is null?\n");
                fflush(stdout);
            }
            last = last->next;
        }
        last->next = new_session;
    }

    sessions->length ++;

    DEBUG_MSG(DEBUG_HS, "Saved session ticket:");
    DEBUG_BYTES(DEBUG_HS, p, new_session->session_ticket_len);

    DEBUG_MSG(DEBUG_HS, "Saved session master secret:");
    DEBUG_BYTES(DEBUG_HS, new_session->master_secret, SSL3_MASTER_SECRET_SIZE);

    return 0;
}

/* Adds a (handshake) packet to the flow's packet chain. If it can complete a record, passes
 * this record to update_flow
 *
 * Note: the code in slitheen.c should ensure that this function only ever gets the next
 * expected sequence number
 */
int add_packet(flow *f, struct packet_info *info){
    if (info->tcp_hdr == NULL || info->app_data_len <= 0){
        return 0;
    }

    packet *new_packet = smalloc(sizeof(packet));

    new_packet->seq_num = ntohl(info->tcp_hdr->sequence_num);
    new_packet->len = info->app_data_len;

    uint8_t *packet_data = smalloc(new_packet->len);
    memcpy(packet_data, info->app_data, new_packet->len);

    new_packet->data = packet_data;
    new_packet->next = NULL;
    uint8_t incoming = (info->ip_hdr->src.s_addr == f->src_ip.s_addr) ? 0 : 1;
    packet_chain *chain = (incoming) ? f->ds_packet_chain : f->us_packet_chain;
    queue *packet_queue = (incoming) ? f->ds_hs_queue : f->us_hs_queue;

    if(new_packet->seq_num < chain->expected_seq_num){
        //see if this packet contains any data we are missing
        //TODO: figure out how/why this happens and what should follow
        printf("ERROR: Received replayed packet O.o\n");

        free(new_packet->data);
        free(new_packet);
        remove_flow(f);
        return 1;

    }

    if(new_packet->seq_num > chain->expected_seq_num) {
        printf("ERROR: Received future packet O.o\n");
        free(new_packet->data);
        free(new_packet);
        remove_flow(f);
        return 1;
    }

    //temporary: see if it's the only packet, if so is new record
    if(peek(packet_queue, 0) == NULL){
        if(new_packet->seq_num == chain->expected_seq_num){
            const struct record_header *record_hdr = (struct record_header *) new_packet->data;
            chain->record_len = RECORD_LEN(record_hdr)+RECORD_HEADER_LEN;
            chain->remaining_record_len = chain->record_len;
        }
    }

    //append packet to queue
    enqueue(packet_queue, new_packet);


    chain->expected_seq_num += new_packet->len;

    uint32_t record_offset = 0; //offset into record for updating info with any changes
    uint32_t info_offset = 0; //offset into info for updating with changes
    uint32_t info_len = 0; //number of bytes that possibly changed

    //while there is still data left:
    uint32_t available_data = new_packet->len;

    while(available_data > 0){

        //if full record, give to update_flow
        if(chain->remaining_record_len <= new_packet->len){//we have enough to make a record
            chain->remaining_record_len = 0;
            uint8_t *record = smalloc(chain->record_len);
            uint32_t record_len = chain->record_len;
            uint32_t tmp_len = chain->record_len;

            packet *next = peek(packet_queue, 0);
            while(tmp_len > 0){
                if(tmp_len >= next->len){
                    memcpy(record+chain->record_len - tmp_len, next->data, next->len);
                    if(next == new_packet){
                        new_packet = NULL;//TODO: why?
                        record_offset = chain->record_len - tmp_len;
                        info_len = next->len;
                    }

                    tmp_len -= next->len;
                    //remove packet from queue
                    next = dequeue(packet_queue);
                    free(next->data);
                    free(next);
                    next = peek(packet_queue, 0); //TODO: Do we need this???
                    available_data = 0;

                } else { //didn't use up entire packet

                    memcpy(record+chain->record_len - tmp_len, next->data, tmp_len);
                    if(next == new_packet){//TODO: opposite shouldn't happen?
                        record_offset = chain->record_len - tmp_len;
                        info_len = tmp_len;
                    }

                    memmove(next->data, next->data+tmp_len, next->len - tmp_len);
                    next->len -= tmp_len;
                    available_data -= tmp_len;
                    tmp_len = 0;

                    //Last part of packet is a new record
                    const struct record_header *record_hdr = (struct record_header *) next->data;
                    chain->record_len = RECORD_LEN(record_hdr)+RECORD_HEADER_LEN;
                    chain->remaining_record_len = chain->record_len;

                }
            }

            //if handshake is complete, send to relay code
            if(f->application == 1){
                //update packet info and send to replace_packet
                struct packet_info *copy_info = copy_packet_info(info);
                copy_info->app_data = record;
                copy_info->app_data_len = record_len;
                replace_packet(f, copy_info);
                free(copy_info->app_data);
                free(copy_info);
            } else {
                if(update_flow(f, record, incoming)){
                    free(record);
                    return 1;//error occurred and flow was removed
                }

                if(f->in_encrypted ==2 && incoming){
                    //if server finished message was received, copy changes back to packet
                    DEBUG_MSG(DEBUG_HS, "Replacing info->data with finished message (%d bytes).\n", info_len);

                    DEBUG_MSG(DEBUG_HS, "Previous bytes:\n");
                    DEBUG_BYTES(DEBUG_HS, (info->app_data + info_offset), info_len);

                    DEBUG_MSG(DEBUG_HS, "New bytes:\n");
                    DEBUG_BYTES(DEBUG_HS, (record + record_offset), info_len);

                    DEBUG_MSG(DEBUG_HS, "Previous packet contents:\n");
                    DEBUG_BYTES(DEBUG_HS, info->app_data, info->app_data_len);

                    memcpy(info->app_data+info_offset, record+record_offset, info_len);

                    DEBUG_MSG(DEBUG_HS, "SLITHEEN: Current packet contents:\n");
                    DEBUG_BYTES(DEBUG_HS, info->app_data, info->app_data_len);

                    //update TCP checksum
                    tcp_checksum(info);
                }
                free(record);

                if(new_packet != NULL){
                    info_offset += info_len;
                }

            }
        } else {//can't make a full record yet
            chain->remaining_record_len -= new_packet->len;
            available_data = 0;
        }
    } //exhausted new packet len

    return 0;

}
