
/* Slitheen - a decoy routing system for censorship resistance
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
#ifndef FLOW_H
#define FLOW_H

#include <netinet/in.h>
#include <semaphore.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include "ptwist.h"
#include "packet.h"
#include "util.h"

#define MAX_FLOWS 10
#define SLITHEEN_ID_LEN 28

struct client_st;
typedef struct client_st client;

typedef struct packet_st{
    uint32_t seq_num;
    uint16_t len;
    uint8_t *data;
    uint32_t expiration;
    struct packet_st *next;
} packet;

typedef struct packet_chain_st packet_chain;

typedef struct queue_block_st{
    int32_t len;
    int32_t offset;
    uint8_t *data;
    struct queue_block_st *next;
    uint16_t stream_id;
} queue_block;

typedef struct data_queue_st {
    queue_block *first_block;
} data_queue;

typedef struct app_data_queue_st {
    packet *first_packet;
} app_data_queue;

typedef struct frame_st {
    uint8_t *packet;
    const struct pcap_pkthdr *header;
    struct inject_args *iargs;
    uint32_t seq_num;
    struct frame_st *next;
} frame;

typedef struct frame_queue_st {
    frame *first_frame;
} frame_queue;

typedef struct session_st {
    uint8_t session_id_len;
    uint8_t session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    struct session_st *next;
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];
    uint8_t client_random[SSL3_RANDOM_SIZE];
    uint8_t server_random[SSL3_RANDOM_SIZE];
    uint32_t session_ticket_len;
    uint8_t *session_ticket;
} session;

typedef struct flow_st {
    sem_t flow_lock;

    uint32_t ref_ctr;
    uint8_t removed;

    struct in_addr src_ip, dst_ip; /* Source (client) and Destination (server) addresses */
    uint16_t src_port, dst_port;	/* Source and Destination ports */

    uint32_t upstream_seq_num;		/* sequence number */
    uint32_t downstream_seq_num;		/* sequence number */

    app_data_queue *upstream_app_data;	/* Saved application-layer data for packet retransmits */
    app_data_queue *downstream_app_data;

    frame_queue *us_frame_queue; /*Held misordered Ethernet frames to be processed and written out later */
    frame_queue *ds_frame_queue; /*Held misordered Ethernet frames to be processed and written out later */

    byte key[16];		/* negotiated key */
    int state;		/* TLS handshake state */
    int in_encrypted;		/* indicates whether incoming flow is encrypted */
    int out_encrypted;		/* indicates whether outgoing flow is encrypted */
    int application; /* indicates handshake is complete */
    int stall; /* indicates the Finished message is expected and relay station should stall */
    int resume_session;
    data_queue *downstream_queue; //TODO: delete (reference client)
    client *client_ptr;

    packet_chain *ds_packet_chain;
    packet_chain *us_packet_chain;
    queue *ds_hs_queue;
    queue *us_hs_queue;
    sem_t packet_chain_lock;

    queue_block *upstream_queue;
    uint32_t upstream_remaining;
    DH *dh;
    EC_KEY *ecdh;
    EVP_PKEY *srvr_key;
    sem_t upstream_queue_lock;

    const EVP_CIPHER *cipher;
    const EVP_MD *message_digest;
    uint8_t keyex_alg;
    uint8_t extended_master_secret;
    uint8_t handshake_hash[EVP_MAX_MD_SIZE];
    EVP_CIPHER_CTX *clnt_read_ctx;
    EVP_CIPHER_CTX *clnt_write_ctx;
    EVP_CIPHER_CTX *srvr_read_ctx;
    EVP_CIPHER_CTX *srvr_write_ctx;
    EVP_MD_CTX *read_mac_ctx;
    EVP_MD_CTX *write_mac_ctx;
    EVP_MD_CTX *hs_md_ctx;

    GCM128_CONTEXT *gcm_ctx_out;
    uint8_t *gcm_ctx_iv;
    int32_t gcm_ctx_ivlen;
    AES_KEY *gcm_ctx_key;

    uint8_t client_random[SSL3_RANDOM_SIZE];
    uint8_t server_random[SSL3_RANDOM_SIZE];
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];

    session *current_session;

    uint8_t read_seq[8];
    uint8_t write_seq[8];

    //for downstream processing
    uint32_t remaining_record_len;
    uint8_t httpstate;
    uint8_t webmstate;
    uint64_t remaining_element;
    uint32_t remaining_response_len;
    uint8_t replace_response;

    uint8_t *outbox;
    int32_t outbox_len;
    int32_t outbox_offset;

    uint8_t *partial_record_header;
    uint8_t partial_record_header_len;

    uint8_t *partial_record;
    uint8_t *partial_record_dec;
    uint32_t partial_record_len;
    uint32_t partial_record_total_len;

    //locking
    //pthread_mutex_t flow_lock = PTHREAD_MUTEX_INITIALIZER;

} flow;

int init_tables(void);
flow *add_flow(struct packet_info *info);
int remove_flow(flow *f);
flow *check_flow(struct packet_info *info);

int init_session_cache (void);
int add_packet(flow *f, struct packet_info *info);

#endif /* FLOW_H */
