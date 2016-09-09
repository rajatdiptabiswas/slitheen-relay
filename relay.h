#ifndef _RELAY_H_
#define _RELAY_H_

#include "flow.h"
#include <stdint.h>

struct proxy_thread_data {
	uint8_t *initial_data;
	uint16_t initial_len;
	uint16_t stream_id;
	int32_t pipefd;
	stream_table *streams;
	data_queue *downstream_queue;
};

typedef struct client_st {
	uint8_t slitheen_id[SLITHEEN_ID_LEN];
	stream_table *streams;
	data_queue *downstream_queue;
	uint16_t encryption_counter;
	struct client_st *next;
	uint8_t *header_key;
	uint8_t *body_key;
	//uint8_t *mac_key
	//EVP_CIPHER_CTX *header_ctx;
	//EVP_CIPHER_CTX *body_ctx;
	EVP_MD_CTX *mac_ctx;
} client;

typedef struct client_table_st {
	client *first;
} client_table;

extern client_table *clients;

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

int replace_packet(flow *f, struct packet_info *info);
int process_downstream(flow *f, int32_t offset, struct packet_info *info);
int read_header(flow *f, struct packet_info *info);
uint32_t get_response_length(uint8_t *response);
int fill_with_downstream(flow *f, uint8_t *data, int32_t length);
uint16_t tcp_checksum(struct packet_info *info);

void *proxy_covert_site(void *data);

#define BEGIN_HEADER 0x10
#define PARSE_HEADER 0x20
#define MID_CONTENT 0x30
#define BEGIN_CHUNK 0x40
#define MID_CHUNK 0x50
#define END_CHUNK 0x60
#define END_BODY 0x70
#define FORFEIT_REST 0x80
#define USE_REST 0x90

#endif /* _RELAY_H_ */
