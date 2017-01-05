#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "flow.h"
#include "ptwist.h"

#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
							(((unsigned int)(c[1]))    )),c+=2)


/* Curves */


int extract_parameters(flow *f, uint8_t *hs);
int encrypt(flow *f, uint8_t *input, uint8_t *output, int32_t len, int32_t incoming, int32_t type, int32_t enc, uint8_t re);
int extract_server_random(flow *f, uint8_t *hs);
int compute_master_secret(flow *f);

int PRF(flow *f, uint8_t *secret, int32_t secret_len,
		uint8_t *seed1, int32_t seed1_len,
		uint8_t *seed2, int32_t seed2_len,
		uint8_t *seed3, int32_t seed3_len,
		uint8_t *seed4, int32_t seed4_len,
		uint8_t *output, int32_t output_len);

int update_finish_hash(flow *f, uint8_t *hs);
int verify_finish_hash(flow *f, uint8_t *p, int32_t incoming);
int init_ciphers(flow *f);
void generate_client_super_keys(uint8_t *secret, client *c);
int super_encrypt(client *c, uint8_t *data, uint32_t len);
void check_handshake(struct packet_info *info);

int check_tag(byte key[16], const byte privkey[PTWIST_BYTES],
	const byte tag[PTWIST_TAG_BYTES], const byte *context,
	size_t context_len);
#define PRE_MASTER_MAX_LEN BUFSIZ

#define SLITHEEN_KEYGEN_CONST "SLITHEEN_KEYGEN"
#define SLITHEEN_KEYGEN_CONST_SIZE 15

#define SLITHEEN_FINISHED_INPUT_CONST "SLITHEEN_FINISH"
#define SLITHEEN_FINISHED_INPUT_CONST_SIZE 15

#define SLITHEEN_SUPER_SECRET_SIZE 16 //extracted from slitheen ID tag
#define SLITHEEN_SUPER_CONST "SLITHEEN_SUPER_ENCRYPT"
#define SLITHEEN_SUPER_CONST_SIZE 22

#endif
