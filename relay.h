
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
#ifndef RELAY_H
#define RELAY_H

#include "flow.h"
#include <stdint.h>

typedef struct stream_table_st stream_table;

typedef struct client_st {
    uint8_t slitheen_id[SLITHEEN_ID_LEN];
    stream_table *streams;
    data_queue *downstream_queue;
    sem_t queue_lock;
    uint32_t encryption_counter;
    struct client_st *next;
    uint8_t *header_key;
    uint8_t *body_key;
    EVP_MD_CTX *mac_ctx;
} client;

typedef struct client_table_st {
    client *first;
} client_table;

extern client_table *clients;

int replace_packet(flow *f, struct packet_info *info);
uint16_t tcp_checksum(struct packet_info *info);

#endif /* RELAY_H */
