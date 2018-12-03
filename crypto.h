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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "flow.h"

int update_handshake_hash(flow *f, uint8_t *hs);
int extract_parameters(flow *f, uint8_t *hs);
int encrypt(flow *f, uint8_t *input, uint8_t *output, int32_t len, int32_t incoming, int32_t type, int32_t enc, uint8_t re);
int extract_server_random(flow *f, uint8_t *hs);
int compute_master_secret(flow *f);

int mark_finished_hash(flow *f, uint8_t *hs);
int init_ciphers(flow *f);
void generate_client_super_keys(uint8_t *secret, client *c);
int super_encrypt(client *c, uint8_t *data, uint32_t len);
int check_handshake(struct packet_info *info);

int partial_aes_gcm_tls_cipher(flow *f, unsigned char *out, const unsigned char *in, size_t len, size_t offset, uint8_t enc);
void partial_aes_gcm_tls_tag(flow *f, unsigned char *tag);

#endif /* CRYPTO_H */
