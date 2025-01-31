/* Name: crypto.c
 *
 * This file contains code for checking tagged flows, processing handshake
 * messages, and computing the master secret for a TLS session.
 */
/* Some code in this document is based on the OpenSSL source files:
 * 	crypto/ec/ec_key.c
 * 	crypto/dh/dh_key.c
 */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions originally developed by SUN MICROSYSTEMS, INC., and
 * contributed to the OpenSSL project.
 */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#include "ptwist.h"
#include "crypto.h"
#include "flow.h"
#include "packet.h"
#include "util.h"
#include "relay.h"

#define NID_sect163k1           721
#define NID_sect163r1           722
#define NID_sect163r2           723
#define NID_sect193r1           724
#define NID_sect193r2           725
#define NID_sect233k1           726
#define NID_sect233r1           727
#define NID_sect239k1           728
#define NID_sect283k1           729
#define NID_sect283r1           730
#define NID_sect409k1           731
#define NID_sect409r1           732
#define NID_sect571k1           733
#define NID_sect571r1           734
#define NID_secp160k1           708
#define NID_secp160r1           709
#define NID_secp160r2           710
#define NID_secp192k1           711
#define NID_X9_62_prime192v1            409
#define NID_secp224k1           712
#define NID_secp224r1           713
#define NID_secp256k1           714
#define NID_X9_62_prime256v1            415
#define NID_secp384r1           715
#define NID_secp521r1           716
#define NID_brainpoolP256r1             927
#define NID_brainpoolP384r1             931
#define NID_brainpoolP512r1             933
#define NID_X25519             1034

#define SLITHEEN_KEYGEN_CONST "SLITHEEN_KEYGEN"
#define SLITHEEN_KEYGEN_CONST_SIZE 15
#define SLITHEEN_FINISHED_INPUT_CONST "SLITHEEN_FINISHED"
#define SLITHEEN_FINISHED_INPUT_CONST_SIZE 17
#define SLITHEEN_SUPER_SECRET_SIZE 16 //extracted from slitheen ID tag
#define SLITHEEN_SUPER_CONST "SLITHEEN_SUPER_ENCRYPT"
#define SLITHEEN_SUPER_CONST_SIZE 22

#define PRE_MASTER_MAX_LEN BUFSIZ
#define TLS_MD_EXTENDED_MASTER_SECRET_CONST "extended master secret"
#define TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE 22

#define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
            (((unsigned int)(c[1]))    )),c+=2)


/* Curve 25519 */
#define X25519_KEYLEN        32
#define X25519_BITS          253
#define X25519_SECURITY_BITS 128

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
typedef struct {
    unsigned char pubkey[X25519_KEYLEN];
    unsigned char *privkey;
} X25519_KEY;
#endif

static int nid_list[] = {
    NID_sect163k1,              /* sect163k1 (1) */
    NID_sect163r1,              /* sect163r1 (2) */
    NID_sect163r2,              /* sect163r2 (3) */
    NID_sect193r1,              /* sect193r1 (4) */
    NID_sect193r2,              /* sect193r2 (5) */
    NID_sect233k1,              /* sect233k1 (6) */
    NID_sect233r1,              /* sect233r1 (7) */
    NID_sect239k1,              /* sect239k1 (8) */
    NID_sect283k1,              /* sect283k1 (9) */
    NID_sect283r1,              /* sect283r1 (10) */
    NID_sect409k1,              /* sect409k1 (11) */
    NID_sect409r1,              /* sect409r1 (12) */
    NID_sect571k1,              /* sect571k1 (13) */
    NID_sect571r1,              /* sect571r1 (14) */
    NID_secp160k1,              /* secp160k1 (15) */
    NID_secp160r1,              /* secp160r1 (16) */
    NID_secp160r2,              /* secp160r2 (17) */
    NID_secp192k1,              /* secp192k1 (18) */
    NID_X9_62_prime192v1,       /* secp192r1 (19) */
    NID_secp224k1,              /* secp224k1 (20) */
    NID_secp224r1,              /* secp224r1 (21) */
    NID_secp256k1,              /* secp256k1 (22) */
    NID_X9_62_prime256v1,       /* secp256r1 (23) */
    NID_secp384r1,              /* secp384r1 (24) */
    NID_secp521r1,              /* secp521r1 (25) */
    NID_brainpoolP256r1,        /* brainpoolP256r1 (26) */
    NID_brainpoolP384r1,        /* brainpoolP384r1 (27) */
#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    NID_brainpoolP512r1,       /* brainpool512r1 (28) */
    NID_X25519                 /* X25519 (29) */
#else
    NID_brainpoolP512r1         /* brainpool512r1 (28) */
#endif
};

static int tls_PRF(flow *f, uint8_t *secret, int32_t secret_len,
        uint8_t *seed1, int32_t seed1_len,
        uint8_t *seed2, int32_t seed2_len,
        uint8_t *seed3, int32_t seed3_len,
        uint8_t *seed4, int32_t seed4_len,
        uint8_t *output, int32_t output_len);

static int check_tag(byte key[16], const byte privkey[PTWIST_BYTES],
        const byte tag[PTWIST_TAG_BYTES], const byte *context,
        size_t context_len);

/** Updates the hash of all TLS handshake messages up to and
 * including the ClientKeyExchange. This hash is eventually used
 *  to compute the TLS extended master secret.
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	hs: A pointer to the start of the handshake message
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int update_handshake_hash(flow *f, uint8_t *hs){
    //find handshake length
    const struct handshake_header *hs_hdr;
    uint8_t *p = hs;
    hs_hdr = (struct handshake_header*) p;
    uint32_t hs_len = HANDSHAKE_MESSAGE_LEN(hs_hdr);

    EVP_DigestUpdate(f->hs_md_ctx, hs, hs_len+4);

    DEBUG_MSG(DEBUG_HS, "Adding to handshake hash:\n");
    DEBUG_BYTES(DEBUG_HS, hs, hs_len);

    return 0;
}
/** Extracts the server parameters from the server key
 *  exchange message
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	hs: the beginning of the server key exchange
 *  		handshake message
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int extract_parameters(flow *f, uint8_t *hs){
    uint8_t *p;
    long i;

    int ok=1;

    p = hs + HANDSHAKE_HEADER_LEN;

    if(f->keyex_alg == 1){
        DH *dh;

        if((dh = DH_new()) == NULL){
            return 1;
        }

        /* Extract prime modulus */
        n2s(p,i);

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        BIGNUM *prime = NULL;
        if(!(prime = BN_bin2bn(p,i,NULL))){
            return 1;
        }
#else
        if(!(dh->p = BN_bin2bn(p,i,NULL))){
            return 1;
        }
#endif
        p += i;

        /* Extract generator */
        n2s(p,i);

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        BIGNUM *group = NULL;
        if(!(group = BN_bin2bn(p,i,NULL))){
            return 1;
        }

        if(!DH_set0_pqg(dh, prime, NULL, group)){
            return 1;
        }
#else
        if(!(dh->g = BN_bin2bn(p,i,NULL))){
            return 1;
        }
#endif
        p += i;

        /* Extract server public value */
        n2s(p,i);

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        BIGNUM *pub = NULL;
        if(!(pub = BN_bin2bn(p,i,NULL))){
            return 1;
        }
        if(!DH_set0_key(dh, pub, NULL)){
            return 1;
        }
#else
        if(!(dh->pub_key = BN_bin2bn(p,i,NULL))){
            return 1;
        }
#endif

        f->dh = dh;
    } else if (f->keyex_alg == 2){
        EC_KEY *ecdh = NULL;
        EC_GROUP *ngroup;
        const EC_GROUP *group;

        BN_CTX *bn_ctx = NULL;
        EC_POINT *srvr_ecpoint = NULL;
        int curve_nid = 0;
        int encoded_pt_len = 0;

        if(p[0] != 0x03){//not a named curve
            goto err;
        }

        //int curve_id = (p[1] << 8) + p[2];
        int curve_id = *(p+2);

        DEBUG_MSG(DEBUG_HS, "Using curve number %d\n", curve_id);

        if((curve_id < 0) || ((unsigned int)curve_id >
                    sizeof(nid_list) / sizeof(nid_list[0]))){
            goto err;
        }

        curve_nid = nid_list[curve_id-1];


#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        if(curve_nid == NID_X25519){
            //this is a custom curve and must be handled differently
            EVP_PKEY *key = EVP_PKEY_new();

            if (key == NULL || !EVP_PKEY_set_type(key, curve_nid)){
                EVP_PKEY_free(key);
                goto err;
            }

            p += 3;
            encoded_pt_len = *p;
            p += 1;

            EVP_PKEY_set1_tls_encodedpoint(key, p, encoded_pt_len);
            f->srvr_key = key;


        } else {
#endif	
            if((ecdh = EC_KEY_new()) == NULL) {
                goto err;
            }

            ngroup = EC_GROUP_new_by_curve_name(curve_nid);

            if(ngroup == NULL){
                DEBUG_MSG(DEBUG_HS, "couldn't get curve by name (%d)\n", curve_nid);
                goto err;
            }

            if(EC_KEY_set_group(ecdh, ngroup) == 0){
                printf("couldn't set group\n");
                goto err;
            }
            EC_GROUP_free(ngroup);

            group = EC_KEY_get0_group(ecdh);

            p += 3;

            /* Get EC point */
            if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) || 
                    ((bn_ctx = BN_CTX_new()) == NULL)) {
                goto err;
            }

            encoded_pt_len = *p;
            p += 1;

            if(EC_POINT_oct2point(group, srvr_ecpoint, p, encoded_pt_len, 
                        bn_ctx) == 0){
                goto err;
            }
            EC_KEY_set_public_key(ecdh, srvr_ecpoint);
            f->ecdh = ecdh;

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        }
#endif

        ecdh = NULL;
        BN_CTX_free(bn_ctx);
        bn_ctx = NULL;
        EC_POINT_free(srvr_ecpoint);
        srvr_ecpoint = NULL;
        ok=0;

err:
        if(bn_ctx != NULL){
            BN_CTX_free(bn_ctx);
        }
        if(srvr_ecpoint != NULL){
            EC_POINT_free(srvr_ecpoint);
        }
        if(ecdh != NULL){
            EC_KEY_free(ecdh);
        }

    }
    return ok;
}

/* Encrypt/Decrypt a TLS record
 *
 *  Inputs:
 * 		f: the tagged flow
 * 		input: a pointer to the data that is to be encrypted/
 * 			   decrypted
 * 		output: a pointer to where the data should be written
 * 				after it is encrypted or decrypted
 * 		len: the length of the data
 * 		incoming: the direction of the record
 * 		type: the type of the TLS record
 * 		enc: 1 for encryption, 0 for decryption
 * 		re:	 1 if this is a re-encryption (counters are reset), 0 otherwise
 * 			 Note: is only checked during encryption
 *
 * 	Output:
 * 		length of the output data
 */
int encrypt(flow *f, uint8_t *input, uint8_t *output, int32_t len, int32_t incoming, int32_t type, int32_t enc, uint8_t re){
    uint8_t *p = input;

    EVP_CIPHER_CTX *ds = (incoming) ? ((enc) ? f->srvr_write_ctx : f->clnt_read_ctx) : ((enc) ? f->clnt_write_ctx : f->srvr_read_ctx);
    if(ds == NULL){
        printf("FAIL\n");
        return 1;
    }

    uint8_t *seq;
    seq = (incoming) ? f->read_seq : f->write_seq;

    if(enc && re){
        for(int i=7; i>=0; i--){
            --seq[i];
            if(seq[i] != 0xff)
                break;
        }
    }

    uint8_t buf[13];
    memcpy(buf, seq, 8);

    for(int i=7; i>=0; i--){
        ++seq[i];
        if(seq[i] != 0)
            break;
    }

    buf[8] = type;
    buf[9] = 0x03;
    buf[10] = 0x03;
    buf[11] = len >> 8; //len >> 8;
    buf[12] = len & 0xff;//len *0xff;
    int32_t pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
            13, buf); // = int32_t pad?

    if(enc)
        len += pad;

    int32_t n = EVP_Cipher(ds, p, p, len); //decrypt in place
    if(n<0) return 0;

    DEBUG_MSG(DEBUG_CRYPTO, "decrypted data:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, p, len);

    if(!enc)
        p[EVP_GCM_TLS_EXPLICIT_IV_LEN+n] = '\0';

    return n;
}


/** Mark the hash in a downstream TLS finished message
 *
 * Changes the finished hash to
 * SHA256_HMAC_96(shared_key, "SLITHEEN_FINISHED" || old_finished_hash)
 *
 * This feature detects and prevents suspicious behaviour in the event
 * of a MiTM or RAD attack.
 *
 * 	Inputs:
 * 		f: the tagged flow
 * 		hs: a pointer to the TLS Finished handshake message
 *
 * 	Output:
 * 		0 on success, 1 on failure
 *              if success, the message pointed to by hs will have
 *                      been updated
 */
int mark_finished_hash(flow *f, uint8_t *hs){
    HMAC_CTX *ctx = NULL;
    uint8_t hmac_output[EVP_MAX_MD_SIZE];
    unsigned int hmac_output_len;

    // Ensure this is a Finished message, of length 12 bytes
    if (memcmp(hs, "\x14\x00\x00\x0c", 4)) {
        return 1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    ctx = HMAC_CTX_new();
#else
    ctx = scalloc(1, sizeof(HMAC_CTX));
    HMAC_CTX_init(ctx);
#endif
    HMAC_Init_ex(ctx, f->key, 16, EVP_sha256(), NULL);
    HMAC_Update(ctx, (const unsigned char *)SLITHEEN_FINISHED_INPUT_CONST, SLITHEEN_FINISHED_INPUT_CONST_SIZE);
    HMAC_Update(ctx, hs+4, 12);
    HMAC_Final(ctx, hmac_output, &hmac_output_len);
#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    HMAC_CTX_free(ctx);
#else
    HMAC_CTX_cleanup(ctx);
    free(ctx);
#endif

    if (hmac_output_len != 32) {
        return 1;
    }

    memmove(hs+4, hmac_output, 12);

    return 0;
}


/** Computes the TLS master secret from the decoy server's
 *  public key parameters and the leaked secret from the
 *  extracted Slitheen tag
 *
 *  Input:
 *  	f: the tagged flow
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int compute_master_secret(flow *f){

    DEBUG_MSG(DEBUG_CRYPTO, "Computing master secret (%x:%d -> %x:%d)...\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);

    DH *dh_srvr = NULL;
    DH *dh_clnt = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL, *order = NULL;

    EC_KEY *clnt_ecdh = NULL;
    EC_POINT *e_pub_key = NULL;

    int ok =1;

    uint8_t *pre_master_secret = scalloc(1, PRE_MASTER_MAX_LEN);

    int32_t pre_master_len;
    uint32_t l;
    int32_t bytes;

    uint8_t *buf = NULL;

    if(f->keyex_alg == 1){
        BN_MONT_CTX *mont = NULL;

        ctx = BN_CTX_new();

        dh_srvr = f->dh;

        if(dh_srvr == NULL){
            goto err;
        }

        dh_clnt = DHparams_dup(dh_srvr);

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        const BIGNUM *p, *q, *g;
        DH_get0_pqg(dh_clnt, &p, &q, &g);
        l = DH_get_length(dh_clnt) ? DH_get_length(dh_clnt) : BN_num_bits(p) - 1;
#else
        l = dh_clnt->length ? dh_clnt->length : BN_num_bits(dh_clnt->p) - 1;
#endif
        bytes = (l+7) / 8;

        buf = (uint8_t *)OPENSSL_malloc(bytes);
        if (buf == NULL){
            BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        pub_key = BN_new();
        priv_key = BN_new();

        DEBUG_MSG(DEBUG_CRYPTO, "tag key =");
        DEBUG_BYTES(DEBUG_CRYPTO, f->key, 16);

        const EVP_MD *tmp = f->message_digest;
        f->message_digest = EVP_sha256();
        tls_PRF(f, f->key, 16,
                (uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
                NULL, 0, NULL, 0, NULL, 0,
                buf, bytes);
        f->message_digest = tmp;

        DEBUG_MSG(DEBUG_CRYPTO, "Generated the client private key [len: %d]: ", bytes);
        DEBUG_BYTES(DEBUG_CRYPTO, buf, bytes);

        if (!BN_bin2bn(buf, bytes, priv_key))
            goto err;

        {
            BIGNUM *prk;

            prk = priv_key;

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
            if (!BN_mod_exp_mont(pub_key, g, prk, p, ctx, mont)){
                goto err;
            }
#else
            if (!dh_clnt->meth->bn_mod_exp(dh_clnt, pub_key, dh_clnt->g, prk, dh_clnt->p, ctx, mont)){
                goto err;
            }
#endif
        }

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        if(!DH_set0_key(dh_clnt, pub_key, priv_key)){
            goto err;
        }
        const BIGNUM *srvr_pub, *srvr_priv;
        DH_get0_key(dh_srvr, &srvr_pub, &srvr_priv);
        pre_master_len = DH_compute_key(pre_master_secret, srvr_pub, dh_clnt);
#else
        dh_clnt->pub_key = pub_key;
        dh_clnt->priv_key = priv_key;
        pre_master_len = DH_compute_key(pre_master_secret, dh_srvr->pub_key, dh_clnt);
#endif


    } else if(f->keyex_alg == 2){
        const EC_GROUP *srvr_group = NULL;
        const EC_POINT *srvr_ecpoint = NULL;
        EC_KEY *tkey;

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        if(f->srvr_key != NULL){

            EVP_PKEY *ckey, *skey;
            EVP_PKEY_CTX *pctx;
            skey = f->srvr_key;

            /* Generate client key from tag */
            X25519_KEY *xkey = OPENSSL_zalloc(sizeof(*xkey));
            xkey->privkey = OPENSSL_secure_malloc(X25519_KEYLEN);

            if(xkey->privkey == NULL){
                goto err;
            }

            const EVP_MD *tmp = f->message_digest;
            f->message_digest = EVP_sha256();
            tls_PRF(f, f->key, 16, (uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
                    NULL, 0, NULL, 0, NULL, 0, xkey->privkey, X25519_KEYLEN);
            f->message_digest = tmp;

            DEBUG_MSG(DEBUG_CRYPTO, "Generated the X25519 client private key [len: %d]: ", X25519_KEYLEN);
            DEBUG_BYTES(DEBUG_CRYPTO, xkey->privkey, X25519_KEYLEN);

            ckey = EVP_PKEY_new();
            EVP_PKEY_assign(ckey, NID_X25519, xkey);

            pctx = EVP_PKEY_CTX_new(ckey, NULL);

            if (EVP_PKEY_derive_init(pctx) <= 0
                    || EVP_PKEY_derive_set_peer(pctx, skey) <= 0
                    || EVP_PKEY_derive(pctx, NULL, (uint64_t *) &pre_master_len) <= 0) {
                goto err;
            }

            if (EVP_PKEY_derive(pctx, pre_master_secret, (uint64_t *) &pre_master_len) <= 0)
                goto err;

            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(ckey);

        } else { /* TODO: need to generate client key in a special way too :S */
#endif
            tkey = f->ecdh;
            if(tkey == NULL){
                goto err;
            }

            srvr_group = EC_KEY_get0_group(tkey);
            srvr_ecpoint = EC_KEY_get0_public_key(tkey);

            if((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
                goto err;
            }

            if((clnt_ecdh = EC_KEY_new()) == NULL) {
                goto err;
            }

            if(!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
                goto err;
            }

            /* Now generate key from tag */

            if((order = BN_new()) == NULL){
                goto err;
            }
            if((ctx = BN_CTX_new()) == NULL){
                goto err;
            }

            if((priv_key = BN_new()) == NULL){
                goto err;
            }

            if(!EC_GROUP_get_order(srvr_group, order, ctx)){
                goto err;
            }

            l = BN_num_bits(order);
            bytes = (l+7)/8;

            buf = (unsigned char *)OPENSSL_malloc(bytes);
            if(buf == NULL){
                goto err;
            }

            const EVP_MD *tmp = f->message_digest;
            f->message_digest = EVP_sha256();
            tls_PRF(f, f->key, 16, (uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
                    NULL, 0, NULL, 0, NULL, 0, buf, bytes);
            f->message_digest = tmp;

            DEBUG_MSG(DEBUG_CRYPTO, "Generated the client private key [len: %d]: ", bytes);
            DEBUG_BYTES(DEBUG_CRYPTO, buf, bytes);

            if(!BN_bin2bn(buf, bytes, priv_key)){
                goto err;
            }

            if((e_pub_key = EC_POINT_new(srvr_group)) == NULL){
                goto err;
            }

            if(!EC_POINT_mul(EC_KEY_get0_group(clnt_ecdh), e_pub_key, priv_key, NULL, NULL, ctx)){
                goto err;
            }

            EC_KEY_set_private_key(clnt_ecdh, priv_key);
            EC_KEY_set_public_key(clnt_ecdh, e_pub_key);


            /*Compute the master secret */
            int32_t field_size = EC_GROUP_get_degree(srvr_group);
            if(field_size <= 0){
                goto err;
            }
            pre_master_len = ECDH_compute_key(pre_master_secret, (field_size + 7) / 8,
                    srvr_ecpoint, clnt_ecdh, NULL);
            if(pre_master_len <= 0) {
                goto err;
            }
#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        }
#endif
    } else {
        //keyex_alg not set, goto error
        printf("keyex_alg not set\n");
        goto err;
    }

    /*Generate master secret */

    if(f->extended_master_secret){

        //compute session hash
        EVP_MD_CTX *md_ctx = NULL;
        uint8_t hash[EVP_MAX_MD_SIZE*2];
        uint32_t hash_len;

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        md_ctx = EVP_MD_CTX_new();
#else
        md_ctx = scalloc(1, sizeof(EVP_MD_CTX));
        EVP_MD_CTX_init(md_ctx);
#endif
        EVP_MD_CTX_copy_ex(md_ctx, f->hs_md_ctx);
        EVP_DigestFinal_ex(md_ctx, hash, &hash_len);

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
        EVP_MD_CTX_free(md_ctx);
#else
        EVP_MD_CTX_cleanup(md_ctx);
        free(md_ctx);
#endif

        tls_PRF(f, pre_master_secret, pre_master_len, (uint8_t *) TLS_MD_EXTENDED_MASTER_SECRET_CONST, TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE, hash, hash_len, NULL, 0, NULL, 0, f->master_secret, SSL3_MASTER_SECRET_SIZE);

        DEBUG_MSG(DEBUG_CRYPTO, "Premaster Secret:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, pre_master_secret, pre_master_len);
        DEBUG_MSG(DEBUG_CRYPTO, "Handshake hash:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, hash, hash_len);
        DEBUG_MSG(DEBUG_CRYPTO, "Master Secret:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, f->master_secret, SSL3_MASTER_SECRET_SIZE);

    } else {

        tls_PRF(f, pre_master_secret, pre_master_len, (uint8_t *) TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE, f->client_random, SSL3_RANDOM_SIZE, f->server_random, SSL3_RANDOM_SIZE, NULL, 0, f->master_secret, SSL3_MASTER_SECRET_SIZE);

        DEBUG_MSG(DEBUG_CRYPTO, "Premaster Secret:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, pre_master_secret, pre_master_len);
        DEBUG_MSG(DEBUG_CRYPTO, "Client Random:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, f->client_random, SSL3_RANDOM_SIZE);
        DEBUG_MSG(DEBUG_CRYPTO, "Server Random:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, f->server_random, SSL3_RANDOM_SIZE);
        DEBUG_MSG(DEBUG_CRYPTO, "Master Secret:\n");
        DEBUG_BYTES(DEBUG_CRYPTO, f->master_secret, SSL3_MASTER_SECRET_SIZE);
    }

    if(f->current_session != NULL){
        memcpy(f->current_session->master_secret, f->master_secret, SSL3_MASTER_SECRET_SIZE);
    }


    //remove pre_master_secret from memory
    memset(pre_master_secret, 0, PRE_MASTER_MAX_LEN);
    ok = 0;

err:
    if((pub_key != NULL) && (dh_srvr == NULL)){
        BN_free(pub_key);
    }
    if((priv_key != NULL) && ((dh_clnt == NULL) || (EC_KEY_get0_private_key(clnt_ecdh) == NULL))){
        BN_free(priv_key);
    }

    if(ctx != NULL){
        BN_CTX_free(ctx);
    }

    OPENSSL_free(buf);
    free(pre_master_secret);
    if(dh_srvr != NULL){
        DH_free(dh_srvr);
        f->dh = NULL;
    }
    if(dh_clnt != NULL) {
        DH_free(dh_clnt);
    }

    if(order){
        BN_free(order);
    }
    if(clnt_ecdh != NULL){
        EC_KEY_free(clnt_ecdh);
    }
    if(e_pub_key != NULL){
        EC_POINT_free(e_pub_key);
    }


    return ok;
}

/** Saves the random none from the server hello message
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	hs: a pointer to the beginning of the server hello msg
 *  
 *  Output:
 *  	0 on success, 1 on failure
 */
int extract_server_random(flow *f, uint8_t *hs){

    uint8_t *p;

    p = hs + HANDSHAKE_HEADER_LEN;

    p+=2; //skip version

    memcpy(f->server_random, p, SSL3_RANDOM_SIZE);
    p += SSL3_RANDOM_SIZE;

    //skip session id
    uint8_t id_len = (uint8_t) p[0];
    p ++;
    p += id_len;

    //now extract ciphersuite

    if(((p[0] <<8) + p[1]) == 0x9E){

        DEBUG_MSG(DEBUG_CRYPTO, "USING DHE-RSA-AES128-GCM-SHA256\n");

        f->keyex_alg = 1;
        f->cipher = EVP_aes_128_gcm();
        f->message_digest = EVP_sha256();

    } else if(((p[0] <<8) + p[1]) == 0x9F){
        DEBUG_MSG(DEBUG_CRYPTO, "USING DHE-RSA-AES256-GCM-SHA384\n");

        f->keyex_alg = 1;
        f->cipher = EVP_aes_256_gcm();
        f->message_digest = EVP_sha384();

    } else if(((p[0] <<8) + p[1]) == 0xC02F){
        DEBUG_MSG(DEBUG_CRYPTO, "USING ECDHE-RSA-AES128-GCM-SHA256\n");

        f->keyex_alg = 2;
        f->cipher = EVP_aes_128_gcm();
        f->message_digest = EVP_sha256();

    } else if(((p[0] <<8) + p[1]) == 0xC030){
        DEBUG_MSG(DEBUG_CRYPTO, "USING ECDHE-RSA-AES256-GCM-SHA384\n");

        f->keyex_alg = 2;
        f->cipher = EVP_aes_256_gcm();
        f->message_digest = EVP_sha384();

    } else {
        DEBUG_MSG(DEBUG_CRYPTO, "%x %x = %x\n", p[0], p[1], ((p[0] <<8) + p[1]));
        DEBUG_MSG(DEBUG_CRYPTO, "Error: unsupported cipher\n");
        return 1;
    }

    return 0;

}

/** PRF using sha384, as defined in RFC 5246
 *  
 *  Inputs:
 *  	secret: the master secret used to sign the hash
 *  	secret_len: the length of the master secret
 *  	seed{1, ..., 4}: seed values that are virtually
 *  		concatenated
 *  	seed{1,...4}_len: length of the seeds
 *  	output: a pointer to the output of the PRF
 *  	output_len: the number of desired bytes
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
static int tls_PRF(flow *f, uint8_t *secret, int32_t secret_len,
        uint8_t *seed1, int32_t seed1_len,
        uint8_t *seed2, int32_t seed2_len,
        uint8_t *seed3, int32_t seed3_len,
        uint8_t *seed4, int32_t seed4_len,
        uint8_t *output, int32_t output_len){

    int ret = 1;

    EVP_MD_CTX *ctx = NULL, *ctx_tmp = NULL, *ctx_init = NULL;
    EVP_PKEY *mac_key;
    const EVP_MD *md;
    if(f == NULL){
        md = EVP_sha256();
    } else {
        md = f->message_digest;
    }

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    ctx = EVP_MD_CTX_new();
    ctx_tmp = EVP_MD_CTX_new();
    ctx_init = EVP_MD_CTX_new();
#else
    ctx = scalloc(1, sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(ctx);
    ctx_tmp = scalloc(1, sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(ctx_tmp);
    ctx_init = scalloc(1, sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(ctx_init);
#endif
    if (ctx == NULL || ctx_tmp == NULL || ctx_init == NULL)
        goto err;

    uint8_t A[EVP_MAX_MD_SIZE];
    size_t len, A_len;
    int chunk = EVP_MD_size(md);
    int remaining = output_len;

    uint8_t *out = output;

    EVP_MD_CTX_set_flags(ctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);

    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, secret_len);

    /* Calculate first A value */
    EVP_DigestSignInit(ctx_init, NULL, md, NULL, mac_key);
    EVP_MD_CTX_copy_ex(ctx, ctx_init);
    if(seed1 != NULL && seed1_len > 0){
        EVP_DigestSignUpdate(ctx, seed1, seed1_len);
    }
    if(seed2 != NULL && seed2_len > 0){
        EVP_DigestSignUpdate(ctx, seed2, seed2_len);
    }
    if(seed3 != NULL && seed3_len > 0){
        EVP_DigestSignUpdate(ctx, seed3, seed3_len);
    }
    if(seed4 != NULL && seed4_len > 0){
        EVP_DigestSignUpdate(ctx, seed4, seed4_len);
    }
    EVP_DigestSignFinal(ctx, A, &A_len);

    //iterate until desired length is achieved
    while(remaining > 0){
        /* Now compute SHA384(secret, A+seed) */
        EVP_MD_CTX_copy_ex(ctx, ctx_init);
        EVP_DigestSignUpdate(ctx, A, A_len);
        EVP_MD_CTX_copy_ex(ctx_tmp, ctx);
        if(seed1 != NULL && seed1_len > 0){
            EVP_DigestSignUpdate(ctx, seed1, seed1_len);
        }
        if(seed2 != NULL && seed2_len > 0){
            EVP_DigestSignUpdate(ctx, seed2, seed2_len);
        }
        if(seed3 != NULL && seed3_len > 0){
            EVP_DigestSignUpdate(ctx, seed3, seed3_len);
        }
        if(seed4 != NULL && seed4_len > 0){
            EVP_DigestSignUpdate(ctx, seed4, seed4_len);
        }

        if(remaining > chunk){
            EVP_DigestSignFinal(ctx, out, &len);
            out += len;
            remaining -= len;

            /* Next A value */
            EVP_DigestSignFinal(ctx_tmp, A, &A_len);
        } else {
            EVP_DigestSignFinal(ctx, A, &A_len);
            memcpy(out, A, remaining);
            remaining -= remaining;
        }
    }
    ret = 0;

err:
    EVP_PKEY_free(mac_key);

    //Check to see if version is greater than OpenSSL 1.1.0e
#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_tmp);
    EVP_MD_CTX_free(ctx_init);
#else
    EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_cleanup(ctx_tmp);
    EVP_MD_CTX_cleanup(ctx_init);
    free(ctx);
    free(ctx_tmp);
    free(ctx_init);
#endif

    OPENSSL_cleanse(A, sizeof(A));
    return ret;
}

/** After receiving change cipher spec, calculate keys from master secret
 *  
 *  Input:
 *  	f: the tagged flow
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int init_ciphers(flow *f){

    EVP_CIPHER_CTX *r_ctx;
    EVP_CIPHER_CTX *w_ctx;
    EVP_CIPHER_CTX *w_ctx_srvr;
    EVP_CIPHER_CTX *r_ctx_srvr;

    GCM128_CONTEXT *o_gcm;

    const EVP_CIPHER *c = f->cipher;

    if(c == NULL){
        /*This *shouldn't* happen, but might if a serverHello msg isn't received
         * or if a session is resumed in a strange way */
        return 1;
    }

    /* Generate Keys */
    uint8_t *write_key, *write_iv;
    uint8_t *read_key, *read_iv;
    int32_t mac_len, key_len, iv_len;

    key_len = EVP_CIPHER_key_length(c);
    iv_len = EVP_CIPHER_iv_length(c); //EVP_GCM_TLS_FIXED_IV_LEN;
    mac_len = EVP_MD_size(f->message_digest);
    int32_t total_len = key_len + iv_len + mac_len;
    total_len *= 2;
    uint8_t *key_block = scalloc(1, total_len);

    tls_PRF(f, f->master_secret, SSL3_MASTER_SECRET_SIZE,
            (uint8_t *) TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
            f->server_random, SSL3_RANDOM_SIZE,
            f->client_random, SSL3_RANDOM_SIZE,
            NULL, 0,
            key_block, total_len);

    DEBUG_MSG(DEBUG_CRYPTO, "Client Random:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, f->client_random, SSL3_RANDOM_SIZE);
    DEBUG_MSG(DEBUG_CRYPTO, "Server Random:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, f->server_random, SSL3_RANDOM_SIZE);
    DEBUG_MSG(DEBUG_CRYPTO, "Master Secret:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, f->master_secret, SSL3_MASTER_SECRET_SIZE);
    DEBUG_MSG(DEBUG_CRYPTO, "Key Block:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, key_block, total_len);

    iv_len = EVP_GCM_TLS_FIXED_IV_LEN;

    write_key = key_block;
    read_key = key_block + key_len;
    write_iv = key_block + 2*key_len;
    read_iv = key_block + 2*key_len + iv_len;

    /* Initialize Cipher Contexts */
    r_ctx = EVP_CIPHER_CTX_new();
    w_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(r_ctx);
    EVP_CIPHER_CTX_init(w_ctx);
    w_ctx_srvr = EVP_CIPHER_CTX_new();
    r_ctx_srvr = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(w_ctx_srvr);
    EVP_CIPHER_CTX_init(r_ctx_srvr);


    DEBUG_MSG(DEBUG_CRYPTO, "EVP_CipherInit_ex(r_ctx,c,key=,iv=,which)\n");
    DEBUG_BYTES(DEBUG_CRYPTO, read_key, key_len);
    DEBUG_MSG(DEBUG_CRYPTO, "\t iv= ");
    DEBUG_BYTES(DEBUG_CRYPTO, read_iv, iv_len);

    DEBUG_MSG(DEBUG_CRYPTO, "EVP_CipherInit_ex(w_ctx,c,key=,iv=,which)\n");
    DEBUG_BYTES(DEBUG_CRYPTO, write_key, key_len);
    DEBUG_MSG(DEBUG_CRYPTO, "\t iv= ");
    DEBUG_BYTES(DEBUG_CRYPTO, write_iv, iv_len);

    if(!EVP_CipherInit_ex(r_ctx, c, NULL, read_key, NULL, 0)){
        printf("FAIL r_ctx\n");
    }
    if(!EVP_CipherInit_ex(w_ctx, c, NULL, write_key, NULL, 1)){
        printf("FAIL w_ctx\n");
    }
    if(!EVP_CipherInit_ex(w_ctx_srvr, c, NULL, read_key, NULL, 1)){
        printf("FAIL w_ctx_srvr\n");
    }
    if(!EVP_CipherInit_ex(r_ctx_srvr, c, NULL, write_key, NULL, 0)){
        printf("FAIL r_ctx_srvr\n");
    }
    EVP_CIPHER_CTX_ctrl(r_ctx, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, read_iv);
    EVP_CIPHER_CTX_ctrl(w_ctx, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, write_iv);
    EVP_CIPHER_CTX_ctrl(w_ctx_srvr, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, read_iv);
    EVP_CIPHER_CTX_ctrl(r_ctx_srvr, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, write_iv);

    /* Set up gcm cipher ctx for partial decryption */
    AES_KEY *key = scalloc(1, sizeof(AES_KEY));
    AES_set_encrypt_key(read_key, EVP_CIPHER_CTX_key_length(r_ctx)*8, key);
    o_gcm = CRYPTO_gcm128_new( key, (block128_f) AES_encrypt);
    f->gcm_ctx_key = key;

    iv_len = EVP_CIPHER_CTX_iv_length(r_ctx);
    f->gcm_ctx_iv = smalloc(iv_len);
    f->gcm_ctx_ivlen = iv_len;
    memcpy(f->gcm_ctx_iv, read_iv, EVP_GCM_TLS_FIXED_IV_LEN);

    /* Assign ctxs to flow structure */
    f->clnt_read_ctx = r_ctx;
    f->clnt_write_ctx = w_ctx;
    f->srvr_read_ctx = r_ctx_srvr;
    f->srvr_write_ctx = w_ctx_srvr;

    f->gcm_ctx_out = o_gcm;

    free(key_block);
    return 0;
}

/* Generate the keys for a client's super encryption layer
 * 
 * The header of each downstream slitheen data chunk is 16 bytes and encrypted with
 * a 256 bit AES key
 *
 * The body of each downstream chunk is CBC encrypted with a 256 bit AES key
 *
 * The last 16 bytes of the body is a MAC over the body
 *
 */
void generate_client_super_keys(uint8_t *secret, client *c){

    EVP_MD_CTX *mac_ctx;
    const EVP_MD *md = EVP_sha256();

    FILE *fp;

    //extract shared secret from SLITHEEN_ID
    uint8_t shared_secret[16];
    byte privkey[PTWIST_BYTES];

    fp = fopen("privkey", "rb");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }
    if(fread(privkey, PTWIST_BYTES, 1, fp) < 1){
        perror("fread");
        exit(1);
    }
    fclose(fp);

    /* check tag*/ 
    if(check_tag(shared_secret, privkey, secret, (const byte *)"context", 7)){
        //something went wrong O.o
        DEBUG_MSG(DEBUG_CRYPTO, "Error extracting secret from tag\n");
        return;
    }

    DEBUG_MSG(DEBUG_CRYPTO, "Shared secret: ");
    DEBUG_BYTES(DEBUG_CRYPTO, shared_secret, 16);

    /* Generate Keys */
    uint8_t *hdr_key, *bdy_key;
    uint8_t *mac_secret;
    EVP_PKEY *mac_key;
    int32_t mac_len, key_len;

    key_len = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    mac_len = EVP_MD_size(md);
    int32_t total_len = 2*key_len + mac_len;
    uint8_t *key_block = scalloc(1, total_len);

    tls_PRF(NULL, shared_secret, SLITHEEN_SUPER_SECRET_SIZE,
            (uint8_t *) SLITHEEN_SUPER_CONST, SLITHEEN_SUPER_CONST_SIZE,
            NULL, 0,
            NULL, 0,
            NULL, 0,
            key_block, total_len);

    DEBUG_MSG(DEBUG_CRYPTO, "slitheend id: \n");
    DEBUG_BYTES(DEBUG_CRYPTO, secret, SLITHEEN_ID_LEN);

    DEBUG_MSG(DEBUG_CRYPTO, "keyblock: \n");
    DEBUG_BYTES(DEBUG_CRYPTO, key_block, total_len);

    hdr_key = key_block;
    bdy_key = key_block + key_len;
    mac_secret = key_block + 2*key_len;

    /* Initialize MAC Context */
    mac_ctx = EVP_MD_CTX_create();

    EVP_DigestInit_ex(mac_ctx, md, NULL);
    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, mac_secret, mac_len);
    EVP_DigestSignInit(mac_ctx, NULL, md, NULL, mac_key);

    c->header_key = smalloc(key_len);
    c->body_key = smalloc(key_len);

    memcpy(c->header_key, hdr_key, key_len);
    memcpy(c->body_key, bdy_key, key_len);

    c->mac_ctx = mac_ctx;

    //Free everything
    free(key_block);
    EVP_PKEY_free(mac_key);

    return;

}

int super_encrypt(client *c, uint8_t *data, uint32_t len){

    int retval = 1;

    EVP_CIPHER_CTX *hdr_ctx = NULL;
    EVP_CIPHER_CTX *bdy_ctx = NULL;

    int32_t out_len;
    size_t mac_len;
    uint8_t *p = data;

    uint8_t output[EVP_MAX_MD_SIZE];

    //first encrypt the header	
    DEBUG_MSG(DEBUG_PROXY, "super encrypt: Plaintext Header:\n");
    DEBUG_BYTES(DEBUG_PROXY, p, SLITHEEN_HEADER_LEN);

    hdr_ctx = EVP_CIPHER_CTX_new();

    if(c->header_key == NULL){
        printf("c->header_key is null\n");
        retval = 0;
        goto end;
    }

    EVP_CipherInit_ex(hdr_ctx, EVP_aes_256_cbc(), NULL, c->header_key, NULL, 1);

    if(!EVP_CipherUpdate(hdr_ctx, p, &out_len, p, SLITHEEN_HEADER_LEN)){
        printf("Failed!\n");
        retval = 0;
        goto end;
    }

    DEBUG_MSG(DEBUG_PROXY, "super encrypt: Encrypted Header (%d bytes):\n", out_len);
    DEBUG_BYTES(DEBUG_PROXY, p, out_len);

    if(len == 0){ //only encrypt header: body contains garbage bytes
        retval = 1;
        goto end;
    }

    //encrypt the body
    p += SLITHEEN_HEADER_LEN;

    //generate IV
    RAND_bytes(p, 16);

    //set up cipher ctx
    bdy_ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(bdy_ctx, EVP_aes_256_cbc(), NULL, c->body_key, p, 1);

    p+= 16;

    DEBUG_MSG(DEBUG_CRYPTO, "super_encrypt: plaintext:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, p, len);

    if(!EVP_CipherUpdate(bdy_ctx, p, &out_len, p, len)){
        printf("Failed!\n");
        retval = 0;
        goto end;
    }

    DEBUG_MSG(DEBUG_CRYPTO, "super_encrypt: Encrypted data (%d bytes) :\n", out_len);
    DEBUG_BYTES(DEBUG_CRYPTO, p, out_len);

    //MAC at the end
    EVP_MD_CTX *mac_ctx = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    mac_ctx = EVP_MD_CTX_new();
#else
    mac_ctx = scalloc(1, sizeof(EVP_MD_CTX));
    EVP_MD_CTX_init(mac_ctx);
#endif

    EVP_MD_CTX_copy_ex(mac_ctx, c->mac_ctx);

    EVP_DigestSignUpdate(mac_ctx, p, out_len);

    EVP_DigestSignFinal(mac_ctx, output, &mac_len);

#if OPENSSL_VERSION_NUMBER >= 0x1010000eL
    EVP_MD_CTX_free(mac_ctx);
#else
    EVP_MD_CTX_cleanup(mac_ctx);
    free(mac_ctx);
#endif

    p += out_len;
    memcpy(p, output, 16);

    DEBUG_MSG(DEBUG_CRYPTO, "super_encrypt: Computed mac:\n");
    DEBUG_BYTES(DEBUG_CRYPTO, output, 16);

end:
    if(hdr_ctx != NULL){
        EVP_CIPHER_CTX_cleanup(hdr_ctx);
        OPENSSL_free(hdr_ctx);
    }
    if(bdy_ctx != NULL){
        EVP_CIPHER_CTX_cleanup(bdy_ctx);
        OPENSSL_free(bdy_ctx);
    }

    return retval;
}

/** Checks a handshake message to see if it is tagged or a
 *  recognized flow. If the client random nonce is tagged,
 *  adds the flow to the flow table to be tracked.
 *
 *  Inputs:
 *  	info: the processed packet
 *  	f: the tagged flow
 *
 *  Output:
 *  	none
 */
int check_handshake(struct packet_info *info){

    FILE *fp;
    int res, code;
    uint8_t *hello_rand;
    const struct handshake_header *handshake_hdr;

    byte privkey[PTWIST_BYTES];
    byte key[16];

    uint8_t *p = info->app_data + RECORD_HEADER_LEN;
    handshake_hdr = (struct handshake_header*) p;

    code = handshake_hdr->type;

    res = 1;

    if (code == 0x01){
        p += CLIENT_HELLO_HEADER_LEN;
        //now pointing to hello random :D
        hello_rand = p;
        p += 4; //skipping time bytes
        /* Load the private key */
        fp = fopen("privkey", "rb");
        if (fp == NULL) {
            perror("fopen");
            exit(1);
        }
        res = fread(privkey, PTWIST_BYTES, 1, fp);
        if (res < 1) {
            perror("fread");
            exit(1);
        }
        fclose(fp);

        /* check tag*/ 
        uint8_t context[4 + SSL3_RANDOM_SIZE - PTWIST_TAG_BYTES];
        memcpy(context, &info->ip_hdr->dst.s_addr, 4);
        memcpy(context + 4, hello_rand, SSL3_RANDOM_SIZE - PTWIST_TAG_BYTES);
        res = check_tag(key, privkey, p, (const byte *)context, sizeof(context));
        //res = check_tag(key, privkey, p, (const byte *)"context", 7);//for phantomjs testing
        if (!res) {

            DEBUG_MSG(DEBUG_CRYPTO, "Received tagged flow! (key =");
            DEBUG_BYTES(DEBUG_CRYPTO, key, 16);

            /* If flow is not in table, save it */
            flow *flow_ptr = check_flow(info);
            if(flow_ptr == NULL){
                flow_ptr = add_flow(info);
                if(flow_ptr == NULL){
                    fprintf(stderr, "Memory failure\n");
                    return 0;
                }

                for(int i=0; i<16; i++){
                    flow_ptr->key[i] = key[i];
                }

                memcpy(flow_ptr->client_random, hello_rand, SSL3_RANDOM_SIZE);

                DEBUG_MSG(DEBUG_CRYPTO, "Hello random:\n");
                DEBUG_BYTES(DEBUG_CRYPTO, hello_rand, SSL3_RANDOM_SIZE);

                flow_ptr->ref_ctr--;

            } else { /* else update saved flow with new key and random nonce */
                for(int i=0; i<16; i++){
                    flow_ptr->key[i] = key[i];
                }

                memcpy(flow_ptr->client_random, hello_rand, SSL3_RANDOM_SIZE);
                flow_ptr->ref_ctr--;
            }

        }
    }

    return !res;
}

/* Check the given tag with the given context and private key.  Return 0
   if the tag is properly formed, non-0 if not.  If the tag is correct,
   set key to the resulting secret key. */
static int check_tag(byte key[16], const byte privkey[PTWIST_BYTES],
        const byte tag[PTWIST_TAG_BYTES], const byte *context,
        size_t context_len)
{
    int ret = -1;
    byte sharedsec[PTWIST_BYTES+context_len];
    byte taghashout[32];
#if PTWIST_PUZZLE_STRENGTH > 0
    byte hashout[32];
    size_t puzzle_len = 16+PTWIST_RESP_BYTES;
    byte value_to_hash[puzzle_len];
    unsigned int firstbits;
    int firstpass = 0;
#endif

    /* Compute the shared secret privkey*TAG */
    ptwist_pointmul(sharedsec, tag, privkey);

    /* Create the hash tag keys */
    memmove(sharedsec+PTWIST_BYTES, context, context_len);
    SHA256(sharedsec, PTWIST_BYTES + context_len, taghashout);

#if PTWIST_PUZZLE_STRENGTH > 0
    /* Construct the proposed solution to the puzzle */
    memmove(value_to_hash, taghashout, 16);
    memmove(value_to_hash+16, tag+PTWIST_BYTES, PTWIST_RESP_BYTES);
    value_to_hash[16+PTWIST_RESP_BYTES-1] &= PTWIST_RESP_MASK;

    /* Hash the proposed solution and see if it is correct; that is, the
     * hash should start with PTWIST_PUZZLE_STRENGTH bits of 0s,
     * followed by the last PTWIST_HASH_SHOWBITS of the tag. */
    md_map_sh256(hashout, value_to_hash, puzzle_len);
#if PTWIST_PUZZLE_STRENGTH < 32
    /* This assumes that you're on an architecture that doesn't care
     * about alignment, and is little endian. */
    firstbits = *(unsigned int*)hashout;
    if ((firstbits & PTWIST_PUZZLE_MASK) == 0) {
        firstpass = 1;
    }
#else
#error "Code assumes PTWIST_PUZZLE_STRENGTH < 32"
#endif
    if (firstpass) {
        bn_t Hbn, Tbn;
        bn_new(Hbn);
        bn_new(Tbn);
        hashout[PTWIST_HASH_TOTBYTES-1] &= PTWIST_HASH_MASK;
        bn_read_bin(Hbn, hashout, PTWIST_HASH_TOTBYTES, BN_POS);
        bn_rsh(Hbn, Hbn, PTWIST_PUZZLE_STRENGTH);
        bn_read_bin(Tbn, tag+PTWIST_BYTES, PTWIST_TAG_BYTES-PTWIST_BYTES,
                BN_POS);
        bn_rsh(Tbn, Tbn, PTWIST_RESP_BITS);

        ret = (bn_cmp(Tbn,Hbn) != CMP_EQ);

        bn_free(Hbn);
        bn_free(Tbn);
    }
#else
    /* We're not using a client puzzle, so just check that the first
     * PTWIST_HASH_SHOWBITS bits of the above hash fill out the rest
     * of the tag.  If there's no puzzle, PTWIST_HASH_SHOWBITS must be
     * a multiple of 8. */
    ret = (memcmp(tag+PTWIST_BYTES, taghashout, PTWIST_HASH_SHOWBITS/8) != 0);
#endif
    if (ret == 0) {
        memmove(key, taghashout+16, 16);
    }
    return ret;
}

/* Modified GCM cipher function */


/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

#define EVP_C_DATA(kstruct, ctx) \
    ((kstruct *)EVP_CIPHER_CTX_get_cipher_data(ctx))

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

#define GCM_CTX_LEN 380 + sizeof(block128_f)

int partial_aes_gcm_tls_cipher(flow *f, unsigned char *out,
        const unsigned char *in, size_t len, size_t offset, uint8_t enc)
{

    // Encrypt/decrypt must be performed in place
    int rv = -1;
    if (out != in)
        return -1;

    //if we're missing the first part of the record, abort
    if ((offset > EVP_GCM_TLS_EXPLICIT_IV_LEN) &&
            (f->partial_record_len < EVP_GCM_TLS_EXPLICIT_IV_LEN ))
        return -1;

    //if we do not yet have the entire explicit IV, there's nothing to decrypt
    if (f->partial_record_len <= EVP_GCM_TLS_EXPLICIT_IV_LEN )
        return 0;

    //set IV
    uint8_t *iv = smalloc(f->gcm_ctx_ivlen);
    memcpy(iv, f->gcm_ctx_iv, EVP_GCM_TLS_FIXED_IV_LEN);

    //make encryption/decryption buffer
    uint8_t *data = scalloc(1, offset + len);
    memset(data, 0, offset); //dummy data to offset
    memcpy(data+offset, in, len);

    if(enc){
        memcpy(iv + f->gcm_ctx_ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN , f->partial_record_dec, EVP_GCM_TLS_EXPLICIT_IV_LEN);
    } else {
        memcpy(iv + f->gcm_ctx_ivlen - EVP_GCM_TLS_EXPLICIT_IV_LEN , f->partial_record, EVP_GCM_TLS_EXPLICIT_IV_LEN);
    }
    CRYPTO_gcm128_setiv(f->gcm_ctx_out, iv, f->gcm_ctx_ivlen);

    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;

    //set AAD
    uint8_t buf[13], seq[8];

    memcpy(seq, f->read_seq, 8);

    for(int i=7; i>=0; i--){
        --seq[i];
        if(seq[i] != 0xff)
            break;
    }

    memcpy(buf, seq, 8);

    buf[8] = 0x17;
    buf[9] = 0x03;
    buf[10] = 0x03;
    buf[11] = len >> 8; //len >> 8;
    buf[12] = len & 0xff;//len *0xff;

    CRYPTO_gcm128_aad(f->gcm_ctx_out, buf, 13);

    // Fix buffer and length to point to payload
    uint8_t *p = data + EVP_GCM_TLS_EXPLICIT_IV_LEN;

    if(enc){
        if ((len > 16) && CRYPTO_gcm128_encrypt(f->gcm_ctx_out, p, p, len+offset))
            goto err;
    } else {
        if ((len > 16) && CRYPTO_gcm128_decrypt(f->gcm_ctx_out, p, p, len+offset))
            goto err;
    }

    //copy data from buffer to output
    memcpy(out, data+offset, len + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    if(offset > 0){
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN;
    } else {
        rv = len;
    }

err:
    free(iv);
    free(data);

    return rv;

}

/*
 * Computes the tag for a (now full) record that was split in multiple parts across
 * two or more packets.
 *
 * Input:
 *  f: The corresponding flow
 *  tag: a pointer to where the tag will be placed
 *  len: the length of the original encryption
 */
void partial_aes_gcm_tls_tag(flow *f, unsigned char *tag){

    CRYPTO_gcm128_tag(f->gcm_ctx_out, tag, EVP_GCM_TLS_TAG_LEN);

}
