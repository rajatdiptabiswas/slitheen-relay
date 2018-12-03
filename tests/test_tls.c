/** test_tls.c
 *
 * Unit tests for testing the AES-GCM partial enc/dec
 * functionality for small/misorded packets
 *
 * Integration tests for testing the TLS state machine
 *
 */

#include <check.h>
#include <stdlib.h>

#include "../flow.h"
#include "../crypto.h"
#include "../cryptothread.h"
#include "../packet.h"
#include "../util.h"
#include "test_util.h"

/* Unit Tests */

//cipher 0 = aes128, cipher 1 = aes256
static void initialize_ciphers(flow *f, char *pathname, int cipher){

    uint8_t *data;
    f->hs_md_ctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(f->hs_md_ctx, md, NULL);

    if (cipher) {
        f->cipher = EVP_aes_256_gcm();
        f->message_digest = EVP_sha384();
    } else {
        f->cipher = EVP_aes_128_gcm();
        f->message_digest = EVP_sha256();
    }

    f->clnt_read_ctx = NULL;
    f->clnt_write_ctx = NULL;
    f->srvr_read_ctx = NULL;
    f->srvr_write_ctx = NULL;
    f->gcm_ctx_out = NULL;
    f->gcm_ctx_iv = NULL;
    f->gcm_ctx_key = NULL;

    memset(f->read_seq, 0, 8);
    memset(f->write_seq, 0, 8);

    //skipping Finished message, so up counters
    f->read_seq[7] = 1;
    f->write_seq[7] = 1;

    /* Cipher initialization */
    if(!read_file(pathname, &data)){
        ck_abort();
    }

    memcpy(f->master_secret, data, SSL3_MASTER_SECRET_SIZE);
    memcpy(f->client_random, data+SSL3_MASTER_SECRET_SIZE, SSL3_RANDOM_SIZE);
    memcpy(f->server_random, data+SSL3_MASTER_SECRET_SIZE+SSL3_RANDOM_SIZE, SSL3_RANDOM_SIZE);

    int result = init_ciphers(f);
    ck_assert_int_eq(result, 0);

    free(data);
}

START_TEST(full_decrypt){

    uint8_t *data;
    int32_t len;
    flow *f = NULL;

    /* Flow initialization */
    f = smalloc(sizeof(flow));
    initialize_ciphers(f, "data/ctx.dat", 0);

    /* Application Data */
    if(!(read_file_len("data/ciphertext.dat", &data, &len))){
        ck_abort();
    }

    int n = encrypt(f, data, data, len, 1, 0x17, 0, 0);
    ck_assert_int_eq(n, len - (EVP_GCM_TLS_TAG_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN));

    free(data);

}
END_TEST

START_TEST(full_encrypt){

    uint8_t *data;
    int len;
    flow *f = NULL;

    /* Flow initialization */
    f = smalloc(sizeof(flow));
    initialize_ciphers(f, "data/ctx.dat", 0);

    /* Application Data */
    if(!(read_file_len("data/plaintext.dat", &data, &len))){
        ck_abort();
    }

    int n = encrypt(f, data, data, len-EVP_GCM_TLS_TAG_LEN, 1, 0x17, 1, 0);
    ck_assert_int_eq(n, len);

    free(data);

}
END_TEST

START_TEST(partial_decrypt){

    uint8_t *data;
    uint8_t *data2;
    int len;
    flow *f = NULL;

    /* Flow initialization */
    f = smalloc(sizeof(flow));
    initialize_ciphers(f, "data/ctx.dat", 0);

    /* Application Data */
    if(!(read_file_len("data/ciphertext.dat", &data, &len))){
        ck_abort();
    }

    if(!(read_file("data/ciphertext.dat", &data2))){
        ck_abort();
    }

    int n = encrypt(f, data, data, len, 1, 0x17, 0, 0);
    ck_assert_int_gt(n, 0);


    f->partial_record = data2;
    n = partial_aes_gcm_tls_cipher(f, data2, data2, len/2, 0, 0);
    ck_assert_int_eq(n, len/2 - EVP_GCM_TLS_EXPLICIT_IV_LEN);

    ck_assert_int_eq(memcmp(data + EVP_GCM_TLS_EXPLICIT_IV_LEN, data2 +
                EVP_GCM_TLS_EXPLICIT_IV_LEN, n), 0);
    free(data2);

    if(!(read_file("data/ciphertext.dat", &data2))){
        ck_abort();
    }

    f->partial_record = data2;
    f->partial_record_len = 100;
    n = partial_aes_gcm_tls_cipher(f, data2+100, data2+100, 300, 100, 0);
    ck_assert_int_eq(n, 300);

    printf("partial bytes:\n");
    for(int i=0; i< 300; i++){
        printf("%02x ", data[100+i]);
    }
    printf("\n");
    printf("partial bytes:\n");
    for(int i=0; i< 300; i++){
        printf("%02x ", data2[100+i]);
    }
    printf("\n");


    ck_assert_int_eq(memcmp(data + 100, data2 + 100, 300), 0);
    free(data2);


    free(data);

}
END_TEST

START_TEST(partial_encrypt){

    uint8_t *data;
    uint8_t *data2;
    int len;
    flow *f = NULL;

    /* Flow initialization */
    f = smalloc(sizeof(flow));
    initialize_ciphers(f, "data/ctx.dat", 0);

    /* Application Data */
    if(!(read_file_len("data/plaintext.dat", &data, &len))){
        ck_abort();
    }

    if(!(read_file("data/plaintext.dat", &data2))){
        ck_abort();
    }
    printf("%s\n", data2+EVP_GCM_TLS_EXPLICIT_IV_LEN);
    fflush(stdout);

    //skipping decrypt, so up counters
    f->read_seq[7] = 2;
    f->write_seq[7] = 2;

    f->partial_record_dec = data;
    int n = partial_aes_gcm_tls_cipher(f, data, data, len/2 + EVP_GCM_TLS_EXPLICIT_IV_LEN, 0, 1);
    ck_assert_int_gt(n, 0);

    f->partial_record_dec = data2;
    n = partial_aes_gcm_tls_cipher(f, data2, data2, len - EVP_GCM_TLS_TAG_LEN, 0, 1);
    ck_assert_int_eq(n, len - EVP_GCM_TLS_TAG_LEN - EVP_GCM_TLS_EXPLICIT_IV_LEN);

    ck_assert_int_eq(memcmp(data, data2, n/2), 0);

    //compute the tag
    partial_aes_gcm_tls_tag(f, data2 + n + EVP_GCM_TLS_EXPLICIT_IV_LEN);

    //decrypt to check tag
    initialize_ciphers(f, "data/ctx.dat", 0);
    n = encrypt(f, data2, data2, len, 1, 0x17, 0, 0);
    printf("%s\n", data2+EVP_GCM_TLS_EXPLICIT_IV_LEN);
    fflush(stdout);
    ck_assert_int_eq(n, len - (EVP_GCM_TLS_TAG_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN));

    free(data);
    free(data2);

}
END_TEST

START_TEST(future_decrypt){

}
END_TEST

START_TEST(future_encrypt){

}
END_TEST

Suite *unit_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Partial AES");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, full_decrypt);
    tcase_add_test(tc_core, full_encrypt);
    tcase_add_test(tc_core, partial_decrypt);
    tcase_add_test(tc_core, partial_encrypt);
    tcase_add_test(tc_core, future_decrypt);
    tcase_add_test(tc_core, future_encrypt);

    suite_add_tcase(s, tc_core);

    return s;
}

/** Integration Tests 
 *
 * These are the following cases of packetization of TLS records:
 *
 * [] = TLS record, | = packet boundary, : = TLS record header bounder, ; = GCM IV ? = GCM tag
 *
 * 1) |[       ]|[     ]|  packet contains entire TLS record
 * 2) |[    |  ][      ]|  packet contains partial TLS record, which finishes in next packet
 * 3) |[    |      |   ]|  TLS record is split across > 2 packets
 * 4) |[   ][   |      ]|  packet contains multiple TLS records
 * 5) |[:|:      ]|        packet boundary splits TLS record header
 * 6) |[;|;      ]|        packet boundary splits GCM IV
 * 7) |[      ?|?]|        packet boundary splits GCM tag
 *
 */
START_TEST(tls_state_machine){

    uint8_t *data, *data2, *p;
    int32_t len, len2;

    flow *f;

    int32_t offset = SSL3_MASTER_SECRET_SIZE + 2*SSL3_RANDOM_SIZE;

    /* Flow initialization */
    f = smalloc(sizeof(flow));
    initialize_ciphers(f, "data/tls_1.dat", 0);

    /* Read in TLS records */
    if(!(read_file_len("data/tls_1.dat", &data, &len))){
        ck_abort();
    }

    if(!(read_file_len("data/tls_2.dat", &data2, &len2))){
        ck_abort();
    }

    p = data + offset;

    //First 5 bytes are TLS records
    struct record_header *record_hdr = (struct record_header *) p;

    printf("Record Hdr: ");
    for(int i=0; i<RECORD_HEADER_LEN; i++)
        printf("%02x ", p[i]);
    printf("\n");

    p += RECORD_HEADER_LEN;

    len = RECORD_LEN(record_hdr);

    printf("len = %d", len);
    printf("offset = %d\n", offset);

    int n = encrypt(f, p, p, len, 1, 0x17, 0, 0);
    ck_assert_int_eq(n, len - (EVP_GCM_TLS_TAG_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN));

    free(data);
    free(data2);
}
END_TEST

Suite *integration_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("TLS State Machine");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, tls_state_machine);

    suite_add_tcase(s, tc_core);
    return s;
}



int main(void){

    int number_failed;
    Suite *s;
    SRunner *sr;

    //initialize Slitheen structures
    if(init_tables()){
        exit(1);
    }
    if(init_session_cache()){
        exit(1);
    }
    init_crypto_locks();


    s = unit_suite();
    sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    s = integration_suite();
    sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    crypto_locks_cleanup();

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
