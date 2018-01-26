/** check_handshake.c
 *
 * Integration-style tests for extracting the TLS master secret for various
 * types of TLS handshakes
 */

#include <check.h>
#include <stdlib.h>

#include "../flow.h"
#include "../crypto.h"
#include "../cryptothread.h"
#include "../packet.h"
#include "../util.h"
#include "test_util.h"

START_TEST(full_handshake_regular){

    flow *f = NULL;
    uint8_t *data;
    struct packet_info *info;

    info = smalloc(sizeof(struct packet_info));

    /* Read in ClientHello message */
    if(!read_file("data/frame_handshake_regular1.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    //Make sure it recognized the tag
    ck_assert_int_eq(check_handshake(info), 1);

    //make sure it saved the flow
    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);

    add_packet(f, info);

    free(data);

    /* Read in ServerHello message */
    if(!read_file("data/frame_handshake_regular2.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);

    add_packet(f, info);

    //make sure it's not using the extended master extension
    ck_assert_int_eq(f->extended_master_secret, 0);

    free(data);

    /* Read in Certificate messages */
    if(!read_file("data/frame_handshake_regular3.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);

    add_packet(f, info);

    free(data);

    if(!read_file("data/frame_handshake_regular4.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);

    add_packet(f, info);

    free(data);

    /* ServerKeyEx, ServerHelloDone */
    if(!read_file("data/frame_handshake_regular5.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);

    add_packet(f, info);

    free(data);

    /* ClientKeyEx, CCS, Finished */
    if(!read_file("data/frame_handshake_regular6.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);

    add_packet(f, info);

    //Verify Finished received
    ck_assert_int_eq(f->out_encrypted, 2);

    free(data);

    /* CCS, Finished (from the server) */
    if(!read_file("data/frame_handshake_regular7.dat", &data)){
        ck_abort();
    }
    extract_packet_headers(data, info);

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);
    
    add_packet(f, info);

    //Make sure both Finished messages were successfully received and decrypted

    f = check_flow(info);
    ck_assert_ptr_ne(f, NULL);
    ck_assert_int_eq(f->in_encrypted, 2);
    ck_assert_int_eq(f->application, 1);

    remove_flow(f);

    free(data);
}
END_TEST

START_TEST(full_handshake_regular_resumed){

    flow *f;
    uint8_t *record;

    //populate record from file
    if(!read_file("data/packet_tagged.dat", &record)){
        ck_abort();
    }


}
END_TEST

START_TEST(full_handshake_extended){



}
END_TEST

START_TEST(full_handshake_extended_resumed){

    flow *f;
    uint8_t *record;

    //populate record from file
    if(!read_file("data/packet_tagged.dat", &record)){
        ck_abort();
    }


}
END_TEST

Suite *tag_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Handshake");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, full_handshake_regular);
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


    s = tag_suite();
    sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    crypto_locks_cleanup();

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
