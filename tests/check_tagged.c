/** check_tagged.c
 *
 * Test the tag-check functionality of Slitheen
 */

#include <check.h>
#include <stdlib.h>

#include "../flow.h"
#include "../crypto.h"
#include "../cryptothread.h"
#include "../packet.h"
#include "../util.h"
#include "test_util.h"

START_TEST(test_recognize_notag){
    struct packet_info *info;
    uint8_t *packet;

    //populate packet_info with a tagged ClientHello message
    if(!read_file("data/packet_untagged.dat", &packet)){
        ck_abort();
    }

    info = smalloc(sizeof(struct packet_info));

    extract_packet_headers(packet, info);

    ck_assert_int_eq(check_handshake(info), 0);
}
END_TEST

START_TEST(test_recognize_tag){
    struct packet_info *info;
    uint8_t *data;
    FILE *fp;
    uint64_t fsize;

    //populate packet_info with a tagged ClientHello message
    if(!read_file("data/packet_tagged.dat", &data)){
        ck_abort();
    }

    info = smalloc(sizeof(struct packet_info));

    extract_packet_headers(data, info);

    ck_assert_int_eq(check_handshake(info), 1);

}
END_TEST

Suite *tag_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Tag");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_recognize_tag);
    tcase_add_test(tc_core, test_recognize_notag);
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
