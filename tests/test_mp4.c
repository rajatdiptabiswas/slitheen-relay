/** test_mp4.c
 *
 * Tests for the relay station mp4 parser
 */

#include <check.h>
#include "../mp4.h"

START_TEST(mp4_parser){
    
    //need to create a flow for this
    flow *f = smalloc(sizeof(flow));

    //we only need to set the mp4_state and remaining_element fields of the flow
    f->mp4_state = BOX_HEADER;
    f->remaining_element = 0;

    uint8_t *data;
    int32_t file_len;

    /* Read in mp4 data */
    if(!read_file_len("data/mp4_bunny.dat", &data, &file_len)){
        ck_abort();
    }

    uint8_t *p = data;
    parse_mp4(f, p, 8);
    ck_assert_int_eq(f->mp4_state, PARSE_BOX);
    ck_assert_int_eq(f->mp4_box_size, 24);
    ck_assert_int_eq(f->mp4_box_type, 0x66747970);
    file_len -= 8;
    p += 8;

    parse_mp4(f, p, 18);
    ck_assert_int_eq(f->mp4_state, PARSE_BOX);
    ck_assert_int_eq(f->mp4_box_size, 6);
    file_len -= 18;
    p += 18;

    parse_mp4(f, p, 6);
    ck_assert_int_eq(f->mp4_state, BOX_HEADER);
    ck_assert_int_eq(f->mp4_box_size, 0);
    file_len -= 6;
    p += 6;

    parse_mp4(f, p, 8);
    ck_assert_int_eq(f->mp4_state, PARSE_BOX);
    ck_assert_int_eq(f->mp4_box_size, 3866);
    ck_assert_int_eq(f->mp4_box_type, 0x6d6f6f76);
    file_len -= 8;
    p += 8;

    parse_mp4(f, p, 3860);
    ck_assert_int_eq(f->mp4_state, PARSE_BOX);
    ck_assert_int_eq(f->mp4_box_size, 6);
    file_len -= 3860;
    p += 3860;

    parse_mp4(f, p, 6);
    ck_assert_int_eq(f->mp4_state, BOX_HEADER);
    ck_assert_int_eq(f->mp4_box_size, 0);
    file_len -= 6;
    p += 6;

    parse_mp4(f, p, 8);
    ck_assert_int_eq(f->mp4_state, PARSE_BOX);
    ck_assert_int_eq(f->mp4_box_size, 0);
    ck_assert_int_eq(f->mp4_box_type, 0x66726565);
    file_len -= 8;
    p += 8;

    parse_mp4(f, p, 8);
    ck_assert_int_eq(f->mp4_state, PARSE_BOX);
    ck_assert_int_eq(f->mp4_box_size, 2066779);
    ck_assert_int_eq(f->mp4_box_type, 0x6d646174);
    file_len -= 8;
    p += 8;

    parse_mp4(f, p, 2066779);
    ck_assert_int_eq(f->mp4_state, BOX_HEADER);
    ck_assert_int_eq(f->mp4_box_size, 0);
    file_len -= 2066779;
    ck_assert_int_eq(file_len, 0);

    free(data);
    free(f);
}
END_TEST

Suite *http_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("MP4 Parser");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, mp4_parser);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void){

    int number_failed;
    Suite *s;
    SRunner *sr;

    s = http_suite();
    sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
