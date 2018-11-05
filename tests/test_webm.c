/** test_webm.c
 *
 * Unit tests for the relay station webm parser
 */

#include <check.h>
#include "../flow.h"
#include "../http.h"
#include "test_util.h"
#include "../webm.h"
#include "../webm.c"

START_TEST(variable_header_parser) {
    //set up common webm length field
    uint8_t *p = malloc(4);

    p[0] = 0x1a;
    p[1] = 0x45;
    p[2] = 0xdf;
    p[3] = 0xa3;

    uint8_t header_len;
    uint32_t header = variable_header(p, &header_len);

    ck_assert_int_eq(header_len, 4);
    ck_assert_int_eq(header, 0x1a45dfa3);
}
END_TEST

START_TEST(variable_length_parser) {

    uint8_t *p = malloc(8);

    p[0] = 0x9f;
    p[1] = 0x00;
    p[2] = 0x00;
    p[3] = 0x00;

    uint8_t int_len;
    uint32_t len = variable_length(p, &int_len);

    ck_assert_int_eq(int_len, 1);
    ck_assert_int_eq(len, 0x1f);

    p[0] = 0x21;
    p[1] = 0x0d;
    p[2] = 0x8c;
    p[3] = 0x00;

    len = variable_length(p, &int_len);

    ck_assert_int_eq(int_len, 3);
    ck_assert_int_eq(len, 0x10d8c);
}
END_TEST

START_TEST(webm_parser) {

    //need to create a flow for this
    flow *f = smalloc(sizeof(flow));

    //we only need to set the webmstate and remaining_element fields of the flow
    f->webmstate = WEBM_HEADER;
    f->remaining_element = 0;

    uint8_t *data;
    int32_t file_len;

    /* Read in webm data */
    if(!read_file_len("data/webm_0x7fd590016250", &data, &file_len)){
        ck_abort();
    }

    uint8_t *p = data;
    parse_webm(f, p, 8);

    //The remaining element length should be the element length (31) - the extra
    //three bytes we parsed (28)
    ck_assert_int_eq(f->remaining_element, 28);

    ck_assert_int_eq(f->webmstate, MID_ELEMENT);

    p += 8;
    file_len -= 8;

    //Parse the rest of the header
    parse_webm(f, p, 28);

    ck_assert_int_eq(f->remaining_element, 0);

    ck_assert_int_eq(f->webmstate, WEBM_HEADER);

    p+= 28;
    file_len -= 28;

    //Now parse segment header
    parse_webm(f, p, 16);

    //ck_assert_int_eq(f->webmstate, MID_ELEMENT);

    p+= 16;
    file_len -= 16;

    parse_webm(f, p, 185);
    ck_assert_int_eq(f->webmstate, WEBM_HEADER);

    //Detect cluster element ID
    p += 185;
    file_len -= 185;

    ck_assert_int_eq(p[0], 0x1f);
    ck_assert_int_eq(p[1], 0x43);
    ck_assert_int_eq(p[2], 0xb6);
    ck_assert_int_eq(p[3], 0x75);

    //Parse into media element
    //parse_webm(f, p, 8);

    //ck_assert_int_eq(f->webmstate, MEDIA);

    //parse to end of file
    //p += 8;
    //file_len -= 8;

    parse_webm(f, p, file_len);

    free(data);

}
END_TEST

Suite *webm_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("WebM Parser");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, variable_header_parser);
    tcase_add_test(tc_core, variable_length_parser);
    tcase_add_test(tc_core, webm_parser);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void){

    int number_failed;
    Suite *s;
    SRunner *sr;

    s = webm_suite();
    sr = srunner_create(s);

    srunner_set_fork_status(sr, CK_NOFORK);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
