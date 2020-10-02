/** unit_test_http.c
 *
 * Unit tests for the relay station http parser
 */

#include <check.h>
#include "../http.c"

START_TEST(test_parse_http_header_1) {
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "304 Not Modified\r\n\r\n";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->http_state, PARSE_HEADER);
    ck_assert_int_eq(f->http_state_next, PARSE_HEADER);
    ck_assert_int_eq(f->content_type, UNKNOWN);
    ck_assert_int_eq(f->webmstate, 0);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_2) {
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "304 Not Modified";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->http_state, FORFEIT_REST);
    ck_assert_int_eq(header_len, -1);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_3) {
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "200";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    f->content_type = UNKNOWN;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->content_type, NOREPLACE);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_4) {
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "Content-Type: image/jpegxxxxxxxx\r";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->content_type, IMAGE);

    ck_assert_str_eq(data, "Content-Type: sli/theen         \r");
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_5) {
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "Content-Type: video/webm";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->content_type, WEBM);
    ck_assert_int_eq(f->webmstate, WEBM_HEADER);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_6){
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "Content-Type: video/mp4";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->content_type, MP4);
    ck_assert_int_eq(f->mp4_state, BOX_HEADER);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_7){
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "200 OK. Content-Type: ???";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->content_type, NOREPLACE);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_8){
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "Transfer-Encoding: chunked";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->http_state_next, BEGIN_CHUNK);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_9){
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "Transfer-Encoding: xxxxxxx";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->http_state_next, FORFEIT_REST);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_10){
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "Content-Length: 1000";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->remaining_response_len, 1000);
    ck_assert_int_eq(f->http_state_next, MID_CONTENT);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

START_TEST(test_parse_http_header_11){
    flow *f = smalloc(sizeof(flow));
    uint8_t data[] = "x\r\n\r\n";
    uint32_t length = strlen(data);

    f->http_state = PARSE_HEADER;
    f->http_state_next = PARSE_HEADER;
    int header_len = parse_http_header(f, &data, length);

    ck_assert_int_eq(f->http_state, FORFEIT_REST);
    ck_assert_int_eq(header_len, length);
    free(f);
}
END_TEST

Suite *http_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("HTTP Parser");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_parse_http_header_1);
    tcase_add_test(tc_core, test_parse_http_header_2);
    tcase_add_test(tc_core, test_parse_http_header_3);
    tcase_add_test(tc_core, test_parse_http_header_4);
    tcase_add_test(tc_core, test_parse_http_header_5);
    tcase_add_test(tc_core, test_parse_http_header_6);
    tcase_add_test(tc_core, test_parse_http_header_7);
    tcase_add_test(tc_core, test_parse_http_header_8);
    tcase_add_test(tc_core, test_parse_http_header_9);
    tcase_add_test(tc_core, test_parse_http_header_10);
    tcase_add_test(tc_core, test_parse_http_header_11);
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

