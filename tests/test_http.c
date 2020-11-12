/** test_http.c
 *
 * Integration tests for the relay station http parser
 */

#include <check.h>
#include "../flow.h"
#include "test_util.h"
#include "../webm.h"
#include "../webm.c"
#include "../relay.h"

START_TEST(parse_full_resource) {

    //need to create a flow for this
    flow *f = smalloc(sizeof(flow));

    //we only need to set the httpstate and remaining_element fields of the flow
    f->http_state = PARSE_HEADER;
    f->remaining_element = 0;

    uint8_t *data;
    int32_t file_len;

    /* Read in http data */
    if(!read_file_len("data/http_SJKHXYTGNB.dat", &data, &file_len)){
        ck_abort();
    }

    uint8_t *p = data;
    parse_http(f, p, file_len);


    ck_assert_int_eq(f->http_state, MID_CONTENT);

    free(data);
    free(f);
}
END_TEST

START_TEST(parse_full_chunked) {

    //need to create a flow for this
    flow *f = smalloc(sizeof(flow));

    //we only need to set the httpstate and remaining_element fields of the flow
    f->http_state = PARSE_HEADER;
    f->remaining_element = 0;

    uint8_t *data;
    int32_t file_len;

    /* Read in http data */
    if(!read_file_len("data/http_chunked.dat", &data, &file_len)){
        ck_abort();
    }

    uint8_t *p = data;
    parse_http(f, p, file_len);

    ck_assert_int_eq(f->http_state, PARSE_HEADER);

    free(data);
    free(f);
}
END_TEST

START_TEST(parse_split_chunked) {

    //need to create a flow for this
    flow *f = smalloc(sizeof(flow));

    //we only need to set the httpstate and remaining_element fields of the flow
    f->http_state = PARSE_HEADER;
    f->remaining_element = 0;

    uint8_t *data;
    int32_t file_len;

    /* Read in http data */
    if(!read_file_len("data/http_chunked.dat", &data, &file_len)){
        ck_abort();
    }

    uint8_t *p = data;

    int header_split = 700;
    parse_http(f, p, header_split);
    ck_assert_int_eq(f->http_state, PARSE_HEADER);
    p += header_split;

    int begin_chunk_split = 32;
    parse_http(f, p, begin_chunk_split);
    ck_assert_int_eq(f->http_state, BEGIN_CHUNK);
    p += begin_chunk_split;

    int mid_chunk_split = 9000;
    parse_http(f, p, mid_chunk_split);
    ck_assert_int_eq(f->http_state, MID_CHUNK);
    p += mid_chunk_split;

    int end_chunk_split = 3492;
    parse_http(f, p, end_chunk_split);
    ck_assert_int_eq(f->http_state, END_CHUNK);
    p += end_chunk_split;

    begin_chunk_split = 2;
    parse_http(f, p, begin_chunk_split);
    ck_assert_int_eq(f->http_state, BEGIN_CHUNK);
    p += begin_chunk_split;

    int end_body_split = 3;
    parse_http(f, p, end_body_split);
    ck_assert_int_eq(f->http_state, END_BODY);
    p += end_body_split;

    parse_http(f, p, 2);
    ck_assert_int_eq(f->http_state, PARSE_HEADER);

    free(data);
    free(f);
}
END_TEST

START_TEST(parse_partial_header) {
    
    //need to create a flow for this
    flow *f = smalloc(sizeof(flow));

    //we only need to set the httpstate and remaining_element fields of the flow
    f->http_state = PARSE_HEADER;
    f->remaining_element = 0;

    uint8_t *data;
    int32_t file_len;

    /* Read in http data */
    if(!read_file_len("data/http_SJKHXYTGNB.dat", &data, &file_len)){
        ck_abort();
    }

    uint8_t *p = data;
    uint8_t temp = p[295];
    p[295] = '\0';
    parse_http(f, p, 295);

    p[295] = temp;

    ck_assert_int_eq(f->http_state, PARSE_HEADER);

    p += 295;
    parse_http(f, p, file_len - 295);

    ck_assert_int_eq(f->http_state, MID_CONTENT);

    free(data);
    free(f);
}
END_TEST

Suite *http_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("HTTP Parser");

    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, parse_full_resource);
    tcase_add_test(tc_core, parse_full_chunked);
    tcase_add_test(tc_core, parse_split_chunked);
    tcase_add_test(tc_core, parse_partial_header);
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
