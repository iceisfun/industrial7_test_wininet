/* hep_status.c - status-line robustness: one raw response per test, the server closes after sending it.
 * The client is HttpOpenRequestA(GET /edge) + HttpSendRequestA; the signature records send result, numeric status,
 * HTTP_QUERY_VERSION, HTTP_QUERY_STATUS_TEXT and the body. Expectations are Win10 VM observations, structurally
 * explained by CHttpHeaderParser::ParseStatusLine@0xbd050 (up to 4 bytes of junk skipped before "HTTP", case-insensitive
 * "HTTP" match, status = any run of ASCII digits accumulated without a range check, reason = rest of the line) and
 * _ParseResponseLine@0xbcea8 (no status line -> HTTP/0.9 "downlevel" response, a synthetic "HTTP/1.0 200 OK").
 * See EVIDENCE.md. */
#include "hep.h"

#define CL2 "Content-Length: 2\r\n\r\nhi"

/* ------------------------------------------------------------ baselines */
RCASE(st_200_baseline,          "HTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_200_http10,            "HTTP/1.0 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.0 txt=OK n=2 body=hi")
RCASE(st_404,                   "HTTP/1.1 404 Not Found\r\n" CL2, "ok=1 st=404 ver=HTTP/1.1 txt=Not Found n=2 body=hi")
RCASE(st_500,                   "HTTP/1.1 500 Internal Server Error\r\n" CL2, "ok=1 st=500 ver=HTTP/1.1 txt=Internal Server Error n=2 body=hi")
/* ------------------------------------------------------------ unusual numbers */
RCASE(st_600,                   "HTTP/1.1 600 Six Hundred\r\n" CL2, "ok=1 st=600 ver=HTTP/1.1 txt=Six Hundred n=2 body=hi")
RCASE(st_699,                   "HTTP/1.1 699 X\r\n" CL2, "ok=1 st=699 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_999,                   "HTTP/1.1 999 X\r\n" CL2, "ok=1 st=999 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_1000,                  "HTTP/1.1 1000 X\r\n" CL2, "ok=1 st=1000 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_12345,                 "HTTP/1.1 12345 X\r\n" CL2, "ok=1 st=12345 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_4294967295,            "HTTP/1.1 4294967295 X\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_4294967296,            "HTTP/1.1 4294967296 X\r\n" CL2, "ok=0 err=12152")
RCASE(st_99999999999999999999,  "HTTP/1.1 99999999999999999999 X\r\n" CL2, "ok=0 err=12152")
RCASE(st_099,                   "HTTP/1.1 099 X\r\n" CL2, "ok=1 st=99 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_099_no_reason,         "HTTP/1.1 099\r\n" CL2, "ok=1 st=99 ver=HTTP/1.1 txt= n=2 body=hi")
RCASE(st_0,                     "HTTP/1.1 0 Zero\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=Zero n=2 body=hi")
RCASE(st_000,                   "HTTP/1.1 000 Zero\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=Zero n=2 body=hi")
RCASE(st_001,                   "HTTP/1.1 001 X\r\n" CL2, "ok=1 st=1 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_42_two_digits,         "HTTP/1.1 42 X\r\n" CL2, "ok=1 st=42 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_7_one_digit,           "HTTP/1.1 7 X\r\n" CL2, "ok=1 st=7 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_0200_leading_zero,     "HTTP/1.1 0200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_minus_1,               "HTTP/1.1 -1 X\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_plus_200,              "HTTP/1.1 +200 OK\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_letters,               "HTTP/1.1 abc OK\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_2OO_letter_o,          "HTTP/1.1 2OO OK\r\n" CL2, "ok=1 st=2 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_200x_suffix,           "HTTP/1.1 200x OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_20_0_space_inside,     "HTTP/1.1 20 0 OK\r\n" CL2, "ok=1 st=20 ver=HTTP/1.1 txt=0 OK n=2 body=hi")
RCASE(st_200_dot_5,             "HTTP/1.1 200.5 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_hex_0xc8,              "HTTP/1.1 0xC8 OK\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_fullwidth_digits,      "HTTP/1.1 \xef\xbc\x92\xef\xbc\x90\xef\xbc\x90 OK\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_high_byte_status,      "HTTP/1.1 \xb2\x30\x30 OK\r\n" CL2, "ok=1 st=4294967295 ver=HTTP/1.1 txt=OK n=2 body=hi")
/* 1xx/2xx without body semantics as a final status */
RCASE(st_199,                   "HTTP/1.1 199 X\r\n" CL2, "ok=1 st=200 ver=HTTP/1.0 txt=OK n=2 body=hi")
RCASE(st_299,                   "HTTP/1.1 299 X\r\n" CL2, "ok=1 st=299 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_399_no_location,       "HTTP/1.1 399 X\r\n" CL2, "ok=1 st=399 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_499,                   "HTTP/1.1 499 X\r\n" CL2, "ok=1 st=499 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_599,                   "HTTP/1.1 599 X\r\n" CL2, "ok=1 st=599 ver=HTTP/1.1 txt=X n=2 body=hi")
RCASE(st_204_with_body_bytes,   "HTTP/1.1 204 No Content\r\n" CL2, "ok=1 st=204 ver=HTTP/1.1 txt=No Content n=2 body=hi")
RCASE(st_304_with_body_bytes,   "HTTP/1.1 304 Not Modified\r\n" CL2, "ok=1 st=304 ver=HTTP/1.1 txt=Not Modified n=2 body=hi")
RCASE(st_101_without_upgrade,   "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nraw-after-101", "ok=1 st=101 ver=HTTP/1.1 txt=Switching Protocols n=0 body=")
RCASE(st_100_then_close,        "HTTP/1.1 100 Continue\r\n\r\n", "ok=0 err=12152")
RCASE(st_100_then_200,          "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_100_twice_then_200,    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_102_then_200,          "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_103_hints_then_200,    "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(st_199_interim_then_200,  "HTTP/1.1 199 Odd\r\n\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
/* ------------------------------------------------------------ reason phrase */
RCASE(rs_no_reason,             "HTTP/1.1 200\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt= n=2 body=hi")
RCASE(rs_no_reason_trailing_sp, "HTTP/1.1 200 \r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt= n=2 body=hi")
RCASE(rs_reason_spaces,         "HTTP/1.1 200 Very  Fine   Indeed\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=Very  Fine   Indeed n=2 body=hi")
RCASE(rs_reason_trailing_ws,    "HTTP/1.1 200 OK  \t\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK  \\t n=2 body=hi")
RCASE(rs_reason_tab_sep,        "HTTP/1.1\t200\tOK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(rs_many_spaces_sep,       "HTTP/1.1     200     OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(rs_reason_high_bytes,     "HTTP/1.1 200 \xc3\xa9t\xc3\xa9\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=\\xc3\\xa9t\\xc3\\xa9 n=2 body=hi")
RCASE(rs_reason_nul,            "HTTP/1.1 200 O\0K\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=O\\x00K n=2 body=hi")
RCASE(rs_reason_long_2000,      "HTTP/1.1 200 "
    "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
    "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
    "\r\n" CL2, NULL)
RCASE(rs_reason_lowercase_ok,   "HTTP/1.1 200 ok\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=ok n=2 body=hi")
RCASE(rs_reason_mismatch_404_ok,"HTTP/1.1 404 OK\r\n" CL2, "ok=1 st=404 ver=HTTP/1.1 txt=OK n=2 body=hi")
/* ------------------------------------------------------------ protocol token */
RCASE(pv_lowercase_http,        "http/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=http/1.1 txt=OK n=2 body=hi")
RCASE(pv_mixed_case_http,       "HtTp/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HtTp/1.1 txt=OK n=2 body=hi")
RCASE(pv_http2,                 "HTTP/2 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/2 txt=OK n=2 body=hi")
RCASE(pv_http20,                "HTTP/2.0 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/2.0 txt=OK n=2 body=hi")
RCASE(pv_http3,                 "HTTP/3 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/3 txt=OK n=2 body=hi")
RCASE(pv_http09,                "HTTP/0.9 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/0.9 txt=OK n=2 body=hi")
RCASE(pv_http99,                "HTTP/9.9 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/9.9 txt=OK n=2 body=hi")
RCASE(pv_http1_no_minor,        "HTTP/1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1 txt=OK n=2 body=hi")
RCASE(pv_http_1_12,             "HTTP/1.12 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.12 txt=OK n=2 body=hi")
RCASE(pv_http_no_slash,         "HTTP 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP txt=OK n=2 body=hi")
RCASE(pv_http_slash_only,       "HTTP/ 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/ txt=OK n=2 body=hi")
RCASE(pv_httpx,                 "HTTPX/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTPX/1.1 txt=OK n=2 body=hi")
RCASE(pv_https_token,           "HTTPS/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTPS/1.1 txt=OK n=2 body=hi")
RCASE(pv_icy,                   "ICY 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.0 txt=OK n=35 body=ICY 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nhi")
RCASE(pv_rtsp,                  "RTSP/1.0 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.0 txt=OK n=40 body=RTSP/1.0 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nhi")
RCASE(pv_junk_1_byte,           "XHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_junk_4_bytes,          "ABCDHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_junk_5_bytes,          "ABCDEHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.0 txt=OK n=45 body=ABCDEHTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nhi")
RCASE(pv_leading_space,         " HTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_leading_tab,           "\tHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_leading_crlf,          "\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_leading_2crlf,         "\r\n\r\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_leading_lf,            "\nHTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(pv_leading_nul,           "\0HTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
/* ------------------------------------------------------------ truncated / absent status line */
RCASE(tr_empty_close,           "", "ok=0 err=12152")
RCASE(tr_one_byte_H,            "H", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=1 body=H")
RCASE(tr_http_only,             "HTTP", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=4 body=HTTP")
RCASE(tr_http_version_only,     "HTTP/1.1", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=8 body=HTTP/1.1")
RCASE(tr_status_no_crlf,        "HTTP/1.1 200 OK", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=15 body=HTTP/1.1 200 OK")
RCASE(tr_status_line_only,      "HTTP/1.1 200 OK\r\n", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(tr_status_line_lf_only,   "HTTP/1.1 200 OK\n", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(tr_status_blank,          "HTTP/1.1 200 OK\r\n\r\n", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(tr_status_blank_body,     "HTTP/1.1 200 OK\r\n\r\nclose-delimited", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=15 body=close-delimited")
RCASE(tr_header_no_terminator,  "HTTP/1.1 200 OK\r\nX-A: 1\r\n", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(tr_header_partial_line,   "HTTP/1.1 200 OK\r\nX-A: 1", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(tr_header_half_name,      "HTTP/1.1 200 OK\r\nConte", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(tr_cl_body_short,         "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
/* HTTP/0.9 style: no status line at all */
RCASE(h09_plain_text,           "hello world, no headers", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=23 body=hello world, no headers")
RCASE(h09_html,                 "<html><body>x</body></html>\r\n", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=29 body=<html><body>x</body></html>\\r\\n")
RCASE(h09_looks_like_header,    "Content-Length: 2\r\n\r\nhi", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=23 body=Content-Length: 2\\r\\n\\r\\nhi")
RCASE(h09_binary,               "\x01\x02\x03\x00\xff\xfe", "ok=1 st=200 ver=HTTP/1.0 txt=OK n=6 body=\\x01\\x02\\x03\\x00\\xff\\xfe")
RCASE(h09_http_later_in_line,   "junk junk HTTP/1.1 200 OK\r\n" CL2, "ok=1 st=200 ver=HTTP/1.0 txt=OK n=50 body=junk junk HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\n")
/* ------------------------------------------------------------ line endings */
RCASE(le_lf_only,               "HTTP/1.1 200 OK\nContent-Length: 2\nX-A: 1\n\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(le_lf_status_crlf_rest,   "HTTP/1.1 200 OK\nContent-Length: 2\r\n\r\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(le_crlf_then_lf_end,      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(le_lf_then_crlf_end,      "HTTP/1.1 200 OK\nContent-Length: 2\n\r\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(le_cr_only,               "HTTP/1.1 200 OK\rContent-Length: 2\r\rhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=0 body=")
RCASE(le_crcrlf,                "HTTP/1.1 200 OK\r\r\nContent-Length: 2\r\r\n\r\r\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")
RCASE(le_lfcr,                  "HTTP/1.1 200 OK\n\rContent-Length: 2\n\r\n\rhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=\\rh")
RCASE(le_status_crlf_cr_cr,     "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\r\nhi", "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=hi")

/* ------------------------------------------------------------ status queries in more detail */
GTEST(hep_status_600_is_not_an_error_class, 150000) {
    /* HttpSendRequest succeeds for any status, and the number round-trips through FLAG_NUMBER and as a string */
    HEP_REQUIRE_HTTP();
    static const int codes[] = { 600, 601, 650, 700, 800, 900, 999 };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        char raw[128]; int n = snprintf(raw, sizeof raw, "HTTP/1.1 %d Custom\r\nContent-Length: 1\r\n\r\nz", codes[i]);
        HEP_SRV(h, hep_start_raw(raw, (size_t)n, 0));
        HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/c", NULL, NULL, NULL, HEP_F, 0);
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        CHECKF(ok, "code %d err %lu", codes[i], ok ? 0 : GetLastError());
        DWORD st = 0, l = sizeof st;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL));
        EXPECT_EQ(st, codes[i]);
        char s[32]; l = sizeof s;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE, s, &l, NULL));
        char want[16]; snprintf(want, sizeof want, "%d", codes[i]);
        EXPECT_STR(s, want);
        EXPECT_EQ(l, strlen(want));
        char b[16]; DWORD rd = 0;
        CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd));
        EXPECT_EQ(rd, 1);
        U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
    }
}

GTEST(hep_status_raw_headers_keep_original_line, 150000) {
    /* RAW_HEADERS_CRLF rebuilds the status line from version/code/text: record how an odd line comes back */
    HEP_REQUIRE_HTTP();
    static const char *lines[] = { "HTTP/1.1 600 Six", "HTTP/1.1 099 X", "http/1.1 200 ok", "HTTP/1.1  200  OK",
                                   "HTTP/1.1 200", "HTTP/2 200 OK", "HTTP/1.1\t200\tOK" };
    /* Win10 VM: version/code/text tokens kept as received ("099", "http/1.1"), separators normalised to one space,
     * an absent reason leaves a trailing space */
    static const char *want[] = { "HTTP/1.1 600 Six", "HTTP/1.1 099 X", "http/1.1 200 ok", "HTTP/1.1 200 OK",
                                  "HTTP/1.1 200 ", "HTTP/2 200 OK", "HTTP/1.1 200 OK" };
    for (size_t i = 0; i < sizeof lines / sizeof lines[0]; i++) {
        char raw[256]; int n = snprintf(raw, sizeof raw, "%s\r\nX-K: v\r\nContent-Length: 0\r\n\r\n", lines[i]);
        HEP_SRV(h, hep_start_raw(raw, (size_t)n, 0));
        HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/r", NULL, NULL, NULL, HEP_F, 0);
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        char b[1024]; DWORD l = sizeof b;
        BOOL q = ok && U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF, b, &l, NULL);
        if (q) t_note("OBS raw[%s] -> %s", lines[i], hep_esc(b, l));
        else t_note("OBS raw[%s] -> ok=%d err=%lu", lines[i], ok, GetLastError());
        CHECK(ok); CHECK(q);
        if (q) { char w[256]; snprintf(w, sizeof w, "%s\r\nX-K: v\r\nContent-Length: 0\r\n\r\n", want[i]); EXPECT_STR(b, w); }
        U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
    }
}

GTEST(hep_status_downlevel_query_errors, 150000) {
    /* HTTP/0.9 response: which queries answer and which fail */
    HEP_REQUIRE_HTTP();
    static const char raw[] = "plain body with no status line";
    HEP_SRV(h, hep_start_raw(raw, sizeof raw - 1, 0));
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/d", NULL, NULL, NULL, HEP_F, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD e = ok ? 0 : GetLastError();
    t_note("OBS downlevel send ok=%d err=%lu", ok, e);
    CHECK(ok);
    if (ok) {
        static const DWORD lv[] = { HTTP_QUERY_STATUS_CODE, HTTP_QUERY_STATUS_TEXT, HTTP_QUERY_VERSION, HTTP_QUERY_RAW_HEADERS_CRLF,
                                    HTTP_QUERY_RAW_HEADERS, HTTP_QUERY_CONTENT_LENGTH, HTTP_QUERY_CONTENT_TYPE, HTTP_QUERY_DATE };
        for (size_t i = 0; i < sizeof lv / sizeof lv[0]; i++) {
            char b[512]; DWORD l = sizeof b;
            SetLastError(0);
            BOOL q = U(HttpQueryInfoA)(hr, lv[i], b, &l, NULL);
            DWORD e = q ? 0 : GetLastError();
            t_note("OBS downlevel level %lu -> %d %s", lv[i], q, q ? hep_esc(b, l) : t_inet_errname(e));
            /* Win10 VM: a synthetic "HTTP/1.0 200 OK" with no headers (_ParseResponseLine@0xbcea8 AddHeader("HTTP/1.0","200","OK")) */
            static const char *want[] = { "200", "OK", "HTTP/1.0", "HTTP/1.0 200 OK\r\n\r\n", "HTTP/1.0 200 OK", NULL, NULL, NULL };
            if (want[i]) { CHECK(q); if (q) EXPECT_STR(b, want[i]); }
            else { CHECK(!q); EXPECT_EQ(e, ERROR_HTTP_HEADER_NOT_FOUND); }
        }
        char body[128]; int rok; size_t n = t_inet_read_all(hr, body, sizeof body, &rok);
        CHECK(rok);
        EXPECT_STR(body, raw);
        EXPECT_EQ(n, sizeof raw - 1);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
