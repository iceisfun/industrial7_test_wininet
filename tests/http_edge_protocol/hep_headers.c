/* hep_headers.c - response header-block robustness: obs-fold, NUL and control bytes, malformed lines, header sizes and
 * counts, tiny TCP segments, Content-Length variants, Transfer-Encoding with Content-Length, Upgrade/Alt-Svc
 * advertisements and Content-Type charsets. Raw response then close (hep_rcase) unless stated otherwise.
 * Parser: CHttpHeaderParser (ParseHeaders / ParseStatusLine@0xbd050) in wininet.dll 11.0.19041; expectations are Win10
 * VM observations (EVIDENCE.md). */
#include "hep.h"
#include <stdlib.h>

#define CL2 "Content-Length: 2\r\n\r\nhi"
#define S200 "HTTP/1.1 200 OK\r\n"

/* ------------------------------------------------------------ obs-fold and whitespace (query X-T) */
RCASEH(fold_space,               S200 "X-T: a\r\n b\r\n" CL2, "X-T", NULL)
RCASEH(fold_tab,                 S200 "X-T: a\r\n\tb\r\n" CL2, "X-T", NULL)
RCASEH(fold_many_lines,          S200 "X-T: a\r\n b\r\n c\r\n\td\r\n" CL2, "X-T", NULL)
RCASEH(fold_only_ws_line,        S200 "X-T: a\r\n   \r\n" CL2, "X-T", NULL)
RCASEH(fold_empty_first,         S200 "X-T:\r\n b\r\n" CL2, "X-T", NULL)
RCASEH(fold_lf_only,             "HTTP/1.1 200 OK\nX-T: a\n b\nContent-Length: 2\n\nhi", "X-T", NULL)
RCASEH(fold_after_status_line,   S200 " X-T: a\r\n" CL2, "X-T", NULL)
RCASEH(fold_into_content_length, S200 "Content-Length:\r\n 2\r\n\r\nhi", "Content-Length", NULL)
RCASEH(ws_before_colon,          S200 "X-T : v\r\n" CL2, "X-T", NULL)
RCASEH(ws_tab_before_colon,      S200 "X-T\t: v\r\n" CL2, "X-T", NULL)
RCASEH(ws_no_space_after_colon,  S200 "X-T:v\r\n" CL2, "X-T", NULL)
RCASEH(ws_many_spaces_value,     S200 "X-T:     v  \r\n" CL2, "X-T", NULL)
RCASEH(ws_trailing_tabs,         S200 "X-T: v\t\t\r\n" CL2, "X-T", NULL)
RCASEH(ws_inner_spaces,          S200 "X-T: a   b\r\n" CL2, "X-T", NULL)
RCASEH(empty_value,              S200 "X-T:\r\n" CL2, "X-T", NULL)
RCASEH(empty_value_space,        S200 "X-T: \r\n" CL2, "X-T", NULL)
RCASEH(colon_in_value,           S200 "X-T: a:b: c\r\n" CL2, "X-T", NULL)
RCASEH(double_colon,             S200 "X-T:: v\r\n" CL2, "X-T", NULL)
RCASEH(no_colon_line_before,     S200 "garbage line\r\nX-T: v\r\n" CL2, "X-T", NULL)
RCASEH(no_colon_line_after,      S200 "X-T: v\r\ngarbage line\r\n" CL2, "X-T", NULL)
RCASEH(empty_name,               S200 ": v\r\nX-T: w\r\n" CL2, "X-T", NULL)
RCASEH(name_with_space,          S200 "X T: v\r\n" CL2, "X T", NULL)
RCASEH(name_lowercase,           S200 "x-t: v\r\n" CL2, "X-T", NULL)
RCASEH(name_utf8,                S200 "X-\xc3\xa9: v\r\nX-T: w\r\n" CL2, "X-T", NULL)
RCASEH(duplicate_first_wins,     S200 "X-T: one\r\nX-T: two\r\n" CL2, "X-T", NULL)
/* ------------------------------------------------------------ NUL and control bytes */
RCASEH(nul_in_value,             S200 "X-T: a\0b\r\n" CL2, "X-T", NULL)
RCASEH(nul_at_value_start,       S200 "X-T: \0b\r\n" CL2, "X-T", NULL)
RCASEH(nul_in_name,              S200 "X-\0T: v\r\nX-T: w\r\n" CL2, "X-T", NULL)
RCASEH(nul_line,                 S200 "\0\r\nX-T: v\r\n" CL2, "X-T", NULL)
RCASEH(nul_before_terminator,    S200 "X-T: v\r\n\0\r\n\r\nhi", "X-T", NULL)
RCASEH(nul_in_content_length,    S200 "X-T: v\r\nContent-Length: 2\0" "0\r\n\r\nhi", "Content-Length", NULL)
RCASEH(ctl_bell_in_value,        S200 "X-T: a\x07" "b\r\n" CL2, "X-T", NULL)
RCASEH(ctl_del_in_value,         S200 "X-T: a\x7f" "b\r\n" CL2, "X-T", NULL)
RCASEH(ctl_bare_cr_in_value,     S200 "X-T: a\rb\r\n" CL2, "X-T", NULL)
RCASEH(ctl_esc_in_name,          S200 "X\x1bT: v\r\nX-T: w\r\n" CL2, "X-T", NULL)
RCASEH(high_bytes_value,         S200 "X-T: \xff\xfe\x80\r\n" CL2, "X-T", NULL)
/* ------------------------------------------------------------ response splitting / injected heads */
RCASEH(split_second_status_in_headers, S200 "X-T: v\r\nHTTP/1.1 302 Found\r\nLocation: /evil\r\n" CL2, "Location", NULL)
RCASEH(split_header_value_crlf_crlf, S200 "X-T: v\r\n\r\nHTTP/1.1 200 OK\r\nX-Evil: 1\r\nContent-Length: 0\r\n\r\n", "X-Evil", NULL)
RCASEH(split_set_cookie_injected_by_lf, S200 "X-T: v\nSet-Cookie: inj=1\r\n" CL2, "Set-Cookie", NULL)

/* ------------------------------------------------------------ Content-Length variants (signature includes cl=) */
RCASECL(cl_exact,               S200 "Content-Length: 2\r\n\r\nhi", NULL)
RCASECL(cl_zero_with_bytes,     S200 "Content-Length: 0\r\n\r\nhi", NULL)
RCASECL(cl_smaller,             S200 "Content-Length: 1\r\n\r\nhi", NULL)
RCASECL(cl_larger_then_close,   S200 "Content-Length: 5\r\n\r\nhi", NULL)
RCASECL(cl_negative,            S200 "Content-Length: -1\r\n\r\nhi", NULL)
RCASECL(cl_negative_big,        S200 "Content-Length: -100\r\n\r\nhi", NULL)
RCASECL(cl_huge_20_digits,      S200 "Content-Length: 99999999999999999999\r\n\r\nhi", NULL)
RCASECL(cl_4294967295,          S200 "Content-Length: 4294967295\r\n\r\nhi", NULL)
RCASECL(cl_4294967296,          S200 "Content-Length: 4294967296\r\n\r\nhi", NULL)
RCASECL(cl_4294967298,          S200 "Content-Length: 4294967298\r\n\r\nhi", NULL)
RCASECL(cl_dup_equal,           S200 "Content-Length: 2\r\nContent-Length: 2\r\n\r\nhi", NULL)
RCASECL(cl_dup_conflict_small_first, S200 "Content-Length: 1\r\nContent-Length: 2\r\n\r\nhi", NULL)
RCASECL(cl_dup_conflict_big_first,   S200 "Content-Length: 2\r\nContent-Length: 1\r\n\r\nhi", NULL)
RCASECL(cl_list_equal,          S200 "Content-Length: 2, 2\r\n\r\nhi", NULL)
RCASECL(cl_list_conflict,       S200 "Content-Length: 1, 2\r\n\r\nhi", NULL)
RCASECL(cl_non_numeric,         S200 "Content-Length: abc\r\n\r\nhi", NULL)
RCASECL(cl_numeric_prefix,      S200 "Content-Length: 1abc\r\n\r\nhi", NULL)
RCASECL(cl_plus_sign,           S200 "Content-Length: +1\r\n\r\nhi", NULL)
RCASECL(cl_hex,                 S200 "Content-Length: 0x1\r\n\r\nhi", NULL)
RCASECL(cl_leading_zeros,       S200 "Content-Length: 0001\r\n\r\nhi", NULL)
RCASECL(cl_spaces_around,       S200 "Content-Length:    1   \r\n\r\nhi", NULL)
RCASECL(cl_inner_space,         S200 "Content-Length: 1 1\r\n\r\nhi", NULL)
RCASECL(cl_empty,               S200 "Content-Length:\r\n\r\nhi", NULL)
RCASECL(cl_lowercase_name,      S200 "content-length: 1\r\n\r\nhi", NULL)
RCASECL(cl_float,               S200 "Content-Length: 1.5\r\n\r\nhi", NULL)
RCASECL(cl_on_head_like_304,    "HTTP/1.1 304 Not Modified\r\nContent-Length: 2\r\n\r\nhi", NULL)
/* ------------------------------------------------------------ Transfer-Encoding with/without Content-Length */
RCASECL(te_chunked_plus_cl,     S200 "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_cl_then_chunked_order, S200 "Transfer-Encoding: chunked\r\nContent-Length: 50\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunked_caps,        S200 "Transfer-Encoding: CHUNKED\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_gzip_chunked,        S200 "Transfer-Encoding: gzip, chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunked_identity,    S200 "Transfer-Encoding: chunked, identity\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_identity_with_cl,    S200 "Transfer-Encoding: identity\r\nContent-Length: 2\r\n\r\nhi", NULL)
RCASECL(te_unknown_close,       S200 "Transfer-Encoding: foo\r\n\r\nhi", NULL)
RCASECL(te_two_headers,         S200 "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunked_http10,      "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunked_space_value, S200 "Transfer-Encoding:   chunked  \r\n\r\n2\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunk_ext_and_trailer, S200 "Transfer-Encoding: chunked\r\n\r\n2;a=b\r\nhi\r\n0\r\nX-Trailer: 1\r\n\r\n", NULL)
RCASECL(te_chunk_size_uppercase_hex, S200 "Transfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n", NULL)
RCASECL(te_chunk_size_leading_zeros, S200 "Transfer-Encoding: chunked\r\n\r\n0002\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunk_lf_only,       S200 "Transfer-Encoding: chunked\r\n\r\n2\nhi\n0\n\n", NULL)
RCASECL(te_chunk_bad_size,      S200 "Transfer-Encoding: chunked\r\n\r\nzz\r\nhi\r\n0\r\n\r\n", NULL)
RCASECL(te_chunk_missing_last,  S200 "Transfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n", NULL)
/* ------------------------------------------------------------ advertisements that must not change the protocol */
RCASEH(adv_alt_svc_h3,          S200 "Alt-Svc: h3=\":443\"; ma=86400\r\n" CL2, "Alt-Svc", NULL)
RCASEH(adv_upgrade_h2c,         S200 "Upgrade: h2c\r\nConnection: Upgrade\r\n" CL2, "Upgrade", NULL)
RCASEH(adv_upgrade_h2,          S200 "Upgrade: h2,h2c\r\n" CL2, "Upgrade", NULL)
RCASEH(adv_http2_settings,      S200 "HTTP2-Settings: AAMAAABkAAQAAP__\r\n" CL2, "HTTP2-Settings", NULL)
RCASEH(adv_426_upgrade_required, "HTTP/1.1 426 Upgrade Required\r\nUpgrade: TLS/1.2, HTTP/1.1\r\nConnection: Upgrade\r\n" CL2, "Upgrade", NULL)
RCASEH(ct_charset_utf8,         S200 "Content-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\n\xc3\xa9\xc3\xa9", "Content-Type", NULL)
RCASEH(ct_charset_latin1,       S200 "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Length: 2\r\n\r\n\xe9\xe9", "Content-Type", NULL)
RCASEH(ct_charset_utf16,        S200 "Content-Type: text/plain; charset=utf-16\r\nContent-Length: 4\r\n\r\n\xff\xfeh\0", "Content-Type", NULL)
RCASEH(ct_charset_bogus,        S200 "Content-Type: text/html; charset=\"x-bogus\"\r\n" CL2, "Content-Type", NULL)
RCASEH(ct_no_type,              S200 "Content-Type:\r\n" CL2, "Content-Type", NULL)

/* ------------------------------------------------------------ the body bytes are never transcoded */
GTEST(hep_ct_charset_body_bytes_identical, 150000) {
    HEP_REQUIRE_HTTP();
    static const char *types[] = { "text/plain; charset=utf-8", "text/plain; charset=iso-8859-1", "text/html; charset=shift_jis",
                                   "application/json; charset=utf-16", "text/plain; charset=koi8-r", "application/octet-stream" };
    static const unsigned char payload[] = { 0xc3, 0xa9, 0x00, 0xff, 0xfe, 0x82, 0xa0, 0x0d, 0x0a, 0x1a, 0x80, 0x41 };
    for (size_t i = 0; i < sizeof types / sizeof types[0]; i++) {
        char head[256]; int n = snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n", types[i], (unsigned)sizeof payload);
        char raw[512]; memcpy(raw, head, (size_t)n); memcpy(raw + n, payload, sizeof payload);
        HEP_SRV(h, hep_start_raw(raw, (size_t)n + sizeof payload, 0));
        hep_req rq = {0}; hep_res r;
        hep_do(h, &rq, &r);
        CHECKF(r.ok, "%s err %lu", types[i], r.err);
        EXPECT_EQ(r.nbody, sizeof payload);
        CHECKF(r.nbody == sizeof payload && !memcmp(r.body, payload, sizeof payload), "body bytes changed for %s: %s", types[i], hep_esc(r.body, r.nbody));
        hep_stop(h);
    }
}

/* ------------------------------------------------------------ sizes: long header lines */
static void long_header_case(size_t vlen, const char *want_sig, int also_value) {
    size_t cap = vlen + 256; char *raw = (char *)malloc(cap);
    size_t n = (size_t)snprintf(raw, cap, "HTTP/1.1 200 OK\r\nX-Long: ");
    for (size_t i = 0; i < vlen; i++) raw[n++] = (char)('a' + i % 26);
    n += (size_t)snprintf(raw + n, cap - n, "\r\nContent-Length: 2\r\n\r\nhi");
    hep_srv *h = hep_start_raw(raw, n, 0);
    free(raw);
    if (!h) return;
    hep_req rq = {0}; hep_res r; rq.timeout_ms = 5000;
    hep_do(h, &rq, &r);
    char tag[64]; snprintf(tag, sizeof tag, "long_header_%zu", vlen);
    EXPECT_SIG(tag, hep_sig(&r, 0), want_sig);
    if (r.ms > 2500) t_note("%s: %lu ms", tag, r.ms);
    (void)also_value;
    hep_stop(h);
}
GTEST(hep_size_header_value_1k, 60000)   { HEP_REQUIRE_HTTP(); long_header_case(1024, NULL, 1); }
GTEST(hep_size_header_value_8k, 60000)   { HEP_REQUIRE_HTTP(); long_header_case(8192, NULL, 1); }
GTEST(hep_size_header_value_16k, 60000)  { HEP_REQUIRE_HTTP(); long_header_case(16384, NULL, 1); }
GTEST(hep_size_header_value_64k, 60000)  { HEP_REQUIRE_HTTP(); long_header_case(65536, NULL, 1); }
GTEST(hep_size_header_value_128k, 150000) { HEP_REQUIRE_HTTP(); long_header_case(131072, NULL, 1); }
GTEST(hep_size_header_value_256k, 150000) { HEP_REQUIRE_HTTP(); long_header_case(262144, NULL, 1); }
GTEST(hep_size_header_value_1m, 60000)   { HEP_REQUIRE_HTTP(); long_header_case(1048576, NULL, 1); }

GTEST(hep_size_long_header_value_roundtrip_64k, 150000) {
    /* when a 64 KB value is accepted, HttpQueryInfo returns it byte for byte */
    HEP_REQUIRE_HTTP();
    size_t vlen = 65536, cap = vlen + 256; char *raw = (char *)malloc(cap);
    size_t n = (size_t)snprintf(raw, cap, "HTTP/1.1 200 OK\r\nX-Long: ");
    for (size_t i = 0; i < vlen; i++) raw[n++] = (char)('a' + i % 26);
    n += (size_t)snprintf(raw + n, cap - n, "\r\nContent-Length: 2\r\n\r\nhi");
    hep_srv *h = hep_start_raw(raw, n, 0); free(raw); if (!h) return;
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/l", NULL, NULL, NULL, HEP_F, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    t_note("OBS 64k header send ok=%d err=%lu", ok, ok ? 0 : GetLastError());
    if (ok) {
        char *buf = (char *)malloc(vlen + 64); DWORD l = (DWORD)vlen + 64; strcpy(buf, "X-Long");
        BOOL q = U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, buf, &l, NULL);
        CHECKF(q, "err %lu", GetLastError());
        if (q) {
            EXPECT_EQ(l, vlen);
            int same = 1; for (size_t i = 0; i < vlen && same; i++) same = buf[i] == (char)('a' + i % 26);
            CHECK(same);
        }
        free(buf);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ sizes: header counts */
static void many_headers_case(int count, int distinct, const char *want_sig) {
    size_t cap = (size_t)count * 40 + 256; char *raw = (char *)malloc(cap);
    size_t n = (size_t)snprintf(raw, cap, "HTTP/1.1 200 OK\r\n");
    for (int i = 0; i < count; i++)
        n += distinct ? (size_t)snprintf(raw + n, cap - n, "X-H%d: v%d\r\n", i, i) : (size_t)snprintf(raw + n, cap - n, "X-Same: v%d\r\n", i);
    n += (size_t)snprintf(raw + n, cap - n, "Content-Length: 2\r\n\r\nhi");
    hep_srv *h = hep_start_raw(raw, n, 0);
    free(raw);
    if (!h) return;
    HINTERNET hi = hep_session(NULL, 5000), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/m", NULL, NULL, NULL, HEP_F, 0);
    DWORD t0 = GetTickCount();
    hep_res r; memset(&r, 0, sizeof r);
    r.ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); r.err = r.ok ? 0 : GetLastError();
    char tag[64]; snprintf(tag, sizeof tag, "many_headers_%d_%s", count, distinct ? "distinct" : "same");
    if (r.ok) {
        DWORD st = 0, l = sizeof st; U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL); r.status = (int)st;
        r.read_ok = 1; r.nbody = t_inet_read_all(hr, r.body, sizeof r.body, &r.read_ok);
        /* the last header is reachable (by name or by index) */
        char b[64]; l = sizeof b;
        if (distinct) { snprintf(b, sizeof b, "X-H%d", count - 1); BOOL q = U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, NULL); t_note("OBS %s last -> %d %s", tag, q, q ? b : t_inet_errname(GetLastError())); }
        else { DWORD idx = (DWORD)count - 1; strcpy(b, "X-Same"); BOOL q = U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, &idx); t_note("OBS %s idx %d -> %d %s", tag, count - 1, q, q ? b : t_inet_errname(GetLastError())); }
    }
    EXPECT_SIG(tag, hep_sig(&r, 0), want_sig);
    t_note("%s: %lu ms", tag, GetTickCount() - t0);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_count_headers_100, 60000)          { HEP_REQUIRE_HTTP(); many_headers_case(100, 1, NULL); }
GTEST(hep_count_headers_1000, 60000)         { HEP_REQUIRE_HTTP(); many_headers_case(1000, 1, NULL); }
GTEST(hep_count_headers_5000, 60000)         { HEP_REQUIRE_HTTP(); many_headers_case(5000, 1, NULL); }
GTEST(hep_count_headers_20000, 60000)        { HEP_REQUIRE_HTTP(); many_headers_case(20000, 1, NULL); }
GTEST(hep_count_same_name_1000, 60000)       { HEP_REQUIRE_HTTP(); many_headers_case(1000, 0, NULL); }
GTEST(hep_count_same_name_10000, 60000)      { HEP_REQUIRE_HTTP(); many_headers_case(10000, 0, NULL); }

/* ------------------------------------------------------------ tiny TCP segments */
static void split_case(const char *tag, int piece, int ms, const char *want_sig) {
    static const char raw[] = "HTTP/1.1 200 OK\r\nX-T: split-value\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\n0123456789";
    srv_step st[3]; memset(st, 0, sizeof st);
    st[0].op = SRV_RECV_HEAD;
    st[1].op = SRV_SEND_SPLIT; st[1].data = raw; st[1].n = sizeof raw - 1; st[1].arg = piece; st[1].flags = (unsigned)ms;
    st[2].op = SRV_CLOSE;
    HEP_SRV(h, hep_start(st, 3));
    hep_req rq = {0}; hep_res r; rq.qname = "X-T"; rq.timeout_ms = 5000;
    hep_do(h, &rq, &r);
    EXPECT_SIG(tag, hep_sig(&r, 7), want_sig);
    hep_stop(h);
}
#define SPLIT_WANT "ok=1 st=200 ver=HTTP/1.1 txt=OK h=split-value n=10 body=0123456789"
GTEST(hep_split_1byte_0ms, 60000)   { HEP_REQUIRE_HTTP(); split_case("split_1_0", 1, 0, SPLIT_WANT); }
GTEST(hep_split_1byte_2ms, 60000)   { HEP_REQUIRE_HTTP(); split_case("split_1_2", 1, 2, SPLIT_WANT); }
GTEST(hep_split_2byte_5ms, 60000)   { HEP_REQUIRE_HTTP(); split_case("split_2_5", 2, 5, SPLIT_WANT); }
GTEST(hep_split_3byte_1ms, 60000)   { HEP_REQUIRE_HTTP(); split_case("split_3_1", 3, 1, SPLIT_WANT); }
GTEST(hep_split_7byte_10ms, 60000)  { HEP_REQUIRE_HTTP(); split_case("split_7_10", 7, 10, SPLIT_WANT); }
GTEST(hep_split_17byte_20ms, 150000) { HEP_REQUIRE_HTTP(); split_case("split_17_20", 17, 20, SPLIT_WANT); }

static int split_at_call(srv_conn *c, const srv_step *st, void *user) {
    /* send the response in two writes split exactly at offset *(int*)user, 60 ms apart */
    static const char raw[] = "HTTP/1.1 200 OK\r\nX-T: split-value\r\nContent-Length: 10\r\n\r\n0123456789";
    int at = *(int *)user;
    if (srv_conn_recv_head(c) < 0) return -1;
    srv_conn_send(c, raw, (size_t)at);
    Sleep(60);
    srv_conn_send(c, raw + at, sizeof raw - 1 - (size_t)at);
    return -1;
}
GTEST(hep_split_every_boundary, 150000) {
    /* a two-segment response, split at every offset of the head: CR|LF, inside the status line, inside "\r\n\r\n" */
    HEP_REQUIRE_HTTP();
    static const char raw[] = "HTTP/1.1 200 OK\r\nX-T: split-value\r\nContent-Length: 10\r\n\r\n0123456789";
    int bad = 0;
    for (int at = 1; at < (int)sizeof raw - 1; at += (at < 60 ? 1 : 3)) {
        srv_step st[2]; memset(st, 0, sizeof st);
        st[0].op = SRV_CALL; st[0].fn = split_at_call;
        hep_srv *h = (hep_srv *)calloc(1, sizeof *h);
        h->steps = (srv_step *)calloc(2, sizeof *h->steps); memcpy(h->steps, st, sizeof st); h->nsteps = 2;
        h->sc.steps = h->steps; h->sc.nsteps = 2;
        int *arg = (int *)malloc(sizeof *arg); *arg = at; h->blob = arg;
        srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = &h->sc; cfg.nscripts = 1; cfg.user = arg;
        if (srv_start(&cfg, &h->s) != SRV_OK) { t_skip("server unavailable"); free(arg); free(h->steps); free(h); return; }
        hep_req rq = {0}; hep_res r; rq.qname = "X-T";
        hep_do(h, &rq, &r);
        const char *sig = hep_sig(&r, 7);
        if (strcmp(sig, SPLIT_WANT)) { bad++; t_check(0, __FILE__, __LINE__, "split at", "offset %d: %s", at, sig); }
        hep_stop(h);
    }
    EXPECT_EQ(bad, 0);
}
