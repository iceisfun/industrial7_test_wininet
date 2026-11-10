/* bio_framing.c - response framing: chunked (sizes, extensions, trailers, malformed sizes), close-delimited,
 * truncated Content-Length, no-body statuses (204/304/HEAD/CL 0), HTTP/1.0 and Connection: close semantics,
 * keep-alive reuse and draining, HttpSendRequest again on the same handle.
 * VM_TIMEOUT: 300 */
#include "bio.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ chunked */
static void chunked_case(size_t n, size_t csz, DWORD piece) {
    srv_step st[] = { S_HEAD(), { SRV_REPLY, NULL, n, 200, NULL, SRV_R_CHUNKED, csz }, S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/ch");
    EXPECT_EQ(bio_status(hr), 200);
    char hb[64]; DWORD err = 0;
    CHECK(bio_hdr(hr, HTTP_QUERY_CONTENT_LENGTH, hb, sizeof hb, &err) == NULL);
    EXPECT_EQ(err, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_STR(bio_hdr(hr, HTTP_QUERY_TRANSFER_ENCODING, hb, sizeof hb, &err), "chunked");
    unsigned char *b = malloc(n + 16); bio_rd r;
    size_t got = bio_read(hr, b, n + 16, piece, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    CHECKF(got == n, "n=%u csz=%u piece=%lu got=%u", (unsigned)n, (unsigned)csz, piece, (unsigned)got);
    CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    EXPECT_EQ(r.over, 0);
    DWORD rd = 77; CHECK(U(InternetReadFile)(hr, b, 16, &rd)); EXPECT_EQ(rd, 0);
    free(b); bio_h(hr); bio_close(&e);
}
#define CH_TEST(n, csz, piece) TEST(bio_chunked_##n##_c##csz##_r##piece) { REQUIRE(U(InternetReadFile)); chunked_case(n, csz, piece); }
CH_TEST(1, 1, 1) CH_TEST(1, 0, 4096)
CH_TEST(10, 3, 1) CH_TEST(10, 3, 4) CH_TEST(10, 10, 100)
CH_TEST(100, 1, 7) CH_TEST(100, 1, 4096)
CH_TEST(4096, 1000, 4096) CH_TEST(4096, 4096, 1) CH_TEST(4096, 4095, 4096) CH_TEST(4097, 4096, 4097)
CH_TEST(8192, 8192, 8192) CH_TEST(8193, 8192, 512) CH_TEST(8193, 1, 8193)
CH_TEST(65536, 65536, 65536) CH_TEST(65537, 4096, 65536) CH_TEST(65537, 65536, 1000) CH_TEST(65535, 7, 65536)
CH_TEST(300000, 65536, 65536) CH_TEST(300000, 100000, 4096) CH_TEST(1048576, 16384, 65536) CH_TEST(1048576, 0, 32768)

/* raw-bytes chunked responses */
static void raw_case(const char *resp, size_t rlen, int close_after, const char *want, size_t wantn, DWORD piece) {
    srv_step st[] = { S_HEAD(), S_SENDN(resp, rlen), S_LOOP() };
    if (close_after) st[2].op = SRV_CLOSE;
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/raw");
    EXPECT_EQ(bio_status(hr), 200);
    char b[512]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, piece, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    CHECKF(n == wantn && !memcmp(b, want, wantn), "got %u bytes", (unsigned)n);
    bio_h(hr); bio_close(&e);
}
#define CHUNK_HEAD "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
#define RAW(lit) lit, sizeof(lit) - 1

TEST(bio_chunked_empty_body) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "0\r\n\r\n"), 0, "", 0, 4096); }
TEST(bio_chunked_extensions) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "5;name=val\r\nhello\r\n3;a;b=\"q\"\r\n123\r\n0;last\r\n\r\n"), 0, "hello123", 8, 4096); }
TEST(bio_chunked_uppercase_hex) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "A\r\n0123456789\r\nb\r\nabcdefghijk\r\n0\r\n\r\n"), 0, "0123456789abcdefghijk", 21, 4096); }
TEST(bio_chunked_leading_zeros) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "0005\r\nhello\r\n000\r\n\r\n"), 0, "hello", 5, 4096); }
TEST(bio_chunked_trailers) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "3\r\nabc\r\n0\r\nX-Trailer: t1\r\nX-Other: t2\r\n\r\n"), 0, "abc", 3, 4096); }
TEST(bio_chunked_one_byte_reads) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "3\r\nabc\r\n1\r\nd\r\n2\r\nef\r\n0\r\n\r\n"), 0, "abcdef", 6, 1); }
TEST(bio_chunked_te_mixed_case) { REQUIRE(U(InternetReadFile)); raw_case(RAW("HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n4\r\nwxyz\r\n0\r\n\r\n"), 0, "wxyz", 4, 4096); }
TEST(bio_chunked_close_after) { REQUIRE(U(InternetReadFile)); raw_case(RAW(CHUNK_HEAD "4\r\nwxyz\r\n0\r\n\r\n"), 1, "wxyz", 4, 4096); }
/* RFC 7230 3.3.3: Transfer-Encoding wins over Content-Length */
TEST(bio_chunked_with_content_length) {
    REQUIRE(U(InternetReadFile));
    raw_case(RAW("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"), 0, "hello", 5, 4096);
}

/* Trailer bytes are consumed: the next request on the kept-alive connection parses cleanly. */
TEST(bio_chunked_trailer_then_keepalive) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND(CHUNK_HEAD "2\r\nok\r\n0\r\nX-T: 1\r\n\r\n"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    for (int i = 0; i < 3; i++) {
        HINTERNET hr = bio_get(&e, "/kt");
        char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
        CHECK(r.ok); EXPECT_EQ(n, 2); CHECK(!memcmp(b, "ok", 2));
        bio_h(hr);
    }
    CHECK(srv_wait_requests(e.s, 3, 2000));
    EXPECT_EQ(srv_conn_count(e.s), 1);
    EXPECT_EQ(srv_req_conn(e.s, 2), 0);
    bio_close(&e);
}

/* Chunk framing split into 1-byte TCP segments */
TEST(bio_chunked_split_segments) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SPLIT(CHUNK_HEAD "3;x=y\r\nabc\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n", 1, 1), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/sp");
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 19); CHECK(n == 19 && !memcmp(b, "abc0123456789abcdef", 19));
    bio_h(hr); bio_close(&e);
}

/* Malformed chunk framing: observe what reads return. Hard checks only for what the VM showed. */
static void bad_chunk_probe(const char *tag, const char *resp, size_t rlen, BOOL *pok, DWORD *perr, size_t *pn, char *pb, size_t cap) {
    srv_step st[] = { S_HEAD(), S_SENDN(resp, rlen), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 3)) { *pok = 2; return; }
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/bad", 0, NULL, &ok, &err);
    if (!ok) { t_note("%s: send failed err=%lu %s", tag, err, t_inet_errname(err)); *pok = 3; *perr = err; *pn = 0; bio_h(hr); bio_close(&e); return; }
    bio_rd r; size_t n = bio_read(hr, pb, cap, 0, &r);
    t_note("%s: read ok=%d err=%lu (%s) n=%u", tag, r.ok, r.err, r.ok ? "-" : t_inet_errname(r.err), (unsigned)n);
    *pok = r.ok; *perr = r.err; *pn = n;
    bio_h(hr); bio_close(&e);
}
TEST(bio_chunked_bad_size_token) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("chunk size 'zz'", RAW(CHUNK_HEAD "zz\r\nhello\r\n0\r\n\r\n"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    CHECK(n == 0 || ok == 0);                  /* never delivers the bytes after a bad size as body */
}
TEST(bio_chunked_bad_size_after_good_chunk) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("good then 'qq'", RAW(CHUNK_HEAD "3\r\nabc\r\nqq\r\nxyz\r\n0\r\n\r\n"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    CHECK(n >= 3 ? !memcmp(b, "abc", 3) : 1);
    CHECK(n <= 3);
}
TEST(bio_chunked_missing_terminal_chunk) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("no 0-chunk then close", RAW(CHUNK_HEAD "5\r\nhello\r\n"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    CHECK(n == 5 && !memcmp(b, "hello", 5));
}
TEST(bio_chunked_short_chunk_then_close) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("chunk 10 with 4 bytes then close", RAW(CHUNK_HEAD "a\r\nabcd"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    CHECK(n <= 4);
    if (n) CHECK(!memcmp(b, "abcd", n));
}
TEST(bio_chunked_huge_size) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("chunk size ffffffffffffffff", RAW(CHUNK_HEAD "ffffffffffffffff\r\nabc"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    CHECK(n <= 3);
}
TEST(bio_chunked_negative_size) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("chunk size -5", RAW(CHUNK_HEAD "-5\r\nhello\r\n0\r\n\r\n"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    CHECK(n == 0 || ok == 0);
}
TEST(bio_chunked_bare_lf_framing) {
    REQUIRE(U(InternetReadFile));
    BOOL ok; DWORD err; size_t n; char b[64];
    bad_chunk_probe("LF-only chunk lines", RAW("HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n5\nhello\n0\n\n"), &ok, &err, &n, b, sizeof b);
    if (ok == 2) return;
    t_note("LF-only chunked body: '%.*s'", (int)(n < 64 ? n : 64), b);
}

/* ------------------------------------------------------------------ close-delimited */
static void closedelim_case(size_t n, unsigned flags, DWORD piece) {
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, n, SRV_R_CLOSE | flags) };
    bio_env e; if (!bio_open(&e, st, 2)) return;
    HINTERNET hr = bio_get(&e, "/cd");
    EXPECT_EQ(bio_status(hr), 200);
    char hb[32]; DWORD err = 0;
    CHECK(bio_hdr(hr, HTTP_QUERY_CONTENT_LENGTH, hb, sizeof hb, &err) == NULL);
    EXPECT_EQ(err, ERROR_HTTP_HEADER_NOT_FOUND);
    unsigned char *b = malloc(n + 16); bio_rd r;
    size_t got = bio_read(hr, b, n + 16, piece, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    CHECKF(got == n, "n=%u got=%u", (unsigned)n, (unsigned)got);
    CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    DWORD rd = 77; CHECK(U(InternetReadFile)(hr, b, 16, &rd)); EXPECT_EQ(rd, 0);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_closedelim_0) { REQUIRE(U(InternetReadFile)); closedelim_case(0, 0, 4096); }
TEST(bio_closedelim_1) { REQUIRE(U(InternetReadFile)); closedelim_case(1, 0, 1); }
TEST(bio_closedelim_5000_by_1) { REQUIRE(U(InternetReadFile)); closedelim_case(5000, 0, 1); }
TEST(bio_closedelim_8192) { REQUIRE(U(InternetReadFile)); closedelim_case(8192, 0, 8192); }
TEST(bio_closedelim_70000) { REQUIRE(U(InternetReadFile)); closedelim_case(70000, 0, 4096); }
TEST(bio_closedelim_1mb) { REQUIRE(U(InternetReadFile)); closedelim_case(1048576, 0, 65536); }
TEST(bio_closedelim_http10_5000) { REQUIRE(U(InternetReadFile)); closedelim_case(5000, SRV_R_HTTP10, 777); }
TEST(bio_closedelim_http10_0) { REQUIRE(U(InternetReadFile)); closedelim_case(0, SRV_R_HTTP10, 4096); }

/* close-delimited body that ends with a half-close (shutdown SD_SEND) instead of closesocket */
TEST(bio_closedelim_shutdown_wr) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\nhalf-closed body"), S_SHUTWR(), S_SLEEP(500), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/sh");
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 16); CHECK(n == 16 && !memcmp(b, "half-closed body", 16));
    bio_h(hr); bio_close(&e);
}

/* close-delimited body arriving slowly in pieces */
TEST(bio_closedelim_slow_pieces) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\n"), S_SPLIT("0123456789abcdefghij", 4, 30), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = bio_get(&e, "/slow");
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 20); CHECK(n == 20 && !memcmp(b, "0123456789abcdefghij", 20));
    t_note("slow close-delimited body arrived in %d reads", r.calls);
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ truncated Content-Length */
/* [W10 n15, 02 6.1]: Content-Length larger than what arrives before the close: TRUE with the bytes received,
 * then TRUE/0 - no error. */
static void trunc_case(size_t n, DWORD piece) {
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, n, SRV_R_TRUNCATE) };
    bio_env e; if (!bio_open(&e, st, 2)) return;
    HINTERNET hr = bio_get(&e, "/tr");
    unsigned char *b = malloc(n + 16); bio_rd r;
    size_t got = bio_read(hr, b, n + 16, piece, &r);
    t_note("truncated CL %u (sent %u): ok=%d err=%lu got=%u", (unsigned)n, (unsigned)(n / 2), r.ok, r.err, (unsigned)got);
    CHECK(r.ok);
    EXPECT_EQ(got, n / 2);
    CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    DWORD rd = 77; BOOL ok = U(InternetReadFile)(hr, b, 16, &rd);
    CHECK(ok); EXPECT_EQ(rd, 0);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_truncated_100) { REQUIRE(U(InternetReadFile)); trunc_case(100, 4096); }
TEST(bio_truncated_100_by_1) { REQUIRE(U(InternetReadFile)); trunc_case(100, 1); }
TEST(bio_truncated_10000) { REQUIRE(U(InternetReadFile)); trunc_case(10000, 4096); }
TEST(bio_truncated_200000) { REQUIRE(U(InternetReadFile)); trunc_case(200000, 65536); }

TEST(bio_truncated_head_only) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/th");
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("CL 10, no body, close: ok=%d err=%lu n=%u", r.ok, r.err, (unsigned)n);
    CHECK(r.ok); EXPECT_EQ(n, 0);
    bio_h(hr); bio_close(&e);
}

/* Server sends more than Content-Length: the extra bytes are not part of the body */
TEST(bio_cl_extra_bytes_ignored) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA-GARBAGE"), S_SLEEP(300), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = bio_get(&e, "/x");
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ no-body responses */
static void nobody_case(const char *verb, const char *resp, size_t rlen, DWORD want_status) {
    srv_step st[] = { S_HEAD(), S_SENDN(resp, rlen), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, verb, "/nb", 0, NULL, &ok, &err);
    CHECKF(ok, "err=%lu", err);
    EXPECT_EQ(bio_status(hr), want_status);
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 0);
    DWORD q = bio_qda(hr, &err);
    CHECKF(q == 0, "QDA=%lu err=%lu", q, err);
    bio_h(hr);
    /* the connection is still in sync: a second request on it gets its own response */
    hr = bio_req(&e, verb, "/nb2", 0, NULL, &ok, &err);
    CHECKF(ok, "second request err=%lu", err);
    EXPECT_EQ(bio_status(hr), want_status);
    n = bio_read(hr, b, sizeof b, 0, &r); CHECK(r.ok); EXPECT_EQ(n, 0);
    bio_h(hr);
    CHECK(srv_wait_requests(e.s, 2, 2000));
    t_note("%s %lu: %d connection(s) for 2 requests", verb, want_status, srv_conn_count(e.s));
    bio_close(&e);
}
TEST(bio_nobody_cl0) { REQUIRE(U(InternetReadFile)); nobody_case("GET", RAW("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 200); }
TEST(bio_nobody_204) { REQUIRE(U(InternetReadFile)); nobody_case("GET", RAW("HTTP/1.1 204 No Content\r\n\r\n"), 204); }
TEST(bio_nobody_204_with_cl0) { REQUIRE(U(InternetReadFile)); nobody_case("GET", RAW("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"), 204); }
TEST(bio_nobody_304) { REQUIRE(U(InternetReadFile)); nobody_case("GET", RAW("HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n"), 304); }
TEST(bio_nobody_head_with_cl) { REQUIRE(U(InternetReadFile)); nobody_case("HEAD", RAW("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"), 200); }
TEST(bio_nobody_head_chunked) { REQUIRE(U(InternetReadFile)); nobody_case("HEAD", RAW("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"), 200); }
TEST(bio_nobody_post_cl0) { REQUIRE(U(InternetReadFile)); nobody_case("POST", RAW("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"), 201); }

/* HEAD keeps the advertised Content-Length queryable */
TEST(bio_head_content_length_header) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "HEAD", "/h", 0, NULL, &ok, &err);
    CHECK(ok);
    DWORD cl = 0, l = sizeof cl;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL));
    EXPECT_EQ(cl, 1234);
    CHECK(srv_wait_requests(e.s, 1, 2000));
    EXPECT_STR(srv_req_method(e.s, 0), "HEAD");
    bio_h(hr); bio_close(&e);
}

/* 100 Continue before the final response: the interim response has no body of its own */
TEST(bio_interim_100_then_body) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/c");
    EXPECT_EQ(bio_status(hr), 200);
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 4); CHECK(!memcmp(b, "body", 4));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ connection persistence */
static int conns_for_two(const srv_step *st, int nst, const char *tag, int expect_conns) {
    bio_env e; if (!bio_open(&e, st, nst)) return -1;
    for (int i = 0; i < 2; i++) {
        HINTERNET hr = bio_get(&e, i ? "/two" : "/one");
        char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
        CHECKF(r.ok && n == 5 && !memcmp(b, "hello", 5), "%s req %d: ok=%d err=%lu n=%u", tag, i, r.ok, r.err, (unsigned)n);
        bio_h(hr);
    }
    CHECK(srv_wait_requests(e.s, 2, 2000));
    int c = srv_conn_count(e.s);
    t_note("%s: %d connection(s) for 2 sequential requests", tag, c);
    if (expect_conns) CHECKF(c == expect_conns, "%s conns=%d want %d", tag, c, expect_conns);
    bio_close(&e);
    return c;
}
TEST(bio_conn_http11_keepalive_reused) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "hello"), S_LOOP() };
    conns_for_two(st, 3, "HTTP/1.1 CL", 1);
}
TEST(bio_conn_chunked_reused) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, NULL, "hello", 2), S_LOOP() };
    conns_for_two(st, 3, "HTTP/1.1 chunked", 1);
}
TEST(bio_conn_close_header_new_connection) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "hello", SRV_R_CONN_CLOSE) };
    conns_for_two(st, 2, "Connection: close", 2);
}
TEST(bio_conn_closedelim_new_connection) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "hello", SRV_R_CLOSE) };
    conns_for_two(st, 2, "close-delimited", 2);
}
/* HTTP/1.0 response with Content-Length and no keep-alive token: server keeps the socket open, the client must not
 * reuse it (it is not persistent by default). */
TEST(bio_conn_http10_not_reused) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "hello", SRV_R_HTTP10), S_LOOP() };
    conns_for_two(st, 3, "HTTP/1.0 CL, no keep-alive", 0);
}
TEST(bio_conn_http10_keepalive_token) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "hello", SRV_R_HTTP10 | SRV_R_KEEPALIVE), S_LOOP() };
    conns_for_two(st, 3, "HTTP/1.0 + Connection: Keep-Alive", 0);
}

/* Request with Connection: close from the client side */
TEST(bio_conn_client_connection_close_header) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "hello"), S_CLOSE_IF_ASKED(), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/cc", 0, "Connection: close\r\n", &ok, &err);
    CHECK(ok);
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5);
    bio_h(hr);
    CHECK(srv_wait_requests(e.s, 1, 2000));
    t_note("client Connection header sent: %s", srv_req_header(e.s, 0, "Connection") ? srv_req_header(e.s, 0, "Connection") : "(none)");
    hr = bio_get(&e, "/after");
    n = bio_read(hr, b, sizeof b, 0, &r); CHECK(r.ok); EXPECT_EQ(n, 5);
    bio_h(hr);
    EXPECT_EQ(srv_conn_count(e.s), 2);
    bio_close(&e);
}

/* Keep-alive draining: the first response is only partly read before its handle is closed. */
static void drain_case(size_t first, size_t readn, const char *tag) {
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, first, 0), S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/first");
    unsigned char *b = malloc(first + 16); DWORD rd = 0;
    if (readn) { CHECK(U(InternetReadFile)(hr, b, (DWORD)readn, &rd)); CHECK(rd <= readn); }
    bio_h(hr);
    hr = bio_get(&e, "/second");
    char sb[32]; bio_rd r; size_t n = 0;
    if (hr) n = bio_read(hr, sb, sizeof sb, 0, &r);
    CHECKF(hr && r.ok && n == 6 && !memcmp(sb, "second", 6), "%s: ok=%d err=%lu n=%u", tag, r.ok, r.err, (unsigned)n);
    CHECK(srv_wait_requests(e.s, 2, 2000));
    t_note("%s: second request on conn %d (connections %d)", tag, srv_req_conn(e.s, 1), srv_conn_count(e.s));
    free(b); bio_h(hr); bio_close(&e);
}
/* drain cases need the second request to land on any connection: when the first is dropped, connection 1 runs the
 * script from step 0 again (S_HEAD + pattern), so give each connection a script that answers "second" for /second */
static int answer_by_target(srv_conn *c, const srv_step *st, void *user) {
    int i = srv_conn_recv_head(c); if (i < 0) return -1;
    srv *s = srv_conn_server(c);
    const char *t = srv_req_target(s, i);
    size_t n = (size_t)(ULONG_PTR)user;
    if (t && !strcmp(t, "/second")) return srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond") ? -1 : 0;
    if (srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: %u\r\n\r\n", (unsigned)n)) return -1;
    static unsigned char buf[8192];
    for (size_t off = 0; off < n; ) {
        size_t k = n - off < sizeof buf ? n - off : sizeof buf;
        for (size_t j = 0; j < k; j++) buf[j] = srv_pattern_byte(off + j);
        if (srv_conn_send(c, buf, k)) return -1;
        off += k;
    }
    return 0;
}
static void drain_case2(size_t first, size_t readn, const char *tag) {
    static const srv_step st[] = { S_CALL(answer_by_target), S_LOOP() };
    static srv_script ring[16]; static LONG k;
    srv_script *sc = &ring[InterlockedIncrement(&k) & 15]; sc->steps = st; sc->nsteps = 2;
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1;
    cfg.user = (void *)(ULONG_PTR)first; cfg.lifetime_ms = 30000;
    bio_env e; if (!bio_open_cfg(&e, &cfg)) return;
    HINTERNET hr = bio_get(&e, "/first");
    unsigned char *b = malloc(first + 16); DWORD rd = 0;
    if (readn) { CHECK(U(InternetReadFile)(hr, b, (DWORD)readn, &rd)); CHECK(rd <= readn); }
    bio_h(hr);
    hr = bio_get(&e, "/second");
    char sb[32]; bio_rd r; memset(&r, 0, sizeof r); size_t n = 0;
    if (hr) n = bio_read(hr, sb, sizeof sb, 0, &r);
    CHECKF(hr && r.ok && n == 6 && !memcmp(sb, "second", 6), "%s: ok=%d err=%lu n=%u", tag, r.ok, r.err, (unsigned)n);
    CHECK(srv_wait_requests(e.s, 2, 2000));
    t_note("%s: second request on conn %d (connections %d)", tag, srv_req_conn(e.s, 1), srv_conn_count(e.s));
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_drain_unread_small) { REQUIRE(U(InternetReadFile)); drain_case2(100, 0, "100-byte body unread"); }
TEST(bio_drain_partial_small) { REQUIRE(U(InternetReadFile)); drain_case2(100, 10, "100-byte body, 10 read"); }
TEST(bio_drain_unread_large) { REQUIRE(U(InternetReadFile)); drain_case2(500000, 0, "500000-byte body unread"); }
TEST(bio_drain_partial_large) { REQUIRE(U(InternetReadFile)); drain_case2(500000, 1000, "500000-byte body, 1000 read"); }
TEST(bio_drain_fully_read_reuses) {
    REQUIRE(U(InternetReadFile));
    drain_case(100, 100, "100-byte body fully read");
}

/* ------------------------------------------------------------------ HttpSendRequest again on the same handle */
TEST(bio_resend_same_handle_after_full_read) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_FMT("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"), S_SEND("r"), S_FMT("%R"), S_LOOP() };
    /* body = "r" + 3-char target "/rs" */
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/rs");
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 4); CHECK(!memcmp(b, "r/rs", 4));
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    CHECKF(ok, "resend err=%lu", GetLastError());
    n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 4); CHECK(!memcmp(b, "r/rs", 4));
    CHECK(srv_wait_requests(e.s, 2, 2000));
    EXPECT_STR(srv_req_line(e.s, 1), "GET /rs HTTP/1.1");
    t_note("resend: connections %d", srv_conn_count(e.s));
    bio_h(hr); bio_close(&e);
}

TEST(bio_resend_same_handle_without_reading) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 3000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/nr");
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD err = GetLastError();
    t_note("resend before reading the body: ok=%d err=%lu %s", ok, err, ok ? "" : t_inet_errname(err));
    if (ok) {
        unsigned char b[3100]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
        CHECK(r.ok); EXPECT_EQ(n, 3000); CHECK(srv_pattern_check(b, n, 0));
    }
    bio_h(hr); bio_close(&e);
}

TEST(bio_resend_after_partial_read) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 3000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/pr");
    unsigned char b[3100]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 10, &rd)); EXPECT_EQ(rd, 10);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD err = GetLastError();
    t_note("resend after partial read: ok=%d err=%lu %s", ok, err, ok ? "" : t_inet_errname(err));
    if (ok) {
        bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
        CHECK(r.ok); EXPECT_EQ(n, 3000); CHECK(srv_pattern_check(b, n, 0));   /* fresh body from offset 0 */
    }
    bio_h(hr); bio_close(&e);
}

/* Different body sizes per request on the same keep-alive connection. */
static int sized_by_target(srv_conn *c, const srv_step *st, void *user) {
    int i = srv_conn_recv_head(c); if (i < 0) return -1;
    const char *t = srv_req_target(srv_conn_server(c), i);
    unsigned n = t ? (unsigned)strtoul(t + 1, NULL, 10) : 0;
    if (srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: %u\r\n\r\n", n)) return -1;
    static unsigned char buf[70000];
    for (unsigned j = 0; j < n && j < sizeof buf; j++) buf[j] = srv_pattern_byte(j);
    return n && srv_conn_send(c, buf, n) ? -1 : 0;
}
TEST(bio_keepalive_size_sequence) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_CALL(sized_by_target), S_LOOP() };
    static srv_script sc[] = { { st, 2 } };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1; cfg.lifetime_ms = 30000;
    bio_env e; if (!bio_open_cfg(&e, &cfg)) return;
    static const unsigned sizes[] = { 0, 1, 4095, 4096, 4097, 0, 8192, 65535, 65536, 65537, 3, 0 };
    unsigned char *b = malloc(70016);
    for (size_t k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        char path[32]; snprintf(path, sizeof path, "/%u", sizes[k]);
        HINTERNET hr = bio_get(&e, path);
        bio_rd r; size_t n = bio_read(hr, b, 70016, 3000, &r);
        CHECKF(r.ok && n == sizes[k] && srv_pattern_check(b, n, 0), "size %u: ok=%d err=%lu n=%u", sizes[k], r.ok, r.err, (unsigned)n);
        bio_h(hr);
    }
    CHECK(srv_wait_requests(e.s, 12, 2000));
    EXPECT_EQ(srv_conn_count(e.s), 1);
    free(b); bio_close(&e);
}
