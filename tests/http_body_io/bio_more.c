/* bio_more.c - bodies of POST/PUT responses, HTTP/1.0 requests (HttpOpenRequest version "HTTP/1.0"),
 * InternetOpenUrl with decoding, redirects with bodies, response bodies of every byte position at chunk and
 * segment boundaries delivered by a slow server.
 * VM_TIMEOUT: 300 */
#include "bio.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ POST / PUT response bodies */
static void post_case(const char *verb, size_t reqn, size_t respn) {
    srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, NULL, respn, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, verb, "/up", NULL, NULL, NULL, T_INET_FRESH, 0);
    unsigned char *req = bio_pattern(reqn);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, req, (DWORD)reqn);
    CHECKF(ok, "%s send err=%lu", verb, GetLastError());
    unsigned char *b = malloc(respn + 16); bio_rd r; size_t n = bio_read(hr, b, respn + 16, 4096, &r);
    CHECK(r.ok); EXPECT_EQ(n, respn); CHECK(srv_pattern_check(b, n < respn ? n : respn, 0));
    CHECK(srv_wait_events(e.s, SRV_EV_BODY, 1, 2000));
    size_t bl = 0; const char *body = srv_req_body(e.s, 0, &bl);
    CHECK(body && bl == reqn && srv_pattern_check(body, bl, 0));
    free(req); free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_post_small_response) { REQUIRE(U(HttpSendRequestA)); post_case("POST", 10, 10); }
TEST(bio_post_large_response) { REQUIRE(U(HttpSendRequestA)); post_case("POST", 100, 200000); }
TEST(bio_post_large_both) { REQUIRE(U(HttpSendRequestA)); post_case("POST", 100000, 100000); }
TEST(bio_put_response) { REQUIRE(U(HttpSendRequestA)); post_case("PUT", 4097, 4097); }
TEST(bio_post_empty_response) { REQUIRE(U(HttpSendRequestA)); post_case("POST", 5, 0); }

/* ------------------------------------------------------------------ HttpOpenRequest("HTTP/1.0") and HTTP/1.0 replies */
static void http10_req_case(unsigned flags, size_t n) {
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, n, flags), S_CLOSE_IF_ASKED(), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/v10", "HTTP/1.0", NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    unsigned char *b = malloc(n + 16); bio_rd r; size_t got = bio_read(hr, b, n + 16, 1000, &r);
    CHECK(r.ok); EXPECT_EQ(got, n); CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    CHECK(srv_wait_requests(e.s, 1, 2000));
    /* Win10 VM (boot wininet-bio-20261109-172245): the lpszVersion "HTTP/1.0" of HttpOpenRequestA does not change the
     * request line; the session's HTTP version (INTERNET_OPTION_HTTP_VERSION, default 1.1) is what goes on the wire */
    EXPECT_STR(srv_req_line(e.s, 0), "GET /v10 HTTP/1.1");
    const char *c = srv_req_header(e.s, 0, "Connection");
    t_note("HTTP/1.0 request Connection header: %s", c ? c : "(none)");
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_http10_request_cl) { REQUIRE(U(HttpSendRequestA)); http10_req_case(SRV_R_HTTP10, 5000); }
TEST(bio_http10_request_closedelim) { REQUIRE(U(HttpSendRequestA)); http10_req_case(SRV_R_HTTP10 | SRV_R_CLOSE, 5000); }
TEST(bio_http10_request_http11_reply) { REQUIRE(U(HttpSendRequestA)); http10_req_case(0, 3000); }

/* ------------------------------------------------------------------ InternetOpenUrl + decoding */
TEST(bio_openurl_decoding_session) {
    REQUIRE(U(InternetOpenUrlA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_HTTP_DECODING, TRUE));
    HINTERNET hu = U(InternetOpenUrlA)(e.hi, srv_url(e.s, "/gz"), "Accept-Encoding: gzip\r\n", (DWORD)-1, T_INET_FRESH, 0);
    CHECK(hu != NULL);
    char *b = malloc(2048); bio_rd r; size_t n = bio_read(hu, b, 2048, 100, &r);
    CHECK(r.ok); EXPECT_EQ(n, SRV_FOX_LEN); CHECK(n == SRV_FOX_LEN && !memcmp(b, srv_fox_text(), n));
    free(b); bio_h(hu); bio_close(&e);
}

/* ------------------------------------------------------------------ redirect bodies */
/* the body of the 302 is drained, the handle delivers only the final body */
TEST(bio_redirect_body_not_delivered) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", "redirect-body-should-not-appear"),
                                   S_HEAD(), S_REPLY(200, NULL, "final"), S_LOOP_TO(2) };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/src", 0, NULL, &ok, &err);
    CHECK(ok); EXPECT_EQ(bio_status(hr), 200);
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "final", 5));
    CHECK(srv_wait_requests(e.s, 2, 2000));
    EXPECT_EQ(srv_conn_count(e.s), 1);           /* the 302 body was drained, the connection reused */
    bio_h(hr); bio_close(&e);
}

TEST(bio_redirect_chunked_body_drained) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(301, "Location: /dst\r\n", "moved-moved-moved", 4),
                                   S_HEAD(), S_REPLY(200, NULL, "final"), S_LOOP_TO(2) };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/src");
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "final", 5));
    bio_h(hr); bio_close(&e);
}

/* NO_AUTO_REDIRECT: the 3xx body itself is readable */
TEST(bio_redirect_no_auto_body_readable) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", "redirect-body"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/src", INTERNET_FLAG_NO_AUTO_REDIRECT, NULL, &ok, &err);
    CHECK(ok); EXPECT_EQ(bio_status(hr), 302);
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 13); CHECK(!memcmp(b, "redirect-body", 13));
    bio_h(hr); bio_close(&e);
}

/* 401 without credentials: the error body is readable */
TEST(bio_401_body_readable) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "need-auth"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/auth");
    EXPECT_EQ(bio_status(hr), 401);
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 9); CHECK(!memcmp(b, "need-auth", 9));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ boundary splits from a slow server */
/* The head and body are split at every position 0..len in two TCP sends with a pause between them. */
static int split_at(srv_conn *c, const srv_step *st, void *user) {
    int i = srv_conn_recv_head(c); if (i < 0) return -1;
    const char *t = srv_req_target(srv_conn_server(c), i);
    size_t at = t ? strtoul(t + 1, NULL, 10) : 0;
    const char *resp = user; size_t n = strlen(resp);
    if (at > n) at = n;
    if (at && srv_conn_send(c, resp, at)) return -1;
    Sleep(15);
    if (n > at && srv_conn_send(c, resp + at, n - at)) return -1;
    return 0;
}
static void split_sweep(const char *resp, const char *want, size_t wantn, const char *tag) {
    static const srv_step st[] = { S_CALL(split_at), S_LOOP() };
    static srv_script sc[] = { { st, 2 } };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1;
    cfg.user = (void *)resp; cfg.lifetime_ms = 60000;
    bio_env e; if (!bio_open_cfg(&e, &cfg)) return;
    size_t n = strlen(resp); int bad = 0;
    for (size_t at = 1; at < n; at++) {
        char path[32]; snprintf(path, sizeof path, "/%u", (unsigned)at);
        BOOL ok; DWORD err;
        HINTERNET hr = bio_req(&e, "GET", path, 0, NULL, &ok, &err);
        char b[256]; bio_rd r; memset(&r, 0, sizeof r); size_t got = ok ? bio_read(hr, b, sizeof b, 3, &r) : 0;
        if (!ok || !r.ok || got != wantn || memcmp(b, want, wantn)) {
            bad++; t_note("%s split at %u: ok=%d read ok=%d err=%lu got=%u", tag, (unsigned)at, ok, r.ok, ok ? r.err : err, (unsigned)got);
        }
        bio_h(hr);
    }
    CHECKF(bad == 0, "%s: %d split positions failed", tag, bad);
    t_note("%s: %u split positions, %d connections", tag, (unsigned)(n - 1), srv_conn_count(e.s));
    bio_close(&e);
}
TEST(bio_split_sweep_content_length) {
    REQUIRE(U(InternetReadFile));
    split_sweep("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nhello world!", "hello world!", 12, "CL");
}
TEST(bio_split_sweep_chunked) {
    REQUIRE(U(InternetReadFile));
    split_sweep("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n7\r\n world!\r\n0\r\nT: x\r\n\r\n", "hello world!", 12, "chunked");
}

/* INTERNET_OPTION_HTTP_VERSION (process-wide, restored afterwards) is what selects an HTTP/1.0 request line */
TEST(bio_http_version_option_10) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetQueryOptionA));
    HTTP_VERSION_INFO old = { 0, 0 }, v10 = { 1, 0 }; DWORD l = sizeof old;
    if (!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &old, &l)) { t_skip("query HTTP_VERSION err=%lu", GetLastError()); return; }
    t_note("process HTTP version %lu.%lu", old.dwMajorVersion, old.dwMinorVersion);
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 3000, SRV_R_HTTP10), S_CLOSE_IF_ASKED(), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v10, sizeof v10));
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/opt10", NULL, NULL, NULL, T_INET_FRESH, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &old, sizeof old);
    CHECK(ok);
    unsigned char b[3100]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 1000, &r);
    CHECK(r.ok); EXPECT_EQ(n, 3000); CHECK(srv_pattern_check(b, n, 0));
    CHECK(srv_wait_requests(e.s, 1, 2000));
    const char *line = srv_req_line(e.s, 0);
    t_note("request line with HTTP_VERSION 1.0: %s", line ? line : "(none)");
    const char *c = srv_req_header(e.s, 0, "Connection");
    t_note("HTTP/1.0 request Connection header: %s", c ? c : "(none)");
    bio_h(hr); bio_close(&e);
}
