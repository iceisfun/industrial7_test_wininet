/* hep_conn.c - connection-level robustness: trailing garbage and extra responses on keep-alive connections,
 * Connection: close honoured on a keep-alive request, stale pooled connections (server closed or reset), early close
 * and reset at every stage of the response, response sent before the request body finished, Expect: 100-continue
 * with slow, missing and refusing servers, HEAD/304 replies carrying body bytes.
 * Expectations: Win10 VM observations (EVIDENCE.md). */
#include "hep.h"
#include <stdlib.h>

/* two scripts: connection 0 runs a, every later connection runs b */
static hep_srv *start2(const srv_step *a, int na, const srv_step *b, int nb) {
    hep_srv *h = (hep_srv *)calloc(1, sizeof *h);
    srv_script *sc = (srv_script *)calloc(2, sizeof *sc);
    sc[0].steps = a; sc[0].nsteps = na; sc[1].steps = b; sc[1].nsteps = nb;
    h->blob = sc;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 2; cfg.lifetime_ms = 30000;
    if (srv_start(&cfg, &h->s) != SRV_OK) { t_skip("server unavailable"); free(sc); free(h); return NULL; }
    return h;
}

/* GET twice on one connect handle; returns both results */
static void two_gets(hep_srv *h, hep_res *r1, hep_res *r2, const char *verb1) {
    HINTERNET hi = hep_session("hep-ka", 3000), hc = hep_connect(hi, h);
    hep_req rq = {0}; rq.verb = verb1; rq.obj = "/one";
    hep_do_on(hc, &rq, r1);
    hep_req rq2 = {0}; rq2.obj = "/two";
    hep_do_on(hc, &rq2, r2);
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}

/* ------------------------------------------------------------ keep-alive framing errors */
GTEST(hep_ka_trailing_garbage_after_body, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiGARBAGE-AFTER-BODY"),
                                  S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("garbage first", hep_sig(&r1, 0), "ok=1 st=200 n=2 body=hi");
    EXPECT_SIG("garbage second", hep_sig(&r2, 0), NULL);
    srv_wait_requests(h->s, 2, 2000);
    t_note("OBS garbage: conns=%d reqs=%d", srv_conn_count(h->s), srv_req_count(h->s));
    hep_stop(h);
}
GTEST(hep_ka_extra_full_response_in_same_write, 30000) {
    /* response splitting on the wire: a second complete response arrives with the first one */
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
                                                   "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Smuggled: 1\r\n\r\nstale"),
                                  S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("split first", hep_sig(&r1, 0), "ok=1 st=200 n=2 body=hi");
    EXPECT_SIG("split second", hep_sig(&r2, 0), NULL);
    srv_wait_requests(h->s, 2, 2000);
    t_note("OBS split: conns=%d reqs=%d", srv_conn_count(h->s), srv_req_count(h->s));
    hep_stop(h);
}
GTEST(hep_ka_cl_shorter_than_body, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"),
                                  S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("short cl first", hep_sig(&r1, 0), "ok=1 st=200 n=3 body=abc");
    EXPECT_SIG("short cl second", hep_sig(&r2, 0), NULL);
    t_note("OBS short cl: conns=%d", srv_conn_count(h->s));
    hep_stop(h);
}
GTEST(hep_ka_chunked_then_garbage, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\nJUNK"),
                                  S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("chunked garbage first", hep_sig(&r1, 0), "ok=1 st=200 n=2 body=hi");
    EXPECT_SIG("chunked garbage second", hep_sig(&r2, 0), NULL);
    t_note("OBS chunked garbage: conns=%d", srv_conn_count(h->s));
    hep_stop(h);
}
GTEST(hep_ka_head_reply_with_body_bytes, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"),
                                  S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, "HEAD");
    EXPECT_SIG("head body first", hep_sig(&r1, 0), "ok=1 st=200 n=0 body=");
    EXPECT_SIG("head body second", hep_sig(&r2, 0), NULL);
    t_note("OBS head body: conns=%d", srv_conn_count(h->s));
    hep_stop(h);
}
GTEST(hep_ka_304_reply_with_body_bytes, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 304 Not Modified\r\nContent-Length: 4\r\n\r\nbody"),
                                  S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("304 body first", hep_sig(&r1, 0), NULL);
    EXPECT_SIG("304 body second", hep_sig(&r2, 0), NULL);
    t_note("OBS 304 body: conns=%d", srv_conn_count(h->s));
    hep_stop(h);
}
GTEST(hep_ka_204_reply_with_body_bytes, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 204 No Content\r\n\r\nbody"),
                                  S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("204 body first", hep_sig(&r1, 0), NULL);
    EXPECT_SIG("204 body second", hep_sig(&r2, 0), NULL);
    t_note("OBS 204 body: conns=%d", srv_conn_count(h->s));
    hep_stop(h);
}

/* ------------------------------------------------------------ Connection: close vs keep-alive */
GTEST(hep_ka_connection_close_honoured_even_if_socket_stays, 30000) {
    /* the server says Connection: close but keeps the socket open: the client must not reuse it */
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi"),
                                  S_HEAD(), S_REPLY(200, NULL, "reused"), S_LOOP_TO(2) };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
    hep_srv *h = start2(a, 5, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("conn close first", hep_sig(&r1, 0), "ok=1 st=200 n=2 body=hi");
    EXPECT_SIG("conn close second", hep_sig(&r2, 0), "ok=1 st=200 n=5 body=fresh");
    CHECK(srv_wait_requests(h->s, 2, 2000));
    EXPECT_EQ(srv_conn_count(h->s), 2);
    hep_stop(h);
}
static const char *const conn_tokens[] = { "close", "Close", "CLOSE", "keep-alive, close", "close, keep-alive", "Upgrade, close",
                                           " close ", "closed", "clos", "TE, close" };
GTEST(hep_ka_connection_token_table, 150000) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof conn_tokens / sizeof conn_tokens[0]; i++) {
        char *resp = (char *)malloc(256);
        snprintf(resp, 256, "HTTP/1.1 200 OK\r\nConnection: %s\r\nContent-Length: 2\r\n\r\nhi", conn_tokens[i]);
        srv_step *a = (srv_step *)calloc(5, sizeof *a);
        a[0].op = SRV_RECV_HEAD; a[1].op = SRV_SEND; a[1].data = resp; a[2].op = SRV_RECV_HEAD;
        a[3].op = SRV_REPLY; a[3].arg = 200; a[3].data = "reused"; a[4].op = SRV_LOOP; a[4].arg = 2;
        static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
        hep_srv *h = start2(a, 5, b, 3); if (!h) { free(a); free(resp); return; }
        hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
        srv_wait_requests(h->s, 2, 2000);
        t_note("OBS Connection: [%s] -> second=%s conns=%d", conn_tokens[i], hep_sig(&r2, 0), srv_conn_count(h->s));
        CHECK(r1.ok && r2.ok);
        hep_stop(h); free(a); free(resp);
    }
}
GTEST(hep_ka_http10_reply_keepalive_token_case, 30000) {
    HEP_REQUIRE_HTTP();
    static const char *tok[] = { "Keep-Alive", "keep-alive", "KEEP-ALIVE", "keepalive" };
    for (size_t i = 0; i < 4; i++) {
        char *resp = (char *)malloc(256);
        snprintf(resp, 256, "HTTP/1.0 200 OK\r\nConnection: %s\r\nContent-Length: 2\r\n\r\nhi", tok[i]);
        srv_step *a = (srv_step *)calloc(5, sizeof *a);
        a[0].op = SRV_RECV_HEAD; a[1].op = SRV_SEND; a[1].data = resp; a[2].op = SRV_RECV_HEAD;
        a[3].op = SRV_REPLY; a[3].arg = 200; a[3].data = "reused"; a[4].op = SRV_LOOP; a[4].arg = 2;
        static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP() };
        hep_srv *h = start2(a, 5, b, 3); if (!h) { free(a); free(resp); return; }
        hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
        srv_wait_requests(h->s, 2, 2000);
        t_note("OBS HTTP/1.0 Connection: [%s] -> second=%s conns=%d", tok[i], hep_sig(&r2, 0), srv_conn_count(h->s));
        CHECK(r1.ok && r2.ok);
        hep_stop(h); free(a); free(resp);
    }
}

/* ------------------------------------------------------------ stale pooled connections */
GTEST(hep_stale_server_closed_after_reply, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_REPLY(200, NULL, "one"), S_SLEEP(100), S_CLOSE() };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "two"), S_LOOP() };
    hep_srv *h = start2(a, 4, b, 3); if (!h) return;
    HINTERNET hi = hep_session("hep-stale", 3000), hc = hep_connect(hi, h);
    hep_req rq = {0}; hep_res r1, r2;
    hep_do_on(hc, &rq, &r1);
    srv_wait_events(h->s, SRV_EV_SCRIPT_DONE, 1, 2000);
    Sleep(200);
    hep_do_on(hc, &rq, &r2);
    EXPECT_SIG("stale close 1", hep_sig(&r1, 0), "ok=1 st=200 n=3 body=one");
    EXPECT_SIG("stale close 2", hep_sig(&r2, 0), "ok=1 st=200 n=3 body=two");
    EXPECT_EQ(srv_conn_count(h->s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_stale_server_reset_after_reply, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_REPLY(200, NULL, "one"), S_SLEEP(100), S_RESET() };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "two"), S_LOOP() };
    hep_srv *h = start2(a, 4, b, 3); if (!h) return;
    HINTERNET hi = hep_session("hep-stale", 3000), hc = hep_connect(hi, h);
    hep_req rq = {0}; hep_res r1, r2;
    hep_do_on(hc, &rq, &r1);
    srv_wait_events(h->s, SRV_EV_SCRIPT_DONE, 1, 2000);
    Sleep(200);
    hep_do_on(hc, &rq, &r2);
    EXPECT_SIG("stale reset 1", hep_sig(&r1, 0), "ok=1 st=200 n=3 body=one");
    EXPECT_SIG("stale reset 2", hep_sig(&r2, 0), "ok=1 st=200 n=3 body=two");
    EXPECT_EQ(srv_conn_count(h->s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_stale_close_after_reading_second_head, 30000) {
    /* the race the client cannot see coming: the pooled socket accepts the request, then closes without a reply */
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_REPLY(200, NULL, "one"), S_HEAD(), S_CLOSE() };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "two"), S_LOOP() };
    hep_srv *h = start2(a, 4, b, 3); if (!h) return;
    HINTERNET hi = hep_session("hep-stale", 3000), hc = hep_connect(hi, h);
    hep_req rq = {0}; hep_res r1, r2;
    hep_do_on(hc, &rq, &r1);
    hep_do_on(hc, &rq, &r2);
    EXPECT_SIG("stale race 1", hep_sig(&r1, 0), "ok=1 st=200 n=3 body=one");
    EXPECT_SIG("stale race 2", hep_sig(&r2, 0), NULL);
    srv_wait_requests(h->s, 2, 2000);
    t_note("OBS stale race GET: conns=%d reqs=%d", srv_conn_count(h->s), srv_req_count(h->s));
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_stale_reset_after_reading_second_head, 30000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_REPLY(200, NULL, "one"), S_HEAD(), S_RESET() };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "two"), S_LOOP() };
    hep_srv *h = start2(a, 4, b, 3); if (!h) return;
    HINTERNET hi = hep_session("hep-stale", 3000), hc = hep_connect(hi, h);
    hep_req rq = {0}; hep_res r1, r2;
    hep_do_on(hc, &rq, &r1);
    hep_do_on(hc, &rq, &r2);
    EXPECT_SIG("stale rst race 1", hep_sig(&r1, 0), "ok=1 st=200 n=3 body=one");
    EXPECT_SIG("stale rst race 2", hep_sig(&r2, 0), NULL);
    srv_wait_requests(h->s, 2, 2000);
    t_note("OBS stale rst race GET: conns=%d reqs=%d", srv_conn_count(h->s), srv_req_count(h->s));
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_stale_close_after_reading_second_head_post, 30000) {
    /* same race with a POST (not idempotent) */
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "one"), S_HEAD(), S_BODY(), S_CLOSE() };
    static const srv_step b[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "two"), S_LOOP() };
    hep_srv *h = start2(a, 6, b, 4); if (!h) return;
    HINTERNET hi = hep_session("hep-stale", 3000), hc = hep_connect(hi, h);
    hep_req rq = {0}; rq.verb = "POST"; rq.opt = "data"; rq.optlen = 4; hep_res r1, r2;
    hep_do_on(hc, &rq, &r1);
    hep_do_on(hc, &rq, &r2);
    EXPECT_SIG("stale race post 1", hep_sig(&r1, 0), "ok=1 st=200 n=3 body=one");
    EXPECT_SIG("stale race post 2", hep_sig(&r2, 0), NULL);
    srv_wait_requests(h->s, 2, 2000);
    t_note("OBS stale race POST: conns=%d reqs=%d", srv_conn_count(h->s), srv_req_count(h->s));
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ early close / reset at every stage (fresh connection) */
static void early(const char *tag, const char *raw, int mode, const char *want) {
    hep_rcase(tag, raw, strlen(raw), mode, NULL, 0, want);
}
GTEST(hep_early_close_before_any_byte, 60000)      { HEP_REQUIRE_HTTP(); early("close_0", "", 0, NULL); }
GTEST(hep_early_reset_before_any_byte, 60000)      { HEP_REQUIRE_HTTP(); early("rst_0", "", 2, NULL); }
GTEST(hep_early_reset_mid_status, 60000)           { HEP_REQUIRE_HTTP(); early("rst_status", "HTTP/1.1 20", 2, NULL); }
GTEST(hep_early_reset_after_status, 60000)         { HEP_REQUIRE_HTTP(); early("rst_after_status", "HTTP/1.1 200 OK\r\n", 2, NULL); }
GTEST(hep_early_reset_mid_headers, 60000)          { HEP_REQUIRE_HTTP(); early("rst_mid_hdr", "HTTP/1.1 200 OK\r\nContent-Le", 2, NULL); }
GTEST(hep_early_reset_after_headers, 60000)        { HEP_REQUIRE_HTTP(); early("rst_after_hdr", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", 2, NULL); }
GTEST(hep_early_reset_mid_body, 60000)             { HEP_REQUIRE_HTTP(); early("rst_mid_body", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab", 2, NULL); }
GTEST(hep_early_reset_mid_chunked, 60000)          { HEP_REQUIRE_HTTP(); early("rst_mid_chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab", 2, NULL); }
GTEST(hep_early_reset_close_delimited, 60000)      { HEP_REQUIRE_HTTP(); early("rst_closedelim", "HTTP/1.1 200 OK\r\n\r\nabcd", 2, NULL); }
GTEST(hep_early_shutwr_mid_body, 60000)            { HEP_REQUIRE_HTTP(); early("shut_mid_body", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab", 1, NULL); }
GTEST(hep_early_shutwr_mid_chunked, 60000)         { HEP_REQUIRE_HTTP(); early("shut_mid_chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab", 1, NULL); }
GTEST(hep_early_shutwr_after_headers_cl, 60000)    { HEP_REQUIRE_HTTP(); early("shut_after_hdr", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n", 1, NULL); }
GTEST(hep_early_close_mid_chunk_size, 60000)       { HEP_REQUIRE_HTTP(); early("close_chunk_size", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4", 0, NULL); }
GTEST(hep_early_close_before_last_chunk, 60000)    { HEP_REQUIRE_HTTP(); early("close_no_last", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n", 0, NULL); }

/* ------------------------------------------------------------ response before the request body was read */
static void early_reply_post(const char *tag, size_t bodylen, int drain, const char *reply, const char *want) {
    srv_step st[5]; memset(st, 0, sizeof st); int k = 0;
    st[k++].op = SRV_RECV_HEAD;
    st[k].op = SRV_SEND; st[k].data = reply; k++;
    if (drain) st[k++].op = SRV_RECV_BODY;
    else { st[k].op = SRV_SLEEP; st[k].arg = 300; k++; }
    st[k++].op = SRV_CLOSE;
    HEP_SRV(h, hep_start(st, k));
    char *body = (char *)malloc(bodylen); memset(body, 'p', bodylen);
    hep_req rq = {0}; hep_res r; rq.verb = "POST"; rq.opt = body; rq.optlen = (DWORD)bodylen; rq.timeout_ms = 3000;
    hep_do(h, &rq, &r);
    EXPECT_SIG(tag, hep_sig(&r, 0), want);
    t_note("%s: %lu ms, server events %d", tag, r.ms, srv_count_events(h->s, SRV_EV_ANY));
    free(body); hep_stop(h);
}
#define R413 "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 3\r\n\r\nbig"
#define R200 "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nearly"
GTEST(hep_early_reply_small_post_drained, 20000)    { HEP_REQUIRE_HTTP(); early_reply_post("early_small_drain", 100, 1, R200, "ok=1 st=200 n=5 body=early"); }
GTEST(hep_early_reply_small_post_not_read, 20000)   { HEP_REQUIRE_HTTP(); early_reply_post("early_small_noread", 100, 0, R413, NULL); }
GTEST(hep_early_reply_large_post_drained, 20000)    { HEP_REQUIRE_HTTP(); early_reply_post("early_large_drain", 4u << 20, 1, R200, NULL); }
GTEST(hep_early_reply_large_post_not_read, 20000)   { HEP_REQUIRE_HTTP(); early_reply_post("early_large_noread", 4u << 20, 0, R413, NULL); }

/* ------------------------------------------------------------ Expect: 100-continue */
static void expect_case(const char *tag, const srv_step *st, int n, const char *want, const char *want_body) {
    HEP_SRV(h, hep_start(st, n));
    hep_req rq = {0}; hep_res r; rq.verb = "POST"; rq.opt = "payload!"; rq.optlen = 8; rq.timeout_ms = 3000;
    rq.hdrs = "Expect: 100-continue\r\n";
    hep_do(h, &rq, &r);
    EXPECT_SIG(tag, hep_sig(&r, 0), want);
    if (srv_wait_requests(h->s, 1, 1000)) {
        size_t bn = 0; const char *b = srv_req_body(h->s, 0, &bn);
        t_note("OBS %s: Expect header on wire=%s body seen=%s (%lu ms)", tag, srv_req_header(h->s, 0, "Expect"), b ? hep_esc(b, bn) : "(not read)", r.ms);
        if (want_body) { CHECK(b != NULL); if (b) EXPECT_STR(hep_esc(b, bn), want_body); }
    }
    hep_stop(h);
}
GTEST(hep_expect_100_then_200, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_100(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE() };
    expect_case("expect_100_200", st, 5, "ok=1 st=200 n=2 body=ok", "payload!");
}
GTEST(hep_expect_slow_100, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_SLEEP(1500), S_100(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE() };
    expect_case("expect_slow_100", st, 6, "ok=1 st=200 n=2 body=ok", "payload!");
}
GTEST(hep_expect_no_100_server_waits_body, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE() };
    expect_case("expect_no_100", st, 4, "ok=1 st=200 n=2 body=ok", "payload!");
}
GTEST(hep_expect_417_without_reading_body, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 417 Expectation Failed\r\nContent-Length: 2\r\n\r\nno"), S_SLEEP(300), S_CLOSE() };
    expect_case("expect_417", st, 4, NULL, NULL);
}
GTEST(hep_expect_final_200_without_100, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nskip"), S_BODY(), S_CLOSE() };
    expect_case("expect_final_200", st, 4, NULL, NULL);
}
GTEST(hep_unsolicited_100_without_expect, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_BODY(), { SRV_REPLY_100, NULL, 0, 1 }, S_REPLY(200, NULL, "ok"), S_CLOSE() };
    HEP_SRV(h, hep_start(st, 5));
    hep_req rq = {0}; hep_res r; rq.verb = "POST"; rq.opt = "x"; rq.optlen = 1;
    hep_do(h, &rq, &r);
    EXPECT_SIG("unsolicited 100", hep_sig(&r, 3), "ok=1 st=200 ver=HTTP/1.1 txt=OK n=2 body=ok");
    hep_stop(h);
}
GTEST(hep_expect_100_headers_not_merged, 20000) {
    /* headers sent on the interim 100 response are not part of the final response */
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 100 Continue\r\nX-Interim: yes\r\n\r\n"), S_BODY(),
                                   S_REPLY(200, "X-Final: yes\r\n", "ok"), S_CLOSE() };
    HEP_SRV(h, hep_start(st, 5));
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/e", NULL, NULL, NULL, HEP_F, 0);
    CHECK(U(HttpSendRequestA)(hr, "Expect: 100-continue\r\n", (DWORD)-1, "abc", 3));
    char b[64]; DWORD l = sizeof b; strcpy(b, "X-Final");
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, NULL));
    l = sizeof b; strcpy(b, "X-Interim");
    BOOL q = U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, NULL);
    t_note("OBS interim header visible=%d (%s)", q, q ? b : t_inet_errname(GetLastError()));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
GTEST(hep_interim_103_link_headers_not_merged, 20000) {
    HEP_REQUIRE_HTTP();
    static const char raw[] = "HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 200 OK\r\nX-Final: y\r\nContent-Length: 2\r\n\r\nhi";
    HEP_SRV(h, hep_start_raw(raw, sizeof raw - 1, 0));
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/e", NULL, NULL, NULL, HEP_F, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    t_note("OBS 103 send ok=%d err=%lu", ok, ok ? 0 : GetLastError());
    if (ok) {
        char b[256]; DWORD l = sizeof b;
        if (U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF, b, &l, NULL)) t_note("OBS 103 raw: %s", hep_esc(b, l));
        l = sizeof b; strcpy(b, "Link");
        BOOL q = U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, b, &l, NULL);
        t_note("OBS 103 Link visible=%d", q);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ close-delimited and keep-alive */
GTEST(hep_ka_close_delimited_http11_new_connection, 20000) {
    HEP_REQUIRE_HTTP();
    static const srv_step a[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\nuntil-close"), S_CLOSE() };
    static const srv_step b[] = { S_HEAD(), S_REPLY(200, NULL, "two"), S_LOOP() };
    hep_srv *h = start2(a, 3, b, 3); if (!h) return;
    hep_res r1, r2; two_gets(h, &r1, &r2, NULL);
    EXPECT_SIG("closedelim 1", hep_sig(&r1, 0), "ok=1 st=200 n=11 body=until-close");
    EXPECT_SIG("closedelim 2", hep_sig(&r2, 0), "ok=1 st=200 n=3 body=two");
    EXPECT_EQ(srv_conn_count(h->s), 2);
    hep_stop(h);
}
GTEST(hep_ka_many_requests_one_socket, 30000) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    int okc = 0;
    for (int i = 0; i < 50; i++) { hep_req rq = {0}; hep_res r; hep_do_on(hc, &rq, &r); okc += r.ok && r.status == 200 && r.nbody == 2; }
    EXPECT_EQ(okc, 50);
    EXPECT_EQ(srv_conn_count(h->s), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
