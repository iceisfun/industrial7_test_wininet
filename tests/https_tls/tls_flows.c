/* tls_flows.c - end-to-end flows over TLS: bodies, keep-alive, client certificates, CONNECT proxy tunnels,
 * http<->https redirects, InternetOpenUrl. Servers: the shared schannel server plus the area's CONNECT proxy. */
#include "tls_util.h"

/* ------------------------------------------------------------------ bodies and framing over TLS */
TEST(tls_flow_large_body_many_records) {
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/big", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    char *buf = malloc(210000); size_t n = 0; DWORD r;
    for (int guard = 0; guard < 10000; guard++) {
        if (!U(InternetReadFile)(t.hr, buf + n, 7777, &r) || r == 0) break;
        n += r;
        if (n > 200000) break;
    }
    EXPECT_EQ(n, 200000);
    CHECK(srv_pattern_check(buf, n, 0));
    free(buf);
    treq_close(&t); srv_stop(s);
}

TEST(tls_flow_chunked_body) {
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, NULL, "chunked over tls: 0123456789", 5), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/c", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    char b[128] = ""; treq_body(&t, b, sizeof b);
    EXPECT_STR(b, "chunked over tls: 0123456789");
    treq_close(&t); srv_stop(s);
}

TEST(tls_flow_close_delimited_body_with_close_notify) {
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "until close", SRV_R_CLOSE) };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 2); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/cd", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    char b[64] = ""; int ok = 0; t_inet_read_all(t.hr, b, sizeof b, &ok);
    EXPECT_STR(b, "until close");
    CHECK(ok);
    treq_close(&t); srv_stop(s);
}

TEST(tls_flow_gzip_body) {
    srv_step keep[] = { S_HEAD(), S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, keep, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/gz", T_INET_FRESH | INTERNET_FLAG_SECURE));
    BOOL dec = TRUE; CHECK(U(InternetSetOptionA)(t.hr, INTERNET_OPTION_HTTP_DECODING, &dec, sizeof dec));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    char b[1024] = ""; size_t n = treq_body(&t, b, sizeof b);
    EXPECT_EQ(n, SRV_FOX_LEN);
    CHECK(!strcmp(b, srv_fox_text()));
    treq_close(&t); srv_stop(s);
}

TEST(tls_flow_post_body_and_wire) {
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(201, NULL, "made"), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 4); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "POST", "/post?x=1", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    static const char hdr[] = "Content-Type: text/plain\r\nX-Tls-Test: 1\r\n";
    SET_ERR(0);
    CHECKF(U(HttpSendRequestA)(t.hr, hdr, (DWORD)-1, "payload-123", 11), "err=%lu", GetLastError());
    EXPECT_EQ(treq_status(&t), 201);
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_STR(srv_req_line(s, 0), "POST /post?x=1 HTTP/1.1");
    EXPECT_STR(srv_req_header(s, 0, "Content-Length"), "11");
    EXPECT_STR(srv_req_header(s, 0, "X-Tls-Test"), "1");
    EXPECT_STR(srv_req_header(s, 0, "User-Agent"), "tls-test");
    char hp[64]; snprintf(hp, sizeof hp, "127.0.0.1:%u", srv_port(s));
    EXPECT_STR(srv_req_header(s, 0, "Host"), hp);
    size_t bl = 0; const char *b = srv_req_body(s, 0, &bl);
    CHECK(b && bl == 11 && !memcmp(b, "payload-123", 11));
    for (int i = 0; i < srv_req_header_count(s, 0); i++) t_note("hdr[%d] %s: %s", i, srv_req_header_name(s, 0, i), srv_req_header_value(s, 0, i));
    treq_close(&t); srv_stop(s);
}

/* the request head over TLS is the same as over plain HTTP: compare with an HTTP server */
TEST(tls_flow_head_same_as_plain_http) {
    srv *s1 = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s1) TLS_SKIP_SRV();
    srv *s2 = srv_http(NULL, 0); if (!s2) { srv_stop(s1); TLS_SKIP_SRV(); }
    treq a, b;
    CHECK(treq_open(&a, "127.0.0.1", srv_port(s1), "GET", "/same", T_INET_FRESH | INTERNET_FLAG_SECURE));
    CHECK(treq_open(&b, "127.0.0.1", srv_port(s2), "GET", "/same", T_INET_FRESH));
    t_https_secflags(a.hr, 0x100);
    EXPECT_EQ(treq_send(&a), 0); EXPECT_EQ(treq_send(&b), 0);
    CHECK(srv_wait_requests(s1, 1, 2000)); CHECK(srv_wait_requests(s2, 1, 2000));
    int n1 = srv_req_header_count(s1, 0), n2 = srv_req_header_count(s2, 0);
    t_note("https headers=%d http headers=%d", n1, n2);
    EXPECT_EQ(n1, n2);
    for (int i = 0; i < n1 && i < n2; i++) {
        EXPECT_STR(srv_req_header_name(s1, 0, i), srv_req_header_name(s2, 0, i));
        if (_stricmp(srv_req_header_name(s1, 0, i), "Host")) EXPECT_STR(srv_req_header_value(s1, 0, i), srv_req_header_value(s2, 0, i));
    }
    treq_close(&a); treq_close(&b); srv_stop(s1); srv_stop(s2);
}

TEST(tls_flow_keepalive_reuse_three_requests) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "ka"), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    for (int i = 0; i < 3; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/k", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE | INTERNET_FLAG_KEEP_CONNECTION, 0);
        t_https_secflags(hr, 0x100);
        CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "i=%d err=%lu", i, GetLastError());
        char b[8]; t_inet_read_all(hr, b, sizeof b, NULL);
        U(InternetCloseHandle)(hr);
    }
    CHECK(srv_wait_requests(s, 3, 2000));
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));
    EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 2));
    EXPECT_EQ(tls_count(s, SRV_EV_TLS_DONE), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* a server that closes after each response: a fresh TLS handshake per request */
TEST(tls_flow_connection_close_new_handshake) {
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "cc", SRV_R_CONN_CLOSE) };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 2); if (!s) TLS_SKIP_SRV();
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    for (int i = 0; i < 2; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/cc", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
        t_https_secflags(hr, 0x100);
        CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "i=%d err=%lu", i, GetLastError());
        char b[8] = ""; t_inet_read_all(hr, b, sizeof b, NULL); EXPECT_STR(b, "cc");
        U(InternetCloseHandle)(hr);
    }
    CHECK(srv_wait_requests(s, 2, 2000));
    CHECK(srv_req_conn(s, 0) != srv_req_conn(s, 1));
    EXPECT_EQ(tls_count(s, SRV_EV_TLS_DONE), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ client certificates */
TEST(tls_clientcert_needed_error) {
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 1, NULL, 0, &rc); if (!s) { t_skip("server: %s", srv_strerror(rc)); return; }
    DWORD st, e = tls_try(s, NULL, SECURITY_FLAG_IGNORE_UNKNOWN_CA, 0, &st);
    EXPECT_EQ(e, ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED);      /* netlb_https_client_cert_requested, Win10 */
    EXPECT_EQ(srv_req_count(s), 0);
    srv_stop(s);
}

TEST(tls_clientcert_needed_even_with_all_ignore_flags) {
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 1, NULL, 0, &rc); if (!s) { t_skip("server: %s", srv_strerror(rc)); return; }
    DWORD st, e = tls_try(s, NULL, SECURITY_SET_MASK, 0, &st);
    EXPECT_EQ(e, ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED);
    srv_stop(s);
}

/* the CA check precedes the client-certificate request */
TEST(tls_clientcert_ca_error_first) {
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 1, NULL, 0, &rc); if (!s) { t_skip("server: %s", srv_strerror(rc)); return; }
    DWORD st, e = tls_try(s, NULL, 0, 0, &st);
    t_note("client cert requested, no ignore flags: err=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    srv_stop(s);
}

TEST(tls_clientcert_context_option_rules) {
    PCCERT_CONTEXT cc = srv_cert_get(SRV_CERT_CLIENT);
    if (!cc) { t_skip("client certificate unavailable"); return; }
    treq t; CHECK(treq_open(&t, "127.0.0.1", 443, "GET", "/cc", T_INET_FRESH | INTERNET_FLAG_SECURE));
    /* session / connect: 12018 */
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(t.hi, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, sizeof(CERT_CONTEXT)), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(t.hc, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, sizeof(CERT_CONTEXT)), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    /* length must be >= sizeof(CERT_CONTEXT) (0x28) */
    EXPECT_EQ(sizeof(CERT_CONTEXT), 0x28);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(t.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, 0x27), ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0);
    BOOL ok = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, NULL, 0);
    DWORD e = ok ? 0 : GetLastError();
    t_note("CLIENT_CERT_CONTEXT NULL,0: ok=%d err=%lu", ok, e);
    CHECK(!ok);
    SET_ERR(0);
    ok = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, sizeof(CERT_CONTEXT));
    CHECKF(ok, "err=%lu", GetLastError());
    /* plain HTTP request (no security entry): 12046 per decomp */
    treq p; CHECK(treq_open(&p, "127.0.0.1", 80, "GET", "/", T_INET_FRESH));
    SET_ERR(0);
    ok = U(InternetSetOptionA)(p.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, sizeof(CERT_CONTEXT));
    e = ok ? 0 : GetLastError();
    t_note("CLIENT_CERT_CONTEXT on http request: ok=%d err=%lu", ok, e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP);
    treq_close(&p);
    treq_close(&t);
}

TEST(tls_clientcert_select_option_rules) {
    treq t; CHECK(treq_open(&t, "127.0.0.1", 443, "GET", "/sel", T_INET_FRESH | INTERNET_FLAG_SECURE));
    DWORD idx = 0; SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(t.hi, INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT, &idx, sizeof idx), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(t.hr, INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT, &idx, 2), ERROR_INSUFFICIENT_BUFFER);
    /* no certificate list yet (no 12044 happened) -> 12046 */
    SET_ERR(0);
    BOOL ok = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT, &idx, sizeof idx);
    DWORD e = ok ? 0 : GetLastError();
    t_note("SELECT_CLIENT_CERT before any request: ok=%d err=%lu", ok, e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_CLIENT_AUTH_NOT_SETUP);
    treq_close(&t);
}

/* 12044 -> set the client certificate -> resend: the server receives it */
TEST(tls_clientcert_retry_with_context) {
    PCCERT_CONTEXT cc = srv_cert_get(SRV_CERT_CLIENT);
    if (!cc) { t_skip("client certificate unavailable"); return; }
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 1, NULL, 0, &rc); if (!s) { t_skip("server: %s", srv_strerror(rc)); return; }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/mtls", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED);
    SET_ERR(0);
    CHECKF(U(InternetSetOptionA)(t.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, sizeof(CERT_CONTEXT)), "err=%lu", GetLastError());
    DWORD e = treq_send(&t);
    t_note("after CLIENT_CERT_CONTEXT: err=%lu %s", e, t_inet_errname(e));
    tls_dump_tls_events(s);
    EXPECT_EQ(e, 0);
    if (!e) {
        EXPECT_EQ(treq_status(&t), 200);
        int saw = 0; for (int i = 0; tls_done_data(s, i); i++) if (tls_ev_field(tls_done_data(s, i), "client_cert") == 1) saw = 1;
        CHECK(saw);
    }
    treq_close(&t); srv_stop(s);
}

/* 12044 -> "continue without a certificate" (CLIENT_CERT_CONTEXT NULL is rejected; probe the documented route) */
TEST(tls_clientcert_continue_without_probe) {
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 1, NULL, 0, &rc); if (!s) { t_skip("server: %s", srv_strerror(rc)); return; }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/nocert", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED);
    BOOL ok = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, NULL, 0);
    DWORD e1 = ok ? 0 : GetLastError();
    DWORD idx = (DWORD)-1;
    BOOL ok2 = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_SECURITY_SELECT_CLIENT_CERT, &idx, sizeof idx);
    DWORD e2 = ok2 ? 0 : GetLastError();
    DWORD e3 = treq_send(&t);
    t_note("continue without cert: CERT_CONTEXT(NULL) ok=%d err=%lu; SELECT(-1) ok=%d err=%lu; resend err=%lu %s",
           ok, e1, ok2, e2, e3, t_inet_errname(e3));
    tls_dump_tls_events(s);
    treq_close(&t); srv_stop(s);
}

/* server demands a certificate (tls_client_cert = 2), client supplies one up front */
TEST(tls_clientcert_up_front) {
    PCCERT_CONTEXT cc = srv_cert_get(SRV_CERT_CLIENT);
    if (!cc) { t_skip("client certificate unavailable"); return; }
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, 0, 2, NULL, 0, &rc); if (!s) { t_skip("server: %s", srv_strerror(rc)); return; }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/pre", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    BOOL ok = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_CLIENT_CERT_CONTEXT, (void *)cc, sizeof(CERT_CONTEXT));
    CHECKF(ok, "err=%lu", GetLastError());
    DWORD e = treq_send(&t);
    t_note("up-front client cert: err=%lu %s", e, t_inet_errname(e));
    tls_dump_tls_events(s);
    EXPECT_EQ(e, 0);
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ CONNECT proxy */
TEST(tls_proxy_connect_tunnel_success) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    tp_srv *p = tp_start("HTTP/1.1 200 Connection established\r\n\r\n", srv_port(s));
    if (!p) { srv_stop(s); t_skip("winsock unavailable"); return; }
    treq t;
    /* the target host never resolves: the proxy maps every CONNECT to the TLS server */
    CHECK(treq_open_proxy(&t, tls_hostport("127.0.0.1", tp_port(p)), "i7tls.invalid", 8443, "/via", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID);
    DWORD e = treq_send(&t);
    t_note("CONNECT tunnel: err=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, 0);
    EXPECT_EQ(treq_status(&t), 200);
    char b[16] = ""; treq_body(&t, b, sizeof b); EXPECT_STR(b, "hello");
    CHECK(tp_wait(p, 1, 2000));
    const char *h = tp_head(p, 0);
    t_note("CONNECT head: %s", h ? h : "(none)");
    CHECK(h && !strncmp(h, "CONNECT i7tls.invalid:8443 HTTP/1.1\r\n", 37));
    CHECK(h && strstr(h, "\r\nHost: i7tls.invalid:8443\r\n") != NULL);
    CHECK(h && strstr(h, "\r\nUser-Agent: tls-test\r\n") != NULL);
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_STR(srv_req_line(s, 0), "GET /via HTTP/1.1");          /* origin-form inside the tunnel */
    EXPECT_STR(srv_req_header(s, 0, "Host"), "i7tls.invalid:8443");
    treq_close(&t); tp_stop(p); srv_stop(s);
}

/* through the tunnel the certificate is checked against the target name: CN error without 0x1000 */
TEST(tls_proxy_connect_cert_checked_against_target) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    tp_srv *p = tp_start("HTTP/1.1 200 Connection established\r\n\r\n", srv_port(s));
    if (!p) { srv_stop(s); t_skip("winsock unavailable"); return; }
    treq t;
    CHECK(treq_open_proxy(&t, tls_hostport("127.0.0.1", tp_port(p)), "i7tls.invalid", 443, "/via", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    DWORD e = treq_send(&t);
    EXPECT_EQ(e, ERROR_INTERNET_SEC_CERT_CN_INVALID);
    CHECK(tp_wait(p, 1, 2000));
    const char *h = tp_head(p, 0);
    CHECK(h && !strncmp(h, "CONNECT i7tls.invalid:443 HTTP/1.1\r\n", 36));
    treq_close(&t); tp_stop(p); srv_stop(s);
}

/* SNI inside the tunnel is the target host */
TEST(tls_proxy_connect_sni_is_target) {
    th_srv *o = th_start(TH_CLOSE); if (!o) { t_skip("winsock unavailable"); return; }
    tp_srv *p = tp_start("HTTP/1.1 200 Connection established\r\n\r\n", th_port(o));
    treq t;
    CHECK(treq_open_proxy(&t, tls_hostport("127.0.0.1", tp_port(p)), "sni-target.i7test.example", 443, "/", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, SECURITY_SET_MASK);
    DWORD e = treq_send(&t);
    th_wait(o, 1, 3000);
    const th_hello *h = th_get(o, 0);
    t_note("tunnel SNI: err=%lu sni=%s", e, h && h->has_sni ? h->sni : "(none)");
    CHECK(h && h->has_sni);
    if (h && h->has_sni) EXPECT_STR(h->sni, "sni-target.i7test.example");
    treq_close(&t); tp_stop(p); th_stop(o);
}

typedef struct { const char *reply; DWORD want_err; DWORD want_status; } proxy_row;
TEST(tls_proxy_connect_refused_matrix) {
    static const proxy_row rows[] = {
        { "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", 0, 403 },
        { "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", 0, 502 },
        { "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n", 0, 407 },
        { "HTTP/1.0 200 OK\r\n\r\n", 0xFFFFFFFF, 0 },
        { "garbage\r\n\r\n", 0xFFFFFFFF, 0 },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        tp_srv *p = tp_start(rows[i].reply, 0);
        if (!p) { t_skip("winsock unavailable"); return; }
        treq t;
        CHECK(treq_open_proxy(&t, tls_hostport("127.0.0.1", tp_port(p)), "i7tls.invalid", 443, "/", T_INET_FRESH | INTERNET_FLAG_SECURE));
        t_https_secflags(t.hr, SECURITY_SET_MASK);
        DWORD e = treq_send(&t), st = e ? 0 : treq_status(&t);
        t_note("proxy reply %.30s -> err=%lu %s status=%lu connects=%d", rows[i].reply, e, t_inet_errname(e), st, tp_count(p));
        if (rows[i].want_err != 0xFFFFFFFF) {
            CHECKF(e == rows[i].want_err && st == rows[i].want_status, "row %u: err=%lu st=%lu", (unsigned)i, e, st);
        } else CHECKF(e != 0, "row %u unexpectedly succeeded (status %lu)", (unsigned)i, st);
        treq_close(&t); tp_stop(p);
    }
}

/* ------------------------------------------------------------------ redirects across schemes */
TEST(tls_redirect_http_to_https) {
    srv *ts = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!ts) TLS_SKIP_SRV();
    char loc[128]; snprintf(loc, sizeof loc, "Location: https://127.0.0.1:%u/landed\r\n", srv_port(ts));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, NULL }, S_LOOP() };
    st[1].hdrs = loc;
    srv *hs = srv_http(st, 3); if (!hs) { srv_stop(ts); TLS_SKIP_SRV(); }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(hs), "GET", "/start", T_INET_FRESH));
    DWORD e = treq_send(&t);
    t_note("http->https redirect, no flags: err=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    /* retry protocol: set the ignore flag on the same handle and resend */
    t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    e = treq_send(&t);
    t_note("after 0x100 resend: err=%lu status=%lu", e, e ? 0 : treq_status(&t));
    EXPECT_EQ(e, 0);
    if (!e) {
        EXPECT_EQ(treq_status(&t), 200);
        char url[256]; DWORD l = sizeof url;
        CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_URL, url, &l));
        char want[128]; snprintf(want, sizeof want, "https://127.0.0.1:%u/landed", srv_port(ts));
        EXPECT_STR(url, want);
        CHECK(tls_secflags(t.hr) & SECURITY_FLAG_SECURE);
    }
    treq_close(&t); srv_stop(hs); srv_stop(ts);
}

TEST(tls_redirect_http_to_https_flags_preset) {
    srv *ts = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!ts) TLS_SKIP_SRV();
    char loc[128]; snprintf(loc, sizeof loc, "Location: https://127.0.0.1:%u/landed\r\n", srv_port(ts));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, NULL }, S_LOOP() };
    st[1].hdrs = loc;
    srv *hs = srv_http(st, 3); if (!hs) { srv_stop(ts); TLS_SKIP_SRV(); }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(hs), "GET", "/start", T_INET_FRESH));
    BOOL set = tls_set_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    t_note("presetting 0x100 on an http request: ok=%d flags=0x%lx", set, tls_secflags(t.hr));
    DWORD e = treq_send(&t);
    t_note("http->https with preset flags: err=%lu %s", e, t_inet_errname(e));
    treq_close(&t); srv_stop(hs); srv_stop(ts);
}

TEST(tls_redirect_https_to_http) {
    static const srv_step hst[] = { S_HEAD(), S_REPLY(200, NULL, "plain-landed"), S_LOOP() };
    srv *hs = srv_http(hst, 3); if (!hs) TLS_SKIP_SRV();
    char loc[128]; snprintf(loc, sizeof loc, "Location: http://127.0.0.1:%u/plain\r\n", srv_port(hs));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, NULL }, S_LOOP() };
    st[1].hdrs = loc;
    srv *ts = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!ts) { srv_stop(hs); TLS_SKIP_SRV(); }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(ts), "GET", "/secure", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    DWORD e = treq_send(&t);
    DWORD st2 = e ? 0 : treq_status(&t);
    t_note("https->http redirect: err=%lu %s status=%lu http requests=%d", e, t_inet_errname(e), st2, srv_req_count(hs));
    EXPECT_EQ(e, 0);
    EXPECT_EQ(st2, 200);
    if (!e) {
        char b[32] = ""; treq_body(&t, b, sizeof b); EXPECT_STR(b, "plain-landed");
        DWORD f = tls_secflags(t.hr);
        t_note("flags after landing on http: 0x%lx", f);
    }
    treq_close(&t); srv_stop(ts); srv_stop(hs);
}

TEST(tls_redirect_https_same_server) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(301, "Location: /moved\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "moved-here"), S_LOOP_TO(2) };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 5); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/orig", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    EXPECT_EQ(treq_status(&t), 200);
    char b[32] = ""; treq_body(&t, b, sizeof b); EXPECT_STR(b, "moved-here");
    CHECK(srv_wait_requests(s, 2, 2000));
    EXPECT_STR(srv_req_line(s, 1), "GET /moved HTTP/1.1");
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));
    treq_close(&t); srv_stop(s);
}

/* redirect to another https origin whose certificate has a CN problem: the flags set for the first hop carry over? */
TEST(tls_redirect_https_to_https_other_cert) {
    srv *s2 = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s2) TLS_SKIP_SRV();
    char loc[128]; snprintf(loc, sizeof loc, "Location: https://127.0.0.1:%u/second\r\n", srv_port(s2));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, NULL }, S_LOOP() };
    st[1].hdrs = loc;
    srv *s1 = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s1) { srv_stop(s2); TLS_SKIP_SRV(); }
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s1), "GET", "/first", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    DWORD e = treq_send(&t);
    t_note("https->https(CN_OTHER) with 0x100: err=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_SEC_CERT_CN_INVALID);
    t_https_secflags(t.hr, 0x1000);
    e = treq_send(&t);
    t_note("+0x1000 resend: err=%lu status=%lu", e, e ? 0 : treq_status(&t));
    EXPECT_EQ(e, 0);
    treq_close(&t); srv_stop(s1); srv_stop(s2);
}

/* ------------------------------------------------------------------ InternetOpenUrl over https */
TEST(tls_openurl_cn_flag_path) {
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    HINTERNET hi = t_inet_open(NULL);
    SET_ERR(0);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/u"), NULL, 0, T_INET_FRESH | INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0);
    DWORD e = hu ? 0 : GetLastError();
    t_note("OpenUrl CN_OTHER + IGNORE_CERT_CN_INVALID: err=%lu", e);
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    if (hu) U(InternetCloseHandle)(hu);
    t_inet_close(hi); srv_stop(s);
}

/* InternetReadFile / QueryDataAvailable across TLS records with a slow, split server */
TEST(tls_flow_split_records_slow) {
    static const srv_step st[] = { S_HEAD(), S_SPLIT("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabcdefghijklmnopqrst", 7, 20), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/split", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    DWORD avail = 0;
    CHECK(U(InternetQueryDataAvailable)(t.hr, &avail, 0, 0));
    CHECK(avail > 0 && avail <= 20);
    char b[64] = ""; treq_body(&t, b, sizeof b);
    EXPECT_STR(b, "abcdefghijklmnopqrst");
    treq_close(&t); srv_stop(s);
}

/* server truncates the body after announcing the full length */
TEST(tls_flow_truncated_body) {
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "0123456789abcdef", SRV_R_TRUNCATE) };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 2); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/tr", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    char b[64] = ""; int ok = 0; size_t n = t_inet_read_all(t.hr, b, sizeof b, &ok);
    t_note("truncated over TLS: read %u bytes ok=%d err=%lu", (unsigned)n, ok, ok ? 0 : GetLastError());
    EXPECT_EQ(n, 8);
    treq_close(&t); srv_stop(s);
}
