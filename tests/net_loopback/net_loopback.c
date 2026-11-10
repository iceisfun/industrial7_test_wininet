/* net_loopback - proves the loopback server chain (common/srv.*, common/tnet.*) with real WinINet clients.
 * Area prefix: netlb_. Every server lives on 127.0.0.1 (+[::1]) on an ephemeral port; no internet.
 * Hard CHECKs are facts measured on the Win10 VM (docs/research/04 F8/F12/F13 and results/win10/net_loopback.txt);
 * everything else is t_note. */
#include "t.h"
#include <winsock2.h>
#include <wininet.h>
#include "srv.h"
#include "tnet.h"

#define START_OR_SKIP(cfgp, sp) do { int rc_ = srv_start((cfgp), (sp)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)

/* --------------------------------------------------------------- the library itself (raw winsock client) */
static int raw_exchange(unsigned short port, const char *req, char *resp, int cap) {
    __typeof__(&socket) p_socket = UIN("ws2_32.dll", socket); __typeof__(&connect) p_connect = UIN("ws2_32.dll", connect);
    __typeof__(&send) p_send = UIN("ws2_32.dll", send); __typeof__(&recv) p_recv = UIN("ws2_32.dll", recv);
    __typeof__(&closesocket) p_close = UIN("ws2_32.dll", closesocket); __typeof__(&setsockopt) p_sso = UIN("ws2_32.dll", setsockopt);
    if (!p_socket || !p_connect || !p_send || !p_recv || !p_close || !p_sso) return -2;
    SOCKET so = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (so == INVALID_SOCKET) return -1;
    DWORD to = 3000; p_sso(so, SOL_SOCKET, SO_RCVTIMEO, (char *)&to, sizeof to);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = (unsigned short)((port >> 8) | (port << 8)); a.sin_addr.s_addr = 0x0100007f;
    int n = 0;
    if (!p_connect(so, (struct sockaddr *)&a, sizeof a) && p_send(so, req, (int)strlen(req), 0) > 0)
        for (int r; n < cap - 1 && (r = p_recv(so, resp + n, cap - 1 - n, 0)) > 0; ) n += r;
    resp[n] = 0; p_close(so);
    return n;
}

TEST(netlb_srv_selftest_raw) {
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, "X-T: %P\r\n", "abc"), S_CLOSE_IF_ASKED(), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s;
    START_OR_SKIP(&cfg, &s);
    char resp[1024];
    int n = raw_exchange(srv_port(s), "POST /x?y HTTP/1.1\r\nHost: h\r\nx-Mixed: 1\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody", resp, sizeof resp);
    if (n == -2) { srv_stop(s); t_skip("ws2_32 exports missing"); return; }
    char want[128]; snprintf(want, sizeof want, "HTTP/1.1 200 OK\r\nX-T: %u\r\nContent-Length: 3\r\n\r\nabc", srv_port(s));
    EXPECT_STR(resp, want);
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_STR(srv_req_line(s, 0), "POST /x?y HTTP/1.1");
    EXPECT_STR(srv_req_method(s, 0), "POST");
    EXPECT_STR(srv_req_target(s, 0), "/x?y");
    EXPECT_EQ(srv_req_header_count(s, 0), 4);
    EXPECT_STR(srv_req_header_name(s, 0, 1), "x-Mixed");
    EXPECT_STR(srv_req_header(s, 0, "X-MIXED"), "1");
    size_t bl = 0; const char *b = srv_req_body(s, 0, &bl);
    CHECK(b && bl == 4 && !memcmp(b, "body", 4));
    srv_stop(s);
}

TEST(netlb_srv_selftest_chunked_upload_and_pipelining) {
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "1"), S_HEAD(), S_REPLYF(200, NULL, "22", SRV_R_CONN_CLOSE) };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s;
    START_OR_SKIP(&cfg, &s);
    char resp[1024];
    int n = raw_exchange(srv_port(s), "PUT /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nabc\r\n2\r\nde\r\n0\r\nTrail: t\r\n\r\n"
                                      "GET /second HTTP/1.1\r\nHost: x\r\n\r\n", resp, sizeof resp);
    if (n == -2) { srv_stop(s); t_skip("ws2_32 exports missing"); return; }
    EXPECT_STR(resp, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n22");
    CHECK(srv_wait_requests(s, 2, 2000));
    size_t bl; const char *b = srv_req_body(s, 0, &bl);
    CHECK(b && bl == 5 && !memcmp(b, "abcde", 5));
    EXPECT_EQ(srv_req_body_chunked(s, 0), 1);
    const char *raw = srv_req_body_raw(s, 0, &bl);
    CHECK(raw && strstr(raw, "Trail: t\r\n") != NULL);
    EXPECT_STR(srv_req_line(s, 1), "GET /second HTTP/1.1");
    EXPECT_EQ(srv_req_conn(s, 1), 0);
    srv_stop(s);
}

TEST(netlb_srv_selftest_encoders) {
    static const char txt[] = "hello hello hello";
    size_t n; unsigned char *gz = srv_deflate_stored(txt, sizeof txt - 1, 0, &n);
    CHECK(gz[0] == 0x1f && gz[1] == 0x8b && n == 10 + 5 + sizeof txt - 1 + 8);
    free(gz);
    EXPECT_EQ(srv_crc32("123456789", 9), 0xCBF43926UL);
    char *b = srv_b64("any carnal pleas", 16); EXPECT_STR(b, "YW55IGNhcm5hbCBwbGVhcw==");
    size_t dn; unsigned char *d = srv_unb64(b, &dn); CHECK(d && dn == 16 && !memcmp(d, "any carnal pleas", 16)); free(b); free(d);
    EXPECT_EQ(strlen(srv_fox_text()), SRV_FOX_LEN);
}

/* --------------------------------------------------------------- WinINet against the scripted HTTP server */
TEST(netlb_get_basic_wire) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA)); REQUIRE(U(HttpSendRequestA));
    srv *s = srv_http(NULL, 0);   /* built-in: 200 "hello", keep-alive loop */
    if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("netlb-agent/1.0");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/p", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hi && hc && hr);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    CHECKF(ok, "err=%lu %s", GetLastError(), t_inet_errname(GetLastError()));
    DWORD st = 0, l = sizeof st;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL));
    EXPECT_EQ(st, 200);
    char body[64]; int rok; size_t n = t_inet_read_all(hr, body, sizeof body, &rok);
    CHECK(rok); EXPECT_EQ(n, 5); EXPECT_STR(body, "hello");
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /p HTTP/1.1");
    char host[64]; snprintf(host, sizeof host, "127.0.0.1:%u", srv_port(s));
    const char *h = srv_req_header(s, 0, "Host"); CHECK(h && !strcmp(h, host));
    h = srv_req_header(s, 0, "User-Agent"); CHECK(h && !strcmp(h, "netlb-agent/1.0"));
    for (int i = 0; i < srv_req_header_count(s, 0); i++) t_note("hdr[%d] %s: %s", i, srv_req_header_name(s, 0, i), srv_req_header_value(s, 0, i));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* 04 F12: InternetOpenUrl(RELOAD|NO_CACHE_WRITE|NO_COOKIES|NO_UI) sends exactly User-Agent, Host, Cache-Control: no-cache */
TEST(netlb_openurl_header_set) {
    REQUIRE(U(InternetOpenUrlA));
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("i7proto/1.0");
    char body[64]; size_t n; DWORD err;
    int st = t_http_get(hi, srv_url(s, "/p"), NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI,
                        body, sizeof body, &n, &err);
    CHECKF(st == 200, "status %d err %lu", st, err);
    EXPECT_STR(body, "hello");
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /p HTTP/1.1");
    EXPECT_EQ(srv_req_header_count(s, 0), 3);
    const char *n0 = srv_req_header_name(s, 0, 0), *n1 = srv_req_header_name(s, 0, 1), *n2 = srv_req_header_name(s, 0, 2);
    CHECK(n0 && !strcmp(n0, "User-Agent")); CHECK(n1 && !strcmp(n1, "Host")); CHECK(n2 && !strcmp(n2, "Cache-Control"));
    const char *cc = srv_req_header(s, 0, "Cache-Control"); CHECK(cc && !strcmp(cc, "no-cache"));
    t_inet_close(hi); srv_stop(s);
}

TEST(netlb_chunked_response) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, "Content-Type: text/plain\r\n", "0123456789abcdefghij", 3), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    char body[64]; size_t n; DWORD err;
    int code = t_http_get(hi, srv_url(s, "/c"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(code, 200); EXPECT_EQ(n, 20); EXPECT_STR(body, "0123456789abcdefghij");
    t_inet_close(hi); srv_stop(s);
}

TEST(netlb_close_delimited_response) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "until-eof", SRV_R_CLOSE) };
    srv *s = srv_http(st, 2); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    char body[64]; size_t n; DWORD err;
    int code = t_http_get(hi, srv_url(s, "/e"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(code, 200); EXPECT_STR(body, "until-eof");
    t_inet_close(hi); srv_stop(s);
}

TEST(netlb_large_pattern_body) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 300000, 0), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    char *body = malloc(400000); size_t n; DWORD err;
    int code = t_http_get(hi, srv_url(s, "/big"), NULL, T_INET_FRESH, body, 400000, &n, &err);
    EXPECT_EQ(code, 200); EXPECT_EQ(n, 300000); CHECK(srv_pattern_check(body, n, 0));
    free(body); t_inet_close(hi); srv_stop(s);
}

TEST(netlb_post_body_wire) {
    REQUIRE(U(HttpSendRequestA));
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/post", NULL, NULL, NULL, T_INET_FRESH, 0);
    static char data[] = "a=1&b=2";
    static const char hdr[] = "Content-Type: application/x-www-form-urlencoded\r\n";
    BOOL ok = U(HttpSendRequestA)(hr, hdr, (DWORD)-1, data, 7);
    CHECKF(ok, "err=%lu", GetLastError());
    char body[16]; t_inet_read_all(hr, body, sizeof body, NULL);
    EXPECT_STR(body, "hello");
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "POST /post HTTP/1.1");
    const char *cl = srv_req_header(s, 0, "Content-Length"); CHECK(cl && !strcmp(cl, "7"));
    size_t bl; const char *b = srv_req_body(s, 0, &bl); CHECK(b && bl == 7 && !memcmp(b, "a=1&b=2", 7));
    const char *ct = srv_req_header(s, 0, "Content-Type"); CHECK(ct && !strcmp(ct, "application/x-www-form-urlencoded"));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

TEST(netlb_keepalive_reuse) {
    REQUIRE(U(InternetOpenUrlA));
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    char body[16]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/1"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/2"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    t_note("keep-alive: conns=%d req0.conn=%d req1.conn=%d", srv_conn_count(s), srv_req_conn(s, 0), srv_req_conn(s, 1));
    EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 0));
    t_inet_close(hi); srv_stop(s);
}

TEST(netlb_redirect_302_relative) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    srv *s = srv_http(st, 5); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    char body[16]; size_t n; DWORD err;
    int code = t_http_get(hi, srv_url(s, "/src"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(code, 200); EXPECT_STR(body, "landed");
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /src HTTP/1.1");
    EXPECT_STR(srv_req_line(s, 1), "GET /dst HTTP/1.1");
    t_inet_close(hi); srv_stop(s);
}

TEST(netlb_gzip_decoding) {
    REQUIRE(U(InternetOpenUrlA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    BOOL on = TRUE;
    CHECK(U(InternetSetOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    char body[2048]; size_t n; DWORD err;
    int code = t_http_get(hi, srv_url(s, "/gz"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(code, 200); EXPECT_EQ(n, SRV_FOX_LEN); CHECK(n == SRV_FOX_LEN && !memcmp(body, srv_fox_text(), n));
    CHECK(srv_wait_requests(s, 1, 2000));
    const char *ae = srv_req_header(s, 0, "Accept-Encoding");
    t_note("Accept-Encoding with HTTP_DECODING: %s", ae ? ae : "(absent)");
    t_inet_close(hi); srv_stop(s);
}

/* stored-deflate gzip built at run time (SRV_R_GZIP) decodes the same way */
TEST(netlb_gzip_stored_decoding) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "stored gzip body", SRV_R_GZIP), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    BOOL on = TRUE; U(InternetSetOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on);
    char body[64]; size_t n; DWORD err;
    int code = t_http_get(hi, srv_url(s, "/gz"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(code, 200); EXPECT_STR(body, "stored gzip body");
    t_inet_close(hi); srv_stop(s);
}

TEST(netlb_localhost_dualstack) {
    REQUIRE(U(InternetOpenUrlA));
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    if (!srv_has_v6(s)) { srv_stop(s); t_skip("no [::1] listener"); return; }
    HINTERNET hi = t_inet_open(NULL);
    char body[16]; size_t n; DWORD err; DWORD t0 = GetTickCount();
    int code = t_http_get(hi, srv_url_host(s, "localhost", "/l"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    DWORD dt = GetTickCount() - t0;
    EXPECT_EQ(code, 200); EXPECT_STR(body, "hello");
    t_note("localhost GET took %lu ms (04 F2: ~1 ms dual-stack, ~2 s v4-only)", dt);
    CHECK(srv_wait_requests(s, 1, 2000));
    char host[64]; snprintf(host, sizeof host, "localhost:%u", srv_port(s));
    const char *h = srv_req_header(s, 0, "Host"); CHECK(h && !strcmp(h, host));
    t_inet_close(hi); srv_stop(s);
}

/* --------------------------------------------------------------- HTTPS (schannel server, self-signed cert) */
/* 04 F8: no flags -> 12045 ERROR_INTERNET_INVALID_CA; IGNORE_UNKNOWN_CA (0x100) -> 200 with the SAN cert */
TEST(netlb_https_get) {
    REQUIRE(U(HttpSendRequestA));
    srv *s = srv_https(NULL, 0, SRV_CERT_LOCALHOST); if (!s) { t_skip("HTTPS server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/s", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    EXPECT_FAIL(!ok, ERROR_INTERNET_INVALID_CA);
    CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    CHECKF(ok, "err=%lu %s", GetLastError(), t_inet_errname(GetLastError()));
    DWORD st = 0, l = sizeof st;
    U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
    EXPECT_EQ(st, 200);
    char body[16]; t_inet_read_all(hr, body, sizeof body, NULL); EXPECT_STR(body, "hello");
    DWORD sf = 0; l = sizeof sf;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, &sf, &l));
    t_note("security flags after success: 0x%lx (04 F8: 0x20000101)", sf);
    CHECK(sf & SECURITY_FLAG_SECURE);
    CHECK(srv_wait_events(s, SRV_EV_TLS_DONE, 1, 3000));
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_TLS_DONE || ev[i].kind == SRV_EV_TLS_ABORT) t_note("tls: %s %s", srv_event_kind_name(ev[i].kind), ev[i].data ? ev[i].data : "");
    EXPECT_STR(srv_req_line(s, 0), "GET /s HTTP/1.1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
    srv_stop(s);
}

/* 04 F8: CN=i7-other.invalid without SAN: 0x100 alone -> 12038; 0x1100 -> 200 */
TEST(netlb_https_cn_mismatch) {
    REQUIRE(U(HttpSendRequestA));
    srv *s = srv_https(NULL, 0, SRV_CERT_CN_OTHER); if (!s) { t_skip("HTTPS server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/cn", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    EXPECT_FAIL(!ok, ERROR_INTERNET_SEC_CERT_CN_INVALID);
    CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_CERT_CN_INVALID));
    ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    CHECKF(ok, "err=%lu %s", GetLastError(), t_inet_errname(GetLastError()));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
    srv_stop(s);
}

/* --------------------------------------------------------------- FTP */
TEST(netlb_ftp_retr_passive) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetConnectA));
    static const srv_ftp_file files[] = { { "/hello.txt", "hello", 5 }, { "/pub/", NULL, -1 } };
    srv_ftp_config fc = { files, 2 };
    srv_config cfg = { SRV_FTP }; cfg.ftp = &fc; srv *s;
    START_OR_SKIP(&cfg, &s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECKF(hc != NULL, "err=%lu %s", GetLastError(), t_inet_errname(GetLastError()));
    HINTERNET hf = hc ? U(FtpOpenFileA)(hc, "hello.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0) : NULL;
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    char body[16] = ""; if (hf) t_inet_read_all(hf, body, sizeof body, NULL);
    EXPECT_STR(body, "hello");
    if (hf) U(InternetCloseHandle)(hf);
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi);
    srv_wait_events(s, SRV_EV_FTP_DATA, 1, 2000);
    int n = srv_ftp_cmd_count(s);
    for (int i = 0; i < n; i++) t_note("ftp cmd[%d] %s", i, srv_ftp_cmd(s, i));
    CHECK(n > 0 && !strcmp(srv_ftp_cmd(s, 0), "USER anonymous"));   /* 04 F13 */
    int saw_retr = 0; for (int i = 0; i < n; i++) if (!strcmp(srv_ftp_cmd(s, i), "RETR hello.txt")) saw_retr = 1;
    CHECK(saw_retr);
    srv_stop(s);
}

TEST(netlb_ftp_stor_passive) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetWriteFile));
    srv_config cfg = { SRV_FTP }; static const srv_ftp_config fc = { 0 }; cfg.ftp = &fc; srv *s;
    START_OR_SKIP(&cfg, &s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), "tester", "pw", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    HINTERNET hf = hc ? U(FtpOpenFileA)(hc, "up.bin", GENERIC_WRITE, FTP_TRANSFER_TYPE_BINARY, 0) : NULL;
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    DWORD w = 0;
    if (hf) { CHECK(U(InternetWriteFile)(hf, "uploaded!", 9, &w)); EXPECT_EQ(w, 9); U(InternetCloseHandle)(hf); }
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi);
    CHECK(srv_wait_events(s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(s, "/up.bin", &n);
    CHECK(d && n == 9 && !memcmp(d, "uploaded!", 9));
    CHECK(srv_ftp_cmd_count(s) > 1 && !strcmp(srv_ftp_cmd(s, 0), "USER tester") && !strcmp(srv_ftp_cmd(s, 1), "PASS ***"));
    srv_stop(s);
}
