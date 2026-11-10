/* wire_extra.c - HTTPS request bytes (decrypted by the loopback schannel server), InternetOpenUrl request bytes,
 * Accept-Encoding with INTERNET_OPTION_HTTP_DECODING, blocked ports (no wire), redirect re-requests.
 * See EVIDENCE.md. */
#include "hrw.h"

/* ------------------------------------------------------------------ HTTPS */
static srv *https_ok(void) {
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE_IF_ASKED(), S_LOOP() };
    return srv_https(st, 5, SRV_CERT_LOCALHOST);
}
GTEST(hrw_https_request_line_and_host, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = https_ok(); if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("tls/1");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/tls?x=1", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_SECURE, 0);
    CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    CHECKF(ok, "err %lu %s", GetLastError(), t_inet_errname(GetLastError()));
    char b[32]; t_inet_read_all(hr, b, sizeof b, NULL); EXPECT_STR(b, "ok");
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /tls?x=1 HTTP/1.1");
    EXPECT_HDR(s, 0, "Host", hrw_hostport(s));
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_https_post_body, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = https_ok(); if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("tls/2");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/tp", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_SECURE, 0);
    CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    CHECK(U(HttpSendRequestA)(hr, "Content-Type: text/plain\r\n", (DWORD)-1, "secret-body", 11));
    char b[32]; t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    size_t n = 0; const char *body = srv_req_body(s, 0, &n);
    CHECK(body && n == 11 && !memcmp(body, "secret-body", 11));
    EXPECT_NAMES(s, 0, "Content-Type|User-Agent|Host|Content-Length|Cache-Control");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_https_keepalive_reuse, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = https_ok(); if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("tls/3");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    for (int i = 0; i < 2; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/k", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_SECURE, 0);
        CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
        CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
        char b[32]; t_inet_read_all(hr, b, sizeof b, NULL);
        U(InternetCloseHandle)(hr);
    }
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl */
TEST(hrw_openurl_headers_param) {
    REQUIRE(U(InternetOpenUrlA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ou/1");
    char body[16]; size_t n; DWORD err;
    int st = t_http_get(hi, srv_url(s, "/ou?a=b"), "X-Ou: 1\r\nX-Ou2: 2\r\n", HRW_F, body, sizeof body, &n, &err);
    EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /ou?a=b HTTP/1.1");
    EXPECT_NAMES(s, 0, "X-Ou|X-Ou2|User-Agent|Host|Cache-Control");
    t_inet_close(hi); srv_stop(s);
}
TEST(hrw_openurl_no_path_is_slash) {
    REQUIRE(U(InternetOpenUrlA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ou/2");
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u", srv_port(s));
    char body[16]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(hi, url, NULL, HRW_F, body, sizeof body, &n, &err), 200);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET / HTTP/1.1");
    t_inet_close(hi); srv_stop(s);
}
TEST(hrw_openurl_fragment_dropped) {
    REQUIRE(U(InternetOpenUrlA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ou/3");
    char body[16]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/frag?q=1#section"), NULL, HRW_F, body, sizeof body, &n, &err), 200);
    CHECK(srv_wait_requests(s, 1, 3000));
    t_note("OpenUrl with fragment: %s", srv_req_line(s, 0));
    EXPECT_STR(srv_req_line(s, 0), "GET /frag?q=1 HTTP/1.1");
    t_inet_close(hi); srv_stop(s);
}
TEST(hrw_openurl_userinfo_basic) {
    REQUIRE(U(InternetOpenUrlA)); HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"u\"\r\n", "no"), S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    srv *s = hrw_srv_steps(st, 5); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ou/4");
    char url[96]; snprintf(url, sizeof url, "http://usr:pwd@127.0.0.1:%u/ui", srv_port(s));
    char body[16]; size_t n; DWORD err;
    int code = t_http_get(hi, url, NULL, HRW_F, body, sizeof body, &n, &err);
    t_note("OpenUrl user:pass@ -> %d, requests=%d, req0 auth=%s", code, srv_req_count(s), srv_req_header(s, 0, "Authorization"));
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /ui HTTP/1.1");
    if (srv_req_count(s) >= 2) EXPECT_HDR(s, 1, "Authorization", "Basic dXNyOnB3ZA==");
    t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ decoding option adds Accept-Encoding */
TEST(hrw_decoding_option_adds_accept_encoding) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "dec/1", "GET", "/dec", NULL, NULL, NULL, HRW_F));
    BOOL on = TRUE;
    CHECK(U(InternetSetOptionA)(w.hr, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Accept-Encoding", "gzip, deflate");
    t_note("decoding names: %s", hrw_names(s, 0));
    hrw_done(&w);
}
TEST(hrw_decoding_option_on_session) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open("dec/2");
    BOOL on = TRUE;
    CHECK(U(InternetSetOptionA)(w.hi, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    w.hc = U(InternetConnectA)(w.hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/dec2", NULL, NULL, NULL, HRW_F, 0);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Accept-Encoding", "gzip, deflate");
    hrw_done(&w);
}
TEST(hrw_decoding_user_accept_encoding_kept) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "dec/3", "GET", "/dec3", NULL, NULL, NULL, HRW_F));
    BOOL on = TRUE;
    CHECK(U(InternetSetOptionA)(w.hr, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    hrw_send(&w, "Accept-Encoding: identity\r\n", (DWORD)-1, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    t_note("user AE + decoding: %d occurrences, first=%s", srv_req_header_occurrences(s, 0, "Accept-Encoding"), srv_req_header(s, 0, "Accept-Encoding"));
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Accept-Encoding"), 1);
    hrw_done(&w);
}
TEST(hrw_no_decoding_user_accept_encoding_verbatim) {
    hrw w; int r = hrw_simple(&w, "ae/1", "GET", "/ae", NULL, NULL, NULL, HRW_F, "Accept-Encoding: br\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Accept-Encoding", "br");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ blocked ports: HttpOpenRequest fails, no wire */
static void blocked_port(INTERNET_PORT port) {
    HINTERNET hi = t_inet_open("bp/1");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    SetLastError(0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, HRW_F, 0);
    DWORD e = GetLastError();
    CHECKF(!hr, "port %u: request opened", port);
    CHECKF(e == ERROR_INTERNET_INVALID_URL, "port %u: err %lu want 12005", port, e);
    if (hr) U(InternetCloseHandle)(hr);
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}
TEST(hrw_blocked_port_25) { HRW_REQUIRE_HTTP(); blocked_port(25); }
TEST(hrw_blocked_port_21) { HRW_REQUIRE_HTTP(); blocked_port(21); }
TEST(hrw_blocked_port_110) { HRW_REQUIRE_HTTP(); blocked_port(110); }
TEST(hrw_blocked_port_143) { HRW_REQUIRE_HTTP(); blocked_port(143); }
TEST(hrw_blocked_port_993) { HRW_REQUIRE_HTTP(); blocked_port(993); }

/* ------------------------------------------------------------------ redirects: what the follow-up request looks like */
TEST(hrw_redirect_302_post_becomes_get) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_BODY(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(3) };
    srv *s = hrw_srv_steps(st, 7); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rd/1", "POST", "/src", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, "Content-Type: text/plain\r\nX-Keep: k\r\n", (DWORD)-1, "abc", 3);
    CHECK(w.ok); EXPECT_EQ(w.status, 200); hrw_read(&w); EXPECT_STR(w.body, "landed");
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 0), "POST /src HTTP/1.1");
    EXPECT_STR(srv_req_line(s, 1), "GET /dst HTTP/1.1");
    EXPECT_NOHDR(s, 1, "Content-Length");
    t_note("after 302: %s", hrw_names(s, 1));
    hrw_dump(s, 1);
    hrw_done(&w);
}
TEST(hrw_redirect_301_get_keeps_custom_headers) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_REPLY(301, "Location: /moved\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "m"), S_LOOP_TO(2) };
    srv *s = hrw_srv_steps(st, 5); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rd/2", "GET", "/orig", NULL, "http://ref.example/", NULL, HRW_F));
    hrw_send(&w, "X-Keep: k\r\n", (DWORD)-1, NULL, 0);
    CHECK(w.ok); EXPECT_EQ(w.status, 200); hrw_read(&w);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 1), "GET /moved HTTP/1.1");
    EXPECT_HDR(s, 1, "X-Keep", "k");
    t_note("after 301: %s", hrw_names(s, 1));
    hrw_dump(s, 1);
    hrw_done(&w);
}
TEST(hrw_redirect_303_put_becomes_get) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(303, "Location: /see\r\n", ""), S_HEAD(), S_BODY(), S_REPLY(200, NULL, "s"), S_LOOP_TO(3) };
    srv *s = hrw_srv_steps(st, 7); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rd/3", "PUT", "/put", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, "xyz", 3);
    CHECK(w.ok); EXPECT_EQ(w.status, 200); hrw_read(&w);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 1), "GET /see HTTP/1.1");
    hrw_done(&w);
}
TEST(hrw_redirect_307_post_keeps_body) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(307, "Location: /tmp307\r\n", ""), S_HEAD(), S_BODY(), S_REPLY(200, NULL, "t"), S_LOOP_TO(3) };
    srv *s = hrw_srv_steps(st, 7); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rd/4", "POST", "/p307", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, "body7", 5);
    t_note("POST 307: ok=%d err=%lu status=%d requests=%d", w.ok, w.err, w.status, srv_req_count(s));
    if (w.ok) hrw_read(&w);
    if (w.ok && srv_wait_requests(s, 2, 3000)) {
        EXPECT_STR(srv_req_line(s, 1), "POST /tmp307 HTTP/1.1");
        size_t n = 0; const char *b = srv_req_body(s, 1, &n);
        CHECK(b && n == 5 && !memcmp(b, "body7", 5));
    }
    hrw_done(&w);
}
