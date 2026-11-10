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
/* Win10 VM (https_tls area too): a TLS connection whose certificate errors were ignored is not pooled; every request
 * handle with SECURITY_FLAG_IGNORE_UNKNOWN_CA makes a new connection. */
GTEST(hrw_https_ignored_cert_not_reused, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = https_ok(); if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("tls/3");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    /* A single loopback TLS handshake occasionally aborts with 12030 on the VM (C1: 2nd attempt, C3: 1st attempt), so
     * a failed attempt is retried (bounded) and the property is checked on the requests that completed. */
    int okc = 0;
    for (int i = 0; i < 5 && okc < 2; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/k", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_SECURE, 0);
        CHECK(t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        DWORD e = ok ? 0 : GetLastError();
        if (!ok) t_note("TLS attempt %d: err=%lu %s conns=%d (retrying)", i, e, t_inet_errname(e), srv_conn_count(s));
        char b[32]; if (ok) { okc++; t_inet_read_all(hr, b, sizeof b, NULL); }
        U(InternetCloseHandle)(hr);
    }
    EXPECT_EQ(okc, 2);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NE(srv_req_conn(s, 0), srv_req_conn(s, 1));
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
TEST(hrw_openurl_fragment_kept) {
    REQUIRE(U(InternetOpenUrlA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ou/3");
    char body[16]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/frag?q=1#section"), NULL, HRW_F, body, sizeof body, &n, &err), 200);
    CHECK(srv_wait_requests(s, 1, 3000));
    /* Win10 VM: InternetOpenUrl keeps the fragment in the request-target */
    EXPECT_STR(srv_req_line(s, 0), "GET /frag?q=1#section HTTP/1.1");
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
    /* Win10 VM: credentials from the URL are not sent pre-emptively; they answer the 401 */
    EXPECT_EQ(code, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /ui HTTP/1.1");
    EXPECT_NOHDR(s, 0, "Authorization");
    EXPECT_HDR(s, 1, "Authorization", "Basic dXNyOnB3ZA==");
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
    /* _CheckDecompressionRequestHeaders@0x664d4 only PARSES a caller Accept-Encoding (gzip/deflate/br bits); it never
     * adds one. Win10 VM: no Accept-Encoding on the wire. */
    EXPECT_NOHDR(s, 0, "Accept-Encoding");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
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
    EXPECT_NOHDR(s, 0, "Accept-Encoding");
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
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Accept-Encoding"), 1);
    EXPECT_HDR(s, 0, "Accept-Encoding", "identity");
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
    /* Win10 VM: the GET drops Content-Type, keeps caller headers, and ends with Connection: Keep-Alive (re-send) */
    EXPECT_NAMES(s, 1, "X-Keep|User-Agent|Host|Cache-Control|Connection");
    EXPECT_HDR(s, 1, "Connection", "Keep-Alive");
    EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 0));
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
    EXPECT_NAMES(s, 1, "Referer|X-Keep|User-Agent|Host|Cache-Control|Connection");
    EXPECT_HDR(s, 1, "Referer", "http://ref.example/");
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
TEST(hrw_redirect_307_post_needs_confirmation) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(307, "Location: /tmp307\r\n", ""), S_HEAD(), S_BODY(), S_REPLY(200, NULL, "t"), S_LOOP_TO(3) };
    srv *s = hrw_srv_steps(st, 7); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rd/4", "POST", "/p307", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, "body7", 5);
    /* Win10 VM: a 307 for a POST is not followed; HttpSendRequest fails with 12168 REDIRECT_NEEDS_CONFIRMATION and
     * nothing is re-sent */
    CHECK(!w.ok); EXPECT_EQ(w.err, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    Sleep(100);
    EXPECT_EQ(srv_req_count(s), 1);
    hrw_done(&w);
}
