/* wire_conn.c - connection reuse, Connection: close, HTTP/1.0 servers, per-server connection limit, proxy request
 * form (absolute URI, CONNECT), Cookie and Authorization emission, cache revalidation headers.
 * Evidence: Win10 VM (server-side connection counting), decomp where cited. See EVIDENCE.md. */
#include "hrw.h"
#include <stdlib.h>

static int get_on(HINTERNET hc, const char *path, DWORD flags, const char *hdrs, int *status) {
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, flags, 0);
    if (!hr) return 0;
    if (hrw_trace) t_note("trace: send %s flags 0x%lx", path, flags);
    BOOL ok = U(HttpSendRequestA)(hr, hdrs, hdrs ? (DWORD)-1 : 0, NULL, 0);
    if (hrw_trace) t_note("trace: sent ok=%d err=%lu", ok, ok ? 0 : GetLastError());
    DWORD st = 0, l = sizeof st;
    if (ok) { U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL); char b[256]; t_inet_read_all(hr, b, sizeof b, NULL); }
    if (status) *status = (int)st;
    if (hrw_trace) t_note("trace: read done status %lu", st);
    U(InternetCloseHandle)(hr);
    if (hrw_trace) t_note("trace: closed");
    return ok;
}
static HINTERNET connect_to(HINTERNET hi, srv *s) { return U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); }

/* ------------------------------------------------------------------ keep-alive reuse */
TEST(hrw_conn_keepalive_three_requests_one_connection) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ka/1"), hc = connect_to(hi, s);
    int st;
    for (int i = 0; i < 3; i++) { CHECK(get_on(hc, "/ka", HRW_F, NULL, &st)); EXPECT_EQ(st, 200); }
    CHECK(srv_wait_requests(s, 3, 3000));
    EXPECT_EQ(srv_conn_count(s), 1);
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 2));
    for (int i = 0; i < 3; i++) EXPECT_NOHDR(s, i, "Connection");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_reuse_across_connect_handles) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ka/1"), hc1 = connect_to(hi, s), hc2 = connect_to(hi, s);
    int st;
    CHECK(get_on(hc1, "/a", HRW_F, NULL, &st)); CHECK(get_on(hc2, "/b", HRW_F, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    t_note("two connect handles, one session: conns=%d", srv_conn_count(s));
    EXPECT_EQ(srv_conn_count(s), 1);
    U(InternetCloseHandle)(hc1); U(InternetCloseHandle)(hc2); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_reuse_across_sessions_observed) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi1 = t_inet_open("ka/1"), hi2 = t_inet_open("ka/2");
    HINTERNET hc1 = connect_to(hi1, s), hc2 = connect_to(hi2, s);
    int st;
    CHECK(get_on(hc1, "/a", HRW_F, NULL, &st)); CHECK(get_on(hc2, "/b", HRW_F, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    t_note("two sessions (different agents): conns=%d", srv_conn_count(s));
    CHECK(srv_conn_count(s) >= 1 && srv_conn_count(s) <= 2);
    U(InternetCloseHandle)(hc1); U(InternetCloseHandle)(hc2); t_inet_close(hi1); t_inet_close(hi2); srv_stop(s);
}
TEST(hrw_conn_request_connection_close_new_socket) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("cc/1"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, "/1", HRW_F, "Connection: close\r\n", &st)); EXPECT_EQ(st, 200);
    CHECK(get_on(hc, "/2", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_HDR(s, 0, "Connection", "Close");   /* the caller wrote "close"; WinINet sends its own spelling */
    EXPECT_NOHDR(s, 1, "Connection");
    EXPECT_EQ(srv_conn_count(s), 2);
    EXPECT_NE(srv_req_conn(s, 0), srv_req_conn(s, 1));
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_server_connection_close_new_socket) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLYF(200, NULL, "bye", SRV_R_CONN_CLOSE) };
    srv *s = hrw_srv_steps(st_, 3); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("cc/1"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, "/1", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(get_on(hc, "/2", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    EXPECT_NOHDR(s, 1, "Connection");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_close_delimited_new_socket) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_REPLYF(200, NULL, "eof-body", SRV_R_CLOSE) };
    srv *s = hrw_srv_steps(st_, 2); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("cd/1"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, "/1", HRW_F, NULL, &st)); CHECK(get_on(hc, "/2", HRW_F, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_http10_server_no_keepalive) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLYF(200, NULL, "ten", SRV_R_HTTP10), S_CLOSE() };
    srv *s = hrw_srv_steps(st_, 4); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("h10/1"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, "/1", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(get_on(hc, "/2", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    /* the client keeps speaking HTTP/1.1 to an HTTP/1.0 server */
    EXPECT_STR(srv_req_line(s, 1), "GET /2 HTTP/1.1");
    EXPECT_NOHDR(s, 1, "Connection");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_http10_server_keepalive_reused) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLYF(200, NULL, "ten", SRV_R_HTTP10 | SRV_R_KEEPALIVE), S_LOOP() };
    srv *s = hrw_srv_steps(st_, 4); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("h10/1"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, "/1", HRW_F, NULL, &st)); CHECK(get_on(hc, "/2", HRW_F, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    t_note("HTTP/1.0 + Connection: Keep-Alive reply: conns=%d", srv_conn_count(s));
    EXPECT_EQ(srv_conn_count(s), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_http10_server_without_header_reused_by_length) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLYF(200, NULL, "ten", SRV_R_HTTP10), S_LOOP() };
    srv *s = hrw_srv_steps(st_, 4); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("h10/1"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, "/1", HRW_F, NULL, &st)); CHECK(get_on(hc, "/2", HRW_F, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    t_note("HTTP/1.0 reply without Connection header, server keeps socket open: conns=%d", srv_conn_count(s));
    EXPECT_EQ(srv_conn_count(s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_client_http10_keepalive_header) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("c10/1"), hc = connect_to(hi, s);
    for (int i = 0; i < 2; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/c10", "HTTP/1.0", NULL, NULL, HRW_F, 0);
        CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)); char b[64]; t_inet_read_all(hr, b, sizeof b, NULL);
        U(InternetCloseHandle)(hr);
    }
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /c10 HTTP/1.1");   /* 1.0 is upgraded (GlobalEnableHttp1_1) */
    EXPECT_NOHDR(s, 0, "Connection");
    EXPECT_EQ(srv_conn_count(s), 1);
    t_note("HTTP/1.0 client, HTTP/1.1 server reply (no Connection header): conns=%d", srv_conn_count(s));
    hrw_dump(s, 0);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn_keep_connection_flag_header) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "kc/1", "GET", "/kc", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_KEEP_CONNECTION, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Connection|Cache-Control");
    EXPECT_HDR(w.s, 0, "Connection", "Keep-Alive");
    hrw_done(&w);
}
/* After an unread body the connection cannot be reused: the next request opens a second connection. */
TEST(hrw_conn_unread_body_forces_second_connection) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    srv *s = hrw_srv_steps_io(st_, 4, 5000); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("ub/1"), hc = connect_to(hi, s);
    HINTERNET h1 = U(HttpOpenRequestA)(hc, "GET", "/big1", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(HttpSendRequestA)(h1, NULL, 0, NULL, 0));
    HINTERNET h2 = U(HttpOpenRequestA)(hc, "GET", "/big2", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(HttpSendRequestA)(h2, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    EXPECT_NE(srv_req_conn(s, 0), srv_req_conn(s, 1));
    U(InternetCloseHandle)(h1); U(InternetCloseHandle)(h2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ per-server connection limit */
TEST(hrw_conn_max_conns_default_value) {
    REQUIRE(U(InternetQueryOptionA));
    DWORD v = 0;
    CHECK(hrw_get_dword_opt(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &v));
    t_note("MAX_CONNS_PER_SERVER default (global) = %lu", v);
    DWORD v10 = 0;
    CHECK(hrw_get_dword_opt(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &v10));
    t_note("MAX_CONNS_PER_1_0_SERVER default (global) = %lu", v10);
    CHECK(v >= 2); CHECK(v10 >= 2);
}

typedef struct { HINTERNET hc; const char *path; volatile LONG done; BOOL ok; } bg_req;
static DWORD WINAPI bg_send(void *p) {
    bg_req *b = (bg_req *)p;
    HINTERNET hr = U(HttpOpenRequestA)(b->hc, "GET", b->path, NULL, NULL, NULL, HRW_F, 0);
    b->ok = hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (b->ok) { char buf[256]; t_inet_read_all(hr, buf, sizeof buf, NULL); }
    if (hr) U(InternetCloseHandle)(hr);
    InterlockedExchange(&b->done, 1);
    return 0;
}
/* MAX_CONNS_PER_SERVER is a global option: on a session handle the set is refused with 12016. */
TEST(hrw_conn_max_conns_session_set_refused) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = t_inet_open("mc/0");
    DWORD one = 1;
    SetLastError(0);
    CHECK(!U(InternetSetOptionA)(hi, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &one, sizeof one));
    EXPECT_ERR(ERROR_INTERNET_INVALID_OPERATION);
    t_inet_close(hi);
}
/* Default limit (2 per HTTP/1.1 server): a third concurrent request is not put on the wire while two connections are
 * busy with unread bodies; it goes out once one of them is drained and released. */
GTEST(hrw_conn_third_request_waits_for_free_connection, 25000) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    srv *s = hrw_srv_steps_io(st_, 4, 5000); if (!s) { t_skip("server unavailable"); return; }
    DWORD lim = 0; hrw_get_dword_opt(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &lim);
    if (lim != 2) { t_skip("MAX_CONNS_PER_SERVER is %lu, not the default 2", lim); srv_stop(s); return; }
    HINTERNET hi = t_inet_open("mc/1"), hc = connect_to(hi, s);
    HINTERNET h1 = U(HttpOpenRequestA)(hc, "GET", "/hold1", NULL, NULL, NULL, HRW_F, 0);
    HINTERNET h2 = U(HttpOpenRequestA)(hc, "GET", "/hold2", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(HttpSendRequestA)(h1, NULL, 0, NULL, 0));
    CHECK(U(HttpSendRequestA)(h2, NULL, 0, NULL, 0));
    bg_req b = { hc, "/third", 0, FALSE };
    HANDLE th = CreateThread(NULL, 0, bg_send, &b, 0, NULL);
    Sleep(1000);
    int during = srv_req_count(s), conns_during = srv_conn_count(s);
    t_note("two bodies unread: requests=%d conns=%d third_done=%ld", during, conns_during, b.done);
    EXPECT_EQ(during, 2);
    EXPECT_EQ(conns_during, 2);
    EXPECT_EQ(b.done, 0);
    char *buf = malloc(300000); t_inet_read_all(h1, buf, 300000, NULL); free(buf);
    U(InternetCloseHandle)(h1);
    if (th) { CHECK(WaitForSingleObject(th, 8000) == WAIT_OBJECT_0); CloseHandle(th); }
    CHECK(b.ok);
    CHECK(srv_wait_requests(s, 3, 3000));
    EXPECT_STR(srv_req_line(s, 2), "GET /third HTTP/1.1");
    t_note("after draining the first: conns=%d third on conn %d (first on %d)", srv_conn_count(s), srv_req_conn(s, 2), srv_req_conn(s, 0));
    EXPECT_EQ(srv_req_conn(s, 2), srv_req_conn(s, 0));
    U(InternetCloseHandle)(h2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
/* With the default limit two outstanding requests use two connections. */
TEST(hrw_conn_default_limit_allows_two) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    srv *s = hrw_srv_steps_io(st_, 4, 5000); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("mc/2"), hc = connect_to(hi, s);
    HINTERNET h1 = U(HttpOpenRequestA)(hc, "GET", "/h1", NULL, NULL, NULL, HRW_F, 0);
    HINTERNET h2 = U(HttpOpenRequestA)(hc, "GET", "/h2", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(HttpSendRequestA)(h1, NULL, 0, NULL, 0));
    CHECK(U(HttpSendRequestA)(h2, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    U(InternetCloseHandle)(h1); U(InternetCloseHandle)(h2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ proxy request form */
static srv *proxy_srv(void) { return hrw_srv(); }
static int proxy_get(srv *s, HINTERNET hi, const char *host, INTERNET_PORT port, const char *path, DWORD flags, int *status) {
    HINTERNET hc = U(InternetConnectA)(hi, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) return 0;
    int ok = get_on(hc, path, flags, NULL, status);
    U(InternetCloseHandle)(hc);
    return ok;
}
GTEST(hrw_proxy_absolute_uri_default_port, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECKF(proxy_get(s, hi, "wire.i7test.example", 80, "/p?q=1", HRW_F, &st), "err %lu", GetLastError());
    EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET http://wire.i7test.example/p?q=1 HTTP/1.1");
    EXPECT_HDR(s, 0, "Host", "wire.i7test.example");
    hrw_dump(s, 0);
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_header_set, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECK(proxy_get(s, hi, "wire.i7test.example", 80, "/p", HRW_F, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_NAMES(s, 0, "User-Agent|Host|Pragma");   /* via proxy RELOAD becomes Pragma: no-cache; no Proxy-Connection on GET */
    EXPECT_HDR(s, 0, "Pragma", "no-cache");
    EXPECT_NOHDR(s, 0, "Cache-Control");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_absolute_uri_explicit_port, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECK(proxy_get(s, hi, "wire.i7test.example", 8080, "/x", HRW_F, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET http://wire.i7test.example:8080/x HTTP/1.1");
    EXPECT_HDR(s, 0, "Host", "wire.i7test.example:8080");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_absolute_uri_root, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECK(proxy_get(s, hi, "wire.i7test.example", 80, NULL, HRW_F, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET http://wire.i7test.example/ HTTP/1.1");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_host_case_preserved, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECK(proxy_get(s, hi, "Wire.I7Test.Example", 80, "/c", HRW_F, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    /* Win10 VM: the request-target host is lower-cased, the Host header keeps the caller casing */
    EXPECT_STR(srv_req_line(s, 0), "GET http://wire.i7test.example/c HTTP/1.1");
    EXPECT_HDR(s, 0, "Host", "Wire.I7Test.Example");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_ipv6_host, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECK(proxy_get(s, hi, "2001:db8::1", 80, "/six", HRW_F, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET http://[2001:db8::1]/six HTTP/1.1");
    EXPECT_HDR(s, 0, "Host", "[2001:db8::1]");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_ipv6_host_port, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    int st = 0;
    CHECK(proxy_get(s, hi, "2001:db8::1", 8081, "/six", HRW_F, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET http://[2001:db8::1]:8081/six HTTP/1.1");
    EXPECT_HDR(s, 0, "Host", "[2001:db8::1]:8081");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_idn_host_w, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetConnectW));
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1"); CHECK(hi != NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"bücher.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECKF(hc != NULL, "err %lu", GetLastError());
    int st = 0;
    if (hc) { get_on(hc, "/idn", HRW_F, NULL, &st); U(InternetCloseHandle)(hc); }
    if (srv_wait_requests(s, 1, 3000)) {
        t_note("IDN via proxy: line=%s", srv_req_line(s, 0));
        hrw_dump(s, 0);
        const char *h = srv_req_header(s, 0, "Host");
        /* Win10 VM (C2): punycode in both the request-target and Host */
        EXPECT_STR(h, "xn--bcher-kva.i7test.example");
        EXPECT_STR(srv_req_line(s, 0), "GET http://xn--bcher-kva.i7test.example/idn HTTP/1.1");
    } else CHECKF(0, "IDN via proxy: nothing reached the proxy");
    t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_post_absolute, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1");
    HINTERNET hc = U(InternetConnectA)(hi, "wire.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/form", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, "k=v", 3));
    char b[64]; t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "POST http://wire.i7test.example/form HTTP/1.1");
    EXPECT_HDR(s, 0, "Content-Length", "3");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_proxy_keepalive_reuse, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = proxy_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "px/1");
    int st;
    CHECK(proxy_get(s, hi, "a.i7test.example", 80, "/1", HRW_F, &st));
    CHECK(proxy_get(s, hi, "b.i7test.example", 80, "/2", HRW_F, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 1);   /* Win10 VM: one proxy connection serves both origins */
    EXPECT_STR(srv_req_line(s, 1), "GET http://b.i7test.example/2 HTTP/1.1");
    t_inet_close(hi); srv_stop(s);
}
/* HTTPS through a proxy starts with CONNECT host:443. The scripted proxy answers 502 so no TLS is attempted. */
GTEST(hrw_proxy_connect_for_https, 20000) {
    HRW_REQUIRE_HTTP();
    static const srv_step st_[] = { S_HEAD(), S_REPLYF(502, NULL, "no", SRV_R_CONN_CLOSE) };
    srv *s = hrw_srv_steps(st_, 2); if (!s) { t_skip("server unavailable"); return; }
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", srv_port(s));
    HINTERNET hi = U(InternetOpenA)("pxs/1", INTERNET_OPEN_TYPE_PROXY, px, "", 0);
    DWORD to = 5000; U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    HINTERNET hc = U(InternetConnectA)(hi, "secure.i7test.example", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/s", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_SECURE, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD e = ok ? 0 : GetLastError(), stc = 0, l = sizeof stc;
    if (ok) U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &stc, &l, NULL);
    t_note("CONNECT 502: ok=%d err=%lu %s status=%lu", ok, e, t_inet_errname(e), stc);
    CHECK(srv_wait_requests(s, 1, 3000));
    CHECK(ok); EXPECT_EQ(stc, 502);
    EXPECT_STR(srv_req_line(s, 0), "CONNECT secure.i7test.example:443 HTTP/1.0");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Content-Length|Proxy-Connection|Pragma");
    EXPECT_HDR(s, 0, "Content-Length", "0");
    EXPECT_HDR(s, 0, "Proxy-Connection", "Keep-Alive");
    EXPECT_HDR(s, 0, "Pragma", "no-cache");
    EXPECT_HDR(s, 0, "Host", "secure.i7test.example:443");
    EXPECT_HDR(s, 0, "User-Agent", "pxs/1");
    hrw_dump(s, 0);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ cookies */
static char g_ck_path[128];
static const char *cookie_base(srv *s, const char *tag) {
    snprintf(g_ck_path, sizeof g_ck_path, "/%s/", t_uniq(tag));
    return g_ck_path;
}
GTEST(hrw_cookie_set_via_api_sent, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetCookieA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    const char *p = cookie_base(s, "ck1");
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1%s", p);
    CHECK(U(InternetSetCookieA)(url, "hrwk", "v1"));
    t_cookie_track(url, "hrwk");
    HINTERNET hi = t_inet_open("ck/1"), hc = connect_to(hi, s);
    char path[200]; snprintf(path, sizeof path, "%sx", p);
    int st;
    CHECK(get_on(hc, path, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(get_on(hc, path, HRW_F, NULL, &st));            /* NO_COOKIES: none */
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_HDR(s, 0, "Cookie", "hrwk=v1");
    EXPECT_NOHDR(s, 1, "Cookie");
    t_note("cookie position: %s", hrw_names(s, 0));
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control|Cookie");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
GTEST(hrw_cookie_two_cookies_joined, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetCookieA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    const char *p = cookie_base(s, "ck2");
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1%s", p);
    CHECK(U(InternetSetCookieA)(url, "a", "1")); t_cookie_track(url, "a");
    CHECK(U(InternetSetCookieA)(url, "b", "2")); t_cookie_track(url, "b");
    HINTERNET hi = t_inet_open("ck/2"), hc = connect_to(hi, s);
    int st;
    CHECK(get_on(hc, p, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(srv_wait_requests(s, 1, 3000));
    const char *c = srv_req_header(s, 0, "Cookie");
    t_note("two cookies: %s", c ? c : "(none)");
    CHECK(c && (!strcmp(c, "a=1; b=2") || !strcmp(c, "b=2; a=1")));
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Cookie"), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
GTEST(hrw_cookie_path_scoped, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetCookieA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    const char *p = cookie_base(s, "ck3");
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1%sinner/", p);
    char val[200]; snprintf(val, sizeof val, "d; path=%sinner/", p);
    CHECK(U(InternetSetCookieA)(url, "deep", val)); t_cookie_track(url, "deep");
    HINTERNET hi = t_inet_open("ck/3"), hc = connect_to(hi, s);
    char in[256], out[256]; snprintf(in, sizeof in, "%sinner/x", p); snprintf(out, sizeof out, "%sother", p);
    int st;
    CHECK(get_on(hc, in, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(get_on(hc, out, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    const char *c0 = srv_req_header(s, 0, "Cookie");
    CHECKF(c0 && strstr(c0, "deep=d"), "inner Cookie %s", c0 ? c0 : "(none)");
    const char *c1 = srv_req_header(s, 1, "Cookie");
    CHECKF(!c1 || !strstr(c1, "deep="), "outer Cookie %s", c1 ? c1 : "(none)");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
static int setcookie_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int k = 0; k < 20; k++) {
        int i = srv_conn_recv_head(c);
        if (i < 0) return -1;
        const char *t = srv_req_target(s, i);
        if (t && strstr(t, "set"))
            srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nSet-Cookie: srvk=sv; path=%s\r\nContent-Length: 2\r\n\r\nok", (const char *)user);
        else srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    }
    return -1;
}
GTEST(hrw_cookie_from_set_cookie_sent_back, 20000) {
    HRW_REQUIRE_HTTP();
    static char base[128]; snprintf(base, sizeof base, "/%s/", t_uniq("ck4"));
    srv *s = hrw_srv_call(setcookie_fn, base); if (!s) { t_skip("server unavailable"); return; }
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1%s", base); t_cookie_track(url, "srvk");
    HINTERNET hi = t_inet_open("ck/4"), hc = connect_to(hi, s);
    char p1[200], p2[200]; snprintf(p1, sizeof p1, "%sset", base); snprintf(p2, sizeof p2, "%sget", base);
    int st;
    CHECK(get_on(hc, p1, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(get_on(hc, p2, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NOHDR(s, 0, "Cookie");
    EXPECT_HDR(s, 1, "Cookie", "srvk=sv");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
GTEST(hrw_cookie_no_cookies_flag_ignores_set_cookie, 20000) {
    HRW_REQUIRE_HTTP();
    static char base[128]; snprintf(base, sizeof base, "/%s/", t_uniq("ck5"));
    srv *s = hrw_srv_call(setcookie_fn, base); if (!s) { t_skip("server unavailable"); return; }
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1%s", base); t_cookie_track(url, "srvk");
    HINTERNET hi = t_inet_open("ck/5"), hc = connect_to(hi, s);
    char p1[200], p2[200]; snprintf(p1, sizeof p1, "%sset", base); snprintf(p2, sizeof p2, "%sget", base);
    int st;
    CHECK(get_on(hc, p1, HRW_F, NULL, &st));   /* NO_COOKIES: not stored */
    CHECK(get_on(hc, p2, HRW_F & ~INTERNET_FLAG_NO_COOKIES, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NOHDR(s, 1, "Cookie");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
TEST(hrw_cookie_manual_header_with_no_cookies) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ckm/1", "GET", "/m", NULL, NULL, NULL, HRW_F, "Cookie: manual=1\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Cookie", "manual=1");
    EXPECT_NAMES(w.s, 0, "Cookie|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ Authorization */
typedef struct { volatile LONG n401; } auth_state;
static int basic_gate_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int k = 0; k < 20; k++) {
        int i = srv_conn_recv_head(c);
        if (i < 0) return -1;
        const char *a = srv_req_header(s, i, "Authorization");
        if (a) srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ngranted");
        else srv_conn_sendf(c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"hrw\"\r\nContent-Length: 2\r\n\r\nno");
    }
    return -1;
}
GTEST(hrw_auth_basic_retry_after_401, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv_call(basic_gate_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("au/1");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), "user", "pass", INTERNET_SERVICE_HTTP, 0, 0);
    int st = 0;
    CHECK(get_on(hc, "/secret", HRW_F, NULL, &st));
    EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NOHDR(s, 0, "Authorization");
    EXPECT_HDR(s, 1, "Authorization", "Basic dXNlcjpwYXNz");
    EXPECT_NAMES(s, 1, "User-Agent|Host|Cache-Control|Connection|Authorization");
    EXPECT_HDR(s, 1, "Connection", "Keep-Alive");
    EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 0));
    EXPECT_EQ(srv_req_count(s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_auth_basic_preemptive_second_request, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv_call(basic_gate_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("au/2");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), "user", "pass", INTERNET_SERVICE_HTTP, 0, 0);
    int st = 0;
    CHECK(get_on(hc, "/dir/a", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(get_on(hc, "/dir/b", HRW_F, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 3, 3000));
    t_note("second request after Basic success: requests=%d req2 auth=%s", srv_req_count(s), srv_req_header(s, 2, "Authorization"));
    EXPECT_EQ(srv_req_count(s), 3);
    EXPECT_HDR(s, 2, "Authorization", "Basic dXNlcjpwYXNz");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_auth_no_auth_flag_returns_401, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv_call(basic_gate_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("au/3");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), "user", "pass", INTERNET_SERVICE_HTTP, 0, 0);
    int st = 0;
    CHECK(get_on(hc, "/secret", HRW_F | INTERNET_FLAG_NO_AUTH, NULL, &st));
    EXPECT_EQ(st, 401);
    Sleep(100);
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_NOHDR(s, 0, "Authorization");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_auth_no_credentials_returns_401, 20000) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv_call(basic_gate_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("au/4"), hc = connect_to(hi, s);
    int st = 0;
    CHECK(get_on(hc, "/secret", HRW_F, NULL, &st));
    EXPECT_EQ(st, 401);
    Sleep(100);
    EXPECT_EQ(srv_req_count(s), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_auth_manual_header_sent_verbatim, 20000) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "au/5", "GET", "/m", NULL, NULL, NULL, HRW_F, "Authorization: Bearer abc.def\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Authorization", "Bearer abc.def");
    EXPECT_NAMES(w.s, 0, "Authorization|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
GTEST(hrw_auth_options_on_request_handle, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv_call(basic_gate_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("au/6"), hc = connect_to(hi, s);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/opt", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "alice", 5));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "s3cret", 6));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    DWORD stc = 0, l = sizeof stc; U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &stc, &l, NULL);
    EXPECT_EQ(stc, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    char *b64 = srv_b64("alice:s3cret", 12); char want[64]; snprintf(want, sizeof want, "Basic %s", b64); free(b64);
    EXPECT_HDR(s, 1, "Authorization", want);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
static int proxy_gate_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int k = 0; k < 20; k++) {
        int i = srv_conn_recv_head(c);
        if (i < 0) return -1;
        if (srv_req_header(s, i, "Proxy-Authorization")) srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        else srv_conn_sendf(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"px\"\r\nContent-Length: 2\r\n\r\nno");
    }
    return -1;
}
GTEST(hrw_auth_proxy_basic, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv_call(proxy_gate_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(s, "pa/1");
    HINTERNET hc = U(InternetConnectA)(hi, "wire.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/p", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "pu", 2));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "pp", 2));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    DWORD stc = 0, l = sizeof stc; U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &stc, &l, NULL);
    EXPECT_EQ(stc, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NOHDR(s, 0, "Proxy-Authorization");
    EXPECT_HDR(s, 1, "Proxy-Authorization", "Basic cHU6cHA=");
    EXPECT_NOHDR(s, 1, "Authorization");
    EXPECT_NAMES(s, 1, "User-Agent|Host|Pragma|Proxy-Connection|Proxy-Authorization");
    hrw_dump(s, 0);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ cache revalidation */
static int cache_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int k = 0; k < 20; k++) {
        int i = srv_conn_recv_head(c);
        if (i < 0) return -1;
        if (srv_req_header(s, i, "If-None-Match") || srv_req_header(s, i, "If-Modified-Since"))
            srv_conn_sendf(c, "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n");
        else
            srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nLast-Modified: Mon, 01 Jan 2018 00:00:00 GMT\r\nETag: \"v1\"\r\nCache-Control: max-age=0\r\nContent-Length: 6\r\n\r\ncached");
    }
    return -1;
}
GTEST(hrw_cache_revalidate_conditional_headers, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(DeleteUrlCacheEntryA));
    srv *s = hrw_srv_call(cache_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    char path[128]; snprintf(path, sizeof path, "/%s.txt", t_uniq("cache"));
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1:%u%s", srv_port(s), path);
    t_cache_track(url);
    HINTERNET hi = t_inet_open("ca/1"), hc = connect_to(hi, s);
    int st = 0;
    DWORD f = INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
    CHECK(get_on(hc, path, f, NULL, &st)); EXPECT_EQ(st, 200);
    CHECK(get_on(hc, path, f | INTERNET_FLAG_RESYNCHRONIZE, NULL, &st));
    t_note("revalidation status seen by caller: %d, requests=%d", st, srv_req_count(s));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NOHDR(s, 0, "If-None-Match");
    EXPECT_NOHDR(s, 0, "If-Modified-Since");
    EXPECT_HDR(s, 1, "If-None-Match", "\"v1\"");
    EXPECT_HDR(s, 1, "If-Modified-Since", "Mon, 01 Jan 2018 00:00:00 GMT");
    EXPECT_NAMES(s, 1, "User-Agent|Host|If-Modified-Since|If-None-Match");
    EXPECT_EQ(st, 200);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
GTEST(hrw_cache_reload_skips_conditionals, 20000) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(DeleteUrlCacheEntryA));
    srv *s = hrw_srv_call(cache_fn, NULL); if (!s) { t_skip("server unavailable"); return; }
    char path[128]; snprintf(path, sizeof path, "/%s.txt", t_uniq("cache2"));
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1:%u%s", srv_port(s), path);
    t_cache_track(url);
    HINTERNET hi = t_inet_open("ca/2"), hc = connect_to(hi, s);
    int st = 0;
    DWORD f = INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
    CHECK(get_on(hc, path, f, NULL, &st));
    CHECK(get_on(hc, path, f | INTERNET_FLAG_RELOAD, NULL, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_NOHDR(s, 1, "If-None-Match");
    EXPECT_NOHDR(s, 1, "If-Modified-Since");
    EXPECT_HDR(s, 1, "Cache-Control", "no-cache");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    if (hrw_trace) t_note("trace: cleanup");
    t_net_cleanup();
    if (hrw_trace) t_note("trace: cleanup done");
}
