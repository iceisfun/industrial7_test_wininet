/* proxy_connectivity: a scripted forward proxy on loopback. What the CLIENT sends to a CERN-style proxy
 * (absolute-URI request line, Host, proxy headers, Proxy-Authorization after 407), per-scheme proxy lists,
 * bypass lists, and CONNECT tunnelling for https (raw relay in pc_util.c -> loopback schannel server).
 * Origin hosts are *.invalid names: when a request reaches the proxy it never needs DNS, and when it bypasses the
 * proxy it fails at once with ERROR_INTERNET_NAME_NOT_RESOLVED (the guest has no DNS, 04 F5). That makes
 * "proxied vs direct" observable without any network.
 * VM_TIMEOUT: 300 */
#include "pc.h"
#include <stdlib.h>

static const srv_step k_proxy_ok[] = { S_HEAD(), S_BODY(), S_REPLY(200, "Content-Type: text/plain\r\n", "proxied"), S_CLOSE_IF_ASKED(), S_LOOP() };
static const srv_step k_origin_ok[] = { S_HEAD(), S_BODY(), S_REPLY(200, "Content-Type: text/plain\r\n", "direct"), S_CLOSE_IF_ASKED(), S_LOOP() };

static srv *start_proxy(void) { return srv_http(k_proxy_ok, (int)(sizeof k_proxy_ok / sizeof k_proxy_ok[0])); }
#define PROXY_OR_SKIP(p) srv *p = start_proxy(); if (!p) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }

/* ------------------------------------------------------------------ absolute-URI request line */
TEST(pc_wire_absolute_uri_openurl) {
    REQUIRE(U(InternetOpenUrlA));
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    CHECK(h != NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-origin.invalid/path/x.txt?q=1&r=2", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "proxied");
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-origin.invalid/path/x.txt?q=1&r=2 HTTP/1.1");
    EXPECT_STR(srv_req_target(p, 0), "http://pc-origin.invalid/path/x.txt?q=1&r=2");
    EXPECT_STR(srv_req_header(p, 0, "Host"), "pc-origin.invalid");
    EXPECT_STR(srv_req_header(p, 0, "User-Agent"), "pc_agent");
    /* Win10 proxied GET (InternetOpenUrl + RELOAD/PRAGMA_NOCACHE): User-Agent, Host, Pragma: no-cache - nothing else;
     * no Proxy-Connection (unlike CONNECT) and no Cache-Control (unlike the direct request, 04 F12) */
    EXPECT_STR(srv_req_header(p, 0, "Pragma"), "no-cache");
    EXPECT_EQ(srv_req_header(p, 0, "Proxy-Connection"), NULL);
    EXPECT_EQ(srv_req_header(p, 0, "Connection"), NULL);
    EXPECT_EQ(srv_req_header(p, 0, "Cache-Control"), NULL);
    EXPECT_EQ(srv_req_header_count(p, 0), 3);
    EXPECT_STR(srv_req_header_name(p, 0, 0), "User-Agent");
    EXPECT_STR(srv_req_header_name(p, 0, 1), "Host");
    EXPECT_STR(srv_req_header_name(p, 0, 2), "Pragma");
    pc_note_req(p, 0);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_absolute_uri_nondefault_port) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-origin.invalid:8080/p", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-origin.invalid:8080/p HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 0, "Host"), "pc-origin.invalid:8080");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_absolute_uri_explicit_port_80) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-origin.invalid:80/p80", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    t_note("explicit :80 -> %s / Host %s", srv_req_line(p, 0), srv_req_header(p, 0, "Host"));
    EXPECT_STR(srv_req_header(p, 0, "Host"), "pc-origin.invalid");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_absolute_uri_httpopenrequest) {
    REQUIRE(U(HttpOpenRequestA));
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.body = body; o.cap = sizeof body;
    EXPECT_EQ(pc_request(h, "pc-origin.invalid", INTERNET_DEFAULT_HTTP_PORT, "/req?x=1", &o, &err), 200);
    EXPECT_STR(body, "proxied");
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-origin.invalid/req?x=1 HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 0, "Host"), "pc-origin.invalid");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_absolute_uri_ip_literal_origin_with_loopback_override) {
    PROXY_OR_SKIP(p);
    /* an IP-literal origin that is not loopback-bypassed: 192.0.2.1 (TEST-NET-1) is never contacted, the proxy answers */
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://192.0.2.1:81/ip", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://192.0.2.1:81/ip HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 0, "Host"), "192.0.2.1:81");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_post_through_proxy) {
    REQUIRE(U(HttpSendRequestA));
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/form", NULL, NULL, NULL, T_INET_FRESH, 0);
    static const char data[] = "a=1&b=2";
    static const char hdr[] = "Content-Type: application/x-www-form-urlencoded\r\n";
    CHECK(U(HttpSendRequestA)(hr, hdr, (DWORD)-1, (void *)data, sizeof data - 1));
    DWORD st = 0, l = sizeof st;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL));
    EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "POST http://pc-origin.invalid/form HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 0, "Content-Length"), "7");
    size_t n; const char *b = srv_req_body(p, 0, &n);
    CHECK(b && n == 7 && !memcmp(b, data, 7));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_head_verb_through_proxy) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; pc_req_opt o = { 0 }; o.verb = "HEAD";
    EXPECT_EQ(pc_request(h, "pc-origin.invalid", 80, "/h", &o, &err), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "HEAD http://pc-origin.invalid/h HTTP/1.1");
    t_inet_close(h); srv_stop(p);
}

/* record the full header set once (promoted facts get their own tests below) */
TEST(pc_wire_header_set_note) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-hdrs.invalid/hdrs", 0, body, sizeof body, &err, NULL), 200);
    DWORD e2; pc_req_opt o = { 0 };
    EXPECT_EQ(pc_request(h, "pc-hdrs.invalid", 80, "/hdrs2", &o, &e2), 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    for (int i = 0; i < srv_req_count(p); i++) pc_note_req(p, i);
    t_note("requests %d conns %d", srv_req_count(p), srv_conn_count(p));
    srv_dump(p);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_no_proxy_authorization_without_challenge) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; pc_req_opt o = { 0 }; o.proxy_user = "puser"; o.proxy_pass = "ppass";
    EXPECT_EQ(pc_request(h, "pc-pre.invalid", 80, "/pre", &o, &err), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    t_note("Proxy-Authorization before any challenge: %s", srv_req_header(p, 0, "Proxy-Authorization") ? srv_req_header(p, 0, "Proxy-Authorization") : "(none)");
    EXPECT_EQ(srv_req_header(p, 0, "Proxy-Authorization"), NULL);
    EXPECT_EQ(srv_req_header(p, 0, "Authorization"), NULL);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_proxy_keepalive_reuse) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-one.invalid/1", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_EQ(pc_get(h, "http://pc-one.invalid/2", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_EQ(pc_get(h, "http://pc-two.invalid/3", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 3, 3000));
    int n = srv_req_count(p);
    t_note("proxy connections %d for 3 InternetOpenUrl calls, %d requests", srv_conn_count(p), n);
    for (int i = 0; i < n; i++) t_note("  req %d conn %d: %s", i, srv_req_conn(p, i), srv_req_line(p, i));
    srv_dump(p);
    EXPECT_EQ(srv_conn_count(p), 1);              /* one keep-alive connection to the proxy serves both origins */
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-one.invalid/1 HTTP/1.1");
    EXPECT_STR(srv_req_line(p, n - 1), "GET http://pc-two.invalid/3 HTTP/1.1");
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ 407 / proxy credentials */
static const srv_step k_407_then_200[] = {
    S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"pc\"\r\n", "need proxy auth"),
    S_HEAD(), S_REPLY(200, NULL, "granted"), S_LOOP_TO(2) };

TEST(pc_wire_407_basic_with_proxy_creds) {
    HTTP_OR_SKIP(p, k_407_then_200);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.proxy_user = "puser"; o.proxy_pass = "ppass"; o.body = body; o.cap = sizeof body;
    int st = pc_request(h, "pc-p407.invalid", 80, "/auth", &o, &err);
    t_note("407 with creds -> status %d err %lu body \"%s\" requests %d", st, err, body, srv_req_count(p));
    EXPECT_EQ(st, 200);
    EXPECT_STR(body, "granted");
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_EQ(srv_req_header(p, 0, "Proxy-Authorization"), NULL);
    char *b64 = srv_b64("puser:ppass", 11); char want[128]; snprintf(want, sizeof want, "Basic %s", b64); free(b64);
    EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), want);
    EXPECT_EQ(srv_req_header(p, 1, "Authorization"), NULL);
    EXPECT_STR(srv_req_line(p, 1), "GET http://pc-p407.invalid/auth HTTP/1.1");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_407_without_creds_returned_to_caller) {
    static const srv_step st407[] = { S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"pc\"\r\n", "need proxy auth"), S_LOOP() };
    HTTP_OR_SKIP(p, st407);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.body = body; o.cap = sizeof body;
    int st = pc_request(h, "pc-origin.invalid", 80, "/noauth", &o, &err);
    EXPECT_EQ(st, 407);
    EXPECT_EQ(err, 0);
    EXPECT_STR(body, "need proxy auth");
    EXPECT_EQ(srv_req_count(p), 1);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_407_query_proxy_authenticate) {
    static const srv_step st407[] = { S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"pcrealm\"\r\n", ""), S_LOOP() };
    HTTP_OR_SKIP(p, st407);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char v[128]; DWORD l = sizeof v;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_PROXY_AUTHENTICATE, v, &l, NULL));
    EXPECT_STR(v, "Basic realm=\"pcrealm\"");
    l = sizeof v; SetLastError(0xdeadbeef);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_WWW_AUTHENTICATE, v, &l, NULL));
    EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_407_creds_set_after_challenge_resend) {
    HTTP_OR_SKIP(p, k_407_then_200);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/late", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    DWORD st = 0, l = sizeof st;
    U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
    EXPECT_EQ(st, 407);
    char sink[64]; DWORD rd; while (U(InternetReadFile)(hr, sink, sizeof sink, &rd) && rd) {}
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "late", 5));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "pw", 3));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    st = 0; l = sizeof st;
    U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
    EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    char *b64 = srv_b64("late:pw", 7); char want[64]; snprintf(want, sizeof want, "Basic %s", b64); free(b64);
    EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), want);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

/* origin 401 through a proxy: the Authorization header (not Proxy-Authorization) carries InternetConnect's credentials */
TEST(pc_wire_origin_401_through_proxy) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"o\"\r\n", "no"),
                                   S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-o401.invalid", 80, "ouser", "opass", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/o", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    DWORD code = 0, l = sizeof code;
    U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &l, NULL);
    EXPECT_EQ(code, 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    char *b64 = srv_b64("ouser:opass", 11); char want[64]; snprintf(want, sizeof want, "Basic %s", b64); free(b64);
    EXPECT_STR(srv_req_header(p, 1, "Authorization"), want);
    EXPECT_EQ(srv_req_header(p, 1, "Proxy-Authorization"), NULL);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

/* Win10: Basic credentials that succeeded for host X are cached process-wide and sent pre-emptively by a NEW session
 * to the same host (observed through a proxy: later requests to that origin carried Authorization without a 401). */
TEST(pc_wire_origin_basic_creds_cached_across_sessions) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"c\"\r\n", "no"),
                                   S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    const char *host = t_uniq_host("cc");
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, host, 80, "cuser", "cpass", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/first", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h);
    CHECK(srv_wait_requests(p, 2, 3000));
    int n0 = srv_req_count(p);
    HINTERNET h2 = pc_open_proxy(srv_hostport(p), NULL);
    char url[256]; snprintf(url, sizeof url, "http://%s/second", host);
    char body[16]; DWORD err;
    EXPECT_EQ(pc_get(h2, url, 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, n0 + 1, 3000));
    char *b64 = srv_b64("cuser:cpass", 11); char want[64]; snprintf(want, sizeof want, "Basic %s", b64); free(b64);
    EXPECT_STR(srv_req_header(p, n0, "Authorization"), want);
    /* a different host gets nothing */
    snprintf(url, sizeof url, "http://%s/other", t_uniq_host("cc2"));
    int n1 = srv_req_count(p);
    EXPECT_EQ(pc_get(h2, url, 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, n1 + 1, 3000));
    EXPECT_EQ(srv_req_header(p, n1, "Authorization"), NULL);
    t_inet_close(h2); srv_stop(p);
}

/* ------------------------------------------------------------------ proxy list syntax and per-scheme selection */
typedef struct { const char *proxy_fmt; const char *url; int proxied; int certain; } scheme_case;
TEST(pc_wire_proxy_list_syntax) {
    PROXY_OR_SKIP(p);
    static const scheme_case t[] = {
        { "%s", "http://pc-s1.invalid/a", 1, 1 },
        { "http=%s", "http://pc-s2.invalid/a", 1, 1 },
        { "HTTP=%s", "http://pc-s3.invalid/a", 1, 1 },
        { "http://%s", "http://pc-s4.invalid/a", 1, 1 },
        { "http=http://%s", "http://pc-s5.invalid/a", 1, 1 },
        { "https=%s", "http://pc-s6.invalid/a", 0, 1 },
        { "ftp=%s", "http://pc-s7.invalid/a", 0, 1 },
        { "http=%s;https=127.0.0.1:1", "http://pc-s8.invalid/a", 1, 1 },
        { "https=127.0.0.1:1;http=%s", "http://pc-s9.invalid/a", 1, 1 },
        { "https=127.0.0.1:1 http=%s", "http://pc-s10.invalid/a", 1, 1 },
        { "socks=%s", "http://pc-s11.invalid/a", 0, 1 },
        { "  %s  ", "http://pc-s12.invalid/a", 1, 1 },
        { "http=%s;", "http://pc-s13.invalid/a", 1, 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char proxy[128]; snprintf(proxy, sizeof proxy, t[i].proxy_fmt, srv_hostport(p));
        HINTERNET h = pc_open_proxy(proxy, NULL);
        if (!h) { CHECKF(0, "open \"%s\" failed %lu", proxy, GetLastError()); continue; }
        int before = srv_req_count(p);
        char body[64]; DWORD err; DWORD ms;
        int st = pc_get(h, t[i].url, 0, body, sizeof body, &err, &ms);
        int via = srv_req_count(p) > before;
        t_note("proxy \"%s\" %s -> status %d err %lu (%s) via-proxy %d %lu ms", proxy, t[i].url, st, err, t_inet_errname(err), via, ms);
        if (t[i].certain) {
            if (t[i].proxied) { CHECKF(st == 200 && via, "\"%s\": expected via proxy (st %d err %lu)", proxy, st, err); }
            else { CHECKF(st == 0 && !via && err == ERROR_INTERNET_NAME_NOT_RESOLVED, "\"%s\": expected direct (st %d err %lu)", proxy, st, err); }
        }
        t_inet_close(h);
    }
    srv_stop(p);
}

/* ------------------------------------------------------------------ bypass lists */
typedef struct { const char *bypass; const char *url; int proxied; int certain; } bypass_case;
TEST(pc_wire_bypass_table) {
    PROXY_OR_SKIP(p);
    static const bypass_case t[] = {
        { NULL, "http://pc-b.invalid/x", 1, 1 },
        { "", "http://pc-b.invalid/x", 1, 1 },
        { "<local>", "http://pc-b.invalid/x", 1, 1 },
        { "<local>", "http://pcbplain/x", 0, 1 },
        { NULL, "http://pcbplain/x", 1, 1 },
        { "*.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "pc-b.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "pc-b.invalid", "http://pc-c.invalid/x", 1, 1 },
        { "PC-B.INVALID", "http://pc-b.invalid/x", 0, 1 },
        { "pc-*", "http://pc-b.invalid/x", 0, 1 },
        { "*b.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "*c.invalid", "http://pc-b.invalid/x", 1, 1 },
        { "pc-?.invalid", "http://pc-b.invalid/x", 1, 1 },          /* no ? wildcard */
        { "a.invalid;pc-b.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "a.invalid pc-b.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "a.invalid,pc-b.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "*", "http://pc-b.invalid/x", 0, 1 },
        { "<-loopback>", "http://pc-b.invalid/x", 1, 1 },
        { "http://pc-b.invalid", "http://pc-b.invalid/x", 0, 1 },
        { "https://pc-b.invalid", "http://pc-b.invalid/x", 1, 1 },
        { "pc-b.invalid:8080", "http://pc-b.invalid:8080/x", 0, 1 },
        { "pc-b.invalid:8080", "http://pc-b.invalid/x", 1, 1 },
        { "pc-b", "http://pc-b.invalid/x", 1, 1 },
        { "invalid", "http://pc-b.invalid/x", 1, 1 },
        { "*.pc-b.invalid", "http://pc-b.invalid/x", 1, 1 },
        { "*.pc-b.invalid", "http://www.pc-b.invalid/x", 0, 1 },
        { "192.0.2.*", "http://192.0.2.7/x", 0, 1 },
        { "192.0.2.7", "http://192.0.2.7/x", 0, 1 },
        { "192.0.2.8", "http://192.0.2.7/x", 1, 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), t[i].bypass, 3000);
        if (!h) { CHECKF(0, "open bypass \"%s\" failed %lu", t[i].bypass ? t[i].bypass : "(null)", GetLastError()); continue; }
        int before = srv_req_count(p);
        char body[64]; DWORD err, ms;
        int st = pc_get(h, t[i].url, 0, body, sizeof body, &err, &ms);
        int via = srv_req_count(p) > before;
        t_note("bypass \"%s\" %s -> status %d err %lu (%s) via-proxy %d %lu ms", t[i].bypass ? t[i].bypass : "(null)", t[i].url, st, err,
               t_inet_errname(err), via, ms);
        if (t[i].certain) {
            const int is_ip = strstr(t[i].url, "192.0.2.") != NULL;
            if (t[i].proxied) CHECKF(st == 200 && via, "bypass \"%s\" %s: expected via proxy (st %d err %lu)", t[i].bypass ? t[i].bypass : "(null)", t[i].url, st, err);
            else if (is_ip) CHECKF(!via, "bypass \"%s\" %s: expected direct (st %d err %lu)", t[i].bypass, t[i].url, st, err);
            else CHECKF(st == 0 && !via && err == ERROR_INTERNET_NAME_NOT_RESOLVED, "bypass \"%s\" %s: expected direct (st %d err %lu)",
                        t[i].bypass ? t[i].bypass : "(null)", t[i].url, st, err);
        }
        t_inet_close(h);
    }
    /* CIDR notation is rejected when the session is opened */
    SetLastError(0xdeadbeef);
    HINTERNET hb = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), "192.0.2.0/24", 0);
    CHECK(hb == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (hb) U(InternetCloseHandle)(hb);
    srv_stop(p);
}

/* Loopback origins and a named proxy: are 127.0.0.1 / localhost / [::1] bypassed without being listed? */
TEST(pc_wire_loopback_implicit_bypass) {
    PROXY_OR_SKIP(p);
    srv *o = srv_http(k_origin_ok, (int)(sizeof k_origin_ok / sizeof k_origin_ok[0]));
    if (!o) { srv_stop(p); t_skip("origin unavailable"); return; }
    static const struct { const char *bypass; const char *host; int proxied; int certain; } t[] = {
        { NULL, "127.0.0.1", 0, 1 }, { NULL, "localhost", 0, 1 }, { NULL, "[::1]", 0, 1 },
        { "<-loopback>", "127.0.0.1", 1, 1 }, { "<-loopback>", "localhost", 1, 1 },
        { "<local>", "127.0.0.1", 0, 1 }, { "<local>;<-loopback>", "127.0.0.1", 1, 1 }, { "127.0.0.1", "127.0.0.1", 0, 1 },
        { "<-LOOPBACK>", "127.0.0.1", 1, 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), t[i].bypass, 3000);
        if (!h) { CHECK(0); continue; }
        int pb = srv_req_count(p), ob = srv_req_count(o);
        char body[64]; DWORD err, ms;
        int st = pc_get(h, srv_url_host(o, t[i].host, "/lb"), 0, body, sizeof body, &err, &ms);
        int via = srv_req_count(p) > pb, dir = srv_req_count(o) > ob;
        t_note("loopback bypass \"%s\" host %s -> status %d body \"%s\" proxy %d origin %d err %lu %lu ms", t[i].bypass ? t[i].bypass : "(null)",
               t[i].host, st, body, via, dir, err, ms);
        EXPECT_EQ(st, 200);
        if (t[i].certain) {
            if (t[i].proxied) { CHECKF(via && !dir, "\"%s\" %s: expected proxied", t[i].bypass ? t[i].bypass : "(null)", t[i].host); EXPECT_STR(body, "proxied"); }
            else { CHECKF(dir && !via, "\"%s\" %s: expected direct", t[i].bypass ? t[i].bypass : "(null)", t[i].host); EXPECT_STR(body, "direct"); }
        }
        if (via) {
            int last = srv_req_count(p) - 1;
            t_note("  proxied line: %s", srv_req_line(p, last));
        }
        t_inet_close(h);
    }
    srv_stop(o); srv_stop(p);
}

TEST(pc_wire_loopback_override_request_line) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), "<-loopback>", 3000);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://127.0.0.1:9/lbo", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "proxied");
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://127.0.0.1:9/lbo HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 0, "Host"), "127.0.0.1:9");
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ switching a session's proxy */
TEST(pc_wire_set_proxy_option_routes_session) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-sw.invalid/a", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)srv_hostport(p), NULL };
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    EXPECT_EQ(pc_get(h, "http://pc-sw.invalid/b", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "proxied");
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-sw.invalid/b HTTP/1.1");
    pi.dwAccessType = INTERNET_OPEN_TYPE_DIRECT; pi.lpszProxy = NULL;
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    Sleep(100);
    int n = srv_req_count(p);
    EXPECT_EQ(pc_get(h, "http://pc-sw.invalid/c", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    Sleep(100);
    EXPECT_EQ(srv_req_count(p), n);
    for (int i = 0; i < srv_req_count(p); i++) t_note("  req %d conn %d: %s", i, srv_req_conn(p, i), srv_req_line(p, i));
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire_set_proxy_bypass_option) {
    PROXY_OR_SKIP(p);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)srv_hostport(p), (LPCTSTR)"pc-byp.invalid" };
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-byp.invalid/a", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    EXPECT_EQ(srv_req_count(p), 0);
    EXPECT_EQ(pc_get(h, "http://pc-nobyp.invalid/a", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_req_count(p) >= 1);
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-nobyp.invalid/a HTTP/1.1");
    t_inet_close(h); srv_stop(p);
}

/* ftp:// URLs through a CERN proxy are sent as an HTTP GET with the ftp URL */
TEST(pc_wire_ftp_url_via_cern_proxy) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\n", "ftp-via-proxy"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err; DWORD ms;
    HINTERNET hu = U(InternetOpenUrlA)(h, "ftp://pc-ftp.invalid/pub/file.txt", NULL, 0, T_INET_FRESH | INTERNET_FLAG_PASSIVE, 0);
    err = hu ? 0 : GetLastError();
    t_note("ftp via proxy: handle %p err %lu (%s) requests %d", hu, err, t_inet_errname(err), srv_req_count(p));
    if (hu) {
        int ok; size_t n = t_inet_read_all(hu, body, sizeof body, &ok);
        t_note("ftp via proxy body \"%s\" n=%zu", body, n);
        EXPECT_STR(body, "ftp-via-proxy");
        DWORD ty = 0, l = sizeof ty; CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_HANDLE_TYPE, &ty, &l));
        EXPECT_EQ(ty, INTERNET_HANDLE_TYPE_HTTP_REQUEST);   /* an ftp URL through a CERN proxy is an HTTP request handle */
        U(InternetCloseHandle)(hu);
    }
    CHECK(hu != NULL);
    CHECK(srv_req_count(p) >= 1);
    if (srv_req_count(p)) {
        pc_note_req(p, 0);
        EXPECT_STR(srv_req_line(p, 0), "GET ftp://pc-ftp.invalid/pub/file.txt HTTP/1.1");
        EXPECT_STR(srv_req_header(p, 0, "Host"), "pc-ftp.invalid:21");   /* the ftp default port is spelled out */
        EXPECT_STR(srv_req_header(p, 0, "User-Agent"), "pc_agent");
    }
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ HTTPS through the proxy: CONNECT */
static const srv_step k_tls_ok[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\n", "tunnelled"), S_CLOSE_IF_ASKED(), S_LOOP() };

typedef struct { srv *tls; pc_relay *r; HINTERNET h; } tunnel_env;
static int tunnel_setup(tunnel_env *e, const char *const *replies, int n, const char *bypass) {
    memset(e, 0, sizeof *e);
    e->tls = srv_https(k_tls_ok, (int)(sizeof k_tls_ok / sizeof k_tls_ok[0]), SRV_CERT_LOCALHOST);
    if (!e->tls) return 0;
    e->r = pc_relay_start(replies, n, srv_port(e->tls));
    if (!e->r) { srv_stop(e->tls); return 0; }
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", pc_relay_port(e->r));
    e->h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, px, bypass, 5000);
    return e->h != NULL;
}
static void tunnel_done(tunnel_env *e) { t_inet_close(e->h); pc_relay_stop(e->r); srv_stop(e->tls); }
#define TUNNEL_OR_SKIP(e, rep, n, byp) tunnel_env e; if (!tunnel_setup(&e, rep, n, byp)) { t_skip("tunnel setup failed (https server: %s)", srv_strerror(srv_last_error())); return; }

static const char *const k_connect_ok[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };

TEST(pc_wire_connect_tunnel_https) {
    REQUIRE(U(HttpSendRequestA));
    TUNNEL_OR_SKIP(e, k_connect_ok, 1, NULL);
    DWORD err, ms; char body[64]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body; o.ms = &ms;
    int st = pc_request(e.h, "pc-tls.invalid", INTERNET_DEFAULT_HTTPS_PORT, "/s?x=1", &o, &err);
    t_note("CONNECT tunnel: status %d err %lu (%s) %lu ms heads %d tunnel bytes %ld", st, err, t_inet_errname(err), ms, pc_relay_heads(e.r), pc_relay_tunnel_bytes(e.r));
    EXPECT_EQ(st, 200);
    EXPECT_STR(body, "tunnelled");
    CHECK(pc_relay_wait_heads(e.r, 1, 3000));
    const char *hd = pc_relay_head(e.r, 0);
    EXPECT_STR(pc_head_line(hd), "CONNECT pc-tls.invalid:443 HTTP/1.0");
    EXPECT_STR(pc_head_header(hd, "Host"), "pc-tls.invalid:443");
    EXPECT_STR(pc_head_header(hd, "User-Agent"), "pc_agent");
    /* Win10: CONNECT is HTTP/1.0 with exactly User-Agent, Host, Content-Length: 0, Proxy-Connection: Keep-Alive, Pragma: no-cache */
    EXPECT_STR(pc_head_header(hd, "Content-Length"), "0");
    EXPECT_STR(pc_head_header(hd, "Proxy-Connection"), "Keep-Alive");
    EXPECT_STR(pc_head_header(hd, "Pragma"), "no-cache");
    EXPECT_EQ(pc_head_header(hd, "Connection"), NULL);
    EXPECT_EQ(pc_head_header(hd, "Proxy-Authorization"), NULL);
    if (hd) {
        const char *ua = strstr(hd, "\r\nUser-Agent:"), *ho = strstr(hd, "\r\nHost:"), *cl = strstr(hd, "\r\nContent-Length:"),
                   *pcn = strstr(hd, "\r\nProxy-Connection:"), *pr = strstr(hd, "\r\nPragma:");
        CHECK(ua && ho && cl && pcn && pr && ua < ho && ho < cl && cl < pcn && pcn < pr);
        int lines = 0; for (const char *q = hd; (q = strstr(q, "\r\n")); q += 2) lines++;
        EXPECT_EQ(lines, 7);   /* request line + 5 headers + empty line */
    }
    /* inside the tunnel the request is origin-form with the origin's Host */
    CHECK(srv_wait_requests(e.tls, 1, 3000));
    EXPECT_STR(srv_req_line(e.tls, 0), "GET /s?x=1 HTTP/1.1");
    EXPECT_STR(srv_req_header(e.tls, 0, "Host"), "pc-tls.invalid");
    EXPECT_EQ(srv_req_header(e.tls, 0, "Proxy-Connection"), NULL);
    EXPECT_EQ(srv_req_header(e.tls, 0, "Proxy-Authorization"), NULL);
    CHECK(pc_relay_tunnel_bytes(e.r) > 0);
    tunnel_done(&e);
}

TEST(pc_wire_connect_tunnel_nondefault_port) {
    TUNNEL_OR_SKIP(e, k_connect_ok, 1, NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    EXPECT_EQ(pc_request(e.h, "pc-tls.invalid", 8443, "/p", &o, &err), 200);
    CHECK(pc_relay_wait_heads(e.r, 1, 3000));
    EXPECT_STR(pc_head_line(pc_relay_head(e.r, 0)), "CONNECT pc-tls.invalid:8443 HTTP/1.0");
    EXPECT_STR(pc_head_header(pc_relay_head(e.r, 0), "Host"), "pc-tls.invalid:8443");
    CHECK(srv_wait_requests(e.tls, 1, 3000));
    EXPECT_STR(srv_req_header(e.tls, 0, "Host"), "pc-tls.invalid:8443");
    tunnel_done(&e);
}

TEST(pc_wire_connect_tunnel_openurl) {
    TUNNEL_OR_SKIP(e, k_connect_ok, 1, NULL);
    /* InternetOpenUrl cannot set ignore flags before the send: expect the certificate error, after a CONNECT */
    char body[64]; DWORD err;
    int st = pc_get(e.h, "https://pc-tls.invalid/u", 0, body, sizeof body, &err, NULL);
    t_note("openurl https via proxy: status %d err %lu (%s)", st, err, t_inet_errname(err));
    CHECK(pc_relay_wait_heads(e.r, 1, 3000));
    EXPECT_STR(pc_head_line(pc_relay_head(e.r, 0)), "CONNECT pc-tls.invalid:443 HTTP/1.0");
    EXPECT_EQ(st, 0);
    CHECK(err == ERROR_INTERNET_INVALID_CA || err == ERROR_INTERNET_SEC_CERT_CN_INVALID || err == ERROR_INTERNET_SEC_INVALID_CERT);
    tunnel_done(&e);
}

TEST(pc_wire_connect_https_only_proxy_entry) {
    tunnel_env e; memset(&e, 0, sizeof e);
    e.tls = srv_https(k_tls_ok, (int)(sizeof k_tls_ok / sizeof k_tls_ok[0]), SRV_CERT_LOCALHOST);
    if (!e.tls) { t_skip("https server unavailable"); return; }
    e.r = pc_relay_start(k_connect_ok, 1, srv_port(e.tls));
    if (!e.r) { srv_stop(e.tls); t_skip("relay"); return; }
    char px[96]; snprintf(px, sizeof px, "https=127.0.0.1:%u", pc_relay_port(e.r));
    e.h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, px, NULL, 5000);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    EXPECT_EQ(pc_request(e.h, "pc-tls.invalid", 443, "/only", &o, &err), 200);
    CHECK(pc_relay_heads(e.r) >= 1);
    for (int i = 0; i < pc_relay_heads(e.r); i++) t_note("https-only proxy head %d: %s", i, pc_head_line(pc_relay_head(e.r, i)));
    EXPECT_STR(pc_head_line(pc_relay_head(e.r, 0)), "CONNECT pc-tls.invalid:443 HTTP/1.0");
    int heads_before = pc_relay_heads(e.r);
    /* plain http with an https-only proxy list goes direct */
    char b2[32]; DWORD e2;
    EXPECT_EQ(pc_get(e.h, "http://pc-tls.invalid/plain", 0, b2, sizeof b2, &e2, NULL), 0);
    EXPECT_EQ(e2, ERROR_INTERNET_NAME_NOT_RESOLVED);
    EXPECT_EQ(pc_relay_heads(e.r), heads_before);
    tunnel_done(&e);
}

TEST(pc_wire_connect_407_then_200_with_creds) {
    static const char *const rep[] = {
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"tun\"\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\n\r\n" };
    TUNNEL_OR_SKIP(e, rep, 2, NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    o.proxy_user = "tuser"; o.proxy_pass = "tpass";
    int st = pc_request(e.h, "pc-tls.invalid", 443, "/a", &o, &err);
    t_note("CONNECT 407->200: status %d err %lu heads %d conns %d", st, err, pc_relay_heads(e.r), pc_relay_conns(e.r));
    EXPECT_EQ(st, 200);
    EXPECT_STR(body, "tunnelled");
    CHECK(pc_relay_wait_heads(e.r, 2, 3000));
    EXPECT_EQ(pc_head_header(pc_relay_head(e.r, 0), "Proxy-Authorization"), NULL);
    char *b64 = srv_b64("tuser:tpass", 11); char want[64]; snprintf(want, sizeof want, "Basic %s", b64); free(b64);
    EXPECT_STR(pc_head_header(pc_relay_head(e.r, 1), "Proxy-Authorization"), want);
    EXPECT_STR(pc_head_line(pc_relay_head(e.r, 1)), "CONNECT pc-tls.invalid:443 HTTP/1.0");
    if (srv_wait_requests(e.tls, 1, 3000)) EXPECT_EQ(srv_req_header(e.tls, 0, "Proxy-Authorization"), NULL);
    tunnel_done(&e);
}

TEST(pc_wire_connect_407_without_creds) {
    static const char *const rep[] = {
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"tun\"\r\nContent-Length: 4\r\n\r\nnope" };
    TUNNEL_OR_SKIP(e, rep, 1, NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    int st = pc_request(e.h, "pc-tls.invalid", 443, "/b", &o, &err);
    t_note("CONNECT 407 no creds: status %d err %lu (%s) body \"%s\" heads %d", st, err, t_inet_errname(err), body, pc_relay_heads(e.r));
    EXPECT_EQ(st, 407);
    EXPECT_EQ(err, 0);
    EXPECT_EQ(srv_req_count(e.tls), 0);
    tunnel_done(&e);
}

TEST(pc_wire_connect_refused_403) {
    static const char *const rep[] = { "HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied" };
    TUNNEL_OR_SKIP(e, rep, 1, NULL);
    DWORD err; char body[64]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    int st = pc_request(e.h, "pc-tls.invalid", 443, "/c", &o, &err);
    t_note("CONNECT 403: status %d err %lu (%s) body \"%s\"", st, err, t_inet_errname(err), body);
    CHECK(st == 403 || (st == 0 && err != 0));
    EXPECT_EQ(srv_req_count(e.tls), 0);
    tunnel_done(&e);
}

TEST(pc_wire_connect_proxy_closes) {
    static const char *const rep[] = { "" };   /* empty reply then the relay waits for the next head; client gets EOF on stop */
    static const char *const rep_close[] = { "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" };
    (void)rep;
    TUNNEL_OR_SKIP(e, rep_close, 1, NULL);
    DWORD err; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100;
    int st = pc_request(e.h, "pc-tls.invalid", 443, "/d", &o, &err);
    t_note("CONNECT 502: status %d err %lu (%s)", st, err, t_inet_errname(err));
    CHECK(st == 502 || (st == 0 && err != 0));
    tunnel_done(&e);
}

TEST(pc_wire_connect_bypassed_https_goes_direct) {
    TUNNEL_OR_SKIP(e, k_connect_ok, 1, "*.invalid");
    DWORD err; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100;
    EXPECT_EQ(pc_request(e.h, "pc-tls.invalid", 443, "/e", &o, &err), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    EXPECT_EQ(pc_relay_heads(e.r), 0);
    tunnel_done(&e);
}
