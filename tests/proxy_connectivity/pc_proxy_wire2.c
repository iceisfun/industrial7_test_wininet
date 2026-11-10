/* proxy_connectivity: more forward-proxy wire behaviour. Redirects through a proxy, URL forms in the absolute-URI
 * request line, HTTP/1.0 requests, cookies for proxied origins, 407 persistence and retries, per-scheme proxy
 * selection for http vs https, CONNECT variants, large and whitespace-laden bypass lists, and several sessions with
 * different proxies. Origins are *.invalid (never resolved when proxied; 12007 at once when sent direct, 04 F5).
 * VM_TIMEOUT: 720 */
#include "pc.h"
#include <stdlib.h>

static const srv_step k_ok[] = { S_HEAD(), S_BODY(), S_REPLY(200, "Content-Type: text/plain\r\n", "proxied"), S_CLOSE_IF_ASKED(), S_LOOP() };
#define PROXY2_OR_SKIP(p) HTTP_OR_SKIP(p, k_ok)

static int status_of(HINTERNET hr) {
    DWORD v = 0, l = sizeof v;
    return U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL) ? (int)v : 0;
}
static void drain(HINTERNET hr) { char b[512]; DWORD rd; for (int i = 0; i < 64 && U(InternetReadFile)(hr, b, sizeof b, &rd) && rd; i++) {} }
static char *basic(const char *up) {
    static char out[4][160]; static int k; char *b64 = srv_b64(up, strlen(up)); char *o = out[k++ & 3];
    snprintf(o, 160, "Basic %s", b64); free(b64); return o;
}



/* ------------------------------------------------------------------ URL forms in the request line */
typedef struct { const char *url; const char *line; const char *host; int certain; } url_case;
TEST(pc_wire2_request_line_url_forms) {
    REQUIRE(U(InternetOpenUrlA));
    PROXY2_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    static const url_case t[] = {
        /* Win10 boot 4: the fragment is NOT stripped from the absolute URI sent to a proxy */
        { "http://pc-f.invalid/a#frag", "GET http://pc-f.invalid/a#frag HTTP/1.1", "pc-f.invalid", 1 },
        { "http://pc-f.invalid/a?q=1#frag", "GET http://pc-f.invalid/a?q=1#frag HTTP/1.1", "pc-f.invalid", 1 },
        { "http://pc-f.invalid", "GET http://pc-f.invalid/ HTTP/1.1", "pc-f.invalid", 1 },
        { "http://pc-f.invalid:8080", "GET http://pc-f.invalid:8080/ HTTP/1.1", "pc-f.invalid:8080", 1 },
        { "http://pc-f.invalid/A/B/C.TXT", "GET http://pc-f.invalid/A/B/C.TXT HTTP/1.1", "pc-f.invalid", 1 },
        { "http://PC-UPPER.INVALID/Up", NULL, NULL, 0 },
        { "http://[2001:db8::1]:8080/v6", "GET http://[2001:db8::1]:8080/v6 HTTP/1.1", "[2001:db8::1]:8080", 0 },
        { "http://[2001:db8::2]/v6", NULL, NULL, 0 },
        { "http://pc-f.invalid/a%20b", "GET http://pc-f.invalid/a%20b HTTP/1.1", "pc-f.invalid", 1 },
        { "http://pc-f.invalid/a b", NULL, NULL, 0 },
        { "http://pc-f.invalid/dir/../x", NULL, NULL, 0 },
        { "http://pc-f.invalid/x?a=b&c=d%26e", "GET http://pc-f.invalid/x?a=b&c=d%26e HTTP/1.1", "pc-f.invalid", 1 },
        { "http://user:pw@pc-f.invalid/cred", NULL, "pc-f.invalid", 0 },
        { "http://pc-f.invalid:80/eighty", "GET http://pc-f.invalid/eighty HTTP/1.1", "pc-f.invalid", 0 },
        { "http://192.0.2.9/ip", "GET http://192.0.2.9/ip HTTP/1.1", "192.0.2.9", 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        int before = srv_req_count(p);
        char body[64]; DWORD err;
        int st = pc_get(h, t[i].url, 0, body, sizeof body, &err, NULL);
        int got = srv_wait_requests(p, before + 1, 3000);
        const char *ln = got ? srv_req_line(p, before) : NULL, *ho = got ? srv_req_header(p, before, "Host") : NULL;
        t_note("OBS url %s -> st %d err %lu line \"%s\" Host \"%s\" Authorization \"%s\"", t[i].url, st, err, ln ? ln : "-", ho ? ho : "-",
               got && srv_req_header(p, before, "Authorization") ? srv_req_header(p, before, "Authorization") : "-");
        if (t[i].certain) {
            CHECKF(st == 200, "%s: status %d err %lu", t[i].url, st, err);
            if (t[i].line) CHECKF(ln && !strcmp(ln, t[i].line), "%s: line \"%s\" want \"%s\"", t[i].url, ln ? ln : "(none)", t[i].line);
            if (t[i].host) CHECKF(ho && !strcmp(ho, t[i].host), "%s: Host \"%s\" want \"%s\"", t[i].url, ho ? ho : "(none)", t[i].host);
        }
    }
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_option_url_on_proxied_request) {
    PROXY2_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-url.invalid", 8081, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/p?x=1", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    if (!hr) { t_skip("handles"); if (hc) U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p); return; }
    char u[256]; DWORD l = sizeof u;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, u, &l));
    EXPECT_STR(u, "http://pc-url.invalid:8081/p?x=1");
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(status_of(hr), 200);
    l = sizeof u; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, u, &l));
    EXPECT_STR(u, "http://pc-url.invalid:8081/p?x=1");    /* the origin URL, never the proxy */
    /* request headers as wininet records them */
    char raw[1024]; l = sizeof raw;
    BOOL ok = U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, raw, &l, NULL);
    CHECK(ok);
    if (ok) {
        char *e = strstr(raw, "\r\n"); if (e) *e = 0;
        t_note("OBS request headers first line: \"%s\"", raw);
        CHECK(!strncmp(raw, "GET ", 4));
    }
    drain(hr); U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ HTTP/1.0 and connection flags */
TEST(pc_wire2_http10_request_through_proxy) {
    PROXY2_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-10.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/ten", "HTTP/1.0", NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(status_of(hr), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    pc_note_req(p, 0);
    /* Win10 boot 4: through a proxy the request goes out as HTTP/1.1 even when HttpOpenRequest asked for HTTP/1.0 */
    t_note("OBS HttpOpenRequest(\"HTTP/1.0\") via proxy -> \"%s\"", srv_req_line(p, 0));
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-10.invalid/ten HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 0, "Host"), "pc-10.invalid");
    t_note("OBS HTTP/1.0 proxied: Proxy-Connection \"%s\" Connection \"%s\"", srv_req_header(p, 0, "Proxy-Connection") ? srv_req_header(p, 0, "Proxy-Connection") : "-",
           srv_req_header(p, 0, "Connection") ? srv_req_header(p, 0, "Connection") : "-");
    drain(hr); U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_keep_connection_flag_headers) {
    PROXY2_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; pc_req_opt o = { 0 }; o.flags = T_INET_FRESH | INTERNET_FLAG_KEEP_CONNECTION;
    EXPECT_EQ(pc_request(h, "pc-kc.invalid", 80, "/kc", &o, &err), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    pc_note_req(p, 0);
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-kc.invalid/kc HTTP/1.1");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_extra_headers_passed_verbatim) {
    PROXY2_OR_SKIP(p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; pc_req_opt o = { 0 };
    o.headers = "X-Pc-Test: one\r\nProxy-Connection: Keep-Alive\r\nx-lower: two\r\n";
    EXPECT_EQ(pc_request(h, "pc-xh.invalid", 80, "/xh", &o, &err), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    pc_note_req(p, 0);
    EXPECT_STR(srv_req_header(p, 0, "X-Pc-Test"), "one");
    EXPECT_STR(srv_req_header(p, 0, "x-lower"), "two");
    EXPECT_STR(srv_req_header(p, 0, "Proxy-Connection"), "Keep-Alive");
    EXPECT_EQ(srv_req_header_occurrences(p, 0, "Proxy-Connection"), 1);
    int idx = srv_req_header_index(p, 0, "x-lower");
    if (idx >= 0) EXPECT_STR(srv_req_header_name(p, 0, idx), "x-lower");   /* casing kept */
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_user_agent_forms) {
    PROXY2_OR_SKIP(p);
    static const char *agents[] = { "Mozilla/4.0 (compatible; pc test)", "a", "UA with  two  spaces", "" };
    for (size_t i = 0; i < sizeof agents / sizeof agents[0]; i++) {
        HINTERNET h = U(InternetOpenA)(agents[i], INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), NULL, 0);
        if (!h) { CHECK(0); continue; }
        pc_set_timeouts(h, 3000, 3000, 3000);
        int before = srv_req_count(p);
        char body[32]; DWORD err;
        EXPECT_EQ(pc_get(h, "http://pc-ua.invalid/ua", 0, body, sizeof body, &err, NULL), 200);
        if (srv_wait_requests(p, before + 1, 3000)) {
            const char *ua = srv_req_header(p, before, "User-Agent");
            t_note("OBS agent \"%s\" -> User-Agent %s%s%s", agents[i], ua ? "\"" : "", ua ? ua : "(absent)", ua ? "\"" : "");
            if (agents[i][0]) CHECKF(ua && !strcmp(ua, agents[i]), "agent \"%s\": got \"%s\"", agents[i], ua ? ua : "(absent)");
            else CHECKF(ua == NULL, "empty agent sent User-Agent \"%s\"", ua);   /* boot 5: no header at all */
        }
        U(InternetCloseHandle)(h);
    }
    srv_stop(p);
}

/* ------------------------------------------------------------------ redirects through the proxy */
TEST(pc_wire2_redirect_absolute_through_proxy) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: http://pc-dst.invalid:8082/landed?z=1\r\n", ""),
                                   S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-src.invalid/start", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "landed");
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_STR(srv_req_line(p, 0), "GET http://pc-src.invalid/start HTTP/1.1");
    EXPECT_STR(srv_req_line(p, 1), "GET http://pc-dst.invalid:8082/landed?z=1 HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 1, "Host"), "pc-dst.invalid:8082");
    pc_note_req(p, 1);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_redirect_relative_through_proxy) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(301, "Location: /moved/here\r\n", ""),
                                   S_HEAD(), S_REPLY(200, NULL, "rel"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-rel.invalid:8083/old/path", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "rel");
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_STR(srv_req_line(p, 1), "GET http://pc-rel.invalid:8083/moved/here HTTP/1.1");
    EXPECT_STR(srv_req_header(p, 1, "Host"), "pc-rel.invalid:8083");
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_redirect_to_loopback_origin_goes_direct) {
    srv *o = srv_http(k_ok, (int)(sizeof k_ok / sizeof k_ok[0]));
    if (!o) { t_skip("origin"); return; }
    static char loc[96]; snprintf(loc, sizeof loc, "Location: http://127.0.0.1:%u/at-origin\r\n", srv_port(o));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, loc }, S_HEAD(), S_REPLY(200, NULL, "should-not"), S_LOOP_TO(2) };
    srv_script sc = { st, 5 }; srv_config cfg = { SRV_HTTP, &sc, 1 }; srv *p;
    if (srv_start(&cfg, &p)) { srv_stop(o); t_skip("proxy"); return; }
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-lr.invalid/r", 0, body, sizeof body, &err, NULL), 200);
    t_note("OBS redirect to loopback: body \"%s\" proxy reqs %d origin reqs %d", body, srv_req_count(p), srv_req_count(o));
    CHECK(srv_wait_requests(o, 1, 3000));
    EXPECT_EQ(srv_req_count(p), 1);                     /* loopback is bypassed implicitly */
    EXPECT_STR(srv_req_line(o, 0), "GET /at-origin HTTP/1.1");
    t_inet_close(h); srv_stop(p); srv_stop(o);
}

TEST(pc_wire2_redirect_to_bypassed_name) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: http://pc-byp2.invalid/x\r\n", "moved"),
                                   S_HEAD(), S_REPLY(200, NULL, "not-bypassed"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), "pc-byp2.invalid", 3000);
    char body[64]; DWORD err;
    int code = pc_get(h, "http://pc-src2.invalid/", 0, body, sizeof body, &err, NULL);
    t_note("OBS redirect to bypassed host: status %d err %lu (%s) proxy reqs %d", code, err, t_inet_errname(err), srv_req_count(p));
    EXPECT_EQ(srv_req_count(p), 1);       /* the redirected request does not go to the proxy */
    EXPECT_EQ(code, 0); EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);   /* boot 5: followed directly -> DNS failure */
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_redirect_noauto_returns_302) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: http://pc-dst3.invalid/\r\n", "moved"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-src3.invalid/", T_INET_FRESH_NOREDIR, body, sizeof body, &err, NULL), 302);
    EXPECT_STR(body, "moved");
    Sleep(100);
    EXPECT_EQ(srv_req_count(p), 1);
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ cookies for proxied origins */
TEST(pc_wire2_cookie_sent_for_proxied_origin) {
    REQUIRE(U(InternetSetCookieA));
    PROXY2_OR_SKIP(p);
    const char *url = t_uniq_cookie_url("pxc");
    CHECK(U(InternetSetCookieA)(url, "pcck", "v1; expires=Fri, 01-Jan-2038 00:00:00 GMT"));
    t_cookie_track(url, "pcck");
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[32]; DWORD err;
    DWORD fl = T_INET_FRESH & ~INTERNET_FLAG_NO_COOKIES;
    EXPECT_EQ(pc_get(h, url, fl, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 1, 3000));
    EXPECT_STR(srv_req_header(p, 0, "Cookie"), "pcck=v1");
    /* NO_COOKIES suppresses it */
    EXPECT_EQ(pc_get(h, url, T_INET_FRESH, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_EQ(srv_req_header(p, 1, "Cookie"), NULL);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_set_cookie_from_proxied_response_stored_for_origin) {
    REQUIRE(U(InternetGetCookieA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Set-Cookie: pcsc=from-proxy; Path=/; expires=Fri, 01-Jan-2038 00:00:00 GMT\r\n", "c"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    const char *url = t_uniq_cookie_url("pxs");
    t_cookie_track(url, "pcsc");
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, url, T_INET_FRESH & ~INTERNET_FLAG_NO_COOKIES, body, sizeof body, &err, NULL), 200);
    char ck[256]; DWORD l = sizeof ck;
    BOOL ok = U(InternetGetCookieA)(url, NULL, ck, &l);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) EXPECT_STR(ck, "pcsc=from-proxy");
    /* not stored for the proxy's own address */
    char purl[96]; snprintf(purl, sizeof purl, "http://%s/", srv_hostport(p));
    l = sizeof ck; ok = U(InternetGetCookieA)(purl, "pcsc", ck, &l);
    CHECK(!ok || !strstr(ck, "from-proxy"));
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ 407 details */
TEST(pc_wire2_407_creds_reused_on_next_request) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"pc2\"\r\n", "need"),
                                   S_HEAD(), S_REPLY(200, NULL, "ok"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; pc_req_opt o = { 0 }; o.proxy_user = "ru"; o.proxy_pass = "rp";
    EXPECT_EQ(pc_request(h, "pc-r407.invalid", 80, "/1", &o, &err), 200);
    pc_req_opt o2 = { 0 };   /* no creds on the second request handle */
    EXPECT_EQ(pc_request(h, "pc-r407.invalid", 80, "/2", &o2, &err), 200);
    EXPECT_EQ(pc_request(h, "pc-other407.invalid", 80, "/3", &o2, &err), 200);
    CHECK(srv_wait_requests(p, 4, 3000));
    for (int i = 0; i < srv_req_count(p); i++)
        t_note("OBS req %d conn %d %s Proxy-Authorization \"%s\"", i, srv_req_conn(p, i), srv_req_line(p, i),
               srv_req_header(p, i, "Proxy-Authorization") ? srv_req_header(p, i, "Proxy-Authorization") : "-");
    EXPECT_EQ(srv_req_count(p), 4);
    EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), basic("ru:rp"));
    /* boot 5: later requests through the same proxy (same or other origin, request handles without credentials) carry
     * the cached proxy credentials pre-emptively */
    EXPECT_STR(srv_req_header(p, 2, "Proxy-Authorization"), basic("ru:rp"));
    EXPECT_STR(srv_req_header(p, 3, "Proxy-Authorization"), basic("ru:rp"));
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_407_wrong_creds_returns_407) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"pcw\"\r\n", "denied"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; char body[32]; pc_req_opt o = { 0 }; o.proxy_user = "bad"; o.proxy_pass = "creds"; o.body = body; o.cap = sizeof body;
    int code = pc_request(h, "pc-w407.invalid", 80, "/w", &o, &err);
    Sleep(100);
    t_note("OBS 407 always + creds: status %d err %lu requests %d", code, err, srv_req_count(p));
    EXPECT_EQ(code, 407);
    EXPECT_STR(body, "denied");
    EXPECT_EQ(srv_req_count(p), 2);   /* boot 5: one retry with the credentials, then the 407 is returned */
    EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), basic("bad:creds"));
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_407_connection_close_resend_on_new_connection) {
    static const srv_step c0[] = { S_HEAD(), S_REPLYF(407, "Proxy-Authenticate: Basic realm=\"cc\"\r\n", "closing", SRV_R_CONN_CLOSE) };
    static const srv_step c1[] = { S_HEAD(), S_REPLY(200, NULL, "second-conn"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(c0), SRV_SCRIPT(c1) };
    srv_config cfg = { SRV_HTTP, sc, 2 }; srv *p;
    START_OR_SKIP(&cfg, &p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; char body[32]; pc_req_opt o = { 0 }; o.proxy_user = "cu"; o.proxy_pass = "cp"; o.body = body; o.cap = sizeof body;
    EXPECT_EQ(pc_request(h, "pc-c407.invalid", 80, "/c", &o, &err), 200);
    EXPECT_STR(body, "second-conn");
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_NE(srv_req_conn(p, 0), srv_req_conn(p, 1));
    EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), basic("cu:cp"));
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_407_creds_on_connect_handle) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"ch\"\r\n", ""),
                                   S_HEAD(), S_REPLY(200, NULL, "ok"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-ch407.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PROXY_USERNAME, "chu", 4));
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PROXY_PASSWORD, "chp", 4));
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/c", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    int code = status_of(hr);
    t_note("OBS 407 with connect-level proxy creds -> %d, requests %d", code, srv_req_count(p));
    EXPECT_EQ(code, 200);
    EXPECT_EQ(srv_req_count(p), 2);
    if (srv_req_count(p) >= 2) EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), basic("chu:chp"));
    drain(hr); U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_407_with_body_and_keepalive_same_connection) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"ka\"\r\nContent-Type: text/html\r\n",
                                                     "<html>a fairly long proxy error page body......................</html>"),
                                   S_HEAD(), S_REPLY(200, NULL, "ok"), S_LOOP_TO(2) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    DWORD err; pc_req_opt o = { 0 }; o.proxy_user = "ku"; o.proxy_pass = "kp";
    EXPECT_EQ(pc_request(h, "pc-ka407.invalid", 80, "/k", &o, &err), 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_EQ(srv_req_conn(p, 0), srv_req_conn(p, 1));   /* the 407 body is drained, the connection reused */
    EXPECT_EQ(srv_conn_count(p), 1);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_407_post_body_resent) {
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(407, "Proxy-Authenticate: Basic realm=\"pb\"\r\n", ""),
                                   S_HEAD(), S_BODY(), S_REPLY(200, NULL, "ok"), S_LOOP_TO(3) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    HINTERNET hc = U(InternetConnectA)(h, "pc-pb.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/pb", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "pu", 3));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "pp", 3));
    static const char data[] = "field=value&x=1";
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, (void *)data, sizeof data - 1));
    EXPECT_EQ(status_of(hr), 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    for (int i = 0; i < 2; i++) {
        size_t n = 0; const char *b = srv_req_body(p, i, &n);
        CHECKF(b && n == sizeof data - 1 && !memcmp(b, data, n), "request %d body n=%zu", i, n);
        EXPECT_STR(srv_req_line(p, i), "POST http://pc-pb.invalid/pb HTTP/1.1");
    }
    EXPECT_STR(srv_req_header(p, 1, "Proxy-Authorization"), basic("pu:pp"));
    drain(hr); U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ proxy responses */
TEST(pc_wire2_proxy_error_statuses_returned) {
    static const int codes[] = { 400, 403, 404, 500, 502, 503, 504 };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        srv_step st[] = { S_HEAD(), { SRV_REPLY, "proxy-error", 11, codes[i], "Content-Type: text/plain\r\n" }, S_LOOP() };
        srv_script sc = { st, 3 }; srv_config cfg = { SRV_HTTP, &sc, 1 }; srv *p;
        if (srv_start(&cfg, &p)) { CHECK(0); continue; }
        HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
        char body[32]; DWORD err;
        int code = pc_get(h, "http://pc-perr.invalid/", 0, body, sizeof body, &err, NULL);
        CHECKF(code == codes[i], "proxy %d -> status %d err %lu", codes[i], code, err);
        EXPECT_STR(body, "proxy-error");
        t_inet_close(h); srv_stop(p);
    }
}

TEST(pc_wire2_proxy_connection_close_forces_new_connection) {
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "one", SRV_R_CONN_CLOSE) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-cc.invalid/1", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_EQ(pc_get(h, "http://pc-cc.invalid/2", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    EXPECT_NE(srv_req_conn(p, 0), srv_req_conn(p, 1));
    EXPECT_EQ(srv_conn_count(p), 2);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_proxy_connection_close_via_proxy_connection_header) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Proxy-Connection: close\r\n", "pcclose"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-pcc.invalid/1", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_EQ(pc_get(h, "http://pc-pcc.invalid/2", 0, body, sizeof body, &err, NULL), 200);
    CHECK(srv_wait_requests(p, 2, 3000));
    t_note("OBS Proxy-Connection: close -> conns %d (req conns %d, %d)", srv_conn_count(p), srv_req_conn(p, 0), srv_req_conn(p, 1));
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_proxy_http10_close_delimited) {
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "close-delimited body", SRV_R_HTTP10 | SRV_R_CLOSE) };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    char body[64]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-h10.invalid/1", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "close-delimited body");
    EXPECT_EQ(pc_get(h, "http://pc-h10.invalid/2", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "close-delimited body");
    EXPECT_EQ(srv_conn_count(p), 2);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_proxy_chunked_gzip_response) {
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, 0, SRV_R_CHUNKED), S_LOOP() };
    srv_step dyn[3]; memcpy(dyn, st, sizeof st); dyn[1].n = srv_fox_gzip_len; dyn[1].n2 = 100;
    srv_script sc = { dyn, 3 }; srv_config cfg = { SRV_HTTP, &sc, 1 }; srv *p;
    START_OR_SKIP(&cfg, &p);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    BOOL dec = TRUE; U(InternetSetOptionA)(h, INTERNET_OPTION_HTTP_DECODING, &dec, sizeof dec);
    static char body[2048]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-gz.invalid/fox", 0, body, sizeof body, &err, NULL), 200);
    /* boot 4: HTTP_DECODING set on the session did not decode the InternetOpenUrl body (raw gzip came back) */
    int decoded = !strcmp(body, srv_fox_text()), raw = !memcmp(body, srv_fox_gzip, 3);
    t_note("OBS gzip via proxy with session HTTP_DECODING: decoded %d raw %d", decoded, raw);
    CHECK(decoded || raw);
    CHECK(srv_wait_requests(p, 1, 3000));
    t_note("OBS Accept-Encoding via proxy with decoding: \"%s\"", srv_req_header(p, 0, "Accept-Encoding") ? srv_req_header(p, 0, "Accept-Encoding") : "-");
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ several sessions / proxies */
TEST(pc_wire2_two_sessions_two_proxies) {
    PROXY2_OR_SKIP(a);
    srv *b = srv_http(k_ok, (int)(sizeof k_ok / sizeof k_ok[0]));
    if (!b) { srv_stop(a); t_skip("second proxy"); return; }
    HINTERNET ha = pc_open_proxy(srv_hostport(a), NULL), hb = pc_open_proxy(srv_hostport(b), NULL);
    char body[32]; DWORD err;
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(pc_get(ha, "http://pc-two-a.invalid/x", 0, body, sizeof body, &err, NULL), 200);
        EXPECT_EQ(pc_get(hb, "http://pc-two-b.invalid/x", 0, body, sizeof body, &err, NULL), 200);
    }
    CHECK(srv_wait_requests(a, 3, 3000)); CHECK(srv_wait_requests(b, 3, 3000));
    EXPECT_EQ(srv_req_count(a), 3); EXPECT_EQ(srv_req_count(b), 3);
    for (int i = 0; i < 3; i++) {
        EXPECT_STR(srv_req_header(a, i, "Host"), "pc-two-a.invalid");
        EXPECT_STR(srv_req_header(b, i, "Host"), "pc-two-b.invalid");
    }
    t_inet_close(ha); t_inet_close(hb); srv_stop(a); srv_stop(b);
}

TEST(pc_wire2_switch_session_proxy_between_requests) {
    PROXY2_OR_SKIP(a);
    srv *b = srv_http(k_ok, (int)(sizeof k_ok / sizeof k_ok[0]));
    if (!b) { srv_stop(a); t_skip("second proxy"); return; }
    HINTERNET h = pc_open_proxy(srv_hostport(a), NULL);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-sw2.invalid/1", 0, body, sizeof body, &err, NULL), 200);
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)srv_hostport(b), NULL };
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    EXPECT_EQ(pc_get(h, "http://pc-sw2.invalid/2", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_EQ(pc_get(h, "http://pc-sw2.invalid/3", 0, body, sizeof body, &err, NULL), 200);
    Sleep(100);
    EXPECT_EQ(srv_req_count(a), 1);
    EXPECT_EQ(srv_req_count(b), 2);
    t_inet_close(h); srv_stop(a); srv_stop(b);
}

/* per-scheme list: http goes to the http= proxy, https CONNECTs to the https= proxy */
TEST(pc_wire2_per_scheme_http_and_https_split) {
    PROXY2_OR_SKIP(hp);
    static const srv_step tls[] = { S_HEAD(), S_REPLY(200, NULL, "tls-origin"), S_CLOSE_IF_ASKED(), S_LOOP() };
    srv *t = srv_https(tls, 4, SRV_CERT_LOCALHOST);
    if (!t) { srv_stop(hp); t_skip("https server"); return; }
    static const char *const rep[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };
    pc_relay *r = pc_relay_start(rep, 1, srv_port(t));
    if (!r) { srv_stop(t); srv_stop(hp); t_skip("relay"); return; }
    char px[128]; snprintf(px, sizeof px, "http=%s;https=127.0.0.1:%u", srv_hostport(hp), pc_relay_port(r));
    HINTERNET h = pc_open_proxy(px, NULL);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-split.invalid/plain", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "proxied");
    pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    EXPECT_EQ(pc_request(h, "pc-split.invalid", 443, "/secure", &o, &err), 200);
    EXPECT_STR(body, "tls-origin");
    CHECK(pc_relay_wait_heads(r, 1, 3000));
    EXPECT_STR(pc_head_line(pc_relay_head(r, 0)), "CONNECT pc-split.invalid:443 HTTP/1.0");
    EXPECT_EQ(srv_req_count(hp), 1);
    t_inet_close(h); pc_relay_stop(r); srv_stop(t); srv_stop(hp);
}

TEST(pc_wire2_http_only_proxy_https_goes_direct) {
    PROXY2_OR_SKIP(p);
    char px[96]; snprintf(px, sizeof px, "http=%s", srv_hostport(p));
    HINTERNET h = pc_open_proxy(px, NULL);
    DWORD err; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100;
    int code = pc_request(h, "pc-hto.invalid", 443, "/s", &o, &err);
    t_note("OBS http= only proxy, https request: status %d err %lu (%s) proxy reqs %d", code, err, t_inet_errname(err), srv_req_count(p));
    EXPECT_EQ(code, 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    EXPECT_EQ(srv_req_count(p), 0);
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ CONNECT variants */
static const srv_step k_tls2[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\n", "tunnelled2"), S_CLOSE_IF_ASKED(), S_LOOP() };
typedef struct { srv *tls; pc_relay *r; HINTERNET h; } tun2;
static int tun2_setup(tun2 *e, const char *const *rep, int n, const char *proxy_fmt) {
    memset(e, 0, sizeof *e);
    e->tls = srv_https(k_tls2, 4, SRV_CERT_LOCALHOST); if (!e->tls) return 0;
    e->r = pc_relay_start(rep, n, srv_port(e->tls)); if (!e->r) { srv_stop(e->tls); return 0; }
    char px[96]; snprintf(px, sizeof px, proxy_fmt ? proxy_fmt : "127.0.0.1:%u", pc_relay_port(e->r));
    e->h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, px, NULL, 5000);
    return e->h != NULL;
}
static void tun2_done(tun2 *e) { t_inet_close(e->h); pc_relay_stop(e->r); srv_stop(e->tls); }
#define TUN2_OR_SKIP(e, rep, n, fmt) tun2 e; if (!tun2_setup(&e, rep, n, fmt)) { t_skip("tunnel setup failed"); return; }

TEST(pc_wire2_connect_reply_variants) {
    static const char *const variants[] = {
        "HTTP/1.0 200 OK\r\n\r\n",
        "HTTP/1.1 200 Connection established\r\nProxy-Agent: pc-relay/1.0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 200 Tunnel\r\nConnection: keep-alive\r\nX-Extra: 1\r\n\r\n",
    };
    for (size_t i = 0; i < sizeof variants / sizeof variants[0]; i++) {
        const char *const rep[] = { variants[i] };
        tun2 e; if (!tun2_setup(&e, rep, 1, NULL)) { t_skip("tunnel setup failed"); return; }
        DWORD err; char body[32]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
        int code = pc_request(e.h, "pc-crv.invalid", 443, "/v", &o, &err);
        CHECKF(code == 200, "variant %zu: status %d err %lu (%s)", i, code, err, t_inet_errname(err));
        EXPECT_STR(body, "tunnelled2");
        tun2_done(&e);
    }
}

TEST(pc_wire2_connect_second_request_new_tunnel_or_reuse) {
    static const char *const rep[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };
    TUN2_OR_SKIP(e, rep, 1, NULL);
    DWORD err; char body[32]; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.body = body; o.cap = sizeof body;
    EXPECT_EQ(pc_request(e.h, "pc-reuse.invalid", 443, "/1", &o, &err), 200);
    EXPECT_EQ(pc_request(e.h, "pc-reuse.invalid", 443, "/2", &o, &err), 200);
    t_note("OBS two https requests via proxy: CONNECT heads %d relay conns %d, origin reqs %d conns %d", pc_relay_heads(e.r), pc_relay_conns(e.r),
           srv_req_count(e.tls), srv_conn_count(e.tls));
    CHECK(pc_relay_heads(e.r) >= 1 && pc_relay_heads(e.r) <= 2);
    EXPECT_EQ(srv_req_count(e.tls), 2);
    for (int i = 0; i < pc_relay_heads(e.r); i++) EXPECT_STR(pc_head_line(pc_relay_head(e.r, i)), "CONNECT pc-reuse.invalid:443 HTTP/1.0");
    tun2_done(&e);
}

TEST(pc_wire2_connect_origin_credentials_stay_inside_tunnel) {
    static const char *const rep[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };
    TUN2_OR_SKIP(e, rep, 1, NULL);
    HINTERNET hc = U(InternetConnectA)(e.h, "pc-oc.invalid", 443, "ouser", "opass", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/oc", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    t_https_secflags(hr, 0x1100);
    CHECK(U(HttpSendRequestA)(hr, "Authorization: Basic Zm9vOmJhcg==\r\n", (DWORD)-1, NULL, 0));
    EXPECT_EQ(status_of(hr), 200);
    CHECK(pc_relay_wait_heads(e.r, 1, 3000));
    EXPECT_EQ(pc_head_header(pc_relay_head(e.r, 0), "Authorization"), NULL);
    CHECK(srv_wait_requests(e.tls, 1, 3000));
    EXPECT_STR(srv_req_header(e.tls, 0, "Authorization"), "Basic Zm9vOmJhcg==");
    drain(hr); U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); tun2_done(&e);
}

TEST(pc_wire2_connect_custom_headers_not_on_connect) {
    static const char *const rep[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };
    TUN2_OR_SKIP(e, rep, 1, NULL);
    DWORD err; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.headers = "X-Inner: secret\r\n";
    EXPECT_EQ(pc_request(e.h, "pc-ch.invalid", 443, "/ch", &o, &err), 200);
    CHECK(pc_relay_wait_heads(e.r, 1, 3000));
    EXPECT_EQ(pc_head_header(pc_relay_head(e.r, 0), "X-Inner"), NULL);
    CHECK(srv_wait_requests(e.tls, 1, 3000));
    EXPECT_STR(srv_req_header(e.tls, 0, "X-Inner"), "secret");
    tun2_done(&e);
}

TEST(pc_wire2_connect_ip_literal_targets) {
    static const char *const rep[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };
    static const struct { const char *host; INTERNET_PORT port; const char *line; } t[] = {
        { "192.0.2.10", 443, "CONNECT 192.0.2.10:443 HTTP/1.0" },
        { "192.0.2.11", 9443, "CONNECT 192.0.2.11:9443 HTTP/1.0" },
        { "[2001:db8::5]", 443, NULL },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        tun2 e; if (!tun2_setup(&e, rep, 1, NULL)) { t_skip("tunnel"); return; }
        DWORD err; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100 | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        int code = pc_request(e.h, t[i].host, t[i].port, "/ip", &o, &err);
        const char *ln = pc_relay_wait_heads(e.r, 1, 3000) ? pc_head_line(pc_relay_head(e.r, 0)) : NULL;
        t_note("OBS CONNECT to %s:%u -> status %d err %lu line \"%s\" Host \"%s\"", t[i].host, t[i].port, code, err, ln ? ln : "-",
               pc_relay_head(e.r, 0) ? pc_head_header(pc_relay_head(e.r, 0), "Host") : "-");
        if (t[i].line) { EXPECT_EQ(code, 200); CHECKF(ln && !strcmp(ln, t[i].line), "got \"%s\" want \"%s\"", ln ? ln : "(none)", t[i].line); }
        tun2_done(&e);
    }
}

TEST(pc_wire2_connect_https_scheme_proxy_entry_uppercase) {
    static const char *const rep[] = { "HTTP/1.1 200 Connection established\r\n\r\n" };
    TUN2_OR_SKIP(e, rep, 1, "HTTPS=127.0.0.1:%u");
    DWORD err; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100;
    EXPECT_EQ(pc_request(e.h, "pc-up.invalid", 443, "/u", &o, &err), 200);
    EXPECT_EQ(pc_relay_heads(e.r), 1);
    tun2_done(&e);
}

/* ------------------------------------------------------------------ bypass lists: size and whitespace */
static int via_proxy(srv *p, const char *bypass, const char *url, int *st, DWORD *err) {
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), bypass, 3000);
    if (!h) { *st = -1; *err = GetLastError(); return -1; }
    int before = srv_req_count(p); char body[32];
    *st = pc_get(h, url, 0, body, sizeof body, err, NULL);
    int via = srv_req_count(p) > before;
    t_inet_close(h);
    return via;
}

TEST(pc_wire2_bypass_long_list) {
    PROXY2_OR_SKIP(p);
    static char list[16384]; size_t n = 0;
    for (int i = 0; i < 400; i++) n += (size_t)snprintf(list + n, sizeof list - n, "%sfiller%d.invalid", i ? ";" : "", i);
    snprintf(list + n, sizeof list - n, ";pc-last.invalid");
    int st; DWORD err;
    int v = via_proxy(p, list, "http://pc-last.invalid/x", &st, &err);
    t_note("OBS %zu-byte bypass list, last entry matches: via %d st %d err %lu", strlen(list), v, st, err);
    EXPECT_EQ(v, 0); EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    v = via_proxy(p, list, "http://filler7.invalid/x", &st, &err);
    EXPECT_EQ(v, 0);
    v = via_proxy(p, list, "http://pc-notlisted.invalid/x", &st, &err);
    EXPECT_EQ(v, 1); EXPECT_EQ(st, 200);
    srv_stop(p);
}

TEST(pc_wire2_bypass_whitespace_and_empty_entries) {
    PROXY2_OR_SKIP(p);
    static const struct { const char *bypass; const char *url; int proxied; int certain; } t[] = {
        { "  pc-ws.invalid  ", "http://pc-ws.invalid/x", 0, 1 },
        { ";;pc-ws.invalid;;", "http://pc-ws.invalid/x", 0, 1 },
        { "a.invalid ;  pc-ws.invalid", "http://pc-ws.invalid/x", 0, 1 },
        { "\tpc-ws.invalid", "http://pc-ws.invalid/x", 0, 0 },
        { ";", "http://pc-ws.invalid/x", 1, 1 },
        { " ", "http://pc-ws.invalid/x", 1, 1 },
        { "pc-ws.invalid.", "http://pc-ws.invalid/x", 1, 0 },
        { "PC-WS.Invalid", "http://pc-ws.invalid/x", 0, 1 },
        { "pc-ws.invalid", "http://PC-WS.INVALID/x", 0, 1 },
        { "*.*", "http://pc-ws.invalid/x", 0, 1 },
        { "*.*", "http://pcwsplain/x", 1, 0 },
        { "pc-ws.*", "http://pc-ws.invalid/x", 0, 1 },
        { "*ws*", "http://pc-ws.invalid/x", 0, 1 },
        { "*nomatch*", "http://pc-ws.invalid/x", 1, 1 },
        { "**", "http://pc-ws.invalid/x", 0, 0 },
        { "http://*.invalid", "http://pc-ws.invalid/x", 0, 1 },
        { "ftp://*.invalid", "http://pc-ws.invalid/x", 1, 1 },
        { "*.invalid:80", "http://pc-ws.invalid/x", 0, 0 },
        { "*.invalid:81", "http://pc-ws.invalid/x", 1, 1 },
        { "*:8080", "http://pc-ws.invalid:8080/x", 0, 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        int st; DWORD err;
        int v = via_proxy(p, t[i].bypass, t[i].url, &st, &err);
        t_note("OBS bypass \"%s\" %s -> via %d st %d err %lu", t[i].bypass, t[i].url, v, st, err);
        if (t[i].certain) CHECKF(v == t[i].proxied, "bypass \"%s\" %s: via %d want %d (st %d err %lu)", t[i].bypass, t[i].url, v, t[i].proxied, st, err);
    }
    srv_stop(p);
}

TEST(pc_wire2_bypass_local_matching_table) {
    PROXY2_OR_SKIP(p);
    static const struct { const char *url; int proxied; } t[] = {
        { "http://pcplainname/x", 0 }, { "http://pcplainname:8080/x", 0 }, { "http://pc.dotted.invalid/x", 1 },
        { "http://192.0.2.12/x", 1 }, { "http://PCUPPERPLAIN/x", 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        int st; DWORD err; int v = via_proxy(p, "<local>", t[i].url, &st, &err);
        t_note("OBS <local> %s -> via %d st %d err %lu", t[i].url, v, st, err);
        CHECKF(v == t[i].proxied, "<local> %s: via %d want %d", t[i].url, v, t[i].proxied);
    }
    srv_stop(p);
}

TEST(pc_wire2_bypass_set_option_table) {
    PROXY2_OR_SKIP(p);
    static const struct { const char *bypass; const char *url; int proxied; } t[] = {
        { "pc-so.invalid", "http://pc-so.invalid/x", 0 }, { "*.invalid", "http://pc-so.invalid/x", 0 },
        { "<local>", "http://pc-so.invalid/x", 1 }, { "other.invalid", "http://pc-so.invalid/x", 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
        INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)srv_hostport(p), (LPCTSTR)t[i].bypass };
        CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
        int before = srv_req_count(p); char body[32]; DWORD err;
        int st = pc_get(h, t[i].url, 0, body, sizeof body, &err, NULL);
        int v = srv_req_count(p) > before;
        CHECKF(v == t[i].proxied, "set bypass \"%s\" %s: via %d want %d (st %d err %lu)", t[i].bypass, t[i].url, v, t[i].proxied, st, err);
        t_inet_close(h);
    }
    srv_stop(p);
}

/* ------------------------------------------------------------------ ftp through a CERN proxy */
TEST(pc_wire2_ftp_urls_via_cern_proxy) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\n", "ftp-body"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open_proxy(srv_hostport(p), NULL);
    static const char *urls[] = { "ftp://pc-ftp2.invalid/dir/", "ftp://pc-ftp2.invalid:2121/f.bin", "ftp://u:pw@pc-ftp2.invalid/priv.txt",
                                  "ftp://pc-ftp2.invalid/a%20b.txt" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        int before = srv_req_count(p);
        HINTERNET hu = U(InternetOpenUrlA)(h, urls[i], NULL, 0, T_INET_FRESH | INTERNET_FLAG_PASSIVE, 0);
        DWORD e = hu ? 0 : GetLastError();
        if (hu) { char b[32]; t_inet_read_all(hu, b, sizeof b, NULL); U(InternetCloseHandle)(hu); }
        int got = srv_wait_requests(p, before + 1, 3000);
        t_note("OBS ftp via proxy %s -> handle %d err %lu line \"%s\" Host \"%s\" Authorization \"%s\"", urls[i], hu != NULL, e,
               got ? srv_req_line(p, before) : "-", got && srv_req_header(p, before, "Host") ? srv_req_header(p, before, "Host") : "-",
               got && srv_req_header(p, before, "Authorization") ? srv_req_header(p, before, "Authorization") : "-");
        CHECK(hu != NULL);
        if (got) CHECK(!strncmp(srv_req_line(p, before), "GET ftp://", 10));
    }
    t_inet_close(h); srv_stop(p);
}

TEST(pc_wire2_ftp_proxy_entry_used_for_ftp_urls) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "via-ftp-entry"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    char px[96]; snprintf(px, sizeof px, "ftp=%s", srv_hostport(p));
    HINTERNET h = pc_open_proxy(px, NULL);
    HINTERNET hu = U(InternetOpenUrlA)(h, "ftp://pc-ftpe.invalid/file.txt", NULL, 0, T_INET_FRESH | INTERNET_FLAG_PASSIVE, 0);
    DWORD e = hu ? 0 : GetLastError();
    t_note("OBS ftp= proxy entry: handle %d err %lu requests %d line \"%s\"", hu != NULL, e, srv_req_count(p),
           srv_req_count(p) ? srv_req_line(p, 0) : "-");
    if (hu) U(InternetCloseHandle)(hu);
    /* plain http with an ftp-only list goes direct */
    char body[16]; DWORD err;
    int before = srv_req_count(p);
    EXPECT_EQ(pc_get(h, "http://pc-ftpe.invalid/", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    EXPECT_EQ(srv_req_count(p), before);
    t_inet_close(h); srv_stop(p);
}

