/* proxy_connectivity: more failure paths. A scripted proxy that misbehaves at every stage of a CONNECT, servers that
 * close or reset before reading the request, malformed/partial responses (direct and through a proxy), handle state
 * after a failed send, recovery of a session after a refusal, timeout option values, and the message table for the
 * connection error codes. Refused connects cost ~2 s each on Windows (04 F3): only a few here.
 * VM_TIMEOUT: 600 */
#include "pc.h"

static int status_of(HINTERNET hr) {
    DWORD v = 0, l = sizeof v;
    return U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL) ? (int)v : 0;
}

/* ------------------------------------------------------------------ CONNECT through a misbehaving proxy */
typedef struct { const char *name; const srv_step *steps; int n; int want_status; DWORD want_err; int certain; } cstage;
#define STEPS2(...) (const srv_step[]){ __VA_ARGS__ }, (int)(sizeof((const srv_step[]){ __VA_ARGS__ }) / sizeof(srv_step))

static void run_connect_stage(const cstage *c) {
    srv_script sc = { c->steps, c->n }; srv_config cfg = { SRV_HTTP, &sc, 1 }; srv *p;
    if (srv_start(&cfg, &p)) { CHECKF(0, "%s: server", c->name); return; }
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), NULL, 3000);
    DWORD err, ms; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.ms = &ms;
    int st = pc_request(h, "pc-cs.invalid", 443, "/cs", &o, &err);
    const char *ln = srv_req_count(p) ? srv_req_line(p, 0) : NULL;
    t_note("OBS CONNECT stage \"%s\": status %d err %lu (%s) %lu ms, first head \"%s\", heads %d conns %d", c->name, st, err, t_inet_errname(err), ms,
           ln ? ln : "-", srv_req_count(p), srv_conn_count(p));
    if (ln) CHECKF(!strcmp(ln, "CONNECT pc-cs.invalid:443 HTTP/1.0"), "%s: head \"%s\"", c->name, ln);
    if (c->certain) {
        CHECKF(st == c->want_status, "%s: status %d want %d", c->name, st, c->want_status);
        if (!c->want_status) CHECKF(err == c->want_err, "%s: err %lu (%s) want %lu (%s)", c->name, err, t_inet_errname(err), c->want_err, t_inet_errname(c->want_err));
    }
    t_inet_close(h); srv_stop(p);
}

static const cstage k_connect_stages[] = {
    { "close without reply", STEPS2(S_HEAD(), S_CLOSE()), 0, 0, 0 },
    { "reset without reply", STEPS2(S_HEAD(), S_RESET()), 0, ERROR_INTERNET_CONNECTION_RESET, 0 },
    { "garbage reply then close", STEPS2(S_HEAD(), S_SEND("garbage\r\n\r\n"), S_CLOSE()), 0, 0, 0 },
    { "200 then close", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 Connection established\r\n\r\n"), S_CLOSE()), 0, 0, 0 },
    { "200 then reset", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 Connection established\r\n\r\n"), S_SLEEP(100), S_RESET()), 0, 0, 0 },
    { "200 then plaintext", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 Connection established\r\n\r\n"), S_BYTES(5),
                                  S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), S_CLOSE()), 0, 0, 0 },
    { "partial status line", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 2"), S_CLOSE()), 0, 0, 0 },
    { "407 without auth header", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"), S_LOOP()), 407, 0, 0 },
    { "301 to CONNECT", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 301 Moved\r\nLocation: http://x.invalid/\r\nContent-Length: 0\r\n\r\n"), S_LOOP()), 0, 0, 0 },
    { "HTTP/1.0 403 close", STEPS2(S_HEAD(), S_SEND("HTTP/1.0 403 Forbidden\r\n\r\nno tunnel"), S_CLOSE()), 403, 0, 0 },
    { "100 then close", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 100 Continue\r\n\r\n"), S_CLOSE()), 0, 0, 0 },
};
TEST(pc_fail2_connect_stage_table) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof k_connect_stages / sizeof k_connect_stages[0]; i++) run_connect_stage(&k_connect_stages[i]);
}

TEST(pc_fail2_connect_proxy_refused) {
    unsigned short dead = pc_closed_port();
    if (!dead) { t_skip("no ws2_32"); return; }
    char px[32]; snprintf(px, sizeof px, "127.0.0.1:%u", dead);
    HINTERNET h = pc_open_proxy(px, NULL);
    DWORD err, ms; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x1100; o.ms = &ms;
    EXPECT_EQ(pc_request(h, "pc-cr.invalid", 443, "/", &o, &err), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    t_note("CONNECT proxy refused: %lu ms", ms);
    t_inet_close(h);
}

/* ------------------------------------------------------------------ the server misbehaves before / around the request */
static const cstage k_early[] = {
    { "close at accept", STEPS2(S_CLOSE()), 0, 0, 0 },
    { "reset at accept", STEPS2(S_RESET()), 0, 0, 0 },
    { "response before request", STEPS2(S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nearly"), S_HEAD(), S_CLOSE()), 0, 0, 0 },
    { "100 then close", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 100 Continue\r\n\r\n"), S_CLOSE()), 0, 0, 0 },
    { "status line only", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n"), S_CLOSE()), 200, 0, 0 },
    { "one byte", STEPS2(S_HEAD(), S_SEND("H"), S_CLOSE()), 0, 0, 0 },
    { "LF-only head", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 OK\nContent-Length: 2\n\nok"), S_CLOSE()), 200, 0, 1 },
    { "unknown status 999", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 999 Odd\r\nContent-Length: 0\r\n\r\n"), S_CLOSE()), 999, 0, 0 },
    { "chunked truncated", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"), S_CLOSE()), 200, 0, 0 },
    { "chunked bad size", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n0\r\n\r\n"), S_CLOSE()), 200, 0, 0 },
    { "Content-Length negative", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nabc"), S_CLOSE()), 200, 0, 0 },
    { "Content-Length garbage", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nxyz"), S_CLOSE()), 200, 0, 0 },
    { "HTTP/2 status line", STEPS2(S_HEAD(), S_SEND("HTTP/2 200\r\nContent-Length: 2\r\n\r\nok"), S_CLOSE()), 0, 0, 0 },
    { "HTTP/1.1 no reason", STEPS2(S_HEAD(), S_SEND("HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok"), S_CLOSE()), 200, 0, 1 },
    { "lowercase http", STEPS2(S_HEAD(), S_SEND("http/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), S_CLOSE()), 0, 0, 0 },
    { "slow head 3 pieces", STEPS2(S_HEAD(), S_SPLIT("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow", 12, 100), S_CLOSE()), 200, 0, 1 },
};

static void run_early(const cstage *c, int proxy) {
    srv_script sc = { c->steps, c->n }; srv_config cfg = { SRV_HTTP, &sc, 1 }; srv *s;
    if (srv_start(&cfg, &s)) { CHECKF(0, "%s: server", c->name); return; }
    HINTERNET h = proxy ? pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(s), NULL, 3000)
                        : pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    char body[64]; DWORD err, ms;
    int st = pc_get(h, proxy ? "http://pc-early.invalid/e" : srv_url(s, "/e"), 0, body, sizeof body, &err, &ms);
    t_note("OBS %s\"%s\": status %d err %lu (%s) body \"%s\" heads %d conns %d %lu ms", proxy ? "proxy " : "", c->name, st, err, t_inet_errname(err), body,
           srv_req_count(s), srv_conn_count(s), ms);
    if (c->certain) {
        CHECKF(st == c->want_status, "%s%s: status %d want %d", proxy ? "proxy " : "", c->name, st, c->want_status);
        if (!c->want_status) CHECKF(err == c->want_err, "%s: err %lu want %lu", c->name, err, c->want_err);
    }
    t_inet_close(h); srv_stop(s);
}
TEST(pc_fail2_early_and_malformed_direct) {
    for (size_t i = 0; i < sizeof k_early / sizeof k_early[0]; i++) run_early(&k_early[i], 0);
}
TEST(pc_fail2_early_and_malformed_via_proxy) {
    for (size_t i = 0; i < sizeof k_early / sizeof k_early[0]; i++) run_early(&k_early[i], 1);
}

/* ------------------------------------------------------------------ handle state after a failed send */
TEST(pc_fail2_request_handle_after_refused_send) {
    unsigned short dead = pc_closed_port();
    if (!dead) { t_skip("no ws2_32"); return; }
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    HINTERNET hc = U(InternetConnectA)(h, "127.0.0.1", dead, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/hs", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    if (!hr) { t_skip("handles"); if (hc) U(InternetCloseHandle)(hc); t_inet_close(h); return; }
    SetLastError(0xdeadbeef);
    CHECK(!U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_ERR(ERROR_INTERNET_CANNOT_CONNECT);
    DWORD v = 0, l = sizeof v; SetLastError(0xdeadbeef);
    BOOL q = U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL);
    DWORD qe = GetLastError();
    t_note("OBS status query after refused send -> %d err %lu", q, qe);
    CHECK(!q);
    char b[16]; DWORD rd = 7; SetLastError(0xdeadbeef);
    BOOL r = U(InternetReadFile)(hr, b, sizeof b, &rd);
    t_note("OBS InternetReadFile after refused send -> %d err %lu read %lu", r, r ? 0 : GetLastError(), rd);
    /* the request line headers are still queryable */
    char raw[512]; l = sizeof raw; SetLastError(0xdeadbeef);
    BOOL rq = U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, raw, &l, NULL);
    t_note("OBS request headers after refused send -> %d err %lu", rq, rq ? 0 : GetLastError());
    /* a second send on the same handle fails the same way */
    SetLastError(0xdeadbeef);
    CHECK(!U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_ERR(ERROR_INTERNET_CANNOT_CONNECT);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h);
}

TEST(pc_fail2_session_recovers_after_refusal) {
    unsigned short dead = pc_closed_port();
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "alive"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/x", dead);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, url, 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    EXPECT_EQ(pc_get(h, srv_url(s, "/ok"), 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "alive");
    EXPECT_EQ(pc_get(h, "http://pc-rec.invalid/", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    EXPECT_EQ(pc_get(h, srv_url(s, "/ok2"), 0, body, sizeof body, &err, NULL), 200);
    t_inet_close(h); srv_stop(s);
}

TEST(pc_fail2_proxy_session_recovers_after_proxy_change) {
    unsigned short dead = pc_closed_port();
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "proxy-alive"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    char px[32]; snprintf(px, sizeof px, "127.0.0.1:%u", dead);
    HINTERNET h = pc_open_proxy(px, NULL);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-pr.invalid/1", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)srv_hostport(s), NULL };
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    EXPECT_EQ(pc_get(h, "http://pc-pr.invalid/2", 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "proxy-alive");
    t_inet_close(h); srv_stop(s);
}

/* ------------------------------------------------------------------ DNS failures (bounded on a worker thread) */
typedef struct { const char *url; int st; DWORD err, ms; } dns2_arg;
static DWORD WINAPI dns2_thread(void *p) {
    dns2_arg *a = p; HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 5000); char body[16];
    a->st = pc_get(h, a->url, 0, body, sizeof body, &a->err, &a->ms);
    t_inet_close(h); return 0;
}
TEST(pc_fail2_dns_invalid_variants) {
    static dns2_arg t[] = { { "http://pc-dns.invalid/" }, { "http://a.b.c.pc-dns.invalid/" }, { "http://PC-DNS-UP.INVALID/" },
                            { "http://pc-dns.invalid:65535/" }, { "https://pc-dns.invalid/" }, { "http://pc-dns.invalid./" },
                            { "http://xn--pc-dns.invalid/" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        t[i].st = -1; t[i].err = 0;
        if (!pc_bounded(dns2_thread, &t[i], 15000)) { t_skip("DNS lookup for %s took > 15 s (resolver environment)", t[i].url); return; }
        t_note("OBS %s -> status %d err %lu (%s) %lu ms", t[i].url, t[i].st, t[i].err, t_inet_errname(t[i].err), t[i].ms);
        if (t[i].ms > 10000) { t_note("slow resolver (%lu ms): not asserting", t[i].ms); continue; }
        CHECKF(t[i].st == 0 && t[i].err == ERROR_INTERNET_NAME_NOT_RESOLVED, "%s: st %d err %lu", t[i].url, t[i].st, t[i].err);
    }
}

TEST(pc_fail2_bad_port_urls) {
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    static const char *urls[] = { "http://127.0.0.1:0/", "http://127.0.0.1:65536/", "http://127.0.0.1:99999/", "http://127.0.0.1:-1/",
                                  "http://127.0.0.1:abc/", "http://127.0.0.1:/" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        char body[16]; DWORD err, ms;
        int st = pc_get(h, urls[i], 0, body, sizeof body, &err, &ms);
        t_note("OBS %s -> status %d err %lu (%s) %lu ms", urls[i], st, err, t_inet_errname(err), ms);
        CHECK(ms < 15000);
    }
    t_inet_close(h);
}

/* ------------------------------------------------------------------ timeout option values */
TEST(pc_fail2_timeout_option_roundtrip) {
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:1", NULL, 0);
    if (!h) { t_skip("open"); return; }
    static const DWORD opts[] = { INTERNET_OPTION_CONNECT_TIMEOUT, INTERNET_OPTION_SEND_TIMEOUT, INTERNET_OPTION_RECEIVE_TIMEOUT,
                                  INTERNET_OPTION_DATA_SEND_TIMEOUT, INTERNET_OPTION_DATA_RECEIVE_TIMEOUT, INTERNET_OPTION_CONNECT_RETRIES };
    static const DWORD vals[] = { 1, 1000, 0x7fffffff, 0xffffffffu };
    for (size_t o = 0; o < sizeof opts / sizeof opts[0]; o++) {
        DWORD d = 0, l = sizeof d;
        BOOL ok = U(InternetQueryOptionA)(h, opts[o], &d, &l);
        t_note("OBS PROXY session option %lu default -> %d value %lu", opts[o], ok, d);
        CHECK(ok);
        for (size_t v = 0; v < sizeof vals / sizeof vals[0]; v++) {
            DWORD x = vals[v];
            BOOL s = U(InternetSetOptionA)(h, opts[o], &x, sizeof x);
            DWORD back = 0; l = sizeof back;
            BOOL q = U(InternetQueryOptionA)(h, opts[o], &back, &l);
            CHECKF(s && q && back == vals[v], "option %lu value %lu: set %d query %d back %lu", opts[o], vals[v], s, q, back);
        }
        DWORD z = 0; SetLastError(0xdeadbeef);
        BOOL s0 = U(InternetSetOptionA)(h, opts[o], &z, sizeof z);
        DWORD back = 7; l = sizeof back; U(InternetQueryOptionA)(h, opts[o], &back, &l);
        t_note("OBS option %lu set 0 -> %d err %lu, reads back %lu", opts[o], s0, s0 ? 0 : GetLastError(), back);
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetSetOptionA)(h, opts[o], &z, 2));
        EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    }
    U(InternetCloseHandle)(h);
}

TEST(pc_fail2_connect_timeout_inherited_by_children) {
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:1", NULL, 0);
    if (!h) { t_skip("open"); return; }
    DWORD v = 1234; CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &v, sizeof v));
    HINTERNET hc = U(InternetConnectA)(h, "pc-ti.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    DWORD c = 0, r = 0, l = sizeof c;
    if (hc) CHECK(U(InternetQueryOptionA)(hc, INTERNET_OPTION_CONNECT_TIMEOUT, &c, &l));
    l = sizeof r; if (hr) CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_CONNECT_TIMEOUT, &r, &l));
    EXPECT_EQ(c, 1234); EXPECT_EQ(r, 1234);
    /* changing the session afterwards does not change existing children */
    v = 4321; CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &v, sizeof v));
    l = sizeof r; if (hr) CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_CONNECT_TIMEOUT, &r, &l));
    t_note("OBS request CONNECT_TIMEOUT after session change: %lu", r);
    if (hr) U(InternetCloseHandle)(hr);
    if (hc) U(InternetCloseHandle)(hc);
    U(InternetCloseHandle)(h);
}

/* a one-shot connect retry count against a refused port: still CANNOT_CONNECT (timing noted) */
TEST(pc_fail2_connect_retries_one_refused) {
    unsigned short dead = pc_closed_port();
    if (!dead) { t_skip("no ws2_32"); return; }
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 5000);
    DWORD one = 1; CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_RETRIES, &one, sizeof one));
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/r1", dead);
    char body[16]; DWORD err, ms;
    EXPECT_EQ(pc_get(h, url, 0, body, sizeof body, &err, &ms), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    t_note("refused with CONNECT_RETRIES=1: %lu ms", ms);
    t_inet_close(h);
}

/* ------------------------------------------------------------------ message table */
TEST(pc_fail2_error_message_texts) {
    HMODULE m = t_module("wininet.dll");
    REQUIRE(m);
    static const struct { DWORD code; const char *prefix; } t[] = {
        { ERROR_INTERNET_TIMEOUT, "The operation timed out" },
        { ERROR_INTERNET_NAME_NOT_RESOLVED, "The server name or address could not be resolved" },
        { ERROR_INTERNET_CANNOT_CONNECT, "A connection with the server could not be established" },
        { ERROR_INTERNET_CONNECTION_ABORTED, "The connection with the server was terminated abnormally" },
        { ERROR_INTERNET_CONNECTION_RESET, "The connection with the server was reset" },
        { ERROR_HTTP_INVALID_SERVER_RESPONSE, "The server returned an invalid or unrecognized response" },
        { ERROR_INTERNET_INVALID_URL, "The URL is invalid" },
        { ERROR_INTERNET_UNRECOGNIZED_SCHEME, "The URL does not use a recognized protocol" },
        { ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "The type of handle supplied is incorrect for this operation" },
        { ERROR_INTERNET_BAD_OPTION_LENGTH, "The length of an option supplied is incorrect for the type of option specified" },
        { ERROR_INTERNET_INVALID_OPTION, "An invalid option value was specified" },
        { ERROR_INTERNET_INVALID_CA, NULL }, { ERROR_INTERNET_PROXY_SERVER_UNREACHABLE, NULL }, { ERROR_INTERNET_DISCONNECTED, NULL },
        { ERROR_INTERNET_NOT_PROXY_REQUEST, NULL }, { ERROR_INTERNET_INVALID_PROXY_REQUEST, NULL }, { ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT, NULL },
        { ERROR_INTERNET_UNABLE_TO_DOWNLOAD_SCRIPT, NULL }, { ERROR_INTERNET_SERVER_UNREACHABLE, NULL }, { ERROR_INTERNET_INCORRECT_HANDLE_STATE, NULL },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char msg[512] = { 0 };
        DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, m, t[i].code,
                                 MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), msg, sizeof msg, NULL);
        if (!n) n = FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, m, t[i].code, 0, msg, sizeof msg, NULL);
        while (n && (msg[n - 1] == '\n' || msg[n - 1] == '\r')) msg[--n] = 0;
        t_note("OBS message %lu: \"%s\"", t[i].code, msg);
        CHECKF(n > 0, "no message for %lu", t[i].code);
        if (t[i].prefix && n) CHECKF(!strncmp(msg, t[i].prefix, strlen(t[i].prefix)), "%lu: \"%s\"", t[i].code, msg);
    }
}

TEST(pc_fail2_errname_helper_covers_codes) {
    /* scaffolding self-check: the helper names every code this area asserts on */
    static const DWORD codes[] = { ERROR_INTERNET_TIMEOUT, ERROR_INTERNET_NAME_NOT_RESOLVED, ERROR_INTERNET_CANNOT_CONNECT,
                                   ERROR_INTERNET_CONNECTION_ABORTED, ERROR_INTERNET_CONNECTION_RESET, ERROR_HTTP_INVALID_SERVER_RESPONSE };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) CHECKF(strcmp(t_inet_errname(codes[i]), "?") != 0, "%lu", codes[i]);
}

/* InternetGetLastResponseInfo after transport errors carries no server text */
TEST(pc_fail2_last_response_info_after_refusal) {
    unsigned short dead = pc_closed_port();
    if (!dead) { t_skip("no ws2_32"); return; }
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/lri", dead);
    char body[16]; DWORD err;
    EXPECT_EQ(pc_get(h, url, 0, body, sizeof body, &err, NULL), 0);
    DWORD e2 = 0xdead; char buf[256]; DWORD l = sizeof buf; buf[0] = 'x';
    BOOL ok = U(InternetGetLastResponseInfoA)(&e2, buf, &l);
    t_note("OBS last response info after refusal: ok %d err %lu len %lu", ok, e2, l);
    CHECK(ok);
    if (ok) { EXPECT_EQ(l, 0); }
    t_inet_close(h);
}
