/* proxy_connectivity: connection failures without any network.
 * Refused loopback ports, unresolvable *.invalid names, connect/receive timeouts, and servers that reset or close
 * at every stage of the response, directly and through a proxy. Refused connects cost ~2 s each on Windows
 * (04 F3), so there are only a few. Timing is t_note'd, never asserted.
 * VM_TIMEOUT: 300 */
#include "pc.h"

static HINTERNET open_direct(DWORD to) { return pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, to); }

/* ------------------------------------------------------------------ refused */
TEST(pc_fail_refused_direct) {
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    HINTERNET h = open_direct(5000);
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/r", p);
    char body[16]; DWORD err, ms;
    EXPECT_EQ(pc_get(h, url, 0, body, sizeof body, &err, &ms), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    t_note("refused direct: err %lu %lu ms", err, ms);
    DWORD ext = 0, l = sizeof ext;
    if (U(InternetQueryOptionA)(NULL, INTERNET_OPTION_EXTENDED_ERROR, &ext, &l)) t_note("EXTENDED_ERROR after refusal: %lu", ext);
    t_inet_close(h);
}

TEST(pc_fail_refused_httpopenrequest) {
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    HINTERNET h = open_direct(5000);
    DWORD err, ms; pc_req_opt o = { 0 }; o.ms = &ms;
    EXPECT_EQ(pc_request(h, "127.0.0.1", p, "/r2", &o, &err), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    t_note("refused HttpSendRequest: %lu ms", ms);
    t_inet_close(h);
}

TEST(pc_fail_refused_via_proxy) {
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    char px[32]; snprintf(px, sizeof px, "127.0.0.1:%u", p);
    HINTERNET h = pc_open_proxy(px, NULL);
    char body[16]; DWORD err, ms;
    int st = pc_get(h, "http://pc-origin.invalid/x", 0, body, sizeof body, &err, &ms);
    t_note("proxy refused: status %d err %lu (%s) %lu ms", st, err, t_inet_errname(err), ms);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    t_inet_close(h);
}

TEST(pc_fail_proxy_name_unresolvable) {
    HINTERNET h = pc_open_proxy("pc-proxy.invalid:8080", NULL);
    CHECK(h != NULL);
    char body[16]; DWORD err, ms;
    int st = pc_get(h, "http://pc-origin.invalid/x", 0, body, sizeof body, &err, &ms);
    t_note("unresolvable proxy: status %d err %lu (%s) %lu ms", st, err, t_inet_errname(err), ms);
    EXPECT_EQ(st, 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    t_inet_close(h);
}

TEST(pc_fail_proxy_list_failover) {
    unsigned short dead = pc_closed_port();
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP() };
    HTTP_OR_SKIP(p, st);
    char px[96]; snprintf(px, sizeof px, "127.0.0.1:%u;%s", dead, srv_hostport(p));
    HINTERNET h = pc_open_proxy(px, NULL);
    char body[16]; DWORD err, ms;
    int code = pc_get(h, "http://pc-fo.invalid/x", 0, body, sizeof body, &err, &ms);
    t_note("proxy list \"%s\": status %d err %lu (%s) second-proxy requests %d %lu ms", px, code, err, t_inet_errname(err), srv_req_count(p), ms);
    CHECK(code == 200 || err == ERROR_INTERNET_CANNOT_CONNECT);
    t_inet_close(h); srv_stop(p);
}

TEST(pc_fail_refused_https) {
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    HINTERNET h = open_direct(5000);
    DWORD err, ms; pc_req_opt o = { 0 }; o.secure = 1; o.secflags = 0x100; o.ms = &ms;
    EXPECT_EQ(pc_request(h, "127.0.0.1", p, "/s", &o, &err), 0);
    EXPECT_EQ(err, ERROR_INTERNET_CANNOT_CONNECT);
    t_note("refused https: %lu ms", ms);
    t_inet_close(h);
}

TEST(pc_fail_refused_ftp_connect) {
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    HINTERNET h = open_direct(5000);
    SetLastError(0xdeadbeef);
    HINTERNET hc = U(InternetConnectA)(h, "127.0.0.1", p, "anonymous", "x@", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    DWORD e = GetLastError();
    CHECK(hc == NULL);
    EXPECT_EQ(e, ERROR_INTERNET_CANNOT_CONNECT);
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(h);
}

/* a short connect timeout races the ~2 s refused-connect retry loop */
TEST(pc_fail_connect_timeout_vs_refused) {
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    pc_set_timeouts(h, 300, 5000, 5000);
    DWORD v = 0, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &v, &l)); EXPECT_EQ(v, 300);
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/t", p);
    char body[16]; DWORD err, ms;
    EXPECT_EQ(pc_get(h, url, 0, body, sizeof body, &err, &ms), 0);
    t_note("connect timeout 300 ms vs refused port: err %lu (%s) %lu ms", err, t_inet_errname(err), ms);
    CHECK(err == ERROR_INTERNET_TIMEOUT || err == ERROR_INTERNET_CANNOT_CONNECT);
    t_inet_close(h);
}

/* ------------------------------------------------------------------ name resolution */
typedef struct { const char *url; int st; DWORD err; DWORD ms; } dns_arg;
static DWORD WINAPI dns_thread(void *p) {
    dns_arg *a = p; HINTERNET h = open_direct(5000); char body[16];
    a->st = pc_get(h, a->url, 0, body, sizeof body, &a->err, &a->ms);
    t_inet_close(h); return 0;
}
TEST(pc_fail_dns_invalid_direct) {
    static const char *urls[] = { "http://pc-dns.invalid/", "http://pc-dns-2.invalid:8080/x", "https://pc-dns.invalid/", "http://pcdnsplain/" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        static dns_arg a; memset(&a, 0, sizeof a); a.url = urls[i];
        if (!pc_bounded(dns_thread, &a, 15000)) { t_skip("name resolution for %s did not finish in 15 s", urls[i]); return; }
        t_note("%s -> status %d err %lu (%s) %lu ms", urls[i], a.st, a.err, t_inet_errname(a.err), a.ms);
        if (a.ms > 10000) { t_note("slow resolver (%lu ms): not asserting", a.ms); continue; }
        EXPECT_EQ(a.st, 0);
        EXPECT_EQ(a.err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    }
}

TEST(pc_fail_dns_invalid_httpopenrequest) {
    HINTERNET h = open_direct(5000);
    SetLastError(0xdeadbeef);
    HINTERNET hc = U(InternetConnectA)(h, "pc-dns3.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);   /* no I/O at InternetConnect for HTTP */
    EXPECT_ERR(0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    SetLastError(0xdeadbeef);
    CHECK(!U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_ERR(ERROR_INTERNET_NAME_NOT_RESOLVED);
    /* a second send on the same handle fails the same way */
    SetLastError(0xdeadbeef);
    CHECK(!U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_ERR(ERROR_INTERNET_NAME_NOT_RESOLVED);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(h);
}

TEST(pc_fail_dns_invalid_ftp) {
    HINTERNET h = open_direct(5000);
    SetLastError(0xdeadbeef);
    HINTERNET hc = U(InternetConnectA)(h, "pc-ftp.invalid", 21, "anonymous", "x@", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    DWORD e = GetLastError();
    CHECK(hc == NULL);
    EXPECT_EQ(e, ERROR_INTERNET_NAME_NOT_RESOLVED);
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(h);
}

/* ------------------------------------------------------------------ receive timeout */
TEST(pc_fail_receive_timeout) {
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late") };
    HTTP_OR_SKIP(s, st);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    pc_set_timeouts(h, 5000, 5000, 800);
    char body[16]; DWORD err, ms;
    EXPECT_EQ(pc_get(h, srv_url(s, "/slow"), 0, body, sizeof body, &err, &ms), 0);
    EXPECT_EQ(err, ERROR_INTERNET_TIMEOUT);
    t_note("receive timeout 800 ms: %lu ms, requests %d", ms, srv_req_count(s));
    t_inet_close(h); srv_stop(s);
}

TEST(pc_fail_receive_timeout_mid_body) {
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"), S_SLEEP(3000), S_SEND("defghij") };
    HTTP_OR_SKIP(s, st);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    pc_set_timeouts(h, 5000, 5000, 800);
    HINTERNET hu = U(InternetOpenUrlA)(h, srv_url(s, "/midbody"), NULL, 0, T_INET_FRESH, 0);
    CHECK(hu != NULL);
    if (hu) {
        char buf[32]; DWORD rd = 0, total = 0; BOOL ok = TRUE; DWORD e = 0;
        for (int i = 0; i < 10; i++) { rd = 0; ok = U(InternetReadFile)(hu, buf + total, sizeof buf - 1 - total, &rd); if (!ok) { e = GetLastError(); break; } if (!rd) break; total += rd; }
        t_note("mid-body stall: ok %d err %lu (%s) total %lu", ok, e, t_inet_errname(e), total);
        CHECK(!ok);
        EXPECT_EQ(e, ERROR_INTERNET_TIMEOUT);
        EXPECT_EQ(total, 3);
        U(InternetCloseHandle)(hu);
    }
    t_inet_close(h); srv_stop(s);
}

TEST(pc_fail_receive_timeout_via_proxy) {
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late") };
    HTTP_OR_SKIP(p, st);
    HINTERNET h = pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(p), NULL, 0);
    pc_set_timeouts(h, 5000, 5000, 800);
    char body[16]; DWORD err, ms;
    EXPECT_EQ(pc_get(h, "http://pc-slow.invalid/", 0, body, sizeof body, &err, &ms), 0);
    EXPECT_EQ(err, ERROR_INTERNET_TIMEOUT);
    t_inet_close(h); srv_stop(p);
}

/* ------------------------------------------------------------------ server misbehaviour at each stage */
typedef struct { const char *name; const srv_step *steps; int n; int want_status; DWORD want_err; int certain; } stage_case;
#define STEPS(...) (const srv_step[]){ __VA_ARGS__ }, (int)(sizeof((const srv_step[]){ __VA_ARGS__ }) / sizeof(srv_step))

static void run_stage(const stage_case *c, int via_proxy) {
    srv_script sc = { c->steps, c->n };
    srv_config cfg = { SRV_HTTP, &sc, 1 }; srv *s;
    int rc = srv_start(&cfg, &s);
    if (rc) { CHECKF(0, "%s: server %s", c->name, srv_strerror(rc)); return; }
    HINTERNET h = via_proxy ? pc_open("pc_agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(s), NULL, 3000) : pc_open("pc_agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 3000);
    char body[64]; DWORD err, ms;
    int st = pc_get(h, via_proxy ? "http://pc-stage.invalid/s" : srv_url(s, "/s"), 0, body, sizeof body, &err, &ms);
    t_note("%s%s: status %d err %lu (%s) body \"%s\" requests %d conns %d %lu ms", via_proxy ? "proxy " : "", c->name, st, err, t_inet_errname(err),
           body, srv_req_count(s), srv_conn_count(s), ms);
    if (c->certain) {
        CHECKF(st == c->want_status, "%s%s: status %d want %d", via_proxy ? "proxy " : "", c->name, st, c->want_status);
        if (!c->want_status) CHECKF(err == c->want_err, "%s%s: err %lu (%s) want %lu (%s)", via_proxy ? "proxy " : "", c->name, err, t_inet_errname(err),
                                    c->want_err, t_inet_errname(c->want_err));
    }
    t_inet_close(h); srv_stop(s);
}

static const stage_case k_stages[] = {
    { "close without response", STEPS(S_HEAD(), S_CLOSE()), 0, ERROR_HTTP_INVALID_SERVER_RESPONSE, 1 },
    { "reset without response", STEPS(S_HEAD(), S_RESET()), 0, ERROR_INTERNET_CONNECTION_RESET, 0 },
    { "close mid status line", STEPS(S_HEAD(), S_SEND("HTTP/1.1 2"), S_CLOSE()), 0, ERROR_HTTP_INVALID_SERVER_RESPONSE, 0 },
    { "close mid headers", STEPS(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Le"), S_CLOSE()), 0, ERROR_HTTP_INVALID_SERVER_RESPONSE, 0 },
    { "close after header line", STEPS(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nX-A: 1\r\n"), S_CLOSE()), 0, ERROR_HTTP_INVALID_SERVER_RESPONSE, 0 },
    { "reset mid headers", STEPS(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Le"), S_RESET()), 0, ERROR_INTERNET_CONNECTION_RESET, 0 },
    { "headers then close (no length)", STEPS(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\nbody"), S_CLOSE()), 200, 0, 1 },
    { "garbage instead of status line", STEPS(S_HEAD(), S_SEND("garbage here\r\n\r\n"), S_CLOSE()), 200, 0, 0 },
    { "truncated body", STEPS(S_HEAD(), S_REPLYF(200, NULL, "0123456789", SRV_R_TRUNCATE)), 200, 0, 1 },
    { "reset mid body", STEPS(S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789"), S_SLEEP(200), S_RESET()), 200, 0, 0 },
    { "HTTP/1.0 close-delimited", STEPS(S_HEAD(), S_REPLYF(200, NULL, "ten bytes!", SRV_R_HTTP10 | SRV_R_CLOSE)), 200, 0, 1 },
};

TEST(pc_fail_stages_direct) {
    for (size_t i = 0; i < sizeof k_stages / sizeof k_stages[0]; i++) run_stage(&k_stages[i], 0);
}
TEST(pc_fail_stages_via_proxy) {
    for (size_t i = 0; i < sizeof k_stages / sizeof k_stages[0]; i++) run_stage(&k_stages[i], 1);
}

TEST(pc_fail_reset_mid_body_read_error) {
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789"), S_SLEEP(300), S_RESET() };
    HTTP_OR_SKIP(s, st);
    HINTERNET h = open_direct(3000);
    HINTERNET hu = U(InternetOpenUrlA)(h, srv_url(s, "/rb"), NULL, 0, T_INET_FRESH, 0);
    CHECK(hu != NULL);
    if (hu) {
        char buf[128]; DWORD total = 0, e = 0; BOOL ok = TRUE;
        for (int i = 0; i < 20; i++) { DWORD rd = 0; ok = U(InternetReadFile)(hu, buf + total, sizeof buf - 1 - total, &rd); if (!ok) { e = GetLastError(); break; } if (!rd) break; total += rd; }
        t_note("reset mid body: ok %d err %lu (%s) total %lu", ok, e, t_inet_errname(e), total);
        EXPECT_EQ(total, 10);
        U(InternetCloseHandle)(hu);
    }
    t_inet_close(h); srv_stop(s);
}

/* a stale keep-alive connection that the server closed is retried transparently on a new connection */
TEST(pc_fail_stale_keepalive_retried) {
    static const srv_step c0[] = { S_HEAD(), S_REPLYF(200, NULL, "first", SRV_R_KEEPALIVE), S_HEAD(), S_CLOSE() };
    static const srv_step c1[] = { S_HEAD(), S_REPLY(200, NULL, "second"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(c0), SRV_SCRIPT(c1) };
    srv_config cfg = { SRV_HTTP, sc, 2 }; srv *s;
    START_OR_SKIP(&cfg, &s);
    HINTERNET h = open_direct(3000);
    char body[32]; DWORD err;
    EXPECT_EQ(pc_get(h, srv_url(s, "/1"), 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "first");
    EXPECT_EQ(pc_get(h, srv_url(s, "/2"), 0, body, sizeof body, &err, NULL), 200);
    EXPECT_STR(body, "second");
    t_note("stale keep-alive: requests %d conns %d", srv_req_count(s), srv_conn_count(s));
    EXPECT_EQ(srv_conn_count(s), 2);
    CHECK(srv_req_count(s) >= 2);
    if (srv_req_count(s) == 3) { EXPECT_STR(srv_req_line(s, 1), "GET /2 HTTP/1.1"); EXPECT_STR(srv_req_line(s, 2), "GET /2 HTTP/1.1"); }
    t_inet_close(h); srv_stop(s);
}

/* ------------------------------------------------------------------ error text */
TEST(pc_fail_error_text_available) {
    HMODULE m = t_module("wininet.dll");
    REQUIRE(m);
    static const DWORD codes[] = { ERROR_INTERNET_TIMEOUT, ERROR_INTERNET_NAME_NOT_RESOLVED, ERROR_INTERNET_CANNOT_CONNECT,
        ERROR_INTERNET_CONNECTION_ABORTED, ERROR_INTERNET_CONNECTION_RESET, ERROR_HTTP_INVALID_SERVER_RESPONSE,
        ERROR_INTERNET_PROXY_SERVER_UNREACHABLE, ERROR_INTERNET_BAD_AUTO_PROXY_SCRIPT, ERROR_INTERNET_INVALID_PROXY_REQUEST,
        ERROR_INTERNET_NOT_PROXY_REQUEST, ERROR_INTERNET_AUTODETECTION_FAILED, ERROR_INTERNET_DISCONNECTED };
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        char msg[512] = { 0 };
        DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, m, codes[i], 0, msg, sizeof msg, NULL);
        CHECKF(n > 0, "no message for %lu (err %lu)", codes[i], GetLastError());
        if (i < 3) t_note("%lu: %s", codes[i], msg);
    }
}

TEST(pc_fail_last_response_info_after_failure) {
    HINTERNET h = open_direct(3000);
    char body[16]; DWORD err;
    EXPECT_EQ(pc_get(h, "http://pc-lri.invalid/", 0, body, sizeof body, &err, NULL), 0);
    EXPECT_EQ(err, ERROR_INTERNET_NAME_NOT_RESOLVED);
    DWORD e2 = 0xdead, l = 0; char buf[256];
    l = sizeof buf; buf[0] = 'x';
    BOOL ok = U(InternetGetLastResponseInfoA)(&e2, buf, &l);
    t_note("last response info: ok %d err %lu len %lu", ok, e2, l);
    CHECK(ok);
    t_inet_close(h);
}
