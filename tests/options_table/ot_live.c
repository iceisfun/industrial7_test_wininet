/* options_table: options observed on live handles (socket info mid-body, URL after a redirect, user agent on the
 * wire, receive timeout effect, hidden connect of InternetOpenUrl, FTP/file kinds), plus the set-only
 * options ERROR_MASK (62), SUPPRESS_BEHAVIOR (81) and the CONNECTED_STATE (50) set. Loopback servers only.
 * Per-process options (81, 50) run in a child process so their globals cannot leak into the rest of the area.
 * Decomp (corpus explorer): InternetQueryOptionA@0x59730 case 0x43 DIAGNOSTIC_SOCKET_INFO (request handles only;
 *   Socket = GetSocket(), ports from the socket object at +0x4b0 or 0, Flags = KEEP_ALIVE(+0x4c0 != 0) |
 *   SECURE(socket virtual) | PROXY(+0x1420 != 0) | TUNNEL(+0x149c bit 9)), case 0x22 URL (request/FTP handles: the
 *   current URL string), case 0x15 PARENT_HANDLE;
 *   InternetSetOptionA@0x551b0 case 0x29 USER_AGENT (session +0x110), case 0x3e ERROR_MASK (length 4; bits outside
 *   0xB -> 87), case 0x51 SUPPRESS_BEHAVIOR (length 4; 0 and 4 clear the cookie-persist suppression, 1 and 2 accepted,
 *   3 purges the in-memory cookie jar (never used here), anything else 87), case 0x32 CONNECTED_STATE (length 8
 *   accepted and otherwise ignored for a non-lowbox process, else 12010).
 * VM_TIMEOUT: 400 */
#include "ot.h"

/* ------------------------------------------------------------------ DIAGNOSTIC_SOCKET_INFO on a live connection */
static void socket_info_mid_body(int tls) {
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, "Content-Type: application/octet-stream\r\n", 65536, 0), S_LOOP() };
    srv *sv = tls ? srv_https(st, 3, SRV_CERT_LOCALHOST) : srv_http(st, 3);
    if (!sv) { t_skip("server unavailable (%s)", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(sv), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/big", NULL, NULL, NULL, T_INET_FRESH | (tls ? INTERNET_FLAG_SECURE : 0), 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        if (tls) t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        CHECKF(ok, "send err %lu", GetLastError());
        if (ok) {
            char b[16]; DWORD rd = 0;
            CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd) && rd == sizeof b);
            INTERNET_DIAGNOSTIC_SOCKET_INFO di; DWORD l = sizeof di; memset(&di, 0xCC, sizeof di);
            CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l));
            EXPECT_EQ(l, sizeof di);
            CHECKF(di.Socket != (DWORD_PTR)~(DWORD_PTR)0 && di.Socket != 0, "socket 0x%llx", (unsigned long long)di.Socket);
            CHECKF(di.DestPort == srv_port(sv), "dest port %lu want %u", di.DestPort, srv_port(sv));
            CHECKF(di.SourcePort != 0 && di.SourcePort != di.DestPort, "source port %lu", di.SourcePort);
            CHECKF(!!(di.Flags & IDSI_FLAG_SECURE) == !!tls, "flags 0x%lx (tls %d)", di.Flags, tls);
            CHECKF(!(di.Flags & (IDSI_FLAG_PROXY | IDSI_FLAG_TUNNEL)), "flags 0x%lx (direct, no proxy)", di.Flags);
            t_note("%s mid-body socket info: src %lu dst %lu flags 0x%lx", tls ? "HTTPS" : "HTTP", di.SourcePort, di.DestPort, di.Flags);
            /* W forwards the same structure */
            INTERNET_DIAGNOSTIC_SOCKET_INFO dw; l = sizeof dw;
            CHECK(U(InternetQueryOptionW)(hr, INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &dw, &l));
            CHECK(l == sizeof dw && dw.Socket == di.Socket && dw.SourcePort == di.SourcePort && dw.DestPort == di.DestPort && dw.Flags == di.Flags);
            /* fixed size: one byte short -> 122 with the size */
            l = sizeof di - 1; SET_ERR(0);
            EXPECT_FAIL(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l), ERROR_INSUFFICIENT_BUFFER);
            EXPECT_EQ(l, sizeof di);
            /* read to the end: the connection goes back to the pool and the request reports no socket */
            static char rest[70000]; size_t n = t_inet_read_all(hr, rest, sizeof rest, NULL);
            EXPECT_EQ(n, 65536 - 16);
            l = sizeof di; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l));
            CHECKF(di.Socket == (DWORD_PTR)~(DWORD_PTR)0 && di.SourcePort == 0 && di.DestPort == 0 && di.Flags == 0,
                   "after the body: socket=0x%llx src=%lu dst=%lu flags=0x%lx", (unsigned long long)di.Socket, di.SourcePort, di.DestPort, di.Flags);
        }
        U(InternetCloseHandle)(hr);
    }
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi);
    srv_stop(sv);
}
TEST(ot_live_socket_info_mid_body_http) { REQUIRE(U(InternetQueryOptionA)); socket_info_mid_body(0); }
TEST(ot_live_socket_info_mid_body_https) { REQUIRE(U(InternetQueryOptionA)); socket_info_mid_body(1); }

TEST(ot_live_socket_info_handle_gates) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    /* case 0x43: request handles only (the file: URL handle is not an HTTP request) */
    static const int ks[] = { OT_S, OT_C, OT_F, OT_L };
    for (int i = 0; i < 4; i++) {
        if (!fx->h[ks[i]]) continue;
        for (int w = 0; w < 2; w++) {
            INTERNET_DIAGNOSTIC_SOCKET_INFO di; DWORD l = sizeof di;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, fx->h[ks[i]], INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        }
    }
    INTERNET_DIAGNOSTIC_SOCKET_INFO di; DWORD l = sizeof di;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    /* not settable: 12009 on a request (set matrix row 67) */
    if (fx->h[OT_R]) { SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(fx->h[OT_R], INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, sizeof di), ERROR_INTERNET_INVALID_OPTION); }
}

/* ------------------------------------------------------------------ URL follows redirects */
static int redir_fn(srv_conn *c, const srv_step *st, void *u) {
    (void)st; (void)u;
    srv *s = srv_conn_server(c); const char *t = srv_req_target(s, srv_conn_last_req(c));
    if (t && !strcmp(t, "/from")) return srv_conn_sendf(c, "HTTP/1.1 302 Found\r\nLocation: /to/end?q=1\r\nContent-Length: 0\r\n\r\n") ? -1 : 0;
    return srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal") ? -1 : 0;
}

TEST(ot_live_url_after_redirect) {
    REQUIRE(U(InternetQueryOptionW));
    static const srv_step st[] = { S_HEAD(), S_CALL(redir_fn), S_LOOP() };
    srv *sv = srv_http(st, 3); if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(sv), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    char want_from[128], want_to[128];
    snprintf(want_from, sizeof want_from, "%s", srv_url(sv, "/from"));
    snprintf(want_to, sizeof want_to, "%s", srv_url(sv, "/to/end?q=1"));
    for (int noauto = 0; noauto < 2 && hc; noauto++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/from", NULL, NULL, NULL, T_INET_FRESH | (noauto ? INTERNET_FLAG_NO_AUTO_REDIRECT : 0), 0);
        if (!hr) { CHECK(hr != NULL); continue; }
        char u[256]; DWORD l = sizeof u;
        CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, u, &l)); EXPECT_STR(u, want_from);
        CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "send err %lu", GetLastError());
        char b[16]; t_inet_read_all(hr, b, sizeof b, NULL);
        DWORD code = 0, cl = sizeof code;
        U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &cl, NULL);
        EXPECT_EQ(code, noauto ? 302 : 200);
        const char *want = noauto ? want_from : want_to;
        l = sizeof u; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, u, &l));
        EXPECT_STR(u, want); EXPECT_EQ(l, strlen(want));
        WCHAR wu[256]; l = sizeof wu;
        CHECK(U(InternetQueryOptionW)(hr, INTERNET_OPTION_URL, wu, &l));
        EXPECT_EQ(l, strlen(want));
        l = 0; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(hr, INTERNET_OPTION_URL, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, (strlen(want) + 1) * 2);
        U(InternetCloseHandle)(hr);
    }
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ USER_AGENT reaches the wire */
TEST(ot_live_user_agent_on_wire) {
    REQUIRE(U(InternetSetOptionW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "", "hello"), S_LOOP() };
    srv *sv = srv_http(st, 3); if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = U(InternetOpenA)("ot-ua-initial", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(sv), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (!c) { if (s) U(InternetCloseHandle)(s); srv_stop(sv); t_skip("handles"); return; }
    HINTERNET r0 = U(HttpOpenRequestA)(c, "GET", "/r0", NULL, NULL, NULL, T_INET_FRESH, 0);   /* before the change */
    CHECK(U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)"ot-ua-A/1.0", 11));
    static const char *paths[] = { "/r1", "/r2" };
    for (int i = 0; i < 2; i++) {
        if (i == 1) CHECK(U(InternetSetOptionW)(s, INTERNET_OPTION_USER_AGENT, (void *)L"ot-ua-W/2.0", 11));
        HINTERNET r = U(HttpOpenRequestA)(c, "GET", paths[i], NULL, NULL, NULL, T_INET_FRESH, 0);
        CHECK(r != NULL);
        if (!r) continue;
        int before = srv_req_count(sv);
        CHECKF(U(HttpSendRequestA)(r, NULL, 0, NULL, 0), "send err %lu", GetLastError());
        char b[16]; t_inet_read_all(r, b, sizeof b, NULL);
        CHECK(srv_req_count(sv) == before + 1);
        EXPECT_STR(srv_req_header(sv, before, "User-Agent"), i ? "ot-ua-W/2.0" : "ot-ua-A/1.0");
        U(InternetCloseHandle)(r);
    }
    if (r0) {
        int before = srv_req_count(sv);
        if (U(HttpSendRequestA)(r0, NULL, 0, NULL, 0)) {
            char b[16]; t_inet_read_all(r0, b, sizeof b, NULL);
            const char *ua = srv_req_count(sv) > before ? srv_req_header(sv, before, "User-Agent") : NULL;
            t_note("request opened before the USER_AGENT change sends User-Agent '%s'", ua ? ua : "(none)");
        } else t_note("r0 send err %lu", GetLastError());
        U(InternetCloseHandle)(r0);
    }
    U(InternetCloseHandle)(c); U(InternetCloseHandle)(s);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ RECEIVE_TIMEOUT on the request takes effect */
TEST(ot_live_receive_timeout_effect) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_SLEEP(4000), S_REPLY(200, "", "late") };
    srv *sv = srv_http(st, 3); if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(sv), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/slow", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        CHECK(ot_sdw(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, 500));
        DWORD t0 = GetTickCount();
        SET_ERR(0);
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        DWORD dt = GetTickCount() - t0;
        EXPECT_FAIL(!ok, ERROR_INTERNET_TIMEOUT);
        t_note("request with RECEIVE_TIMEOUT 500 failed after %lu ms (server answers after 4000 ms)", dt);
        U(InternetCloseHandle)(hr);
    }
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ InternetOpenUrl: the hidden connect handle */
TEST(ot_live_open_url_hidden_connect) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "", "hello"), S_LOOP() };
    srv *sv = srv_http(st, 3); if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hu = s ? U(InternetOpenUrlA)(s, srv_url(sv, "/u"), NULL, 0, T_INET_FRESH, 0x77) : NULL;
    CHECKF(hu != NULL, "InternetOpenUrl err %lu", GetLastError());
    if (hu) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_HANDLE_TYPE, &t, &l)); EXPECT_EQ(t, INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        HINTERNET p = NULL; l = sizeof p;
        CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_PARENT_HANDLE, &p, &l));
        CHECKF(p != NULL && p != s, "parent %p session %p", p, s);
        if (p && p != s) {
            l = sizeof t; CHECK(U(InternetQueryOptionA)(p, INTERNET_OPTION_HANDLE_TYPE, &t, &l)); EXPECT_EQ(t, INTERNET_HANDLE_TYPE_CONNECT_HTTP);
            HINTERNET pp = NULL; l = sizeof pp;
            CHECK(U(InternetQueryOptionA)(p, INTERNET_OPTION_PARENT_HANDLE, &pp, &l)); EXPECT_EQ(pp, s);
        }
        ULONGLONG ctx = 0; l = sizeof ctx;
        CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_CONTEXT_VALUE, &ctx, &l)); EXPECT_EQ(ctx, 0x77);
        char u[256]; l = sizeof u;
        CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_URL, u, &l)); EXPECT_STR(u, srv_url(sv, "/u"));
        char b[16]; t_inet_read_all(hu, b, sizeof b, NULL);
        U(InternetCloseHandle)(hu);
    }
    if (s) U(InternetCloseHandle)(s);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ FTP connect and file: URL handles */
TEST(ot_live_parent_context_ftp_and_file) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    static const int ks[] = { OT_F, OT_L };
    int seen = 0;
    for (int i = 0; i < 2; i++) {
        HINTERNET h = fx->h[ks[i]]; if (!h) { t_note("kind %c missing", OT_KINDS[ks[i]]); continue; }
        seen++;
        HINTERNET p = NULL; DWORD l = sizeof p;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PARENT_HANDLE, &p, &l));
        CHECKF(p == fx->h[OT_S], "kind %c parent %p session %p", OT_KINDS[ks[i]], p, fx->h[OT_S]);
        ULONGLONG v = 1; l = sizeof v;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); EXPECT_EQ(v, 0);
        ULONGLONG nv = 0xA1B2C3D4E5F60718ull;
        CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &nv, 8));
        l = sizeof v; CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); CHECK(v == nv);
        nv = 0; CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &nv, 8));   /* restore the shared fixture */
    }
    CHECK(seen > 0);
}

TEST(ot_live_ftp_connect_timeouts) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_file files[] = { { "/a.txt", "a", 1, "20200102030405" } };
    srv_ftp_config fc = { files, 1 }; srv_config cfg = { SRV_FTP }; cfg.ftp = &fc; srv *sv;
    if (srv_start(&cfg, &sv)) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { srv_stop(sv); t_skip("InternetOpen"); return; }
    CHECK(ot_sdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, 4567));
    CHECK(ot_sdw(s, INTERNET_OPTION_CONNECT_TIMEOUT, 4321));
    HINTERNET f = U(InternetConnectA)(s, "127.0.0.1", srv_port(sv), "anonymous", "x@y", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECKF(f != NULL, "FTP connect err %lu", GetLastError());
    if (f) {
        DWORD v;
        CHECK(ot_qdw(f, INTERNET_OPTION_RECEIVE_TIMEOUT, &v)); EXPECT_EQ(v, 4567);
        CHECK(ot_qdw(f, INTERNET_OPTION_CONNECT_TIMEOUT, &v)); EXPECT_EQ(v, 4321);
        CHECK(ot_sdw(f, INTERNET_OPTION_RECEIVE_TIMEOUT, 7654));
        CHECK(ot_qdw(f, INTERNET_OPTION_RECEIVE_TIMEOUT, &v)); EXPECT_EQ(v, 7654);
        CHECK(ot_qdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v)); EXPECT_EQ(v, 4567);
        /* HTTP-only options on an FTP connect */
        DWORD l = sizeof v;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(f, INTERNET_OPTION_REQUEST_FLAGS, &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(f, INTERNET_OPTION_SECURITY_FLAGS, 0x100), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        U(InternetCloseHandle)(f);
    }
    U(InternetCloseHandle)(s);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ ERROR_MASK (62): set-only, per handle */
TEST(ot_live_error_mask_values) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c, t.r };
    static const DWORD good[] = { 0, INTERNET_ERROR_MASK_INSERT_CDROM, INTERNET_ERROR_MASK_COMBINED_SEC_CERT,
                                  INTERNET_ERROR_MASK_LOGIN_FAILURE_DISPLAY_ENTITY_BODY, 0xB };
    static const DWORD bad[] = { INTERNET_ERROR_MASK_NEED_MSN_SSPI_PKG, 0xF, 0x10, 0x80000000u, 0xFFFFFFFF };
    for (int k = 0; k < 3; k++)
        for (int w = 0; w < 2; w++) {
            for (int i = 0; i < 5; i++) { DWORD v = good[i]; SET_ERR(0); CHECKF(ot_s(w, hs[k], INTERNET_OPTION_ERROR_MASK, &v, 4), "%c %c mask 0x%lx err %lu", "SCR"[k], w ? 'W' : 'A', v, GetLastError()); }
            for (int i = 0; i < 5; i++) { DWORD v = bad[i]; SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], INTERNET_OPTION_ERROR_MASK, &v, 4), ERROR_INVALID_PARAMETER); }
            ULONGLONG v8 = 1;
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], INTERNET_OPTION_ERROR_MASK, &v8, 8), ERROR_INTERNET_BAD_OPTION_LENGTH);
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], INTERNET_OPTION_ERROR_MASK, &v8, 2), ERROR_INTERNET_BAD_OPTION_LENGTH);
            /* set-only: the query has no case for 62 */
            DWORD q, l = sizeof q;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, hs[k], INTERNET_OPTION_ERROR_MASK, &q, &l), ERROR_INVALID_PARAMETER);
        }
    DWORD v = 1;
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_ERROR_MASK, &v, 4), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    ot_trio_close(&t);
}

/* ------------------------------------------------------------------ per-process options, in a child */
static int g_bad;
#define CK(c, ...) do { if (!(c)) { printf("  LV MISMATCH line %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); g_bad++; } } while (0)
static DWORD set_e(HINTERNET h, DWORD opt, const void *p, DWORD n) {
    SetLastError(0xdead); return U(InternetSetOptionA)(h, opt, (void *)p, n) ? 0 : GetLastError();
}

static void sc_suppress(void) {
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hs[] = { NULL, s };
    /* 3 (INTERNET_SUPPRESS_COOKIE_PERSIST) is never sent: it purges the in-memory cookie jar */
    static const DWORD ok[] = { INTERNET_SUPPRESS_RESET_ALL, INTERNET_SUPPRESS_COOKIE_POLICY, INTERNET_SUPPRESS_COOKIE_POLICY_RESET,
                                4 /* INTERNET_SUPPRESS_COOKIE_PERSIST_RESET */ };
    static const DWORD bad[] = { 5, 6, 0x10, 0x7fffffff, 0xffffffff };
    for (int k = 0; k < 2; k++) {
        if (k && !s) break;
        for (int i = 0; i < 4; i++) { DWORD e = set_e(hs[k], INTERNET_OPTION_SUPPRESS_BEHAVIOR, &ok[i], 4); CK(e == 0, "h%d value %lu: %lu", k, ok[i], e); }
        for (int i = 0; i < 5; i++) { DWORD e = set_e(hs[k], INTERNET_OPTION_SUPPRESS_BEHAVIOR, &bad[i], 4); CK(e == 87, "h%d value 0x%lx: %lu", k, bad[i], e); }
        ULONGLONG z = 0;
        DWORD e = set_e(hs[k], INTERNET_OPTION_SUPPRESS_BEHAVIOR, &z, 8); CK(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "h%d len 8: %lu", k, e);
        e = set_e(hs[k], INTERNET_OPTION_SUPPRESS_BEHAVIOR, &z, 3); CK(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "h%d len 3: %lu", k, e);
        DWORD q, l = sizeof q; SetLastError(0xdead);
        BOOL r = U(InternetQueryOptionA)(hs[k], INTERNET_OPTION_SUPPRESS_BEHAVIOR, &q, &l);
        CK(!r && GetLastError() == 87, "h%d query r=%d e=%lu (set-only)", k, r, GetLastError());
    }
    if (s) U(InternetCloseHandle)(s);
}

static void sc_connected(void) {
    DWORD v = 0, l = sizeof v;
    CK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &v, &l) && v == 1 && l == 4, "initial CONNECTED_STATE %lu", v);
    INTERNET_CONNECTED_INFO ci = { INTERNET_STATE_CONNECTED, 0 };
    DWORD e = set_e(NULL, INTERNET_OPTION_CONNECTED_STATE, &ci, sizeof ci); CK(e == 0, "set CONNECTED: %lu", e);
    e = set_e(NULL, INTERNET_OPTION_CONNECTED_STATE, &ci, 4); CK(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "len 4: %lu", e);
    e = set_e(NULL, INTERNET_OPTION_CONNECTED_STATE, &ci, 12); CK(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "len 12: %lu", e);
    /* the 8-byte set is accepted and ignored: going offline does not stick */
    INTERNET_CONNECTED_INFO off = { INTERNET_STATE_DISCONNECTED_BY_USER, ISO_FORCE_DISCONNECTED };
    e = set_e(NULL, INTERNET_OPTION_CONNECTED_STATE, &off, sizeof off); CK(e == 0, "set DISCONNECTED_BY_USER: %lu", e);
    v = 0; l = sizeof v;
    CK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &v, &l) && v == 1, "CONNECTED_STATE after the offline set %lu", v);
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (s) {
        v = 0; l = sizeof v;
        CK(U(InternetQueryOptionA)(s, INTERNET_OPTION_CONNECTED_STATE, &v, &l) && v == 1, "session CONNECTED_STATE %lu", v);
        e = set_e(s, INTERNET_OPTION_CONNECTED_STATE, &ci, sizeof ci); CK(e == 0, "set on a session: %lu", e);
        U(InternetCloseHandle)(s);
    }
    e = set_e(NULL, INTERNET_OPTION_CONNECTED_STATE, &ci, sizeof ci); CK(e == 0, "set CONNECTED back: %lu", e);
}

CHILD(ot_lv) {
    if (argc < 2 || !U(InternetSetOptionA)) return 0xC0DE0002;
    if (!strcmp(argv[1], "suppress")) sc_suppress();
    else if (!strcmp(argv[1], "connected")) sc_connected();
    else return 0xC0DE0003;
    printf("  LV %s mismatches=%d\n", argv[1], g_bad);
    fflush(stdout);
    return g_bad;
}

TEST(ot_live_suppress_behavior_values) {
    REQUIRE(U(InternetSetOptionA));
    DWORD rc = ot_run_child_io("ot_lv", "suppress", 20000);
    CHECKF(rc == 0, "child exit 0x%lx", rc);
}
TEST(ot_live_connected_state_set_ignored) {
    REQUIRE(U(InternetSetOptionA));
    DWORD rc = ot_run_child_io("ot_lv", "connected", 20000);
    CHECKF(rc == 0, "child exit 0x%lx", rc);
}
