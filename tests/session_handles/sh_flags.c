/* session_handles / what the InternetOpen access type and flags and the InternetConnect flags do to the handles below them:
 * OFFLINE (== FROM_CACHE) sessions and requests, named-proxy forms (scheme-specific lists, bypass entries, loopback),
 * VIA_PROXY request flag, ASYNC sessions (handle creation stays synchronous), FTP PASSIVE vs active data connections.
 * Evidence: [D InternalInternetOpen, InitBeginSendRequest (OFFLINE -> cache only), InternetQueryOptionA case 0x17
 * (REQUEST_FLAGS: +0x318 FROM_CACHE, +0x3bc VIA_PROXY, +0x3c0 NO_HEADERS, +0x31c CACHE_WRITE_DISABLED)], VM boots
 * (EVIDENCE.md). Cache entries are created only under unique URLs and removed (t_cache_track). VM_TIMEOUT: 240 */
#include "sh.h"

/* ------------------------------------------------------------------ OFFLINE */
TEST(sh_flags_offline_flag_value) {
    EXPECT_EQ(INTERNET_FLAG_OFFLINE, INTERNET_FLAG_FROM_CACHE);
    EXPECT_EQ(INTERNET_FLAG_OFFLINE, 0x01000000);
}

/* An OFFLINE session never touches the network for an uncached URL. */
TEST(sh_flags_offline_session_uncached_no_wire) {
    REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = (HINTERNET)t_inet_open_ex("offline", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    CHECK(s != NULL);
    char path[96]; snprintf(path, sizeof path, "/offline/%s", t_uniq("u"));
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", path, NULL, NULL, NULL, INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        SetLastError(0);
        BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
        DWORD e = GetLastError();
        t_note("OFFLINE session, uncached GET: ok=%d err %lu (%s)", ok, ok ? 0 : e, t_inet_errname(e));
        CHECK(!ok);
        { int c_ = !!(e == ERROR_FILE_NOT_FOUND); t_check(c_, __FILE__, __LINE__, "e == ERROR_FILE_NOT_FOUND", "err %lu want 2", e); }
        sh_close(r);
    }
    Sleep(200);
    EXPECT_EQ(srv_conn_count(sv), 0);
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}

/* The same through InternetOpenUrl, and with FROM_CACHE on the request of a normal session. */
TEST(sh_flags_from_cache_request_uncached_no_wire) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("fromcache");
    char path[96]; snprintf(path, sizeof path, "/fc/%s", t_uniq("u"));
    SetLastError(0);
    HINTERNET r = s ? U(InternetOpenUrlA)(s, srv_url(sv, path), NULL, 0, INTERNET_FLAG_FROM_CACHE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0) : NULL;
    DWORD e = GetLastError();
    t_note("OpenUrl FROM_CACHE uncached: h=%p err %lu (%s)", r, r ? 0 : e, t_inet_errname(e));
    CHECK(r == NULL);
    { int c_ = !!(e == ERROR_FILE_NOT_FOUND); t_check(c_, __FILE__, __LINE__, "e == ERROR_FILE_NOT_FOUND", "err %lu want 2", e); }
    if (r) sh_close(r);
    /* the OFFLINE session form through InternetOpenUrl */
    HINTERNET so = (HINTERNET)t_inet_open_ex("offline-ou", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    SetLastError(0);
    HINTERNET r2 = so ? U(InternetOpenUrlA)(so, srv_url(sv, path), NULL, 0, INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0) : NULL;
    e = GetLastError();
    CHECK(r2 == NULL);
    { int c_ = !!(e == ERROR_FILE_NOT_FOUND); t_check(c_, __FILE__, __LINE__, "e == ERROR_FILE_NOT_FOUND", "offline session OpenUrl err %lu want 2", e); }
    if (r2) sh_close(r2);
    Sleep(200);
    EXPECT_EQ(srv_conn_count(sv), 0);
    if (so) sh_close(so);
    if (s) sh_close(s);
    srv_stop(sv);
}

/* A cached response is served to an OFFLINE session without a request, and REQUEST_FLAGS shows FROM_CACHE. */
TEST(sh_flags_offline_session_serves_cached_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Cache-Control: max-age=86400\r\nContent-Type: text/plain\r\n", "cached-body"), S_LOOP() };
    srv *sv = srv_http(st, 3);
    if (!sv) { t_skip("server unavailable"); return; }
    char path[96]; snprintf(path, sizeof path, "/oc/%s.txt", t_uniq("c"));
    const char *url = srv_url(sv, path);
    char urlcopy[256]; snprintf(urlcopy, sizeof urlcopy, "%s", url);
    t_cache_track(urlcopy);
    HINTERNET on = sh_open_to("online");
    HINTERNET r = on ? U(InternetOpenUrlA)(on, urlcopy, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0) : NULL;
    { int c_ = !!(r != NULL); t_check(c_, __FILE__, __LINE__, "r != NULL", "online fetch err %lu", GetLastError()); }
    if (r) { char b[32]; t_inet_read_all(r, b, sizeof b, NULL); EXPECT_STR(b, "cached-body"); sh_close(r); }
    if (on) sh_close(on);
    CHECK(srv_wait_requests(sv, 1, 3000));
    int before = srv_req_count(sv);
    HINTERNET off = (HINTERNET)t_inet_open_ex("offline2", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    HINTERNET r2 = off ? U(InternetOpenUrlA)(off, urlcopy, NULL, 0, INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0) : NULL;
    { int c_ = !!(r2 != NULL); t_check(c_, __FILE__, __LINE__, "r2 != NULL", "offline fetch err %lu", GetLastError()); }
    if (r2) {
        DWORD f, len, e;
        CHECK(sh_qdw(r2, INTERNET_OPTION_REQUEST_FLAGS, &f, &len, &e));
        { int c_ = !!(f & INTERNET_REQFLAG_FROM_CACHE); t_check(c_, __FILE__, __LINE__, "f & INTERNET_REQFLAG_FROM_CACHE", "REQUEST_FLAGS 0x%lx", f); }
        EXPECT_EQ(f, INTERNET_REQFLAG_FROM_CACHE);   /* VM: exactly 1 */
        char b[32]; t_inet_read_all(r2, b, sizeof b, NULL); EXPECT_STR(b, "cached-body");
        sh_close(r2);
    }
    Sleep(200);
    EXPECT_EQ(srv_req_count(sv), before);
    if (off) sh_close(off);
    t_net_cleanup();
    srv_stop(sv);
}

/* ------------------------------------------------------------------ named proxy forms */
static HINTERNET sh_proxy_session(const char *proxy, const char *bypass) {
    HINTERNET s = U(InternetOpenA)("proxyform", INTERNET_OPEN_TYPE_PROXY, proxy, bypass, 0);
    if (s) { DWORD to = 5000; for (DWORD o = 2; o <= 8; o++) if (o != 3 && o != 4) U(InternetSetOptionA)(s, o, &to, sizeof to); }
    return s;
}
/* send GET http://host:port/path through session s; returns 1 if the send succeeded */
static int sh_send_via(HINTERNET s, const char *host, unsigned short port, const char *path, DWORD *flags_out) {
    HINTERNET c = U(InternetConnectA)(s, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET r = c ? sh_request(c, path, 0) : NULL;
    int ok = r && U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
    if (flags_out) { DWORD v = 0, l = 4; *flags_out = r && U(InternetQueryOptionA)(r, INTERNET_OPTION_REQUEST_FLAGS, &v, &l) ? v : 0xffffffff; }
    if (r) { char b[16]; t_inet_read_all(r, b, sizeof b, NULL); sh_close(r); }
    if (c) sh_close(c);
    return ok;
}

/* "http=host:port" applies to http only; "ftp=" / "https=" entries leave http direct. */
TEST(sh_flags_proxy_scheme_specific_lists) {
    REQUIRE(U(HttpSendRequestA));
    srv *px = srv_http(NULL, 0), *org = srv_http(NULL, 0);
    if (!px || !org) { srv_stop(px); srv_stop(org); t_skip("server unavailable"); return; }
    char pl[128];
    struct { const char *fmt; int via; } rows[] = {
        { "http=%s", 1 }, { "http=http://%s", 1 }, { "ftp=%s", 0 }, { "https=%s", 0 }, { "ftp=%s https=%s", 0 },
        { "http=%s;ftp=127.0.0.1:9", 1 }, { "%s", 1 },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        snprintf(pl, sizeof pl, rows[i].fmt, srv_hostport(px), srv_hostport(px));
        int pb = srv_req_count(px), ob = srv_req_count(org);
        HINTERNET s = sh_proxy_session(pl, NULL);
        { int c_ = !!(s != NULL); t_check(c_, __FILE__, __LINE__, "s != NULL", "InternetOpen(PROXY, \"%s\") err %lu", pl, GetLastError()); }
        if (!s) continue;
        /* target the origin server through a name, so only an explicit proxy can reach it... except the direct
         * rows, which go to the real origin by IP */
        DWORD f = 0;
        int ok;
        if (rows[i].via) ok = sh_send_via(s, "viahost.i7test.example", 80, "/v", &f);
        else ok = sh_send_via(s, "127.0.0.1", srv_port(org), "/d", &f);
        { int c_ = !!(ok); t_check(c_, __FILE__, __LINE__, "ok", "row %zu [%s]: send err %lu", i, pl, GetLastError()); }
        srv_wait_requests(rows[i].via ? px : org, (rows[i].via ? pb : ob) + 1, 2000);
        int pv = srv_req_count(px) - pb, ov = srv_req_count(org) - ob;
        { int c_ = !!(rows[i].via ? (pv == 1 && ov == 0) : (pv == 0 && ov == 1)); t_check(c_, __FILE__, __LINE__, "rows[i].via ? (pv == 1 && ov == 0) : (pv == 0 && ov == 1)", "row %zu [%s]: proxy got %d origin got %d", i, pl, pv, ov); }
        { int c_ = !!(rows[i].via ? (f & INTERNET_REQFLAG_VIA_PROXY) != 0 : (f & INTERNET_REQFLAG_VIA_PROXY) == 0); t_check(c_, __FILE__, __LINE__, "rows[i].via ? (f & INTERNET_REQFLAG_VIA_PROXY) != 0 : (f & INTERNET_REQFLAG_VIA_PROXY) == 0", "row %zu [%s]: REQUEST_FLAGS 0x%lx", i, pl, f); }
        if (rows[i].via && pv == 1) EXPECT_STR(srv_req_target(px, pb), "http://viahost.i7test.example/v");
        if (!rows[i].via && ov == 1) EXPECT_STR(srv_req_target(org, ob), "/d");
        sh_close(s);
    }
    srv_stop(px); srv_stop(org);
}

/* Bypass entries and loopback: every row goes direct on Win10, including a non-matching list and no list (VM). */
TEST(sh_flags_proxy_bypass_entries_for_loopback) {
    REQUIRE(U(HttpSendRequestA));
    srv *px = srv_http(NULL, 0), *org = srv_http(NULL, 0);
    if (!px || !org) { srv_stop(px); srv_stop(org); t_skip("server unavailable"); return; }
    struct { const char *bypass; int direct; } rows[] = {
        { "127.0.0.1", 1 }, { "127.0.0.*", 1 }, { "127.*", 1 }, { "*", 1 }, { "other.i7test.example;127.0.0.1", 1 },
        /* VM: 127.0.0.1 is never sent to a named proxy, whatever the bypass list says */
        { "other.i7test.example", 1 }, { "<local>", 1 }, { NULL, 1 }, { "", 1 },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        int pb = srv_req_count(px), ob = srv_req_count(org);
        HINTERNET s = sh_proxy_session(srv_hostport(px), rows[i].bypass);
        CHECK(s != NULL); if (!s) continue;
        DWORD f = 0;
        int ok = sh_send_via(s, "127.0.0.1", srv_port(org), "/b", &f);
        Sleep(100);
        int pv = srv_req_count(px) - pb, ov = srv_req_count(org) - ob;
        if (rows[i].direct == 1) {
            { int c_ = !!(ok && pv == 0 && ov == 1); t_check(c_, __FILE__, __LINE__, "ok && pv == 0 && ov == 1", "bypass [%s]: ok=%d proxy %d origin %d", rows[i].bypass, ok, pv, ov); }
            { int c_ = !!((f & INTERNET_REQFLAG_VIA_PROXY) == 0); t_check(c_, __FILE__, __LINE__, "(f & INTERNET_REQFLAG_VIA_PROXY) == 0", "bypass [%s]: flags 0x%lx", rows[i].bypass, f); }
        } else {
            t_note("bypass [%s], target 127.0.0.1: ok=%d via proxy %d direct %d flags 0x%lx", rows[i].bypass ? rows[i].bypass : "(null)", ok, pv, ov, f);
            CHECK(pv + ov == 1);
        }
        sh_close(s);
    }
    srv_stop(px); srv_stop(org);
}

/* "<local>" bypasses dotless names: a request to a dotless host with a bypass of <local> is not sent to the proxy. */
TEST(sh_flags_proxy_local_bypasses_dotless_names) {
    REQUIRE(U(HttpSendRequestA));
    srv *px = srv_http(NULL, 0);
    if (!px) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_proxy_session(srv_hostport(px), "<local>");
    if (s) { DWORD to = 2000; U(InternetSetOptionA)(s, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to); }
    DWORD f = 0;
    /* "i7dotless" is not resolvable: the direct attempt fails quickly; what matters is that the proxy never sees it */
    int ok = s ? sh_send_via(s, "i7nosuchdotlesshost", 80, "/l", &f) : 0;
    DWORD e = GetLastError();
    Sleep(200);
    t_note("<local> bypass, dotless host: ok=%d err %lu proxy requests %d", ok, e, srv_req_count(px));
    EXPECT_EQ(srv_req_count(px), 0);
    /* a dotted name still uses the proxy */
    int ok2 = s ? sh_send_via(s, "dotted.i7test.example", 80, "/m", &f) : 0;
    CHECK(ok2);
    CHECK(srv_wait_requests(px, 1, 2000));
    if (s) sh_close(s);
    srv_stop(px);
}

/* The proxy settings of one session do not leak into another DIRECT session in the same process. */
TEST(sh_flags_proxy_session_isolated) {
    REQUIRE(U(HttpSendRequestA));
    srv *px = srv_http(NULL, 0), *org = srv_http(NULL, 0);
    if (!px || !org) { srv_stop(px); srv_stop(org); t_skip("server unavailable"); return; }
    HINTERNET sp = sh_proxy_session(srv_hostport(px), NULL);
    HINTERNET sd = sh_open_to("direct-next-to-proxy");
    CHECK(sp && sd);
    DWORD f = 0;
    if (sd) CHECK(sh_send_via(sd, "127.0.0.1", srv_port(org), "/direct", &f));
    CHECK(srv_wait_requests(org, 1, 2000));
    EXPECT_EQ(srv_req_count(px), 0);
    CHECK((f & INTERNET_REQFLAG_VIA_PROXY) == 0);
    if (sp) CHECK(sh_send_via(sp, "iso.i7test.example", 80, "/p", &f));
    CHECK(srv_wait_requests(px, 1, 2000));
    if (sp) sh_close(sp);
    if (sd) sh_close(sd);
    srv_stop(px); srv_stop(org);
}

/* A proxy that is not listening: 12029 and the request is not retried direct. */
TEST(sh_flags_proxy_dead_no_direct_fallback) {
    REQUIRE(U(HttpSendRequestA));
    srv *org = srv_http(NULL, 0);
    unsigned short dead = sh_dead_port();
    if (!org || !dead) { srv_stop(org); t_skip("server unavailable"); return; }
    char pl[64]; snprintf(pl, sizeof pl, "127.0.0.1:%u", dead);
    HINTERNET s = sh_proxy_session(pl, NULL);
    /* 5 s connect timeout: a refused loopback connect takes ~2 s on Windows; 2 s gives 12002 (VM) */
    HINTERNET c = s ? sh_connect(s, "deadproxy.i7test.example", 80, 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/x", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        SetLastError(0);
        EXPECT_FAIL(!U(HttpSendRequestA)(r, NULL, 0, NULL, 0), ERROR_INTERNET_CANNOT_CONNECT);
        sh_close(r);
    }
    EXPECT_EQ(srv_conn_count(org), 0);
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(org);
}

/* ------------------------------------------------------------------ ASYNC session: handle creation is synchronous */
static sh_cb_rec g_flags_rec;
TEST(sh_flags_async_session_handles_created_synchronously) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_flags_rec); sh_cb_cur = &g_flags_rec;
    HINTERNET s = U(InternetOpenA)("async-create", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    U(InternetSetStatusCallbackA)(s, sh_cb);
    SetLastError(0xdeadbeef);
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0x91);
    CHECK(c != NULL);
    EXPECT_EQ(GetLastError(), 0);
    SetLastError(0xdeadbeef);
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0x92) : NULL;
    CHECK(r != NULL);
    EXPECT_EQ(GetLastError(), 0);
    /* HANDLE_CREATED is delivered synchronously on this thread */
    int k = sh_cb_first(&g_flags_rec, INTERNET_STATUS_HANDLE_CREATED, 0x92);
    CHECK(k >= 0);
    if (k >= 0) EXPECT_EQ(g_flags_rec.ev[k].tid, GetCurrentThreadId());
    if (r) {
        DWORD v, len, e;
        CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(v, INTERNET_REQFLAG_NO_HEADERS);   /* VM: no ASYNC bit */
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
    sh_cb_cur = NULL;
}

/* INTERNET_FLAG_ASYNC on InternetConnect of a synchronous session does not make the session async: a send blocks
 * and returns TRUE directly. */
TEST(sh_flags_async_connect_flag_on_sync_session) {
    REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("sync-session");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(sv), NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_ASYNC, 1) : NULL;
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/sync", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_ASYNC, 2) : NULL;
    CHECK(r != NULL);
    if (r) {
        SetLastError(0);
        BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
        { int c_ = !!(ok); t_check(c_, __FILE__, __LINE__, "ok", "send err %lu", GetLastError()); }
        DWORD code = 0, cl = sizeof code;
        CHECK(U(HttpQueryInfoA)(r, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &code, &cl, NULL)); EXPECT_EQ(code, 200);
        sh_close(r);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ FTP PASSIVE vs active */
static int sh_ftp_cmd_seen(srv *f, const char *p1, const char *p2) {
    for (int i = 0; i < srv_ftp_cmd_count(f); i++) {
        const char *c = srv_ftp_cmd(f, i);
        if (!strncmp(c, p1, strlen(p1)) || (p2 && !strncmp(c, p2, strlen(p2)))) return 1;
    }
    return 0;
}
TEST(sh_flags_ftp_passive_flag_selects_data_mode) {
    REQUIRE(U(FtpOpenFileA));
    for (int passive = 1; passive >= 0; passive--) {
        srv *f = sh_ftp_start();
        if (!f) { t_skip("ftp server unavailable"); return; }
        HINTERNET s = sh_open_to("ftp-mode");
        HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, passive ? INTERNET_FLAG_PASSIVE : 0, 1) : NULL;
        CHECK(c != NULL);
        HINTERNET fo = c ? U(FtpOpenFileA)(c, "hello.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0) : NULL;
        { int c_ = !!(fo != NULL); t_check(c_, __FILE__, __LINE__, "fo != NULL", "passive=%d FtpOpenFile err %lu", passive, GetLastError()); }
        if (fo) {
            char b[16]; size_t n = t_inet_read_all(fo, b, sizeof b, NULL);
            EXPECT_EQ(n, 5);
            sh_close(fo);
        }
        int pasv = sh_ftp_cmd_seen(f, "PASV", "EPSV"), port = sh_ftp_cmd_seen(f, "PORT", "EPRT");
        { int c_ = !!(passive ? (pasv && !port) : (port && !pasv)); t_check(c_, __FILE__, __LINE__, "passive ? (pasv && !port) : (port && !pasv)", "passive=%d: PASV/EPSV seen %d PORT/EPRT seen %d", passive, pasv, port); }
        if (c) {
            DWORD v, len, e;
            /* REQUEST_FLAGS is not answered for FCon; the FTP connect has no PASSIVE readback */
            CHECK(!sh_qdw(c, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
            sh_close(c);
        }
        if (s) sh_close(s);
        srv_stop(f);
    }
}

/* The FTP find handle reports NO_HEADERS (8) only: INTERNET_REQFLAG_PASSIVE (0x10) is never set, passive or not (VM). */
TEST(sh_flags_ftp_find_request_flags_passive_bit) {
    REQUIRE(U(FtpFindFirstFileA));
    for (int passive = 1; passive >= 0; passive--) {
        srv *f = sh_ftp_start();
        if (!f) { t_skip("ftp server unavailable"); return; }
        HINTERNET s = sh_open_to("ftp-pbit");
        HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, passive ? INTERNET_FLAG_PASSIVE : 0, 1) : NULL;
        WIN32_FIND_DATAA fd;
        HINTERNET fh = c ? U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 2) : NULL;
        { int c_ = !!(fh != NULL); t_check(c_, __FILE__, __LINE__, "fh != NULL", "passive=%d find err %lu", passive, GetLastError()); }
        if (fh) {
            DWORD v, len, e;
            CHECK(sh_qdw(fh, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e));
            CHECKF(v == INTERNET_REQFLAG_NO_HEADERS, "FTP find REQUEST_FLAGS passive=%d: 0x%lx", passive, v);   /* VM: no PASSIVE bit either way */
            sh_close(fh);
        }
        if (c) sh_close(c);
        if (s) sh_close(s);
        srv_stop(f);
    }
}

/* Which loopback spellings bypass a named proxy with no bypass list (127.0.0.1 does, see above). VM: the implicit
 * bypass matches the host string (127.0.0.1, localhost in any case, ::1 with or without brackets), not the 127/8
 * range: 127.0.0.2 and 127.1 are sent to the proxy (absolute-form target, VIA_PROXY). */
TEST(sh_flags_proxy_loopback_names) {
    REQUIRE(U(HttpSendRequestA));
    srv *px = srv_http(NULL, 0), *org = srv_http(NULL, 0);
    if (!px || !org) { srv_stop(px); srv_stop(org); t_skip("server unavailable"); return; }
    static const char *const hosts[] = { "localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.2", "127.1" };
    static const int direct[] = { 1, 1, 1, 1, 0, 0 };
    for (size_t i = 0; i < sizeof hosts / sizeof *hosts; i++) {
        int pb = srv_req_count(px), ob = srv_req_count(org);
        HINTERNET s = sh_proxy_session(srv_hostport(px), NULL);
        if (!s) { CHECK(!"open"); continue; }
        DWORD f = 0;
        SetLastError(0);
        int ok = sh_send_via(s, hosts[i], srv_port(org), "/lb", &f);
        DWORD e = GetLastError();
        Sleep(100);
        int pv = srv_req_count(px) - pb, ov = srv_req_count(org) - ob;
        t_note("named proxy, no bypass, host [%s]: ok=%d err %lu via proxy %d direct %d flags 0x%lx target [%s]", hosts[i], ok, ok ? 0 : e, pv, ov, f,
               pv ? srv_req_target(px, pb) : ov ? srv_req_target(org, ob) : "-");
        CHECKF(ok && (direct[i] ? (ov == 1 && pv == 0) : (pv == 1 && ov == 0)), "host [%s]: ok=%d proxy %d direct %d", hosts[i], ok, pv, ov);
        CHECKF(direct[i] ? !(f & INTERNET_REQFLAG_VIA_PROXY) : (f & INTERNET_REQFLAG_VIA_PROXY) != 0, "host [%s]: flags 0x%lx", hosts[i], f);
        if (!direct[i] && pv == 1) {
            char want[96]; snprintf(want, sizeof want, "http://%s:%u/lb", hosts[i], srv_port(org));
            EXPECT_STR(srv_req_target(px, pb), want);
        }
        sh_close(s);
    }
    srv_stop(px); srv_stop(org);
}
