/* proxy_connectivity: INTERNET_OPTION_PROXY read-back normalisation, partial buffers, session-scoped set details,
 * PROXY_USERNAME/PASSWORD edge cases, PER_CONNECTION_OPTION (read-only) per option, and the connectivity-related
 * "refresh" options that only re-read state.
 * Decomp: InternetQueryOptionA@0x59730 case 0x26 (NULL handle -> LegacyGetProxySettings(GlobalProxyInfo), session ->
 * INTERNET_HANDLE_OBJECT::LegacyGetSessionProxySettings, other handle types -> 12018), case 0x2b/0x2c (12018 for NULL,
 * session and one more handle type; GetUserOrPass otherwise), case 0x36..0x39/0x46 -> ERROR_NOT_SUPPORTED;
 * InternetSetOptionA@0x551b0 case 0x25 (REFRESH: NULL handle or a session sharing GlobalProxyInfo -> re-read, TRUE;
 * non-session -> 12018), case 0x26, case 0x27 (SETTINGS_CHANGED: purges keep-alive connections), case 0x5f;
 * QueryPerConnOptions@0x13b2c0 (FLAGS_UI = FLAGS, dwOptionError zeroed first).
 * Nothing here writes per-user or process-wide proxy state.
 * VM_TIMEOUT: 180 */
#include "pc.h"
#include <stdlib.h>

#ifndef INTERNET_OPTION_REFRESH
#define INTERNET_OPTION_REFRESH 37
#endif
#ifndef INTERNET_OPTION_SETTINGS_CHANGED
#define INTERNET_OPTION_SETTINGS_CHANGED 39
#endif
#ifndef INTERNET_OPTION_PROXY_SETTINGS_CHANGED
#define INTERNET_OPTION_PROXY_SETTINGS_CHANGED 95
#endif

static int reg_proxy_enable2(void) {
    DWORD v = 0, n = sizeof v;
    if (RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable",
                     RRF_RT_REG_DWORD, NULL, &v, &n) != ERROR_SUCCESS) return 0;
    return (int)v;
}

/* read back INTERNET_OPTION_PROXY of a session into caller storage; returns len or 0 */
static DWORD readback(HINTERNET h, char *buf, DWORD cap, INTERNET_PROXY_INFO **pi) {
    DWORD l = cap; memset(buf, 0xcc, cap);
    if (!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l)) return 0;
    *pi = (INTERNET_PROXY_INFO *)buf;
    return l;
}
static const char *s_or(const void *p) { return p ? (const char *)p : "(null)"; }

/* ------------------------------------------------------------------ proxy read-back normalisation */
/* LegacyGetProxySettings / session read-back: CharLowerA, then ';' and ',' become ' '. */
typedef struct { const char *in; const char *want; } norm_case;
static const norm_case k_proxy_norm[] = {
    { "127.0.0.1:8080", "127.0.0.1:8080" },
    { "PROXY.INVALID:3128", "proxy.invalid:3128" },
    { "A.b.C.invalid:1", "a.b.c.invalid:1" },
    { "http=X.invalid:1;https=Y.invalid:2", "http=x.invalid:1 https=y.invalid:2" },
    { "http=x.invalid:1,https=y.invalid:2", "http=x.invalid:1 https=y.invalid:2" },
    { "HTTP://X.INVALID:1", "http://x.invalid:1" },
    { "[::1]:3128", "[::1]:3128" },
    { "SOCKS=s.invalid:1080", "socks=s.invalid:1080" },
    { "ftp=f.invalid:21;gopher=g.invalid:70", "ftp=f.invalid:21 gopher=g.invalid:70" },
    { "a.invalid:1;b.invalid:2;c.invalid:3", "a.invalid:1 b.invalid:2 c.invalid:3" },
    { "a.invalid:1 b.invalid:2", "a.invalid:1 b.invalid:2" },
    { "x.invalid", "x.invalid" },
    { "x.invalid:0", "x.invalid:0" },
    { "x.invalid:65535", "x.invalid:65535" },
    { "x", "x" },
};
TEST(pc_opt2_proxy_readback_normalised) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    for (size_t i = 0; i < sizeof k_proxy_norm / sizeof k_proxy_norm[0]; i++) {
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, k_proxy_norm[i].in, NULL, 0);
        if (!h) { CHECKF(0, "open \"%s\" failed %lu", k_proxy_norm[i].in, GetLastError()); continue; }
        char buf[1024]; INTERNET_PROXY_INFO *pi = NULL;
        DWORD l = readback(h, buf, sizeof buf, &pi);
        CHECKF(l != 0, "\"%s\": query failed %lu", k_proxy_norm[i].in, GetLastError());
        if (l) {
            EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
            CHECKF(pi->lpszProxy && !strcmp((const char *)pi->lpszProxy, k_proxy_norm[i].want), "\"%s\": got \"%s\" want \"%s\"",
                   k_proxy_norm[i].in, s_or(pi->lpszProxy), k_proxy_norm[i].want);
            CHECKF(l == 24 + 2 * (strlen(k_proxy_norm[i].want) + 1), "\"%s\": len %lu", k_proxy_norm[i].in, l);
        }
        U(InternetCloseHandle)(h);
    }
}

/* whitespace and empty list elements: recorded as observed */
TEST(pc_opt2_proxy_readback_whitespace) {
    REQUIRE(U(InternetOpenA));
    static const char *in[] = { " x.invalid:1", "x.invalid:1 ", "  x.invalid:1  ", "x.invalid:1;", ";x.invalid:1", "x.invalid:1;;y.invalid:2",
                                "x.invalid:1\ty.invalid:2", "http= x.invalid:1", "http =x.invalid:1", "x.invalid :1" };
    for (size_t i = 0; i < sizeof in / sizeof in[0]; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, in[i], NULL, 0);
        DWORD e = GetLastError();
        if (!h) { t_note("OBS open proxy \"%s\" -> NULL err %lu", in[i], e); continue; }
        char buf[1024]; INTERNET_PROXY_INFO *pi = NULL;
        DWORD l = readback(h, buf, sizeof buf, &pi);
        t_note("OBS open proxy \"%s\" -> \"%s\" len %lu", in[i], l ? s_or(pi->lpszProxy) : "(query failed)", l);
        CHECK(l != 0);
        U(InternetCloseHandle)(h);
    }
}

static const norm_case k_bypass_norm[] = {
    { "<local>", "<local>" },
    { "<LOCAL>", "<local>" },
    { "<-loopback>", "<-loopback>" },
    { "*.INVALID", "*.invalid" },
    { "a.invalid;b.invalid", "a.invalid b.invalid" },
    { "a.invalid,b.invalid", "a.invalid b.invalid" },
    { "A.invalid;B.invalid,<Local>", "a.invalid b.invalid <local>" },
    { "10.*", "10.*" },
    { "http://Host.Invalid", "http://host.invalid" },
    { "host.invalid:8080", "host.invalid:8080" },
};
TEST(pc_opt2_bypass_readback_normalised) {
    REQUIRE(U(InternetOpenA));
    for (size_t i = 0; i < sizeof k_bypass_norm / sizeof k_bypass_norm[0]; i++) {
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "p.invalid:1", k_bypass_norm[i].in, 0);
        if (!h) { CHECKF(0, "open bypass \"%s\" failed %lu", k_bypass_norm[i].in, GetLastError()); continue; }
        char buf[1024]; INTERNET_PROXY_INFO *pi = NULL;
        DWORD l = readback(h, buf, sizeof buf, &pi);
        CHECK(l != 0);
        if (l) {
            /* lpszProxyBypass = "<proxy copy> <bypass>" (Win10 layout, see pc_options.c) */
            char want[256]; snprintf(want, sizeof want, "p.invalid:1 %s", k_bypass_norm[i].want);
            CHECKF(pi->lpszProxyBypass && !strcmp((const char *)pi->lpszProxyBypass, want), "bypass \"%s\": got \"%s\" want \"%s\"",
                   k_bypass_norm[i].in, s_or(pi->lpszProxyBypass), want);
            DWORD wl = (DWORD)(24 + 2 * (strlen("p.invalid:1") + 1) + strlen(k_bypass_norm[i].want) + 1);
            CHECKF(l == wl, "bypass \"%s\": len %lu want %lu", k_bypass_norm[i].in, l, wl);
        }
        U(InternetCloseHandle)(h);
    }
}

/* empty bypass string: same layout as no bypass at all? */
TEST(pc_opt2_bypass_empty_vs_null) {
    REQUIRE(U(InternetOpenA));
    HINTERNET a = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "p.invalid:1", NULL, 0);
    HINTERNET b = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "p.invalid:1", "", 0);
    CHECK(a != NULL); CHECK(b != NULL);
    if (a && b) {
        char ba[256], bb[256]; INTERNET_PROXY_INFO *pa = NULL, *pb = NULL;
        DWORD la = readback(a, ba, sizeof ba, &pa), lb = readback(b, bb, sizeof bb, &pb);
        t_note("OBS bypass NULL -> len %lu \"%s\"; bypass \"\" -> len %lu \"%s\"", la, la ? s_or(pa->lpszProxyBypass) : "-", lb,
               lb ? s_or(pb->lpszProxyBypass) : "-");
        EXPECT_EQ(la, 24 + 2 * 12);
        EXPECT_EQ(la, lb);
        if (la && lb) EXPECT_STR((const char *)pb->lpszProxyBypass, (const char *)pa->lpszProxyBypass);
    }
    if (a) U(InternetCloseHandle)(a);
    if (b) U(InternetCloseHandle)(b);
}

/* W open: strings converted to ANSI internally; read back through A and W queries */
TEST(pc_opt2_open_w_readback) {
    REQUIRE(U(InternetOpenW)); REQUIRE(U(InternetQueryOptionW));
    static const struct { const WCHAR *p, *b; const char *wp, *wb; } t[] = {
        { L"P.Invalid:1", NULL, "p.invalid:1", NULL },
        { L"http=a.invalid:1;https=b.invalid:2", L"<local>;X.invalid", "http=a.invalid:1 https=b.invalid:2", "<local> x.invalid" },
        { L"[::1]:8888", L"*.invalid", "[::1]:8888", "*.invalid" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        HINTERNET h = U(InternetOpenW)(L"pc", INTERNET_OPEN_TYPE_PROXY, t[i].p, t[i].b, 0);
        if (!h) { CHECKF(0, "open %zu failed %lu", i, GetLastError()); continue; }
        char bufA[512], bufW[512]; DWORD la = sizeof bufA, lw = sizeof bufW;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, bufA, &la));
        CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_PROXY, bufW, &lw));
        EXPECT_EQ(la, lw);
        INTERNET_PROXY_INFO *pa = (INTERNET_PROXY_INFO *)bufA, *pw = (INTERNET_PROXY_INFO *)bufW;
        EXPECT_STR((const char *)pa->lpszProxy, t[i].wp);
        EXPECT_STR((const char *)pw->lpszProxy, t[i].wp);
        char wb[256]; if (t[i].wb) snprintf(wb, sizeof wb, "%s %s", t[i].wp, t[i].wb); else snprintf(wb, sizeof wb, "%s", t[i].wp);
        EXPECT_STR((const char *)pa->lpszProxyBypass, wb);
        U(InternetCloseHandle)(h);
    }
}

/* ------------------------------------------------------------------ partial buffers */
TEST(pc_opt2_proxy_query_partial_buffer_named) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", "<local>", 0);
    if (!h) { t_skip("open failed"); return; }
    const DWORD need = 62;
    static const DWORD lens[] = { 1, 8, 23, 24, 25, 40, 61 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        unsigned char buf[128]; memset(buf, 0xcc, sizeof buf);
        DWORD l = lens[i]; SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INSUFFICIENT_BUFFER, "len %lu: ok %d err %lu", lens[i], ok, e);
        CHECKF(l == need, "len %lu: need %lu", lens[i], l);
        /* observed: which of the caller's bytes were touched */
        int z = 0; while (z < 128 && buf[z] == 0) z++;
        int last = -1; for (int k = 0; k < 128; k++) if (buf[k] != 0xcc) last = k;
        t_note("OBS partial len %lu: leading zero bytes %d, last touched byte %d", lens[i], z, last);
        CHECKF(last < (int)lens[i], "len %lu: wrote byte %d past the buffer", lens[i], last);
    }
    U(InternetCloseHandle)(h);
}

TEST(pc_opt2_proxy_query_partial_buffer_direct) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    static const DWORD lens[] = { 1, 8, 16, 23 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        unsigned char buf[64]; memset(buf, 0xcc, sizeof buf);
        DWORD l = lens[i];
        CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l));
        EXPECT_EQ(l, 24);
        int last = -1; for (int k = 0; k < 64; k++) if (buf[k] != 0xcc) last = k;
        t_note("OBS direct partial len %lu: last touched byte %d", lens[i], last);
        CHECKF(last < (int)lens[i], "len %lu: wrote past the buffer", lens[i]);
    }
    /* larger than needed: len is set to 24 */
    char big[100]; DWORD l = sizeof big;
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, big, &l));
    EXPECT_EQ(l, 24);
    U(InternetCloseHandle)(h);
}

TEST(pc_opt2_proxy_query_exact_len_grows_with_input) {
    REQUIRE(U(InternetOpenA));
    char proxy[300];
    for (int n = 1; n <= 256; n = n * 2 + 1) {
        memset(proxy, 'h', n); proxy[n] = 0; strcat(proxy, ":1");
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, proxy, NULL, 0);
        if (!h) { CHECKF(0, "open %d failed", n); continue; }
        DWORD need = 0; CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, NULL, &need));
        DWORD want = (DWORD)(24 + 2 * (strlen(proxy) + 1));
        CHECKF(need == want, "proxy len %zu: need %lu want %lu", strlen(proxy), need, want);
        U(InternetCloseHandle)(h);
    }
}

/* ------------------------------------------------------------------ handles */
TEST(pc_opt2_proxy_query_closed_handle) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    CHECK(U(InternetCloseHandle)(h));
    char buf[256]; DWORD l = sizeof buf; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l);
    DWORD e = GetLastError();
    t_note("OBS query PROXY on closed session -> %d err %lu", ok, e);
    CHECK(!ok);
    CHECK(e == ERROR_INVALID_HANDLE || e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_DIRECT, NULL, NULL };
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    t_note("OBS set PROXY on closed session -> err %lu", GetLastError());
}

TEST(pc_opt2_proxy_on_ftp_and_url_handles) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_OFFLINE);
    if (!h) { t_skip("open failed"); return; }
    /* an FTP connect handle in offline mode is created without network traffic */
    HINTERNET hf = U(InternetConnectA)(h, "pc-ftp.invalid", 21, NULL, NULL, INTERNET_SERVICE_FTP, 0, 0);
    t_note("OBS offline FTP connect handle %p err %lu", hf, hf ? 0 : GetLastError());
    if (hf) {
        char buf[64]; DWORD l = sizeof buf; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(hf, INTERNET_OPTION_PROXY, buf, &l));
        EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        U(InternetCloseHandle)(hf);
    }
    U(InternetCloseHandle)(h);
}

/* ------------------------------------------------------------------ set on a session */
TEST(pc_opt2_set_proxy_preconfig_on_session) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL };
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi);
    DWORD e = GetLastError();
    char buf[256]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(h, buf, sizeof buf, &q);
    t_note("OBS set PRECONFIG on PROXY session -> %d err %lu; read back access %lu proxy \"%s\" len %lu", ok, e, l ? q->dwAccessType : 0,
           l ? s_or(q->lpszProxy) : "-", l);
    /* decomp: access 0 passes the argument check (only bits above 3, 2, and 3 without a proxy are rejected) */
    CHECK(ok);
    if (ok && l && !reg_proxy_enable2()) EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    U(InternetCloseHandle)(h);
}

TEST(pc_opt2_set_proxy_replaces_bypass) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "a.invalid:1", "<local>", 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"B.invalid:2", NULL };
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    char buf[256]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(h, buf, sizeof buf, &q);
    CHECK(l != 0);
    if (l) {
        EXPECT_STR((const char *)q->lpszProxy, "b.invalid:2");
        EXPECT_STR((const char *)q->lpszProxyBypass, "b.invalid:2");   /* no bypass any more */
        EXPECT_EQ(l, 24 + 2 * 12);
    }
    pi.lpszProxyBypass = (LPCTSTR)"*.Example.Invalid;<local>";
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    l = readback(h, buf, sizeof buf, &q);
    if (l) EXPECT_STR((const char *)q->lpszProxyBypass, "b.invalid:2 *.example.invalid <local>");
    U(InternetCloseHandle)(h);
}

TEST(pc_opt2_set_proxy_direct_ignores_strings) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "a.invalid:1", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_DIRECT, (LPCTSTR)"ignored.invalid:9", (LPCTSTR)"<local>" };
    CHECK(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi));
    char buf[256]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(h, buf, sizeof buf, &q);
    CHECK(l != 0);
    if (l) { EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_DIRECT); EXPECT_EQ(q->lpszProxy, NULL); EXPECT_EQ(l, 24); }
    U(InternetCloseHandle)(h);
}

TEST(pc_opt2_set_proxy_many_times) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    for (int i = 0; i < 50; i++) {
        char px[64]; snprintf(px, sizeof px, "p%d.invalid:%d", i, 1000 + i);
        INTERNET_PROXY_INFO pi = { (i % 3) ? INTERNET_OPEN_TYPE_PROXY : INTERNET_OPEN_TYPE_DIRECT, (LPCTSTR)px, NULL };
        CHECKF(U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi), "iteration %d err %lu", i, GetLastError());
        char buf[256]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(h, buf, sizeof buf, &q);
        if (!l) { CHECK(0); continue; }
        if (i % 3) { CHECKF(q->lpszProxy && !strcmp((const char *)q->lpszProxy, px), "iteration %d: \"%s\"", i, s_or(q->lpszProxy)); }
        else { EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_DIRECT); }
    }
    U(InternetCloseHandle)(h);
}

TEST(pc_opt2_set_proxy_long_string) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    char *px = malloc(4200); size_t n = 0;
    for (int i = 0; n < 4000; i++) n += (size_t)sprintf(px + n, "%sp%d.invalid:%d", i ? ";" : "", i, 1000 + i);
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)px, NULL };
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi);
    DWORD e = GetLastError();
    DWORD need = 0; U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, NULL, &need);
    t_note("OBS set %zu-char proxy list -> %d err %lu, need %lu", n, ok, e, need);
    CHECK(ok);
    if (ok) EXPECT_EQ(need, 24 + 2 * (n + 1));
    free(px);
    U(InternetCloseHandle)(h);
}

/* ------------------------------------------------------------------ PROXY_USERNAME / PASSWORD details */
static HINTERNET open_req(HINTERNET *ph, HINTERNET *pc) {
    *ph = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    *pc = *ph ? U(InternetConnectA)(*ph, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    return *pc ? U(HttpOpenRequestA)(*pc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
}
static void close3(HINTERNET r, HINTERNET c, HINTERNET h) { if (r) U(InternetCloseHandle)(r); if (c) U(InternetCloseHandle)(c); if (h) U(InternetCloseHandle)(h); }

TEST(pc_opt2_proxy_creds_long_values) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET h, c, r = open_req(&h, &c);
    if (!r) { close3(r, c, h); t_skip("handles"); return; }
    static const int lens[] = { 1, 63, 64, 255, 256, 1000 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        char *v = malloc(lens[i] + 1); for (int k = 0; k < lens[i]; k++) v[k] = (char)('a' + k % 26); v[lens[i]] = 0;
        CHECKF(U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, v, lens[i] + 1), "set %d", lens[i]);
        char *out = malloc(lens[i] + 16); DWORD l = lens[i] + 16;
        CHECK(U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, out, &l));
        CHECKF(l == (DWORD)lens[i] && !strcmp(out, v), "len %d: got %lu", lens[i], l);
        l = 0; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, NULL, &l));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, (DWORD)lens[i] + 1);
        free(out); free(v);
    }
    close3(r, c, h);
}

TEST(pc_opt2_proxy_creds_empty_and_overwrite) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET h, c, r = open_req(&h, &c);
    if (!r) { close3(r, c, h); t_skip("handles"); return; }
    char out[64]; DWORD l;
    CHECK(U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_PASSWORD, "first", 6));
    CHECK(U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_PASSWORD, "second", 7));
    l = sizeof out; CHECK(U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_PASSWORD, out, &l));
    EXPECT_STR(out, "second"); EXPECT_EQ(l, 6);
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_PASSWORD, "", 1);
    t_note("OBS set empty PROXY_PASSWORD -> %d err %lu", ok, GetLastError());
    l = sizeof out; memset(out, 'x', sizeof out);
    BOOL q = U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_PASSWORD, out, &l);
    t_note("OBS after empty set: query %d len %lu out0 %d", q, l, out[0]);
    if (ok && q) { EXPECT_EQ(l, 0); EXPECT_EQ(out[0], 0); }
    /* username and password are independent */
    CHECK(U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, "uu", 3));
    l = sizeof out; CHECK(U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, out, &l)); EXPECT_STR(out, "uu");
    close3(r, c, h);
}

TEST(pc_opt2_proxy_creds_length_arg) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET h, c, r = open_req(&h, &c);
    if (!r) { close3(r, c, h); t_skip("handles"); return; }
    /* the A set takes a NUL-terminated string: the length argument is observed, not the terminator */
    static const DWORD lens[] = { 0, 1, 3, 100 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, "abcdef", lens[i]);
        DWORD e = GetLastError();
        char out[64] = { 0 }; DWORD l = sizeof out;
        BOOL q = U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, out, &l);
        t_note("OBS set PROXY_USERNAME \"abcdef\" len %lu -> %d err %lu; read \"%s\" (%lu) q=%d", lens[i], ok, e, out, l, q);
    }
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, NULL, 0);
    t_note("OBS set PROXY_USERNAME NULL/0 -> %d err %lu", ok, GetLastError());
    close3(r, c, h);
}

TEST(pc_opt2_proxy_creds_request_inherits_connect) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    HINTERNET c = h ? U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (!c) { close3(NULL, c, h); t_skip("handles"); return; }
    CHECK(U(InternetSetOptionA)(c, INTERNET_OPTION_PROXY_USERNAME, "cu", 3));
    CHECK(U(InternetSetOptionA)(c, INTERNET_OPTION_PROXY_PASSWORD, "cp", 3));
    HINTERNET r = U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(r != NULL);
    if (r) {
        char u[32] = "?", p[32] = "?"; DWORD lu = sizeof u, lp = sizeof p;
        BOOL a = U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, u, &lu);
        BOOL b = U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_PASSWORD, p, &lp);
        t_note("OBS request after connect-level proxy creds: user %d \"%s\" (%lu) pass %d \"%s\" (%lu)", a, u, lu, b, p, lp);
        CHECK(a); CHECK(b);
        /* request-level set does not change the connect handle */
        CHECK(U(InternetSetOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, "ru", 3));
        char cu[32]; DWORD lc = sizeof cu;
        CHECK(U(InternetQueryOptionA)(c, INTERNET_OPTION_PROXY_USERNAME, cu, &lc));
        EXPECT_STR(cu, "cu");
    }
    close3(r, c, h);
}

TEST(pc_opt2_proxy_creds_w_unicode) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET h, c, r = open_req(&h, &c);
    if (!r) { close3(r, c, h); t_skip("handles"); return; }
    static const WCHAR wu[] = { 'u', 0x00e9, 's', 0 };   /* "u\xe9s" */
    CHECK(U(InternetSetOptionW)(r, INTERNET_OPTION_PROXY_USERNAME, (void *)wu, 4));
    WCHAR wo[16] = { 0 }; DWORD l = sizeof wo;
    CHECK(U(InternetQueryOptionW)(r, INTERNET_OPTION_PROXY_USERNAME, wo, &l));
    EXPECT_EQ(l, 3);
    CHECK(!lstrcmpW(wo, wu));
    char ao[16] = { 0 }; l = sizeof ao;
    CHECK(U(InternetQueryOptionA)(r, INTERNET_OPTION_PROXY_USERNAME, ao, &l));
    char want[16]; WideCharToMultiByte(CP_ACP, 0, wu, -1, want, sizeof want, NULL, NULL);
    EXPECT_STR(ao, want);
    close3(r, c, h);
}

/* ------------------------------------------------------------------ PER_CONNECTION_OPTION (query only) */
static BOOL perconn_one(HINTERNET h, DWORD opt, INTERNET_PER_CONN_OPTIONA *o) {
    o->dwOption = opt; memset(&o->Value, 0xcc, sizeof o->Value);
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 1, 0xbad, o };
    DWORD l = sizeof lst;
    return U(InternetQueryOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l);
}
static int is_string_opt(DWORD o) { return o == 2 || o == 3 || o == 4 || o == 6 || o == 9; }

TEST(pc_opt2_perconn_each_option_alone) {
    REQUIRE(U(InternetQueryOptionA));
    for (DWORD opt = 1; opt <= 10; opt++) {
        INTERNET_PER_CONN_OPTIONA o;
        BOOL ok = perconn_one(NULL, opt, &o);
        CHECKF(ok, "option %lu err %lu", opt, GetLastError());
        if (!ok) continue;
        if (is_string_opt(opt)) {
            t_note("OBS perconn %lu = %s", opt, o.Value.pszValue ? o.Value.pszValue : "(null)");
            if (o.Value.pszValue) GlobalFree(o.Value.pszValue);
        } else if (opt == 8) {
            t_note("OBS perconn 8 (LAST_DETECT_TIME) = %08lx%08lx", o.Value.ftValue.dwHighDateTime, o.Value.ftValue.dwLowDateTime);
        } else {
            t_note("OBS perconn %lu = 0x%lx", opt, o.Value.dwValue);
            CHECKF(o.Value.dwValue != 0xccccccccu, "option %lu not written", opt);
        }
    }
}

TEST(pc_opt2_perconn_flags_ui_equals_flags) {
    REQUIRE(U(InternetQueryOptionA));
    INTERNET_PER_CONN_OPTIONA o[2];
    o[0].dwOption = INTERNET_PER_CONN_FLAGS; o[1].dwOption = 10 /* INTERNET_PER_CONN_FLAGS_UI */;
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 2, 0xbad, o };
    DWORD l = sizeof lst;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l));
    t_note("FLAGS 0x%lx FLAGS_UI 0x%lx", o[0].Value.dwValue, o[1].Value.dwValue);
    EXPECT_EQ(o[1].Value.dwValue, o[0].Value.dwValue);
    EXPECT_EQ(lst.dwOptionError, 0);
}

TEST(pc_opt2_perconn_a_w_agree) {
    REQUIRE(U(InternetQueryOptionW));
    for (DWORD opt = 1; opt <= 10; opt++) {
        INTERNET_PER_CONN_OPTIONA oa; INTERNET_PER_CONN_OPTIONW ow;
        BOOL a = perconn_one(NULL, opt, &oa);
        ow.dwOption = opt; memset(&ow.Value, 0xcc, sizeof ow.Value);
        INTERNET_PER_CONN_OPTION_LISTW lw = { sizeof lw, NULL, 1, 0xbad, &ow }; DWORD l = sizeof lw;
        BOOL w = U(InternetQueryOptionW)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &lw, &l);
        CHECKF(a && w, "option %lu: A %d W %d", opt, a, w);
        if (!a || !w) continue;
        if (is_string_opt(opt)) {
            if (!oa.Value.pszValue || !ow.Value.pszValue) CHECKF(oa.Value.pszValue == NULL && ow.Value.pszValue == NULL, "option %lu: NULL mismatch", opt);
            else { char c[1024]; WideCharToMultiByte(CP_ACP, 0, ow.Value.pszValue, -1, c, sizeof c, NULL, NULL); EXPECT_STR(oa.Value.pszValue, c); }
            if (oa.Value.pszValue) GlobalFree(oa.Value.pszValue);
            if (ow.Value.pszValue) GlobalFree(ow.Value.pszValue);
        } else if (opt == 8) {
            EXPECT_EQ(oa.Value.ftValue.dwLowDateTime, ow.Value.ftValue.dwLowDateTime);
        } else {
            CHECKF(oa.Value.dwValue == ow.Value.dwValue, "option %lu: A 0x%lx W 0x%lx", opt, oa.Value.dwValue, ow.Value.dwValue);
        }
    }
}

TEST(pc_opt2_perconn_session_vs_null_flags) {
    REQUIRE(U(InternetOpenA));
    INTERNET_PER_CONN_OPTIONA g, s;
    CHECK(perconn_one(NULL, INTERNET_PER_CONN_FLAGS, &g));
    static const DWORD acc[] = { INTERNET_OPEN_TYPE_DIRECT, INTERNET_OPEN_TYPE_PRECONFIG, INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY };
    for (size_t i = 0; i < 3; i++) {
        HINTERNET h = U(InternetOpenA)("pc", acc[i], NULL, NULL, 0);
        if (!h) { CHECK(0); continue; }
        CHECK(perconn_one(h, INTERNET_PER_CONN_FLAGS, &s));
        t_note("OBS access %lu: session FLAGS 0x%lx, NULL handle FLAGS 0x%lx", acc[i], s.Value.dwValue, g.Value.dwValue);
        /* the session path reads GlobalProxyInfo; without a configured proxy both agree on DIRECT */
        CHECK(s.Value.dwValue & PROXY_TYPE_DIRECT);
        if (!reg_proxy_enable2()) CHECK(!(s.Value.dwValue & PROXY_TYPE_PROXY));
        U(InternetCloseHandle)(h);
    }
}

TEST(pc_opt2_perconn_dwsize_variants) {
    REQUIRE(U(InternetQueryOptionA));
    static const DWORD sizes[] = { 0, 4, 0x1f, 0x20, 0x21, 0x40, 0xffffffffu };
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        INTERNET_PER_CONN_OPTIONA o; o.dwOption = INTERNET_PER_CONN_FLAGS; o.Value.dwValue = 0xcccccccc;
        INTERNET_PER_CONN_OPTION_LISTA lst = { sizes[i], NULL, 1, 0xbad, &o };
        DWORD l = sizeof lst; SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l);
        t_note("OBS perconn list.dwSize 0x%lx -> %d err %lu value 0x%lx l %lu", sizes[i], ok, ok ? 0 : GetLastError(), o.Value.dwValue, l);
    }
}

TEST(pc_opt2_perconn_named_connection) {
    REQUIRE(U(InternetQueryOptionA));
    INTERNET_PER_CONN_OPTIONA o[2]; o[0].dwOption = INTERNET_PER_CONN_FLAGS; o[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    char conn[] = "pc-no-such-connectoid";
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, conn, 2, 0xbad, o };
    DWORD l = sizeof lst; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l);
    t_note("OBS perconn connection \"%s\" -> %d err %lu FLAGS 0x%lx server %s", conn, ok, ok ? 0 : GetLastError(),
           ok ? o[0].Value.dwValue : 0, ok && o[1].Value.pszValue ? o[1].Value.pszValue : "(null)");
    if (ok) {
        CHECK(o[0].Value.dwValue & PROXY_TYPE_DIRECT);
        if (o[1].Value.pszValue) GlobalFree(o[1].Value.pszValue);
    }
}

TEST(pc_opt2_perconn_error_index_positions) {
    REQUIRE(U(InternetQueryOptionA));
    /* dwOptionError = index of the first unknown option; options before it were processed */
    for (int pos = 0; pos < 5; pos++) {
        INTERNET_PER_CONN_OPTIONA o[5];
        for (int k = 0; k < 5; k++) o[k].dwOption = (k == pos) ? 42 : INTERNET_PER_CONN_FLAGS;
        INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 5, 0xbad, o };
        DWORD l = sizeof lst; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(lst.dwOptionError == (DWORD)pos, "pos %d: dwOptionError %lu", pos, lst.dwOptionError);
        for (int k = 0; k < pos; k++) CHECKF(o[k].Value.dwValue & PROXY_TYPE_DIRECT, "pos %d: option %d not filled (0x%lx)", pos, k, o[k].Value.dwValue);
    }
}

TEST(pc_opt2_perconn_set_bad_args_on_null_handle) {
    REQUIRE(U(InternetSetOptionA));
    /* argument errors only: never reaches the registry */
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 0, 0, NULL };
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, sizeof lst)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    static const DWORD lens[] = { 0, 1, 8, 0x1f };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetSetOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, lens[i]);
        DWORD e = GetLastError();
        CHECKF(!ok, "len %lu accepted", lens[i]);
        t_note("OBS set perconn NULL handle len %lu -> err %lu", lens[i], e);
        if (lens[i]) CHECKF(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "len %lu err %lu", lens[i], e);
    }
}

/* ------------------------------------------------------------------ refresh-style options (re-read only) */
TEST(pc_opt2_refresh_on_null_and_session) {
    REQUIRE(U(InternetSetOptionA));
    SetLastError(0xdeadbeef);
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_REFRESH, NULL, 0));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (h) {
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_REFRESH, NULL, 0);
        t_note("OBS REFRESH on PRECONFIG session -> %d err %lu", ok, GetLastError());
        CHECK(ok);
        U(InternetCloseHandle)(h);
    }
    h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (h) {
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_REFRESH, NULL, 0);
        t_note("OBS REFRESH on PROXY session -> %d err %lu", ok, GetLastError());
        /* the session keeps its own proxy */
        char buf[128]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(h, buf, sizeof buf, &q);
        if (l) EXPECT_STR((const char *)q->lpszProxy, "127.0.0.1:3128");
        HINTERNET c = U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (c) {
            SetLastError(0xdeadbeef);
            CHECK(!U(InternetSetOptionA)(c, INTERNET_OPTION_REFRESH, NULL, 0));
            EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
            U(InternetCloseHandle)(c);
        }
        U(InternetCloseHandle)(h);
    }
    /* the global configuration is unchanged by a refresh */
    char buf[128]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(NULL, buf, sizeof buf, &q);
    if (l && !reg_proxy_enable2()) EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
}

TEST(pc_opt2_settings_changed_options) {
    REQUIRE(U(InternetSetOptionA));
    SetLastError(0xdeadbeef);
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0));
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(NULL, INTERNET_OPTION_PROXY_SETTINGS_CHANGED, NULL, 0);
    t_note("OBS PROXY_SETTINGS_CHANGED -> %d err %lu", ok, GetLastError());
    CHECK(ok);
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (h) {
        SetLastError(0xdeadbeef);
        ok = U(InternetSetOptionA)(h, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
        t_note("OBS SETTINGS_CHANGED on a session -> %d err %lu", ok, GetLastError());
        U(InternetCloseHandle)(h);
    }
    /* these are set-only */
    static const DWORD so[] = { INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_PROXY_SETTINGS_CHANGED };
    for (size_t i = 0; i < 3; i++) {
        char b[16]; DWORD l = sizeof b; SetLastError(0xdeadbeef);
        BOOL q = U(InternetQueryOptionA)(NULL, so[i], b, &l);
        DWORD e = GetLastError();
        t_note("OBS query set-only option %lu -> %d err %lu", so[i], q, e);
        CHECK(!q);
    }
    char buf[128]; INTERNET_PROXY_INFO *q = NULL; DWORD l = readback(NULL, buf, sizeof buf, &q);
    if (l && !reg_proxy_enable2()) EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
}

/* SETTINGS_CHANGED purges pooled keep-alive connections (PurgeKeepAlivesAndDuos): the next request opens a new one */
TEST(pc_opt2_settings_changed_purges_keepalive) {
    REQUIRE(U(InternetSetOptionA));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "ka", SRV_R_KEEPALIVE), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    HINTERNET h = t_inet_open("pc_purge");
    char body[16]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(h, srv_url(s, "/1"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    EXPECT_EQ(t_http_get(h, srv_url(s, "/2"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));    /* pooled */
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0));
    EXPECT_EQ(t_http_get(h, srv_url(s, "/3"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    CHECK(srv_wait_requests(s, 3, 3000));
    t_note("OBS after SETTINGS_CHANGED: req conns %d %d %d (connections %d)", srv_req_conn(s, 0), srv_req_conn(s, 1), srv_req_conn(s, 2), srv_conn_count(s));
    EXPECT_NE(srv_req_conn(s, 2), srv_req_conn(s, 1));
    EXPECT_EQ(srv_conn_count(s), 2);
    t_inet_close(h); srv_stop(s);
}

/* ------------------------------------------------------------------ connectivity option table */
typedef struct { DWORD opt; const char *name; } opt_name;
TEST(pc_opt2_connectivity_option_table) {
    REQUIRE(U(InternetQueryOptionA));
    static const opt_name t[] = {
        { 50, "CONNECTED_STATE" }, { 51, "IDLE_STATE" }, { 52, "OFFLINE_SEMANTICS" }, { 64, "BYPASS_EDITED_ENTRY" },
        { 70, "DISABLE_AUTODIAL" }, { 82, "AUTODIAL_MODE" }, { 83, "AUTODIAL_CONNECTION" }, { 85, "AUTODIAL_HWND" },
        { 103, "MAX_CONNS_PER_PROXY" }, { 54, "CALLBACK_FILTER(0x36)" }, { 55, "CONNECT_TIME(0x37)" },
        { 56, "SEND_THROUGHPUT(0x38)" }, { 57, "RECEIVE_THROUGHPUT(0x39)" },
    };
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        for (int on = 0; on < 2; on++) {
            HINTERNET x = on ? h : NULL;
            unsigned char b[64]; memset(b, 0xcc, sizeof b); DWORD l = sizeof b; SetLastError(0xdeadbeef);
            BOOL ok = U(InternetQueryOptionA)(x, t[i].opt, b, &l);
            DWORD e = ok ? 0 : GetLastError();
            t_note("OBS query %s(%lu) on %s -> %d err %lu len %lu dword 0x%lx", t[i].name, t[i].opt, on ? "session" : "NULL", ok, e, l, *(DWORD *)b);
        }
    }
    /* decomp: 0x36..0x39 and 0x46 report ERROR_NOT_SUPPORTED */
    static const DWORD ns[] = { 54, 55, 56, 57, 70 };
    for (size_t i = 0; i < sizeof ns / sizeof ns[0]; i++) {
        DWORD v, l = sizeof v; SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(h, ns[i], &v, &l);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_NOT_SUPPORTED, "option %lu: ok %d err %lu", ns[i], ok, e);
    }
    if (h) U(InternetCloseHandle)(h);
}

TEST(pc_opt2_bypass_edited_entry_read) {
    REQUIRE(U(InternetQueryOptionA));
    DWORD v = 0xcccccccc, l = sizeof v;
    BOOL ok = U(InternetQueryOptionA)(NULL, 64 /* BYPASS_EDITED_ENTRY */, &v, &l);
    t_note("OBS BYPASS_EDITED_ENTRY -> %d value %lu len %lu err %lu", ok, v, l, ok ? 0 : GetLastError());
    CHECK(ok);
    if (ok) { EXPECT_EQ(l, 4); CHECK(v == 0 || v == 1); }
}

TEST(pc_opt2_autodial_connection_query) {
    REQUIRE(U(InternetQueryOptionA));
    char b[64]; memset(b, 'x', sizeof b); DWORD l = sizeof b; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(NULL, 83 /* AUTODIAL_CONNECTION */, b, &l);
    t_note("OBS AUTODIAL_CONNECTION -> %d len %lu b0 %d err %lu", ok, l, b[0], ok ? 0 : GetLastError());
    CHECK(ok);
    if (ok) EXPECT_EQ(b[0], 0);    /* decomp: the buffer's first byte is cleared, no connectoid */
}
