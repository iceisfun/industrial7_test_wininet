/* proxy_connectivity: InternetOpen access types, INTERNET_OPTION_PROXY / PROXY_USERNAME / PROXY_PASSWORD,
 * INTERNET_OPTION_PER_CONNECTION_OPTION (read-only), connected-state options.
 * Decomp: InternalInternetOpen@0xe0650, InternetQueryOptionA@0x59730 (case 0x26/0x2b/0x2c/0x32/0x4b),
 * InternetSetOptionA@0x551b0 (case 0x26/0x2b/0x2c/0x32/0x4b), InternetQueryOptionW@0xc5d50,
 * LegacyGetSessionProxySettings@0x15fb2c, LegacyGetProxySettings@0x166840, QueryPerConnOptions@0x13b2c0.
 * Nothing here writes per-user or process-wide proxy state: INTERNET_OPTION_PROXY is only ever SET on a session
 * handle (session-scoped), never on the NULL handle; PER_CONNECTION_OPTION is only queried.
 * VM_TIMEOUT: 240 */
#include "pc.h"
#include <stdlib.h>

/* registry: is the per-user proxy enabled (read only)? -1 unknown */
static int reg_proxy_enable(void) {
    DWORD v = 0, n = sizeof v;
    if (RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable",
                     RRF_RT_REG_DWORD, NULL, &v, &n) != ERROR_SUCCESS) return 0;
    return (int)v;
}
static int reg_has_autoconfig(void) {
    char b[8]; DWORD n = sizeof b;
    return RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "AutoConfigURL",
                        RRF_RT_REG_SZ, NULL, b, &n) != ERROR_FILE_NOT_FOUND;
}

/* Query INTERNET_OPTION_PROXY (A) into a fresh heap buffer; returns the BOOL, *err, *len. */
static BOOL qproxy(HINTERNET h, INTERNET_PROXY_INFO **out, DWORD *len, DWORD *err) {
    static char buf[4096];
    DWORD l = sizeof buf; memset(buf, 0xcc, sizeof buf);
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l);
    if (err) *err = ok ? GetLastError() : GetLastError();
    if (len) *len = l;
    if (out) *out = (INTERNET_PROXY_INFO *)buf;
    return ok;
}
static BOOL setproxy(HINTERNET h, DWORD access, const char *proxy, const char *bypass, DWORD len, DWORD *err) {
    INTERNET_PROXY_INFO pi; pi.dwAccessType = access; pi.lpszProxy = (LPCTSTR)proxy; pi.lpszProxyBypass = (LPCTSTR)bypass;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, &pi, len);
    if (err) *err = GetLastError();
    return ok;
}

/* ------------------------------------------------------------------ InternetOpen access types */
TEST(pc_open_access_types_valid) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    static const struct { DWORD access; const char *proxy; } t[] = {
        { INTERNET_OPEN_TYPE_PRECONFIG, NULL }, { INTERNET_OPEN_TYPE_DIRECT, NULL }, { INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:1" },
        { INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY, NULL }, { INTERNET_OPEN_TYPE_DIRECT, "ignored.invalid:1" },
        { INTERNET_OPEN_TYPE_PRECONFIG, "ignored.invalid:1" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("pc", t[i].access, t[i].proxy, NULL, 0);
        CHECKF(h != NULL, "access %lu err %lu", t[i].access, GetLastError());
        if (!h) continue;
        EXPECT_ERR(0);
        DWORD ty = 0, l = sizeof ty;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &ty, &l));
        EXPECT_EQ(ty, INTERNET_HANDLE_TYPE_INTERNET);
        U(InternetCloseHandle)(h);
    }
}

TEST(pc_open_access_types_invalid) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetOpenW));
    static const DWORD bad[] = { 2, 5, 6, 7, 8, 9, 0x10, 0x13, 99, 0x100, 0x80000000u, 0x80000001u, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("pc", bad[i], "127.0.0.1:1", NULL, 0);
        CHECKF(h == NULL, "access 0x%lx accepted", bad[i]);
        if (h) U(InternetCloseHandle)(h);
        DWORD e = GetLastError(); CHECKF(e == ERROR_INVALID_PARAMETER, "access 0x%lx err %lu", bad[i], e);
        SetLastError(0xdeadbeef);
        h = U(InternetOpenW)(L"pc", bad[i], NULL, NULL, 0);
        CHECKF(h == NULL, "W access 0x%lx accepted", bad[i]);
        if (h) U(InternetCloseHandle)(h);
        e = GetLastError(); CHECKF(e == ERROR_INVALID_PARAMETER, "W access 0x%lx err %lu", bad[i], e);
    }
}

TEST(pc_open_proxy_requires_proxy_name) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetOpenW));
    SetLastError(0xdeadbeef);
    EXPECT_FAIL(U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, NULL, NULL, 0) == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_FAIL(U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "", NULL, 0) == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_FAIL(U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, NULL, "<local>", 0) == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_FAIL(U(InternetOpenW)(L"pc", INTERNET_OPEN_TYPE_PROXY, NULL, NULL, 0) == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_FAIL(U(InternetOpenW)(L"pc", INTERNET_OPEN_TYPE_PROXY, L"", NULL, 0) == NULL, ERROR_INVALID_PARAMETER);
}

/* Proxy strings InternetOpen accepts (no network I/O happens at open time). */
TEST(pc_open_proxy_string_forms_accepted) {
    REQUIRE(U(InternetOpenA));
    static const char *forms[] = {
        "127.0.0.1:3128", "127.0.0.1", "localhost:8080", "proxy.invalid:80", "http=127.0.0.1:1", "http=127.0.0.1:1;https=127.0.0.1:2",
        "http=127.0.0.1:1 https=127.0.0.1:2", "http://127.0.0.1:3128", "ftp=127.0.0.1:21", "https=127.0.0.1:2",
        "HTTP=127.0.0.1:1", "127.0.0.1:1;127.0.0.1:2", "[::1]:3128", "socks=127.0.0.1:1080",
    };
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, forms[i], NULL, 0);
        CHECKF(h != NULL, "proxy \"%s\" err %lu", forms[i], GetLastError());
        if (h) U(InternetCloseHandle)(h);
    }
}

TEST(pc_open_bypass_forms_accepted) {
    REQUIRE(U(InternetOpenA));
    static const char *forms[] = { "<local>", "<-loopback>", "*.invalid", "127.0.0.1", "a.invalid;b.invalid", "a.invalid b.invalid",
                                   "http://a.invalid", "a.invalid:8080", "*", "", "10.*", "<local>;*.example.test" };
    for (size_t i = 0; i < sizeof forms / sizeof forms[0]; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:1", forms[i], 0);
        CHECKF(h != NULL, "bypass \"%s\" err %lu", forms[i], GetLastError());
        if (h) U(InternetCloseHandle)(h);
    }
}

/* ------------------------------------------------------------------ INTERNET_OPTION_PROXY query */
TEST(pc_query_proxy_direct_session) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("InternetOpen failed %lu", GetLastError()); return; }
    INTERNET_PROXY_INFO *pi; DWORD len, err;
    CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(len, sizeof(INTERNET_PROXY_INFO));
    EXPECT_EQ(sizeof(INTERNET_PROXY_INFO), 24);
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    EXPECT_EQ(pi->lpszProxy, NULL);
    EXPECT_EQ(pi->lpszProxyBypass, NULL);
    U(InternetCloseHandle)(h);
}

TEST(pc_query_proxy_direct_ignores_proxy_args) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, "127.0.0.1:3128", "<local>", 0);
    if (!h) { t_skip("InternetOpen failed %lu", GetLastError()); return; }
    INTERNET_PROXY_INFO *pi; DWORD len, err;
    CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    EXPECT_EQ(pi->lpszProxy, NULL);
    EXPECT_EQ(len, 24);
    U(InternetCloseHandle)(h);
}

TEST(pc_query_proxy_direct_short_buffer) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("InternetOpen failed"); return; }
    char buf[64]; static const DWORD lens[] = { 0, 1, 8, 16, 23 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        DWORD l = lens[i]; SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l);
        CHECKF(!ok, "len %lu succeeded", lens[i]);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        CHECKF(l == 24, "len %lu -> need %lu", lens[i], l);
    }
    DWORD l = 0; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, NULL, &l));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 24);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(InternetCloseHandle)(h);
}

static void check_named(const char *proxy, const char *bypass, const char *want_proxy, const char *want_bypass) {
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, proxy, bypass, 0);
    if (!h) { CHECKF(0, "open \"%s\" failed %lu", proxy, GetLastError()); return; }
    INTERNET_PROXY_INFO *pi; DWORD len, err;
    BOOL ok = qproxy(h, &pi, &len, &err);
    CHECKF(ok, "query \"%s\" err %lu", proxy, err);
    if (ok) {
        EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
        CHECKF(pi->lpszProxy && !strcmp((const char *)pi->lpszProxy, want_proxy), "proxy \"%s\": got \"%s\" want \"%s\"", proxy,
               pi->lpszProxy ? (const char *)pi->lpszProxy : "(null)", want_proxy);
        /* Win10 quirk (LegacyGetProxySettings@0x166840): lpszProxyBypass points at a second copy of the proxy string,
         * followed by " <bypass>" when there is one. Required size = 24 + 2*(strlen(proxy)+1) [+ strlen(bypass)+1]. */
        char wb[512];
        if (want_bypass) snprintf(wb, sizeof wb, "%s %s", want_proxy, want_bypass); else snprintf(wb, sizeof wb, "%s", want_proxy);
        CHECKF(pi->lpszProxyBypass && !strcmp((const char *)pi->lpszProxyBypass, wb), "bypass \"%s\": got \"%s\" want \"%s\"",
               bypass ? bypass : "(null)", pi->lpszProxyBypass ? (const char *)pi->lpszProxyBypass : "(null)", wb);
        DWORD want_len = (DWORD)(24 + 2 * (strlen(want_proxy) + 1) + (want_bypass ? strlen(want_bypass) + 1 : 0));
        CHECKF(len == want_len, "len %lu want %lu", len, want_len);
        CHECK((const char *)pi->lpszProxy == (const char *)pi + 24);
        CHECK(len >= 24);
        CHECKF((char *)pi->lpszProxy >= (char *)pi && (char *)pi->lpszProxy < (char *)pi + len, "proxy string outside the buffer");
        t_note("proxy \"%s\" bypass \"%s\" -> len %lu proxy \"%s\" bypass \"%s\"", proxy, bypass ? bypass : "(null)", len,
               pi->lpszProxy ? (const char *)pi->lpszProxy : "(null)", pi->lpszProxyBypass ? (const char *)pi->lpszProxyBypass : "(null)");
    }
    U(InternetCloseHandle)(h);
}

TEST(pc_query_proxy_named_session) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    check_named("127.0.0.1:3128", "<local>", "127.0.0.1:3128", "<local>");
    check_named("np:3128", "<local>", "np:3128", "<local>");
    check_named("127.0.0.1:3128", NULL, "127.0.0.1:3128", NULL);
}

TEST(pc_query_proxy_named_lowercased) {
    REQUIRE(U(InternetOpenA));
    check_named("PROXY.INVALID:3128", NULL, "proxy.invalid:3128", NULL);
    check_named("Mixed.Case.Invalid:1", "A.INVALID", "mixed.case.invalid:1", "a.invalid");
}

TEST(pc_query_proxy_named_per_scheme) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "http=127.0.0.1:1;https=127.0.0.1:2", NULL, 0);
    if (!h) { t_skip("open failed %lu", GetLastError()); return; }
    INTERNET_PROXY_INFO *pi; DWORD len, err;
    CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    const char *p = pi->lpszProxy ? (const char *)pi->lpszProxy : "";
    t_note("per-scheme proxy reads back as \"%s\"", p);
    EXPECT_STR(p, "http=127.0.0.1:1 https=127.0.0.1:2");   /* ';' and ',' become spaces */
    U(InternetCloseHandle)(h);
}

TEST(pc_query_proxy_named_size_query) {
    REQUIRE(U(InternetOpenA));
    static const struct { const char *p, *b; } t[] = { { "127.0.0.1:3128", "<local>" }, { "a.invalid:1", NULL }, { "x:1", "y" },
                                                        { "http=127.0.0.1:1;https=127.0.0.1:2", "*.invalid;<local>" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, t[i].p, t[i].b, 0);
        if (!h) { CHECKF(0, "open %s", t[i].p); continue; }
        DWORD need = 0; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, NULL, &need));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        size_t exact = 24 + 2 * (strlen(t[i].p) + 1) + (t[i].b ? strlen(t[i].b) + 1 : 0);
        CHECKF(need == exact, "\"%s\": need %lu want %zu", t[i].p, need, exact);
        t_note("size query \"%s\"/\"%s\": need %lu", t[i].p, t[i].b ? t[i].b : "(null)", need);
        /* exactly need bytes succeeds; need-1 fails with the same need */
        char *buf = malloc(need + 16); DWORD l = need;
        CHECKF(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l), "exact need %lu failed %lu", need, GetLastError());
        DWORD l2 = need - 1; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, buf, &l2));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l2, need);
        free(buf);
        U(InternetCloseHandle)(h);
    }
}

TEST(pc_query_proxy_W_returns_ansi_struct) {
    REQUIRE(U(InternetOpenW)); REQUIRE(U(InternetQueryOptionW));
    HINTERNET h = U(InternetOpenW)(L"pc", INTERNET_OPEN_TYPE_PROXY, L"127.0.0.1:3128", L"<local>", 0);
    if (!h) { t_skip("open failed %lu", GetLastError()); return; }
    char buf[512]; DWORD l = sizeof buf;
    BOOL ok = U(InternetQueryOptionW)(h, INTERNET_OPTION_PROXY, buf, &l);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) {
        INTERNET_PROXY_INFO *pi = (INTERNET_PROXY_INFO *)buf;
        EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
        /* the W query is routed straight to InternetQueryOptionA: the strings are ANSI */
        CHECK(pi->lpszProxy && !strcmp((const char *)pi->lpszProxy, "127.0.0.1:3128"));
        CHECK(pi->lpszProxyBypass && !strcmp((const char *)pi->lpszProxyBypass, "127.0.0.1:3128 <local>"));
        EXPECT_EQ(l, 62);
    }
    U(InternetCloseHandle)(h);
}

TEST(pc_query_proxy_wrong_handle_types) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    HINTERNET hc = U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    CHECK(hr != NULL);
    char buf[256]; DWORD l;
    if (hc) { l = sizeof buf; SetLastError(0xdeadbeef); CHECK(!U(InternetQueryOptionA)(hc, INTERNET_OPTION_PROXY, buf, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (hr) { l = sizeof buf; SetLastError(0xdeadbeef); CHECK(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_PROXY, buf, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_DIRECT, NULL, NULL };
    if (hc) { SetLastError(0xdeadbeef); CHECK(!U(InternetSetOptionA)(hc, INTERNET_OPTION_PROXY, &pi, sizeof pi)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (hr) { SetLastError(0xdeadbeef); CHECK(!U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY, &pi, sizeof pi)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (hr) U(InternetCloseHandle)(hr);
    if (hc) U(InternetCloseHandle)(hc);
    U(InternetCloseHandle)(h);
}

/* NULL handle: the process/per-user configuration (read only). */
TEST(pc_query_proxy_global_read_only) {
    REQUIRE(U(InternetQueryOptionA));
    INTERNET_PROXY_INFO *pi; DWORD len, err;
    BOOL ok = qproxy(NULL, &pi, &len, &err);
    CHECKF(ok, "err %lu", err);
    if (!ok) return;
    t_note("global proxy: access %lu proxy \"%s\" bypass \"%s\" len %lu (ProxyEnable=%d AutoConfigURL=%s)", pi->dwAccessType,
           pi->lpszProxy ? (const char *)pi->lpszProxy : "(null)", pi->lpszProxyBypass ? (const char *)pi->lpszProxyBypass : "(null)",
           len, reg_proxy_enable(), reg_has_autoconfig() ? "set" : "unset");
    CHECK(pi->dwAccessType == INTERNET_OPEN_TYPE_DIRECT || pi->dwAccessType == INTERNET_OPEN_TYPE_PROXY);
    if (!reg_proxy_enable()) { EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT); EXPECT_EQ(len, 24); }
}

TEST(pc_query_proxy_preconfig_session) {
    REQUIRE(U(InternetOpenA));
    static const DWORD acc[] = { INTERNET_OPEN_TYPE_PRECONFIG, INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY };
    for (int i = 0; i < 2; i++) {
        HINTERNET h = U(InternetOpenA)("pc", acc[i], NULL, NULL, 0);
        if (!h) { CHECK(0); continue; }
        INTERNET_PROXY_INFO *pi; DWORD len, err;
        BOOL ok = qproxy(h, &pi, &len, &err);
        CHECKF(ok, "access %lu err %lu", acc[i], err);
        if (ok) {
            t_note("access %lu: proxy access %lu len %lu proxy \"%s\"", acc[i], pi->dwAccessType, len, pi->lpszProxy ? (const char *)pi->lpszProxy : "(null)");
            if (!reg_proxy_enable()) EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
        }
        U(InternetCloseHandle)(h);
    }
}

/* ------------------------------------------------------------------ INTERNET_OPTION_PROXY set (session scope only) */
TEST(pc_set_proxy_on_session_roundtrip) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetOptionA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    DWORD err;
    CHECKF(setproxy(h, INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", "<local>", sizeof(INTERNET_PROXY_INFO), &err), "err %lu", err);
    INTERNET_PROXY_INFO *pi; DWORD len;
    CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    CHECK(pi->lpszProxy && !strcmp((const char *)pi->lpszProxy, "127.0.0.1:3128"));
    CHECK(pi->lpszProxyBypass && !strcmp((const char *)pi->lpszProxyBypass, "127.0.0.1:3128 <local>"));
    /* back to DIRECT */
    CHECKF(setproxy(h, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, sizeof(INTERNET_PROXY_INFO), &err), "err %lu", err);
    CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    EXPECT_EQ(pi->lpszProxy, NULL);
    /* the global configuration is untouched */
    INTERNET_PROXY_INFO *g; CHECK(qproxy(NULL, &g, &len, &err));
    if (!reg_proxy_enable()) EXPECT_EQ(g->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    U(InternetCloseHandle)(h);
}

TEST(pc_set_proxy_session_does_not_leak_to_other_sessions) {
    REQUIRE(U(InternetOpenA));
    HINTERNET a = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET b = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!a || !b) { t_skip("open failed"); if (a) U(InternetCloseHandle)(a); if (b) U(InternetCloseHandle)(b); return; }
    DWORD err; CHECK(setproxy(a, INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:9", NULL, 24, &err));
    INTERNET_PROXY_INFO *pi; DWORD len;
    CHECK(qproxy(b, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    CHECK(qproxy(a, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    U(InternetCloseHandle)(a); U(InternetCloseHandle)(b);
}

TEST(pc_set_proxy_bad_length) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    static const DWORD lens[] = { 1, 4, 8, 16, 23, 25, 32, 48 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        DWORD err; BOOL ok = setproxy(h, INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:1", NULL, lens[i], &err);
        CHECKF(!ok, "len %lu accepted", lens[i]);
        CHECKF(err == ERROR_INTERNET_BAD_OPTION_LENGTH, "len %lu err %lu", lens[i], err);
    }
    DWORD err; CHECK(!setproxy(h, INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:1", NULL, 0, &err));
    EXPECT_EQ(err, ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(h, INTERNET_OPTION_PROXY, NULL, 24));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* nothing changed */
    INTERNET_PROXY_INFO *pi; DWORD len; CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    U(InternetCloseHandle)(h);
}

TEST(pc_set_proxy_bad_access_type) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    static const DWORD bad[] = { 2, 4, 5, 7, 8, 0x10, 0x103, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        DWORD err; BOOL ok = setproxy(h, bad[i], "127.0.0.1:1", NULL, 24, &err);
        CHECKF(!ok, "access 0x%lx accepted", bad[i]);
        CHECKF(err == ERROR_INVALID_PARAMETER, "access 0x%lx err %lu", bad[i], err);
    }
    DWORD err;
    CHECK(!setproxy(h, INTERNET_OPEN_TYPE_PROXY, NULL, NULL, 24, &err)); EXPECT_EQ(err, ERROR_INVALID_PARAMETER);
    CHECK(!setproxy(h, INTERNET_OPEN_TYPE_PROXY, "", "<local>", 24, &err)); EXPECT_EQ(err, ERROR_INVALID_PARAMETER);
    INTERNET_PROXY_INFO *pi; DWORD len; CHECK(qproxy(h, &pi, &len, &err));
    EXPECT_EQ(pi->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    U(InternetCloseHandle)(h);
}

TEST(pc_set_proxy_W_option) {
    REQUIRE(U(InternetOpenW)); REQUIRE(U(InternetSetOptionW));
    HINTERNET h = U(InternetOpenW)(L"pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    /* InternetSetOptionW(PROXY) takes the A struct layout; set with ANSI strings and read back */
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"127.0.0.1:4321", (LPCTSTR)"<local>" };
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionW)(h, INTERNET_OPTION_PROXY, &pi, sizeof pi);
    t_note("InternetSetOptionW(PROXY, ANSI strings) -> %d err %lu", ok, GetLastError());
    INTERNET_PROXY_INFO *q; DWORD len, err;
    if (ok && qproxy(h, &q, &len, &err)) {
        t_note("read back: access %lu proxy \"%s\"", q->dwAccessType, q->lpszProxy ? (const char *)q->lpszProxy : "(null)");
        EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    }
    U(InternetCloseHandle)(h);
}

/* ------------------------------------------------------------------ PROXY_USERNAME / PROXY_PASSWORD */
TEST(pc_proxy_creds_wrong_handles) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    static const DWORD opts[] = { INTERNET_OPTION_PROXY_USERNAME, INTERNET_OPTION_PROXY_PASSWORD };
    for (int i = 0; i < 2; i++) {
        char buf[64]; DWORD l = sizeof buf;
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(h, opts[i], buf, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        l = sizeof buf; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(NULL, opts[i], buf, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetSetOptionA)(h, opts[i], "u", 2)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        l = sizeof buf; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionW)(h, opts[i], buf, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetSetOptionW)(h, opts[i], L"u", 2)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    U(InternetCloseHandle)(h);
}

static void creds_roundtrip(HINTERNET hx, const char *what) {
    char buf[64]; DWORD l;
    /* fresh handle: nothing set */
    l = sizeof buf; memset(buf, 'x', sizeof buf); SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(hx, INTERNET_OPTION_PROXY_USERNAME, buf, &l);
    t_note("%s: fresh PROXY_USERNAME ok=%d err=%lu len=%lu buf0=%d", what, ok, GetLastError(), l, ok ? buf[0] : -1);
    CHECKF(ok, "%s fresh username query err %lu", what, GetLastError());
    if (ok) { EXPECT_EQ(l, 0); EXPECT_EQ(buf[0], 0); }
    CHECK(U(InternetSetOptionA)(hx, INTERNET_OPTION_PROXY_USERNAME, "puser", 6));
    CHECK(U(InternetSetOptionA)(hx, INTERNET_OPTION_PROXY_PASSWORD, "ppass", 6));
    l = sizeof buf; CHECK(U(InternetQueryOptionA)(hx, INTERNET_OPTION_PROXY_USERNAME, buf, &l));
    EXPECT_STR(buf, "puser"); EXPECT_EQ(l, 5);
    l = sizeof buf; CHECK(U(InternetQueryOptionA)(hx, INTERNET_OPTION_PROXY_PASSWORD, buf, &l));
    EXPECT_STR(buf, "ppass"); EXPECT_EQ(l, 5);
    /* size query: A reports strlen + 1 */
    l = 2; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(hx, INTERNET_OPTION_PROXY_USERNAME, buf, &l));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 6);
    /* W view of the same value */
    WCHAR wb[64]; l = sizeof wb;
    CHECK(U(InternetQueryOptionW)(hx, INTERNET_OPTION_PROXY_USERNAME, wb, &l));
    CHECK(!lstrcmpW(wb, L"puser")); EXPECT_EQ(l, 5);
    l = 2; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionW)(hx, INTERNET_OPTION_PROXY_USERNAME, wb, &l));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 12);
    /* W set, A read */
    CHECK(U(InternetSetOptionW)(hx, INTERNET_OPTION_PROXY_USERNAME, L"wuser", 6));
    l = sizeof buf; CHECK(U(InternetQueryOptionA)(hx, INTERNET_OPTION_PROXY_USERNAME, buf, &l));
    EXPECT_STR(buf, "wuser");
}

TEST(pc_proxy_creds_on_connect_handle) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetConnectA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    HINTERNET hc = U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    if (hc) { creds_roundtrip(hc, "connect"); U(InternetCloseHandle)(hc); }
    U(InternetCloseHandle)(h);
}

TEST(pc_proxy_creds_on_request_handle) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(HttpOpenRequestA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    HINTERNET hc = U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) { creds_roundtrip(hr, "request"); U(InternetCloseHandle)(hr); }
    if (hc) U(InternetCloseHandle)(hc);
    U(InternetCloseHandle)(h);
}

TEST(pc_proxy_creds_connect_not_inherited_after_open) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    HINTERNET hc = U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) { CHECK(0); U(InternetCloseHandle)(h); return; }
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PROXY_USERNAME, "cuser", 6));
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    if (hr) {
        char buf[64]; DWORD l = sizeof buf; buf[0] = 0;
        BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, buf, &l);
        t_note("request after connect set: ok=%d user=\"%s\" len=%lu", ok, ok ? buf : "", l);
        CHECK(ok);
        U(InternetCloseHandle)(hr);
    }
    U(InternetCloseHandle)(hc); U(InternetCloseHandle)(h);
}

/* ------------------------------------------------------------------ PER_CONNECTION_OPTION (query only) */
TEST(pc_perconn_query_arg_errors) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PER_CONN_OPTIONA o[1]; o[0].dwOption = INTERNET_PER_CONN_FLAGS;
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 1, 0, o };
    EXPECT_EQ(sizeof lst, 0x20);
    DWORD l = sizeof lst; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, &l));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    static const DWORD shorts[] = { 0, 1, 4, 16, 0x1f };
    for (size_t i = 0; i < sizeof shorts / sizeof shorts[0]; i++) {
        l = shorts[i]; SetLastError(0xdeadbeef);
        CHECKF(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l), "len %lu", shorts[i]);
        DWORD e = GetLastError(); CHECKF(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "len %lu err %lu", shorts[i], e);
    }
    l = sizeof lst; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, &l));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    U(InternetCloseHandle)(h);
}

TEST(pc_perconn_query_invalid_option_id) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    static const DWORD bad[] = { 0, 11, 12, 100, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        INTERNET_PER_CONN_OPTIONA o[3];
        o[0].dwOption = INTERNET_PER_CONN_FLAGS; o[1].dwOption = INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS; o[2].dwOption = bad[i];
        INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 3, 0xbad, o };
        DWORD l = sizeof lst; SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l);
        CHECKF(!ok, "option %lu accepted", bad[i]);
        DWORD e = GetLastError(); CHECKF(e == ERROR_INVALID_PARAMETER, "option %lu err %lu", bad[i], e);
        CHECKF(lst.dwOptionError == 2, "option %lu: dwOptionError %lu", bad[i], lst.dwOptionError);
    }
    U(InternetCloseHandle)(h);
}

static void perconn_all(HINTERNET h, const char *what, DWORD *flags_out) {
    INTERNET_PER_CONN_OPTIONA o[10];
    for (int i = 0; i < 10; i++) { o[i].dwOption = (DWORD)(i + 1); memset(&o[i].Value, 0xcc, sizeof o[i].Value); }
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 10, 0xbad, o };
    DWORD l = sizeof lst; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l);
    CHECKF(ok, "%s: err %lu", what, GetLastError());
    if (!ok) return;
    EXPECT_EQ(lst.dwOptionError, 0);
    EXPECT_EQ(l, sizeof lst);
    DWORD f = o[0].Value.dwValue;
    if (flags_out) *flags_out = f;
    t_note("%s: FLAGS=0x%lx server=%s bypass=%s autoconfig=%s autodisc=0x%lx reload=%lu lastdetecturl=%s flags_ui=0x%lx", what, f,
           o[1].Value.pszValue ? o[1].Value.pszValue : "(null)", o[2].Value.pszValue ? o[2].Value.pszValue : "(null)",
           o[3].Value.pszValue ? o[3].Value.pszValue : "(null)", o[4].Value.dwValue, o[6].Value.dwValue,
           o[8].Value.pszValue ? o[8].Value.pszValue : "(null)", o[9].Value.dwValue);
    CHECK(f & PROXY_TYPE_DIRECT);
    CHECK((f & ~0x1fu) == 0);
    if (!reg_proxy_enable()) { CHECK(!(f & PROXY_TYPE_PROXY)); }
    if (!reg_has_autoconfig()) { CHECK(!(f & PROXY_TYPE_AUTO_PROXY_URL)); EXPECT_EQ(o[3].Value.pszValue, NULL); }
    for (int i = 1; i < 10; i++) if ((i == 1 || i == 2 || i == 3 || i == 5 || i == 8) && o[i].Value.pszValue) GlobalFree(o[i].Value.pszValue);
}

TEST(pc_perconn_query_all_session) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    perconn_all(h, "direct session", NULL);
    U(InternetCloseHandle)(h);
}

TEST(pc_perconn_query_all_global) {
    REQUIRE(U(InternetQueryOptionA));
    perconn_all(NULL, "NULL handle (registry)", NULL);
}

/* QueryPerConnOptions consults the global proxy configuration, not the session's own proxy */
TEST(pc_perconn_query_proxy_session_reports_global) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", "<local>", 0);
    if (!h) { t_skip("open failed"); return; }
    DWORD f = 0; perconn_all(h, "PROXY session", &f);
    if (!reg_proxy_enable()) CHECKF(!(f & PROXY_TYPE_PROXY), "PROXY session FLAGS 0x%lx", f);
    U(InternetCloseHandle)(h);
}

TEST(pc_perconn_query_zero_options) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 0, 0xbad, NULL };
    DWORD l = sizeof lst;
    CHECKF(U(InternetQueryOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l), "err %lu", GetLastError());
    EXPECT_EQ(lst.dwOptionError, 0);
    U(InternetCloseHandle)(h);
}

TEST(pc_perconn_query_W) {
    REQUIRE(U(InternetOpenW)); REQUIRE(U(InternetQueryOptionW));
    HINTERNET h = U(InternetOpenW)(L"pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PER_CONN_OPTIONW o[3];
    o[0].dwOption = INTERNET_PER_CONN_FLAGS; o[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER; o[2].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    INTERNET_PER_CONN_OPTION_LISTW lst = { sizeof lst, NULL, 3, 0xbad, o };
    DWORD l = sizeof lst;
    BOOL ok = U(InternetQueryOptionW)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) {
        CHECK(o[0].Value.dwValue & PROXY_TYPE_DIRECT);
        t_note("W: FLAGS=0x%lx server=%ls autoconfig=%ls", o[0].Value.dwValue, o[1].Value.pszValue ? o[1].Value.pszValue : L"(null)",
               o[2].Value.pszValue ? o[2].Value.pszValue : L"(null)");
        if (!reg_has_autoconfig()) EXPECT_EQ(o[2].Value.pszValue, NULL);
        if (o[1].Value.pszValue) GlobalFree(o[1].Value.pszValue);
        if (o[2].Value.pszValue) GlobalFree(o[2].Value.pszValue);
    }
    l = 4; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionW)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, &l));
    EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    U(InternetCloseHandle)(h);
}

/* set with invalid arguments never reaches the registry */
TEST(pc_perconn_set_arg_errors_only) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetOptionA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    INTERNET_PER_CONN_OPTION_LISTA lst = { sizeof lst, NULL, 0, 0, NULL };
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, sizeof lst)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, 0x1f)); EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, 4)); EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionW)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, sizeof lst)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionW)(h, INTERNET_OPTION_PER_CONNECTION_OPTION, &lst, 8)); EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    U(InternetCloseHandle)(h);
}

/* ------------------------------------------------------------------ connected-state style options (NULL handle) */
TEST(pc_option_connected_state_query) {
    REQUIRE(U(InternetQueryOptionA));
    static const struct { DWORD opt; DWORD want; const char *n; } t[] = {
        { INTERNET_OPTION_CONNECTED_STATE, 1, "CONNECTED_STATE" }, { 82 /* AUTODIAL_MODE */, 1, "AUTODIAL_MODE" },
        { 51 /* IDLE_STATE */, 0, "IDLE_STATE" }, { 52 /* OFFLINE_SEMANTICS */, 0, "OFFLINE_SEMANTICS" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        DWORD v = 0xcccccccc, l = sizeof v; SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(NULL, t[i].opt, &v, &l);
        CHECKF(ok, "%s err %lu", t[i].n, GetLastError());
        if (ok) { CHECKF(v == t[i].want, "%s = %lu want %lu", t[i].n, v, t[i].want); EXPECT_EQ(l, 4); }
        l = 2; SetLastError(0xdeadbeef);
        CHECKF(!U(InternetQueryOptionA)(NULL, t[i].opt, &v, &l), "%s short", t[i].n);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
        l = sizeof v; SetLastError(0xdeadbeef);
        ok = U(InternetQueryOptionW)(NULL, t[i].opt, &v, &l);
        CHECKF(ok && v == t[i].want, "%s W ok=%d v=%lu err %lu", t[i].n, ok, v, GetLastError());
    }
}

TEST(pc_option_connected_state_on_session) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    DWORD v = 0xcccccccc, l = sizeof v; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_CONNECTED_STATE, &v, &l);
    CHECK(ok);
    if (ok) EXPECT_EQ(v, INTERNET_STATE_CONNECTED);
    U(InternetCloseHandle)(h);
}

/* Setting CONNECTED_STATE switches the process to offline mode: on Win10 22H2 the 8-byte INTERNET_CONNECTED_INFO set
 * SUCCEEDED from this test process (VM run 1, contrary to the IfLowBoxIsProcessIE branch read in the decomp), so only the
 * length checks stay here; an offline set/restore belongs in a dx_ area. */
TEST(pc_option_connected_state_set_bad_length) {
    REQUIRE(U(InternetSetOptionA));
    INTERNET_CONNECTED_INFO ci = { INTERNET_STATE_CONNECTED, 0 };
    EXPECT_EQ(sizeof ci, 8);
    static const DWORD lens[] = { 1, 4, 7, 9, 12, 16 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECKF(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &ci, lens[i]), "len %lu accepted", lens[i]);
        DWORD e = GetLastError(); CHECKF(e == ERROR_INTERNET_BAD_OPTION_LENGTH, "len %lu err %lu", lens[i], e);
    }
    DWORD v = 0, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &v, &l));
    EXPECT_EQ(v, INTERNET_STATE_CONNECTED);
}

TEST(pc_option_offline_mode_not_implemented) {
    REQUIRE(U(InternetQueryOptionA));
    DWORD v = 0, l = sizeof v; SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_OFFLINE_MODE, &v, &l));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (h) {
        l = sizeof v; SetLastError(0xdeadbeef);
        CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_OFFLINE_MODE, &v, &l));
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        U(InternetCloseHandle)(h);
    }
}

TEST(pc_option_max_conns_per_proxy_read) {
    REQUIRE(U(InternetQueryOptionA));
    DWORD v = 0, l = sizeof v; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryOptionA)(NULL, 103 /* INTERNET_OPTION_MAX_CONNS_PER_PROXY */, &v, &l);
    CHECK(ok);
    if (ok) { EXPECT_EQ(l, 4); EXPECT_EQ(v, 4); }
}
