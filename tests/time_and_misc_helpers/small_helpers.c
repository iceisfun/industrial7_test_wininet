/* Small exported helpers: IsDomainLegalCookieDomainA/W (#116/#117), InternetFreeCookies, per-site cookie decision
 * lookups, Get/Set/IncrementUrlCacheHeaderData, _GetFileExtensionFromUrl, HttpIsHostHstsEnabled,
 * InternetAlgIdToString(A|W), InternetSecurityProtocolToString(A|W), InternetGetSecurityInfoByURL(A|W|plain).
 * Nothing here changes per-user state: cookies use unique hosts and are expired by t_net_cleanup, the cache
 * header DWORDs are only read, and the per-site decision APIs are only queried. */
#include "tm.h"
#include "srv.h"
#include "tnet.h"

/* ------------------------------------------------------------ IsDomainLegalCookieDomain (#116 A, #117 W)
 * [D IsDomainLegalCookieDomainA@0x1ea30 -> FormatReverseDomain + IsDomainLegal@0x320ac]:
 * NULL either -> FALSE, 87. Both strings are lower-cased. A domain without letters (IP literal) must equal the host.
 * Otherwise the domain must lie inside the host's registrable domain (public-suffix aware, GetDomainFromHost) and
 * the host must domain-match the domain. */
static IsDomainLegalCookieDomainA_pfn idl_a(void) { return (IsDomainLegalCookieDomainA_pfn)t_proc_ord("wininet.dll", 116); }
static IsDomainLegalCookieDomainW_pfn idl_w(void) { return (IsDomainLegalCookieDomainW_pfn)t_proc_ord("wininet.dll", 117); }

typedef struct { const char *dom, *host; int want; } idl_case;
static const idl_case idl[] = {
    { "example.com", "www.example.com", 1 },
    { "example.com", "example.com", 1 },
    { "www.example.com", "www.example.com", 1 },
    { "example.com", "a.b.c.example.com", 1 },
    { "b.c.example.com", "a.b.c.example.com", 1 },
    { "www.example.com", "example.com", 0 },
    { "com", "www.example.com", 0 },
    { "other.com", "www.example.com", 0 },
    { "ample.com", "www.example.com", 0 },
    { "le.com", "example.com", 0 },
    { "EXAMPLE.COM", "www.example.com", 1 },
    { "example.com", "WWW.EXAMPLE.COM", 1 },
    { "b.co.uk", "a.b.co.uk", 1 },
    { "co.uk", "a.b.co.uk", 0 },
    { "uk", "a.b.co.uk", 0 },
    { "127.0.0.1", "127.0.0.1", 1 },
    { "0.0.1", "127.0.0.1", 0 },
    { "127.0.0.2", "127.0.0.1", 0 },
    { "10.0.0.1", "127.0.0.1", 0 },
    { "i7test.example", "a.i7test.example", 1 },
    { "a.i7test.example", "b.i7test.example", 0 },
};

TEST(tsh_idl_resolve_by_ordinal) {
    CHECK(idl_a() != NULL); CHECK(idl_w() != NULL);
    t_note("#116=%p #117=%p", (void *)idl_a(), (void *)idl_w());
}

TEST(tsh_idl_a_table) {
    IsDomainLegalCookieDomainA_pfn f = idl_a(); REQUIRE(f);
    for (size_t i = 0; i < sizeof idl / sizeof idl[0]; i++) {
        BOOL r = f(idl[i].dom, idl[i].host);
        CHECKF(!!r == idl[i].want, "A(%s, %s) got %d want %d", idl[i].dom, idl[i].host, r, idl[i].want);
    }
}

TEST(tsh_idl_w_table) {
    IsDomainLegalCookieDomainW_pfn f = idl_w(); REQUIRE(f);
    for (size_t i = 0; i < sizeof idl / sizeof idl[0]; i++) {
        WCHAR d[128], h[128];
        MultiByteToWideChar(CP_ACP, 0, idl[i].dom, -1, d, 128); MultiByteToWideChar(CP_ACP, 0, idl[i].host, -1, h, 128);
        BOOL r = f(d, h);
        CHECKF(!!r == idl[i].want, "W(%s, %s) got %d want %d", idl[i].dom, idl[i].host, r, idl[i].want);
    }
}

TEST(tsh_idl_a_null) {
    IsDomainLegalCookieDomainA_pfn f = idl_a(); REQUIRE(f);
    SET_ERR(0); CHECK(!f(NULL, "example.com")); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f("example.com", NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!f(NULL, NULL));          EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tsh_idl_observations) {
    /* inputs whose answer depends on the public-suffix data or on leading-dot handling: record */
    IsDomainLegalCookieDomainA_pfn f = idl_a(); REQUIRE(f);
    static const char *const p[][2] = { { ".example.com", "www.example.com" }, { "localhost", "localhost" },
        { "example.com.", "www.example.com" }, { "github.io", "x.github.io" }, { "x.github.io", "x.github.io" },
        { "", "example.com" }, { "", "" }, { "co.jp", "a.co.jp" }, { "example", "a.example" } };
    for (size_t i = 0; i < sizeof p / sizeof p[0]; i++) t_note("IsDomainLegalCookieDomainA(%s, %s) = %d", p[i][0], p[i][1], f(p[i][0], p[i][1]));
}

/* ------------------------------------------------------------ InternetFreeCookies [D @0xbf1b0 -> InternalInternetFreeCookies] */
TEST(tsh_free_cookies_null) {
    REQUIRE(UN(InternetFreeCookies));
    SET_ERR(0x4242);
    UN(InternetFreeCookies)(NULL, 0);
    UN(InternetFreeCookies)(NULL, 5);
    UN(InternetFreeCookies)(NULL, 0xFFFFFFFFu);
    EXPECT_ERR(0x4242);
}

TEST(tsh_free_cookies_after_ex2) {
    REQUIRE(UN(InternetFreeCookies)); REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    const char *url = t_uniq_cookie_url("fc");
    CHECK(U(InternetSetCookieA)(url, "tmhfc", "v1"));
    t_cookie_track(url, "tmhfc");
    WCHAR wurl[256]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 256);
    void *arr = NULL; DWORD cnt = 0;
    DWORD r = UN(InternetGetCookieEx2)(wurl, NULL, 0, &arr, &cnt);
    t_note("InternetGetCookieEx2 -> %lu cnt=%lu", r, cnt);
    EXPECT_EQ(r, 0);
    CHECK(arr != NULL && cnt == 1);
    if (arr && cnt == 1) {
        tm_cookie2 *c = (tm_cookie2 *)arr;
        CHECK(c->pwszName && !lstrcmpW(c->pwszName, L"tmhfc"));
        CHECK(c->pwszValue && !lstrcmpW(c->pwszValue, L"v1"));
        EXPECT_EQ(c->fExpiresSet, FALSE);
    }
    SET_ERR(0x4242);
    if (arr) UN(InternetFreeCookies)(arr, cnt);
    EXPECT_ERR(0x4242);
    t_net_cleanup();
}

/* ------------------------------------------------------------ per-site cookie decisions (read-only)
 * [D InternetGetPerSiteCookieDecisionA@0x168ae0]: NULL host/out -> FALSE 87; no decision -> FALSE 12004.
 * [D InternetEnumPerSiteCookieDecisionA@0x168970]: NULL name/size/decision -> FALSE 87; else RegEnumKeyExA result. */
TEST(tsh_persite_get_args) {
    REQUIRE(U(InternetGetPerSiteCookieDecisionA)); REQUIRE(U(InternetGetPerSiteCookieDecisionW));
    unsigned long d = 0x77;
    SET_ERR(0); CHECK(!U(InternetGetPerSiteCookieDecisionA)(NULL, &d));          EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetGetPerSiteCookieDecisionA)("example.com", NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetGetPerSiteCookieDecisionW)(NULL, &d));          EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetGetPerSiteCookieDecisionW)(L"example.com", NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(d, 0x77);
}

TEST(tsh_persite_get_unknown_host) {
    REQUIRE(U(InternetGetPerSiteCookieDecisionA)); REQUIRE(U(InternetGetPerSiteCookieDecisionW));
    const char *h = t_uniq_host("psd");
    unsigned long d = 0x77;
    SET_ERR(0);
    CHECK(!U(InternetGetPerSiteCookieDecisionA)(h, &d));
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
    EXPECT_EQ(d, 0x77);
    WCHAR wh[128]; MultiByteToWideChar(CP_ACP, 0, h, -1, wh, 128);
    SET_ERR(0);
    CHECK(!U(InternetGetPerSiteCookieDecisionW)(wh, &d));
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
    SET_ERR(0);
    CHECK(!U(InternetGetPerSiteCookieDecisionA)("notadomain", &d));      /* not a domain: same failure */
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
}

TEST(tsh_persite_enum_args) {
    REQUIRE(U(InternetEnumPerSiteCookieDecisionA)); REQUIRE(U(InternetEnumPerSiteCookieDecisionW));
    char name[256]; unsigned long n = sizeof name, d = 0;
    SET_ERR(0); CHECK(!U(InternetEnumPerSiteCookieDecisionA)(NULL, &n, &d, 0));   EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetEnumPerSiteCookieDecisionA)(name, NULL, &d, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetEnumPerSiteCookieDecisionA)(name, &n, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    WCHAR wname[256]; n = 256;
    SET_ERR(0); CHECK(!U(InternetEnumPerSiteCookieDecisionW)(NULL, &n, &d, 0));    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetEnumPerSiteCookieDecisionW)(wname, NULL, &d, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetEnumPerSiteCookieDecisionW)(wname, &n, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tsh_persite_enum_past_end) {
    REQUIRE(U(InternetEnumPerSiteCookieDecisionA));
    char name[256]; unsigned long n = sizeof name, d = 0;
    int count = 0;
    for (DWORD i = 0; i < 64; i++) {
        n = sizeof name;
        if (!U(InternetEnumPerSiteCookieDecisionA)(name, &n, &d, i)) break;
        count++;
    }
    t_note("existing per-site decisions: %d (not asserted)", count);
    n = sizeof name;
    SET_ERR(0);
    BOOL r = U(InternetEnumPerSiteCookieDecisionA)(name, &n, &d, 100000);
    DWORD e = GetLastError();
    t_note("enum index 100000: r=%d e=%lu", r, e);
    CHECK(!r);
    CHECK(e == ERROR_NO_MORE_ITEMS || e == ERROR_INVALID_HANDLE || e == ERROR_FILE_NOT_FOUND);
}

/* ------------------------------------------------------------ cache header data [D GetUrlCacheHeaderData@0x295a0,
 * SetUrlCacheHeaderData@0x1a2f90, IncrementUrlCacheHeaderData@0x20960]: index >= 32 -> FALSE 87; Get with NULL out -> 87.
 * Only reads and rejected writes here: a successful Set/Increment would change the per-user cache. */
TEST(tsh_cache_header_get_all) {
    REQUIRE(UN(GetUrlCacheHeaderData));
    char line[600] = ""; size_t o = 0;
    for (DWORD i = 0; i < 32; i++) {
        DWORD v = 0xAAAAAAAA;
        SET_ERR(0xdead);
        BOOL r = UN(GetUrlCacheHeaderData)(i, &v);
        DWORD e = GetLastError();
        CHECKF(r && e == 0, "index %lu r=%d e=%lu", i, r, e);
        o += snprintf(line + o, sizeof line - o, "%lu:%lx ", i, v);
    }
    t_note("cache header data: %s", line);
}

TEST(tsh_cache_header_bad_index) {
    REQUIRE(UN(GetUrlCacheHeaderData)); REQUIRE(UN(SetUrlCacheHeaderData)); REQUIRE(UN(IncrementUrlCacheHeaderData));
    static const DWORD idx[] = { 32, 33, 64, 0x80000000u, 0xFFFFFFFFu };
    for (int i = 0; i < 5; i++) {
        DWORD v = 0x55;
        SET_ERR(0); CHECKF(!UN(GetUrlCacheHeaderData)(idx[i], &v), "get %lu", idx[i]);       EXPECT_ERR(ERROR_INVALID_PARAMETER);
        EXPECT_EQ(v, 0x55);
        SET_ERR(0); CHECKF(!UN(SetUrlCacheHeaderData)(idx[i], 1), "set %lu", idx[i]);        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0); CHECKF(!UN(IncrementUrlCacheHeaderData)(idx[i], &v), "inc %lu", idx[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        EXPECT_EQ(v, 0x55);
    }
}

TEST(tsh_cache_header_get_null) {
    REQUIRE(UN(GetUrlCacheHeaderData));
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(0, NULL));  EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(31, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(32, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tsh_cache_header_stable_reads) {
    REQUIRE(UN(GetUrlCacheHeaderData));
    DWORD a = 0, b = 1;
    CHECK(UN(GetUrlCacheHeaderData)(5, &a)); CHECK(UN(GetUrlCacheHeaderData)(5, &b));
    EXPECT_EQ(a, b);
}

/* ------------------------------------------------------------ _GetFileExtensionFromUrl [D @0x1470f0 + GetFileExtensionFromUrl@0xe30c]
 * Returns a Win32 code. 87: NULL/empty url, NULL buffer, *pcch == 0. 2: no extension (the last '.' before '?', '#'
 * or the end, reset by any of <>\"/:|?* after it; longer than 260 counts as none). 122: buffer too small,
 * *pcch = len+1. 0: extension copied, *pcch left unchanged. The second argument is ignored. */
typedef struct { const char *url; DWORD want; const char *ext; } fe_case;
static const fe_case fe[] = {
    { "http://h/a/b.txt", 0, "txt" },
    { "http://h/x.tar.gz?y=1.2", 0, "gz" },
    { "http://h/x.html#frag.htm", 0, "html" },
    { "http://h/x.HTML", 0, "HTML" },
    { "http://h/a.b/c", 2, NULL },
    { "http://h/x.", 0, "" },
    { "http://host.com", 0, "com" },
    { "http://host.com/", 2, NULL },
    { "file.txt", 0, "txt" },
    { "a.b\\c", 2, NULL },
    { "x.ht m", 0, "ht m" },
    { "x.a:b", 2, NULL },
    { "x.a*b", 2, NULL },
    { "x.a|b", 2, NULL },
    { "x.a\"b", 2, NULL },
    { "x.a<b", 2, NULL },
    { "x.a>b", 2, NULL },
    { "noext", 2, NULL },
    { "?a.b", 2, NULL },
    { "#a.b", 2, NULL },
    { ".hidden", 0, "hidden" },
    { "http://h/a..b", 0, "b" },
    { "http://h/a.b?", 0, "b" },
    { "http://h/a.b#", 0, "b" },
    { "http://h/a.b?c.d", 0, "b" },
    { "http://h/a.b.c.d", 0, "d" },
    { "http://h/dir.d/f", 2, NULL },
    { "http://h/dir.d/f.e", 0, "e" },
    { "C:\\dir\\f.exe", 0, "exe" },
    { "C:\\dir.d\\f", 2, NULL },
    { "http://h/%2e.x", 0, "x" },
    { "http://h/a.b%2fc", 0, "b%2fc" },
    { "http://h/a.b;c", 0, "b;c" },
    { "http://h/a.b&c", 0, "b&c" },
};

TEST(tsh_fileext_table) {
    REQUIRE(UN(_GetFileExtensionFromUrl));
    for (size_t i = 0; i < sizeof fe / sizeof fe[0]; i++) {
        char buf[300]; memset(buf, 'Z', sizeof buf); DWORD n = sizeof buf;
        DWORD r = UN(_GetFileExtensionFromUrl)((LPSTR)fe[i].url, 0, buf, &n);
        CHECKF(r == fe[i].want, "[%s] got %lu want %lu", fe[i].url, r, fe[i].want);
        if (r == 0 && fe[i].ext) {
            CHECKF(!strcmp(buf, fe[i].ext), "[%s] ext [%s] want [%s]", fe[i].url, buf, fe[i].ext);
            EXPECT_EQ(n, sizeof buf);   /* not updated on success */
        }
        if (fe[i].want == 2) CHECKF(buf[0] == 0, "[%s] buffer not cleared", fe[i].url);
    }
}

TEST(tsh_fileext_args) {
    REQUIRE(UN(_GetFileExtensionFromUrl));
    char buf[32]; DWORD n = sizeof buf;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(_GetFileExtensionFromUrl)(NULL, 0, buf, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(_GetFileExtensionFromUrl)("", 0, buf, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(_GetFileExtensionFromUrl)("a.txt", 0, NULL, &n), ERROR_INVALID_PARAMETER);
    n = 0; buf[0] = 'Z';
    EXPECT_EQ(UN(_GetFileExtensionFromUrl)("a.txt", 0, buf, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(buf[0], 'Z');
    n = sizeof buf;
    EXPECT_EQ(UN(_GetFileExtensionFromUrl)("a.txt", 0xFFFFFFFFu, buf, &n), 0);   /* 2nd arg ignored */
    EXPECT_STR(buf, "txt");
    EXPECT_ERR(0x4242);                                                           /* no SetLastError */
}

TEST(tsh_fileext_buffer_sizes) {
    REQUIRE(UN(_GetFileExtensionFromUrl));
    for (DWORD cap = 1; cap <= 8; cap++) {
        char buf[16]; memset(buf, 'Z', sizeof buf); DWORD n = cap;
        DWORD r = UN(_GetFileExtensionFromUrl)("http://h/f.html", 0, buf, &n);
        if (cap >= 5) { CHECKF(r == 0 && !strcmp(buf, "html") && n == cap, "cap %lu r=%lu", cap, r); }
        else {
            CHECKF(r == ERROR_INSUFFICIENT_BUFFER && n == 5, "cap %lu r=%lu n=%lu", cap, r, n);
            CHECKF(buf[cap - 1] == 0 && buf[cap] == 'Z', "cap %lu: truncated copy", cap);
        }
    }
}

TEST(tsh_fileext_length_limit) {
    REQUIRE(UN(_GetFileExtensionFromUrl));
    static char url[600], buf[600];
    for (int len = 257; len <= 262; len++) {
        strcpy(url, "http://h/f."); memset(url + 11, 'a', len); url[11 + len] = 0;
        DWORD n = sizeof buf;
        DWORD r = UN(_GetFileExtensionFromUrl)(url, 0, buf, &n);
        DWORD want = len <= 259 ? 0 : 2;     /* the dot counts: dot+ext must be <= 260 [D] */
        CHECKF(r == want, "ext len %d got %lu want %lu", len, r, want);
        if (r == 0) EXPECT_EQ(strlen(buf), (size_t)len);
    }
}

/* ------------------------------------------------------------ HttpIsHostHstsEnabled [D @0xbc1a0] (returns Win32 code) */
TEST(tsh_hsts_args) {
    REQUIRE(UN(HttpIsHostHstsEnabled));
    BOOL b = 7;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(HttpIsHostHstsEnabled)(NULL, &b), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(b, 0);                          /* *pfEnabled = 0 first */
    EXPECT_EQ(UN(HttpIsHostHstsEnabled)(L"example.com", NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(HttpIsHostHstsEnabled)(NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

TEST(tsh_hsts_unknown_hosts) {
    REQUIRE(UN(HttpIsHostHstsEnabled));
    const char *u = t_uniq_host("hsts");
    WCHAR wu[128]; MultiByteToWideChar(CP_ACP, 0, u, -1, wu, 128);
    const WCHAR *hosts[] = { L"127.0.0.1", L"localhost", wu, L"i7-no-such-host.invalid" };
    for (int i = 0; i < 4; i++) {
        BOOL b = 7;
        DWORD r = UN(HttpIsHostHstsEnabled)(hosts[i], &b);
        CHECKF(r == 0 && b == FALSE, "host %d r=%lu b=%d", i, r, b);
    }
    BOOL b = 7;
    DWORD r = UN(HttpIsHostHstsEnabled)(L"", &b);
    t_note("HttpIsHostHstsEnabled(\"\") = %lu, %d", r, b);
}

/* ------------------------------------------------------------ InternetSecurityProtocolToString [D @0x1844f0]
 * table: SP_PROT 0x8, 0x20, 0x2, 0x80, 0x200, 0x800, 0x2000 -> MUI strings 1807..1810, 1863..1865; other -> 87.
 * reserved != 0 or NULL pcch -> 87. NULL buffer: *pcch = 0 -> FALSE 122 with *pcch = len+1. Success: *pcch = len. */
static const DWORD prot_ids[] = { 0x8, 0x20, 0x2, 0x80, 0x200, 0x800, 0x2000 };
static const char *const prot_names[] = { "SSL 2.0", "SSL 3.0", "PCT 1.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };

TEST(tsh_secproto_strings_a) {
    REQUIRE(UN(InternetSecurityProtocolToStringA));
    for (int i = 0; i < 7; i++) {
        DWORD n = 0;
        SET_ERR(0);
        BOOL r = UN(InternetSecurityProtocolToStringA)(prot_ids[i], NULL, &n, 0);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && n > 1, "size query 0x%lx r=%d e=%lu n=%lu", prot_ids[i], r, e, n);
        char buf[128] = ""; DWORD bn = sizeof buf;
        SET_ERR(0xdead);
        r = UN(InternetSecurityProtocolToStringA)(prot_ids[i], buf, &bn, 0);
        e = GetLastError();
        t_note("protocol 0x%lx -> [%s] (%lu)", prot_ids[i], buf, bn);
        CHECKF(r && e == 0, "0x%lx r=%d e=%lu", prot_ids[i], r, e);
        EXPECT_EQ(bn, strlen(buf)); EXPECT_EQ(bn + 1, n);
        CHECKF(!strcmp(buf, prot_names[i]), "0x%lx -> [%s] want [%s]", prot_ids[i], buf, prot_names[i]);
        /* exact length (no room for NUL) -> 122 */
        DWORD xn = (DWORD)strlen(buf); char xb[128];
        SET_ERR(0);
        CHECK(!UN(InternetSecurityProtocolToStringA)(prot_ids[i], xb, &xn, 0)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(xn, n);
    }
}

TEST(tsh_secproto_strings_w) {
    REQUIRE(UN(InternetSecurityProtocolToStringW)); REQUIRE(UN(InternetSecurityProtocolToStringA));
    for (int i = 0; i < 7; i++) {
        char a[128] = ""; DWORD an = sizeof a;
        UN(InternetSecurityProtocolToStringA)(prot_ids[i], a, &an, 0);
        WCHAR w[128] = L""; DWORD wn = 128;
        CHECK(UN(InternetSecurityProtocolToStringW)(prot_ids[i], w, &wn, 0));
        WCHAR aw[128]; MultiByteToWideChar(CP_ACP, 0, a, -1, aw, 128);
        EXPECT_WSTR(w, aw); EXPECT_EQ(wn, an);
        DWORD qn = 0;
        SET_ERR(0); CHECK(!UN(InternetSecurityProtocolToStringW)(prot_ids[i], NULL, &qn, 0)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(qn, an + 1);
    }
}

TEST(tsh_secproto_unknown_and_args) {
    REQUIRE(UN(InternetSecurityProtocolToStringA)); REQUIRE(UN(InternetSecurityProtocolToStringW));
    static const DWORD unk[] = { 0, 1, 4, 0x10, 0x40, 0x100, 0x400, 0x1000, 0x4000, 0xA0, 0xFFFFFFFFu, 0x800 | 0x200 };
    char buf[64]; WCHAR wb[64];
    for (size_t i = 0; i < sizeof unk / sizeof unk[0]; i++) {
        DWORD n = sizeof buf;
        SET_ERR(0); CHECKF(!UN(InternetSecurityProtocolToStringA)(unk[i], buf, &n, 0), "0x%lx", unk[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        n = 64;
        SET_ERR(0); CHECKF(!UN(InternetSecurityProtocolToStringW)(unk[i], wb, &n, 0), "W 0x%lx", unk[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    DWORD n = sizeof buf;
    SET_ERR(0); CHECK(!UN(InternetSecurityProtocolToStringA)(0x800, buf, &n, 1));    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetSecurityProtocolToStringA)(0x800, buf, NULL, 0));  EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetSecurityProtocolToStringW)(0x800, wb, NULL, 0));   EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = 64;
    SET_ERR(0); CHECK(!UN(InternetSecurityProtocolToStringW)(0x800, wb, &n, 0xFFFFFFFFu)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------ InternetAlgIdToString [D @0x184130]: 43 known ALG_IDs
 * (table at .data 0x46f700); unknown ids are formatted with MUI string 1862. Same length protocol as above. */
static const DWORD alg_ids[] = { 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8009, 0x2400, 0x2200, 0xa400, 0x6601, 0x6609,
    0x6603, 0x6602, 0x6801, 0x660d, 0x6802, 0xaa01, 0xaa02, 0xaa04, 0x660a, 0x660b, 0x2000, 0x6604, 0xaa03, 0xa003,
    0x660c, 0x8008, 0x4c01, 0x4c02, 0x4c03, 0x4c07, 0x4c04, 0x4c05, 0x4c06, 0x800a, 0x800b, 0x660e, 0x660f, 0x6610,
    0x6611, 0x800c, 0x800d, 0x800e };

TEST(tsh_algid_known_a) {
    REQUIRE(UN(InternetAlgIdToStringA));
    for (size_t i = 0; i < sizeof alg_ids / sizeof alg_ids[0]; i++) {
        DWORD n = 0;
        SET_ERR(0);
        BOOL r = UN(InternetAlgIdToStringA)(alg_ids[i], NULL, &n, 0);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && n > 1, "size 0x%lx r=%d e=%lu n=%lu", alg_ids[i], r, e, n);
        char buf[160] = ""; DWORD bn = sizeof buf;
        SET_ERR(0xdead);
        r = UN(InternetAlgIdToStringA)(alg_ids[i], buf, &bn, 0);
        e = GetLastError();
        CHECKF(r && e == 0 && bn == strlen(buf) && bn + 1 == n, "0x%lx r=%d e=%lu bn=%lu n=%lu", alg_ids[i], r, e, bn, n);
        t_note("alg 0x%04lx -> [%s]", alg_ids[i], buf);
    }
}

TEST(tsh_algid_selected_names) {
    REQUIRE(UN(InternetAlgIdToStringA));
    static const struct { DWORD id; const char *s; } t[] = {
        { 0x6801, "RC4" }, { 0x6603, "3DES" }, { 0x660e, "AES 128" }, { 0x6610, "AES 256" }, { 0x8003, "MD5" },
        { 0x8004, "SHA" }, { 0xa400, "RSA" }, { 0x800c, "SHA 256" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char buf[160] = ""; DWORD n = sizeof buf;
        CHECK(UN(InternetAlgIdToStringA)(t[i].id, buf, &n, 0));
        CHECKF(strstr(buf, t[i].s) != NULL, "0x%lx -> [%s] expected to contain [%s]", t[i].id, buf, t[i].s);
    }
}

TEST(tsh_algid_unknown_formatted) {
    REQUIRE(UN(InternetAlgIdToStringA)); REQUIRE(UN(InternetAlgIdToStringW));
    static const DWORD unk[] = { 0, 1, 0x1234, 0xFFFF, 0x12345678 };
    for (int i = 0; i < 5; i++) {
        char buf[160] = ""; DWORD n = sizeof buf;
        SET_ERR(0xdead);
        BOOL r = UN(InternetAlgIdToStringA)(unk[i], buf, &n, 0);
        DWORD e = GetLastError();
        t_note("unknown alg 0x%lx -> r=%d e=%lu [%s]", unk[i], r, e, buf);
        CHECK(r); EXPECT_EQ(e, 0); EXPECT_EQ(n, strlen(buf)); CHECK(n > 0);
        WCHAR w[160] = L""; DWORD wn = 160;
        CHECK(UN(InternetAlgIdToStringW)(unk[i], w, &wn, 0));
        EXPECT_EQ(wn, n);
    }
    /* the id is rendered in the text: two different unknown ids give different strings */
    char a[160] = "", b[160] = ""; DWORD na = sizeof a, nb = sizeof b;
    UN(InternetAlgIdToStringA)(0x1234, a, &na, 0); UN(InternetAlgIdToStringA)(0x4321, b, &nb, 0);
    CHECK(strcmp(a, b) != 0);
}

TEST(tsh_algid_args) {
    REQUIRE(UN(InternetAlgIdToStringA)); REQUIRE(UN(InternetAlgIdToStringW));
    char buf[64]; WCHAR wb[64]; DWORD n = sizeof buf;
    SET_ERR(0); CHECK(!UN(InternetAlgIdToStringA)(0x6801, buf, &n, 1));  EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetAlgIdToStringA)(0x6801, buf, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    n = 64;
    SET_ERR(0); CHECK(!UN(InternetAlgIdToStringW)(0x6801, wb, &n, 2));   EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetAlgIdToStringW)(0x6801, wb, NULL, 0));  EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* a small buffer: 122 and the needed size (chars incl NUL) */
    char full[64] = ""; DWORD fn = sizeof full;
    CHECK(UN(InternetAlgIdToStringA)(0x6801, full, &fn, 0));
    DWORD sn = 1; char sb[4] = "ZZZ";
    SET_ERR(0); CHECK(!UN(InternetAlgIdToStringA)(0x6801, sb, &sn, 0)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sn, fn + 1);
    EXPECT_EQ(sb[0], 'Z');                    /* nothing copied when it does not fit [D] */
}

/* ------------------------------------------------------------ InternetGetSecurityInfoByURL [D @0x36b10, W@0x36a30]
 * both outputs NULL -> FALSE 87; host not in the SSL cache -> FALSE 12028. After a TLS request the cached chain is
 * returned (duplicated) and *pdwSecureFlags = flags & 0x07A00000 (| 0x400000 when a flag at +0x368 is set). */
TEST(tsh_secinfo_args) {
    REQUIRE(UN(InternetGetSecurityInfoByURLA)); REQUIRE(UN(InternetGetSecurityInfoByURLW)); REQUIRE(UN(InternetGetSecurityInfoByURL));
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURLA)("https://127.0.0.1/", NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURLW)(L"https://127.0.0.1/", NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURL)("https://127.0.0.1/", NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tsh_secinfo_unknown_host) {
    REQUIRE(UN(InternetGetSecurityInfoByURLA)); REQUIRE(UN(InternetGetSecurityInfoByURLW));
    char url[200]; snprintf(url, sizeof url, "https://%s/", t_uniq_host("si"));
    PCCERT_CHAIN_CONTEXT ch = (PCCERT_CHAIN_CONTEXT)(ULONG_PTR)0x1234; DWORD fl = 0x5555;
    SET_ERR(0);
    CHECK(!UN(InternetGetSecurityInfoByURLA)(url, &ch, &fl));
    EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
    EXPECT_EQ((ULONG_PTR)ch, 0x1234); EXPECT_EQ(fl, 0x5555);
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURLA)(url, NULL, &fl)); EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURLA)(url, &ch, NULL)); EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
    WCHAR w[200]; MultiByteToWideChar(CP_ACP, 0, url, -1, w, 200);
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURLW)(w, &ch, &fl)); EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
    SET_ERR(0); CHECK(!UN(InternetGetSecurityInfoByURLA)("http://127.0.0.1:1/", &ch, &fl)); EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
}

TEST(tsh_secinfo_after_tls_request) {
    REQUIRE(UN(InternetGetSecurityInfoByURLA)); REQUIRE(UN(InternetGetSecurityInfoByURLW));
    REQUIRE(U(CertFreeCertificateChain)); REQUIRE(U(CertCompareCertificate));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "tls"), S_LOOP() };
    srv *s = srv_https(st, 3, SRV_CERT_LOCALHOST);
    if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("si");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/si", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0) : NULL;
    CHECK(hr != NULL);
    BOOL sent = FALSE;
    if (hr) { t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA); sent = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); }
    CHECKF(sent, "send err %lu", GetLastError());
    if (sent) {
        char rb[16]; DWORD rd = 0; U(InternetReadFile)(hr, rb, sizeof rb, &rd);
        const char *url = srv_url(s, "/si");
        PCCERT_CHAIN_CONTEXT ch = NULL; DWORD fl = 0xFFFFFFFF;
        SET_ERR(0xdead);
        BOOL r = UN(InternetGetSecurityInfoByURLA)((LPSTR)url, &ch, &fl);
        DWORD e = GetLastError();
        t_note("after TLS: r=%d e=%lu chain=%p flags=0x%lx", r, e, (void *)ch, fl);
        CHECK(r); EXPECT_EQ(e, 0); CHECK(ch != NULL);
        CHECK((fl & ~0x07E00000u) == 0);
        if (ch) {
            CHECK(ch->cChain >= 1);
            if (ch->cChain >= 1 && ch->rgpChain[0]->cElement >= 1) {
                PCCERT_CONTEXT leaf = ch->rgpChain[0]->rgpElement[0]->pCertContext, mine = srv_cert_get(SRV_CERT_LOCALHOST);
                CHECK(leaf && mine && U(CertCompareCertificate)(X509_ASN_ENCODING, leaf->pCertInfo, mine->pCertInfo));
            }
            U(CertFreeCertificateChain)(ch);
        }
        /* flags-only query, other path, W */
        DWORD fl2 = 0xFFFFFFFF;
        CHECK(UN(InternetGetSecurityInfoByURLA)((LPSTR)srv_url(s, "/other/path?q=1"), NULL, &fl2));
        EXPECT_EQ(fl2, fl);
        WCHAR w[200]; MultiByteToWideChar(CP_ACP, 0, url, -1, w, 200);
        PCCERT_CHAIN_CONTEXT cw = NULL;
        CHECK(UN(InternetGetSecurityInfoByURLW)(w, &cw, NULL));
        CHECK(cw != NULL); if (cw) U(CertFreeCertificateChain)(cw);
        /* same host and port, plain http scheme: record */
        char hurl[128]; snprintf(hurl, sizeof hurl, "http://%s/", srv_hostport(s));
        PCCERT_CHAIN_CONTEXT ch3 = NULL;
        r = UN(InternetGetSecurityInfoByURLA)(hurl, &ch3, NULL);
        t_note("http:// same host:port -> r=%d e=%lu", r, GetLastError());
        if (ch3) U(CertFreeCertificateChain)(ch3);
        /* other port on the same host */
        char purl[128]; snprintf(purl, sizeof purl, "https://127.0.0.1:%u/", (unsigned)(srv_port(s) == 65535 ? 1 : srv_port(s) + 1));
        ch3 = NULL;
        r = UN(InternetGetSecurityInfoByURLA)(purl, &ch3, NULL);
        t_note("https other port -> r=%d e=%lu", r, GetLastError());
        if (ch3) U(CertFreeCertificateChain)(ch3);
    }
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
    srv_stop(s);
}
