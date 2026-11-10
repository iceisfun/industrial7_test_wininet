/* url_crack: review pass 3 additions.
 * Evidence: [D] InternetCrackUrlW@0x2d690 / FixStrings@0x2dc98 (UTF-8 inner call, UTF-16 counts), InternetCreateUrlW@0x607f0
 * (components converted with WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS); if any conversion needs the default
 * char the whole call is redone in UTF-8 with a (len+1)*3 inner buffer and the result is copied back with CP_UTF8;
 * nonzero dwXxxLength is used as the component length, 0 means wcslen), _InternetCrackUrlA@0x2dd88.
 * [VM] every hard CHECK below was observed on the Win10 22H2 VM (see EVIDENCE.md, pass 3).
 * Pure string APIs: no network, no registry, no cache, no global state. Threads are bounded and always joined.
 * VM_TIMEOUT: 120 */
#include "uc.h"

static void zcw(URL_COMPONENTSW *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }
static void zca(URL_COMPONENTSA *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }
static int acp_1252(void) { return GetACP() == 1252; }

/* ---- concurrency: the four APIs keep no shared mutable state ------------------------------------------------- */
typedef struct { int id; LONG bad; LONG done; } thr_t;
static DWORD WINAPI crack_worker(LPVOID p) {
    thr_t *t = (thr_t *)p;
    static const struct { const char *u; const char *h; unsigned port; const char *path; } v[] = {
        { "http://user:pass@host.example:8080/path/x?q=1#f", "host.example", 8080, "/path/x" },
        { "https://a.b.c/", "a.b.c", 443, "/" },
        { "ftp://f.example/d/f.txt", "f.example", 21, "/d/f.txt" },
        { "http://[::1]:81/v6", "[::1]", 81, "/v6" },
        { "gopher://g:70/1/x", "g", 70, "/1/x" },
    };
    for (int it = 0; it < 200; it++) {
        int k = (it + t->id) % 5;
        char ub[128], h[64], pa[64], x[64];
        strcpy(ub, v[k].u);
        URL_COMPONENTSA a; zca(&a);
        a.lpszHostName = h; a.dwHostNameLength = sizeof h; a.lpszUrlPath = pa; a.dwUrlPathLength = sizeof pa;
        a.lpszExtraInfo = x; a.dwExtraInfoLength = sizeof x;
        if (!U(InternetCrackUrlA)(ub, 0, 0, &a) || strcmp(h, v[k].h) || strcmp(pa, v[k].path) || a.nPort != v[k].port)
            InterlockedIncrement(&t->bad);
        WCHAR wh[64], wpa[64];
        URL_COMPONENTSW w; zcw(&w);
        w.lpszHostName = wh; w.dwHostNameLength = 64; w.lpszUrlPath = wpa; w.dwUrlPathLength = 64;
        WCHAR wu[128]; MultiByteToWideChar(CP_UTF8, 0, v[k].u, -1, wu, 128);
        if (!U(InternetCrackUrlW)(wu, 0, 0, &w) || w.nPort != v[k].port || w.dwHostNameLength != strlen(v[k].h))
            InterlockedIncrement(&t->bad);
        char o[256]; DWORD n = sizeof o;
        if (!U(InternetCanonicalizeUrlA)("http://H/a/./b/../c d", o, &n, 0) || strcmp(o, "http://h/a/c%20d"))
            InterlockedIncrement(&t->bad);
        n = sizeof o;
        if (!U(InternetCombineUrlA)("http://h/a/b/c", "../d", o, &n, 0) || strcmp(o, "http://h/a/d"))
            InterlockedIncrement(&t->bad);
        URL_COMPONENTSA c; zca(&c); c.nScheme = INTERNET_SCHEME_HTTPS; c.nPort = 443; c.lpszHostName = "h"; c.lpszUrlPath = "/x";
        n = sizeof o;
        if (!U(InternetCreateUrlA)(&c, 0, o, &n) || strcmp(o, "https://h/x"))
            InterlockedIncrement(&t->bad);
        InterlockedIncrement(&t->done);
    }
    return 0;
}
TEST(url_crack_r3_threads_consistent) {
    /* 4 threads x 200 iterations of crack A/W, canonicalize, combine, create: every result must be the same as the
     * single-threaded one (no static scratch buffers). Bounded: 30 s total, threads always joined. */
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW)); REQUIRE(U(InternetCanonicalizeUrlA));
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCreateUrlA));
    thr_t t[4]; HANDLE h[4]; int n = 0;
    for (int i = 0; i < 4; i++) {
        t[i].id = i; t[i].bad = 0; t[i].done = 0;
        h[i] = CreateThread(NULL, 0, crack_worker, &t[i], 0, NULL);
        CHECKF(h[i] != NULL, "CreateThread %d: %lu", i, GetLastError());
        if (h[i]) n++; else break;
    }
    if (n) {
        DWORD w = WaitForMultipleObjects(n, h, TRUE, 30000);
        CHECKF(w < WAIT_OBJECT_0 + n, "threads did not finish within 30 s (wait %lu)", w);
        if (w == WAIT_TIMEOUT) WaitForMultipleObjects(n, h, TRUE, 30000);
    }
    for (int i = 0; i < n; i++) {
        CHECKF(t[i].bad == 0, "thread %d: %ld mismatches", i, t[i].bad);
        CHECKF(t[i].done == 200, "thread %d: %ld iterations", i, t[i].done);
        CloseHandle(h[i]);
    }
}

/* ---- dwUrlLength with an embedded NUL ------------------------------------------------------------------------ */
TEST(url_crack_r3_embedded_nul_inside_length) {
    /* "http://h\0/x" cracked with dwUrlLength 11 (covers the NUL): recorded for A and W, then pinned */
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    char u[] = "http://h\0/x";
    char h[64], pa[64]; h[0] = pa[0] = 0;
    URL_COMPONENTSA a; zca(&a); a.lpszHostName = h; a.dwHostNameLength = 64; a.lpszUrlPath = pa; a.dwUrlPathLength = 64;
    SET_ERR(0xdead);
    BOOL r = U(InternetCrackUrlA)(u, 11, 0, &a);
    DWORD e = GetLastError();
    t_note("A embedded NUL: r=%d err=%lu host \"%s\" (%lu) path \"%s\" (%lu)", r, e, h, a.dwHostNameLength, pa, a.dwUrlPathLength);
    CHECKF(r && !strcmp(h, "h") && !strcmp(pa, ""), "A r=%d err=%lu host \"%s\" path \"%s\"", r, e, h, pa);
    WCHAR wu[] = L"http://h\0/x";
    WCHAR wh[64], wpa[64]; wh[0] = wpa[0] = 0;
    URL_COMPONENTSW w; zcw(&w); w.lpszHostName = wh; w.dwHostNameLength = 64; w.lpszUrlPath = wpa; w.dwUrlPathLength = 64;
    SET_ERR(0xdead);
    r = U(InternetCrackUrlW)(wu, 11, 0, &w);
    e = GetLastError();
    t_note("W embedded NUL: r=%d err=%lu host \"%s\" (%lu) path \"%s\" (%lu)", r, e, uc_a(wh), w.dwHostNameLength, uc_a(wpa), w.dwUrlPathLength);
    CHECKF(r && !lstrcmpW(wh, L"h") && !lstrcmpW(wpa, L""), "W r=%d err=%lu host \"%s\" path \"%s\"", r, e, uc_a(wh), uc_a(wpa));
}

/* ---- W: characters outside the BMP (surrogate pairs) ---------------------------------------------------------- */
TEST(url_crack_r3_W_surrogate_pairs_lengths) {
    /* [D] lengths are UTF-16 code units (MultiByteToWideChar over the UTF-8 span): U+1F600 counts 2 */
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://h\xD83D\xDE00/p\xD83D\xDE00?x\xD83D\xDE00";
    WCHAR h[32], pa[32], x[32];
    URL_COMPONENTSW c; zcw(&c);
    c.lpszHostName = h; c.dwHostNameLength = 32; c.lpszUrlPath = pa; c.dwUrlPathLength = 32; c.lpszExtraInfo = x; c.dwExtraInfoLength = 32;
    SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlW)(u, 0, 0, &c));
    EXPECT_ERR(0);
    EXPECT_WSTR(h, L"h\xD83D\xDE00");      EXPECT_EQ(c.dwHostNameLength, 3);
    EXPECT_WSTR(pa, L"/p\xD83D\xDE00");    EXPECT_EQ(c.dwUrlPathLength, 4);
    EXPECT_WSTR(x, L"?x\xD83D\xDE00");     EXPECT_EQ(c.dwExtraInfoLength, 4);
}
TEST(url_crack_r3_W_surrogate_pairs_pointer_mode) {
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://h\xD83D\xDE00/p\xD83D\xDE00?x";
    URL_COMPONENTSW c; zcw(&c); c.dwHostNameLength = 1; c.dwUrlPathLength = 1; c.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlW)(u, 0, 0, &c));
    CHECK(c.lpszHostName == u + 7);  EXPECT_EQ(c.dwHostNameLength, 3);
    CHECK(c.lpszUrlPath == u + 10);  EXPECT_EQ(c.dwUrlPathLength, 4);
    CHECK(c.lpszExtraInfo == u + 14); EXPECT_EQ(c.dwExtraInfoLength, 2);
}
TEST(url_crack_r3_W_surrogate_pair_buffer_boundary) {
    /* host "h" U+1F600 = 3 code units, 5 UTF-8 bytes. L=3: inner buffer 12 bytes fits, copy-back needs 4 -> 122,
     * length stays 3; L=4 fits. */
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://h\xD83D\xDE00/";
    for (int L = 3; L <= 4; L++) {
        WCHAR h[16]; lstrcpyW(h, L"QQQQQQQQ");
        URL_COMPONENTSW c; zcw(&c); c.lpszHostName = h; c.dwHostNameLength = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(u, 0, 0, &c);
        DWORD e = GetLastError();
        if (L == 3) {
            CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "L=3 r=%d err=%lu", r, e);
            EXPECT_EQ(c.dwHostNameLength, 3);
            EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTP);
        } else {
            CHECKF(r && e == 0, "L=4 r=%d err=%lu", r, e);
            EXPECT_WSTR(h, L"h\xD83D\xDE00"); EXPECT_EQ(c.dwHostNameLength, 3);
        }
    }
}
TEST(url_crack_r3_W_lone_surrogate) {
    /* [D] the W URL is converted with WideCharToMultiByte(CP_UTF8, 0): a lone surrogate becomes U+FFFD (EF BF BD) */
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://h/a\xD800" L"b";
    WCHAR pa[32]; pa[0] = 0;
    URL_COMPONENTSW c; zcw(&c); c.lpszUrlPath = pa; c.dwUrlPathLength = 32;
    SET_ERR(0xdead);
    BOOL r = U(InternetCrackUrlW)(u, 0, 0, &c);
    DWORD e = GetLastError();
    t_note("lone surrogate: r=%d err=%lu path %04x %04x %04x %04x len %lu", r, e, pa[0], pa[1], pa[2], pa[3], c.dwUrlPathLength);
    CHECKF(r && e == 0, "r=%d err=%lu", r, e);
    EXPECT_WSTR(pa, L"/a\xFFFD" L"b");
    EXPECT_EQ(c.dwUrlPathLength, 4);
}

/* ---- DECODE | ESCAPE together --------------------------------------------------------------------------------- */
TEST(url_crack_r3_decode_and_escape_lengths) {
    /* ESCAPE's DecodeUrlInSitu runs before the split, so the stored lengths are the decoded ones; the DECODE pass
     * that follows finds nothing left to unescape. A and W agree. */
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    uc_crack_t o;
    uc_crackA("http://h/a%20b?c%20d", ICU_DECODE | ICU_ESCAPE, 1, &o);
    CHECKF(o.r, "A err %lu", o.err);
    EXPECT_STR(o.path, "/a b");  EXPECT_EQ(o.lpath, 4);
    EXPECT_STR(o.extra, "?c d"); EXPECT_EQ(o.lextra, 4);
    uc_crackW("http://h/a%20b?c%20d", ICU_DECODE | ICU_ESCAPE, 1, &o);
    CHECKF(o.r, "W err %lu", o.err);
    EXPECT_STR(o.path, "/a b");  EXPECT_EQ(o.lpath, 4);
    EXPECT_STR(o.extra, "?c d"); EXPECT_EQ(o.lextra, 4);
}
TEST(url_crack_r3_W_decode_escape_input_untouched) {
    REQUIRE(U(InternetCrackUrlW));
    WCHAR u[] = L"http://h%41st/a%20b?c%20d";
    WCHAR pa[64]; URL_COMPONENTSW c;
    DWORD fl[] = { 0, ICU_DECODE, ICU_ESCAPE, ICU_DECODE | ICU_ESCAPE };
    for (int i = 0; i < 4; i++) {
        zcw(&c); c.lpszUrlPath = pa; c.dwUrlPathLength = 64;
        CHECKF(U(InternetCrackUrlW)(u, 0, fl[i], &c), "flags 0x%lx err %lu", fl[i], GetLastError());
        EXPECT_WSTR(u, L"http://h%41st/a%20b?c%20d");
    }
}

/* ---- InternetCreateUrlW: component lengths and the UTF-8 fallback ---------------------------------------------- */
TEST(url_crack_r3_create_W_component_lengths_honoured) {
    /* [D] nonzero dwXxxLength is passed to WideCharToMultiByte as the source count */
    REQUIRE(U(InternetCreateUrlW));
    URL_COMPONENTSW c; WCHAR o[64]; DWORD n;
    zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.lpszHostName = L"host"; c.dwHostNameLength = 2; c.lpszUrlPath = L"/";
    n = 64; CHECK(U(InternetCreateUrlW)(&c, 0, o, &n)); EXPECT_WSTR(o, L"http://ho:0/"); EXPECT_EQ(n, 12);
    zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.nPort = 80; c.lpszHostName = L"h"; c.lpszUrlPath = L"/abcdef"; c.dwUrlPathLength = 3;
    n = 64; CHECK(U(InternetCreateUrlW)(&c, 0, o, &n)); EXPECT_WSTR(o, L"http://h/ab");
    zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.nPort = 80; c.lpszHostName = L"h"; c.lpszUrlPath = L"/";
    c.lpszUserName = L"userXX"; c.dwUserNameLength = 4; c.lpszPassword = L"pwXX"; c.dwPasswordLength = 2;
    n = 64; CHECK(U(InternetCreateUrlW)(&c, 0, o, &n)); EXPECT_WSTR(o, L"http://user:pw@h/");
    zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.nPort = 80; c.lpszHostName = L"h"; c.lpszUrlPath = L"/";
    c.lpszExtraInfo = L"?a=1&b=2"; c.dwExtraInfoLength = 4;
    n = 64; CHECK(U(InternetCreateUrlW)(&c, 0, o, &n)); EXPECT_WSTR(o, L"http://h/?a=1");
    zcw(&c); c.nScheme = INTERNET_SCHEME_DEFAULT; c.nPort = 443; c.lpszScheme = L"https-x"; c.dwSchemeLength = 5; c.lpszHostName = L"h"; c.lpszUrlPath = L"/";
    n = 64; CHECK(U(InternetCreateUrlW)(&c, 0, o, &n)); EXPECT_WSTR(o, L"https://h/");
}
TEST(url_crack_r3_create_W_utf8_fallback) {
    /* [D] a component that the ANSI code page cannot represent (U+4E2D under 1252) restarts the whole call in UTF-8:
     * every component is then UTF-8, ICU_ESCAPE escapes UTF-8 bytes (U+00E9 -> %C3%A9 instead of %E9) and the result
     * is copied back with CP_UTF8. Gated on ACP 1252 (other code pages may represent the characters). */
    REQUIRE(U(InternetCreateUrlW));
    if (!acp_1252()) { t_skip("needs ACP 1252 (have %u)", GetACP()); return; }
    static const struct { const WCHAR *path; DWORD fl; const WCHAR *want; } v[] = {
        { L"/\u4e2d", 0, L"http://h/\u4e2d" },
        { L"/\u4e2d", ICU_ESCAPE, L"http://h/%E4%B8%AD" },
        { L"/\u00e9\u4e2d", 0, L"http://h/\u00e9\u4e2d" },
        { L"/\u00e9\u4e2d", ICU_ESCAPE, L"http://h/%C3%A9%E4%B8%AD" },
        { L"/\u00e9", ICU_ESCAPE, L"http://h/%E9" },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        URL_COMPONENTSW c; WCHAR o[128]; DWORD n = 128; o[0] = 0;
        zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.nPort = 80; c.lpszHostName = L"h"; c.lpszUrlPath = (LPWSTR)v[i].path;
        SET_ERR(0xdead);
        BOOL r = U(InternetCreateUrlW)(&c, v[i].fl, o, &n);
        DWORD e = GetLastError();
        CHECKF(r, "row %u failed %lu", i, e);
        CHECKF(!lstrcmpW(o, v[i].want), "row %u: got \"%s\" want \"%s\"", i, uc_a(o), uc_a(v[i].want));
        CHECKF(n == (DWORD)lstrlenW(v[i].want), "row %u: len %lu want %d", i, n, lstrlenW(v[i].want));
    }
}
TEST(url_crack_r3_create_W_utf8_fallback_host_and_user) {
    REQUIRE(U(InternetCreateUrlW));
    if (!acp_1252()) { t_skip("needs ACP 1252 (have %u)", GetACP()); return; }
    URL_COMPONENTSW c; WCHAR o[128]; DWORD n = 128; o[0] = 0;
    zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.nPort = 80; c.lpszHostName = L"\u4e2d.example"; c.lpszUserName = L"u\u00e9";
    c.lpszUrlPath = L"/x";
    CHECKF(U(InternetCreateUrlW)(&c, 0, o, &n), "err %lu", GetLastError());
    EXPECT_WSTR(o, L"http://u\u00e9@\u4e2d.example/x");
    EXPECT_EQ(n, 21);
}
TEST(url_crack_r3_create_W_utf8_fallback_size_query) {
    /* recorded: size query (NULL buffer) for a path that needs the UTF-8 restart */
    REQUIRE(U(InternetCreateUrlW));
    if (!acp_1252()) { t_skip("needs ACP 1252 (have %u)", GetACP()); return; }
    URL_COMPONENTSW c; DWORD n = 0;
    zcw(&c); c.nScheme = INTERNET_SCHEME_HTTP; c.nPort = 80; c.lpszHostName = L"h"; c.lpszUrlPath = L"/\u4e2d";
    SET_ERR(0xdead);
    BOOL r = U(InternetCreateUrlW)(&c, 0, NULL, &n);
    DWORD e = GetLastError();
    t_note("UTF-8 fallback size query: r=%d err=%lu n=%lu", r, e, n);
    CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "r=%d err=%lu", r, e);
    /* "http://h/" + 3 UTF-8 bytes + NUL = 13 bytes -> x2 */
    EXPECT_EQ(n, 26);
}

/* ---- Create -> Crack round trip through W --------------------------------------------------------------------- */
TEST(url_crack_r3_create_crack_roundtrip_W) {
    REQUIRE(U(InternetCreateUrlW)); REQUIRE(U(InternetCrackUrlW));
    static const struct { INTERNET_SCHEME ns; const WCHAR *h; int port; const WCHAR *u, *p, *path, *x; } v[] = {
        { INTERNET_SCHEME_HTTP, L"host.example", 8080, L"user", L"pass", L"/p/q", L"?x=1#y" },
        { INTERNET_SCHEME_HTTPS, L"h", 443, NULL, NULL, L"/a", NULL },
        { INTERNET_SCHEME_FTP, L"f.example", 2121, L"u", NULL, L"/d/f.txt", NULL },
        { INTERNET_SCHEME_HTTP, L"::1", 81, NULL, NULL, L"/v6", NULL },
        { INTERNET_SCHEME_GOPHER, L"g", 70, NULL, NULL, L"/1/x", NULL },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        URL_COMPONENTSW c; WCHAR o[256]; DWORD n = 256;
        zcw(&c); c.nScheme = v[i].ns; c.nPort = (INTERNET_PORT)v[i].port; c.lpszHostName = (LPWSTR)v[i].h;
        c.lpszUserName = (LPWSTR)v[i].u; c.lpszPassword = (LPWSTR)v[i].p; c.lpszUrlPath = (LPWSTR)v[i].path; c.lpszExtraInfo = (LPWSTR)v[i].x;
        CHECKF(U(InternetCreateUrlW)(&c, 0, o, &n), "create row %u err %lu", i, GetLastError());
        WCHAR h[64], us[32], pw[32], pa[64], x[64]; h[0] = us[0] = pw[0] = pa[0] = x[0] = 0;
        URL_COMPONENTSW k; zcw(&k);
        k.lpszHostName = h; k.dwHostNameLength = 64; k.lpszUserName = us; k.dwUserNameLength = 32;
        k.lpszPassword = pw; k.dwPasswordLength = 32; k.lpszUrlPath = pa; k.dwUrlPathLength = 64; k.lpszExtraInfo = x; k.dwExtraInfoLength = 64;
        CHECKF(U(InternetCrackUrlW)(o, 0, 0, &k), "crack \"%s\" err %lu", uc_a(o), GetLastError());
        const char *t = uc_a(o);
        CHECKF(k.nScheme == v[i].ns && k.nPort == v[i].port, "%s: ns %d port %u", t, k.nScheme, k.nPort);
        int v6 = !lstrcmpW(v[i].h, L"::1");
        CHECKF(!lstrcmpW(h, v6 ? L"[::1]" : v[i].h), "%s: host \"%s\"", t, uc_a(h));
        CHECKF(!lstrcmpW(us, v[i].u ? v[i].u : L"") && !lstrcmpW(pw, v[i].p ? v[i].p : L""), "%s: userinfo", t);
        CHECKF(!lstrcmpW(pa, v[i].path) && !lstrcmpW(x, v[i].x ? v[i].x : L""), "%s: path \"%s\" extra \"%s\"", t, uc_a(pa), uc_a(x));
    }
}

/* ---- Canonicalize / Combine stability ----------------------------------------------------------------------- */
TEST(url_crack_r3_canon_idempotent_http) {
    /* canonicalizing an already canonical http URL (flags 0) returns it unchanged, A and W */
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    static const char *v[] = { "HTTP://Host.Example:80/a/./b/../c", "http://h/a b/c?d e#f g", "http://h/%7Euser/", "https://h:443/x/../y",
                               "http://h/a\\b\\..\\c", "http://u:p@h:81/p?q", "ftp://f/d/../e", "http://h/a/b/../../../x" };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        char o1[512], o2[512]; DWORD n1 = sizeof o1, n2 = sizeof o2;
        CHECKF(U(InternetCanonicalizeUrlA)(v[i], o1, &n1, 0), "A1 %s err %lu", v[i], GetLastError());
        CHECKF(U(InternetCanonicalizeUrlA)(o1, o2, &n2, 0), "A2 %s err %lu", o1, GetLastError());
        CHECKF(!strcmp(o1, o2) && n1 == n2, "A not idempotent: \"%s\" -> \"%s\" -> \"%s\"", v[i], o1, o2);
        WCHAR w1[512], w2[512]; n1 = 512; n2 = 512;
        CHECKF(U(InternetCanonicalizeUrlW)(uc_w(v[i]), w1, &n1, 0), "W1 %s err %lu", v[i], GetLastError());
        CHECKF(U(InternetCanonicalizeUrlW)(w1, w2, &n2, 0), "W2 err %lu", GetLastError());
        CHECKF(!lstrcmpW(w1, w2) && n1 == n2, "W not idempotent: \"%s\" -> \"%s\"", v[i], uc_a(w2));
        CHECKF(!strcmp(uc_a(w1), o1), "A/W differ for \"%s\": \"%s\" vs \"%s\"", v[i], o1, uc_a(w1));
    }
}
TEST(url_crack_r3_combine_equals_canon_of_absolute) {
    /* combining any base with an absolute http URL gives the canonical form of that URL (flags 0) */
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCanonicalizeUrlA));
    static const char *bases[] = { "http://a/b/c/d;p?q", "ftp://f/x/y", "https://s/", "http://h/a b/" };
    static const char *rel[] = { "http://X.Y/a/./b/../c d", "https://h:443/p?q#f", "ftp://u@f:21/a/../b" };
    for (unsigned i = 0; i < sizeof bases / sizeof *bases; i++) for (unsigned j = 0; j < sizeof rel / sizeof *rel; j++) {
        char c1[512], c2[512]; DWORD n1 = sizeof c1, n2 = sizeof c2;
        CHECKF(U(InternetCombineUrlA)(bases[i], rel[j], c1, &n1, 0), "combine %s + %s err %lu", bases[i], rel[j], GetLastError());
        CHECKF(U(InternetCanonicalizeUrlA)(rel[j], c2, &n2, 0), "canon %s err %lu", rel[j], GetLastError());
        CHECKF(!strcmp(c1, c2), "%s + %s: combine \"%s\" canon \"%s\"", bases[i], rel[j], c1, c2);
    }
}
TEST(url_crack_r3_W_non_bmp_canon_combine_recorded) {
    /* recorded only: W canonicalize/combine of characters outside the ANSI code page (shlwapi behaviour) */
    REQUIRE(U(InternetCanonicalizeUrlW)); REQUIRE(U(InternetCombineUrlW));
    WCHAR o[256]; DWORD n = 256;
    BOOL r = U(InternetCanonicalizeUrlW)(L"http://h/\u4e2d \xD83D\xDE00", o, &n, 0);
    t_note("canonW U+4E2D U+1F600: r=%d err=%lu \"%s\" n=%lu (ACP %u)", r, r ? 0 : GetLastError(), r ? uc_a(o) : "", n, GetACP());
    CHECK(r);
    n = 256;
    r = U(InternetCombineUrlW)(L"http://h/a/", L"\u4e2d", o, &n, 0);
    t_note("combineW U+4E2D: r=%d \"%s\" n=%lu", r, r ? uc_a(o) : "", n);
    CHECK(r);
    n = 256;
    r = U(InternetCanonicalizeUrlW)(L"http://h/\u4e2d", o, &n, ICU_NO_ENCODE);
    CHECK(r);
    if (r) { EXPECT_WSTR(o, L"http://h/\u4e2d"); EXPECT_EQ(n, 10); }
}

/* ---- miscellaneous crack edges -------------------------------------------------------------------------------- */
TEST(url_crack_r3_A_scheme_only_buffers) {
    /* only the scheme buffer is supplied: the other components are skipped, nScheme/nPort still set */
    REQUIRE(U(InternetCrackUrlA));
    static const struct { const char *u; const char *s; int ns; unsigned port; } v[] = {
        { "HTTPS://H/", "HTTPS", INTERNET_SCHEME_HTTPS, 443 }, { "Ftp://h:2121/", "Ftp", INTERNET_SCHEME_FTP, 2121 },
        { "x-y.z+w://h/", "x-y.z+w", INTERNET_SCHEME_UNKNOWN, 0 }, { "mailto:a@b", "mailto", INTERNET_SCHEME_MAILTO, 0 },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        char s[32]; URL_COMPONENTSA c; zca(&c); c.lpszScheme = s; c.dwSchemeLength = 32;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlA)(v[i].u, 0, 0, &c);
        CHECKF(r, "%s err %lu", v[i].u, GetLastError());
        CHECKF(!strcmp(s, v[i].s) && c.dwSchemeLength == strlen(v[i].s), "%s: scheme \"%s\" %lu", v[i].u, s, c.dwSchemeLength);
        CHECKF(c.nScheme == v[i].ns && c.nPort == v[i].port, "%s: ns %d port %u", v[i].u, c.nScheme, c.nPort);
        CHECK(c.lpszHostName == NULL && c.dwHostNameLength == 0);
    }
}
TEST(url_crack_r3_mixed_pointer_and_buffer_modes) {
    /* host as a buffer, path in pointer mode, user not requested: each component follows its own mode */
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    const char *u = "http://us:pw@host.example/a/b?c";
    char h[64]; URL_COMPONENTSA a; zca(&a);
    a.lpszHostName = h; a.dwHostNameLength = 64; a.dwUrlPathLength = 1; a.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &a));
    EXPECT_STR(h, "host.example"); EXPECT_EQ(a.dwHostNameLength, 12);
    CHECK(a.lpszUrlPath == u + 25);   EXPECT_EQ(a.dwUrlPathLength, 4);
    CHECK(a.lpszExtraInfo == u + 29); EXPECT_EQ(a.dwExtraInfoLength, 2);
    CHECK(a.lpszUserName == NULL);    EXPECT_EQ(a.dwUserNameLength, 0);
    const WCHAR *wu = L"http://us:pw@host.example/a/b?c";
    WCHAR wh[64]; URL_COMPONENTSW w; zcw(&w);
    w.lpszHostName = wh; w.dwHostNameLength = 64; w.dwUrlPathLength = 1; w.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlW)(wu, 0, 0, &w));
    EXPECT_WSTR(wh, L"host.example"); EXPECT_EQ(w.dwHostNameLength, 12);
    CHECK(w.lpszUrlPath == wu + 25);   EXPECT_EQ(w.dwUrlPathLength, 4);
    CHECK(w.lpszExtraInfo == wu + 29); EXPECT_EQ(w.dwExtraInfoLength, 2);
    CHECK(w.lpszUserName == NULL);     EXPECT_EQ(w.dwUserNameLength, 0);
}
TEST(url_crack_r3_W_explicit_length_non_ascii) {
    /* dwUrlLength counts WCHARs on the W side: cutting after "/\u00e9" keeps exactly that */
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://h/\u00e9\u4e2dxyz";
    WCHAR pa[32]; URL_COMPONENTSW c;
    for (DWORD len = 9; len <= 12; len++) {
        zcw(&c); c.lpszUrlPath = pa; c.dwUrlPathLength = 32; pa[0] = 0;
        CHECKF(U(InternetCrackUrlW)(u, len, 0, &c), "len %lu err %lu", len, GetLastError());
        CHECKF(c.dwUrlPathLength == len - 8 && !wcsncmp(pa, u + 8, len - 8) && pa[len - 8] == 0,
               "len %lu: path \"%s\" %lu", len, uc_a(pa), c.dwUrlPathLength);
    }
}
