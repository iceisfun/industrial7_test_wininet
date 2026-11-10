/* url_crack: InternetCrackUrlW wrapper mechanics and the per-component length protocol.
 * Evidence: [D] wininet!InternetCrackUrlW@0x2d690 and FixStrings@0x2dc98 (decomp from the Win10 reference corpus):
 *  - for every component whose buffer pointer is non-NULL the wrapper sizes an internal UTF-8 buffer of (len+1)*3
 *    bytes, where len is the caller's length or, when that is 0, inetstrlenW(caller's buffer);
 *  - after the inner _InternetCrackUrlA succeeds, FixStrings copies scheme, host, user, password, path, extra back
 *    in that order with MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ..., cch = caller's length); the first
 *    copy that fails stops the loop (later components keep their buffers AND lengths) and the call fails;
 *  - a copy that fails with ERROR_NO_UNICODE_TRANSLATION (bytes decoded from %XX that are not UTF-8) restarts the
 *    whole copy-back with CP_ACP;
 *  - a component with no internal pointer gets length 0; in pointer mode the pointer is the caller's string plus the
 *    UTF-16 count of the UTF-8 prefix, and the length is the UTF-16 count of the (possibly %-decoded) component.
 * [VM] every expectation below was observed on the Win10 22H2 VM (probe boot ucprobe3 + the area run).
 * VM_TIMEOUT: 120 */
#include "uc.h"

static void zcw(URL_COMPONENTSW *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }
static void zca(URL_COMPONENTSA *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }
static int acp_1252(void) { return GetACP() == 1252; }

/* ---- W: a buffer with length 0 is sized from its current contents ------------------------------------------ */
TEST(url_crack_wrap_W_len0_buffer_sized_by_contents) {
    /* [D] len 0 + buffer -> inetstrlenW(buffer); copy-back with cch 0 only counts. [VM] r=1, len 4, buffer unchanged */
    REQUIRE(U(InternetCrackUrlW));
    static const WCHAR *init[] = { L"xxxxxxxx", L"x" };
    for (int i = 0; i < 2; i++) {
        URL_COMPONENTSW c; WCHAR h[64]; lstrcpyW(h, init[i]);
        zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 0;
        SET_ERR(0xdead);
        CHECKF(U(InternetCrackUrlW)(L"http://host/p", 0, 0, &c), "buffer \"%s\": failed %lu", uc_a(init[i]), GetLastError());
        EXPECT_ERR(0);
        EXPECT_EQ(c.dwHostNameLength, 4);
        CHECKF(!lstrcmpW(h, init[i]), "buffer rewritten: \"%s\"", uc_a(h));
        EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTP);
        EXPECT_EQ(c.nPort, 80);
    }
}
TEST(url_crack_wrap_W_len0_empty_buffer_fails) {
    /* "" -> internal buffer of 3 bytes -> inner A call fails 122; nothing is written back (nScheme stays 0) */
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR h[64]; h[0] = 0;
    zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlW)(L"http://host/p", 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwHostNameLength, 0);
    EXPECT_EQ(c.nScheme, 0);
    EXPECT_EQ(c.nPort, 0);
}
TEST(url_crack_wrap_A_len0_buffer_is_too_small) {
    /* A has no such sizing: len 0 <= 4 -> 122, *len = 5, and the buffer is not even cleared */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char h[64]; strcpy(h, "xxxxxxxx");
    zca(&c); c.lpszHostName = h; c.dwHostNameLength = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)("http://host/p", 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwHostNameLength, 5);
    CHECK(c.lpszHostName == h);
    EXPECT_STR(h, "xxxxxxxx");
}

/* ---- W: copy-back order and partial writes ----------------------------------------------------------------- */
TEST(url_crack_wrap_W_copyback_stops_at_failing_component) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR s[16], h[8], u[16], pa[64];
    lstrcpyW(s, L"SS"); lstrcpyW(h, L"HHH"); lstrcpyW(u, L"ZZ"); lstrcpyW(pa, L"QQ");
    zcw(&c);
    c.lpszScheme = s; c.dwSchemeLength = 16; c.lpszHostName = h; c.dwHostNameLength = 3;
    c.lpszUserName = u; c.dwUserNameLength = 16; c.lpszUrlPath = pa; c.dwUrlPathLength = 64;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlW)(L"http://me@hosts/p", 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_WSTR(s, L"http");  EXPECT_EQ(c.dwSchemeLength, 4);          /* before the failure: copied */
    CHECK(h[0] == 'h' && h[1] == 'o' && h[2] == 's');                  /* failing one: first 3 chars, no NUL */
    EXPECT_EQ(c.dwHostNameLength, 3);
    EXPECT_WSTR(u, L"ZZ");    EXPECT_EQ(c.dwUserNameLength, 16);       /* after: untouched */
    EXPECT_WSTR(pa, L"QQ");   EXPECT_EQ(c.dwUrlPathLength, 64);
    EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTP);                        /* inner call succeeded: set */
    EXPECT_EQ(c.nPort, 80);
}
TEST(url_crack_wrap_W_copyback_path_fails_extra_untouched) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR h[16], pa[4], x[16];
    lstrcpyW(x, L"XX");
    zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 16; c.lpszUrlPath = pa; c.dwUrlPathLength = 4;
    c.lpszExtraInfo = x; c.dwExtraInfoLength = 16;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlW)(L"http://h/abcdef?q", 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_WSTR(h, L"h"); EXPECT_EQ(c.dwHostNameLength, 1);
    EXPECT_EQ(c.dwUrlPathLength, 4);
    EXPECT_WSTR(x, L"XX"); EXPECT_EQ(c.dwExtraInfoLength, 16);
}
TEST(url_crack_wrap_W_host_boundary) {
    /* "hosts": 4 -> partial "host" (no NUL), 5 -> "hosts" without NUL, both 122 with the length unchanged; 6, 7 ok */
    REQUIRE(U(InternetCrackUrlW));
    for (int L = 4; L <= 7; L++) {
        URL_COMPONENTSW c; WCHAR h[16]; lstrcpyW(h, L"QQQQQQQQQQ");
        zcw(&c); c.lpszHostName = h; c.dwHostNameLength = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(L"http://hosts/p", 0, 0, &c);
        DWORD e = GetLastError();
        if (L <= 5) {
            CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "L=%d r=%d err=%lu", L, r, e);
            CHECKF(c.dwHostNameLength == (DWORD)L, "L=%d len %lu", L, c.dwHostNameLength);
            CHECKF(!wcsncmp(h, L"hosts", L) && h[L] == 'Q', "L=%d buffer \"%s\"", L, uc_a(h));
        } else {
            CHECKF(r && e == 0, "L=%d r=%d err=%lu", L, r, e);
            CHECKF(c.dwHostNameLength == 5 && !lstrcmpW(h, L"hosts"), "L=%d len %lu \"%s\"", L, c.dwHostNameLength, uc_a(h));
        }
    }
}
TEST(url_crack_wrap_W_non_ascii_internal_buffer) {
    /* 3 CJK chars = 9 UTF-8 bytes. L=2: internal 9 bytes < 10 -> inner failure, nothing touched; L=3: internal 12
     * bytes fit, copy-back fails (needs 4 WCHARs) after writing 3; L=4: ok */
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://\u4e2d\u4e2d\u4e2d/p";
    for (int L = 2; L <= 5; L++) {
        URL_COMPONENTSW c; WCHAR h[16]; h[0] = 'Q'; h[1] = 0;
        zcw(&c); c.lpszHostName = h; c.dwHostNameLength = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(u, 0, 0, &c);
        DWORD e = GetLastError();
        if (L == 2) {
            CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "L=2 r=%d err=%lu", r, e);
            EXPECT_EQ(c.dwHostNameLength, 2); EXPECT_EQ(h[0], 'Q'); EXPECT_EQ(c.nScheme, 0);
        } else if (L == 3) {
            CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "L=3 r=%d err=%lu", r, e);
            EXPECT_EQ(c.dwHostNameLength, 3); CHECK(h[0] == 0x4e2d && h[1] == 0x4e2d && h[2] == 0x4e2d);
            EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTP);
        } else {
            CHECKF(r && e == 0, "L=%d r=%d err=%lu", L, r, e);
            EXPECT_EQ(c.dwHostNameLength, 3); EXPECT_WSTR(h, L"\u4e2d\u4e2d\u4e2d");
        }
    }
}

/* ---- per-component boundary matrix (A and W) on one URL ----------------------------------------------------- */
static const char *BU = "http://user:pass@host.example:8080/path/x?q=1#f";
static const char *bwant[6] = { "http", "host.example", "user", "pass", "/path/x", "?q=1#f" };
TEST(url_crack_wrap_A_component_boundary_matrix) {
    /* [D][VM] L <= needed -> 122, *len = needed+1, first char cleared; every other component still filled */
    REQUIRE(U(InternetCrackUrlA));
    for (int comp = 0; comp < 6; comp++) for (int L = 1; L <= 15; L++) {
        char b[6][64]; URL_COMPONENTSA a; zca(&a);
        LPSTR *pp[6] = { &a.lpszScheme, &a.lpszHostName, &a.lpszUserName, &a.lpszPassword, &a.lpszUrlPath, &a.lpszExtraInfo };
        DWORD *ll[6] = { &a.dwSchemeLength, &a.dwHostNameLength, &a.dwUserNameLength, &a.dwPasswordLength, &a.dwUrlPathLength, &a.dwExtraInfoLength };
        for (int i = 0; i < 6; i++) { strcpy(b[i], "@@@@@@@@@@@@@@@@@@@@"); *pp[i] = b[i]; *ll[i] = 64; }
        *ll[comp] = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlA)(BU, 0, 0, &a);
        DWORD e = GetLastError();
        DWORD need = (DWORD)strlen(bwant[comp]);
        if ((DWORD)L > need) {
            CHECKF(r && e == 0, "comp %d L %d: r=%d err=%lu", comp, L, r, e);
            for (int i = 0; i < 6; i++)
                CHECKF(!strcmp(b[i], bwant[i]) && *ll[i] == strlen(bwant[i]), "comp %d L %d: [%d] \"%s\" %lu", comp, L, i, b[i], *ll[i]);
        } else {
            CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "comp %d L %d: r=%d err=%lu", comp, L, r, e);
            CHECKF(*ll[comp] == need + 1 && b[comp][0] == 0, "comp %d L %d: len %lu first 0x%02x", comp, L, *ll[comp], (unsigned char)b[comp][0]);
            for (int i = 0; i < 6; i++) if (i != comp)
                CHECKF(!strcmp(b[i], bwant[i]) && *ll[i] == strlen(bwant[i]), "comp %d L %d: other [%d] \"%s\" %lu", comp, L, i, b[i], *ll[i]);
        }
    }
}
TEST(url_crack_wrap_W_component_boundary_matrix) {
    /* [D][VM] W: L > needed -> ok. (L+1)*3 < needed+1 -> inner A call fails: nothing written, no length changed,
     * nScheme/nPort untouched. Otherwise copy-back fails at that component: earlier ones copied, this one gets its
     * first L chars (no NUL) and keeps length L, later ones untouched. */
    REQUIRE(U(InternetCrackUrlW));
    for (int comp = 0; comp < 6; comp++) for (int L = 1; L <= 15; L++) {
        WCHAR b[6][64]; URL_COMPONENTSW w; zcw(&w);
        LPWSTR *pp[6] = { &w.lpszScheme, &w.lpszHostName, &w.lpszUserName, &w.lpszPassword, &w.lpszUrlPath, &w.lpszExtraInfo };
        DWORD *ll[6] = { &w.dwSchemeLength, &w.dwHostNameLength, &w.dwUserNameLength, &w.dwPasswordLength, &w.dwUrlPathLength, &w.dwExtraInfoLength };
        for (int i = 0; i < 6; i++) { lstrcpyW(b[i], L"@@@@@@@@@@@@@@@@@@@@"); *pp[i] = b[i]; *ll[i] = 64; }
        *ll[comp] = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(uc_w(BU), 0, 0, &w);
        DWORD e = GetLastError();
        DWORD need = (DWORD)strlen(bwant[comp]);
        if ((DWORD)L > need) {
            CHECKF(r && e == 0, "comp %d L %d: r=%d err=%lu", comp, L, r, e);
            for (int i = 0; i < 6; i++)
                CHECKF(!strcmp(uc_a(b[i]), bwant[i]) && *ll[i] == strlen(bwant[i]), "comp %d L %d: [%d] \"%s\" %lu", comp, L, i, uc_a(b[i]), *ll[i]);
            continue;
        }
        CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "comp %d L %d: r=%d err=%lu", comp, L, r, e);
        if ((DWORD)(L + 1) * 3 < need + 1) {
            for (int i = 0; i < 6; i++)
                CHECKF(*ll[i] == (DWORD)(i == comp ? L : 64) && !lstrcmpW(b[i], L"@@@@@@@@@@@@@@@@@@@@"),
                       "comp %d L %d (inner failure): [%d] \"%s\" %lu", comp, L, i, uc_a(b[i]), *ll[i]);
            CHECKF(w.nScheme == 0 && w.nPort == 0, "comp %d L %d: nScheme %d nPort %u", comp, L, w.nScheme, w.nPort);
        } else {
            for (int i = 0; i < comp; i++)
                CHECKF(!strcmp(uc_a(b[i]), bwant[i]) && *ll[i] == strlen(bwant[i]), "comp %d L %d: earlier [%d] \"%s\" %lu", comp, L, i, uc_a(b[i]), *ll[i]);
            int okp = *ll[comp] == (DWORD)L && b[comp][L] == '@';
            for (int k = 0; k < L; k++) okp = okp && b[comp][k] == (WCHAR)bwant[comp][k];
            CHECKF(okp, "comp %d L %d: partial \"%s\" len %lu", comp, L, uc_a(b[comp]), *ll[comp]);
            for (int i = comp + 1; i < 6; i++)
                CHECKF(*ll[i] == 64 && !lstrcmpW(b[i], L"@@@@@@@@@@@@@@@@@@@@"), "comp %d L %d: later [%d] \"%s\" %lu", comp, L, i, uc_a(b[i]), *ll[i]);
            CHECKF(w.nScheme == INTERNET_SCHEME_HTTP && w.nPort == 8080, "comp %d L %d: nScheme %d nPort %u", comp, L, w.nScheme, w.nPort);
        }
    }
}

/* ---- W: CP_ACP retry when the decoded bytes are not UTF-8 ---------------------------------------------------- */
typedef struct { const WCHAR *url; DWORD flags; DWORD err; const WCHAR *host, *user, *pass, *path, *extra; DWORD lpath, lextra; int acp; } wacp_t;
TEST(url_crack_wrap_W_acp_retry) {
    /* [D] FixStrings fails with 1113 on invalid UTF-8 -> whole copy-back redone with CP_ACP; the call then succeeds
     * but GetLastError() stays 1113 (the saved error is what SetLastError gets). UTF-8 escapes need no retry.
     * ICU_DECODE lengths are the escaped A lengths re-counted over the stale tail; ICU_ESCAPE decodes first. */
    REQUIRE(U(InternetCrackUrlW));
    static const wacp_t v[] = {
        { L"http://h%E9st/p", 0, 1113, L"h\u00e9st", L"", L"", L"/p", L"", 2, 0, 1 },
        { L"http://h%E9st/p", ICU_DECODE, 1113, L"h\u00e9st", L"", L"", L"/p", L"", 2, 0, 1 },
        { L"http://h%E9st/p", ICU_ESCAPE, 1113, L"h\u00e9st", L"", L"", L"/p", L"", 2, 0, 1 },
        { L"http://h%C3%A9st/p", 0, 0, L"h\u00e9st", L"", L"", L"/p", L"", 2, 0, 0 },
        { L"http://h%C3%A9st/p", ICU_DECODE, 0, L"h\u00e9st", L"", L"", L"/p", L"", 2, 0, 0 },
        { L"http://u%E9:p%E9@h/", 0, 1113, L"h", L"u\u00e9", L"p\u00e9", L"/", L"", 1, 0, 1 },
        { L"http://u%E9:p%E9@h/", ICU_ESCAPE, 1113, L"h", L"u\u00e9", L"p\u00e9", L"/", L"", 1, 0, 1 },
        { L"http://h/%E9?%E9", 0, 0, L"h", L"", L"", L"/%E9", L"?%E9", 4, 4, 0 },
        { L"http://h/%E9?%E9", ICU_DECODE, 1113, L"h", L"", L"", L"/\u00e9", L"?\u00e9", 4, 4, 1 },
        { L"http://h/%E9?%E9", ICU_ESCAPE, 1113, L"h", L"", L"", L"/\u00e9", L"?\u00e9", 2, 2, 1 },
        { L"http://h/%C3%A9?%C3%A9", 0, 0, L"h", L"", L"", L"/%C3%A9", L"?%C3%A9", 7, 7, 0 },
        { L"http://h/%C3%A9?%C3%A9", ICU_DECODE, 0, L"h", L"", L"", L"/\u00e9", L"?\u00e9", 6, 6, 0 },
        { L"http://h/%C3%A9?%C3%A9", ICU_ESCAPE, 0, L"h", L"", L"", L"/\u00e9", L"?\u00e9", 2, 2, 0 },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        if (v[i].acp && !acp_1252()) { t_note("ACP %u: skipping %s 0x%lx", GetACP(), uc_a(v[i].url), v[i].flags); continue; }
        URL_COMPONENTSW c; WCHAR h[64], u[64], p[64], pa[64], x[64];
        h[0] = u[0] = p[0] = pa[0] = x[0] = 0;
        zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUserName = u; c.dwUserNameLength = 64;
        c.lpszPassword = p; c.dwPasswordLength = 64; c.lpszUrlPath = pa; c.dwUrlPathLength = 64; c.lpszExtraInfo = x; c.dwExtraInfoLength = 64;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(v[i].url, 0, v[i].flags, &c);
        DWORD e = GetLastError();
        const char *tag = uc_a(v[i].url);
        CHECKF(r, "%s 0x%lx failed %lu", tag, v[i].flags, e);
        CHECKF(e == v[i].err, "%s 0x%lx: last error %lu want %lu", tag, v[i].flags, e, v[i].err);
        CHECKF(!lstrcmpW(h, v[i].host) && c.dwHostNameLength == (DWORD)lstrlenW(v[i].host), "%s 0x%lx host \"%s\" %lu", tag, v[i].flags, uc_a(h), c.dwHostNameLength);
        CHECKF(!lstrcmpW(u, v[i].user) && c.dwUserNameLength == (DWORD)lstrlenW(v[i].user), "%s 0x%lx user \"%s\" %lu", tag, v[i].flags, uc_a(u), c.dwUserNameLength);
        CHECKF(!lstrcmpW(p, v[i].pass) && c.dwPasswordLength == (DWORD)lstrlenW(v[i].pass), "%s 0x%lx pass \"%s\" %lu", tag, v[i].flags, uc_a(p), c.dwPasswordLength);
        CHECKF(!lstrcmpW(pa, v[i].path) && c.dwUrlPathLength == v[i].lpath, "%s 0x%lx path \"%s\" %lu", tag, v[i].flags, uc_a(pa), c.dwUrlPathLength);
        CHECKF(!lstrcmpW(x, v[i].extra) && c.dwExtraInfoLength == v[i].lextra, "%s 0x%lx extra \"%s\" %lu", tag, v[i].flags, uc_a(x), c.dwExtraInfoLength);
    }
}
TEST(url_crack_wrap_file_url_8bit_escape) {
    /* file:///C:/%E9: A gives byte 0xE9; W (ACP 1252) gives U+00C3 U+00A9 (the UTF-8 bytes of the W->UTF-8
     * conversion read back through the ACP), and with ICU_ESCAPE U+FFFD + the stale "E9" tail */
    REQUIRE(U(InternetCrackUrlW));
    if (!acp_1252()) { t_skip("needs ACP 1252"); return; }
    URL_COMPONENTSW c; WCHAR pa[64];
    zcw(&c); c.lpszUrlPath = pa; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlW)(L"file:///C:/%E9", 0, 0, &c));
    EXPECT_WSTR(pa, L"C:\\\u00c3\u00a9"); EXPECT_EQ(c.dwUrlPathLength, 5);
    zcw(&c); c.lpszUrlPath = pa; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlW)(L"file:///C:/%E9", 0, ICU_ESCAPE, &c));
    EXPECT_WSTR(pa, L"C:\\\ufffdE9"); EXPECT_EQ(c.dwUrlPathLength, 6);
}

/* ---- pointer mode with %-escapes ----------------------------------------------------------------------------- */
TEST(url_crack_wrap_W_pointer_mode_escaped_authority) {
    /* [VM] W pointer mode: offsets index the caller's string; with dwFlags 0 the host/user length is the ESCAPED
     * length ("h%41st" = 6), with ICU_DECODE (plus one real buffer) the decoded one ("hAst" = 4) */
    REQUIRE(U(InternetCrackUrlW));
    struct { const WCHAR *u; DWORD fl; long long ho, hl, uo, ul, po, pl, xo, xl, pwl; } v[] = {
        { L"http://h%41st/p?q", 0,          7, 6, -1, 0, 13, 2, 15, 2, -1 },
        { L"http://h%41st/p?q", ICU_DECODE, 7, 4, -1, 0, 13, 2, 15, 2, 0 },
        { L"http://u%41:p@h/p", 0,          14, 1, 7, 4, 15, 2, -1, 0, -1 },
        { L"http://u%41:p@h/p", ICU_DECODE, 14, 1, 7, 2, 15, 2, -1, 0, 1 },
        { L"http://h/a%20b?c%20d", 0,       7, 1, -1, 0, 8, 6, 14, 6, -1 },
        { L"http://h/a%20b?c%20d", ICU_DECODE, 7, 1, -1, 0, 8, 6, 14, 6, 0 },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        URL_COMPONENTSW c; WCHAR pb[64];
        zcw(&c); c.dwHostNameLength = c.dwUrlPathLength = c.dwExtraInfoLength = c.dwUserNameLength = 1;
        if (v[i].fl) { c.lpszPassword = pb; c.dwPasswordLength = 64; }
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(v[i].u, 0, v[i].fl, &c);
        const char *t = uc_a(v[i].u);
        CHECKF(r, "%s 0x%lx failed %lu", t, v[i].fl, GetLastError());
#define OFF(p) ((p) ? (long long)((p) - v[i].u) : -1LL)
        CHECKF(OFF(c.lpszHostName) == v[i].ho && c.dwHostNameLength == v[i].hl, "%s 0x%lx host off %lld len %lu", t, v[i].fl, OFF(c.lpszHostName), c.dwHostNameLength);
        CHECKF(OFF(c.lpszUserName) == v[i].uo && c.dwUserNameLength == v[i].ul, "%s 0x%lx user off %lld len %lu", t, v[i].fl, OFF(c.lpszUserName), c.dwUserNameLength);
        CHECKF(OFF(c.lpszUrlPath) == v[i].po && c.dwUrlPathLength == v[i].pl, "%s 0x%lx path off %lld len %lu", t, v[i].fl, OFF(c.lpszUrlPath), c.dwUrlPathLength);
        CHECKF(OFF(c.lpszExtraInfo) == v[i].xo && c.dwExtraInfoLength == v[i].xl, "%s 0x%lx extra off %lld len %lu", t, v[i].fl, OFF(c.lpszExtraInfo), c.dwExtraInfoLength);
#undef OFF
        if (v[i].pwl >= 0) CHECKF(c.dwPasswordLength == v[i].pwl, "%s pass len %lu", t, c.dwPasswordLength);
    }
}
TEST(url_crack_wrap_A_pointer_mode_escaped_host) {
    /* A, dwFlags 0: the host is decoded in place in the caller's string; the pointer/length describe "hAst" */
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://h%41st/p?q";
    URL_COMPONENTSA c; zca(&c); c.dwHostNameLength = 1; c.dwUrlPathLength = 1;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    CHECK(c.lpszHostName == u + 7);  EXPECT_EQ(c.dwHostNameLength, 4);
    CHECK(c.lpszUrlPath == u + 13);  EXPECT_EQ(c.dwUrlPathLength, 4);
    EXPECT_STR(u, "http://hAstst/p?q");
}

/* ---- dwUrlLength ---------------------------------------------------------------------------------------------- */
TEST(url_crack_wrap_url_length_extremes) {
    /* [D] W: dwUrlLength >= 0x80000000 is kept as is and the (len+1)*3 allocation overflows -> ERROR_NOT_ENOUGH_MEMORY.
     * A stops at the NUL. Both: a count that cuts "http://" short -> 12006. */
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    static const struct { DWORD len; int wr; DWORD werr; int ar; DWORD aerr; } v[] = {
        { 0x7fffffff, 1, 0, 1, 0 }, { 0x80000000, 0, ERROR_NOT_ENOUGH_MEMORY, 1, 0 }, { 0xffffffff, 0, ERROR_NOT_ENOUGH_MEMORY, 1, 0 },
        { 3, 0, 12006, 0, 12006 }, { 5, 0, 12006, 0, 12006 }, { 7, 0, 12006, 0, 12006 }, { 8, 1, 0, 1, 0 },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        URL_COMPONENTSW c; WCHAR h[64]; h[0] = 0;
        zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 64;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(L"http://h/x", v[i].len, 0, &c);
        DWORD e = GetLastError();
        CHECKF(r == v[i].wr && (r ? e == 0 : e == v[i].werr), "W len 0x%lx: r=%d err=%lu", v[i].len, r, e);
        if (r) CHECKF(!lstrcmpW(h, L"h") && c.dwHostNameLength == 1, "W len 0x%lx host \"%s\"", v[i].len, uc_a(h));
        URL_COMPONENTSA a; char ha[64]; ha[0] = 0;
        zca(&a); a.lpszHostName = ha; a.dwHostNameLength = 64;
        SET_ERR(0xdead);
        r = U(InternetCrackUrlA)("http://h/x", v[i].len, 0, &a);
        e = GetLastError();
        CHECKF(r == v[i].ar && (r ? e == 0 : e == v[i].aerr), "A len 0x%lx: r=%d err=%lu", v[i].len, r, e);
        if (r) CHECKF(!strcmp(ha, "h") && a.dwHostNameLength == 1, "A len 0x%lx host \"%s\"", v[i].len, ha);
    }
}
typedef struct { int k, r; DWORD err; unsigned port; const char *s, *h, *u, *p, *pa, *x; } sweep_t;
static const sweep_t SW[] = {
    { 1, 0, 12006, 0, "", "", "", "", "", "" },
    { 2, 0, 12006, 0, "", "", "", "", "", "" },
    { 3, 0, 12006, 0, "", "", "", "", "", "" },
    { 4, 0, 12006, 0, "", "", "", "", "", "" },
    { 5, 0, 12006, 0, "", "", "", "", "", "" },
    { 6, 0, 12006, 0, "", "", "", "", "", "" },
    { 7, 0, 12006, 0, "", "", "", "", "", "" },
    { 8, 1, 0, 80, "http", "u", "", "", "", "" },
    { 9, 1, 0, 80, "http", "u", "", "", "", "" },
    { 10, 0, 12005, 0, "", "", "", "", "", "" },
    { 11, 0, 12005, 0, "", "", "", "", "", "" },
    { 12, 1, 0, 80, "http", "h", "u", "p", "", "" },
    { 13, 1, 0, 80, "http", "h.", "u", "p", "", "" },
    { 14, 1, 0, 80, "http", "h.x", "u", "p", "", "" },
    { 15, 1, 0, 80, "http", "h.x", "u", "p", "", "" },
    { 16, 1, 0, 8, "http", "h.x", "u", "p", "", "" },
    { 17, 1, 0, 81, "http", "h.x", "u", "p", "", "" },
    { 18, 1, 0, 81, "http", "h.x", "u", "p", "/", "" },
    { 19, 1, 0, 81, "http", "h.x", "u", "p", "/a", "" },
    { 20, 1, 0, 81, "http", "h.x", "u", "p", "/a/", "" },
    { 21, 1, 0, 81, "http", "h.x", "u", "p", "/a/b", "" },
    { 22, 1, 0, 81, "http", "h.x", "u", "p", "/a/b", "?" },
    { 23, 1, 0, 81, "http", "h.x", "u", "p", "/a/b", "?q" },
    { 24, 1, 0, 81, "http", "h.x", "u", "p", "/a/b", "?q#" },
    { 25, 1, 0, 81, "http", "h.x", "u", "p", "/a/b", "?q#f" },
};
TEST(url_crack_wrap_url_length_sweep) {
    /* [VM] "http://u:p@h.x:81/a/b?q#f" cracked with dwUrlLength 1..25, A and W identical. Notable: "http://u" = host
     * u; "http://u:p" -> 12005 (port "p"); "http://u:p@" -> 12005 (empty host); a cut port ":8" -> 8. */
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    const char *url = "http://u:p@h.x:81/a/b?q#f";
    for (unsigned i = 0; i < sizeof SW / sizeof *SW; i++) {
        for (int wide = 0; wide < 2; wide++) {
            char s[64], h[64], u[64], p[64], pa[64], x[64]; BOOL r; DWORD e; unsigned port;
            if (!wide) {
                URL_COMPONENTSA a; zca(&a); s[0] = h[0] = u[0] = p[0] = pa[0] = x[0] = 0;
                a.lpszScheme = s; a.dwSchemeLength = 64; a.lpszHostName = h; a.dwHostNameLength = 64; a.lpszUserName = u; a.dwUserNameLength = 64;
                a.lpszPassword = p; a.dwPasswordLength = 64; a.lpszUrlPath = pa; a.dwUrlPathLength = 64; a.lpszExtraInfo = x; a.dwExtraInfoLength = 64;
                SET_ERR(0xdead); r = U(InternetCrackUrlA)(url, SW[i].k, 0, &a); e = GetLastError(); port = a.nPort;
            } else {
                WCHAR ws[64], wh[64], wu[64], wp[64], wpa[64], wx[64]; URL_COMPONENTSW w; zcw(&w);
                ws[0] = wh[0] = wu[0] = wp[0] = wpa[0] = wx[0] = 0;
                w.lpszScheme = ws; w.dwSchemeLength = 64; w.lpszHostName = wh; w.dwHostNameLength = 64; w.lpszUserName = wu; w.dwUserNameLength = 64;
                w.lpszPassword = wp; w.dwPasswordLength = 64; w.lpszUrlPath = wpa; w.dwUrlPathLength = 64; w.lpszExtraInfo = wx; w.dwExtraInfoLength = 64;
                SET_ERR(0xdead); r = U(InternetCrackUrlW)(uc_w(url), SW[i].k, 0, &w); e = GetLastError(); port = w.nPort;
                strcpy(s, uc_a(ws)); strcpy(h, uc_a(wh)); strcpy(u, uc_a(wu)); strcpy(p, uc_a(wp)); strcpy(pa, uc_a(wpa)); strcpy(x, uc_a(wx));
            }
            const char *api = wide ? "W" : "A";
            if (!SW[i].r) { CHECKF(!r && e == SW[i].err, "%s k=%d: r=%d err=%lu want %lu", api, SW[i].k, r, e, SW[i].err); continue; }
            CHECKF(r && e == 0, "%s k=%d: r=%d err=%lu", api, SW[i].k, r, e);
            CHECKF(port == SW[i].port, "%s k=%d: port %u want %u", api, SW[i].k, port, SW[i].port);
            CHECKF(!strcmp(s, SW[i].s) && !strcmp(h, SW[i].h) && !strcmp(u, SW[i].u) && !strcmp(p, SW[i].p) && !strcmp(pa, SW[i].pa) && !strcmp(x, SW[i].x),
                   "%s k=%d: \"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"", api, SW[i].k, s, h, u, p, pa, x);
        }
    }
}

/* ---- CreateUrl / Canonicalize / Combine buffer boundaries ---------------------------------------------------- */
TEST(url_crack_wrap_create_A_boundary_sweep) {
    /* "http://host.example/abc" (23): *len 0..23 -> 122, need 24, buffer untouched; 24.. -> ok, 23 */
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA a; zca(&a); a.nScheme = INTERNET_SCHEME_HTTP; a.nPort = 80; a.lpszHostName = "host.example"; a.lpszUrlPath = "/abc";
    for (DWORD L = 0; L <= 26; L++) {
        char o[64]; memset(o, '@', sizeof o); o[63] = 0; DWORD n = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCreateUrlA)(&a, 0, o, &n);
        DWORD e = GetLastError();
        if (L < 24) CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && n == 24 && o[0] == '@', "L=%lu r=%d err=%lu n=%lu o[0]=%c", L, r, e, n, o[0]);
        else CHECKF(r && n == 23 && !strcmp(o, "http://host.example/abc"), "L=%lu r=%d err=%lu n=%lu \"%s\"", L, r, e, n, o);
    }
}
TEST(url_crack_wrap_create_W_boundary_sweep) {
    /* [D] InternetCreateUrlW sizes the inner A buffer from *len (or, when *len == 0, wcslen of the caller's buffer)
     * [VM] *len 0 with a 63-char buffer: success, 23, nothing written; 1..10: inner failure -> 122, need 48 bytes,
     * untouched; 11..23: copy-back failure -> 122, 46 (23*2, no NUL), first L chars written; 24..: ok, 23 chars */
    REQUIRE(U(InternetCreateUrlW));
    URL_COMPONENTSW w; zcw(&w); w.nScheme = INTERNET_SCHEME_HTTP; w.nPort = 80; w.lpszHostName = L"host.example"; w.lpszUrlPath = L"/abc";
    const WCHAR *want = L"http://host.example/abc";
    for (DWORD L = 0; L <= 52; L++) {
        WCHAR o[64]; for (int i = 0; i < 63; i++) o[i] = '@'; o[63] = 0; DWORD n = L;
        SET_ERR(0xdead);
        BOOL r = U(InternetCreateUrlW)(&w, 0, o, &n);
        DWORD e = GetLastError();
        if (L == 0) CHECKF(r && n == 23 && o[0] == '@' && o[62] == '@', "L=0 r=%d err=%lu n=%lu o[0]=%04x", r, e, n, o[0]);
        else if (L <= 10) CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && n == 48 && o[0] == '@', "L=%lu r=%d err=%lu n=%lu", L, r, e, n);
        else if (L <= 23) CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && n == 46 && !wcsncmp(o, want, L) && o[L] == '@', "L=%lu r=%d err=%lu n=%lu", L, r, e, n);
        else CHECKF(r && n == 23 && !lstrcmpW(o, want), "L=%lu r=%d err=%lu n=%lu \"%s\"", L, r, e, n, uc_a(o));
    }
}
TEST(url_crack_wrap_canon_combine_boundary_untouched) {
    /* [VM] too small: 122, need incl. NUL (A bytes / W chars), the caller's buffer is not written */
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    for (DWORD L = 1; L <= 15; L++) {
        char o[64]; WCHAR w[64]; DWORD n; BOOL r; DWORD e;
        memset(o, '@', 63); o[63] = 0; n = L; SET_ERR(0xdead);
        r = U(InternetCanonicalizeUrlA)("http://h/a b", o, &n, 0); e = GetLastError();
        if (L < 15) CHECKF(!r && e == 122 && n == 15 && o[0] == '@', "canon A L=%lu r=%d e=%lu n=%lu", L, r, e, n);
        else CHECKF(r && n == 14 && !strcmp(o, "http://h/a%20b"), "canon A L=%lu \"%s\"", L, o);
        for (int i = 0; i < 63; i++) w[i] = '@'; w[63] = 0; n = L; SET_ERR(0xdead);
        r = U(InternetCanonicalizeUrlW)(L"http://h/a b", w, &n, 0); e = GetLastError();
        if (L < 15) CHECKF(!r && e == 122 && n == 15 && w[0] == '@', "canon W L=%lu r=%d e=%lu n=%lu", L, r, e, n);
        else CHECKF(r && n == 14 && !lstrcmpW(w, L"http://h/a%20b"), "canon W L=%lu \"%s\"", L, uc_a(w));
        memset(o, '@', 63); o[63] = 0; n = L; SET_ERR(0xdead);
        r = U(InternetCombineUrlA)("http://h/a/b", "c d", o, &n, 0); e = GetLastError();
        CHECKF(!r && e == 122 && n == 17 && o[0] == '@', "combine A L=%lu r=%d e=%lu n=%lu", L, r, e, n);
        for (int i = 0; i < 63; i++) w[i] = '@'; w[63] = 0; n = L; SET_ERR(0xdead);
        r = U(InternetCombineUrlW)(L"http://h/a/b", L"c d", w, &n, 0); e = GetLastError();
        CHECKF(!r && e == 122 && n == 17 && w[0] == '@', "combine W L=%lu r=%d e=%lu n=%lu", L, r, e, n);
    }
    DWORD n = 17; char o[64];
    CHECK(U(InternetCombineUrlA)("http://h/a/b", "c d", o, &n, 0));
    EXPECT_STR(o, "http://h/a/c%20d"); EXPECT_EQ(n, 16);
    n = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlW)(L"http://h/a/b", L"c d", NULL, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
}
TEST(url_crack_wrap_long_inputs) {
    /* [VM] no INTERNET_MAX_URL_LENGTH limit in these paths: 8009-char canonicalize and 8011-char create succeed */
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCreateUrlA));
    static char big[9000], o[9000]; DWORD n;
    strcpy(big, "http://h/"); memset(big + 9, 'a', 8000); big[8009] = 0;
    n = sizeof o; CHECK(U(InternetCanonicalizeUrlA)(big, o, &n, 0)); EXPECT_EQ(n, 8009); CHECK(!strcmp(o, big));
    n = sizeof o; CHECK(U(InternetCombineUrlA)(big, "x", o, &n, 0)); EXPECT_EQ(n, 10); EXPECT_STR(o, "http://h/x");
    URL_COMPONENTSA a; zca(&a); a.nScheme = INTERNET_SCHEME_HTTP; a.lpszHostName = "h"; a.lpszUrlPath = big + 8;
    n = sizeof o; CHECK(U(InternetCreateUrlA)(&a, 0, o, &n)); EXPECT_EQ(n, 8011);
    CHECK(!strncmp(o, "http://h:0/aaa", 14));
    memset(big + 9, 'a', 2100); big[2109] = 0;
    n = sizeof o; CHECK(U(InternetCanonicalizeUrlA)(big, o, &n, 0)); EXPECT_EQ(n, 2109);
}
