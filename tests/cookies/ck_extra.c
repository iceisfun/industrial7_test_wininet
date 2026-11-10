/* ck_extra.c - the rest of the cookie export surface: the IsDomainLegalCookieDomainA/W predicate (ordinals 116/117),
 * the retired InternalInternetGetCookie stub (ordinal 346), per-site cookie decisions (argument validation and
 * lookups only: nothing here saves or clears a decision), and the Netscape cookie file import/export
 * (ordinals 108-111) restricted to this process's unique hosts.
 * Decomp: IsDomainLegalCookieDomainA@0x1ea30, IsDomainLegal@0x320ac, IsDomainLegalCookieDomainW@0x16a770,
 * InternetGet/Set/EnumPerSiteCookieDecisionA/W@0x168970.., ImportCookieFileW@0x134fe0, ExportCookieFileW@0x1356d0.
 * VM_TIMEOUT: 90 */
#include "ck.h"

typedef BOOL (WINAPI *legal_a_fn)(LPCSTR domain, LPCSTR host);
typedef BOOL (WINAPI *legal_w_fn)(LPCWSTR domain, LPCWSTR host);
typedef BOOL (WINAPI *import_a_fn)(LPCSTR file);
typedef BOOL (WINAPI *import_w_fn)(LPCWSTR file);
typedef BOOL (WINAPI *export_a_fn)(LPCSTR file, BOOL append);
typedef BOOL (WINAPI *export_w_fn)(LPCWSTR file, BOOL append);
/* Wine exports these ordinals as aborting stubs, so they are skipped there (plumbing runs only). */
static FARPROC ord_or_null(unsigned n) { return t_is_wine() ? NULL : t_proc_ord("wininet.dll", n); }
#define ORD(fn_t, n) ((fn_t)ord_or_null(n))

/* ------------------------------------------------------------------------------------------ domain legality */
static const struct { const char *dom, *host; BOOL want; } k_legal[] = {
    { "example.com", "www.example.com", TRUE },
    { "www.example.com", "www.example.com", TRUE },
    { "example.com", "example.com", TRUE },
    { "example.com", "a.b.example.com", TRUE },
    { "b.example.com", "a.b.example.com", TRUE },
    { "com", "www.example.com", FALSE },
    { "com", "com", FALSE },
    { "other.com", "www.example.com", FALSE },
    { "a.www.example.com", "www.example.com", FALSE },
    { "ample.com", "www.example.com", FALSE },
    { "EXAMPLE.COM", "www.example.com", TRUE },
    { "example.co.uk", "www.example.co.uk", TRUE },
    { "co.uk", "www.example.co.uk", FALSE },
    { "uk", "www.example.co.uk", FALSE },
    { "i7test.example", "wininet1.i7test.example", TRUE },
    { "example", "wininet1.i7test.example", FALSE },
    { "127.0.0.1", "127.0.0.1", TRUE },
    { "0.0.1", "127.0.0.1", FALSE },
    { "127.0.0.2", "127.0.0.1", FALSE },
    { "localhost", "localhost", FALSE },          /* VM boot 2: a single-label domain is never legal */
};
TEST(ck_legal_domain_a_table) {
    legal_a_fn f = ORD(legal_a_fn, 116);
    REQUIRE(f);
    for (size_t i = 0; i < sizeof k_legal / sizeof k_legal[0]; i++) {
        BOOL r = f(k_legal[i].dom, k_legal[i].host);
        CHECKF(!!r == k_legal[i].want, "IsDomainLegalCookieDomainA(%s, %s) = %d want %d", k_legal[i].dom, k_legal[i].host, r, k_legal[i].want);
    }
}
TEST(ck_legal_domain_w_table) {
    legal_w_fn f = ORD(legal_w_fn, 117);
    REQUIRE(f);
    for (size_t i = 0; i < sizeof k_legal / sizeof k_legal[0]; i++) {
        WCHAR d[128], h[128];
        lstrcpyW(d, ck_w(k_legal[i].dom)); lstrcpyW(h, ck_w(k_legal[i].host));
        BOOL r = f(d, h);
        CHECKF(!!r == k_legal[i].want, "IsDomainLegalCookieDomainW(%s, %s) = %d want %d", k_legal[i].dom, k_legal[i].host, r, k_legal[i].want);
    }
}
TEST(ck_legal_domain_a_null_args) {
    legal_a_fn f = ORD(legal_a_fn, 116);
    REQUIRE(f);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(f(NULL, "www.example.com"), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(f("example.com", NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_legal_domain_leading_dot) {
    legal_a_fn f = ORD(legal_a_fn, 116);
    REQUIRE(f);
    BOOL r = f(".example.com", "www.example.com");
    t_note("IsDomainLegalCookieDomainA(.example.com, www.example.com) = %d", r);
    CHECK(1);
}
TEST(ck_internal_get_cookie_stub) {
    typedef DWORD (WINAPI *stub_fn)(void);
    stub_fn f = (stub_fn)ord_or_null(346);
    REQUIRE(f);
    EXPECT_EQ(f(), ERROR_NO_MORE_ITEMS);   /* retired: return 0x103 */
}

/* ------------------------------------------------------------------------------------------ per-site decisions (read-only) */
TEST(ck_persite_exports_present) {
    REQUIRE(U(InternetClearAllPerSiteCookieDecisions));
    REQUIRE(U(InternetGetPerSiteCookieDecisionA)); REQUIRE(U(InternetGetPerSiteCookieDecisionW));
    REQUIRE(U(InternetSetPerSiteCookieDecisionA)); REQUIRE(U(InternetSetPerSiteCookieDecisionW));
    REQUIRE(U(InternetEnumPerSiteCookieDecisionA)); REQUIRE(U(InternetEnumPerSiteCookieDecisionW));
    CHECK(1);   /* InternetClearAllPerSiteCookieDecisions deletes every decision: never called outside dx_ */
}
TEST(ck_persite_get_null_args) {
    REQUIRE(U(InternetGetPerSiteCookieDecisionA));
    unsigned long r = 77;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionA)(NULL, &r), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionA)(ck_host("psg"), NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionW)(NULL, &r), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionW)(ck_w(ck_host("psgw")), NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_persite_get_unknown_host) {
    REQUIRE(U(InternetGetPerSiteCookieDecisionA));
    unsigned long r = 77;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionA)(ck_host("psu"), &r), FALSE);
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionW)(ck_w(ck_host("psuw")), &r), FALSE);
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
}
TEST(ck_persite_set_null_host) {
    REQUIRE(U(InternetSetPerSiteCookieDecisionA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetPerSiteCookieDecisionA)(NULL, COOKIE_STATE_ACCEPT), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetPerSiteCookieDecisionW)(NULL, COOKIE_STATE_ACCEPT), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_persite_set_invalid_decisions_noop) {
    REQUIRE(U(InternetSetPerSiteCookieDecisionA)); REQUIRE(U(InternetGetPerSiteCookieDecisionA));
    /* only 0 (clear), 1 (accept) and 5 (reject) are acted upon; anything else returns FALSE with error 0 */
    static const DWORD bad[] = { 2, 3, 4, 6, 7, 0x100, 0xffffffff };
    const char *h = ck_host("psinv");
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        BOOL r = U(InternetSetPerSiteCookieDecisionA)(h, bad[i]);
        DWORD e = GetLastError();
        CHECKF(r == FALSE && e == 0, "decision %lu: r=%d gle=%lu", bad[i], r, e);
    }
    unsigned long d = 77;
    EXPECT_EQ(U(InternetGetPerSiteCookieDecisionA)(h, &d), FALSE);   /* still nothing stored */
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetPerSiteCookieDecisionW)(ck_w(h), 3);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    t_note("SetPerSiteCookieDecisionW(3): gle=%lu", e);
}
TEST(ck_persite_clear_unknown_host) {
    REQUIRE(U(InternetSetPerSiteCookieDecisionA));
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetPerSiteCookieDecisionA)(ck_host("psclr"), COOKIE_STATE_UNKNOWN);
    DWORD e = GetLastError();
    t_note("clear decision of an unknown host: r=%d gle=%lu", r, e);
    CHECK(1);
}
TEST(ck_persite_enum_null_args) {
    REQUIRE(U(InternetEnumPerSiteCookieDecisionA));
    char name[256]; unsigned long sz = sizeof name, dec = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetEnumPerSiteCookieDecisionA)(NULL, &sz, &dec, 0), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetEnumPerSiteCookieDecisionA)(name, NULL, &dec, 0), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetEnumPerSiteCookieDecisionA)(name, &sz, NULL, 0), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    WCHAR wn[256];
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetEnumPerSiteCookieDecisionW)(NULL, &sz, &dec, 0), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetEnumPerSiteCookieDecisionW)(wn, &sz, NULL, 0), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_persite_enum_past_end) {
    REQUIRE(U(InternetEnumPerSiteCookieDecisionA));
    char name[256]; unsigned long sz = sizeof name, dec = 0;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetEnumPerSiteCookieDecisionA)(name, &sz, &dec, 100000);
    DWORD e = GetLastError();
    t_note("enum index 100000: r=%d gle=%lu", r, e);
    EXPECT_EQ(r, FALSE);
    int n = 0;
    for (; n < 200; n++) { sz = sizeof name; if (!U(InternetEnumPerSiteCookieDecisionA)(name, &sz, &dec, n)) break; }
    t_note("per-site decisions on this machine: %d (enumerated, not asserted)", n);
}

/* ------------------------------------------------------------------------------------------ Netscape cookie files */
static char *read_file(const char *path, DWORD *n) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(f, NULL), got = 0;
    char *b = malloc(sz + 1);
    if (!ReadFile(f, b, sz, &got, NULL)) got = 0;
    b[got] = 0; CloseHandle(f);
    if (n) *n = got;
    return b;
}
static int write_file(const char *path, const char *data) {
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; WriteFile(f, data, (DWORD)strlen(data), &w, NULL); CloseHandle(f);
    return w == strlen(data);
}
/* D (ExportCookieFileW subtracts 0x19dae9064bafa80, ImportCookieFileW adds 0x2b60b04e9 seconds) + VM: the file
 * column is the Unix time of the expiry plus 363543 s (an epoch about 4.2 days early); import undoes it. */
#define CK_FILE_EPOCH_SKEW 363543ULL
static unsigned long long unix_now(void) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return u.QuadPart / 10000000ULL - 11644473600ULL;
}
TEST(ck_file_export_contains_persistent_cookie) {
    export_a_fn ex = ORD(export_a_fn, 109);
    REQUIRE(ex); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("exp");
    char d[300]; snprintf(d, sizeof d, "exn=exv; path=/ex/; expires=%s", ck_date(2));
    EXPECT_EQ(ck_set(ck_url(h, "/ex/"), NULL, d), TRUE);
    ck_set(ck_url(h, "/ex/"), NULL, "sessonly=1; path=/ex/");
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "export.txt");
    SetLastError(0xdeadbeef);
    BOOL r = ex(fn, FALSE);
    EXPECT_EQ(r, TRUE);
    DWORD n; char *txt = read_file(fn, &n);
    CHECK(txt != NULL);
    if (txt) {
        EXPECT_EQ(strncmp(txt, "#  Internet Explorer cookie file, exported for Netscape browsers.\r\n\r\n", 69), 0);
        char pre[400]; snprintf(pre, sizeof pre, "\n%s\tTRUE\t/ex/\tFALSE\t", h);
        char *line = strstr(txt, pre);
        CHECKF(line != NULL, "no export line for %s", h);
        if (line) {
            char *num = line + strlen(pre), *end = NULL;
            unsigned long long ex_t = strtoull(num, &end, 10), now = unix_now();
            long long skew = (long long)ex_t - (long long)(now + 2 * 86400);
            CHECKF(skew >= (long long)CK_FILE_EPOCH_SKEW - 5 && skew <= (long long)CK_FILE_EPOCH_SKEW + 1, "exported expiry %llu, now+2d %llu, skew %lld", ex_t, now + 2 * 86400, skew);
            CHECKF(end && !strncmp(end, "\texn\texv\r\n", 10), "line tail '%.20s'", end ? end : "");
        }
        char sess[300]; snprintf(sess, sizeof sess, "%s\tTRUE\t/ex/\tFALSE", h);
        char *first = strstr(txt, sess);
        CHECK(first && !strstr(first + 1, sess));          /* the session cookie is not exported */
        CHECK(strstr(txt, "\tsessonly\t") == NULL);
        free(txt);
    }
    DeleteFileA(fn);
    ck_cleanup();
}
TEST(ck_file_export_append_has_no_header) {
    export_a_fn ex = ORD(export_a_fn, 109);
    REQUIRE(ex);
    const char *h = ck_host("expapp");
    char d[300]; snprintf(d, sizeof d, "apn=apv; expires=%s", ck_date(2));
    ck_set(ck_url(h, "/"), NULL, d);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "export_append.txt");
    write_file(fn, "PREFIX\r\n");
    EXPECT_EQ(ex(fn, TRUE), TRUE);
    char *txt = read_file(fn, NULL);
    CHECK(txt && !strncmp(txt, "PREFIX\r\n", 8));
    CHECK(txt && strstr(txt, "#  Internet Explorer cookie file") == NULL);
    CHECK(txt && strstr(txt, h) != NULL);
    free(txt); DeleteFileA(fn);
    ck_cleanup();
}
TEST(ck_file_export_w_and_null) {
    export_w_fn exw = ORD(export_w_fn, 111); export_a_fn exa = ORD(export_a_fn, 109);
    REQUIRE(exw); REQUIRE(exa);
    EXPECT_EQ(exa(NULL, FALSE), FALSE);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "export_w.txt");
    WCHAR wfn[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, fn, -1, wfn, MAX_PATH);
    EXPECT_EQ(exw(wfn, FALSE), TRUE);
    DWORD n; char *txt = read_file(fn, &n);
    CHECK(txt && n >= 69);
    free(txt); DeleteFileA(fn);
}
TEST(ck_file_import_creates_cookie) {
    import_a_fn im = ORD(import_a_fn, 108);
    REQUIRE(im);
    const char *h = ck_host("imp");
    ck_track(ck_url(h, "/imp/"), "imn", "path=/imp/", 0);
    char dom[300]; snprintf(dom, sizeof dom, "path=/imp/; domain=%s", h);
    ck_track(ck_url(h, "/imp/"), "imn", dom, 0);
    char line[600]; snprintf(line, sizeof line, "# comment\r\n\r\n%s\tTRUE\t/imp/\tFALSE\t%llu\timn\timv\r\n", h, unix_now() + CK_FILE_EPOCH_SKEW + 2 * 86400);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "import.txt");
    CHECK(write_file(fn, line));
    SetLastError(0xdeadbeef);
    BOOL r = im(fn);
    t_note("ImportCookieFileA: r=%d gle=%lu", r, GetLastError());
    EXPECT_EQ(r, TRUE);
    EXPECT_STR(ck_gets(ck_url(h, "/imp/"), NULL, 0), "imn=imv");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    const char *sub = ck_gets(ck_url(ck_host("x"), "/imp/"), NULL, 0);
    char subh[300]; snprintf(subh, sizeof subh, "www.%s", h);
    t_note("imported cookie from www.<host>: '%s'", ck_gets(ck_url(subh, "/imp/"), NULL, 0));
    (void)sub;
    DeleteFileA(fn);
    ck_cleanup();
    EXPECT_STR(ck_gets(ck_url(h, "/imp/"), NULL, 0), "");
}
TEST(ck_file_import_secure_column) {
    import_a_fn im = ORD(import_a_fn, 108);
    REQUIRE(im);
    const char *h = ck_host("imps");
    char dom[300]; snprintf(dom, sizeof dom, "path=/; domain=%s", h);
    ck_track(ck_surl(h, "/"), "isn", dom, 0); ck_track(ck_surl(h, "/"), "isn", "path=/", 0);
    char line[600]; snprintf(line, sizeof line, "%s\tTRUE\t/\tTRUE\t%llu\tisn\tisv\r\n", h, unix_now() + CK_FILE_EPOCH_SKEW + 2 * 86400);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "import_s.txt");
    write_file(fn, line);
    EXPECT_EQ(im(fn), TRUE);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_surl(h, "/"), NULL, 0), "isn=isv");
    DeleteFileA(fn);
    ck_cleanup();
}
TEST(ck_file_import_does_not_overwrite) {
    import_a_fn im = ORD(import_a_fn, 108);
    REQUIRE(im);
    const char *h = ck_host("impno");
    ck_set(ck_url(h, "/"), NULL, "keep=old; path=/");
    char dom[300]; snprintf(dom, sizeof dom, "path=/; domain=%s", h);
    ck_track(ck_url(h, "/"), "keep", dom, 0);
    char line[600]; snprintf(line, sizeof line, "%s\tTRUE\t/\tFALSE\t%llu\tkeep\tnew\r\n", h, unix_now() + CK_FILE_EPOCH_SKEW + 2 * 86400);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "import_no.txt");
    write_file(fn, line);
    BOOL r = im(fn);
    t_note("import over an existing cookie: r=%d", r);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "keep=old");
    DeleteFileA(fn);
    ck_cleanup();
}
TEST(ck_file_import_short_line_ignored) {
    import_a_fn im = ORD(import_a_fn, 108);
    REQUIRE(im);
    const char *h = ck_host("impshort");
    char line[600]; snprintf(line, sizeof line, "%s\tTRUE\t/\tFALSE\t%llu\tonlyname\r\n", h, unix_now() + CK_FILE_EPOCH_SKEW + 2 * 86400);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "import_short.txt");
    write_file(fn, line);
    BOOL r = im(fn);
    t_note("import of a 6-field line: r=%d", r);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    DeleteFileA(fn);
}
TEST(ck_file_import_missing_file_and_null) {
    import_a_fn im = ORD(import_a_fn, 108); import_w_fn imw = ORD(import_w_fn, 110);
    REQUIRE(im); REQUIRE(imw);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "does_not_exist.txt");
    EXPECT_EQ(im(fn), FALSE);
    EXPECT_EQ(im(NULL), FALSE);
    WCHAR wfn[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, fn, -1, wfn, MAX_PATH);
    EXPECT_EQ(imw(wfn), FALSE);
}
TEST(ck_file_import_empty_file) {
    import_a_fn im = ORD(import_a_fn, 108);
    REQUIRE(im);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "import_empty.txt");
    write_file(fn, "");
    EXPECT_EQ(im(fn), FALSE);
    write_file(fn, "# only a comment\r\n");
    BOOL r = im(fn);
    t_note("import of a comment-only file: r=%d", r);
    DeleteFileA(fn);
}
TEST(ck_file_export_import_roundtrip) {
    export_a_fn ex = ORD(export_a_fn, 109); import_a_fn im = ORD(import_a_fn, 108);
    REQUIRE(ex); REQUIRE(im);
    const char *h = ck_host("rtrip");
    char d[300]; snprintf(d, sizeof d, "rt=1; path=/rt/; expires=%s", ck_date(2));
    ck_set(ck_url(h, "/rt/"), NULL, d);
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "export_rt.txt");
    EXPECT_EQ(ex(fn, FALSE), TRUE);
    /* keep only our host's line, delete the cookie, import it back */
    DWORD n; char *txt = read_file(fn, &n);
    char *line = txt ? strstr(txt, h) : NULL;
    CHECK(line != NULL);
    if (line) {
        char *e = strstr(line, "\r\n"); if (e) *e = 0;
        char one[800]; snprintf(one, sizeof one, "%s\r\n", line);
        write_file(fn, one);
        ck_set(ck_url(h, "/rt/"), NULL, "rt=; path=/rt/; " CK_PAST);
        EXPECT_STR(ck_gets(ck_url(h, "/rt/"), NULL, 0), "");
        char dom[300]; snprintf(dom, sizeof dom, "path=/rt/; domain=%s", h);
        ck_track(ck_url(h, "/rt/"), "rt", dom, 0);
        EXPECT_EQ(im(fn), TRUE);
        EXPECT_STR(ck_gets(ck_url(h, "/rt/"), NULL, 0), "rt=1");
    }
    free(txt); DeleteFileA(fn);
    ck_cleanup();
}
