/* ck_ex2set.c - InternetSetCookieEx2 (structured INTERNET_COOKIE2 input) and the array view of
 * InternetGetCookieEx2: argument validation order, the call-flag and cookie-flag masks, HttpOnly / NON_SCRIPT,
 * Secure, SameSite, session vs persistent (fExpiresSet), Domain and Path fields, deletion through a past expiry,
 * and the per-entry fields of a multi-cookie result.
 * Decomp: InternalInternetSetCookieEx2@0xcc77c (cookie NULL / name+value NULL / url NULL -> 87, call flags
 * & 0xbff96f8f -> 87, cookie flags & 0x7fc79dfc -> 87, state NULL -> 87; HttpOnly without NON_SCRIPT -> 4317 with
 * state 5; Strict|Lax -> Lax dropped; fExpiresSet == 0 -> session; leading '.' of the domain skipped; path of
 * 0x8000+ chars -> 87), CCookieJar::SetCookieParsed@0x3126c, InternalInternetGetCookieEx2@0x83820.
 * VM_TIMEOUT: 90 */
#include "ck.h"

#define REQ_EX2() do { REQUIRE(UN(InternetSetCookieEx2)); REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(UN(InternetFreeCookies)); } while (0)
#define DAY 864000000000ULL

static FILETIME ft_days(int days) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    u.QuadPart += (ULONGLONG)((LONGLONG)days * (LONGLONG)DAY);
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart; return ft;
}
static ULONGLONG ft64(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

/* InternetSetCookieEx2 with a cookie built from the arguments; registers cleanup (name/path/domain). *state is
 * pre-set to 99 so an untouched out-param is visible. */
typedef struct { const char *name, *value, *domain, *path; DWORD cflags; BOOL expset; int days; } s2spec;
static DWORD s2(const char *url, const s2spec *sp, DWORD flags, DWORD *state) {
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c);
    WCHAR wn[256], wv[2048], wd[256], wp[512];
    if (sp->name) { lstrcpynW(wn, ck_w(sp->name), 256); c.pwszName = wn; }
    if (sp->value) { lstrcpynW(wv, ck_w(sp->value), 1024); c.pwszValue = wv; }
    if (sp->domain) { lstrcpynW(wd, ck_w(sp->domain), 256); c.pwszDomain = wd; }
    if (sp->path) { lstrcpynW(wp, ck_w(sp->path), 512); c.pwszPath = wp; }
    c.dwFlags = sp->cflags; c.fExpiresSet = sp->expset;
    if (sp->expset) c.ftExpires = ft_days(sp->days);
    char attrs[600] = "";
    if (sp->path) snprintf(attrs, sizeof attrs, "path=%s", sp->path);
    if (sp->domain) snprintf(attrs + strlen(attrs), sizeof attrs - strlen(attrs), "%sdomain=%s", attrs[0] ? "; " : "", sp->domain);
    if (url) ck_track(url, sp->name ? sp->name : "", attrs[0] ? attrs : NULL, flags & INTERNET_COOKIE_APPLY_HOST_ONLY);
    DWORD st = 99;
    DWORD r = UN(InternetSetCookieEx2)(url ? ck_w(url) : NULL, &c, NULL, flags, &st);
    if (state) *state = st;
    return r;
}

/* copy of an InternetGetCookieEx2 result */
typedef struct { char name[256], value[1024], domain[256], path[512]; DWORD flags; ULONGLONG exp; BOOL expset; int name_null; } e2item;
typedef struct { DWORD r, n; e2item it[16]; } e2list;
static void e2get(const char *url, const char *name, DWORD flags, e2list *o) {
    memset(o, 0, sizeof *o);
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    WCHAR wname[256];
    if (name) lstrcpynW(wname, ck_w(name), 256);
    o->r = UN(InternetGetCookieEx2)(ck_w(url), name ? wname : NULL, flags, &arr, &n);
    o->n = n;
    for (DWORD i = 0; o->r == 0 && arr && i < n && i < 16; i++) {
        e2item *e = &o->it[i];
        e->name_null = arr[i].pwszName == NULL;
        snprintf(e->name, sizeof e->name, "%s", arr[i].pwszName ? ck_a(arr[i].pwszName) : "");
        snprintf(e->value, sizeof e->value, "%s", arr[i].pwszValue ? ck_a(arr[i].pwszValue) : "");
        snprintf(e->domain, sizeof e->domain, "%s", arr[i].pwszDomain ? ck_a(arr[i].pwszDomain) : "(null)");
        snprintf(e->path, sizeof e->path, "%s", arr[i].pwszPath ? ck_a(arr[i].pwszPath) : "(null)");
        e->flags = arr[i].dwFlags; e->exp = ft64(arr[i].ftExpires); e->expset = arr[i].fExpiresSet;
    }
    if (arr) UN(InternetFreeCookies)(arr, n);
}

/* ------------------------------------------------------------------------------------------ argument validation */
TEST(ck_ex2set_null_cookie_state_untouched) {
    REQ_EX2();
    DWORD st = 99;
    EXPECT_EQ(UN(InternetSetCookieEx2)(ck_w(ck_url(ck_host("e2n"), "/")), NULL, NULL, 0, &st), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(st, 99);                                       /* D: 87 is returned before *state = 0 */
}
TEST(ck_ex2set_name_and_value_null) {
    REQ_EX2();
    s2spec sp = { NULL, NULL, NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(ck_host("e2nv"), "/"), &sp, 0, &st), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(st, 99);
    ck_cleanup();
}
TEST(ck_ex2set_null_url) {
    REQ_EX2();
    s2spec sp = { "n", "v", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(NULL, &sp, 0, &st), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(st, 99);
}
TEST(ck_ex2set_null_state_after_flag_checks) {
    REQ_EX2();
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c); c.pwszName = (PWSTR)L"n"; c.pwszValue = (PWSTR)L"v";
    const char *u = ck_url(ck_host("e2ns"), "/");
    ck_track(u, "n", NULL, 0);
    EXPECT_EQ(UN(InternetSetCookieEx2)(ck_w(u), &c, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_STR(ck_gets(u, NULL, 0), "");                     /* nothing stored */
    ck_cleanup();
}
TEST(ck_ex2set_bad_call_flags_table) {
    REQ_EX2();
    /* D: call flags & 0xbff96f8f != 0 -> 87 */
    static const DWORD bad[] = { 0x1, 0x2, 0x4, 0x8, 0x80, 0x100, 0x200, 0x400, 0x800, INTERNET_COOKIE_HTTPONLY, 0x4000,
                                 0x10000, 0x80000, 0x100000, 0x200000, 0x400000, 0x1000000, 0x80000000 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const char *u = ck_url(ck_host("e2bf"), "/");
        s2spec sp = { "bf", "1", NULL, "/", 0, FALSE, 0 };
        DWORD st; DWORD r = s2(u, &sp, bad[i], &st);
        CHECKF(r == ERROR_INVALID_PARAMETER && st == 99, "flags 0x%lx -> r=%lu state=%lu", bad[i], r, st);
        CHECKF(!strcmp(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), ""), "flags 0x%lx stored a cookie", bad[i]);
        ck_cleanup();
    }
}
TEST(ck_ex2set_good_call_flags_table) {
    REQ_EX2();
    static const DWORD good[] = { 0, INTERNET_COOKIE_THIRD_PARTY, INTERNET_COOKIE_NON_SCRIPT, INTERNET_COOKIE_APPLY_HOST_ONLY, 0x40000, 0x40000000 };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        const char *u = ck_url(ck_host("e2gf"), "/");
        s2spec sp = { "gf", "1", NULL, "/", 0, FALSE, 0 };
        DWORD st; DWORD r = s2(u, &sp, good[i], &st);
        CHECKF(r == 0, "flags 0x%lx -> r=%lu", good[i], r);
        t_note("Ex2 set flags 0x%lx: r=%lu state=%lu get='%s'", good[i], r, st, ck_gets(u, NULL, 0));
        ck_cleanup();
    }
}
TEST(ck_ex2set_bad_cookie_flags_table) {
    REQ_EX2();
    /* D: cookie dwFlags & 0x7fc79dfc != 0 -> 87 */
    static const DWORD bad[] = { 0x4, 0x8, INTERNET_COOKIE_THIRD_PARTY, 0x20, INTERNET_COOKIE_EVALUATE_P3P, 0x80, 0x100, 0x400, 0x800,
                                 INTERNET_COOKIE_NON_SCRIPT, INTERNET_COOKIE_APPLY_HOST_ONLY, 0x10000, 0x20000, 0x40000,
                                 INTERNET_COOKIE_SAME_SITE_LEVEL_CROSS_SITE, 0x800000, 0x1000000, 0x40000000 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const char *u = ck_url(ck_host("e2bc"), "/");
        s2spec sp = { "bc", "1", NULL, "/", bad[i], FALSE, 0 };
        DWORD st; DWORD r = s2(u, &sp, 0, &st);
        CHECKF(r == ERROR_INVALID_PARAMETER && st == 99, "cookie flags 0x%lx -> r=%lu state=%lu", bad[i], r, st);
        ck_cleanup();
    }
}
TEST(ck_ex2set_good_cookie_flags_table) {
    REQ_EX2();
    static const DWORD good[] = { 0, INTERNET_COOKIE_IS_SECURE, INTERNET_COOKIE_IS_SESSION, INTERNET_COOKIE_IS_RESTRICTED,
                                  INTERNET_COOKIE_HOST_ONLY, INTERNET_COOKIE_HOST_ONLY_APPLIED, INTERNET_COOKIE_SAME_SITE_STRICT, INTERNET_COOKIE_SAME_SITE_LAX };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        const char *u = ck_surl(ck_host("e2gc"), "/");
        s2spec sp = { "gc", "1", NULL, "/", good[i], FALSE, 0 };
        DWORD st; DWORD r = s2(u, &sp, 0, &st);
        CHECKF(r == 0 && st == COOKIE_STATE_ACCEPT, "cookie flags 0x%lx -> r=%lu state=%lu", good[i], r, st);
        ck_cleanup();
    }
}

/* ------------------------------------------------------------------------------------------ stored shape */
TEST(ck_ex2set_session_default_fields) {
    REQ_EX2();
    const char *h = ck_host("e2sd");
    const char *u = ck_url(h, "/");
    s2spec sp = { "sd", "v1", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &sp, 0, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    e2list l; e2get(u, NULL, 0, &l);
    EXPECT_EQ(l.r, 0); EXPECT_EQ(l.n, 1);
    EXPECT_STR(l.it[0].name, "sd"); EXPECT_STR(l.it[0].value, "v1");
    EXPECT_STR(l.it[0].path, "/");
    EXPECT_STR(l.it[0].domain, h);
    EXPECT_EQ(l.it[0].flags, 0x202);
    CHECK(l.it[0].flags & INTERNET_COOKIE_IS_SESSION);
    EXPECT_EQ(l.it[0].expset, FALSE);
    EXPECT_STR(ck_gets(u, NULL, 0), "sd=v1");
    ck_cleanup();
}
TEST(ck_ex2set_expires_ignored_without_expset) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2ne"), "/");
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c);
    c.pwszName = (PWSTR)L"ne"; c.pwszValue = (PWSTR)L"1"; c.pwszPath = (PWSTR)L"/";
    c.ftExpires = ft_days(5); c.fExpiresSet = FALSE;
    ck_track(u, "ne", "path=/", 0);
    DWORD st = 99; EXPECT_EQ(UN(InternetSetCookieEx2)(ck_w(u), &c, NULL, 0, &st), 0);
    e2list l; e2get(u, NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    CHECK(l.it[0].flags & INTERNET_COOKIE_IS_SESSION);
    EXPECT_EQ(l.it[0].expset, FALSE);
    ck_cleanup();
}
TEST(ck_ex2set_persistent_expiry_roundtrip) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2pe"), "/");
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c);
    c.pwszName = (PWSTR)L"pe"; c.pwszValue = (PWSTR)L"1"; c.pwszPath = (PWSTR)L"/";
    c.ftExpires = ft_days(3); c.fExpiresSet = TRUE;
    ck_track(u, "pe", "path=/", 0);
    DWORD st = 99; EXPECT_EQ(UN(InternetSetCookieEx2)(ck_w(u), &c, NULL, 0, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    e2list l; e2get(u, NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    t_note("Ex2-set persistent: flags=0x%lx set=%016llx got=%016llx", l.it[0].flags, ft64(c.ftExpires), l.it[0].exp);
    CHECK(!(l.it[0].flags & INTERNET_COOKIE_IS_SESSION));
    EXPECT_EQ(l.it[0].expset, TRUE);
    ULONGLONG want = ft64(c.ftExpires), got = l.it[0].exp;
    CHECKF(got == want, "expiry moved: set %llx got %llx", want, got);   /* VM boot 3: stored verbatim */
    ck_cleanup();
}
TEST(ck_ex2set_past_expiry_deletes) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2pd"), "/");
    s2spec a = { "pd", "1", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &a, 0, &st), 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "pd=1");
    s2spec b = { "pd", "x", NULL, "/", 0, TRUE, -2 };
    EXPECT_EQ(s2(u, &b, 0, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_ex2set_past_expiry_unknown_name_ok) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2pu"), "/");
    s2spec b = { "never", "x", NULL, "/", 0, TRUE, -2 };
    DWORD st; EXPECT_EQ(s2(u, &b, 0, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_ex2set_replace_value) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2rv"), "/");
    s2spec a = { "rv", "one", NULL, "/", 0, FALSE, 0 }, b = { "rv", "two", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &a, 0, &st), 0); EXPECT_EQ(s2(u, &b, 0, &st), 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "rv=two");
    e2list l; e2get(u, NULL, 0, &l); EXPECT_EQ(l.n, 1);
    ck_cleanup();
}
TEST(ck_ex2set_interop_with_string_api) {
    REQ_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("e2io"), "/");
    ck_set(u, NULL, "io=str; path=/");
    s2spec b = { "io", "struct", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &b, 0, &st), 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "io=struct");             /* same (name, path, host) identity */
    ck_set(u, NULL, "io=str2; path=/");
    EXPECT_STR(ck_gets(u, NULL, 0), "io=str2");
    ck_cleanup();
}
TEST(ck_ex2set_nameless_cookie) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2nl"), "/");
    s2spec sp = { NULL, "barevalue", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &sp, 0, &st), 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "barevalue");
    e2list l; e2get(u, NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    EXPECT_EQ(l.it[0].name_null, 1);                          /* VM boot 3: pwszName NULL for a nameless cookie */
    EXPECT_STR(l.it[0].value, "barevalue");
    ck_cleanup();
}
TEST(ck_ex2set_value_null_is_empty) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2vn"), "/");
    s2spec sp = { "vn", NULL, NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &sp, 0, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "vn=");
    ck_cleanup();
}
TEST(ck_ex2set_value_with_semicolon_stored_verbatim) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2sc"), "/");
    s2spec sp = { "sc", "a; path=/x/; b", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &sp, 0, &st), 0);
    /* no parsing on this path: the whole value is stored, the path field decides */
    EXPECT_STR(ck_gets(u, NULL, 0), "sc=a; path=/x/; b");
    ck_cleanup();
}
TEST(ck_ex2set_secure_cookie) {
    REQ_EX2();
    const char *h = ck_host("e2se");
    s2spec sp = { "se", "1", NULL, "/", INTERNET_COOKIE_IS_SECURE, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(h, "/"), &sp, 0, &st), 0);  /* set through an http URL */
    ck_track(ck_surl(h, "/"), "se", "path=/", 0);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_surl(h, "/"), NULL, 0), "se=1");
    e2list l; e2get(ck_surl(h, "/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    CHECK(l.it[0].flags & INTERNET_COOKIE_IS_SECURE);
    ck_cleanup();
}
TEST(ck_ex2set_httponly_requires_non_script) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2ho"), "/");
    s2spec sp = { "ho", "1", NULL, "/", INTERNET_COOKIE_HTTPONLY, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &sp, 0, &st), ERROR_INVALID_OPERATION);
    EXPECT_EQ(st, COOKIE_STATE_REJECT);                       /* D: *state = 5 before the 4317 */
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "");
    EXPECT_EQ(s2(u, &sp, INTERNET_COOKIE_NON_SCRIPT, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "ho=1");
    e2list l; e2get(u, NULL, INTERNET_COOKIE_NON_SCRIPT, &l);
    EXPECT_EQ(l.n, 1);
    CHECK(l.it[0].flags & INTERNET_COOKIE_HTTPONLY);
    ck_cleanup();
}
TEST(ck_ex2set_httponly_existing_protected) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2hp"), "/");
    s2spec ho = { "hp", "orig", NULL, "/", INTERNET_COOKIE_HTTPONLY, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &ho, INTERNET_COOKIE_NON_SCRIPT, &st), 0);
    s2spec plain = { "hp", "new", NULL, "/", 0, FALSE, 0 };
    DWORD r = s2(u, &plain, 0, &st);
    EXPECT_EQ(r, ERROR_INVALID_OPERATION);                   /* D: SetCookieParsed returns 4 for a live HttpOnly cookie */
    EXPECT_EQ(st, COOKIE_STATE_REJECT);
    r = s2(u, &plain, INTERNET_COOKIE_NON_SCRIPT, &st);      /* NON_SCRIPT alone does not set param_11 on this path */
    t_note("overwrite HttpOnly with NON_SCRIPT, no HttpOnly cookie flag: r=%lu state=%lu now='%s'", r, st, ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY));
    EXPECT_EQ(r, ERROR_INVALID_OPERATION);
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "hp=orig");
    ck_cleanup();
}
TEST(ck_ex2set_samesite_flags) {
    REQ_EX2();
    static const struct { DWORD in, want; } t[] = {
        { INTERNET_COOKIE_SAME_SITE_STRICT, INTERNET_COOKIE_SAME_SITE_STRICT },
        { INTERNET_COOKIE_SAME_SITE_LAX, INTERNET_COOKIE_SAME_SITE_LAX },
        { INTERNET_COOKIE_SAME_SITE_STRICT | INTERNET_COOKIE_SAME_SITE_LAX, INTERNET_COOKIE_SAME_SITE_STRICT },
        { 0, 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("e2ss"), "/");
        s2spec sp = { "ss", "1", NULL, "/", t[i].in, FALSE, 0 };
        DWORD st; DWORD r = s2(u, &sp, 0, &st);
        e2list l; e2get(u, NULL, 0, &l);
        DWORD got = l.n ? l.it[0].flags & (INTERNET_COOKIE_SAME_SITE_STRICT | INTERNET_COOKIE_SAME_SITE_LAX) : 0xffffffff;
        CHECKF(r == 0 && l.n == 1 && got == t[i].want, "case %u: in 0x%lx r=%lu n=%lu samesite 0x%lx want 0x%lx", (unsigned)i, t[i].in, r, l.n, got, t[i].want);
        e2get(u, NULL, INTERNET_COOKIE_SAME_SITE_LEVEL_CROSS_SITE, &l);
        CHECKF(l.n == (t[i].want ? 0u : 1u), "case %u: cross-site get n=%lu", (unsigned)i, l.n);
        ck_cleanup();
    }
}
TEST(ck_ex2set_host_only_flag_and_apply) {
    REQ_EX2();
    const char *h = ck_host("e2hof");
    char sub[300]; snprintf(sub, sizeof sub, "www.%s", h);
    s2spec sp = { "hof", "1", NULL, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(h, "/"), &sp, INTERNET_COOKIE_APPLY_HOST_ONLY, &st), 0);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "hof=1");
    EXPECT_STR(ck_gets(ck_url(sub, "/"), NULL, 0), "");
    e2list l; e2get(ck_url(h, "/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    EXPECT_EQ(l.it[0].flags, 0x84202);
    CHECK(l.it[0].flags & INTERNET_COOKIE_HOST_ONLY);
    const char *h2 = ck_host("e2hog");
    char sub2[300]; snprintf(sub2, sizeof sub2, "www.%s", h2);
    EXPECT_EQ(s2(ck_url(h2, "/"), &sp, 0, &st), 0);
    EXPECT_STR(ck_gets(ck_url(sub2, "/"), NULL, 0), "hof=1");   /* no host-only by default, as for the string API */
    ck_cleanup();
}
TEST(ck_ex2set_domain_field) {
    REQ_EX2();
    const char *h = ck_host("e2df");
    char sub[300]; snprintf(sub, sizeof sub, "www.%s", h);
    s2spec sp = { "df", "1", h, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(sub, "/"), &sp, 0, &st), 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "df=1");
    EXPECT_STR(ck_gets(ck_url(sub, "/"), NULL, 0), "df=1");
    char sib[300]; snprintf(sib, sizeof sib, "other.%s", h);
    EXPECT_STR(ck_gets(ck_url(sib, "/"), NULL, 0), "df=1");
    e2list l; e2get(ck_url(sub, "/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    EXPECT_STR(l.it[0].domain, h);
    ck_cleanup();
}
TEST(ck_ex2set_domain_leading_dot_skipped) {
    REQ_EX2();
    const char *h = ck_host("e2dd");
    char sub[300], dot[300]; snprintf(sub, sizeof sub, "www.%s", h); snprintf(dot, sizeof dot, ".%s", h);
    s2spec sp = { "dd", "1", dot, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(sub, "/"), &sp, 0, &st), 0);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "dd=1");
    e2list l; e2get(ck_url(sub, "/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    EXPECT_STR(l.it[0].domain, h);
    ck_cleanup();
}
TEST(ck_ex2set_domain_unrelated_rejected) {
    REQ_EX2();
    const char *h = ck_host("e2du");
    s2spec sp = { "du", "1", "unrelated.i7other.example", "/", 0, FALSE, 0 };
    DWORD st; DWORD r = s2(ck_url(h, "/"), &sp, 0, &st);
    EXPECT_EQ(r, ERROR_INVALID_PARAMETER);                   /* D: IsDomainLegal fails -> SetLastError(87), mapped */
    EXPECT_EQ(st, 0);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_ex2set_domain_child_rejected) {
    REQ_EX2();
    const char *h = ck_host("e2dc");
    char child[300]; snprintf(child, sizeof child, "deeper.%s", h);
    s2spec sp = { "dc", "1", child, "/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(h, "/"), &sp, 0, &st), ERROR_INVALID_PARAMETER);
    ck_cleanup();
}
TEST(ck_ex2set_path_scoping) {
    REQ_EX2();
    const char *h = ck_host("e2ps");
    s2spec sp = { "ps", "1", NULL, "/scope/", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(h, "/"), &sp, 0, &st), 0);   /* set from "/", path names another directory */
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/scope/"), NULL, 0), "ps=1");
    EXPECT_STR(ck_gets(ck_url(h, "/scope/deeper/x"), NULL, 0), "ps=1");
    EXPECT_STR(ck_gets(ck_url(h, "/other/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_ex2set_path_default_from_url) {
    REQ_EX2();
    const char *h = ck_host("e2pdu");
    s2spec sp = { "pdu", "1", NULL, NULL, 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(ck_url(h, "/dir/page.html"), &sp, 0, &st), 0);
    ck_track(ck_url(h, "/dir/"), "pdu", "path=/dir/", 0); ck_track(ck_url(h, "/dir/"), "pdu", "path=/dir", 0);
    e2list l; e2get(ck_url(h, "/dir/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    EXPECT_STR(l.it[0].path, "/dir/");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/dir/x"), NULL, 0), "pdu=1");
    ck_cleanup();
}
TEST(ck_ex2set_path_without_slash_rejected) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2pw"), "/");
    s2spec sp = { "pw", "1", NULL, "noslash", 0, FALSE, 0 };
    DWORD st; EXPECT_EQ(s2(u, &sp, 0, &st), ERROR_INVALID_PARAMETER);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_ex2set_path_too_long_rejected) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2pl"), "/");
    WCHAR *p = malloc(0x9000 * sizeof(WCHAR));
    if (!p) { t_skip("oom"); return; }
    p[0] = L'/'; for (int i = 1; i < 0x8800; i++) p[i] = L'a'; p[0x8800] = 0;
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c); c.pwszName = (PWSTR)L"pl"; c.pwszValue = (PWSTR)L"1"; c.pwszPath = p;
    DWORD st = 99;
    EXPECT_EQ(UN(InternetSetCookieEx2)(ck_w(u), &c, NULL, 0, &st), ERROR_INVALID_PARAMETER);   /* D: >= 0x8000 */
    EXPECT_EQ(st, 0);                                                                           /* D: *state = 0 already */
    free(p);
}
TEST(ck_ex2set_bad_url_errors) {
    REQ_EX2();
    static const char *urls[] = { "not a url", "ftp://e2bu.i7test.example/", "http://bad host.i7test.example/" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        s2spec sp = { "bu", "1", NULL, "/", 0, FALSE, 0 };
        DWORD st = 99;
        INTERNET_COOKIE2 c; memset(&c, 0, sizeof c); c.pwszName = (PWSTR)L"bu"; c.pwszValue = (PWSTR)L"1"; c.pwszPath = (PWSTR)L"/";
        DWORD r = UN(InternetSetCookieEx2)(ck_w(urls[i]), &c, NULL, 0, &st);
        static const DWORD want[] = { ERROR_INTERNET_UNRECOGNIZED_SCHEME, ERROR_INVALID_PARAMETER, ERROR_INTERNET_INVALID_URL };
        CHECKF(r == want[i] && st == 0, "url '%s': r=%lu state=%lu want %lu", urls[i], r, st, want[i]);   /* VM boot 3 */
        (void)sp;
    }
}
TEST(ck_ex2set_p3p_header_accepted) {
    REQ_EX2();
    const char *u = ck_url(ck_host("e2p3"), "/");
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c); c.pwszName = (PWSTR)L"p3"; c.pwszValue = (PWSTR)L"1"; c.pwszPath = (PWSTR)L"/";
    ck_track(u, "p3", "path=/", 0);
    DWORD st = 99;
    DWORD r = UN(InternetSetCookieEx2)(ck_w(u), &c, L"CP=\"NOI DSP COR NID\"", 0, &st);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(r, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "p3=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ Ex2 get: arrays */
TEST(ck_ex2get_array_order_and_fields) {
    REQ_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("e2ar");
    ck_set(ck_url(h, "/"), NULL, "root=r; path=/");
    ck_set(ck_url(h, "/"), NULL, "deep=d; path=/a/b/");
    ck_set(ck_url(h, "/"), NULL, "mid=m; path=/a/");
    const char *s = ck_gets(ck_url(h, "/a/b/c"), NULL, 0);
    EXPECT_STR(s, "deep=d; mid=m; root=r");
    e2list l; e2get(ck_url(h, "/a/b/c"), NULL, 0, &l);
    EXPECT_EQ(l.r, 0); EXPECT_EQ(l.n, 3);
    t_note("Ex2 array: [%s %s] [%s %s] [%s %s]", l.it[0].name, l.it[0].path, l.it[1].name, l.it[1].path, l.it[2].name, l.it[2].path);
    EXPECT_STR(l.it[0].name, "deep"); EXPECT_STR(l.it[0].path, "/a/b/"); EXPECT_STR(l.it[0].value, "d");
    EXPECT_STR(l.it[1].name, "mid");  EXPECT_STR(l.it[1].path, "/a/");
    EXPECT_STR(l.it[2].name, "root"); EXPECT_STR(l.it[2].path, "/");
    for (int i = 0; i < 3; i++) EXPECT_STR(l.it[i].domain, h);
    ck_cleanup();
}
TEST(ck_ex2get_name_filter_multiple_paths) {
    REQ_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("e2nm");
    ck_set(ck_url(h, "/"), NULL, "same=root; path=/");
    ck_set(ck_url(h, "/"), NULL, "same=deep; path=/d/");
    ck_set(ck_url(h, "/"), NULL, "other=o; path=/");
    e2list l; e2get(ck_url(h, "/d/x"), "same", 0, &l);
    EXPECT_EQ(l.n, 2);
    EXPECT_STR(l.it[0].value, "deep");
    EXPECT_STR(l.it[1].value, "root");
    e2get(ck_url(h, "/d/x"), "SAME", 0, &l);
    EXPECT_EQ(l.n, 0);
    ck_cleanup();
}
TEST(ck_ex2get_secure_filtered_by_scheme) {
    REQ_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("e2sf");
    ck_set(ck_surl(h, "/"), NULL, "s=1; secure");
    ck_set(ck_url(h, "/"), NULL, "p=1");
    e2list l; e2get(ck_url(h, "/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 1); EXPECT_STR(l.it[0].name, "p");
    e2get(ck_surl(h, "/"), NULL, 0, &l);
    EXPECT_EQ(l.n, 2);
    ck_cleanup();
}
TEST(ck_ex2get_third_party_flag_hides) {
    REQ_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("e2tp"), "/");
    ck_set(u, NULL, "tp=1");
    e2list l; e2get(u, NULL, INTERNET_COOKIE_THIRD_PARTY, &l);
    EXPECT_EQ(l.r, 0);
    EXPECT_EQ(l.n, 0);                                         /* VM boot 3: hidden under default settings */
    e2get(u, NULL, 0, &l);
    EXPECT_EQ(l.n, 1);
    ck_cleanup();
}
TEST(ck_ex2get_many_cookies_count) {
    REQ_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("e2mc"), "/");
    for (int i = 0; i < 40; i++) { char d[64]; snprintf(d, sizeof d, "m%02d=%d", i, i); ck_set(u, NULL, d); }
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(u), NULL, 0, &arr, &n), 0);
    EXPECT_EQ(n, 40);
    int inorder = 1;
    for (DWORD i = 0; arr && i < n; i++) { char want[16]; snprintf(want, sizeof want, "m%02lu", i); if (strcmp(ck_a(arr[i].pwszName), want)) inorder = 0; }
    CHECK(inorder);                                            /* same path: insertion order */
    if (arr) UN(InternetFreeCookies)(arr, n);
    ck_cleanup();
}
TEST(ck_ex2get_bad_url_errors) {
    REQ_EX2();
    static const char *urls[] = { "not a url", "ftp://e2gu.i7test.example/", "" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        INTERNET_COOKIE2 *arr = NULL; DWORD n = 77;
        DWORD r = UN(InternetGetCookieEx2)(ck_w(urls[i]), NULL, 0, &arr, &n);
        static const DWORD want[] = { ERROR_INTERNET_UNRECOGNIZED_SCHEME, ERROR_INVALID_PARAMETER, ERROR_INTERNET_UNRECOGNIZED_SCHEME };
        CHECKF(r == want[i] && n == 0, "url '%s': r=%lu n=%lu want %lu", urls[i], r, n, want[i]);   /* VM boot 3 */
        if (r == 0 && arr) UN(InternetFreeCookies)(arr, n);
    }
}
