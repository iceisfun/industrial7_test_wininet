/* ck_more.c - second pass over the string API: exhaustive buffer-size sweeps for A and W, Max-Age / Expires
 * edge forms seen through the INTERNET_COOKIE2 view, the W Ex functions with HttpOnly / NON_SCRIPT, EVALUATE_P3P
 * with a P3P header, file: URLs, concurrent setters on several threads, and the import/export probes.
 * Decomp: InternetGetCookieExA@0x16a140, InternetGetCookieExW@0xbeed0, InternalInternetSetCookie@0x6a7d0
 * (EVALUATE_P3P -> EvaluateCookiePolicy with dwReserved as the header), CalculateCookieExpiryTime@0x23b84
 * (max-age overflow clamps to 0x7ffffa7fd71bbfff), ImportCookieFileW@0x134fe0. VM_TIMEOUT: 90 */
#include "ck.h"

static ULONGLONG now64(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }

/* first cookie's (expset, expiry, flags) via InternetGetCookieEx2; returns the count */
static DWORD e2first(const char *url, BOOL *expset, ULONGLONG *exp, DWORD *flags) {
    *expset = FALSE; *exp = 0; *flags = 0;
    if (!UN(InternetGetCookieEx2) || !UN(InternetFreeCookies)) return 0;
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    if (UN(InternetGetCookieEx2)(ck_w(url), NULL, 0, &arr, &n) != 0) return 0;
    if (n && arr) { *expset = arr[0].fExpiresSet; *exp = ((ULONGLONG)arr[0].ftExpires.dwHighDateTime << 32) | arr[0].ftExpires.dwLowDateTime; *flags = arr[0].dwFlags; }
    if (arr) UN(InternetFreeCookies)(arr, n);
    return n;
}

/* ------------------------------------------------------------------------------------------ buffer sweeps */
TEST(ck_more_a_buffer_sweep) {
    REQUIRE(U(InternetGetCookieExA)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("sweepa"), "/");
    ck_set(u, NULL, "alpha=1"); ck_set(u, NULL, "beta=22"); ck_set(u, NULL, "gamma=333");
    const char *want = "alpha=1; beta=22; gamma=333";
    DWORD need = (DWORD)strlen(want) + 1;
    for (DWORD cap = 0; cap <= need + 4; cap++) {
        char b[64]; memset(b, 'Z', sizeof b); DWORD sz = cap;
        SetLastError(0xdeadbeef);
        BOOL r = U(InternetGetCookieExA)(u, NULL, b, &sz, 0, NULL);
        DWORD e = GetLastError();
        if (cap < need) CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && sz == need && b[0] == 'Z', "cap %lu: r=%d gle=%lu sz=%lu", cap, r, e, sz);
        else CHECKF(r && sz == need && !strcmp(b, want) && b[need] == 'Z', "cap %lu: r=%d gle=%lu sz=%lu b='%.40s'", cap, r, e, sz, b);
    }
    ck_cleanup();
}
TEST(ck_more_w_buffer_sweep) {
    REQUIRE(U(InternetGetCookieExW)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("sweepw"), "/");
    ck_set(u, NULL, "alpha=1"); ck_set(u, NULL, "beta=22");
    const char *want = "alpha=1; beta=22";
    DWORD need = (DWORD)strlen(want) + 1;
    for (DWORD cap = 0; cap <= need + 4; cap++) {
        WCHAR b[64]; for (int i = 0; i < 64; i++) b[i] = L'Z';
        DWORD sz = cap;
        SetLastError(0xdeadbeef);
        BOOL r = U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL);
        DWORD e = GetLastError();
        if (cap < need) CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && sz == need * 2 && b[0] == L'Z', "cap %lu: r=%d gle=%lu sz=%lu", cap, r, e, sz);
        else CHECKF(r && sz == need && !strcmp(ck_a(b), want) && b[need] == L'Z', "cap %lu: r=%d gle=%lu sz=%lu", cap, r, e, sz);
    }
    ck_cleanup();
}
TEST(ck_more_get_a_non_ex_sweep) {
    REQUIRE(U(InternetGetCookieA)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("sweepg"), "/");
    ck_set(u, NULL, "k=vv");
    DWORD need = 5;
    for (DWORD cap = 0; cap <= need + 2; cap++) {
        char b[32]; memset(b, 'Z', sizeof b); DWORD sz = cap;
        SetLastError(0xdeadbeef);
        BOOL r = U(InternetGetCookieA)(u, NULL, b, &sz);
        DWORD e = GetLastError();
        if (cap < need) CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER && sz == need, "cap %lu: r=%d gle=%lu sz=%lu", cap, r, e, sz);
        else CHECKF(r && sz == need && !strcmp(b, "k=vv"), "cap %lu: r=%d gle=%lu sz=%lu", cap, r, e, sz);
    }
    ck_cleanup();
}
TEST(ck_more_size_grows_with_each_cookie) {
    REQUIRE(U(InternetGetCookieExA)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("grow"), "/");
    DWORD expect = 0;
    for (int i = 0; i < 12; i++) {
        char d[64]; snprintf(d, sizeof d, "c%d=%0*d", i, i + 1, 0);
        ck_set(u, NULL, d);
        expect += (DWORD)strlen(d) + (i ? 2 : 0);
        DWORD sz = 0;
        BOOL r = U(InternetGetCookieExA)(u, NULL, NULL, &sz, 0, NULL);
        CHECKF(r && sz == expect + 1, "after %d cookies: r=%d sz=%lu want %lu", i + 1, r, sz, expect + 1);
    }
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ expiry forms */
typedef enum { K_SESSION, K_PERSIST, K_GONE } kind_t;
static const char *kname(kind_t k) { return k == K_SESSION ? "session" : k == K_PERSIST ? "persistent" : "deleted"; }
static kind_t observe(const char *u) {
    BOOL es; ULONGLONG ex; DWORD fl;
    DWORD n = e2first(u, &es, &ex, &fl);
    if (n == 0) return K_GONE;
    return es ? K_PERSIST : K_SESSION;
}
TEST(ck_more_max_age_forms_table) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    static const struct { const char *attr; kind_t want; } t[] = {
        { "max-age=60", K_PERSIST },
        { "Max-Age=86400", K_PERSIST },
        { "MAX-AGE=60", K_PERSIST },
        { "max-age = 60", K_PERSIST },
        { "max-age=0", K_GONE },
        { "MAX-AGE=0", K_GONE },
        { "max-age=-1", K_GONE },
        { "max-age=-86400", K_GONE },
        { "max-age=", K_SESSION },
        { "max-age", K_SESSION },
        { "max-age=abc", K_SESSION },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("maf"), "/");
        ck_set(u, NULL, "mf=old");                         /* existing session cookie, so "deleted" is observable */
        char d[128]; snprintf(d, sizeof d, "mf=new; %s", t[i].attr);
        ck_set(u, NULL, d);
        kind_t k = observe(u);
        CHECKF(k == t[i].want, "case %u '%s': %s want %s (get '%s')", (unsigned)i, t[i].attr, kname(k), kname(t[i].want), ck_gets(u, NULL, 0));
        ck_cleanup();
    }
}
TEST(ck_more_max_age_odd_forms_ignored) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    static const char *t[] = { "max-age=+60", "max-age=60abc", "max-age=60.5", "max-age=0x10", "max-age=99999999999",
                               "max-age=2147483648", "max-age=4294967296", "max-age=-0", "max-age=\"60\"", "max-age= -5" };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("mao"), "/");
        ck_set(u, NULL, "mo=old");
        char d[128]; snprintf(d, sizeof d, "mo=new; %s", t[i]);
        BOOL r = ck_set(u, NULL, d);
        BOOL es; ULONGLONG ex; DWORD fl; DWORD n = e2first(u, &es, &ex, &fl);
        long long secs = n && es ? (long long)((LONGLONG)ex - (LONGLONG)now64()) / 10000000LL : 0;
        t_note("'%s': set=%d n=%lu expset=%d secs=%lld", t[i], r, n, es, secs);
        CHECK(r == TRUE);
        /* VM boot 3: every odd form is ignored (session cookie replaced) except "= -5", which still deletes */
        if (strstr(t[i], "-5")) CHECKF(n == 0, "'%s' n=%lu", t[i], n);
        else CHECKF(n == 1 && !es && !strcmp(ck_gets(u, NULL, 0), "mo=new"), "'%s' n=%lu expset=%d", t[i], n, es);
        ck_cleanup();
    }
}
TEST(ck_more_max_age_huge_is_persistent) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("mah"), "/");
    ck_set(u, NULL, "mh=1; max-age=315360000");   /* ten years */
    BOOL es; ULONGLONG ex; DWORD fl;
    EXPECT_EQ(e2first(u, &es, &ex, &fl), 1);
    EXPECT_EQ(es, TRUE);
    ULONGLONG n = now64();
    CHECKF(ex > n + 3600ULL * 24 * 3600 * 10000000ULL, "expiry only %lld s ahead", (long long)((ex - n) / 10000000ULL));
    ck_cleanup();
}
TEST(ck_more_expires_far_future_forms) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    static const char *t[] = { "Fri, 31 Dec 2100 23:59:59 GMT", "Thu, 31-Dec-2037 23:59:59 GMT", "Tue, 19 Jan 2038 03:14:08 GMT",
                               "Wed, 01 Jan 2200 00:00:00 GMT" };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("eff"), "/");
        char d[128]; snprintf(d, sizeof d, "ef=1; expires=%s", t[i]);
        ck_set(u, NULL, d);
        BOOL es; ULONGLONG ex; DWORD fl; DWORD n = e2first(u, &es, &ex, &fl);
        SYSTEMTIME st; FILETIME f; f.dwLowDateTime = (DWORD)ex; f.dwHighDateTime = (DWORD)(ex >> 32); memset(&st, 0, sizeof st);
        FileTimeToSystemTime(&f, &st);
        t_note("expires '%s': n=%lu expset=%d -> %04u-%02u-%02u", t[i], n, es, st.wYear, st.wMonth, st.wDay);
        CHECKF(n == 1 && es, "case '%s' n=%lu expset=%d", t[i], n, es);
        ck_cleanup();
    }
}
TEST(ck_more_expires_exact_value) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("efx"), "/");
    ck_set(u, NULL, "ex=1; expires=Fri, 31 Dec 2100 23:59:59 GMT");
    BOOL es; ULONGLONG ex; DWORD fl;
    EXPECT_EQ(e2first(u, &es, &ex, &fl), 1);
    SYSTEMTIME st = { 2100, 12, 5, 31, 23, 59, 59, 0 }; FILETIME f; SystemTimeToFileTime(&st, &f);
    ULONGLONG want = ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime;
    CHECKF(ex == want, "expiry %llx want %llx", ex, want);
    ck_cleanup();
}
TEST(ck_more_expires_then_max_age_zero_case_mix) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("mx0"), "/");
    ck_set(u, NULL, "z=1");
    char d[200]; snprintf(d, sizeof d, "z=2; EXPIRES=%s; Max-Age=0", ck_date(3));
    ck_set(u, NULL, d);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_more_session_to_persistent_and_back) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("sp"), "/");
    ck_set(u, NULL, "sp=1");
    EXPECT_EQ(observe(u), K_SESSION);
    char d[200]; snprintf(d, sizeof d, "sp=2; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_EQ(observe(u), K_PERSIST);
    ck_set(u, NULL, "sp=3");
    EXPECT_EQ(observe(u), K_SESSION);
    EXPECT_STR(ck_gets(u, NULL, 0), "sp=3");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ W Ex + flags */
TEST(ck_more_setex_w_httponly_and_getex_w_flags) {
    REQUIRE(U(InternetSetCookieExW)); REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("wh"), "/");
    ck_track(u, "wh", NULL, 0);
    SetLastError(0xdeadbeef);
    DWORD r = U(InternetSetCookieExW)(ck_w(u), NULL, L"wh=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, 0);
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    static const struct { DWORD fl; BOOL vis; } t[] = { { 0, FALSE }, { INTERNET_COOKIE_HTTPONLY, TRUE }, { INTERNET_COOKIE_NON_SCRIPT, TRUE } };
    for (size_t i = 0; i < 3; i++) {
        WCHAR b[64]; DWORD sz = 64;
        SetLastError(0xdeadbeef);
        BOOL g = U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, t[i].fl, NULL);
        DWORD e = GetLastError();
        if (t[i].vis) CHECKF(g && !lstrcmpW(b, L"wh=1"), "flags 0x%lx: g=%d gle=%lu", t[i].fl, g, e);
        else CHECKF(!g && e == ERROR_NO_MORE_ITEMS, "flags 0x%lx: g=%d gle=%lu", t[i].fl, g, e);
    }
    ck_cleanup();
}
TEST(ck_more_setex_w_httponly_without_flag_rejected) {
    REQUIRE(U(InternetSetCookieExW));
    const char *u = ck_url(ck_host("whr"), "/");
    ck_track(u, "whr", NULL, 0);
    SetLastError(0xdeadbeef);
    DWORD r = U(InternetSetCookieExW)(ck_w(u), NULL, L"whr=1; HttpOnly", 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(r, COOKIE_STATE_REJECT);
    EXPECT_EQ(e, 0);   /* D (InternetSetCookieExW keeps GLE only when the state is 0) + VM: REJECT with GLE 0 */
    ck_cleanup();
}
TEST(ck_more_setex_non_script_accepts_httponly) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("nsh"), "/");
    DWORD gle;
    EXPECT_EQ(ck_setx(u, NULL, "nsh=1; HttpOnly", INTERNET_COOKIE_NON_SCRIPT, &gle), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_NON_SCRIPT), "nsh=1");
    ck_cleanup();
}
TEST(ck_more_get_flags_combined_httponly_and_plain) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("mix"), "/");
    ck_set(u, NULL, "plain=1");
    ck_setx(u, NULL, "hidden=2; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL);
    ck_set(u, NULL, "plain2=3");
    EXPECT_STR(ck_gets(u, NULL, 0), "plain=1; plain2=3");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "plain=1; hidden=2; plain2=3");
    EXPECT_STR(ck_gets(u, "hidden", 0), "");
    EXPECT_STR(ck_gets(u, "hidden", INTERNET_COOKIE_HTTPONLY), "hidden=2");
    ck_cleanup();
}
TEST(ck_more_evaluate_p3p_with_header) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("p3"), "/");
    ck_track(u, "p3", NULL, 0);
    SetLastError(0xdeadbeef);
    DWORD r = U(InternetSetCookieExA)(u, NULL, "p3=1", INTERNET_COOKIE_EVALUATE_P3P, (DWORD_PTR)"CP=\"NOI DSP COR NID CUR OUR NOR\"");
    DWORD e = GetLastError();
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(e, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "p3=1");
    ck_cleanup();
}
TEST(ck_more_evaluate_p3p_null_header) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("p3n"), "/");
    ck_track(u, "p3n", NULL, 0);
    DWORD r = U(InternetSetCookieExA)(u, NULL, "p3n=1", INTERNET_COOKIE_EVALUATE_P3P, 0);
    t_note("EVALUATE_P3P without header: state=%lu gle=%lu get='%s'", r, GetLastError(), ck_gets(u, NULL, 0));
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ odd URLs */
TEST(ck_more_file_url_cookie) {
    REQUIRE(U(InternetSetCookieA));
    char url[300]; snprintf(url, sizeof url, "file:///C:/%s/page.htm", t_uniq("ckfile"));
    char dir[300]; snprintf(dir, sizeof dir, "%.*s", (int)(strrchr(url, '/') - url + 1), url);
    SetLastError(0xdeadbeef);
    BOOL r = ck_set(url, NULL, "fc=1");
    DWORD e = GetLastError();
    const char *g = ck_gets(url, NULL, 0);
    t_note("file URL cookie: set=%d gle=%lu", r, e);
    EXPECT_EQ(r, TRUE);                                            /* VM boot 3 */
    EXPECT_STR(g, "fc=1");
    EXPECT_STR(ck_gets(dir, NULL, 0), "fc=1");
    ck_cleanup();
}
TEST(ck_more_url_trailing_dot_host) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("tdot");
    char dot[300]; snprintf(dot, sizeof dot, "%s.", h);
    SetLastError(0xdeadbeef);
    BOOL r = ck_set(ck_url(dot, "/"), NULL, "td=1");
    EXPECT_EQ(r, TRUE);                                            /* VM boot 3: "h." is its own jar entry */
    EXPECT_STR(ck_gets(ck_url(dot, "/"), NULL, 0), "td=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_more_percent_encoded_path_not_decoded) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("pct");
    ck_set(ck_url(h, "/"), NULL, "pe=1; path=/a%20b/");
    EXPECT_STR(ck_gets(ck_url(h, "/a%20b/x"), NULL, 0), "pe=1");
    EXPECT_STR(ck_gets(ck_url(h, "/a%20c/x"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_more_query_in_get_url_ignored) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("qg");
    ck_set(ck_url(h, "/"), NULL, "q=1; path=/qq/");
    EXPECT_STR(ck_gets(ck_url(h, "/qq/page?x=/zz/"), NULL, 0), "q=1");
    EXPECT_STR(ck_gets(ck_url(h, "/page?x=/qq/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/qq/#frag"), NULL, 0), "q=1");
    ck_cleanup();
}
TEST(ck_more_many_hosts_isolated) {
    REQUIRE(U(InternetSetCookieA));
    char hosts[10][200];
    for (int i = 0; i < 10; i++) { snprintf(hosts[i], 200, "%s", ck_host("iso")); char d[32]; snprintf(d, sizeof d, "iso=%d", i); ck_set(ck_url(hosts[i], "/"), NULL, d); }
    for (int i = 0; i < 10; i++) { char w[32]; snprintf(w, sizeof w, "iso=%d", i); EXPECT_STR(ck_gets(ck_url(hosts[i], "/"), NULL, 0), w); }
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ threads */
typedef struct { char url[200]; int base; int ok; } thr_arg;
static DWORD WINAPI setter(void *p) {
    thr_arg *a = p;
    __typeof__(&InternetSetCookieA) f = U(InternetSetCookieA);
    for (int i = 0; i < 25; i++) { char d[64]; snprintf(d, sizeof d, "t%d_%d=%d", a->base, i, i); if (f(a->url, NULL, d)) a->ok++; }
    return 0;
}
TEST(ck_more_threads_concurrent_setters) {
    REQUIRE(U(InternetSetCookieA));
    static thr_arg args[8]; HANDLE th[8]; int nt = 0;   /* static: a thread still running after a wait timeout must not see a dead stack frame */
    const char *shared = ck_url(ck_host("thr"), "/");
    for (int t = 0; t < 8; t++) {
        snprintf(args[t].url, sizeof args[t].url, "%s", (t & 1) ? shared : ck_url(ck_host("thr"), "/"));
        args[t].base = t; args[t].ok = 0;
        for (int i = 0; i < 25; i++) { char n[32]; snprintf(n, sizeof n, "t%d_%d", t, i); ck_track(args[t].url, n, NULL, 0); }
    }
    for (int t = 0; t < 8; t++) { th[nt] = CreateThread(NULL, 0, setter, &args[t], 0, NULL); if (th[nt]) nt++; }
    DWORD w = WaitForMultipleObjects(nt, th, TRUE, 20000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    for (int i = 0; i < nt; i++) CloseHandle(th[i]);
    for (int t = 0; t < 8; t++) {
        EXPECT_EQ(args[t].ok, 25);
        const char *g = ck_gets(args[t].url, NULL, 0);
        int found = 0;
        for (int i = 0; i < 25; i++) { char it[32]; snprintf(it, sizeof it, "t%d_%d=%d", t, i, i); found += ck_has(g, it); }
        CHECKF(found == 25, "thread %d: %d of 25 cookies present", t, found);
    }
    EXPECT_EQ(ck_count(ck_gets(shared, NULL, 0)), 100);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ import / export probes */
typedef BOOL (WINAPI *import_a_fn)(LPCSTR file);
typedef BOOL (WINAPI *export_a_fn)(LPCSTR file, BOOL append);
static FARPROC ordp(unsigned n) { return t_is_wine() ? NULL : t_proc_ord("wininet.dll", n); }
static unsigned long long unix_now(void) { return now64() / 10000000ULL - 11644473600ULL; }
#define SKEW 363543LL   /* cookie-file epoch skew, see ck_extra.c */
static int wfile(const char *path, const char *data) {
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; WriteFile(f, data, (DWORD)strlen(data), &w, NULL); CloseHandle(f);
    return w == strlen(data);
}
TEST(ck_more_import_expiry_skew) {
    import_a_fn im = (import_a_fn)ordp(108);
    REQUIRE(im);
    static const int days[] = { 1, 2, 7, 30, 365 };
    for (size_t i = 0; i < sizeof days / sizeof days[0]; i++) {
        const char *h = ck_host("impx");
        char dom[300]; snprintf(dom, sizeof dom, "path=/; domain=%s", h);
        ck_track(ck_url(h, "/"), "ix", dom, 0); ck_track(ck_url(h, "/"), "ix", "path=/", 0);
        char line[600]; snprintf(line, sizeof line, "%s\tTRUE\t/\tFALSE\t%llu\tix\tiv\r\n", h, unix_now() + (unsigned long long)days[i] * 86400);
        char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "import_probe.txt");
        wfile(fn, line);
        BOOL r = im(fn);
        const char *a = ck_gets(ck_url(h, "/"), NULL, 0);
        const char *b = ck_gets(ck_url(h, "/"), NULL, INTERNET_COOKIE_HTTPONLY);
        BOOL es; ULONGLONG ex; DWORD fl; DWORD n = e2first(ck_url(h, "/"), &es, &ex, &fl);
        t_note("import +%dd: r=%d get='%s' httponly-get='%s' ex2 n=%lu flags=0x%lx expset=%d", days[i], r, a, b, n, fl, es);
        CHECK(r == TRUE);
        /* VM boot 3: the column is read SKEW seconds early, so lines less than ~4.2 days ahead arrive expired */
        BOOL vis = (long long)days[i] * 86400 > SKEW;
        CHECKF(vis ? (n == 1 && es && !strcmp(a, "ix=iv")) : (n == 0 && !strcmp(a, "")), "+%dd: n=%lu get='%s'", days[i], n, a);
        if (n == 1) {
            long long d = (long long)(ex / 10000000ULL - 11644473600ULL) - (long long)(unix_now() + (unsigned long long)days[i] * 86400) + SKEW;
            CHECKF(d >= -30 && d <= 5, "+%dd: stored expiry off by %lld s from column-SKEW", days[i], d);
        }
        DeleteFileA(fn);
        ck_cleanup();
    }
}
TEST(ck_more_export_expiry_skew) {
    export_a_fn ex = (export_a_fn)ordp(109);
    REQUIRE(ex); REQUIRE(U(InternetSetCookieA));
    static const int days[] = { 1, 2, 30 };
    const char *h[3];
    for (int i = 0; i < 3; i++) {
        h[i] = ck_host("expx");
        char d[200]; snprintf(d, sizeof d, "xx=1; expires=%s", ck_date(days[i]));
        ck_set(ck_url(h[i], "/"), NULL, d);
    }
    const char *hm = ck_host("expm");
    ck_set(ck_url(hm, "/"), NULL, "xm=1; max-age=3600");
    char fn[MAX_PATH]; t_tmpfile(fn, sizeof fn, "export_probe.txt");
    EXPECT_EQ(ex(fn, FALSE), TRUE);
    HANDLE f = CreateFileA(fn, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    static char txt[1 << 20]; DWORD n = 0;
    if (f != INVALID_HANDLE_VALUE) { ReadFile(f, txt, sizeof txt - 1, &n, NULL); CloseHandle(f); }
    txt[n] = 0;
    unsigned long long now = unix_now();
    for (int i = 0; i < 4; i++) {
        const char *host = i < 3 ? h[i] : hm;
        char pre[300]; snprintf(pre, sizeof pre, "\n%s\tTRUE\t/\tFALSE\t", host);
        char *l = strstr(txt, pre);
        unsigned long long v = l ? strtoull(l + strlen(pre), NULL, 10) : 0;
        t_note("export %s: line=%d value=%llu delta=%lld s", i < 3 ? (i == 0 ? "+1d" : i == 1 ? "+2d" : "+30d") : "max-age 3600", l != NULL, v, (long long)(v - now));
        CHECK(l != NULL);
        long long want = (long long)now + (i < 3 ? days[i] * 86400LL : 3600LL) + SKEW;
        CHECKF((long long)v >= want - 5 && (long long)v <= want + 1, "value %llu want ~%lld", v, want);
    }
    DeleteFileA(fn);
    ck_cleanup();
}
