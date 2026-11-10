/* ck_parse.c - cookie string parsing through InternetSetCookie: name=value tokenising, whitespace, nameless
 * cookies, attributes (expires / max-age / path / domain / secure / httponly / samesite / version), and the
 * INTERNET_COOKIE2 view (InternetGetCookieEx2) of what was stored.
 * Decomp: ParseHeader@0x6c760, CCookieJar::SetCookieParsed@0x3126c, InternalInternetGetCookieEx2@0x83820,
 * AddCookieToArray@0x85050. VM_TIMEOUT: 120 */
#include "ck.h"

/* ------------------------------------------------------------------------------------------ Ex2 helpers */
typedef struct { int found; char name[512], value[2048], domain[512], path[512]; DWORD flags; FILETIME exp; BOOL expset; DWORD count; } ck2;
static DWORD ex2_get(const char *url, const char *name, DWORD flags, ck2 *out) {
    memset(out, 0, sizeof *out);
    if (!UN(InternetGetCookieEx2) || !UN(InternetFreeCookies)) return ERROR_PROC_NOT_FOUND;
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    DWORD r = UN(InternetGetCookieEx2)(ck_w(url), name ? ck_w(name) : NULL, flags, &arr, &n);
    out->count = n;
    if (r == 0 && n > 0 && arr) {
        out->found = 1;
        snprintf(out->name, sizeof out->name, "%s", arr[0].pwszName ? ck_a(arr[0].pwszName) : "(null)");
        snprintf(out->value, sizeof out->value, "%s", arr[0].pwszValue ? ck_a(arr[0].pwszValue) : "(null)");
        snprintf(out->domain, sizeof out->domain, "%s", arr[0].pwszDomain ? ck_a(arr[0].pwszDomain) : "(null)");
        snprintf(out->path, sizeof out->path, "%s", arr[0].pwszPath ? ck_a(arr[0].pwszPath) : "(null)");
        out->flags = arr[0].dwFlags; out->exp = arr[0].ftExpires; out->expset = arr[0].fExpiresSet;
    }
    if (arr) UN(InternetFreeCookies)(arr, n);
    return r;
}
#define REQUIRE_EX2() do { REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(UN(InternetFreeCookies)); } while (0)

/* ------------------------------------------------------------------------------------------ name=value table */
typedef struct { const char *in; const char *out; } kv_case;
static const kv_case k_kv[] = {
    { "a=1", "a=1" },
    { "a=1;", "a=1" },
    { "a=1; ", "a=1" },
    { "  a  =  1  ", "a=1" },
    { "\ta\t=\t1\t", "a=1" },
    { "a = b c", "a=b c" },
    { "a=b=c", "a=b=c" },
    { "a==b", "a==b" },
    { "a=", "a=" },
    { "a= ", "a=" },
    { "a=;path=/", "a=" },
    { "lone", "lone" },
    { " lone ", "lone" },
    { "lone; path=/", "lone" },
    { "two words", "two words" },
    { "=v", "v" },
    { " = v", "v" },
    { "a=\"quoted value\"", "a=\"quoted value\"" },
    { "a=1,b=2", "a=1,b=2" },
    { "a=1; b=2", "a=1" },
    { "a=1; unknown=zz; flag", "a=1" },
    { "MiXeD=VaLuE", "MiXeD=VaLuE" },
    { "pct=%20%3B", "pct=%20%3B" },
    { "sym=!#$&'()*+-./:<>?@[]^_`{|}~", "sym=!#$&'()*+-./:<>?@[]^_`{|}~" },
    { "n.with.dots=1", "n.with.dots=1" },
    { "n-dash_u=1", "n-dash_u=1" },
    { "b64=YWJj+/==", "b64=YWJj+/==" },
    { "a=1;path=/;secure_not=1", "a=1" },
};
TEST(ck_parse_name_value_table) {
    REQUIRE(U(InternetSetCookieA));
    for (size_t i = 0; i < sizeof k_kv / sizeof k_kv[0]; i++) {
        const char *u = ck_url(ck_host("kv"), "/");
        BOOL r = ck_set(u, NULL, k_kv[i].in);
        CHECKF(r == TRUE, "case %u set '%s' r=%d gle=%lu", (unsigned)i, k_kv[i].in, r, GetLastError());
        const char *got = ck_gets(u, NULL, 0);
        CHECKF(!strcmp(got, k_kv[i].out), "case %u '%s': got '%s' want '%s'", (unsigned)i, k_kv[i].in, got, k_kv[i].out);
        ck_cleanup();
    }
}
TEST(ck_parse_name_param_table) {
    REQUIRE(U(InternetSetCookieA));
    static const struct { const char *name, *data, *out; } t[] = {
        { "n", "v", "n=v" },
        { "n", "v; path=/", "n=v" },
        { "n", "", "n=" },
        { "n", "a=b", "n=a=b" },
        { "  n  ", "v", "n=v" },
        { "", "v", "v" },
        { "n", "  v  ", "n=v" },
        { "UPPER", "Low", "UPPER=Low" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("np"), "/");
        BOOL r = ck_set(u, t[i].name, t[i].data);
        CHECKF(r == TRUE, "case %u r=%d", (unsigned)i, r);
        const char *got = ck_gets(u, NULL, 0);
        CHECKF(!strcmp(got, t[i].out), "case %u name='%s' data='%s': got '%s' want '%s'", (unsigned)i, t[i].name, t[i].data, got, t[i].out);
        ck_cleanup();
    }
}
TEST(ck_parse_empty_data) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("empty"), "/");
    BOOL r = ck_set(u, NULL, "");
    DWORD e = GetLastError();
    char b[64]; BOOL g = ck_get(u, NULL, 0, b, sizeof b);
    t_note("set \"\": r=%d gle=%lu; get r=%d gle=%lu size=%lu '%s'", r, e, g, ck_gle, ck_size, b);
    ck_cleanup();
}
TEST(ck_parse_name_with_semicolon_param) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("nsemi"), "/");
    ck_track(u, "a", NULL, 0);
    EXPECT_EQ(ck_set(u, "a;b", "1"), TRUE);      /* stored as "a;b=1": name "a", the rest is an attribute token */
    EXPECT_STR(ck_gets(u, NULL, 0), "a");
    ck_cleanup();
}
TEST(ck_parse_value_with_semicolon_param) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("vsemi"), "/");
    EXPECT_EQ(ck_set(u, "v", "x;y"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "v=x");
    ck_cleanup();
}
TEST(ck_parse_control_char_value) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ctl"), "/");
    BOOL r = ck_set(u, NULL, "c=x\x01y");
    const char *got = ck_gets(u, NULL, 0);
    char hex[64] = ""; for (int i = 0; got[i] && i < 12; i++) snprintf(hex + strlen(hex), sizeof hex - strlen(hex), "%02x", (unsigned char)got[i]);
    t_note("control char value: set r=%d got hex %s", r, hex);
    CHECK(r == TRUE);
    CHECK(!strncmp(got, "c=x", 3) && strlen(got) == 5);
    ck_cleanup();
}
TEST(ck_parse_long_value_4096) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("l4k"), "/");
    char *d = malloc(4096 + 3); strcpy(d, "L="); memset(d + 2, 'v', 4096); d[4098] = 0;
    EXPECT_EQ(ck_set(u, NULL, d), TRUE);
    const char *got = ck_gets(u, NULL, 0);
    EXPECT_EQ(strlen(got), 4098);
    CHECK(!strcmp(got, d));
    free(d);
    ck_cleanup();
}
TEST(ck_parse_size_limit_total_5119_ok) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("l5119"), "/");
    char *d = malloc(5120); strcpy(d, "L="); memset(d + 2, 'w', 5117); d[5119] = 0;     /* 5119 chars + NUL = 0x1400 */
    BOOL r = ck_set(u, NULL, d);
    DWORD e = GetLastError();
    EXPECT_EQ(r, TRUE);
    t_note("5119-char cookie: r=%d gle=%lu", r, e);
    EXPECT_EQ(strlen(ck_gets(u, NULL, 0)), 5119);
    free(d);
    ck_cleanup();
}
TEST(ck_parse_size_limit_total_5120_fails) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("l5120"), "/");
    char *d = malloc(5121); strcpy(d, "L="); memset(d + 2, 'w', 5118); d[5120] = 0;
    SetLastError(0xdeadbeef);
    BOOL r = ck_set(u, NULL, d);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    t_note("5120-char cookie: r=%d gle=%lu", r, e);
    EXPECT_EQ(e, ERROR_INSUFFICIENT_BUFFER);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    free(d);
    ck_cleanup();
}
TEST(ck_parse_size_limit_name_param_counts) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("lnp"), "/");
    /* "N" + "=" + data: 2 + 5117 = 5119 fits, 2 + 5118 = 5120 does not */
    char *d = malloc(5120); memset(d, 'x', 5118); d[5117] = 0;
    EXPECT_EQ(ck_set(u, "N", d), TRUE);
    EXPECT_EQ(strlen(ck_gets(u, NULL, 0)), 5119);
    d[5117] = 'x'; d[5118] = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(ck_set(u, "N", d), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(strlen(ck_gets(u, NULL, 0)), 5119);      /* the earlier cookie is untouched */
    free(d);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ expiry */
TEST(ck_attr_expires_past_deletes) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("exp"), "/");
    EXPECT_EQ(ck_set(u, NULL, "e=1"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "e=1");
    EXPECT_EQ(ck_set(u, NULL, "e=2; " CK_PAST), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    ck_cleanup();
}
TEST(ck_attr_expires_formats_table) {
    REQUIRE(U(InternetSetCookieA));
    static const char *past[] = {
        "expires=Thu, 01 Jan 1970 00:00:01 GMT",
        "expires=Thu, 01-Jan-1970 00:00:01 GMT",
        "expires=Thursday, 01-Jan-70 00:00:01 GMT",
        "expires=Thu Jan  1 00:00:01 1970",
        "Expires=Sat, 01 Jan 2000 00:00:00 GMT",
        "EXPIRES=Sat, 01-Jan-2000 00:00:00 GMT",
        "expires = Sat, 01 Jan 2000 00:00:00 GMT",
    };
    for (size_t i = 0; i < sizeof past / sizeof past[0]; i++) {
        const char *u = ck_url(ck_host("expf"), "/");
        ck_set(u, NULL, "e=1");
        char d[256]; snprintf(d, sizeof d, "e=1; %s", past[i]);
        BOOL r = ck_set(u, NULL, d);
        const char *got = ck_gets(u, NULL, 0);
        CHECKF(r == TRUE && !strcmp(got, ""), "past format %u '%s': r=%d got '%s'", (unsigned)i, past[i], r, got);
        ck_cleanup();
    }
}
TEST(ck_attr_expires_future_formats_table) {
    REQUIRE(U(InternetSetCookieA));
    const char *fut[4]; char a[3][128];
    snprintf(a[0], sizeof a[0], "expires=%s", ck_date(3));
    snprintf(a[1], sizeof a[1], "expires=%s", ck_date_old(3));
    snprintf(a[2], sizeof a[2], "expires=Fri, 01 Jan 2100 00:00:00 GMT");
    fut[0] = a[0]; fut[1] = a[1]; fut[2] = a[2];
    for (int i = 0; i < 3; i++) {
        const char *u = ck_url(ck_host("expfut"), "/");
        char d[256]; snprintf(d, sizeof d, "f=1; %s", fut[i]);
        BOOL r = ck_set(u, NULL, d);
        const char *got = ck_gets(u, NULL, 0);
        CHECKF(r == TRUE && !strcmp(got, "f=1"), "future format %d '%s': r=%d got '%s'", i, fut[i], r, got);
        ck_cleanup();
        EXPECT_STR(ck_gets(u, NULL, 0), "");   /* cleanup removed the persistent cookie */
    }
}
TEST(ck_attr_expires_garbage_is_session) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("expg"), "/");
    EXPECT_EQ(ck_set(u, NULL, "g=1; expires=not a date"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "g=1");
    ck_cleanup();
}
TEST(ck_attr_max_age_zero_deletes) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ma0"), "/");
    ck_set(u, NULL, "m=1");
    EXPECT_STR(ck_gets(u, NULL, 0), "m=1");
    EXPECT_EQ(ck_set(u, NULL, "m=1; max-age=0"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_attr_max_age_negative_deletes) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("maneg"), "/");
    ck_set(u, NULL, "m=1");
    EXPECT_EQ(ck_set(u, NULL, "m=1; Max-Age=-100"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_attr_max_age_positive_kept) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("mapos"), "/");
    EXPECT_EQ(ck_set(u, NULL, "m=1; max-age=3600"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "m=1");
    ck_cleanup();
    EXPECT_STR(ck_gets(u, NULL, 0), "");
}
TEST(ck_attr_max_age_wins_over_past_expires_before) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("mawin1"), "/");
    EXPECT_EQ(ck_set(u, NULL, "m=1; max-age=3600; " CK_PAST), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "m=1");
    ck_cleanup();
}
TEST(ck_attr_max_age_wins_over_past_expires_after) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("mawin2"), "/");
    EXPECT_EQ(ck_set(u, NULL, "m=1; " CK_PAST "; max-age=3600"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "m=1");
    ck_cleanup();
}
TEST(ck_attr_max_age_zero_wins_over_future_expires) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("mawin3"), "/");
    ck_set(u, NULL, "m=1");
    char d[200]; snprintf(d, sizeof d, "m=1; expires=%s; max-age=0", ck_date(3));
    EXPECT_EQ(ck_set(u, NULL, d), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_attr_max_age_garbage_ignored) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("magb"), "/");
    EXPECT_EQ(ck_set(u, NULL, "m=1; max-age=abc"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "m=1");
    EXPECT_EQ(ck_set(u, NULL, "m2=1; max-age"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "m=1; m2=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ Ex2 view of attributes */
TEST(ck_ex2_session_cookie_fields) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ex2s");
    const char *u = ck_url(h, "/");
    ck_set(u, NULL, "sn=sv; path=/");
    ck2 c; DWORD r = ex2_get(u, NULL, 0, &c);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(c.count, 1);
    EXPECT_STR(c.name, "sn");
    EXPECT_STR(c.value, "sv");
    EXPECT_STR(c.path, "/");
    t_note("ex2 session: domain='%s' flags=0x%lx expset=%d exp=%08lx%08lx", c.domain, c.flags, c.expset, c.exp.dwHighDateTime, c.exp.dwLowDateTime);
    EXPECT_STR(c.domain, h);
    CHECK(c.flags & INTERNET_COOKIE_IS_SESSION);
    CHECK(!(c.flags & INTERNET_COOKIE_IS_SECURE));
    CHECK(!(c.flags & INTERNET_COOKIE_HTTPONLY));
    EXPECT_EQ(c.expset, FALSE);
    ck_cleanup();
}
TEST(ck_ex2_persistent_cookie_fields) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ex2p"), "/");
    char d[200]; snprintf(d, sizeof d, "pn=pv; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    ck2 c; EXPECT_EQ(ex2_get(u, NULL, 0, &c), 0);
    EXPECT_STR(c.name, "pn");
    t_note("ex2 persistent: flags=0x%lx expset=%d", c.flags, c.expset);
    CHECK(!(c.flags & INTERNET_COOKIE_IS_SESSION));
    EXPECT_EQ(c.expset, TRUE);
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULONGLONG e = ((ULONGLONG)c.exp.dwHighDateTime << 32) | c.exp.dwLowDateTime, n = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    CHECKF(e > n + 864000000000ULL && e < n + 3ULL * 864000000000ULL, "expiry not ~2 days ahead");
    ck_cleanup();
}
TEST(ck_ex2_max_age_expiry) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ex2m"), "/");
    ck_set(u, NULL, "ma=1; max-age=7200");
    ck2 c; EXPECT_EQ(ex2_get(u, NULL, 0, &c), 0);
    CHECK(!(c.flags & INTERNET_COOKIE_IS_SESSION));
    EXPECT_EQ(c.expset, TRUE);
    FILETIME now; GetSystemTimeAsFileTime(&now);
    LONGLONG e = (LONGLONG)(((ULONGLONG)c.exp.dwHighDateTime << 32) | c.exp.dwLowDateTime), n = (LONGLONG)(((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime);
    LONGLONG d = (e - n) / 10000000;   /* seconds */
    CHECKF(d > 7000 && d <= 7200, "max-age 7200 -> %lld s", d);
    ck_cleanup();
}
TEST(ck_ex2_secure_flag) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ex2sec");
    ck_set(ck_surl(h, "/"), NULL, "sec=1; secure");
    ck2 c; EXPECT_EQ(ex2_get(ck_surl(h, "/"), NULL, 0, &c), 0);
    EXPECT_EQ(c.count, 1);
    t_note("ex2 secure flags=0x%lx", c.flags);
    CHECK(c.flags & INTERNET_COOKIE_IS_SECURE);
    EXPECT_EQ(ex2_get(ck_url(h, "/"), NULL, 0, &c), 0);
    EXPECT_EQ(c.count, 0);
    ck_cleanup();
}
TEST(ck_ex2_httponly_flag) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("ex2ho"), "/");
    EXPECT_EQ(ck_setx(u, NULL, "ho=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL), COOKIE_STATE_ACCEPT);
    ck2 c; EXPECT_EQ(ex2_get(u, NULL, 0, &c), 0);
    EXPECT_EQ(c.count, 0);                                    /* not without NON_SCRIPT */
    EXPECT_EQ(ex2_get(u, NULL, INTERNET_COOKIE_NON_SCRIPT, &c), 0);
    EXPECT_EQ(c.count, 1);
    t_note("ex2 httponly flags=0x%lx", c.flags);
    CHECK(c.flags & INTERNET_COOKIE_HTTPONLY);
    ck_cleanup();
}
TEST(ck_ex2_samesite_flags) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    static const struct { const char *attr; DWORD want; } t[] = {
        { "SameSite=Strict", INTERNET_COOKIE_SAME_SITE_STRICT },
        { "samesite=strict", INTERNET_COOKIE_SAME_SITE_STRICT },
        { "SameSite=Lax", INTERNET_COOKIE_SAME_SITE_LAX },
        { "SameSite=None", 0 },
        { "SameSite=bogus", 0 },
        { "SameSite", 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("ss"), "/");
        char d[128]; snprintf(d, sizeof d, "ss=1; %s", t[i].attr);
        BOOL r = ck_set(u, NULL, d);
        ck2 c; DWORD e = ex2_get(u, NULL, 0, &c);
        DWORD got = c.flags & (INTERNET_COOKIE_SAME_SITE_STRICT | INTERNET_COOKIE_SAME_SITE_LAX);
        CHECKF(r && e == 0 && c.count == 1 && got == t[i].want, "case %u '%s': r=%d e=%lu n=%lu flags=0x%lx want samesite 0x%lx", (unsigned)i, t[i].attr, r, e, c.count, c.flags, t[i].want);
        ck_cleanup();
    }
}
TEST(ck_ex2_host_only_flag) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("ex2hostonly"), "/");
    EXPECT_EQ(ck_setx(u, NULL, "h=1", INTERNET_COOKIE_APPLY_HOST_ONLY, NULL), COOKIE_STATE_ACCEPT);
    ck2 c; EXPECT_EQ(ex2_get(u, NULL, 0, &c), 0);
    t_note("ex2 host-only flags=0x%lx", c.flags);
    CHECK(c.flags & INTERNET_COOKIE_HOST_ONLY);
    const char *u2 = ck_url(ck_host("ex2nohostonly"), "/");
    EXPECT_EQ(ck_setx(u2, NULL, "h=1", 0, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_EQ(ex2_get(u2, NULL, 0, &c), 0);
    t_note("ex2 default flags=0x%lx", c.flags);
    CHECK(!(c.flags & INTERNET_COOKIE_HOST_ONLY));
    ck_cleanup();
}
TEST(ck_ex2_domain_attr_view) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ex2dom");
    char sub[300]; snprintf(sub, sizeof sub, "www.%s", h);
    char d[400]; snprintf(d, sizeof d, "dd=1; domain=.%s", h);
    EXPECT_EQ(ck_set(ck_url(sub, "/"), NULL, d), TRUE);
    ck2 c; EXPECT_EQ(ex2_get(ck_url(sub, "/"), NULL, 0, &c), 0);
    EXPECT_EQ(c.count, 1);
    t_note("ex2 domain attr: domain='%s' path='%s' flags=0x%lx", c.domain, c.path, c.flags);
    EXPECT_STR(c.domain, h);
    ck_cleanup();
}
TEST(ck_ex2_name_filter_and_counts) {
    REQUIRE_EX2(); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ex2n"), "/");
    ck_set(u, NULL, "a=1"); ck_set(u, NULL, "b=2"); ck_set(u, NULL, "c=3");
    ck2 c;
    EXPECT_EQ(ex2_get(u, NULL, 0, &c), 0); EXPECT_EQ(c.count, 3);
    EXPECT_EQ(ex2_get(u, "b", 0, &c), 0); EXPECT_EQ(c.count, 1); EXPECT_STR(c.value, "2");
    EXPECT_EQ(ex2_get(u, "zz", 0, &c), 0); EXPECT_EQ(c.count, 0);
    ck_cleanup();
}
TEST(ck_ex2_none_is_success_zero) {
    REQUIRE_EX2();
    ck2 c; DWORD r = ex2_get(ck_url(ck_host("ex2none"), "/"), NULL, 0, &c);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(c.count, 0);
}
TEST(ck_ex2_invalid_args) {
    REQUIRE_EX2();
    INTERNET_COOKIE2 *arr = (INTERNET_COOKIE2 *)1; DWORD n = 5;
    EXPECT_EQ(UN(InternetGetCookieEx2)(NULL, NULL, 0, &arr, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(ck_url(ck_host("e2a"), "/")), NULL, 0, NULL, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(ck_url(ck_host("e2b"), "/")), NULL, 0, &arr, NULL), ERROR_INVALID_PARAMETER);
    /* flag mask 0xdfb9efef: anything outside THIRD_PARTY|NON_SCRIPT|0x40000|SAME_SITE_LEVEL_CROSS_SITE|ALL_COOKIES is 87 */
    static const DWORD bad[] = { 0x1, 0x2, 0x20, 0x40, 0x80, 0x2000, 0x4000, 0x8000, 0x80000, 0x100000, 0x200000, 0x40000000, 0x80000000 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        arr = NULL; n = 0;
        DWORD r = UN(InternetGetCookieEx2)(ck_w(ck_url(ck_host("e2f"), "/")), NULL, bad[i], &arr, &n);
        CHECKF(r == ERROR_INVALID_PARAMETER, "flag 0x%lx -> %lu", bad[i], r);
        if (r == 0 && arr) UN(InternetFreeCookies)(arr, n);
    }
    static const DWORD good[] = { 0, INTERNET_COOKIE_THIRD_PARTY, INTERNET_COOKIE_NON_SCRIPT, 0x40000, INTERNET_COOKIE_SAME_SITE_LEVEL_CROSS_SITE };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        arr = NULL; n = 0;
        DWORD r = UN(InternetGetCookieEx2)(ck_w(ck_url(ck_host("e2g"), "/")), NULL, good[i], &arr, &n);
        CHECKF(r == 0 && n == 0, "flag 0x%lx -> %lu n=%lu", good[i], r, n);
        if (arr) UN(InternetFreeCookies)(arr, n);
    }
}
TEST(ck_ex2_all_cookies_requires_empty_url) {
    REQUIRE_EX2();
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(ck_url(ck_host("e2all"), "/")), NULL, 0x20000000, &arr, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(InternetGetCookieEx2)(L"", NULL, 0x20000000 | INTERNET_COOKIE_NON_SCRIPT, &arr, &n), ERROR_INVALID_PARAMETER);
}
TEST(ck_ex2_free_null_ok) {
    REQUIRE(UN(InternetFreeCookies));
    UN(InternetFreeCookies)(NULL, 0);
    UN(InternetFreeCookies)(NULL, 3);
    CHECK(1);
}
TEST(ck_ex2_set_basic) {
    REQUIRE(UN(InternetSetCookieEx2)); REQUIRE_EX2();
    const char *h = ck_host("s2");
    const char *u = ck_url(h, "/");
    ck_track(u, "s2n", NULL, 0);
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c);
    c.pwszName = (PWSTR)L"s2n"; c.pwszValue = (PWSTR)L"s2v"; c.pwszPath = (PWSTR)L"/";
    DWORD st = 99;
    DWORD r = UN(InternetSetCookieEx2)(ck_w(u), &c, NULL, 0, &st);
    t_note("InternetSetCookieEx2: r=%lu state=%lu", r, st);
    EXPECT_EQ(r, 0);
    EXPECT_EQ(st, COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "s2n=s2v");
    ck_cleanup();
}
TEST(ck_ex2_set_invalid_args) {
    REQUIRE(UN(InternetSetCookieEx2));
    INTERNET_COOKIE2 c; memset(&c, 0, sizeof c); c.pwszName = (PWSTR)L"n"; c.pwszValue = (PWSTR)L"v";
    DWORD st = 0;
    EXPECT_EQ(UN(InternetSetCookieEx2)(NULL, &c, NULL, 0, &st), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(InternetSetCookieEx2)(ck_w(ck_url(ck_host("s2i"), "/")), NULL, NULL, 0, &st), ERROR_INVALID_PARAMETER);
    DWORD r = UN(InternetSetCookieEx2)(ck_w(ck_url(ck_host("s2j"), "/")), &c, NULL, 0, NULL);
    t_note("InternetSetCookieEx2 NULL state: r=%lu", r);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ attribute names */
TEST(ck_attr_names_case_insensitive) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("aci");
    ck_set(ck_url(h, "/"), NULL, "p1=1; PATH=/up/");
    ck_set(ck_url(h, "/"), NULL, "p2=1; Path=/up/");
    ck_set(ck_url(h, "/"), NULL, "p3=1; pAtH=/up/");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    const char *got = ck_gets(ck_url(h, "/up/"), NULL, 0);
    CHECKF(ck_count(got) == 3 && ck_has(got, "p1=1") && ck_has(got, "p2=1") && ck_has(got, "p3=1"), "got '%s'", got);
    ck_cleanup();
}
TEST(ck_attr_secure_case_and_spacing) {
    REQUIRE(U(InternetSetCookieA));
    static const char *v[] = { "s=1; secure", "s=1; Secure", "s=1;SECURE", "s=1; secure ;", "s=1;\tsecure" };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        const char *h = ck_host("secc");
        ck_set(ck_surl(h, "/"), NULL, v[i]);
        const char *a = ck_gets(ck_url(h, "/"), NULL, 0);
        const char *b = ck_gets(ck_surl(h, "/"), NULL, 0);
        CHECKF(!strcmp(a, "") && !strcmp(b, "s=1"), "case %u '%s': http '%s' https '%s'", (unsigned)i, v[i], a, b);
        ck_cleanup();
    }
}
TEST(ck_attr_httponly_case_variants_rejected_without_flag) {
    REQUIRE(U(InternetSetCookieA));
    static const char *v[] = { "h=1; HttpOnly", "h=1; httponly", "h=1;HTTPONLY", "h=1; httponly; path=/" };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        const char *u = ck_url(ck_host("hoc"), "/");
        SetLastError(0xdeadbeef);
        BOOL r = ck_set(u, NULL, v[i]);
        DWORD e = GetLastError();
        CHECKF(r == FALSE && e == ERROR_INVALID_OPERATION, "case %u '%s': r=%d gle=%lu", (unsigned)i, v[i], r, e);
        ck_cleanup();
    }
}
TEST(ck_attr_httponly_lookalikes_accepted) {
    REQUIRE(U(InternetSetCookieA));
    static const char *v[] = { "h=1; HttpOnlyX", "h=1; xHttpOnly", "h=HttpOnly", "HttpOnly=1" };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        const char *u = ck_url(ck_host("hol"), "/");
        BOOL r = ck_set(u, NULL, v[i]);
        CHECKF(r == TRUE, "case %u '%s': r=%d gle=%lu", (unsigned)i, v[i], r, GetLastError());
        CHECKF(ck_count(ck_gets(u, NULL, 0)) == 1, "case %u not readable", (unsigned)i);
        ck_cleanup();
    }
}
TEST(ck_attr_version_ignored) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ver"), "/");
    EXPECT_EQ(ck_set(u, NULL, "v=1; Version=1"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "v=1");
    ck_cleanup();
}
TEST(ck_attr_comment_ignored) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("cmt"), "/");
    EXPECT_EQ(ck_set(u, NULL, "v=1; Comment=hello; CommentURL=\"http://x/\"; Discard; Port=\"80\""), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "v=1");
    ck_cleanup();
}
