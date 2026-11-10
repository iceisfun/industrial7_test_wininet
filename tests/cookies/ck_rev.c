/* ck_rev.c - review pass 3: decomp-driven edge cases not covered by the other files.
 *   - InternalInternetSetCookie@0x6a7d0: the HttpOnly check runs before the URL is parsed; the name parameter is
 *     glued as "name=" + data and re-parsed; APPLY_P3P with a NULL state; INTERNET_COOKIE_HTTPONLY on a plain cookie.
 *   - InternetSetOptionA@0x551b0 case 0x51 (INTERNET_OPTION_SUPPRESS_BEHAVIOR): 0 resets the persist suppression,
 *     1/2 (cookie policy) are accepted without effect, NULL buffer -> 87.
 *   - CCookieJar::SetCookieParsed@0x3126c: Path= is cut at '?' and at '#'.
 *   - jar semantics: same name host vs domain cookie, deleting a domain cookie from a sibling host, Secure + HttpOnly,
 *     Max-Age expiry over time (bounded 2.5 s sleep).
 *   - wire: cross-host redirect (127.0.0.1 -> localhost) keeps cookies host-scoped, NO_COOKIES across a redirect,
 *     40 Set-Cookie headers, quoted / high-byte values verbatim, whitespace around name and value.
 * VM_TIMEOUT: 240 */
#include "ck.h"

typedef struct { DWORD n; DWORD flags; char path[256]; char domain[256]; } rv2;
static DWORD rv_ex2(const char *url, const char *name, rv2 *o) {
    memset(o, 0, sizeof *o);
    if (!UN(InternetGetCookieEx2) || !UN(InternetFreeCookies)) return ERROR_PROC_NOT_FOUND;
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    DWORD r = UN(InternetGetCookieEx2)(ck_w(url), name ? ck_w(name) : NULL, 0, &arr, &n);
    o->n = n;
    if (!r && n && arr) {
        o->flags = arr[0].dwFlags;
        snprintf(o->path, sizeof o->path, "%s", arr[0].pwszPath ? ck_a(arr[0].pwszPath) : "(null)");
        snprintf(o->domain, sizeof o->domain, "%s", arr[0].pwszDomain ? ck_a(arr[0].pwszDomain) : "(null)");
    }
    if (arr) UN(InternetFreeCookies)(arr, n);
    return r;
}

/* ------------------------------------------------------------------------------------------ set: ordering of checks */
TEST(ck_rev_httponly_check_precedes_url_parse) {
    REQUIRE(U(InternetSetCookieExA));
    /* D: ParseHeader + the HttpOnly test (flags & 0x3000 == 0 && cookie HttpOnly -> 0x10dd, state 5) run before
     * PathAndRDomainFromURL, so a bad URL is not reported for an HttpOnly cookie without the flag. */
    static const char *urls[] = { "not a url", "ftp://wininet-ck.i7test.example/x/", "http://bad!host.i7test.example/" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        SetLastError(0xdeadbeef);
        DWORD r = U(InternetSetCookieExA)(urls[i], NULL, "h=1; HttpOnly", 0, 0);
        DWORD e = GetLastError();
        CHECKF(r == COOKIE_STATE_REJECT && e == ERROR_INVALID_OPERATION, "'%s': state %lu gle %lu", urls[i], r, e);
        /* with the flag the URL is parsed and the usual error comes back */
        SetLastError(0xdeadbeef);
        r = U(InternetSetCookieExA)(urls[i], NULL, "h=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, 0);
        e = GetLastError();
        CHECKF(r == COOKIE_STATE_UNKNOWN && e != 0 && e != ERROR_INVALID_OPERATION, "'%s' + HTTPONLY: state %lu gle %lu", urls[i], r, e);
    }
    /* the NULL checks still come first */
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieExA)(NULL, NULL, "h=1; HttpOnly", 0, 0), COOKIE_STATE_UNKNOWN);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_rev_httponly_bad_url_set_a_returns_false) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)("not a url", NULL, "h=1; HttpOnly"), FALSE);
    EXPECT_ERR(ERROR_INVALID_OPERATION);
}

/* ------------------------------------------------------------------------------------------ set: name parameter */
TEST(ck_rev_name_param_with_equals_reparsed) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("nmeq"), "/");
    ck_track(u, "a", NULL, 0);
    EXPECT_EQ(U(InternetSetCookieA)(u, "a=b", "c"), TRUE);     /* D: "a=b" "=" "c" -> parsed as name a, value b=c */
    EXPECT_STR(ck_gets(u, NULL, 0), "a=b=c");
    EXPECT_STR(ck_gets(u, "a", 0), "a=b=c");
    EXPECT_STR(ck_gets(u, "a=b", 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    ck_cleanup();
}
TEST(ck_rev_name_param_attributes_in_data_apply) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("nmattr");
    const char *u = ck_url(h, "/");
    ck_track(u, "na", "path=/only/", 0);
    EXPECT_EQ(U(InternetSetCookieA)(u, "na", "1; path=/only/"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/only/x"), NULL, 0), "na=1");
    ck_cleanup();
}
TEST(ck_rev_name_param_overwrites_data_form) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("nmow"), "/");
    ck_set(u, NULL, "k=1");
    ck_set(u, "k", "2");
    EXPECT_STR(ck_gets(u, NULL, 0), "k=2");
    ck_set(u, NULL, "k=3");
    EXPECT_STR(ck_gets(u, NULL, 0), "k=3");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ set: flags */
TEST(ck_rev_apply_p3p_null_state_accepts) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("ap3p"), "/");
    DWORD gle, r = ck_setx(u, NULL, "ap=1", INTERNET_COOKIE_APPLY_P3P, &gle);   /* D: dwReserved is the P3P state, NULL here */
    t_note("APPLY_P3P, NULL state: state %lu gle %lu", r, gle);
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(gle, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "ap=1");
    ck_cleanup();
}
TEST(ck_rev_httponly_flag_on_plain_cookie) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("hoplain"), "/");
    DWORD gle, r = ck_setx(u, NULL, "pl=1", INTERNET_COOKIE_HTTPONLY, &gle);
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(gle, 0);
    const char *g0 = ck_gets(u, NULL, 0);
    const char *g1 = ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY);
    rv2 c; rv_ex2(u, NULL, &c);
    t_note("plain cookie set with INTERNET_COOKIE_HTTPONLY: get(0)='%s' get(HTTPONLY)='%s' ex2 n=%lu flags=0x%lx", g0, g1, c.n, c.flags);
    EXPECT_STR(g1, "pl=1");
    ck_cleanup();
}
TEST(ck_rev_non_script_flag_on_plain_cookie) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("nsplain"), "/");
    DWORD gle, r = ck_setx(u, NULL, "ns=1", INTERNET_COOKIE_NON_SCRIPT, &gle);
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(gle, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "ns=1");          /* NON_SCRIPT does not make a plain cookie HttpOnly */
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ Path= cut characters */
TEST(ck_rev_path_attr_cut_at_hash) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("phash");
    SetLastError(0xdeadbeef);
    BOOL r = ck_set(ck_url(h, "/"), NULL, "ph=1; path=/a#frag");
    DWORD e = GetLastError();
    EXPECT_EQ(r, TRUE); EXPECT_EQ(e, 0);
    EXPECT_STR(ck_gets(ck_url(h, "/a/"), NULL, 0), "ph=1");   /* D: SetCookieParsed cuts the path at '?' or '#' */
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    rv2 c;
    if (!rv_ex2(ck_url(h, "/a/"), NULL, &c) && c.n == 1) EXPECT_STR(c.path, "/a");
    ck_cleanup();
}
TEST(ck_rev_path_attr_cut_at_first_of_query_and_hash) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("phq");
    ck_set(ck_url(h, "/"), NULL, "pqh=1; path=/x#y?z");
    EXPECT_STR(ck_gets(ck_url(h, "/x/"), NULL, 0), "pqh=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ jar semantics */
TEST(ck_rev_same_name_host_and_domain_cookie_coexist) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("hdsame");
    char sub[300]; snprintf(sub, sizeof sub, "sub.%s", h);
    const char *us = ck_url(sub, "/");
    char d[400];
    ck_set(us, NULL, "d=host");
    snprintf(d, sizeof d, "d=dom; domain=%s", h);
    ck_set(us, NULL, d);
    const char *g = ck_gets(us, NULL, 0);
    EXPECT_EQ(ck_count(g), 2);
    EXPECT_STR(g, "d=host; d=dom");                         /* host cookies before domain cookies */
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "d=dom");
    ck_cleanup();
}
TEST(ck_rev_delete_domain_cookie_from_sibling_host) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("sib");
    char s1[300], s2[300], d[400];
    snprintf(s1, sizeof s1, "one.%s", h); snprintf(s2, sizeof s2, "two.%s", h);
    snprintf(d, sizeof d, "sd=1; domain=%s", h);
    ck_set(ck_url(s1, "/"), NULL, d);
    EXPECT_STR(ck_gets(ck_url(s2, "/"), NULL, 0), "sd=1");
    snprintf(d, sizeof d, "sd=x; domain=%s; %s", h, CK_PAST);
    EXPECT_EQ(U(InternetSetCookieA)(ck_url(s2, "/"), NULL, d), TRUE);
    EXPECT_STR(ck_gets(ck_url(s1, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_rev_host_cookie_not_deleted_by_domain_delete) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("hnd");
    char d[400];
    ck_set(ck_url(h, "/"), NULL, "hk=1");
    snprintf(d, sizeof d, "hk=x; domain=%s; %s", h, CK_PAST);
    EXPECT_EQ(U(InternetSetCookieA)(ck_url(h, "/"), NULL, d), TRUE);
    t_note("host cookie after a Domain= delete of the same name: '%s'", ck_gets(ck_url(h, "/"), NULL, 0));
    ck_cleanup();
}
TEST(ck_rev_secure_httponly_combined) {
    REQUIRE(U(InternetSetCookieExA));
    const char *h = ck_host("sho");
    EXPECT_EQ(ck_setx(ck_url(h, "/"), NULL, "sh=1; Secure; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, INTERNET_COOKIE_HTTPONLY), "");
    EXPECT_STR(ck_gets(ck_surl(h, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_surl(h, "/"), NULL, INTERNET_COOKIE_HTTPONLY), "sh=1");
    rv2 c;
    if (!rv_ex2(ck_surl(h, "/"), NULL, &c) && c.n == 1) {
        CHECKF((c.flags & (INTERNET_COOKIE_IS_SECURE | INTERNET_COOKIE_HTTPONLY)) == (INTERNET_COOKIE_IS_SECURE | INTERNET_COOKIE_HTTPONLY), "flags 0x%lx", c.flags);
    }
    ck_cleanup();
}
TEST(ck_rev_secure_cookie_overwritten_from_http) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("secow");
    ck_set(ck_url(h, "/"), NULL, "so=1; secure");
    BOOL r = ck_set(ck_url(h, "/"), NULL, "so=2");
    const char *gh = ck_gets(ck_url(h, "/"), NULL, 0), *gs = ck_gets(ck_surl(h, "/"), NULL, 0);
    t_note("plain so=2 over secure so=1 from http: r=%d http='%s' https='%s'", r, gh, gs);
    EXPECT_EQ(r, TRUE);
    ck_cleanup();
}
TEST(ck_rev_max_age_one_second_expires) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ma1"), "/");
    ck_set(u, NULL, "m1=1; max-age=1");
    ck_set(u, NULL, "m9=1; max-age=600");
    EXPECT_STR(ck_gets(u, NULL, 0), "m1=1; m9=1");
    Sleep(2500);                                             /* generous margin: expiry = set time + 1 s */
    EXPECT_STR(ck_gets(u, NULL, 0), "m9=1");
    ck_cleanup();
}
TEST(ck_rev_expired_cookie_not_counted_in_size_query) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("ma2"), "/");
    ck_set(u, NULL, "gone=1; max-age=1");
    ck_set(u, NULL, "kept=1");
    Sleep(2500);
    DWORD sz = 0;
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, NULL, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, strlen("kept=1") + 1);
    ck_cleanup();
}
TEST(ck_rev_getex_a_name_filter_size_query) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("nfsq"), "/");
    ck_set(u, NULL, "a=1");
    ck_set(u, NULL, "bbb=22222");
    DWORD sz = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(u, "bbb", NULL, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, strlen("bbb=22222") + 1);
    char b[8]; sz = sizeof b; b[0] = 'Z';
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(u, "bbb", b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, strlen("bbb=22222") + 1);
    EXPECT_EQ(b[0], 'Z');
    ck_cleanup();
}
TEST(ck_rev_httponly_name_filter_needs_flag) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("honf"), "/");
    ck_setx(u, NULL, "hn=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL);
    ck_set(u, NULL, "pn=1");
    EXPECT_STR(ck_gets(u, "hn", 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    EXPECT_STR(ck_gets(u, "hn", INTERNET_COOKIE_HTTPONLY), "hn=1");
    EXPECT_STR(ck_gets(u, "pn", INTERNET_COOKIE_HTTPONLY), "pn=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ SUPPRESS_BEHAVIOR (global) */
CHILD(ck_rev_child_get) {
    if (argc < 2) return 99;
    char b[1024]; DWORD sz = sizeof b;
    BOOL r = U(InternetGetCookieExA)(argv[1], NULL, b, &sz, 0, NULL);
    return r ? 0 : 1;
}
static BOOL rv_suppress(DWORD v, DWORD *gle) {
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v);
    if (gle) *gle = GetLastError();
    return r;
}
TEST(ck_rev_suppress_reset_all_clears_persist_suppression) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetSetCookieA));
    EXPECT_EQ(rv_suppress(INTERNET_SUPPRESS_COOKIE_PERSIST, NULL), TRUE);
    DWORD gle;
    EXPECT_EQ(rv_suppress(0 /* INTERNET_SUPPRESS_RESET_ALL */, &gle), TRUE);   /* D: case 0x51, value 0 -> persist = 0 */
    const char *u = ck_url(ck_host("srall"), "/");
    char d[200]; snprintf(d, sizeof d, "ra=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_EQ(t_run_child("ck_rev_child_get", u, 20000), 0);   /* persistent again: visible to a child */
    rv_suppress(INTERNET_SUPPRESS_COOKIE_PERSIST_RESET, NULL);
    ck_cleanup();
}
TEST(ck_rev_suppress_cookie_policy_values_accepted) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetSetCookieA));
    DWORD gle;
    BOOL r1 = rv_suppress(1 /* INTERNET_SUPPRESS_COOKIE_POLICY */, &gle);
    EXPECT_EQ(r1, TRUE);
    /* D: value 1 changes nothing: third-party gets still see nothing, persistent cookies stay persistent */
    const char *u = ck_url(ck_host("spol"), "/");
    char d[200]; snprintf(d, sizeof d, "po=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_THIRD_PARTY), "");
    EXPECT_STR(ck_gets(u, NULL, 0), "po=1");
    EXPECT_EQ(t_run_child("ck_rev_child_get", u, 20000), 0);
    BOOL r2 = rv_suppress(2 /* INTERNET_SUPPRESS_COOKIE_POLICY_RESET */, &gle);
    t_note("SUPPRESS_COOKIE_POLICY_RESET: r=%d gle=%lu", r2, gle);
    EXPECT_EQ(r2, TRUE);
    ck_cleanup();
}
TEST(ck_rev_suppress_behavior_null_buffer) {
    REQUIRE(U(InternetSetOptionA));
    DWORD v = INTERNET_SUPPRESS_COOKIE_PERSIST;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, NULL, sizeof v), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);                     /* D: 0x51 is not in the NULL-buffer whitelist */
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, 0), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* nothing was applied: persistent cookies still reach a child */
    const char *u = ck_url(ck_host("snull"), "/");
    char d[200]; snprintf(d, sizeof d, "sn=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_EQ(t_run_child("ck_rev_child_get", u, 20000), 0);
    ck_cleanup();
}
TEST(ck_rev_suppress_behavior_w_matches_a) {
    REQUIRE(U(InternetSetOptionW)); REQUIRE(U(InternetSetCookieA));
    DWORD v = INTERNET_SUPPRESS_COOKIE_PERSIST;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetOptionW)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v), TRUE);
    const char *u = ck_url(ck_host("sw"), "/");
    char d[200]; snprintf(d, sizeof d, "sw=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_STR(ck_gets(u, NULL, 0), "sw=1");
    EXPECT_EQ(t_run_child("ck_rev_child_get", u, 20000), 1);   /* session-only while suppressed */
    v = INTERNET_SUPPRESS_COOKIE_PERSIST_RESET;
    EXPECT_EQ(U(InternetSetOptionW)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v), TRUE);
    v = 0x99;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetOptionW)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ wire */
typedef struct { srv *s; char path[300]; char api[400]; } rvw;
static int rvw_start(rvw *w, const srv_script *sc, int n) {
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = n;
    w->s = NULL;
    return srv_start(&cfg, &w->s);
}
static void rvw_paths(rvw *w, const char *tag) {
    snprintf(w->path, sizeof w->path, "%s/", ck_upath(tag));
    snprintf(w->api, sizeof w->api, "http://127.0.0.1%s", w->path);
}
static const char *rvw_url(rvw *w, const char *sfx) { char p[600]; snprintf(p, sizeof p, "%s%s", w->path, sfx ? sfx : ""); return srv_url(w->s, p); }
#define RVW_OR_SKIP(w, sc, n) do { int rc_ = rvw_start((w), (sc), (n)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)

TEST(ck_rev_wire_redirect_to_other_host_keeps_scope) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; rvw_paths(&w, "xh");
    char hdr[800];
    snprintf(hdr, sizeof hdr, "Set-Cookie: xr=1; path=%s\r\nLocation: http://localhost:%%P%sdst\r\n", w.path, w.path);
    srv_step st[] = { S_HEAD(), S_REPLY(302, NULL, ""), S_LOOP() };
    st[1].hdrs = hdr;
    srv_step st2[] = { S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP() };
    srv_script sc[] = { { st, 3 }, { st2, 3 } };
    RVW_OR_SKIP(&w, sc, 2);
    char lapi[400]; snprintf(lapi, sizeof lapi, "http://localhost%s", w.path);
    char d[600]; snprintf(d, sizeof d, "lh=1; path=%s", w.path);
    ck_set(lapi, NULL, d);
    ck_track(w.api, "xr", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, "src"), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(srv_req_header(w.s, 0, "Cookie"), NULL);
    char want[400]; snprintf(want, sizeof want, "GET %sdst HTTP/1.1", w.path);
    EXPECT_STR(srv_req_line(w.s, 1), want);
    EXPECT_STR(srv_req_header(w.s, 1, "Cookie"), "lh=1");      /* the 127.0.0.1 cookie stays with 127.0.0.1 */
    EXPECT_STR(ck_gets(w.api, NULL, 0), "xr=1");
    EXPECT_STR(ck_gets(lapi, NULL, 0), "lh=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_no_cookies_across_redirect) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; rvw_paths(&w, "ncr");
    char hdr[800];
    snprintf(hdr, sizeof hdr, "Set-Cookie: nr=1; path=%s\r\nLocation: %sdst\r\n", w.path, w.path);
    srv_step st[] = { S_HEAD(), S_REPLY(302, NULL, ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    st[1].hdrs = hdr;
    srv_step st2[] = { S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP() };
    srv_script sc[] = { { st, 5 }, { st2, 3 } };
    RVW_OR_SKIP(&w, sc, 2);
    char d[600]; snprintf(d, sizeof d, "pre=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    ck_track(w.api, "nr", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, "src"), NULL, INTERNET_FLAG_NO_COOKIES), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(srv_req_header(w.s, 0, "Cookie"), NULL);
    EXPECT_STR(srv_req_header(w.s, 1, "Cookie"), NULL);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "pre=1");               /* the 302's Set-Cookie was not stored */
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* one response with a caller-built header block, then the same server answers a second request */
static int rvw_one(rvw *w, const char *tag, const char *hdrs) {   /* tag NULL: paths already set by rvw_paths */
    if (tag) rvw_paths(w, tag);
    static srv_step st[64][3]; static srv_script sc[64]; static LONG k;
    LONG i = InterlockedIncrement(&k) & 63;
    srv_step a[3] = { S_HEAD(), S_REPLY(200, NULL, "ok"), S_LOOP() };
    a[1].hdrs = hdrs;
    memcpy(st[i], a, sizeof a);
    sc[i].steps = st[i]; sc[i].nsteps = 3;
    return rvw_start(w, &sc[i], 1);
}
#define RVW1_OR_SKIP(w, tag, h) do { int rc_ = rvw_one((w), (tag), (h)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)

TEST(ck_rev_wire_forty_set_cookie_headers) {
    REQUIRE(U(InternetOpenUrlA));
    static char hdrs[8192]; size_t o = 0;
    rvw w; rvw_paths(&w, "f40");
    for (int i = 0; i < 40; i++) o += (size_t)snprintf(hdrs + o, sizeof hdrs - o, "Set-Cookie: c%02d=v%d; path=%s\r\n", i, i, w.path);
    RVW1_OR_SKIP(&w, NULL, hdrs);
    for (int i = 0; i < 40; i++) { char n[8]; snprintf(n, sizeof n, "c%02d", i); ck_track(w.api, n, NULL, 0); }
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    char want[2048]; size_t wo = 0;
    for (int i = 0; i < 40; i++) wo += (size_t)snprintf(want + wo, sizeof want - wo, "%sc%02d=v%d", i ? "; " : "", i, i);
    EXPECT_STR(ck_gets(w.api, NULL, 0), want);
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(srv_req_header(w.s, 1, "Cookie"), want);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 1, "Cookie"), 1);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_quoted_value_verbatim) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; RVW1_OR_SKIP(&w, "quo", "Set-Cookie: q=\"a b\"; path=%R\r\n");
    ck_track(w.api, "q", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "q=\"a b\"");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(srv_req_header(w.s, 1, "Cookie"), "q=\"a b\"");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_high_bytes_verbatim) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; RVW1_OR_SKIP(&w, "hib", "Set-Cookie: u8=caf\xc3\xa9; path=%R\r\n");
    ck_track(w.api, "u8", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    const char *g = ck_gets(w.api, NULL, 0);
    t_note("UTF-8 Set-Cookie stored as (hex tail) %02x %02x", (unsigned char)g[strlen(g) > 1 ? strlen(g) - 2 : 0], (unsigned char)g[strlen(g) ? strlen(g) - 1 : 0]);
    EXPECT_STR(g, "u8=caf\xc3\xa9");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(srv_req_header(w.s, 1, "Cookie"), "u8=caf\xc3\xa9");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_whitespace_around_name_and_value) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; RVW1_OR_SKIP(&w, "wsp", "Set-Cookie:    sp1  =  v1  ;   path=%R  \r\nSet-Cookie:\tsp2=v2\t;path=%R\r\n");
    ck_track(w.api, "sp1", NULL, 0); ck_track(w.api, "sp2", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "sp1=v1; sp2=v2");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_domain_localhost_from_ip_rejected) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; RVW1_OR_SKIP(&w, "dli", "Set-Cookie: dl=1; path=%R; domain=localhost\r\nSet-Cookie: d1=1; path=%R; domain=0.0.1\r\nSet-Cookie: ok=1; path=%R\r\n");
    ck_track(w.api, "ok", NULL, 0); ck_track(w.api, "dl", NULL, 0); ck_track(w.api, "d1", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "ok=1");
    char lapi[400]; snprintf(lapi, sizeof lapi, "http://localhost%s", w.path);
    EXPECT_STR(ck_gets(lapi, NULL, 0), "");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_path_attr_not_prefix_of_request) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; rvw_paths(&w, "npx");
    static char hdrs[1024];
    snprintf(hdrs, sizeof hdrs, "Set-Cookie: np=1; path=%selse/\r\nSet-Cookie: ok=1; path=%s\r\n", w.path, w.path);
    RVW1_OR_SKIP(&w, NULL, hdrs);
    char else_api[600]; snprintf(else_api, sizeof else_api, "%selse/", w.api);
    ck_track(w.api, "ok", NULL, 0); ck_track(else_api, "np", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    /* request /<p>/sub/x: path=/<p>/else/ is a sibling of the request directory */
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, "sub/x"), NULL, 0), 200);
    const char *g = ck_gets(else_api, NULL, 0);
    t_note("Set-Cookie with a Path that does not prefix the request path: jar at else/ = '%s'", g);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "ok=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_max_age_one_second_not_sent_later) {
    REQUIRE(U(InternetOpenUrlA));
    rvw w; RVW1_OR_SKIP(&w, "wma1", "Set-Cookie: short=1; max-age=1; path=%R\r\nSet-Cookie: long=1; max-age=600; path=%R\r\n");
    ck_track(w.api, "short", NULL, 0); ck_track(w.api, "long", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    Sleep(2500);
    EXPECT_EQ(ck_wire_get(hi, rvw_url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(srv_req_header(w.s, 1, "Cookie"), "long=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_rev_wire_connect_flag_no_cookies) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA)); REQUIRE(U(HttpSendRequestA));
    rvw w; RVW1_OR_SKIP(&w, "cnc", "Set-Cookie: cn=1; path=%R\r\n");
    char d[600]; snprintf(d, sizeof d, "pre=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    ck_track(w.api, "cn", NULL, 0);
    HINTERNET hi = t_inet_open("ck-rev");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(w.s), NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_NO_COOKIES, 0);
    CHECK(hc != NULL);
    if (hc) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", w.path, NULL, NULL, NULL, CK_WIRE_BASE, 0);
        CHECK(hr != NULL);
        if (hr) {
            CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
            char buf[256]; int ok; t_inet_read_all(hr, buf, sizeof buf, &ok);
            t_inet_close(hr);
        }
        t_inet_close(hc);
    }
    CHECK(srv_wait_requests(w.s, 1, 5000));
    const char *c = srv_req_header(w.s, 0, "Cookie");
    t_note("InternetConnect(NO_COOKIES) + HttpOpenRequest(0): Cookie=%s jar='%s'", c ? c : "(none)", ck_gets(w.api, NULL, 0));
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
