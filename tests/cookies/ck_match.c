/* ck_match.c - which stored cookies a URL sees: host / domain matching (Domain=, host-only, IP literals,
 * localhost), path matching, Secure, HttpOnly + INTERNET_COOKIE_HTTPONLY / NON_SCRIPT, SameSite + cross-site get,
 * ordering of the returned list, replacement and duplicates, deletion, the 180-per-domain limit, and the
 * process-wide jar (two InternetOpen sessions, a child process).
 * Decomp: InternalInternetGetCookieEx2@0x83820 (match loop), CCookieJar::SetCookieParsed@0x3126c,
 * IsDomainLegal@0x320ac, CCookieJar::EnforceCookieLimits@0x31f9c (0xb3 < count), PathAndRDomainFromURL@0x5fe30.
 * VM_TIMEOUT: 120 */
#include "ck.h"

/* sub.host helper */
static const char *sub(const char *label, const char *host) { static char b[8][300]; static int i; char *r = b[i++ & 7]; snprintf(r, 300, "%s.%s", label, host); return r; }

/* ------------------------------------------------------------------------------------------ domains */
TEST(ck_dom_default_no_domain_visibility) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dnd");
    ck_set(ck_url(h, "/"), NULL, "d=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "d=1");
    const char *s = ck_gets(ck_url(sub("www", h), "/"), NULL, 0);
    t_note("cookie without Domain= set on host, read from www.host: '%s'", s);
    EXPECT_STR(s, "d=1");                                                  /* not host-only unless APPLY_HOST_ONLY */
    EXPECT_STR(ck_gets(ck_url(sub("a.b", h), "/"), NULL, 0), "d=1");
    const char *parent = strchr(h, '.') + 1;                                 /* i7test.example */
    EXPECT_STR(ck_gets(ck_url(parent, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_dom_apply_host_only) {
    REQUIRE(U(InternetSetCookieExA));
    const char *h = ck_host("dho");
    EXPECT_EQ(ck_setx(ck_url(h, "/"), NULL, "ho=1", INTERNET_COOKIE_APPLY_HOST_ONLY, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "ho=1");
    EXPECT_STR(ck_gets(ck_url(sub("www", h), "/"), NULL, 0), "");
    ck_cleanup();
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
}
TEST(ck_dom_apply_host_only_ignored_with_domain_attr) {
    REQUIRE(U(InternetSetCookieExA));
    const char *h = ck_host("dhod");
    char d[300]; snprintf(d, sizeof d, "hod=1; domain=%s", h);
    EXPECT_EQ(ck_setx(ck_url(h, "/"), NULL, d, INTERNET_COOKIE_APPLY_HOST_ONLY, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(ck_url(sub("www", h), "/"), NULL, 0), "hod=1");
    ck_cleanup();
}
TEST(ck_dom_parent_domain_attr) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dpar");
    char d[300]; snprintf(d, sizeof d, "pd=1; domain=%s", h);
    EXPECT_EQ(ck_set(ck_url(sub("www", h), "/"), NULL, d), TRUE);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "pd=1");
    EXPECT_STR(ck_gets(ck_url(sub("www", h), "/"), NULL, 0), "pd=1");
    EXPECT_STR(ck_gets(ck_url(sub("other", h), "/"), NULL, 0), "pd=1");
    EXPECT_STR(ck_gets(ck_url(sub("x.y", h), "/"), NULL, 0), "pd=1");
    ck_cleanup();
}
TEST(ck_dom_leading_dot_equivalent) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ddot");
    char d[300]; snprintf(d, sizeof d, "dot=1; domain=.%s", h);
    EXPECT_EQ(ck_set(ck_url(sub("www", h), "/"), NULL, d), TRUE);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "dot=1");
    EXPECT_STR(ck_gets(ck_url(sub("other", h), "/"), NULL, 0), "dot=1");
    /* the same cookie without the dot replaces it (same domain key) */
    char d2[300]; snprintf(d2, sizeof d2, "dot=2; domain=%s", h);
    EXPECT_EQ(ck_set(ck_url(sub("www", h), "/"), NULL, d2), TRUE);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "dot=2");
    ck_cleanup();
}
TEST(ck_dom_domain_attr_case_insensitive) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dcase");
    char up[300]; snprintf(up, sizeof up, "%s", h); for (char *p = up; *p; p++) *p = (char)toupper((unsigned char)*p);
    char d[400]; snprintf(d, sizeof d, "dc=1; domain=%s", up);
    BOOL r = ck_set(ck_url(sub("www", h), "/"), NULL, d);
    t_note("upper-case Domain=: r=%d gle=%lu", r, GetLastError());
    EXPECT_EQ(r, TRUE);
    EXPECT_STR(ck_gets(ck_url(sub("z", h), "/"), NULL, 0), "dc=1");
    ck_cleanup();
}
TEST(ck_dom_unrelated_domain_rejected) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dunrel"), *o = ck_host("dother");
    char d[300]; snprintf(d, sizeof d, "x=1; domain=%s", o);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(ck_set(ck_url(h, "/"), NULL, d), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_STR(ck_gets(ck_url(o, "/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_dom_child_domain_rejected) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dchild");
    char d[300]; snprintf(d, sizeof d, "x=1; domain=www.%s", h);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(ck_set(ck_url(h, "/"), NULL, d), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_STR(ck_gets(ck_url(sub("www", h), "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_dom_tld_rejected) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dtld");
    SetLastError(0xdeadbeef);
    EXPECT_EQ(ck_set(ck_url(h, "/"), NULL, "x=1; domain=example"), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(ck_set(ck_url(h, "/"), NULL, "x=1; domain=.example"), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ck_cleanup();
}
TEST(ck_dom_registrable_parent_accepted) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dreg");                      /* wininet...dreg.i7test.example */
    BOOL r = ck_set(ck_url(h, "/"), NULL, "reg=1; domain=i7test.example");
    t_note("Domain=i7test.example from %s: r=%d gle=%lu", h, r, GetLastError());
    EXPECT_EQ(r, TRUE);
    /* visible to a sibling host: clean it up immediately, it is shared by every host of this suffix */
    EXPECT_STR(ck_gets(ck_url(ck_host("dsib"), "/"), "reg", 0), "reg=1");
    ck_cleanup();
    EXPECT_STR(ck_gets(ck_url(h, "/"), "reg", 0), "");
}
TEST(ck_dom_suffix_not_label_boundary) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("dsfx");
    ck_set(ck_url(h, "/"), NULL, "sfx=1");
    char evil[300]; snprintf(evil, sizeof evil, "evil%s", h);   /* same suffix, different label */
    EXPECT_STR(ck_gets(ck_url(evil, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_dom_ip_literal_exact) {
    REQUIRE(U(InternetSetCookieA));
    const char *p = ck_upath("ip");
    char pp[300]; snprintf(pp, sizeof pp, "%s/", p);
    char d[400]; snprintf(d, sizeof d, "ip=1; path=%s", pp);
    EXPECT_EQ(ck_set(ck_url("127.0.0.1", pp), NULL, d), TRUE);
    EXPECT_STR(ck_gets(ck_url("127.0.0.1", pp), NULL, 0), "ip=1");
    EXPECT_STR(ck_gets(ck_url("127.0.0.2", pp), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url("localhost", pp), NULL, 0), "");
    char d2[300]; snprintf(d2, sizeof d2, "http://127.0.0.1:8080%s", pp);
    EXPECT_STR(ck_gets(d2, NULL, 0), "ip=1");                       /* not port-scoped */
    ck_cleanup();
}
TEST(ck_dom_ip_domain_attr_exact_only) {
    REQUIRE(U(InternetSetCookieA));
    const char *p = ck_upath("ipd");
    char pp[300]; snprintf(pp, sizeof pp, "%s/", p);
    char d[400]; snprintf(d, sizeof d, "ipd=1; path=%s; domain=127.0.0.1", pp);
    EXPECT_EQ(ck_set(ck_url("127.0.0.1", pp), NULL, d), TRUE);
    EXPECT_STR(ck_gets(ck_url("127.0.0.1", pp), NULL, 0), "ipd=1");
    snprintf(d, sizeof d, "ipx=1; path=%s; domain=0.0.1", pp);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(ck_set(ck_url("127.0.0.1", pp), NULL, d), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ck_cleanup();
}
TEST(ck_dom_localhost) {
    REQUIRE(U(InternetSetCookieA));
    const char *p = ck_upath("lh");
    char pp[300]; snprintf(pp, sizeof pp, "%s/", p);
    char d[400]; snprintf(d, sizeof d, "lh=1; path=%s", pp);
    EXPECT_EQ(ck_set(ck_url("localhost", pp), NULL, d), TRUE);
    EXPECT_STR(ck_gets(ck_url("localhost", pp), NULL, 0), "lh=1");
    EXPECT_STR(ck_gets(ck_url("LOCALHOST", pp), NULL, 0), "lh=1");
    EXPECT_STR(ck_gets(ck_url("127.0.0.1", pp), NULL, 0), "");
    snprintf(d, sizeof d, "lhd=1; path=%s; domain=localhost", pp);
    BOOL r = ck_set(ck_url("localhost", pp), NULL, d);
    t_note("Domain=localhost on localhost: r=%d gle=%lu", r, GetLastError());
    ck_cleanup();
}
TEST(ck_dom_ipv6_literal) {
    REQUIRE(U(InternetSetCookieA));
    const char *p = ck_upath("v6");
    char pp[300]; snprintf(pp, sizeof pp, "%s/", p);
    char d[400]; snprintf(d, sizeof d, "v6=1; path=%s", pp);
    BOOL r = ck_set(ck_url("[::1]", pp), NULL, d);
    t_note("[::1]: set r=%d gle=%lu get='%s'", r, GetLastError(), ck_gets(ck_url("[::1]", pp), NULL, 0));
    EXPECT_EQ(r, TRUE);
    EXPECT_STR(ck_gets(ck_url("[::1]", pp), NULL, 0), "v6=1");
    EXPECT_STR(ck_gets(ck_url("127.0.0.1", pp), NULL, 0), "");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ paths */
TEST(ck_path_attr_prefix_table) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ptab");
    ck_set(ck_url(h, "/"), NULL, "pa=1; path=/a");
    static const struct { const char *path; int vis; } t[] = {
        { "/", 0 }, { "/a", 0 }, { "/a/", 1 }, { "/a/b", 1 }, { "/a/b/c", 1 }, { "/ab/", 1 }, { "/abc/x", 1 }, { "/b/a/", 0 },
        { "/A/", 0 }, { "/a?x", 0 }, { "/a/?x", 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *g = ck_gets(ck_url(h, t[i].path), NULL, 0);
        int vis = !strcmp(g, "pa=1");
        CHECKF(vis == t[i].vis, "Path=/a, get %s: visible=%d want %d ('%s')", t[i].path, vis, t[i].vis, g);
    }
    ck_cleanup();
}
TEST(ck_path_attr_trailing_slash_table) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ptab2");
    ck_set(ck_url(h, "/"), NULL, "ps=1; path=/a/");
    static const struct { const char *path; int vis; } t[] = {
        { "/", 0 }, { "/a", 0 }, { "/a/", 1 }, { "/a/x", 1 }, { "/a/x/y", 1 }, { "/ab/", 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *g = ck_gets(ck_url(h, t[i].path), NULL, 0);
        int vis = !strcmp(g, "ps=1");
        CHECKF(vis == t[i].vis, "Path=/a/, get %s: visible=%d want %d ('%s')", t[i].path, vis, t[i].vis, g);
    }
    ck_cleanup();
}
TEST(ck_path_root_visible_everywhere) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("proot");
    ck_set(ck_url(h, "/deep/er/"), NULL, "r=1; path=/");
    static const char *p[] = { "/", "/x", "/deep/", "/deep/er/page", "/a/b/c/d/" };
    for (size_t i = 0; i < 5; i++) EXPECT_STR(ck_gets(ck_url(h, p[i]), NULL, 0), "r=1");
    ck_cleanup();
}
TEST(ck_path_default_from_url_table) {
    REQUIRE(U(InternetSetCookieA));
    /* set URL -> where the cookie (no Path=) is visible */
    static const struct { const char *set; const char *get; int vis; } t[] = {
        { "/d1/d2/page", "/d1/d2/", 1 },
        { "/d1/d2/page", "/d1/", 0 },
        { "/d1/d2/page", "/", 0 },
        { "/d1/d2/", "/d1/d2/", 1 },
        { "/d1/d2/", "/d1/", 0 },
        { "/d1/d2", "/d1/", 1 },
        { "/d1/d2", "/", 0 },
        { "/", "/", 1 },
        { "/", "/any/", 1 },
        { "/page", "/", 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *h = ck_host("pdef");
        ck_set(ck_url(h, t[i].set), NULL, "dp=1");
        const char *g = ck_gets(ck_url(h, t[i].get), NULL, 0);
        int vis = !strcmp(g, "dp=1");
        CHECKF(vis == t[i].vis, "case %u set at %s, get %s: visible=%d want %d ('%s')", (unsigned)i, t[i].set, t[i].get, vis, t[i].vis, g);
        ck_cleanup();
    }
}
TEST(ck_path_default_ex2_view) {
    REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(UN(InternetFreeCookies));
    static const char *setp[] = { "/d1/d2/page", "/d1/d2/", "/d1/d2", "/page", "/" };
    for (int i = 0; i < 5; i++) {
        const char *h = ck_host("pdefx");
        ck_set(ck_url(h, setp[i]), NULL, "dx=1");
        INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
        DWORD r = UN(InternetGetCookieEx2)(ck_w(ck_url(h, "/d1/d2/x/")), NULL, 0, &arr, &n);
        t_note("default path for set at %s: r=%lu n=%lu path=%s", setp[i], r, n, (n && arr) ? ck_a(arr[0].pwszPath) : "-");
        if (arr) UN(InternetFreeCookies)(arr, n);
        ck_cleanup();
    }
    CHECK(1);
}
TEST(ck_path_attr_without_slash_rejected) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("pnoslash");
    SetLastError(0xdeadbeef);
    BOOL r = ck_set(ck_url(h, "/"), NULL, "ns=1; path=abc");
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    ck_cleanup();
}
TEST(ck_path_attr_empty_value) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("pempty");
    BOOL r = ck_set(ck_url(h, "/x/y/"), NULL, "pe=1; path=");
    t_note("path= (empty) r=%d gle=%lu; / '%s' /x/ '%s' /x/y/ '%s'", r, GetLastError(), ck_gets(ck_url(h, "/"), NULL, 0),
           ck_gets(ck_url(h, "/x/"), NULL, 0), ck_gets(ck_url(h, "/x/y/"), NULL, 0));
    EXPECT_EQ(r, TRUE);
    ck_cleanup();
}
TEST(ck_path_attr_with_query_char) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("pquery");
    SetLastError(0xdeadbeef);
    BOOL r = ck_set(ck_url(h, "/"), NULL, "pq=1; path=/a?b");
    DWORD e = GetLastError();
    t_note("path=/a?b: r=%d gle=%lu; /a/ '%s'", r, e, ck_gets(ck_url(h, "/a/"), NULL, 0));
    ck_cleanup();
    CHECK(1);
}
TEST(ck_path_case_sensitive) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("pcase");
    ck_set(ck_url(h, "/"), NULL, "pc=1; path=/Mixed/");
    EXPECT_STR(ck_gets(ck_url(h, "/Mixed/"), NULL, 0), "pc=1");
    EXPECT_STR(ck_gets(ck_url(h, "/mixed/"), NULL, 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/MIXED/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_path_same_name_different_paths_coexist) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("pcoex");
    ck_set(ck_url(h, "/"), NULL, "n=root; path=/");
    ck_set(ck_url(h, "/"), NULL, "n=deep; path=/a/");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "n=root");
    const char *g = ck_gets(ck_url(h, "/a/"), NULL, 0);
    CHECKF(ck_count(g) == 2 && ck_has(g, "n=root") && ck_has(g, "n=deep"), "got '%s'", g);
    EXPECT_STR(g, "n=deep; n=root");                   /* longer path first */
    /* deleting one leaves the other */
    ck_set(ck_url(h, "/"), NULL, "n=; path=/a/; " CK_PAST);
    EXPECT_STR(ck_gets(ck_url(h, "/a/"), NULL, 0), "n=root");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ ordering */
TEST(ck_order_same_path_insertion) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ord1"), "/");
    ck_set(u, NULL, "c1=1"); ck_set(u, NULL, "c2=2"); ck_set(u, NULL, "c3=3"); ck_set(u, NULL, "c4=4");
    EXPECT_STR(ck_gets(u, NULL, 0), "c1=1; c2=2; c3=3; c4=4");
    ck_cleanup();
}
TEST(ck_order_reverse_alpha_names_kept_in_insertion) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ord2"), "/");
    ck_set(u, NULL, "zz=1"); ck_set(u, NULL, "mm=2"); ck_set(u, NULL, "aa=3");
    EXPECT_STR(ck_gets(u, NULL, 0), "zz=1; mm=2; aa=3");
    ck_cleanup();
}
TEST(ck_order_replace_keeps_position) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ord3"), "/");
    ck_set(u, NULL, "a=1"); ck_set(u, NULL, "b=2"); ck_set(u, NULL, "c=3");
    ck_set(u, NULL, "a=9");
    const char *g = ck_gets(u, NULL, 0);
    t_note("after replacing first: '%s'", g);
    EXPECT_STR(g, "a=9; b=2; c=3");
    ck_cleanup();
}
TEST(ck_order_delete_then_readd_goes_last) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ord4"), "/");
    ck_set(u, NULL, "a=1"); ck_set(u, NULL, "b=2");
    ck_set(u, NULL, "a=1; " CK_PAST);
    EXPECT_STR(ck_gets(u, NULL, 0), "b=2");
    ck_set(u, NULL, "a=3");
    EXPECT_STR(ck_gets(u, NULL, 0), "b=2; a=3");
    ck_cleanup();
}
TEST(ck_order_longer_path_first) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ordp");
    ck_set(ck_url(h, "/"), NULL, "root=1; path=/");
    ck_set(ck_url(h, "/"), NULL, "deep=1; path=/a/b/");
    ck_set(ck_url(h, "/"), NULL, "mid=1; path=/a/");
    EXPECT_STR(ck_gets(ck_url(h, "/a/b/c"), NULL, 0), "deep=1; mid=1; root=1");
    EXPECT_STR(ck_gets(ck_url(h, "/a/x"), NULL, 0), "mid=1; root=1");
    ck_cleanup();
}
TEST(ck_order_domain_vs_host_cookies) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ordd");
    char d[300]; snprintf(d, sizeof d, "dom=1; domain=%s", h);
    ck_set(ck_url(sub("www", h), "/"), NULL, "host=1");
    ck_set(ck_url(sub("www", h), "/"), NULL, d);
    const char *g = ck_gets(ck_url(sub("www", h), "/"), NULL, 0);
    t_note("host vs domain order: '%s'", g);
    CHECKF(ck_count(g) == 2 && ck_has(g, "host=1") && ck_has(g, "dom=1"), "got '%s'", g);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ replacement / duplicates */
TEST(ck_dup_replace_value) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("dup1"), "/");
    ck_set(u, NULL, "k=1"); ck_set(u, NULL, "k=2"); ck_set(u, NULL, "k=3");
    EXPECT_STR(ck_gets(u, NULL, 0), "k=3");
    ck_cleanup();
}
TEST(ck_dup_names_case_sensitive) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("dup2"), "/");
    ck_set(u, NULL, "k=1"); ck_set(u, NULL, "K=2");
    const char *g = ck_gets(u, NULL, 0);
    t_note("k vs K: '%s'", g);
    EXPECT_STR(g, "k=1; K=2");
    ck_cleanup();
}
TEST(ck_dup_session_replaced_by_persistent) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("dup3"), "/");
    ck_set(u, NULL, "k=s");
    char d[200]; snprintf(d, sizeof d, "k=p; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_STR(ck_gets(u, NULL, 0), "k=p");
    ck_set(u, NULL, "k=s2");
    EXPECT_STR(ck_gets(u, NULL, 0), "k=s2");
    ck_cleanup();
    EXPECT_STR(ck_gets(u, NULL, 0), "");
}
TEST(ck_dup_name_param_vs_data_same_cookie) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("dup4"), "/");
    ck_set(u, "k", "1");
    ck_set(u, NULL, "k=2");
    EXPECT_STR(ck_gets(u, NULL, 0), "k=2");
    ck_cleanup();
}
TEST(ck_dup_nameless_replaced) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("dup5"), "/");
    ck_set(u, NULL, "first");
    ck_set(u, NULL, "second");
    EXPECT_STR(ck_gets(u, NULL, 0), "second");          /* both have the empty name */
    ck_cleanup();
}
TEST(ck_dup_same_value_twice) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("dup6"), "/");
    EXPECT_EQ(ck_setx(u, NULL, "s=1", 0, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_EQ(ck_setx(u, NULL, "s=1", 0, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "s=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ deletion */
TEST(ck_del_requires_same_path) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("delp");
    ck_set(ck_url(h, "/"), NULL, "d=1; path=/a/");
    ck_set(ck_url(h, "/"), NULL, "d=1; path=/; " CK_PAST);      /* different path: no effect */
    EXPECT_STR(ck_gets(ck_url(h, "/a/"), NULL, 0), "d=1");
    ck_set(ck_url(h, "/"), NULL, "d=1; path=/a/; " CK_PAST);
    EXPECT_STR(ck_gets(ck_url(h, "/a/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_del_requires_same_domain) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("deld");
    char d[300]; snprintf(d, sizeof d, "d=1; domain=%s", h);
    ck_set(ck_url(sub("www", h), "/"), NULL, d);
    ck_set(ck_url(sub("www", h), "/"), NULL, "d=1; " CK_PAST);   /* host cookie www.h: different key */
    EXPECT_STR(ck_gets(ck_url(sub("www", h), "/"), NULL, 0), "d=1");
    snprintf(d, sizeof d, "d=1; domain=%s; %s", h, CK_PAST);
    ck_set(ck_url(sub("www", h), "/"), NULL, d);
    EXPECT_STR(ck_gets(ck_url(sub("www", h), "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_del_one_of_many) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("del3"), "/");
    ck_set(u, NULL, "a=1"); ck_set(u, NULL, "b=2"); ck_set(u, NULL, "c=3");
    ck_set(u, NULL, "b=; " CK_PAST);
    EXPECT_STR(ck_gets(u, NULL, 0), "a=1; c=3");
    ck_cleanup();
}
TEST(ck_del_value_irrelevant) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("delv"), "/");
    ck_set(u, NULL, "a=keep");
    ck_set(u, NULL, "a=other; max-age=0");
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ secure */
TEST(ck_secure_set_via_http_url) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("sech");
    BOOL r = ck_set(ck_url(h, "/"), NULL, "sh=1; secure");
    t_note("secure cookie set through an http:// URL: r=%d gle=%lu", r, GetLastError());
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    const char *s = ck_gets(ck_surl(h, "/"), NULL, 0);
    t_note("  visible on https: '%s'", s);
    ck_cleanup();
}
TEST(ck_secure_mixed_list) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("secmix");
    ck_set(ck_surl(h, "/"), NULL, "plain=1");
    ck_set(ck_surl(h, "/"), NULL, "sec=1; secure");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "plain=1");
    EXPECT_STR(ck_gets(ck_surl(h, "/"), NULL, 0), "plain=1; sec=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ httponly */
TEST(ck_httponly_set_flags_table) {
    REQUIRE(U(InternetSetCookieExA));
    static const struct { DWORD flags; DWORD state; DWORD gle; } t[] = {
        { 0, COOKIE_STATE_REJECT, ERROR_INVALID_OPERATION },
        { INTERNET_COOKIE_HTTPONLY, COOKIE_STATE_ACCEPT, 0 },
        { INTERNET_COOKIE_NON_SCRIPT, COOKIE_STATE_ACCEPT, 0 },
        { INTERNET_COOKIE_HTTPONLY | INTERNET_COOKIE_NON_SCRIPT, COOKIE_STATE_ACCEPT, 0 },
        { INTERNET_COOKIE_THIRD_PARTY, COOKIE_STATE_REJECT, ERROR_INVALID_OPERATION },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const char *u = ck_url(ck_host("hotab"), "/");
        DWORD gle, r = ck_setx(u, NULL, "ho=1; HttpOnly", t[i].flags, &gle);
        CHECKF(r == t[i].state && gle == t[i].gle, "flags 0x%lx: state %lu gle %lu want %lu/%lu", t[i].flags, r, gle, t[i].state, t[i].gle);
        ck_cleanup();
    }
}
TEST(ck_httponly_get_flags_table) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("hoget"), "/");
    ck_setx(u, NULL, "plain=1", 0, NULL);
    EXPECT_EQ(ck_setx(u, NULL, "ho=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "plain=1");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "plain=1; ho=1");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_NON_SCRIPT), "plain=1; ho=1");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_THIRD_PARTY), "plain=1");
    EXPECT_STR(ck_gets(u, "ho", 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    EXPECT_STR(ck_gets(u, "ho", INTERNET_COOKIE_HTTPONLY), "ho=1");
    char b[64]; DWORD sz = sizeof b;
    EXPECT_EQ(U(InternetGetCookieA)(u, NULL, b, &sz), TRUE);
    EXPECT_STR(b, "plain=1");
    ck_cleanup();
}
TEST(ck_httponly_only_cookie_invisible_no_more_items) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("hoonly"), "/");
    ck_setx(u, NULL, "ho=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    WCHAR b[32]; DWORD sz = 32;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieW)(ck_w(u), NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    sz = 32;
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, INTERNET_COOKIE_HTTPONLY, NULL), TRUE);
    EXPECT_WSTR(b, L"ho=1");
    ck_cleanup();
}
TEST(ck_httponly_overwrite_without_flag_rejected) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("hoow"), "/");
    ck_setx(u, NULL, "ho=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL);
    DWORD gle, r = ck_setx(u, NULL, "ho=2", 0, &gle);
    EXPECT_EQ(r, COOKIE_STATE_REJECT);
    EXPECT_EQ(gle, ERROR_INVALID_OPERATION);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)(u, NULL, "ho=3"), FALSE);
    EXPECT_ERR(ERROR_INVALID_OPERATION);
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "ho=1");
    EXPECT_EQ(ck_setx(u, NULL, "ho=4", INTERNET_COOKIE_NON_SCRIPT, &gle), COOKIE_STATE_ACCEPT);
    const char *g = ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY);
    t_note("after non-script overwrite without HttpOnly attr: '%s' / plain get '%s'", g, ck_gets(u, NULL, 0));
    EXPECT_STR(g, "ho=4");
    ck_cleanup();
}
TEST(ck_httponly_delete_without_flag_rejected) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("hodel"), "/");
    ck_setx(u, NULL, "ho=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)(u, NULL, "ho=; " CK_PAST), FALSE);
    EXPECT_ERR(ERROR_INVALID_OPERATION);
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "ho=1");
    DWORD gle;
    EXPECT_EQ(U(InternetSetCookieExA)(u, NULL, "ho=; " CK_PAST, INTERNET_COOKIE_HTTPONLY, 0), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "");
    (void)gle;
    ck_cleanup();
}
TEST(ck_httponly_other_name_unaffected) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("hooth"), "/");
    ck_setx(u, NULL, "ho=1; HttpOnly", INTERNET_COOKIE_HTTPONLY, NULL);
    EXPECT_EQ(ck_setx(u, NULL, "other=1", 0, NULL), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_HTTPONLY), "ho=1; other=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ samesite on get */
TEST(ck_samesite_cross_site_get) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("sscs"), "/");
    ck_set(u, NULL, "none=1");
    ck_set(u, NULL, "strict=1; SameSite=Strict");
    ck_set(u, NULL, "lax=1; SameSite=Lax");
    ck_set(u, NULL, "nn=1; SameSite=None");
    EXPECT_STR(ck_gets(u, NULL, 0), "none=1; strict=1; lax=1; nn=1");
    EXPECT_STR(ck_gets(u, NULL, INTERNET_COOKIE_SAME_SITE_LEVEL_CROSS_SITE), "none=1; nn=1");
    ck_cleanup();
}
TEST(ck_getex_unknown_flags_masked) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("gflags"), "/");
    ck_set(u, NULL, "f=1");
    static const DWORD fl[] = { 0x1, 0x2, 0x4, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x4000, 0x8000, 0x10000, 0x80000, 0x100000, 0x200000, 0x800000, 0x20000000, 0x40000000, 0x80000000 };
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        const char *g = ck_gets(u, NULL, fl[i]);
        CHECKF(!strcmp(g, "f=1"), "flags 0x%lx: '%s' gle=%lu", fl[i], g, ck_gle);
    }
    ck_cleanup();
}
TEST(ck_getex_restricted_zone_flag) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("grz"), "/");
    ck_set(u, NULL, "rz=1");
    const char *g = ck_gets(u, NULL, INTERNET_FLAG_RESTRICTED_ZONE);
    t_note("get with INTERNET_FLAG_RESTRICTED_ZONE: '%s' gle=%lu", g, ck_gle);
    EXPECT_STR(g, "rz=1");               /* 0x20000 is masked off by 0x461010 */
    ck_cleanup();
}
TEST(ck_getex_third_party_flag) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("g3p"), "/");
    ck_set(u, NULL, "tp=1");
    char d[200]; snprintf(d, sizeof d, "tpp=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    const char *g = ck_gets(u, NULL, INTERNET_COOKIE_THIRD_PARTY);
    t_note("get THIRD_PARTY: '%s' gle=%lu", g, ck_gle);
    ck_cleanup();
    CHECK(1);
}
TEST(ck_setex_third_party_flag) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("s3p"), "/");
    DWORD gle, r = ck_setx(u, NULL, "s3=1", INTERNET_COOKIE_THIRD_PARTY, &gle);
    t_note("set THIRD_PARTY session: state=%lu gle=%lu get='%s'", r, gle, ck_gets(u, NULL, 0));
    char d[200]; snprintf(d, sizeof d, "s3p=1; expires=%s", ck_date(2));
    r = ck_setx(u, NULL, d, INTERNET_COOKIE_THIRD_PARTY, &gle);
    t_note("set THIRD_PARTY persistent: state=%lu gle=%lu get='%s'", r, gle, ck_gets(u, NULL, 0));
    ck_cleanup();
    CHECK(1);
}

/* ------------------------------------------------------------------------------------------ limits */
TEST(ck_limit_180_per_domain_evicts_oldest) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("lim"), "/");
    char d[64];
    ck_set(u, NULL, "c0=0");
    Sleep(40);                                     /* c0 is strictly the oldest */
    for (int i = 1; i < 180; i++) { snprintf(d, sizeof d, "c%d=%d", i, i); ck_set(u, NULL, d); }
    const char *g = ck_gets(u, NULL, 0);
    EXPECT_EQ(ck_count(g), 180);
    CHECK(ck_has(g, "c0=0"));
    ck_set(u, NULL, "c180=180");
    g = ck_gets(u, NULL, 0);
    EXPECT_EQ(ck_count(g), 180);
    CHECKF(!ck_has(g, "c0=0"), "oldest cookie still present");
    CHECK(ck_has(g, "c180=180"));
    CHECK(ck_has(g, "c1=1"));
    ck_cleanup();
}
TEST(ck_limit_replacing_does_not_evict) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("lim2"), "/");
    char d[64];
    for (int i = 0; i < 180; i++) { snprintf(d, sizeof d, "c%d=%d", i, i); ck_set(u, NULL, d); }
    ck_set(u, NULL, "c5=new");
    const char *g = ck_gets(u, NULL, 0);
    EXPECT_EQ(ck_count(g), 180);
    CHECK(ck_has(g, "c0=0"));
    CHECK(ck_has(g, "c5=new"));
    ck_cleanup();
}
TEST(ck_limit_counts_all_paths_of_domain) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("lim3");
    char d[64];
    ck_set(ck_url(h, "/"), NULL, "first=1; path=/p0/");
    Sleep(40);
    for (int i = 1; i < 180; i++) { snprintf(d, sizeof d, "c%d=1; path=/p%d/", i, i % 7); ck_set(ck_url(h, "/"), NULL, d); }
    EXPECT_STR(ck_gets(ck_url(h, "/p0/"), "first", 0), "first=1");
    ck_set(ck_url(h, "/"), NULL, "last=1; path=/p3/");
    EXPECT_STR(ck_gets(ck_url(h, "/p0/"), "first", 0), "");
    EXPECT_STR(ck_gets(ck_url(h, "/p3/"), "last", 0), "last=1");
    ck_cleanup();
}
TEST(ck_limit_separate_hosts_independent) {
    REQUIRE(U(InternetSetCookieA));
    const char *h1 = ck_host("lim4a"), *h2 = ck_host("lim4b");
    char d[64];
    for (int i = 0; i < 100; i++) { snprintf(d, sizeof d, "c%d=1", i); ck_set(ck_url(h1, "/"), NULL, d); ck_set(ck_url(h2, "/"), NULL, d); }
    EXPECT_EQ(ck_count(ck_gets(ck_url(h1, "/"), NULL, 0)), 100);
    EXPECT_EQ(ck_count(ck_gets(ck_url(h2, "/"), NULL, 0)), 100);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ the process-wide jar */
TEST(ck_jar_shared_between_sessions) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetCookieA));
    HINTERNET a = t_inet_open("ck-a"), b = t_inet_open("ck-b");
    CHECK(a != NULL && b != NULL);
    const char *u = ck_url(ck_host("jar"), "/");
    ck_set(u, NULL, "j=1");
    t_inet_close(a);
    EXPECT_STR(ck_gets(u, NULL, 0), "j=1");      /* closing a session does not clear the jar */
    t_inet_close(b);
    EXPECT_STR(ck_gets(u, NULL, 0), "j=1");
    ck_cleanup();
}
TEST(ck_jar_no_session_needed) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("nosess"), "/");
    EXPECT_EQ(ck_set(u, NULL, "n=1"), TRUE);     /* no InternetOpen at all in this test */
    EXPECT_STR(ck_gets(u, NULL, 0), "n=1");
    ck_cleanup();
}

CHILD(ck_child_get) {
    /* argv: url name-or-"-" ; prints "CKGET <r> <gle> <data>" and returns 0 if found, 1 if not */
    if (argc < 3) return 99;
    char b[1024]; DWORD sz = sizeof b;
    BOOL r = U(InternetGetCookieExA)(argv[1], strcmp(argv[2], "-") ? argv[2] : NULL, b, &sz, 0, NULL);
    printf("  CKGET %d %lu %s\n", r, GetLastError(), r ? b : "");
    return r ? 0 : 1;
}
CHILD(ck_child_set) {
    /* argv: url data ; sets the cookie (persistent or not) and exits without cleanup */
    if (argc < 3) return 99;
    return U(InternetSetCookieA)(argv[1], NULL, argv[2]) ? 0 : 1;
}
static DWORD run_get_child(const char *url, const char *name) {
    char args[1200]; snprintf(args, sizeof args, "%s %s", url, name ? name : "-");
    return t_run_child("ck_child_get", args, 20000);
}
TEST(ck_jar_session_not_visible_in_child) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("chs"), "/");
    ck_set(u, NULL, "sess=1");
    EXPECT_EQ(run_get_child(u, NULL), 1);
    ck_cleanup();
}
TEST(ck_jar_persistent_visible_in_child) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("chp"), "/");
    char d[200]; snprintf(d, sizeof d, "pers=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_EQ(run_get_child(u, NULL), 0);
    ck_cleanup();
    EXPECT_EQ(run_get_child(u, NULL), 1);         /* deletion is visible across processes too */
}
TEST(ck_jar_child_persistent_visible_in_parent) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("chpp"), "/");
    char d[200]; snprintf(d, sizeof d, "fromchild=1; expires=%s", ck_date(2));
    ck_track(u, "fromchild", NULL, 0);
    char args[1200]; snprintf(args, sizeof args, "%s \"%s\"", u, d);
    EXPECT_EQ(t_run_child("ck_child_set", args, 20000), 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "fromchild=1");
    ck_cleanup();
}
TEST(ck_jar_child_session_gone_in_parent) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("chsp"), "/");
    ck_track(u, "childsess", NULL, 0);
    char args[1200]; snprintf(args, sizeof args, "%s childsess=1", u);
    EXPECT_EQ(t_run_child("ck_child_set", args, 20000), 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    ck_cleanup();
}
TEST(ck_jar_suppress_persist_option) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetSetCookieA));
    DWORD v = INTERNET_SUPPRESS_COOKIE_PERSIST;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v);
    DWORD e = GetLastError();
    EXPECT_EQ(r, TRUE);
    t_note("SUPPRESS_BEHAVIOR(COOKIE_PERSIST): r=%d gle=%lu", r, e);
    const char *u = ck_url(ck_host("supp"), "/");
    char d[200]; snprintf(d, sizeof d, "sp=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_STR(ck_gets(u, NULL, 0), "sp=1");
    EXPECT_EQ(run_get_child(u, NULL), 1);          /* stored as a session cookie only */
    if (UN(InternetGetCookieEx2) && UN(InternetFreeCookies)) {
        INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
        if (!UN(InternetGetCookieEx2)(ck_w(u), NULL, 0, &arr, &n) && n == 1) {
            t_note("suppressed persistent cookie flags=0x%lx expset=%d", arr[0].dwFlags, arr[0].fExpiresSet);
            CHECK(arr[0].dwFlags & INTERNET_COOKIE_IS_SESSION);
        }
        if (arr) UN(InternetFreeCookies)(arr, n);
    }
    v = INTERNET_SUPPRESS_COOKIE_PERSIST_RESET;
    EXPECT_EQ(U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v), TRUE);
    const char *u2 = ck_url(ck_host("supp2"), "/");
    snprintf(d, sizeof d, "sp2=1; expires=%s", ck_date(2));
    ck_set(u2, NULL, d);
    EXPECT_EQ(run_get_child(u2, NULL), 0);         /* persistence is back */
    ck_cleanup();
}
TEST(ck_jar_suppress_behavior_bad_values) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetQueryOptionA));
    DWORD v = 0x99;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v);
    DWORD e = GetLastError();
    t_note("SUPPRESS_BEHAVIOR 0x99: r=%d gle=%lu", r, e);
    SetLastError(0xdeadbeef);
    r = U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, 2);
    e = GetLastError();
    EXPECT_EQ(r, FALSE);
    t_note("SUPPRESS_BEHAVIOR len 2: r=%d gle=%lu", r, e);
    DWORD q = 0, qs = sizeof q;
    SetLastError(0xdeadbeef);
    r = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &q, &qs);
    t_note("query SUPPRESS_BEHAVIOR: r=%d gle=%lu", r, GetLastError());
    v = INTERNET_SUPPRESS_COOKIE_PERSIST_RESET;
    U(InternetSetOptionA)(NULL, INTERNET_OPTION_SUPPRESS_BEHAVIOR, &v, sizeof v);
}
TEST(ck_jar_end_browser_session_clears_session_cookies) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ebs"), "/");
    ck_set(u, NULL, "sess=1");
    char d[200]; snprintf(d, sizeof d, "pers=1; expires=%s", ck_date(2));
    ck_set(u, NULL, d);
    EXPECT_STR(ck_gets(u, NULL, 0), "sess=1; pers=1");
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetOptionA)(NULL, INTERNET_OPTION_END_BROWSER_SESSION, NULL, 0);
    t_note("END_BROWSER_SESSION: r=%d gle=%lu -> '%s'", r, GetLastError(), ck_gets(u, NULL, 0));
    EXPECT_EQ(r, TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "pers=1");
    ck_cleanup();
}
