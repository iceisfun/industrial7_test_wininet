/* urlcache_entries / cache keys (URL normalization) and behaviour across processes.
 * Decomp: ConvertCacheUrlCharToInternal@0x36828 / ConvertCacheUrlWCharToInternal@0x3292c (http/https/cookie keys are
 * parsed, everything else is verbatim), ConvertCacheHttpUrlWCharToInternal@0x34ce0 (IdnToAscii on the host, port digits,
 * 12005 on malformed), ReconstructCacheHttpUrlW@0x35550 (default port 80/443 dropped; scheme and path copied as typed).
 * Child processes re-launch this exe (--child) and touch only entries named by the parent. */
#include "uce.h"

static BOOL commit_nofile(const char *url) {
    return U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL);
}
/* source URL stored for a key, or "" */
static void stored_name(const char *url, char *out, size_t cap) {
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    out[0] = 0; if (i) { snprintf(out, cap, "%s", i->lpszSourceUrlName ? i->lpszSourceUrlName : ""); free(i); }
}

/* --------------------------------------------------------------- default ports */
TEST(uce_key_http_default_port_dropped) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kp80");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s:80/x.txt", host); snprintf(b, sizeof b, "http://%s/x.txt", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    CHECK(uce_exists(b));                 /* same key [D ReconstructCacheHttpUrlW: port == 80 omitted] */
    char s[512]; stored_name(a, s, sizeof s);
    EXPECT_STR(s, b);
    CHECK(uce_del(b));
    CHECK(!uce_exists(a));
}
TEST(uce_key_https_default_port_dropped) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kp443");
    char a[300], b[300]; snprintf(a, sizeof a, "https://%s:443/y", host); snprintf(b, sizeof b, "https://%s/y", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(b));
    CHECK(uce_exists(a));
    char s[512]; stored_name(a, s, sizeof s);
    EXPECT_STR(s, b);
    CHECK(uce_del(a));
    CHECK(!uce_exists(b));
}
TEST(uce_key_nondefault_ports_distinct) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kpx");
    char a[300], b[300], c[300], d[300];
    snprintf(a, sizeof a, "http://%s:8080/z", host); snprintf(b, sizeof b, "http://%s/z", host);
    snprintf(c, sizeof c, "http://%s:443/z", host); snprintf(d, sizeof d, "https://%s:80/z", host);
    t_cache_track(a); t_cache_track(b); t_cache_track(c); t_cache_track(d);
    CHECK(commit_nofile(a));
    CHECK(!uce_exists(b));
    CHECK(commit_nofile(c));
    CHECK(commit_nofile(d));
    char s[512];
    stored_name(a, s, sizeof s); EXPECT_STR(s, a);
    stored_name(c, s, sizeof s); EXPECT_STR(s, c);      /* 443 is not the default for http */
    stored_name(d, s, sizeof s); EXPECT_STR(s, d);      /* 80 is not the default for https */
    CHECK(uce_del(a)); CHECK(uce_del(c)); CHECK(uce_del(d));
}
TEST(uce_key_port_leading_zeros) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kp0");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s:0080/q", host); snprintf(b, sizeof b, "http://%s/q", host);
    t_cache_track(a); t_cache_track(b);
    BOOL r = commit_nofile(a);
    CHECK(r);
    if (r) { CHECK(uce_exists(b)); char s[512]; stored_name(a, s, sizeof s); EXPECT_STR(s, b); }
    uce_del(a);
}
TEST(uce_key_port_explicit_rewritten) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kp81");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s:081/q", host); snprintf(b, sizeof b, "http://%s:81/q", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s);
    EXPECT_STR(s, b);                     /* the port is re-printed with %d [D] */
    CHECK(uce_exists(b));
    CHECK(uce_del(b));
}

/* --------------------------------------------------------------- case */
TEST(uce_key_host_case) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kcase");
    char up[200]; strcpy(up, host); CharUpperA(up);
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s/case.txt", up); snprintf(b, sizeof b, "http://%s/case.txt", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s);
    t_note("upper-case host stored as %s", s);
    BOOL same = uce_exists(b);
    t_note("lower-case lookup finds it: %d", same);
    uce_del(a); uce_del(b);
    CHECK(!uce_exists(a));
}
TEST(uce_key_scheme_case) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kscheme");
    char a[300], b[300]; snprintf(a, sizeof a, "HTTP://%s/s.txt", host); snprintf(b, sizeof b, "http://%s/s.txt", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s);
    t_note("upper-case scheme stored as %s; lower lookup %d", s, uce_exists(b));
    uce_del(a); uce_del(b);
    CHECK(!uce_exists(a));
}
TEST(uce_key_path_case_distinct) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kpath");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s/Path/File.TXT", host); snprintf(b, sizeof b, "http://%s/path/file.txt", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s);
    EXPECT_STR(s, a);                      /* path copied as typed [D] */
    t_note("path-case lookup finds it: %d", uce_exists(b));
    uce_del(a); uce_del(b);
}

/* --------------------------------------------------------------- fragments, queries */
TEST(uce_key_fragment) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kfrag");
    char a[300], b[300], c[300];
    snprintf(a, sizeof a, "http://%s/f.htm#anchor", host); snprintf(b, sizeof b, "http://%s/f.htm", host);
    snprintf(c, sizeof c, "http://%s/f.htm#other", host);
    t_cache_track(a); t_cache_track(b); t_cache_track(c);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s);
    t_note("fragment url stored as %s; no-fragment lookup %d; other-fragment lookup %d", s, uce_exists(b), uce_exists(c));
    uce_del(a); uce_del(b); uce_del(c);
    CHECK(!uce_exists(a));
}
TEST(uce_key_query_distinct) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kq");
    char a[300], b[300], c[300];
    snprintf(a, sizeof a, "http://%s/q?x=1", host); snprintf(b, sizeof b, "http://%s/q?x=2", host); snprintf(c, sizeof c, "http://%s/q", host);
    t_cache_track(a); t_cache_track(b); t_cache_track(c);
    CHECK(commit_nofile(a));
    CHECK(!uce_exists(b));
    CHECK(!uce_exists(c));
    char s[512]; stored_name(a, s, sizeof s); EXPECT_STR(s, a);
    CHECK(commit_nofile(b));
    CHECK(uce_exists(a) && uce_exists(b));
    CHECK(uce_del(a)); CHECK(uce_del(b));
}
TEST(uce_key_trailing_slash_distinct) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kslash");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s/dir/", host); snprintf(b, sizeof b, "http://%s/dir", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    CHECK(!uce_exists(b));
    CHECK(uce_del(a));
}
TEST(uce_key_host_only_vs_root) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kroot");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s", host); snprintf(b, sizeof b, "http://%s/", host);
    t_cache_track(a); t_cache_track(b);
    BOOL r = commit_nofile(a);
    CHECK(r);
    char s[512]; stored_name(a, s, sizeof s);
    t_note("host-only stored as %s; root lookup %d", s, uce_exists(b));
    uce_del(a); uce_del(b);
}
TEST(uce_key_http_vs_https_distinct) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("khs");
    char a[300], b[300]; snprintf(a, sizeof a, "http://%s/p", host); snprintf(b, sizeof b, "https://%s/p", host);
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    CHECK(!uce_exists(b));
    CHECK(commit_nofile(b));
    CHECK(uce_del(a));
    CHECK(uce_exists(b));
    CHECK(uce_del(b));
}
TEST(uce_key_ipv4_and_ipv6_hosts) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char a[300], b[300];
    snprintf(a, sizeof a, "http://127.0.0.1:1/%s.txt", t_uniq("v4"));
    snprintf(b, sizeof b, "http://[::1]:1/%s.txt", t_uniq("v6"));
    t_cache_track(a); t_cache_track(b);
    CHECK(commit_nofile(a));
    CHECK(commit_nofile(b));
    char s[512];
    stored_name(a, s, sizeof s); EXPECT_STR(s, a);
    stored_name(b, s, sizeof s); EXPECT_STR(s, b);
    CHECK(uce_del(a)); CHECK(uce_del(b));
}
TEST(uce_key_userinfo) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("kui");
    char a[300], b[300]; snprintf(a, sizeof a, "http://user:pw@%s/u", host); snprintf(b, sizeof b, "http://%s/u", host);
    t_cache_track(a); t_cache_track(b);
    BOOL r = commit_nofile(a);
    DWORD e = GetLastError();
    char s[512]; s[0] = 0; if (r) stored_name(a, s, sizeof s);
    t_note("userinfo key: r=%d err=%lu stored=%s plain-lookup=%d", r, r ? 0 : e, s, uce_exists(b));
    uce_del(a); uce_del(b);
}
TEST(uce_key_idn_host_w) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(GetUrlCacheEntryInfoW));
    /* the host goes through IdnToAscii [D] */
    WCHAR u[300]; swprintf(u, 300, L"http://b\x00fc" L"cher%lu.i7test.example/i.txt", GetCurrentProcessId());
    WCHAR puny[300]; swprintf(puny, 300, L"http://xn--bcher%lu-", GetCurrentProcessId());
    t_cache_track(uce_a(u));
    BOOL r = U(CommitUrlCacheEntryW)(u, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL);
    CHECK(r);
    if (!r) return;
    DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(u, NULL, &e);
    CHECK(i != NULL);
    if (i) {
        t_note("IDN stored as %s", uce_a(i->lpszSourceUrlName));
        CHECK(!wcsncmp(i->lpszSourceUrlName, puny, wcslen(puny)));
        /* the punycode spelling is the same key */
        CHECK(U(GetUrlCacheEntryInfoW)(i->lpszSourceUrlName, NULL, NULL));
        CHECK(U(DeleteUrlCacheEntryW)(i->lpszSourceUrlName));
        free(i);
    }
    CHECK(!U(GetUrlCacheEntryInfoW)(u, NULL, NULL));
}
TEST(uce_key_utf8_path_w_vs_a) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(GetUrlCacheEntryInfoA));
    /* A keys are converted with CP_UTF8 (0xfde9) [D ConvertCacheUrlCharToInternal] */
    const char *host = t_uniq_host("kutf");
    char a[300]; snprintf(a, sizeof a, "http://%s/caf\xc3\xa9.txt", host);
    WCHAR w[300]; MultiByteToWideChar(CP_UTF8, 0, a, -1, w, 300);
    t_cache_track(a);
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    SET_ERR(0xdeadbeef);
    CHECK(U(GetUrlCacheEntryInfoA)(a, NULL, NULL));
    CHECK(U(DeleteUrlCacheEntryA)(a));
    CHECK(!U(GetUrlCacheEntryInfoW)(w, NULL, NULL));
}

/* --------------------------------------------------------------- non-http keys */
TEST(uce_key_ftp_verbatim) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char a[300]; snprintf(a, sizeof a, "ftp://%s:21/pub/f.bin", t_uniq_host("kftp"));
    t_cache_track(a);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s);
    EXPECT_STR(s, a);                     /* not reconstructed: :21 stays [D only http/https parsed] */
    CHECK(uce_del(a));
}
TEST(uce_key_opaque_scheme) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char a[300]; snprintf(a, sizeof a, "i7test:%s", t_uniq("opaque"));
    t_cache_track(a);
    BOOL r = commit_nofile(a);
    DWORD e = GetLastError();
    t_note("opaque key commit r=%d err=%lu", r, r ? 0 : e);
    if (r) { char s[512]; stored_name(a, s, sizeof s); EXPECT_STR(s, a); CHECK(uce_del(a)); }
}
TEST(uce_key_bad_http_never_stored) {
    REQUIRE(U(CommitUrlCacheEntryA));
    static const char *bad[] = { "http:", "http:/", "http://", "https://:80/", "http://h:65536/", "http://h:-1/", "http://[zz/" };
    for (size_t k = 0; k < sizeof bad / sizeof *bad; k++) {
        SET_ERR(0xdeadbeef);
        BOOL r = commit_nofile(bad[k]);
        DWORD e = GetLastError();
        t_note("bad key %-16s r=%d err=%lu", bad[k], r, e);
        CHECKF(!r, "%s accepted", bad[k]);
        if (r) uce_del(bad[k]);
    }
}
TEST(uce_key_max_port) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char a[300]; snprintf(a, sizeof a, "http://%s:65535/m", t_uniq_host("kmax"));
    t_cache_track(a);
    CHECK(commit_nofile(a));
    char s[512]; stored_name(a, s, sizeof s); EXPECT_STR(s, a);
    CHECK(uce_del(a));
}
TEST(uce_key_long_url) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char a[2100]; int n = snprintf(a, sizeof a, "http://%s/", t_uniq_host("klong"));
    while (n < 2000) { a[n] = (char)('a' + (n % 26)); n++; }
    a[n] = 0;
    t_cache_track(a);
    BOOL r = commit_nofile(a);
    CHECK(r);
    if (r) { DWORD sz = 0; U(GetUrlCacheEntryInfoA)(a, NULL, &sz); EXPECT_EQ(sz, UCE_INFO_SIZE + uce_slot(strlen(a))); CHECK(uce_del(a)); }
}

/* --------------------------------------------------------------- across processes */
CHILD(uce_exists) { return argc > 1 && U(GetUrlCacheEntryInfoA)(argv[1], NULL, NULL) ? 0 : 10 + (int)(GetLastError() & 0xff); }
CHILD(uce_readfile) {
    if (argc < 3) return 99;
    char buf[4096]; DWORD sz = sizeof buf;
    if (!U(RetrieveUrlCacheEntryFileA)(argv[1], (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0)) return 20;
    char rb[256]; int n = uce_read_file(((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszLocalFileName, rb, sizeof rb);
    U(UnlockUrlCacheEntryFileA)(argv[1], 0);
    return (n == (int)strlen(argv[2]) && !memcmp(rb, argv[2], n)) ? 0 : 21;
}
CHILD(uce_commit) {
    if (argc < 3) return 99;
    char p[MAX_PATH];
    if (!U(CreateUrlCacheEntryA)(argv[1], 0, "txt", p, 0)) return 30;
    if (!uce_write_file(p, argv[2], (DWORD)strlen(argv[2]))) return 31;
    return U(CommitUrlCacheEntryA)(argv[1], p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL) ? 0 : 32;
}
CHILD(uce_delete) { return argc > 1 && U(DeleteUrlCacheEntryA)(argv[1]) ? 0 : 40 + (int)(GetLastError() & 0xff); }
CHILD(uce_lock_and_exit) {
    if (argc < 2) return 99;
    char buf[4096]; DWORD sz = sizeof buf;
    return U(RetrieveUrlCacheEntryFileA)(argv[1], (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0) ? 0 : 50;
}

static char g_args[1024];
static const char *args2(const char *a, const char *b) { snprintf(g_args, sizeof g_args, "\"%s\" \"%s\"", a, b ? b : ""); return g_args; }

TEST(uce_xproc_child_sees_parent_entry) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("xp1"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "from parent", 11, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    EXPECT_EQ(t_run_child("uce_exists", args2(url, NULL), 20000), 0);
    EXPECT_EQ(t_run_child("uce_readfile", args2(url, "from parent"), 20000), 0);
    CHECK(uce_del(url));
    EXPECT_EQ(t_run_child("uce_exists", args2(url, NULL), 20000), 10 + ERROR_FILE_NOT_FOUND);
}
TEST(uce_xproc_parent_sees_child_entry) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("xp2");
    EXPECT_EQ(t_run_child("uce_commit", args2(url, "from child"), 20000), 0);
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    CHECK(i != NULL);
    if (i) {
        char rb[64]; int n = i->lpszLocalFileName ? uce_read_file(i->lpszLocalFileName, rb, sizeof rb) : -1;
        CHECK(n == 10 && !memcmp(rb, "from child", 10));
        free(i);
    }
    EXPECT_EQ(t_run_child("uce_delete", args2(url, NULL), 20000), 0);
    CHECK(!uce_exists(url));
}
TEST(uce_xproc_child_delete_missing) {
    const char *url = uce_url("xp3");
    EXPECT_EQ(t_run_child("uce_delete", args2(url, NULL), 20000), 40 + ERROR_FILE_NOT_FOUND);
}
TEST(uce_xproc_child_deletes_parent_locked) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("xp4"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "locked by parent", 16, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    char buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    DWORD rc = t_run_child("uce_delete", args2(url, NULL), 20000);
    t_note("child delete of parent-locked entry: rc=%lu (0=deleted, 40+err)", rc);
    CHECK(rc == 0 || rc == 40 + ERROR_SHARING_VIOLATION);
    U(UnlockUrlCacheEntryFileA)(url, 0);
    if (uce_exists(url)) CHECK(uce_del(url));
    CHECK(!uce_exists(url));
}
TEST(uce_xproc_child_lock_released_at_exit) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("xp5"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "child locks", 11, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    EXPECT_EQ(t_run_child("uce_lock_and_exit", args2(url, NULL), 20000), 0);
    SET_ERR(0xdeadbeef);
    BOOL d = uce_del(url);
    t_note("delete after child exited holding a lock: r=%d err=%lu", d, d ? 0 : GetLastError());
    if (!d && uce_exists(url)) uce_del(url);
}
TEST(uce_xproc_replace_by_child) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("xp6"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "v1", 2, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    EXPECT_EQ(t_run_child("uce_commit", args2(url, "version two"), 20000), 0);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwSizeLow, 11); CHECK(_stricmp(i->lpszLocalFileName, p) != 0); free(i); } else CHECK(0);
    CHECK(!uce_file_exists(p));
    CHECK(uce_del(url));
}
