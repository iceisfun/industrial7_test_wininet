/* urlcache_entries / entry point x input matrices: every URL-taking cache entry API (A and W) against invalid http keys
 * (ERROR_INTERNET_INVALID_URL), missing entries (ERROR_FILE_NOT_FOUND), equivalent spellings of an existing key (all
 * resolve to it) and distinct spellings (none do).
 * Decomp: every front end converts the key first with ConvertCacheUrlCharToInternal@0x36828 (A, CP_UTF8) or
 * ConvertCacheHttpUrlWCharToInternal@0x34ce0 (W) -> 0x80072ee5 for a malformed http(s) key; ReconstructCacheHttpUrlW@0x35550
 * drops the default port and re-prints the port with %d. Lookups miss with 0x80070002.
 * Tags: [D] decomp + VM, [W10] VM-observed, [K] knowledge + VM. */
#include "uce.h"

typedef BOOL (*op_fn)(const char *url);
static char g_ib[8192];

static BOOL op_info_a_probe(const char *u) { return U(GetUrlCacheEntryInfoA)(u, NULL, NULL); }
static BOOL op_info_a_size(const char *u) {
    DWORD sz = sizeof g_ib;
    return U(GetUrlCacheEntryInfoA)(u, (INTERNET_CACHE_ENTRY_INFOA *)g_ib, &sz);
}
static BOOL op_info_w_probe(const char *u) { return U(GetUrlCacheEntryInfoW)(uce_w(u), NULL, NULL); }
static BOOL op_info_w_size(const char *u) {
    DWORD sz = sizeof g_ib;
    return U(GetUrlCacheEntryInfoW)(uce_w(u), (INTERNET_CACHE_ENTRY_INFOW *)g_ib, &sz);
}
static BOOL op_info_exa(const char *u) {
    DWORD sz = sizeof g_ib;
    return U(GetUrlCacheEntryInfoExA)(u, (INTERNET_CACHE_ENTRY_INFOA *)g_ib, &sz, NULL, NULL, NULL, 0);
}
static BOOL op_info_exw(const char *u) {
    DWORD sz = sizeof g_ib;
    return U(GetUrlCacheEntryInfoExW)(uce_w(u), (INTERNET_CACHE_ENTRY_INFOW *)g_ib, &sz, NULL, NULL, NULL, 0);
}
static BOOL op_set_a(const char *u) {
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.dwHitRate = 9;
    return U(SetUrlCacheEntryInfoA)(u, &n, CACHE_ENTRY_HITRATE_FC);
}
static BOOL op_set_w(const char *u) {
    INTERNET_CACHE_ENTRY_INFOW n; memset(&n, 0, sizeof n); n.dwHitRate = 9;
    return U(SetUrlCacheEntryInfoW)(uce_w(u), &n, CACHE_ENTRY_HITRATE_FC);
}
/* retrieve + immediate unlock, so a success leaves no lock behind; the error is the retrieve's */
static BOOL op_retr_a(const char *u) {
    DWORD sz = sizeof g_ib;
    if (!U(RetrieveUrlCacheEntryFileA)(u, (INTERNET_CACHE_ENTRY_INFOA *)g_ib, &sz, 0)) return FALSE;
    U(UnlockUrlCacheEntryFileA)(u, 0); SetLastError(0); return TRUE;
}
static BOOL op_retr_w(const char *u) {
    DWORD sz = sizeof g_ib;
    if (!U(RetrieveUrlCacheEntryFileW)(uce_w(u), (INTERNET_CACHE_ENTRY_INFOW *)g_ib, &sz, 0)) return FALSE;
    U(UnlockUrlCacheEntryFileW)(uce_w(u), 0); SetLastError(0); return TRUE;
}
static BOOL op_stream_a(const char *u) {
    DWORD sz = sizeof g_ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(u, (INTERNET_CACHE_ENTRY_INFOA *)g_ib, &sz, FALSE, 0);
    if (!h) return FALSE;
    U(UnlockUrlCacheEntryStream)(h, 0); SetLastError(0); return TRUE;
}
static BOOL op_stream_w(const char *u) {
    DWORD sz = sizeof g_ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamW)(uce_w(u), (INTERNET_CACHE_ENTRY_INFOW *)g_ib, &sz, TRUE, 0);
    if (!h) return FALSE;
    U(UnlockUrlCacheEntryStream)(h, 0); SetLastError(0); return TRUE;
}
static BOOL op_unlock_a(const char *u) { return U(UnlockUrlCacheEntryFileA)(u, 0); }
static BOOL op_unlock_w(const char *u) { return U(UnlockUrlCacheEntryFileW)(uce_w(u), 0); }

static const struct { const char *name; op_fn fn; } g_ops[] = {
    { "GetInfoA(probe)", op_info_a_probe }, { "GetInfoA(buf)", op_info_a_size },
    { "GetInfoW(probe)", op_info_w_probe }, { "GetInfoW(buf)", op_info_w_size },
    { "GetInfoExA", op_info_exa },          { "GetInfoExW", op_info_exw },
    { "SetInfoA", op_set_a },               { "SetInfoW", op_set_w },
    { "RetrieveFileA", op_retr_a },         { "RetrieveFileW", op_retr_w },
    { "RetrieveStreamA", op_stream_a },     { "RetrieveStreamW", op_stream_w },
    { "UnlockFileA", op_unlock_a },         { "UnlockFileW", op_unlock_w },
};
#define NOPS (sizeof g_ops / sizeof *g_ops)

static BOOL have_all(void) {
    return U(GetUrlCacheEntryInfoExA) && U(GetUrlCacheEntryInfoExW) && U(SetUrlCacheEntryInfoW) && U(RetrieveUrlCacheEntryStreamW) &&
           U(UnlockUrlCacheEntryFileW) && U(UnlockUrlCacheEntryStream) && U(RetrieveUrlCacheEntryFileW);
}

/* --------------------------------------------------------------- malformed http(s) keys */
static const char *g_bad[] = {
    "http://", "https://", "http:/x", "http:x", "https:x", "http:///p", "http://:80/", "https://:443/a",
    "http://h:65536/", "http://h:99999999/", "http://h:8x/", "http://h:-1/", "http://h: 80/", "HTTP:x", "Https:/a",
};
TEST(uce_amx_invalid_url_every_op) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    for (size_t b = 0; b < sizeof g_bad / sizeof *g_bad; b++) {
        for (size_t o = 0; o < NOPS; o++) {
            SET_ERR(0xdeadbeef);
            BOOL r = g_ops[o].fn(g_bad[b]);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "%s(\"%s\") -> %d err %lu", g_ops[o].name, g_bad[b], r, e);
        }
    }
}
TEST(uce_amx_invalid_url_delete_create_commit) {
    REQUIRE(U(DeleteUrlCacheEntryW)); REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(CreateUrlCacheEntryW));
    for (size_t b = 0; b < sizeof g_bad / sizeof *g_bad; b++) {
        const char *u = g_bad[b];
        SET_ERR(0xdeadbeef);
        BOOL r = U(DeleteUrlCacheEntryA)(u); DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "DeleteA(%s) %d %lu", u, r, e);
        SET_ERR(0xdeadbeef);
        r = U(DeleteUrlCacheEntryW)(uce_w(u)); e = GetLastError();
        CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "DeleteW(%s) %d %lu", u, r, e);
        WCHAR wp[MAX_PATH] = L"keep";
        SET_ERR(0xdeadbeef);
        r = U(CreateUrlCacheEntryW)(uce_w(u), 0, L"txt", wp, 0); e = GetLastError();
        CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "CreateW(%s) %d %lu", u, r, e);
        CHECK(!lstrcmpW(wp, L"keep"));
        if (r) DeleteFileW(wp);
        SET_ERR(0xdeadbeef);
        r = U(CommitUrlCacheEntryW)(uce_w(u), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL); e = GetLastError();
        CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "CommitW(%s) %d %lu", u, r, e);
        if (r) U(DeleteUrlCacheEntryW)(uce_w(u));
        SET_ERR(0xdeadbeef);
        r = U(CommitUrlCacheEntryA)(u, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL); e = GetLastError();
        CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "CommitA(%s) %d %lu", u, r, e);
        if (r) U(DeleteUrlCacheEntryA)(u);
    }
}

/* --------------------------------------------------------------- missing entries */
TEST(uce_amx_missing_every_op) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    static const char *shapes[] = { "http://%s/m.txt", "https://%s/m", "http://%s:8080/q?x=1", "ftp://%s/f", "i7scheme:%s", "http://%s/#frag" };
    for (size_t s = 0; s < sizeof shapes / sizeof *shapes; s++) {
        char u[512]; snprintf(u, sizeof u, shapes[s], t_uniq_host("amxm"));
        for (size_t o = 0; o < NOPS; o++) {
            SET_ERR(0xdeadbeef);
            BOOL r = g_ops[o].fn(u);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_FILE_NOT_FOUND, "%s(%s) -> %d err %lu", g_ops[o].name, u, r, e);
        }
        SET_ERR(0xdeadbeef);
        BOOL r = U(DeleteUrlCacheEntryA)(u); DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_FILE_NOT_FOUND, "DeleteA(%s) %d %lu", u, r, e);
        SET_ERR(0xdeadbeef);
        r = U(DeleteUrlCacheEntryW)(uce_w(u)); e = GetLastError();
        CHECKF(!r && e == ERROR_FILE_NOT_FOUND, "DeleteW(%s) %d %lu", u, r, e);
    }
}

/* --------------------------------------------------------------- existing entry: every op succeeds */
TEST(uce_amx_existing_every_op) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    const char *url = uce_url("amxe"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "every op", 8, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    for (size_t o = 0; o < NOPS; o++) {
        SET_ERR(0xdeadbeef);
        BOOL r = g_ops[o].fn(url);
        DWORD e = GetLastError();
        /* success clears the last error [D SetLastError(WX_WIN32_FROM_HR(S_OK))]; unlocking an unlocked entry succeeds [W10] */
        CHECKF(r && e == 0, "%s -> %d err %lu", g_ops[o].name, r, e);
    }
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    /* Set put the hit rate to 9; the 4 retrievals after it (file A/W, stream A/W) each counted one [W10] */
    if (i) { EXPECT_EQ(i->dwUseCount, 0); EXPECT_EQ(i->dwHitRate, 13); free(i); } else CHECK(0);
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    CHECK(!uce_file_exists(p));
}

/* --------------------------------------------------------------- equivalent and distinct spellings */
TEST(uce_amx_equivalent_spellings_every_op) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    const char *host = t_uniq_host("amxq");
    char url[256]; snprintf(url, sizeof url, "http://%s/eq.txt", host);
    t_cache_track(url);
    char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "eq", 2, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    /* the default port is dropped and the port is re-printed with %d [D ReconstructCacheHttpUrlW] */
    static const char *alts[] = { "http://%s:80/eq.txt", "http://%s:080/eq.txt", "http://%s:0000080/eq.txt" };
    for (size_t a = 0; a < sizeof alts / sizeof *alts; a++) {
        char alt[256]; snprintf(alt, sizeof alt, alts[a], host);
        for (size_t o = 0; o < NOPS; o++) {
            SET_ERR(0xdeadbeef);
            BOOL r = g_ops[o].fn(alt);
            DWORD e = GetLastError();
            CHECKF(r && e == 0, "%s(%s) -> %d err %lu", g_ops[o].name, alt, r, e);
        }
        DWORD sz = sizeof g_ib;
        if (U(GetUrlCacheEntryInfoA)(alt, (INTERNET_CACHE_ENTRY_INFOA *)g_ib, &sz))
            EXPECT_STR(((INTERNET_CACHE_ENTRY_INFOA *)g_ib)->lpszSourceUrlName, url);
    }
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    char alt[256]; snprintf(alt, sizeof alt, "http://%s:80/eq.txt", host);
    SET_ERR(0xdeadbeef);
    CHECK(U(DeleteUrlCacheEntryW)(uce_w(alt))); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
}
TEST(uce_amx_https_equivalent_spellings) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *host = t_uniq_host("amxs");
    char url[256]; snprintf(url, sizeof url, "https://%s/s.txt", host);
    t_cache_track(url);
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    static const char *alts[] = { "https://%s:443/s.txt", "https://%s:0443/s.txt" };
    for (size_t a = 0; a < sizeof alts / sizeof *alts; a++) {
        char alt[256]; snprintf(alt, sizeof alt, alts[a], host);
        for (size_t o = 0; o < 8; o++) {    /* the info/set ops: the entry has no file to retrieve */
            SET_ERR(0xdeadbeef);
            BOOL r = g_ops[o].fn(alt);
            DWORD e = GetLastError();
            CHECKF(r && e == 0, "%s(%s) -> %d err %lu", g_ops[o].name, alt, r, e);
        }
    }
    /* :80 is not the https default and :443 is not the http default */
    char x[256]; snprintf(x, sizeof x, "https://%s:80/s.txt", host);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(x), ERROR_FILE_NOT_FOUND);
    snprintf(x, sizeof x, "http://%s:443/s.txt", host);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(x), ERROR_FILE_NOT_FOUND);
    CHECK(uce_del(url));
}
TEST(uce_amx_distinct_spellings_every_op) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    const char *host = t_uniq_host("amxd");
    char url[256]; snprintf(url, sizeof url, "http://%s/dx.txt", host);
    t_cache_track(url);
    char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "dx", 2, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    char HOST[128]; strcpy(HOST, host); CharUpperA(HOST);
    char alts[12][300];
    int n = 0;
    snprintf(alts[n++], 300, "HTTP://%s/dx.txt", host);       /* scheme case [W10: keys are case-sensitive] */
    snprintf(alts[n++], 300, "http://%s/dx.txt", HOST);       /* host case */
    snprintf(alts[n++], 300, "http://%s/DX.TXT", host);       /* path case */
    snprintf(alts[n++], 300, "http://%s/dx.txt#a", host);     /* fragment kept in the key [W10] */
    snprintf(alts[n++], 300, "http://%s/dx.txt?", host);      /* empty query */
    snprintf(alts[n++], 300, "http://%s:81/dx.txt", host);
    snprintf(alts[n++], 300, "https://%s/dx.txt", host);
    snprintf(alts[n++], 300, "http://%s//dx.txt", host);
    snprintf(alts[n++], 300, "http://%s/./dx.txt", host);
    snprintf(alts[n++], 300, "http://%s/dx%%2etxt", host);
    snprintf(alts[n++], 300, "http://%s./dx.txt", host);
    snprintf(alts[n++], 300, "http://u@%s/dx.txt", host);
    for (int a = 0; a < n; a++) {
        for (size_t o = 0; o < NOPS; o++) {
            SET_ERR(0xdeadbeef);
            BOOL r = g_ops[o].fn(alts[a]);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_FILE_NOT_FOUND, "%s(%s) -> %d err %lu", g_ops[o].name, alts[a], r, e);
        }
        SET_ERR(0xdeadbeef);
        BOOL r = U(DeleteUrlCacheEntryA)(alts[a]); DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_FILE_NOT_FOUND, "DeleteA(%s) %d %lu", alts[a], r, e);
    }
    /* none of them touched the real entry */
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwHitRate, 1); EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- NULL url everywhere */
TEST(uce_amx_null_url_every_op) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    char b[1024]; DWORD sz;
    struct { const char *name; BOOL r; DWORD e; } res[16]; int n = 0;
#define NULLCASE(nm, call) do { SET_ERR(0xdeadbeef); BOOL r_ = (call); res[n].name = nm; res[n].r = r_; res[n].e = GetLastError(); n++; } while (0)
    sz = sizeof b; NULLCASE("GetInfoA", U(GetUrlCacheEntryInfoA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz));
    sz = sizeof b; NULLCASE("GetInfoW", U(GetUrlCacheEntryInfoW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)b, &sz));
    sz = sizeof b; NULLCASE("GetInfoExA", U(GetUrlCacheEntryInfoExA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, NULL, NULL, NULL, 0));
    sz = sizeof b; NULLCASE("GetInfoExW", U(GetUrlCacheEntryInfoExW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)b, &sz, NULL, NULL, NULL, 0));
    { INTERNET_CACHE_ENTRY_INFOA a; memset(&a, 0, sizeof a); NULLCASE("SetInfoA", U(SetUrlCacheEntryInfoA)(NULL, &a, CACHE_ENTRY_HITRATE_FC)); }
    { INTERNET_CACHE_ENTRY_INFOW w; memset(&w, 0, sizeof w); NULLCASE("SetInfoW", U(SetUrlCacheEntryInfoW)(NULL, &w, CACHE_ENTRY_HITRATE_FC)); }
    sz = sizeof b; NULLCASE("RetrieveA", U(RetrieveUrlCacheEntryFileA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    sz = sizeof b; NULLCASE("RetrieveW", U(RetrieveUrlCacheEntryFileW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)b, &sz, 0));
    sz = sizeof b; NULLCASE("StreamA", U(RetrieveUrlCacheEntryStreamA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, FALSE, 0) != NULL);
    sz = sizeof b; NULLCASE("StreamW", U(RetrieveUrlCacheEntryStreamW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)b, &sz, FALSE, 0) != NULL);
    NULLCASE("UnlockA", U(UnlockUrlCacheEntryFileA)(NULL, 0));
    NULLCASE("UnlockW", U(UnlockUrlCacheEntryFileW)(NULL, 0));
    NULLCASE("DeleteA", U(DeleteUrlCacheEntryA)(NULL));
    NULLCASE("DeleteW", U(DeleteUrlCacheEntryW)(NULL));
    NULLCASE("CommitA", U(CommitUrlCacheEntryA)(NULL, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    NULLCASE("CommitW", U(CommitUrlCacheEntryW)(NULL, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
#undef NULLCASE
    /* NULL key -> 87 on every front end [D] */
    for (int k = 0; k < n; k++) CHECKF(!res[k].r && res[k].e == ERROR_INVALID_PARAMETER, "%s(NULL) -> %d err %lu", res[k].name, res[k].r, res[k].e);
}

/* --------------------------------------------------------------- empty url */
TEST(uce_amx_empty_url_lookups) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); if (!have_all()) { t_skip("missing exports"); return; }
    /* "" is a legal (non-http) key; nothing in a fresh profile is stored under it, so lookups miss.
       Observed values are noted rather than asserted: other software may have committed "" on a persistent box. */
    for (size_t o = 0; o < NOPS; o++) {
        if (g_ops[o].fn == op_set_a || g_ops[o].fn == op_set_w || g_ops[o].fn == op_unlock_a || g_ops[o].fn == op_unlock_w) continue;
        SET_ERR(0xdeadbeef);
        BOOL r = g_ops[o].fn("");
        DWORD e = GetLastError();
        t_note("%s(\"\") -> %d err %lu", g_ops[o].name, r, e);
        CHECKF(r || e == ERROR_FILE_NOT_FOUND || e == ERROR_INVALID_PARAMETER, "%s(\"\") err %lu", g_ops[o].name, e);
    }
}

/* --------------------------------------------------------------- non-http schemes are verbatim keys */
TEST(uce_amx_nonhttp_keys_verbatim) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *host = t_uniq_host("amxv");
    static const char *shapes[][2] = {
        { "ftp://%s/a.txt", "ftp://%s:21/a.txt" },
        { "ftp://%s/a.txt", "FTP://%s/a.txt" },
        { "file:///c:/%s.txt", "file:///C:/%s.txt" },
        { "i7x:%s", "I7X:%s" },
        { "i7x://%s:80/", "i7x://%s/" },
    };
    for (size_t k = 0; k < sizeof shapes / sizeof *shapes; k++) {
        char a[300], b[300];
        snprintf(a, sizeof a, shapes[k][0], host); snprintf(b, sizeof b, shapes[k][1], host);
        t_cache_track(a);
        SET_ERR(0xdeadbeef);
        BOOL r = U(CommitUrlCacheEntryA)(a, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL);
        CHECKF(r, "%s err %lu", a, GetLastError());
        if (!r) continue;
        CHECK(uce_exists(a));
        /* only http/https are parsed; other keys match byte for byte [D ConvertCacheUrlCharToInternal] */
        SET_ERR(0xdeadbeef);
        BOOL v = uce_exists(b); DWORD e = GetLastError();
        CHECKF(!v && e == ERROR_FILE_NOT_FOUND, "%s found via %s (err %lu)", a, b, e);
        CHECK(uce_del(a));
    }
}
