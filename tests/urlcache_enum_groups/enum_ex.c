/* urlcache_enum_groups / enum_ex.c - FindFirstUrlCacheEntryExA/W, FindNextUrlCacheEntryExA/W:
 * filters, group-scoped enumeration, FIND_FLAGS_RETREIVE_ONLY_STRUCT_INFO / ..._FIXED_AND_FILENAME, reserved args.
 * Determinism: every enumeration whose CONTENT is checked is scoped to a group this test created
 * (GroupId filter, pattern "" = the content container only), so foreign cache entries never matter.
 * Evidence: [D] FindFirstUrlCacheEntryExA@0x83c0 / ExW@0x7d80, GetInitialUrlCacheEntryFindHandleHelper@0x8648,
 * CCacheEntryEnum::Next@0x9f50 (filter: (filter & type) == type; group: entry group list contains GroupId),
 * ConvertCacheEntryInfoA@0x92c0 (modes 4 and 8), FindNextUrlCacheEntryExW@0x1a0220. [VM] Win10 22H2.
 * VM_TIMEOUT: 240 */
#include "ueg.h"
#include <stdlib.h>

#define REQ_EX_A() do { REQUIRE(U(FindFirstUrlCacheEntryExA)); REQUIRE(U(FindNextUrlCacheEntryExA)); REQUIRE(U(FindCloseUrlCache)); } while (0)
#define REQ_EX_W() do { REQUIRE(U(FindFirstUrlCacheEntryExW)); REQUIRE(U(FindNextUrlCacheEntryExW)); REQUIRE(U(FindCloseUrlCache)); } while (0)
#define REQ_GRP() do { REQUIRE(U(CreateUrlCacheGroup)); REQUIRE(U(DeleteUrlCacheGroup)); REQUIRE(U(SetUrlCacheEntryGroupA)); } while (0)

/* group with n fresh entries; returns gid (0 -> skip). urls[] receives the URLs. */
static GROUPID group_with_entries(const char *tag, int n, const char **urls) {
    GROUPID g = ueg_group_new(0);
    if (!g) return 0;
    for (int i = 0; i < n; i++) {
        char t[64]; snprintf(t, sizeof t, "%s%d", tag, i);
        urls[i] = ueg_url(t);
        if (!ueg_make_simple(urls[i])) return 0;
        if (!U(SetUrlCacheEntryGroupA)(urls[i], INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL)) return 0;
    }
    return g;
}
#define GROUP_OR_SKIP(g, tag, n, urls) do { REQ_GRP(); (g) = group_with_entries(tag, n, urls); if (!(g)) { t_skip("group setup failed (%lu)", GetLastError()); return; } } while (0)

/* ------------------------------------------------------------------ parameter validation */
TEST(ueg_ffxa_null_size_87) {
    REQ_EX_A();
    char buf[512];
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExA)(NULL, 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOA *)buf, NULL, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExA)(NULL, 0, UEG_DEFAULT_FILTER, 0, NULL, NULL, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(ueg_ffxa_zero_size_with_buffer_87) {
    REQ_EX_A();
    char buf[512]; DWORD sz = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExA)(NULL, 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 0);
}
TEST(ueg_ffxa_reserved_87) {
    REQ_EX_A();
    char buf[4096]; DWORD sz = sizeof buf; int dummy = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExA)(NULL, 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, &dummy), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, sizeof buf);
}
TEST(ueg_ffxw_null_size_87) {
    REQ_EX_W();
    char buf[512];
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExW)(NULL, 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOW *)buf, NULL, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(ueg_ffxw_zero_size_with_buffer_87) {
    REQ_EX_W();
    char buf[512]; DWORD sz = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExW)(NULL, 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(ueg_ffxw_reserved_87) {
    REQ_EX_W();
    char buf[4096]; DWORD sz = sizeof buf; int dummy = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindFirstUrlCacheEntryExW)(NULL, 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, &dummy), ERROR_INVALID_PARAMETER);
}
/* lpGroupAttributes / lpcbGroupAttributes are ignored (not validated) [D]. */
TEST(ueg_ffxa_group_attribute_args_ignored) {
    REQ_EX_A();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "gaa", 1, urls);
    char buf[4096]; DWORD sz = sizeof buf; char ga[64]; DWORD gacb = 3;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, ga, &gacb, NULL);
    CHECK(h != NULL);
    if (h) {
        EXPECT_ERR(0);
        EXPECT_EQ(gacb, 3);
        EXPECT_STR(((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszSourceUrlName, urls[0]);
        sz = sizeof buf; SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, ga, &gacb, NULL), ERROR_NO_MORE_ITEMS);
        U(FindCloseUrlCache)(h);
    }
}
TEST(ueg_fnxa_param_validation) {
    REQ_EX_A();
    const char *urls[2]; GROUPID g; GROUP_OR_SKIP(g, "fnxv", 2, urls);
    char buf[4096]; DWORD sz = sizeof buf; int dummy = 0;
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (!h) return;
    sz = sizeof buf; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, (INTERNET_CACHE_ENTRY_INFOA *)buf, NULL, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    DWORD z = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, (INTERNET_CACHE_ENTRY_INFOA *)buf, &z, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    sz = sizeof buf; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, &dummy), ERROR_INVALID_PARAMETER);
    /* none of the failures consumed the second entry */
    sz = sizeof buf; SET_ERR(0xdead);
    CHECK(U(FindNextUrlCacheEntryExA)(h, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL));
    EXPECT_ERR(0);
    sz = sizeof buf;
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
    U(FindCloseUrlCache)(h);
}
TEST(ueg_fnxw_param_validation) {
    REQ_EX_W();
    const char *urls[2]; GROUPID g; GROUP_OR_SKIP(g, "fnxvw", 2, urls);
    char buf[4096]; DWORD sz = sizeof buf; int dummy = 0;
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (!h) return;
    sz = sizeof buf; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, (INTERNET_CACHE_ENTRY_INFOW *)buf, NULL, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    DWORD z = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, (INTERNET_CACHE_ENTRY_INFOW *)buf, &z, NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    sz = sizeof buf; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, &dummy), ERROR_INVALID_PARAMETER);
    sz = sizeof buf;
    CHECK(U(FindNextUrlCacheEntryExW)(h, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL));
    sz = sizeof buf;
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
    U(FindCloseUrlCache)(h);
}

/* ------------------------------------------------------------------ group-scoped enumeration (deterministic) */
typedef struct { const char **urls; int n; int hits[16]; int other; } set_ctx;
static int set_cb(const INTERNET_CACHE_ENTRY_INFOA *e, DWORD size, void *c_) {
    set_ctx *c = c_; int m = 0; (void)size;
    for (int i = 0; i < c->n; i++) if (e->lpszSourceUrlName && !strcmp(e->lpszSourceUrlName, c->urls[i])) { c->hits[i]++; m = 1; }
    if (!m) c->other++;
    return 1;
}
TEST(ueg_group_scope_exact_set) {
    REQ_EX_A();
    const char *urls[5]; GROUPID g; GROUP_OR_SKIP(g, "gset", 5, urls);
    set_ctx c = { urls, 5 }; DWORD last = 0;
    int n = ueg_enum_ex_a("", 0, UEG_DEFAULT_FILTER, g, set_cb, &c, &last);
    EXPECT_EQ(n, 5);
    EXPECT_EQ(last, ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(c.other, 0);
    for (int i = 0; i < 5; i++) CHECKF(c.hits[i] == 1, "url %d seen %d times", i, c.hits[i]);
}
TEST(ueg_group_scope_null_pattern) {
    REQ_EX_A();
    const char *urls[3]; GROUPID g; GROUP_OR_SKIP(g, "gnull", 3, urls);
    set_ctx c = { urls, 3 }; DWORD last = 0;
    int n = ueg_enum_ex_a(NULL, 0, UEG_DEFAULT_FILTER, g, set_cb, &c, &last);
    for (int i = 0; i < 3; i++) CHECKF(c.hits[i] == 1, "url %d seen %d times", i, c.hits[i]);
    t_note("NULL pattern + group: %d entries (%d foreign, e.g. cookies are not group-filtered), end %lu", n, c.other, last);
}
TEST(ueg_group_scope_empty_group_259) {
    REQ_EX_A(); REQ_GRP();
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("CreateUrlCacheGroup failed %lu", GetLastError()); return; }
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_NO_MORE_ITEMS);
    if (h) U(FindCloseUrlCache)(h);
    EXPECT_EQ(sz, sizeof buf);    /* nothing converted */
}
TEST(ueg_group_scope_w_exact_set) {
    REQ_EX_W();
    const char *urls[3]; GROUPID g; GROUP_OR_SKIP(g, "gsetw", 3, urls);
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    int hits[3] = { 0 }, n = 0, other = 0;
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", 0, UEG_DEFAULT_FILTER, g, e, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (h) {
        do {
            n++; int m = 0;
            for (int i = 0; i < 3; i++) if (e->lpszSourceUrlName && !lstrcmpW(e->lpszSourceUrlName, ueg_w(urls[i]))) { hits[i]++; m = 1; }
            if (!m) other++;
            EXPECT_EQ(e->dwStructSize, 0x70);
            CHECK(e->lpszFileExtension && !lstrcmpW(e->lpszFileExtension, L"txt"));
            sz = cap;
        } while (n < 50 && U(FindNextUrlCacheEntryExW)(h, e, &sz, NULL, NULL, NULL));
        EXPECT_ERR(ERROR_NO_MORE_ITEMS);
        U(FindCloseUrlCache)(h);
    }
    EXPECT_EQ(n, 3); EXPECT_EQ(other, 0);
    for (int i = 0; i < 3; i++) EXPECT_EQ(hits[i], 1);
    free(e);
}
/* W conversion size: 0x70 + al4(2*(url+1)) + al4(2*(file+1)) + al4(2*(ext+1)) [+ header] */
TEST(ueg_group_scope_w_size_formula) {
    REQ_EX_W();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "wsz", 1, urls);
    DWORD sz = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", 0, UEG_DEFAULT_FILTER, g, NULL, &sz, NULL, NULL, NULL);
    if (h) { t_note("W FindFirstEx with NULL buffer and size 0 returned a handle"); U(FindCloseUrlCache)(h); }
    else EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD s2 = cap;
    h = U(FindFirstUrlCacheEntryExW)(L"", 0, UEG_DEFAULT_FILTER, g, e, &s2, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (h) {
        DWORD want = 0x70 + ueg_align4(2 * ((DWORD)lstrlenW(e->lpszSourceUrlName) + 1));
        if (e->lpszLocalFileName) want += ueg_align4(2 * ((DWORD)lstrlenW(e->lpszLocalFileName) + 1));
        if (e->lpszFileExtension) want += ueg_align4(2 * ((DWORD)lstrlenW(e->lpszFileExtension) + 1));
        EXPECT_EQ(e->dwHeaderInfoSize, 0);
        EXPECT_EQ(s2, want);
        if (!h || sz) EXPECT_EQ(sz, want);
        U(FindCloseUrlCache)(h);
    }
    free(e);
}

/* ------------------------------------------------------------------ filter semantics: (filter & type) == type */
static const DWORD k_types[] = {
    NORMAL_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | TRACK_OFFLINE_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | TRACK_ONLINE_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | SPARSE_CACHE_ENTRY,
};
static const DWORD k_filters[] = {
    0, NORMAL_CACHE_ENTRY, STICKY_CACHE_ENTRY, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY,
    UEG_DEFAULT_FILTER, UEG_DEFAULT_FILTER | EDITED_CACHE_ENTRY, UEG_DEFAULT_FILTER | SPARSE_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, NORMAL_CACHE_ENTRY | TRACK_OFFLINE_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | TRACK_ONLINE_CACHE_ENTRY, NORMAL_CACHE_ENTRY | SPARSE_CACHE_ENTRY,
    0xffffffff, ~(DWORD)NORMAL_CACHE_ENTRY, COOKIE_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY,
};
#define NT (sizeof k_types / sizeof *k_types)
#define NF (sizeof k_filters / sizeof *k_filters)
TEST(ueg_filter_matrix_a) {
    REQ_EX_A(); REQ_GRP();
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    const char *urls[NT]; DWORD stored[NT];
    for (size_t i = 0; i < NT; i++) {
        char t[32]; snprintf(t, sizeof t, "fm%u", (unsigned)i);
        urls[i] = ueg_url(t);
        if (!ueg_make_entry(urls[i], k_types[i], ueg_days(30), ueg_days(-1), NULL, "txt", "f")) { t_skip("commit type 0x%lx failed %lu", k_types[i], GetLastError()); return; }
        CHECK(U(SetUrlCacheEntryGroupA)(urls[i], INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL));
        INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(urls[i], NULL);
        /* SPARSE entries are invisible to GetUrlCacheEntryInfo (2) [VM, urlcache_entries]: use the committed type */
        stored[i] = e ? e->CacheEntryType : k_types[i]; free(e);
        if (stored[i] != k_types[i]) t_note("committed type 0x%lx stored as 0x%lx", k_types[i], stored[i]);
    }
    for (size_t f = 0; f < NF; f++) {
        set_ctx c = { urls, (int)NT }; DWORD last = 0;
        int n = ueg_enum_ex_a("", 0, k_filters[f], g, set_cb, &c, &last);
        int want_n = 0;
        for (size_t i = 0; i < NT; i++) {
            int want = (k_filters[f] & stored[i]) == stored[i];
            want_n += want;
            CHECKF(c.hits[i] == want, "filter 0x%lx type 0x%lx: seen %d want %d", k_filters[f], stored[i], c.hits[i], want);
        }
        EXPECT_EQ(c.other, 0);
        CHECKF(n == want_n, "filter 0x%lx: %d entries want %d", k_filters[f], n, want_n);
        EXPECT_EQ(last, ERROR_NO_MORE_ITEMS);
    }
}
TEST(ueg_filter_matrix_w) {
    REQ_EX_W(); REQ_GRP();
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    const char *urls[NT]; DWORD stored[NT];
    for (size_t i = 0; i < NT; i++) {
        char t[32]; snprintf(t, sizeof t, "fmw%u", (unsigned)i);
        urls[i] = ueg_url(t);
        if (!ueg_make_entry(urls[i], k_types[i], ueg_days(30), ueg_days(-1), NULL, "txt", "f")) { t_skip("commit failed"); return; }
        CHECK(U(SetUrlCacheEntryGroupA)(urls[i], INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL));
        INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(urls[i], NULL);
        stored[i] = e ? e->CacheEntryType : k_types[i]; free(e);
    }
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap);
    for (size_t f = 0; f < NF; f++) {
        int hits[NT] = { 0 }, n = 0;
        DWORD sz = cap;
        HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", 0, k_filters[f], g, e, &sz, NULL, NULL, NULL);
        if (h) {
            do {
                n++;
                for (size_t i = 0; i < NT; i++) if (e->lpszSourceUrlName && !lstrcmpW(e->lpszSourceUrlName, ueg_w(urls[i]))) {
                    hits[i]++;
                    CHECKF(e->CacheEntryType == stored[i], "W type 0x%lx vs A 0x%lx", e->CacheEntryType, stored[i]);
                }
                sz = cap;
            } while (n < 50 && U(FindNextUrlCacheEntryExW)(h, e, &sz, NULL, NULL, NULL));
            U(FindCloseUrlCache)(h);
        } else EXPECT_ERR(ERROR_NO_MORE_ITEMS);
        int want_n = 0;
        for (size_t i = 0; i < NT; i++) {
            int want = (k_filters[f] & stored[i]) == stored[i]; want_n += want;
            CHECKF(hits[i] == want, "W filter 0x%lx type 0x%lx: seen %d want %d", k_filters[f], stored[i], hits[i], want);
        }
        EXPECT_EQ(n, want_n);
    }
    free(e);
}
/* the stored type of a committed entry */
TEST(ueg_commit_type_roundtrip) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    for (size_t i = 0; i < NT; i++) {
        char t[32]; snprintf(t, sizeof t, "ct%u", (unsigned)i);
        const char *url = ueg_url(t);
        if (!ueg_make_entry(url, k_types[i], ueg_days(30), ueg_days(-1), NULL, "txt", "t")) { CHECKF(0, "commit type 0x%lx failed %lu", k_types[i], GetLastError()); continue; }
        INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(url, NULL);
        if (k_types[i] & SPARSE_CACHE_ENTRY) {   /* hidden from GetUrlCacheEntryInfo [VM, urlcache_entries] */
            if (e) t_note("SPARSE entry visible to GetUrlCacheEntryInfoA, type 0x%lx", e->CacheEntryType);
            free(e); continue;
        }
        CHECK(e != NULL);
        if (e) { CHECKF(e->CacheEntryType == k_types[i], "type 0x%lx stored 0x%lx", k_types[i], e->CacheEntryType); free(e); }
    }
}
/* FindFirstUrlCacheEntryA uses the default filter (0x300035): an EDITED entry is invisible to it. */
TEST(ueg_plain_default_filter_hides_edited) {
    REQUIRE(U(FindFirstUrlCacheEntryA));
    const char *ue = ueg_url("edhid"), *un = ueg_url("edvis");
    if (!ueg_make_entry(ue, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, "txt", "e")) { t_skip("commit failed"); return; }
    if (!ueg_make_simple(un)) { t_skip("commit failed"); return; }
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a(NULL, ue, &n), 0);
    EXPECT_EQ(ueg_plain_contains_a(NULL, un, &n), 1);
    /* ...but the Ex API with EDITED in the filter finds it */
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER | EDITED_CACHE_ENTRY, 0, ue, &n), 1);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, 0, ue, &n), 0);
}
TEST(ueg_plain_default_filter_hides_sparse) {
    REQUIRE(U(FindFirstUrlCacheEntryA));
    const char *us = ueg_url("sphid");
    if (!ueg_make_entry(us, NORMAL_CACHE_ENTRY | SPARSE_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, "txt", "s")) { t_skip("commit failed"); return; }
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a(NULL, us, &n), 0);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER | SPARSE_CACHE_ENTRY, 0, us, &n), 1);
}

/* ------------------------------------------------------------------ FIND_FLAGS_RETREIVE_ONLY_STRUCT_INFO (0x2) */
TEST(ueg_flag_struct_only_basic) {
    REQ_EX_A();
    const char *urls[2]; GROUPID g; GROUP_OR_SKIP(g, "so", 2, urls);
    unsigned char buf[0x200]; memset(buf, 0xCC, sizeof buf);
    DWORD sz = 0x100;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_ONLY_STRUCT, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (!h) return;
    INTERNET_CACHE_ENTRY_INFOA *e = (INTERNET_CACHE_ENTRY_INFOA *)buf;
    EXPECT_ERR(0);
    EXPECT_EQ(e->dwStructSize, 0x70);
    CHECK(e->lpszSourceUrlName == NULL);
    CHECK(e->lpszLocalFileName == NULL);
    CHECK(e->lpszFileExtension == NULL);
    CHECK(e->lpHeaderInfo == NULL);
    EXPECT_EQ(e->dwSizeLow, 5);
    CHECK(e->CacheEntryType & NORMAL_CACHE_ENTRY);
    CHECK(ueg_u64(e->ExpireTime) != 0);
    EXPECT_EQ(sz, 0x100);                         /* size is not rewritten in this mode [D] */
    int z = 1; for (int i = 0x70; i < 0x100; i++) if (buf[i] != 0) z = 0;
    CHECK(z);                                     /* the whole caller buffer is zeroed first [D memset(dst,0,*size)] */
    int cc = 1; for (int i = 0x100; i < 0x200; i++) if (buf[i] != 0xCC) cc = 0;
    CHECK(cc);
    sz = 0x70; SET_ERR(0xdead);
    CHECK(U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL));
    EXPECT_EQ(sz, 0x70);
    CHECK(e->lpszSourceUrlName == NULL);
    sz = 0x70;
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
    U(FindCloseUrlCache)(h);
}
TEST(ueg_flag_struct_only_small_122_size_untouched) {
    REQ_EX_A();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "sos", 1, urls);
    static const DWORD sizes[] = { 1, 4, 0x40, 0x6c, 0x6f };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        unsigned char buf[0x100]; DWORD sz = sizes[i];
        SET_ERR(0xdead);
        HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_ONLY_STRUCT, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
        CHECKF(h == NULL, "size %lu accepted", sizes[i]);
        if (h) { U(FindCloseUrlCache)(h); continue; }
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        CHECKF(sz == sizes[i], "size %lu rewritten to %lu", sizes[i], sz);
    }
}
TEST(ueg_flag_struct_only_null_buffer_87) {
    REQ_EX_A();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "son", 1, urls);
    DWORD sz = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_ONLY_STRUCT, UEG_DEFAULT_FILTER, g, NULL, &sz, NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    if (h) U(FindCloseUrlCache)(h);
    sz = 0x200; SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_ONLY_STRUCT, UEG_DEFAULT_FILTER, g, NULL, &sz, NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    if (h) U(FindCloseUrlCache)(h);
}
TEST(ueg_flag_struct_only_w) {
    REQ_EX_W();
    const char *urls[2]; GROUPID g; GROUP_OR_SKIP(g, "sow", 2, urls);
    unsigned char buf[0x100]; memset(buf, 0xCC, sizeof buf); DWORD sz = 0x80;
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", UEG_FIND_ONLY_STRUCT, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (!h) return;
    INTERNET_CACHE_ENTRY_INFOW *e = (INTERNET_CACHE_ENTRY_INFOW *)buf;
    EXPECT_EQ(e->dwStructSize, 0x70);
    CHECK(e->lpszSourceUrlName == NULL);
    CHECK(e->lpszLocalFileName == NULL);
    EXPECT_EQ(e->dwSizeLow, 5);
    EXPECT_EQ(sz, 0x80);
    int z = 1; for (int i = 0x70; i < 0x80; i++) if (buf[i]) z = 0;
    CHECK(z);
    sz = 0x6f; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, e, &sz, NULL, NULL, NULL), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, 0x6f);
    sz = 0x70;
    CHECK(U(FindNextUrlCacheEntryExW)(h, e, &sz, NULL, NULL, NULL));
    sz = 0x70;
    EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, e, &sz, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
    U(FindCloseUrlCache)(h);
}

/* ------------------------------------------------------------------ FIND_FLAGS_RETREIVE_ONLY_FIXED_AND_FILENAME (0x4) */
TEST(ueg_flag_fixed_and_filename_a) {
    REQ_EX_A();
    const char *urls[2]; GROUPID g; GROUP_OR_SKIP(g, "ff", 2, urls);
    INTERNET_CACHE_ENTRY_INFOA *ref = ueg_info_a(urls[0], NULL);
    unsigned char buf[0x400]; memset(buf, 0xCC, sizeof buf); DWORD sz = 0x174;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_FIXED_AND_FILENAME, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (h) {
        INTERNET_CACHE_ENTRY_INFOA *e = (INTERNET_CACHE_ENTRY_INFOA *)buf;
        EXPECT_ERR(0);
        EXPECT_EQ(e->dwStructSize, 0x70);
        CHECK(e->lpszSourceUrlName == NULL);
        CHECK(e->lpszFileExtension == NULL);
        CHECK(e->lpHeaderInfo == NULL);
        CHECK(e->lpszLocalFileName == (LPSTR)(buf + 0x70));
        CHECK(e->lpszLocalFileName && GetFileAttributesA(e->lpszLocalFileName) != INVALID_FILE_ATTRIBUTES);
        EXPECT_EQ(sz, 0x174);
        int cc = 1; for (int i = 0x174; i < 0x400; i++) if (buf[i] != 0xCC) cc = 0;
        CHECK(cc);                                  /* exactly 0x174 bytes are cleared */
        EXPECT_EQ(e->dwSizeLow, 5);
        sz = 0x174;
        CHECK(U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL));
        CHECK(e->lpszLocalFileName == (LPSTR)(buf + 0x70));
        int matched = 0;
        if (ref && ref->lpszLocalFileName && e->lpszLocalFileName) matched = !strcmp(ref->lpszLocalFileName, e->lpszLocalFileName);
        sz = 0x174;
        EXPECT_FAIL(!U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
        U(FindCloseUrlCache)(h);
        (void)matched;
    }
    free(ref);
}
TEST(ueg_flag_fixed_and_filename_small_122) {
    REQ_EX_A();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "ffs", 1, urls);
    static const DWORD sizes[] = { 0x70, 0x100, 0x173 };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        unsigned char buf[0x200]; DWORD sz = sizes[i];
        SET_ERR(0xdead);
        HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_FIXED_AND_FILENAME, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
        CHECKF(h == NULL, "size 0x%lx accepted", sizes[i]);
        if (h) { U(FindCloseUrlCache)(h); continue; }
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(sz, sizes[i]);
    }
    DWORD sz = 0; SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_FIXED_AND_FILENAME, UEG_DEFAULT_FILTER, g, NULL, &sz, NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    if (h) U(FindCloseUrlCache)(h);
}
TEST(ueg_flag_both_bits_fixed_wins) {
    REQ_EX_A();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "fb", 1, urls);
    unsigned char buf[0x200]; DWORD sz = 0x100;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_ONLY_STRUCT | UEG_FIND_FIXED_AND_FILENAME, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INSUFFICIENT_BUFFER);   /* 0x4 is checked first: needs 0x174 */
    if (h) U(FindCloseUrlCache)(h);
    sz = 0x174;
    h = U(FindFirstUrlCacheEntryExA)("", UEG_FIND_ONLY_STRUCT | UEG_FIND_FIXED_AND_FILENAME, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszLocalFileName == (LPSTR)(buf + 0x70)); U(FindCloseUrlCache)(h); }
}
TEST(ueg_flag_fixed_and_filename_w) {
    REQ_EX_W();
    const char *urls[1]; GROUPID g; GROUP_OR_SKIP(g, "ffw", 1, urls);
    unsigned char buf[0x400]; memset(buf, 0xCC, sizeof buf); DWORD sz = 0x300;
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", UEG_FIND_FIXED_AND_FILENAME, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL);
    if (!h) { t_note("W FIXED_AND_FILENAME with 0x300 bytes: err %lu size %lu", GetLastError(), sz); }
    else {
        INTERNET_CACHE_ENTRY_INFOW *e = (INTERNET_CACHE_ENTRY_INFOW *)buf;
        EXPECT_EQ(e->dwStructSize, 0x70);
        CHECK(e->lpszSourceUrlName == NULL);
        t_note("W FIXED_AND_FILENAME: local=%p (buf+0x70=%p) size=%lu", e->lpszLocalFileName, buf + 0x70, sz);
        U(FindCloseUrlCache)(h);
    }
}

/* ------------------------------------------------------------------ the flags of FindFirstUrlCacheEntryA (1) */
/* Ex with pattern "" and flags 0 enumerates the content container only; flags 1 continues into the other
 * containers [D GetInitialUrlCacheEntryFindHandleHelper: state -1 vs 0]. A history (visited:) entry tells them apart. */
TEST(ueg_flag1_spans_containers) {
    REQ_EX_A(); REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(DeleteUrlCacheEntryA));
    char vurl[300]; snprintf(vurl, sizeof vurl, "Visited: %s@%s", t_uniq("vu"), t_uniq_cache_url("vis"));
    t_cache_track(vurl);
    if (!U(CommitUrlCacheEntryA)(vurl, NULL, ueg_days(30), ueg_days(-1), URLHISTORY_CACHE_ENTRY | NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL)) {
        t_skip("history commit failed %lu", GetLastError()); return;
    }
    int n0 = 0, n1 = 0, nv = 0;
    int in0 = ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, 0, vurl, &n0);
    int in1 = ueg_enum_contains_a("", 1, UEG_DEFAULT_FILTER, 0, vurl, &n1);
    int inv = ueg_enum_contains_a("visited:", 0, UEG_DEFAULT_FILTER, 0, vurl, &nv);
    EXPECT_EQ(in0, 0);
    EXPECT_EQ(inv, 1);
    t_note("'' flags0: %d entries (has visited %d); flags1: %d entries (has visited %d); visited: %d", n0, in0, n1, in1, nv);
    CHECK(n1 >= n0);
    CHECK(U(DeleteUrlCacheEntryA)(vurl));
}
TEST(ueg_visited_pattern_case_insensitive) {
    REQ_EX_A(); REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(DeleteUrlCacheEntryA));
    char vurl[300]; snprintf(vurl, sizeof vurl, "Visited: %s@%s", t_uniq("vc"), t_uniq_cache_url("visc"));
    t_cache_track(vurl);
    if (!U(CommitUrlCacheEntryA)(vurl, NULL, ueg_days(30), ueg_days(-1), URLHISTORY_CACHE_ENTRY | NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL)) {
        t_skip("history commit failed %lu", GetLastError()); return;
    }
    static const char *pats[] = { "visited:", "Visited:", "VISITED:" };
    for (int i = 0; i < 3; i++) {
        int n = 0, in = ueg_enum_contains_a(pats[i], 0, UEG_DEFAULT_FILTER, 0, vurl, &n);
        CHECKF(in == 1, "pattern %s: %d (of %d)", pats[i], in, n);
    }
    /* the plain API also finds it, through every container */
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a(NULL, vurl, &n), 1);
    EXPECT_EQ(ueg_plain_contains_a("visited:", vurl, &n), 1);
    CHECK(U(DeleteUrlCacheEntryA)(vurl));
    EXPECT_EQ(ueg_plain_contains_a("visited:", vurl, &n), 0);
}
/* A pattern that starts with ':' and names no container yields ERROR_NO_MORE_ITEMS [D GetContainer returns 1]. */
TEST(ueg_colon_pattern_unknown_container_259) {
    REQ_EX_A(); REQUIRE(U(FindFirstUrlCacheEntryA));
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)(":ueg_no_such_container:", 0, UEG_DEFAULT_FILTER, 0, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    DWORD e = GetLastError();
    if (h) { t_note("':' pattern returned an entry: %s", ((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszSourceUrlName); U(FindCloseUrlCache)(h); }
    CHECK(h == NULL);
    CHECKF(e == ERROR_NO_MORE_ITEMS, "err %lu", e);
    sz = sizeof buf; SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryA)(":ueg_no_such_container:", (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz);
    e = GetLastError();
    if (h) U(FindCloseUrlCache)(h);
    t_note("plain ':' pattern: handle=%p err=%lu", h, e);
}

/* ------------------------------------------------------------------ cookies through the enumeration API */
TEST(ueg_cookie_pattern_sees_persistent_cookie) {
    REQ_EX_A(); REQUIRE(U(InternetSetCookieA)); REQUIRE(U(FindFirstUrlCacheEntryA));
    const char *host = t_uniq_host("ck");
    char url[300]; snprintf(url, sizeof url, "http://%s/ueg/", host);
    t_cookie_track(url, "uegc");
    if (!U(InternetSetCookieA)(url, "uegc", "v1; expires=Sat, 01-Jan-2050 00:00:00 GMT")) { t_skip("InternetSetCookieA failed %lu", GetLastError()); return; }
    int n = 0;
    int f = ueg_plain_contains_a("cookie:", host, &n);
    int fall = ueg_plain_contains_a(NULL, host, &n);
    int fex = 0, nex = 0;
    fex = ueg_enum_contains_a("cookie:", 0, UEG_DEFAULT_FILTER, 0, "", &nex);   /* count only */
    t_note("persistent cookie on %s: 'cookie:' sees it %d, NULL sees it %d, 'cookie:' Ex count %d", host, f, fall, nex);
    CHECK(f >= 1);
    CHECK(fall >= 1);          /* NULL pattern walks content, then the other containers */
    (void)fex;
}
typedef struct { const char *needle; int hits; DWORD types; } sub_ctx;
static int sub_cb(const INTERNET_CACHE_ENTRY_INFOA *e, DWORD size, void *c_) {
    sub_ctx *c = c_; (void)size;
    if (e->lpszSourceUrlName && strstr(e->lpszSourceUrlName, c->needle)) { c->hits++; c->types |= e->CacheEntryType; }
    return 1;
}
TEST(ueg_cookie_entry_shape) {
    REQ_EX_A(); REQUIRE(U(InternetSetCookieA));
    const char *host = t_uniq_host("cks");
    char url[300]; snprintf(url, sizeof url, "http://%s/p/", host);
    t_cookie_track(url, "uegs");
    if (!U(InternetSetCookieA)(url, "uegs", "v; expires=Sat, 01-Jan-2050 00:00:00 GMT")) { t_skip("InternetSetCookieA failed %lu", GetLastError()); return; }
    sub_ctx c = { host, 0, 0 }; DWORD last = 0;
    ueg_enum_ex_a("cookie:", 0, UEG_DEFAULT_FILTER, 0, sub_cb, &c, &last);
    CHECK(c.hits >= 1);
    if (c.hits) CHECKF(c.types & COOKIE_CACHE_ENTRY, "cookie entry type 0x%lx", c.types);
    sub_ctx c0 = { host, 0, 0 };
    ueg_enum_ex_a("", 0, UEG_DEFAULT_FILTER, 0, sub_cb, &c0, &last);
    EXPECT_EQ(c0.hits, 0);                         /* content container only */
    sub_ctx c1 = { host, 0, 0 };
    ueg_enum_ex_a("cookie:", 0, NORMAL_CACHE_ENTRY, 0, sub_cb, &c1, &last);
    t_note("cookie entry type 0x%lx; NORMAL-only filter over cookie: hits %d", c.types, c1.hits);
}
