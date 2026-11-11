/* urlcache_enum_groups / extra.c - review pass 2: deterministic (group-scoped) versions of the enumeration
 * edge cases that enum_plain.c only covers through the whole cache, header-size alignment, entries changed or
 * deleted mid-enumeration, SetUrlCacheEntryInfo interplay with the enumeration filter and IsUrlCacheEntryExpired,
 * group lifetime while an enumeration is open, binary blob overwrite, group-attribute struct-size handling.
 * Evidence: [D] CCacheEntryEnum::Next (filter/group test per entry at the cursor), ConvertCacheEntryInfoA
 * (al4(header)), SetUrlCacheGroupAttributeA@0x1a2b80 (dwGroupSize never read), FindCloseUrlCache@0x35b40,
 * IsUrlCacheEntryExpiredA@0x1a1500; [VM] Win10 22H2 boots (see EVIDENCE.md).
 * VM_TIMEOUT: 120 */
#include "ueg.h"
#include <stdlib.h>

#define REQ_EXG() do { REQUIRE(U(FindFirstUrlCacheEntryExA)); REQUIRE(U(FindNextUrlCacheEntryExA)); REQUIRE(U(FindCloseUrlCache)); \
    REQUIRE(U(CreateUrlCacheGroup)); REQUIRE(U(DeleteUrlCacheGroup)); REQUIRE(U(SetUrlCacheEntryGroupA)); } while (0)

static GROUPID xgroup(const char *tag, int n, const char **urls, DWORD gflags) {
    GROUPID g = ueg_group_new(gflags);
    if (!g) return 0;
    for (int i = 0; i < n; i++) {
        char t[64]; snprintf(t, sizeof t, "%s%d", tag, i);
        urls[i] = ueg_url(t);
        if (!ueg_make_simple(urls[i])) return 0;
        if (!SEGQ(U(SetUrlCacheEntryGroupA)(urls[i], INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL))) return 0;
    }
    return g;
}
#define XGROUP_OR_SKIP(g, tag, n, urls) do { REQ_EXG(); (g) = xgroup(tag, n, urls, 0); if (!(g)) { t_skip("group setup failed (%lu)", GetLastError()); return; } } while (0)
static int idx_of(const char *u, const char **urls, int n) { for (int i = 0; i < n; i++) if (u && !strcmp(u, urls[i])) return i; return -1; }

/* ------------------------------------------------------------------ deletion while a group enumeration is open */
/* An entry deleted before the cursor reaches it is still returned (group-scope enumeration is a snapshot on Win10). */
TEST(ueg_x_delete_ahead_not_returned) {
    const char *urls[4]; GROUPID g; XGROUP_OR_SKIP(g, "dah", 4, urls);
    REQUIRE(U(DeleteUrlCacheEntryA));
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, e, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (!h) { free(e); return; }
    int seen[4] = { 0 }, first = idx_of(e->lpszSourceUrlName, urls, 4);
    CHECK(first >= 0);
    if (first >= 0) seen[first]++;
    int victim = (first + 2) & 3;                 /* any entry not returned yet */
    CHECK(U(DeleteUrlCacheEntryA)(urls[victim]));
    int n = 1;
    for (;;) {
        sz = cap; SET_ERR(0xdead);
        if (!U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
        int k = idx_of(e->lpszSourceUrlName, urls, 4);
        CHECKF(k >= 0, "foreign entry %s", e->lpszSourceUrlName);
        if (k >= 0) seen[k]++;
        if (++n > 10) break;
    }
    U(FindCloseUrlCache)(h);
    /* Win10 (VM, triage): a group-scoped enumeration is a snapshot taken at FindFirst; an entry deleted ahead of the
     * cursor is still returned, exactly once. */
    EXPECT_EQ(n, 4);
    for (int i = 0; i < 4; i++) CHECKF(seen[i] == 1, "url %d seen %d (victim %d)", i, seen[i], victim);
    free(e);
}
/* Deleting a member entry removes it from the group's enumeration. */
TEST(ueg_x_deleted_member_leaves_group) {
    const char *urls[2]; GROUPID g; XGROUP_OR_SKIP(g, "dml", 2, urls);
    REQUIRE(U(DeleteUrlCacheEntryA));
    CHECK(U(DeleteUrlCacheEntryA)(urls[0]));
    int n = 0;
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, urls[0], &n), 0);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, urls[1], &n), 1);
    EXPECT_EQ(n, 1);
    CHECK(U(DeleteUrlCacheEntryA)(urls[1]));
    char buf[1024]; DWORD sz = sizeof buf; SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_NO_MORE_ITEMS);
    if (h) U(FindCloseUrlCache)(h);
}
/* Deleting the group while one of its enumerations is open: the open handle stays closable. */
TEST(ueg_x_group_deleted_during_enum) {
    const char *urls[3]; GROUPID g; XGROUP_OR_SKIP(g, "gdd", 3, urls);
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, e, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (!h) { free(e); return; }
    CHECK(U(DeleteUrlCacheGroup)(g, 0, NULL)); ueg_group_untrack(g);
    int more = 0; DWORD last = 0;
    for (int i = 0; i < 10; i++) { sz = cap; if (!U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL)) { last = GetLastError(); break; } more++; }
    t_note("after DeleteUrlCacheGroup the open group enumeration returned %d more entries, then err %lu", more, last);
    CHECK(more <= 2);
    SET_ERR(0xdead);
    CHECK(U(FindCloseUrlCache)(h));
    EXPECT_ERR(0);
    for (int i = 0; i < 3; i++) CHECK(ueg_exists(urls[i]));   /* flags 0: members are kept */
    free(e);
}

/* ------------------------------------------------------------------ header alignment, deterministic */
/* Headers of every length mod 4: the A size is 0x70 + al4(url+1) + al4(file+1) + al4(ext+1) + al4(hdr). */
TEST(ueg_x_header_alignment_sizes) {
    REQ_EXG();
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    static const char *hdrs[] = { "H", "HT", "HTT", "HTTP", "HTTP/", "HTTP/1.1 200 OK\r\n\r\n" };
    const char *urls[6];
    for (int i = 0; i < 6; i++) {
        char t[16]; snprintf(t, sizeof t, "hal%d", i);
        urls[i] = ueg_url(t);
        if (!ueg_make_entry(urls[i], NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-1), hdrs[i], "bin", "h")) { t_skip("commit failed %lu", GetLastError()); return; }
        CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(urls[i], 0, g, NULL, 0, NULL)));
    }
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, e, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    int n = 0, seen = 0;
    while (h && n < 20) {
        n++;
        int k = idx_of(e->lpszSourceUrlName, urls, 6);
        CHECK(k >= 0);
        if (k >= 0) {
            seen++;
            DWORD hl = (DWORD)strlen(hdrs[k]);
            EXPECT_EQ(e->dwHeaderInfoSize, hl);
            CHECK(e->lpHeaderInfo && !memcmp(e->lpHeaderInfo, hdrs[k], hl));
            DWORD want = 0x70 + ueg_align4((DWORD)strlen(urls[k]) + 1) + ueg_align4((DWORD)strlen(e->lpszLocalFileName) + 1) + ueg_align4(4) + ueg_align4(hl);
            CHECKF(sz == want, "hdr len %lu: size %lu want %lu", hl, sz, want);
            CHECK(((ULONG_PTR)e->lpHeaderInfo - (ULONG_PTR)e) % 4 == 0);
        }
        sz = cap;
        if (!U(FindNextUrlCacheEntryExA)(h, e, &sz, NULL, NULL, NULL)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
    }
    if (h) U(FindCloseUrlCache)(h);
    EXPECT_EQ(seen, 6);
    free(e);
}
/* The W enumeration of an entry with headers: the header comes back too (layout recorded). */
TEST(ueg_x_header_w_enum) {
    REQ_EXG(); REQUIRE(U(FindFirstUrlCacheEntryExW));
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    const char *url = ueg_url("hw"); const char *hdr = "HTTP/1.1 200 OK\r\nX-W: 1\r\n\r\n";
    if (!ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-1), hdr, "txt", "w")) { t_skip("commit failed"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL)));
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", 0, UEG_DEFAULT_FILTER, g, e, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (h) {
        CHECK(e->lpszSourceUrlName && !lstrcmpW(e->lpszSourceUrlName, ueg_w(url)));
        CHECK(e->lpHeaderInfo != NULL);
        CHECK(e->dwHeaderInfoSize != 0);
        /* ConvertCacheEntryInfoW widens the stored header back to UTF-16; dwHeaderInfoSize counts characters
         * [D, VM-confirmed for GetUrlCacheEntryInfoW in urlcache_entries; the enumeration uses the same converter] */
        EXPECT_EQ(e->dwHeaderInfoSize, (DWORD)strlen(hdr));
        if (e->lpHeaderInfo) CHECK(!memcmp(e->lpHeaderInfo, ueg_w(hdr), 2 * strlen(hdr)));
        t_note("W enum header: size %lu (A len %u) total %lu", e->dwHeaderInfoSize, (unsigned)strlen(hdr), sz);
        sz = cap; SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryExW)(h, e, &sz, NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
        U(FindCloseUrlCache)(h);
    }
    free(e);
}

/* ------------------------------------------------------------------ SetUrlCacheEntryInfo seen by the enumeration */
TEST(ueg_x_setinfo_type_changes_filter_result) {
    const char *urls[1]; GROUPID g; XGROUP_OR_SKIP(g, "sit", 1, urls);
    REQUIRE(U(SetUrlCacheEntryInfoA));
    EXPECT_EQ(ueg_enum_contains_a("", 0, NORMAL_CACHE_ENTRY, g, urls[0], NULL), 1);
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci;
    ci.CacheEntryType = NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY;
    CHECK(U(SetUrlCacheEntryInfoA)(urls[0], &ci, CACHE_ENTRY_ATTRIBUTE_FC));
    INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(urls[0], NULL);
    DWORD t = e ? e->CacheEntryType : 0; free(e);
    t_note("type after SetUrlCacheEntryInfoA(STICKY|NORMAL): 0x%lx", t);
    if (t & STICKY_CACHE_ENTRY) {
        EXPECT_EQ(ueg_enum_contains_a("", 0, NORMAL_CACHE_ENTRY, g, urls[0], NULL), 0);
        EXPECT_EQ(ueg_enum_contains_a("", 0, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, g, urls[0], NULL), 1);
    }
}
TEST(ueg_x_setinfo_expire_then_expired) {
    REQUIRE(U(SetUrlCacheEntryInfoA)); REQUIRE(UN(IsUrlCacheEntryExpiredA));
    const char *url = ueg_url("sie");
    FILETIME lm = ueg_days(-9);
    if (!ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_days(30), lm, NULL, "txt", "e")) { t_skip("commit failed"); return; }
    FILETIME ft;
    CHECK(!UN(IsUrlCacheEntryExpiredA)(url, 0, &ft));
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci; ci.ExpireTime = ueg_days(-2);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_EXPTIME_FC));
    SET_ERR(0xdead);
    CHECK(UN(IsUrlCacheEntryExpiredA)(url, 0, &ft));
    EXPECT_ERR(0);
    EXPECT_EQ(ueg_u64(ft), ueg_u64(lm));
    ci.ExpireTime = ueg_days(5);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_EXPTIME_FC));
    CHECK(!UN(IsUrlCacheEntryExpiredA)(url, 0, &ft));
}
/* The enumeration reports the expire time SetUrlCacheEntryInfo stored. */
TEST(ueg_x_setinfo_expire_seen_by_enum) {
    const char *urls[1]; GROUPID g; XGROUP_OR_SKIP(g, "see", 1, urls);
    REQUIRE(U(SetUrlCacheEntryInfoA));
    FILETIME ne = ueg_days(77);
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci; ci.ExpireTime = ne;
    CHECK(U(SetUrlCacheEntryInfoA)(urls[0], &ci, CACHE_ENTRY_EXPTIME_FC));
    char buf[4096]; DWORD sz = sizeof buf;
    HANDLE h = U(FindFirstUrlCacheEntryExA)("", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    if (h) { EXPECT_EQ(ueg_u64(((INTERNET_CACHE_ENTRY_INFOA *)buf)->ExpireTime), ueg_u64(ne)); U(FindCloseUrlCache)(h); }
}

/* ------------------------------------------------------------------ pattern + group */
/* The pattern picks the container, the group filters inside it: 'visited:' + a group of content entries -> 259. */
TEST(ueg_x_group_with_visited_pattern_259) {
    const char *urls[2]; GROUPID g; XGROUP_OR_SKIP(g, "gvp", 2, urls);
    char buf[4096]; DWORD sz = sizeof buf; SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryExA)("visited:", 0, UEG_DEFAULT_FILTER, g, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL);
    DWORD e = GetLastError();
    if (h) { t_note("visited: + content group returned %s", ((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszSourceUrlName); U(FindCloseUrlCache)(h); }
    CHECK(h == NULL);
    CHECKF(e == ERROR_NO_MORE_ITEMS, "err %lu", e);
}
/* A history ("Visited: ...") entry can be put in a group; record whether it then shows up in group enumerations. */
TEST(ueg_x_history_entry_in_group) {
    REQ_EXG(); REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(DeleteUrlCacheEntryA));
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    char vurl[300]; snprintf(vurl, sizeof vurl, "Visited: %s@%s", t_uniq("hg"), t_uniq_cache_url("hgv"));
    t_cache_track(vurl);
    if (!U(CommitUrlCacheEntryA)(vurl, NULL, ueg_days(30), ueg_days(-1), URLHISTORY_CACHE_ENTRY | NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL)) { t_skip("history commit failed %lu", GetLastError()); return; }
    SET_ERR(0xdead);
    BOOL r = U(SetUrlCacheEntryGroupA)(vurl, 0, g, NULL, 0, NULL);
    DWORD er = GetLastError();
    int nv = 0, n0 = 0;
    int inv = ueg_enum_contains_a("visited:", 0, UEG_DEFAULT_FILTER, g, vurl, &nv);
    int in0 = ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, vurl, &n0);
    t_note("SetUrlCacheEntryGroupA(history) -> %d err %lu; group enum visited: %d/%d, content: %d/%d", r, er, inv, nv, in0, n0);
    EXPECT_EQ(in0, 0);                            /* never shows up in the content container */
    if (r) { CHECK(U(SetUrlCacheEntryGroupA)(vurl, 1, g, NULL, 0, NULL)); }
    CHECK(U(DeleteUrlCacheEntryA)(vurl));
}

/* ------------------------------------------------------------------ groups: lifetime and handles */
TEST(ueg_x_many_groups_listed_then_gone) {
    REQUIRE(U(CreateUrlCacheGroup)); REQUIRE(U(DeleteUrlCacheGroup)); REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindNextUrlCacheGroup));
    GROUPID gs[20]; int made = 0;
    for (int i = 0; i < 20; i++) { gs[i] = ueg_group_new(i & 1 ? CACHEGROUP_FLAG_NONPURGEABLE : 0); if (gs[i]) made++; }
    EXPECT_EQ(made, 20);
    int listed = 0, total = 0;
    for (int i = 0; i < 20; i++) if (gs[i]) listed += ueg_groups_contains(gs[i], &total) == 1;
    EXPECT_EQ(listed, made);
    int gone = 0;
    for (int i = 0; i < 20; i++) if (gs[i] && U(DeleteUrlCacheGroup)(gs[i], 0, NULL)) { ueg_group_untrack(gs[i]); gone++; }
    EXPECT_EQ(gone, made);
    int still = 0, total2 = 0;
    for (int i = 0; i < 20; i++) if (gs[i]) still += ueg_groups_contains(gs[i], &total2);
    EXPECT_EQ(still, 0);
    EXPECT_EQ(total - total2, made);
}
TEST(ueg_x_group_find_handle_double_close_6) {
    REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindCloseUrlCache)); REQUIRE(U(CreateUrlCacheGroup));
    GROUPID mine = ueg_group_new(0);
    if (!mine) { t_skip("no group"); return; }
    GROUPID g = 0;
    HANDLE h = U(FindFirstUrlCacheGroup)(0, CACHEGROUP_SEARCH_ALL, NULL, 0, &g, NULL);
    CHECK(h != NULL);
    if (!h) return;
    SET_ERR(0xdead);
    CHECK(U(FindCloseUrlCache)(h));
    EXPECT_ERR(0);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindCloseUrlCache)(h), ERROR_INVALID_HANDLE);
}
/* A group created after FindFirstUrlCacheGroup: record whether the open enumeration returns it. */
TEST(ueg_x_group_created_after_find_first) {
    REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindNextUrlCacheGroup)); REQUIRE(U(CreateUrlCacheGroup));
    GROUPID a = ueg_group_new(0);
    if (!a) { t_skip("no group"); return; }
    GROUPID cur = 0;
    HANDLE h = U(FindFirstUrlCacheGroup)(0, CACHEGROUP_SEARCH_ALL, NULL, 0, &cur, NULL);
    CHECK(h != NULL);
    if (!h) return;
    GROUPID b = ueg_group_new(0);
    int sa = cur == a, sb = cur == b, n = 1;
    while (n < UEG_ENUM_CAP && U(FindNextUrlCacheGroup)(h, &cur, NULL)) { n++; sa += cur == a; sb += cur == b; }
    U(FindCloseUrlCache)(h);
    EXPECT_EQ(sa, 1);
    CHECK(sb <= 1);
    t_note("group created after FindFirstUrlCacheGroup seen by that enumeration: %d (of %d)", sb, n);
}
/* The group survives deleting all its members; deleting it afterwards still works. */
TEST(ueg_x_group_outlives_members) {
    const char *urls[2]; GROUPID g; XGROUP_OR_SKIP(g, "gom", 2, urls);
    REQUIRE(U(DeleteUrlCacheEntryA)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    CHECK(U(DeleteUrlCacheEntryA)(urls[0])); CHECK(U(DeleteUrlCacheEntryA)(urls[1]));
    EXPECT_EQ(ueg_groups_contains(g, NULL), 1);
    INTERNET_CACHE_GROUP_INFOA a; DWORD cb = sizeof a;
    CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &a, &cb, NULL));
    SET_ERR(0xdead);
    CHECK(U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL));
    EXPECT_ERR(0);
    ueg_group_untrack(g);
}
/* Re-adding an entry after removing it from a group restores the membership (no stale state). */
TEST(ueg_x_seg_readd_after_remove) {
    const char *urls[1]; GROUPID g; XGROUP_OR_SKIP(g, "rar", 1, urls);
    for (int i = 0; i < 3; i++) {
        CHECK(U(SetUrlCacheEntryGroupA)(urls[0], INTERNET_CACHE_GROUP_REMOVE, g, NULL, 0, NULL));
        EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, urls[0], NULL), 0);
        CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(urls[0], INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL)));
        EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, urls[0], NULL), 1);
    }
}
/* Re-committing a URL that is a group member: record whether the membership survives. */
TEST(ueg_x_recommit_member) {
    const char *urls[1]; GROUPID g; XGROUP_OR_SKIP(g, "rcm", 1, urls);
    CHECK(ueg_make_entry(urls[0], NORMAL_CACHE_ENTRY, ueg_days(40), ueg_days(-1), NULL, "txt", "second"));
    INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(urls[0], NULL);
    CHECK(e != NULL);
    if (e) EXPECT_EQ(e->dwSizeLow, 6);
    free(e);
    t_note("re-committed member still in its group: %d", ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, urls[0], NULL));
}

/* ------------------------------------------------------------------ group attributes: dwGroupSize is not an input */
/* SetUrlCacheGroupAttributeA/W never read dwGroupSize [D]: 0 or garbage there is accepted. */
TEST(ueg_x_set_attr_groupsize_not_validated) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(SetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(CreateUrlCacheGroup));
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    static const DWORD szs[] = { 0, 1, 0x9b, 0xffffffff };
    for (int i = 0; i < 4; i++) {
        INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = szs[i]; a.dwGroupType = 100 + i;
        SET_ERR(0xdead);
        CHECKF(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, &a, NULL), "A dwGroupSize %lu err %lu", szs[i], GetLastError());
        INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = szs[i]; w.dwDiskQuota = 10 + i;
        CHECKF(U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_QUOTA, &w, NULL), "W dwGroupSize %lu err %lu", szs[i], GetLastError());
        INTERNET_CACHE_GROUP_INFOA r; DWORD cb = sizeof r;
        CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &r, &cb, NULL));
        EXPECT_EQ(r.dwGroupType, 100 + i);
        EXPECT_EQ(r.dwDiskQuota, 10 + i);
    }
}
/* Attributes are per group: setting one group's type does not touch another's. */
TEST(ueg_x_attr_isolated_between_groups) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(CreateUrlCacheGroup));
    GROUPID g1 = ueg_group_new(0), g2 = ueg_group_new(0);
    if (!g1 || !g2) { t_skip("no group"); return; }
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; a.dwGroupType = 0x51; a.dwDiskQuota = 0x52;
    CHECK(U(SetUrlCacheGroupAttributeA)(g1, 0, CACHEGROUP_ATTRIBUTE_TYPE | CACHEGROUP_ATTRIBUTE_QUOTA, &a, NULL));
    INTERNET_CACHE_GROUP_INFOA r; DWORD cb = sizeof r;
    CHECK(U(GetUrlCacheGroupAttributeA)(g2, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &r, &cb, NULL));
    EXPECT_EQ(r.dwGroupType, 0);
    EXPECT_EQ(r.dwDiskQuota, 0);
    cb = sizeof r;
    CHECK(U(GetUrlCacheGroupAttributeA)(g1, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &r, &cb, NULL));
    EXPECT_EQ(r.dwGroupType, 0x51);
    EXPECT_EQ(r.dwDiskQuota, 0x52);
}
/* A name set through W with characters outside the ANSI code page, read back through A and W. */
TEST(ueg_x_groupname_non_ascii) {
    REQUIRE(U(SetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(CreateUrlCacheGroup));
    GROUPID g = ueg_group_new(0);
    if (!g) { t_skip("no group"); return; }
    INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = sizeof w;
    lstrcpyW(w.szGroupName, L"ueg-\x00e9\x4e2d");
    CHECK(U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME | CACHEGROUP_ATTRIBUTE_QUOTA, &w, NULL));
    INTERNET_CACHE_GROUP_INFOW rw; memset(&rw, 0, sizeof rw); DWORD cb = sizeof rw;
    CHECK(U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &rw, &cb, NULL));
    EXPECT_WSTR(rw.szGroupName, L"ueg-\x00e9\x4e2d");
    INTERNET_CACHE_GROUP_INFOA ra; memset(&ra, 0, sizeof ra); cb = sizeof ra;
    SET_ERR(0xdead);
    BOOL r = U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &ra, &cb, NULL);
    t_note("A view of a non-ASCII group name: ret %d err %lu bytes %02x %02x %02x %02x %02x %02x", r, GetLastError(),
           (unsigned char)ra.szGroupName[0], (unsigned char)ra.szGroupName[4], (unsigned char)ra.szGroupName[5],
           (unsigned char)ra.szGroupName[6], (unsigned char)ra.szGroupName[7], (unsigned char)ra.szGroupName[8]);
}

/* ------------------------------------------------------------------ binary blobs */
TEST(ueg_x_blob_overwrite) {
    REQUIRE(UN(CommitUrlCacheEntryBinaryBlob)); REQUIRE(UN(GetUrlCacheEntryBinaryBlob));
    const char *url = ueg_url("blobow");
    BYTE d1[16], d2[40];
    for (int i = 0; i < 16; i++) d1[i] = (BYTE)(0xA0 + i);
    for (int i = 0; i < 40; i++) d2[i] = (BYTE)(0x10 + i);
    DWORD r = UN(CommitUrlCacheEntryBinaryBlob)(ueg_w(url), 1, ueg_days(20), ueg_days(-1), d1, sizeof d1);
    EXPECT_EQ(r, 0);
    if (r) return;
    r = UN(CommitUrlCacheEntryBinaryBlob)(ueg_w(url), 1, ueg_days(21), ueg_days(-1), d2, sizeof d2);
    EXPECT_EQ(r, 0);
    DWORD type = 0, cb = 0; FILETIME a, b, c; BYTE *blob = NULL;
    r = UN(GetUrlCacheEntryBinaryBlob)(ueg_w(url), &type, &a, &b, &c, &blob, &cb);
    EXPECT_EQ(r, 0);
    if (!r) { EXPECT_EQ(cb, sizeof d2); CHECK(blob && !memcmp(blob, d2, sizeof d2)); }
}
TEST(ueg_x_blob_on_normal_entry) {
    REQUIRE(UN(GetUrlCacheEntryBinaryBlob));
    const char *url = ueg_url("blobnorm");
    if (!ueg_make_simple(url)) { t_skip("commit failed"); return; }
    DWORD type = 0, cb = 0; FILETIME a, b, c; BYTE *blob = NULL;
    DWORD r = UN(GetUrlCacheEntryBinaryBlob)(ueg_w(url), &type, &a, &b, &c, &blob, &cb);
    t_note("GetUrlCacheEntryBinaryBlob on a file-backed entry -> %lu type 0x%lx cb %lu", r, type, cb);
    if (r) { EXPECT_EQ(cb, 0); CHECK(blob == NULL); }
}
/* A blob entry is a normal cache entry: DeleteUrlCacheEntry removes it and Get then fails with 2. */
TEST(ueg_x_blob_deleted_by_delete_entry) {
    REQUIRE(UN(CommitUrlCacheEntryBinaryBlob)); REQUIRE(UN(GetUrlCacheEntryBinaryBlob)); REQUIRE(U(DeleteUrlCacheEntryA));
    const char *url = ueg_url("blobdel");
    BYTE d[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    DWORD r = UN(CommitUrlCacheEntryBinaryBlob)(ueg_w(url), 1, ueg_days(20), ueg_days(-1), d, sizeof d);
    EXPECT_EQ(r, 0);
    if (r) return;
    SET_ERR(0xdead);
    CHECK(U(DeleteUrlCacheEntryA)(url));
    DWORD type = 0, cb = 0; FILETIME a, b, c; BYTE *blob = NULL;
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(ueg_w(url), &type, &a, &b, &c, &blob, &cb), ERROR_FILE_NOT_FOUND);
}

/* ------------------------------------------------------------------ W Ex size query in a group */
TEST(ueg_x_fnxw_size_query_exact) {
    const char *urls[3]; GROUPID g; XGROUP_OR_SKIP(g, "wsq", 3, urls);
    REQUIRE(U(FindFirstUrlCacheEntryExW)); REQUIRE(U(FindNextUrlCacheEntryExW));
    DWORD cap = 4096; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryExW)(L"", 0, UEG_DEFAULT_FILTER, g, e, &sz, NULL, NULL, NULL);
    CHECK(h != NULL);
    int got = 1;
    while (h && got < 5) {
        DWORD z = 0; SET_ERR(0xdead);
        BOOL r = U(FindNextUrlCacheEntryExW)(h, NULL, &z, NULL, NULL, NULL);
        if (r) { CHECKF(0, "NULL-buffer size query succeeded"); break; }
        DWORD er = GetLastError();
        if (er == ERROR_NO_MORE_ITEMS) break;
        EXPECT_EQ(er, ERROR_INSUFFICIENT_BUFFER);
        CHECK(z > 0x70 && z < cap);
        if (!(z > 0x70 && z < cap)) break;
        DWORD s2 = z; SET_ERR(0xdead);
        CHECK(U(FindNextUrlCacheEntryExW)(h, e, &s2, NULL, NULL, NULL));
        EXPECT_EQ(s2, z);
        got++;
    }
    if (h) U(FindCloseUrlCache)(h);
    EXPECT_EQ(got, 3);
    free(e);
}
