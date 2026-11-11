/* urlcache_enum_groups / groups.c - CreateUrlCacheGroup, DeleteUrlCacheGroup, FindFirst/NextUrlCacheGroup,
 * Get/SetUrlCacheGroupAttributeA/W, SetUrlCacheEntryGroup[A/W].
 * Every group created here is deleted (explicitly, or by the atexit registry in ueg.c).
 * Evidence: [D] CreateUrlCacheGroup@0x19f8b0 (flags & ~7 -> 87, reserved -> 87), CCacheClientContainer::CreateGroup
 * (GIDONLY 4 -> id only, NONPURGEABLE 1 -> high bit 0x1000000000000000), CContainerProps::CreateGroup/DeleteGroup/
 * FindGroup/UpdateGroup/GetGroup, DeleteUrlCacheGroup@0x19fb20, FindFirstUrlCacheGroup@0x19ff20,
 * FindNextUrlCacheGroup@0x1a0400, GetUrlCacheGroupAttributeA@0x1a1080 / W@0x1a12d0 (*cb = 0x9c / 0x114 always),
 * SetUrlCacheGroupAttributeA@0x1a2b80 / W, SetUrlCacheEntryGroup@0x1a2580 / W@0x1a2770,
 * CCacheContainer::SetUrlGroup / SetUrlGroupAtCursor / UnsetUrlGroupAtCursor. [VM] Win10 22H2.
 * VM_TIMEOUT: 240 */
#include "ueg.h"
#include <stdlib.h>

#define REQ_G() do { REQUIRE(U(CreateUrlCacheGroup)); REQUIRE(U(DeleteUrlCacheGroup)); } while (0)
#define NEW_OR_SKIP(g, fl) do { REQ_G(); (g) = ueg_group_new(fl); if (!(g)) { t_skip("CreateUrlCacheGroup(0x%x) failed %lu", (unsigned)(fl), GetLastError()); return; } } while (0)
#define STICKY_BIT 0x1000000000000000LL
#define LOW60(g) ((ULONGLONG)(g) & 0x0fffffffffffffffULL)

/* ------------------------------------------------------------------ CreateUrlCacheGroup */
TEST(ueg_create_group_reserved_87) {
    REQ_G();
    int dummy;
    SET_ERR(0xdead);
    GROUPID g = U(CreateUrlCacheGroup)(0, &dummy);
    EXPECT_FAIL(g == 0, ERROR_INVALID_PARAMETER);
    if (g) U(DeleteUrlCacheGroup)(g, 0, NULL);
}
TEST(ueg_create_group_bad_flags_87) {
    REQ_G();
    static const DWORD bad[] = { 8, 0x10, 0x100, 0x80000000, 0xfffffff8, 0xffffffff, 0x9, 0xf };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0xdead);
        GROUPID g = U(CreateUrlCacheGroup)(bad[i], NULL);
        CHECKF(g == 0, "flags 0x%lx created a group", bad[i]);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "flags 0x%lx err %lu", bad[i], e);
        if (g) U(DeleteUrlCacheGroup)(g, 0, NULL);
    }
}
TEST(ueg_create_group_valid_flags) {
    REQ_G();
    for (DWORD f = 0; f < 8; f++) {
        SET_ERR(0xdead);
        GROUPID g = U(CreateUrlCacheGroup)(f, NULL);
        if ((f & CACHEGROUP_FLAG_GIDONLY) && (f & CACHEGROUP_FLAG_NONPURGEABLE)) {   /* Win10: GIDONLY|NONPURGEABLE is invalid */
            CHECKF(g == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "flags %lu gid 0x%llx err %lu", f, (unsigned long long)g, GetLastError());
            continue;
        }
        CHECKF(g != 0, "flags %lu err %lu", f, GetLastError());
        if (!g) continue;
        EXPECT_ERR(0);
        int sticky = (g & STICKY_BIT) != 0;
        CHECKF(sticky == (int)(f & CACHEGROUP_FLAG_NONPURGEABLE), "flags %lu gid 0x%llx", f, (unsigned long long)g);
        CHECKF(((ULONGLONG)g & 0xe000000000000000ULL) == 0, "flags %lu gid 0x%llx", f, (unsigned long long)g);
        CHECK(LOW60(g) != 0);
        if (!(f & CACHEGROUP_FLAG_GIDONLY)) { ueg_group_track(g); CHECK(U(DeleteUrlCacheGroup)(g, 0, NULL)); ueg_group_untrack(g); }
    }
}
TEST(ueg_create_group_ids_increase) {
    REQ_G();
    GROUPID a = ueg_group_new(0), b = ueg_group_new(0), c = ueg_group_new(CACHEGROUP_FLAG_NONPURGEABLE);
    CHECK(a && b && c);
    if (!(a && b && c)) return;
    CHECK(a != b); CHECK(b != c);
    EXPECT_EQ(LOW60(b), LOW60(a) + 1);
    EXPECT_EQ(LOW60(c), LOW60(b) + 1);
    EXPECT_EQ((ULONGLONG)c & 0xf000000000000000ULL, (ULONGLONG)STICKY_BIT);
    t_note("group ids 0x%llx 0x%llx 0x%llx", (unsigned long long)a, (unsigned long long)b, (unsigned long long)c);
}
/* GIDONLY: the next id is returned but no group is created and the counter does not move [D]. */
TEST(ueg_create_group_gidonly_creates_nothing) {
    REQ_G(); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID p = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY, NULL);
    CHECK(p != 0);
    if (!p) return;
    INTERNET_CACHE_GROUP_INFOA gi; DWORD cb = sizeof gi;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeA)(p, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, &cb, NULL), ERROR_FILE_NOT_FOUND);
    int found = ueg_groups_contains(p, NULL);
    EXPECT_EQ(found, 0);
    GROUPID p2 = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY, NULL);
    EXPECT_EQ(p2, p);
    GROUPID real = ueg_group_new(0);
    CHECK(real != 0);
    EXPECT_EQ(real, p);
    /* Win10 (VM, triage): GIDONLY|NONPURGEABLE is rejected with ERROR_INVALID_PARAMETER */
    SET_ERR(0xdead);
    GROUPID p3 = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY | CACHEGROUP_FLAG_NONPURGEABLE, NULL);
    EXPECT_EQ(p3, 0);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ DeleteUrlCacheGroup */
TEST(ueg_delete_group_reserved_87) {
    GROUPID g; NEW_OR_SKIP(g, 0);
    int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(DeleteUrlCacheGroup)(g, 0, &dummy), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(ueg_groups_contains(g, NULL), 1);       /* still there */
    SET_ERR(0xdead);
    CHECK(U(DeleteUrlCacheGroup)(g, 0, NULL));
    EXPECT_ERR(0);
    ueg_group_untrack(g);
}
TEST(ueg_delete_group_twice_2) {
    GROUPID g; NEW_OR_SKIP(g, 0);
    CHECK(U(DeleteUrlCacheGroup)(g, 0, NULL));
    ueg_group_untrack(g);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(DeleteUrlCacheGroup)(g, 0, NULL), ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(ueg_groups_contains(g, NULL), 0);
}
TEST(ueg_delete_group_invalid_ids_2) {
    REQ_G();
    GROUPID cur = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY, NULL);   /* next id: does not exist yet */
    const GROUPID bad[] = { 0, (GROUPID)STICKY_BIT, (GROUPID)0x2000000000000001LL, (GROUPID)0x8000000000000001ULL,
                            (GROUPID)0xe000000000000005ULL, (GROUPID)-1, cur, cur + 1000, (GROUPID)0x0fffffffffffffffLL };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0xdead);
        BOOL r = U(DeleteUrlCacheGroup)(bad[i], 0, NULL);
        CHECKF(!r, "gid 0x%llx deleted", (unsigned long long)bad[i]);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_FILE_NOT_FOUND, "gid 0x%llx err %lu", (unsigned long long)bad[i], e);
    }
}
TEST(ueg_delete_group_flags_ignored_bits) {
    REQ_G();
    static const DWORD fl[] = { 0, 1, 2, 3, 4, 0x100, 0xffffffff };
    for (size_t i = 0; i < sizeof fl / sizeof *fl; i++) {
        GROUPID g = ueg_group_new(0);
        CHECK(g != 0);
        if (!g) continue;
        SET_ERR(0xdead);
        BOOL r = U(DeleteUrlCacheGroup)(g, fl[i], NULL);
        CHECKF(r, "flags 0x%lx err %lu", fl[i], GetLastError());
        if (r) ueg_group_untrack(g);
    }
}

/* ------------------------------------------------------------------ FindFirst/NextUrlCacheGroup */
TEST(ueg_find_group_null_id_87) {
    REQUIRE(U(FindFirstUrlCacheGroup));
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheGroup)(0, CACHEGROUP_SEARCH_ALL, NULL, 0, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
}
TEST(ueg_find_group_flags_87) {
    REQUIRE(U(FindFirstUrlCacheGroup));
    static const DWORD fl[] = { 1, 2, 0x80000000 };
    for (size_t i = 0; i < 3; i++) {
        GROUPID g = 0; SET_ERR(0xdead);
        HANDLE h = U(FindFirstUrlCacheGroup)(fl[i], CACHEGROUP_SEARCH_ALL, NULL, 0, &g, NULL);
        CHECK(h == NULL);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        EXPECT_EQ(g, 0);
        if (h) U(FindCloseUrlCache)(h);
    }
}
/* dwFilter, the search condition and lpReserved of FindFirstUrlCacheGroup are not validated [D]. */
TEST(ueg_find_group_ignored_args) {
    REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindCloseUrlCache));
    GROUPID mine; NEW_OR_SKIP(mine, 0);
    int dummy = 0; GROUPID g = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheGroup)(0, 0x12345, &dummy, 77, &g, &dummy);
    CHECK(h != NULL);
    if (h) { EXPECT_ERR(0); CHECK(g != 0); U(FindCloseUrlCache)(h); }
}
TEST(ueg_find_group_sees_created_and_not_deleted) {
    REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindNextUrlCacheGroup));
    GROUPID a; NEW_OR_SKIP(a, 0);
    GROUPID b = ueg_group_new(CACHEGROUP_FLAG_NONPURGEABLE);
    CHECK(b != 0);
    int n = 0;
    EXPECT_EQ(ueg_groups_contains(a, &n), 1);
    EXPECT_EQ(ueg_groups_contains(b, &n), 1);
    t_note("%d groups enumerated", n);
    CHECK(U(DeleteUrlCacheGroup)(a, 0, NULL)); ueg_group_untrack(a);
    EXPECT_EQ(ueg_groups_contains(a, &n), 0);
    EXPECT_EQ(ueg_groups_contains(b, &n), 1);
}
TEST(ueg_find_group_handle_protocol) {
    REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindNextUrlCacheGroup)); REQUIRE(U(FindCloseUrlCache));
    GROUPID mine; NEW_OR_SKIP(mine, 0);
    GROUPID g = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheGroup)(0, CACHEGROUP_SEARCH_ALL, NULL, 0, &g, NULL);
    CHECK(h != NULL);
    if (!h) return;
    EXPECT_ERR(0);
    CHECK(((ULONG_PTR)h & 1) == 1);
    int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheGroup)(h, NULL, NULL), ERROR_INVALID_PARAMETER);
    GROUPID x = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheGroup)(h, &x, &dummy), ERROR_INVALID_PARAMETER);
    int n = 1, seen_dup = 0; GROUPID prev = g;
    for (;;) {
        SET_ERR(0xdead);
        if (!U(FindNextUrlCacheGroup)(h, &x, NULL)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
        EXPECT_ERR(0);
        if (x == prev) seen_dup++;
        prev = x;
        if (++n > UEG_ENUM_CAP) break;
    }
    EXPECT_EQ(seen_dup, 0);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheGroup)(h, &x, NULL), ERROR_NO_MORE_ITEMS);
    CHECK(U(FindCloseUrlCache)(h));
    SET_ERR(0xdead);
    BOOL r = U(FindNextUrlCacheGroup)(h, &x, NULL);
    CHECK(!r);
    t_note("FindNextUrlCacheGroup after close: err %lu", GetLastError());
}
TEST(ueg_find_group_bogus_handles) {
    REQUIRE(U(FindNextUrlCacheGroup));
    static const ULONG_PTR hv[] = { 2, 0x100, 0x7ffffff1 };
    for (size_t i = 0; i < 3; i++) {
        GROUPID x = 0; SET_ERR(0xdead);
        BOOL r = U(FindNextUrlCacheGroup)((HANDLE)hv[i], &x, NULL);
        CHECK(!r);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_HANDLE, "handle 0x%llx err %lu", (unsigned long long)hv[i], e);
    }
    GROUPID x = 0; SET_ERR(0xdead);
    BOOL r = U(FindNextUrlCacheGroup)(NULL, &x, NULL);
    CHECK(!r);
    t_note("FindNextUrlCacheGroup(NULL) err %lu", GetLastError());
}
/* Handle types are not interchangeable: an entry-find handle is not a group-find handle and vice versa. */
TEST(ueg_find_group_handle_type_confusion) {
    REQUIRE(U(FindFirstUrlCacheGroup)); REQUIRE(U(FindNextUrlCacheGroup)); REQUIRE(U(FindNextUrlCacheEntryA)); REQUIRE(U(FindFirstUrlCacheEntryA));
    GROUPID mine; NEW_OR_SKIP(mine, 0);
    const char *url = ueg_url("conf");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    GROUPID g = 0;
    HANDLE hg = U(FindFirstUrlCacheGroup)(0, 0, NULL, 0, &g, NULL);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); DWORD sz = cap;
    HANDLE he = U(FindFirstUrlCacheEntryA)(NULL, e, &sz);
    CHECK(hg != NULL); CHECK(he != NULL);
    if (hg && he) {
        sz = cap; SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(hg, e, &sz), ERROR_INVALID_HANDLE);
        GROUPID x = 0; SET_ERR(0xdead);
        CHECK(!U(FindNextUrlCacheGroup)(he, &x, NULL));
        DWORD er = GetLastError();
        CHECKF(er == ERROR_INVALID_HANDLE, "err %lu", er);
        /* both still work afterwards */
        sz = cap; BOOL r1 = U(FindNextUrlCacheEntryA)(he, e, &sz);
        CHECK(r1 || GetLastError() == ERROR_NO_MORE_ITEMS);
    }
    if (hg) CHECK(U(FindCloseUrlCache)(hg));
    if (he) CHECK(U(FindCloseUrlCache)(he));
    free(e);
}

/* ------------------------------------------------------------------ GetUrlCacheGroupAttributeA/W */
TEST(ueg_get_attr_param_validation_a) {
    REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA gi; DWORD cb = sizeof gi; int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, NULL, &cb, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(cb, sizeof gi);                      /* untouched: rejected before the size is published */
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, NULL, NULL), ERROR_INVALID_PARAMETER);
    cb = sizeof gi; SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, &cb, &dummy), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(cb, sizeof gi);
}
TEST(ueg_get_attr_param_validation_w) {
    REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOW gi; DWORD cb = sizeof gi; int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, NULL, &cb, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, NULL, NULL), ERROR_INVALID_PARAMETER);
    cb = sizeof gi; SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, &cb, &dummy), ERROR_INVALID_PARAMETER);
}
TEST(ueg_get_attr_struct_sizes) {
    CHECK(sizeof(INTERNET_CACHE_GROUP_INFOA) == 0x9c);
    CHECK(sizeof(INTERNET_CACHE_GROUP_INFOW) == 0x114);
}
/* *lpcbGroupInfo is always set to the structure size; smaller -> 122 (before the group is even looked up). */
TEST(ueg_get_attr_small_size_122_a) {
    REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    static const DWORD sizes[] = { 0, 1, 4, 0x24, 0x9b };
    for (size_t i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        INTERNET_CACHE_GROUP_INFOA gi; DWORD cb = sizes[i];
        SET_ERR(0xdead);
        CHECK(!U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, &cb, NULL));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(cb, 0x9c);
        /* same for a group that does not exist: the size check comes first */
        cb = sizes[i]; SET_ERR(0xdead);
        CHECK(!U(GetUrlCacheGroupAttributeA)((GROUPID)0x0ffffffffffffff0LL, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, &cb, NULL));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(cb, 0x9c);
    }
}
TEST(ueg_get_attr_small_size_122_w) {
    REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    static const DWORD sizes[] = { 0, 0x9c, 0x113 };
    for (size_t i = 0; i < 3; i++) {
        INTERNET_CACHE_GROUP_INFOW gi; DWORD cb = sizes[i];
        SET_ERR(0xdead);
        CHECK(!U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &gi, &cb, NULL));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(cb, 0x114);
    }
}
TEST(ueg_get_attr_large_size_resets_cb) {
    REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    unsigned char buf[0x400]; DWORD cb = sizeof buf;
    SET_ERR(0xdead);
    CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, (INTERNET_CACHE_GROUP_INFOA *)buf, &cb, NULL));
    EXPECT_ERR(0);
    EXPECT_EQ(cb, 0x9c);
    cb = sizeof buf;
    CHECK(U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, (INTERNET_CACHE_GROUP_INFOW *)buf, &cb, NULL));
    EXPECT_EQ(cb, 0x114);
}
TEST(ueg_get_attr_missing_group_2) {
    REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeW)); REQ_G();
    GROUPID nx = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY, NULL);
    const GROUPID bad[] = { 0, (GROUPID)STICKY_BIT, (GROUPID)0xe000000000000001ULL, nx, nx + 50 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        INTERNET_CACHE_GROUP_INFOA a; DWORD cb = sizeof a;
        SET_ERR(0xdead);
        CHECK(!U(GetUrlCacheGroupAttributeA)(bad[i], 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &a, &cb, NULL));
        DWORD e = GetLastError();
        CHECKF(e == ERROR_FILE_NOT_FOUND, "A gid 0x%llx err %lu", (unsigned long long)bad[i], e);
        INTERNET_CACHE_GROUP_INFOW w; cb = sizeof w;
        SET_ERR(0xdead);
        CHECK(!U(GetUrlCacheGroupAttributeW)(bad[i], 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &w, &cb, NULL));
        e = GetLastError();
        CHECKF(e == ERROR_FILE_NOT_FOUND, "W gid 0x%llx err %lu", (unsigned long long)bad[i], e);
    }
}
TEST(ueg_get_attr_defaults) {
    REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    GROUPID s = ueg_group_new(CACHEGROUP_FLAG_NONPURGEABLE);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0xCC, sizeof a); DWORD cb = sizeof a;
    CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &a, &cb, NULL));
    EXPECT_EQ(a.dwGroupFlags, 0);
    EXPECT_EQ(a.dwGroupType, 0);
    EXPECT_EQ(a.dwDiskUsage, 0);
    EXPECT_EQ(a.dwDiskQuota, 0);
    for (int i = 0; i < 4; i++) EXPECT_EQ(a.dwOwnerStorage[i], 0);
    EXPECT_STR(a.szGroupName, "");
    EXPECT_EQ(a.dwGroupSize, 0xCCCCCCCC);         /* GET never writes dwGroupSize [D] */
    INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0xCC, sizeof w); cb = sizeof w;
    CHECK(U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &w, &cb, NULL));
    EXPECT_EQ(w.dwGroupFlags, 0); EXPECT_EQ(w.dwGroupType, 0); EXPECT_EQ(w.dwDiskQuota, 0);
    EXPECT_EQ(w.szGroupName[0], 0);
    EXPECT_EQ(w.dwGroupSize, 0xCCCCCCCC);
    if (s) {
        memset(&a, 0xCC, sizeof a); cb = sizeof a;
        CHECK(U(GetUrlCacheGroupAttributeA)(s, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &a, &cb, NULL));
        EXPECT_EQ(a.dwGroupFlags, CACHEGROUP_FLAG_NONPURGEABLE);
        EXPECT_EQ(a.dwGroupType, 0);
    }
}
/* Which fields each attribute bit writes [D]: FLAG <- attr&3, TYPE <- attr&5, QUOTA <- attr&9, USAGE <- attr&1,
 * STORAGE <- attr&0x20, NAME <- attr&0x10. Everything else keeps the caller's bytes. */
static const DWORD k_attr_bits[] = { 0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80000000, 3, 0x30, 0x3f, 0xffffffff };
TEST(ueg_get_attr_field_selection_a) {
    REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    for (size_t i = 0; i < sizeof k_attr_bits / sizeof *k_attr_bits; i++) {
        DWORD at = k_attr_bits[i];
        INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0xCC, sizeof a); DWORD cb = sizeof a;
        SET_ERR(0xdead);
        BOOL r = U(GetUrlCacheGroupAttributeA)(g, 0, at, &a, &cb, NULL);
        CHECKF(r, "attr 0x%lx err %lu", at, GetLastError());
        if (!r) continue;
        CHECKF((a.dwGroupFlags == 0) == ((at & 3) != 0), "attr 0x%lx flags 0x%lx", at, a.dwGroupFlags);
        CHECKF((a.dwGroupType == 0) == ((at & 5) != 0), "attr 0x%lx type 0x%lx", at, a.dwGroupType);
        CHECKF((a.dwDiskQuota == 0) == ((at & 9) != 0), "attr 0x%lx quota 0x%lx", at, a.dwDiskQuota);
        CHECKF((a.dwDiskUsage == 0) == ((at & 1) != 0), "attr 0x%lx usage 0x%lx", at, a.dwDiskUsage);
        CHECKF((a.dwOwnerStorage[0] == 0) == ((at & 0x20) != 0), "attr 0x%lx storage 0x%lx", at, a.dwOwnerStorage[0]);
        CHECKF(((unsigned char)a.szGroupName[0] == 0) == ((at & 0x10) != 0), "attr 0x%lx name[0] 0x%x", at, (unsigned char)a.szGroupName[0]);
        EXPECT_EQ(a.dwGroupSize, 0xCCCCCCCC);
    }
}
TEST(ueg_get_attr_field_selection_w) {
    REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    for (size_t i = 0; i < sizeof k_attr_bits / sizeof *k_attr_bits; i++) {
        DWORD at = k_attr_bits[i];
        INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0xCC, sizeof w); DWORD cb = sizeof w;
        BOOL r = U(GetUrlCacheGroupAttributeW)(g, 0, at, &w, &cb, NULL);
        CHECKF(r, "attr 0x%lx err %lu", at, GetLastError());
        if (!r) continue;
        CHECKF((w.dwGroupFlags == 0) == ((at & 3) != 0), "attr 0x%lx flags", at);
        CHECKF((w.dwGroupType == 0) == ((at & 5) != 0), "attr 0x%lx type", at);
        CHECKF((w.dwDiskQuota == 0) == ((at & 9) != 0), "attr 0x%lx quota", at);
        CHECKF((w.dwDiskUsage == 0) == ((at & 1) != 0), "attr 0x%lx usage", at);
        CHECKF((w.dwOwnerStorage[3] == 0) == ((at & 0x20) != 0), "attr 0x%lx storage", at);
        CHECKF((w.szGroupName[0] == 0) == ((at & 0x10) != 0), "attr 0x%lx name", at);
        EXPECT_EQ(w.dwGroupSize, 0xCCCCCCCC);
    }
}
/* dwFlags of GetUrlCacheGroupAttribute is ignored */
TEST(ueg_get_attr_flags_ignored) {
    REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    static const DWORD fl[] = { 1, 0x80000000, 0xffffffff };
    for (size_t i = 0; i < 3; i++) {
        INTERNET_CACHE_GROUP_INFOA a; DWORD cb = sizeof a;
        CHECKF(U(GetUrlCacheGroupAttributeA)(g, fl[i], CACHEGROUP_ATTRIBUTE_GET_ALL, &a, &cb, NULL), "flags 0x%lx err %lu", fl[i], GetLastError());
    }
}

/* ------------------------------------------------------------------ SetUrlCacheGroupAttributeA/W */
TEST(ueg_set_attr_param_validation) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(SetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a;
    INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = sizeof w;
    int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, NULL, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, &a, &dummy), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, NULL, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, &w, &dummy), ERROR_INVALID_PARAMETER);
}
TEST(ueg_set_attr_missing_group_2) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(SetUrlCacheGroupAttributeW)); REQ_G();
    GROUPID nx = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY, NULL);
    const GROUPID bad[] = { 0, (GROUPID)0xe000000000000001ULL, nx, nx + 7 };
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; a.dwGroupType = 5;
    INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = sizeof w;
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0xdead);
        CHECK(!U(SetUrlCacheGroupAttributeA)(bad[i], 0, CACHEGROUP_ATTRIBUTE_TYPE, &a, NULL));
        DWORD e = GetLastError();
        CHECKF(e == ERROR_FILE_NOT_FOUND, "A gid 0x%llx err %lu", (unsigned long long)bad[i], e);
        SET_ERR(0xdead);
        CHECK(!U(SetUrlCacheGroupAttributeW)(bad[i], 0, CACHEGROUP_ATTRIBUTE_TYPE, &w, NULL));
        e = GetLastError();
        CHECKF(e == ERROR_FILE_NOT_FOUND, "W gid 0x%llx err %lu", (unsigned long long)bad[i], e);
    }
}
static int get_a(GROUPID g, INTERNET_CACHE_GROUP_INFOA *a) { memset(a, 0xCC, sizeof *a); DWORD cb = sizeof *a; return U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, a, &cb, NULL); }
static int get_w(GROUPID g, INTERNET_CACHE_GROUP_INFOW *w) { memset(w, 0xCC, sizeof *w); DWORD cb = sizeof *w; return U(GetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, w, &cb, NULL); }

TEST(ueg_set_attr_type_roundtrip) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    static const DWORD types[] = { 1, 0x10, 0x12345678, 0xffffffff, 0 };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; a.dwGroupType = types[i];
        SET_ERR(0xdead);
        CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, &a, NULL));
        EXPECT_ERR(0);
        INTERNET_CACHE_GROUP_INFOA r;
        CHECK(get_a(g, &r));
        EXPECT_EQ(r.dwGroupType, types[i]);
    }
}
TEST(ueg_set_attr_quota_roundtrip_kb) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    static const DWORD q[] = { 1, 1024, 0x3fffff, 0 };
    for (size_t i = 0; i < sizeof q / sizeof *q; i++) {
        INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; a.dwDiskQuota = q[i];
        CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_QUOTA, &a, NULL));
        INTERNET_CACHE_GROUP_INFOA r;
        CHECK(get_a(g, &r));
        EXPECT_EQ(r.dwDiskQuota, q[i]);
    }
}
TEST(ueg_set_attr_flag_roundtrip) {
    REQUIRE(U(SetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    static const DWORD f[] = { 1, 2, 0xabcd, 0 };
    for (size_t i = 0; i < 4; i++) {
        INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = sizeof w; w.dwGroupFlags = f[i];
        CHECK(U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_FLAG, &w, NULL));
        INTERNET_CACHE_GROUP_INFOW r;
        CHECK(get_w(g, &r));
        EXPECT_EQ(r.dwGroupFlags, f[i]);
    }
}
TEST(ueg_set_attr_storage_roundtrip) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a;
    a.dwOwnerStorage[0] = 0x11111111; a.dwOwnerStorage[1] = 0x22222222; a.dwOwnerStorage[2] = 0x33333333; a.dwOwnerStorage[3] = 0x44444444;
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_STORAGE, &a, NULL));
    INTERNET_CACHE_GROUP_INFOA r; CHECK(get_a(g, &r));
    for (int i = 0; i < 4; i++) EXPECT_EQ(r.dwOwnerStorage[i], a.dwOwnerStorage[i]);
    INTERNET_CACHE_GROUP_INFOW rw; CHECK(get_w(g, &rw));
    for (int i = 0; i < 4; i++) EXPECT_EQ(rw.dwOwnerStorage[i], a.dwOwnerStorage[i]);
}
/* Only the selected attributes change; unselected ones keep their stored values. */
TEST(ueg_set_attr_selective_update) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a;
    a.dwGroupType = 7; a.dwDiskQuota = 99; a.dwGroupFlags = 0; a.dwOwnerStorage[1] = 5;
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE | CACHEGROUP_ATTRIBUTE_QUOTA | CACHEGROUP_ATTRIBUTE_STORAGE, &a, NULL));
    INTERNET_CACHE_GROUP_INFOA b; memset(&b, 0, sizeof b); b.dwGroupSize = sizeof b;
    b.dwGroupType = 1000; b.dwDiskQuota = 2000; b.dwOwnerStorage[1] = 3000;
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, &b, NULL));
    INTERNET_CACHE_GROUP_INFOA r; CHECK(get_a(g, &r));
    EXPECT_EQ(r.dwGroupType, 1000);
    EXPECT_EQ(r.dwDiskQuota, 99);
    EXPECT_EQ(r.dwOwnerStorage[1], 5);
    /* BASIC (1) maps to no writable attribute: a call with only BASIC changes nothing */
    b.dwGroupType = 1; b.dwDiskQuota = 1; b.dwGroupFlags = 1;
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_BASIC, &b, NULL));
    CHECK(get_a(g, &r));
    EXPECT_EQ(r.dwGroupType, 1000);
    EXPECT_EQ(r.dwDiskQuota, 99);
    EXPECT_EQ(r.dwGroupFlags, 0);
    /* attribute 0 is accepted and is a no-op */
    SET_ERR(0xdead);
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, 0, &b, NULL));
    CHECK(get_a(g, &r));
    EXPECT_EQ(r.dwGroupType, 1000);
}
/* Group names: SetUrlCacheGroupAttribute copies the caller's name into the request only when
 * CACHEGROUP_ATTRIBUTE_QUOTA (8) is set, but the server stores it when GROUPNAME (0x10) is set [D both A and W]. */
TEST(ueg_set_attr_groupname_needs_quota_bit) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA)); REQUIRE(U(SetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeW));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; strcpy(a.szGroupName, "ueg-name-a");
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME, &a, NULL));
    INTERNET_CACHE_GROUP_INFOA r; CHECK(get_a(g, &r));
    t_note("A GROUPNAME only -> '%s'", r.szGroupName);
    a.dwDiskQuota = 0;
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME | CACHEGROUP_ATTRIBUTE_QUOTA, &a, NULL));
    CHECK(get_a(g, &r));
    EXPECT_STR(r.szGroupName, "ueg-name-a");
    INTERNET_CACHE_GROUP_INFOW rw; CHECK(get_w(g, &rw));
    EXPECT_WSTR(rw.szGroupName, L"ueg-name-a");
    INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = sizeof w; lstrcpyW(w.szGroupName, L"ueg-name-w");
    CHECK(U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME | CACHEGROUP_ATTRIBUTE_QUOTA, &w, NULL));
    CHECK(get_w(g, &rw));
    EXPECT_WSTR(rw.szGroupName, L"ueg-name-w");
    CHECK(get_a(g, &r));
    EXPECT_STR(r.szGroupName, "ueg-name-w");
    /* QUOTA alone does not store a name */
    lstrcpyW(w.szGroupName, L"other");
    CHECK(U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_QUOTA, &w, NULL));
    CHECK(get_w(g, &rw));
    EXPECT_WSTR(rw.szGroupName, L"ueg-name-w");
}
TEST(ueg_set_attr_groupname_max_length) {
    REQUIRE(U(SetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeW)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOW w; memset(&w, 0, sizeof w); w.dwGroupSize = sizeof w;
    for (int i = 0; i < 119; i++) w.szGroupName[i] = (WCHAR)('a' + i % 26);
    CHECK(U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME | CACHEGROUP_ATTRIBUTE_QUOTA, &w, NULL));
    INTERNET_CACHE_GROUP_INFOW rw; CHECK(get_w(g, &rw));
    EXPECT_EQ(lstrlenW(rw.szGroupName), 119);
    INTERNET_CACHE_GROUP_INFOA ra; CHECK(get_a(g, &ra));
    EXPECT_EQ(strlen(ra.szGroupName), 119);
    /* 120 characters without a terminator do not fit StringCchCopyW(dst, 120, src) */
    for (int i = 0; i < 120; i++) w.szGroupName[i] = 'z';
    SET_ERR(0xdead);
    BOOL r = U(SetUrlCacheGroupAttributeW)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME | CACHEGROUP_ATTRIBUTE_QUOTA, &w, NULL);
    t_note("120-char unterminated group name: ret %d err %lu", r, GetLastError());
}
TEST(ueg_set_attr_flags_param_ignored) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; a.dwGroupType = 42;
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0xffffffff, CACHEGROUP_ATTRIBUTE_TYPE, &a, NULL));
    INTERNET_CACHE_GROUP_INFOA r; CHECK(get_a(g, &r));
    EXPECT_EQ(r.dwGroupType, 42);
}
TEST(ueg_set_attr_on_deleted_group_2) {
    REQUIRE(U(SetUrlCacheGroupAttributeA)); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    CHECK(U(DeleteUrlCacheGroup)(g, 0, NULL)); ueg_group_untrack(g);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; DWORD cb = sizeof a;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_TYPE, &a, NULL), ERROR_FILE_NOT_FOUND);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &a, &cb, NULL), ERROR_FILE_NOT_FOUND);
}

/* ------------------------------------------------------------------ SetUrlCacheEntryGroup */
#define REQ_SEG() do { REQUIRE(U(SetUrlCacheEntryGroupA)); REQUIRE(U(SetUrlCacheEntryGroupW)); } while (0)
TEST(ueg_seg_param_validation_a) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("segp");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    BYTE attr[4] = { 0 }; int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(NULL, 0, g, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, 0, 0, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, 0, g, attr, 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 4, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, &dummy), ERROR_INVALID_PARAMETER);
    /* none of those added the entry to the group */
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, NULL), 0);
}
TEST(ueg_seg_param_validation_w) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("segpw");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    const WCHAR *wu = ueg_w(url); BYTE attr[4] = { 0 }; int dummy;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupW)(NULL, 0, g, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupW)(wu, 0, 0, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupW)(wu, 0, g, attr, 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupW)(wu, 0, g, NULL, 4, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupW)(wu, 0, g, NULL, 0, &dummy), ERROR_INVALID_PARAMETER);
}
/* The undecorated SetUrlCacheEntryGroup is the same code as SetUrlCacheEntryGroupA (same RVA). */
TEST(ueg_seg_plain_is_a) {
    REQUIRE(t_proc_in("wininet.dll", "SetUrlCacheEntryGroup")); REQUIRE(t_proc_in("wininet.dll", "SetUrlCacheEntryGroupA"));
    EXPECT_EQ(t_proc_in("wininet.dll", "SetUrlCacheEntryGroup"), t_proc_in("wininet.dll", "SetUrlCacheEntryGroupA"));
}
TEST(ueg_seg_missing_entry_2) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("segmiss");      /* never created */
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL), ERROR_FILE_NOT_FOUND);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupW)(ueg_w(url), INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL), ERROR_FILE_NOT_FOUND);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_REMOVE, g, NULL, 0, NULL), ERROR_FILE_NOT_FOUND);
}
TEST(ueg_seg_missing_group_2) {
    REQ_SEG(); REQ_G();
    const char *url = ueg_url("segng");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    GROUPID nx = U(CreateUrlCacheGroup)(CACHEGROUP_FLAG_GIDONLY, NULL);
    const GROUPID bad[] = { nx, nx + 3, (GROUPID)STICKY_BIT, (GROUPID)0xe000000000000001ULL, (GROUPID)-1 };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SET_ERR(0xdead);
        CHECK(!U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_ADD, bad[i], NULL, 0, NULL));
        DWORD e = GetLastError();
        CHECKF(e == ERROR_FILE_NOT_FOUND, "gid 0x%llx err %lu", (unsigned long long)bad[i], e);
    }
}
TEST(ueg_seg_add_remove_membership) {
    REQ_SEG(); REQUIRE(U(FindFirstUrlCacheEntryExA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("segar");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    int n = 0;
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, &n), 0);
    SET_ERR(0xdead);
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL)));
    CHECK(GetLastError() == 0 || GetLastError() == ERROR_NOT_ENOUGH_QUOTA);   /* quota-0 group: 1816 yet member added */
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, &n), 1);
    EXPECT_EQ(n, 1);
    /* adding again is a successful no-op */
    SET_ERR(0xdead);
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL)));
    CHECK(GetLastError() == 0 || GetLastError() == ERROR_NOT_ENOUGH_QUOTA);   /* quota-0 group: 1816 yet member added */
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, &n), 1);
    EXPECT_EQ(n, 1);
    SET_ERR(0xdead);
    CHECK(U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_REMOVE, g, NULL, 0, NULL));
    EXPECT_ERR(0);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, &n), 0);
    /* removing a membership that is not there -> 2 */
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_REMOVE, g, NULL, 0, NULL), ERROR_FILE_NOT_FOUND);
    CHECK(ueg_exists(url));                       /* membership changes never delete the entry */
}
TEST(ueg_seg_w_add_remove) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("segw");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupW)(ueg_w(url), INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL)));
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, NULL), 1);
    CHECK(U(SetUrlCacheEntryGroupW)(ueg_w(url), INTERNET_CACHE_GROUP_REMOVE, g, NULL, 0, NULL));
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, NULL), 0);
}
/* Only bit 0 of dwFlags is used (REMOVE); other bits are ignored [D CCacheClientContainer::SetUrlGroup flags & 1]. */
TEST(ueg_seg_flag_bits) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("segfl");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 2, g, NULL, 0, NULL)));                    /* 2 -> add */
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, NULL), 1);
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0xfffffffe, g, NULL, 0, NULL)));           /* still add (idempotent) */
    CHECK(U(SetUrlCacheEntryGroupA)(url, 3, g, NULL, 0, NULL));                    /* 3 -> remove */
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, NULL), 0);
}
TEST(ueg_seg_entry_in_two_groups) {
    REQ_SEG();
    GROUPID g1; NEW_OR_SKIP(g1, 0);
    GROUPID g2 = ueg_group_new(0); CHECK(g2 != 0); if (!g2) return;
    const char *u1 = ueg_url("two1"), *u2 = ueg_url("two2");
    if (!ueg_make_simple(u1) || !ueg_make_simple(u2)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(u1, 0, g1, NULL, 0, NULL)));
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(u1, 0, g2, NULL, 0, NULL)));
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(u2, 0, g2, NULL, 0, NULL)));
    int n1 = 0, n2 = 0;
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g1, u1, &n1), 1);
    EXPECT_EQ(n1, 1);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g2, u1, &n2), 1);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g2, u2, &n2), 1);
    EXPECT_EQ(n2, 2);
    CHECK(U(SetUrlCacheEntryGroupA)(u1, INTERNET_CACHE_GROUP_REMOVE, g1, NULL, 0, NULL));
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g2, u1, &n2), 1);
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g1, u1, &n1), 0);
}
/* Many groups on one entry (the membership list grows past its initial allocation) */
TEST(ueg_seg_entry_in_many_groups) {
    REQ_SEG();
    const char *url = ueg_url("manyg");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    GROUPID gs[12]; int ok = 0;
    for (int i = 0; i < 12; i++) { gs[i] = ueg_group_new(0); if (gs[i] && SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, gs[i], NULL, 0, NULL))) ok++; }
    EXPECT_EQ(ok, 12);
    int seen = 0;
    for (int i = 0; i < 12; i++) if (gs[i]) seen += ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, gs[i], url, NULL);
    EXPECT_EQ(seen, 12);
    /* remove the odd ones; the even ones still list it */
    for (int i = 1; i < 12; i += 2) CHECK(U(SetUrlCacheEntryGroupA)(url, 1, gs[i], NULL, 0, NULL));
    for (int i = 0; i < 12; i++) EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, gs[i], url, NULL), (i & 1) ? 0 : 1);
    /* re-adding reuses a freed slot */
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, gs[1], NULL, 0, NULL)));
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, gs[1], url, NULL), 1);
}

/* ------------------------------------------------------------------ DeleteUrlCacheGroup and member entries */
TEST(ueg_delete_group_keeps_entries) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("dgk");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL)));
    CHECK(U(DeleteUrlCacheGroup)(g, 0, NULL)); ueg_group_untrack(g);
    CHECK(ueg_exists(url));
    /* the entry is no longer a member of anything: removing g now fails (group gone) */
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(SetUrlCacheEntryGroupA)(url, INTERNET_CACHE_GROUP_REMOVE, g, NULL, 0, NULL), ERROR_FILE_NOT_FOUND);
}
TEST(ueg_delete_group_flush_deletes_entries) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *u1 = ueg_url("dgf1"), *u2 = ueg_url("dgf2"), *uo = ueg_url("dgfo");
    if (!ueg_make_simple(u1) || !ueg_make_simple(u2) || !ueg_make_simple(uo)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(u1, 0, g, NULL, 0, NULL)));
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(u2, 0, g, NULL, 0, NULL)));
    SET_ERR(0xdead);
    CHECK(U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL));
    EXPECT_ERR(0);
    ueg_group_untrack(g);
    CHECK(!ueg_exists(u1));
    CHECK(!ueg_exists(u2));
    CHECK(ueg_exists(uo));                        /* not a member: untouched */
}
TEST(ueg_delete_group_flush_keeps_multi_member) {
    REQ_SEG();
    GROUPID g1; NEW_OR_SKIP(g1, 0);
    GROUPID g2 = ueg_group_new(0); CHECK(g2 != 0); if (!g2) return;
    const char *both = ueg_url("dgmb"), *only = ueg_url("dgmo");
    if (!ueg_make_simple(both) || !ueg_make_simple(only)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(both, 0, g1, NULL, 0, NULL)));
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(both, 0, g2, NULL, 0, NULL)));
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(only, 0, g1, NULL, 0, NULL)));
    CHECK(U(DeleteUrlCacheGroup)(g1, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL)); ueg_group_untrack(g1);
    CHECK(ueg_exists(both));                      /* still in g2 */
    CHECK(!ueg_exists(only));
    EXPECT_EQ(ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g2, both, NULL), 1);
}
/* flag 1 (NONPURGEABLE) is not the flush flag: delete with 1 keeps entries */
TEST(ueg_delete_group_flag1_no_flush) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("dg1");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL)));
    CHECK(U(DeleteUrlCacheGroup)(g, 1, NULL)); ueg_group_untrack(g);
    CHECK(ueg_exists(url));
}

/* ------------------------------------------------------------------ non-purgeable groups make members sticky */
TEST(ueg_nonpurgeable_group_sets_sticky) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, CACHEGROUP_FLAG_NONPURGEABLE);
    const char *url = ueg_url("stk");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(url, NULL);
    CHECK(e && !(e->CacheEntryType & STICKY_CACHE_ENTRY));
    free(e);
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL)));
    e = ueg_info_a(url, NULL);
    CHECK(e != NULL);
    if (e) CHECKF(e->CacheEntryType & STICKY_CACHE_ENTRY, "type 0x%lx", e->CacheEntryType);
    free(e);
    CHECK(U(SetUrlCacheEntryGroupA)(url, 1, g, NULL, 0, NULL));
    e = ueg_info_a(url, NULL);
    CHECK(e != NULL);
    if (e) CHECKF(!(e->CacheEntryType & STICKY_CACHE_ENTRY), "type after remove 0x%lx", e->CacheEntryType);
    free(e);
}
TEST(ueg_purgeable_group_does_not_set_sticky) {
    REQ_SEG();
    GROUPID g; NEW_OR_SKIP(g, 0);
    const char *url = ueg_url("nstk");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL)));
    INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(url, NULL);
    CHECK(e != NULL);
    if (e) EXPECT_EQ(e->CacheEntryType, NORMAL_CACHE_ENTRY);
    free(e);
}
TEST(ueg_sticky_kept_while_any_nonpurgeable_group) {
    REQ_SEG();
    GROUPID s1; NEW_OR_SKIP(s1, CACHEGROUP_FLAG_NONPURGEABLE);
    GROUPID s2 = ueg_group_new(CACHEGROUP_FLAG_NONPURGEABLE); CHECK(s2 != 0); if (!s2) return;
    const char *url = ueg_url("stk2");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, s1, NULL, 0, NULL)));
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, s2, NULL, 0, NULL)));
    CHECK(U(SetUrlCacheEntryGroupA)(url, 1, s1, NULL, 0, NULL));
    INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(url, NULL);
    CHECK(e && (e->CacheEntryType & STICKY_CACHE_ENTRY));
    free(e);
    CHECK(U(SetUrlCacheEntryGroupA)(url, 1, s2, NULL, 0, NULL));
    e = ueg_info_a(url, NULL);
    CHECK(e && !(e->CacheEntryType & STICKY_CACHE_ENTRY));
    free(e);
}
/* A STICKY entry (committed sticky) does not lose STICKY when removed from a non-purgeable group? -> observe */
TEST(ueg_sticky_commit_and_nonpurgeable_group) {
    REQ_SEG();
    GROUPID s; NEW_OR_SKIP(s, CACHEGROUP_FLAG_NONPURGEABLE);
    const char *url = ueg_url("stk3");
    if (!ueg_make_entry(url, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, "txt", "s")) { t_skip("no entry"); return; }
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, s, NULL, 0, NULL)));
    CHECK(U(SetUrlCacheEntryGroupA)(url, 1, s, NULL, 0, NULL));
    INTERNET_CACHE_ENTRY_INFOA *e = ueg_info_a(url, NULL);
    CHECK(e != NULL);
    if (e) t_note("committed-sticky entry after add/remove of a non-purgeable group: type 0x%lx", e->CacheEntryType);
    free(e);
}

/* ------------------------------------------------------------------ disk usage accounting */
TEST(ueg_group_usage_tracks_members) {
    REQ_SEG(); REQUIRE(U(GetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    char *big = malloc(64 * 1024 + 1); memset(big, 'u', 64 * 1024); big[64 * 1024] = 0;
    const char *url = ueg_url("usage");
    int made = ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, "txt", big);
    free(big);
    if (!made) { t_skip("no entry"); return; }
    INTERNET_CACHE_GROUP_INFOA a; DWORD cb = sizeof a;
    CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_BASIC, &a, &cb, NULL));
    EXPECT_EQ(a.dwDiskUsage, 0);
    CHECK(SEGQ(U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL)));
    cb = sizeof a;
    CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_BASIC, &a, &cb, NULL));
    CHECKF(a.dwDiskUsage >= 64, "usage %lu KB", a.dwDiskUsage);
    t_note("group usage after a 64 KiB member: %lu KB", a.dwDiskUsage);
    CHECK(U(SetUrlCacheEntryGroupA)(url, 1, g, NULL, 0, NULL));
    cb = sizeof a;
    CHECK(U(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_BASIC, &a, &cb, NULL));
    EXPECT_EQ(a.dwDiskUsage, 0);
}
TEST(ueg_group_quota_exceeded) {
    REQ_SEG(); REQUIRE(U(SetUrlCacheGroupAttributeA));
    GROUPID g; NEW_OR_SKIP(g, 0);
    INTERNET_CACHE_GROUP_INFOA a; memset(&a, 0, sizeof a); a.dwGroupSize = sizeof a; a.dwDiskQuota = 4;   /* 4 KB */
    CHECK(U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_QUOTA, &a, NULL));
    char *big = malloc(32 * 1024 + 1); memset(big, 'q', 32 * 1024); big[32 * 1024] = 0;
    const char *url = ueg_url("quota");
    int made = ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, "txt", big);
    free(big);
    if (!made) { t_skip("no entry"); return; }
    SET_ERR(0xdead);
    BOOL r = U(SetUrlCacheEntryGroupA)(url, 0, g, NULL, 0, NULL);
    DWORD e = GetLastError();
    t_note("32 KiB entry into a 4 KB-quota group: ret %d err %lu; member afterwards %d", r, e, ueg_enum_contains_a("", 0, UEG_DEFAULT_FILTER, g, url, NULL));
    if (!r) EXPECT_EQ(e, ERROR_NOT_ENOUGH_QUOTA);
}
