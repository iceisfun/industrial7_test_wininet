/* urlcache_enum_groups / containers_misc.c - FindFirst/NextUrlCacheContainerA/W, Create/DeleteUrlCacheContainerA/W
 * (argument validation only: creating a container is a dx_ operation), Get/SetUrlCacheConfigInfoA/W (Set: NULL only),
 * FreeUrlCacheSpaceA/W (argument validation only), IsUrlCacheEntryExpiredA/W, Commit/GetUrlCacheEntryBinaryBlob.
 * Evidence: [D] FindFirstUrlCacheContainerW@0x29aa0 / A@0x29240 (NULL args -> 87; invalid handle 6 -> mapped to 87),
 * GetInitialUrlCacheContainerFindHandleHelper@0x29398 (option 1 + unchanged counter -> 12051),
 * FindNextUrlCacheContainerHelper@0x36720 (only type-3 extensible containers), ConvertCacheContainerInfoA/W,
 * CreateUrlCacheContainerW@0xd19b0 / A@0xd410, DeleteUrlCacheContainerW@0x21520 / A@0x19f9e0,
 * GetUrlCacheConfigInfoW@0x1a0b40 / A@0x1a0890 + GetUrlCacheConfigInfoHelper@0x1ab1a4, SetUrlCacheConfigInfoW@0x1a2460,
 * FreeUrlCacheSpaceW@0x1a0790 (percent > 100 -> 87), IsUrlCacheEntryExpiredW@0x1a1660 / A@0x1a1500,
 * GetUrlCacheEntryBinaryBlobInternal@0xe5080 (returns the error code), CommitUrlCacheEntryBinaryBlobInternal@0x33298.
 * VM_TIMEOUT: 180 */
#include "ueg.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ FindFirst/NextUrlCacheContainer */
TEST(ueg_container_find_null_args_a) {
    REQUIRE(UN(FindFirstUrlCacheContainerA));
    char buf[1024]; DWORD sz = sizeof buf, mod = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindFirstUrlCacheContainerA)(NULL, (UEG_CONTAINER_INFOA *)buf, &sz, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindFirstUrlCacheContainerA)(&mod, NULL, &sz, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindFirstUrlCacheContainerA)(&mod, (UEG_CONTAINER_INFOA *)buf, NULL, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(mod, 0);
    EXPECT_EQ(sz, sizeof buf);
}
TEST(ueg_container_find_null_args_w) {
    REQUIRE(UN(FindFirstUrlCacheContainerW));
    char buf[1024]; DWORD sz = sizeof buf, mod = 0;
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindFirstUrlCacheContainerW)(NULL, (UEG_CONTAINER_INFOW *)buf, &sz, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindFirstUrlCacheContainerW)(&mod, NULL, &sz, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindFirstUrlCacheContainerW)(&mod, (UEG_CONTAINER_INFOW *)buf, NULL, 0), ERROR_INVALID_PARAMETER);
}
/* Enumerates the extensible containers present on this box. Either a list ending in 259, or 259 straight away. */
TEST(ueg_container_enum_a) {
    REQUIRE(UN(FindFirstUrlCacheContainerA)); REQUIRE(UN(FindNextUrlCacheContainerA)); REQUIRE(U(FindCloseUrlCache));
    DWORD cap = 4096; UEG_CONTAINER_INFOA *ci = malloc(cap); DWORD sz = cap, mod = 0;
    SET_ERR(0xdead);
    HANDLE h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &sz, 0);
    DWORD e = GetLastError();
    t_note("container modified counter %lu", mod);
    if (!h) { EXPECT_EQ(e, ERROR_NO_MORE_ITEMS); t_note("no extensible containers"); free(ci); return; }
    EXPECT_EQ(e, 0);
    int n = 0;
    do {
        n++;
        EXPECT_EQ(ci->dwCacheVersion, 0x70);
        CHECK(ci->lpszName && ci->lpszCachePrefix && ci->lpszVolumeLabel && ci->lpszVolumeTitle);
        if (ci->lpszName && ci->lpszCachePrefix) {
            DWORD want = 0x28 + ueg_align4((DWORD)strlen(ci->lpszName) + 1) + ueg_align4((DWORD)strlen(ci->lpszCachePrefix) + 1) + 8;
            EXPECT_EQ(sz, want);
            CHECK((char *)ci->lpszName == (char *)ci + 0x28);
            EXPECT_STR(ci->lpszVolumeLabel, "");
            EXPECT_STR(ci->lpszVolumeTitle, "");
            CHECK(strlen(ci->lpszName) > 0);
            t_note("container '%s' prefix '%s'", ci->lpszName, ci->lpszCachePrefix);
        }
        sz = cap;
    } while (n < 500 && UN(FindNextUrlCacheContainerA)(h, ci, &sz));
    if (n < 500) EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    sz = cap; SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindNextUrlCacheContainerA)(h, ci, &sz), ERROR_NO_MORE_ITEMS);
    CHECK(U(FindCloseUrlCache)(h));
    free(ci);
}
TEST(ueg_container_enum_w_matches_a) {
    REQUIRE(UN(FindFirstUrlCacheContainerA)); REQUIRE(UN(FindFirstUrlCacheContainerW)); REQUIRE(UN(FindNextUrlCacheContainerA)); REQUIRE(UN(FindNextUrlCacheContainerW));
    DWORD cap = 4096; UEG_CONTAINER_INFOA *a = malloc(cap); UEG_CONTAINER_INFOW *w = malloc(cap);
    DWORD sa = cap, sw = cap, ma = 0, mw = 0;
    HANDLE ha = UN(FindFirstUrlCacheContainerA)(&ma, a, &sa, 0);
    HANDLE hw = UN(FindFirstUrlCacheContainerW)(&mw, w, &sw, 0);
    CHECK((ha == NULL) == (hw == NULL));
    EXPECT_EQ(ma, mw);
    int n = 0;
    while (ha && hw && n < 500) {
        n++;
        EXPECT_EQ(w->dwCacheVersion, 0x70);
        CHECK(!lstrcmpW(w->lpszName, ueg_w(a->lpszName)));
        CHECK(!lstrcmpW(w->lpszCachePrefix, ueg_w(a->lpszCachePrefix)));
        DWORD want = 0x28 + ueg_align4(2 * ((DWORD)lstrlenW(w->lpszName) + 1)) + ueg_align4(2 * ((DWORD)lstrlenW(w->lpszCachePrefix) + 1)) + 8;
        EXPECT_EQ(sw, want);
        sa = cap; sw = cap;
        BOOL ra = UN(FindNextUrlCacheContainerA)(ha, a, &sa), rw = UN(FindNextUrlCacheContainerW)(hw, w, &sw);
        CHECK(ra == rw);
        if (!ra || !rw) break;
    }
    if (ha) U(FindCloseUrlCache)(ha);
    if (hw) U(FindCloseUrlCache)(hw);
    t_note("%d extensible containers", n);
    free(a); free(w);
}
TEST(ueg_container_find_small_buffer) {
    REQUIRE(UN(FindFirstUrlCacheContainerA)); REQUIRE(UN(FindNextUrlCacheContainerA));
    DWORD cap = 4096; UEG_CONTAINER_INFOA *ci = malloc(cap); DWORD sz = cap, mod = 0;
    HANDLE h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &sz, 0);
    if (!h) { free(ci); t_skip("no extensible containers on this box"); return; }
    DWORD need = sz;
    U(FindCloseUrlCache)(h);
    DWORD small = 0x28; mod = 0; SET_ERR(0xdead);
    h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &small, 0);
    EXPECT_FAIL(h == NULL, ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(small, need);
    if (h) U(FindCloseUrlCache)(h);
    small = need; mod = 0;
    h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &small, 0);
    CHECK(h != NULL);
    if (h) {
        DWORD z = 4; SET_ERR(0xdead);
        BOOL r = UN(FindNextUrlCacheContainerA)(h, ci, &z);
        CHECK(!r);
        DWORD e = GetLastError();
        CHECK(e == ERROR_INSUFFICIENT_BUFFER || e == ERROR_NO_MORE_ITEMS);
        U(FindCloseUrlCache)(h);
    }
    free(ci);
}
/* CACHE_FIND_CONTAINER_RETURN_NOCHANGE with an up-to-date counter -> ERROR_INTERNET_NO_NEW_CONTAINERS (12051). */
TEST(ueg_container_find_nochange_12051) {
    REQUIRE(UN(FindFirstUrlCacheContainerA)); REQUIRE(UN(FindFirstUrlCacheContainerW));
    DWORD cap = 4096; UEG_CONTAINER_INFOA *ci = malloc(cap); DWORD sz = cap, mod = 0xffffffff;
    HANDLE h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &sz, 0);
    if (h) U(FindCloseUrlCache)(h);
    DWORD cur = mod;
    CHECK(cur != 0xffffffff);
    sz = cap; SET_ERR(0xdead);
    h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &sz, UEG_FIND_CONTAINER_RETURN_NOCHANGE);
    EXPECT_FAIL(h == NULL, UEG_ERROR_NO_NEW_CONTAINERS);
    EXPECT_EQ(mod, cur);
    if (h) U(FindCloseUrlCache)(h);
    sz = cap; SET_ERR(0xdead);
    h = UN(FindFirstUrlCacheContainerW)(&mod, (UEG_CONTAINER_INFOW *)ci, &sz, UEG_FIND_CONTAINER_RETURN_NOCHANGE);
    EXPECT_FAIL(h == NULL, UEG_ERROR_NO_NEW_CONTAINERS);
    if (h) U(FindCloseUrlCache)(h);
    /* a stale counter with NOCHANGE behaves like option 0 and refreshes *pdwModified */
    DWORD stale = cur + 12345; sz = cap; SET_ERR(0xdead);
    h = UN(FindFirstUrlCacheContainerA)(&stale, ci, &sz, UEG_FIND_CONTAINER_RETURN_NOCHANGE);
    DWORD e = GetLastError();
    CHECK(h != NULL || e == ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(stale, cur);
    if (h) U(FindCloseUrlCache)(h);
    /* other option bits are ignored */
    sz = cap; mod = 0xfffffffe;
    h = UN(FindFirstUrlCacheContainerA)(&mod, ci, &sz, 0xfffffffe);
    e = GetLastError();
    CHECK(h != NULL || e == ERROR_NO_MORE_ITEMS);
    if (h) U(FindCloseUrlCache)(h);
    free(ci);
}
TEST(ueg_container_findnext_args) {
    REQUIRE(UN(FindNextUrlCacheContainerA)); REQUIRE(UN(FindNextUrlCacheContainerW));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindNextUrlCacheContainerA)((HANDLE)1, NULL, &sz), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindNextUrlCacheContainerA)((HANDLE)1, (UEG_CONTAINER_INFOA *)buf, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindNextUrlCacheContainerW)((HANDLE)1, NULL, &sz), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(FindNextUrlCacheContainerW)((HANDLE)1, (UEG_CONTAINER_INFOW *)buf, NULL), ERROR_INVALID_PARAMETER);
}
/* An invalid handle (6 inside) is reported as ERROR_INVALID_PARAMETER by the container APIs [D]. */
TEST(ueg_container_findnext_bad_handle_87) {
    REQUIRE(UN(FindNextUrlCacheContainerA)); REQUIRE(UN(FindNextUrlCacheContainerW));
    static const ULONG_PTR hv[] = { 0, 2, 0x100, 0x7ffffff1 };
    for (size_t i = 0; i < 4; i++) {
        char buf[1024]; DWORD sz = sizeof buf;
        SET_ERR(0xdead);
        CHECK(!UN(FindNextUrlCacheContainerA)((HANDLE)hv[i], (UEG_CONTAINER_INFOA *)buf, &sz));
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "A handle 0x%llx err %lu", (unsigned long long)hv[i], e);
        sz = sizeof buf; SET_ERR(0xdead);
        CHECK(!UN(FindNextUrlCacheContainerW)((HANDLE)hv[i], (UEG_CONTAINER_INFOW *)buf, &sz));
        e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "W handle 0x%llx err %lu", (unsigned long long)hv[i], e);
    }
}
TEST(ueg_container_findnext_entry_handle_87) {
    REQUIRE(UN(FindNextUrlCacheContainerA)); REQUIRE(U(FindFirstUrlCacheEntryA));
    const char *url = ueg_url("cfe");
    if (!ueg_make_simple(url)) { t_skip("no entry"); return; }
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, e, &sz);
    CHECK(h != NULL);
    if (h) {
        sz = cap; SET_ERR(0xdead);
        EXPECT_FAIL(!UN(FindNextUrlCacheContainerA)(h, (UEG_CONTAINER_INFOA *)e, &sz), ERROR_INVALID_PARAMETER);
        sz = cap;
        BOOL r = U(FindNextUrlCacheEntryA)(h, e, &sz);
        CHECK(r || GetLastError() == ERROR_NO_MORE_ITEMS);     /* the entry handle survives */
        CHECK(U(FindCloseUrlCache)(h));
    }
    free(e);
}

/* ------------------------------------------------------------------ Create/DeleteUrlCacheContainer: argument checks only */
TEST(ueg_create_container_bad_args_w) {
    REQUIRE(UN(CreateUrlCacheContainerW));
    WCHAR longname[80]; for (int i = 0; i < 64; i++) longname[i] = 'n'; longname[64] = 0;      /* 64 chars: too long */
    WCHAR name[64]; lstrcpyW(name, ueg_w(t_uniq("ctr")));
    DWORD dummy = 0; char pv[4];
    struct { const WCHAR *n, *p; void *pv; DWORD *cb; } cases[] = {
        { NULL, L"uegpfx:", NULL, NULL }, { L"", L"uegpfx:", NULL, NULL }, { longname, L"uegpfx:", NULL, NULL },
        { name, NULL, NULL, NULL }, { name, L"", NULL, NULL }, { name, L"uegpfx:", pv, NULL }, { name, L"uegpfx:", NULL, &dummy },
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        SET_ERR(0xdead);
        BOOL r = UN(CreateUrlCacheContainerW)(cases[i].n, cases[i].p, NULL, 0, 0, 0, cases[i].pv, cases[i].cb);
        CHECKF(!r, "case %u created a container", (unsigned)i);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "case %u err %lu", (unsigned)i, e);
        if (r) UN(DeleteUrlCacheContainerW)(cases[i].n, 0);
    }
}
TEST(ueg_create_container_bad_args_a) {
    REQUIRE(UN(CreateUrlCacheContainerA));
    char longname[80]; memset(longname, 'n', 64); longname[64] = 0;
    char name[64]; snprintf(name, sizeof name, "%s", t_uniq("ctra"));
    DWORD dummy = 0; char pv[4];
    struct { const char *n, *p; void *pv; DWORD *cb; } cases[] = {
        { NULL, "uegpfx:", NULL, NULL }, { "", "uegpfx:", NULL, NULL }, { longname, "uegpfx:", NULL, NULL },
        { name, NULL, NULL, NULL }, { name, "", NULL, NULL }, { name, "uegpfx:", pv, NULL }, { name, "uegpfx:", NULL, &dummy },
    };
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        SET_ERR(0xdead);
        BOOL r = UN(CreateUrlCacheContainerA)(cases[i].n, cases[i].p, NULL, 0, 0, 0, cases[i].pv, cases[i].cb);
        CHECKF(!r, "case %u created a container", (unsigned)i);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "case %u err %lu", (unsigned)i, e);
        if (r) UN(DeleteUrlCacheContainerA)(cases[i].n, 0);
    }
}
TEST(ueg_delete_container_bad_args) {
    REQUIRE(UN(DeleteUrlCacheContainerA)); REQUIRE(UN(DeleteUrlCacheContainerW));
    SET_ERR(0xdead); EXPECT_FAIL(!UN(DeleteUrlCacheContainerA)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(DeleteUrlCacheContainerA)("", 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(DeleteUrlCacheContainerW)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(DeleteUrlCacheContainerW)(L"", 0), ERROR_INVALID_PARAMETER);
}
/* Deleting a container name that does not exist touches nothing; record the error. */
TEST(ueg_delete_container_missing) {
    REQUIRE(UN(DeleteUrlCacheContainerA)); REQUIRE(UN(DeleteUrlCacheContainerW));
    const char *nm = t_uniq("nosuchctr");
    SET_ERR(0xdead);
    BOOL r = UN(DeleteUrlCacheContainerA)(nm, 0);
    DWORD e = GetLastError();
    t_note("DeleteUrlCacheContainerA(missing) -> %d err %lu", r, e);
    SET_ERR(0xdead);
    BOOL rw = UN(DeleteUrlCacheContainerW)(ueg_w(t_uniq("nosuchctrw")), 0);
    DWORD ew = GetLastError();
    t_note("DeleteUrlCacheContainerW(missing) -> %d err %lu", rw, ew);
    CHECK(r == rw);
    CHECK(e == ew);
}

/* ------------------------------------------------------------------ GetUrlCacheConfigInfo */
TEST(ueg_config_null_87) {
    REQUIRE(UN(GetUrlCacheConfigInfoA)); REQUIRE(UN(GetUrlCacheConfigInfoW));
    DWORD cb = 0;
    SET_ERR(0xdead); EXPECT_FAIL(!UN(GetUrlCacheConfigInfoA)(NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(GetUrlCacheConfigInfoA)(NULL, &cb, UEG_CC_CONTENT_PATHS_FC), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(GetUrlCacheConfigInfoW)(NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(GetUrlCacheConfigInfoW)(NULL, &cb, UEG_CC_CONTENT_PATHS_FC), ERROR_INVALID_PARAMETER);
}
TEST(ueg_config_struct_sizes) {
    EXPECT_EQ(sizeof(UEG_CONFIG_INFOA), 300);
    EXPECT_EQ(sizeof(UEG_CONFIG_INFOW), 0x230);
}
static const struct { DWORD fc; DWORD container; } k_paths[] = {
    { UEG_CC_CONTENT_PATHS_FC, 0 }, { UEG_CC_COOKIES_PATHS_FC, 1 }, { UEG_CC_HISTORY_PATHS_FC, 2 },
};
TEST(ueg_config_paths_w) {
    REQUIRE(UN(GetUrlCacheConfigInfoW));
    for (int i = 0; i < 3; i++) {
        UEG_CONFIG_INFOW c; memset(&c, 0xCC, sizeof c); c.dwStructSize = sizeof c; c.dwContainer = 77;
        SET_ERR(0xdead);
        BOOL r = UN(GetUrlCacheConfigInfoW)(&c, NULL, k_paths[i].fc);
        CHECKF(r, "fc 0x%lx err %lu", k_paths[i].fc, GetLastError());
        if (!r) continue;
        EXPECT_ERR(0);
        EXPECT_EQ(c.dwContainer, k_paths[i].container);
        EXPECT_EQ(c.fPerUser, 1);
        EXPECT_EQ(c.dwNumCachePaths, 1);
        CHECK(c.CachePath[0] != 0);
        DWORD at = GetFileAttributesW(c.CachePath);
        CHECKF(at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_DIRECTORY), "path attrs 0x%lx", at);
        CHECK(c.dwQuota != 0xCCCCCCCC);
        EXPECT_EQ(c.dwReserved4, 0xCCCCCCCC);      /* never written */
        char pa[MAX_PATH * 2]; WideCharToMultiByte(CP_ACP, 0, c.CachePath, -1, pa, sizeof pa, NULL, NULL);
        t_note("container %lu path '%s' quota %lu KB", c.dwContainer, pa, c.dwQuota);
    }
}
TEST(ueg_config_paths_a) {
    REQUIRE(UN(GetUrlCacheConfigInfoA)); REQUIRE(UN(GetUrlCacheConfigInfoW));
    for (int i = 0; i < 3; i++) {
        UEG_CONFIG_INFOA c; memset(&c, 0xCC, sizeof c); c.dwStructSize = sizeof c; c.dwContainer = 0;
        SET_ERR(0xdead);
        BOOL r = UN(GetUrlCacheConfigInfoA)(&c, NULL, k_paths[i].fc);
        CHECKF(r, "fc 0x%lx err %lu", k_paths[i].fc, GetLastError());
        if (!r) continue;
        EXPECT_EQ(c.fPerUser, 1);
        EXPECT_EQ(c.dwNumCachePaths, 1);
        size_t L = strnlen(c.CachePath, MAX_PATH);
        CHECK(L > 0 && L < MAX_PATH);
        if (L) CHECKF(c.CachePath[L - 1] == '\\', "A path '%s' lacks the trailing backslash", c.CachePath);
        /* the A path is the W path (+ '\' if the W one lacks it) */
        UEG_CONFIG_INFOW w; memset(&w, 0, sizeof w); w.dwStructSize = sizeof w;
        if (UN(GetUrlCacheConfigInfoW)(&w, NULL, k_paths[i].fc)) {
            char wa[MAX_PATH * 2]; WideCharToMultiByte(CP_ACP, 0, w.CachePath, -1, wa, sizeof wa, NULL, NULL);
            size_t wl = strlen(wa);
            if (wl && wa[wl - 1] != '\\') { wa[wl] = '\\'; wa[wl + 1] = 0; }
            CHECKF(!lstrcmpiA(wa, c.CachePath), "A '%s' vs W '%s'", c.CachePath, wa);
            EXPECT_EQ(c.dwQuota, w.dwQuota);
        }
        /* the A API never writes dwContainer */
        EXPECT_EQ(c.dwContainer, 0);
    }
}
/* No *_PATHS_FC: dwContainer selects the container; an invalid one with QUOTA_FC -> 2, without any flag -> TRUE and
 * nothing but fPerUser written. */
TEST(ueg_config_container_selector_w) {
    REQUIRE(UN(GetUrlCacheConfigInfoW));
    for (DWORD k = 0; k < 3; k++) {
        UEG_CONFIG_INFOW c; memset(&c, 0xCC, sizeof c); c.dwStructSize = sizeof c; c.dwContainer = k;
        CHECK(UN(GetUrlCacheConfigInfoW)(&c, NULL, UEG_CC_QUOTA_FC));
        EXPECT_EQ(c.dwContainer, k);
        EXPECT_EQ(c.dwNumCachePaths, 1);
        CHECK(c.dwQuota != 0xCCCCCCCC);
    }
    UEG_CONFIG_INFOW c; memset(&c, 0xCC, sizeof c); c.dwStructSize = sizeof c; c.dwContainer = 5;
    SET_ERR(0xdead);
    EXPECT_FAIL(!UN(GetUrlCacheConfigInfoW)(&c, NULL, UEG_CC_QUOTA_FC), ERROR_FILE_NOT_FOUND);
    memset(&c, 0xCC, sizeof c); c.dwStructSize = sizeof c; c.dwContainer = 5;
    SET_ERR(0xdead);
    CHECK(UN(GetUrlCacheConfigInfoW)(&c, NULL, 0));
    EXPECT_ERR(0);
    EXPECT_EQ(c.fPerUser, 1);
    EXPECT_EQ(c.dwNumCachePaths, 0xCCCCCCCC);
    EXPECT_EQ(c.dwQuota, 0xCCCCCCCC);
    EXPECT_EQ(c.dwContainer, 5);
}
TEST(ueg_config_sync_mode) {
    REQUIRE(UN(GetUrlCacheConfigInfoW)); REQUIRE(UN(GetUrlCacheConfigInfoA));
    UEG_CONFIG_INFOW w; memset(&w, 0xCC, sizeof w); w.dwStructSize = sizeof w; w.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoW)(&w, NULL, UEG_CC_SYNC_MODE_FC));
    CHECK(w.dwSyncMode <= 4);
    UEG_CONFIG_INFOA a; memset(&a, 0xCC, sizeof a); a.dwStructSize = sizeof a; a.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoA)(&a, NULL, UEG_CC_SYNC_MODE_FC));
    EXPECT_EQ(a.dwSyncMode, w.dwSyncMode);
    t_note("cache sync mode %lu", w.dwSyncMode);
    /* without SYNC_MODE_FC the field is untouched */
    memset(&w, 0xCC, sizeof w); w.dwStructSize = sizeof w; w.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoW)(&w, NULL, UEG_CC_CONTENT_PATHS_FC));
    EXPECT_EQ(w.dwSyncMode, 0xCCCCCCCC);
}
/* CONTENT_USAGE_FC fills dwNormalUsage only when dwStructSize is the full size [D]. */
TEST(ueg_config_usage_needs_full_struct) {
    REQUIRE(UN(GetUrlCacheConfigInfoW));
    UEG_CONFIG_INFOW c; memset(&c, 0xCC, sizeof c); c.dwStructSize = sizeof c; c.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoW)(&c, NULL, UEG_CC_CONTENT_USAGE_FC | UEG_CC_STICKY_USAGE_FC));
    CHECK(c.dwNormalUsage != 0xCCCCCCCC);
    EXPECT_EQ(c.dwExemptUsage, 0);
    memset(&c, 0xCC, sizeof c); c.dwStructSize = 0x22c; c.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoW)(&c, NULL, UEG_CC_CONTENT_USAGE_FC | UEG_CC_STICKY_USAGE_FC));
    EXPECT_EQ(c.dwNormalUsage, 0xCCCCCCCC);
    EXPECT_EQ(c.dwExemptUsage, 0xCCCCCCCC);
}
TEST(ueg_config_usage_a) {
    REQUIRE(UN(GetUrlCacheConfigInfoA));
    UEG_CONFIG_INFOA c; memset(&c, 0xCC, sizeof c); c.dwStructSize = 300; c.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoA)(&c, NULL, UEG_CC_CONTENT_USAGE_FC | UEG_CC_STICKY_USAGE_FC));
    CHECK(c.dwNormalUsage != 0xCCCCCCCC);
    EXPECT_EQ(c.dwExemptUsage, 0);
    memset(&c, 0xCC, sizeof c); c.dwStructSize = 0x128; c.dwContainer = 0;
    CHECK(UN(GetUrlCacheConfigInfoA)(&c, NULL, UEG_CC_CONTENT_USAGE_FC | UEG_CC_STICKY_USAGE_FC));
    EXPECT_EQ(c.dwNormalUsage, 0xCCCCCCCC);
}
/* dwStructSize is not validated (0 works) and the size argument is ignored */
TEST(ueg_config_structsize_not_validated) {
    REQUIRE(UN(GetUrlCacheConfigInfoW));
    UEG_CONFIG_INFOW c; memset(&c, 0, sizeof c); c.dwStructSize = 0;
    DWORD cb = 1;
    SET_ERR(0xdead);
    CHECK(UN(GetUrlCacheConfigInfoW)(&c, &cb, UEG_CC_CONTENT_PATHS_FC));
    EXPECT_EQ(cb, 1);
    EXPECT_EQ(c.dwNumCachePaths, 1);
}
TEST(ueg_set_config_null_87) {
    REQUIRE(UN(SetUrlCacheConfigInfoA)); REQUIRE(UN(SetUrlCacheConfigInfoW));
    SET_ERR(0xdead); EXPECT_FAIL(!UN(SetUrlCacheConfigInfoA)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(SetUrlCacheConfigInfoW)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(SetUrlCacheConfigInfoW)(NULL, UEG_CC_QUOTA_FC), ERROR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ FreeUrlCacheSpace: argument checks only */
TEST(ueg_free_space_percent_over_100_87) {
    REQUIRE(UN(FreeUrlCacheSpaceA)); REQUIRE(UN(FreeUrlCacheSpaceW));
    static const DWORD bad[] = { 101, 200, 0x10000, 0xffffffff };
    for (size_t i = 0; i < 4; i++) {
        SET_ERR(0xdead);
        CHECK(!UN(FreeUrlCacheSpaceW)(NULL, bad[i], 0));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0xdead);
        CHECK(!UN(FreeUrlCacheSpaceA)(NULL, bad[i], 0));
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "A %lu err %lu", bad[i], e);
    }
}
TEST(ueg_free_space_exports) {
    CHECK(t_proc_in("wininet.dll", "FreeUrlCacheSpaceA") != NULL);
    CHECK(t_proc_in("wininet.dll", "FreeUrlCacheSpaceW") != NULL);
    CHECK(t_proc_in("wininet.dll", "UrlCacheFreeGlobalSpace") != NULL);
    CHECK(t_proc_in("wininet.dll", "UrlCacheFreeSpace") == NULL);   /* no such export */
}

/* ------------------------------------------------------------------ IsUrlCacheEntryExpired */
TEST(ueg_expired_null_args) {
    REQUIRE(UN(IsUrlCacheEntryExpiredA)); REQUIRE(UN(IsUrlCacheEntryExpiredW));
    FILETIME ft = ueg_ft(0x1234);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(IsUrlCacheEntryExpiredA)(NULL, 0, &ft), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(ueg_u64(ft), 0x1234);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(IsUrlCacheEntryExpiredA)("http://x.example/", 0, NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(IsUrlCacheEntryExpiredW)(NULL, 0, &ft), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!UN(IsUrlCacheEntryExpiredW)(L"http://x.example/", 0, NULL), ERROR_INVALID_PARAMETER);
}
TEST(ueg_expired_missing_entry) {
    REQUIRE(UN(IsUrlCacheEntryExpiredA)); REQUIRE(UN(IsUrlCacheEntryExpiredW));
    const char *url = ueg_url("expmiss");
    FILETIME ft = ueg_ft(0x55555555);
    SET_ERR(0xdead);
    BOOL r = UN(IsUrlCacheEntryExpiredA)(url, 0, &ft);
    EXPECT_FAIL(!r, ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(ueg_u64(ft), 0);                    /* zeroed before the lookup [D] */
    ft = ueg_ft(0x55555555); SET_ERR(0xdead);
    r = UN(IsUrlCacheEntryExpiredW)(ueg_w(url), 0, &ft);
    EXPECT_FAIL(!r, ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(ueg_u64(ft), 0);
}
TEST(ueg_expired_past_and_future) {
    REQUIRE(UN(IsUrlCacheEntryExpiredA)); REQUIRE(UN(IsUrlCacheEntryExpiredW));
    const char *old = ueg_url("expold"), *fresh = ueg_url("expnew");
    FILETIME lm = ueg_days(-10);
    if (!ueg_make_entry(old, NORMAL_CACHE_ENTRY, ueg_days(-3), lm, NULL, "txt", "o") ||
        !ueg_make_entry(fresh, NORMAL_CACHE_ENTRY, ueg_days(30), lm, NULL, "txt", "n")) { t_skip("commit failed"); return; }
    FILETIME ft = ueg_ft(0);
    SET_ERR(0xdead);
    BOOL r = UN(IsUrlCacheEntryExpiredA)(old, 0, &ft);
    CHECK(r);
    EXPECT_ERR(0);
    EXPECT_EQ(ueg_u64(ft), ueg_u64(lm));          /* returns the entry's last-modified time */
    ft = ueg_ft(0); SET_ERR(0xdead);
    r = UN(IsUrlCacheEntryExpiredA)(fresh, 0, &ft);
    CHECK(!r);
    EXPECT_ERR(0);
    EXPECT_EQ(ueg_u64(ft), ueg_u64(lm));
    ft = ueg_ft(0);
    CHECK(UN(IsUrlCacheEntryExpiredW)(ueg_w(old), 0, &ft));
    EXPECT_EQ(ueg_u64(ft), ueg_u64(lm));
    ft = ueg_ft(0); SET_ERR(0xdead);
    CHECK(!UN(IsUrlCacheEntryExpiredW)(ueg_w(fresh), 0, &ft));
    EXPECT_ERR(0);
}
TEST(ueg_expired_no_expire_time) {
    REQUIRE(UN(IsUrlCacheEntryExpiredA));
    const char *url = ueg_url("expnone");
    if (!ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_ft(0), ueg_days(-1), NULL, "txt", "z")) { t_skip("commit failed"); return; }
    FILETIME ft = ueg_ft(0);
    SET_ERR(0xdead);
    BOOL r = UN(IsUrlCacheEntryExpiredA)(url, 0, &ft);
    t_note("entry without expire time: expired=%d err=%lu", r, GetLastError());
    CHECK(ueg_u64(ft) != 0);
}
TEST(ueg_expired_flags_variants) {
    REQUIRE(UN(IsUrlCacheEntryExpiredA));
    const char *old = ueg_url("expfl"), *fresh = ueg_url("expfl2");
    if (!ueg_make_entry(old, NORMAL_CACHE_ENTRY, ueg_days(-3), ueg_days(-10), NULL, "txt", "o") ||
        !ueg_make_entry(fresh, NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-10), NULL, "txt", "n")) { t_skip("commit failed"); return; }
    static const DWORD fl[] = { 0, 1, 2, 0x100, 0x80000000 };
    for (size_t i = 0; i < 5; i++) {
        FILETIME ft;
        BOOL a = UN(IsUrlCacheEntryExpiredA)(old, fl[i], &ft);
        BOOL b = UN(IsUrlCacheEntryExpiredA)(fresh, fl[i], &ft);
        t_note("flags 0x%lx: past-expiry entry %d, future-expiry entry %d", fl[i], a, b);
        CHECK(!b);
    }
}

/* ------------------------------------------------------------------ binary blobs */
TEST(ueg_blob_get_null_args_87) {
    REQUIRE(UN(GetUrlCacheEntryBinaryBlob));
    DWORD type = 7, cb = 9; FILETIME a = ueg_ft(1), b = ueg_ft(2), c = ueg_ft(3); BYTE *blob = (BYTE *)1;
    const WCHAR *u = ueg_w(ueg_url("blobargs"));
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(NULL, &type, &a, &b, &c, &blob, &cb), ERROR_INVALID_PARAMETER);
    /* every output was cleared first */
    EXPECT_EQ(type, 0); EXPECT_EQ(cb, 0); CHECK(blob == NULL);
    EXPECT_EQ(ueg_u64(a), 0); EXPECT_EQ(ueg_u64(b), 0); EXPECT_EQ(ueg_u64(c), 0);
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(u, NULL, &a, &b, &c, &blob, &cb), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(u, &type, NULL, &b, &c, &blob, &cb), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(u, &type, &a, NULL, &c, &blob, &cb), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(u, &type, &a, &b, NULL, &blob, &cb), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(u, &type, &a, &b, &c, NULL, &cb), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(GetUrlCacheEntryBinaryBlob)(u, &type, &a, &b, &c, &blob, NULL), ERROR_INVALID_PARAMETER);
}
TEST(ueg_blob_get_missing) {
    REQUIRE(UN(GetUrlCacheEntryBinaryBlob));
    DWORD type = 7, cb = 9; FILETIME a, b, c; BYTE *blob = NULL;
    DWORD r = UN(GetUrlCacheEntryBinaryBlob)(ueg_w(ueg_url("blobmiss")), &type, &a, &b, &c, &blob, &cb);
    EXPECT_EQ(r, ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(type, 0); EXPECT_EQ(cb, 0); CHECK(blob == NULL);
}
TEST(ueg_blob_commit_args) {
    REQUIRE(UN(CommitUrlCacheEntryBinaryBlob));
    BYTE data[4] = { 1, 2, 3, 4 };
    EXPECT_EQ(UN(CommitUrlCacheEntryBinaryBlob)(NULL, 1, ueg_days(1), ueg_days(-1), data, 4), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(CommitUrlCacheEntryBinaryBlob)(L"", 1, ueg_days(1), ueg_days(-1), data, 4), ERROR_INVALID_PARAMETER);
}
TEST(ueg_blob_roundtrip) {
    REQUIRE(UN(CommitUrlCacheEntryBinaryBlob)); REQUIRE(UN(GetUrlCacheEntryBinaryBlob));
    const char *url = ueg_url("blob");
    BYTE data[300]; for (int i = 0; i < 300; i++) data[i] = (BYTE)(i * 7 + 1);
    FILETIME exp = ueg_days(20), mod = ueg_days(-4);
    DWORD r = UN(CommitUrlCacheEntryBinaryBlob)(ueg_w(url), 0x1234, exp, mod, data, sizeof data);
    EXPECT_EQ(r, 0);
    if (r) { t_note("commit blob err %lu", r); return; }
    DWORD type = 0, cb = 0; FILETIME a, b, c; BYTE *blob = NULL;
    r = UN(GetUrlCacheEntryBinaryBlob)(ueg_w(url), &type, &a, &b, &c, &blob, &cb);
    EXPECT_EQ(r, 0);
    if (r) return;
    EXPECT_EQ(cb, sizeof data);
    CHECK(blob && !memcmp(blob, data, sizeof data));
    t_note("blob: type 0x%lx ft1 %llx ft2 %llx ft3 %llx (exp %llx mod %llx)", type, ueg_u64(a), ueg_u64(b), ueg_u64(c), ueg_u64(exp), ueg_u64(mod));
    CHECK(ueg_u64(a) == ueg_u64(exp) || ueg_u64(b) == ueg_u64(exp) || ueg_u64(c) == ueg_u64(exp));
    /* the blob is not freed: its allocator is internal; the leak is a few hundred bytes */
    int n = 0;
    t_note("blob entry visible to the content enumeration: %d", ueg_enum_contains_a("", 0, 0xffffffff, 0, url, &n));
}
TEST(ueg_blob_empty) {
    REQUIRE(UN(CommitUrlCacheEntryBinaryBlob)); REQUIRE(UN(GetUrlCacheEntryBinaryBlob));
    const char *url = ueg_url("blob0");
    DWORD r = UN(CommitUrlCacheEntryBinaryBlob)(ueg_w(url), 1, ueg_days(20), ueg_days(-1), NULL, 0);
    t_note("commit empty blob -> %lu", r);
    if (r) return;
    DWORD type = 0, cb = 77; FILETIME a, b, c; BYTE *blob = (BYTE *)1;
    r = UN(GetUrlCacheEntryBinaryBlob)(ueg_w(url), &type, &a, &b, &c, &blob, &cb);
    t_note("get empty blob -> %lu cb %lu blob %p", r, cb, blob);
}
