/* Ordinal-only exports with real bodies that are safe to drive: #103 PerformOperationOverUrlCacheA (a cache-entry
 * visitor, run only over a private cache group this test creates) and #403 InternetAutoProxyOnSendRequestComplete
 * (argument validation only), plus a per-ordinal cross-check that every ordinal-only export is distinct code or a
 * known folded alias.
 * VM_TIMEOUT: 120 */
#include "gs.h"
#include "tnet.h"

/* ================================================================== #103 PerformOperationOverUrlCacheA
 * [D PerformOperationOverUrlCacheA@0x1a7420]
 *   buf = HeapAlloc(0x470); h = FindFirstUrlCacheEntryExA(a1, a2, a3, a4, buf, &cb, a5, a6, a7)
 *   (retry once with a bigger buffer on 122); h == NULL -> return 0 (whatever the reason);
 *   loop: cb(entry, &cb, a9) until it returns FALSE or FindNext fails; FindCloseUrlCache;
 *   return GetLastError() == ERROR_NO_MORE_ITEMS. GetLastError is never set by the function itself. */
typedef BOOL (WINAPI *gs_visit_cb)(INTERNET_CACHE_ENTRY_INFOA *, DWORD *, void *);
typedef BOOL (WINAPI *gs_PerformOp)(LPCSTR, DWORD, DWORD, GROUPID, void *, DWORD *, void *, gs_visit_cb, void *);
#define GS_FILTER (NORMAL_CACHE_ENTRY | COOKIE_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY | TRACK_OFFLINE_CACHE_ENTRY | \
                   TRACK_ONLINE_CACHE_ENTRY | STICKY_CACHE_ENTRY)

typedef struct { int calls; int stop_after; int ctx_ok; int size_ok; char seen[4][200]; } gs_visit;
static BOOL WINAPI gs_visit_fn(INTERNET_CACHE_ENTRY_INFOA *e, DWORD *cb, void *ctx) {
    gs_visit *v = (gs_visit *)ctx;
    if (!v) return FALSE;
    v->ctx_ok++;
    if (cb && *cb >= sizeof *e) v->size_ok++;
    if (v->calls < 4 && e && e->lpszSourceUrlName) lstrcpynA(v->seen[v->calls], e->lpszSourceUrlName, 200);
    v->calls++;
    return v->calls < v->stop_after;
}

static int gs_cache_entry(const char *url) {
    char file[MAX_PATH];
    if (!U(CreateUrlCacheEntryA) || !U(CommitUrlCacheEntryA)) return 0;
    if (!U(CreateUrlCacheEntryA)(url, 0, "txt", file, 0)) return 0;
    HANDLE h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w; WriteFile(h, "gs", 2, &w, NULL); CloseHandle(h);
    /* expiry 30 days ahead, last-modified one day back (same shape as the urlcache_enum_groups fixtures) */
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER u; u.LowPart = now.dwLowDateTime; u.HighPart = now.dwHighDateTime;
    ULARGE_INTEGER ex = u, lm = u;
    ex.QuadPart += 30ULL * 86400ULL * 10000000ULL; lm.QuadPart -= 86400ULL * 10000000ULL;
    FILETIME fe = { ex.LowPart, ex.HighPart }, fl = { lm.LowPart, lm.HighPart };
    if (!U(CommitUrlCacheEntryA)(url, file, fe, fl, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL)) return 0;
    t_cache_track(url);
    return 1;
}

/* a fresh group with n fresh entries; 0 on failure */
static GROUPID gs_group_with(int n, char urls[][200]) {
    if (!U(CreateUrlCacheGroup) || !U(SetUrlCacheEntryGroupA)) return 0;
    GROUPID g = U(CreateUrlCacheGroup)(0, NULL);
    if (!g) { t_note("CreateUrlCacheGroup failed: %lu", GetLastError()); return 0; }
    /* [VM boot 3] with the new group's quota of 0 KB, SetUrlCacheEntryGroupA(ADD) failed with 1816
     * (ERROR_NOT_ENOUGH_QUOTA): give the private group 1 MB first */
    if (U(SetUrlCacheGroupAttributeA)) {
        INTERNET_CACHE_GROUP_INFOA gi; memset(&gi, 0, sizeof gi); gi.dwGroupSize = sizeof gi; gi.dwDiskQuota = 1024;
        if (!U(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_QUOTA, &gi, NULL)) t_note("set group quota: %lu", GetLastError());
    }
    for (int i = 0; i < n; i++) {
        char tag[32]; snprintf(tag, sizeof tag, "gs_ord103_%d", i);
        lstrcpynA(urls[i], t_uniq_cache_url(tag), 200);
        int step = 0; DWORD e = 0;
        if (!gs_cache_entry(urls[i])) { step = 1; e = GetLastError(); }
        else if (!U(SetUrlCacheEntryGroupA)(urls[i], INTERNET_CACHE_GROUP_ADD, g, NULL, 0, NULL)) { step = 2; e = GetLastError(); }
        if (step) {
            t_note("group setup: entry %d failed at %s with %lu", i, step == 1 ? "create/commit" : "SetUrlCacheEntryGroupA", e);
            U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL);
            return 0;
        }
    }
    return g;
}

TEST(gs_ord103_reserved_rejected_no_callback) {
    REQUIRE_ORD(103);
    gs_PerformOp f = GS_ORD(gs_PerformOp, 103);
    gs_visit v; memset(&v, 0, sizeof v); v.stop_after = 100;
    int dummy = 0;
    SET_ERR(0x4242);
    BOOL r = f("", 0, GS_FILTER, 0, NULL, NULL, &dummy, gs_visit_fn, &v);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(v.calls, 0);
    /* the error is FindFirstUrlCacheEntryExA's (reserved != NULL -> 87) */
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
}

TEST(gs_ord103_empty_group_returns_false) {
    REQUIRE_ORD(103); REQUIRE(U(CreateUrlCacheGroup)); REQUIRE(U(DeleteUrlCacheGroup));
    gs_PerformOp f = GS_ORD(gs_PerformOp, 103);
    GROUPID g = U(CreateUrlCacheGroup)(0, NULL);
    if (!g) { t_skip("CreateUrlCacheGroup failed: %lu", GetLastError()); return; }
    gs_visit v; memset(&v, 0, sizeof v); v.stop_after = 100;
    SET_ERR(0x4242);
    BOOL r = f("", 0, GS_FILTER, g, NULL, NULL, NULL, gs_visit_fn, &v);
    DWORD e = GetLastError();
    /* FindFirst fails with ERROR_NO_MORE_ITEMS: the function returns FALSE on that path (only the loop path
     * maps 259 to TRUE) */
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(v.calls, 0);
    EXPECT_EQ(e, ERROR_NO_MORE_ITEMS);
    CHECK(U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL));
}

TEST(gs_ord103_visits_group_entries) {
    REQUIRE_ORD(103); REQUIRE(U(DeleteUrlCacheGroup));
    gs_PerformOp f = GS_ORD(gs_PerformOp, 103);
    char urls[3][200];
    GROUPID g = gs_group_with(3, urls);
    if (!g) { t_skip("group setup failed: %lu", GetLastError()); return; }
    gs_visit v; memset(&v, 0, sizeof v); v.stop_after = 100;
    SET_ERR(0x4242);
    BOOL r = f("", 0, GS_FILTER, g, NULL, NULL, NULL, gs_visit_fn, &v);
    DWORD e = GetLastError();
    EXPECT_EQ(r, TRUE);
    EXPECT_EQ(e, ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(v.calls, 3);
    EXPECT_EQ(v.ctx_ok, 3);
    EXPECT_EQ(v.size_ok, 3);
    for (int i = 0; i < 3; i++) {
        int found = 0;
        for (int j = 0; j < 3 && j < v.calls; j++) if (!lstrcmpiA(v.seen[j], urls[i])) found = 1;
        CHECKF(found, "%s not visited", urls[i]);
    }
    CHECK(U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL));
    t_net_cleanup();
}

TEST(gs_ord103_callback_stops) {
    REQUIRE_ORD(103); REQUIRE(U(DeleteUrlCacheGroup));
    gs_PerformOp f = GS_ORD(gs_PerformOp, 103);
    char urls[3][200];
    GROUPID g = gs_group_with(3, urls);
    if (!g) { t_skip("group setup failed: %lu", GetLastError()); return; }
    for (int stop = 1; stop <= 2; stop++) {
        gs_visit v; memset(&v, 0, sizeof v); v.stop_after = stop;
        SET_ERR(0x4242);
        BOOL r = f("", 0, GS_FILTER, g, NULL, NULL, NULL, gs_visit_fn, &v);
        DWORD e = GetLastError();
        EXPECT_EQ(v.calls, stop);
        /* the loop ends on the callback, not on 259: TRUE only if GetLastError happens to be 259 */
        CHECKF(r == (e == ERROR_NO_MORE_ITEMS), "stop=%d r=%d e=%lu", stop, r, e);
        t_note("#103 stop after %d: r=%d GLE=%lu", stop, r, e);
    }
    CHECK(U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL));
    t_net_cleanup();
}

TEST(gs_ord103_pattern_without_group) {
    REQUIRE_ORD(103);
    gs_PerformOp f = GS_ORD(gs_PerformOp, 103);
    /* a group id that was never created: nothing matches */
    gs_visit v; memset(&v, 0, sizeof v); v.stop_after = 100;
    SET_ERR(0);
    BOOL r = f("", 0, GS_FILTER, 0x7FFFFFFF12345678LL, NULL, NULL, NULL, gs_visit_fn, &v);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(v.calls, 0);
    t_note("#103 unknown group: GLE %lu", e);
}

/* ================================================================== #403 InternetAutoProxyOnSendRequestComplete
 * [D @0x165fc0] arg2 NULL, arg2[0] == 0, arg2[1] == 0 or arg3 NULL -> E_INVALIDARG (returned as an HRESULT, not a
 * Win32 code); validation happens before GlobalDataInitialize. */
typedef HRESULT (WINAPI *gs_AutoProxyOnComplete)(DWORD, void **, void *);
TEST(gs_ord403_autoproxy_on_complete_args) {
    REQUIRE_ORD(403);
    gs_AutoProxyOnComplete f = GS_ORD(gs_AutoProxyOnComplete, 403);
    void *pair_zero[2] = { NULL, NULL };
    void *pair_first[2] = { (void *)0x1, NULL };
    void *pair_second[2] = { NULL, (void *)0x1 };
    BYTE info[64]; gs_fill(info, sizeof info);
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(f(0, NULL, info), E_INVALIDARG);
        EXPECT_EQ(f(0, NULL, NULL), E_INVALIDARG);
        EXPECT_EQ(f(1, pair_zero, info), E_INVALIDARG);
        EXPECT_EQ(f(1, pair_first, info), E_INVALIDARG);
        EXPECT_EQ(f(1, pair_second, info), E_INVALIDARG);
        EXPECT_ERR(gs_seeds[s]);
    }
    /* both pair members set but no info -> still E_INVALIDARG */
    BYTE a, b;
    void *pair_ok[2] = { &a, &b };
    EXPECT_EQ(f(0, pair_ok, NULL), E_INVALIDARG);
    CHECK(gs_untouched(info, sizeof info));
}

/* ================================================================== ordinal-only addresses
 * the folded groups in the reference: {104 = HttpCheckDavCompliance}, {112 = IsDuoStream = UrlCacheServer =
 * RegisterUrlCacheNotification}, {120..123}. Everything else is its own body. Recorded as notes (linker detail),
 * with hard checks only on "resolves and lies inside wininet". */
TEST(gs_ordinal_only_addresses) {
    static const unsigned ords[] = { 101, 102, 103, 104, 105, 108, 109, 110, 111, 112, 116, 117, 118, 120, 121, 122, 123,
                                     346, 401, 402, 403, 410, 411, 413, 420, 421, 422, 423 };
    ULONG_PTR lo = 0, hi = 0;
    int have = gs_module_range(t_module("wininet.dll"), &lo, &hi);
    int distinct = 0;
    for (size_t i = 0; i < sizeof ords / sizeof ords[0]; i++) {
        FARPROC p = gs_ord(ords[i]);
        CHECKF(p != NULL, "#%u missing", ords[i]);
        if (have && p) CHECKF((ULONG_PTR)p >= lo && (ULONG_PTR)p < hi, "#%u outside wininet", ords[i]);
        int dup = 0;
        for (size_t j = 0; j < i; j++) if (gs_ord(ords[j]) == p) dup = 1;
        if (!dup) distinct++;
    }
    t_note("ordinal-only exports: %zu entries, %d distinct addresses (reference: 25)", sizeof ords / sizeof ords[0], distinct);
    t_note("#112 == UrlCacheServer: %s; #120 == #123: %s", gs_ord(112) == t_proc_in("wininet.dll", "UrlCacheServer") ? "yes" : "no",
           gs_ord(120) == gs_ord(123) ? "yes" : "no");
}

/* the named exports that share the #112 body behave identically through every name */
TEST(gs_ord112_folded_names_same_result) {
    REQUIRE_ORD(112); REQUIRE(UN(UrlCacheServer)); REQUIRE(UN(RegisterUrlCacheNotification));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        DWORD a = GS_ORD(gs_IsDuoStream, 112)();
        DWORD b = UN(UrlCacheServer)();
        DWORD c = UN(RegisterUrlCacheNotification)(NULL, 0, 0, 0, 0);
        EXPECT_EQ(a, 1); EXPECT_EQ(b, 1); EXPECT_EQ(c, 1);
        EXPECT_ERR(gs_seeds[s]);
    }
}
