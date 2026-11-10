/* The small UrlCache* (WinINet 10 "extensible cache") exports and InternetConvertUrlFromWireToWideChar.
 * These exports had no caller anywhere else in the corpus. Only argument validation and read-only queries are
 * made here: nothing creates a container, changes a limit/age, or writes extra data. The one positive
 * existence probe uses a unique URL from t_uniq_cache_url, which t_net_cleanup deletes.
 *
 * Evidence [D] (Win10 19041 decomp; every Internal function returns WX_WIN32_FROM_HR(hr), 0x80070057 -> 87):
 *  UrlCacheGetGlobalCacheSize@0x1a37e0      NULL size or NULL limit -> 87 (the first DWORD is not read)
 *  UrlCacheGetGlobalLimitInternal@0x19f070  *out = 0 first (when out != NULL); type >= 4 or out NULL -> 87
 *  UrlCacheSetGlobalLimitInternal          type >= 4 -> 87 (only that path is used here: no limit is changed)
 *  UrlCacheFreeEntryInfo@0x1fc10            NULL -> no-op; otherwise frees 4 strings and zeroes 0x68 bytes
 *  UrlCacheCloseEntryHandle@0x1a3550        NULL -> no-op
 *  UrlCacheCheckEntriesExistInternal@0x19ec34  memset(out, 0, 4*count) FIRST; count-1 >= 0x400 -> 87;
 *                                           NULL urls or NULL out -> 87; any NULL/empty URL -> 87
 *  UrlCacheGetContentPathsInternal@0x19ef90 NULL ppaths, *ppaths != NULL, NULL pcount, *pcount != 0 -> 87
 *  UrlCacheContainerSetEntryMaximumAgeInternal  NULL or empty name -> 87
 *  UrlCacheCreateContainerInternal          name NULL/empty/>= 64 chars, prefix or path NULL/empty -> 87
 *  UrlCacheFindFirstEntryInternal           zero info (0x68 bytes), *handle = NULL; flags != 0 or info NULL -> 87
 *  UrlCacheFindNextEntryInternal            NULL handle or NULL info -> 87
 *  UrlCacheGetEntryInfoInternal             NULL or empty URL -> 87
 *  UrlCacheRetrieveEntryFile/StreamInternal zero info, *handle = NULL; URL NULL/empty, info NULL, handle NULL -> 87
 *  UrlCacheReadEntryStreamInternal          *read = 0 first; NULL handle/buffer/pread -> 87
 *  UrlCacheUpdateEntryExtraDataInternal     URL NULL/empty, or cb != 0 with NULL data -> 87
 *  InternetConvertUrlFromWireToWideChar@0x13e80 -> ...Internal@0x13f20: NULL out, NULL url or NULL base -> 87
 *                                           (before *out = NULL); result = InternetCombineUrlW(base, url) */
#include "tm.h"
#include "tnet.h"

UDECL(DWORD, UrlCacheGetGlobalCacheSize, (DWORD, ULONGLONG *, ULONGLONG *));
UDECL(DWORD, UrlCacheGetGlobalLimit, (DWORD, ULONGLONG *));
UDECL(DWORD, UrlCacheSetGlobalLimit, (DWORD, ULONGLONG));
UDECL(void,  UrlCacheFreeEntryInfo, (void *));
UDECL(void,  UrlCacheCloseEntryHandle, (void *));
UDECL(DWORD, UrlCacheCheckEntriesExist, (PCWSTR *, DWORD, BOOL *));
UDECL(DWORD, UrlCacheGetContentPaths, (PWSTR **, DWORD *));
UDECL(DWORD, UrlCacheContainerSetEntryMaximumAge, (PCWSTR, DWORD));
UDECL(DWORD, UrlCacheCreateContainer, (PCWSTR, PCWSTR, PCWSTR, ULONGLONG, DWORD));
UDECL(DWORD, UrlCacheFindFirstEntry, (PCWSTR, DWORD, DWORD, LONGLONG, void *, HANDLE *));
UDECL(DWORD, UrlCacheFindNextEntry, (HANDLE, void *));
UDECL(DWORD, UrlCacheGetEntryInfo, (void *, PCWSTR, void *));
UDECL(DWORD, UrlCacheRetrieveEntryFile, (void *, PCWSTR, void *, void **));
UDECL(DWORD, UrlCacheRetrieveEntryStream, (void *, PCWSTR, BOOL, void *, void **));
UDECL(DWORD, UrlCacheReadEntryStream, (void *, ULONGLONG, void *, DWORD, DWORD *));
UDECL(DWORD, UrlCacheUpdateEntryExtraData, (void *, PCWSTR, const BYTE *, DWORD));
UDECL(DWORD, InternetConvertUrlFromWireToWideChar, (PCSTR, DWORD, PCWSTR, DWORD, DWORD, BOOL, DWORD, PWSTR *));

#define INFO_SIZE 0x68   /* sizeof(URLCACHE_ENTRY_INFO) on x64 [D WxZeroOut<_URLCACHE_ENTRY_INFO>] */
typedef struct { unsigned char b[INFO_SIZE]; unsigned char guard[8]; } info_buf;
static int info_zero(const info_buf *x) { for (int i = 0; i < INFO_SIZE; i++) if (x->b[i]) return 0; return 1; }

/* ------------------------------------------------------------ global size / limits (read-only) */
TEST(tca_global_cache_size_args) {
    REQUIRE(UN(UrlCacheGetGlobalCacheSize));
    ULONGLONG a = 0x1111, b = 0x2222;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(UrlCacheGetGlobalCacheSize)(0, NULL, &b), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheGetGlobalCacheSize)(0, &a, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheGetGlobalCacheSize)(0xFFFFFFFFu, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(a, 0x1111); EXPECT_EQ(b, 0x2222);
    a = b = 0;
    DWORD r = UN(UrlCacheGetGlobalCacheSize)(0, &a, &b);
    t_note("UrlCacheGetGlobalCacheSize -> %lu size=%llu limit=%llu", r, (unsigned long long)a, (unsigned long long)b);
}

TEST(tca_global_limit_get) {
    REQUIRE(UN(UrlCacheGetGlobalLimit));
    static const DWORD bad[] = { 4, 5, 0x100, 0x80000000u, 0xFFFFFFFFu };
    for (int i = 0; i < 5; i++) {
        ULONGLONG v = 0x5555;
        DWORD r = UN(UrlCacheGetGlobalLimit)(bad[i], &v);
        CHECKF(r == ERROR_INVALID_PARAMETER, "type %lu -> %lu", bad[i], r);
        CHECKF(v == 0, "type %lu: out not zeroed (0x%llx)", bad[i], (unsigned long long)v);   /* zeroed first [D] */
    }
    for (DWORD t = 0; t < 4; t++) {
        EXPECT_EQ(UN(UrlCacheGetGlobalLimit)(t, NULL), ERROR_INVALID_PARAMETER);
        ULONGLONG v = 0x5555;
        DWORD r = UN(UrlCacheGetGlobalLimit)(t, &v);
        t_note("UrlCacheGetGlobalLimit(%lu) -> %lu value=%llu", t, r, (unsigned long long)v);
    }
}

TEST(tca_global_limit_set_rejects_type) {
    /* only the rejected path: a successful Set would change the per-user cache quota */
    REQUIRE(UN(UrlCacheSetGlobalLimit));
    static const DWORD bad[] = { 4, 0x10, 0xFFFFFFFFu };
    for (int i = 0; i < 3; i++) {
        SET_ERR(0x4242);
        EXPECT_EQ(UN(UrlCacheSetGlobalLimit)(bad[i], 1), ERROR_INVALID_PARAMETER);
        EXPECT_ERR(0x4242);    /* Win32 code returned, SetLastError not called on this path [D] */
    }
}

/* ------------------------------------------------------------ free / close: NULL no-ops */
TEST(tca_free_and_close_null) {
    REQUIRE(UN(UrlCacheFreeEntryInfo)); REQUIRE(UN(UrlCacheCloseEntryHandle));
    SET_ERR(0x4242);
    UN(UrlCacheFreeEntryInfo)(NULL);
    UN(UrlCacheCloseEntryHandle)(NULL);
    EXPECT_ERR(0x4242);
}

TEST(tca_free_zeroed_info) {
    /* a zeroed info block holds only NULL strings: freeing it is a no-op that leaves it zeroed [D] */
    REQUIRE(UN(UrlCacheFreeEntryInfo));
    info_buf x; memset(&x, 0, sizeof x); memset(x.guard, 0xAB, sizeof x.guard);
    UN(UrlCacheFreeEntryInfo)(x.b);
    CHECK(info_zero(&x));
    CHECK(tm_is_filled(x.guard, sizeof x.guard));     /* only 0x68 bytes are touched */
}

/* ------------------------------------------------------------ UrlCacheCheckEntriesExist */
TEST(tca_check_exist_args) {
    REQUIRE(UN(UrlCacheCheckEntriesExist));
    PCWSTR one[1] = { L"http://example.invalid/x" };
    BOOL out[4];
    EXPECT_EQ(UN(UrlCacheCheckEntriesExist)(one, 0, NULL), ERROR_INVALID_PARAMETER);      /* count 0 */
    out[0] = 7;
    EXPECT_EQ(UN(UrlCacheCheckEntriesExist)(NULL, 1, out), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(out[0], 0);                                                                  /* zeroed first [D] */
    PCWSTR holes[2] = { L"http://example.invalid/y", NULL };
    out[0] = out[1] = 7;
    EXPECT_EQ(UN(UrlCacheCheckEntriesExist)(holes, 2, out), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(out[0], 0); EXPECT_EQ(out[1], 0);
    PCWSTR empty[1] = { L"" };
    out[0] = 7;
    EXPECT_EQ(UN(UrlCacheCheckEntriesExist)(empty, 1, out), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(out[0], 0);
}

TEST(tca_check_exist_count_limit) {
    /* count 1..0x400 accepted, 0x401 rejected after the output array was cleared [D] */
    REQUIRE(UN(UrlCacheCheckEntriesExist));
    static BOOL out[0x402];
    static PCWSTR urls[0x401];
    for (int i = 0; i < 0x401; i++) urls[i] = L"http://example.invalid/z";
    for (int i = 0; i < 0x402; i++) out[i] = 7;
    EXPECT_EQ(UN(UrlCacheCheckEntriesExist)(urls, 0x401, out), ERROR_INVALID_PARAMETER);
    int cleared = 1; for (int i = 0; i < 0x401; i++) if (out[i] != 0) cleared = 0;
    CHECK(cleared); EXPECT_EQ(out[0x401], 7);
}

TEST(tca_check_exist_missing_urls) {
    REQUIRE(UN(UrlCacheCheckEntriesExist));
    WCHAR u1[200], u2[200];
    MultiByteToWideChar(CP_ACP, 0, t_uniq_cache_url("cem1"), -1, u1, 200);
    MultiByteToWideChar(CP_ACP, 0, t_uniq_cache_url("cem2"), -1, u2, 200);
    PCWSTR urls[2] = { u1, u2 };
    BOOL out[2] = { 7, 7 };
    DWORD r = UN(UrlCacheCheckEntriesExist)(urls, 2, out);
    t_note("CheckEntriesExist(2 unique missing) -> %lu [%d %d]", r, out[0], out[1]);
    EXPECT_EQ(out[0], 0); EXPECT_EQ(out[1], 0);    /* cleared before anything else, never set for a missing URL */
    t_net_cleanup();
}

/* Positive probe through the classic API: an entry committed with CommitUrlCacheEntryA. Whether the new
 * API sees classic Content entries is recorded first (note), not asserted. */
TEST(tca_check_exist_committed_entry) {
    REQUIRE(UN(UrlCacheCheckEntriesExist)); REQUIRE(U(CreateUrlCacheEntryA)); REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = t_uniq_cache_url("cee");
    char path[MAX_PATH] = "";
    if (!U(CreateUrlCacheEntryA)(url, 5, "txt", path, 0)) { t_skip("CreateUrlCacheEntryA failed %lu", GetLastError()); return; }
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, "hello", 5, &w, NULL); CloseHandle(f); }
    FILETIME z = { 0, 0 };
    BOOL c = U(CommitUrlCacheEntryA)(url, path, z, z, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    CHECKF(c, "commit %lu", GetLastError());
    if (c) {
        WCHAR wu[200]; MultiByteToWideChar(CP_ACP, 0, url, -1, wu, 200);
        WCHAR wm[200]; MultiByteToWideChar(CP_ACP, 0, t_uniq_cache_url("ceemiss"), -1, wm, 200);
        PCWSTR urls[2] = { wu, wm };
        BOOL out[2] = { 7, 7 };
        DWORD r = UN(UrlCacheCheckEntriesExist)(urls, 2, out);
        t_note("CheckEntriesExist(committed, missing) -> %lu [%d %d]", r, out[0], out[1]);
        EXPECT_EQ(out[1], 0);
        if (UN(UrlCacheGetEntryInfo)) {
            info_buf x; memset(&x, 0xAB, sizeof x);
            r = UN(UrlCacheGetEntryInfo)(NULL, wu, x.b);
            t_note("UrlCacheGetEntryInfo(committed) -> %lu (info zero=%d)", r, info_zero(&x));
            if (r == 0 && UN(UrlCacheFreeEntryInfo)) { UN(UrlCacheFreeEntryInfo)(x.b); CHECK(info_zero(&x)); }
        }
    }
    t_net_cleanup();
}

/* ------------------------------------------------------------ UrlCacheGetContentPaths */
TEST(tca_content_paths_args) {
    REQUIRE(UN(UrlCacheGetContentPaths));
    PWSTR *paths = NULL; DWORD n = 0;
    EXPECT_EQ(UN(UrlCacheGetContentPaths)(NULL, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheGetContentPaths)(&paths, NULL), ERROR_INVALID_PARAMETER);
    PWSTR fake = NULL;
    paths = &fake;   /* *ppaths must be NULL on entry */
    EXPECT_EQ(UN(UrlCacheGetContentPaths)(&paths, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(paths, &fake);
    paths = NULL; n = 3;   /* *pcount must be 0 on entry */
    EXPECT_EQ(UN(UrlCacheGetContentPaths)(&paths, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(paths, NULL); EXPECT_EQ(n, 3);
}

TEST(tca_content_paths_query) {
    /* read-only; the returned array is left allocated (owner/allocator not documented) */
    REQUIRE(UN(UrlCacheGetContentPaths));
    PWSTR *paths = NULL; DWORD n = 0;
    DWORD r = UN(UrlCacheGetContentPaths)(&paths, &n);
    t_note("UrlCacheGetContentPaths -> %lu count=%lu", r, n);
    if (r == 0 && paths) for (DWORD i = 0; i < n && i < 8; i++) t_note("  path[%lu] = %ls", i, paths[i] ? paths[i] : L"(null)");
    if (r == 0) CHECK(n == 0 || paths != NULL);
}

/* ------------------------------------------------------------ container management: rejected arguments only */
TEST(tca_container_age_args) {
    REQUIRE(UN(UrlCacheContainerSetEntryMaximumAge));
    EXPECT_EQ(UN(UrlCacheContainerSetEntryMaximumAge)(NULL, 60), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheContainerSetEntryMaximumAge)(L"", 60), ERROR_INVALID_PARAMETER);
}

TEST(tca_create_container_args) {
    REQUIRE(UN(UrlCacheCreateContainer));
    WCHAR tmp[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, t_tmpdir(), -1, tmp, MAX_PATH);
    WCHAR n64[70]; for (int i = 0; i < 64; i++) n64[i] = L'a'; n64[64] = 0;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(UrlCacheCreateContainer)(NULL, L"i7p:", tmp, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheCreateContainer)(L"", L"i7p:", tmp, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheCreateContainer)(n64, L"i7p:", tmp, 0, 0), ERROR_INVALID_PARAMETER);   /* >= 64 chars */
    EXPECT_EQ(UN(UrlCacheCreateContainer)(L"i7c", NULL, tmp, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheCreateContainer)(L"i7c", L"", tmp, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheCreateContainer)(L"i7c", L"i7p:", NULL, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheCreateContainer)(L"i7c", L"i7p:", L"", 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------ find / info / retrieve / read: argument checks */
TEST(tca_find_first_args) {
    REQUIRE(UN(UrlCacheFindFirstEntry));
    info_buf x; memset(&x, 0xAB, sizeof x);
    HANDLE h = (HANDLE)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheFindFirstEntry)(NULL, 1, 0, 0, x.b, &h), ERROR_INVALID_PARAMETER);   /* flags != 0 */
    CHECK(info_zero(&x)); EXPECT_EQ(h, NULL);                                                /* outputs cleared first */
    CHECK(tm_is_filled(x.guard, sizeof x.guard));
    h = (HANDLE)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheFindFirstEntry)(NULL, 0, 0, 0, NULL, &h), ERROR_INVALID_PARAMETER);  /* info NULL */
    EXPECT_EQ(h, NULL);
    EXPECT_EQ(UN(UrlCacheFindFirstEntry)(NULL, 0xFFFFFFFFu, 0, 0, NULL, NULL), ERROR_INVALID_PARAMETER);
}

TEST(tca_find_next_args) {
    REQUIRE(UN(UrlCacheFindNextEntry));
    info_buf x; memset(&x, 0, sizeof x);
    EXPECT_EQ(UN(UrlCacheFindNextEntry)(NULL, x.b), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheFindNextEntry)(NULL, NULL), ERROR_INVALID_PARAMETER);
}

TEST(tca_get_entry_info_args) {
    REQUIRE(UN(UrlCacheGetEntryInfo));
    info_buf x; memset(&x, 0xAB, sizeof x);
    EXPECT_EQ(UN(UrlCacheGetEntryInfo)(NULL, NULL, x.b), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheGetEntryInfo)(NULL, L"", x.b), ERROR_INVALID_PARAMETER);
    CHECK(tm_is_filled(&x, sizeof x));           /* info is not cleared on the argument path [D] */
    WCHAR wu[200]; MultiByteToWideChar(CP_ACP, 0, t_uniq_cache_url("gei"), -1, wu, 200);
    DWORD r = UN(UrlCacheGetEntryInfo)(NULL, wu, x.b);
    t_note("UrlCacheGetEntryInfo(missing) -> %lu", r);
    CHECK(r != 0);
    r = UN(UrlCacheGetEntryInfo)(NULL, wu, NULL);
    t_note("UrlCacheGetEntryInfo(missing, NULL info) -> %lu", r);
    CHECK(r != 0);
    t_net_cleanup();
}

TEST(tca_retrieve_file_args) {
    REQUIRE(UN(UrlCacheRetrieveEntryFile));
    info_buf x; void *h;
    memset(&x, 0xAB, sizeof x); h = (void *)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheRetrieveEntryFile)(NULL, NULL, x.b, &h), ERROR_INVALID_PARAMETER);
    CHECK(info_zero(&x)); EXPECT_EQ(h, NULL);
    memset(&x, 0xAB, sizeof x); h = (void *)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheRetrieveEntryFile)(NULL, L"", x.b, &h), ERROR_INVALID_PARAMETER);
    CHECK(info_zero(&x)); EXPECT_EQ(h, NULL);
    h = (void *)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheRetrieveEntryFile)(NULL, L"http://example.invalid/r", NULL, &h), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(h, NULL);
    memset(&x, 0xAB, sizeof x);
    EXPECT_EQ(UN(UrlCacheRetrieveEntryFile)(NULL, L"http://example.invalid/r", x.b, NULL), ERROR_INVALID_PARAMETER);
    CHECK(info_zero(&x));
}

TEST(tca_retrieve_stream_args) {
    REQUIRE(UN(UrlCacheRetrieveEntryStream));
    info_buf x; void *h;
    memset(&x, 0xAB, sizeof x); h = (void *)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheRetrieveEntryStream)(NULL, NULL, FALSE, x.b, &h), ERROR_INVALID_PARAMETER);
    CHECK(info_zero(&x)); EXPECT_EQ(h, NULL);
    h = (void *)(ULONG_PTR)0x1234;
    EXPECT_EQ(UN(UrlCacheRetrieveEntryStream)(NULL, L"http://example.invalid/s", TRUE, NULL, &h), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(h, NULL);
    memset(&x, 0xAB, sizeof x);
    EXPECT_EQ(UN(UrlCacheRetrieveEntryStream)(NULL, L"http://example.invalid/s", FALSE, x.b, NULL), ERROR_INVALID_PARAMETER);
    CHECK(info_zero(&x));
}

TEST(tca_retrieve_missing_entry) {
    REQUIRE(UN(UrlCacheRetrieveEntryFile)); REQUIRE(UN(UrlCacheRetrieveEntryStream));
    WCHAR wu[200]; MultiByteToWideChar(CP_ACP, 0, t_uniq_cache_url("rme"), -1, wu, 200);
    info_buf x; void *h = (void *)(ULONG_PTR)0x1234;
    DWORD r = UN(UrlCacheRetrieveEntryFile)(NULL, wu, x.b, &h);
    t_note("RetrieveEntryFile(missing) -> %lu", r);
    CHECK(r != 0); EXPECT_EQ(h, NULL);
    if (r == 0 && h) UN(UrlCacheCloseEntryHandle)(h);
    h = (void *)(ULONG_PTR)0x1234;
    r = UN(UrlCacheRetrieveEntryStream)(NULL, wu, FALSE, x.b, &h);
    t_note("RetrieveEntryStream(missing) -> %lu", r);
    CHECK(r != 0); EXPECT_EQ(h, NULL);
    if (r == 0 && h) UN(UrlCacheCloseEntryHandle)(h);
    t_net_cleanup();
}

TEST(tca_read_stream_args) {
    REQUIRE(UN(UrlCacheReadEntryStream));
    char buf[16]; DWORD n = 0x77;
    EXPECT_EQ(UN(UrlCacheReadEntryStream)(NULL, 0, buf, sizeof buf, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(n, 0);                       /* *pcbRead = 0 before the handle check [D] */
    EXPECT_EQ(UN(UrlCacheReadEntryStream)(NULL, 0, buf, sizeof buf, NULL), ERROR_INVALID_PARAMETER);
}

TEST(tca_update_extra_data_args) {
    REQUIRE(UN(UrlCacheUpdateEntryExtraData));
    static const BYTE d[4] = { 1, 2, 3, 4 };
    EXPECT_EQ(UN(UrlCacheUpdateEntryExtraData)(NULL, NULL, d, 4), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheUpdateEntryExtraData)(NULL, L"", d, 4), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(UrlCacheUpdateEntryExtraData)(NULL, L"http://example.invalid/u", NULL, 4), ERROR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------ InternetConvertUrlFromWireToWideChar */
TEST(tcw_wire_url_args) {
    REQUIRE(UN(InternetConvertUrlFromWireToWideChar));
    PWSTR out = (PWSTR)(ULONG_PTR)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(InternetConvertUrlFromWireToWideChar)(NULL, 4, L"http://h/", CP_UTF8, CP_UTF8, FALSE, CP_UTF8, &out), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(out, (PWSTR)(ULONG_PTR)0x1234);                                                    /* untouched */
    EXPECT_EQ(UN(InternetConvertUrlFromWireToWideChar)("/a", 2, NULL, CP_UTF8, CP_UTF8, FALSE, CP_UTF8, &out), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(InternetConvertUrlFromWireToWideChar)("/a", 2, L"http://h/", CP_UTF8, CP_UTF8, FALSE, CP_UTF8, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(out, (PWSTR)(ULONG_PTR)0x1234);
    EXPECT_ERR(0x4242);
}

/* The converted URL is allocated from wininet's heap; it is deliberately not freed here (a few bytes). */
static void wire(const char *url, const WCHAR *base, const WCHAR *want, int hard) {
    PWSTR out = NULL;
    DWORD r = UN(InternetConvertUrlFromWireToWideChar)(url, (DWORD)strlen(url), base, CP_UTF8, CP_UTF8, FALSE, CP_UTF8, &out);
    t_note("wire [%s] base [%ls] -> %lu [%ls]", url, base, r, out ? out : L"(null)");
    if (!hard) return;
    CHECKF(r == 0 && out && !lstrcmpW(out, want), "[%s] -> %lu [%ls] want [%ls]", url, r, out ? out : L"(null)", want);
}
TEST(tcw_wire_url_combine) {
    REQUIRE(UN(InternetConvertUrlFromWireToWideChar));
    wire("http://h.example/a/b", L"http://other.example/", L"http://h.example/a/b", 1);
    wire("/x/y", L"http://h.example/a/b", L"http://h.example/x/y", 1);
    wire("c", L"http://h.example/a/b", L"http://h.example/a/c", 1);
    wire("../c", L"http://h.example/a/b/d", L"http://h.example/a/c", 1);
    wire("https://s.example:8443/p?q=1#f", L"http://h.example/", L"https://s.example:8443/p?q=1#f", 1);
    /* encodings and host forms: recorded */
    wire("/%E4%B8%AD", L"http://h.example/", NULL, 0);
    wire("/\xE4\xB8\xAD", L"http://h.example/", NULL, 0);
    wire("/a b", L"http://h.example/", NULL, 0);
    wire("http://[::1]/v6", L"http://h.example/", NULL, 0);
    wire("http://xn--fsq.example/", L"http://h.example/", NULL, 0);
}

TEST(tcw_wire_url_cch_limits_input) {
    /* cchUrl bounds the input: the copy is NUL-terminated at cchUrl [D memcpy + NUL] */
    REQUIRE(UN(InternetConvertUrlFromWireToWideChar));
    PWSTR out = NULL;
    DWORD r = UN(InternetConvertUrlFromWireToWideChar)("/abcdef", 4, L"http://h.example/", CP_UTF8, CP_UTF8, FALSE, CP_UTF8, &out);
    t_note("cch 4 of /abcdef -> %lu [%ls]", r, out ? out : L"(null)");
    CHECKF(r == 0 && out && !lstrcmpW(out, L"http://h.example/abc"), "r=%lu", r);
}
