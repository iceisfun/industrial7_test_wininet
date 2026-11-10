/* HTML5 AppCache exports (IE10/11 plumbing, still exported and still implemented on Win10) and a few other
 * undocumented helpers that validate their arguments before touching any state: only the validation paths and
 * read-only queries are exercised here, never a path that creates or deletes an AppCache group, frees cache
 * space or changes the content path.
 *
 * [D AppCache*Internal] every entry point calls GlobalDataInitialize() first, then checks its pointer arguments
 * in order, each NULL giving E_INVALIDARG; the exported wrapper returns WX_WIN32_FROM_HR(hr) as a DWORD, so the
 * caller sees 87. GetLastError is never set on these paths.
 * VM_TIMEOUT: 120 */
#include "gs.h"

/* ---- prototypes (not in the mingw headers) ------------------------------------------------------------- */
typedef struct { PWSTR pwszManifestUrl; FILETIME ftLastAccessTime; ULONGLONG ullSize; } gs_ac_group_info;   /* 24 bytes */
typedef struct { DWORD dwAppCacheGroupCount; gs_ac_group_info *pAppCacheGroups; } gs_ac_group_list;
typedef struct { PWSTR pwszUrl; DWORD dwEntryType; } gs_ac_dl_entry;                                       /* 16 bytes */
typedef struct { DWORD dwEntryCount; gs_ac_dl_entry *pEntries; } gs_ac_dl_list;
UDECL(DWORD, AppCacheLookup, (PCWSTR, DWORD, void **));
UDECL(DWORD, AppCacheCheckManifest, (PCWSTR, PCWSTR, const BYTE *, DWORD, const BYTE *, DWORD, DWORD *, void **));
UDECL(DWORD, AppCacheGetInfo, (void *, gs_ac_group_info *));
UDECL(DWORD, AppCacheGetGroupList, (gs_ac_group_list *));
UDECL(DWORD, AppCacheGetIEGroupList, (gs_ac_group_list *));
UDECL(void,  AppCacheFreeGroupList, (gs_ac_group_list *));
UDECL(DWORD, AppCacheGetManifestUrl, (void *, PWSTR *));
UDECL(DWORD, AppCacheGetFallbackUrl, (void *, PCWSTR, PWSTR *));
UDECL(DWORD, AppCacheDeleteGroup, (PCWSTR));
UDECL(DWORD, AppCacheDeleteIEGroup, (PCWSTR));
UDECL(DWORD, AppCacheGetDownloadList, (void *, gs_ac_dl_list *));
UDECL(void,  AppCacheFreeDownloadList, (gs_ac_dl_list *));
UDECL(DWORD, AppCacheFinalize, (void *, const BYTE *, DWORD, DWORD *));
UDECL(DWORD, AppCacheCreateAndCommitFile, (void *, PCWSTR, PCWSTR, const BYTE *, DWORD));
UDECL(void,  AppCacheCloseHandle, (void *));
UDECL(DWORD, AppCacheDuplicateHandle, (void *, void **));
UDECL(DWORD, HttpGetServerCredentials, (PCWSTR, PWSTR *, PWSTR *));
UDECL(DWORD, HttpGetTunnelSocket, (HINTERNET, ULONGLONG *, BYTE **, DWORD *));
UDECL(BOOL,  UpdateUrlCacheContentPath, (LPCSTR));
UDECL(void,  UrlZonesDetach, (void));

static const WCHAR gs_ac_url[] = L"http://127.0.0.1:1/gs_appcache/page.html";
static const WCHAR gs_ac_manifest[] = L"http://127.0.0.1:1/gs_appcache/app.manifest";

/* ================================================================== presence */
TEST(gs_appcache_exports_resolve) {
    static const char *names[] = {
        "AppCacheCheckManifest", "AppCacheCloseHandle", "AppCacheCreateAndCommitFile", "AppCacheDeleteGroup",
        "AppCacheDeleteIEGroup", "AppCacheDuplicateHandle", "AppCacheFinalize", "AppCacheFreeDownloadList",
        "AppCacheFreeGroupList", "AppCacheFreeIESpace", "AppCacheFreeSpace", "AppCacheGetDownloadList",
        "AppCacheGetFallbackUrl", "AppCacheGetGroupList", "AppCacheGetIEGroupList", "AppCacheGetInfo",
        "AppCacheGetManifestUrl", "AppCacheLookup",
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        CHECKF(t_proc_in("wininet.dll", names[i]) != NULL, "%s missing", names[i]);
    /* there are no A/W suffixed variants */
    static const char *absent[] = { "AppCacheLookupW", "AppCacheLookupA", "AppCacheCheckManifestW", "AppCacheGetInfoW" };
    for (size_t i = 0; i < sizeof absent / sizeof absent[0]; i++)
        CHECKF(GetProcAddress(t_module("wininet.dll"), absent[i]) == NULL, "%s exported", absent[i]);
}

/* ================================================================== AppCacheLookup
 * [D AppCacheLookupInternal@0x3650c] url NULL -> 87; out NULL -> 87; flags & ~1 -> 87 (out untouched on all three);
 * InPrivate -> 0x80072f9d; else *out = NULL, CAppCacheServer::Lookup. */
TEST(gs_appcache_lookup_null_args) {
    REQUIRE(UN(AppCacheLookup));
    void *h = (void *)0x1234;
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        h = (void *)0x1234;
        EXPECT_EQ(UN(AppCacheLookup)(NULL, 0, &h), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(h, (void *)0x1234);
        EXPECT_EQ(UN(AppCacheLookup)(gs_ac_url, 0, NULL), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(UN(AppCacheLookup)(NULL, 0, NULL), ERROR_INVALID_PARAMETER);
        EXPECT_ERR(gs_seeds[s]);
    }
}

TEST(gs_appcache_lookup_bad_flags) {
    REQUIRE(UN(AppCacheLookup));
    for (int b = 1; b < 32; b++) {
        void *h = (void *)0x1234;
        SET_ERR(0x4242);
        DWORD r = UN(AppCacheLookup)(gs_ac_url, 1u << b, &h);
        CHECKF(r == ERROR_INVALID_PARAMETER, "flag bit %d: r=%lu", b, r);
        CHECKF(h == (void *)0x1234, "flag bit %d: out written", b);
        EXPECT_ERR(0x4242);
    }
    void *h = (void *)0x1234;
    EXPECT_EQ(UN(AppCacheLookup)(gs_ac_url, 0xFFFFFFFFu, &h), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheLookup)(gs_ac_url, 3, &h), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(h, (void *)0x1234);
}

TEST(gs_appcache_lookup_unknown_url) {
    REQUIRE(UN(AppCacheLookup)); REQUIRE(UN(AppCacheCloseHandle));
    WCHAR url[160];
    _snwprintf(url, 160, L"http://127.0.0.1:1/gs_appcache_%lu/never.html", GetCurrentProcessId());
    for (DWORD fl = 0; fl < 2; fl++) {
        void *h = (void *)0x1234;
        SET_ERR(0x4242);
        DWORD r = UN(AppCacheLookup)(url, fl, &h);
        t_note("AppCacheLookup(unknown url, flags %lu) = %lu, handle %p, GLE %lu", fl, r, h, GetLastError());
        CHECKF(r != 0, "flags %lu: unknown url found", fl);
        /* [D] the out pointer is cleared before the server lookup once validation passed */
        CHECKF(h == NULL || h == (void *)0x1234, "flags %lu: handle %p", fl, h);
        if (!r && h) UN(AppCacheCloseHandle)(h);
    }
}

/* ================================================================== AppCacheCheckManifest
 * [D AppCacheCheckManifestInternal] the master URL (arg 1) is NOT validated; manifest URL, manifest data, data size,
 * headers, header size, state out and handle out are checked in that order (87 each), outs untouched. */
TEST(gs_appcache_check_manifest_arg_order) {
    REQUIRE(UN(AppCacheCheckManifest));
    static const BYTE data[] = "CACHE MANIFEST\n";
    static const BYTE hdr[] = "HTTP/1.1 200 OK\r\nContent-Type: text/cache-manifest\r\n\r\n";
    for (int miss = 0; miss < 7; miss++) {
        DWORD state = 0xA5A5A5A5u; void *h = (void *)0x1234;
        SET_ERR(0x4242);
        DWORD r = UN(AppCacheCheckManifest)(gs_ac_url,
                                            miss == 0 ? NULL : gs_ac_manifest,
                                            miss == 1 ? NULL : data, miss == 2 ? 0 : (DWORD)sizeof data - 1,
                                            miss == 3 ? NULL : hdr,  miss == 4 ? 0 : (DWORD)sizeof hdr - 1,
                                            miss == 5 ? NULL : &state, miss == 6 ? NULL : &h);
        CHECKF(r == ERROR_INVALID_PARAMETER, "missing arg %d: r=%lu", miss, r);
        CHECKF(state == 0xA5A5A5A5u, "missing arg %d: state written", miss);
        CHECKF(h == (void *)0x1234, "missing arg %d: handle written", miss);
        EXPECT_ERR(0x4242);
    }
    /* everything NULL */
    EXPECT_EQ(UN(AppCacheCheckManifest)(NULL, NULL, NULL, 0, NULL, 0, NULL, NULL), ERROR_INVALID_PARAMETER);
    /* two missing: still 87 */
    DWORD st = 7; void *h = (void *)0x1234;
    EXPECT_EQ(UN(AppCacheCheckManifest)(NULL, gs_ac_manifest, data, 0, NULL, 0, &st, &h), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(st, 7);
    EXPECT_EQ(h, (void *)0x1234);
}

/* ================================================================== handle-taking functions with a NULL handle */
TEST(gs_appcache_get_info_null) {
    REQUIRE(UN(AppCacheGetInfo));
    gs_ac_group_info gi; gs_fill(&gi, sizeof gi);
    EXPECT_EQ(sizeof gi, 24);
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheGetInfo)(NULL, &gi), ERROR_INVALID_PARAMETER);
    CHECK(gs_untouched(&gi, sizeof gi));
    EXPECT_EQ(UN(AppCacheGetInfo)(NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

TEST(gs_appcache_get_manifest_url_null) {
    REQUIRE(UN(AppCacheGetManifestUrl));
    PWSTR p = (PWSTR)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheGetManifestUrl)(NULL, &p), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(p, (PWSTR)0x1234);
    EXPECT_EQ(UN(AppCacheGetManifestUrl)(NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

TEST(gs_appcache_get_fallback_url_null) {
    REQUIRE(UN(AppCacheGetFallbackUrl));
    PWSTR p = (PWSTR)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheGetFallbackUrl)(NULL, gs_ac_url, &p), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheGetFallbackUrl)(NULL, NULL, &p), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheGetFallbackUrl)(NULL, gs_ac_url, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheGetFallbackUrl)(NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(p, (PWSTR)0x1234);
    EXPECT_ERR(0x4242);
}

TEST(gs_appcache_get_download_list_null) {
    REQUIRE(UN(AppCacheGetDownloadList));
    gs_ac_dl_list dl; gs_fill(&dl, sizeof dl);
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheGetDownloadList)(NULL, &dl), ERROR_INVALID_PARAMETER);
    CHECK(gs_untouched(&dl, sizeof dl));
    EXPECT_EQ(UN(AppCacheGetDownloadList)(NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

/* [D AppCacheFinalizeInternal] handle, data, size, state out: 87 each, state untouched */
TEST(gs_appcache_finalize_null) {
    REQUIRE(UN(AppCacheFinalize));
    static const BYTE data[] = "CACHE MANIFEST\n";
    DWORD st = 0xA5A5A5A5u;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheFinalize)(NULL, data, sizeof data - 1, &st), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheFinalize)(NULL, NULL, 0, &st), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheFinalize)(NULL, data, 0, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheFinalize)(NULL, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(st, 0xA5A5A5A5u);
    EXPECT_ERR(0x4242);
}

TEST(gs_appcache_create_commit_file_null) {
    REQUIRE(UN(AppCacheCreateAndCommitFile));
    static const BYTE hdr[] = "HTTP/1.1 200 OK\r\n\r\n";
    char src[MAX_PATH]; t_tmpfile(src, sizeof src, "gs_ac_src.txt");
    WCHAR srcw[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, src, -1, srcw, MAX_PATH);
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheCreateAndCommitFile)(NULL, srcw, gs_ac_url, hdr, sizeof hdr - 1), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheCreateAndCommitFile)(NULL, NULL, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
    /* nothing was created next to the (non-existent) source */
    CHECK(GetFileAttributesA(src) == INVALID_FILE_ATTRIBUTES);
}

/* [D AppCacheDuplicateHandle@0x6fc20] NULL source or NULL out -> 87 before *out is cleared */
TEST(gs_appcache_duplicate_null) {
    REQUIRE(UN(AppCacheDuplicateHandle));
    void *o = (void *)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheDuplicateHandle)(NULL, &o), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(o, (void *)0x1234);
    EXPECT_EQ(UN(AppCacheDuplicateHandle)(NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

/* [D AppCacheCloseHandleInternal] NULL is an early return */
TEST(gs_appcache_close_null) {
    REQUIRE(UN(AppCacheCloseHandle));
    SET_ERR(0x4242);
    UN(AppCacheCloseHandle)(NULL);
    UN(AppCacheCloseHandle)(NULL);
    EXPECT_ERR(0x4242);
}

/* ================================================================== delete group: NULL only (a real URL would delete) */
TEST(gs_appcache_delete_group_null) {
    REQUIRE(UN(AppCacheDeleteGroup)); REQUIRE(UN(AppCacheDeleteIEGroup));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(UN(AppCacheDeleteGroup)(NULL), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(UN(AppCacheDeleteIEGroup)(NULL), ERROR_INVALID_PARAMETER);
        EXPECT_ERR(gs_seeds[s]);
    }
}

/* a manifest URL that cannot exist: whatever the code, it is not success and not 87 (the URL is valid) */
TEST(gs_appcache_delete_group_unknown) {
    REQUIRE(UN(AppCacheDeleteGroup));
    WCHAR url[160];
    _snwprintf(url, 160, L"http://127.0.0.1:1/gs_appcache_%lu/none.manifest", GetCurrentProcessId());
    DWORD r = UN(AppCacheDeleteGroup)(url);
    t_note("AppCacheDeleteGroup(unknown manifest) = %lu", r);
    CHECK(r != ERROR_INVALID_PARAMETER);
}

/* ================================================================== group lists
 * [D AppCacheGetGroupListInternal] NULL -> 87; else the list is zeroed and filled from the server. */
TEST(gs_appcache_group_list_null) {
    REQUIRE(UN(AppCacheGetGroupList)); REQUIRE(UN(AppCacheGetIEGroupList));
    SET_ERR(0x4242);
    EXPECT_EQ(UN(AppCacheGetGroupList)(NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(AppCacheGetIEGroupList)(NULL), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

static void gs_ac_list_check(DWORD (WINAPI *get)(gs_ac_group_list *), const char *label) {
    gs_ac_group_list l; gs_fill(&l, sizeof l);
    DWORD r = get(&l);
    t_note("%s = %lu: %lu groups", label, r, r ? 0 : l.dwAppCacheGroupCount);
    if (r) return;
    CHECK(l.dwAppCacheGroupCount == 0 || l.pAppCacheGroups != NULL);
    /* [VM boot 3] an empty list still carries an (allocated) array pointer: freed by AppCacheFreeGroupList */
    for (DWORD i = 0; i < l.dwAppCacheGroupCount && i < 64; i++)
        CHECKF(l.pAppCacheGroups[i].pwszManifestUrl != NULL, "%s: group %lu without url", label, i);
    UN(AppCacheFreeGroupList)(&l);
    EXPECT_EQ(l.dwAppCacheGroupCount, 0);
    EXPECT_EQ(l.pAppCacheGroups, NULL);
}
TEST(gs_appcache_group_list_read) {
    REQUIRE(UN(AppCacheGetGroupList)); REQUIRE(UN(AppCacheFreeGroupList));
    gs_ac_list_check(UN(AppCacheGetGroupList), "AppCacheGetGroupList");
}
TEST(gs_appcache_ie_group_list_read) {
    REQUIRE(UN(AppCacheGetIEGroupList)); REQUIRE(UN(AppCacheFreeGroupList));
    gs_ac_list_check(UN(AppCacheGetIEGroupList), "AppCacheGetIEGroupList");
}

/* [D FreeAppCacheGroupList] NULL ok; otherwise both fields are zeroed even when the array pointer is NULL */
TEST(gs_appcache_free_group_list_edges) {
    REQUIRE(UN(AppCacheFreeGroupList));
    SET_ERR(0x4242);
    UN(AppCacheFreeGroupList)(NULL);
    gs_ac_group_list l = { 5, NULL };
    UN(AppCacheFreeGroupList)(&l);
    EXPECT_EQ(l.dwAppCacheGroupCount, 0);
    EXPECT_EQ(l.pAppCacheGroups, NULL);
    gs_ac_group_list z = { 0, NULL };
    UN(AppCacheFreeGroupList)(&z);
    EXPECT_EQ(z.dwAppCacheGroupCount, 0);
    EXPECT_ERR(0x4242);
}

/* [D AppCacheFreeDownloadList@0x28330] NULL ok; a list whose entry pointer is NULL is left alone (count kept) */
TEST(gs_appcache_free_download_list_edges) {
    REQUIRE(UN(AppCacheFreeDownloadList));
    SET_ERR(0x4242);
    UN(AppCacheFreeDownloadList)(NULL);
    gs_ac_dl_list l = { 5, NULL };
    UN(AppCacheFreeDownloadList)(&l);
    EXPECT_EQ(l.dwEntryCount, 5);
    EXPECT_EQ(l.pEntries, NULL);
    EXPECT_ERR(0x4242);
}

/* ================================================================== HttpGetServerCredentials
 * [D HttpGetServerCredentialsInternal@0x21d30] url, user out, password out: NULL -> 87 (outs untouched);
 * then both outs = NULL; URL converted; realm/other password caches searched; nothing found -> ERROR_NOT_FOUND (1168).
 * Returns a Win32 code; GetLastError is not set. */
TEST(gs_server_credentials_null_args) {
    REQUIRE(UN(HttpGetServerCredentials));
    PWSTR u = (PWSTR)0x1234, p = (PWSTR)0x5678;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(HttpGetServerCredentials)(NULL, &u, &p), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(HttpGetServerCredentials)(L"http://127.0.0.1:1/", NULL, &p), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(HttpGetServerCredentials)(L"http://127.0.0.1:1/", &u, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(HttpGetServerCredentials)(NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(u, (PWSTR)0x1234);
    EXPECT_EQ(p, (PWSTR)0x5678);
    EXPECT_ERR(0x4242);
}

TEST(gs_server_credentials_unknown_host) {
    REQUIRE(UN(HttpGetServerCredentials));
    WCHAR url[128];
    _snwprintf(url, 128, L"http://gs-creds-%lu.invalid:8080/x", GetCurrentProcessId());
    PWSTR u = (PWSTR)0x1234, p = (PWSTR)0x5678;
    SET_ERR(0x4242);
    DWORD r = UN(HttpGetServerCredentials)(url, &u, &p);
    EXPECT_EQ(r, ERROR_NOT_FOUND);
    EXPECT_EQ(u, NULL);
    EXPECT_EQ(p, NULL);
    t_note("HttpGetServerCredentials miss: GLE %lu (seeded 0x4242)", GetLastError());   /* [VM] 0: an internal call resets it */
    /* loopback with nothing cached either */
    u = (PWSTR)0x1234; p = (PWSTR)0x5678;
    EXPECT_EQ(UN(HttpGetServerCredentials)(L"http://127.0.0.1:1/gs_nocreds", &u, &p), ERROR_NOT_FOUND);
    EXPECT_EQ(u, NULL);
    EXPECT_EQ(p, NULL);
}

TEST(gs_server_credentials_odd_urls) {
    REQUIRE(UN(HttpGetServerCredentials));
    static const WCHAR *urls[] = { L"", L"not a url", L"ftp://127.0.0.1/", L"https://127.0.0.1:1/", L"http://" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        PWSTR u = (PWSTR)0x1234, p = (PWSTR)0x5678;
        DWORD r = UN(HttpGetServerCredentials)(urls[i], &u, &p);
        t_note("HttpGetServerCredentials('%ls') = %lu", urls[i], r);
        CHECKF(r != 0, "'%ls' found credentials", urls[i]);
        /* [D] both outs are cleared before the URL is parsed */
        CHECKF(u == NULL && p == NULL, "'%ls': outs %p %p", urls[i], u, p);
    }
}

/* ================================================================== HttpGetTunnelSocket
 * [D InternalHttpGetTunnelSocket@0x148f0c] outs are initialised first (*sock = ~0, *buf = NULL, *len = 0; no NULL
 * checks, so this test never passes NULL outs), then the handle is mapped (unknown -> ERROR_INVALID_HANDLE) and must
 * be a local HTTP request handle. */
TEST(gs_tunnel_socket_null_handle) {
    REQUIRE(UN(HttpGetTunnelSocket));
    ULONGLONG sock = 0x1111; BYTE *buf = (BYTE *)0x2222; DWORD len = 0x3333;
    SET_ERR(0x4242);
    DWORD r = UN(HttpGetTunnelSocket)(NULL, &sock, &buf, &len);
    EXPECT_EQ(r, ERROR_INVALID_HANDLE);
    EXPECT_EQ(sock, (ULONGLONG)-1);
    EXPECT_EQ(buf, NULL);
    EXPECT_EQ(len, 0);
    t_note("HttpGetTunnelSocket(NULL) GLE after: %lu", GetLastError());
}

TEST(gs_tunnel_socket_wrong_handles) {
    REQUIRE(UN(HttpGetTunnelSocket));
    HINTERNET s = gs_session();
    HINTERNET c = gs_connect_http(s);
    HINTERNET rq = gs_request(c, "/gs_tunnel");
    HINTERNET hs[3] = { s, c, rq };
    static const char *lbl[3] = { "session", "connect", "unsent request" };
    for (int i = 0; i < 3; i++) {
        if (!hs[i]) continue;
        ULONGLONG sock = 0x1111; BYTE *buf = (BYTE *)0x2222; DWORD len = 0x3333;
        DWORD r = UN(HttpGetTunnelSocket)(hs[i], &sock, &buf, &len);
        t_note("HttpGetTunnelSocket(%s) = %lu", lbl[i], r);
        CHECKF(r != 0, "%s: succeeded", lbl[i]);
        CHECK(sock == (ULONGLONG)-1);
        CHECK(buf == NULL);
        CHECK(len == 0);
        if (i < 2) CHECKF(r == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "%s: r=%lu", lbl[i], r);
    }
    if (rq) {
        U(InternetCloseHandle)(rq);
        ULONGLONG sock = 0; BYTE *buf = NULL; DWORD len = 0;
        EXPECT_EQ(UN(HttpGetTunnelSocket)(rq, &sock, &buf, &len), ERROR_INVALID_HANDLE);
    }
    if (c) U(InternetCloseHandle)(c);
}

/* ================================================================== UpdateUrlCacheContentPath
 * [D UpdateUrlCacheContentPath@0x1a3360] NULL -> FALSE, SetLastError(87). Any other value moves the per-user
 * cache: never called with a path. */
TEST(gs_update_cache_content_path_null) {
    REQUIRE(UN(UpdateUrlCacheContentPath));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        CHECK(!UN(UpdateUrlCacheContentPath)(NULL));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

/* ================================================================== UrlZonesDetach
 * [D UrlZonesDetach@0x17f6c0] releases the cached zone/security managers under a lock; void, no GLE. Later zone
 * users re-create them on demand. */
TEST(gs_url_zones_detach) {
    REQUIRE(UN(UrlZonesDetach)); REQUIRE(U(PrivacyGetZonePreferenceW));
    DWORD before = 0xA5A5, after = 0xA5A5;
    DWORD r1 = U(PrivacyGetZonePreferenceW)(3, PRIVACY_TYPE_FIRST_PARTY, &before, NULL, NULL);
    SET_ERR(0x4242);
    UN(UrlZonesDetach)();
    UN(UrlZonesDetach)();
    EXPECT_ERR(0x4242);
    DWORD r2 = U(PrivacyGetZonePreferenceW)(3, PRIVACY_TYPE_FIRST_PARTY, &after, NULL, NULL);
    EXPECT_EQ(r1, r2);
    EXPECT_EQ(before, after);
    /* the zone-aware helpers keep working */
    if (U(InternetCrackUrlA)) {
        URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc; uc.dwHostNameLength = 1;
        CHECK(U(InternetCrackUrlA)("http://127.0.0.1/x", 0, 0, &uc));
    }
}

/* ================================================================== Passport / SSO: resolve only (they reach the
 * passport nexus over the network) */
TEST(gs_passport_exports_resolve_only) {
    CHECK(t_proc_in("wininet.dll", "CreateMD5SSOHash") != NULL);
    CHECK(t_proc_in("wininet.dll", "ForceNexusLookup") != NULL);
    CHECK(t_proc_in("wininet.dll", "ForceNexusLookupExW") != NULL);
    CHECK(GetProcAddress(t_module("wininet.dll"), "CreateMD5SSOHashA") == NULL);
    CHECK(GetProcAddress(t_module("wininet.dll"), "CreateMD5SSOHashW") == NULL);
}
