/* Small undocumented/legacy helpers with real argument validation: privacy zone preferences, HSTS query,
 * DAV, HTTP push and dependency handles (urlmon plumbing), security-info-by-URL (UI: only the paths that
 * fail before a dialog), cache-entry unlock edges, request-file locks, cache-group attributes and the
 * cache header counters.
 * VM_TIMEOUT: 150 */
#include "gs.h"
#include "srv.h"
#include "tnet.h"
#ifndef URLZONE_INTERNET
#define URLZONE_INTERNET 3
#endif

/* ================================================================== PrivacyGetZonePreferenceW
 * [D PrivacyGetZonePreferenceW@0x69630]
 *   zone in [5, 999] or > 10000, or type > 1                     -> 87
 *   buf == NULL && len != NULL && *len != 0                      -> 0, nothing written
 *   buf != NULL && len == NULL                                   -> 0, nothing written
 *   otherwise: reads the zone's privacy setting; if buf: *len <= strlen -> 234 (ERROR_MORE_DATA); *len = strlen + 1
 *   *pdwTemplate = PRIVACY_TEMPLATE_* (0..5, 100 custom, 101 advanced) when non-NULL. */
TEST(gs_privacy_get_bad_zone_type) {
    REQUIRE(U(PrivacyGetZonePreferenceW));
    static const DWORD zones[] = { 5, 6, 100, 999, 10001, 0x7FFFFFFFu, 0xFFFFFFFFu };
    for (size_t z = 0; z < sizeof zones / sizeof zones[0]; z++) {
        DWORD tpl = 0xA5A5;
        SET_ERR(0x4242);
        EXPECT_EQ(U(PrivacyGetZonePreferenceW)(zones[z], PRIVACY_TYPE_FIRST_PARTY, &tpl, NULL, NULL), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(tpl, 0xA5A5);
    }
    static const DWORD types[] = { 2, 3, 0x100, 0xFFFFFFFFu };
    for (size_t t = 0; t < 4; t++) {
        DWORD tpl = 0xA5A5;
        EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, types[t], &tpl, NULL, NULL), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(tpl, 0xA5A5);
    }
}

static int gs_valid_template(DWORD t) { return t <= PRIVACY_TEMPLATE_LOW || t == PRIVACY_TEMPLATE_CUSTOM || t == PRIVACY_TEMPLATE_ADVANCED; }

TEST(gs_privacy_get_template_standard_zones) {
    REQUIRE(U(PrivacyGetZonePreferenceW));
    for (DWORD zone = 0; zone <= 4; zone++)
        for (DWORD type = 0; type <= 1; type++) {
            DWORD tpl = 0xA5A5;
            DWORD r = U(PrivacyGetZonePreferenceW)(zone, type, &tpl, NULL, NULL);
            CHECKF(r == 0, "zone %lu type %lu r=%lu", zone, type, r);
            CHECKF(gs_valid_template(tpl), "zone %lu type %lu template %lu", zone, type, tpl);
            t_note("privacy zone %lu %s: template %lu", zone, type ? "3rd" : "1st", tpl);
        }
}

TEST(gs_privacy_get_template_stable) {
    REQUIRE(U(PrivacyGetZonePreferenceW));
    DWORD a = 0, b = 0;
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, PRIVACY_TYPE_FIRST_PARTY, &a, NULL, NULL), 0);
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, PRIVACY_TYPE_FIRST_PARTY, &b, NULL, NULL), 0);
    EXPECT_EQ(a, b);
    /* NULL template pointer is allowed */
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, PRIVACY_TYPE_THIRD_PARTY, NULL, NULL, NULL), 0);
}

TEST(gs_privacy_get_buffer_rules) {
    REQUIRE(U(PrivacyGetZonePreferenceW));
    /* buf NULL with a non-zero length: early success, template untouched */
    DWORD tpl = 0xA5A5, len = 10;
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, 0, &tpl, NULL, &len), 0);
    EXPECT_EQ(tpl, 0xA5A5);
    EXPECT_EQ(len, 10);
    /* buf without a length: early success, nothing written */
    WCHAR buf[64]; gs_fill(buf, sizeof buf);
    tpl = 0xA5A5;
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, 0, &tpl, buf, NULL), 0);
    EXPECT_EQ(tpl, 0xA5A5);
    CHECK(gs_untouched(buf, sizeof buf));
    /* buf NULL and *len == 0: full query, length not updated */
    tpl = 0xA5A5; len = 0;
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, 0, &tpl, NULL, &len), 0);
    CHECK(gs_valid_template(tpl));
    EXPECT_EQ(len, 0);
}

TEST(gs_privacy_get_string_sizes) {
    REQUIRE(U(PrivacyGetZonePreferenceW));
    WCHAR big[0x4100]; DWORD len = sizeof big / sizeof big[0], tpl = 0;
    DWORD r = U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, 0, &tpl, big, &len);
    EXPECT_EQ(r, 0);
    if (r) return;
    DWORD sl = (DWORD)lstrlenW(big);
    EXPECT_EQ(len, sl + 1);
    t_note("privacy zone 3 1st-party: template %lu, string %lu chars%s", tpl, sl, sl ? "" : " (empty)");
    if (sl) CHECK(!wcsncmp(big, L"IE6-P3PV1/settings:", 19));
    /* exactly strlen: too small (the check is *len <= strlen) */
    WCHAR small[0x4100]; DWORD l2 = sl;
    gs_fill(small, sizeof small);
    r = U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, 0, &tpl, small, &l2);
    EXPECT_EQ(r, ERROR_MORE_DATA);
    EXPECT_EQ(l2, sl + 1);
    /* strlen + 1 fits */
    l2 = sl + 1;
    EXPECT_EQ(U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, 0, &tpl, small, &l2), 0);
    EXPECT_EQ(l2, sl + 1);
    CHECK(!lstrcmpW(small, big));
}

TEST(gs_privacy_get_custom_zone_range) {
    REQUIRE(U(PrivacyGetZonePreferenceW));
    static const DWORD zones[] = { 1000, 5000, 10000 };
    for (size_t i = 0; i < 3; i++) {
        DWORD tpl = 0xA5A5;
        DWORD r = U(PrivacyGetZonePreferenceW)(zones[i], 0, &tpl, NULL, NULL);
        CHECKF(r != ERROR_INVALID_PARAMETER, "zone %lu rejected", zones[i]);
        t_note("privacy custom zone %lu: r=%lu template %lu", zones[i], r, tpl);
    }
}

/* ================================================================== PrivacySetZonePreferenceW (argument checks only)
 * [D PrivacySetZonePreferenceW@0xcea10] 87 when: zone in [5,999] or > 10000; type > 1; template not in
 * {0..5,100,101}; pref NULL with CUSTOM(100); pref non-NULL with a template other than 100/101.
 * All of these return before anything is read or written. If one unexpectedly succeeds the original
 * template/string for the zone is written back. */
typedef struct { DWORD zone, type, tpl; const WCHAR *pref; } gs_pset;
static void gs_privacy_restore(DWORD zone, DWORD type, DWORD tpl, const WCHAR *s) {
    if (tpl == PRIVACY_TEMPLATE_CUSTOM || tpl == PRIVACY_TEMPLATE_ADVANCED) U(PrivacySetZonePreferenceW)(zone, type, tpl, s);
    else U(PrivacySetZonePreferenceW)(zone, type, tpl, NULL);
}
TEST(gs_privacy_set_invalid_args) {
    REQUIRE(U(PrivacySetZonePreferenceW)); REQUIRE(U(PrivacyGetZonePreferenceW));
    static const gs_pset bad[] = {
        { 5, 0, PRIVACY_TEMPLATE_MEDIUM, NULL }, { 999, 0, PRIVACY_TEMPLATE_MEDIUM, NULL },
        { 10001, 0, PRIVACY_TEMPLATE_MEDIUM, NULL }, { 0xFFFFFFFFu, 0, PRIVACY_TEMPLATE_MEDIUM, NULL },
        { URLZONE_INTERNET, 2, PRIVACY_TEMPLATE_MEDIUM, NULL }, { URLZONE_INTERNET, 0xFFFFFFFFu, PRIVACY_TEMPLATE_MEDIUM, NULL },
        { URLZONE_INTERNET, 0, 6, NULL }, { URLZONE_INTERNET, 0, 99, NULL }, { URLZONE_INTERNET, 0, 102, NULL },
        { URLZONE_INTERNET, 0, 0xFFFFFFFFu, NULL },
        { URLZONE_INTERNET, 0, PRIVACY_TEMPLATE_CUSTOM, NULL },
        { URLZONE_INTERNET, 0, PRIVACY_TEMPLATE_MEDIUM, L"IE6-P3PV1/settings: always=a" },
        { URLZONE_INTERNET, 1, PRIVACY_TEMPLATE_NO_COOKIES, L"x" },
        { URLZONE_INTERNET, 0, PRIVACY_TEMPLATE_LOW, L"" },
    };
    DWORD saved_tpl[2] = { 0, 0 }; static WCHAR saved_s[2][0x4100];
    for (DWORD t = 0; t < 2; t++) {
        DWORD l = 0x4100;
        saved_s[t][0] = 0;
        U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, t, &saved_tpl[t], saved_s[t], &l);
    }
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0x4242);
        DWORD r = U(PrivacySetZonePreferenceW)(bad[i].zone, bad[i].type, bad[i].tpl, bad[i].pref);
        CHECKF(r == ERROR_INVALID_PARAMETER, "case %zu (zone %lu type %lu tpl %lu) r=%lu", i, bad[i].zone, bad[i].type, bad[i].tpl, r);
        if (r == 0 && bad[i].zone == URLZONE_INTERNET && bad[i].type < 2) {
            t_note("case %zu unexpectedly succeeded: restoring zone 3 type %lu", i, bad[i].type);
            gs_privacy_restore(URLZONE_INTERNET, bad[i].type, saved_tpl[bad[i].type], saved_s[bad[i].type]);
        }
    }
    for (DWORD t = 0; t < 2; t++) {
        DWORD now = 0xA5A5;
        U(PrivacyGetZonePreferenceW)(URLZONE_INTERNET, t, &now, NULL, NULL);
        EXPECT_EQ(now, saved_tpl[t]);
    }
}

/* ================================================================== HttpIsHostHstsEnabled
 * [D HttpIsHostHstsEnabled@0xbc1a0] *pf = 0 first; NULL host or out -> 87 (WX_WIN32_FROM_HR(E_INVALIDARG));
 * else CHstsManager::IsHostHstsW (learned + preloaded list). Returns a Win32 code. */
TEST(gs_hsts_null_args) {
    REQUIRE(UN(HttpIsHostHstsEnabled));
    BOOL f = 0x5A5A;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(HttpIsHostHstsEnabled)(NULL, &f), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(f, 0);
    EXPECT_EQ(UN(HttpIsHostHstsEnabled)(L"127.0.0.1", NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(UN(HttpIsHostHstsEnabled)(NULL, NULL), ERROR_INVALID_PARAMETER);
    t_note("HttpIsHostHstsEnabled GLE after: %lu", GetLastError());
}

TEST(gs_hsts_local_hosts_false) {
    REQUIRE(UN(HttpIsHostHstsEnabled));
    char uniq[96]; snprintf(uniq, sizeof uniq, "gs-hsts-%lu.invalid", GetCurrentProcessId());
    WCHAR uw[96]; MultiByteToWideChar(CP_ACP, 0, uniq, -1, uw, 96);
    const WCHAR *hosts[] = { L"127.0.0.1", L"localhost", L"[::1]", L"::1", L"", L"a", uw, L"example.invalid",
                             L"127.0.0.1:443", L"LOCALHOST" };
    for (size_t i = 0; i < sizeof hosts / sizeof hosts[0]; i++) {
        BOOL f = 0x5A5A;
        DWORD r = UN(HttpIsHostHstsEnabled)(hosts[i], &f);
        CHECKF(r == 0, "host %zu r=%lu", i, r);
        CHECKF(f == 0, "host %zu enabled=%d", i, f);
    }
}

TEST(gs_hsts_preload_observations) {
    REQUIRE(UN(HttpIsHostHstsEnabled));
    /* the preload list is data, not code: observations only (no network is used) */
    const WCHAR *hosts[] = { L"google.com", L"www.google.com", L"accounts.google.com", L"paypal.com", L"www.paypal.com",
                             L"twitter.com", L"login.live.com", L"microsoft.com" };
    char line[512]; size_t pos = 0;
    for (size_t i = 0; i < sizeof hosts / sizeof hosts[0]; i++) {
        BOOL f = 0x5A5A;
        DWORD r = UN(HttpIsHostHstsEnabled)(hosts[i], &f);
        CHECK(r == 0);
        CHECK(f == 0 || f == 1);
        pos += snprintf(line + pos, sizeof line - pos, "%ls=%d ", hosts[i], f);
    }
    t_note("hsts preload: %s", line);
}

/* ================================================================== HTTP push (urlmon plumbing)
 * [D HttpPushEnableInternal] *phWait = NULL first; NULL request or NULL setting -> 87; setting GUID that is
 * not REAL_TIME_NOTIFICATION_CAPABILITY -> 87; NULL phWait (with the right GUID) -> 87.
 * [D HttpPushWaitInternal] status zeroed (8 bytes, NULL ok); NULL handle or type > 2 -> 87.
 * [D HttpPushClose] NULL is a no-op. */
TEST(gs_push_enable_args) {
    REQUIRE(UN(HttpPushEnable));
    gs_push_setting st; memset(&st, 0, sizeof st);
    HANDLE w = (HANDLE)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(HttpPushEnable)(NULL, &st, &w), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(w, NULL);
    w = (HANDLE)0x1234;
    EXPECT_EQ(UN(HttpPushEnable)(NULL, NULL, &w), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(w, NULL);
    EXPECT_EQ(UN(HttpPushEnable)(NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    HINTERNET c = gs_connect_http(gs_session());
    HINTERNET r = gs_request(c, "/gs_push");
    if (r) {
        w = (HANDLE)0x1234;
        EXPECT_EQ(UN(HttpPushEnable)(r, NULL, &w), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(w, NULL);
        /* wrong transport GUID */
        w = (HANDLE)0x1234;
        EXPECT_EQ(UN(HttpPushEnable)(r, &st, &w), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(w, NULL);
        memset(&st, 0xFF, sizeof st);
        EXPECT_EQ(UN(HttpPushEnable)(r, &st, NULL), ERROR_INVALID_PARAMETER);
        U(InternetCloseHandle)(r);
    }
    if (c) U(InternetCloseHandle)(c);
    t_note("HttpPushEnable GLE after: %lu", GetLastError());
}

TEST(gs_push_wait_args) {
    REQUIRE(UN(HttpPushWait));
    for (DWORD type = 0; type < 5; type++) {
        gs_push_status s; gs_fill(&s, sizeof s);
        SET_ERR(0x4242);
        EXPECT_EQ(UN(HttpPushWait)(NULL, type, &s), ERROR_INVALID_PARAMETER);
        CHECK(gs_all_zero(&s, sizeof s));
        EXPECT_EQ(UN(HttpPushWait)(NULL, type, NULL), ERROR_INVALID_PARAMETER);
    }
    gs_push_status s; gs_fill(&s, sizeof s);
    EXPECT_EQ(UN(HttpPushWait)(NULL, 0xFFFFFFFFu, &s), ERROR_INVALID_PARAMETER);
    CHECK(gs_all_zero(&s, sizeof s));
}

TEST(gs_push_close_null) {
    REQUIRE(UN(HttpPushClose));
    SET_ERR(0x4242);
    UN(HttpPushClose)(NULL);
    UN(HttpPushClose)(NULL);
    EXPECT_ERR(0x4242);
}

/* ================================================================== dependency handles
 * [D HttpOpenDependencyHandleInternal] NULL request or NULL out -> 87 (out untouched when request is NULL);
 * else *out = NULL; handle not a request -> 12018 INCORRECT_HANDLE_TYPE; second open on the same request
 * -> 12019 INCORRECT_HANDLE_STATE; else a CDependentHostList.
 * [D HttpDuplicateDependencyHandle] NULL either -> 87.  [D HttpCloseDependencyHandle] NULL ok.
 * [D HttpIndicatePageLoadComplete] NULL ok; returns 0 (rax cleared on every path). */
TEST(gs_dependency_open_args) {
    REQUIRE(UN(HttpOpenDependencyHandle));
    HANDLE d = (HANDLE)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(HttpOpenDependencyHandle)(NULL, FALSE, &d), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(d, (HANDLE)0x1234);
    EXPECT_EQ(UN(HttpOpenDependencyHandle)(NULL, TRUE, NULL), ERROR_INVALID_PARAMETER);
    HINTERNET s = gs_session();
    if (!s) return;
    EXPECT_EQ(UN(HttpOpenDependencyHandle)(s, FALSE, NULL), ERROR_INVALID_PARAMETER);
    d = (HANDLE)0x1234;
    EXPECT_EQ(UN(HttpOpenDependencyHandle)(s, FALSE, &d), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    EXPECT_EQ(d, NULL);
    HINTERNET c = gs_connect_http(s);
    if (c) {
        d = (HANDLE)0x1234;
        EXPECT_EQ(UN(HttpOpenDependencyHandle)(c, TRUE, &d), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        EXPECT_EQ(d, NULL);
        U(InternetCloseHandle)(c);
    }
}

TEST(gs_dependency_open_closed_handle) {
    REQUIRE(UN(HttpOpenDependencyHandle));
    HINTERNET c = gs_connect_http(gs_session());
    HINTERNET r = gs_request(c, "/gs_dep_closed");
    if (!r) { t_skip("no request"); if (c) U(InternetCloseHandle)(c); return; }
    U(InternetCloseHandle)(r);
    HANDLE d = (HANDLE)0x1234;
    DWORD e = UN(HttpOpenDependencyHandle)(r, FALSE, &d);
    EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    EXPECT_EQ(d, NULL);
    U(InternetCloseHandle)(c);
}

TEST(gs_dependency_open_request_lifecycle) {
    REQUIRE(UN(HttpOpenDependencyHandle)); REQUIRE(UN(HttpCloseDependencyHandle)); REQUIRE(UN(HttpIndicatePageLoadComplete));
    HINTERNET c = gs_connect_http(gs_session());
    char path[64]; snprintf(path, sizeof path, "/gs_dep_%lu", GetCurrentProcessId());
    HINTERNET r = gs_request(c, path);
    if (!r) { t_skip("no request"); if (c) U(InternetCloseHandle)(c); return; }
    HANDLE d = NULL;
    DWORD e = UN(HttpOpenDependencyHandle)(r, FALSE, &d);
    EXPECT_EQ(e, 0);
    CHECK(d != NULL);
    if (!e && d) {
        HANDLE d2 = (HANDLE)0x1234;
        EXPECT_EQ(UN(HttpOpenDependencyHandle)(r, FALSE, &d2), ERROR_INTERNET_INCORRECT_HANDLE_STATE);
        EXPECT_EQ(d2, NULL);
        DWORD pr = UN(HttpIndicatePageLoadComplete)(d);
        t_note("HttpIndicatePageLoadComplete(dep) = %lu", pr);
        UN(HttpCloseDependencyHandle)(d);
    }
    CHECK(U(InternetCloseHandle)(r));
    U(InternetCloseHandle)(c);
}

TEST(gs_dependency_dup_close_null) {
    REQUIRE(UN(HttpDuplicateDependencyHandle)); REQUIRE(UN(HttpCloseDependencyHandle)); REQUIRE(UN(HttpIndicatePageLoadComplete));
    HANDLE out = (HANDLE)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(UN(HttpDuplicateDependencyHandle)(NULL, &out), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(out, (HANDLE)0x1234);
    EXPECT_EQ(UN(HttpDuplicateDependencyHandle)(NULL, NULL), ERROR_INVALID_PARAMETER);
    UN(HttpCloseDependencyHandle)(NULL);
    EXPECT_EQ(UN(HttpIndicatePageLoadComplete)(NULL), 0);
    EXPECT_ERR(0x4242);
}

/* ================================================================== security info by URL (UI-capable)
 * [D InternetShowSecurityInfoByURL(A)@0x138720] FindCertEntryInCache: only https URLs whose host is in this
 * process's SSL cache reach ShowSecurityInfo (a cryptui dialog). Any other URL returns FALSE without UI.
 * This area never makes a TLS request, so the cache is empty. Every call is bounded anyway. */
typedef struct { const char *a; const WCHAR *w; BOOL r; DWORD e; } gs_ssi;
static void gs_ssi_job(void *p) {
    gs_ssi *c = (gs_ssi *)p;
    SetLastError(0x4242);
    if (c->a) c->r = UN(InternetShowSecurityInfoByURLA)((LPSTR)c->a, NULL);
    else c->r = UN(InternetShowSecurityInfoByURLW)(c->w, NULL);
    c->e = GetLastError();
}
TEST(gs_show_security_info_by_url_a_no_cache) {
    REQUIRE(UN(InternetShowSecurityInfoByURLA)); REQUIRE(UN(InternetShowSecurityInfoByURL));
    static const char *urls[] = { "http://127.0.0.1/", "https://gs-nosuch.invalid/", "https://127.0.0.1:1/", "ftp://127.0.0.1/",
                                  "https://", "not a url", "" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        gs_ssi c = { urls[i], NULL, 7, 0 };
        if (!gs_bounded(gs_ssi_job, &c, 5000)) { CHECKF(0, "%s: blocked (UI?)", urls[i]); return; }
        CHECKF(c.r == FALSE, "%s: r=%d", urls[i], c.r);
        CHECKF(c.e == 0x4242, "%s: GLE %lu", urls[i], c.e);
    }
}

TEST(gs_show_security_info_by_url_w_no_cache) {
    REQUIRE(UN(InternetShowSecurityInfoByURLW));
    static const WCHAR *urls[] = { L"http://127.0.0.1/", L"https://gs-nosuch.invalid/", L"https://127.0.0.1:1/x" };
    for (size_t i = 0; i < 3; i++) {
        gs_ssi c = { NULL, urls[i], 7, 0 };
        if (!gs_bounded(gs_ssi_job, &c, 5000)) { CHECKF(0, "url %zu blocked (UI?)", i); return; }
        CHECKF(c.r == FALSE, "url %zu: r=%d", i, c.r);
        t_note("InternetShowSecurityInfoByURLW url %zu: GLE %lu", i, c.e);
    }
}

TEST(gs_security_ui_exports_resolve_only) {
    CHECK(t_proc_in("wininet.dll", "ShowSecurityInfo") != NULL);
    CHECK(t_proc_in("wininet.dll", "ShowX509EncodedCertificate") != NULL);
    CHECK(t_proc_in("wininet.dll", "InternetShowSecurityInfoByURL") != NULL);
}

/* ================================================================== UnlockUrlCacheEntryFile edges
 * [D UnlockUrlCacheEntryFile(A)@0x1a30d0, W@0x1a3210] NULL url or reserved != 0 -> FALSE, 87;
 * else container lookup + UnlockUrl. */
TEST(gs_unlock_cache_entry_args) {
    REQUIRE(UN(UnlockUrlCacheEntryFileA)); REQUIRE(UN(UnlockUrlCacheEntryFileW)); REQUIRE(UN(UnlockUrlCacheEntryFile));
    static const DWORD res[] = { 1, 2, 0x80000000u, 0xFFFFFFFFu };
    SET_ERR(0); CHECK(!UN(UnlockUrlCacheEntryFileA)(NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(UnlockUrlCacheEntryFileW)(NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(UnlockUrlCacheEntryFile)(NULL, 0));  EXPECT_ERR(ERROR_INVALID_PARAMETER);
    for (size_t i = 0; i < 4; i++) {
        SET_ERR(0); CHECK(!UN(UnlockUrlCacheEntryFileA)("http://127.0.0.1/gs", res[i])); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0); CHECK(!UN(UnlockUrlCacheEntryFileW)(L"http://127.0.0.1/gs", res[i])); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0); CHECK(!UN(UnlockUrlCacheEntryFileA)(NULL, res[i])); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(gs_unlock_cache_entry_unknown_url) {
    REQUIRE(UN(UnlockUrlCacheEntryFileA)); REQUIRE(UN(UnlockUrlCacheEntryFileW));
    const char *url = t_uniq_cache_url("gs_unlock_unknown");
    SET_ERR(0);
    BOOL r = UN(UnlockUrlCacheEntryFileA)(url, 0);
    DWORD e = GetLastError();
    CHECK(!r);
    CHECKF(e == ERROR_FILE_NOT_FOUND, "A e=%lu", e);
    WCHAR w[300]; MultiByteToWideChar(CP_ACP, 0, url, -1, w, 300);
    SET_ERR(0);
    r = UN(UnlockUrlCacheEntryFileW)(w, 0);
    DWORD e2 = GetLastError();
    CHECK(!r);
    EXPECT_EQ(e2, e);
}

static int gs_make_cache_entry(const char *url, char *file, size_t cap) {
    if (!U(CreateUrlCacheEntryA) || !U(CommitUrlCacheEntryA)) return 0;
    if (!U(CreateUrlCacheEntryA)(url, 0, "txt", file, 0)) return 0;
    HANDLE h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w; WriteFile(h, "gopher_and_stubs", 16, &w, NULL); CloseHandle(h);
    FILETIME z = { 0 };
    if (!U(CommitUrlCacheEntryA)(url, file, z, z, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL)) return 0;
    t_cache_track(url);
    (void)cap;
    return 1;
}

TEST(gs_unlock_cache_entry_after_retrieve) {
    REQUIRE(UN(UnlockUrlCacheEntryFileA)); REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(CreateUrlCacheEntryA));
    const char *url = t_uniq_cache_url("gs_unlock_retr");
    char file[MAX_PATH];
    if (!gs_make_cache_entry(url, file, sizeof file)) { t_skip("could not create cache entry: %lu", GetLastError()); return; }
    BYTE buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    SET_ERR(0x4242);
    CHECK(UN(UnlockUrlCacheEntryFileA)(url, 0));
    EXPECT_ERR(0);
    /* unlocking an entry that is no longer locked */
    SET_ERR(0x4242);
    BOOL r = UN(UnlockUrlCacheEntryFileA)(url, 0);
    t_note("second unlock: r=%d e=%lu", r, GetLastError());
    /* never retrieved: unlock on a committed-but-unlocked entry */
    if (U(DeleteUrlCacheEntryA)) CHECK(U(DeleteUrlCacheEntryA)(url));
}

TEST(gs_unlock_cache_entry_w_after_retrieve) {
    REQUIRE(UN(UnlockUrlCacheEntryFileW)); REQUIRE(U(RetrieveUrlCacheEntryFileW)); REQUIRE(U(CreateUrlCacheEntryA));
    const char *url = t_uniq_cache_url("gs_unlock_w");
    char file[MAX_PATH];
    if (!gs_make_cache_entry(url, file, sizeof file)) { t_skip("could not create cache entry"); return; }
    WCHAR w[300]; MultiByteToWideChar(CP_ACP, 0, url, -1, w, 300);
    BYTE buf[8192]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileW)(w, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, 0));
    SET_ERR(0x4242);
    CHECK(UN(UnlockUrlCacheEntryFileW)(w, 0));
    EXPECT_ERR(0);
    /* the locked entry could not be deleted while locked; after unlock it can */
    if (U(DeleteUrlCacheEntryW)) CHECK(U(DeleteUrlCacheEntryW)(w));
}

TEST(gs_unlock_cache_entry_plain_is_ansi) {
    REQUIRE(UN(UnlockUrlCacheEntryFile)); REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = t_uniq_cache_url("gs_unlock_plain");
    char file[MAX_PATH];
    if (!gs_make_cache_entry(url, file, sizeof file)) { t_skip("could not create cache entry"); return; }
    BYTE buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    CHECK(UN(UnlockUrlCacheEntryFile)(url, 0));
    if (U(DeleteUrlCacheEntryA)) CHECK(U(DeleteUrlCacheEntryA)(url));
}

/* ================================================================== InternetLockRequestFile / Unlock
 * [D InternetLockRequestFile@0x1be40] handle not mapped -> 6; session/connect handles -> 6;
 * request without a data file -> FALSE, 2; else CreateFileW(datafile) and a refcounted lock (second lock on
 * the same handle returns the same lock). [D InternetUnlockRequestFile@0xb790] signature check -> 87. */
TEST(gs_lock_request_file_bad_handles) {
    REQUIRE(UN(InternetLockRequestFile));
    HANDLE lk = (HANDLE)0x1234;
    SET_ERR(0);
    CHECK(!UN(InternetLockRequestFile)(NULL, &lk));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    EXPECT_EQ(lk, (HANDLE)0x1234);
    HINTERNET s = gs_session();
    if (s) { SET_ERR(0); CHECK(!UN(InternetLockRequestFile)(s, &lk)); EXPECT_ERR(ERROR_INVALID_HANDLE); }
    HINTERNET c = gs_connect_http(s);
    if (c) { SET_ERR(0); CHECK(!UN(InternetLockRequestFile)(c, &lk)); EXPECT_ERR(ERROR_INVALID_HANDLE); }
    HINTERNET r = gs_request(c, "/gs_lock_unsent");
    if (r) {
        SET_ERR(0);
        CHECK(!UN(InternetLockRequestFile)(r, &lk));
        EXPECT_ERR(ERROR_FILE_NOT_FOUND);
        EXPECT_EQ(lk, (HANDLE)0x1234);
        U(InternetCloseHandle)(r);
        SET_ERR(0);
        CHECK(!UN(InternetLockRequestFile)(r, &lk));   /* closed */
        EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
    if (c) U(InternetCloseHandle)(c);
}

TEST(gs_unlock_request_file_bad_signature) {
    REQUIRE(UN(InternetUnlockRequestFile));
    DWORD fake[16]; memset(fake, 0, sizeof fake);
    SET_ERR(0);
    CHECK(!UN(InternetUnlockRequestFile)((HANDLE)fake));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    fake[0] = 0xAA55AA56u;
    SET_ERR(0);
    CHECK(!UN(InternetUnlockRequestFile)((HANDLE)fake));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(fake[2] == 0);   /* refcount word untouched */
}

TEST(gs_lock_request_file_after_download) {
    REQUIRE(UN(InternetLockRequestFile)); REQUIRE(UN(InternetUnlockRequestFile)); REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n", "locked-body"), S_LOOP() };
    srv *s = srv_http(st, 3);
    if (!s) { t_skip("server unavailable: %s", srv_strerror(srv_last_error())); return; }
    char path[64]; snprintf(path, sizeof path, "/gs_lock_%lu", GetCurrentProcessId());
    const char *url = srv_url(s, path);
    char urlcopy[256]; lstrcpynA(urlcopy, url, sizeof urlcopy);
    t_cache_track(urlcopy);
    HINTERNET hi = t_inet_open("gs_lock");
    HINTERNET h = hi ? U(InternetOpenUrlA)(hi, urlcopy, NULL, 0,
                                           INTERNET_FLAG_RELOAD | INTERNET_FLAG_NEED_FILE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0) : NULL;
    CHECKF(h != NULL, "OpenUrl e=%lu", GetLastError());
    if (h) {
        char body[64]; int ok = 0;
        size_t n = t_inet_read_all(h, body, sizeof body, &ok);
        CHECK(ok); EXPECT_EQ(n, 11);
        HANDLE lk1 = NULL, lk2 = NULL;
        SET_ERR(0x4242);
        BOOL r1 = UN(InternetLockRequestFile)(h, &lk1);
        DWORD e1 = GetLastError();
        CHECKF(r1, "lock e=%lu", e1);
        if (r1) {
            EXPECT_EQ(e1, 0);
            CHECK(lk1 != NULL);
            CHECK(UN(InternetLockRequestFile)(h, &lk2));
            EXPECT_EQ(lk1, lk2);    /* one lock per handle, refcounted */
            char df[MAX_PATH] = ""; DWORD dl = sizeof df;
            if (U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, df, &dl))
                CHECKF(GetFileAttributesA(df) != INVALID_FILE_ATTRIBUTES, "data file %s missing", df);
            SET_ERR(0x4242);
            CHECK(UN(InternetUnlockRequestFile)(lk2));
            EXPECT_ERR(0);
            CHECK(UN(InternetUnlockRequestFile)(lk1));
        }
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
    t_net_cleanup();
}

/* ================================================================== cache group attributes
 * [D SetUrlCacheGroupAttributeA@0x1a2b80] info NULL or reserved non-NULL -> FALSE, 87.
 * [D GetUrlCacheGroupAttributeA@0x1a1080] info/len NULL or reserved -> 87; *len < 156 -> 122 with *len = 156
 * (before the group is looked up). */
TEST(gs_set_group_attr_args) {
    REQUIRE(UN(SetUrlCacheGroupAttributeA)); REQUIRE(UN(SetUrlCacheGroupAttributeW));
    INTERNET_CACHE_GROUP_INFOA ia; INTERNET_CACHE_GROUP_INFOW iw;
    memset(&ia, 0, sizeof ia); ia.dwGroupSize = sizeof ia;
    memset(&iw, 0, sizeof iw); iw.dwGroupSize = sizeof iw;
    int res;
    static const GROUPID gids[] = { 0, 1, 0x7FFFFFFF12345678LL };
    for (size_t g = 0; g < 3; g++) {
        SET_ERR(0); CHECK(!UN(SetUrlCacheGroupAttributeA)(gids[g], 0, CACHEGROUP_ATTRIBUTE_GET_ALL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0); CHECK(!UN(SetUrlCacheGroupAttributeA)(gids[g], 0, CACHEGROUP_ATTRIBUTE_GROUPNAME, &ia, &res)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0); CHECK(!UN(SetUrlCacheGroupAttributeW)(gids[g], 0, CACHEGROUP_ATTRIBUTE_GET_ALL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0); CHECK(!UN(SetUrlCacheGroupAttributeW)(gids[g], 0, CACHEGROUP_ATTRIBUTE_FLAG, &iw, &res)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(gs_get_group_attr_size_first) {
    REQUIRE(UN(GetUrlCacheGroupAttributeA)); REQUIRE(UN(GetUrlCacheGroupAttributeW));
    INTERNET_CACHE_GROUP_INFOA ia; INTERNET_CACHE_GROUP_INFOW iw; DWORD len; int res;
    EXPECT_EQ(sizeof ia, 156);
    static const DWORD small[] = { 0, 1, 155 };
    for (size_t i = 0; i < 3; i++) {
        len = small[i];
        SET_ERR(0);
        CHECK(!UN(GetUrlCacheGroupAttributeA)(0x7FFFFFFF12345678LL, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &ia, &len, NULL));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(len, sizeof ia);
    }
    len = sizeof ia;
    SET_ERR(0); CHECK(!UN(GetUrlCacheGroupAttributeA)(1, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, NULL, &len, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(GetUrlCacheGroupAttributeA)(1, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &ia, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(GetUrlCacheGroupAttributeA)(1, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &ia, &len, &res)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    len = 0;
    SET_ERR(0);
    CHECK(!UN(GetUrlCacheGroupAttributeW)(0x7FFFFFFF12345678LL, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &iw, &len, NULL));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(len, sizeof iw);
}

TEST(gs_group_attr_unknown_group) {
    REQUIRE(UN(GetUrlCacheGroupAttributeA)); REQUIRE(UN(SetUrlCacheGroupAttributeA));
    INTERNET_CACHE_GROUP_INFOA ia; DWORD len = sizeof ia;
    memset(&ia, 0, sizeof ia); ia.dwGroupSize = sizeof ia;
    SET_ERR(0);
    BOOL r = UN(GetUrlCacheGroupAttributeA)(0x7FFFFFFF12345678LL, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &ia, &len, NULL);
    DWORD e = GetLastError();
    CHECK(!r);
    t_note("GetUrlCacheGroupAttributeA unknown group: e=%lu", e);
    CHECKF(e == ERROR_FILE_NOT_FOUND, "e=%lu", e);
    SET_ERR(0);
    r = UN(SetUrlCacheGroupAttributeA)(0x7FFFFFFF12345678LL, 0, CACHEGROUP_ATTRIBUTE_FLAG, &ia, NULL);
    e = GetLastError();
    CHECK(!r);
    t_note("SetUrlCacheGroupAttributeA unknown group: e=%lu", e);
    CHECKF(e == ERROR_FILE_NOT_FOUND, "e=%lu", e);
}

TEST(gs_group_attr_roundtrip) {
    REQUIRE(U(CreateUrlCacheGroup)); REQUIRE(U(DeleteUrlCacheGroup));
    REQUIRE(UN(GetUrlCacheGroupAttributeA)); REQUIRE(UN(SetUrlCacheGroupAttributeA));
    GROUPID g = U(CreateUrlCacheGroup)(0, NULL);
    CHECKF(g != 0, "CreateUrlCacheGroup e=%lu", GetLastError());
    if (!g) return;
    INTERNET_CACHE_GROUP_INFOA ia; DWORD len = sizeof ia;
    memset(&ia, 0, sizeof ia); ia.dwGroupSize = sizeof ia;
    CHECK(UN(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &ia, &len, NULL));
    t_note("new group: flags=0x%lx type=0x%lx quota=%lu", ia.dwGroupFlags, ia.dwGroupType, ia.dwDiskQuota);
    char name[64]; snprintf(name, sizeof name, "gs_group_%lu", GetCurrentProcessId());
    lstrcpynA(ia.szGroupName, name, GROUPNAME_MAX_LENGTH);
    ia.dwOwnerStorage[0] = 0x11; ia.dwOwnerStorage[3] = 0x44;
    SET_ERR(0x4242);
    BOOL r = UN(SetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GROUPNAME | CACHEGROUP_ATTRIBUTE_STORAGE, &ia, NULL);
    CHECKF(r, "set e=%lu", GetLastError());
    if (r) EXPECT_ERR(0);
    INTERNET_CACHE_GROUP_INFOA back; memset(&back, 0, sizeof back); len = sizeof back;
    CHECK(UN(GetUrlCacheGroupAttributeA)(g, 0, CACHEGROUP_ATTRIBUTE_GET_ALL, &back, &len, NULL));
    EXPECT_STR(back.szGroupName, name);
    /* [D GetUrlCacheGroupAttributeA@0x1a1080] dwGroupSize is never written; *len is set to 156 */
    EXPECT_EQ(back.dwGroupSize, 0);
    EXPECT_EQ(len, sizeof back);
    EXPECT_EQ(back.dwOwnerStorage[0], 0x11);
    EXPECT_EQ(back.dwOwnerStorage[3], 0x44);
    CHECK(U(DeleteUrlCacheGroup)(g, CACHEGROUP_FLAG_FLUSHURL_ONDELETE, NULL));
}

/* ================================================================== cache header counters
 * [D IncrementUrlCacheHeaderData@0x20960] index >= 32 -> FALSE, 87 (valid indexes change a per-user counter:
 * not called). [D GetUrlCacheHeaderData@0x295a0] index >= 32 or NULL out -> 87. */
TEST(gs_increment_header_data_bad_index) {
    REQUIRE(UN(IncrementUrlCacheHeaderData));
    static const DWORD idx[] = { 32, 33, 64, 0x100, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof idx / sizeof idx[0]; i++) {
        DWORD v = 0xA5A5;
        SET_ERR(0);
        CHECKF(!UN(IncrementUrlCacheHeaderData)(idx[i], &v), "index %lu", idx[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        EXPECT_EQ(v, 0xA5A5);
        SET_ERR(0);
        CHECK(!UN(IncrementUrlCacheHeaderData)(idx[i], NULL));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(gs_get_header_data_bad_args) {
    REQUIRE(UN(GetUrlCacheHeaderData));
    DWORD v = 0xA5A5;
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(32, &v));          EXPECT_ERR(ERROR_INVALID_PARAMETER); EXPECT_EQ(v, 0xA5A5);
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(0xFFFFFFFFu, &v)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(0, NULL));         EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(GetUrlCacheHeaderData)(31, NULL));        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    for (DWORD i = 0; i < 32; i++) {
        v = 0xA5A5;
        SET_ERR(0x4242);
        CHECKF(UN(GetUrlCacheHeaderData)(i, &v), "index %lu e=%lu", i, GetLastError());
        EXPECT_ERR(0);
    }
}
