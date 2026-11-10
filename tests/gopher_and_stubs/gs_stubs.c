/* Retired features compiled down to constant behaviour (named stubs and ordinal-only exports).
 * Each comment cites the decomp; "GLE unchanged" means the body never calls SetLastError, which the tests
 * prove by seeding several values first.
 * VM_TIMEOUT: 120 */
#include "gs.h"

/* ------------------------------------------------------------------ cert UI stubs
 * [D ParseX509EncodedCertificateForListBoxEntry@0x1847f0 = ShowCertificate = ShowClientAuthCerts]
 *   SetLastError(120); return 120;   (DWORD, not BOOL) */
TEST(gs_show_certificate_stub) {
    REQUIRE(UN(ShowCertificate));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(UN(ShowCertificate)(NULL, NULL), ERROR_CALL_NOT_IMPLEMENTED);
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    }
    BYTE junk[64]; gs_fill(junk, sizeof junk);
    SET_ERR(0);
    EXPECT_EQ(UN(ShowCertificate)(GetDesktopWindow(), junk), ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    CHECK(gs_untouched(junk, sizeof junk));
}

TEST(gs_show_client_auth_certs_stub) {
    REQUIRE(UN(ShowClientAuthCerts));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(UN(ShowClientAuthCerts)(NULL), ERROR_CALL_NOT_IMPLEMENTED);
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    }
    SET_ERR(0);
    EXPECT_EQ(UN(ShowClientAuthCerts)(GetDesktopWindow()), ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
}

TEST(gs_parse_x509_listbox_stub) {
    REQUIRE(UN(ParseX509EncodedCertificateForListBoxEntry));
    BYTE cert[32]; char out[128]; DWORD len;
    static const DWORD lens[] = { 0, 1, 128, 0xFFFFFFFFu };
    for (size_t i = 0; i < 4; i++) {
        for (int nulls = 0; nulls < 4; nulls++) {
            gs_fill(cert, sizeof cert); gs_fill(out, sizeof out);
            len = lens[i];
            SET_ERR(0x4242);
            DWORD r = UN(ParseX509EncodedCertificateForListBoxEntry)(nulls & 1 ? NULL : cert, sizeof cert,
                                                                       nulls & 2 ? NULL : out, &len);
            CHECKF(r == ERROR_CALL_NOT_IMPLEMENTED, "len=%lu nulls=%d r=%lu", lens[i], nulls, r);
            EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            EXPECT_EQ(len, lens[i]);
            CHECK(gs_untouched(out, sizeof out));
            CHECK(gs_untouched(cert, sizeof cert));
        }
    }
    SET_ERR(0);
    EXPECT_EQ(UN(ParseX509EncodedCertificateForListBoxEntry)(NULL, 0, NULL, NULL), ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
}

/* ------------------------------------------------------------------ cache housekeeping stubs */
/* [D DeleteIE3Cache@0x1a7320] return 120; no SetLastError. rundll32-style signature. */
TEST(gs_delete_ie3_cache_stub) {
    REQUIRE(UN(DeleteIE3Cache));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(UN(DeleteIE3Cache)(NULL, NULL, NULL, 0), ERROR_CALL_NOT_IMPLEMENTED);
        EXPECT_ERR(gs_seeds[s]);
    }
    char cmd[] = "";
    SET_ERR(0x77);
    EXPECT_EQ(UN(DeleteIE3Cache)(NULL, GetModuleHandleA(NULL), cmd, SW_HIDE), ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_ERR(0x77);
}

/* [D RunOnceUrlCache@0xdabf0 = DllInstall = InternetGetCertByURL(A)] xor eax,eax; ret */
TEST(gs_run_once_url_cache_stub) {
    REQUIRE(UN(RunOnceUrlCache));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(UN(RunOnceUrlCache)(NULL, NULL, NULL, 0), 0);
        EXPECT_ERR(gs_seeds[s]);
    }
    char cmd[] = "x";
    SET_ERR(5);
    EXPECT_EQ(UN(RunOnceUrlCache)(NULL, GetModuleHandleA(NULL), cmd, SW_SHOWNORMAL), 0);
    EXPECT_ERR(5);
}

TEST(gs_get_cert_by_url_stub) {
    REQUIRE(UN(InternetGetCertByURL)); REQUIRE(UN(InternetGetCertByURLA));
    char url[] = "https://127.0.0.1/";
    char buf[64];
    static const DWORD sizes[] = { 0, 1, 64 };
    for (size_t i = 0; i < 3; i++)
        for (size_t s = 0; s < GS_NSEEDS; s++) {
            gs_fill(buf, sizeof buf);
            SET_ERR(gs_seeds[s]);
            CHECK(!UN(InternetGetCertByURL)(url, buf, sizes[i]));
            EXPECT_ERR(gs_seeds[s]);
            CHECK(gs_untouched(buf, sizeof buf));
            SET_ERR(gs_seeds[s]);
            CHECK(!UN(InternetGetCertByURLA)(i ? url : NULL, i ? buf : NULL, sizes[i]));
            EXPECT_ERR(gs_seeds[s]);
            CHECK(gs_untouched(buf, sizeof buf));
        }
}

/* DllInstall is the same folded "return 0" body: S_OK, nothing registered. */
TEST(gs_dll_install_stub) {
    REQUIRE(UN(DllInstall));
    static const PCWSTR cmds[] = { NULL, L"", L"i", L"u", L"anything" };
    for (int inst = 0; inst < 2; inst++)
        for (size_t i = 0; i < sizeof cmds / sizeof cmds[0]; i++) {
            SET_ERR(0x4242);
            EXPECT_EQ(UN(DllInstall)(inst, cmds[i]), S_OK);
            EXPECT_ERR(0x4242);
        }
}

/* [D IsDuoStream@0xdb0e0 = RegisterUrlCacheNotification = UrlCacheServer = #112] return 1 */
TEST(gs_url_cache_server_stub) {
    REQUIRE(UN(UrlCacheServer));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(UN(UrlCacheServer)(), 1);
        EXPECT_ERR(gs_seeds[s]);
    }
}

TEST(gs_register_url_cache_notification_stub) {
    REQUIRE(UN(RegisterUrlCacheNotification));
    static const UINT msgs[] = { 0, WM_USER, 0xFFFFFFFFu };
    for (size_t m = 0; m < 3; m++) {
        SET_ERR(0x99);
        EXPECT_EQ(UN(RegisterUrlCacheNotification)(NULL, msgs[m], 0, 0, 0), 1);
        EXPECT_ERR(0x99);
        EXPECT_EQ(UN(RegisterUrlCacheNotification)(GetDesktopWindow(), msgs[m], (GROUPID)-1, 0xFFFFFFFFu, 1), 1);
        EXPECT_ERR(0x99);
    }
}

TEST(gs_ord112_is_duo_stream) {
    REQUIRE_ORD(112);
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(GS_ORD(gs_IsDuoStream, 112)(), 1);
        EXPECT_ERR(gs_seeds[s]);
    }
}

/* [D DispatchAPICall@0xdac00] a bare `ret`: nothing to assert except that it returns. */
TEST(gs_dispatch_api_call_returns) {
    REQUIRE(UN(DispatchAPICall));
    SET_ERR(0x31337);
    UN(DispatchAPICall)();
    UN(DispatchAPICall)();
    EXPECT_ERR(0x31337);
}

/* ------------------------------------------------------------------ Fortezza
 * [D InternetFortezzaCommand@0x14a060, InternetQueryFortezzaStatus@0x14a0d0] SetLastError(120); return FALSE */
TEST(gs_fortezza_command_table) {
    REQUIRE(UN(InternetFortezzaCommand));
    static const DWORD cmds[] = { 0, 1, 2, 3, 4, 0x100, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof cmds / sizeof cmds[0]; i++)
        for (size_t s = 0; s < GS_NSEEDS; s++) {
            SET_ERR(gs_seeds[s]);
            CHECKF(!UN(InternetFortezzaCommand)(cmds[i], NULL, 0), "cmd %lu", cmds[i]);
            EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        }
    SET_ERR(0);
    CHECK(!UN(InternetFortezzaCommand)(1, GetDesktopWindow(), (DWORD_PTR)-1));
    EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
}

TEST(gs_fortezza_status_untouched) {
    REQUIRE(UN(InternetQueryFortezzaStatus));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        DWORD st = 0xA5A5A5A5u;
        SET_ERR(gs_seeds[s]);
        CHECK(!UN(InternetQueryFortezzaStatus)(&st, 0));
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        EXPECT_EQ(st, 0xA5A5A5A5u);
        SET_ERR(gs_seeds[s]);
        CHECK(!UN(InternetQueryFortezzaStatus)(NULL, 1));
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    }
}

/* ------------------------------------------------------------------ HttpCheckDavCompliance
 * [D HttpCheckDavCompliance@0x167230 (= #104), HttpCheckDavComplianceW #105 @0x1672f0]
 *   if (out) *out = 0;  GLE = (url && token && out && !reserved) ? 12016 : 87;  return FALSE. */
typedef BOOL (WINAPI *gs_dav_a_pfn)(LPCSTR, LPCSTR, LPBOOL, HWND, LPVOID);
static void gs_dav_table_a(gs_dav_a_pfn f, const char *label) {
    static const char *urls[] = { NULL, "", "http://127.0.0.1:1/dav/" };
    static const char *toks[] = { NULL, "", "1", "2" };
    for (int u = 0; u < 3; u++) for (int t = 0; t < 4; t++) for (int o = 0; o < 2; o++) for (int rs = 0; rs < 2; rs++) {
        BOOL found = 0x5A5A;
        SET_ERR(0);
        BOOL r = f(urls[u], toks[t], o ? &found : NULL, NULL, rs ? (LPVOID)&found : NULL);
        DWORD e = GetLastError();
        DWORD want = (urls[u] && toks[t] && o && !rs) ? ERROR_INTERNET_INVALID_OPERATION : ERROR_INVALID_PARAMETER;
        CHECKF(!r, "%s u=%d t=%d o=%d rs=%d returned TRUE", label, u, t, o, rs);
        CHECKF(e == want, "%s u=%d t=%d o=%d rs=%d: e=%lu want %lu", label, u, t, o, rs, e, want);
        if (o) CHECKF(found == 0, "%s u=%d t=%d rs=%d: *out=0x%x", label, u, t, rs, found);
        else CHECK(found == 0x5A5A || (rs && found == 0));
    }
}
TEST(gs_dav_compliance_named) {
    REQUIRE(UN(HttpCheckDavCompliance));
    gs_dav_table_a((gs_dav_a_pfn)UN(HttpCheckDavCompliance), "HttpCheckDavCompliance");
}
TEST(gs_dav_compliance_ord104) {
    REQUIRE_ORD(104);
    gs_dav_table_a(GS_ORD(gs_DavA, 104), "#104");
    t_note("#104 == HttpCheckDavCompliance address: %s", (FARPROC)UN(HttpCheckDavCompliance) == gs_ord(104) ? "yes" : "no");
}
TEST(gs_dav_compliance_w_ord105) {
    REQUIRE_ORD(105);
    gs_DavW f = GS_ORD(gs_DavW, 105);
    static const WCHAR *urls[] = { NULL, L"", L"http://127.0.0.1:1/dav/" };
    for (int u = 0; u < 3; u++) for (int t = 0; t < 2; t++) for (int o = 0; o < 2; o++) for (int rs = 0; rs < 2; rs++) {
        BOOL found = 0x5A5A;
        SET_ERR(0);
        BOOL r = f(urls[u], t ? L"1" : NULL, o ? &found : NULL, GetDesktopWindow(), rs ? (LPVOID)&found : NULL);
        DWORD e = GetLastError();
        DWORD want = (urls[u] && t && o && !rs) ? ERROR_INTERNET_INVALID_OPERATION : ERROR_INVALID_PARAMETER;
        CHECK(!r);
        CHECKF(e == want, "u=%d t=%d o=%d rs=%d: e=%lu want %lu", u, t, o, rs, e, want);
        if (o) CHECK(found == 0);
    }
    /* no name for the wide variant */
    CHECK(GetProcAddress(t_module("wininet.dll"), "HttpCheckDavComplianceW") == NULL);
}

/* ------------------------------------------------------------------ P3P / cookie retired ordinals */
/* [D GetP3PPolicy@0x13c4f0 = #120..#123] SetLastError(120); return 0xFF */
TEST(gs_ord120_123_get_p3p_policy) {
    for (unsigned o = 120; o <= 123; o++) {
        gs_GetP3PPolicy f = GS_ORD(gs_GetP3PPolicy, o);
        CHECKF(f != NULL, "#%u missing", o);
        if (!f) continue;
        BYTE b[32]; gs_fill(b, sizeof b);
        for (size_t s = 0; s < GS_NSEEDS; s++) {
            SET_ERR(gs_seeds[s]);
            DWORD r = f(NULL, NULL, NULL, NULL);
            CHECKF(r == 0xFF, "#%u returned 0x%lx", o, r);
            EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        }
        SET_ERR(0);
        EXPECT_EQ(f(b, b, b, b), 0xFF);
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        CHECK(gs_untouched(b, sizeof b));
    }
}

/* [D InternalInternetGetCookie #346 @0x1a7410] return ERROR_NO_MORE_ITEMS (0x103); GLE untouched */
TEST(gs_ord346_internal_get_cookie) {
    REQUIRE_ORD(346);
    gs_InternalInternetGetCookie f = GS_ORD(gs_InternalInternetGetCookie, 346);
    char buf[16]; gs_fill(buf, sizeof buf);
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(f(NULL, NULL, NULL), ERROR_NO_MORE_ITEMS);
        EXPECT_ERR(gs_seeds[s]);
    }
    EXPECT_EQ(f("http://127.0.0.1/", buf, buf), ERROR_NO_MORE_ITEMS);
    CHECK(gs_untouched(buf, sizeof buf));
}

/* [D FindP3PPolicySymbol #118 @0x167210] NULL -> -1; only 3- or 4-char strings can match; table of 91 tokens. */
TEST(gs_ord118_find_p3p_symbol_rejects) {
    REQUIRE_ORD(118);
    gs_FindP3PPolicySymbol f = GS_ORD(gs_FindP3PPolicySymbol, 118);
    SET_ERR(0x4242);
    EXPECT_EQ(f(NULL), -1);
    EXPECT_ERR(0x4242);
    static const char *bad[] = { "", "N", "NO", "NOIxx", "NOIaaa", "zzz", "ZZZ", "zzza", "123", "   ", "NOI ", "XXXa" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECKF(f(bad[i]) == -1, "'%s' -> %d", bad[i], f(bad[i]));
}

TEST(gs_ord118_find_p3p_symbol_tokens) {
    REQUIRE_ORD(118);
    gs_FindP3PPolicySymbol f = GS_ORD(gs_FindP3PPolicySymbol, 118);
    /* compact-policy tokens (P3P 1.0 section 4): every one is in the table */
    static const char *tok[] = { "NOI", "ALL", "CAO", "IDC", "OTI", "NON", "DSP", "COR", "MON", "LAW", "NID",
                                 "CUR", "ADM", "DEV", "TAI", "PSA", "PSD", "IVA", "IVD", "CON", "HIS", "TEL",
                                 "OTP", "OUR", "DEL", "SAM", "UNR", "PUB", "OTR", "NOR", "STP", "LEG", "BUS",
                                 "IND", "PHY", "ONL", "UNI", "PUR", "FIN", "COM", "NAV", "INT", "DEM", "CNT",
                                 "STA", "POL", "HEA", "PRE", "LOC", "GOV", "OTC", "TST" };
    int seen[128]; memset(seen, 0, sizeof seen);
    char line[1024]; size_t pos = 0;
    for (size_t i = 0; i < sizeof tok / sizeof tok[0]; i++) {
        int r = f(tok[i]);
        CHECKF(r >= 0 && r < 91, "%s -> %d", tok[i], r);
        if (r >= 0 && r < 128) { CHECKF(!seen[r], "%s shares index %d", tok[i], r); seen[r] = 1; }
        pos += snprintf(line + pos, sizeof line - pos, "%s=%d ", tok[i], r);
        if (pos > sizeof line - 16) { t_note("p3p: %s", line); pos = 0; }
    }
    if (pos) t_note("p3p: %s", line);
    /* the matcher is case-sensitive (exact byte compare) */
    EXPECT_EQ(f("noi"), -1);
    EXPECT_EQ(f("Noi"), -1);
}

TEST(gs_ord118_find_p3p_symbol_suffix) {
    REQUIRE_ORD(118);
    gs_FindP3PPolicySymbol f = GS_ORD(gs_FindP3PPolicySymbol, 118);
    /* tokens with an a/i/o qualifier: the bare form matches the 'a' (always) entry */
    static const char *base[] = { "CUR", "ADM", "DEV", "TAI", "PSA", "PSD", "IVA", "IVD", "CON", "HIS", "TEL", "OTP" };
    for (size_t i = 0; i < sizeof base / sizeof base[0]; i++) {
        char a[5], ii[5], o[5];
        snprintf(a, 5, "%sa", base[i]); snprintf(ii, 5, "%si", base[i]); snprintf(o, 5, "%so", base[i]);
        int rb = f(base[i]), ra = f(a), ri = f(ii), ro = f(o);
        t_note("p3p %s: bare=%d a=%d i=%d o=%d", base[i], rb, ra, ri, ro);
        CHECKF(rb == ra, "%s bare %d vs a %d", base[i], rb, ra);
    }
}

/* ------------------------------------------------------------------ cache-server / jet ordinals */
/* [D GetCacheServerConnection #410] if (p) *p = NULL; return E_FAIL */
TEST(gs_ord410_get_cache_server_connection) {
    REQUIRE_ORD(410);
    gs_GetCacheServerConnection f = GS_ORD(gs_GetCacheServerConnection, 410);
    void *p = (void *)0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(f(&p), E_FAIL);
    EXPECT_EQ(p, NULL);
    EXPECT_EQ(f(NULL), E_FAIL);
    EXPECT_ERR(0x4242);
}

/* [D CreateCacheServerRpcBinding #411] if (out) *out = NULL; return arg1 ? E_FAIL : E_INVALIDARG */
TEST(gs_ord411_create_cache_server_rpc_binding) {
    REQUIRE_ORD(411);
    gs_CreateCacheServerRpcBinding f = GS_ORD(gs_CreateCacheServerRpcBinding, 411);
    void *p = (void *)0x1234; int dummy = 0;
    SET_ERR(0x4242);
    EXPECT_EQ(f(NULL, &p), E_INVALIDARG);  EXPECT_EQ(p, NULL);
    p = (void *)0x1234;
    EXPECT_EQ(f(&dummy, &p), E_FAIL);      EXPECT_EQ(p, NULL);
    EXPECT_EQ(f(NULL, NULL), E_INVALIDARG);
    EXPECT_EQ(f(&dummy, NULL), E_FAIL);
    EXPECT_ERR(0x4242);
}

/* [D SetGlobalJetParameters #413] return E_FAIL */
TEST(gs_ord413_set_global_jet_parameters) {
    REQUIRE_ORD(413);
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        EXPECT_EQ(GS_ORD(gs_SetGlobalJetParameters, 413)(), E_FAIL);
        EXPECT_ERR(gs_seeds[s]);
    }
}

/* [D ReadGuidsForConnectedNetworks #401] return 0 (WPP only); arguments never read */
TEST(gs_ord401_read_guids_for_connected_networks) {
    REQUIRE_ORD(401);
    gs_ReadGuidsForConnectedNetworks f = GS_ORD(gs_ReadGuidsForConnectedNetworks, 401);
    BYTE b[64]; gs_fill(b, sizeof b);
    SET_ERR(0x4242);
    EXPECT_EQ(f(NULL, NULL, NULL, NULL, NULL, NULL), 0);
    EXPECT_EQ(f(b, b, b, b, b, b), 0);
    EXPECT_ERR(0x4242);
    CHECK(gs_untouched(b, sizeof b));
}

/* [D InternetAutoProxyGetProxyForUrl #402] if (arg2) memset(arg2, 0, 0x28); return 0 */
TEST(gs_ord402_autoproxy_get_proxy_for_url) {
    REQUIRE_ORD(402);
    gs_AutoProxyGetProxyForUrl f = GS_ORD(gs_AutoProxyGetProxyForUrl, 402);
    BYTE b[0x40]; gs_fill(b, sizeof b);
    SET_ERR(0x4242);
    EXPECT_EQ(f((void *)L"http://127.0.0.1/", b), 0);
    CHECK(gs_all_zero(b, 0x28));
    CHECK(gs_untouched(b + 0x28, sizeof b - 0x28));
    EXPECT_EQ(f(NULL, NULL), 0);
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------------ GetDiskInfoA (#102)
 * [D GetDiskInfoA@0x1a7330] path NULL, shorter than 2 chars or not NUL-terminated within 260 -> FALSE, 87.
 * Otherwise GetDiskFreeSpaceExA(path, free, total, NULL); on success *pdw = 1 when pdw != NULL. */
TEST(gs_ord102_get_disk_info_args) {
    REQUIRE_ORD(102);
    gs_GetDiskInfoA f = GS_ORD(gs_GetDiskInfoA, 102);
    ULARGE_INTEGER fr, to; DWORD one = 0;
    static const char *bad[] = { NULL, "", "C" };
    for (size_t i = 0; i < 3; i++) {
        SET_ERR(0);
        CHECKF(!f(bad[i], &one, &fr, &to), "bad[%zu]", i);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    char longp[300]; memset(longp, 'a', sizeof longp - 1); longp[sizeof longp - 1] = 0;
    longp[0] = 'C'; longp[1] = ':'; longp[2] = '\\';
    SET_ERR(0);
    CHECK(!f(longp, &one, &fr, &to));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(gs_ord102_get_disk_info_tempdir) {
    REQUIRE_ORD(102);
    gs_GetDiskInfoA f = GS_ORD(gs_GetDiskInfoA, 102);
    const char *dir = t_tmpdir();
    ULARGE_INTEGER fr = { 0 }, to = { 0 }, fr2, to2;
    DWORD one = 0xA5A5;
    SET_ERR(0);
    BOOL r = f(dir, &one, &fr, &to);
    CHECKF(r, "e=%lu", GetLastError());
    if (!r) return;
    EXPECT_EQ(one, 1);
    CHECK(to.QuadPart > 0);
    CHECK(fr.QuadPart <= to.QuadPart);
    CHECK(GetDiskFreeSpaceExA(dir, &fr2, &to2, NULL));
    EXPECT_EQ(to.QuadPart, to2.QuadPart);
    /* NULL cluster-out is allowed */
    CHECK(f(dir, NULL, &fr, &to));
    /* the drive root works as well */
    char root[4] = { dir[0], ':', '\\', 0 };
    one = 0;
    CHECK(f(root, &one, &fr, &to));
    EXPECT_EQ(one, 1);
}

TEST(gs_ord102_get_disk_info_missing_dir) {
    REQUIRE_ORD(102);
    gs_GetDiskInfoA f = GS_ORD(gs_GetDiskInfoA, 102);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "no_such_dir\\deeper\\");
    ULARGE_INTEGER fr, to; DWORD one = 0xA5A5;
    SET_ERR(0);
    BOOL r = f(p, &one, &fr, &to);
    DWORD e = GetLastError();
    CHECK(!r);
    EXPECT_EQ(one, 0xA5A5);
    /* the error is whatever GetDiskFreeSpaceExA reported */
    ULARGE_INTEGER a, b;
    SET_ERR(0);
    CHECK(!GetDiskFreeSpaceExA(p, &a, &b, NULL));
    EXPECT_EQ(e, GetLastError());
}

/* ------------------------------------------------------------------ cookie file import/export ordinals
 * [D ImportCookieFileA #108] NULL path -> 0 (no SetLastError); else MultiByteToWideChar and #110.
 * [D ImportCookieFileW #110] ReadFileToBufferW fails or file empty -> 0 (nothing imported). */
TEST(gs_ord108_110_import_cookie_file_negative) {
    REQUIRE_ORD(108); REQUIRE_ORD(110);
    gs_ImportCookieFileA fa = GS_ORD(gs_ImportCookieFileA, 108);
    gs_ImportCookieFileW fw = GS_ORD(gs_ImportCookieFileW, 110);
    SET_ERR(0x4242);
    CHECK(!fa(NULL));
    EXPECT_ERR(0x4242);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "gs_nocookies.txt");
    DeleteFileA(p);
    CHECK(!fa(p));
    WCHAR pw[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, p, -1, pw, MAX_PATH);
    CHECK(!fw(pw));
    /* an empty file imports nothing and fails */
    HANDLE h = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    CHECK(!fa(p));
    CHECK(!fw(pw));
    DeleteFileA(p);
}

TEST(gs_ord109_export_cookie_file_null) {
    REQUIRE_ORD(109); REQUIRE_ORD(111);
    gs_ExportCookieFileA fa = GS_ORD(gs_ExportCookieFileA, 109);
    SET_ERR(0x4242);
    CHECK(!fa(NULL, FALSE));
    CHECK(!fa(NULL, TRUE));
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------------ IsDomainLegalCookieDomain (#116/#117)
 * [D IsDomainLegalCookieDomainA@0x1ea30] NULL either -> FALSE, 87. Otherwise reversed-domain legality. */
TEST(gs_ord116_117_domain_legal_null) {
    REQUIRE_ORD(116); REQUIRE_ORD(117);
    gs_IdlA fa = GS_ORD(gs_IdlA, 116);
    SET_ERR(0);
    CHECK(!fa(NULL, "example.com")); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!fa("example.com", NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!fa(NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(gs_ord116_117_domain_legal_table) {
    REQUIRE_ORD(116); REQUIRE_ORD(117);
    gs_IdlA fa = GS_ORD(gs_IdlA, 116);
    gs_IdlW fw = GS_ORD(gs_IdlW, 117);
    static const struct { const char *dom, *host; int want; } t[] = {
        { "example.com", "www.example.com", 1 },
        { "example.com", "example.com", 1 },
        { "www.example.com", "www.example.com", 1 },
        { "other.com", "www.example.com", 0 },
        { "ample.com", "www.example.com", 0 },
        { "a.b.example.com", "www.example.com", 0 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        BOOL ra = fa(t[i].dom, t[i].host);
        WCHAR dw[64], hw[64];
        MultiByteToWideChar(CP_ACP, 0, t[i].dom, -1, dw, 64);
        MultiByteToWideChar(CP_ACP, 0, t[i].host, -1, hw, 64);
        BOOL rw = fw(dw, hw);
        CHECKF(!!ra == t[i].want, "A(%s, %s) = %d", t[i].dom, t[i].host, ra);
        CHECKF(!!rw == !!ra, "W(%s, %s) = %d vs A %d", t[i].dom, t[i].host, rw, ra);
    }
}

/* ------------------------------------------------------------------ COM entry points (no registration) */
TEST(gs_dll_get_class_object_unknown_clsid) {
    REQUIRE(UN(DllGetClassObject));
    static const GUID bogus = { 0x1f7a0c3e, 0x5a2b, 0x4c1d, { 0x9e, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab } };
    static const GUID iid_unknown = { 0x00000000, 0x0000, 0x0000, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    static const GUID iid_cf = { 0x00000001, 0x0000, 0x0000, { 0xC0, 0, 0, 0, 0, 0, 0, 0x46 } };
    void *pv = (void *)0x1234;
    HRESULT hr = UN(DllGetClassObject)(&bogus, &iid_cf, &pv);
    EXPECT_EQ(hr, CLASS_E_CLASSNOTAVAILABLE);
    CHECKF(pv == NULL || pv == (void *)0x1234, "pv=%p", pv);
    t_note("DllGetClassObject bogus clsid: pv %s", pv == NULL ? "cleared" : "untouched");
    pv = (void *)0x1234;
    EXPECT_EQ(UN(DllGetClassObject)(&bogus, &iid_unknown, &pv), CLASS_E_CLASSNOTAVAILABLE);
}

TEST(gs_dll_can_unload_now) {
    REQUIRE(UN(DllCanUnloadNow));
    HRESULT hr = UN(DllCanUnloadNow)();
    CHECKF(hr == S_OK || hr == S_FALSE, "hr=0x%lx", hr);
    t_note("DllCanUnloadNow = 0x%lx", hr);
}

TEST(gs_dll_register_exports_resolve_only) {
    /* registering is system-wide: resolve-only */
    CHECK(t_proc_in("wininet.dll", "DllRegisterServer") != NULL);
    CHECK(t_proc_in("wininet.dll", "DllUnregisterServer") != NULL);
}

/* [D GetProxyDllInfo@0x132630] *a = &aProxyFileList; *b = &CLSID_PSFactoryBuffer (both inside wininet) */
TEST(gs_get_proxy_dll_info) {
    REQUIRE(UN(GetProxyDllInfo));
    void *a = NULL, *b = NULL;
    SET_ERR(0x4242);
    UN(GetProxyDllInfo)(&a, &b);
    EXPECT_ERR(0x4242);
    CHECK(a != NULL); CHECK(b != NULL);
    ULONG_PTR lo, hi;
    if (gs_module_range(t_module("wininet.dll"), &lo, &hi)) {
        CHECK((ULONG_PTR)a >= lo && (ULONG_PTR)a < hi);
        CHECK((ULONG_PTR)b >= lo && (ULONG_PTR)b < hi);
    }
    void *a2 = NULL, *b2 = NULL;
    UN(GetProxyDllInfo)(&a2, &b2);
    EXPECT_EQ(a, a2); EXPECT_EQ(b, b2);
    if (b) {
        const GUID *g = (const GUID *)b;
        t_note("proxy CLSID {%08lX-%04X-%04X-...}", g->Data1, g->Data2, g->Data3);
    }
}

/* [D InternetFreeProxyInfoList@0x166170] NULL ok; zeroes the 16-byte list header even when empty */
TEST(gs_free_proxy_info_list_empty) {
    REQUIRE(UN(InternetFreeProxyInfoList));
    UN(InternetFreeProxyInfoList)(NULL);
    struct { DWORD count; DWORD pad; void *list; BYTE tail[16]; } l;
    gs_fill(&l, sizeof l);
    l.count = 0; l.pad = 0x77; l.list = NULL;
    SET_ERR(0x4242);
    UN(InternetFreeProxyInfoList)(&l);
    EXPECT_ERR(0x4242);
    CHECK(gs_all_zero(&l, 16));
    CHECK(gs_untouched(l.tail, sizeof l.tail));
}

/* [D InternetSetSecureLegacyServersAppCompat] flips a process global (if a feature flag is on); void.
 * Resolve-only: calling it would change TLS behaviour for every later test in the process. */
TEST(gs_secure_legacy_servers_appcompat_resolves) {
    CHECK(t_proc_in("wininet.dll", "InternetSetSecureLegacyServersAppCompat") != NULL);
}

/* Passport nexus: network lookups, never called. */
TEST(gs_force_nexus_lookup_resolve_only) {
    CHECK(t_proc_in("wininet.dll", "ForceNexusLookup") != NULL);
    CHECK(t_proc_in("wininet.dll", "ForceNexusLookupExW") != NULL);
    CHECK(GetProcAddress(t_module("wininet.dll"), "ForceNexusLookupExA") == NULL);
    CHECK(GetProcAddress(t_module("wininet.dll"), "ForceNexusLookupEx") == NULL);
}
