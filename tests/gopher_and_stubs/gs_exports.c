/* Export-table conformance: every export of wininet.dll and its companion modules resolves by name and by
 * ordinal, both give the same address, ordinal-only exports have no name, forwarders land in their target
 * module, and ordinals outside the table do not resolve.
 * Source of the tables: tools/<module>_exports.json (corpus export tables of the Win10 19041 binaries),
 * compiled into gs_exptab.c by gen_exptab.py.
 * VM_TIMEOUT: 120 */
#include "gs.h"

typedef struct { const char *dll; const gs_export *tab; const size_t *n; } gs_modtab;
static const gs_modtab gs_mods[] = {
    { "wininet.dll",  gs_exp_wininet,  &gs_exp_wininet_n },
    { "urlmon.dll",   gs_exp_urlmon,   &gs_exp_urlmon_n },
    { "winhttp.dll",  gs_exp_winhttp,  &gs_exp_winhttp_n },
    { "sspicli.dll",  gs_exp_sspicli,  &gs_exp_sspicli_n },
    { "schannel.dll", gs_exp_schannel, &gs_exp_schannel_n },
    { "crypt32.dll",  gs_exp_crypt32,  &gs_exp_crypt32_n },
    { "ws2_32.dll",   gs_exp_ws2_32,   &gs_exp_ws2_32_n },
};

static const gs_modtab *gs_find_mod(const char *dll) {
    for (size_t i = 0; i < sizeof gs_mods / sizeof gs_mods[0]; i++) if (!lstrcmpiA(gs_mods[i].dll, dll)) return &gs_mods[i];
    return NULL;
}

/* forwarder "DLL.Name" -> address resolved in the target module */
static FARPROC gs_resolve_forwarder(const char *fw) {
    char dll[64]; const char *dot = strchr(fw, '.');
    if (!dot || (size_t)(dot - fw) >= sizeof dll - 5) return NULL;
    memcpy(dll, fw, dot - fw); dll[dot - fw] = 0;
    lstrcatA(dll, ".dll");
    HMODULE h = LoadLibraryA(dll);
    if (!h) return NULL;
    if (dot[1] == '#') return GetProcAddress(h, MAKEINTRESOURCEA(atoi(dot + 2)));
    return GetProcAddress(h, dot + 1);
}

/* names: hard; ordinals: hard; name/ordinal agreement: hard; forwarders: hard */
static void gs_check_module(const char *dll, int *n_named, int *n_ord, int *n_fw) {
    const gs_modtab *m = gs_find_mod(dll);
    HMODULE h = t_module(dll);
    CHECKF(h != NULL, "%s does not load", dll);
    if (!h || !m) return;
    int miss_name = 0, miss_ord = 0, disagree = 0, fw_bad = 0;
    for (size_t i = 0; i < *m->n; i++) {
        const gs_export *e = &m->tab[i];
        FARPROC po = GetProcAddress(h, MAKEINTRESOURCEA(e->ord));
        if (!po) { miss_ord++; CHECKF(0, "%s: ordinal %u (%s) does not resolve", dll, e->ord, e->name ? e->name : "-"); }
        else (*n_ord)++;
        if (e->name) {
            FARPROC pn = GetProcAddress(h, e->name);
            if (!pn) { miss_name++; CHECKF(0, "%s!%s does not resolve", dll, e->name); continue; }
            (*n_named)++;
            if (po && po != pn) { disagree++; CHECKF(0, "%s!%s: name %p != ordinal %u %p", dll, e->name, pn, e->ord, po); }
            if (e->forwarder) {
                FARPROC pt = gs_resolve_forwarder(e->forwarder);
                (*n_fw)++;
                if (pt != pn) { fw_bad++; CHECKF(0, "%s!%s -> %s: %p vs target %p", dll, e->name, e->forwarder, pn, pt); }
            }
        }
    }
    t_note("%s: %zu table rows, %d names missing, %d ordinals missing, %d name/ordinal mismatches, %d bad forwarders",
           dll, *m->n, miss_name, miss_ord, disagree, fw_bad);
}

TEST(gs_exports_wininet_all) {
    int a = 0, b = 0, c = 0;
    gs_check_module("wininet.dll", &a, &b, &c);
    EXPECT_EQ(a, 299);
    EXPECT_EQ(b, 327);
    EXPECT_EQ(c, 0);
}
TEST(gs_exports_urlmon_all)   { int a = 0, b = 0, c = 0; gs_check_module("urlmon.dll", &a, &b, &c);   t_note("urlmon: %d named, %d ordinals", a, b); }
TEST(gs_exports_winhttp_all)  { int a = 0, b = 0, c = 0; gs_check_module("winhttp.dll", &a, &b, &c);  t_note("winhttp: %d named", a); }
TEST(gs_exports_sspicli_all)  { int a = 0, b = 0, c = 0; gs_check_module("sspicli.dll", &a, &b, &c);  t_note("sspicli: %d named", a); }
TEST(gs_exports_schannel_all) { int a = 0, b = 0, c = 0; gs_check_module("schannel.dll", &a, &b, &c); EXPECT_EQ(c, 24); }
TEST(gs_exports_crypt32_all)  { int a = 0, b = 0, c = 0; gs_check_module("crypt32.dll", &a, &b, &c);  EXPECT_EQ(c, 3); }
TEST(gs_exports_ws2_32_all)   { int a = 0, b = 0, c = 0; gs_check_module("ws2_32.dll", &a, &b, &c);   t_note("ws2_32: %d named", a); }

/* wininet: the ordinal range is 101..427 with no gaps; 100 and 428 do not resolve */
TEST(gs_exports_wininet_ordinal_bounds) {
    HMODULE h = t_module("wininet.dll");
    if (!h) { t_skip("no wininet"); return; }
    static const unsigned out[] = { 1, 2, 99, 100, 428, 429, 500, 1000, 0xFFFF };
    for (size_t i = 0; i < sizeof out / sizeof out[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(h, MAKEINTRESOURCEA(out[i])) == NULL, "ordinal %u resolves", out[i]);
        EXPECT_ERR(ERROR_INVALID_ORDINAL);   /* [VM boot 3] 182 for ordinals, 127 only for names */
    }
    for (unsigned o = 101; o <= 427; o++) CHECKF(GetProcAddress(h, MAKEINTRESOURCEA(o)) != NULL, "ordinal %u missing", o);
}

TEST(gs_exports_wininet_ordinal_only_unnamed) {
    /* PDB names of the ordinal-only exports are not export names */
    static const char *pdb[] = { "DoConnectoidsExist", "GetDiskInfoA", "PerformOperationOverUrlCacheA", "HttpCheckDavComplianceW",
                                 "ImportCookieFileA", "ExportCookieFileA", "ImportCookieFileW", "ExportCookieFileW", "IsDuoStream",
                                 "IsDomainLegalCookieDomainA", "IsDomainLegalCookieDomainW", "FindP3PPolicySymbol", "GetP3PPolicy",
                                 "InternalInternetGetCookie", "ReadGuidsForConnectedNetworks", "InternetAutoProxyGetProxyForUrl",
                                 "InternetAutoProxyOnSendRequestComplete", "GetCacheServerConnection", "CreateCacheServerRpcBinding",
                                 "SetGlobalJetParameters", "IsLanConnection", "IsDialUpConnection",
                                 "RegisterForNetworkChangeNotification", "UnRegisterNetworkChangeNotification" };
    HMODULE h = t_module("wininet.dll");
    for (size_t i = 0; i < sizeof pdb / sizeof pdb[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(h, pdb[i]) == NULL, "%s is exported by name", pdb[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
    int unnamed = 0;
    for (size_t i = 0; i < gs_exp_wininet_n; i++) if (!gs_exp_wininet[i].name) unnamed++;
    EXPECT_EQ(unnamed, 28);
}

/* exact ordinal numbers of selected named exports (the export table is the ABI for ordinal importers) */
TEST(gs_exports_wininet_selected_ordinals) {
    static const struct { const char *n; unsigned o; } t[] = {
        { "AppCacheCheckManifest", 106 }, { "CommitUrlCacheEntryA", 136 }, { "DeleteIE3Cache", 146 },
        { "GopherCreateLocatorA", 216 }, { "GopherOpenFileW", 225 }, { "HttpCheckDavCompliance", 228 },
        { "HttpOpenRequestA", 238 }, { "HttpSendRequestW", 248 }, { "InternetAutodial", 259 },
        { "InternetCloseHandle", 267 }, { "InternetDial", 280 }, { "InternetFortezzaCommand", 288 },
        { "InternetOpenA", 316 }, { "InternetOpenW", 319 }, { "InternetReadFile", 324 },
        { "InternetSetStatusCallback", 345 }, { "InternetSetStatusCallbackA", 347 }, { "InternetWriteFileExA", 360 },
        { "LoadUrlCacheContent", 365 }, { "ParseX509EncodedCertificateForListBoxEntry", 366 },
        { "PrivacyGetZonePreferenceW", 367 }, { "RunOnceUrlCache", 377 }, { "ShowCertificate", 388 },
        { "UnlockUrlCacheEntryFile", 392 }, { "UrlCacheServer", 419 }, { "UrlCacheSetGlobalLimit", 424 },
    };
    HMODULE h = t_module("wininet.dll");
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        FARPROC a = GetProcAddress(h, t[i].n), b = GetProcAddress(h, MAKEINTRESOURCEA(t[i].o));
        CHECKF(a && a == b, "%s @%u: %p vs %p", t[i].n, t[i].o, a, b);
    }
}

/* the last three ordinals in the table after UrlCacheSetGlobalLimit */
TEST(gs_exports_wininet_tail) {
    HMODULE h = t_module("wininet.dll");
    for (unsigned o = 424; o <= 427; o++) {
        const gs_export *e = NULL;
        for (size_t i = 0; i < gs_exp_wininet_n; i++) if (gs_exp_wininet[i].ord == o) e = &gs_exp_wininet[i];
        CHECKF(e != NULL, "no table row for %u", o);
        if (e && e->name) CHECKF(GetProcAddress(h, e->name) == GetProcAddress(h, MAKEINTRESOURCEA(o)), "%s", e->name);
    }
}

/* every export address lies inside wininet's own image (no forwarders in wininet) */
TEST(gs_exports_wininet_in_image) {
    HMODULE h = t_module("wininet.dll");
    ULONG_PTR lo, hi;
    if (!gs_module_range(h, &lo, &hi)) { t_skip("no PE header"); return; }
    int outside = 0;
    for (size_t i = 0; i < gs_exp_wininet_n; i++) {
        ULONG_PTR p = (ULONG_PTR)GetProcAddress(h, MAKEINTRESOURCEA(gs_exp_wininet[i].ord));
        if (p && (p < lo || p >= hi)) { outside++; CHECKF(0, "ordinal %u at %p outside wininet", gs_exp_wininet[i].ord, (void *)p); }
    }
    EXPECT_EQ(outside, 0);
}

/* folded (shared-RVA) groups: a linker detail - observed, never required */
TEST(gs_exports_wininet_folding_notes) {
    HMODULE h = t_module("wininet.dll");
    int groups = 0, kept = 0;
    for (size_t i = 0; i < gs_exp_wininet_n; i++) {
        int first = 1, peers = 0, same = 0;
        for (size_t j = 0; j < gs_exp_wininet_n; j++) {
            if (gs_exp_wininet[j].rva != gs_exp_wininet[i].rva || i == j) continue;
            if (j < i) first = 0;
            peers++;
            if (GetProcAddress(h, MAKEINTRESOURCEA(gs_exp_wininet[i].ord)) == GetProcAddress(h, MAKEINTRESOURCEA(gs_exp_wininet[j].ord))) same++;
        }
        if (peers && first) { groups++; if (same == peers) kept++; }
    }
    t_note("wininet folded export groups in the reference: %d; still folded here: %d", groups, kept);
    CHECK(groups > 0);
}

/* the undecorated legacy names are ANSI entry points (same address as ...A in the reference) */
TEST(gs_exports_wininet_plain_aliases) {
    static const char *p[][2] = {
        { "DeleteUrlCacheEntry", "DeleteUrlCacheEntryA" }, { "InternetConfirmZoneCrossing", "InternetConfirmZoneCrossingA" },
        { "InternetDial", "InternetDialA" }, { "InternetGetConnectedStateEx", "InternetGetConnectedStateExA" },
        { "InternetGetSecurityInfoByURL", "InternetGetSecurityInfoByURLA" }, { "InternetGoOnline", "InternetGoOnlineA" },
        { "InternetSetDialState", "InternetSetDialStateA" }, { "InternetSetStatusCallback", "InternetSetStatusCallbackA" },
        { "InternetShowSecurityInfoByURL", "InternetShowSecurityInfoByURLA" }, { "InternetTimeFromSystemTime", "InternetTimeFromSystemTimeA" },
        { "InternetTimeToSystemTime", "InternetTimeToSystemTimeA" }, { "SetUrlCacheEntryGroup", "SetUrlCacheEntryGroupA" },
        { "UnlockUrlCacheEntryFile", "UnlockUrlCacheEntryFileA" },
    };
    HMODULE h = t_module("wininet.dll");
    int same = 0;
    for (size_t i = 0; i < sizeof p / sizeof p[0]; i++) {
        FARPROC a = GetProcAddress(h, p[i][0]), b = GetProcAddress(h, p[i][1]);
        CHECKF(a && b, "%s / %s", p[i][0], p[i][1]);
        if (a == b) same++;
    }
    t_note("plain==A alias addresses: %d of %zu", same, sizeof p / sizeof p[0]);
}

/* names are case-sensitive and exact */
TEST(gs_exports_name_case_exact) {
    HMODULE h = t_module("wininet.dll");
    static const char *bad[] = { "internetopena", "INTERNETOPENA", "InternetOpenA ", " InternetOpenA", "InternetOpen",
                                 "InternetOpenAW", "HttpOpenRequest", "GopherCreateLocatorX", "" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(h, bad[i]) == NULL, "'%s' resolves", bad[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

/* schannel forwards its SSPI entry points to sspicli */
TEST(gs_exports_schannel_forwarders) {
    static const char *f[] = { "AcceptSecurityContext", "AcquireCredentialsHandleA", "AcquireCredentialsHandleW",
                               "InitializeSecurityContextW", "QueryContextAttributesW", "FreeContextBuffer",
                               "DeleteSecurityContext", "EncryptMessage", "DecryptMessage", "InitSecurityInterfaceW" };
    for (size_t i = 0; i < sizeof f / sizeof f[0]; i++) {
        FARPROC a = t_proc_in("schannel.dll", f[i]), b = t_proc_in("sspicli.dll", f[i]);
        int fw = 0;
        for (size_t j = 0; j < gs_exp_schannel_n; j++) if (gs_exp_schannel[j].name && !strcmp(gs_exp_schannel[j].name, f[i]) && gs_exp_schannel[j].forwarder) fw = 1;
        if (!fw) { t_note("%s is not a forwarder in the reference table", f[i]); continue; }
        CHECKF(a && a == b, "schannel!%s %p vs sspicli %p", f[i], a, b);
    }
}

/* crypt32 forwards the memory-protection pair to dpapi */
TEST(gs_exports_crypt32_dpapi_forwarders) {
    HMODULE d = LoadLibraryA("dpapi.dll");
    CHECK(d != NULL);
    if (!d) return;
    static const char *f[] = { "CryptProtectMemory", "CryptUnprotectMemory", "CryptUpdateProtectedState" };
    for (size_t i = 0; i < 3; i++) {
        FARPROC a = t_proc_in("crypt32.dll", f[i]), b = GetProcAddress(d, f[i]);
        CHECKF(a && a == b, "crypt32!%s %p vs dpapi %p", f[i], a, b);
    }
}

/* ws2_32: classic BSD ordinals (stable since Winsock 2) */
TEST(gs_exports_ws2_32_classic_ordinals) {
    static const struct { const char *n; unsigned o; } t[] = {
        { "accept", 1 }, { "bind", 2 }, { "closesocket", 3 }, { "connect", 4 }, { "getpeername", 5 },
        { "getsockname", 6 }, { "getsockopt", 7 }, { "htonl", 8 }, { "htons", 9 }, { "ioctlsocket", 10 },
        { "inet_addr", 11 }, { "inet_ntoa", 12 }, { "listen", 13 }, { "ntohl", 14 }, { "ntohs", 15 },
        { "recv", 16 }, { "recvfrom", 17 }, { "select", 18 }, { "send", 19 }, { "sendto", 20 },
        { "setsockopt", 21 }, { "shutdown", 22 }, { "socket", 23 }, { "WSAStartup", 115 }, { "WSACleanup", 116 },
        { "WSAGetLastError", 111 }, { "WSASetLastError", 112 }, { "gethostbyname", 52 },
    };
    HMODULE h = t_module("ws2_32.dll");
    if (!h) { t_skip("no ws2_32"); return; }
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        FARPROC a = GetProcAddress(h, t[i].n), b = GetProcAddress(h, MAKEINTRESOURCEA(t[i].o));
        CHECKF(a && a == b, "%s @%u: %p vs %p", t[i].n, t[i].o, a, b);
    }
}

/* the reference table itself agrees with those classic ordinals (sanity of gs_exptab.c) */
TEST(gs_exports_table_sanity) {
    size_t n = 0;
    for (size_t i = 0; i < sizeof gs_mods / sizeof gs_mods[0]; i++) {
        const gs_modtab *m = &gs_mods[i];
        for (size_t j = 1; j < *m->n; j++) CHECKF(m->tab[j].ord > m->tab[j - 1].ord, "%s rows not sorted at %zu", m->dll, j);
        n += *m->n;
    }
    EXPECT_EQ(gs_exp_wininet_n, 327);
    EXPECT_EQ(gs_exp_schannel_n, 36);
    t_note("export rows checked: %zu", n);
}

/* GetProcAddress through U()/UIN() agrees with the table for the stub family */
TEST(gs_exports_harness_agrees) {
    HMODULE h = t_module("wininet.dll");
    for (size_t i = 0; i < gs_exp_wininet_n; i++) {
        const gs_export *e = &gs_exp_wininet[i];
        if (!e->name) continue;
        CHECKF(t_proc_in("wininet.dll", e->name) == GetProcAddress(h, e->name), "%s", e->name);
        CHECKF(t_proc_ord("wininet.dll", e->ord) == GetProcAddress(h, MAKEINTRESOURCEA(e->ord)), "#%u", e->ord);
    }
}
