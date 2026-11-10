/* proxy_connectivity: RAS / autodial stubs, GetProxyDllInfo, InternetGetConnectedStateEx buffer handling and
 * InternetCheckConnection URL forms.
 * Decomp (wininet 10.0.19041): InternetAutodial@0x13c520, InternetAutodialHangup@0x13c5e0, InternetDial(A)@0x13c690,
 * InternetDialW@0x13c760, InternetHangUp@0x13c9b0, InternetSetDialState(A)@0x13ca50, InternetSetDialStateW@0x13cab0,
 * InternetAutodialCallback@0x133af0, GetProxyDllInfo@0x132630, IsRasEnumEntriesWPresent@0xdf700,
 * InternetGetConnectedStateExW@0xd8340, InternetGetConnectedStateEx(A)@0x286e0, InternetCheckConnectionA@0x137a50.
 * On Win10 desktop every dial entry point is a stub: it validates its arguments, asks IsRasEnumEntriesWPresent and
 * returns. Nothing is ever dialled and no UI is shown (the HWND is only traced), so these are safe to call.
 * VM_TIMEOUT: 120 */
#include "pc.h"

UDECL(DWORD, InternetDialA, (HWND, LPSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetDialW, (HWND, LPWSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetDial, (HWND, LPSTR, DWORD, DWORD_PTR *, DWORD));
UDECL(DWORD, InternetHangUp, (DWORD_PTR, DWORD));
UDECL(BOOL, InternetAutodial, (DWORD, HWND));
UDECL(BOOL, InternetAutodialHangup, (DWORD));
UDECL(BOOL, InternetSetDialStateA, (LPCSTR, DWORD, DWORD));
UDECL(BOOL, InternetSetDialStateW, (LPCWSTR, DWORD, DWORD));
UDECL(BOOL, InternetSetDialState, (LPCSTR, DWORD, DWORD));
UDECL(void, InternetAutodialCallback, (DWORD, LPVOID));
UDECL(void, GetProxyDllInfo, (void **, void **));
UDECL(BOOL, InternetCheckConnectionA, (LPCSTR, DWORD, DWORD));
UDECL(BOOL, InternetCheckConnectionW, (LPCWSTR, DWORD, DWORD));

/* RAS is present on Win10 desktop: InternetGetConnectedState reports INTERNET_RAS_INSTALLED (lab 0x12). The stubs
 * branch on the same IsRasEnumEntriesWPresent(), so derive the "RAS absent" error from the flag. */
static int ras_present(void) {
    DWORD f = 0;
    if (!U(InternetGetConnectedState)) return 1;
    U(InternetGetConnectedState)(&f, 0);
    return (f & INTERNET_RAS_INSTALLED) != 0;
}

/* ------------------------------------------------------------------ InternetAutodial */
TEST(pc_dial_autodial_flags) {
    REQUIRE(UN(InternetAutodial));
    int ras = ras_present();
    /* (flags & 0xfffffff0) == 0 is accepted; the stub never dials */
    for (DWORD f = 0; f <= 0xF; f++) {
        SetLastError(0xdeadbeef);
        BOOL r = UN(InternetAutodial)(f, NULL);
        if (ras) { CHECKF(r, "flags 0x%lx -> FALSE err %lu", f, GetLastError()); EXPECT_ERR(0); }
        else { CHECKF(!r, "flags 0x%lx", f); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED); }
    }
    static const DWORD bad[] = { 0x10, 0x11, 0x20, 0x100, 0x1000, 0x10000, 0x80000000u, 0xfffffff0u, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECKF(!UN(InternetAutodial)(bad[i], NULL), "flags 0x%lx accepted", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(pc_dial_autodial_hwnd_ignored) {
    REQUIRE(UN(InternetAutodial));
    if (!ras_present()) { t_skip("RAS not installed"); return; }
    /* a non-window HWND value is only traced */
    SetLastError(0xdeadbeef);
    CHECK(UN(InternetAutodial)(INTERNET_AUTODIAL_FORCE_UNATTENDED, (HWND)(ULONG_PTR)0x12345));
    EXPECT_ERR(0);
    SetLastError(0xdeadbeef);
    CHECK(UN(InternetAutodial)(INTERNET_AUTODIAL_FORCE_ONLINE | INTERNET_AUTODIAL_FAILIFSECURITYCHECK, GetDesktopWindow()));
    EXPECT_ERR(0);
    /* still online afterwards */
    DWORD v = 0, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &v, &l));
    EXPECT_EQ(v, INTERNET_STATE_CONNECTED);
}

TEST(pc_dial_autodial_hangup) {
    REQUIRE(UN(InternetAutodialHangup));
    int ras = ras_present();
    SetLastError(0xdeadbeef);
    BOOL r = UN(InternetAutodialHangup)(0);
    if (ras) { CHECK(r); EXPECT_ERR(0); } else { CHECK(!r); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED); }
    static const DWORD bad[] = { 1, 2, 0x10, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECKF(!UN(InternetAutodialHangup)(bad[i]), "reserved 0x%lx accepted", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    /* repeatable */
    for (int i = 0; i < 5; i++) { SetLastError(0xdeadbeef); CHECK(UN(InternetAutodialHangup)(0) == r); }
}

/* ------------------------------------------------------------------ InternetDial / InternetHangUp return a DWORD */
TEST(pc_dial_internetdial_a) {
    REQUIRE(UN(InternetDialA));
    int ras = ras_present();
    DWORD_PTR conn = (DWORD_PTR)0x1122334455667788ull;
    char name[] = "pc-connectoid-that-does-not-exist";
    DWORD r = UN(InternetDialA)(NULL, name, INTERNET_AUTODIAL_FORCE_UNATTENDED, &conn, 0);
    EXPECT_EQ(r, ras ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(conn, 0);                                   /* *lpdwConnection is zeroed first */
    conn = 77; r = UN(InternetDialA)(NULL, NULL, 0, &conn, 0);
    EXPECT_EQ(r, ras ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(conn, 0);
    /* NULL lpdwConnection */
    EXPECT_EQ(UN(InternetDialA)(NULL, name, 0, NULL, 0), ERROR_INVALID_PARAMETER);
    /* reserved != 0 wins over everything, and the connection is still zeroed */
    static const DWORD rs[] = { 1, 2, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof rs / sizeof rs[0]; i++) {
        conn = 5;
        EXPECT_EQ(UN(InternetDialA)(NULL, name, 0, &conn, rs[i]), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(conn, 0);
        EXPECT_EQ(UN(InternetDialA)(NULL, name, 0, NULL, rs[i]), ERROR_INVALID_PARAMETER);
    }
    /* dwFlags are not validated */
    static const DWORD fl[] = { 0x8000, 0x10000, 0xffffffffu };
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        conn = 9;
        EXPECT_EQ(UN(InternetDialA)(NULL, name, fl[i], &conn, 0), ras ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED);
        EXPECT_EQ(conn, 0);
    }
}

TEST(pc_dial_internetdial_w) {
    REQUIRE(UN(InternetDialW));
    int ras = ras_present();
    DWORD_PTR conn = 1234;
    WCHAR name[] = L"pc-connectoid-w";
    EXPECT_EQ(UN(InternetDialW)(NULL, name, 0, &conn, 0), ras ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(conn, 0);
    conn = 1; EXPECT_EQ(UN(InternetDialW)(NULL, NULL, INTERNET_DIAL_UNATTENDED, &conn, 0), ras ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(conn, 0);
    EXPECT_EQ(UN(InternetDialW)(NULL, name, 0, NULL, 0), ERROR_INVALID_PARAMETER);
    conn = 3; EXPECT_EQ(UN(InternetDialW)(NULL, name, 0, &conn, 1), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(conn, 0);
}

TEST(pc_dial_internetdial_plain_is_a) {
    /* InternetDial and InternetDialA are the same export (0x13c690) */
    FARPROC a = t_proc_in("wininet.dll", "InternetDial"), b = t_proc_in("wininet.dll", "InternetDialA");
    REQUIRE(a); REQUIRE(b);
    EXPECT_EQ(a, b);
    CHECK(t_proc_in("wininet.dll", "InternetDialW") != a);
    DWORD_PTR conn = 8; char n[] = "x";
    EXPECT_EQ(UN(InternetDial)(NULL, n, 0, &conn, 0), ras_present() ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(conn, 0);
}

TEST(pc_dial_hangup) {
    REQUIRE(UN(InternetHangUp));
    int ras = ras_present();
    static const DWORD_PTR conns[] = { 0, 1, 0x1234, (DWORD_PTR)-1 };
    for (size_t i = 0; i < sizeof conns / sizeof conns[0]; i++) {
        SetLastError(0x4321);
        DWORD r = UN(InternetHangUp)(conns[i], 0);
        CHECKF(r == (ras ? ERROR_SUCCESS : ERROR_CALL_NOT_IMPLEMENTED), "conn %p -> %lu", (void *)conns[i], r);
        EXPECT_ERR(0x4321);                    /* the result is returned, GetLastError is not set */
        r = UN(InternetHangUp)(conns[i], 1);
        EXPECT_EQ(r, ERROR_INVALID_PARAMETER);
        r = UN(InternetHangUp)(conns[i], 0xffffffffu);
        EXPECT_EQ(r, ERROR_INVALID_PARAMETER);
    }
    SetLastError(0x4321); UN(InternetHangUp)(0, 7);
    EXPECT_ERR(0x4321);
}

TEST(pc_dial_set_dial_state_always_fails) {
    REQUIRE(UN(InternetSetDialStateA)); REQUIRE(UN(InternetSetDialStateW));
    static const DWORD states[] = { 0, INTERNET_DIALSTATE_DISCONNECTED, 2, 0xffffffffu };
    for (size_t i = 0; i < sizeof states / sizeof states[0]; i++) {
        for (DWORD res = 0; res < 2; res++) {
            SetLastError(0xdeadbeef);
            CHECK(!UN(InternetSetDialStateA)("pc-connectoid", states[i], res)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SetLastError(0xdeadbeef);
            CHECK(!UN(InternetSetDialStateA)(NULL, states[i], res)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SetLastError(0xdeadbeef);
            CHECK(!UN(InternetSetDialStateW)(L"pc-connectoid", states[i], res)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SetLastError(0xdeadbeef);
            CHECK(!UN(InternetSetDialStateW)(NULL, states[i], res)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        }
    }
    EXPECT_EQ(t_proc_in("wininet.dll", "InternetSetDialState"), t_proc_in("wininet.dll", "InternetSetDialStateA"));
    SetLastError(0xdeadbeef);
    CHECK(!UN(InternetSetDialState)("x", 0, 0)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
}

TEST(pc_dial_autodial_callback_is_noop) {
    REQUIRE(UN(InternetAutodialCallback));
    SetLastError(0x4242);
    UN(InternetAutodialCallback)(0, NULL);
    UN(InternetAutodialCallback)(1, (LPVOID)(ULONG_PTR)0x10);
    UN(InternetAutodialCallback)(0xffffffffu, NULL);
    EXPECT_ERR(0x4242);
    DWORD f = 0; U(InternetGetConnectedState)(&f, 0);
    CHECK(!(f & INTERNET_CONNECTION_OFFLINE));
}

/* ------------------------------------------------------------------ GetProxyDllInfo (COM proxy/stub registration data) */
static int in_module(HMODULE m, const void *p) {
    const BYTE *base = (const BYTE *)m;
    const IMAGE_DOS_HEADER *d = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + d->e_lfanew);
    return (const BYTE *)p >= base && (const BYTE *)p < base + nt->OptionalHeader.SizeOfImage;
}
TEST(pc_dial_get_proxy_dll_info) {
    REQUIRE(UN(GetProxyDllInfo));
    HMODULE m = t_module("wininet.dll"); REQUIRE(m);
    void *list = NULL, *clsid = NULL;
    SetLastError(0x5151);
    UN(GetProxyDllInfo)(&list, &clsid);
    EXPECT_ERR(0x5151);
    CHECK(list != NULL); CHECK(clsid != NULL);
    if (list) CHECK(in_module(m, list));
    if (clsid) CHECK(in_module(m, clsid));
    /* stable */
    void *l2 = NULL, *c2 = NULL; UN(GetProxyDllInfo)(&l2, &c2);
    EXPECT_EQ(l2, list); EXPECT_EQ(c2, clsid);
    if (clsid) {
        const GUID *g = clsid;
        t_note("proxy dll CLSID {%08lx-%04x-%04x-...}", g->Data1, g->Data2, g->Data3);
        CHECK(g->Data1 != 0 || g->Data2 != 0);
    }
    if (list) {
        /* aProxyFileList: NULL-terminated array of ProxyFileInfo pointers, each inside the image */
        void **pp = list; int n = 0;
        while (n < 64 && pp[n]) { CHECKF(in_module(m, pp[n]), "entry %d outside image", n); n++; }
        t_note("proxy file list entries: %d", n);
        CHECK(n >= 1 && n < 64);
    }
}

/* ------------------------------------------------------------------ InternetGetConnectedStateEx buffers */
TEST(pc_dial_connected_state_ex_w_truncation) {
    REQUIRE(U(InternetGetConnectedStateExW));
    WCHAR full[260] = { 0 }; DWORD f0 = 0;
    BOOL r0 = U(InternetGetConnectedStateExW)(&f0, full, 260, 0);
    size_t n = wcslen(full);
    t_note("connection name \"%ls\" (%zu chars) flags 0x%lx", full, n, f0);
    if (!r0 || !(f0 & INTERNET_CONNECTION_LAN) || n < 4) { t_skip("no LAN connection name to truncate"); return; }
    /* the LAN name comes from LoadStringW(cch): it is truncated to cch-1 characters and NUL-terminated */
    for (DWORD cch = 1; cch <= n + 2 && cch < 40; cch++) {
        WCHAR b[64]; for (int i = 0; i < 64; i++) b[i] = 0x7777;
        DWORD f = 0; SetLastError(0xdeadbeef);
        BOOL r = U(InternetGetConnectedStateExW)(&f, b, cch, 0);
        EXPECT_EQ(r, r0); EXPECT_EQ(f, f0);
        size_t want = cch - 1 < n ? cch - 1 : n;
        CHECKF(wcslen(b) == want && !wcsncmp(b, full, want), "cch %lu: \"%ls\" (%zu) want %zu", cch, b, wcslen(b), want);
        CHECKF(b[cch] == 0x7777 || cch > n, "cch %lu: wrote past the buffer", cch);
    }
}

TEST(pc_dial_connected_state_ex_a_truncation) {
    REQUIRE(U(InternetGetConnectedStateExA));
    char full[260] = { 0 }; DWORD f0 = 0;
    BOOL r0 = U(InternetGetConnectedStateExA)(&f0, full, sizeof full, 0);
    size_t n = strlen(full);
    if (!r0 || n < 4) { t_skip("no connection name"); return; }
    for (DWORD len = 1; len <= n + 2 && len < 40; len++) {
        char b[64]; memset(b, 'Z', sizeof b);
        DWORD f = 0; SetLastError(0xdeadbeef);
        BOOL r = U(InternetGetConnectedStateExA)(&f, b, len, 0);
        DWORD e = GetLastError();
        EXPECT_EQ(r, r0); EXPECT_EQ(f, f0);
        if (len > n) {
            EXPECT_STR(b, full);
            CHECKF(e == 0, "len %lu: err %lu", len, e);
        } else {
            /* WideCharToMultiByte fails with ERROR_INSUFFICIENT_BUFFER; wininet forces b[len-1] = 0 */
            EXPECT_EQ(b[len - 1], 0);
            CHECKF(strlen(b) == len - 1 && !strncmp(b, full, len - 1), "len %lu: \"%s\"", len, b);
            CHECKF(b[len] == 'Z', "len %lu: wrote past the buffer", len);
            EXPECT_EQ(e, ERROR_INSUFFICIENT_BUFFER);   /* boot 5: TRUE, with WideCharToMultiByte's 122 left in GetLastError */
        }
    }
}

TEST(pc_dial_connected_state_ex_null_flags) {
    REQUIRE(U(InternetGetConnectedStateExW));
    DWORD f0 = 0; BOOL r0 = U(InternetGetConnectedState)(&f0, 0);
    WCHAR w[64]; SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetConnectedStateExW)(NULL, w, 64, 0), r0);
    EXPECT_ERR(0);
    char a[64]; SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetConnectedStateExA)(NULL, a, 64, 0), r0);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetConnectedStateExW)(NULL, NULL, 0, 0), r0);
    EXPECT_ERR(0);
    /* reserved with NULL everything */
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetGetConnectedStateExW)(NULL, NULL, 0, 2));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(pc_dial_connected_state_ex_reserved_table) {
    REQUIRE(U(InternetGetConnectedStateExW)); REQUIRE(U(InternetGetConnectedStateExA));
    static const DWORD rs[] = { 1, 2, 3, 0x100, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof rs / sizeof rs[0]; i++) {
        DWORD f = 0xcccccccc; WCHAR w[8] = { 'x', 'x', 0 };
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetGetConnectedStateExW)(&f, w, 8, rs[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        EXPECT_EQ(f, 0); EXPECT_EQ(w[0], 0);
        f = 0xcccccccc; char a[8] = "xx";
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetGetConnectedStateExA)(&f, a, 8, rs[i]));
        EXPECT_EQ(f, 0); EXPECT_EQ(a[0], 0);
    }
}

TEST(pc_dial_connected_state_flags_consistent) {
    REQUIRE(U(InternetGetConnectedState));
    DWORD f = 0; BOOL r = U(InternetGetConnectedState)(&f, 0);
    DWORD fe = 0; char n[64]; BOOL re = U(InternetGetConnectedStateExA)(&fe, n, sizeof n, 0);
    EXPECT_EQ(r, re); EXPECT_EQ(f, fe);
    /* at most one of MODEM/LAN, CONFIGURED (0x40) only with PROXY (0x4) or a dial-up connection */
    CHECK(!((f & INTERNET_CONNECTION_MODEM) && (f & INTERNET_CONNECTION_LAN)));
    if (f & INTERNET_CONNECTION_CONFIGURED) CHECK((f & INTERNET_CONNECTION_PROXY) || (f & INTERNET_CONNECTION_MODEM));
    if (!r) t_note("not connected: flags 0x%lx", f);
}

/* ------------------------------------------------------------------ InternetCheckConnection URL forms */
typedef struct { BOOL ok; DWORD err, ms; } icc_res;
static icc_res icc(const char *url, DWORD flags) {
    icc_res r; DWORD t0 = GetTickCount();
    SetLastError(0xdeadbeef);
    r.ok = UN(InternetCheckConnectionA)(url, flags, 0);
    r.err = r.ok ? 0 : GetLastError();
    r.ms = GetTickCount() - t0;
    return r;
}

/* FORCE + a listening loopback port in every scheme form: a bare TCP connect, nothing is sent */
TEST(pc_dial_check_connection_force_scheme_forms) {
    REQUIRE(UN(InternetCheckConnectionA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    static const char *fmts[] = { "http://127.0.0.1:%u/", "http://127.0.0.1:%u", "https://127.0.0.1:%u/", "ftp://127.0.0.1:%u/",
                                  "HTTP://127.0.0.1:%u/x?y#z", "http://user:pw@127.0.0.1:%u/p", "gopher://127.0.0.1:%u/",
                                  "http://localhost:%u/" };
    for (size_t i = 0; i < sizeof fmts / sizeof fmts[0]; i++) {
        char url[128]; snprintf(url, sizeof url, fmts[i], srv_port(s));
        icc_res r = icc(url, FLAG_ICC_FORCE_CONNECTION);
        t_note("ICC FORCE %s -> %d err %lu (%s) %lu ms", url, r.ok, r.err, t_inet_errname(r.err), r.ms);
        /* boot 5: http/https forms are a bare TCP connect; ftp waits for an FTP banner that never comes (12111 after ~5 s);
         * gopher is rejected with 87 */
        if (i == 3) CHECKF(!r.ok && r.err == ERROR_FTP_DROPPED, "%s: ok %d err %lu", url, r.ok, r.err);
        else if (i == 6) CHECKF(!r.ok && r.err == ERROR_INVALID_PARAMETER, "%s: ok %d err %lu", url, r.ok, r.err);
        else CHECKF(r.ok, "%s: err %lu", url, r.err);
    }
    Sleep(200);
    t_note("server saw %d requests, %d connections", srv_req_count(s), srv_conn_count(s));
    EXPECT_EQ(srv_req_count(s), 0);
    EXPECT_EQ(srv_conn_count(s), 7);
    srv_stop(s);
}

/* the FORCE bit is bit 0 only: other flag bits take the no-force path (FindNearestServer, URL ignored) */
TEST(pc_dial_check_connection_flag_bits) {
    REQUIRE(UN(InternetCheckConnectionA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    /* make sure the process has a "nearest server" so the no-force path is deterministic: TRUE */
    HINTERNET h = t_inet_open("pc_icc");
    char body[8]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(h, srv_url(s, "/warm"), NULL, T_INET_FRESH, body, sizeof body, &n, &err), 200);
    t_inet_close(h);
    int c0 = srv_conn_count(s);
    static const DWORD fl[] = { 0, 2, 4, 0x10, 0x80000000u, 0xfffffffeu };
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        icc_res r = icc("http://pc-icc-ignored.invalid/", fl[i]);
        CHECKF(r.ok, "flags 0x%lx: err %lu", fl[i], r.err);
    }
    Sleep(100);
    EXPECT_EQ(srv_conn_count(s), c0);   /* nothing connected */
    /* odd flags = FORCE */
    unsigned short dead = pc_closed_port();
    if (dead) {
        char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/", dead);
        icc_res r = icc(url, 0x3);
        CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_INTERNET_CANNOT_CONNECT);
    }
    srv_stop(s);
}

TEST(pc_dial_check_connection_w_forms) {
    REQUIRE(UN(InternetCheckConnectionW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    WCHAR url[96]; swprintf(url, 96, L"http://127.0.0.1:%u/w", srv_port(s));
    SetLastError(0xdeadbeef);
    CHECK(UN(InternetCheckConnectionW)(url, FLAG_ICC_FORCE_CONNECTION, 0));
    SetLastError(0xdeadbeef);
    CHECK(!UN(InternetCheckConnectionW)(url, FLAG_ICC_FORCE_CONNECTION, 1));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!UN(InternetCheckConnectionW)(L"not a url", FLAG_ICC_FORCE_CONNECTION, 0));
    EXPECT_ERR(ERROR_INTERNET_UNRECOGNIZED_SCHEME);
    unsigned short dead = pc_closed_port();
    if (dead) {
        swprintf(url, 96, L"http://127.0.0.1:%u/", dead);
        SetLastError(0xdeadbeef);
        CHECK(!UN(InternetCheckConnectionW)(url, FLAG_ICC_FORCE_CONNECTION, 0));
        EXPECT_ERR(ERROR_INTERNET_CANNOT_CONNECT);
    }
    srv_stop(s);
}

TEST(pc_dial_check_connection_reserved_table) {
    REQUIRE(UN(InternetCheckConnectionA));
    static const DWORD rs[] = { 1, 2, 0x100, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof rs / sizeof rs[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECK(!UN(InternetCheckConnectionA)("http://127.0.0.1:9/", FLAG_ICC_FORCE_CONNECTION, rs[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        CHECK(!UN(InternetCheckConnectionA)(NULL, 0, rs[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(pc_dial_check_connection_bad_url_table) {
    REQUIRE(UN(InternetCheckConnectionA));
    static const struct { const char *url; DWORD err; int certain; } t[] = {
        { "not a url", ERROR_INTERNET_UNRECOGNIZED_SCHEME, 1 },
        { "http//x", ERROR_INTERNET_UNRECOGNIZED_SCHEME, 1 },
        { "mailto:a@b", ERROR_INVALID_PARAMETER, 1 },
        { "", ERROR_INTERNET_UNRECOGNIZED_SCHEME, 1 },
        { "http://", ERROR_INTERNET_UNRECOGNIZED_SCHEME, 1 },
        { "http:///path", ERROR_INTERNET_INVALID_URL, 1 },
        { "file:///c:/x", 0, 1 },            /* boot 5: TRUE (no host to connect to) */
        { "about:blank", 0, 1 },
        { "javascript:1", ERROR_INVALID_PARAMETER, 1 },
        { "http://127.0.0.1:99999/", ERROR_INTERNET_INVALID_URL, 1 },
        { "http://127.0.0.1:0/", ERROR_INTERNET_CANNOT_CONNECT, 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        icc_res r = icc(t[i].url, FLAG_ICC_FORCE_CONNECTION);
        t_note("ICC FORCE \"%s\" -> %d err %lu (%s) %lu ms", t[i].url, r.ok, r.err, t_inet_errname(r.err), r.ms);
        if (t[i].certain) { CHECKF(r.ok == !t[i].err && r.err == t[i].err, "\"%s\": ok %d err %lu want %lu", t[i].url, r.ok, r.err, t[i].err); }
    }
}

/* a closed port on every scheme form fails with CANNOT_CONNECT */
TEST(pc_dial_check_connection_closed_port_schemes) {
    REQUIRE(UN(InternetCheckConnectionA));
    unsigned short dead = pc_closed_port();
    if (!dead) { t_skip("no ws2_32"); return; }
    static const char *fmts[] = { "http://127.0.0.1:%u/", "https://127.0.0.1:%u/", "ftp://127.0.0.1:%u/" };
    for (size_t i = 0; i < sizeof fmts / sizeof fmts[0]; i++) {
        char url[96]; snprintf(url, sizeof url, fmts[i], dead);
        icc_res r = icc(url, FLAG_ICC_FORCE_CONNECTION);
        t_note("ICC closed %s -> err %lu %lu ms", url, r.err, r.ms);
        CHECK(!r.ok);
        EXPECT_EQ(r.err, ERROR_INTERNET_CANNOT_CONNECT);
    }
}

/* a host name longer than 256 characters: the decomp copies the host only when it fits 0x100 bytes; observe */
TEST(pc_dial_check_connection_long_host) {
    REQUIRE(UN(InternetCheckConnectionA));
    char url[700]; strcpy(url, "http://");
    size_t p = strlen(url);
    for (int i = 0; i < 300; i++) url[p++] = (i % 60 == 59) ? '.' : 'a';
    strcpy(url + p, ".invalid/");
    icc_res r = icc(url, FLAG_ICC_FORCE_CONNECTION);
    t_note("ICC long host (%zu chars) -> %d err %lu (%s) %lu ms", p - 7, r.ok, r.err, t_inet_errname(r.err), r.ms);
    CHECK(r.ms < 30000);
    CHECK(r.ok);   /* decomp + boot 5: a host over 0x100 chars is not copied, nothing is connected, the check "succeeds" */
}

/* ------------------------------------------------------------------ autoproxy helpers: more argument forms */
UDECL(DWORD, InternetGetProxyForUrl, (HINTERNET, LPCWSTR, PC_PROXY_INFO_LIST *));
UDECL(void, InternetFreeProxyInfoList, (PC_PROXY_INFO_LIST *));
UDECL(BOOL, IsHostInProxyBypassList, (INTERNET_SCHEME, LPCSTR, DWORD));

typedef struct { const WCHAR *url; DWORD r; PC_PROXY_INFO_LIST l; } gp2_arg;
static DWORD WINAPI gp2_thread(void *p) { gp2_arg *a = p; memset(&a->l, 0xcc, sizeof a->l); a->r = UN(InternetGetProxyForUrl)(NULL, a->url, &a->l); return 0; }

TEST(pc_dial_get_proxy_for_url_scheme_table) {
    REQUIRE(UN(InternetGetProxyForUrl)); REQUIRE(UN(InternetFreeProxyInfoList));
    static const struct { const WCHAR *url; int certain_ok; } t[] = {
        /* certain_ok: 1 = ERROR_SUCCESS, otherwise the error observed on Win10 boot 5 */
        { L"http://pc-gp.invalid/", 1 }, { L"https://pc-gp.invalid/", 1 }, { L"ftp://pc-gp.invalid/", 1 }, { L"HTTP://PC-GP.INVALID/", 1 },
        { L"http://[::1]:8080/", 1 }, { L"http://127.0.0.1/", 1 }, { L"ws://pc-gp.invalid/", 1 }, { L"wss://pc-gp.invalid/", 1 },
        { L"gopher://pc-gp.invalid/", 1 }, { L"file:///c:/x.txt", ERROR_INTERNET_INVALID_URL }, { L"not a url", ERROR_INTERNET_UNRECOGNIZED_SCHEME },
        { L"pc-gp.invalid", ERROR_INTERNET_UNRECOGNIZED_SCHEME }, { L"http://", ERROR_INTERNET_INVALID_URL }, { L"mailto:a@b.invalid", 1 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        static gp2_arg a; a.url = t[i].url; a.r = 0xdead;
        if (!pc_bounded(gp2_thread, &a, 15000)) { t_skip("InternetGetProxyForUrl blocked > 15 s"); return; }
        t_note("OBS GetProxyForUrl(NULL, %ls) -> %lu count %lu fProxy %d fBypass %d scheme %d port %u", t[i].url, a.r,
               a.r == 0 ? a.l.dwProxyInfoCount : 0, a.r == 0 && a.l.dwProxyInfoCount ? a.l.pProxyInfo[0].fProxy : -1,
               a.r == 0 && a.l.dwProxyInfoCount ? a.l.pProxyInfo[0].fBypass : -1, a.r == 0 && a.l.dwProxyInfoCount ? (int)a.l.pProxyInfo[0].ProxyScheme : -1,
               a.r == 0 && a.l.dwProxyInfoCount ? a.l.pProxyInfo[0].ProxyPort : 0);
        CHECKF(a.r == (t[i].certain_ok == 1 ? 0 : (DWORD)t[i].certain_ok), "%ls -> %lu", t[i].url, a.r);
        if (a.r == 0 && a.l.dwProxyInfoCount && !a.l.pProxyInfo[0].fProxy) { EXPECT_EQ(a.l.pProxyInfo[0].fBypass, FALSE); EXPECT_EQ(a.l.pProxyInfo[0].ProxyPort, 0); }
        if (a.r == 0) { CHECK(a.l.dwProxyInfoCount >= 1); UN(InternetFreeProxyInfoList)(&a.l); }
        else EXPECT_EQ(a.l.dwProxyInfoCount, 0);
    }
}

TEST(pc_dial_get_proxy_for_url_free_twice_safe) {
    REQUIRE(UN(InternetGetProxyForUrl)); REQUIRE(UN(InternetFreeProxyInfoList));
    static gp2_arg a; a.url = L"http://pc-free.invalid/";
    if (!pc_bounded(gp2_thread, &a, 15000)) { t_skip("blocked"); return; }
    EXPECT_EQ(a.r, 0);
    if (a.r) return;
    UN(InternetFreeProxyInfoList)(&a.l);
    EXPECT_EQ(a.l.dwProxyInfoCount, 0); EXPECT_EQ(a.l.pProxyInfo, NULL);
    UN(InternetFreeProxyInfoList)(&a.l);      /* the list was reset: a second free is a no-op */
    EXPECT_EQ(a.l.dwProxyInfoCount, 0);
}

typedef struct { char *buf; DWORD len, flags; BOOL r; DWORD e; } dap2_arg;
static DWORD WINAPI dap2_thread(void *p) { dap2_arg *a = p; SetLastError(0xdeadbeef); a->r = U(DetectAutoProxyUrl)(a->buf, a->len, a->flags); a->e = GetLastError(); return 0; }
TEST(pc_dial_detect_auto_proxy_url_buffer_sizes) {
    REQUIRE(U(DetectAutoProxyUrl));
    static const DWORD lens[] = { 1, 2, 16, 2048 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        static char buf[2048]; memset(buf, 'x', sizeof buf);
        static dap2_arg a; a.buf = buf; a.len = lens[i]; a.flags = PROXY_AUTO_DETECT_TYPE_DHCP;
        if (!pc_bounded(dap2_thread, &a, 20000)) { t_skip("DetectAutoProxyUrl blocked > 20 s"); return; }
        t_note("OBS DetectAutoProxyUrl(len %lu) -> %d err %lu buf0 %d buf[len] %d", lens[i], a.r, a.e, buf[0], lens[i] < sizeof buf ? buf[lens[i]] : -1);
        CHECK(!a.r);
        EXPECT_EQ(buf[0], 0);
        if (lens[i] < sizeof buf) CHECKF(buf[lens[i]] == 'x', "len %lu: wrote past the buffer", lens[i]);
        EXPECT_EQ(a.e, ERROR_INTERNET_AUTODETECTION_FAILED);
    }
}

TEST(pc_dial_detect_auto_proxy_url_flag_values) {
    REQUIRE(U(DetectAutoProxyUrl));
    static const DWORD fl[] = { 0, 4, 8, 0x80000000u };
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        static char buf[256];
        static dap2_arg a; a.buf = buf; a.len = sizeof buf; a.flags = fl[i]; memset(buf, 'x', sizeof buf);
        if (!pc_bounded(dap2_thread, &a, 20000)) { t_skip("DetectAutoProxyUrl blocked > 20 s"); return; }
        t_note("OBS DetectAutoProxyUrl(flags 0x%lx) -> %d err %lu buf0 %d", fl[i], a.r, a.e, buf[0]);
        CHECK(!a.r);
        EXPECT_EQ(a.e, ERROR_INVALID_PARAMETER);   /* boot 5: only DHCP (1) / DNS_A (2) bits are accepted */
        EXPECT_EQ(buf[0], 0);
    }
}

typedef struct { INTERNET_SCHEME s; const char *h; DWORD cch; BOOL r; DWORD e; } ihb2_arg;
static DWORD WINAPI ihb2_thread(void *p) { ihb2_arg *a = p; SetLastError(0xdeadbeef); a->r = UN(IsHostInProxyBypassList)(a->s, a->h, a->cch); a->e = GetLastError(); return 0; }
TEST(pc_dial_is_host_in_bypass_list_lengths) {
    REQUIRE(UN(IsHostInProxyBypassList));
    static const struct { const char *h; DWORD cch; } t[] = {
        { "pc-len.invalid", 0 }, { "pc-len.invalid", 3 }, { "pc-len.invalid", 14 }, { "pc-len.invalid", 1000 }, { "<local>", 7 },
        { "pclocalname", 11 }, { "[::1]", 5 }, { "::1", 3 }, { "PC-LEN.INVALID", 14 },
    };
    DWORD pe = 0, n = sizeof pe;
    RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable", RRF_RT_REG_DWORD, NULL, &pe, &n);
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        static ihb2_arg a; a.s = INTERNET_SCHEME_HTTP; a.h = t[i].h; a.cch = t[i].cch; a.r = -1;
        if (!pc_bounded(ihb2_thread, &a, 15000)) { t_skip("blocked"); return; }
        t_note("OBS IsHostInProxyBypassList(http, \"%s\", %lu) -> %d err %lu", t[i].h, t[i].cch, a.r, a.e);
        if (!pe) EXPECT_EQ(a.r, FALSE);
        /* boot 5: "<local>" is not a host name (12005); every other form leaves GetLastError 0 */
        EXPECT_EQ(a.e, !strcmp(t[i].h, "<local>") ? ERROR_INTERNET_INVALID_URL : 0);
    }
}
