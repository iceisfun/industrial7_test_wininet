/* proxy_connectivity: connectivity and autoproxy entry points.
 * Decomp: InternetGetConnectedStateExW@0xd8340, InternetGetConnectedStateEx(A)@0x286e0, InternetGetConnectedState@0xd82e0,
 * InternetCheckConnectionA@0x137a50 / W@0x138f60, InternetGoOnline(A)@0x13c830 / W@0x13c8f0, InternetAttemptConnect@0x1378d0,
 * DetectAutoProxyUrl@0x165bb0, InternetInitializeAutoProxyDll@0x5bf80, InternetGetProxyForUrl@0x166250
 * (-> InternetGetProxyForUrlInternal@0x16578c), InternetFreeProxyInfoList@0x166170, IsHostInProxyBypassList@0x5eea0,
 * DoConnectoidsExist (ordinal 101)@0x13d320, FindNearestServer@0x14c35c.
 * Calls that may touch WPAD run on a worker thread with an outer wait. No setting is changed.
 * VM_TIMEOUT: 240 */
#include "pc.h"

UDECL(BOOL, IsHostInProxyBypassList, (INTERNET_SCHEME, LPCSTR, DWORD));
UDECL(DWORD, InternetGetProxyForUrl, (HINTERNET, LPCWSTR, PC_PROXY_INFO_LIST *));
UDECL(void, InternetFreeProxyInfoList, (PC_PROXY_INFO_LIST *));
typedef BOOL (WINAPI *DoConnectoidsExist_pfn)(void);

/* ------------------------------------------------------------------ exports */
TEST(pc_exports_present) {
    static const char *names[] = { "InternetGetConnectedState", "InternetGetConnectedStateEx", "InternetGetConnectedStateExA",
        "InternetGetConnectedStateExW", "InternetCheckConnectionA", "InternetCheckConnectionW", "InternetGoOnline", "InternetGoOnlineA",
        "InternetGoOnlineW", "InternetAttemptConnect", "DetectAutoProxyUrl", "InternetInitializeAutoProxyDll", "InternetGetProxyForUrl",
        "InternetFreeProxyInfoList", "IsHostInProxyBypassList", "InternetAutodial", "InternetAutodialHangup", "InternetDial",
        "InternetDialA", "InternetDialW", "InternetHangUp", "InternetSetDialState", "InternetSetDialStateA", "InternetSetDialStateW",
        "DeleteWpadCacheForNetworks", "GetProxyDllInfo" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) CHECKF(t_proc_in("wininet.dll", names[i]) != NULL, "%s missing", names[i]);
}

/* Present in the SDK header, absent from the Win10 export table (they lived in jsproxy-era wininet). */
TEST(pc_exports_absent) {
    static const char *names[] = { "InternetGetProxyInfo", "InternetDeInitializeAutoProxyDll", "DoConnectoidsExist" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) CHECKF(t_proc_in("wininet.dll", names[i]) == NULL, "%s exported", names[i]);
    /* DoConnectoidsExist is exported by ordinal only */
    CHECK(t_proc_ord("wininet.dll", 101) != NULL);
}

TEST(pc_aliases_share_code) {
    CHECK(t_proc_in("wininet.dll", "InternetGoOnline") == t_proc_in("wininet.dll", "InternetGoOnlineA"));
    CHECK(t_proc_in("wininet.dll", "InternetGetConnectedStateEx") == t_proc_in("wininet.dll", "InternetGetConnectedStateExA"));
    CHECK(t_proc_in("wininet.dll", "InternetGoOnlineW") != t_proc_in("wininet.dll", "InternetGoOnlineA"));
}

/* ------------------------------------------------------------------ InternetAttemptConnect */
TEST(pc_attempt_connect) {
    REQUIRE(U(InternetAttemptConnect));
    SetLastError(0x1234);
    EXPECT_EQ(U(InternetAttemptConnect)(0), ERROR_SUCCESS);
    static const DWORD nz[] = { 1, 2, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof nz / sizeof nz[0]; i++) EXPECT_EQ(U(InternetAttemptConnect)(nz[i]), ERROR_INVALID_PARAMETER);
    /* the DWORD is the result; GetLastError is not touched */
    SetLastError(0x1234); U(InternetAttemptConnect)(5);
    EXPECT_ERR(0x1234);
}

/* ------------------------------------------------------------------ InternetGetConnectedState(Ex) */
#define ICS_KNOWN (INTERNET_CONNECTION_MODEM | INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_PROXY | INTERNET_CONNECTION_MODEM_BUSY | \
                   INTERNET_RAS_INSTALLED | INTERNET_CONNECTION_OFFLINE | INTERNET_CONNECTION_CONFIGURED)

TEST(pc_connected_state_basic) {
    REQUIRE(U(InternetGetConnectedState));
    DWORD f = 0xcccccccc; SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetConnectedState)(&f, 0);
    DWORD e = GetLastError();
    t_note("InternetGetConnectedState -> %d flags 0x%lx err %lu", r, f, e);
    CHECK(r == TRUE || r == FALSE);
    CHECKF((f & ~ICS_KNOWN) == 0, "flags 0x%lx", f);
    EXPECT_EQ(e, 0);
    CHECK(!(f & INTERNET_CONNECTION_MODEM));
    CHECK(f & INTERNET_RAS_INSTALLED);
    CHECK(!(f & INTERNET_CONNECTION_OFFLINE));
    if (r) CHECK(f & INTERNET_CONNECTION_LAN);
}

TEST(pc_connected_state_null_flags) {
    REQUIRE(U(InternetGetConnectedState));
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetConnectedState)(NULL, 0);
    DWORD e = GetLastError();
    DWORD f = 0; BOOL r2 = U(InternetGetConnectedState)(&f, 0);
    EXPECT_EQ(r, r2);
    EXPECT_EQ(e, 0);
}

TEST(pc_connected_state_reserved_nonzero) {
    REQUIRE(U(InternetGetConnectedState));
    static const DWORD rs[] = { 1, 2, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof rs / sizeof rs[0]; i++) {
        DWORD f = 0xcccccccc; SetLastError(0xdeadbeef);
        BOOL r = U(InternetGetConnectedState)(&f, rs[i]);
        CHECKF(!r, "reserved 0x%lx -> TRUE", rs[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        EXPECT_EQ(f, 0);   /* zeroed before the argument check */
    }
}

TEST(pc_connected_state_ex_w) {
    REQUIRE(U(InternetGetConnectedStateExW));
    DWORD f0 = 0; BOOL r0 = U(InternetGetConnectedState)(&f0, 0);
    WCHAR name[260]; memset(name, 0xcc, sizeof name);
    DWORD f = 0xcccccccc; SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetConnectedStateExW)(&f, name, 260, 0);
    EXPECT_ERR(0);
    EXPECT_EQ(r, r0);
    EXPECT_EQ(f, f0);
    CHECK(name[0] != 0xcccc);
    t_note("ExW -> %d flags 0x%lx name \"%ls\"", r, f, name);
    if (r && (f & INTERNET_CONNECTION_LAN)) CHECK(name[0] != 0);
    /* name buffer of length 0: untouched apart from the leading NUL */
    WCHAR one[4] = { 'x', 'y', 0, 0 };
    f = 0; U(InternetGetConnectedStateExW)(&f, one, 0, 0);
    EXPECT_EQ(one[0], 0);
    EXPECT_EQ(one[1], 'y');
    /* NULL name pointer is fine */
    f = 0; SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetConnectedStateExW)(&f, NULL, 260, 0), r0);
    EXPECT_EQ(f, f0);
    /* reserved */
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetGetConnectedStateExW)(&f, name, 260, 1));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(name[0], 0);
}

TEST(pc_connected_state_ex_a) {
    REQUIRE(U(InternetGetConnectedStateExA));
    DWORD f0 = 0; BOOL r0 = U(InternetGetConnectedState)(&f0, 0);
    char name[260]; memset(name, 'x', sizeof name);
    DWORD f = 0xcccccccc; SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetConnectedStateExA)(&f, name, sizeof name, 0);
    EXPECT_ERR(0);
    EXPECT_EQ(r, r0); EXPECT_EQ(f, f0);
    t_note("ExA -> %d flags 0x%lx name \"%s\"", r, f, name);
    CHECK(memchr(name, 0, sizeof name) != NULL);
    WCHAR wname[260] = { 0 }; DWORD fw = 0;
    U(InternetGetConnectedStateExW)(&fw, wname, 260, 0);
    char conv[260]; WideCharToMultiByte(CP_ACP, 0, wname, -1, conv, sizeof conv, NULL, NULL);
    EXPECT_STR(name, conv);
    /* short buffer: WideCharToMultiByte fails and the last byte of the buffer is forced to NUL */
    if (strlen(conv) >= 3) {
        char sb[3] = { 'q', 'q', 'q' };
        U(InternetGetConnectedStateExA)(&f, sb, 3, 0);
        EXPECT_EQ(sb[2], 0);
    }
    CHECK(U(InternetGetConnectedStateExA)(&f, NULL, 0, 0) == r0);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetGetConnectedStateEx)(&f, name, sizeof name, 7));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(pc_connected_state_repeatable) {
    REQUIRE(U(InternetGetConnectedState));
    DWORD f0 = 0; BOOL r0 = U(InternetGetConnectedState)(&f0, 0);
    for (int i = 0; i < 20; i++) {
        DWORD f = 0; BOOL r = U(InternetGetConnectedState)(&f, 0);
        CHECKF(r == r0 && f == f0, "iteration %d: %d/0x%lx vs %d/0x%lx", i, r, f, r0, f0);
    }
}

/* ------------------------------------------------------------------ InternetGoOnline */
TEST(pc_go_online_flags) {
    REQUIRE(U(InternetGoOnlineA)); REQUIRE(U(InternetGoOnlineW));
    static const DWORD good[] = { 0, 1, 2, 3 };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        SetLastError(0xdeadbeef);
        BOOL r = U(InternetGoOnlineA)(NULL, NULL, good[i]);
        CHECKF(r, "A flags %lu err %lu", good[i], GetLastError());
        EXPECT_ERR(0);
        SetLastError(0xdeadbeef);
        r = U(InternetGoOnlineW)(NULL, NULL, good[i]);
        CHECKF(r, "W flags %lu err %lu", good[i], GetLastError());
        EXPECT_ERR(0);
    }
    static const DWORD bad[] = { 4, 5, 8, 0x10, 0x100, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECKF(!U(InternetGoOnlineA)(NULL, NULL, bad[i]), "A flags 0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        CHECKF(!U(InternetGoOnlineW)(NULL, NULL, bad[i]), "W flags 0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        CHECKF(!U(InternetGoOnline)(NULL, NULL, bad[i]), "plain flags 0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(pc_go_online_url_ignored) {
    REQUIRE(U(InternetGoOnlineA));
    char url[] = "http://pc-go-online.invalid/x";
    WCHAR wurl[] = L"http://pc-go-online.invalid/x";
    char junk[] = "not a url";
    SetLastError(0xdeadbeef); CHECK(U(InternetGoOnlineA)(url, NULL, 0)); EXPECT_ERR(0);
    SetLastError(0xdeadbeef); CHECK(U(InternetGoOnlineW)(wurl, NULL, 0)); EXPECT_ERR(0);
    SetLastError(0xdeadbeef); CHECK(U(InternetGoOnline)(junk, NULL, 0)); EXPECT_ERR(0);
    DWORD v = 0, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &v, &l));
    EXPECT_EQ(v, INTERNET_STATE_CONNECTED);
}

/* ------------------------------------------------------------------ DoConnectoidsExist (ordinal 101) */
TEST(pc_do_connectoids_exist) {
    DoConnectoidsExist_pfn f = (DoConnectoidsExist_pfn)t_proc_ord("wininet.dll", 101);
    REQUIRE(f);
    SetLastError(0xdeadbeef);
    BOOL r = f();
    t_note("DoConnectoidsExist -> %d err %lu", r, GetLastError());
    CHECK(r == 0 || r == 1);
    EXPECT_EQ(f(), r);   /* a TRUE answer is latched; a FALSE answer is re-evaluated but stable here */
}

/* ------------------------------------------------------------------ InternetCheckConnection */
TEST(pc_check_connection_reserved) {
    REQUIRE(U(InternetCheckConnectionA)); REQUIRE(U(InternetCheckConnectionW));
    static const DWORD rs[] = { 1, 2, 0xffffffffu };
    for (size_t i = 0; i < sizeof rs / sizeof rs[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetCheckConnectionA)("http://127.0.0.1:1/", FLAG_ICC_FORCE_CONNECTION, rs[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetCheckConnectionW)(L"http://127.0.0.1:1/", 0, rs[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetCheckConnectionA)(NULL, 0, rs[i]));
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(pc_check_connection_force_listening) {
    REQUIRE(U(InternetCheckConnectionA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    DWORD t0 = GetTickCount(); SetLastError(0xdeadbeef);
    BOOL r = U(InternetCheckConnectionA)(srv_url(s, "/check"), FLAG_ICC_FORCE_CONNECTION, 0);
    DWORD e = GetLastError(), ms = GetTickCount() - t0;
    CHECKF(r, "err %lu (%s)", e, t_inet_errname(e));
    t_note("check listening: %d err %lu %lu ms", r, e, ms);
    /* a TCP connect only: no HTTP request is sent */
    CHECK(srv_wait_events(s, SRV_EV_ACCEPT, 1, 3000));
    Sleep(200);
    EXPECT_EQ(srv_req_count(s), 0);
    srv_stop(s);
}

TEST(pc_check_connection_force_listening_W) {
    REQUIRE(U(InternetCheckConnectionW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    WCHAR wurl[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(s, "/w"), -1, wurl, 128);
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetCheckConnectionW)(wurl, FLAG_ICC_FORCE_CONNECTION, 0);
    CHECKF(r, "err %lu", GetLastError());
    CHECK(srv_wait_events(s, SRV_EV_ACCEPT, 1, 3000));
    srv_stop(s);
}

TEST(pc_check_connection_force_closed_port) {
    REQUIRE(U(InternetCheckConnectionA));
    unsigned short p = pc_closed_port();
    if (!p) { t_skip("no ws2_32"); return; }
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/", p);
    DWORD t0 = GetTickCount(); SetLastError(0xdeadbeef);
    BOOL r = U(InternetCheckConnectionA)(url, FLAG_ICC_FORCE_CONNECTION, 0);
    DWORD e = GetLastError(), ms = GetTickCount() - t0;
    t_note("check closed port %u: %d err %lu (%s) %lu ms", p, r, e, t_inet_errname(e), ms);
    CHECK(!r);
    EXPECT_EQ(e, ERROR_INTERNET_CANNOT_CONNECT);
}

TEST(pc_check_connection_force_unresolvable) {
    REQUIRE(U(InternetCheckConnectionA));
    DWORD t0 = GetTickCount(); SetLastError(0xdeadbeef);
    BOOL r = U(InternetCheckConnectionA)("http://pc-check.invalid/", FLAG_ICC_FORCE_CONNECTION, 0);
    DWORD e = GetLastError(), ms = GetTickCount() - t0;
    t_note("check .invalid: %d err %lu (%s) %lu ms (forced check resolves through a slower path than HttpSendRequest)", r, e, t_inet_errname(e), ms);
    CHECK(!r);
    EXPECT_EQ(e, ERROR_INTERNET_NAME_NOT_RESOLVED);
}

TEST(pc_check_connection_bad_url) {
    REQUIRE(U(InternetCheckConnectionA));
    static const char *bad[] = { "not a url", "http//x", "mailto:a@b" };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        BOOL r = U(InternetCheckConnectionA)(bad[i], FLAG_ICC_FORCE_CONNECTION, 0);
        DWORD e = GetLastError();
        t_note("check \"%s\": %d err %lu (%s)", bad[i], r, e, t_inet_errname(e));
        CHECKF(!r, "\"%s\" accepted", bad[i]);
        CHECKF(e == (i < 2 ? ERROR_INTERNET_UNRECOGNIZED_SCHEME : ERROR_INVALID_PARAMETER), "\"%s\" err %lu", bad[i], e);
    }
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetCheckConnectionA)("not a url", FLAG_ICC_FORCE_CONNECTION, 0));
    EXPECT_ERR(ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}

/* Without FLAG_ICC_FORCE_CONNECTION the URL is ignored: the answer is "has this process got any server info"
 * (FindNearestServer). After a connection to the loopback server there is one. */
TEST(pc_check_connection_noforce_after_traffic) {
    REQUIRE(U(InternetCheckConnectionA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    HTTP_OR_SKIP(s, st);
    HINTERNET h = t_inet_open("pc");
    char body[16]; DWORD err;
    EXPECT_EQ(pc_get(h, srv_url(s, "/warm"), 0, body, sizeof body, &err, NULL), 200);
    t_inet_close(h);
    SetLastError(0xdeadbeef);
    CHECK(U(InternetCheckConnectionA)("http://pc-noforce.invalid/", 0, 0));
    SetLastError(0xdeadbeef);
    CHECK(U(InternetCheckConnectionA)(NULL, 0, 0));
    SetLastError(0xdeadbeef);
    CHECK(U(InternetCheckConnectionW)(NULL, 0, 0));
    int before = srv_conn_count(s);
    Sleep(100);
    EXPECT_EQ(srv_conn_count(s), before);   /* nothing connected */
    srv_stop(s);
}

/* A fresh process has no server info: non-forced check fails with ERROR_NOT_CONNECTED (2250); forced with a NULL URL
 * fails with ERROR_INTERNET_INVALID_OPERATION (12016). */
CHILD(pc_fresh_check) {
    DWORD out = 0;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetCheckConnectionA)(NULL, 0, 0);
    DWORD e1 = GetLastError();
    SetLastError(0xdeadbeef);
    BOOL r2 = U(InternetCheckConnectionA)(NULL, FLAG_ICC_FORCE_CONNECTION, 0);
    DWORD e2 = GetLastError();
    printf("child: noforce r=%d e=%lu force r=%d e=%lu\n", r, e1, r2, e2);
    if (!r && e1 == ERROR_NOT_CONNECTED) out |= 1;
    if (!r2 && e2 == ERROR_INTERNET_INVALID_OPERATION) out |= 2;
    return (int)(0x100 | out);
}
TEST(pc_check_connection_fresh_process) {
    REQUIRE(U(InternetCheckConnectionA));
    DWORD code = t_run_child("pc_fresh_check", NULL, 15000);
    if (code == 0xDEAD0000 || code == 0xDEAD0001) { t_skip("child failed 0x%lx", code); return; }
    t_note("child exit 0x%lx", code);
    CHECK(code & 0x100);
    CHECKF(code & 1, "non-forced check in a fresh process did not fail with 2250");
    CHECKF(code & 2, "forced NULL-url check in a fresh process did not fail with 12016");
}

/* ------------------------------------------------------------------ DetectAutoProxyUrl */
TEST(pc_detect_auto_proxy_url_args) {
    REQUIRE(U(DetectAutoProxyUrl));
    char b[8];
    SetLastError(0xdeadbeef);
    CHECK(!U(DetectAutoProxyUrl)(b, 0, PROXY_AUTO_DETECT_TYPE_DHCP)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SetLastError(0xdeadbeef);
    CHECK(!U(DetectAutoProxyUrl)(NULL, 0, PROXY_AUTO_DETECT_TYPE_DHCP)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SetLastError(0xdeadbeef);
    CHECK(!U(DetectAutoProxyUrl)(NULL, 16, PROXY_AUTO_DETECT_TYPE_DHCP)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!U(DetectAutoProxyUrl)(NULL, 1, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

typedef struct { DWORD flags; BOOL r; DWORD e; char url[512]; DWORD ms; } detect_arg;
static DWORD WINAPI detect_thread(void *p) {
    detect_arg *a = p; DWORD t0 = GetTickCount();
    memset(a->url, 'x', sizeof a->url);
    SetLastError(0xdeadbeef);
    a->r = U(DetectAutoProxyUrl)(a->url, sizeof a->url, a->flags);
    a->e = GetLastError(); a->ms = GetTickCount() - t0;
    return 0;
}
TEST(pc_detect_auto_proxy_url_no_wpad) {
    REQUIRE(U(DetectAutoProxyUrl));
    static const DWORD fl[] = { PROXY_AUTO_DETECT_TYPE_DHCP, PROXY_AUTO_DETECT_TYPE_DNS_A, PROXY_AUTO_DETECT_TYPE_DHCP | PROXY_AUTO_DETECT_TYPE_DNS_A };
    for (size_t i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        static detect_arg a; memset(&a, 0, sizeof a); a.flags = fl[i];
        if (!pc_bounded(detect_thread, &a, 20000)) { t_skip("DetectAutoProxyUrl(%lu) still running after 20 s (WPAD on this network?)", fl[i]); return; }
        t_note("DetectAutoProxyUrl(%lu) -> %d err %lu (%s) %lu ms url0=%d", fl[i], a.r, a.e, t_inet_errname(a.e), a.ms, a.url[0]);
        /* the lab network has no DHCP option 252 and no DNS (04 F4/F5): detection fails */
        CHECK(!a.r);
        EXPECT_EQ(a.url[0], 0);   /* buffer is cleared before detection */
        CHECKF(a.e == ERROR_INTERNET_AUTODETECTION_FAILED, "err %lu", a.e);
    }
}

/* ------------------------------------------------------------------ InternetInitializeAutoProxyDll */
TEST(pc_init_autoproxy_dll_bad_flags) {
    REQUIRE(U(InternetInitializeAutoProxyDll));
    static const DWORD bad[] = { 0x10, 0x20, 0x100, 0x80000000u, 0xffffffffu, 0x6, 0xA, 0xE, 0x7, 0xF, 0x11 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECKF(!U(InternetInitializeAutoProxyDll)(bad[i]), "flags 0x%lx accepted", bad[i]);
        DWORD e = GetLastError(); CHECKF(e == ERROR_INVALID_PARAMETER, "flags 0x%lx err %lu", bad[i], e);
    }
}

typedef struct { DWORD flags; BOOL r; DWORD e; DWORD ms; } iapd_arg;
static DWORD WINAPI iapd_thread(void *p) {
    iapd_arg *a = p; DWORD t0 = GetTickCount(); SetLastError(0xdeadbeef);
    a->r = U(InternetInitializeAutoProxyDll)(a->flags); a->e = GetLastError(); a->ms = GetTickCount() - t0; return 0;
}
TEST(pc_init_autoproxy_dll_async_flags) {
    REQUIRE(U(InternetInitializeAutoProxyDll));
    static const DWORD good[] = { 0, 1, 4, 8, 0xC, 5 };
    for (size_t i = 0; i < sizeof good / sizeof good[0]; i++) {
        static iapd_arg a; memset(&a, 0, sizeof a); a.flags = good[i];
        if (!pc_bounded(iapd_thread, &a, 10000)) { t_skip("InternetInitializeAutoProxyDll(0x%lx) blocked > 10 s", good[i]); return; }
        t_note("InternetInitializeAutoProxyDll(0x%lx) -> %d err %lu %lu ms", good[i], a.r, a.e, a.ms);
        CHECKF(a.r, "flags 0x%lx", good[i]); CHECKF(a.e == 0, "flags 0x%lx err %lu", good[i], a.e);
    }
}

TEST(pc_init_autoproxy_dll_sync) {
    REQUIRE(U(InternetInitializeAutoProxyDll));
    static iapd_arg a; memset(&a, 0, sizeof a); a.flags = 2;
    if (!pc_bounded(iapd_thread, &a, 15000)) { t_skip("InternetInitializeAutoProxyDll(2) blocked > 15 s"); return; }
    t_note("InternetInitializeAutoProxyDll(2) -> %d err %lu %lu ms", a.r, a.e, a.ms);
    CHECK(a.r); EXPECT_EQ(a.e, 0);   /* lab: no WPAD/PAC configured, the synchronous init completes at once */
}

/* ------------------------------------------------------------------ InternetGetProxyForUrl / InternetFreeProxyInfoList */
TEST(pc_get_proxy_for_url_args) {
    REQUIRE(UN(InternetGetProxyForUrl));
    PC_PROXY_INFO_LIST l; memset(&l, 0xcc, sizeof l);
    EXPECT_EQ(UN(InternetGetProxyForUrl)(NULL, NULL, &l), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(l.dwProxyInfoCount, 0); EXPECT_EQ(l.pProxyInfo, NULL);   /* list zeroed first */
    memset(&l, 0xcc, sizeof l);
    EXPECT_EQ(UN(InternetGetProxyForUrl)(NULL, L"", &l), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(l.dwProxyInfoCount, 0);
    EXPECT_EQ(UN(InternetGetProxyForUrl)(NULL, L"http://a.invalid/", NULL), ERROR_INVALID_PARAMETER);
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hc = h ? U(InternetConnectA)(h, "a.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (hc) {
        memset(&l, 0xcc, sizeof l);
        EXPECT_EQ(UN(InternetGetProxyForUrl)(hc, L"http://a.invalid/", &l), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(l.dwProxyInfoCount, 0);
        U(InternetCloseHandle)(hc);
    }
    if (h) U(InternetCloseHandle)(h);
    /* InternetFreeProxyInfoList(NULL) is a no-op; freeing a zeroed list is fine */
    UN(InternetFreeProxyInfoList)(NULL);
    memset(&l, 0, sizeof l); UN(InternetFreeProxyInfoList)(&l);
    EXPECT_EQ(l.dwProxyInfoCount, 0);
}

TEST(pc_get_proxy_for_url_closed_handle) {
    REQUIRE(UN(InternetGetProxyForUrl));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    U(InternetCloseHandle)(h);
    PC_PROXY_INFO_LIST l; memset(&l, 0xcc, sizeof l);
    DWORD r = UN(InternetGetProxyForUrl)(h, L"http://a.invalid/", &l);
    t_note("closed handle -> %lu", r);
    EXPECT_EQ(r, ERROR_INVALID_HANDLE);
    EXPECT_EQ(l.dwProxyInfoCount, 0);
}

typedef struct { HINTERNET h; const WCHAR *url; DWORD r; PC_PROXY_INFO_LIST l; DWORD ms; } gpfu_arg;
static DWORD WINAPI gpfu_thread(void *p) {
    gpfu_arg *a = p; DWORD t0 = GetTickCount();
    a->r = UN(InternetGetProxyForUrl)(a->h, a->url, &a->l); a->ms = GetTickCount() - t0; return 0;
}
TEST(pc_get_proxy_for_url_direct_config) {
    REQUIRE(UN(InternetGetProxyForUrl)); REQUIRE(UN(InternetFreeProxyInfoList));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    static const WCHAR *urls[] = { L"http://pc-gpfu.invalid/a", L"https://pc-gpfu.invalid:8443/b", L"http://127.0.0.1:1/" };
    for (int pass = 0; pass < 2; pass++)
        for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
            static gpfu_arg a; memset(&a, 0, sizeof a); a.h = pass ? h : NULL; a.url = urls[i];
            if (!pc_bounded(gpfu_thread, &a, 15000)) { t_skip("InternetGetProxyForUrl blocked > 15 s"); return; }
            t_note("GetProxyForUrl(%s, %ls) -> %lu count %lu fProxy %d proxy %ls %lu ms", pass ? "session" : "NULL", urls[i], a.r,
                   a.l.dwProxyInfoCount, a.l.dwProxyInfoCount ? a.l.pProxyInfo[0].fProxy : -1,
                   a.l.dwProxyInfoCount && a.l.pProxyInfo[0].pwszProxy ? a.l.pProxyInfo[0].pwszProxy : L"(null)", a.ms);
            EXPECT_EQ(a.r, ERROR_SUCCESS);
            if (a.r == 0) {
                CHECK(a.l.dwProxyInfoCount >= 1);
                CHECK(a.l.pProxyInfo != NULL);
                if (a.l.dwProxyInfoCount && a.l.pProxyInfo) {
                    if (!pass || 1) {
                        DWORD pe = 0, n = sizeof pe;
                        RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable", RRF_RT_REG_DWORD, NULL, &pe, &n);
                        if (!pe) EXPECT_EQ(a.l.pProxyInfo[0].fProxy, FALSE);
                    }
                }
                UN(InternetFreeProxyInfoList)(&a.l);
                EXPECT_EQ(a.l.dwProxyInfoCount, 0); EXPECT_EQ(a.l.pProxyInfo, NULL);
            }
        }
    if (h) U(InternetCloseHandle)(h);
}

/* the session's own proxy is not consulted: a PROXY session still answers from the global configuration */
TEST(pc_get_proxy_for_url_ignores_session_proxy) {
    REQUIRE(UN(InternetGetProxyForUrl));
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:3128", NULL, 0);
    if (!h) { t_skip("open failed"); return; }
    static gpfu_arg a; memset(&a, 0, sizeof a); a.h = h; a.url = L"http://pc-gpfu2.invalid/";
    if (!pc_bounded(gpfu_thread, &a, 15000)) { t_skip("blocked"); return; }
    t_note("PROXY session -> %lu count %lu fProxy %d", a.r, a.l.dwProxyInfoCount, a.l.dwProxyInfoCount ? a.l.pProxyInfo[0].fProxy : -1);
    EXPECT_EQ(a.r, 0);
    DWORD pe = 0, n = sizeof pe;
    RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable", RRF_RT_REG_DWORD, NULL, &pe, &n);
    if (a.r == 0 && a.l.dwProxyInfoCount && !pe) EXPECT_EQ(a.l.pProxyInfo[0].fProxy, FALSE);
    if (a.r == 0) UN(InternetFreeProxyInfoList)(&a.l);
    U(InternetCloseHandle)(h);
}

/* ------------------------------------------------------------------ IsHostInProxyBypassList */
TEST(pc_is_host_in_bypass_list_args) {
    REQUIRE(UN(IsHostInProxyBypassList));
    static const INTERNET_SCHEME bad[] = { INTERNET_SCHEME_GOPHER, INTERNET_SCHEME_FILE, INTERNET_SCHEME_NEWS, INTERNET_SCHEME_MAILTO,
                                           (INTERNET_SCHEME)99, INTERNET_SCHEME_UNKNOWN };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SetLastError(0xdeadbeef);
        CHECKF(!UN(IsHostInProxyBypassList)(bad[i], "a.invalid", 9), "scheme %d", bad[i]);
        DWORD e = GetLastError(); CHECKF(e == ERROR_INTERNET_UNRECOGNIZED_SCHEME, "scheme %d err %lu", bad[i], e);
    }
    SetLastError(0xdeadbeef);
    CHECK(!UN(IsHostInProxyBypassList)(INTERNET_SCHEME_HTTP, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!UN(IsHostInProxyBypassList)(INTERNET_SCHEME_HTTP, "", 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

typedef struct { INTERNET_SCHEME sch; const char *host; BOOL r; DWORD e; } ihb_arg;
static DWORD WINAPI ihb_thread(void *p) {
    ihb_arg *a = p; SetLastError(0xdeadbeef); a->r = UN(IsHostInProxyBypassList)(a->sch, a->host, (DWORD)strlen(a->host)); a->e = GetLastError(); return 0;
}
TEST(pc_is_host_in_bypass_list_direct_config) {
    REQUIRE(UN(IsHostInProxyBypassList));
    static const struct { INTERNET_SCHEME s; const char *h; } t[] = {
        { INTERNET_SCHEME_HTTP, "pc-bypass.invalid" }, { INTERNET_SCHEME_HTTPS, "pc-bypass.invalid" }, { INTERNET_SCHEME_FTP, "pc-bypass.invalid" },
        { INTERNET_SCHEME_DEFAULT, "pc-bypass.invalid" }, { INTERNET_SCHEME_HTTP, "127.0.0.1" }, { INTERNET_SCHEME_HTTP, "localhost" },
        { INTERNET_SCHEME_HTTP, "intranethost" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        static ihb_arg a; a.sch = t[i].s; a.host = t[i].h; a.r = -1; a.e = 0;
        if (!pc_bounded(ihb_thread, &a, 15000)) { t_skip("IsHostInProxyBypassList blocked"); return; }
        t_note("IsHostInProxyBypassList(%d, %s) -> %d err %lu", t[i].s, t[i].h, a.r, a.e);
        CHECK(a.r == TRUE || a.r == FALSE);
        DWORD pe = 0, n = sizeof pe;
        RegGetValueA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "ProxyEnable", RRF_RT_REG_DWORD, NULL, &pe, &n);
        if (!pe) EXPECT_EQ(a.r, FALSE);   /* no proxy configured: nothing is "in the bypass list" */
        EXPECT_EQ(a.e, 0);
    }
}
