/* Dial-up / autodial / online family and connectivity ordinals (no UI: every call either fails argument
 * validation or is a no-op on a machine with the RAS API set present).
 *
 * [D InternetAutodial@0x13c520]     flags & ~0xF -> FALSE, 87; RAS missing -> FALSE, 120; else TRUE, GLE 0
 * [D InternetAutodialHangup]        reserved != 0 -> FALSE, 87; else TRUE, GLE 0
 * [D InternetDial(A)@0x13c690, W@0x13c760]  DWORD result, never SetLastError; *lpdwConnection = 0 first;
 *                                   reserved != 0 or lpdwConnection NULL -> 87; RAS missing -> 120; else 0
 * [D InternetHangUp@0x13c9b0]       DWORD; reserved != 0 -> 87; else 0
 * [D InternetGoOnline(A)@0x13c830, W@0x13c8f0]  flags & ~3 -> FALSE, 87; else TRUE, GLE 0
 * [D InternetSetDialState(A/W)]     always FALSE, 120
 * [D InternetAutodialCallback@0x133af0]  void no-op
 * VM_TIMEOUT: 120 */
#include "gs.h"

/* ------------------------------------------------------------------ InternetAutodial */
TEST(gs_autodial_bad_flag_bits) {
    REQUIRE(UN(InternetAutodial));
    for (int b = 4; b < 32; b++) {
        for (int base = 0; base < 2; base++) {
            DWORD f = (1u << b) | (base ? INTERNET_AUTODIAL_FORCE_UNATTENDED : 0);
            SET_ERR(0);
            CHECKF(!UN(InternetAutodial)(f, NULL), "flags 0x%lx", f);
            EXPECT_ERR(ERROR_INVALID_PARAMETER);
        }
    }
    SET_ERR(0);
    CHECK(!UN(InternetAutodial)(0xFFFFFFFFu, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    CHECK(!UN(InternetAutodial)(0xFFFFFFF0u, GetDesktopWindow())); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(gs_autodial_valid_flags_noop) {
    REQUIRE(UN(InternetAutodial));
    for (DWORD f = 0; f < 16; f++)
        for (size_t s = 0; s < GS_NSEEDS; s++) {
            SET_ERR(gs_seeds[s]);
            BOOL r = UN(InternetAutodial)(f, NULL);
            DWORD e = GetLastError();
            CHECKF(r && e == 0, "flags=%lu seed=%lu r=%d e=%lu", f, gs_seeds[s], r, e);
        }
}

TEST(gs_autodial_named_flags) {
    REQUIRE(UN(InternetAutodial));
    static const DWORD f[] = { INTERNET_AUTODIAL_FORCE_ONLINE, INTERNET_AUTODIAL_FORCE_UNATTENDED,
                               INTERNET_AUTODIAL_FAILIFSECURITYCHECK, INTERNET_AUTODIAL_OVERRIDE_NET_PRESENT,
                               INTERNET_AUTODIAL_FLAGS_MASK };
    for (size_t i = 0; i < sizeof f / sizeof f[0]; i++) {
        SET_ERR(0x4242);
        CHECKF(UN(InternetAutodial)(f[i], NULL), "flag 0x%lx", f[i]);
        EXPECT_ERR(0);
    }
    EXPECT_EQ(INTERNET_AUTODIAL_FLAGS_MASK, 0xF);
}

TEST(gs_autodial_hangup_table) {
    REQUIRE(UN(InternetAutodialHangup));
    for (int b = 0; b < 32; b++) {
        SET_ERR(0);
        CHECKF(!UN(InternetAutodialHangup)(1u << b), "reserved bit %d", b);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        SET_ERR(gs_seeds[s]);
        CHECK(UN(InternetAutodialHangup)(0));
        EXPECT_ERR(0);
    }
}

/* ------------------------------------------------------------------ InternetDial */
typedef DWORD (WINAPI *gs_dial_a)(HWND, LPSTR, DWORD, DWORD_PTR *, DWORD);
static void gs_dial_table_a(gs_dial_a f, const char *label) {
    char name[] = "i7-no-such-connectoid";
    static const DWORD flags[] = { 0, INTERNET_AUTODIAL_FORCE_ONLINE, INTERNET_AUTODIAL_FORCE_UNATTENDED,
                                   INTERNET_DIAL_UNATTENDED, INTERNET_DIAL_SHOW_OFFLINE, INTERNET_DIAL_FORCE_PROMPT,
                                   0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        /* reserved != 0 */
        DWORD_PTR conn = 0x1234;
        SET_ERR(0x4242);
        EXPECT_EQ(f(NULL, name, flags[i], &conn, 1), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(conn, 0);
        EXPECT_ERR(0x4242);
        /* NULL connection out */
        EXPECT_EQ(f(NULL, name, flags[i], NULL, 0), ERROR_INVALID_PARAMETER);
        EXPECT_ERR(0x4242);
        /* valid: no-op */
        conn = 0x1234;
        DWORD r = f(NULL, name, flags[i], &conn, 0);
        CHECKF(r == 0, "%s flags=0x%lx r=%lu", label, flags[i], r);
        EXPECT_EQ(conn, 0);
        EXPECT_ERR(0x4242);
        conn = 0x1234;
        EXPECT_EQ(f(NULL, NULL, flags[i], &conn, 0), 0);
        EXPECT_EQ(conn, 0);
    }
    static const DWORD res[] = { 2, 0x80000000u, 0xFFFFFFFFu };
    for (size_t i = 0; i < 3; i++) {
        DWORD_PTR conn = 7;
        EXPECT_EQ(f(NULL, NULL, 0, &conn, res[i]), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(conn, 0);
    }
}
TEST(gs_dial_a_table)     { REQUIRE(UN(InternetDialA)); gs_dial_table_a((gs_dial_a)UN(InternetDialA), "A"); }
TEST(gs_dial_plain_table) { REQUIRE(UN(InternetDial));  gs_dial_table_a((gs_dial_a)UN(InternetDial), "plain"); }

TEST(gs_dial_w_table) {
    REQUIRE(UN(InternetDialW));
    WCHAR name[] = L"i7-no-such-connectoid";
    for (int r = 0; r < 4; r++) {
        DWORD reserved = r == 0 ? 0 : r == 1 ? 1 : r == 2 ? 0x10 : 0xFFFFFFFFu;
        for (int np = 0; np < 2; np++) {
            DWORD_PTR conn = 0x5555;
            SET_ERR(0x31);
            DWORD res = UN(InternetDialW)(NULL, np ? NULL : name, INTERNET_DIAL_UNATTENDED, &conn, reserved);
            EXPECT_EQ(res, reserved ? ERROR_INVALID_PARAMETER : 0);
            EXPECT_EQ(conn, 0);
            EXPECT_ERR(0x31);
        }
        SET_ERR(0x31);
        EXPECT_EQ(UN(InternetDialW)(NULL, name, 0, NULL, reserved), ERROR_INVALID_PARAMETER);
        EXPECT_ERR(0x31);
    }
}

TEST(gs_dial_plain_is_ansi) {
    REQUIRE(UN(InternetDial)); REQUIRE(UN(InternetDialA));
    t_note("InternetDial == InternetDialA address: %s", (void *)UN(InternetDial) == (void *)UN(InternetDialA) ? "yes" : "no");
    char name[] = "x";
    DWORD_PTR c1 = 9, c2 = 9;
    EXPECT_EQ(UN(InternetDial)(NULL, name, 0, &c1, 0), UN(InternetDialA)(NULL, name, 0, &c2, 0));
    EXPECT_EQ(c1, c2);
}

/* ------------------------------------------------------------------ InternetHangUp */
TEST(gs_hangup_table) {
    REQUIRE(UN(InternetHangUp));
    static const DWORD_PTR conns[] = { 0, 1, 0x1234, (DWORD_PTR)-1 };
    for (size_t c = 0; c < 4; c++) {
        SET_ERR(0x4242);
        for (int b = 0; b < 32; b++)
            CHECKF(UN(InternetHangUp)(conns[c], 1u << b) == ERROR_INVALID_PARAMETER, "conn=%zu bit %d", c, b);
        EXPECT_EQ(UN(InternetHangUp)(conns[c], 0), 0);
        EXPECT_ERR(0x4242);
    }
}

/* ------------------------------------------------------------------ InternetGoOnline */
TEST(gs_goonline_a_flags) {
    REQUIRE(UN(InternetGoOnlineA));
    char url[] = "http://127.0.0.1/";
    for (int b = 2; b < 32; b++) {
        SET_ERR(0);
        CHECKF(!UN(InternetGoOnlineA)(url, NULL, 1u << b), "bit %d", b);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    for (DWORD f = 0; f < 4; f++) {
        SET_ERR(0x4242);
        CHECKF(UN(InternetGoOnlineA)(url, NULL, f), "flags %lu", f);
        EXPECT_ERR(0);
        SET_ERR(0x4242);
        CHECKF(UN(InternetGoOnlineA)(NULL, NULL, f), "NULL url flags %lu", f);
        EXPECT_ERR(0);
    }
}

TEST(gs_goonline_w_flags) {
    REQUIRE(UN(InternetGoOnlineW));
    WCHAR url[] = L"http://127.0.0.1/";
    for (int b = 2; b < 32; b++) {
        SET_ERR(0);
        CHECKF(!UN(InternetGoOnlineW)(url, NULL, 1u << b), "bit %d", b);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    SET_ERR(0);
    CHECK(!UN(InternetGoOnlineW)(NULL, NULL, 0xFFFFFFFFu)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    for (DWORD f = 0; f < 4; f++) {
        SET_ERR(0x4242);
        CHECK(UN(InternetGoOnlineW)(url, NULL, f));
        EXPECT_ERR(0);
    }
}

TEST(gs_goonline_plain) {
    REQUIRE(UN(InternetGoOnline));
    SET_ERR(0); CHECK(!UN(InternetGoOnline)(NULL, NULL, 4)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(InternetGoOnline)(NULL, NULL, 0x80000000u)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0x4242); CHECK(UN(InternetGoOnline)(NULL, NULL, 3)); EXPECT_ERR(0);
}

/* going "online" does not flip the process into offline/online state queries */
TEST(gs_goonline_does_not_set_offline) {
    REQUIRE(UN(InternetGoOnlineA)); REQUIRE(U(InternetQueryOptionA));
    DWORD before = 0, after = 0, l = sizeof before;
    BOOL r1 = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &before, &l);
    UN(InternetGoOnlineA)(NULL, NULL, 0);
    l = sizeof after;
    BOOL r2 = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CONNECTED_STATE, &after, &l);
    CHECK(r1 && r2);
    EXPECT_EQ(before, after);
    t_note("INTERNET_OPTION_CONNECTED_STATE = 0x%lx", after);
}

/* ------------------------------------------------------------------ InternetSetDialState */
TEST(gs_set_dial_state_all_variants) {
    REQUIRE(UN(InternetSetDialStateA)); REQUIRE(UN(InternetSetDialStateW)); REQUIRE(UN(InternetSetDialState));
    static const DWORD states[] = { 0, INTERNET_DIALSTATE_DISCONNECTED, 2, 0x10, 0xFFFFFFFFu };
    static const DWORD res[] = { 0, 1, 0xFFFFFFFFu };
    for (size_t s = 0; s < sizeof states / sizeof states[0]; s++)
        for (size_t r = 0; r < 3; r++) {
            SET_ERR(0); CHECK(!UN(InternetSetDialStateA)("conn", states[s], res[r])); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SET_ERR(0); CHECK(!UN(InternetSetDialStateA)(NULL, states[s], res[r]));   EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SET_ERR(0); CHECK(!UN(InternetSetDialStateW)(L"conn", states[s], res[r])); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SET_ERR(0); CHECK(!UN(InternetSetDialStateW)(NULL, states[s], res[r]));   EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
            SET_ERR(0); CHECK(!UN(InternetSetDialState)("", states[s], res[r]));      EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        }
}

/* ------------------------------------------------------------------ InternetAutodialCallback */
TEST(gs_autodial_callback_noop) {
    REQUIRE(UN(InternetAutodialCallback));
    static const DWORD ops[] = { 0, 1, 2, 3, 4, 0x80000000u, 0xFFFFFFFFu };
    BYTE b[16]; gs_fill(b, sizeof b);
    SET_ERR(0x4242);
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        UN(InternetAutodialCallback)(ops[i], NULL);
        UN(InternetAutodialCallback)(ops[i], b);
    }
    EXPECT_ERR(0x4242);
    CHECK(gs_untouched(b, sizeof b));
}

/* ------------------------------------------------------------------ InternetGetConnectedState(Ex) */
TEST(gs_connected_state_reserved_rejected) {
    REQUIRE(U(InternetGetConnectedState));
    DWORD fl = 0xA5A5;
    BOOL r = U(InternetGetConnectedState)(&fl, 0);
    t_note("InternetGetConnectedState: r=%d flags=0x%lx", r, fl);
    CHECK((fl & ~(DWORD)0xFF) == 0 || fl == 0xA5A5);
    for (int b = 0; b < 32; b++) {
        fl = 0xA5A5;
        SET_ERR(0);
        BOOL rr = U(InternetGetConnectedState)(&fl, 1u << b);
        DWORD e = GetLastError();
        if (b == 0) t_note("InternetGetConnectedState(reserved=1): r=%d e=%lu flags=0x%lx", rr, e, fl);
        CHECKF(!rr && e == ERROR_INVALID_PARAMETER, "reserved bit %d: r=%d e=%lu", b, rr, e);
    }
}

TEST(gs_connected_state_ex_buffers) {
    REQUIRE(U(InternetGetConnectedStateExA)); REQUIRE(U(InternetGetConnectedStateExW));
    char name[256]; WCHAR namew[256]; DWORD fl = 0, flw = 0;
    gs_fill(name, sizeof name);
    BOOL ra = U(InternetGetConnectedStateExA)(&fl, name, sizeof name, 0);
    BOOL rw = U(InternetGetConnectedStateExW)(&flw, namew, 256, 0);
    CHECK(!!ra == !!rw);
    EXPECT_EQ(fl, flw);
    t_note("ConnectedStateEx: A r=%d flags=0x%lx name='%s'", ra, fl, gs_untouched(name, 1) ? "(untouched)" : name);
    SET_ERR(0);
    BOOL r = U(InternetGetConnectedStateExA)(&fl, name, sizeof name, 1);
    t_note("ConnectedStateExA(reserved=1): r=%d e=%lu", r, GetLastError());
    CHECK(!r);
}

/* ------------------------------------------------------------------ ordinals #101, #420, #421 */
/* [D DoConnectoidsExist #101] RAS present -> TRUE/FALSE from RasEnumEntries; RAS missing -> FALSE, 120 */
TEST(gs_ord101_do_connectoids_exist) {
    REQUIRE_ORD(101);
    gs_DoConnectoidsExist f = GS_ORD(gs_DoConnectoidsExist, 101);
    SET_ERR(0x4242);
    BOOL r1 = f();
    DWORD e1 = GetLastError();
    BOOL r2 = f();
    CHECKF(r1 == 0 || r1 == 1, "r=%d", r1);
    EXPECT_EQ(r1, r2);
    t_note("DoConnectoidsExist #101 = %d (GLE %lu)", r1, e1);
    if (!r1) CHECKF(e1 == 0x4242 || e1 == ERROR_CALL_NOT_IMPLEMENTED || e1 == 0, "e=%lu", e1);
}

TEST(gs_ord420_421_lan_dialup) {
    REQUIRE_ORD(420); REQUIRE_ORD(421);
    BOOL lan = 0x5A5A, dial = 0x5A5A;
    HRESULT h1 = GS_ORD(gs_IsLanConnection, 420)(&lan);
    HRESULT h2 = GS_ORD(gs_IsDialUpConnection, 421)(&dial);
    t_note("IsLanConnection #420: hr=0x%lx lan=%d; IsDialUpConnection #421: hr=0x%lx dial=%d", h1, lan, h2, dial);
    if (SUCCEEDED(h1)) CHECKF(lan == 0 || lan == 1, "lan=%d", lan);
    if (SUCCEEDED(h2)) CHECKF(dial == 0 || dial == 1, "dial=%d", dial);
}

TEST(gs_ord422_423_netchange_resolve_only) {
    /* RegisterForNetworkChangeNotification / UnRegister: process-global notification plumbing, resolve only */
    CHECK(gs_ord(422) != NULL);
    CHECK(gs_ord(423) != NULL);
    CHECK(GetProcAddress(t_module("wininet.dll"), "RegisterForNetworkChangeNotification") == NULL);
    CHECK(GetProcAddress(t_module("wininet.dll"), "UnRegisterNetworkChangeNotification") == NULL);
}
