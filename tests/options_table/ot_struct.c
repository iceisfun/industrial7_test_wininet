/* options_table: structure-valued options on session handles: PROXY (38) as INTERNET_PROXY_INFO on A and W,
 * per-session proxy set/get (never the NULL handle: that would change the process-wide proxy), USER_AGENT edge
 * cases. No traffic: the proxy addresses are never contacted.
 * Decomp: InternetQueryOptionA case 0x26 (session proxy info -> INTERNET_PROXY_INFO + strings packed after it),
 * InternetSetOptionA case 0x26 / 0x29 (USER_AGENT: empty string -> 12010). */
#include "ot.h"
typedef struct { DWORD dwAccessType; LPCWSTR lpszProxy; LPCWSTR lpszProxyBypass; } ot_proxy_info_w;

static void q_proxy_a(HINTERNET h, DWORD *type, char *proxy, char *bypass, DWORD *need) {
    static BYTE b[2048]; DWORD l = 0;
    *type = 0xdead; proxy[0] = bypass[0] = 0; *need = 0;
    SET_ERR(0);
    BOOL r = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, NULL, &l);
    CHECKF(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "PROXY NULL buffer r=%d err=%lu", r, GetLastError());
    *need = l;
    CHECKF(l >= sizeof(INTERNET_PROXY_INFO), "PROXY need %lu", l);
    DWORD l2 = l - 1; SET_ERR(0);
    r = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, b, &l2);
    CHECKF(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l2 == l, "PROXY need-1: r=%d err=%lu len %lu want %lu", r, GetLastError(), l2, l);
    l2 = l; memset(b, 0xCC, sizeof b);
    r = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, b, &l2);
    CHECKF(r, "PROXY exact err %lu", GetLastError());
    if (!r) return;
    INTERNET_PROXY_INFO *pi = (INTERNET_PROXY_INFO *)b;
    *type = pi->dwAccessType;
    if (pi->lpszProxy) { CHECK((BYTE *)pi->lpszProxy >= b && (BYTE *)pi->lpszProxy < b + l); lstrcpynA(proxy, (const char *)pi->lpszProxy, 256); }
    if (pi->lpszProxyBypass) { CHECK((BYTE *)pi->lpszProxyBypass >= b && (BYTE *)pi->lpszProxyBypass < b + l); lstrcpynA(bypass, (const char *)pi->lpszProxyBypass, 256); }
    t_note("PROXY A: type %lu proxy '%s' bypass '%s' len %lu (in %lu)", *type, proxy, bypass, l2, l);
}

TEST(ot_struct_proxy_direct_session) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    DWORD type, need; char p[256], b[256];
    q_proxy_a(s, &type, p, b, &need);
    EXPECT_EQ(type, INTERNET_OPEN_TYPE_DIRECT);
    EXPECT_STR(p, "");
    U(InternetCloseHandle)(s);
}

TEST(ot_struct_proxy_named_session) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:9", "<local>", 0);
    if (!s) { t_skip("InternetOpen PROXY err %lu", GetLastError()); return; }
    DWORD type, need; char p[256], b[256];
    q_proxy_a(s, &type, p, b, &need);
    EXPECT_EQ(type, INTERNET_OPEN_TYPE_PROXY);
    EXPECT_STR(p, "127.0.0.1:9");
    /* the stored bypass list starts with the proxy server itself (VM): "127.0.0.1:9 <local>", 24 + 12 + 20 bytes */
    EXPECT_STR(b, "127.0.0.1:9 <local>");
    EXPECT_EQ(need, 56);
    /* W: InternetQueryOptionW forwards 38 to the A body unchanged (decomp: no W case for 0x26), so the W caller
     * gets the same size and ANSI strings behind the LPCWSTR fields (VM) */
    static BYTE w[4096]; DWORD lw = 0;
    SET_ERR(0); BOOL r = U(InternetQueryOptionW)(s, INTERNET_OPTION_PROXY, NULL, &lw);
    CHECKF(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "W NULL r=%d err=%lu", r, GetLastError());
    EXPECT_EQ(lw, need);
    DWORD l2 = sizeof w;
    r = U(InternetQueryOptionW)(s, INTERNET_OPTION_PROXY, w, &l2);
    CHECKF(r, "W err %lu", GetLastError());
    if (r) {
        ot_proxy_info_w *pw = (ot_proxy_info_w *)w;
        EXPECT_EQ(pw->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
        EXPECT_EQ(l2, need);
        CHECK(pw->lpszProxy && !strcmp((const char *)pw->lpszProxy, "127.0.0.1:9"));
        CHECK(pw->lpszProxyBypass && !strcmp((const char *)pw->lpszProxyBypass, "127.0.0.1:9 <local>"));
    }
    U(InternetCloseHandle)(s);
}

TEST(ot_struct_proxy_set_on_session) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"127.0.0.1:8", (LPCTSTR)"*.example" };
    SET_ERR(0); BOOL r = U(InternetSetOptionA)(s, INTERNET_OPTION_PROXY, &pi, sizeof pi);
    CHECKF(r, "set PROXY on session err %lu", GetLastError());
    if (r) {
        DWORD type, need; char p[256], b[256];
        q_proxy_a(s, &type, p, b, &need);
        EXPECT_EQ(type, INTERNET_OPEN_TYPE_PROXY);
        EXPECT_STR(p, "127.0.0.1:8");
        EXPECT_STR(b, "127.0.0.1:8 *.example");    /* proxy prepended to the bypass list (VM) */
        EXPECT_EQ(need, 58);
        INTERNET_PROXY_INFO d = { INTERNET_OPEN_TYPE_DIRECT, NULL, NULL };
        CHECK(U(InternetSetOptionA)(s, INTERNET_OPTION_PROXY, &d, sizeof d));
        q_proxy_a(s, &type, p, b, &need);
        EXPECT_EQ(type, INTERNET_OPEN_TYPE_DIRECT);
        EXPECT_EQ(need, sizeof(INTERNET_PROXY_INFO));
    }
    /* wrong handle types: connect / request (decomp: 12018) */
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 1, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET rq = c ? U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    if (rq) {
        BYTE b[512]; DWORD l = sizeof b;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(c, INTERNET_OPTION_PROXY, b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        l = sizeof b; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(rq, INTERNET_OPTION_PROXY, b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(c, INTERNET_OPTION_PROXY, &pi, sizeof pi), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        U(InternetCloseHandle)(rq);
    }
    if (c) U(InternetCloseHandle)(c);
    U(InternetCloseHandle)(s);
}

TEST(ot_struct_proxy_set_short_length) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"127.0.0.1:8", NULL };
    static const DWORD lens[] = { 4, 8, 16, 23 };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_PROXY, &pi, lens[i]), ERROR_INTERNET_BAD_OPTION_LENGTH);
    }
    DWORD type, need; char p[256], b[256];
    q_proxy_a(s, &type, p, b, &need);
    EXPECT_EQ(type, INTERNET_OPEN_TYPE_DIRECT);    /* nothing was applied */
    U(InternetCloseHandle)(s);
}

TEST(ot_struct_user_agent_empty_and_nul) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    /* case 0x29: first character NUL -> 12010, agent unchanged */
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)"", 1), ERROR_INTERNET_BAD_OPTION_LENGTH);
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)"\0abc", 4), ERROR_INTERNET_BAD_OPTION_LENGTH);
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)"abc", 0), ERROR_INVALID_PARAMETER);
    char b[64]; DWORD l = sizeof b;
    CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_USER_AGENT, b, &l));
    EXPECT_STR(b, OT_AGENT);
    /* A copies a NUL-terminated string: the length beyond the first NUL is ignored */
    SET_ERR(0); BOOL r = U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)"ab\0cd", 5);
    CHECK(r);
    l = sizeof b; CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_USER_AGENT, b, &l));
    EXPECT_STR(b, "ab"); EXPECT_EQ(l, 2);
    /* W: L"" -> 12010 too (W converts, then the A body sees an empty string) */
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionW)(s, INTERNET_OPTION_USER_AGENT, (void *)L"", 1), ERROR_INTERNET_BAD_OPTION_LENGTH);
    U(InternetCloseHandle)(s);
}

TEST(ot_struct_user_agent_long) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    static char ua[3001]; for (int i = 0; i < 3000; i++) ua[i] = 'a' + i % 26; ua[3000] = 0;
    CHECK(U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, ua, 3000));
    static char b[4096]; DWORD l = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(s, INTERNET_OPTION_USER_AGENT, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 3001);
    l = sizeof b; CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_USER_AGENT, b, &l));
    EXPECT_EQ(l, 3000); CHECK(!strcmp(b, ua));
    DWORD lw = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(s, INTERNET_OPTION_USER_AGENT, NULL, &lw), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(lw, 6002);
    U(InternetCloseHandle)(s);
}
