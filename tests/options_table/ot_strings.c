/* options_table: string-valued options and their exact size contracts on A and W.
 * Rules (decomp InternetQueryOptionA@0x59730 common string tail; InternetQueryOptionW@0xc5d50):
 *   A: success *len = strlen (no NUL); ERROR_INSUFFICIENT_BUFFER *len = strlen + 1.
 *   W generic path (28, 29, 41, 43, 44, 53, 83): the W wrapper queries A into a temporary buffer of *len BYTES, converts
 *     with MultiByteToWideChar(CP_ACP); success *len = characters without NUL; 122 *len = BYTES with NUL ((n+1)*2).
 *   W URL (34): UrlCharToWChar, same units (success chars, 122 bytes incl. NUL).
 *   Set W: string options take dwBufferLength in characters (InternetSetOptionW@0x53e10).
 * Credentials used here are dummies on a loopback connect that is never authenticated. */
#include "ot.h"

static void check_str_a(HINTERNET h, DWORD opt, const char *want, int line) {
    char buf[512]; DWORD n = (DWORD)strlen(want), l;
    l = 0; SET_ERR(0);
    BOOL r = U(InternetQueryOptionA)(h, opt, NULL, &l);
    t_check(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l == n + 1, __FILE__, line, "A NULL buffer", "opt %lu r=%d err=%lu len=%lu want 122/%lu", opt, r, GetLastError(), l, n + 1);
    l = n; memset(buf, 'Z', sizeof buf); SET_ERR(0);
    r = U(InternetQueryOptionA)(h, opt, buf, &l);
    t_check(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l == n + 1, __FILE__, line, "A len=strlen", "opt %lu r=%d err=%lu len=%lu want 122/%lu", opt, r, GetLastError(), l, n + 1);
    t_check(buf[0] == 'Z', __FILE__, line, "A short buffer untouched", "opt %lu first byte 0x%02x", opt, (unsigned char)buf[0]);
    l = n + 1; memset(buf, 'Z', sizeof buf); SET_ERR(0xdead);
    r = U(InternetQueryOptionA)(h, opt, buf, &l);
    t_check(r && l == n && !strcmp(buf, want), __FILE__, line, "A exact", "opt %lu r=%d err=%lu len=%lu want %lu value '%s' want '%s'", opt, r, GetLastError(), l, n, r ? buf : "", want);
    l = sizeof buf; memset(buf, 'Z', sizeof buf);
    r = U(InternetQueryOptionA)(h, opt, buf, &l);
    t_check(r && l == n && !strcmp(buf, want) && buf[n + 1] == 'Z', __FILE__, line, "A large", "opt %lu r=%d len=%lu", opt, r, l);
}

static void check_str_w(HINTERNET h, DWORD opt, const char *want, int line) {
    WCHAR buf[512], ww[512]; DWORD n = (DWORD)strlen(want), l;
    for (DWORD i = 0; i <= n; i++) ww[i] = (unsigned char)want[i];
    l = 0; SET_ERR(0);
    BOOL r = U(InternetQueryOptionW)(h, opt, NULL, &l);
    t_check(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l == (n + 1) * 2, __FILE__, line, "W NULL buffer", "opt %lu r=%d err=%lu len=%lu want 122/%lu", opt, r, GetLastError(), l, (n + 1) * 2);
    l = n * 2 + 1; SET_ERR(0);                   /* one byte short of (n+1)*2 */
    r = U(InternetQueryOptionW)(h, opt, buf, &l);
    t_check(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l == (n + 1) * 2, __FILE__, line, "W one byte short", "opt %lu r=%d err=%lu len=%lu want 122/%lu", opt, r, GetLastError(), l, (n + 1) * 2);
    l = n + 1; SET_ERR(0);                       /* characters instead of bytes: too small */
    r = U(InternetQueryOptionW)(h, opt, buf, &l);
    if (n) t_check(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l == (n + 1) * 2, __FILE__, line, "W len in chars", "opt %lu r=%d err=%lu len=%lu want 122/%lu", opt, r, GetLastError(), l, (n + 1) * 2);
    l = (n + 1) * 2; memset(buf, 0x5A, sizeof buf); SET_ERR(0xdead);
    r = U(InternetQueryOptionW)(h, opt, buf, &l);
    t_check(r && l == n && !lstrcmpW(buf, ww), __FILE__, line, "W exact", "opt %lu r=%d err=%lu len=%lu want %lu", opt, r, GetLastError(), l, n);
    l = sizeof buf; memset(buf, 0x5A, sizeof buf);
    r = U(InternetQueryOptionW)(h, opt, buf, &l);
    t_check(r && l == n && !lstrcmpW(buf, ww), __FILE__, line, "W large", "opt %lu r=%d len=%lu", opt, r, l);
}
#define STR_A(h, o, s) check_str_a((h), (o), (s), __LINE__)
#define STR_W(h, o, s) check_str_w((h), (o), (s), __LINE__)
#define STR_AW(h, o, s) do { STR_A(h, o, s); STR_W(h, o, s); } while (0)

/* ---------------------------------------------------------------- USER_AGENT (41): session only */
TEST(ot_str_user_agent_default) {
    REQUIRE(U(InternetQueryOptionW));
    HINTERNET s = U(InternetOpenA)("ot-agent/1.0 (probe)", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    STR_AW(s, INTERNET_OPTION_USER_AGENT, "ot-agent/1.0 (probe)");
    U(InternetCloseHandle)(s);
}

TEST(ot_str_user_agent_null_agent) {
    REQUIRE(U(InternetQueryOptionW));
    HINTERNET s = U(InternetOpenA)(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    char b[16]; DWORD l = sizeof b; memset(b, 'Z', sizeof b);
    BOOL r = U(InternetQueryOptionA)(s, INTERNET_OPTION_USER_AGENT, b, &l);
    /* VM: an empty agent string, TRUE with *len 0 and a NUL written */
    CHECKF(r, "USER_AGENT with a NULL agent: err %lu", GetLastError());
    if (r) { EXPECT_EQ(l, 0); EXPECT_EQ(b[0], 0); }
    l = 0; SET_ERR(0); r = U(InternetQueryOptionA)(s, INTERNET_OPTION_USER_AGENT, NULL, &l);
    CHECKF(!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER && l == 1, "NULL buffer: r=%d err=%lu len=%lu", r, GetLastError(), l);
    U(InternetCloseHandle)(s);
}

TEST(ot_str_user_agent_set_a) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    static const char ua[] = "Mozilla/5.0 (ot) wininet-conformance";
    CHECK(U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)ua, (DWORD)strlen(ua)));
    STR_AW(s, INTERNET_OPTION_USER_AGENT, ua);
    CHECK(U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, (void *)"x", 1));
    STR_AW(s, INTERNET_OPTION_USER_AGENT, "x");
    U(InternetCloseHandle)(s);
}

TEST(ot_str_user_agent_set_w_chars) {
    REQUIRE(U(InternetSetOptionW));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    static const WCHAR ua[] = L"wide-agent-0123456789";
    CHECK(U(InternetSetOptionW)(s, INTERNET_OPTION_USER_AGENT, (void *)ua, (DWORD)lstrlenW(ua)));  /* characters */
    STR_AW(s, INTERNET_OPTION_USER_AGENT, "wide-agent-0123456789");
    /* a length shorter than the string: the W wrapper copies that many characters */
    CHECK(U(InternetSetOptionW)(s, INTERNET_OPTION_USER_AGENT, (void *)ua, 4));
    STR_AW(s, INTERNET_OPTION_USER_AGENT, "wide");
    U(InternetCloseHandle)(s);
}

TEST(ot_str_user_agent_wrong_handles) {
    REQUIRE(U(InternetQueryOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.c, t.r };
    for (int k = 0; k < 2; k++)
        for (int w = 0; w < 2; w++) {
            char b[64]; DWORD l = sizeof b;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, hs[k], INTERNET_OPTION_USER_AGENT, b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], INTERNET_OPTION_USER_AGENT, w ? (void *)L"a" : (void *)"a", 1), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        }
    char b[64]; DWORD l = sizeof b;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_USER_AGENT, b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    EXPECT_EQ(l, 0);
    ot_trio_close(&t);
}

/* ---------------------------------------------------------------- URL (34): request handles */
TEST(ot_str_url_request) {
    REQUIRE(U(InternetQueryOptionW));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    STR_AW(t.r, INTERNET_OPTION_URL, "http://127.0.0.1/trio");
    HINTERNET r2 = U(HttpOpenRequestA)(t.c, "POST", "/a/b?c=d&e", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(r2 != NULL);
    if (r2) { STR_AW(r2, INTERNET_OPTION_URL, "http://127.0.0.1/a/b?c=d&e"); U(InternetCloseHandle)(r2); }
    HINTERNET r3 = U(HttpOpenRequestA)(t.c, "GET", "/sec", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    if (r3) { STR_AW(r3, INTERNET_OPTION_URL, "https://127.0.0.1:80/sec"); U(InternetCloseHandle)(r3); }
    ot_trio_close(&t);
}

TEST(ot_str_url_with_port_and_sent) {
    REQUIRE(U(InternetQueryOptionW));
    ot_fx *fx = ot_fx_all(); if (!fx || !fx->h[OT_X]) { t_skip("fixture"); return; }
    STR_AW(fx->h[OT_X], INTERNET_OPTION_URL, fx->url_x);
    if (fx->h[OT_R]) STR_AW(fx->h[OT_R], INTERNET_OPTION_URL, fx->url_r);
    if (fx->h[OT_T]) STR_AW(fx->h[OT_T], INTERNET_OPTION_URL, fx->url_t);
}

TEST(ot_str_url_wrong_handles) {
    REQUIRE(U(InternetQueryOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c };
    for (int k = 0; k < 2; k++)
        for (int w = 0; w < 2; w++) {
            char b[256]; DWORD l = sizeof b;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, hs[k], INTERNET_OPTION_URL, b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        }
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(t.r, INTERNET_OPTION_URL, NULL, NULL), ERROR_INVALID_PARAMETER);
    ot_trio_close(&t);
}

/* ---------------------------------------------------------------- USERNAME / PASSWORD (28/29), PROXY_* (43/44) */
TEST(ot_str_username_password_connect) {
    REQUIRE(U(InternetQueryOptionW));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, "ot_user", "ot_dummy_pw", INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    if (c) {
        STR_AW(c, INTERNET_OPTION_USERNAME, "ot_user");
        STR_AW(c, INTERNET_OPTION_PASSWORD, "ot_dummy_pw");
        HINTERNET r = U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0);
        if (r) {
            char b[64]; DWORD l = sizeof b;
            BOOL ok = U(InternetQueryOptionA)(r, INTERNET_OPTION_USERNAME, b, &l);
            /* the request answers the connect's credentials (VM) */
            CHECKF(ok && l == 7 && !strcmp(b, "ot_user"), "request USERNAME: r=%d err=%lu len=%lu '%s'", ok, ok ? 0 : GetLastError(), l, ok ? b : "");
            U(InternetCloseHandle)(r);
        }
        U(InternetCloseHandle)(c);
    }
    U(InternetCloseHandle)(s);
}

TEST(ot_str_username_set_roundtrip) {
    REQUIRE(U(InternetSetOptionW));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.c, t.r };
    for (int k = 0; k < 2; k++) {
        CHECK(U(InternetSetOptionA)(hs[k], INTERNET_OPTION_USERNAME, (void *)"alpha_user", 10));
        STR_AW(hs[k], INTERNET_OPTION_USERNAME, "alpha_user");
        CHECK(U(InternetSetOptionA)(hs[k], INTERNET_OPTION_PASSWORD, (void *)"beta_dummy", 10));
        STR_AW(hs[k], INTERNET_OPTION_PASSWORD, "beta_dummy");
        CHECK(U(InternetSetOptionW)(hs[k], INTERNET_OPTION_USERNAME, (void *)L"gamma", 5));
        STR_AW(hs[k], INTERNET_OPTION_USERNAME, "gamma");
        CHECK(U(InternetSetOptionW)(hs[k], INTERNET_OPTION_PASSWORD, (void *)L"delta_pw", 8));
        STR_AW(hs[k], INTERNET_OPTION_PASSWORD, "delta_pw");
        CHECK(U(InternetSetOptionA)(hs[k], INTERNET_OPTION_PROXY_USERNAME, (void *)"px_user", 7));
        STR_AW(hs[k], INTERNET_OPTION_PROXY_USERNAME, "px_user");
        CHECK(U(InternetSetOptionA)(hs[k], INTERNET_OPTION_PROXY_PASSWORD, (void *)"px_dummy", 8));
        STR_AW(hs[k], INTERNET_OPTION_PROXY_PASSWORD, "px_dummy");
    }
    ot_trio_close(&t);
}

TEST(ot_str_credentials_session_rejected) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    static const DWORD opts[] = { INTERNET_OPTION_USERNAME, INTERNET_OPTION_PASSWORD, INTERNET_OPTION_PROXY_USERNAME, INTERNET_OPTION_PROXY_PASSWORD };
    for (int i = 0; i < 4; i++) {
        char b[32]; DWORD l = sizeof b;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(s, opts[i], b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, opts[i], (void *)"abc", 3), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionW)(s, opts[i], (void *)L"abc", 3), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    U(InternetCloseHandle)(s);
}

TEST(ot_str_secondary_cache_key) {
    REQUIRE(U(InternetSetOptionW));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    CHECK(U(InternetSetOptionA)(t.r, INTERNET_OPTION_SECONDARY_CACHE_KEY, (void *)"post-key-1", 10));
    STR_AW(t.r, INTERNET_OPTION_SECONDARY_CACHE_KEY, "post-key-1");
    CHECK(U(InternetSetOptionW)(t.r, INTERNET_OPTION_SECONDARY_CACHE_KEY, (void *)L"wkey", 4));
    STR_AW(t.r, INTERNET_OPTION_SECONDARY_CACHE_KEY, "wkey");
    char b[32]; DWORD l = sizeof b;
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.c, INTERNET_OPTION_SECONDARY_CACHE_KEY, (void *)"k", 1), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.s, INTERNET_OPTION_SECONDARY_CACHE_KEY, (void *)"k", 1), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    ot_trio_close(&t);
}
