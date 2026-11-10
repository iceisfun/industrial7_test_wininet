/* http_auth: credential options INTERNET_OPTION_USERNAME (28), PASSWORD (29), PROXY_USERNAME (43),
 * PROXY_PASSWORD (44), SUPPRESS_SERVER_AUTH (104) on session / connect / request handles. No network:
 * InternetConnect/HttpOpenRequest for HTTP do not connect.
 * Decomp grounding: InternetQueryOptionA case 0x1c/0x1d/0x2b/0x2c -> NULL handle, session ('Inet') -> 12018,
 * else INTERNET_CONNECT_HANDLE_OBJECT::GetUserOrPass; InternetSetOptionW case 0x1c/0x1d with NULL handle sets the
 * process-global credentials (not used here), 0x2b/0x2c with NULL handle -> TRUE without effect. */
#include "auth.h"

typedef struct { HINTERNET hi, hc, hr; } hset;
static int open_set(hset *h, const char *user, const char *pass) {
    h->hi = t_inet_open(NULL); h->hc = h->hr = NULL;
    if (!h->hi) return 0;
    h->hc = U(InternetConnectA)(h->hi, "127.0.0.1", 9, user, pass, INTERNET_SERVICE_HTTP, 0, 0);   /* never connected */
    if (h->hc) h->hr = U(HttpOpenRequestA)(h->hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0);
    return h->hc && h->hr;
}
static void close_set(hset *h) { a_close(h->hr); a_close(h->hc); a_close(h->hi); }
#define OPEN_OR_SKIP(h, u, p) do { if (!open_set(&(h), (u), (p))) { close_set(&(h)); t_skip("handles unavailable: %lu", GetLastError()); return; } } while (0)

static const DWORD g_cred_opts[] = { INTERNET_OPTION_USERNAME, INTERNET_OPTION_PASSWORD, INTERNET_OPTION_PROXY_USERNAME, INTERNET_OPTION_PROXY_PASSWORD };

TEST(auth_opt_connect_args_queryable_on_connect) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", "cpass");
    char b[64]; DWORD l;
    CHECK(a_qopt(h.hc, INTERNET_OPTION_USERNAME, b, sizeof b, &l)); EXPECT_STR(b, "cuser");
    t_note("A query USERNAME returned length %lu for \"cuser\"", l);
    CHECK(a_qopt(h.hc, INTERNET_OPTION_PASSWORD, b, sizeof b, &l)); EXPECT_STR(b, "cpass");
    t_note("A query PASSWORD returned length %lu for \"cpass\"", l);
    close_set(&h);
}

TEST(auth_opt_connect_args_inherited_by_request) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", "cpass");
    char b[64];
    CHECK(a_qopt(h.hr, INTERNET_OPTION_USERNAME, b, sizeof b, NULL)); EXPECT_STR(b, "cuser");
    CHECK(a_qopt(h.hr, INTERNET_OPTION_PASSWORD, b, sizeof b, NULL)); EXPECT_STR(b, "cpass");
    close_set(&h);
}

TEST(auth_opt_session_handle_rejected) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, "u", "p");
    for (int i = 0; i < 4; i++) {
        char b[64]; DWORD l = sizeof b;
        SET_ERR(0); CHECKF(!U(InternetQueryOptionA)(h.hi, g_cred_opts[i], b, &l), "query opt %lu on session", g_cred_opts[i]); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); CHECKF(!U(InternetSetOptionA)(h.hi, g_cred_opts[i], "x", 1), "set opt %lu on session", g_cred_opts[i]); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        WCHAR w[64]; l = sizeof w;
        SET_ERR(0); CHECKF(!U(InternetQueryOptionW)(h.hi, g_cred_opts[i], w, &l), "queryW opt %lu on session", g_cred_opts[i]); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); CHECKF(!U(InternetSetOptionW)(h.hi, g_cred_opts[i], L"x", 1), "setW opt %lu on session", g_cred_opts[i]); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    close_set(&h);
}

TEST(auth_opt_null_handle_query_rejected) {
    REQUIRE(U(InternetQueryOptionA));
    for (int i = 0; i < 4; i++) {
        char b[64]; DWORD l = sizeof b;
        SET_ERR(0); CHECKF(!U(InternetQueryOptionA)(NULL, g_cred_opts[i], b, &l), "query opt %lu on NULL", g_cred_opts[i]); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
}

TEST(auth_opt_null_handle_set_proxy_creds_accepted) {
    REQUIRE(U(InternetSetOptionA));
    /* decomp: InternetSetOptionW case 0x2b/0x2c, param_1 == 0 -> returns TRUE without storing anything */
    SET_ERR(0); CHECK(U(InternetSetOptionW)(NULL, INTERNET_OPTION_PROXY_USERNAME, L"i7nobody", 8));
    SET_ERR(0); CHECK(U(InternetSetOptionW)(NULL, INTERNET_OPTION_PROXY_PASSWORD, L"i7nothing", 9));
    SET_ERR(0); BOOL a = U(InternetSetOptionA)(NULL, INTERNET_OPTION_PROXY_USERNAME, "i7nobody", 8);
    t_note("InternetSetOptionA(NULL, PROXY_USERNAME) = %d err=%lu", a, a ? 0 : GetLastError());
    CHECK(a);
}

TEST(auth_opt_request_set_and_query_roundtrip) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    static const char *vals[] = { "ruser", "rpass", "pxuser", "pxpass" };
    for (int i = 0; i < 4; i++) {
        CHECKF(U(InternetSetOptionA)(h.hr, g_cred_opts[i], (void *)vals[i], (DWORD)strlen(vals[i])), "set %lu err=%lu", g_cred_opts[i], GetLastError());
        char b[64];
        CHECKF(a_qopt(h.hr, g_cred_opts[i], b, sizeof b, NULL), "query %lu err=%lu", g_cred_opts[i], GetLastError());
        CHECKF(!strcmp(b, vals[i]), "opt %lu: got [%s] want [%s]", g_cred_opts[i], b, vals[i]);
    }
    close_set(&h);
}

TEST(auth_opt_connect_set_and_query_roundtrip) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    static const char *vals[] = { "cu2", "cp2", "pu2", "pp2" };
    for (int i = 0; i < 4; i++) {
        CHECKF(U(InternetSetOptionA)(h.hc, g_cred_opts[i], (void *)vals[i], (DWORD)strlen(vals[i])), "set %lu err=%lu", g_cred_opts[i], GetLastError());
        char b[64];
        CHECKF(a_qopt(h.hc, g_cred_opts[i], b, sizeof b, NULL), "query %lu err=%lu", g_cred_opts[i], GetLastError());
        CHECKF(!strcmp(b, vals[i]), "opt %lu: got [%s] want [%s]", g_cred_opts[i], b, vals[i]);
    }
    close_set(&h);
}

TEST(auth_opt_request_set_does_not_change_connect) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", "cpass");
    CHECK(U(InternetSetOptionA)(h.hr, INTERNET_OPTION_USERNAME, "ruser", 5));
    CHECK(U(InternetSetOptionA)(h.hr, INTERNET_OPTION_PASSWORD, "rpass", 5));
    char b[64];
    CHECK(a_qopt(h.hr, INTERNET_OPTION_USERNAME, b, sizeof b, NULL)); EXPECT_STR(b, "ruser");
    CHECK(a_qopt(h.hc, INTERNET_OPTION_USERNAME, b, sizeof b, NULL)); EXPECT_STR(b, "cuser");
    CHECK(a_qopt(h.hc, INTERNET_OPTION_PASSWORD, b, sizeof b, NULL)); EXPECT_STR(b, "cpass");
    close_set(&h);
}

TEST(auth_opt_connect_set_after_request_open) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", "cpass");
    CHECK(U(InternetSetOptionA)(h.hc, INTERNET_OPTION_USERNAME, "later", 5));
    char b[64];
    CHECK(a_qopt(h.hc, INTERNET_OPTION_USERNAME, b, sizeof b, NULL)); EXPECT_STR(b, "later");
    CHECK(a_qopt(h.hr, INTERNET_OPTION_USERNAME, b, sizeof b, NULL));
    t_note("request USERNAME after connect changed post-open: [%s]", b);
    close_set(&h);
}

TEST(auth_opt_no_connect_creds_query) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    for (int i = 0; i < 4; i++) {
        char b[64] = "zz"; DWORD l = sizeof b; SET_ERR(0);
        BOOL ok = U(InternetQueryOptionA)(h.hc, g_cred_opts[i], b, &l);
        DWORD e = ok ? 0 : GetLastError();
        t_note("no creds: query opt %lu on connect -> ok=%d err=%lu len=%lu val=[%s]", g_cred_opts[i], ok, e, l, ok ? b : "");
        if (ok) CHECKF(b[0] == 0, "opt %lu: [%s]", g_cred_opts[i], b);
        l = sizeof b; ok = U(InternetQueryOptionA)(h.hr, g_cred_opts[i], b, &l);
        if (ok) CHECKF(b[0] == 0, "req opt %lu: [%s]", g_cred_opts[i], b);
    }
    close_set(&h);
}

TEST(auth_opt_query_small_buffer_a) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, "abcdefgh", "p");
    char b[4]; DWORD l = sizeof b; SET_ERR(0);
    CHECK(!U(InternetQueryOptionA)(h.hc, INTERNET_OPTION_USERNAME, b, &l)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    t_note("A small buffer: required length reported %lu for 8 chars", l);
    CHECK(l == 8 || l == 9);
    l = 0; SET_ERR(0);
    CHECK(!U(InternetQueryOptionA)(h.hc, INTERNET_OPTION_USERNAME, NULL, &l)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    t_note("A NULL buffer: required %lu", l);
    char big[64]; DWORD need = l; l = need;
    CHECK(U(InternetQueryOptionA)(h.hc, INTERNET_OPTION_USERNAME, big, &l)); EXPECT_STR(big, "abcdefgh");
    close_set(&h);
}

TEST(auth_opt_query_small_buffer_w) {
    REQUIRE(U(InternetQueryOptionW));
    hset h; OPEN_OR_SKIP(h, "abcdefgh", "p");
    WCHAR w[4]; DWORD l = sizeof w; SET_ERR(0);
    CHECK(!U(InternetQueryOptionW)(h.hc, INTERNET_OPTION_USERNAME, w, &l)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    t_note("W small buffer: required length reported %lu for 8 chars", l);
    WCHAR big[64]; l = sizeof big;
    CHECK(U(InternetQueryOptionW)(h.hc, INTERNET_OPTION_USERNAME, big, &l)); EXPECT_WSTR(big, L"abcdefgh");
    t_note("W query USERNAME returned length %lu for 8 chars", l);
    close_set(&h);
}

TEST(auth_opt_wide_set_query) {
    REQUIRE(U(InternetSetOptionW));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    CHECK(U(InternetSetOptionW)(h.hr, INTERNET_OPTION_USERNAME, L"wide\x00fc", 5));
    CHECK(U(InternetSetOptionW)(h.hr, INTERNET_OPTION_PASSWORD, L"pw", 2));
    WCHAR w[64]; DWORD l = sizeof w;
    CHECK(U(InternetQueryOptionW)(h.hr, INTERNET_OPTION_USERNAME, w, &l)); EXPECT_WSTR(w, L"wide\x00fc");
    l = sizeof w; CHECK(U(InternetQueryOptionW)(h.hr, INTERNET_OPTION_PASSWORD, w, &l)); EXPECT_WSTR(w, L"pw");
    char b[64]; CHECK(a_qopt(h.hr, INTERNET_OPTION_PASSWORD, b, sizeof b, NULL)); EXPECT_STR(b, "pw");
    close_set(&h);
}

TEST(auth_opt_set_ansi_query_wide) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    CHECK(U(InternetSetOptionA)(h.hc, INTERNET_OPTION_USERNAME, "ansiuser", 8));
    WCHAR w[64]; DWORD l = sizeof w;
    CHECK(U(InternetQueryOptionW)(h.hc, INTERNET_OPTION_USERNAME, w, &l)); EXPECT_WSTR(w, L"ansiuser");
    close_set(&h);
}

TEST(auth_opt_set_length_shorter_than_string) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    BOOL ok = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_USERNAME, "abcdef", 3);
    char b[64] = ""; a_qopt(h.hr, INTERNET_OPTION_USERNAME, b, sizeof b, NULL);
    t_note("set USERNAME \"abcdef\" with length 3: ok=%d -> [%s]", ok, b);
    CHECK(ok);
    close_set(&h);
}

TEST(auth_opt_set_zero_length) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", NULL);
    SET_ERR(0); BOOL ok = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_USERNAME, "zl", 0);
    DWORD e = ok ? 0 : GetLastError();
    char b[64] = ""; a_qopt(h.hr, INTERNET_OPTION_USERNAME, b, sizeof b, NULL);
    t_note("set USERNAME with length 0: ok=%d err=%lu -> [%s]", ok, e, b);
    close_set(&h);
}

TEST(auth_opt_set_empty_string) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", "cpass");
    BOOL ok = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_USERNAME, "", 0);
    char b[64] = "zz"; DWORD l = sizeof b; BOOL q = U(InternetQueryOptionA)(h.hr, INTERNET_OPTION_USERNAME, b, &l);
    t_note("set USERNAME \"\": ok=%d; query ok=%d val=[%s] len=%lu", ok, q, q ? b : "", l);
    close_set(&h);
}

TEST(auth_opt_set_null_buffer) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, "cuser", "cpass");
    SET_ERR(0); BOOL ok = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_USERNAME, NULL, 0);
    DWORD e = ok ? 0 : GetLastError();
    t_note("set USERNAME NULL,0: ok=%d err=%lu", ok, e);
    if (!ok) CHECK(e == ERROR_INVALID_PARAMETER || e == ERROR_INTERNET_BAD_OPTION_LENGTH);
    close_set(&h);
}

TEST(auth_opt_long_username) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    char longu[1100]; memset(longu, 'u', 1000); longu[1000] = 0;
    BOOL ok = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_USERNAME, longu, 1000);
    DWORD e = ok ? 0 : GetLastError();
    char b[1100] = ""; DWORD l = sizeof b; BOOL q = U(InternetQueryOptionA)(h.hr, INTERNET_OPTION_USERNAME, b, &l);
    t_note("1000-char USERNAME: set ok=%d err=%lu, query ok=%d len=%lu strlen=%zu", ok, e, q, l, strlen(b));
    CHECK(ok);
    if (q) EXPECT_EQ(strlen(b), 1000);
    close_set(&h);
}

TEST(auth_opt_suppress_server_auth) {
    REQUIRE(U(InternetSetOptionA));
    hset h; OPEN_OR_SKIP(h, NULL, NULL);
    DWORD v = 1;
    BOOL r = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v); DWORD er = r ? 0 : GetLastError();
    BOOL c = U(InternetSetOptionA)(h.hc, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v); DWORD ec = c ? 0 : GetLastError();
    BOOL s = U(InternetSetOptionA)(h.hi, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v); DWORD es = s ? 0 : GetLastError();
    BOOL n = U(InternetSetOptionA)(h.hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, NULL, 0); DWORD en = n ? 0 : GetLastError();
    DWORD q = 0, ql = sizeof q; BOOL qq = U(InternetQueryOptionA)(h.hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &q, &ql); DWORD eq = qq ? 0 : GetLastError();
    t_note("SUPPRESS_SERVER_AUTH set: request ok=%d err=%lu; connect ok=%d err=%lu; session ok=%d err=%lu; NULL buf ok=%d err=%lu; query ok=%d err=%lu",
           r, er, c, ec, s, es, n, en, qq, eq);
    close_set(&h);
}

TEST(auth_opt_closed_request_handle) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, "u", "p");
    HINTERNET hr2 = U(HttpOpenRequestA)(h.hc, "GET", "/2", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr2 != NULL);
    char b[64];
    CHECK(a_qopt(hr2, INTERNET_OPTION_USERNAME, b, sizeof b, NULL)); EXPECT_STR(b, "u");
    a_close(hr2);
    close_set(&h);
}

TEST(auth_opt_request_handle_after_connect_closed) {
    REQUIRE(U(InternetQueryOptionA));
    hset h; OPEN_OR_SKIP(h, "u", "p");
    /* the request handle keeps its own copy of the credentials after its parent goes away */
    char b[64];
    CHECK(a_qopt(h.hr, INTERNET_OPTION_USERNAME, b, sizeof b, NULL)); EXPECT_STR(b, "u");
    a_close(h.hr); h.hr = NULL;
    close_set(&h);
}
