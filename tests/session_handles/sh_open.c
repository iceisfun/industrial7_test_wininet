/* session_handles / InternetOpenA/W: access types, proxy strings, agents, flags, session option defaults.
 * VM_TIMEOUT: 240
 * Evidence: [D InternalInternetOpen@0xe0650, InternetOpenW@0x515a0, InternetQueryOptionA@0x59730], VM runs (EVIDENCE.md). */
#include "sh.h"

/* ------------------------------------------------------------------ access types */
typedef struct { DWORD access; const char *proxy; int ok; } sh_access_row;
static const sh_access_row sh_access_tab[] = {
    { INTERNET_OPEN_TYPE_PRECONFIG, NULL, 1 },
    { INTERNET_OPEN_TYPE_DIRECT, NULL, 1 },
    { INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:9", 1 },
    { INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY, NULL, 1 },
    { INTERNET_OPEN_TYPE_PROXY, NULL, 0 },
    { INTERNET_OPEN_TYPE_PROXY, "", 0 },
    { 2, NULL, 0 }, { 5, NULL, 0 }, { 6, NULL, 0 }, { 7, NULL, 0 }, { 8, NULL, 0 }, { 9, NULL, 0 },
    { 0x10, NULL, 0 }, { 0x14, NULL, 0 }, { 99, NULL, 0 }, { 0x100, NULL, 0 }, { 0x80000000u, NULL, 0 },
    { 0xffffffffu, NULL, 0 }, { 0xfffffffbu, NULL, 0 },
    /* a proxy string does not rescue an invalid access type */
    { 2, "127.0.0.1:9", 0 }, { 7, "127.0.0.1:9", 0 },
    /* a proxy string with a non-PROXY access type is accepted */
    { INTERNET_OPEN_TYPE_DIRECT, "127.0.0.1:9", 1 },
    { INTERNET_OPEN_TYPE_PRECONFIG, "127.0.0.1:9", 1 },
};

TEST(sh_open_a_access_type_table) {
    REQUIRE(U(InternetOpenA));
    for (size_t i = 0; i < sizeof sh_access_tab / sizeof *sh_access_tab; i++) {
        const sh_access_row *r = &sh_access_tab[i];
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("sh-agent", r->access, r->proxy, NULL, 0);
        DWORD e = GetLastError();
        if (r->ok) {
            CHECKF(h != NULL, "row %u access 0x%lx proxy %s: err %lu", (unsigned)i, r->access, r->proxy ? r->proxy : "(null)", e);
            if (h) { EXPECT_EQ(e, 0); EXPECT_EQ(sh_htype(h, NULL), INTERNET_HANDLE_TYPE_INTERNET); CHECK(sh_close(h)); }
        } else {
            CHECKF(h == NULL, "row %u access 0x%lx should fail", (unsigned)i, r->access);
            CHECKF(e == ERROR_INVALID_PARAMETER, "row %u access 0x%lx err %lu want 87", (unsigned)i, r->access, e);
            if (h) sh_close(h);
        }
    }
}

TEST(sh_open_w_access_type_table) {
    REQUIRE(U(InternetOpenW));
    for (size_t i = 0; i < sizeof sh_access_tab / sizeof *sh_access_tab; i++) {
        const sh_access_row *r = &sh_access_tab[i];
        WCHAR wp[64]; LPCWSTR p = NULL;
        if (r->proxy) { MultiByteToWideChar(CP_ACP, 0, r->proxy, -1, wp, 64); p = wp; }
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenW)(L"sh-agent", r->access, p, NULL, 0);
        DWORD e = GetLastError();
        if (r->ok) {
            CHECKF(h != NULL, "row %u access 0x%lx: err %lu", (unsigned)i, r->access, e);
            if (h) { EXPECT_EQ(e, 0); EXPECT_EQ(sh_htype(h, NULL), INTERNET_HANDLE_TYPE_INTERNET); CHECK(sh_close(h)); }
        } else {
            CHECKF(h == NULL, "row %u access 0x%lx should fail", (unsigned)i, r->access);
            CHECKF(e == ERROR_INVALID_PARAMETER, "row %u access 0x%lx err %lu want 87", (unsigned)i, r->access, e);
            if (h) sh_close(h);
        }
    }
}

TEST(sh_open_a_direct_basic) {
    REQUIRE(U(InternetOpenA));
    SetLastError(0xdeadbeef);
    HINTERNET h = U(InternetOpenA)("sh-basic", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL);
    EXPECT_EQ(GetLastError(), 0);
    if (!h) return;
    DWORD e; EXPECT_EQ(sh_htype(h, &e), INTERNET_HANDLE_TYPE_INTERNET); EXPECT_EQ(e, 0);
    SetLastError(0xdeadbeef);
    CHECK(sh_close(h));
}

TEST(sh_open_w_direct_basic) {
    REQUIRE(U(InternetOpenW));
    SetLastError(0xdeadbeef);
    HINTERNET h = U(InternetOpenW)(L"sh-basic-w", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL);
    EXPECT_EQ(GetLastError(), 0);
    if (!h) return;
    EXPECT_EQ(sh_htype(h, NULL), INTERNET_HANDLE_TYPE_INTERNET);
    CHECK(sh_close(h));
}

TEST(sh_open_proxy_null_and_empty_87) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetOpenW));
    SetLastError(0); HINTERNET h = U(InternetOpenA)("a", INTERNET_OPEN_TYPE_PROXY, NULL, NULL, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER); if (h) sh_close(h);
    SetLastError(0); h = U(InternetOpenA)("a", INTERNET_OPEN_TYPE_PROXY, "", NULL, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER); if (h) sh_close(h);
    SetLastError(0); h = U(InternetOpenA)("a", INTERNET_OPEN_TYPE_PROXY, NULL, "<local>", 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER); if (h) sh_close(h);
    SetLastError(0); h = U(InternetOpenW)(L"a", INTERNET_OPEN_TYPE_PROXY, NULL, NULL, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER); if (h) sh_close(h);
    SetLastError(0); h = U(InternetOpenW)(L"a", INTERNET_OPEN_TYPE_PROXY, L"", NULL, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER); if (h) sh_close(h);
}

TEST(sh_open_null_agent_ok) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetOpenW));
    SetLastError(0xdeadbeef);
    HINTERNET h = U(InternetOpenA)(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL); EXPECT_EQ(GetLastError(), 0);
    if (h) {
        char buf[64]; DWORD len, e;
        CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
        EXPECT_STR(buf, ""); EXPECT_EQ(len, 0);
        sh_close(h);
    }
    h = U(InternetOpenW)(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL);
    if (h) {
        WCHAR wb[32]; DWORD len, e;
        CHECK(sh_qstrw(h, INTERNET_OPTION_USER_AGENT, wb, sizeof wb, &len, &e));
        EXPECT_WSTR(wb, L""); EXPECT_EQ(len, 0);
        sh_close(h);
    }
}

TEST(sh_open_empty_agent_ok) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL);
    if (!h) return;
    char buf[16]; DWORD len, e;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    EXPECT_STR(buf, ""); EXPECT_EQ(len, 0);
    sh_close(h);
}

/* ------------------------------------------------------------------ user agent query protocol (A) */
TEST(sh_open_agent_query_a_protocol) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET h = sh_open("Agent/1.0 (sh)");
    CHECK(h != NULL); if (!h) return;
    const DWORD n = (DWORD)strlen("Agent/1.0 (sh)");
    /* NULL buffer: size query -> 122, chars incl NUL */
    DWORD len = 0;
    SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, NULL, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, n + 1);
    /* NULL buffer with a nonzero length: still a size query */
    len = 100; SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, NULL, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, n + 1);
    /* exactly strlen: one short */
    char buf[64]; memset(buf, 'x', sizeof buf);
    len = n; SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, buf, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, n + 1);
    /* exact fit */
    len = n + 1; memset(buf, 'x', sizeof buf); SetLastError(0xdeadbeef);
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, buf, &len));
    EXPECT_EQ(len, n); EXPECT_STR(buf, "Agent/1.0 (sh)");
    EXPECT_EQ(GetLastError(), 0);
    /* larger buffer */
    len = sizeof buf; memset(buf, 'x', sizeof buf);
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, buf, &len));
    EXPECT_EQ(len, n); EXPECT_STR(buf, "Agent/1.0 (sh)");
    /* NULL length pointer */
    SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, buf, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    sh_close(h);
}

/* W: success length in characters, 122 length in bytes incl NUL */
TEST(sh_open_agent_query_w_protocol) {
    REQUIRE(U(InternetOpenW)); REQUIRE(U(InternetQueryOptionW));
    HINTERNET h = U(InternetOpenW)(L"WideAgent/2", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL); if (!h) return;
    const DWORD n = 11;
    DWORD len = 0; SetLastError(0);
    CHECK(!U(InternetQueryOptionW)(h, INTERNET_OPTION_USER_AGENT, NULL, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, (n + 1) * 2);
    WCHAR wb[64];
    len = n * 2; SetLastError(0);
    CHECK(!U(InternetQueryOptionW)(h, INTERNET_OPTION_USER_AGENT, wb, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, (n + 1) * 2);
    len = (n + 1) * 2;
    CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_USER_AGENT, wb, &len));
    EXPECT_EQ(len, n); EXPECT_WSTR(wb, L"WideAgent/2");
    len = sizeof wb;
    CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_USER_AGENT, wb, &len));
    EXPECT_EQ(len, n); EXPECT_WSTR(wb, L"WideAgent/2");
    /* the same session read through the A entry point */
    char ab[64]; DWORD al, e;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, ab, sizeof ab, &al, &e));
    EXPECT_STR(ab, "WideAgent/2"); EXPECT_EQ(al, n);
    sh_close(h);
}

TEST(sh_open_agent_a_set_w_query) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionW));
    HINTERNET h = sh_open("narrow-agent");
    CHECK(h != NULL); if (!h) return;
    WCHAR wb[64]; DWORD len, e;
    CHECK(sh_qstrw(h, INTERNET_OPTION_USER_AGENT, wb, sizeof wb, &len, &e));
    EXPECT_WSTR(wb, L"narrow-agent"); EXPECT_EQ(len, 12);
    sh_close(h);
}

TEST(sh_open_agent_long_roundtrip) {
    REQUIRE(U(InternetOpenA));
    static char ua[4097];
    for (int i = 0; i < 4096; i++) ua[i] = (char)('a' + i % 26);
    ua[4096] = 0;
    HINTERNET h = sh_open(ua);
    CHECK(h != NULL); if (!h) return;
    static char buf[5000]; DWORD len, e;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    EXPECT_EQ(len, 4096);
    CHECK(!strcmp(buf, ua));
    sh_close(h);
}

TEST(sh_open_agent_with_spaces_kept_in_option) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = sh_open("  padded agent \t");
    CHECK(h != NULL); if (!h) return;
    char buf[64]; DWORD len, e;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    t_note("agent with blanks reads back as [%s] len %lu", buf, len);
    EXPECT_STR(buf, "  padded agent \t");
    sh_close(h);
}

/* ------------------------------------------------------------------ user agent set */
TEST(sh_open_agent_set_roundtrip) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET h = sh_open("first");
    CHECK(h != NULL); if (!h) return;
    char ua[] = "second-agent"; DWORD e;
    CHECK(sh_set(h, INTERNET_OPTION_USER_AGENT, ua, (DWORD)strlen(ua), &e));
    char buf[64]; DWORD len;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    EXPECT_STR(buf, "second-agent"); EXPECT_EQ(len, 12);
    /* length is ignored for the A string: the NUL-terminated text is used */
    char ua3[] = "third";
    CHECK(sh_set(h, INTERNET_OPTION_USER_AGENT, ua3, 1, &e));
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    t_note("USER_AGENT set with length 1 of \"third\" reads back [%s]", buf);
    sh_close(h);
}

TEST(sh_open_agent_set_empty_12010) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET h = sh_open("keep");
    CHECK(h != NULL); if (!h) return;
    char empty[4] = ""; DWORD e;
    CHECK(!sh_set(h, INTERNET_OPTION_USER_AGENT, empty, 1, &e));
    EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
    char buf[16]; DWORD len;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    EXPECT_STR(buf, "keep");
    /* NULL buffer / zero length: 87 */
    CHECK(!sh_set(h, INTERNET_OPTION_USER_AGENT, NULL, 5, &e)); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    char x[] = "x";
    CHECK(!sh_set(h, INTERNET_OPTION_USER_AGENT, x, 0, &e)); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    sh_close(h);
}

TEST(sh_open_agent_set_w_length_in_chars) {
    REQUIRE(U(InternetSetOptionW));
    HINTERNET h = sh_open("orig");
    CHECK(h != NULL); if (!h) return;
    WCHAR w[] = L"wide-set-agent";
    SetLastError(0);
    CHECK(U(InternetSetOptionW)(h, INTERNET_OPTION_USER_AGENT, w, 4));      /* 4 characters */
    char buf[64]; DWORD len, e;
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    EXPECT_STR(buf, "wide");
    CHECK(U(InternetSetOptionW)(h, INTERNET_OPTION_USER_AGENT, w, (DWORD)wcslen(w)));
    CHECK(sh_qstr(h, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e));
    EXPECT_STR(buf, "wide-set-agent");
    sh_close(h);
}

/* ------------------------------------------------------------------ flags */
static const DWORD sh_open_flags_tab[] = {
    0, INTERNET_FLAG_ASYNC, INTERNET_FLAG_FROM_CACHE, INTERNET_FLAG_OFFLINE,
    INTERNET_FLAG_ASYNC | INTERNET_FLAG_OFFLINE, 0x00000001, 0x00000100, 0x80000000u, 0x7fffffffu, 0xffffffffu,
};
TEST(sh_open_flags_never_fail) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetOpenW));
    for (size_t i = 0; i < sizeof sh_open_flags_tab / sizeof *sh_open_flags_tab; i++) {
        DWORD f = sh_open_flags_tab[i];
        SetLastError(0xdeadbeef);
        HINTERNET h = U(InternetOpenA)("flags", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, f);
        DWORD e = GetLastError();
        CHECKF(h != NULL, "A flags 0x%lx err %lu", f, e);
        if (h) { EXPECT_EQ(e, 0); EXPECT_EQ(sh_htype(h, NULL), 1); sh_close(h); }
        h = U(InternetOpenW)(L"flags", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, f);
        CHECKF(h != NULL, "W flags 0x%lx", f);
        if (h) sh_close(h);
    }
}

TEST(sh_open_async_session_basic_options) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("async", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    CHECK(h != NULL); if (!h) return;
    EXPECT_EQ(sh_htype(h, NULL), INTERNET_HANDLE_TYPE_INTERNET);
    DWORD v, len, e;
    /* INTERNET_OPTION_ASYNC (30) is not implemented: 120 */
    CHECK(!sh_qdw(h, INTERNET_OPTION_ASYNC, &v, &len, &e)); EXPECT_EQ(e, ERROR_CALL_NOT_IMPLEMENTED);
    /* connect + request work synchronously even on an async session (no I/O) */
    HINTERNET c = sh_connect(h, "127.0.0.1", 80, 1);
    CHECK(c != NULL);
    HINTERNET r = c ? sh_request(c, "/x", 2) : NULL;
    CHECK(r != NULL);
    if (r) EXPECT_EQ(sh_htype(r, NULL), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
    if (r) sh_close(r);
    if (c) sh_close(c);
    CHECK(sh_close(h));
}

/* ------------------------------------------------------------------ session defaults */
TEST(sh_open_session_parent_is_null) {
    HINTERNET h = sh_open("p");
    CHECK(h != NULL); if (!h) return;
    ULONG_PTR v; DWORD len, e;
    CHECK(sh_qptr(h, INTERNET_OPTION_PARENT_HANDLE, &v, &len, &e));
    EXPECT_EQ(v, 0); EXPECT_EQ(len, sizeof(void *));
    sh_close(h);
}

TEST(sh_open_session_context_default_zero) {
    HINTERNET h = sh_open("c");
    CHECK(h != NULL); if (!h) return;
    ULONG_PTR v; DWORD len, e;
    CHECK(sh_qptr(h, INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e));
    EXPECT_EQ(v, 0); EXPECT_EQ(len, 8);
    sh_close(h);
}

TEST(sh_open_session_handle_values_distinct) {
    HINTERNET a = sh_open("a"), b = sh_open("b"), c = sh_open("c");
    CHECK(a && b && c);
    CHECK(a != b && b != c && a != c);
    t_note("session handle values %p %p %p", a, b, c);
    if (a) sh_close(a);
    if (b) sh_close(b);
    if (c) sh_close(c);
}

TEST(sh_open_proxy_info_named_proxy) {
    REQUIRE(U(InternetOpenA));
    HINTERNET h = U(InternetOpenA)("px", INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:9", "<local>", 0);
    CHECK(h != NULL); if (!h) return;
    DWORD len = 0;
    SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, NULL, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    CHECK(len >= sizeof(INTERNET_PROXY_INFO) + strlen("127.0.0.1:9") + 1);
    t_note("INTERNET_OPTION_PROXY size for named proxy: %lu", len);
    union { INTERNET_PROXY_INFO pi; char raw[512]; } u;
    len = sizeof u;
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, &u, &len));
    EXPECT_EQ(u.pi.dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    EXPECT_STR((const char *)u.pi.lpszProxy, "127.0.0.1:9");
    /* Win10 reports the session bypass list as "<proxy> <bypass>" (size 56 = 24 + 12 + 20) */
    EXPECT_STR((const char *)u.pi.lpszProxyBypass, "127.0.0.1:9 <local>");
    EXPECT_EQ(len, 56);
    sh_close(h);
}

TEST(sh_open_proxy_info_direct) {
    HINTERNET h = sh_open("d");
    CHECK(h != NULL); if (!h) return;
    union { INTERNET_PROXY_INFO pi; char raw[512]; } u; DWORD len = sizeof u;
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, &u, &len));
    EXPECT_EQ(u.pi.dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    t_note("DIRECT proxy info: proxy=%p bypass=%p len=%lu", u.pi.lpszProxy, u.pi.lpszProxyBypass, len);
    sh_close(h);
}

TEST(sh_open_proxy_info_direct_ignores_proxy_string) {
    HINTERNET h = U(InternetOpenA)("d", INTERNET_OPEN_TYPE_DIRECT, "127.0.0.1:9", "<local>", 0);
    CHECK(h != NULL); if (!h) return;
    union { INTERNET_PROXY_INFO pi; char raw[512]; } u; DWORD len = sizeof u;
    CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, &u, &len));
    EXPECT_EQ(u.pi.dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    sh_close(h);
}

TEST(sh_open_proxy_info_preconfig_note) {
    HINTERNET h = U(InternetOpenA)("pc", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    CHECK(h != NULL); if (!h) return;
    union { INTERNET_PROXY_INFO pi; char raw[1024]; } u; DWORD len = sizeof u;
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, &u, &len);
    t_note("PRECONFIG session PROXY query ok=%d err=%lu access=%lu len=%lu", ok, ok ? 0 : GetLastError(), ok ? u.pi.dwAccessType : 0, len);
    EXPECT_EQ(sh_htype(h, NULL), 1);
    sh_close(h);
    h = U(InternetOpenA)("pc4", INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY, NULL, NULL, 0);
    CHECK(h != NULL); if (!h) return;
    len = sizeof u;
    ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, &u, &len);
    t_note("PRECONFIG_WITH_NO_AUTOPROXY PROXY query ok=%d access=%lu", ok, ok ? u.pi.dwAccessType : 0);
    sh_close(h);
}

TEST(sh_open_proxy_w_query) {
    REQUIRE(U(InternetOpenW)); REQUIRE(U(InternetQueryOptionW));
    HINTERNET h = U(InternetOpenW)(L"pw", INTERNET_OPEN_TYPE_PROXY, L"127.0.0.1:9", L"<local>", 0);
    CHECK(h != NULL); if (!h) return;
    union { INTERNET_PROXY_INFO pi; char raw[1024]; } u; DWORD len = sizeof u;
    CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_PROXY, &u, &len));
    EXPECT_EQ(u.pi.dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    char pa[80] = "", pb[80] = "", wa[80] = "", wb[80] = "";
    if (u.pi.lpszProxy) { lstrcpynA(pa, (const char *)u.pi.lpszProxy, 40); WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)u.pi.lpszProxy, -1, wa, 40, NULL, NULL); }
    if (u.pi.lpszProxyBypass) { lstrcpynA(pb, (const char *)u.pi.lpszProxyBypass, 40); WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)u.pi.lpszProxyBypass, -1, wb, 40, NULL, NULL); }
    t_note("W PROXY query len %lu: proxy as A [%s] as W [%s]; bypass as A [%s] as W [%s]", len, pa, wa, pb, wb);
    /* Win10 quirk: InternetQueryOptionW(PROXY) on a session returns the A layout (narrow strings), same size as A */
    EXPECT_EQ(len, 56);
    EXPECT_STR(pa, "127.0.0.1:9");
    EXPECT_STR(pb, "127.0.0.1:9 <local>");
    sh_close(h);
}

/* PROXY session against a loopback "proxy": the request goes to the proxy in absolute form, no DNS for the origin. */
TEST(sh_open_named_proxy_sends_absolute_uri) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "via-proxy"), S_CLOSE_IF_ASKED(), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s;
    SH_START_OR_SKIP(&cfg, &s);
    HINTERNET h = U(InternetOpenA)("sh-proxy-agent", INTERNET_OPEN_TYPE_PROXY, srv_hostport(s), NULL, 0);
    CHECK(h != NULL);
    if (h) {
        DWORD to = 5000;
        U(InternetSetOptionA)(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
        U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
        HINTERNET c = sh_connect(h, "origin.i7test.example", 80, 0);
        HINTERNET r = c ? sh_request(c, "/via?x=1", 0) : NULL;
        CHECK(r != NULL);
        if (r) {
            BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
            CHECKF(ok, "send err %lu", GetLastError());
            if (ok) {
                char body[64]; int rok; t_inet_read_all(r, body, sizeof body, &rok);
                EXPECT_STR(body, "via-proxy");
            }
            if (srv_wait_requests(s, 1, 3000)) {
                EXPECT_STR(srv_req_target(s, 0), "http://origin.i7test.example/via?x=1");
                EXPECT_STR(srv_req_header(s, 0, "Host"), "origin.i7test.example");
                EXPECT_STR(srv_req_header(s, 0, "User-Agent"), "sh-proxy-agent");
                t_note("proxy request: [%s] Proxy-Connection=[%s]", srv_req_line(s, 0), srv_req_header(s, 0, "Proxy-Connection") ? srv_req_header(s, 0, "Proxy-Connection") : "(none)");
            } else CHECK(!"proxy saw no request");
            sh_close(r);
        }
        if (c) sh_close(c);
        sh_close(h);
    }
    srv_stop(s);
}

/* The proxy bypass list routes a listed host directly. */
TEST(sh_open_named_proxy_bypass_goes_direct) {
    REQUIRE(U(HttpSendRequestA));
    srv *direct = srv_http(NULL, 0);
    if (!direct) { t_skip("server unavailable"); return; }
    srv *proxy = srv_http(NULL, 0);
    if (!proxy) { srv_stop(direct); t_skip("server unavailable"); return; }
    HINTERNET h = U(InternetOpenA)("byp", INTERNET_OPEN_TYPE_PROXY, srv_hostport(proxy), "127.0.0.1", 0);
    CHECK(h != NULL);
    if (h) {
        DWORD to = 5000;
        U(InternetSetOptionA)(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
        HINTERNET c = sh_connect(h, "127.0.0.1", srv_port(direct), 0);
        HINTERNET r = c ? sh_request(c, "/direct", 0) : NULL;
        if (r) {
            BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
            CHECKF(ok, "send err %lu", GetLastError());
            CHECK(srv_wait_requests(direct, 1, 3000));
            if (srv_req_count(direct) > 0) EXPECT_STR(srv_req_line(direct, 0), "GET /direct HTTP/1.1");
            EXPECT_EQ(srv_req_count(proxy), 0);
            sh_close(r);
        } else CHECK(r != NULL);
        if (c) sh_close(c);
        sh_close(h);
    }
    srv_stop(proxy); srv_stop(direct);
}

/* ------------------------------------------------------------------ many sessions */
TEST(sh_open_many_sessions_loop) {
    REQUIRE(U(InternetOpenA));
    /* warm-up so lazily created process state is not counted */
    for (int i = 0; i < 20; i++) { HINTERNET h = sh_open("warm"); if (h) sh_close(h); }
    DWORD hc0 = 0, hc1 = 0; GetProcessHandleCount(GetCurrentProcess(), &hc0);
    int fails = 0, type_bad = 0, close_bad = 0;
    for (int i = 0; i < 500; i++) {
        HINTERNET h = sh_open("loop");
        if (!h) { fails++; continue; }
        if (sh_htype(h, NULL) != 1) type_bad++;
        if (!sh_close(h)) close_bad++;
    }
    GetProcessHandleCount(GetCurrentProcess(), &hc1);
    EXPECT_EQ(fails, 0); EXPECT_EQ(type_bad, 0); EXPECT_EQ(close_bad, 0);
    t_note("kernel handle count before %lu after %lu open/close x500", hc0, hc1);
    CHECKF(hc1 <= hc0 + 16, "kernel handles grew from %lu to %lu over 500 sessions", hc0, hc1);
}

TEST(sh_open_many_sessions_tree_loop) {
    for (int i = 0; i < 10; i++) {           /* warm-up */
        HINTERNET h = sh_open("w"); HINTERNET c = h ? sh_connect(h, "127.0.0.1", 80, 0) : NULL;
        HINTERNET r = c ? sh_request(c, "/", 0) : NULL; if (r) sh_close(r); if (c) sh_close(c); if (h) sh_close(h);
    }
    DWORD hc0 = 0, hc1 = 0; GetProcessHandleCount(GetCurrentProcess(), &hc0);
    int bad = 0;
    for (int i = 0; i < 200; i++) {
        HINTERNET h = sh_open("tree");
        HINTERNET c = h ? sh_connect(h, "127.0.0.1", 80, 0) : NULL;
        HINTERNET r = c ? sh_request(c, "/t", 0) : NULL;
        if (!h || !c || !r) bad++;
        if (i & 1) { if (r) sh_close(r); if (c) sh_close(c); }
        if (h && !sh_close(h)) bad++;         /* odd: children first; even: parent closes the tree */
    }
    GetProcessHandleCount(GetCurrentProcess(), &hc1);
    EXPECT_EQ(bad, 0);
    t_note("kernel handle count before %lu after %lu (200 session trees)", hc0, hc1);
    CHECKF(hc1 <= hc0 + 16, "kernel handles grew from %lu to %lu", hc0, hc1);
}

TEST(sh_open_many_concurrent_sessions) {
    enum { N = 64 };
    HINTERNET hs[N]; int ok = 0, distinct = 1;
    for (int i = 0; i < N; i++) { hs[i] = sh_open("conc"); if (hs[i]) ok++; }
    EXPECT_EQ(ok, N);
    for (int i = 0; i < N; i++) for (int j = i + 1; j < N; j++) if (hs[i] && hs[i] == hs[j]) distinct = 0;
    CHECK(distinct);
    int types = 0;
    for (int i = 0; i < N; i++) if (hs[i] && sh_htype(hs[i], NULL) == 1) types++;
    EXPECT_EQ(types, N);
    int closed = 0;
    for (int i = N - 1; i >= 0; i--) if (hs[i] && sh_close(hs[i])) closed++;
    EXPECT_EQ(closed, N);
}

/* ------------------------------------------------------------------ global (NULL handle) facts that sessions rely on */
TEST(sh_open_version_option) {
    INTERNET_VERSION_INFO vi; DWORD len = sizeof vi;
    memset(&vi, 0xcc, sizeof vi);
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_VERSION, &vi, &len));
    EXPECT_EQ(len, sizeof vi);
    EXPECT_EQ(vi.dwMajorVersion, 1); EXPECT_EQ(vi.dwMinorVersion, 2);
    HINTERNET h = sh_open("v");
    if (h) {
        INTERNET_VERSION_INFO v2; len = sizeof v2;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_VERSION, &v2, &len));
        EXPECT_EQ(v2.dwMajorVersion, 1); EXPECT_EQ(v2.dwMinorVersion, 2);
        sh_close(h);
    }
    len = 4; SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_VERSION, &vi, &len));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 8);
}

TEST(sh_open_http_version_option) {
    HTTP_VERSION_INFO hv; DWORD len = sizeof hv;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &hv, &len));
    EXPECT_EQ(len, 8); EXPECT_EQ(hv.dwMajorVersion, 1); EXPECT_EQ(hv.dwMinorVersion, 1);
}

TEST(sh_open_w_agent_non_ascii_note) {
    REQUIRE(U(InternetOpenW));
    HINTERNET h = U(InternetOpenW)(L"agent-\x00e9\x4e2d", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(h != NULL); if (!h) return;
    unsigned char buf[64]; DWORD len = sizeof buf;
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_USER_AGENT, buf, &len);
    char hex[200] = ""; for (DWORD i = 0; ok && i < len && i < 40; i++) sprintf(hex + strlen(hex), "%02x", buf[i]);
    t_note("W agent with U+00E9 U+4E2D stored as %lu bytes: %s (ACP->UTF-8 fallback per InternetOpenW)", len, hex);
    sh_close(h);
}
