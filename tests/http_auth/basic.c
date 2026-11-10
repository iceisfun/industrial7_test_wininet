/* http_auth: Basic authentication against an in-process gate server (auth.h).
 * The gate answers 200 only to an exact expected Authorization value, else 401 + challenge, so a 200 proves the
 * client computed base64(user:pass) exactly; the recorder shows what was sent on every leg. */
#include "auth.h"

#define CH_BASIC "WWW-Authenticate: Basic realm=\"i7\"\r\n"

/* ------------------------------------------------------------------ helper self tests (pure, no wininet) */
TEST(auth_selftest_md5_md4_hmac) {
    char h[33]; unsigned char d[16];
    a_md5("", 0, d); a_hex(d, 16, h); EXPECT_STR(h, "d41d8cd98f00b204e9800998ecf8427e");
    a_md5("abc", 3, d); a_hex(d, 16, h); EXPECT_STR(h, "900150983cd24fb0d6963f7d28e17f72");
    a_md5_hex("The quick brown fox jumps over the lazy dog", h); EXPECT_STR(h, "9e107d9d372bb6826bd81d3542a419d6");
    a_md4("", 0, d); a_hex(d, 16, h); EXPECT_STR(h, "31d6cfe0d16ae931b73c59d7e0c089c0");
    a_md4("abc", 3, d); a_hex(d, 16, h); EXPECT_STR(h, "a448017aaf21d8525fc10ae87aa6729d");
    a_md4("message digest", 14, d); a_hex(d, 16, h); EXPECT_STR(h, "d9130a8164549fe818874806e1c7014b");
    a_hmac_md5("Jefe", 4, "what do ya want for nothing?", 28, d); a_hex(d, 16, h); EXPECT_STR(h, "750c783e6ab0b503eaa86e310a5db738");
    /* RFC 2617 3.5 example */
    a_digest_response("Mufasa", "testrealm@host.com", "Circle Of Life", "GET", "/dir/index.html",
                      "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b", "auth", 0, h);
    EXPECT_STR(h, "6629fae49393a05397450978507c4ef1");
    EXPECT_STR(a_basic("Aladdin", "open sesame"), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    char v[64];
    CHECK(a_param("Digest realm=\"a, b\", nonce=xyz, qop=\"auth\"", "nonce", v, sizeof v)); EXPECT_STR(v, "xyz");
    CHECK(a_param("Digest realm=\"a, b\", nonce=xyz, qop=\"auth\"", "realm", v, sizeof v)); EXPECT_STR(v, "a, b");
    CHECK(!a_param("Digest realm=\"a\"", "nonce", v, sizeof v));
    EXPECT_EQ(a_param_count("Digest realm=\"a, b\", nonce=xyz, qop=\"auth\""), 3);
}

/* ------------------------------------------------------------------ challenge without credentials */
TEST(auth_basic_no_creds_returns_401_to_caller) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/nc"; ares r; a_once(s, &q, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401);
    EXPECT_STR(r.body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    CHECK(REQ_AUTH(s, 0) == NULL);
    srv_stop(s);
}

TEST(auth_basic_no_creds_www_authenticate_queryable) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = "WWW-Authenticate: Basic realm=\"i7 realm\"\r\n"; g.accept[0] = "x";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 401);
    char b[256]; DWORD idx = 0;
    CHECK(a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Basic realm=\"i7 realm\"");
    EXPECT_EQ(idx, 1);
    SET_ERR(0); CHECK(!a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    DWORD l = sizeof b; SET_ERR(0); CHECK(!U(HttpQueryInfoA)(r.hr, HTTP_QUERY_PROXY_AUTHENTICATE, b, &l, NULL)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_STATUS_TEXT, &idx, b, sizeof b)); EXPECT_STR(b, "Unauthorized");
    /* raw form */
    char raw[1024]; l = sizeof raw; CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_RAW_HEADERS_CRLF, raw, &l, NULL));
    CHECK(strstr(raw, "WWW-Authenticate: Basic realm=\"i7 realm\"\r\n") != NULL);
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_query_multiple_challenges_by_index) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = "WWW-Authenticate: Bearer realm=\"b\"\r\nWWW-Authenticate: Basic realm=\"one\"\r\nWWW-Authenticate: X-Custom abc\r\n"; g.accept[0] = "x";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 401);
    char b[256]; DWORD idx = 0;
    CHECK(a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Bearer realm=\"b\""); EXPECT_EQ(idx, 1);
    CHECK(a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Basic realm=\"one\""); EXPECT_EQ(idx, 2);
    CHECK(a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "X-Custom abc"); EXPECT_EQ(idx, 3);
    SET_ERR(0); CHECK(!a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    /* by custom name too */
    strcpy(b, "WWW-Authenticate"); DWORD l = sizeof b; idx = 1;
    CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_CUSTOM, b, &l, &idx)); EXPECT_STR(b, "Basic realm=\"one\""); EXPECT_EQ(idx, 2);
    /* small buffer */
    char tiny[4]; l = sizeof tiny; idx = 0; SET_ERR(0);
    CHECK(!U(HttpQueryInfoA)(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, tiny, &l, &idx)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, strlen("Bearer realm=\"b\"") + 1); EXPECT_EQ(idx, 0);
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ credential sources */
TEST(auth_basic_connect_creds_retry) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/cc"; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "ok");
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_AUTH(s, 0) == NULL);
    EXPECT_STR(REQ_AUTH(s, 1), "Basic dXNlcjpwYXNz");
    EXPECT_STR(srv_req_line(s, 1), "GET /cc HTTP/1.1");
    EXPECT_EQ(g.n_ok, 1); EXPECT_EQ(g.n_deny, 1);
    srv_stop(s);
}

TEST(auth_basic_retry_reuses_keepalive_connection) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));
    EXPECT_EQ(srv_conn_count(s), 1);
    srv_stop(s);
}

TEST(auth_basic_retry_after_server_closes_challenge_connection) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass"); g.close_on_deny = 1;
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(srv_req_conn(s, 0) != srv_req_conn(s, 1));
    EXPECT_STR(REQ_AUTH(s, 1), "Basic dXNlcjpwYXNz");
    srv_stop(s);
}

TEST(auth_basic_request_option_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("ruser", "rpass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.ruser = "ruser"; q.rpass = "rpass"; ares r; a_once(s, &q, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_AUTH(s, 0) == NULL);
    EXPECT_STR(REQ_AUTH(s, 1), a_basic("ruser", "rpass"));
    srv_stop(s);
}

TEST(auth_basic_request_option_overrides_connect_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("ruser", "rpass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "cuser"; q.cpass = "cpass"; q.ruser = "ruser"; q.rpass = "rpass"; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_AUTH(s, 1), a_basic("ruser", "rpass"));
    srv_stop(s);
}

TEST(auth_basic_request_username_with_connect_password) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("ruser", "cpass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "cuser"; q.cpass = "cpass"; q.ruser = "ruser"; ares r; a_once(s, &q, &r);
    a_dump(s);
    const char *a = REQ_AUTH(s, 1);
    t_note("request USERNAME only over connect cuser/cpass: status=%lu auth=%s", r.status, a ? a : "(none)");
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(a, a_basic("ruser", "cpass"));
    srv_stop(s);
}

TEST(auth_basic_resend_same_handle_after_setting_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("late", "creds");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/late", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(a_status(hr), 401);
    char buf[64]; t_inet_read_all(hr, buf, sizeof buf, NULL); EXPECT_STR(buf, "denied");
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "late", 4));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "creds", 5));
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    EXPECT_EQ(a_status(hr), 200);
    t_inet_read_all(hr, buf, sizeof buf, NULL); EXPECT_STR(buf, "ok");
    a_dump(s);
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_AUTH(s, 0) == NULL);
    EXPECT_STR(REQ_AUTH(s, 1), a_basic("late", "creds"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_open_url_userinfo) {
    REQUIRE(U(InternetOpenUrlA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("urlu", "urlp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    char url[256]; snprintf(url, sizeof url, "http://urlu:urlp@%s/ui", srv_hostport(s));
    char body[64]; size_t n; DWORD err = 0;
    int code = t_http_get(hi, url, NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    a_dump(s);
    EXPECT_EQ(code, 200); EXPECT_STR(body, "ok");
    CHECK(srv_req_count(s) >= 1);
    EXPECT_STR(REQ_AUTH(s, srv_req_count(s) - 1), a_basic("urlu", "urlp"));
    EXPECT_STR(srv_req_line(s, 0), "GET /ui HTTP/1.1");
    t_note("userinfo URL: %d request(s), first auth=%s", srv_req_count(s), REQ_AUTH(s, 0) ? REQ_AUTH(s, 0) : "(none)");
    t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_open_url_userinfo_percent_encoded) {
    REQUIRE(U(InternetOpenUrlA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("u@x", "p:q");
    g.accept[1] = a_basic("u%40x", "p%3Aq");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    char url[256]; snprintf(url, sizeof url, "http://u%%40x:p%%3Aq@%s/pe", srv_hostport(s));
    char body[64]; size_t n; DWORD err = 0;
    int code = t_http_get(hi, url, NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    a_dump(s);
    int last = srv_req_count(s) - 1; const char *a = last >= 0 ? REQ_AUTH(s, last) : NULL;
    t_note("percent-encoded userinfo: code=%d err=%lu auth=%s (decoded form %s)", code, err, a ? a : "(none)", a_basic("u@x", "p:q"));
    EXPECT_EQ(code, 200);
    t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_open_url_no_userinfo_returns_401) {
    REQUIRE(U(InternetOpenUrlA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("a", "b");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    char body[64]; size_t n; DWORD err = 0;
    int code = t_http_get(hi, srv_url(s, "/nui"), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(code, 401); EXPECT_STR(body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ credential encoding table */
typedef struct { const char *tag, *user, *pass; } cred_row;
static const cred_row g_creds[] = {
    { "plain",      "user",              "pass" },
    { "colon_pass", "user",              "pa:ss" },
    { "space",      "us er",             "p a s s" },
    { "symbols",    "u!#$%&'*+-.^_`|~",  "!\"#$%&'()*+,-./;<=>?@[\\]^_`{|}~" },
    { "at_user",    "user@example.test", "pw" },
    { "backslash",  "DOM\\user",         "pw" },
    { "digits",     "0123456789",        "9876543210" },
    { "long",       "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu",
                    "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp" },
    { "one_char",   "a",                 "b" },
    { "pad1",       "ab",                "c" },
    { "pad2",       "abc",               "d" },
};
static void run_cred_row(const cred_row *c, int via_option) {
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic(c->user, c->pass);
    srv *s = gate_start(&g); if (!s) { t_note("%s: server unavailable", c->tag); return; }
    areq q = {0};
    if (via_option) { q.ruser = c->user; q.rpass = c->pass; } else { q.cuser = c->user; q.cpass = c->pass; }
    ares r; a_once(s, &q, &r);
    CHECKF(r.status == 200, "%s via %s: status %lu", c->tag, via_option ? "option" : "connect", r.status);
    const char *a = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    CHECKF(a && !strcmp(a, a_basic(c->user, c->pass)), "%s: auth=%s want %s", c->tag, a ? a : "(none)", a_basic(c->user, c->pass));
    CHECKF(srv_req_count(s) == 2, "%s: %d requests", c->tag, srv_req_count(s));
    srv_stop(s);
}
TEST(auth_basic_cred_table_via_connect) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof g_creds / sizeof g_creds[0]; i++) run_cred_row(&g_creds[i], 0);
}
TEST(auth_basic_cred_table_via_request_option) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof g_creds / sizeof g_creds[0]; i++) run_cred_row(&g_creds[i], 1);
}

TEST(auth_basic_user_without_password) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("solo", "");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "solo"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("user without password: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(REQ_AUTH(s, srv_req_count(s) - 1), "Basic c29sbzo=");
    srv_stop(s);
}

TEST(auth_basic_empty_password_string) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("solo", "");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "solo"; q.cpass = ""; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("user + empty password: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 200);
    srv_stop(s);
}

TEST(auth_basic_password_without_user) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("", "lonely");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cpass = "lonely"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("password without user: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_basic_wide_connect_non_ascii) {
    REQUIRE(U(InternetConnectW));
    /* u+00FC (u-umlaut) in user and password: record which byte encoding wininet puts inside base64 */
    gate g = {0}; g.challenge = CH_BASIC;
    g.accept[0] = a_basic("\xc3\xbcser", "p\xc3\xa4ss");   /* UTF-8 */
    g.accept[1] = a_basic("\xfcser", "p\xe4ss");           /* Windows-1252 */
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), L"\x00fcser", L"p\x00e4ss", INTERNET_SERVICE_HTTP, 0, 0);
    areq q = {0}; ares r; a_send(hc, &q, &r, 0);
    a_dump(s);
    const char *a = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    size_t dn = 0; unsigned char *d = a && !strncmp(a, "Basic ", 6) ? srv_unb64(a + 6, &dn) : NULL;
    char hx[256] = ""; if (d) a_hex(d, dn < 100 ? dn : 100, hx);
    t_note("non-ASCII Basic creds: status=%lu decoded=%s acp=%u", r.status, hx, GetACP());
    EXPECT_EQ(r.status, 200);
    free(d); a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ challenge syntax variants */
typedef struct { const char *tag, *challenge; int expect_retry; } ch_row;
static const ch_row g_ch[] = {
    { "quoted_realm",     "WWW-Authenticate: Basic realm=\"i7\"\r\n", 1 },
    { "lower_scheme",     "WWW-Authenticate: basic realm=\"i7\"\r\n", 1 },
    { "upper_scheme",     "WWW-Authenticate: BASIC realm=\"i7\"\r\n", 1 },
    { "no_realm",         "WWW-Authenticate: Basic\r\n", 1 },
    { "empty_realm",      "WWW-Authenticate: Basic realm=\"\"\r\n", 1 },
    { "unquoted_realm",   "WWW-Authenticate: Basic realm=i7\r\n", 1 },
    { "comma_in_realm",   "WWW-Authenticate: Basic realm=\"a, b\"\r\n", 1 },
    { "charset_param",    "WWW-Authenticate: Basic realm=\"i7\", charset=\"UTF-8\"\r\n", 1 },
    { "lower_header",     "www-authenticate: Basic realm=\"i7\"\r\n", 1 },
    { "bearer_then_basic","WWW-Authenticate: Bearer realm=\"x\"\r\nWWW-Authenticate: Basic realm=\"i7\"\r\n", 1 },
    { "unknown_then_basic","WWW-Authenticate: X-Unknown a=b\r\nWWW-Authenticate: Basic realm=\"i7\"\r\n", 1 },
    { "bearer_only",      "WWW-Authenticate: Bearer realm=\"x\"\r\n", 0 },
    { "unknown_only",     "WWW-Authenticate: X-Unknown\r\n", 0 },
    { "no_header",        "", 0 },
    { "empty_header",     "WWW-Authenticate: \r\n", 0 },
};
TEST(auth_basic_challenge_variants) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof g_ch / sizeof g_ch[0]; i++) {
        const ch_row *c = &g_ch[i];
        gate g = {0}; g.challenge = c->challenge; g.accept[0] = a_basic("cu", "cp");
        srv *s = gate_start(&g); if (!s) { t_skip("server unavailable"); return; }
        areq q = {0}; q.cuser = "cu"; q.cpass = "cp"; ares r; a_once(s, &q, &r);
        int n = srv_req_count(s);
        t_note("challenge %-18s -> ok=%d status=%lu requests=%d", c->tag, r.ok, r.status, n);
        CHECKF(r.ok, "%s: err=%lu", c->tag, r.err);
        if (c->expect_retry) {
            CHECKF(r.status == 200, "%s: status %lu", c->tag, r.status);
            CHECKF(n == 2, "%s: %d requests", c->tag, n);
        } else {
            CHECKF(r.status == 401, "%s: status %lu", c->tag, r.status);
            CHECKF(n == 1, "%s: %d requests", c->tag, n);
            CHECKF(REQ_AUTH(s, 0) == NULL, "%s: unexpected auth", c->tag);
        }
        srv_stop(s);
    }
}

/* ------------------------------------------------------------------ rejected credentials */
TEST(auth_basic_wrong_creds_final_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "wrong"; ares r; a_once(s, &q, &r);
    a_dump(s);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401);
    EXPECT_STR(r.body, "denied");
    int n = srv_req_count(s);
    t_note("wrong Basic creds: %d requests", n);
    EXPECT_EQ(n, 2);
    for (int i = 1; i < n; i++) EXPECT_STR(REQ_AUTH(s, i), a_basic("user", "wrong"));
    EXPECT_EQ(g.n_ok, 0);
    srv_stop(s);
}

TEST(auth_basic_wrong_creds_send_again_on_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "wrong");
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 401);
    int before = srv_req_count(s);
    /* fix the password and resend on the same request handle */
    CHECK(U(InternetSetOptionA)(r.hr, INTERNET_OPTION_PASSWORD, "right", 5));
    CHECKF(U(HttpSendRequestA)(r.hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    EXPECT_EQ(a_status(r.hr), 200);
    a_dump(s);
    int n = srv_req_count(s);
    t_note("wrong then right: %d requests before, %d after", before, n);
    EXPECT_STR(REQ_AUTH(s, n - 1), a_basic("user", "right"));
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_no_auth_flag_returns_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pass"; q.flags = T_INET_FRESH | INTERNET_FLAG_NO_AUTH; ares r; a_once(s, &q, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401);
    EXPECT_STR(r.body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    CHECK(REQ_AUTH(s, 0) == NULL);
    srv_stop(s);
}

TEST(auth_basic_no_auth_flag_request_option_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.ruser = "user"; q.rpass = "pass"; q.flags = T_INET_FRESH | INTERNET_FLAG_NO_AUTH; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_basic_caller_supplied_authorization_header) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("hdr", "val");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.hdrs = "Authorization: Basic aGRyOnZhbA==\r\n"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(REQ_AUTH(s, 0), "Basic aGRyOnZhbA==");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Authorization"), 1);
    srv_stop(s);
}

TEST(auth_basic_caller_header_wrong_then_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pass"; q.hdrs = "Authorization: Basic Ym9ndXM6Ym9ndXM=\r\n"; ares r; a_once(s, &q, &r);
    a_dump(s);
    int n = srv_req_count(s);
    t_note("caller Authorization header + connect creds: status=%lu requests=%d", r.status, n);
    EXPECT_STR(REQ_AUTH(s, 0), "Basic Ym9ndXM6Ym9ndXM=");
    srv_stop(s);
}

/* ------------------------------------------------------------------ methods */
TEST(auth_basic_post_body_resent) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.verb = "POST"; q.path = "/post"; q.cuser = "user"; q.cpass = "pass"; q.body = "a=1&b=2"; q.body_len = 7;
    q.hdrs = "Content-Type: application/x-www-form-urlencoded\r\n";
    ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    for (int i = 0; i < srv_req_count(s) && i < 2; i++) {
        EXPECT_STR(srv_req_method(s, i), "POST");
        size_t bl = 0; const char *b = srv_req_body(s, i, &bl);
        CHECKF(b && bl == 7 && !memcmp(b, "a=1&b=2", 7), "req %d body len %zu", i, bl);
        EXPECT_STR(srv_req_header(s, i, "Content-Length"), "7");
    }
    EXPECT_STR(REQ_AUTH(s, 1), "Basic dXNlcjpwYXNz");
    srv_stop(s);
}

TEST(auth_basic_head_request) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.verb = "HEAD"; q.cuser = "user"; q.cpass = "pass"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(srv_req_method(s, 1), "HEAD");
    EXPECT_STR(REQ_AUTH(s, 1), "Basic dXNlcjpwYXNz");
    EXPECT_EQ(r.n, 0);
    srv_stop(s);
}

TEST(auth_basic_put_and_delete) {
    REQUIRE(U(HttpSendRequestA));
    const char *verbs[] = { "PUT", "DELETE", "OPTIONS", "PATCH" };
    for (int v = 0; v < 4; v++) {
        gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
        srv *s = gate_start(&g); if (!s) { t_skip("server unavailable"); return; }
        areq q = {0}; q.verb = verbs[v]; q.cuser = "user"; q.cpass = "pass";
        if (v == 0) { q.body = "xyz"; q.body_len = 3; }
        ares r; a_once(s, &q, &r);
        CHECKF(r.status == 200, "%s: status %lu", verbs[v], r.status);
        CHECKF(srv_req_count(s) == 2, "%s: %d requests", verbs[v], srv_req_count(s));
        if (srv_req_count(s) == 2) { EXPECT_STR(srv_req_method(s, 1), verbs[v]); EXPECT_STR(REQ_AUTH(s, 1), "Basic dXNlcjpwYXNz"); }
        srv_stop(s);
    }
}

/* ------------------------------------------------------------------ request header introspection */
TEST(auth_basic_query_request_authorization_header) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 200);
    char b[256]; DWORD idx = 0;
    int ok = a_query(r.hr, HTTP_QUERY_AUTHORIZATION | HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx, b, sizeof b);
    t_note("request Authorization via HttpQueryInfo: ok=%d err=%lu val=%s", ok, ok ? 0 : GetLastError(), b);
    char raw[2048]; DWORD l = sizeof raw;
    if (U(HttpQueryInfoA)(r.hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, raw, &l, NULL)) {
        t_note("request raw headers: %.300s", raw);
        CHECK(strstr(raw, "GET / HTTP/1.1\r\n") == raw);
    } else CHECKF(0, "raw request headers err=%lu", GetLastError());
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_response_headers_after_success) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("user", "pass"); g.ok_hdrs = "X-Gate: passed\r\n";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pass");
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 200);
    char b[256]; DWORD idx = 0;
    /* the final response is the 200: the 401's challenge header is gone */
    SET_ERR(0); CHECK(!a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    strcpy(b, "X-Gate"); DWORD l = sizeof b; CHECK(U(HttpQueryInfoA)(r.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_STR(b, "passed");
    idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_STATUS_TEXT, &idx, b, sizeof b)); EXPECT_STR(b, "OK");
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ wide API */
TEST(auth_basic_wide_request_option_creds) {
    REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(InternetSetOptionW));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("wuser", "wpass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(InternetSetOptionW)(hr, INTERNET_OPTION_USERNAME, L"wuser", 5));
    CHECK(U(InternetSetOptionW)(hr, INTERNET_OPTION_PASSWORD, L"wpass", 5));
    CHECKF(U(HttpSendRequestW)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_STR(REQ_AUTH(s, 1), a_basic("wuser", "wpass"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_basic_wide_connect_creds) {
    REQUIRE(U(InternetConnectW));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("wcu", "wcp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), L"wcu", L"wcp", INTERNET_SERVICE_HTTP, 0, 0);
    areq q = {0}; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(REQ_AUTH(s, 1), a_basic("wcu", "wcp"));
    a_close(hc); t_inet_close(hi); srv_stop(s);
}
