/* ck_wire2.c - more cookies on the wire: HttpOpenRequest/HttpSendRequest (GET, POST, HEAD), keep-alive reuse,
 * Set-Cookie on HEAD / chunked / HTTP/1.0 / 401 / 304-less responses, Expires with a comma inside one header,
 * Set-Cookie with no value / no name, path-scoped cookies across a redirect, three-level path order on the wire,
 * the position of the Cookie header in the request, INTERNET_FLAG_NO_COOKIES on one request of a session,
 * and network cookies seen through InternetGetCookieEx2. Every server is the in-process loopback server.
 * Decomp: HTTP_REQUEST_HANDLE_OBJECT::CreateCookieHeaderIfNeeded@0x68f50, ::ExtractSetCookieHeaders@0x2f058.
 * VM_TIMEOUT: 150 */
#include "ck.h"

typedef struct { srv *s; srv_step st[4]; char path[300]; char api[400]; } w2;
/* every request: status `code` with `hdrs` (may use %R) and body "ok"; keep-alive */
static int w2_start(w2 *w, int code, const char *hdrs, DWORD rflags) {
    srv_step a[3] = { S_HEAD(), S_REPLYF(200, NULL, "ok", 0), S_LOOP() };
    a[1].arg = code; a[1].hdrs = hdrs; a[1].flags = rflags;
    memcpy(w->st, a, sizeof a);
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    static srv_script sc[64]; static LONG sci;
    LONG k = InterlockedIncrement(&sci) & 63;
    sc[k].steps = w->st; sc[k].nsteps = 3;
    cfg.kind = SRV_HTTP; cfg.scripts = &sc[k]; cfg.nscripts = 1;
    snprintf(w->path, sizeof w->path, "%s/", ck_upath("w2"));
    snprintf(w->api, sizeof w->api, "http://127.0.0.1%s", w->path);
    w->s = NULL;
    return srv_start(&cfg, &w->s);
}
#define W2_OR_SKIP(w, code, hdrs, fl) do { int rc_ = w2_start((w), (code), (hdrs), (fl)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)
static const char *w2url(w2 *w, const char *sfx) { char p[600]; snprintf(p, sizeof p, "%s%s", w->path, sfx ? sfx : ""); return srv_url(w->s, p); }
static const char *w2api(w2 *w, const char *sfx) { static char b[4][600]; static int i; char *r = b[i++ & 3]; snprintf(r, 600, "%s%s", w->api, sfx ? sfx : ""); return r; }
static const char *chdr(srv *s, int i) { return srv_req_header(s, i, "Cookie"); }

/* one request through InternetConnect + HttpOpenRequest + HttpSendRequest; returns the status */
static int w2_req(HINTERNET hi, w2 *w, const char *verb, const char *sfx, const char *hdrs, const char *body, DWORD flags) {
    __typeof__(&InternetConnectA) pc = U(InternetConnectA);
    __typeof__(&HttpOpenRequestA) po = U(HttpOpenRequestA);
    __typeof__(&HttpSendRequestA) ps = U(HttpSendRequestA);
    __typeof__(&HttpQueryInfoA) pq = U(HttpQueryInfoA);
    if (!pc || !po || !ps || !pq) return 0;
    HINTERNET hc = pc(hi, "127.0.0.1", srv_port(w->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) return 0;
    char obj[600]; snprintf(obj, sizeof obj, "%s%s", w->path, sfx ? sfx : "");
    HINTERNET hr = po(hc, verb, obj, NULL, NULL, NULL, CK_WIRE_BASE | flags, 0);
    int code = 0;
    if (hr) {
        if (ps(hr, hdrs, hdrs ? (DWORD)-1 : 0, (void *)body, body ? (DWORD)strlen(body) : 0)) {
            DWORD c = 0, sz = sizeof c;
            if (pq(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &c, &sz, NULL)) code = (int)c;
            char buf[512]; int ok; t_inet_read_all(hr, buf, sizeof buf, &ok);
        }
        t_inet_close(hr);
    }
    t_inet_close(hc);
    return code;
}
#define REQ_W2() do { REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA)); REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetOpenUrlA)); } while (0)

/* ------------------------------------------------------------------------------------------ verbs */
TEST(ck_wire2_get_via_open_request_sends_cookie) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[600]; snprintf(d, sizeof d, "orq=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(w2_req(hi, &w, "GET", "x", NULL, NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(chdr(w.s, 0), "orq=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_post_sends_cookie) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[600]; snprintf(d, sizeof d, "pst=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(w2_req(hi, &w, "POST", "form", "Content-Type: application/x-www-form-urlencoded\r\n", "a=b", 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(srv_req_method(w.s, 0), "POST");
    EXPECT_STR(chdr(w.s, 0), "pst=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_head_sends_cookie_and_stores_set_cookie) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: hd=1; path=%R\r\n", 0);
    char d[600]; snprintf(d, sizeof d, "pre=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(w2_req(hi, &w, "HEAD", NULL, NULL, NULL, 0), 200);
    ck_track(w.api, "hd", NULL, 0);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(srv_req_method(w.s, 0), "HEAD");
    EXPECT_STR(chdr(w.s, 0), "pre=1");
    EXPECT_STR(ck_gets(w.api, NULL, 0), "pre=1; hd=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_keepalive_second_request_carries_new_cookie) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: ka=1; path=%R\r\n", 0);
    ck_track(w.api, "ka", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(w2_req(hi, &w, "GET", NULL, NULL, NULL, 0), 200);
    EXPECT_EQ(w2_req(hi, &w, "GET", NULL, NULL, NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(chdr(w.s, 0), NULL);
    EXPECT_STR(chdr(w.s, 1), "ka=1");
    t_note("keep-alive: conn0=%d conn1=%d", srv_req_conn(w.s, 0), srv_req_conn(w.s, 1));
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_resend_same_request_handle) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: rs=1; path=%R\r\n", 0);
    ck_track(w.api, "rs", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(w.s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", w.path, NULL, NULL, NULL, CK_WIRE_BASE, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        char buf[256]; int ok;
        EXPECT_EQ(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), TRUE); t_inet_read_all(hr, buf, sizeof buf, &ok);
        EXPECT_EQ(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), TRUE); t_inet_read_all(hr, buf, sizeof buf, &ok);
        CHECK(srv_wait_requests(w.s, 2, 3000));
        EXPECT_STR(chdr(w.s, 0), NULL);
        t_note("resend on the same handle: second Cookie='%s' occurrences=%d", chdr(w.s, 1) ? chdr(w.s, 1) : "(none)", srv_req_header_occurrences(w.s, 1, "Cookie"));
        EXPECT_STR(chdr(w.s, 1), "rs=1");
        EXPECT_EQ(srv_req_header_occurrences(w.s, 1, "Cookie"), 1);
        t_inet_close(hr);
    }
    t_inet_close(hc); t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ response framing */
TEST(ck_wire2_set_cookie_chunked_response) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: ch=1; path=%R\r\n", SRV_R_CHUNKED);
    ck_track(w.api, "ch", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "ch=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_http10_response) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: h10=1; path=%R\r\n", SRV_R_HTTP10);
    ck_track(w.api, "h10", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "h10=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_close_delimited_response) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: cd=1; path=%R\r\n", SRV_R_CLOSE);
    ck_track(w.api, "cd", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "cd=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_on_500_stored) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 500, "Set-Cookie: e5=1; path=%R\r\n", 0);
    ck_track(w.api, "e5", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 500);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "e5=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_on_401_stored) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 401, "WWW-Authenticate: Basic realm=\"ck\"\r\nSet-Cookie: e4=1; path=%R\r\n", 0);
    ck_track(w.api, "e4", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 401);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "e4=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_expires_with_comma_persistent) {
    REQ_W2(); REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(UN(InternetFreeCookies));
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: ec=1; path=%R; expires=Fri, 31 Dec 2100 23:59:59 GMT\r\n", 0);
    ck_track(w.api, "ec", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "ec=1");
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(w.api), NULL, 0, &arr, &n), 0);
    EXPECT_EQ(n, 1);
    if (n && arr) {
        EXPECT_EQ(arr[0].fExpiresSet, TRUE);
        SYSTEMTIME st; FileTimeToSystemTime(&arr[0].ftExpires, &st);
        EXPECT_EQ(st.wYear, 2100);
    }
    if (arr) UN(InternetFreeCookies)(arr, n);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_max_age_persistent) {
    REQ_W2(); REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(UN(InternetFreeCookies));
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: ma=1; path=%R; Max-Age=3600\r\n", 0);
    ck_track(w.api, "ma", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(w.api), NULL, 0, &arr, &n), 0);
    EXPECT_EQ(n, 1);
    if (n && arr) {
        EXPECT_EQ(arr[0].fExpiresSet, TRUE);
        CHECK(!(arr[0].dwFlags & INTERNET_COOKIE_IS_SESSION));
    }
    if (arr) UN(InternetFreeCookies)(arr, n);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_nameless_value) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: bareword; path=%R\r\n", 0);
    ck_track(w.api, "", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "bareword");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(chdr(w.s, 1), "bareword");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_empty_value) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: ev=; path=%R\r\n", 0);
    ck_track(w.api, "ev", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api, NULL, 0), "ev=");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(chdr(w.s, 1), "ev=");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_empty_header_ignored) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: \r\nSet-Cookie: real=1; path=%R\r\n", 0);
    ck_track(w.api, "real", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    const char *g = ck_gets(w.api, NULL, 0);
    t_note("empty Set-Cookie + real: '%s'", g);
    CHECK(ck_has(g, "real=1"));
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_samesite_and_secure_flags) {
    REQ_W2(); REQUIRE(UN(InternetGetCookieEx2)); REQUIRE(UN(InternetFreeCookies));
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: sst=1; path=%R; SameSite=Strict\r\nSet-Cookie: ssl=1; path=%R; SameSite=Lax\r\n", 0);
    ck_track(w.api, "sst", NULL, 0); ck_track(w.api, "ssl", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    INTERNET_COOKIE2 *arr = NULL; DWORD n = 0;
    EXPECT_EQ(UN(InternetGetCookieEx2)(ck_w(w.api), NULL, 0, &arr, &n), 0);
    EXPECT_EQ(n, 2);
    if (n == 2 && arr) {
        EXPECT_EQ(arr[0].dwFlags & (INTERNET_COOKIE_SAME_SITE_STRICT | INTERNET_COOKIE_SAME_SITE_LAX), INTERNET_COOKIE_SAME_SITE_STRICT);
        EXPECT_EQ(arr[1].dwFlags & (INTERNET_COOKIE_SAME_SITE_STRICT | INTERNET_COOKIE_SAME_SITE_LAX), INTERNET_COOKIE_SAME_SITE_LAX);
        t_note("network cookie flags: 0x%lx 0x%lx", arr[0].dwFlags, arr[1].dwFlags);
    }
    if (arr) UN(InternetFreeCookies)(arr, n);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_set_cookie_domain_localhost_on_localhost) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: dl=1; path=%R; domain=localhost\r\n", 0);
    char lapi[600]; snprintf(lapi, sizeof lapi, "http://localhost%s", w.path);
    ck_track(lapi, "dl", NULL, 0); ck_track(lapi, "dl", "domain=localhost", 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, srv_url_host(w.s, "localhost", w.path), NULL, 0), 200);
    const char *g = ck_gets(lapi, NULL, 0);
    t_note("Set-Cookie domain=localhost from localhost: '%s'", g);
    EXPECT_STR(g, "");                                            /* VM boot 1 (API): Domain=localhost -> 87 */
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ request side */
TEST(ck_wire2_three_level_path_order) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[700];
    snprintf(d, sizeof d, "top=1; path=%s", w.path); ck_set(w.api, NULL, d);
    snprintf(d, sizeof d, "bot=3; path=%sa/b/", w.path); ck_set(w.api, NULL, d);
    snprintf(d, sizeof d, "mid=2; path=%sa/", w.path); ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, "a/b/c"), NULL, 0), 200);
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, "a/x"), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(chdr(w.s, 0), "bot=3; mid=2; top=1");
    EXPECT_STR(chdr(w.s, 1), "mid=2; top=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_cookie_header_position) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[600]; snprintf(d, sizeof d, "pos=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    int n = srv_req_header_count(w.s, 0), ci = srv_req_header_index(w.s, 0, "Cookie");
    char order[600] = "";
    for (int i = 0; i < n; i++) snprintf(order + strlen(order), sizeof order - strlen(order), "%s%s", i ? "," : "", srv_req_header_name(w.s, 0, i));
    t_note("request header order: %s (Cookie at %d of %d)", order, ci, n);
    CHECK(ci >= 0);
    EXPECT_STR(srv_req_header_name(w.s, 0, ci), "Cookie");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_no_cookies_on_one_request_only) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[600]; snprintf(d, sizeof d, "nc=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(w2_req(hi, &w, "GET", NULL, NULL, NULL, INTERNET_FLAG_NO_COOKIES), 200);
    EXPECT_EQ(w2_req(hi, &w, "GET", NULL, NULL, NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(chdr(w.s, 0), NULL);
    EXPECT_STR(chdr(w.s, 1), "nc=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_add_request_headers_cookie_with_jar) {
    REQ_W2(); REQUIRE(U(HttpAddRequestHeadersA));
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[600]; snprintf(d, sizeof d, "jar=1; path=%s", w.path);
    ck_set(w.api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(w.s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", w.path, NULL, NULL, NULL, CK_WIRE_BASE, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        EXPECT_EQ(U(HttpAddRequestHeadersA)(hr, "Cookie: mine=2\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD), TRUE);
        EXPECT_EQ(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), TRUE);
        char buf[256]; int ok; t_inet_read_all(hr, buf, sizeof buf, &ok);
        CHECK(srv_wait_requests(w.s, 1, 3000));
        const char *c = chdr(w.s, 0);
        t_note("HttpAddRequestHeaders Cookie + jar: '%s' (occurrences %d)", c ? c : "(none)", srv_req_header_occurrences(w.s, 0, "Cookie"));
        EXPECT_STR(c, "jar=1");                                   /* same as the lpszHeaders case (ck_wire_user_cookie_header_and_jar) */
        t_inet_close(hr);
    }
    t_inet_close(hc); t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_redirect_target_path_scoped_cookie) {
    REQ_W2();
    /* 302 from <path>from to <path>to/; cookie only for <path>to/ */
    srv_step st[] = { S_HEAD(), S_FMT("HTTP/1.1 302 Found\r\nLocation: %Rx/to/\r\nContent-Length: 0\r\n\r\n"), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    srv_script sc = { st, 5 };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = &sc; cfg.nscripts = 1;
    srv *s = NULL; CK_START_OR_SKIP(&cfg, &s);
    char path[300]; snprintf(path, sizeof path, "%s/", ck_upath("rd"));
    char api[500]; snprintf(api, sizeof api, "http://127.0.0.1%sx/to/", path);
    char d[700]; snprintf(d, sizeof d, "tgt=1; path=%sx/to/", path);
    ck_set(api, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, srv_url(s, path), NULL, 0), 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_header(s, 0, "Cookie"), NULL);
    t_note("redirect target: %s", srv_req_target(s, 1));
    EXPECT_STR(srv_req_header(s, 1, "Cookie"), "tgt=1");
    t_inet_close(hi); srv_stop(s);
    ck_cleanup();
}
TEST(ck_wire2_cookie_visible_to_new_session_after_close) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, "Set-Cookie: life=1; path=%R\r\n", 0);
    ck_track(w.api, "life", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    t_inet_close(hi);                                           /* the session that received it is gone */
    EXPECT_STR(ck_gets(w.api, NULL, 0), "life=1");
    HINTERNET h2 = t_inet_open("ck-wire2b");
    EXPECT_EQ(ck_wire_get(h2, w2url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(chdr(w.s, 1), "life=1");
    t_inet_close(h2); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire2_httponly_and_plain_both_sent) {
    REQ_W2();
    w2 w; W2_OR_SKIP(&w, 200, NULL, 0);
    char d[600];
    snprintf(d, sizeof d, "plain=1; path=%s", w.path); ck_set(w.api, NULL, d);
    snprintf(d, sizeof d, "ho=2; path=%s; HttpOnly", w.path); ck_setx(w.api, NULL, d, INTERNET_COOKIE_HTTPONLY, NULL);
    HINTERNET hi = t_inet_open("ck-wire2");
    EXPECT_EQ(ck_wire_get(hi, w2url(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(chdr(w.s, 0), "plain=1; ho=2");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
