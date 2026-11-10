/* rs_limits.c - redirect limits, refused redirects, NO_AUTO_REDIRECT, confirmation/resend, scheme changes, options.
 * VM_TIMEOUT: 240
 * Decomp: HttpSendRequest_Start@0x72da0 (budget at fsm+0x100 from GlobalMaxHttpRedirects, 12156 when exhausted,
 *         12168 for non GET/HEAD and FORMS_SUBMIT), Redirect@0x12618 (scheme must be http/https, HTTPS->HTTP Referer
 *         removal, If-Modified-Since removal, 12040/12039/12052 zone-crossing warnings), InternetSetOptionA@0x551b0. */
#include "rs.h"

/* ------------------------------------------------------------------ redirect budget */
static int loop_case(const char *first, int nroutes, const char **paths, const char **locs, DWORD flags, rs_res *r) {
    rs_router rt; rs_router_init(&rt);
    char hdr[8][128];
    for (int i = 0; i < nroutes; i++) { snprintf(hdr[i], sizeof hdr[i], "Location: %s\r\n", locs[i]); rs_add(&rt, paths[i], 302, hdr[i], "again"); }
    srv *s = rs_start(&rt, SRV_HTTP);
    if (!s) return -1;
    rs_opt o = { 0 }; o.flags = flags;
    rs_do(s, "GET", first, &o, r);
    Sleep(100);
    int n = srv_req_count(s);
    srv_stop(s);
    return n;
}

TEST(rs_limit_loop_budget) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    Sleep(100);
    int n = srv_req_count(s);
    t_note("endless chain: ok=%d err=%lu(%s) status=%lu requests=%d url=%s", r.ok, r.err, rs_err(r.err), r.status, n, r.url);
    CHECK(!r.ok);
    EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_FAILED);
    CHECKF(n >= 5 && n <= 200, "requests=%d", n);
    EXPECT_EQ(srv_conn_count(s), 1);
    srv_stop(s);
}

TEST(rs_limit_loop_budget_exact) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    Sleep(100);
    int n = srv_req_count(s);
    /* the counter is fsm+0x100 = GlobalMaxHttpRedirects (registry MaxHttpRedirects); one request per budget unit + the first */
    t_note("redirect budget: %d requests before %lu", n, r.err);
    EXPECT_EQ(n, 11);   /* Win10 VM: budget 10 (async loop test boot rs2: 11 requests, 10 REDIRECT callbacks) */
    char last[32]; snprintf(last, sizeof last, "/loop/%d", n - 1);
    EXPECT_STR(srv_req_target(s, n - 1), last);
    srv_stop(s);
}

TEST(rs_limit_after_failure_state) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\nX-Hop: yes\r\n", "hopbody");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    Sleep(100);
    int n = srv_req_count(s);
    t_note("after 12156: status=%lu text=%s url=%s location=%s body=%s", r.status, r.text, r.url, r.location, r.body);
    EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_FAILED);
    EXPECT_EQ(r.status, 302);
    char want[64]; snprintf(want, sizeof want, "/loop/%d", n);
    EXPECT_STR(r.location, want);
    srv_stop(s);
}

TEST(rs_limit_self_loop) {
    REQUIRE(U(HttpSendRequestA));
    const char *p[] = { "/self" }, *l[] = { "/self" };
    rs_res r; int n = loop_case("/self", 1, p, l, RS_FRESH, &r);
    if (n < 0) { t_skip("server unavailable"); return; }
    t_note("self loop: ok=%d err=%lu requests=%d", r.ok, r.err, n);
    CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_FAILED);
    EXPECT_EQ(n, 11);   /* Win10 VM: budget 10 (async loop test boot rs2: 11 requests, 10 REDIRECT callbacks) */
}

TEST(rs_limit_two_cycle) {
    REQUIRE(U(HttpSendRequestA));
    const char *p[] = { "/a", "/b" }, *l[] = { "/b", "/a" };
    rs_res r; int n = loop_case("/a", 2, p, l, RS_FRESH, &r);
    if (n < 0) { t_skip("server unavailable"); return; }
    t_note("a<->b: ok=%d err=%lu requests=%d", r.ok, r.err, n);
    CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_FAILED);
    EXPECT_EQ(n, 11);   /* Win10 VM: budget 10 (async loop test boot rs2: 11 requests, 10 REDIRECT callbacks) */
}

TEST(rs_limit_loop_noautoredirect) {
    REQUIRE(U(HttpSendRequestA));
    const char *p[] = { "/self" }, *l[] = { "/self" };
    rs_res r; int n = loop_case("/self", 1, p, l, RS_NOREDIR, &r);
    if (n < 0) { t_skip("server unavailable"); return; }
    CHECK(r.ok); EXPECT_EQ(r.status, 302); EXPECT_EQ(n, 1);
    EXPECT_STR(r.location, "/self"); EXPECT_STR(r.body, "again");
}

/* each HttpSendRequest gets a fresh budget (RunSM resets it) */
TEST(rs_limit_budget_per_send) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/loop/0", NULL, NULL, NULL, RS_FRESH, 0);
    BOOL ok1 = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD e1 = GetLastError();
    Sleep(50); int n1 = srv_req_count(s);
    BOOL ok2 = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD e2 = GetLastError();
    Sleep(50); int n2 = srv_req_count(s) - n1;
    t_note("send1 ok=%d err=%lu n=%d; send2 ok=%d err=%lu n=%d", ok1, e1, n1, ok2, e2, n2);
    CHECK(!ok1); EXPECT_EQ(e1, ERROR_HTTP_REDIRECT_FAILED);
    CHECK(!ok2); EXPECT_EQ(e2, ERROR_HTTP_REDIRECT_FAILED);
    EXPECT_EQ(n1, n2);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ Locations that are not followed */
static void refused(const char *loc, int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    char hdr[300]; snprintf(hdr, sizeof hdr, "Location: %s\r\n", loc);
    rs_add(&rt, "/src", code, hdr, "refused-body");
    rs_add(&rt, "*", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    Sleep(50);
    int n = srv_req_count(s);
    t_note("Location '%s' (%d): ok=%d err=%lu(%s) status=%lu reqs=%d url=%s body=%s", loc, code, r.ok, r.err, rs_err(r.err), r.status, n, r.url, r.body);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_EQ(n, 1);
    /* Win10 VM boot rs2 (rs_openurl_302_ftp_refused): Redirect_Fsm drains the 3xx body before Redirect() refuses the
     * Location, so the returned 3xx has an empty body */
    EXPECT_EQ(r.nbody, 0);
    srv_stop(s);
}
TEST(rs_refuse_ftp_scheme)        { refused("ftp://127.0.0.1:%P/f.txt", 302); }
TEST(rs_refuse_file_scheme)       { refused("file:///C:/Windows/win.ini", 302); }
TEST(rs_refuse_mailto_scheme)     { refused("mailto:nobody@i7test.example", 302); }
TEST(rs_refuse_javascript_scheme) { refused("javascript:alert(1)", 302); }
TEST(rs_refuse_gopher_scheme)     { refused("gopher://127.0.0.1:%P/1", 302); }
TEST(rs_refuse_about_scheme)      { refused("about:blank", 302); }
TEST(rs_refuse_unknown_scheme)    { refused("i7x://127.0.0.1:%P/x", 302); }
TEST(rs_refuse_ftp_scheme_301)    { refused("ftp://127.0.0.1:%P/f.txt", 301); }
TEST(rs_refuse_ftp_scheme_307)    { refused("ftp://127.0.0.1:%P/f.txt", 307); }
TEST(rs_refuse_ftp_scheme_303)    { refused("ftp://127.0.0.1:%P/f.txt", 303); }
TEST(rs_refuse_empty_host)        { refused("http:///nohost", 302); }

static void odd_location(const char *loc) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    char hdr[300]; snprintf(hdr, sizeof hdr, "Location: %s\r\n", loc);
    rs_add(&rt, "/src", 302, hdr, "odd");
    rs_add(&rt, "*", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    Sleep(50);
    t_note("odd Location '%s': ok=%d err=%lu(%s) status=%lu reqs=%d tgt1=%s url=%s", loc, r.ok, r.err, rs_err(r.err), r.status, srv_req_count(s),
           srv_req_target(s, 1) ? srv_req_target(s, 1) : "-", r.url);
    srv_stop(s);
}
TEST(rs_odd_location_empty)        { odd_location(""); }
TEST(rs_odd_location_space_in_path){ odd_location("/a b"); }
TEST(rs_odd_location_utf8)         { odd_location("/caf\xc3\xa9"); }
TEST(rs_odd_location_backslash)    { odd_location("\\back"); }
TEST(rs_odd_location_userinfo)     { odd_location("http://user:pw@127.0.0.1:%P/ui"); }

/* ------------------------------------------------------------------ NO_AUTO_REDIRECT */
static void noauto(int code, const char *method) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Location: /dst\r\nX-Was: redirect\r\n", "moved");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "p=1";
    rs_opt o = { 0 }; o.flags = RS_NOREDIR; rs_res r;
    if (!strcmp(method, "POST")) { o.data = data; o.ndata = 3; }
    rs_do(s, method, "/src", &o, &r);
    Sleep(50);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(r.location, "/dst");
    if (strcmp(method, "HEAD")) EXPECT_STR(r.body, "moved"); else EXPECT_EQ(r.nbody, 0);
    char url[128]; snprintf(url, sizeof url, "http://%s/src", rs_hp(s));
    EXPECT_STR(r.url, url);
    EXPECT_STR(r.text, rs_reason(code));
    CHECK(strstr(r.raw, "X-Was: redirect") != NULL);
    srv_stop(s);
}
TEST(rs_noauto_301_get)  { noauto(301, "GET"); }
TEST(rs_noauto_302_get)  { noauto(302, "GET"); }
TEST(rs_noauto_303_get)  { noauto(303, "GET"); }
TEST(rs_noauto_307_get)  { noauto(307, "GET"); }
TEST(rs_noauto_308_get)  { noauto(308, "GET"); }
TEST(rs_noauto_300_get)  { noauto(300, "GET"); }
TEST(rs_noauto_301_post) { noauto(301, "POST"); }
TEST(rs_noauto_302_post) { noauto(302, "POST"); }
TEST(rs_noauto_303_post) { noauto(303, "POST"); }
TEST(rs_noauto_307_post) { noauto(307, "POST"); }
TEST(rs_noauto_308_post) { noauto(308, "POST"); }
TEST(rs_noauto_302_head) { noauto(302, "HEAD"); }
TEST(rs_noauto_302_put)  { noauto(302, "PUT"); }

/* The Location value is returned verbatim (not resolved against the request URL) */
TEST(rs_noauto_location_buffer_protocol) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: ../rel/path?x=1\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_NOREDIR; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/a/src", &o, &r);
    EXPECT_STR(r.location, "../rel/path?x=1");
    if (hr) {
        DWORD l = 0;
        SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_LOCATION, NULL, &l, NULL), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 16);
        char b[8]; l = sizeof b;
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_LOCATION, b, &l, NULL), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 16);
        char b2[16]; l = sizeof b2;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_LOCATION, b2, &l, NULL));
        EXPECT_EQ(l, 15); EXPECT_STR(b2, "../rel/path?x=1");
        WCHAR w[32]; l = sizeof w;
        CHECK(U(HttpQueryInfoW)(hr, HTTP_QUERY_LOCATION, w, &l, NULL));
        EXPECT_EQ(l, 30); EXPECT_WSTR(w, L"../rel/path?x=1");
        DWORD idx = 1; l = sizeof b2;
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_LOCATION, b2, &l, &idx), ERROR_HTTP_HEADER_NOT_FOUND);
        DWORD num = 0; l = sizeof num;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &num, &l, NULL));
        EXPECT_EQ(num, 302); EXPECT_EQ(l, 4);
        char sc[8]; l = sizeof sc;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE, sc, &l, NULL));
        EXPECT_STR(sc, "302"); EXPECT_EQ(l, 3);
    }
    t_inet_close(hi); srv_stop(s);
}

/* With NO_AUTO_REDIRECT the caller can follow by hand: the second request reuses the connection */
TEST(rs_noauto_manual_follow) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "m");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h1 = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_NOREDIR, 0);
    CHECK(U(HttpSendRequestA)(h1, NULL, 0, NULL, 0));
    char loc[64]; DWORD l = sizeof loc;
    CHECK(U(HttpQueryInfoA)(h1, HTTP_QUERY_LOCATION, loc, &l, NULL));
    char sink[64]; t_inet_read_all(h1, sink, sizeof sink, NULL);
    U(InternetCloseHandle)(h1);
    HINTERNET h2 = U(HttpOpenRequestA)(hc, "GET", loc, NULL, NULL, NULL, RS_NOREDIR, 0);
    CHECK(U(HttpSendRequestA)(h2, NULL, 0, NULL, 0));
    EXPECT_EQ(rs_status(h2), 200);
    U(InternetCloseHandle)(h2);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1));
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ 12168 and resending */
static void resend_after_confirm(int code, const char *method) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Location: /dst\r\n", "m");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, method, "/src", NULL, NULL, NULL, RS_FRESH, 0);
    static char data[] = "resend-me";
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, data, 9);
    DWORD e = GetLastError();
    char url[256]; DWORD l = sizeof url; url[0] = 0; U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, url, &l);
    t_note("%d %s: ok=%d err=%lu url-after=%s status=%lu", code, method, ok, e, url, rs_status(hr));
    CHECK(!ok); EXPECT_EQ(e, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    EXPECT_STR(url, srv_url(s, "/dst"));     /* Redirect() already moved the handle to the new URL */
    ok = U(HttpSendRequestA)(hr, NULL, 0, data, 9);
    e = GetLastError();
    CHECKF(ok, "resend err=%lu %s", e, rs_err(e));
    EXPECT_EQ(rs_status(hr), 200);
    int n = rs_wait(s, 2, 2000);
    EXPECT_EQ(n, 2);
    char want[64]; snprintf(want, sizeof want, "%s /dst HTTP/1.1", method);
    EXPECT_STR(srv_req_line(s, 1), want);
    size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
    CHECK(b && bl == 9 && !memcmp(b, "resend-me", 9));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(rs_confirm_resend_307_post) { resend_after_confirm(307, "POST"); }
TEST(rs_confirm_resend_308_post) { resend_after_confirm(308, "POST"); }
TEST(rs_confirm_resend_307_put)  { resend_after_confirm(307, "PUT"); }
TEST(rs_confirm_resend_302_put)  { resend_after_confirm(302, "PUT"); }
TEST(rs_confirm_resend_301_delete) { resend_after_confirm(301, "DELETE"); }

/* INTERNET_FLAG_FORMS_SUBMIT (0x40): any followed redirect asks for confirmation (fsm+0x138) */
static void forms_submit(int code, const char *method) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Location: /dst\r\n", "m");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "f=1";
    rs_opt o = { 0 }; o.flags = RS_FRESH | INTERNET_FLAG_FORMS_SUBMIT; rs_res r;
    if (strcmp(method, "GET")) { o.data = data; o.ndata = 3; }
    rs_do(s, method, "/src", &o, &r);
    Sleep(50);
    t_note("FORMS_SUBMIT %d %s: ok=%d err=%lu status=%lu reqs=%d", code, method, r.ok, r.err, r.status, srv_req_count(s));
    CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}
TEST(rs_forms_submit_302_get)  { forms_submit(302, "GET"); }
TEST(rs_forms_submit_302_post) { forms_submit(302, "POST"); }
TEST(rs_forms_submit_303_post) { forms_submit(303, "POST"); }
TEST(rs_forms_submit_301_get)  { forms_submit(301, "GET"); }
TEST(rs_forms_submit_307_get)  { forms_submit(307, "GET"); }

TEST(rs_forms_submit_200_unaffected) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/f", 200, NULL, "fine");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH | INTERNET_FLAG_FORMS_SUBMIT; rs_res r;
    rs_do(s, "POST", "/f", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "fine");
    srv_stop(s);
}

/* ------------------------------------------------------------------ headers rewritten by Redirect() */
TEST(rs_hdr_if_modified_since_dropped) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.hdrs = "If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\nX-Other: 1\r\n"; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_STR(srv_req_header(s, 0, "If-Modified-Since"), "Sat, 29 Oct 1994 19:43:31 GMT");
    CHECK(srv_req_header(s, 1, "If-Modified-Since") == NULL);
    EXPECT_STR(srv_req_header(s, 1, "X-Other"), "1");
    srv_stop(s);
}

TEST(rs_hdr_referer_kept_same_scheme) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.referrer = "http://ref.i7test.example/page"; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_STR(srv_req_header(s, 0, "Referer"), "http://ref.i7test.example/page");
    EXPECT_STR(srv_req_header(s, 1, "Referer"), "http://ref.i7test.example/page");
    srv_stop(s);
}

TEST(rs_hdr_wininet_adds_no_referer) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    CHECK(srv_req_header(s, 1, "Referer") == NULL);
    for (int i = 0; i < srv_req_header_count(s, 1); i++) t_note("hop hdr[%d] %s: %s", i, srv_req_header_name(s, 1, i), srv_req_header_value(s, 1, i));
    EXPECT_EQ(srv_req_header_count(s, 1), srv_req_header_count(s, 0));
    for (int i = 0; i < srv_req_header_count(s, 0) && i < srv_req_header_count(s, 1); i++)
        EXPECT_STR(srv_req_header_name(s, 1, i), srv_req_header_name(s, 0, i));
    srv_stop(s);
}

TEST(rs_hdr_custom_authorization_on_hop) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.hdrs = "Authorization: Bearer i7-dummy-token\r\nCookie: manual=1\r\n"; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    t_note("hop Authorization=%s Cookie=%s", srv_req_header(s, 1, "Authorization") ? srv_req_header(s, 1, "Authorization") : "(none)",
           srv_req_header(s, 1, "Cookie") ? srv_req_header(s, 1, "Cookie") : "(none)");
    EXPECT_STR(srv_req_header(s, 0, "Authorization"), "Bearer i7-dummy-token");
    srv_stop(s);
}

/* ------------------------------------------------------------------ scheme changes (HTTPS server over schannel) */
static void scheme_change(int from_https, DWORD extra_flags, const char *method, const char *tag) {
    REQUIRE(U(HttpSendRequestA));
    rs_router r2; rs_router_init(&r2);
    rs_add(&r2, "/landing", 200, NULL, "landed");
    srv *s2 = rs_start(&r2, from_https ? SRV_HTTP : SRV_HTTPS);
    if (!s2) { t_skip("target server unavailable: %s", srv_strerror(srv_last_error())); return; }
    rs_router rt; rs_router_init(&rt); rt.alt_port = srv_port(s2);
    rs_add(&rt, "/src", 302, from_https ? "Location: http://127.0.0.1:%A/landing\r\n" : "Location: https://127.0.0.1:%A/landing\r\n", "m");
    srv *s = rs_start(&rt, from_https ? SRV_HTTPS : SRV_HTTP);
    if (!s) { srv_stop(s2); t_skip("source server unavailable: %s", srv_strerror(srv_last_error())); return; }
    static const char data[] = "x=1";
    rs_opt o = { 0 }; o.flags = RS_FRESH | extra_flags; o.referrer = "http://ref.i7test.example/r"; rs_res r;
    if (!from_https) o.secflags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    if (!strcmp(method, "POST")) { o.data = data; o.ndata = 3; }
    rs_do(s, method, "/src", &o, &r);
    Sleep(100);
    t_note("%s: ok=%d err=%lu(%s) status=%lu src_reqs=%d dst_reqs=%d url=%s", tag, r.ok, r.err, rs_err(r.err), r.status, srv_req_count(s), srv_req_count(s2), r.url);
    if (srv_req_count(s2) > 0) t_note("%s: target Referer=%s", tag, srv_req_header(s2, 0, "Referer") ? srv_req_header(s2, 0, "Referer") : "(none)");
    EXPECT_EQ(srv_req_count(s), 1);
    if (from_https) {
        /* HTTPS -> HTTP: followed; Redirect() drops the Referer header when leaving https */
        CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
        EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "landed");
        EXPECT_EQ(srv_req_count(s2), 1);
        CHECK(srv_req_header(s2, 0, "Referer") == NULL);
        char want[64]; snprintf(want, sizeof want, "%s /landing HTTP/1.1", !strcmp(method, "POST") ? "GET" : method);
        EXPECT_STR(srv_req_line(s2, 0), want);
        EXPECT_STR(r.url, srv_url(s2, "/landing"));
    } else {
        CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
        EXPECT_EQ(r.status, 200);
        EXPECT_EQ(srv_req_count(s2), 1);
        EXPECT_STR(r.url, srv_url(s2, "/landing"));
        EXPECT_STR(srv_req_header(s2, 0, "Referer"), "http://ref.i7test.example/r");
    }
    srv_stop(s); srv_stop(s2);
}
TEST(rs_scheme_https_to_http_get)          { scheme_change(1, 0, "GET", "https->http GET"); }
TEST(rs_scheme_https_to_http_post)         { scheme_change(1, 0, "POST", "https->http POST"); }
TEST(rs_scheme_https_to_http_ignore_flag)  { scheme_change(1, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP, "GET", "https->http IGNORE_TO_HTTP"); }
TEST(rs_scheme_http_to_https_get)          { scheme_change(0, 0, "GET", "http->https GET"); }
TEST(rs_scheme_http_to_https_ignore_flag)  { scheme_change(0, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, "GET", "http->https IGNORE_TO_HTTPS"); }

/* http -> https without any certificate ignore flag: the hop fails on the self-signed certificate */
TEST(rs_scheme_http_to_https_untrusted_cert) {
    REQUIRE(U(HttpSendRequestA));
    rs_router r2; rs_router_init(&r2);
    rs_add(&r2, "/landing", 200, NULL, "landed");
    srv *s2 = rs_start(&r2, SRV_HTTPS);
    if (!s2) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    rs_router rt; rs_router_init(&rt); rt.alt_port = srv_port(s2);
    rs_add(&rt, "/src", 302, "Location: https://127.0.0.1:%A/landing\r\n", "m");
    srv *s = rs_start(&rt, SRV_HTTP);
    if (!s) { srv_stop(s2); t_skip("server unavailable"); return; }
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    t_note("http->https untrusted: ok=%d err=%lu(%s) status=%lu url=%s", r.ok, r.err, rs_err(r.err), r.status, r.url);
    CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_INTERNET_INVALID_CA);
    EXPECT_EQ(srv_req_count(s2), 0);
    EXPECT_STR(r.url, srv_url(s2, "/landing"));
    srv_stop(s); srv_stop(s2);
}

/* https -> https on the same server (certificate flags of the handle stay in force) */
TEST(rs_scheme_https_same_server) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 301, "Location: /secure-dst\r\n", "");
    rs_add(&rt, "/secure-dst", 200, NULL, "secure-landed");
    srv *s; RS_START(&rt, SRV_HTTPS, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "secure-landed");
    EXPECT_STR(r.url, srv_url(s, "/secure-dst"));
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    srv_stop(s);
}

/* ------------------------------------------------------------------ options */
/* WinINet has no INTERNET_OPTION_REDIRECT_POLICY / MAX_REDIRECTS: 88 is WinHTTP's REDIRECT_POLICY number; in wininet
 * option 88 is a request-handle BOOL guarded by GlobalSendUTF8ServerToProxy (12009 when that is off). */
TEST(rs_option_88_is_not_redirect_policy) {
    REQUIRE(U(InternetSetOptionA));
    srv *s = rs_plain(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, RS_FRESH, 0);
    DWORD v = 0; SET_ERR(0);
    BOOL ok = U(InternetSetOptionA)(hr, 88, &v, sizeof v); DWORD e = GetLastError();
    t_note("InternetSetOption(req, 88, 0): ok=%d err=%lu", ok, e);
    DWORD q = 0, l = sizeof q; SET_ERR(0);
    BOOL okq = U(InternetQueryOptionA)(hr, 88, &q, &l); DWORD eq = GetLastError();
    t_note("InternetQueryOption(req, 88): ok=%d err=%lu val=%lu", okq, eq, q);
    CHECK(!okq);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

TEST(rs_option_enable_redirect_cache_read) {
    REQUIRE(U(InternetSetOptionA));
    srv *s = rs_plain(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, RS_FRESH, 0);
    DWORD v = 1; SET_ERR(0);
    CHECKF(U(InternetSetOptionA)(hr, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, sizeof v), "err=%lu", GetLastError());
    SET_ERR(0);
    BOOL ok = U(InternetSetOptionA)(hi, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, sizeof v); DWORD e = GetLastError();
    t_note("ENABLE_REDIRECT_CACHE_READ on session: ok=%d err=%lu", ok, e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    ok = U(InternetSetOptionA)(hr, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 2); e = GetLastError();
    t_note("ENABLE_REDIRECT_CACHE_READ len 2: ok=%d err=%lu", ok, e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* the request flags (INTERNET_OPTION_REQUEST_FLAGS / FLAGS) reflect NO_AUTO_REDIRECT */
TEST(rs_option_flags_reflect_noauto) {
    REQUIRE(U(InternetQueryOptionA));
    srv *s = rs_plain(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, RS_NOREDIR, 0);
    DWORD f = 0, l = sizeof f;
    CHECKF(U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &f, &l), "err=%lu", GetLastError());
    t_note("INTERNET_OPTION_REQUEST_FLAGS (NO_AUTO_REDIRECT request) = 0x%lx", f);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
