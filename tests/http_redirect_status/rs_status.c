/* rs_status.c - non-redirect status codes pass through as data; status line parsing; interim 1xx; Retry-After/Refresh.
 * VM_TIMEOUT: 240
 * Decomp: HttpSendRequest_Start@0x72da0 (only 300..303/307/308 redirect; 401/407 auth; 408 resend), HttpQueryInfoA (STATUS_CODE
 * case 0x13, *len = 4 for FLAG_NUMBER), CHttpHeaders::_CopyValueToBuffer (122 + len+1). */
#include "rs.h"

/* ------------------------------------------------------------------ every status code is data, HttpSendRequest TRUE */
static void passthrough(int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    int nobody = code == 204 || code == 304;
    rs_add(&rt, "/s", code, "Content-Type: text/plain\r\nX-Code: %P\r\n", nobody ? "" : "status-body");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH | INTERNET_FLAG_NO_AUTH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr;
    rs_res r;
    SET_ERR(0xdeadbeef);
    rs_do(s, "GET", "/s", &o, &r);
    CHECKF(r.ok, "%d: err=%lu %s", code, r.err, rs_err(r.err));
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_STR(r.text, rs_reason(code));
    EXPECT_STR(r.version, "HTTP/1.1");
    if (nobody) EXPECT_EQ(r.nbody, 0); else EXPECT_STR(r.body, "status-body");
    CHECK(r.read_ok);
    if (hr) {
        char sc[16], want[16]; DWORD l = sizeof sc; snprintf(want, sizeof want, "%d", code);
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE, sc, &l, NULL));
        EXPECT_STR(sc, want); EXPECT_EQ(l, 3);
        WCHAR w[16]; l = sizeof w;
        CHECK(U(HttpQueryInfoW)(hr, HTTP_QUERY_STATUS_CODE, w, &l, NULL));
        EXPECT_EQ(l, 6);
        DWORD n = 0; l = sizeof n;
        CHECK(U(HttpQueryInfoW)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &n, &l, NULL));
        EXPECT_EQ(n, (DWORD)code); EXPECT_EQ(l, 4);
        char raw[1024]; l = sizeof raw;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF, raw, &l, NULL));
        char line[96]; snprintf(line, sizeof line, "HTTP/1.1 %d %s\r\n", code, rs_reason(code));
        CHECKF(!strncmp(raw, line, strlen(line)), "raw starts '%.40s'", raw);
        char ct[64]; l = sizeof ct;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_TYPE, ct, &l, NULL));
        EXPECT_STR(ct, "text/plain");
    }
    t_inet_close(hi);
    Sleep(20);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}
#define PT(c) TEST(rs_status_##c) { passthrough(c); }
PT(200) PT(201) PT(202) PT(203) PT(204) PT(205) PT(207) PT(208) PT(226)
PT(400) PT(401) PT(402) PT(403) PT(404) PT(405) PT(406) PT(409) PT(410) PT(411) PT(413) PT(414) PT(415)
PT(417) PT(418) PT(421) PT(422) PT(423) PT(424) PT(425) PT(426) PT(428) PT(429) PT(431) PT(451)
PT(500) PT(501) PT(502) PT(503) PT(504) PT(505) PT(506) PT(507) PT(508) PT(510) PT(511)

/* codes with side paths in the decomp: record what Win10 does, check the stable part */
static void special(int code, const char *hdrs, const char *tag) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", code, hdrs, "special-body");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    Sleep(100);
    t_note("%s: ok=%d err=%lu(%s) status=%lu reqs=%d body=%s", tag, r.ok, r.err, rs_err(r.err), r.status, srv_req_count(s), r.body);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_STR(r.body, "special-body");
    srv_stop(s);
}
TEST(rs_status_206_unsolicited)       { special(206, "Content-Range: bytes 0-11/100\r\n", "206 without Range"); }
TEST(rs_status_412_unsolicited)       { special(412, NULL, "412"); }
TEST(rs_status_416_unsolicited)       { special(416, "Content-Range: bytes */100\r\n", "416"); }
TEST(rs_status_401_no_challenge)      { special(401, NULL, "401 without WWW-Authenticate"); }
TEST(rs_status_407_no_challenge)      { special(407, NULL, "407 without Proxy-Authenticate, no proxy"); }
TEST(rs_status_401_basic_no_creds_noauth) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", 401, "WWW-Authenticate: Basic realm=\"rs\"\r\n", "denied");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH | INTERNET_FLAG_NO_AUTH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 401); EXPECT_STR(r.body, "denied");
    Sleep(50); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

/* 408 Request Timeout: the decomp has a resend path for 408 on reused keep-alive connections; on a fresh connection
 * it is returned. */
TEST(rs_status_408_fresh_connection) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", 408, NULL, "timeout");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    Sleep(100);
    t_note("408: ok=%d err=%lu status=%lu reqs=%d", r.ok, r.err, r.status, srv_req_count(s));
    CHECK(r.ok); EXPECT_EQ(r.status, 408);
    srv_stop(s);
}

/* ------------------------------------------------------------------ status line parsing */
static void statusline(const char *line, DWORD want_code, const char *want_text, const char *want_ver) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_route *e = rs_addx(&rt, "/s", 200, NULL, "sl", RS_F_RAWSTATUS);
    e->reason = line;
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    t_note("status line '%s': ok=%d err=%lu status=%lu text='%s' version='%s' body=%s", line, r.ok, r.err, r.status, r.text, r.version, r.body);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, want_code);
    if (want_text) EXPECT_STR(r.text, want_text);
    if (want_ver) EXPECT_STR(r.version, want_ver);
    srv_stop(s);
}
TEST(rs_line_custom_reason)        { statusline("HTTP/1.1 404 Nope Nope", 404, "Nope Nope", "HTTP/1.1"); }
TEST(rs_line_reason_empty)         { statusline("HTTP/1.1 200 ", 200, "", "HTTP/1.1"); }
TEST(rs_line_reason_missing)       { statusline("HTTP/1.1 200", 200, "", "HTTP/1.1"); }
TEST(rs_line_http10)               { statusline("HTTP/1.0 200 OK", 200, "OK", "HTTP/1.0"); }
TEST(rs_line_reason_wrong_for_code){ statusline("HTTP/1.1 500 OK", 500, "OK", "HTTP/1.1"); }
TEST(rs_line_reason_long)          { statusline("HTTP/1.1 201 A rather long reason phrase with several words", 201, "A rather long reason phrase with several words", NULL); }
TEST(rs_line_lowercase_reason)     { statusline("HTTP/1.1 200 ok", 200, "ok", NULL); }
TEST(rs_line_code_600)             { statusline("HTTP/1.1 600 Beyond", 600, "Beyond", NULL); }
TEST(rs_line_code_999)             { statusline("HTTP/1.1 999 Max", 999, "Max", NULL); }
TEST(rs_line_code_299)             { statusline("HTTP/1.1 299 Custom", 299, "Custom", NULL); }

static void odd_statusline(const char *line) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_route *e = rs_addx(&rt, "/s", 200, NULL, "sl", RS_F_RAWSTATUS | RS_F_CLOSE);
    e->reason = line;
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    t_note("odd status line '%s': ok=%d err=%lu(%s) status=%lu text='%s' version='%s'", line, r.ok, r.err, rs_err(r.err), r.status, r.text, r.version);
    srv_stop(s);
}
TEST(rs_line_odd_two_digit)   { odd_statusline("HTTP/1.1 99 Short"); }
TEST(rs_line_odd_four_digit)  { odd_statusline("HTTP/1.1 2000 Long"); }
TEST(rs_line_odd_nonnumeric)  { odd_statusline("HTTP/1.1 abc Bad"); }
TEST(rs_line_odd_http2)       { odd_statusline("HTTP/2 200 OK"); }
TEST(rs_line_odd_lowercase)   { odd_statusline("http/1.1 200 OK"); }
TEST(rs_line_odd_extra_space) { odd_statusline("HTTP/1.1  200 OK"); }
TEST(rs_line_odd_code_199)    { odd_statusline("HTTP/1.1 199 Odd"); }

/* ------------------------------------------------------------------ interim 1xx responses are skipped */
static void interim(const char *pre, int code, const char *tag) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_route *e = rs_addx(&rt, "/s", code, "X-Final: yes\r\n", "final-body", 0);
    e->pre = pre;
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    t_note("%s: ok=%d err=%lu status=%lu raw0='%.30s' intermediate_cb=%d", tag, r.ok, r.err, r.status, r.raw, rs_cb_count(INTERNET_STATUS_INTERMEDIATE_RESPONSE));
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_STR(r.body, "final-body");
    char line[64]; snprintf(line, sizeof line, "HTTP/1.1 %d ", code);
    CHECK(!strncmp(r.raw, line, strlen(line)));
    CHECK(strstr(r.raw, "X-Final: yes") != NULL);
    CHECK(strstr(r.raw, "Continue") == NULL);
    srv_stop(s);
}
TEST(rs_1xx_100_then_200)       { interim("HTTP/1.1 100 Continue\r\n\r\n", 200, "100+200"); }
TEST(rs_1xx_100_then_404)       { interim("HTTP/1.1 100 Continue\r\n\r\n", 404, "100+404"); }
TEST(rs_1xx_two_100s)           { interim("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n", 200, "100+100+200"); }
TEST(rs_1xx_102_processing)     { interim("HTTP/1.1 102 Processing\r\n\r\n", 200, "102+200"); }
TEST(rs_1xx_103_early_hints)    { interim("HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n", 200, "103+200"); }
TEST(rs_1xx_100_with_headers)   { interim("HTTP/1.1 100 Continue\r\nX-Interim: 1\r\n\r\n", 200, "100(hdr)+200"); }
TEST(rs_1xx_100_http10)         { interim("HTTP/1.0 100 Continue\r\n\r\n", 200, "1.0 100+200"); }

TEST(rs_1xx_100_then_redirect) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, "/src", 302, "Location: /dst\r\n", "", RS_F_100);
    rs_addx(&rt, "/dst", 200, NULL, "landed", RS_F_100);
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "landed");
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    srv_stop(s);
}

TEST(rs_1xx_100_on_post_body) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, "/p", 201, NULL, "created", RS_F_100);
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "0123456789";
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.data = data; o.ndata = 10; rs_res r;
    rs_do(s, "POST", "/p", &o, &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 201); EXPECT_STR(r.body, "created");
    size_t bl; const char *b = srv_req_body(s, 0, &bl);
    CHECK(b && bl == 10);
    t_note("Expect header sent by wininet: %s", srv_req_header(s, 0, "Expect") ? srv_req_header(s, 0, "Expect") : "(none)");
    CHECK(srv_req_header(s, 0, "Expect") == NULL);
    srv_stop(s);
}

/* interim responses raise INTERNET_STATUS_INTERMEDIATE_RESPONSE (120) with the interim status code */
TEST(rs_1xx_intermediate_callback) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_route *e = rs_addx(&rt, "/s", 200, NULL, "ok", 0);
    e->pre = "HTTP/1.1 100 Continue\r\n\r\n";
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    rs_cb_dump();
    int i = rs_cb_index(INTERNET_STATUS_INTERMEDIATE_RESPONSE, 0);
    t_note("INTERMEDIATE_RESPONSE count=%d first dw=%lu len=%lu", rs_cb_count(INTERNET_STATUS_INTERMEDIATE_RESPONSE), i >= 0 ? g_rs_cb.dw[i] : 0, i >= 0 ? g_rs_cb.len[i] : 0);
    CHECK(r.ok);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_INTERMEDIATE_RESPONSE), 1);
    if (i >= 0) { EXPECT_EQ(g_rs_cb.dw[i], 100); EXPECT_EQ(g_rs_cb.len[i], 4); }
    srv_stop(s);
}

/* ------------------------------------------------------------------ Retry-After / Refresh are informational only */
TEST(rs_retry_after_503_not_retried) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", 503, "Retry-After: 1\r\n", "busy");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 503); EXPECT_STR(r.body, "busy");
    if (hr) {
        char v[16]; DWORD l = sizeof v;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_RETRY_AFTER, v, &l, NULL)); EXPECT_STR(v, "1");
        DWORD n = 0; l = sizeof n;
        SET_ERR(0xdeadbeef);
        BOOL okn = U(HttpQueryInfoA)(hr, HTTP_QUERY_RETRY_AFTER | HTTP_QUERY_FLAG_NUMBER, &n, &l, NULL);
        DWORD en = okn ? 0 : GetLastError();
        /* Win10 VM boot rs2: the FLAG_NUMBER form of RETRY_AFTER fails (only the string form works) */
        t_note("RETRY_AFTER|FLAG_NUMBER: ok=%d err=%lu val=%lu len=%lu", okn, en, n, l);
        CHECK(!okn); EXPECT_EQ(en, ERROR_HTTP_INVALID_QUERY_REQUEST);   /* Win10 VM rs3: 12154 */
    }
    t_inet_close(hi);
    Sleep(1500);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(rs_retry_after_429_date) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", 429, "Retry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\n", "slow down");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 429);
    if (hr) {
        char v[64]; DWORD l = sizeof v;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_RETRY_AFTER, v, &l, NULL)); EXPECT_STR(v, "Wed, 21 Oct 2015 07:28:00 GMT");
    }
    t_inet_close(hi);
    Sleep(50); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(rs_retry_after_on_redirect_followed) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 301, "Location: /dst\r\nRetry-After: 120\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    srv_stop(s);
}

static void refresh(int code, const char *val) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    char h[200]; snprintf(h, sizeof h, "Refresh: %s\r\n", val);
    rs_add(&rt, "/s", code, h, "page");
    rs_add(&rt, "*", 200, NULL, "refreshed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, (DWORD)code); EXPECT_STR(r.body, "page");
    if (hr) {
        char v[200]; DWORD l = sizeof v; strcpy(v, "Refresh");
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, v, &l, NULL));
        EXPECT_STR(v, val);
        l = sizeof v; CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_REFRESH, v, &l, NULL)); EXPECT_STR(v, val);
    }
    t_inet_close(hi);
    Sleep(100); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}
TEST(rs_refresh_ignored_200)        { refresh(200, "0; url=/elsewhere"); }
TEST(rs_refresh_ignored_absolute)   { refresh(200, "0;URL=http://127.0.0.1:1/x"); }
TEST(rs_refresh_ignored_404)        { refresh(404, "1"); }

/* Content-Location is not a redirect either */
TEST(rs_content_location_ignored) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", 201, "Content-Location: /other\r\n", "made");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "POST", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 201); EXPECT_STR(r.url, srv_url(s, "/s"));
    Sleep(50); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

/* Location on a 2xx / 4xx / 5xx response is not followed (the switch only covers 3xx) */
static void location_on(int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", code, "Location: /else\r\n", "here");
    rs_add(&rt, "*", 200, NULL, "else");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, (DWORD)code); EXPECT_STR(r.body, "here"); EXPECT_STR(r.location, "/else");
    Sleep(50); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}
TEST(rs_location_on_200_ignored) { location_on(200); }
TEST(rs_location_on_201_ignored) { location_on(201); }
TEST(rs_location_on_404_ignored) { location_on(404); }
TEST(rs_location_on_500_ignored) { location_on(500); }

/* ------------------------------------------------------------------ error responses keep the connection usable */
TEST(rs_error_status_keepalive_reuse) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/404", 404, NULL, "nf");
    rs_add(&rt, "/500", 500, NULL, "ise");
    rs_add(&rt, "/ok", 200, NULL, "ok");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    const char *paths[] = { "/404", "/500", "/ok" }; DWORD want[] = { 404, 500, 200 };
    for (int i = 0; i < 3; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", paths[i], NULL, NULL, NULL, RS_FRESH | INTERNET_FLAG_KEEP_CONNECTION, 0);
        CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
        EXPECT_EQ(rs_status(hr), want[i]);
        char b[32]; t_inet_read_all(hr, b, sizeof b, NULL);
        U(InternetCloseHandle)(hr);
    }
    EXPECT_EQ(rs_wait(s, 3, 2000), 3);
    EXPECT_EQ(srv_conn_count(s), 1);
    EXPECT_EQ(srv_req_conn(s, 2), srv_req_conn(s, 0));
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* the same handle re-sent after a 404 */
TEST(rs_error_status_resend_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/x", 404, NULL, "nf");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, RS_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)); EXPECT_EQ(rs_status(hr), 404);
    char b[32]; t_inet_read_all(hr, b, sizeof b, NULL); EXPECT_STR(b, "nf");
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)); EXPECT_EQ(rs_status(hr), 404);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* InternetOpenUrl returns a handle for a 404/500 (no error) */
static void openurl_status(int code) {
    REQUIRE(U(InternetOpenUrlA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/x", code, NULL, "err-body");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    char body[64]; size_t n; DWORD err;
    int st = t_http_get(hi, srv_url(s, "/x"), NULL, RS_FRESH, body, sizeof body, &n, &err);
    EXPECT_EQ(st, code); EXPECT_EQ(err, 0); EXPECT_STR(body, "err-body");
    t_inet_close(hi); srv_stop(s);
}
TEST(rs_openurl_404) { openurl_status(404); }
TEST(rs_openurl_500) { openurl_status(500); }
TEST(rs_openurl_403) { openurl_status(403); }
TEST(rs_openurl_503) { openurl_status(503); }

/* HTTP_QUERY_STATUS_CODE argument rules */
TEST(rs_query_status_index_nonzero) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/x", 404, NULL, "nf");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/x", &o, &r);
    if (hr) {
        DWORD v = 0, l = sizeof v, idx = 0;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, &idx));
        EXPECT_EQ(v, 404);
        t_note("index after STATUS_CODE query: %lu", idx);
        idx = 1; l = sizeof v; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, &idx), ERROR_HTTP_HEADER_NOT_FOUND);
        l = 2; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 4);
        char b[2]; l = sizeof b; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE, b, &l, NULL), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 4);
        l = sizeof v; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_REQUEST_HEADERS, &v, &l, NULL), ERROR_HTTP_INVALID_QUERY_REQUEST);
        char t[32]; l = sizeof t;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_TEXT, t, &l, NULL)); EXPECT_STR(t, "Not Found"); EXPECT_EQ(l, 9);
        l = 0; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_TEXT, NULL, &l, NULL), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 10);
    }
    t_inet_close(hi); srv_stop(s);
}

/* 204 / 304 / HEAD: no body is read even if the server announces none */
TEST(rs_status_204_then_keepalive) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/x", 204, NULL, "");
    rs_add(&rt, "/y", 200, NULL, "next");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    char body[32]; size_t n; DWORD err;
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/x"), NULL, RS_FRESH, body, sizeof body, &n, &err), 204);
    EXPECT_EQ(n, 0);
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/y"), NULL, RS_FRESH, body, sizeof body, &n, &err), 200);
    EXPECT_STR(body, "next");
    EXPECT_EQ(srv_conn_count(s), 1);
    t_inet_close(hi); srv_stop(s);
}

TEST(rs_status_304_unsolicited_nocache) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/x", 304, "ETag: \"abc\"\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.hdrs = "If-None-Match: \"abc\"\r\n"; rs_res r;
    rs_do(s, "GET", "/x", &o, &r);
    t_note("unsolicited 304 (no cache entry): ok=%d err=%lu status=%lu n=%zu", r.ok, r.err, r.status, r.nbody);
    CHECK(r.ok); EXPECT_EQ(r.status, 304); EXPECT_EQ(r.nbody, 0);
    EXPECT_STR(srv_req_header(s, 0, "If-None-Match"), "\"abc\"");
    srv_stop(s);
}
