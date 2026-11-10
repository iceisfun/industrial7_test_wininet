/* rs_more.c - redirects through HttpSendRequestEx/HttpEndRequest, the W entry points, async mode, mixed chains,
 * redirect targets that answer with errors, cookies on unfollowed 3xx, and HttpQueryInfo on the final response.
 * VM_TIMEOUT: 240
 * Decomp: HttpSendRequest_Start@0x72da0 (redirect switch, budget fsm+0x100 -> 12156, confirmation fsm+0xf8/0x138 -> 12168,
 *         ExtractSetCookieHeaders before the switch unless NO_COOKIES 0x80000), Redirect@0x12618 (scheme 3/4 only,
 *         Host replaced, Content-Length/Content-Type removed for GET, If-Modified-Since (0x20) always removed,
 *         InternetIndicateStatusString(110, new URL)). */
#include "rs.h"

/* ------------------------------------------------------------------ HttpSendRequestEx / HttpEndRequest */
typedef struct { BOOL sendex, write, end; DWORD esendex, eend, written; } rs_ex;

static void do_sendex(HINTERNET hr, const char *data, DWORD n, rs_ex *x) {
    memset(x, 0, sizeof *x);
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = n;
    SetLastError(0xdeadbeef);
    x->sendex = U(HttpSendRequestExA)(hr, &ib, NULL, 0, 0); x->esendex = x->sendex ? 0 : GetLastError();
    if (!x->sendex) return;
    x->write = TRUE;
    if (n) x->write = U(InternetWriteFile)(hr, data, n, &x->written);
    SetLastError(0xdeadbeef);
    x->end = U(HttpEndRequestA)(hr, NULL, 0, 0); x->eend = x->end ? 0 : GetLastError();
}

static void sendex_redirect(int code, const char *method, int want_follow, const char *want_method2) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Location: /dst\r\n", "moved");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open("rs-agent/1.0");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    HINTERNET hr = U(HttpOpenRequestA)(hc, method, "/src", NULL, NULL, NULL, RS_FRESH, 2);
    CHECK(hr != NULL);
    rs_ex x; do_sendex(hr, "0123456789", 10, &x);
    rs_res r; memset(&r, 0, sizeof r); rs_collect(hr, &r, 1);
    int n = rs_wait(s, want_follow == 1 ? 2 : 1, 2000);
    t_note("SendRequestEx %d %s: sendex=%d write=%d(%lu) end=%d err=%lu(%s) status=%lu reqs=%d url=%s", code, method, x.sendex, x.write,
           x.written, x.end, x.eend, rs_err(x.eend), r.status, n, r.url);
    CHECK(x.sendex); CHECK(x.write); EXPECT_EQ(x.written, 10);
    char line[64]; snprintf(line, sizeof line, "%s /src HTTP/1.1", method);
    EXPECT_STR(srv_req_line(s, 0), line);
    EXPECT_STR(srv_req_header(s, 0, "Content-Length"), "10");
    if (want_follow == 1) {
        CHECKF(x.end, "err=%lu %s", x.eend, rs_err(x.eend));
        EXPECT_EQ(r.status, 200); EXPECT_EQ(n, 2); EXPECT_STR(r.body, "landed");
        snprintf(line, sizeof line, "%s /dst HTTP/1.1", want_method2);
        EXPECT_STR(srv_req_line(s, 1), line);
        EXPECT_STR(r.url, srv_url(s, "/dst"));
    } else if (want_follow == 0) {
        CHECKF(x.end, "err=%lu", x.eend);
        EXPECT_EQ(r.status, (DWORD)code); EXPECT_EQ(n, 1);
    } else {
        CHECK(!x.end); EXPECT_EQ(x.eend, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION); EXPECT_EQ(n, 1);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(rs_sendex_302_post_to_get)   { sendex_redirect(302, "POST", 1, "GET"); }
TEST(rs_sendex_301_post_to_get)   { sendex_redirect(301, "POST", 1, "GET"); }
TEST(rs_sendex_303_post_to_get)   { sendex_redirect(303, "POST", 1, "GET"); }
TEST(rs_sendex_303_put_to_get)    { sendex_redirect(303, "PUT", 1, "GET"); }
TEST(rs_sendex_307_post_confirm)  { sendex_redirect(307, "POST", 2, NULL); }
TEST(rs_sendex_308_post_confirm)  { sendex_redirect(308, "POST", 2, NULL); }
TEST(rs_sendex_302_put_confirm)   { sendex_redirect(302, "PUT", 2, NULL); }

TEST(rs_sendex_noauto_302_post) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "moved");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/src", NULL, NULL, NULL, RS_NOREDIR, 0);
    rs_ex x; do_sendex(hr, "abc", 3, &x);
    CHECK(x.sendex); CHECKF(x.end, "err=%lu", x.eend);
    EXPECT_EQ(rs_status(hr), 302);
    char b[32]; t_inet_read_all(hr, b, sizeof b, NULL); EXPECT_STR(b, "moved");
    Sleep(50); EXPECT_EQ(srv_req_count(s), 1);
    size_t bl; const char *body = srv_req_body(s, 0, &bl); CHECK(body && bl == 3 && !memcmp(body, "abc", 3));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ W entry points */
TEST(rs_w_sendrequest_redirect_url) {
    REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW)); REQUIRE(U(InternetQueryOptionW));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/wsrc", 301, "Location: /wdst?x=1\r\n", "");
    rs_add(&rt, "/wdst?x=1", 200, NULL, "wlanded");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = U(InternetOpenW)(L"rs-w/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"POST", L"/wsrc", NULL, NULL, NULL, RS_FRESH, 0);
    static char d[] = "w=1";
    CHECK(U(HttpSendRequestW)(hr, L"X-W: 1\r\n", (DWORD)-1, d, 3));
    EXPECT_EQ(rs_status(hr), 200);
    WCHAR w[256]; DWORD l = sizeof w;
    CHECK(U(InternetQueryOptionW)(hr, INTERNET_OPTION_URL, w, &l));
    WCHAR want[128]; swprintf(want, 128, L"http://127.0.0.1:%u/wdst?x=1", srv_port(s));
    EXPECT_WSTR(w, want);
    t_note("InternetQueryOptionW(URL) len=%lu for %d chars", l, lstrlenW(want));
    EXPECT_EQ(l, (DWORD)lstrlenW(want) * 2);
    WCHAR st[16]; l = sizeof st;
    CHECK(U(HttpQueryInfoW)(hr, HTTP_QUERY_STATUS_CODE, st, &l, NULL)); EXPECT_WSTR(st, L"200"); EXPECT_EQ(l, 6);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_STR(srv_req_line(s, 1), "GET /wdst?x=1 HTTP/1.1");
    EXPECT_STR(srv_req_header(s, 1, "X-W"), "1");
    EXPECT_STR(srv_req_header(s, 1, "User-Agent"), "rs-w/1.0");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi); srv_stop(s);
}

TEST(rs_w_openurl_redirect) {
    REQUIRE(U(InternetOpenUrlW));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/a", 302, "Location: http://localhost:%P/b\r\n", "");
    rs_add(&rt, "/b", 200, NULL, "wb");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    WCHAR url[128]; swprintf(url, 128, L"http://127.0.0.1:%u/a", srv_port(s));
    HINTERNET hu = U(InternetOpenUrlW)(hi, url, NULL, 0, RS_FRESH, 0);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (hu) {
        WCHAR w[256]; DWORD l = sizeof w;
        CHECK(U(InternetQueryOptionW)(hu, INTERNET_OPTION_URL, w, &l));
        WCHAR want[128]; swprintf(want, 128, L"http://localhost:%u/b", srv_port(s));
        EXPECT_WSTR(w, want);
        EXPECT_EQ(rs_status(hu), 200);
        U(InternetCloseHandle)(hu);
    }
    t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl table */
typedef struct { int code; const char *loc; const char *want_path; int follow; } ou_case;
static void openurl_case(const ou_case *c) {
    REQUIRE(U(InternetOpenUrlA));
    rs_router rt; rs_router_init(&rt);
    char hdr[256]; snprintf(hdr, sizeof hdr, "Location: %s\r\n", c->loc);
    rs_add(&rt, "/d1/d2/src", c->code, hdr, "src-body");
    rs_add(&rt, "*", 200, NULL, "dst-body");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/d1/d2/src"), NULL, 0, RS_FRESH, 7);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (hu) {
        rs_res r; memset(&r, 0, sizeof r); rs_collect(hu, &r, 1);
        if (c->follow) {
            EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "dst-body");
            EXPECT_STR(r.url, srv_url(s, c->want_path));
            EXPECT_EQ(rs_wait(s, 2, 2000), 2);
            EXPECT_STR(srv_req_target(s, 1), c->want_path);
        } else {
            EXPECT_EQ(r.status, (DWORD)c->code); EXPECT_STR(r.body, "src-body");
            Sleep(30); EXPECT_EQ(srv_req_count(s), 1);
        }
        U(InternetCloseHandle)(hu);
    }
    t_inet_close(hi); srv_stop(s);
}
#define OU(name, code, loc, path, f) TEST(rs_openurl_##name) { static const ou_case c = { code, loc, path, f }; openurl_case(&c); }
OU(301_abs, 301, "/x1", "/x1", 1)
OU(302_rel, 302, "sib", "/d1/d2/sib", 1)
OU(303_dotdot, 303, "../up", "/d1/up", 1)
OU(307_query, 307, "?q=7", "/d1/d2/src?q=7", 1)
OU(308_full, 308, "http://127.0.0.1:%P/full", "/full", 1)
OU(302_proto_rel, 302, "//127.0.0.1:%P/pr", "/pr", 1)
OU(302_dotdot_above_root, 302, "../../../../top", "/top", 1)
OU(302_ftp_refused, 302, "ftp://127.0.0.1:%P/f", NULL, 0)
OU(304_not_followed, 304, "/x", NULL, 0)
OU(305_not_followed, 305, "/x", NULL, 0)

/* ------------------------------------------------------------------ mixed chains: method per hop */
static void mixed_chain(const char *method, const int *codes, int ncodes, const char **want_methods) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    static char paths[8][16], hdrs[8][64];
    for (int i = 0; i < ncodes; i++) {
        snprintf(paths[i], sizeof paths[i], "/h%d", i);
        snprintf(hdrs[i], sizeof hdrs[i], "Location: /h%d\r\n", i + 1);
        rs_add(&rt, paths[i], codes[i], hdrs[i], "");
    }
    rs_add(&rt, "*", 200, NULL, "end");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "body=1";
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    if (strcmp(method, "GET") && strcmp(method, "HEAD")) { o.data = data; o.ndata = 6; }
    rs_do(s, method, "/h0", &o, &r);
    int n = rs_wait(s, ncodes + 1, 3000);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 200); EXPECT_EQ(n, ncodes + 1);
    for (int i = 0; i <= ncodes && i < n; i++) {
        char want[48]; snprintf(want, sizeof want, "%s /h%d HTTP/1.1", want_methods[i], i);
        EXPECT_STR(srv_req_line(s, i), want);
    }
    EXPECT_EQ(srv_conn_count(s), 1);
    srv_stop(s);
}
TEST(rs_mixed_get_all_codes) {
    static const int c[] = { 301, 302, 303, 307, 308 };
    static const char *m[] = { "GET", "GET", "GET", "GET", "GET", "GET" };
    mixed_chain("GET", c, 5, m);
}
TEST(rs_mixed_head_303_becomes_get) {
    static const int c[] = { 301, 307, 303, 302 };
    static const char *m[] = { "HEAD", "HEAD", "HEAD", "GET", "GET" };
    mixed_chain("HEAD", c, 4, m);
}
TEST(rs_mixed_post_302_then_307) {
    static const int c[] = { 302, 307, 308 };
    static const char *m[] = { "POST", "GET", "GET", "GET" };
    mixed_chain("POST", c, 3, m);
}
TEST(rs_mixed_put_303_then_301) {
    static const int c[] = { 303, 301, 302 };
    static const char *m[] = { "PUT", "GET", "GET", "GET" };
    mixed_chain("PUT", c, 3, m);
}

/* ------------------------------------------------------------------ the redirect target answers with an error */
static void target_status(int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", code, "X-Target: 1\r\n", code == 204 || code == 304 ? "" : "target-error");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH | INTERNET_FLAG_NO_AUTH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECKF(r.ok, "%d: err=%lu %s", code, r.err, rs_err(r.err));
    EXPECT_EQ(r.status, (DWORD)code);
    EXPECT_STR(r.text, rs_reason(code));
    EXPECT_STR(r.url, srv_url(s, "/dst"));
    if (code != 204 && code != 304) EXPECT_STR(r.body, "target-error");
    CHECK(strstr(r.raw, "X-Target: 1") != NULL);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    srv_stop(s);
}
TEST(rs_target_204) { target_status(204); }
TEST(rs_target_400) { target_status(400); }
TEST(rs_target_401) { target_status(401); }
TEST(rs_target_403) { target_status(403); }
TEST(rs_target_404) { target_status(404); }
TEST(rs_target_410) { target_status(410); }
TEST(rs_target_500) { target_status(500); }
TEST(rs_target_502) { target_status(502); }
TEST(rs_target_503) { target_status(503); }

/* the redirect target closes the connection without answering */
TEST(rs_target_drops_connection) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_CLOSE() };
    static const srv_step st2[] = { S_HEAD(), S_CLOSE() };
    static const srv_script sc[] = { SRV_SCRIPT(st), SRV_SCRIPT(st2) };
    srv_config cfg = { SRV_HTTP, sc, 2 }; srv *s;
    if (srv_start(&cfg, &s)) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_FRESH, 0);
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD e = GetLastError();
    char url[256]; DWORD l = sizeof url; url[0] = 0; U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, url, &l);
    t_note("target drops: ok=%d err=%lu(%s) reqs=%d conns=%d url=%s", ok, e, rs_err(e), srv_req_count(s), srv_conn_count(s), url);
    CHECK(!ok);
    CHECKF(e == ERROR_INTERNET_CONNECTION_RESET || e == ERROR_HTTP_INVALID_SERVER_RESPONSE || e == ERROR_INTERNET_CONNECTION_ABORTED,
           "err=%lu %s", e, rs_err(e));
    EXPECT_STR(url, srv_url(s, "/dst"));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ state after a failed redirect budget */
TEST(rs_limit_url_after_failure) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    Sleep(50);
    int n = srv_req_count(s);
    char want[64]; snprintf(want, sizeof want, "/loop/%d", n - 1);
    t_note("after 12156: url=%s reqs=%d", r.url, n);
    EXPECT_STR(r.url, srv_url(s, want));
    srv_stop(s);
}

/* ------------------------------------------------------------------ cookies on a 3xx that is not followed */
TEST(rs_cookie_on_noauto_302_stored) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetGetCookieA));
    char path[96]; snprintf(path, sizeof path, "/%s", t_uniq("cknoauto"));
    char src[128], hdr[256], ckurl[200];
    snprintf(src, sizeof src, "%s/src", path);
    snprintf(hdr, sizeof hdr, "Set-Cookie: rsna=1; Path=%s\r\nLocation: %s/dst\r\n", path, path);
    snprintf(ckurl, sizeof ckurl, "http://127.0.0.1%s/", path);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, src, 302, hdr, "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(ckurl, "rsna");
    rs_opt o = { 0 }; o.flags = RS_FRESH_COOKIES | INTERNET_FLAG_NO_AUTO_REDIRECT; rs_res r;
    rs_do(s, "GET", src, &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 302);
    char jar[128]; DWORD l = sizeof jar;
    CHECK(U(InternetGetCookieA)(ckurl, NULL, jar, &l));
    EXPECT_STR(jar, "rsna=1");
    t_net_cleanup(); srv_stop(s);
}

TEST(rs_cookie_on_refused_redirect_stored) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetGetCookieA));
    char path[96]; snprintf(path, sizeof path, "/%s", t_uniq("ckref"));
    char src[128], hdr[256], ckurl[200];
    snprintf(src, sizeof src, "%s/src", path);
    snprintf(hdr, sizeof hdr, "Set-Cookie: rsrf=2; Path=%s\r\nLocation: ftp://127.0.0.1:%%P/x\r\n", path);
    snprintf(ckurl, sizeof ckurl, "http://127.0.0.1%s/", path);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, src, 302, hdr, "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(ckurl, "rsrf");
    rs_opt o = { 0 }; o.flags = RS_FRESH_COOKIES; rs_res r;
    rs_do(s, "GET", src, &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 302);
    char jar[128]; DWORD l = sizeof jar;
    CHECK(U(InternetGetCookieA)(ckurl, NULL, jar, &l));
    EXPECT_STR(jar, "rsrf=2");
    t_net_cleanup(); srv_stop(s);
}

/* a cookie set by 127.0.0.1's 302 is not sent to localhost after a host-changing redirect */
TEST(rs_cookie_not_sent_to_other_host) {
    REQUIRE(U(HttpSendRequestA));
    char path[96]; snprintf(path, sizeof path, "/%s", t_uniq("ckhost"));
    char src[128], dst[128], hdr[300], ckurl[200];
    snprintf(src, sizeof src, "%s/src", path); snprintf(dst, sizeof dst, "%s/dst", path);
    snprintf(hdr, sizeof hdr, "Set-Cookie: rsho=3; Path=%s\r\nLocation: http://localhost:%%P%s\r\n", path, dst);
    snprintf(ckurl, sizeof ckurl, "http://127.0.0.1%s/", path);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, src, 302, hdr, "");
    rs_add(&rt, dst, 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(ckurl, "rsho");
    rs_opt o = { 0 }; o.flags = RS_FRESH_COOKIES; rs_res r;
    rs_do(s, "GET", src, &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    CHECK(srv_req_header(s, 1, "Cookie") == NULL);
    t_net_cleanup(); srv_stop(s);
}

/* ------------------------------------------------------------------ headers added with HttpAddRequestHeaders survive a hop */
TEST(rs_addheaders_survive_hop) {
    REQUIRE(U(HttpAddRequestHeadersA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 307, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_FRESH, 0);
    CHECK(U(HttpAddRequestHeadersA)(hr, "X-Added: one\r\nAccept: text/rs\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(rs_status(hr), 200);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    for (int i = 0; i < 2; i++) {
        EXPECT_STR(srv_req_header(s, i, "X-Added"), "one");
        EXPECT_STR(srv_req_header(s, i, "Accept"), "text/rs");
        EXPECT_EQ(srv_req_header_occurrences(s, i, "Host"), 1);
        EXPECT_EQ(srv_req_header_occurrences(s, i, "X-Added"), 1);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* Host header follows the new authority and is not duplicated; a caller-supplied Host is replaced */
TEST(rs_host_header_caller_supplied) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: http://localhost:%P/dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.hdrs = "Host: custom.i7test.example\r\n"; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    t_note("caller Host: req0=%s req1=%s", srv_req_header(s, 0, "Host") ? srv_req_header(s, 0, "Host") : "-",
           srv_req_header(s, 1, "Host") ? srv_req_header(s, 1, "Host") : "-");
    EXPECT_EQ(srv_req_header_occurrences(s, 1, "Host"), 1);
    char lh[64]; snprintf(lh, sizeof lh, "localhost:%u", srv_port(s));
    EXPECT_STR(srv_req_header(s, 1, "Host"), lh);
    srv_stop(s);
}

/* ------------------------------------------------------------------ HttpQueryInfo on the final response */
TEST(rs_query_final_response_forms) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\nX-Hop: 1\r\n", "");
    rs_add(&rt, "/dst", 202, "X-Dst: 2\r\n", "acc");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 202);
    if (hr) {
        char raw[1024]; DWORD l = sizeof raw;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS, raw, &l, NULL));
        EXPECT_STR(raw, "HTTP/1.1 202 Accepted");                /* NUL-separated: first entry is the status line */
        char v[64]; l = sizeof v; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, strcpy(v, "X-Hop"), &l, NULL), ERROR_HTTP_HEADER_NOT_FOUND);
        l = sizeof v; strcpy(v, "X-Dst");
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM, v, &l, NULL)); EXPECT_STR(v, "2");
        ULONGLONG n64 = 0; l = sizeof n64;
        BOOL ok64 = U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER64, &n64, &l, NULL);
        t_note("STATUS_CODE|NUMBER64: ok=%d err=%lu val=%llu len=%lu", ok64, ok64 ? 0 : GetLastError(), n64, l);
        CHECK(ok64); EXPECT_EQ(n64, 202); EXPECT_EQ(l, 8);
        l = sizeof v;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_VERSION, v, &l, NULL)); EXPECT_STR(v, "HTTP/1.1"); EXPECT_EQ(l, 8);
        l = sizeof v;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_TEXT, v, &l, NULL)); EXPECT_STR(v, "Accepted"); EXPECT_EQ(l, 8);
    }
    t_inet_close(hi); srv_stop(s);
}

TEST(rs_query_status_before_send) {
    REQUIRE(U(HttpQueryInfoA));
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, RS_FRESH, 0);
    DWORD v = 0, l = sizeof v; SET_ERR(0);
    BOOL ok = U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL); DWORD e = GetLastError();
    t_note("STATUS_CODE before send: ok=%d err=%lu(%s)", ok, e, rs_err(e));
    CHECK(!ok); EXPECT_EQ(e, ERROR_HTTP_HEADER_NOT_FOUND);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ async mode */
static struct { HANDLE ev; volatile LONG done; INTERNET_ASYNC_RESULT res; int redirects; char url[300]; } g_as;
static void CALLBACK as_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (ctx != 2) return;
    if (st == INTERNET_STATUS_REDIRECT) { g_as.redirects++; if (info) lstrcpynA(g_as.url, (const char *)info, sizeof g_as.url); }
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && info) { g_as.res = *(INTERNET_ASYNC_RESULT *)info; InterlockedExchange(&g_as.done, 1); SetEvent(g_as.ev); }
}
/* returns 1 when the send completed (sync or async) with ok and err filled, 0 on a wait timeout */
static int as_send(HINTERNET hr, const void *data, DWORD n, BOOL *ok, DWORD *err, int *pending) {
    ResetEvent(g_as.ev); g_as.done = 0; *pending = 0;
    SetLastError(0xdeadbeef);
    *ok = U(HttpSendRequestA)(hr, NULL, 0, (LPVOID)data, n);
    *err = *ok ? 0 : GetLastError();
    if (*ok || *err != ERROR_IO_PENDING) return 1;
    *pending = 1;
    if (WaitForSingleObject(g_as.ev, 8000) != WAIT_OBJECT_0) return 0;
    *ok = (BOOL)g_as.res.dwResult; *err = *ok ? 0 : g_as.res.dwError;
    return 1;
}
static void async_redirect(int code, const char *method, int loop, DWORD want_err, DWORD want_status) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    if (loop) rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    else { rs_add(&rt, "/src", code, "Location: /dst\r\n", "m"); rs_add(&rt, "/dst", 200, NULL, "landed"); }
    srv *s; RS_START(&rt, SRV_HTTP, s);
    if (!g_as.ev) g_as.ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_as.redirects = 0; g_as.url[0] = 0;
    HINTERNET hi = t_inet_open_ex("rs-async/1.0", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    if (!hi) { srv_stop(s); t_skip("async session failed"); return; }
    U(InternetSetStatusCallbackA)(hi, as_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    HINTERNET hr = U(HttpOpenRequestA)(hc, method, loop ? "/loop/0" : "/src", NULL, NULL, NULL, RS_FRESH, 2);
    BOOL ok; DWORD err; int pending;
    static const char d[] = "async";
    int done = as_send(hr, strcmp(method, "GET") ? d : NULL, strcmp(method, "GET") ? 5 : 0, &ok, &err, &pending);
    Sleep(50);
    t_note("async %d %s loop=%d: done=%d pending=%d ok=%d err=%lu(%s) reqs=%d redirects=%d", code, method, loop, done, pending, ok, err,
           rs_err(err), srv_req_count(s), g_as.redirects);
    CHECK(done);
    if (done) {
        EXPECT_EQ(err, want_err);
        CHECK(want_err ? !ok : ok);
        if (want_status) EXPECT_EQ(rs_status(hr), want_status);
        if (!loop && !want_err) { EXPECT_EQ(g_as.redirects, 1); EXPECT_STR(g_as.url, srv_url(s, "/dst")); }
        if (loop) EXPECT_EQ(g_as.redirects, srv_req_count(s) - 1);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc);
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi);
    Sleep(50);
    srv_stop(s);
}
TEST(rs_async_302_get)            { async_redirect(302, "GET", 0, 0, 200); }
TEST(rs_async_303_post)           { async_redirect(303, "POST", 0, 0, 200); }
TEST(rs_async_307_post_confirm)   { async_redirect(307, "POST", 0, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION, 307); }
TEST(rs_async_loop_budget)        { async_redirect(302, "GET", 1, ERROR_HTTP_REDIRECT_FAILED, 302); }

/* ------------------------------------------------------------------ option numbers that are WinHTTP-only */
static void option_probe(DWORD opt, const char *name) {
    REQUIRE(U(InternetQueryOptionA));
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, RS_FRESH, 0);
    HINTERNET hs[3] = { hi, hc, hr }; static const char *hn[3] = { "session", "connect", "request" };
    for (int k = 0; k < 3; k++) {
        DWORD v = 0, l = sizeof v; SET_ERR(0);
        BOOL okq = U(InternetQueryOptionA)(hs[k], opt, &v, &l); DWORD eq = GetLastError();
        DWORD w = 5; SET_ERR(0);
        BOOL oks = U(InternetSetOptionA)(hs[k], opt, &w, sizeof w); DWORD es = GetLastError();
        t_note("option %lu (%s) on %s: query ok=%d err=%lu val=%lu len=%lu; set(5) ok=%d err=%lu", opt, name, hn[k], okq, okq ? 0 : eq, v, l,
               oks, oks ? 0 : es);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(rs_option_probe_89_winhttp_max_redirects) { option_probe(89, "WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS"); }
TEST(rs_option_probe_88_winhttp_redirect_policy) { option_probe(88, "WINHTTP_OPTION_REDIRECT_POLICY"); }
