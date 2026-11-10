/* rs_cbcookie.c - status callbacks during redirects, cookies set on 3xx, request-header view after a hop,
 * keep-alive, and 304 revalidation through the URL cache.
 * VM_TIMEOUT: 240
 * Decomp: Redirect@0x12618 -> InternetIndicateStatusString(0x6e = INTERNET_STATUS_REDIRECT, new URL);
 *         HttpSendRequest_Start@0x72da0 -> ExtractSetCookieHeaders before the redirect switch (skipped with NO_COOKIES 0x80000),
 *         GetFromCachePostNetIO for 304. */
#include "rs.h"

/* ------------------------------------------------------------------ INTERNET_STATUS_REDIRECT */
static void cb_redirect(int wide) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetSetStatusCallbackW));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = wide ? 2 : 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    rs_cb_dump();
    CHECK(r.ok);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 1);
    int i = rs_cb_index(INTERNET_STATUS_REDIRECT, 0);
    if (i >= 0) {
        t_note("REDIRECT info='%s' len=%lu ctx=%llu", g_rs_cb.str[i], g_rs_cb.len[i], (unsigned long long)g_rs_cb.ctx[i]);
        EXPECT_STR(g_rs_cb.str[i], srv_url(s, "/dst"));
        /* [W10, async_callbacks] narrow: length counts the NUL; W callback: UTF-16, length in characters without NUL */
        EXPECT_EQ(g_rs_cb.len[i], (DWORD)strlen(srv_url(s, "/dst")) + (wide ? 0 : 1));
        EXPECT_EQ(g_rs_cb.ctx[i], 2);   /* the request handle's context */
        /* ordering: after the first response, before the second request is sent */
        int resp0 = rs_cb_index(INTERNET_STATUS_RESPONSE_RECEIVED, 0);
        int send1 = rs_cb_index(INTERNET_STATUS_SENDING_REQUEST, 1);
        CHECKF(resp0 >= 0 && resp0 < i, "resp0=%d redirect=%d", resp0, i);
        CHECKF(send1 > i, "send1=%d redirect=%d", send1, i);
    }
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_SENDING_REQUEST), 2);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REQUEST_SENT), 2);
    srv_stop(s);
}
TEST(rs_cb_redirect_ansi) { cb_redirect(0); }
TEST(rs_cb_redirect_wide) { cb_redirect(1); }

TEST(rs_cb_redirect_chain_urls) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/3", 200, NULL, "end");
    rs_add(&rt, "/loop/*", 301, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 3);
    for (int k = 0; k < 3; k++) {
        int i = rs_cb_index(INTERNET_STATUS_REDIRECT, k);
        char p[32]; snprintf(p, sizeof p, "/loop/%d", k + 1);
        if (i >= 0) EXPECT_STR(g_rs_cb.str[i], srv_url(s, p));
    }
    srv_stop(s);
}

TEST(rs_cb_redirect_absolute_other_port) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router r2; rs_router_init(&r2); rs_add(&r2, "/far", 200, NULL, "far");
    srv *s2; RS_START(&r2, SRV_HTTP, s2);
    rs_router rt; rs_router_init(&rt); rt.alt_port = srv_port(s2);
    rs_add(&rt, "/src", 307, "Location: http://localhost:%A/far?q=1\r\n", "");
    srv *s = rs_start(&rt, SRV_HTTP);
    if (!s) { srv_stop(s2); t_skip("server unavailable"); return; }
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    rs_cb_dump();
    CHECK(r.ok); EXPECT_STR(r.body, "far");
    int i = rs_cb_index(INTERNET_STATUS_REDIRECT, 0);
    CHECK(i >= 0);
    if (i >= 0) EXPECT_STR(g_rs_cb.str[i], srv_url_host(s2, "localhost", "/far?q=1"));
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_CONNECTED_TO_SERVER), 2);
    for (int k = 0; k < g_rs_cb.n; k++)
        if (g_rs_cb.st[k] == INTERNET_STATUS_RESOLVING_NAME || g_rs_cb.st[k] == INTERNET_STATUS_NAME_RESOLVED || g_rs_cb.st[k] == INTERNET_STATUS_CONNECTED_TO_SERVER)
            t_note("cb %lu '%s'", g_rs_cb.st[k], g_rs_cb.str[k]);
    srv_stop(s); srv_stop(s2);
}

TEST(rs_cb_redirect_fragment_in_string) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst#frag\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    int i = rs_cb_index(INTERNET_STATUS_REDIRECT, 0);
    CHECK(r.ok); CHECK(i >= 0);
    if (i >= 0) t_note("REDIRECT with fragment: '%s'", g_rs_cb.str[i]);
    EXPECT_STR(srv_req_target(s, 1), "/dst");
    srv_stop(s);
}

TEST(rs_cb_no_redirect_when_noauto) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_NOREDIR; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 302);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 0);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_SENDING_REQUEST), 1);
    srv_stop(s);
}

TEST(rs_cb_no_redirect_for_refused_scheme) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: ftp://127.0.0.1:%P/f\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    t_note("ftp Location: ok=%d err=%lu redirect_cbs=%d", r.ok, r.err, rs_cb_count(INTERNET_STATUS_REDIRECT));
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 0);
    srv_stop(s);
}

/* 307 POST: Redirect() runs (URL moves, REDIRECT is indicated) before the 12168 is returned */
TEST(rs_cb_redirect_before_confirmation) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 307, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char d[] = "abc";
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; o.data = d; o.ndata = 3; rs_res r;
    rs_do(s, "POST", "/src", &o, &r);
    rs_cb_dump();
    CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 1);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_SENDING_REQUEST), 1);
    srv_stop(s);
}

TEST(rs_cb_loop_redirect_count) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/*", 302, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/loop/0", &o, &r);
    Sleep(50);
    int n = srv_req_count(s);
    t_note("loop: requests=%d REDIRECT callbacks=%d SENDING=%d", n, rs_cb_count(INTERNET_STATUS_REDIRECT), rs_cb_count(INTERNET_STATUS_SENDING_REQUEST));
    EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_FAILED);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), n - 1);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_SENDING_REQUEST), n);
    srv_stop(s);
}

/* callbacks only fire for a nonzero context: request context 0 -> no REDIRECT callback */
TEST(rs_cb_zero_context_silent) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    rs_cb_install(hi, 0);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(rs_status(hr), 200);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 0);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc);
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ request-header view after a hop */
TEST(rs_reqhdr_view_after_redirect) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: http://localhost:%P/dst?z=1\r\n", "");
    rs_add(&rt, "/dst?z=1", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char d[] = "k=v";
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.data = d; o.ndata = 3; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "POST", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200);
    if (hr) {
        char v[512]; DWORD l = sizeof v;
        char lh[64]; snprintf(lh, sizeof lh, "localhost:%u", srv_port(s));
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_HOST | HTTP_QUERY_FLAG_REQUEST_HEADERS, v, &l, NULL)); EXPECT_STR(v, lh);
        l = sizeof v;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_REQUEST_METHOD, v, &l, NULL)); EXPECT_STR(v, "GET");
        l = sizeof v;
        CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, v, &l, NULL));
        t_note("request headers after hop: %s", v);
        CHECK(!strncmp(v, "GET /dst?z=1 HTTP/1.1\r\n", 23));
        l = sizeof v; SET_ERR(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_REQUEST_HEADERS, v, &l, NULL), ERROR_HTTP_HEADER_NOT_FOUND);
        l = sizeof v;
        CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, v, &l));
        EXPECT_STR(v, srv_url_host(s, "localhost", "/dst?z=1"));
        WCHAR w[512]; l = sizeof w;
        CHECK(U(InternetQueryOptionW)(hr, INTERNET_OPTION_URL, w, &l));
        char wa[512]; WideCharToMultiByte(CP_ACP, 0, w, -1, wa, sizeof wa, NULL, NULL);
        EXPECT_STR(wa, srv_url_host(s, "localhost", "/dst?z=1"));
    }
    t_inet_close(hi); srv_stop(s);
}

/* INTERNET_OPTION_URL before the send is the original URL */
TEST(rs_option_url_before_send) {
    REQUIRE(U(InternetQueryOptionA));
    srv *s = rs_plain(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/before?x=1", NULL, NULL, NULL, RS_FRESH, 0);
    char v[256]; DWORD l = sizeof v;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, v, &l));
    EXPECT_STR(v, srv_url(s, "/before?x=1"));
    EXPECT_EQ(l, (DWORD)strlen(v));
    l = 4; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, v, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, (DWORD)strlen(srv_url(s, "/before?x=1")) + 1);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ cookies set by the 3xx */
typedef struct { char path[96]; char src[128]; char dst[128]; char hdr[256]; char url[256]; } ckpaths;
static void ck_paths(ckpaths *c, const char *tag, const char *cookie_attr) {
    snprintf(c->path, sizeof c->path, "/%s", t_uniq(tag));
    snprintf(c->src, sizeof c->src, "%s/src", c->path);
    snprintf(c->dst, sizeof c->dst, "%s/dst", c->path);
    snprintf(c->hdr, sizeof c->hdr, "Set-Cookie: rsck=v1; %s\r\nLocation: %s\r\n", cookie_attr, c->dst);
    snprintf(c->url, sizeof c->url, "http://127.0.0.1%s/", c->path);
}

TEST(rs_cookie_from_302_sent_on_hop) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetGetCookieA));
    ckpaths c; char attr[160];
    snprintf(attr, sizeof attr, "Path=%s", "/"); /* replaced below */
    ck_paths(&c, "ck302", "");
    snprintf(attr, sizeof attr, "Path=%s", c.path);
    snprintf(c.hdr, sizeof c.hdr, "Set-Cookie: rsck=v1; %s\r\nLocation: %s\r\n", attr, c.dst);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, c.src, 302, c.hdr, "");
    rs_add(&rt, c.dst, 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(c.url, "rsck");
    rs_opt o = { 0 }; o.flags = RS_FRESH_COOKIES; o.cb = 1; rs_res r;
    rs_do(s, "GET", c.src, &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    CHECK(srv_req_header(s, 0, "Cookie") == NULL);
    EXPECT_STR(srv_req_header(s, 1, "Cookie"), "rsck=v1");
    char jar[256]; DWORD l = sizeof jar;
    CHECK(U(InternetGetCookieA)(c.url, NULL, jar, &l));
    EXPECT_STR(jar, "rsck=v1");
    t_note("cookie callbacks: received=%d sent=%d", rs_cb_count(INTERNET_STATUS_COOKIE_RECEIVED), rs_cb_count(INTERNET_STATUS_COOKIE_SENT));
    t_net_cleanup();
    srv_stop(s);
}

TEST(rs_cookie_from_302_no_cookies_flag) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetGetCookieA));
    ckpaths c; ck_paths(&c, "cknc", "");
    snprintf(c.hdr, sizeof c.hdr, "Set-Cookie: rsck=v2; Path=%s\r\nLocation: %s\r\n", c.path, c.dst);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, c.src, 302, c.hdr, "");
    rs_add(&rt, c.dst, 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(c.url, "rsck");
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;   /* RS_FRESH has NO_COOKIES */
    rs_do(s, "GET", c.src, &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    CHECK(srv_req_header(s, 1, "Cookie") == NULL);
    char jar[256]; DWORD l = sizeof jar; SET_ERR(0);
    EXPECT_FAIL(!U(InternetGetCookieA)(c.url, NULL, jar, &l), ERROR_NO_MORE_ITEMS);
    t_net_cleanup();
    srv_stop(s);
}

TEST(rs_cookie_from_302_other_path_not_sent) {
    REQUIRE(U(HttpSendRequestA));
    ckpaths c; ck_paths(&c, "ckop", "");
    char other[160]; snprintf(other, sizeof other, "%s/elsewhere", c.path);
    snprintf(c.hdr, sizeof c.hdr, "Set-Cookie: rsck=v3; Path=%s\r\nLocation: %s\r\n", other, c.dst);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, c.src, 302, c.hdr, "");
    rs_add(&rt, c.dst, 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    char ckurl[256]; snprintf(ckurl, sizeof ckurl, "http://127.0.0.1%s/", other);
    t_cookie_track(ckurl, "rsck");
    rs_opt o = { 0 }; o.flags = RS_FRESH_COOKIES; rs_res r;
    rs_do(s, "GET", c.src, &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    CHECK(srv_req_header(s, 1, "Cookie") == NULL);
    t_net_cleanup();
    srv_stop(s);
}

TEST(rs_cookie_two_from_chain) {
    REQUIRE(U(HttpSendRequestA));
    char base[96]; snprintf(base, sizeof base, "/%s", t_uniq("ckch"));
    char a[128], b[128], d[128], ha[300], hb[300], ckurl[200];
    snprintf(a, sizeof a, "%s/a", base); snprintf(b, sizeof b, "%s/b", base); snprintf(d, sizeof d, "%s/d", base);
    snprintf(ha, sizeof ha, "Set-Cookie: rsa=1; Path=%s\r\nLocation: %s\r\n", base, b);
    snprintf(hb, sizeof hb, "Set-Cookie: rsb=2; Path=%s\r\nLocation: %s\r\n", base, d);
    snprintf(ckurl, sizeof ckurl, "http://127.0.0.1%s/", base);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, a, 301, ha, ""); rs_add(&rt, b, 303, hb, ""); rs_add(&rt, d, 200, NULL, "done");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(ckurl, "rsa"); t_cookie_track(ckurl, "rsb");
    rs_opt o = { 0 }; o.flags = RS_FRESH_COOKIES; rs_res r;
    rs_do(s, "GET", a, &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 3, 2000), 3);
    EXPECT_STR(srv_req_header(s, 1, "Cookie"), "rsa=1");
    const char *c2 = srv_req_header(s, 2, "Cookie");
    t_note("third request Cookie: %s", c2 ? c2 : "(none)");
    CHECK(c2 && strstr(c2, "rsa=1") && strstr(c2, "rsb=2"));
    t_net_cleanup();
    srv_stop(s);
}

/* ------------------------------------------------------------------ INTERNET_FLAG_KEEP_CONNECTION */
TEST(rs_keep_connection_across_redirect) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "x");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    rs_add(&rt, "/again", 200, NULL, "again");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h1 = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_FRESH | INTERNET_FLAG_KEEP_CONNECTION, 0);
    CHECK(U(HttpSendRequestA)(h1, NULL, 0, NULL, 0)); EXPECT_EQ(rs_status(h1), 200);
    char b[32]; t_inet_read_all(h1, b, sizeof b, NULL); U(InternetCloseHandle)(h1);
    HINTERNET h2 = U(HttpOpenRequestA)(hc, "GET", "/again", NULL, NULL, NULL, RS_FRESH | INTERNET_FLAG_KEEP_CONNECTION, 0);
    CHECK(U(HttpSendRequestA)(h2, NULL, 0, NULL, 0)); EXPECT_EQ(rs_status(h2), 200);
    t_inet_read_all(h2, b, sizeof b, NULL); U(InternetCloseHandle)(h2);
    EXPECT_EQ(rs_wait(s, 3, 2000), 3);
    EXPECT_EQ(srv_conn_count(s), 1);
    EXPECT_EQ(srv_req_conn(s, 2), srv_req_conn(s, 0));
    for (int i = 0; i < 3; i++) t_note("req%d Connection: %s", i, srv_req_header(s, i, "Connection") ? srv_req_header(s, i, "Connection") : "(none)");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

TEST(rs_keep_connection_flag_visible) {
    REQUIRE(U(InternetQueryOptionA));
    srv *s = rs_plain(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, RS_FRESH | INTERNET_FLAG_KEEP_CONNECTION, 0);
    DWORD f = 0, l = sizeof f;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &f, &l));
    t_note("flags with KEEP_CONNECTION: 0x%lx", f);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(rs_status(hr), 200);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ 304 Not Modified through the URL cache */
#define CACHE_FLAGS (INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES)

static int cached_get(srv *s, const char *path, DWORD flags, char *body, size_t cap, DWORD *status) {
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, flags, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    *status = ok ? rs_status(hr) : 0;
    int rok; t_inet_read_all(hr, body, cap, &rok);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
    return ok ? 0 : (int)e;
}

TEST(rs_cache_304_revalidation) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(DeleteUrlCacheEntryA));
    char path[128]; snprintf(path, sizeof path, "/%s.txt", t_uniq("c304"));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, path, 200, "Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT\r\nETag: \"rs-v1\"\r\nCache-Control: max-age=0\r\nContent-Type: text/plain\r\n",
            "cached-v1", RS_F_COND304);
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cache_track(srv_url(s, path));
    char body[64]; DWORD st;
    EXPECT_EQ(cached_get(s, path, CACHE_FLAGS, body, sizeof body, &st), 0);
    EXPECT_EQ(st, 200); EXPECT_STR(body, "cached-v1");
    int e = cached_get(s, path, CACHE_FLAGS | INTERNET_FLAG_RESYNCHRONIZE, body, sizeof body, &st);
    int n = rs_wait(s, 2, 2000);
    t_note("revalidation: err=%d status=%lu body=%s requests=%d INM=%s IMS=%s", e, st, body, n,
           srv_req_header(s, 1, "If-None-Match") ? srv_req_header(s, 1, "If-None-Match") : "-",
           srv_req_header(s, 1, "If-Modified-Since") ? srv_req_header(s, 1, "If-Modified-Since") : "-");
    EXPECT_EQ(e, 0);
    EXPECT_EQ(n, 2);
    EXPECT_STR(body, "cached-v1");             /* body comes from the cache entry */
    EXPECT_STR(srv_req_header(s, 1, "If-None-Match"), "\"rs-v1\"");
    EXPECT_STR(srv_req_header(s, 1, "If-Modified-Since"), "Wed, 21 Oct 2015 07:28:00 GMT");
    EXPECT_EQ(st, 200);
    t_net_cleanup();
    srv_stop(s);
}

TEST(rs_cache_304_status_query_detail) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(DeleteUrlCacheEntryA));
    char path[128]; snprintf(path, sizeof path, "/%s.txt", t_uniq("c304q"));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, path, 200, "ETag: \"rs-q\"\r\nCache-Control: no-cache\r\nX-Origin: first\r\n", "body-q", RS_F_COND304);
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cache_track(srv_url(s, path));
    char body[64]; DWORD st;
    cached_get(s, path, CACHE_FLAGS, body, sizeof body, &st);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, CACHE_FLAGS | INTERNET_FLAG_RESYNCHRONIZE, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    rs_res r; memset(&r, 0, sizeof r); rs_collect(hr, &r, 1);
    t_note("304-revalidated view: status=%lu text=%s raw0=%.40s body=%s", r.status, r.text, r.raw, r.body);
    EXPECT_STR(r.body, "body-q");
    DWORD fl = 0, l = sizeof fl;
    if (U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &fl, &l)) t_note("INTERNET_OPTION_REQUEST_FLAGS = 0x%lx (FROM_CACHE=0x1)", fl);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    t_net_cleanup();
    srv_stop(s);
}

/* a 304 while the cache entry is missing (RELOAD + own If-None-Match): passed to the caller as data */
TEST(rs_cache_304_without_entry_is_data) {
    REQUIRE(U(HttpSendRequestA));
    char path[128]; snprintf(path, sizeof path, "/%s.txt", t_uniq("c304n"));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, path, 200, "ETag: \"rs-n\"\r\n", "never", RS_F_COND304);
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.hdrs = "If-None-Match: \"rs-n\"\r\n"; rs_res r;
    rs_do(s, "GET", path, &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 304); EXPECT_EQ(r.nbody, 0);
    EXPECT_STR(r.text, "Not Modified");
    srv_stop(s);
}

/* a cacheable 301: record whether the second request for the source is answered from the cache */
TEST(rs_cache_redirect_301_note) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(DeleteUrlCacheEntryA));
    char src[128], dst[128], hdr[256];
    snprintf(src, sizeof src, "/%s.src", t_uniq("c301"));
    snprintf(dst, sizeof dst, "%s.dst", src);
    snprintf(hdr, sizeof hdr, "Location: %s\r\nCache-Control: max-age=3600\r\n", dst);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, src, 301, hdr, "");
    rs_add(&rt, dst, 200, "Cache-Control: max-age=3600\r\n", "cached-target");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cache_track(srv_url(s, src)); t_cache_track(srv_url(s, dst));
    char body[64]; DWORD st;
    EXPECT_EQ(cached_get(s, src, CACHE_FLAGS, body, sizeof body, &st), 0);
    EXPECT_EQ(st, 200); EXPECT_STR(body, "cached-target");
    int n1 = rs_wait(s, 2, 2000);
    EXPECT_EQ(n1, 2);
    EXPECT_EQ(cached_get(s, src, CACHE_FLAGS, body, sizeof body, &st), 0);
    Sleep(100);
    int n2 = srv_req_count(s);
    t_note("cached 301: second fetch status=%lu body=%s new server requests=%d", st, body, n2 - n1);
    EXPECT_STR(body, "cached-target");
    t_net_cleanup();
    srv_stop(s);
}
