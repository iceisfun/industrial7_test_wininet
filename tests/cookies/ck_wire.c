/* ck_wire.c - cookies on the wire against the in-process loopback server: Set-Cookie responses stored in the jar,
 * the Cookie request header WinINet builds from the jar (recorded by the server), INTERNET_FLAG_NO_COOKIES,
 * HttpOnly / Secure / path / domain rules for network cookies, redirects, Set-Cookie2, HTTP_QUERY_SET_COOKIE,
 * the COOKIE_SENT / COOKIE_RECEIVED status callbacks and HTTPS.
 * Cookies on 127.0.0.1 are not port-scoped, so every test uses its own path (ck_upath).
 * Decomp: HTTP_REQUEST_HANDLE_OBJECT::CreateCookieHeaderIfNeeded@0x68f50, ::ExtractSetCookieHeaders@0x2f058
 * (HTTP_QUERY_SET_COOKIE 0x2b only; SetCookieParsed with param_11 = 1, i.e. HttpOnly allowed), HttpSendRequest_Start
 * (0x4f4 & 0x80000 NO_COOKIES). VM_TIMEOUT: 150 */
#include "ck.h"

/* connection 0: first request gets set_hdrs (status code), every later request on it a plain 200;
 * connections 1+: always a plain 200 */
typedef struct { srv *s; srv_step s0[5]; srv_step s1[3]; srv_script sc[2]; char path[300]; char api_url[400]; } wsrv;
static int wsrv_start_kind(wsrv *w, const char *set_hdrs, int code, srv_kind kind) {
    srv_step a[5] = { S_HEAD(), S_REPLY(200, NULL, "ok"), S_HEAD(), S_REPLY(200, NULL, "ok"), S_LOOP_TO(2) };
    srv_step b[3] = { S_HEAD(), S_REPLY(200, NULL, "ok"), S_LOOP() };
    a[1].hdrs = set_hdrs; a[1].arg = code;
    if (kind == SRV_HTTPS) { b[1].hdrs = set_hdrs; b[1].arg = code; } /* an aborted first TLS handshake burns connection 0 */
    memcpy(w->s0, a, sizeof a); memcpy(w->s1, b, sizeof b);
    w->sc[0].steps = w->s0; w->sc[0].nsteps = 5; w->sc[1].steps = w->s1; w->sc[1].nsteps = 3;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = kind; cfg.scripts = w->sc; cfg.nscripts = 2; cfg.cert_profile = SRV_CERT_LOCALHOST;
    snprintf(w->path, sizeof w->path, "%s/", ck_upath("w"));
    snprintf(w->api_url, sizeof w->api_url, "%s://127.0.0.1%s", kind == SRV_HTTPS ? "https" : "http", w->path);
    w->s = NULL;
    return srv_start(&cfg, &w->s);
}
static int wsrv_start(wsrv *w, const char *set_hdrs) { return wsrv_start_kind(w, set_hdrs, 200, SRV_HTTP); }
#define WSRV_OR_SKIP(w, hdrs) do { int rc_ = wsrv_start((w), (hdrs)); if (rc_) { t_skip("server unavailable: %s", srv_strerror(rc_)); return; } } while (0)
/* url of the test path (+ suffix) on the server */
static const char *wurl(wsrv *w, const char *suffix) { char p[600]; snprintf(p, sizeof p, "%s%s", w->path, suffix ? suffix : ""); return srv_url(w->s, p); }
static const char *wapi(wsrv *w, const char *suffix) { static char b[4][600]; static int i; char *r = b[i++ & 3]; snprintf(r, 600, "%s%s", w->api_url, suffix ? suffix : ""); return r; }
static const char *cookie_hdr(srv *s, int i) { return srv_req_header(s, i, "Cookie"); }

/* ------------------------------------------------------------------------------------------ receive */
TEST(ck_wire_set_cookie_stored) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: w1=v1; path=%R\r\n");
    ck_track(w.api_url, "w1", NULL, 0); ck_track(w.api_url, "w1", "path=/", 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "w1=v1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_cookie_roundtrip) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: rt=1; path=%R\r\n");
    ck_track(w.api_url, "rt", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, "next"), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), NULL);
    EXPECT_STR(cookie_hdr(w.s, 1), "rt=1");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 1, "Cookie"), 1);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_multiple_set_cookie_headers) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: m1=a; path=%R\r\nSet-Cookie: m2=b; path=%R\r\nSet-Cookie: m3=c; path=%R\r\n");
    ck_track(w.api_url, "m1", NULL, 0); ck_track(w.api_url, "m2", NULL, 0); ck_track(w.api_url, "m3", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "m1=a; m2=b; m3=c");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 1), "m1=a; m2=b; m3=c");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_set_cookie_same_name_last_wins) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: dup=first; path=%R\r\nSet-Cookie: dup=second; path=%R\r\n");
    ck_track(w.api_url, "dup", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "dup=second");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_set_cookie_comma_not_split) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: c1=1, c2=2; path=%R\r\n");
    ck_track(w.api_url, "c1", NULL, 0); ck_track(w.api_url, "c2", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    const char *g = ck_gets(w.api_url, NULL, 0);
    EXPECT_STR(g, "c1=1, c2=2");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_set_cookie2_ignored) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie2: v2=1; Version=1; Path=%R\r\n");
    ck_track(w.api_url, "v2", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 1), NULL);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_set_cookie_header_case) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "set-cookie: lc=1; path=%R\r\nSET-COOKIE: uc=1; path=%R\r\n");
    ck_track(w.api_url, "lc", NULL, 0); ck_track(w.api_url, "uc", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "lc=1; uc=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_httponly_stored_and_sent) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: hw=1; path=%R; HttpOnly\r\n");
    ck_track(w.api_url, "hw", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "");                          /* invisible to plain script-style get */
    EXPECT_STR(ck_gets(w.api_url, NULL, INTERNET_COOKIE_HTTPONLY), "hw=1");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 1), "hw=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_secure_cookie_over_http) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: sw=1; path=%R; secure\r\n");
    ck_track(w.api_url, "sw", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    char su[600]; snprintf(su, sizeof su, "https://127.0.0.1%s", w.path);
    EXPECT_STR(ck_gets(su, NULL, 0), "sw=1");   /* stored from plain http, readable for https */
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 1), NULL);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_default_path) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: dp=1\r\n");
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, "sub/page"), NULL, 0), 200);
    ck_track(wapi(&w, "sub/page"), "dp", NULL, 0);
    const char *a = ck_gets(wapi(&w, "sub/"), NULL, 0), *b = ck_gets(w.api_url, NULL, 0), *c = ck_gets(wapi(&w, "sub/x/"), NULL, 0);
    EXPECT_STR(a, "dp=1");
    EXPECT_STR(b, "");
    EXPECT_STR(c, "dp=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_max_age_zero_deletes) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: del=x; path=%R; Max-Age=0\r\n");
    ck_set(w.api_url, NULL, "del=1");
    char d[600]; snprintf(d, sizeof d, "del=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "del=1");
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "del=1");
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_expires_past_deletes) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: dx=x; path=%R; expires=Thu, 01 Jan 1970 00:00:01 GMT\r\n");
    char d[600]; snprintf(d, sizeof d, "dx=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_path_mismatch_not_sent) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "other=1; path=%sother/", w.path);
    ck_set(w.api_url, NULL, d);
    snprintf(d, sizeof d, "here=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, "page"), NULL, 0), 200);
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, "other/page"), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "here=1");
    EXPECT_STR(cookie_hdr(w.s, 1), "other=1; here=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_bad_path_attr_rejected) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: bp=1; path=noslash\r\nSet-Cookie: ok=1; path=%R\r\n");
    ck_track(w.api_url, "ok", NULL, 0); ck_track(w.api_url, "bp", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "ok=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_domain_attr_rules) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: good=1; path=%R; domain=127.0.0.1\r\nSet-Cookie: bad=1; path=%R; domain=i7test.example\r\n");
    ck_track(w.api_url, "good", NULL, 0); ck_track(w.api_url, "good", "domain=127.0.0.1", 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "good=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_localhost_and_ip_separate) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "iponly=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    char lu[700]; snprintf(lu, sizeof lu, "%s", srv_url_host(w.s, "localhost", w.path));
    EXPECT_EQ(ck_wire_get(hi, lu, NULL, 0), 200);
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(cookie_hdr(w.s, 0), NULL);
    EXPECT_STR(cookie_hdr(w.s, 1), "iponly=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ send */
TEST(ck_wire_api_cookie_sent) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "api=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "api=1");
    EXPECT_STR(srv_req_header_name(w.s, 0, srv_req_header_index(w.s, 0, "cookie")), "Cookie");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_no_cookie_header_when_empty) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_EQ(srv_req_header_index(w.s, 0, "Cookie"), -1);
    t_inet_close(hi); srv_stop(w.s);
}
TEST(ck_wire_order_longer_path_first) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600];
    snprintf(d, sizeof d, "short=1; path=%s", w.path); ck_set(w.api_url, NULL, d);
    snprintf(d, sizeof d, "long=1; path=%sa/b/", w.path); ck_set(w.api_url, NULL, d);
    snprintf(d, sizeof d, "mid=1; path=%sa/", w.path); ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, "a/b/c"), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "long=1; mid=1; short=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_api_httponly_cookie_sent) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "aho=1; path=%s; HttpOnly", w.path);
    EXPECT_EQ(ck_setx(w.api_url, NULL, d, INTERNET_COOKIE_HTTPONLY, NULL), COOKIE_STATE_ACCEPT);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "aho=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_samesite_cookies_sent_direct) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600];
    snprintf(d, sizeof d, "st=1; path=%s; SameSite=Strict", w.path); ck_set(w.api_url, NULL, d);
    snprintf(d, sizeof d, "lx=1; path=%s; SameSite=Lax", w.path); ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    const char *c = cookie_hdr(w.s, 0);
    EXPECT_STR(c, "st=1; lx=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_nameless_cookie_sent_as_value) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "barevalue; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    snprintf(d, sizeof d, "named=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "barevalue; named=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_user_cookie_header_and_jar) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "jar=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), "Cookie: user=1\r\n", 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    int occ = srv_req_header_occurrences(w.s, 0, "Cookie");
    const char *c = cookie_hdr(w.s, 0);
    t_note("user Cookie header + jar: occurrences=%d first='%s'", occ, c ? c : "(none)");
    EXPECT_EQ(occ, 1);
    EXPECT_STR(c, "jar=1");              /* VM: the jar's Cookie header replaces the caller's */
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_large_cookie_roundtrip) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char *d = malloc(5000); int n = snprintf(d, 5000, "big=");
    memset(d + n, 'q', 4000); d[n + 4000] = 0;
    char *full = malloc(5200); snprintf(full, 5200, "%s; path=%s", d, w.path);
    EXPECT_EQ(ck_set(w.api_url, NULL, full), TRUE);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    const char *c = cookie_hdr(w.s, 0);
    CHECK(c != NULL && !strcmp(c, d));
    t_inet_close(hi); srv_stop(w.s);
    free(d); free(full);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ NO_COOKIES */
TEST(ck_wire_no_cookies_flag_not_stored) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: nc=1; path=%R\r\n");
    ck_track(w.api_url, "nc", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, INTERNET_FLAG_NO_COOKIES), 200);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_no_cookies_flag_not_sent) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "ns=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, INTERNET_FLAG_NO_COOKIES), 200);
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), NULL);
    EXPECT_STR(cookie_hdr(w.s, 1), "ns=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_no_cookies_user_header_kept) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "jar=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), "Cookie: mine=1\r\n", INTERNET_FLAG_NO_COOKIES), 200);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), "mine=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_no_cookies_on_http_open_request) {
    REQUIRE(U(HttpOpenRequestA)); REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetConnectA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: hor=1; path=%R\r\n");
    ck_track(w.api_url, "hor", NULL, 0);
    char d[600]; snprintf(d, sizeof d, "pre=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(w.s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", w.path, NULL, NULL, NULL, CK_WIRE_BASE | INTERNET_FLAG_NO_COOKIES, 0);
    CHECK(hr != NULL);
    EXPECT_EQ(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), TRUE);
    char b[64]; int ok; t_inet_read_all(hr, b, sizeof b, &ok);
    t_inet_close(hr);
    CHECK(srv_wait_requests(w.s, 1, 3000));
    EXPECT_STR(cookie_hdr(w.s, 0), NULL);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "pre=1");      /* hor=1 was not stored */
    hr = U(HttpOpenRequestA)(hc, "GET", w.path, NULL, NULL, NULL, CK_WIRE_BASE, 0);
    EXPECT_EQ(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), TRUE);
    t_inet_read_all(hr, b, sizeof b, &ok);
    t_inet_close(hr);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 1), "pre=1");
    t_inet_close(hc); t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ redirects, sessions */
TEST(ck_wire_set_cookie_on_redirect_stored_and_sent) {
    REQUIRE(U(InternetOpenUrlA));
    char p[300]; snprintf(p, sizeof p, "%s/", ck_upath("rd"));
    char hdr[700]; snprintf(hdr, sizeof hdr, "Set-Cookie: rd=1; path=%s\r\nLocation: %sdst\r\n", p, p);
    srv_step st[] = { S_HEAD(), S_REPLY(302, NULL, ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    st[1].hdrs = hdr;
    srv_step st2[] = { S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP() };
    srv_script sc[] = { { st, 5 }, { st2, 3 } };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 2;
    srv *s; CK_START_OR_SKIP(&cfg, &s);
    char api[400]; snprintf(api, sizeof api, "http://127.0.0.1%s", p);
    ck_track(api, "rd", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    char src[400]; snprintf(src, sizeof src, "%ssrc", p);
    EXPECT_EQ(ck_wire_get(hi, srv_url(s, src), NULL, 0), 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(cookie_hdr(s, 0), NULL);
    char want[400]; snprintf(want, sizeof want, "GET %sdst HTTP/1.1", p);
    EXPECT_STR(srv_req_line(s, 1), want);
    EXPECT_STR(cookie_hdr(s, 1), "rd=1");
    EXPECT_STR(ck_gets(api, NULL, 0), "rd=1");
    t_inet_close(hi); srv_stop(s);
    ck_cleanup();
}
TEST(ck_wire_set_cookie_on_404_stored) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; int rc = wsrv_start_kind(&w, "Set-Cookie: nf=1; path=%R\r\n", 404, SRV_HTTP);
    if (rc) { t_skip("server unavailable: %s", srv_strerror(rc)); return; }
    ck_track(w.api_url, "nf", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    EXPECT_EQ(ck_wire_get(hi, wurl(&w, NULL), NULL, 0), 404);
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "nf=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_jar_shared_between_sessions) {
    REQUIRE(U(InternetOpenUrlA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: shared=1; path=%R\r\n");
    ck_track(w.api_url, "shared", NULL, 0);
    HINTERNET a = t_inet_open("ck-a"), b = t_inet_open("ck-b");
    EXPECT_EQ(ck_wire_get(a, wurl(&w, NULL), NULL, 0), 200);
    t_inet_close(a);
    EXPECT_EQ(ck_wire_get(b, wurl(&w, NULL), NULL, 0), 200);
    CHECK(srv_wait_requests(w.s, 2, 3000));
    EXPECT_STR(cookie_hdr(w.s, 1), "shared=1");
    t_inet_close(b); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_query_set_cookie_header) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(HttpQueryInfoA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: q1=1; path=%R\r\nSet-Cookie: q2=2; path=%R; HttpOnly\r\n");
    ck_track(w.api_url, "q1", NULL, 0); ck_track(w.api_url, "q2", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    HINTERNET h = U(InternetOpenUrlA)(hi, wurl(&w, NULL), NULL, 0, CK_WIRE_BASE, 0);
    CHECK(h != NULL);
    char b[256], want[400]; DWORD sz = sizeof b, idx = 0;
    EXPECT_EQ(U(HttpQueryInfoA)(h, HTTP_QUERY_SET_COOKIE, b, &sz, &idx), TRUE);
    snprintf(want, sizeof want, "q1=1; path=%s", w.path);
    EXPECT_STR(b, want);
    EXPECT_EQ(idx, 1);
    sz = sizeof b;
    EXPECT_EQ(U(HttpQueryInfoA)(h, HTTP_QUERY_SET_COOKIE, b, &sz, &idx), TRUE);
    snprintf(want, sizeof want, "q2=2; path=%s; HttpOnly", w.path);
    EXPECT_STR(b, want);
    sz = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpQueryInfoA)(h, HTTP_QUERY_SET_COOKIE, b, &sz, &idx), FALSE);
    EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    sz = sizeof b;
    EXPECT_EQ(U(HttpQueryInfoA)(h, HTTP_QUERY_RAW_HEADERS_CRLF, b, &sz, NULL), TRUE);
    CHECK(strstr(b, "Set-Cookie: q1=1") != NULL);
    t_inet_close(h);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
TEST(ck_wire_query_request_cookie_header) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(HttpQueryInfoA));
    wsrv w; WSRV_OR_SKIP(&w, NULL);
    char d[600]; snprintf(d, sizeof d, "rq=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    HINTERNET h = U(InternetOpenUrlA)(hi, wurl(&w, NULL), NULL, 0, CK_WIRE_BASE, 0);
    CHECK(h != NULL);
    char b[256]; DWORD sz = sizeof b;
    BOOL r = U(HttpQueryInfoA)(h, HTTP_QUERY_COOKIE | HTTP_QUERY_FLAG_REQUEST_HEADERS, b, &sz, NULL);
    EXPECT_EQ(r, TRUE);
    EXPECT_STR(b, "rq=1");
    t_inet_close(h);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ status callbacks */
static volatile LONG g_cb_sent, g_cb_recv;
static DWORD g_cb_recv_len;
static void CALLBACK ck_status_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    if (status == INTERNET_STATUS_COOKIE_SENT) InterlockedIncrement(&g_cb_sent);
    if (status == INTERNET_STATUS_COOKIE_RECEIVED) { InterlockedIncrement(&g_cb_recv); g_cb_recv_len = len; }
}
TEST(ck_wire_status_callbacks) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetSetStatusCallbackA));
    wsrv w; WSRV_OR_SKIP(&w, "Set-Cookie: cb=1; path=%R\r\n");
    ck_track(w.api_url, "cb", NULL, 0);
    HINTERNET hi = t_inet_open("ck-wire");
    g_cb_sent = g_cb_recv = 0;
    U(InternetSetStatusCallbackA)(hi, ck_status_cb);
    HINTERNET h = U(InternetOpenUrlA)(hi, wurl(&w, NULL), NULL, 0, CK_WIRE_BASE, 0x1234);
    CHECK(h != NULL);
    char b[64]; int ok; t_inet_read_all(h, b, sizeof b, &ok); t_inet_close(h);
    LONG r1 = g_cb_recv, s1 = g_cb_sent;
    h = U(InternetOpenUrlA)(hi, wurl(&w, NULL), NULL, 0, CK_WIRE_BASE, 0x1235);
    CHECK(h != NULL);
    t_inet_read_all(h, b, sizeof b, &ok); t_inet_close(h);
    t_note("callbacks: first request recv=%ld sent=%ld (len %lu); after second recv=%ld sent=%ld", r1, s1, g_cb_recv_len, g_cb_recv, g_cb_sent);
    EXPECT_EQ(g_cb_recv, 1);
    EXPECT_EQ(g_cb_sent, 1);
    EXPECT_EQ(r1, 1);
    EXPECT_EQ(s1, 0);
    CHECK(g_cb_sent >= 1);
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ HTTPS */
static int https_get_f(HINTERNET hi, srv *s, const char *path, DWORD fl) {
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hc) return 0;
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, fl | INTERNET_FLAG_SECURE, 0);
    int code = 0;
    if (hr) {
        t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
        if (U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)) {
            DWORD c = 0, sz = sizeof c;
            if (U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &c, &sz, NULL)) code = (int)c;
            char b[64]; int ok; t_inet_read_all(hr, b, sizeof b, &ok);
        } else t_note("https send failed: %lu %s", GetLastError(), t_inet_errname(GetLastError()));
        t_inet_close(hr);
    }
    t_inet_close(hc);
    return code;
}
static int https_get(HINTERNET hi, srv *s, const char *path) { return https_get_f(hi, s, path, CK_WIRE_BASE); }
TEST(ck_wire_https_secure_cookie_sent) {
    REQUIRE(U(HttpOpenRequestA));
    wsrv w; int rc = wsrv_start_kind(&w, "Set-Cookie: tls=1; path=%R; secure\r\n", 200, SRV_HTTPS);
    if (rc) { t_skip("https server unavailable: %s", srv_strerror(rc)); return; }
    ck_track(w.api_url, "tls", NULL, 0);
    char d[600]; snprintf(d, sizeof d, "plainck=1; path=%s", w.path);
    ck_set(w.api_url, NULL, d);
    HINTERNET hi = t_inet_open("ck-wire");
    int g1 = https_get(hi, w.s, w.path);
    if (g1 != 200) { t_note("first https GET failed (%d); retrying once", g1); g1 = https_get(hi, w.s, w.path); }
    EXPECT_EQ(g1, 200);
    EXPECT_EQ(https_get(hi, w.s, w.path), 200);
    CHECK(srv_wait_requests(w.s, 2, 5000));
    EXPECT_STR(cookie_hdr(w.s, 0), "plainck=1");
    EXPECT_STR(cookie_hdr(w.s, 1), "plainck=1; tls=1");
    EXPECT_STR(ck_gets(w.api_url, NULL, 0), "plainck=1; tls=1");
    char hu[600]; snprintf(hu, sizeof hu, "http://127.0.0.1%s", w.path);
    EXPECT_STR(ck_gets(hu, NULL, 0), "plainck=1");
    t_inet_close(hi); srv_stop(w.s);
    ck_cleanup();
}
