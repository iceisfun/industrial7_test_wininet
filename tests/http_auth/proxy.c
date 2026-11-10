/* http_auth: proxy authentication (407 + Proxy-Authenticate) against an in-process "proxy".
 * The session is InternetOpen(INTERNET_OPEN_TYPE_PROXY, "127.0.0.1:<port>") - a per-handle setting, nothing
 * system-wide. Requests go to a fictitious origin (i7origin.invalid) so the proxy is never bypassed and no
 * name is resolved: the loopback gate receives the absolute-form request line. */
#include "auth.h"

#define CH_PBASIC "Proxy-Authenticate: Basic realm=\"i7proxy\"\r\n"
#define ORIGIN "i7origin.invalid"

static HINTERNET proxy_session(srv *s) {
    t_net_prepare();
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", srv_port(s));
    HINTERNET hi = U(InternetOpenA)("i7proxyauth", INTERNET_OPEN_TYPE_PROXY, px, NULL, 0);
    DWORD to = 5000;
    if (hi) { U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, 4); }
    return hi;
}
static void proxy_once(srv *s, const char *cuser, const char *cpass, const areq *q, ares *r) {
    HINTERNET hi = proxy_session(s);
    HINTERNET hc = hi ? U(InternetConnectA)(hi, ORIGIN, 80, cuser, cpass, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (!hc) { memset(r, 0, sizeof *r); r->err = GetLastError(); a_close(hi); return; }
    a_send(hc, q, r, 0);
    a_close(hc); a_close(hi);
}

TEST(auth_proxy_request_line_absolute_form) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/abs?x=1"; ares r; proxy_once(s, NULL, NULL, &q, &r);
    a_dump(s);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 407);
    EXPECT_STR(r.body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(srv_req_line(s, 0), "GET http://" ORIGIN "/abs?x=1 HTTP/1.1");
    EXPECT_STR(srv_req_header(s, 0, "Host"), ORIGIN);
    CHECK(REQ_PAUTH(s, 0) == NULL);
    srv_stop(s);
}

TEST(auth_proxy_407_queryable) {
    REQUIRE(U(HttpQueryInfoA));
    gate g = {0}; g.code = 407; g.challenge = "Proxy-Authenticate: Basic realm=\"i7proxy\"\r\nProxy-Authenticate: NTLM\r\n"; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = proxy_session(s), hc = U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    EXPECT_EQ(r.status, 407);
    char b[128]; DWORD idx = 0;
    CHECK(a_query(r.hr, HTTP_QUERY_PROXY_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Basic realm=\"i7proxy\"");
    CHECK(a_query(r.hr, HTTP_QUERY_PROXY_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "NTLM");
    SET_ERR(0); CHECK(!a_query(r.hr, HTTP_QUERY_PROXY_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; SET_ERR(0); CHECK(!a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0; CHECK(a_query(r.hr, HTTP_QUERY_STATUS_TEXT, &idx, b, sizeof b)); EXPECT_STR(b, "Proxy Authentication Required");
    a_close(r.hr); a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_proxy_basic_request_option_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("puser", "ppass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/p"; q.puser = "puser"; q.ppass = "ppass"; ares r; proxy_once(s, NULL, NULL, &q, &r);
    a_dump(s);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "ok");
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_PAUTH(s, 0) == NULL);
    EXPECT_STR(REQ_PAUTH(s, 1), a_basic("puser", "ppass"));
    CHECK(REQ_AUTH(s, 1) == NULL);
    EXPECT_STR(srv_req_line(s, 1), "GET http://" ORIGIN "/p HTTP/1.1");
    srv_stop(s);
}

TEST(auth_proxy_no_creds_returns_407) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("puser", "ppass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; ares r; proxy_once(s, NULL, NULL, &q, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 407); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_proxy_connect_creds_used_for_proxy) {
    REQUIRE(U(HttpSendRequestA));
    /* ProcessResponseHeaders: with no proxy credentials, the server credentials are tried for the proxy
       (GetUserPassAndCredentials(0, ...)) unless GlobalUserPassServerOnly is set */
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("cuser", "cpass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; ares r; proxy_once(s, "cuser", "cpass", &q, &r);
    a_dump(s);
    t_note("407 with only InternetConnect creds: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_PAUTH(s, 1), a_basic("cuser", "cpass"));
    srv_stop(s);
}

TEST(auth_proxy_request_server_creds_used_for_proxy) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("ruser", "rpass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.ruser = "ruser"; q.rpass = "rpass"; ares r; proxy_once(s, NULL, NULL, &q, &r);
    a_dump(s);
    t_note("407 with only request USERNAME/PASSWORD: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 200);   /* Win10 VM: server creds answer the proxy when no proxy creds exist */
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_PAUTH(s, 1), a_basic("ruser", "rpass"));
    srv_stop(s);
}

TEST(auth_proxy_connect_creds_win_over_request_proxy_creds) {
    REQUIRE(U(HttpSendRequestA));
    /* Win10 VM: with InternetConnect credentials present, the proxy leg answers with THOSE, even though
       PROXY_USERNAME/PASSWORD were set on the request; the proxy rejects them and the 407 reaches the caller */
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("puser", "ppass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.puser = "puser"; q.ppass = "ppass"; ares r; proxy_once(s, "cuser", "cpass", &q, &r);
    a_dump(s);
    CHECK(r.ok);
    EXPECT_EQ(r.status, 407);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_PAUTH(s, 1), a_basic("cuser", "cpass"));
    srv_stop(s);
}

TEST(auth_proxy_wrong_creds_final_407) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("puser", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.puser = "puser"; q.ppass = "wrong"; ares r; proxy_once(s, NULL, NULL, &q, &r);
    a_dump(s);
    t_note("proxy wrong creds: status=%lu requests=%d", r.status, srv_req_count(s));
    CHECK(r.ok);
    EXPECT_EQ(r.status, 407);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_EQ(g.n_ok, 0);
    srv_stop(s);
}

TEST(auth_proxy_no_auth_flag) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("puser", "ppass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.puser = "puser"; q.ppass = "ppass"; q.flags = T_INET_FRESH | INTERNET_FLAG_NO_AUTH; ares r; proxy_once(s, NULL, NULL, &q, &r);
    EXPECT_EQ(r.status, 407); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_proxy_resend_after_setting_proxy_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("late", "proxy");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = proxy_session(s), hc = U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/late", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)); EXPECT_EQ(a_status(hr), 407);
    char buf[64]; t_inet_read_all(hr, buf, sizeof buf, NULL);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "late", 4));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "proxy", 5));
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    EXPECT_EQ(a_status(hr), 200);
    a_dump(s);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(REQ_PAUTH(s, 1), a_basic("late", "proxy"));
    a_close(hr); a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_proxy_preemptive_second_request) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("puser", "ppass");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = proxy_session(s), hc = U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    areq q = {0}; q.path = "/a"; q.puser = "puser"; q.ppass = "ppass"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    areq q2 = {0}; q2.path = "/zzz/other"; a_send(hc, &q2, &r, 0);
    a_dump(s);
    t_note("second request via proxy without per-request creds: status=%lu, %d more requests, first pauth=%s", r.status,
           srv_req_count(s) - before, REQ_PAUTH(s, before) ? REQ_PAUTH(s, before) : "(none)");
    /* Win10 VM: proxy credentials are cached for the proxy and sent pre-emptively on any later path */
    EXPECT_EQ(r.status, 200); EXPECT_EQ(srv_req_count(s) - before, 1);
    EXPECT_STR(REQ_PAUTH(s, before), a_basic("puser", "ppass"));
    a_close(hc); a_close(hi); srv_stop(s);
}

/* proxy 407 then origin 401: Proxy-Authorization must stay on the origin retry */
static int chain_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    const char *pv = a_basic("puser", "ppass"), *ov = a_basic("ouser", "opass");
    char pwant[128], owant[128]; snprintf(pwant, sizeof pwant, "%s", pv); snprintf(owant, sizeof owant, "%s", ov);
    for (int it = 0; it < 16; it++) {
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        const char *p = srv_req_header(s, ri, "Proxy-Authorization"), *o = srv_req_header(s, ri, "Authorization");
        if (!p || strcmp(p, pwant)) srv_conn_sendf(c, "HTTP/1.1 407 Proxy Authentication Required\r\n" CH_PBASIC "Content-Length: 1\r\n\r\nP");
        else if (!o || strcmp(o, owant)) srv_conn_sendf(c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"origin\"\r\nContent-Length: 1\r\n\r\nO");
        else srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nboth");
    }
    return -1;
}
TEST(auth_proxy_connect_creds_answer_proxy_in_chain) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_CALL(chain_fn) }; static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.path = "/chain"; q.puser = "puser"; q.ppass = "ppass"; ares r; proxy_once(s, "ouser", "opass", &q, &r);
    a_dump(s);
    /* Win10 VM: origin creds from InternetConnect are sent to the proxy; the 407 is returned */
    CHECK(r.ok); EXPECT_EQ(r.status, 407); EXPECT_STR(r.body, "P");
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) { EXPECT_STR(REQ_PAUTH(s, 1), a_basic("ouser", "opass")); CHECK(REQ_AUTH(s, 1) == NULL); }
    srv_stop(s);
}

TEST(auth_proxy_then_origin_auth) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_CALL(chain_fn) }; static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.path = "/chain"; q.puser = "puser"; q.ppass = "ppass"; q.ruser = "ouser"; q.rpass = "opass"; ares r; proxy_once(s, NULL, NULL, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "both");
    int n = srv_req_count(s);
    t_note("proxy+origin chain: %d requests", n);
    EXPECT_EQ(n, 3);
    if (n >= 3) {
        CHECK(REQ_PAUTH(s, 0) == NULL); CHECK(REQ_AUTH(s, 0) == NULL);
        EXPECT_STR(REQ_PAUTH(s, 1), a_basic("puser", "ppass")); CHECK(REQ_AUTH(s, 1) == NULL);
        EXPECT_STR(REQ_PAUTH(s, 2), a_basic("puser", "ppass")); EXPECT_STR(REQ_AUTH(s, 2), a_basic("ouser", "opass"));
    }
    srv_stop(s);
}

TEST(auth_proxy_ntlm_custom_gate) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = "Proxy-Authenticate: NTLM\r\n"; g.ntlm_mode = 1; g.pass = "proxypw";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.puser = "i7proxyuser"; q.ppass = "proxypw"; ares r; proxy_once(s, NULL, NULL, &q, &r);
    a_dump(s);
    t_note("proxy NTLM: status=%lu requests=%d user=[%s] v2ok=%d", r.status, srv_req_count(s), g.ntlm_user, g.ntlm_v2_ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    EXPECT_STR(g.ntlm_user, "i7proxyuser");
    if (srv_req_count(s) >= 3) {
        CHECK(!strncmp(REQ_PAUTH(s, 1) ? REQ_PAUTH(s, 1) : "", "NTLM TlRMTVNTUAAB", 17));
        CHECK(!strncmp(REQ_PAUTH(s, 2) ? REQ_PAUTH(s, 2) : "", "NTLM TlRMTVNTUAAD", 17));
    }
    srv_stop(s);
}
