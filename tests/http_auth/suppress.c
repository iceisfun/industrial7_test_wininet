/* http_auth: INTERNET_OPTION_SUPPRESS_SERVER_AUTH (104).
 * Docs: "Sets an HTTP request object such that it will not logon to origin servers, but will perform automatic
 * logon to HTTP proxy servers." Decomp InternetSetOptionA case 0x68: request handles only (type 'Hreq'), sets
 * flag 0x2000 at +0x149c unless +0x149c & 0x20 is already set, in which case the call fails with 12019
 * (ERROR_INTERNET_INCORRECT_HANDLE_STATE). The value buffer is not read (options.c, Win10 VM). */
#include "auth.h"

#define CH_SB "WWW-Authenticate: Basic realm=\"i7sup\"\r\n"

static int suppress(HINTERNET hr) { DWORD v = 1; return U(InternetSetOptionA)(hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v) != 0; }

/* send on a fresh request of hc with SUPPRESS_SERVER_AUTH set first */
static void sup_send(HINTERNET hc, const char *path, ares *r, int keep) {
    memset(r, 0, sizeof *r);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH, 0);
    if (!hr) { r->err = GetLastError(); return; }
    CHECK(suppress(hr));
    r->ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); r->err = r->ok ? 0 : GetLastError();
    r->status = a_status(hr);
    if (r->ok) r->n = t_inet_read_all(hr, r->body, sizeof r->body, NULL);
    if (keep) r->hr = hr; else a_close(hr);
}

TEST(auth_suppress_no_automatic_logon_localhost) {
    REQUIRE(U(HttpSendRequestA));
    /* same server as auth_ntlm_sspi_server_default_creds_localhost (which logs on automatically): suppressed */
    static const srv_step st[] = { S_AUTH("NTLM"), S_REPLY(200, NULL, "ntlm-ok"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "localhost", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    ares r; sup_send(hc, "/sup/auto", &r, 0);
    a_dump(s);
    t_note("suppressed automatic logon: ok=%d status=%lu requests=%d", r.ok, r.status, srv_req_count(s));
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    CHECK(srv_req_count(s) < 1 || REQ_AUTH(s, 0) == NULL);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_explicit_basic_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_SB; g.accept[0] = a_basic("su", "sp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "su", "sp");
    ares r; sup_send(hc, "/sup/basic", &r, 0);
    a_dump(s);
    t_note("SUPPRESS_SERVER_AUTH + explicit Basic creds: status=%lu requests=%d", r.status, srv_req_count(s));
    CHECKF(r.ok, "err=%lu", r.err);
    CHECK(r.status == 200 || r.status == 401);
    CHECK(srv_req_count(s) <= 2);
    CHECK(srv_req_count(s) < 1 || REQ_AUTH(s, 0) == NULL);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_explicit_ntlm_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: NTLM\r\n"; g.ntlm_mode = 1; g.pass = "sup-pw";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "supntlm", "sup-pw");
    ares r; sup_send(hc, "/sup/ntlm", &r, 0);
    a_dump(s);
    t_note("SUPPRESS_SERVER_AUTH + explicit NTLM creds: status=%lu requests=%d v2ok=%d", r.status, srv_req_count(s), g.ntlm_v2_ok);
    CHECKF(r.ok, "err=%lu", r.err);
    CHECK(r.status == 200 || r.status == 401);
    CHECK(srv_req_count(s) <= 3);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_explicit_digest_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"\r\n", "sd", "sdp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "sd", "sdp");
    ares r; sup_send(hc, "/sup/digest", &r, 0);
    a_dump(s);
    t_note("SUPPRESS_SERVER_AUTH + explicit Digest creds: status=%lu requests=%d", r.status, srv_req_count(s));
    CHECKF(r.ok, "err=%lu", r.err);
    CHECK(r.status == 200 || r.status == 401);
    CHECK(srv_req_count(s) <= 2);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_no_creds_basic_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_SB; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    ares r; sup_send(hc, "/sup/nc", &r, 1);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(r.body, "denied");
    char b[128]; DWORD idx = 0;
    CHECK(a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); EXPECT_STR(b, "Basic realm=\"i7sup\"");
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_set_after_send) {
    REQUIRE(U(InternetSetOptionA));
    gate g = {0}; g.challenge = CH_SB; g.accept[0] = "never";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/sup/after", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    DWORD v = 1; SetLastError(0xdeadbeef);
    BOOL ok = U(InternetSetOptionA)(hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v); DWORD e = ok ? 0 : GetLastError();
    t_note("SUPPRESS_SERVER_AUTH after HttpSendRequest: ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    CHECK(ok || e == ERROR_INTERNET_INCORRECT_HANDLE_STATE);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_wide_set_and_zero_value) {
    REQUIRE(U(InternetSetOptionW));
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 9, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, T_INET_FRESH, 0);
    REQUIRE(hr);
    DWORD v = 1, z = 0;
    CHECK(U(InternetSetOptionW)(hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &z, sizeof z));   /* value not read */
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, 1));
    SET_ERR(0);
    CHECK(!U(InternetSetOptionW)(hc, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &v, sizeof v)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    a_close(hr); a_close(hc); t_inet_close(hi);
}

TEST(auth_suppress_zero_value_still_suppresses_automatic_logon) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_AUTH("NTLM"), S_REPLY(200, NULL, "ntlm-ok"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "localhost", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/sup/zero", NULL, NULL, NULL, T_INET_FRESH, 0);
    DWORD z = 0; CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_SUPPRESS_SERVER_AUTH, &z, sizeof z));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    DWORD st_ = a_status(hr);
    a_dump(s);
    t_note("SUPPRESS_SERVER_AUTH with value 0: status=%lu requests=%d", st_, srv_req_count(s));
    /* decomp: the set path ORs the flag in without reading the buffer */
    EXPECT_EQ(st_, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_suppress_cached_credentials_preemptive) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_SB; g.accept[0] = a_basic("cu", "cp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "cu", "cp");
    areq q = {0}; q.path = "/sup/c/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    sup_send(hc, "/sup/c/b", &r, 0);
    a_dump(s);
    const char *a = srv_req_count(s) > before ? REQ_AUTH(s, before) : NULL;
    t_note("SUPPRESS after a cached Basic success: status=%lu legs=%d first-leg auth=%s", r.status, srv_req_count(s) - before, a ? a : "(none)");
    CHECK(r.status == 200 || r.status == 401);
    CHECK(srv_req_count(s) - before <= 2);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

static HINTERNET sup_proxy_session(srv *s) {
    t_net_prepare();
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", srv_port(s));
    HINTERNET hi = U(InternetOpenA)("i7supproxy", INTERNET_OPEN_TYPE_PROXY, px, NULL, 0);
    DWORD to = 5000;
    if (hi) { U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, 4); }
    return hi;
}

TEST(auth_suppress_proxy_basic_still_answered) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = "Proxy-Authenticate: Basic realm=\"i7supproxy\"\r\n"; g.accept[0] = a_basic("spx", "spp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = sup_proxy_session(s);
    HINTERNET hc = U(InternetConnectA)(hi, "i7origin.invalid", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/sup/proxy", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(suppress(hr));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "spx", 3));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "spp", 3));
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD st_ = a_status(hr);
    a_dump(s);
    /* documented: proxies are still authenticated */
    CHECKF(ok, "err=%lu", GetLastError());
    EXPECT_EQ(st_, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_PAUTH(s, 1), a_basic("spx", "spp"));
    a_close(hr); a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_suppress_proxy_then_origin_challenge) {
    REQUIRE(U(HttpSendRequestA));
    /* proxy authenticated, origin 401 (through the proxy) is not answered with the request's server creds */
    gate g = {0}; g.code = 401; g.challenge = CH_SB; g.accept[0] = a_basic("ou", "op");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = sup_proxy_session(s);
    HINTERNET hc = U(InternetConnectA)(hi, "i7origin.invalid", 80, "ou", "op", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/sup/origin", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(suppress(hr));
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD st_ = a_status(hr);
    a_dump(s);
    t_note("SUPPRESS via proxy, origin 401 with connect creds: status=%lu requests=%d", st_, srv_req_count(s));
    CHECKF(ok, "err=%lu", GetLastError());
    CHECK(st_ == 200 || st_ == 401);
    CHECK(srv_req_count(s) <= 2);
    a_close(hr); a_close(hc); a_close(hi); srv_stop(s);
}
