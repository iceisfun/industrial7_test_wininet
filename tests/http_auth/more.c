/* http_auth: review pass 3 additions (prefix auth_x_).
 *  - credentials set with InternetSetOption on the CONNECT handle (not InternetConnect arguments), server and proxy
 *  - proxy Digest (407 + Proxy-Authenticate: Digest) verified by recomputing the MD5 chain
 *  - credential cache scope (host name), INTERNET_OPTION_END_BROWSER_SESSION flushing it
 *    ([D EndBrowserSession -> AuthFlush -> FlushPwcList(g_pwcRealm / g_pwcOther / g_pwcProxy)])
 *  - async sessions with Digest and NTLM legs, HTTP/1.0 request version on the retry, an NTLM server that never
 *    sends a type 2, proxy then origin credentials supplied in two rounds, InternetOpenUrl userinfo option view.
 * Every peer is an in-process loopback server; every wait is bounded. */
#include "auth.h"
#include <stdlib.h>

#define CH_BASIC "WWW-Authenticate: Basic realm=\"i7x\"\r\n"
#define CH_PBASIC "Proxy-Authenticate: Basic realm=\"i7xp\"\r\n"
#define ORIGIN "i7origin.invalid"

static HINTERNET x_proxy_session(srv *s) {
    t_net_prepare();
    char px[64]; snprintf(px, sizeof px, "127.0.0.1:%u", srv_port(s));
    HINTERNET hi = U(InternetOpenA)("i7xproxy", INTERNET_OPEN_TYPE_PROXY, px, NULL, 0);
    DWORD to = 5000;
    if (hi) { U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, 4); U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, 4); }
    return hi;
}

/* ------------------------------------------------------------------ InternetSetOption on the connect handle */
TEST(auth_x_connect_setoption_creds_answer_challenge) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("cso", "csp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_USERNAME, "cso", 3));
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PASSWORD, "csp", 3));
    areq q = {0}; q.path = "/xc/a"; ares r; a_send(hc, &q, &r, 0);
    a_dump(s);
    /* the request reads USERNAME/PASSWORD through to its connect object (options.c), and they answer the challenge */
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_AUTH(s, 0) == NULL);
    EXPECT_STR(REQ_AUTH(s, 1), a_basic("cso", "csp"));
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_x_connect_setoption_after_open_request) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("lateu", "latep");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/xc/late", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    /* set on the connect handle after the request handle exists */
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_USERNAME, "lateu", 5));
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PASSWORD, "latep", 5));
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    DWORD st = a_status(hr);
    a_dump(s);
    t_note("connect creds set after HttpOpenRequest: status=%lu requests=%d", st, srv_req_count(s));
    EXPECT_EQ(st, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("lateu", "latep"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_x_connect_setoption_proxy_creds_answer_407) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("cpu", "cpp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = x_proxy_session(s), hc = hi ? U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    CHECK(hc != NULL);
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PROXY_USERNAME, "cpu", 3));
    CHECK(U(InternetSetOptionA)(hc, INTERNET_OPTION_PROXY_PASSWORD, "cpp", 3));
    areq q = {0}; q.path = "/xp/a"; ares r; a_send(hc, &q, &r, 0);
    a_dump(s);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_PAUTH(s, 0) == NULL);
    EXPECT_STR(REQ_PAUTH(s, 1), a_basic("cpu", "cpp"));
    CHECK(REQ_AUTH(s, 1) == NULL);
    a_close(hc); a_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ proxy Digest */
#define CH_PDIGEST "Proxy-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"pxnonce0123456789\"\r\n"
TEST(auth_x_proxy_digest_proxy_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PDIGEST; g.verify = digest_verify;
    g.user = "pdu"; g.pass = "pdp"; g.realm = "i7digest"; g.nonce = "pxnonce0123456789";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = x_proxy_session(s), hc = hi ? U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    areq q = {0}; q.path = "/pd/x?y=1"; q.puser = "pdu"; q.ppass = "pdp"; ares r; a_send(hc, &q, &r, 0);
    a_dump(s);
    const char *pa = srv_req_count(s) >= 2 ? REQ_PAUTH(s, 1) : NULL;
    char uri[256] = "";
    if (pa) a_param(pa, "uri", uri, sizeof uri);
    t_note("proxy digest: status=%lu requests=%d uri=[%s]", r.status, srv_req_count(s), uri);
    CHECKF(r.ok, "err=%lu", r.err);
    /* the gate's verifier recomputed the MD5 chain with the method and the uri as sent */
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(pa && !strncmp(pa, "Digest ", 7));
    CHECK(REQ_AUTH(s, 1) == NULL);
    a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_x_proxy_digest_wrong_creds_final_407) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PDIGEST; g.verify = digest_verify; g.deny_403_after = 6;
    g.user = "pdu"; g.pass = "right"; g.realm = "i7digest"; g.nonce = "pxnonce0123456789";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = x_proxy_session(s), hc = hi ? U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    areq q = {0}; q.path = "/pdw"; q.puser = "pdu"; q.ppass = "wrong"; ares r; a_send(hc, &q, &r, 0);
    a_dump(s);
    t_note("proxy digest wrong creds: status=%lu requests=%d", r.status, srv_req_count(s));
    CHECK(r.ok);
    EXPECT_EQ(r.status, 407);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_EQ(g.n_ok, 0);
    a_close(hc); a_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ credential cache scope */
TEST(auth_x_cache_scoped_to_host_name) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("hn", "hp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "hn", "hp");
    areq q = {0}; q.path = "/hn/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    /* same server and port, reached by another host name, no credentials */
    HINTERNET hc2 = U(InternetConnectA)(hi, "localhost", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    a_send(hc2, &q, &r, 0);
    a_dump(s);
    int n = srv_req_count(s) - before;
    const char *a0 = n >= 1 ? REQ_AUTH(s, before) : NULL;
    t_note("cached 127.0.0.1 creds, request to localhost: status=%lu requests=%d auth0=%s", r.status, n, a0 ? a0 : "(none)");
    /* the password cache is keyed by host name: nothing pre-emptive, nothing to answer the challenge with */
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(n, 1);
    CHECK(a0 == NULL);
    a_close(hc2); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_x_cache_populated_by_request_option_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("ro", "rp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; q.path = "/ro/a"; q.ruser = "ro"; q.rpass = "rp"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    areq q2 = {0}; q2.path = "/ro/b"; a_send(hc, &q2, &r, 0);
    a_dump(s);
    /* credentials that came from the request options are cached like InternetConnect ones */
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s) - before, 1);
    EXPECT_STR(REQ_AUTH(s, before), a_basic("ro", "rp"));
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

static BOOL end_browser_session(void) { return U(InternetSetOptionA)(NULL, INTERNET_OPTION_END_BROWSER_SESSION, NULL, 0); }

TEST(auth_x_end_browser_session_flushes_server_cache) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("eb", "ep");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "eb", "ep");
    areq q = {0}; q.path = "/eb/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    a_close(hc);
    /* baseline: a credential-less connect is pre-authenticated from the cache */
    int b1 = srv_req_count(s);
    HINTERNET hc2 = a_connect(hi, s, NULL, NULL); a_send(hc2, &q, &r, 0); a_close(hc2);
    EXPECT_EQ(r.status, 200); EXPECT_EQ(srv_req_count(s) - b1, 1); EXPECT_STR(REQ_AUTH(s, b1), a_basic("eb", "ep"));
    SET_ERR(0xdeadbeef);
    CHECKF(end_browser_session(), "END_BROWSER_SESSION err=%lu", GetLastError());
    int b2 = srv_req_count(s);
    HINTERNET hc3 = a_connect(hi, s, NULL, NULL); a_send(hc3, &q, &r, 0);
    a_dump(s);
    /* decomp EndBrowserSession -> AuthFlush: the PWC lists are emptied, the challenge goes to the caller */
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s) - b2, 1);
    CHECK(REQ_AUTH(s, b2) == NULL);
    a_close(hc3); t_inet_close(hi); srv_stop(s);
}

TEST(auth_x_end_browser_session_flushes_proxy_cache) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.code = 407; g.challenge = CH_PBASIC; g.accept[0] = a_basic("ebp", "epp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = x_proxy_session(s), hc = hi ? U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    areq q = {0}; q.path = "/ebp/a"; q.puser = "ebp"; q.ppass = "epp"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    areq q2 = {0}; q2.path = "/ebp/b";
    int b1 = srv_req_count(s); a_send(hc, &q2, &r, 0);
    EXPECT_EQ(r.status, 200); EXPECT_EQ(srv_req_count(s) - b1, 1);   /* proxy.c: proxy creds are pre-emptive */
    CHECKF(end_browser_session(), "END_BROWSER_SESSION err=%lu", GetLastError());
    int b2 = srv_req_count(s); a_send(hc, &q2, &r, 0);
    a_dump(s);
    t_note("proxy after END_BROWSER_SESSION: status=%lu requests=%d pauth0=%s", r.status, srv_req_count(s) - b2,
           srv_req_count(s) > b2 && REQ_PAUTH(s, b2) ? REQ_PAUTH(s, b2) : "(none)");
    /* decomp AuthFlush: g_pwcProxy is flushed too */
    EXPECT_EQ(r.status, 407);
    EXPECT_EQ(srv_req_count(s) - b2, 1);
    CHECK(srv_req_count(s) > b2 && REQ_PAUTH(s, b2) == NULL);
    a_close(hc); a_close(hi); srv_stop(s);
}

TEST(auth_x_end_browser_session_keeps_handle_creds) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    /* the flush empties the cache, not the credentials held by an open connect handle */
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("kh", "kp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "kh", "kp");
    areq q = {0}; q.path = "/kh/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    CHECK(end_browser_session());
    int b = srv_req_count(s); a_send(hc, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s) - b, 2);   /* no pre-emptive header any more, the challenge is answered again */
    if (srv_req_count(s) - b >= 2) { CHECK(REQ_AUTH(s, b) == NULL); EXPECT_STR(REQ_AUTH(s, b + 1), a_basic("kh", "kp")); }
    char buf[64]; CHECK(a_qopt(hc, INTERNET_OPTION_USERNAME, buf, sizeof buf, NULL)); EXPECT_STR(buf, "kh");
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_x_digest_cache_new_session) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"dcnonce0001\"\r\n", "dcu", "dcp");
    g.nonce = "dcnonce0001";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/dc/a"; q.cuser = "dcu"; q.cpass = "dcp"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    q.cuser = q.cpass = NULL; a_once(s, &q, &r);
    a_dump(s);
    int n = srv_req_count(s) - before;
    const char *a0 = n >= 1 ? REQ_AUTH(s, before) : NULL;
    char nc[16] = ""; if (a0) a_param(a0, "nc", nc, sizeof nc);
    t_note("digest, new session without creds: status=%lu requests=%d auth0=%.40s nc=%s", r.status, n, a0 ? a0 : "(none)", nc);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(n, 1);
    CHECK(a0 && !strncmp(a0, "Digest ", 7));
    EXPECT_STR(nc, "00000002");
    if (a0) digest_check_recorded(s, before, "dcu", "i7digest", "dcp", 0, "auth");
    srv_stop(s);
}

/* ------------------------------------------------------------------ async sessions */
static HANDLE g_xev; static volatile DWORD g_xres, g_xerr;
static void CALLBACK x_async_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == 0x77) {
        INTERNET_ASYNC_RESULT *ar = info; g_xres = (DWORD)ar->dwResult; g_xerr = ar->dwError; SetEvent(g_xev);
    }
}
/* one async GET with InternetConnect credentials; returns the final status (0 on failure) */
static DWORD x_async_get(srv *s, const char *user, const char *pass, const char *path) {
    g_xev = CreateEventA(NULL, FALSE, FALSE, NULL); g_xres = 0; g_xerr = 0;
    HINTERNET hi = t_inet_open_ex("i7xasync", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    DWORD st = 0;
    if (hi) {
        U(InternetSetStatusCallbackA)(hi, x_async_cb);
        HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), user, pass, INTERNET_SERVICE_HTTP, 0, 0x77);
        HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH, 0x77) : NULL;
        if (hr) {
            BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
            DWORD e = ok ? 0 : GetLastError();
            if (!ok) {
                CHECKF(e == ERROR_IO_PENDING, "send err=%lu", e);
                if (e == ERROR_IO_PENDING) {
                    DWORD w = WaitForSingleObject(g_xev, 8000);
                    CHECKF(w == WAIT_OBJECT_0, "async completion wait=%lu", w);
                    if (w == WAIT_OBJECT_0) CHECKF(g_xres == 1, "async result=%lu err=%lu", g_xres, g_xerr);
                }
            }
            st = a_status(hr);
        }
        U(InternetSetStatusCallbackA)(hi, NULL);
        a_close(hr); a_close(hc); a_close(hi);
    }
    CloseHandle(g_xev); g_xev = NULL;
    return st;
}

TEST(auth_x_async_digest) {
    REQUIRE(U(InternetSetStatusCallbackA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"asyncnonce01\"\r\n", "adu", "adp");
    g.nonce = "asyncnonce01";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    DWORD st = x_async_get(s, "adu", "adp", "/async/digest");
    a_dump(s);
    EXPECT_EQ(st, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) digest_check_recorded(s, 1, "adu", "i7digest", "adp", 0, "auth");
    srv_stop(s);
}

TEST(auth_x_async_ntlm_custom_gate) {
    REQUIRE(U(InternetSetStatusCallbackA));
    gate g = {0}; g.challenge = "WWW-Authenticate: NTLM\r\n"; g.ntlm_mode = 1; g.pass = "asyncntlm";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    DWORD st = x_async_get(s, "i7async", "asyncntlm", "/async/ntlm");
    a_dump(s);
    EXPECT_EQ(st, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    EXPECT_STR(g.ntlm_user, "i7async");
    if (srv_req_count(s) >= 3) { EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 2)); }
    srv_stop(s);
}

TEST(auth_x_async_wrong_creds_final_401) {
    REQUIRE(U(InternetSetStatusCallbackA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("aw", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    DWORD st = x_async_get(s, "aw", "wrong", "/async/wrong");
    a_dump(s);
    EXPECT_EQ(st, 401);
    EXPECT_EQ(srv_req_count(s), 2);   /* same bound as the synchronous path (basic.c) */
    srv_stop(s);
}

/* ------------------------------------------------------------------ request version */
TEST(auth_x_http10_request_version_retry) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("v10", "p10");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "v10", "p10");
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/v10", "HTTP/1.0", NULL, NULL, T_INET_FRESH, 0);
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    EXPECT_EQ(a_status(hr), 200);
    a_dump(s);
    int n = srv_req_count(s);
    EXPECT_EQ(n, 2);
    for (int i = 0; i < n && i < 2; i++) EXPECT_STR(srv_req_line(s, i), "GET /v10 HTTP/1.0");
    if (n >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("v10", "p10"));
    if (n >= 2) t_note("HTTP/1.0 legs: conn %d / %d, Connection=%s", srv_req_conn(s, 0), srv_req_conn(s, 1),
                       srv_req_header(s, 0, "Connection") ? srv_req_header(s, 0, "Connection") : "(none)");
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ NTLM without a type 2 */
static int ntlm_no_t2_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int it = 0; it < 16; it++) {
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        if (ri >= 8) { srv_conn_sendf(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nstop"); continue; }
        (void)s;
        srv_conn_sendf(c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 6\r\n\r\ndenied");
    }
    return -1;
}
TEST(auth_x_ntlm_server_never_sends_type2) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_CALL(ntlm_no_t2_fn) }; static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; cfg.io_timeout_ms = 1000; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.path = "/not2"; q.cuser = "i7user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    int n = srv_req_count(s);
    t_note("NTLM server answering the type 1 with a bare 'NTLM' challenge: ok=%d status=%lu requests=%d", r.ok, r.status, n);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401);
    CHECK(n >= 2 && n <= 8);   /* bounded; the exact count is recorded */
    if (n >= 2) CHECK(REQ_AUTH(s, 1) && !strncmp(REQ_AUTH(s, 1), "NTLM TlRMTVNTUAAB", 17));
    srv_stop(s);
}

/* ------------------------------------------------------------------ proxy, then origin credentials in a second round */
static int two_round_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    char pw[128], ow[128]; snprintf(pw, sizeof pw, "%s", a_basic("pu2", "pp2")); snprintf(ow, sizeof ow, "%s", a_basic("ou2", "op2"));
    for (int it = 0; it < 16; it++) {
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        const char *p = srv_req_header(s, ri, "Proxy-Authorization"), *o = srv_req_header(s, ri, "Authorization");
        if (!p || strcmp(p, pw)) srv_conn_sendf(c, "HTTP/1.1 407 Proxy Authentication Required\r\n" CH_PBASIC "Content-Length: 1\r\n\r\nP");
        else if (!o || strcmp(o, ow)) srv_conn_sendf(c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"o2\"\r\nContent-Length: 1\r\n\r\nO");
        else srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nboth");
    }
    return -1;
}
TEST(auth_x_proxy_then_origin_creds_second_round) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_CALL(two_round_fn) }; static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; cfg.io_timeout_ms = 1000; srv *s; START_OR_SKIP(&cfg, &s);
    HINTERNET hi = x_proxy_session(s), hc = hi ? U(InternetConnectA)(hi, ORIGIN, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/two", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_USERNAME, "pu2", 3));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PROXY_PASSWORD, "pp2", 3));
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    DWORD st1 = a_status(hr); int n1 = srv_req_count(s);
    char sink[64]; t_inet_read_all(hr, sink, sizeof sink, NULL);
    /* round 1: proxy answered with PROXY_*, the origin 401 is handed back (no origin credentials yet) */
    EXPECT_EQ(st1, 401); EXPECT_STR(sink, "O"); EXPECT_EQ(n1, 2);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "ou2", 3));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "op2", 3));
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    DWORD st2 = a_status(hr);
    t_inet_read_all(hr, sink, sizeof sink, NULL);
    a_dump(s);
    int n = srv_req_count(s);
    t_note("proxy+origin in two rounds: round1 %lu (%d reqs), round2 %lu (%d reqs total) body=%s", st1, n1, st2, n, sink);
    EXPECT_EQ(st2, 200); EXPECT_STR(sink, "both");
    /* every leg of round 2 carries the proxy credentials (proxy cache), the last one the origin credentials too */
    for (int i = n1; i < n; i++) EXPECT_STR(REQ_PAUTH(s, i), a_basic("pu2", "pp2"));
    if (n > n1) EXPECT_STR(REQ_AUTH(s, n - 1), a_basic("ou2", "op2"));
    a_close(hr); a_close(hc); a_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl userinfo: option view */
TEST(auth_x_open_url_userinfo_option_view) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetQueryOptionA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("ouv", "opv");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    char url[256]; snprintf(url, sizeof url, "http://ouv:opv@%s/ov", srv_hostport(s));
    HINTERNET hu = U(InternetOpenUrlA)(hi, url, NULL, 0, T_INET_FRESH, 0);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (hu) {
        EXPECT_EQ(a_status(hu), 200);
        char u[64], p[64]; DWORD ul = 0, pl = 0;
        int uok = a_qopt(hu, INTERNET_OPTION_USERNAME, u, sizeof u, &ul);
        int pok = a_qopt(hu, INTERNET_OPTION_PASSWORD, p, sizeof p, &pl);
        t_note("InternetOpenUrl userinfo -> USERNAME ok=%d [%s] len %lu, PASSWORD ok=%d [%s] len %lu", uok, u, ul, pok, pok ? "<set>" : "", pl);
        /* the userinfo becomes the connect credentials of the URL handle */
        CHECK(uok); EXPECT_STR(u, "ouv"); EXPECT_EQ(ul, 3);
        CHECK(pok); EXPECT_STR(p, "opv");
        a_close(hu);
    }
    EXPECT_EQ(srv_req_count(s), 2);
    t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ challenge on a 401 to a HEAD with NO_AUTH via ex */
TEST(auth_x_request_option_creds_cleared_with_empty_string) {
    REQUIRE(U(InternetSetOptionA)); REQUIRE(U(HttpSendRequestA));
    /* options.c: setting "" fails with 87, so the earlier credentials stay and are used */
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("keep", "kpw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/keep", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "keep", 4));
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "kpw", 3));
    SET_ERR(0); BOOL e1 = U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "", 0); DWORD err = GetLastError();
    CHECK(!e1); EXPECT_EQ(err, ERROR_INVALID_PARAMETER);
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    EXPECT_EQ(a_status(hr), 200);
    a_dump(s);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("keep", "kpw"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}
