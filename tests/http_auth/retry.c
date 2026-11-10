/* http_auth: retry bounds and challenge sequencing. A scripted server decides each reply from the request index
 * and the credential header, so the tests can count exactly how many legs wininet sends before it hands the
 * response back (never an unbounded loop: every server falls back to 403 after a few denials). */
#include "auth.h"
#include <stdlib.h>

typedef struct rs rs;
/* fill buf with a full HTTP response for request ri (n = 0-based index on this server) */
typedef void (*rs_fn)(rs *r, srv *s, int ri, int n, char *buf, size_t cap);
struct rs { rs_fn fn; int cap403; volatile LONG n; const char *user, *pass; char nonce[64]; };

static int rs_call(srv_conn *c, const srv_step *st, void *user) {
    rs *r = user; srv *s = srv_conn_server(c);
    for (int it = 0; it < 32; it++) {
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        int n = (int)InterlockedIncrement(&r->n) - 1;
        char *b = malloc(8192);
        if (r->cap403 && n >= r->cap403) snprintf(b, 8192, "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\n\r\nstop");
        else r->fn(r, s, ri, n, b, 8192);
        srv_conn_send(c, b, strlen(b)); free(b);
    }
    return -1;
}
static srv *rs_start(rs *r) {
    static const srv_step st[] = { S_CALL(rs_call) };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; cfg.user = r; cfg.lifetime_ms = 20000;
    cfg.io_timeout_ms = 1000;   /* see gate_start_kind */
    srv *s = NULL; if (srv_start(&cfg, &s)) return NULL; return s;
}
static void r401(char *b, size_t cap, const char *chal) {
    snprintf(b, cap, "HTTP/1.1 401 Unauthorized\r\n%sContent-Length: 6\r\n\r\ndenied", chal);
}
static void r200(char *b, size_t cap) { snprintf(b, cap, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); }

/* ------------------------------------------------------------------ servers */
static void fn_rotating_realm(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    char ch[128]; snprintf(ch, sizeof ch, "WWW-Authenticate: Basic realm=\"rot%d\"\r\n", n); r401(b, cap, ch);
}
static void fn_basic_then_nochallenge(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    if (!REQ_AUTH(s, ri)) r401(b, cap, "WWW-Authenticate: Basic realm=\"x\"\r\n"); else r401(b, cap, "");
}
static void fn_basic_then_403(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    if (!REQ_AUTH(s, ri)) r401(b, cap, "WWW-Authenticate: Basic realm=\"x\"\r\n");
    else snprintf(b, cap, "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden");
}
static void fn_basic_then_digest(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    const char *a = REQ_AUTH(s, ri);
    if (!a) r401(b, cap, "WWW-Authenticate: Basic realm=\"sw\"\r\n");
    else if (!_strnicmp(a, "Basic ", 6)) r401(b, cap, "WWW-Authenticate: Digest realm=\"sw\", nonce=\"abcdef0123\", qop=\"auth\"\r\n");
    else r200(b, cap);
}
static void fn_stale_forever(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    char ch[256];
    snprintf(ch, sizeof ch, "WWW-Authenticate: Digest realm=\"st\", nonce=\"n%08d\", qop=\"auth\"%s\r\n", n, REQ_AUTH(s, ri) ? ", stale=true" : "");
    r401(b, cap, ch);
}
static void fn_ok_after_two_auth(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    /* accept only on the second request that carries credentials (the client must retry twice) */
    static volatile LONG seen; if (n == 0) seen = 0;
    if (REQ_AUTH(s, ri) && InterlockedIncrement(&seen) >= 2) r200(b, cap);
    else r401(b, cap, "WWW-Authenticate: Basic realm=\"two\"\r\n");
}
static void fn_200_with_challenge(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    snprintf(b, cap, "HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic realm=\"ignored\"\r\nContent-Length: 2\r\n\r\nok");
}
static void fn_407_from_origin(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    if (REQ_PAUTH(s, ri)) r200(b, cap);
    else snprintf(b, cap, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"px\"\r\nContent-Length: 6\r\n\r\ndenied");
}
static void fn_digest_stale_once(rs *r, srv *s, int ri, int n, char *b, size_t cap) {
    /* nonce n0 -> stale -> nonce n1 accepted when the response verifies */
    const char *a = REQ_AUTH(s, ri);
    char ch[256];
    if (!a) { r401(b, cap, "WWW-Authenticate: Digest realm=\"so\", nonce=\"nonce0\", qop=\"auth\"\r\n"); return; }
    char nonce[64] = "", uri[256] = "", nc[16] = "", cn[128] = "", resp[64] = "", qop[16] = "";
    a_param(a, "nonce", nonce, sizeof nonce); a_param(a, "uri", uri, sizeof uri); a_param(a, "nc", nc, sizeof nc);
    a_param(a, "cnonce", cn, sizeof cn); a_param(a, "response", resp, sizeof resp); a_param(a, "qop", qop, sizeof qop);
    char want[33]; a_digest_response(r->user, "so", r->pass, srv_req_method(s, ri), uri, nonce, nc, cn, qop, 0, want);
    if (strcmp(want, resp)) { r401(b, cap, "WWW-Authenticate: Digest realm=\"so\", nonce=\"nonce1\", qop=\"auth\"\r\n"); return; }
    if (!strcmp(nonce, "nonce0")) { snprintf(ch, sizeof ch, "WWW-Authenticate: Digest realm=\"so\", nonce=\"nonce1\", qop=\"auth\", stale=true\r\n"); r401(b, cap, ch); return; }
    r200(b, cap);
}

static void rs_once(rs *r, srv **ps, const char *path, const char *u, const char *p, DWORD flags, ares *res) {
    *ps = rs_start(r);
    if (!*ps) { memset(res, 0, sizeof *res); return; }
    areq q = {0}; q.path = path; q.cuser = u; q.cpass = p; q.flags = flags;
    a_once(*ps, &q, res);
}

/* ------------------------------------------------------------------ tests */
TEST(auth_retry_rotating_realm_bounded) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_rotating_realm; r.cap403 = 8; srv *s; ares res;
    rs_once(&r, &s, "/rt/rot", "ru", "rp", 0, &res); SRV_OR_SKIP(s);
    a_dump(s);
    t_note("rotating realm: status=%lu requests=%d", res.status, srv_req_count(s));
    CHECK(srv_req_count(s) < 8);
    EXPECT_EQ(res.status, 401);
    EXPECT_EQ(srv_req_count(s), 2);
    srv_stop(s);
}

TEST(auth_retry_401_without_challenge_after_credentials) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_basic_then_nochallenge; r.cap403 = 8; srv *s; ares res;
    rs_once(&r, &s, "/rt/noch", "nu", "np", 0, &res); SRV_OR_SKIP(s);
    a_dump(s);
    CHECKF(res.ok, "err=%lu", res.err);
    EXPECT_EQ(res.status, 401);
    EXPECT_EQ(srv_req_count(s), 2);
    EXPECT_STR(res.body, "denied");
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("nu", "np"));
    srv_stop(s);
}

TEST(auth_retry_403_after_credentials) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_basic_then_403; r.cap403 = 8; srv *s; ares res;
    rs_once(&r, &s, "/rt/403", "fu", "fp", 0, &res); SRV_OR_SKIP(s);
    CHECKF(res.ok, "err=%lu", res.err);
    EXPECT_EQ(res.status, 403);
    EXPECT_STR(res.body, "forbidden");
    EXPECT_EQ(srv_req_count(s), 2);
    srv_stop(s);
}

TEST(auth_retry_scheme_switch_basic_to_digest) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_basic_then_digest; r.cap403 = 8; srv *s; ares res;
    rs_once(&r, &s, "/rt/switch", "su", "sp", 0, &res); SRV_OR_SKIP(s);
    a_dump(s);
    t_note("Basic then Digest challenge: status=%lu requests=%d", res.status, srv_req_count(s));
    CHECK(srv_req_count(s) <= 4);
    CHECK(res.status == 200 || res.status == 401);
    if (srv_req_count(s) >= 2) EXPECT_STR(REQ_AUTH(s, 1), a_basic("su", "sp"));
    srv_stop(s);
}

TEST(auth_retry_digest_stale_forever_bounded) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_stale_forever; r.cap403 = 10; srv *s; ares res;
    rs_once(&r, &s, "/rt/stale", "su", "sp", 0, &res); SRV_OR_SKIP(s);
    a_dump(s);
    t_note("stale=true forever: status=%lu requests=%d", res.status, srv_req_count(s));
    CHECK(srv_req_count(s) < 10);
    EXPECT_EQ(res.status, 401);
    srv_stop(s);
}

TEST(auth_retry_digest_stale_once_new_nonce_used) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_digest_stale_once; r.cap403 = 8; r.user = "so-user"; r.pass = "so-pass"; srv *s; ares res;
    rs_once(&r, &s, "/rt/staleonce", "so-user", "so-pass", 0, &res); SRV_OR_SKIP(s);
    a_dump(s);
    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    if (srv_req_count(s) >= 3) {
        char n1[32] = "", n2[32] = "";
        a_param(REQ_AUTH(s, 1), "nonce", n1, sizeof n1); a_param(REQ_AUTH(s, 2), "nonce", n2, sizeof n2);
        EXPECT_STR(n1, "nonce0"); EXPECT_STR(n2, "nonce1");
        char nc[16] = ""; a_param(REQ_AUTH(s, 2), "nc", nc, sizeof nc);
        t_note("nc on the new nonce: %s", nc);
    }
    srv_stop(s);
}

TEST(auth_retry_server_needs_two_credentialed_legs) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_ok_after_two_auth; r.cap403 = 8; srv *s; ares res;
    rs_once(&r, &s, "/rt/two", "tu", "tp", 0, &res); SRV_OR_SKIP(s);
    a_dump(s);
    /* Basic: exactly one credentialed retry per HttpSendRequest (basic.c auth_basic_wrong_creds_final_401) */
    EXPECT_EQ(res.status, 401);
    EXPECT_EQ(srv_req_count(s), 2);
    srv_stop(s);
}

TEST(auth_retry_200_with_challenge_header_not_retried) {
    REQUIRE(U(HttpSendRequestA));
    rs r = {0}; r.fn = fn_200_with_challenge; r.cap403 = 8; srv *s; ares res;
    rs_once(&r, &s, "/rt/200ch", "cu", "cp", 0, &res); SRV_OR_SKIP(s);
    EXPECT_EQ(res.status, 200);
    EXPECT_EQ(srv_req_count(s), 1);
    CHECK(REQ_AUTH(s, 0) == NULL);
    srv_stop(s);
}

TEST(auth_retry_407_from_direct_origin) {
    REQUIRE(U(HttpSendRequestA));
    /* a 407 from a server that is not a configured proxy: observe whether proxy credentials are applied */
    rs r = {0}; r.fn = fn_407_from_origin; r.cap403 = 8; srv *s = rs_start(&r); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/rt/407direct"; q.puser = "pu"; q.ppass = "pp"; ares res; a_once(s, &q, &res);
    a_dump(s);
    t_note("407 from a direct origin with PROXY_USERNAME set: status=%lu requests=%d pauth=%s", res.status, srv_req_count(s),
           srv_req_count(s) >= 2 && REQ_PAUTH(s, 1) ? REQ_PAUTH(s, 1) : "(none)");
    CHECK(srv_req_count(s) <= 3);
    CHECK(res.status == 200 || res.status == 407);
    srv_stop(s);
}

TEST(auth_retry_wrong_then_right_on_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: Basic realm=\"wr\"\r\n"; g.accept[0] = a_basic("right", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/rt/wr", NULL, NULL, NULL, T_INET_FRESH, 0);
    U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "wrong", 5); U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, "pw", 2);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(a_status(hr), 401);
    int n1 = srv_req_count(s);
    { char tmp[64]; t_inet_read_all(hr, tmp, sizeof tmp, NULL); }
    U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, "right", 5);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    a_dump(s);
    EXPECT_EQ(a_status(hr), 200);
    EXPECT_EQ(n1, 2);
    int n = srv_req_count(s);
    CHECK(n >= 3 && n <= 4);
    if (n >= 3) EXPECT_STR(REQ_AUTH(s, n - 1), a_basic("right", "pw"));
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_retry_many_requests_same_connect_wrong_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: Basic realm=\"many\"\r\n"; g.accept[0] = a_basic("never", "never");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "bad", "bad");
    int total = 0;
    for (int i = 0; i < 4; i++) {
        areq q = {0}; char p[32]; snprintf(p, sizeof p, "/rt/many/%d", i); q.path = p; ares r; a_send(hc, &q, &r, 0);
        CHECKF(r.status == 401, "req %d status %lu", i, r.status);
        int now = srv_req_count(s); t_note("request %d used %d legs", i, now - total); total = now;
    }
    /* every HttpSendRequest is bounded; the remembered failed pair may be sent pre-emptively (cache.c) */
    CHECK(srv_req_count(s) <= 8);
    CHECK(srv_req_count(s) >= 4);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_retry_keepalive_connection_count) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: Basic realm=\"ka\"\r\n"; g.accept[0] = a_basic("k", "a");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "k", "a");
    for (int i = 0; i < 3; i++) { areq q = {0}; char p[32]; snprintf(p, sizeof p, "/rt/ka/%d", i); q.path = p; ares r; a_send(hc, &q, &r, 0); CHECKF(r.status == 200, "req %d", i); }
    a_dump(s);
    /* 401 + retry, then two pre-emptive requests: one keep-alive connection for all of it */
    EXPECT_EQ(srv_req_count(s), 4);
    EXPECT_EQ(srv_conn_count(s), 1);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}
