/* http_auth: Digest authentication (RFC 2617 / 2069). The gate recomputes the response from the known password,
 * and the tests recompute it again from the recorded Authorization header, so every 200 is a verified MD5 chain. */
#include "auth.h"
#include <stdlib.h>

#define D_NONCE  "dcd98b7102dd2f0e8b11d0f600bfb0c093"
#define D_OPAQUE "5ccc069c403ebaf9f0171e9517f40e41"

/* verify callback: accept a Digest header whose response matches g->pass for the current nonce */
int digest_verify(gate *g, srv *s, int ri, const char *hv) {
    if (_strnicmp(hv, "Digest ", 7)) return 0;
    char user[128], realm[128], nonce[128], uri[512], resp[64], qop[32] = "", nc[32] = "", cnonce[128] = "", alg[32] = "";
    if (!a_param(hv, "username", user, sizeof user) || !a_param(hv, "realm", realm, sizeof realm) || !a_param(hv, "nonce", nonce, sizeof nonce) ||
        !a_param(hv, "uri", uri, sizeof uri) || !a_param(hv, "response", resp, sizeof resp)) return 0;
    a_param(hv, "qop", qop, sizeof qop); a_param(hv, "nc", nc, sizeof nc); a_param(hv, "cnonce", cnonce, sizeof cnonce); a_param(hv, "algorithm", alg, sizeof alg);
    if (strcmp(user, g->user) || strcmp(realm, g->realm) || strcmp(nonce, g->nonce)) return 0;
    char want[33]; a_digest_response(g->user, g->realm, g->pass, srv_req_method(s, ri), uri, nonce, nc, cnonce, qop, g->sess, want);
    return !strcmp(want, resp);
}

/* check the recorded header of request i: recompute the response with method/uri as sent */
int digest_check_recorded(srv *s, int i, const char *user, const char *realm, const char *pass, int sess, const char *want_qop) {
    const char *hv = REQ_AUTH(s, i);
    if (!hv) { CHECKF(0, "req %d: no Authorization", i); return 0; }
    CHECKF(!strncmp(hv, "Digest ", 7), "req %d: scheme %.20s", i, hv);
    char u[128] = "", r[128] = "", n[128] = "", uri[512] = "", resp[64] = "", qop[32] = "", nc[32] = "", cn[128] = "";
    CHECK(a_param(hv, "username", u, sizeof u)); EXPECT_STR(u, user);
    CHECK(a_param(hv, "realm", r, sizeof r));    EXPECT_STR(r, realm);
    CHECK(a_param(hv, "nonce", n, sizeof n));
    CHECK(a_param(hv, "uri", uri, sizeof uri));  EXPECT_STR(uri, srv_req_target(s, i));
    CHECK(a_param(hv, "response", resp, sizeof resp)); EXPECT_EQ(strlen(resp), 32);
    int hq = a_param(hv, "qop", qop, sizeof qop);
    if (want_qop) { CHECK(hq); EXPECT_STR(qop, want_qop); CHECK(a_param(hv, "nc", nc, sizeof nc)); EXPECT_EQ(strlen(nc), 8); CHECK(a_param(hv, "cnonce", cn, sizeof cn)); CHECK(cn[0] != 0); }
    else { CHECK(!hq); }
    char want[33]; a_digest_response(user, realm, pass, srv_req_method(s, i), uri, n, nc, cn, qop, sess, want);
    EXPECT_STR(resp, want);
    return !strcmp(resp, want);
}

void dgate(gate *g, const char *challenge, const char *user, const char *pass) {
    memset(g, 0, sizeof *g); g->challenge = challenge; g->verify = digest_verify; g->user = user; g->pass = pass; g->realm = "i7digest"; g->nonce = D_NONCE;
}

#define CH_DIGEST_AUTH "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"" D_NONCE "\", opaque=\"" D_OPAQUE "\"\r\n"

TEST(auth_digest_qop_auth_md5) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "Mufasa", "Circle Of Life");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/dir/index.html"; q.cuser = "Mufasa"; q.cpass = "Circle Of Life"; ares r; a_once(s, &q, &r);
    a_dump(s);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "ok");
    EXPECT_EQ(srv_req_count(s), 2);
    CHECK(REQ_AUTH(s, 0) == NULL);
    if (srv_req_count(s) >= 2) {
        digest_check_recorded(s, 1, "Mufasa", "i7digest", "Circle Of Life", 0, "auth");
        const char *hv = REQ_AUTH(s, 1); char v[128];
        CHECK(a_param(hv, "nonce", v, sizeof v)); EXPECT_STR(v, D_NONCE);
        CHECK(a_param(hv, "opaque", v, sizeof v)); EXPECT_STR(v, D_OPAQUE);
        CHECK(a_param(hv, "nc", v, sizeof v)); EXPECT_STR(v, "00000001");
        if (a_param(hv, "algorithm", v, sizeof v)) t_note("algorithm echoed: %s", v); else t_note("algorithm not echoed");
        t_note("digest header (%d params): %s", a_param_count(hv), hv);
    }
    EXPECT_EQ(g.n_ok, 1);
    srv_stop(s);
}

TEST(auth_digest_header_param_order_and_quoting) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/o"; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    const char *hv = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    CHECK(hv != NULL);
    if (hv) {
        t_note("digest header: %s", hv);
        CHECK(strstr(hv, "username=\"user\"") != NULL);
        CHECK(strstr(hv, "realm=\"i7digest\"") != NULL);
        CHECK(strstr(hv, "nonce=\"" D_NONCE "\"") != NULL);
        CHECK(strstr(hv, "uri=\"/o\"") != NULL);
        CHECK(strstr(hv, "nc=00000001") != NULL);      /* nc is unquoted (RFC 2617) */
        const char *u = strstr(hv, "username="), *re = strstr(hv, "response=");
        CHECK(u && re && u < re);
    }
    srv_stop(s);
}

TEST(auth_digest_rfc2069_no_qop) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"" D_NONCE "\"\r\n", "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/2069"; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) {
        digest_check_recorded(s, 1, "user", "i7digest", "pw", 0, NULL);
        char v[64]; CHECK(!a_param(REQ_AUTH(s, 1), "nc", v, sizeof v)); CHECK(!a_param(REQ_AUTH(s, 1), "cnonce", v, sizeof v));
    }
    srv_stop(s);
}

TEST(auth_digest_md5_sess) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", algorithm=MD5-sess, nonce=\"" D_NONCE "\"\r\n", "user", "pw"); g.sess = 1;
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/sess"; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("MD5-sess: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 200);
    if (srv_req_count(s) >= 2) {
        digest_check_recorded(s, 1, "user", "i7digest", "pw", 1, "auth");
        char v[32]; CHECK(a_param(REQ_AUTH(s, 1), "algorithm", v, sizeof v)); EXPECT_STR(v, "MD5-sess");
    }
    srv_stop(s);
}

TEST(auth_digest_algorithm_md5_explicit) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", algorithm=MD5, nonce=\"" D_NONCE "\"\r\n", "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    if (srv_req_count(s) >= 2) {
        digest_check_recorded(s, 1, "user", "i7digest", "pw", 0, "auth");
        char v[32]; CHECK(a_param(REQ_AUTH(s, 1), "algorithm", v, sizeof v)); EXPECT_STR(v, "MD5");
    }
    srv_stop(s);
}

TEST(auth_digest_qop_list_picks_auth) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth,auth-int\", nonce=\"" D_NONCE "\"\r\n", "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    if (srv_req_count(s) >= 2) digest_check_recorded(s, 1, "user", "i7digest", "pw", 0, "auth");
    srv_stop(s);
}

TEST(auth_digest_uri_with_query) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/q/p?a=1&b=two"; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    if (srv_req_count(s) >= 2) { digest_check_recorded(s, 1, "user", "i7digest", "pw", 0, "auth"); EXPECT_STR(srv_req_target(s, 1), "/q/p?a=1&b=two"); }
    srv_stop(s);
}

TEST(auth_digest_post_method_in_ha2) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.verb = "POST"; q.path = "/post"; q.cuser = "user"; q.cpass = "pw"; q.body = "payload"; q.body_len = 7; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    if (srv_req_count(s) >= 2) {
        digest_check_recorded(s, 1, "user", "i7digest", "pw", 0, "auth");
        size_t bl; const char *b = srv_req_body(s, 1, &bl); CHECK(b && bl == 7 && !memcmp(b, "payload", 7));
    }
    srv_stop(s);
}

TEST(auth_digest_request_option_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "opt", "secret");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.ruser = "opt"; q.rpass = "secret"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    if (srv_req_count(s) >= 2) digest_check_recorded(s, 1, "opt", "i7digest", "secret", 0, "auth");
    srv_stop(s);
}

TEST(auth_digest_no_creds_returns_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; ares r; a_once(s, &q, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 401); EXPECT_STR(r.body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_digest_wrong_password_final_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "wrong"; ares r; a_once(s, &q, &r);
    a_dump(s);
    CHECK(r.ok); EXPECT_EQ(r.status, 401);
    t_note("digest wrong password: %d requests", srv_req_count(s));
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) digest_check_recorded(s, 1, "user", "i7digest", "wrong", 0, "auth");
    EXPECT_EQ(g.n_ok, 0);
    srv_stop(s);
}

TEST(auth_digest_no_auth_flag) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; q.flags = T_INET_FRESH | INTERNET_FLAG_NO_AUTH; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 401); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_digest_second_request_nonce_count) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, CH_DIGEST_AUTH, "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "user", "pw");
    areq q = {0}; q.path = "/nc/a"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    q.path = "/nc/b"; a_send(hc, &q, &r, 0);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    int n = srv_req_count(s);
    const char *hv = REQ_AUTH(s, before); char nc[16] = "";
    t_note("second digest request: %d more requests; first carries %s", n - before, hv ? hv : "(none)");
    EXPECT_EQ(n - before, 1);   /* Win10 VM: pre-emptive Digest on the second request */
    CHECK(hv && a_param(hv, "nc", nc, sizeof nc)); EXPECT_STR(nc, "00000002");
    if (hv && a_param(hv, "nc", nc, sizeof nc)) {
        digest_check_recorded(s, before, "user", "i7digest", "pw", 0, "auth");
    }
    digest_check_recorded(s, n - 1, "user", "i7digest", "pw", 0, "auth");
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* stale=true: the server rotates the nonce; the client must answer the new nonce without asking for credentials */
static volatile LONG g_stale_n;
static int stale_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int it = 0; it < 16; it++) {
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        LONG k = InterlockedIncrement(&g_stale_n);
        const char *hv = srv_req_header(s, ri, "Authorization");
        char n[128] = "", resp[64] = "", uri[256] = "", nc[16] = "", cn[128] = "", qop[16] = "";
        int ok = 0;
        if (hv && a_param(hv, "nonce", n, sizeof n) && a_param(hv, "response", resp, sizeof resp) && a_param(hv, "uri", uri, sizeof uri)) {
            a_param(hv, "nc", nc, sizeof nc); a_param(hv, "cnonce", cn, sizeof cn); a_param(hv, "qop", qop, sizeof qop);
            char want[33]; a_digest_response("user", "i7digest", "pw", srv_req_method(s, ri), uri, n, nc, cn, qop, 0, want);
            ok = !strcmp(want, resp) && !strcmp(n, "nonce2");
        }
        if (ok) srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        else if (hv) srv_conn_sendf(c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"nonce2\", stale=true\r\nContent-Length: 0\r\n\r\n");
        else srv_conn_sendf(c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"nonce1\"\r\nContent-Length: 0\r\n\r\n");
    }
    return -1;
}
TEST(auth_digest_stale_nonce_retry) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_CALL(stale_fn) }; static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s; START_OR_SKIP(&cfg, &s);
    areq q = {0}; q.path = "/stale"; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("stale nonce: status=%lu requests=%d", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(srv_req_count(s), 3);
    char n[32];
    if (srv_req_count(s) >= 3) {
        CHECK(a_param(REQ_AUTH(s, 1), "nonce", n, sizeof n)); EXPECT_STR(n, "nonce1");
        CHECK(a_param(REQ_AUTH(s, 2), "nonce", n, sizeof n)); EXPECT_STR(n, "nonce2");
        digest_check_recorded(s, 2, "user", "i7digest", "pw", 0, "auth");
    }
    srv_stop(s);
}

TEST(auth_digest_and_basic_offered) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Basic realm=\"i7digest\"\r\nWWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"" D_NONCE "\"\r\n", "user", "pw");
    g.accept[0] = a_basic("user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    const char *hv = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    t_note("Basic listed first, Digest second -> client chose %.10s", hv ? hv : "(none)");
    CHECK(hv && !strncmp(hv, "Digest ", 7));   /* Win10 VM: Digest preferred over Basic regardless of order */
    srv_stop(s);
}

TEST(auth_digest_then_basic_offered) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", nonce=\"" D_NONCE "\"\r\nWWW-Authenticate: Basic realm=\"i7digest\"\r\n", "user", "pw");
    g.accept[0] = a_basic("user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    const char *hv = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    t_note("Digest listed first, Basic second -> client chose %.10s", hv ? hv : "(none)");
    CHECK(hv && !strncmp(hv, "Digest ", 7));
    srv_stop(s);
}

TEST(auth_digest_unsupported_algorithm) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\", algorithm=SHA-512-256, nonce=\"" D_NONCE "\"\r\n", "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("unsupported digest algorithm: ok=%d err=%lu status=%lu requests=%d", r.ok, r.err, r.status, srv_req_count(s));
    /* Win10 VM: the request is re-sent once without any Authorization, then the 401 goes to the caller */
    CHECK(r.ok); EXPECT_EQ(r.status, 401); EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) == 2) CHECK(REQ_AUTH(s, 1) == NULL);
    srv_stop(s);
}

TEST(auth_digest_missing_nonce) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", qop=\"auth\"\r\n", "user", "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("digest without nonce: ok=%d err=%lu status=%lu requests=%d", r.ok, r.err, r.status, srv_req_count(s));
    CHECK(r.ok); EXPECT_EQ(r.status, 401); EXPECT_EQ(srv_req_count(s), 2);   /* Win10 VM, as for an unknown algorithm */
    if (srv_req_count(s) == 2) CHECK(REQ_AUTH(s, 1) == NULL);
    srv_stop(s);
}

/* table of user/password/realm combos, each verified end to end */
typedef struct { const char *user, *pass, *realm_hdr, *realm; } drow;
static const drow g_drows[] = {
    { "u", "p", "r", "r" },
    { "user name", "pass word", "realm with spaces", "realm with spaces" },
    { "user@host", "p:a:s:s", "testrealm@host.com", "testrealm@host.com" },
    { "DOM\\\\user", "x", "i7", "i7" },
    { "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef", "long-realm-0123456789", "long-realm-0123456789" },
};
TEST(auth_digest_cred_table) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof g_drows / sizeof g_drows[0]; i++) {
        const drow *d = &g_drows[i];
        char user_plain[64]; { const char *p = d->user; size_t k = 0; while (*p && k + 1 < sizeof user_plain) { if (p[0] == '\\' && p[1] == '\\') p++; user_plain[k++] = *p++; } user_plain[k] = 0; }
        char ch[512]; snprintf(ch, sizeof ch, "WWW-Authenticate: Digest realm=\"%s\", qop=\"auth\", nonce=\"" D_NONCE "\"\r\n", d->realm_hdr);
        gate g; dgate(&g, ch, user_plain, d->pass); g.realm = d->realm;
        srv *s = gate_start(&g); if (!s) { t_skip("server unavailable"); return; }
        areq q = {0}; q.cuser = user_plain; q.cpass = d->pass; ares r; a_once(s, &q, &r);
        CHECKF(r.status == 200, "row %zu (%s): status %lu", i, user_plain, r.status);
        if (srv_req_count(s) >= 2) {
            const char *hv = REQ_AUTH(s, 1); char u[128] = "";
            a_param(hv, "username", u, sizeof u);
            t_note("row %zu username param=[%s] header=%.120s", i, u, hv ? hv : "");
        }
        srv_stop(s);
    }
}
