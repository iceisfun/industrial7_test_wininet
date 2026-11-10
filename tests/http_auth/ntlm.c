/* http_auth: NTLM and Negotiate.
 * Two servers:
 *  - the gate in NTLM mode (auth_util.c): a hand-written NTLM server with a fixed challenge that verifies the
 *    client's NTLMv2 response (NTProofStr) against a known password. Independent of local accounts and policy.
 *  - SRV_AUTH_SSPI (common/srv_http.c): AcceptSecurityContext against the local SAM (real Windows server side).
 * Token bytes are never compared except the fixed NTLMSSP header fields and what the verifier proves. */
#include "auth.h"
#include <stdlib.h>

static unsigned g16(const unsigned char *p) { return p[0] | p[1] << 8; }
static unsigned g32(const unsigned char *p) { return g16(p) | g16(p + 2) << 16; }

static unsigned char *tok_of(const char *hv, const char *scheme, size_t *n) {
    size_t sl = strlen(scheme);
    if (!hv || _strnicmp(hv, scheme, sl) || hv[sl] != ' ') return NULL;
    return srv_unb64(hv + sl + 1, n);
}

static void ngate(gate *g, const char *pass) {
    memset(g, 0, sizeof *g); g->challenge = "WWW-Authenticate: NTLM\r\n"; g->ntlm_mode = 1; g->pass = pass;
}

TEST(auth_ntlm_explicit_creds_v2_verified) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "i7-Secret1");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/ntlm"; q.cuser = "i7user"; q.cpass = "i7-Secret1"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("ntlm: status=%lu requests=%d user=[%s] domain=[%s] ws=[%s] v2ok=%d type1 flags=0x%08x", r.status, srv_req_count(s),
           g.ntlm_user, g.ntlm_domain, g.ntlm_ws, g.ntlm_v2_ok, g.ntlm_type1_flags);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(r.body, "ok");
    EXPECT_EQ(srv_req_count(s), 3);
    CHECK(REQ_AUTH(s, 0) == NULL);
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    EXPECT_STR(g.ntlm_user, "i7user");
    /* all three legs on one connection (NTLM is connection-oriented) */
    if (srv_req_count(s) >= 3) { EXPECT_EQ(srv_req_conn(s, 0), srv_req_conn(s, 1)); EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 2)); }
    srv_stop(s);
}

TEST(auth_ntlm_type1_structure) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    CHECK(srv_req_count(s) >= 2);
    size_t n = 0; unsigned char *t = srv_req_count(s) >= 2 ? tok_of(REQ_AUTH(s, 1), "NTLM", &n) : NULL;
    CHECK(t != NULL);
    if (t) {
        CHECK(n >= 32);
        CHECK(!memcmp(t, "NTLMSSP\0", 8));
        EXPECT_EQ(g32(t + 8), 1);
        unsigned fl = g32(t + 12);
        t_note("type1: %zu bytes flags=0x%08x", n, fl);
        EXPECT_EQ(n, 40); EXPECT_EQ(fl, 0xa2088207u);   /* Win10 VM, explicit credentials */
        CHECK(fl & 0x00000001);   /* NEGOTIATE_UNICODE */
        CHECK(fl & 0x00000200);   /* NEGOTIATE_NTLM */
        CHECK(fl & 0x00000004);   /* REQUEST_TARGET */
        CHECK(fl & 0x00080000);   /* EXTENDED_SESSIONSECURITY */
        if (n >= 40 && (fl & 0x02000000)) t_note("type1 version %u.%u build %u rev %u", t[32], t[33], g16(t + 34), t[39]);
        free(t);
    }
    EXPECT_STR(REQ_AUTH(s, 1) ? "x" : NULL, "x");
    if (srv_req_count(s) >= 2) CHECK(!strncmp(REQ_AUTH(s, 1), "NTLM TlRMTVNTUAAB", 17));
    srv_stop(s);
}

TEST(auth_ntlm_type3_structure) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    CHECK(srv_req_count(s) >= 3);
    if (srv_req_count(s) >= 3) {
        CHECK(!strncmp(REQ_AUTH(s, 2), "NTLM TlRMTVNTUAAD", 17));
        size_t n; unsigned char *t = tok_of(REQ_AUTH(s, 2), "NTLM", &n);
        CHECK(t && n >= 64);
        if (t && n >= 64) {
            EXPECT_EQ(g32(t + 8), 3);
            unsigned lml = g16(t + 12), ntl = g16(t + 20), fl = g32(t + 60);
            t_note("type3: %zu bytes lm=%u nt=%u flags=0x%08x domain=[%s] ws=[%s]", n, lml, ntl, fl, g.ntlm_domain, g.ntlm_ws);
            CHECK(ntl > 24);                  /* NTLMv2 response (16-byte proof + blob) */
            EXPECT_EQ(lml, 24);               /* Win10 VM */
            EXPECT_EQ(fl, 0xa2888205u);       /* Win10 VM, answering NTLM_T2_FLAGS 0xE2898215 */
            char cn[64]; DWORD cl = sizeof cn; if (GetComputerNameA(cn, &cl)) { EXPECT_STR(g.ntlm_domain, cn); EXPECT_STR(g.ntlm_ws, cn); }
            CHECK(fl & 0x00000001);           /* unicode strings */
            /* blob: 0x0101 0000, reserved, timestamp, client challenge */
            unsigned nto = g32(t + 24);
            if (nto + 28 <= n) { EXPECT_EQ(t[nto + 16], 1); EXPECT_EQ(t[nto + 17], 1); }
        }
        free(t);
    }
    srv_stop(s);
}

TEST(auth_ntlm_domain_backslash_user) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "I7DOMAIN\\i7user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    t_note("DOMAIN\\user: status=%lu user=[%s] domain=[%s] v2ok=%d", r.status, g.ntlm_user, g.ntlm_domain, g.ntlm_v2_ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(g.ntlm_user, "i7user");
    EXPECT_STR(g.ntlm_domain, "I7DOMAIN");
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    srv_stop(s);
}

TEST(auth_ntlm_upn_user) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7user@i7dom.test"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    t_note("UPN user: status=%lu user=[%s] domain=[%s] v2ok=%d", r.status, g.ntlm_user, g.ntlm_domain, g.ntlm_v2_ok);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(g.ntlm_user, "i7user@i7dom.test"); EXPECT_STR(g.ntlm_domain, "");   /* Win10 VM */
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    srv_stop(s);
}

TEST(auth_ntlm_wrong_password_final_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "right");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7user"; q.cpass = "wrong"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("ntlm wrong password: ok=%d err=%lu status=%lu requests=%d", r.ok, r.err, r.status, srv_req_count(s));
    CHECK(r.ok);
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(g.n_ok, 0);
    EXPECT_EQ(g.ntlm_v2_ok, 0);
    CHECK(srv_req_count(s) >= 3 && srv_req_count(s) <= 8);
    srv_stop(s);
}

TEST(auth_ntlm_request_option_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "optpw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.ruser = "optuser"; q.rpass = "optpw"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(g.ntlm_user, "optuser");
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    srv_stop(s);
}

TEST(auth_ntlm_no_auth_flag) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7user"; q.cpass = "pw"; q.flags = T_INET_FRESH | INTERNET_FLAG_NO_AUTH; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_ntlm_post_body) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.verb = "POST"; q.cuser = "i7user"; q.cpass = "pw"; q.body = "0123456789"; q.body_len = 10; ares r; a_once(s, &q, &r);
    a_dump(s);
    EXPECT_EQ(r.status, 200);
    int n = srv_req_count(s);
    for (int i = 0; i < n; i++) {
        size_t bl = 0; const char *b = srv_req_body(s, i, &bl);
        t_note("ntlm POST leg %d: Content-Length=%s body=%zu", i, srv_req_header(s, i, "Content-Length") ? srv_req_header(s, i, "Content-Length") : "(none)", b ? bl : 0);
    }
    if (n >= 1) { size_t bl; const char *b = srv_req_body(s, n - 1, &bl); CHECK(b && bl == 10 && !memcmp(b, "0123456789", 10)); }
    /* Win10 VM: the type-1 leg is sent with Content-Length: 0 and no body; the anonymous and type-3 legs carry it */
    EXPECT_EQ(n, 3);
    if (n == 3) { EXPECT_STR(srv_req_header(s, 0, "Content-Length"), "10"); EXPECT_STR(srv_req_header(s, 1, "Content-Length"), "0"); EXPECT_STR(srv_req_header(s, 2, "Content-Length"), "10"); }
    srv_stop(s);
}

TEST(auth_ntlm_second_request_same_connection) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "i7user", "pw");
    areq q = {0}; q.path = "/n1"; ares r; a_send(hc, &q, &r, 0);
    EXPECT_EQ(r.status, 200);
    int before = srv_req_count(s);
    q.path = "/n2"; a_send(hc, &q, &r, 0);
    a_dump(s);
    t_note("second NTLM request: status=%lu, %d more requests, first auth=%.20s", r.status, srv_req_count(s) - before,
           REQ_AUTH(s, before) ? REQ_AUTH(s, before) : "(none)");
    EXPECT_EQ(r.status, 200);
    /* Win10 VM: the second request starts anonymously again and runs the full handshake on the same connection */
    EXPECT_EQ(srv_req_count(s) - before, 3);
    CHECK(REQ_AUTH(s, before) == NULL);
    if (srv_req_count(s) >= before + 3) { EXPECT_EQ(srv_req_conn(s, before), srv_req_conn(s, 0)); CHECK(!strncmp(REQ_AUTH(s, before + 1), "NTLM TlRMTVNTUAAB", 17)); }
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ntlm_challenge_queryable_without_creds) {
    REQUIRE(U(HttpSendRequestA));
    gate g; ngate(&g, "pw");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, NULL, NULL);
    areq q = {0}; ares r; a_send(hc, &q, &r, 1);
    a_dump(s);
    t_note("NTLM challenge, no explicit creds: status=%lu requests=%d (default-credential policy decides)", r.status, srv_req_count(s));
    EXPECT_EQ(r.status, 401); EXPECT_EQ(srv_req_count(s), 1);   /* 127.0.0.1: no automatic logon (Win10 VM) */
    char b[128]; DWORD idx = 0;
    if (r.status == 401) { CHECK(a_query(r.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx, b, sizeof b)); }
    a_close(r.hr); a_close(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ real SSPI server side (local SAM) */
TEST(auth_ntlm_sspi_server_unknown_account) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_AUTH("NTLM"), S_REPLY(200, NULL, "ntlm-ok"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7nouser"; q.cpass = "i7-not-a-password"; ares r; a_once(s, &q, &r);
    a_dump(s);
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_AUTH) t_note("sspi: %s", ev[i].data);
    CHECK(r.ok); EXPECT_EQ(r.status, 401);
    EXPECT_EQ(srv_req_count(s), 3);
    if (srv_req_count(s) >= 3) {
        CHECK(REQ_AUTH(s, 0) == NULL);
        CHECK(!strncmp(REQ_AUTH(s, 1), "NTLM TlRMTVNTUAAB", 17));
        CHECK(!strncmp(REQ_AUTH(s, 2), "NTLM TlRMTVNTUAAD", 17));
    }
    srv_stop(s);
}

TEST(auth_ntlm_sspi_server_default_creds_localhost) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_AUTH("NTLM"), S_REPLY(200, NULL, "ntlm-ok"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "localhost", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    areq q = {0}; ares r; a_send(hc, &q, &r, 0);
    a_dump(s);
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_AUTH) t_note("sspi (localhost, default creds): %s", ev[i].data);
    t_note("localhost default creds: ok=%d status=%lu body=%s requests=%d", r.ok, r.status, r.body, srv_req_count(s));
    CHECK(r.ok);
    /* Win10 VM (default zones): "localhost" is Local Intranet -> automatic logon with the process token */
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "ntlm-ok"); EXPECT_EQ(srv_req_count(s), 3);
    EXPECT_EQ(srv_count_events(s, SRV_EV_AUTH), 1);
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_AUTH) CHECKF(!strncmp(ev[i].data, "ok ", 3), "%s", ev[i].data);
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_ntlm_sspi_server_default_creds_ip) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_AUTH("NTLM"), S_REPLY(200, NULL, "ntlm-ok"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    areq q = {0}; ares r; a_once(s, &q, &r);
    a_dump(s);
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_AUTH) t_note("sspi (127.0.0.1, default creds): %s", ev[i].data);
    t_note("127.0.0.1 default creds: ok=%d status=%lu requests=%d", r.ok, r.status, srv_req_count(s));
    CHECK(r.ok);
    /* Win10 VM (default zones): 127.0.0.1 is not Local Intranet -> no automatic logon, the 401 goes to the caller */
    EXPECT_EQ(r.status, 401); EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(auth_negotiate_sspi_server_first_token) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_AUTH("Negotiate"), S_REPLY(200, NULL, "nego-ok"), S_LOOP() };
    srv *s = srv_http(st, 3); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7nouser"; q.cpass = "i7-not-a-password"; ares r; a_once(s, &q, &r);
    a_dump(s);
    const srv_event *ev; int ne = srv_events(s, &ev);
    for (int i = 0; i < ne; i++) if (ev[i].kind == SRV_EV_AUTH) t_note("sspi negotiate: %s", ev[i].data);
    t_note("negotiate: ok=%d status=%lu requests=%d", r.ok, r.status, srv_req_count(s));
    CHECK(r.ok); EXPECT_EQ(r.status, 401);   /* unknown account rejected by the local SAM */
    EXPECT_EQ(srv_req_count(s), 3);
    CHECK(REQ_AUTH(s, 0) == NULL);
    if (srv_req_count(s) >= 2) {
        const char *a = REQ_AUTH(s, 1);
        CHECK(a && !strncmp(a, "Negotiate ", 10));
        size_t n; unsigned char *t = tok_of(a, "Negotiate", &n);
        CHECK(t && n > 16);
        if (t) {
            t_note("negotiate token[0]=0x%02x len=%zu ntlmssp=%d", t[0], n, n >= 8 && !memcmp(t, "NTLMSSP\0", 8));
            CHECK(t[0] == 0x60 || !memcmp(t, "NTLMSSP\0", 8));   /* SPNEGO NegTokenInit or raw NTLM */
        }
        free(t);
    }
    srv_stop(s);
}

TEST(auth_negotiate_challenge_with_custom_ntlm_gate_scheme_choice) {
    REQUIRE(U(HttpSendRequestA));
    /* server offers Negotiate and NTLM; record which scheme the client starts with */
    gate g; ngate(&g, "pw"); g.challenge = "WWW-Authenticate: Negotiate\r\nWWW-Authenticate: NTLM\r\n";
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = "i7user"; q.cpass = "pw"; ares r; a_once(s, &q, &r);
    a_dump(s);
    const char *a = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    t_note("Negotiate+NTLM offered: status=%lu first scheme=%.12s", r.status, a ? a : "(none)");
    CHECK(r.ok);
    /* Win10 VM: Negotiate is preferred; on a workgroup machine with explicit creds the token is a raw NTLMSSP type 1 */
    CHECK(a && !strncmp(a, "Negotiate TlRMTVNTUAAB", 22));
    EXPECT_EQ(r.status, 401);   /* the custom gate only verifies the NTLM scheme */
    srv_stop(s);
}
