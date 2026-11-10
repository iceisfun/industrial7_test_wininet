/* http_auth: authentication over HTTPS (schannel loopback server, SRV_CERT_LOCALHOST + IGNORE_UNKNOWN_CA) and the
 * status-callback view of an authenticated exchange. */
#include "auth.h"

#define CH_BASIC "WWW-Authenticate: Basic realm=\"i7tls\"\r\n"

static void tls_send(srv *s, const char *user, const char *pass, const char *path, ares *r) {
    memset(r, 0, sizeof *r);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), user, pass, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0) : NULL;
    if (hr) {
        t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
        r->ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); r->err = r->ok ? 0 : GetLastError();
        r->status = a_status(hr);
        if (r->ok) r->n = t_inet_read_all(hr, r->body, sizeof r->body, NULL);
    } else r->err = GetLastError();
    a_close(hr); a_close(hc); t_inet_close(hi);
}

TEST(auth_https_basic_retry) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("tlsuser", "tlspass");
    srv *s = gate_start_kind(&g, SRV_HTTPS); SRV_OR_SKIP(s);
    ares r; tls_send(s, "tlsuser", "tlspass", "/tls", &r);
    a_dump(s);
    t_note("https basic: ok=%d err=%lu status=%lu", r.ok, r.err, r.status);
    CHECKF(r.ok, "err=%lu %s", r.err, t_inet_errname(r.err));
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "ok");
    EXPECT_EQ(srv_req_count(s), 2);
    if (srv_req_count(s) >= 2) { CHECK(REQ_AUTH(s, 0) == NULL); EXPECT_STR(REQ_AUTH(s, 1), a_basic("tlsuser", "tlspass")); }
    srv_stop(s);
}

TEST(auth_https_basic_no_creds_401) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = "never";
    srv *s = gate_start_kind(&g, SRV_HTTPS); SRV_OR_SKIP(s);
    ares r; tls_send(s, NULL, NULL, "/tls", &r);
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, 401); EXPECT_STR(r.body, "denied");
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

static int dig_verify(gate *g, srv *s, int ri, const char *hv) {
    char n[128], uri[256], resp[64], nc[16] = "", cn[128] = "", qop[16] = "", want[33];
    if (_strnicmp(hv, "Digest ", 7) || !a_param(hv, "nonce", n, sizeof n) || !a_param(hv, "uri", uri, sizeof uri) || !a_param(hv, "response", resp, sizeof resp)) return 0;
    a_param(hv, "nc", nc, sizeof nc); a_param(hv, "cnonce", cn, sizeof cn); a_param(hv, "qop", qop, sizeof qop);
    a_digest_response(g->user, g->realm, g->pass, srv_req_method(s, ri), uri, n, nc, cn, qop, 0, want);
    return !strcmp(want, resp);
}
TEST(auth_https_digest) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: Digest realm=\"i7tls\", qop=\"auth\", nonce=\"tlsnonce01\"\r\n"; g.verify = dig_verify;
    g.user = "du"; g.pass = "dp"; g.realm = "i7tls"; g.nonce = "tlsnonce01";
    srv *s = gate_start_kind(&g, SRV_HTTPS); SRV_OR_SKIP(s);
    ares r; tls_send(s, "du", "dp", "/tlsdigest", &r);
    a_dump(s);
    t_note("https digest: ok=%d err=%lu status=%lu", r.ok, r.err, r.status);
    EXPECT_EQ(r.status, 200);
    srv_stop(s);
}

TEST(auth_https_ntlm_custom_gate) {
    REQUIRE(U(HttpSendRequestA));
    gate g = {0}; g.challenge = "WWW-Authenticate: NTLM\r\n"; g.ntlm_mode = 1; g.pass = "tlsntlm";
    srv *s = gate_start_kind(&g, SRV_HTTPS); SRV_OR_SKIP(s);
    ares r; tls_send(s, "i7tlsuser", "tlsntlm", "/tlsntlm", &r);
    a_dump(s);
    t_note("https ntlm: status=%lu v2ok=%d user=[%s]", r.status, g.ntlm_v2_ok, g.ntlm_user);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(g.ntlm_v2_ok, 1);
    srv_stop(s);
}

/* ------------------------------------------------------------------ status callbacks */
#define MAXCB 128
static DWORD g_cb[MAXCB]; static volatile LONG g_ncb;
static void CALLBACK cbfn(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    LONG i = InterlockedIncrement(&g_ncb) - 1; if (i < MAXCB) g_cb[i] = st;
}
static int count_cb(DWORD st) { int k = 0; for (LONG i = 0; i < g_ncb && i < MAXCB; i++) if (g_cb[i] == st) k++; return k; }

TEST(auth_callback_sequence_basic_retry) {
    REQUIRE(U(InternetSetStatusCallbackA));
    gate g = {0}; g.challenge = CH_BASIC; g.accept[0] = a_basic("cb", "cbp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    g_ncb = 0;
    HINTERNET hi = t_inet_open(NULL);
    U(InternetSetStatusCallbackA)(hi, cbfn);
    HINTERNET hc = a_connect(hi, s, "cb", "cbp");
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/cb", NULL, NULL, NULL, T_INET_FRESH, 1);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    EXPECT_EQ(a_status(hr), 200);
    char line[512] = ""; size_t o = 0;
    for (LONG i = 0; i < g_ncb && i < MAXCB && o + 8 < sizeof line; i++) o += snprintf(line + o, sizeof line - o, "%lu ", g_cb[i]);
    t_note("callbacks: %s", line);
    EXPECT_EQ(count_cb(INTERNET_STATUS_SENDING_REQUEST), 2);
    EXPECT_EQ(count_cb(INTERNET_STATUS_REQUEST_SENT), 2);
    EXPECT_EQ(count_cb(INTERNET_STATUS_RESPONSE_RECEIVED), 2);
    EXPECT_EQ(count_cb(INTERNET_STATUS_CONNECTED_TO_SERVER), 1);
    a_close(hr); a_close(hc);
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi); srv_stop(s);
}
