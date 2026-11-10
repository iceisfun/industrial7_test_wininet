/* tls_wire.c - what the client puts on the wire during the handshake, and how it reacts to broken servers.
 *  - ClientHello facts from a raw observer (th_*): record/legacy versions, SNI, ALPN, extensions;
 *  - INTERNET_OPTION_ENABLE_HTTP_PROTOCOL (148) validation (decomp InternetSetOptionA case 0x94: len != 4 -> 12010,
 *    handle not session/connect/request -> 12018, bits outside 3 -> 87, stored value & ~1) and its ALPN effect
 *    (decomp SecureNegotiate_Fsm: ALPN "h2,http/1.1" only when the enabled protocols include TLS 1.2/1.3);
 *  - server protocol restrictions (SCH_CREDENTIALS) and the negotiated version;
 *  - broken servers: close, reset, alert, plaintext, garbage, truncated ServerHello.
 * Client protocol versions come from the per-user SecureProtocols value (GetSecureProtocolsSettings): the lab image
 * has 0x800 (TLS 1.2 only); the OS default is 0xA80. That value is read (never written) to pick expectations. */
#include "tls_util.h"

static DWORD client_secure_protocols(void) {
    static DWORD v = 0xFFFFFFFF;
    if (v != 0xFFFFFFFF) return v;
    DWORD d = 0, l = sizeof d, ty = 0; HKEY k;
    v = 0xA80;   /* OS default when no value is present (decomp: WxGetRegistryDwordWithPolicies default 0xA80) */
    if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &k)) {
        if (!RegQueryValueExA(k, "SecureProtocols", NULL, &ty, (BYTE *)&d, &l) && ty == REG_DWORD) { RegCloseKey(k); return v = d; }
        RegCloseKey(k);
    }
    l = sizeof d;
    if (!RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &k)) {
        if (!RegQueryValueExA(k, "SecureProtocols", NULL, &ty, (BYTE *)&d, &l) && ty == REG_DWORD) v = d;
        RegCloseKey(k);
    }
    return v;
}

/* one https request to the observer; returns the wininet error */
static DWORD hello_request(th_srv *t, const char *host, DWORD http_proto, int set_proto) {
    treq r; DWORD e;
    if (!treq_open(&r, host, th_port(t), "GET", "/h", T_INET_FRESH | INTERNET_FLAG_SECURE)) { e = GetLastError(); treq_close(&r); return e ? e : 1; }
    if (set_proto) U(InternetSetOptionA)(r.hi, INTERNET_OPTION_ENABLE_HTTP_PROTOCOL, &http_proto, sizeof http_proto);
    t_https_secflags(r.hr, SECURITY_SET_MASK);
    e = treq_send(&r);
    treq_close(&r);
    return e;
}
static void note_hello(const char *tag, const th_hello *h) {
    if (!h) { t_note("%s: no hello", tag); return; }
    char ex[512] = ""; size_t o = 0;
    for (int i = 0; i < h->nexts && o < sizeof ex - 8; i++) o += snprintf(ex + o, sizeof ex - o, "%s%u", i ? "," : "", h->exts[i]);
    char vs[128] = ""; o = 0;
    for (int i = 0; i < h->nver && o < sizeof vs - 8; i++) o += snprintf(vs + o, sizeof vs - o, "%s%04x", i ? "," : "", h->versions[i]);
    t_note("%s: complete=%d rec=%02x/%04x hs=%d ver=%04x ciphers=%d first=%04x sni=%s alpn=%s versions=%s exts=%s bytes=%u",
           tag, h->complete, h->rec_type, h->rec_ver, h->hs_type, h->client_ver, h->ncipher, h->ncipher ? h->ciphers[0] : 0,
           h->has_sni ? h->sni : "(none)", h->has_alpn ? h->alpn : "(none)", vs, ex, (unsigned)h->nbytes);
}

#define TH_START_OR_SKIP(t, r) th_srv *t = th_start(r); if (!t) { t_skip("winsock unavailable"); return; }

/* ------------------------------------------------------------------ ClientHello basics */
TEST(tls_hello_basic_shape) {
    REQUIRE(U(HttpSendRequestA));
    TH_START_OR_SKIP(t, TH_CLOSE);
    DWORD e = hello_request(t, "127.0.0.1", 0, 0);
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0);
    note_hello("127.0.0.1", h);
    t_note("request error=%lu %s, connections=%d", e, t_inet_errname(e), th_count(t));
    CHECK(h && h->complete);
    if (h) {
        EXPECT_EQ(h->rec_type, 0x16);
        EXPECT_EQ(h->hs_type, 1);
        EXPECT_EQ(h->client_ver, 0x0303);               /* TLS 1.2 legacy_version */
        CHECK(h->ncipher > 0);
        CHECK(h->has_sigalgs);
        CHECK(h->has_ems);
        CHECK(h->has_reneg_info);
        CHECK(th_has_ext(h, 10));                       /* supported_groups */
        CHECK(th_has_ext(h, 11));                       /* ec_point_formats */
        /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 offered */
        int has_c030 = 0; for (int i = 0; i < h->ncipher; i++) if (h->ciphers[i] == 0xC030) has_c030 = 1;
        CHECK(has_c030);
    }
    CHECK(e != 0);
    th_stop(t);
}

/* SNI: no server_name for an IP literal, the host name otherwise */
TEST(tls_hello_sni_ip_literal) {
    TH_START_OR_SKIP(t, TH_CLOSE);
    hello_request(t, "127.0.0.1", 0, 0);
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0); note_hello("ip", h);
    CHECK(h && h->complete && !h->has_sni);
    th_stop(t);
}

TEST(tls_hello_sni_localhost) {
    TH_START_OR_SKIP(t, TH_CLOSE);
    hello_request(t, "localhost", 0, 0);
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0); note_hello("localhost", h);
    CHECK(h && h->complete && h->has_sni);
    if (h) EXPECT_STR(h->sni, "localhost");
    th_stop(t);
}

TEST(tls_hello_sni_case_preserved) {
    TH_START_OR_SKIP(t, TH_CLOSE);
    hello_request(t, "LocalHost", 0, 0);
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0); note_hello("LocalHost", h);
    CHECK(h && h->has_sni);
    if (h && h->has_sni) { t_note("SNI for 'LocalHost' = %s", h->sni); CHECK(!_stricmp(h->sni, "localhost")); }
    th_stop(t);
}

TEST(tls_hello_sni_ipv6_literal) {
    TH_START_OR_SKIP(t, TH_CLOSE);
    /* the observer listens on v4 only: [::1] must fail to connect, nothing reaches it */
    DWORD e = hello_request(t, "[::1]", 0, 0);
    t_note("[::1] against a v4-only observer: err=%lu %s conns=%d", e, t_inet_errname(e), th_count(t));
    EXPECT_EQ(th_count(t), 0);
    CHECK(e != 0);
    th_stop(t);
}

/* ------------------------------------------------------------------ ALPN / ENABLE_HTTP_PROTOCOL */
TEST(tls_hello_alpn_default_absent) {
    TH_START_OR_SKIP(t, TH_CLOSE);
    hello_request(t, "localhost", 0, 0);
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0); note_hello("default", h);
    CHECK(h && h->complete);
    if (h) CHECK(!h->has_alpn);
    th_stop(t);
}

TEST(tls_hello_alpn_http2_enabled) {
    if (!(client_secure_protocols() & 0x2800)) { t_skip("SecureProtocols 0x%lx has neither TLS 1.2 nor 1.3", client_secure_protocols()); return; }
    TH_START_OR_SKIP(t, TH_CLOSE);
    hello_request(t, "localhost", HTTP_PROTOCOL_FLAG_HTTP2, 1);
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0); note_hello("http2", h);
    CHECK(h && h->complete && h->has_alpn);
    if (h && h->has_alpn) EXPECT_STR(h->alpn, "h2,http/1.1");
    th_stop(t);
}

TEST(tls_hello_alpn_flag1_ignored) {
    TH_START_OR_SKIP(t, TH_CLOSE);
    hello_request(t, "localhost", 1, 1);                 /* bit 0 is masked off by the setter */
    th_wait(t, 1, 3000);
    const th_hello *h = th_get(t, 0); note_hello("flag1", h);
    CHECK(h && h->complete);
    if (h) CHECK(!h->has_alpn);
    th_stop(t);
}

TEST(tls_enable_http_protocol_option_rules) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    HINTERNET hs[3] = { hi, hc, hr };
    static const char *nm[3] = { "session", "connect", "request" };
    for (int h = 0; h < 3; h++) {
        static const struct { DWORD v; DWORD len; DWORD err; } rows[] = {
            { 0, 4, 0 }, { 1, 4, 0 }, { 2, 4, 0 }, { 3, 4, 0 },
            { 4, 4, ERROR_INVALID_PARAMETER }, { 0x80000000, 4, ERROR_INVALID_PARAMETER }, { 0xFFFFFFFF, 4, ERROR_INVALID_PARAMETER },
            { 2, 2, ERROR_INTERNET_BAD_OPTION_LENGTH }, { 2, 8, ERROR_INTERNET_BAD_OPTION_LENGTH },
        };
        for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
            DWORD buf[2] = { rows[i].v, 0 }; SET_ERR(0);
            BOOL ok = U(InternetSetOptionA)(hs[h], INTERNET_OPTION_ENABLE_HTTP_PROTOCOL, buf, rows[i].len);
            DWORD e = ok ? 0 : GetLastError();
            CHECKF(e == rows[i].err && ok == !rows[i].err, "%s v=0x%lx len=%lu: ok=%d err=%lu want %lu", nm[h], rows[i].v, rows[i].len, ok, e, rows[i].err);
        }
    }
    /* NULL handle: per-handle option */
    DWORD v = 2; SET_ERR(0);
    BOOL ok = U(InternetSetOptionA)(NULL, INTERNET_OPTION_ENABLE_HTTP_PROTOCOL, &v, sizeof v);
    DWORD e = ok ? 0 : GetLastError();
    t_note("ENABLE_HTTP_PROTOCOL on NULL: ok=%d err=%lu", ok, e);
    CHECK(!ok);
    /* query: probe (no query case in the decomp switch) */
    DWORD q = 0xDEAD, l = sizeof q; SET_ERR(0);
    ok = U(InternetQueryOptionA)(hi, INTERNET_OPTION_ENABLE_HTTP_PROTOCOL, &q, &l);
    t_note("query ENABLE_HTTP_PROTOCOL on session: ok=%d err=%lu v=0x%lx", ok, ok ? 0 : GetLastError(), q);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
}

/* HTTP/2 enabled against an HTTP/1.1-only TLS server: ALPN is offered but not selected -> HTTP/1.1, protocol used 0 */
TEST(tls_alpn_offered_server_ignores) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/alpn", T_INET_FRESH | INTERNET_FLAG_SECURE));
    DWORD v = HTTP_PROTOCOL_FLAG_HTTP2;
    CHECK(U(InternetSetOptionA)(t.hr, INTERNET_OPTION_ENABLE_HTTP_PROTOCOL, &v, sizeof v));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    EXPECT_EQ(treq_status(&t), 200);
    DWORD used = 0xDEAD, l = sizeof used;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_HTTP_PROTOCOL_USED, &used, &l));
    EXPECT_EQ(used, 0);
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_STR(srv_req_line(s, 0), "GET /alpn HTTP/1.1");
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ broken servers */
typedef struct { int reaction; const char *name; DWORD want; } broken_row;
static void broken_case(int reaction, const char *name, DWORD want) {
    th_srv *t = th_start(reaction); if (!t) { t_skip("winsock unavailable"); return; }
    DWORD t0 = GetTickCount();
    DWORD e = hello_request(t, "127.0.0.1", 0, 0);
    DWORD dt = GetTickCount() - t0;
    th_wait(t, 1, 2000);
    t_note("%s: err=%lu %s connections=%d (%lu ms)", name, e, t_inet_errname(e), th_count(t), dt);
    CHECKF(e == want, "%s: err=%lu %s want %lu %s", name, e, t_inet_errname(e), want, t_inet_errname(want));
    th_stop(t);
}
TEST(tls_broken_server_close_after_hello) { broken_case(TH_CLOSE, "close", ERROR_INTERNET_SECURITY_CHANNEL_ERROR); }
TEST(tls_broken_server_reset_after_hello) { broken_case(TH_RESET, "reset", ERROR_INTERNET_CONNECTION_RESET); }
TEST(tls_broken_server_fatal_alert) { broken_case(TH_ALERT, "alert", ERROR_INTERNET_SECURITY_CHANNEL_ERROR); }
TEST(tls_broken_server_plaintext_http) { broken_case(TH_PLAINTEXT_HTTP, "plaintext", ERROR_INTERNET_SECURITY_CHANNEL_ERROR); }
TEST(tls_broken_server_garbage) { broken_case(TH_GARBAGE, "garbage", ERROR_INTERNET_SECURITY_CHANNEL_ERROR); }
TEST(tls_broken_server_truncated_serverhello) { broken_case(TH_HANGUP_AFTER_SH, "truncated-sh", ERROR_INTERNET_SECURITY_CHANNEL_ERROR); }
TEST(tls_broken_server_close_without_reading) { broken_case(TH_SILENT_CLOSE_NOREAD, "close-noread", ERROR_INTERNET_SECURITY_CHANNEL_ERROR); }

/* HTTPS request to a plain HTTP server (the shared library) */
TEST(tls_broken_https_to_http_server) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "plain"), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/x", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, SECURITY_SET_MASK);
    DWORD e = treq_send(&t);
    t_note("https->http server: err=%lu %s, server requests=%d", e, t_inet_errname(e), srv_req_count(s));
    EXPECT_EQ(e, ERROR_INTERNET_SECURITY_CHANNEL_ERROR);
    treq_close(&t); srv_stop(s);
}

/* plain HTTP request to the TLS server: the server sees a non-TLS first byte and aborts */
TEST(tls_broken_http_to_https_server) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/x", T_INET_FRESH));
    DWORD e = treq_send(&t);
    DWORD st = e ? 0 : treq_status(&t);
    t_note("http->https server: err=%lu %s status=%lu", e, t_inet_errname(e), st);
    tls_dump_tls_events(s);
    CHECK(e != 0 || st != 200);
    CHECK(srv_wait_events(s, SRV_EV_TLS_ABORT, 1, 2000));
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ protocol versions against restricted servers */
static void restricted(DWORD srv_proto, DWORD client_bit, const char *name) {
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, srv_proto, 0, NULL, 0, &rc);
    if (!s) { t_skip("%s server credential unavailable: %s", name, srv_strerror(rc)); return; }
    DWORD st, e = tls_try(s, NULL, SECURITY_FLAG_IGNORE_UNKNOWN_CA, 0, &st);
    const char *d = tls_done_data(s, 0);
    t_note("%s server: err=%lu %s status=%lu tls=%s conns=%d (client SecureProtocols=0x%lx)", name, e, t_inet_errname(e), st, d ? d : "(no TLS_DONE)", srv_conn_count(s), client_secure_protocols());
    tls_dump_tls_events(s);
    if (client_secure_protocols() & client_bit) {
        CHECKF(e == 0 && st == 200, "%s: err=%lu", name, e);
        CHECK(d && tls_ev_field(d, "proto") == srv_proto);
    } else {
        CHECKF(e != 0, "%s succeeded though the client protocol is disabled", name);
        CHECK(d == NULL);
        EXPECT_EQ(srv_req_count(s), 0);
    }
    srv_stop(s);
}
TEST(tls_proto_server_tls12_only) { restricted(TLS_SP_TLS1_2_SERVER, 0x800, "TLS1.2"); }
TEST(tls_proto_server_tls11_only) { restricted(TLS_SP_TLS1_1_SERVER, 0x200, "TLS1.1"); }
TEST(tls_proto_server_tls10_only) { restricted(TLS_SP_TLS1_0_SERVER, 0x80, "TLS1.0"); }
TEST(tls_proto_server_tls13_only) { restricted(TLS_SP_TLS1_3_SERVER, 0x2000, "TLS1.3"); }

/* the error code when no protocol overlaps */
TEST(tls_proto_no_overlap_error) {
    if (client_secure_protocols() & 0x80) { t_skip("client allows TLS 1.0 (SecureProtocols=0x%lx)", client_secure_protocols()); return; }
    int rc; srv *s = tls_srv_cfg(SRV_CERT_LOCALHOST, TLS_SP_TLS1_0_SERVER, 0, NULL, 0, &rc);
    if (!s) { t_skip("TLS1.0 server unavailable: %s", srv_strerror(rc)); return; }
    DWORD st, e = tls_try(s, NULL, SECURITY_FLAG_IGNORE_UNKNOWN_CA, 0, &st);
    t_note("no overlap: err=%lu %s, connections=%d", e, t_inet_errname(e), srv_conn_count(s));
    EXPECT_EQ(e, ERROR_INTERNET_SECURITY_CHANNEL_ERROR);
    srv_stop(s);
}

/* the client's view of the negotiated protocol equals the server's */
TEST(tls_proto_both_ends_agree) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/v", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    EXPECT_EQ(treq_send(&t), 0);
    tls_sec_conn_info sci; memset(&sci, 0, sizeof sci); DWORD l = sizeof sci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l));
    const char *d = tls_done_data(s, 0);
    CHECK(d != NULL);
    DWORD sp = tls_ev_field(d, "proto");
    /* client protocol bit = server bit << 1 (SP_PROT_*_CLIENT) */
    EXPECT_EQ(sci.connectionInfo.dwProtocol, sp << 1);
    treq_close(&t); srv_stop(s);
}
