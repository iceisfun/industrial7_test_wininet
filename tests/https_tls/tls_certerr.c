/* tls_certerr.c - certificate verification outcomes and the retry protocol.
 * The server certificates are the shared profiles (common/srv_tls.c): LOCALHOST (SAN dns+ip, serverAuth),
 * CN_OTHER (CN=i7-other.invalid, no SAN), EXPIRED (as LOCALHOST, now-30d..now-1d), NO_EKU (as LOCALHOST, no EKU),
 * CLIENT (CN=i7-client, no SAN, EKU clientAuth only). All are self-signed and in no store.
 * Decomp: MapInternetError maps CERT_E_UNTRUSTEDROOT -> 12045, CERT_E_EXPIRED/VALIDITYPERIODNESTING -> 12037,
 * CERT_E_CN_NO_MATCH -> 12038, CERT_E_WRONG_USAGE and other 0x800B.... -> 12169, SEC_E_* (0x8009....) -> 12157,
 * CRYPT_E_REVOKED -> 12170, CRYPT_E_NO_REVOCATION_CHECK -> 0. Every server is fresh (fresh port) per row. */
#include "tls_util.h"

#define E_CA   ERROR_INTERNET_INVALID_CA                 /* 12045 */
#define E_CN   ERROR_INTERNET_SEC_CERT_CN_INVALID        /* 12038 */
#define E_DATE ERROR_INTERNET_SEC_CERT_DATE_INVALID      /* 12037 */
#define E_INV  ERROR_INTERNET_SEC_INVALID_CERT           /* 12169 */
#define E_ERRS ERROR_INTERNET_SEC_CERT_ERRORS            /* 12055 */

typedef struct { int profile; const char *host; DWORD secflags; DWORD openflags; DWORD want; } cert_row;

static const char *prof_name(int p) {
    switch (p) { case SRV_CERT_LOCALHOST: return "LOCALHOST"; case SRV_CERT_CN_OTHER: return "CN_OTHER"; case SRV_CERT_EXPIRED: return "EXPIRED";
                 case SRV_CERT_NO_EKU: return "NO_EKU"; case SRV_CERT_CLIENT: return "CLIENT"; }
    return "?";
}

static void run_rows(const cert_row *rows, size_t n) {
    for (size_t i = 0; i < n; i++) {
        const cert_row *r = &rows[i];
        srv *s = tls_srv(r->profile, NULL, 0);
        if (!s) { t_skip("HTTPS server unavailable (%s): %s", prof_name(r->profile), srv_strerror(srv_last_error())); return; }
        DWORD st, e = tls_try(s, r->host, r->secflags, r->openflags, &st);
        CHECKF(e == r->want, "%s host=%s sec=0x%lx open=0x%lx: err=%lu %s want %lu %s", prof_name(r->profile), r->host, r->secflags, r->openflags,
               e, t_inet_errname(e), r->want, t_inet_errname(r->want));
        if (r->want == 0) CHECKF(st == 200, "%s sec=0x%lx status=%lu", prof_name(r->profile), r->secflags, st);
        else CHECKF(st == 0, "status %lu after failure", st);
        /* on success the server saw exactly one request; on a cert failure it saw none */
        int nreq = srv_req_count(s);
        CHECKF(r->want ? nreq == 0 : nreq == 1, "%s sec=0x%lx requests=%d", prof_name(r->profile), r->secflags, nreq);
        srv_stop(s);
    }
}

/* ------------------------------------------------------------------ LOCALHOST profile */
TEST(tls_cert_localhost_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const cert_row rows[] = {
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0, 0, E_CA },
        { SRV_CERT_LOCALHOST, "localhost", 0, 0, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x100, 0, 0 },
        { SRV_CERT_LOCALHOST, "localhost", 0x100, 0, 0 },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x1000, 0, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x2000, 0, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x80, 0, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x200, 0, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x3280, 0, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x3380, 0, 0 },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x13380, 0, 0 },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x100 | 0x80, 0, 0 },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0, INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, E_CA },
        { SRV_CERT_LOCALHOST, "127.0.0.1", 0x100, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0 },
        { SRV_CERT_LOCALHOST, "[::1]", 0x100, 0, 0 },
    };
    run_rows(rows, sizeof rows / sizeof rows[0]);
}

/* ------------------------------------------------------------------ CN mismatch */
TEST(tls_cert_cn_other_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const cert_row rows[] = {
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0, 0, E_CA },
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0x100, 0, E_CN },
        { SRV_CERT_CN_OTHER, "localhost", 0x100, 0, E_CN },
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0x1100, 0, 0 },
        { SRV_CERT_CN_OTHER, "localhost", 0x1100, 0, 0 },
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0x100, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0 },
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0x1000, 0, E_CA },
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0x2100, 0, E_CN },
        { SRV_CERT_CN_OTHER, "127.0.0.1", 0x0380, 0, E_CN },
        { SRV_CERT_CN_OTHER, "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_rows(rows, sizeof rows / sizeof rows[0]);
}

/* ------------------------------------------------------------------ expired */
TEST(tls_cert_expired_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const cert_row rows[] = {
        { SRV_CERT_EXPIRED, "127.0.0.1", 0, 0, E_CA },
        { SRV_CERT_EXPIRED, "127.0.0.1", 0x100, 0, E_DATE },              /* netlb_https_expired_cert, Win10 */
        { SRV_CERT_EXPIRED, "localhost", 0x100, 0, E_DATE },
        { SRV_CERT_EXPIRED, "127.0.0.1", 0x2100, 0, 0 },
        { SRV_CERT_EXPIRED, "127.0.0.1", 0x100, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
        { SRV_CERT_EXPIRED, "127.0.0.1", 0x1100, 0, E_DATE },
        { SRV_CERT_EXPIRED, "127.0.0.1", 0x2000, 0, E_CA },
        { SRV_CERT_EXPIRED, "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_rows(rows, sizeof rows / sizeof rows[0]);
}

/* ------------------------------------------------------------------ no EKU (all usages allowed) */
TEST(tls_cert_no_eku_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const cert_row rows[] = {
        { SRV_CERT_NO_EKU, "127.0.0.1", 0, 0, E_CA },
        { SRV_CERT_NO_EKU, "127.0.0.1", 0x100, 0, 0 },
        { SRV_CERT_NO_EKU, "localhost", 0x100, 0, 0 },
    };
    run_rows(rows, sizeof rows / sizeof rows[0]);
}

/* ------------------------------------------------------------------ clientAuth-only EKU as a server cert (+ CN mismatch) */
TEST(tls_cert_wrong_usage_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const cert_row rows[] = {
        { SRV_CERT_CLIENT, "127.0.0.1", 0, 0, E_CA },
        { SRV_CERT_CLIENT, "127.0.0.1", 0x100, 0, E_INV },             /* Win10 VM: wrong usage reported before CN */
        { SRV_CERT_CLIENT, "127.0.0.1", 0x1100, 0, E_INV },
        { SRV_CERT_CLIENT, "127.0.0.1", 0x1300, 0, 0 },
        { SRV_CERT_CLIENT, "127.0.0.1", 0x0300, 0, E_CN },
        { SRV_CERT_CLIENT, "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_rows(rows, sizeof rows / sizeof rows[0]);
}

/* ------------------------------------------------------------------ retry protocol on one request handle */
TEST(tls_retry_unknown_ca_same_handle) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/r", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, E_CA);
    EXPECT_EQ(treq_status(&t), 0);
    SEND_EQ(&t, E_CA);                       /* resend without change: same error */
    CHECK(t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 200);
    char b[32] = ""; treq_body(&t, b, sizeof b); EXPECT_STR(b, "hello");
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_EQ(srv_req_count(s), 1);
    EXPECT_STR(srv_req_line(s, 0), "GET /r HTTP/1.1");
    t_note("connections=%d tls_done=%d tls_abort=%d", srv_conn_count(s), tls_count(s, SRV_EV_TLS_DONE), tls_count(s, SRV_EV_TLS_ABORT));
    CHECK(srv_conn_count(s) >= 3);
    treq_close(&t); srv_stop(s);
}

TEST(tls_retry_cn_then_ca_chain) {
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/r", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, E_CA);
    CHECK(t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SEND_EQ(&t, E_CN);
    CHECK(t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_CERT_CN_INVALID));
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 200);
    EXPECT_EQ(tls_secflags(t.hr), 0x20001101);            /* 04 F8 */
    treq_close(&t); srv_stop(s);
}

TEST(tls_retry_expired_chain) {
    srv *s = tls_srv(SRV_CERT_EXPIRED, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/r", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, E_CA);
    CHECK(t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SEND_EQ(&t, E_DATE);
    CHECK(t_https_secflags(t.hr, SECURITY_FLAG_IGNORE_CERT_DATE_INVALID));
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 200);
    EXPECT_EQ(tls_secflags(t.hr), 0x20002101);
    treq_close(&t); srv_stop(s);
}

TEST(tls_retry_wrong_usage_chain) {
    srv *s = tls_srv(SRV_CERT_CLIENT, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/r", T_INET_FRESH | INTERNET_FLAG_SECURE));
    DWORD seq[4]; DWORD add[3] = { 0x100, 0x1000, 0x200 };
    seq[0] = treq_send(&t);
    for (int i = 0; i < 3; i++) { t_https_secflags(t.hr, add[i]); seq[i + 1] = treq_send(&t); }
    t_note("wrong-usage chain: %lu -> +0x100 %lu -> +0x1000 %lu -> +0x200 %lu", seq[0], seq[1], seq[2], seq[3]);
    EXPECT_EQ(seq[0], E_CA); EXPECT_EQ(seq[1], E_INV); EXPECT_EQ(seq[2], E_INV); EXPECT_EQ(seq[3], 0);
    EXPECT_EQ(tls_secflags(t.hr), 0x20001301);
    treq_close(&t); srv_stop(s);
}

/* the W send path reports the same error */
TEST(tls_retry_wide_send) {
    REQUIRE(U(HttpSendRequestW)); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(InternetConnectW));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    SET_ERR(0);
    EXPECT_FAIL(!U(HttpSendRequestW)(hr, NULL, 0, NULL, 0), E_CA);
    DWORD f = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    CHECK(U(InternetSetOptionW)(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f));
    CHECK(U(HttpSendRequestW)(hr, NULL, 0, NULL, 0));
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* HttpSendRequestEx/HttpEndRequest: where does the certificate error surface? */
TEST(tls_retry_sendrequestex_path) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "posted"), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 4); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "POST", "/ex", T_INET_FRESH | INTERNET_FLAG_SECURE));
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 4;
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestExA)(t.hr, &ib, NULL, 0, 0);
    DWORD e = ok ? 0 : GetLastError();
    t_note("SendRequestEx without flags: ok=%d err=%lu %s", ok, e, t_inet_errname(e));
    CHECK(!ok); EXPECT_EQ(e, E_CA);
    CHECK(t_https_secflags(t.hr, 0x100));
    ok = U(HttpSendRequestExA)(t.hr, &ib, NULL, 0, 0);
    CHECKF(ok, "err=%lu", GetLastError());
    DWORD w = 0;
    if (ok) {
        CHECK(U(InternetWriteFile)(t.hr, "data", 4, &w)); EXPECT_EQ(w, 4);
        CHECKF(U(HttpEndRequestA)(t.hr, NULL, 0, 0), "err=%lu", GetLastError());
        EXPECT_EQ(treq_status(&t), 200);
        char b[32] = ""; treq_body(&t, b, sizeof b); EXPECT_STR(b, "posted");
        CHECK(srv_wait_requests(s, 1, 2000));
        size_t bl = 0; const char *body = srv_req_body(s, 0, &bl);
        CHECK(body && bl == 4 && !memcmp(body, "data", 4));
    }
    treq_close(&t); srv_stop(s);
}

/* a successful TLS connection is pooled; a new request on it still verifies with its own flags (04 F9) */
TEST(tls_pooled_connection_flags_per_request) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "k"), S_LOOP() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/a", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    SEND_OK(&t);
    char b[16]; treq_body(&t, b, sizeof b);
    HINTERNET h2 = U(HttpOpenRequestA)(t.hc, "GET", "/b", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    t_https_secflags(h2, 0x100);
    SET_ERR(0);
    CHECKF(U(HttpSendRequestA)(h2, NULL, 0, NULL, 0), "err=%lu", GetLastError());
    t_inet_read_all(h2, b, sizeof b, NULL);
    CHECK(srv_wait_requests(s, 2, 2000));
    t_note("two ok requests: conns=%d req_conn=%d,%d tls_done=%d", srv_conn_count(s), srv_req_conn(s, 0), srv_req_conn(s, 1), tls_count(s, SRV_EV_TLS_DONE));
    /* Win10 VM: a connection whose cert errors were ignored is not reused by another request handle */
    CHECK(srv_req_conn(s, 0) != srv_req_conn(s, 1));
    EXPECT_EQ(tls_count(s, SRV_EV_TLS_DONE), 2);
    HINTERNET h3 = U(HttpOpenRequestA)(t.hc, "GET", "/c", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(h3, NULL, 0, NULL, 0);
    DWORD e = ok ? 0 : GetLastError();
    t_note("third request without flags on a pooled TLS connection: ok=%d err=%lu requests=%d conns=%d", ok, e, srv_req_count(s), srv_conn_count(s));
    EXPECT_EQ(e, E_CA);
    EXPECT_EQ(srv_req_count(s), 2);
    U(InternetCloseHandle)(h3); U(InternetCloseHandle)(h2);
    treq_close(&t); srv_stop(s);
}

/* InternetErrorDlg is UI; with FLAGS_ERROR_UI_FLAGS_NO_UI it must not block. Probe the return only, on a worker
 * thread with a bounded wait so a dialog could never hang the area. */
typedef struct { HINTERNET hr; DWORD r; } dlg_arg;
static DWORD WINAPI dlg_thread(LPVOID p) {
    dlg_arg *a = p;
    a->r = U(InternetErrorDlg)(NULL, a->hr, ERROR_INTERNET_INVALID_CA,
                               FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA, NULL);
    return 0;
}
TEST(tls_errordlg_no_ui_probe) {
    REQUIRE(U(InternetErrorDlg));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/d", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, E_CA);
    static dlg_arg a; a.hr = t.hr; a.r = 0xFFFFFFFF;
    HANDLE th = CreateThread(NULL, 0, dlg_thread, &a, 0, NULL);
    DWORD w = WaitForSingleObject(th, 3000);
    if (w != WAIT_OBJECT_0) { t_note("InternetErrorDlg(NO_UI) did not return within 3 s (thread leaked, handles leaked)"); CHECK(0); return; }
    CloseHandle(th);
    t_note("InternetErrorDlg(NO_UI|CHANGE_OPTIONS|GENERATE_DATA, 12045) -> %lu, flags now 0x%lx", a.r, tls_secflags(t.hr));
    EXPECT_EQ(a.r, ERROR_CANCELLED);                      /* Win10 VM: 1223, no flags changed */
    EXPECT_EQ(tls_secflags(t.hr), 0);
    DWORD e = treq_send(&t);
    t_note("resend after the NO_UI dialog call: err=%lu", e);
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    treq_close(&t); srv_stop(s);
}
