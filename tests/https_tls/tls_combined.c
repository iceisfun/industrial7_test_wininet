/* tls_combined.c - INTERNET_OPTION_ERROR_MASK (62) with INTERNET_ERROR_MASK_COMBINED_SEC_CERT (2) on HTTPS requests:
 * the "combined" certificate-error mode that yields ERROR_INTERNET_SEC_CERT_ERRORS (12055).
 * VM_TIMEOUT: 240
 *
 * Decomp (wininet 19041):
 *  - InternetSetOptionA case 0x3e stores the mask (bits 0xb only, else 87) at handle +0x3cc.
 *  - HTTP_REQUEST_HANDLE_OBJECT::OpenConnection_Fsm calls CSecureSocket::CreateInstance(*(this + 0x3cc), ...), and
 *    CreateInstance stores that value at socket +0x58: the request's error mask becomes the socket flags.
 *  - CSecureSocket::VerifyTrust, when (socket +0x58 & 2):
 *      * the SSL policy starts with fdwChecks = 0 (the request's security flags are NOT passed);
 *      * on an error it loops: 12045 -> add 0x100 to the checks, DLG_FLAGS_INVALID_CA 0x01000000;
 *        12038 -> add 0x1000, DLG_FLAGS_SEC_CERT_CN_INVALID 0x02000000 (counted only when GlobalWarnOnBadCertRecving);
 *        12037 -> add 0x2000, DLG_FLAGS_SEC_CERT_DATE_INVALID 0x04000000; 12057 -> add 0x80, DLG_FLAGS_SEC_CERT_REV_FAILED
 *        0x00800000; 12062 -> add 0x10000, 0x00200000; 12170 -> stop, plain 12170; any other error (12169 wrong usage)
 *        -> stop with that error. Each error whose IGNORE bit is not in the request's security flags marks the result;
 *      * after the loop, when marked: the DLG bits are ORed into the security flags (INTERNET_OPTION_SECURITY_FLAGS
 *        read-back) and the result is 12055, except 12057 when the revocation failure is among them and
 *        IGNORE_REVOCATION (0x80) is not set.
 *    Without the bit the policy gets the request flags and errors come one at a time (tls_certerr.c, tls_pki.c).
 * Every expectation below was derived from that code and checked on the Win10 VM (EVIDENCE.md).
 */
#include "tls_pki.h"

#define E_CA   ERROR_INTERNET_INVALID_CA                 /* 12045 */
#define E_CN   ERROR_INTERNET_SEC_CERT_CN_INVALID        /* 12038 */
#define E_DATE ERROR_INTERNET_SEC_CERT_DATE_INVALID      /* 12037 */
#define E_INV  ERROR_INTERNET_SEC_INVALID_CERT           /* 12169 */
#define E_REVF ERROR_INTERNET_SEC_CERT_REV_FAILED        /* 12057 */
#define E_ERRS ERROR_INTERNET_SEC_CERT_ERRORS            /* 12055 */

#define D_CA   0x01000000u   /* DLG_FLAGS_INVALID_CA */
#define D_CN   0x02000000u   /* DLG_FLAGS_SEC_CERT_CN_INVALID */
#define D_DATE 0x04000000u   /* DLG_FLAGS_SEC_CERT_DATE_INVALID */
#define D_REV  0x00800000u   /* DLG_FLAGS_SEC_CERT_REV_FAILED */
#define D_ALL  (D_CA | D_CN | D_DATE | D_REV | 0x00200000u)
#define COMB   INTERNET_ERROR_MASK_COMBINED_SEC_CERT

#define SAN_LOCAL "dns:localhost,ip4:127.0.0.1,ip6:::1"

static int set_mask(HINTERNET h, DWORD v) { return U(InternetSetOptionA)(h, INTERNET_OPTION_ERROR_MASK, &v, sizeof v); }

static DWORD reg_dw(HKEY root, const char *path, const char *name, DWORD dflt) {
    HKEY k; DWORD v = dflt, t, l = sizeof v;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, name, NULL, &t, (BYTE *)&v, &l) != ERROR_SUCCESS || t != REG_DWORD) v = dflt;
        RegCloseKey(k);
    }
    return v;
}
#define IS_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define IS_POL "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
/* read only: CertificateRevocation (policy, HKCU; default 1) */
static int rev_on(void) {
    static int v = -2;
    if (v == -2) {
        DWORD pol = reg_dw(HKEY_LOCAL_MACHINE, IS_POL, "CertificateRevocation", 0xFFFFFFFF);
        DWORD cu = reg_dw(HKEY_CURRENT_USER, IS_KEY, "CertificateRevocation", 0xFFFFFFFF);
        v = pol != 0xFFFFFFFF ? pol != 0 : cu != 0xFFFFFFFF ? cu != 0 : 1;
    }
    return v;
}
/* read only: WarnonBadCertRecving (GlobalWarnOnBadCertRecving; default 1). When 0 a CN mismatch does not mark the result. */
static int warn_cn(void) {
    static int v = -2;
    if (v == -2) {
        DWORD pol = reg_dw(HKEY_LOCAL_MACHINE, IS_POL, "WarnonBadCertRecving", 0xFFFFFFFF);
        DWORD cu = reg_dw(HKEY_CURRENT_USER, IS_KEY, "WarnonBadCertRecving", 0xFFFFFFFF);
        t_note("registry WarnonBadCertRecving: HKCU=0x%lx policy=0x%lx; CertificateRevocation effective=%d", cu, pol, rev_on());
        v = pol != 0xFFFFFFFF ? pol != 0 : cu != 0xFFFFFFFF ? cu != 0 : 1;
    }
    return v;
}

/* one request on a fresh session; mask set on the request (where == 2), the connect handle (1) or the session (0)
 * before the child handles exist. Returns the send error; *flags = security flags after the send. */
typedef struct { DWORD err, status, flags; int reqs; } cres;
static cres comb_shared(int profile, const char *host, int where, DWORD mask, DWORD secflags, DWORD openflags) {
    cres r = { 0xFFFFFFFF, 0, 0xDEADBEEF, -1 };
    srv *s = tls_srv(profile, NULL, 0);
    if (!s) { r.err = 0xFFFFFFFE; return r; }
    treq t; memset(&t, 0, sizeof t);
    t.hi = t_inet_open("tls-comb");
    if (t.hi && where == 0) CHECK(set_mask(t.hi, mask));
    t.hc = t.hi ? U(InternetConnectA)(t.hi, host, srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (t.hc && where == 1) CHECK(set_mask(t.hc, mask));
    t.hr = t.hc ? U(HttpOpenRequestA)(t.hc, "GET", "/c", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE | openflags, 0) : NULL;
    if (t.hr) {
        if (where == 2) CHECK(set_mask(t.hr, mask));
        if (secflags) t_https_secflags(t.hr, secflags);
        r.err = treq_send(&t);
        if (r.err == ERROR_INTERNET_CONNECTION_RESET) {
            t_note("transient %lu on send, retrying once", r.err); r.err = treq_send(&t);
        }
        r.flags = tls_secflags(t.hr);
        if (!r.err) { char b[64]; r.status = treq_status(&t); treq_body(&t, b, sizeof b); }
    }
    treq_close(&t);
    r.reqs = srv_req_count(s);
    srv_stop(s);
    return r;
}
static const char *pname(int p) {
    switch (p) { case SRV_CERT_LOCALHOST: return "LOCALHOST"; case SRV_CERT_CN_OTHER: return "CN_OTHER"; case SRV_CERT_EXPIRED: return "EXPIRED";
                 case SRV_CERT_NO_EKU: return "NO_EKU"; case SRV_CERT_CLIENT: return "CLIENT"; }
    return "?";
}
/* row: want error, want flags after the send (masked with D_ALL | 0x13380; 0xFFFFFFFF = do not check) */
typedef struct { int profile; DWORD sec, open, want, wflags; } crow;
static void run_crows(const char *tag, const crow *rows, size_t n) {
    for (size_t i = 0; i < n; i++) {
        const crow *w = &rows[i];
        cres r = comb_shared(w->profile, "127.0.0.1", 2, COMB, w->sec, w->open);
        if (r.err == 0xFFFFFFFE) { t_skip("HTTPS server unavailable: %s", srv_strerror(srv_last_error())); return; }
        t_note("%s %s sec=0x%lx open=0x%lx -> err=%lu %s flags=0x%lx reqs=%d", tag, pname(w->profile), w->sec, w->open, r.err, t_inet_errname(r.err), r.flags, r.reqs);
        CHECKF(r.err == w->want, "%s %s sec=0x%lx: err=%lu want %lu", tag, pname(w->profile), w->sec, r.err, w->want);
        if (w->wflags != 0xFFFFFFFF) CHECKF((r.flags & (D_ALL | 0x13380)) == w->wflags, "%s %s sec=0x%lx: flags=0x%lx want 0x%lx (masked)", tag, pname(w->profile), w->sec, r.flags, w->wflags);
        if (!w->want) { CHECKF(r.status == 200, "status %lu", r.status); CHECKF(r.reqs == 1, "reqs %d", r.reqs); }
        else CHECKF(r.reqs == 0, "%s %s sec=0x%lx: reqs %d after %lu", tag, pname(w->profile), w->sec, r.reqs, r.err);
    }
}

/* ------------------------------------------------------------------ shared self-signed profiles */
TEST(tls_comb_localhost_untrusted) {
    REQUIRE(U(HttpSendRequestA));
    /* only the unknown CA: 12055 + DLG_FLAGS_INVALID_CA unless 0x100 is set */
    const crow rows[] = {
        { SRV_CERT_LOCALHOST, 0, 0, E_ERRS, D_CA },
        { SRV_CERT_LOCALHOST, 0x1000 | 0x2000 | 0x80 | 0x200, 0, E_ERRS, D_CA | 0x3280 },
        { SRV_CERT_LOCALHOST, 0x100, 0, 0, 0x100 },
        { SRV_CERT_LOCALHOST, 0x3380, 0, 0, 0x3380 },
        { SRV_CERT_LOCALHOST, 0, INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, E_ERRS, 0xFFFFFFFF },
    };
    run_crows("localhost", rows, sizeof rows / sizeof rows[0]);
}

TEST(tls_comb_cn_other) {
    REQUIRE(U(HttpSendRequestA));
    int w = warn_cn();
    /* untrusted + name mismatch: both reported at once */
    const crow rows[] = {
        { SRV_CERT_CN_OTHER, 0, 0, E_ERRS, D_CA | D_CN },
        { SRV_CERT_CN_OTHER, 0x100, 0, w ? E_ERRS : 0, w ? (D_CA | D_CN | 0x100) : 0x100 },
        { SRV_CERT_CN_OTHER, 0x1000, 0, E_ERRS, D_CA | D_CN | 0x1000 },
        { SRV_CERT_CN_OTHER, 0x1100, 0, 0, 0x1100 },
        { SRV_CERT_CN_OTHER, 0x100, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0, 0x1100 },
    };
    run_crows("cn_other", rows, sizeof rows / sizeof rows[0]);
}

TEST(tls_comb_expired) {
    REQUIRE(U(HttpSendRequestA));
    const crow rows[] = {
        { SRV_CERT_EXPIRED, 0, 0, E_ERRS, D_CA | D_DATE },
        { SRV_CERT_EXPIRED, 0x100, 0, E_ERRS, D_CA | D_DATE | 0x100 },
        { SRV_CERT_EXPIRED, 0x2000, 0, E_ERRS, D_CA | D_DATE | 0x2000 },
        { SRV_CERT_EXPIRED, 0x2100, 0, 0, 0x2100 },
        { SRV_CERT_EXPIRED, 0x100, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0, 0x2100 },
    };
    run_crows("expired", rows, sizeof rows / sizeof rows[0]);
}

TEST(tls_comb_no_eku) {
    REQUIRE(U(HttpSendRequestA));
    const crow rows[] = { { SRV_CERT_NO_EKU, 0, 0, E_ERRS, D_CA }, { SRV_CERT_NO_EKU, 0x100, 0, 0, 0x100 } };
    run_crows("no_eku", rows, sizeof rows / sizeof rows[0]);
}

/* wrong usage is not one of the combined errors: the loop stops with 12169, and IGNORE_WRONG_USAGE (0x200) is never
 * passed to the policy in this mode (fdwChecks starts at 0), so even SECURITY_SET_MASK cannot reach the server.
 * The unknown CA seen before it still turns the result into 12055 when 0x100 is not set. */
TEST(tls_comb_wrong_usage_stops_loop) {
    REQUIRE(U(HttpSendRequestA));
    const crow rows[] = {
        { SRV_CERT_CLIENT, 0, 0, E_ERRS, D_CA },
        { SRV_CERT_CLIENT, 0x200, 0, E_ERRS, D_CA | 0x200 },
        { SRV_CERT_CLIENT, 0x100, 0, E_INV, 0x100 },
        { SRV_CERT_CLIENT, 0x1300, 0, E_INV, 0x1300 },
        { SRV_CERT_CLIENT, SECURITY_SET_MASK, 0, E_INV, SECURITY_SET_MASK },
    };
    run_crows("client-eku", rows, sizeof rows / sizeof rows[0]);
}

/* the other mask bits do not change certificate errors */
TEST(tls_comb_other_mask_bits_no_effect) {
    REQUIRE(U(HttpSendRequestA));
    static const DWORD masks[] = { 0, INTERNET_ERROR_MASK_INSERT_CDROM, INTERNET_ERROR_MASK_LOGIN_FAILURE_DISPLAY_ENTITY_BODY, 0x9 };
    for (size_t i = 0; i < sizeof masks / sizeof masks[0]; i++) {
        cres r = comb_shared(SRV_CERT_CN_OTHER, "127.0.0.1", 2, masks[i], 0, 0);
        if (r.err == 0xFFFFFFFE) { t_skip("HTTPS server unavailable"); return; }
        CHECKF(r.err == E_CA, "mask 0x%lx: err=%lu", masks[i], r.err);
        CHECKF(r.flags == 0, "mask 0x%lx: flags 0x%lx", masks[i], r.flags);
        r = comb_shared(SRV_CERT_CN_OTHER, "127.0.0.1", 2, masks[i], 0x100, 0);
        CHECKF(r.err == E_CN, "mask 0x%lx + 0x100: err=%lu", masks[i], r.err);
    }
    /* 0xB = every valid bit: combined mode */
    cres r = comb_shared(SRV_CERT_CN_OTHER, "127.0.0.1", 2, 0xB, 0, 0);
    CHECKF(r.err == E_ERRS, "mask 0xb: err=%lu", r.err);
}

/* where the mask is set: request (above), connect handle or session before the request exists (observed) */
TEST(tls_comb_mask_on_parent_handles) {
    REQUIRE(U(HttpSendRequestA));
    for (int where = 0; where < 2; where++) {
        cres r = comb_shared(SRV_CERT_LOCALHOST, "127.0.0.1", where, COMB, 0, 0);
        if (r.err == 0xFFFFFFFE) { t_skip("HTTPS server unavailable"); return; }
        t_note("mask on %s: err=%lu %s flags=0x%lx", where ? "connect" : "session", r.err, t_inet_errname(r.err), r.flags);
        CHECKF(r.err == E_CA || r.err == E_ERRS, "mask on %s: err=%lu", where ? "connect" : "session", r.err);
    }
}

/* ------------------------------------------------------------------ retry protocol in combined mode */
TEST(tls_comb_retry_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t;
    if (!treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/r", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); srv_stop(s); t_skip("open"); return; }
    CHECK(set_mask(t.hr, COMB));
    SEND_EQ(&t, E_ERRS);
    DWORD f = tls_secflags(t.hr);
    t_note("after first 12055: flags=0x%lx", f);
    EXPECT_EQ(f & D_ALL, D_CA | D_CN);
    /* the error names both problems; setting both ignore bits is enough for the resend */
    t_https_secflags(t.hr, 0x100 | 0x1000);
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 200);
    f = tls_secflags(t.hr);
    t_note("after success: flags=0x%lx", f);
    EXPECT_EQ(f & 0x1101, 0x1101);
    char b[32]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

TEST(tls_comb_retry_one_bit_at_a_time) {
    REQUIRE(U(HttpSendRequestA));
    if (!warn_cn()) { t_skip("WarnonBadCertRecving is 0"); return; }
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t;
    if (!treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/r", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); srv_stop(s); t_skip("open"); return; }
    CHECK(set_mask(t.hr, COMB));
    SEND_EQ(&t, E_ERRS);
    t_https_secflags(t.hr, 0x100);
    SEND_EQ(&t, E_ERRS);                 /* the name mismatch alone still gives 12055, not 12038 */
    t_https_secflags(t.hr, 0x1000);
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 200);
    char b[32]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

/* the mask can be changed between sends on one handle: combined, then plain, then combined again */
TEST(tls_comb_mask_toggle_between_sends) {
    REQUIRE(U(HttpSendRequestA));
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t;
    if (!treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/t", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); srv_stop(s); t_skip("open"); return; }
    CHECK(set_mask(t.hr, COMB));
    SEND_EQ(&t, E_ERRS);
    CHECK(set_mask(t.hr, 0));
    SEND_EQ(&t, E_CA);
    CHECK(set_mask(t.hr, COMB));
    SEND_EQ(&t, E_ERRS);
    treq_close(&t);
    EXPECT_EQ(srv_req_count(s), 0);
    srv_stop(s);
}

/* HttpSendRequestEx reports the combined error itself */
TEST(tls_comb_sendrequestex) {
    REQUIRE(U(HttpSendRequestExA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t;
    if (!treq_open(&t, "127.0.0.1", srv_port(s), "POST", "/x", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); srv_stop(s); t_skip("open"); return; }
    CHECK(set_mask(t.hr, COMB));
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 3;
    SET_ERR(0xDEAD);
    BOOL ok = U(HttpSendRequestExA)(t.hr, &ib, NULL, 0, 0);
    DWORD e = ok ? 0 : GetLastError();
    EXPECT_EQ(e, E_ERRS);
    t_https_secflags(t.hr, 0x100);
    SET_ERR(0xDEAD);
    ok = U(HttpSendRequestExA)(t.hr, &ib, NULL, 0, 0);
    e = ok ? 0 : GetLastError();
    if (e == ERROR_INTERNET_CONNECTION_RESET) { t_note("transient %lu, retrying once", e); ok = U(HttpSendRequestExA)(t.hr, &ib, NULL, 0, 0); e = ok ? 0 : GetLastError(); }
    EXPECT_EQ(e, 0);
    if (ok) {
        DWORD w = 0;
        CHECK(U(InternetWriteFile)(t.hr, "abc", 3, &w));
        EXPECT_EQ(w, 3);
        CHECK(U(HttpEndRequestA)(t.hr, NULL, 0, 0));
        EXPECT_EQ(treq_status(&t), 200);
        char b[32]; treq_body(&t, b, sizeof b);
    }
    treq_close(&t);
    srv_stop(s);
}

/* InternetErrorDlg is not used: the combined error is meant for one dialog. With NO_UI the call must not block. */

/* W option entry point sets the same mask */
TEST(tls_comb_mask_set_wide) {
    REQUIRE(U(InternetSetOptionW));
    srv *s = tls_srv(SRV_CERT_EXPIRED, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t;
    if (!treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/w", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); srv_stop(s); t_skip("open"); return; }
    DWORD m = COMB;
    CHECK(U(InternetSetOptionW)(t.hr, INTERNET_OPTION_ERROR_MASK, &m, sizeof m));
    SEND_EQ(&t, E_ERRS);
    EXPECT_EQ(tls_secflags(t.hr) & D_ALL, D_CA | D_DATE);
    treq_close(&t);
    srv_stop(s);
}

/* ------------------------------------------------------------------ issued leaves (tls_pki_util.c): revocation */
static mts *serve_leaf(const char *subj, const char *san, int eku, int nb, int na) {
    pki_spec sp; memset(&sp, 0, sizeof sp);
    sp.subject = subj; sp.san = san; sp.eku = eku; sp.nb_days = nb; sp.na_days = na; sp.ku = 0xA0;
    pki_ent *leaf = pki_make(&sp, pki_root());
    if (!leaf) return NULL;
    pki_ent *ch[1] = { pki_root() };
    PCCERT_CONTEXT c = pki_server_cert(leaf, ch, 1);
    return c ? mts_start(c, 0) : NULL;
}
static cres comb_pki(mts *m, DWORD sec) {
    cres r = { 0xFFFFFFFF, 0, 0xDEADBEEF, -1 };
    int before = mts_requests(m);
    treq t;
    if (treq_open(&t, "127.0.0.1", mts_port(m), "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE)) {
        CHECK(set_mask(t.hr, COMB));
        if (sec) t_https_secflags(t.hr, sec);
        r.err = treq_send(&t);
        r.flags = tls_secflags(t.hr);
        if (!r.err) { char b[64]; r.status = treq_status(&t); treq_body(&t, b, sizeof b); }
    }
    treq_close(&t);
    r.reqs = mts_requests(m) - before;
    return r;
}
typedef struct { DWORD sec, want, wflags; } prow2;
static void run_p2(mts *m, const char *tag, const prow2 *rows, size_t n) {
    for (size_t i = 0; i < n; i++) {
        cres r = comb_pki(m, rows[i].sec);
        t_note("%s sec=0x%lx -> err=%lu %s flags=0x%lx reqs=%d", tag, rows[i].sec, r.err, t_inet_errname(r.err), r.flags, r.reqs);
        CHECKF(r.err == rows[i].want, "%s sec=0x%lx: err=%lu want %lu", tag, rows[i].sec, r.err, rows[i].want);
        if (rows[i].wflags != 0xFFFFFFFF) CHECKF((r.flags & (D_ALL | 0x13380)) == rows[i].wflags, "%s sec=0x%lx: flags 0x%lx want 0x%lx", tag, rows[i].sec, r.flags, rows[i].wflags);
        CHECKF(rows[i].want ? r.reqs == 0 : r.reqs == 1, "%s sec=0x%lx: reqs %d", tag, rows[i].sec, r.reqs);
    }
}

/* partial chain (issuer not sent): unknown CA + revocation unknown. A revocation failure among the combined errors
 * is reported as 12057, not 12055, unless 0x80 is set. */
TEST(tls_comb_pki_revocation_precedence) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30);
    if (!m) { t_skip("certificate factory or schannel server unavailable"); return; }
    if (rev_on()) {
        const prow2 rows[] = {
            { 0, E_REVF, D_CA | D_REV },
            { 0x100, E_REVF, D_CA | D_REV | 0x100 },
            { 0x80, E_ERRS, D_CA | D_REV | 0x80 },
            { 0x180, 0, 0x180 },
            { SECURITY_SET_MASK, 0, SECURITY_SET_MASK },
        };
        run_p2(m, "pki partial", rows, sizeof rows / sizeof rows[0]);
    } else {
        const prow2 rows[] = { { 0, E_ERRS, D_CA }, { 0x100, 0, 0x100 } };
        run_p2(m, "pki partial (revocation off)", rows, 2);
    }
    mts_stop(m);
}

/* expired + name mismatch + unknown CA (+ revocation): every error at once */
TEST(tls_comb_pki_all_errors_at_once) {
    REQUIRE(U(HttpSendRequestA));
    if (!warn_cn()) { t_skip("WarnonBadCertRecving is 0"); return; }
    mts *m = serve_leaf("CN=i7-other.invalid", NULL, PKI_EKU_SERVER, -30, -2);
    if (!m) { t_skip("certificate factory or schannel server unavailable"); return; }
    DWORD R = rev_on() ? D_REV : 0;
    const prow2 rows[] = {
        { 0, rev_on() ? E_REVF : E_ERRS, D_CA | D_CN | D_DATE | R },
        { 0x80, E_ERRS, D_CA | D_CN | D_DATE | R | 0x80 },
        { 0x180, E_ERRS, D_CA | D_CN | D_DATE | R | 0x180 },
        { 0x2180, E_ERRS, D_CA | D_CN | D_DATE | R | 0x2180 },
        { 0x3180, 0, 0x3180 },
    };
    run_p2(m, "pki expired+cn", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

/* an issued clientAuth-only leaf: wrong usage stops the loop (12169) once the CA is ignored, whatever else is set */
TEST(tls_comb_pki_wrong_usage) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_CLIENT, -1, 30);
    if (!m) { t_skip("certificate factory or schannel server unavailable"); return; }
    const prow2 rows[] = {
        { 0, E_ERRS, D_CA },
        { 0x100, E_INV, 0x100 },
        { 0x380, E_INV, 0x380 },
        { SECURITY_SET_MASK, E_INV, SECURITY_SET_MASK },
    };
    run_p2(m, "pki clientAuth", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}
