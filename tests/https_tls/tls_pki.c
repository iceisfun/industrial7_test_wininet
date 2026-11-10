/* tls_pki.c - certificate chains, name matching, validity, key usage, signature hash and revocation, against the
 * mini schannel server (tls_pki_util.c) serving certificates issued by a per-process, untrusted test root.
 * VM_TIMEOUT: 420
 *
 * Decomp (wininet 19041):
 *  - CSecureSocket::VerifyTrust builds HTTPSPolicyCallbackData { cbStruct 0x18, dwAuthType 2 (server),
 *    fdwChecks = the request's security flags } and calls WinVerifySecureChannel with the server name from the
 *    connect handle, MultiByteToWideChar'd, **one trailing '.' removed**. fdwRevocationChecks = 1 (whole chain) when
 *    GlobalEnableRevocation ("CertificateRevocation") is set and security-flag bit 0x800000 is clear.
 *  - MapInternetError: CERT_E_UNTRUSTEDROOT 0x800B0109 -> 12045, CERT_E_EXPIRED/VALIDITYPERIODNESTING -> 12037,
 *    CERT_E_CN_NO_MATCH -> 12038, CERT_E_WRONG_USAGE 0x800B0110 and every other 0x800B.... -> 12169,
 *    TRUST_E_CERT_SIGNATURE 0x80096004 -> 12169 (12062 if the chain has CERT_TRUST_HAS_WEAK_SIGNATURE),
 *    CRYPT_E_REVOKED -> 12170, CRYPT_E_REVOCATION_OFFLINE -> 12057, CRYPT_E_NO_REVOCATION_CHECK -> 0 (success).
 *
 * Win10 VM (boot tls4): the schannel server sends only the leaf (the untrusted issuer in the credential's store is not
 * sent), so the client builds a PARTIAL chain: dwErrorStatus 0x1010040 = PARTIAL_CHAIN | REVOCATION_STATUS_UNKNOWN |
 * OFFLINE_REVOCATION. SECURITY_FLAG_IGNORE_UNKNOWN_CA (0x100) covers the partial chain; the revocation state then
 * surfaces as 12057 for every issued leaf, CDP or not (no CRL is fetched: the issuer is unknown), so the success flags
 * for issued leaves are 0x180 (IGNORE_UNKNOWN_CA | IGNORE_REVOCATION). Policy errors come out in a fixed order: wrong
 * usage (12169), then validity (12037), then name (12038), then revocation (12057). A leaf with an AIA caIssuers URL
 * makes CryptoAPI fetch the issuer over HTTP (User-Agent Microsoft-CryptoAPI/10.0), completing the chain.
 */
#include "tls_pki.h"

#define E_CA   ERROR_INTERNET_INVALID_CA                 /* 12045 */
#define E_CN   ERROR_INTERNET_SEC_CERT_CN_INVALID        /* 12038 */
#define E_DATE ERROR_INTERNET_SEC_CERT_DATE_INVALID      /* 12037 */
#define E_INV  ERROR_INTERNET_SEC_INVALID_CERT           /* 12169 */
#define E_REVF ERROR_INTERNET_SEC_CERT_REV_FAILED        /* 12057 */
#define E_REVD 12170                                     /* ERROR_INTERNET_SEC_CERT_REVOKED */
#define E_SCH  ERROR_INTERNET_SECURITY_CHANNEL_ERROR     /* 12157 */
#define OKF    0x180                                     /* IGNORE_UNKNOWN_CA | IGNORE_REVOCATION */

#define SAN_LOCAL "dns:localhost,ip4:127.0.0.1,ip6:::1"

/* ------------------------------------------------------------------ helpers */
static pki_ent *mk_leaf(const char *subj, const char *san, int eku, int nb, int na, int hash, int bits, const char *cdp, const char *aia, pki_ent *issuer) {
    pki_spec sp; memset(&sp, 0, sizeof sp);
    sp.subject = subj; sp.san = san; sp.eku = eku; sp.nb_days = nb; sp.na_days = na; sp.hash = hash; sp.bits = bits;
    sp.cdp = cdp; sp.aia = aia; sp.ku = 0xA0;
    return pki_make(&sp, issuer ? issuer : pki_root());
}
static pki_ent *good_leaf(void) { return mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL); }
static pki_ent *simple_leaf(const char *subj, const char *san, int eku, int nb, int na) { return mk_leaf(subj, san, eku, nb, na, PKI_SHA256, 0, NULL, NULL, NULL); }

/* server for leaf; the issuer goes into the credential store too (schannel does not send it, see above) */
static mts *serve_iss(pki_ent *leaf, pki_ent *issuer) {
    if (!leaf) return NULL;
    pki_ent *ch[1] = { issuer ? issuer : pki_root() };
    PCCERT_CONTEXT c = pki_server_cert(leaf, ch, 1);
    return c ? mts_start(c, 0) : NULL;
}
static mts *serve(pki_ent *leaf) { return serve_iss(leaf, NULL); }
#define PKI_SKIP() do { t_skip("certificate factory or schannel server unavailable"); return; } while (0)

static DWORD reg_dword(HKEY root, const char *path, const char *name, DWORD dflt) {
    HKEY k; DWORD v = dflt, t, l = sizeof v;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, name, NULL, &t, (BYTE *)&v, &l) != ERROR_SUCCESS || t != REG_DWORD) v = dflt;
        RegCloseKey(k);
    }
    return v;
}
/* registry (read only): CertificateRevocation (policy, then HKCU; wininet default 1) */
static int revocation_enabled(void) {
    static int v = -2;
    if (v == -2) {
        DWORD pol = reg_dword(HKEY_LOCAL_MACHINE, "Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "CertificateRevocation", 0xFFFFFFFF);
        DWORD cu = reg_dword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "CertificateRevocation", 0xFFFFFFFF);
        t_note("registry CertificateRevocation: HKCU=0x%lx policy=0x%lx", cu, pol);
        v = pol != 0xFFFFFFFF ? pol != 0 : cu != 0xFFFFFFFF ? cu != 0 : 1;
    }
    return v;
}
/* 12057 when revocation checking is on, else success */
#define E_REV_OR_OK (revocation_enabled() ? E_REVF : 0)

typedef struct { const char *host; DWORD sec; DWORD open; DWORD want; } prow;
static void run_prows(mts *m, const char *what, const prow *r, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int before = mts_requests(m);
        DWORD want = r[i].want == 0xFFFF ? E_REV_OR_OK : r[i].want;
        DWORD st, e = pki_get(r[i].host, mts_port(m), r[i].sec, r[i].open, &st, NULL);
        CHECKF(e == want, "%s host=%s sec=0x%lx open=0x%lx: err=%lu %s want %lu %s", what, r[i].host, r[i].sec, r[i].open, e,
               t_inet_errname(e), want, t_inet_errname(want));
        if (!want) CHECKF(st == 200, "%s sec=0x%lx status %lu", what, r[i].sec, st);
        int nreq = mts_requests(m) - before;
        /* the request reaches the server only after a successful verification */
        if (!want) CHECKF(nreq == 1, "%s sec=0x%lx requests=%d", what, r[i].sec, nreq);
        else CHECKF(nreq == 0, "%s sec=0x%lx requests=%d after error %lu", what, r[i].sec, nreq, e);
    }
}
#define REVF 0xFFFF   /* row marker: 12057 if revocation checking is enabled, else 0 */
static DWORD observe(mts *m, const char *what, const char *host, DWORD sec) {
    DWORD st, e = pki_get(host, mts_port(m), sec, 0, &st, NULL);
    t_note("%s host=%s sec=0x%lx -> err=%lu %s status=%lu", what, host, sec, e, t_inet_errname(e), st);
    return e;
}

/* HTTP helper server answering every GET with one fixed response (CRL, issuer certificate or an error status) */
typedef struct { srv *s; srv_step st[4]; srv_script sc; BYTE *body; } blob_srv;
static int blob_start(blob_srv *c, int status, const char *ctype) {
    memset(c, 0, sizeof *c);
    srv_step head = S_HEAD(), loop = S_LOOP_TO(0), end = S_END();
    c->st[0] = head;
    c->st[1].op = SRV_REPLY; c->st[1].data = ""; c->st[1].n = 0; c->st[1].arg = status; c->st[1].hdrs = ctype;
    c->st[2] = loop; c->st[3] = end;
    c->sc.steps = c->st; c->sc.nsteps = 4;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = &c->sc; cfg.nscripts = 1; cfg.v4_only = 1;
    return srv_start(&cfg, &c->s) == SRV_OK;
}
static void blob_set(blob_srv *c, const BYTE *der, DWORD n) {
    free(c->body); c->body = malloc(n ? n : 1); memcpy(c->body, der, n);
    c->st[1].data = (const char *)c->body; c->st[1].n = n;
}
static void blob_stop(blob_srv *c) { if (c->s) srv_stop(c->s); c->s = NULL; free(c->body); c->body = NULL; }
static void blob_report(blob_srv *c, const char *tag) {
    int n = srv_req_count(c->s);
    t_note("%s: helper server saw %d request(s)%s%s", tag, n, n ? ": " : "", n ? srv_req_line(c->s, 0) : "");
}
#define CT_CRL  "Content-Type: application/pkix-crl\r\n"
#define CT_CERT "Content-Type: application/pkix-cert\r\n"

/* ------------------------------------------------------------------ factory sanity (scaffolding) */
TEST(tls_pki_factory_chain_shape) {
    REQUIRE(U(CertCreateCertificateContext));
    pki_ent *root = pki_root(), *leaf = good_leaf();
    if (!root || !leaf) PKI_SKIP();
    CHECK(U(CertCompareCertificateName)(X509_ASN_ENCODING, &leaf->cert->pCertInfo->Issuer, &root->cert->pCertInfo->Subject));
    CHECK(U(CertCompareCertificateName)(X509_ASN_ENCODING, &root->cert->pCertInfo->Issuer, &root->cert->pCertInfo->Subject));
    CHECK(strstr(pki_simple_name(leaf->cert, 1), "i7 Test Root") != NULL);
    EXPECT_STR(pki_simple_name(leaf->cert, 0), "localhost");
    CHECK(U(CryptVerifyCertificateSignature)(0, X509_ASN_ENCODING, leaf->cert->pbCertEncoded, leaf->cert->cbCertEncoded, &root->cert->pCertInfo->SubjectPublicKeyInfo));
}

/* ------------------------------------------------------------------ issued leaf, issuer not available */
TEST(tls_pki_partial_chain_matrix) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf());
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "localhost", 0, 0, E_CA },
        { "127.0.0.1", 0x80, 0, E_CA },
        { "127.0.0.1", 0x1000 | 0x2000 | 0x200 | 0x80, 0, E_CA },
        { "127.0.0.1", 0, INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, E_CA },
        { "127.0.0.1", 0x100, 0, REVF },
        { "localhost", 0x100, 0, REVF },
        { "127.0.0.1", 0x3300, 0, REVF },
        { "127.0.0.1", 0x10100, 0, REVF },
        { "127.0.0.1", OKF, 0, 0 },
        { "localhost", OKF, 0, 0 },
        { "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_prows(m, "partial chain", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_success_wire_and_body) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf());
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), OKF, 0, &st, &t);
    EXPECT_EQ(e, 0);
    if (!e) {
        char b[64]; size_t n = treq_body(&t, b, sizeof b);
        EXPECT_EQ(n, 6); EXPECT_STR(b, MTS_BODY);
        EXPECT_EQ(st, 200);
    }
    treq_close(&t);
    mts_wait_conns(m, 1, 3000);
    const mts_conn *c = mts_get(m, 0);
    CHECK(c != NULL);
    if (c) {
        EXPECT_EQ(c->done, 1);
        EXPECT_STR(c->line, "GET /p HTTP/1.1");
        EXPECT_STR(c->ua, "tls-test");
        EXPECT_EQ(c->client_cert, 0);
        EXPECT_EQ(c->proto, TLS_SP_TLS1_2_SERVER);
    }
    mts_stop(m);
}

TEST(tls_pki_rejected_handshake_server_view) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf());
    if (!m) PKI_SKIP();
    DWORD st, e = pki_get("127.0.0.1", mts_port(m), 0, 0, &st, NULL);
    EXPECT_EQ(e, E_CA);
    mts_wait_conns(m, 1, 3000);
    EXPECT_EQ(mts_conns(m), 1);
    EXPECT_EQ(mts_requests(m), 0);
    const mts_conn *c = mts_get(m, 0);
    if (c) t_note("rejected: server handshake done=%d asc=0x%lx", c->done, c->asc);
    mts_stop(m);
}

/* the failed attempt's flags: 12057 leaves the request flags without SECURE and strength bits */
TEST(tls_pki_secflags_after_rev_failure_and_success) {
    REQUIRE(U(InternetQueryOptionA));
    mts *m = serve(good_leaf());
    if (!m) PKI_SKIP();
    treq t;
    if (!treq_open(&t, "127.0.0.1", mts_port(m), "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); mts_stop(m); t_skip("open"); return; }
    SEND_EQ(&t, E_CA);
    EXPECT_EQ(tls_secflags(t.hr), 0);
    t_https_secflags(t.hr, 0x100);
    SEND_EQ(&t, E_REV_OR_OK);
    if (revocation_enabled()) {
        EXPECT_EQ(tls_secflags(t.hr), 0x100);
        SEND_EQ(&t, E_REVF);                     /* unchanged flags: the same error */
        t_https_secflags(t.hr, 0x80);
        SEND_EQ(&t, 0);
    }
    EXPECT_EQ(treq_status(&t), 200);
    DWORD f = tls_secflags(t.hr);
    t_note("issued chain success secflags=0x%lx", f);
    EXPECT_EQ(f & 0x180, revocation_enabled() ? 0x180 : 0x100);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, SECURITY_FLAG_SECURE);
    EXPECT_EQ(f & 0x20000000, 0x20000000);
    EXPECT_EQ(f & 0x3200, 0);
    char b[16]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    EXPECT_EQ(mts_requests(m), 1);
    mts_stop(m);
}

/* ------------------------------------------------------------------ security information for an issued leaf */
TEST(tls_pki_certinfo_names_and_dates) {
    REQUIRE(U(InternetQueryOptionA));
    pki_ent *leaf = good_leaf();
    mts *m = serve(leaf);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), OKF, 0, &st, &t);
    EXPECT_EQ(e, 0);
    INTERNET_CERTIFICATE_INFO ci; DWORD l = sizeof ci; memset(&ci, 0, sizeof ci);
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
    CHECK(ok);
    if (ok) {
        EXPECT_EQ(l, sizeof ci);
        CHECK(ci.lpszSubjectInfo && ci.lpszIssuerInfo);
        if (ci.lpszSubjectInfo) EXPECT_STR(ci.lpszSubjectInfo, pki_simple_name(leaf->cert, 0));
        if (ci.lpszIssuerInfo) EXPECT_STR(ci.lpszIssuerInfo, pki_simple_name(leaf->cert, 1));
        if (ci.lpszIssuerInfo) CHECK(strstr(ci.lpszIssuerInfo, "i7 wininet corpus") != NULL);
        CHECK(!memcmp(&ci.ftExpiry, &leaf->cert->pCertInfo->NotAfter, sizeof(FILETIME)));
        CHECK(!memcmp(&ci.ftStart, &leaf->cert->pCertInfo->NotBefore, sizeof(FILETIME)));
        EXPECT_EQ(ci.lpszProtocolName, NULL);
        EXPECT_EQ(ci.lpszSignatureAlgName, NULL);
        EXPECT_EQ(ci.lpszEncryptionAlgName, NULL);
        EXPECT_EQ(ci.dwKeySize, 256);
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    }
    char s[2048]; l = sizeof s;
    ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, s, &l);
    CHECK(ok);
    if (ok) {
        CHECK(strstr(s, "localhost") != NULL);
        CHECK(strstr(s, "i7 Test Root") != NULL);
        EXPECT_EQ(l, strlen(s));
    }
    char b[16]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    mts_stop(m);
}

/* InternetQueryOptionW forwards options 0x1e..0x2c except 0x21/0x22/0x29 to InternetQueryOptionA (decomp, the W
 * dispatch): option 32 returns the ANSI layout, so the "W" struct's string pointers point at char strings. */
TEST(tls_pki_certinfo_wide_query_is_ansi) {
    REQUIRE(U(InternetQueryOptionW));
    pki_ent *leaf = good_leaf();
    mts *m = serve(leaf);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), OKF, 0, &st, &t);
    EXPECT_EQ(e, 0);
    INTERNET_CERTIFICATE_INFO ci; DWORD l = sizeof ci; memset(&ci, 0, sizeof ci);
    BOOL ok = U(InternetQueryOptionW)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
    CHECK(ok);
    if (ok) {
        EXPECT_EQ(l, sizeof ci);
        const char *subj = (const char *)ci.lpszSubjectInfo, *iss = (const char *)ci.lpszIssuerInfo;
        if (subj) EXPECT_STR(subj, pki_simple_name(leaf->cert, 0)); else CHECK(0);
        if (iss) EXPECT_STR(iss, pki_simple_name(leaf->cert, 1)); else CHECK(0);
        CHECK(!memcmp(&ci.ftExpiry, &leaf->cert->pCertInfo->NotAfter, sizeof(FILETIME)));
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    }
    l = 10; memset(&ci, 0, sizeof ci);
    SetLastError(0xDEAD);
    ok = U(InternetQueryOptionW)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
    CHECK(!ok);
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
    EXPECT_EQ(l, sizeof ci);
    char b[16]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    mts_stop(m);
}

TEST(tls_pki_chain_context_partial) {
    REQUIRE(U(InternetQueryOptionA));
    pki_ent *leaf = good_leaf();
    mts *m = serve(leaf);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), OKF, 0, &st, &t);
    EXPECT_EQ(e, 0);
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = sizeof ch;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
    CHECK(ok && ch);
    if (ok && ch) {
        EXPECT_EQ(ch->cChain, 1);
        PCERT_SIMPLE_CHAIN sc = ch->rgpChain[0];
        EXPECT_EQ(sc->cElement, 1);
        if (sc->cElement >= 1) CHECK(U(CertCompareCertificate)(X509_ASN_ENCODING, sc->rgpElement[0]->pCertContext->pCertInfo, leaf->cert->pCertInfo));
        /* after a success with 0x180 the stored chain only says PARTIAL_CHAIN (boot tls5) */
        EXPECT_EQ(ch->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN);
        EXPECT_EQ(ch->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED, 0);
        U(CertFreeCertificateChain)(ch);
    }
    char b[16]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    /* after the 12057 failure (0x100 only) the unverified chain carries the revocation bits (boot tls4) */
    if (revocation_enabled()) {
        e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
        EXPECT_EQ(e, E_REVF);
        ch = NULL; l = sizeof ch;
        ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
        CHECK(ok && ch);
        if (ok && ch) {
            EXPECT_EQ(ch->rgpChain[0]->cElement, 1);
            EXPECT_EQ(ch->TrustStatus.dwErrorStatus, CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION);
            U(CertFreeCertificateChain)(ch);
        }
        treq_close(&t);
    }
    mts_stop(m);
}

/* ------------------------------------------------------------------ name matching */
TEST(tls_pki_san_dns_only_ip_host) {
    REQUIRE(U(HttpSendRequestA));
    /* SAN dns:localhost only: an IP literal does not match; the name error comes before revocation */
    mts *m = serve(simple_leaf("CN=localhost", "dns:localhost", PKI_EKU_SERVER, -1, 30));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, E_CN },
        { "127.0.0.1", OKF, 0, E_CN },
        { "127.0.0.1", 0x1100, 0, REVF },
        { "127.0.0.1", 0x1180, 0, 0 },
        { "127.0.0.1", OKF, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0 },
        { "localhost", OKF, 0, 0 },
        { "LOCALHOST", OKF, 0, 0 },
    };
    run_prows(m, "san-dns-only", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_san_ip_only_cn_fallback) {
    REQUIRE(U(HttpSendRequestA));
    /* SAN with only an IP entry: the IP literal matches it, and the host name still matches CN=localhost */
    mts *m = serve(simple_leaf("CN=localhost", "ip4:127.0.0.1", PKI_EKU_SERVER, -1, 30));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, REVF },
        { "127.0.0.1", OKF, 0, 0 },
        { "localhost", 0x100, 0, REVF },
        { "localhost", OKF, 0, 0 },
    };
    run_prows(m, "san-ip-only", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_cn_only_ip_literal) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=127.0.0.1", NULL, PKI_EKU_SERVER, -1, 30));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, REVF },
        { "127.0.0.1", OKF, 0, 0 },
        { "localhost", OKF, 0, E_CN },
        { "localhost", OKF | 0x1000, 0, 0 },
    };
    run_prows(m, "cn-ip", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_cn_only_name) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=localhost", NULL, PKI_EKU_SERVER, -1, 30));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "localhost", OKF, 0, 0 },
        { "LocalHost", OKF, 0, 0 },
        { "127.0.0.1", OKF, 0, E_CN },
        { "127.0.0.1", OKF | 0x1000, 0, 0 },
    };
    run_prows(m, "cn-name", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_san_uppercase_dns) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=x", "dns:LOCALHOST", PKI_EKU_SERVER, -1, 30));
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "localhost", OKF, 0, 0 }, { "127.0.0.1", OKF, 0, E_CN } };
    run_prows(m, "san-upper", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_san_wildcard_forms_do_not_match_localhost) {
    REQUIRE(U(HttpSendRequestA));
    static const char *sans[] = { "dns:*", "dns:*host", "dns:local*", "dns:*.localhost" };
    for (size_t i = 0; i < sizeof sans / sizeof sans[0]; i++) {
        mts *m = serve(simple_leaf("CN=x", sans[i], PKI_EKU_SERVER, -1, 30));
        if (!m) PKI_SKIP();
        prow r[2] = { { "localhost", OKF, 0, E_CN }, { "localhost", OKF | 0x1000, 0, 0 } };
        run_prows(m, sans[i], r, 2);
        mts_stop(m);
    }
}

TEST(tls_pki_trailing_dot_host) {
    REQUIRE(U(HttpSendRequestA));
    /* VerifyTrust removes one trailing '.' from the host name before the policy check */
    mts *m = serve(simple_leaf("CN=localhost", "dns:localhost", PKI_EKU_SERVER, -1, 30));
    if (!m) PKI_SKIP();
    DWORD st, e = pki_get("localhost.", mts_port(m), OKF, 0, &st, NULL);
    if (e == ERROR_INTERNET_NAME_NOT_RESOLVED || e == ERROR_INTERNET_CANNOT_CONNECT) { mts_stop(m); t_skip("localhost. does not resolve here (%lu)", e); return; }
    EXPECT_EQ(e, 0);
    EXPECT_EQ(st, 200);
    e = pki_get("localhost.", mts_port(m), 0x100, 0, &st, NULL);
    EXPECT_EQ(e, E_REV_OR_OK);
    mts_stop(m);
}

/* ------------------------------------------------------------------ validity period */
TEST(tls_pki_not_yet_valid_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, 2, 30));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "127.0.0.1", 0x100, 0, E_DATE },
        { "127.0.0.1", OKF, 0, E_DATE },
        { "127.0.0.1", 0x2100, 0, REVF },
        { "127.0.0.1", 0x2180, 0, 0 },
        { "127.0.0.1", OKF, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
        { "127.0.0.1", OKF | 0x1000, 0, E_DATE },
    };
    run_prows(m, "not-yet-valid", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_expired_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -30, -2));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "127.0.0.1", 0x100, 0, E_DATE },
        { "127.0.0.1", 0x2100, 0, REVF },
        { "127.0.0.1", 0x2180, 0, 0 },
        { "localhost", OKF, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
    };
    run_prows(m, "expired", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

/* ------------------------------------------------------------------ extended key usage */
TEST(tls_pki_eku_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const struct { int eku; DWORD want_okf; const char *name; } rows[] = {
        { PKI_EKU_SERVER, 0, "serverAuth" },
        { PKI_EKU_BOTH, 0, "serverAuth+clientAuth" },
        { PKI_EKU_NONE, 0, "no EKU" },
        { PKI_EKU_ANY, 0, "anyExtendedKeyUsage" },   /* accepted for serverAuth (boot tls5) */
        { PKI_EKU_CLIENT, E_INV, "clientAuth" },
        { PKI_EKU_CODESIGN, E_INV, "codeSigning" },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        mts *m = serve(simple_leaf("CN=localhost", SAN_LOCAL, rows[i].eku, -1, 30));
        if (!m) PKI_SKIP();
        if (rows[i].want_okf == 0xFFFFFFFF) {   /* not yet confirmed: observed, plus the WRONG_USAGE-ignored success */
            observe(m, rows[i].name, "127.0.0.1", OKF);
            prow r[2] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", OKF | 0x200, 0, 0 } };
            run_prows(m, rows[i].name, r, 2);
        } else {
            prow r[4] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", OKF, 0, rows[i].want_okf },
                          { "127.0.0.1", 0x300, 0, rows[i].want_okf ? REVF : REVF }, { "127.0.0.1", OKF | 0x200, 0, 0 } };
            run_prows(m, rows[i].name, r, 4);
        }
        mts_stop(m);
    }
}

/* ------------------------------------------------------------------ several problems at once: order of the errors */
TEST(tls_pki_error_order_expired_cn) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=i7-other.invalid", NULL, PKI_EKU_SERVER, -30, -2));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "127.0.0.1", 0x100, 0, E_DATE },
        { "127.0.0.1", 0x1100, 0, E_DATE },
        { "127.0.0.1", 0x2100, 0, E_CN },
        { "127.0.0.1", 0x3100, 0, REVF },
        { "127.0.0.1", 0x3180, 0, 0 },
    };
    run_prows(m, "expired+cn", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_error_order_usage_expired) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_CLIENT, -30, -2));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, E_INV },
        { "127.0.0.1", 0x300, 0, E_DATE },
        { "127.0.0.1", 0x2100, 0, E_INV },
        { "127.0.0.1", 0x2300, 0, REVF },
        { "127.0.0.1", 0x2380, 0, 0 },
    };
    run_prows(m, "usage+expired", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_error_order_all_four) {
    REQUIRE(U(HttpSendRequestA));
    /* wrong usage + expired + name mismatch + revocation unknown: 12169 -> 12037 -> 12038 -> 12057 */
    mts *m = serve(simple_leaf("CN=i7-other.invalid", NULL, PKI_EKU_CLIENT, -30, -2));
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, E_INV },
        { "127.0.0.1", 0x300, 0, E_DATE },
        { "127.0.0.1", 0x1100, 0, E_INV },
        { "127.0.0.1", 0x2100, 0, E_INV },
        { "127.0.0.1", 0x3100, 0, E_INV },
        { "127.0.0.1", 0x1300, 0, E_DATE },
        { "127.0.0.1", 0x2300, 0, E_CN },
        { "127.0.0.1", 0x3300, 0, REVF },
        { "127.0.0.1", 0x0180, 0, E_INV },
        { "127.0.0.1", 0x0380, 0, E_DATE },
        { "127.0.0.1", 0x2380, 0, E_CN },
        { "127.0.0.1", 0x3380, 0, 0 },
        { "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_prows(m, "usage+expired+cn", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

/* retry protocol on one handle through the whole sequence of errors */
TEST(tls_pki_retry_sequence_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(simple_leaf("CN=i7-other.invalid", NULL, PKI_EKU_SERVER, -30, -2));
    if (!m) PKI_SKIP();
    treq t;
    if (!treq_open(&t, "127.0.0.1", mts_port(m), "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); mts_stop(m); t_skip("open failed"); return; }
    SEND_EQ(&t, E_CA);
    t_https_secflags(t.hr, 0x100);
    SEND_EQ(&t, E_DATE);
    t_https_secflags(t.hr, 0x2000);
    SEND_EQ(&t, E_CN);
    t_https_secflags(t.hr, 0x1000);
    SEND_EQ(&t, E_REV_OR_OK);
    if (revocation_enabled()) { t_https_secflags(t.hr, 0x80); SEND_EQ(&t, 0); }
    EXPECT_EQ(treq_status(&t), 200);
    char b[32]; size_t n = treq_body(&t, b, sizeof b); EXPECT_EQ(n, 6);
    DWORD f = tls_secflags(t.hr);
    EXPECT_EQ(f & 0x3100, 0x3100);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, SECURITY_FLAG_SECURE);
    treq_close(&t);
    EXPECT_EQ(mts_requests(m), 1);
    /* four rejected handshakes and one accepted: one connection per attempt */
    mts_wait_conns(m, revocation_enabled() ? 5 : 4, 3000);
    EXPECT_EQ(mts_conns(m), revocation_enabled() ? 5 : 4);
    mts_stop(m);
}

/* ------------------------------------------------------------------ signature hash and key size */
TEST(tls_pki_md5_signed_leaf_rejected_by_schannel) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_MD5, 0, NULL, NULL, NULL));
    if (!m) PKI_SKIP();
    /* the handshake itself fails, so no security flag helps */
    static const prow rows[] = { { "127.0.0.1", 0x100, 0, E_SCH }, { "127.0.0.1", 0x10100, 0, E_SCH }, { "127.0.0.1", SECURITY_SET_MASK | 0x10000, 0, E_SCH } };
    run_prows(m, "md5", rows, 3);
    mts_stop(m);
}
TEST(tls_pki_sha1_signed_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA1, 0, NULL, NULL, NULL));
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, REVF }, { "127.0.0.1", 0x10100, 0, REVF }, { "127.0.0.1", OKF, 0, 0 } };
    run_prows(m, "sha1", rows, 4);
    mts_stop(m);
}
TEST(tls_pki_sha384_signed_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA384, 0, NULL, NULL, NULL));
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, REVF }, { "127.0.0.1", OKF, 0, 0 } };
    run_prows(m, "sha384", rows, 3);
    mts_stop(m);
}
TEST(tls_pki_rsa1024_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 1024, NULL, NULL, NULL));
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "127.0.0.1", 0x100, 0, REVF }, { "127.0.0.1", OKF, 0, 0 } };
    run_prows(m, "rsa1024", rows, 2);
    mts_stop(m);
}
TEST(tls_pki_rsa4096_leaf_keybitness) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 4096, NULL, NULL, NULL));
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), OKF, 0, &st, &t);
    EXPECT_EQ(e, 0);
    /* KEY_BITNESS reports the cipher strength, not the RSA modulus size */
    DWORD kb = 0, l = sizeof kb;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_KEY_BITNESS, &kb, &l));
    EXPECT_EQ(kb, 256);
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); l = sizeof ci;
    if (U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l)) {
        EXPECT_EQ(ci.dwKeySize, kb);
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    } else CHECK(0);
    char b[16]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    mts_stop(m);
}

/* ------------------------------------------------------------------ CDP without a reachable issuer: no CRL fetch */
static void cdp_partial_case(int status, int revoke, const char *tag) {
    blob_srv c; if (!blob_start(&c, status, CT_CRL)) PKI_SKIP();
    pki_ent *leaf = mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, srv_url(c.s, "/i7.crl"), NULL, NULL);
    if (!leaf) { blob_stop(&c); PKI_SKIP(); }
    if (status == 200) {
        pki_ent *rv[1] = { leaf }; DWORD n = 0;
        BYTE *der = pki_crl(pki_root(), rv, revoke ? 1 : 0, 7, &n);
        if (!der) { blob_stop(&c); PKI_SKIP(); }
        blob_set(&c, der, n); free(der);
    }
    mts *m = serve(leaf);
    if (!m) { blob_stop(&c); PKI_SKIP(); }
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, REVF }, { "127.0.0.1", OKF, 0, 0 }, { "127.0.0.1", SECURITY_SET_MASK | 0x10000, 0, 0 },
    };
    run_prows(m, tag, rows, 4);
    blob_report(&c, tag);
    EXPECT_EQ(srv_req_count(c.s), 0);   /* partial chain: the CRL cannot be verified, so it is not fetched */
    mts_stop(m); blob_stop(&c);
}
TEST(tls_pki_cdp_partial_chain_404) { REQUIRE(U(HttpSendRequestA)); cdp_partial_case(404, 0, "cdp 404 partial"); }
TEST(tls_pki_cdp_partial_chain_revoked_crl) { REQUIRE(U(HttpSendRequestA)); cdp_partial_case(200, 1, "cdp revoked partial"); }
TEST(tls_pki_cdp_partial_chain_good_crl) { REQUIRE(U(HttpSendRequestA)); cdp_partial_case(200, 0, "cdp good partial"); }

TEST(tls_pki_cdp_closed_port) {
    REQUIRE(U(HttpSendRequestA));
    blob_srv c; if (!blob_start(&c, 404, CT_CRL)) PKI_SKIP();
    char url[128]; snprintf(url, sizeof url, "%s", srv_url(c.s, "/gone.crl"));
    blob_stop(&c);
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, url, NULL, NULL));
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "127.0.0.1", 0x100, 0, REVF }, { "127.0.0.1", OKF, 0, 0 } };
    run_prows(m, "cdp refused", rows, 2);
    mts_stop(m);
}

/* ------------------------------------------------------------------ AIA: the client fetches the issuer */
typedef struct { blob_srv aia, crl; pki_ent *iss, *leaf; mts *m; } aia_fx;
/* crl_status: 0 = no CDP, 404, or 200 with a CRL revoking the leaf when revoke */
static int aia_setup(aia_fx *f, pki_ent *issuer, int crl_status, int revoke, int nb, int na) {
    memset(f, 0, sizeof *f);
    f->iss = issuer ? issuer : pki_root();
    if (!f->iss || !blob_start(&f->aia, 200, CT_CERT)) return 0;
    blob_set(&f->aia, f->iss->cert->pbCertEncoded, f->iss->cert->cbCertEncoded);
    if (crl_status && !blob_start(&f->crl, crl_status, CT_CRL)) { blob_stop(&f->aia); return 0; }
    f->leaf = mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, nb, na, PKI_SHA256, 0, crl_status ? srv_url(f->crl.s, "/aia.crl") : NULL,
                      srv_url(f->aia.s, "/issuer.crt"), f->iss);
    if (f->leaf && crl_status == 200) {
        pki_ent *rv[1] = { f->leaf }; DWORD n = 0;
        BYTE *der = pki_crl(f->iss, rv, revoke ? 1 : 0, 7, &n);
        if (der) { blob_set(&f->crl, der, n); free(der); }
    }
    f->m = f->leaf ? serve_iss(f->leaf, f->iss) : NULL;
    if (!f->m) { blob_stop(&f->aia); blob_stop(&f->crl); return 0; }
    return 1;
}
static void aia_teardown(aia_fx *f) { mts_stop(f->m); blob_stop(&f->aia); blob_stop(&f->crl); }

TEST(tls_pki_aia_complete_chain) {
    REQUIRE(U(HttpSendRequestA));
    aia_fx f; if (!aia_setup(&f, NULL, 0, 0, -1, 30)) PKI_SKIP();
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x1000 | 0x2000 | 0x200 | 0x80, 0, E_CA }, { "127.0.0.1", OKF, 0, 0 } };
    run_prows(f.m, "aia", rows, 3);
    static const prow rows2[] = { { "127.0.0.1", 0x100, 0, REVF } };   /* no CDP: revocation unknown */
    run_prows(f.m, "aia no CDP", rows2, 1);
    blob_report(&f.aia, "aia");
    CHECK(srv_req_count(f.aia.s) >= 1);
    if (srv_req_count(f.aia.s) >= 1) {
        EXPECT_STR(srv_req_line(f.aia.s, 0), "GET /issuer.crt HTTP/1.1");
        const char *ua = srv_req_header(f.aia.s, 0, "User-Agent");
        EXPECT_STR(ua, "Microsoft-CryptoAPI/10.0");
        EXPECT_STR(srv_req_header(f.aia.s, 0, "Host"), srv_hostport(f.aia.s));
        for (int h = 0; h < srv_req_header_count(f.aia.s, 0); h++) t_note("  AIA hdr %s: %s", srv_req_header_name(f.aia.s, 0, h), srv_req_header_value(f.aia.s, 0, h));
    }
    /* the chain the request reports now has two elements (observed) */
    treq t; DWORD st;
    if (!pki_get("127.0.0.1", mts_port(f.m), OKF, 0, &st, &t)) {
        PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = sizeof ch;
        BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
        CHECK(ok && ch);
        if (ok && ch) {
            /* complete chain (leaf + fetched root): UNTRUSTED_ROOT, info HAS_PREFERRED_ISSUER... as observed (boot tls5) */
            EXPECT_EQ(ch->rgpChain[0]->cElement, 2);
            EXPECT_EQ(ch->TrustStatus.dwErrorStatus, CERT_TRUST_IS_UNTRUSTED_ROOT);
            EXPECT_EQ(ch->TrustStatus.dwInfoStatus, 0x100);
            if (ch->rgpChain[0]->cElement == 2) {
                CHECK(U(CertCompareCertificate)(X509_ASN_ENCODING, ch->rgpChain[0]->rgpElement[1]->pCertContext->pCertInfo, f.iss->cert->pCertInfo));
                CHECK(ch->rgpChain[0]->rgpElement[1]->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED);
            }
            U(CertFreeCertificateChain)(ch);
        }
        char b[16]; treq_body(&t, b, sizeof b);
    }
    treq_close(&t);
    aia_teardown(&f);
}

/* complete chain to an untrusted root plus a reachable CDP: Windows does not fetch the CRL for an untrusted chain, so the
 * result is 12057 whatever the CRL says (404, valid, revoking the leaf), and IGNORE_REVOCATION clears it (boot tls5).
 * 12170 (revoked) needs a trusted root, i.e. a store change: dx_ area only. */
static void aia_cdp_case(int status, int revoke, const char *tag) {
    aia_fx f; if (!aia_setup(&f, NULL, status, revoke, -1, 30)) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, REVF }, { "127.0.0.1", OKF, 0, 0 }, { "127.0.0.1", SECURITY_SET_MASK | 0x10000, 0, 0 },
    };
    run_prows(f.m, tag, rows, 4);
    blob_report(&f.crl, tag);
    EXPECT_EQ(srv_req_count(f.crl.s), 0);
    CHECK(srv_req_count(f.aia.s) >= 1);
    aia_teardown(&f);
}
TEST(tls_pki_aia_cdp_404) { REQUIRE(U(HttpSendRequestA)); aia_cdp_case(404, 0, "aia+cdp 404"); }
TEST(tls_pki_aia_cdp_good_crl) { REQUIRE(U(HttpSendRequestA)); aia_cdp_case(200, 0, "aia+cdp good"); }
TEST(tls_pki_aia_cdp_revoked) { REQUIRE(U(HttpSendRequestA)); aia_cdp_case(200, 1, "aia+cdp revoked"); }

TEST(tls_pki_aia_expired_issuer) {
    REQUIRE(U(HttpSendRequestA));
    pki_spec sp; memset(&sp, 0, sizeof sp);
    char subj[96]; snprintf(subj, sizeof subj, "CN=i7 Expired Root %lu", GetCurrentProcessId());
    sp.subject = subj; sp.nb_days = -60; sp.na_days = -5; sp.ca = 1;
    pki_ent *old = pki_make(&sp, NULL);
    if (!old) PKI_SKIP();
    aia_fx f; if (!aia_setup(&f, old, 0, 0, -1, 30)) PKI_SKIP();
    /* an expired issuer in the (complete) chain is a validity error like an expired leaf (boot tls5) */
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, E_DATE }, { "127.0.0.1", OKF, 0, E_DATE },
                                 { "127.0.0.1", 0x2100, 0, REVF }, { "127.0.0.1", OKF | 0x2000, 0, 0 } };
    run_prows(f.m, "aia expired issuer", rows, 5);
    blob_report(&f.aia, "aia expired issuer");
    aia_teardown(&f);
}
