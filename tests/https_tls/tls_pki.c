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
 * The security flags are the SSL policy's fdwChecks, so 0x80 ignores "revocation unknown/offline", never "revoked".
 */
#include "tls_pki.h"

#define E_CA   ERROR_INTERNET_INVALID_CA                 /* 12045 */
#define E_CN   ERROR_INTERNET_SEC_CERT_CN_INVALID        /* 12038 */
#define E_DATE ERROR_INTERNET_SEC_CERT_DATE_INVALID      /* 12037 */
#define E_INV  ERROR_INTERNET_SEC_INVALID_CERT           /* 12169 */
#define E_REVF ERROR_INTERNET_SEC_CERT_REV_FAILED        /* 12057 */
#define E_REVD 12170                                     /* ERROR_INTERNET_SEC_CERT_REVOKED */
#define E_WEAK 12062                                     /* ERROR_INTERNET_SEC_CERT_WEAK_SIGNATURE */

#define SAN_LOCAL "dns:localhost,ip4:127.0.0.1,ip6:::1"

/* ------------------------------------------------------------------ helpers */
static pki_ent *mk_leaf(const char *subj, const char *san, int eku, int nb, int na, int hash, int bits, const char *cdp, const char *aia, pki_ent *issuer) {
    pki_spec sp; memset(&sp, 0, sizeof sp);
    sp.subject = subj; sp.san = san; sp.eku = eku; sp.nb_days = nb; sp.na_days = na; sp.hash = hash; sp.bits = bits;
    sp.cdp = cdp; sp.aia = aia; sp.ku = 0xA0;
    return pki_make(&sp, issuer ? issuer : pki_root());
}
static pki_ent *good_leaf(void) { return mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL); }

/* server for leaf; send_root: also put the root into the credential store */
static mts *serve(pki_ent *leaf, int send_root) {
    if (!leaf) return NULL;
    pki_ent *ch[1] = { pki_root() };
    PCCERT_CONTEXT c = pki_server_cert(leaf, ch, send_root ? 1 : 0);
    return c ? mts_start(c, 0) : NULL;
}
#define PKI_SKIP() do { t_skip("certificate factory or schannel server unavailable"); return; } while (0)

/* registry (read only): HKCU Internet Settings CertificateRevocation; -1 when absent */
static DWORD reg_dword(HKEY root, const char *path, const char *name, DWORD dflt) {
    HKEY k; DWORD v = dflt, t, l = sizeof v;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, name, NULL, &t, (BYTE *)&v, &l) != ERROR_SUCCESS || t != REG_DWORD) v = dflt;
        RegCloseKey(k);
    }
    return v;
}
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

typedef struct { const char *host; DWORD sec; DWORD open; DWORD want; } prow;
static void run_prows(mts *m, const char *what, const prow *r, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int before = mts_requests(m);
        DWORD st, e = pki_get(r[i].host, mts_port(m), r[i].sec, r[i].open, &st, NULL);
        CHECKF(e == r[i].want, "%s host=%s sec=0x%lx open=0x%lx: err=%lu %s want %lu %s", what, r[i].host, r[i].sec, r[i].open, e,
               t_inet_errname(e), r[i].want, t_inet_errname(r[i].want));
        if (!r[i].want) CHECKF(st == 200, "%s sec=0x%lx status %lu", what, r[i].sec, st);
        int nreq = mts_requests(m) - before;
        /* the request reaches the server only after a successful verification */
        if (!r[i].want) CHECKF(nreq == 1, "%s sec=0x%lx requests=%d", what, r[i].sec, nreq);
        else CHECKF(nreq == 0, "%s sec=0x%lx requests=%d after error %lu", what, r[i].sec, nreq, e);
    }
}
/* observe-only row runner: prints the outcome; used for expectations not yet confirmed */
static DWORD observe(mts *m, const char *what, const char *host, DWORD sec) {
    DWORD st, e = pki_get(host, mts_port(m), sec, 0, &st, NULL);
    t_note("%s host=%s sec=0x%lx -> err=%lu %s status=%lu", what, host, sec, e, t_inet_errname(e), st);
    return e;
}

/* ------------------------------------------------------------------ factory sanity (scaffolding) */
TEST(tls_pki_factory_chain_shape) {
    REQUIRE(U(CertCreateCertificateContext));
    pki_ent *root = pki_root(), *leaf = good_leaf();
    if (!root || !leaf) PKI_SKIP();
    CHECK(U(CertCompareCertificateName)(X509_ASN_ENCODING, &leaf->cert->pCertInfo->Issuer, &root->cert->pCertInfo->Subject));
    CHECK(U(CertCompareCertificateName)(X509_ASN_ENCODING, &root->cert->pCertInfo->Issuer, &root->cert->pCertInfo->Subject));
    CHECK(strstr(pki_simple_name(leaf->cert, 1), "i7 Test Root") != NULL);
    EXPECT_STR(pki_simple_name(leaf->cert, 0), "localhost");
    /* the signature verifies with the root's public key */
    CHECK(U(CryptVerifyCertificateSignature)(0, X509_ASN_ENCODING, leaf->cert->pbCertEncoded, leaf->cert->cbCertEncoded, &root->cert->pCertInfo->SubjectPublicKeyInfo));
}

/* ------------------------------------------------------------------ untrusted root */
TEST(tls_pki_untrusted_root_matrix) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf(), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "localhost", 0, 0, E_CA },
        { "127.0.0.1", 0x1000 | 0x2000 | 0x200 | 0x80, 0, E_CA },
        { "127.0.0.1", 0, INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, E_CA },
        { "127.0.0.1", 0x100, 0, 0 },
        { "localhost", 0x100, 0, 0 },
        { "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_prows(m, "ca-issued", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_success_wire_and_body) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf(), 1);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
    EXPECT_EQ(e, 0);
    if (!e) {
        char b[64]; size_t n = treq_body(&t, b, sizeof b);
        EXPECT_EQ(n, 6); b[n < sizeof b ? n : sizeof b - 1] = 0; EXPECT_STR(b, MTS_BODY);
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
        t_note("negotiated protocol 0x%lx", c->proto);
    }
    mts_stop(m);
}

/* a rejected certificate: the handshake completes on the server side, then the client closes without a request */
TEST(tls_pki_rejected_handshake_server_view) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf(), 1);
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

/* ------------------------------------------------------------------ security information for an issued chain */
TEST(tls_pki_certinfo_names_and_dates) {
    REQUIRE(U(InternetQueryOptionA));
    pki_ent *leaf = good_leaf();
    mts *m = serve(leaf, 1);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
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
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    }
    /* option 35: the formatted string names the subject and the issuer */
    char s[2048]; l = sizeof s;
    ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, s, &l);
    CHECK(ok);
    if (ok) {
        CHECK(strstr(s, "localhost") != NULL);
        CHECK(strstr(s, "i7 Test Root") != NULL);
        EXPECT_EQ(l, strlen(s));
    }
    treq_close(&t);
    mts_stop(m);
}

/* InternetQueryOptionW forwards options 0x1e..0x2c except 0x21/0x22/0x29 to InternetQueryOptionA (decomp, the W
 * dispatch): option 32 returns the ANSI layout, so the "W" struct's string pointers point at char strings. */
TEST(tls_pki_certinfo_wide_query_is_ansi) {
    REQUIRE(U(InternetQueryOptionW));
    pki_ent *leaf = good_leaf();
    mts *m = serve(leaf, 1);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
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
    /* short buffer: same rule as the A entry (12004 per tls_info), size 64 */
    l = 10; memset(&ci, 0, sizeof ci);
    SetLastError(0xDEAD);
    ok = U(InternetQueryOptionW)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
    CHECK(!ok);
    EXPECT_ERR(ERROR_INTERNET_INTERNAL_ERROR);
    EXPECT_EQ(l, sizeof ci);
    treq_close(&t);
    mts_stop(m);
}

static void chain_probe(int send_root, const char *tag) {
    pki_ent *leaf = good_leaf();
    mts *m = serve(leaf, send_root);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
    EXPECT_EQ(e, 0);
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = sizeof ch;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
    CHECK(ok && ch);
    if (ok && ch) {
        EXPECT_EQ(ch->cChain, 1);
        PCERT_SIMPLE_CHAIN sc = ch->rgpChain[0];
        t_note("%s: elements=%lu chain error=0x%lx info=0x%lx", tag, sc->cElement, ch->TrustStatus.dwErrorStatus, ch->TrustStatus.dwInfoStatus);
        CHECK(sc->cElement >= 1);
        if (sc->cElement >= 1) CHECK(U(CertCompareCertificate)(X509_ASN_ENCODING, sc->rgpElement[0]->pCertContext->pCertInfo, leaf->cert->pCertInfo));
        if (send_root) {
            EXPECT_EQ(sc->cElement, 2);
            if (sc->cElement == 2) {
                CHECK(U(CertCompareCertificate)(X509_ASN_ENCODING, sc->rgpElement[1]->pCertContext->pCertInfo, pki_root()->cert->pCertInfo));
                CHECK(sc->rgpElement[1]->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED);
                CHECK(!(sc->rgpElement[0]->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED));
                CHECK(ch->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT);
                CHECK(!(ch->TrustStatus.dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN));
            }
        }
        U(CertFreeCertificateChain)(ch);
    }
    treq_close(&t);
    mts_stop(m);
}
TEST(tls_pki_chain_context_with_root_sent) { REQUIRE(U(InternetQueryOptionA)); chain_probe(1, "root sent"); }
TEST(tls_pki_chain_context_leaf_only) { REQUIRE(U(InternetQueryOptionA)); chain_probe(0, "leaf only"); }

TEST(tls_pki_leaf_only_errors) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(good_leaf(), 0);
    if (!m) PKI_SKIP();
    DWORD e0 = observe(m, "leaf-only", "127.0.0.1", 0);
    DWORD e1 = observe(m, "leaf-only", "127.0.0.1", 0x100);
    CHECK(e0 != 0);
    (void)e1;
    mts_stop(m);
}

/* ------------------------------------------------------------------ name matching */
TEST(tls_pki_san_dns_only_ip_host) {
    REQUIRE(U(HttpSendRequestA));
    /* CN=localhost, SAN dns:localhost only: an IP literal does not match (SAN present, CN not consulted) */
    mts *m = serve(mk_leaf("CN=localhost", "dns:localhost", PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, E_CN },
        { "127.0.0.1", 0x1100, 0, 0 },
        { "127.0.0.1", 0x100, INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0 },
        { "localhost", 0x100, 0, 0 },
        { "LOCALHOST", 0x100, 0, 0 },
    };
    run_prows(m, "san-dns-only", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_san_ip_only_name_host) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", "ip4:127.0.0.1", PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0x100, 0, 0 },
        { "localhost", 0x1100, 0, 0 },
    };
    run_prows(m, "san-ip-only", rows, sizeof rows / sizeof rows[0]);
    observe(m, "san-ip-only, CN=localhost", "localhost", 0x100);
    mts_stop(m);
}

TEST(tls_pki_cn_only_ip_literal) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=127.0.0.1", NULL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "CN=127.0.0.1 no SAN", "127.0.0.1", 0x100);
    static const prow rows[] = {
        { "localhost", 0x100, 0, E_CN },
        { "localhost", 0x1100, 0, 0 },
        { "127.0.0.1", 0x1100, 0, 0 },
    };
    run_prows(m, "cn-ip", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_cn_only_name) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", NULL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "localhost", 0x100, 0, 0 },
        { "LocalHost", 0x100, 0, 0 },
        { "127.0.0.1", 0x100, 0, E_CN },
        { "127.0.0.1", 0x1100, 0, 0 },
    };
    run_prows(m, "cn-name", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_san_uppercase_dns) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=x", "dns:LOCALHOST", PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "localhost", 0x100, 0, 0 }, { "127.0.0.1", 0x100, 0, E_CN } };
    run_prows(m, "san-upper", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_san_wildcard_forms) {
    REQUIRE(U(HttpSendRequestA));
    /* "*" alone and "*host" partial labels: observed only */
    static const char *sans[] = { "dns:*", "dns:*host", "dns:local*", "dns:*.localhost" };
    for (size_t i = 0; i < sizeof sans / sizeof sans[0]; i++) {
        mts *m = serve(mk_leaf("CN=x", sans[i], PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
        if (!m) PKI_SKIP();
        observe(m, sans[i], "localhost", 0x100);
        mts_stop(m);
    }
}

TEST(tls_pki_trailing_dot_host) {
    REQUIRE(U(HttpSendRequestA));
    /* VerifyTrust removes one trailing '.' from the host name before the policy check */
    mts *m = serve(mk_leaf("CN=localhost", "dns:localhost", PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    DWORD st, e = pki_get("localhost.", mts_port(m), 0x100, 0, &st, NULL);
    t_note("localhost. -> %lu %s status %lu", e, t_inet_errname(e), st);
    if (e == ERROR_INTERNET_NAME_NOT_RESOLVED || e == ERROR_INTERNET_CANNOT_CONNECT) { mts_stop(m); t_skip("localhost. does not resolve here (%lu)", e); return; }
    EXPECT_EQ(e, 0);
    EXPECT_EQ(st, 200);
    mts_stop(m);
}

/* ------------------------------------------------------------------ validity period */
TEST(tls_pki_not_yet_valid_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, 2, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "127.0.0.1", 0x100, 0, E_DATE },
        { "127.0.0.1", 0x2100, 0, 0 },
        { "127.0.0.1", 0x100, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
        { "127.0.0.1", 0x1100, 0, E_DATE },
    };
    run_prows(m, "not-yet-valid", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_expired_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -30, -2, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "127.0.0.1", 0x100, 0, E_DATE },
        { "127.0.0.1", 0x2100, 0, 0 },
        { "localhost", 0x100, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
    };
    run_prows(m, "expired", rows, sizeof rows / sizeof rows[0]);
    mts_stop(m);
}

TEST(tls_pki_leaf_outlives_root) {
    REQUIRE(U(HttpSendRequestA));
    /* leaf valid beyond the root's NotAfter (root: +60 d): observed (Windows does not enforce nesting for SSL) */
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 400, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "leaf outlives root", "127.0.0.1", 0x100);
    mts_stop(m);
}

TEST(tls_pki_expired_root) {
    REQUIRE(U(HttpSendRequestA));
    pki_spec sp; memset(&sp, 0, sizeof sp);
    char subj[96]; snprintf(subj, sizeof subj, "CN=i7 Expired Root %lu", GetCurrentProcessId());
    sp.subject = subj; sp.nb_days = -60; sp.na_days = -5; sp.ca = 1;
    pki_ent *oldroot = pki_make(&sp, NULL);
    if (!oldroot) PKI_SKIP();
    pki_ent *leaf = mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, NULL, oldroot);
    if (!leaf) PKI_SKIP();
    pki_ent *ch[1] = { oldroot };
    PCCERT_CONTEXT c = pki_server_cert(leaf, ch, 1);
    mts *m = c ? mts_start(c, 0) : NULL;
    if (!m) PKI_SKIP();
    observe(m, "expired root", "127.0.0.1", 0x100);
    observe(m, "expired root", "127.0.0.1", 0x2100);
    mts_stop(m);
}

/* ------------------------------------------------------------------ extended key usage */
TEST(tls_pki_eku_matrix) {
    REQUIRE(U(HttpSendRequestA));
    static const struct { int eku; DWORD want100; DWORD want300; const char *name; } rows[] = {
        { PKI_EKU_SERVER, 0, 0, "serverAuth" },
        { PKI_EKU_BOTH, 0, 0, "serverAuth+clientAuth" },
        { PKI_EKU_NONE, 0, 0, "no EKU" },
        { PKI_EKU_CLIENT, E_INV, 0, "clientAuth" },
        { PKI_EKU_CODESIGN, E_INV, 0, "codeSigning" },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, rows[i].eku, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
        if (!m) PKI_SKIP();
        prow r[3] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, rows[i].want100 }, { "127.0.0.1", 0x300, 0, rows[i].want300 } };
        run_prows(m, rows[i].name, r, 3);
        mts_stop(m);
    }
}

TEST(tls_pki_eku_any_purpose) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_ANY, -1, 30, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "anyExtendedKeyUsage", "127.0.0.1", 0x100);
    static const prow rows[] = { { "127.0.0.1", 0x300, 0, 0 } };
    run_prows(m, "anyEKU", rows, 1);
    mts_stop(m);
}

/* ------------------------------------------------------------------ several problems at once: which error first */
TEST(tls_pki_error_order_expired_cn) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=i7-other.invalid", NULL, PKI_EKU_SERVER, -30, -2, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    DWORD a = observe(m, "expired+cn", "127.0.0.1", 0x100);
    DWORD b = observe(m, "expired+cn", "127.0.0.1", 0x1100);
    DWORD c = observe(m, "expired+cn", "127.0.0.1", 0x2100);
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x3100, 0, 0 } };
    run_prows(m, "expired+cn", rows, 2);
    CHECK(a == E_DATE || a == E_CN);
    (void)b; (void)c;
    mts_stop(m);
}

TEST(tls_pki_error_order_usage_expired) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_CLIENT, -30, -2, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "usage+expired", "127.0.0.1", 0x100);
    observe(m, "usage+expired", "127.0.0.1", 0x300);
    observe(m, "usage+expired", "127.0.0.1", 0x2100);
    static const prow rows[] = { { "127.0.0.1", 0x2300, 0, 0 } };
    run_prows(m, "usage+expired", rows, 1);
    mts_stop(m);
}

TEST(tls_pki_error_order_all_three) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=i7-other.invalid", NULL, PKI_EKU_CLIENT, -30, -2, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const DWORD seq[] = { 0x100, 0x300, 0x1100, 0x2100, 0x1300, 0x2300, 0x3100 };
    for (size_t i = 0; i < sizeof seq / sizeof seq[0]; i++) observe(m, "usage+expired+cn", "127.0.0.1", seq[i]);
    static const prow rows[] = { { "127.0.0.1", 0x3300, 0, 0 }, { "127.0.0.1", SECURITY_SET_MASK, 0, 0 } };
    run_prows(m, "usage+expired+cn", rows, 2);
    mts_stop(m);
}

/* retry protocol on one handle through a sequence of errors */
TEST(tls_pki_retry_sequence_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=i7-other.invalid", NULL, PKI_EKU_SERVER, -30, -2, PKI_SHA256, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    treq t;
    if (!treq_open(&t, "127.0.0.1", mts_port(m), "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); mts_stop(m); t_skip("open failed"); return; }
    SEND_EQ(&t, E_CA);
    t_https_secflags(t.hr, 0x100);
    DWORD e1 = treq_send(&t);
    CHECK(e1 == E_DATE || e1 == E_CN);
    t_https_secflags(t.hr, e1 == E_DATE ? 0x2000 : 0x1000);
    DWORD e2 = treq_send(&t);
    CHECK(e2 == (e1 == E_DATE ? E_CN : E_DATE));
    t_note("retry sequence: 12045 -> %lu -> %lu", e1, e2);
    t_https_secflags(t.hr, 0x3000);
    SEND_EQ(&t, 0);
    EXPECT_EQ(treq_status(&t), 200);
    char b[32]; size_t n = treq_body(&t, b, sizeof b); EXPECT_EQ(n, 6);
    DWORD f = tls_secflags(t.hr);
    EXPECT_EQ(f & 0x3100, 0x3100);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, SECURITY_FLAG_SECURE);
    treq_close(&t);
    EXPECT_EQ(mts_requests(m), 1);
    mts_stop(m);
}

/* ------------------------------------------------------------------ signature hash and key size */
TEST(tls_pki_sha1_signed_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA1, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "sha1 leaf", "127.0.0.1", 0x100);
    observe(m, "sha1 leaf", "127.0.0.1", 0x10100);
    mts_stop(m);
}
TEST(tls_pki_md5_signed_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_MD5, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "md5 leaf", "127.0.0.1", 0x100);
    observe(m, "md5 leaf", "127.0.0.1", 0x10100);
    observe(m, "md5 leaf", "127.0.0.1", SECURITY_SET_MASK | 0x10000);
    mts_stop(m);
}
TEST(tls_pki_sha384_signed_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA384, 0, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, 0 } };
    run_prows(m, "sha384", rows, 2);
    mts_stop(m);
}
TEST(tls_pki_rsa1024_leaf) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 1024, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    observe(m, "rsa1024 leaf", "127.0.0.1", 0x100);
    mts_stop(m);
}
TEST(tls_pki_rsa4096_leaf_keybitness) {
    REQUIRE(U(HttpSendRequestA));
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 4096, NULL, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
    EXPECT_EQ(e, 0);
    /* KEY_BITNESS reports the cipher strength, not the RSA modulus size */
    DWORD kb = 0, l = sizeof kb;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_KEY_BITNESS, &kb, &l));
    t_note("rsa4096 server: KEY_BITNESS=%lu", kb);
    CHECK(kb != 4096);
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); l = sizeof ci;
    if (U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l)) {
        EXPECT_EQ(ci.dwKeySize, kb);
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    }
    treq_close(&t);
    mts_stop(m);
}

/* ------------------------------------------------------------------ revocation (CRL distribution point on loopback) */
typedef struct { srv *s; srv_step st[4]; srv_script sc; BYTE *crl; } crl_srv;
/* HTTP server answering every GET with status / body (keep-alive loop) */
static int crl_start(crl_srv *c, int status) {
    memset(c, 0, sizeof *c);
    srv_step head = S_HEAD(), loop = S_LOOP_TO(0), end = S_END();
    c->st[0] = head;
    c->st[1].op = SRV_REPLY; c->st[1].data = ""; c->st[1].n = 0; c->st[1].arg = status;
    c->st[1].hdrs = "Content-Type: application/pkix-crl\r\n";
    c->st[2] = loop; c->st[3] = end;
    c->sc.steps = c->st; c->sc.nsteps = 4;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = &c->sc; cfg.nscripts = 1; cfg.v4_only = 1;
    return srv_start(&cfg, &c->s) == SRV_OK;
}
static void crl_set(crl_srv *c, BYTE *der, DWORD n) { c->crl = der; c->st[1].data = (const char *)der; c->st[1].n = n; }
static void crl_stop(crl_srv *c) { srv_stop(c->s); c->s = NULL; free(c->crl); c->crl = NULL; }
static void crl_report(crl_srv *c, const char *tag) {
    int n = srv_req_count(c->s);
    t_note("%s: CRL server saw %d request(s)%s%s%s%s", tag, n, n ? ": " : "", n ? srv_req_line(c->s, 0) : "",
           n ? " UA=" : "", n && srv_req_header(c->s, 0, "User-Agent") ? srv_req_header(c->s, 0, "User-Agent") : "");
}

TEST(tls_pki_revocation_offline_404) {
    REQUIRE(U(HttpSendRequestA));
    crl_srv c; if (!crl_start(&c, 404)) PKI_SKIP();
    pki_ent *leaf = mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, srv_url(c.s, "/i7.crl"), NULL, NULL);
    mts *m = serve(leaf, 1);
    if (!m) { crl_stop(&c); PKI_SKIP(); }
    int rev = revocation_enabled();
    DWORD e = observe(m, "cdp 404", "127.0.0.1", 0x100);
    crl_report(&c, "cdp 404");
    if (rev) {
        EXPECT_EQ(e, E_REVF);
        CHECK(srv_req_count(c.s) >= 1);
        if (srv_req_count(c.s) >= 1) EXPECT_STR(srv_req_line(c.s, 0), "GET /i7.crl HTTP/1.1");
    } else EXPECT_EQ(e, 0);
    static const prow rows[] = {
        { "127.0.0.1", 0, 0, E_CA },
        { "127.0.0.1", 0x180, 0, 0 },
        { "127.0.0.1", SECURITY_SET_MASK, 0, 0 },
    };
    run_prows(m, "cdp 404", rows, 3);
    mts_stop(m); crl_stop(&c);
}

TEST(tls_pki_revocation_offline_closed_port) {
    REQUIRE(U(HttpSendRequestA));
    /* a port that was just released: connection refused */
    crl_srv c; if (!crl_start(&c, 404)) PKI_SKIP();
    char url[128]; snprintf(url, sizeof url, "%s", srv_url(c.s, "/gone.crl"));
    crl_stop(&c);
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, url, NULL, NULL), 1);
    if (!m) PKI_SKIP();
    DWORD t0 = GetTickCount();
    DWORD e = observe(m, "cdp refused", "127.0.0.1", 0x100);
    t_note("cdp refused: %lu ms", GetTickCount() - t0);
    if (revocation_enabled()) EXPECT_EQ(e, E_REVF); else EXPECT_EQ(e, 0);
    static const prow rows[] = { { "127.0.0.1", 0x180, 0, 0 } };
    run_prows(m, "cdp refused", rows, 1);
    mts_stop(m);
}

TEST(tls_pki_revocation_good_crl) {
    REQUIRE(U(HttpSendRequestA));
    crl_srv c; if (!crl_start(&c, 200)) PKI_SKIP();
    pki_ent *leaf = mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, srv_url(c.s, "/good.crl"), NULL, NULL);
    DWORD n = 0; BYTE *der = leaf ? pki_crl(pki_root(), NULL, 0, 7, &n) : NULL;
    if (!der) { crl_stop(&c); PKI_SKIP(); }
    crl_set(&c, der, n);
    mts *m = serve(leaf, 1);
    if (!m) { crl_stop(&c); PKI_SKIP(); }
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA }, { "127.0.0.1", 0x100, 0, 0 } };
    run_prows(m, "good crl", rows, 2);
    crl_report(&c, "good crl");
    if (revocation_enabled()) CHECK(srv_req_count(c.s) >= 1);
    mts_stop(m); crl_stop(&c);
}

TEST(tls_pki_revocation_revoked) {
    REQUIRE(U(HttpSendRequestA));
    crl_srv c; if (!crl_start(&c, 200)) PKI_SKIP();
    pki_ent *leaf = mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, srv_url(c.s, "/revoked.crl"), NULL, NULL);
    pki_ent *rv[1] = { leaf };
    DWORD n = 0; BYTE *der = leaf ? pki_crl(pki_root(), rv, 1, 7, &n) : NULL;
    if (!der) { crl_stop(&c); PKI_SKIP(); }
    crl_set(&c, der, n);
    mts *m = serve(leaf, 1);
    if (!m) { crl_stop(&c); PKI_SKIP(); }
    int rev = revocation_enabled();
    DWORD e = observe(m, "revoked", "127.0.0.1", 0x100);
    crl_report(&c, "revoked");
    EXPECT_EQ(e, rev ? E_REVD : 0);
    /* IGNORE_REVOCATION covers an unknown status, not a revoked certificate */
    e = observe(m, "revoked", "127.0.0.1", 0x180);
    EXPECT_EQ(e, rev ? E_REVD : 0);
    e = observe(m, "revoked", "127.0.0.1", SECURITY_SET_MASK | 0x10000);
    EXPECT_EQ(e, rev ? E_REVD : 0);
    static const prow rows[] = { { "127.0.0.1", 0, 0, E_CA } };
    run_prows(m, "revoked", rows, 1);
    mts_stop(m); crl_stop(&c);
}

TEST(tls_pki_revocation_retry_same_handle) {
    REQUIRE(U(HttpSendRequestA));
    if (!revocation_enabled()) { t_skip("CertificateRevocation disabled"); return; }
    crl_srv c; if (!crl_start(&c, 404)) PKI_SKIP();
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, srv_url(c.s, "/r.crl"), NULL, NULL), 1);
    if (!m) { crl_stop(&c); PKI_SKIP(); }
    treq t;
    if (!treq_open(&t, "127.0.0.1", mts_port(m), "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE)) { treq_close(&t); mts_stop(m); crl_stop(&c); t_skip("open"); return; }
    SEND_EQ(&t, E_CA);
    t_https_secflags(t.hr, 0x100);
    SEND_EQ(&t, E_REVF);
    DWORD f = tls_secflags(t.hr);
    t_note("secflags after 12057: 0x%lx", f);
    EXPECT_EQ(f & 0x100, 0x100);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, 0);
    SEND_EQ(&t, E_REVF);                 /* unchanged flags: the same error again */
    t_https_secflags(t.hr, 0x80);
    SEND_EQ(&t, 0);
    EXPECT_EQ(treq_status(&t), 200);
    f = tls_secflags(t.hr);
    EXPECT_EQ(f & 0x180, 0x180);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, SECURITY_FLAG_SECURE);
    char b[16]; treq_body(&t, b, sizeof b);
    treq_close(&t);
    EXPECT_EQ(mts_requests(m), 1);
    mts_stop(m); crl_stop(&c);
}

TEST(tls_pki_revocation_crl_wire) {
    REQUIRE(U(HttpSendRequestA));
    if (!revocation_enabled()) { t_skip("CertificateRevocation disabled"); return; }
    crl_srv c; if (!crl_start(&c, 404)) PKI_SKIP();
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, srv_url(c.s, "/wire.crl"), NULL, NULL), 1);
    if (!m) { crl_stop(&c); PKI_SKIP(); }
    DWORD st; pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, NULL);
    int n = srv_req_count(c.s);
    CHECK(n >= 1);
    if (n >= 1) {
        EXPECT_STR(srv_req_method(c.s, 0), "GET");
        EXPECT_STR(srv_req_target(c.s, 0), "/wire.crl");
        const char *ua = srv_req_header(c.s, 0, "User-Agent");
        t_note("CRL fetch UA=%s Host=%s", ua ? ua : "(none)", srv_req_header(c.s, 0, "Host") ? srv_req_header(c.s, 0, "Host") : "(none)");
        CHECK(ua && strstr(ua, "Microsoft-CryptoAPI") == ua);
        EXPECT_STR(srv_req_header(c.s, 0, "Host"), srv_hostport(c.s));
        for (int h = 0; h < srv_req_header_count(c.s, 0); h++) t_note("  CRL hdr %s: %s", srv_req_header_name(c.s, 0, h), srv_req_header_value(c.s, 0, h));
    }
    mts_stop(m); crl_stop(&c);
}

/* ------------------------------------------------------------------ AIA: issuer not sent by the server */
TEST(tls_pki_aia_issuer_fetch) {
    REQUIRE(U(HttpSendRequestA));
    crl_srv c; if (!crl_start(&c, 200)) PKI_SKIP();
    c.st[1].hdrs = "Content-Type: application/pkix-cert\r\n";
    pki_ent *root = pki_root();
    if (!root) { crl_stop(&c); PKI_SKIP(); }
    BYTE *der = malloc(root->cert->cbCertEncoded); memcpy(der, root->cert->pbCertEncoded, root->cert->cbCertEncoded);
    crl_set(&c, der, root->cert->cbCertEncoded);
    mts *m = serve(mk_leaf("CN=localhost", SAN_LOCAL, PKI_EKU_SERVER, -1, 30, PKI_SHA256, 0, NULL, srv_url(c.s, "/ca.crt"), NULL), 0);
    if (!m) { crl_stop(&c); PKI_SKIP(); }
    observe(m, "aia leaf-only", "127.0.0.1", 0);
    crl_report(&c, "aia");
    observe(m, "aia leaf-only", "127.0.0.1", 0x100);
    mts_stop(m); crl_stop(&c);
}

/* ------------------------------------------------------------------ security flags read-back with an issued chain */
TEST(tls_pki_secflags_readback) {
    REQUIRE(U(InternetQueryOptionA));
    mts *m = serve(good_leaf(), 1);
    if (!m) PKI_SKIP();
    treq t; DWORD st;
    DWORD e = pki_get("127.0.0.1", mts_port(m), 0x100, 0, &st, &t);
    EXPECT_EQ(e, 0);
    DWORD f = tls_secflags(t.hr);
    t_note("issued chain success secflags=0x%lx", f);
    EXPECT_EQ(f & 0x100, 0x100);
    EXPECT_EQ(f & SECURITY_FLAG_SECURE, SECURITY_FLAG_SECURE);
    EXPECT_EQ(f & 0x20000000, 0x20000000);
    EXPECT_EQ(f & 0x3280, 0);
    treq_close(&t);
    mts_stop(m);
}
