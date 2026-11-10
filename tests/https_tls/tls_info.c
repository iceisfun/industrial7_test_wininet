/* tls_info.c - security information queries on a request handle:
 *   32  SECURITY_CERTIFICATE_STRUCT (INTERNET_CERTIFICATE_INFO, 64 bytes on x64)
 *   35  SECURITY_CERTIFICATE (formatted string)
 *   36  SECURITY_KEY_BITNESS
 *   66  SECURITY_CONNECTION_INFO (716 bytes)
 *   105 SERVER_CERT_CHAIN_CONTEXT
 * Decomp (InternetQueryOptionA): all request-handle-only (others 12018). 32/35/36 call GetSecurityInfo, which fails
 * with 12004 when the request has no security cache entry -> the query returns 12016. ConvertSecurityInfoIntoCertInfoStruct
 * fills ftExpiry=NotAfter, ftStart=NotBefore, subject/issuer via CertNameToStrA(0x28000001) (LocalAlloc'd), leaves the
 * protocol/signature/encryption name pointers NULL and copies dwKeySize. 66 requires >= 0x2CC (else 122) and on 12004
 * returns TRUE with fSecure=0. 105 needs >= 8 (else 122) and returns 12019 without a chain. */
#include "tls_util.h"

static __typeof__(&CertFreeCertificateChain) p_free_chain(void) { return UIN("crypt32.dll", CertFreeCertificateChain); }

/* a request that completed over TLS (0x100) against srv s; 1 on success */
static int good_request(treq *t, srv *s, const char *host) {
    if (!treq_open(t, host ? host : "127.0.0.1", srv_port(s), "GET", "/i", T_INET_FRESH | INTERNET_FLAG_SECURE)) return 0;
    t_https_secflags(t->hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    DWORD e = treq_send(t);
    if (e == ERROR_INTERNET_CONNECTION_ABORTED || e == ERROR_INTERNET_CONNECTION_RESET) {
        /* seen once on the VM (boot tls5): a transient abort of a fresh loopback connection; retry once on the same handle */
        t_note("good_request: transient %lu, retrying once", e);
        e = treq_send(t);
    }
    if (e) { t_note("good_request failed: %lu %s", e, t_inet_errname(e)); return 0; }
    char b[64]; treq_body(t, b, sizeof b);
    return 1;
}

static int ft_eq(FILETIME a, FILETIME b) { return a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime; }

/* ------------------------------------------------------------------ 32 SECURITY_CERTIFICATE_STRUCT */
TEST(tls_info_certstruct_size) {
    EXPECT_EQ(sizeof(INTERNET_CERTIFICATE_INFO), 64);
    EXPECT_EQ(offsetof(INTERNET_CERTIFICATE_INFO, lpszSubjectInfo), 16);
    EXPECT_EQ(offsetof(INTERNET_CERTIFICATE_INFO, dwKeySize), 56);
}

TEST(tls_info_certstruct_after_success) {
    REQUIRE(U(InternetQueryOptionA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    PCCERT_CONTEXT sc = srv_cert_get(SRV_CERT_LOCALHOST);
    treq t; CHECK(good_request(&t, s, NULL));
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0xCC, sizeof ci); DWORD l = sizeof ci;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
    CHECKF(ok, "err=%lu", GetLastError());
    if (ok) {
        EXPECT_EQ(l, sizeof ci);
        CHECK(sc && ft_eq(ci.ftExpiry, sc->pCertInfo->NotAfter));
        CHECK(sc && ft_eq(ci.ftStart, sc->pCertInfo->NotBefore));
        EXPECT_STR(ci.lpszSubjectInfo, "localhost");
        EXPECT_STR(ci.lpszIssuerInfo, "localhost");
        CHECK(ci.lpszProtocolName == NULL);
        CHECK(ci.lpszSignatureAlgName == NULL);
        CHECK(ci.lpszEncryptionAlgName == NULL);
        t_note("certstruct dwKeySize=%lu", ci.dwKeySize);
        EXPECT_EQ(ci.dwKeySize, 256);
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    }
    treq_close(&t); srv_stop(s);
}

TEST(tls_info_certstruct_cn_other) {
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/i", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x1100);
    SEND_EQ(&t, 0);
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); DWORD l = sizeof ci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l));
    EXPECT_STR(ci.lpszSubjectInfo, "i7-other.invalid");
    EXPECT_STR(ci.lpszIssuerInfo, "i7-other.invalid");
    if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
    if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    treq_close(&t); srv_stop(s);
}

/* the expired certificate's validity is reported verbatim */
TEST(tls_info_certstruct_expired_dates) {
    srv *s = tls_srv(SRV_CERT_EXPIRED, NULL, 0); if (!s) TLS_SKIP_SRV();
    PCCERT_CONTEXT sc = srv_cert_get(SRV_CERT_EXPIRED);
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/i", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x2100);
    SEND_EQ(&t, 0);
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); DWORD l = sizeof ci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l));
    CHECK(sc && ft_eq(ci.ftExpiry, sc->pCertInfo->NotAfter));
    CHECK(sc && ft_eq(ci.ftStart, sc->pCertInfo->NotBefore));
    FILETIME now; GetSystemTimeAsFileTime(&now);
    CHECK(CompareFileTime(&ci.ftExpiry, &now) < 0);
    CHECK(CompareFileTime(&ci.ftStart, &ci.ftExpiry) < 0);
    if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
    if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    treq_close(&t); srv_stop(s);
}

/* after a failed (12045) handshake the struct still describes the server certificate */
TEST(tls_info_certstruct_after_ca_failure) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/i", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, ERROR_INTERNET_INVALID_CA);
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); DWORD l = sizeof ci;
    SET_ERR(0);
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
    t_note("certstruct after 12045: ok=%d err=%lu subject=%s", ok, ok ? 0 : GetLastError(), ok && ci.lpszSubjectInfo ? ci.lpszSubjectInfo : "(null)");
    CHECK(ok);
    if (ok) {
        EXPECT_STR(ci.lpszSubjectInfo, "localhost");
        if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
        if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    }
    treq_close(&t); srv_stop(s);
}

TEST(tls_info_certstruct_buffer_sizes) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    INTERNET_CERTIFICATE_INFO ci; DWORD l;
    /* NULL buffer / zero length */
    l = 0; SET_ERR(0);
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, NULL, &l);
    DWORD e = ok ? 0 : GetLastError();
    t_note("certstruct NULL/0: ok=%d err=%lu len=%lu", ok, e, l);
    CHECK(ok); EXPECT_EQ(l, 64);        /* decomp ConvertSecurityInfoIntoCertInfoStruct: NULL/0 -> size only, success */
    /* short */
    static const DWORD lens[] = { 1, 8, 32, 63 };
    for (size_t i = 0; i < 4; i++) {
        memset(&ci, 0, sizeof ci); l = lens[i]; SET_ERR(0);
        ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l);
        e = ok ? 0 : GetLastError();
        t_note("certstruct len %lu: ok=%d err=%lu len=%lu", lens[i], ok, e, l);
        CHECK(!ok);
        CHECKF(e == ERROR_INTERNET_INTERNAL_ERROR, "len %lu err %lu", lens[i], e);   /* decomp: short -> 12004 */
        EXPECT_EQ(l, 64);
    }
    /* larger than needed */
    char big[128]; memset(big, 0x5A, sizeof big); l = sizeof big;
    ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, big, &l);
    CHECK(ok); EXPECT_EQ(l, 64);
    EXPECT_EQ((unsigned char)big[100], 0x5A);
    if (ok) { INTERNET_CERTIFICATE_INFO *p = (void *)big; LocalFree(p->lpszSubjectInfo); LocalFree(p->lpszIssuerInfo); }
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ non-TLS / not-yet-sent requests */
typedef struct { DWORD opt; DWORD len; } optlen;
static const optlen k_secopts[] = {
    { INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, 64 }, { INTERNET_OPTION_SECURITY_CERTIFICATE, 512 },
    { INTERNET_OPTION_SECURITY_KEY_BITNESS, 4 },
};

TEST(tls_info_plain_http_request_invalid_operation) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "plain"), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/p", T_INET_FRESH));
    for (int sent = 0; sent < 2; sent++) {
        if (sent) { SEND_EQ(&t, 0); char b[16]; treq_body(&t, b, sizeof b); }
        for (size_t i = 0; i < sizeof k_secopts / sizeof k_secopts[0]; i++) {
            char buf[512]; DWORD l = k_secopts[i].len; SET_ERR(0);
            BOOL ok = U(InternetQueryOptionA)(t.hr, k_secopts[i].opt, buf, &l);
            DWORD e = ok ? 0 : GetLastError();
            CHECKF(!ok && e == ERROR_INTERNET_INVALID_OPERATION, "sent=%d opt %lu: ok=%d err=%lu", sent, k_secopts[i].opt, ok, e);
        }
        /* 66: TRUE with fSecure = 0 */
        tls_sec_conn_info sci; memset(&sci, 0xCC, sizeof sci); DWORD l = sizeof sci;
        BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l);
        CHECKF(ok, "sent=%d err=%lu", sent, GetLastError());
        EXPECT_EQ(sci.dwSize, 0x2CC); EXPECT_EQ(sci.fSecure, 0);
        /* 105: no chain */
        PCCERT_CHAIN_CONTEXT ch = (PCCERT_CHAIN_CONTEXT)1; l = sizeof ch; SET_ERR(0);
        ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
        DWORD e = ok ? 0 : GetLastError();
        CHECKF(!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_STATE, "sent=%d chain: ok=%d err=%lu", sent, ok, e);
        if (ok && ch) p_free_chain()(ch);
    }
    treq_close(&t); srv_stop(s);
}

TEST(tls_info_https_request_before_send) {
    treq t; CHECK(treq_open(&t, "127.0.0.1", 443, "GET", "/b", T_INET_FRESH | INTERNET_FLAG_SECURE));
    for (size_t i = 0; i < sizeof k_secopts / sizeof k_secopts[0]; i++) {
        char buf[512]; DWORD l = k_secopts[i].len; SET_ERR(0);
        BOOL ok = U(InternetQueryOptionA)(t.hr, k_secopts[i].opt, buf, &l);
        DWORD e = ok ? 0 : GetLastError();
        t_note("unsent https opt %lu: ok=%d err=%lu first dword=0x%lx", k_secopts[i].opt, ok, e, *(DWORD *)buf);
        CHECKF(ok, "opt %lu before send: err=%lu (Win10 VM: the security entry exists from HttpOpenRequest)", k_secopts[i].opt, e);
        if (ok && k_secopts[i].opt == INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT) {
            INTERNET_CERTIFICATE_INFO *ci = (void *)buf;
            t_note("unsent certstruct: subject=%p issuer=%p key=%lu", ci->lpszSubjectInfo, ci->lpszIssuerInfo, ci->dwKeySize);
            CHECK(ci->lpszSubjectInfo == NULL && ci->lpszIssuerInfo == NULL);
        }
    }
    tls_sec_conn_info sci; memset(&sci, 0xCC, sizeof sci); DWORD l = sizeof sci;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l);
    t_note("unsent https opt 66: ok=%d err=%lu dwSize=%lu fSecure=%d proto=0x%lx", ok, ok ? 0 : GetLastError(), sci.dwSize, sci.fSecure, sci.connectionInfo.dwProtocol);
    CHECK(ok);
    EXPECT_EQ(sci.dwSize, 0x2CC);
    PCCERT_CHAIN_CONTEXT ch = NULL; l = sizeof ch; SET_ERR(0);
    ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
    DWORD e = ok ? 0 : GetLastError();
    CHECKF(!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_STATE, "chain before send: ok=%d err=%lu", ok, e);
    if (ok && ch) p_free_chain()(ch);
    treq_close(&t);
}

/* session and connect handles: 12018 for every security info option */
TEST(tls_info_wrong_handle_types) {
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    static const DWORD opts[] = { INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, INTERNET_OPTION_SECURITY_CERTIFICATE,
                                  INTERNET_OPTION_SECURITY_KEY_BITNESS, INTERNET_OPTION_SECURITY_CONNECTION_INFO,
                                  INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, INTERNET_OPTION_HTTP_PROTOCOL_USED };
    HINTERNET hs[2] = { hi, hc };
    for (int h = 0; h < 2; h++)
        for (size_t i = 0; i < sizeof opts / sizeof opts[0]; i++) {
            char buf[1024]; DWORD l = sizeof buf; SET_ERR(0);
            BOOL ok = U(InternetQueryOptionA)(hs[h], opts[i], buf, &l);
            DWORD e = ok ? 0 : GetLastError();
            CHECKF(!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "%s opt %lu: ok=%d err=%lu", h ? "connect" : "session", opts[i], ok, e);
        }
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}

/* ------------------------------------------------------------------ 35 SECURITY_CERTIFICATE (string) */
TEST(tls_info_certificate_string) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    char buf[2048]; DWORD l = sizeof buf; memset(buf, 0, sizeof buf);
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, buf, &l);
    CHECKF(ok, "err=%lu", GetLastError());
    t_note("certificate string (%lu chars): %.300s", l, buf);
    CHECK(strstr(buf, "localhost") != NULL);
    EXPECT_EQ(l, strlen(buf));
    /* sizing quirk (decomp case 0x23 + Win10 VM): any buffer shorter than strlen+1 -> 122 and *len = 1, not the needed size */
    DWORD need = l + 1, l2 = 4; char tiny[4]; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, tiny, &l2), ERROR_INSUFFICIENT_BUFFER);
    t_note("short query asked for %lu (string %lu)", l2, l);
    EXPECT_EQ(l2, 1);
    l2 = l; SET_ERR(0);   /* exactly strlen: no room for the NUL */
    EXPECT_FAIL(!U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, buf, &l2), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l2, 1);
    l2 = need;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, buf, &l2));
    EXPECT_EQ(l2, need - 1);
    /* W: InternetQueryOptionW has no conversion branch for 35: the ANSI bytes come back unchanged */
    WCHAR wb[2048]; DWORD wl = sizeof wb; memset(wb, 0, sizeof wb);
    ok = U(InternetQueryOptionW)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE, wb, &wl);
    CHECKF(ok, "W err=%lu", GetLastError());
    t_note("W certificate string length field %lu", wl);
    CHECK(strstr((char *)wb, "localhost") != NULL);
    EXPECT_EQ(wl, l);
    CHECK(!memcmp(wb, buf, l));
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ 36 SECURITY_KEY_BITNESS */
TEST(tls_info_key_bitness) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    DWORD kb = 0, l = sizeof kb;
    CHECKF(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_KEY_BITNESS, &kb, &l), "err=%lu", GetLastError());
    EXPECT_EQ(l, 4);
    t_note("key bitness %lu", kb);
    /* same value as the certificate struct's dwKeySize and the connection info's cipher strength */
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); l = sizeof ci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l));
    EXPECT_EQ(kb, ci.dwKeySize);
    if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
    if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    tls_sec_conn_info sci; memset(&sci, 0, sizeof sci); l = sizeof sci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l));
    EXPECT_EQ(kb, sci.connectionInfo.dwCipherStrength);
    l = 3; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_KEY_BITNESS, &kb, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 4);
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ 66 SECURITY_CONNECTION_INFO */
TEST(tls_info_connection_info_size_rule) {
    EXPECT_EQ(sizeof(tls_sec_conn_info), 0x2CC);
    EXPECT_EQ(offsetof(tls_sec_conn_info, cipherInfo), 0x24);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    static const DWORD lens[] = { 0, 4, 36, 0x2CB };
    for (size_t i = 0; i < 4; i++) {
        tls_sec_conn_info sci; DWORD l = lens[i]; SET_ERR(0);
        BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l);
        DWORD e = ok ? 0 : GetLastError();
        CHECKF(!ok && e == ERROR_INSUFFICIENT_BUFFER, "len %lu: ok=%d err=%lu", lens[i], ok, e);
        CHECKF(l == 0x2CC, "len %lu -> needed %lu", lens[i], l);
    }
    treq_close(&t); srv_stop(s);
}

TEST(tls_info_connection_info_after_success) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    tls_sec_conn_info sci; memset(&sci, 0xCC, sizeof sci); DWORD l = sizeof sci;
    CHECKF(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l), "err=%lu", GetLastError());
    EXPECT_EQ(l, 0x2CC);
    EXPECT_EQ(sci.dwSize, 0x2CC);
    EXPECT_EQ(sci.fSecure, 1);
    tls_conn_info *c = &sci.connectionInfo; tls_cipher_info *k = &sci.cipherInfo;
    t_note("conn: proto=0x%lx cipher=0x%lx strength=%lu hash=0x%lx/%lu exch=0x%lx/%lu", c->dwProtocol, c->aiCipher, c->dwCipherStrength, c->aiHash, c->dwHashStrength, c->aiExch, c->dwExchStrength);
    t_note("cipherinfo: ver=%lu proto=0x%lx suite=0x%lx base=0x%lx name=%ls cipher=%ls len=%lu hash=%ls exch=%ls cert=%ls keytype=%lu",
           k->dwVersion, k->dwProtocol, k->dwCipherSuite, k->dwBaseCipherSuite, k->szCipherSuite, k->szCipher, k->dwCipherLen, k->szHash, k->szExchange, k->szCertificate, k->dwKeyType);
    EXPECT_EQ(c->dwProtocol, TLS_SP_TLS1_2_CLIENT);
    EXPECT_EQ(k->dwProtocol, 0x0303);                 /* TLS 1.2 wire version in CipherInfo */
    EXPECT_EQ(k->dwVersion, SECPKGCONTEXT_CIPHERINFO_V1);
    /* both ends agree: the server's own schannel view (TLS_DONE) */
    const char *d = tls_done_data(s, 0);
    CHECK(d != NULL);
    if (d) {
        EXPECT_EQ(c->aiCipher, tls_ev_field(d, "cipher"));
        EXPECT_EQ(k->dwCipherSuite, tls_ev_field(d, "suite"));
        EXPECT_EQ(tls_ev_field(d, "proto"), TLS_SP_TLS1_2_SERVER);
    }
    CHECK(k->szCipherSuite[0] != 0);
    CHECK(wcsncmp(k->szCipherSuite, L"TLS_", 4) == 0);
    CHECK(k->dwCipherLen > 0);
    treq_close(&t); srv_stop(s);
}

TEST(tls_info_connection_info_after_failure) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/f", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, ERROR_INTERNET_INVALID_CA);
    tls_sec_conn_info sci; memset(&sci, 0xCC, sizeof sci); DWORD l = sizeof sci;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l);
    t_note("after 12045: ok=%d dwSize=%lu fSecure=%d proto=0x%lx suite=0x%lx", ok, sci.dwSize, sci.fSecure, sci.connectionInfo.dwProtocol, sci.cipherInfo.dwCipherSuite);
    CHECK(ok);
    EXPECT_EQ(sci.dwSize, 0x2CC);
    EXPECT_EQ(sci.fSecure, 1);
    EXPECT_EQ(sci.connectionInfo.dwProtocol, 0);       /* 04 F10: zeros after a failed verification */
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ 105 SERVER_CERT_CHAIN_CONTEXT */
TEST(tls_info_server_chain_after_success) {
    REQUIRE(p_free_chain());
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    PCCERT_CONTEXT sc = srv_cert_get(SRV_CERT_LOCALHOST);
    treq t; CHECK(good_request(&t, s, NULL));
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = sizeof ch;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
    CHECKF(ok && ch, "err=%lu", GetLastError());
    EXPECT_EQ(l, 8);
    if (ok && ch) {
        CHECK(ch->cChain >= 1);
        PCERT_SIMPLE_CHAIN sch = ch->rgpChain[0];
        CHECK(sch->cElement == 1);                       /* self-signed: leaf == root */
        PCCERT_CONTEXT leaf = sch->rgpElement[0]->pCertContext;
        CHECK(sc && leaf && leaf->cbCertEncoded == sc->cbCertEncoded && !memcmp(leaf->pbCertEncoded, sc->pbCertEncoded, sc->cbCertEncoded));
        t_note("chain trust error=0x%lx info=0x%lx", ch->TrustStatus.dwErrorStatus, ch->TrustStatus.dwInfoStatus);
        CHECK(ch->TrustStatus.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT);
        t_note("element[0] trust error=0x%lx info=0x%lx", sch->rgpElement[0]->TrustStatus.dwErrorStatus, sch->rgpElement[0]->TrustStatus.dwInfoStatus);
        CHECK(sch->rgpElement[0]->TrustStatus.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED);
        p_free_chain()(ch);
    }
    /* each query hands out a new reference */
    PCCERT_CHAIN_CONTEXT c1 = NULL, c2 = NULL; l = 8;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &c1, &l)); l = 8;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &c2, &l));
    CHECK(c1 && c1 == c2);
    if (c1) p_free_chain()(c1);
    if (c2) p_free_chain()(c2);
    treq_close(&t); srv_stop(s);
}

TEST(tls_info_server_chain_short_buffer) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    for (DWORD len = 0; len < 8; len += 4) {
        PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = len; SET_ERR(0);
        EXPECT_FAIL(!U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 8);
        CHECK(ch == NULL);
    }
    treq_close(&t); srv_stop(s);
}

/* after a verification failure the (unverified) chain is still available: decomp falls back to
 * DuplicateUnverifiedCertChain */
TEST(tls_info_server_chain_after_failure) {
    REQUIRE(p_free_chain());
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    PCCERT_CONTEXT sc = srv_cert_get(SRV_CERT_CN_OTHER);
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/f", T_INET_FRESH | INTERNET_FLAG_SECURE));
    SEND_EQ(&t, ERROR_INTERNET_INVALID_CA);
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = sizeof ch; SET_ERR(0);
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l);
    t_note("chain after 12045: ok=%d err=%lu ch=%p", ok, ok ? 0 : GetLastError(), ch);
    CHECK(ok && ch);
    if (ok && ch) {
        PCCERT_CONTEXT leaf = ch->rgpChain[0]->rgpElement[0]->pCertContext;
        CHECK(sc && leaf->cbCertEncoded == sc->cbCertEncoded && !memcmp(leaf->pbCertEncoded, sc->pbCertEncoded, sc->cbCertEncoded));
        p_free_chain()(ch);
    }
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ HTTP_PROTOCOL_USED (149) */
TEST(tls_info_http_protocol_used) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/h", T_INET_FRESH | INTERNET_FLAG_SECURE));
    DWORD v = 0xDEAD, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_HTTP_PROTOCOL_USED, &v, &l));
    EXPECT_EQ(v, 0);
    l = 3; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_HTTP_PROTOCOL_USED, &v, &l), ERROR_INTERNET_BAD_OPTION_LENGTH);
    t_https_secflags(t.hr, 0x100);
    DWORD se = treq_send(&t);
    if (se == ERROR_INTERNET_CONNECTION_ABORTED) { t_note("first send aborted (12030), retrying once"); se = treq_send(&t); }
    EXPECT_EQ(se, 0);
    l = sizeof v; v = 0xDEAD;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_HTTP_PROTOCOL_USED, &v, &l));
    EXPECT_EQ(v, 0);                                   /* HTTP/1.1, not HTTP_PROTOCOL_FLAG_HTTP2 */
    treq_close(&t); srv_stop(s);
}

/* the same information through a localhost URL (SNI path) */
TEST(tls_info_localhost_host) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, "localhost"));
    INTERNET_CERTIFICATE_INFO ci; memset(&ci, 0, sizeof ci); DWORD l = sizeof ci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l));
    EXPECT_STR(ci.lpszSubjectInfo, "localhost");
    if (ci.lpszSubjectInfo) LocalFree(ci.lpszSubjectInfo);
    if (ci.lpszIssuerInfo) LocalFree(ci.lpszIssuerInfo);
    char hostport[64]; snprintf(hostport, sizeof hostport, "localhost:%u", srv_port(s));
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_STR(srv_req_header(s, 0, "Host"), hostport);
    treq_close(&t); srv_stop(s);
}

/* INTERNET_OPTION_URL of a secure request is https:// */
TEST(tls_info_url_option_scheme) {
    treq t; CHECK(treq_open(&t, "127.0.0.1", 8443, "GET", "/path?q=1", T_INET_FRESH | INTERNET_FLAG_SECURE));
    char url[256]; DWORD l = sizeof url;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_URL, url, &l));
    EXPECT_STR(url, "https://127.0.0.1:8443/path?q=1");
    treq_close(&t);
    CHECK(treq_open(&t, "127.0.0.1", 443, "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE));
    l = sizeof url;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_URL, url, &l));
    EXPECT_STR(url, "https://127.0.0.1/p");
    treq_close(&t);
    CHECK(treq_open(&t, "127.0.0.1", 443, "GET", "/p", T_INET_FRESH));
    l = sizeof url;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_URL, url, &l));
    EXPECT_STR(url, "http://127.0.0.1:443/p");
    treq_close(&t);
    /* INTERNET_DEFAULT_PORT (0) with SECURE -> 443 */
    CHECK(treq_open(&t, "127.0.0.1", 0, "GET", "/p", T_INET_FRESH | INTERNET_FLAG_SECURE));
    l = sizeof url;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_URL, url, &l));
    t_note("port 0 + SECURE url=%s", url);
    EXPECT_STR(url, "https://127.0.0.1:80/p");             /* Win10 VM: port 0 resolved at InternetConnect (no SECURE there) -> 80 */
    treq_close(&t);
}

/* REQUEST_FLAGS (23) on a TLS request: probe */
TEST(tls_info_request_flags_probe) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(good_request(&t, s, NULL));
    DWORD rf = 0, l = sizeof rf;
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_REQUEST_FLAGS, &rf, &l);
    t_note("request flags after TLS GET: ok=%d 0x%lx", ok, rf);
    CHECK(ok);
    treq_close(&t); srv_stop(s);
}
