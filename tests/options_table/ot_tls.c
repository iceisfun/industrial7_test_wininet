/* options_table: TLS-only options on a completed HTTPS request (fixture kind T: loopback schannel server,
 * SRV_CERT_LOCALHOST, sent with SECURITY_FLAG_IGNORE_UNKNOWN_CA) versus a plain HTTP request (X).
 * Decomp: InternetQueryOptionA case 0x1f (SECURITY_FLAGS), 0x20 (CERTIFICATE_STRUCT), 0x23 (SECURITY_CERTIFICATE),
 * 0x24 (KEY_BITNESS), 0x69 (SERVER_CERT_CHAIN_CONTEXT). The lab negotiates TLS 1.2 ECDHE_RSA_AES_256_GCM (SRV.md). */
#include "ot.h"
#include <wincrypt.h>

static ot_fx *tls_fx(void) {
    ot_fx *fx = ot_fx_all();
    if (!fx || !fx->h[OT_T]) return NULL;
    return fx;
}

TEST(ot_tls_security_flags_after_handshake) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = tls_fx(); if (!fx) { t_skip("HTTPS fixture unavailable"); return; }
    DWORD v;
    CHECK(ot_qdw(fx->h[OT_T], INTERNET_OPTION_SECURITY_FLAGS, &v));
    CHECKF(v & SECURITY_FLAG_SECURE, "flags 0x%lx", v);
    CHECKF(v & SECURITY_FLAG_IGNORE_UNKNOWN_CA, "flags 0x%lx (the ignore bit set before the send stays)", v);
    t_note("T SECURITY_FLAGS 0x%lx (04 F8 measured 0x20000101)", v);
    CHECK(ot_qdw(fx->h[OT_X], INTERNET_OPTION_SECURITY_FLAGS, &v));
    CHECKF(!(v & SECURITY_FLAG_SECURE), "plain HTTP request flags 0x%lx", v);
    t_note("X SECURITY_FLAGS 0x%lx", v);
}

TEST(ot_tls_key_bitness) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = tls_fx(); if (!fx) { t_skip("HTTPS fixture unavailable"); return; }
    for (int w = 0; w < 2; w++) {
        DWORD v = 0, l = sizeof v;
        CHECK(ot_q(w, fx->h[OT_T], INTERNET_OPTION_SECURITY_KEY_BITNESS, &v, &l));
        EXPECT_EQ(l, 4);
        CHECKF(v == 128 || v == 256, "key bitness %lu", v);
        t_note("KEY_BITNESS %lu", v);
    }
}

TEST(ot_tls_certificate_struct) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = tls_fx(); if (!fx) { t_skip("HTTPS fixture unavailable"); return; }
    INTERNET_CERTIFICATE_INFO ci; DWORD l = 0;
    /* VM: a NULL buffer is not an error here (TRUE, *len = 64, nothing written); a short buffer fails with
     * 12004 ERROR_INTERNET_INTERNAL_ERROR, not 122 */
    SET_ERR(0xdead); CHECK(U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, NULL, &l));
    EXPECT_EQ(l, sizeof ci);
    l = sizeof ci - 1;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l), ERROR_INTERNET_INTERNAL_ERROR);
    EXPECT_EQ(l, sizeof ci);
    l = 1;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l), ERROR_INTERNET_INTERNAL_ERROR);
    memset(&ci, 0, sizeof ci); l = sizeof ci;
    CHECK(U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l));
    EXPECT_EQ(l, sizeof ci);
    CHECK(ci.lpszSubjectInfo && strstr(ci.lpszSubjectInfo, "localhost"));
    CHECK(ci.lpszIssuerInfo && strstr(ci.lpszIssuerInfo, "localhost"));      /* self-signed */
    CHECK(CompareFileTime(&ci.ftExpiry, &ci.ftStart) > 0);
    CHECKF(ci.dwKeySize == 128 || ci.dwKeySize == 256, "dwKeySize %lu", ci.dwKeySize);
    t_note("cert subject '%s' protocol '%s' sig '%s' enc '%s' key %lu", ci.lpszSubjectInfo ? ci.lpszSubjectInfo : "(null)",
           ci.lpszProtocolName ? ci.lpszProtocolName : "(null)", ci.lpszSignatureAlgName ? ci.lpszSignatureAlgName : "(null)",
           ci.lpszEncryptionAlgName ? ci.lpszEncryptionAlgName : "(null)", ci.dwKeySize);
    LocalFree(ci.lpszSubjectInfo); LocalFree(ci.lpszIssuerInfo); LocalFree(ci.lpszProtocolName);
    LocalFree(ci.lpszSignatureAlgName); LocalFree(ci.lpszEncryptionAlgName);
}

TEST(ot_tls_certificate_string) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = tls_fx(); if (!fx) { t_skip("HTTPS fixture unavailable"); return; }
    /* VM: the formatted certificate is built into the caller's buffer, so the size probe cannot report it:
     * NULL buffer or any buffer that is too small -> 122 with *len = 1; a large buffer -> TRUE, *len = strlen. */
    DWORD l = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 1);
    static char b[4096]; DWORD n = sizeof b; memset(b, 0xCC, sizeof b);
    CHECK(U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, b, &n));
    CHECKF(n > 16 && n < sizeof b && strlen(b) == n, "len %lu strlen %u", n, (unsigned)strlen(b));
    CHECK(!strncmp(b, "Subject:\r\nlocalhost\r\nIssuer:\r\nlocalhost\r\n", 39));
    t_note("SECURITY_CERTIFICATE (%lu chars): %.200s", n, b);
    DWORD l2 = n; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, b, &l2), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l2, 1);
    /* strlen + 1 (room for the NUL) is enough: TRUE, *len = strlen (VM) */
    l2 = n + 1; SET_ERR(0); BOOL r = U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, b, &l2);
    CHECKF(r && l2 == n, "strlen+1: r=%d err=%lu len=%lu want %lu", r, r ? 0 : GetLastError(), l2, n);
    /* W forwards to A for this option: same answers */
    DWORD lw = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, NULL, &lw), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(lw, 1);
    lw = sizeof b; CHECK(U(InternetQueryOptionW)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, b, &lw));
    EXPECT_EQ(lw, n);
}

TEST(ot_tls_server_cert_chain_context) {
    REQUIRE(U(InternetQueryOptionA));
    REQUIRE(UIN("crypt32.dll", CertFreeCertificateChain));
    ot_fx *fx = tls_fx(); if (!fx) { t_skip("HTTPS fixture unavailable"); return; }
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD l = sizeof ch;
    CHECK(U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l));
    EXPECT_EQ(l, sizeof ch);
    CHECK(ch != NULL);
    if (ch) {
        CHECK(ch->cChain >= 1 && ch->rgpChain[0]->cElement >= 1);
        PCCERT_CONTEXT leaf = ch->rgpChain[0]->rgpElement[0]->pCertContext;
        PCCERT_CONTEXT mine = srv_cert_get(SRV_CERT_LOCALHOST);
        if (leaf && mine && UIN("crypt32.dll", CertCompareCertificate))
            CHECK(UIN("crypt32.dll", CertCompareCertificate)(X509_ASN_ENCODING, leaf->pCertInfo, mine->pCertInfo));
        t_note("chain: %lu chain(s), %lu element(s), trust error 0x%lx", ch->cChain, ch->rgpChain[0]->cElement, ch->TrustStatus.dwErrorStatus);
        UIN("crypt32.dll", CertFreeCertificateChain)(ch);
    }
    l = 4; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, &ch, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 8);
}

TEST(ot_tls_options_on_plain_http) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx || !fx->h[OT_X]) { t_skip("fixture"); return; }
    /* not a TLS request (unsent R and completed X): the certificate options fail with 12016
     * ERROR_INTERNET_INVALID_OPERATION, the chain context with 12019 ERROR_INTERNET_INCORRECT_HANDLE_STATE (VM, qtab) */
    static const struct { DWORD opt, err; } m[] = {
        { INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, ERROR_INTERNET_INVALID_OPERATION },
        { INTERNET_OPTION_SECURITY_CERTIFICATE, ERROR_INTERNET_INVALID_OPERATION },
        { INTERNET_OPTION_SECURITY_KEY_BITNESS, ERROR_INTERNET_INVALID_OPERATION },
        { INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT, ERROR_INTERNET_INCORRECT_HANDLE_STATE } };
    for (int i = 0; i < 4; i++)
        for (int k = OT_R; k <= OT_X; k++)
            for (int w = 0; w < 2; w++) {
                if (!fx->h[k]) continue;
                BYTE b[256]; DWORD l = sizeof b;
                SET_ERR(0); BOOL r = ot_q(w, fx->h[k], m[i].opt, b, &l);
                CHECKF(!r && GetLastError() == m[i].err, "opt %lu on plain HTTP %c %c: r=%d err %lu want %lu", m[i].opt, OT_KINDS[k], w ? 'W' : 'A', r, GetLastError(), m[i].err);
            }
}
