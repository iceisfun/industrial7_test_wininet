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
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, sizeof ci);
    l = sizeof ci - 1;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, &ci, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, sizeof ci);
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
    DWORD l = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    CHECK(l > 1 && l < 4096);
    char *b = calloc(1, l + 16); DWORD need = l;
    DWORD l2 = need;
    CHECK(U(InternetQueryOptionA)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, b, &l2));
    CHECKF(l2 == need - 1 && strlen(b) == l2, "len %lu need %lu strlen %u", l2, need, (unsigned)strlen(b));
    CHECK(strstr(b, "localhost") != NULL);
    t_note("SECURITY_CERTIFICATE (%lu chars): %.160s", l2, b);
    free(b);
    /* W: same string, bytes on 122 */
    DWORD lw = 0;
    SET_ERR(0); BOOL r = U(InternetQueryOptionW)(fx->h[OT_T], INTERNET_OPTION_SECURITY_CERTIFICATE, NULL, &lw);
    t_note("W SECURITY_CERTIFICATE NULL buffer: r=%d err=%lu len=%lu (A need %lu)", r, GetLastError(), lw, need);
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
    /* not a TLS request: certificate options fail; recorded per option */
    static const DWORD opts[] = { INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, INTERNET_OPTION_SECURITY_CERTIFICATE,
                                  INTERNET_OPTION_SECURITY_KEY_BITNESS, INTERNET_OPTION_SERVER_CERT_CHAIN_CONTEXT };
    for (int i = 0; i < 4; i++)
        for (int k = OT_R; k <= OT_X; k++) {
            BYTE b[256]; DWORD l = sizeof b;
            SET_ERR(0); BOOL r = U(InternetQueryOptionA)(fx->h[k], opts[i], b, &l);
            CHECKF(!r, "opt %lu on plain HTTP %c succeeded", opts[i], OT_KINDS[k]);
            t_note("opt %lu on %c: err %lu", opts[i], OT_KINDS[k], GetLastError());
        }
}
