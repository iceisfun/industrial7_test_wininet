/* tls_secflags.c - INTERNET_OPTION_SECURITY_FLAGS (31) semantics: valid handle types, lengths, the settable mask,
 * OR-only set, request-flag mapping, read-back before/after a TLS exchange.
 * Decomp grounding (wininet 11.0.19041): InternetSetOptionA case 0x1f -> request handle only (else 12018),
 * dwBufferLength < 4 -> 122, value & 0x13380 OR-ed into the security cache entry (+0x338) when the request has one;
 * InternetQueryOptionA case 0x1f -> request handle only, value from the entry (+0x338). Hard CHECKs are decomp facts
 * confirmed on the Win10 VM, or VM observations (see EVIDENCE.md). */
#include "tls_util.h"

#define SEC_MASK 0x13380u   /* REVOCATION|UNKNOWN_CA|WRONG_USAGE|CN_INVALID|DATE_INVALID|WEAK_SIGNATURE */

static HINTERNET open_https_req(treq *t, unsigned short port, DWORD flags) {
    if (!treq_open(t, "127.0.0.1", port ? port : 443, "GET", "/sf", T_INET_FRESH | INTERNET_FLAG_SECURE | flags)) return NULL;
    return t->hr;
}

/* ------------------------------------------------------------------ handle types */
TEST(tls_secflags_session_handle_rejected) {
    REQUIRE(U(InternetQueryOptionA)); REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = t_inet_open(NULL);
    DWORD f = 0x100, l = sizeof f;
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(hi, INTERNET_OPTION_SECURITY_FLAGS, &f, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(hi, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_inet_close(hi);
}

TEST(tls_secflags_connect_handle_rejected) {
    REQUIRE(U(InternetConnectA));
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    DWORD f = 0x100, l = sizeof f;
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(hc, INTERNET_OPTION_SECURITY_FLAGS, &f, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(hc, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    /* W entry points route to the same handler */
    SET_ERR(0); l = sizeof f;
    EXPECT_FAIL(!U(InternetQueryOptionW)(hc, INTERNET_OPTION_SECURITY_FLAGS, &f, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionW)(hc, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}

TEST(tls_secflags_null_handle_rejected) {
    REQUIRE(U(InternetQueryOptionA));
    DWORD f = 0, l = sizeof f;
    SET_ERR(0);
    BOOL ok = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_SECURITY_FLAGS, &f, &l);
    CHECK(!ok);
    DWORD e = GetLastError();
    CHECKF(e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "err=%lu", e);
    SET_ERR(0);
    ok = U(InternetSetOptionA)(NULL, INTERNET_OPTION_SECURITY_FLAGS, &f, sizeof f);
    CHECK(!ok);
    e = GetLastError();
    CHECKF(e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "err=%lu", e);
}

/* ------------------------------------------------------------------ lengths */
TEST(tls_secflags_query_short_buffer) {
    REQUIRE(U(InternetQueryOptionA));
    treq t; HINTERNET hr = open_https_req(&t, 0, 0);
    CHECK(hr != NULL);
    for (DWORD len = 0; len < 4; len++) {
        DWORD f = 0x55AA55AA, l = len;
        SET_ERR(0);
        EXPECT_FAIL(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, &l), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, 4);
        EXPECT_EQ(f, 0x55AA55AA);   /* untouched */
    }
    DWORD l = 4;
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 4);
    DWORD big[4] = { 0, 0x11111111, 0x22222222, 0x33333333 }; l = sizeof big;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, big, &l));
    EXPECT_EQ(l, 4);
    EXPECT_EQ(big[1], 0x11111111);
    treq_close(&t);
}

TEST(tls_secflags_set_short_buffer) {
    REQUIRE(U(InternetSetOptionA));
    treq t; HINTERNET hr = open_https_req(&t, 0, 0);
    DWORD before = tls_secflags(hr);
    for (DWORD len = 1; len < 4; len++) {
        DWORD f = 0x100;
        SET_ERR(0);
        EXPECT_FAIL(!U(InternetSetOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, len), ERROR_INSUFFICIENT_BUFFER);
    }
    EXPECT_EQ(tls_secflags(hr), before);
    /* longer than 4 is accepted (only the first DWORD is used) */
    DWORD f2[2] = { 0x100, 0xFFFFFFFF };
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, f2, sizeof f2));
    EXPECT_EQ(tls_secflags(hr), before | 0x100);
    treq_close(&t);
}

TEST(tls_secflags_set_null_buffer) {
    REQUIRE(U(InternetSetOptionA));
    treq t; HINTERNET hr = open_https_req(&t, 0, 0);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, NULL, 4), ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    DWORD f = 0x100;
    EXPECT_FAIL(!U(InternetSetOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, 0), ERROR_INVALID_PARAMETER);
    treq_close(&t);
}

/* ------------------------------------------------------------------ initial values */
TEST(tls_secflags_initial_https_request) {
    REQUIRE(U(InternetQueryOptionA));
    treq t; HINTERNET hr = open_https_req(&t, 0, 0);
    DWORD f = tls_secflags(hr);
    t_note("secure request before send: 0x%lx", f);
    EXPECT_EQ(f, 0);
    treq_close(&t);
}

/* request flags INTERNET_FLAG_IGNORE_CERT_* (HttpOpenRequest) are NOT visible in the security flags before the send
 * (Win10 VM: 0); they are applied at send time and then read back (see tls_secflags_request_flag_after_success). */
TEST(tls_secflags_from_request_flags) {
    REQUIRE(U(HttpOpenRequestA));
    static const struct { DWORD open, want; } tab[] = {
        { 0, 0 },
        { INTERNET_FLAG_IGNORE_CERT_CN_INVALID, 0 },
        { INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
        { INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0 },
        { INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP, 0 },
        { INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, 0 },
        { INTERNET_FLAG_KEEP_CONNECTION, 0 },
    };
    for (size_t i = 0; i < sizeof tab / sizeof tab[0]; i++) {
        treq t; HINTERNET hr = open_https_req(&t, 0, tab[i].open);
        CHECKF(hr != NULL, "row %u", (unsigned)i);
        DWORD f = tls_secflags(hr);
        CHECKF(f == tab[i].want, "row %u open=0x%lx flags=0x%lx want 0x%lx", (unsigned)i, tab[i].open, f, tab[i].want);
        treq_close(&t);
    }
}

/* ------------------------------------------------------------------ set semantics */
/* each single bit: only bits in 0x13380 stick */
TEST(tls_secflags_set_single_bits) {
    REQUIRE(U(InternetSetOptionA));
    for (int b = 0; b < 32; b++) {
        treq t; HINTERNET hr = open_https_req(&t, 0, 0);
        DWORD before = tls_secflags(hr), v = 1u << b;
        SET_ERR(0);
        BOOL ok = U(InternetSetOptionA)(hr, INTERNET_OPTION_SECURITY_FLAGS, &v, sizeof v);
        CHECKF(ok, "bit %d err=%lu", b, GetLastError());
        DWORD after = tls_secflags(hr);
        CHECKF(after == (before | (v & SEC_MASK)), "bit %d: before 0x%lx after 0x%lx", b, before, after);
        treq_close(&t);
    }
}

TEST(tls_secflags_set_all_ones) {
    treq t; HINTERNET hr = open_https_req(&t, 0, 0);
    CHECK(tls_set_secflags(hr, 0xFFFFFFFF));
    EXPECT_EQ(tls_secflags(hr), SEC_MASK);
    treq_close(&t);
}

TEST(tls_secflags_set_is_or_only) {
    treq t; HINTERNET hr = open_https_req(&t, 0, 0);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    EXPECT_EQ(tls_secflags(hr), SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    CHECK(tls_set_secflags(hr, 0));                          /* cannot clear */
    EXPECT_EQ(tls_secflags(hr), SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_REVOCATION));
    EXPECT_EQ(tls_secflags(hr), SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    EXPECT_EQ(tls_secflags(hr), SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION);
    treq_close(&t);
}

/* SECURITY_SET_MASK-style combinations, table-driven */
TEST(tls_secflags_set_combinations) {
    static const DWORD v[] = {
        SECURITY_FLAG_IGNORE_REVOCATION, SECURITY_FLAG_IGNORE_UNKNOWN_CA, SECURITY_FLAG_IGNORE_WRONG_USAGE,
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID, SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, SECURITY_FLAG_IGNORE_WEAK_SIGNATURE,
        SECURITY_SET_MASK, SECURITY_IGNORE_ERROR_MASK, SECURITY_FLAG_SECURE, SECURITY_FLAG_STRENGTH_STRONG,
        SECURITY_FLAG_STRENGTH_WEAK | SECURITY_FLAG_STRENGTH_MEDIUM, SECURITY_FLAG_SSL | SECURITY_FLAG_SSL3 | SECURITY_FLAG_PCT,
        SECURITY_FLAG_OPT_IN_WEAK_SIGNATURE, SECURITY_FLAG_UNKNOWNBIT, SECURITY_FLAG_FORTEZZA, 0x4000, 0x8000, 0x800, 0x400,
        0x00040000, 0x00800000, 0x04000000, SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTPS, SECURITY_FLAG_IGNORE_REDIRECT_TO_HTTP,
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        treq t; HINTERNET hr = open_https_req(&t, 0, 0);
        CHECKF(tls_set_secflags(hr, v[i]), "v=0x%lx", v[i]);
        DWORD got = tls_secflags(hr);
        CHECKF(got == (v[i] & SEC_MASK), "set 0x%lx read 0x%lx want 0x%lx", v[i], got, v[i] & SEC_MASK);
        treq_close(&t);
    }
}

/* OR with the request-flag bits */
TEST(tls_secflags_set_on_top_of_request_flags) {
    treq t; HINTERNET hr = open_https_req(&t, 0, INTERNET_FLAG_IGNORE_CERT_CN_INVALID);
    EXPECT_EQ(tls_secflags(hr), 0);                       /* request flag not visible before send */
    CHECK(tls_set_secflags(hr, 0x100));
    EXPECT_EQ(tls_secflags(hr), 0x100);
    CHECK(tls_set_secflags(hr, 0x2000 | 0x80));
    EXPECT_EQ(tls_secflags(hr), 0x2180);
    treq_close(&t);
}

/* W variants agree with A */
TEST(tls_secflags_wide_entry_points) {
    REQUIRE(U(InternetQueryOptionW)); REQUIRE(U(InternetSetOptionW));
    treq t; HINTERNET hr = open_https_req(&t, 0, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
    DWORD f = 0, l = sizeof f;
    CHECK(U(InternetQueryOptionW)(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, &l));
    EXPECT_EQ(l, 4); EXPECT_EQ(f, 0);
    DWORD v = 0x100 | 0x200;
    CHECK(U(InternetSetOptionW)(hr, INTERNET_OPTION_SECURITY_FLAGS, &v, sizeof v));
    EXPECT_EQ(tls_secflags(hr), 0x300);
    l = 2; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionW)(hr, INTERNET_OPTION_SECURITY_FLAGS, &f, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 4);
    SET_ERR(0);
    EXPECT_FAIL(!U(InternetSetOptionW)(hr, INTERNET_OPTION_SECURITY_FLAGS, &v, 2), ERROR_INSUFFICIENT_BUFFER);
    treq_close(&t);
}

/* plain HTTP request handle: the option is accepted on the handle type */
TEST(tls_secflags_plain_http_request) {
    treq t;
    CHECK(treq_open(&t, "127.0.0.1", 80, "GET", "/p", T_INET_FRESH));
    DWORD f = 0xDEAD, l = sizeof f;
    SET_ERR(0);
    BOOL ok = U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_FLAGS, &f, &l);
    t_note("http request: query ok=%d err=%lu flags=0x%lx", ok, ok ? 0 : GetLastError(), f);
    CHECK(ok);
    EXPECT_EQ(f, 0);
    DWORD v = 0x100;
    SET_ERR(0);
    ok = U(InternetSetOptionA)(t.hr, INTERNET_OPTION_SECURITY_FLAGS, &v, sizeof v);
    t_note("http request: set ok=%d err=%lu -> 0x%lx", ok, ok ? 0 : GetLastError(), tls_secflags(t.hr));
    CHECK(ok);
    treq_close(&t);
}

/* ------------------------------------------------------------------ read-back around a real exchange */
TEST(tls_secflags_after_success_localhost_cert) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), 0);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    DWORD e = treq_send(&t);
    EXPECT_EQ(e, 0);
    DWORD f = tls_secflags(hr);
    t_note("after success: 0x%lx", f);
    EXPECT_EQ(f, SECURITY_FLAG_STRENGTH_STRONG | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_SECURE);   /* 04 F8 */
    CHECK(f & SECURITY_FLAG_SECURE);
    CHECK(!(f & (SECURITY_FLAG_STRENGTH_WEAK | SECURITY_FLAG_STRENGTH_MEDIUM)));
    treq_close(&t); srv_stop(s);
}

TEST(tls_secflags_after_success_all_ignores) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), 0);
    CHECK(tls_set_secflags(hr, SECURITY_SET_MASK));
    SEND_EQ(&t, 0);
    DWORD f = tls_secflags(hr);
    t_note("after success with SECURITY_SET_MASK: 0x%lx", f);
    EXPECT_EQ(f, SECURITY_FLAG_STRENGTH_STRONG | SECURITY_SET_MASK | SECURITY_FLAG_SECURE);
    treq_close(&t); srv_stop(s);
}

/* after a certificate failure: what does the flags option report? */
TEST(tls_secflags_after_invalid_ca_failure) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), 0);
    SEND_EQ(&t, ERROR_INTERNET_INVALID_CA);
    DWORD f = tls_secflags(hr);
    t_note("after 12045: flags=0x%lx", f);
    EXPECT_EQ(f, 0);                                         /* Win10 VM: no SECURE/STRENGTH bits after 12045 */
    treq_close(&t); srv_stop(s);
}

TEST(tls_secflags_after_cn_failure) {
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), 0);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SEND_EQ(&t, ERROR_INTERNET_SEC_CERT_CN_INVALID);
    DWORD f = tls_secflags(hr);
    t_note("after 12038: flags=0x%lx", f);
    EXPECT_EQ(f, SECURITY_FLAG_IGNORE_UNKNOWN_CA);            /* Win10 VM: only what was set */
    treq_close(&t); srv_stop(s);
}

/* the request flag is applied at send time and then reads back (04 F8: 0x20001101) */
TEST(tls_secflags_request_flag_after_success) {
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), INTERNET_FLAG_IGNORE_CERT_CN_INVALID);
    EXPECT_EQ(tls_secflags(hr), 0);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SEND_EQ(&t, 0);
    EXPECT_EQ(tls_secflags(hr), SECURITY_FLAG_STRENGTH_STRONG | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_SECURE);
    treq_close(&t); srv_stop(s);
}

TEST(tls_secflags_request_date_flag_after_success) {
    srv *s = tls_srv(SRV_CERT_EXPIRED, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), INTERNET_FLAG_IGNORE_CERT_DATE_INVALID);
    CHECK(tls_set_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    SEND_EQ(&t, 0);
    EXPECT_EQ(tls_secflags(hr), SECURITY_FLAG_STRENGTH_STRONG | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_SECURE);
    treq_close(&t); srv_stop(s);
}

/* the private options 98 and 151 read the same security-cache entry (decomp cases 0x62 / 0x97): probe */
TEST(tls_secflags_private_options_probe) {
    srv *s = tls_srv(SRV_CERT_CN_OTHER, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), 0);
    DWORD v98 = 0xDEAD, v151 = 0xDEAD, l = 4;
    BOOL ok98 = U(InternetQueryOptionA)(hr, 98, &v98, &l); DWORD e98 = ok98 ? 0 : GetLastError(); l = 4;
    BOOL ok151 = U(InternetQueryOptionA)(hr, 151, &v151, &l); DWORD e151 = ok151 ? 0 : GetLastError();
    t_note("before send: opt98 ok=%d err=%lu v=0x%lx; opt151 ok=%d err=%lu v=0x%lx", ok98, e98, v98, ok151, e151, v151);
    DWORD e1 = treq_send(&t);
    l = 4; ok98 = U(InternetQueryOptionA)(hr, 98, &v98, &l); e98 = ok98 ? 0 : GetLastError(); l = 4;
    ok151 = U(InternetQueryOptionA)(hr, 151, &v151, &l); e151 = ok151 ? 0 : GetLastError();
    t_note("after send err=%lu: opt98 ok=%d err=%lu v=0x%lx; opt151 ok=%d err=%lu v=0x%lx", e1, ok98, e98, v98, ok151, e151, v151);
    CHECK(ok98); CHECK(ok151);
    EXPECT_EQ(v98, tls_secflags(hr));                         /* decomp: both read +0x338 */
    /* session handle -> 12018 for both */
    l = 4; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(t.hi, 98, &v98, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = 4; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(t.hi, 151, &v151, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = 2; SET_ERR(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(hr, 151, &v151, &l), ERROR_INTERNET_BAD_OPTION_LENGTH);
    treq_close(&t); srv_stop(s);
}

/* flags are per request: a second request on the same connect handle starts clean (04 F9) */
TEST(tls_secflags_not_inherited_by_next_request) {
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; HINTERNET hr = open_https_req(&t, srv_port(s), 0);
    CHECK(tls_set_secflags(hr, 0x100));
    SEND_EQ(&t, 0);
    char b[32]; treq_body(&t, b, sizeof b);
    HINTERNET hr2 = U(HttpOpenRequestA)(t.hc, "GET", "/second", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    DWORD f2 = tls_secflags(hr2);
    t_note("second request before send: 0x%lx", f2);
    EXPECT_EQ(f2, 0);
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(hr2, NULL, 0, NULL, 0);
    EXPECT_FAIL(!ok, ERROR_INTERNET_INVALID_CA);           /* 04 F9 */
    U(InternetCloseHandle)(hr2);
    treq_close(&t); srv_stop(s);
}

/* the SECURE flag on a session-level InternetOpenUrl handle */
TEST(tls_secflags_openurl_handle) {
    REQUIRE(U(InternetOpenUrlA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    HINTERNET hi = t_inet_open(NULL);
    SET_ERR(0);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/u"), NULL, 0, T_INET_FRESH, 0);
    DWORD e = hu ? 0 : GetLastError();
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    CHECK(hu == NULL);
    /* request flags can carry CN/DATE but not UNKNOWN_CA: still 12045 */
    SET_ERR(0);
    hu = U(InternetOpenUrlA)(hi, srv_url(s, "/u2"), NULL, 0, T_INET_FRESH | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    e = hu ? 0 : GetLastError();
    EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
    if (hu) U(InternetCloseHandle)(hu);
    t_inet_close(hi); srv_stop(s);
}
