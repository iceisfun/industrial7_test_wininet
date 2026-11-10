/* tls_misc.c - security helper exports:
 *   InternetSecurityProtocolToStringA/W (decomp 0x1844f0): reserved != 0 or pcch == NULL -> 87; protocol not in a
 *     7-entry table -> 87; a NULL buffer sets *pcch = 0 first, so it always ends in 122 with *pcch = length + 1;
 *     a buffer shorter than length+1 -> 122 with *pcch = length + 1; success writes *pcch = length (no NUL).
 *   InternetGetSecurityInfoByURLA/W (decomp 0x36b10): both out pointers NULL -> failure; URL host without a security
 *     cache entry -> 12028 ERROR_INTERNET_ITEM_NOT_FOUND; flags = entry flags & 0x7a00000 (| 0x400000). */
#include "tls_util.h"

UDECL(BOOL, InternetSecurityProtocolToStringA, (DWORD, LPSTR, LPDWORD, DWORD));
UDECL(BOOL, InternetSecurityProtocolToStringW, (DWORD, LPWSTR, LPDWORD, DWORD));
typedef BOOL (WINAPI *secinfo_by_url_a)(LPSTR, PCCERT_CHAIN_CONTEXT *, DWORD *);
typedef BOOL (WINAPI *secinfo_by_url_w)(LPCWSTR, PCCERT_CHAIN_CONTEXT *, DWORD *);
#define P_SIBU_A ((secinfo_by_url_a)t_proc("InternetGetSecurityInfoByURLA"))
#define P_SIBU_W ((secinfo_by_url_w)t_proc("InternetGetSecurityInfoByURLW"))
#define P_SIBU   ((secinfo_by_url_a)t_proc("InternetGetSecurityInfoByURL"))

/* ------------------------------------------------------------------ InternetSecurityProtocolToString */
TEST(tls_protostr_param_validation) {
    REQUIRE(UN(InternetSecurityProtocolToStringA));
    char b[128]; DWORD n = sizeof b;
    SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(0x800, b, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(0x800, b, &n, 1), ERROR_INVALID_PARAMETER);
    SET_ERR(0); n = sizeof b;
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(0, b, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0); n = sizeof b;
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(0xFFFFFFFF, b, &n, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(n, sizeof b);   /* unknown protocol: count untouched */
}

TEST(tls_protostr_tls12_sizing) {
    REQUIRE(UN(InternetSecurityProtocolToStringA));
    char b[128]; DWORD n = sizeof b; memset(b, 0, sizeof b);
    SET_ERR(0xBEEF);
    BOOL ok = UN(InternetSecurityProtocolToStringA)(TLS_SP_TLS1_2_CLIENT, b, &n, 0);
    CHECKF(ok, "err=%lu", GetLastError());
    EXPECT_ERR(0);
    t_note("0x800 -> \"%s\" (%lu)", b, n);
    EXPECT_EQ(n, strlen(b));
    CHECK(strstr(b, "1.2") != NULL);
    DWORD len = n;
    /* NULL buffer: always 122 with length + 1 */
    n = 500; SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(TLS_SP_TLS1_2_CLIENT, NULL, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, len + 1);
    /* exactly the string length (no room for NUL) */
    n = len; SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(TLS_SP_TLS1_2_CLIENT, b, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, len + 1);
    n = 0; SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(TLS_SP_TLS1_2_CLIENT, b, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, len + 1);
    /* length + 1 fits */
    char c[128]; memset(c, 'x', sizeof c); n = len + 1;
    CHECK(UN(InternetSecurityProtocolToStringA)(TLS_SP_TLS1_2_CLIENT, c, &n, 0));
    EXPECT_EQ(n, len);
    EXPECT_EQ(c[len], 0);
    EXPECT_EQ(c[len + 1], 'x');
}

/* which single protocol bits are known: exactly 7 table entries in the decomp */
TEST(tls_protostr_known_bits) {
    REQUIRE(UN(InternetSecurityProtocolToStringA));
    int known = 0; char all[1024] = ""; size_t o = 0;
    for (int bit = 0; bit < 32; bit++) {
        char b[128] = ""; DWORD n = sizeof b; SET_ERR(0);
        BOOL ok = UN(InternetSecurityProtocolToStringA)(1u << bit, b, &n, 0);
        DWORD e = ok ? 0 : GetLastError();
        if (ok) { known++; o += snprintf(all + o, sizeof all - o, " 0x%x=\"%s\"", 1u << bit, b); }
        else CHECKF(e == ERROR_INVALID_PARAMETER, "bit %d err=%lu", bit, e);
    }
    t_note("known protocol bits (%d):%s", known, all);
    CHECK(known >= 5 && known <= 7);
    /* the TLS client bits are all known */
    static const DWORD must[] = { 0x80, 0x200, 0x800 };
    for (int i = 0; i < 3; i++) { char b[128]; DWORD n = sizeof b; CHECKF(UN(InternetSecurityProtocolToStringA)(must[i], b, &n, 0), "0x%lx", must[i]); }
    /* combinations are not in the table */
    char b[128]; DWORD n = sizeof b; SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringA)(0x800 | 0x200, b, &n, 0), ERROR_INVALID_PARAMETER);
}

TEST(tls_protostr_wide_matches_ansi) {
    REQUIRE(UN(InternetSecurityProtocolToStringW)); REQUIRE(UN(InternetSecurityProtocolToStringA));
    static const DWORD protos[] = { 0x80, 0x200, 0x800, 0x2000, 0x20, 0x8 };
    for (int i = 0; i < 6; i++) {
        char a[128] = ""; DWORD na = sizeof a;
        WCHAR w[128] = L""; DWORD nw = 128;
        BOOL oa = UN(InternetSecurityProtocolToStringA)(protos[i], a, &na, 0);
        BOOL ow = UN(InternetSecurityProtocolToStringW)(protos[i], w, &nw, 0);
        CHECKF(oa == ow, "0x%lx A=%d W=%d", protos[i], oa, ow);
        if (oa && ow) {
            char wa[128]; WideCharToMultiByte(CP_ACP, 0, w, -1, wa, sizeof wa, NULL, NULL);
            CHECKF(!strcmp(a, wa), "0x%lx: %s vs %s", protos[i], a, wa);
            EXPECT_EQ(na, nw);
        }
    }
    WCHAR w[4]; DWORD nw = 0; SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringW)(0x800, w, &nw, 0), ERROR_INSUFFICIENT_BUFFER);
    CHECK(nw > 1);
    SET_ERR(0);
    EXPECT_FAIL(!UN(InternetSecurityProtocolToStringW)(0x800, w, NULL, 0), ERROR_INVALID_PARAMETER);
}

/* the protocol of a live connection maps to a known string */
TEST(tls_protostr_of_live_connection) {
    REQUIRE(UN(InternetSecurityProtocolToStringA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/ps", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    SEND_EQ(&t, 0);
    tls_sec_conn_info sci; memset(&sci, 0, sizeof sci); DWORD l = sizeof sci;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_SECURITY_CONNECTION_INFO, &sci, &l));
    char b[128] = ""; DWORD n = sizeof b;
    CHECKF(UN(InternetSecurityProtocolToStringA)(sci.connectionInfo.dwProtocol, b, &n, 0), "proto 0x%lx err=%lu", sci.connectionInfo.dwProtocol, GetLastError());
    t_note("live protocol 0x%lx = %s", sci.connectionInfo.dwProtocol, b);
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ InternetGetSecurityInfoByURL */
TEST(tls_secinfo_by_url_params) {
    REQUIRE(P_SIBU_A);
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD f = 0;
    SET_ERR(0);
    BOOL ok = P_SIBU_A("https://127.0.0.1:1/x", NULL, NULL);
    DWORD e = ok ? 0 : GetLastError();
    t_note("both out NULL: ok=%d err=%lu", ok, e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    /* never-contacted host -> not found */
    SET_ERR(0);
    ok = P_SIBU_A("https://never-contacted.i7test.example/", &ch, &f);
    e = ok ? 0 : GetLastError();
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_ITEM_NOT_FOUND);
    CHECK(ch == NULL);
    /* the unadorned export is the A one */
    CHECK(P_SIBU == P_SIBU_A);
}

TEST(tls_secinfo_by_url_after_connect) {
    REQUIRE(P_SIBU_A); REQUIRE(P_SIBU_W);
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(treq_open(&t, "127.0.0.1", srv_port(s), "GET", "/bu", T_INET_FRESH | INTERNET_FLAG_SECURE));
    t_https_secflags(t.hr, 0x100);
    SEND_EQ(&t, 0);
    char b[16]; treq_body(&t, b, sizeof b);
    char url[128]; snprintf(url, sizeof url, "https://127.0.0.1:%u/bu", srv_port(s));
    PCCERT_CHAIN_CONTEXT ch = NULL; DWORD f = 0xDEAD; SET_ERR(0);
    BOOL ok = P_SIBU_A(url, &ch, &f);
    DWORD e = ok ? 0 : GetLastError();
    t_note("by URL after a 0x100 connect (handle open): ok=%d err=%lu chain=%p flags=0x%lx", ok, e, ch, f);
    if (ok) {
        CHECK(ch != NULL);
        CHECK((f & ~0x7e00000u) == 0);
        if (ch) UIN("crypt32.dll", CertFreeCertificateChain)(ch);
    }
    WCHAR wurl[128]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 128);
    ch = NULL; f = 0xDEAD;
    BOOL okw = P_SIBU_W(wurl, &ch, &f);
    DWORD ew = okw ? 0 : GetLastError();
    CHECKF(okw == ok && ew == e, "W ok=%d err=%lu vs A ok=%d err=%lu", okw, ew, ok, e);
    if (okw && ch) UIN("crypt32.dll", CertFreeCertificateChain)(ch);
    /* flags only */
    f = 0xDEAD; SET_ERR(0);
    BOOL ok2 = P_SIBU_A(url, NULL, &f);
    CHECK(ok2 == ok);
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ option checks on the FTP / other handle kinds */
TEST(tls_secflags_handle_types_matrix) {
    /* every security option on a session handle -> 12018; numbers from the decomp switch */
    static const DWORD opts[] = { 31, 32, 35, 36, 66, 105, 149, 98, 151 };
    HINTERNET hi = t_inet_open(NULL);
    for (size_t i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        char buf[1024]; DWORD l = sizeof buf; SET_ERR(0);
        BOOL ok = U(InternetQueryOptionA)(hi, opts[i], buf, &l);
        DWORD e = ok ? 0 : GetLastError();
        CHECKF(!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "A opt %lu: ok=%d err=%lu", opts[i], ok, e);
        l = sizeof buf; SET_ERR(0);
        ok = U(InternetQueryOptionW)(hi, opts[i], buf, &l);
        e = ok ? 0 : GetLastError();
        CHECKF(!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "W opt %lu: ok=%d err=%lu", opts[i], ok, e);
    }
    t_inet_close(hi);
}

/* SECURITY_FLAGS read-back on many fresh requests: never anything but 0 before send */
TEST(tls_secflags_fresh_requests_stable) {
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    static const char *verbs[] = { "GET", "POST", "HEAD", "PUT", "OPTIONS", "DELETE" };
    for (int i = 0; i < 6; i++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, verbs[i], "/v", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
        CHECKF(hr != NULL, "%s", verbs[i]);
        EXPECT_EQ(tls_secflags(hr), 0);
        CHECK(tls_set_secflags(hr, 0x100));
        EXPECT_EQ(tls_secflags(hr), 0x100);
        U(InternetCloseHandle)(hr);
    }
    U(InternetCloseHandle)(hc); t_inet_close(hi);
}
