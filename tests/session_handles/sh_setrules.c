/* session_handles / InternetSetOption(Ex) rules per option and handle type, beyond the matrix in sh_options.c:
 * SetOptionEx flags, PROXY on a session (struct size, access validation, effect on later requests), ERROR_MASK,
 * REQUEST_PRIORITY, buffer sizes, timeouts edge values, read-only option list, no-op options, SECURITY_FLAGS mask on
 * a SECURE request, CONTEXT_VALUE as the callback context, W setters.
 * Evidence: [D InternetSetOptionA@0x551b0: len/buffer 0 -> 87; read-only list {1,9,0xf,0x11,0x13,0x14,0x16,0x33,0x37,
 * 0x38,0x39,0x3d,0x61,0x93} -> 12011; {0x10,0x4e,0x4f,0x50} -> 120; 0x36 -> 50; {0xb,0x34,0x5b,0x5c,0x5d} no-op TRUE;
 * {0x46,0x52} len 4 TRUE else 12010; case 0x26 PROXY (Inet only, len 0x18, access & ~3, 2, 3 with NULL/"" -> 87);
 * case 0x1f SECURITY_FLAGS (HReq only, len < 4 -> 122, ORs value & 0x13380); case 0x2d CONTEXT_VALUE (len 8);
 * case 0x3a REQUEST_PRIORITY (HReq, len 4); case 0x3e ERROR_MASK (len 4, value & ~0xb -> 87); case 0x40
 * BYPASS_EDITED_ENTRY (handle -> 12018); case 0xc/0xd (value 0 -> 87)], [D InternetSetOptionExA@0x139ba0: dwFlags != 0
 * -> 87]. VM boots: EVIDENCE.md. */
#include "sh.h"

UDECL(BOOL, InternetSetOptionExA, (HINTERNET, DWORD, LPVOID, DWORD, DWORD));
UDECL(BOOL, InternetSetOptionExW, (HINTERNET, DWORD, LPVOID, DWORD, DWORD));

typedef struct { HINTERNET s, c, r; } sh3;
static int sh3_make(sh3 *t, DWORD rflags) {
    t->s = sh_open("setrules");
    t->c = t->s ? U(InternetConnectA)(t->s, "127.0.0.1", 80, "u", "p", INTERNET_SERVICE_HTTP, 0, 1) : NULL;
    t->r = t->c ? U(HttpOpenRequestA)(t->c, "GET", "/sr", NULL, NULL, NULL, T_INET_FRESH | rflags, 2) : NULL;
    return t->s && t->c && t->r;
}
static void sh3_free(sh3 *t) { if (t->r) sh_close(t->r); if (t->c) sh_close(t->c); if (t->s) sh_close(t->s); }

/* ------------------------------------------------------------------ InternetSetOptionEx */
TEST(sh_setex_flags_nonzero_87) {
    REQUIRE(UN(InternetSetOptionExA)); REQUIRE(UN(InternetSetOptionExW));
    HINTERNET s = sh_open("setex"); CHECK(s != NULL); if (!s) return;
    static const DWORD flags[] = { 1, 2, 0x10, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof flags / sizeof *flags; i++) {
        DWORD v = 1111; SetLastError(0);
        BOOL ok = UN(InternetSetOptionExA)(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, sizeof v, flags[i]);
        { int c_ = !!(!ok && GetLastError() == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INVALID_PARAMETER", "ExA flags 0x%lx: ok=%d err %lu", flags[i], ok, GetLastError()); }
        SetLastError(0);
        ok = UN(InternetSetOptionExW)(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, sizeof v, flags[i]);
        { int c_ = !!(!ok && GetLastError() == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INVALID_PARAMETER", "ExW flags 0x%lx: ok=%d err %lu", flags[i], ok, GetLastError()); }
    }
    DWORD v, e;
    CHECK(sh_qdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 30000);   /* nothing was applied */
    sh_close(s);
}

TEST(sh_setex_flags_zero_forwards) {
    REQUIRE(UN(InternetSetOptionExA)); REQUIRE(UN(InternetSetOptionExW));
    HINTERNET s = sh_open("setex0"); CHECK(s != NULL); if (!s) return;
    DWORD v = 2468, e;
    CHECK(UN(InternetSetOptionExA)(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, sizeof v, 0));
    CHECK(sh_qdw(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 2468);
    v = 1357;
    CHECK(UN(InternetSetOptionExW)(s, INTERNET_OPTION_SEND_TIMEOUT, &v, sizeof v, 0));
    CHECK(sh_qdw(s, INTERNET_OPTION_SEND_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 1357);
    /* the same errors as InternetSetOption once forwarded */
    SetLastError(0);
    EXPECT_FAIL(!UN(InternetSetOptionExA)(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, 2, 0), ERROR_INTERNET_BAD_OPTION_LENGTH);
    SetLastError(0);
    EXPECT_FAIL(!UN(InternetSetOptionExA)(s, INTERNET_OPTION_HANDLE_TYPE, &v, 4, 0), ERROR_INTERNET_OPTION_NOT_SETTABLE);
    SetLastError(0);
    EXPECT_FAIL(!UN(InternetSetOptionExA)(SH_GARBAGE1, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, 4, 0), ERROR_INVALID_HANDLE);
    sh_close(s);
}

/* ------------------------------------------------------------------ option-number classes on a session */
TEST(sh_set_readonly_option_list_12011) {
    sh3 t; CHECK(sh3_make(&t, 0));
    static const DWORD ro[] = { 1, 9, 0xf, 0x11, 0x13, 0x14, 0x16, 0x33, 0x37, 0x38, 0x39, 0x3d, 0x61, 0x93 };
    HINTERNET hs[3] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) for (size_t i = 0; i < sizeof ro / sizeof *ro; i++) {
        if (!hs[k]) continue;
        ULONG_PTR v = 0; DWORD e;
        BOOL ok = sh_set(hs[k], ro[i], &v, sizeof v, &e);
        { int c_ = !!(!ok && e == ERROR_INTERNET_OPTION_NOT_SETTABLE); t_check(c_, __FILE__, __LINE__, "!ok && e == ERROR_INTERNET_OPTION_NOT_SETTABLE", "set option 0x%lx on handle %d: ok=%d err %lu want 12011", ro[i], k, ok, e); }
    }
    sh3_free(&t);
}

TEST(sh_set_not_implemented_and_not_supported) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    static const DWORD e120[] = { 0x10, 0x4e, 0x4f, 0x50 };
    for (int k = 0; k < 3; k++) {
        if (!hs[k]) continue;
        DWORD v = 0, e;
        for (size_t i = 0; i < sizeof e120 / sizeof *e120; i++)
            { int c_ = !!(!sh_set(hs[k], e120[i], &v, 4, &e) && e == ERROR_CALL_NOT_IMPLEMENTED); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], e120[i], &v, 4, &e) && e == ERROR_CALL_NOT_IMPLEMENTED", "set 0x%lx on %d: err %lu want 120", e120[i], k, e); }
        { int c_ = !!(!sh_set(hs[k], 0x36, &v, 4, &e) && e == ERROR_NOT_SUPPORTED); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], 0x36, &v, 4, &e) && e == ERROR_NOT_SUPPORTED", "set CALLBACK_FILTER on %d: err %lu want 50", k, e); }
    }
    sh3_free(&t);
}

/* LISTEN_TIMEOUT (11), OFFLINE_SEMANTICS (52) and 91..93 are accepted and ignored; AUTODIAL_MODE (82) and
 * DISABLE_AUTODIAL (70) only check the length. */
TEST(sh_set_noop_options_on_handles) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    static const DWORD noop[] = { 0xb, 0x34, 0x5b, 0x5c, 0x5d };
    for (int k = 0; k < 3; k++) {
        if (!hs[k]) continue;
        DWORD v = 5, e;
        for (size_t i = 0; i < sizeof noop / sizeof *noop; i++)
            { int c_ = !!(sh_set(hs[k], noop[i], &v, 4, &e)); t_check(c_, __FILE__, __LINE__, "sh_set(hs[k], noop[i], &v, 4, &e)", "set no-op 0x%lx on %d: err %lu", noop[i], k, e); }
        { int c_ = !!(sh_set(hs[k], 0x52, &v, 4, &e)); t_check(c_, __FILE__, __LINE__, "sh_set(hs[k], 0x52, &v, 4, &e)", "set AUTODIAL_MODE on %d: err %lu", k, e); }
        { int c_ = !!(!sh_set(hs[k], 0x52, &v, 2, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], 0x52, &v, 2, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH", "set AUTODIAL_MODE len 2 on %d: err %lu", k, e); }
        { int c_ = !!(sh_set(hs[k], 0x46, &v, 4, &e)); t_check(c_, __FILE__, __LINE__, "sh_set(hs[k], 0x46, &v, 4, &e)", "set DISABLE_AUTODIAL on %d: err %lu", k, e); }
        { int c_ = !!(!sh_set(hs[k], 0x46, &v, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], 0x46, &v, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH", "set DISABLE_AUTODIAL len 8 on %d: err %lu", k, e); }
        /* AUTODIAL_MODE still reads its constant */
        DWORD r; CHECK(sh_qdw(hs[k], 0x52, &r, NULL, &e)); EXPECT_EQ(r, 1);
    }
    sh3_free(&t);
}

/* Options above 0xc0 (and 0) are invalid for set, for every handle, before the length is looked at. */
TEST(sh_set_out_of_range_options_12009) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    static const DWORD bad[] = { 0, 0xc1, 0xc2, 0x100, 0x1000, 0x7fffffff, 0xffffffffu };
    for (int k = 0; k < 3; k++) for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        if (!hs[k]) continue;
        DWORD v = 1, e;
        { int c_ = !!(!sh_set(hs[k], bad[i], &v, 4, &e) && e == ERROR_INTERNET_INVALID_OPTION); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], bad[i], &v, 4, &e) && e == ERROR_INTERNET_INVALID_OPTION", "set 0x%lx on %d: err %lu", bad[i], k, e); }
        { int c_ = !!(!sh_set(hs[k], bad[i], &v, 3, &e) && e == ERROR_INTERNET_INVALID_OPTION); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], bad[i], &v, 3, &e) && e == ERROR_INTERNET_INVALID_OPTION", "set 0x%lx len 3 on %d: err %lu", bad[i], k, e); }
    }
    sh3_free(&t);
}

/* ------------------------------------------------------------------ PROXY on a session */
TEST(sh_set_proxy_session_roundtrip) {
    HINTERNET s = sh_open("proxyset"); CHECK(s != NULL); if (!s) return;
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"127.0.0.1:9", (LPCTSTR)"bypass.i7test.example" };
    DWORD e;
    { int c_ = !!(sh_set(s, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e)); t_check(c_, __FILE__, __LINE__, "sh_set(s, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e)", "set PROXY err %lu", e); }
    BYTE buf[512]; DWORD len = sizeof buf;
    CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_PROXY, buf, &len));
    INTERNET_PROXY_INFO *q = (INTERNET_PROXY_INFO *)buf;
    EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_PROXY);
    EXPECT_STR((const char *)q->lpszProxy, "127.0.0.1:9");
    /* VM: as for InternetOpen(PROXY), the session bypass string reads "<proxy list> <bypass list>" */
    EXPECT_STR((const char *)q->lpszProxyBypass, "127.0.0.1:9 bypass.i7test.example");
    EXPECT_EQ(len, sizeof(INTERNET_PROXY_INFO) + 12 + 34);
    /* back to DIRECT */
    INTERNET_PROXY_INFO pd = { INTERNET_OPEN_TYPE_DIRECT, NULL, NULL };
    { int c_ = !!(sh_set(s, INTERNET_OPTION_PROXY, &pd, sizeof pd, &e)); t_check(c_, __FILE__, __LINE__, "sh_set(s, INTERNET_OPTION_PROXY, &pd, sizeof pd, &e)", "set PROXY DIRECT err %lu", e); }
    len = sizeof buf;
    CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_PROXY, buf, &len));
    EXPECT_EQ(q->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    EXPECT_EQ(len, sizeof(INTERNET_PROXY_INFO));
    sh_close(s);
}

TEST(sh_set_proxy_session_validation) {
    sh3 t; CHECK(sh3_make(&t, 0));
    if (!t.s) { sh3_free(&t); return; }
    DWORD e;
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"127.0.0.1:9", NULL };
    BYTE big[64]; memset(big, 0, sizeof big); memcpy(big, &pi, sizeof pi);
    /* wrong struct sizes */
    static const DWORD lens[] = { 4, 16, 23, 25, 32, 48 };
    for (size_t i = 0; i < sizeof lens / sizeof *lens; i++)
        { int c_ = !!(!sh_set(t.s, INTERNET_OPTION_PROXY, big, lens[i], &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH); t_check(c_, __FILE__, __LINE__, "!sh_set(t.s, INTERNET_OPTION_PROXY, big, lens[i], &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH", "PROXY len %lu: err %lu", lens[i], e); }
    /* bad access types */
    static const DWORD acc[] = { 2, 4, 5, 8, 0x10, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof acc / sizeof *acc; i++) {
        INTERNET_PROXY_INFO b = { acc[i], (LPCTSTR)"127.0.0.1:9", NULL };
        { int c_ = !!(!sh_set(t.s, INTERNET_OPTION_PROXY, &b, sizeof b, &e) && e == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!sh_set(t.s, INTERNET_OPTION_PROXY, &b, sizeof b, &e) && e == ERROR_INVALID_PARAMETER", "PROXY access %lu: err %lu", acc[i], e); }
    }
    INTERNET_PROXY_INFO n1 = { INTERNET_OPEN_TYPE_PROXY, NULL, NULL }, n2 = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)"", NULL };
    { int c_ = !!(!sh_set(t.s, INTERNET_OPTION_PROXY, &n1, sizeof n1, &e) && e == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!sh_set(t.s, INTERNET_OPTION_PROXY, &n1, sizeof n1, &e) && e == ERROR_INVALID_PARAMETER", "PROXY NULL proxy: err %lu", e); }
    { int c_ = !!(!sh_set(t.s, INTERNET_OPTION_PROXY, &n2, sizeof n2, &e) && e == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!sh_set(t.s, INTERNET_OPTION_PROXY, &n2, sizeof n2, &e) && e == ERROR_INVALID_PARAMETER", "PROXY empty proxy: err %lu", e); }
    /* access 0 (PRECONFIG) is accepted */
    INTERNET_PROXY_INFO p0 = { INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL };
    BOOL ok = sh_set(t.s, INTERNET_OPTION_PROXY, &p0, sizeof p0, &e);
    CHECKF(ok, "PROXY set access 0 on session: err %lu", e);   /* VM: accepted */
    INTERNET_PROXY_INFO pd = { INTERNET_OPEN_TYPE_DIRECT, NULL, NULL };
    CHECK(sh_set(t.s, INTERNET_OPTION_PROXY, &pd, sizeof pd, &e));
    /* handle type is checked first: connect/request give 12018 even with a bad length */
    { int c_ = !!(!sh_set(t.c, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_set(t.c, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "PROXY on connect: err %lu", e); }
    { int c_ = !!(!sh_set(t.r, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_set(t.r, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "PROXY on request: err %lu", e); }
    { int c_ = !!(!sh_set(t.c, INTERNET_OPTION_PROXY, big, 7, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_set(t.c, INTERNET_OPTION_PROXY, big, 7, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "PROXY len 7 on connect: err %lu", e); }
    /* the session is still DIRECT after all the rejected sets */
    BYTE buf[256]; DWORD len = sizeof buf;
    CHECK(U(InternetQueryOptionA)(t.s, INTERNET_OPTION_PROXY, buf, &len));
    EXPECT_EQ(((INTERNET_PROXY_INFO *)buf)->dwAccessType, INTERNET_OPEN_TYPE_DIRECT);
    sh3_free(&t);
}

/* A proxy set on a DIRECT session after it was opened is used by requests created afterwards. */
TEST(sh_set_proxy_session_used_by_new_request) {
    REQUIRE(U(HttpSendRequestA));
    srv *px = srv_http(NULL, 0);
    if (!px) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("late-proxy");
    INTERNET_PROXY_INFO pi = { INTERNET_OPEN_TYPE_PROXY, (LPCTSTR)srv_hostport(px), NULL };
    DWORD e;
    CHECK(s && sh_set(s, INTERNET_OPTION_PROXY, &pi, sizeof pi, &e));
    HINTERNET c = s ? sh_connect(s, "lateproxy.i7test.example", 80, 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/lp", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        { int c_ = !!(U(HttpSendRequestA)(r, NULL, 0, NULL, 0)); t_check(c_, __FILE__, __LINE__, "U(HttpSendRequestA)(r, NULL, 0, NULL, 0)", "send via late proxy err %lu", GetLastError()); }
        CHECK(srv_wait_requests(px, 1, 3000));
        if (srv_req_count(px) > 0) {
            EXPECT_STR(srv_req_target(px, 0), "http://lateproxy.i7test.example/lp");
            EXPECT_STR(srv_req_header(px, 0, "Host"), "lateproxy.i7test.example");
        }
        DWORD f, len;
        CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &f, &len, &e));
        { int c_ = !!(f & INTERNET_REQFLAG_VIA_PROXY); t_check(c_, __FILE__, __LINE__, "f & INTERNET_REQFLAG_VIA_PROXY", "REQUEST_FLAGS 0x%lx lacks VIA_PROXY", f); }
        sh_close(r);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(px);
}

/* ------------------------------------------------------------------ request-only options */
TEST(sh_set_request_priority) {
    sh3 t; CHECK(sh3_make(&t, 0));
    if (!t.r) { sh3_free(&t); return; }
    DWORD v, e;
    CHECK(sh_qdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &v, NULL, &e)); EXPECT_EQ(v, 0);
    static const DWORD vals[] = { 0, 1, 100, 0x7fffffff, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof vals / sizeof *vals; i++) {
        CHECK(sh_setdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, vals[i], &e));
        CHECK(sh_qdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &v, NULL, &e)); { int c_ = !!(v == vals[i]); t_check(c_, __FILE__, __LINE__, "v == vals[i]", "priority %lx read %lx", vals[i], v); }
    }
    DWORD z = 1;
    CHECK(!sh_set(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &z, 2, &e)); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
    CHECK(!sh_set(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &z, 8, &e)); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
    CHECK(!sh_setdw(t.s, INTERNET_OPTION_REQUEST_PRIORITY, 1, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(!sh_setdw(t.c, INTERNET_OPTION_REQUEST_PRIORITY, 1, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    sh3_free(&t);
}

TEST(sh_set_error_mask_values) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) {
        if (!hs[k]) continue;
        DWORD e;
        static const DWORD good[] = { 0, 1, 2, 3, 8, 9, 0xa, 0xb };
        static const DWORD bad[] = { 4, 5, 0x10, 0x20, 0x100, 0x80000000u, 0xffffffffu };
        for (size_t i = 0; i < sizeof good / sizeof *good; i++)
            { int c_ = !!(sh_setdw(hs[k], INTERNET_OPTION_ERROR_MASK, good[i], &e)); t_check(c_, __FILE__, __LINE__, "sh_setdw(hs[k], INTERNET_OPTION_ERROR_MASK, good[i], &e)", "ERROR_MASK 0x%lx on %d: err %lu", good[i], k, e); }
        for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
            { int c_ = !!(!sh_setdw(hs[k], INTERNET_OPTION_ERROR_MASK, bad[i], &e) && e == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!sh_setdw(hs[k], INTERNET_OPTION_ERROR_MASK, bad[i], &e) && e == ERROR_INVALID_PARAMETER", "ERROR_MASK 0x%lx on %d: err %lu", bad[i], k, e); }
        ULONG_PTR big = 1;
        { int c_ = !!(!sh_set(hs[k], INTERNET_OPTION_ERROR_MASK, &big, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], INTERNET_OPTION_ERROR_MASK, &big, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH", "ERROR_MASK len 8 on %d: err %lu", k, e); }
        sh_setdw(hs[k], INTERNET_OPTION_ERROR_MASK, 0, &e);
    }
    if (t.r) {
        DWORD v = 0xcc, len = sizeof v; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(t.r, INTERNET_OPTION_ERROR_MASK, &v, &len);
        CHECKF(!ok && GetLastError() == ERROR_INVALID_PARAMETER, "query ERROR_MASK: ok=%d err %lu", ok, GetLastError());   /* VM: write-only (87) */
    }
    sh3_free(&t);
}

TEST(sh_set_security_flags_mask_on_secure_request) {
    sh3 t; CHECK(sh3_make(&t, INTERNET_FLAG_SECURE));
    if (!t.r) { sh3_free(&t); return; }
    DWORD v0, v, e;
    CHECK(sh_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v0, NULL, &e));
    t_note("SECURE request initial SECURITY_FLAGS 0x%lx", v0);
    CHECK(sh_setdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, SECURITY_FLAG_IGNORE_UNKNOWN_CA, &e));
    CHECK(sh_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v, NULL, &e)); EXPECT_EQ(v, v0 | SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    /* only the ignore bits are taken: 0x13380 */
    CHECK(sh_setdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, 0xffffffffu, &e));
    CHECK(sh_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v, NULL, &e)); EXPECT_EQ(v, v0 | 0x13380);
    /* setting 0 removes nothing (OR semantics) */
    CHECK(sh_setdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, 0, &e));
    CHECK(sh_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v, NULL, &e)); EXPECT_EQ(v, v0 | 0x13380);
    WORD w = 0x100;
    CHECK(!sh_set(t.r, INTERNET_OPTION_SECURITY_FLAGS, &w, 2, &e)); EXPECT_EQ(e, ERROR_INSUFFICIENT_BUFFER);
    ULONG_PTR q = 0x80;   /* a longer buffer is accepted */
    CHECK(sh_set(t.r, INTERNET_OPTION_SECURITY_FLAGS, &q, 8, &e));
    sh3_free(&t);
}

/* Each ignore bit on its own, on a fresh SECURE request. */
TEST(sh_set_security_flags_individual_bits) {
    static const DWORD bits[] = { 0x80, 0x100, 0x200, 0x1000, 0x2000, 0x10000, 0x1, 0x4, 0x40, 0x8000, 0x4000, 0x20000 };
    for (size_t i = 0; i < sizeof bits / sizeof *bits; i++) {
        sh3 t; CHECK(sh3_make(&t, INTERNET_FLAG_SECURE));
        if (!t.r) { sh3_free(&t); continue; }
        DWORD v0, v, e;
        CHECK(sh_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v0, NULL, &e));
        CHECK(sh_setdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, bits[i], &e));
        CHECK(sh_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v, NULL, &e));
        DWORD want = v0 | (bits[i] & 0x13380);
        { int c_ = !!(v == want); t_check(c_, __FILE__, __LINE__, "v == want", "bit 0x%lx: 0x%lx -> 0x%lx want 0x%lx", bits[i], v0, v, want); }
        sh3_free(&t);
    }
}

/* ------------------------------------------------------------------ buffer sizes */
TEST(sh_set_buffer_sizes) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[2] = { t.c, t.r };
    static const DWORD opt[2] = { INTERNET_OPTION_READ_BUFFER_SIZE, INTERNET_OPTION_WRITE_BUFFER_SIZE };
    for (int k = 0; k < 2; k++) for (int o = 0; o < 2; o++) {
        if (!hs[k]) continue;
        DWORD v, e;
        CHECK(sh_qdw(hs[k], opt[o], &v, NULL, &e)); { int c_ = !!(v == 4096); t_check(c_, __FILE__, __LINE__, "v == 4096", "handle %d option %lu default %lu", k, opt[o], v); }
        static const DWORD vals[] = { 1, 512, 8192, 65536, 0x100000 };
        for (size_t i = 0; i < sizeof vals / sizeof *vals; i++) {
            { int c_ = !!(sh_setdw(hs[k], opt[o], vals[i], &e)); t_check(c_, __FILE__, __LINE__, "sh_setdw(hs[k], opt[o], vals[i], &e)", "set %lu=%lu on %d err %lu", opt[o], vals[i], k, e); }
            CHECK(sh_qdw(hs[k], opt[o], &v, NULL, &e)); { int c_ = !!(v == vals[i]); t_check(c_, __FILE__, __LINE__, "v == vals[i]", "option %lu on %d: set %lu read %lu", opt[o], k, vals[i], v); }
        }
        { int c_ = !!(!sh_setdw(hs[k], opt[o], 0, &e) && e == ERROR_INVALID_PARAMETER); t_check(c_, __FILE__, __LINE__, "!sh_setdw(hs[k], opt[o], 0, &e) && e == ERROR_INVALID_PARAMETER", "option %lu = 0 on %d: err %lu", opt[o], k, e); }
        ULONG_PTR big = 4096;
        { int c_ = !!(!sh_set(hs[k], opt[o], &big, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], opt[o], &big, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH", "option %lu len 8 on %d: err %lu", opt[o], k, e); }
    }
    DWORD e;
    if (t.s) { int c_ = !!(!sh_setdw(t.s, INTERNET_OPTION_WRITE_BUFFER_SIZE, 4096, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_setdw(t.s, INTERNET_OPTION_WRITE_BUFFER_SIZE, 4096, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "WRITE_BUFFER_SIZE on session err %lu", e); }
    sh3_free(&t);
}

/* ------------------------------------------------------------------ timeouts */
TEST(sh_set_timeout_edge_values) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    static const DWORD opts[] = { 2, 3, 4, 5, 6, 7, 8, 63 };
    static const DWORD vals[] = { 0, 1, 999, 0x7fffffff, 0xffffffffu };
    for (int k = 0; k < 3; k++) for (size_t o = 0; o < sizeof opts / sizeof *opts; o++) for (size_t i = 0; i < sizeof vals / sizeof *vals; i++) {
        if (!hs[k]) continue;
        DWORD v, e, before = 0;
        sh_qdw(hs[k], opts[o], &before, NULL, &e);
        { int c_ = !!(sh_setdw(hs[k], opts[o], vals[i], &e)); t_check(c_, __FILE__, __LINE__, "sh_setdw(hs[k], opts[o], vals[i], &e)", "set timeout %lu=%lx on %d err %lu", opts[o], vals[i], k, e); }
        CHECK(sh_qdw(hs[k], opts[o], &v, NULL, &e));
        /* VM: CONNECT_BACKOFF is accepted and ignored (always 0); CONNECT_TIMEOUT 0 is accepted and ignored (value kept),
         * as for the global value [D InternetSetOptionA case 2 `if (uVar17 == 0) goto ...`] */
        if (opts[o] == 4) { CHECKF(v == 0, "CONNECT_BACKOFF on %d reads %lu", k, v); continue; }
        if (opts[o] == 2 && vals[i] == 0) { CHECKF(v == before, "CONNECT_TIMEOUT 0 on %d: before %lu after %lu", k, before, v); continue; }
        { int c_ = !!(v == vals[i]); t_check(c_, __FILE__, __LINE__, "v == vals[i]", "timeout %lu on handle %d: set %lx read %lx", opts[o], k, vals[i], v); }
    }
    sh3_free(&t);
}

TEST(sh_set_from_cache_timeout_roundtrip) {
    sh3 t; CHECK(sh3_make(&t, 0));
    if (!t.s) { sh3_free(&t); return; }
    DWORD v, e;
    CHECK(sh_qdw(t.s, INTERNET_OPTION_FROM_CACHE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 0xffffffffu);   /* VM */
    CHECK(sh_setdw(t.s, INTERNET_OPTION_FROM_CACHE_TIMEOUT, 777, &e));
    CHECK(sh_qdw(t.s, INTERNET_OPTION_FROM_CACHE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 777);
    CHECK(!sh_set(t.s, INTERNET_OPTION_FROM_CACHE_TIMEOUT, &v, 8, &e)); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
    sh3_free(&t);
}

/* ------------------------------------------------------------------ other per-handle options */
TEST(sh_set_bypass_edited_entry_on_handle_12018) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) {
        if (!hs[k]) continue;
        DWORD e;
        { int c_ = !!(!sh_setdw(hs[k], INTERNET_OPTION_BYPASS_EDITED_ENTRY, 1, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_setdw(hs[k], INTERNET_OPTION_BYPASS_EDITED_ENTRY, 1, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "on %d err %lu", k, e); }
        ULONG_PTR b = 1;
        { int c_ = !!(!sh_set(hs[k], INTERNET_OPTION_BYPASS_EDITED_ENTRY, &b, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], INTERNET_OPTION_BYPASS_EDITED_ENTRY, &b, 8, &e) && e == ERROR_INTERNET_BAD_OPTION_LENGTH", "len 8 on %d err %lu", k, e); }
    }
    sh3_free(&t);
}

TEST(sh_set_codepage_and_idn_roundtrip) {
    sh3 t; CHECK(sh3_make(&t, 0));
    HINTERNET hs[3] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) {
        if (!hs[k]) continue;
        DWORD v, e;
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_CODEPAGE, &v, NULL, &e)); CHECKF(v == 0xffffffffu, "CODEPAGE default on %d: %lu", k, v);   /* VM: -1 (unset) */
        CHECK(sh_setdw(hs[k], INTERNET_OPTION_CODEPAGE, 65001, &e));
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_CODEPAGE, &v, NULL, &e)); EXPECT_EQ(v, 65001);
        CHECK(sh_setdw(hs[k], INTERNET_OPTION_CODEPAGE, 1252, &e));
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_CODEPAGE, &v, NULL, &e)); EXPECT_EQ(v, 1252);
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_IDN, &v, NULL, &e)); t_note("IDN default on %d: 0x%lx", k, v);   /* 3 on the lab VM; policy dependent */
    }
    /* a child created after the parent change copies it */
    DWORD e, v;
    if (t.s) {
        CHECK(sh_setdw(t.s, INTERNET_OPTION_CODEPAGE, 936, &e));
        HINTERNET c2 = sh_connect(t.s, "127.0.0.1", 80, 0);
        if (c2) { CHECK(sh_qdw(c2, INTERNET_OPTION_CODEPAGE, &v, NULL, &e)); EXPECT_EQ(v, 936);   /* VM: copied at creation */ sh_close(c2); }
    }
    sh3_free(&t);
}

TEST(sh_set_http_decoding_values) {
    sh3 t; CHECK(sh3_make(&t, 0));
    if (!t.r) { sh3_free(&t); return; }
    DWORD v, e;
    static const DWORD vals[] = { 1, 2, 0x100, 0xffffffffu, 0 };
    for (size_t i = 0; i < sizeof vals / sizeof *vals; i++) {
        CHECK(sh_setdw(t.r, INTERNET_OPTION_HTTP_DECODING, vals[i], &e));
        CHECK(sh_qdw(t.r, INTERNET_OPTION_HTTP_DECODING, &v, NULL, &e)); { int c_ = !!(v == vals[i]); t_check(c_, __FILE__, __LINE__, "v == vals[i]", "HTTP_DECODING set %lx read %lx", vals[i], v); }
    }
    CHECK(!sh_set(t.r, INTERNET_OPTION_HTTP_DECODING, &v, 2, &e)); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
    /* NULL handle: not a per-process option */
    CHECK(!sh_setdw(NULL, INTERNET_OPTION_HTTP_DECODING, 1, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    sh3_free(&t);
}

/* NULL handle + per-handle credential options that are not per-process: 12018, nothing changes. */
TEST(sh_set_null_handle_proxy_credentials_12018) {
    char v[] = "nobody"; DWORD e;
    CHECK(!sh_set(NULL, INTERNET_OPTION_PROXY_USERNAME, v, sizeof v, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(!sh_set(NULL, INTERNET_OPTION_PROXY_PASSWORD, v, sizeof v, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(!sh_set(NULL, INTERNET_OPTION_REQUEST_PRIORITY, v, 4, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(!sh_set(NULL, INTERNET_OPTION_SECURITY_FLAGS, v, 4, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(!sh_set(NULL, INTERNET_OPTION_READ_BUFFER_SIZE, v, 4, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}

/* ------------------------------------------------------------------ credentials via set (A length ignored, W length in chars) */
TEST(sh_set_credentials_a_length_ignored) {
    sh3 t; CHECK(sh3_make(&t, 0));
    if (!t.c) { sh3_free(&t); return; }
    char u[] = "longusername"; DWORD e, len;
    CHECK(sh_set(t.c, INTERNET_OPTION_USERNAME, u, 1, &e));
    char b[64];
    CHECK(sh_qstr(t.c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "longusername"); EXPECT_EQ(len, 12);
    char p[] = "pw-xyz";
    CHECK(sh_set(t.c, INTERNET_OPTION_PASSWORD, p, 200, &e));
    CHECK(sh_qstr(t.c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "pw-xyz");
    char pu[] = "pxuser";
    CHECK(sh_set(t.c, INTERNET_OPTION_PROXY_USERNAME, pu, 3, &e));
    CHECK(sh_qstr(t.c, INTERNET_OPTION_PROXY_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "pxuser");
    /* "" clears */
    char em[] = "";
    CHECK(sh_set(t.c, INTERNET_OPTION_USERNAME, em, 1, &e));
    CHECK(sh_qstr(t.c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
    sh3_free(&t);
}

TEST(sh_set_credentials_w) {
    REQUIRE(U(InternetSetOptionW));
    sh3 t; CHECK(sh3_make(&t, 0));
    if (!t.c) { sh3_free(&t); return; }
    WCHAR u[] = L"wideuser", p[] = L"widepass";
    CHECK(U(InternetSetOptionW)(t.c, INTERNET_OPTION_USERNAME, u, 8));
    CHECK(U(InternetSetOptionW)(t.c, INTERNET_OPTION_PASSWORD, p, 8));
    char b[64]; DWORD len, e;
    CHECK(sh_qstr(t.c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "wideuser");
    CHECK(sh_qstr(t.c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "widepass");
    WCHAR wb[64]; DWORD wl;
    CHECK(sh_qstrw(t.c, INTERNET_OPTION_USERNAME, wb, sizeof wb, &wl, &e)); EXPECT_WSTR(wb, L"wideuser"); EXPECT_EQ(wl, 8);
    /* a shorter W length does not truncate USERNAME (unlike USER_AGENT) */
    WCHAR u2[] = L"truncated";
    CHECK(U(InternetSetOptionW)(t.c, INTERNET_OPTION_USERNAME, u2, 5));
    CHECK(sh_qstr(t.c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "truncated");   /* VM: the W length is ignored for USERNAME */
    /* on a session: 12018 */
    SetLastError(0);
    CHECK(!U(InternetSetOptionW)(t.s, INTERNET_OPTION_USERNAME, u, 8)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    sh3_free(&t);
}

TEST(sh_set_user_agent_w_on_session) {
    REQUIRE(U(InternetSetOptionW));
    HINTERNET s = sh_open("before-w"); CHECK(s != NULL); if (!s) return;
    WCHAR ua[] = L"wide-agent/1.0";
    CHECK(U(InternetSetOptionW)(s, INTERNET_OPTION_USER_AGENT, ua, lstrlenW(ua)));
    char b[64]; DWORD len, e;
    CHECK(sh_qstr(s, INTERNET_OPTION_USER_AGENT, b, sizeof b, &len, &e)); EXPECT_STR(b, "wide-agent/1.0"); EXPECT_EQ(len, 14);
    WCHAR wb[64]; DWORD wl;
    CHECK(sh_qstrw(s, INTERNET_OPTION_USER_AGENT, wb, sizeof wb, &wl, &e)); EXPECT_WSTR(wb, L"wide-agent/1.0"); EXPECT_EQ(wl, 14);
    sh_close(s);
}

/* ------------------------------------------------------------------ CONTEXT_VALUE is what callbacks receive */
static sh_cb_rec g_ctx_rec;
TEST(sh_set_context_value_changes_callback_context) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    sh_cb_reset(&g_ctx_rec); sh_cb_cur = &g_ctx_rec;
    HINTERNET s = sh_open_to("ctxcb");
    if (s) U(InternetSetStatusCallbackA)(s, sh_cb);
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0x51) : NULL;
    HINTERNET r = c ? sh_request(c, "/ctx", 0x52) : NULL;
    CHECK(r != NULL);
    if (r) {
        ULONG_PTR nc = 0x5353; DWORD e;
        CHECK(sh_set(r, INTERNET_OPTION_CONTEXT_VALUE, &nc, sizeof nc, &e));
        int before = g_ctx_rec.n;
        CHECK(U(HttpSendRequestA)(r, NULL, 0, NULL, 0));
        int n53 = 0, n52 = 0, nall = 0;
        EnterCriticalSection(&g_ctx_rec.cs);
        for (int i = before; i < g_ctx_rec.n; i++) {
            if (g_ctx_rec.ev[i].h != r) continue;
            nall++;
            if (g_ctx_rec.ev[i].ctx == 0x5353) n53++;
            if (g_ctx_rec.ev[i].ctx == 0x52) n52++;
        }
        LeaveCriticalSection(&g_ctx_rec.cs);
        { int c_ = !!(nall > 0 && n53 == nall && n52 == 0); t_check(c_, __FILE__, __LINE__, "nall > 0 && n53 == nall && n52 == 0", "send callbacks: total %d new-ctx %d old-ctx %d", nall, n53, n52); }
        CHECK(sh_cb_count(&g_ctx_rec, INTERNET_STATUS_REQUEST_SENT, 0x5353) >= 1);
        CHECK(sh_cb_count(&g_ctx_rec, INTERNET_STATUS_RESPONSE_RECEIVED, 0x5353) >= 1);
        /* the context was taken at callback time, so HANDLE_CLOSING also carries the new value */
        sh_close(r);
        CHECK(sh_cb_count(&g_ctx_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x5353) == 1);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    sh_cb_cur = NULL;
    srv_stop(sv);
}

/* Setting CONTEXT_VALUE to 0 silences the callbacks for that handle (sync API). */
TEST(sh_set_context_value_zero_silences) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    sh_cb_reset(&g_ctx_rec); sh_cb_cur = &g_ctx_rec;
    HINTERNET s = sh_open_to("ctx0");
    if (s) U(InternetSetStatusCallbackA)(s, sh_cb);
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0x61) : NULL;
    HINTERNET r = c ? sh_request(c, "/z", 0x62) : NULL;
    CHECK(r != NULL);
    if (r) {
        ULONG_PTR z = 0; DWORD e;
        CHECK(sh_set(r, INTERNET_OPTION_CONTEXT_VALUE, &z, sizeof z, &e));
        int before = g_ctx_rec.n;
        CHECK(U(HttpSendRequestA)(r, NULL, 0, NULL, 0));
        int n = 0;
        EnterCriticalSection(&g_ctx_rec.cs);
        for (int i = before; i < g_ctx_rec.n; i++) if (g_ctx_rec.ev[i].h == r) n++;
        LeaveCriticalSection(&g_ctx_rec.cs);
        EXPECT_EQ(n, 0);
        sh_close(r);
        EXPECT_EQ(sh_cb_count(&g_ctx_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x62), 0);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    sh_cb_cur = NULL;
    srv_stop(sv);
}
