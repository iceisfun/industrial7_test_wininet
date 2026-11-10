/* options_table: value semantics (set -> get round trips, fixed answers, handle-type gates) for the non-string,
 * non-timeout options. Decomp references are InternetQueryOptionA@0x59730 / InternetSetOptionA@0x551b0 case labels
 * (hex). Global (NULL-handle) values that are changed are restored before the test ends. */
#include "ot.h"

static BOOL q8(HINTERNET h, DWORD opt, ULONGLONG *v, DWORD *l) { *l = 8; *v = 0xDEADBEEFDEADBEEFull; return U(InternetQueryOptionA)(h, opt, v, l); }

TEST(ot_val_version_info) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    /* case 0x28: static InternetVersionInfo, any handle (per-process option) */
    for (int k = 0; k < OT_NK; k++) {
        if (k != OT_N && !fx->h[k]) continue;
        for (int w = 0; w < 2; w++) {
            INTERNET_VERSION_INFO vi = { 0xdead, 0xdead }; DWORD l = sizeof vi;
            CHECK(ot_q(w, fx->h[k], INTERNET_OPTION_VERSION, &vi, &l));
            CHECKF(l == 8 && vi.dwMajorVersion == 1 && vi.dwMinorVersion == 2, "kind %c: %lu.%lu len %lu", OT_KINDS[k], vi.dwMajorVersion, vi.dwMinorVersion, l);
        }
    }
    INTERNET_VERSION_INFO vi = { 1, 2 };
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_VERSION, &vi, sizeof vi), ERROR_INTERNET_INVALID_OPTION);
}

TEST(ot_val_http_version_global) {
    REQUIRE(U(InternetSetOptionA));
    HTTP_VERSION_INFO old = { 0, 0 }, v; DWORD l = sizeof old;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &old, &l));
    CHECKF(l == 8 && old.dwMajorVersion == 1 && old.dwMinorVersion == 1, "default HTTP_VERSION %lu.%lu", old.dwMajorVersion, old.dwMinorVersion);
    HTTP_VERSION_INFO h10 = { 1, 0 };
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &h10, sizeof h10));
    l = sizeof v; CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v, &l));
    CHECK(v.dwMajorVersion == 1 && v.dwMinorVersion == 0);
    /* the session answers the same process-wide value */
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (s) { l = sizeof v; CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_HTTP_VERSION, &v, &l)); CHECK(v.dwMajorVersion == 1 && v.dwMinorVersion == 0); U(InternetCloseHandle)(s); }
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &h10, 4), ERROR_INTERNET_BAD_OPTION_LENGTH);
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &h10, 12), ERROR_INTERNET_BAD_OPTION_LENGTH);
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &old, sizeof old));
    l = sizeof v; CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v, &l));
    CHECK(v.dwMajorVersion == old.dwMajorVersion && v.dwMinorVersion == old.dwMinorVersion);
    l = 7; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v, &l), ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 8);
}

TEST(ot_val_fixed_answers) {
    REQUIRE(U(InternetQueryOptionA));
    /* case 0x32/0x52: CONNECTED_STATE and AUTODIAL_MODE answer 1; case 0x33/0x34: IDLE_STATE, OFFLINE_SEMANTICS 0 */
    static const struct { DWORD opt, v; } m[] = { { INTERNET_OPTION_CONNECTED_STATE, 1 }, { 82, 1 }, { 51, 0 }, { 52, 0 } };
    for (int i = 0; i < 4; i++)
        for (int w = 0; w < 2; w++) {
            DWORD v = 0xdead, l = sizeof v;
            CHECK(ot_q(w, NULL, m[i].opt, &v, &l));
            CHECKF(v == m[i].v && l == 4, "opt %lu %c: %lu len %lu want %lu", m[i].opt, w ? 'W' : 'A', v, l, m[i].v);
        }
    /* case 0x36..0x39, 0x46: CALLBACK_FILTER, CONNECT_TIME, SEND/RECEIVE_THROUGHPUT, DISABLE_AUTODIAL -> ERROR_NOT_SUPPORTED */
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    static const DWORD ns[] = { 54, 55, 56, 57, 70 };
    for (int i = 0; i < 5; i++) {
        DWORD v, l = sizeof v;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(t.s, ns[i], &v, &l), ERROR_NOT_SUPPORTED);
        l = sizeof v; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(t.r, ns[i], &v, &l), ERROR_NOT_SUPPORTED);
    }
    /* case 0xf/0x10/0x1a/0x1e/0x4e: ASYNC_ID, ASYNC_PRIORITY, OFFLINE_MODE, ASYNC, IDENTITY -> ERROR_CALL_NOT_IMPLEMENTED */
    static const DWORD ni[] = { 16, 26, 30, 78 };
    for (int i = 0; i < 4; i++) {
        DWORD v, l = sizeof v;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(t.s, ni[i], &v, &l), ERROR_CALL_NOT_IMPLEMENTED);
    }
    ot_trio_close(&t);
}

TEST(ot_val_context_value) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)0x1122334455667788ull);
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, (DWORD_PTR)0xABCD) : NULL;
    CHECK(c && r);
    if (r) {
        ULONGLONG v; DWORD l;
        CHECK(q8(s, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); EXPECT_EQ(l, 8); EXPECT_EQ(v, 0);
        CHECK(q8(c, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); EXPECT_EQ(l, 8); CHECK(v == 0x1122334455667788ull);
        CHECK(q8(r, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); EXPECT_EQ(l, 8); EXPECT_EQ(v, 0xABCD);
        /* option 10 (old CONTEXT_VALUE number) answers the same on query (case 10 shares case 0x2d) */
        CHECK(q8(r, 10, &v, &l)); EXPECT_EQ(v, 0xABCD);
        ULONGLONG nv = 0x0102030405060708ull;
        CHECK(U(InternetSetOptionA)(r, INTERNET_OPTION_CONTEXT_VALUE, &nv, 8));
        CHECK(q8(r, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); CHECK(v == nv);
        CHECK(U(InternetSetOptionW)(s, INTERNET_OPTION_CONTEXT_VALUE, &nv, 8));
        CHECK(q8(s, INTERNET_OPTION_CONTEXT_VALUE, &v, &l)); CHECK(v == nv);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(r, INTERNET_OPTION_CONTEXT_VALUE, &nv, 4), ERROR_INTERNET_BAD_OPTION_LENGTH);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(r, 10, &nv, 8), ERROR_INTERNET_INVALID_OPTION);
        l = 4; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(r, INTERNET_OPTION_CONTEXT_VALUE, &v, &l), ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 8);
    }
    if (r) U(InternetCloseHandle)(r);
    if (c) U(InternetCloseHandle)(c);
    U(InternetCloseHandle)(s);
}

TEST(ot_val_parent_handle) {
    REQUIRE(U(InternetQueryOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    ULONGLONG v; DWORD l;
    CHECK(q8(t.s, INTERNET_OPTION_PARENT_HANDLE, &v, &l)); EXPECT_EQ(l, 8); EXPECT_EQ(v, 0);
    CHECK(q8(t.c, INTERNET_OPTION_PARENT_HANDLE, &v, &l)); EXPECT_EQ(l, 8); CHECKF(v == (ULONGLONG)(ULONG_PTR)t.s, "connect parent 0x%llx session %p", v, t.s);
    CHECK(q8(t.r, INTERNET_OPTION_PARENT_HANDLE, &v, &l)); EXPECT_EQ(l, 8); CHECKF(v == (ULONGLONG)(ULONG_PTR)t.c, "request parent 0x%llx connect %p", v, t.c);
    l = 8; SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.r, INTERNET_OPTION_PARENT_HANDLE, &v, 8), ERROR_INTERNET_INVALID_OPTION);
    ot_trio_close(&t);
}

TEST(ot_val_buffer_sizes) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    static const DWORD opts[] = { INTERNET_OPTION_READ_BUFFER_SIZE, INTERNET_OPTION_WRITE_BUFFER_SIZE };
    for (int i = 0; i < 2; i++) {
        DWORD v;
        SET_ERR(0); DWORD l = sizeof v; EXPECT_FAIL(!U(InternetQueryOptionA)(t.s, opts[i], &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.s, opts[i], 4096), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        HINTERNET hs[] = { t.c, t.r };
        for (int k = 0; k < 2; k++) {
            DWORD d; CHECK(ot_qdw(hs[k], opts[i], &d)); t_note("opt %lu kind %c default %lu", opts[i], k ? 'R' : 'C', d);
            CHECK(ot_sdw(hs[k], opts[i], 12345)); CHECK(ot_qdw(hs[k], opts[i], &v)); EXPECT_EQ(v, 12345);
            CHECK(ot_sdw(hs[k], opts[i], 1)); CHECK(ot_qdw(hs[k], opts[i], &v)); EXPECT_EQ(v, 1);
            SET_ERR(0); EXPECT_FAIL(!ot_sdw(hs[k], opts[i], 0), ERROR_INVALID_PARAMETER);
            CHECK(ot_qdw(hs[k], opts[i], &v)); EXPECT_EQ(v, 1);
        }
    }
    ot_trio_close(&t);
}

TEST(ot_val_codepage_options) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) {
        DWORD v;
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_CODEPAGE, 65001)); CHECK(ot_qdw(hs[k], INTERNET_OPTION_CODEPAGE, &v)); EXPECT_EQ(v, 65001);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_CODEPAGE, 1252)); CHECK(ot_qdw(hs[k], INTERNET_OPTION_CODEPAGE, &v)); EXPECT_EQ(v, 1252);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_CODEPAGE, 0));
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(hs[k], INTERNET_OPTION_CODEPAGE, 1), ERROR_INVALID_PARAMETER);       /* not a code page */
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(hs[k], INTERNET_OPTION_CODEPAGE, 0x7fffffff), ERROR_INVALID_PARAMETER);
        /* CODEPAGE_PATH (100) and CODEPAGE_EXTRA (101) validate the same way */
        for (DWORD o = 100; o <= 101; o++) {
            CHECK(ot_sdw(hs[k], o, 65001)); CHECK(ot_qdw(hs[k], o, &v)); EXPECT_EQ(v, 65001);
            CHECK(ot_sdw(hs[k], o, 0));
            SET_ERR(0); EXPECT_FAIL(!ot_sdw(hs[k], o, 1), ERROR_INVALID_PARAMETER);
        }
        /* IDN (102): any value */
        CHECK(ot_sdw(hs[k], 102, 1)); CHECK(ot_qdw(hs[k], 102, &v)); t_note("IDN after set 1: %lu", v);
    }
    ot_trio_close(&t);
}

TEST(ot_val_http_decoding) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) {
        DWORD v;
        CHECK(ot_qdw(hs[k], INTERNET_OPTION_HTTP_DECODING, &v)); EXPECT_EQ(v, 0);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_HTTP_DECODING, 1)); CHECK(ot_qdw(hs[k], INTERNET_OPTION_HTTP_DECODING, &v)); EXPECT_EQ(v, 1);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_HTTP_DECODING, 0)); CHECK(ot_qdw(hs[k], INTERNET_OPTION_HTTP_DECODING, &v)); EXPECT_EQ(v, 0);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_HTTP_DECODING, 7)); CHECK(ot_qdw(hs[k], INTERNET_OPTION_HTTP_DECODING, &v));
        t_note("HTTP_DECODING after set 7 on %c: %lu", "SCR"[k], v);
    }
    DWORD v, l = sizeof v;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_DECODING, &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(NULL, INTERNET_OPTION_HTTP_DECODING, 1), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    /* a request created after the session enabled decoding */
    CHECK(ot_sdw(t.s, INTERNET_OPTION_HTTP_DECODING, 1));
    HINTERNET c2 = U(InternetConnectA)(t.s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET r2 = c2 ? U(HttpOpenRequestA)(c2, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    if (r2) { CHECK(ot_qdw(c2, INTERNET_OPTION_HTTP_DECODING, &v)); t_note("connect created after session decoding=1: %lu", v);
              CHECK(ot_qdw(r2, INTERNET_OPTION_HTTP_DECODING, &v)); t_note("request created after session decoding=1: %lu", v); U(InternetCloseHandle)(r2); }
    if (c2) U(InternetCloseHandle)(c2);
    ot_trio_close(&t);
}

TEST(ot_val_request_flags_and_priority) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx || !fx->h[OT_R]) { t_skip("fixture"); return; }
    DWORD v, l;
    /* case 0x17: only request/file handles */
    l = sizeof v; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_S], INTERNET_OPTION_REQUEST_FLAGS, &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof v; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_C], INTERNET_OPTION_REQUEST_FLAGS, &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(ot_qdw(fx->h[OT_R], INTERNET_OPTION_REQUEST_FLAGS, &v)); EXPECT_EQ(v, 0);
    if (fx->h[OT_X]) { CHECK(ot_qdw(fx->h[OT_X], INTERNET_OPTION_REQUEST_FLAGS, &v)); t_note("REQUEST_FLAGS after a fresh GET: 0x%lx", v); }
    /* REQUEST_PRIORITY (58): requests only, any value */
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    CHECK(ot_qdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &v)); EXPECT_EQ(v, 0);
    CHECK(ot_sdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, 0x7fffffff)); CHECK(ot_qdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &v)); EXPECT_EQ(v, 0x7fffffff);
    CHECK(ot_sdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, 3)); CHECK(ot_qdw(t.r, INTERNET_OPTION_REQUEST_PRIORITY, &v)); EXPECT_EQ(v, 3);
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.c, INTERNET_OPTION_REQUEST_PRIORITY, 3), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof v; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(t.s, INTERNET_OPTION_REQUEST_PRIORITY, &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    ot_trio_close(&t);
}

TEST(ot_val_security_flags_http_request) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    DWORD v, l;
    CHECK(ot_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v)); t_note("SECURITY_FLAGS on a plain HTTP request: 0x%lx", v);
    DWORD base = v;
    /* only the ignore bits are accepted (case 0x1f) */
    CHECK(ot_sdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, base | SECURITY_FLAG_IGNORE_UNKNOWN_CA));
    CHECK(ot_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v)); CHECKF(v & SECURITY_FLAG_IGNORE_UNKNOWN_CA, "0x%lx", v);
    CHECK(ot_sdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, v | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE));
    CHECK(ot_qdw(t.r, INTERNET_OPTION_SECURITY_FLAGS, &v));
    CHECKF((v & 0x3380) == 0x3380, "ignore bits 0x%lx", v);
    t_note("SECURITY_FLAGS after setting all ignore bits: 0x%lx", v);
    /* session / connect: wrong handle type (SRV.md F9) */
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.s, INTERNET_OPTION_SECURITY_FLAGS, 0x100), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.c, INTERNET_OPTION_SECURITY_FLAGS, 0x100), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof v; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(t.s, INTERNET_OPTION_SECURITY_FLAGS, &v, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    /* short set length: 122 (case 0x1f checks < 4 before 12010) */
    WORD w2 = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.r, INTERNET_OPTION_SECURITY_FLAGS, &w2, 2), ERROR_INSUFFICIENT_BUFFER);
    ot_trio_close(&t);
}

TEST(ot_val_bufferless_actions_handle_gates) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    /* REFRESH (37): NULL or session only; IGNORE_OFFLINE (77): any real handle; 87/89/90 session only */
    CHECK(U(InternetSetOptionA)(t.s, INTERNET_OPTION_REFRESH, NULL, 0));
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.c, INTERNET_OPTION_REFRESH, NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.r, INTERNET_OPTION_REFRESH, NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    CHECK(U(InternetSetOptionA)(t.s, INTERNET_OPTION_IGNORE_OFFLINE, NULL, 0));
    CHECK(U(InternetSetOptionA)(t.c, INTERNET_OPTION_IGNORE_OFFLINE, NULL, 0));
    CHECK(U(InternetSetOptionA)(t.r, INTERNET_OPTION_IGNORE_OFFLINE, NULL, 0));
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_IGNORE_OFFLINE, NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    static const DWORD sess_only[] = { 87, 89, 90 };
    for (int i = 0; i < 3; i++) {
        CHECK(U(InternetSetOptionA)(t.s, sess_only[i], NULL, 0));
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.c, sess_only[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.r, sess_only[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, sess_only[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    /* request-only buffer-less options (126, 150) */
    static const DWORD req_only[] = { 126, 150 };
    for (int i = 0; i < 2; i++) {
        CHECK(U(InternetSetOptionA)(t.r, req_only[i], NULL, 0));
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.s, req_only[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.c, req_only[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    ot_trio_close(&t);
}

TEST(ot_val_max_conns_defaults_global) {
    REQUIRE(U(InternetQueryOptionA));
    DWORD a, b;
    CHECK(ot_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &a));
    CHECK(ot_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &b));
    t_note("MAX_CONNS_PER_SERVER %lu, PER_1_0_SERVER %lu (registry-configurable; IE11 defaults 10/10 on Win10)", a, b);
    CHECK(a >= 2 && a <= 128); CHECK(b >= 2 && b <= 128);
    /* session/request: not HCon -> 12016 (case 0x49 LAB_18005a6f5 / 0x4a) */
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    DWORD v, l = sizeof v;
    SET_ERR(0); BOOL r = U(InternetQueryOptionA)(t.c, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &v, &l);
    EXPECT_FAIL(!r, ERROR_INTERNET_INVALID_OPERATION);        /* connect without server info */
    l = sizeof v; SET_ERR(0); r = U(InternetQueryOptionA)(t.c, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &v, &l);
    EXPECT_FAIL(!r, ERROR_INTERNET_INVALID_OPERATION);
    ot_trio_close(&t);
}

TEST(ot_val_max_conns_used_connect) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx || !fx->h[OT_X]) { t_skip("fixture"); return; }
    DWORD g, v;
    CHECK(ot_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &g));
    /* the connect that carried X now has server info: it answers the server limit */
    CHECK(ot_qdw(fx->h[OT_C], INTERNET_OPTION_MAX_CONNS_PER_SERVER, &v)); EXPECT_EQ(v, g);
}
