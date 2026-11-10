/* options_table: timeout, retry and connection-limit options (2..8, 63, 73, 74, 103).
 * Decomp: InternetSetOptionA@0x551b0 case 2..8/0x3f (global branch writes Global*Timeout, CONNECT_TIMEOUT 0 skipped),
 * INTERNET_HANDLE_OBJECT::SetTimeout@0x53bc0 (per-handle fields; CONNECT 0 ignored; BACKOFF not stored),
 * INTERNET_HANDLE_OBJECT::GetTimeout@0x6ec14 (BACKOFF always 0), GetGlobalTimeoutValue@0x6a790,
 * InternetSetOptionA case 0x49/0x4a (0 -> 160 ERROR_BAD_ARGUMENTS, EnsureRangeLimits(2,128), HCon without server
 * info -> 12016). Every test that changes a global value restores it. */
#include "ot.h"

static const DWORD TO_OPTS[] = { INTERNET_OPTION_CONNECT_TIMEOUT, INTERNET_OPTION_CONNECT_RETRIES, INTERNET_OPTION_SEND_TIMEOUT,
                                 INTERNET_OPTION_RECEIVE_TIMEOUT, INTERNET_OPTION_DATA_SEND_TIMEOUT, INTERNET_OPTION_DATA_RECEIVE_TIMEOUT,
                                 INTERNET_OPTION_FROM_CACHE_TIMEOUT };
#define NTO (int)(sizeof TO_OPTS / sizeof TO_OPTS[0])

TEST(ot_to_session_roundtrip) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    for (int i = 0; i < NTO; i++) {
        DWORD v = 10000 + 111 * i, got;
        CHECKF(ot_sdw(t.s, TO_OPTS[i], v), "set opt %lu err %lu", TO_OPTS[i], GetLastError());
        CHECKF(ot_qdw(t.s, TO_OPTS[i], &got) && got == v, "opt %lu got %lu want %lu", TO_OPTS[i], got, v);
    }
    ot_trio_close(&t);
}

TEST(ot_to_request_roundtrip_w) {
    REQUIRE(U(InternetSetOptionW));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < NTO; i++) {
            DWORD v = 20000 + 7 * i + k, got = 0, l = sizeof got;
            CHECK(U(InternetSetOptionW)(hs[k], TO_OPTS[i], &v, sizeof v));
            CHECK(U(InternetQueryOptionW)(hs[k], TO_OPTS[i], &got, &l));
            EXPECT_EQ(l, 4); EXPECT_EQ(got, v);
        }
    ot_trio_close(&t);
}

TEST(ot_to_handles_hold_their_own_values) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    for (int i = 0; i < NTO; i++) {
        DWORD c0, r0, got;
        CHECK(ot_qdw(t.c, TO_OPTS[i], &c0)); CHECK(ot_qdw(t.r, TO_OPTS[i], &r0));
        CHECK(ot_sdw(t.s, TO_OPTS[i], 31000 + i));                 /* parent changed after the children exist */
        CHECK(ot_qdw(t.c, TO_OPTS[i], &got)); EXPECT_EQ(got, c0);
        CHECK(ot_qdw(t.r, TO_OPTS[i], &got)); EXPECT_EQ(got, r0);
        CHECK(ot_sdw(t.r, TO_OPTS[i], 32000 + i));                 /* child changed: parent keeps its value */
        CHECK(ot_qdw(t.s, TO_OPTS[i], &got)); EXPECT_EQ(got, 31000 + i);
        CHECK(ot_qdw(t.c, TO_OPTS[i], &got)); EXPECT_EQ(got, c0);
    }
    ot_trio_close(&t);
}

TEST(ot_to_children_copy_parent_at_creation) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    for (int i = 0; i < NTO; i++) CHECK(ot_sdw(s, TO_OPTS[i], 41000 + i));
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    CHECK(c && r);
    for (int i = 0; i < NTO && r; i++) {
        DWORD got;
        CHECK(ot_qdw(c, TO_OPTS[i], &got)); CHECKF(got == 41000 + (DWORD)i, "connect opt %lu got %lu", TO_OPTS[i], got);
        CHECK(ot_qdw(r, TO_OPTS[i], &got)); CHECKF(got == 41000 + (DWORD)i, "request opt %lu got %lu", TO_OPTS[i], got);
    }
    if (r) U(InternetCloseHandle)(r);
    if (c) U(InternetCloseHandle)(c);
    U(InternetCloseHandle)(s);
}

TEST(ot_to_connect_timeout_zero_ignored) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++) {
        DWORD got;
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_CONNECT_TIMEOUT, 4321));
        SET_ERR(0xdead);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_CONNECT_TIMEOUT, 0));      /* TRUE, but SetTimeout skips 0 */
        CHECK(ot_qdw(hs[k], INTERNET_OPTION_CONNECT_TIMEOUT, &got)); EXPECT_EQ(got, 4321);
        /* the other timeouts do accept 0 */
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_RECEIVE_TIMEOUT, 0));
        CHECK(ot_qdw(hs[k], INTERNET_OPTION_RECEIVE_TIMEOUT, &got)); EXPECT_EQ(got, 0);
        CHECK(ot_sdw(hs[k], INTERNET_OPTION_CONNECT_RETRIES, 0));
        CHECK(ot_qdw(hs[k], INTERNET_OPTION_CONNECT_RETRIES, &got)); EXPECT_EQ(got, 0);
    }
    ot_trio_close(&t);
}

TEST(ot_to_global_connect_timeout_zero_ignored) {
    REQUIRE(U(InternetSetOptionA));
    DWORD old, got;
    CHECK(ot_qdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, &old));
    CHECK(ot_sdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, 0));
    CHECK(ot_qdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, &got)); EXPECT_EQ(got, old);
    CHECK(ot_sdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, old + 1));
    CHECK(ot_qdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, &got)); EXPECT_EQ(got, old + 1);
    CHECK(ot_sdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, old));
    CHECK(ot_qdw(NULL, INTERNET_OPTION_CONNECT_TIMEOUT, &got)); EXPECT_EQ(got, old);
}

TEST(ot_to_global_roundtrip_and_new_session) {
    REQUIRE(U(InternetSetOptionA));
    DWORD old[NTO];
    for (int i = 0; i < NTO; i++) CHECK(ot_qdw(NULL, TO_OPTS[i], &old[i]));
    for (int i = 0; i < NTO; i++) CHECK(ot_sdw(NULL, TO_OPTS[i], 51000 + i));
    for (int i = 0; i < NTO; i++) { DWORD g; CHECK(ot_qdw(NULL, TO_OPTS[i], &g)); EXPECT_EQ(g, 51000 + i); }
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    for (int i = 0; i < NTO && s; i++) {
        DWORD g; CHECK(ot_qdw(s, TO_OPTS[i], &g));
        CHECKF(g == 51000 + (DWORD)i, "new session opt %lu got %lu (copied from the globals at InternetOpen)", TO_OPTS[i], g);
    }
    for (int i = 0; i < NTO; i++) CHECK(ot_sdw(NULL, TO_OPTS[i], old[i]));          /* restore */
    for (int i = 0; i < NTO && s; i++) { DWORD g; CHECK(ot_qdw(s, TO_OPTS[i], &g)); EXPECT_EQ(g, 51000 + i); } /* session keeps its copy */
    if (s) U(InternetCloseHandle)(s);
}

TEST(ot_to_backoff_reads_zero) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { NULL, t.s, t.c, t.r };
    for (int k = 0; k < 4; k++) {
        DWORD got;
        CHECK(ot_qdw(hs[k], INTERNET_OPTION_CONNECT_BACKOFF, &got)); EXPECT_EQ(got, 0);
        if (k) {   /* per-handle: accepted, never stored */
            CHECK(ot_sdw(hs[k], INTERNET_OPTION_CONNECT_BACKOFF, 777));
            CHECK(ot_qdw(hs[k], INTERNET_OPTION_CONNECT_BACKOFF, &got)); EXPECT_EQ(got, 0);
        }
    }
    ot_trio_close(&t);
}

TEST(ot_to_length_rules) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { NULL, t.s, t.c, t.r };
    for (int k = 0; k < 4; k++)
        for (int i = 0; i < NTO; i++)
            for (int w = 0; w < 2; w++) {
                DWORD opt = TO_OPTS[i]; ULONGLONG v = 5000; DWORD l;
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], opt, &v, 0), ERROR_INVALID_PARAMETER);
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], opt, &v, 2), ERROR_INTERNET_BAD_OPTION_LENGTH);
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], opt, &v, 8), ERROR_INTERNET_BAD_OPTION_LENGTH);
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], opt, NULL, 4), ERROR_INVALID_PARAMETER);
                /* query: NULL buffer / short buffer -> 122 with the size; long buffer -> 4 */
                l = 0; SET_ERR(0); EXPECT_FAIL(!ot_q(w, hs[k], opt, NULL, &l), ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
                l = 3; SET_ERR(0); EXPECT_FAIL(!ot_q(w, hs[k], opt, &v, &l), ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
                l = 8; CHECK(ot_q(w, hs[k], opt, &v, &l)); EXPECT_EQ(l, 4);
                l = 4; SET_ERR(0); EXPECT_FAIL(!ot_q(w, hs[k], opt, NULL, &l), ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
            }
    ot_trio_close(&t);
}

TEST(ot_to_values_not_validated) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    static const DWORD vals[] = { 1, 0x7fffffff, 0x80000000, 0xffffffff };
    for (int i = 0; i < NTO; i++)
        for (int j = 0; j < 4; j++) {
            DWORD got;
            CHECK(ot_sdw(t.r, TO_OPTS[i], vals[j]));
            CHECK(ot_qdw(t.r, TO_OPTS[i], &got)); EXPECT_EQ(got, vals[j]);
        }
    ot_trio_close(&t);
}

/* ---- connection limits ------------------------------------------------------------------------ */
static const DWORD CONN_OPTS[] = { INTERNET_OPTION_MAX_CONNS_PER_SERVER, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER };

TEST(ot_conns_global_clamped_2_128) {
    REQUIRE(U(InternetSetOptionA));
    for (int i = 0; i < 2; i++) {
        DWORD opt = CONN_OPTS[i], old, got;
        CHECK(ot_qdw(NULL, opt, &old));
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(NULL, opt, 0), ERROR_BAD_ARGUMENTS);
        CHECK(ot_qdw(NULL, opt, &got)); EXPECT_EQ(got, old);
        static const struct { DWORD in, out; } m[] = { { 1, 2 }, { 2, 2 }, { 3, 3 }, { 10, 10 }, { 128, 128 }, { 129, 128 }, { 0xffffffff, 128 } };
        for (int j = 0; j < 7; j++) {
            CHECK(ot_sdw(NULL, opt, m[j].in));
            CHECK(ot_qdw(NULL, opt, &got)); CHECKF(got == m[j].out, "opt %lu set %lu got %lu want %lu", opt, m[j].in, got, m[j].out);
        }
        CHECK(ot_sdw(NULL, opt, old));
        CHECK(ot_qdw(NULL, opt, &got)); EXPECT_EQ(got, old);
    }
}

TEST(ot_conns_wrong_handles) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    for (int i = 0; i < 2; i++) {
        DWORD opt = CONN_OPTS[i];
        /* session / request: not an HCon -> 12016; an unused connect accepts the value (clamped 2..128, VM) */
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.s, opt, 4), ERROR_INTERNET_INVALID_OPERATION);
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.r, opt, 4), ERROR_INTERNET_INVALID_OPERATION);
        /* unused connect: SetNewLimit on its CServerInfo, or 12016 when it has none yet (varied between boots) */
        SET_ERR(0); BOOL r = ot_sdw(t.c, opt, 4);
        CHECKF(r || GetLastError() == ERROR_INTERNET_INVALID_OPERATION, "opt %lu set on connect err %lu", opt, GetLastError());
        t_note("opt %lu set 4 on an unused connect: r=%d", opt, r);
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.c, opt, 0), ERROR_BAD_ARGUMENTS);   /* 0 is checked first */
        SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.s, opt, 0), ERROR_BAD_ARGUMENTS);
    }
    ot_trio_close(&t);
}

TEST(ot_conns_per_proxy_global_only) {
    REQUIRE(U(InternetSetOptionA));
    DWORD old, got;
    CHECK(ot_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_PROXY, &old));
    t_note("MAX_CONNS_PER_PROXY default %lu", old);
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_PROXY, 0), ERROR_BAD_ARGUMENTS);
    CHECK(ot_sdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_PROXY, old));
    CHECK(ot_qdw(NULL, INTERNET_OPTION_MAX_CONNS_PER_PROXY, &got)); EXPECT_EQ(got, old);
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.s, INTERNET_OPTION_MAX_CONNS_PER_PROXY, 4), ERROR_INTERNET_INVALID_OPERATION);
    SET_ERR(0); EXPECT_FAIL(!ot_sdw(t.c, INTERNET_OPTION_MAX_CONNS_PER_PROXY, 4), ERROR_INTERNET_INVALID_OPERATION);
    ot_trio_close(&t);
}
