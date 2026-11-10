/* options_table: entry rules shared by every option (order of the checks, NULL handle, dead handles, units).
 * Decomp: InternetQueryOptionA@0x59730 (lpdwBufferLength NULL -> 87 before anything else; NULL buffer -> *len = 0;
 * NULL handle: per-process options + 15/24 only, else 12009 outside 1..0xC0 / 12018 inside, *len = 0),
 * InternetSetOptionA@0x551b0 (NULL buffer or zero length -> 87 before the handle is looked at, except the
 * buffer-less options; NULL handle like query; outside 1..0xC0 -> 12009), MapHandleToAddress@0x58740 (stale
 * handle -> 6 ERROR_INVALID_HANDLE). */
#include "ot.h"

static const DWORD OUTSIDE[] = { 0, 0xC1, 0xC2, 0xFF, 0x100, 1000, 99999, 0x7FFFFFFF, 0xFFFFFFFF };
#define NOUT (int)(sizeof OUTSIDE / sizeof OUTSIDE[0])

TEST(ot_rule_query_null_length_pointer) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    static const DWORD opts[] = { 0, 2, 9, 21, 31, 59, 99999 };
    for (int k = 0; k < OT_NK; k++) {
        if (k != OT_N && !fx->h[k]) continue;
        for (int i = 0; i < 7; i++) {
            DWORD v[4];
            SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[k], opts[i], v, NULL), ERROR_INVALID_PARAMETER);
            SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[k], opts[i], NULL, NULL), ERROR_INVALID_PARAMETER);
            /* W forwards these options to A unchanged */
            SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(fx->h[k], opts[i], v, NULL), ERROR_INVALID_PARAMETER);
        }
    }
}

TEST(ot_rule_query_null_handle_inside_range) {
    REQUIRE(U(InternetQueryOptionA));
    /* options that are never per-process: always 12018 with *len forced to 0 */
    static const DWORD opts[] = { 1, 9, 10, 12, 13, 21, 22, 23, 28, 29, 31, 32, 33, 34, 35, 36, 41, 43, 44, 45, 53, 58, 65, 68, 100, 101, 102, 105, 0xC0 };
    for (int i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++)
        for (int w = 0; w < 2; w++) {
            BYTE b[64]; DWORD l = sizeof b;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, NULL, opts[i], b, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
            CHECKF(l == 0, "opt %lu %c: len %lu after the NULL-handle rejection", opts[i], w ? 'W' : 'A', l);
        }
}

TEST(ot_rule_query_null_handle_outside_range) {
    REQUIRE(U(InternetQueryOptionA));
    for (int i = 0; i < NOUT; i++)
        for (int w = 0; w < 2; w++) {
            BYTE b[64]; DWORD l = sizeof b;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, NULL, OUTSIDE[i], b, &l), ERROR_INTERNET_INVALID_OPTION);
        }
}

TEST(ot_rule_set_null_handle) {
    REQUIRE(U(InternetSetOptionA));
    static const DWORD inside[] = { 1, 9, 10, 12, 13, 21, 28, 31, 34, 41, 45, 58, 65, 68, 100, 0xC0 };
    for (int w = 0; w < 2; w++) {
        for (int i = 0; i < (int)(sizeof inside / sizeof inside[0]); i++) {
            DWORD v = 1;
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, NULL, inside[i], &v, sizeof v), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        }
        for (int i = 0; i < NOUT; i++) {
            DWORD v = 1;
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, NULL, OUTSIDE[i], &v, sizeof v), ERROR_INTERNET_INVALID_OPTION);
        }
    }
}

TEST(ot_rule_set_outside_range_real_handles) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < NOUT; i++)
            for (int w = 0; w < 2; w++) {
                DWORD v = 1;
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], OUTSIDE[i], &v, sizeof v), ERROR_INTERNET_INVALID_OPTION);
                /* the NULL-buffer check runs first: 87 even for a nonexistent option */
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], OUTSIDE[i], NULL, 0), ERROR_INVALID_PARAMETER);
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], OUTSIDE[i], &v, 0), ERROR_INVALID_PARAMETER);
            }
    ot_trio_close(&t);
}

TEST(ot_rule_closed_handle) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    CHECK(U(InternetCloseHandle)(c));
    CHECK(U(InternetCloseHandle)(s));
    HINTERNET dead[] = { s, c };
    for (int k = 0; k < 2; k++)
        for (int w = 0; w < 2; w++) {
            DWORD v = 1234, l = sizeof v;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, dead[k], INTERNET_OPTION_CONNECT_TIMEOUT, &v, &l), ERROR_INVALID_HANDLE);
            l = sizeof v;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, dead[k], INTERNET_OPTION_HANDLE_TYPE, &v, &l), ERROR_INVALID_HANDLE);
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, dead[k], INTERNET_OPTION_CONNECT_TIMEOUT, &v, sizeof v), ERROR_INVALID_HANDLE);
            /* argument checks that come before the handle lookup still win */
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, dead[k], INTERNET_OPTION_CONNECT_TIMEOUT, &v, NULL), ERROR_INVALID_PARAMETER);
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, dead[k], INTERNET_OPTION_CONNECT_TIMEOUT, NULL, 0), ERROR_INVALID_PARAMETER);
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, dead[k], INTERNET_OPTION_CONNECT_TIMEOUT, &v, 0), ERROR_INVALID_PARAMETER);
        }
}

TEST(ot_rule_bogus_handle_values) {
    REQUIRE(U(InternetQueryOptionA));
    /* HINTERNETs are small integers mapped through a table (MapHandleToAddress): values that were never issued are
     * rejected without being dereferenced. */
    static const ULONG_PTR vals[] = { 1, 4, 0x00CC0000, 0x00CC0001, 0x00FFFFFC, 0x7FFFFFF0 };
    for (int i = 0; i < 6; i++)
        for (int w = 0; w < 2; w++) {
            DWORD v, l = sizeof v;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, (HINTERNET)vals[i], INTERNET_OPTION_HANDLE_TYPE, &v, &l), ERROR_INVALID_HANDLE);
            v = 1000;
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, (HINTERNET)vals[i], INTERNET_OPTION_RECEIVE_TIMEOUT, &v, sizeof v), ERROR_INVALID_HANDLE);
        }
}

TEST(ot_rule_handle_type_values) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    static const struct { int k; DWORD t; } m[] = {
        { OT_S, INTERNET_HANDLE_TYPE_INTERNET }, { OT_C, INTERNET_HANDLE_TYPE_CONNECT_HTTP }, { OT_R, INTERNET_HANDLE_TYPE_HTTP_REQUEST },
        { OT_X, INTERNET_HANDLE_TYPE_HTTP_REQUEST }, { OT_T, INTERNET_HANDLE_TYPE_HTTP_REQUEST }, { OT_F, INTERNET_HANDLE_TYPE_CONNECT_FTP },
        { OT_L, INTERNET_HANDLE_TYPE_FILE_REQUEST } };
    for (int i = 0; i < 7; i++) {
        if (!fx->h[m[i].k]) { t_note("kind %c missing", OT_KINDS[m[i].k]); continue; }
        for (int w = 0; w < 2; w++) {
            DWORD v = 0xdeadbeef, l = sizeof v;
            CHECK(ot_q(w, fx->h[m[i].k], INTERNET_OPTION_HANDLE_TYPE, &v, &l));
            CHECKF(v == m[i].t && l == 4, "kind %c %c: type %lu len %lu want %lu", OT_KINDS[m[i].k], w ? 'W' : 'A', v, l, m[i].t);
            SET_ERR(0); EXPECT_FAIL(!ot_s(w, fx->h[m[i].k], INTERNET_OPTION_HANDLE_TYPE, &v, sizeof v), ERROR_INTERNET_OPTION_NOT_SETTABLE);
        }
    }
}

TEST(ot_rule_handle_type_ftp_find_and_file) {
    REQUIRE(U(FtpFindFirstFileA));
    static const srv_ftp_file files[] = { { "/hello.txt", "hello", 5, "20200102030405" }, { "/pub/", NULL, -1 } };
    srv_ftp_config fc = { files, 2 }; srv_config cfg = { SRV_FTP }; cfg.ftp = &fc; srv *s;
    if (srv_start(&cfg, &s)) { t_skip("ftp server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hf = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), "anonymous", "x@y", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECK(hf != NULL);
    if (hf) {
        WIN32_FIND_DATAA fd;
        HINTERNET hfind = U(FtpFindFirstFileA)(hf, "/*", &fd, INTERNET_FLAG_RELOAD, 0);
        if (hfind) {
            DWORD v = 0, l = sizeof v;
            CHECK(U(InternetQueryOptionA)(hfind, INTERNET_OPTION_HANDLE_TYPE, &v, &l)); EXPECT_EQ(v, INTERNET_HANDLE_TYPE_FTP_FIND);
            l = sizeof v; CHECK(U(InternetQueryOptionA)(hfind, INTERNET_OPTION_REQUEST_FLAGS, &v, &l));
            t_note("ftp find REQUEST_FLAGS 0x%lx", v);
            U(InternetCloseHandle)(hfind);
        } else t_note("FtpFindFirstFile failed %lu", GetLastError());
        HINTERNET hfile = U(FtpOpenFileA)(hf, "/hello.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0);
        if (hfile) {
            DWORD v = 0, l = sizeof v;
            CHECK(U(InternetQueryOptionA)(hfile, INTERNET_OPTION_HANDLE_TYPE, &v, &l)); EXPECT_EQ(v, INTERNET_HANDLE_TYPE_FTP_FILE);
            char b[16]; DWORD rd = 0; U(InternetReadFile)(hfile, b, sizeof b, &rd);
            char url[128]; l = sizeof url;
            if (U(InternetQueryOptionA)(hfile, INTERNET_OPTION_URL, url, &l)) t_note("ftp file URL '%s' len %lu", url, l);
            else t_note("ftp file URL err %lu", GetLastError());
            U(InternetCloseHandle)(hfile);
        } else t_note("FtpOpenFile failed %lu", GetLastError());
        U(InternetCloseHandle)(hf);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(ot_rule_null_buffer_sets_len_zero_then_122) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    /* *len is forced to 0 for a NULL buffer, so a non-zero *len does not matter */
    static const struct { DWORD opt; int k; DWORD need; } m[] = {
        { INTERNET_OPTION_HANDLE_TYPE, OT_S, 4 }, { INTERNET_OPTION_RECEIVE_TIMEOUT, OT_C, 4 }, { INTERNET_OPTION_PARENT_HANDLE, OT_R, 8 },
        { INTERNET_OPTION_CONTEXT_VALUE, OT_R, 8 }, { INTERNET_OPTION_HTTP_VERSION, OT_N, 8 }, { INTERNET_OPTION_VERSION, OT_N, 8 } };
    for (int i = 0; i < 6; i++) {
        DWORD l = 4096;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[m[i].k], m[i].opt, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
        CHECKF(l == m[i].need, "opt %lu: len %lu want %lu", m[i].opt, l, m[i].need);
        l = 4096;
        SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(fx->h[m[i].k], m[i].opt, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
        CHECKF(l == m[i].need, "opt %lu W: len %lu want %lu", m[i].opt, l, m[i].need);
    }
}

TEST(ot_rule_short_buffer_untouched) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    static const DWORD opts[] = { INTERNET_OPTION_HANDLE_TYPE, INTERNET_OPTION_CONNECT_TIMEOUT, INTERNET_OPTION_PARENT_HANDLE, INTERNET_OPTION_CONTEXT_VALUE };
    for (int i = 0; i < 4; i++)
        for (int w = 0; w < 2; w++) {
            BYTE b[16]; memset(b, 0xA5, sizeof b); DWORD l = 3;
            SET_ERR(0); EXPECT_FAIL(!ot_q(w, fx->h[OT_R], opts[i], b, &l), ERROR_INSUFFICIENT_BUFFER);
            CHECKF(b[0] == 0xA5 && b[1] == 0xA5 && b[2] == 0xA5, "opt %lu %c: buffer written on failure (%s)", opts[i], w ? 'W' : 'A', ot_hex(b, 4));
        }
}

TEST(ot_rule_success_last_error) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    /* InternetQueryOptionA ends with SetLastError(0 or err): success clears a stale value */
    static const DWORD opts[] = { INTERNET_OPTION_HANDLE_TYPE, INTERNET_OPTION_CONNECT_TIMEOUT, INTERNET_OPTION_USER_AGENT, INTERNET_OPTION_PARENT_HANDLE };
    for (int i = 0; i < 4; i++) {
        BYTE b[256]; DWORD l = sizeof b;
        SET_ERR(0xdead);
        CHECK(U(InternetQueryOptionA)(fx->h[OT_S], opts[i], b, &l));
        CHECKF(GetLastError() == 0, "opt %lu: GetLastError %lu after success", opts[i], GetLastError());
    }
}

TEST(ot_rule_a_and_w_agree_on_fixed_options) {
    REQUIRE(U(InternetQueryOptionW));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    static const DWORD opts[] = { 2, 3, 5, 6, 7, 8, 9, 12, 13, 22, 23, 31, 36, 58, 59, 63, 65, 68, 73, 74, 100, 101, 102, 103, 148 };
    int compared = 0;
    for (int k = 0; k < OT_NK; k++) {
        if (k != OT_N && !fx->h[k]) continue;
        for (int i = 0; i < (int)(sizeof opts / sizeof opts[0]); i++) {
            BYTE a[64], b[64]; DWORD la = sizeof a, lb = sizeof b; memset(a, 0, sizeof a); memset(b, 0, sizeof b);
            SET_ERR(0); BOOL ra = U(InternetQueryOptionA)(fx->h[k], opts[i], a, &la); DWORD ea = GetLastError();
            SET_ERR(0); BOOL rb = U(InternetQueryOptionW)(fx->h[k], opts[i], b, &lb); DWORD eb = GetLastError();
            CHECKF(ra == rb && la == lb && (ra ? !memcmp(a, b, la) : ea == eb), "kind %c opt %lu: A r=%d e=%lu l=%lu / W r=%d e=%lu l=%lu",
                   OT_KINDS[k], opts[i], ra, ea, la, rb, eb, lb);
            compared++;
        }
    }
    CHECK(compared > 50);
}

TEST(ot_rule_readonly_options) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    /* 12011 ERROR_INTERNET_OPTION_NOT_SETTABLE on real handles (InternetSetOptionA first case group + VM) */
    static const DWORD ro[] = { 1, 9, 15, 17, 19, 20, 51, 55, 56, 57, 61, 97, 147 };
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < (int)(sizeof ro / sizeof ro[0]); i++)
            for (int w = 0; w < 2; w++) {
                ULONGLONG v = 0;
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], ro[i], &v, 4), ERROR_INTERNET_OPTION_NOT_SETTABLE);
                SET_ERR(0); EXPECT_FAIL(!ot_s(w, hs[k], ro[i], &v, 8), ERROR_INTERNET_OPTION_NOT_SETTABLE);
            }
    /* KEEP_CONNECTION (22) is read-only too */
    DWORD v = 1;
    SET_ERR(0); EXPECT_FAIL(!ot_s(0, t.c, INTERNET_OPTION_KEEP_CONNECTION, &v, 4), ERROR_INTERNET_OPTION_NOT_SETTABLE);
    ot_trio_close(&t);
}

TEST(ot_rule_not_implemented_options) {
    REQUIRE(U(InternetSetOptionA));
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    /* ASYNC_PRIORITY (16), 78..80 -> 120 ERROR_CALL_NOT_IMPLEMENTED on set (session/connect/request) */
    static const DWORD ni[] = { 16, 78, 79, 80 };
    HINTERNET hs[] = { t.s, t.c, t.r };
    for (int k = 0; k < 3; k++)
        for (int i = 0; i < 4; i++) {
            DWORD v = 0;
            SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(hs[k], ni[i], &v, 4), ERROR_CALL_NOT_IMPLEMENTED);
            SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionW)(hs[k], ni[i], &v, 4), ERROR_CALL_NOT_IMPLEMENTED);
        }
    /* CALLBACK_FILTER (54): ERROR_NOT_SUPPORTED */
    DWORD v = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.s, 54, &v, 4), ERROR_NOT_SUPPORTED);
    ot_trio_close(&t);
}
