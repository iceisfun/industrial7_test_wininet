/* hqi_args.c - HttpQueryInfoA/W argument validation, handle checks, modifier rules.
 * VM_TIMEOUT: 240
 *
 * Decomp basis [D]: HttpQueryInfoA@0x54ae0 checks, in order: handle (MapHandleToAddress -> 6, type 'HReq' -> 12018),
 * level (low 26 bits) > 0x5F && != 0xFFFF -> 87, lpdwBufferLength NULL -> 87, illegal modifier pairs -> 87,
 * *lpdwIndex != 0 with COALESCE_WITH_COMMA -> 12150, *lpdwIndex != 0 for levels 18..22 -> 12150,
 * CUSTOM: NULL buffer -> 87, ASCII control/space in the name -> 87 (name ends at NUL ':' CR LF),
 * known level: modifier bits (0xF8000000) not in GlobalKnownHeaders[level].mask -> 12154,
 * NULL buffer -> *len = 0 first, then QueryInfo. HttpQueryInfoW@0x54330 adds: len NULL or (*len != 0 && buffer NULL) -> 87.
 */
#include "rh.h"

static const char RESP_BASIC[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 5\r\n"
    "X-Test:   42\r\n"
    "X-Multi: a\r\n"
    "X-Multi: b\r\n"
    "Date: Tue, 15 Nov 1994 12:45:26 GMT\r\n"
    "Connection: close\r\n"
    "\r\n"
    "hello";

#define OPEN_BASIC(c) do { if (!RH_RAW((c), "GET", RESP_BASIC)) return; RH_SENT_OR_FAIL(c); } while (0)

/* ------------------------------------------------------------------ handles */
TEST(hqi_args_null_handle) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    char b[64]; DWORD l = sizeof b;
    SetLastError(0);
    CHECK(!U(HttpQueryInfoA)(NULL, HTTP_QUERY_STATUS_CODE, b, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    WCHAR w[64]; l = sizeof w;
    CHECK(!U(HttpQueryInfoW)(NULL, HTTP_QUERY_STATUS_CODE, w, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    strcpy(b, "X-Test"); l = sizeof b;
    CHECK(!U(HttpQueryInfoA)(NULL, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}

TEST(hqi_args_garbage_handles) {
    REQUIRE(U(HttpQueryInfoA));
    static const ULONG_PTR vals[] = { 1, 4, 0xCC0, 0x12340, 0xFFFC, 0x7FFFFFF0 };
    for (size_t i = 0; i < sizeof vals / sizeof vals[0]; i++) {
        char b[64]; DWORD l = sizeof b;
        SetLastError(0);
        BOOL ok = U(HttpQueryInfoA)((HINTERNET)vals[i], HTTP_QUERY_STATUS_CODE, b, &l, NULL);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_HANDLE, "handle %p: ok=%d err=%lu", (void *)vals[i], ok, e);
    }
}

/* the handle is validated before the level and the length pointer [D] */
TEST(hqi_args_handle_checked_before_params) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    SetLastError(0);
    CHECK(!U(HttpQueryInfoA)(NULL, HTTP_QUERY_STATUS_CODE, NULL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    char b[8]; DWORD l = sizeof b;
    CHECK(!U(HttpQueryInfoA)(NULL, 0x1234, b, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    CHECK(!U(HttpQueryInfoA)(NULL, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_SYSTEMTIME, b, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    /* W validates the length pointer first (before calling A) [D HttpQueryInfoW] */
    CHECK(!U(HttpQueryInfoW)(NULL, HTTP_QUERY_STATUS_CODE, NULL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    l = 8;
    CHECK(!U(HttpQueryInfoW)(NULL, HTTP_QUERY_STATUS_CODE, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(hqi_args_wrong_handle_types) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(InternetConnectA));
    HINTERNET hi = t_inet_open("rh-agent/1.0");
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hi && hc);
    char b[64]; DWORD l;
    l = sizeof b; CHECK(!U(HttpQueryInfoA)(hi, HTTP_QUERY_STATUS_CODE, b, &l, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof b; CHECK(!U(HttpQueryInfoA)(hc, HTTP_QUERY_STATUS_CODE, b, &l, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    WCHAR w[32]; l = sizeof w;
    CHECK(!U(HttpQueryInfoW)(hi, HTTP_QUERY_STATUS_CODE, w, &l, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof w; CHECK(!U(HttpQueryInfoW)(hc, HTTP_QUERY_RAW_HEADERS_CRLF, w, &l, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    strcpy(b, "X-Test"); l = sizeof b;
    CHECK(!U(HttpQueryInfoA)(hc, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
}

TEST(hqi_args_closed_request_handle) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    HINTERNET hr = c.hr;
    CHECK(U(InternetCloseHandle)(hr)); c.hr = NULL;
    char b[64]; DWORD l = sizeof b;
    SetLastError(0);
    CHECK(!U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE, b, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    WCHAR w[32]; l = sizeof w;
    CHECK(!U(HttpQueryInfoW)(hr, HTTP_QUERY_STATUS_TEXT, w, &l, NULL)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    rh_close(&c);
}

/* ------------------------------------------------------------------ level range */
TEST(hqi_args_level_out_of_range) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    static const DWORD lv[] = { 0x60, 0x61, 0x62, 0x7F, 0x80, 0xFF, 0x100, 0x1000, 0x7FFF, 0xFFFE, 0x10000, 0x1FFFF, 0x10000 | 0xFFFF,
                                0x100000, 0x1000000, 0x2000000, 0x3FFFFFE, 0x3FFFFFF };
    for (size_t i = 0; i < sizeof lv / sizeof lv[0]; i++) {
        EXPECT_QERR(c.hr, lv[i], ERROR_INVALID_PARAMETER);
        EXPECT_QERRW(c.hr, lv[i], ERROR_INVALID_PARAMETER);
        EXPECT_QERR(c.hr, lv[i] | HTTP_QUERY_FLAG_NUMBER, ERROR_INVALID_PARAMETER);
    }
    /* the highest valid levels answer normally */
    EXPECT_QA(c.hr, 0x5F, NULL);   /* Public-Key-Pins-Report-Only, absent */
    EXPECT_QA(c.hr, 0x5E, NULL);
    EXPECT_QA(c.hr, HTTP_QUERY_PUBLIC_KEY_PINS_REPORT_ONLY, NULL);
    rh_close(&c);
}

TEST(hqi_args_null_length_pointer) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    char b[64]; WCHAR w[64];
    static const DWORD lv[] = { HTTP_QUERY_STATUS_CODE, HTTP_QUERY_STATUS_TEXT, HTTP_QUERY_CONTENT_TYPE, HTTP_QUERY_RAW_HEADERS_CRLF,
                                HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, HTTP_QUERY_DATE | HTTP_QUERY_FLAG_SYSTEMTIME,
                                HTTP_QUERY_USER_AGENT | HTTP_QUERY_FLAG_REQUEST_HEADERS, HTTP_QUERY_MIME_VERSION };
    for (size_t i = 0; i < sizeof lv / sizeof lv[0]; i++) {
        SetLastError(0);
        CHECKF(!U(HttpQueryInfoA)(c.hr, lv[i], b, NULL, NULL), "A level 0x%lx", lv[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(!U(HttpQueryInfoW)(c.hr, lv[i], w, NULL, NULL), "W level 0x%lx", lv[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    strcpy(b, "X-Test");
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    lstrcpyW(w, L"X-Test");
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_CUSTOM, w, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    rh_close(&c);
}

/* ------------------------------------------------------------------ modifier pairs (87) */
static const DWORD bad_pairs[] = {
    HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA,
    HTTP_QUERY_FLAG_NUMBER64 | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA,
    HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_NUMBER64,
    HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_SYSTEMTIME,
    HTTP_QUERY_FLAG_SYSTEMTIME | HTTP_QUERY_FLAG_NUMBER64,
    HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA,
    HTTP_QUERY_FLAG_SYSTEMTIME | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA,
    HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_NUMBER64 | HTTP_QUERY_FLAG_SYSTEMTIME,
    HTTP_QUERY_MODIFIER_FLAGS_MASK,
    HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_SYSTEMTIME,
    HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA | HTTP_QUERY_FLAG_COALESCE,
};

TEST(hqi_args_bad_modifier_pairs) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    static const DWORD lv[] = { HTTP_QUERY_CONTENT_LENGTH, HTTP_QUERY_DATE, HTTP_QUERY_STATUS_CODE, HTTP_QUERY_CONTENT_TYPE,
                                HTTP_QUERY_RAW_HEADERS_CRLF, HTTP_QUERY_MIME_VERSION, HTTP_QUERY_SET_COOKIE };
    for (size_t p = 0; p < sizeof bad_pairs / sizeof bad_pairs[0]; p++)
        for (size_t i = 0; i < sizeof lv / sizeof lv[0]; i++) {
            EXPECT_QERR(c.hr, lv[i] | bad_pairs[p], ERROR_INVALID_PARAMETER);
            EXPECT_QERRW(c.hr, lv[i] | bad_pairs[p], ERROR_INVALID_PARAMETER);
        }
    for (size_t p = 0; p < sizeof bad_pairs / sizeof bad_pairs[0]; p++) {
        EXPECT_QCERR(c.hr, "X-Test", bad_pairs[p], ERROR_INVALID_PARAMETER);
        EXPECT_QCERR(c.hr, "X-Absent", bad_pairs[p], ERROR_INVALID_PARAMETER);
    }
    rh_close(&c);
}

/* pairs that are NOT rejected by the pair check */
TEST(hqi_args_allowed_modifier_pairs) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    DWORD n = 0, l;
    /* REQUEST_HEADERS|NUMBER on Content-Length (mask 0xA8): passes; request has no Content-Length -> 12150 */
    EXPECT_QERR(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_NUMBER, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_NUMBER64, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR(c.hr, HTTP_QUERY_DATE | HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_SYSTEMTIME, ERROR_HTTP_HEADER_NOT_FOUND);
    /* COALESCE with NUMBER passes the pair check but COALESCE is in no mask -> 12154 */
    EXPECT_QERR(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_COALESCE | HTTP_QUERY_FLAG_NUMBER, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR(c.hr, HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_COALESCE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, ERROR_HTTP_INVALID_QUERY_REQUEST);
    /* COALESCE_WITH_COMMA is outside the mask bits: allowed for every level */
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "text/plain");
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "OK");
    EXPECT_QA(c.hr, HTTP_QUERY_VERSION | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "HTTP/1.1");
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "200");
    l = sizeof n;
    CHECK(rh_callA(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_COALESCE, &n, sizeof n, NULL) == FALSE);
    EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    rh_close(&c);
}

/* ------------------------------------------------------------------ per-level modifier masks (12154) */
static const DWORD mods4[] = { HTTP_QUERY_FLAG_SYSTEMTIME, HTTP_QUERY_FLAG_NUMBER, HTTP_QUERY_FLAG_COALESCE, HTTP_QUERY_FLAG_NUMBER64 };

TEST(hqi_args_modifier_mask_table) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    int rejected = 0, accepted = 0;
    for (DWORD lv = 0; lv < 96; lv++) {
        for (size_t m = 0; m < 4; m++) {
            DWORD mod = mods4[m];
            BYTE buf[64]; DWORD idx = 0;
            rh_callA(c.hr, lv | mod, buf, sizeof buf, &idx);
            if (!(rh_known[lv].mask & mod)) {
                rejected++;
                CHECKF(!rh_ok && rh_err == ERROR_HTTP_INVALID_QUERY_REQUEST, "level %lu mod 0x%lx: ok=%d err=%lu want 12154", lv, mod, rh_ok, rh_err);
            } else {
                accepted++;
                /* allowed: Content-Length NUMBER/NUMBER64 = 0, STATUS_CODE NUMBER = 200, absent date headers = 12150 */
                if (lv == HTTP_QUERY_CONTENT_LENGTH) CHECKF(rh_ok && rh_len == (mod == HTTP_QUERY_FLAG_NUMBER ? 4u : 8u), "CL mod 0x%lx ok=%d err=%lu len=%lu", mod, rh_ok, rh_err, rh_len);
                else if (lv == HTTP_QUERY_STATUS_CODE) CHECKF(rh_ok && *(DWORD *)buf == 200 && rh_len == 4, "STATUS_CODE NUMBER ok=%d err=%lu", rh_ok, rh_err);
                else CHECKF(!rh_ok && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "level %lu mod 0x%lx ok=%d err=%lu want 12150", lv, mod, rh_ok, rh_err);
            }
        }
    }
    EXPECT_EQ(accepted, 9);    /* 6 SYSTEMTIME levels (9, 11, 32, 36, 59, 68), CL NUMBER + NUMBER64, STATUS_CODE NUMBER */
    t_note("mask table: %d rejected, %d accepted", rejected, accepted);
    rh_close(&c);
}

/* the same rules through HttpQueryInfoW (non-CUSTOM levels pass straight to A) */
TEST(hqi_args_modifier_mask_table_w) {
    REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    for (DWORD lv = 0; lv < 96; lv++)
        for (size_t m = 0; m < 4; m++) {
            if (rh_known[lv].mask & mods4[m]) continue;
            WCHAR w[32];
            rh_callW(c.hr, lv | mods4[m], w, sizeof w, NULL);
            CHECKF(!rh_ok && rh_err == ERROR_HTTP_INVALID_QUERY_REQUEST, "W level %lu mod 0x%lx: ok=%d err=%lu", lv, mods4[m], rh_ok, rh_err);
        }
    rh_close(&c);
}

/* REQUEST_HEADERS is rejected (12154) only for the levels whose mask lacks 0x80000000: 19, 20, 46, 71 [D] */
TEST(hqi_args_request_flag_mask) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    for (DWORD lv = 0; lv < 96; lv++) {
        char b[4096]; rh_callA(c.hr, lv | HTTP_QUERY_FLAG_REQUEST_HEADERS, b, sizeof b, NULL);
        if (!(rh_known[lv].mask & HTTP_QUERY_FLAG_REQUEST_HEADERS))
            CHECKF(!rh_ok && rh_err == ERROR_HTTP_INVALID_QUERY_REQUEST, "REQ level %lu ok=%d err=%lu want 12154", lv, rh_ok, rh_err);
        else
            CHECKF(rh_ok || rh_err != ERROR_HTTP_INVALID_QUERY_REQUEST, "REQ level %lu unexpectedly 12154", lv);
    }
    EXPECT_QERR(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_REQUEST_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_NUMBER, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR(c.hr, HTTP_QUERY_STATUS_TEXT | HTTP_QUERY_FLAG_REQUEST_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERRW(c.hr, HTTP_QUERY_STATUS_TEXT | HTTP_QUERY_FLAG_REQUEST_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR(c.hr, HTTP_QUERY_REFRESH | HTTP_QUERY_FLAG_REQUEST_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR(c.hr, HTTP_QUERY_ECHO_REQUEST | HTTP_QUERY_FLAG_REQUEST_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    rh_close(&c);
}

/* STATUS_TEXT (mask 0): every mask modifier rejected; Refresh likewise */
TEST(hqi_args_status_text_takes_no_modifiers) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    for (size_t m = 0; m < 4; m++) {
        EXPECT_QERR(c.hr, HTTP_QUERY_STATUS_TEXT | mods4[m], ERROR_HTTP_INVALID_QUERY_REQUEST);
        EXPECT_QERR(c.hr, HTTP_QUERY_REFRESH | mods4[m], ERROR_HTTP_INVALID_QUERY_REQUEST);
        EXPECT_QERR(c.hr, HTTP_QUERY_VERSION | mods4[m], ERROR_HTTP_INVALID_QUERY_REQUEST);
        EXPECT_QERR(c.hr, HTTP_QUERY_RAW_HEADERS | mods4[m], ERROR_HTTP_INVALID_QUERY_REQUEST);
        EXPECT_QERR(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF | mods4[m], ERROR_HTTP_INVALID_QUERY_REQUEST);
    }
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, "OK");
    EXPECT_QA(c.hr, HTTP_QUERY_REFRESH, NULL);
    rh_close(&c);
}

/* CUSTOM bypasses the per-level masks: any single modifier is accepted [D] */
TEST(hqi_args_custom_bypasses_mask) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    DWORD n; ULONGLONG n64; SYSTEMTIME st;
    CHECK(rh_qnumc(c.hr, "X-Test", &n)); EXPECT_EQ(n, 42); EXPECT_EQ(rh_len, 4);
    CHECK(rh_qnum64c(c.hr, "X-Test", &n64)); CHECK(n64 == 42); EXPECT_EQ(rh_len, 8);
    CHECK(rh_qtimec(c.hr, "Date", &st)); EXPECT_EQ(st.wYear, 1994); EXPECT_EQ(st.wMonth, 11); EXPECT_EQ(st.wDay, 15);
    /* known header through CUSTOM keeps the custom rules: Content-Type|NUMBER via CUSTOM is not a mask error */
    CHECK(rh_qnumc(c.hr, "Content-Length", &n)); EXPECT_EQ(n, 5);
    const char *v = rh_qac(c.hr, "X-Multi", HTTP_QUERY_FLAG_COALESCE, NULL);   /* COALESCE = plain query for CUSTOM */
    EXPECT_STR(v, "a");
    v = rh_qac(c.hr, "Content-Type", HTTP_QUERY_FLAG_COALESCE, NULL);
    EXPECT_STR(v, "text/plain");
    rh_close(&c);
}

/* ------------------------------------------------------------------ index rules */
TEST(hqi_args_index_with_coalesce_comma) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    char b[256]; DWORD idx;
    idx = 1; strcpy(b, "X-Multi");
    CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_EQ(idx, 1);
    idx = 1;
    CHECK(!rh_callA(c.hr, HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    idx = 0xFFFFFFFF;
    CHECK(!rh_callA(c.hr, HTTP_QUERY_STATUS_TEXT | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    /* index 0 with comma: fine */
    idx = 0; strcpy(b, "X-Multi");
    CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, sizeof b, &idx)); EXPECT_STR(b, "a, b");
    rh_close(&c);
}

TEST(hqi_args_index_on_synthetic_levels) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    static const DWORD lv[] = { HTTP_QUERY_VERSION, HTTP_QUERY_STATUS_CODE, HTTP_QUERY_STATUS_TEXT, HTTP_QUERY_RAW_HEADERS, HTTP_QUERY_RAW_HEADERS_CRLF };
    for (size_t i = 0; i < 5; i++) {
        char b[1024]; DWORD idx = 0;
        CHECKF(rh_callA(c.hr, lv[i], b, sizeof b, &idx), "level %lu idx 0 err=%lu", lv[i], rh_err);
        EXPECT_EQ(idx, 0);   /* not advanced: these never go through _FindHeader [D] */
        idx = 1;
        CHECKF(!rh_callA(c.hr, lv[i], b, sizeof b, &idx) && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "level %lu idx 1: ok=%d err=%lu", lv[i], rh_ok, rh_err);
        EXPECT_EQ(idx, 1);
        idx = 7; WCHAR w[512];
        CHECKF(!rh_callW(c.hr, lv[i], w, sizeof w, &idx) && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "W level %lu idx 7: ok=%d err=%lu", lv[i], rh_ok, rh_err);
    }
    DWORD idx = 1, n = 0, l = sizeof n;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &n, &l, &idx)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    rh_close(&c);
}

/* ------------------------------------------------------------------ CUSTOM name validation */
TEST(hqi_args_custom_null_buffer) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    DWORD l = 100; SetLastError(0);
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    l = 0;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    l = 100;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_CUSTOM, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_CUSTOM, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    l = 0;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    rh_close(&c);
}

static const struct { const char *name; DWORD err; const char *val; } custom_names[] = {
    { "X-Test", 0, "42" },
    { "x-test", 0, "42" },
    { "X-TEST", 0, "42" },
    { "x-TeSt", 0, "42" },
    { "X-Test:", 0, "42" },              /* name ends at ':' */
    { "X-Test:junk after", 0, "42" },
    { "X-Test: 99", 0, "42" },           /* the space is after the terminator: not checked */
    { "X-Test\r\n", 0, "42" },
    { "X-Test\rzz", 0, "42" },
    { "X-Test\nzz", 0, "42" },
    { "X-Test ", ERROR_INVALID_PARAMETER, NULL },
    { " X-Test", ERROR_INVALID_PARAMETER, NULL },
    { "X Test", ERROR_INVALID_PARAMETER, NULL },
    { "X-\tTest", ERROR_INVALID_PARAMETER, NULL },
    { "X-Test\t", ERROR_INVALID_PARAMETER, NULL },
    { "\x01X-Test", ERROR_INVALID_PARAMETER, NULL },
    { "X-Te\x1fst", ERROR_INVALID_PARAMETER, NULL },
    { "X-Test\x7f", ERROR_INVALID_PARAMETER, NULL },
    { "X-Test\v", ERROR_INVALID_PARAMETER, NULL },
    { "X-Test\f", ERROR_INVALID_PARAMETER, NULL },
    { "", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { ":", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { ":X-Test", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { "X-Tes", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { "X-Test2", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { "X-Test;", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { "X_Test", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { "X-T\xe9st", ERROR_HTTP_HEADER_NOT_FOUND, NULL },  /* non-ASCII is not validated, just not found */
    { "\xe9", ERROR_HTTP_HEADER_NOT_FOUND, NULL },
    { "X-Multi", 0, "a" },
    { "content-type", 0, "text/plain" },    /* known header by name, any case */
    { "CONTENT-LENGTH", 0, "5" },
    { "Date:", 0, "Tue, 15 Nov 1994 12:45:26 GMT" },
    { "Content-Type ", ERROR_INVALID_PARAMETER, NULL },
};

TEST(hqi_args_custom_name_rules_a) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    for (size_t i = 0; i < sizeof custom_names / sizeof custom_names[0]; i++) {
        char b[256]; strcpy(b, custom_names[i].name);
        rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, sizeof b, NULL);
        const char *nm = rh_esc(custom_names[i].name, strlen(custom_names[i].name));
        if (custom_names[i].err) CHECKF(!rh_ok && rh_err == custom_names[i].err, "\"%s\": ok=%d err=%lu want %lu", nm, rh_ok, rh_err, custom_names[i].err);
        else CHECKF(rh_ok && !strcmp(b, custom_names[i].val) && rh_len == strlen(custom_names[i].val), "\"%s\": ok=%d err=%lu got \"%s\" want \"%s\"",
                    nm, rh_ok, rh_err, rh_ok ? b : "", custom_names[i].val);
    }
    rh_close(&c);
}

TEST(hqi_args_custom_name_rules_w) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    for (size_t i = 0; i < sizeof custom_names / sizeof custom_names[0]; i++) {
        if (strchr(custom_names[i].name, '\xe9') && !rh_acp1252()) continue;
        const char *g = rh_qwc(c.hr, custom_names[i].name, 0, NULL);
        const char *nm = rh_esc(custom_names[i].name, strlen(custom_names[i].name));
        if (custom_names[i].err) CHECKF(!g && rh_err == custom_names[i].err, "W \"%s\": err=%lu want %lu", nm, rh_err, custom_names[i].err);
        else CHECKF(g && !strcmp(g, custom_names[i].val) && rh_len == 2 * strlen(custom_names[i].val), "W \"%s\": err=%lu got \"%s\" len=%lu",
                    nm, rh_err, g ? g : "", rh_len);
    }
    rh_close(&c);
}

/* the name buffer is also the output buffer: a short buffer holding the name reports the size it needs */
TEST(hqi_args_custom_name_buffer_reuse) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    char b[16]; strcpy(b, "X-Test");
    DWORD l = 7;          /* holds "X-Test\0"; value "42" needs 3 */
    CHECK(U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_STR(b, "42"); EXPECT_EQ(l, 2);
    strcpy(b, "Content-Type"); l = 5;   /* buffer length smaller than the name: still read as a C string */
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 11);
    EXPECT_STR(b, "Content-Type");    /* untouched on 122 */
    strcpy(b, "X-Test"); l = 2;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 3);
    strcpy(b, "X-Test"); l = 3;
    CHECK(U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_STR(b, "42"); EXPECT_EQ(l, 2);
    strcpy(b, "X-Test"); l = 0;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 3);
    rh_close(&c);
}

/* ------------------------------------------------------------------ NULL buffer conventions */
TEST(hqi_args_null_buffer_a_is_size_query) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_BASIC(&c);
    DWORD l;
    /* A: a NULL buffer zeroes *len first, so any length gives 122 + the needed size (not 87) [D] */
    static const DWORD lens[] = { 0, 1, 100, 0xFFFFFFFF };
    for (size_t i = 0; i < 4; i++) {
        l = lens[i]; SetLastError(0);
        CHECKF(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL, &l, NULL), "len in %lu", lens[i]);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 11);
        l = lens[i];
        CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_TEXT, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 3);
        l = lens[i];
        CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
        l = lens[i];
        CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
        l = lens[i];
        CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_DATE | HTTP_QUERY_FLAG_SYSTEMTIME, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 16);
        /* absent header: 12150 and *len was zeroed */
        l = lens[i];
        CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_LOCATION, NULL, &l, NULL)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(l, 0);
    }
    rh_close(&c);
}

TEST(hqi_args_null_buffer_w) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    DWORD l;
    /* W: NULL buffer with *len != 0 -> 87; *len == 0 -> 122 with the byte size incl. the NUL [D] */
    l = 100; SetLastError(0);
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER); EXPECT_EQ(l, 100);
    l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 22);
    l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_STATUS_TEXT, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 6);
    l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_VERSION, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 18);
    l = 0;   /* binary results keep the A size */
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 4);
    l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_DATE | HTTP_QUERY_FLAG_SYSTEMTIME, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 16);
    l = 0;   /* absent: 12150, *len untouched (0) */
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_LOCATION, NULL, &l, NULL)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(l, 0);
    l = 4;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, NULL, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    rh_close(&c);
}

TEST(hqi_args_not_found_keeps_length) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    char b[100]; memset(b, 'Z', sizeof b);
    DWORD l = 77;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_LOCATION, b, &l, NULL)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_EQ(l, 77); EXPECT_EQ(b[0], 'Z');
    WCHAR w[50]; l = sizeof w; w[0] = 0x5A5A;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_LOCATION, w, &l, NULL)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_EQ(l, sizeof w); EXPECT_EQ(w[0], 0x5A5A);
    DWORD idx = 5; l = sizeof b;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_TYPE, b, &l, &idx)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_EQ(idx, 5); EXPECT_EQ(l, sizeof b);
    rh_close(&c);
}

/* success clears the thread's last error [D: SetLastError(dwErrCode) epilogue] */
TEST(hqi_args_success_sets_last_error_zero) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_BASIC(&c);
    char b[64]; DWORD l = sizeof b;
    SetLastError(0xBEEF);
    CHECK(U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_TEXT, b, &l, NULL)); EXPECT_EQ(GetLastError(), 0);
    WCHAR w[64]; l = sizeof w; SetLastError(0xBEEF);
    CHECK(U(HttpQueryInfoW)(c.hr, HTTP_QUERY_STATUS_TEXT, w, &l, NULL)); EXPECT_EQ(GetLastError(), 0);
    DWORD n; l = sizeof n; SetLastError(1234);
    CHECK(U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &n, &l, NULL)); EXPECT_EQ(GetLastError(), 0);
    strcpy(b, "X-Test"); l = sizeof b; SetLastError(5);
    CHECK(U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM, b, &l, NULL)); EXPECT_EQ(GetLastError(), 0);
    rh_close(&c);
}

/* ------------------------------------------------------------------ before HttpSendRequest */
TEST(hqi_args_before_send) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_BASIC, sizeof RESP_BASIC - 1)) return;
    /* request-side answers exist before sending [W10 laneg task 64] */
    EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    EXPECT_QA(c.hr, HTTP_QUERY_VERSION | HTTP_QUERY_FLAG_REQUEST_HEADERS, "HTTP/1.1");
    EXPECT_QW(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    /* response side before a response [W10]: the response-present flag is already set (no 12019, unlike the
     * decomp's naming suggests); STATUS_CODE falls back to "0" [D QueryInfo case 0x13], the raw block is the empty
     * status line + final CRLF, VERSION/STATUS_TEXT have no string yet -> 12150 */
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_CODE, "0");
    EXPECT_Q(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "\r\n\r\n");
    EXPECT_QERR2(c.hr, HTTP_QUERY_STATUS_TEXT, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_VERSION, ERROR_HTTP_HEADER_NOT_FOUND);
    DWORD n; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &n)); EXPECT_EQ(n, 0);
    const char *v = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS, NULL);
    t_note("before send RAW_HEADERS: %s err=%lu len=%lu", v ? rh_esc(v, rh_len + 1) : "(fail)", rh_err, rh_len);
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL);
    EXPECT_QC(c.hr, "X-Test", NULL);
    /* after sending, the same handle answers from the response */
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_TYPE, "text/plain");
    EXPECT_QC(c.hr, "X-Test", "42");
    rh_close(&c);
}
