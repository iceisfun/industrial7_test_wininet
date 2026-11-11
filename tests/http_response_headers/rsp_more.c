/* rsp_more.c - third pass (adversarial review): 1xx edge cases from ReceiveResponse_Fsm, junk before the status
 * line, whitespace-only lines, and the order of the HttpQueryInfoA/W argument checks relative to the *len / index
 * side effects (NULL buffer zeroing, the state check, W name conversion through CP_ACP).
 * VM_TIMEOUT: 180
 *
 * [D] HTTP_REQUEST_HANDLE_OBJECT::ReceiveResponse_Fsm@0x67708: after a status line is parsed, code 101 (0x65) goes
 *     to the WebSocket / HTTP2-upgrade handlers only when the request asked for one, else it is the final response;
 *     codes outside 100..199 (`99 < code - 100U`) are final; any other 1xx resets the header store
 *     (CHttpHeaders::Initialize) and the loop reads the next status line. The loop has no interim count limit.
 * [D] HttpQueryInfoA@0x54ae0: handle, then level/len/pair checks (87), then the index rules, then CUSTOM name
 *     validation or the level mask (12154); only after these is `*len = 0` done for a NULL buffer, and only after
 *     that the response-state gate (flag 0x200 -> 12019). So an early error leaves *len and *index untouched, while
 *     a 12019 from the state gate has already zeroed *len.
 * [D] HttpQueryInfoW@0x54330: CUSTOM names are converted with WideCharToMultiByte(CP_ACP, 0, ...) (default char,
 *     so an unmappable WCHAR becomes '?'); CUSTOM|NUMBER/NUMBER64/SYSTEMTIME (mask 0x68000000) results are copied
 *     raw and *len is what A reported.
 */
#include "rh.h"

#define TAIL "Content-Length: 0\r\nConnection: close\r\n\r\n"

static int go(rh_t *c, const char *raw, size_t n) {
    if (!rh_raw(c, "GET", raw, n)) return 0;
    if (!c->sent) { t_check(0, __FILE__, __LINE__, "HttpSendRequest", "err=%lu %s", c->err, t_inet_errname(c->err)); rh_close(c); return 0; }
    return 1;
}
#define GO(c, lit) do { if (!go((c), (lit), sizeof(lit) - 1)) return; } while (0)

/* ------------------------------------------------------------------ 1xx */
/* 101 without a WebSocket/HTTP2 upgrade request is the final response [D 0x65 branch] */
TEST(rsp_more_101_without_upgrade_is_final) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c;
    GO(&c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x-test\r\nConnection: Upgrade\r\nX-N: 101\r\n\r\n"
           "HTTP/1.1 200 OK\r\nX-N: 200\r\n" TAIL);
    DWORD n = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &n)); EXPECT_EQ(n, 101);
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_TEXT, "Switching Protocols");
    EXPECT_Q(c.hr, HTTP_QUERY_UPGRADE, "x-test");
    EXPECT_Q(c.hr, HTTP_QUERY_CONNECTION, "Upgrade");
    EXPECT_QC(c.hr, "X-N", "101");
    DWORD idx = 1; CHECK(!rh_qac(c.hr, "X-N", 0, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(idx, 1);
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x-test\r\nConnection: Upgrade\r\nX-N: 101\r\n\r\n");
    rh_close(&c);
}

/* an interim response followed by EOF: there is no final response */
TEST(rsp_more_interim_then_eof) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!RH_RAW(&c, "GET", "HTTP/1.1 100 Continue\r\nX-I: 1\r\n\r\n")) return;
    t_note("100 then EOF: sent=%d err=%lu %s", c.sent, c.err, t_inet_errname(c.err));
    CHECK(!c.sent);
    EXPECT_EQ(c.err, ERROR_HTTP_INVALID_SERVER_RESPONSE);
    rh_close(&c);
}

/* code range check is on the number: 099 is final [D: 99 < code - 100U] */
TEST(rsp_more_status_below_100_is_final) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *lines[] = { "HTTP/1.1 099 Low", "HTTP/1.1 99 Low", "HTTP/1.1 001 Low" };
    static const DWORD nums[] = { 99, 99, 1 };
    for (int i = 0; i < 3; i++) {
        char resp[256]; int k = snprintf(resp, sizeof resp, "%s\r\nX-K: k%d\r\n" TAIL, lines[i], i);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)k)) return;
        CHECKF(c.sent, "\"%s\": err=%lu", lines[i], c.err);
        if (c.sent) {
            DWORD n = 0; CHECKF(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &n) && n == nums[i], "\"%s\": num=%lu err=%lu", lines[i], n, rh_err);
            EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, "Low");
            char want[8]; snprintf(want, sizeof want, "k%d", i);
            EXPECT_QC(c.hr, "X-K", want);
        }
        rh_close(&c);
    }
}

/* "0100": the token parses to 100, so it is an interim response like "100" [D numeric check, W10 0200 -> 200] */
TEST(rsp_more_zero_padded_100_is_interim) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 0100 Padded\r\nX-I: interim\r\n\r\nHTTP/1.1 200 OK\r\nX-F: final\r\n" TAIL);
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "200");
    EXPECT_QC(c.hr, "X-F", "final");
    EXPECT_QC(c.hr, "X-I", NULL);
    rh_close(&c);
}

/* many interim responses in a row are all consumed [D: no interim count in the loop] */
TEST(rsp_more_many_interim_responses) {
    REQUIRE(U(HttpQueryInfoA));
    static char resp[8192]; size_t k = 0;
    for (int i = 0; i < 40; i++) k += (size_t)snprintf(resp + k, sizeof resp - k, "HTTP/1.1 %d Interim\r\nX-I: %d\r\n\r\n", (i % 3 == 0) ? 100 : (i % 3 == 1) ? 102 : 199, i);
    k += (size_t)snprintf(resp + k, sizeof resp - k, "HTTP/1.1 202 Accepted\r\nX-F: f\r\n" TAIL);
    rh_t c; if (!go(&c, resp, k)) return;
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "202");
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, "Accepted");
    EXPECT_QC(c.hr, "X-I", NULL);
    EXPECT_QC(c.hr, "X-F", "f");
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 202 Accepted\r\nX-F: f\r\n" TAIL);
    rh_close(&c);
}

/* a 101 after a 100: the 100 is consumed, the 101 ends the loop [D] */
TEST(rsp_more_101_after_100_is_final) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 100 Continue\r\nX-A: 100\r\n\r\nHTTP/1.1 101 Switching\r\nX-A: 101\r\n\r\nHTTP/1.1 200 OK\r\nX-A: 200\r\n" TAIL);
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "101");
    EXPECT_QC(c.hr, "X-A", "101");
    rh_close(&c);
}

/* ------------------------------------------------------------------ junk and blank-ish lines */
/* a UTF-8 BOM (3 bytes) before "HTTP": within the 4 junk bytes that are skipped [W10 rsp_status_leading_junk] */
TEST(rsp_more_bom_before_status_line) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "\xEF\xBB\xBFHTTP/1.1 203 Bom\r\nX-K: k\r\n" TAIL);
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "203");
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, "Bom");
    EXPECT_QC(c.hr, "X-K", "k");
    EXPECT_QA(c.hr, HTTP_QUERY_VERSION, "HTTP/1.1");
    rh_close(&c);
}

/* [W10] a line of spaces/tab between headers ends the stored head: later headers (X-B, X-C and the TAIL ones) are not visible */
TEST(rsp_more_whitespace_only_line) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-A: 1\r\n   \r\nX-B: 2\r\n\t\r\nX-C: 3\r\n" TAIL);
    EXPECT_QC(c.hr, "X-A", "1");
    const char *b = rh_qac(c.hr, "X-B", 0, NULL);
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    t_note("whitespace-only line: X-B=%s raw=%s", b ? b : "(absent)", raw ? rh_esc(raw, strlen(raw)) : "(fail)");
    CHECKF(!b, "X-B visible after whitespace-only line");
    CHECKF(!rh_qac(c.hr, "X-C", 0, NULL), "X-C visible after whitespace-only line");
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\n");
    rh_close(&c);
}

/* ------------------------------------------------------------------ argument-check order vs side effects */
static const char RESP_M[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-M: a\r\nX-M: b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/* the early errors return before *len is zeroed for a NULL buffer [D] */
TEST(hqi_more_null_buffer_len_kept_on_early_errors) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_M)) return; RH_SENT_OR_FAIL(&c);
    static const struct { DWORD level; DWORD idx; DWORD err; } t[] = {
        { 0x60, 0, ERROR_INVALID_PARAMETER },
        { HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_NUMBER64, 0, ERROR_INVALID_PARAMETER },
        { HTTP_QUERY_DATE | HTTP_QUERY_FLAG_SYSTEMTIME | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, 0, ERROR_INVALID_PARAMETER },
        { HTTP_QUERY_STATUS_TEXT | HTTP_QUERY_FLAG_NUMBER, 0, ERROR_HTTP_INVALID_QUERY_REQUEST },
        { HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_COALESCE, 0, ERROR_HTTP_INVALID_QUERY_REQUEST },
        { HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_NUMBER, 2, ERROR_HTTP_INVALID_QUERY_REQUEST },
        { HTTP_QUERY_VERSION, 1, ERROR_HTTP_HEADER_NOT_FOUND },
        { HTTP_QUERY_RAW_HEADERS_CRLF, 3, ERROR_HTTP_HEADER_NOT_FOUND },
        { HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, 1, ERROR_HTTP_HEADER_NOT_FOUND },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        DWORD len = 77, idx = t[i].idx; SetLastError(0);
        BOOL ok = U(HttpQueryInfoA)(c.hr, t[i].level, NULL, &len, &idx);
        DWORD e = GetLastError();
        CHECKF(!ok && e == t[i].err && len == 77 && idx == t[i].idx, "level 0x%lx idx %lu: ok=%d err=%lu (want %lu) len=%lu idx=%lu",
               t[i].level, t[i].idx, ok, e, t[i].err, len, idx);
    }
    /* contrast: once the checks pass, the NULL buffer zeroes *len: a present header reports its size, an absent one 0 */
    DWORD len = 77; SetLastError(0);
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL, &len, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 11);
    len = 77;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_EXPIRES, NULL, &len, NULL)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(len, 0);
    DWORD idx = 5; len = 77;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL, &len, &idx)); EXPECT_ERR(ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(len, 0); EXPECT_EQ(idx, 5);
    rh_close(&c);
}

/* the index is never written by an argument error, a CUSTOM name error or a mask error [D] */
TEST(hqi_more_index_untouched_on_errors) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_M)) return; RH_SENT_OR_FAIL(&c);
    char b[64]; DWORD idx;
    idx = 1; CHECK(!rh_callA(c.hr, 0x61, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_INVALID_PARAMETER); EXPECT_EQ(idx, 1);
    idx = 1; strcpy(b, "X M"); CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_INVALID_PARAMETER); EXPECT_EQ(idx, 1);
    idx = 1; CHECK(!rh_callA(c.hr, HTTP_QUERY_CONTENT_TYPE | HTTP_QUERY_FLAG_SYSTEMTIME, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST); EXPECT_EQ(idx, 1);
    idx = 1; CHECK(!rh_callA(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_SYSTEMTIME, b, sizeof b, &idx));
    EXPECT_EQ(rh_err, ERROR_INVALID_PARAMETER); EXPECT_EQ(idx, 1);
    /* the same index then works for a legal query and advances */
    idx = 1; strcpy(b, "X-M"); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, sizeof b, &idx)); EXPECT_STR(b, "b"); EXPECT_EQ(idx, 2);
    WCHAR w[32]; idx = 1; lstrcpyW(w, L"X M");
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, sizeof w, &idx)); EXPECT_EQ(rh_err, ERROR_INVALID_PARAMETER); EXPECT_EQ(idx, 1);
    rh_close(&c);
}

/* the state gate comes after the NULL-buffer zeroing: during HttpSendRequestEx a NULL-buffer query gives 12019 with
 * *len = 0, while a query with a buffer leaves *len alone [D HttpQueryInfoA, W10 12019 from rsp_life_send_request_ex_end_request] */
TEST(hqi_more_state_error_after_len_zeroing) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile)); REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, "X-Ex: done\r\n", "ok"), S_CLOSE() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "POST", "/ex", 0)) { rh_close(&c); return; }
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 3;
    CHECK(U(HttpSendRequestExA)(c.hr, &ib, NULL, 0, 0));
    DWORD len = 55; SetLastError(0);
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_CODE, NULL, &len, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_STATE); EXPECT_EQ(len, 0);
    len = 55;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL, &len, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_STATE); EXPECT_EQ(len, 0);
    char b[64]; len = sizeof b; memset(b, 0x5A, sizeof b);
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_CODE, b, &len, NULL)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_STATE);
    EXPECT_EQ(len, sizeof b); EXPECT_EQ((BYTE)b[0], 0x5A);
    /* the argument checks still come first: an illegal pair is 87 with *len untouched */
    len = 55;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_FLAG_NUMBER64, NULL, &len, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER); EXPECT_EQ(len, 55);
    len = 55;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_STATUS_TEXT | HTTP_QUERY_FLAG_NUMBER, NULL, &len, NULL));
    EXPECT_ERR(ERROR_HTTP_INVALID_QUERY_REQUEST); EXPECT_EQ(len, 55);
    /* request side during the upload goes through a different state check: only recorded */
    len = sizeof b; SetLastError(0);
    BOOL ok = U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_REQUEST_HEADERS, b, &len, NULL);
    t_note("REQ Content-Length during HttpSendRequestEx: ok=%d err=%lu value=%s", ok, ok ? 0 : GetLastError(), ok ? rh_esc(b, len) : "-");
    DWORD w = 0; CHECK(U(InternetWriteFile)(c.hr, "abc", 3, &w));
    CHECK(U(HttpEndRequestA)(c.hr, NULL, 0, 0));
    EXPECT_QC(c.hr, "X-Ex", "done");
    char body[8] = { 0 }; t_inet_read_all(c.hr, body, sizeof body, NULL); EXPECT_STR(body, "ok");
    rh_close(&c);
}

/* ------------------------------------------------------------------ W specifics */
/* W converts the CUSTOM name with CP_ACP and the default char: an unmappable WCHAR becomes '?' [D] */
TEST(hqi_more_w_custom_name_unmappable_char) {
    REQUIRE(U(HttpQueryInfoW));
    if (!rh_acp1252()) { t_skip("ACP is not 1252"); return; }
    rh_t c; GO(&c, "HTTP/1.1 200 OK\r\nX-?: q\r\nX-??: qq\r\n" TAIL);
    WCHAR w[64];
    lstrcpyW(w, L"X-\x4E00");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, sizeof w, NULL)); CHECK(!lstrcmpW(w, L"q")); EXPECT_EQ(rh_len, 2);
    lstrcpyW(w, L"x-\x4E00\x4E01");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, sizeof w, NULL)); CHECK(!lstrcmpW(w, L"qq")); EXPECT_EQ(rh_len, 4);
    lstrcpyW(w, L"X-\x4E00\x4E00\x4E00");
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, sizeof w, NULL)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QC(c.hr, "X-?", "q");
    rh_close(&c);
}

/* W CUSTOM|NUMBER / SYSTEMTIME: raw result, *len = A's size, also on 122 [D raw path, mask 0x68000000] */
TEST(hqi_more_w_custom_binary_short_buffer) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; GO(&c, "HTTP/1.1 200 OK\r\nX-N: 4321\r\nX-Long-Number-Header-Name: 77\r\nX-D: Sun, 06 Nov 1994 08:49:37 GMT\r\n" TAIL);
    BYTE b[128]; WCHAR *w = (WCHAR *)b;
    static const DWORD nsz[] = { 0, 1, 2, 3 };
    for (size_t i = 0; i < 4; i++) {
        memset(b, 0, sizeof b); lstrcpyW(w, L"X-N");
        CHECKF(!rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, b, nsz[i], NULL) && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 4,
               "W CUSTOM|NUMBER size %lu: ok=%d err=%lu len=%lu", nsz[i], rh_ok, rh_err, rh_len);
    }
    memset(b, 0, sizeof b); lstrcpyW(w, L"X-D");
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_SYSTEMTIME, b, 15, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 16);
    memset(b, 0, sizeof b); lstrcpyW(w, L"X-D");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_SYSTEMTIME, b, 16, NULL)); EXPECT_EQ(rh_len, 16);
    EXPECT_EQ(((SYSTEMTIME *)b)->wYear, 1994); EXPECT_EQ(((SYSTEMTIME *)b)->wSecond, 37);
    /* *len smaller than the wide name: the name is still read as a C string and the 4-byte result fits */
    memset(b, 0, sizeof b); lstrcpyW(w, L"X-Long-Number-Header-Name");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, b, 4, NULL)); EXPECT_EQ(rh_len, 4); EXPECT_EQ(*(DWORD *)b, 77);
    rh_close(&c);
}

/* W string sizes with an odd byte count: 2(n+1) needed, an odd extra byte is ignored [D] */
TEST(hqi_more_w_odd_buffer_lengths) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_M)) return; RH_SENT_OR_FAIL(&c);
    /* "text/plain": n = 10, needs 22 bytes */
    static const DWORD sz[] = { 21, 22, 23, 32, 33, 34, 35 };
    for (size_t i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        WCHAR w[64]; memset(w, 0xEE, sizeof w);
        rh_callW(c.hr, HTTP_QUERY_CONTENT_TYPE, w, sz[i], NULL);
        if (sz[i] < 22) CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 22, "size %lu: ok=%d err=%lu len=%lu", sz[i], rh_ok, rh_err, rh_len);
        else CHECKF(rh_ok && rh_len == 20 && !lstrcmpW(w, L"text/plain"), "size %lu: ok=%d err=%lu len=%lu", sz[i], rh_ok, rh_err, rh_len);
    }
    /* CUSTOM path: the same sizes */
    for (size_t i = 0; i < sizeof sz / sizeof sz[0]; i++) {
        WCHAR w[64]; memset(w, 0xEE, sizeof w); lstrcpyW(w, L"Content-Type");
        rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, sz[i], NULL);
        if (sz[i] < 22) CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 22, "CUSTOM size %lu: ok=%d err=%lu len=%lu", sz[i], rh_ok, rh_err, rh_len);
        else CHECKF(rh_ok && rh_len == 20 && !lstrcmpW(w, L"text/plain"), "CUSTOM size %lu: ok=%d err=%lu len=%lu", sz[i], rh_ok, rh_err, rh_len);
    }
    rh_close(&c);
}

/* W with *len = 0 and a non-NULL buffer is a size query: 122 with 2(n+1); an absent header gives 12150 [D] */
TEST(hqi_more_w_zero_length_nonnull_buffer) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_M)) return; RH_SENT_OR_FAIL(&c);
    WCHAR w[32]; DWORD idx;
    w[0] = 0x1234; idx = 0;
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CONTENT_TYPE, w, 0, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 22);
    EXPECT_EQ(w[0], 0x1234); EXPECT_EQ(idx, 0);
    CHECK(!rh_callW(c.hr, HTTP_QUERY_EXPIRES, w, 0, NULL)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    lstrcpyW(w, L"X-M"); idx = 1;
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 0, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 4); EXPECT_EQ(idx, 1);
    rh_close(&c);
}

/* ------------------------------------------------------------------ status line + headers */
/* a status line ending in LF only, headers in CRLF (and the reverse) */
TEST(rsp_more_status_line_terminators) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *raws[] = {
        "HTTP/1.1 200 Lf\nX-A: 1\r\n" TAIL,
        "HTTP/1.1 200 Lf\r\nX-A: 1\n" "Content-Length: 0\nConnection: close\n\n",
        "HTTP/1.1 200 Lf\nX-A: 1\nContent-Length: 0\r\nConnection: close\r\n\n",
    };
    for (int i = 0; i < 3; i++) {
        rh_t c; if (!go(&c, raws[i], strlen(raws[i]))) return;
        EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, "Lf");
        EXPECT_QC(c.hr, "X-A", "1");
        EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 Lf\r\nX-A: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        rh_close(&c);
    }
}

/* the same header name in several casings: one header family for lookup, each casing kept in RAW */
TEST(rsp_more_case_variants_one_family) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nx-fam: 1\r\nX-FAM: 2\r\nX-Fam: 3\r\ncache-control: a\r\nCACHE-CONTROL: b\r\n" TAIL);
    const char *v = rh_qac(c.hr, "X-fAm", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); EXPECT_STR(v, "1, 2, 3");
    v = rh_qa(c.hr, HTTP_QUERY_CACHE_CONTROL | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); EXPECT_STR(v, "a, b");
    v = rh_qw(c.hr, HTTP_QUERY_CACHE_CONTROL | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); EXPECT_STR(v, "a, b"); EXPECT_EQ(rh_len, 8);
    DWORD idx = 2; v = rh_qac(c.hr, "x-FAM", 0, &idx); EXPECT_STR(v, "3"); EXPECT_EQ(idx, 3);
    idx = 1; v = rh_qa(c.hr, HTTP_QUERY_CACHE_CONTROL, &idx); EXPECT_STR(v, "b"); EXPECT_EQ(idx, 2);
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nx-fam: 1\r\nX-FAM: 2\r\nX-Fam: 3\r\ncache-control: a\r\nCACHE-CONTROL: b\r\n" TAIL);
    rh_close(&c);
}
