/* hqi_buffer.c - HttpQueryInfoA/W buffer protocol: sizes, NUL termination, 122 + required size, A vs W units.
 * VM_TIMEOUT: 240
 *
 * [D] CHttpHeaders::_FindHeader / _CopyValueToBuffer (string): buffer >= len+1 -> copy len bytes + NUL, *len = len,
 * index++; else 122 and *len = len+1, buffer and index untouched. NUMBER: 4 bytes, SYSTEMTIME: 16, NUMBER64: 8
 * (*len = size on 122 too). HttpQueryInfoW: non-binary results are produced by A in the caller's buffer and then
 * widened in place; W needs 2*(len+1) bytes, reports 2*(len+1) on 122 and 2*len on success. Because A runs first,
 * a W buffer of at least len+1 but less than 2*(len+1) bytes fails with 122 AFTER A has advanced the index.
 */
#include "rh.h"

/* known levels used as carriers for values of chosen lengths */
static const struct { DWORD level; const char *name; int n; } carriers[] = {
    { HTTP_QUERY_MIME_VERSION, "Mime-Version", 0 },
    { HTTP_QUERY_ALLOW, "Allow", 1 },
    { HTTP_QUERY_PUBLIC, "Public", 2 },
    { HTTP_QUERY_SERVER, "Server", 7 },
    { HTTP_QUERY_VIA, "Via", 31 },
    { HTTP_QUERY_WARNING, "Warning", 200 },
    { HTTP_QUERY_CONTENT_DISPOSITION, "Content-Disposition", 1000 },
    { HTTP_QUERY_ETAG, "Etag", 4095 },
};
#define NCARR (sizeof carriers / sizeof carriers[0])

static char g_resp[32768];
static char g_vals[NCARR][4100];

static void val_for(int k, char *out) {
    int n = carriers[k].n;
    for (int i = 0; i < n; i++) out[i] = (char)('A' + (i * 7 + k) % 26 + ((i % 3) == 1 ? 32 : 0));
    out[n] = 0;
}
static size_t build_resp(void) {
    size_t o = 0;
    o += (size_t)snprintf(g_resp + o, sizeof g_resp - o, "HTTP/1.1 200 OK\r\n");
    for (size_t k = 0; k < NCARR; k++) {
        val_for((int)k, g_vals[k]);
        o += (size_t)snprintf(g_resp + o, sizeof g_resp - o, "%s:%s%s\r\n", carriers[k].name, carriers[k].n ? " " : "", g_vals[k]);
    }
    o += (size_t)snprintf(g_resp + o, sizeof g_resp - o, "Content-Length: 0\r\nConnection: close\r\n\r\n");
    return o;
}
static int open_carriers(rh_t *c) {
    size_t n = build_resp();
    if (!rh_raw(c, "GET", g_resp, n)) return 0;
    if (!c->sent) { t_check(0, __FILE__, __LINE__, "send", "err=%lu", c->err); rh_close(c); return 0; }
    return 1;
}

TEST(hqi_buf_a_string_size_table) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!open_carriers(&c)) return;
    static char buf[8300];
    for (size_t k = 0; k < NCARR; k++) {
        int n = carriers[k].n;
        int sizes[] = { 0, 1, n - 1, n, n + 1, n + 2, n + 100 };
        for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            int sz = sizes[s]; if (sz < 0) continue;
            memset(buf, 'Z', (size_t)sz + 16);
            DWORD idx = 0;
            rh_callA(c.hr, carriers[k].level, buf, (DWORD)sz, &idx);
            if (sz >= n + 1) {
                CHECKF(rh_ok && rh_len == (DWORD)n, "%s n=%d size=%d: ok=%d err=%lu len=%lu", carriers[k].name, n, sz, rh_ok, rh_err, rh_len);
                CHECKF(!memcmp(buf, g_vals[k], (size_t)n) && buf[n] == 0, "%s n=%d size=%d: content/NUL", carriers[k].name, n, sz);
                CHECKF(buf[n + 1] == 'Z' && buf[n + 15] == 'Z', "%s size=%d: wrote past the NUL", carriers[k].name, sz);
                EXPECT_EQ(idx, 1);
            } else {
                CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == (DWORD)(n + 1), "%s n=%d size=%d: ok=%d err=%lu len=%lu",
                       carriers[k].name, n, sz, rh_ok, rh_err, rh_len);
                CHECKF(buf[0] == 'Z' && buf[sz > 0 ? sz - 1 : 0] == 'Z', "%s size=%d: buffer touched on 122", carriers[k].name, sz);
                EXPECT_EQ(idx, 0);
            }
        }
    }
    rh_close(&c);
}

TEST(hqi_buf_w_string_size_table) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!open_carriers(&c)) return;
    static WCHAR buf[8300];
    for (size_t k = 0; k < NCARR; k++) {
        int n = carriers[k].n;
        int sizes[] = { 0, 1, 2, n, n + 1, 2 * n, 2 * n + 1, 2 * n + 2, 2 * n + 3, 2 * n + 4, 3 * n + 3, 3 * n + 4, 4 * n + 10 };
        for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            int sz = sizes[s];
            for (int i = 0; i < 8300; i++) buf[i] = 0x5A5A;
            rh_callW(c.hr, carriers[k].level, buf, (DWORD)sz, NULL);
            if (sz >= 2 * n + 2) {
                CHECKF(rh_ok && rh_len == (DWORD)(2 * n), "W %s n=%d size=%d: ok=%d err=%lu len=%lu", carriers[k].name, n, sz, rh_ok, rh_err, rh_len);
                int good = buf[n] == 0;
                for (int i = 0; i < n && good; i++) good = buf[i] == (WCHAR)(unsigned char)g_vals[k][i];
                CHECKF(good, "W %s n=%d size=%d: content", carriers[k].name, n, sz);
            } else {
                CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == (DWORD)(2 * n + 2), "W %s n=%d size=%d: ok=%d err=%lu len=%lu",
                       carriers[k].name, n, sz, rh_ok, rh_err, rh_len);
            }
        }
    }
    rh_close(&c);
}

/* A succeeds inside W's buffer (len+1 <= bytes < 2*(len+1)): W reports 122 but the index already moved [D HttpQueryInfoW] */
TEST(hqi_buf_w_partial_buffer_advances_index) {
    REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nVia: abcdef\r\nVia: ghijkl\r\nVia: mn\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    WCHAR w[64]; DWORD idx = 0;
    /* 6 bytes < 7 (A need): A fails, index stays */
    CHECK(!rh_callW(c.hr, HTTP_QUERY_VIA, w, 6, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 14); EXPECT_EQ(idx, 0);
    /* 8 bytes: A fits ("abcdef\0"), W needs 14 */
    CHECK(!rh_callW(c.hr, HTTP_QUERY_VIA, w, 8, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 14);
    EXPECT_EQ(idx, 1);
    /* the next full query therefore returns the second Via */
    CHECK(rh_callW(c.hr, HTTP_QUERY_VIA, w, sizeof w, &idx)); CHECK(!lstrcmpW(w, L"ghijkl")); EXPECT_EQ(idx, 2);
    /* 13 bytes (odd, just below 14) for "mn": A need 3, W need 6 */
    CHECK(rh_callW(c.hr, HTTP_QUERY_VIA, w, 13, &idx)); CHECK(!lstrcmpW(w, L"mn")); EXPECT_EQ(rh_len, 4); EXPECT_EQ(idx, 3);
    CHECK(!rh_callW(c.hr, HTTP_QUERY_VIA, w, sizeof w, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(idx, 3);
    /* A with the same sizes never advances on 122 */
    char a[64]; idx = 0;
    CHECK(!rh_callA(c.hr, HTTP_QUERY_VIA, a, 6, &idx)); EXPECT_EQ(rh_len, 7); EXPECT_EQ(idx, 0);
    CHECK(rh_callA(c.hr, HTTP_QUERY_VIA, a, 7, &idx)); EXPECT_STR(a, "abcdef"); EXPECT_EQ(idx, 1);
    rh_close(&c);
}

TEST(hqi_buf_w_custom_partial_buffer) {
    REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-M: a\r\nX-M: b\r\nX-Long: 0123456789\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    WCHAR w[64]; DWORD idx = 0;
    lstrcpyW(w, L"X-M");
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 2, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 4);
    EXPECT_EQ(idx, 1);   /* A had room for "a\0" */
    lstrcpyW(w, L"X-M");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 4, &idx)); CHECK(!lstrcmpW(w, L"b")); EXPECT_EQ(rh_len, 2); EXPECT_EQ(idx, 2);
    /* name longer than the buffer the caller declares: the name is still read in full */
    lstrcpyW(w, L"X-Long"); idx = 0;
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 4, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 22); EXPECT_EQ(idx, 0);
    lstrcpyW(w, L"X-Long");
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 0, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 22);
    lstrcpyW(w, L"X-Long");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 22, &idx)); CHECK(!lstrcmpW(w, L"0123456789")); EXPECT_EQ(rh_len, 20);
    rh_close(&c);
}

/* ------------------------------------------------------------------ binary results */
TEST(hqi_buf_number_sizes) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 203 Fine\r\nContent-Length: 4\r\nX-N: 1234567\r\nConnection: close\r\n\r\nbody";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    static const DWORD sizes[] = { 0, 1, 2, 3, 4, 5, 8, 100 };
    static const DWORD lv[] = { HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER };
    static const DWORD want[] = { 4, 203 };
    for (int w = 0; w < 2; w++)
        for (size_t l = 0; l < 2; l++)
            for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
                BYTE b[128]; memset(b, 0xEE, sizeof b);
                if (w) rh_callW(c.hr, lv[l], b, sizes[s], NULL); else rh_callA(c.hr, lv[l], b, sizes[s], NULL);
                if (sizes[s] >= 4) {
                    CHECKF(rh_ok && rh_len == 4 && *(DWORD *)b == want[l] && b[4] == 0xEE, "%c level 0x%lx size %lu: ok=%d err=%lu len=%lu v=%lu",
                           w ? 'W' : 'A', lv[l], sizes[s], rh_ok, rh_err, rh_len, *(DWORD *)b);
                } else {
                    CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 4 && b[0] == 0xEE, "%c level 0x%lx size %lu: ok=%d err=%lu len=%lu",
                           w ? 'W' : 'A', lv[l], sizes[s], rh_ok, rh_err, rh_len);
                }
            }
    /* custom NUMBER: same 4-byte protocol, name in the buffer */
    char b[64]; strcpy(b, "X-N");
    CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, b, 3, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 4);
    strcpy(b, "X-N");
    CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, b, 4, NULL)); EXPECT_EQ(*(DWORD *)b, 1234567); EXPECT_EQ(rh_len, 4);
    WCHAR wb[32]; lstrcpyW(wb, L"X-N");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, wb, sizeof wb, NULL)); EXPECT_EQ(*(DWORD *)wb, 1234567); EXPECT_EQ(rh_len, 4);
    rh_close(&c);
}

TEST(hqi_buf_systemtime_sizes) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nLast-Modified: Sun, 06 Nov 1994 08:49:37 GMT\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    static const DWORD sizes[] = { 0, 1, 8, 15, 16, 17, 32 };
    for (int w = 0; w < 2; w++)
        for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            BYTE b[64]; memset(b, 0xEE, sizeof b);
            DWORD lv = HTTP_QUERY_LAST_MODIFIED | HTTP_QUERY_FLAG_SYSTEMTIME;
            if (w) rh_callW(c.hr, lv, b, sizes[s], NULL); else rh_callA(c.hr, lv, b, sizes[s], NULL);
            SYSTEMTIME *st = (SYSTEMTIME *)b;
            if (sizes[s] >= 16)
                CHECKF(rh_ok && rh_len == 16 && st->wYear == 1994 && st->wMonth == 11 && st->wDay == 6 && st->wDayOfWeek == 0 && st->wHour == 8 &&
                       st->wMinute == 49 && st->wSecond == 37 && st->wMilliseconds == 0 && b[16] == 0xEE,
                       "%c size %lu: ok=%d err=%lu len=%lu", w ? 'W' : 'A', sizes[s], rh_ok, rh_err, rh_len);
            else
                CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 16 && b[0] == 0xEE, "%c size %lu: ok=%d err=%lu len=%lu",
                       w ? 'W' : 'A', sizes[s], rh_ok, rh_err, rh_len);
        }
    rh_close(&c);
}

TEST(hqi_buf_number64_sizes) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 5000000000\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "HEAD", resp)) return; RH_SENT_OR_FAIL(&c);
    static const DWORD sizes[] = { 0, 4, 7, 8, 9, 16 };
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
        BYTE b[32]; memset(b, 0xEE, sizeof b);
        rh_callA(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER64, b, sizes[s], NULL);
        if (sizes[s] >= 8) CHECKF(rh_ok && rh_len == 8 && *(ULONGLONG *)b == 5000000000ull && b[8] == 0xEE, "size %lu ok=%d err=%lu len=%lu", sizes[s], rh_ok, rh_err, rh_len);
        else CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 8 && b[0] == 0xEE, "size %lu ok=%d err=%lu len=%lu", sizes[s], rh_ok, rh_err, rh_len);
    }
    /* the 32-bit form overflows: _FormatAsDword -> 12153 ERROR_HTTP_INVALID_HEADER [D] */
    DWORD n;
    CHECK(!rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_HEADER);
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_LENGTH, "5000000000");
    rh_close(&c);
}

/* W + NUMBER64 on a known level is not in W's raw-copy mask (0x60000000): the 8 bytes are widened as text [D] */
TEST(hqi_buf_w_number64_known_level_widened) {
    REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 258\r\nX-N: 258\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "HEAD", resp)) return; RH_SENT_OR_FAIL(&c);
    WCHAR w[32]; memset(w, 0xEE, sizeof w);
    /* 8 bytes: A fits, widening needs 9 WCHARs */
    rh_callW(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER64, w, 8, NULL);
    CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 18, "8 bytes: ok=%d err=%lu len=%lu", rh_ok, rh_err, rh_len);
    memset(w, 0xEE, sizeof w);
    rh_callW(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER64, w, sizeof w, NULL);
    /* 258 = 02 01 00 00 00 00 00 00 -> L"\x02\x01" + six L'\0', length 16 bytes */
    CHECKF(rh_ok && rh_len == 16 && w[0] == 2 && w[1] == 1 && w[2] == 0 && w[7] == 0 && w[8] == 0, "full: ok=%d err=%lu len=%lu w0=%x w1=%x", rh_ok, rh_err, rh_len, w[0], w[1]);
    /* CUSTOM|NUMBER64 is raw-copied by W (mask 0x68000000 on that path) */
    lstrcpyW(w, L"X-N");
    rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER64, w, sizeof w, NULL);
    CHECKF(rh_ok && rh_len == 8 && *(ULONGLONG *)w == 258, "custom: ok=%d err=%lu len=%lu", rh_ok, rh_err, rh_len);
    lstrcpyW(w, L"X-N");
    rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER64, w, 8, NULL);
    CHECKF(rh_ok && rh_len == 8 && *(ULONGLONG *)w == 258, "custom 8: ok=%d err=%lu len=%lu", rh_ok, rh_err, rh_len);
    rh_close(&c);
}

/* ------------------------------------------------------------------ synthetic string levels */
TEST(hqi_buf_status_text_sizes) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    char a[64]; WCHAR w[64];
    static const struct { DWORD lv; const char *v; } t[] = {
        { HTTP_QUERY_STATUS_TEXT, "Not Found" }, { HTTP_QUERY_VERSION, "HTTP/1.1" }, { HTTP_QUERY_STATUS_CODE, "404" } };
    for (size_t i = 0; i < 3; i++) {
        DWORD n = (DWORD)strlen(t[i].v);
        CHECK(!rh_callA(c.hr, t[i].lv, a, n, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, n + 1);
        CHECK(rh_callA(c.hr, t[i].lv, a, n + 1, NULL)); EXPECT_STR(a, t[i].v); EXPECT_EQ(rh_len, n);
        CHECK(!rh_callA(c.hr, t[i].lv, a, 0, NULL)); EXPECT_EQ(rh_len, n + 1);
        CHECK(!rh_callW(c.hr, t[i].lv, w, 2 * n + 1, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 2 * n + 2);
        CHECK(!rh_callW(c.hr, t[i].lv, w, n + 1, NULL)); EXPECT_EQ(rh_len, 2 * n + 2);
        CHECK(!rh_callW(c.hr, t[i].lv, w, n, NULL)); EXPECT_EQ(rh_len, 2 * n + 2);
        CHECK(rh_callW(c.hr, t[i].lv, w, 2 * n + 2, NULL)); EXPECT_EQ(rh_len, 2 * n);
        char back[64]; WideCharToMultiByte(CP_ACP, 0, w, -1, back, sizeof back, NULL, NULL); EXPECT_STR(back, t[i].v);
    }
    rh_close(&c);
}

TEST(hqi_buf_empty_value) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-E:\r\nServer:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    char a[16] = "zzzz"; WCHAR w[8] = { 'z', 'z' };
    CHECK(!rh_callA(c.hr, HTTP_QUERY_SERVER, a, 0, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 1);
    CHECK(rh_callA(c.hr, HTTP_QUERY_SERVER, a, 1, NULL)); EXPECT_EQ(rh_len, 0); EXPECT_EQ(a[0], 0); EXPECT_EQ(a[1], 'z');
    CHECK(!rh_callW(c.hr, HTTP_QUERY_SERVER, w, 1, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 2);
    CHECK(rh_callW(c.hr, HTTP_QUERY_SERVER, w, 2, NULL)); EXPECT_EQ(rh_len, 0); EXPECT_EQ(w[0], 0);
    EXPECT_QC(c.hr, "X-E", "");
    strcpy(a, "X-E");
    CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM, a, 0, NULL)); EXPECT_EQ(rh_len, 1);
    /* an empty value is not a number: NUMBER -> 12154 (_FormatAsUlonglong: no digits) [D] */
    DWORD n; CHECK(!rh_qnumc(c.hr, "X-E", &n)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    ULONGLONG n64; CHECK(!rh_qnum64c(c.hr, "X-E", &n64)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    rh_close(&c);
}

/* ------------------------------------------------------------------ raw header blocks */
static const char RESP_RAW[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 5\r\n"
    "X-A: 1\r\n"
    "Connection: close\r\n"
    "\r\nhello";
static const char RAW_CRLF[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nX-A: 1\r\nConnection: close\r\n\r\n";
static const char RAW_NUL[] = "HTTP/1.1 200 OK\0Content-Type: text/plain\0Content-Length: 5\0X-A: 1\0Connection: close\0";

TEST(hqi_buf_raw_headers_crlf_exact) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_RAW)) return; RH_SENT_OR_FAIL(&c);
    EXPECT_Q(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, RAW_CRLF);
    DWORD n = (DWORD)strlen(RAW_CRLF);
    char a[512]; DWORD l = 0;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, n + 1);
    CHECK(!rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, a, n, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, n + 1);
    CHECK(!rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, a, n - 1, NULL)); EXPECT_EQ(rh_len, n + 1);
    CHECK(!rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, a, 10, NULL)); EXPECT_EQ(rh_len, n + 1);
    memset(a, 'Z', sizeof a);
    CHECK(rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, a, n + 1, NULL)); EXPECT_EQ(rh_len, n); CHECK(!memcmp(a, RAW_CRLF, n + 1));
    WCHAR w[512]; l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, &l, NULL)); EXPECT_EQ(l, 2 * (n + 1));
    CHECK(!rh_callW(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, w, 2 * n + 1, NULL)); EXPECT_EQ(rh_len, 2 * (n + 1));
    CHECK(rh_callW(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, w, 2 * n + 2, NULL)); EXPECT_EQ(rh_len, 2 * n);
    rh_close(&c);
}

TEST(hqi_buf_raw_headers_nul_layout) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_RAW)) return; RH_SENT_OR_FAIL(&c);
    DWORD n = sizeof RAW_NUL - 1;   /* every line followed by one NUL; the terminating NUL is not counted */
    char a[512]; memset(a, 'Z', sizeof a);
    CHECK(rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS, a, sizeof a, NULL));
    EXPECT_EQ(rh_len, n);
    CHECKF(!memcmp(a, RAW_NUL, n) && a[n] == 0, "layout: %s", rh_esc(a, n + 1));
    EXPECT_EQ(a[n + 1], 'Z');
    /* double NUL at the end */
    CHECK(a[n - 1] == 0 && a[n] == 0);
    /* walking the strings gives the lines */
    int lines = 0; for (const char *p = a; *p; p += strlen(p) + 1) lines++;
    EXPECT_EQ(lines, 5);
    DWORD l = 0;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_RAW_HEADERS, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, n + 1);
    CHECK(!rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS, a, n, NULL)); EXPECT_EQ(rh_len, n + 1);
    CHECK(rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS, a, n + 1, NULL)); EXPECT_EQ(rh_len, n);
    /* W widens the embedded NULs too */
    WCHAR w[512];
    CHECK(rh_callW(c.hr, HTTP_QUERY_RAW_HEADERS, w, sizeof w, NULL)); EXPECT_EQ(rh_len, 2 * n);
    int good = 1; for (DWORD i = 0; i <= n && good; i++) good = w[i] == (i < n ? (WCHAR)(unsigned char)RAW_NUL[i] : 0);
    CHECK(good);
    l = 0;
    CHECK(!U(HttpQueryInfoW)(c.hr, HTTP_QUERY_RAW_HEADERS, NULL, &l, NULL)); EXPECT_EQ(l, 2 * (n + 1));
    rh_close(&c);
}

TEST(hqi_buf_large_value_roundtrip) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static char resp[80000]; static char val[70000];
    for (int i = 0; i < 65000; i++) val[i] = (char)('a' + i % 26);
    val[65000] = 0;
    int n = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\nX-Big: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", val);
    rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return; RH_SENT_OR_FAIL(&c);
    static char b[70000]; strcpy(b, "X-Big");
    CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, 100, NULL)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 65001);
    strcpy(b, "X-Big");
    CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, 65001, NULL)); EXPECT_EQ(rh_len, 65000); CHECK(!strcmp(b, val));
    static WCHAR w[70000]; lstrcpyW(w, L"X-Big");
    CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 100, NULL)); EXPECT_EQ(rh_len, 130002);
    lstrcpyW(w, L"X-Big");
    CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 130002, NULL)); EXPECT_EQ(rh_len, 130000); CHECK(w[0] == 'a' && w[64999] == (WCHAR)val[64999] && w[65000] == 0);
    rh_close(&c);
}

/* ------------------------------------------------------------------ bytes and code pages */
TEST(hqi_buf_high_bytes_a_verbatim_w_acp) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-Lat: caf\xe9\r\nX-Utf: \xc3\xa9t\xc3\xa9\r\nX-Hi: \x80\xff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    const char *v = rh_qac(c.hr, "X-Lat", 0, NULL); EXPECT_STR(v, "caf\xe9"); EXPECT_EQ(rh_len, 4);
    v = rh_qac(c.hr, "X-Utf", 0, NULL); EXPECT_STR(v, "\xc3\xa9t\xc3\xa9"); EXPECT_EQ(rh_len, 5);
    v = rh_qac(c.hr, "X-Hi", 0, NULL); EXPECT_STR(v, "\x80\xff"); EXPECT_EQ(rh_len, 2);
    if (!rh_acp1252()) { t_note("ACP %u: W code-page checks skipped", GetACP()); rh_close(&c); return; }
    v = rh_qwc(c.hr, "X-Lat", 0, NULL); CHECK(v != NULL); EXPECT_EQ(rh_len, 8);
    const WCHAR *w = rh_lastw(); CHECK(w[0] == 'c' && w[3] == 0x00E9 && w[4] == 0);
    v = rh_qwc(c.hr, "X-Utf", 0, NULL); EXPECT_EQ(rh_len, 10);   /* bytes widened one by one through CP 1252, not UTF-8 */
    w = rh_lastw(); CHECK(w[0] == 0x00C3 && w[1] == 0x00A9 && w[2] == 't');
    v = rh_qwc(c.hr, "X-Hi", 0, NULL); EXPECT_EQ(rh_len, 4);
    w = rh_lastw(); CHECK(w[0] == 0x20AC && w[1] == 0x00FF);    /* 0x80 is the euro sign in 1252 */
    rh_close(&c);
}
