/* rsp_values.c - the bytes of names, values and reason phrases: control bytes inside and at the ends of a value,
 * known-name look-alikes, long names, odd reason phrases, a second status line among the headers, and a header
 * line that names a level the caller did not mean.
 * VM_TIMEOUT: 180
 *
 * [D] CHttpHeaderParser::ParseHeaders@0x8a150: the name ends at ':' (whitespace before it dropped), LWS after the
 * colon and at the end of the line is skipped, the rest is stored as is. [W10] (rsp_headers.c) NUL inside a value is
 * kept, a bare CR ends a line, lines without a colon are dropped. These tests widen the byte coverage.
 */
#include "rh.h"

#define TAIL "Content-Length: 0\r\nConnection: close\r\n\r\n"

static int go(rh_t *c, const char *raw, size_t n) {
    if (!rh_raw(c, "GET", raw, n)) return 0;
    if (!c->sent) { t_check(0, __FILE__, __LINE__, "HttpSendRequest", "err=%lu %s", c->err, t_inet_errname(c->err)); rh_close(c); return 0; }
    return 1;
}

/* every C0 control byte other than HT/LF/CR (and NUL, covered elsewhere), and DEL, in the middle of a value */
TEST(rsp_val_control_bytes_inside_value) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static char resp[4096]; size_t k = (size_t)sprintf(resp, "HTTP/1.1 200 OK\r\n");
    int bytes[40], nb = 0;
    for (int b = 1; b < 32; b++) if (b != '\t' && b != '\n' && b != '\r') bytes[nb++] = b;
    bytes[nb++] = 0x7F;
    for (int i = 0; i < nb; i++) k += (size_t)sprintf(resp + k, "X-C%02X: a%cb\r\n", bytes[i], bytes[i]);
    k += (size_t)sprintf(resp + k, TAIL);
    rh_t c; if (!go(&c, resp, k)) return;
    for (int i = 0; i < nb; i++) {
        char nm[16], want[4] = { 'a', (char)bytes[i], 'b', 0 }; snprintf(nm, sizeof nm, "X-C%02X", bytes[i]);
        const char *v = rh_qac(c.hr, nm, 0, NULL);
        CHECKF(v && rh_len == 3 && !memcmp(v, want, 3), "byte 0x%02x: got %s len=%lu err=%lu", bytes[i], v ? rh_esc(v, rh_len) : "(fail)", rh_len, rh_err);
        v = rh_qwc(c.hr, nm, 0, NULL);
        const WCHAR *w = rh_lastw();
        CHECKF(v && rh_len == 6 && w[0] == 'a' && w[1] == (WCHAR)bytes[i] && w[2] == 'b', "W byte 0x%02x: len=%lu w1=0x%x", bytes[i], rh_len, v ? w[1] : 0);
    }
    rh_close(&c);
}

/* control bytes at the start and end of a value: which ones count as whitespace? (VT, FF and others) */
TEST(rsp_val_control_bytes_at_value_ends) {
    REQUIRE(U(HttpQueryInfoA));
    static char resp[4096]; size_t k = (size_t)sprintf(resp, "HTTP/1.1 200 OK\r\n");
    static const int bytes[] = { 0x01, 0x0B, 0x0C, 0x1F, 0x7F };
    for (size_t i = 0; i < 5; i++) k += (size_t)sprintf(resp + k, "X-S%02X: %cv\r\nX-E%02X: v%c\r\n", bytes[i], bytes[i], bytes[i], bytes[i]);
    k += (size_t)sprintf(resp + k, TAIL);
    rh_t c; if (!go(&c, resp, k)) return;
    for (size_t i = 0; i < 5; i++) {
        char nm[16];
        snprintf(nm, sizeof nm, "X-S%02X", bytes[i]); const char *v = rh_qac(c.hr, nm, 0, NULL);
        t_note("leading 0x%02x: %s len %lu", bytes[i], v ? rh_esc(v, rh_len) : "(fail)", rh_len);
        CHECKF(v && (rh_len == 1 || rh_len == 2), "leading 0x%02x: stored (trimmed or not) len=%lu err=%lu", bytes[i], rh_len, rh_err);
        snprintf(nm, sizeof nm, "X-E%02X", bytes[i]); v = rh_qac(c.hr, nm, 0, NULL);
        t_note("trailing 0x%02x: %s len %lu", bytes[i], v ? rh_esc(v, rh_len) : "(fail)", rh_len);
        CHECKF(v && (rh_len == 1 || rh_len == 2) && v[0] == 'v', "trailing 0x%02x: len=%lu err=%lu", bytes[i], rh_len, rh_err);
    }
    rh_close(&c);
}

/* names that start or end like a known header are not that header */
TEST(rsp_val_known_name_lookalikes) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c;
    static const char R[] = "HTTP/1.1 200 OK\r\nServer-Timing: 1\r\nServe: 2\r\nXServer: 3\r\nContent-Typ: 4\r\nContent-Types: 5\r\n"
                            "Etags: 6\r\nVary-: 7\r\nAge2: 8\r\n" TAIL;
    if (!go(&c, R, sizeof R - 1)) return;
    EXPECT_QERR2(c.hr, HTTP_QUERY_SERVER, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_CONTENT_TYPE, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_ETAG, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_VARY, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_AGE, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QC(c.hr, "Server-Timing", "1"); EXPECT_QC(c.hr, "Serve", "2"); EXPECT_QC(c.hr, "XServer", "3");
    EXPECT_QC(c.hr, "Content-Typ", "4"); EXPECT_QC(c.hr, "Content-Types", "5"); EXPECT_QC(c.hr, "Etags", "6");
    EXPECT_QC(c.hr, "Vary-", "7"); EXPECT_QC(c.hr, "Age2", "8");
    EXPECT_QC(c.hr, "Server", NULL); EXPECT_QC(c.hr, "Serv", NULL); EXPECT_QC(c.hr, "Server-", NULL);
    rh_close(&c);
}

/* long header names */
TEST(rsp_val_long_names) {
    REQUIRE(U(HttpQueryInfoA));
    static const int lens[] = { 64, 255, 256, 1024, 4096, 8192 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        static char name[9000], resp[20000];
        name[0] = 'X'; name[1] = '-';
        for (int j = 2; j < lens[i]; j++) name[j] = (char)('a' + j % 26);
        name[lens[i]] = 0;
        int n = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\n%s: long-name\r\nX-After: a\r\n" TAIL, name);
        rh_t c; if (!go(&c, resp, (size_t)n)) return;
        EXPECT_QC(c.hr, name, "long-name");
        EXPECT_QC(c.hr, "X-After", "a");
        const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
        CHECKF(raw && strstr(raw, name) && strstr(raw, ": long-name\r\n"), "len %d raw", lens[i]);
        rh_close(&c);
    }
}

/* reason phrases: tabs, colons, high bytes, a header-like text, long */
TEST(rsp_val_reason_phrase_bytes) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *reasons[] = { "OK\tTab", "Moved: here", "X-Header: like", "\xc3\x9cnicode \xe2\x9c\x93", "a;b,c=d", "(paren) [br] {cu}", "\"quoted\"" };
    for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "HTTP/1.1 200 %s\r\nX-I: %u\r\n" TAIL, reasons[i], (unsigned)i);
        rh_t c; if (!go(&c, resp, (size_t)n)) return;
        EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, reasons[i]);
        char want[300]; snprintf(want, sizeof want, "HTTP/1.1 200 %s\r\nX-I: %u\r\n" TAIL, reasons[i], (unsigned)i);
        EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, want);
        EXPECT_QC(c.hr, "X-Header", NULL);
        rh_close(&c);
    }
    static char longr[5000], resp[6000];
    for (int i = 0; i < 4096; i++) longr[i] = (char)('A' + i % 26);
    longr[4096] = 0;
    int n = snprintf(resp, sizeof resp, "HTTP/1.1 299 %s\r\n" TAIL, longr);
    rh_t c; if (!go(&c, resp, (size_t)n)) return;
    const char *v = rh_qa(c.hr, HTTP_QUERY_STATUS_TEXT, NULL);
    CHECKF(v && rh_len == 4096 && !strcmp(v, longr), "4096-byte reason: len=%lu err=%lu", rh_len, rh_err);
    DWORD code = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &code)); EXPECT_EQ(code, 299);
    rh_close(&c);
}

/* a second status line among the headers is a line without a colon: dropped [W10 rsp_hdr_line_without_colon] */
TEST(rsp_val_second_status_line_in_headers) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R[] = "HTTP/1.1 200 OK\r\nX-A: 1\r\nHTTP/1.1 404 Not Found\r\nX-B: 2\r\n" TAIL;
    rh_t c; if (!go(&c, R, sizeof R - 1)) return;
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_CODE, "200");
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_TEXT, "OK");
    EXPECT_QC(c.hr, "X-A", "1"); EXPECT_QC(c.hr, "X-B", "2");
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nX-A: 1\r\nX-B: 2\r\n" TAIL);
    rh_close(&c);
}

/* header names that collide with the synthetic levels' notion (no "Status-Code" header is consulted) */
TEST(rsp_val_headers_named_like_synthetic_levels) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R[] = "HTTP/1.1 201 Created\r\nStatus-Code: 999\r\nStatus-Text: fake\r\nVersion: HTTP/9.9\r\nRequest-Method: PUT\r\nStatus: 500\r\n" TAIL;
    rh_t c; if (!go(&c, R, sizeof R - 1)) return;
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_CODE, "201");
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_TEXT, "Created");
    EXPECT_Q(c.hr, HTTP_QUERY_VERSION, "HTTP/1.1");
    EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    EXPECT_QC(c.hr, "Status-Code", "999"); EXPECT_QC(c.hr, "Status", "500"); EXPECT_QC(c.hr, "Version", "HTTP/9.9");
    rh_close(&c);
}

/* the value is exactly what follows the trimmed colon, even when it looks like more headers */
TEST(rsp_val_value_looks_like_headers) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R[] = "HTTP/1.1 200 OK\r\nX-V: Content-Type: text/evil\r\nX-W: a: b: c\r\nX-Semi: a=1; b=2, c=3\r\n" TAIL;
    rh_t c; if (!go(&c, R, sizeof R - 1)) return;
    EXPECT_QC(c.hr, "X-V", "Content-Type: text/evil");
    EXPECT_QC(c.hr, "X-W", "a: b: c");
    EXPECT_QC(c.hr, "X-Semi", "a=1; b=2, c=3");
    EXPECT_QERR2(c.hr, HTTP_QUERY_CONTENT_TYPE, ERROR_HTTP_HEADER_NOT_FOUND);
    rh_close(&c);
}

/* value lengths around common buffer sizes, all in one response, A and W sizes */
TEST(rsp_val_lengths_around_buffer_sizes) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const int lens[] = { 0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1025, 2047, 2048, 2049 };
    static char resp[64000]; size_t k = (size_t)sprintf(resp, "HTTP/1.1 200 OK\r\n");
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        k += (size_t)sprintf(resp + k, "X-L%d: ", lens[i]);
        for (int j = 0; j < lens[i]; j++) resp[k++] = (char)('a' + (j * 7 + lens[i]) % 26);
        k += (size_t)sprintf(resp + k, "\r\n");
    }
    k += (size_t)sprintf(resp + k, TAIL);
    rh_t c; if (!go(&c, resp, k)) return;
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        char nm[16]; snprintf(nm, sizeof nm, "X-L%d", lens[i]);
        static char want[4096]; for (int j = 0; j < lens[i]; j++) want[j] = (char)('a' + (j * 7 + lens[i]) % 26); want[lens[i]] = 0;
        EXPECT_QC(c.hr, nm, want);
        /* exact-1 and exact through A */
        static char b[4096]; DWORD n = (DWORD)lens[i];
        if (n >= 8) { lstrcpyA(b, nm); CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, n, NULL)); CHECKF(rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == n + 1, "%s A len %lu: err=%lu len=%lu", nm, n, rh_err, rh_len); }
        lstrcpyA(b, nm); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM, b, n + 1 < 6 ? 6 : n + 1, NULL)); EXPECT_EQ(rh_len, n);
        /* W: 2n+1 bytes is short, 2n+2 is enough */
        static WCHAR w[4096];
        MultiByteToWideChar(CP_ACP, 0, nm, -1, w, 64);
        BOOL okw = rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 2 * n + 1 < 14 ? 14 : 2 * n + 1, NULL);
        if (2 * n + 1 >= 14) CHECKF(!okw && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 2 * n + 2, "%s W len %lu: ok=%d err=%lu len=%lu", nm, 2 * n + 1, okw, rh_err, rh_len);
        MultiByteToWideChar(CP_ACP, 0, nm, -1, w, 64);
        okw = rh_callW(c.hr, HTTP_QUERY_CUSTOM, w, 2 * n + 2 < 14 ? 14 : 2 * n + 2, NULL);
        CHECKF(okw && rh_len == 2 * n, "%s W exact: ok=%d err=%lu len=%lu", nm, okw, rh_err, rh_len);
    }
    rh_close(&c);
}
