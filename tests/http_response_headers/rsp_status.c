/* rsp_status.c - status-line parsing: codes, reasons, versions, spacing, HTTP/0.9, interim 1xx, broken responses.
 * VM_TIMEOUT: 300
 *
 * [D] CHttpHeaderParser::ParseStatusLine@0xbd050: skips leading SP/HT, looks for "HTTP" case-insensitively,
 * version token up to SP/HT, then SP/HT run, status token up to SP/HT/CR/LF (digits; parsing stops at the first
 * non-digit), SP/HT run, reason up to CR/LF. No "HTTP" -> downlevel (HTTP/0.9): every response-side query
 * answers 12151 ERROR_HTTP_DOWNLEVEL_SERVER (QueryInfo checks this[0x142c] & 2 first).
 */
#include "rh.h"

#define RESP_TAIL "Content-Length: 0\r\nConnection: close\r\n\r\n"

static const struct { int code; const char *reason; } codes[] = {
    { 200, "OK" }, { 201, "Created" }, { 202, "Accepted" }, { 203, "Non-Authoritative Information" }, { 204, "No Content" },
    { 205, "Reset Content" }, { 206, "Partial Content" }, { 207, "Multi-Status" }, { 208, "Already Reported" }, { 226, "IM Used" },
    { 299, "Custom 2xx" }, { 300, "Multiple Choices" }, { 301, "Moved Permanently" }, { 302, "Found" }, { 303, "See Other" },
    { 304, "Not Modified" }, { 305, "Use Proxy" }, { 306, "Unused" }, { 307, "Temporary Redirect" }, { 308, "Permanent Redirect" },
    { 400, "Bad Request" }, { 401, "Unauthorized" }, { 402, "Payment Required" }, { 403, "Forbidden" }, { 404, "Not Found" },
    { 405, "Method Not Allowed" }, { 406, "Not Acceptable" }, { 407, "Proxy Authentication Required" }, { 408, "Request Timeout" },
    { 409, "Conflict" }, { 410, "Gone" }, { 411, "Length Required" }, { 412, "Precondition Failed" }, { 413, "Payload Too Large" },
    { 414, "URI Too Long" }, { 415, "Unsupported Media Type" }, { 416, "Range Not Satisfiable" }, { 417, "Expectation Failed" },
    { 418, "I'm a teapot" }, { 421, "Misdirected Request" }, { 422, "Unprocessable Entity" }, { 425, "Too Early" },
    { 426, "Upgrade Required" }, { 428, "Precondition Required" }, { 429, "Too Many Requests" }, { 431, "Request Header Fields Too Large" },
    { 451, "Unavailable For Legal Reasons" }, { 499, "Client Closed" }, { 500, "Internal Server Error" }, { 501, "Not Implemented" },
    { 502, "Bad Gateway" }, { 503, "Service Unavailable" }, { 504, "Gateway Timeout" }, { 505, "HTTP Version Not Supported" },
    { 507, "Insufficient Storage" }, { 511, "Network Authentication Required" }, { 599, "Custom 5xx" }, { 600, "Six Hundred" },
    { 999, "Nine Nine Nine" },
};

static void check_status(rh_t *c, int code, const char *reason, const char *version) {
    char cs[16]; snprintf(cs, sizeof cs, "%d", code);
    EXPECT_Q(c->hr, HTTP_QUERY_STATUS_CODE, cs);
    EXPECT_Q(c->hr, HTTP_QUERY_STATUS_TEXT, reason);
    EXPECT_Q(c->hr, HTTP_QUERY_VERSION, version);
    DWORD n; CHECKF(rh_qnum(c->hr, HTTP_QUERY_STATUS_CODE, &n) && n == (DWORD)code, "STATUS_CODE|NUMBER %d: got %lu err=%lu", code, n, rh_err);
}

TEST(rsp_status_code_table) {
    REQUIRE(U(HttpQueryInfoA));
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "HTTP/1.1 %d %s\r\n" RESP_TAIL, codes[i].code, codes[i].reason);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "code %d: send err=%lu %s", codes[i].code, c.err, t_inet_errname(c.err));
        if (c.sent) {
            check_status(&c, codes[i].code, codes[i].reason, "HTTP/1.1");
            char raw[300]; snprintf(raw, sizeof raw, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", codes[i].code, codes[i].reason);
            EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, raw);
        }
        rh_close(&c);
    }
}

/* the reason phrase is whatever the server sent, not a canonical text */
TEST(rsp_status_reason_verbatim) {
    REQUIRE(U(HttpQueryInfoA));
    static const struct { const char *line; int code; const char *reason; } t[] = {
        { "HTTP/1.1 200 All Good Here", 200, "All Good Here" },
        { "HTTP/1.1 404 Nope", 404, "Nope" },
        { "HTTP/1.1 200 ok", 200, "ok" },
        { "HTTP/1.1 500 Server: Exploded (really)", 500, "Server: Exploded (really)" },
        { "HTTP/1.1 200 caf\xe9", 200, "caf\xe9" },
        { "HTTP/1.1 200 \x22quoted\x22", 200, "\x22quoted\x22" },
        { "HTTP/1.1 201 A  B   C", 201, "A  B   C" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "%s\r\n" RESP_TAIL, t[i].line);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "%s: err=%lu", t[i].line, c.err);
        if (c.sent) { char cs[8]; snprintf(cs, sizeof cs, "%d", t[i].code); EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, cs); EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, t[i].reason); }
        rh_close(&c);
    }
}

TEST(rsp_status_http10) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    check_status(&c, 200, "OK", "HTTP/1.0");
    EXPECT_Q(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\n");
    char b[16]; { size_t bn_ = rh_body(&c, b, sizeof b); EXPECT_EQ(bn_, 3); } EXPECT_STR(b, "abc");
    rh_close(&c);
}

TEST(rsp_status_http10_close_delimited) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.0 200 OK\r\nX-K: v\r\n\r\nuntil close";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    check_status(&c, 200, "OK", "HTTP/1.0");
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_LENGTH, NULL);
    char b[32]; { size_t bn_ = rh_body(&c, b, sizeof b); EXPECT_EQ(bn_, 11); } EXPECT_STR(b, "until close");
    rh_close(&c);
}

TEST(rsp_status_missing_reason) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char *lines[] = { "HTTP/1.1 200", "HTTP/1.1 200 ", "HTTP/1.1 200\t", "HTTP/1.1 204   " };
    static const int codes_[] = { 200, 200, 200, 204 };
    for (int i = 0; i < 4; i++) {
        char resp[128]; int n = snprintf(resp, sizeof resp, "%s\r\n" RESP_TAIL, lines[i]);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "\"%s\": err=%lu", lines[i], c.err);
        if (c.sent) {
            check_status(&c, codes_[i], "", "HTTP/1.1");
            DWORD l = 0; char a[4];
            CHECK(!rh_callA(c.hr, HTTP_QUERY_STATUS_TEXT, a, 0, NULL)); EXPECT_EQ(rh_len, 1);
            CHECK(rh_callA(c.hr, HTTP_QUERY_STATUS_TEXT, a, 1, NULL)); EXPECT_EQ(rh_len, 0);
            /* [W10] the status line is rebuilt as "<version> <code> <reason>": an empty reason leaves a trailing space */
            char want[96]; snprintf(want, sizeof want, "HTTP/1.1 %d \r\nContent-Length: 0\r\nConnection: close\r\n\r\n", codes_[i]);
            EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, want);
            (void)l;
        }
        rh_close(&c);
    }
}

TEST(rsp_status_spacing_variants) {
    REQUIRE(U(HttpQueryInfoA));
    static const struct { const char *line; int code; const char *reason; const char *ver; } t[] = {
        { "HTTP/1.1   201    Created", 201, "Created", "HTTP/1.1" },
        { "HTTP/1.1\t202\tAccepted", 202, "Accepted", "HTTP/1.1" },
        { "HTTP/1.1 \t 203 \t Fine", 203, "Fine", "HTTP/1.1" },
        { "  HTTP/1.1 200 Lead", 200, "Lead", "HTTP/1.1" },
        { "\tHTTP/1.1 200 LeadTab", 200, "LeadTab", "HTTP/1.1" },
        { "HTTP/1.1 200 Trail  ", 200, "Trail  ", "HTTP/1.1" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "%s\r\n" RESP_TAIL, t[i].line);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "\"%s\": err=%lu", rh_esc(t[i].line, strlen(t[i].line)), c.err);
        if (c.sent) check_status(&c, t[i].code, t[i].reason, t[i].ver);
        rh_close(&c);
    }
}

TEST(rsp_status_version_variants) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *vers[] = { "HTTP/1.1", "HTTP/1.0", "http/1.1", "Http/1.1", "HTTP/1.2", "HTTP/2.0", "HTTP/2", "HTTP/0.9", "HTTP/1", "HTTP/9.9" };
    for (size_t i = 0; i < sizeof vers / sizeof vers[0]; i++) {
        char resp[128]; int n = snprintf(resp, sizeof resp, "%s 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", vers[i]);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "%s: err=%lu", vers[i], c.err);
        if (c.sent) {
            EXPECT_QA(c.hr, HTTP_QUERY_VERSION, vers[i]);
            EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "200");
            char b[8]; size_t bn = rh_body(&c, b, sizeof b);
            CHECKF(bn == 2 && !strcmp(b, "ok"), "%s body %u \"%s\"", vers[i], (unsigned)bn, b);
        }
        rh_close(&c);
    }
}

/* "HTTP" may appear after up to 4 bytes of junk [D ParseStatusLine scan loop]; observed values recorded */
TEST(rsp_status_leading_junk) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *pre[] = { "x", "xy", "xyz", "wxyz", "vwxyz", "\r\n", "\r\n\r\n" };
    for (size_t i = 0; i < sizeof pre / sizeof pre[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "%sHTTP/1.1 200 OK\r\nX-J: %u\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", pre[i], (unsigned)i);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        const char *code = c.sent ? rh_qa(c.hr, HTTP_QUERY_STATUS_CODE, NULL) : NULL;
        DWORD qerr = rh_err;
        const char *xj = c.sent ? rh_qac(c.hr, "X-J", 0, NULL) : NULL;
        const char *ver = c.sent ? rh_qa(c.hr, HTTP_QUERY_VERSION, NULL) : NULL;
        char b[128] = ""; size_t bn = c.sent ? rh_body(&c, b, sizeof b) : 0;
        /* [W10] up to 4 junk bytes (or blank lines) before "HTTP" are skipped; 5 bytes -> treated as HTTP/0.9 */
        char want_xj[8]; snprintf(want_xj, sizeof want_xj, "%u", (unsigned)i);
        CHECKF(c.sent && code && !strcmp(code, "200"), "junk %u: sent=%d err=%lu code=%s qerr=%lu", (unsigned)i, c.sent, c.err, code ? code : "-", qerr);
        if (i == 4) { EXPECT_STR(ver, "HTTP/1.0"); CHECK(!xj); EXPECT_EQ(bn, (size_t)n); }
        else { EXPECT_STR(ver, "HTTP/1.1"); EXPECT_STR(xj, want_xj); EXPECT_EQ(bn, 2); EXPECT_STR(b, "ok"); }
        rh_close(&c);
    }
}

/* [W10] status token: the string answer is the token as sent; the number stops at the first non-digit and a value
 * of 0 (no digits, "0", "-200") reads back as 0xFFFFFFFF; > 0xFFFFFFFF or an empty token -> HttpSendRequest 12152.
 * A bare "HTTP/1.1" line is treated as a 0.9 response (200 OK synthesised, the line is body). */
TEST(rsp_status_code_token_variants) {
    REQUIRE(U(HttpQueryInfoA));
    static const struct { const char *line; DWORD send_err; DWORD num; const char *code; const char *text; } t[] = {
        { "HTTP/1.1 2x0 Odd", 0, 2, "2x0", "Odd" },
        { "HTTP/1.1 abc Letters", 0, 0xFFFFFFFF, "abc", "Letters" },
        { "HTTP/1.1 0200 Zero", 0, 200, "0200", "Zero" },
        { "HTTP/1.1 0 Zero", 0, 0xFFFFFFFF, "0", "Zero" },
        { "HTTP/1.1 4294967295 Max", 0, 0xFFFFFFFF, "4294967295", "Max" },
        { "HTTP/1.1 4294967296 Over", ERROR_HTTP_INVALID_SERVER_RESPONSE, 0, NULL, NULL },
        { "HTTP/1.1 99999999999999999999999 Huge", ERROR_HTTP_INVALID_SERVER_RESPONSE, 0, NULL, NULL },
        { "HTTP/1.1 -200 Neg", 0, 0xFFFFFFFF, "-200", "Neg" },
        { "HTTP/1.1 20 Short", 0, 20, "20", "Short" },
        { "HTTP/1.1 1000 Long", 0, 1000, "1000", "Long" },
        { "HTTP/1.1 ", ERROR_HTTP_INVALID_SERVER_RESPONSE, 0, NULL, NULL },
        { "HTTP/1.1  \t ", ERROR_HTTP_INVALID_SERVER_RESPONSE, 0, NULL, NULL },
        { "HTTP/1.1", 0, 200, "200", NULL },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "%s\r\nX-K: k\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok", t[i].line);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        const char *ln = rh_esc(t[i].line, strlen(t[i].line));
        if (t[i].send_err) { CHECKF(!c.sent && c.err == t[i].send_err, "\"%s\": sent=%d err=%lu", ln, c.sent, c.err); rh_close(&c); continue; }
        CHECKF(c.sent, "\"%s\": err=%lu", ln, c.err);
        if (c.sent) {
            DWORD num = 0; CHECKF(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &num) && num == t[i].num, "\"%s\": num %lu err=%lu", ln, num, rh_err);
            EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, t[i].code);
            if (t[i].text) { EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, t[i].text); EXPECT_QC(c.hr, "X-K", "k"); }
            else { EXPECT_QC(c.hr, "X-K", NULL); EXPECT_QA(c.hr, HTTP_QUERY_VERSION, "HTTP/1.0"); }
        }
        rh_close(&c);
    }
}

/* ------------------------------------------------------------------ HTTP/0.9 (no status line) */
/* [W10] Win10 does NOT answer 12151 for a status-less (HTTP/0.9) response: it synthesises a status
 * (VERSION "HTTP/1.0", 200) and keeps no headers; the whole stream is the body. The downlevel flag the decomp
 * checks (this[0x142c] & 2) is evidently not set on this path. */
TEST(rsp_status_http09_synthesised) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    static const char resp[] = "hello world, no headers here\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_CODE, "200");
    EXPECT_Q(c.hr, HTTP_QUERY_VERSION, "HTTP/1.0");
    DWORD n32; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &n32)); EXPECT_EQ(n32, 200);
    const char *t = rh_qa(c.hr, HTTP_QUERY_STATUS_TEXT, NULL);
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    t_note("HTTP/0.9: STATUS_TEXT=%s (err %lu) RAW_HEADERS_CRLF=%s", t ? rh_esc(t, strlen(t)) : "(fail)", rh_err, raw ? rh_esc(raw, strlen(raw)) : "(fail)");
    EXPECT_QERR2(c.hr, HTTP_QUERY_CONTENT_TYPE, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_CONTENT_LENGTH, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR2(c.hr, HTTP_QUERY_ECHO_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QCERR(c.hr, "X-Anything", 0, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR(c.hr, HTTP_QUERY_EXPIRES | HTTP_QUERY_FLAG_SYSTEMTIME, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR(c.hr, 0x60, ERROR_INVALID_PARAMETER);
    EXPECT_Q(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    EXPECT_QA(c.hr, HTTP_QUERY_USER_AGENT | HTTP_QUERY_FLAG_REQUEST_HEADERS, "rh-agent/1.0");
    char b[64]; size_t n = rh_body(&c, b, sizeof b);
    EXPECT_EQ(n, sizeof resp - 1); EXPECT_STR(b, resp);
    rh_close(&c);
}

TEST(rsp_status_http09_short_and_binary) {
    REQUIRE(U(HttpQueryInfoA));
    /* includes truncated status lines followed by close: "HTTP/" and "HTTP/1.1 2" are also treated as 0.9 [W10] */
    static const char *bodies[] = { "OK", "HTT", "<html>hi</html>", "FTP/1.0 200 OK\r\n\r\n", "X-Header: looks like one\r\n\r\n", "HTTP/", "HTTP/1.1 2" };
    for (size_t i = 0; i < sizeof bodies / sizeof bodies[0]; i++) {
        rh_t c; if (!rh_raw(&c, "GET", bodies[i], strlen(bodies[i]))) return;
        CHECKF(c.sent, "body \"%s\": err=%lu", rh_esc(bodies[i], strlen(bodies[i])), c.err);
        if (c.sent) {
            EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "200");
            EXPECT_QA(c.hr, HTTP_QUERY_VERSION, "HTTP/1.0");
            char b[64]; size_t n = rh_body(&c, b, sizeof b);
            if (i < 5) CHECKF(n == strlen(bodies[i]) && !memcmp(b, bodies[i], n), "body %u \"%s\"", (unsigned)n, rh_esc(b, n));
            else t_note("truncated \"%s\" as 0.9: body %u \"%s\"", bodies[i], (unsigned)n, rh_esc(b, n));
        }
        rh_close(&c);
    }
}

/* ------------------------------------------------------------------ interim 1xx */
TEST(rsp_status_100_continue_consumed) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 Final\r\nX-F: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    check_status(&c, 200, "Final", "HTTP/1.1");
    EXPECT_QC(c.hr, "X-F", "1");
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 Final\r\nX-F: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
    char b[8]; { size_t bn_ = rh_body(&c, b, sizeof b); EXPECT_EQ(bn_, 2); } EXPECT_STR(b, "ok");
    rh_close(&c);
}

TEST(rsp_status_several_interim) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\n"
                               "HTTP/1.1 201 Made\r\nContent-Length: 1\r\nConnection: close\r\n\r\nz";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    check_status(&c, 201, "Made", "HTTP/1.1");
    char b[8]; { size_t bn_ = rh_body(&c, b, sizeof b); EXPECT_EQ(bn_, 1); }
    rh_close(&c);
}

TEST(rsp_status_interim_headers_dropped) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\nX-Interim: yes\r\n\r\n"
                               "HTTP/1.1 200 OK\r\nX-Final: yes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    const char *code = rh_qa(c.hr, HTTP_QUERY_STATUS_CODE, NULL);
    const char *xi = rh_qac(c.hr, "X-Interim", 0, NULL);
    const char *link = rh_qa(c.hr, HTTP_QUERY_LINK, NULL);
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    CHECK(!xi); CHECK(!link);   /* [W10] interim headers are discarded */
    EXPECT_STR(raw, "HTTP/1.1 200 OK\r\nX-Final: yes\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    EXPECT_STR(code, "200");
    EXPECT_QC(c.hr, "X-Final", "yes");
    rh_close(&c);
}

/* HTTP/1.0 100 Continue and a 100 with a reason only */
TEST(rsp_status_interim_variants) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *pre[] = { "HTTP/1.0 100 Continue\r\n\r\n", "HTTP/1.1 100\r\n\r\n", "HTTP/1.1 100 Continue\r\nX-I: 1\r\n\r\n", "HTTP/1.1 199 Odd\r\n\r\n" };
    for (size_t i = 0; i < 4; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "%sHTTP/1.1 200 OK\r\nX-N: %u\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", pre[i], (unsigned)i);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        const char *code = c.sent ? rh_qa(c.hr, HTTP_QUERY_STATUS_CODE, NULL) : NULL;
        const char *xn = c.sent ? rh_qac(c.hr, "X-N", 0, NULL) : NULL;
        t_note("interim \"%s\": sent=%d err=%lu code=%s X-N=%s", rh_esc(pre[i], strlen(pre[i])), c.sent, c.err, code ? code : "-", xn ? xn : "-");
        char wn[8]; snprintf(wn, sizeof wn, "%u", (unsigned)i);
        CHECK(c.sent); EXPECT_STR(code, "200"); EXPECT_STR(xn, wn);   /* [W10] every 1xx (incl. 199, HTTP/1.0 100) skipped */
        rh_close(&c);
    }
}

/* ------------------------------------------------------------------ broken / empty responses */
TEST(rsp_status_empty_response) {
    REQUIRE(U(HttpSendRequestA));
    srv_step st[] = { S_HEAD(), S_CLOSE() };
    rh_t c; if (!rh_start(&c, st, 2)) return;
    if (!rh_open(&c, "GET", "/e", 0)) { rh_close(&c); return; }
    rh_send(&c, NULL, NULL, 0);
    CHECK(!c.sent);
    t_note("empty response: err=%lu %s, connections=%d", c.err, t_inet_errname(c.err), srv_conn_count(c.s));
    EXPECT_EQ(c.err, ERROR_HTTP_INVALID_SERVER_RESPONSE);   /* [W10] */
    rh_close(&c);
}

TEST(rsp_status_reset_response) {
    REQUIRE(U(HttpSendRequestA));
    srv_step st[] = { S_HEAD(), S_RESET() };
    rh_t c; if (!rh_start(&c, st, 2)) return;
    if (!rh_open(&c, "GET", "/e", 0)) { rh_close(&c); return; }
    rh_send(&c, NULL, NULL, 0);
    CHECK(!c.sent);
    t_note("RST response: err=%lu %s, connections=%d", c.err, t_inet_errname(c.err), srv_conn_count(c.s));
    EXPECT_EQ(c.err, ERROR_INTERNET_CONNECTION_RESET);   /* [W10] */
    rh_close(&c);
}

TEST(rsp_status_truncated_head) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *raws[] = { "HTTP/1.1 200 OK\r\nX-A: 1\r\n", "HTTP/1.1 200 OK\r\nX-A: 1", "HTTP/1.1 200 OK", "HTTP/1.1 200 OK\r\n", "HTTP/1.1 2", "HTTP/" };
    for (size_t i = 0; i < sizeof raws / sizeof raws[0]; i++) {
        rh_t c; if (!rh_raw(&c, "GET", raws[i], strlen(raws[i]))) return;
        const char *code = c.sent ? rh_qa(c.hr, HTTP_QUERY_STATUS_CODE, NULL) : NULL; DWORD qe = rh_err;
        const char *xa = c.sent ? rh_qac(c.hr, "X-A", 0, NULL) : NULL;
        /* [W10] EOF ends the head: no error, status 200; X-A kept when its line arrived (even without CRLF) */
        CHECKF(c.sent && code && !strcmp(code, "200"), "truncated \"%s\": sent=%d err=%lu code=%s qe=%lu", rh_esc(raws[i], strlen(raws[i])), c.sent, c.err, code ? code : "-", qe);
        if (i < 2) EXPECT_STR(xa, "1"); else CHECK(!xa);
        rh_close(&c);
    }
}

/* ------------------------------------------------------------------ redirects are reported, not followed (NO_AUTO_REDIRECT) */
TEST(rsp_status_redirect_location_verbatim) {
    REQUIRE(U(HttpQueryInfoA));
    static const struct { int code; const char *loc; } t[] = {
        { 301, "/moved" }, { 302, "http://127.0.0.1:1/x?y=z" }, { 303, "other" }, { 307, "/t%20emp" }, { 308, "  /padded" } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char resp[256]; int n = snprintf(resp, sizeof resp, "HTTP/1.1 %d R\r\nLocation: %s\r\n" RESP_TAIL, t[i].code, t[i].loc);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "%d: err=%lu", t[i].code, c.err);
        if (c.sent) {
            char cs[8]; snprintf(cs, sizeof cs, "%d", t[i].code);
            EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, cs);
            const char *want = t[i].loc; while (*want == ' ') want++;
            EXPECT_Q(c.hr, HTTP_QUERY_LOCATION, want);
            EXPECT_EQ(srv_req_count(c.s), 1);
        }
        rh_close(&c);
    }
}
