/* rsp_headers.c - response header-line parsing: whitespace, empty values, casing, colons, folding, odd lines,
 * duplicates, line endings, counts and size limits, HEAD/204/304 framing, content headers.
 * VM_TIMEOUT: 300
 *
 * [D] CHttpHeaderParser::ParseHeaders@0x8a150 splits each line at the first ':' (or CR/LF), skips LWS after the
 * colon; QueryFilteredRawHeaders rebuilds RAW_HEADERS(_CRLF) as "Name: value" per stored header, names as received.
 */
#include "rh.h"

#define TAIL "Content-Length: 0\r\nConnection: close\r\n\r\n"

static int go(rh_t *c, const char *raw, size_t n) {
    if (!rh_raw(c, "GET", raw, n)) return 0;
    if (!c->sent) { t_check(0, __FILE__, __LINE__, "HttpSendRequest", "err=%lu %s", c->err, t_inet_errname(c->err)); rh_close(c); return 0; }
    return 1;
}
#define GO(c, lit) do { if (!go((c), (lit), sizeof(lit) - 1)) return; } while (0)

static void note_custom(HINTERNET h, const char *name) {
    const char *v = rh_qac(h, name, 0, NULL);
    t_note("%s -> %s%s%s (err %lu len %lu)", rh_esc(name, strlen(name)), v ? "\"" : "", v ? rh_esc(v, strlen(v)) : "not found", v ? "\"" : "", rh_err, rh_len);
}

/* ------------------------------------------------------------------ whitespace */
TEST(rsp_hdr_value_leading_whitespace_trimmed) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-1:v1\r\nX-2: v2\r\nX-3:    v3\r\nX-4:\tv4\r\nX-5: \t \t v5\r\n" TAIL);
    EXPECT_QC(c.hr, "X-1", "v1"); EXPECT_QC(c.hr, "X-2", "v2"); EXPECT_QC(c.hr, "X-3", "v3"); EXPECT_QC(c.hr, "X-4", "v4"); EXPECT_QC(c.hr, "X-5", "v5");
    rh_close(&c);
}

TEST(rsp_hdr_value_trailing_whitespace) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-T1: v1 \r\nX-T2: v2   \r\nX-T3: v3\t\r\nX-T4: a b \t \r\n" TAIL);
    EXPECT_QC(c.hr, "X-T1", "v1"); EXPECT_QC(c.hr, "X-T2", "v2"); EXPECT_QC(c.hr, "X-T3", "v3"); EXPECT_QC(c.hr, "X-T4", "a b");
    rh_close(&c);
}

TEST(rsp_hdr_value_inner_whitespace_kept) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-In: a  b   c\r\nX-Tab: a\tb\r\nX-Q: \"  q  \"\r\n" TAIL);
    EXPECT_QC(c.hr, "X-In", "a  b   c"); EXPECT_QC(c.hr, "X-Tab", "a\tb"); EXPECT_QC(c.hr, "X-Q", "\"  q  \"");
    rh_close(&c);
}

TEST(rsp_hdr_empty_values) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-E1:\r\nX-E2: \r\nX-E3:      \r\nX-E4:\t\r\nContent-Language:\r\n" TAIL);
    EXPECT_QC(c.hr, "X-E1", ""); EXPECT_QC(c.hr, "X-E2", ""); EXPECT_QC(c.hr, "X-E3", ""); EXPECT_QC(c.hr, "X-E4", "");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_LANGUAGE, "");
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    EXPECT_STR(raw, "HTTP/1.1 200 OK\r\nX-E1: \r\nX-E2: \r\nX-E3: \r\nX-E4: \r\nContent-Language: \r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    rh_close(&c);
}

/* whitespace between the name and the colon */
TEST(rsp_hdr_space_before_colon) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-Sp : sp\r\nX-Tb\t: tb\r\nContent-Type : text/x\r\n" TAIL);
    note_custom(c.hr, "X-Sp"); note_custom(c.hr, "X-Tb");
    const char *ct = rh_qa(c.hr, HTTP_QUERY_CONTENT_TYPE, NULL);
    t_note("\"Content-Type :\" -> level query %s (err %lu)", ct ? ct : "not found", rh_err);
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    t_note("raw: %s", raw ? rh_esc(raw, strlen(raw)) : "-");
    rh_close(&c);
}

/* ------------------------------------------------------------------ names */
TEST(rsp_hdr_name_casing_preserved_in_raw) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nx-MiXeD-CaSe: 1\r\nCONTENT-TYPE: text/x\r\nserver: lower\r\n" TAIL);
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nx-MiXeD-CaSe: 1\r\nCONTENT-TYPE: text/x\r\nserver: lower\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    EXPECT_QC(c.hr, "X-MIXED-CASE", "1"); EXPECT_QC(c.hr, "x-mixed-case", "1");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_TYPE, "text/x");
    EXPECT_Q(c.hr, HTTP_QUERY_SERVER, "lower");
    rh_close(&c);
}

TEST(rsp_hdr_name_charset) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX_Under: u\r\nX.Dot: d\r\nX!#$%&'*+^`|~: t\r\n1234: n\r\nX-\xe9: hi\r\n" TAIL);
    EXPECT_QC(c.hr, "X_Under", "u"); EXPECT_QC(c.hr, "X.Dot", "d"); EXPECT_QC(c.hr, "X!#$%&'*+^`|~", "t"); EXPECT_QC(c.hr, "1234", "n");
    note_custom(c.hr, "X-\xe9");
    rh_close(&c);
}

TEST(rsp_hdr_colon_in_value) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-Url: http://a:b@h:80/p?q=1:2\r\nX-Colon:: double\r\nX-Time: 12:34:56\r\n" TAIL);
    EXPECT_QC(c.hr, "X-Url", "http://a:b@h:80/p?q=1:2");
    EXPECT_QC(c.hr, "X-Time", "12:34:56");
    note_custom(c.hr, "X-Colon");
    rh_close(&c);
}

TEST(rsp_hdr_line_without_colon) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-Before: 1\r\nThis line has no colon\r\nX-After: 2\r\n" TAIL);
    EXPECT_QC(c.hr, "X-Before", "1");
    note_custom(c.hr, "X-After");
    note_custom(c.hr, "This line has no colon");
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    t_note("raw: %s", raw ? rh_esc(raw, strlen(raw)) : "-");
    rh_close(&c);
}

TEST(rsp_hdr_empty_name) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-Before: 1\r\n: nameless\r\nX-After: 2\r\n" TAIL);
    EXPECT_QC(c.hr, "X-Before", "1");
    note_custom(c.hr, "X-After");
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    t_note("raw: %s", raw ? rh_esc(raw, strlen(raw)) : "-");
    rh_close(&c);
}

/* ------------------------------------------------------------------ folding (obs-fold) */
TEST(rsp_hdr_folded_continuation) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nX-Fold: a\r\n b\r\n\tc\r\nX-Next: n\r\nServer: s1\r\n  s2\r\n" TAIL);
    note_custom(c.hr, "X-Fold");
    const char *sv = rh_qa(c.hr, HTTP_QUERY_SERVER, NULL);
    t_note("folded Server -> %s", sv ? rh_esc(sv, strlen(sv)) : "not found");
    EXPECT_QC(c.hr, "X-Next", "n");
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    t_note("raw: %s", raw ? rh_esc(raw, strlen(raw)) : "-");
    rh_close(&c);
}

TEST(rsp_hdr_fold_on_first_header_line) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\n X-Lead: indented\r\nX-B: b\r\n" TAIL);
    note_custom(c.hr, "X-Lead");
    EXPECT_QC(c.hr, "X-B", "b");
    const char *t = rh_qa(c.hr, HTTP_QUERY_STATUS_TEXT, NULL);
    t_note("status text with indented first header: %s", t ? rh_esc(t, strlen(t)) : "-");
    rh_close(&c);
}

/* ------------------------------------------------------------------ line endings */
TEST(rsp_hdr_lf_only_line_endings) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\nX-A: 1\nContent-Type: text/lf\nContent-Length: 2\nConnection: close\n\nok");
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "200");
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_TEXT, "OK");
    EXPECT_QC(c.hr, "X-A", "1");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_TYPE, "text/lf");
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nX-A: 1\r\nContent-Type: text/lf\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
    char b[8]; EXPECT_EQ(rh_body(&c, b, sizeof b), 2); EXPECT_STR(b, "ok");
    rh_close(&c);
}

TEST(rsp_hdr_mixed_line_endings) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\nX-A: 1\r\nX-B: 2\nContent-Length: 3\r\nConnection: close\n\r\nabc");
    EXPECT_QC(c.hr, "X-A", "1"); EXPECT_QC(c.hr, "X-B", "2");
    char b[8]; EXPECT_EQ(rh_body(&c, b, sizeof b), 3); EXPECT_STR(b, "abc");
    rh_close(&c);
}

TEST(rsp_hdr_bare_cr_and_nul_in_value) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-Cr: a\rb\r\nX-Nul: a\0b\r\nX-After: z\r\n" TAIL;
    rh_t c; if (!go(&c, resp, sizeof resp - 1)) return;
    note_custom(c.hr, "X-Cr"); note_custom(c.hr, "X-Nul"); note_custom(c.hr, "X-After");
    rh_close(&c);
}

/* ------------------------------------------------------------------ duplicates */
TEST(rsp_hdr_duplicate_known_header) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nContent-Type: text/one\r\nServer: s1\r\nContent-Type: text/two\r\nServer: s2\r\n" TAIL);
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_TYPE, "text/one");
    EXPECT_QC(c.hr, "Content-Type", "text/one");
    DWORD idx = 1;
    EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_CONTENT_TYPE, &idx), "text/two"); EXPECT_EQ(idx, 2);
    EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_SERVER | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL), "s1, s2");
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nContent-Type: text/one\r\nServer: s1\r\nContent-Type: text/two\r\nServer: s2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    rh_close(&c);
}

TEST(rsp_hdr_duplicate_content_length) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *raws[] = {
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde",
        "HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nConnection: close\r\n\r\nabc",
    };
    for (int i = 0; i < 3; i++) {
        rh_t c; if (!rh_raw(&c, "GET", raws[i], strlen(raws[i]))) return;
        DWORD n = 0; BOOL ok = c.sent ? rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n) : 0;
        char b[16] = ""; size_t bn = c.sent ? rh_body(&c, b, sizeof b) : 0;
        t_note("CL variant %d: sent=%d err=%lu CL|NUMBER=%s%lu body=%u \"%s\"", i, c.sent, c.err, ok ? "" : "fail:", ok ? n : rh_err, (unsigned)bn, b);
        if (i == 0) { CHECK(c.sent && ok && n == 3 && bn == 3); }
        rh_close(&c);
    }
}

/* ------------------------------------------------------------------ counts and sizes */
TEST(rsp_hdr_many_distinct_headers) {
    REQUIRE(U(HttpQueryInfoA));
    static char resp[200000]; size_t o = 0;
    o += (size_t)snprintf(resp + o, sizeof resp - o, "HTTP/1.1 200 OK\r\n");
    for (int i = 0; i < 1000; i++) o += (size_t)snprintf(resp + o, sizeof resp - o, "X-H%d: value-%d\r\n", i, i * 7);
    o += (size_t)snprintf(resp + o, sizeof resp - o, TAIL);
    rh_t c; if (!go(&c, resp, o)) return;
    int bad = 0;
    for (int i = 0; i < 1000; i++) {
        char nm[16], want[32]; snprintf(nm, sizeof nm, "X-H%d", i); snprintf(want, sizeof want, "value-%d", i * 7);
        const char *v = rh_qac(c.hr, nm, 0, NULL);
        if (!v || strcmp(v, want)) { if (bad++ < 5) t_check(0, __FILE__, __LINE__, nm, "got %s err=%lu", v ? v : "(fail)", rh_err); }
        else t_check(1, __FILE__, __LINE__, nm, NULL);
    }
    EXPECT_EQ(bad, 0);
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    CHECK(raw && rh_len == o - 0 && !strcmp(raw, resp));
    rh_close(&c);
}

TEST(rsp_hdr_repeated_header_count) {
    REQUIRE(U(HttpQueryInfoA));
    static char resp[100000]; size_t o = 0;
    o += (size_t)snprintf(resp + o, sizeof resp - o, "HTTP/1.1 200 OK\r\n");
    for (int i = 0; i < 300; i++) o += (size_t)snprintf(resp + o, sizeof resp - o, "X-Rep: %d\r\n", i);
    o += (size_t)snprintf(resp + o, sizeof resp - o, TAIL);
    rh_t c; if (!go(&c, resp, o)) return;
    DWORD idx = 0; int n = 0, inorder = 1;
    for (int guard = 0; guard < 400; guard++) {
        const char *v = rh_qac(c.hr, "X-Rep", 0, &idx);
        if (!v) { EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); break; }
        if (atoi(v) != n) inorder = 0;
        n++;
        if ((DWORD)n != idx) { inorder = 0; }
    }
    EXPECT_EQ(n, 300); CHECK(inorder); EXPECT_EQ(idx, 300);
    const char *co = rh_qac(c.hr, "X-Rep", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL);
    CHECK(co && !strncmp(co, "0, 1, 2, ", 9) && strstr(co, ", 298, 299") && !co[strlen(co)]);
    rh_close(&c);
}

TEST(rsp_hdr_long_values) {
    REQUIRE(U(HttpQueryInfoA));
    static const int lens[] = { 1023, 1024, 4096, 8191, 8192, 16384, 65535, 65536, 131072 };
    for (size_t k = 0; k < sizeof lens / sizeof lens[0]; k++) {
        static char resp[200000], val[140000];
        for (int i = 0; i < lens[k]; i++) val[i] = (char)('0' + (i % 10));
        val[lens[k]] = 0;
        int n = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\nX-Long: %s\r\nX-After: after\r\n" TAIL, val);
        rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return;
        CHECKF(c.sent, "len %d: send err=%lu %s", lens[k], c.err, t_inet_errname(c.err));
        if (c.sent) {
            const char *v = rh_qac(c.hr, "X-Long", 0, NULL);
            CHECKF(v && rh_len == (DWORD)lens[k] && !strcmp(v, val), "len %d: got len %lu err=%lu", lens[k], rh_len, rh_err);
            EXPECT_QC(c.hr, "X-After", "after");
        }
        rh_close(&c);
    }
}

/* total head sizes well past typical limits: recorded (WinINet buffers the whole head) */
TEST(rsp_hdr_huge_head_sizes) {
    REQUIRE(U(HttpQueryInfoA));
    static const int kb[] = { 256, 1024, 4096 };
    static char resp[4300 * 1024];
    for (size_t k = 0; k < 3; k++) {
        size_t o = 0; int lines = 0;
        o += (size_t)snprintf(resp + o, sizeof resp - o, "HTTP/1.1 200 OK\r\n");
        while (o < (size_t)kb[k] * 1024) o += (size_t)snprintf(resp + o, sizeof resp - o, "X-Fill%d: %0100d\r\n", lines++, 0);
        o += (size_t)snprintf(resp + o, sizeof resp - o, "X-Last: last\r\n" TAIL);
        rh_t c; if (!rh_raw(&c, "GET", resp, o)) return;
        const char *v = c.sent ? rh_qac(c.hr, "X-Last", 0, NULL) : NULL;
        t_note("head %d KB (%d lines): sent=%d err=%lu %s X-Last=%s", kb[k], lines, c.sent, c.err, t_inet_errname(c.err), v ? v : "-");
        if (k == 0) { CHECK(c.sent); EXPECT_STR(v, "last"); }
        rh_close(&c);
    }
}

/* ------------------------------------------------------------------ framing-related responses */
TEST(rsp_hdr_head_content_length_without_body) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nContent-Type: text/plain\r\n\r\n";
    srv_step st[] = { S_HEAD(), S_SENDN(resp, sizeof resp - 1), S_SLEEP(2500), S_CLOSE() };
    rh_t c; if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "HEAD", "/h", 0)) { rh_close(&c); return; }
    DWORD t0 = GetTickCount();
    CHECK(rh_send(&c, NULL, NULL, 0));
    DWORD t1 = GetTickCount();
    DWORD n; CHECK(rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n)); EXPECT_EQ(n, 1000);
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_TYPE, "text/plain");
    char b[16]; DWORD rd = 1;
    CHECK(U(InternetReadFile)(c.hr, b, sizeof b, &rd)); EXPECT_EQ(rd, 0);
    DWORD t2 = GetTickCount();
    t_note("HEAD: send %lu ms, read %lu ms (server holds the connection 2500 ms)", t1 - t0, t2 - t1);
    if (srv_wait_requests(c.s, 1, 2000)) EXPECT_STR(srv_req_method(c.s, 0), "HEAD");
    rh_close(&c);
}

TEST(rsp_hdr_head_chunked_without_body) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-H: 1\r\n\r\n";
    srv_step st[] = { S_HEAD(), S_SENDN(resp, sizeof resp - 1), S_SLEEP(2000), S_CLOSE() };
    rh_t c; if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "HEAD", "/h", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_Q(c.hr, HTTP_QUERY_TRANSFER_ENCODING, "chunked");
    EXPECT_QC(c.hr, "X-H", "1");
    char b[16]; DWORD rd = 1; CHECK(U(InternetReadFile)(c.hr, b, sizeof b, &rd)); EXPECT_EQ(rd, 0);
    rh_close(&c);
}

TEST(rsp_hdr_204_and_304_with_length) {
    REQUIRE(U(HttpQueryInfoA));
    static const char *raws[] = { "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nX-S: 204\r\n\r\n",
                                  "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\nX-S: 304\r\n\r\n" };
    for (int i = 0; i < 2; i++) {
        srv_step st[] = { S_HEAD(), S_SENDN(raws[i], strlen(raws[i])), S_SLEEP(2000), S_CLOSE() };
        rh_t c; if (!rh_start(&c, st, 4)) return;
        if (!rh_open(&c, "GET", "/n", 0)) { rh_close(&c); return; }
        CHECK(rh_send(&c, NULL, NULL, 0));
        DWORD n; CHECK(rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n)); EXPECT_EQ(n, 5);
        EXPECT_QC(c.hr, "X-S", i ? "304" : "204");
        DWORD t0 = GetTickCount();
        char b[16]; DWORD rd = 9; BOOL ok = U(InternetReadFile)(c.hr, b, sizeof b, &rd);
        t_note("%s: read ok=%d rd=%lu in %lu ms", i ? "304" : "204", ok, rd, GetTickCount() - t0);
        CHECK(ok); EXPECT_EQ(rd, 0);
        rh_close(&c);
    }
}

TEST(rsp_hdr_chunked_has_no_content_length) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n");
    EXPECT_Q(c.hr, HTTP_QUERY_TRANSFER_ENCODING, "chunked");
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_LENGTH, NULL);
    DWORD n; CHECK(!rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    char b[16]; EXPECT_EQ(rh_body(&c, b, sizeof b), 5); EXPECT_STR(b, "abcde");
    note_custom(c.hr, "X-Trailer");
    rh_close(&c);
}

TEST(rsp_hdr_content_headers_verbatim) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 206 Partial\r\nContent-Type: text/html; charset=\"utf-8\"\r\nContent-Encoding: identity\r\n"
           "Content-Language: en-US, de\r\nContent-Location: /alt/x.html\r\nContent-Disposition: attachment; filename=\"a b.txt\"\r\n"
           "Content-Range: bytes 2-5/10\r\nContent-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==\r\nContent-Base: http://base.invalid/\r\n"
           "Content-Transfer-Encoding: binary\r\nContent-Id: <id@x>\r\nContent-Description: desc text\r\nContent-Length: 4\r\nConnection: close\r\n\r\n2345");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_TYPE, "text/html; charset=\"utf-8\"");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_ENCODING, "identity");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_LANGUAGE, "en-US, de");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_LOCATION, "/alt/x.html");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_DISPOSITION, "attachment; filename=\"a b.txt\"");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_RANGE, "bytes 2-5/10");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_MD5, "Q2hlY2sgSW50ZWdyaXR5IQ==");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_BASE, "http://base.invalid/");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_TRANSFER_ENCODING, "binary");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_ID, "<id@x>");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_DESCRIPTION, "desc text");
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_LENGTH, "4");
    char b[8]; EXPECT_EQ(rh_body(&c, b, sizeof b), 4); EXPECT_STR(b, "2345");
    rh_close(&c);
}

/* Content-Encoding stays visible whether or not WinINet decodes (decoding is off by default) */
TEST(rsp_hdr_content_encoding_gzip_not_decoded_by_default) {
    REQUIRE(U(HttpQueryInfoA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Type: text/plain\r\n", srv_fox_gzip, srv_fox_gzip_len, SRV_R_CONN_CLOSE) };
    rh_t c; if (!rh_start(&c, st, 2)) return;
    if (!rh_open(&c, "GET", "/gz", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_Q(c.hr, HTTP_QUERY_CONTENT_ENCODING, "gzip");
    DWORD n; CHECK(rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n)); EXPECT_EQ(n, srv_fox_gzip_len);
    static char b[4096]; size_t bn = rh_body(&c, b, sizeof b);
    EXPECT_EQ(bn, srv_fox_gzip_len);
    CHECK((unsigned char)b[0] == 0x1f && (unsigned char)b[1] == 0x8b);
    rh_close(&c);
}

TEST(rsp_hdr_content_encoding_gzip_decoded) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(InternetSetOptionA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Type: text/plain\r\n", srv_fox_gzip, srv_fox_gzip_len, SRV_R_CONN_CLOSE) };
    rh_t c; if (!rh_start(&c, st, 2)) return;
    if (!rh_open(&c, "GET", "/gz", 0)) { rh_close(&c); return; }
    BOOL on = TRUE; CHECK(U(InternetSetOptionA)(c.hr, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    CHECK(rh_send(&c, NULL, NULL, 0));
    const char *ce = rh_qa(c.hr, HTTP_QUERY_CONTENT_ENCODING, NULL);
    const char *cl = rh_qa(c.hr, HTTP_QUERY_CONTENT_LENGTH, NULL);
    const char *ae = rh_qa(c.hr, HTTP_QUERY_ACCEPT_ENCODING | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
    t_note("decoding on: Content-Encoding=%s Content-Length=%s req Accept-Encoding=%s", ce ? ce : "(gone)", cl ? cl : "(gone)", ae ? ae : "(none)");
    static char b[4096]; size_t bn = rh_body(&c, b, sizeof b);
    EXPECT_EQ(bn, SRV_FOX_LEN);
    CHECK(!memcmp(b, srv_fox_text(), SRV_FOX_LEN));
    rh_close(&c);
}

TEST(rsp_hdr_set_cookie_kept_with_no_cookies) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; HttpOnly\r\nSet-Cookie2: c=3\r\n" TAIL);
    EXPECT_Q(c.hr, HTTP_QUERY_SET_COOKIE, "a=1; Path=/");
    DWORD idx = 1; EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_SET_COOKIE, &idx), "b=2; HttpOnly");
    EXPECT_Q(c.hr, HTTP_QUERY_SET_COOKIE2, "c=3");
    EXPECT_QA(c.hr, HTTP_QUERY_COOKIE | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);   /* NO_COOKIES: none sent */
    rh_close(&c);
}

/* the auth challenge headers on 401/407 come back verbatim with NO_AUTH */
TEST(rsp_hdr_auth_challenges_verbatim) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    GO(&c, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"r1\"\r\nWWW-Authenticate: Bearer error=\"x\"\r\n"
           "Proxy-Authenticate: Basic realm=\"p\"\r\n" TAIL);
    EXPECT_QA(c.hr, HTTP_QUERY_STATUS_CODE, "401");
    EXPECT_Q(c.hr, HTTP_QUERY_WWW_AUTHENTICATE, "Basic realm=\"r1\"");
    DWORD idx = 1; EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_WWW_AUTHENTICATE, &idx), "Bearer error=\"x\"");
    EXPECT_Q(c.hr, HTTP_QUERY_PROXY_AUTHENTICATE, "Basic realm=\"p\"");
    EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_WWW_AUTHENTICATE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL), "Basic realm=\"r1\", Bearer error=\"x\"");
    rh_close(&c);
}
