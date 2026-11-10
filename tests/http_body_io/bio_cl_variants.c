/* bio_cl_variants.c - Content-Length header spellings and conflicts, LF-only heads, Content-Length on
 * responses that also carry Connection: close, and how much of the body each one delivers.
 * Each case runs on its own server and connection (the server closes after the body + 300 ms).
 * Cases marked "VM boot 2" were observed on the Win10 VM and are asserted; the CL query results stay notes.
 * VM_TIMEOUT: 300 */
#include "bio.h"
#include <stdlib.h>

typedef struct {
    const char *name;
    const char *resp;      /* full raw response (server closes 300 ms after sending it) */
    int want_send_ok;      /* 1: HttpSendRequest must succeed */
    int want_n;            /* expected body length, -1: only noted */
    const char *want;      /* expected body prefix (want_n bytes), NULL: not checked */
} clv_case;

static const clv_case clv[] = {
    { "plain CL 5",            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL leading zeros",      "HTTP/1.1 200 OK\r\nContent-Length: 0005\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL extra spaces",       "HTTP/1.1 200 OK\r\nContent-Length:    5   \r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL no space",           "HTTP/1.1 200 OK\r\nContent-Length:5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL tab",                "HTTP/1.1 200 OK\r\nContent-Length:\t5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL lower-case name",    "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL upper-case name",    "HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "CL duplicate equal",    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "CL duplicate differ",   "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 7\r\n\r\nhelloXXXX", 1, 3, "hel" },  /* VM boot 2 */
    { "CL list 5, 5",          "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "CL non-numeric",        "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nhelloXXXX", 1, 0, "" },  /* VM boot 2 */
    { "CL negative",           "HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\nhelloXXXX", 1, 0, "" },  /* VM boot 2 */
    { "CL trailing garbage",   "HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "CL empty value",        "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\nhelloXXXX", 1, 0, "" },  /* VM boot 2 */
    { "CL 2^32+5",             "HTTP/1.1 200 OK\r\nContent-Length: 4294967301\r\n\r\nhelloXXXX", 1, 9, "helloXXXX" },  /* VM boot 2 */
    { "CL huge digits",        "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\nhelloXXXX", 0, -1, NULL },  /* VM boot 2: 12153 */
    { "CL + Connection close", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "LF-only head",          "HTTP/1.1 200 OK\nContent-Length: 5\n\nhelloXXXX", 1, 5, "hello" },
    { "mixed CRLF/LF head",    "HTTP/1.1 200 OK\r\nContent-Length: 5\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "HTTP/1.0 CL",           "HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "HTTP/1.0 no length",    "HTTP/1.0 200 OK\r\n\r\nhelloXXXX", 1, 9, "helloXXXX" },
    { "no reason phrase",      "HTTP/1.1 200\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },
    { "folded header before CL", "HTTP/1.1 200 OK\r\nX-Fold: a\r\n b\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "TE identity + CL",      "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "TE gzip, chunked (no decoding)", "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 1, 15, "5\r\nhello\r\n0\r\n\r\n" },  /* VM boot 2 */
    { "TE unknown",            "HTTP/1.1 200 OK\r\nTransfer-Encoding: foo\r\n\r\nhelloXXXX", 1, 9, "helloXXXX" },  /* VM boot 2 */
    { "CL 0 with body bytes",  "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nhelloXXXX", 1, 0, "" },
    { "204 with body bytes",   "HTTP/1.1 204 No Content\r\n\r\nhelloXXXX", 1, 0, "" },  /* VM boot 2 */
    { "304 with CL 5",         "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },  /* VM boot 2 */
    { "1xx 102 then 200",      "HTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloXXXX", 1, 5, "hello" },
};

static void clv_run(const clv_case *c) {
    srv_step st[] = { S_HEAD(), { SRV_SEND, c->resp, strlen(c->resp) }, S_SLEEP(300), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/v", 0, NULL, &ok, &err);
    if (!ok) {
        t_note("[%s] send failed err=%lu %s", c->name, err, t_inet_errname(err));
        CHECKF(!c->want_send_ok, "[%s] send failed err=%lu", c->name, err);
        bio_h(hr); bio_close(&e); return;
    }
    DWORD st_code = bio_status(hr);
    DWORD cl = 0, l = sizeof cl;
    BOOL clok = U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL);
    DWORD clerr = clok ? 0 : GetLastError();
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("[%s] status=%lu CL query ok=%d val=%lu err=%lu | read ok=%d err=%lu n=%u '%.*s'", c->name, st_code, clok, cl, clerr,
           r.ok, r.err, (unsigned)n, (int)(n < 20 ? n : 20), b);
    if (c->want_n >= 0) {
        CHECKF(r.ok, "[%s] read failed err=%lu", c->name, r.err);
        CHECKF(n == (size_t)c->want_n, "[%s] n=%u want %d", c->name, (unsigned)n, c->want_n);
        if (c->want && n == (size_t)c->want_n) CHECKF(!memcmp(b, c->want, n), "[%s] body mismatch", c->name);
    }
    CHECK(r.over == 0);
    const char *eoh = strstr(c->resp, "\r\n\r\n"); const char *eol = strstr(c->resp, "\n\n");
    size_t sent_body = strlen(c->resp) - (eoh ? (size_t)(eoh + 4 - c->resp) : eol ? (size_t)(eol + 2 - c->resp) : 0);
    CHECKF(n <= sent_body, "[%s] %u bytes, server sent %u body bytes", c->name, (unsigned)n, (unsigned)sent_body);   /* never more than sent */
    bio_h(hr); bio_close(&e);
}

#define CLV(i, nm) TEST(bio_clv_##nm) { REQUIRE(U(InternetReadFile)); clv_run(&clv[i]); }
CLV(0, plain) CLV(1, leading_zeros) CLV(2, extra_spaces) CLV(3, no_space) CLV(4, tab) CLV(5, lower_name) CLV(6, upper_name)
CLV(7, dup_equal) CLV(8, dup_differ) CLV(9, list_equal) CLV(10, non_numeric) CLV(11, negative) CLV(12, trailing_garbage)
CLV(13, empty_value) CLV(14, over_4g) CLV(15, huge_digits) CLV(16, with_conn_close) CLV(17, lf_only_head) CLV(18, mixed_eol_head)
CLV(19, http10_cl) CLV(20, http10_no_length) CLV(21, no_reason) CLV(22, folded_header) CLV(23, te_identity) CLV(24, te_gzip_chunked)
CLV(25, te_unknown) CLV(26, cl0_with_bytes) CLV(27, s204_with_bytes) CLV(28, s304_with_cl) CLV(29, s102_then_200)

_Static_assert(sizeof clv / sizeof clv[0] == 30, "one TEST per clv case");
