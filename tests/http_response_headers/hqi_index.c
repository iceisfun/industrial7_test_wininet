/* hqi_index.c - repeated headers: lpdwIndex enumeration and update, COALESCE_WITH_COMMA, request-side duplicates.
 * VM_TIMEOUT: 240
 *
 * [D] _FindHeader walks to occurrence *lpdwIndex (known headers: per-level list; custom: the custom list, matched by
 * hash + case-insensitive name) and, only on a successful copy, increments *lpdwIndex. A miss leaves it unchanged
 * (12150). COALESCE_WITH_COMMA joins every occurrence with ", " (_QueryCoalescedKnownHeader / _QueryCoalescedCustomHeader);
 * size protocol as for a single value (need = joined length + 1). [W10 laneg task 64] X-Multi: index 0 -> "a", then 1 -> "b", index 2 after.
 */
#include "rh.h"

static const char RESP_DUP[] =
    "HTTP/1.1 200 OK\r\n"
    "Set-Cookie: a=1\r\n"
    "X-Dup: one\r\n"
    "Vary: Accept\r\n"
    "Set-Cookie: b=2; Path=/\r\n"
    "x-dup: two\r\n"
    "Server: srv\r\n"
    "Set-Cookie: c=3\r\n"
    "X-DUP: three\r\n"
    "Vary: Cookie\r\n"
    "Content-Length: 0\r\nConnection: close\r\n\r\n";

#define OPEN_DUP(c) do { if (!RH_RAW((c), "GET", RESP_DUP)) return; RH_SENT_OR_FAIL(c); } while (0)

static void walk_level(HINTERNET h, DWORD lv, const char *const *want, int n, int wide, const char *file, int line) {
    DWORD idx = 0;
    for (int i = 0; i < n; i++) {
        DWORD before = idx;
        const char *v = wide ? rh_qw(h, lv, &idx) : rh_qa(h, lv, &idx);
        t_check(v && !strcmp(v, want[i]) && idx == before + 1, file, line, "walk", "%c level %lu step %d: got \"%s\" err=%lu idx %lu->%lu want \"%s\"",
                wide ? 'W' : 'A', lv, i, v ? v : "(fail)", rh_err, before, idx, want[i]);
    }
    const char *v = wide ? rh_qw(h, lv, &idx) : rh_qa(h, lv, &idx);
    t_check(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == (DWORD)n, file, line, "walk end", "%c level %lu: got %s err=%lu idx=%lu",
            wide ? 'W' : 'A', lv, v ? v : "(fail)", rh_err, idx);
}
static void walk_custom(HINTERNET h, const char *name, const char *const *want, int n, int wide, const char *file, int line) {
    DWORD idx = 0;
    for (int i = 0; i < n; i++) {
        DWORD before = idx;
        const char *v = wide ? rh_qwc(h, name, 0, &idx) : rh_qac(h, name, 0, &idx);
        t_check(v && !strcmp(v, want[i]) && idx == before + 1, file, line, "walk custom", "%c \"%s\" step %d: got \"%s\" err=%lu idx %lu->%lu want \"%s\"",
                wide ? 'W' : 'A', name, i, v ? v : "(fail)", rh_err, before, idx, want[i]);
    }
    const char *v = wide ? rh_qwc(h, name, 0, &idx) : rh_qac(h, name, 0, &idx);
    t_check(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == (DWORD)n, file, line, "walk custom end", "%c \"%s\": got %s err=%lu idx=%lu",
            wide ? 'W' : 'A', name, v ? v : "(fail)", rh_err, idx);
}
#define WALK(h, lv, arr, w)  walk_level((h), (lv), (arr), (int)(sizeof(arr) / sizeof((arr)[0])), (w), __FILE__, __LINE__)
#define WALKC(h, nm, arr, w) walk_custom((h), (nm), (arr), (int)(sizeof(arr) / sizeof((arr)[0])), (w), __FILE__, __LINE__)

static const char *const cookies[] = { "a=1", "b=2; Path=/", "c=3" };
static const char *const dups[] = { "one", "two", "three" };
static const char *const varys[] = { "Accept", "Cookie" };
static const char *const servers[] = { "srv" };

TEST(hqi_idx_walk_known_a) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_DUP(&c);
    WALK(c.hr, HTTP_QUERY_SET_COOKIE, cookies, 0);
    WALK(c.hr, HTTP_QUERY_VARY, varys, 0);
    WALK(c.hr, HTTP_QUERY_SERVER, servers, 0);
    rh_close(&c);
}

TEST(hqi_idx_walk_known_w) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_DUP(&c);
    WALK(c.hr, HTTP_QUERY_SET_COOKIE, cookies, 1);
    WALK(c.hr, HTTP_QUERY_VARY, varys, 1);
    WALK(c.hr, HTTP_QUERY_SERVER, servers, 1);
    rh_close(&c);
}

/* custom names of differing case are one header */
TEST(hqi_idx_walk_custom_mixed_case) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_DUP(&c);
    WALKC(c.hr, "X-Dup", dups, 0);
    WALKC(c.hr, "x-dup", dups, 0);
    WALKC(c.hr, "X-DUP:", dups, 0);
    WALKC(c.hr, "X-Dup", dups, 1);
    /* a known header through CUSTOM walks the same list as its level */
    WALKC(c.hr, "set-cookie", cookies, 0);
    WALKC(c.hr, "SET-COOKIE", cookies, 1);
    WALKC(c.hr, "Vary", varys, 0);
    rh_close(&c);
}

TEST(hqi_idx_direct_index_access) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_DUP(&c);
    for (DWORD i = 0; i < 3; i++) {
        DWORD idx = i;
        EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_SET_COOKIE, &idx), cookies[i]); EXPECT_EQ(idx, i + 1);
        idx = i;
        EXPECT_STR(rh_qac(c.hr, "X-Dup", 0, &idx), dups[i]); EXPECT_EQ(idx, i + 1);
    }
    static const DWORD past[] = { 3, 4, 100, 0x7FFFFFFF, 0xFFFFFFFF };
    for (size_t k = 0; k < 5; k++) {
        DWORD idx = past[k];
        CHECK(!rh_qa(c.hr, HTTP_QUERY_SET_COOKIE, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(idx, past[k]);
        idx = past[k];
        CHECK(!rh_qac(c.hr, "X-Dup", 0, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(idx, past[k]);
    }
    DWORD idx = 2;   /* Server occurs once */
    CHECK(!rh_qa(c.hr, HTTP_QUERY_SERVER, &idx)); EXPECT_EQ(idx, 2);
    idx = 1; CHECK(!rh_qa(c.hr, HTTP_QUERY_SERVER, &idx)); EXPECT_EQ(idx, 1);
    idx = 0; EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_SERVER, &idx), "srv"); EXPECT_EQ(idx, 1);
    rh_close(&c);
}

TEST(hqi_idx_null_index_pointer_is_first) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_DUP(&c);
    for (int i = 0; i < 3; i++) {
        EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_SET_COOKIE, NULL), "a=1");
        EXPECT_STR(rh_qac(c.hr, "X-Dup", 0, NULL), "one");
    }
    rh_close(&c);
}

/* the index is not advanced by a 122, so the caller can grow the buffer and retry */
TEST(hqi_idx_unchanged_on_insufficient_buffer) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; OPEN_DUP(&c);
    char b[64]; DWORD idx = 1;
    CHECK(!rh_callA(c.hr, HTTP_QUERY_SET_COOKIE, b, 5, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 12); EXPECT_EQ(idx, 1);
    CHECK(rh_callA(c.hr, HTTP_QUERY_SET_COOKIE, b, rh_len, &idx)); EXPECT_STR(b, "b=2; Path=/"); EXPECT_EQ(idx, 2);
    DWORD l = 0; idx = 2;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_SET_COOKIE, NULL, &l, &idx)); EXPECT_EQ(l, 4); EXPECT_EQ(idx, 2);
    /* binary forms advance the index too */
    static const char resp2[] = "HTTP/1.1 200 OK\r\nX-N: 1\r\nX-N: 2\r\nX-N: 3\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c2; if (!RH_RAW(&c2, "GET", resp2)) { rh_close(&c); return; }
    if (c2.sent) {
        for (DWORD i = 0; i < 3; i++) {
            char nb[16]; strcpy(nb, "X-N"); DWORD ix = i;
            CHECK(rh_callA(c2.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, nb, sizeof nb, &ix)); EXPECT_EQ(*(DWORD *)nb, i + 1); EXPECT_EQ(ix, i + 1);
            strcpy(nb, "X-N"); ix = i;
            CHECK(!rh_callA(c2.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, nb, 3, &ix)); EXPECT_EQ(rh_len, 4); EXPECT_EQ(ix, i);
        }
    }
    rh_close(&c2);
    rh_close(&c);
}

TEST(hqi_idx_interleaved_order_preserved) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-I: 1\r\nContent-Type: a/b\r\nX-I: 2\r\nServer: s\r\nX-Other: o\r\nX-I: 3\r\nX-I: 4\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    static const char *const xi[] = { "1", "2", "3", "4" };
    WALKC(c.hr, "X-I", xi, 0);
    WALKC(c.hr, "X-I", xi, 1);
    rh_close(&c);
}

/* ------------------------------------------------------------------ COALESCE_WITH_COMMA */
TEST(hqi_idx_coalesce_known_and_custom) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_DUP(&c);
    EXPECT_Q(c.hr, HTTP_QUERY_SET_COOKIE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "a=1, b=2; Path=/, c=3");
    EXPECT_Q(c.hr, HTTP_QUERY_VARY | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "Accept, Cookie");
    EXPECT_Q(c.hr, HTTP_QUERY_SERVER | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, "srv");
    EXPECT_QERR2(c.hr, HTTP_QUERY_LOCATION | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, ERROR_HTTP_HEADER_NOT_FOUND);
    const char *v = rh_qac(c.hr, "X-Dup", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); EXPECT_STR(v, "one, two, three"); EXPECT_EQ(rh_len, 15);
    v = rh_qwc(c.hr, "x-dup", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); EXPECT_STR(v, "one, two, three"); EXPECT_EQ(rh_len, 30);
    v = rh_qac(c.hr, "Set-Cookie", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); EXPECT_STR(v, "a=1, b=2; Path=/, c=3");
    v = rh_qac(c.hr, "X-Nope", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL); CHECK(!v); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    /* index 0 is accepted and left alone */
    DWORD idx = 0;
    v = rh_qa(c.hr, HTTP_QUERY_SET_COOKIE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, &idx); CHECK(v != NULL); EXPECT_EQ(idx, 0);
    rh_close(&c);
}

TEST(hqi_idx_coalesce_buffer_sizes) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; OPEN_DUP(&c);
    const char *joined = "a=1, b=2; Path=/, c=3"; DWORD n = (DWORD)strlen(joined);
    char b[128]; WCHAR w[128];
    static const int d[] = { -100, -2, -1, 0, 1, 5 };
    for (size_t k = 0; k < 6; k++) {
        int sz = (int)n + 1 + d[k]; if (sz < 0) sz = 0;
        memset(b, 'Z', sizeof b);
        rh_callA(c.hr, HTTP_QUERY_SET_COOKIE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, (DWORD)sz, NULL);
        if (sz >= (int)n + 1) CHECKF(rh_ok && rh_len == n && !strcmp(b, joined), "A known size %d: ok=%d err=%lu len=%lu", sz, rh_ok, rh_err, rh_len);
        else CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == n + 1, "A known size %d: ok=%d err=%lu len=%lu", sz, rh_ok, rh_err, rh_len);
        rh_callW(c.hr, HTTP_QUERY_SET_COOKIE | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, w, (DWORD)(2 * sz), NULL);
        if (sz >= (int)n + 1) CHECKF(rh_ok && rh_len == 2 * n, "W known bytes %d: ok=%d err=%lu len=%lu", 2 * sz, rh_ok, rh_err, rh_len);
        else CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == 2 * (n + 1), "W known bytes %d: ok=%d err=%lu len=%lu", 2 * sz, rh_ok, rh_err, rh_len);
    }
    const char *cj = "one, two, three"; DWORD cn = (DWORD)strlen(cj);
    for (size_t k = 0; k < 6; k++) {
        int sz = (int)cn + 1 + d[k]; if (sz < 0) sz = 0;
        strcpy(b, "X-Dup");
        rh_callA(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, (DWORD)sz, NULL);
        if (sz >= (int)cn + 1) CHECKF(rh_ok && rh_len == cn && !strcmp(b, cj), "A custom size %d: ok=%d err=%lu len=%lu", sz, rh_ok, rh_err, rh_len);
        else CHECKF(!rh_ok && rh_err == ERROR_INSUFFICIENT_BUFFER && rh_len == cn + 1, "A custom size %d: ok=%d err=%lu len=%lu", sz, rh_ok, rh_err, rh_len);
    }
    DWORD l = 0;
    CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_VARY | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 15);
    rh_close(&c);
}

TEST(hqi_idx_coalesce_with_empty_values) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-E:\r\nX-E: b\r\nX-E:\r\nVia:\r\nVia:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    EXPECT_STR(rh_qac(c.hr, "X-E", HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL), ", b, ");
    EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_VIA | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, NULL), ", ");
    static const char *const xe[] = { "", "b", "" };
    WALKC(c.hr, "X-E", xe, 0);
    rh_close(&c);
}

/* ------------------------------------------------------------------ request side duplicates */
TEST(hqi_idx_request_header_duplicates) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpAddRequestHeadersA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!rh_raw_nosend(&c, "GET", resp, sizeof resp - 1)) return;
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "X-R: 1\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "X-R: 2\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "x-r: 3\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    /* before send: the request headers are queryable and indexable */
    static const char *const xr[] = { "1", "2", "3" };
    DWORD idx = 0;
    for (int i = 0; i < 3; i++) {
        const char *v = rh_qac(c.hr, "X-R", HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx);
        CHECKF(v && !strcmp(v, xr[i]) && idx == (DWORD)i + 1, "pre-send %d: %s err=%lu idx=%lu", i, v ? v : "(fail)", rh_err, idx);
    }
    CHECK(!rh_qac(c.hr, "X-R", HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(idx, 3);
    /* REQUEST_HEADERS + COALESCE_WITH_COMMA is an illegal pair */
    EXPECT_QCERR(c.hr, "X-R", HTTP_QUERY_FLAG_REQUEST_HEADERS | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, ERROR_INVALID_PARAMETER);
    CHECK(rh_send(&c, NULL, NULL, 0));
    if (srv_wait_requests(c.s, 1, 3000)) {
        EXPECT_EQ(srv_req_header_occurrences(c.s, 0, "X-R"), 3);
        idx = 0;
        for (int i = 0; i < 3; i++) EXPECT_STR(rh_qac(c.hr, "X-R", HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx), xr[i]);
    }
    rh_close(&c);
}

TEST(hqi_idx_request_header_coalesced_by_add) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpAddRequestHeadersA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!rh_raw_nosend(&c, "GET", resp, sizeof resp - 1)) return;
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "X-C: 1\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "X-C: 2\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "X-S: a\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpAddRequestHeadersA)(c.hr, "X-S: b\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON));
    EXPECT_STR(rh_qac(c.hr, "X-C", HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL), "1, 2");
    EXPECT_STR(rh_qac(c.hr, "X-S", HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL), "a; b");
    DWORD idx = 1; CHECK(!rh_qac(c.hr, "X-C", HTTP_QUERY_FLAG_REQUEST_HEADERS, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    CHECK(rh_send(&c, NULL, NULL, 0));
    if (srv_wait_requests(c.s, 1, 3000)) { EXPECT_STR(srv_req_header(c.s, 0, "X-C"), "1, 2"); EXPECT_STR(srv_req_header(c.s, 0, "X-S"), "a; b"); }
    rh_close(&c);
}

/* a fresh request handle on the same connection has its own response headers and index space */
TEST(hqi_idx_second_request_on_keepalive) {
    REQUIRE(U(HttpQueryInfoA));
    srv_step st[] = { S_HEAD(), S_REPLY(200, "X-Seq: first\r\nX-Seq: first-b\r\n", "1"), S_HEAD(), S_REPLY(201, "X-Seq: second\r\n", "22"), S_CLOSE() };
    rh_t c; if (!rh_start(&c, st, 5)) return;
    if (!rh_open(&c, "GET", "/1", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0));
    static const char *const one[] = { "first", "first-b" };
    WALKC(c.hr, "X-Seq", one, 0);
    char b[8]; rh_body(&c, b, sizeof b);
    HINTERNET hr2 = U(HttpOpenRequestA)(c.hc, "GET", "/2", NULL, NULL, NULL, RH_FLAGS, 0);
    CHECK(hr2 && U(HttpSendRequestA)(hr2, NULL, 0, NULL, 0));
    if (hr2) {
        static const char *const two[] = { "second" };
        WALKC(hr2, "X-Seq", two, 0);
        EXPECT_QA(hr2, HTTP_QUERY_STATUS_CODE, "201");
        WALKC(c.hr, "X-Seq", one, 0);   /* the first handle still answers from its own response */
        rh_body(&c, b, sizeof b);
        U(InternetCloseHandle)(hr2);
    }
    if (srv_req_count(c.s) == 2) EXPECT_EQ(srv_req_conn(c.s, 0), srv_req_conn(c.s, 1));
    rh_close(&c);
}
