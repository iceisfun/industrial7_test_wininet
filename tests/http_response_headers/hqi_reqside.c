/* hqi_reqside.c - HTTP_QUERY_FLAG_REQUEST_HEADERS: the request header store as seen through HttpQueryInfoA/W, before
 * and after HttpSendRequest, after HttpAddRequestHeaders with every flag, numbers and dates on request headers,
 * the request RAW_HEADERS (NUL) layout against the wire, and the separation of request and response stores.
 * VM_TIMEOUT: 180
 *
 * [D] HttpQueryInfoA: with FLAG_REQUEST_HEADERS (0x80000000) the lookup goes to the request CHttpHeaders store
 * instead of the response one; the same _FindHeader / _CopyValueToBuffer protocol applies; the per-level mask still
 * applies (REQ is bit 31 of every mask except STATUS_TEXT, Refresh, Ms-Echo-Request and level 19/20).
 */
#include "rh.h"

static const char RESP_OK[] = "HTTP/1.1 200 OK\r\nServer: real\r\nX-Resp: r\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
#define REQF HTTP_QUERY_FLAG_REQUEST_HEADERS

static const char *rq(HINTERNET h, const char *name, DWORD *idx) { return rh_qac(h, name, REQF, idx); }
#define EXPECT_RQ(h, name, want) do { const char *v_ = rq((h), (name), NULL); const char *w_ = (want); \
    if (w_) CHECKF(v_ && !strcmp(v_, w_), "request %s: got \"%s\" err=%lu want \"%s\"", (name), v_ ? rh_esc(v_, strlen(v_)) : "(fail)", rh_err, w_); \
    else CHECKF(!v_ && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "request %s: want 12150, got \"%s\" err=%lu", (name), v_ ? v_ : "(fail)", rh_err); } while (0)

static BOOL add(HINTERNET h, const char *hdr, DWORD flags, DWORD *err) {
    SetLastError(0);
    BOOL ok = U(HttpAddRequestHeadersA)(h, hdr, (DWORD)-1, flags);
    *err = ok ? 0 : GetLastError();
    return ok;
}

static void walk_req(HINTERNET h, const char *name, const char *const *want, int n, const char *file, int line) {
    DWORD idx = 0;
    for (int i = 0; i < n; i++) {
        const char *v = rq(h, name, &idx);
        t_check(v && !strcmp(v, want[i]) && idx == (DWORD)i + 1, file, line, "request walk", "%s[%d]: \"%s\" err=%lu idx=%lu want \"%s\"", name, i,
                v ? v : "(fail)", rh_err, idx, want[i]);
    }
    const char *v = rq(h, name, &idx);
    t_check(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND && idx == (DWORD)n, file, line, "request walk end", "%s: %s err=%lu idx=%lu", name, v ? v : "(fail)", rh_err, idx);
}
#define WALKR(h, nm, ...) do { static const char *const w_[] = { __VA_ARGS__ }; walk_req((h), (nm), w_, (int)(sizeof w_ / sizeof w_[0]), __FILE__, __LINE__); } while (0)
#define WALKR0(h, nm) walk_req((h), (nm), NULL, 0, __FILE__, __LINE__)

TEST(hqi_req_added_header_visible_before_send) {
    REQUIRE(U(HttpAddRequestHeadersA)); REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_OK, sizeof RESP_OK - 1)) return;
    DWORD e;
    CHECK(add(c.hr, "X-Q: 1\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    EXPECT_RQ(c.hr, "X-Q", "1");
    EXPECT_RQ(c.hr, "x-q", "1");
    EXPECT_QC(c.hr, "X-Q", NULL);   /* not in the response store */
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF | REQF, NULL);
    /* [W10] before the send the request store holds only the request line and what the caller added:
     * Host and User-Agent are added when the request is sent */
    CHECKF(raw && !strcmp(raw, "GET /r HTTP/1.1\r\nX-Q: 1\r\n\r\n"), "request raw before send: %s", raw ? rh_esc(raw, strlen(raw)) : "(fail)");
    EXPECT_QERR(c.hr, HTTP_QUERY_HOST | REQF, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QERR(c.hr, HTTP_QUERY_USER_AGENT | REQF, ERROR_HTTP_HEADER_NOT_FOUND);
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_RQ(c.hr, "X-Q", "1");
    EXPECT_QC(c.hr, "X-Resp", "r");
    rh_close(&c);
}

TEST(hqi_req_add_flag_matrix) {
    REQUIRE(U(HttpAddRequestHeadersA)); REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_OK, sizeof RESP_OK - 1)) return;
    DWORD e;
    CHECK(add(c.hr, "X-Q: 1\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    CHECK(add(c.hr, "X-Q: 2\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    WALKR(c.hr, "X-Q", "1", "2");
    /* ADD_IF_NEW on an existing name: 12155 ERROR_HTTP_HEADER_ALREADY_EXISTS [K] */
    BOOL ok = add(c.hr, "X-Q: 3\r\n", HTTP_ADDREQ_FLAG_ADD_IF_NEW, &e);
    CHECKF(!ok && e == ERROR_HTTP_HEADER_ALREADY_EXISTS, "ADD_IF_NEW existing: ok=%d err=%lu", ok, e);
    WALKR(c.hr, "X-Q", "1", "2");
    CHECK(add(c.hr, "X-New: n\r\n", HTTP_ADDREQ_FLAG_ADD_IF_NEW, &e));
    EXPECT_RQ(c.hr, "X-New", "n");
    /* REPLACE: first occurrence */
    ok = add(c.hr, "X-Q: 9\r\n", HTTP_ADDREQ_FLAG_REPLACE, &e);
    CHECKF(ok, "REPLACE err=%lu", e);
    /* [W10] REPLACE removes the first occurrence and appends the new value at the end */
    WALKR(c.hr, "X-Q", "2", "9");
    /* REPLACE with an empty value removes [K] */
    CHECK(add(c.hr, "X-New:\r\n", HTTP_ADDREQ_FLAG_REPLACE, &e));
    EXPECT_RQ(c.hr, "X-New", NULL);
    /* REPLACE of an absent name */
    /* [W10] REPLACE of an absent name adds it */
    ok = add(c.hr, "X-Absent: a\r\n", HTTP_ADDREQ_FLAG_REPLACE, &e);
    CHECKF(ok, "REPLACE absent err=%lu", e);
    EXPECT_RQ(c.hr, "X-Absent", "a");
    ok = add(c.hr, "X-Absent2: a\r\n", HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD, &e);
    CHECKF(ok, "REPLACE|ADD absent err=%lu", e);
    EXPECT_RQ(c.hr, "X-Absent2", "a");
    /* coalescing */
    CHECK(add(c.hr, "X-C: a\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    CHECK(add(c.hr, "X-C: b\r\n", HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA, &e));
    EXPECT_RQ(c.hr, "X-C", "a, b");
    CHECK(add(c.hr, "X-S: a\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    CHECK(add(c.hr, "X-S: b\r\n", HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON, &e));
    EXPECT_RQ(c.hr, "X-S", "a; b");
    /* after sending, the query matches what the server received */
    CHECK(rh_send(&c, NULL, NULL, 0));
    if (srv_wait_requests(c.s, 1, 2000)) {
        EXPECT_STR(srv_req_header(c.s, 0, "X-C"), "a, b");
        EXPECT_STR(srv_req_header(c.s, 0, "X-S"), "a; b");
        EXPECT_EQ(srv_req_header_occurrences(c.s, 0, "X-Q"), 2);
        EXPECT_EQ(srv_req_header_occurrences(c.s, 0, "X-New"), 0);
        const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF | REQF, NULL);
        size_t hn = 0; const char *wire = srv_req_head_raw(c.s, 0, &hn);
        CHECKF(raw && wire && strlen(raw) == hn && !memcmp(raw, wire, hn), "raw|REQ == wire\n got %s\nwire %s", raw ? rh_esc(raw, strlen(raw)) : "(fail)", wire ? rh_esc(wire, hn) : "-");
    }
    rh_close(&c);
}

TEST(hqi_req_numbers_and_dates) {
    REQUIRE(U(HttpAddRequestHeadersA)); REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_OK, sizeof RESP_OK - 1)) return;
    DWORD e;
    CHECK(add(c.hr, "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nX-N: 77\r\nMax-Forwards: 5\r\nX-Big: 5000000000\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    SYSTEMTIME t; CHECK(rh_qtime(c.hr, HTTP_QUERY_IF_MODIFIED_SINCE | REQF, &t));
    CHECKF(t.wYear == 1994 && t.wMonth == 11 && t.wDay == 6 && t.wHour == 8 && t.wMinute == 49 && t.wSecond == 37 && t.wDayOfWeek == 0,
           "%u-%u-%u %u:%u:%u dow %u", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wDayOfWeek);
    EXPECT_EQ(rh_len, sizeof(SYSTEMTIME));
    /* CUSTOM bypasses the masks [D] */
    { char b[64]; lstrcpyA(b, "X-N"); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF | HTTP_QUERY_FLAG_NUMBER, b, sizeof b, NULL)); EXPECT_EQ(*(DWORD *)b, 77); EXPECT_EQ(rh_len, 4); }
    { char b[64]; lstrcpyA(b, "Max-Forwards"); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF | HTTP_QUERY_FLAG_NUMBER, b, sizeof b, NULL)); EXPECT_EQ(*(DWORD *)b, 5); }
    { char b[64]; lstrcpyA(b, "X-Big"); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF | HTTP_QUERY_FLAG_NUMBER64, b, sizeof b, NULL)); EXPECT_EQ(*(ULONGLONG *)b, 5000000000ull); EXPECT_EQ(rh_len, 8); }
    { char b[64]; lstrcpyA(b, "X-Big"); CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF | HTTP_QUERY_FLAG_NUMBER, b, sizeof b, NULL)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_HEADER); }
    /* level masks: Max-Forwards takes only REQ -> NUMBER is rejected [D GlobalKnownHeaders] */
    EXPECT_QERR(c.hr, HTTP_QUERY_MAX_FORWARDS | REQF | HTTP_QUERY_FLAG_NUMBER, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QA(c.hr, HTTP_QUERY_MAX_FORWARDS | REQF, "5");
    EXPECT_QA(c.hr, HTTP_QUERY_IF_MODIFIED_SINCE | REQF, "Sun, 06 Nov 1994 08:49:37 GMT");
    rh_close(&c);
}

TEST(hqi_req_post_content_length) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_SENDN(RESP_OK, sizeof RESP_OK - 1), S_CLOSE() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "POST", "/post", 0)) { rh_close(&c); return; }
    EXPECT_QERR(c.hr, HTTP_QUERY_CONTENT_LENGTH | REQF, ERROR_HTTP_HEADER_NOT_FOUND);
    CHECK(rh_send(&c, "Content-Type: text/plain\r\n", "hello world", 11));
    DWORD n = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH | REQF, &n)); EXPECT_EQ(n, 11);
    ULONGLONG n64 = 0; CHECK(rh_qnum64(c.hr, HTTP_QUERY_CONTENT_LENGTH | REQF, &n64)); EXPECT_EQ(n64, 11);
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_LENGTH | REQF, "11");
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_TYPE | REQF, "text/plain");
    EXPECT_QA(c.hr, HTTP_QUERY_CONTENT_LENGTH, "0");   /* the response's own */
    EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD, "POST");
    rh_close(&c);
}

/* RAW_HEADERS | REQ: NUL-separated lines of the request head as it went on the wire */
TEST(hqi_req_raw_nul_layout_matches_wire) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_OK, sizeof RESP_OK - 1)) return;
    CHECK(rh_send(&c, "X-One: 1\r\nX-Two: 2\r\n", NULL, 0)); RH_SENT_OR_FAIL(&c);
    if (!srv_wait_requests(c.s, 1, 2000)) { CHECK(0); rh_close(&c); return; }
    size_t hn = 0; const char *wire = srv_req_head_raw(c.s, 0, &hn);
    char want[4096]; size_t wn = 0;
    for (size_t i = 0; wire && i + 1 < hn && wn < sizeof want - 2; i++) {
        if (wire[i] == '\r' && wire[i + 1] == '\n') { want[wn++] = 0; i++; if (i + 2 < hn && wire[i + 1] == '\r' && wire[i + 2] == '\n') break; }
        else want[wn++] = wire[i];
    }
    char a[4096]; memset(a, 'Z', sizeof a);
    BOOL ok = rh_callA(c.hr, HTTP_QUERY_RAW_HEADERS | REQF, a, sizeof a, NULL);
    CHECKF(ok && rh_len == wn && !memcmp(a, want, wn) && a[wn] == 0, "ok=%d len=%lu want %u\n got %s\nwant %s", ok, rh_len, (unsigned)wn, rh_esc(a, rh_len + 1), rh_esc(want, wn));
    WCHAR w[4096];
    ok = rh_callW(c.hr, HTTP_QUERY_RAW_HEADERS | REQF, w, sizeof w, NULL);
    CHECKF(ok && rh_len == 2 * wn, "W ok=%d len=%lu", ok, rh_len);
    int same = ok; for (size_t i = 0; same && i < wn; i++) same = w[i] == (WCHAR)(unsigned char)want[i];
    CHECK(same);
    rh_close(&c);
}

/* request and response stores are separate even for the same name */
TEST(hqi_req_and_response_stores_separate) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_OK, sizeof RESP_OK - 1)) return;
    CHECK(rh_send(&c, "Server: fake\r\nX-Resp: from-request\r\n", NULL, 0)); RH_SENT_OR_FAIL(&c);
    EXPECT_Q(c.hr, HTTP_QUERY_SERVER, "real");
    EXPECT_QA(c.hr, HTTP_QUERY_SERVER | REQF, "fake");
    EXPECT_QW(c.hr, HTTP_QUERY_SERVER | REQF, "fake");
    EXPECT_QC(c.hr, "X-Resp", "r");
    EXPECT_RQ(c.hr, "X-Resp", "from-request");
    EXPECT_RQ(c.hr, "Content-Length", NULL);   /* a GET without a body sends none [W10 http_request_wire] */
    rh_close(&c);
}

/* Host and User-Agent after sending: exactly what went on the wire */
TEST(hqi_req_host_and_user_agent_after_send) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!RH_RAW(&c, "GET", RESP_OK)) return; RH_SENT_OR_FAIL(&c);
    char host[64]; snprintf(host, sizeof host, "127.0.0.1:%u", srv_port(c.s));
    EXPECT_QA(c.hr, HTTP_QUERY_HOST | REQF, host);
    EXPECT_QW(c.hr, HTTP_QUERY_HOST | REQF, host);
    EXPECT_QA(c.hr, HTTP_QUERY_USER_AGENT | REQF, "rh-agent/1.0");
    EXPECT_QA(c.hr, HTTP_QUERY_HOST, NULL);           /* the response has no Host */
    if (srv_wait_requests(c.s, 1, 2000)) { EXPECT_STR(srv_req_header(c.s, 0, "Host"), host); EXPECT_STR(srv_req_header(c.s, 0, "User-Agent"), "rh-agent/1.0"); }
    rh_close(&c);
}

/* buffer protocol on the request side mirrors the response side */
TEST(hqi_req_buffer_protocol) {
    REQUIRE(U(HttpAddRequestHeadersA)); REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!rh_raw_nosend(&c, "GET", RESP_OK, sizeof RESP_OK - 1)) return;
    DWORD e; CHECK(add(c.hr, "X-Buf: 0123456789\r\nX-Buf: ab\r\n", HTTP_ADDREQ_FLAG_ADD, &e));
    char b[64]; DWORD idx = 0;
    lstrcpyA(b, "X-Buf"); CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF, b, 10, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 11); EXPECT_EQ(idx, 0);
    lstrcpyA(b, "X-Buf"); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF, b, 11, &idx)); EXPECT_STR(b, "0123456789"); EXPECT_EQ(rh_len, 10); EXPECT_EQ(idx, 1);
    lstrcpyA(b, "X-Buf"); CHECK(rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF, b, 3, &idx)); EXPECT_STR(b, "ab"); EXPECT_EQ(idx, 2);
    lstrcpyA(b, "X-Buf"); CHECK(!rh_callA(c.hr, HTTP_QUERY_CUSTOM | REQF, b, sizeof b, &idx)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(idx, 2);
    WCHAR w[64]; idx = 0;
    /* W: 20 bytes holds the 11-byte A copy but not 22 bytes of W: 122, and the index has already advanced (the
     * quirk of hqi_buf_w_partial_buffer_advances_index, here on the request side) */
    lstrcpyW(w, L"X-Buf"); CHECK(!rh_callW(c.hr, HTTP_QUERY_CUSTOM | REQF, w, 20, &idx)); EXPECT_EQ(rh_err, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(rh_len, 22); EXPECT_EQ(idx, 1);
    lstrcpyW(w, L"X-Buf"); CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM | REQF, w, 22, &idx)); CHECK(!lstrcmpW(w, L"ab")); EXPECT_EQ(rh_len, 4); EXPECT_EQ(idx, 2);
    idx = 0;
    lstrcpyW(w, L"X-Buf"); CHECK(rh_callW(c.hr, HTTP_QUERY_CUSTOM | REQF, w, 22, &idx)); CHECK(!lstrcmpW(w, L"0123456789")); EXPECT_EQ(rh_len, 20); EXPECT_EQ(idx, 1);
    /* [W10] CUSTOM with a zero length: 87, *len 0 */
    { DWORD l = 0; lstrcpyA(b, "X-Buf"); SetLastError(0);
      CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM | REQF | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, &l, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER); EXPECT_EQ(l, 0); }
    { DWORD l = 6; lstrcpyA(b, "X-Buf"); SetLastError(0);
      CHECK(!U(HttpQueryInfoA)(c.hr, HTTP_QUERY_CUSTOM | REQF | HTTP_QUERY_FLAG_COALESCE_WITH_COMMA, b, &l, NULL)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 15); }
    rh_close(&c);
}

/* headers given to HttpSendRequest are visible afterwards; a resend without headers */
TEST(hqi_req_send_headers_and_resend) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), S_LOOP() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "GET", "/rs", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, "X-Send: s\r\n", NULL, 0));
    EXPECT_RQ(c.hr, "X-Send", "s");
    CHECK(rh_send(&c, NULL, NULL, 0));
    if (srv_wait_requests(c.s, 2, 2000)) {
        int n2 = srv_req_header_occurrences(c.s, 1, "X-Send");
        const char *v = rq(c.hr, "X-Send", NULL);
        t_note("resend without headers: X-Send on the wire %d time(s); request store says %s", n2, v ? v : "(absent)");
        EXPECT_EQ(n2, 1);   /* [W10] headers given to HttpSendRequest stay in the request (once) */
        CHECKF((n2 > 0) == (v != NULL), "query agrees with wire: wire %d, query %s", n2, v ? v : "(absent)");
    } else CHECK(0);
    rh_close(&c);
}
