/* wire_body.c - request bodies on the wire: lpOptional, HttpSendRequestEx + InternetWriteFile + HttpEndRequest,
 * caller-framed chunked uploads, Expect: 100-continue, Content-Length rules.
 * Evidence: InitBeginSendRequest@0x88e20 (Content-Length "%I32u" from the optional length / dwBufferTotal, also 0 when
 * the method index > 1), Win10 VM. See EVIDENCE.md. */
#include "hrw.h"
#include <stdlib.h>

static int body_is(srv *s, int i, const void *p, size_t n) {
    size_t bl = 0; const char *b = srv_req_body(s, i, &bl);
    return b && bl == n && !memcmp(b, p, n);
}

/* ------------------------------------------------------------------ lpOptional */
static void opt_body(const char *verb, const void *data, DWORD n, const char *want_cl) {
    hrw w; int r = hrw_simple(&w, "b/1", verb, "/b", NULL, NULL, NULL, HRW_F, NULL, data, n);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    CHECK(srv_wait_events(w.s, SRV_EV_BODY, 1, 3000) || n == 0);
    const char *cl = srv_req_header(w.s, 0, "Content-Length");
    CHECKF(want_cl ? (cl && !strcmp(cl, want_cl)) : !cl, "%s: Content-Length got %s want %s", verb, cl ? cl : "(none)", want_cl ? want_cl : "(none)");
    if (n) CHECKF(body_is(w.s, 0, data, n), "%s: body mismatch", verb);
    EXPECT_EQ(srv_req_body_chunked(w.s, 0), 0);
    EXPECT_NOHDR(w.s, 0, "Transfer-Encoding");
    EXPECT_NOHDR(w.s, 0, "Content-Type");
    EXPECT_EQ(w.status, 200);
    hrw_done(&w);
}
TEST(hrw_body_post_small) { HRW_REQUIRE_HTTP(); opt_body("POST", "a=1&b=2", 7, "7"); }
TEST(hrw_body_put_small) { HRW_REQUIRE_HTTP(); opt_body("PUT", "put-data", 8, "8"); }
TEST(hrw_body_patch_small) { HRW_REQUIRE_HTTP(); opt_body("PATCH", "{\"a\":1}", 7, "7"); }
TEST(hrw_body_delete_with_body) { HRW_REQUIRE_HTTP(); opt_body("DELETE", "del", 3, "3"); }
TEST(hrw_body_custom_verb_body) { HRW_REQUIRE_HTTP(); opt_body("REPORT", "<x/>", 4, "4"); }
TEST(hrw_body_get_with_body) { HRW_REQUIRE_HTTP(); opt_body("GET", "getbody", 7, "7"); }
TEST(hrw_body_post_binary_nuls) { HRW_REQUIRE_HTTP(); static const char d[] = { 0, 1, 2, 0, '\r', '\n', 0, (char)0xff }; opt_body("POST", d, sizeof d, "8"); }
TEST(hrw_body_post_zero_len_ptr) { HRW_REQUIRE_HTTP(); opt_body("POST", "ignored", 0, "0"); }
TEST(hrw_body_post_null) { HRW_REQUIRE_HTTP(); opt_body("POST", NULL, 0, "0"); }
TEST(hrw_body_get_null) { HRW_REQUIRE_HTTP(); opt_body("GET", NULL, 0, NULL); }
TEST(hrw_body_head_null) { HRW_REQUIRE_HTTP(); opt_body("HEAD", NULL, 0, NULL); }
TEST(hrw_body_post_one_byte) { HRW_REQUIRE_HTTP(); opt_body("POST", "x", 1, "1"); }

TEST(hrw_body_post_large_256k) {
    HRW_REQUIRE_HTTP();
    DWORD n = 256 * 1024; unsigned char *d = malloc(n);
    for (DWORD i = 0; i < n; i++) d[i] = srv_pattern_byte(i);
    hrw w; int r = hrw_simple(&w, "big/1", "POST", "/big", NULL, NULL, NULL, HRW_F, NULL, d, n);
    if (r < 0) { free(d); t_skip("server unavailable"); return; }
    CHECK(r);
    CHECK(srv_wait_events(w.s, SRV_EV_BODY, 1, 5000));
    EXPECT_HDR(w.s, 0, "Content-Length", "262144");
    size_t bl = 0; const char *b = srv_req_body(w.s, 0, &bl);
    EXPECT_EQ(bl, n); CHECK(b && srv_pattern_check(b, bl, 0));
    free(d); hrw_done(&w);
}

TEST(hrw_body_post_header_order) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "o/1", "POST", "/o", NULL, NULL, NULL, HRW_F, "Content-Type: text/plain\r\n", "abc", 3);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_NAMES(w.s, 0, "Content-Type|User-Agent|Host|Content-Length|Cache-Control");
    EXPECT_HDR(w.s, 0, "Content-Type", "text/plain");
    hrw_dump(w.s, 0);
    hrw_done(&w);
}
TEST(hrw_body_post_nobody_header_order) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "o/1", "POST", "/o", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Content-Length|Cache-Control");
    hrw_done(&w);
}

/* A caller-supplied Content-Length is replaced by the real optional length. */
TEST(hrw_body_user_content_length_replaced) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "o/1", "POST", "/o", NULL, NULL, NULL, HRW_F, "Content-Length: 3\r\n", "abc", 3);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Content-Length"), 1);
    EXPECT_HDR(w.s, 0, "Content-Length", "3");
    t_note("user CL position: %s", hrw_names(w.s, 0));
    hrw_done(&w);
}

/* Re-sending the same POST handle with new optional data. Win10 VM (boot C1): the second request carried the FIRST
 * body ("one", Content-Length 3). */
TEST(hrw_body_post_resend_reuses_first_body) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rs/1", "POST", "/rs", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, "one", 3); CHECK(w.ok); hrw_read(&w);
    hrw_send(&w, NULL, 0, "second", 6); CHECKF(w.ok, "err %lu", w.err); hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 2, 3000));
    size_t n1 = 0; const char *b1 = srv_req_body(s, 1, &n1);
    t_note("re-send body: %.*s (CL %s) conns=%d", (int)n1, b1 ? b1 : "", srv_req_header(s, 1, "Content-Length"), srv_conn_count(s));
    hrw_dump(s, 1);
    CHECK(body_is(s, 0, "one", 3)); CHECK(body_is(s, 1, "one", 3));
    EXPECT_HDR(s, 1, "Content-Length", "3");
    EXPECT_EQ(srv_req_header_occurrences(s, 1, "Content-Length"), 1);
    hrw_done(&w);
}

/* ------------------------------------------------------------------ HttpSendRequestEx */
static BOOL send_ex(HINTERNET hr, const char *hdrs, const void *first, DWORD nfirst, DWORD total) {
    INTERNET_BUFFERSA b; memset(&b, 0, sizeof b);
    b.dwStructSize = sizeof b;
    b.lpcszHeader = hdrs; b.dwHeadersLength = hdrs ? (DWORD)strlen(hdrs) : 0;
    b.lpvBuffer = (LPVOID)first; b.dwBufferLength = nfirst; b.dwBufferTotal = total;
    return U(HttpSendRequestExA)(hr, &b, NULL, 0, 0);
}
static BOOL write_all(HINTERNET hr, const void *p, DWORD n) {
    DWORD wr = 0;
    BOOL ok = U(InternetWriteFile)(hr, p, n, &wr);
    return ok && wr == n;
}
#define EX_REQUIRE() do { REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(InternetWriteFile)); REQUIRE(U(HttpEndRequestA)); HRW_REQUIRE_HTTP(); } while (0)

GTEST(hrw_ex_write_pieces, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "POST", "/ex", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, NULL, NULL, 0, 11));
    CHECK(write_all(w.hr, "hello", 5)); CHECK(write_all(w.hr, " ", 1)); CHECK(write_all(w.hr, "world", 5));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w); EXPECT_STR(w.body, "ok");
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "POST /ex HTTP/1.1");
    EXPECT_HDR(s, 0, "Content-Length", "11");
    CHECK(body_is(s, 0, "hello world", 11));
    EXPECT_NAMES(s, 0, "User-Agent|Host|Content-Length|Cache-Control");
    hrw_done(&w);
}
GTEST(hrw_ex_initial_buffer_plus_write, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "PUT", "/ex", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, NULL, "abc", 3, 6));
    CHECK(write_all(w.hr, "def", 3));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "6");
    CHECK(body_is(s, 0, "abcdef", 6));
    hrw_done(&w);
}
GTEST(hrw_ex_initial_buffer_only, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "POST", "/ex", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, NULL, "whole", 5, 5));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "5");
    CHECK(body_is(s, 0, "whole", 5));
    hrw_done(&w);
}
GTEST(hrw_ex_headers_in_buffers, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "POST", "/ex", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, "X-Ex: 1\r\nContent-Type: application/octet-stream\r\n", NULL, 0, 2));
    CHECK(write_all(w.hr, "zz", 2));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "X-Ex", "1");
    EXPECT_HDR(s, 0, "Content-Type", "application/octet-stream");
    EXPECT_NAMES(s, 0, "X-Ex|Content-Type|User-Agent|Host|Content-Length|Cache-Control");
    hrw_done(&w);
}
GTEST(hrw_ex_null_buffers_post, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "POST", "/ex", NULL, NULL, NULL, HRW_F));
    CHECKF(U(HttpSendRequestExA)(w.hr, NULL, NULL, 0, 0), "err %lu", GetLastError());
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "0");
    hrw_done(&w);
}
GTEST(hrw_ex_total_zero_get, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "GET", "/exg", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, NULL, NULL, 0, 0));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w); EXPECT_STR(w.body, "ok");
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_NOHDR(s, 0, "Content-Length");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
GTEST(hrw_ex_large_writes, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "POST", "/exl", NULL, NULL, NULL, HRW_F));
    DWORD total = 100000; unsigned char *d = malloc(total);
    for (DWORD i = 0; i < total; i++) d[i] = srv_pattern_byte(i);
    CHECK(send_ex(w.hr, NULL, NULL, 0, total));
    for (DWORD off = 0; off < total; off += 7000) { DWORD n = total - off < 7000 ? total - off : 7000; CHECK(write_all(w.hr, d + off, n)); }
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 5000));
    EXPECT_HDR(s, 0, "Content-Length", "100000");
    size_t bl = 0; const char *b = srv_req_body(s, 0, &bl);
    EXPECT_EQ(bl, total); CHECK(b && srv_pattern_check(b, bl, 0));
    free(d); hrw_done(&w);
}
GTEST(hrw_ex_w_variant, 20000) {
    REQUIRE(U(HttpSendRequestExW)); REQUIRE(U(HttpEndRequestW)); REQUIRE(U(InternetWriteFile)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "exw/1", "POST", "/exw", NULL, NULL, NULL, HRW_F));
    INTERNET_BUFFERSW b; memset(&b, 0, sizeof b); b.dwStructSize = sizeof b;
    b.lpcszHeader = L"X-Wex: 1\r\n"; b.dwHeadersLength = 10; b.dwBufferTotal = 4;
    BOOL ok = U(HttpSendRequestExW)(w.hr, &b, NULL, 0, 0);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) {
        CHECK(write_all(w.hr, "wxyz", 4));
        CHECKF(U(HttpEndRequestW)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
        hrw_read(&w);
        CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
        EXPECT_HDR(s, 0, "X-Wex", "1");
        EXPECT_HDR(s, 0, "Content-Length", "4");
        CHECK(body_is(s, 0, "wxyz", 4));
    }
    hrw_done(&w);
}
/* Headers are not on the wire before the first write? Observe when the head leaves the client. */
GTEST(hrw_ex_head_sent_at_sendrequestex, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex/1", "POST", "/when", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, NULL, NULL, 0, 3));
    int early = srv_wait_requests(s, 1, 1500);
    t_note("head received before any InternetWriteFile: %d", early);
    CHECK(early);
    CHECK(write_all(w.hr, "abc", 3));
    CHECK(U(HttpEndRequestA)(w.hr, NULL, 0, 0));
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    CHECK(body_is(s, 0, "abc", 3));
    hrw_done(&w);
}

/* ------------------------------------------------------------------ chunked upload framed by the caller */
GTEST(hrw_chunked_upload_caller_framed, 20000) {
    EX_REQUIRE();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ch/1", "POST", "/chunk", NULL, NULL, NULL, HRW_F));
    CHECK(send_ex(w.hr, "Transfer-Encoding: chunked\r\n", NULL, 0, 0));
    static const char c1[] = "5\r\nhello\r\n", c2[] = "6\r\n world\r\n", c3[] = "0\r\n\r\n";
    CHECK(write_all(w.hr, c1, sizeof c1 - 1)); CHECK(write_all(w.hr, c2, sizeof c2 - 1)); CHECK(write_all(w.hr, c3, sizeof c3 - 1));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w); EXPECT_STR(w.body, "ok");
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Transfer-Encoding", "chunked");
    /* WinINet still adds Content-Length from dwBufferTotal (0); it does not know the caller framed the body */
    EXPECT_HDR(s, 0, "Content-Length", "0");
    EXPECT_NAMES(s, 0, "Transfer-Encoding|User-Agent|Host|Content-Length|Cache-Control");
    EXPECT_EQ(srv_req_body_chunked(s, 0), 1);
    CHECK(body_is(s, 0, "hello world", 11));
    hrw_dump(s, 0);
    hrw_done(&w);
}
GTEST(hrw_chunked_header_via_add, 20000) {
    EX_REQUIRE(); REQUIRE(U(HttpAddRequestHeadersA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ch/1", "PUT", "/chunk", NULL, NULL, NULL, HRW_F));
    CHECK(U(HttpAddRequestHeadersA)(w.hr, "Transfer-Encoding: chunked", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(send_ex(w.hr, NULL, NULL, 0, 0));
    static const char c[] = "3\r\nabc\r\n0\r\n\r\n";
    CHECK(write_all(w.hr, c, sizeof c - 1));
    CHECKF(U(HttpEndRequestA)(w.hr, NULL, 0, 0), "end err %lu", GetLastError());
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "0");
    CHECK(body_is(s, 0, "abc", 3));
    hrw_done(&w);
}
GTEST(hrw_chunked_with_optional_data, 20000) {
    HRW_REQUIRE_HTTP();
    static const char c[] = "4\r\ndata\r\n0\r\n\r\n";
    hrw w; int r = hrw_simple(&w, "ch/1", "POST", "/co", NULL, NULL, NULL, HRW_F, "Transfer-Encoding: chunked\r\n", c, sizeof c - 1);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    CHECK(srv_wait_events(w.s, SRV_EV_BODY, 1, 3000));
    EXPECT_NAMES(w.s, 0, "Transfer-Encoding|User-Agent|Host|Content-Length|Cache-Control");
    EXPECT_HDR(w.s, 0, "Content-Length", "14");   /* the optional length, framing bytes included */
    CHECK(body_is(w.s, 0, "data", 4));
    hrw_done(&w);
}

/* ------------------------------------------------------------------ Expect: 100-continue */
GTEST(hrw_expect_100_continue, 20000) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_100(), S_BODY(), S_REPLY(200, NULL, "ok"), S_CLOSE_IF_ASKED(), S_LOOP() };
    srv *s = hrw_srv_steps(st, 6); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "ex100/1", "POST", "/e", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, "Expect: 100-continue\r\n", (DWORD)-1, "payload", 7);
    CHECKF(w.ok, "err %lu", w.err);
    EXPECT_EQ(w.status, 200);
    hrw_read(&w); EXPECT_STR(w.body, "ok");
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Expect", "100-continue");
    EXPECT_HDR(s, 0, "Content-Length", "7");
    CHECK(body_is(s, 0, "payload", 7));
    hrw_done(&w);
}
GTEST(hrw_expect_no_100_from_server, 20000) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ex/1", "POST", "/e", NULL, NULL, NULL, HRW_F, "Expect: 100-continue\r\n", "abc", 3);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_EQ(w.status, 200);
    CHECK(srv_wait_events(w.s, SRV_EV_BODY, 1, 3000));
    CHECK(body_is(w.s, 0, "abc", 3));
    hrw_done(&w);
}

/* ------------------------------------------------------------------ InternetWriteFile misuse (no wire) */
GTEST(hrw_writefile_before_sendex_fails, 20000) {
    REQUIRE(U(InternetWriteFile)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "wf/1", "POST", "/wf", NULL, NULL, NULL, HRW_F));
    DWORD wr = 77; SetLastError(0);
    BOOL ok = U(InternetWriteFile)(w.hr, "abc", 3, &wr);
    DWORD e = GetLastError();
    CHECK(!ok);
    t_note("InternetWriteFile before send: err %lu %s wr=%lu", e, t_inet_errname(e), wr);
    CHECK(e == ERROR_INTERNET_INCORRECT_HANDLE_STATE || e == ERROR_INTERNET_INVALID_OPERATION);
    Sleep(50);
    EXPECT_EQ(srv_req_count(s), 0);
    hrw_done(&w);
}
GTEST(hrw_endrequest_without_sendex_fails, 20000) {
    REQUIRE(U(HttpEndRequestA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "er/1", "POST", "/er", NULL, NULL, NULL, HRW_F));
    SetLastError(0);
    BOOL ok = U(HttpEndRequestA)(w.hr, NULL, 0, 0);
    DWORD e = GetLastError();
    CHECK(!ok);
    t_note("HttpEndRequest without SendRequestEx: err %lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_OPERATION_CANCELLED);
    hrw_done(&w);
}
