/* ac_send.c - status sequence of HttpSendRequest in synchronous and asynchronous sessions, ERROR_IO_PENDING,
 * REQUEST_COMPLETE results, delivering thread, status information payloads, keep-alive reuse, errors.
 * Every peer is an in-process loopback server (common/srv.h). */
#include "ac.h"

/* VM_TIMEOUT: 420 */

static const DWORD SKIP_NOISE[] = { INTERNET_STATUS_HANDLE_CREATED, INTERNET_STATUS_HANDLE_CLOSING, AC_ST_330,
                                    INTERNET_STATUS_COOKIE_SENT, INTERNET_STATUS_COOKIE_RECEIVED, INTERNET_STATUS_DETECTING_PROXY, 0 };

/* send on f->hr and return the index of the first event recorded by the send */
static int send_async(ac_flow *f, const char *hdrs, void *opt, DWORD optn, BOOL *ret, DWORD *gle, INTERNET_ASYNC_RESULT *res) {
    int n0 = ac_count();
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    SetLastError(0xdeadbeef);
    *ret = U(HttpSendRequestA)(f->hr, hdrs, hdrs ? (DWORD)-1 : 0, opt, optn);
    *gle = GetLastError();
    memset(res, 0, sizeof *res);
    if (!*ret && *gle == ERROR_IO_PENDING) {
        if (!ac_wait_complete(CTX_REQ, c0 + 1, 8000, res)) t_check(0, __FILE__, __LINE__, "REQUEST_COMPLETE", "timed out");
    }
    return n0;
}

/* ------------------------------------------------------------------ async basics */
TEST(ac_async_send_returns_io_pending) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/a", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, ERROR_IO_PENDING);
    EXPECT_EQ(res.dwResult, TRUE);
    EXPECT_EQ(res.dwError, 0);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_flow_close(&f);
}
TEST(ac_async_send_complete_once) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/a", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    ac_quiesce(100, 500);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    int i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        EXPECT_EQ(ev.h, f.hr);
        EXPECT_EQ(ev.len, sizeof(INTERNET_ASYNC_RESULT));
        CHECK(ev.has_info);
    }
    ac_flow_close(&f);
}
TEST(ac_async_send_sequence_fresh_connection) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/seq", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    ac_quiesce(100, 500);
    t_note("full sequence: %s", ac_seq(0, NULL));
    ac_dump("async fresh send");
    /* IP literal: no RESOLVING_NAME / NAME_RESOLVED; DETECTING_PROXY (80) even on a DIRECT session [W10] */
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    EXPECT_STR(ac_seq_range(CTX_REQ, n0, -1, SKIP_NOISE), "20,21,30,31,40,41,100");
    /* every send-phase event belongs to the request handle */
    for (int i = n0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); CHECKF(ev.ctx == CTX_REQ && ev.h == f.hr, "event %d st=%lu ctx=%llx", i, ev.st, (unsigned long long)ev.ctx); }
    ac_flow_close(&f);
}
TEST(ac_async_send_relative_order) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/ord", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    static const DWORD chain[] = { 80, 20, 21, 30, 31, 40, 41, 100 };
    for (unsigned i = 0; i + 1 < sizeof chain / sizeof chain[0]; i++)
        CHECKF(ac_before(chain[i], chain[i + 1], CTX_REQ), "%lu before %lu (seq %s)", chain[i], chain[i + 1], ac_seq(CTX_REQ, NULL));
    for (unsigned i = 0; i < sizeof chain / sizeof chain[0]; i++)
        CHECKF(ac_count_st_ctx(chain[i], CTX_REQ) >= 1, "status %lu present", chain[i]);
    /* 127.0.0.1 is not resolved: neither 10 nor 11 */
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_RESOLVING_NAME, CTX_REQ), 0);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_NAME_RESOLVED, CTX_REQ), 0);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_DETECTING_PROXY, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_CONNECTING_TO_SERVER, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_CONNECTED_TO_SERVER, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_SENDING_REQUEST, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_SENT, CTX_REQ), 1);
    /* nothing at the connect handle's context during the send */
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_RESOLVING_NAME, CTX_CON), 0);
    ac_flow_close(&f);
}
TEST(ac_async_send_complete_thread) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/t", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    int i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0); ac_ev ev;
    CHECK(i >= 0);
    if (i >= 0 && ac_get(i, &ev)) {
        CHECKF(ev.tid != ac_main_tid, "REQUEST_COMPLETE delivered on the calling thread");
    }
    /* [W10] every send-phase status of an async request comes from a WinINet worker thread, none from the caller */
    EXPECT_EQ(ac_count_tid(CTX_REQ, ac_main_tid) - 1 /* HANDLE_CREATED */, 0);
    /* note which statuses came on the calling thread (the part executed before 997 was returned) */
    char buf[256] = ""; size_t n = 0;
    for (int k = n0; k < ac_count(); k++) { ac_get(k, &ev); if (ev.tid == ac_main_tid && n + 8 < sizeof buf) n += snprintf(buf + n, sizeof buf - n, "%lu,", ev.st); }
    t_note("async send: statuses on the calling thread: %s (worker: %d)", buf, ac_count_not_tid(CTX_REQ, ac_main_tid));
    ac_flow_close(&f);
}
#define EXACT_RESP "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
TEST(ac_async_send_info_payloads) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND(EXACT_RESP), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/info", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    ac_ev ev; int i;
    i = ac_find(INTERNET_STATUS_DETECTING_PROXY, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) { EXPECT_EQ(ev.has_info, 0); EXPECT_EQ(ev.len, 0); } else CHECK(i >= 0);
    /* CONNECTING_TO_SERVER / CONNECTED_TO_SERVER: the address as a NUL-terminated string, length includes the NUL */
    static const DWORD addr_st[] = { INTERNET_STATUS_CONNECTING_TO_SERVER, INTERNET_STATUS_CONNECTED_TO_SERVER };
    for (int k = 0; k < 2; k++) {
        i = ac_find(addr_st[k], CTX_REQ, n0);
        if (i >= 0 && ac_get(i, &ev)) { CHECK(ev.has_info); EXPECT_STR((char *)ev.info, "127.0.0.1"); EXPECT_EQ(ev.len, 10); }
        else CHECK(i >= 0);
    }
    static const DWORD noinfo_st[] = { INTERNET_STATUS_SENDING_REQUEST, INTERNET_STATUS_RECEIVING_RESPONSE };
    for (int k = 0; k < 2; k++) {
        i = ac_find(noinfo_st[k], CTX_REQ, n0);
        if (i >= 0 && ac_get(i, &ev)) { EXPECT_EQ(ev.has_info, 0); EXPECT_EQ(ev.len, 0); } else CHECK(i >= 0);
    }
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t hn = 0; srv_req_head_raw(f.s, 0, &hn);
    i = ac_find(INTERNET_STATUS_REQUEST_SENT, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) {
        EXPECT_EQ(ev.len, sizeof(DWORD));
        EXPECT_EQ(ac_info_dword(&ev), hn);
    } else CHECK(i >= 0);
    i = ac_find(INTERNET_STATUS_RESPONSE_RECEIVED, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) {
        EXPECT_EQ(ev.len, sizeof(DWORD));
        /* bytes taken from the socket by that receive: the whole 43-byte reply normally arrives in one segment */
        t_note("RESPONSE_RECEIVED %lu bytes (reply %u)", ac_info_dword(&ev), (unsigned)strlen(EXACT_RESP));
        CHECK(ac_info_dword(&ev) > 0 && ac_info_dword(&ev) <= strlen(EXACT_RESP));
    } else CHECK(i >= 0);
    i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) { EXPECT_EQ(ev.len, sizeof(INTERNET_ASYNC_RESULT)); EXPECT_EQ(ev.h, f.hr); } else CHECK(i >= 0);
    ac_flow_close(&f);
}
TEST(ac_async_send_keepalive_reuse_sequence) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/k1", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res; char body[64]; int np;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, body, sizeof body, &np), 5);
    ac_close_wait(f.hr, CTX_REQ);
    f.hr = U(HttpOpenRequestA)(f.hc, "GET", "/k2", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ);
    CHECK(f.hr != NULL); if (!f.hr) { ac_flow_close(&f); return; }
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING); EXPECT_EQ(res.dwResult, TRUE);
    CHECK(srv_wait_requests(f.s, 2, 2000));
    EXPECT_EQ(srv_req_conn(f.s, 1), srv_req_conn(f.s, 0));
    ac_quiesce(100, 500);
    t_note("reused connection sequence: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,30,31,40,41,100");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_CONNECTING_TO_SERVER, CTX_REQ), 1);   /* only the first request connected */
    ac_flow_close(&f);
}
TEST(ac_async_send_post_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "posted"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/post", T_INET_FRESH)) return;
    static char data[] = "a=1&b=2";
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, "Content-Type: application/x-www-form-urlencoded\r\n", data, 7, &r, &e, &res);
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING); EXPECT_EQ(res.dwResult, TRUE); EXPECT_EQ(res.dwError, 0);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn = 0; const char *b = srv_req_body(f.s, 0, &bn);
    CHECK(b && bn == 7 && !memcmp(b, "a=1&b=2", 7));
    size_t hn = 0; srv_req_head_raw(f.s, 0, &hn);
    int i = ac_find(INTERNET_STATUS_REQUEST_SENT, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) { t_note("POST REQUEST_SENT=%lu head=%u body=7", ac_info_dword(&ev), (unsigned)hn); CHECK(ac_info_dword(&ev) == hn + 7 || ac_info_dword(&ev) == hn); }
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_SENT, CTX_REQ), 1);
    char body[32]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, body, sizeof body, &np), 6);
    EXPECT_STR(body, "posted");
    ac_flow_close(&f);
}
TEST(ac_async_send_head_request) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "HEAD", "/h", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(e, ERROR_IO_PENDING); EXPECT_EQ(res.dwResult, TRUE);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    static DWORD rd; static char b[16];
    rd = 77;
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    if (!ok && GetLastError() == ERROR_IO_PENDING) { INTERNET_ASYNC_RESULT r2; CHECK(ac_wait_complete(CTX_REQ, 2, 5000, &r2)); }
    else CHECK(ok);
    EXPECT_EQ(rd, 0);
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ async errors */
TEST(ac_async_send_connect_refused) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/x", T_INET_FRESH)) return;
    srv_stop(f.s); f.s = NULL;                     /* the port is now closed: connect is refused (~2 s, 04 F3) */
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    EXPECT_EQ(res.dwResult, FALSE);
    EXPECT_EQ(res.dwError, ERROR_INTERNET_CANNOT_CONNECT);
    ac_quiesce(100, 500);
    t_note("refused sequence: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,100");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_CONNECTED_TO_SERVER, CTX_REQ), 0);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_SENDING_REQUEST, CTX_REQ), 0);
    CHECK(ac_count_st_ctx(INTERNET_STATUS_CONNECTING_TO_SERVER, CTX_REQ) >= 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    /* after a failed async send the handle has no response */
    DWORD st = 0, l = sizeof st;
    SetLastError(0xdeadbeef);
    BOOL q = U(HttpQueryInfoA)(f.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
    t_note("STATUS_CODE query after failed async send: ok=%d err=%lu status=%lu", q, GetLastError(), st);
    ac_flow_close(&f);
}
TEST(ac_async_send_server_resets) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_RESET() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 2, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rst", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    EXPECT_EQ(res.dwResult, FALSE);
    t_note("reset: dwError=%lu (%s) seq=%s", res.dwError, t_inet_errname(res.dwError), ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(res.dwError, ERROR_INTERNET_CONNECTION_RESET);
    CHECK(ac_before(INTERNET_STATUS_CLOSING_CONNECTION, INTERNET_STATUS_CONNECTION_CLOSED, CTX_REQ));
    CHECK(ac_before(INTERNET_STATUS_CONNECTION_CLOSED, INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ));
    ac_flow_close(&f);
}
TEST(ac_async_send_server_closes_without_reply) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_CLOSE() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 2, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/eof", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    EXPECT_EQ(res.dwResult, FALSE);
    t_note("empty reply: dwError=%lu (%s) seq=%s requests=%d", res.dwError, t_inet_errname(res.dwError), ac_seq_range(0, n0, -1, NULL), srv_req_count(f.s));
    EXPECT_EQ(res.dwError, ERROR_HTTP_INVALID_SERVER_RESPONSE);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,50,51,100");
    ac_flow_close(&f);
}
TEST(ac_async_send_receive_timeout) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late") };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/slow", T_INET_FRESH)) return;
    DWORD to = 1000;
    CHECK(U(InternetSetOptionA)(f.hr, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to));
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    /* [W10] a 1 s RECEIVE_TIMEOUT set on the request did not cut a 3 s server delay short (completed with 200) */
    t_note("receive-timeout 1000 on request: dwResult=%llu dwError=%lu status=%lu seq=%s", (unsigned long long)res.dwResult, res.dwError,
           ac_status_code(f.hr), ac_seq_range(0, n0, -1, NULL));
    ac_flow_close(&f);
}
TEST(ac_async_send_bad_header_sync_failure) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/bh", T_INET_FRESH)) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    /* a header line without a colon is rejected while parsing, before any I/O */
    BOOL r = U(HttpSendRequestA)(f.hr, "NoColonHere\r\n", (DWORD)-1, NULL, 0);
    DWORD e = GetLastError();
    /* [W10] rejected synchronously with 12150, no status callback at all */
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, ERROR_HTTP_HEADER_NOT_FOUND);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "");
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ async: callback placement / context */
TEST(ac_async_callback_on_request_only) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, NULL, "GET", "/ro", T_INET_FRESH)) return;
    EXPECT_EQ(U(InternetSetStatusCallbackA)(f.hr, ac_cb), NULL);
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(e, ERROR_IO_PENDING); EXPECT_EQ(res.dwResult, TRUE);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, 0), 0);
    char body[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, body, sizeof body, &np), 5);
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 2000));
    ac_flow_close(&f);
}
TEST(ac_async_callback_on_connect_only) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, NULL, "GET", "/co", T_INET_FRESH)) return;
    /* the request was created before the callback was set on its parent: it has none */
    EXPECT_EQ(U(InternetSetStatusCallbackA)(f.hc, ac_cb), NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(f.hr, NULL), NULL);
    HINTERNET hr2 = U(HttpOpenRequestA)(f.hc, "GET", "/co2", NULL, NULL, NULL, T_INET_FRESH, CTX_ALT);
    CHECK(hr2 != NULL);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_ALT), 1);
    if (hr2) {
        int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_ALT);
        SetLastError(0xdeadbeef);
        BOOL r = U(HttpSendRequestA)(hr2, NULL, 0, NULL, 0);
        EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
        INTERNET_ASYNC_RESULT res;
        CHECK(ac_wait_complete(CTX_ALT, c0 + 1, 5000, &res));
        EXPECT_EQ(res.dwResult, TRUE);
        ac_close_wait(hr2, CTX_ALT);
    }
    U(InternetSetStatusCallbackA)(f.hc, NULL);
    ac_flow_close(&f);
}
TEST(ac_async_context_zero_request) {
    REQ_ASYNC_API();
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/z", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    t_note("async send with context 0: r=%d err=%lu", r, e);
    CHECK(srv_wait_requests(s, 1, 3000));
    ac_quiesce(200, 1500);
    /* no event can be delivered for the request: its context is 0 [D InternetIndicateStatus] */
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, 0), 0);
    CHECKF(!r && e == ERROR_IO_PENDING, "r=%d err=%lu", r, e);
    ac_close_wait(hr, 0); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
TEST(ac_async_no_callback_still_pending) {
    REQ_ASYNC_API();
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open(INTERNET_FLAG_ASYNC);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/nc", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ);
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    CHECK(srv_wait_requests(s, 1, 3000));
    Sleep(300);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
    EXPECT_EQ(ac_count(), 0);
    srv_stop(s);
}
/* host name "localhost": the only name the lab guest can resolve (04 F5); the servers listen on 127.0.0.1 and [::1] */
static HINTERNET open_localhost_req(srv *s, HINTERNET *phi, HINTERNET *phc, DWORD sflags, INTERNET_STATUS_CALLBACK cb, int wide) {
    *phi = ac_open(sflags);
    if (wide) U(InternetSetStatusCallbackW)(*phi, cb); else U(InternetSetStatusCallbackA)(*phi, cb);
    *phc = U(InternetConnectA)(*phi, "localhost", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    return *phc ? U(HttpOpenRequestA)(*phc, "GET", "/lh", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ) : NULL;
}
static void close_localhost(srv *s, HINTERNET hi, HINTERNET hc, HINTERNET hr) {
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi); srv_stop(s);
}
TEST(ac_async_localhost_resolution_sequence) {
    REQ_ASYNC_API();
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin(); HINTERNET hi, hc;
    HINTERNET hr = open_localhost_req(s, &hi, &hc, INTERNET_FLAG_ASYNC, ac_cb, 0);
    CHECK(hr != NULL);
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(pending, 1);
    ac_quiesce(100, 300);
    t_note("localhost async: %s", ac_seq_range(0, n0, -1, NULL));
    ac_dump("localhost");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_RESOLVING_NAME, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_NAME_RESOLVED, CTX_REQ), 1);
    CHECK(ac_before(INTERNET_STATUS_RESOLVING_NAME, INTERNET_STATUS_NAME_RESOLVED, CTX_REQ));
    CHECK(ac_before(INTERNET_STATUS_NAME_RESOLVED, INTERNET_STATUS_CONNECTING_TO_SERVER, CTX_REQ));
    int i = ac_find(INTERNET_STATUS_RESOLVING_NAME, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) { EXPECT_STR((char *)ev.info, "localhost"); t_note("RESOLVING_NAME len=%lu", ev.len); }
    i = ac_find(INTERNET_STATUS_NAME_RESOLVED, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) t_note("NAME_RESOLVED len=%lu '%s'", ev.len, (char *)ev.info);
    i = ac_find(INTERNET_STATUS_CONNECTED_TO_SERVER, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) t_note("CONNECTED_TO_SERVER len=%lu '%s'", ev.len, (char *)ev.info);
    close_localhost(s, hi, hc, hr);
}
TEST(ac_sync_localhost_resolution_sequence) {
    REQ_ASYNC_API();
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin(); HINTERNET hi, hc;
    HINTERNET hr = open_localhost_req(s, &hi, &hc, 0, ac_cb, 0);
    int n0 = ac_count();
    CHECK(hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    t_note("localhost sync: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_RESOLVING_NAME, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_NAME_RESOLVED, CTX_REQ), 1);
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    close_localhost(s, hi, hc, hr);
}
TEST(ac_async_w_callback_strings) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin(); HINTERNET hi, hc;
    HINTERNET hr = open_localhost_req(s, &hi, &hc, INTERNET_FLAG_ASYNC, ac_cbw, 1);
    int pending; DWORD err; int n0 = ac_count();
    CHECK(hr && ac_send_wait(hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_ev ev; int i;
    /* UnicodeStatusCallbackWrapper converts RESOLVING_NAME (10) and REDIRECT (110) only [D] */
    i = ac_find(INTERNET_STATUS_RESOLVING_NAME, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) {
        EXPECT_EQ(ev.wide, 1);
        CHECK(ev.has_info && !lstrcmpW((WCHAR *)ev.info, L"localhost"));
        t_note("W RESOLVING_NAME len=%lu", ev.len);
    } else CHECK(i >= 0);
    i = ac_find(INTERNET_STATUS_NAME_RESOLVED, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) {
        /* passed through unconverted: still a narrow string */
        CHECKF(ev.has_info && ev.info[0] && ev.info[1], "NAME_RESOLVED stays narrow in the W callback");
        t_note("W NAME_RESOLVED len=%lu '%s'", ev.len, (char *)ev.info);
    } else CHECK(i >= 0);
    i = ac_find(INTERNET_STATUS_CONNECTING_TO_SERVER, CTX_REQ, n0);
    if (i >= 0 && ac_get(i, &ev)) { CHECK(ev.info[0] && ev.info[1]); t_note("W CONNECTING_TO_SERVER len=%lu '%s'", ev.len, (char *)ev.info); }
    close_localhost(s, hi, hc, hr);
}

/* ------------------------------------------------------------------ synchronous sessions with a callback */
TEST(ac_sync_send_sequence) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/s", T_INET_FRESH)) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    CHECKF(r, "err=%lu", GetLastError());
    int n1 = ac_count();
    ac_quiesce(100, 400);
    EXPECT_EQ(ac_count(), n1);            /* nothing arrives after the synchronous call returned */
    t_note("sync send sequence: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41");
    ac_flow_close(&f);
}
TEST(ac_sync_send_no_request_complete) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/s", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    char b[16]; size_t n = t_inet_read_all(f.hr, b, sizeof b, NULL);
    EXPECT_EQ(n, 5);
    ac_quiesce(100, 400);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    ac_flow_close(&f);
}
TEST(ac_sync_send_all_on_calling_thread) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/s", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    char b[16]; t_inet_read_all(f.hr, b, sizeof b, NULL);
    ac_flow_close(&f);
    int other = ac_count_not_tid(0, ac_main_tid);
    EXPECT_EQ(other, 0);
    CHECK(ac_count() >= 10);
}
TEST(ac_sync_send_payloads_match_async) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/pl", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t hn = 0; srv_req_head_raw(f.s, 0, &hn);
    ac_ev ev; int i = ac_find(INTERNET_STATUS_REQUEST_SENT, CTX_REQ, 0);
    if (i >= 0 && ac_get(i, &ev)) EXPECT_EQ(ac_info_dword(&ev), hn); else CHECK(i >= 0);
    i = ac_find(INTERNET_STATUS_RESOLVING_NAME, CTX_REQ, 0);
    if (i >= 0 && ac_get(i, &ev)) EXPECT_STR((char *)ev.info, "127.0.0.1"); else CHECK(i >= 0);
    ac_flow_close(&f);
}
TEST(ac_sync_connect_refused_events) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/x", T_INET_FRESH)) return;
    srv_stop(f.s); f.s = NULL;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    CHECK(!U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    EXPECT_ERR(ERROR_INTERNET_CANNOT_CONNECT);
    t_note("sync refused sequence: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20");
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_CONNECTED_TO_SERVER, CTX_REQ), 0);
    ac_flow_close(&f);
}
TEST(ac_sync_no_callback_baseline) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, NULL, "GET", "/b", T_INET_FRESH)) return;
    SetLastError(0xdeadbeef);
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_flow_close(&f);
    EXPECT_EQ(ac_count(), 0);
}

/* ------------------------------------------------------------------ connection close statuses */
TEST(ac_async_connection_close_statuses) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "bye", SRV_R_CONN_CLOSE) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 2, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/c", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res; char body[16]; int np;
    int n0 = send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(res.dwResult, TRUE);
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, body, sizeof body, &np), 3);
    EXPECT_STR(body, "bye");
    int n1 = ac_count();
    ac_close_wait(f.hr, CTX_REQ); f.hr = NULL;
    ac_quiesce(100, 500);
    t_note("conn-close: send+read=%s close=%s", ac_seq_range(0, n0, n1, NULL), ac_seq_range(0, n1, -1, NULL));
    int cc = ac_count_st_ctx(INTERNET_STATUS_CLOSING_CONNECTION, CTX_REQ), cd = ac_count_st_ctx(INTERNET_STATUS_CONNECTION_CLOSED, CTX_REQ);
    t_note("CLOSING_CONNECTION=%d CONNECTION_CLOSED=%d", cc, cd);
    EXPECT_EQ(cc, cd);
    if (cc && cd) CHECK(ac_before(INTERNET_STATUS_CLOSING_CONNECTION, INTERNET_STATUS_CONNECTION_CLOSED, CTX_REQ));
    ac_flow_close(&f);
}
TEST(ac_async_keepalive_close_statuses) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/ka", T_INET_FRESH)) return;
    BOOL r; DWORD e; INTERNET_ASYNC_RESULT res; char body[16]; int np;
    send_async(&f, NULL, NULL, 0, &r, &e, &res);
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, body, sizeof body, &np), 5);
    int n1 = ac_count();
    ac_close_wait(f.hr, CTX_REQ); f.hr = NULL;
    ac_quiesce(100, 400);
    /* a kept-alive connection goes back to the pool: closing the request does not close it */
    t_note("keep-alive close: %s", ac_seq_range(0, n1, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n1, -1, NULL), "70");
    ac_flow_close(&f);
}
