/* ac_y.c - async mode, third pass (prefix ac_y_): InternetReadFileEx[W] parameter rules read in the decompilation,
 * HttpSendRequestExW / HttpEndRequestW in async sessions, NULL-handle ordering of the Ex entry points, contexts set
 * before the send or from inside HANDLE_CREATED, closing the parent from inside REQUEST_COMPLETE, more exact status
 * sequences (HEAD, Connection: close then a new connection, sync InternetOpenUrl redirect, W callbacks).
 * Every peer is an in-process loopback server; no cookies or cache entries are written (T_INET_FRESH).
 *
 * Decomp grounding [D] (corpus explorer, wininet.dll 10.0.19041):
 *  - InternetReadFileExW@0xa2d90: lpBuffersOut == NULL or lpcszHeader != NULL -> 87; otherwise the call is
 *    InternetReadFileExA with the same arguments (INTERNET_BUFFERSW has the same 0x38 layout).
 *  - InternetReadFileExA@0xa2e20: MapHandleToAddress failure -> that error; the handle must be an HTTP request
 *    ('Req'); dwStructSize != 0x38 -> 87; dwBufferLength == 0 -> no ReadFileEx FSM, completed in place
 *    (ReadFile_End with success); dwFlags is passed to CFsm_ReadFileEx without validation.
 *  - HttpSendRequestExW@0xd1700: NULL handle -> 6 (first); lpBuffersOut != NULL -> 87; dwStructSize != 0x38 -> 87;
 *    lpcszHeader converted (code page 65001) and handed to HttpWrapSendRequest(..., 0x11) with lpvBuffer /
 *    dwBufferLength / dwBufferTotal.
 *  - HttpSendRequestExA@0xd7f30: lpBuffersOut != NULL -> 87 before the handle is looked at; a NULL lpBuffersIn is
 *    allowed (HttpWrapSendRequest without buffers).
 *  - HttpEndRequestW@0xd88a0: NULL handle -> 6, lpBuffersOut != NULL -> 87, else HttpWrapSendRequest(..., 0x12)
 *    exactly like HttpEndRequestA.
 */
#include "ac.h"

static const DWORD SKIP_Y[] = { INTERNET_STATUS_HANDLE_CREATED, INTERNET_STATUS_HANDLE_CLOSING, AC_ST_330,
                                INTERNET_STATUS_COOKIE_SENT, INTERNET_STATUS_COOKIE_RECEIVED, INTERNET_STATUS_DETECTING_PROXY, 0 };

/* head now, body 800 ms later: nothing of the body is buffered when the send completes */
static const srv_step ST_Y_DELAYED[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"), S_SLEEP(800), S_SEND("hello"), S_LOOP() };

static int y_send(ac_flow *f, const srv_step *st, int n, const char *verb, const char *path) {
    if (!ac_flow_open(f, st, n, INTERNET_FLAG_ASYNC, ac_cb, verb, path, T_INET_FRESH)) return 0;
    int pending; DWORD err;
    if (!ac_send_wait(f->hr, CTX_REQ, NULL, NULL, 0, &pending, &err)) { t_check(0, __FILE__, __LINE__, "send", "err %lu", err); ac_flow_close(f); return 0; }
    return 1;
}

/* ================================================================== InternetReadFileEx[W] */
/* ExW forwards to ExA: the A struct-size rule applies to the W call too [D] */
TEST(ac_y_rfex_w_bad_struct_size) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExW));
    ac_begin(); ac_flow f;
    if (!y_send(&f, NULL, 0, "GET", "/ws")) return;
    static INTERNET_BUFFERSW ib; static char b[16];
    static const DWORD sizes[] = { 0, 0x37, 0x39, 0x70 };
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        memset(&ib, 0, sizeof ib); ib.dwStructSize = sizes[k]; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetReadFileExW)(f.hr, &ib, IRF_ASYNC, 0);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "dwStructSize 0x%lx: ok=%d err=%lu", sizes[k], ok, e);
    }
    EXPECT_EQ(sizeof(INTERNET_BUFFERSW), 0x38);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    /* the body is still there */
    char out[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, out, sizeof out, &np), 5);
    ac_flow_close(&f);
}
/* NULL handle: A reports the handle error; W checks its buffer argument first [D] */
TEST(ac_y_rfex_null_handle) {
    REQUIRE(U(InternetReadFileExA)); REQUIRE(U(InternetReadFileExW));
    static INTERNET_BUFFERSA ia; static INTERNET_BUFFERSW iw; static char b[8];
    memset(&ia, 0, sizeof ia); ia.dwStructSize = sizeof ia; ia.lpvBuffer = b; ia.dwBufferLength = sizeof b;
    memset(&iw, 0, sizeof iw); iw.dwStructSize = sizeof iw; iw.lpvBuffer = b; iw.dwBufferLength = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetReadFileExA)(NULL, &ia, IRF_ASYNC, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetReadFileExW)(NULL, &iw, IRF_ASYNC, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetReadFileExW)(NULL, NULL, IRF_ASYNC, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    iw.lpcszHeader = L"X: 1";
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetReadFileExW)(NULL, &iw, IRF_ASYNC, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
/* dwBufferLength 0 with nothing buffered: no FSM is started, the call succeeds at once with 0 bytes [D] */
TEST(ac_y_rfex_zero_length_completes_in_place) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!y_send(&f, ST_Y_DELAYED, 5, "GET", "/z0")) return;
    static INTERNET_BUFFERSA ib; static char b[16];
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = 0;
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, 0);
    DWORD e = GetLastError();
    t_note("ReadFileEx(len 0) with nothing buffered: ok=%d err=%lu len=%lu", ok, e, ib.dwBufferLength);
    CHECK(ok);
    EXPECT_EQ(ib.dwBufferLength, 0);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "");
    char out[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, out, sizeof out, &np), 5);
    EXPECT_STR(out, "hello");
    ac_flow_close(&f);
}
/* dwFlags is not validated [D]: an undefined flag bit behaves like IRF_ASYNC (pending, then one completion) */
TEST(ac_y_rfex_undefined_flags_accepted) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!y_send(&f, ST_Y_DELAYED, 5, "GET", "/uf")) return;
    static INTERNET_BUFFERSA ib; static char b[16];
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, 0x80000000u, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    if (!ok && e == ERROR_IO_PENDING) {
        CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r));
        EXPECT_EQ(r.dwResult, TRUE);
        EXPECT_EQ(ib.dwBufferLength, 5);
        CHECK(!memcmp(b, "hello", 5));
    }
    ac_flow_close(&f);
}
/* ExW in an async session: pending, completion on the request's context (not dwContext), buffer filled */
TEST(ac_y_rfex_w_async_pending) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExW));
    ac_begin(); ac_flow f;
    if (!y_send(&f, ST_Y_DELAYED, 5, "GET", "/wp")) return;
    static INTERNET_BUFFERSW ib; static char b[16];
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExW)(f.hr, &ib, IRF_ASYNC, CTX_ALT);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE); EXPECT_EQ(r.dwError, 0);
    EXPECT_EQ(ib.dwBufferLength, 5);
    CHECK(!memcmp(b, "hello", 5));
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st_ctx(0, CTX_ALT), 0);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "40,41,100");
    ac_flow_close(&f);
}
/* ReadFileEx on a connect handle: whatever the immediate result, the outcome is consistent (997 is followed by
 * exactly one completion, an immediate failure by none) and nothing is sent */
TEST(ac_y_rfex_on_connect_handle) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rc", T_INET_FRESH)) return;
    static INTERNET_BUFFERSA ib; static char b[16];
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hc, &ib, IRF_ASYNC, 0);
    DWORD e = GetLastError();
    t_note("ReadFileEx(connect handle): ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    EXPECT_EQ(ok, FALSE);
    if (e == ERROR_IO_PENDING) CHECK(ac_wait_st(INTERNET_STATUS_REQUEST_COMPLETE, 0, 1, 3000));
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), e == ERROR_IO_PENDING ? 1 : 0);
    EXPECT_EQ(srv_req_count(f.s), 0);
    ac_flow_close(&f);
}
/* QDA on a request that was never sent: consistent outcome, nothing on the wire */
TEST(ac_y_qda_before_send) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/qb", T_INET_FRESH)) return;
    static DWORD av; av = 0xdeadbeef;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    DWORD e = GetLastError();
    if (!ok && e == ERROR_IO_PENDING) CHECK(ac_wait_st(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, 1, 3000));
    ac_quiesce(100, 300);
    t_note("QDA before send (async): ok=%d err=%lu (%s) av=0x%lx events=%s", ok, e, t_inet_errname(e), av, ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), (!ok && e == ERROR_IO_PENDING) ? 1 : 0);
    EXPECT_EQ(srv_req_count(f.s), 0);
    ac_flow_close(&f);
}

/* ================================================================== HttpSendRequestEx / HttpEndRequest, NULL handles */
TEST(ac_y_sendex_a_null_handle_order) {
    REQUIRE(U(HttpSendRequestExA));
    static INTERNET_BUFFERSA out; memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    /* [D] lpBuffersOut is checked before the handle */
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExA)(NULL, NULL, &out, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    static INTERNET_BUFFERSA in; memset(&in, 0, sizeof in); in.dwStructSize = 4;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExA)(NULL, &in, NULL, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    /* valid arguments: the NULL handle reaches HttpWrapSendRequest, which fails with 6 (as HttpEndRequestA(NULL)) */
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExA)(NULL, NULL, NULL, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(ac_y_sendex_w_null_handle_first) {
    REQUIRE(U(HttpSendRequestExW));
    static INTERNET_BUFFERSW out, bad; memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    memset(&bad, 0, sizeof bad); bad.dwStructSize = 1;
    /* [D] W checks the handle first */
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExW)(NULL, NULL, &out, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExW)(NULL, &bad, NULL, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExW)(NULL, NULL, NULL, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(ac_y_sendex_w_param_checks) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestExW));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/wp", T_INET_FRESH)) return;
    static INTERNET_BUFFERSW in, out;
    memset(&in, 0, sizeof in); in.dwStructSize = sizeof in;
    memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExW)(f.hr, &in, &out, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpSendRequestExW)(f.hr, NULL, &out, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    static const DWORD sz[] = { 0, 0x28, 0x37, 0x39 };
    for (unsigned k = 0; k < sizeof sz / sizeof sz[0]; k++) {
        memset(&in, 0, sizeof in); in.dwStructSize = sz[k];
        SetLastError(0xdeadbeef);
        BOOL ok = U(HttpSendRequestExW)(f.hr, &in, NULL, 0, 0);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "dwStructSize 0x%lx: ok=%d err=%lu", sz[k], ok, e);
    }
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count(), n0);
    EXPECT_EQ(srv_req_count(f.s), 0);
    ac_flow_close(&f);
}
/* the W path end to end: SendRequestExW (headers in the struct) -> two writes -> EndRequestW */
TEST(ac_y_sendex_w_end_w_async) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestExW)); REQUIRE(U(HttpEndRequestW)); REQUIRE(U(InternetWriteFile));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "wgot"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/exw", T_INET_FRESH)) return;
    static INTERNET_BUFFERSW ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 6;
    ib.lpcszHeader = L"X-Ex: w\r\n"; ib.dwHeadersLength = (DWORD)-1;
    int c = 0, n0 = ac_count(); INTERNET_ASYNC_RESULT r;
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestExW)(f.hr, &ib, NULL, 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    ac_quiesce(50, 300);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,100");
    static DWORD wr; static char d1[] = "uvw", d2[] = "xyz";
    for (int k = 0; k < 2; k++) {
        wr = 0;
        SetLastError(0xdeadbeef);
        ok = U(InternetWriteFile)(f.hr, k ? d2 : d1, 3, &wr);
        if (!ok && GetLastError() == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); }
        CHECK(ok);
        EXPECT_EQ(wr, 3);
    }
    int n1 = ac_count();
    SetLastError(0xdeadbeef);
    ok = U(HttpEndRequestW)(f.hr, NULL, 0, 0);
    e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); EXPECT_EQ(r.dwError, 0); }
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(0, n1, -1, NULL), "40,41,100");
    EXPECT_EQ(ac_status_code(f.hr), 200);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn = 0; const char *b = srv_req_body(f.s, 0, &bn);
    CHECK(b && bn == 6 && !memcmp(b, "uvwxyz", 6));
    EXPECT_STR(srv_req_header(f.s, 0, "X-Ex"), "w");
    EXPECT_STR(srv_req_header(f.s, 0, "Content-Length"), "6");
    char out[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, out, sizeof out, &np), 4);
    ac_flow_close(&f);
}
/* HttpSendRequestExA with no INTERNET_BUFFERS at all, then HttpEndRequestA: both go pending and complete */
TEST(ac_y_sendex_null_buffers_async) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "nb"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/nb", T_INET_FRESH)) return;
    INTERNET_ASYNC_RESULT r; int c = 0;
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestExA)(f.hr, NULL, NULL, 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    SetLastError(0xdeadbeef);
    ok = U(HttpEndRequestA)(f.hr, NULL, 0, 0);
    e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    EXPECT_EQ(ac_status_code(f.hr), 200);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn = 99; srv_req_body(f.s, 0, &bn);
    EXPECT_EQ(bn, 0);
    EXPECT_STR(srv_req_method(f.s, 0), "POST");
    size_t hn = 0; t_note("SendRequestEx(NULL buffers) head: %s", srv_req_head_raw(f.s, 0, &hn));
    ac_flow_close(&f);
}
/* HttpEndRequestW on a request never started with HttpSendRequestEx behaves like the A call [D same wrapper] */
TEST(ac_y_endreq_w_without_sendex) {
    REQ_ASYNC_API(); REQUIRE(U(HttpEndRequestW));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/ew", T_INET_FRESH)) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpEndRequestW)(f.hr, NULL, 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(CTX_REQ, 1, 5000, &r));
    EXPECT_EQ(r.dwResult, FALSE);
    EXPECT_EQ(r.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
    ac_quiesce(100, 500);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "100");
    EXPECT_EQ(srv_req_count(f.s), 0);
    ac_flow_close(&f);
}
/* HttpSendRequestW with an optional body in an async session */
TEST(ac_y_sendrequest_w_async_post) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestW));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "pw"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/pw", T_INET_FRESH)) return;
    static char data[] = "k=v&w=1";
    int n0 = ac_count(), c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestW)(f.hr, L"X-Wb: 2\r\n", (DWORD)-1, data, 7);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn = 0, hn = 0; const char *b = srv_req_body(f.s, 0, &bn); srv_req_head_raw(f.s, 0, &hn);
    CHECK(b && bn == 7 && !memcmp(b, "k=v&w=1", 7));
    EXPECT_STR(srv_req_header(f.s, 0, "X-Wb"), "2");
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    int i = ac_find(INTERNET_STATUS_REQUEST_SENT, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) CHECKF(ac_info_dword(&ev) == hn + 7, "REQUEST_SENT %lu head %zu", ac_info_dword(&ev), hn);
    else CHECK(i >= 0);
    ac_flow_close(&f);
}

/* ================================================================== contexts */
/* CONTEXT_VALUE changed before the send: every status of the send carries the new value */
TEST(ac_y_context_set_before_send) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/cb", T_INET_FRESH)) return;
    DWORD_PTR nv = CTX_ALT;
    CHECK(U(InternetSetOptionA)(f.hr, INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv));
    int n0 = ac_count();
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_ALT, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(pending, 1);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(CTX_ALT, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    EXPECT_STR(ac_seq_range(CTX_REQ, n0, -1, NULL), "");
    for (int i = n0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); CHECKF(ev.h == f.hr, "event %d st %lu on another handle", i, ev.st); }
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_ALT, 1, 2000));
    ac_flow_close(&f);
}
static volatile LONG g_y_setctx;
static void hook_setctx_in_created(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)h;
    if (st != INTERNET_STATUS_HANDLE_CREATED || ctx != CTX_REQ || !info || len < sizeof(HINTERNET)) return;
    HINTERNET nh; memcpy(&nh, info, sizeof nh);
    DWORD_PTR nv = CTX_ALT;
    if (U(InternetSetOptionA)(nh, INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv)) InterlockedIncrement(&g_y_setctx);
}
/* the new handle named in HANDLE_CREATED is usable from inside the callback: setting its context there redirects
 * every later status */
TEST(ac_y_reentrant_set_context_in_created) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin(); g_y_setctx = 0;
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    ac_hook = hook_setctx_in_created;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/sc", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ) : NULL;
    ac_hook = NULL;
    CHECK(hr != NULL);
    EXPECT_EQ(g_y_setctx, 1);
    int n0 = ac_count(), pending; DWORD err;
    if (hr) CHECK(ac_send_wait(hr, CTX_ALT, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(CTX_ALT, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_REQ), 1);
    EXPECT_STR(ac_seq_range(CTX_REQ, n0, -1, NULL), "");
    if (hr) ac_close_wait(hr, CTX_ALT);
    ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* ================================================================== calls from inside the callback */
static struct { HINTERNET hc, hr; volatile LONG fired; BOOL ret; DWORD err; HANDLE ev; } g_yr;
static void hook_close_parent_in_complete(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)h; (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && InterlockedIncrement(&g_yr.fired) == 1) {
        SetLastError(0xdeadbeef);
        g_yr.ret = U(InternetCloseHandle)(g_yr.hc); g_yr.err = GetLastError();
        SetEvent(g_yr.ev);
    }
}
/* closing the CONNECT handle from inside the request's REQUEST_COMPLETE closes both; the request closes first */
TEST(ac_y_reentrant_close_connect_in_complete) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/cp", T_INET_FRESH)) return;
    memset(&g_yr, 0, sizeof g_yr); g_yr.hc = f.hc; g_yr.hr = f.hr; g_yr.ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    ac_hook = hook_close_parent_in_complete;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_yr.ev, 8000), WAIT_OBJECT_0);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 3000));
    ac_hook = NULL;
    ac_quiesce(100, 500);
    EXPECT_EQ(g_yr.ret, TRUE);
    t_note("close connect inside REQUEST_COMPLETE: ret=%d err=%lu seq=%s", g_yr.ret, g_yr.err, ac_seq(0, NULL));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    int ir = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 0), ic = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 0);
    int ip = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, 0);
    CHECKF(ip >= 0 && ip < ir && ir < ic, "complete@%d req-closing@%d con-closing@%d", ip, ir, ic);
    /* both handles are gone */
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetCloseHandle)(f.hr)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    f.hr = f.hc = NULL;
    CloseHandle(g_yr.ev);
    ac_flow_close(&f);
}
static void hook_read_in_sent(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_SENT && ctx == CTX_REQ && InterlockedIncrement(&g_yr.fired) == 1) {
        static char b[8]; static DWORD rd;
        SetLastError(0xdeadbeef);
        g_yr.ret = U(InternetReadFile)(h, b, sizeof b, &rd); g_yr.err = GetLastError();
    }
}
/* InternetReadFile from inside REQUEST_SENT (the send is still in progress): Win10 accepts it (TRUE/0, unlike a read after a pending send); the send then completes normally */
TEST(ac_y_reentrant_read_in_request_sent) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rs", T_INET_FRESH)) return;
    memset(&g_yr, 0, sizeof g_yr);
    ac_hook = hook_read_in_sent;
    int pending; DWORD err;
    int ok = ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err);
    ac_hook = NULL;
    t_note("read inside REQUEST_SENT: ret=%d err=%lu (%s); send ok=%d err=%lu", g_yr.ret, g_yr.err, t_inet_errname(g_yr.err), ok, err);
    EXPECT_EQ(g_yr.fired, 1);
    /* Win10 triage: the read inside REQUEST_SENT returns TRUE/0 (not rejected); outcome noted only */
    CHECK(ok);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    char b[16]; int np;
    ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np);
    ac_flow_close(&f);
}
static volatile LONG g_y_sesrm; static INTERNET_STATUS_CALLBACK g_y_sesprev; static HINTERNET g_y_ses;
static void hook_remove_session_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)h; (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && InterlockedIncrement(&g_y_sesrm) == 1)
        g_y_sesprev = U(InternetSetStatusCallbackA)(g_y_ses, NULL);
}
/* removing the SESSION's callback from inside a request's completion does not affect the request or its connect
 * handle (each holds its own copy taken at creation): their HANDLE_CLOSING statuses still arrive */
TEST(ac_y_reentrant_remove_session_cb_children_keep) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f; g_y_sesrm = 0; g_y_sesprev = NULL;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rm", T_INET_FRESH)) return;
    g_y_ses = f.hi;
    ac_hook = hook_remove_session_cb;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(50, 300);
    ac_hook = NULL;
    EXPECT_EQ(g_y_sesrm, 1);
    EXPECT_EQ(g_y_sesprev, ac_cb);
    void *p = (void *)1; DWORD l = sizeof p;
    CHECK(U(InternetQueryOptionA)(f.hi, INTERNET_OPTION_CALLBACK, &p, &l)); EXPECT_EQ(p, NULL);
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 2000));
    U(InternetCloseHandle)(f.hc); f.hc = NULL;
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 2000));
    ac_flow_close(&f);
}

/* ================================================================== exact sequences */
TEST(ac_y_async_head_sequence) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "HEAD", "/hs", T_INET_FRESH)) return;
    int n0 = ac_count(), pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(pending, 1);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    EXPECT_EQ(ac_status_code(f.hr), 200);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    EXPECT_STR(srv_req_method(f.s, 0), "HEAD");
    ac_flow_close(&f);
}
/* a "Connection: close" reply: the next request on the same connect handle opens a new connection (20,21 again) */
TEST(ac_y_conn_close_then_new_connection) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "one", SRV_R_CONN_CLOSE) };
    ac_begin(); ac_flow f;
    if (!y_send(&f, st, 2, "GET", "/c1")) return;
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 3);
    ac_close_wait(f.hr, CTX_REQ);
    f.hr = U(HttpOpenRequestA)(f.hc, "GET", "/c2", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ);
    CHECK(f.hr != NULL); if (!f.hr) { ac_flow_close(&f); return; }
    int n0 = ac_count(), pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    t_note("request after Connection: close: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    CHECK(srv_wait_requests(f.s, 2, 2000));
    EXPECT_EQ(srv_conn_count(f.s), 2);
    CHECK(srv_req_conn(f.s, 0) != srv_req_conn(f.s, 1));
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 3);
    ac_flow_close(&f);
}
/* synchronous InternetOpenUrl following a redirect: every status on the calling thread, no REQUEST_COMPLETE */
TEST(ac_y_openurl_sync_redirect_sequence) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /to\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "to"), S_LOOP_TO(2) };
    srv *s; SRV_OR_SKIP(s, srv_http(st, 5));
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/from"), NULL, 0, T_INET_FRESH, CTX_URL);
    CHECK(hu != NULL);
    t_note("sync openurl redirect: %s", ac_seq(0, NULL));
    EXPECT_STR(ac_seq(0, NULL), "60,80,20,21,30,31,40,41,110,80,30,31,40,41");
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_URL, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) { EXPECT_STR((char *)ev.info, srv_url(s, "/to")); EXPECT_EQ(ev.len, strlen(srv_url(s, "/to")) + 1); }
    else CHECK(i >= 0);
    if (hu) {
        EXPECT_EQ(ac_status_code(hu), 200);
        ac_close_wait(hu, CTX_URL);
    }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
/* W callback, async InternetOpenUrlA with a redirect: REDIRECT arrives as UTF-16 with the length in characters */
TEST(ac_y_openurl_async_w_redirect_wide) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetSetStatusCallbackW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /wide\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "w"), S_LOOP_TO(2) };
    srv *s; SRV_OR_SKIP(s, srv_http(st, 5));
    ac_begin();
    HINTERNET hi = ac_open(INTERNET_FLAG_ASYNC);
    EXPECT_EQ(U(InternetSetStatusCallbackW)(hi, ac_cbw), NULL);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/narrow"), NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    CHECK(r.dwResult != 0);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq(0, NULL), "60,80,20,21,30,31,40,41,110,80,30,31,40,41,100");
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_URL, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        WCHAR want[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(s, "/wide"), -1, want, 128);
        EXPECT_EQ(ev.wide, 1);
        EXPECT_WSTR((const WCHAR *)ev.info, want);
        EXPECT_EQ(ev.len, (DWORD)lstrlenW(want));
    } else CHECK(i >= 0);
    for (int k = 0; k < ac_count(); k++) { ac_get(k, &ev); CHECKF(ev.wide == 1, "event %d st %lu not on the W callback", k, ev.st); }
    if (r.dwResult) ac_close_wait((HINTERNET)r.dwResult, CTX_URL);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
/* synchronous session with a W callback: REDIRECT is converted there too (the wrapper does not look at the mode) */
TEST(ac_y_sync_w_callback_redirect_wide) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /sw\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "s"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, 0, NULL, "GET", "/sy", T_INET_FRESH)) return;
    EXPECT_EQ(U(InternetSetStatusCallbackW)(f.hr, ac_cbw), NULL);
    int n0 = ac_count();
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,110,80,30,31,40,41");
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        WCHAR want[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(f.s, "/sw"), -1, want, 128);
        EXPECT_EQ(ev.wide, 1);
        EXPECT_WSTR((const WCHAR *)ev.info, want);
        EXPECT_EQ(ev.len, (DWORD)lstrlenW(want));
    } else CHECK(i >= 0);
    ac_flow_close(&f);
}
/* async redirect: everything after HANDLE_CREATED, including the REDIRECT and the second send, comes from WinINet
 * worker threads */
TEST(ac_y_async_redirect_all_on_workers) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /w2\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "w2"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/w1", T_INET_FRESH)) return;
    int n0 = ac_count(), pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    int on_main = 0;
    for (int i = n0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); if (ev.tid == ac_main_tid) on_main++; }
    EXPECT_EQ(on_main, 0);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REDIRECT, CTX_REQ), 1);
    ac_flow_close(&f);
}
/* the URL handle from an async InternetOpenUrl carries the session callback; removing it there silences its close */
TEST(ac_y_openurl_handle_callback_removed) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/cbr"), NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    HINTERNET h = (HINTERNET)r.dwResult;
    CHECK(h != NULL);
    if (h) {
        char b[16]; int np;
        EXPECT_EQ(ac_read_all_async(h, CTX_URL, b, sizeof b, &np), 5);
        EXPECT_EQ(U(InternetSetStatusCallbackA)(h, NULL), ac_cb);
        int n0 = ac_count();
        CHECK(U(InternetCloseHandle)(h));
        ac_quiesce(100, 400);
        t_note("after closing the URL handle without its callback: %s", ac_seq_range(0, n0, -1, NULL));
        /* nothing for the URL handle itself (its internal parent connect handle is not asserted) */
        EXPECT_EQ(ac_find_h(INTERNET_STATUS_HANDLE_CLOSING, h, n0), -1);
        for (int i = n0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); CHECKF(ev.h != h, "event %d st %lu for the URL handle", i, ev.st); }
    }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
