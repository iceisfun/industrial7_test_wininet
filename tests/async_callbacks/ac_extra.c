/* ac_extra.c - async mode, second pass: parameter validation grounded in the decompilation (HttpEndRequest,
 * InternetQueryDataAvailable), calls made from inside the status callback (close, query, replace, send another
 * request), event-driven state machines (the pattern an application uses: the callback signals, the main thread
 * waits with a bounded timeout), closing handles with reads/QDA pending, many requests in flight with distinct
 * contexts, POST/header size tables against REQUEST_SENT, buffer-size tables for async reads, decoding, HEAD/204,
 * redirect chains and InternetOpenUrl with redirects/headers. Every peer is an in-process loopback server. */
#include "ac.h"

/* VM_TIMEOUT: 300 */

static const DWORD SKIP_X[] = { INTERNET_STATUS_HANDLE_CREATED, INTERNET_STATUS_HANDLE_CLOSING, AC_ST_330,
                                INTERNET_STATUS_COOKIE_SENT, INTERNET_STATUS_COOKIE_RECEIVED, INTERNET_STATUS_DETECTING_PROXY,
                                INTERNET_STATUS_RESOLVING_NAME, INTERNET_STATUS_NAME_RESOLVED, 0 };

static int x_send(ac_flow *f, const srv_step *st, int n, DWORD sflags, const char *verb, const char *path) {
    if (!ac_flow_open(f, st, n, sflags, ac_cb, verb, path, T_INET_FRESH)) return 0;
    int pending; DWORD err;
    if (!ac_send_wait(f->hr, CTX_REQ, NULL, NULL, 0, &pending, &err)) { t_check(0, __FILE__, __LINE__, "send", "err %lu", err); ac_flow_close(f); return 0; }
    return 1;
}
/* read the whole body with a fixed buffer size; returns total or -1 */
static long x_read_all_bs(HINTERNET hr, DWORD_PTR ctx, DWORD bs, char *out, size_t cap, int *npend, int *nsync) {
    static char chunk[65536]; static DWORD rd;
    long tot = 0; *npend = 0; *nsync = 0;
    if (bs > sizeof chunk) bs = sizeof chunk;
    for (int guard = 0; guard < 200000; guard++) {
        int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, ctx);
        rd = 0xdeadbeef;
        BOOL ok = U(InternetReadFile)(hr, chunk, bs, &rd);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) return -1;
            (*npend)++;
            INTERNET_ASYNC_RESULT r;
            if (!ac_wait_complete(ctx, c0 + 1, 8000, &r) || !r.dwResult) return -1;
        } else (*nsync)++;
        if (rd == 0) break;
        if (rd > bs) return -1;
        if (out && (size_t)tot + rd <= cap) memcpy(out + tot, chunk, rd);
        tot += rd;
    }
    return tot;
}

/* ================================================================== parameter validation [D] */
/* HttpEndRequestA@0xd46c0: lpBuffersOut != NULL -> SetLastError(87), FALSE, before touching the handle */
TEST(ac_x_endreq_a_buffersout_rejected) {
    REQ_ASYNC_API(); REQUIRE(U(HttpEndRequestA));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/e", T_INET_FRESH)) return;
    static INTERNET_BUFFERSA out; memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpEndRequestA)(f.hr, &out, 0, 0);
    EXPECT_EQ(ok, FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count(), n0);
    EXPECT_EQ(srv_req_count(f.s), 0);
    ac_flow_close(&f);
}
/* HttpEndRequestW@0xd88a0: same rule */
TEST(ac_x_endreq_w_buffersout_rejected) {
    REQ_ASYNC_API(); REQUIRE(U(HttpEndRequestW));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/e", T_INET_FRESH)) return;
    static INTERNET_BUFFERSW out; memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpEndRequestW)(f.hr, &out, 0, 0);
    EXPECT_EQ(ok, FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count(), n0);
    ac_flow_close(&f);
}
/* HttpEndRequestW@0xd88a0: NULL handle -> 6 (checked before lpBuffersOut) */
TEST(ac_x_endreq_w_null_handle) {
    REQUIRE(U(HttpEndRequestW));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpEndRequestW)(NULL, NULL, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
    static INTERNET_BUFFERSW out; memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpEndRequestW)(NULL, &out, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_HANDLE);
}
/* HttpEndRequestA with a NULL handle goes to HttpWrapSendRequest(NULL) */
TEST(ac_x_endreq_a_null_handle) {
    REQUIRE(U(HttpEndRequestA));
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpEndRequestA)(NULL, NULL, 0, 0);
    DWORD e = GetLastError();
    t_note("HttpEndRequestA(NULL): ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    EXPECT_EQ(ok, FALSE);
    CHECKF(e == ERROR_INVALID_HANDLE || e == ERROR_INTERNET_INVALID_OPERATION, "err %lu", e);
    /* A checks lpBuffersOut first: a non-NULL out pointer gives 87 even with a NULL handle [D] */
    static INTERNET_BUFFERSA out; memset(&out, 0, sizeof out); out.dwStructSize = sizeof out;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpEndRequestA)(NULL, &out, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
/* HttpEndRequest on a request that was never started with HttpSendRequestEx, async session */
TEST(ac_x_endreq_without_sendex) {
    REQ_ASYNC_API(); REQUIRE(U(HttpEndRequestA));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/e", T_INET_FRESH)) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpEndRequestA)(f.hr, NULL, 0, 0);
    DWORD e = GetLastError();
    t_note("HttpEndRequest without SendRequestEx: ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    EXPECT_EQ(ok, FALSE);
    if (e == ERROR_IO_PENDING) {
        INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(CTX_REQ, 1, 5000, &r));
        t_note("  completion dwResult=%llu dwError=%lu (%s)", (unsigned long long)r.dwResult, r.dwError, t_inet_errname(r.dwError));
    }
    ac_quiesce(100, 500);
    t_note("  statuses: %s, requests at server %d", ac_seq_range(0, n0, -1, NULL), srv_req_count(f.s));
    ac_flow_close(&f);
}
/* InternetQueryDataAvailable@0x76b20: valid handle, lpdwNumberOfBytesAvailable == NULL -> 87 */
TEST(ac_x_qda_null_out_param) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!x_send(&f, NULL, 0, INTERNET_FLAG_ASYNC, "GET", "/q")) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetQueryDataAvailable)(f.hr, NULL, 0, 0), FALSE); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ac_quiesce(100, 300);
    t_note("events after QDA(NULL): %s", ac_seq_range(0, n0, -1, NULL));
    /* the request is still usable */
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    ac_flow_close(&f);
}
TEST(ac_x_qda_null_handle) {
    REQUIRE(U(InternetQueryDataAvailable));
    static DWORD av; av = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(NULL, &av, 0, 0);
    DWORD e = GetLastError();
    t_note("QDA(NULL handle): ok=%d err=%lu av=0x%lx", ok, e, av);
    EXPECT_EQ(ok, FALSE);
    CHECKF(e == ERROR_INVALID_HANDLE || e == ERROR_INTERNET_INVALID_OPERATION, "err %lu", e);
}
/* QDA on a connect handle (not a request) */
TEST(ac_x_qda_on_connect_handle) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/q", T_INET_FRESH)) return;
    static DWORD av; av = 0xdeadbeef;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hc, &av, 0, 0);
    DWORD e = GetLastError();
    t_note("QDA(connect handle): ok=%d err=%lu (%s) av=0x%lx", ok, e, t_inet_errname(e), av);
    EXPECT_EQ(ok, FALSE);
    CHECK(e != ERROR_IO_PENDING);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    t_note("  events: %s", ac_seq_range(0, n0, -1, NULL));
    ac_flow_close(&f);
}
/* InternetReadFile on a connect handle in an async session */
TEST(ac_x_read_on_connect_handle) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/q", T_INET_FRESH)) return;
    static char b[8]; static DWORD rd; rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hc, b, sizeof b, &rd);
    DWORD e = GetLastError();
    t_note("InternetReadFile(connect handle): ok=%d err=%lu (%s) rd=0x%lx", ok, e, t_inet_errname(e), rd);
    EXPECT_EQ(ok, FALSE);
    CHECK(e != ERROR_IO_PENDING);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    ac_flow_close(&f);
}
/* HttpSendRequest on a connect handle in an async session: synchronous failure, no completion */
TEST(ac_x_send_on_connect_handle) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/q", T_INET_FRESH)) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestA)(f.hc, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    t_note("HttpSendRequest(connect handle): ok=%d err=%lu (%s)", ok, e, t_inet_errname(e));
    EXPECT_EQ(ok, FALSE);
    CHECK(e != ERROR_IO_PENDING);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    t_note("  events: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(srv_req_count(f.s), 0);
    ac_flow_close(&f);
}

/* ================================================================== calls from inside the callback */
static struct { HINTERNET hr, hr2; volatile LONG fired; BOOL ret; DWORD err; DWORD val; INTERNET_STATUS_CALLBACK prev; HANDLE ev; } g_re;
static void re_reset(void) { memset(&g_re, 0, sizeof g_re); g_re.ev = CreateEventA(NULL, TRUE, FALSE, NULL); }
static void re_done(void) { if (g_re.ev) CloseHandle(g_re.ev); g_re.ev = NULL; }

static void hook_close_in_complete(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && h == g_re.hr && InterlockedIncrement(&g_re.fired) == 1) {
        SetLastError(0xdeadbeef);
        g_re.ret = U(InternetCloseHandle)(h); g_re.err = GetLastError();
        SetEvent(g_re.ev);
    }
}
TEST(ac_x_reentrant_close_in_complete) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rc", T_INET_FRESH)) { re_done(); return; }
    g_re.hr = f.hr; ac_hook = hook_close_in_complete;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_re.ev, 8000), WAIT_OBJECT_0);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 3000));
    ac_hook = NULL;
    ac_quiesce(100, 500);
    EXPECT_EQ(g_re.ret, TRUE);
    t_note("close inside REQUEST_COMPLETE: ret=%d err=%lu; seq %s", g_re.ret, g_re.err, ac_seq(CTX_REQ, NULL));
    /* HANDLE_CLOSING of the request comes after its REQUEST_COMPLETE */
    CHECK(ac_before(INTERNET_STATUS_REQUEST_COMPLETE, INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    f.hr = NULL;    /* closed by the hook */
    ac_flow_close(&f); re_done();
}
static void hook_query_in_complete(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && InterlockedIncrement(&g_re.fired) == 1) {
        DWORD v = 0, l = sizeof v;
        SetLastError(0xdeadbeef);
        g_re.ret = U(HttpQueryInfoA)(h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &v, &l, NULL);
        g_re.err = GetLastError(); g_re.val = v;
        SetEvent(g_re.ev);
    }
}
TEST(ac_x_reentrant_query_info_in_complete) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(203, NULL, "nai"), S_LOOP() };
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rq", T_INET_FRESH)) { re_done(); return; }
    ac_hook = hook_query_in_complete;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_re.ev, 8000), WAIT_OBJECT_0);
    ac_hook = NULL;
    EXPECT_EQ(g_re.ret, TRUE);
    EXPECT_EQ(g_re.val, 203);
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 3);
    ac_flow_close(&f); re_done();
}
static void hook_ctx_query(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_HANDLE_CLOSING || st == INTERNET_STATUS_HANDLE_CREATED) return;
    DWORD_PTR v = 0; DWORD l = sizeof v;
    if (U(InternetQueryOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &v, &l) && v == ctx) InterlockedIncrement((LONG *)&g_re.val);
    else InterlockedIncrement(&g_re.fired);
}
/* every status of the send arrives with hInternet whose CONTEXT_VALUE equals dwContext, queryable from inside */
TEST(ac_x_reentrant_context_query_every_status) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/cq", T_INET_FRESH)) { re_done(); return; }
    ac_hook = hook_ctx_query;
    int n0 = ac_count();
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    ac_hook = NULL;
    int n = ac_count() - n0;
    EXPECT_EQ(g_re.fired, 0);
    EXPECT_EQ((int)g_re.val, n);
    EXPECT_EQ(n, 8);
    ac_flow_close(&f); re_done();
}
static void hook_remove_cb_in_complete(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && InterlockedIncrement(&g_re.fired) == 1) {
        SetLastError(0xdeadbeef);
        g_re.prev = U(InternetSetStatusCallbackA)(h, NULL); g_re.err = GetLastError();
        SetEvent(g_re.ev);
    }
}
/* removing the request's callback from inside its REQUEST_COMPLETE: returns the old one; later statuses
 * (HANDLE_CLOSING of the request) are not delivered, the connect handle's still are */
TEST(ac_x_reentrant_remove_callback_in_complete) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rr", T_INET_FRESH)) { re_done(); return; }
    ac_hook = hook_remove_cb_in_complete;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_re.ev, 8000), WAIT_OBJECT_0);
    ac_hook = NULL;
    EXPECT_EQ(g_re.prev, ac_cb);
    EXPECT_EQ(g_re.err, 0);
    char b[16]; static DWORD rd; rd = 0;
    Sleep(100);
    int n0 = ac_count();
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    t_note("read after removing callback: ok=%d err=%lu rd=%lu", ok, GetLastError(), rd);
    if (!ok && GetLastError() == ERROR_IO_PENDING) Sleep(1500);
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    ac_quiesce(100, 500);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 0);
    for (int i = n0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); CHECKF(ev.ctx != CTX_REQ, "event %d st=%lu after removal", i, ev.st); }
    ac_close_wait(f.hc, CTX_CON); f.hc = NULL;
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    ac_flow_close(&f); re_done();
}
static void hook_send_second(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)h; (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && InterlockedIncrement(&g_re.fired) == 1) {
        SetLastError(0xdeadbeef);
        g_re.ret = U(HttpSendRequestA)(g_re.hr2, NULL, 0, NULL, 0); g_re.err = GetLastError();
        SetEvent(g_re.ev);
    }
}
/* starting another request from inside a completion is allowed and goes pending */
TEST(ac_x_reentrant_send_other_request) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/one", T_INET_FRESH)) { re_done(); return; }
    g_re.hr2 = U(HttpOpenRequestA)(f.hc, "GET", "/two", NULL, NULL, NULL, T_INET_FRESH, CTX_ALT);
    CHECK(g_re.hr2 != NULL);
    ac_hook = hook_send_second;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_re.ev, 8000), WAIT_OBJECT_0);
    ac_hook = NULL;
    t_note("send from inside the callback: ret=%d err=%lu", g_re.ret, g_re.err);
    EXPECT_EQ(g_re.ret, FALSE); EXPECT_EQ(g_re.err, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT res;
    CHECK(ac_wait_complete(CTX_ALT, 1, 8000, &res));
    EXPECT_EQ(res.dwResult, TRUE); EXPECT_EQ(res.dwError, 0);
    EXPECT_EQ(ac_status_code(g_re.hr2), 200);
    CHECK(srv_wait_requests(f.s, 2, 2000));
    EXPECT_STR(srv_req_target(f.s, 0), "/one");
    EXPECT_STR(srv_req_target(f.s, 1), "/two");
    ac_quiesce(100, 300);
    t_note("second request statuses: %s (server connections %d)", ac_seq(CTX_ALT, NULL), srv_conn_count(f.s));
    ac_close_wait(g_re.hr2, CTX_ALT);
    ac_flow_close(&f); re_done();
}
static void hook_qda_in_complete(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && ctx == CTX_REQ && InterlockedIncrement(&g_re.fired) == 1) {
        static DWORD av; av = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        g_re.ret = U(InternetQueryDataAvailable)(h, &av, 0, 0); g_re.err = GetLastError(); g_re.val = av;
        SetEvent(g_re.ev);
    }
}
TEST(ac_x_reentrant_qda_in_complete) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/qq", T_INET_FRESH)) { re_done(); return; }
    ac_hook = hook_qda_in_complete;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_re.ev, 8000), WAIT_OBJECT_0);
    ac_hook = NULL;
    t_note("QDA inside send completion: ret=%d err=%lu av=%lu", g_re.ret, g_re.err, g_re.val);
    if (g_re.ret) EXPECT_EQ(g_re.val, 5);
    else { EXPECT_EQ(g_re.err, ERROR_IO_PENDING); CHECK(ac_wait_complete(CTX_REQ, 2, 5000, NULL)); }
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    ac_flow_close(&f); re_done();
}
static void hook_replace_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)info; (void)len;
    if (st == INTERNET_STATUS_REQUEST_SENT && ctx == CTX_REQ && InterlockedIncrement(&g_re.fired) == 1) {
        g_re.prev = U(InternetSetStatusCallbackA)(h, ac_cb2); g_re.err = GetLastError();
    }
}
/* replacing the callback from inside REQUEST_SENT: the remaining statuses (40,41,100) go to the new callback */
TEST(ac_x_reentrant_replace_callback_mid_send) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f; re_reset();
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rp", T_INET_FRESH)) { re_done(); return; }
    ac_hook = hook_replace_cb;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    ac_hook = NULL;
    EXPECT_EQ(g_re.prev, ac_cb);
    EXPECT_EQ(g_re.err, 0);
    /* collect which recorder each status went to */
    char a[128] = "", b2[128] = ""; size_t na = 0, nb = 0;
    for (int i = 0; i < ac_count(); i++) {
        ac_ev ev; ac_get(i, &ev); if (ev.ctx != CTX_REQ || ev.st == INTERNET_STATUS_HANDLE_CREATED) continue;
        if (ev.wide == 2) nb += snprintf(b2 + nb, sizeof b2 - nb, "%s%lu", nb ? "," : "", ev.st);
        else na += snprintf(a + na, sizeof a - na, "%s%lu", na ? "," : "", ev.st);
    }
    t_note("old callback: %s / new callback: %s", a, b2);
    EXPECT_STR(a, "80,20,21,30,31");
    EXPECT_STR(b2, "40,41,100");
    ac_flow_close(&f); re_done();
}

/* ================================================================== event-driven state machine */
/* The application pattern: the callback advances a state machine and signals an event; the main thread only
 * waits (bounded). GET + full body read, every read started from the callback or after its signal. */
static struct {
    HINTERNET hr; HANDLE ev; volatile LONG state; /* 0 sending, 1 reading, 2 done, 3 failed */
    char buf[256]; DWORD len; char chunk[4]; DWORD rd; volatile LONG completions, inline_reads;
} g_sm;
static void sm_pump(void) {
    for (int guard = 0; guard < 1000; guard++) {
        g_sm.rd = 0;
        if (!U(InternetReadFile)(g_sm.hr, g_sm.chunk, sizeof g_sm.chunk, &g_sm.rd)) {
            if (GetLastError() != ERROR_IO_PENDING) { g_sm.state = 3; SetEvent(g_sm.ev); }
            return;    /* the completion continues the machine */
        }
        InterlockedIncrement(&g_sm.inline_reads);
        if (g_sm.rd == 0) { g_sm.state = 2; SetEvent(g_sm.ev); return; }
        if (g_sm.len + g_sm.rd < sizeof g_sm.buf) { memcpy(g_sm.buf + g_sm.len, g_sm.chunk, g_sm.rd); g_sm.len += g_sm.rd; }
    }
    g_sm.state = 3; SetEvent(g_sm.ev);
}
static void hook_sm(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    (void)h;
    if (st != INTERNET_STATUS_REQUEST_COMPLETE || ctx != CTX_REQ || !info || len < sizeof(INTERNET_ASYNC_RESULT)) return;
    InterlockedIncrement(&g_sm.completions);
    INTERNET_ASYNC_RESULT *r = (INTERNET_ASYNC_RESULT *)info;
    if (!r->dwResult) { g_sm.state = 3; SetEvent(g_sm.ev); return; }
    if (g_sm.state == 0) { g_sm.state = 1; sm_pump(); return; }
    if (g_sm.state == 1) {
        if (g_sm.rd == 0) { g_sm.state = 2; SetEvent(g_sm.ev); return; }
        if (g_sm.len + g_sm.rd < sizeof g_sm.buf) { memcpy(g_sm.buf + g_sm.len, g_sm.chunk, g_sm.rd); g_sm.len += g_sm.rd; }
        sm_pump();
    }
}
static int sm_run(const srv_step *st, int n, const char *path, const char *want) {
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, n, INTERNET_FLAG_ASYNC, ac_cb, "GET", path, T_INET_FRESH)) return 0;
    memset(&g_sm, 0, sizeof g_sm); g_sm.hr = f.hr; g_sm.ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    ac_hook = hook_sm;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    DWORD w = WaitForSingleObject(g_sm.ev, 10000);
    ac_hook = NULL;
    EXPECT_EQ(w, WAIT_OBJECT_0);
    EXPECT_EQ(g_sm.state, 2);
    g_sm.buf[g_sm.len] = 0;
    if (want) { EXPECT_EQ(g_sm.len, strlen(want)); EXPECT_STR(g_sm.buf, want); }
    t_note("state machine %s: len=%lu completions=%ld inline=%ld", path, g_sm.len, g_sm.completions, g_sm.inline_reads);
    CloseHandle(g_sm.ev);
    ac_quiesce(100, 300);
    ac_flow_close(&f);
    return 1;
}
TEST(ac_x_sm_get_buffered_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "state-machine-body"), S_LOOP() };
    sm_run(st, 3, "/sm1", "state-machine-body");
}
TEST(ac_x_sm_get_trickled_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"), S_SPLIT("abcdefghijklmnopqrst", 3, 60), S_LOOP() };
    sm_run(st, 4, "/sm2", "abcdefghijklmnopqrst");
    CHECK(g_sm.completions >= 2);
}
TEST(ac_x_sm_get_chunked_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, NULL, "chunky-state-machine-payload", 5), S_LOOP() };
    sm_run(st, 3, "/sm3", "chunky-state-machine-payload");
}
TEST(ac_x_sm_get_close_delimited) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\nuntil"), S_SLEEP(200), S_SEND("-close"), S_CLOSE() };
    sm_run(st, 5, "/sm4", "until-close");
}
TEST(ac_x_sm_get_empty_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, ""), S_LOOP() };
    sm_run(st, 3, "/sm5", "");
}
TEST(ac_x_sm_get_404_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(404, NULL, "missing"), S_LOOP() };
    sm_run(st, 3, "/sm6", "missing");
}
/* a failing send drives the machine to the failed state through REQUEST_COMPLETE(FALSE) */
TEST(ac_x_sm_failure_reported) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_RESET() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 2, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/smf", T_INET_FRESH)) return;
    memset(&g_sm, 0, sizeof g_sm); g_sm.hr = f.hr; g_sm.ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    ac_hook = hook_sm;
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    EXPECT_EQ(WaitForSingleObject(g_sm.ev, 10000), WAIT_OBJECT_0);
    ac_hook = NULL;
    EXPECT_EQ(g_sm.state, 3);
    EXPECT_EQ(g_sm.completions, 1);
    INTERNET_ASYNC_RESULT res; CHECK(ac_wait_complete(CTX_REQ, 1, 10, &res));
    EXPECT_EQ(res.dwResult, FALSE);
    EXPECT_EQ(res.dwError, ERROR_INTERNET_CONNECTION_RESET);
    CloseHandle(g_sm.ev);
    ac_flow_close(&f);
}

/* ================================================================== closing with operations pending */
static const srv_step ST_SLOW_HEAD[] = { S_HEAD(), S_SLEEP(1500), S_REPLY(200, NULL, "late"), S_LOOP() };
static const srv_step ST_SLOW_BODY[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"), S_SLEEP(1500), S_SEND("body"), S_LOOP() };

/* close the connect handle (not the request) while the request's send is pending */
TEST(ac_x_close_connect_with_send_pending) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, ST_SLOW_HEAD, 4, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/cc", T_INET_FRESH)) return;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    srv_wait_requests(f.s, 1, 3000);
    int n0 = ac_count();
    EXPECT_EQ(U(InternetCloseHandle)(f.hc), TRUE); f.hc = NULL;
    ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 4000);
    ac_quiesce(200, 2500);
    t_note("close connect with send pending: %s", ac_seq_range(0, n0, -1, NULL));
    ac_dump("close connect pending");
    INTERNET_ASYNC_RESULT res;
    if (ac_wait_complete(CTX_REQ, 1, 10, &res)) {
        t_note("  completion dwResult=%llu dwError=%lu (%s)", (unsigned long long)res.dwResult, res.dwError, t_inet_errname(res.dwError));
        EXPECT_EQ(res.dwResult, FALSE);
        EXPECT_EQ(res.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
    }
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    int ir = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0), ic = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, n0);
    CHECKF(ir >= 0 && ic >= 0 && ir < ic, "request closes before its parent (%d, %d)", ir, ic);
    f.hr = NULL;
    ac_flow_close(&f);
}
/* close the request while an InternetQueryDataAvailable is pending */
TEST(ac_x_close_request_qda_pending) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!x_send(&f, ST_SLOW_BODY, 5, INTERNET_FLAG_ASYNC, "GET", "/cq")) return;
    static DWORD av; av = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    int n0 = ac_count();
    EXPECT_EQ(U(InternetCloseHandle)(f.hr), TRUE);
    ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 4000);
    ac_quiesce(200, 2500);
    t_note("close with QDA pending: %s", ac_seq_range(0, n0, -1, NULL));
    INTERNET_ASYNC_RESULT res;
    CHECK(ac_wait_complete(CTX_REQ, 2, 10, &res));
    EXPECT_EQ(res.dwResult, FALSE);
    EXPECT_EQ(res.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    CHECK(ac_before(INTERNET_STATUS_REQUEST_COMPLETE, INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ));
    f.hr = NULL;
    ac_flow_close(&f);
}
/* close the request while an InternetReadFileEx(IRF_ASYNC) is pending */
TEST(ac_x_close_request_rfex_pending) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!x_send(&f, ST_SLOW_BODY, 5, INTERNET_FLAG_ASYNC, "GET", "/cx")) return;
    static INTERNET_BUFFERSA ib; static char b[16];
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, CTX_ALT);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    int n0 = ac_count();
    EXPECT_EQ(U(InternetCloseHandle)(f.hr), TRUE);
    ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 4000);
    ac_quiesce(200, 2500);
    t_note("close with ReadFileEx pending: %s", ac_seq_range(0, n0, -1, NULL));
    INTERNET_ASYNC_RESULT res;
    CHECK(ac_wait_complete(CTX_REQ, 2, 10, &res));
    EXPECT_EQ(res.dwResult, FALSE);
    EXPECT_EQ(res.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
    EXPECT_EQ(ac_count_st_ctx(0, CTX_ALT), 0);   /* dwContext of ReadFileEx is not used for delivery [D] */
    f.hr = NULL;
    ac_flow_close(&f);
}
/* closing the session while a read is pending: the request and connect handles close too, children first */
TEST(ac_x_close_session_read_pending) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!x_send(&f, ST_SLOW_BODY, 5, INTERNET_FLAG_ASYNC, "GET", "/cs")) return;
    static char b[16]; static DWORD rd; rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    EXPECT_EQ(ok, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    int n0 = ac_count();
    EXPECT_EQ(U(InternetCloseHandle)(f.hi), TRUE);
    ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 4000);
    ac_quiesce(200, 2500);
    t_note("close session with read pending: %s", ac_seq_range(0, n0, -1, NULL));
    INTERNET_ASYNC_RESULT res;
    CHECK(ac_wait_complete(CTX_REQ, 2, 10, &res));
    EXPECT_EQ(res.dwResult, FALSE);
    EXPECT_EQ(res.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
    int ir = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0), ic = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, n0);
    CHECKF(ir >= 0 && ic >= 0 && ir < ic, "request before connect (%d, %d)", ir, ic);
    f.hr = f.hc = f.hi = NULL;
    ac_flow_close(&f);
}
/* closing an idle request (sent, body read) produces exactly one HANDLE_CLOSING and no REQUEST_COMPLETE */
TEST(ac_x_close_idle_request_no_complete) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!x_send(&f, NULL, 0, INTERNET_FLAG_ASYNC, "GET", "/ci")) return;
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    ac_quiesce(100, 300);
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    int n0 = ac_count();
    ac_close_wait(f.hr, CTX_REQ); f.hr = NULL;
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "70");
    ac_flow_close(&f);
}

/* ================================================================== many requests in flight */
#define X_NREQ 6
TEST(ac_x_many_requests_distinct_contexts) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SLEEP(100), S_REPLY(200, NULL, "multi"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/m0", T_INET_FRESH)) return;
    HINTERNET hr[X_NREQ]; DWORD_PTR ctx[X_NREQ];
    for (int i = 0; i < X_NREQ; i++) {
        char p[16]; snprintf(p, sizeof p, "/m%d", i);
        ctx[i] = (DWORD_PTR)0x77000100 + i;
        hr[i] = U(HttpOpenRequestA)(f.hc, "GET", p, NULL, NULL, NULL, T_INET_FRESH, ctx[i]);
        CHECK(hr[i] != NULL);
    }
    for (int i = 0; i < X_NREQ; i++) {
        SetLastError(0xdeadbeef);
        BOOL r = hr[i] ? U(HttpSendRequestA)(hr[i], NULL, 0, NULL, 0) : TRUE;
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_IO_PENDING, "request %d: r=%d e=%lu", i, r, e);
    }
    for (int i = 0; i < X_NREQ; i++) {
        INTERNET_ASYNC_RESULT res;
        CHECKF(ac_wait_complete(ctx[i], 1, 10000, &res), "request %d completed", i);
        EXPECT_EQ(res.dwResult, TRUE); EXPECT_EQ(res.dwError, 0);
        int k = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, ctx[i], 0); ac_ev ev;
        if (k >= 0 && ac_get(k, &ev)) { EXPECT_EQ(ev.h, hr[i]); CHECK(ev.tid != ac_main_tid); }
        EXPECT_EQ(ac_status_code(hr[i]), 200);
    }
    ac_quiesce(100, 500);
    for (int i = 0; i < X_NREQ; i++) {
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, ctx[i]), 1);
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_SENDING_REQUEST, ctx[i]), 1);
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_SENT, ctx[i]), 1);
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_RECEIVING_RESPONSE, ctx[i]), 1);
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_RESPONSE_RECEIVED, ctx[i]), 1);
        /* every event carrying this context is for this handle */
        for (int k = 0; k < ac_count(); k++) { ac_ev ev; ac_get(k, &ev); if (ev.ctx == ctx[i] && ev.st != INTERNET_STATUS_HANDLE_CREATED) CHECKF(ev.h == hr[i], "ctx %d event st %lu on another handle", i, ev.st); }
        char b[16]; int np;
        EXPECT_EQ(ac_read_all_async(hr[i], ctx[i], b, sizeof b, &np), 5);
        t_note("request %d: %s", i, ac_seq(ctx[i], NULL));
    }
    EXPECT_EQ(srv_req_count(f.s), X_NREQ);
    t_note("connections used for %d concurrent requests: %d", X_NREQ, srv_conn_count(f.s));
    for (int i = 0; i < X_NREQ; i++) ac_close_wait(hr[i], ctx[i]);
    ac_flow_close(&f);
}
/* per-request contexts on separate connect handles (different servers) */
TEST(ac_x_requests_on_two_servers) {
    REQ_ASYNC_API();
    srv *s1, *s2; SRV_OR_SKIP(s1, srv_http(NULL, 0));
    s2 = srv_http(NULL, 0); if (!s2) { srv_stop(s1); t_skip("server 2 unavailable"); return; }
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET c1 = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s1), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET c2 = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s2), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_ALT);
    HINTERNET r1 = U(HttpOpenRequestA)(c1, "GET", "/s1", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ);
    HINTERNET r2 = U(HttpOpenRequestA)(c2, "GET", "/s2", NULL, NULL, NULL, T_INET_FRESH, CTX_URL);
    CHECK(r1 && r2);
    BOOL a = U(HttpSendRequestA)(r1, NULL, 0, NULL, 0); DWORD ea = GetLastError();
    BOOL b = U(HttpSendRequestA)(r2, NULL, 0, NULL, 0); DWORD eb = GetLastError();
    EXPECT_EQ(a, FALSE); EXPECT_EQ(ea, ERROR_IO_PENDING);
    EXPECT_EQ(b, FALSE); EXPECT_EQ(eb, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT x;
    CHECK(ac_wait_complete(CTX_REQ, 1, 8000, &x)); EXPECT_EQ(x.dwResult, TRUE);
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &x)); EXPECT_EQ(x.dwResult, TRUE);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq(CTX_REQ, SKIP_X), "20,21,30,31,40,41,100");
    EXPECT_STR(ac_seq(CTX_URL, SKIP_X), "20,21,30,31,40,41,100");
    EXPECT_EQ(srv_req_count(s1), 1); EXPECT_EQ(srv_req_count(s2), 1);
    ac_close_wait(r1, CTX_REQ); ac_close_wait(r2, CTX_URL); ac_close_wait(c1, CTX_CON); ac_close_wait(c2, CTX_ALT);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s1); srv_stop(s2);
}

/* ================================================================== REQUEST_SENT payload tables */
/* [W10 round 2] REQUEST_SENT carries head size (+ body when sent with HttpSendRequest) */
TEST(ac_x_post_size_table_request_sent) {
    REQ_ASYNC_API();
    static const DWORD sizes[] = { 0, 1, 2, 17, 100, 1000, 4096, 5000 };
    static char body[5000];
    for (unsigned i = 0; i < sizeof body; i++) body[i] = (char)('A' + i % 26);
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "ok"), S_LOOP() };
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        ac_begin(); ac_flow f;
        if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/size", T_INET_FRESH)) return;
        int n0 = ac_count(), pending; DWORD err;
        CHECKF(ac_send_wait(f.hr, CTX_REQ, NULL, sizes[k] ? body : NULL, sizes[k], &pending, &err), "size %lu err %lu", sizes[k], err);
        CHECK(pending);
        CHECK(srv_wait_requests(f.s, 1, 2000));
        size_t hn = 0, bn = 0; srv_req_head_raw(f.s, 0, &hn); srv_req_body(f.s, 0, &bn);
        EXPECT_EQ(bn, sizes[k]);
        int i = ac_find(INTERNET_STATUS_REQUEST_SENT, CTX_REQ, n0); ac_ev ev;
        CHECK(i >= 0);
        if (i >= 0 && ac_get(i, &ev)) {
            EXPECT_EQ(ev.len, 4);
            t_note("POST %lu: REQUEST_SENT=%lu head=%zu body=%zu", sizes[k], ac_info_dword(&ev), hn, bn);
            CHECKF(ac_info_dword(&ev) == hn + bn, "size %lu: REQUEST_SENT %lu head %zu body %zu", sizes[k], ac_info_dword(&ev), hn, bn);
        }
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_SENT, CTX_REQ), 1);
        ac_quiesce(50, 300);
        EXPECT_STR(ac_seq_range(0, n0, -1, SKIP_X), "20,21,30,31,40,41,100");
        ac_flow_close(&f);
    }
}
/* extra request headers given to HttpSendRequest: REQUEST_SENT still equals the bytes of the head on the wire */
TEST(ac_x_header_table_request_sent) {
    REQ_ASYNC_API();
    static const char *hdrs[] = { NULL, "X-A: 1\r\n", "X-Long: 0123456789012345678901234567890123456789\r\n", "X-A: 1\r\nX-B: 2\r\nX-C: 3\r\n",
                                  "Accept: text/plain\r\n", "Referer: http://127.0.0.1/ref\r\n" };
    for (unsigned k = 0; k < sizeof hdrs / sizeof hdrs[0]; k++) {
        ac_begin(); ac_flow f;
        if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/hdr", T_INET_FRESH)) return;
        int n0 = ac_count(), pending; DWORD err;
        CHECKF(ac_send_wait(f.hr, CTX_REQ, hdrs[k], NULL, 0, &pending, &err), "hdr %u err %lu", k, err);
        CHECK(srv_wait_requests(f.s, 1, 2000));
        size_t hn = 0; srv_req_head_raw(f.s, 0, &hn);
        int i = ac_find(INTERNET_STATUS_REQUEST_SENT, CTX_REQ, n0); ac_ev ev;
        if (i >= 0 && ac_get(i, &ev)) CHECKF(ac_info_dword(&ev) == hn, "hdr %u: REQUEST_SENT %lu head %zu", k, ac_info_dword(&ev), hn);
        else CHECK(i >= 0);
        char b[16]; int np;
        EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
        ac_flow_close(&f);
    }
}

/* ================================================================== async read tables */
/* body of N pattern bytes read with buffer size B: content is exact, the total matches, no read fails */
TEST(ac_x_read_bufsize_table) {
    REQ_ASYNC_API();
    static const DWORD bs[] = { 1, 2, 3, 7, 64, 1000, 4096, 65536 };
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 3000, 0), S_LOOP() };
    static char out[4000];
    for (unsigned k = 0; k < sizeof bs / sizeof bs[0]; k++) {
        ac_begin(); ac_flow f;
        if (!x_send(&f, st, 3, INTERNET_FLAG_ASYNC, "GET", "/bs")) return;
        int np, ns;
        long n = x_read_all_bs(f.hr, CTX_REQ, bs[k], out, sizeof out, &np, &ns);
        CHECKF(n == 3000, "bufsize %lu: total %ld", bs[k], n);
        CHECKF(n == 3000 && srv_pattern_check(out, 3000, 0), "bufsize %lu: content", bs[k]);
        t_note("bufsize %lu: pending=%d sync=%d", bs[k], np, ns);
        ac_flow_close(&f);
    }
}
/* the same with a trickled body (data arrives in pieces after the head) */
TEST(ac_x_read_bufsize_table_trickled) {
    REQ_ASYNC_API();
    static const DWORD bs[] = { 1, 5, 16, 4096 };
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n"), S_SPLIT("abcdefghijklmnopqrstuvwxyz", 6, 40), S_LOOP() };
    static char out[64];
    for (unsigned k = 0; k < sizeof bs / sizeof bs[0]; k++) {
        ac_begin(); ac_flow f;
        if (!x_send(&f, st, 4, INTERNET_FLAG_ASYNC, "GET", "/tr")) return;
        int np, ns;
        long n = x_read_all_bs(f.hr, CTX_REQ, bs[k], out, sizeof out, &np, &ns);
        CHECKF(n == 26, "bufsize %lu: total %ld", bs[k], n);
        out[n > 0 && n < 64 ? n : 0] = 0;
        EXPECT_STR(out, "abcdefghijklmnopqrstuvwxyz");
        t_note("trickled bufsize %lu: pending=%d sync=%d", bs[k], np, ns);
        ac_flow_close(&f);
    }
}
/* body-size table for chunked responses: every size reads back exactly */
TEST(ac_x_chunked_size_table) {
    REQ_ASYNC_API();
    static const unsigned csz[] = { 1, 3, 16, 100, 0 };
    static const char body[] = "chunked-transfer-encoding-body-with-a-few-dozen-bytes-0123456789";
    static srv_step st[3];
    static char out[128];
    for (unsigned k = 0; k < sizeof csz / sizeof csz[0]; k++) {
        srv_step a = S_HEAD(), b = S_REPLY_CHUNKED(200, NULL, body, 0), c = S_LOOP();
        b.n2 = csz[k];
        st[0] = a; st[1] = b; st[2] = c;
        ac_begin(); ac_flow f;
        if (!x_send(&f, st, 3, INTERNET_FLAG_ASYNC, "GET", "/ch")) return;
        int np, ns;
        long n = x_read_all_bs(f.hr, CTX_REQ, 4096, out, sizeof out, &np, &ns);
        CHECKF(n == (long)strlen(body), "chunk %u: total %ld", csz[k], n);
        out[n > 0 && n < (long)sizeof out ? n : 0] = 0;
        EXPECT_STR(out, body);
        ac_flow_close(&f);
    }
}
/* repeated reads after the end of the body: TRUE with 0 bytes, synchronously, no REQUEST_COMPLETE */
TEST(ac_x_read_after_eof_repeated) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!x_send(&f, NULL, 0, INTERNET_FLAG_ASYNC, "GET", "/eof")) return;
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    ac_quiesce(100, 300);
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    static char x[16]; static DWORD rd;
    for (int i = 0; i < 5; i++) {
        rd = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetReadFile)(f.hr, x, sizeof x, &rd);
        CHECKF(ok, "read %d after EOF: err %lu", i, GetLastError());
        EXPECT_EQ(rd, 0);
    }
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    ac_flow_close(&f);
}
/* QDA pending -> the completion's dwError is the byte count [W10 round 2]; a read of exactly that many bytes then
 * returns synchronously with them */
TEST(ac_x_qda_then_exact_read) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"), S_SLEEP(600), S_SEND("payload"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!x_send(&f, st, 4, INTERNET_FLAG_ASYNC, "GET", "/qe")) return;
    static DWORD av; av = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    EXPECT_EQ(ok, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, 2, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE);
    EXPECT_EQ(r.dwError, 7);
    EXPECT_EQ(av, 7);
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    static char b[16]; static DWORD rd; rd = 0;
    SetLastError(0xdeadbeef);
    ok = U(InternetReadFile)(f.hr, b, 7, &rd);
    CHECK(ok); EXPECT_EQ(rd, 7);
    CHECK(!memcmp(b, "payload", 7));
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    ac_flow_close(&f);
}
/* QDA when the body is already buffered: synchronous TRUE with the byte count, no completion */
TEST(ac_x_qda_buffered_table) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    static const DWORD sizes[] = { 1, 10, 100, 1000 };
    static srv_step st[3];
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        srv_step a = S_HEAD(), b = S_REPLY_PATTERN(200, NULL, sizes[k], 0), c = S_LOOP();
        st[0] = a; st[1] = b; st[2] = c;
        ac_begin(); ac_flow f;
        if (!x_send(&f, st, 3, INTERNET_FLAG_ASYNC, "GET", "/qb")) return;
        Sleep(150);
        int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
        static DWORD av; av = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
        DWORD e = GetLastError();
        if (!ok && e == ERROR_IO_PENDING) { INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 3000, &r)); t_note("size %lu: QDA pending", sizes[k]); }
        else { CHECKF(ok, "size %lu err %lu", sizes[k], e); CHECKF(av >= 1 && av <= sizes[k], "size %lu: av %lu", sizes[k], av); }
        t_note("size %lu: QDA ok=%d av=%lu", sizes[k], ok, av);
        char out[1100]; int np;
        EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, out, sizeof out, &np), (long)sizes[k]);
        ac_flow_close(&f);
    }
}

/* ================================================================== decoding, HEAD, 204, redirects */
TEST(ac_x_gzip_decoding_async) {
    REQ_ASYNC_API();
    static srv_step st[3];
    srv_step a = S_HEAD(), b = S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0), c = S_LOOP();
    st[0] = a; st[1] = b; st[2] = c;
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/gz", T_INET_FRESH)) return;
    BOOL on = TRUE;
    CHECK(U(InternetSetOptionA)(f.hr, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, "Accept-Encoding: gzip\r\n", NULL, 0, &pending, &err));
    static char out[1200]; int np, ns;
    long n = x_read_all_bs(f.hr, CTX_REQ, 128, out, sizeof out, &np, &ns);
    EXPECT_EQ(n, SRV_FOX_LEN);
    CHECK(n == SRV_FOX_LEN && !memcmp(out, srv_fox_text(), SRV_FOX_LEN));
    t_note("gzip decode async: pending=%d sync=%d", np, ns);
    ac_flow_close(&f);
}
TEST(ac_x_gzip_no_decoding_raw) {
    REQ_ASYNC_API();
    static srv_step st[3];
    srv_step a = S_HEAD(), b = S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0), c = S_LOOP();
    st[0] = a; st[1] = b; st[2] = c;
    ac_begin(); ac_flow f;
    if (!x_send(&f, st, 3, INTERNET_FLAG_ASYNC, "GET", "/gzr")) return;
    static char out[1200]; int np, ns;
    long n = x_read_all_bs(f.hr, CTX_REQ, 4096, out, sizeof out, &np, &ns);
    EXPECT_EQ(n, (long)srv_fox_gzip_len);
    CHECK(n == (long)srv_fox_gzip_len && !memcmp(out, srv_fox_gzip, srv_fox_gzip_len));
    ac_flow_close(&f);
}
TEST(ac_x_head_read_zero_sync) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!x_send(&f, st, 3, INTERNET_FLAG_ASYNC, "HEAD", "/h")) return;
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    static char b[16]; static DWORD rd; rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    CHECK(ok); EXPECT_EQ(rd, 0);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_flow_close(&f);
}
TEST(ac_x_204_read_zero_sync) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 204 No Content\r\n\r\n"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!x_send(&f, st, 3, INTERNET_FLAG_ASYNC, "GET", "/204")) return;
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    static char b[16]; static DWORD rd; rd = 0xdeadbeef;
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    CHECK(ok); EXPECT_EQ(rd, 0);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    EXPECT_EQ(ac_status_code(f.hr), 204);
    ac_flow_close(&f);
}
static const srv_step ST_CHAIN3[] = {
    S_HEAD(), S_REPLY(302, "Location: /r2\r\n", ""),
    S_HEAD(), S_REPLY(302, "Location: /r3\r\n", ""),
    S_HEAD(), S_REPLY(302, "Location: /final\r\n", ""),
    S_HEAD(), S_REPLY(200, NULL, "end"), S_LOOP_TO(6) };
TEST(ac_x_redirect_chain_three) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, ST_CHAIN3, 9, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/r1", T_INET_FRESH)) return;
    int n0 = ac_count(), pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    CHECK(pending);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REDIRECT, CTX_REQ), 3);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    EXPECT_STR(ac_seq_range(0, n0, -1, SKIP_X), "20,21,30,31,40,41,110,30,31,40,41,110,30,31,40,41,110,30,31,40,41,100");
    /* the REDIRECT strings name the next URL, in order */
    static const char *want[] = { "/r2", "/r3", "/final" };
    int from = n0;
    for (int k = 0; k < 3; k++) {
        int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_REQ, from); ac_ev ev;
        if (i < 0 || !ac_get(i, &ev)) { CHECK(i >= 0); break; }
        CHECKF(strstr((char *)ev.info, want[k]) != NULL, "redirect %d: '%s'", k, (char *)ev.info);
        EXPECT_STR((char *)ev.info, srv_url(f.s, want[k]));
        from = i + 1;
    }
    EXPECT_EQ(srv_req_count(f.s), 4);
    EXPECT_STR(srv_req_target(f.s, 3), "/final");
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 3);
    EXPECT_STR(b, "end");
    ac_flow_close(&f);
}
/* POST -> 303 -> GET: the verb changes, the body is not re-sent */
TEST(ac_x_redirect_303_post_to_get) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(303, "Location: /see\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "seen"), S_LOOP_TO(3) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 6, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/form", T_INET_FRESH)) return;
    static char data[] = "a=1&b=2";
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, "Content-Type: application/x-www-form-urlencoded\r\n", data, 7, &pending, &err));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REDIRECT, CTX_REQ), 1);
    CHECK(srv_wait_requests(f.s, 2, 2000));
    EXPECT_STR(srv_req_method(f.s, 0), "POST");
    EXPECT_STR(srv_req_method(f.s, 1), "GET");
    EXPECT_STR(srv_req_target(f.s, 1), "/see");
    CHECK(srv_req_header(f.s, 1, "Content-Length") == NULL || !strcmp(srv_req_header(f.s, 1, "Content-Length"), "0"));
    size_t hn3 = 0; t_note("303 follow-up head: %s", srv_req_head_raw(f.s, 1, &hn3));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 4);
    ac_flow_close(&f);
}
/* a redirect whose body arrives late: the REDIRECT status is still raised before the new request */
TEST(ac_x_redirect_with_body) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /b\r\n", "moved away"), S_HEAD(), S_REPLY(200, NULL, "b!"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/a", T_INET_FRESH)) return;
    int n0 = ac_count(), pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    t_note("redirect with body: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, SKIP_X), "20,21,30,31,40,41,110,30,31,40,41,100");
    EXPECT_EQ(srv_conn_count(f.s), 1);
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 2);
    ac_flow_close(&f);
}
/* InternetOpenUrl async following a redirect: REDIRECT on the URL context, the result handle is the final one */
TEST(ac_x_openurl_async_redirect) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /there\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "there"), S_LOOP_TO(2) };
    srv *s; SRV_OR_SKIP(s, srv_http(st, 5));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/here"), NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    HINTERNET h = (HINTERNET)r.dwResult;
    CHECK(h != NULL);
    ac_quiesce(100, 300);
    t_note("openurl redirect seq: %s", ac_seq(CTX_URL, NULL));
    EXPECT_STR(ac_seq(CTX_URL, SKIP_X), "20,21,30,31,40,41,110,30,31,40,41,100");
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_URL, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) EXPECT_STR((char *)ev.info, srv_url(s, "/there"));
    if (h) {
        char u[256]; DWORD ul = sizeof u;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_URL, u, &ul));
        EXPECT_STR(u, srv_url(s, "/there"));
        char b[16]; int np;
        EXPECT_EQ(ac_read_all_async(h, CTX_URL, b, sizeof b, &np), 5);
        ac_close_wait(h, CTX_URL);
    }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
/* InternetOpenUrl async with extra headers: they reach the wire */
TEST(ac_x_openurl_async_headers) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/hh"), "X-Async-Test: yes\r\n", (DWORD)-1, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    CHECK(srv_wait_requests(s, 1, 2000));
    const char *v = srv_req_header(s, 0, "X-Async-Test");
    CHECK(v && !strcmp(v, "yes"));
    if (r.dwResult) ac_close_wait((HINTERNET)r.dwResult, CTX_URL);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
/* InternetOpenUrl async 404: still completes with a handle (HTTP errors are not WinINet errors) */
TEST(ac_x_openurl_async_404_handle) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(404, NULL, "nope"), S_LOOP() };
    srv *s; SRV_OR_SKIP(s, srv_http(st, 3));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/nf"), NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    CHECK(r.dwResult != 0); EXPECT_EQ(r.dwError, 0);
    if (r.dwResult) {
        EXPECT_EQ(ac_status_code((HINTERNET)r.dwResult), 404);
        char b[16]; int np;
        EXPECT_EQ(ac_read_all_async((HINTERNET)r.dwResult, CTX_URL, b, sizeof b, &np), 4);
        ac_close_wait((HINTERNET)r.dwResult, CTX_URL);
    }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* ================================================================== HttpSendRequestEx with a first buffer */
TEST(ac_x_sendex_initial_buffer) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "got"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/ib", T_INET_FRESH)) return;
    static INTERNET_BUFFERSA ib; static char first[] = "head";
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = first; ib.dwBufferLength = 4; ib.dwBufferTotal = 10;
    int c = 0; INTERNET_ASYNC_RESULT r;
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestExA)(f.hr, &ib, NULL, 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    static DWORD wr; static char rest[] = "-tail!";
    wr = 0;
    ok = U(InternetWriteFile)(f.hr, rest, 6, &wr);
    if (!ok && GetLastError() == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); }
    else CHECK(ok);
    EXPECT_EQ(wr, 6);
    ok = U(HttpEndRequestA)(f.hr, NULL, 0, 0);
    e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn = 0; const char *body = srv_req_body(f.s, 0, &bn);
    EXPECT_EQ(bn, 10);
    CHECK(body && bn == 10 && !memcmp(body, "head-tail!", 10));
    EXPECT_STR(srv_req_header(f.s, 0, "Content-Length"), "10");
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_flow_close(&f);
}
/* InternetWriteFile of a larger block in an async session */
TEST(ac_x_sendex_large_write) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "big"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "PUT", "/big", T_INET_FRESH)) return;
    static INTERNET_BUFFERSA ib; static char data[100000];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (char)srv_pattern_byte(i);
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = sizeof data;
    int c = 0; INTERNET_ASYNC_RESULT r;
    BOOL ok = U(HttpSendRequestExA)(f.hr, &ib, NULL, 0, 0);
    if (!ok && GetLastError() == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    else CHECK(ok);
    static DWORD wr; wr = 0;
    SetLastError(0xdeadbeef);
    ok = U(InternetWriteFile)(f.hr, data, sizeof data, &wr);
    DWORD e = GetLastError();
    t_note("100000-byte InternetWriteFile async: ok=%d err=%lu wr=%lu", ok, e, wr);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 8000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    else CHECK(ok);
    EXPECT_EQ(wr, sizeof data);
    ok = U(HttpEndRequestA)(f.hr, NULL, 0, 0);
    if (!ok && GetLastError() == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    else CHECK(ok);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn = 0; const char *body = srv_req_body(f.s, 0, &bn);
    EXPECT_EQ(bn, sizeof data);
    CHECK(body && bn == sizeof data && srv_pattern_check(body, bn, 0));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_flow_close(&f);
}

/* ================================================================== synchronous session details */
/* sync session, InternetReadFileEx(IRF_ASYNC) completes synchronously and never raises REQUEST_COMPLETE */
TEST(ac_x_sync_rfex_irf_async) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/srf", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    static INTERNET_BUFFERSA ib; static char b[16];
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, 0);
    CHECK(ok);
    EXPECT_EQ(ib.dwBufferLength, 5);
    CHECK(!memcmp(b, "hello", 5));
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    ac_flow_close(&f);
}
/* sync session: reading a body that arrives late blocks and reports 40/41 (or nothing) on the calling thread */
TEST(ac_x_sync_late_body_statuses) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, ST_SLOW_BODY, 5, 0, ac_cb, "GET", "/slb", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    int n0 = ac_count();
    static char b[16]; static DWORD rd; rd = 0;
    CHECK(U(InternetReadFile)(f.hr, b, sizeof b, &rd));
    EXPECT_EQ(rd, 4);
    t_note("sync late body read statuses: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "40,41");
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    ac_flow_close(&f);
}
/* async session: a pending read of a late body reports 40,41,100 (same as ac_read_pending_statuses) with the
 * RESPONSE_RECEIVED byte count equal to the bytes then delivered */
TEST(ac_x_async_late_body_received_count) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!x_send(&f, ST_SLOW_BODY, 5, INTERNET_FLAG_ASYNC, "GET", "/alb")) return;
    int n0 = ac_count();
    static char b[16]; static DWORD rd; rd = 0;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    EXPECT_EQ(ok, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, 2, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE); EXPECT_EQ(r.dwError, 0);
    EXPECT_EQ(rd, 4);
    CHECK(!memcmp(b, "body", 4));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "40,41,100");
    int i = ac_find(INTERNET_STATUS_RESPONSE_RECEIVED, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) { EXPECT_EQ(ev.len, 4); EXPECT_EQ(ac_info_dword(&ev), 4); }
    ac_flow_close(&f);
}

/* ================================================================== callback on the session vs the request */
/* a callback set only on the session after the request was opened is not seen by that request */
TEST(ac_x_session_cb_after_request_open) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, NULL, "GET", "/late-cb", T_INET_FRESH)) return;
    EXPECT_EQ(U(InternetSetStatusCallbackA)(f.hi, ac_cb), NULL);
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    CHECK(srv_wait_requests(f.s, 1, 3000));
    Sleep(500);
    EXPECT_EQ(ac_count_st_ctx(0, CTX_REQ), 0);
    EXPECT_EQ(ac_count(), 0);
    /* the request is still usable: wait for it to finish via a sync-looking poll of the status code */
    DWORD st = 0;
    for (int i = 0; i < 40 && !(st = ac_status_code(f.hr)); i++) Sleep(50);
    EXPECT_EQ(st, 200);
    /* a request opened from that (callback-less) connect stays silent too: inheritance is a snapshot taken at
     * creation from the direct parent; a NEW connect handle picks the session callback up */
    HINTERNET h2 = U(HttpOpenRequestA)(f.hc, "GET", "/late-cb2", NULL, NULL, NULL, T_INET_FRESH, CTX_ALT);
    CHECK(h2 != NULL);
    HINTERNET hc2 = U(InternetConnectA)(f.hi, "127.0.0.1", srv_port(f.s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_URL);
    CHECK(hc2 != NULL);
    HINTERNET h3 = hc2 ? U(HttpOpenRequestA)(hc2, "GET", "/late-cb3", NULL, NULL, NULL, T_INET_FRESH, CTX_ALT + 1) : NULL;
    CHECK(h3 != NULL);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_ALT), 0);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_URL), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_ALT + 1), 1);
    int pending; DWORD err;
    if (h3) { CHECKF(ac_send_wait(h3, CTX_ALT + 1, NULL, NULL, 0, &pending, &err), "err %lu", err); }
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_ALT + 1), 1);
    if (h3) ac_close_wait(h3, CTX_ALT + 1);
    if (hc2) ac_close_wait(hc2, CTX_URL);
    U(InternetCloseHandle)(h2);
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    ac_quiesce(50, 300);
    EXPECT_EQ(ac_count_st_ctx(0, CTX_ALT), 0);
    ac_flow_close(&f);
}
/* two requests on one connect: callback on one request only; the other request's statuses are silent */
TEST(ac_x_callback_on_one_of_two_requests) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, NULL, "GET", "/one", T_INET_FRESH)) return;
    HINTERNET h2 = U(HttpOpenRequestA)(f.hc, "GET", "/two", NULL, NULL, NULL, T_INET_FRESH, CTX_ALT);
    CHECK(h2 != NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(h2, ac_cb), NULL);
    BOOL a = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0); DWORD ea = GetLastError();
    EXPECT_EQ(a, FALSE); EXPECT_EQ(ea, ERROR_IO_PENDING);
    int pending; DWORD err;
    CHECK(ac_send_wait(h2, CTX_ALT, NULL, NULL, 0, &pending, &err));
    CHECK(srv_wait_requests(f.s, 2, 3000));
    ac_quiesce(100, 500);
    EXPECT_EQ(ac_count_st_ctx(0, CTX_REQ), 0);
    EXPECT_STR(ac_seq(CTX_ALT, SKIP_X), "20,21,30,31,40,41,100");
    ac_close_wait(h2, CTX_ALT);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_ALT), 1);
    for (int i = 0; i < 40 && !ac_status_code(f.hr); i++) Sleep(50);
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    ac_flow_close(&f);
}
/* W and A callbacks on two requests of the same connect: narrow vs wide strings per handle */
TEST(ac_x_w_and_a_on_sibling_requests) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, NULL, "GET", "/src", T_INET_FRESH)) return;
    EXPECT_EQ(U(InternetSetStatusCallbackW)(f.hr, ac_cbw), NULL);
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_REQ, 0); ac_ev ev;
    CHECK(i >= 0);
    if (i >= 0 && ac_get(i, &ev)) {
        EXPECT_EQ(ev.wide, 1);
        WCHAR want[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(f.s, "/dst"), -1, want, 128);
        EXPECT_WSTR((const WCHAR *)ev.info, want);
    }
    int k = ac_find(INTERNET_STATUS_CONNECTING_TO_SERVER, CTX_REQ, 0);
    if (k >= 0 && ac_get(k, &ev)) EXPECT_STR((char *)ev.info, "127.0.0.1");   /* not converted [D UnicodeStatusCallbackWrapper] */
    ac_flow_close(&f);
}

/* ================================================================== misc */
/* INTERNET_FLAG_ASYNC session: InternetConnect never raises REQUEST_COMPLETE for HTTP */
TEST(ac_x_connect_http_no_complete) {
    REQ_ASYNC_API();
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hc[4];
    for (int i = 0; i < 4; i++) {
        SetLastError(0xdeadbeef);
        hc[i] = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON + i);
        CHECK(hc[i] != NULL);
    }
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_HANDLE_CREATED), 4);
    EXPECT_EQ(ac_count_tid(0, ac_main_tid), 4);
    EXPECT_EQ(srv_conn_count(s), 0);   /* InternetConnect(HTTP) opens no connection */
    for (int i = 0; i < 4; i++) ac_close_wait(hc[i], CTX_CON + i);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_HANDLE_CLOSING), 4);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
/* HttpAddRequestHeaders in an async session is synchronous */
TEST(ac_x_add_headers_sync_in_async_session) {
    REQ_ASYNC_API(); REQUIRE(U(HttpAddRequestHeadersA));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/ah", T_INET_FRESH)) return;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(HttpAddRequestHeadersA)(f.hr, "X-Added: 1\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD), TRUE);
    ac_quiesce(50, 200);
    EXPECT_EQ(ac_count(), n0);
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    CHECK(srv_wait_requests(f.s, 1, 2000));
    const char *v = srv_req_header(f.s, 0, "X-Added");
    CHECK(v && !strcmp(v, "1"));
    ac_flow_close(&f);
}
/* HttpQueryInfo in an async session after completion: synchronous, no status */
TEST(ac_x_query_info_after_complete_silent) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!x_send(&f, NULL, 0, INTERNET_FLAG_ASYNC, "GET", "/qi")) return;
    ac_quiesce(100, 300);
    int n0 = ac_count();
    char buf[512]; DWORD l = sizeof buf;
    CHECK(U(HttpQueryInfoA)(f.hr, HTTP_QUERY_RAW_HEADERS_CRLF, buf, &l, NULL));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    l = sizeof buf;
    CHECK(U(HttpQueryInfoA)(f.hr, HTTP_QUERY_CONTENT_LENGTH, buf, &l, NULL));
    EXPECT_STR(buf, "5");
    EXPECT_EQ(ac_count(), n0);
    ac_flow_close(&f);
}
/* status values seen in this area's scenarios are within the documented set */
TEST(ac_x_status_values_documented) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /d\r\nSet-Cookie: x=1\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "d"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/s", T_INET_FRESH)) return;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    char b[8]; int np; ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np);
    ac_flow_close(&f);
    static const DWORD known[] = { 10, 11, 20, 21, 30, 31, 40, 41, 42, 43, 50, 51, 60, 70, 80, 100, 110, 120, 140, 200, 320, 321, 322, 323, 324, 325, 326, 327, 330 };
    for (int i = 0; i < ac_count(); i++) {
        ac_ev ev; ac_get(i, &ev); int ok = 0;
        for (unsigned k = 0; k < sizeof known / sizeof known[0]; k++) if (known[k] == ev.st) ok = 1;
        CHECKF(ok, "status %lu", ev.st);
    }
    /* INTERNET_FLAG_NO_COOKIES (part of T_INET_FRESH): no cookie status, nothing stored */
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_COOKIE_RECEIVED), 0);
    t_note("statuses with Set-Cookie + redirect, NO_COOKIES: %s", ac_seq(0, NULL));
}
