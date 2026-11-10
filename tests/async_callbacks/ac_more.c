/* ac_more.c - calls made while an async operation is pending, callback/context changes mid-operation,
 * several requests in flight, table-driven status codes and body sizes, W entry points, sync-mode redirects
 * and cookies. */
#include "ac.h"

/* reply after 1 s: long enough that the test's next call happens while the send is pending */
static const srv_step ST_LATE[] = { S_HEAD(), S_SLEEP(1000), S_REPLY(200, NULL, "late"), S_LOOP() };

static int start_pending(ac_flow *f, const srv_step *st, int n) {
    if (!ac_flow_open(f, st, n, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/late", T_INET_FRESH)) return 0;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f->hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    if (r || e != ERROR_IO_PENDING) { t_check(0, __FILE__, __LINE__, "send pending", "r=%d err=%lu", r, e); ac_flow_close(f); return 0; }
    srv_wait_requests(f->s, 1, 3000);
    return 1;
}

/* ------------------------------------------------------------------ calls while a send is pending */
TEST(ac_pending_query_status_during_send) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return;
    DWORD st = 0, l = sizeof st;
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpQueryInfoA)(f.hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
    DWORD e = GetLastError();
    t_note("STATUS_CODE while send pending: ok=%d err=%lu (%s) st=%lu", ok, e, t_inet_errname(e), st);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_STATE);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, 1, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_flow_close(&f);
}
/* A second HttpSendRequest on a request whose first send is still pending is accepted with 997 [W10 rounds 2,3],
 * but in round 3 the process then died with STATUS_HEAP_CORRUPTION (0xc0000374) inside WinINet. The probe therefore
 * runs in a child process that reports the immediate return through its exit code and terminates itself at once
 * (TerminateProcess skips DLL detach, so the corrupted state is never walked). */
CHILD(ac_second_send_child) {
    (void)argc; (void)argv;
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return 2;
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    TerminateProcess(GetCurrentProcess(), ok ? 41 : e == ERROR_IO_PENDING ? 42 : 100 + (e & 0xff));
    return 3;
}
TEST(ac_pending_second_send) {
    REQ_ASYNC_API();
    DWORD code = t_run_child("ac_second_send_child", NULL, 15000);
    t_note("second send while pending (child): exit=0x%lx (41 TRUE, 42 FALSE+997, 100+n other error)", code);
    EXPECT_EQ(code, 42);
}
TEST(ac_pending_read_during_send) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return;
    static char b[16]; static DWORD rd;
    rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    DWORD e = GetLastError();
    t_note("read while send pending: ok=%d err=%lu (%s) rd=0x%lx", ok, e, t_inet_errname(e), rd);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_STATE);
    INTERNET_ASYNC_RESULT r;
    ac_wait_complete(CTX_REQ, 1, 5000, &r);
    ac_quiesce(200, 2000);
    t_note("completions after read-during-send: %d seq=%s", ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), ac_seq(CTX_REQ, NULL));
    ac_flow_close(&f);
}
TEST(ac_pending_qda_during_send) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return;
    static DWORD av;
    av = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    DWORD e = GetLastError();
    t_note("QDA while send pending: ok=%d err=%lu (%s) av=0x%lx", ok, e, t_inet_errname(e), av);
    CHECK(!ok); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_STATE);
    INTERNET_ASYNC_RESULT r;
    ac_wait_complete(CTX_REQ, 1, 5000, &r);
    ac_quiesce(200, 2000);
    ac_flow_close(&f);
}
TEST(ac_pending_callback_removed) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return;
    EXPECT_EQ(U(InternetSetStatusCallbackA)(f.hr, NULL), ac_cb);
    int n0 = ac_count();
    Sleep(2000);    /* the reply comes after 1 s */
    t_note("callback removed while pending: %d further events (%s)", ac_count() - n0, ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 0);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    ac_flow_close(&f);
}
TEST(ac_pending_callback_replaced) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return;
    EXPECT_EQ(U(InternetSetStatusCallbackA)(f.hr, ac_cb2), ac_cb);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, 1, 5000, &r));
    int i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) EXPECT_EQ(ev.wide, 2);    /* the new callback gets the completion */
    EXPECT_EQ(r.dwResult, TRUE);
    ac_flow_close(&f);
}
TEST(ac_pending_context_changed) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    ac_begin(); ac_flow f;
    if (!start_pending(&f, ST_LATE, 4)) return;
    DWORD_PTR nv = CTX_ALT;
    CHECK(U(InternetSetOptionA)(f.hr, INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv));
    ac_wait_st(INTERNET_STATUS_REQUEST_COMPLETE, 0, 1, 5000);
    ac_quiesce(100, 400);
    int old = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), neu = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_ALT);
    t_note("context changed while pending: completion on old ctx=%d new ctx=%d seq(all)=%s", old, neu, ac_seq(0, NULL));
    /* [W10] the completion keeps the context the operation started with */
    EXPECT_EQ(old, 1); EXPECT_EQ(neu, 0);
    U(InternetCloseHandle)(f.hr);
    ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_ALT, 1, 2000);
    f.hr = NULL;
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ several requests in flight */
TEST(ac_two_requests_in_flight) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SLEEP(300), S_REPLY(200, NULL, "x"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/one", T_INET_FRESH)) return;
    HINTERNET h2 = U(HttpOpenRequestA)(f.hc, "GET", "/two", NULL, NULL, NULL, T_INET_FRESH, CTX_ALT);
    CHECK(h2 != NULL); if (!h2) { ac_flow_close(&f); return; }
    SetLastError(0xdeadbeef); BOOL r1 = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0); DWORD e1 = GetLastError();
    SetLastError(0xdeadbeef); BOOL r2 = U(HttpSendRequestA)(h2, NULL, 0, NULL, 0); DWORD e2 = GetLastError();
    EXPECT_EQ(r1, FALSE); EXPECT_EQ(e1, ERROR_IO_PENDING);
    EXPECT_EQ(r2, FALSE); EXPECT_EQ(e2, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT a, b;
    CHECK(ac_wait_complete(CTX_REQ, 1, 5000, &a));
    CHECK(ac_wait_complete(CTX_ALT, 1, 5000, &b));
    EXPECT_EQ(a.dwResult, TRUE); EXPECT_EQ(b.dwResult, TRUE);
    CHECK(srv_wait_requests(f.s, 2, 2000));
    t_note("two in flight: connections=%d", srv_conn_count(f.s));
    EXPECT_EQ(srv_conn_count(f.s), 2);     /* the second request cannot share the busy connection */
    /* every event names its own request */
    for (int i = 0; i < ac_count(); i++) {
        ac_ev ev; ac_get(i, &ev);
        if (ev.st == INTERNET_STATUS_HANDLE_CREATED) continue;
        if (ev.ctx == CTX_REQ) CHECK(ev.h == f.hr);
        if (ev.ctx == CTX_ALT) CHECK(ev.h == h2);
    }
    ac_close_wait(h2, CTX_ALT);
    ac_flow_close(&f);
}
TEST(ac_sequential_requests_reuse_table) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/0", T_INET_FRESH)) return;
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    for (int k = 0; k < 8; k++) {
        DWORD_PTR ctx = 0x7000 + k;
        char path[16]; snprintf(path, sizeof path, "/s%d", k);
        HINTERNET h = U(HttpOpenRequestA)(f.hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH, ctx);
        CHECK(h != NULL); if (!h) break;
        int n0 = ac_count(), pending; DWORD err;
        CHECK(ac_send_wait(h, ctx, NULL, NULL, 0, &pending, &err));
        EXPECT_EQ(pending, 1);
        char body[16]; int np;
        EXPECT_EQ(ac_read_all_async(h, ctx, body, sizeof body, &np), 5);
        EXPECT_STR(body, "hello");
        /* [W10] send, then the reads add one 40/41 pair */
        const char *want = k == 0 ? "80,20,21,30,31,40,41,100,40,41" : "80,30,31,40,41,100,40,41";
        CHECKF(!strcmp(ac_seq_range(ctx, n0, -1, NULL), want), "k=%d seq %s want %s", k, ac_seq_range(ctx, n0, -1, NULL), want);
        ac_close_wait(h, ctx);
    }
    CHECK(srv_wait_requests(f.s, 8, 2000));
    EXPECT_EQ(srv_conn_count(f.s), 1);
    ac_flow_close(&f);
}
TEST(ac_two_sessions_two_callbacks) {
    REQ_ASYNC_API();
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET h1 = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb), h2 = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb2);
    HINTERNET c1 = U(InternetConnectA)(h1, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET c2 = U(InternetConnectA)(h2, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_ALT);
    HINTERNET r1 = U(HttpOpenRequestA)(c1, "GET", "/1", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ);
    HINTERNET r2 = U(HttpOpenRequestA)(c2, "GET", "/2", NULL, NULL, NULL, T_INET_FRESH, CTX_URL);
    int p; DWORD e;
    CHECK(ac_send_wait(r1, CTX_REQ, NULL, NULL, 0, &p, &e));
    CHECK(ac_send_wait(r2, CTX_URL, NULL, NULL, 0, &p, &e));
    for (int i = 0; i < ac_count(); i++) {
        ac_ev ev; ac_get(i, &ev);
        if (ev.ctx == CTX_REQ || ev.ctx == CTX_CON) CHECKF(ev.wide == 0, "event %d st %lu went to the wrong callback", i, ev.st);
        if (ev.ctx == CTX_URL || ev.ctx == CTX_ALT) CHECKF(ev.wide == 2, "event %d st %lu went to the wrong callback", i, ev.st);
    }
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_URL), 1);
    ac_close_wait(r1, CTX_REQ); ac_close_wait(r2, CTX_URL); ac_close_wait(c1, CTX_CON); ac_close_wait(c2, CTX_ALT);
    U(InternetCloseHandle)(h1); U(InternetCloseHandle)(h2);
    srv_stop(s);
}

/* ------------------------------------------------------------------ tables */
TEST(ac_status_code_table) {
    REQ_ASYNC_API();
    static const int codes[] = { 200, 201, 202, 204, 206, 301, 302, 303, 307, 400, 401, 403, 404, 405, 410, 418, 500, 501, 502, 503 };
    for (unsigned k = 0; k < sizeof codes / sizeof codes[0]; k++) {
        srv_step st[] = { S_HEAD(), { SRV_REPLY, "body", 4, codes[k], codes[k] >= 300 && codes[k] < 400 ? "Location: /elsewhere\r\n" : NULL }, S_LOOP() };
        ac_begin(); ac_flow f;
        if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/code", T_INET_FRESH_NOREDIR)) return;
        int pending; DWORD err; int n0 = ac_count();
        int ok = ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err);
        CHECKF(ok && pending, "code %d: ok=%d pending=%d err=%lu", codes[k], ok, pending, err);
        CHECKF(ac_status_code(f.hr) == (DWORD)codes[k], "code %d: got %lu", codes[k], ac_status_code(f.hr));
        ac_quiesce(50, 300);
        const char *s = ac_seq_range(0, n0, -1, NULL);
        CHECKF(!strcmp(s, "80,20,21,30,31,40,41,100"), "code %d: seq %s", codes[k], s);
        EXPECT_EQ(ac_count_st(INTERNET_STATUS_REDIRECT), 0);
        char b[16]; int np;
        long n = ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np);
        /* the server sends Content-Length: 4 and the bytes even with 204; WinINet delivers them [W10] */
        CHECKF(n == 4, "code %d: body %ld", codes[k], n);
        ac_flow_close(&f);
    }
}
TEST(ac_body_size_table) {
    REQ_ASYNC_API();
    static const size_t sizes[] = { 0, 1, 2, 100, 1023, 1024, 4096, 8191, 8192, 8193, 16384, 65535, 65536, 65537, 150000 };
    static char big[150001];
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, sizes[k], 0), S_LOOP() };
        ac_begin(); ac_flow f;
        if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/sz", T_INET_FRESH)) return;
        int pending; DWORD err;
        CHECKF(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err), "size %u err %lu", (unsigned)sizes[k], err);
        int np = 0;
        long n = ac_read_all_async(f.hr, CTX_REQ, big, sizeof big, &np);
        CHECKF(n == (long)sizes[k], "size %u: read %ld", (unsigned)sizes[k], n);
        CHECKF(srv_pattern_check(big, sizes[k], 0), "size %u: pattern", (unsigned)sizes[k]);
        /* every pending read completed exactly once */
        CHECKF(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ) == 1 + np, "size %u: completions %d pending %d", (unsigned)sizes[k],
               ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), np);
        ac_flow_close(&f);
    }
}
TEST(ac_verb_table_async) {
    REQ_ASYNC_API();
    static const char *verbs[] = { "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "X-CUSTOM" };
    for (unsigned k = 0; k < sizeof verbs / sizeof verbs[0]; k++) {
        static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "v"), S_LOOP() };
        ac_begin(); ac_flow f;
        if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, verbs[k], "/v", T_INET_FRESH)) return;
        int pending; DWORD err;
        CHECKF(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err) && pending, "verb %s err %lu", verbs[k], err);
        CHECK(srv_wait_requests(f.s, 1, 2000));
        CHECKF(!strcmp(srv_req_method(f.s, 0) ? srv_req_method(f.s, 0) : "", verbs[k]), "verb %s", verbs[k]);
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_SENT, CTX_REQ), 1);
        ac_flow_close(&f);
    }
}

/* ------------------------------------------------------------------ W entry points */
TEST(ac_w_apis_async) {
    REQ_ASYNC_API(); REQUIRE(U(InternetConnectW)); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW)); REQUIRE(U(InternetOpenW));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = U(InternetOpenW)(L"ac-w", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    CHECK(hi != NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackW)(hi, ac_cbw), NULL);
    HINTERNET hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET hr = hc ? U(HttpOpenRequestW)(hc, L"GET", L"/w", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ) : NULL;
    CHECK(hr != NULL);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_HANDLE_CREATED), 2);
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestW)(hr, L"X-W: 1\r\n", (DWORD)-1, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT res;
    CHECK(ac_wait_complete(CTX_REQ, 1, 5000, &res));
    EXPECT_EQ(res.dwResult, TRUE);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    for (int i = 0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); CHECK(ev.wide == 1); }
    CHECK(srv_wait_requests(s, 1, 2000));
    EXPECT_STR(srv_req_header(s, 0, "X-W"), "1");
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetCloseHandle)(hi);
    srv_stop(s);
}
TEST(ac_openurl_w_async) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlW));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open(INTERNET_FLAG_ASYNC);
    U(InternetSetStatusCallbackW)(hi, ac_cbw);
    WCHAR url[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(s, "/ouw"), -1, url, 128);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlW)(hi, url, NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 5000, &r));
    CHECK(r.dwResult != 0);
    ac_quiesce(100, 300);
    EXPECT_STR(ac_seq(0, NULL), "60,80,20,21,30,31,40,41,100");
    if (r.dwResult) ac_close_wait((HINTERNET)r.dwResult, CTX_URL);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* ------------------------------------------------------------------ sync mode: redirects, cookies, closing */
TEST(ac_sync_redirect_sequence) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, 0, ac_cb, "GET", "/src", T_INET_FRESH)) return;
    int n0 = ac_count();
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,110,80,30,31,40,41");
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        char want[96]; snprintf(want, sizeof want, "http://127.0.0.1:%u/dst", srv_port(f.s));
        EXPECT_STR((char *)ev.info, want);
        EXPECT_EQ(ev.len, strlen(want) + 1);   /* [W10] narrow: length includes the terminating NUL */
    } else CHECK(i >= 0);
    ac_flow_close(&f);
}
TEST(ac_sync_cookie_received) {
    REQ_ASYNC_API();
    const char *path = t_uniq("sck");
    char p1[128], sc[256];
    snprintf(p1, sizeof p1, "/%s/a", path);
    snprintf(sc, sizeof sc, "Set-Cookie: acsy=v; Path=/%s\r\n", path);
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "c", 1, 200, sc }, S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, 0, ac_cb, "GET", p1, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_UI)) return;
    char curl[160]; snprintf(curl, sizeof curl, "http://127.0.0.1/%s/", path);
    t_cookie_track(curl, "acsy");
    int n0 = ac_count();
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,321");
    ac_flow_close(&f);
}
TEST(ac_sync_closing_on_calling_thread) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, 0, ac_cb, "GET", "/c", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    int n0 = ac_count();
    CHECK(U(InternetCloseHandle)(f.hr));
    /* synchronous: delivered before InternetCloseHandle returns. The 5-byte body was never read, so the
     * connection is not reusable and is closed first (50, 51) [W10] */
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "50,51,70");
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    int i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) EXPECT_EQ(ev.tid, ac_main_tid);
    f.hr = NULL;
    ac_flow_close(&f);
}
/* an async request whose response was not read: closing it still reports only HANDLE_CLOSING */
TEST(ac_async_close_unread_response) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 100000, 0), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/unread", T_INET_FRESH)) return;
    int p; DWORD e;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &p, &e));
    int n0 = ac_count();
    U(InternetCloseHandle)(f.hr); f.hr = NULL;
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 3000));
    ac_quiesce(100, 500);
    t_note("close with 100000 unread bytes: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "50,51,70");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    ac_flow_close(&f);
}
TEST(ac_async_zero_length_read) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/z", T_INET_FRESH)) return;
    int p; DWORD e;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &p, &e));
    static char b[8]; static DWORD rd;
    rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, 0, &rd);
    DWORD err = GetLastError();
    t_note("zero-length async read: ok=%d err=%lu rd=0x%lx", ok, err, rd);
    CHECK(ok); EXPECT_EQ(rd, 0);   /* [W10] */
    if (!ok && err == ERROR_IO_PENDING) { INTERNET_ASYNC_RESULT r; ac_wait_complete(CTX_REQ, 2, 3000, &r); }
    char body[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, body, sizeof body, &np), 5);
    ac_flow_close(&f);
}
TEST(ac_async_read_request_complete_payload) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n"), S_SLEEP(500), S_SEND("abc"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/p", T_INET_FRESH)) return;
    int p; DWORD e;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &p, &e));
    static char b[8]; static DWORD rd;
    int n0 = ac_count();
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    EXPECT_EQ(ok, FALSE);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, 2, 5000, &r));
    int i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        EXPECT_EQ(ev.h, f.hr);
        EXPECT_EQ(ev.len, sizeof(INTERNET_ASYNC_RESULT));
        CHECK(ev.tid != ac_main_tid);
        EXPECT_EQ(r.dwResult, TRUE);
        EXPECT_EQ(r.dwError, 0);
    } else CHECK(i >= 0);
    EXPECT_EQ(rd, 3);
    ac_flow_close(&f);
}
