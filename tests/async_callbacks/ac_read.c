/* ac_read.c - asynchronous InternetReadFile / InternetReadFileEx / InternetQueryDataAvailable, completion
 * semantics (what is written when, what REQUEST_COMPLETE carries), reads driven from inside the callback.
 * Async output parameters live in static storage: WinINet may write them from a worker thread after the call
 * returned ERROR_IO_PENDING. */
#include "ac.h"

/* head now, body after a delay: the body is not buffered when the send completes */
static const srv_step ST_DELAYED[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"), S_SLEEP(800), S_SEND("hello"), S_LOOP() };
/* head and a first part, then the rest */
static const srv_step ST_TWO_PARTS[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde"), S_SLEEP(800), S_SEND("fghij"), S_LOOP() };

static int open_and_send(ac_flow *f, const srv_step *st, int n, DWORD sflags) {
    if (!ac_flow_open(f, st, n, sflags, ac_cb, "GET", "/r", T_INET_FRESH)) return 0;
    int pending; DWORD err;
    if (!ac_send_wait(f->hr, CTX_REQ, NULL, NULL, 0, &pending, &err)) { t_check(0, __FILE__, __LINE__, "send", "err %lu", err); ac_flow_close(f); return 0; }
    return 1;
}

/* ------------------------------------------------------------------ InternetReadFile */
TEST(ac_read_buffered_completes_synchronously) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static DWORD rd;
    Sleep(200);    /* the 5-byte body arrived with the head */
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    DWORD e = GetLastError();
    t_note("buffered async read: ok=%d err=%lu rd=%lu", ok, e, rd);
    CHECK(ok);
    EXPECT_EQ(rd, 5);
    CHECK(!memcmp(b, "hello", 5));
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    rd = 0xdeadbeef;
    ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    if (!ok && GetLastError() == ERROR_IO_PENDING) { INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 3000, &r)); t_note("EOF read went pending"); }
    else CHECK(ok);
    EXPECT_EQ(rd, 0);
    ac_flow_close(&f);
}
TEST(ac_read_pending_then_complete) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_DELAYED, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static DWORD rd;
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    int n0 = ac_count();
    rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE);
    EXPECT_EQ(e, ERROR_IO_PENDING);
    t_note("rd right after pending read: 0x%lx", rd);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE);
    EXPECT_EQ(r.dwError, 0);
    EXPECT_EQ(rd, 5);
    CHECK(!memcmp(b, "hello", 5));
    t_note("pending read sequence: %s", ac_seq_range(0, n0, -1, NULL));
    int i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) { EXPECT_EQ(ev.h, f.hr); CHECK(ev.tid != ac_main_tid); }
    ac_flow_close(&f);
}
TEST(ac_read_pending_statuses) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_DELAYED, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static DWORD rd;
    int n0 = ac_count();
    rd = 0;
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    if (!ok && GetLastError() == ERROR_IO_PENDING) { INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(CTX_REQ, 2, 5000, &r)); }
    ac_quiesce(100, 300);
    const char *s = ac_seq_range(CTX_REQ, n0, -1, NULL);
    t_note("read statuses: %s", s);
    EXPECT_STR(s, "40,41,100");
    int i = ac_find(INTERNET_STATUS_RESPONSE_RECEIVED, CTX_REQ, n0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) EXPECT_EQ(ac_info_dword(&ev), 5);
    ac_flow_close(&f);
}
/* [W10] an async InternetReadFile does not return the 5 buffered bytes early: it goes pending and completes once
 * the buffer is full or the body is complete (here: all 10 bytes in one completion) */
TEST(ac_read_partial_waits_for_rest) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_TWO_PARTS, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static DWORD rd;
    Sleep(100);
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    rd = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    DWORD e = GetLastError();
    t_note("first read: ok=%d err=%lu rd=0x%lx", ok, e, rd);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    if (!ok && e == ERROR_IO_PENDING) CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r));
    EXPECT_EQ(r.dwResult, TRUE);
    EXPECT_EQ(rd, 10);
    CHECK(!memcmp(b, "abcdefghij", 10));
    rd = 0xdeadbeef;
    ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    CHECK(ok); EXPECT_EQ(rd, 0);
    ac_flow_close(&f);
}
/* a read that asks for no more than what is buffered completes synchronously */
TEST(ac_read_small_buffer_from_buffered_data) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_TWO_PARTS, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static DWORD rd;
    Sleep(100);
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    for (int k = 0; k < 5; k++) {
        rd = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetReadFile)(f.hr, b + k, 1, &rd);
        CHECKF(ok, "k=%d err=%lu", k, GetLastError());
        EXPECT_EQ(rd, 1);
    }
    CHECK(!memcmp(b, "abcde", 5));
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c0);
    ac_flow_close(&f);
}
TEST(ac_read_whole_body_pattern) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, st, 3, INTERNET_FLAG_ASYNC)) return;
    static char big[200001];
    int np = 0;
    long n = ac_read_all_async(f.hr, CTX_REQ, big, sizeof big, &np);
    EXPECT_EQ(n, 200000);
    CHECK(srv_pattern_check(big, 200000, 0));
    t_note("200000 bytes read with %d pending reads", np);
    ac_flow_close(&f);
}
TEST(ac_read_chunked_async) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n"), S_SLEEP(500), S_SEND("4\r\ndefg\r\n0\r\n\r\n"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, st, 5, INTERNET_FLAG_ASYNC)) return;
    char b[64]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 7);
    EXPECT_STR(b, "abcdefg");
    t_note("chunked: %d pending reads", np);
    ac_flow_close(&f);
}
TEST(ac_read_close_delimited_async) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\nxyz"), S_SLEEP(500), S_SEND("123"), S_CLOSE() };
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, st, 5, INTERNET_FLAG_ASYNC)) return;
    char b[64]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 6);
    EXPECT_STR(b, "xyz123");
    ac_flow_close(&f);
}
TEST(ac_read_truncated_body_async) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, NULL, "0123456789", SRV_R_TRUNCATE) };
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, st, 2, INTERNET_FLAG_ASYNC)) return;
    char b[64]; int np;
    long n = ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np);
    t_note("truncated body: read %ld", n);
    EXPECT_EQ(n, 5);   /* [W10] the premature close ends the body without an error */
    ac_flow_close(&f);
}
TEST(ac_read_sync_session_with_callback) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, ST_DELAYED, 5, 0, ac_cb, "GET", "/r", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    int n0 = ac_count();
    char b[16]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(f.hr, b, sizeof b, &rd));
    EXPECT_EQ(rd, 5);
    t_note("sync read statuses: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(CTX_REQ, n0, -1, NULL), "40,41");
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    ac_flow_close(&f);
}
TEST(ac_read_bad_handle_async_session) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    static char b[8]; static DWORD rd;
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetReadFile)(hi, b, sizeof b, &rd));
    DWORD e = GetLastError();
    t_note("InternetReadFile(session) err=%lu", e);
    CHECK(e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE || e == ERROR_INVALID_HANDLE);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_read_before_send_async) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/r", T_INET_FRESH)) return;
    static char b[8]; static DWORD rd;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    DWORD e = GetLastError();
    t_note("read before send (async): ok=%d err=%lu rd=%lu", ok, e, rd);
    CHECK(ok); EXPECT_EQ(rd, 0);   /* [W10] */
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ InternetQueryDataAvailable */
TEST(ac_qda_buffered_sync_return) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    Sleep(200);
    static DWORD av;
    av = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    t_note("QDA buffered: ok=%d err=%lu av=%lu", ok, GetLastError(), av);
    CHECK(ok); EXPECT_EQ(av, 5);
    ac_flow_close(&f);
}
TEST(ac_qda_pending_result) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_DELAYED, 5, INTERNET_FLAG_ASYNC)) return;
    static DWORD av;
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    av = 0xdeadbeef;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r));
    t_note("QDA completion: dwResult=%llu dwError=%lu av=0x%lx", (unsigned long long)r.dwResult, r.dwError, av);
    EXPECT_EQ(r.dwResult, TRUE);
    /* the available byte count is reported in dwError of the completion */
    EXPECT_EQ(r.dwError, 5);
    EXPECT_EQ(av, 5);   /* [W10] lpdwNumberOfBytesAvailable is written as well */
    /* and the data is now buffered: a second QDA answers synchronously */
    DWORD av2 = 0;
    CHECK(U(InternetQueryDataAvailable)(f.hr, &av2, 0, 0));
    EXPECT_EQ(av2, 5);
    static char b[16]; static DWORD rd;
    CHECK(U(InternetReadFile)(f.hr, b, sizeof b, &rd));
    EXPECT_EQ(rd, 5);
    ac_flow_close(&f);
}
TEST(ac_qda_at_eof) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    static DWORD av; av = 0xdeadbeef;
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(CTX_REQ, c0 + 1, 3000, &r));
        t_note("QDA at EOF went pending: %llu/%lu", (unsigned long long)r.dwResult, r.dwError);
    } else { CHECK(ok); EXPECT_EQ(av, 0); }
    ac_flow_close(&f);
}
TEST(ac_qda_flags_nonzero) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    Sleep(100);
    static DWORD av; av = 0;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetQueryDataAvailable)(f.hr, &av, 1, 0);
    t_note("QDA dwFlags=1: ok=%d err=%lu av=%lu", ok, GetLastError(), av);
    CHECK(ok); EXPECT_EQ(av, 5);   /* [W10] reserved arguments are not validated */
    av = 0;
    ok = U(InternetQueryDataAvailable)(f.hr, &av, 0, 0x55);
    t_note("QDA dwContext=0x55: ok=%d err=%lu av=%lu", ok, GetLastError(), av);
    CHECK(ok); EXPECT_EQ(av, 5);
    ac_flow_close(&f);
}
TEST(ac_qda_sync_session) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryDataAvailable));
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, ST_DELAYED, 5, 0, ac_cb, "GET", "/r", T_INET_FRESH)) return;
    CHECK(U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0));
    DWORD av = 0;
    CHECK(U(InternetQueryDataAvailable)(f.hr, &av, 0, 0));
    EXPECT_EQ(av, 5);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ InternetReadFileEx */
TEST(ac_rfex_irf_async_pending) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_DELAYED, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static INTERNET_BUFFERSA ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, CTX_ALT);
    DWORD e = GetLastError();
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(0, c0 + 1, 5000, &r));
    int i = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, 0), j = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_ALT, 0);
    t_note("ReadFileEx completion: req-ctx@%d alt-ctx@%d dwResult=%llu len=%lu", i, j, (unsigned long long)r.dwResult, ib.dwBufferLength);
    /* the dwContext argument is not used for the completion: the handle's context is (decomp: thread ctx = handle+0xb8) */
    EXPECT_EQ(j, -1);
    EXPECT_EQ(r.dwResult, TRUE);
    EXPECT_EQ(ib.dwBufferLength, 5);
    CHECK(!memcmp(b, "hello", 5));
    ac_flow_close(&f);
}
TEST(ac_rfex_irf_async_buffered) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    Sleep(200);
    static char b[64]; static INTERNET_BUFFERSA ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, 0);
    t_note("ReadFileEx buffered: ok=%d err=%lu len=%lu", ok, GetLastError(), ib.dwBufferLength);
    CHECK(ok); EXPECT_EQ(ib.dwBufferLength, 5);
    ac_flow_close(&f);
}
TEST(ac_rfex_irf_no_wait) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_DELAYED, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static INTERNET_BUFFERSA ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_NO_WAIT, 0);
    DWORD e = GetLastError();
    t_note("IRF_NO_WAIT with nothing buffered: ok=%d err=%lu len=%lu", ok, e, ib.dwBufferLength);
    /* [W10] IRF_NO_WAIT does not turn the read into a poll in an async session: it goes pending */
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(0, c0 + 1, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); t_note("NO_WAIT completion len=%lu", ib.dwBufferLength); }
    ac_flow_close(&f);
}
TEST(ac_rfex_irf_sync_flag_in_async_session) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, ST_DELAYED, 5, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static INTERNET_BUFFERSA ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    int c0 = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_SYNC, 0);
    DWORD e = GetLastError();
    t_note("IRF_SYNC in async session: ok=%d err=%lu len=%lu", ok, e, ib.dwBufferLength);
    /* [W10] IRF_SYNC does not force a synchronous read in an async session */
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { INTERNET_ASYNC_RESULT r; CHECK(ac_wait_complete(0, c0 + 1, 5000, &r)); EXPECT_EQ(ib.dwBufferLength, 5); }
    ac_flow_close(&f);
}
TEST(ac_rfex_bad_struct_size) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static INTERNET_BUFFERSA ib;
    static const DWORD sizes[] = { 0, 4, sizeof(INTERNET_BUFFERSA) - 1, sizeof(INTERNET_BUFFERSA) + 1, 40 };
    for (unsigned k = 0; k < sizeof sizes / sizeof sizes[0]; k++) {
        memset(&ib, 0, sizeof ib); ib.dwStructSize = sizes[k]; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, 0);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "size %lu: ok=%d err=%lu", sizes[k], ok, e);
    }
    EXPECT_EQ(sizeof(INTERNET_BUFFERSA), 0x38);
    ac_flow_close(&f);
}
TEST(ac_rfex_w_header_rejected) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExW));
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, NULL, 0, INTERNET_FLAG_ASYNC)) return;
    static char b[64]; static INTERNET_BUFFERSW ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b; ib.lpcszHeader = L"X: y";
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetReadFileExW)(f.hr, &ib, IRF_ASYNC, 0));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetReadFileExW)(f.hr, NULL, IRF_ASYNC, 0));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ac_flow_close(&f);
}
TEST(ac_rfex_whole_body) {
    REQ_ASYNC_API(); REQUIRE(U(InternetReadFileExA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 70000, 0), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!open_and_send(&f, st, 3, INTERNET_FLAG_ASYNC)) return;
    static char big[70000], b[4096]; static INTERNET_BUFFERSA ib;
    size_t tot = 0; int np = 0;
    for (int g = 0; g < 1000; g++) {
        memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
        int c0 = ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ);
        BOOL ok = U(InternetReadFileExA)(f.hr, &ib, IRF_ASYNC, 0);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) { CHECKF(0, "err %lu", GetLastError()); break; }
            np++;
            INTERNET_ASYNC_RESULT r; if (!ac_wait_complete(CTX_REQ, c0 + 1, 5000, &r) || !r.dwResult) { CHECK(0); break; }
        }
        if (!ib.dwBufferLength) break;
        if (tot + ib.dwBufferLength <= sizeof big) memcpy(big + tot, b, ib.dwBufferLength);
        tot += ib.dwBufferLength;
    }
    EXPECT_EQ(tot, 70000);
    CHECK(srv_pattern_check(big, 70000, 0));
    t_note("ReadFileEx 70000 bytes, %d pending", np);
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ reads driven from inside the callback */
static struct {
    HINTERNET hr; char buf[8192]; size_t tot; DWORD rd; volatile LONG done, failed, inline_reads, async_reads; HANDLE ev;
} g_chain;
static void chain_read_more(void) {
    for (int guard = 0; guard < 1000; guard++) {
        g_chain.rd = 0;
        BOOL ok = U(InternetReadFile)(g_chain.hr, g_chain.buf + g_chain.tot, (DWORD)(sizeof g_chain.buf - 1 - g_chain.tot), &g_chain.rd);
        if (!ok) {
            if (GetLastError() == ERROR_IO_PENDING) { InterlockedIncrement(&g_chain.async_reads); return; }
            InterlockedExchange(&g_chain.failed, 1); SetEvent(g_chain.ev); return;
        }
        InterlockedIncrement(&g_chain.inline_reads);
        if (!g_chain.rd) { InterlockedExchange(&g_chain.done, 1); SetEvent(g_chain.ev); return; }
        g_chain.tot += g_chain.rd;
    }
}
static void hook_chain(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (st != INTERNET_STATUS_REQUEST_COMPLETE || ctx != CTX_REQ) return;
    INTERNET_ASYNC_RESULT *r = (INTERNET_ASYNC_RESULT *)info;
    if (!r || !r->dwResult) { InterlockedExchange(&g_chain.failed, 1); SetEvent(g_chain.ev); return; }
    /* the send completed or a pending read completed */
    g_chain.tot += g_chain.rd; g_chain.rd = 0;
    chain_read_more();
}
TEST(ac_reentrant_read_chain_in_callback) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nchain"), S_SLEEP(300), S_SEND("-of-"), S_SLEEP(300), S_SEND("cb!"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 7, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/chain", T_INET_FRESH)) return;
    memset(&g_chain, 0, sizeof g_chain); g_chain.hr = f.hr; g_chain.ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    ac_hook = hook_chain;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    DWORD w = WaitForSingleObject(g_chain.ev, 8000);
    ac_hook = NULL;
    EXPECT_EQ(w, WAIT_OBJECT_0);
    EXPECT_EQ(g_chain.done, 1); EXPECT_EQ(g_chain.failed, 0);
    g_chain.buf[g_chain.tot] = 0;
    EXPECT_STR(g_chain.buf, "chain-of-cb!");
    t_note("chain: inline=%ld async=%ld", g_chain.inline_reads, g_chain.async_reads);
    CHECK(g_chain.async_reads >= 1);
    CloseHandle(g_chain.ev);
    ac_flow_close(&f);
}
/* the callback receives a copy of the status information [D InternetIndicateStatus memcpy] */
static volatile LONG g_mod_ok;
static void hook_scribble(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (st == INTERNET_STATUS_REQUEST_SENT && info && len >= 4) { *(DWORD *)info = 0xFFFFFFFF; InterlockedIncrement(&g_mod_ok); }
}
TEST(ac_callback_info_is_copy) {
    REQ_ASYNC_API();
    ac_begin(); g_mod_ok = 0;
    ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/copy", T_INET_FRESH)) return;
    ac_hook = hook_scribble;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_hook = NULL;
    EXPECT_EQ(g_mod_ok, 1);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 5);
    ac_flow_close(&f);
}
