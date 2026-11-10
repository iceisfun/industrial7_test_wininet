/* bio_ex_qda.c - InternetReadFileExA/W (INTERNET_BUFFERS, IRF_* flags), InternetQueryDataAvailable,
 * InternetSetFilePointer (non-cached -> error, cache-backed seek), async reads with a status callback.
 * VM_TIMEOUT: 300
 * [D] = InternetReadFileExA@0xa2e20, InternetReadFileExW@0xa2d90, InternetQueryDataAvailable@0x76b20,
 *       InternetSetFilePointer@0x138550 -> HTTP_REQUEST_HANDLE_OBJECT::SetStreamPointer@0x16f818 */
#include "bio.h"
#include <stdlib.h>

static const srv_step st_hello[] = { S_HEAD(), S_REPLY(200, NULL, "hello"), S_LOOP() };

/* ------------------------------------------------------------------ InternetReadFileExA */
TEST(bio_rfex_struct_size_wrong_is_87) {
    REQUIRE(U(InternetReadFileExA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    static const DWORD sizes[] = { 0, 1, sizeof(INTERNET_BUFFERSA) - 1, sizeof(INTERNET_BUFFERSA) + 1, 40, 0x1000 };
    char b[16];
    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib);
        ib.dwStructSize = sizes[i]; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
        SetLastError(0);
        BOOL ok = U(InternetReadFileExA)(hr, &ib, 0, 0);
        DWORD err = GetLastError();
        CHECKF(!ok && err == ERROR_INVALID_PARAMETER, "dwStructSize=%lu ok=%d err=%lu", sizes[i], ok, err);
    }
    EXPECT_EQ(sizeof(INTERNET_BUFFERSA), 0x38);
    bio_rd r; size_t n = bio_read_ex(hr, b, sizeof b, 0, 0, &r);   /* nothing was consumed */
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));
    bio_h(hr); bio_close(&e);
}

TEST(bio_rfex_session_handle) {
    REQUIRE(U(InternetReadFileExA));
    HINTERNET hi = t_inet_open(NULL); if (!hi) { t_skip("InternetOpen"); return; }
    char b[8]; INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    BOOL ok = U(InternetReadFileExA)(hi, &ib, 0, 0); DWORD err = GetLastError();
    t_note("ReadFileExA(session): ok=%d err=%lu %s", ok, err, t_inet_errname(err));
    CHECK(!ok);
    EXPECT_EQ(err, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_inet_close(hi);
}

TEST(bio_rfex_connect_handle) {
    REQUIRE(U(InternetReadFileExA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    char b[8]; INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    BOOL ok = U(InternetReadFileExA)(e.hc, &ib, 0, 0); DWORD err = GetLastError();
    CHECK(!ok); EXPECT_EQ(err, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    bio_close(&e);
}

TEST(bio_rfex_null_and_closed_handle_is_6) {
    REQUIRE(U(InternetReadFileExA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    bio_h(hr);
    char b[8]; INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    EXPECT_FAIL(!U(InternetReadFileExA)(NULL, &ib, 0, 0), ERROR_INVALID_HANDLE);
    EXPECT_FAIL(!U(InternetReadFileExA)(hr, &ib, 0, 0), ERROR_INVALID_HANDLE);
    bio_close(&e);
}

TEST(bio_rfex_zero_length) {
    REQUIRE(U(InternetReadFileExA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[8]; INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = 0;
    CHECK(U(InternetReadFileExA)(hr, &ib, 0, 0));
    EXPECT_EQ(ib.dwBufferLength, 0);
    bio_rd r; size_t n = bio_read_ex(hr, b, sizeof b, 0, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5);
    bio_h(hr); bio_close(&e);
}

TEST(bio_rfex_fields_untouched) {
    REQUIRE(U(InternetReadFileExA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[64];
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    ib.dwBufferTotal = 0x1234; ib.dwOffsetLow = 0x55; ib.dwOffsetHigh = 0x66; ib.Next = NULL; ib.lpcszHeader = NULL; ib.dwHeadersLength = 0x77;
    CHECK(U(InternetReadFileExA)(hr, &ib, IRF_SYNC, 0));
    EXPECT_EQ(ib.dwBufferLength, 5); CHECK(!memcmp(b, "hello", 5));
    EXPECT_EQ(ib.dwStructSize, sizeof ib);
    EXPECT_EQ(ib.lpvBuffer, b);
    t_note("after ReadFileExA: total=0x%lx offlow=0x%lx offhigh=0x%lx hdrlen=0x%lx", ib.dwBufferTotal, ib.dwOffsetLow, ib.dwOffsetHigh, ib.dwHeadersLength);
    ib.dwBufferLength = sizeof b;
    CHECK(U(InternetReadFileExA)(hr, &ib, IRF_SYNC, 0));
    EXPECT_EQ(ib.dwBufferLength, 0);
    bio_h(hr); bio_close(&e);
}

static void rfex_case(size_t n, DWORD piece, DWORD flags) {
    REQUIRE(U(InternetReadFileExA));
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, n, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/x");
    unsigned char *b = malloc(n + 16); bio_rd r;
    size_t got = bio_read_ex(hr, b, n + 16, piece, flags, &r);
    CHECKF(r.ok, "flags=0x%lx err=%lu", flags, r.err);
    CHECKF(got == n, "n=%u flags=0x%lx got=%u", (unsigned)n, flags, (unsigned)got);
    CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    EXPECT_EQ(r.over, 0);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_rfex_sync_small) { rfex_case(5, 4096, IRF_SYNC); }
TEST(bio_rfex_sync_8193_by_4096) { rfex_case(8193, 4096, IRF_SYNC); }
TEST(bio_rfex_sync_65537) { rfex_case(65537, 65536, IRF_SYNC); }
TEST(bio_rfex_sync_1mb) { rfex_case(1048576, 32768, IRF_SYNC); }
TEST(bio_rfex_flags0_300000) { rfex_case(300000, 4097, 0); }
TEST(bio_rfex_by_1) { rfex_case(3000, 1, IRF_SYNC); }
/* IRF_ASYNC on a synchronous session completes synchronously */
TEST(bio_rfex_async_flag_on_sync_session) { rfex_case(70000, 8192, IRF_ASYNC); }

/* IRF_NO_WAIT on a sync session: returns whatever is buffered (possibly 0 before data arrives) */
TEST(bio_rfex_no_wait) {
    REQUIRE(U(InternetReadFileExA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 40000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/nw");
    unsigned char *b = malloc(40016); size_t n = 0; int zero = 0, fails = 0; DWORD lasterr = 0;
    for (int i = 0; i < 2000 && n < 40000; i++) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b + n; ib.dwBufferLength = 4096;
        if (!U(InternetReadFileExA)(hr, &ib, IRF_NO_WAIT, 0)) { fails++; lasterr = GetLastError(); Sleep(5); continue; }
        if (!ib.dwBufferLength) { zero++; Sleep(5); continue; }
        CHECK(ib.dwBufferLength <= 4096);
        n += ib.dwBufferLength;
    }
    t_note("IRF_NO_WAIT: n=%u zero-reads=%d fails=%d lasterr=%lu", (unsigned)n, zero, fails, lasterr);
    EXPECT_EQ(n, 40000);
    CHECK(srv_pattern_check(b, n, 0));
    free(b); bio_h(hr); bio_close(&e);
}

/* Next pointer in INTERNET_BUFFERSA is not followed (only the first buffer is filled) */
TEST(bio_rfex_next_not_followed) {
    REQUIRE(U(InternetReadFileExA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b1[2], b2[16]; memset(b2, 0xCC, sizeof b2);
    INTERNET_BUFFERSA second; memset(&second, 0, sizeof second); second.dwStructSize = sizeof second; second.lpvBuffer = b2; second.dwBufferLength = sizeof b2;
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b1; ib.dwBufferLength = sizeof b1; ib.Next = &second;
    CHECK(U(InternetReadFileExA)(hr, &ib, IRF_SYNC, 0));
    EXPECT_EQ(ib.dwBufferLength, 2); CHECK(!memcmp(b1, "he", 2));
    EXPECT_EQ(second.dwBufferLength, sizeof b2);
    EXPECT_EQ((unsigned char)b2[0], 0xCC);
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ InternetReadFileExW */
TEST(bio_rfexw_null_buffers_is_87) {
    REQUIRE(U(InternetReadFileExW));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    EXPECT_FAIL(!U(InternetReadFileExW)(hr, NULL, 0, 0), ERROR_INVALID_PARAMETER);
    EXPECT_FAIL(!U(InternetReadFileExW)(NULL, NULL, 0, 0), ERROR_INVALID_PARAMETER);   /* [D] checked before the handle */
    bio_h(hr); bio_close(&e);
}

TEST(bio_rfexw_header_pointer_is_87) {
    REQUIRE(U(InternetReadFileExW));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[16];
    INTERNET_BUFFERSW ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    ib.lpcszHeader = L"X: y\r\n"; ib.dwHeadersLength = 6;
    EXPECT_FAIL(!U(InternetReadFileExW)(hr, &ib, 0, 0), ERROR_INVALID_PARAMETER);
    ib.lpcszHeader = NULL;
    CHECK(U(InternetReadFileExW)(hr, &ib, 0, 0));
    EXPECT_EQ(ib.dwBufferLength, 5); CHECK(!memcmp(b, "hello", 5));
    bio_h(hr); bio_close(&e);
}

TEST(bio_rfexw_full_read) {
    REQUIRE(U(InternetReadFileExW));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 20000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/w");
    unsigned char *b = malloc(20016); size_t n = 0; int ok = 1;
    for (int i = 0; i < 100000; i++) {
        INTERNET_BUFFERSW ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b + n; ib.dwBufferLength = 999;
        if (!U(InternetReadFileExW)(hr, &ib, IRF_SYNC, 0)) { ok = 0; break; }
        if (!ib.dwBufferLength) break;
        n += ib.dwBufferLength; if (n > 20000) break;
    }
    CHECK(ok); EXPECT_EQ(n, 20000); CHECK(srv_pattern_check(b, n, 0));
    free(b); bio_h(hr); bio_close(&e);
}

TEST(bio_rfexw_struct_size_wrong_is_87) {
    REQUIRE(U(InternetReadFileExW));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[16];
    INTERNET_BUFFERSW ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib - 8; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b;
    EXPECT_FAIL(!U(InternetReadFileExW)(hr, &ib, 0, 0), ERROR_INVALID_PARAMETER);
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ InternetQueryDataAvailable */
TEST(bio_qda_null_out_is_87) {
    REQUIRE(U(InternetQueryDataAvailable));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    EXPECT_FAIL(!U(InternetQueryDataAvailable)(hr, NULL, 0, 0), ERROR_INVALID_PARAMETER);
    bio_h(hr); bio_close(&e);
}

TEST(bio_qda_bad_handles) {
    REQUIRE(U(InternetQueryDataAvailable));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    DWORD n = 77;
    EXPECT_FAIL(!U(InternetQueryDataAvailable)(NULL, &n, 0, 0), ERROR_INVALID_HANDLE);
    n = 77; BOOL ok = U(InternetQueryDataAvailable)(e.hi, &n, 0, 0); DWORD err = GetLastError();
    t_note("QDA(session): ok=%d err=%lu n=%lu", ok, err, n);
    CHECK(!ok); EXPECT_EQ(err, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    n = 77; ok = U(InternetQueryDataAvailable)(e.hc, &n, 0, 0); err = GetLastError();
    t_note("QDA(connect): ok=%d err=%lu n=%lu", ok, err, n);
    CHECK(!ok); EXPECT_EQ(err, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    HINTERNET hr = bio_get(&e, "/a"); bio_h(hr);
    n = 77; EXPECT_FAIL(!U(InternetQueryDataAvailable)(hr, &n, 0, 0), ERROR_INVALID_HANDLE);
    bio_close(&e);
}

TEST(bio_qda_small_body_exact) {
    REQUIRE(U(InternetQueryDataAvailable));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    DWORD err; DWORD q = bio_qda(hr, &err);
    EXPECT_EQ(q, 5);
    char b[16]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 2, &rd)); EXPECT_EQ(rd, 2);
    EXPECT_EQ(bio_qda(hr, &err), 3);
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd)); EXPECT_EQ(rd, 3);
    EXPECT_EQ(bio_qda(hr, &err), 0);
    EXPECT_EQ(bio_qda(hr, &err), 0);       /* repeatable at EOF */
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd)); EXPECT_EQ(rd, 0);
    EXPECT_EQ(bio_qda(hr, &err), 0);
    bio_h(hr); bio_close(&e);
}

TEST(bio_qda_does_not_consume) {
    REQUIRE(U(InternetQueryDataAvailable));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    DWORD err;
    for (int i = 0; i < 5; i++) EXPECT_EQ(bio_qda(hr, &err), 5);
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));
    bio_h(hr); bio_close(&e);
}

TEST(bio_qda_flags_and_context_ignored) {
    REQUIRE(U(InternetQueryDataAvailable));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    DWORD n = 77; BOOL ok = U(InternetQueryDataAvailable)(hr, &n, 0x1234, 0x5678); DWORD err = GetLastError();
    t_note("QDA dwFlags=0x1234 dwContext=0x5678: ok=%d err=%lu n=%lu", ok, err, n);
    CHECK(ok); EXPECT_EQ(n, 5);
    bio_h(hr); bio_close(&e);
}

/* QDA-driven read loop: every value is <= remaining, reading exactly that many never blocks short, sum == body */
static void qda_loop_case(size_t n, unsigned flags) {
    REQUIRE(U(InternetQueryDataAvailable));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, NULL, n, 200, NULL, flags, flags & SRV_R_CHUNKED ? 3000 : 0 }, S_LOOP() };
    bio_env e; if (!bio_open(&e, st, flags & SRV_R_CLOSE ? 2 : 3)) return;
    HINTERNET hr = bio_get(&e, "/q");
    unsigned char *b = malloc(n + 65536); size_t got = 0; int bad = 0, iters = 0; DWORD first = 0, maxq = 0;
    for (; iters < 200000; iters++) {
        DWORD err; DWORD q = bio_qda(hr, &err);
        if (q == (DWORD)-1) { CHECKF(0, "QDA failed err=%lu at %u", err, (unsigned)got); break; }
        if (!iters) first = q;
        if (q > maxq) maxq = q;
        if (q == 0) break;
        if (got + q > n) { bad++; break; }
        DWORD rd = 0;
        if (!U(InternetReadFile)(hr, b + got, q, &rd)) { CHECKF(0, "read err=%lu", GetLastError()); break; }
        if (rd != q) bad++;
        got += rd;
    }
    t_note("QDA loop n=%u flags=0x%x: first=%lu max=%lu iterations=%d", (unsigned)n, flags, first, maxq, iters);
    EXPECT_EQ(bad, 0);
    EXPECT_EQ(got, n);
    CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    if (n) CHECK(first >= 1 && first <= n);
    DWORD rd = 77; CHECK(U(InternetReadFile)(hr, b, 16, &rd)); EXPECT_EQ(rd, 0);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_qda_loop_cl_0) { qda_loop_case(0, 0); }
TEST(bio_qda_loop_cl_1) { qda_loop_case(1, 0); }
TEST(bio_qda_loop_cl_4096) { qda_loop_case(4096, 0); }
TEST(bio_qda_loop_cl_8193) { qda_loop_case(8193, 0); }
TEST(bio_qda_loop_cl_65537) { qda_loop_case(65537, 0); }
TEST(bio_qda_loop_cl_1mb) { qda_loop_case(1048576, 0); }
TEST(bio_qda_loop_chunked_10000) { qda_loop_case(10000, SRV_R_CHUNKED); }
TEST(bio_qda_loop_chunked_200000) { qda_loop_case(200000, SRV_R_CHUNKED); }
TEST(bio_qda_loop_closedelim_5000) { qda_loop_case(5000, SRV_R_CLOSE); }
TEST(bio_qda_loop_closedelim_100000) { qda_loop_case(100000, SRV_R_CLOSE); }

/* QDA blocks until data arrives (sync), it does not report 0 before the end of the body */
TEST(bio_qda_waits_for_slow_body) {
    REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde"), S_SLEEP(400), S_SEND("fghij"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/slow");
    char b[16]; DWORD rd = 0, err;
    DWORD q = bio_qda(hr, &err);
    CHECK(q >= 1 && q <= 5);
    CHECK(U(InternetReadFile)(hr, b, 5, &rd)); EXPECT_EQ(rd, 5);
    DWORD t0 = GetTickCount();
    q = bio_qda(hr, &err);
    t_note("QDA across a 400 ms gap: %lu after %lu ms", q, GetTickCount() - t0);
    EXPECT_EQ(q, 5);
    CHECK(U(InternetReadFile)(hr, b + 5, 5, &rd)); EXPECT_EQ(rd, 5);
    CHECK(!memcmp(b, "abcdefghij", 10));
    EXPECT_EQ(bio_qda(hr, &err), 0);
    bio_h(hr); bio_close(&e);
}

TEST(bio_qda_before_send) {
    REQUIRE(U(InternetQueryDataAvailable));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/never", NULL, NULL, NULL, T_INET_FRESH, 0);
    DWORD n = 77; BOOL ok = U(InternetQueryDataAvailable)(hr, &n, 0, 0); DWORD err = GetLastError();
    t_note("QDA before send: ok=%d err=%lu %s n=%lu", ok, err, ok ? "" : t_inet_errname(err), n);
    EXPECT_EQ(srv_req_count(e.s), 0);
    bio_h(hr); bio_close(&e);
}

TEST(bio_qda_truncated_body) {
    REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 1000, SRV_R_TRUNCATE) };
    bio_env e; if (!bio_open(&e, st, 2)) return;
    HINTERNET hr = bio_get(&e, "/t");
    unsigned char b[1100]; size_t got = 0; DWORD err = 0;
    for (int i = 0; i < 100; i++) {
        DWORD q = bio_qda(hr, &err);
        if (q == (DWORD)-1 || q == 0) { t_note("truncated: QDA end value %ld err=%lu after %u bytes", (long)q, err, (unsigned)got); break; }
        DWORD rd = 0; if (!U(InternetReadFile)(hr, b + got, q, &rd) || !rd) break;
        got += rd;
    }
    EXPECT_EQ(got, 500);
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ InternetSetFilePointer */
TEST(bio_sfp_session_handle_is_12018) {
    REQUIRE(U(InternetSetFilePointer));
    HINTERNET hi = t_inet_open(NULL);
    SetLastError(0);
    DWORD r = U(InternetSetFilePointer)(hi, 0, NULL, FILE_BEGIN, 0);
    EXPECT_EQ(r, INVALID_SET_FILE_POINTER);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_inet_close(hi);
}

TEST(bio_sfp_connect_handle_is_12018) {
    REQUIRE(U(InternetSetFilePointer));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    DWORD r = U(InternetSetFilePointer)(e.hc, 0, NULL, FILE_BEGIN, 0);
    EXPECT_EQ(r, INVALID_SET_FILE_POINTER);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    bio_close(&e);
}

TEST(bio_sfp_null_handle_is_6) {
    REQUIRE(U(InternetSetFilePointer));
    HINTERNET hi = t_inet_open(NULL);
    DWORD r = U(InternetSetFilePointer)(NULL, 0, NULL, FILE_BEGIN, 0);
    EXPECT_EQ(r, INVALID_SET_FILE_POINTER);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    t_inet_close(hi);
}

/* [D SetStreamPointer]: a response that is not cache-backed cannot seek: 12016 (checked before the move method) */
TEST(bio_sfp_nocache_is_12016) {
    REQUIRE(U(InternetSetFilePointer));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    static const DWORD methods[] = { FILE_BEGIN, FILE_CURRENT, FILE_END, 3, 0x1234 };
    for (size_t i = 0; i < 5; i++) {
        SetLastError(0);
        DWORD r = U(InternetSetFilePointer)(hr, 0, NULL, methods[i], 0);
        DWORD err = GetLastError();
        CHECKF(r == INVALID_SET_FILE_POINTER && err == ERROR_INTERNET_INVALID_OPERATION, "method %lu: r=0x%lx err=%lu", methods[i], r, err);
    }
    char b[16]; bio_rd rr; size_t n = bio_read(hr, b, sizeof b, 0, &rr);
    CHECK(rr.ok); EXPECT_EQ(n, 5);
    SetLastError(0);
    DWORD r = U(InternetSetFilePointer)(hr, 0, NULL, FILE_BEGIN, 0);
    EXPECT_EQ(r, INVALID_SET_FILE_POINTER); EXPECT_ERR(ERROR_INTERNET_INVALID_OPERATION);
    bio_h(hr); bio_close(&e);
}

TEST(bio_sfp_before_send) {
    REQUIRE(U(InternetSetFilePointer));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/n", NULL, NULL, NULL, T_INET_FRESH, 0);
    SetLastError(0);
    DWORD r = U(InternetSetFilePointer)(hr, 0, NULL, FILE_BEGIN, 0);
    EXPECT_EQ(r, INVALID_SET_FILE_POINTER); EXPECT_ERR(ERROR_INTERNET_INVALID_OPERATION);
    bio_h(hr); bio_close(&e);
}

/* Cache-backed response (cache write allowed): seek within the downloaded body. URL is unique (fresh port) and is
 * deleted from the cache afterwards. */
TEST(bio_sfp_cached_seek) {
    REQUIRE(U(InternetSetFilePointer)); REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Cache-Control: max-age=600\r\nContent-Type: text/plain\r\n", "0123456789ABCDEFGHIJ"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    char url[128]; snprintf(url, sizeof url, "%s", srv_url(e.s, "/seek.txt"));
    t_cache_track(url);
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/seek.txt", NULL, NULL, NULL,
                                       INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 7, &r);
    CHECK(r.ok); EXPECT_EQ(n, 20);
    SetLastError(0);
    DWORD p = U(InternetSetFilePointer)(hr, 0, NULL, FILE_BEGIN, 0); DWORD err = GetLastError();
    t_note("cache-backed seek to 0: r=0x%lx err=%lu", p, err);
    if (p == INVALID_SET_FILE_POINTER) {
        t_note("seek not available on this response (err %lu %s)", err, t_inet_errname(err));
        CHECK(err == ERROR_INTERNET_INVALID_OPERATION);
    } else {
        EXPECT_EQ(p, 0);
        DWORD rd = 0; CHECK(U(InternetReadFile)(hr, b, 4, &rd)); EXPECT_EQ(rd, 4); CHECK(!memcmp(b, "0123", 4));
        p = U(InternetSetFilePointer)(hr, 10, NULL, FILE_BEGIN, 0); EXPECT_EQ(p, 10);
        CHECK(U(InternetReadFile)(hr, b, 3, &rd)); EXPECT_EQ(rd, 3); CHECK(!memcmp(b, "ABC", 3));
        p = U(InternetSetFilePointer)(hr, 2, NULL, FILE_CURRENT, 0); t_note("FILE_CURRENT +2 -> %lu", p);
        EXPECT_EQ(p, 15);
        p = U(InternetSetFilePointer)(hr, -3, NULL, FILE_END, 0); t_note("FILE_END -3 -> %lu", p);
        EXPECT_EQ(p, 17);
        CHECK(U(InternetReadFile)(hr, b, 10, &rd)); EXPECT_EQ(rd, 3); CHECK(!memcmp(b, "HIJ", 3));
        SetLastError(0); p = U(InternetSetFilePointer)(hr, 0, NULL, 3, 0);
        EXPECT_EQ(p, INVALID_SET_FILE_POINTER); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SetLastError(0); p = U(InternetSetFilePointer)(hr, -100, NULL, FILE_END, 0);
        EXPECT_EQ(p, INVALID_SET_FILE_POINTER); EXPECT_ERR(ERROR_NEGATIVE_SEEK);
        LONG hi = 0; p = U(InternetSetFilePointer)(hr, 5, &hi, FILE_BEGIN, 0);
        EXPECT_EQ(p, 5); EXPECT_EQ(hi, 0);
        CHECK(U(InternetReadFile)(hr, b, 5, &rd)); EXPECT_EQ(rd, 5); CHECK(!memcmp(b, "56789", 5));
    }
    bio_h(hr); bio_close(&e);
    U(DeleteUrlCacheEntryA)(url);
}

/* ------------------------------------------------------------------ async session */
typedef struct { HANDLE ev; volatile LONG completes; volatile DWORD result; volatile DWORD error; } async_ctx;
static void CALLBACK async_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    async_ctx *a = (async_ctx *)ctx;
    if (status == INTERNET_STATUS_REQUEST_COMPLETE && a) {
        INTERNET_ASYNC_RESULT *r = info;
        a->result = (DWORD)r->dwResult; a->error = r->dwError;
        InterlockedIncrement(&a->completes);
        SetEvent(a->ev);
    }
}
TEST(bio_async_read_loop) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetReadFileExA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 100000, 0), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable"); return; }
    async_ctx a; memset(&a, 0, sizeof a); a.ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    HINTERNET hi = t_inet_open_ex("bio-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    CHECK(hi != NULL);
    U(InternetSetStatusCallbackA)(hi, async_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&a);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/async", NULL, NULL, NULL, T_INET_FRESH, (DWORD_PTR)&a);
    CHECK(hc && hr);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD err = GetLastError();
    if (!ok) {
        EXPECT_EQ(err, ERROR_IO_PENDING);
        CHECK(WaitForSingleObject(a.ev, 5000) == WAIT_OBJECT_0);
        CHECK(a.result != 0);
    }
    EXPECT_EQ(bio_status(hr), 200);
    unsigned char *b = malloc(100016); size_t n = 0; int pend = 0, sync = 0, guard = 0;
    while (n <= 100000 && guard++ < 10000) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b + n; ib.dwBufferLength = 8192;
        ok = U(InternetReadFileExA)(hr, &ib, IRF_ASYNC, (DWORD_PTR)&a);
        if (!ok) {
            err = GetLastError();
            if (err != ERROR_IO_PENDING) { CHECKF(0, "async read err=%lu", err); break; }
            pend++;
            if (WaitForSingleObject(a.ev, 5000) != WAIT_OBJECT_0) { CHECKF(0, "async read timed out"); break; }
            if (!a.result) { CHECKF(0, "async read completed with error %lu", a.error); break; }
        } else sync++;
        if (!ib.dwBufferLength) break;
        n += ib.dwBufferLength;
    }
    t_note("async read: %u bytes, %d pending, %d immediate completions", (unsigned)n, pend, sync);
    EXPECT_EQ(n, 100000); CHECK(srv_pattern_check(b, n, 0));
    U(InternetSetStatusCallbackA)(hi, NULL);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
    free(b); srv_stop(s); CloseHandle(a.ev);
}

TEST(bio_async_irf_no_wait) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetReadFileExA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 30000, 0), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable"); return; }
    async_ctx a; memset(&a, 0, sizeof a); a.ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    HINTERNET hi = t_inet_open_ex("bio-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    U(InternetSetStatusCallbackA)(hi, async_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&a);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/nw", NULL, NULL, NULL, T_INET_FRESH, (DWORD_PTR)&a);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (!ok && GetLastError() == ERROR_IO_PENDING) CHECK(WaitForSingleObject(a.ev, 5000) == WAIT_OBJECT_0);
    unsigned char *b = malloc(30016); size_t n = 0; int zero = 0, pend = 0;
    for (int i = 0; i < 3000 && n < 30000; i++) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b + n; ib.dwBufferLength = 4096;
        ok = U(InternetReadFileExA)(hr, &ib, IRF_NO_WAIT, (DWORD_PTR)&a);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) { pend++; WaitForSingleObject(a.ev, 5000); continue; }
            CHECKF(0, "IRF_NO_WAIT err=%lu", err); break;
        }
        if (!ib.dwBufferLength) { zero++; Sleep(5); continue; }
        n += ib.dwBufferLength;
    }
    t_note("async IRF_NO_WAIT: n=%u zero=%d pending=%d", (unsigned)n, zero, pend);
    EXPECT_EQ(n, 30000); CHECK(srv_pattern_check(b, n, 0));
    U(InternetSetStatusCallbackA)(hi, NULL);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
    free(b); srv_stop(s); CloseHandle(a.ev);
}

TEST(bio_async_qda) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 50000, 0), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable"); return; }
    async_ctx a; memset(&a, 0, sizeof a); a.ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    HINTERNET hi = t_inet_open_ex("bio-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    U(InternetSetStatusCallbackA)(hi, async_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&a);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/qa", NULL, NULL, NULL, T_INET_FRESH, (DWORD_PTR)&a);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (!ok && GetLastError() == ERROR_IO_PENDING) CHECK(WaitForSingleObject(a.ev, 5000) == WAIT_OBJECT_0);
    unsigned char *b = malloc(50016); size_t n = 0; int pend = 0;
    for (int i = 0; i < 5000; i++) {
        DWORD q = 0;
        ok = U(InternetQueryDataAvailable)(hr, &q, 0, 0);
        if (!ok) {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) { CHECKF(0, "async QDA err=%lu", err); break; }
            pend++;
            if (WaitForSingleObject(a.ev, 5000) != WAIT_OBJECT_0) { CHECK(0); break; }
            q = a.error ? 0 : (DWORD)-2;   /* dwResult carries the count on REQUEST_COMPLETE for QDA [K] */
            continue;
        }
        if (!q) break;
        if (q > 50016 - n) q = (DWORD)(50016 - n);
        DWORD rd = 0;
        ok = U(InternetReadFile)(hr, b + n, q, &rd);
        if (!ok) {
            if (GetLastError() == ERROR_IO_PENDING) { if (WaitForSingleObject(a.ev, 5000) != WAIT_OBJECT_0) { CHECK(0); break; } pend++; n += rd; continue; }
            CHECK(0); break;
        }
        n += rd;
    }
    t_note("async QDA loop: n=%u pending=%d", (unsigned)n, pend);
    EXPECT_EQ(n, 50000); CHECK(srv_pattern_check(b, n, 0));
    U(InternetSetStatusCallbackA)(hi, NULL);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
    free(b); srv_stop(s); CloseHandle(a.ev);
}
