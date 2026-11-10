/* bio_misc2.c - more body-handling paths: HttpSendRequestEx/InternetWriteFile/HttpEndRequest, wide-character entry
 * points, cache-backed bodies (INTERNET_FLAG_NEED_FILE, INTERNET_OPTION_DATAFILE_NAME, seeking, reading a body back
 * from the cache), a read cancelled by closing the handle, parallel readers, 206 bodies, interim responses, big
 * heads, read-buffer and timeout options, request-handle reuse.
 * Cache entries use URLs with this test's own server port and are deleted afterwards (t_cache_track).
 * VM_TIMEOUT: 300 */
#include "bio.h"
#include <stdlib.h>

#define CHUNK_HEAD_M2 "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
static const srv_step st_hello[] = { S_HEAD(), S_REPLY(200, NULL, "hello"), S_LOOP() };

/* ------------------------------------------------------------------ HttpSendRequestEx / HttpEndRequest */
TEST(bio_m2_sendex_write_end_then_read) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, NULL, 70000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "POST", "/ex", NULL, NULL, NULL, T_INET_FRESH, 0);
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 10;
    CHECK(U(HttpSendRequestExA)(hr, &ib, NULL, 0, 0));
    DWORD w = 0;
    CHECK(U(InternetWriteFile)(hr, "0123456789", 10, &w)); EXPECT_EQ(w, 10);
    CHECK(U(HttpEndRequestA)(hr, NULL, 0, 0));
    EXPECT_EQ(bio_status(hr), 200);
    unsigned char *b = malloc(70016); bio_rd r; size_t n = bio_read(hr, b, 70016, 9000, &r);
    CHECK(r.ok); EXPECT_EQ(n, 70000); CHECK(srv_pattern_check(b, n, 0));
    size_t bl = 0; const char *body = srv_req_body(e.s, 0, &bl);
    CHECK(body && bl == 10 && !memcmp(body, "0123456789", 10));
    free(b); bio_h(hr); bio_close(&e);
}

TEST(bio_m2_read_before_end_request) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "after-end"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "POST", "/ex", NULL, NULL, NULL, T_INET_FRESH, 0);
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 3;
    CHECK(U(HttpSendRequestExA)(hr, &ib, NULL, 0, 0));
    DWORD w = 0; CHECK(U(InternetWriteFile)(hr, "abc", 3, &w));
    char b[32]; DWORD rd = 77; SetLastError(0);
    BOOL ok = U(InternetReadFile)(hr, b, sizeof b, &rd); DWORD err = GetLastError();
    t_note("InternetReadFile between HttpSendRequestEx and HttpEndRequest: ok=%d err=%lu %s rd=%lu", ok, err, ok ? "" : t_inet_errname(err), rd);
    CHECK(!ok || rd == 0);
    CHECK(U(HttpEndRequestA)(hr, NULL, 0, 0));
    bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 9); CHECK(n == 9 && !memcmp(b, "after-end", 9));
    bio_h(hr); bio_close(&e);
}

TEST(bio_m2_sendex_no_body_chunked_response) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, NULL, "chunked reply to SendRequestEx", 4), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/exg", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(U(HttpSendRequestExA)(hr, NULL, NULL, 0, 0));
    CHECK(U(HttpEndRequestA)(hr, NULL, 0, 0));
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 5, &r);
    CHECK(r.ok); EXPECT_EQ(n, 30); CHECK(n == 30 && !memcmp(b, "chunked reply to SendRequestEx", 30));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ wide-character entry points */
TEST(bio_m2_wide_request_read) {
    REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 12345, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = U(HttpOpenRequestW)(e.hc, L"GET", L"/w", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    CHECK(U(HttpSendRequestW)(hr, NULL, 0, NULL, 0));
    unsigned char b[12400]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 1000, &r);
    CHECK(r.ok); EXPECT_EQ(n, 12345); CHECK(srv_pattern_check(b, n, 0));
    DWORD cl = 0, l = sizeof cl;
    CHECK(U(HttpQueryInfoW)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL)); EXPECT_EQ(cl, 12345);
    bio_h(hr); bio_close(&e);
}

TEST(bio_m2_wide_openurl_read) {
    REQUIRE(U(InternetOpenUrlW));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, NULL, "wide openurl body", 3), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    WCHAR url[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(e.s, "/wu"), -1, url, 128);
    HINTERNET hu = U(InternetOpenUrlW)(e.hi, url, NULL, 0, T_INET_FRESH, 0);
    CHECK(hu != NULL);
    char b[64]; bio_rd r; size_t n = hu ? bio_read(hu, b, sizeof b, 2, &r) : 0;
    CHECK(r.ok); EXPECT_EQ(n, 17); CHECK(n == 17 && !memcmp(b, "wide openurl body", 17));
    bio_h(hu); bio_close(&e);
}

TEST(bio_m2_wide_readfileex_large) {
    REQUIRE(U(InternetReadFileExW));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 300000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/wx");
    unsigned char *b = malloc(300100); size_t n = 0; int ok = 1, over = 0;
    for (int i = 0; i < 10000; i++) {
        INTERNET_BUFFERSW ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = b + n;
        ib.dwBufferLength = 300100 - n < 16384 ? (DWORD)(300100 - n) : 16384;
        DWORD want = ib.dwBufferLength;
        if (!U(InternetReadFileExW)(hr, &ib, IRF_SYNC, 0)) { ok = 0; break; }
        if (ib.dwBufferLength > want) over++;
        if (!ib.dwBufferLength) break;
        n += ib.dwBufferLength;
    }
    CHECK(ok); EXPECT_EQ(n, 300000); EXPECT_EQ(over, 0); CHECK(srv_pattern_check(b, n, 0));
    free(b); bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ cache-backed bodies */
/* request that may write the cache (no NO_CACHE_WRITE), unique URL (fresh port) */
static HINTERNET cached_get(bio_env *e, const char *path, DWORD extra, char *url, size_t ucap) {
    snprintf(url, ucap, "%s", srv_url(e->s, path));
    t_cache_track(url);
    HINTERNET hr = U(HttpOpenRequestA)(e->hc, "GET", path, NULL, NULL, NULL,
                                       INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES | extra, 0);
    CHECK(hr != NULL);
    CHECKF(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0), "send err=%lu", GetLastError());
    return hr;
}
#define CACHEABLE "Cache-Control: max-age=600\r\nContent-Type: application/octet-stream\r\n"

TEST(bio_m2_need_file_datafile_matches_body) {
    REQUIRE(U(InternetQueryOptionA)); REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, CACHEABLE, 50000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    char url[128]; HINTERNET hr = cached_get(&e, "/nf.bin", INTERNET_FLAG_NEED_FILE, url, sizeof url);
    unsigned char *b = malloc(50100); bio_rd r; size_t n = bio_read(hr, b, 50100, 7000, &r);
    CHECK(r.ok); EXPECT_EQ(n, 50000); CHECK(srv_pattern_check(b, n, 0));
    char path[MAX_PATH] = { 0 }; DWORD l = sizeof path;
    BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_DATAFILE_NAME, path, &l);
    t_note("DATAFILE_NAME: ok=%d err=%lu len=%lu", ok, ok ? 0 : GetLastError(), l);
    CHECK(ok);
    if (ok) {
        HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        CHECKF(f != INVALID_HANDLE_VALUE, "open data file err=%lu", GetLastError());
        if (f != INVALID_HANDLE_VALUE) {
            unsigned char *fb = malloc(50100); DWORD got = 0;
            CHECK(ReadFile(f, fb, 50100, &got, NULL));
            EXPECT_EQ(got, 50000); CHECK(got == 50000 && !memcmp(fb, b, 50000));
            free(fb); CloseHandle(f);
        }
    }
    free(b); bio_h(hr); bio_close(&e);
    U(DeleteUrlCacheEntryA)(url);
}

TEST(bio_m2_datafile_name_no_cache_write) {
    REQUIRE(U(InternetQueryOptionA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/ncw");
    char b[16]; bio_rd r; bio_read(hr, b, sizeof b, 0, &r);
    char path[MAX_PATH]; DWORD l = sizeof path; SetLastError(0);
    BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_DATAFILE_NAME, path, &l); DWORD err = GetLastError();
    t_note("DATAFILE_NAME with NO_CACHE_WRITE: ok=%d err=%lu %s", ok, err, ok ? "" : t_inet_errname(err));
    CHECK(!ok);
    bio_h(hr); bio_close(&e);
}

static void seek_read_check(HINTERNET hr, LONG to, DWORD method, DWORD want_pos, DWORD len, size_t total) {
    DWORD p = U(InternetSetFilePointer)(hr, to, NULL, method, 0);
    CHECKF(p == want_pos, "seek %ld method %lu -> %lu want %lu (err %lu)", to, method, p, want_pos, GetLastError());
    if (p != want_pos) return;
    unsigned char b[4096]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, len, &rd));
    DWORD exp = (DWORD)(total - want_pos < len ? total - want_pos : len);
    CHECKF(rd == exp, "read after seek to %lu: %lu want %lu", want_pos, rd, exp);
    CHECK(srv_pattern_check(b, rd, want_pos));
}
/* Win10 VM boots 1-2: a cache-backed response is seekable while it is being read (backwards and forwards, also past
 * what has been downloaded). FILE_END and some FILE_CURRENT moves fail with 131 while reading; seeking after EOF
 * depends on the handle's history (see the notes), so those are recorded only. */
TEST(bio_m2_seek_cached_large_body) {
    REQUIRE(U(InternetSetFilePointer)); REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, CACHEABLE, 100000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    char url[128]; HINTERNET hr = cached_get(&e, "/seek.bin", 0, url, sizeof url);
    unsigned char *b = malloc(100100); DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 1000, &rd)); CHECK(rd >= 1 && rd <= 1000 && srv_pattern_check(b, rd, 0));
    seek_read_check(hr, 0, FILE_BEGIN, 0, 100, 100000);
    seek_read_check(hr, 50000, FILE_BEGIN, 50000, 100, 100000);
    seek_read_check(hr, 1, FILE_BEGIN, 1, 4096, 100000);
    seek_read_check(hr, 65536, FILE_BEGIN, 65536, 4096, 100000);
    DWORD p = U(InternetSetFilePointer)(hr, 1000, NULL, FILE_BEGIN, 0); EXPECT_EQ(p, 1000);
    seek_read_check(hr, 500, FILE_CURRENT, 1500, 10, 100000);
    SetLastError(0);
    p = U(InternetSetFilePointer)(hr, -1510, NULL, FILE_CURRENT, 0); DWORD err = GetLastError();
    t_note("FILE_CURRENT -1510 after seeking to 1500 and reading 10: r=%ld err=%lu", (long)p, err);  /* boot 2: 131 */
    SetLastError(0);
    p = U(InternetSetFilePointer)(hr, -10, NULL, FILE_END, 0); err = GetLastError();
    t_note("FILE_END -10 on a 100000-byte cached body being read: r=%lu err=%lu", p, err);
    SetLastError(0);
    p = U(InternetSetFilePointer)(hr, 200000, NULL, FILE_BEGIN, 0); err = GetLastError();
    t_note("seek past the end of a 100000-byte cached body: r=%lu err=%lu", p, err);
    /* whole body from 0 to EOF */
    p = U(InternetSetFilePointer)(hr, 0, NULL, FILE_BEGIN, 0); EXPECT_EQ(p, 0);
    bio_rd r; size_t n = bio_read(hr, b, 100100, 3333, &r);
    CHECK(r.ok); EXPECT_EQ(n, 100000); CHECK(srv_pattern_check(b, n, 0));
    SetLastError(0);
    p = U(InternetSetFilePointer)(hr, 0, NULL, FILE_BEGIN, 0); err = GetLastError();
    /* boot 1 (no seek before EOF): 12016; boot 2 (after seeks while reading): 0 succeeded */
    t_note("seek to 0 after reading to EOF (handle seeked before): r=%ld err=%lu", (long)p, err);
    free(b); bio_h(hr); bio_close(&e);
    U(DeleteUrlCacheEntryA)(url);
}

TEST(bio_m2_seek_cached_before_full_read) {
    REQUIRE(U(InternetSetFilePointer)); REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, CACHEABLE, 100000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    char url[128]; HINTERNET hr = cached_get(&e, "/seekp.bin", 0, url, sizeof url);
    unsigned char b[4096]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 1000, &rd)); EXPECT_EQ(rd, 1000);
    SetLastError(0);
    DWORD p = U(InternetSetFilePointer)(hr, 0, NULL, FILE_BEGIN, 0); DWORD err = GetLastError();
    t_note("seek back to 0 after 1000 of 100000 bytes: r=%lu err=%lu", p, err);
    EXPECT_EQ(p, 0);
    if (p == 0) {
        CHECK(U(InternetReadFile)(hr, b, 500, &rd)); CHECK(rd <= 500 && srv_pattern_check(b, rd, 0));
    }
    SetLastError(0);
    p = U(InternetSetFilePointer)(hr, 90000, NULL, FILE_BEGIN, 0); err = GetLastError();
    t_note("seek forward to 90000 (not downloaded yet): r=%lu err=%lu", p, err);
    EXPECT_EQ(p, 90000);
    if (p == 90000) { CHECK(U(InternetReadFile)(hr, b, 100, &rd)); CHECK(srv_pattern_check(b, rd, 90000)); }
    bio_h(hr); bio_close(&e);
    U(DeleteUrlCacheEntryA)(url);
}

/* body read back from the cache: a second handle with INTERNET_FLAG_FROM_CACHE gets the same bytes without a request */
TEST(bio_m2_body_from_cache) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, CACHEABLE, 30000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    char url[128]; HINTERNET hr = cached_get(&e, "/fc.bin", 0, url, sizeof url);
    unsigned char *b = malloc(30100); bio_rd r; size_t n = bio_read(hr, b, 30100, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 30000);
    bio_h(hr);
    hr = U(HttpOpenRequestA)(e.hc, "GET", "/fc.bin", NULL, NULL, NULL, INTERNET_FLAG_FROM_CACHE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD err = GetLastError();
    CHECKF(ok, "FROM_CACHE send err=%lu %s", err, t_inet_errname(err));
    if (ok) {
        memset(b, 0, 30100);
        DWORD q = bio_qda(hr, &err);
        t_note("QDA on a cache-served body: %lu", q);
        n = bio_read(hr, b, 30100, 4000, &r);
        CHECK(r.ok); EXPECT_EQ(n, 30000); CHECK(srv_pattern_check(b, n, 0));
        DWORD fl = 0, l = sizeof fl;
        if (U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &fl, &l)) {
            t_note("REQUEST_FLAGS of the cache-served handle: 0x%lx", fl);
            CHECK(fl & INTERNET_REQFLAG_FROM_CACHE);
        }
    }
    EXPECT_EQ(srv_req_count(e.s), 1);
    free(b); bio_h(hr); bio_close(&e);
    U(DeleteUrlCacheEntryA)(url);
}

TEST(bio_m2_request_flags_fresh) {
    REQUIRE(U(InternetQueryOptionA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/rf");
    char b[16]; bio_rd r; bio_read(hr, b, sizeof b, 0, &r);
    DWORD fl = 0xDEAD, l = sizeof fl;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &fl, &l));
    t_note("REQUEST_FLAGS of a network response read to the end: 0x%lx", fl);
    CHECK(!(fl & INTERNET_REQFLAG_FROM_CACHE));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ cancel a blocked read by closing the handle */
typedef struct { HINTERNET h; BOOL ok; DWORD err; DWORD rd; DWORD ms; } rd_thr;
static DWORD WINAPI blocked_reader(LPVOID p) {
    rd_thr *t = p; char b[64]; DWORD t0 = GetTickCount();
    t->rd = 0; t->ok = U(InternetReadFile)(t->h, b, sizeof b, &t->rd); t->err = GetLastError();
    t->ms = GetTickCount() - t0;
    return 0;
}
TEST(bio_m2_close_handle_cancels_blocked_read) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab"), S_SLEEP(4000), S_SEND("cdefghij"), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/blk");
    char b[8]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 2, &rd)); EXPECT_EQ(rd, 2);
    rd_thr t = { hr };
    HANDLE th = CreateThread(NULL, 0, blocked_reader, &t, 0, NULL);
    Sleep(400);
    DWORD t0 = GetTickCount();
    U(InternetCloseHandle)(hr);
    DWORD w = WaitForSingleObject(th, 8000);
    t_note("blocked read after close: thread %s, ok=%d err=%lu %s rd=%lu read took %lu ms, close+join %lu ms",
           w == WAIT_OBJECT_0 ? "done" : "STILL BLOCKED", t.ok, t.err, t.ok ? "" : t_inet_errname(t.err), t.rd, t.ms, GetTickCount() - t0);
    CHECK(w == WAIT_OBJECT_0);
    if (w == WAIT_OBJECT_0) CHECK(!t.ok || t.rd == 0 || t.rd == 8);
    CloseHandle(th);
    bio_close(&e);
}

/* ------------------------------------------------------------------ parallel readers on one connect handle */
typedef struct { bio_env *e; int idx; int ok; size_t n; } par_ctx;
static int par_by_target(srv_conn *c, const srv_step *st, void *user) {
    int i = srv_conn_recv_head(c); if (i < 0) return -1;
    const char *t = srv_req_target(srv_conn_server(c), i);
    unsigned k = t ? (unsigned)strtoul(t + 2, NULL, 10) : 0;      /* "/p<k>": body = pattern from offset k*1000 */
    size_t n = 200000;
    if (srv_conn_sendf(c, "HTTP/1.1 200 OK\r\nContent-Length: %u\r\n\r\n", (unsigned)n)) return -1;
    unsigned char buf[16384];
    for (size_t off = 0; off < n; ) {
        size_t m = n - off < sizeof buf ? n - off : sizeof buf;
        for (size_t j = 0; j < m; j++) buf[j] = srv_pattern_byte(k * 1000 + off + j);
        if (srv_conn_send(c, buf, m)) return -1;
        off += m;
    }
    return 0;
}
static DWORD WINAPI par_thread(LPVOID p) {
    par_ctx *x = p; char path[16]; snprintf(path, sizeof path, "/p%d", x->idx);
    HINTERNET hr = U(HttpOpenRequestA)(x->e->hc, "GET", path, NULL, NULL, NULL, T_INET_FRESH, 0);
    if (!hr || !U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)) { if (hr) U(InternetCloseHandle)(hr); return 0; }
    unsigned char *b = malloc(200100); size_t n = 0; int ok = 1;
    for (int g = 0; g < 100000; g++) {
        DWORD rd = 0, want = 1000 + 37 * x->idx;
        if (n + want > 200100) want = (DWORD)(200100 - n);
        if (!U(InternetReadFile)(hr, b + n, want, &rd)) { ok = 0; break; }
        if (!rd) break;
        n += rd;
    }
    x->n = n; x->ok = ok && n == 200000 && srv_pattern_check(b, n, (size_t)x->idx * 1000);
    free(b); U(InternetCloseHandle)(hr);
    return 0;
}
TEST(bio_m2_parallel_readers) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_CALL(par_by_target), S_LOOP() };
    static srv_script sc[] = { { st, 2 } };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1; cfg.lifetime_ms = 30000;
    bio_env e; if (!bio_open_cfg(&e, &cfg)) return;
    par_ctx x[4]; HANDLE th[4];
    for (int i = 0; i < 4; i++) { x[i].e = &e; x[i].idx = i + 1; x[i].ok = 0; x[i].n = 0; th[i] = CreateThread(NULL, 0, par_thread, &x[i], 0, NULL); }
    DWORD w = WaitForMultipleObjects(4, th, TRUE, 20000);
    CHECK(w != WAIT_TIMEOUT);
    for (int i = 0; i < 4; i++) { CHECKF(x[i].ok, "reader %d: n=%u", i + 1, (unsigned)x[i].n); CloseHandle(th[i]); }
    t_note("4 parallel readers used %d connection(s)", srv_conn_count(e.s));
    bio_close(&e);
}

/* ------------------------------------------------------------------ 206, interim responses, big heads */
TEST(bio_m2_partial_content_206) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(206, "Content-Range: bytes 10-19/100\r\n", "0123456789"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/r", 0, "Range: bytes=10-19\r\n", &ok, &err);
    CHECK(ok); EXPECT_EQ(bio_status(hr), 206);
    char hb[64]; EXPECT_STR(bio_hdr(hr, HTTP_QUERY_CONTENT_RANGE, hb, sizeof hb, &err), "bytes 10-19/100");
    char b[32]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 3, &r);
    CHECK(r.ok); EXPECT_EQ(n, 10); CHECK(!memcmp(b, "0123456789", 10));
    CHECK(srv_wait_requests(e.s, 1, 2000));
    EXPECT_STR(srv_req_header(e.s, 0, "Range"), "bytes=10-19");
    bio_h(hr); bio_close(&e);
}

TEST(bio_m2_two_interim_100_then_chunked) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\nX-I: 1\r\n\r\n"
                                                    CHUNK_HEAD_M2 "4\r\nbody\r\n0\r\n\r\n"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/c");
    EXPECT_EQ(bio_status(hr), 200);
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 4); CHECK(!memcmp(b, "body", 4));
    bio_h(hr); bio_close(&e);
}

static void big_head_case(size_t hdr_bytes, size_t body) {
    char *resp = malloc(hdr_bytes + body + 256); size_t k = 0;
    k += sprintf(resp + k, "HTTP/1.1 200 OK\r\nContent-Length: %u\r\n", (unsigned)body);
    for (int i = 0; k < hdr_bytes; i++) k += sprintf(resp + k, "X-Pad-%04d: %0*d\r\n", i, 60, i);
    k += sprintf(resp + k, "\r\n");
    for (size_t j = 0; j < body; j++) resp[k + j] = (char)srv_pattern_byte(j);
    k += body;
    srv_step st[] = { S_HEAD(), S_SENDN(resp, k), S_LOOP() };
    bio_env e; if (bio_open(&e, st, 3)) {
        HINTERNET hr = bio_get(&e, "/bh");
        unsigned char *b = malloc(body + 16); bio_rd r; size_t n = bio_read(hr, b, body + 16, 0, &r);
        CHECKF(r.ok && n == body && srv_pattern_check(b, n, 0), "%u-byte head: ok=%d err=%lu n=%u", (unsigned)hdr_bytes, r.ok, r.err, (unsigned)n);
        free(b); bio_h(hr); bio_close(&e);
    }
    free(resp);
}
TEST(bio_m2_head_8k_body_10) { REQUIRE(U(InternetReadFile)); big_head_case(8192, 10); }
TEST(bio_m2_head_30k_body_100k) { REQUIRE(U(InternetReadFile)); big_head_case(30000, 100000); }
TEST(bio_m2_head_4095_body_1) { REQUIRE(U(InternetReadFile)); big_head_case(4095, 1); }

/* head arriving one byte per segment, body in one piece */
TEST(bio_m2_slow_head_fast_body) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SPLIT("HTTP/1.1 200 OK\r\nContent-Length: 40000\r\n\r\n", 1, 2), S_PATTERN(40000), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = bio_get(&e, "/sh");
    unsigned char *b = malloc(40016); bio_rd r; size_t n = bio_read(hr, b, 40016, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 40000); CHECK(srv_pattern_check(b, n, 0));
    free(b); bio_h(hr); bio_close(&e);
}

/* head and the whole body in one TCP send (body bytes already buffered with the head) */
TEST(bio_m2_head_and_body_one_segment) {
    REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\nabcdefghijklmnopqrstuvwxyz"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/one");
    DWORD err; DWORD q = bio_qda(hr, &err);
    EXPECT_EQ(q, 26);                         /* everything arrived with the head */
    char b[32]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd)); EXPECT_EQ(rd, 26); CHECK(!memcmp(b, "abcdefghijklmnopqrstuvwxyz", 26));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ framing variants on keep-alive */
TEST(bio_m2_http11_no_length_keepalive_header_is_close_delimited) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\nuntil-close"), S_SLEEP(300), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = bio_get(&e, "/ka");
    char b[32]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 11); CHECK(n == 11 && !memcmp(b, "until-close", 11));
    bio_h(hr); bio_close(&e);
}
TEST(bio_m2_http10_keepalive_no_length_close_delimited) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\n\r\nten-bytes!"), S_SLEEP(300), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = bio_get(&e, "/ka10");
    char b[32]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 10); CHECK(n == 10 && !memcmp(b, "ten-bytes!", 10));
    bio_h(hr); bio_close(&e);
}

/* extra bytes after a Content-Length body on a kept-alive connection: what the next request on it sees */
TEST(bio_m2_stale_bytes_before_next_response) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nstale"),
                                   S_HEAD(), S_REPLY(200, NULL, "fresh"), S_LOOP_TO(2) };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/1");
    char b[32]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));
    bio_h(hr);
    BOOL ok; DWORD err;
    hr = bio_req(&e, "GET", "/2", 0, NULL, &ok, &err);
    n = ok ? bio_read(hr, b, sizeof b, 0, &r) : 0;
    t_note("next response after stale bytes: send ok=%d err=%lu body '%.*s' (connections %d)", ok, err, (int)n, b, srv_conn_count(e.s));
    /* VM boot 1: the connection with unread extra bytes is not reused; the new connection runs the script from its
     * first step, so its answer is "hello" */
    CHECK(ok); EXPECT_EQ(srv_conn_count(e.s), 2);
    CHECK(n == 5 && !memcmp(b, "hello", 5));
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ options around reading */
TEST(bio_m2_read_buffer_size_option) {
    REQUIRE(U(InternetQueryOptionA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 100000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/rb", NULL, NULL, NULL, T_INET_FRESH, 0);
    DWORD v = 0xDEAD, l = sizeof v;
    BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_READ_BUFFER_SIZE, &v, &l);
    t_note("READ_BUFFER_SIZE on a request: ok=%d err=%lu v=%lu", ok, ok ? 0 : GetLastError(), v);
    BOOL sok = bio_set_dword(hr, INTERNET_OPTION_READ_BUFFER_SIZE, 512);
    t_note("set READ_BUFFER_SIZE 512: ok=%d err=%lu", sok, sok ? 0 : GetLastError());
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    unsigned char *b = malloc(100100); bio_rd r; size_t n = bio_read(hr, b, 100100, 65536, &r);
    CHECK(r.ok); EXPECT_EQ(n, 100000); CHECK(srv_pattern_check(b, n, 0));
    t_note("100000 bytes with READ_BUFFER_SIZE 512 and 65536-byte reads: %d reads, largest %lu", r.calls, r.maxrd);
    free(b); bio_h(hr); bio_close(&e);
}

/* Receive timeout set on the session BEFORE InternetConnect (so the connect and request handles inherit it), with a
 * 2.5 s stall in the middle of the body. Observed only: Win10 VM boot 1 showed that a 400-500 ms RECEIVE_TIMEOUT set
 * on an existing session or on the request did not cut such stalls short. Invariants: no byte invented, and a
 * failure is 12002. */
static void stall_probe(DWORD tmo, const char *tag) {
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde"), S_SLEEP(2500), S_SEND("fghij"), S_SLEEP(300), S_CLOSE() };
    srv_step cp[6]; memcpy(cp, st, sizeof cp);
    srv_script sc = { cp, 6 };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = &sc; cfg.nscripts = 1; cfg.lifetime_ms = 20000;
    srv *s = NULL; if (srv_start(&cfg, &s)) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open_ex("bio-tmo", INTERNET_OPEN_TYPE_DIRECT, 0, tmo);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/st", NULL, NULL, NULL, T_INET_FRESH, 0);
    DWORD v = 0, l = sizeof v; U(InternetQueryOptionA)(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, &l);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[16]; bio_rd r; DWORD t0 = GetTickCount(); size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("%s: request RECEIVE_TIMEOUT %lu, 2.5 s stall mid-body: ok=%d err=%lu %s n=%u after %lu ms", tag, v, r.ok, r.err,
           r.ok ? "" : t_inet_errname(r.err), (unsigned)n, GetTickCount() - t0);
    CHECK(n <= 10 && !memcmp(b, "abcdefghij", n));
    if (!r.ok) EXPECT_EQ(r.err, ERROR_INTERNET_TIMEOUT); else EXPECT_EQ(n, 10);
    bio_h(hr); bio_h(hc); t_inet_close(hi); srv_stop(s);
}
TEST(bio_m2_stall_session_timeout_400) { REQUIRE(U(InternetReadFile)); stall_probe(400, "session timeouts 400"); }
TEST(bio_m2_stall_session_timeout_1000) { REQUIRE(U(InternetReadFile)); stall_probe(1000, "session timeouts 1000"); }

TEST(bio_m2_data_receive_timeout_option) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde"), S_SLEEP(2500), S_SEND("fghij"), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/dt", NULL, NULL, NULL, T_INET_FRESH, 0);
    BOOL sok = bio_set_dword(hr, INTERNET_OPTION_DATA_RECEIVE_TIMEOUT, 400);
    DWORD v = 0, l = sizeof v; U(InternetQueryOptionA)(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, &l);
    t_note("DATA_RECEIVE_TIMEOUT 400 on request: set ok=%d; RECEIVE_TIMEOUT now %lu", sok, v);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[16]; bio_rd r; DWORD t0 = GetTickCount(); size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("mid-body stall with DATA_RECEIVE_TIMEOUT 400: ok=%d err=%lu %s n=%u after %lu ms", r.ok, r.err, r.ok ? "" : t_inet_errname(r.err), (unsigned)n, GetTickCount() - t0);
    CHECK(!memcmp(b, "abcdefghij", n));
    CHECK(r.ok); EXPECT_EQ(n, 10);             /* VM boot 1: no 12002, the read waited out the stall */
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ request handle reuse */
TEST(bio_m2_resend_after_chunked_partial) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, NULL, "0123456789abcdefghijklmnopqrstuvwxyz", 5), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/rc");
    char b[64]; DWORD rd = 0; size_t got = 0;
    while (got < 7) { rd = 0; if (!U(InternetReadFile)(hr, b + got, (DWORD)(7 - got), &rd) || !rd) break; got += rd; }
    EXPECT_EQ(got, 7); CHECK(!memcmp(b, "0123456", 7));     /* VM boot 1: a 7-byte read of 5-byte chunks returned 4 */
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD err = GetLastError();
    t_note("resend after 7 of 36 chunked bytes: ok=%d err=%lu", ok, err);
    CHECK(ok);
    if (ok) {
        bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
        CHECK(r.ok); EXPECT_EQ(n, 36); CHECK(n == 36 && !memcmp(b, "0123456789abcdefghijklmnopqrstuvwxyz", 36));
        CHECK(srv_wait_requests(e.s, 2, 2000));
    }
    bio_h(hr); bio_close(&e);
}

TEST(bio_m2_resend_three_times_counts) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "again"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/r3");
    for (int i = 0; i < 3; i++) {
        char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
        CHECKF(r.ok && n == 5 && !memcmp(b, "again", 5), "round %d", i);
        if (i < 2) CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    }
    CHECK(srv_wait_requests(e.s, 3, 2000));
    EXPECT_EQ(srv_req_count(e.s), 3);
    EXPECT_EQ(srv_conn_count(e.s), 1);
    bio_h(hr); bio_close(&e);
}

/* request headers stay queryable after the body is read */
TEST(bio_m2_request_headers_after_body) {
    REQUIRE(U(HttpQueryInfoA));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/rh", 0, "X-Mine: 42\r\n", &ok, &err);
    char b[16]; bio_rd r; bio_read(hr, b, sizeof b, 0, &r);
    char hb[64];
    CHECK(bio_custom(hr, "X-Mine", hb, sizeof hb, &err) == NULL);   /* the response has no X-Mine */
    lstrcpyA(hb, "X-Mine"); DWORD l = sizeof hb;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_REQUEST_HEADERS, hb, &l, NULL));
    EXPECT_STR(hb, "42");
    bio_h(hr); bio_close(&e);
}
