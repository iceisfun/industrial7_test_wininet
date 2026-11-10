/* bio_read.c - InternetReadFile: argument validation, handle types, Content-Length bodies of every size class
 * around the 4096/8192/65536 boundaries up to 1 MB, read-size sweeps, EOF semantics, integrity (CRC32/SHA-256),
 * InternetOpenUrl handles.
 * VM_TIMEOUT: 600
 * Evidence: [D InternalInternetReadFile] for argument checks, everything else measured on the Win10 22H2 VM. */
#include "bio.h"
#include <stdlib.h>

/* ------------------------------------------------------------------ argument validation */
static const srv_step st_hello[] = { S_HEAD(), S_REPLY(200, NULL, "hello"), S_LOOP() };

TEST(bio_rf_null_bytesread_is_87) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[16];
    SetLastError(0);
    EXPECT_FAIL(!U(InternetReadFile)(hr, b, sizeof b, NULL), ERROR_INVALID_PARAMETER);
    /* the failed call consumed nothing */
    bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));
    bio_h(hr); bio_close(&e);
}

TEST(bio_rf_null_buffer_is_87) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    DWORD rd = 77;
    EXPECT_FAIL(!U(InternetReadFile)(hr, NULL, 10, &rd), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rd, 0);                       /* [D] *lpdwNumberOfBytesRead is zeroed before the buffer check */
    rd = 77;
    EXPECT_FAIL(!U(InternetReadFile)(hr, NULL, 0, &rd), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(rd, 0);
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5);
    bio_h(hr); bio_close(&e);
}

TEST(bio_rf_zero_length_read) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[16]; memset(b, 0xCC, sizeof b);
    for (int i = 0; i < 3; i++) {
        DWORD rd = 77; SetLastError(0xBEEF);
        CHECK(U(InternetReadFile)(hr, b, 0, &rd));
        EXPECT_EQ(rd, 0);
    }
    CHECK((unsigned char)b[0] == 0xCC);
    bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));   /* zero-length reads consumed nothing */
    bio_h(hr); bio_close(&e);
}

TEST(bio_rf_session_handle_is_12018) {
    REQUIRE(U(InternetReadFile));
    HINTERNET hi = t_inet_open(NULL); if (!hi) { t_skip("InternetOpen"); return; }
    char b[8]; DWORD rd = 77;
    EXPECT_FAIL(!U(InternetReadFile)(hi, b, sizeof b, &rd), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_note("session handle: *read after 12018 = %lu", rd);
    t_inet_close(hi);
}

TEST(bio_rf_connect_handle_is_12018) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    char b[8]; DWORD rd = 77;
    EXPECT_FAIL(!U(InternetReadFile)(e.hc, b, sizeof b, &rd), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    bio_close(&e);
}

TEST(bio_rf_null_handle_is_6) {
    REQUIRE(U(InternetReadFile));
    HINTERNET hi = t_inet_open(NULL);           /* make sure wininet is initialised */
    char b[8]; DWORD rd = 77;
    EXPECT_FAIL(!U(InternetReadFile)(NULL, b, sizeof b, &rd), ERROR_INVALID_HANDLE);
    t_inet_close(hi);
}

TEST(bio_rf_closed_request_handle_is_6) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    CHECK(U(InternetCloseHandle)(hr));
    char b[8]; DWORD rd = 77;
    EXPECT_FAIL(!U(InternetReadFile)(hr, b, sizeof b, &rd), ERROR_INVALID_HANDLE);
    bio_close(&e);
}

TEST(bio_rf_child_after_session_close_is_6) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    U(InternetCloseHandle)(e.hi); e.hi = NULL;      /* closes the connect and request children too */
    char b[8]; DWORD rd = 77;
    BOOL ok = U(InternetReadFile)(hr, b, sizeof b, &rd); DWORD err = GetLastError();
    CHECKF(!ok && err == ERROR_INVALID_HANDLE, "ok=%d err=%lu rd=%lu", ok, err, rd);
    e.hc = NULL; bio_close(&e);
}

/* [W10 prior lane, 02 section 16 row 2]: reading a request that was never sent succeeds with 0 bytes */
TEST(bio_rf_before_send) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/never", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    char b[8]; DWORD rd = 77;
    BOOL ok = U(InternetReadFile)(hr, b, sizeof b, &rd); DWORD err = GetLastError();
    t_note("read before send: ok=%d err=%lu rd=%lu", ok, err, rd);
    CHECK(ok); EXPECT_EQ(rd, 0);
    EXPECT_EQ(srv_req_count(e.s), 0);          /* nothing went on the wire */
    bio_h(hr); bio_close(&e);
}

/* bytes past *lpdwNumberOfBytesRead are untouched */
TEST(bio_rf_buffer_tail_untouched) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    unsigned char b[64]; memset(b, 0xCC, sizeof b);
    DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd));
    EXPECT_EQ(rd, 5);
    CHECK(!memcmp(b, "hello", 5));
    int clean = 1; for (size_t i = 5; i < sizeof b; i++) if (b[i] != 0xCC) clean = 0;
    CHECK(clean);
    memset(b, 0xCC, sizeof b); rd = 77;
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd));
    EXPECT_EQ(rd, 0); EXPECT_EQ(b[0], 0xCC);
    bio_h(hr); bio_close(&e);
}

TEST(bio_rf_eof_is_repeatable) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[16]; bio_rd r; bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(r.n, 5);
    for (int i = 0; i < 5; i++) {
        DWORD rd = 77; SetLastError(0xBEEF);
        BOOL ok = U(InternetReadFile)(hr, b, sizeof b, &rd);
        CHECK(ok); EXPECT_EQ(rd, 0);
    }
    EXPECT_EQ(bio_status(hr), 200);            /* headers still queryable after EOF */
    bio_h(hr); bio_close(&e);
}

TEST(bio_rf_last_error_after_success) {
    REQUIRE(U(InternetReadFile));
    bio_env e; if (!bio_open(&e, st_hello, 3)) return;
    HINTERNET hr = bio_get(&e, "/a");
    char b[16]; DWORD rd = 0;
    SetLastError(0xBEEF);
    CHECK(U(InternetReadFile)(hr, b, 2, &rd));
    t_note("GetLastError after successful read: %lu", GetLastError());
    EXPECT_EQ(rd, 2); CHECK(!memcmp(b, "he", 2));
    SetLastError(0xBEEF);
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd));
    EXPECT_EQ(rd, 3); CHECK(!memcmp(b, "llo", 3));
    t_note("GetLastError after final data read: %lu", GetLastError());
    SetLastError(0xBEEF);
    CHECK(U(InternetReadFile)(hr, b, sizeof b, &rd)); EXPECT_EQ(rd, 0);
    t_note("GetLastError after EOF read: %lu", GetLastError());
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ Content-Length size sweep */
/* One server per test, pattern body of n bytes, read with pieces of `piece` bytes. Checks the whole contract:
 * byte count, content, Content-Length header, no over-read, EOF repeatable. */
static void cl_case(size_t n, DWORD piece) {
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, n, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/cl");
    EXPECT_EQ(bio_status(hr), 200);
    DWORD cl = 0xDEAD, l = sizeof cl;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL));
    EXPECT_EQ(cl, n);
    unsigned char *b = malloc(n + 16);
    bio_rd r; size_t got = bio_read(hr, b, n + 16, piece, &r);
    CHECKF(r.ok, "read failed err=%lu after %u bytes", r.err, (unsigned)got);
    CHECKF(got == n, "n=%u piece=%lu got=%u", (unsigned)n, piece, (unsigned)got);
    CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    EXPECT_EQ(r.over, 0);
    CHECK(r.maxrd <= piece);
    if (piece < n) CHECK(r.calls >= (int)((n + piece - 1) / piece));
    DWORD rd = 77; CHECK(U(InternetReadFile)(hr, b, 16, &rd)); EXPECT_EQ(rd, 0);
    free(b); bio_h(hr); bio_close(&e);
}
#define CL_TEST(n, piece) TEST(bio_cl_##n##_by_##piece) { REQUIRE(U(InternetReadFile)); cl_case(n, piece); }
CL_TEST(0, 1) CL_TEST(0, 4096)
CL_TEST(1, 1) CL_TEST(1, 4096)
CL_TEST(2, 1)
CL_TEST(100, 1) CL_TEST(100, 7) CL_TEST(100, 100) CL_TEST(100, 99) CL_TEST(100, 101)
CL_TEST(4095, 1) CL_TEST(4095, 4096) CL_TEST(4095, 4095)
CL_TEST(4096, 1) CL_TEST(4096, 4095) CL_TEST(4096, 4096) CL_TEST(4096, 4097) CL_TEST(4096, 65536)
CL_TEST(4097, 4096) CL_TEST(4097, 13) CL_TEST(4097, 65536)
CL_TEST(8191, 8192) CL_TEST(8191, 1000)
CL_TEST(8192, 1) CL_TEST(8192, 8191) CL_TEST(8192, 8192) CL_TEST(8192, 8193)
CL_TEST(8193, 8192) CL_TEST(8193, 4096) CL_TEST(8193, 65536)
CL_TEST(16384, 4096) CL_TEST(32767, 32768) CL_TEST(32768, 32768) CL_TEST(32769, 32768)
CL_TEST(65535, 65536) CL_TEST(65535, 512) CL_TEST(65535, 1)
CL_TEST(65536, 65536) CL_TEST(65536, 65535) CL_TEST(65536, 4096) CL_TEST(65536, 65537)
CL_TEST(65537, 65536) CL_TEST(65537, 8192) CL_TEST(65537, 131072)
CL_TEST(131072, 65536) CL_TEST(131073, 4096) CL_TEST(262144, 1048576)
CL_TEST(1048576, 65536) CL_TEST(1048576, 8192) CL_TEST(1048576, 1048577) CL_TEST(1048577, 32768)

/* A single large read returns more than one network segment once the data has arrived ([W10] 02 6.1): */
TEST(bio_rf_large_read_gathers) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 20000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/g");
    Sleep(200);
    unsigned char *b = malloc(30000); DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 30000, &rd));
    t_note("first read of a 20000-byte body into 30000: %lu bytes", rd);
    CHECK(rd > 0 && rd <= 20000);
    CHECK(srv_pattern_check(b, rd, 0));
    bio_rd r; size_t more = bio_read(hr, b + rd, 30000 - rd, 0, &r);
    CHECK(r.ok); EXPECT_EQ(rd + more, 20000);
    CHECK(srv_pattern_check(b, rd + more, 0));
    free(b); bio_h(hr); bio_close(&e);
}

/* Read sizes that change from call to call (1, 2, 3, ... bytes) never lose or duplicate a byte. */
TEST(bio_rf_varying_piece_sizes) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 50000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/v");
    unsigned char *b = malloc(50016); size_t n = 0; int ok = 1, over = 0;
    for (DWORD piece = 1; n < 50016; piece = piece % 997 + 1) {
        DWORD rd = 0;
        if (!U(InternetReadFile)(hr, b + n, piece, &rd)) { ok = 0; break; }
        if (rd > piece) over++;
        if (!rd) break;
        n += rd;
    }
    CHECK(ok); EXPECT_EQ(n, 50000); EXPECT_EQ(over, 0);
    CHECK(srv_pattern_check(b, n, 0));
    free(b); bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ integrity of non-pattern data */
TEST(bio_rf_binary_all_byte_values) {
    REQUIRE(U(InternetReadFile));
    static unsigned char body[256 * 64];
    for (size_t i = 0; i < sizeof body; i++) body[i] = (unsigned char)(i * 131 + (i >> 8));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Type: application/octet-stream\r\n", body, sizeof body, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/bin");
    unsigned char *b = malloc(sizeof body + 16); bio_rd r;
    size_t n = bio_read(hr, b, sizeof body + 16, 333, &r);
    CHECK(r.ok); EXPECT_EQ(n, sizeof body);
    CHECK(n == sizeof body && !memcmp(b, body, n));
    EXPECT_EQ(srv_crc32(b, n), srv_crc32(body, sizeof body));
    free(b); bio_h(hr); bio_close(&e);
}

TEST(bio_rf_nul_and_crlf_bytes_in_body) {
    REQUIRE(U(InternetReadFile));
    static const char body[] = "a\0b\r\n\r\nHTTP/1.1 200 OK\r\n\0\0\n";
    srv_step st[] = { S_HEAD(), S_REPLYN(200, NULL, body, sizeof body - 1, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/nul");
    unsigned char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 3, &r);
    CHECK(r.ok); EXPECT_EQ(n, sizeof body - 1);
    CHECK(n == sizeof body - 1 && !memcmp(b, body, n));
    bio_h(hr); bio_close(&e);
}

TEST(bio_rf_1mb_sha256) {
    REQUIRE(U(InternetReadFile));
    const size_t N = 1048576 + 333;
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, N, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/big");
    unsigned char *want = bio_pattern(N), *b = malloc(N + 64);
    bio_rd r; size_t n = bio_read(hr, b, N + 64, 12345, &r);
    CHECK(r.ok); EXPECT_EQ(n, N);
    unsigned char h1[32], h2[32];
    if (bio_sha256(want, N, h1) && bio_sha256(b, n, h2)) CHECK(!memcmp(h1, h2, 32));
    else t_note("sha256 unavailable; crc only");
    EXPECT_EQ(srv_crc32(b, n), srv_crc32(want, N));
    free(want); free(b); bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ InternetOpenUrl handles */
static void openurl_case(size_t n, DWORD piece) {
    REQUIRE(U(InternetOpenUrlA));
    srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, n, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hu = U(InternetOpenUrlA)(e.hi, srv_url(e.s, "/ou"), NULL, 0, T_INET_FRESH, 0);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (!hu) { bio_close(&e); return; }
    DWORD type = 0, l = sizeof type;
    CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_HANDLE_TYPE, &type, &l));
    EXPECT_EQ(type, INTERNET_HANDLE_TYPE_HTTP_REQUEST);
    EXPECT_EQ(bio_status(hu), 200);
    unsigned char *b = malloc(n + 16); bio_rd r;
    size_t got = bio_read(hu, b, n + 16, piece, &r);
    CHECK(r.ok); EXPECT_EQ(got, n); CHECK(srv_pattern_check(b, got < n ? got : n, 0));
    free(b); bio_h(hu); bio_close(&e);
}
TEST(bio_openurl_0) { openurl_case(0, 4096); }
TEST(bio_openurl_1) { openurl_case(1, 1); }
TEST(bio_openurl_4096) { openurl_case(4096, 1000); }
TEST(bio_openurl_65537) { openurl_case(65537, 65536); }
TEST(bio_openurl_300000) { openurl_case(300000, 7777); }

TEST(bio_openurl_read_wire_and_status) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(404, "Content-Type: text/plain\r\n", "not here"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hu = U(InternetOpenUrlA)(e.hi, srv_url(e.s, "/missing?x=1"), NULL, 0, T_INET_FRESH, 0);
    CHECK(hu != NULL);
    EXPECT_EQ(bio_status(hu), 404);            /* error statuses still give a readable body */
    char b[32]; bio_rd r; size_t n = bio_read(hu, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 8); CHECK(!memcmp(b, "not here", 8));
    CHECK(srv_wait_requests(e.s, 1, 2000));
    EXPECT_STR(srv_req_line(e.s, 0), "GET /missing?x=1 HTTP/1.1");
    bio_h(hu); bio_close(&e);
}

/* Error statuses: body readable for each, byte-exact */
static void status_body_case(int code) {
    srv_step st[] = { S_HEAD(), S_REPLY(code, NULL, "status-body-0123456789"), S_LOOP() };
    st[1].arg = code;
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/s");
    EXPECT_EQ(bio_status(hr), (DWORD)code);
    char b[64]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 5, &r);
    CHECK(r.ok); EXPECT_EQ(n, 22); CHECK(n == 22 && !memcmp(b, "status-body-0123456789", 22));
    bio_h(hr); bio_close(&e);
}
TEST(bio_status_body_200) { status_body_case(200); }
TEST(bio_status_body_201) { status_body_case(201); }
TEST(bio_status_body_400) { status_body_case(400); }
TEST(bio_status_body_403) { status_body_case(403); }
TEST(bio_status_body_404) { status_body_case(404); }
TEST(bio_status_body_500) { status_body_case(500); }
TEST(bio_status_body_503) { status_body_case(503); }

/* Request handle reads interleaved with header queries */
TEST(bio_rf_queryinfo_after_partial_read) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, "Content-Type: x/y\r\nX-Body: yes\r\n", 10000, 0), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/q");
    unsigned char b[10016]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 100, &rd)); EXPECT_EQ(rd, 100);
    EXPECT_EQ(bio_status(hr), 200);
    char hb[256]; DWORD err;
    EXPECT_STR(bio_hdr(hr, HTTP_QUERY_CONTENT_TYPE, hb, sizeof hb, &err), "x/y");
    EXPECT_STR(bio_hdr(hr, HTTP_QUERY_CONTENT_LENGTH, hb, sizeof hb, &err), "10000");
    EXPECT_STR(bio_custom(hr, "X-Body", hb, sizeof hb, &err), "yes");
    const char *raw = bio_hdr(hr, HTTP_QUERY_RAW_HEADERS_CRLF, hb, sizeof hb, &err);
    CHECK(raw && !strncmp(raw, "HTTP/1.1 200 OK\r\n", 17));
    bio_rd r; size_t n = bio_read(hr, b + 100, sizeof b - 100, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n + 100, 10000); CHECK(srv_pattern_check(b, 10000, 0));
    EXPECT_STR(bio_hdr(hr, HTTP_QUERY_CONTENT_LENGTH, hb, sizeof hb, &err), "10000");
    bio_h(hr); bio_close(&e);
}

/* Two request handles on the same connect handle, read interleaved: each gets its own body. */
TEST(bio_rf_two_requests_interleaved) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_FMT("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"), S_SEND(""), S_FMT("%R"), S_LOOP() };
    /* body is the 6-char request target ("/aaaaa" / "/bbbbb") */
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET h1 = bio_get(&e, "/aaaaa"), h2 = bio_get(&e, "/bbbbb");
    char b1[16] = { 0 }, b2[16] = { 0 }; DWORD rd = 0;
    CHECK(U(InternetReadFile)(h1, b1, 3, &rd)); EXPECT_EQ(rd, 3);
    CHECK(U(InternetReadFile)(h2, b2, 3, &rd)); EXPECT_EQ(rd, 3);
    bio_rd r; size_t n1 = bio_read(h1, b1 + 3, 10, 0, &r) + 3; CHECK(r.ok);
    size_t n2 = bio_read(h2, b2 + 3, 10, 0, &r) + 3; CHECK(r.ok);
    EXPECT_EQ(n1, 6); EXPECT_EQ(n2, 6);
    EXPECT_STR(b1, "/aaaaa"); EXPECT_STR(b2, "/bbbbb");
    t_note("two concurrent requests used %d connection(s)", srv_conn_count(e.s));
    bio_h(h1); bio_h(h2); bio_close(&e);
}
