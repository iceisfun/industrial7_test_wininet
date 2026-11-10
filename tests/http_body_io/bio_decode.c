/* bio_decode.c - Content-Encoding handling (INTERNET_OPTION_HTTP_DECODING on/off, with and without the app's
 * Accept-Encoding), receive timeouts while waiting for the head and in the middle of a body, connection resets,
 * slow servers.
 * VM_TIMEOUT: 300 */
#include "bio.h"
#include <stdlib.h>
#define CHUNK_HEAD_ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

/* ------------------------------------------------------------------ HTTP_DECODING option itself */
TEST(bio_dec_option_query_default) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = t_inet_open(NULL);
    DWORD v = 0xDEAD, l = sizeof v;
    BOOL ok = U(InternetQueryOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &v, &l); DWORD err = GetLastError();
    t_note("query HTTP_DECODING on a fresh session: ok=%d err=%lu v=%lu len=%lu", ok, err, v, l);
    if (ok) { EXPECT_EQ(v, 0); EXPECT_EQ(l, 4); }
    t_inet_close(hi);
}

TEST(bio_dec_option_set_query_roundtrip) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = t_inet_open(NULL);
    CHECK(bio_set_dword(hi, INTERNET_OPTION_HTTP_DECODING, TRUE));
    DWORD v = 0xDEAD, l = sizeof v;
    BOOL ok = U(InternetQueryOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &v, &l);
    t_note("after set TRUE: query ok=%d err=%lu v=%lu", ok, ok ? 0 : GetLastError(), v);
    if (ok) EXPECT_EQ(v, 1);
    CHECK(bio_set_dword(hi, INTERNET_OPTION_HTTP_DECODING, FALSE));
    v = 0xDEAD; l = sizeof v;
    ok = U(InternetQueryOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &v, &l);
    if (ok) EXPECT_EQ(v, 0);
    t_inet_close(hi);
}

TEST(bio_dec_option_set_null_handle) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = t_inet_open(NULL);
    BOOL on = TRUE;
    BOOL ok = U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on); DWORD err = GetLastError();
    t_note("set HTTP_DECODING on NULL handle: ok=%d err=%lu %s", ok, err, ok ? "" : t_inet_errname(err));
    CHECK(!ok);
    t_inet_close(hi);
}

TEST(bio_dec_option_bad_length) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = t_inet_open(NULL);
    DWORD on = TRUE;
    BOOL ok = U(InternetSetOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &on, 2); DWORD err = GetLastError();
    t_note("set HTTP_DECODING len 2: ok=%d err=%lu %s", ok, err, ok ? "" : t_inet_errname(err));
    CHECK(!ok);
    EXPECT_EQ(err, ERROR_INTERNET_BAD_OPTION_LENGTH);
    t_inet_close(hi);
}

/* ------------------------------------------------------------------ decoding matrix */
enum { DEC_OFF = 0, DEC_SESSION = 1, DEC_REQUEST = 2, DEC_CONNECT = 3 };
static void dec_case(const void *body, size_t blen, unsigned flags, const char *ce_hdr, const char *accept,
                     int where, const void *want, size_t wantn, DWORD piece) {
    srv_step st[] = { S_HEAD(), { SRV_REPLY, (const char *)body, blen, 200, ce_hdr, flags, flags & SRV_R_CHUNKED ? 100 : 0 }, S_LOOP() };
    bio_env e; if (!bio_open_dec(&e, st, 3, where == DEC_SESSION)) return;   /* session option before InternetConnect */
    if (where == DEC_CONNECT) CHECK(bio_set_dword(e.hc, INTERNET_OPTION_HTTP_DECODING, TRUE));
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/dec", NULL, NULL, NULL, T_INET_FRESH, 0);
    if (where == DEC_REQUEST) CHECK(bio_set_dword(hr, INTERNET_OPTION_HTTP_DECODING, TRUE));
    BOOL ok = U(HttpSendRequestA)(hr, accept, accept ? (DWORD)-1 : 0, NULL, 0);
    CHECKF(ok, "send err=%lu", GetLastError());
    EXPECT_EQ(bio_status(hr), 200);
    unsigned char *b = malloc(wantn + blen + 4096); bio_rd r;
    size_t n = bio_read(hr, b, wantn + blen + 4096, piece, &r);
    CHECKF(r.ok, "read err=%lu", r.err);
    CHECKF(n == wantn && !memcmp(b, want, wantn), "got %u bytes want %u (where=%d accept=%s)", (unsigned)n, (unsigned)wantn, where, accept ? accept : "-");
    EXPECT_EQ(r.over, 0);
    CHECK(srv_wait_requests(e.s, 1, 2000));
    const char *ae = srv_req_header(e.s, 0, "Accept-Encoding");
    if (accept) CHECK(ae != NULL); else CHECKF(ae == NULL, "client sent Accept-Encoding: %s", ae);
    free(b); bio_h(hr); bio_close(&e);
}
#define AE "Accept-Encoding: gzip, deflate\r\n"
#define FOXT srv_fox_text(), SRV_FOX_LEN

/* real Huffman bodies */
TEST(bio_dec_gzip_session_on) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", AE, DEC_SESSION, FOXT, 65536); }
TEST(bio_dec_gzip_request_on) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", AE, DEC_REQUEST, FOXT, 65536); }
TEST(bio_dec_gzip_connect_on) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", AE, DEC_CONNECT, FOXT, 65536); }
TEST(bio_dec_gzip_off_passthrough) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", AE, DEC_OFF, srv_fox_gzip, srv_fox_gzip_len, 65536); }
TEST(bio_dec_gzip_on_no_accept_passthrough) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", NULL, DEC_SESSION, srv_fox_gzip, srv_fox_gzip_len, 65536); }
TEST(bio_dec_gzip_by_1) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", AE, DEC_SESSION, FOXT, 1); }
TEST(bio_dec_gzip_by_7) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", AE, DEC_SESSION, FOXT, 7); }
TEST(bio_dec_gzip_chunked) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, SRV_R_CHUNKED, "Content-Encoding: gzip\r\n", AE, DEC_SESSION, FOXT, 4096); }
TEST(bio_dec_gzip_closedelim) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, SRV_R_CLOSE, "Content-Encoding: gzip\r\n", AE, DEC_SESSION, FOXT, 4096); }
TEST(bio_dec_xgzip) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: x-gzip\r\n", AE, DEC_SESSION, FOXT, 4096); }
TEST(bio_dec_gzip_uppercase_token) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: GZIP\r\n", AE, DEC_SESSION, FOXT, 4096); }
TEST(bio_dec_zlib_deflate) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_zlib, srv_fox_zlib_len, 0, "Content-Encoding: deflate\r\n", AE, DEC_SESSION, FOXT, 4096); }
TEST(bio_dec_zlib_by_1) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_zlib, srv_fox_zlib_len, 0, "Content-Encoding: deflate\r\n", AE, DEC_SESSION, FOXT, 1); }
TEST(bio_dec_zlib_off_passthrough) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_zlib, srv_fox_zlib_len, 0, "Content-Encoding: deflate\r\n", AE, DEC_OFF, srv_fox_zlib, srv_fox_zlib_len, 4096); }
TEST(bio_dec_rawdeflate) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_raw, srv_fox_raw_len, 0, "Content-Encoding: deflate\r\n", AE, DEC_SESSION, FOXT, 4096); }
TEST(bio_dec_identity_passthrough) { REQUIRE(U(InternetReadFile)); dec_case("plain text", 10, 0, "Content-Encoding: identity\r\n", AE, DEC_SESSION, "plain text", 10, 4096); }
TEST(bio_dec_no_content_encoding) { REQUIRE(U(InternetReadFile)); dec_case("plain text", 10, 0, NULL, AE, DEC_SESSION, "plain text", 10, 4096); }
TEST(bio_dec_unknown_encoding_passthrough) { REQUIRE(U(InternetReadFile)); dec_case("brotli?!", 8, 0, "Content-Encoding: br\r\n", AE, DEC_SESSION, "brotli?!", 8, 4096); }

/* stored-block encodings built at run time */
TEST(bio_dec_stored_gzip) { REQUIRE(U(InternetReadFile)); dec_case("stored gzip body", 16, SRV_R_GZIP, NULL, AE, DEC_SESSION, "stored gzip body", 16, 4096); }
TEST(bio_dec_stored_zlib) { REQUIRE(U(InternetReadFile)); dec_case("stored zlib body", 16, SRV_R_DEFLATE, NULL, AE, DEC_SESSION, "stored zlib body", 16, 4096); }
TEST(bio_dec_stored_raw) { REQUIRE(U(InternetReadFile)); dec_case("stored raw body", 15, SRV_R_RAWDEFLATE, NULL, AE, DEC_SESSION, "stored raw body", 15, 4096); }
TEST(bio_dec_stored_gzip_chunked) { REQUIRE(U(InternetReadFile)); dec_case("chunked stored gzip body", 24, SRV_R_GZIP | SRV_R_CHUNKED, NULL, AE, DEC_SESSION, "chunked stored gzip body", 24, 3); }

static void dec_large(size_t n, unsigned flags, DWORD piece) {
    unsigned char *p = bio_pattern(n);
    dec_case(p, n, flags, NULL, AE, DEC_SESSION, p, n, piece);
    free(p);
}
TEST(bio_dec_stored_gzip_65537) { REQUIRE(U(InternetReadFile)); dec_large(65537, SRV_R_GZIP, 65536); }
TEST(bio_dec_stored_gzip_300000) { REQUIRE(U(InternetReadFile)); dec_large(300000, SRV_R_GZIP, 8192); }
TEST(bio_dec_stored_zlib_200000_chunked) { REQUIRE(U(InternetReadFile)); dec_large(200000, SRV_R_DEFLATE | SRV_R_CHUNKED, 4096); }
TEST(bio_dec_stored_gzip_1mb) { REQUIRE(U(InternetReadFile)); dec_large(1048576, SRV_R_GZIP, 65536); }

/* Accept-Encoding header variants the application may send */
TEST(bio_dec_accept_gzip_only) { REQUIRE(U(InternetReadFile)); dec_case(srv_fox_gzip, srv_fox_gzip_len, 0, "Content-Encoding: gzip\r\n", "Accept-Encoding: gzip\r\n", DEC_SESSION, FOXT, 4096); }

/* headers after decoding */
TEST(bio_dec_headers_after_decoding) {
    REQUIRE(U(InternetReadFile));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, "Content-Encoding: gzip\r\n", srv_fox_gzip, srv_fox_gzip_len, 0), S_LOOP() };
    bio_env e; if (!bio_open_dec(&e, st, 3, 1)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/h", 0, AE, &ok, &err);
    CHECK(ok);
    char hb[128];
    const char *ce = bio_hdr(hr, HTTP_QUERY_CONTENT_ENCODING, hb, sizeof hb, &err);
    t_note("decoded response: Content-Encoding query -> %s (err %lu)", ce ? ce : "(none)", err);
    DWORD cl = 0, l = sizeof cl;
    BOOL clok = U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL);
    t_note("decoded response: Content-Length query ok=%d value=%lu (wire %u, decoded %u)", clok, cl, (unsigned)srv_fox_gzip_len, SRV_FOX_LEN);
    DWORD q = bio_qda(hr, &err);
    t_note("decoded response: first QDA %lu", q);
    CHECK(q != (DWORD)-1 && q >= 1);
    char *b = malloc(4096); bio_rd r; size_t n = bio_read(hr, b, 4096, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, SRV_FOX_LEN);
    EXPECT_EQ(bio_qda(hr, &err), 0);
    free(b); bio_h(hr); bio_close(&e);
}

/* corrupt compressed data */
static void dec_corrupt(const char *tag, const unsigned char *p, size_t n, const char *ce) {
    srv_step st[] = { S_HEAD(), S_REPLYN(200, ce, p, n, 0), S_LOOP() };
    bio_env e; if (!bio_open_dec(&e, st, 3, 1)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/bad", 0, AE, &ok, &err);
    if (!ok) { t_note("%s: send failed err=%lu %s", tag, err, t_inet_errname(err)); bio_h(hr); bio_close(&e); return; }
    char *b = malloc(8192); bio_rd r; size_t got = bio_read(hr, b, 8192, 0, &r);
    t_note("%s: read ok=%d err=%lu %s n=%u", tag, r.ok, r.err, r.ok ? "" : t_inet_errname(r.err), (unsigned)got);
    if (!r.ok) EXPECT_EQ(r.err, ERROR_INTERNET_DECODING_FAILED);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_dec_corrupt_gzip_header) {
    REQUIRE(U(InternetReadFile));
    unsigned char bad[64]; memset(bad, 0x5A, sizeof bad); bad[0] = 0x1f; bad[1] = 0x8b; bad[2] = 0x99;   /* bad CM */
    dec_corrupt("gzip with bad method byte", bad, sizeof bad, "Content-Encoding: gzip\r\n");
}
TEST(bio_dec_corrupt_deflate_stream) {
    REQUIRE(U(InternetReadFile));
    unsigned char *bad = malloc(srv_fox_gzip_len); memcpy(bad, srv_fox_gzip, srv_fox_gzip_len);
    for (size_t i = 12; i < srv_fox_gzip_len - 8; i += 3) bad[i] ^= 0xFF;
    dec_corrupt("gzip with corrupted deflate data", bad, srv_fox_gzip_len, "Content-Encoding: gzip\r\n");
    free(bad);
}
TEST(bio_dec_not_compressed_but_labelled) {
    REQUIRE(U(InternetReadFile));
    static const unsigned char plain[] = "this is not gzip at all, just text";
    dec_corrupt("plain text labelled gzip", plain, sizeof plain - 1, "Content-Encoding: gzip\r\n");
}
TEST(bio_dec_truncated_gzip) {
    REQUIRE(U(InternetReadFile));
    dec_corrupt("gzip cut to half", srv_fox_gzip, srv_fox_gzip_len / 2, "Content-Encoding: gzip\r\n");
}

/* ------------------------------------------------------------------ receive timeouts */
/* head arrives later than a short receive timeout set on the existing session (observed: no effect, see below) */
TEST(bio_timeout_before_head) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_SLEEP(2500), S_REPLY(200, NULL, "late") };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, 500));
    BOOL ok; DWORD err; DWORD t0 = GetTickCount();
    HINTERNET hr = bio_req(&e, "GET", "/late", 0, NULL, &ok, &err);
    DWORD dt = GetTickCount() - t0;
    t_note("head after 2.5 s, receive timeout 500 ms: ok=%d err=%lu (%s) after %lu ms", ok, err, t_inet_errname(err), dt);
    /* Win10 VM boot 1: a 500 ms RECEIVE_TIMEOUT set on an existing session does not cut a 2.5 s wait for the head */
    CHECK(ok);
    bio_h(hr); bio_close(&e);
}

/* timeout set on the request handle instead of the session */
TEST(bio_timeout_request_handle_option) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_SLEEP(2500), S_REPLY(200, NULL, "late") };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/late", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(bio_set_dword(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, 500));
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); DWORD err = GetLastError();
    t_note("request RECEIVE_TIMEOUT 500, head after 2.5 s: ok=%d err=%lu", ok, err);
    CHECK(ok);                                 /* Win10 VM boot 1: no 12002 */
    bio_h(hr); bio_close(&e);
}

/* body stalls in the middle longer than a short receive timeout set on the existing session (observed: no effect) */
TEST(bio_timeout_mid_body) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde"), S_SLEEP(2500), S_SEND("fghij"), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, 500));
    HINTERNET hr = bio_get(&e, "/stall");
    char b[16]; bio_rd r; DWORD t0 = GetTickCount();
    size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("mid-body stall: ok=%d err=%lu (%s) n=%u after %lu ms", r.ok, r.err, t_inet_errname(r.err), (unsigned)n, GetTickCount() - t0);
    CHECK(n <= 10 && !memcmp(b, "abcdefghij", n));
    CHECK(r.ok); EXPECT_EQ(n, 10);             /* Win10 VM boot 1: the read waited out the stall, no 12002 */
    bio_h(hr); bio_close(&e);
}

/* chunked body stalls between chunks */
TEST(bio_timeout_mid_chunked) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND(CHUNK_HEAD_ "3\r\nabc\r\n"), S_SLEEP(2500), S_SEND("0\r\n\r\n"), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, 500));
    HINTERNET hr = bio_get(&e, "/stallc");
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("chunked stall: ok=%d err=%lu (%s) n=%u", r.ok, r.err, t_inet_errname(r.err), (unsigned)n);
    CHECK(r.ok); EXPECT_EQ(n, 3); CHECK(!memcmp(b, "abc", 3));   /* Win10 VM boot 1: no 12002 */
    bio_h(hr); bio_close(&e);
}

/* a slow but steady body (gaps shorter than the timeout) completes */
TEST(bio_timeout_slow_but_within) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"), S_SPLIT("slow-bytes!!", 2, 150), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, 1500));
    HINTERNET hr = bio_get(&e, "/steady");
    char b[32]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 12); CHECK(!memcmp(b, "slow-bytes!!", 12));
    bio_h(hr); bio_close(&e);
}

/* RECEIVE_TIMEOUT option round trip on a request handle (value is per handle) */
TEST(bio_timeout_option_roundtrip) {
    REQUIRE(U(InternetQueryOptionA));
    bio_env e; static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "x"), S_LOOP() };
    if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/t", NULL, NULL, NULL, T_INET_FRESH, 0);
    DWORD v = 0, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, &l));
    EXPECT_EQ(v, 5000);                        /* inherited from the session (t_inet_open sets 5000) */
    CHECK(bio_set_dword(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, 1234));
    v = 0; l = sizeof v;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, &l)); EXPECT_EQ(v, 1234);
    v = 0; l = sizeof v;
    CHECK(U(InternetQueryOptionA)(e.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, &l)); EXPECT_EQ(v, 5000);
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ resets and abrupt closes */
static void abort_probe(const char *tag, const srv_step *st, int nst, size_t want_n, const char *want, DWORD *perr, BOOL *pok, size_t *pn) {
    bio_env e; if (!bio_open(&e, st, nst)) { *pok = 2; return; }
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/ab", 0, NULL, &ok, &err);
    if (!ok) {
        t_note("%s: send failed err=%lu %s", tag, err, t_inet_errname(err));
        *pok = 3; *perr = err; *pn = 0; bio_h(hr); bio_close(&e); return;
    }
    char b[256]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    t_note("%s: read ok=%d err=%lu %s n=%u", tag, r.ok, r.err, r.ok ? "" : t_inet_errname(r.err), (unsigned)n);
    if (want) CHECK(n <= want_n && !memcmp(b, want, n));
    *pok = r.ok; *perr = r.err; *pn = n;
    bio_h(hr); bio_close(&e);
}
TEST(bio_reset_mid_body) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde"), S_SLEEP(200), S_RESET() };
    BOOL ok; DWORD err; size_t n;
    abort_probe("RST after 5 of 10 body bytes", st, 4, 5, "abcde", &err, &ok, &n);
    if (ok == 2) return;
    CHECK(ok == 0 || ok == 1);
}
TEST(bio_reset_mid_chunked) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND(CHUNK_HEAD_ "5\r\nhello\r\n"), S_SLEEP(200), S_RESET() };
    BOOL ok; DWORD err; size_t n;
    abort_probe("RST after one chunk", st, 4, 5, "hello", &err, &ok, &n);
}
TEST(bio_reset_closedelim) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\n\r\npartial"), S_SLEEP(200), S_RESET() };
    BOOL ok; DWORD err; size_t n;
    abort_probe("RST ending a close-delimited body", st, 4, 7, "partial", &err, &ok, &n);
}
TEST(bio_reset_before_head) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_RESET() };
    BOOL ok; DWORD err = 0; size_t n;
    abort_probe("RST instead of a response", st, 2, 0, NULL, &err, &ok, &n);
    if (ok == 2) return;
    EXPECT_EQ(ok, 3);
    CHECKF(err == ERROR_INTERNET_CONNECTION_RESET || err == ERROR_INTERNET_CONNECTION_ABORTED, "err=%lu", err);
}
TEST(bio_close_before_head) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_CLOSE() };
    BOOL ok; DWORD err = 0; size_t n;
    abort_probe("graceful close instead of a response", st, 2, 0, NULL, &err, &ok, &n);
    if (ok == 2) return;
    EXPECT_EQ(ok, 3);
}
TEST(bio_close_mid_head) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Le"), S_CLOSE() };
    BOOL ok; DWORD err = 0; size_t n;
    abort_probe("close in the middle of the head", st, 3, 0, NULL, &err, &ok, &n);
}
TEST(bio_http09_style_body) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND("just bytes, no status line"), S_CLOSE() };
    BOOL ok; DWORD err = 0; size_t n;
    abort_probe("response without status line", st, 3, 0, NULL, &err, &ok, &n);
}

/* keep-alive connection closed by the server between requests: wininet retries on a new connection */
TEST(bio_keepalive_server_closed_between) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "hello"), S_SLEEP(300), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    HINTERNET hr = bio_get(&e, "/1");
    char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); bio_h(hr);
    Sleep(800);                                /* server has closed the idle connection by now */
    hr = bio_get(&e, "/2");
    n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 5); CHECK(!memcmp(b, "hello", 5));
    CHECK(srv_wait_requests(e.s, 2, 2000));
    EXPECT_EQ(srv_conn_count(e.s), 2);
    bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ HTTPS body reads (schannel record framing) */
static void https_case(size_t n, unsigned flags, DWORD piece) {
    REQUIRE(U(InternetReadFile));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, NULL, n, 200, NULL, flags, flags & SRV_R_CHUNKED ? 5000 : 0 }, S_LOOP() };
    srv *s = srv_https(st, 3, SRV_CERT_LOCALHOST);
    if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/s", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    CHECKF(ok, "https send err=%lu %s", GetLastError(), t_inet_errname(GetLastError()));
    unsigned char *b = malloc(n + 16); bio_rd r; size_t got = ok ? bio_read(hr, b, n + 16, piece, &r) : 0;
    if (ok) { CHECKF(r.ok, "err=%lu", r.err); EXPECT_EQ(got, n); CHECK(srv_pattern_check(b, got < n ? got : n, 0)); }
    free(b); bio_h(hr); bio_h(hc); t_inet_close(hi); srv_stop(s);
}
TEST(bio_https_cl_16385) { https_case(16385, 0, 4096); }       /* crosses one TLS record (16384) */
TEST(bio_https_cl_1mb) { https_case(1048576, 0, 65536); }
TEST(bio_https_chunked_100000) { https_case(100000, SRV_R_CHUNKED, 1000); }
TEST(bio_https_closedelim_50000) { https_case(50000, SRV_R_CLOSE, 8192); }
TEST(bio_https_by_1) { https_case(3000, 0, 1); }
