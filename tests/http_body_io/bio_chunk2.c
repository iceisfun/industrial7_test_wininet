/* bio_chunk2.c - chunked-framing grammar as implemented by the Win10 parser.
 * [D] CHUNK_TRANSFER::GetToken@0x16ea0 classifies one byte: hex digit (0), ':' (2), CR (3), LF (4), anything else (1).
 * [D] CHUNK_TRANSFER::ParseChunkInput@0x16af4 is a state machine:
 *   start-of-size-line: must be a hex digit, anything else -> error 12004 (internal);
 *   in size: hex digits accumulate (64-bit, overflow -> 12152), any other non-CR/LF byte starts the "extension",
 *            which runs to CR (so "5zz", "5 ", "5:x" all mean 5, and "0x5" means 0);
 *   every line end must be exactly CR LF (bare LF, CR CR -> error);
 *   after chunk data: exactly CR LF, anything else -> error;
 *   after the 0-size line: trailer lines, each needing a ':' before its CR; an empty line ends the body.
 * Valid cases are hard-checked byte for byte; invalid ones must fail the read and must never deliver bytes that
 * are not chunk data. The error code the application finally sees is recorded (and checked once the VM showed it).
 * VM_TIMEOUT: 240 */
#include "bio.h"
#include <stdlib.h>

#define CH_HEAD "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

typedef struct {
    const char *name;
    const char *chunks;    /* body bytes after the head */
    int valid;             /* 1: read must succeed and give want */
    const char *want;      /* valid: the whole body; invalid: the longest prefix that may be delivered */
} ch2_case;

static const ch2_case ch2[] = {
    /* valid (decomp grammar) */
    { "space after size",          "5 \r\nhello\r\n0\r\n\r\n",                 1, "hello" },
    { "tab after size",            "5\t\r\nhello\r\n0\r\n\r\n",                1, "hello" },
    { "letters after size",        "5zz\r\nhello\r\n0\r\n\r\n",                1, "hello" },
    { "colon after size",          "5:x\r\nhello\r\n0\r\n\r\n",                1, "hello" },
    { "0x prefix is size 0",       "0x5\r\n\r\n",                              1, "" },
    { "17 leading zeros",          "00000000000000005\r\nhello\r\n0\r\n\r\n",   1, "hello" },
    { "lower-case f",              "f\r\n0123456789abcde\r\n0\r\n\r\n",          1, "0123456789abcde" },
    { "mixed-case hex",            "1a\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n", 1, "abcdefghijklmnopqrstuvwxyz" },
    { "trailer no space",          "2\r\nok\r\n0\r\nA:b\r\n\r\n",               1, "ok" },
    { "trailer empty value",       "2\r\nok\r\n0\r\nX:\r\n\r\n",                1, "ok" },
    { "two trailers",              "2\r\nok\r\n0\r\nA: 1\r\nB: 2\r\n\r\n",      1, "ok" },
    { "ext on last chunk",         "2\r\nok\r\n0;fin=1\r\n\r\n",               1, "ok" },
    { "empty ext",                 "5;\r\nhello\r\n0;\r\n\r\n",                1, "hello" },
    { "quoted ext with CRLF-free", "5;a=\"b c\"\r\nhello\r\n0\r\n\r\n",          1, "hello" },
    { "chunk data has CRLF",       "6\r\nab\r\ncd\r\n0\r\n\r\n",                1, "ab\r\ncd" },
    { "chunk data is hex text",    "5\r\n0\r\n\r\n\r\n0\r\n\r\n",               1, "0\r\n\r\n" },
    { "1-byte chunks",             "1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n",   1, "abc" },
    { "zero-size then nothing",    "0\r\n\r\n",                                1, "" },
    /* invalid (decomp grammar) */
    { "leading space",             " 5\r\nhello\r\n0\r\n\r\n",                 0, "" },
    { "empty size line",           "\r\n5\r\nhello\r\n0\r\n\r\n",              0, "" },
    { "LF-only lines",             "5\nhello\n0\n\n",                          0, "" },
    { "bare LF after data",        "5\r\nhello\n0\r\n\r\n",                    0, "hello" },
    { "junk after data",           "5\r\nhelloX\r\n0\r\n\r\n",                 0, "hello" },
    { "CR CR LF after size",       "5\r\r\nhello\r\n0\r\n\r\n",                0, "" },
    { "trailer without colon",     "2\r\nok\r\n0\r\nNoColon\r\n\r\n",          0, "ok" },
    { "size 17 hex digits",        "10000000000000000\r\nabc",                 0, "" },
    { "plus sign",                 "+5\r\nhello\r\n0\r\n\r\n",                 0, "" },
    { "second size invalid",       "2\r\nok\r\n-1\r\nzz\r\n0\r\n\r\n",          0, "ok" },
    { "data longer than size",     "3\r\nhello\r\n0\r\n\r\n",                  0, "hel" },
};
#define NCH2 ((int)(sizeof ch2 / sizeof ch2[0]))

static void ch2_run(const ch2_case *c, DWORD piece) {
    char resp[512]; snprintf(resp, sizeof resp, "%s%s", CH_HEAD, c->chunks);
    srv_step st[] = { S_HEAD(), { SRV_SEND, resp, strlen(resp) }, S_SLEEP(200), S_CLOSE() };
    bio_env e; if (!bio_open(&e, st, 4)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/c2", 0, NULL, &ok, &err);
    if (!ok) {
        t_note("[%s] send failed err=%lu %s", c->name, err, t_inet_errname(err));
        CHECKF(!c->valid, "[%s] send failed err=%lu", c->name, err);
        bio_h(hr); bio_close(&e); return;
    }
    char b[256]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, piece, &r);
    size_t wl = strlen(c->want);
    if (c->valid) {
        CHECKF(r.ok, "[%s] read failed err=%lu %s after %u bytes", c->name, r.err, t_inet_errname(r.err), (unsigned)n);
        CHECKF(n == wl && !memcmp(b, c->want, wl), "[%s] got %u bytes '%.*s' want '%s'", c->name, (unsigned)n, (int)(n < 40 ? n : 40), b, c->want);
    } else {
        t_note("[%s] read ok=%d err=%lu %s n=%u", c->name, r.ok, r.err, r.ok ? "" : t_inet_errname(r.err), (unsigned)n);
        CHECKF(n <= wl && !memcmp(b, c->want, n), "[%s] delivered %u bytes '%.*s', more than the valid prefix '%s'", c->name, (unsigned)n, (int)(n < 40 ? n : 40), b, c->want);
    }
    EXPECT_EQ(r.over, 0);
    bio_h(hr); bio_close(&e);
}

/* one TEST per case, read in 4096-byte and in 1-byte pieces */
#define CH2(i, nm) \
    TEST(bio_ch2_##nm) { REQUIRE(U(InternetReadFile)); _Static_assert(i < NCH2, "index"); ch2_run(&ch2[i], 4096); } \
    TEST(bio_ch2_##nm##_by1) { REQUIRE(U(InternetReadFile)); ch2_run(&ch2[i], 1); }
CH2(0, space_after_size) CH2(1, tab_after_size) CH2(2, letters_after_size) CH2(3, colon_after_size)
CH2(4, hex_prefix_is_zero) CH2(5, many_leading_zeros) CH2(6, lower_f) CH2(7, mixed_case_hex) CH2(8, trailer_no_space)
CH2(9, trailer_empty_value) CH2(10, two_trailers) CH2(11, ext_last_chunk) CH2(12, empty_ext) CH2(13, quoted_ext)
CH2(14, data_has_crlf) CH2(15, data_is_hex_text) CH2(16, one_byte_chunks) CH2(17, zero_then_nothing)
CH2(18, inv_leading_space) CH2(19, inv_empty_size_line) CH2(20, inv_lf_only) CH2(21, inv_bare_lf_after_data)
CH2(22, inv_junk_after_data) CH2(23, inv_cr_cr_lf) CH2(24, inv_trailer_no_colon) CH2(25, inv_size_overflow)
CH2(26, inv_plus_sign) CH2(27, inv_second_size) CH2(28, inv_data_longer)
_Static_assert(NCH2 == 29, "one CH2 line per case");

/* the same grammar on a kept-alive connection: after a valid body with trailers the next request still parses */
TEST(bio_ch2_trailers_keepalive_three) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SEND(CH_HEAD "3;x\r\nabc\r\n0;y\r\nT1: a\r\nT2:b\r\n\r\n"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    for (int i = 0; i < 3; i++) {
        HINTERNET hr = bio_get(&e, "/k");
        char b[16]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, i + 1, &r);
        CHECKF(r.ok && n == 3 && !memcmp(b, "abc", 3), "request %d: ok=%d err=%lu n=%u", i, r.ok, r.err, (unsigned)n);
        bio_h(hr);
    }
    CHECK(srv_wait_requests(e.s, 3, 2000));
    EXPECT_EQ(srv_conn_count(e.s), 1);
    bio_close(&e);
}

/* many chunks: 3000 one-byte chunks and 200 chunks of random-ish sizes */
static int many_chunks(srv_conn *c, const srv_step *st, void *user) {
    int i = srv_conn_recv_head(c); if (i < 0) return -1;
    int mode = (int)(ULONG_PTR)user;
    if (srv_conn_sendf(c, CH_HEAD)) return -1;
    size_t off = 0; char buf[4200];
    if (mode == 0) {
        for (int k = 0; k < 3000; k++) {
            int l = snprintf(buf, sizeof buf, "1\r\n%c\r\n", srv_pattern_byte(off)); off++;
            if (srv_conn_send(c, buf, (size_t)l)) return -1;
        }
    } else {
        unsigned x = 12345;
        for (int k = 0; k < 200; k++) {
            x = x * 1103515245u + 12345u; size_t sz = 1 + (x >> 16) % 4000;
            int l = snprintf(buf, sizeof buf, "%x;k=%d\r\n", (unsigned)sz, k);
            for (size_t j = 0; j < sz; j++) buf[l + j] = (char)srv_pattern_byte(off + j);
            memcpy(buf + l + sz, "\r\n", 2);
            if (srv_conn_send(c, buf, l + sz + 2)) return -1;
            off += sz;
        }
    }
    return srv_conn_sendf(c, "0\r\n\r\n") ? -1 : 0;
}
static size_t many_total(int mode) {
    if (!mode) return 3000;
    unsigned x = 12345; size_t t = 0;
    for (int k = 0; k < 200; k++) { x = x * 1103515245u + 12345u; t += 1 + (x >> 16) % 4000; }
    return t;
}
static void many_case(int mode, DWORD piece) {
    static const srv_step st[] = { S_CALL(many_chunks), S_LOOP() };
    static srv_script sc[] = { { st, 2 } };
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_HTTP; cfg.scripts = sc; cfg.nscripts = 1;
    cfg.user = (void *)(ULONG_PTR)mode; cfg.lifetime_ms = 30000;
    bio_env e; if (!bio_open_cfg(&e, &cfg)) return;
    size_t want = many_total(mode);
    HINTERNET hr = bio_get(&e, "/many");
    unsigned char *b = malloc(want + 4096); bio_rd r; size_t n = bio_read(hr, b, want + 4096, piece, &r);
    CHECKF(r.ok, "err=%lu", r.err); EXPECT_EQ(n, want); CHECK(srv_pattern_check(b, n < want ? n : want, 0));
    EXPECT_EQ(r.over, 0);
    /* the connection is reusable afterwards */
    bio_h(hr);
    hr = bio_get(&e, "/again");
    n = bio_read(hr, b, want + 4096, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, want);
    EXPECT_EQ(srv_conn_count(e.s), 1);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_ch2_3000_one_byte_chunks) { REQUIRE(U(InternetReadFile)); many_case(0, 4096); }
TEST(bio_ch2_3000_one_byte_chunks_by_7) { REQUIRE(U(InternetReadFile)); many_case(0, 7); }
TEST(bio_ch2_200_varied_chunks) { REQUIRE(U(InternetReadFile)); many_case(1, 65536); }
TEST(bio_ch2_200_varied_chunks_by_1000) { REQUIRE(U(InternetReadFile)); many_case(1, 1000); }
TEST(bio_ch2_200_varied_chunks_by_4001) { REQUIRE(U(InternetReadFile)); many_case(1, 4001); }

/* chunk framing that arrives one byte per TCP segment, including extensions and trailers */
TEST(bio_ch2_slow_bytes_with_trailers) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_SPLIT(CH_HEAD "4;e=\"1\"\r\nwxyz\r\n2:q\r\n12\r\n0\r\nA:1\r\nB : 2\r\n\r\n", 1, 2), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 3)) return;
    HINTERNET hr = bio_get(&e, "/slow");
    char b[32]; bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, 6); CHECK(n == 6 && !memcmp(b, "wxyz12", 6));
    bio_h(hr); bio_close(&e);
}

/* QDA on a chunked body never reports more than the body still holds */
TEST(bio_ch2_qda_bounded_by_chunks) {
    REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_SEND(CH_HEAD "3\r\nabc\r\n"), S_SLEEP(300), S_SEND("4\r\ndefg\r\n0\r\n\r\n"), S_LOOP() };
    bio_env e; if (!bio_open(&e, st, 5)) return;
    HINTERNET hr = bio_get(&e, "/q");
    char b[16]; DWORD err, rd = 0; size_t got = 0;
    for (int i = 0; i < 20; i++) {
        DWORD q = bio_qda(hr, &err);
        if (q == (DWORD)-1) { CHECKF(0, "QDA err=%lu", err); break; }
        CHECKF(q <= 7 - got, "QDA %lu with %u of 7 bytes read", q, (unsigned)got);
        if (!q) break;
        if (q > 7 - got) q = (DWORD)(7 - got);
        CHECK(U(InternetReadFile)(hr, b + got, q, &rd)); CHECK(rd == q);
        got += rd;
    }
    EXPECT_EQ(got, 7); CHECK(!memcmp(b, "abcdefg", 7));
    EXPECT_EQ(bio_qda(hr, &err), 0);
    bio_h(hr); bio_close(&e);
}
