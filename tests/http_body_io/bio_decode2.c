/* bio_decode2.c - Content-Encoding decoding rules taken from the Win10 decompilation and checked on the VM:
 *  - which Accept-Encoding tokens the application must send ([D] HTTP_REQUEST_HANDLE_OBJECT::
 *    _CheckDecompressionRequestHeaders@0x664d4: exact "gzip, deflate" / "gzip, deflate, br", else comma tokens,
 *    trimmed, compared case-insensitively over their whole length),
 *  - which Content-Encoding values are decoded ([D] CheckDecompression@0xbdd3c: exactly one Content-Encoding
 *    header, value gzip | x-gzip | deflate | br, the matching token accepted; Content-Types application/x-tar,
 *    x-gzip, x-compress, x-compressed are left encoded; after decoding Content-Encoding is removed and the
 *    Accept-Encoding token is removed from Vary),
 *  - what the decompressor accepts ([D] DECOMPRESSOR::Init@0x1ed60 / CreateDecompression@0x1ef0c: gzip = zlib
 *    windowBits 31, deflate = zlib 15 with a retry as raw deflate (ZlibDecomp@0x1a50), br = brotli;
 *    Decompress@0x1b10 treats zlib's "incorrect data check" (CRC32 / Adler-32 mismatch) as a clean end;
 *    other errors give ERROR_INTERNET_DECODING_FAILED 12175).
 * Compressed bodies come from gen_bio_data.py (bio_data.c).
 * VM_TIMEOUT: 300 */
#include "bio.h"
#include "bio_data.h"
#include <stdlib.h>

typedef struct {
    const void *body; size_t blen; unsigned rflags; size_t csz;
    const char *rhdrs;         /* response header lines (Content-Encoding, Content-Type, Vary ...) */
    const char *reqhdrs;       /* headers passed to HttpSendRequestA */
    const char *addhdrs;       /* headers added with HttpAddRequestHeadersA before the send */
    int decode;                /* 1: HTTP_DECODING TRUE on the session */
    DWORD piece;               /* read size (0 = 65536) */
    const char *verb;          /* NULL = GET */
} d2_in;

typedef struct {
    int ran; BOOL sent; DWORD send_err; DWORD status;
    bio_rd r; size_t n; unsigned char *b;
    char ae[256]; int has_ae;
    char ce[128]; DWORD ce_err;           /* Content-Encoding query after the send, before the first read */
    char vary[256]; DWORD vary_err;       /* Vary query after the send */
} d2_out;

static void d2_run(const d2_in *in, d2_out *o) {
    memset(o, 0, sizeof *o);
    srv_step st[] = { S_HEAD(), { SRV_REPLY, (const char *)in->body, in->blen, 200, in->rhdrs, in->rflags, in->csz }, S_LOOP() };
    if (in->blen == 0) { st[1].data = ""; }
    bio_env e; if (!bio_open_dec(&e, st, (in->rflags & (SRV_R_CLOSE | SRV_R_TRUNCATE)) ? 2 : 3, in->decode)) return;
    o->ran = 1;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, in->verb ? in->verb : "GET", "/d2", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(hr != NULL);
    if (in->addhdrs) CHECK(U(HttpAddRequestHeadersA)(hr, in->addhdrs, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SetLastError(0);
    o->sent = U(HttpSendRequestA)(hr, in->reqhdrs, in->reqhdrs ? (DWORD)-1 : 0, NULL, 0);
    o->send_err = o->sent ? 0 : GetLastError();
    CHECKF(o->sent, "send err=%lu %s", o->send_err, t_inet_errname(o->send_err));
    o->status = bio_status(hr);
    if (!bio_hdr(hr, HTTP_QUERY_CONTENT_ENCODING, o->ce, sizeof o->ce, &o->ce_err)) o->ce[0] = 0;
    if (!bio_hdr(hr, HTTP_QUERY_VARY, o->vary, sizeof o->vary, &o->vary_err)) o->vary[0] = 0;
    size_t cap = in->blen * 2 + 1100000;
    o->b = malloc(cap);
    o->n = o->sent ? bio_read(hr, o->b, cap, in->piece, &o->r) : 0;
    CHECK(o->r.over == 0);
    if (srv_wait_requests(e.s, 1, 2000)) {
        const char *ae = srv_req_header(e.s, 0, "Accept-Encoding");
        if (ae) { o->has_ae = 1; lstrcpynA(o->ae, ae, sizeof o->ae); }
    }
    bio_h(hr); bio_close(&e);
}
static void d2_free(d2_out *o) { free(o->b); o->b = NULL; }

/* decoded to the 900-byte fox text */
static void expect_fox(d2_out *o, const char *tag) {
    CHECKF(o->r.ok, "%s: read failed err=%lu %s", tag, o->r.err, t_inet_errname(o->r.err));
    CHECKF(o->n == SRV_FOX_LEN && !memcmp(o->b, srv_fox_text(), SRV_FOX_LEN), "%s: got %u bytes, not the decoded text", tag, (unsigned)o->n);
}
/* passed through undecoded: exactly the wire body */
static void expect_raw(d2_out *o, const void *body, size_t blen, const char *tag) {
    CHECKF(o->r.ok, "%s: read failed err=%lu", tag, o->r.err);
    CHECKF(o->n == blen && !memcmp(o->b, body, blen), "%s: got %u bytes, want the %u encoded bytes", tag, (unsigned)o->n, (unsigned)blen);
}
static int is_pattern(const unsigned char *b, size_t n) { return srv_pattern_check(b, n, 0); }
static void mislabel_case(const void *body, size_t blen, const char *ce, const char *tag);

#define GZ_FOX srv_fox_gzip, srv_fox_gzip_len
#define ZL_FOX srv_fox_zlib, srv_fox_zlib_len
#define RAW_FOX srv_fox_raw, srv_fox_raw_len
#define CE_GZIP "Content-Encoding: gzip\r\n"
#define CE_DEFL "Content-Encoding: deflate\r\n"
#define CE_BR   "Content-Encoding: br\r\n"
#define AE_GD   "Accept-Encoding: gzip, deflate\r\n"
#define AE_GDB  "Accept-Encoding: gzip, deflate, br\r\n"

/* ------------------------------------------------------------------ Accept-Encoding gating */
static void ae_case(const char *ae, const void *body, size_t blen, const char *ce, int want_decoded) {
    d2_in in = { body, blen, 0, 0, ce, ae, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        if (want_decoded) expect_fox(&o, ae); else expect_raw(&o, body, blen, ae);
        CHECK(o.has_ae);
    }
    d2_free(&o);
}
TEST(bio_d2_ae_gzip_only) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: gzip\r\n", GZ_FOX, CE_GZIP, 1); }
TEST(bio_d2_ae_deflate_only_gzip_body) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: deflate\r\n", GZ_FOX, CE_GZIP, 0); }
TEST(bio_d2_ae_gzip_only_deflate_body) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: gzip\r\n", ZL_FOX, CE_DEFL, 0); }
TEST(bio_d2_ae_deflate_only_deflate_body) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: deflate\r\n", RAW_FOX, CE_DEFL, 1); }
TEST(bio_d2_ae_uppercase_pair) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: GZIP, DEFLATE\r\n", GZ_FOX, CE_GZIP, 1); }
TEST(bio_d2_ae_spaced_tokens) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: deflate ,   gzip  \r\n", GZ_FOX, CE_GZIP, 1); }
TEST(bio_d2_ae_no_space_tokens) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: deflate,gzip\r\n", GZ_FOX, CE_GZIP, 1); }
TEST(bio_d2_ae_qvalue_token_not_matched) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: gzip;q=1.0\r\n", GZ_FOX, CE_GZIP, 0); }
TEST(bio_d2_ae_qvalue_other_token_matched) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: deflate;q=0.5, gzip\r\n", GZ_FOX, CE_GZIP, 1); }
TEST(bio_d2_ae_identity_then_gzip) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: identity, gzip\r\n", GZ_FOX, CE_GZIP, 1); }
TEST(bio_d2_ae_star_not_matched) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: *\r\n", GZ_FOX, CE_GZIP, 0); }
TEST(bio_d2_ae_xgzip_token_not_matched) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: x-gzip\r\n", GZ_FOX, "Content-Encoding: x-gzip\r\n", 0); }
TEST(bio_d2_ae_gzip_accepts_xgzip) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: gzip\r\n", GZ_FOX, "Content-Encoding: x-gzip\r\n", 1); }
TEST(bio_d2_ae_identity_only) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: identity\r\n", GZ_FOX, CE_GZIP, 0); }
TEST(bio_d2_ae_gd_with_br_body_not_decoded) { REQUIRE(U(InternetReadFile)); ae_case(AE_GD, bio_br_fox, bio_br_fox_len, CE_BR, 0); }
TEST(bio_d2_ae_gdb_br_body) { REQUIRE(U(InternetReadFile)); ae_case(AE_GDB, bio_br_fox, bio_br_fox_len, CE_BR, 1); }
TEST(bio_d2_ae_br_only_br_body) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: br\r\n", bio_br_fox, bio_br_fox_len, CE_BR, 1); }
TEST(bio_d2_ae_br_only_gzip_body) { REQUIRE(U(InternetReadFile)); ae_case("Accept-Encoding: br\r\n", GZ_FOX, CE_GZIP, 0); }
TEST(bio_d2_ae_br_uppercase_ce) { REQUIRE(U(InternetReadFile)); ae_case(AE_GDB, bio_br_fox, bio_br_fox_len, "Content-Encoding: BR\r\n", 1); }

/* Accept-Encoding added with HttpAddRequestHeaders (not passed to the send) also enables decoding */
TEST(bio_d2_ae_via_add_request_headers) {
    REQUIRE(U(HttpAddRequestHeadersA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP, NULL, AE_GD, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { expect_fox(&o, "added AE"); CHECK(o.has_ae); }
    d2_free(&o);
}
/* two Accept-Encoding lines: every instance is scanned */
TEST(bio_d2_ae_two_header_lines) {
    REQUIRE(U(InternetReadFile));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP, "Accept-Encoding: deflate\r\nAccept-Encoding: gzip\r\n", NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { expect_fox(&o, "two AE lines"); t_note("two AE lines arrived as: %s", o.ae); }
    d2_free(&o);
}

/* ------------------------------------------------------------------ Content-Encoding gating */
static void ce_case(const char *rhdrs, const void *body, size_t blen, int want_decoded, const char *tag) {
    d2_in in = { body, blen, 0, 0, rhdrs, AE_GDB, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        t_note("%s: CE after send '%s' (err %lu), read ok=%d n=%u", tag, o.ce, o.ce_err, o.r.ok, (unsigned)o.n);
        if (want_decoded) expect_fox(&o, tag); else expect_raw(&o, body, blen, tag);
    }
    d2_free(&o);
}
TEST(bio_d2_ce_two_headers_not_decoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP CE_GZIP, GZ_FOX, 0, "two Content-Encoding: gzip lines"); }
TEST(bio_d2_ce_list_not_decoded) { REQUIRE(U(InternetReadFile)); ce_case("Content-Encoding: gzip, identity\r\n", GZ_FOX, 0, "Content-Encoding: gzip, identity"); }
TEST(bio_d2_ce_mixed_case_decoded) { REQUIRE(U(InternetReadFile)); ce_case("Content-Encoding: gZiP\r\n", GZ_FOX, 1, "Content-Encoding: gZiP"); }
TEST(bio_d2_ce_deflate_uppercase) { REQUIRE(U(InternetReadFile)); ce_case("Content-Encoding: DEFLATE\r\n", RAW_FOX, 1, "Content-Encoding: DEFLATE"); }
TEST(bio_d2_ce_compress_not_decoded) { REQUIRE(U(InternetReadFile)); ce_case("Content-Encoding: compress\r\n", GZ_FOX, 0, "Content-Encoding: compress"); }
TEST(bio_d2_ce_lowercase_name) { REQUIRE(U(InternetReadFile)); ce_case("content-encoding: gzip\r\n", GZ_FOX, 1, "content-encoding: gzip"); }

/* Content-Type exclusions (table at wininet!0x1f44b0, compared exactly, case-insensitively) */
TEST(bio_d2_ct_x_gzip_left_encoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: application/x-gzip\r\n", GZ_FOX, 0, "CT application/x-gzip"); }
TEST(bio_d2_ct_x_tar_left_encoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: application/x-tar\r\n", GZ_FOX, 0, "CT application/x-tar"); }
TEST(bio_d2_ct_x_compress_left_encoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: application/x-compress\r\n", GZ_FOX, 0, "CT application/x-compress"); }
TEST(bio_d2_ct_x_compressed_left_encoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: application/x-compressed\r\n", GZ_FOX, 0, "CT application/x-compressed"); }
TEST(bio_d2_ct_x_gzip_uppercase_left_encoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: APPLICATION/X-GZIP\r\n", GZ_FOX, 0, "CT APPLICATION/X-GZIP"); }
TEST(bio_d2_ct_x_gzip_with_param_decoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: application/x-gzip; x=1\r\n", GZ_FOX, 1, "CT application/x-gzip; x=1"); }
TEST(bio_d2_ct_text_plain_decoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: text/plain\r\n", GZ_FOX, 1, "CT text/plain"); }
TEST(bio_d2_ct_octet_stream_decoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_GZIP "Content-Type: application/octet-stream\r\n", GZ_FOX, 1, "CT application/octet-stream"); }
TEST(bio_d2_ct_x_tar_deflate_left_encoded) { REQUIRE(U(InternetReadFile)); ce_case(CE_DEFL "Content-Type: application/x-tar\r\n", ZL_FOX, 0, "CT application/x-tar, deflate"); }
/* other compression-looking types: observed only */
static void ct_probe(const char *ct) {
    char h[160]; snprintf(h, sizeof h, CE_GZIP "Content-Type: %s\r\n", ct);
    d2_in in = { GZ_FOX, 0, 0, h, AE_GD, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        int dec = o.r.ok && o.n == SRV_FOX_LEN && !memcmp(o.b, srv_fox_text(), SRV_FOX_LEN);
        int raw = o.r.ok && o.n == srv_fox_gzip_len && !memcmp(o.b, srv_fox_gzip, o.n);
        t_note("Content-Type %s with gzip: %s", ct, dec ? "decoded" : raw ? "left encoded" : "other");
        CHECK(dec || raw);
    }
    d2_free(&o);
}
TEST(bio_d2_ct_probe_zip) { REQUIRE(U(InternetReadFile)); ct_probe("application/zip"); }
TEST(bio_d2_ct_probe_gzip) { REQUIRE(U(InternetReadFile)); ct_probe("application/gzip"); }
TEST(bio_d2_ct_probe_x_gtar) { REQUIRE(U(InternetReadFile)); ct_probe("application/x-gtar"); }
TEST(bio_d2_ct_probe_x_spoon) { REQUIRE(U(InternetReadFile)); ct_probe("application/x-spoon"); }

/* ------------------------------------------------------------------ headers after decoding */
TEST(bio_d2_ce_header_removed_when_decoded) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP, AE_GD, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        expect_fox(&o, "decoded");
        CHECKF(o.ce[0] == 0 && o.ce_err == ERROR_HTTP_HEADER_NOT_FOUND, "Content-Encoding still '%s' (err %lu)", o.ce, o.ce_err);
    }
    d2_free(&o);
}
TEST(bio_d2_ce_header_kept_when_not_decoding) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP, AE_GD, NULL, 0, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { expect_raw(&o, GZ_FOX, "decoding off"); EXPECT_STR(o.ce, "gzip"); }
    d2_free(&o);
}
TEST(bio_d2_ce_header_kept_when_not_accepted) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP, "Accept-Encoding: deflate\r\n", NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { expect_raw(&o, GZ_FOX, "gzip not accepted"); EXPECT_STR(o.ce, "gzip"); }
    d2_free(&o);
}
TEST(bio_d2_vary_single_token_removed) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP "Vary: Accept-Encoding\r\n", AE_GD, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        expect_fox(&o, "vary");
        t_note("Vary 'Accept-Encoding' after decoding: '%s' err=%lu", o.vary, o.vary_err);
        CHECKF(o.vary_err == ERROR_HTTP_HEADER_NOT_FOUND, "Vary still '%s'", o.vary);
    }
    d2_free(&o);
}
TEST(bio_d2_vary_token_list_trimmed) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP "Vary: Accept-Encoding, Cookie\r\n", AE_GD, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        expect_fox(&o, "vary list");
        t_note("Vary 'Accept-Encoding, Cookie' after decoding: '%s' err=%lu", o.vary, o.vary_err);
        CHECK(o.vary_err == 0);
        CHECK(strstr(o.vary, "Cookie") != NULL);
        CHECKF(!strstr(o.vary, "Accept-Encoding") && !strstr(o.vary, "accept-encoding"), "Vary '%s'", o.vary);
    }
    d2_free(&o);
}
TEST(bio_d2_vary_other_token_untouched) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP "Vary: User-Agent\r\n", AE_GD, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { expect_fox(&o, "vary UA"); EXPECT_STR(o.vary, "User-Agent"); }
    d2_free(&o);
}
TEST(bio_d2_vary_kept_when_not_decoding) {
    REQUIRE(U(HttpQueryInfoA));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP "Vary: Accept-Encoding\r\n", AE_GD, NULL, 0, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { expect_raw(&o, GZ_FOX, "vary off"); EXPECT_STR(o.vary, "Accept-Encoding"); }
    d2_free(&o);
}
TEST(bio_d2_content_length_after_decoding) {
    REQUIRE(U(HttpQueryInfoA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, srv_fox_gzip, srv_fox_gzip_len, 0), S_LOOP() };
    bio_env e; if (!bio_open_dec(&e, st, 3, 1)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/cl", 0, AE_GD, &ok, &err);
    CHECK(ok);
    DWORD cl = 0, l = sizeof cl;
    BOOL clok = U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL);
    t_note("Content-Length after decoding: ok=%d value=%lu (wire %u)", clok, cl, (unsigned)srv_fox_gzip_len);
    CHECK(!clok);                              /* Win10 VM boot 2: the Content-Length header is gone after decoding */
    char *b = malloc(4096); bio_rd r; size_t n = bio_read(hr, b, 4096, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, SRV_FOX_LEN);
    cl = 0; l = sizeof cl;
    BOOL clok2 = U(HttpQueryInfoA)(hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &cl, &l, NULL);
    t_note("Content-Length after reading the decoded body: ok=%d value=%lu", clok2, cl);
    free(b); bio_h(hr); bio_close(&e);
}

/* ------------------------------------------------------------------ gzip / zlib / brotli stream variants */
static void fmt_case(const void *body, size_t blen, const char *ce, const char *tag) {
    d2_in in = { body, blen, 0, 0, ce, AE_GDB, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) expect_fox(&o, tag);
    d2_free(&o);
}
TEST(bio_d2_gzip_fname) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_fname, bio_gz_fname_len, CE_GZIP, "FNAME"); }
TEST(bio_d2_gzip_fextra) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_fextra, bio_gz_fextra_len, CE_GZIP, "FEXTRA"); }
TEST(bio_d2_gzip_fcomment) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_fcomment, bio_gz_fcomment_len, CE_GZIP, "FCOMMENT"); }
TEST(bio_d2_gzip_fhcrc) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_fhcrc, bio_gz_fhcrc_len, CE_GZIP, "FHCRC"); }
TEST(bio_d2_gzip_all_flags) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_allflags, bio_gz_allflags_len, CE_GZIP, "all header flags"); }
TEST(bio_d2_gzip_ftext_mtime) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_ftext_mtime, bio_gz_ftext_mtime_len, CE_GZIP, "FTEXT+MTIME"); }
/* [D Decompress]: "incorrect data check" ends the stream cleanly */
TEST(bio_d2_gzip_bad_crc_ignored) { REQUIRE(U(InternetReadFile)); fmt_case(bio_gz_badcrc, bio_gz_badcrc_len, CE_GZIP, "bad CRC32"); }
/* zlib data under the deflate label fails (Win10 VM boot 2), so the Adler-32 case can only be seen under the gzip label,
 * which on the VM also accepted zlib data (bio_d2_zlib_body_labelled_gzip) */
TEST(bio_d2_zlib_bad_adler_ignored) { REQUIRE(U(InternetReadFile)); fmt_case(bio_zl_badadler, bio_zl_badadler_len, CE_GZIP, "bad Adler-32 under gzip"); }
TEST(bio_d2_zlib_bad_adler_under_deflate_fails) { REQUIRE(U(InternetReadFile)); mislabel_case(bio_zl_badadler, bio_zl_badadler_len, CE_DEFL, "zlib (bad Adler) under deflate"); }
TEST(bio_d2_br_fox_by_1) {
    REQUIRE(U(InternetReadFile));
    d2_in in = { bio_br_fox, bio_br_fox_len, 0, 0, CE_BR, AE_GDB, NULL, 1, 1 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) expect_fox(&o, "br by 1");
    d2_free(&o);
}

/* streams that end oddly: observed, with the invariants every outcome must satisfy */
static void odd_case(const void *body, size_t blen, const char *ce, const char *want, size_t wantn, const char *tag, d2_out *o) {
    d2_in in = { body, blen, 0, 0, ce, AE_GDB, NULL, 1, 4096 };
    d2_run(&in, o);
    if (!o->ran) return;
    t_note("%s: read ok=%d err=%lu %s n=%u", tag, o->r.ok, o->r.err, o->r.ok ? "" : t_inet_errname(o->r.err), (unsigned)o->n);
    if (!o->r.ok) EXPECT_EQ(o->r.err, ERROR_INTERNET_DECODING_FAILED);
    if (want) CHECKF(o->n <= wantn && !memcmp(o->b, want, o->n), "%s: delivered bytes are not a prefix of the plain text", tag);
}
TEST(bio_d2_gzip_bad_isize) {
    REQUIRE(U(InternetReadFile)); d2_out o;
    odd_case(bio_gz_badisize, bio_gz_badisize_len, CE_GZIP, srv_fox_text(), SRV_FOX_LEN, "bad ISIZE", &o); d2_free(&o);
}
TEST(bio_d2_gzip_two_members) {
    REQUIRE(U(InternetReadFile)); d2_out o;
    odd_case(bio_gz_two_members, bio_gz_two_members_len, CE_GZIP, "first-member|second-member", 26, "two members", &o);
    if (o.ran && o.r.ok) CHECK(o.n >= 13);
    d2_free(&o);
}
TEST(bio_d2_gzip_trailing_garbage) {
    REQUIRE(U(InternetReadFile)); d2_out o;
    odd_case(bio_gz_trailing_garbage, bio_gz_trailing_garbage_len, CE_GZIP, srv_fox_text(), SRV_FOX_LEN, "member + junk", &o);
    d2_free(&o);
}
TEST(bio_d2_gzip_no_trailer) {
    REQUIRE(U(InternetReadFile)); d2_out o;
    odd_case(bio_gz_no_trailer, bio_gz_no_trailer_len, CE_GZIP, srv_fox_text(), SRV_FOX_LEN, "no trailer", &o); d2_free(&o);
}
TEST(bio_d2_gzip_truncated_by_close) {
    REQUIRE(U(InternetReadFile));
    d2_in in = { bio_gz_pat300k, bio_gz_pat300k_len, SRV_R_TRUNCATE, 0, CE_GZIP, AE_GD, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        t_note("gzip cut by the server (CL announced): read ok=%d err=%lu n=%u", o.r.ok, o.r.err, (unsigned)o.n);
        CHECK(o.n < 300000 && is_pattern(o.b, o.n));
        if (!o.r.ok) EXPECT_EQ(o.r.err, ERROR_INTERNET_DECODING_FAILED);
    }
    d2_free(&o);
}

/* empty streams */
static void empty_case(const void *body, size_t blen, const char *ce, const char *tag) {
    d2_in in = { body, blen, 0, 0, ce, AE_GDB, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { CHECKF(o.r.ok, "%s err=%lu", tag, o.r.err); EXPECT_EQ(o.n, 0); }
    d2_free(&o);
}
TEST(bio_d2_gzip_empty_stream) { REQUIRE(U(InternetReadFile)); empty_case(bio_gz_empty, bio_gz_empty_len, CE_GZIP, "gzip of nothing"); }
TEST(bio_d2_br_empty_stream) { REQUIRE(U(InternetReadFile)); empty_case(bio_br_empty, bio_br_empty_len, CE_BR, "br of nothing"); }
TEST(bio_d2_gzip_label_empty_body) { REQUIRE(U(InternetReadFile)); empty_case("", 0, CE_GZIP, "CE gzip, CL 0"); }

/* wrong label for the data: [D] gzip = windowBits 31 only, deflate = zlib then raw */
static void mislabel_case(const void *body, size_t blen, const char *ce, const char *tag) {
    d2_in in = { body, blen, 0, 0, ce, AE_GDB, NULL, 1, 4096 };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        t_note("%s: read ok=%d err=%lu n=%u", tag, o.r.ok, o.r.err, (unsigned)o.n);
        CHECKF(!o.r.ok && o.r.err == ERROR_INTERNET_DECODING_FAILED, "%s: ok=%d err=%lu", tag, o.r.ok, o.r.err);
        EXPECT_EQ(o.n, 0);
    }
    d2_free(&o);
}
TEST(bio_d2_gzip_body_labelled_deflate) { REQUIRE(U(InternetReadFile)); mislabel_case(GZ_FOX, CE_DEFL, "gzip data, CE deflate"); }
/* Win10 VM boot 2: the gzip decoder also accepts zlib-wrapped data (zlib windowBits 47 style auto-detection) */
TEST(bio_d2_zlib_body_labelled_gzip) { REQUIRE(U(InternetReadFile)); fmt_case(ZL_FOX, CE_GZIP, "zlib data, CE gzip"); }
TEST(bio_d2_zlib_body_labelled_deflate_fails) { REQUIRE(U(InternetReadFile)); mislabel_case(ZL_FOX, CE_DEFL, "zlib data, CE deflate"); }
TEST(bio_d2_br_body_labelled_gzip) { REQUIRE(U(InternetReadFile)); mislabel_case(bio_br_fox, bio_br_fox_len, CE_GZIP, "brotli data, CE gzip"); }
TEST(bio_d2_gzip_body_labelled_br) { REQUIRE(U(InternetReadFile)); mislabel_case(GZ_FOX, CE_BR, "gzip data, CE br"); }
/* raw deflate under the deflate label decodes through the raw retry */
TEST(bio_d2_raw_deflate_retry_fox) { REQUIRE(U(InternetReadFile)); fmt_case(srv_fox_raw, srv_fox_raw_len, CE_DEFL, "raw deflate fox"); }

/* ------------------------------------------------------------------ large expansions */
static void big_case(const void *body, size_t blen, const char *ce, size_t plain_n, int zeros, DWORD piece, unsigned rflags, const char *tag) {
    d2_in in = { body, blen, rflags, rflags & SRV_R_CHUNKED ? 7 : 0, ce, AE_GDB, NULL, 1, piece };
    d2_out o; d2_run(&in, &o);
    if (o.ran) {
        CHECKF(o.r.ok, "%s: err=%lu", tag, o.r.err);
        CHECKF(o.n == plain_n, "%s: n=%u want %u", tag, (unsigned)o.n, (unsigned)plain_n);
        if (zeros) { size_t bad = 0; for (size_t i = 0; i < o.n; i++) if (o.b[i]) bad++; CHECKF(!bad, "%s: %u non-zero bytes", tag, (unsigned)bad); }
        else CHECK(is_pattern(o.b, o.n));
        CHECK(o.r.maxrd <= (piece ? piece : 65536));
        t_note("%s: %d reads, largest %lu", tag, o.r.calls, o.r.maxrd);
    }
    d2_free(&o);
}
TEST(bio_d2_gzip_zeros_1mb) { REQUIRE(U(InternetReadFile)); big_case(bio_gz_zeros1m, bio_gz_zeros1m_len, CE_GZIP, 1048576, 1, 65536, 0, "gzip 1 MiB zeros"); }
TEST(bio_d2_gzip_zeros_1mb_by_4096) { REQUIRE(U(InternetReadFile)); big_case(bio_gz_zeros1m, bio_gz_zeros1m_len, CE_GZIP, 1048576, 1, 4096, 0, "gzip 1 MiB zeros by 4096"); }
TEST(bio_d2_gzip_pat300k) { REQUIRE(U(InternetReadFile)); big_case(bio_gz_pat300k, bio_gz_pat300k_len, CE_GZIP, 300000, 0, 8192, 0, "gzip pattern 300000"); }
TEST(bio_d2_gzip_pat300k_by_3) { REQUIRE(U(InternetReadFile)); big_case(bio_gz_pat300k, bio_gz_pat300k_len, CE_GZIP, 300000, 0, 3, 0, "gzip pattern 300000 by 3"); }
TEST(bio_d2_gzip_pat300k_chunked7) { REQUIRE(U(InternetReadFile)); big_case(bio_gz_pat300k, bio_gz_pat300k_len, CE_GZIP, 300000, 0, 65536, SRV_R_CHUNKED, "gzip pattern, 7-byte chunks"); }
TEST(bio_d2_gzip_pat300k_closedelim) { REQUIRE(U(InternetReadFile)); big_case(bio_gz_pat300k, bio_gz_pat300k_len, CE_GZIP, 300000, 0, 10000, SRV_R_CLOSE, "gzip pattern close-delimited"); }
TEST(bio_d2_zlib_pat100k_under_gzip) { REQUIRE(U(InternetReadFile)); big_case(bio_zl_pat100k, bio_zl_pat100k_len, CE_GZIP, 100000, 0, 4096, 0, "zlib pattern 100000 under gzip"); }
TEST(bio_d2_zlib_pat100k_under_deflate_fails) { REQUIRE(U(InternetReadFile)); mislabel_case(bio_zl_pat100k, bio_zl_pat100k_len, CE_DEFL, "zlib pattern under deflate"); }
TEST(bio_d2_raw_pat100k) { REQUIRE(U(InternetReadFile)); big_case(bio_raw_pat100k, bio_raw_pat100k_len, CE_DEFL, 100000, 0, 4096, 0, "raw deflate pattern 100000"); }
TEST(bio_d2_br_pat100k) { REQUIRE(U(InternetReadFile)); big_case(bio_br_pat100k, bio_br_pat100k_len, CE_BR, 100000, 0, 4096, 0, "br pattern 100000"); }
TEST(bio_d2_br_pat100k_by_1000_chunked) { REQUIRE(U(InternetReadFile)); big_case(bio_br_pat100k, bio_br_pat100k_len, CE_BR, 100000, 0, 1000, SRV_R_CHUNKED, "br pattern chunked"); }

/* ------------------------------------------------------------------ decoding with the other read APIs */
TEST(bio_d2_qda_loop_decoded) {
    REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, bio_gz_pat300k, 0, 0), S_LOOP() };
    srv_step s2[3]; memcpy(s2, st, sizeof s2); s2[1].n = bio_gz_pat300k_len;
    bio_env e; if (!bio_open_dec(&e, s2, 3, 1)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/q", 0, AE_GD, &ok, &err);
    CHECK(ok);
    unsigned char *b = malloc(300000 + 70000); size_t got = 0; int bad = 0, it = 0; DWORD maxq = 0;
    for (; it < 100000; it++) {
        DWORD q = bio_qda(hr, &err);
        if (q == (DWORD)-1) { CHECKF(0, "QDA err=%lu", err); break; }
        if (!q) break;
        if (q > maxq) maxq = q;
        DWORD rd = 0;
        if (!U(InternetReadFile)(hr, b + got, q, &rd)) { CHECKF(0, "read err=%lu", GetLastError()); break; }
        if (rd > q) bad++;
        if (!rd) break;
        got += rd;
        if (got > 300000) break;
    }
    t_note("decoded QDA loop: %u bytes, %d iterations, largest QDA %lu", (unsigned)got, it, maxq);
    EXPECT_EQ(bad, 0); EXPECT_EQ(got, 300000); CHECK(is_pattern(b, got));
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_d2_readfileex_decoded) {
    REQUIRE(U(InternetReadFileExA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_BR, bio_br_pat100k, bio_br_pat100k_len, 0), S_LOOP() };
    bio_env e; if (!bio_open_dec(&e, st, 3, 1)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/x", 0, AE_GDB, &ok, &err);
    CHECK(ok);
    unsigned char *b = malloc(100000 + 70000); bio_rd r;
    size_t n = bio_read_ex(hr, b, 170000, 5000, IRF_SYNC, &r);
    CHECK(r.ok); EXPECT_EQ(n, 100000); CHECK(is_pattern(b, n)); EXPECT_EQ(r.over, 0);
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_d2_keepalive_two_decoded) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, srv_fox_gzip, 0, 0), S_LOOP() };
    srv_step s2[3]; memcpy(s2, st, sizeof s2); s2[1].n = srv_fox_gzip_len;
    bio_env e; if (!bio_open_dec(&e, s2, 3, 1)) return;
    for (int i = 0; i < 3; i++) {
        BOOL ok; DWORD err;
        HINTERNET hr = bio_req(&e, "GET", "/k", 0, AE_GD, &ok, &err);
        CHECK(ok);
        char *b = malloc(4096); bio_rd r; size_t n = bio_read(hr, b, 4096, 333, &r);
        CHECKF(r.ok && n == SRV_FOX_LEN && !memcmp(b, srv_fox_text(), n), "request %d: ok=%d n=%u", i, r.ok, (unsigned)n);
        free(b); bio_h(hr);
    }
    CHECK(srv_wait_requests(e.s, 3, 2000));
    EXPECT_EQ(srv_conn_count(e.s), 1);
    bio_close(&e);
}
/* the decoded body is only partly read, the handle closed, then the next request on the same connect handle */
TEST(bio_d2_partial_decoded_then_next) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, srv_fox_gzip, 0, 0), S_LOOP() };
    srv_step s2[3]; memcpy(s2, st, sizeof s2); s2[1].n = srv_fox_gzip_len;
    bio_env e; if (!bio_open_dec(&e, s2, 3, 1)) return;
    BOOL ok; DWORD err;
    HINTERNET hr = bio_req(&e, "GET", "/p1", 0, AE_GD, &ok, &err);
    char b[2048]; DWORD rd = 0;
    CHECK(U(InternetReadFile)(hr, b, 10, &rd)); EXPECT_EQ(rd, 10); CHECK(!memcmp(b, srv_fox_text(), 10));
    bio_h(hr);
    hr = bio_req(&e, "GET", "/p2", 0, AE_GD, &ok, &err);
    CHECK(ok);
    bio_rd r; size_t n = bio_read(hr, b, sizeof b, 0, &r);
    CHECK(r.ok); EXPECT_EQ(n, SRV_FOX_LEN); CHECK(n == SRV_FOX_LEN && !memcmp(b, srv_fox_text(), n));
    t_note("partly read decoded body then next request: %d connection(s)", srv_conn_count(e.s));
    bio_h(hr); bio_close(&e);
}
TEST(bio_d2_head_gzip_no_body) {
    REQUIRE(U(InternetReadFile));
    d2_in in = { GZ_FOX, 0, 0, CE_GZIP, AE_GD, NULL, 1, 4096, "HEAD" };
    d2_out o; d2_run(&in, &o);
    if (o.ran) { CHECK(o.r.ok); EXPECT_EQ(o.n, 0); EXPECT_EQ(o.status, 200); }
    d2_free(&o);
}

/* where the option is set */
TEST(bio_d2_request_option_off_overrides_session) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, srv_fox_gzip, 0, 0), S_LOOP() };
    srv_step s2[3]; memcpy(s2, st, sizeof s2); s2[1].n = srv_fox_gzip_len;
    bio_env e; if (!bio_open_dec(&e, s2, 3, 1)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/o", NULL, NULL, NULL, T_INET_FRESH, 0);
    DWORD v = 0xDEAD, l = sizeof v;
    BOOL qok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_HTTP_DECODING, &v, &l);
    t_note("request HTTP_DECODING inherited from the session: ok=%d v=%lu", qok, v);
    CHECK(qok); EXPECT_EQ(v, 1);
    CHECK(bio_set_dword(hr, INTERNET_OPTION_HTTP_DECODING, FALSE));
    CHECK(U(HttpSendRequestA)(hr, AE_GD, (DWORD)-1, NULL, 0));
    char *b = malloc(4096); bio_rd r; size_t n = bio_read(hr, b, 4096, 0, &r);
    int dec = n == SRV_FOX_LEN && !memcmp(b, srv_fox_text(), n), raw = n == srv_fox_gzip_len && !memcmp(b, srv_fox_gzip, n);
    t_note("session TRUE, request FALSE: %s", dec ? "decoded" : raw ? "left encoded" : "other");
    CHECK(r.ok); CHECK(raw);
    free(b); bio_h(hr); bio_close(&e);
}
/* Win10 VM boot 1: the connect handle copies HTTP_DECODING from the session when it is created; setting the session
 * option later reaches neither the connect handle nor its requests */
TEST(bio_d2_session_option_after_connect_not_inherited) {
    REQUIRE(U(InternetQueryOptionA));
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, srv_fox_gzip, 0, 0), S_LOOP() };
    srv_step s2[3]; memcpy(s2, st, sizeof s2); s2[1].n = srv_fox_gzip_len;
    bio_env e; if (!bio_open(&e, s2, 3)) return;
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_HTTP_DECODING, TRUE));
    DWORD v = 0xDEAD, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(e.hc, INTERNET_OPTION_HTTP_DECODING, &v, &l)); EXPECT_EQ(v, 0);
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/o", NULL, NULL, NULL, T_INET_FRESH, 0);
    v = 0xDEAD; l = sizeof v;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_HTTP_DECODING, &v, &l)); EXPECT_EQ(v, 0);
    CHECK(U(HttpSendRequestA)(hr, AE_GD, (DWORD)-1, NULL, 0));
    char *b = malloc(4096); bio_rd r; size_t n = bio_read(hr, b, 4096, 0, &r);
    CHECK(r.ok); CHECK(n == srv_fox_gzip_len && !memcmp(b, srv_fox_gzip, n));
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_d2_session_before_connect_inherited) {
    REQUIRE(U(InternetQueryOptionA));
    bio_env e; if (!bio_open_dec(&e, NULL, 0, 1)) return;
    DWORD v = 0xDEAD, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(e.hc, INTERNET_OPTION_HTTP_DECODING, &v, &l)); EXPECT_EQ(v, 1);
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/o", NULL, NULL, NULL, T_INET_FRESH, 0);
    v = 0xDEAD; l = sizeof v;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_HTTP_DECODING, &v, &l)); EXPECT_EQ(v, 1);
    /* turning it off on the connect handle does not change an existing request */
    CHECK(bio_set_dword(e.hc, INTERNET_OPTION_HTTP_DECODING, FALSE));
    v = 0xDEAD; l = sizeof v;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_HTTP_DECODING, &v, &l));
    t_note("request option after the connect handle was set FALSE: %lu", v);
    bio_h(hr); bio_close(&e);
}
TEST(bio_d2_session_option_after_open_request) {
    REQUIRE(U(InternetReadFile));
    static const srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, srv_fox_gzip, 0, 0), S_LOOP() };
    srv_step s2[3]; memcpy(s2, st, sizeof s2); s2[1].n = srv_fox_gzip_len;
    bio_env e; if (!bio_open(&e, s2, 3)) return;
    HINTERNET hr = U(HttpOpenRequestA)(e.hc, "GET", "/o", NULL, NULL, NULL, T_INET_FRESH, 0);
    CHECK(bio_set_dword(e.hi, INTERNET_OPTION_HTTP_DECODING, TRUE));
    CHECK(U(HttpSendRequestA)(hr, AE_GD, (DWORD)-1, NULL, 0));
    char *b = malloc(4096); bio_rd r; size_t n = bio_read(hr, b, 4096, 0, &r);
    int dec = n == SRV_FOX_LEN && !memcmp(b, srv_fox_text(), n), raw = n == srv_fox_gzip_len && !memcmp(b, srv_fox_gzip, n);
    t_note("session option set after HttpOpenRequest: %s", dec ? "decoded" : raw ? "left encoded" : "other");
    CHECK(r.ok); CHECK(raw);                   /* Win10 VM boot 1: left encoded */
    free(b); bio_h(hr); bio_close(&e);
}
TEST(bio_d2_openurl_br) {
    REQUIRE(U(InternetOpenUrlA));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_BR, bio_br_fox, bio_br_fox_len, 0), S_LOOP() };
    bio_env e; if (!bio_open_dec(&e, st, 3, 1)) return;
    HINTERNET hu = U(InternetOpenUrlA)(e.hi, srv_url(e.s, "/br"), AE_GDB, (DWORD)-1, T_INET_FRESH, 0);
    CHECK(hu != NULL);
    char *b = malloc(2048); bio_rd r; size_t n = hu ? bio_read(hu, b, 2048, 64, &r) : 0;
    CHECK(r.ok); EXPECT_EQ(n, SRV_FOX_LEN); CHECK(n == SRV_FOX_LEN && !memcmp(b, srv_fox_text(), n));
    free(b); bio_h(hu); bio_close(&e);
}
/* HTTPS bodies with decoding. Win10 VM boots 1-2: with HTTP_DECODING set on the session before InternetConnect and a
 * 1590-byte gzip body, HttpSendRequest failed with 12030 (deterministic, not explained yet), so the variants are probed:
 * where = 0 no decoding, 1 session before connect, 2 request handle. A successful send must deliver the exact bytes. */
static void https_dec_probe(int where, const void *body, size_t blen, size_t plain_n, const char *tag) {
    REQUIRE(U(InternetReadFile));
    srv_step st[] = { S_HEAD(), S_REPLYN(200, CE_GZIP, body, blen, 0), S_LOOP() };
    srv *s = srv_https(st, 3, SRV_CERT_LOCALHOST);
    if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open(NULL);
    if (where == 1) CHECK(bio_set_dword(hi, INTERNET_OPTION_HTTP_DECODING, TRUE));
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/s", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0);
    if (where == 2) CHECK(bio_set_dword(hr, INTERNET_OPTION_HTTP_DECODING, TRUE));
    t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    BOOL ok = U(HttpSendRequestA)(hr, AE_GD, (DWORD)-1, NULL, 0); DWORD err = ok ? 0 : GetLastError();
    size_t cap = plain_n + blen + 70000;
    unsigned char *b = malloc(cap); bio_rd r; memset(&r, 0, sizeof r); size_t n = ok ? bio_read(hr, b, cap, 7000, &r) : 0;
    t_note("%s: send ok=%d err=%lu %s; read ok=%d err=%lu n=%u", tag, ok, err, t_inet_errname(err), r.ok, r.err, (unsigned)n);
    if (ok && r.ok) {
        if (where) CHECKF(n == plain_n, "%s: n=%u", tag, (unsigned)n);
        else CHECK(n == blen && !memcmp(b, body, blen));
    }
    if (!where) CHECK(ok && r.ok);
    free(b); bio_h(hr); bio_h(hc); t_inet_close(hi); srv_stop(s);
}
TEST(bio_d2_https_gzip_pat300k) { https_dec_probe(1, bio_gz_pat300k, bio_gz_pat300k_len, 300000, "https gzip 300000, session decoding"); }
TEST(bio_d2_https_gzip_pat300k_request) { https_dec_probe(2, bio_gz_pat300k, bio_gz_pat300k_len, 300000, "https gzip 300000, request decoding"); }
TEST(bio_d2_https_gzip_pat300k_off) { https_dec_probe(0, bio_gz_pat300k, bio_gz_pat300k_len, 300000, "https gzip 300000, no decoding"); }
TEST(bio_d2_https_gzip_fox_request) { https_dec_probe(2, srv_fox_gzip, srv_fox_gzip_len, SRV_FOX_LEN, "https gzip fox, request decoding"); }
