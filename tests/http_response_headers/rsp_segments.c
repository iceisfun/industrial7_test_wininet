/* rsp_segments.c - the response head delivered in pieces: split at every byte offset, two splits, drip-fed pieces,
 * interim responses in their own segment, LF-only heads, and body bytes that share a segment with the head.
 * VM_TIMEOUT: 240
 *
 * Whatever the TCP segmentation, the parsed result must equal the one-write result: the parser
 * (CHttpHeaderParser::ParseHeaders@0x8a150 / ParseStatusLine@0xbd050 [D]) resumes on the bytes it has, and the
 * head ends only at the blank line. Expectations for the unsplit form are the [W10] facts of rsp_headers.c and
 * rsp_status.c; these tests only assert that splitting does not change them.
 *
 * The server answers through an SRV_CALL that reads the split plan from the request target ("/s/<a>/<b>"):
 * bytes [0,a) are sent, then a short pause, then [a,b), a pause, then the rest. Waits are bounded (pauses <= 25 ms).
 */
#include "rh.h"

static const char *g_resp;   /* response used by split_fn (tests run sequentially) */
static size_t g_resp_n;
static int g_pause_ms = 20;

static int split_fn(srv_conn *cn, const srv_step *st, void *user) {
    srv *s = srv_conn_server(cn);
    const char *tg = srv_req_target(s, srv_conn_last_req(cn));
    size_t a = g_resp_n, b = g_resp_n;
    if (tg && !strncmp(tg, "/s/", 3)) {
        a = (size_t)strtoul(tg + 3, NULL, 10);
        const char *p = strchr(tg + 3, '/');
        b = p ? (size_t)strtoul(p + 1, NULL, 10) : g_resp_n;
    }
    if (a > g_resp_n) a = g_resp_n;
    if (b > g_resp_n || b < a) b = g_resp_n;
    if (a && srv_conn_send(cn, g_resp, a)) return -1;
    if (a < b) { Sleep(g_pause_ms); if (srv_conn_send(cn, g_resp + a, b - a)) return -1; }
    if (b < g_resp_n) { Sleep(g_pause_ms); if (srv_conn_send(cn, g_resp + b, g_resp_n - b)) return -1; }
    return 0;
}

typedef struct { srv *s; srv_step st[4]; srv_script sc; HINTERNET hi, hc; } seg_srv;

static int seg_start(seg_srv *g, const char *resp, size_t n) {
    memset(g, 0, sizeof *g);
    g_resp = resp; g_resp_n = n;
    srv_step st[] = { S_HEAD(), S_BODY(), S_CALL(split_fn), S_CLOSE() };
    memcpy(g->st, st, sizeof st);
    g->sc.steps = g->st; g->sc.nsteps = 4;
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTP; cfg.scripts = &g->sc; cfg.nscripts = 1; cfg.lifetime_ms = 60000; cfg.v4_only = 1;
    int rc = srv_start(&cfg, &g->s);
    if (rc) { g->s = NULL; t_skip("server unavailable: %s", srv_strerror(rc)); return 0; }
    g->hi = t_inet_open("rh-seg/1.0");
    g->hc = g->hi ? U(InternetConnectA)(g->hi, "127.0.0.1", srv_port(g->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (!g->hc) { CHECKF(0, "session err=%lu", GetLastError()); return 0; }
    return 1;
}
static void seg_stop(seg_srv *g) {
    if (g->hc) U(InternetCloseHandle)(g->hc);
    if (g->hi) U(InternetCloseHandle)(g->hi);
    if (g->s) srv_stop(g->s);
    memset(g, 0, sizeof *g);
}
/* open + send "/s/a/b"; returns the request handle or NULL (CHECK done) */
static HINTERNET seg_get(seg_srv *g, const char *verb, size_t a, size_t b, const char *file, int line) {
    /* the server accepts at most SRV_MAXCONN (64) connections: start a fresh one well before that */
    if (srv_conn_count(g->s) >= 56) {
        const char *r = g_resp; size_t rn = g_resp_n;
        seg_stop(g);
        if (!seg_start(g, r, rn)) return NULL;
    }
    char path[64]; snprintf(path, sizeof path, "/s/%u/%u", (unsigned)a, (unsigned)b);
    HINTERNET hr = U(HttpOpenRequestA)(g->hc, verb, path, NULL, NULL, NULL, RH_FLAGS, 0);
    if (!hr) { t_check(0, file, line, "HttpOpenRequestA", "err=%lu", GetLastError()); return NULL; }
    SetLastError(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (!ok) {
        DWORD e = GetLastError();
        t_check(0, file, line, "HttpSendRequestA", "split %u/%u err=%lu %s", (unsigned)a, (unsigned)b, e, t_inet_errname(e));
        U(InternetCloseHandle)(hr); return NULL;
    }
    return hr;
}

/* compare a string query against want, without spamming: returns 1 when equal */
static int q_eq(HINTERNET h, DWORD lv, const char *name, const char *want) {
    const char *v = name ? rh_qac(h, name, 0, NULL) : rh_qa(h, lv, NULL);
    if (!want) return !v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND;
    return v && !strcmp(v, want) && rh_len == strlen(want);
}

/* the reference response: status line, 5 headers incl. a duplicate and an empty value, a 4-byte body */
static const char RESP_REF[] =
    "HTTP/1.1 203 Partial Info\r\n"
    "Server: seg-srv\r\n"
    "X-Alpha:  alpha  value \r\n"
    "x-dup: d1\r\n"
    "X-Empty:\r\n"
    "X-Dup: d2\r\n"
    "Content-Length: 4\r\n"
    "Connection: close\r\n"
    "\r\n"
    "body";
static const char RESP_REF_RAW[] =
    "HTTP/1.1 203 Partial Info\r\nServer: seg-srv\r\nX-Alpha: alpha  value\r\nx-dup: d1\r\nX-Empty: \r\nX-Dup: d2\r\n"
    "Content-Length: 4\r\nConnection: close\r\n\r\n";

/* every query of the reference response; returns the number of mismatches (each one reported) */
static int check_ref(HINTERNET hr, const char *tag, const char *file, int line) {
    int bad = 0;
#define R(cond, ...) do { if (!(cond)) { bad++; t_check(0, file, line, #cond, __VA_ARGS__); } else t_check(1, file, line, #cond, NULL); } while (0)
    DWORD code = 0; BOOL okn = rh_qnum(hr, HTTP_QUERY_STATUS_CODE, &code);
    R(okn && code == 203, "%s: status ok=%d code=%lu err=%lu", tag, okn, code, rh_err);
    R(q_eq(hr, HTTP_QUERY_STATUS_TEXT, NULL, "Partial Info"), "%s: status text", tag);
    R(q_eq(hr, HTTP_QUERY_VERSION, NULL, "HTTP/1.1"), "%s: version", tag);
    R(q_eq(hr, HTTP_QUERY_SERVER, NULL, "seg-srv"), "%s: server", tag);
    R(q_eq(hr, 0, "X-Alpha", "alpha  value"), "%s: X-Alpha", tag);
    R(q_eq(hr, 0, "X-Empty", ""), "%s: X-Empty", tag);
    DWORD idx = 0; const char *v1 = rh_qac(hr, "X-DUP", 0, &idx); int ok1 = v1 && !strcmp(v1, "d1");
    const char *v2 = rh_qac(hr, "X-DUP", 0, &idx); int ok2 = v2 && !strcmp(v2, "d2");
    R(ok1 && ok2 && idx == 2, "%s: X-Dup walk idx=%lu", tag, idx);
    const char *raw = rh_qa(hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    R(raw && !strcmp(raw, RESP_REF_RAW), "%s: raw=%s", tag, raw ? rh_esc(raw, strlen(raw)) : "(fail)");
    char body[32] = { 0 }; int rok = 0; size_t n = t_inet_read_all(hr, body, sizeof body, &rok);
    R(n == 4 && !memcmp(body, "body", 4), "%s: body n=%u \"%s\"", tag, (unsigned)n, rh_esc(body, n));
#undef R
    return bad;
}

TEST(rsp_seg_split_head_at_every_offset) {
    REQUIRE(U(HttpQueryInfoA));
    seg_srv g; if (!seg_start(&g, RESP_REF, sizeof RESP_REF - 1)) { seg_stop(&g); return; }
    size_t n = sizeof RESP_REF - 1, failed = 0;
    for (size_t a = 1; a < n && failed < 5; a++) {
        HINTERNET hr = seg_get(&g, "GET", a, a, __FILE__, __LINE__);
        if (!hr) { failed++; continue; }
        char tag[32]; snprintf(tag, sizeof tag, "split@%u", (unsigned)a);
        if (check_ref(hr, tag, __FILE__, __LINE__)) failed++;
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}

TEST(rsp_seg_split_head_twice) {
    REQUIRE(U(HttpQueryInfoA));
    seg_srv g; if (!seg_start(&g, RESP_REF, sizeof RESP_REF - 1)) { seg_stop(&g); return; }
    size_t n = sizeof RESP_REF - 1, failed = 0;
    g_pause_ms = 10;
    for (size_t a = 3; a < n && failed < 5; a += 17)
        for (size_t b = a + 1; b < n && failed < 5; b += 23) {
            HINTERNET hr = seg_get(&g, "GET", a, b, __FILE__, __LINE__);
            if (!hr) { failed++; continue; }
            char tag[32]; snprintf(tag, sizeof tag, "split@%u,%u", (unsigned)a, (unsigned)b);
            if (check_ref(hr, tag, __FILE__, __LINE__)) failed++;
            U(InternetCloseHandle)(hr);
        }
    g_pause_ms = 20;
    seg_stop(&g);
}

/* the blank line split in every way, LF-only heads at every offset */
static const char RESP_LF[] = "HTTP/1.1 200 OK\nX-Lf: one\nServer: lf\nContent-Length: 2\nConnection: close\n\nok";
TEST(rsp_seg_lf_only_head_at_every_offset) {
    REQUIRE(U(HttpQueryInfoA));
    seg_srv g; if (!seg_start(&g, RESP_LF, sizeof RESP_LF - 1)) { seg_stop(&g); return; }
    size_t n = sizeof RESP_LF - 1; int failed = 0;
    for (size_t a = 1; a < n && failed < 5; a++) {
        HINTERNET hr = seg_get(&g, "GET", a, a, __FILE__, __LINE__);
        if (!hr) { failed++; continue; }
        int ok = q_eq(hr, 0, "X-Lf", "one") && q_eq(hr, HTTP_QUERY_SERVER, NULL, "lf") && q_eq(hr, HTTP_QUERY_STATUS_CODE, NULL, "200");
        const char *raw = rh_qa(hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
        int okr = raw && !strcmp(raw, "HTTP/1.1 200 OK\r\nX-Lf: one\r\nServer: lf\r\nContent-Length: 2\r\nConnection: close\r\n\r\n");
        char body[8] = { 0 }; size_t bn = t_inet_read_all(hr, body, sizeof body, NULL);
        CHECKF(ok && okr && bn == 2 && !strcmp(body, "ok"), "split@%u ok=%d raw=%s body=%s", (unsigned)a, ok, raw ? rh_esc(raw, strlen(raw)) : "(fail)", rh_esc(body, bn));
        if (!(ok && okr)) failed++;
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}

/* an interim 100 in its own segment, and split inside it */
static const char RESP_INT[] =
    "HTTP/1.1 100 Continue\r\nX-Interim: yes\r\n\r\n"
    "HTTP/1.1 200 OK\r\nX-Final: f\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc";
TEST(rsp_seg_interim_response_split) {
    REQUIRE(U(HttpQueryInfoA));
    seg_srv g; if (!seg_start(&g, RESP_INT, sizeof RESP_INT - 1)) { seg_stop(&g); return; }
    size_t n = sizeof RESP_INT - 1, interim = strlen("HTTP/1.1 100 Continue\r\nX-Interim: yes\r\n\r\n");
    size_t cuts[] = { 1, 5, 9, 12, 20, interim - 2, interim - 1, interim, interim + 1, interim + 8, interim + 20, n - 3, n - 1 };
    for (size_t i = 0; i < sizeof cuts / sizeof cuts[0]; i++) {
        HINTERNET hr = seg_get(&g, "GET", cuts[i], cuts[i], __FILE__, __LINE__);
        if (!hr) continue;
        DWORD code = 0; rh_qnum(hr, HTTP_QUERY_STATUS_CODE, &code);
        CHECKF(code == 200, "cut %u: code %lu", (unsigned)cuts[i], code);
        CHECKF(q_eq(hr, 0, "X-Final", "f"), "cut %u: X-Final", (unsigned)cuts[i]);
        CHECKF(q_eq(hr, 0, "X-Interim", NULL), "cut %u: X-Interim dropped [W10 rsp_status_interim_headers_dropped]", (unsigned)cuts[i]);
        char body[8] = { 0 }; size_t bn = t_inet_read_all(hr, body, sizeof body, NULL);
        CHECKF(bn == 3 && !strcmp(body, "abc"), "cut %u: body %s", (unsigned)cuts[i], rh_esc(body, bn));
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}

/* drip-feeding: SRV_SEND_SPLIT in pieces of k bytes */
static void drip_one(const char *resp, size_t n, int piece, int ms, int (*verify)(HINTERNET, int), const char *file, int line) {
    rh_t c;
    srv_step st[] = { S_HEAD(), S_BODY(), { SRV_SEND_SPLIT, resp, n, piece, NULL, (unsigned)ms }, S_CLOSE() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "GET", "/drip", 0)) { rh_close(&c); return; }
    rh_send(&c, NULL, NULL, 0);
    t_check(c.sent, file, line, "send", "piece %d err=%lu", piece, c.err);
    if (c.sent) t_check(verify(c.hr, piece), file, line, "drip verify", "piece %d", piece);
    rh_close(&c);
}
static int verify_ref(HINTERNET hr, int piece) { char tag[24]; snprintf(tag, sizeof tag, "piece %d", piece); return check_ref(hr, tag, __FILE__, __LINE__) == 0; }
TEST(rsp_seg_drip_piece_sizes) {
    REQUIRE(U(HttpQueryInfoA));
    static const int pieces[] = { 1, 2, 3, 4, 5, 7, 11, 16, 31, 64, 100 };
    for (size_t i = 0; i < sizeof pieces / sizeof pieces[0]; i++)
        drip_one(RESP_REF, sizeof RESP_REF - 1, pieces[i], pieces[i] < 4 ? 1 : 3, verify_ref, __FILE__, __LINE__);
}

/* a big head (96 headers, ~6 KB) in 512-byte pieces: crossing every internal buffer boundary */
static char g_big[16384]; static size_t g_big_n;
static void build_big(void) {
    size_t k = 0;
    k += (size_t)sprintf(g_big + k, "HTTP/1.1 200 Big\r\n");
    for (int i = 0; i < 96; i++) k += (size_t)sprintf(g_big + k, "X-H%02d: value-%02d-%.*s\r\n", i, i, 30 + (i % 17), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    k += (size_t)sprintf(g_big + k, "Content-Length: 0\r\nConnection: close\r\n\r\n");
    g_big_n = k;
}
static int verify_big(HINTERNET hr, int piece) {
    int bad = 0;
    for (int i = 0; i < 96; i++) {
        char nm[16], want[128]; snprintf(nm, sizeof nm, "X-H%02d", i);
        snprintf(want, sizeof want, "value-%02d-%.*s", i, 30 + (i % 17), "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        if (!q_eq(hr, 0, nm, want)) { bad++; t_note("piece %d: %s wrong (err %lu)", piece, nm, rh_err); }
    }
    const char *raw = rh_qa(hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    if (!raw || strcmp(raw, g_big)) bad++;
    CHECKF(bad == 0, "piece %d: %d mismatches", piece, bad);
    return bad == 0;
}
TEST(rsp_seg_big_head_pieces) {
    REQUIRE(U(HttpQueryInfoA));
    build_big();
    static const int pieces[] = { 97, 512, 1000, 1460, 4096 };
    for (size_t i = 0; i < sizeof pieces / sizeof pieces[0]; i++) drip_one(g_big, g_big_n, pieces[i], 3, verify_big, __FILE__, __LINE__);
}

/* the body shares the first segment with the head, the rest follows later; Content-Length and close-delimited */
TEST(rsp_seg_body_shares_segment_with_head) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R1[] = "HTTP/1.1 200 OK\r\nX-B: 1\r\nContent-Length: 20\r\nConnection: close\r\n\r\n0123456789abcdefghij";
    seg_srv g; if (!seg_start(&g, R1, sizeof R1 - 1)) { seg_stop(&g); return; }
    size_t head = strlen("HTTP/1.1 200 OK\r\nX-B: 1\r\nContent-Length: 20\r\nConnection: close\r\n\r\n");
    size_t cuts[] = { head, head + 1, head + 5, head + 19 };
    for (size_t i = 0; i < 4; i++) {
        HINTERNET hr = seg_get(&g, "GET", cuts[i], cuts[i], __FILE__, __LINE__);
        if (!hr) continue;
        CHECKF(q_eq(hr, 0, "X-B", "1"), "cut %u", (unsigned)cuts[i]);
        ULONGLONG cl = 0; CHECK(rh_qnum64(hr, HTTP_QUERY_CONTENT_LENGTH, &cl)); EXPECT_EQ(cl, 20);
        char body[32] = { 0 }; size_t bn = t_inet_read_all(hr, body, sizeof body, NULL);
        CHECKF(bn == 20 && !strcmp(body, "0123456789abcdefghij"), "cut %u body %s", (unsigned)cuts[i], rh_esc(body, bn));
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}

/* HTTP/1.0 close-delimited response split around the blank line */
TEST(rsp_seg_close_delimited_split) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R1[] = "HTTP/1.0 200 OK\r\nX-Ten: 10\r\n\r\nclose-delimited-body";
    seg_srv g; if (!seg_start(&g, R1, sizeof R1 - 1)) { seg_stop(&g); return; }
    size_t head = strlen("HTTP/1.0 200 OK\r\nX-Ten: 10\r\n\r\n");
    size_t cuts[] = { 4, 9, head - 3, head - 2, head - 1, head, head + 2 };
    for (size_t i = 0; i < sizeof cuts / sizeof cuts[0]; i++) {
        HINTERNET hr = seg_get(&g, "GET", cuts[i], cuts[i], __FILE__, __LINE__);
        if (!hr) continue;
        CHECKF(q_eq(hr, 0, "X-Ten", "10") && q_eq(hr, HTTP_QUERY_VERSION, NULL, "HTTP/1.0"), "cut %u", (unsigned)cuts[i]);
        CHECKF(q_eq(hr, HTTP_QUERY_CONTENT_LENGTH, NULL, NULL), "cut %u: no Content-Length is synthesised", (unsigned)cuts[i]);
        char body[64] = { 0 }; size_t bn = t_inet_read_all(hr, body, sizeof body, NULL);
        CHECKF(bn == 20 && !strcmp(body, "close-delimited-body"), "cut %u body %s", (unsigned)cuts[i], rh_esc(body, bn));
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}

/* chunked body, the head and the first chunk-size line split at several offsets */
TEST(rsp_seg_chunked_split) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R1[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-C: c\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    seg_srv g; if (!seg_start(&g, R1, sizeof R1 - 1)) { seg_stop(&g); return; }
    size_t head = strlen("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-C: c\r\nConnection: close\r\n\r\n");
    size_t cuts[] = { 20, 40, head - 1, head, head + 1, head + 2, head + 3, head + 9, sizeof R1 - 4 };
    for (size_t i = 0; i < sizeof cuts / sizeof cuts[0]; i++) {
        HINTERNET hr = seg_get(&g, "GET", cuts[i], cuts[i], __FILE__, __LINE__);
        if (!hr) continue;
        CHECKF(q_eq(hr, 0, "X-C", "c") && q_eq(hr, HTTP_QUERY_TRANSFER_ENCODING, NULL, "chunked"), "cut %u", (unsigned)cuts[i]);
        char body[64] = { 0 }; size_t bn = t_inet_read_all(hr, body, sizeof body, NULL);
        CHECKF(bn == 11 && !strcmp(body, "hello world"), "cut %u body %s", (unsigned)cuts[i], rh_esc(body, bn));
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}

/* HEAD with every split: no body is waited for */
TEST(rsp_seg_head_request_split) {
    REQUIRE(U(HttpQueryInfoA));
    static const char R1[] = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-H: head\r\nConnection: close\r\n\r\n";
    seg_srv g; if (!seg_start(&g, R1, sizeof R1 - 1)) { seg_stop(&g); return; }
    size_t n = sizeof R1 - 1;
    for (size_t a = 2; a < n; a += 5) {
        HINTERNET hr = seg_get(&g, "HEAD", a, a, __FILE__, __LINE__);
        if (!hr) continue;
        CHECKF(q_eq(hr, 0, "X-H", "head") && q_eq(hr, HTTP_QUERY_CONTENT_LENGTH, NULL, "1000"), "cut %u", (unsigned)a);
        char body[8]; size_t bn = t_inet_read_all(hr, body, sizeof body, NULL);
        CHECKF(bn == 0, "cut %u: HEAD body %u", (unsigned)a, (unsigned)bn);
        U(InternetCloseHandle)(hr);
    }
    seg_stop(&g);
}
