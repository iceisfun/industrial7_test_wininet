/* hqi_levels.c - every HTTP_QUERY_* level (0..95) against a response carrying every known header,
 * CUSTOM-by-name equivalence, the synthetic levels, and the request-side view (FLAG_REQUEST_HEADERS vs the wire).
 * VM_TIMEOUT: 240
 *
 * [D] GlobalKnownHeaders (wininet rva 0x1f3660) maps level -> canonical name; _FindHeader looks a CUSTOM name up
 * through GlobalHeaderHashs first, so CUSTOM "content-type" is the same header as level 1. QueryInfo special-cases
 * 18 VERSION, 19 STATUS_CODE, 20 STATUS_TEXT, 21/22 RAW_HEADERS(_CRLF) (QueryFilteredRawHeaders: status line + every
 * header as "Name: value" in arrival order), 45 REQUEST_METHOD (the verb, response or request side) and returns
 * 12154 for 73/74 (ECHO_HEADERS*) on the response side.
 */
#include "rh.h"

/* levels not put in the bulk response: synthetic, framing-sensitive or with side effects */
static int bulk_skip(DWORD lv) {
    return !rh_known[lv].name || lv == HTTP_QUERY_TRANSFER_ENCODING || lv == HTTP_QUERY_ECHO_REQUEST || lv == HTTP_QUERY_ECHO_REPLY ||
           lv == HTTP_QUERY_X_P2P_PEERDIST;
}
static const char *bulk_value(DWORD lv) {
    static char v[96][48];
    if (lv == HTTP_QUERY_CONTENT_LENGTH) return "0";
    if (lv == HTTP_QUERY_CONNECTION) return "close";
    if (!v[lv][0]) snprintf(v[lv], sizeof v[lv], "v%lu-%s", lv, rh_known[lv].name);
    return v[lv];
}
static char g_bulk[16384], g_bulk_crlf[16384];
static size_t bulk_build(int lower) {
    size_t o = 0, r = 0;
    o += (size_t)snprintf(g_bulk + o, sizeof g_bulk - o, "HTTP/1.1 200 OK\r\n");
    memcpy(g_bulk_crlf, g_bulk, o); r = o;
    for (DWORD lv = 0; lv < 96; lv++) {
        if (bulk_skip(lv)) continue;
        char nm[64]; lstrcpynA(nm, rh_known[lv].name, sizeof nm);
        if (lower) CharLowerA(nm);
        int k = snprintf(g_bulk + o, sizeof g_bulk - o, "%s: %s\r\n", nm, bulk_value(lv));
        memcpy(g_bulk_crlf + r, g_bulk + o, (size_t)k); o += (size_t)k; r += (size_t)k;
    }
    o += (size_t)snprintf(g_bulk + o, sizeof g_bulk - o, "\r\n");
    memcpy(g_bulk_crlf + r, "\r\n", 3);
    return o;
}
static int open_bulk(rh_t *c, int lower) {
    size_t n = bulk_build(lower);
    if (!rh_raw(c, "GET", g_bulk, n)) return 0;
    if (!c->sent) { t_check(0, __FILE__, __LINE__, "send", "err=%lu %s", c->err, t_inet_errname(c->err)); rh_close(c); return 0; }
    return 1;
}

TEST(hqi_lvl_every_known_level_a) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!open_bulk(&c, 0)) return;
    int n = 0;
    for (DWORD lv = 0; lv < 96; lv++) {
        if (!rh_known[lv].name) continue;
        EXPECT_QA(c.hr, lv, bulk_skip(lv) ? NULL : bulk_value(lv));
        n++;
    }
    EXPECT_EQ(n, 88);
    rh_close(&c);
}

TEST(hqi_lvl_every_known_level_w) {
    REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!open_bulk(&c, 0)) return;
    for (DWORD lv = 0; lv < 96; lv++) {
        if (!rh_known[lv].name) continue;
        EXPECT_QW(c.hr, lv, bulk_skip(lv) ? NULL : bulk_value(lv));
    }
    rh_close(&c);
}

/* the response names were sent in lower case: lookup by level is case-insensitive */
TEST(hqi_lvl_every_known_level_lowercase_names) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!open_bulk(&c, 1)) return;
    for (DWORD lv = 0; lv < 96; lv++) {
        if (!rh_known[lv].name) continue;
        EXPECT_QA(c.hr, lv, bulk_skip(lv) ? NULL : bulk_value(lv));
    }
    /* and RAW_HEADERS_CRLF keeps the names as received */
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL);
    CHECKF(raw && !strcmp(raw, g_bulk_crlf), "raw: %s", raw ? rh_esc(raw, 400) : "(fail)");
    rh_close(&c);
}

TEST(hqi_lvl_custom_name_equals_level) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!open_bulk(&c, 0)) return;
    for (DWORD lv = 0; lv < 96; lv++) {
        if (!rh_known[lv].name) continue;
        const char *want = bulk_skip(lv) ? NULL : bulk_value(lv);
        char nm[64];
        EXPECT_QC(c.hr, rh_known[lv].name, want);
        lstrcpynA(nm, rh_known[lv].name, sizeof nm); CharLowerA(nm); EXPECT_QC(c.hr, nm, want);
        lstrcpynA(nm, rh_known[lv].name, sizeof nm); CharUpperA(nm); EXPECT_QC(c.hr, nm, want);
        snprintf(nm, sizeof nm, "%s:", rh_known[lv].name); EXPECT_QC(c.hr, nm, want);
    }
    rh_close(&c);
}

TEST(hqi_lvl_raw_headers_crlf_is_rebuilt_in_order) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!open_bulk(&c, 0)) return;
    EXPECT_Q(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, g_bulk_crlf);
    /* RAW_HEADERS: same lines, NUL separated */
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS, NULL);
    CHECK(raw != NULL);
    if (raw) {
        size_t total = strlen(g_bulk_crlf) - 2;   /* drop the final blank line; each CRLF becomes one NUL */
        int lines = 0; const char *p = raw, *q = g_bulk_crlf; int same = 1;
        while (*p) {
            const char *e = strstr(q, "\r\n"); size_t ll = strlen(p);
            if (!e || (size_t)(e - q) != ll || memcmp(p, q, ll)) { same = 0; break; }
            q = e + 2; p += ll + 1; lines++;
        }
        CHECK(same);
        EXPECT_EQ(rh_len, total - (size_t)lines);
        EXPECT_EQ(lines, 1 + 88 - 4);
    }
    rh_close(&c);
}

TEST(hqi_lvl_synthetic_levels_on_bulk) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!open_bulk(&c, 0)) return;
    EXPECT_Q(c.hr, HTTP_QUERY_VERSION, "HTTP/1.1");
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_CODE, "200");
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_TEXT, "OK");
    EXPECT_Q(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    EXPECT_QERR2(c.hr, HTTP_QUERY_ECHO_HEADERS, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QERR2(c.hr, HTTP_QUERY_ECHO_HEADERS_CRLF, ERROR_HTTP_INVALID_QUERY_REQUEST);
    DWORD n;
    CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &n)); EXPECT_EQ(n, 200);
    CHECK(rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n)); EXPECT_EQ(n, 0);
    rh_close(&c);
}

/* the header names that bulk_skip excludes, each probed on its own (values recorded, no side effect asserted) */
TEST(hqi_lvl_side_effect_headers) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nMs-Echo-Reply: er\r\nMs-Echo-Request: eq\r\nX-P2P-PeerDist: Version=1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    static const DWORD lv[] = { HTTP_QUERY_ECHO_REPLY, HTTP_QUERY_ECHO_REQUEST, HTTP_QUERY_X_P2P_PEERDIST };
    /* [W10] all three are stored and returned like any other header; the body is unaffected */
    static const char *want[] = { "er", "eq", "Version=1.0" };
    for (int i = 0; i < 3; i++) EXPECT_Q(c.hr, lv[i], want[i]);
    EXPECT_QC(c.hr, "Ms-Echo-Reply", "er");
    char body[16]; size_t bn = rh_body(&c, body, sizeof body);
    EXPECT_EQ(bn, 2); EXPECT_STR(body, "ok");
    rh_close(&c);
}

/* request side: FLAG_REQUEST_HEADERS for every level agrees with what the server received */
TEST(hqi_lvl_request_side_matches_wire) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!rh_raw_nosend(&c, "GET", resp, sizeof resp - 1)) return;
    CHECK(rh_send(&c, "X-Req: one\r\nAccept-Language: xx-YY\r\nReferer: http://ref.invalid/\r\nFrom: f@x.invalid\r\n", NULL, 0));
    RH_SENT_OR_FAIL(&c);
    CHECK(srv_wait_requests(c.s, 1, 3000));
    int present = 0;
    for (DWORD lv = 0; lv < 96; lv++) {
        if (!rh_known[lv].name || !(rh_known[lv].mask & HTTP_QUERY_FLAG_REQUEST_HEADERS)) continue;
        const char *wire = srv_req_header(c.s, 0, rh_known[lv].name);
        const char *v = rh_qa(c.hr, lv | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
        if (wire) {
            present++;
            CHECKF(v && !strcmp(v, wire), "REQ level %lu %s: got \"%s\" err=%lu wire \"%s\"", lv, rh_known[lv].name, v ? v : "(fail)", rh_err, wire);
        } else {
            CHECKF(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "REQ level %lu %s: got \"%s\" err=%lu, not on the wire", lv, rh_known[lv].name, v ? v : "(fail)", rh_err);
        }
    }
    CHECK(present >= 5);   /* User-Agent, Host, Accept-Language, Referer, From (+ Cache-Control/Pragma per flags) */
    for (int h = 0; h < srv_req_header_count(c.s, 0); h++) {
        const char *nm = srv_req_header_name(c.s, 0, h);
        const char *v = rh_qac(c.hr, nm, HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
        CHECKF(v && !strcmp(v, srv_req_header_value(c.s, 0, h)), "CUSTOM|REQ %s: got \"%s\" err=%lu", nm, v ? v : "(fail)", rh_err);
    }
    EXPECT_STR(rh_qac(c.hr, "X-Req", HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL), "one");
    EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_USER_AGENT | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL), "rh-agent/1.0");
    EXPECT_STR(rh_qa(c.hr, HTTP_QUERY_HOST | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL), srv_hostport(c.s));
    /* response-side queries for request-only headers find nothing */
    EXPECT_QA(c.hr, HTTP_QUERY_USER_AGENT, NULL);
    EXPECT_QC(c.hr, "X-Req", NULL);
    rh_close(&c);
}

/* RAW_HEADERS_CRLF | REQUEST_HEADERS is the request head that went out */
TEST(hqi_lvl_request_raw_headers_match_wire) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!rh_raw_nosend(&c, "GET", resp, sizeof resp - 1)) return;
    CHECK(rh_send(&c, "X-One: 1\r\nX-Two: two\r\n", NULL, 0)); RH_SENT_OR_FAIL(&c);
    CHECK(srv_wait_requests(c.s, 1, 3000));
    size_t wn = 0; const char *wire = srv_req_head_raw(c.s, 0, &wn);
    const char *v = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
    CHECKF(v && wire && strlen(v) == wn && !memcmp(v, wire, wn), "req raw: %s\n      wire: %s", v ? rh_esc(v, strlen(v)) : "(fail)", wire ? rh_esc(wire, wn) : "(none)");
    EXPECT_EQ(rh_len, wn);
    /* NUL-separated flavour of the same block */
    const char *n0 = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
    CHECK(n0 != NULL);
    /* each CRLF becomes one NUL and the final blank line is dropped: len = wire - (header lines + request line) - 2 */
    if (n0) { EXPECT_STR(n0, srv_req_line(c.s, 0)); EXPECT_EQ(rh_len, wn - (size_t)(srv_req_header_count(c.s, 0) + 1) - 2); }
    rh_close(&c);
}

TEST(hqi_lvl_request_method_and_version) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    static const char *verbs[] = { "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "XCUSTOM", "get" };
    for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
        rh_t c; if (!rh_raw_nosend(&c, verbs[i], resp, sizeof resp - 1)) return;
        EXPECT_Q(c.hr, HTTP_QUERY_REQUEST_METHOD, verbs[i]);
        EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD | HTTP_QUERY_FLAG_REQUEST_HEADERS, verbs[i]);
        rh_send(&c, NULL, NULL, 0);
        CHECKF(c.sent, "%s: err=%lu", verbs[i], c.err);
        EXPECT_Q(c.hr, HTTP_QUERY_REQUEST_METHOD, verbs[i]);
        if (srv_wait_requests(c.s, 1, 3000)) EXPECT_STR(srv_req_method(c.s, 0), verbs[i]);
        rh_close(&c);
    }
    /* HttpOpenRequest version string: [W10] "HTTP/1.0" is not honoured, the request still goes out as HTTP/1.1
     * (the session's INTERNET_OPTION_HTTP_VERSION wins) and the request-side VERSION says HTTP/1.1 */
    static const char *vers[] = { "HTTP/1.0", "HTTP/1.1" };
    for (int i = 0; i < 2; i++) {
        rh_t c; srv_step st[] = { S_HEAD(), S_SENDN(resp, sizeof resp - 1), S_CLOSE() };
        if (!rh_start(&c, st, 3)) return;
        if (!rh_open_v(&c, "GET", "/v", vers[i], 0)) { rh_close(&c); return; }
        EXPECT_QA(c.hr, HTTP_QUERY_VERSION | HTTP_QUERY_FLAG_REQUEST_HEADERS, "HTTP/1.1");
        rh_send(&c, NULL, NULL, 0);
        EXPECT_QA(c.hr, HTTP_QUERY_VERSION | HTTP_QUERY_FLAG_REQUEST_HEADERS, "HTTP/1.1");
        EXPECT_QA(c.hr, HTTP_QUERY_VERSION, "HTTP/1.1");   /* response side = the server's version */
        if (srv_wait_requests(c.s, 1, 3000)) { char want[64]; snprintf(want, sizeof want, "GET /v %s", "HTTP/1.1"); EXPECT_STR(srv_req_line(c.s, 0), want); }
        rh_close(&c);
    }
}
