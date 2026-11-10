/* wire_more.c - second pass: HttpQueryInfo(REQUEST_HEADERS) against the recorded wire, more HttpAddRequestHeaders
 * edge cases (separators, flag combinations, headers created by HttpOpenRequest), header persistence across re-sends,
 * proxy bypass, cross-server redirects (Host follows the Location), keep-alive retry after a dead pooled socket,
 * cache validators, CR/LF injection attempts in caller strings, W entry points.
 * Evidence: InitBeginSendRequest@0x88e20 (UA index 0x27, Host index 0x37 "%s" / "%s:%d", Content-Length index 5
 * "%I32u"), the Win10 VM. See EVIDENCE.md. */
#include "hrw.h"
#include <stdlib.h>

static srv *srv_scripts(const srv_script *sc, int n, void *user) {
    return hrw_srv_cfg(sc, n, user, HRW_IO_MS);
}
static int send_get(HINTERNET hc, const char *verb, const char *path, DWORD flags, const char *hdrs, const void *opt, DWORD n, int *status) {
    HINTERNET hr = U(HttpOpenRequestA)(hc, verb, path, NULL, NULL, NULL, flags, 0);
    if (!hr) return 0;
    BOOL ok = U(HttpSendRequestA)(hr, hdrs, hdrs ? (DWORD)-1 : 0, (LPVOID)opt, n);
    DWORD st = 0, l = sizeof st;
    if (ok) { U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL); char b[256]; t_inet_read_all(hr, b, sizeof b, NULL); }
    if (status) *status = (int)st;
    U(InternetCloseHandle)(hr);
    return ok;
}
static HINTERNET conn(HINTERNET hi, srv *s) { return U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0); }

/* ------------------------------------------------------------------ HttpQueryInfo(REQUEST_HEADERS) == wire */
static const char *qreq(HINTERNET hr, DWORD level, DWORD *err) {
    static char b[4][1024]; static int k; char *o = b[k++ & 3];
    DWORD l = 1024; SetLastError(0);
    BOOL ok = U(HttpQueryInfoA)(hr, level | HTTP_QUERY_FLAG_REQUEST_HEADERS, o, &l, NULL);
    *err = ok ? 0 : GetLastError();
    return ok ? o : NULL;
}
typedef struct { DWORD level; const char *name; } qmap;
static const qmap g_q[] = {
    { HTTP_QUERY_USER_AGENT, "User-Agent" }, { HTTP_QUERY_HOST, "Host" }, { HTTP_QUERY_REFERER, "Referer" },
    { HTTP_QUERY_ACCEPT, "Accept" }, { HTTP_QUERY_CONTENT_LENGTH, "Content-Length" }, { HTTP_QUERY_CACHE_CONTROL, "Cache-Control" },
    { HTTP_QUERY_CONNECTION, "Connection" }, { HTTP_QUERY_CONTENT_TYPE, "Content-Type" }, { HTTP_QUERY_COOKIE, "Cookie" },
    { HTTP_QUERY_PRAGMA, "Pragma" }, { HTTP_QUERY_AUTHORIZATION, "Authorization" }, { HTTP_QUERY_ACCEPT_ENCODING, "Accept-Encoding" },
};
/* Every known request header that went on the wire answers the same value from HttpQueryInfo; absent ones -> 12150. */
static void query_matrix(const char *verb, const char *ref, const char **acc, const char *hdrs, const void *opt, DWORD n) {
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "qm/1", verb, "/qm", NULL, ref, acc, HRW_F));
    hrw_send(&w, hdrs, hdrs ? (DWORD)-1 : 0, opt, n); CHECKF(w.ok, "err %lu", w.err); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    for (size_t i = 0; i < sizeof g_q / sizeof g_q[0]; i++) {
        DWORD e; const char *v = qreq(w.hr, g_q[i].level, &e);
        const char *wire = srv_req_header(s, 0, g_q[i].name);
        /* Win10 VM: a caller Authorization header is on the wire but HTTP_QUERY_AUTHORIZATION on the request block
         * answers 12150 */
        if (g_q[i].level == HTTP_QUERY_AUTHORIZATION) wire = NULL;
        if (wire) CHECKF(v && !strcmp(v, wire), "%s %s: query \"%s\" (err %lu) wire \"%s\"", verb, g_q[i].name, v ? v : "(null)", e, wire);
        else CHECKF(!v && e == ERROR_HTTP_HEADER_NOT_FOUND, "%s %s: absent on wire but query \"%s\" err %lu", verb, g_q[i].name, v ? v : "(null)", e);
    }
    DWORD e; const char *m = qreq(w.hr, HTTP_QUERY_REQUEST_METHOD, &e);
    CHECKF(m && !strcmp(m, srv_req_method(s, 0)), "method query %s wire %s", m ? m : "(null)", srv_req_method(s, 0));
    hrw_done(&w);
}
TEST(hrw_qi_matrix_get) { HRW_REQUIRE_HTTP(); query_matrix("GET", NULL, NULL, NULL, NULL, 0); }
TEST(hrw_qi_matrix_get_ref_accept) { HRW_REQUIRE_HTTP(); static const char *a[] = { "text/plain", "x/y", NULL }; query_matrix("GET", "http://r.example/", a, NULL, NULL, 0); }
TEST(hrw_qi_matrix_post_body) { HRW_REQUIRE_HTTP(); query_matrix("POST", NULL, NULL, "Content-Type: application/x-www-form-urlencoded\r\n", "a=b", 3); }
TEST(hrw_qi_matrix_put_manual) { HRW_REQUIRE_HTTP(); query_matrix("PUT", NULL, NULL, "Cookie: m=1\r\nAuthorization: Bearer t\r\nConnection: Keep-Alive\r\n", "xy", 2); }
TEST(hrw_qi_matrix_head) { HRW_REQUIRE_HTTP(); query_matrix("HEAD", NULL, NULL, "Accept-Encoding: gzip\r\nPragma: no-cache\r\n", NULL, 0); }

/* Before HttpSendRequest the request block has no User-Agent/Host yet (they are added in InitBeginSendRequest). */
TEST(hrw_qi_before_send_no_ua_host) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "qb/1", "GET", "/qb", NULL, "http://r.example/", NULL, HRW_F));
    DWORD e;
    CHECK(!qreq(w.hr, HTTP_QUERY_USER_AGENT, &e)); EXPECT_EQ(e, ERROR_HTTP_HEADER_NOT_FOUND);
    CHECK(!qreq(w.hr, HTTP_QUERY_HOST, &e)); EXPECT_EQ(e, ERROR_HTTP_HEADER_NOT_FOUND);
    const char *r = qreq(w.hr, HTTP_QUERY_REFERER, &e);
    EXPECT_STR(r, "http://r.example/");
    const char *m = qreq(w.hr, HTTP_QUERY_REQUEST_METHOD, &e);
    EXPECT_STR(m, "GET");
    hrw_done(&w);
}
TEST(hrw_qi_raw_crlf_before_send) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "qr/1", "DELETE", "/qr?x", NULL, NULL, NULL, HRW_F));
    DWORD e; const char *raw = qreq(w.hr, HTTP_QUERY_RAW_HEADERS_CRLF, &e);
    CHECKF(raw != NULL, "err %lu", e);
    t_note("request block before send: %s", raw ? raw : "(null)");
    CHECK(raw && !strncmp(raw, "DELETE /qr?x HTTP/1.1\r\n", 23));
    hrw_done(&w);
}
TEST(hrw_qi_version_request) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "qv/1", "GET", "/qv", "HTTP/1.0", NULL, NULL, HRW_F));
    DWORD e; const char *v = qreq(w.hr, HTTP_QUERY_VERSION, &e);
    t_note("request VERSION query for HTTP/1.0 open: %s err %lu", v ? v : "(null)", e);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    v = qreq(w.hr, HTTP_QUERY_VERSION, &e);
    CHECKF(v && !strcmp(v, "HTTP/1.1"), "VERSION after send %s (wire %s)", v ? v : "(null)", srv_req_line(s, 0));
    hrw_done(&w);
}

/* ------------------------------------------------------------------ more HttpAddRequestHeaders */
static BOOL addh(HINTERNET hr, const char *h, DWORD flags) { SetLastError(0xdeadbeef); return U(HttpAddRequestHeadersA)(hr, h, (DWORD)-1, flags); }
#define OPEN2(w, s, verb, path, ref, acc) \
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP(); \
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; } \
    hrw w; CHECK(hrw_open(&w, s, "am/1", verb, path, NULL, ref, acc, HRW_F))
#define SEND2(w) do { hrw_send(&(w), NULL, 0, NULL, 0); CHECKF((w).ok, "send err %lu", (w).err); if ((w).ok) hrw_read(&(w)); CHECK(srv_wait_requests((w).s, 1, 3000)); } while (0)

TEST(hrw_add2_cr_only_separator) {
    OPEN2(w, s, "GET", "/cr", NULL, NULL);
    BOOL ok = addh(w.hr, "X-1: a\rX-2: b", HTTP_ADDREQ_FLAG_ADD);
    CHECK(ok);
    SEND2(w);
    EXPECT_NAMES(s, 0, "X-1|X-2|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_lfcr_separator) {
    OPEN2(w, s, "GET", "/lfcr", NULL, NULL);
    CHECK(addh(w.hr, "X-1: a\n\rX-2: b", HTTP_ADDREQ_FLAG_ADD));
    SEND2(w);
    EXPECT_NAMES(s, 0, "X-1|X-2|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_same_name_twice_one_call) {
    OPEN2(w, s, "GET", "/d", NULL, NULL);
    CHECK(addh(w.hr, "X-D: 1\r\nX-D: 2", HTTP_ADDREQ_FLAG_ADD));
    SEND2(w);
    EXPECT_NAMES(s, 0, "X-D|X-D|User-Agent|Host|Cache-Control");
    EXPECT_STR(srv_req_header_value(s, 0, 1), "2");
    hrw_done(&w);
}
TEST(hrw_add2_if_new_same_name_twice_one_call) {
    OPEN2(w, s, "GET", "/d", NULL, NULL);
    CHECK(!addh(w.hr, "X-D: 1\r\nX-D: 2", HTTP_ADDREQ_FLAG_ADD_IF_NEW));
    EXPECT_ERR(ERROR_HTTP_HEADER_ALREADY_EXISTS);
    SEND2(w);
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "X-D"), 1);
    EXPECT_HDR(s, 0, "X-D", "1");
    hrw_done(&w);
}
TEST(hrw_add2_coalesce_same_call) {
    OPEN2(w, s, "GET", "/c", NULL, NULL);
    CHECK(addh(w.hr, "X-C: 1\r\nX-C: 2\r\nX-C: 3", HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    SEND2(w);
    EXPECT_HDR(s, 0, "X-C", "1, 2, 3");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "X-C"), 1);
    hrw_done(&w);
}
TEST(hrw_add2_semicolon_cookie_manual) {
    OPEN2(w, s, "GET", "/ck", NULL, NULL);
    CHECK(addh(w.hr, "Cookie: a=1", HTTP_ADDREQ_FLAG_ADD));
    CHECK(addh(w.hr, "Cookie: b=2", HTTP_ADDREQ_FLAG_COALESCE_WITH_SEMICOLON));
    SEND2(w);
    EXPECT_HDR(s, 0, "Cookie", "a=1; b=2");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Cookie"), 1);
    hrw_done(&w);
}
TEST(hrw_add2_coalesce_duplicate_target) {
    OPEN2(w, s, "GET", "/c", NULL, NULL);
    CHECK(addh(w.hr, "X-C: 1", HTTP_ADDREQ_FLAG_ADD));
    CHECK(addh(w.hr, "X-C: 2", HTTP_ADDREQ_FLAG_ADD));
    CHECK(addh(w.hr, "X-C: 3", HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA));
    SEND2(w);
    EXPECT_STR(srv_req_header_value(s, 0, 0), "1, 3");
    EXPECT_STR(srv_req_header_value(s, 0, 1), "2");
    hrw_done(&w);
}
TEST(hrw_add2_if_new_referer_from_open) {
    OPEN2(w, s, "GET", "/r", "http://r.example/", NULL);
    CHECK(!addh(w.hr, "Referer: http://other.example/", HTTP_ADDREQ_FLAG_ADD_IF_NEW));
    EXPECT_ERR(ERROR_HTTP_HEADER_ALREADY_EXISTS);
    SEND2(w);
    EXPECT_HDR(s, 0, "Referer", "http://r.example/");
    hrw_done(&w);
}
TEST(hrw_add2_replace_referer_from_open) {
    OPEN2(w, s, "GET", "/r", "http://r.example/", NULL);
    CHECK(addh(w.hr, "Referer: http://other.example/", HTTP_ADDREQ_FLAG_REPLACE));
    SEND2(w);
    EXPECT_HDR(s, 0, "Referer", "http://other.example/");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Referer"), 1);
    EXPECT_NAMES(s, 0, "Referer|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_add_second_referer) {
    OPEN2(w, s, "GET", "/r", "http://r.example/", NULL);
    CHECK(addh(w.hr, "Referer: http://two.example/", HTTP_ADDREQ_FLAG_ADD));
    SEND2(w);
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Referer"), 2);
    hrw_done(&w);
}
TEST(hrw_add2_if_new_accept_from_open) {
    static const char *a[] = { "text/plain", NULL };
    OPEN2(w, s, "GET", "/a", NULL, a);
    CHECK(!addh(w.hr, "Accept: */*", HTTP_ADDREQ_FLAG_ADD_IF_NEW));
    EXPECT_ERR(ERROR_HTTP_HEADER_ALREADY_EXISTS);
    SEND2(w);
    EXPECT_HDR(s, 0, "Accept", "text/plain");
    hrw_done(&w);
}
TEST(hrw_add2_remove_accept_from_open) {
    static const char *a[] = { "text/plain", NULL };
    OPEN2(w, s, "GET", "/a", NULL, a);
    CHECK(addh(w.hr, "Accept:", HTTP_ADDREQ_FLAG_REPLACE));
    SEND2(w);
    EXPECT_NOHDR(s, 0, "Accept");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
/* Win10 VM: REPLACE on an absent header adds it, so a REPLACE of User-Agent/Host before the send installs the caller
 * value, and InitBeginSendRequest (_ReplaceHeader flag 0x10000000) keeps it. */
TEST(hrw_add2_replace_user_agent_before_send_adds) {
    OPEN2(w, s, "GET", "/u", NULL, NULL);
    CHECK(addh(w.hr, "User-Agent: r", HTTP_ADDREQ_FLAG_REPLACE));
    SEND2(w);
    EXPECT_HDR(s, 0, "User-Agent", "r");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "User-Agent"), 1);
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_replace_host_before_send_adds) {
    OPEN2(w, s, "GET", "/h", NULL, NULL);
    CHECK(addh(w.hr, "Host: x.example", HTTP_ADDREQ_FLAG_REPLACE));
    SEND2(w);
    EXPECT_HDR(s, 0, "Host", "x.example");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Host"), 1);
    EXPECT_NAMES(s, 0, "Host|User-Agent|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_host_lowercase_name) {
    OPEN2(w, s, "GET", "/h", NULL, NULL);
    CHECK(addh(w.hr, "host: lower.example", HTTP_ADDREQ_FLAG_ADD));
    SEND2(w);
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Host"), 1);
    EXPECT_HDR(s, 0, "Host", "lower.example");
    EXPECT_NAMES(s, 0, "host|User-Agent|Cache-Control");   /* Win10 VM: caller casing and position kept */
    hrw_done(&w);
}
TEST(hrw_add2_user_agent_empty_value_allowed) {
    OPEN2(w, s, "GET", "/u", NULL, NULL);
    BOOL ok = addh(w.hr, "User-Agent:", HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_ALLOW_EMPTY_VALUES);
    CHECKF(ok, "err %lu", GetLastError());
    SEND2(w);
    /* Win10 VM: the caller's empty User-Agent wins over the session agent */
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "User-Agent"), 1);
    EXPECT_HDR(s, 0, "User-Agent", "");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_replace_and_if_new) {
    OPEN2(w, s, "GET", "/f", NULL, NULL);
    CHECK(addh(w.hr, "X-F: 1", HTTP_ADDREQ_FLAG_ADD));
    BOOL ok = addh(w.hr, "X-F: 2", HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD_IF_NEW);
    CHECK(!ok); EXPECT_ERR(ERROR_HTTP_HEADER_ALREADY_EXISTS);   /* Win10 VM: ADD_IF_NEW is checked first */
    SEND2(w);
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "X-F"), 1);
    EXPECT_HDR(s, 0, "X-F", "1");
    hrw_done(&w);
}
TEST(hrw_add2_coalesce_and_replace) {
    OPEN2(w, s, "GET", "/f", NULL, NULL);
    CHECK(addh(w.hr, "X-F: 1", HTTP_ADDREQ_FLAG_ADD));
    BOOL ok = addh(w.hr, "X-F: 2", HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_COALESCE_WITH_COMMA);
    CHECK(ok);
    SEND2(w);
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "X-F"), 1);
    EXPECT_HDR(s, 0, "X-F", "2");   /* Win10 VM: REPLACE wins over COALESCE */
    hrw_done(&w);
}
TEST(hrw_add2_space_inside_name) {
    OPEN2(w, s, "GET", "/sp", NULL, NULL);
    BOOL ok = addh(w.hr, "X Sp: v", HTTP_ADDREQ_FLAG_ADD);
    DWORD e = GetLastError();
    t_note("space inside header name: ok=%d err=%lu", ok, e);
    CHECK(ok);
    SEND2(w);
    hrw_dump(s, 0);
    hrw_done(&w);
}
TEST(hrw_add2_value_with_crlf_continuation) {
    OPEN2(w, s, "GET", "/fold", NULL, NULL);
    BOOL ok = addh(w.hr, "X-Fold: a\r\n b", HTTP_ADDREQ_FLAG_ADD);
    /* Win10 VM: the continuation is a second line " b" without a colon -> 87, the first line stays applied */
    CHECK(!ok); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SEND2(w);
    EXPECT_HDR(s, 0, "X-Fold", "a");
    EXPECT_NAMES(s, 0, "X-Fold|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_w_lf_only_lines) {
    OPEN2(w, s, "GET", "/wl", NULL, NULL);
    REQUIRE(U(HttpAddRequestHeadersW));
    CHECK(U(HttpAddRequestHeadersW)(w.hr, L"X-A: 1\nX-B: 2\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    SEND2(w);
    EXPECT_NAMES(s, 0, "X-A|X-B|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_add2_w_replace) {
    OPEN2(w, s, "GET", "/wr", NULL, NULL);
    REQUIRE(U(HttpAddRequestHeadersW));
    CHECK(U(HttpAddRequestHeadersW)(w.hr, L"X-A: 1", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpAddRequestHeadersW)(w.hr, L"X-A: 2", (DWORD)-1, HTTP_ADDREQ_FLAG_REPLACE));
    SEND2(w);
    EXPECT_HDR(s, 0, "X-A", "2");
    hrw_done(&w);
}
TEST(hrw_add2_w_empty_rejected) {
    REQUIRE(U(HttpAddRequestHeadersW));
    OPEN2(w, s, "GET", "/we", NULL, NULL);
    SetLastError(0);
    CHECK(!U(HttpAddRequestHeadersW)(w.hr, L"", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SetLastError(0);
    CHECK(!U(HttpAddRequestHeadersW)(w.hr, NULL, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    hrw_done(&w);
}

/* ------------------------------------------------------------------ headers across re-sends of one handle */
TEST(hrw_resend_send_headers_persist) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rp/1", "GET", "/rp", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, "X-Once: 1\r\n", (DWORD)-1, NULL, 0); CHECK(w.ok); hrw_read(&w);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 2, 3000));
    t_note("re-send names: %s", hrw_names(s, 1));
    EXPECT_HDR(s, 1, "X-Once", "1");
    EXPECT_EQ(srv_req_header_occurrences(s, 1, "X-Once"), 1);
    hrw_done(&w);
}
TEST(hrw_resend_same_send_headers_not_duplicated) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rp/2", "GET", "/rp", NULL, NULL, NULL, HRW_F));
    for (int i = 0; i < 3; i++) { hrw_send(&w, "X-Rep: v\r\n", (DWORD)-1, NULL, 0); CHECK(w.ok); hrw_read(&w); }
    CHECK(srv_wait_requests(s, 3, 3000));
    for (int i = 0; i < 3; i++) EXPECT_EQ(srv_req_header_occurrences(s, i, "X-Rep"), 1);
    EXPECT_EQ(srv_conn_count(s), 1);
    hrw_done(&w);
}
TEST(hrw_resend_post_without_optional) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rp/3", "POST", "/rp", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, "12345", 5); CHECK(w.ok); hrw_read(&w);
    hrw_send(&w, NULL, 0, NULL, 0);
    DWORD e2 = w.err; BOOL ok2 = w.ok;
    if (ok2) hrw_read(&w);
    CHECK(srv_wait_requests(s, 2, 3000));
    size_t n1 = 0; const char *b1 = srv_req_body(s, 1, &n1);
    t_note("POST re-send without optional: ok=%d err=%lu %s status=%d; wire CL %s body %.*s", ok2, e2, t_inet_errname(e2), w.status,
           srv_req_header(s, 1, "Content-Length"), (int)n1, b1 ? b1 : "");
    EXPECT_HDR(s, 0, "Content-Length", "5");
    EXPECT_HDR(s, 1, "Content-Length", "5");   /* Win10 VM: the first optional data is re-sent */
    hrw_done(&w);
}

/* ------------------------------------------------------------------ CR/LF in caller strings */
TEST(hrw_inject_agent_crlf) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open_ex("ag\r\nX-Inj: 1", INTERNET_OPEN_TYPE_DIRECT, 0, 5000);
    CHECK(w.hi != NULL);
    w.hc = conn(w.hi, s);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/inj", NULL, NULL, NULL, HRW_F, 0);
    hrw_send(&w, NULL, 0, NULL, 0);
    CHECK(w.ok);
    if (w.ok) hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    /* Win10 VM: the agent string is cut at the CR */
    EXPECT_HDR(s, 0, "User-Agent", "ag");
    EXPECT_NOHDR(s, 0, "X-Inj");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_inject_referer_crlf) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open("ri/1"); w.hc = conn(w.hi, s);
    SetLastError(0);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/ri", NULL, "http://r.example/\r\nX-Inj: 1", NULL, HRW_F, 0);
    CHECK(w.hr != NULL);
    if (w.hr) {
        hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok);
        if (w.ok) hrw_read(&w);
        CHECK(srv_wait_requests(s, 1, 3000));
        EXPECT_HDR(s, 0, "Referer", "http://r.example/");   /* Win10 VM: cut at the CR */
        EXPECT_NOHDR(s, 0, "X-Inj");
    }
    hrw_done(&w);
}
TEST(hrw_inject_object_crlf) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open("oi/1"); w.hc = conn(w.hi, s);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/a b\r\nX-Inj: 1", NULL, NULL, NULL, HRW_F, 0);
    CHECK(w.hr != NULL);
    if (w.hr) {
        hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok);
        if (w.ok) { hrw_read(&w); CHECK(srv_wait_requests(s, 1, 3000)); }
        /* Win10 VM: CR/LF are dropped from the object name and the spaces escaped */
        EXPECT_STR(srv_req_line(s, 0), "GET /a%20bX-Inj:%201 HTTP/1.1");
        EXPECT_NOHDR(s, 0, "X-Inj");
        EXPECT_EQ(srv_req_count(s), 1);
    }
    hrw_done(&w);
}
TEST(hrw_inject_accept_crlf) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open("ai/1"); w.hc = conn(w.hi, s);
    static const char *a[] = { "text/plain\r\nX-Inj: 1", NULL };
    SetLastError(0);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/ai", NULL, NULL, a, HRW_F, 0);
    CHECK(w.hr != NULL);
    if (w.hr) {
        hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok);
        if (w.ok) hrw_read(&w);
        CHECK(srv_wait_requests(s, 1, 3000));
        EXPECT_HDR(s, 0, "Accept", "text/plain");   /* Win10 VM: cut at the CR */
        EXPECT_NOHDR(s, 0, "X-Inj");
    }
    hrw_done(&w);
}

/* ------------------------------------------------------------------ object name: more forms */
static void obj2(const char *obj, const char *want) {
    hrw w; int r = hrw_simple(&w, "o2/1", "GET", obj, NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECKF(r, "obj '%s' not recorded ok=%d err=%lu", obj, w.ok, w.err);
    const char *t = srv_req_target(w.s, 0);
    if (want) CHECKF(t && !strcmp(t, want), "obj '%s': target got \"%s\" want \"%s\"", obj, t ? t : "(null)", want);
    else t_note("obj '%s' -> target \"%s\"", obj, t ? t : "(null)");
    hrw_done(&w);
}
TEST(hrw_obj2_query_space) { HRW_REQUIRE_HTTP(); obj2("/q?a b", "/q?a%20b"); }
/* the object-name forms below: Win10 VM (boot C1) */
TEST(hrw_obj2_backslash) { HRW_REQUIRE_HTTP(); obj2("/a\\b", "/a/b"); }
TEST(hrw_obj2_lone_percent) { HRW_REQUIRE_HTTP(); obj2("/p%zz", "/p%zz"); }
TEST(hrw_obj2_tab) { HRW_REQUIRE_HTTP(); obj2("/t\tx", "/tx"); }
TEST(hrw_obj2_query_only) { HRW_REQUIRE_HTTP(); obj2("?only=1", "/?only=1"); }
TEST(hrw_obj2_trailing_dot_segment) { HRW_REQUIRE_HTTP(); obj2("/a/b/..", "/a/"); }
TEST(hrw_obj2_encoded_dot_segment) { HRW_REQUIRE_HTTP(); obj2("/a/%2e%2e/b", "/a/%2e%2e/b"); }
TEST(hrw_obj2_semicolon_params) { HRW_REQUIRE_HTTP(); obj2("/a;p=1/b;q", "/a;p=1/b;q"); }
TEST(hrw_obj2_reserved_chars) { HRW_REQUIRE_HTTP(); obj2("/r?x=[1]&y={2}|^`", "/r?x=[1]&y={2}|^`"); }
TEST(hrw_obj2_https_absolute_direct) { HRW_REQUIRE_HTTP(); obj2("https://o.example/p", "/https://o.example/p"); }

/* ------------------------------------------------------------------ verbs: more forms */
TEST(hrw_verb2_long) {
    HRW_REQUIRE_HTTP();
    char v[129]; for (int i = 0; i < 128; i++) v[i] = (char)('A' + i % 26); v[128] = 0;
    hrw w; int r = hrw_simple(&w, "vl/1", v, "/vl", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECKF(r, "ok=%d err=%lu", w.ok, w.err);
    EXPECT_STR(srv_req_method(w.s, 0), v);
    hrw_done(&w);
}
TEST(hrw_verb2_w_lowercase) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "vw/1", "GET", "/", NULL, NULL, NULL, HRW_F));
    U(InternetCloseHandle)(w.hr);
    w.hr = U(HttpOpenRequestW)(w.hc, L"post", L"/vw", NULL, NULL, NULL, HRW_F, 0);
    CHECK(w.hr != NULL);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "post /vw HTTP/1.1");
    EXPECT_HDR(s, 0, "Content-Length", "0");
    hrw_done(&w);
}
TEST(hrw_verb2_w_ver10_upgraded) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "vw/2", "GET", "/", NULL, NULL, NULL, HRW_F));
    U(InternetCloseHandle)(w.hr);
    w.hr = U(HttpOpenRequestW)(w.hc, L"GET", L"/v10", L"HTTP/1.0", NULL, NULL, HRW_F, 0);
    CHECK(w.hr != NULL);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "GET /v10 HTTP/1.1");
    hrw_done(&w);
}
TEST(hrw_ref2_w_nonascii) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rw/1", "GET", "/", NULL, NULL, NULL, HRW_F));
    U(InternetCloseHandle)(w.hr);
    w.hr = U(HttpOpenRequestW)(w.hc, NULL, L"/rw", NULL, L"http://r.example/café", NULL, HRW_F, 0);
    CHECKF(w.hr != NULL, "open err %lu", GetLastError());
    hrw_send(&w, NULL, 0, NULL, 0); CHECKF(w.ok, "send err %lu %s", w.err, t_inet_errname(w.err)); if (w.ok) hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    const char *r = srv_req_header(s, 0, "Referer");
    t_note("W referer with U+00E9 -> \"%s\"", r ? r : "(none)");
    CHECK(r != NULL);
    hrw_done(&w);
}

/* ------------------------------------------------------------------ bodies: more */
TEST(hrw_body2_send_w_optional) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpSendRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "bw/1", "POST", "/bw", NULL, NULL, NULL, HRW_F));
    CHECK(U(HttpSendRequestW)(w.hr, L"Content-Type: text/plain\r\n", (DWORD)-1, "wbody", 5));
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "5");
    size_t n = 0; const char *b = srv_req_body(s, 0, &n);
    CHECK(b && n == 5 && !memcmp(b, "wbody", 5));
    EXPECT_NAMES(s, 0, "Content-Type|User-Agent|Host|Content-Length|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_body2_head_with_optional) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "bh/1", "HEAD", "/bh", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, "hb", 2);
    CHECK(w.ok); EXPECT_EQ(w.status, 200);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "2");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Content-Length|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_body2_post_keepalive_reuse) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("pk/1"), hc = conn(hi, s);
    int st = 0;
    for (int i = 0; i < 3; i++) { CHECK(send_get(hc, "POST", "/pk", HRW_F, NULL, "abc", 3, &st)); EXPECT_EQ(st, 200); }
    CHECK(srv_wait_events(s, SRV_EV_BODY, 3, 3000));
    EXPECT_EQ(srv_conn_count(s), 1);
    for (int i = 0; i < 3; i++) EXPECT_HDR(s, i, "Content-Length", "3");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_body2_sendex_get_with_total, 20000) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(InternetWriteFile)); REQUIRE(U(HttpEndRequestA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "bx/1", "GET", "/bx", NULL, NULL, NULL, HRW_F));
    INTERNET_BUFFERSA b; memset(&b, 0, sizeof b); b.dwStructSize = sizeof b; b.dwBufferTotal = 4;
    CHECK(U(HttpSendRequestExA)(w.hr, &b, NULL, 0, 0));
    DWORD wr = 0; CHECK(U(InternetWriteFile)(w.hr, "gget", 4, &wr)); EXPECT_EQ(wr, 4);
    CHECK(U(HttpEndRequestA)(w.hr, NULL, 0, 0));
    hrw_read(&w);
    CHECK(srv_wait_events(s, SRV_EV_BODY, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "4");
    size_t n = 0; const char *bd = srv_req_body(s, 0, &n);
    CHECK(bd && n == 4 && !memcmp(bd, "gget", 4));
    hrw_done(&w);
}
GTEST(hrw_body2_sendex_buffer_length_ignored_without_ptr, 20000) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "bx/2", "POST", "/bx", NULL, NULL, NULL, HRW_F));
    INTERNET_BUFFERSA b; memset(&b, 0, sizeof b); b.dwStructSize = sizeof b; b.lpvBuffer = NULL; b.dwBufferLength = 9; b.dwBufferTotal = 0;
    BOOL ok = U(HttpSendRequestExA)(w.hr, &b, NULL, 0, 0);
    CHECKF(ok, "err %lu", GetLastError());
    if (ok) { CHECK(U(HttpEndRequestA)(w.hr, NULL, 0, 0)); hrw_read(&w); }
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Content-Length", "0");   /* InitBeginSendRequest: a NULL buffer forces the length to 0 */
    hrw_done(&w);
}

/* ------------------------------------------------------------------ keep-alive: dead pooled socket */
GTEST(hrw_ka_retry_after_server_reset, 20000) {
    HRW_REQUIRE_HTTP();
    /* connection 0: answers one request, then resets on the second; connection 1+: normal */
    static const srv_step c0[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "one"), S_HEAD(), S_RESET() };
    static const srv_step c1[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "two"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(c0), SRV_SCRIPT(c1) };
    srv *s = srv_scripts(sc, 2, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("kr/1"), hc = conn(hi, s);
    int st = 0;
    CHECK(send_get(hc, "GET", "/k1", HRW_F, NULL, NULL, 0, &st)); EXPECT_EQ(st, 200);
    BOOL ok = send_get(hc, "GET", "/k2", HRW_F, NULL, NULL, 0, &st);
    t_note("second request after RST on the pooled socket: ok=%d err=%lu status=%d requests=%d conns=%d", ok, ok ? 0 : GetLastError(), st, srv_req_count(s), srv_conn_count(s));
    CHECK(ok); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 3, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    EXPECT_STR(srv_req_line(s, 1), "GET /k2 HTTP/1.1");
    EXPECT_STR(srv_req_line(s, 2), "GET /k2 HTTP/1.1");
    EXPECT_EQ(srv_req_conn(s, 1), 0);
    EXPECT_EQ(srv_req_conn(s, 2), 1);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
GTEST(hrw_ka_retry_after_server_close, 20000) {
    HRW_REQUIRE_HTTP();
    static const srv_step c0[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "one"), S_HEAD(), S_CLOSE() };
    static const srv_step c1[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "two"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(c0), SRV_SCRIPT(c1) };
    srv *s = srv_scripts(sc, 2, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("kr/2"), hc = conn(hi, s);
    int st = 0;
    CHECK(send_get(hc, "GET", "/k1", HRW_F, NULL, NULL, 0, &st));
    BOOL ok = send_get(hc, "GET", "/k2", HRW_F, NULL, NULL, 0, &st);
    t_note("second request after FIN without reply: ok=%d status=%d requests=%d conns=%d", ok, st, srv_req_count(s), srv_conn_count(s));
    CHECK(ok); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 3, 3000));
    EXPECT_EQ(srv_conn_count(s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
/* A POST whose reused connection dies is re-sent with its body on the new connection. */
GTEST(hrw_ka_retry_post_resends_body, 20000) {
    HRW_REQUIRE_HTTP();
    static const srv_step c0[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "one"), S_HEAD(), S_RESET() };
    static const srv_step c1[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "two"), S_LOOP() };
    static const srv_script sc[] = { SRV_SCRIPT(c0), SRV_SCRIPT(c1) };
    srv *s = srv_scripts(sc, 2, NULL); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("kr/3"), hc = conn(hi, s);
    int st = 0;
    CHECK(send_get(hc, "GET", "/k1", HRW_F, NULL, NULL, 0, &st));
    BOOL ok = send_get(hc, "POST", "/kp", HRW_F, NULL, "postdata", 8, &st);
    t_note("POST after RST: ok=%d status=%d requests=%d conns=%d", ok, st, srv_req_count(s), srv_conn_count(s));
    CHECK(ok); EXPECT_EQ(st, 200);
    /* the RST'd attempt on connection 0 was read as a head only, so two BODY events */
    if (srv_wait_events(s, SRV_EV_BODY, 2, 3000) && srv_wait_requests(s, 3, 3000)) {
        int last = srv_req_count(s) - 1;
        size_t n = 0; const char *b = srv_req_body(s, last, &n);
        CHECK(b && n == 8 && !memcmp(b, "postdata", 8));
        EXPECT_HDR(s, last, "Content-Length", "8");
    } else CHECKF(0, "re-sent POST body not recorded (requests=%d)", srv_req_count(s));
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ proxy bypass and proxy forms */
static HINTERNET proxy_session_bypass(srv *px, const char *bypass, const char *agent) {
    char p[64]; snprintf(p, sizeof p, "http=127.0.0.1:%u", srv_port(px));
    t_net_prepare();
    HINTERNET h = U(InternetOpenA)(agent, INTERNET_OPEN_TYPE_PROXY, p, bypass, 0);
    if (h) { DWORD to = 5000; U(InternetSetOptionA)(h, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to); U(InternetSetOptionA)(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to); }
    return h;
}
GTEST(hrw_proxy2_bypass_ip_goes_direct, 20000) {
    HRW_REQUIRE_HTTP();
    srv *px = hrw_srv(), *org = hrw_srv();
    if (!px || !org) { srv_stop(px); srv_stop(org); t_skip("server unavailable"); return; }
    HINTERNET hi = proxy_session_bypass(px, "127.0.0.1", "bp/1"); CHECK(hi != NULL);
    HINTERNET hc = conn(hi, org);
    int st = 0;
    CHECK(send_get(hc, "GET", "/direct", HRW_F, NULL, NULL, 0, &st)); EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(org, 1, 3000));
    EXPECT_STR(srv_req_line(org, 0), "GET /direct HTTP/1.1");
    EXPECT_EQ(srv_req_count(px), 0);
    EXPECT_NAMES(org, 0, "User-Agent|Host|Cache-Control");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(px); srv_stop(org);
}
GTEST(hrw_proxy2_bypass_other_host_uses_proxy, 20000) {
    HRW_REQUIRE_HTTP();
    srv *px = hrw_srv(); if (!px) { t_skip("server unavailable"); return; }
    HINTERNET hi = proxy_session_bypass(px, "other.i7test.example", "bp/2"); CHECK(hi != NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "via.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    int st = 0;
    CHECK(send_get(hc, "GET", "/v", HRW_F, NULL, NULL, 0, &st));
    CHECK(srv_wait_requests(px, 1, 3000));
    EXPECT_STR(srv_req_line(px, 0), "GET http://via.i7test.example/v HTTP/1.1");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(px);
}
GTEST(hrw_proxy2_bypass_wildcard, 20000) {
    HRW_REQUIRE_HTTP();
    srv *px = hrw_srv(), *org = hrw_srv();
    if (!px || !org) { srv_stop(px); srv_stop(org); t_skip("server unavailable"); return; }
    HINTERNET hi = proxy_session_bypass(px, "127.0.0.*", "bp/3"); CHECK(hi != NULL);
    HINTERNET hc = conn(hi, org);
    int st = 0;
    CHECK(send_get(hc, "GET", "/wild", HRW_F, NULL, NULL, 0, &st));
    CHECK(srv_wait_requests(org, 1, 3000));
    EXPECT_STR(srv_req_line(org, 0), "GET /wild HTTP/1.1");
    EXPECT_EQ(srv_req_count(px), 0);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(px); srv_stop(org);
}
GTEST(hrw_proxy2_all_schemes_form, 20000) {
    HRW_REQUIRE_HTTP();
    srv *px = hrw_srv(); if (!px) { t_skip("server unavailable"); return; }
    char p[64]; snprintf(p, sizeof p, "127.0.0.1:%u", srv_port(px));
    HINTERNET hi = U(InternetOpenA)("px2/1", INTERNET_OPEN_TYPE_PROXY, p, "", 0);
    CHECK(hi != NULL);
    DWORD to = 5000; U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    HINTERNET hc = U(InternetConnectA)(hi, "all.i7test.example", 81, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    int st = 0;
    CHECK(send_get(hc, "GET", "/all?x=1", HRW_F, NULL, NULL, 0, &st));
    CHECK(srv_wait_requests(px, 1, 3000));
    EXPECT_STR(srv_req_line(px, 0), "GET http://all.i7test.example:81/all?x=1 HTTP/1.1");
    EXPECT_HDR(px, 0, "Host", "all.i7test.example:81");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(px);
}
GTEST(hrw_proxy2_no_reload_header_set, 20000) {
    HRW_REQUIRE_HTTP();
    srv *px = hrw_srv(); if (!px) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(px, "px2/2");
    HINTERNET hc = U(InternetConnectA)(hi, "nr.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    char path[96]; snprintf(path, sizeof path, "/%s", t_uniq("nr"));
    int st = 0;
    CHECK(send_get(hc, "GET", path, HRW_F_NORL, NULL, NULL, 0, &st));
    CHECK(srv_wait_requests(px, 1, 3000));
    t_note("proxy without RELOAD: %s", hrw_names(px, 0));
    EXPECT_NAMES(px, 0, "User-Agent|Host");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(px);
}
GTEST(hrw_proxy2_post_header_set, 20000) {
    HRW_REQUIRE_HTTP();
    srv *px = hrw_srv(); if (!px) { t_skip("server unavailable"); return; }
    HINTERNET hi = hrw_proxy_session(px, "px2/3");
    HINTERNET hc = U(InternetConnectA)(hi, "post.i7test.example", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    int st = 0;
    CHECK(send_get(hc, "POST", "/pp", HRW_F, NULL, "zz", 2, &st));
    CHECK(srv_wait_events(px, SRV_EV_BODY, 1, 3000));
    t_note("proxy POST names: %s", hrw_names(px, 0));
    EXPECT_NAMES(px, 0, "User-Agent|Host|Content-Length|Pragma");
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(px);
}

/* ------------------------------------------------------------------ redirects across servers */
static int redir_fn(srv_conn *c, const srv_step *st, void *user) {
    srv *s = srv_conn_server(c);
    for (int k = 0; k < 10; k++) {
        int i = srv_conn_recv_head(c);
        if (i < 0) return -1;
        srv_conn_sendf(c, "HTTP/1.1 %s\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n", srv_req_line(s, i) && strstr(srv_req_line(s, i), "/307") ? "307 Temporary Redirect" : "302 Found", (const char *)user);
    }
    return -1;
}
static void cross_redirect(const char *verb, const char *path, const void *body, DWORD n, const char *hdrs,
                           const char *want_verb, int want_body) {
    srv *dst = hrw_srv(); if (!dst) { t_skip("server unavailable"); return; }
    static char loc[128]; snprintf(loc, sizeof loc, "http://127.0.0.1:%u/landing?q=1", srv_port(dst));
    srv *src = hrw_srv_call(redir_fn, loc); if (!src) { srv_stop(dst); t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("xr/1"), hc = conn(hi, src);
    HINTERNET hr = U(HttpOpenRequestA)(hc, verb, path, NULL, "http://ref.example/", NULL, HRW_F, 0);
    BOOL ok = U(HttpSendRequestA)(hr, hdrs, hdrs ? (DWORD)-1 : 0, (LPVOID)body, n);
    CHECKF(ok, "err %lu", GetLastError());
    DWORD stc = 0, l = sizeof stc; if (ok) U(HttpQueryInfoA)(hr, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &stc, &l, NULL);
    EXPECT_EQ(stc, 200);
    char b[64]; if (ok) t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_requests(dst, 1, 3000));
    char want[96]; snprintf(want, sizeof want, "%s /landing?q=1 HTTP/1.1", want_verb);
    EXPECT_STR(srv_req_line(dst, 0), want);
    EXPECT_HDR(dst, 0, "Host", hrw_hostport(dst));
    EXPECT_EQ(srv_req_count(src), 1);
    if (want_body) {
        CHECK(srv_wait_events(dst, SRV_EV_BODY, 1, 3000));
        size_t bn = 0; const char *bb = srv_req_body(dst, 0, &bn);
        CHECK(bb && bn == n && !memcmp(bb, body, n));
    } else EXPECT_NOHDR(dst, 0, "Content-Length");
    t_note("%s redirected to other port: names %s", verb, hrw_names(dst, 0));
    hrw_dump(dst, 0);
    char url[256]; DWORD ul = sizeof url;
    if (U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, url, &ul)) {
        char wu[160]; snprintf(wu, sizeof wu, "http://127.0.0.1:%u/landing?q=1", srv_port(dst));
        EXPECT_STR(url, wu);
    }
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(src); srv_stop(dst);
}
TEST(hrw_redir2_get_cross_port) { HRW_REQUIRE_HTTP(); cross_redirect("GET", "/302", NULL, 0, NULL, "GET", 0); }
TEST(hrw_redir2_post_cross_port_becomes_get) { HRW_REQUIRE_HTTP(); cross_redirect("POST", "/302", "pb", 2, NULL, "GET", 0); }
TEST(hrw_redir2_custom_header_cross_port) {
    HRW_REQUIRE_HTTP();
    srv *dst = hrw_srv(); if (!dst) { t_skip("server unavailable"); return; }
    static char loc[128]; snprintf(loc, sizeof loc, "http://127.0.0.1:%u/h", srv_port(dst));
    srv *src = hrw_srv_call(redir_fn, loc); if (!src) { srv_stop(dst); t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("xr/2"), hc = conn(hi, src);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/302", NULL, "http://ref.example/", NULL, HRW_F, 0);
    CHECK(U(HttpSendRequestA)(hr, "X-Carry: c\r\nAuthorization: Bearer zz\r\n", (DWORD)-1, NULL, 0));
    char b[64]; t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(srv_wait_requests(dst, 1, 3000));
    t_note("cross-port redirect: X-Carry=%s Authorization=%s Referer=%s", srv_req_header(dst, 0, "X-Carry"), srv_req_header(dst, 0, "Authorization"), srv_req_header(dst, 0, "Referer"));
    EXPECT_HDR(dst, 0, "X-Carry", "c");
    hrw_dump(dst, 0);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(src); srv_stop(dst);
}
TEST(hrw_redir2_no_auto_redirect_single_request) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /never\r\n", ""), S_LOOP() };
    srv *s = hrw_srv_steps(st, 3); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "nr/1", "GET", "/stay", NULL, NULL, NULL, HRW_F | INTERNET_FLAG_NO_AUTO_REDIRECT));
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); EXPECT_EQ(w.status, 302); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    Sleep(100);
    EXPECT_EQ(srv_req_count(s), 1);
    hrw_done(&w);
}
TEST(hrw_redir2_same_server_reuses_connection) {
    HRW_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /b\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "b"), S_LOOP_TO(2) };
    srv *s = hrw_srv_steps(st, 5); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rr/1", "GET", "/a", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); EXPECT_EQ(w.status, 200); hrw_read(&w);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_EQ(srv_conn_count(s), 1);
    EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 0));
    EXPECT_NAMES(s, 1, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ cache validators: which conditionals are sent */
typedef struct { const char *lm; const char *etag; } val_cfg;
static int val_fn(srv_conn *c, const srv_step *st, void *user) {
    const val_cfg *v = (const val_cfg *)user; srv *s = srv_conn_server(c);
    for (int k = 0; k < 10; k++) {
        int i = srv_conn_recv_head(c);
        if (i < 0) return -1;
        if (srv_req_header(s, i, "If-None-Match") || srv_req_header(s, i, "If-Modified-Since"))
            srv_conn_sendf(c, "HTTP/1.1 304 Not Modified\r\n\r\n");
        else {
            char h[256] = "";
            if (v->lm) { strcat(h, "Last-Modified: "); strcat(h, v->lm); strcat(h, "\r\n"); }
            if (v->etag) { strcat(h, "ETag: "); strcat(h, v->etag); strcat(h, "\r\n"); }
            srv_conn_sendf(c, "HTTP/1.1 200 OK\r\n%sCache-Control: max-age=0\r\nContent-Length: 5\r\n\r\nvalid", h);
        }
    }
    return -1;
}
static void validators(const val_cfg *v, const char *want_ims, const char *want_inm, const char *want_names) {
    srv *s = hrw_srv_call(val_fn, (void *)v); if (!s) { t_skip("server unavailable"); return; }
    char path[128]; snprintf(path, sizeof path, "/%s.txt", t_uniq("val"));
    char url[256]; snprintf(url, sizeof url, "http://127.0.0.1:%u%s", srv_port(s), path);
    t_cache_track(url);
    HINTERNET hi = t_inet_open("val/1"), hc = conn(hi, s);
    DWORD f = INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
    int st = 0;
    CHECK(send_get(hc, "GET", path, f, NULL, NULL, 0, &st)); EXPECT_EQ(st, 200);
    CHECK(send_get(hc, "GET", path, f | INTERNET_FLAG_RESYNCHRONIZE, NULL, NULL, 0, &st));
    EXPECT_EQ(st, 200);
    CHECK(srv_wait_requests(s, 2, 3000));
    const char *ims = srv_req_header(s, 1, "If-Modified-Since"), *inm = srv_req_header(s, 1, "If-None-Match");
    CHECKF(want_ims ? (ims && !strcmp(ims, want_ims)) : !ims, "If-Modified-Since %s", ims ? ims : "(none)");
    CHECKF(want_inm ? (inm && !strcmp(inm, want_inm)) : !inm, "If-None-Match %s", inm ? inm : "(none)");
    if (want_names) EXPECT_NAMES(s, 1, want_names);
    t_note("revalidation names: %s", hrw_names(s, 1));
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
    t_net_cleanup();
}
GTEST(hrw_cache2_last_modified_only, 20000) { HRW_REQUIRE_HTTP(); static const val_cfg v = { "Tue, 02 Jan 2018 03:04:05 GMT", NULL }; validators(&v, "Tue, 02 Jan 2018 03:04:05 GMT", NULL, "User-Agent|Host|If-Modified-Since"); }
GTEST(hrw_cache2_etag_only, 20000) { HRW_REQUIRE_HTTP(); static const val_cfg v = { NULL, "\"e-only\"" }; validators(&v, NULL, "\"e-only\"", "User-Agent|Host|If-None-Match"); }
GTEST(hrw_cache2_weak_etag, 20000) { HRW_REQUIRE_HTTP(); static const val_cfg v = { NULL, "W/\"weak\"" }; validators(&v, NULL, "W/\"weak\"", NULL); }
GTEST(hrw_cache2_no_validators_unconditional, 20000) { HRW_REQUIRE_HTTP(); static const val_cfg v = { NULL, NULL }; validators(&v, NULL, NULL, NULL); }

/* ------------------------------------------------------------------ explicit Connection headers */
TEST(hrw_conn2_explicit_keepalive_header) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ck/1", "GET", "/k", NULL, NULL, NULL, HRW_F, "Connection: Keep-Alive\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Connection"), 1);
    EXPECT_HDR(w.s, 0, "Connection", "Keep-Alive");
    hrw_done(&w);
}
TEST(hrw_conn2_close_via_addheaders) {
    REQUIRE(U(HttpAddRequestHeadersA)); HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("cv/1"), hc = conn(hi, s);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/c1", NULL, NULL, NULL, HRW_F, 0);
    CHECK(U(HttpAddRequestHeadersA)(hr, "Connection: close", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
    char b[16]; t_inet_read_all(hr, b, sizeof b, NULL); U(InternetCloseHandle)(hr);
    int st = 0;
    CHECK(send_get(hc, "GET", "/c2", HRW_F, NULL, NULL, 0, &st));
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_HDR(s, 0, "Connection", "Close");
    EXPECT_EQ(srv_conn_count(s), 2);
    U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(hrw_conn2_proxy_connection_header_dropped_direct) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "pc/1", "GET", "/pc", NULL, NULL, NULL, HRW_F, "Proxy-Connection: Keep-Alive\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_NOHDR(w.s, 0, "Proxy-Connection");   /* Win10 VM: dropped on a direct connection */
    hrw_done(&w);
}

/* ------------------------------------------------------------------ timing probe (notes only): where a wire test spends time */
TEST(hrw_zz_phase_timing) {
    HRW_REQUIRE_HTTP();
    for (int round = 0; round < 2; round++) {
        DWORD t0 = GetTickCount();
        srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
        DWORD t1 = GetTickCount();
        hrw w; CHECK(hrw_open(&w, s, "tm/1", "GET", "/tm", NULL, NULL, NULL, HRW_F));
        DWORD t2 = GetTickCount();
        hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok);
        DWORD t3 = GetTickCount();
        hrw_read(&w);
        DWORD t4 = GetTickCount();
        CHECK(srv_wait_requests(s, 1, 3000));
        DWORD t5 = GetTickCount();
        U(InternetCloseHandle)(w.hr); DWORD t6 = GetTickCount();
        U(InternetCloseHandle)(w.hc); DWORD t7 = GetTickCount();
        U(InternetCloseHandle)(w.hi); DWORD t8 = GetTickCount();
        srv_stop(s); DWORD t9 = GetTickCount();
        t_note("round %d ms: srv_start=%lu open=%lu send=%lu read=%lu wait=%lu close_req=%lu close_conn=%lu close_sess=%lu srv_stop=%lu",
               round, t1 - t0, t2 - t1, t3 - t2, t4 - t3, t5 - t4, t6 - t5, t7 - t6, t8 - t7, t9 - t8);
    }
}
