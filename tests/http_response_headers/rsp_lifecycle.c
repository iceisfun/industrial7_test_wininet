/* rsp_lifecycle.c - where response headers live over a request's life: during and after the body read, after a
 * second HttpSendRequest on the same handle, with HttpSendRequestEx/HttpEndRequest, on InternetOpenUrl handles,
 * after an automatic redirect, after a failed send, over HTTPS, on reused keep-alive connections, from another
 * thread, and with several request handles open at once.
 * VM_TIMEOUT: 240
 *
 * [D] HTTP_REQUEST_HANDLE_OBJECT::ReuseObject@0x3ade8 (run when a request handle is sent again) clears the
 * response flags (+0x142c) and calls CHttpHeaders::_Reset on the response header store (+0xc20): a resend must not
 * keep any header of the previous response.
 */
#include "rh.h"

static int q_is(HINTERNET h, DWORD lv, const char *name, const char *want) {
    const char *v = name ? rh_qac(h, name, 0, NULL) : rh_qa(h, lv, NULL);
    if (!want) return !v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND;
    return v && !strcmp(v, want);
}
static int q_note(HINTERNET h, DWORD lv, const char *name, const char *what) {
    const char *v = name ? rh_qac(h, name, 0, NULL) : rh_qa(h, lv, NULL);
    t_note("%s: %s%s%s err=%lu len=%lu", what, v ? "\"" : "", v ? rh_esc(v, strlen(v)) : "(fail)", v ? "\"" : "", rh_err, rh_len);
    return v != NULL;
}

/* SRV_CALL: answer request i (0-based, arrival order) with "X-Round: i+1" and status 200 + i */
static int round_fn(srv_conn *cn, const srv_step *st, void *user) {
    int i = srv_conn_last_req(cn);
    char body[16]; int bn = snprintf(body, sizeof body, "round-%d", i + 1);
    if (i == 0) return srv_conn_sendf(cn, "HTTP/1.1 200 OK\r\nX-Round: %d\r\nX-Only-First: yes\r\nX-Multi: a\r\nX-Multi: b\r\nContent-Length: %d\r\n\r\n%s", i + 1, bn, body) ? -1 : 0;
    return srv_conn_sendf(cn, "HTTP/1.1 %d Round%d\r\nX-Round: %d\r\nX-Multi: c\r\nContent-Length: %d\r\n\r\n%s", 200 + i, i + 1, i + 1, bn, body) ? -1 : 0;
}

static void check_round2(HINTERNET hr) {
    DWORD code = 0; CHECK(rh_qnum(hr, HTTP_QUERY_STATUS_CODE, &code)); EXPECT_EQ(code, 201);
    EXPECT_Q(hr, HTTP_QUERY_STATUS_TEXT, "Round2");
    EXPECT_QC(hr, "X-Round", "2");
    EXPECT_QC(hr, "X-Only-First", NULL);   /* [D ReuseObject -> CHttpHeaders::_Reset] */
    DWORD idx = 1; const char *v = rh_qac(hr, "X-Multi", 0, &idx);
    CHECKF(!v && rh_err == ERROR_HTTP_HEADER_NOT_FOUND, "X-Multi[1] after resend: %s err=%lu", v ? v : "(fail)", rh_err);
    EXPECT_QC(hr, "X-Multi", "c");
    EXPECT_QA(hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 201 Round2\r\nX-Round: 2\r\nX-Multi: c\r\nContent-Length: 7\r\n\r\n");
    char body[32] = { 0 }; size_t n = t_inet_read_all(hr, body, sizeof body, NULL);
    CHECKF(n == 7 && !strcmp(body, "round-2"), "body %s", rh_esc(body, n));
}

TEST(rsp_life_resend_replaces_headers) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_CALL(round_fn), S_LOOP() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "GET", "/round", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_QC(c.hr, "X-Round", "1"); EXPECT_QC(c.hr, "X-Only-First", "yes");
    char body[32]; size_t n = t_inet_read_all(c.hr, body, sizeof body, NULL); EXPECT_EQ(n, 7);
    CHECK(rh_send(&c, NULL, NULL, 0));
    check_round2(c.hr);
    rh_close(&c);
}

/* resend without reading the first body: the old body is drained or the connection dropped; headers are still replaced */
TEST(rsp_life_resend_without_reading_body) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_CALL(round_fn), S_LOOP() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "GET", "/round", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_QC(c.hr, "X-Only-First", "yes");
    CHECK(rh_send(&c, NULL, NULL, 0));
    check_round2(c.hr);
    t_note("connections used for two sends without a read: %d", srv_conn_count(c.s));
    rh_close(&c);
}

/* query state while the body is being read: unchanged before, during and after EOF */
TEST(rsp_life_headers_stable_during_body_read) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY_PATTERN(200, "X-Stable: s\r\nServer: st\r\n", 20000, SRV_R_CONN_CLOSE) };
    if (!rh_start(&c, st, 3)) return;
    if (!rh_open(&c, "GET", "/big", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0)); RH_SENT_OR_FAIL(&c);
    char raw0[2048]; const char *r = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL); lstrcpynA(raw0, r ? r : "", sizeof raw0);
    CHECK(r && strstr(raw0, "X-Stable: s\r\n"));
    static char buf[32768]; DWORD got = 0, total = 0;
    CHECK(U(InternetReadFile)(c.hr, buf, 100, &got)); total += got;
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, raw0);
    EXPECT_QC(c.hr, "X-Stable", "s");
    ULONGLONG cl = 0; CHECK(rh_qnum64(c.hr, HTTP_QUERY_CONTENT_LENGTH, &cl)); EXPECT_EQ(cl, 20000);
    for (int i = 0; i < 1000; i++) { got = 0; if (!U(InternetReadFile)(c.hr, buf, sizeof buf, &got) || !got) break; total += got; }
    EXPECT_EQ(total, 20000);
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, raw0);
    EXPECT_Q(c.hr, HTTP_QUERY_SERVER, "st");
    DWORD code = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &code)); EXPECT_EQ(code, 200);
    /* another EOF read, then query again */
    got = 1; CHECK(U(InternetReadFile)(c.hr, buf, 10, &got)); EXPECT_EQ(got, 0);
    EXPECT_QC(c.hr, "X-Stable", "s");
    rh_close(&c);
}

/* HttpSendRequestEx + InternetWriteFile + HttpEndRequest: the response is queryable after HttpEndRequest */
TEST(rsp_life_send_request_ex_end_request) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(201, "X-Ex: done\r\nLocation: /made\r\n", "ok"), S_CLOSE() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "POST", "/ex", 0)) { rh_close(&c); return; }
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 5;
    CHECK(U(HttpSendRequestExA)(c.hr, &ib, NULL, 0, 0));
    /* between the upload and HttpEndRequest there is no response yet [K]; record what the query says */
    q_note(c.hr, HTTP_QUERY_STATUS_CODE, NULL, "STATUS_CODE before HttpEndRequest");
    q_note(c.hr, 0, "X-Ex", "X-Ex before HttpEndRequest");
    DWORD w = 0; CHECK(U(InternetWriteFile)(c.hr, "12345", 5, &w)); EXPECT_EQ(w, 5);
    CHECK(U(HttpEndRequestA)(c.hr, NULL, 0, 0));
    DWORD code = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &code)); EXPECT_EQ(code, 201);
    EXPECT_QC(c.hr, "X-Ex", "done");
    EXPECT_Q(c.hr, HTTP_QUERY_LOCATION, "/made");
    DWORD reqlen = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_REQUEST_HEADERS, &reqlen)); EXPECT_EQ(reqlen, 5);
    EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD, "POST");
    char body[8] = { 0 }; size_t n = t_inet_read_all(c.hr, body, sizeof body, NULL); EXPECT_STR(body, "ok");
    rh_close(&c);
}

/* InternetOpenUrl returns an HTTP request handle: response and request queries work on it */
TEST(rsp_life_open_url_handle) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, "X-Url: yes\r\nContent-Type: text/x-url\r\n", "u"), S_CLOSE() };
    if (!rh_start(&c, st, 4)) return;
    c.hi = t_inet_open("rh-ou/1.0");
    HINTERNET hu = c.hi ? U(InternetOpenUrlA)(c.hi, srv_url(c.s, "/ou?q=1"), "X-Req: r1\r\n", (DWORD)-1, RH_FLAGS, 0) : NULL;
    CHECKF(hu != NULL, "InternetOpenUrlA err=%lu", GetLastError());
    if (hu) {
        EXPECT_Q(hu, HTTP_QUERY_STATUS_CODE, "200");
        EXPECT_QC(hu, "X-Url", "yes");
        EXPECT_Q(hu, HTTP_QUERY_CONTENT_TYPE, "text/x-url");
        EXPECT_QA(hu, HTTP_QUERY_REQUEST_METHOD, "GET");
        const char *v = rh_qac(hu, "X-Req", HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
        CHECKF(v && !strcmp(v, "r1"), "request X-Req: %s err=%lu", v ? v : "(fail)", rh_err);
        const char *raw = rh_qa(hu, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
        CHECKF(raw && !strncmp(raw, "GET /ou?q=1 HTTP/1.1\r\n", 22), "request raw: %s", raw ? rh_esc(raw, strlen(raw)) : "(fail)");
        if (raw && srv_wait_requests(c.s, 1, 2000)) {
            size_t hn = 0; const char *wire = srv_req_head_raw(c.s, 0, &hn);
            CHECKF(wire && strlen(raw) == hn && !memcmp(raw, wire, hn), "request raw == wire: %s", wire ? rh_esc(wire, hn) : "(none)");
        }
        U(InternetCloseHandle)(hu);
    }
    rh_close(&c);
}

/* automatic redirect: the handle answers with the final response only */
TEST(rsp_life_auto_redirect_final_headers) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c;
    srv_step st[] = { S_HEAD(), S_BODY(), S_FMT("HTTP/1.1 302 Found\r\nLocation: /final\r\nX-First: 1\r\nContent-Length: 0\r\n\r\n"),
                      S_HEAD(), S_BODY(), S_SEND("HTTP/1.1 200 Final\r\nX-Final: 2\r\nContent-Length: 2\r\n\r\nok"), S_CLOSE() };
    if (!rh_start(&c, st, 7)) return;
    if (!rh_open(&c, "GET", "/start", T_INET_FRESH | INTERNET_FLAG_NO_AUTH)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0)); RH_SENT_OR_FAIL(&c);
    DWORD code = 0; CHECK(rh_qnum(c.hr, HTTP_QUERY_STATUS_CODE, &code)); EXPECT_EQ(code, 200);
    EXPECT_Q(c.hr, HTTP_QUERY_STATUS_TEXT, "Final");
    EXPECT_QC(c.hr, "X-Final", "2");
    EXPECT_QC(c.hr, "X-First", NULL);
    EXPECT_QERR2(c.hr, HTTP_QUERY_LOCATION, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 Final\r\nX-Final: 2\r\nContent-Length: 2\r\n\r\n");
    const char *raw = rh_qa(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, NULL);
    CHECKF(raw && !strncmp(raw, "GET /final HTTP/1.1\r\n", 21), "request raw after redirect: %s", raw ? rh_esc(raw, strlen(raw)) : "(fail)");
    EXPECT_EQ(srv_req_count(c.s), 2);
    rh_close(&c);
}

/* failed sends: what the handle answers afterwards */
TEST(rsp_life_after_invalid_response) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!rh_raw(&c, "GET", "", 0)) return;
    CHECK(!c.sent); EXPECT_EQ(c.err, ERROR_HTTP_INVALID_SERVER_RESPONSE);
    q_note(c.hr, HTTP_QUERY_STATUS_CODE, NULL, "STATUS_CODE after 12152");
    q_note(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, "RAW_HEADERS_CRLF after 12152");
    q_note(c.hr, HTTP_QUERY_VERSION, NULL, "VERSION after 12152");
    EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    EXPECT_QC(c.hr, "X-Anything", NULL);
    rh_close(&c);
}

TEST(rsp_life_after_connection_refused) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_CLOSE() };
    if (!rh_start(&c, st, 2)) return;
    unsigned short port = srv_port(c.s);
    srv_stop(c.s); c.s = NULL;   /* nobody listens on the port any more */
    c.hi = t_inet_open("rh-refused/1.0");
    c.hc = c.hi ? U(InternetConnectA)(c.hi, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    c.hr = c.hc ? U(HttpOpenRequestA)(c.hc, "GET", "/x", NULL, NULL, NULL, RH_FLAGS, 0) : NULL;
    if (!c.hr) { CHECKF(0, "open err=%lu", GetLastError()); rh_close(&c); return; }
    rh_send(&c, NULL, NULL, 0);
    CHECK(!c.sent);
    CHECKF(c.err == ERROR_INTERNET_CANNOT_CONNECT, "err=%lu %s", c.err, t_inet_errname(c.err));
    q_note(c.hr, HTTP_QUERY_STATUS_CODE, NULL, "STATUS_CODE after 12029");
    q_note(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, NULL, "RAW_HEADERS_CRLF after 12029");
    EXPECT_QC(c.hr, "Server", NULL);
    EXPECT_QA(c.hr, HTTP_QUERY_REQUEST_METHOD, "GET");
    rh_close(&c);
}

/* a good response followed by a resend that fails: the old headers are gone [D ReuseObject] */
static int good_then_bad(srv_conn *cn, const srv_step *st, void *user) {
    if (srv_conn_last_req(cn) == 0) return srv_conn_sendf(cn, "HTTP/1.1 200 OK\r\nX-Good: 1\r\nContent-Length: 0\r\n\r\n") ? -1 : 0;
    return -1;   /* close without answering */
}
TEST(rsp_life_resend_failure_clears_old_headers) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; srv_step st[] = { S_HEAD(), S_BODY(), S_CALL(good_then_bad), S_LOOP() };
    if (!rh_start(&c, st, 4)) return;
    if (!rh_open(&c, "GET", "/gb", 0)) { rh_close(&c); return; }
    CHECK(rh_send(&c, NULL, NULL, 0));
    EXPECT_QC(c.hr, "X-Good", "1");
    rh_send(&c, NULL, NULL, 0);
    t_note("resend to a server that closes: sent=%d err=%lu %s (conns %d)", c.sent, c.err, t_inet_errname(c.err), srv_conn_count(c.s));
    if (!c.sent) {
        EXPECT_QC(c.hr, "X-Good", NULL);
        q_note(c.hr, HTTP_QUERY_STATUS_CODE, NULL, "STATUS_CODE after failed resend");
    }
    rh_close(&c);
}

/* HTTPS: the parser is the same; check the raw block, trimming, dropping of folded lines, duplicates */
TEST(rsp_life_https_response_headers) {
    REQUIRE(U(HttpQueryInfoA));
    static const srv_step st[] = { S_HEAD(), S_BODY(),
        S_SEND("HTTP/1.1 200 Secure OK\r\nX-Tls:   t  \r\nX-Fold: a\r\n b\r\nx-dup: 1\r\nX-DUP: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\nsec"),
        S_CLOSE() };
    srv *s = srv_https(st, 4, SRV_CERT_LOCALHOST);
    if (!s) { t_skip("HTTPS server unavailable: %s", srv_strerror(srv_last_error())); return; }
    HINTERNET hi = t_inet_open("rh-tls/1.0");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/tls", NULL, NULL, NULL, RH_FLAGS | INTERNET_FLAG_SECURE, 0) : NULL;
    if (!hr) { CHECKF(0, "open err=%lu", GetLastError()); goto out; }
    t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    SetLastError(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    if (!ok && GetLastError() == ERROR_INTERNET_INVALID_CA) { t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA); ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); }
    CHECKF(ok, "https send err=%lu %s", GetLastError(), t_inet_errname(GetLastError()));
    if (ok) {
        EXPECT_Q(hr, HTTP_QUERY_STATUS_TEXT, "Secure OK");
        EXPECT_QC(hr, "X-Tls", "t");
        EXPECT_QC(hr, "X-Fold", "a");
        DWORD idx = 0; const char *v = rh_qac(hr, "x-Dup", 0, &idx); CHECK(v && !strcmp(v, "1"));
        v = rh_qac(hr, "x-Dup", 0, &idx); CHECK(v && !strcmp(v, "2")); EXPECT_EQ(idx, 2);
        EXPECT_QA(hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 Secure OK\r\nX-Tls: t\r\nX-Fold: a\r\nx-dup: 1\r\nX-DUP: 2\r\nContent-Length: 3\r\nConnection: close\r\n\r\n");
        char body[8] = { 0 }; size_t n = t_inet_read_all(hr, body, sizeof body, NULL); CHECKF(n == 3 && !strcmp(body, "sec"), "body %s", rh_esc(body, n));
    }
out:
    if (hr) U(InternetCloseHandle)(hr);
    if (hc) U(InternetCloseHandle)(hc);
    if (hi) U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* keep-alive: two request handles in turn over one connection; each answers its own response */
static int ka_fn(srv_conn *cn, const srv_step *st, void *user) {
    int i = srv_conn_last_req(cn);
    const char *m = srv_req_method(srv_conn_server(cn), i);
    const char *tg = srv_req_target(srv_conn_server(cn), i);
    if (tg && !strcmp(tg, "/head1000")) return srv_conn_sendf(cn, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-Which: head\r\n\r\n") ? -1 : 0;
    if (tg && !strcmp(tg, "/204")) return srv_conn_sendf(cn, "HTTP/1.1 204 No Content\r\nX-Which: 204\r\n\r\n") ? -1 : 0;
    if (tg && !strcmp(tg, "/304")) return srv_conn_sendf(cn, "HTTP/1.1 304 Not Modified\r\nX-Which: 304\r\nETag: \"e\"\r\n\r\n") ? -1 : 0;
    return srv_conn_sendf(cn, "HTTP/1.1 200 OK\r\nX-Which: %s %s #%d\r\nContent-Length: 4\r\n\r\nbody", m ? m : "?", tg ? tg : "?", i) ? -1 : 0;
}
static int ka_start(rh_t *c) {
    srv_step st[] = { S_HEAD(), S_BODY(), S_CALL(ka_fn), S_LOOP() };
    if (!rh_start(c, st, 4)) return 0;
    c->hi = t_inet_open("rh-ka/1.0");
    c->hc = c->hi ? U(InternetConnectA)(c->hi, "127.0.0.1", srv_port(c->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    if (!c->hc) { CHECKF(0, "connect err=%lu", GetLastError()); rh_close(c); return 0; }
    return 1;
}
static HINTERNET ka_req(rh_t *c, const char *verb, const char *path) {
    HINTERNET hr = U(HttpOpenRequestA)(c->hc, verb, path, NULL, NULL, NULL, RH_FLAGS, 0);
    if (!hr) { CHECKF(0, "open %s err=%lu", path, GetLastError()); return NULL; }
    if (!U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)) { CHECKF(0, "send %s err=%lu", path, GetLastError()); U(InternetCloseHandle)(hr); return NULL; }
    return hr;
}
static void ka_pair(const char *verb1, const char *path1, const char *which1, size_t body1) {
    rh_t c; if (!ka_start(&c)) return;
    HINTERNET h1 = ka_req(&c, verb1, path1);
    if (h1) {
        EXPECT_QC(h1, "X-Which", which1);
        char b[64] = { 0 }; size_t n = t_inet_read_all(h1, b, sizeof b, NULL);
        CHECKF(n == body1, "%s %s body %u want %u", verb1, path1, (unsigned)n, (unsigned)body1);
        U(InternetCloseHandle)(h1);
    }
    HINTERNET h2 = ka_req(&c, "GET", "/second");
    if (h2) {
        const char *v = rh_qac(h2, "X-Which", 0, NULL);
        CHECKF(v && !strncmp(v, "GET /second #", 13), "after %s %s: second X-Which %s err=%lu", verb1, path1, v ? v : "(fail)", rh_err);
        EXPECT_QA(h2, HTTP_QUERY_STATUS_TEXT, "OK");
        char b[64] = { 0 }; size_t n = t_inet_read_all(h2, b, sizeof b, NULL); CHECKF(n == 4 && !strcmp(b, "body"), "second body %s", rh_esc(b, n));
        U(InternetCloseHandle)(h2);
    }
    t_note("%s %s then GET: %d connection(s)", verb1, path1, srv_conn_count(c.s));
    rh_close(&c);
}
TEST(rsp_life_keepalive_get_then_get) { REQUIRE(U(HttpQueryInfoA)); ka_pair("GET", "/first", "GET /first #0", 4); }
TEST(rsp_life_keepalive_head_then_get) { REQUIRE(U(HttpQueryInfoA)); ka_pair("HEAD", "/head1000", "head", 0); }
TEST(rsp_life_keepalive_204_then_get) { REQUIRE(U(HttpQueryInfoA)); ka_pair("GET", "/204", "204", 0); }
TEST(rsp_life_keepalive_304_then_get) { REQUIRE(U(HttpQueryInfoA)); ka_pair("GET", "/304", "304", 0); }

/* two request handles with responses held at once: queries are per handle */
TEST(rsp_life_two_handles_independent) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t a, b;
    if (!RH_RAW(&a, "GET", "HTTP/1.1 200 A\r\nX-Who: a\r\nServer: sa\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) return;
    if (!RH_RAW(&b, "GET", "HTTP/1.1 404 B\r\nX-Who: b\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) { rh_close(&a); return; }
    CHECK(a.sent && b.sent);
    for (int round = 0; round < 3; round++) {
        EXPECT_QC(a.hr, "X-Who", "a"); EXPECT_QC(b.hr, "X-Who", "b");
        EXPECT_Q(a.hr, HTTP_QUERY_STATUS_CODE, "200"); EXPECT_Q(b.hr, HTTP_QUERY_STATUS_CODE, "404");
        EXPECT_Q(a.hr, HTTP_QUERY_SERVER, "sa"); EXPECT_QERR2(b.hr, HTTP_QUERY_SERVER, ERROR_HTTP_HEADER_NOT_FOUND);
    }
    rh_close(&a); rh_close(&b);
}

/* a query from a thread other than the one that sent */
typedef struct { HINTERNET h; char v[64]; DWORD err, code; } thr_arg;
static DWORD WINAPI q_thread(void *p) {
    thr_arg *t = p; DWORD n = sizeof t->v;
    lstrcpyA(t->v, "X-Thread");
    t->err = U(HttpQueryInfoA)(t->h, HTTP_QUERY_CUSTOM, t->v, &n, NULL) ? 0 : GetLastError();
    n = sizeof t->code; U(HttpQueryInfoA)(t->h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &t->code, &n, NULL);
    return 0;
}
TEST(rsp_life_query_from_other_thread) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!RH_RAW(&c, "GET", "HTTP/1.1 202 Accepted\r\nX-Thread: other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) return;
    RH_SENT_OR_FAIL(&c);
    thr_arg t; memset(&t, 0, sizeof t); t.h = c.hr;
    HANDLE th = CreateThread(NULL, 0, q_thread, &t, 0, NULL);
    CHECK(th != NULL);
    if (th) { CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0); CloseHandle(th); }
    EXPECT_EQ(t.err, 0); EXPECT_STR(t.v, "other"); EXPECT_EQ(t.code, 202);
    rh_close(&c);
}

/* the connect handle is closed while the request handle is still open */
TEST(rsp_life_query_after_parent_closed) {
    REQUIRE(U(HttpQueryInfoA));
    rh_t c; if (!RH_RAW(&c, "GET", "HTTP/1.1 200 OK\r\nX-P: p\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) return;
    RH_SENT_OR_FAIL(&c);
    EXPECT_QC(c.hr, "X-P", "p");
    U(InternetCloseHandle)(c.hc); c.hc = NULL;
    const char *v = rh_qac(c.hr, "X-P", 0, NULL);
    t_note("query after the connect handle was closed: %s err=%lu", v ? v : "(fail)", rh_err);
    U(InternetCloseHandle)(c.hi); c.hi = NULL;
    v = rh_qac(c.hr, "X-P", 0, NULL);
    t_note("query after the session handle was closed: %s err=%lu", v ? v : "(fail)", rh_err);
    U(InternetCloseHandle)(c.hr); c.hr = NULL;
    rh_close(&c);
}

/* the same response read through HttpQueryInfoA and W, many times: no state is consumed by a query */
TEST(rsp_life_queries_are_repeatable) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!RH_RAW(&c, "GET", "HTTP/1.1 200 OK\r\nX-R: r\r\nX-R: s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) return;
    RH_SENT_OR_FAIL(&c);
    for (int i = 0; i < 25; i++) {
        EXPECT_QC(c.hr, "X-R", "r");
        DWORD idx = 1; const char *v = rh_qwc(c.hr, "X-R", 0, &idx); CHECK(v && !strcmp(v, "s") && idx == 2);
        EXPECT_QA(c.hr, HTTP_QUERY_RAW_HEADERS_CRLF, "HTTP/1.1 200 OK\r\nX-R: r\r\nX-R: s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    }
    rh_close(&c);
}
