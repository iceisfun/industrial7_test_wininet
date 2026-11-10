/* tls_more.c - HTTP semantics over TLS (verbs, status codes, framing, large uploads and headers, concurrency),
 * the INTERNET_FLAG_SECURE placement, cross-scheme redirect flags and option behaviour after the handle is used.
 * Shared schannel server (LOCALHOST profile, 0x100 set on every request). Everything the client sends is checked
 * through the server's recorder, so the expectations equal the plain-HTTP ones of the other areas. */
#include "tls_util.h"

static treq *open_ok(treq *t, srv *s, const char *verb, const char *path, DWORD flags) {
    if (!treq_open(t, "127.0.0.1", srv_port(s), verb, path, T_INET_FRESH | INTERNET_FLAG_SECURE | flags)) return NULL;
    t_https_secflags(t->hr, 0x100);
    return t;
}

/* ------------------------------------------------------------------ verbs and status codes */
typedef struct { const char *verb; int code; const char *body; int has_body; } vrow;
TEST(tls_more_verb_status_table) {
    REQUIRE(U(HttpSendRequestA));
    static const vrow rows[] = {
        { "GET", 200, "get-body", 1 }, { "HEAD", 200, "head-body", 0 }, { "DELETE", 200, "deleted", 1 }, { "OPTIONS", 200, "opts", 1 },
        { "GET", 204, "", 0 }, { "GET", 404, "nf", 1 }, { "GET", 500, "ise", 1 }, { "GET", 403, "forbidden", 1 },
        { "GET", 418, "teapot", 1 }, { "GET", 299, "odd", 1 }, { "PROPFIND", 207, "multi", 1 }, { "GET", 410, "gone", 1 },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        const vrow *v = &rows[i];
        srv_step st[] = { S_HEAD(), { SRV_REPLY, v->body, strlen(v->body), v->code, NULL }, S_END() };
        srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
        treq t;
        if (!open_ok(&t, s, v->verb, "/v", 0)) { treq_close(&t); srv_stop(s); CHECKF(0, "open %s", v->verb); continue; }
        DWORD e = treq_send(&t);
        CHECKF(e == 0, "%s %d: send %lu", v->verb, v->code, e);
        CHECKF(treq_status(&t) == (DWORD)v->code, "%s: status %lu want %d", v->verb, treq_status(&t), v->code);
        char b[64] = ""; size_t n = treq_body(&t, b, sizeof b);
        if (v->has_body) { CHECKF(n == strlen(v->body), "%s %d: body %zu", v->verb, v->code, n); CHECKF(!strcmp(b, v->body), "%s body '%s'", v->verb, b); }
        else CHECKF(n == 0, "%s %d: body %zu bytes", v->verb, v->code, n);
        CHECKF(srv_req_count(s) == 1, "%s requests %d", v->verb, srv_req_count(s));
        if (srv_req_count(s) == 1) {
            char want[64]; snprintf(want, sizeof want, "%s /v HTTP/1.1", v->verb);
            CHECKF(!strcmp(srv_req_line(s, 0), want), "line '%s'", srv_req_line(s, 0));
            const char *h = srv_req_header(s, 0, "Host");
            CHECKF(h && !strcmp(h, srv_hostport(s)), "Host %s", h ? h : "(null)");
        }
        treq_close(&t); srv_stop(s);
    }
}

TEST(tls_more_status_text_and_version) {
    REQUIRE(U(HttpQueryInfoA));
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 201 Made It\r\nContent-Length: 2\r\nX-Tls: yes\r\n\r\nok"), S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/t", 0));
    SEND_OK(&t);
    char b[128]; DWORD l = sizeof b;
    CHECK(U(HttpQueryInfoA)(t.hr, HTTP_QUERY_STATUS_TEXT, b, &l, NULL)); EXPECT_STR(b, "Made It"); EXPECT_EQ(l, 7);
    l = sizeof b; CHECK(U(HttpQueryInfoA)(t.hr, HTTP_QUERY_VERSION, b, &l, NULL)); EXPECT_STR(b, "HTTP/1.1");
    l = sizeof b; CHECK(U(HttpQueryInfoA)(t.hr, HTTP_QUERY_CUSTOM, strcpy(b, "X-Tls"), &l, NULL)); EXPECT_STR(b, "yes");
    l = sizeof b; CHECK(U(HttpQueryInfoA)(t.hr, HTTP_QUERY_CONTENT_LENGTH, b, &l, NULL)); EXPECT_STR(b, "2");
    /* request headers as sent */
    char rq[1024]; l = sizeof rq;
    CHECK(U(HttpQueryInfoA)(t.hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, rq, &l, NULL));
    CHECK(strncmp(rq, "GET /t HTTP/1.1\r\n", 17) == 0);
    char hh[96]; snprintf(hh, sizeof hh, "\r\nHost: %s\r\n", srv_hostport(s));
    CHECK(strstr(rq, hh) != NULL);
    char body[8]; size_t bn = treq_body(&t, body, sizeof body); EXPECT_EQ(bn, 2);
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ uploads over TLS */
TEST(tls_more_post_large_body) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "got"), S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 4); if (!s) TLS_SKIP_SRV();
    size_t n = 300000; char *p = malloc(n);
    for (size_t i = 0; i < n; i++) p[i] = (char)srv_pattern_byte(i);
    treq t; CHECK(open_ok(&t, s, "POST", "/up", 0));
    SetLastError(0xDEAD);
    BOOL ok = U(HttpSendRequestA)(t.hr, "Content-Type: application/octet-stream\r\n", (DWORD)-1, p, (DWORD)n);
    CHECKF(ok, "send %lu", GetLastError());
    EXPECT_EQ(treq_status(&t), 200);
    if (srv_req_count(s) == 1) {
        size_t bn = 0; const char *b = srv_req_body(s, 0, &bn);
        EXPECT_EQ(bn, n);
        CHECK(b && bn == n && srv_pattern_check(b, bn, 0));
        char cl[16]; snprintf(cl, sizeof cl, "%zu", n);
        EXPECT_STR(srv_req_header(s, 0, "Content-Length"), cl);
    } else CHECK(0);
    char r[8]; treq_body(&t, r, sizeof r);
    treq_close(&t); srv_stop(s); free(p);
}

TEST(tls_more_sendrequestex_chunked_upload) {
    REQUIRE(U(HttpSendRequestExA));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "chunks"), S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 4); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "POST", "/ch", 0));
    CHECK(U(HttpAddRequestHeadersA)(t.hr, "Transfer-Encoding: chunked\r\n", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib;
    CHECK(U(HttpSendRequestExA)(t.hr, &ib, NULL, 0, 0));
    static const char *pieces[] = { "5\r\nhello\r\n", "6\r\n world\r\n", "0\r\n\r\n" };
    for (int i = 0; i < 3; i++) { DWORD w = 0; CHECK(U(InternetWriteFile)(t.hr, pieces[i], (DWORD)strlen(pieces[i]), &w)); EXPECT_EQ(w, strlen(pieces[i])); }
    CHECK(U(HttpEndRequestA)(t.hr, NULL, 0, 0));
    EXPECT_EQ(treq_status(&t), 200);
    if (srv_req_count(s) == 1) {
        size_t bn = 0; const char *b = srv_req_body(s, 0, &bn);
        EXPECT_EQ(bn, 11);
        CHECK(b && !memcmp(b, "hello world", 11));
        EXPECT_EQ(srv_req_body_chunked(s, 0), 1);
        EXPECT_STR(srv_req_header(s, 0, "Transfer-Encoding"), "chunked");
        /* Win10: the caller's chunked header does not suppress "Content-Length: 0" from dwBufferTotal (see http_request_wire) */
        EXPECT_STR(srv_req_header(s, 0, "Content-Length"), "0");
    } else CHECK(0);
    char r[16]; treq_body(&t, r, sizeof r);
    treq_close(&t); srv_stop(s);
}

TEST(tls_more_large_request_headers) {
    REQUIRE(U(HttpAddRequestHeadersA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, NULL, "hdr"), S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/h", 0));
    /* 6 headers of 6000 bytes: the head spans several TLS records */
    char *h = malloc(6100);
    for (int i = 0; i < 6; i++) {
        int k = snprintf(h, 64, "X-Big-%d: ", i);
        for (int j = 0; j < 6000; j++) h[k + j] = (char)('A' + (i + j) % 26);
        strcpy(h + k + 6000, "\r\n");
        CHECK(U(HttpAddRequestHeadersA)(t.hr, h, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    }
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 200);
    if (srv_req_count(s) == 1) {
        for (int i = 0; i < 6; i++) {
            char nm[16]; snprintf(nm, sizeof nm, "X-Big-%d", i);
            const char *v = srv_req_header(s, 0, nm);
            CHECKF(v && strlen(v) == 6000, "%s len %zu", nm, v ? strlen(v) : 0);
            if (v) CHECKF(v[0] == (char)('A' + i % 26) && v[5999] == (char)('A' + (i + 5999) % 26), "%s content", nm);
        }
        size_t rn = 0; srv_req_head_raw(s, 0, &rn);
        CHECK(rn > 36000);
    } else CHECK(0);
    char r[8]; treq_body(&t, r, sizeof r);
    free(h); treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ reads */
TEST(tls_more_query_data_available_large) {
    REQUIRE(U(InternetQueryDataAvailable));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 100000, 0), S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/big", 0));
    SEND_OK(&t);
    size_t tot = 0; char *buf = malloc(100000 + 65536); int bad = 0, rounds = 0;
    for (; rounds < 2000; rounds++) {
        DWORD av = 0;
        if (!U(InternetQueryDataAvailable)(t.hr, &av, 0, 0)) { bad = 1; break; }
        if (av == 0) break;
        CHECKF(av <= 100000 - tot, "available %lu > remaining %zu", av, 100000 - tot);
        DWORD got = 0;
        if (av > 65536) av = 65536;
        if (!U(InternetReadFile)(t.hr, buf + tot, av, &got)) { bad = 1; break; }
        if (got != av) t_note("read %lu of %lu available", got, av);
        if (!got) break;
        tot += got;
        if (tot >= 100000) break;
    }
    CHECK(!bad);
    EXPECT_EQ(tot, 100000);
    CHECK(srv_pattern_check(buf, tot, 0));
    DWORD av = 1; CHECK(U(InternetQueryDataAvailable)(t.hr, &av, 0, 0)); EXPECT_EQ(av, 0);
    t_note("100000 bytes over TLS in %d QueryDataAvailable rounds", rounds);
    free(buf); treq_close(&t); srv_stop(s);
}

TEST(tls_more_readfileex_chunks) {
    REQUIRE(U(InternetReadFileExA));
    static const srv_step st[] = { S_HEAD(), { SRV_REPLY, NULL, 50000, 200, NULL, SRV_R_CHUNKED, 777 }, S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/c", 0));
    SEND_OK(&t);
    char *buf = malloc(50000 + 8192); size_t tot = 0;
    for (int i = 0; i < 1000 && tot < 50000; i++) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib;
        ib.lpvBuffer = buf + tot; ib.dwBufferLength = (DWORD)(50000 - tot < 4096 ? 50000 - tot : 4096);
        if (!U(InternetReadFileExA)(t.hr, &ib, IRF_SYNC, 0)) { CHECKF(0, "ReadFileEx %lu", GetLastError()); break; }
        if (!ib.dwBufferLength) break;
        CHECK(ib.dwBufferLength <= 4096);
        tot += ib.dwBufferLength;
    }
    EXPECT_EQ(tot, 50000);
    CHECK(srv_pattern_check(buf, tot, 0));
    free(buf); treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ concurrency: separate sessions on threads */
typedef struct { srv *s; DWORD err; DWORD status; size_t n; } cjob;
static DWORD WINAPI cthread(LPVOID p) {
    cjob *j = p; treq t;
    j->err = 1;
    if (open_ok(&t, j->s, "GET", "/c", 0)) {
        j->err = treq_send(&t);
        if (!j->err) { char b[64]; j->status = treq_status(&t); j->n = treq_body(&t, b, sizeof b); }
    }
    treq_close(&t);
    return 0;
}
TEST(tls_more_concurrent_sessions) {
    REQUIRE(U(HttpSendRequestA));
    /* one server per thread (the request bundles run concurrently; each server sees one request) */
    cjob j[6]; HANDLE th[6]; srv *sv[6];
    for (int i = 0; i < 6; i++) { sv[i] = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!sv[i]) { for (int k = 0; k < i; k++) srv_stop(sv[k]); TLS_SKIP_SRV(); } }
    for (int i = 0; i < 6; i++) { memset(&j[i], 0, sizeof j[i]); j[i].s = sv[i]; th[i] = CreateThread(NULL, 0, cthread, &j[i], 0, NULL); }
    DWORD w = WaitForMultipleObjects(6, th, TRUE, 20000);
    EXPECT_EQ(w, WAIT_OBJECT_0);
    for (int i = 0; i < 6; i++) {
        CHECKF(j[i].err == 0 && j[i].status == 200 && j[i].n == 5, "job %d: err %lu status %lu n %zu", i, j[i].err, j[i].status, j[i].n);
        CloseHandle(th[i]);
    }
    for (int i = 0; i < 6; i++) {
        EXPECT_EQ(srv_req_count(sv[i]), 1);
        EXPECT_EQ(tls_count(sv[i], SRV_EV_TLS_DONE), 1);
        srv_stop(sv[i]);
    }
}

/* ------------------------------------------------------------------ where INTERNET_FLAG_SECURE takes effect */
TEST(tls_more_secure_flag_on_connect_only) {
    REQUIRE(U(InternetConnectA));
    /* INTERNET_FLAG_SECURE passed to InternetConnect (not HttpOpenRequest): observed */
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    HINTERNET hi = t_inet_open("tls-test");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/s", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        DWORD f = 0, l = sizeof f;
        CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &f, &l));
        t_note("connect-level SECURE: request flags 0x%lx", f);
        char url[256]; l = sizeof url;
        if (U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, url, &l)) t_note("connect-level SECURE: URL %s", url);
        t_https_secflags(hr, 0x100);
        SetLastError(0xDEAD);
        BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        DWORD e = ok ? 0 : GetLastError();
        t_note("connect-level SECURE: send ok=%d err=%lu %s TLS handshakes=%d", ok, e, t_inet_errname(e), tls_count(s, SRV_EV_TLS_DONE));
    }
    if (hr) U(InternetCloseHandle)(hr);
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi);
    srv_stop(s);
}

TEST(tls_more_request_flags_option_secure_bit) {
    REQUIRE(U(InternetQueryOptionA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/f", 0));
    DWORD f = 0, l = sizeof f;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_REQUEST_FLAGS, &f, &l));
    t_note("REQUEST_FLAGS before send 0x%lx", f);
    SEND_OK(&t);
    l = sizeof f; CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_REQUEST_FLAGS, &f, &l));
    t_note("REQUEST_FLAGS after send 0x%lx", f);
    char url[256]; l = sizeof url;
    CHECK(U(InternetQueryOptionA)(t.hr, INTERNET_OPTION_URL, url, &l));
    char want[96]; snprintf(want, sizeof want, "https://127.0.0.1:%u/f", srv_port(s));
    EXPECT_STR(url, want);
    char b[8]; treq_body(&t, b, sizeof b);
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ cross-scheme redirect flags */
static void redirect_case(int to_https, DWORD flags, const char *tag) {
    static const srv_step land[] = { S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP() };
    srv *dst = to_https ? tls_srv(SRV_CERT_LOCALHOST, land, 3) : srv_http(land, 3);
    if (!dst) TLS_SKIP_SRV();
    char loc[128]; snprintf(loc, sizeof loc, "Location: %s://127.0.0.1:%u/land\r\n", to_https ? "https" : "http", srv_port(dst));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, NULL }, S_LOOP() };
    st[1].hdrs = loc;
    srv *src = to_https ? srv_http(st, 3) : tls_srv(SRV_CERT_LOCALHOST, st, 3);
    if (!src) { srv_stop(dst); TLS_SKIP_SRV(); }
    treq t;
    CHECK(treq_open(&t, "127.0.0.1", srv_port(src), "GET", "/from", T_INET_FRESH | (to_https ? 0 : INTERNET_FLAG_SECURE) | flags));
    if (!to_https) t_https_secflags(t.hr, 0x100);
    DWORD e = treq_send(&t);
    DWORD st2 = e ? 0 : treq_status(&t);
    t_note("%s flags=0x%lx: err=%lu %s status=%lu dst requests=%d", tag, flags, e, t_inet_errname(e), st2, srv_req_count(dst));
    if (to_https) {
        /* the new https origin starts without 0x100: certificate error, nothing sent to the target */
        EXPECT_EQ(e, ERROR_INTERNET_INVALID_CA);
        EXPECT_EQ(srv_req_count(dst), 0);
    } else {
        EXPECT_EQ(e, 0);
        EXPECT_EQ(st2, 200);
        EXPECT_EQ(srv_req_count(dst), 1);
    }
    char b[32]; if (!e) treq_body(&t, b, sizeof b);
    treq_close(&t); srv_stop(src); srv_stop(dst);
}
TEST(tls_more_redirect_to_https_ignore_flag) { REQUIRE(U(HttpSendRequestA)); redirect_case(1, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, "http->https IGNORE_REDIRECT_TO_HTTPS"); }
TEST(tls_more_redirect_to_http_ignore_flag) { REQUIRE(U(HttpSendRequestA)); redirect_case(0, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP, "https->http IGNORE_REDIRECT_TO_HTTP"); }
TEST(tls_more_redirect_to_http_both_flags) { REQUIRE(U(HttpSendRequestA)); redirect_case(0, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS, "https->http both"); }

TEST(tls_more_redirect_no_auto_redirect) {
    REQUIRE(U(HttpSendRequestA));
    char loc[] = "Location: https://127.0.0.1:1/elsewhere\r\n";
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, loc }, S_END() };
    srv *s = tls_srv(SRV_CERT_LOCALHOST, st, 3); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/r", INTERNET_FLAG_NO_AUTO_REDIRECT));
    SEND_OK(&t);
    EXPECT_EQ(treq_status(&t), 302);
    char b[128] = ""; DWORD l = sizeof b;
    CHECK(U(HttpQueryInfoA)(t.hr, HTTP_QUERY_LOCATION, b, &l, NULL));
    EXPECT_STR(b, "https://127.0.0.1:1/elsewhere");
    treq_close(&t); srv_stop(s);
}

/* ------------------------------------------------------------------ options after close / on a used handle */
TEST(tls_more_secflags_set_after_success_no_effect_on_result) {
    REQUIRE(U(InternetSetOptionA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    treq t; CHECK(open_ok(&t, s, "GET", "/a", 0));
    SEND_OK(&t);
    DWORD f0 = tls_secflags(t.hr);
    CHECK(tls_set_secflags(t.hr, 0x2000));
    DWORD f1 = tls_secflags(t.hr);
    EXPECT_EQ(f1, f0 | 0x2000);
    char b[16]; size_t bn = treq_body(&t, b, sizeof b); EXPECT_EQ(bn, 5);
    treq_close(&t); srv_stop(s);
}

TEST(tls_more_head_then_get_new_requests) {
    REQUIRE(U(HttpSendRequestA));
    srv *s = tls_srv(SRV_CERT_LOCALHOST, NULL, 0); if (!s) TLS_SKIP_SRV();
    static const char *verbs[] = { "HEAD", "GET", "HEAD", "GET" };
    for (int i = 0; i < 4; i++) {
        treq t; CHECK(open_ok(&t, s, verbs[i], "/hg", 0));
        SEND_OK(&t);
        EXPECT_EQ(treq_status(&t), 200);
        char b[16]; size_t n = treq_body(&t, b, sizeof b);
        CHECKF(n == (strcmp(verbs[i], "HEAD") ? 5u : 0u), "%s body %zu", verbs[i], n);
        treq_close(&t);
    }
    EXPECT_EQ(srv_req_count(s), 4);
    for (int i = 0; i < 4 && i < srv_req_count(s); i++) EXPECT_STR(srv_req_method(s, i), verbs[i]);
    srv_stop(s);
}
