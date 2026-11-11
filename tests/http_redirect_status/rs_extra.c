/* rs_extra.c - review pass 2: 300 method rules, 3xx without Location for non-GET methods, refused ports
 * (IsInappropriateHTTPPort), unreachable targets, what is left on the handle after 12168 and how a resend behaves
 * (HttpSendRequest and HttpSendRequestEx), header handling on the hop (order, Authorization, Cookie), long Locations,
 * callback order on a reused and on a new connection, async chains, and promoted status-line observations.
 * VM_TIMEOUT: 200
 * Decomp: HttpSendRequest_Start@0x72da0 (case 300 with Location -> case 0x12d; budget; fsm+0x138 = FORMS_SUBMIT or the
 *         new method is POST), Redirect@0x12618 (CrackUrl, IsValidHostNameA, scheme 3/4 only, IsInappropriateHTTPPort ->
 *         0x2f7c, CloseConnection before InternetIndicateStatusString(0x6e), Host replaced, 0x20 removed). */
#include "rs.h"

/* ------------------------------------------------------------------ 300 with Location: same rules as 301/302 */
/* decomp: `case 300:` jumps to the 0x12d/0x12e code when the Location list (+0xe38) is not empty */
static void m300(const char *method, int want_kind /* 0 same, 1 GET, 2 confirm */) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 300, "Location: /dst\r\n", "choices");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "p=300";
    int has_body = strcmp(method, "GET") && strcmp(method, "HEAD");
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    if (has_body) { o.data = data; o.ndata = 5; }
    rs_do(s, method, "/src", &o, &r);
    int n = rs_wait(s, want_kind == 2 ? 1 : 2, 2000);
    Sleep(30); n = srv_req_count(s);
    t_note("300 %s: ok=%d err=%lu(%s) status=%lu reqs=%d line1=%s", method, r.ok, r.err, rs_err(r.err), r.status, n,
           n > 1 ? srv_req_line(s, 1) : "-");
    if (want_kind == 2) {
        CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION); EXPECT_EQ(n, 1); EXPECT_EQ(r.status, 300);
    } else {
        CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
        EXPECT_EQ(r.status, 200); EXPECT_EQ(n, 2);
        char want[48]; snprintf(want, sizeof want, "%s /dst HTTP/1.1", want_kind == 1 ? "GET" : method);
        EXPECT_STR(srv_req_line(s, 1), want);
        if (want_kind == 1) CHECK(srv_req_header(s, 1, "Content-Length") == NULL);
    }
    srv_stop(s);
}
TEST(rs_x_300_post_becomes_get) { m300("POST", 1); }
TEST(rs_x_300_head_kept)        { m300("HEAD", 0); }
TEST(rs_x_300_put_confirm)      { m300("PUT", 2); }
TEST(rs_x_300_delete_confirm)   { m300("DELETE", 2); }

/* ------------------------------------------------------------------ 3xx without Location for a POST */
static void post_no_location(int code) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", code, "Content-Type: text/plain\r\n", "nowhere");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char data[] = "q=1";
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.data = data; o.ndata = 3; rs_res r;
    rs_do(s, "POST", "/src", &o, &r);
    Sleep(30);
    int n = srv_req_count(s);
    t_note("%d POST without Location: ok=%d err=%lu(%s) status=%lu reqs=%d nbody=%zu", code, r.ok, r.err, rs_err(r.err), r.status, n, r.nbody);
    EXPECT_EQ(n, 1); EXPECT_EQ(r.status, (DWORD)code);
    size_t bl = 0; const char *b = srv_req_body(s, 0, &bl);
    CHECK(b && bl == 3);
    /* 308 (and 300) need a Location to enter the redirect path; 301/302/303/307 drain and fail in Redirect() with 12150 */
    if (code == 308) { CHECKF(r.ok, "err=%lu", r.err); EXPECT_STR(r.body, "nowhere"); }
    else { CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_HTTP_HEADER_NOT_FOUND); EXPECT_EQ(r.nbody, 0); }
    srv_stop(s);
}
TEST(rs_x_301_post_no_location) { post_no_location(301); }
TEST(rs_x_307_post_no_location) { post_no_location(307); }
TEST(rs_x_308_post_no_location) { post_no_location(308); }

/* ------------------------------------------------------------------ Locations on ports WinINet refuses */
/* Redirect(): IsInappropriateHTTPPort(port) -> 0x2f7c (12156), which the caller turns into success: the 3xx is returned
 * (body already drained), nothing is connected, the URL stays. Ports: 0 19 21 25 110 119 143 220 465 990 993 995. */
static void bad_port(unsigned port) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    char hdr[96]; snprintf(hdr, sizeof hdr, "Location: http://127.0.0.1:%u/x\r\n", port);
    rs_add(&rt, "/src", 302, hdr, "bad-port");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    DWORD t0 = GetTickCount();
    rs_do(s, "GET", "/src", &o, &r);
    DWORD dt = GetTickCount() - t0;
    t_note("Location port %u: ok=%d err=%lu(%s) status=%lu url=%s nbody=%zu redirect_cbs=%d connecting_cbs=%d %lums", port, r.ok, r.err,
           rs_err(r.err), r.status, r.url, r.nbody, rs_cb_count(INTERNET_STATUS_REDIRECT), rs_cb_count(INTERNET_STATUS_CONNECTING_TO_SERVER), dt);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 302);
    EXPECT_EQ(r.nbody, 0);
    EXPECT_STR(r.url, srv_url(s, "/src"));
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 0);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_CONNECTING_TO_SERVER), 1);
    srv_stop(s);
}
TEST(rs_x_port_21_refused)  { bad_port(21); }
TEST(rs_x_port_25_refused)  { bad_port(25); }
TEST(rs_x_port_110_refused) { bad_port(110); }
TEST(rs_x_port_119_refused) { bad_port(119); }
TEST(rs_x_port_143_refused) { bad_port(143); }
TEST(rs_x_port_993_refused) { bad_port(993); }

/* ------------------------------------------------------------------ the target does not listen */
TEST(rs_x_target_port_closed) {
    REQUIRE(U(HttpSendRequestA));
    srv *dead = rs_plain(); if (!dead) { t_skip("server unavailable"); return; }
    unsigned short dport = srv_port(dead); srv_stop(dead);   /* the port is closed now */
    rs_router rt; rs_router_init(&rt); rt.alt_port = dport;
    rs_add(&rt, "/src", 302, "Location: http://127.0.0.1:%A/gone\r\n", "m");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    DWORD t0 = GetTickCount();
    rs_do(s, "GET", "/src", &o, &r);
    char want[96]; snprintf(want, sizeof want, "http://127.0.0.1:%u/gone", dport);
    t_note("closed target: ok=%d err=%lu(%s) status=%lu url=%s %lums", r.ok, r.err, rs_err(r.err), r.status, r.url, GetTickCount() - t0);
    CHECK(!r.ok); EXPECT_EQ(r.err, ERROR_INTERNET_CANNOT_CONNECT);
    EXPECT_STR(r.url, want);                 /* Redirect() moved the handle before the connect */
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}

/* ------------------------------------------------------------------ after 12168: handle state and resends */
static HINTERNET confirm_setup(srv *s, const char *method, HINTERNET *hi, HINTERNET *hc, BOOL *ok, DWORD *e) {
    *hi = t_inet_open(NULL);
    *hc = U(InternetConnectA)(*hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(*hc, method, "/src", NULL, NULL, NULL, RS_FRESH, 0);
    static char data[] = "first-body";
    SET_ERR(0);
    *ok = U(HttpSendRequestA)(hr, NULL, 0, data, 10); *e = GetLastError();
    return hr;
}

TEST(rs_x_confirm_handle_view) {
    REQUIRE(U(HttpSendRequestA)); REQUIRE(U(InternetQueryOptionW));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 307, "Location: /dst\r\nX-Src: 1\r\n", "src-body");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi, hc; BOOL ok; DWORD e;
    HINTERNET hr = confirm_setup(s, "POST", &hi, &hc, &ok, &e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    rs_res r; memset(&r, 0, sizeof r); rs_collect(hr, &r, 1);
    t_note("after 12168: status=%lu location=%s url=%s nbody=%zu read_ok=%d raw=%.60s", r.status, r.location, r.url, r.nbody, r.read_ok, r.raw);
    EXPECT_EQ(r.status, 307);
    EXPECT_STR(r.location, "/dst");
    EXPECT_STR(r.url, srv_url(s, "/dst"));
    CHECK(strstr(r.raw, "X-Src: 1") != NULL);
    EXPECT_EQ(r.nbody, 0);                     /* DrainAndRedirect drained the 307 body before the 12168 */
    WCHAR w[256]; DWORD l = sizeof w;
    CHECK(U(InternetQueryOptionW)(hr, INTERNET_OPTION_URL, w, &l));
    char wa[256]; WideCharToMultiByte(CP_ACP, 0, w, -1, wa, sizeof wa, NULL, NULL);
    EXPECT_STR(wa, srv_url(s, "/dst"));
    char m[16]; l = sizeof m;
    CHECK(U(HttpQueryInfoA)(hr, HTTP_QUERY_REQUEST_METHOD, m, &l, NULL));
    EXPECT_STR(m, "POST");
    Sleep(30); EXPECT_EQ(srv_req_count(s), 1);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* resend after 12168 without optional data: the method stays, no body */
TEST(rs_x_confirm_resend_without_body) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 307, "Location: /dst\r\n", "m");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi, hc; BOOL ok; DWORD e;
    HINTERNET hr = confirm_setup(s, "POST", &hi, &hc, &ok, &e);
    CHECK(!ok); EXPECT_EQ(e, ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    SET_ERR(0);
    ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); e = GetLastError();
    int n = rs_wait(s, 2, 2000);
    t_note("resend without body: ok=%d err=%lu(%s) status=%lu reqs=%d line=%s CL=%s", ok, ok ? 0 : e, rs_err(ok ? 0 : e), rs_status(hr), n,
           n > 1 ? srv_req_line(s, 1) : "-", n > 1 && srv_req_header(s, 1, "Content-Length") ? srv_req_header(s, 1, "Content-Length") : "-");
    CHECKF(ok, "err=%lu %s", e, rs_err(e));
    EXPECT_EQ(rs_status(hr), 200); EXPECT_EQ(n, 2);
    EXPECT_STR(srv_req_line(s, 1), "POST /dst HTTP/1.1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* 12168 from HttpEndRequest, then a second HttpSendRequestEx/InternetWriteFile/HttpEndRequest on the same handle */
TEST(rs_x_confirm_resend_sendex) {
    REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 308, "Location: /dst\r\n", "m");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "POST", "/src", NULL, NULL, NULL, RS_FRESH, 0);
    BOOL okx[2] = { 0 }, okend[2] = { 0 }; DWORD ex[2] = { 0 }, eend[2] = { 0 }, wr[2] = { 0 };
    for (int k = 0; k < 2; k++) {
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 6;
        SET_ERR(0); okx[k] = U(HttpSendRequestExA)(hr, &ib, NULL, 0, 0); ex[k] = okx[k] ? 0 : GetLastError();
        if (!okx[k]) break;
        U(InternetWriteFile)(hr, k ? "again!" : "first!", 6, &wr[k]);
        SET_ERR(0); okend[k] = U(HttpEndRequestA)(hr, NULL, 0, 0); eend[k] = okend[k] ? 0 : GetLastError();
        if (okend[k]) break;
    }
    int n = rs_wait(s, 2, 2000);
    t_note("sendex resend: #1 ex=%d/%lu end=%d/%lu; #2 ex=%d/%lu end=%d/%lu; status=%lu reqs=%d line1=%s", okx[0], ex[0], okend[0], eend[0],
           okx[1], ex[1], okend[1], eend[1], rs_status(hr), n, n > 1 ? srv_req_line(s, 1) : "-");
    CHECK(okx[0]); CHECK(!okend[0]); EXPECT_EQ(eend[0], ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION);
    CHECKF(okx[1], "err=%lu", ex[1]); CHECKF(okend[1], "err=%lu %s", eend[1], rs_err(eend[1]));
    EXPECT_EQ(n, 2);
    EXPECT_STR(srv_req_line(s, 1), "POST /dst HTTP/1.1");
    size_t bl = 0; const char *b = srv_req_body(s, 1, &bl);
    CHECK(b && bl == 6 && !memcmp(b, "again!", 6));
    EXPECT_EQ(rs_status(hr), 200);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* NO_AUTO_REDIRECT: sending the same handle again asks the original URL again (nothing is followed) */
TEST(rs_x_noauto_resend_same_url) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "m");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_NOREDIR, 0);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)); EXPECT_EQ(rs_status(hr), 302);
    char b[32]; t_inet_read_all(hr, b, sizeof b, NULL);
    CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0)); EXPECT_EQ(rs_status(hr), 302);
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_STR(srv_req_target(s, 0), "/src"); EXPECT_STR(srv_req_target(s, 1), "/src");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ request headers on the hop */
TEST(rs_x_hop_caller_header_order) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.hdrs = "X-Alpha: 1\r\nX-Beta: 2\r\nX-Gamma: 3\r\n"; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    for (int i = 0; i < 2; i++) {
        char line[512]; size_t k = 0;
        for (int h = 0; h < srv_req_header_count(s, i) && k < sizeof line - 64; h++) k += snprintf(line + k, sizeof line - k, "%s;", srv_req_header_name(s, i, h));
        line[k] = 0; t_note("req%d header order: %s", i, line);
        int a = srv_req_header_index(s, i, "X-Alpha"), b = srv_req_header_index(s, i, "X-Beta"), c = srv_req_header_index(s, i, "X-Gamma");
        CHECKF(a >= 0 && a < b && b < c, "req%d a=%d b=%d c=%d", i, a, b, c);
        EXPECT_EQ(srv_req_header_occurrences(s, i, "X-Alpha"), 1);
    }
    srv_stop(s);
}

/* Win10 VM boot rs4 (rs_hdr_custom_authorization_on_hop note): a caller Authorization header is not repeated on the hop,
 * a caller Cookie header is */
static void auth_on_hop(int via_addreq, int other_host) {
    REQUIRE(U(HttpAddRequestHeadersA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, other_host ? "Location: http://localhost:%P/dst\r\n" : "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    static const char h[] = "Authorization: Bearer i7-dummy\r\nCookie: manual=2\r\nX-Keep: 1\r\n";
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/src", NULL, NULL, NULL, RS_FRESH, 0);
    if (via_addreq) CHECK(U(HttpAddRequestHeadersA)(hr, h, (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    BOOL ok = U(HttpSendRequestA)(hr, via_addreq ? NULL : h, via_addreq ? 0 : (DWORD)-1, NULL, 0);
    CHECKF(ok, "err=%lu", GetLastError());
    int n = rs_wait(s, 2, 2000);
    const char *a0 = srv_req_header(s, 0, "Authorization"), *a1 = n > 1 ? srv_req_header(s, 1, "Authorization") : NULL;
    const char *c1 = n > 1 ? srv_req_header(s, 1, "Cookie") : NULL;
    t_note("Authorization addreq=%d other_host=%d: req0=%s req1=%s cookie1=%s", via_addreq, other_host, a0 ? a0 : "(none)", a1 ? a1 : "(none)", c1 ? c1 : "(none)");
    EXPECT_EQ(n, 2);
    EXPECT_STR(a0, "Bearer i7-dummy");
    CHECK(a1 == NULL);
    EXPECT_STR(c1, "manual=2");
    EXPECT_STR(n > 1 ? srv_req_header(s, 1, "X-Keep") : NULL, "1");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); srv_stop(s);
}
TEST(rs_x_auth_header_sendreq_same_host)  { auth_on_hop(0, 0); }
TEST(rs_x_auth_header_addreq_same_host)   { auth_on_hop(1, 0); }
TEST(rs_x_auth_header_sendreq_other_host) { auth_on_hop(0, 1); }

/* ------------------------------------------------------------------ long Location */
TEST(rs_x_long_location) {
    REQUIRE(U(HttpSendRequestA));
    static char path[1100], hdr[1200];
    path[0] = '/'; for (int i = 1; i < 900; i++) path[i] = (char)('a' + i % 26); path[900] = 0;
    snprintf(hdr, sizeof hdr, "Location: %s\r\n", path);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 301, hdr, "");
    rs_add(&rt, "*", 200, NULL, "long-landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECKF(r.ok, "err=%lu %s", r.err, rs_err(r.err));
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "long-landed");
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_STR(srv_req_target(s, 1), path);
    static char want[1000]; snprintf(want, sizeof want, "http://%s%s", rs_hp(s), path);   /* srv_url's buffer is shorter */
    EXPECT_STR(r.url, want);
    srv_stop(s);
}

/* ------------------------------------------------------------------ callback order */
static void filtered_seq(char *out, size_t cap) {
    size_t k = 0; out[0] = 0;
    for (int i = 0; i < g_rs_cb.n && k + 8 < cap; i++) {
        DWORD st = g_rs_cb.st[i];
        if (st == 20 || st == 21 || st == 30 || st == 31 || st == 40 || st == 41 || st == 110)
            k += snprintf(out + k, cap - k, "%s%lu", k ? "," : "", st);
    }
}
/* Win10 emits a trailing 40,41 pair for the body read depending on how the body arrives; the pair is optional (seen in 1 of 3 runs absent) */
static int seq_is(const char *seq, const char *want) {
    char t[300];
    if (!strcmp(seq, want)) return 1;
    snprintf(t, sizeof t, "%s,40,41", want);
    return !strcmp(seq, t);
}
/* keep-alive: one connect, REDIRECT between the first RESPONSE_RECEIVED and the second SENDING_REQUEST (Win10 VM rs4:
 * 60,60,80,20,21,30,31,40,41,110,80,30,31,40,41,70,70) */
TEST(rs_x_cb_sequence_reused_connection) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    rs_cb_dump();
    char seq[256]; filtered_seq(seq, sizeof seq);
    CHECK(r.ok);
    CHECKF(seq_is(seq, "20,21,30,31,40,41,110,30,31,40,41"), "seq=%s", seq);
    srv_stop(s);
}
/* Connection: close on the 3xx: Redirect() closes the connection before indicating REDIRECT, the hop connects again */
TEST(rs_x_cb_sequence_new_connection) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, "/src", 302, "Location: /dst\r\n", "", RS_F_CLOSE);
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    rs_cb_dump();
    char seq[256]; filtered_seq(seq, sizeof seq);
    CHECK(r.ok); EXPECT_EQ(srv_conn_count(s), 2);
    CHECKF(seq_is(seq, "20,21,30,31,40,41,110,20,21,30,31,40,41"), "seq=%s", seq);
    srv_stop(s);
}
/* REDIRECT is indicated once per followed hop, also when the 3xx came with a 100 Continue first */
TEST(rs_x_cb_redirect_after_interim) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_addx(&rt, "/src", 303, "Location: /dst\r\n", "", RS_F_100);
    rs_add(&rt, "/dst", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.cb = 1; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    rs_cb_dump();
    CHECK(r.ok); EXPECT_EQ(r.status, 200);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_REDIRECT), 1);
    EXPECT_EQ(rs_cb_count(INTERNET_STATUS_INTERMEDIATE_RESPONSE), 1);
    int im = rs_cb_index(INTERNET_STATUS_INTERMEDIATE_RESPONSE, 0), rd = rs_cb_index(INTERNET_STATUS_REDIRECT, 0);
    CHECKF(im >= 0 && rd > im, "intermediate=%d redirect=%d", im, rd);
    srv_stop(s);
}

/* ------------------------------------------------------------------ async chains */
static struct {
    CRITICAL_SECTION cs; int init; HANDLE ev;
    int n; DWORD st[128]; char redir[4][200]; int nredir; int ncomplete; DWORD_PTR res; DWORD err;
} g_ax;
static void CALLBACK ax_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (ctx != 2) return;
    EnterCriticalSection(&g_ax.cs);
    if (g_ax.n < 128) g_ax.st[g_ax.n++] = st;
    if (st == INTERNET_STATUS_REDIRECT && info && g_ax.nredir < 4) lstrcpynA(g_ax.redir[g_ax.nredir++], (const char *)info, 200);
    if (st == INTERNET_STATUS_REQUEST_COMPLETE && info) {
        g_ax.ncomplete++; g_ax.res = ((INTERNET_ASYNC_RESULT *)info)->dwResult; g_ax.err = ((INTERNET_ASYNC_RESULT *)info)->dwError;
        SetEvent(g_ax.ev);
    }
    LeaveCriticalSection(&g_ax.cs);
}
/* returns 1 when completed; ok and err are the final result */
static int ax_run(srv *s, const char *path, DWORD flags, BOOL *ok, DWORD *err, HINTERNET *keep_hi, HINTERNET *keep_hr) {
    if (!g_ax.init) { InitializeCriticalSection(&g_ax.cs); g_ax.ev = CreateEventA(NULL, TRUE, FALSE, NULL); g_ax.init = 1; }
    EnterCriticalSection(&g_ax.cs);
    g_ax.n = 0; g_ax.nredir = 0; g_ax.ncomplete = 0; g_ax.res = 0; g_ax.err = 0; ResetEvent(g_ax.ev);
    LeaveCriticalSection(&g_ax.cs);
    HINTERNET hi = t_inet_open_ex("rs-ax/1.0", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    if (!hi) return -1;
    U(InternetSetStatusCallbackA)(hi, ax_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, flags, 2);
    SET_ERR(0);
    *ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0); *err = *ok ? 0 : GetLastError();
    int done = 1;
    if (!*ok && *err == ERROR_IO_PENDING) {
        done = WaitForSingleObject(g_ax.ev, 8000) == WAIT_OBJECT_0;
        if (done) { *ok = (BOOL)g_ax.res; *err = *ok ? 0 : g_ax.err; }
    }
    Sleep(100);   /* a second REQUEST_COMPLETE would show up here */
    *keep_hi = hi; *keep_hr = hr;
    (void)hc;
    return done;
}
static void ax_close(HINTERNET hi, HINTERNET hr) {
    U(InternetCloseHandle)(hr);
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi);   /* closes the connect handle too */
    Sleep(50);
}

TEST(rs_x_async_chain_three) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/loop/3", 200, NULL, "end");
    rs_add(&rt, "/loop/*", 307, "Location: /loop/%N\r\n", "");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    BOOL ok; DWORD err; HINTERNET hi = NULL, hr = NULL;
    int done = ax_run(s, "/loop/0", RS_FRESH, &ok, &err, &hi, &hr);
    if (done < 0) { srv_stop(s); t_skip("async session failed"); return; }
    t_note("async chain: done=%d ok=%d err=%lu redirects=%d completes=%d reqs=%d", done, ok, err, g_ax.nredir, g_ax.ncomplete, srv_req_count(s));
    CHECK(done); CHECKF(ok, "err=%lu %s", err, rs_err(err));
    EXPECT_EQ(rs_status(hr), 200);
    EXPECT_EQ(g_ax.nredir, 3); EXPECT_EQ(g_ax.ncomplete, 1);
    for (int k = 0; k < 3 && k < g_ax.nredir; k++) { char p[32]; snprintf(p, sizeof p, "/loop/%d", k + 1); EXPECT_STR(g_ax.redir[k], srv_url(s, p)); }
    /* REQUEST_COMPLETE comes after the last REDIRECT */
    int last_rd = -1, comp = -1;
    for (int i = 0; i < g_ax.n; i++) { if (g_ax.st[i] == INTERNET_STATUS_REDIRECT) last_rd = i; if (g_ax.st[i] == INTERNET_STATUS_REQUEST_COMPLETE && comp < 0) comp = i; }
    CHECKF(last_rd >= 0 && comp > last_rd, "last redirect=%d complete=%d", last_rd, comp);
    ax_close(hi, hr); srv_stop(s);
}

TEST(rs_x_async_noauto) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 301, "Location: /dst\r\n", "m");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    BOOL ok; DWORD err; HINTERNET hi = NULL, hr = NULL;
    int done = ax_run(s, "/src", RS_NOREDIR, &ok, &err, &hi, &hr);
    if (done < 0) { srv_stop(s); t_skip("async session failed"); return; }
    CHECK(done); CHECKF(ok, "err=%lu", err);
    EXPECT_EQ(rs_status(hr), 301);
    EXPECT_EQ(g_ax.nredir, 0); EXPECT_EQ(g_ax.ncomplete, 1);
    EXPECT_EQ(srv_req_count(s), 1);
    ax_close(hi, hr); srv_stop(s);
}

TEST(rs_x_async_no_location) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, NULL, "nowhere");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    BOOL ok; DWORD err; HINTERNET hi = NULL, hr = NULL;
    int done = ax_run(s, "/src", RS_FRESH, &ok, &err, &hi, &hr);
    if (done < 0) { srv_stop(s); t_skip("async session failed"); return; }
    t_note("async 302 without Location: done=%d ok=%d err=%lu(%s)", done, ok, err, rs_err(err));
    CHECK(done); CHECK(!ok); EXPECT_EQ(err, ERROR_HTTP_HEADER_NOT_FOUND);
    EXPECT_EQ(rs_status(hr), 302);
    EXPECT_EQ(g_ax.nredir, 0); EXPECT_EQ(g_ax.ncomplete, 1);
    ax_close(hi, hr); srv_stop(s);
}

TEST(rs_x_async_refused_port) {
    REQUIRE(U(InternetSetStatusCallbackA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: http://127.0.0.1:25/x\r\n", "m");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    BOOL ok; DWORD err; HINTERNET hi = NULL, hr = NULL;
    int done = ax_run(s, "/src", RS_FRESH, &ok, &err, &hi, &hr);
    if (done < 0) { srv_stop(s); t_skip("async session failed"); return; }
    t_note("async port 25 Location: done=%d ok=%d err=%lu(%s) status=%lu", done, ok, err, rs_err(err), rs_status(hr));
    CHECK(done); CHECKF(ok, "err=%lu %s", err, rs_err(err));
    EXPECT_EQ(rs_status(hr), 302);
    EXPECT_EQ(g_ax.nredir, 0); EXPECT_EQ(g_ax.ncomplete, 1);
    ax_close(hi, hr); srv_stop(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl with a cookie on the 302 */
TEST(rs_x_openurl_cookie_on_302) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetGetCookieA));
    char base[96]; snprintf(base, sizeof base, "/%s", t_uniq("ckou"));
    char src[128], dst[128], hdr[300], ckurl[200];
    snprintf(src, sizeof src, "%s/src", base); snprintf(dst, sizeof dst, "%s/dst", base);
    snprintf(hdr, sizeof hdr, "Set-Cookie: rsou=7; Path=%s\r\nLocation: %s\r\n", base, dst);
    snprintf(ckurl, sizeof ckurl, "http://127.0.0.1%s/", base);
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, src, 302, hdr, ""); rs_add(&rt, dst, 200, NULL, "ou-landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    t_cookie_track(ckurl, "rsou");
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, src), NULL, 0, RS_FRESH_COOKIES, 0);
    CHECKF(hu != NULL, "err=%lu", GetLastError());
    if (hu) { EXPECT_EQ(rs_status(hu), 200); U(InternetCloseHandle)(hu); }
    EXPECT_EQ(rs_wait(s, 2, 2000), 2);
    EXPECT_STR(srv_req_header(s, 1, "Cookie"), "rsou=7");
    t_inet_close(hi); t_net_cleanup(); srv_stop(s);
}

/* ------------------------------------------------------------------ redirect target answers HTTP/1.0 */
TEST(rs_x_target_http10_version) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /dst\r\n", "");
    rs_addx(&rt, "/dst", 200, NULL, "ten", RS_F_HTTP10);
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 200); EXPECT_STR(r.version, "HTTP/1.0"); EXPECT_STR(r.body, "ten");
    CHECK(!strncmp(r.raw, "HTTP/1.0 200 OK\r\n", 17));
    srv_stop(s);
}

/* INTERNET_OPTION_URL after a redirect with a buffer that is too small: 122 and the size with the NUL */
TEST(rs_x_url_option_short_buffer_after_redirect) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/src", 302, "Location: /a-rather-longer-destination\r\n", "");
    rs_add(&rt, "/a-rather-longer-destination", 200, NULL, "landed");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/src", &o, &r);
    CHECK(r.ok);
    if (hr) {
        const char *want = srv_url(s, "/a-rather-longer-destination");
        char v[16]; DWORD l = sizeof v; SET_ERR(0);
        EXPECT_FAIL(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, v, &l), ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(l, (DWORD)strlen(want) + 1);
        char big[256]; l = sizeof big;
        CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, big, &l));
        EXPECT_STR(big, want); EXPECT_EQ(l, (DWORD)strlen(want));
    }
    t_inet_close(hi); srv_stop(s);
}

/* ------------------------------------------------------------------ status lines (promoted from rs_line_odd_* notes) */
static void odd_line_exact(const char *line, DWORD want_code, const char *want_text, const char *want_ver) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_route *e = rs_addx(&rt, "/s", 200, NULL, "sl", RS_F_RAWSTATUS | RS_F_CLOSE);
    e->reason = line;
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    /* Win10 VM boot rs4 (t_note in rs_line_odd_*), re-confirmed in this pass */
    CHECKF(r.ok, "err=%lu", r.err);
    EXPECT_EQ(r.status, want_code); EXPECT_STR(r.text, want_text); EXPECT_STR(r.version, want_ver);
    EXPECT_STR(r.body, "sl");
    srv_stop(s);
}
TEST(rs_x_line_two_digit)   { odd_line_exact("HTTP/1.1 99 Short", 99, "Short", "HTTP/1.1"); }
TEST(rs_x_line_four_digit)  { odd_line_exact("HTTP/1.1 2000 Long", 2000, "Long", "HTTP/1.1"); }
TEST(rs_x_line_http2)       { odd_line_exact("HTTP/2 200 OK", 200, "OK", "HTTP/2"); }
TEST(rs_x_line_lowercase)   { odd_line_exact("http/1.1 200 OK", 200, "OK", "http/1.1"); }
TEST(rs_x_line_extra_space) { odd_line_exact("HTTP/1.1  200 OK", 200, "OK", "HTTP/1.1"); }

/* ------------------------------------------------------------------ Retry-After with FLAG_SYSTEMTIME */
TEST(rs_x_retry_after_systemtime) {
    REQUIRE(U(HttpSendRequestA));
    rs_router rt; rs_router_init(&rt);
    rs_add(&rt, "/s", 503, "Retry-After: Wed, 21 Oct 2015 07:28:00 GMT\r\n", "busy");
    srv *s; RS_START(&rt, SRV_HTTP, s);
    rs_opt o = { 0 }; o.flags = RS_FRESH; o.keep_open = 1; HINTERNET hi = NULL, hr = NULL; o.out_hi = &hi; o.out_hreq = &hr; rs_res r;
    rs_do(s, "GET", "/s", &o, &r);
    CHECK(r.ok); EXPECT_EQ(r.status, 503);
    if (hr) {
        SYSTEMTIME st; memset(&st, 0, sizeof st); DWORD l = sizeof st; SET_ERR(0);
        BOOL ok = U(HttpQueryInfoA)(hr, HTTP_QUERY_RETRY_AFTER | HTTP_QUERY_FLAG_SYSTEMTIME, &st, &l, NULL);
        DWORD e = ok ? 0 : GetLastError();
        t_note("RETRY_AFTER|SYSTEMTIME: ok=%d err=%lu %04u-%02u-%02u %02u:%02u:%02u len=%lu", ok, e, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, l);
        CHECK(ok);
        if (ok) { EXPECT_EQ(st.wYear, 2015); EXPECT_EQ(st.wMonth, 10); EXPECT_EQ(st.wDay, 21); EXPECT_EQ(st.wHour, 7); EXPECT_EQ(st.wMinute, 28); }
    }
    t_inet_close(hi); srv_stop(s);
}
