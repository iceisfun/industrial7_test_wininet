/* ac_misc.c - async InternetOpenUrl, redirects (REDIRECT 110), cookies (320/321), 1xx responses (120), auth
 * challenges, closing handles with operations pending, HttpSendRequestEx / InternetWriteFile / HttpEndRequest in
 * async mode, FTP connect in async mode, HTTPS. */
#include "ac.h"

static const DWORD SKIP_NOISE[] = { INTERNET_STATUS_HANDLE_CREATED, INTERNET_STATUS_HANDLE_CLOSING, AC_ST_330,
                                    INTERNET_STATUS_COOKIE_SENT, INTERNET_STATUS_COOKIE_RECEIVED, INTERNET_STATUS_DETECTING_PROXY, 0 };

/* ------------------------------------------------------------------ InternetOpenUrl */
TEST(ac_openurl_async_pending_and_handle) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/ou"), NULL, 0, T_INET_FRESH, CTX_URL);
    DWORD e = GetLastError();
    EXPECT_EQ(hu, NULL);
    EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    HINTERNET hres = (HINTERNET)r.dwResult;
    CHECK(hres != NULL);
    EXPECT_EQ(r.dwError, 0);
    int ic = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_URL, 0); ac_ev ev;
    CHECK(ic >= 0);
    if (ic >= 0 && ac_get(ic, &ev)) {
        EXPECT_EQ((HINTERNET)ac_info_ptr(&ev), hres);
        /* [W10] the URL handle is created by the worker, not before InternetOpenUrl returns */
        CHECK(ev.tid != ac_main_tid);
    }
    int irc = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_URL, 0);
    if (irc >= 0 && ac_get(irc, &ev)) { EXPECT_EQ(ev.h, hi); t_note("openurl REQUEST_COMPLETE h=%p (session %p, url %p)", ev.h, hi, hres); }
    ac_quiesce(100, 400);
    t_note("openurl sequence: %s", ac_seq(0, NULL));
    ac_dump("openurl");
    if (hres) {
        EXPECT_EQ(ac_status_code(hres), 200);
        char b[16]; int np;
        EXPECT_EQ(ac_read_all_async(hres, CTX_URL, b, sizeof b, &np), 5);
        EXPECT_STR(b, "hello");
        ac_close_wait(hres, CTX_URL);
    }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
TEST(ac_openurl_async_sequence) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/ou"), NULL, 0, T_INET_FRESH, CTX_URL);
    INTERNET_ASYNC_RESULT r;
    CHECK(hu == NULL);
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    ac_quiesce(100, 400);
    /* everything carries the InternetOpenUrl context; the result handle is created first.
     * [W10] round 3: InternetOpenUrl to the 127.0.0.1 literal reported RESOLVING_NAME/NAME_RESOLVED (10,11) right
     * after DETECTING_PROXY on one boot and not on the others (resolver-cache state): accepted only as that pair. */
    const char *sq = ac_seq(0, NULL);
    t_note("openurl async sequence: %s", sq);
    CHECKF(!strcmp(sq, "60,80,20,21,30,31,40,41,100") || !strcmp(sq, "60,80,10,11,20,21,30,31,40,41,100"), "seq %s", sq);
    CHECK(ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_URL, 0) == 0);
    for (int i = 0; i < ac_count(); i++) { ac_ev ev; ac_get(i, &ev); CHECKF(ev.ctx == CTX_URL, "event %d ctx %llx st %lu", i, (unsigned long long)ev.ctx, ev.st); }
    if (r.dwResult) ac_close_wait((HINTERNET)r.dwResult, CTX_URL);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
TEST(ac_openurl_async_connect_refused) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    char url[128]; snprintf(url, sizeof url, "%s", srv_url(s, "/dead"));
    srv_stop(s);
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlA)(hi, url, NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_URL, 1, 8000, &r));
    EXPECT_EQ(r.dwResult, 0);
    EXPECT_EQ(r.dwError, ERROR_INTERNET_CANNOT_CONNECT);
    ac_quiesce(200, 800);
    t_note("openurl refused: %s", ac_seq(0, NULL));
    /* [W10] the internal handle is closed (70) before the failure is reported (100) */
    EXPECT_STR(ac_seq(0, NULL), "60,80,20,70,100");
    /* the handle created for the request is closed internally */
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_URL), ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_URL));
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
/* [W10] an unparsable URL is reported through the completion, not synchronously; "" fails with 87 up front */
TEST(ac_openurl_async_bad_url) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    static const char *bad[] = { "notaurl", "zz://127.0.0.1/" };
    for (unsigned i = 0; i < 2; i++) {
        ac_begin();
        HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
        SetLastError(0xdeadbeef);
        HINTERNET hu = U(InternetOpenUrlA)(hi, bad[i], NULL, 0, T_INET_FRESH, CTX_URL);
        DWORD e = GetLastError();
        EXPECT_EQ(hu, NULL);
        EXPECT_EQ(e, ERROR_IO_PENDING);
        INTERNET_ASYNC_RESULT r;
        CHECK(ac_wait_complete(CTX_URL, 1, 5000, &r));
        ac_quiesce(100, 300);
        t_note("openurl('%s') async: completion %llu/%lu (%s) seq=%s", bad[i], (unsigned long long)r.dwResult, r.dwError, t_inet_errname(r.dwError), ac_seq(0, NULL));
        EXPECT_EQ(r.dwResult, 0);
        EXPECT_EQ(r.dwError, ERROR_INTERNET_UNRECOGNIZED_SCHEME);
        EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 1);
        U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    }
}
TEST(ac_openurl_async_empty_url) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlA)(hi, "", NULL, 0, T_INET_FRESH, CTX_URL);
    EXPECT_EQ(hu, NULL);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count(), 0);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_openurl_sync_with_callback) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/sync"), NULL, 0, T_INET_FRESH, CTX_URL);
    CHECK(hu != NULL);
    int ic = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_URL, 0); ac_ev ev;
    if (ic >= 0 && ac_get(ic, &ev)) EXPECT_EQ((HINTERNET)ac_info_ptr(&ev), hu); else CHECK(ic >= 0);
    t_note("sync openurl: %s", ac_seq(0, NULL));
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    EXPECT_EQ(ac_count_not_tid(0, ac_main_tid), 0);
    EXPECT_STR(ac_seq(0, NULL), "60,80,20,21,30,31,40,41");
    if (hu) ac_close_wait(hu, CTX_URL);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
TEST(ac_openurl_async_context_zero) {
    REQ_ASYNC_API(); REQUIRE(U(InternetOpenUrlA));
    srv *s; SRV_OR_SKIP(s, srv_http(NULL, 0));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hu = U(InternetOpenUrlA)(hi, srv_url(s, "/z"), NULL, 0, T_INET_FRESH, 0);
    DWORD e = GetLastError();
    t_note("async openurl ctx 0: h=%p err=%lu", hu, e);
    CHECK(srv_wait_requests(s, 1, 3000));
    ac_quiesce(200, 1000);
    EXPECT_EQ(ac_count(), 0);
    if (hu) U(InternetCloseHandle)(hu);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* ------------------------------------------------------------------ redirects */
TEST(ac_redirect_status_and_url) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/src", T_INET_FRESH)) return;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(pending, 1);
    EXPECT_EQ(ac_status_code(f.hr), 200);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REDIRECT, CTX_REQ), 1);
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_REQ, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        char want[128]; snprintf(want, sizeof want, "http://127.0.0.1:%u/dst", srv_port(f.s));
        CHECK(ev.has_info);
        EXPECT_STR((char *)ev.info, want);
        EXPECT_EQ(ev.len, strlen(want) + 1);
    }
    t_note("redirect sequence: %s", ac_seq(CTX_REQ, NULL));
    CHECK(ac_before(INTERNET_STATUS_RESPONSE_RECEIVED, INTERNET_STATUS_REDIRECT, CTX_REQ));
    CHECK(ac_before(INTERNET_STATUS_REDIRECT, INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np), 6);
    ac_flow_close(&f);
}
TEST(ac_redirect_sequence_exact) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "landed"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/src", T_INET_FRESH)) return;
    int pending; DWORD err;
    int n0 = ac_count();
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 400);
    /* [W10] the redirect re-runs proxy detection (80) and reuses the kept-alive connection */
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,110,80,30,31,40,41,100");
    CHECK(srv_wait_requests(f.s, 2, 2000));
    EXPECT_EQ(srv_req_conn(f.s, 1), srv_req_conn(f.s, 0));
    ac_flow_close(&f);
}
TEST(ac_redirect_w_callback_url_wide) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /wdst\r\n", ""), S_HEAD(), S_REPLY(200, NULL, "w"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, NULL, "GET", "/w", T_INET_FRESH)) return;
    U(InternetSetStatusCallbackW)(f.hr, ac_cbw);
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    int i = ac_find(INTERNET_STATUS_REDIRECT, CTX_REQ, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) {
        WCHAR want[128]; swprintf(want, 128, L"http://127.0.0.1:%u/wdst", srv_port(f.s));
        CHECK(ev.has_info && !lstrcmpW((WCHAR *)ev.info, want));
        EXPECT_EQ(ev.len, (DWORD)lstrlenW(want));   /* [W10] W: characters, no NUL */
    } else CHECK(i >= 0);
    ac_flow_close(&f);
}
TEST(ac_redirect_no_auto_redirect) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(302, "Location: /dst\r\n", ""), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/src", T_INET_FRESH_NOREDIR)) return;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(ac_status_code(f.hr), 302);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REDIRECT), 0);
    ac_flow_close(&f);
}
TEST(ac_redirect_cross_port_new_connection) {
    REQ_ASYNC_API();
    srv *dst; SRV_OR_SKIP(dst, srv_http(NULL, 0));
    char loc[128]; snprintf(loc, sizeof loc, "Location: http://127.0.0.1:%u/there\r\n", srv_port(dst));
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "", 0, 302, loc }, S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/here", T_INET_FRESH)) { srv_stop(dst); return; }
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_quiesce(100, 400);
    const char *s = ac_seq_range(CTX_REQ, n0, -1, SKIP_NOISE);
    t_note("cross-port redirect: %s", ac_seq_range(CTX_REQ, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,110,80,20,21,30,31,40,41,100");
    ac_flow_close(&f);
    srv_stop(dst);
}

/* ------------------------------------------------------------------ cookies */
#define COOKIE_FLAGS (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_NO_UI)
TEST(ac_cookie_received_and_sent) {
    REQ_ASYNC_API();
    const char *path = t_uniq("ck");
    char p1[128], sc[256];
    snprintf(p1, sizeof p1, "/%s/a", path);
    snprintf(sc, sizeof sc, "Set-Cookie: acck=v1; Path=/%s\r\n", path);
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "c", 1, 200, sc }, S_HEAD(), S_REPLY(200, NULL, "d"), S_LOOP_TO(2) };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "GET", p1, COOKIE_FLAGS)) return;
    char curl[160]; snprintf(curl, sizeof curl, "http://127.0.0.1/%s/", path);
    t_cookie_track(curl, "acck");
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    t_note("set-cookie response statuses: %s", ac_seq_range(0, n0, -1, NULL));
    ac_dump("cookie1");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_COOKIE_RECEIVED, CTX_REQ), 1);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,321,100");
    int ir = ac_find(INTERNET_STATUS_COOKIE_RECEIVED, CTX_REQ, n0); ac_ev ev;
    if (ir >= 0 && ac_get(ir, &ev)) {
        ac_in_cookie_state cs; memcpy(&cs, ev.info, sizeof cs);
        EXPECT_EQ(ev.len, sizeof(ac_in_cookie_state));
        EXPECT_EQ(cs.cSession, 1); EXPECT_EQ(cs.cPersistent, 0); EXPECT_EQ(cs.cAccepted, 1);
        EXPECT_EQ(cs.cLeashed, 0); EXPECT_EQ(cs.cDowngraded, 0); EXPECT_EQ(cs.cBlocked, 0);
    }
    char b[8]; int np; ac_read_all_async(f.hr, CTX_REQ, b, sizeof b, &np);
    ac_close_wait(f.hr, CTX_REQ);
    f.hr = U(HttpOpenRequestA)(f.hc, "GET", p1, NULL, NULL, NULL, COOKIE_FLAGS, CTX_REQ);
    CHECK(f.hr != NULL); if (!f.hr) { ac_flow_close(&f); return; }
    int n1 = ac_count();
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    CHECK(srv_wait_requests(f.s, 2, 2000));
    EXPECT_STR(srv_req_header(f.s, 1, "Cookie"), "acck=v1");
    ac_quiesce(100, 300);
    t_note("cookie request statuses: %s", ac_seq_range(0, n1, -1, NULL));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_COOKIE_SENT, CTX_REQ), 1);
    /* [W10] COOKIE_SENT comes while the request is built, before SENDING_REQUEST (kept-alive connection: no 20/21) */
    EXPECT_STR(ac_seq_range(0, n1, -1, NULL), "80,320,30,31,40,41,100");
    int is = ac_find(INTERNET_STATUS_COOKIE_SENT, CTX_REQ, n1);
    if (is >= 0 && ac_get(is, &ev)) {
        ac_out_cookie_state os; memcpy(&os, ev.info, sizeof os);
        t_note("COOKIE_SENT len=%lu cSent=%d cSuppressed=%d", ev.len, os.cSent, os.cSuppressed);
        EXPECT_EQ(ev.len, sizeof(ac_out_cookie_state));
        EXPECT_EQ(os.cSent, 1); EXPECT_EQ(os.cSuppressed, 0);
    }
    ac_flow_close(&f);
}
TEST(ac_cookie_no_cookies_flag_silent) {
    REQ_ASYNC_API();
    const char *path = t_uniq("nck");
    char p1[128], sc[256];
    snprintf(p1, sizeof p1, "/%s/a", path);
    snprintf(sc, sizeof sc, "Set-Cookie: acnk=v1; Path=/%s\r\n", path);
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "c", 1, 200, sc }, S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", p1, T_INET_FRESH)) return;
    char curl[160]; snprintf(curl, sizeof curl, "http://127.0.0.1/%s/", path);
    t_cookie_track(curl, "acnk");
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_COOKIE_RECEIVED), 0);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_COOKIE_SENT), 0);
    ac_flow_close(&f);
}
TEST(ac_cookie_info_payload) {
    REQ_ASYNC_API();
    const char *path = t_uniq("ckp");
    char p1[128], sc[256];
    snprintf(p1, sizeof p1, "/%s/a", path);
    snprintf(sc, sizeof sc, "Set-Cookie: acp1=1; Path=/%s\r\nSet-Cookie: acp2=2; Path=/%s\r\n", path, path);
    srv_step st[] = { S_HEAD(), { SRV_REPLY, "c", 1, 200, sc }, S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", p1, COOKIE_FLAGS)) return;
    char curl[160]; snprintf(curl, sizeof curl, "http://127.0.0.1/%s/", path);
    t_cookie_track(curl, "acp1"); t_cookie_track(curl, "acp2");
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    ac_quiesce(100, 300);
    int i = ac_find(INTERNET_STATUS_COOKIE_RECEIVED, CTX_REQ, 0); ac_ev ev;
    /* [W10] one COOKIE_RECEIVED per response, counting every cookie it set */
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_COOKIE_RECEIVED, CTX_REQ), 1);
    if (i >= 0 && ac_get(i, &ev)) {
        ac_in_cookie_state cs; memcpy(&cs, ev.info, sizeof cs);
        EXPECT_EQ(cs.cSession, 2); EXPECT_EQ(cs.cAccepted, 2); EXPECT_EQ(cs.cPersistent, 0); EXPECT_EQ(cs.cBlocked, 0);
    } else CHECK(i >= 0);
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ 1xx / auth */
TEST(ac_intermediate_response_100) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_SEND("HTTP/1.1 100 Continue\r\n\r\n"), S_REPLY(200, NULL, "ok"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 5, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/c", T_INET_FRESH)) return;
    static char data[] = "xyz";
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, data, 3, &pending, &err));
    EXPECT_EQ(ac_status_code(f.hr), 200);
    ac_quiesce(100, 300);
    t_note("100-continue statuses: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_INTERMEDIATE_RESPONSE, CTX_REQ), 1);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,120,40,41,100");
    int i = ac_find(INTERNET_STATUS_INTERMEDIATE_RESPONSE, CTX_REQ, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) { t_note("INTERMEDIATE len=%lu dword=%lu", ev.len, ac_info_dword(&ev)); EXPECT_EQ(ac_info_dword(&ev), 100); }
    ac_flow_close(&f);
}
TEST(ac_auth_401_no_credentials) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "no"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/auth", T_INET_FRESH)) return;
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(ac_status_code(f.hr), 401);
    ac_quiesce(100, 300);
    t_note("401 statuses: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    ac_flow_close(&f);
}
TEST(ac_auth_401_basic_with_credentials) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "no"), S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    srv *s; SRV_OR_SKIP(s, srv_http(st, 5));
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), "user", "dummy", INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/auth", NULL, NULL, NULL, T_INET_FRESH, CTX_REQ);
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    DWORD code = ac_status_code(hr);
    ac_quiesce(100, 300);
    t_note("401+creds: status %lu requests %d statuses %s", code, srv_req_count(s), ac_seq_range(0, n0, -1, NULL));
    EXPECT_EQ(code, 200);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ), 1);
    CHECK(srv_wait_requests(s, 2, 2000));
    const char *a = srv_req_header(s, 1, "Authorization");
    CHECK(a && !strcmp(a, "Basic dXNlcjpkdW1teQ=="));
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}

/* ------------------------------------------------------------------ closing with operations pending */
TEST(ac_close_request_send_pending) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late") };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/pend", T_INET_FRESH)) return;
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    CHECK(srv_wait_requests(f.s, 1, 3000));
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    CHECK(U(InternetCloseHandle)(f.hr));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 5000));
    ac_quiesce(200, 1500);
    t_note("close with send pending: %s", ac_seq_range(0, n0, -1, NULL));
    /* [W10] the connection is torn down, the send completes with 12017, then HANDLE_CLOSING */
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "50,51,100,70");
    ac_dump("close-pending");
    int ic = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0), ih = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0);
    if (ic >= 0) {
        ac_ev ev; ac_get(ic, &ev); INTERNET_ASYNC_RESULT res; memcpy(&res, ev.info, sizeof res);
        t_note("pending send completed: dwResult=%llu dwError=%lu (%s)", (unsigned long long)res.dwResult, res.dwError, t_inet_errname(res.dwError));
        EXPECT_EQ(res.dwResult, FALSE);
        EXPECT_EQ(res.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
        CHECKF(ic < ih, "REQUEST_COMPLETE@%d before HANDLE_CLOSING@%d", ic, ih);
    } else CHECKF(ic >= 0, "pending send completes when its handle is closed");
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    f.hr = NULL;
    ac_flow_close(&f);
}
TEST(ac_close_request_read_pending) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SEND("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"), S_SLEEP(3000), S_SEND("hello") };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/rp", T_INET_FRESH)) return;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    static char b[16]; static DWORD rd;
    SetLastError(0xdeadbeef);
    BOOL ok = U(InternetReadFile)(f.hr, b, sizeof b, &rd);
    EXPECT_EQ(ok, FALSE); EXPECT_ERR(ERROR_IO_PENDING);
    int n0 = ac_count();
    CHECK(U(InternetCloseHandle)(f.hr));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 5000));
    ac_quiesce(200, 1500);
    t_note("close with read pending: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "50,51,100,70");
    int ic = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0), ih = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0);
    if (ic >= 0) {
        ac_ev ev; ac_get(ic, &ev); INTERNET_ASYNC_RESULT res; memcpy(&res, ev.info, sizeof res);
        t_note("pending read completed: dwResult=%llu dwError=%lu (%s)", (unsigned long long)res.dwResult, res.dwError, t_inet_errname(res.dwError));
        EXPECT_EQ(res.dwResult, FALSE);
        EXPECT_EQ(res.dwError, ERROR_INTERNET_OPERATION_CANCELLED);
        CHECK(ic < ih);
    } else CHECKF(ic >= 0, "pending read completes when its handle is closed");
    f.hr = NULL;
    ac_flow_close(&f);
}
TEST(ac_close_session_with_send_pending) {
    REQ_ASYNC_API();
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late") };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 3, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/sp", T_INET_FRESH)) return;
    BOOL r = U(HttpSendRequestA)(f.hr, NULL, 0, NULL, 0);
    EXPECT_EQ(r, FALSE);
    CHECK(srv_wait_requests(f.s, 1, 3000));
    int n0 = ac_count();
    CHECK(U(InternetCloseHandle)(f.hi));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 5000));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 5000));
    ac_quiesce(200, 1500);
    t_note("close session with send pending: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "50,51,100,70,70");
    int icp = ac_find(INTERNET_STATUS_REQUEST_COMPLETE, CTX_REQ, n0); ac_ev evp;
    if (icp >= 0 && ac_get(icp, &evp)) { INTERNET_ASYNC_RESULT rr; memcpy(&rr, evp.info, sizeof rr); EXPECT_EQ(rr.dwResult, 0); EXPECT_EQ(rr.dwError, ERROR_INTERNET_OPERATION_CANCELLED); }
    int ir = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0), ic = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, n0);
    CHECK(ir >= 0 && ic >= 0 && ir < ic);
    f.hr = f.hc = f.hi = NULL;
    ac_flow_close(&f);
}
TEST(ac_close_after_complete_no_extra) {
    REQ_ASYNC_API();
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, NULL, 0, INTERNET_FLAG_ASYNC, ac_cb, "GET", "/ok", T_INET_FRESH)) return;
    int pending; DWORD err;
    CHECK(ac_send_wait(f.hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    int c = ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE);
    ac_close_wait(f.hr, CTX_REQ); f.hr = NULL;
    ac_quiesce(100, 400);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), c);
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ HttpSendRequestEx / InternetWriteFile / HttpEndRequest */
TEST(ac_sendex_write_end_async) {
    REQ_ASYNC_API(); REQUIRE(U(HttpSendRequestExA)); REQUIRE(U(HttpEndRequestA)); REQUIRE(U(InternetWriteFile));
    static const srv_step st[] = { S_HEAD(), S_BODY(), S_REPLY(200, NULL, "got"), S_LOOP() };
    ac_begin(); ac_flow f;
    if (!ac_flow_open(&f, st, 4, INTERNET_FLAG_ASYNC, ac_cb, "POST", "/ex", T_INET_FRESH)) return;
    static INTERNET_BUFFERSA ib;
    memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.dwBufferTotal = 6;
    int c = 0; INTERNET_ASYNC_RESULT r;
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    BOOL ok = U(HttpSendRequestExA)(f.hr, &ib, NULL, 0, 0);
    DWORD e = GetLastError();
    t_note("HttpSendRequestEx async: ok=%d err=%lu", ok, e);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    t_note("after SendRequestEx: %s", ac_seq_range(0, n0, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,100");
    static DWORD wr; static char d1[] = "abc", d2[] = "def";
    for (int k = 0; k < 2; k++) {
        wr = 0xdeadbeef;
        SetLastError(0xdeadbeef);
        ok = U(InternetWriteFile)(f.hr, k ? d2 : d1, 3, &wr);
        e = GetLastError();
        t_note("InternetWriteFile[%d] async: ok=%d err=%lu wr=%lu", k, ok, e, wr);
        if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
        /* [W10] small writes complete synchronously even in an async session */
        CHECK(ok);
        EXPECT_EQ(wr, 3);
    }
    int n1 = ac_count();
    SetLastError(0xdeadbeef);
    ok = U(HttpEndRequestA)(f.hr, NULL, 0, 0);
    e = GetLastError();
    t_note("HttpEndRequest async: ok=%d err=%lu", ok, e);
    EXPECT_EQ(ok, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    if (!ok && e == ERROR_IO_PENDING) { CHECK(ac_wait_complete(CTX_REQ, ++c, 5000, &r)); EXPECT_EQ(r.dwResult, TRUE); }
    ac_quiesce(100, 300);
    t_note("after EndRequest: %s", ac_seq_range(0, n1, -1, NULL));
    EXPECT_STR(ac_seq_range(0, n1, -1, NULL), "40,41,100");
    EXPECT_EQ(ac_status_code(f.hr), 200);
    CHECK(srv_wait_requests(f.s, 1, 2000));
    size_t bn; const char *b = srv_req_body(f.s, 0, &bn);
    CHECK(b && bn == 6 && !memcmp(b, "abcdef", 6));
    ac_flow_close(&f);
}

/* ------------------------------------------------------------------ FTP in async mode */
TEST(ac_ftp_connect_async) {
    REQ_ASYNC_API();
    static const srv_ftp_file files[] = { { "/a.txt", "ftpdata", 7, NULL } };
    srv_ftp_config fc = { files, 1 };
    srv_config cfg = { SRV_FTP }; cfg.ftp = &fc; srv *s;
    START_OR_SKIP(&cfg, &s);
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, CTX_CON);
    DWORD e = GetLastError();
    t_note("async FTP connect: h=%p err=%lu", hc, e);
    EXPECT_EQ(hc, NULL); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_CON, 1, 8000, &r));
    HINTERNET h = (HINTERNET)r.dwResult;
    CHECK(h != NULL); EXPECT_EQ(r.dwError, 0);
    ac_quiesce(100, 300);
    t_note("ftp connect statuses: %s", ac_seq(0, NULL));
    int i = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_CON, 0); ac_ev ev;
    if (i >= 0 && ac_get(i, &ev)) EXPECT_EQ((HINTERNET)ac_info_ptr(&ev), h); else CHECK(i >= 0);
    CHECK(ac_before(INTERNET_STATUS_HANDLE_CREATED, INTERNET_STATUS_REQUEST_COMPLETE, CTX_CON));
    if (h) ac_close_wait(h, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
TEST(ac_ftp_connect_async_refused) {
    REQ_ASYNC_API();
    srv_config cfg = { SRV_FTP }; srv *s;
    START_OR_SKIP(&cfg, &s);
    unsigned short port = srv_port(s);
    srv_stop(s);
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    SetLastError(0xdeadbeef);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, CTX_CON);
    EXPECT_EQ(hc, NULL); EXPECT_ERR(ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT r;
    CHECK(ac_wait_complete(CTX_CON, 1, 8000, &r));
    EXPECT_EQ(r.dwResult, 0);
    EXPECT_EQ(r.dwError, ERROR_INTERNET_CANNOT_CONNECT);
    ac_quiesce(200, 800);
    t_note("ftp refused: %s", ac_seq(0, NULL));
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ HTTPS */
TEST(ac_https_async_sequence) {
    REQ_ASYNC_API();
    srv *s = srv_https(NULL, 0, SRV_CERT_LOCALHOST);
    if (!s) { t_skip("https server unavailable: %s", srv_strerror(srv_last_error())); return; }
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/tls", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, CTX_REQ);
    CHECK(hr != NULL);
    t_https_secflags(hr, SECURITY_FLAG_IGNORE_UNKNOWN_CA);
    int pending; DWORD err; int n0 = ac_count();
    CHECK(ac_send_wait(hr, CTX_REQ, NULL, NULL, 0, &pending, &err));
    EXPECT_EQ(ac_status_code(hr), 200);
    ac_quiesce(100, 300);
    t_note("https statuses: %s", ac_seq_range(0, n0, -1, NULL));
    /* [W10] no extra status for the TLS handshake */
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "80,20,21,30,31,40,41,100");
    char b[16]; int np;
    EXPECT_EQ(ac_read_all_async(hr, CTX_REQ, b, sizeof b, &np), 5);
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
/* [W10] round 1: with an untrusted certificate the async send did not complete within 8 s (statuses 80,20,21 only);
 * probe with a longer bound and record what happens */
TEST(ac_https_async_cert_error_probe) {
    REQ_ASYNC_API();
    srv_config cfg = { SRV_HTTPS }; cfg.cert_profile = SRV_CERT_LOCALHOST; cfg.lifetime_ms = 40000; srv *s;
    START_OR_SKIP(&cfg, &s);
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, CTX_CON);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/tls", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, CTX_REQ);
    int n0 = ac_count();
    DWORD t0 = GetTickCount();
    SetLastError(0xdeadbeef);
    BOOL r = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE); EXPECT_EQ(e, ERROR_IO_PENDING);
    INTERNET_ASYNC_RESULT res;
    int done = ac_wait_complete(CTX_REQ, 1, 20000, &res);
    t_note("https untrusted cert async: done=%d after %lu ms dwResult=%llu dwError=%lu (%s) seq=%s", done, GetTickCount() - t0,
           (unsigned long long)res.dwResult, res.dwError, t_inet_errname(res.dwError), ac_seq_range(0, n0, -1, NULL));
    srv_dump(s);
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    ac_quiesce(100, 2000);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    srv_stop(s);
}
