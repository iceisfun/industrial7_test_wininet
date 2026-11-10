/* session_handles / handle lifetime edges: hidden connects of InternetOpenUrl, wide trees, callbacks that are set only on
 * part of a tree, removing a callback, re-entrant calls inside HANDLE_CLOSING / HANDLE_CREATED, closing with unread
 * bodies, FTP trees, handle value reuse.
 * Evidence: [D _InternetCloseHandle@0x138b84 (MapHandleToAddress(h, &obj, 1) invalidates the handle before the object
 * is dereferenced; the close only fails on 6 or 12004), InternalInternetCloseHandle child loop, InternetSetStatusCallbackCore],
 * VM boots (EVIDENCE.md). */
#include "sh.h"

static sh_cb_rec g_life_rec;

static void sh_life_note(sh_cb_rec *r, const char *tag) {
    char line[1024] = ""; size_t o = 0;
    EnterCriticalSection(&r->cs);
    for (int i = 0; i < r->n && o < sizeof line - 32; i++)
        o += snprintf(line + o, sizeof line - o, "%lu/%llx ", r->ev[i].status, (unsigned long long)r->ev[i].ctx);
    LeaveCriticalSection(&r->cs);
    t_note("%s callbacks (status/ctx): %s", tag, line);
}

/* ------------------------------------------------------------------ hidden connect of InternetOpenUrl */
TEST(sh_life_close_hidden_connect_of_openurl) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("hidden-close");
    HINTERNET r = s ? U(InternetOpenUrlA)(s, srv_url(sv, "/h"), NULL, 0, T_INET_FRESH, 1) : NULL;
    CHECK(r != NULL);
    if (r) {
        HINTERNET hc = sh_parent(r, NULL);
        EXPECT_EQ(sh_htype(hc, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        SetLastError(0xdeadbeef);
        BOOL ok = sh_close(hc);
        DWORD e = GetLastError();
        CHECKF(ok, "close(hidden connect of OpenUrl): err %lu", e);   /* VM: allowed, and it takes the request with it */
        DWORD e2; DWORD t = sh_htype(r, &e2);
        t_note("request after closing its hidden connect: type %lu err %lu", t, e2);
        if (ok) {
            /* a closed parent takes its children with it */
            EXPECT_EQ(e2, ERROR_INVALID_HANDLE);
            SetLastError(0); EXPECT_FAIL(!sh_close(r), ERROR_INVALID_HANDLE);
        } else {
            char b[16]; t_inet_read_all(r, b, sizeof b, NULL);
            sh_close(r);
        }
    }
    if (s) sh_close(s);
    srv_stop(sv);
}

/* Two InternetOpenUrl requests to the same server get two distinct hidden connects. */
TEST(sh_life_openurl_hidden_connects_distinct) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("hidden-2");
    HINTERNET r1 = s ? U(InternetOpenUrlA)(s, srv_url(sv, "/a"), NULL, 0, T_INET_FRESH, 1) : NULL;
    HINTERNET r2 = s ? U(InternetOpenUrlA)(s, srv_url(sv, "/b"), NULL, 0, T_INET_FRESH, 2) : NULL;
    CHECK(r1 && r2);
    if (r1 && r2) {
        HINTERNET p1 = sh_parent(r1, NULL), p2 = sh_parent(r2, NULL);
        CHECK(p1 != p2);
        CHECK(p1 != s && p2 != s);
        char b[16];
        t_inet_read_all(r1, b, sizeof b, NULL);
        CHECK(sh_close(r1));
        DWORD e; sh_htype(p1, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        EXPECT_EQ(sh_htype(p2, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);   /* the other tree is untouched */
        EXPECT_EQ(sh_htype(r2, NULL), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        t_inet_read_all(r2, b, sizeof b, NULL);
        CHECK(sh_close(r2));
        sh_htype(p2, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    } else {
        if (r1) sh_close(r1);
        if (r2) sh_close(r2);
    }
    if (s) sh_close(s);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ wide trees */
TEST(sh_life_close_session_with_wide_tree) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_life_rec); sh_cb_cur = &g_life_rec;
    HINTERNET s = U(InternetOpenA)("wide", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    CHECK(U(InternetSetStatusCallbackA)(s, sh_cb) == NULL);
    enum { NC = 12, NR = 6 };
    HINTERNET c[NC], r[NC][NR];
    int made = 0;
    for (int i = 0; i < NC; i++) {
        c[i] = sh_connect(s, "127.0.0.1", (INTERNET_PORT)(8000 + i), 0x1000 + i);
        CHECK(c[i] != NULL);
        for (int j = 0; j < NR; j++) {
            r[i][j] = c[i] ? sh_request(c[i], "/w", 0x2000 + i * 16 + j) : NULL;
            CHECK(r[i][j] != NULL);
            if (r[i][j]) made++;
        }
    }
    EXPECT_EQ(made, NC * NR);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CREATED, (DWORD_PTR)-1), NC + NC * NR);
    CHECK(sh_close(s));
    int bad = 0;
    for (int i = 0; i < NC; i++) {
        DWORD e; if (c[i]) { sh_htype(c[i], &e); if (e != ERROR_INVALID_HANDLE) bad++; }
        for (int j = 0; j < NR; j++) if (r[i][j]) { sh_htype(r[i][j], &e); if (e != ERROR_INVALID_HANDLE) bad++; }
    }
    EXPECT_EQ(bad, 0);
    /* HANDLE_CLOSING for every child with a context; the session itself has context 0 and stays silent */
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, (DWORD_PTR)-1), NC + NC * NR);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, 0), 0);
    /* every request of a connect closes before that connect */
    int order_ok = 1;
    EnterCriticalSection(&g_life_rec.cs);
    for (int i = 0; i < NC; i++) {
        int ci = -1, last_r = -1;
        for (int k = 0; k < g_life_rec.n; k++) {
            if (g_life_rec.ev[k].status != INTERNET_STATUS_HANDLE_CLOSING) continue;
            DWORD_PTR x = g_life_rec.ev[k].ctx;
            if (x == (DWORD_PTR)(0x1000 + i)) ci = k;
            if (x >= (DWORD_PTR)(0x2000 + i * 16) && x < (DWORD_PTR)(0x2000 + i * 16 + NR)) last_r = k;
        }
        if (!(ci > last_r && last_r >= 0)) order_ok = 0;
    }
    LeaveCriticalSection(&g_life_rec.cs);
    CHECK(order_ok);
    sh_cb_cur = NULL;
}

/* ------------------------------------------------------------------ callbacks on part of a tree */
TEST(sh_life_callback_only_on_connect) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_life_rec); sh_cb_cur = &g_life_rec;
    HINTERNET s = U(InternetOpenA)("cb-connect", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0xa1);
    CHECK(c != NULL);
    if (c) CHECK(U(InternetSetStatusCallbackA)(c, sh_cb) == NULL);
    HINTERNET c2 = sh_connect(s, "127.0.0.1", 81, 0xa2);   /* sibling created afterwards: no callback */
    HINTERNET r = c ? sh_request(c, "/", 0xa3) : NULL;
    HINTERNET r2 = c2 ? sh_request(c2, "/", 0xa4) : NULL;
    CHECK(r && r2);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CREATED, 0xa3), 1);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CREATED, 0xa4), 0);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CREATED, 0xa2), 0);
    CHECK(sh_close(s));
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, 0xa3), 1);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, 0xa1), 1);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, 0xa2), 0);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, 0xa4), 0);
    sh_life_note(&g_life_rec, "callback on connect only");
    sh_cb_cur = NULL;
}

/* InternetSetStatusCallback(h, NULL) removes it: no HANDLE_CLOSING afterwards; the previous callback is returned. */
TEST(sh_life_callback_removed_with_null) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_life_rec); sh_cb_cur = &g_life_rec;
    HINTERNET s = sh_open("cb-null"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0xb1);
    CHECK(c != NULL);
    if (c) {
        CHECK(U(InternetSetStatusCallbackA)(c, sh_cb) == NULL);
        SetLastError(0xdeadbeef);
        INTERNET_STATUS_CALLBACK prev = U(InternetSetStatusCallbackA)(c, NULL);
        EXPECT_EQ(prev, sh_cb);
        ULONG_PTR cb = 1; DWORD len, e;
        CHECK(sh_qptr(c, INTERNET_OPTION_CALLBACK, &cb, &len, &e)); EXPECT_EQ(cb, 0);
        CHECK(sh_close(c));
        EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, (DWORD_PTR)-1), 0);
    }
    sh_close(s);
    sh_cb_cur = NULL;
}

/* A callback set on the session after children exist does not reach them (copied at creation only). */
TEST(sh_life_callback_set_late_not_propagated) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_life_rec); sh_cb_cur = &g_life_rec;
    HINTERNET s = sh_open("cb-late"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0xc1);
    CHECK(U(InternetSetStatusCallbackA)(s, sh_cb) == NULL);
    HINTERNET r = c ? sh_request(c, "/", 0xc2) : NULL;
    CHECK(r != NULL);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CREATED, (DWORD_PTR)-1), 0);
    ULONG_PTR cb = 1; DWORD len, e;
    if (c) { CHECK(sh_qptr(c, INTERNET_OPTION_CALLBACK, &cb, &len, &e)); EXPECT_EQ(cb, 0); }
    if (r) { CHECK(sh_qptr(r, INTERNET_OPTION_CALLBACK, &cb, &len, &e)); EXPECT_EQ(cb, 0); }
    CHECK(sh_qptr(s, INTERNET_OPTION_CALLBACK, &cb, &len, &e)); EXPECT_EQ(cb, (ULONG_PTR)sh_cb);
    sh_close(s);
    EXPECT_EQ(sh_cb_count(&g_life_rec, INTERNET_STATUS_HANDLE_CLOSING, (DWORD_PTR)-1), 0);
    sh_cb_cur = NULL;
}

/* ------------------------------------------------------------------ re-entrant calls inside callbacks */
typedef struct { HINTERNET target; DWORD htype_ok, htype_err, htype_val; int seen; ULONG_PTR ctx_val; } sh_reent;
static sh_reent g_reent;
static void CALLBACK sh_reent_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD infolen) {
    if (status != INTERNET_STATUS_HANDLE_CLOSING || h != g_reent.target || g_reent.seen) return;
    g_reent.seen = 1;
    DWORD v = 0, len = sizeof v;
    SetLastError(0);
    BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &v, &len);
    g_reent.htype_ok = ok; g_reent.htype_err = ok ? 0 : GetLastError(); g_reent.htype_val = v;
    ULONG_PTR cv = 0; len = sizeof cv;
    if (U(InternetQueryOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &cv, &len)) g_reent.ctx_val = cv;
}
TEST(sh_life_query_inside_handle_closing) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET s = sh_open("reent"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0xd1);
    CHECK(c != NULL);
    if (c) {
        memset(&g_reent, 0, sizeof g_reent); g_reent.target = c;
        U(InternetSetStatusCallbackA)(c, sh_reent_cb);
        CHECK(sh_close(c));
        CHECK(g_reent.seen);
        /* the handle value is already unmapped when HANDLE_CLOSING is delivered */
        t_note("HANDLE_TYPE inside HANDLE_CLOSING: ok=%lu err %lu val %lu ctx 0x%llx", g_reent.htype_ok, g_reent.htype_err, g_reent.htype_val, (unsigned long long)g_reent.ctx_val);
        CHECK(!g_reent.htype_ok && g_reent.htype_err == ERROR_INVALID_HANDLE);
    }
    sh_close(s);
}

/* Closing the brand-new handle from inside its own HANDLE_CREATED callback. */
static HINTERNET g_created_closed; static int g_created_close_ok = -1; static DWORD g_created_close_err;
static void CALLBACK sh_close_created_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD infolen) {
    if (status != INTERNET_STATUS_HANDLE_CREATED || ctx != 0xe2 || g_created_closed) return;
    HINTERNET nh = info && infolen >= sizeof(HINTERNET) ? *(HINTERNET *)info : NULL;
    g_created_closed = nh ? nh : (HINTERNET)1;
    SetLastError(0);
    BOOL ok = nh ? U(InternetCloseHandle)(nh) : FALSE;
    g_created_close_ok = ok; g_created_close_err = ok ? 0 : GetLastError();
}
TEST(sh_life_close_inside_handle_created) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET s = sh_open("created-close"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0xe1);
    if (c) {
        g_created_closed = NULL; g_created_close_ok = -1;
        U(InternetSetStatusCallbackA)(c, sh_close_created_cb);
        SetLastError(0xdeadbeef);
        HINTERNET r = sh_request(c, "/", 0xe2);
        DWORD e = GetLastError();
        t_note("HttpOpenRequest whose HANDLE_CREATED callback closed it: h=%p (cb saw %p) err %lu close ok=%d err %lu", r, g_created_closed, e, g_created_close_ok, g_created_close_err);
        CHECK(g_created_closed != NULL);
        /* VM: the close inside HANDLE_CREATED succeeds and HttpOpenRequest then returns NULL with 12017 */
        EXPECT_EQ(g_created_close_ok, 1);
        CHECK(r == NULL); EXPECT_EQ(e, ERROR_INTERNET_OPERATION_CANCELLED);
        if (r) {
            DWORD e2; DWORD t = sh_htype(r, &e2);
            t_note("returned handle afterwards: type %lu err %lu", t, e2);
            if (!g_created_close_ok) sh_close(r);
        }
        U(InternetSetStatusCallbackA)(c, NULL);
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ closing with unread data */
TEST(sh_life_close_request_with_unread_body_then_reuse_connect) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 200000, 0), S_LOOP() };
    srv *sv = srv_http(st, 3);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("unread");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    for (int round = 0; c && round < 3; round++) {
        HINTERNET r = sh_request(c, "/big", 0);
        CHECK(r != NULL);
        if (!r) break;
        { int c_ = !!(U(HttpSendRequestA)(r, NULL, 0, NULL, 0)); t_check(c_, __FILE__, __LINE__, "U(HttpSendRequestA)(r, NULL, 0, NULL, 0)", "round %d send err %lu", round, GetLastError()); }
        char b[64]; DWORD rd = 0;
        CHECK(U(InternetReadFile)(r, b, sizeof b, &rd) && rd == sizeof b);
        CHECK(srv_pattern_check(b, rd, 0));
        CHECK(sh_close(r));
    }
    /* VM: a request closed with most of its body unread is not drained: its connection is dropped and the next
     * request opens a new one */
    EXPECT_EQ(srv_conn_count(sv), 3);
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}

/* Closing a session drops its connections: the server sees the socket end within a few seconds. */
TEST(sh_life_close_session_ends_server_connection) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_PATTERN(200, NULL, 300000, 0), S_LOOP() };
    srv *sv = srv_http(st, 3);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("end-conn");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/big", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        CHECK(U(HttpSendRequestA)(r, NULL, 0, NULL, 0));
        char b[16]; DWORD rd; U(InternetReadFile)(r, b, sizeof b, &rd);
    }
    if (s) CHECK(sh_close(s));
    int ended = srv_wait_events(sv, SRV_EV_EOF, 1, 4000) || srv_count_events(sv, SRV_EV_RESET) > 0 || srv_count_events(sv, SRV_EV_ERROR) > 0 || srv_count_events(sv, SRV_EV_CLOSED) > 0;
    t_note("after closing a session mid-body: eof=%d reset=%d error=%d closed=%d", srv_count_events(sv, SRV_EV_EOF), srv_count_events(sv, SRV_EV_RESET), srv_count_events(sv, SRV_EV_ERROR), srv_count_events(sv, SRV_EV_CLOSED));
    CHECK(ended);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ FTP trees */
TEST(sh_life_close_session_with_ftp_tree) {
    REQUIRE(U(FtpFindFirstFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-life");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 1) : NULL;
    WIN32_FIND_DATAA fd;
    HINTERNET fh = c ? U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 2) : NULL;
    CHECK(c && fh);
    CHECK(s && sh_close(s));
    DWORD e;
    if (c) { sh_htype(c, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE); }
    if (fh) {
        sh_htype(fh, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        SetLastError(0); EXPECT_FAIL(!U(InternetFindNextFileA)(fh, &fd), ERROR_INVALID_HANDLE);
    }
    /* the control connection is closed: QUIT or EOF reaches the server */
    int quit = 0;
    for (int w = 0; w < 40 && !quit; w++) {
        for (int i = 0; i < srv_ftp_cmd_count(f); i++) if (!strncmp(srv_ftp_cmd(f, i), "QUIT", 4)) quit = 1;
        if (!quit) { if (srv_count_events(f, SRV_EV_EOF) || srv_count_events(f, SRV_EV_RESET)) break; Sleep(100); }
    }
    t_note("FTP session close: QUIT=%d eof=%d reset=%d", quit, srv_count_events(f, SRV_EV_EOF), srv_count_events(f, SRV_EV_RESET));
    srv_stop(f);
}

/* Closing an FTP connect: what the server sees (note), and the next connect to the same server works. */
TEST(sh_life_close_ftp_connect_sends_quit) {
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-quit");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 1) : NULL;
    CHECK(c != NULL);
    if (c) {
        CHECK(sh_close(c));
        int quit = 0;
        for (int w = 0; w < 30 && !quit; w++) {
            for (int i = 0; i < srv_ftp_cmd_count(f); i++) if (!strncmp(srv_ftp_cmd(f, i), "QUIT", 4)) quit = 1;
            if (!quit) Sleep(100);
        }
        /* VM: no QUIT reaches the server within 3 s (the control connection is not closed gracefully at once);
         * recorded only. A new connect works regardless. */
        t_note("QUIT after closing an FTP connect: %d (commands %d)", quit, srv_ftp_cmd_count(f));
        HINTERNET c2 = U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 1);
        CHECK(c2 != NULL);
        if (c2) sh_close(c2);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* ------------------------------------------------------------------ handle values */
TEST(sh_life_handle_value_reuse_after_close) {
    HINTERNET a = sh_open("reuse-a"); CHECK(a != NULL); if (!a) return;
    ULONG_PTR va = (ULONG_PTR)a;
    CHECK(sh_close(a));
    HINTERNET b = sh_open("reuse-b"); CHECK(b != NULL); if (!b) return;
    t_note("handle value after close/open: old %p new %p (reused=%d)", (void *)va, b, (ULONG_PTR)b == va);
    /* whatever the value, the new handle carries the new state */
    char buf[32]; DWORD len, e;
    CHECK(sh_qstr(b, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e)); EXPECT_STR(buf, "reuse-b");
    sh_close(b);
}

/* Handles stay valid across many open/close cycles of unrelated sessions. */
TEST(sh_life_handles_survive_unrelated_churn) {
    HINTERNET keep = sh_open("keeper"); CHECK(keep != NULL); if (!keep) return;
    HINTERNET kc = sh_connect(keep, "127.0.0.1", 80, 0x77);
    for (int i = 0; i < 200; i++) {
        HINTERNET t = sh_open("churn");
        HINTERNET tc = t ? sh_connect(t, "127.0.0.1", 80, 0) : NULL;
        if (tc) sh_close(tc);
        if (t) sh_close(t);
    }
    EXPECT_EQ(sh_htype(keep, NULL), INTERNET_HANDLE_TYPE_INTERNET);
    if (kc) {
        EXPECT_EQ(sh_htype(kc, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        ULONG_PTR v; CHECK(sh_qptr(kc, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0x77);
        EXPECT_EQ(sh_parent(kc, NULL), keep);
    }
    char b[32]; DWORD len, e;
    CHECK(sh_qstr(keep, INTERNET_OPTION_USER_AGENT, b, sizeof b, &len, &e)); EXPECT_STR(b, "keeper");
    if (kc) sh_close(kc);
    sh_close(keep);
}

/* Closing a request whose send failed (dead port) works and leaves the connect usable. */
TEST(sh_life_close_after_failed_send) {
    REQUIRE(U(HttpSendRequestA));
    unsigned short dead = sh_dead_port();
    if (!dead) { t_skip("no port"); return; }
    HINTERNET s = sh_open_to("failsend");
    /* keep the 5 s connect timeout: a refused loopback connect takes ~2 s on Windows (SYN retries), a 2 s
     * timeout turns it into 12002 (VM) */
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", dead, 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/x", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        SetLastError(0);
        EXPECT_FAIL(!U(HttpSendRequestA)(r, NULL, 0, NULL, 0), ERROR_INTERNET_CANNOT_CONNECT);
        DWORD v, len, e;
        CHECK(sh_qdw(r, INTERNET_OPTION_HANDLE_TYPE, &v, &len, &e)); EXPECT_EQ(v, INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        SetLastError(0xdeadbeef);
        CHECK(sh_close(r)); EXPECT_EQ(GetLastError(), 0);
        HINTERNET r2 = sh_request(c, "/y", 0);
        CHECK(r2 != NULL);
        if (r2) sh_close(r2);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
}
