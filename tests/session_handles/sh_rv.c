/* session_handles / review pass 3: FTP InternetConnect credential and OFFLINE rules, async sessions (FTP connect and
 * InternetOpenUrl run synchronously when dwContext is 0), InternetOpenUrl handle/URL validation order, status-callback
 * arguments of HANDLE_CREATED / HANDLE_CLOSING, re-entrant closes inside HANDLE_CLOSING (run on a watchdog thread),
 * PARENT_HANDLE / CONTEXT_VALUE buffer protocol, identity options that cannot be set, server names that HttpConnect does
 * not validate, partial and long HTTP credentials, proxy string read-back, closing a connect while another thread
 * creates requests under it, async session churn, InternetGetConnectedStateExA rules.
 * Evidence: [D FtpConnect@0x136e6c (GetEmailNameAndPassword before any I/O; OFFLINE on the session or the connect flags
 * skips FtpConnectBlocking; FtpConnectNonBlocking only for an async session with dwContext != 0),
 * GetEmailNameAndPassword@0x136c00 (password without user -> 87; user without password -> ""),
 * InternalInternetOpenUrlA@0x13753c (MapHandleToAddress -> RIsHandleLocal('Inet') -> URL NULL/"" 87; sync path when
 * the session is not async or dwContext == 0), HttpConnect@0x5c250 (server name: only NULL/"" rejected; empty user /
 * password become NULL)], VM boots (EVIDENCE.md, "Pass 3"). Every wait is bounded. VM_TIMEOUT: 240 */
#include "sh.h"

/* ------------------------------------------------------------------ FTP InternetConnect credentials */
/* A password without a user name is rejected before any I/O (a dead port proves nothing was attempted). */
TEST(sh_rv_ftp_password_without_user_87) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(InternetConnectW));
    unsigned short dead = sh_dead_port();
    if (!dead) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-pw-only"); CHECK(s != NULL); if (!s) return;
    const char *users[] = { NULL, "" };
    for (int i = 0; i < 2; i++) {
        SetLastError(0);
        HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", dead, users[i], "pw-only", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        DWORD e = GetLastError();
        CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "A user %s + password: h=%p err %lu want 87", users[i] ? "\"\"" : "NULL", c, e);
        if (c) sh_close(c);
    }
    const WCHAR *wusers[] = { NULL, L"" };
    for (int i = 0; i < 2; i++) {
        SetLastError(0);
        HINTERNET c = U(InternetConnectW)(s, L"127.0.0.1", dead, wusers[i], L"pw-only", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
        DWORD e = GetLastError();
        CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "W user %s + password: h=%p err %lu want 87", wusers[i] ? "\"\"" : "NULL", c, e);
        if (c) sh_close(c);
    }
    sh_close(s);
}

/* A user name without a password logs in with an empty password; PASSWORD reads "". */
static srv *sh_rv_ftp_start_recpass(void) {
    static srv_ftp_config fc;
    fc.files = sh_ftp_files; fc.nfiles = 4; fc.record_pass = 1;     /* test dummies only: no real credentials */
    srv_config cfg = { SRV_FTP }; cfg.ftp = &fc;
    srv *s = NULL;
    if (srv_start(&cfg, &s)) return NULL;
    return s;
}
TEST(sh_rv_ftp_user_without_password) {
    srv *f = sh_rv_ftp_start_recpass();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-user-only");
    SetLastError(0xdeadbeef);
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), "only-user", NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    CHECKF(c != NULL, "ftp connect with user only: err %lu", GetLastError());
    if (c) {
        char b[64]; DWORD len, e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "only-user");
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e));
        t_note("FTP user-only connect: PASSWORD reads [%s] len %lu", b, len);
        EXPECT_STR(b, "");
        if (srv_wait_events(f, SRV_EV_FTP_CMD, 2, 3000)) {
            EXPECT_STR(srv_ftp_cmd(f, 0), "USER only-user");
            const char *p = srv_ftp_cmd(f, 1);
            t_note("FTP user-only connect: second command [%s]", p ? p : "(null)");
            CHECK(p && !strncmp(p, "PASS", 4));
        } else CHECK(!"no FTP login seen");
        sh_close(c);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* No user and no password: USER anonymous, and the connect reads back "anonymous" (password noted only: it is the
 * per-machine e-mail name from GetMyEmailName). */
TEST(sh_rv_ftp_anonymous_password_note) {
    srv *f = sh_rv_ftp_start_recpass();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-anon");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), "", "", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    CHECKF(c != NULL, "ftp connect with \"\"/\"\": err %lu", GetLastError());
    if (c) {
        char b[64]; DWORD len, e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "anonymous");
        BOOL ok = sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e);
        t_note("anonymous FTP connect: PASSWORD ok=%d len %lu", ok, len);
        if (srv_wait_events(f, SRV_EV_FTP_CMD, 2, 3000)) EXPECT_STR(srv_ftp_cmd(f, 0), "USER anonymous");
        else CHECK(!"no FTP login seen");
        sh_close(c);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* INTERNET_FLAG_OFFLINE on the FTP connect, or an OFFLINE session: the FTP connect handle is created without any I/O. */
TEST(sh_rv_ftp_connect_offline_no_io) {
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-offline-flag");
    SetLastError(0xdeadbeef);
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_OFFLINE | INTERNET_FLAG_PASSIVE, 0x31) : NULL;
    DWORD e = GetLastError();
    CHECKF(c != NULL, "FTP connect with INTERNET_FLAG_OFFLINE: err %lu", e);
    if (c) {
        EXPECT_EQ(e, 0);
        EXPECT_EQ(sh_htype(c, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        EXPECT_EQ(sh_parent(c, NULL), s);
        char b[32]; DWORD len, qe;
        BOOL ok = sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &qe);
        t_note("offline FTP connect: USERNAME ok=%d [%s]", ok, ok ? b : "");
        sh_close(c);
    }
    HINTERNET so = (HINTERNET)t_inet_open_ex("ftp-offline-session", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    SetLastError(0xdeadbeef);
    HINTERNET c2 = so ? U(InternetConnectA)(so, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    e = GetLastError();
    CHECKF(c2 != NULL, "FTP connect on an OFFLINE session: err %lu", e);
    if (c2) { EXPECT_EQ(e, 0); EXPECT_EQ(sh_htype(c2, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP); sh_close(c2); }
    Sleep(200);
    EXPECT_EQ(srv_conn_count(f), 0);
    if (so) sh_close(so);
    if (s) sh_close(s);
    srv_stop(f);
}

/* ------------------------------------------------------------------ async sessions */
static HANDLE g_rv_evt;
static volatile ULONG_PTR g_rv_res; static volatile DWORD g_rv_err; static volatile LONG g_rv_done;
static void CALLBACK sh_rv_async_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    if (status == INTERNET_STATUS_REQUEST_COMPLETE && info && ctx == 0x5a) {
        INTERNET_ASYNC_RESULT *ar = info;
        g_rv_res = ar->dwResult; g_rv_err = ar->dwError;
        if (InterlockedIncrement(&g_rv_done) == 1 && g_rv_evt) SetEvent(g_rv_evt);
    }
}

/* FTP connect on an async session: dwContext 0 -> synchronous login; dwContext != 0 -> ERROR_IO_PENDING and the
 * handle arrives in REQUEST_COMPLETE. */
TEST(sh_rv_ftp_connect_async_session_context_rule) {
    REQUIRE(U(InternetSetStatusCallbackA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = (HINTERNET)t_inet_open_ex("ftp-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    CHECK(s != NULL);
    if (!s) { srv_stop(f); return; }
    U(InternetSetStatusCallbackA)(s, sh_rv_async_cb);
    SetLastError(0xdeadbeef);
    HINTERNET c0 = U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    DWORD e = GetLastError();
    CHECKF(c0 != NULL, "async session, FTP connect with context 0: err %lu", e);
    if (c0) {
        EXPECT_EQ(e, 0);
        EXPECT_EQ(sh_htype(c0, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        CHECK(srv_ftp_cmd_count(f) >= 2);          /* the login already happened */
        sh_close(c0);
    }
    g_rv_evt = CreateEventA(NULL, TRUE, FALSE, NULL); g_rv_done = 0; g_rv_res = 0; g_rv_err = 0;
    int conns0 = srv_conn_count(f);
    SetLastError(0xdeadbeef);
    HINTERNET c1 = U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0x5a);
    e = GetLastError();
    t_note("async session, FTP connect with context: h=%p err %lu", c1, c1 ? 0 : e);
    CHECKF(c1 == NULL && e == ERROR_IO_PENDING, "async FTP connect with context: h=%p err %lu want NULL/997", c1, e);
    DWORD w = WaitForSingleObject(g_rv_evt, 5000);
    CHECKF(w == WAIT_OBJECT_0, "no REQUEST_COMPLETE within 5 s");
    if (w == WAIT_OBJECT_0) {
        HINTERNET ch = (HINTERNET)g_rv_res;
        t_note("async FTP connect completion: result %p err %lu", ch, g_rv_err);
        CHECK(ch != NULL);
        if (ch) { EXPECT_EQ(sh_htype(ch, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP); EXPECT_EQ(sh_parent(ch, NULL), s); sh_close(ch); }
        CHECK(srv_conn_count(f) > conns0);
    }
    if (c1) sh_close(c1);
    sh_close(s);                                    /* closes anything still pending */
    Sleep(200);
    if (w == WAIT_OBJECT_0) CloseHandle(g_rv_evt);  /* a late callback would still find a live event otherwise */
    g_rv_evt = NULL;
    srv_stop(f);
}

/* InternetOpenUrl on an async session, dwContext 0: Win10 still goes asynchronous (NULL / 997), no handle comes back directly. */
TEST(sh_rv_openurl_async_session_zero_context_sync) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = (HINTERNET)t_inet_open_ex("ou-async", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_ASYNC, 5000);
    CHECK(s != NULL);
    if (s) {
        SetLastError(0xdeadbeef);
        HINTERNET r = U(InternetOpenUrlA)(s, srv_url(sv, "/async0"), NULL, 0, T_INET_FRESH, 0);
        DWORD e = GetLastError();
        t_note("async session, InternetOpenUrl context 0: h=%p err %lu", r, r ? 0 : e);
        CHECKF(r == NULL && e == ERROR_IO_PENDING, "async session, InternetOpenUrl context 0: h=%p err %lu want NULL/997", r, e);
        if (r) sh_close(r);
        sh_close(s);
        Sleep(200);
    }
    srv_stop(sv);
}

/* ------------------------------------------------------------------ InternetOpenUrl validation order */
TEST(sh_rv_openurl_handle_checked_before_url) {
    REQUIRE(U(InternetOpenUrlA));
    unsigned short dead = sh_dead_port();
    if (!dead) { t_skip("server unavailable"); return; }
    char url[64]; snprintf(url, sizeof url, "http://127.0.0.1:%u/x", dead);
    SetLastError(0);
    HINTERNET r = U(InternetOpenUrlA)(NULL, url, NULL, 0, T_INET_FRESH, 0);
    EXPECT_FAIL(r == NULL, ERROR_INVALID_HANDLE); if (r) sh_close(r);
    SetLastError(0);
    r = U(InternetOpenUrlA)(SH_GARBAGE1, NULL, NULL, 0, 0, 0);
    EXPECT_FAIL(r == NULL, ERROR_INVALID_HANDLE); if (r) sh_close(r);
    HINTERNET s = sh_open_to("ou-order"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", dead, 0);
    if (c) {
        SetLastError(0);
        r = U(InternetOpenUrlA)(c, url, NULL, 0, T_INET_FRESH, 0);
        EXPECT_FAIL(r == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); if (r) sh_close(r);
        SetLastError(0);
        r = U(InternetOpenUrlA)(c, NULL, NULL, 0, 0, 0);
        EXPECT_FAIL(r == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); if (r) sh_close(r);
        HINTERNET rq = sh_request(c, "/", 0);
        if (rq) {
            SetLastError(0);
            r = U(InternetOpenUrlA)(rq, url, NULL, 0, T_INET_FRESH, 0);
            EXPECT_FAIL(r == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); if (r) sh_close(r);
            sh_close(rq);
        }
        sh_close(c);
    }
    SetLastError(0);
    r = U(InternetOpenUrlA)(s, NULL, NULL, 0, 0, 0);
    EXPECT_FAIL(r == NULL, ERROR_INVALID_PARAMETER); if (r) sh_close(r);
    SetLastError(0);
    r = U(InternetOpenUrlA)(s, "", NULL, 0, 0, 0);
    EXPECT_FAIL(r == NULL, ERROR_INVALID_PARAMETER); if (r) sh_close(r);
    CHECK(sh_close(s));
    SetLastError(0);
    r = U(InternetOpenUrlA)(s, url, NULL, 0, T_INET_FRESH, 0);     /* closed session */
    EXPECT_FAIL(r == NULL, ERROR_INVALID_HANDLE); if (r) sh_close(r);
}

/* ------------------------------------------------------------------ callback arguments */
static sh_cb_rec g_rv_rec;
static int sh_rv_find(sh_cb_rec *r, DWORD status, DWORD_PTR ctx) { return sh_cb_first(r, status, ctx); }
TEST(sh_rv_callback_args_created_and_closing) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_rv_rec); sh_cb_cur = &g_rv_rec;
    HINTERNET s = sh_open("cb-args"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    U(InternetSetStatusCallbackA)(s, sh_cb);
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0x61);
    HINTERNET r = c ? sh_request(c, "/args", 0x62) : NULL;
    CHECK(c && r);
    int kc = sh_rv_find(&g_rv_rec, INTERNET_STATUS_HANDLE_CREATED, 0x61), kr = sh_rv_find(&g_rv_rec, INTERNET_STATUS_HANDLE_CREATED, 0x62);
    CHECK(kc >= 0 && kr >= 0);
    if (kc >= 0) {
        sh_cb_ev *ev = &g_rv_rec.ev[kc];
        t_note("HANDLE_CREATED(connect): hInternet %p (session %p connect %p) infolen %lu info %llx", ev->h, s, c, ev->infolen, (unsigned long long)ev->info0);
        EXPECT_EQ(ev->info0, (ULONG_PTR)c); EXPECT_EQ(ev->infolen, sizeof(HINTERNET));
        EXPECT_EQ(ev->h, s);
    }
    if (kr >= 0) {
        sh_cb_ev *ev = &g_rv_rec.ev[kr];
        EXPECT_EQ(ev->info0, (ULONG_PTR)r); EXPECT_EQ(ev->infolen, sizeof(HINTERNET));
        EXPECT_EQ(ev->h, c);                       /* VM pass 1: the parent handle, not the new one */
    }
    if (r) CHECK(sh_close(r));
    int kx = sh_rv_find(&g_rv_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x62);
    CHECK(kx >= 0);
    if (kx >= 0) { sh_cb_ev *ev = &g_rv_rec.ev[kx]; EXPECT_EQ(ev->h, r); EXPECT_EQ(ev->info0, (ULONG_PTR)r); EXPECT_EQ(ev->infolen, sizeof(HINTERNET)); }
    if (c) CHECK(sh_close(c));
    int ky = sh_rv_find(&g_rv_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x61);
    CHECK(ky >= 0);
    if (ky >= 0) { sh_cb_ev *ev = &g_rv_rec.ev[ky]; EXPECT_EQ(ev->h, c); EXPECT_EQ(ev->info0, (ULONG_PTR)c); EXPECT_EQ(ev->infolen, sizeof(HINTERNET)); }
    /* every callback so far ran on this thread */
    int other = 0;
    EnterCriticalSection(&g_rv_rec.cs);
    for (int i = 0; i < g_rv_rec.n; i++) if (g_rv_rec.ev[i].tid != GetCurrentThreadId()) other++;
    LeaveCriticalSection(&g_rv_rec.cs);
    EXPECT_EQ(other, 0);
    sh_close(s);
    sh_cb_cur = NULL;
}

/* ------------------------------------------------------------------ re-entrant closes inside HANDLE_CLOSING */
/* Each scenario runs on a worker thread with a bounded wait, so a deadlock fails the test instead of hanging the exe. */
typedef struct {
    HINTERNET s, c, r;          /* tree */
    HINTERNET target;           /* handle whose HANDLE_CLOSING triggers the inner close */
    HINTERNET inner;            /* handle closed from inside that callback */
    volatile LONG fired; BOOL inner_ok; DWORD inner_err;
    BOOL outer_ok; DWORD outer_err;
} sh_rv_reent;
static sh_rv_reent g_rv_re;
static void CALLBACK sh_rv_reent_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD infolen) {
    if (status != INTERNET_STATUS_HANDLE_CLOSING || h != g_rv_re.target) return;
    if (InterlockedIncrement(&g_rv_re.fired) != 1) return;
    SetLastError(0);
    g_rv_re.inner_ok = U(InternetCloseHandle)(g_rv_re.inner);
    g_rv_re.inner_err = g_rv_re.inner_ok ? 0 : GetLastError();
}
static DWORD WINAPI sh_rv_reent_thread(LPVOID p) {
    SetLastError(0);
    g_rv_re.outer_ok = U(InternetCloseHandle)(g_rv_re.target);
    g_rv_re.outer_err = g_rv_re.outer_ok ? 0 : GetLastError();
    return 0;
}
static int sh_rv_reent_run(void) {
    HANDLE th = CreateThread(NULL, 0, sh_rv_reent_thread, NULL, 0, NULL);
    if (!th) return 0;
    DWORD w = WaitForSingleObject(th, 8000);
    CloseHandle(th);
    return w == WAIT_OBJECT_0;
}

/* Closing a handle again from inside its own HANDLE_CLOSING: the value is already unmapped, so FALSE/6. */
TEST(sh_rv_close_self_inside_own_handle_closing) {
    REQUIRE(U(InternetSetStatusCallbackA));
    memset(&g_rv_re, 0, sizeof g_rv_re);
    g_rv_re.s = sh_open("reclose-self"); CHECK(g_rv_re.s != NULL); if (!g_rv_re.s) return;
    g_rv_re.c = sh_connect(g_rv_re.s, "127.0.0.1", 80, 0x71);
    CHECK(g_rv_re.c != NULL);
    if (g_rv_re.c) {
        U(InternetSetStatusCallbackA)(g_rv_re.c, sh_rv_reent_cb);
        g_rv_re.target = g_rv_re.c; g_rv_re.inner = g_rv_re.c;
        int done = sh_rv_reent_run();
        CHECKF(done, "close did not return within 8 s");
        if (!done) return;                          /* leave everything alone: the worker may still be inside wininet */
        EXPECT_EQ(g_rv_re.fired, 1);
        CHECK(g_rv_re.outer_ok);
        t_note("re-close inside own HANDLE_CLOSING: ok=%d err %lu", g_rv_re.inner_ok, g_rv_re.inner_err);
        CHECK(!g_rv_re.inner_ok); EXPECT_EQ(g_rv_re.inner_err, ERROR_INVALID_HANDLE);
    }
    sh_close(g_rv_re.s);
}

/* Closing the parent connect from inside the HANDLE_CLOSING of its request. */
TEST(sh_rv_close_parent_inside_child_handle_closing) {
    REQUIRE(U(InternetSetStatusCallbackA));
    memset(&g_rv_re, 0, sizeof g_rv_re);
    g_rv_re.s = sh_open("reclose-parent"); CHECK(g_rv_re.s != NULL); if (!g_rv_re.s) return;
    g_rv_re.c = sh_connect(g_rv_re.s, "127.0.0.1", 80, 0x72);
    if (g_rv_re.c) U(InternetSetStatusCallbackA)(g_rv_re.c, sh_rv_reent_cb);
    g_rv_re.r = g_rv_re.c ? sh_request(g_rv_re.c, "/child", 0x73) : NULL;
    CHECK(g_rv_re.r != NULL);
    if (g_rv_re.r) {
        g_rv_re.target = g_rv_re.r; g_rv_re.inner = g_rv_re.c;
        int done = sh_rv_reent_run();
        CHECKF(done, "close did not return within 8 s");
        if (!done) return;
        EXPECT_EQ(g_rv_re.fired, 1);
        t_note("close parent inside child HANDLE_CLOSING: inner ok=%d err %lu, outer ok=%d err %lu", g_rv_re.inner_ok, g_rv_re.inner_err, g_rv_re.outer_ok, g_rv_re.outer_err);
        CHECK(g_rv_re.outer_ok);
        CHECK(g_rv_re.inner_ok);
        DWORD e;
        sh_htype(g_rv_re.c, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        sh_htype(g_rv_re.r, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        EXPECT_EQ(sh_htype(g_rv_re.s, NULL), INTERNET_HANDLE_TYPE_INTERNET);    /* the session survives */
    }
    sh_close(g_rv_re.s);
}

/* ------------------------------------------------------------------ PARENT_HANDLE / CONTEXT_VALUE buffer protocol */
TEST(sh_rv_parent_handle_buffer_protocol) {
    HINTERNET s = sh_open("parent-proto"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        DWORD small = 0xcccccccc, len = 4;
        SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(r, INTERNET_OPTION_PARENT_HANDLE, &small, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, sizeof(HINTERNET));
        len = 0; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(r, INTERNET_OPTION_PARENT_HANDLE, NULL, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, sizeof(HINTERNET));
        ULONG_PTR v = 0; len = sizeof v;
        CHECK(U(InternetQueryOptionW)(r, INTERNET_OPTION_PARENT_HANDLE, &v, &len));
        EXPECT_EQ(v, (ULONG_PTR)c); EXPECT_EQ(len, sizeof(HINTERNET));
        BYTE big[16]; memset(big, 0xab, sizeof big); len = sizeof big;
        CHECK(U(InternetQueryOptionA)(c, INTERNET_OPTION_PARENT_HANDLE, big, &len));
        EXPECT_EQ(len, 8); EXPECT_EQ(*(ULONG_PTR *)big, (ULONG_PTR)s);
        EXPECT_EQ(big[8], 0xab);                   /* nothing written past the 8 bytes */
    }
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_rv_context_value_w_roundtrip) {
    REQUIRE(U(InternetSetOptionW)); REQUIRE(U(InternetQueryOptionW));
    HINTERNET s = sh_open("ctx-w"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0x1234);
    CHECK(c != NULL);
    if (c) {
        ULONG_PTR v = 0; DWORD len = sizeof v;
        CHECK(U(InternetQueryOptionW)(c, INTERNET_OPTION_CONTEXT_VALUE, &v, &len));
        EXPECT_EQ(v, 0x1234); EXPECT_EQ(len, 8);
        DWORD_PTR nv = (DWORD_PTR)0x8877665544332211ull;
        SetLastError(0xdeadbeef);
        CHECK(U(InternetSetOptionW)(c, INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv));
        len = sizeof v;
        CHECK(U(InternetQueryOptionA)(c, INTERNET_OPTION_CONTEXT_VALUE, &v, &len));
        EXPECT_EQ(v, (ULONG_PTR)0x8877665544332211ull);
        DWORD four = 1; SetLastError(0);
        CHECK(!U(InternetSetOptionW)(c, INTERNET_OPTION_CONTEXT_VALUE, &four, 4));
        EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
        sh_close(c);
    }
    sh_close(s);
}

/* PARENT_HANDLE, REQUEST_FLAGS and URL are query-only: setting them gives 12009 (not 12011) on every handle type. */
TEST(sh_rv_set_identity_options_12009) {
    HINTERNET s = sh_open("ident-set"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 1);
    HINTERNET r = c ? sh_request(c, "/i", 2) : NULL;
    CHECK(r != NULL);
    HINTERNET hs[3] = { s, c, r };
    static const DWORD opts[] = { INTERNET_OPTION_PARENT_HANDLE, INTERNET_OPTION_REQUEST_FLAGS, INTERNET_OPTION_URL };
    for (int k = 0; k < 3; k++) for (int i = 0; i < 3; i++) {
        if (!hs[k]) continue;
        BYTE buf[16] = { 0 }; DWORD e;
        BOOL ok = sh_set(hs[k], opts[i], buf, 8, &e);
        CHECKF(!ok && e == ERROR_INTERNET_INVALID_OPTION, "set option %lu on handle %d: ok=%d err %lu want 12009", opts[i], k, ok, e);
    }
    /* the values are unchanged */
    if (r) {
        EXPECT_EQ(sh_parent(r, NULL), c);
        DWORD v; CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &v, NULL, NULL)); EXPECT_EQ(v, INTERNET_REQFLAG_NO_HEADERS);
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
}

/* ------------------------------------------------------------------ server names HttpConnect does not validate */
TEST(sh_rv_connect_server_names_not_validated) {
    HINTERNET s = sh_open("names"); CHECK(s != NULL); if (!s) return;
    static const char *const names[] = { "127.0.0.1:8080", "a b", "http://h.example", "h.example/path", "%41%42", "-", "_", "a..b", "300.1.1.1" };
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET c = U(InternetConnectA)(s, names[i], 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        DWORD e = GetLastError();
        CHECKF(c != NULL && e == 0, "InternetConnectA([%s]): h=%p err %lu", names[i], c, e);
        if (!c) continue;
        EXPECT_EQ(sh_htype(c, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        HINTERNET r = sh_request(c, "/p", 0);
        char url[256] = ""; DWORD len = 0, qe = 0;
        if (r) sh_qstr(r, INTERNET_OPTION_URL, url, sizeof url, &len, &qe);
        t_note("server name [%s]: HttpOpenRequest %s (err %lu), URL [%s]", names[i], r ? "ok" : "failed", r ? 0 : GetLastError(), url);
        if (r) sh_close(r);
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ HTTP credentials */
TEST(sh_rv_http_partial_credentials) {
    HINTERNET s = sh_open("partial"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, "only-user", NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    char b[64]; DWORD len, e;
    if (c) {
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "only-user");
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        sh_close(c);
    }
    /* unlike FTP, HTTP accepts a password without a user name */
    SetLastError(0xdeadbeef);
    c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, "only-pass", INTERNET_SERVICE_HTTP, 0, 0);
    CHECKF(c != NULL, "HTTP connect with password only: err %lu", GetLastError());
    if (c) {
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "only-pass");
        sh_close(c);
    }
    c = U(InternetConnectW)(s, L"127.0.0.1", 80, L"", L"only-pass-w", INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    if (c) {
        WCHAR w[32]; CHECK(sh_qstrw(c, INTERNET_OPTION_PASSWORD, w, sizeof w, &len, &e)); EXPECT_WSTR(w, L"only-pass-w");
        sh_close(c);
    }
    sh_close(s);
}

TEST(sh_rv_http_long_credentials_roundtrip) {
    HINTERNET s = sh_open("longcred"); CHECK(s != NULL); if (!s) return;
    static char user[2001], pass[3001], buf[4000];
    for (int i = 0; i < 2000; i++) user[i] = (char)('A' + i % 26);
    for (int i = 0; i < 3000; i++) pass[i] = (char)('0' + i % 10);
    user[2000] = 0; pass[3000] = 0;
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, user, pass, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    if (c) {
        DWORD len = 0; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(c, INTERNET_OPTION_USERNAME, NULL, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 2001);
        DWORD e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, buf, sizeof buf, &len, &e)); EXPECT_EQ(len, 2000); CHECK(!strcmp(buf, user));
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, buf, sizeof buf, &len, &e)); EXPECT_EQ(len, 3000); CHECK(!strcmp(buf, pass));
        HINTERNET r = sh_request(c, "/", 0);
        if (r) { CHECK(sh_qstr(r, INTERNET_OPTION_PASSWORD, buf, sizeof buf, &len, &e)); EXPECT_EQ(len, 3000); sh_close(r); }
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ proxy string read-back */
TEST(sh_rv_proxy_info_readback_forms) {
    static const struct { const char *proxy, *bypass; } rows[] = {
        { "127.0.0.1:9", NULL }, { "127.0.0.1:9", "" }, { "http=127.0.0.1:9 ftp=127.0.0.1:10", "a.example;b.example" },
        { "http://127.0.0.1:9", "<local>" },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        HINTERNET h = U(InternetOpenA)("pxrb", INTERNET_OPEN_TYPE_PROXY, rows[i].proxy, rows[i].bypass, 0);
        CHECKF(h != NULL, "row %u: InternetOpen err %lu", (unsigned)i, GetLastError());
        if (!h) continue;
        union { INTERNET_PROXY_INFO pi; char raw[512]; } u; DWORD len = sizeof u;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_PROXY, &u, &len));
        const char *p = (const char *)u.pi.lpszProxy, *b = (const char *)u.pi.lpszProxyBypass;
        t_note("row %u proxy [%s] bypass [%s]: access %lu lpszProxy [%s] lpszProxyBypass [%s] len %lu", (unsigned)i, rows[i].proxy,
               rows[i].bypass ? rows[i].bypass : "(null)", u.pi.dwAccessType, p ? p : "(null)", b ? b : "(null)", len);
        EXPECT_EQ(u.pi.dwAccessType, INTERNET_OPEN_TYPE_PROXY);
        EXPECT_STR(p, rows[i].proxy);
        sh_close(h);
    }
}

/* ------------------------------------------------------------------ closing a connect while another thread creates requests under it */
typedef struct { HINTERNET c; volatile LONG stop; volatile LONG made, fail6, fail18, failother, close_ok, close6; volatile DWORD other_err; } sh_rv_mk;
static DWORD WINAPI sh_rv_mk_thread(LPVOID p) {
    sh_rv_mk *m = (sh_rv_mk *)p;
    DWORD t0 = GetTickCount();
    for (int i = 0; i < 1000000 && !m->stop && GetTickCount() - t0 < 5000; i++) {
        SetLastError(0);
        HINTERNET r = U(HttpOpenRequestA)(m->c, "GET", "/mk", NULL, NULL, NULL, T_INET_FRESH, 0);
        DWORD e = GetLastError();
        if (r) {
            m->made++;
            if (U(InternetCloseHandle)(r)) m->close_ok++; else if (GetLastError() == ERROR_INVALID_HANDLE) m->close6++;
        } else if (e == ERROR_INVALID_HANDLE) { if (++m->fail6 > 20) break; }
        else if (e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE) { if (++m->fail18 > 20) break; }
        else { m->failother++; m->other_err = e; }
    }
    return 0;
}
TEST(sh_rv_conc_close_connect_while_requests_created) {
    HINTERNET s = sh_open("mkconn"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    CHECK(c != NULL);
    if (c) {
        static sh_rv_mk m; memset((void *)&m, 0, sizeof m); m.c = c;
        HANDLE th = CreateThread(NULL, 0, sh_rv_mk_thread, &m, 0, NULL);
        while (m.made < 50 && WaitForSingleObject(th, 1) == WAIT_TIMEOUT) ;    /* bounded by the worker's own 5 s limit */
        CHECK(sh_close(c));
        DWORD w = WaitForSingleObject(th, 8000);
        m.stop = 1;
        if (w != WAIT_OBJECT_0) w = WaitForSingleObject(th, 5000);
        CHECK(w == WAIT_OBJECT_0);
        CloseHandle(th);
        t_note("requests created around connect close: made %ld fail6 %ld fail18 %ld failother %ld (last %lu) close_ok %ld close6 %ld",
               m.made, m.fail6, m.fail18, m.failother, m.other_err, m.close_ok, m.close6);
        CHECK(m.made >= 50);
        CHECK(m.fail6 + m.fail18 > 0);
        CHECK(m.failother <= 3);
        EXPECT_EQ(m.close_ok + m.close6, m.made);
        EXPECT_EQ(sh_htype(s, NULL), INTERNET_HANDLE_TYPE_INTERNET);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ async session churn */
TEST(sh_rv_async_sessions_loop_no_leak) {
    for (int i = 0; i < 10; i++) {          /* warm-up: the async worker pool is created once per process */
        HINTERNET h = U(InternetOpenA)("async-warm", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
        HINTERNET c = h ? sh_connect(h, "127.0.0.1", 80, 1) : NULL;
        HINTERNET r = c ? sh_request(c, "/", 2) : NULL;
        if (r) sh_close(r);
        if (h) sh_close(h);
    }
    DWORD hc0 = 0, hc1 = 0; GetProcessHandleCount(GetCurrentProcess(), &hc0);
    int bad = 0;
    for (int i = 0; i < 150; i++) {
        HINTERNET h = U(InternetOpenA)("async-loop", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
        HINTERNET c = h ? sh_connect(h, "127.0.0.1", 80, 1) : NULL;
        HINTERNET r = c ? sh_request(c, "/", 2) : NULL;
        if (!h || !c || !r) bad++;
        if (h && !sh_close(h)) bad++;
    }
    GetProcessHandleCount(GetCurrentProcess(), &hc1);
    EXPECT_EQ(bad, 0);
    t_note("kernel handle count before %lu after %lu (150 async session trees)", hc0, hc1);
    CHECKF(hc1 <= hc0 + 16, "kernel handles grew from %lu to %lu", hc0, hc1);
}

/* ------------------------------------------------------------------ InternetGetConnectedStateExA */
TEST(sh_rv_connected_state_ex_a_rules) {
    REQUIRE(U(InternetGetConnectedStateExA)); REQUIRE(U(InternetGetConnectedState));
    DWORD f0 = 0; BOOL r0 = U(InternetGetConnectedState)(&f0, 0);
    char name[64] = "zz"; DWORD f = 0xffffffff;
    SetLastError(0);
    BOOL r = U(InternetGetConnectedStateExA)(&f, name, sizeof name, 3);
    DWORD e = GetLastError();
    t_note("ExA reserved 3: ret %d err %lu flags 0x%lx name[0] %d", r, e, f, name[0]);
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_PARAMETER); EXPECT_EQ(f, 0);
    f = 0xffffffff;
    r = U(InternetGetConnectedStateExA)(&f, NULL, 0, 0);
    EXPECT_EQ(r, r0); EXPECT_EQ(f, f0);
    /* NULL flags pointer with a name buffer */
    memset(name, 'x', sizeof name);
    r = U(InternetGetConnectedStateExA)(NULL, name, sizeof name, 0);
    EXPECT_EQ(r, r0);
    CHECK(memchr(name, 0, sizeof name) != NULL);
}
