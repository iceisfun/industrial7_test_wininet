/* session_handles / InternetCloseHandle: NULL/garbage/double close, parent-with-children, callbacks on close,
 * closing from inside a status callback, closing a request that another thread is using.
 * Evidence: [D InternetCloseHandle@0x5cd60 -> InternalInternetCloseHandle@0x5b6d0, MapHandleToAddress@0x58740,
 * InternetSetStatusCallbackCore@0xcef20]. */
#include "sh.h"

/* ------------------------------------------------------------------ callback recorder */
sh_cb_rec *sh_cb_cur;
void sh_cb_reset(sh_cb_rec *r) {
    if (!r->cs_init) { InitializeCriticalSection(&r->cs); r->cs_init = 1; }   /* per recorder (zero-initialised statics) */
    EnterCriticalSection(&r->cs);
    r->n = 0; r->close_on_status_h = NULL; r->close_on_status = 0; r->closed_ok = -1; r->closed_err = 0; r->close_done = 0;
    LeaveCriticalSection(&r->cs);
}
void CALLBACK sh_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD infolen) {
    sh_cb_rec *r = sh_cb_cur;
    if (!r) return;
    HINTERNET to_close = NULL;
    EnterCriticalSection(&r->cs);
    if (r->n < 512) {
        sh_cb_ev *e = &r->ev[r->n++];
        e->h = h; e->ctx = ctx; e->status = status; e->infolen = infolen; e->tid = GetCurrentThreadId();
        e->info0 = 0;
        if (info && infolen >= sizeof(ULONG_PTR)) memcpy(&e->info0, info, sizeof(ULONG_PTR));
        else if (info && infolen >= 4) { DWORD d; memcpy(&d, info, 4); e->info0 = d; }
    }
    if (r->close_on_status && status == r->close_on_status && !r->close_done) { to_close = r->close_on_status_h; r->close_done = 1; }
    LeaveCriticalSection(&r->cs);
    if (to_close) {
        SetLastError(0);
        BOOL ok = U(InternetCloseHandle)(to_close);
        r->closed_err = ok ? 0 : GetLastError();
        r->closed_ok = ok ? 1 : 0;
    }
}
int sh_cb_count(sh_cb_rec *r, DWORD status, DWORD_PTR ctx) {
    int n = 0;
    EnterCriticalSection(&r->cs);
    for (int i = 0; i < r->n; i++) if (r->ev[i].status == status && (ctx == (DWORD_PTR)-1 || r->ev[i].ctx == ctx)) n++;
    LeaveCriticalSection(&r->cs);
    return n;
}
int sh_cb_first(sh_cb_rec *r, DWORD status, DWORD_PTR ctx) {
    int k = -1;
    EnterCriticalSection(&r->cs);
    for (int i = 0; i < r->n; i++) if (r->ev[i].status == status && (ctx == (DWORD_PTR)-1 || r->ev[i].ctx == ctx)) { k = i; break; }
    LeaveCriticalSection(&r->cs);
    return k;
}
static void sh_cb_note(sh_cb_rec *r, const char *tag) {
    char line[1024] = ""; size_t o = 0;
    EnterCriticalSection(&r->cs);
    for (int i = 0; i < r->n && o < sizeof line - 32; i++)
        o += snprintf(line + o, sizeof line - o, "%lu/%llu ", r->ev[i].status, (unsigned long long)r->ev[i].ctx);
    LeaveCriticalSection(&r->cs);
    t_note("%s callbacks (status/ctx): %s", tag, line);
}
static sh_cb_rec g_rec;

/* ------------------------------------------------------------------ simple error cases */
TEST(sh_close_null_6) {
    REQUIRE(U(InternetCloseHandle));
    SetLastError(0);
    EXPECT_FAIL(!U(InternetCloseHandle)(NULL), ERROR_INVALID_HANDLE);
}

static const ULONG_PTR sh_garbage_vals[] = { 1, 2, 3, 4, 0x1234, 0xcc0000, 0x00cc0003, 0x7fff0000, 0x7ffffff0, 0x10000000 };
TEST(sh_close_garbage_6) {
    REQUIRE(U(InternetCloseHandle));
    for (size_t i = 0; i < sizeof sh_garbage_vals / sizeof *sh_garbage_vals; i++) {
        SetLastError(0);
        BOOL ok = U(InternetCloseHandle)((HINTERNET)sh_garbage_vals[i]);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INVALID_HANDLE, "close(0x%llx): ok=%d err %lu", (unsigned long long)sh_garbage_vals[i], ok, e);
    }
}

TEST(sh_close_double_close_each_type) {
    HINTERNET s = sh_open("dc"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0); CHECK(c != NULL);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL; CHECK(r != NULL);
    if (r) { CHECK(sh_close(r)); SetLastError(0); EXPECT_FAIL(!sh_close(r), ERROR_INVALID_HANDLE); }
    if (c) { CHECK(sh_close(c)); SetLastError(0); EXPECT_FAIL(!sh_close(c), ERROR_INVALID_HANDLE); }
    CHECK(sh_close(s));
    SetLastError(0); EXPECT_FAIL(!sh_close(s), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!sh_close(s), ERROR_INVALID_HANDLE);
}

TEST(sh_close_success_last_error_note) {
    HINTERNET s = sh_open("le"); CHECK(s != NULL); if (!s) return;
    SetLastError(0xdeadbeef);
    BOOL ok = sh_close(s);
    CHECK(ok);
    t_note("GetLastError after successful InternetCloseHandle: %lu", GetLastError());
}

TEST(sh_close_closed_handle_all_apis_6) {
    HINTERNET s = sh_open("ch"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    if (r) sh_close(r);
    DWORD v, len, e;
    if (r) {
        CHECK(!sh_qdw(r, INTERNET_OPTION_HANDLE_TYPE, &v, &len, &e)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        EXPECT_EQ(len, 0);
        CHECK(!sh_setdw(r, INTERNET_OPTION_SEND_TIMEOUT, 1000, &e)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        SetLastError(0);
        EXPECT_FAIL(!U(HttpSendRequestA)(r, NULL, 0, NULL, 0), ERROR_INVALID_HANDLE);
        char b[4]; DWORD rd;
        SetLastError(0);
        EXPECT_FAIL(!U(InternetReadFile)(r, b, sizeof b, &rd), ERROR_INVALID_HANDLE);
        DWORD l2 = sizeof b; SetLastError(0);
        EXPECT_FAIL(!U(HttpQueryInfoA)(r, HTTP_QUERY_STATUS_CODE, b, &l2, NULL), ERROR_INVALID_HANDLE);
        SetLastError(0);
        INTERNET_STATUS_CALLBACK prev = U(InternetSetStatusCallbackA)(r, sh_cb);
        EXPECT_EQ(prev, INTERNET_INVALID_STATUS_CALLBACK); EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
    if (c) {
        sh_close(c);
        SetLastError(0);
        HINTERNET r2 = sh_request(c, "/", 0);
        EXPECT_FAIL(r2 == NULL, ERROR_INVALID_HANDLE);
        if (r2) sh_close(r2);
    }
    sh_close(s);
    CHECK(!sh_qdw(s, INTERNET_OPTION_HANDLE_TYPE, &v, &len, &e)); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
}

/* ------------------------------------------------------------------ parent with live children */
TEST(sh_close_session_invalidates_children) {
    HINTERNET s = sh_open("tree"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    CHECK(c && r);
    SetLastError(0xdeadbeef);
    CHECK(sh_close(s));
    DWORD e;
    if (c) { sh_htype(c, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE); }
    if (r) { sh_htype(r, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE); }
    if (r) { SetLastError(0); BOOL ok = sh_close(r); t_note("close(request) after its session was closed: ok=%d err=%lu", ok, ok ? 0 : GetLastError()); EXPECT_FAIL(!ok, ERROR_INVALID_HANDLE); }
    if (c) { SetLastError(0); BOOL ok = sh_close(c); EXPECT_FAIL(!ok, ERROR_INVALID_HANDLE); }
}

TEST(sh_close_connect_invalidates_requests) {
    HINTERNET s = sh_open("tree2"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0); CHECK(c != NULL); if (!c) { sh_close(s); return; }
    enum { N = 40 };
    HINTERNET r[N]; int made = 0;
    for (int i = 0; i < N; i++) { r[i] = sh_request(c, "/", (DWORD_PTR)i); if (r[i]) made++; }
    EXPECT_EQ(made, N);
    CHECK(sh_close(c));
    int invalid = 0;
    for (int i = 0; i < N; i++) { DWORD e = 0; if (r[i]) { sh_htype(r[i], &e); if (e == ERROR_INVALID_HANDLE) invalid++; } }
    EXPECT_EQ(invalid, N);
    /* the session survives */
    EXPECT_EQ(sh_htype(s, NULL), 1);
    HINTERNET c2 = sh_connect(s, "127.0.0.1", 80, 0); CHECK(c2 != NULL);
    if (c2) sh_close(c2);
    CHECK(sh_close(s));
}

TEST(sh_close_request_leaves_connect_usable) {
    HINTERNET s = sh_open("rl"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    for (int i = 0; i < 20 && c; i++) {
        HINTERNET r = sh_request(c, "/", 0);
        CHECK(r != NULL);
        if (r) CHECK(sh_close(r));
    }
    if (c) { EXPECT_EQ(sh_htype(c, NULL), 4); CHECK(sh_close(c)); }
    CHECK(sh_close(s));
}

TEST(sh_close_children_first_then_parent) {
    HINTERNET s = sh_open("cf"); CHECK(s != NULL); if (!s) return;
    HINTERNET c1 = sh_connect(s, "127.0.0.1", 80, 0), c2 = sh_connect(s, "127.0.0.1", 81, 0);
    HINTERNET r1 = c1 ? sh_request(c1, "/a", 0) : NULL, r2 = c2 ? sh_request(c2, "/b", 0) : NULL;
    CHECK(c1 && c2 && r1 && r2);
    if (r1) CHECK(sh_close(r1));
    if (c1) CHECK(sh_close(c1));
    /* sibling branch untouched */
    if (r2) EXPECT_EQ(sh_htype(r2, NULL), 13);
    if (c2) EXPECT_EQ(sh_parent(c2, NULL), s);
    if (r2) CHECK(sh_close(r2));
    if (c2) CHECK(sh_close(c2));
    CHECK(sh_close(s));
}

TEST(sh_close_other_session_unaffected) {
    HINTERNET a = sh_open("a"), b = sh_open("b"); CHECK(a && b);
    HINTERNET ca = a ? sh_connect(a, "127.0.0.1", 80, 0) : NULL, cb = b ? sh_connect(b, "127.0.0.1", 80, 0) : NULL;
    if (a) CHECK(sh_close(a));
    DWORD e;
    if (ca) { sh_htype(ca, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE); }
    if (cb) { EXPECT_EQ(sh_htype(cb, &e), 4); EXPECT_EQ(sh_parent(cb, NULL), b); }
    if (b) CHECK(sh_close(b));
}

/* ------------------------------------------------------------------ status callbacks around close */
TEST(sh_close_set_status_callback_rules) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetSetStatusCallbackW));
    SetLastError(0);
    INTERNET_STATUS_CALLBACK p = U(InternetSetStatusCallbackA)(NULL, sh_cb);
    EXPECT_EQ(p, INTERNET_INVALID_STATUS_CALLBACK); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0);
    p = U(InternetSetStatusCallbackA)(SH_GARBAGE1, sh_cb);
    EXPECT_EQ(p, INTERNET_INVALID_STATUS_CALLBACK); EXPECT_ERR(ERROR_INVALID_HANDLE);
    HINTERNET s = sh_open("cbr"); CHECK(s != NULL); if (!s) return;
    p = U(InternetSetStatusCallbackA)(s, sh_cb);
    EXPECT_EQ(p, NULL);
    p = U(InternetSetStatusCallbackA)(s, NULL);
    EXPECT_EQ(p, sh_cb);
    p = U(InternetSetStatusCallbackW)(s, sh_cb);
    EXPECT_EQ(p, NULL);
    /* CALLBACK option reads it back; setting it is not allowed */
    ULONG_PTR v; DWORD len, e;
    CHECK(sh_qptr(s, INTERNET_OPTION_CALLBACK, &v, &len, &e)); EXPECT_EQ(v, (ULONG_PTR)sh_cb); EXPECT_EQ(len, 8);
    INTERNET_STATUS_CALLBACK cbv = sh_cb;
    CHECK(!sh_set(s, INTERNET_OPTION_CALLBACK, &cbv, sizeof cbv, &e)); EXPECT_EQ(e, ERROR_INTERNET_OPTION_NOT_SETTABLE);
    /* children inherit the callback at creation */
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    if (c) { CHECK(sh_qptr(c, INTERNET_OPTION_CALLBACK, &v, &len, &e)); EXPECT_EQ(v, (ULONG_PTR)sh_cb); }
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    if (r) { CHECK(sh_qptr(r, INTERNET_OPTION_CALLBACK, &v, &len, &e)); EXPECT_EQ(v, (ULONG_PTR)sh_cb); }
    /* changing the parent later does not change existing children */
    U(InternetSetStatusCallbackA)(s, NULL);
    if (c) { CHECK(sh_qptr(c, INTERNET_OPTION_CALLBACK, &v, &len, &e)); EXPECT_EQ(v, (ULONG_PTR)sh_cb); }
    CHECK(sh_qptr(s, INTERNET_OPTION_CALLBACK, &v, &len, &e)); EXPECT_EQ(v, 0);
    if (r) { U(InternetSetStatusCallbackA)(r, NULL); sh_close(r); }
    if (c) { U(InternetSetStatusCallbackA)(c, NULL); sh_close(c); }
    sh_close(s);
}

TEST(sh_close_callback_handle_created_and_closing) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_rec); sh_cb_cur = &g_rec;
    HINTERNET s = sh_open("cb"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    DWORD_PTR sctx = 0x51; DWORD e;
    CHECK(sh_set(s, INTERNET_OPTION_CONTEXT_VALUE, &sctx, sizeof sctx, &e));
    U(InternetSetStatusCallbackA)(s, sh_cb);
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0x52);
    HINTERNET r = c ? sh_request(c, "/", 0x53) : NULL;
    CHECK(c && r);
    sh_cb_note(&g_rec, "after create");
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CREATED, 0x52), 1);
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CREATED, 0x53), 1);
    int k = sh_cb_first(&g_rec, INTERNET_STATUS_HANDLE_CREATED, 0x53);
    if (k >= 0) {
        t_note("HANDLE_CREATED(request): cb handle %p infolen %lu info0 %llx (request %p)", g_rec.ev[k].h, g_rec.ev[k].infolen, (unsigned long long)g_rec.ev[k].info0, r);
        EXPECT_EQ(g_rec.ev[k].info0, (ULONG_PTR)r);
    }
    int before = g_rec.n;
    CHECK(sh_close(s));        /* closes the whole tree */
    sh_cb_note(&g_rec, "after close");
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x51), 1);
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x52), 1);
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x53), 1);
    int i_r = sh_cb_first(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x53), i_c = sh_cb_first(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x52),
        i_s = sh_cb_first(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x51);
    CHECK(i_r >= before && i_c >= before && i_s >= before);
    t_note("HANDLE_CLOSING order indices: request %d connect %d session %d", i_r, i_c, i_s);
    CHECK(i_r < i_c && i_c < i_s);    /* children are torn down before the parent */
    if (i_r >= 0) { EXPECT_EQ(g_rec.ev[i_r].h, r); t_note("HANDLE_CLOSING(request) infolen %lu info0 %llx", g_rec.ev[i_r].infolen, (unsigned long long)g_rec.ev[i_r].info0); }
    if (i_s >= 0) EXPECT_EQ(g_rec.ev[i_s].h, s);
    sh_cb_cur = NULL;
}

TEST(sh_close_callback_zero_context_silent) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_rec); sh_cb_cur = &g_rec;
    HINTERNET s = sh_open("cb0"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    U(InternetSetStatusCallbackA)(s, sh_cb);
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
    sh_cb_note(&g_rec, "zero-context");
    EXPECT_EQ(g_rec.n, 0);
    sh_cb_cur = NULL;
}

/* close another handle from inside a callback */
TEST(sh_close_from_callback_other_handle) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_rec); sh_cb_cur = &g_rec;
    HINTERNET s = sh_open("cbx"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET victim = c ? sh_request(c, "/victim", 0) : NULL;
    CHECK(victim != NULL);
    U(InternetSetStatusCallbackA)(c, sh_cb);
    g_rec.close_on_status = INTERNET_STATUS_HANDLE_CREATED; g_rec.close_on_status_h = victim;
    HINTERNET r = c ? sh_request(c, "/trigger", 0x99) : NULL;
    CHECK(r != NULL);
    EXPECT_EQ(g_rec.close_done, 1);
    EXPECT_EQ(g_rec.closed_ok, 1);
    DWORD e; sh_htype(victim, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    if (r) EXPECT_EQ(sh_htype(r, NULL), 13);
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
    sh_cb_cur = NULL;
}

/* close a handle from inside the HANDLE_CLOSING callback of its sibling */
TEST(sh_close_from_closing_callback_sibling) {
    REQUIRE(U(InternetSetStatusCallbackA));
    sh_cb_reset(&g_rec); sh_cb_cur = &g_rec;
    HINTERNET s = sh_open("cbs"); CHECK(s != NULL); if (!s) { sh_cb_cur = NULL; return; }
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    if (c) U(InternetSetStatusCallbackA)(c, sh_cb);
    HINTERNET r = c ? sh_request(c, "/self", 0x77) : NULL;
    CHECK(r != NULL);
    HINTERNET sib = c ? sh_request(c, "/sib", 0x78) : NULL;
    g_rec.close_on_status = INTERNET_STATUS_HANDLE_CLOSING; g_rec.close_on_status_h = r; g_rec.close_done = 0;
    if (sib) CHECK(sh_close(sib));
    EXPECT_EQ(g_rec.close_done, 1);
    EXPECT_EQ(g_rec.closed_ok, 1);
    DWORD e; if (r) { sh_htype(r, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE); }
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x77), 1);
    EXPECT_EQ(sh_cb_count(&g_rec, INTERNET_STATUS_HANDLE_CLOSING, 0x78), 1);
    if (c) sh_close(c);
    sh_close(s);
    sh_cb_cur = NULL;
}

/* close a request from inside its own status callback during a synchronous HttpSendRequest */
typedef struct { HINTERNET r; BOOL ok; DWORD err; } sh_send_arg;
static DWORD WINAPI sh_send_thread(LPVOID p) {
    sh_send_arg *a = p;
    SetLastError(0);
    a->ok = U(HttpSendRequestA)(a->r, NULL, 0, NULL, 0);
    a->err = a->ok ? 0 : GetLastError();
    return 0;
}
TEST(sh_close_self_from_callback_during_send) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static const srv_step st[] = { S_HEAD(), S_SLEEP(1500), S_REPLY(200, NULL, "late"), S_CLOSE() };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *sv;
    SH_START_OR_SKIP(&cfg, &sv);
    sh_cb_reset(&g_rec); sh_cb_cur = &g_rec;
    HINTERNET s = sh_open_to("cbsend");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/selfclose", 0x31) : NULL;
    CHECK(r != NULL);
    if (r) {
        U(InternetSetStatusCallbackA)(r, sh_cb);
        g_rec.close_on_status = INTERNET_STATUS_REQUEST_SENT; g_rec.close_on_status_h = r;
        sh_send_arg a = { r, TRUE, 0 };
        HANDLE th = CreateThread(NULL, 0, sh_send_thread, &a, 0, NULL);
        DWORD w = WaitForSingleObject(th, 10000);
        CHECKF(w == WAIT_OBJECT_0, "HttpSendRequest did not return within 10 s");
        if (w == WAIT_OBJECT_0) {
            EXPECT_EQ(g_rec.close_done, 1);
            EXPECT_EQ(g_rec.closed_ok, 1);
            t_note("send after self-close in REQUEST_SENT: ok=%d err=%lu (%s)", a.ok, a.err, t_inet_errname(a.err));
            CHECK(!a.ok);
            EXPECT_EQ(a.err, ERROR_INTERNET_OPERATION_CANCELLED);
            CloseHandle(th);
        }
        sh_cb_note(&g_rec, "self-close during send");
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
    sh_cb_cur = NULL;
}

/* close a request from another thread while HttpSendRequest waits for the response */
TEST(sh_close_request_while_send_blocked) {
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late"), S_CLOSE() };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *sv;
    SH_START_OR_SKIP(&cfg, &sv);
    HINTERNET s = sh_open_to("blk");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/block", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        sh_send_arg a = { r, TRUE, 0 };
        HANDLE th = CreateThread(NULL, 0, sh_send_thread, &a, 0, NULL);
        CHECK(srv_wait_requests(sv, 1, 3000));
        Sleep(100);
        DWORD t0 = GetTickCount();
        CHECK(sh_close(r));
        DWORD w = WaitForSingleObject(th, 10000);
        CHECKF(w == WAIT_OBJECT_0, "sender still blocked 10 s after close");
        if (w == WAIT_OBJECT_0) {
            t_note("blocked send after close: ok=%d err=%lu (%s), returned %lu ms after close", a.ok, a.err, t_inet_errname(a.err), GetTickCount() - t0);
            CHECK(!a.ok);
            EXPECT_EQ(a.err, ERROR_INTERNET_OPERATION_CANCELLED);
            CloseHandle(th);
        }
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}

/* a session closed while another thread is blocked in a send on one of its requests */
TEST(sh_close_session_while_send_blocked) {
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late"), S_CLOSE() };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *sv;
    SH_START_OR_SKIP(&cfg, &sv);
    HINTERNET s = sh_open_to("blk2");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/block2", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        sh_send_arg a = { r, TRUE, 0 };
        HANDLE th = CreateThread(NULL, 0, sh_send_thread, &a, 0, NULL);
        CHECK(srv_wait_requests(sv, 1, 3000));
        Sleep(100);
        CHECK(sh_close(s));
        DWORD w = WaitForSingleObject(th, 10000);
        CHECKF(w == WAIT_OBJECT_0, "sender still blocked 10 s after session close");
        if (w == WAIT_OBJECT_0) {
            t_note("blocked send after session close: ok=%d err=%lu (%s)", a.ok, a.err, t_inet_errname(a.err));
            CHECK(!a.ok);
            CloseHandle(th);
        }
        DWORD e; sh_htype(r, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    }
    srv_stop(sv);
}

/* async session: closing a request with a pending send completes it as cancelled */
static HANDLE g_async_evt;
static volatile DWORD g_async_res, g_async_err, g_async_seen;
static void CALLBACK sh_async_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    if (status == INTERNET_STATUS_REQUEST_COMPLETE && info) {
        INTERNET_ASYNC_RESULT *ar = info;
        g_async_res = (DWORD)ar->dwResult; g_async_err = ar->dwError; g_async_seen++;
        SetEvent(g_async_evt);
    }
}
TEST(sh_close_async_pending_send) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static const srv_step st[] = { S_HEAD(), S_SLEEP(3000), S_REPLY(200, NULL, "late"), S_CLOSE() };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *sv;
    SH_START_OR_SKIP(&cfg, &sv);
    g_async_evt = CreateEventA(NULL, FALSE, FALSE, NULL); g_async_seen = 0;
    HINTERNET s = U(InternetOpenA)("async-close", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    CHECK(s != NULL);
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    if (s) U(InternetSetStatusCallbackA)(s, sh_async_cb);
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/async", NULL, NULL, NULL, T_INET_FRESH, 0x1) : NULL;
    CHECK(r != NULL);
    if (r) {
        U(InternetSetStatusCallbackA)(r, sh_async_cb);
        SetLastError(0);
        BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_IO_PENDING, "async send ok=%d err %lu", ok, e);
        CHECK(srv_wait_requests(sv, 1, 3000));
        CHECK(sh_close(r));
        DWORD w = WaitForSingleObject(g_async_evt, 6000);
        t_note("async pending send closed: completion wait=%lu seen=%lu result=%lu err=%lu (%s)", w, g_async_seen, g_async_res, g_async_err, t_inet_errname(g_async_err));
        CHECKF(w == WAIT_OBJECT_0, "no REQUEST_COMPLETE within 6 s of closing the pending request");   /* VM: always delivered */
        if (w == WAIT_OBJECT_0) { EXPECT_EQ(g_async_seen, 1); EXPECT_EQ(g_async_res, 0); EXPECT_EQ(g_async_err, ERROR_INTERNET_OPERATION_CANCELLED); }
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    Sleep(200);
    srv_stop(sv);
    /* keep the event alive if the completion never came: a late callback must not SetEvent a closed (reused) handle */
    if (g_async_seen) CloseHandle(g_async_evt);
}
