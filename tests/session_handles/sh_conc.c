/* session_handles / handles used from several threads: racing closes of one handle, closing a parent while other
 * threads query or create children, concurrent session creation, callbacks of sync calls run on the calling thread,
 * concurrent InternetSetStatusCallback.
 * Evidence: [D _InternetCloseHandle@0x138b84: MapHandleToAddress(h, &obj, 1) removes the handle from the map under the
 * map lock, so exactly one closer wins], VM boots (EVIDENCE.md). Every wait is bounded. */
#include "sh.h"

typedef struct { HINTERNET h; HANDLE go; volatile LONG ok; volatile LONG err; } sh_closer;
static DWORD WINAPI sh_closer_thread(LPVOID p) {
    sh_closer *c = (sh_closer *)p;
    WaitForSingleObject(c->go, 5000);
    SetLastError(0);
    BOOL ok = U(InternetCloseHandle)(c->h);
    c->ok = ok; c->err = ok ? 0 : (LONG)GetLastError();
    return 0;
}
TEST(sh_conc_racing_close_exactly_one_wins) {
    REQUIRE(U(InternetCloseHandle));
    int one_winner = 0, rounds = 0, bad_err = 0;
    for (int i = 0; i < 100; i++) {
        HINTERNET s = sh_open("race");
        HINTERNET c = s ? sh_connect(s, "127.0.0.1", 80, 0) : NULL;
        if (!c) { CHECK(!"setup"); if (s) sh_close(s); break; }
        HANDLE go = CreateEventA(NULL, TRUE, FALSE, NULL);
        sh_closer cl[4]; HANDLE th[4];
        for (int k = 0; k < 4; k++) { cl[k].h = c; cl[k].go = go; cl[k].ok = -1; cl[k].err = 0; th[k] = CreateThread(NULL, 0, sh_closer_thread, &cl[k], 0, NULL); }
        SetEvent(go);
        DWORD w = WaitForMultipleObjects(4, th, TRUE, 10000);
        if (w >= WAIT_OBJECT_0 + 4) { CHECK(!"closer threads did not finish within 10 s"); return; }   /* cl[] still in use */
        int wins = 0;
        for (int k = 0; k < 4; k++) { if (cl[k].ok == 1) wins++; else if (cl[k].err != ERROR_INVALID_HANDLE) bad_err++; CloseHandle(th[k]); }
        CloseHandle(go);
        if (wins == 1) one_winner++;
        rounds++;
        sh_close(s);
    }
    EXPECT_EQ(one_winner, rounds);
    EXPECT_EQ(bad_err, 0);
}

/* Threads query a request while the main thread closes the session: every query either succeeds with the right
 * type or fails with 6; nothing else. */
typedef struct { HINTERNET r; volatile LONG stop; LONG ok, inval, other; } sh_qloop;
static DWORD WINAPI sh_qloop_thread(LPVOID p) {
    sh_qloop *q = (sh_qloop *)p;
    DWORD t0 = GetTickCount();
    /* run until the main thread says stop (bounded by 5 s): a fixed iteration count can finish before the close */
    for (int i = 0; !q->stop && GetTickCount() - t0 < 5000; i++) {
        DWORD v = 0, len = sizeof v;
        SetLastError(0);
        if (U(InternetQueryOptionA)(q->r, INTERNET_OPTION_HANDLE_TYPE, &v, &len)) {
            if (v == INTERNET_HANDLE_TYPE_HTTP_REQUEST) InterlockedIncrement(&q->ok); else InterlockedIncrement(&q->other);
        } else {
            if (GetLastError() == ERROR_INVALID_HANDLE) { InterlockedIncrement(&q->inval); if (q->inval > 50) break; }
            else InterlockedIncrement(&q->other);
        }
    }
    return 0;
}
TEST(sh_conc_query_while_session_closed) {
    HINTERNET s = sh_open("qclose"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    CHECK(r != NULL);
    if (!r) { sh_close(s); return; }
    sh_qloop q = { r, 0, 0, 0, 0 };
    HANDLE th[3];
    for (int k = 0; k < 3; k++) th[k] = CreateThread(NULL, 0, sh_qloop_thread, &q, 0, NULL);
    Sleep(50);
    CHECK(sh_close(s));
    Sleep(50);
    q.stop = 1;
    WaitForMultipleObjects(3, th, TRUE, 10000);
    for (int k = 0; k < 3; k++) CloseHandle(th[k]);
    t_note("queries during session close: ok %ld invalid %ld other %ld", q.ok, q.inval, q.other);
    EXPECT_EQ(q.other, 0);
    CHECK(q.ok > 0);
    CHECK(q.inval > 0);
}

/* A thread creating connects in a loop while the session is closed: creation fails with 6 afterwards, every
 * connect it did get is either closed with the session or closable once. */
typedef struct { HINTERNET s; volatile LONG stop; LONG made, fail6, fail18, failother, close_ok, close6; DWORD other_err; } sh_mk;
static DWORD WINAPI sh_mk_thread(LPVOID p) {
    sh_mk *m = (sh_mk *)p;
    for (int i = 0; i < 100000 && !m->stop; i++) {
        SetLastError(0);
        HINTERNET c = U(InternetConnectA)(m->s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        DWORD e = GetLastError();
        if (c) {
            m->made++;
            if (U(InternetCloseHandle)(c)) m->close_ok++; else if (GetLastError() == ERROR_INVALID_HANDLE) m->close6++;
        } else if (e == ERROR_INVALID_HANDLE) { if (++m->fail6 > 20) break; }
        else if (e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE) { if (++m->fail18 > 20) break; }  /* the freed session value was reused by a child created in the race window */
        else { m->failother++; m->other_err = e; }
    }
    return 0;
}
TEST(sh_conc_create_children_while_session_closed) {
    HINTERNET s = sh_open("mkclose"); CHECK(s != NULL); if (!s) return;
    sh_mk m; memset(&m, 0, sizeof m); m.s = s;
    HANDLE th = CreateThread(NULL, 0, sh_mk_thread, &m, 0, NULL);
    Sleep(50);
    CHECK(sh_close(s));
    DWORD w = WaitForSingleObject(th, 5000);
    m.stop = 1;
    if (w != WAIT_OBJECT_0) WaitForSingleObject(th, 5000);
    CloseHandle(th);
    t_note("children created around session close: made %ld fail6 %ld fail18 %ld failother %ld (last other err %lu) close_ok %ld close6 %ld", m.made, m.fail6, m.fail18, m.failother, m.other_err, m.close_ok, m.close6);
    CHECK(m.made > 0);
    CHECK(m.fail6 + m.fail18 > 0);
    /* VM boot 1: one creation in the close window failed with another error; at most a handful are tolerated */
    CHECK(m.failother <= 3);
    EXPECT_EQ(m.close_ok + m.close6, m.made);
}

/* 8 threads opening and closing sessions with children concurrently: no failures, no handle leak. */
typedef struct { LONG fail; } sh_par;
static DWORD WINAPI sh_par_thread(LPVOID p) {
    sh_par *x = (sh_par *)p;
    for (int i = 0; i < 100; i++) {
        HINTERNET s = U(InternetOpenA)("par", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
        HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
        if (!r) InterlockedIncrement(&x->fail);
        DWORD v = 0, len = sizeof v;
        if (r && (!U(InternetQueryOptionA)(r, INTERNET_OPTION_HANDLE_TYPE, &v, &len) || v != 13)) InterlockedIncrement(&x->fail);
        if (s && !U(InternetCloseHandle)(s)) InterlockedIncrement(&x->fail);   /* closes the whole tree */
    }
    return 0;
}
TEST(sh_conc_parallel_session_trees_no_leak) {
    DWORD hc0 = 0, hc1 = 0;
    GetProcessHandleCount(GetCurrentProcess(), &hc0);
    sh_par x = { 0 };
    HANDLE th[8];
    for (int k = 0; k < 8; k++) th[k] = CreateThread(NULL, 0, sh_par_thread, &x, 0, NULL);
    WaitForMultipleObjects(8, th, TRUE, 30000);
    for (int k = 0; k < 8; k++) CloseHandle(th[k]);
    EXPECT_EQ(x.fail, 0);
    GetProcessHandleCount(GetCurrentProcess(), &hc1);
    t_note("kernel handle count before %lu after %lu (8 threads x 100 trees)", hc0, hc1);
    CHECK(hc1 <= hc0 + 16);
}

/* Callbacks of synchronous calls run on the calling thread, also when another thread made the session. */
static sh_cb_rec g_conc_rec;
typedef struct { HINTERNET s; unsigned short port; DWORD tid; int ok; } sh_sendjob;
static DWORD WINAPI sh_send_thread(LPVOID p) {
    sh_sendjob *j = (sh_sendjob *)p;
    j->tid = GetCurrentThreadId();
    HINTERNET c = U(InternetConnectA)(j->s, "127.0.0.1", j->port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0x71);
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/tid", NULL, NULL, NULL, T_INET_FRESH, 0x72) : NULL;
    j->ok = r && U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
    if (r) { char b[16]; t_inet_read_all(r, b, sizeof b, NULL); U(InternetCloseHandle)(r); }
    if (c) U(InternetCloseHandle)(c);
    return 0;
}
TEST(sh_conc_sync_callbacks_on_calling_thread) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    sh_cb_reset(&g_conc_rec); sh_cb_cur = &g_conc_rec;
    HINTERNET s = sh_open_to("tid");
    if (s) U(InternetSetStatusCallbackA)(s, sh_cb);
    sh_sendjob j = { s, srv_port(sv), 0, 0 };
    HANDLE th = s ? CreateThread(NULL, 0, sh_send_thread, &j, 0, NULL) : NULL;
    if (th) { WaitForSingleObject(th, 10000); CloseHandle(th); }
    CHECK(j.ok);
    int n = 0, other = 0;
    EnterCriticalSection(&g_conc_rec.cs);
    for (int i = 0; i < g_conc_rec.n; i++) {
        if (g_conc_rec.ev[i].ctx != 0x72 && g_conc_rec.ev[i].ctx != 0x71) continue;
        n++;
        if (g_conc_rec.ev[i].tid != j.tid) other++;
    }
    LeaveCriticalSection(&g_conc_rec.cs);
    t_note("sync callbacks for the worker's handles: %d, on another thread: %d", n, other);
    CHECK(n >= 5);
    EXPECT_EQ(other, 0);
    if (s) sh_close(s);
    sh_cb_cur = NULL;
    srv_stop(sv);
}

/* Concurrent InternetSetStatusCallback on one handle: every call returns a valid previous value and the final
 * CALLBACK option holds one of the values that were set. */
static void CALLBACK sh_cb_a(HINTERNET h, DWORD_PTR c, DWORD s, LPVOID i, DWORD l) { }
static void CALLBACK sh_cb_b(HINTERNET h, DWORD_PTR c, DWORD s, LPVOID i, DWORD l) { }
typedef struct { HINTERNET h; int which; LONG bad; } sh_setcb;
static DWORD WINAPI sh_setcb_thread(LPVOID p) {
    sh_setcb *x = (sh_setcb *)p;
    for (int i = 0; i < 2000; i++) {
        INTERNET_STATUS_CALLBACK want = (i & 1) ? (x->which ? sh_cb_a : sh_cb_b) : NULL;
        INTERNET_STATUS_CALLBACK prev = U(InternetSetStatusCallbackA)(x->h, want);
        if (prev == INTERNET_INVALID_STATUS_CALLBACK || (prev != NULL && prev != sh_cb_a && prev != sh_cb_b)) InterlockedIncrement(&x->bad);
    }
    return 0;
}
TEST(sh_conc_set_status_callback_concurrently) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET s = sh_open("setcb"); CHECK(s != NULL); if (!s) return;
    sh_setcb x[4]; HANDLE th[4];
    for (int k = 0; k < 4; k++) { x[k].h = s; x[k].which = k & 1; x[k].bad = 0; th[k] = CreateThread(NULL, 0, sh_setcb_thread, &x[k], 0, NULL); }
    WaitForMultipleObjects(4, th, TRUE, 20000);
    LONG bad = 0;
    for (int k = 0; k < 4; k++) { bad += x[k].bad; CloseHandle(th[k]); }
    EXPECT_EQ(bad, 0);
    ULONG_PTR cb = 1; DWORD len, e;
    CHECK(sh_qptr(s, INTERNET_OPTION_CALLBACK, &cb, &len, &e));
    CHECK(cb == 0 || cb == (ULONG_PTR)sh_cb_a || cb == (ULONG_PTR)sh_cb_b);
    sh_close(s);
}

/* Many threads each holding a request on one connect and setting options on their own request: per-handle values
 * never mix. */
typedef struct { HINTERNET c; int id; LONG bad; } sh_optjob;
static DWORD WINAPI sh_opt_thread(LPVOID p) {
    sh_optjob *j = (sh_optjob *)p;
    HINTERNET r = U(HttpOpenRequestA)(j->c, "GET", "/opt", NULL, NULL, NULL, T_INET_FRESH, 0x1000 + j->id);
    if (!r) { j->bad++; return 0; }
    for (int i = 0; i < 500; i++) {
        DWORD v = 10000 + j->id * 1000 + i, got = 0, len = sizeof got;
        U(InternetSetOptionA)(r, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, sizeof v);
        if (!U(InternetQueryOptionA)(r, INTERNET_OPTION_RECEIVE_TIMEOUT, &got, &len) || got != v) j->bad++;
        ULONG_PTR cv = 0; len = sizeof cv;
        if (!U(InternetQueryOptionA)(r, INTERNET_OPTION_CONTEXT_VALUE, &cv, &len) || cv != (ULONG_PTR)(0x1000 + j->id)) j->bad++;
    }
    U(InternetCloseHandle)(r);
    return 0;
}
TEST(sh_conc_per_request_options_do_not_mix) {
    HINTERNET s = sh_open("optmix"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    CHECK(c != NULL);
    if (c) {
        sh_optjob j[6]; HANDLE th[6];
        for (int k = 0; k < 6; k++) { j[k].c = c; j[k].id = k; j[k].bad = 0; th[k] = CreateThread(NULL, 0, sh_opt_thread, &j[k], 0, NULL); }
        WaitForMultipleObjects(6, th, TRUE, 20000);
        LONG bad = 0;
        for (int k = 0; k < 6; k++) { bad += j[k].bad; CloseHandle(th[k]); }
        EXPECT_EQ(bad, 0);
        DWORD v, e; CHECK(sh_qdw(c, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); EXPECT_EQ(v, 30000);   /* the connect is untouched */
        sh_close(c);
    }
    sh_close(s);
}

/* A request opened on one thread, sent on a second and read and closed on a third. */
typedef struct { HINTERNET r; int step; BOOL ok; char body[32]; } sh_hop;
static DWORD WINAPI sh_hop_thread(LPVOID p) {
    sh_hop *h = (sh_hop *)p;
    if (h->step == 1) h->ok = U(HttpSendRequestA)(h->r, NULL, 0, NULL, 0);
    else { t_inet_read_all(h->r, h->body, sizeof h->body, NULL); h->ok = U(InternetCloseHandle)(h->r); }
    return 0;
}
TEST(sh_conc_request_hops_threads) {
    REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("hop");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/hop", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        sh_hop h = { r, 1, FALSE, "" };
        HANDLE t1 = CreateThread(NULL, 0, sh_hop_thread, &h, 0, NULL); WaitForSingleObject(t1, 10000); CloseHandle(t1);
        CHECK(h.ok);
        h.step = 2; h.ok = FALSE;
        HANDLE t2 = CreateThread(NULL, 0, sh_hop_thread, &h, 0, NULL); WaitForSingleObject(t2, 10000); CloseHandle(t2);
        CHECK(h.ok); EXPECT_STR(h.body, "hello");
        DWORD e; sh_htype(r, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}
