/* session_handles / handles used across threads, InternetAttemptConnect, InternetGetConnectedState(Ex).
 * Evidence: [D InternetAttemptConnect@0x1378d0, InternetGetConnectedState@0xd82e0, InternetGetConnectedStateExW@0xd8340,
 * InternetGetConnectedStateEx(A)@0x286e0]. Every wait is bounded. */
#include "sh.h"

/* ------------------------------------------------------------------ threads sharing a connect handle */
typedef struct { HINTERNET c; int iters; volatile LONG bad; volatile LONG done; } sh_thr_shared;
static DWORD WINAPI sh_thr_requests(LPVOID p) {
    sh_thr_shared *a = p;
    for (int i = 0; i < a->iters; i++) {
        HINTERNET r = sh_request(a->c, "/thr", (DWORD_PTR)(i + 1));
        if (!r) { InterlockedIncrement(&a->bad); continue; }
        if (sh_htype(r, NULL) != INTERNET_HANDLE_TYPE_HTTP_REQUEST) InterlockedIncrement(&a->bad);
        if (sh_parent(r, NULL) != a->c) InterlockedIncrement(&a->bad);
        ULONG_PTR v = 0;
        if (!sh_qptr(r, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL) || v != (ULONG_PTR)(i + 1)) InterlockedIncrement(&a->bad);
        if (!sh_close(r)) InterlockedIncrement(&a->bad);
    }
    InterlockedIncrement(&a->done);
    return 0;
}
TEST(sh_thr_shared_connect_requests) {
    HINTERNET s = sh_open("thr"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0); CHECK(c != NULL);
    if (c) {
        enum { NT = 8 };
        sh_thr_shared a = { c, 150, 0, 0 };
        HANDLE th[NT];
        for (int i = 0; i < NT; i++) th[i] = CreateThread(NULL, 0, sh_thr_requests, &a, 0, NULL);
        DWORD w = WaitForMultipleObjects(NT, th, TRUE, 30000);
        CHECKF(w < WAIT_OBJECT_0 + NT, "threads did not finish (w=%lu)", w);
        EXPECT_EQ(a.bad, 0); EXPECT_EQ(a.done, NT);
        for (int i = 0; i < NT; i++) CloseHandle(th[i]);
        EXPECT_EQ(sh_htype(c, NULL), 4);
        sh_close(c);
    }
    sh_close(s);
}

static DWORD WINAPI sh_thr_trees(LPVOID p) {
    sh_thr_shared *a = p;
    for (int i = 0; i < a->iters; i++) {
        HINTERNET s = sh_open("tree-thr");
        HINTERNET c = s ? sh_connect(s, "127.0.0.1", 80, 1) : NULL;
        HINTERNET r = c ? sh_request(c, "/", 2) : NULL;
        if (!s || !c || !r) InterlockedIncrement(&a->bad);
        if (r && sh_parent(r, NULL) != c) InterlockedIncrement(&a->bad);
        if (c && sh_parent(c, NULL) != s) InterlockedIncrement(&a->bad);
        if (s && !sh_close(s)) InterlockedIncrement(&a->bad);
        /* no post-close probe of r here: other threads may already have been given the same handle value */
    }
    InterlockedIncrement(&a->done);
    return 0;
}
TEST(sh_thr_independent_session_trees) {
    enum { NT = 8 };
    sh_thr_shared a = { NULL, 60, 0, 0 };
    HANDLE th[NT];
    for (int i = 0; i < NT; i++) th[i] = CreateThread(NULL, 0, sh_thr_trees, &a, 0, NULL);
    DWORD w = WaitForMultipleObjects(NT, th, TRUE, 30000);
    CHECKF(w < WAIT_OBJECT_0 + NT, "threads did not finish (w=%lu)", w);
    EXPECT_EQ(a.bad, 0); EXPECT_EQ(a.done, NT);
    for (int i = 0; i < NT; i++) CloseHandle(th[i]);
}

/* one writer flips the user agent, readers must always see a whole value */
typedef struct { HINTERNET s; volatile LONG stop; volatile LONG torn; volatile LONG reads; } sh_ua_arg;
static DWORD WINAPI sh_thr_ua_reader(LPVOID p) {
    sh_ua_arg *a = p;
    while (!a->stop) {
        char b[64]; DWORD len = sizeof b;
        if (U(InternetQueryOptionA)(a->s, INTERNET_OPTION_USER_AGENT, b, &len)) {
            if (strcmp(b, "agent-AAAAAAAAAAAAAAAA") && strcmp(b, "agent-BB")) InterlockedIncrement(&a->torn);
            InterlockedIncrement(&a->reads);
        }
    }
    return 0;
}
TEST(sh_thr_user_agent_concurrent_set_query) {
    HINTERNET s = sh_open("agent-AAAAAAAAAAAAAAAA"); CHECK(s != NULL); if (!s) return;
    sh_ua_arg a = { s, 0, 0, 0 };
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, sh_thr_ua_reader, &a, 0, NULL);
    int set_fail = 0;
    for (int i = 0; i < 2000; i++) {
        char *v = (i & 1) ? "agent-BB" : "agent-AAAAAAAAAAAAAAAA";
        if (!U(InternetSetOptionA)(s, INTERNET_OPTION_USER_AGENT, v, (DWORD)strlen(v))) set_fail++;
    }
    a.stop = 1;
    DWORD w = WaitForMultipleObjects(4, th, TRUE, 10000);
    CHECK(w < WAIT_OBJECT_0 + 4);
    for (int i = 0; i < 4; i++) CloseHandle(th[i]);
    EXPECT_EQ(set_fail, 0);
    /* Win10 replaces the session agent string without a lock (CWxStringA Empty+Append, [D InternetSetOptionA case 0x29]):
     * concurrent readers can observe a mixed value. Record it; never CHECK either way. */
    t_note("USER_AGENT concurrent reads %ld, torn/mixed values %ld (unsynchronised on Win10)", a.reads, a.torn);
    /* reads can be 0 on Win10: every query may hit the unlocked Empty window and fail (timing) */
    sh_close(s);
}

/* a handle created on one thread is used and closed on another */
typedef struct { HINTERNET h; DWORD type; BOOL closed; } sh_xt_arg;
static DWORD WINAPI sh_thr_use_close(LPVOID p) {
    sh_xt_arg *a = p;
    a->type = sh_htype(a->h, NULL);
    a->closed = sh_close(a->h);
    return 0;
}
TEST(sh_thr_close_on_other_thread) {
    HINTERNET s = sh_open("xt"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    sh_xt_arg a = { c, 0, FALSE };
    HANDLE th = CreateThread(NULL, 0, sh_thr_use_close, &a, 0, NULL);
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0);
    CloseHandle(th);
    EXPECT_EQ(a.type, 4); CHECK(a.closed);
    DWORD e; sh_htype(c, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    sh_xt_arg b = { s, 0, FALSE };
    th = CreateThread(NULL, 0, sh_thr_use_close, &b, 0, NULL);
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0);
    CloseHandle(th);
    EXPECT_EQ(b.type, 1); CHECK(b.closed);
}

/* GETs on one shared session from several threads, against a keep-alive loopback server */
typedef struct { HINTERNET s; srv *sv; int idx; int ok200; int bodyok; } sh_get_arg;
static DWORD WINAPI sh_thr_get(LPVOID p) {
    sh_get_arg *a = p;
    for (int i = 0; i < 5; i++) {
        char path[32]; snprintf(path, sizeof path, "/t%d/%d", a->idx, i);
        char body[32]; size_t n; DWORD err;
        int st = t_http_get(a->s, srv_url(a->sv, path), NULL, T_INET_FRESH, body, sizeof body, &n, &err);
        if (st == 200) a->ok200++;
        if (!strcmp(body, "hello")) a->bodyok++;
    }
    return 0;
}
TEST(sh_thr_shared_session_parallel_gets) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("par"); CHECK(s != NULL);
    if (s) {
        enum { NT = 4 };
        sh_get_arg a[NT]; HANDLE th[NT];
        for (int i = 0; i < NT; i++) { a[i] = (sh_get_arg){ s, sv, i, 0, 0 }; th[i] = CreateThread(NULL, 0, sh_thr_get, &a[i], 0, NULL); }
        DWORD w = WaitForMultipleObjects(NT, th, TRUE, 30000);
        CHECKF(w < WAIT_OBJECT_0 + NT, "GET threads did not finish");
        for (int i = 0; i < NT; i++) { EXPECT_EQ(a[i].ok200, 5); EXPECT_EQ(a[i].bodyok, 5); CloseHandle(th[i]); }
        CHECK(srv_wait_requests(sv, NT * 5, 3000));
        EXPECT_EQ(srv_req_count(sv), NT * 5);
        t_note("parallel GETs: %d requests over %d connections", srv_req_count(sv), srv_conn_count(sv));
        sh_close(s);
    }
    srv_stop(sv);
}

/* EXTENDED_ERROR is per thread and readable with a NULL handle */
static DWORD WINAPI sh_thr_ext_err(LPVOID p) {
    DWORD v = 0xffff, len = sizeof v;
    *(BOOL *)p = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_EXTENDED_ERROR, &v, &len) && len == 4;
    return 0;
}
TEST(sh_thr_extended_error_null_handle) {
    DWORD v = 0xffff, len = sizeof v;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_EXTENDED_ERROR, &v, &len));
    EXPECT_EQ(len, 4);
    t_note("EXTENDED_ERROR on this thread: %lu", v);
    BOOL ok = FALSE;
    HANDLE th = CreateThread(NULL, 0, sh_thr_ext_err, &ok, 0, NULL);
    CHECK(WaitForSingleObject(th, 5000) == WAIT_OBJECT_0);
    CloseHandle(th);
    CHECK(ok);
}

/* ------------------------------------------------------------------ InternetAttemptConnect */
TEST(sh_attempt_connect) {
    REQUIRE(U(InternetAttemptConnect));
    SetLastError(0x1234);
    EXPECT_EQ(U(InternetAttemptConnect)(0), ERROR_SUCCESS);
    EXPECT_EQ(GetLastError(), 0x1234);          /* returns the code, does not touch the last error */
    const DWORD bad[] = { 1, 2, 0x80000000u, 0xffffffffu };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        SetLastError(0x1234);
        DWORD r = U(InternetAttemptConnect)(bad[i]);
        CHECKF(r == ERROR_INVALID_PARAMETER, "InternetAttemptConnect(0x%lx) = %lu", bad[i], r);
        EXPECT_EQ(GetLastError(), 0x1234);
    }
}

/* ------------------------------------------------------------------ InternetGetConnectedState(Ex) */
#define SH_CONN_KNOWN (INTERNET_CONNECTION_MODEM | INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_PROXY | INTERNET_CONNECTION_MODEM_BUSY | \
                       INTERNET_RAS_INSTALLED | INTERNET_CONNECTION_OFFLINE | INTERNET_CONNECTION_CONFIGURED)
TEST(sh_connected_state_shape) {
    REQUIRE(U(InternetGetConnectedState));
    DWORD f = 0xffffffff;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetConnectedState)(&f, 0);
    DWORD e = GetLastError();
    t_note("InternetGetConnectedState: ret=%d flags=0x%lx GLE=%lu", r, f, e);
    EXPECT_EQ(f & ~SH_CONN_KNOWN, 0);
    CHECK(f != 0xffffffff);
    if (r) CHECK(f & (INTERNET_CONNECTION_LAN | INTERNET_CONNECTION_MODEM));
    /* NULL flags pointer is allowed */
    BOOL r2 = U(InternetGetConnectedState)(NULL, 0);
    EXPECT_EQ(r2, r);
}

TEST(sh_connected_state_reserved_87) {
    REQUIRE(U(InternetGetConnectedState));
    DWORD f = 0xffffffff;
    SetLastError(0);
    BOOL r = U(InternetGetConnectedState)(&f, 1);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    EXPECT_EQ(f, 0);   /* zeroed before the reserved check */
    REQUIRE(U(InternetGetConnectedStateExW));
    WCHAR name[64] = L"zz"; f = 0xffffffff;
    SetLastError(0);
    r = U(InternetGetConnectedStateExW)(&f, name, 64, 7);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    EXPECT_EQ(f, 0); EXPECT_EQ(name[0], 0);
}

TEST(sh_connected_state_ex_w_shape) {
    REQUIRE(U(InternetGetConnectedStateExW)); REQUIRE(U(InternetGetConnectedState));
    DWORD f = 0, f0 = 0;
    BOOL r0 = U(InternetGetConnectedState)(&f0, 0);
    WCHAR name[256]; memset(name, 0xcc, sizeof name);
    BOOL r = U(InternetGetConnectedStateExW)(&f, name, 256, 0);
    char an[256] = ""; WideCharToMultiByte(CP_ACP, 0, name, -1, an, sizeof an, NULL, NULL);
    t_note("InternetGetConnectedStateExW: ret=%d flags=0x%lx name=[%s]", r, f, an);
    EXPECT_EQ(r, r0); EXPECT_EQ(f, f0);
    CHECK(lstrlenW(name) < 256);
    if (f & INTERNET_CONNECTION_LAN) CHECK(name[0] != 0);
    /* no name buffer */
    DWORD f2 = 0;
    EXPECT_EQ(U(InternetGetConnectedStateExW)(&f2, NULL, 0, 0), r);
    EXPECT_EQ(f2, f);
}

TEST(sh_connected_state_ex_a_shape) {
    REQUIRE(U(InternetGetConnectedStateExA)); REQUIRE(U(InternetGetConnectedStateExW));
    DWORD fa = 0, fw = 0;
    char an[256]; memset(an, 'x', sizeof an);
    WCHAR wn[256];
    BOOL ra = U(InternetGetConnectedStateExA)(&fa, an, sizeof an, 0);
    BOOL rw = U(InternetGetConnectedStateExW)(&fw, wn, 256, 0);
    EXPECT_EQ(ra, rw); EXPECT_EQ(fa, fw);
    char conv[256] = ""; WideCharToMultiByte(CP_ACP, 0, wn, -1, conv, sizeof conv, NULL, NULL);
    EXPECT_STR(an, conv);
    /* the undecorated export is the A form (same RVA) */
    FARPROC p1 = t_proc_in("wininet.dll", "InternetGetConnectedStateEx"), p2 = t_proc_in("wininet.dll", "InternetGetConnectedStateExA");
    CHECK(p1 != NULL && p1 == p2);
    /* a short A buffer is truncated and still NUL-terminated */
    if (strlen(an) > 3) {
        char small[4]; memset(small, 'q', sizeof small); DWORD f3;
        U(InternetGetConnectedStateExA)(&f3, small, sizeof small, 0);
        EXPECT_EQ(small[3], 0);
    }
}
