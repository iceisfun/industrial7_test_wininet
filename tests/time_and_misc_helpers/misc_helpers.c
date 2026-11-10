/* Small non-UI helpers: dial/online family, zone crossing, InternetErrorDlg NO-UI paths, ResumeSuspendedDownload,
 * InternetAttemptConnect, InternetCheckConnection, connected state, Fortezza and autodial stubs.
 * VM_TIMEOUT: 180 */
#include "tm.h"
#include "srv.h"
#include "tnet.h"

/* ------------------------------------------------------------ bounded runner */
typedef struct { tm_fn fn; void *arg; } tm_job;
static DWORD WINAPI tm_job_thread(void *p) { tm_job *j = (tm_job *)p; j->fn(j->arg); return 0; }
int tm_run_bounded(tm_fn fn, void *arg, DWORD ms) {
    tm_job *j = (tm_job *)malloc(sizeof *j); j->fn = fn; j->arg = arg;
    HANDLE h = CreateThread(NULL, 0, tm_job_thread, j, 0, NULL);
    if (!h) { free(j); return 0; }
    DWORD w = WaitForSingleObject(h, ms);
    CloseHandle(h);
    if (w != WAIT_OBJECT_0) { t_note("bounded call did not return within %lu ms (UI?) - thread leaked", ms); return 0; }
    free(j);
    return 1;
}

/* ------------------------------------------------------------ InternetGoOnline [D InternetGoOnline@0x13c830, W@0x13c8f0]
 * flags & ~3 -> FALSE, 87; else TRUE (RAS API set present on desktop Win10), GLE 0. The URL and HWND are not used. */
TEST(tmh_goonline_flags_table) {
    REQUIRE(U(InternetGoOnlineA)); REQUIRE(U(InternetGoOnlineW));
    static const DWORD bad[] = { 4, 8, 0x10, 0x100, 0x80000000u, 0xFFFFFFFFu, 7 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        SET_ERR(0);
        CHECKF(!U(InternetGoOnlineA)("http://127.0.0.1/", NULL, bad[i]), "A flags=0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0);
        CHECKF(!U(InternetGoOnlineW)(L"http://127.0.0.1/", NULL, bad[i]), "W flags=0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(tmh_goonline_valid_flags) {
    REQUIRE(U(InternetGoOnlineA)); REQUIRE(U(InternetGoOnlineW));
    for (DWORD f = 0; f < 4; f++) {
        SET_ERR(0xdead);
        BOOL r = U(InternetGoOnlineA)("http://127.0.0.1/", NULL, f);
        DWORD e = GetLastError();
        CHECKF(r && e == 0, "A flags=%lu r=%d e=%lu", f, r, e);
        SET_ERR(0xdead);
        r = U(InternetGoOnlineW)(NULL, NULL, f);
        e = GetLastError();
        CHECKF(r && e == 0, "W flags=%lu r=%d e=%lu", f, r, e);
    }
}

TEST(tmh_goonline_plain_alias) {
    REQUIRE(UN(InternetGoOnline));
    SET_ERR(0); CHECK(!UN(InternetGoOnline)(NULL, NULL, 4)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); CHECK(UN(InternetGoOnline)(NULL, NULL, 0)); EXPECT_ERR(0);
}

/* ------------------------------------------------------------ InternetSetDialState [D @0x13ca50]: always FALSE, 120 */
TEST(tmh_setdialstate_always_120) {
    REQUIRE(U(InternetSetDialStateA)); REQUIRE(U(InternetSetDialStateW)); REQUIRE(UN(InternetSetDialState));
    static const DWORD states[] = { 0, 1, 2, 0xFFFFFFFFu };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0); CHECK(!U(InternetSetDialStateA)("conn", states[i], 0));      EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        SET_ERR(0); CHECK(!U(InternetSetDialStateW)(L"conn", states[i], 0));     EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        SET_ERR(0); CHECK(!UN(InternetSetDialState)(NULL, states[i], 1));        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        SET_ERR(0); CHECK(!U(InternetSetDialStateA)(NULL, states[i], 0xFFFFFFFFu)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    }
}

/* ------------------------------------------------------------ InternetAutodial / Hangup [D @0x13c520, @0x13c5e0] */
TEST(tmh_autodial_flags) {
    REQUIRE(U(InternetAutodial));
    for (int b = 4; b < 32; b++) {
        SET_ERR(0);
        CHECKF(!U(InternetAutodial)(1u << b, NULL), "flag bit %d", b);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    for (DWORD f = 0; f < 16; f++) {
        SET_ERR(0xdead);
        BOOL r = U(InternetAutodial)(f, NULL);
        DWORD e = GetLastError();
        CHECKF(r && e == 0, "flags=%lu r=%d e=%lu", f, r, e);
    }
}

TEST(tmh_autodial_hangup) {
    REQUIRE(U(InternetAutodialHangup));
    static const DWORD bad[] = { 1, 2, 0x80000000u, 0xFFFFFFFFu };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0); CHECKF(!U(InternetAutodialHangup)(bad[i]), "reserved=0x%lx", bad[i]); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    SET_ERR(0xdead); CHECK(U(InternetAutodialHangup)(0)); EXPECT_ERR(0);
}

/* ------------------------------------------------------------ InternetDial / HangUp [D @0x13c690, @0x13c9b0]
 * Return a Win32 code (not a BOOL) and never call SetLastError. *lpdwConnection = 0 first. */
TEST(tmh_dial_args) {
    REQUIRE(U(InternetDialA)); REQUIRE(U(InternetDialW));
    DWORD_PTR conn = 0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(U(InternetDialA)(NULL, "x", 0, NULL, 0), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
    conn = 0x1234;
    EXPECT_EQ(U(InternetDialA)(NULL, "x", 0, &conn, 1), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(conn, 0);                         /* zeroed before the reserved check */
    conn = 0x1234;
    EXPECT_EQ(U(InternetDialW)(NULL, L"x", 0, &conn, 0xFFFFFFFFu), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(conn, 0);
    EXPECT_EQ(U(InternetDialW)(NULL, L"x", 0, NULL, 1), ERROR_INVALID_PARAMETER);
}

TEST(tmh_dial_success_is_noop) {
    REQUIRE(U(InternetDialA)); REQUIRE(U(InternetDialW)); REQUIRE(UN(InternetDial));
    DWORD_PTR conn = 0x1234;
    SET_ERR(0x4242);
    EXPECT_EQ(U(InternetDialA)(NULL, "i7-no-such-connectoid", INTERNET_DIAL_UNATTENDED, &conn, 0), 0);
    EXPECT_EQ(conn, 0); EXPECT_ERR(0x4242);
    conn = 7;
    EXPECT_EQ(U(InternetDialW)(NULL, NULL, 0, &conn, 0), 0); EXPECT_EQ(conn, 0);
    conn = 7;
    EXPECT_EQ(UN(InternetDial)(NULL, NULL, 0, &conn, 0), 0); EXPECT_EQ(conn, 0);
}

TEST(tmh_hangup) {
    REQUIRE(U(InternetHangUp));
    SET_ERR(0x4242);
    EXPECT_EQ(U(InternetHangUp)(0, 1), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(U(InternetHangUp)(0x1234, 0xFFFFFFFFu), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(U(InternetHangUp)(0, 0), 0);
    EXPECT_EQ(U(InternetHangUp)(0x1234, 0), 0);
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------ InternetAttemptConnect [D @0x1378d0] */
TEST(tmh_attempt_connect) {
    REQUIRE(U(InternetAttemptConnect));
    SET_ERR(0x4242);
    EXPECT_EQ(U(InternetAttemptConnect)(0), 0);
    for (int b = 0; b < 32; b++) EXPECT_EQ(U(InternetAttemptConnect)(1u << b), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(U(InternetAttemptConnect)(0xFFFFFFFFu), ERROR_INVALID_PARAMETER);
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------ Fortezza / autodial callback stubs */
TEST(tmh_fortezza_stubs) {
    REQUIRE(UN(InternetFortezzaCommand)); REQUIRE(UN(InternetQueryFortezzaStatus));
    DWORD st = 0x77;
    SET_ERR(0); CHECK(!UN(InternetFortezzaCommand)(0, NULL, 0));        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    SET_ERR(0); CHECK(!UN(InternetFortezzaCommand)(1, NULL, 0));        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    SET_ERR(0); CHECK(!UN(InternetFortezzaCommand)(2, NULL, 0));        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    SET_ERR(0); CHECK(!UN(InternetQueryFortezzaStatus)(&st, 0));        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    EXPECT_EQ(st, 0x77);
    SET_ERR(0); CHECK(!UN(InternetQueryFortezzaStatus)(NULL, 0));       EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
}

TEST(tmh_autodial_callback_noop) {
    REQUIRE(UN(InternetAutodialCallback));
    SET_ERR(0x4242);
    UN(InternetAutodialCallback)(0, NULL);
    UN(InternetAutodialCallback)(1, NULL);
    UN(InternetAutodialCallback)(0xFFFFFFFFu, NULL);
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------ InternetConfirmZoneCrossing [D @0x185370, W@0x27970,
 * ConfirmZoneCrossing@0x27a8c, CrackSchemeA@0x13ad2c]. With hWnd == NULL no UI is possible; the DWORD result is
 * 0 unless exactly one side is https: http->https 12039, https->(not https/javascript/vbscript) 12040.
 * A URL without ':' or with an unknown scheme counts as scheme -1. bPost is ignored. */
typedef struct { const char *from, *to; DWORD want; } zc_case;
static const zc_case zc[] = {
    { "http://a/", "http://b/", 0 },
    { "https://a/", "https://b/", 0 },
    { "http://a/", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "https://a/", "http://a/", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "ftp://a/", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "https://a/", "ftp://a/", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "file:///c:/x", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "https://a/", "file:///c:/x", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "https://a/", "javascript:alert(1)", 0 },
    { "https://a/", "vbscript:msgbox(1)", 0 },
    { "javascript:x", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "https://a/", "mailto:x@y", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "https://a/", "nocolon", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "nocolon", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "nocolon", "http://a/", 0 },
    { "nocolon", "alsonocolon", 0 },
    { "https://a/", "i7unknownscheme:x", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "i7unknownscheme:x", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "i7unknownscheme:x", "http://a/", 0 },
    { "http://a/", "ftp://a/", 0 },
    { "ftp://a/", "file:///x", 0 },
    { "https:", "https:", 0 },
    { ":https", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "https://a/", "", ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR },
    { "", "https://a/", ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR },
    { "https://127.0.0.1:443/x?y#z", "https://other/", 0 },
};

TEST(tmh_zone_crossing_a_table) {
    REQUIRE(U(InternetConfirmZoneCrossingA));
    for (size_t i = 0; i < sizeof zc / sizeof zc[0]; i++)
        for (int post = 0; post < 2; post++) {
            SET_ERR(0x4242);
            DWORD r = U(InternetConfirmZoneCrossingA)(NULL, (LPSTR)zc[i].from, (LPSTR)zc[i].to, post);
            CHECKF(r == zc[i].want, "A [%s] -> [%s] post=%d got %lu want %lu", zc[i].from, zc[i].to, post, r, zc[i].want);
            EXPECT_ERR(0x4242);
        }
}

TEST(tmh_zone_crossing_w_table) {
    REQUIRE(U(InternetConfirmZoneCrossingW));
    for (size_t i = 0; i < sizeof zc / sizeof zc[0]; i++) {
        WCHAR f[128], t2[128];
        MultiByteToWideChar(CP_ACP, 0, zc[i].from, -1, f, 128);
        MultiByteToWideChar(CP_ACP, 0, zc[i].to, -1, t2, 128);
        DWORD r = U(InternetConfirmZoneCrossingW)(NULL, f, t2, FALSE);
        CHECKF(r == zc[i].want, "W [%s] -> [%s] got %lu want %lu", zc[i].from, zc[i].to, r, zc[i].want);
    }
}

TEST(tmh_zone_crossing_plain_alias) {
    REQUIRE(UN(InternetConfirmZoneCrossing));
    EXPECT_EQ(UN(InternetConfirmZoneCrossing)(NULL, "http://a/", "https://a/", FALSE), ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR);
    EXPECT_EQ(UN(InternetConfirmZoneCrossing)(NULL, "https://a/", "http://a/", TRUE), ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR);
}

TEST(tmh_zone_crossing_null_first_url) {
    /* lpszUrlPrev == NULL -> 0 before either URL is parsed [D] */
    REQUIRE(U(InternetConfirmZoneCrossingA)); REQUIRE(U(InternetConfirmZoneCrossingW));
    EXPECT_EQ(U(InternetConfirmZoneCrossingA)(NULL, NULL, "https://a/", FALSE), 0);
    EXPECT_EQ(U(InternetConfirmZoneCrossingA)(NULL, NULL, NULL, FALSE), 0);
    EXPECT_EQ(U(InternetConfirmZoneCrossingW)(NULL, NULL, L"https://a/", TRUE), 0);
    EXPECT_EQ(U(InternetConfirmZoneCrossingW)(NULL, NULL, NULL, FALSE), 0);
}

TEST(tmh_zone_crossing_scheme_case) {
    REQUIRE(U(InternetConfirmZoneCrossingA));
    DWORD r1 = U(InternetConfirmZoneCrossingA)(NULL, "http://a/", "HTTPS://a/", FALSE);
    DWORD r2 = U(InternetConfirmZoneCrossingA)(NULL, "HTTPS://a/", "https://a/", FALSE);
    DWORD r3 = U(InternetConfirmZoneCrossingA)(NULL, "HtTpS://a/", "HTTP://a/", FALSE);
    t_note("scheme case: http->HTTPS %lu, HTTPS->https %lu, HtTpS->HTTP %lu", r1, r2, r3);
    EXPECT_EQ(r1, ERROR_INTERNET_HTTP_TO_HTTPS_ON_REDIR);
    EXPECT_EQ(r2, 0);
    EXPECT_EQ(r3, ERROR_INTERNET_HTTPS_TO_HTTP_ON_REDIR);
}

/* ------------------------------------------------------------ InternetErrorDlg: paths that end before any UI
 * [D InternetErrorDlg@0x185430]: 12053 -> 120 immediately; hRequest NULL with 12014/12034/12044 -> 87; unmapped
 * handle -> 6; a non-request handle -> 0; 12161/12907 with FLAGS_ERROR_UI_FLAGS_NO_UI -> 12162. Every call runs
 * on a bounded worker thread with hWnd = NULL as a safety net. */
typedef struct { HWND hwnd; HINTERNET h; DWORD err, flags; DWORD ret; void *data; } ed_args;
static void ed_call(void *p) { ed_args *a = (ed_args *)p; a->ret = U(InternetErrorDlg)(a->hwnd, a->h, a->err, a->flags, a->data ? &a->data : NULL); }
static int ed(HINTERNET h, DWORD err, DWORD flags, DWORD *ret) {
    static ed_args a; a.hwnd = NULL; a.h = h; a.err = err; a.flags = flags; a.ret = 0xFFFFFFFFu; a.data = NULL;
    int ok = tm_run_bounded(ed_call, &a, 8000);
    *ret = a.ret;
    return ok;
}

TEST(tmh_errordlg_insert_cdrom_120) {
    REQUIRE(U(InternetErrorDlg));
    DWORD r;
    static const DWORD fl[] = { FLAGS_ERROR_UI_FLAGS_NO_UI, FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FILTER_FOR_ERRORS,
                                FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA | FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS };
    for (int i = 0; i < 3; i++) {
        CHECK(ed(NULL, ERROR_INTERNET_INSERT_CDROM, fl[i], &r));
        EXPECT_EQ(r, ERROR_CALL_NOT_IMPLEMENTED);
        CHECK(ed((HINTERNET)(ULONG_PTR)0x7FFF0000, ERROR_INTERNET_INSERT_CDROM, fl[i], &r));
        EXPECT_EQ(r, ERROR_CALL_NOT_IMPLEMENTED);   /* checked before the handle */
    }
}

TEST(tmh_errordlg_null_request_87) {
    REQUIRE(U(InternetErrorDlg));
    static const DWORD errs[] = { ERROR_INTERNET_INCORRECT_PASSWORD, ERROR_INTERNET_NEED_UI, ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED };
    for (int i = 0; i < 3; i++) {
        DWORD r;
        CHECK(ed(NULL, errs[i], FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
        CHECKF(r == ERROR_INVALID_PARAMETER, "err %lu -> %lu", errs[i], r);
        CHECK(ed(NULL, errs[i], FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_FLAGS_GENERATE_DATA, &r));
        CHECKF(r == ERROR_INVALID_PARAMETER, "err %lu (gen data) -> %lu", errs[i], r);
    }
}

TEST(tmh_errordlg_unmapped_handle_6) {
    REQUIRE(U(InternetErrorDlg));
    static const DWORD errs[] = { ERROR_INTERNET_INCORRECT_PASSWORD, ERROR_INTERNET_SEC_CERT_CN_INVALID, ERROR_INTERNET_INVALID_CA,
                                  ERROR_HTTP_REDIRECT_NEEDS_CONFIRMATION, 0 };
    for (int i = 0; i < 5; i++) {
        DWORD r;
        CHECK(ed((HINTERNET)(ULONG_PTR)0x7FFF0000, errs[i], FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
        CHECKF(r == ERROR_INVALID_HANDLE, "err %lu -> %lu", errs[i], r);
    }
}

TEST(tmh_errordlg_non_request_handle_0) {
    REQUIRE(U(InternetErrorDlg)); REQUIRE(U(InternetConnectA));
    HINTERNET hi = t_inet_open("ed");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    CHECK(hc != NULL);
    DWORD r;
    CHECK(ed(hi, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
    t_note("session handle -> %lu", r);
    EXPECT_EQ(r, 0);
    if (hc) {
        CHECK(ed(hc, ERROR_INTERNET_SEC_CERT_CN_INVALID, FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
        t_note("connect handle -> %lu", r);
        EXPECT_EQ(r, 0);
    }
    t_inet_close(hc); t_inet_close(hi);
}

TEST(tmh_errordlg_cookie_no_ui_declined) {
    REQUIRE(U(InternetErrorDlg));
    DWORD r;
    CHECK(ed(NULL, ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION, FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
    EXPECT_EQ(r, ERROR_HTTP_COOKIE_DECLINED);
    CHECK(ed(NULL, 12907, FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
    EXPECT_EQ(r, ERROR_HTTP_COOKIE_DECLINED);
    CHECK(ed(NULL, ERROR_HTTP_COOKIE_NEEDS_CONFIRMATION, FLAGS_ERROR_UI_FLAGS_NO_UI | FLAGS_ERROR_UI_SERIALIZE_DIALOGS, &r));
    EXPECT_EQ(r, ERROR_HTTP_COOKIE_DECLINED);
}

TEST(tmh_errordlg_closed_handle_6) {
    REQUIRE(U(InternetErrorDlg)); REQUIRE(U(InternetCloseHandle));
    HINTERNET hi = t_inet_open("edc");
    CHECK(hi != NULL); if (!hi) return;
    U(InternetCloseHandle)(hi);
    DWORD r;
    CHECK(ed(hi, ERROR_INTERNET_INCORRECT_PASSWORD, FLAGS_ERROR_UI_FLAGS_NO_UI, &r));
    EXPECT_EQ(r, ERROR_INVALID_HANDLE);
}

/* ------------------------------------------------------------ ResumeSuspendedDownload [D @0x13c410]
 * unmapped -> FALSE, 6; a request handle not blocked on user input -> FALSE, 12017 (never TRUE: success = 997). */
TEST(tmh_resume_suspended_download) {
    REQUIRE(U(ResumeSuspendedDownload)); REQUIRE(U(HttpOpenRequestA)); REQUIRE(U(InternetConnectA));
    SET_ERR(0); CHECK(!U(ResumeSuspendedDownload)(NULL, 0));                         EXPECT_ERR(ERROR_INVALID_HANDLE);
    SET_ERR(0); CHECK(!U(ResumeSuspendedDownload)((HINTERNET)(ULONG_PTR)0x7FFF0000, 1)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    HINTERNET hi = t_inet_open("rsd");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, INTERNET_FLAG_NO_UI, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        static const DWORD results[] = { 0, ERROR_SUCCESS, ERROR_CANCELLED, 0xFFFFFFFFu };
        for (int i = 0; i < 4; i++) {
            SET_ERR(0);
            BOOL r = U(ResumeSuspendedDownload)(hr, results[i]);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_INTERNET_OPERATION_CANCELLED, "result=%lu r=%d e=%lu", results[i], r, e);
        }
    }
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
    SET_ERR(0); CHECK(!U(ResumeSuspendedDownload)(hr ? hr : (HINTERNET)(ULONG_PTR)0x7FFF0004, 0)); EXPECT_ERR(ERROR_INVALID_HANDLE);
}

/* ------------------------------------------------------------ InternetCheckConnection [D @0x137a50] */
TEST(tmh_check_connection_reserved) {
    REQUIRE(U(InternetCheckConnectionA)); REQUIRE(U(InternetCheckConnectionW));
    SET_ERR(0); CHECK(!U(InternetCheckConnectionA)("http://127.0.0.1/", 0, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetCheckConnectionA)(NULL, FLAG_ICC_FORCE_CONNECTION, 0xFFFFFFFFu)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetCheckConnectionW)(L"http://127.0.0.1/", 0, 2)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tmh_check_connection_force_loopback) {
    REQUIRE(U(InternetCheckConnectionA)); REQUIRE(U(InternetCheckConnectionW));
    srv *s = srv_http(NULL, 0);
    if (!s) { t_skip("server unavailable"); return; }
    SET_ERR(0xdead);
    BOOL r = U(InternetCheckConnectionA)(srv_url(s, "/icc"), FLAG_ICC_FORCE_CONNECTION, 0);
    DWORD e = GetLastError();
    t_note("ICC force A to live loopback: r=%d e=%lu conns=%d", r, e, srv_conn_count(s));
    CHECK(r);
    CHECK(srv_wait_events(s, SRV_EV_ACCEPT, 1, 3000));
    WCHAR wu[128]; MultiByteToWideChar(CP_ACP, 0, srv_url(s, "/iccw"), -1, wu, 128);
    r = U(InternetCheckConnectionW)(wu, FLAG_ICC_FORCE_CONNECTION, 0);
    CHECK(r);
    CHECK(srv_wait_events(s, SRV_EV_ACCEPT, 2, 3000));
    CHECK(srv_req_count(s) == 0);           /* a TCP probe only: no HTTP request is sent */
    srv_stop(s);
}

TEST(tmh_check_connection_force_refused) {
    REQUIRE(U(InternetCheckConnectionA));
    srv *s = srv_http(NULL, 0);
    if (!s) { t_skip("server unavailable"); return; }
    char url[128]; snprintf(url, sizeof url, "%s", srv_url(s, "/"));
    srv_stop(s);                                 /* port now closed */
    SET_ERR(0);
    BOOL r = U(InternetCheckConnectionA)(url, FLAG_ICC_FORCE_CONNECTION, 0);
    DWORD e = GetLastError();
    t_note("ICC force to closed port: r=%d e=%lu", r, e);
    CHECK(!r);
    EXPECT_EQ(e, ERROR_INTERNET_CANNOT_CONNECT);
}

CHILD(icc_fresh) {
    /* fresh process: no server is known yet */
    int mode = argc > 1 ? atoi(argv[1]) : 0;
    SetLastError(0);
    BOOL r = mode == 0 ? U(InternetCheckConnectionA)(NULL, 0, 0)
           : mode == 1 ? U(InternetCheckConnectionA)(NULL, FLAG_ICC_FORCE_CONNECTION, 0)
                       : U(InternetCheckConnectionA)("http://127.0.0.1:9/", 0, 0);
    DWORD e = GetLastError();
    return (r ? 0x10000 : 0) | (int)(e & 0xFFFF);
}
TEST(tmh_check_connection_fresh_process) {
    REQUIRE(U(InternetCheckConnectionA));
    DWORD c0 = t_run_child("icc_fresh", "0", 20000);
    DWORD c1 = t_run_child("icc_fresh", "1", 20000);
    DWORD c2 = t_run_child("icc_fresh", "2", 20000);
    t_note("fresh ICC(NULL,0)=0x%lx ICC(NULL,FORCE)=0x%lx ICC(url,0)=0x%lx", c0, c1, c2);
    EXPECT_EQ(c0, ERROR_NOT_CONNECTED);                  /* no nearest server -> 2250 */
    EXPECT_EQ(c1, ERROR_INTERNET_INVALID_OPERATION);     /* FORCE without URL and no server -> 12016 */
    EXPECT_EQ(c2, ERROR_NOT_CONNECTED);                  /* URL without FORCE is not probed */
}

/* ------------------------------------------------------------ connected state (environment: notes + argument checks) */
TEST(tmh_connected_state_notes) {
    REQUIRE(U(InternetGetConnectedState)); REQUIRE(U(InternetGetConnectedStateExA)); REQUIRE(U(InternetGetConnectedStateExW));
    DWORD f = 0xFFFFFFFF;
    SET_ERR(0xdead);
    BOOL r = U(InternetGetConnectedState)(&f, 0);
    t_note("InternetGetConnectedState r=%d flags=0x%lx gle=%lu", r, f, GetLastError());
    CHECK((f & ~0x7Fu) == 0);                             /* only INTERNET_CONNECTION_* bits */
    char name[256]; DWORD fa = 0xFFFFFFFF;
    r = U(InternetGetConnectedStateExA)(&fa, name, sizeof name, 0);
    t_note("ExA r=%d flags=0x%lx name=[%s]", r, fa, name);
    WCHAR wname[256]; DWORD fw = 0xFFFFFFFF;
    r = U(InternetGetConnectedStateExW)(&fw, wname, 256, 0);
    t_note("ExW r=%d flags=0x%lx", r, fw);
    EXPECT_EQ(fa, f); EXPECT_EQ(fw, f);
    SET_ERR(0xdead);
    r = U(InternetGetConnectedState)(NULL, 0);
    t_note("NULL flags r=%d gle=%lu", r, GetLastError());
}

TEST(tmh_connected_state_reserved) {
    REQUIRE(U(InternetGetConnectedState)); REQUIRE(U(InternetGetConnectedStateExW));
    DWORD f = 0x1234;
    SET_ERR(0);
    BOOL r = U(InternetGetConnectedState)(&f, 1);
    DWORD e = GetLastError();
    t_note("reserved=1: r=%d e=%lu flags=0x%lx", r, e, f);
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    EXPECT_EQ(f, 0);                                     /* zeroed before the checks [D] */
    WCHAR nm[8] = L"zz"; f = 0x1234;
    SET_ERR(0);
    r = U(InternetGetConnectedStateExW)(&f, nm, 8, 5);
    e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_PARAMETER); EXPECT_EQ(nm[0], 0);
}
