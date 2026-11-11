/* fc_async.c - FTP on an INTERNET_FLAG_ASYNC session.
 * FtpConnect (decomp): on an async session InternetConnect(FTP) runs the non-blocking state machine
 * (FtpConnectNonBlocking -> CFsm_FtpConnect queued, ERROR_IO_PENDING, NULL handle) only when dwContext != 0;
 * with a zero context it connects synchronously (FtpConnectBlocking) and returns the handle.
 * Completion arrives as INTERNET_STATUS_REQUEST_COMPLETE (INTERNET_ASYNC_RESULT: dwResult = handle / BOOL).
 * All waits are bounded (5 s). */
#include "ftp.h"

typedef struct {
    HANDLE done;
    volatile LONG n;
    DWORD st[96];
    DWORD_PTR res; DWORD err;
    HINTERNET created;
    volatile LONG completes;
} acb;
static acb A;

static void CALLBACK async_cb(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    LONG i = InterlockedIncrement(&A.n) - 1;
    if (i < 96) A.st[i] = status;
    if (status == INTERNET_STATUS_HANDLE_CREATED && info && len >= sizeof(INTERNET_ASYNC_RESULT) && !A.created)
        A.created = (HINTERNET)((INTERNET_ASYNC_RESULT *)info)->dwResult;
    if (status == INTERNET_STATUS_REQUEST_COMPLETE) {
        if (info) { A.res = ((INTERNET_ASYNC_RESULT *)info)->dwResult; A.err = ((INTERNET_ASYNC_RESULT *)info)->dwError; }
        InterlockedIncrement(&A.completes);
        if (A.done) SetEvent(A.done);
    }
}
static void acb_reset(void) {
    if (!A.done) A.done = CreateEventA(NULL, FALSE, FALSE, NULL);
    ResetEvent(A.done);
    A.n = 0; A.res = 0; A.err = 0; A.created = NULL; A.completes = 0;
}
static void acb_dump(const char *what) {
    char b[768]; size_t o = 0; int n = A.n < 96 ? A.n : 96; b[0] = 0;
    for (int i = 0; i < n && o < sizeof b - 16; i++) o += snprintf(b + o, sizeof b - o, "%s%lu", i ? "," : "", A.st[i]);
    t_note("%s: callbacks %s; completes=%ld res=0x%llx err=%lu", what, b, A.completes, (unsigned long long)A.res, A.err);
}
static int acb_wait(DWORD ms) { return WaitForSingleObject(A.done, ms) == WAIT_OBJECT_0; }

static HINTERNET async_session(void) {
    HINTERNET hi = U(InternetOpenA)("ftpc-async", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, INTERNET_FLAG_ASYNC);
    if (!hi) return NULL;
    DWORD to = 5000;
    U(InternetSetOptionA)(hi, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
    U(InternetSetOptionA)(hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    U(InternetSetOptionA)(hi, INTERNET_OPTION_SEND_TIMEOUT, &to, sizeof to);
    acb_reset();
    U(InternetSetStatusCallbackA)(hi, async_cb);
    return hi;
}
static void async_close(fcx *x) {
    if (x->hi) U(InternetSetStatusCallbackA)(x->hi, NULL);
    fc_end(x);
    Sleep(50);
}

/* async InternetConnect with a context: pending, completes with the handle; returns the handle or NULL */
static HINTERNET async_connect(fcx *x, const char *user, const char *pass, DWORD_PTR ctx, DWORD *perr, int *pending) {
    SetLastError(0);
    HINTERNET hc = U(InternetConnectA)(x->hi, "127.0.0.1", srv_port(x->s), user, pass, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, ctx);
    DWORD e = GetLastError();
    *pending = 0;
    if (!hc && e == ERROR_IO_PENDING) {
        *pending = 1;
        if (!acb_wait(5000)) { *perr = WAIT_TIMEOUT; return NULL; }
        *perr = A.err;
        return A.res ? (HINTERNET)A.res : NULL;
    }
    *perr = hc ? 0 : e;
    return hc;
}

TEST(ftpc_async_connect_zero_context_is_synchronous) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetStatusCallbackA));
    fcx x; if (!fc_start(&x, NULL)) return;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); fc_end(&x); return; }
    SetLastError(0);
    x.hc = U(InternetConnectA)(x.hi, "127.0.0.1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECKF(x.hc != NULL, "err=%lu", GetLastError());
    /* the login already happened when the call returned */
    EXPECT_STR(fc_seq(&x, 0), "USER anonymous|PASS ***");
    EXPECT_EQ(A.completes, 0);
    async_close(&x);
}

TEST(ftpc_async_connect_with_context_pends) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetStatusCallbackA));
    fcx x; if (!fc_start(&x, NULL)) return;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); fc_end(&x); return; }
    DWORD err = 0; int pending = 0;
    HINTERNET hc = async_connect(&x, NULL, NULL, 0x5151, &err, &pending);
    acb_dump("async FTP connect");
    CHECK(pending);
    CHECKF(hc != NULL, "err=%lu", err);
    EXPECT_EQ(err, 0);
    if (hc) {
        x.hc = hc;
        CHECK(A.created == NULL || A.created == hc);
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(hc, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_CONNECT_FTP);
    }
    CHECK(fc_wait_ncmd(&x, 2, 2000));
    EXPECT_STR(fc_seq(&x, 0), "USER anonymous|PASS ***");
    async_close(&x);
}

TEST(ftpc_async_connect_login_failure_completes_with_error) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetStatusCallbackA));
    static const srv_ftp_override ov[] = { { "PASS", "530 Login incorrect.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); fc_end(&x); return; }
    DWORD err = 0; int pending = 0;
    HINTERNET hc = async_connect(&x, "alice", "bad", 0x77, &err, &pending);
    acb_dump("async FTP connect, PASS 530");
    CHECK(pending);
    CHECK(hc == NULL);
    EXPECT_EQ(err, ERROR_INTERNET_INCORRECT_PASSWORD);
    if (hc) x.hc = hc;
    async_close(&x);
}

TEST(ftpc_async_connect_no_listener) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetSetStatusCallbackA));
    fcx x; if (!fc_start(&x, NULL)) return;
    unsigned short port = srv_port(x.s);
    srv_stop(x.s); x.s = NULL;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); return; }
    SetLastError(0);
    HINTERNET hc = U(InternetConnectA)(x.hi, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0x88);
    DWORD e = GetLastError();
    if (!hc && e == ERROR_IO_PENDING) {
        CHECK(acb_wait(8000));
        acb_dump("async FTP connect, refused");
        EXPECT_EQ(A.res, 0);
        EXPECT_EQ(A.err, ERROR_INTERNET_CANNOT_CONNECT);
    } else {
        CHECKF(0, "expected ERROR_IO_PENDING, got h=%p err=%lu", hc, e);
        if (hc) U(InternetCloseHandle)(hc);
    }
    async_close(&x);
}

TEST(ftpc_async_directory_calls) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpSetCurrentDirectoryA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); fc_end(&x); return; }
    DWORD err = 0; int pending = 0;
    x.hc = async_connect(&x, NULL, NULL, 0x99, &err, &pending);
    CHECKF(x.hc != NULL, "connect err=%lu", err);
    if (x.hc) {
        acb_reset();
        SetLastError(0);
        BOOL ok = U(FtpSetCurrentDirectoryA)(x.hc, "pub");
        DWORD e = ok ? 0 : GetLastError();
        if (!ok && e == ERROR_IO_PENDING) { CHECK(acb_wait(5000)); ok = (BOOL)A.res; e = A.err; }
        acb_dump("async FtpSetCurrentDirectory");
        CHECKF(ok, "err=%lu", e);
        /* FtpGetCurrentDirectory: the buffer must stay valid until completion */
        static char d[128]; static DWORD l; memset(d, 0, sizeof d); l = sizeof d;
        acb_reset();
        SetLastError(0);
        ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
        e = ok ? 0 : GetLastError();
        int pend = !ok && e == ERROR_IO_PENDING;
        if (pend) { CHECK(acb_wait(5000)); ok = (BOOL)A.res; e = A.err; }
        acb_dump("async FtpGetCurrentDirectory");
        t_note("async PWD: pending=%d ok=%d err=%lu dir=[%s] len=%lu", pend, ok, e, d, l);
        CHECK(ok);
        EXPECT_STR(d, "/pub");
        EXPECT_STR(fc_seq(&x, 2), "CWD pub|PWD");
    }
    async_close(&x);
}

TEST(ftpc_async_open_file_and_read) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetReadFile));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); fc_end(&x); return; }
    DWORD err = 0; int pending = 0;
    x.hc = async_connect(&x, NULL, NULL, 0x99, &err, &pending);
    CHECKF(x.hc != NULL, "connect err=%lu", err);
    if (x.hc) {
        acb_reset();
        SetLastError(0);
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0xAB);
        DWORD e = hf ? 0 : GetLastError();
        int pend = !hf && e == ERROR_IO_PENDING;
        if (pend) { CHECK(acb_wait(5000)); hf = (HINTERNET)A.res; e = A.err; }
        acb_dump("async FtpOpenFile");
        t_note("async FtpOpenFile: pending=%d h=%p err=%lu", pend, hf, e);
        CHECKF(hf != NULL, "err=%lu", e);
        if (hf) {
            static char b[32]; static DWORD got; DWORD total = 0; memset(b, 0, sizeof b); got = 0;
            for (int i = 0; i < 20 && total < sizeof b - 1; i++) {
                acb_reset();
                SetLastError(0);
                BOOL ok = U(InternetReadFile)(hf, b + total, sizeof b - 1 - total, &got);
                if (!ok && GetLastError() == ERROR_IO_PENDING) { if (!acb_wait(5000)) break; ok = (BOOL)A.res; got = A.err; /* Win10 (VM, triage 2026-11): *lpdwNumberOfBytesRead is NOT written on async completion; the byte count arrives in INTERNET_ASYNC_RESULT.dwError */ }
                t_note("async read[%d]: ok=%d got=%lu lasterr=%lu A.res=%llu A.err=%lu n=%d", i, ok, got, GetLastError(), (unsigned long long)A.res, A.err, A.n);
                if (!ok || got == 0) break;
                total += got;
            }
            b[total] = 0;
            EXPECT_STR(b, "hello");
            U(InternetCloseHandle)(hf);
        }
        CHECK(fc_find(&x, "RETR hello.txt", 0) >= 0);
    }
    async_close(&x);
}

TEST(ftpc_async_find_first_file) {
    REQUIRE(U(InternetOpenA)); REQUIRE(U(FtpFindFirstFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    x.hi = async_session();
    if (!x.hi) { CHECKF(0, "InternetOpen(ASYNC) err=%lu", GetLastError()); fc_end(&x); return; }
    DWORD err = 0; int pending = 0;
    x.hc = async_connect(&x, NULL, NULL, 0x99, &err, &pending);
    CHECKF(x.hc != NULL, "connect err=%lu", err);
    if (x.hc) {
        static WIN32_FIND_DATAA fd; memset(&fd, 0, sizeof fd);
        acb_reset();
        SetLastError(0);
        HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "pub/*", &fd, FC_NC, 0xCD);
        DWORD e = hf ? 0 : GetLastError();
        int pend = !hf && e == ERROR_IO_PENDING;
        if (pend) { CHECK(acb_wait(5000)); hf = (HINTERNET)A.res; e = A.err; }
        acb_dump("async FtpFindFirstFile");
        CHECKF(hf != NULL, "err=%lu", e);
        if (hf) {
            CHECKF(!strcmp(fd.cFileName, "readme.txt") || !strcmp(fd.cFileName, "data.bin"), "first=[%s]", fd.cFileName);
            U(InternetCloseHandle)(hf);
        }
    }
    async_close(&x);
}
