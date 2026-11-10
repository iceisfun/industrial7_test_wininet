/* fc_handles.c - generic WinINet entry points applied to FTP handles: InternetQueryDataAvailable (find handles
 * report sizeof(WIN32_FIND_DATA) while entries remain), InternetSetFilePointer (HTTP only), InternetReadFileEx,
 * handle options (type, parent, context, URL), status callbacks of the synchronous FTP calls, closed-handle errors,
 * REST/APPE driven through FtpCommand, and a few extra listing/transfer shapes.
 * Decomp: wInternetQueryDataAvailable, wFtpQueryDataAvailable, InternetSetFilePointer, wFtpFindNextFile. */
#include "ftp.h"

static int std_open(fcx *x) { srv_ftp_config c = FC_STD_CFG; return fc_open(x, &c); }

/* ------------------------------------------------------------------ InternetQueryDataAvailable */
TEST(ftpc_qda_find_handle_reports_find_data_size) {
    REQUIRE(U(InternetQueryDataAvailable)); REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        DWORD avail = 0xdead;
        SetLastError(0xbeef);
        BOOL ok = U(InternetQueryDataAvailable)(hf, &avail, 0, 0);
        CHECKF(ok, "err=%lu", GetLastError());
        /* wFtpQueryDataAvailable: 0x140 (sizeof WIN32_FIND_DATAA) while the entry list is not empty */
        EXPECT_EQ(avail, 0x140);
        int steps = 0;
        while (U(InternetFindNextFileA)(hf, &fd) && steps < 50) steps++;
        avail = 0xdead;
        ok = U(InternetQueryDataAvailable)(hf, &avail, 0, 0);
        t_note("find QDA after exhausting (%d more entries): ok=%d avail=%lu err=%lu", steps, ok, avail, ok ? 0 : GetLastError());
        CHECK(ok);
        EXPECT_EQ(avail, 0);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_qda_find_single_entry) {
    REQUIRE(U(InternetQueryDataAvailable)); REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "hello.txt", &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        EXPECT_STR(fd.cFileName, "hello.txt");
        DWORD avail = 0xdead;
        BOOL ok = U(InternetQueryDataAvailable)(hf, &avail, 0, 0);
        CHECK(ok);
        t_note("find QDA with the only entry already returned: %lu", avail);
        EXPECT_EQ(avail, 0);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_qda_file_handle) {
    REQUIRE(U(InternetQueryDataAvailable)); REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "pub/data.bin", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        DWORD avail = 0xdead;
        BOOL ok = U(InternetQueryDataAvailable)(hf, &avail, 0, 0);
        CHECKF(ok, "err=%lu", GetLastError());
        t_note("FTP file QDA before reading: %lu", avail);
        CHECK(avail != 0xdead);
        CHECK(avail <= 100000);
        static char big[120000]; int rok = 0;
        size_t n = fc_read(hf, big, sizeof big, &rok);
        EXPECT_EQ(n, 100000);
        CHECK(srv_pattern_check(big, 100000, 0));
        avail = 0xdead;
        ok = U(InternetQueryDataAvailable)(hf, &avail, 0, 0);
        t_note("FTP file QDA at EOF: ok=%d avail=%lu err=%lu", ok, avail, ok ? 0 : GetLastError());
        CHECK(ok);
        EXPECT_EQ(avail, 0);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_qda_connect_handle_wrong_type) {
    REQUIRE(U(InternetQueryDataAvailable));
    fcx x; if (!std_open(&x)) return;
    DWORD avail = 0xdead;
    SetLastError(0);
    EXPECT_FAIL(!U(InternetQueryDataAvailable)(x.hc, &avail, 0, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    fc_end(&x);
}

TEST(ftpc_qda_write_handle) {
    REQUIRE(U(InternetQueryDataAvailable)); REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "qdaw.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        DWORD avail = 0xdead;
        BOOL ok = U(InternetQueryDataAvailable)(hf, &avail, 0, 0);
        t_note("QDA on an FTP write handle: ok=%d avail=%lu err=%lu", ok, avail, ok ? 0 : GetLastError());
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ InternetSetFilePointer: HTTP request handles only */
TEST(ftpc_setfilepointer_ftp_file_wrong_type) {
    REQUIRE(U(InternetSetFilePointer)); REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        static const DWORD methods[] = { FILE_BEGIN, FILE_CURRENT, FILE_END };
        for (int i = 0; i < 3; i++) {
            SetLastError(0);
            DWORD r = U(InternetSetFilePointer)(hf, 1, NULL, methods[i], 0);
            DWORD e = GetLastError();
            CHECKF(r == INVALID_SET_FILE_POINTER, "method %lu -> %lu", methods[i], r);
            CHECKF(e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "method %lu err=%lu", methods[i], e);
        }
        char b[16] = ""; fc_read(hf, b, sizeof b, NULL);
        EXPECT_STR(b, "hello");   /* nothing moved */
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_setfilepointer_find_and_connect_wrong_type) {
    REQUIRE(U(InternetSetFilePointer)); REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    DWORD r = U(InternetSetFilePointer)(x.hc, 0, NULL, FILE_BEGIN, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(r, INVALID_SET_FILE_POINTER);
    EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    if (hf) {
        SetLastError(0);
        r = U(InternetSetFilePointer)(hf, 0, NULL, FILE_BEGIN, 0);
        e = GetLastError();
        EXPECT_EQ(r, INVALID_SET_FILE_POINTER);
        EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        U(InternetCloseHandle)(hf);
    } else CHECKF(0, "find err=%lu", GetLastError());
    fc_end(&x);
}

/* ------------------------------------------------------------------ InternetReadFileEx on FTP */
TEST(ftpc_readfileex_ftp_file) {
    REQUIRE(U(InternetReadFileExA)); REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        char b[32] = "";
        INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib);
        ib.dwStructSize = sizeof ib; ib.lpvBuffer = b; ib.dwBufferLength = sizeof b - 1;
        SetLastError(0);
        BOOL ok = U(InternetReadFileExA)(hf, &ib, IRF_SYNC, 0);
        DWORD e = ok ? 0 : GetLastError();
        t_note("InternetReadFileExA on FTP file: ok=%d err=%lu len=%lu", ok, e, ib.dwBufferLength);
        if (ok) { b[ib.dwBufferLength < sizeof b ? ib.dwBufferLength : sizeof b - 1] = 0; CHECKF(!strncmp(b, "hello", ib.dwBufferLength), "b=[%s]", b); }
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ handle options */
TEST(ftpc_find_handle_parent_and_type) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0x55);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FIND);
        HINTERNET p = NULL; l = sizeof p;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_PARENT_HANDLE, &p, &l));
        EXPECT_EQ(p, x.hc);
        DWORD_PTR ctx = 0; l = sizeof ctx;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_CONTEXT_VALUE, &ctx, &l));
        EXPECT_EQ(ctx, 0x55);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_file_handle_context_value) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0xC0FFEE);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        DWORD_PTR ctx = 0; DWORD l = sizeof ctx;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_CONTEXT_VALUE, &ctx, &l));
        EXPECT_EQ(ctx, 0xC0FFEE);
        EXPECT_EQ(l, sizeof(DWORD_PTR));
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_connect_handle_context_value) {
    REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!fc_start(&x, NULL)) return;
    x.hi = t_inet_open("ftpc");
    x.hc = U(InternetConnectA)(x.hi, "127.0.0.1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0x1234);
    CHECKF(x.hc != NULL, "err=%lu", GetLastError());
    if (x.hc) {
        DWORD_PTR ctx = 0; DWORD l = sizeof ctx;
        CHECK(U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_CONTEXT_VALUE, &ctx, &l));
        EXPECT_EQ(ctx, 0x1234);
    }
    fc_end(&x);
}

TEST(ftpc_file_handle_url_option) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "pub/readme.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        char url[256] = ""; DWORD l = sizeof url;
        BOOL ok = U(InternetQueryOptionA)(hf, INTERNET_OPTION_URL, url, &l);
        t_note("URL of FtpOpenFile(pub/readme.txt): ok=%d [%s] len=%lu", ok, url, l);
        if (ok) {
            char want[128]; snprintf(want, sizeof want, "ftp://127.0.0.1:%u/", srv_port(x.s));
            CHECKF(!strncmp(url, want, strlen(want)), "url=[%s]", url);
            CHECKF(strstr(url, "readme.txt") != NULL, "url=[%s]", url);
        }
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_connect_handle_server_port_options) {
    REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!std_open(&x)) return;
    DWORD to = 0, l = sizeof to;
    BOOL ok = U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, &l);
    CHECK(ok);
    EXPECT_EQ(to, 5000);   /* inherited from the session handle (t_inet_open sets 5 s) */
    to = 0; l = sizeof to;
    CHECK(U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_CONNECT_TIMEOUT, &to, &l));
    EXPECT_EQ(to, 5000);
    fc_end(&x);
}

/* ------------------------------------------------------------------ closed handles */
TEST(ftpc_closed_find_handle_invalid) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(InternetFindNextFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECK(hf != NULL);
    if (hf) {
        CHECK(U(InternetCloseHandle)(hf));
        SetLastError(0);
        EXPECT_FAIL(!U(InternetFindNextFileA)(hf, &fd), ERROR_INVALID_HANDLE);
        /* the session is free again: a new find works */
        HINTERNET h2 = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
        CHECKF(h2 != NULL, "err=%lu", GetLastError());
        if (h2) U(InternetCloseHandle)(h2);
    }
    fc_end(&x);
}

TEST(ftpc_closed_file_handle_invalid) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetReadFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) {
        CHECK(U(InternetCloseHandle)(hf));
        char b[8]; DWORD r = 0;
        SetLastError(0);
        EXPECT_FAIL(!U(InternetReadFile)(hf, b, sizeof b, &r), ERROR_INVALID_HANDLE);
        SetLastError(0);
        DWORD hi = 0;
        DWORD lo = U(FtpGetFileSize)(hf, &hi);
        EXPECT_EQ(lo, 0xFFFFFFFF);
        EXPECT_EQ(GetLastError(), ERROR_INVALID_HANDLE);
    }
    fc_end(&x);
}

TEST(ftpc_close_connect_with_open_file_child) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    /* closing the parent closes the children too */
    CHECK(U(InternetCloseHandle)(x.hc)); x.hc = NULL;
    if (hf) {
        char b[8]; DWORD r = 0;
        SetLastError(0);
        BOOL ok = U(InternetReadFile)(hf, b, sizeof b, &r);
        DWORD e = ok ? 0 : GetLastError();
        t_note("read on a file handle whose connect handle was closed: ok=%d err=%lu r=%lu", ok, e, r);
        CHECK(!ok);
        EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ status callbacks (synchronous) */
#define CB_MAX 128
static volatile LONG cb_n;
static DWORD cb_status[CB_MAX];
static DWORD_PTR cb_ctx[CB_MAX];
static HINTERNET cb_h[CB_MAX];
static void CALLBACK fc_cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    LONG i = InterlockedIncrement(&cb_n) - 1;
    if (i < CB_MAX) { cb_status[i] = st; cb_ctx[i] = ctx; cb_h[i] = h; }
}
static void cb_reset(void) { cb_n = 0; memset(cb_status, 0, sizeof cb_status); }
static int cb_find(DWORD st, DWORD_PTR ctx, int from) {
    int n = cb_n < CB_MAX ? cb_n : CB_MAX;
    for (int i = from; i < n; i++) if (cb_status[i] == st && cb_ctx[i] == ctx) return i;
    return -1;
}
static void cb_dump(const char *what) {
    char b[1024]; size_t o = 0; int n = cb_n < CB_MAX ? cb_n : CB_MAX; b[0] = 0;
    for (int i = 0; i < n && o < sizeof b - 16; i++) o += snprintf(b + o, sizeof b - o, "%s%lu", i ? "," : "", cb_status[i]);
    t_note("%s callbacks: %s", what, b);
}

TEST(ftpc_callback_connect_sequence) {
    REQUIRE(U(InternetSetStatusCallbackA));
    fcx x; if (!fc_start(&x, NULL)) return;
    x.hi = t_inet_open("ftpc");
    cb_reset();
    U(InternetSetStatusCallbackA)(x.hi, fc_cb);
    x.hc = U(InternetConnectA)(x.hi, "127.0.0.1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0x77);
    CHECKF(x.hc != NULL, "err=%lu", GetLastError());
    cb_dump("FTP connect");
    int created = cb_find(INTERNET_STATUS_HANDLE_CREATED, 0x77, 0);
    CHECK(created >= 0);
    int conn = cb_find(INTERNET_STATUS_CONNECTED_TO_SERVER, 0x77, 0);
    t_note("HANDLE_CREATED at %d, CONNECTED_TO_SERVER at %d", created, conn);
    if (x.hc) {
        int before = cb_n;
        U(InternetCloseHandle)(x.hc);
        int closing = cb_find(INTERNET_STATUS_HANDLE_CLOSING, 0x77, before);
        cb_dump("FTP connect close");
        CHECK(closing >= 0);
        x.hc = NULL;
    }
    U(InternetSetStatusCallbackA)(x.hi, NULL);
    fc_end(&x);
}

TEST(ftpc_callback_file_handle_created_and_closing) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    cb_reset();
    U(InternetSetStatusCallbackA)(x.hc, fc_cb);
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0x99);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    cb_dump("FtpOpenFile");
    int created = cb_find(INTERNET_STATUS_HANDLE_CREATED, 0x99, 0);
    CHECK(created >= 0);
    if (created >= 0) EXPECT_EQ(cb_h[created], hf);
    if (hf) {
        char b[16]; fc_read(hf, b, sizeof b, NULL);
        int before = cb_n;
        U(InternetCloseHandle)(hf);
        cb_dump("FtpOpenFile close");
        CHECK(cb_find(INTERNET_STATUS_HANDLE_CLOSING, 0x99, before) >= 0);
    }
    U(InternetSetStatusCallbackA)(x.hc, NULL);
    fc_end(&x);
}

TEST(ftpc_callback_zero_context_suppressed) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    cb_reset();
    U(InternetSetStatusCallbackA)(x.hc, fc_cb);
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) U(InternetCloseHandle)(hf);
    cb_dump("FtpOpenFile ctx=0");
    /* synchronous calls with a zero context report nothing */
    EXPECT_EQ(cb_n, 0);
    U(InternetSetStatusCallbackA)(x.hc, NULL);
    fc_end(&x);
}

TEST(ftpc_callback_find_handle_created) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    cb_reset();
    U(InternetSetStatusCallbackA)(x.hc, fc_cb);
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0x42);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    cb_dump("FtpFindFirstFile");
    CHECK(cb_find(INTERNET_STATUS_HANDLE_CREATED, 0x42, 0) >= 0);
    if (hf) U(InternetCloseHandle)(hf);
    CHECK(cb_find(INTERNET_STATUS_HANDLE_CLOSING, 0x42, 0) >= 0);
    U(InternetSetStatusCallbackA)(x.hc, NULL);
    fc_end(&x);
}

/* ------------------------------------------------------------------ REST / APPE through FtpCommand */
TEST(ftpc_command_rest_then_retr) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    CHECKF(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_BINARY, "REST 2", 0, NULL), "REST err=%lu", GetLastError());   /* 350 is class 3 */
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, "RETR hello.txt", 0, &h), "RETR err=%lu", GetLastError());
    if (h) {
        char b[16] = ""; fc_read(h, b, sizeof b, NULL);
        t_note("REST 2 + RETR hello.txt via FtpCommand: [%s] seq %s", b, fc_seq(&x, 2));
        EXPECT_STR(b, "llo");
        U(InternetCloseHandle)(h);
    }
    EXPECT_STR(fc_cmd(&x, 2), "REST 2");
    fc_end(&x);
}

TEST(ftpc_command_appe_appends) {
    REQUIRE(U(FtpCommandA)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, "APPE hello.txt", 0, &h), "err=%lu", GetLastError());
    if (h) {
        DWORD w = 0;
        CHECK(U(InternetWriteFile)(h, " world", 6, &w));
        EXPECT_EQ(w, 6);
        U(InternetCloseHandle)(h);
    }
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/hello.txt", &n);
    EXPECT_STR(d ? d : "", "hello world");
    EXPECT_EQ(n, 11);
    fc_end(&x);
}

TEST(ftpc_command_nlst_content) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST /pub", 0, &h), "err=%lu", GetLastError());
    if (h) {
        char b[512] = ""; fc_read(h, b, sizeof b, NULL);
        CHECKF(strstr(b, "readme.txt") && strstr(b, "data.bin"), "nlst=[%s]", b);
        U(InternetCloseHandle)(h);
    }
    EXPECT_STR(fc_cmd(&x, 2), "TYPE A");
    EXPECT_STR(fc_cmd(&x, 3), "PASV");
    EXPECT_STR(fc_cmd(&x, 4), "NLST /pub");
    fc_end(&x);
}

TEST(ftpc_command_list_raw_text_not_parsed) {
    REQUIRE(U(FtpCommandA));
    srv_ftp_config c; memset(&c, 0, sizeof c);
    c.list_override = "-rw-r--r--   1 u  g   12 Jan 02  2020 x.txt\r\nthis line is junk\r\n";
    fcx x; if (!fc_open(&x, &c)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "LIST", 0, &h), "err=%lu", GetLastError());
    if (h) {
        char b[512] = ""; fc_read(h, b, sizeof b, NULL);
        EXPECT_STR(b, c.list_override);   /* FtpCommand data is the raw byte stream */
        U(InternetCloseHandle)(h);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ W variants of the transfer calls */
TEST(ftpc_open_w_write_and_read_back) {
    REQUIRE(U(FtpOpenFileW)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileW)(x.hc, L"wide upload.txt", GENERIC_WRITE, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) { DWORD w = 0; CHECK(U(InternetWriteFile)(hf, "W-data", 6, &w)); U(InternetCloseHandle)(hf); }
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/wide upload.txt", &n);
    EXPECT_STR(d ? d : "", "W-data");
    CHECK(fc_find(&x, "STOR wide upload.txt", 0) >= 0);
    fc_end(&x);
}

TEST(ftpc_find_w_fields) {
    REQUIRE(U(FtpFindFirstFileW));
    srv_ftp_config c; memset(&c, 0, sizeof c);
    c.list_override = "-rw-r--r--   1 owner group     1234 Mar 04  2015 wide name.txt\r\n";
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAW fd; memset(&fd, 0x5a, sizeof fd);
    HINTERNET hf = U(FtpFindFirstFileW)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        EXPECT_WSTR(fd.cFileName, L"wide name.txt");
        EXPECT_EQ(fd.nFileSizeLow, 1234);
        EXPECT_EQ(fd.nFileSizeHigh, 0);
        EXPECT_EQ(fd.dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
        EXPECT_EQ(fd.dwReserved0, 0x644);
        SYSTEMTIME st; fc_ft_to_st(&fd.ftLastWriteTime, &st);
        EXPECT_EQ(st.wYear, 2015); EXPECT_EQ(st.wMonth, 3); EXPECT_EQ(st.wDay, 4);
        t_note("W find: cAlternateFileName[0]=0x%04x ftCreation=%08lx:%08lx", fd.cAlternateFileName[0],
               fd.ftCreationTime.dwHighDateTime, fd.ftCreationTime.dwLowDateTime);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_find_a_unused_fields) {
    REQUIRE(U(FtpFindFirstFileA));
    srv_ftp_config c; memset(&c, 0, sizeof c);
    c.list_override = "-rw-r--r--   1 owner group     77 Mar 04  2015 f.txt\r\n";
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAA fd; memset(&fd, 0x5a, sizeof fd);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        EXPECT_STR(fd.cFileName, "f.txt");
        EXPECT_EQ(fd.ftCreationTime.dwLowDateTime, 0);
        EXPECT_EQ(fd.ftCreationTime.dwHighDateTime, 0);
        EXPECT_EQ(fd.ftLastAccessTime.dwLowDateTime, 0);
        EXPECT_EQ(fd.ftLastAccessTime.dwHighDateTime, 0);
        t_note("A find: dwReserved1=0x%lx cAlternateFileName[0]=0x%02x name tail byte=0x%02x", fd.dwReserved1,
               (unsigned char)fd.cAlternateFileName[0], (unsigned char)fd.cFileName[6]);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_find_ansi_codepage_name) {
    REQUIRE(U(FtpFindFirstFileW));
    srv_ftp_config c; memset(&c, 0, sizeof c);
    c.list_override = "-rw-r--r--   1 owner group     5 Mar 04  2015 caf\xe9.txt\r\n";
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAW fd; memset(&fd, 0, sizeof fd);
    HINTERNET hf = U(FtpFindFirstFileW)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        t_note("ACP=%u: name bytes 0xE9 -> W char U+%04X", GetACP(), fd.cFileName[3]);
        if (GetACP() == 1252) EXPECT_EQ(fd.cFileName[3], 0x00E9);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ more listing shapes */
static const struct { const char *line; const char *name; DWORD attr; DWORD lo; } shape_tab[] = {
    { "-rw-r--r--    1 0        0              10 Jan 01  2020 numeric ids.txt", "numeric ids.txt", FILE_ATTRIBUTE_NORMAL, 10 },
    { "drwxr-xr-x    2 ftp      ftp          4096 Feb 29  2020 leapdir", "leapdir", FILE_ATTRIBUTE_DIRECTORY, 4096 },
    { "-rw-r--r--    1 user     group  1234567890 Dec 31  1999 y2k.bin", "y2k.bin", FILE_ATTRIBUTE_NORMAL, 1234567890 },
    { "-rw-r--r--    1 user     group           0 Jul 04  2010   lead spaces", "lead spaces", FILE_ATTRIBUTE_NORMAL, 0 },   /* ParseUnixDirectory: SkipSpaces(' ') before _ExtractFilename */
    { "-rwxrwxrwx    1 user     group          42 Aug 15  2018 tab\there", "tab\there", FILE_ATTRIBUTE_NORMAL, 42 },
};

TEST(ftpc_unix_listing_shapes_table) {
    REQUIRE(U(FtpFindFirstFileA));
    for (int i = 0; i < NF(shape_tab); i++) {
        char lst[512]; snprintf(lst, sizeof lst, "%s\r\n", shape_tab[i].line);
        WIN32_FIND_DATAA v[4]; int n = 0; DWORD err = 0;
        if (!fc_list_raw(lst, NULL, v, 4, &n, &err)) return;
        CHECKF(n == 1, "[%d] n=%d err=%lu", i, n, err);
        if (n >= 1) {
            t_note("[%d] name=[%s] attr=0x%lx size=%lu", i, v[0].cFileName, v[0].dwFileAttributes, v[0].nFileSizeLow);
            CHECKF(!strcmp(v[0].cFileName, shape_tab[i].name), "[%d] name=[%s] want [%s]", i, v[0].cFileName, shape_tab[i].name);
            CHECKF(v[0].dwFileAttributes == shape_tab[i].attr, "[%d] attr=0x%lx", i, v[0].dwFileAttributes);
            CHECKF(v[0].nFileSizeLow == shape_tab[i].lo, "[%d] size=%lu", i, v[0].nFileSizeLow);
        }
    }
}

TEST(ftpc_dos_listing_shapes) {
    REQUIRE(U(FtpFindFirstFileA));
    static const char lst[] =
        "01-01-20  12:00PM                  100 noon.txt\r\n"
        "01-01-20  12:30AM                  101 half past midnight.txt\r\n"
        "12-31-2021  11:59PM       <DIR>          year4dir\r\n";
    WIN32_FIND_DATAA v[8]; int n = 0; DWORD err = 0;
    if (!fc_list_raw(lst, NULL, v, 8, &n, &err)) return;
    EXPECT_EQ(n, 3);
    for (int i = 0; i < n && i < 8; i++) {
        SYSTEMTIME st; fc_ft_to_st(&v[i].ftLastWriteTime, &st);
        t_note("dos shape[%d] [%s] attr=0x%lx size=%lu %04u-%02u-%02u %02u:%02u", i, v[i].cFileName, v[i].dwFileAttributes,
               v[i].nFileSizeLow, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    }
    const WIN32_FIND_DATAA *a = fc_by_name(v, n, "noon.txt");
    CHECK(a != NULL);
    if (a) { SYSTEMTIME st; fc_ft_to_st(&a->ftLastWriteTime, &st); EXPECT_EQ(st.wHour, 12); EXPECT_EQ(st.wMinute, 0); EXPECT_EQ(a->nFileSizeLow, 100); EXPECT_EQ(st.wYear, 2020); }
    a = fc_by_name(v, n, "half past midnight.txt");
    CHECK(a != NULL);
    if (a) { SYSTEMTIME st; fc_ft_to_st(&a->ftLastWriteTime, &st); EXPECT_EQ(st.wHour, 0); EXPECT_EQ(st.wMinute, 30); }
    a = fc_by_name(v, n, "year4dir");
    CHECK(a != NULL);
    if (a) { SYSTEMTIME st; fc_ft_to_st(&a->ftLastWriteTime, &st); EXPECT_EQ(a->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY); EXPECT_EQ(st.wYear, 2021); EXPECT_EQ(st.wHour, 23); }
}

/* ------------------------------------------------------------------ connect defaults */
TEST(ftpc_connect_port_zero_means_21) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = t_inet_open("ftpc");
    if (!hi) { t_skip("InternetOpen failed"); return; }
    /* offline: no connection is attempted, the handle just records the server and port */
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", INTERNET_INVALID_PORT_NUMBER, NULL, NULL, INTERNET_SERVICE_FTP,
                                       INTERNET_FLAG_PASSIVE | INTERNET_FLAG_OFFLINE, 0);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    if (hc) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(hc, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_CONNECT_FTP);
        U(InternetCloseHandle)(hc);
    }
    U(InternetCloseHandle)(hi);
}

TEST(ftpc_connect_hostname_localhost) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_start(&x, NULL)) return;
    x.hi = t_inet_open("ftpc");
    x.hc = U(InternetConnectA)(x.hi, "localhost", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECKF(x.hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_seq(&x, 0), "USER anonymous|PASS ***");
    fc_end(&x);
}

TEST(ftpc_connect_ipv6_literal) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!fc_start(&x, NULL)) return;
    x.hi = t_inet_open("ftpc");
    x.hc = U(InternetConnectA)(x.hi, "::1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    DWORD e = x.hc ? 0 : GetLastError();
    t_note("InternetConnect(\"::1\") FTP: h=%p err=%lu", x.hc, e);
    if (x.hc) {
        char d[32] = ""; DWORD l = sizeof d;
        CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
        EXPECT_STR(d, "/");
    }
    fc_end(&x);
}
