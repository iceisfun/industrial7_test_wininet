/* fc_cmd.c - FtpCommandA/W (with and without a data connection), InternetGetLastResponseInfoA/W after FTP replies,
 * and ftp:// URLs through InternetOpenUrl (file, directory as HTML or raw find data, ;type=, credentials).
 * Decomp: InternalFtpCommandA, wFtpCommand, I_Command, I_NegotiateDataConnection, FtpCommandW,
 * InternetGetLastResponseInfoA, ReceiveFtpResponse, ParseFtpUrl, MakeHtmlDirEntry. */
#include "ftp.h"
#include <stdlib.h>

static int std_open(fcx *x) { srv_ftp_config c = FC_STD_CFG; return fc_open(x, &c); }

/* ------------------------------------------------------------------ FtpCommand without data */
TEST(ftpc_command_noop) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hcmd = (HINTERNET)(ULONG_PTR)0x1234;
    SetLastError(0xdead);
    CHECKF(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, &hcmd), "err=%lu", GetLastError());
    t_note("FtpCommand(fExpectResponse=FALSE) phFtpCommand after: %p", hcmd);
    EXPECT_STR(fc_seq(&x, 2), "NOOP");
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "200 NOOP ok.") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_command_sent_verbatim) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    static const char *cmds[] = { "noop", "NoOp", "SYST", "MODE S", "STRU F", "ALLO 100", "SITE  two  spaces" };
    for (int i = 0; i < NF(cmds); i++) {
        int before = fc_ncmd(&x);
        U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, cmds[i], 0, NULL);
        CHECKF(!strcmp(fc_cmd(&x, before), cmds[i]), "sent [%s] want [%s]", fc_cmd(&x, before), cmds[i]);
    }
    fc_end(&x);
}

TEST(ftpc_command_reply_class_table) {
    REQUIRE(U(FtpCommandA));
    static const struct { const char *reply; int ok; } tab[] = {
        { "110 restart marker", 1 }, { "125 already open", 1 }, { "200 ok", 1 }, { "211 status", 1 }, { "331 need password", 1 },
        { "350 pending further information", 1 }, { "421 closing", 0 }, { "450 unavailable", 0 }, { "500 syntax", 0 },
        { "502 not implemented", 0 }, { "530 not logged in", 0 }, { "550 unavailable", 0 },
    };
    for (int i = 0; i < NF(tab); i++) {
        srv_ftp_override ov[] = { { "XTST", tab[i].reply, 0 } };
        srv_ftp_config c = { NULL, 0, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        SetLastError(0);
        BOOL ok = U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "XTST arg", 0, NULL);
        DWORD e = GetLastError();
        CHECKF(!!ok == tab[i].ok, "reply [%s]: ok=%d err=%lu", tab[i].reply, ok, e);
        if (!ok) CHECKF(e == ERROR_INTERNET_EXTENDED_ERROR, "reply [%s]: err=%lu", tab[i].reply, e);
        DWORD le; const char *r = fc_resp(&le);
        CHECKF(strstr(r, tab[i].reply) != NULL, "reply [%s]: resp [%s]", tab[i].reply, r);
        fc_end(&x);
    }
}

TEST(ftpc_command_unknown_502) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "XYZZY", 0, NULL), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "502 Command not implemented.") != NULL, "resp=[%s]", r);
    /* still usable */
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    fc_end(&x);
}

TEST(ftpc_command_changes_server_state) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "CWD pub", 0, NULL));
    char d[64] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/pub");
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "MKD made_by_cmd", 0, NULL));
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "made_by_cmd"));
    fc_end(&x);
}

TEST(ftpc_command_multiline_reply_text) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "FEAT", 0, NULL));
    DWORD e; const char *r = fc_resp(&e);
    t_note("FEAT response text: [%s]", r);
    CHECKF(strstr(r, "211-Features:") && strstr(r, " SIZE") && strstr(r, " EPSV") && strstr(r, "211 End"), "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_command_validation_87) {
    REQUIRE(U(FtpCommandA)); REQUIRE(U(FtpCommandW));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "", 0, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST", 0, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(x.hc, TRUE, 0, "NLST", 0, &h), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(x.hc, TRUE, 3, "NLST", 0, &h), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandW)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, NULL, 0, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandW)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, L"", 0, NULL), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    /* the transfer-type flags are only validated when a data connection is requested */
    CHECK(U(FtpCommandA)(x.hc, FALSE, 0, "NOOP", 0, NULL));
    CHECK(U(FtpCommandA)(x.hc, FALSE, 3, "NOOP", 0, NULL));
    EXPECT_EQ(fc_count(&x, "NOOP"), 2);
    fc_end(&x);
}

TEST(ftpc_command_w) {
    REQUIRE(U(FtpCommandW));
    fcx x; if (!std_open(&x)) return;
    CHECKF(U(FtpCommandW)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, L"CWD dir two", 0, NULL), "err=%lu", GetLastError());
    EXPECT_STR(fc_cmd(&x, 2), "CWD dir two");
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpCommand with a data connection */
TEST(ftpc_command_nlst_data_handle) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST", 0, &h), "err=%lu", GetLastError());
    CHECK(h != NULL);
    if (h) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        t_note("FtpCommand data handle type: %lu", t);
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FILE);
        char b[1024] = ""; int ok = 0;
        fc_read(h, b, sizeof b, &ok);
        CHECK(ok);
        CHECKF(strstr(b, "hello.txt\r\n") && strstr(b, "pub\r\n") && strstr(b, "dir two\r\n"), "data=[%s]", b);
        U(InternetCloseHandle)(h);
    }
    EXPECT_STR(fc_seq(&x, 2), "TYPE A|PASV|NLST");
    /* the session continues normally after the data handle is closed */
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    fc_end(&x);
}

TEST(ftpc_command_list_binary_type) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, "LIST pub", 0, &h), "err=%lu", GetLastError());
    if (h) {
        char b[1024] = ""; fc_read(h, b, sizeof b, NULL);
        CHECKF(strstr(b, "readme.txt") && strstr(b, "-rw-r--r--"), "data=[%s]", b);
        U(InternetCloseHandle)(h);
    }
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|LIST pub");
    fc_end(&x);
}

TEST(ftpc_command_retr_sends_size_first) {
    REQUIRE(U(FtpCommandA)); REQUIRE(U(FtpGetFileSize));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, "RETR hello.txt", 0, &h), "err=%lu", GetLastError());
    if (h) {
        char b[32] = ""; fc_read(h, b, sizeof b, NULL);
        EXPECT_STR(b, "hello");
        U(InternetCloseHandle)(h);
    }
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|SIZE hello.txt|RETR hello.txt");
    fc_end(&x);
}

TEST(ftpc_command_stor_data_handle) {
    REQUIRE(U(FtpCommandA)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, "STOR viacmd.bin", 0, &h), "err=%lu", GetLastError());
    if (h) {
        DWORD w = 0;
        BOOL ok = U(InternetWriteFile)(h, "cmd-data", 8, &w);
        t_note("InternetWriteFile on an FtpCommand(STOR) handle: ok=%d err=%lu w=%lu", ok, ok ? 0 : GetLastError(), w);
        U(InternetCloseHandle)(h);
        if (ok) {
            CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
            long n = 0; const char *d = srv_ftp_file_data(x.s, "/viacmd.bin", &n);
            CHECK(d && n == 8 && !memcmp(d, "cmd-data", 8));
        }
    }
    fc_end(&x);
}

TEST(ftpc_command_data_rejected) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = (HINTERNET)(ULONG_PTR)0x77;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, "RETR ghost.bin", 0, &h), ERROR_INTERNET_EXTENDED_ERROR);
    t_note("phFtpCommand after a failed data command: %p", h);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 ghost.bin") != NULL, "resp=[%s]", r);
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    fc_end(&x);
}

TEST(ftpc_command_data_while_handle_open) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECK(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST", 0, &h));
    HINTERNET h2 = NULL;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST", 0, &h2), ERROR_FTP_TRANSFER_IN_PROGRESS);
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL), ERROR_FTP_TRANSFER_IN_PROGRESS);
    if (h) { char b[512]; fc_read(h, b, sizeof b, NULL); U(InternetCloseHandle)(h); }
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    fc_end(&x);
}

TEST(ftpc_command_active_mode_data) {
    REQUIRE(U(FtpCommandA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!fc_connect(&x, NULL, NULL, 0)) { CHECKF(0, "connect %lu", GetLastError()); fc_end(&x); return; }
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandA)(x.hc, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST pub", 0, &h), "err=%lu", GetLastError());
    if (h) { char b[256] = ""; fc_read(h, b, sizeof b, NULL); CHECKF(strstr(b, "readme.txt") != NULL, "data=[%s]", b); U(InternetCloseHandle)(h); }
    CHECK(fc_find(&x, "PORT 127,0,0,1,", 0) >= 0);
    fc_end(&x);
}

/* ------------------------------------------------------------------ InternetGetLastResponseInfo */
TEST(ftpc_lastresp_validation) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    char b[16]; DWORD e = 0, l = sizeof b;
    SetLastError(0); EXPECT_FAIL(!U(InternetGetLastResponseInfoA)(NULL, b, &l), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(InternetGetLastResponseInfoA)(&e, b, NULL), ERROR_INVALID_PARAMETER);
}

TEST(ftpc_lastresp_buffer_contract) {
    REQUIRE(U(InternetGetLastResponseInfoA)); REQUIRE(U(FtpCommandA));
    static const srv_ftp_override ov[] = { { "XRSP", "250 0123456789", 0 } };
    srv_ftp_config c = { NULL, 0, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "XRSP", 0, NULL));
    char full[256] = ""; DWORD e = 7, l = sizeof full;
    CHECK(U(InternetGetLastResponseInfoA)(&e, full, &l));
    EXPECT_EQ(l, strlen(full));
    t_note("response text len=%lu err=%lu [%s]", l, e, full);
    CHECK(!strncmp(full, "250 0123456789", 14));
    DWORD need = l + 1;
    /* size query */
    DWORD q = 0; e = 7;
    SetLastError(0);
    EXPECT_FAIL(!U(InternetGetLastResponseInfoA)(&e, NULL, &q), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(q, need);
    /* zero-length buffer */
    char tiny[4] = "zzz"; q = 0;
    SetLastError(0);
    EXPECT_FAIL(!U(InternetGetLastResponseInfoA)(&e, tiny, &q), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(q, need);
    EXPECT_EQ(tiny[0], 'z');
    /* short buffer: truncated, NUL-terminated, full size reported */
    char sb[8]; memset(sb, 'q', sizeof sb); q = 8;
    SetLastError(0);
    EXPECT_FAIL(!U(InternetGetLastResponseInfoA)(&e, sb, &q), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(q, need);
    CHECK(!memcmp(sb, "250 012", 7) && sb[7] == 0);
    /* exact fit (strlen + 1) */
    char eb[256]; q = need;
    CHECK(U(InternetGetLastResponseInfoA)(&e, eb, &q));
    EXPECT_EQ(q, need - 1);
    EXPECT_STR(eb, full);
    /* one short of the fit */
    q = need - 1;
    SetLastError(0);
    EXPECT_FAIL(!U(InternetGetLastResponseInfoA)(&e, eb, &q), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(q, need);
    fc_end(&x);
}

TEST(ftpc_lastresp_wide) {
    REQUIRE(U(InternetGetLastResponseInfoW)); REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    WCHAR w[128] = L""; DWORD e = 5, l = NF(w);
    CHECKF(U(InternetGetLastResponseInfoW)(&e, w, &l), "err=%lu", GetLastError());
    CHECK(!wcsncmp(w, L"200 NOOP ok.", 12));
    t_note("W response len=%lu", l);
    DWORD q = 0;
    SetLastError(0);
    BOOL ok = U(InternetGetLastResponseInfoW)(&e, NULL, &q);
    t_note("W size query: ok=%d err=%lu len=%lu", ok, ok ? 0 : GetLastError(), q);
    CHECK(!ok);
    fc_end(&x);
}

struct lr_th { DWORD len; BOOL ok; };
static DWORD WINAPI lr_thr(LPVOID p) {
    struct lr_th *st = p;
    char b[64]; DWORD e = 0; st->len = sizeof b;
    st->ok = U(InternetGetLastResponseInfoA)(&e, b, &st->len);
    return 0;
}
TEST(ftpc_lastresp_is_per_thread) {
    REQUIRE(U(InternetGetLastResponseInfoA)); REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    DWORD e; const char *r = fc_resp(&e);
    CHECK(strstr(r, "200 NOOP ok.") != NULL);
    /* another thread sees nothing */
    struct lr_th st = { 99, 0 };
    HANDLE t = CreateThread(NULL, 0, lr_thr, &st, 0, NULL);
    CHECK(t != NULL);
    if (t) { CHECK(WaitForSingleObject(t, 5000) == WAIT_OBJECT_0); CloseHandle(t); }
    CHECK(st.ok);
    EXPECT_EQ(st.len, 0);
    fc_end(&x);
}

TEST(ftpc_lastresp_replaced_by_each_command) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL));
    DWORD e; const char *r1 = fc_resp(&e);
    CHECK(strstr(r1, "200 NOOP ok.") != NULL);
    CHECK(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "SYST", 0, NULL));
    const char *r2 = fc_resp(&e);
    CHECKF(strstr(r2, "215 UNIX Type: L8") != NULL && strstr(r2, "NOOP") == NULL, "resp=[%s]", r2);
    fc_end(&x);
}

/* ------------------------------------------------------------------ ftp:// via InternetOpenUrl */
static HINTERNET open_url(fcx *x, const char *path, DWORD flags) {
    if (!x->hi) x->hi = t_inet_open("ftpc");
    char url[512]; snprintf(url, sizeof url, "ftp://127.0.0.1:%u%s", srv_port(x->s), path);
    return U(InternetOpenUrlA)(x->hi, url, NULL, 0, flags, 0);
}

TEST(ftpc_url_file) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/hello.txt", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) {
        char b[64] = ""; fc_read(h, b, sizeof b, NULL);
        EXPECT_STR(b, "hello");
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FILE);
        U(InternetCloseHandle)(h);
    }
    fc_dump(&x);
    EXPECT_STR(fc_cmd(&x, 0), "USER anonymous");
    CHECK(fc_find(&x, "RETR", 0) >= 0);
    fc_end(&x);
}

TEST(ftpc_url_nested_file_with_space) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/dir%20two/in%20space.txt", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) { char b[64] = ""; fc_read(h, b, sizeof b, NULL); EXPECT_STR(b, "spaced"); U(InternetCloseHandle)(h); }
    fc_dump(&x);
    fc_end(&x);
}

TEST(ftpc_url_credentials) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG; c.record_pass = 1;
    fcx x; if (!fc_start(&x, &c)) return;
    x.hi = t_inet_open("ftpc");
    char url[256]; snprintf(url, sizeof url, "ftp://urluser:urlpass@127.0.0.1:%u/hello.txt", srv_port(x.s));
    HINTERNET h = U(InternetOpenUrlA)(x.hi, url, NULL, 0, T_INET_FRESH | INTERNET_FLAG_PASSIVE, 0);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) U(InternetCloseHandle)(h);
    EXPECT_STR(fc_cmd(&x, 0), "USER urluser");
    EXPECT_STR(fc_cmd(&x, 1), "PASS urlpass");
    fc_end(&x);
}

TEST(ftpc_url_type_a_and_i) {
    REQUIRE(U(InternetOpenUrlA));
    static const struct { const char *suffix; const char *type; } tab[] = { { ";type=a", "TYPE A" }, { ";type=i", "TYPE I" }, { ";TYPE=A", "TYPE A" } };
    for (int i = 0; i < NF(tab); i++) {
        srv_ftp_config c = FC_STD_CFG;
        fcx x; if (!fc_start(&x, &c)) return;
        char path[64]; snprintf(path, sizeof path, "/lf.txt%s", tab[i].suffix);
        HINTERNET h = open_url(&x, path, T_INET_FRESH | INTERNET_FLAG_PASSIVE);
        CHECKF(h != NULL, "%s err=%lu", path, GetLastError());
        if (h) { char b[32] = ""; fc_read(h, b, sizeof b, NULL); EXPECT_STR(b, "a\nb\nc"); U(InternetCloseHandle)(h); }
        CHECKF(fc_find(&x, tab[i].type, 0) >= 0, "%s: seq %s", path, fc_seq(&x, 0));
        fc_end(&x);
    }
}

TEST(ftpc_url_bad_type_invalid_url) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET h = open_url(&x, "/lf.txt;type=x", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(h == NULL, ERROR_INTERNET_INVALID_URL);
    if (h) U(InternetCloseHandle)(h);
    Sleep(50);
    EXPECT_EQ(srv_conn_count(x.s), 0);
    fc_end(&x);
}

TEST(ftpc_url_directory_html) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/pub/", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FIND_HTML);
        char *b = calloc(1, 16384); int ok = 0;
        size_t n = fc_read(h, b, 16384, &ok);
        CHECK(ok);
        t_note("directory HTML (%zu bytes): %.600s", n, b);
        CHECKF(strstr(b, "readme.txt") && strstr(b, "data.bin"), "html lacks entries");
        CHECKF(strstr(b, "<A HREF=\"") != NULL || strstr(b, "<a href=\"") != NULL, "no anchors");
        free(b);
        U(InternetCloseHandle)(h);
    }
    fc_dump(&x);
    CHECK(fc_find(&x, "LIST", 0) >= 0);
    fc_end(&x);
}

TEST(ftpc_url_root_directory) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) {
        char *b = calloc(1, 16384); fc_read(h, b, 16384, NULL);
        CHECKF(strstr(b, "hello.txt") && strstr(b, "pub"), "root html: %.300s", b);
        free(b);
        U(InternetCloseHandle)(h);
    }
    fc_dump(&x);
    fc_end(&x);
}

TEST(ftpc_url_directory_without_slash) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/pub", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) {
        DWORD t = 0, l = sizeof t;
        U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &l);
        char *b = calloc(1, 16384); fc_read(h, b, 16384, NULL);
        t_note("ftp://.../pub (no slash): handle type %lu, body %.200s", t, b);
        CHECK(strstr(b, "readme.txt") != NULL);
        free(b);
        U(InternetCloseHandle)(h);
    }
    fc_dump(&x);
    int r = fc_find(&x, "RETR", 0), cw = fc_find(&x, "CWD", 0);
    CHECKF(r >= 0 && cw > r, "file attempt first, then CWD: %s", fc_seq(&x, 0));
    fc_end(&x);
}

TEST(ftpc_url_type_d_forces_directory) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/pub;type=d", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) { char *b = calloc(1, 16384); fc_read(h, b, 16384, NULL); CHECK(strstr(b, "readme.txt") != NULL); free(b); U(InternetCloseHandle)(h); }
    fc_dump(&x);
    CHECK(fc_find(&x, "RETR", 0) < 0);
    fc_end(&x);
}

TEST(ftpc_url_missing_path) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET h = open_url(&x, "/ghost.txt", T_INET_FRESH | INTERNET_FLAG_PASSIVE);
    DWORD e = GetLastError();
    CHECK(h == NULL);
    t_note("ftp:// missing file: err=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_EXTENDED_ERROR);
    if (h) U(InternetCloseHandle)(h);
    fc_dump(&x);
    fc_end(&x);
}

TEST(ftpc_url_directory_raw_data) {
    REQUIRE(U(InternetOpenUrlA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h = open_url(&x, "/pub/", T_INET_FRESH | INTERNET_FLAG_PASSIVE | INTERNET_FLAG_RAW_DATA);
    CHECKF(h != NULL, "err=%lu", GetLastError());
    if (h) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FIND);
        WIN32_FIND_DATAA fd[4]; memset(fd, 0, sizeof fd); DWORD rd = 0;
        BOOL ok = U(InternetReadFile)(h, fd, sizeof fd, &rd);
        t_note("RAW_DATA dir read: ok=%d err=%lu bytes=%lu first=[%s]", ok, ok ? 0 : GetLastError(), rd, fd[0].cFileName);
        WIN32_FIND_DATAA f1; memset(&f1, 0, sizeof f1);
        BOOL n1 = U(InternetFindNextFileA)(h, &f1);
        t_note("RAW_DATA InternetFindNextFile: ok=%d err=%lu name=[%s]", n1, n1 ? 0 : GetLastError(), f1.cFileName);
        U(InternetCloseHandle)(h);
    }
    fc_end(&x);
}

TEST(ftpc_url_login_failure) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_ftp_override ov[] = { { "PASS", "530 Login incorrect.", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_start(&x, &c)) return;
    x.hi = t_inet_open("ftpc");
    char url[256]; snprintf(url, sizeof url, "ftp://bad:creds@127.0.0.1:%u/hello.txt", srv_port(x.s));
    SetLastError(0);
    HINTERNET h = U(InternetOpenUrlA)(x.hi, url, NULL, 0, T_INET_FRESH | INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(h == NULL, ERROR_INTERNET_INCORRECT_PASSWORD);
    if (h) U(InternetCloseHandle)(h);
    fc_end(&x);
}
