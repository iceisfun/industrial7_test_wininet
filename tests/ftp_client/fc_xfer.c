/* fc_xfer.c - FtpOpenFile (read/write, ASCII/BINARY), FtpGetFileSize, FtpGetFile/FtpPutFile (+W, +Ex),
 * data-connection negotiation (TYPE, PASV/EPSV, PORT/EPRT, PASV refusal fallback), transfer-in-progress rules.
 * Decomp: InternalFtpOpenFileA, wFtpOpenFile, I_NegotiateDataConnection, I_AttemptDataNegotiation, FtpGetFileSize,
 * InternalFtpGetFileW, InternalFtpPutFileW, FtpGetFileA, FtpPutFileA, FtpGetFileEx, wFtpReadFile, wFtpWriteFile,
 * wFtpCloseFile. */
#include "ftp.h"
#include <stdlib.h>

static int std_open(fcx *x) { srv_ftp_config c = FC_STD_CFG; return fc_open(x, &c); }

/* ------------------------------------------------------------------ FtpOpenFile read */
TEST(ftpc_open_read_binary_wire) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    char b[32] = ""; int ok = 0;
    if (hf) { size_t n = fc_read(hf, b, sizeof b, &ok); EXPECT_EQ(n, 5); CHECK(ok); U(InternetCloseHandle)(hf); }
    EXPECT_STR(b, "hello");
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|SIZE hello.txt|RETR hello.txt");
    fc_end(&x);
}

TEST(ftpc_open_read_ascii_wire) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_ASC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    char b[32] = "";
    if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
    EXPECT_STR(b, "hello");
    EXPECT_STR(fc_seq(&x, 2), "TYPE A|PASV|SIZE hello.txt|RETR hello.txt");
    fc_end(&x);
}

TEST(ftpc_open_flags_zero_is_binary) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) U(InternetCloseHandle)(hf);
    EXPECT_STR(fc_cmd(&x, 2), "TYPE I");
    fc_end(&x);
}

TEST(ftpc_open_path_forms_verbatim) {
    REQUIRE(U(FtpOpenFileA));
    static const struct { const char *arg; const char *retr; } tab[] = {
        { "/pub/readme.txt", "RETR /pub/readme.txt" }, { "pub/readme.txt", "RETR pub/readme.txt" },
        { "dir two/in space.txt", "RETR dir two/in space.txt" }, { "./hello.txt", "RETR ./hello.txt" },
    };
    for (int i = 0; i < NF(tab); i++) {
        fcx x; if (!std_open(&x)) return;
        HINTERNET hf = U(FtpOpenFileA)(x.hc, tab[i].arg, GENERIC_READ, FC_BIN, 0);
        CHECKF(hf != NULL, "%s err=%lu", tab[i].arg, GetLastError());
        if (hf) U(InternetCloseHandle)(hf);
        CHECKF(fc_find(&x, tab[i].retr, 0) >= 0, "missing [%s] in %s", tab[i].retr, fc_seq(&x, 0));
        char sz[256]; snprintf(sz, sizeof sz, "SIZE %s", tab[i].arg);
        CHECKF(fc_find(&x, sz, 0) >= 0, "missing [%s]", sz);
        fc_end(&x);
    }
}

TEST(ftpc_open_read_relative_to_cwd) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "readme.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    char b[32] = "";
    if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
    EXPECT_STR(b, "read me\n");
    fc_end(&x);
}

TEST(ftpc_open_read_large_binary) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "/pub/data.bin", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        char *b = malloc(120000); int ok = 0;
        size_t n = fc_read(hf, b, 120000, &ok);
        CHECK(ok);
        EXPECT_EQ(n, 100000);
        CHECK(srv_pattern_check(b, n, 0));
        free(b);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_open_read_small_chunks) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetReadFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "/pub/data.bin", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) {
        size_t total = 0; int good = 1; unsigned char c[7];
        for (int g = 0; g < 30000; g++) {
            DWORD rd = 0;
            if (!U(InternetReadFile)(hf, c, sizeof c, &rd)) { good = 0; break; }
            if (!rd) break;
            if (!srv_pattern_check(c, rd, total)) good = 0;
            total += rd;
        }
        CHECK(good);
        EXPECT_EQ(total, 100000);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_open_read_empty_file) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetReadFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "empty.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        char b[8]; DWORD rd = 99;
        CHECK(U(InternetReadFile)(hf, b, sizeof b, &rd));
        EXPECT_EQ(rd, 0);
        rd = 99;
        CHECK(U(InternetReadFile)(hf, b, sizeof b, &rd));
        EXPECT_EQ(rd, 0);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_ascii_read_no_newline_conversion) {
    REQUIRE(U(FtpOpenFileA));
    static const char *names[] = { "crlf.txt", "lf.txt" };
    static const char *want[] = { "a\r\nb\r\n", "a\nb\nc" };
    for (int i = 0; i < 2; i++) {
        fcx x; if (!std_open(&x)) return;
        HINTERNET hf = U(FtpOpenFileA)(x.hc, names[i], GENERIC_READ, FC_ASC, 0);
        CHECK(hf != NULL);
        char b[32] = "";
        if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
        CHECKF(!strcmp(b, want[i]), "%s: bytes changed in ASCII mode (len %zu)", names[i], strlen(b));
        fc_end(&x);
    }
}

TEST(ftpc_open_read_missing_extended_error) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "ghost.bin", GENERIC_READ, FC_BIN, 0);
    EXPECT_FAIL(hf == NULL, ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 ghost.bin: No such file or directory.") != NULL, "resp=[%s]", r);
    /* SIZE failing does not stop the RETR attempt */
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|SIZE ghost.bin|RETR ghost.bin");
    /* the session is still usable */
    HINTERNET h2 = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(h2 != NULL, "err=%lu", GetLastError());
    if (h2) U(InternetCloseHandle)(h2);
    fc_end(&x);
}

TEST(ftpc_open_retr_reply_classes) {
    REQUIRE(U(FtpOpenFileA));
    static const struct { const char *reply; } tab[] = { { "450 File busy." }, { "550 Denied." }, { "530 Not logged in." }, { "350 Odd." } };
    for (int i = 0; i < NF(tab); i++) {
        srv_ftp_override ov[] = { { "RETR", tab[i].reply, 0 } };
        srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        SetLastError(0);
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
        DWORD e = GetLastError();
        CHECKF(hf == NULL && e == ERROR_INTERNET_EXTENDED_ERROR, "RETR [%s]: h=%p err=%lu", tab[i].reply, hf, e);
        if (hf) U(InternetCloseHandle)(hf);
        fc_end(&x);
    }
}

TEST(ftpc_open_validation_87) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(FtpOpenFileW));
    fcx x; if (!std_open(&x)) return;
    static const struct { const char *name; DWORD access; DWORD flags; } tab[] = {
        { NULL, GENERIC_READ, FC_BIN }, { "", GENERIC_READ, FC_BIN },
        { "hello.txt", 0, FC_BIN }, { "hello.txt", GENERIC_READ | GENERIC_WRITE, FC_BIN },
        { "hello.txt", GENERIC_EXECUTE, FC_BIN }, { "hello.txt", GENERIC_ALL, FC_BIN },
        { "hello.txt", GENERIC_READ | 1, FC_BIN }, { "hello.txt", GENERIC_READ, FC_NC | 3 },
        { "hello.txt", GENERIC_WRITE, FC_NC | 3 }, { "hello.txt", FILE_READ_DATA, FC_BIN },
    };
    for (int i = 0; i < NF(tab); i++) {
        SetLastError(0);
        HINTERNET hf = U(FtpOpenFileA)(x.hc, tab[i].name, tab[i].access, tab[i].flags, 0);
        DWORD e = GetLastError();
        CHECKF(hf == NULL && e == ERROR_INVALID_PARAMETER, "row %d: h=%p err=%lu", i, hf, e);
        if (hf) U(InternetCloseHandle)(hf);
    }
    SetLastError(0);
    EXPECT_FAIL(U(FtpOpenFileW)(x.hc, NULL, GENERIC_READ, FC_BIN, 0) == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    EXPECT_FAIL(U(FtpOpenFileW)(x.hc, L"", GENERIC_READ, FC_BIN, 0) == NULL, ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    fc_end(&x);
}

TEST(ftpc_open_w) {
    REQUIRE(U(FtpOpenFileW));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileW)(x.hc, L"dir two/in space.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    char b[32] = "";
    if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
    EXPECT_STR(b, "spaced");
    CHECK(fc_find(&x, "RETR dir two/in space.txt", 0) >= 0);
    fc_end(&x);
}

TEST(ftpc_file_handle_properties) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FILE);
        HINTERNET p = NULL; l = sizeof p;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_PARENT_HANDLE, &p, &l));
        EXPECT_EQ(p, x.hc);
        char url[256] = ""; l = sizeof url;
        BOOL ok = U(InternetQueryOptionA)(hf, INTERNET_OPTION_URL, url, &l);
        t_note("FTP file handle URL: ok=%d [%s]", ok, url);
        DWORD rb = 0; l = sizeof rb;
        ok = U(InternetQueryOptionA)(hf, INTERNET_OPTION_READ_BUFFER_SIZE, &rb, &l);
        t_note("FTP file handle read buffer size: ok=%d %lu", ok, rb);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ transfer-in-progress rules */
TEST(ftpc_open_second_open_in_progress) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h1 = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(h1 != NULL);
    int before = fc_ncmd(&x);
    SetLastError(0);
    HINTERNET h2 = U(FtpOpenFileA)(x.hc, "lf.txt", GENERIC_READ, FC_BIN, 0);
    EXPECT_FAIL(h2 == NULL, ERROR_FTP_TRANSFER_IN_PROGRESS);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), before);
    if (h2) U(InternetCloseHandle)(h2);
    if (h1) { char b[16]; fc_read(h1, b, sizeof b, NULL); U(InternetCloseHandle)(h1); }
    HINTERNET h3 = U(FtpOpenFileA)(x.hc, "lf.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(h3 != NULL, "after close err=%lu", GetLastError());
    char b[16] = "";
    if (h3) { fc_read(h3, b, sizeof b, NULL); U(InternetCloseHandle)(h3); }
    EXPECT_STR(b, "a\nb\nc");
    fc_end(&x);
}

TEST(ftpc_commands_blocked_while_file_open) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h1 = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(h1 != NULL);
    char d[32]; DWORD l = sizeof d;
    SetLastError(0); EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(x.hc, d, &l), ERROR_FTP_TRANSFER_IN_PROGRESS);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(x.hc, "pub"), ERROR_FTP_TRANSFER_IN_PROGRESS);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(x.hc, "lf.txt"), ERROR_FTP_TRANSFER_IN_PROGRESS);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryA)(x.hc, "nd"), ERROR_FTP_TRANSFER_IN_PROGRESS);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL), ERROR_FTP_TRANSFER_IN_PROGRESS);
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hfind = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    EXPECT_FAIL(hfind == NULL, ERROR_FTP_TRANSFER_IN_PROGRESS);
    if (hfind) U(InternetCloseHandle)(hfind);
    Sleep(50);
    CHECK(fc_find(&x, "PWD", 0) < 0 && fc_find(&x, "CWD", 0) < 0 && fc_find(&x, "DELE", 0) < 0 && fc_find(&x, "NOOP", 0) < 0);
    if (h1) { char b[16]; fc_read(h1, b, sizeof b, NULL); U(InternetCloseHandle)(h1); }
    l = sizeof d;
    CHECKF(U(FtpGetCurrentDirectoryA)(x.hc, d, &l), "after close err=%lu", GetLastError());
    fc_end(&x);
}

TEST(ftpc_close_read_before_eof_then_continue) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetReadFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) { char b[2]; DWORD rd = 0; CHECK(U(InternetReadFile)(hf, b, 2, &rd)); U(InternetCloseHandle)(hf); }
    char d[64] = ""; DWORD l = sizeof d;
    BOOL ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
    t_note("PWD after early close: ok=%d err=%lu dir=[%s]", ok, ok ? 0 : GetLastError(), d);
    Sleep(100);
    fc_dump(&x);
    int ab = -1; for (int i = 0; i < fc_ncmd(&x); i++) if (strstr(fc_cmd(&x, i), "ABOR")) ab = i;
    t_note("ABOR on the wire: %s", ab >= 0 ? "yes" : "no");
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpOpenFile write */
TEST(ftpc_open_write_wire_and_data) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "up.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        DWORD w = 0;
        CHECK(U(InternetWriteFile)(hf, "part1-", 6, &w)); EXPECT_EQ(w, 6);
        CHECK(U(InternetWriteFile)(hf, "part2", 5, &w)); EXPECT_EQ(w, 5);
        CHECK(U(InternetCloseHandle)(hf));
    }
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/up.bin", &n);
    CHECK(d && n == 11 && !memcmp(d, "part1-part2", 11));
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|STOR up.bin");
    DWORD e; const char *r = fc_resp(&e);
    t_note("last response after write close: [%s]", r);
    CHECKF(strstr(r, "226 Transfer complete.") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_open_write_ascii_wire_no_conversion) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "text.txt", GENERIC_WRITE, FC_ASC, 0);
    CHECK(hf != NULL);
    if (hf) { DWORD w; CHECK(U(InternetWriteFile)(hf, "l1\nl2\r\nl3\r", 10, &w)); U(InternetCloseHandle)(hf); }
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/text.txt", &n);
    CHECKF(d && n == 10 && !memcmp(d, "l1\nl2\r\nl3\r", 10), "stored %ld bytes", n);
    EXPECT_STR(fc_seq(&x, 2), "TYPE A|PASV|STOR text.txt");
    fc_end(&x);
}

TEST(ftpc_open_write_empty_file) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "zero.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) CHECK(U(InternetCloseHandle)(hf));
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = -1; const char *d = srv_ftp_file_data(x.s, "/zero.bin", &n);
    CHECK(d != NULL && n == 0);
    fc_end(&x);
}

TEST(ftpc_open_write_large) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "big.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECK(hf != NULL);
    size_t total = 300000;
    if (hf) {
        unsigned char *b = malloc(total);
        for (size_t i = 0; i < total; i++) b[i] = srv_pattern_byte(i);
        size_t o = 0; int good = 1;
        while (o < total) { DWORD w = 0, k = (DWORD)(total - o > 65536 ? 65536 : total - o); if (!U(InternetWriteFile)(hf, b + o, k, &w) || w != k) { good = 0; break; } o += w; }
        CHECK(good);
        free(b);
        U(InternetCloseHandle)(hf);
    }
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 5000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/big.bin", &n);
    CHECK(d && n == (long)total && srv_pattern_check(d, n, 0));
    fc_end(&x);
}

TEST(ftpc_open_write_rejected) {
    REQUIRE(U(FtpOpenFileA));
    static const srv_ftp_override ov[] = { { "STOR", "553 Could not create file.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "nope.bin", GENERIC_WRITE, FC_BIN, 0);
    EXPECT_FAIL(hf == NULL, ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "553 Could not create file.") != NULL, "resp=[%s]", r);
    CHECK(fc_find(&x, "SIZE", 0) < 0);
    fc_end(&x);
}

TEST(ftpc_read_write_direction_mismatch) {
    REQUIRE(U(FtpOpenFileA)); REQUIRE(U(InternetReadFile)); REQUIRE(U(InternetWriteFile));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hr = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hr != NULL);
    if (hr) {
        DWORD w = 77;
        SetLastError(0);
        BOOL ok = U(InternetWriteFile)(hr, "x", 1, &w);
        DWORD e = GetLastError();
        CHECK(!ok);
        t_note("InternetWriteFile on FTP read handle: err=%lu", e);
        EXPECT_EQ(e, ERROR_ACCESS_DENIED);
        char b[16]; fc_read(hr, b, sizeof b, NULL);
        U(InternetCloseHandle)(hr);
    }
    HINTERNET hw = U(FtpOpenFileA)(x.hc, "w.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECK(hw != NULL);
    if (hw) {
        char b[4]; DWORD rd = 77;
        SetLastError(0);
        BOOL ok = U(InternetReadFile)(hw, b, sizeof b, &rd);
        DWORD e = GetLastError();
        CHECK(!ok);
        t_note("InternetReadFile on FTP write handle: err=%lu", e);
        EXPECT_EQ(e, ERROR_ACCESS_DENIED);
        U(InternetCloseHandle)(hw);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpGetFileSize */
TEST(ftpc_getfilesize_from_size_reply) {
    REQUIRE(U(FtpGetFileSize));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "/pub/data.bin", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) {
        DWORD hi = 0xdead;
        SetLastError(0xbeef);
        DWORD lo = U(FtpGetFileSize)(hf, &hi);
        EXPECT_EQ(lo, 100000);
        EXPECT_EQ(hi, 0);
        EXPECT_EQ(GetLastError(), 0);
        CHECK(U(FtpGetFileSize)(hf, NULL) == 100000);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_getfilesize_64bit_and_null_high) {
    REQUIRE(U(FtpGetFileSize));
    static const srv_ftp_override ov[] = { { "SIZE", "213 5000000000", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) {
        DWORD hi = 0;
        DWORD lo = U(FtpGetFileSize)(hf, &hi);
        EXPECT_EQ(lo, 705032704);
        EXPECT_EQ(hi, 1);
        SetLastError(0);
        lo = U(FtpGetFileSize)(hf, NULL);
        EXPECT_EQ(lo, 0xffffffff);
        EXPECT_ERR(ERROR_ARITHMETIC_OVERFLOW);
        char b[16] = ""; fc_read(hf, b, sizeof b, NULL);
        EXPECT_STR(b, "hello");   /* the real data still flows */
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_getfilesize_from_150_when_size_unsupported) {
    REQUIRE(U(FtpGetFileSize));
    static const char *size_replies[] = { "502 SIZE not implemented.", "550 Could not get size.", "213 notanumber" };
    for (int i = 0; i < NF(size_replies); i++) {
        srv_ftp_override ov[] = { { "SIZE", size_replies[i], 0 } };
        srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "/pub/readme.txt", GENERIC_READ, FC_BIN, 0);
        CHECKF(hf != NULL, "[%s] err=%lu", size_replies[i], GetLastError());
        if (hf) {
            DWORD hi = 9; SetLastError(0);
            DWORD lo = U(FtpGetFileSize)(hf, &hi);
            CHECKF(lo == 8 && hi == 0, "SIZE [%s]: size from \"150 ... (8 bytes)\" = %lu:%lu err=%lu", size_replies[i], hi, lo, GetLastError());
            U(InternetCloseHandle)(hf);
        }
        fc_end(&x);
    }
}

TEST(ftpc_getfilesize_unknown_on_write_handle) {
    REQUIRE(U(FtpGetFileSize));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "new.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECK(hf != NULL);
    if (hf) {
        DWORD hi = 5;
        SetLastError(0);
        DWORD lo = U(FtpGetFileSize)(hf, &hi);
        EXPECT_EQ(lo, 0xffffffff);
        EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
        EXPECT_EQ(hi, 0);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_getfilesize_wrong_handles) {
    REQUIRE(U(FtpGetFileSize));
    fcx x; if (!std_open(&x)) return;
    DWORD hi = 3;
    SetLastError(0);
    DWORD r = U(FtpGetFileSize)(x.hc, &hi);
    EXPECT_EQ(r, 0xffffffff);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    EXPECT_EQ(hi, 0);
    SetLastError(0);
    r = U(FtpGetFileSize)(x.hi, NULL);
    EXPECT_EQ(r, 0xffffffff);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0);
    r = U(FtpGetFileSize)(NULL, NULL);
    EXPECT_EQ(r, 0xffffffff);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    fc_end(&x);
}

/* ------------------------------------------------------------------ data connection negotiation */
TEST(ftpc_active_mode_port) {
    REQUIRE(U(FtpOpenFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!fc_connect(&x, NULL, NULL, 0)) { CHECKF(0, "connect err=%lu", GetLastError()); fc_end(&x); return; }
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECKF(hf != NULL, "active RETR err=%lu", GetLastError());
    char b[16] = "";
    if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
    EXPECT_STR(b, "hello");
    EXPECT_STR(fc_cmd(&x, 2), "TYPE I");
    CHECKF(!strncmp(fc_cmd(&x, 3), "PORT 127,0,0,1,", 15), "got [%s]", fc_cmd(&x, 3));
    CHECK(fc_find(&x, "PASV", 0) < 0);
    unsigned h[6] = { 0 };
    CHECK(sscanf(fc_cmd(&x, 3), "PORT %u,%u,%u,%u,%u,%u", &h[0], &h[1], &h[2], &h[3], &h[4], &h[5]) == 6 && (h[4] << 8 | h[5]) != 0);
    EXPECT_STR(fc_seq(&x, 4), "SIZE hello.txt|RETR hello.txt");
    fc_end(&x);
}

TEST(ftpc_active_mode_list_and_stor) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(FtpPutFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!fc_connect(&x, NULL, NULL, 0)) { CHECKF(0, "connect err=%lu", GetLastError()); fc_end(&x); return; }
    WIN32_FIND_DATAA v[16]; DWORD err;
    int n = fc_list(&x, "*.txt", v, 16, &err);
    EXPECT_EQ(n, 4);
    HINTERNET hw = U(FtpOpenFileA)(x.hc, "act.bin", GENERIC_WRITE, FC_BIN, 0);
    CHECK(hw != NULL);
    if (hw) { DWORD w; CHECK(U(InternetWriteFile)(hw, "active", 6, &w)); U(InternetCloseHandle)(hw); }
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 2, 3000));
    long m = 0; const char *d = srv_ftp_file_data(x.s, "/act.bin", &m);
    CHECK(d && m == 6 && !memcmp(d, "active", 6));
    EXPECT_EQ(fc_count(&x, "PORT 127,0,0,1,"), 2);
    fc_end(&x);
}

TEST(ftpc_pasv_refused_falls_back_to_port) {
    REQUIRE(U(FtpOpenFileA));
    static const char *refusals[] = { "502 PASV not implemented.", "500 Unknown command.", "425 Cannot open passive connection.", "530 Not now." };
    for (int i = 0; i < NF(refusals); i++) {
        srv_ftp_override ov[] = { { "PASV", refusals[i], 0 } };
        srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
        CHECKF(hf != NULL, "PASV [%s]: err=%lu", refusals[i], GetLastError());
        char b[16] = "";
        if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
        CHECKF(!strcmp(b, "hello"), "PASV [%s]: body [%s]", refusals[i], b);
        const char *seq = fc_seq(&x, 2);
        CHECKF(!strncmp(seq, "TYPE I|PASV|TYPE I|PORT 127,0,0,1,", 34), "PASV [%s]: seq %s", refusals[i], seq);
        fc_end(&x);
    }
}

TEST(ftpc_pasv_other_failures_no_fallback) {
    REQUIRE(U(FtpOpenFileA));
    static const char *replies[] = { "421 Service closing.", "501 Syntax error.", "450 busy", "227 no address here", "227 Entering Passive Mode (1,2,3)" };
    for (int i = 0; i < NF(replies); i++) {
        srv_ftp_override ov[] = { { "PASV", replies[i], 0 } };
        srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        SetLastError(0);
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
        DWORD e = GetLastError();
        CHECKF(hf == NULL && e == ERROR_INTERNET_EXTENDED_ERROR, "PASV [%s]: h=%p err=%lu", replies[i], hf, e);
        Sleep(50);
        CHECKF(fc_find(&x, "PORT", 0) < 0 && fc_find(&x, "RETR", 0) < 0, "PASV [%s]: seq %s", replies[i], fc_seq(&x, 2));
        if (hf) U(InternetCloseHandle)(hf);
        fc_end(&x);
    }
}

TEST(ftpc_pasv_foreign_address_rejected) {
    REQUIRE(U(FtpOpenFileA));
    static const srv_ftp_override ov[] = { { "PASV", "227 Entering Passive Mode (10,9,8,7,4,1).", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    EXPECT_FAIL(hf == NULL, ERROR_INTERNET_EXTENDED_ERROR);
    Sleep(50);
    CHECK(fc_find(&x, "RETR", 0) < 0);
    if (hf) U(InternetCloseHandle)(hf);
    fc_end(&x);
}

TEST(ftpc_type_rejected) {
    REQUIRE(U(FtpOpenFileA));
    static const srv_ftp_override ov[] = { { "TYPE I", "504 Binary not supported.", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    EXPECT_FAIL(hf == NULL, ERROR_INTERNET_EXTENDED_ERROR);
    Sleep(50);
    EXPECT_STR(fc_seq(&x, 2), "TYPE I");
    HINTERNET ha = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_ASC, 0);
    CHECKF(ha != NULL, "ASCII still works: err=%lu", GetLastError());
    if (ha) U(InternetCloseHandle)(ha);
    fc_end(&x);
}

TEST(ftpc_ipv6_active_eprt) {
    REQUIRE(U(FtpOpenFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!srv_has_v6(x.s)) { t_skip("no [::1] listener"); fc_end(&x); return; }
    x.hi = t_inet_open("ftpc");
    x.hc = U(InternetConnectA)(x.hi, "::1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, 0, 0);
    if (!x.hc) {
        DWORD e = GetLastError();
        t_note("InternetConnect(\"::1\") failed %lu; trying \"[::1]\"", e);
        x.hc = U(InternetConnectA)(x.hi, "[::1]", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, 0, 0);
    }
    CHECKF(x.hc != NULL, "connect v6 err=%lu", GetLastError());
    if (x.hc) {
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
        CHECKF(hf != NULL, "v6 active RETR err=%lu", GetLastError());
        char b[16] = "";
        if (hf) { fc_read(hf, b, sizeof b, NULL); U(InternetCloseHandle)(hf); }
        EXPECT_STR(b, "hello");
        int i = fc_find(&x, "EPRT", 0);
        CHECKF(i >= 0 && !strncmp(fc_cmd(&x, i), "EPRT |2|::1|", 12), "seq %s", fc_seq(&x, 0));
        CHECK(fc_find(&x, "PORT", 0) < 0);
    }
    fc_end(&x);
}

TEST(ftpc_ipv6_passive_sends_epsv) {
    REQUIRE(U(FtpOpenFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!srv_has_v6(x.s)) { t_skip("no [::1] listener"); fc_end(&x); return; }
    x.hi = t_inet_open("ftpc");
    x.hc = U(InternetConnectA)(x.hi, "::1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECKF(x.hc != NULL, "connect v6 err=%lu", GetLastError());
    if (x.hc) {
        /* the test server's EPSV listener is IPv4 only, so the transfer itself may fail: assert the command only */
        HINTERNET hf = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
        t_note("v6 passive RETR: h=%p err=%lu seq=%s", hf, hf ? 0 : GetLastError(), fc_seq(&x, 0));
        if (hf) U(InternetCloseHandle)(hf);
        CHECK(fc_find(&x, "EPSV", 0) >= 0);
        CHECK(fc_find(&x, "PASV", 0) < 0);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpGetFile */
TEST(ftpc_getfile_basic) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("get1.txt");
    CHECKF(U(FtpGetFileA)(x.hc, "hello.txt", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "err=%lu", GetLastError());
    size_t n; char *d = fc_get_local(lp, &n);
    CHECK(d && n == 5 && !memcmp(d, "hello", 5));
    free(d);
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|SIZE hello.txt|RETR hello.txt");
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_large_binary) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("get_big.bin");
    CHECKF(U(FtpGetFileA)(x.hc, "/pub/data.bin", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "err=%lu", GetLastError());
    size_t n; char *d = fc_get_local(lp, &n);
    CHECK(d && n == 100000 && srv_pattern_check(d, n, 0));
    free(d);
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_ascii_type_and_no_conversion) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("get_lf.txt");
    CHECK(U(FtpGetFileA)(x.hc, "lf.txt", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_ASC, 0));
    size_t n; char *d = fc_get_local(lp, &n);
    CHECKF(d && n == 5 && !memcmp(d, "a\nb\nc", 5), "local %zu bytes", n);
    free(d);
    EXPECT_STR(fc_cmd(&x, 2), "TYPE A");
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_fail_if_exists) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("exists.txt");
    CHECK(fc_put_local(lp, "original", 8));
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_FILE_EXISTS);
    size_t n; char *d = fc_get_local(lp, &n);
    CHECK(d && n == 8 && !memcmp(d, "original", 8));
    free(d);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);   /* the local file is created before any network traffic */
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_overwrite_existing) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("over.txt");
    CHECK(fc_put_local(lp, "a much longer original content", 30));
    CHECKF(U(FtpGetFileA)(x.hc, "hello.txt", lp, FALSE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "err=%lu", GetLastError());
    size_t n; char *d = fc_get_local(lp, &n);
    CHECK(d && n == 5 && !memcmp(d, "hello", 5));
    free(d);
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_attributes_applied) {
    REQUIRE(U(FtpGetFileA));
    static const DWORD attrs[] = { FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM };
    for (int i = 0; i < NF(attrs); i++) {
        fcx x; if (!std_open(&x)) return;
        const char *lp = fc_local("attr.txt");
        CHECKF(U(FtpGetFileA)(x.hc, "hello.txt", lp, TRUE, attrs[i], FC_BIN, 0), "attr 0x%lx err=%lu", attrs[i], GetLastError());
        DWORD a = GetFileAttributesA(lp);
        CHECKF(a != INVALID_FILE_ATTRIBUTES && (a & attrs[i]) == attrs[i], "attr 0x%lx -> 0x%lx", attrs[i], a);
        fc_del_local(lp);
        fc_end(&x);
    }
}

TEST(ftpc_getfile_remote_missing_leaves_no_file) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("missing.txt");
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "ghost.txt", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_INTERNET_EXTENDED_ERROR);
    CHECK(!fc_local_exists(lp));
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 ghost.txt") != NULL, "resp=[%s]", r);
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_remote_missing_deletes_overwritten_local) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("victim.txt");
    CHECK(fc_put_local(lp, "keep me?", 8));
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "ghost.txt", lp, FALSE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_INTERNET_EXTENDED_ERROR);
    CHECKF(!fc_local_exists(lp), "a failed FtpGetFile(fFailIfExists=FALSE) removes the truncated local file");
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_getfile_local_dir_missing) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    char lp[MAX_PATH]; snprintf(lp, sizeof lp, "%snodir_%lu\\f.txt", t_tmpdir(), GetCurrentProcessId());
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_PATH_NOT_FOUND);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    fc_end(&x);
}

TEST(ftpc_getfile_validation_87) {
    REQUIRE(U(FtpGetFileA)); REQUIRE(U(FtpGetFileW));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("v.txt");
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileA)(x.hc, NULL, lp, TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "", lp, TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", NULL, TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", "", TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", lp, TRUE, 0, FC_NC | 3, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileW)(x.hc, NULL, L"x", TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileW)(x.hc, L"hello.txt", NULL, TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpGetFileW)(x.hc, L"", L"x", TRUE, 0, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    CHECK(!fc_local_exists(lp));
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    fc_end(&x);
}

TEST(ftpc_getfile_w_and_ex) {
    REQUIRE(U(FtpGetFileW)); REQUIRE(U(FtpGetFileEx));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("getw.txt");
    WCHAR wl[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, lp, -1, wl, MAX_PATH);
    CHECKF(U(FtpGetFileW)(x.hc, L"dir two/in space.txt", wl, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "W err=%lu", GetLastError());
    size_t n; char *d = fc_get_local(lp, &n);
    CHECK(d && n == 6 && !memcmp(d, "spaced", 6));
    free(d); fc_del_local(lp);
    CHECKF(U(FtpGetFileEx)(x.hc, "/pub/readme.txt", wl, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "Ex err=%lu", GetLastError());
    d = fc_get_local(lp, &n);
    CHECK(d && n == 8 && !memcmp(d, "read me\n", 8));
    free(d); fc_del_local(lp);
    CHECK(fc_find(&x, "RETR dir two/in space.txt", 0) >= 0 && fc_find(&x, "RETR /pub/readme.txt", 0) >= 0);
    fc_end(&x);
}

TEST(ftpc_getfile_while_file_open) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h1 = U(FtpOpenFileA)(x.hc, "hello.txt", GENERIC_READ, FC_BIN, 0);
    CHECK(h1 != NULL);
    const char *lp = fc_local("busy.txt");
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "lf.txt", lp, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_FTP_TRANSFER_IN_PROGRESS);
    CHECK(!fc_local_exists(lp));
    if (h1) U(InternetCloseHandle)(h1);
    fc_del_local(lp);
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpPutFile */
TEST(ftpc_putfile_basic) {
    REQUIRE(U(FtpPutFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("put1.txt");
    CHECK(fc_put_local(lp, "uploaded content", 16));
    CHECKF(U(FtpPutFileA)(x.hc, lp, "remote.txt", FC_BIN, 0), "err=%lu", GetLastError());
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/remote.txt", &n);
    CHECK(d && n == 16 && !memcmp(d, "uploaded content", 16));
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|STOR remote.txt");
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "226") != NULL, "resp=[%s]", r);
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_putfile_large_and_ascii) {
    REQUIRE(U(FtpPutFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("put_big.bin");
    size_t total = 250001; unsigned char *b = malloc(total);
    for (size_t i = 0; i < total; i++) b[i] = srv_pattern_byte(i);
    CHECK(fc_put_local(lp, b, total));
    free(b);
    CHECKF(U(FtpPutFileA)(x.hc, lp, "/pub/up.bin", FC_ASC, 0), "err=%lu", GetLastError());
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/pub/up.bin", &n);
    CHECK(d && n == (long)total && srv_pattern_check(d, n, 0));
    EXPECT_STR(fc_seq(&x, 2), "TYPE A|PASV|STOR /pub/up.bin");
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_putfile_empty_local) {
    REQUIRE(U(FtpPutFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("put_empty.txt");
    CHECK(fc_put_local(lp, "", 0));
    CHECKF(U(FtpPutFileA)(x.hc, lp, "e.txt", FC_BIN, 0), "err=%lu", GetLastError());
    long n = -1; CHECK(srv_ftp_file_data(x.s, "/e.txt", &n) != NULL && n == 0);
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_putfile_local_missing) {
    REQUIRE(U(FtpPutFileA));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("does_not_exist.txt");
    SetLastError(0);
    EXPECT_FAIL(!U(FtpPutFileA)(x.hc, lp, "r.txt", FC_BIN, 0), ERROR_FILE_NOT_FOUND);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    fc_end(&x);
}

TEST(ftpc_putfile_rejected) {
    REQUIRE(U(FtpPutFileA));
    static const srv_ftp_override ov[] = { { "STOR", "552 Quota exceeded.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    const char *lp = fc_local("put_rej.txt");
    CHECK(fc_put_local(lp, "x", 1));
    SetLastError(0);
    EXPECT_FAIL(!U(FtpPutFileA)(x.hc, lp, "r.txt", FC_BIN, 0), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "552 Quota exceeded.") != NULL, "resp=[%s]", r);
    CHECK(fc_local_exists(lp));   /* the local source is untouched */
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_putfile_validation_87) {
    REQUIRE(U(FtpPutFileA)); REQUIRE(U(FtpPutFileW));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("pv.txt"); fc_put_local(lp, "x", 1);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileA)(x.hc, NULL, "r", FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileA)(x.hc, "", "r", FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileA)(x.hc, lp, NULL, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileA)(x.hc, lp, "", FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileA)(x.hc, lp, "r", FC_NC | 3, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileW)(x.hc, NULL, L"r", FC_BIN, 0), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileW)(x.hc, L"x", NULL, FC_BIN, 0), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_putfile_w_and_ex) {
    REQUIRE(U(FtpPutFileW)); REQUIRE(U(FtpPutFileEx));
    fcx x; if (!std_open(&x)) return;
    const char *lp = fc_local("putw.txt"); CHECK(fc_put_local(lp, "wide", 4));
    WCHAR wl[MAX_PATH]; MultiByteToWideChar(CP_ACP, 0, lp, -1, wl, MAX_PATH);
    CHECKF(U(FtpPutFileW)(x.hc, wl, L"w name.txt", FC_BIN, 0), "W err=%lu", GetLastError());
    CHECKF(U(FtpPutFileEx)(x.hc, wl, "ex.txt", FC_BIN, 0), "Ex err=%lu", GetLastError());
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/w name.txt", &n);
    CHECK(d && n == 4 && !memcmp(d, "wide", 4));
    d = srv_ftp_file_data(x.s, "/ex.txt", &n);
    CHECK(d && n == 4 && !memcmp(d, "wide", 4));
    fc_del_local(lp);
    fc_end(&x);
}

TEST(ftpc_put_then_get_roundtrip) {
    REQUIRE(U(FtpPutFileA)); REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *src = fc_local("rt_src.bin"), *dst = fc_local("rt_dst.bin");
    unsigned char b[4096]; for (int i = 0; i < 4096; i++) b[i] = (unsigned char)(i * 31 + 7);
    CHECK(fc_put_local(src, b, sizeof b));
    CHECK(U(FtpPutFileA)(x.hc, src, "rt.bin", FC_BIN, 0));
    CHECK(U(FtpGetFileA)(x.hc, "rt.bin", dst, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0));
    size_t n; char *d = fc_get_local(dst, &n);
    CHECK(d && n == sizeof b && !memcmp(d, b, sizeof b));
    free(d);
    DWORD hi = 0;
    HINTERNET hf = U(FtpOpenFileA)(x.hc, "rt.bin", GENERIC_READ, FC_BIN, 0);
    CHECK(hf && U(FtpGetFileSize)(hf, &hi) == 4096);
    if (hf) U(InternetCloseHandle)(hf);
    fc_del_local(src); fc_del_local(dst);
    fc_end(&x);
}
