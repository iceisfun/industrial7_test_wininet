/* fc_extra.c - review pass 2 additions: ANSI-code-page conversion of the W entry points (FtpCreateDirectoryW and
 * FtpGetCurrentDirectoryW convert with CP_ACP, decomp), FtpGetFile/FtpPutFile in active mode, FtpGetFile into a
 * local path that is a directory (InternalFtpGetFileW creates the local file before any traffic), CDUP/".." forms,
 * FtpCommandW with a data connection, handles of a closed parent, and InternetReadFile on a find handle.
 * Evidence: tests/ftp_client/EVIDENCE.md ("Pass 2 additions"). */
#include "ftp.h"
#include <stdlib.h>

static int std_open(fcx *x) { srv_ftp_config c = FC_STD_CFG; return fc_open(x, &c); }

/* ------------------------------------------------------------------ W names -> CP_ACP on the wire */
TEST(ftpc_x_w_name_converted_with_acp) {
    REQUIRE(U(FtpCreateDirectoryW));
    if (GetACP() != 1252) { t_skip("ACP %u is not 1252", GetACP()); return; }
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    CHECKF(U(FtpCreateDirectoryW)(x.hc, L"caf\x00e9"), "err=%lu", GetLastError());
    /* FtpCreateDirectoryW: WideCharToMultiByte(CP_ACP, 0, ...) then FtpCreateDirectoryA */
    EXPECT_STR(fc_cmd(&x, 2), "MKD caf\xe9");
    fc_end(&x);
}

TEST(ftpc_x_w_unmappable_name_note) {
    REQUIRE(U(FtpCreateDirectoryW));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryW)(x.hc, L"x\x4e2dy");
    DWORD e = ok ? 0 : GetLastError();
    const char *c = fc_cmd(&x, 2);
    char hex[64] = ""; size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)c; *p && o < sizeof hex - 4; p++) o += snprintf(hex + o, sizeof hex - o, "%02x", *p);
    t_note("FtpCreateDirectoryW(L\"x\\u4e2dy\") ACP=%u: ok=%d err=%lu wire=[%s] hex %s", GetACP(), ok, e, c, hex);
    CHECK(!strncmp(c, "MKD x", 5));
    fc_end(&x);
}

TEST(ftpc_x_pwd_w_converts_with_acp) {
    REQUIRE(U(FtpGetCurrentDirectoryW));
    if (GetACP() != 1252) { t_skip("ACP %u is not 1252", GetACP()); return; }
    static const srv_ftp_override ov[] = { { "PWD", "257 \"/caf\xe9\" is current directory.", 0 } };
    srv_ftp_config c; memset(&c, 0, sizeof c); c.overrides = ov; c.noverrides = 1;
    fcx x; if (!fc_open(&x, &c)) return;
    WCHAR d[32]; memset(d, 0x5a, sizeof d); DWORD l = NF(d);
    SetLastError(0);
    CHECKF(U(FtpGetCurrentDirectoryW)(x.hc, d, &l), "err=%lu", GetLastError());
    EXPECT_WSTR(d, L"/caf\x00e9");
    EXPECT_EQ(l, 6);   /* MultiByteToWideChar(..., -1, ...) count: includes the NUL */
    fc_end(&x);
}

/* ------------------------------------------------------------------ directory navigation forms */
TEST(ftpc_x_cwd_dotdot_verbatim) {
    REQUIRE(U(FtpSetCurrentDirectoryA)); REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, ".."));
    char d[64] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/");
    EXPECT_STR(fc_seq(&x, 2), "CWD pub|CWD ..|PWD");
    fc_end(&x);
}

TEST(ftpc_x_cdup_via_command) {
    REQUIRE(U(FtpCommandA)); REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "/pub"));
    CHECKF(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "CDUP", 0, NULL), "err=%lu", GetLastError());
    char d[64] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/");   /* the client keeps no directory cache: PWD asks the server */
    EXPECT_STR(fc_seq(&x, 2), "CWD /pub|CDUP|PWD");
    fc_end(&x);
}

/* ------------------------------------------------------------------ whole-file transfers in active mode */
TEST(ftpc_x_getfile_active_mode) {
    REQUIRE(U(FtpGetFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!fc_connect(&x, NULL, NULL, 0)) { CHECKF(0, "connect err=%lu", GetLastError()); fc_end(&x); return; }
    const char *loc = fc_local("actget.txt");
    fc_del_local(loc);
    CHECKF(U(FtpGetFileA)(x.hc, "pub/readme.txt", loc, FALSE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "err=%lu", GetLastError());
    size_t n = 0; char *p = fc_get_local(loc, &n);
    EXPECT_STR(p ? p : "", "read me\n");
    free(p);
    fc_del_local(loc);
    CHECK(fc_find(&x, "PORT 127,0,0,1,", 0) >= 0);
    CHECK(fc_find(&x, "PASV", 0) < 0);
    CHECK(fc_find(&x, "RETR pub/readme.txt", 0) >= 0);
    fc_end(&x);
}

TEST(ftpc_x_putfile_active_mode) {
    REQUIRE(U(FtpPutFileA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_start(&x, &c)) return;
    if (!fc_connect(&x, NULL, NULL, 0)) { CHECKF(0, "connect err=%lu", GetLastError()); fc_end(&x); return; }
    const char *loc = fc_local("actput.txt");
    CHECK(fc_put_local(loc, "active upload", 13));
    CHECKF(U(FtpPutFileA)(x.hc, loc, "up.txt", FC_BIN, 0), "err=%lu", GetLastError());
    fc_del_local(loc);
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/up.txt", &n);
    EXPECT_STR(d ? d : "", "active upload");
    EXPECT_EQ(n, 13);
    int port = fc_find(&x, "PORT 127,0,0,1,", 0), stor = fc_find(&x, "STOR up.txt", 0);
    CHECK(port >= 0 && stor > port);
    CHECK(fc_find(&x, "PASV", 0) < 0);
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpGetFile local-side failures */
TEST(ftpc_x_getfile_local_path_is_directory) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    char dir[MAX_PATH]; snprintf(dir, sizeof dir, "%s", fc_local("adir"));
    CHECK(CreateDirectoryA(dir, NULL));
    int before = fc_ncmd(&x);
    SetLastError(0);
    /* InternalFtpGetFileW: CreateFileW(local, GENERIC_WRITE, CREATE_ALWAYS) fails on a directory -> 5, no traffic */
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", dir, FALSE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_ACCESS_DENIED);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), before);
    DWORD a = GetFileAttributesA(dir);
    CHECK(a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY));   /* not deleted */
    SetLastError(0);
    /* fail-if-exists on a directory: Win10 (VM, triage 2026-11) reports 5, not 80 (CREATE_NEW on a directory) */
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", dir, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_ACCESS_DENIED);
    RemoveDirectoryA(dir);
    fc_end(&x);
}

TEST(ftpc_x_getfile_session_usable_after_local_failure) {
    REQUIRE(U(FtpGetFileA));
    fcx x; if (!std_open(&x)) return;
    const char *loc = fc_local("exists.txt");
    CHECK(fc_put_local(loc, "keep", 4));
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetFileA)(x.hc, "hello.txt", loc, TRUE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), ERROR_FILE_EXISTS);
    size_t n = 0; char *p = fc_get_local(loc, &n);
    EXPECT_STR(p ? p : "", "keep");   /* untouched */
    free(p);
    /* the connection is not busy: a second GetFile with overwrite works */
    CHECKF(U(FtpGetFileA)(x.hc, "hello.txt", loc, FALSE, FILE_ATTRIBUTE_NORMAL, FC_BIN, 0), "err=%lu", GetLastError());
    p = fc_get_local(loc, &n);
    EXPECT_STR(p ? p : "", "hello");
    free(p);
    fc_del_local(loc);
    EXPECT_EQ(fc_count(&x, "RETR"), 1);
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpCommandW with a data connection */
TEST(ftpc_x_command_w_data_handle) {
    REQUIRE(U(FtpCommandW));
    fcx x; if (!std_open(&x)) return;
    HINTERNET h = NULL;
    CHECKF(U(FtpCommandW)(x.hc, TRUE, FTP_TRANSFER_TYPE_BINARY, L"RETR pub/readme.txt", 0x31, &h), "err=%lu", GetLastError());
    if (h) {
        char b[64] = ""; fc_read(h, b, sizeof b, NULL);
        EXPECT_STR(b, "read me\n");
        DWORD_PTR ctx = 0; DWORD l = sizeof ctx;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &ctx, &l));
        EXPECT_EQ(ctx, 0x31);
        U(InternetCloseHandle)(h);
    } else CHECK(h != NULL);
    EXPECT_STR(fc_cmd(&x, 2), "TYPE I");
    CHECK(fc_find(&x, "RETR pub/readme.txt", 0) >= 0);
    fc_end(&x);
}

/* ------------------------------------------------------------------ closed parents */
TEST(ftpc_x_close_session_invalidates_connect) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(InternetCloseHandle)(x.hi)); x.hi = NULL;
    char d[32] = ""; DWORD l = sizeof d;
    SetLastError(0);
    BOOL ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
    DWORD e = ok ? 0 : GetLastError();
    t_note("PWD on a connect handle whose session was closed: ok=%d err=%lu", ok, e);
    CHECK(!ok);
    EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    x.hc = NULL;   /* closed with its parent */
    fc_end(&x);
}

/* ------------------------------------------------------------------ InternetReadFile on a plain find handle */
TEST(ftpc_x_readfile_on_find_handle_note) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(InternetReadFile));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        char b[64]; DWORD r = 0xdead;
        SetLastError(0);
        BOOL ok = U(InternetReadFile)(hf, b, sizeof b, &r);
        DWORD e = ok ? 0 : GetLastError();
        t_note("InternetReadFile on an FTP find handle: ok=%d err=%lu read=%lu", ok, e, r);
        /* whatever happens, FindNext still delivers the remaining entries */
        int more = 0; for (int g = 0; g < 50 && U(InternetFindNextFileA)(hf, &fd); g++) more++;
        t_note("FindNext after ReadFile: %d more entries", more);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ uploads: data arrives exactly once */
TEST(ftpc_x_putfile_binary_bytes_exact) {
    REQUIRE(U(FtpPutFileA));
    fcx x; if (!std_open(&x)) return;
    static unsigned char raw[512];
    for (int i = 0; i < (int)sizeof raw; i++) raw[i] = (unsigned char)(i * 7 + 3);
    raw[10] = '\r'; raw[11] = '\n'; raw[20] = '\n'; raw[30] = 0;
    const char *loc = fc_local("bin.dat");
    CHECK(fc_put_local(loc, raw, sizeof raw));
    CHECKF(U(FtpPutFileA)(x.hc, loc, "bin.dat", FC_BIN, 0), "err=%lu", GetLastError());
    fc_del_local(loc);
    CHECK(srv_wait_events(x.s, SRV_EV_FTP_DATA, 1, 3000));
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/bin.dat", &n);
    EXPECT_EQ(n, (long)sizeof raw);
    CHECK(d && n == (long)sizeof raw && !memcmp(d, raw, sizeof raw));
    EXPECT_STR(fc_seq(&x, 2), "TYPE I|PASV|STOR bin.dat");
    fc_end(&x);
}
