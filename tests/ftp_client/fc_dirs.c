/* fc_dirs.c - FtpGetCurrentDirectory / FtpSetCurrentDirectory / FtpCreateDirectory / FtpRemoveDirectory /
 * FtpDeleteFile / FtpRenameFile (A and W): wire commands, reply-class rules, buffer-length contracts, error mapping.
 * Decomp: InternalFtpGetCurrentDirectoryA, wFtpGetCurrentDirectory, FtpGetCurrentDirectoryW, wFtpSetCurrentDirectory,
 * wFtpCreateDirectory, wFtpRemoveDirectory, wFtpDeleteFile, wFtpRenameFile, I_Command, Internal*A validation. */
#include "ftp.h"

static int std_open(fcx *x) { srv_ftp_config c = FC_STD_CFG; return fc_open(x, &c); }

/* ------------------------------------------------------------------ FtpGetCurrentDirectoryA */
TEST(ftpc_pwd_root) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    char d[64]; memset(d, 'x', sizeof d); DWORD l = sizeof d;
    SetLastError(0xdead);
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/");
    EXPECT_EQ(l, 1);
    EXPECT_STR(fc_seq(&x, 2), "PWD");
    fc_end(&x);
}

TEST(ftpc_pwd_each_call_sends_pwd) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    for (int i = 0; i < 3; i++) { char d[64]; DWORD l = sizeof d; CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l)); }
    EXPECT_EQ(fc_count(&x, "PWD"), 3);
    fc_end(&x);
}

TEST(ftpc_pwd_after_cwd) {
    REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpSetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    char d[64] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/pub");
    EXPECT_EQ(l, 4);
    EXPECT_STR(fc_seq(&x, 2), "CWD pub|PWD");
    fc_end(&x);
}

TEST(ftpc_pwd_dir_with_space) {
    REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpSetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "dir two"));
    char d[64] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/dir two");
    EXPECT_EQ(l, 8);
    EXPECT_STR(fc_cmd(&x, 2), "CWD dir two");
    fc_end(&x);
}

/* PWD reply parsing table: reply text -> (ok, dir or error) */
static const struct { const char *reply; int ok; const char *dir; DWORD err; } pwd_tab[] = {
    { "257 \"/a/b\" is current directory.", 1, "/a/b", 0 },
    { "257 \"/a\"\"b\" quote doubled", 1, "/a", 0 },     /* decomp: a doubled quote is skipped, the next quote ends */
    { "257 \"\"\"\"", 1, "", 0 },
    { "257 \"/\"", 1, "/", 0 },
    { "257 \"/x y/z\" with spaces", 1, "/x y/z", 0 },
    { "257 \"/unterminated", 1, "/unterminated\r\n", 0 },  /* VM: runs to the end of the stored reply incl. CRLF */
    { "257 \"\" empty", 1, "", 0 },
    { "257-first line\r\n257 \"/multi\" last line", 1, "/multi", 0 },
    { "257 /no/quotes/here", 0, NULL, ERROR_INTERNET_EXTENDED_ERROR },
    { "200 \"/x\" but not 257", 1, "", 0 },
    { "250 \"/x\" wrong 2xx code", 1, "", 0 },
    { "350 \"/x\" class 3", 0, NULL, ERROR_INTERNET_EXTENDED_ERROR },
    { "550 PWD not allowed", 0, NULL, ERROR_INTERNET_EXTENDED_ERROR },
    { "421 closing", 0, NULL, ERROR_INTERNET_EXTENDED_ERROR },
    { "502 not implemented", 0, NULL, ERROR_INTERNET_EXTENDED_ERROR },
};
TEST(ftpc_pwd_reply_parsing_table) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    for (int i = 0; i < NF(pwd_tab); i++) {
        srv_ftp_override ov[] = { { "PWD", pwd_tab[i].reply, 0 } };
        srv_ftp_config c = { NULL, 0, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        char d[128]; memset(d, 'z', sizeof d); d[127] = 0; DWORD l = sizeof d;
        SetLastError(0);
        BOOL ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
        DWORD e = GetLastError();
        if (pwd_tab[i].ok < 0) {
            t_note("PWD [%s] -> ok=%d err=%lu dir=[%s] len=%lu", pwd_tab[i].reply, ok, e, ok ? d : "", l);
            fc_end(&x); continue;
        }
        CHECKF(!!ok == pwd_tab[i].ok, "row %d [%s]: ok=%d err=%lu", i, pwd_tab[i].reply, ok, e);
        if (ok && pwd_tab[i].ok) {
            CHECKF(!strcmp(d, pwd_tab[i].dir), "row %d dir [%s] want [%s]", i, d, pwd_tab[i].dir);
            CHECKF(l == strlen(pwd_tab[i].dir), "row %d len %lu", i, l);
        } else if (!ok) {
            CHECKF(e == pwd_tab[i].err, "row %d err %lu want %lu", i, e, pwd_tab[i].err);
        }
        fc_end(&x);
    }
}

TEST(ftpc_pwd_error_response_text) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    static const srv_ftp_override ov[] = { { "PWD", "550 Permission denied for PWD.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    char d[64]; DWORD l = sizeof d;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(x.hc, d, &l), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 Permission denied for PWD.") != NULL, "resp=[%s]", r);
    t_note("last response error field after 550: %lu", e);
    fc_end(&x);
}

TEST(ftpc_pwd_buffer_lengths) {
    REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpSetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "/pub"));
    /* "/pub": 4 chars; success needs room for the NUL; failure reports chars + 1 */
    static const DWORD caps[] = { 1, 2, 3, 4 };
    for (int i = 0; i < NF(caps); i++) {
        char d[16]; memset(d, 'q', sizeof d); DWORD l = caps[i];
        SetLastError(0);
        BOOL ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
        CHECKF(!ok, "cap %lu unexpectedly ok", caps[i]);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        CHECKF(l == 5, "cap %lu -> len %lu", caps[i], l);
    }
    char d[16]; DWORD l = 5;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/pub");
    EXPECT_EQ(l, 4);
    fc_end(&x);
}

TEST(ftpc_pwd_null_buffer_reports_size) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    DWORD l = 100;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(x.hc, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, 2);   /* "/" + NUL */
    EXPECT_EQ(fc_count(&x, "PWD"), 1);   /* the server is still asked */
    fc_end(&x);
}

TEST(ftpc_pwd_null_length_is_87) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    char d[16];
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(x.hc, d, NULL), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_count(&x, "PWD"), 0);
    fc_end(&x);
}

TEST(ftpc_pwd_long_path) {
    REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpCreateDirectoryA));
    fcx x; if (!std_open(&x)) return;
    char name[240]; memset(name, 'd', 230); name[230] = 0;
    CHECK(U(FtpCreateDirectoryA)(x.hc, name));
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, name));
    char d[512] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_EQ(l, 231);
    CHECK(d[0] == '/' && !strcmp(d + 1, name));
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpGetCurrentDirectoryW */
TEST(ftpc_pwd_w_length_includes_nul) {
    REQUIRE(U(FtpGetCurrentDirectoryW));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    WCHAR d[32]; DWORD l = NF(d);
    CHECK(U(FtpGetCurrentDirectoryW)(x.hc, d, &l));
    EXPECT_WSTR(d, L"/pub");
    t_note("FtpGetCurrentDirectoryW success length=%lu for L\"/pub\"", l);
    EXPECT_EQ(l, 5);
    fc_end(&x);
}

TEST(ftpc_pwd_w_small_buffer) {
    REQUIRE(U(FtpGetCurrentDirectoryW));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    WCHAR d[32]; DWORD l = 2;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetCurrentDirectoryW)(x.hc, d, &l), ERROR_INSUFFICIENT_BUFFER);
    t_note("FtpGetCurrentDirectoryW cap 2 -> length %lu", l);
    EXPECT_EQ(l, 10);
    fc_end(&x);
}

TEST(ftpc_pwd_w_null_buffer) {
    REQUIRE(U(FtpGetCurrentDirectoryW));
    fcx x; if (!std_open(&x)) return;
    DWORD l = 50;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetCurrentDirectoryW)(x.hc, NULL, &l), ERROR_INSUFFICIENT_BUFFER);
    t_note("FtpGetCurrentDirectoryW NULL buffer -> length %lu", l);
    EXPECT_EQ(l, 4);
    fc_end(&x);
}

TEST(ftpc_pwd_w_null_length_is_87) {
    REQUIRE(U(FtpGetCurrentDirectoryW));
    fcx x; if (!std_open(&x)) return;
    WCHAR d[8];
    SetLastError(0);
    EXPECT_FAIL(!U(FtpGetCurrentDirectoryW)(x.hc, d, NULL), ERROR_INVALID_PARAMETER);
    fc_end(&x);
}

/* ------------------------------------------------------------------ FtpSetCurrentDirectory */
TEST(ftpc_cwd_wire_verbatim) {
    REQUIRE(U(FtpSetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    static const char *args[] = { "pub", "/pub/", "..", "/", "dir two", "/dir two/", "." };
    for (int i = 0; i < NF(args); i++) {
        int before = fc_ncmd(&x);
        CHECKF(U(FtpSetCurrentDirectoryA)(x.hc, args[i]), "CWD %s err=%lu", args[i], GetLastError());
        char want[64]; snprintf(want, sizeof want, "CWD %s", args[i]);
        CHECKF(!strcmp(fc_cmd(&x, before), want), "sent [%s] want [%s]", fc_cmd(&x, before), want);
        EXPECT_EQ(fc_ncmd(&x), before + 1);
    }
    fc_end(&x);
}

TEST(ftpc_cwd_missing_dir_extended_error) {
    REQUIRE(U(FtpSetCurrentDirectoryA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(x.hc, "nosuchdir"), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 nosuchdir: No such file or directory.") != NULL, "resp=[%s]", r);
    /* the session is still usable */
    char d[32]; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/");
    fc_end(&x);
}

TEST(ftpc_cwd_null_or_empty_is_87) {
    REQUIRE(U(FtpSetCurrentDirectoryA)); REQUIRE(U(FtpSetCurrentDirectoryW));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(x.hc, ""), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryW)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryW)(x.hc, L""), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_count(&x, "CWD"), 0);
    fc_end(&x);
}

TEST(ftpc_cwd_w) {
    REQUIRE(U(FtpSetCurrentDirectoryW));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryW)(x.hc, L"dir two"));
    EXPECT_STR(fc_cmd(&x, 2), "CWD dir two");
    fc_end(&x);
}

/* reply class rules shared by CWD/MKD/RMD/DELE: only 2xx succeeds */
static const struct { const char *reply; int ok; } cls_tab[] = {
    { "200 fine", 1 }, { "250 done", 1 }, { "257 \"/x\" created", 1 }, { "299 odd but 2xx", 1 },
    { "150 preliminary", 0 }, { "350 pending", 0 }, { "421 closing", 0 }, { "450 busy", 0 },
    { "500 syntax", 0 }, { "502 not implemented", 0 }, { "550 no", 0 }, { "553 bad name", 0 },
};
typedef BOOL (WINAPI *one_arg_fn)(HINTERNET, LPCSTR);
static void class_table(const char *verb, one_arg_fn fn, const char *arg) {
    for (int i = 0; i < NF(cls_tab); i++) {
        srv_ftp_override ov[] = { { verb, cls_tab[i].reply, 0 } };
        srv_ftp_config c = { NULL, 0, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        SetLastError(0);
        BOOL ok = fn(x.hc, arg);
        DWORD e = GetLastError();
        CHECKF(!!ok == cls_tab[i].ok, "%s reply [%s]: ok=%d err=%lu", verb, cls_tab[i].reply, ok, e);
        if (!ok) CHECKF(e == ERROR_INTERNET_EXTENDED_ERROR, "%s [%s] err=%lu", verb, cls_tab[i].reply, e);
        if (!ok) { DWORD le; const char *r = fc_resp(&le); CHECKF(strstr(r, cls_tab[i].reply) != NULL, "%s resp [%s]", verb, r); }
        char want[64]; snprintf(want, sizeof want, "%s %s", verb, arg);
        CHECKF(!strcmp(fc_cmd(&x, 2), want), "%s sent [%s]", verb, fc_cmd(&x, 2));
        fc_end(&x);
    }
}
TEST(ftpc_cwd_reply_classes)   { REQUIRE(U(FtpSetCurrentDirectoryA)); class_table("CWD", U(FtpSetCurrentDirectoryA), "somewhere"); }
TEST(ftpc_mkd_reply_classes)   { REQUIRE(U(FtpCreateDirectoryA)); class_table("MKD", U(FtpCreateDirectoryA), "newdir"); }
TEST(ftpc_rmd_reply_classes)   { REQUIRE(U(FtpRemoveDirectoryA)); class_table("RMD", U(FtpRemoveDirectoryA), "olddir"); }
TEST(ftpc_dele_reply_classes)  { REQUIRE(U(FtpDeleteFileA)); class_table("DELE", U(FtpDeleteFileA), "file.txt"); }

/* ------------------------------------------------------------------ create / remove directory */
TEST(ftpc_mkdir_rmdir_roundtrip) {
    REQUIRE(U(FtpCreateDirectoryA)); REQUIRE(U(FtpRemoveDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCreateDirectoryA)(x.hc, "made"));
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "made"));
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, ".."));
    CHECK(U(FtpRemoveDirectoryA)(x.hc, "made"));
    SetLastError(0);
    EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(x.hc, "made"), ERROR_INTERNET_EXTENDED_ERROR);
    EXPECT_STR(fc_seq(&x, 2), "MKD made|CWD made|CWD ..|RMD made|CWD made");
    fc_end(&x);
}

TEST(ftpc_mkdir_existing_fails) {
    REQUIRE(U(FtpCreateDirectoryA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCreateDirectoryA)(x.hc, "pub"), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 pub: File exists.") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_rmdir_nonempty_fails) {
    REQUIRE(U(FtpRemoveDirectoryA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpRemoveDirectoryA)(x.hc, "pub"), ERROR_INTERNET_EXTENDED_ERROR);
    fc_end(&x);
}

TEST(ftpc_mkdir_rmdir_paths_verbatim) {
    REQUIRE(U(FtpCreateDirectoryA)); REQUIRE(U(FtpRemoveDirectoryA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCreateDirectoryA)(x.hc, "/pub/sub dir"));
    CHECK(U(FtpRemoveDirectoryA)(x.hc, "/pub/sub dir"));
    EXPECT_STR(fc_seq(&x, 2), "MKD /pub/sub dir|RMD /pub/sub dir");
    fc_end(&x);
}

TEST(ftpc_mkdir_rmdir_w) {
    REQUIRE(U(FtpCreateDirectoryW)); REQUIRE(U(FtpRemoveDirectoryW));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCreateDirectoryW)(x.hc, L"wdir"));
    CHECK(U(FtpRemoveDirectoryW)(x.hc, L"wdir"));
    EXPECT_STR(fc_seq(&x, 2), "MKD wdir|RMD wdir");
    fc_end(&x);
}

TEST(ftpc_mkdir_rmdir_null_or_empty_is_87) {
    REQUIRE(U(FtpCreateDirectoryA)); REQUIRE(U(FtpRemoveDirectoryA)); REQUIRE(U(FtpCreateDirectoryW)); REQUIRE(U(FtpRemoveDirectoryW));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryA)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryA)(x.hc, ""), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryA)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryA)(x.hc, ""), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryW)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryW)(x.hc, L""), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryW)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryW)(x.hc, L""), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 2);
    fc_end(&x);
}

/* ------------------------------------------------------------------ delete */
TEST(ftpc_delete_file) {
    REQUIRE(U(FtpDeleteFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(srv_ftp_file_data(x.s, "/hello.txt", NULL) != NULL);
    CHECK(U(FtpDeleteFileA)(x.hc, "hello.txt"));
    EXPECT_STR(fc_cmd(&x, 2), "DELE hello.txt");
    CHECK(srv_ftp_file_data(x.s, "/hello.txt", NULL) == NULL);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "250 DELE command successful.") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_delete_missing_extended_error) {
    REQUIRE(U(FtpDeleteFileA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpDeleteFileA)(x.hc, "ghost.txt"), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "550 ghost.txt: No such file.") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_delete_relative_to_cwd) {
    REQUIRE(U(FtpDeleteFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    CHECK(U(FtpDeleteFileA)(x.hc, "readme.txt"));
    CHECK(srv_ftp_file_data(x.s, "/pub/readme.txt", NULL) == NULL);
    CHECK(srv_ftp_file_data(x.s, "/hello.txt", NULL) != NULL);
    fc_end(&x);
}

TEST(ftpc_delete_w_and_validation) {
    REQUIRE(U(FtpDeleteFileW)); REQUIRE(U(FtpDeleteFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpDeleteFileW)(x.hc, L"dir two/in space.txt"));
    EXPECT_STR(fc_cmd(&x, 2), "DELE dir two/in space.txt");
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(x.hc, ""), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileW)(x.hc, NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileW)(x.hc, L""), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 3);
    fc_end(&x);
}

/* ------------------------------------------------------------------ rename */
TEST(ftpc_rename_file) {
    REQUIRE(U(FtpRenameFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpRenameFileA)(x.hc, "hello.txt", "renamed.txt"));
    EXPECT_STR(fc_seq(&x, 2), "RNFR hello.txt|RNTO renamed.txt");
    long n = 0; const char *d = srv_ftp_file_data(x.s, "/renamed.txt", &n);
    CHECK(d && n == 5 && !memcmp(d, "hello", 5));
    CHECK(srv_ftp_file_data(x.s, "/hello.txt", NULL) == NULL);
    fc_end(&x);
}

TEST(ftpc_rename_missing_source_no_rnto) {
    REQUIRE(U(FtpRenameFileA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "ghost", "x"), ERROR_INTERNET_EXTENDED_ERROR);
    Sleep(50);
    EXPECT_STR(fc_seq(&x, 2), "RNFR ghost");
    fc_end(&x);
}

TEST(ftpc_rename_rnfr_must_be_3xx) {
    REQUIRE(U(FtpRenameFileA));
    static const char *replies[] = { "250 RNFR accepted with 2xx", "200 ok", "150 hmm" };
    for (int i = 0; i < NF(replies); i++) {
        srv_ftp_override ov[] = { { "RNFR", replies[i], 0 } };
        srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
        fcx x; if (!fc_open(&x, &c)) return;
        SetLastError(0);
        BOOL ok = U(FtpRenameFileA)(x.hc, "hello.txt", "y");
        DWORD e = GetLastError();
        CHECKF(!ok && e == ERROR_INTERNET_EXTENDED_ERROR, "RNFR [%s]: ok=%d err=%lu", replies[i], ok, e);
        Sleep(50);
        CHECKF(fc_find(&x, "RNTO", 0) < 0, "RNTO sent after [%s]", replies[i]);
        fc_end(&x);
    }
}

TEST(ftpc_rename_rnto_failure) {
    REQUIRE(U(FtpRenameFileA));
    static const srv_ftp_override ov[] = { { "RNTO", "553 Rename not allowed.", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "hello.txt", "nope.txt"), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "553 Rename not allowed.") != NULL, "resp=[%s]", r);
    EXPECT_STR(fc_seq(&x, 2), "RNFR hello.txt|RNTO nope.txt");
    fc_end(&x);
}

TEST(ftpc_rename_rnto_class3_fails) {
    REQUIRE(U(FtpRenameFileA));
    static const srv_ftp_override ov[] = { { "RNTO", "350 still pending", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "hello.txt", "x"), ERROR_INTERNET_EXTENDED_ERROR);
    fc_end(&x);
}

TEST(ftpc_rename_target_exists) {
    REQUIRE(U(FtpRenameFileA));
    fcx x; if (!std_open(&x)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "hello.txt", "lf.txt"), ERROR_INTERNET_EXTENDED_ERROR);
    CHECK(srv_ftp_file_data(x.s, "/hello.txt", NULL) != NULL);
    fc_end(&x);
}

TEST(ftpc_rename_w_and_validation) {
    REQUIRE(U(FtpRenameFileW)); REQUIRE(U(FtpRenameFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpRenameFileW)(x.hc, L"lf.txt", L"new name.txt"));
    EXPECT_STR(fc_seq(&x, 2), "RNFR lf.txt|RNTO new name.txt");
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, NULL, "b"), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "a", NULL), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "", "b"), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(x.hc, "a", ""), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileW)(x.hc, NULL, L"b"), ERROR_INVALID_PARAMETER);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileW)(x.hc, L"a", NULL), ERROR_INVALID_PARAMETER);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), 4);
    fc_end(&x);
}

TEST(ftpc_rename_directory) {
    REQUIRE(U(FtpRenameFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpCreateDirectoryA)(x.hc, "d1"));
    CHECK(U(FtpRenameFileA)(x.hc, "d1", "d2"));
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "d2"));
    fc_end(&x);
}

/* ------------------------------------------------------------------ handle validation (no network) */
TEST(ftpc_dir_ops_invalid_handle_6) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    HINTERNET bad = NULL;
    char d[8]; DWORD l = sizeof d;
    SetLastError(0); EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(bad, d, &l), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(bad, "x"), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryA)(bad, "x"), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryA)(bad, "x"), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(bad, "x"), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(bad, "x", "y"), ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(bad, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL), ERROR_INVALID_HANDLE);
    WIN32_FIND_DATAA fd;
    SetLastError(0); EXPECT_FAIL(U(FtpFindFirstFileA)(bad, NULL, &fd, 0, 0) == NULL, ERROR_INVALID_HANDLE);
    SetLastError(0); EXPECT_FAIL(U(FtpOpenFileA)(bad, "x", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0) == NULL, ERROR_INVALID_HANDLE);
}

TEST(ftpc_dir_ops_on_session_handle_12018) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    HINTERNET hi = t_inet_open("ftpc");
    if (!hi) { t_skip("InternetOpen failed"); return; }
    char d[8]; DWORD l = sizeof d;
    SetLastError(0); EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(hi, d, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(hi, "x"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryA)(hi, "x"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryA)(hi, "x"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(hi, "x"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(hi, "x", "y"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(hi, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    WIN32_FIND_DATAA fd;
    SetLastError(0); EXPECT_FAIL(U(FtpFindFirstFileA)(hi, NULL, &fd, 0, 0) == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(U(FtpOpenFileA)(hi, "x", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0) == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    U(InternetCloseHandle)(hi);
}

TEST(ftpc_dir_ops_on_http_connect_handle_12018) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    HINTERNET hi = t_inet_open("ftpc");
    if (!hi) { t_skip("InternetOpen failed"); return; }
    /* HTTP connect handles do no network I/O at creation */
    HINTERNET hh = U(InternetConnectA)(hi, "127.0.0.1", 9, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hh != NULL);
    char d[8]; DWORD l = sizeof d;
    SetLastError(0); EXPECT_FAIL(!U(FtpGetCurrentDirectoryA)(hh, d, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(hh, "x"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(hh, "x"), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(!U(FtpCommandA)(hh, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    WIN32_FIND_DATAA fd;
    SetLastError(0); EXPECT_FAIL(U(FtpFindFirstFileA)(hh, NULL, &fd, 0, 0) == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); EXPECT_FAIL(U(FtpOpenFileA)(hh, "x", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0) == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    if (hh) U(InternetCloseHandle)(hh);
    U(InternetCloseHandle)(hi);
}
