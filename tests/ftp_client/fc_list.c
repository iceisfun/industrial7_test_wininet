/* fc_list.c - FtpFindFirstFile / InternetFindNextFile: LIST command on the wire, UNIX ls -l and DOS/IIS listing
 * parsing into WIN32_FIND_DATA (attributes, sizes incl. 64-bit, dates, unix permission bits in dwReserved0,
 * symlinks, spaces), wildcard filtering, empty / failed listings, find handle rules.
 * Decomp: wFtpFindFirstFile, InternalFtpFindFirstFileA, ParseDirList, DetermineDirectoryFormat, ParseUnixDirectory,
 * ReadUnixPermissions, ExtractFileSize, ExtractUnixDate, _ExtractFilename, ParseNtDirectory, ExtractNtDate,
 * IsNtDateFormat, wFtpFindNextFile. */
#include "ftp.h"
#include <stdlib.h>

static int std_open(fcx *x) { srv_ftp_config c = FC_STD_CFG; return fc_open(x, &c); }

static void check_st(const FILETIME *ft, int y, int mo, int d, int h, int mi, const char *what) {
    SYSTEMTIME st; fc_ft_to_st(ft, &st);
    CHECKF(st.wYear == y && st.wMonth == mo && st.wDay == d && st.wHour == h && st.wMinute == mi && st.wSecond == 0,
           "%s: got %04u-%02u-%02u %02u:%02u:%02u want %04d-%02d-%02d %02d:%02d:00", what,
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, y, mo, d, h, mi);
}
static int ft_zero(const FILETIME *f) { return f->dwLowDateTime == 0 && f->dwHighDateTime == 0; }

/* ------------------------------------------------------------------ wire */
TEST(ftpc_find_wire_null_pattern) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_seq(&x, 2), "TYPE A|PASV|LIST");
    if (hf) U(InternetCloseHandle)(hf);
    fc_end(&x);
}

static const struct { const char *pattern; const char *list_cmd; } find_wire_tab[] = {
    { "", "LIST" },
    { "*", "LIST" },
    { "*.txt", "LIST" },
    { "h?llo.txt", "LIST" },
    { "hello.txt", "LIST hello.txt" },
    { "pub", "LIST pub" },
    { "pub/", "LIST pub/" },
    { "pub/*.txt", "LIST pub/" },
    { "/pub/read*", "LIST /pub/" },
    { "/pub/readme.txt", "LIST /pub/readme.txt" },
    { "dir two", "LIST dir two" },
    { "pub\\*.bin", "LIST pub\\" },
};
TEST(ftpc_find_wire_list_argument_table) {
    REQUIRE(U(FtpFindFirstFileA));
    for (int i = 0; i < NF(find_wire_tab); i++) {
        fcx x; if (!std_open(&x)) return;
        WIN32_FIND_DATAA fd;
        HINTERNET hf = U(FtpFindFirstFileA)(x.hc, find_wire_tab[i].pattern, &fd, FC_NC, 0);
        DWORD e = hf ? 0 : GetLastError();
        int li = fc_find(&x, "LIST", 0), ni = fc_find(&x, "NLST", 0);
        CHECKF(li >= 0 && !strcmp(fc_cmd(&x, li), find_wire_tab[i].list_cmd), "pattern [%s]: sent [%s] want [%s] (err %lu)",
               find_wire_tab[i].pattern, li >= 0 ? fc_cmd(&x, li) : "(no LIST)", find_wire_tab[i].list_cmd, e);
        CHECK(ni < 0);
        if (hf) U(InternetCloseHandle)(hf);
        fc_end(&x);
    }
}

TEST(ftpc_find_root_entries_from_server_listing) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA v[32]; DWORD err;
    int n = fc_list(&x, NULL, v, 32, &err);
    EXPECT_EQ(err, ERROR_NO_MORE_FILES);
    t_note("root listing: %d entries", n);
    EXPECT_EQ(n, 6);   /* hello.txt pub crlf.txt lf.txt empty.txt "dir two" */
    const WIN32_FIND_DATAA *h = fc_by_name(v, n < 32 ? n : 32, "hello.txt");
    CHECK(h != NULL);
    if (h) {
        EXPECT_EQ(h->nFileSizeLow, 5); EXPECT_EQ(h->nFileSizeHigh, 0);
        EXPECT_EQ(h->dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
        EXPECT_EQ(h->dwReserved0, 0x644);
        check_st(&h->ftLastWriteTime, 2020, 1, 2, 0, 0, "hello.txt (server lists \"Jan 02  2020\")");
        CHECK(ft_zero(&h->ftCreationTime)); CHECK(ft_zero(&h->ftLastAccessTime));
        EXPECT_EQ(h->cAlternateFileName[0], 0);
    }
    const WIN32_FIND_DATAA *p = fc_by_name(v, n < 32 ? n : 32, "pub");
    CHECK(p != NULL);
    if (p) { EXPECT_EQ(p->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY); EXPECT_EQ(p->dwReserved0, 0x755); EXPECT_EQ(p->nFileSizeLow, 0); }
    CHECK(fc_by_name(v, n < 32 ? n : 32, "dir two") != NULL);
    const WIN32_FIND_DATAA *e0 = fc_by_name(v, n < 32 ? n : 32, "empty.txt");
    CHECK(e0 && e0->nFileSizeLow == 0 && e0->dwFileAttributes == FILE_ATTRIBUTE_NORMAL);
    fc_end(&x);
}

TEST(ftpc_find_subdir_via_cwd) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    WIN32_FIND_DATAA v[8]; DWORD err;
    int n = fc_list(&x, NULL, v, 8, &err);
    EXPECT_EQ(n, 2);
    CHECK(fc_by_name(v, n, "readme.txt") && fc_by_name(v, n, "data.bin"));
    const WIN32_FIND_DATAA *d = fc_by_name(v, n, "data.bin");
    if (d) EXPECT_EQ(d->nFileSizeLow, 100000);
    const WIN32_FIND_DATAA *r = fc_by_name(v, n, "readme.txt");
    if (r) check_st(&r->ftLastWriteTime, 2019, 6, 15, 0, 0, "readme.txt");
    fc_end(&x);
}

TEST(ftpc_find_wildcard_filters_client_side) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA v[16]; DWORD err;
    int n = fc_list(&x, "*.txt", v, 16, &err);
    EXPECT_EQ(n, 4);   /* hello crlf lf empty */
    for (int i = 0; i < n && i < 16; i++) { size_t l = strlen(v[i].cFileName); CHECKF(l > 4 && !strcmp(v[i].cFileName + l - 4, ".txt"), "entry %s", v[i].cFileName); }
    CHECK(fc_by_name(v, n, "pub") == NULL);
    fc_end(&x);
}

static const struct { const char *pattern; int count; const char *one; } wild_tab[] = {
    { "*", 6, "pub" }, { "*.*", 4, "hello.txt" }, { "h*", 1, "hello.txt" }, { "?f.txt", 1, "lf.txt" },
    { "*.TXT", 4, "lf.txt" }, { "HEL*.TXT", 1, "hello.txt" }, { "*two", 1, "dir two" }, { "e*y.txt", 1, "empty.txt" },
};
TEST(ftpc_find_wildcard_table) {
    REQUIRE(U(FtpFindFirstFileA));
    for (int i = 0; i < NF(wild_tab); i++) {
        srv_ftp_config c = FC_STD_CFG;
        fcx x; if (!fc_open(&x, &c)) return;
        WIN32_FIND_DATAA v[16]; DWORD err;
        int n = fc_list(&x, wild_tab[i].pattern, v, 16, &err);
        CHECKF(n == wild_tab[i].count, "pattern %s: %d entries (err %lu) want %d", wild_tab[i].pattern, n, err, wild_tab[i].count);
        if (n > 0) CHECKF(fc_by_name(v, n, wild_tab[i].one) != NULL, "pattern %s lacks %s", wild_tab[i].pattern, wild_tab[i].one);
        fc_end(&x);
    }
}

TEST(ftpc_find_wildcard_no_match_is_no_more_files) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "*.zip", &fd, FC_NC, 0);
    EXPECT_FAIL(hf == NULL, ERROR_NO_MORE_FILES);
    if (hf) U(InternetCloseHandle)(hf);
    fc_end(&x);
}

TEST(ftpc_find_single_file_by_name) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA v[4]; DWORD err;
    int n = fc_list(&x, "/pub/readme.txt", v, 4, &err);
    EXPECT_EQ(n, 1);
    if (n >= 1) { EXPECT_STR(v[0].cFileName, "readme.txt"); EXPECT_EQ(v[0].nFileSizeLow, 8); }
    fc_end(&x);
}

TEST(ftpc_find_missing_name_empty_listing) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "ghost.txt", &fd, FC_NC, 0);
    EXPECT_FAIL(hf == NULL, ERROR_NO_MORE_FILES);   /* the server sends an empty LIST */
    fc_end(&x);
}

/* ------------------------------------------------------------------ find handle rules */
TEST(ftpc_find_handle_type_and_next_exhaustion) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(InternetFindNextFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "hello.txt", &fd, FC_NC, 0);
    CHECK(hf != NULL);
    if (hf) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FIND);
        HINTERNET p = NULL; l = sizeof p;
        CHECK(U(InternetQueryOptionA)(hf, INTERNET_OPTION_PARENT_HANDLE, &p, &l));
        EXPECT_EQ(p, x.hc);
        for (int i = 0; i < 3; i++) { SetLastError(0); EXPECT_FAIL(!U(InternetFindNextFileA)(hf, &fd), ERROR_NO_MORE_FILES); }
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_find_null_finddata_keeps_first_entry) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(InternetFindNextFileA));
    fcx x; if (!std_open(&x)) return;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "hello.txt", NULL, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        WIN32_FIND_DATAA fd; memset(&fd, 0, sizeof fd);
        CHECK(U(InternetFindNextFileA)(hf, &fd));
        EXPECT_STR(fd.cFileName, "hello.txt");
        SetLastError(0); EXPECT_FAIL(!U(InternetFindNextFileA)(hf, &fd), ERROR_NO_MORE_FILES);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

TEST(ftpc_find_second_find_while_open_in_progress) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET h1 = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECK(h1 != NULL);
    int before = fc_ncmd(&x);
    SetLastError(0);
    HINTERNET h2 = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    EXPECT_FAIL(h2 == NULL, ERROR_FTP_TRANSFER_IN_PROGRESS);
    Sleep(50);
    EXPECT_EQ(fc_ncmd(&x), before);
    if (h2) U(InternetCloseHandle)(h2);
    if (h1) U(InternetCloseHandle)(h1);
    HINTERNET h3 = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(h3 != NULL, "after close err=%lu", GetLastError());
    if (h3) U(InternetCloseHandle)(h3);
    fc_end(&x);
}

TEST(ftpc_find_other_commands_allowed_while_find_open) {
    REQUIRE(U(FtpFindFirstFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    HINTERNET h1 = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECK(h1 != NULL);
    char d[32]; DWORD l = sizeof d;
    BOOL ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
    CHECKF(ok, "PWD with open find handle: err=%lu", GetLastError());
    if (h1) U(InternetCloseHandle)(h1);
    fc_end(&x);
}

TEST(ftpc_find_next_on_wrong_handles) {
    REQUIRE(U(InternetFindNextFileA));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    BOOL ok = U(InternetFindNextFileA)(x.hc, &fd);
    DWORD e = GetLastError();
    CHECK(!ok);
    t_note("InternetFindNextFile(connect handle) -> %lu", e);
    EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0);
    EXPECT_FAIL(!U(InternetFindNextFileA)(NULL, &fd), ERROR_INVALID_HANDLE);
    fc_end(&x);
}

TEST(ftpc_find_w_variant) {
    REQUIRE(U(FtpFindFirstFileW)); REQUIRE(U(InternetFindNextFileW));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAW fd; memset(&fd, 0, sizeof fd);
    HINTERNET hf = U(FtpFindFirstFileW)(x.hc, L"dir two/*", &fd, FC_NC, 0);
    CHECKF(hf != NULL, "err=%lu", GetLastError());
    if (hf) {
        EXPECT_WSTR(fd.cFileName, L"in space.txt");
        EXPECT_EQ(fd.nFileSizeLow, 6);
        EXPECT_EQ(fd.dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
        EXPECT_EQ(fd.dwReserved0, 0x644);
        SetLastError(0); EXPECT_FAIL(!U(InternetFindNextFileW)(hf, &fd), ERROR_NO_MORE_FILES);
        U(InternetCloseHandle)(hf);
    }
    EXPECT_STR(fc_cmd(&x, fc_find(&x, "LIST", 0)), "LIST dir two/");
    fc_end(&x);
}

TEST(ftpc_find_w_next_via_a_handle_mix) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(InternetFindNextFileW));
    fcx x; if (!std_open(&x)) return;
    WIN32_FIND_DATAA fa;
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, "*.txt", &fa, FC_NC, 0);
    CHECK(hf != NULL);
    if (hf) {
        WIN32_FIND_DATAW fw; memset(&fw, 0, sizeof fw);
        BOOL ok = U(InternetFindNextFileW)(hf, &fw);
        t_note("InternetFindNextFileW on an A find handle: ok=%d err=%lu name0=0x%04x", ok, ok ? 0 : GetLastError(), fw.cFileName[0]);
        U(InternetCloseHandle)(hf);
    }
    fc_end(&x);
}

/* ------------------------------------------------------------------ server-side failures */
TEST(ftpc_find_list_550_immediate_is_extended_error) {
    REQUIRE(U(FtpFindFirstFileA));
    static const srv_ftp_override ov[] = { { "LIST", "550 No files found.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    DWORD e = GetLastError();
    CHECK(hf == NULL);
    t_note("LIST answered 550 without data: err=%lu", e);
    EXPECT_EQ(e, ERROR_INTERNET_EXTENDED_ERROR);
    DWORD le; const char *r = fc_resp(&le);
    CHECKF(strstr(r, "550 No files found.") != NULL, "resp=[%s]", r);
    /* a find can be retried afterwards */
    if (hf) U(InternetCloseHandle)(hf);
    fc_end(&x);
}

TEST(ftpc_find_list_450_is_extended_error) {
    REQUIRE(U(FtpFindFirstFileA));
    static const srv_ftp_override ov[] = { { "LIST", "450 Directory busy.", 1 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    EXPECT_FAIL(hf == NULL, ERROR_INTERNET_EXTENDED_ERROR);
    HINTERNET h2 = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    CHECKF(h2 != NULL, "retry err=%lu", GetLastError());
    if (h2) U(InternetCloseHandle)(h2);
    fc_end(&x);
}

TEST(ftpc_find_type_a_rejected) {
    REQUIRE(U(FtpFindFirstFileA));
    static const srv_ftp_override ov[] = { { "TYPE", "504 Type not supported.", 0 } };
    srv_ftp_config c = { fc_std_files, fc_std_nfiles, ov, 1 };
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    EXPECT_FAIL(hf == NULL, ERROR_INTERNET_EXTENDED_ERROR);
    Sleep(50);
    EXPECT_STR(fc_seq(&x, 2), "TYPE A");
    fc_end(&x);
}

TEST(ftpc_find_empty_listing_no_more_files) {
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("", NULL, v, 4, &n, &err)) return;
    EXPECT_EQ(n, -1);
    EXPECT_EQ(err, ERROR_NO_MORE_FILES);
}

TEST(ftpc_find_whitespace_only_listing) {
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("\r\n\r\n  \r\n", NULL, v, 4, &n, &err)) return;
    t_note("whitespace-only listing: n=%d err=%lu", n, err);
    CHECK(n == -1);
}

TEST(ftpc_find_unknown_format_extended_error) {
    REQUIRE(U(FtpFindFirstFileA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.list_override = "this is not a directory listing\r\nnor is this\r\n";
    fcx x; if (!fc_open(&x, &c)) return;
    WIN32_FIND_DATAA fd;
    SetLastError(0);
    HINTERNET hf = U(FtpFindFirstFileA)(x.hc, NULL, &fd, FC_NC, 0);
    DWORD e = GetLastError();
    CHECK(hf == NULL);
    EXPECT_EQ(e, ERROR_INTERNET_EXTENDED_ERROR);
    DWORD le; const char *r = fc_resp(&le);
    t_note("unknown listing format: err=%lu last response=[%s]", e, r);
    CHECKF(strstr(r, "this is not a directory listing") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

TEST(ftpc_find_name_not_found_text) {
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("ghost.txt: not found\r\n", "ghost.txt", v, 4, &n, &err)) return;
    EXPECT_EQ(n, -1);
    EXPECT_EQ(err, ERROR_NO_MORE_FILES);
    if (!fc_list_raw("GHOST.TXT: The system cannot find the file specified.\r\n", "ghost.txt", v, 4, &n, &err)) return;
    EXPECT_EQ(n, -1);
    EXPECT_EQ(err, ERROR_NO_MORE_FILES);
}

/* ------------------------------------------------------------------ UNIX listing parser */
static const char unix_listing[] =
    "total 42\r\n"
    "-rw-r--r--   1 owner    group        1234 Jan 15  2019 file1.txt\r\n"
    "drwxr-xr-x   2 owner    group        4096 Mar  3  2018 subdir\r\n"
    "lrwxrwxrwx   1 owner    group          11 Dec 31  2020 link -> target.txt\r\n"
    "-rw-r--r--   1 owner    group           5 Feb 29  2020 name with spaces.txt\r\n"
    "-rwxr-x---   1 owner    group  5000000000 Jul  4  2021 big.iso\r\n"
    "-rw-------   1 owner    group           0 Oct 10  1999 empty\r\n"
    "-rw-r--r--   1 owner              77 Nov  5  2018 nogroup.txt\r\n"
    "-rw-r--r--   1 owner    group           3 Jan  1  2001 trail  \r\n"
    "-rw-r--r--   1 owner    group           3 JAN  2  2001 upper.txt\r\n"
    "-r--r--r--   1 owner    group          10 Sep 30  2010 readonly.txt\n"
    "drwx------   2 owner    group         512 Aug  8  2008 private dir\n"
    "-rw-rw-rw-   1 owner    group  18446744073709551615 Jan  1  2001 max64\r\n"
    "crw-rw-rw-   1 root     root       1,   3 Jan  1  2001 nulldev\r\n";

TEST(ftpc_unix_listing_parse) {
    WIN32_FIND_DATAA v[32]; int n; DWORD err;
    if (!fc_list_raw(unix_listing, NULL, v, 32, &n, &err)) return;
    EXPECT_EQ(err, ERROR_NO_MORE_FILES);
    for (int i = 0; i < n && i < 32; i++) t_note("unix[%d] name=[%s] attr=0x%lx size=%lu:%lu perm=0x%lx", i, v[i].cFileName, v[i].dwFileAttributes, v[i].nFileSizeHigh, v[i].nFileSizeLow, v[i].dwReserved0);
    if (n < 1) return;
    int m = n < 32 ? n : 32;
    const WIN32_FIND_DATAA *e;
    e = fc_by_name(v, m, "file1.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_NORMAL); EXPECT_EQ(e->nFileSizeLow, 1234); EXPECT_EQ(e->nFileSizeHigh, 0); EXPECT_EQ(e->dwReserved0, 0x644); check_st(&e->ftLastWriteTime, 2019, 1, 15, 0, 0, "file1.txt"); CHECK(ft_zero(&e->ftCreationTime) && ft_zero(&e->ftLastAccessTime)); }
    e = fc_by_name(v, m, "subdir"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY); EXPECT_EQ(e->nFileSizeLow, 4096); EXPECT_EQ(e->dwReserved0, 0x755); check_st(&e->ftLastWriteTime, 2018, 3, 3, 0, 0, "subdir"); }
    e = fc_by_name(v, m, "link"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, 0); EXPECT_EQ(e->nFileSizeLow, 11); EXPECT_EQ(e->dwReserved0, 0x777); check_st(&e->ftLastWriteTime, 2020, 12, 31, 0, 0, "link"); }
    CHECK(fc_by_name(v, m, "link -> target.txt") == NULL);
    e = fc_by_name(v, m, "name with spaces.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeLow, 5); check_st(&e->ftLastWriteTime, 2020, 2, 29, 0, 0, "leap day"); }
    e = fc_by_name(v, m, "big.iso"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeHigh, 1); EXPECT_EQ(e->nFileSizeLow, 705032704); EXPECT_EQ(e->dwReserved0, 0x750); }
    e = fc_by_name(v, m, "empty"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeLow, 0); EXPECT_EQ(e->dwReserved0, 0x600); check_st(&e->ftLastWriteTime, 1999, 10, 10, 0, 0, "1999"); }
    e = fc_by_name(v, m, "nogroup.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeLow, 77); check_st(&e->ftLastWriteTime, 2018, 11, 5, 0, 0, "nogroup"); }
    e = fc_by_name(v, m, "trail  "); CHECKF(e != NULL, "trailing spaces kept in the name");
    e = fc_by_name(v, m, "upper.txt"); CHECK(e);
    if (e) check_st(&e->ftLastWriteTime, 2001, 1, 2, 0, 0, "upper-case month");
    e = fc_by_name(v, m, "readonly.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_NORMAL); EXPECT_EQ(e->dwReserved0, 0x444); }
    e = fc_by_name(v, m, "private dir"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY); EXPECT_EQ(e->dwReserved0, 0x700); }
    e = fc_by_name(v, m, "max64"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeHigh, 0xffffffff); EXPECT_EQ(e->nFileSizeLow, 0xffffffff); EXPECT_EQ(e->dwReserved0, 0x666); }
    CHECK(fc_by_name(v, m, "total") == NULL);
}

TEST(ftpc_unix_listing_order_preserved) {
    char buf[8192]; size_t o = 0;
    for (int i = 0; i < 60; i++) o += snprintf(buf + o, sizeof buf - o, "-rw-r--r--   1 o g %d Jan  1  2001 f%03d\r\n", i, i);
    WIN32_FIND_DATAA *v = calloc(80, sizeof *v); int n; DWORD err;
    if (!fc_list_raw(buf, NULL, v, 80, &n, &err)) { free(v); return; }
    EXPECT_EQ(n, 60);
    for (int i = 0; i < n && i < 60; i++) {
        char want[16]; snprintf(want, sizeof want, "f%03d", i);
        CHECKF(!strcmp(v[i].cFileName, want) && v[i].nFileSizeLow == (DWORD)i, "entry %d = %s/%lu", i, v[i].cFileName, v[i].nFileSizeLow);
    }
    free(v);
}

TEST(ftpc_unix_listing_lf_only_and_blank_lines) {
    WIN32_FIND_DATAA v[8]; int n; DWORD err;
    if (!fc_list_raw("-rw-r--r-- 1 o g 1 Jan  1  2001 a\n\n\n-rw-r--r-- 1 o g 2 Jan  1  2001 b\n", NULL, v, 8, &n, &err)) return;
    EXPECT_EQ(n, 2);
    if (n == 2) { EXPECT_STR(v[0].cFileName, "a"); EXPECT_STR(v[1].cFileName, "b"); EXPECT_EQ(v[1].nFileSizeLow, 2); }
}

TEST(ftpc_unix_listing_no_trailing_newline) {
    WIN32_FIND_DATAA v[8]; int n; DWORD err;
    if (!fc_list_raw("-rw-r--r-- 1 o g 9 Jan  1  2001 last", NULL, v, 8, &n, &err)) return;
    EXPECT_EQ(n, 1);
    if (n == 1) { EXPECT_STR(v[0].cFileName, "last"); EXPECT_EQ(v[0].nFileSizeLow, 9); }
}

TEST(ftpc_unix_listing_wildcard_filter) {
    WIN32_FIND_DATAA v[32]; int n; DWORD err;
    if (!fc_list_raw(unix_listing, "*.txt", v, 32, &n, &err)) return;
    for (int i = 0; i < n && i < 32; i++) t_note("filtered: %s", v[i].cFileName);
    EXPECT_EQ(n, 5);   /* file1 "name with spaces" nogroup upper readonly */
    CHECK(fc_by_name(v, n < 32 ? n : 32, "big.iso") == NULL);
}

TEST(ftpc_unix_listing_dot_entries) {
    WIN32_FIND_DATAA v[8]; int n; DWORD err;
    if (!fc_list_raw("drwxr-xr-x 2 o g 512 Jan  1  2001 .\r\ndrwxr-xr-x 9 o g 512 Jan  1  2001 ..\r\n-rw-r--r-- 1 o g 1 Jan  1  2001 real\r\n",
                     NULL, v, 8, &n, &err)) return;
    t_note("dot entries: n=%d first=[%s]", n, n > 0 ? v[0].cFileName : "");
    CHECK(n >= 1 && fc_by_name(v, n < 8 ? n : 8, "real") != NULL);
}

TEST(ftpc_unix_listing_long_name_truncated) {
    char name[400]; memset(name, 'n', 300); name[300] = 0;
    char buf[600]; snprintf(buf, sizeof buf, "-rw-r--r-- 1 o g 1 Jan  1  2001 %s\r\n", name);
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw(buf, NULL, v, 4, &n, &err)) return;
    EXPECT_EQ(n, 1);
    if (n == 1) {
        size_t l = strnlen(v[0].cFileName, MAX_PATH);
        t_note("300-char name stored as %zu chars", l);
        EXPECT_EQ(l, 259);
    }
}

/* time-of-day form: the year is the current year unless that is more than 5 days in the future */
static void expect_hhmm_year(const WIN32_FIND_DATAA *e, int mo, int d, int h, int mi) {
    SYSTEMTIME now; GetSystemTime(&now);
    FILETIME fnow; SystemTimeToFileTime(&now, &fnow);
    ULONGLONG lim = ((ULONGLONG)fnow.dwHighDateTime << 32 | fnow.dwLowDateTime) + 5ULL * 24 * 3600 * 10000000ULL;
    FILETIME flim = { (DWORD)lim, (DWORD)(lim >> 32) }; SYSTEMTIME slim; FileTimeToSystemTime(&flim, &slim);
    SYSTEMTIME cand = { slim.wYear, (WORD)mo, 0, (WORD)d, (WORD)h, (WORD)mi, 0, 0 };
    FILETIME fc; SystemTimeToFileTime(&cand, &fc);
    ULONGLONG c = (ULONGLONG)fc.dwHighDateTime << 32 | fc.dwLowDateTime;
    int y = c > lim ? slim.wYear - 1 : slim.wYear;
    check_st(&e->ftLastWriteTime, y, mo, d, h, mi, e->cFileName);
}
TEST(ftpc_unix_listing_time_of_day_year_inference) {
    static const char *mon[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    SYSTEMTIME now; GetSystemTime(&now); FILETIME f; SystemTimeToFileTime(&now, &f);
    ULONGLONG t = (ULONGLONG)f.dwHighDateTime << 32 | f.dwLowDateTime, day = 24ULL * 3600 * 10000000ULL;
    SYSTEMTIME past, fut; FILETIME fp = { (DWORD)(t - 60 * day), (DWORD)((t - 60 * day) >> 32) }, ff = { (DWORD)(t + 60 * day), (DWORD)((t + 60 * day) >> 32) };
    FileTimeToSystemTime(&fp, &past); FileTimeToSystemTime(&ff, &fut);
    char buf[512];
    snprintf(buf, sizeof buf, "-rw-r--r-- 1 o g 1 %s %2u 13:45 past\r\n-rw-r--r-- 1 o g 1 %s %2u 07:05 future\r\n-rw-r--r-- 1 o g 1 %s %2u 00:00 midnight\r\n",
             mon[past.wMonth - 1], past.wDay, mon[fut.wMonth - 1], fut.wDay, mon[past.wMonth - 1], past.wDay);
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw(buf, NULL, v, 4, &n, &err)) return;
    EXPECT_EQ(n, 3);
    if (n == 3) {
        expect_hhmm_year(&v[0], past.wMonth, past.wDay, 13, 45);
        expect_hhmm_year(&v[1], fut.wMonth, fut.wDay, 7, 5);
        expect_hhmm_year(&v[2], past.wMonth, past.wDay, 0, 0);
        SYSTEMTIME s; fc_ft_to_st(&v[1].ftLastWriteTime, &s);
        t_note("future-dated %s %u -> year %u (now %u)", mon[fut.wMonth - 1], fut.wDay, s.wYear, now.wYear);
    }
}

TEST(ftpc_unix_listing_bad_month_default_time) {
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("-rw-r--r-- 1 o g 4 Foo  1  2001 badmonth\r\n-rw-r--r-- 1 o g 4 Jan 32  2001 badday\r\n", NULL, v, 4, &n, &err)) return;
    t_note("bad dates: n=%d", n);
    for (int i = 0; i < n && i < 4; i++) {
        SYSTEMTIME s; fc_ft_to_st(&v[i].ftLastWriteTime, &s);
        t_note("  [%s] size=%lu time=%04u-%02u-%02u %02u:%02u", v[i].cFileName, v[i].nFileSizeLow, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute);
    }
    CHECK(n >= 1);
}

static const struct { const char *perm; DWORD attr; DWORD bits; } perm_tab[] = {
    { "-rwxrwxrwx", 0x80, 0x777 }, { "----------", 0x80, 0x000 }, { "drwxr-xr-x", 0x10, 0x755 }, { "-r-x------", 0x80, 0x500 },
    { "--w--w--w-", 0x80, 0x222 }, { "---x--x--x", 0x80, 0x111 }, { "Drwxr-xr-x", 0x10, 0x755 }, { "lrwxrwxrwx", 0, 0x777 },
    { "prw-r--r--", 0, 0x644 }, { "srwxrwxrwx", 0, 0x777 }, { "-rwsr-xr-x", 0x80, 0x655 }, { "-rwxr-sr-t", 0x80, 0x744 },
};
TEST(ftpc_unix_permission_bits_table) {
    char buf[2048]; size_t o = 0;
    for (int i = 0; i < NF(perm_tab); i++) o += snprintf(buf + o, sizeof buf - o, "%s 1 o g %d Jan  1  2001 p%02d\r\n", perm_tab[i].perm, i, i);
    WIN32_FIND_DATAA v[16]; int n; DWORD err;
    if (!fc_list_raw(buf, NULL, v, 16, &n, &err)) return;
    EXPECT_EQ(n, NF(perm_tab));
    for (int i = 0; i < NF(perm_tab); i++) {
        char nm[8]; snprintf(nm, sizeof nm, "p%02d", i);
        const WIN32_FIND_DATAA *e = fc_by_name(v, n < 16 ? n : 16, nm);
        CHECKF(e != NULL, "%s missing", perm_tab[i].perm);
        if (!e) continue;
        CHECKF(e->dwFileAttributes == perm_tab[i].attr, "%s attr 0x%lx want 0x%lx", perm_tab[i].perm, e->dwFileAttributes, perm_tab[i].attr);
        CHECKF(e->dwReserved0 == perm_tab[i].bits, "%s bits 0x%lx want 0x%lx", perm_tab[i].perm, e->dwReserved0, perm_tab[i].bits);
        CHECKF(e->nFileSizeLow == (DWORD)i, "%s size %lu", perm_tab[i].perm, e->nFileSizeLow);
    }
}

/* ------------------------------------------------------------------ DOS / IIS listing parser */
static const char dos_listing[] =
    "01-15-19  10:30AM       <DIR>          My Dir\r\n"
    "12-31-99  11:59PM                 1234 old.txt\r\n"
    "02-29-2020  12:00AM                  0 leap.txt\r\n"
    "07-04-21  12:15PM           5000000000 big.bin\r\n"
    "03-05-80  01:02AM                   42 eighty.txt\r\n"
    "03-05-79  01:02PM                   43 seventynine.txt\r\n"
    "11-11-11  12:00PM                   10 a b c.txt\r\n"
    "06-30-05  09:09                      7 no ampm.txt\r\n"
    "10-01-15  08:00am       <dir>          lower dir\r\n";

TEST(ftpc_dos_listing_parse) {
    WIN32_FIND_DATAA v[16]; int n; DWORD err;
    if (!fc_list_raw(dos_listing, NULL, v, 16, &n, &err)) return;
    EXPECT_EQ(err, ERROR_NO_MORE_FILES);
    EXPECT_EQ(n, 9);
    for (int i = 0; i < n && i < 16; i++) {
        SYSTEMTIME s; fc_ft_to_st(&v[i].ftLastWriteTime, &s);
        t_note("dos[%d] name=[%s] attr=0x%lx size=%lu:%lu res0=0x%lx %04u-%02u-%02u %02u:%02u", i, v[i].cFileName, v[i].dwFileAttributes, v[i].nFileSizeHigh, v[i].nFileSizeLow, v[i].dwReserved0, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute);
    }
    int m = n < 16 ? (n < 0 ? 0 : n) : 16;
    const WIN32_FIND_DATAA *e;
    e = fc_by_name(v, m, "My Dir"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY); EXPECT_EQ(e->nFileSizeLow, 0); EXPECT_EQ(e->dwReserved0, 0); check_st(&e->ftLastWriteTime, 2019, 1, 15, 10, 30, "My Dir"); CHECK(ft_zero(&e->ftCreationTime)); }
    e = fc_by_name(v, m, "old.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_NORMAL); EXPECT_EQ(e->nFileSizeLow, 1234); check_st(&e->ftLastWriteTime, 1999, 12, 31, 23, 59, "11:59PM"); }
    e = fc_by_name(v, m, "leap.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeLow, 0); EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_NORMAL); check_st(&e->ftLastWriteTime, 2020, 2, 29, 0, 0, "12:00AM 4-digit year"); }
    e = fc_by_name(v, m, "big.bin"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeHigh, 1); EXPECT_EQ(e->nFileSizeLow, 705032704); check_st(&e->ftLastWriteTime, 2021, 7, 4, 12, 15, "12:15PM"); }
    e = fc_by_name(v, m, "eighty.txt"); CHECK(e);
    if (e) check_st(&e->ftLastWriteTime, 1980, 3, 5, 1, 2, "yy=80 -> 1980");
    e = fc_by_name(v, m, "seventynine.txt"); CHECK(e);
    if (e) check_st(&e->ftLastWriteTime, 2079, 3, 5, 13, 2, "yy=79 -> 2079");
    e = fc_by_name(v, m, "a b c.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeLow, 10); check_st(&e->ftLastWriteTime, 2011, 11, 11, 12, 0, "12:00PM"); }
    e = fc_by_name(v, m, "no ampm.txt"); CHECK(e);
    if (e) { EXPECT_EQ(e->nFileSizeLow, 7); check_st(&e->ftLastWriteTime, 2005, 6, 30, 9, 9, "24h"); }
    e = fc_by_name(v, m, "lower dir"); CHECK(e);
    if (e) { EXPECT_EQ(e->dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY); check_st(&e->ftLastWriteTime, 2015, 10, 1, 8, 0, "lower-case am"); }
}

TEST(ftpc_dos_listing_wildcard) {
    WIN32_FIND_DATAA v[16]; int n; DWORD err;
    if (!fc_list_raw(dos_listing, "*dir", v, 16, &n, &err)) return;
    EXPECT_EQ(n, 2);
}

TEST(ftpc_dos_listing_leading_spaces) {
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("   \r\n  01-02-03  04:05AM   99 x.txt\r\n", NULL, v, 4, &n, &err)) return;
    EXPECT_EQ(n, 1);
    if (n == 1) { EXPECT_STR(v[0].cFileName, "x.txt"); EXPECT_EQ(v[0].nFileSizeLow, 99); check_st(&v[0].ftLastWriteTime, 2003, 1, 2, 4, 5, "x.txt"); }
}

TEST(ftpc_dos_listing_many_entries) {
    char buf[8192]; size_t o = 0;
    for (int i = 0; i < 40; i++) o += snprintf(buf + o, sizeof buf - o, "%02d-%02d-20  %02d:%02dPM %12d file %02d.dat\r\n", i % 12 + 1, i % 28 + 1, i % 12 + 1, i, i * 1000, i);
    WIN32_FIND_DATAA *v = calloc(50, sizeof *v); int n; DWORD err;
    if (!fc_list_raw(buf, NULL, v, 50, &n, &err)) { free(v); return; }
    EXPECT_EQ(n, 40);
    for (int i = 0; i < n && i < 40; i++) {
        char want[32]; snprintf(want, sizeof want, "file %02d.dat", i);
        CHECKF(!strcmp(v[i].cFileName, want) && v[i].nFileSizeLow == (DWORD)(i * 1000), "dos entry %d = [%s] %lu", i, v[i].cFileName, v[i].nFileSizeLow);
        int h = i % 12 + 1; h = h < 12 ? h + 12 : 12;
        SYSTEMTIME s; fc_ft_to_st(&v[i].ftLastWriteTime, &s);
        CHECKF(s.wYear == 2020 && s.wMonth == i % 12 + 1 && s.wDay == i % 28 + 1 && s.wHour == h && s.wMinute == i, "dos entry %d time %u-%u-%u %u:%u", i, s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute);
    }
    free(v);
}

TEST(ftpc_listing_unix_detection_needs_perm_token) {
    /* a unix-looking line whose first token is not a permission string is not recognised */
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("abcdefghij 1 o g 1 Jan  1  2001 f\r\n", NULL, v, 4, &n, &err)) return;
    t_note("non-permission first token: n=%d err=%lu", n, err);
    EXPECT_EQ(n, -1);
}

TEST(ftpc_listing_total_zero_header) {
    WIN32_FIND_DATAA v[4]; int n; DWORD err;
    if (!fc_list_raw("total 0\r\n-rw-r--r-- 1 o g 6 Jan  1  2001 only\r\n", NULL, v, 4, &n, &err)) return;
    EXPECT_EQ(n, 1);
    if (n == 1) EXPECT_STR(v[0].cFileName, "only");
}
