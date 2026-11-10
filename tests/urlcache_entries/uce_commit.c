/* urlcache_entries / CommitUrlCacheEntryA/W: entry creation, types, times, headers, extension, replacement.
 * Decomp: CommitUrlCacheEntryA@0xdaa0, CommitUrlCacheEntryW@0xd1820, CommitUrlCacheEntryHelper@0x32a10,
 * CCacheClientContainer::AddUrl@0x32b80, CCacheContainer::AddUrl@0x7bef0 (server side: GetFileAttributesExW on the
 * local file, VerifyCacheEntryPath unless EDITED, locked entry -> 0x80070020, sticky -> exempt delta 0x15180,
 * VerifyReplaceEditedEntry@0xcf688). */
#include "uce.h"

/* --------------------------------------------------------------- parameter validation */
TEST(uce_commit_a_null_url) {
    REQUIRE(U(CommitUrlCacheEntryA));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(NULL, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL),
                ERROR_INVALID_PARAMETER);
}
TEST(uce_commit_w_null_url) {
    REQUIRE(U(CommitUrlCacheEntryW));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryW)(NULL, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL),
                ERROR_INVALID_PARAMETER);
}
TEST(uce_commit_a_missing_local_file) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(CreateUrlCacheEntryA));
    const char *url = uce_url("cmiss");
    char path[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0));
    CHECK(DeleteFileA(path));
    SET_ERR(0xdeadbeef);
    /* GetFileAttributesExW on the local file fails -> its error [D AddUrl] */
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(url, path, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL),
                ERROR_FILE_NOT_FOUND);
    CHECK(!uce_exists(url));
}
TEST(uce_commit_w_missing_local_file) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(CreateUrlCacheEntryW));
    const char *url = uce_url("cwmiss");
    WCHAR path[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryW)(uce_w(url), 0, L"txt", path, 0));
    CHECK(DeleteFileW(path));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryW)(uce_w(url), path, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, L"txt", NULL),
                ERROR_FILE_NOT_FOUND);
    CHECK(!uce_exists(url));
}
TEST(uce_commit_missing_dir) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("cmdir");
    char p[MAX_PATH]; snprintf(p, sizeof p, "%sno_such_dir\\file.txt", t_tmpdir());
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL),
                ERROR_PATH_NOT_FOUND);
    CHECK(!uce_exists(url));
}
TEST(uce_commit_file_outside_container) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("cout");
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "outside.txt");
    CHECK(uce_write_file(p, "outside", 7));
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    DWORD e = GetLastError();
    /* non-EDITED entries must live in the container (VerifyCacheEntryPath -> E_INVALIDARG) [D] [W10] */
    CHECK(!r);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    CHECK(!uce_exists(url));
    CHECK(uce_file_exists(p));          /* the caller's file is left alone */
    if (r) uce_del(url);
}
TEST(uce_commit_edited_file_outside_container) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("cedout");
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "edited_out.txt");
    CHECK(uce_write_file(p, "edited", 6));
    SET_ERR(0xdeadbeef);
    /* EDITED_CACHE_ENTRY skips VerifyCacheEntryPath [D AddUrl (flags & 8)] */
    BOOL r = U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, NULL, 0, "txt", NULL);
    CHECK(r); EXPECT_ERR(0);              /* [W10] */
    if (r) {
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        CHECK(i != NULL);
        if (i) { CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p)); CHECK(i->CacheEntryType & EDITED_CACHE_ENTRY); free(i); }
        CHECK(uce_del(url));
    }
    DeleteFileA(p);
}

/* --------------------------------------------------------------- basic commit and the stored fields */
TEST(uce_commit_a_basic) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("cbas");
    char path[MAX_PATH];
    ULONGLONG t0 = uce_now();
    FILETIME exp = uce_ft(t0 + 3 * UCE_DAY), mod = uce_ft(t0 - 2 * UCE_DAY);
    DWORD err = 0;
    SET_ERR(0xdeadbeef);
    BOOL r = uce_make_ex(url, "txt", "0123456789", 10, NORMAL_CACHE_ENTRY, NULL, exp, mod, path, &err);
    CHECKF(r, "err %lu", err);
    if (!r) return;
    EXPECT_ERR(0);
    DWORD sz = 0;
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, &sz, &err);
    CHECKF(i != NULL, "info err %lu", err);
    if (!i) { uce_del(url); return; }
    EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
    EXPECT_STR(i->lpszSourceUrlName, url);
    CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, path));
    EXPECT_EQ(i->CacheEntryType, NORMAL_CACHE_ENTRY);
    EXPECT_EQ(i->dwUseCount, 0);          /* use count = current lock count [W10] */
    EXPECT_EQ(i->dwHitRate, 1);           /* a new entry starts at 1 [D AddUrl local_1c4 = 1] [W10] */
    EXPECT_EQ(i->dwSizeLow, 10);
    EXPECT_EQ(i->dwSizeHigh, 0);
    EXPECT_EQ(uce_u64(i->ExpireTime), uce_u64(exp));
    EXPECT_EQ(uce_u64(i->LastModifiedTime), uce_u64(mod));
    ULONGLONG la = uce_u64(i->LastAccessTime), ls = uce_u64(i->LastSyncTime);
    CHECKF(la + UCE_DAY > t0 && la < t0 + UCE_DAY, "LastAccess %llx now %llx", la, t0);   /* set to now at commit [D] */
    CHECKF(ls + UCE_DAY > t0 && ls < t0 + UCE_DAY, "LastSync %llx now %llx", ls, t0);    /* commit time too [W10] */
    EXPECT_EQ(i->lpHeaderInfo, NULL);
    EXPECT_EQ(i->dwHeaderInfoSize, 0);
    EXPECT_STR(i->lpszFileExtension, "txt");
    EXPECT_EQ(i->dwExemptDelta, 0);
    /* strings live inside the caller's buffer */
    CHECK(uce_inside(i->lpszSourceUrlName, i, sz));
    CHECK(uce_inside(i->lpszLocalFileName, i, sz));
    CHECK(uce_inside(i->lpszFileExtension, i, sz));
    free(i);
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    CHECK(!uce_exists(url));
    CHECK(!uce_file_exists(path));       /* deleting the entry deletes its file [D DeleteEntryFile] */
}
TEST(uce_commit_w_basic) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(CreateUrlCacheEntryW)); REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("cwbas"); const WCHAR *wurl = uce_w(url);
    WCHAR path[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryW)(wurl, 5, L"htm", path, 0));
    CHECK(uce_write_fileW(path, "abcde", 5));
    ULONGLONG t0 = uce_now();
    FILETIME exp = uce_ft(t0 + UCE_DAY), mod = uce_ft(t0 - UCE_DAY);
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryW)(wurl, path, exp, mod, NORMAL_CACHE_ENTRY, NULL, 0, L"htm", NULL);
    CHECK(r); EXPECT_ERR(0);
    if (!r) { DeleteFileW(path); return; }
    DWORD sz = 0, err = 0;
    INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(wurl, &sz, &err);
    CHECKF(i != NULL, "err %lu", err);
    if (i) {
        EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
        EXPECT_WSTR(i->lpszSourceUrlName, wurl);
        CHECK(i->lpszLocalFileName && !lstrcmpiW(i->lpszLocalFileName, path));
        EXPECT_EQ(i->dwSizeLow, 5);
        EXPECT_EQ(uce_u64(i->ExpireTime), uce_u64(exp));
        EXPECT_EQ(uce_u64(i->LastModifiedTime), uce_u64(mod));
        CHECK(i->lpszFileExtension && !lstrcmpW(i->lpszFileExtension, L"htm"));
        free(i);
    }
    CHECK(U(DeleteUrlCacheEntryW)(wurl));
    CHECK(!uce_file_existsW(path));
}
TEST(uce_commit_no_local_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("cnofile");
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL);
    CHECK(r); EXPECT_ERR(0);
    if (!r) return;
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    CHECK(i != NULL);
    if (i) {
        EXPECT_EQ(i->lpszLocalFileName, NULL);
        EXPECT_EQ(i->dwSizeLow, 0);
        EXPECT_EQ(i->lpszFileExtension, NULL);
        free(i);
    }
    CHECK(uce_del(url));
}
TEST(uce_commit_empty_local_file_string) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("cempty");
    BOOL r = U(CommitUrlCacheEntryA)(url, "", uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL);
    CHECK(r);   /* "" is treated like NULL: no file checks [D (local && *local)] */
    if (r) { DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e); if (i) { EXPECT_EQ(i->lpszLocalFileName, NULL); free(i); } CHECK(uce_del(url)); }
}
TEST(uce_commit_zero_byte_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("czero");
    char path[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "", 0, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, path, &err));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    CHECK(i != NULL);
    if (i) { EXPECT_EQ(i->dwSizeLow, 0); CHECK(i->lpszLocalFileName != NULL); free(i); }
    CHECK(uce_del(url));
}
TEST(uce_commit_size_matches_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    static const DWORD sizes[] = { 1, 2, 3, 100, 511, 512, 4095, 4096, 4097, 65536, 100000 };
    char *buf = (char *)malloc(100000); memset(buf, 'z', 100000);
    for (size_t k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        const char *url = uce_url("csize");
        char path[MAX_PATH]; DWORD err;
        BOOL r = uce_make_ex(url, "bin", buf, sizes[k], NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, path, &err);
        CHECKF(r, "size %lu err %lu", sizes[k], err);
        if (!r) continue;
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        CHECK(i != NULL);
        if (i) { CHECKF(i->dwSizeLow == sizes[k], "size %lu got %lu", sizes[k], i->dwSizeLow); EXPECT_EQ(i->dwSizeHigh, 0); free(i); }
        CHECK(uce_del(url));
    }
    free(buf);
}
TEST(uce_commit_size_taken_at_commit) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* the expected size passed to Create is only a hint; the entry size is the file size at commit [D GetFileAttributesExW] */
    const char *url = uce_url("chint");
    char path[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 99999, "txt", path, 0));
    CHECK(uce_write_file(path, "seven!!", 7));
    CHECK(U(CommitUrlCacheEntryA)(url, path, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwSizeLow, 7); free(i); } else CHECK(0);
    /* growing the file afterwards does not change the entry */
    CHECK(uce_write_file(path, "fourteen bytes", 14));
    i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwSizeLow, 7); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- entry types */
static const struct { DWORD type; const char *name; } g_types[] = {
    { NORMAL_CACHE_ENTRY, "NORMAL" }, { STICKY_CACHE_ENTRY, "STICKY" }, { NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, "NORMAL|STICKY" },
    { EDITED_CACHE_ENTRY, "EDITED" }, { NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, "NORMAL|EDITED" },
    { TRACK_OFFLINE_CACHE_ENTRY, "TRACK_OFFLINE" }, { TRACK_ONLINE_CACHE_ENTRY, "TRACK_ONLINE" },
    { SPARSE_CACHE_ENTRY, "SPARSE" }, { COOKIE_CACHE_ENTRY, "COOKIE" }, { URLHISTORY_CACHE_ENTRY, "URLHISTORY" },
    { 0, "zero" }, { NORMAL_CACHE_ENTRY | 0x00000002, "NORMAL|0x2" }, { SPARSE_CACHE_ENTRY | NORMAL_CACHE_ENTRY, "SPARSE|NORMAL" },
    { STICKY_CACHE_ENTRY | EDITED_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY, "STICKY|EDITED|HIST" },
};
TEST(uce_commit_types_roundtrip) {
    REQUIRE(U(CommitUrlCacheEntryA));
    for (size_t k = 0; k < sizeof g_types / sizeof *g_types; k++) {
        const char *url = uce_url("ctype");
        char path[MAX_PATH]; DWORD err;
        BOOL r = uce_make_ex(url, "txt", "typed", 5, g_types[k].type, NULL, uce_zero_ft, uce_zero_ft, path, &err);
        CHECKF(r, "%s err %lu", g_types[k].name, err);
        if (!r) continue;
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        if (g_types[k].type & SPARSE_CACHE_ENTRY) {
            /* sparse entries exist (delete works) but GetUrlCacheEntryInfo does not report them [W10] */
            CHECKF(i == NULL && err == ERROR_FILE_NOT_FOUND, "%s info err %lu", g_types[k].name, err);
            free(i); i = NULL;
        } else CHECKF(i != NULL, "%s info err %lu", g_types[k].name, err);
        if (i) {
            /* the committed bits come back with the content container's NORMAL bit (0x1) ORed in
               [D AddUrl: container flags | type] [W10] */
            CHECKF(i->CacheEntryType == (g_types[k].type | NORMAL_CACHE_ENTRY), "%s got 0x%lx", g_types[k].name, i->CacheEntryType);
            CHECKF(i->dwExemptDelta == ((g_types[k].type & STICKY_CACHE_ENTRY) ? 86400u : 0u), "%s exempt %lu", g_types[k].name, i->dwExemptDelta);
            free(i);
        }
        CHECKF(uce_del(url), "%s del err %lu", g_types[k].name, GetLastError());
        /* delete removes the owned file, except for EDITED entries [D CContainerProps::DeleteEntryFile (type & 8)] */
        if (g_types[k].type & EDITED_CACHE_ENTRY) CHECKF(uce_file_exists(path), "%s file gone", g_types[k].name);
        else CHECKF(!uce_file_exists(path), "%s file left", g_types[k].name);
        DeleteFileA(path);
    }
}
TEST(uce_commit_sticky_exempt_delta) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("csticky");
    char path[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "s", 1, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, path, &err));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    CHECK(i != NULL);
    /* sticky entries get a one-day exemption: 0x15180 = 86400 s [D AddUrl local_1e0] */
    if (i) { EXPECT_EQ(i->dwExemptDelta, 86400); CHECK(i->CacheEntryType & STICKY_CACHE_ENTRY); free(i); }
    CHECK(uce_del(url));
}
TEST(uce_commit_nonsticky_no_exempt) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("cnonst");
    char path[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "n", 1, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, path, &err));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwExemptDelta, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_cookie_type_no_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("ccookie");
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, COOKIE_CACHE_ENTRY, NULL, 0, NULL, NULL);
    CHECK(r);
    if (r) { DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e); if (i) { CHECK(i->CacheEntryType & COOKIE_CACHE_ENTRY); free(i); } CHECK(uce_del(url)); }
}
TEST(uce_commit_urlhistory_type_no_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("chist");
    BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, URLHISTORY_CACHE_ENTRY, NULL, 0, NULL, NULL);
    CHECK(r);
    if (r) { DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e); if (i) { CHECK(i->CacheEntryType & URLHISTORY_CACHE_ENTRY); free(i); } CHECK(uce_del(url)); }
}

/* --------------------------------------------------------------- times */
TEST(uce_commit_times_table) {
    REQUIRE(U(CommitUrlCacheEntryA));
    ULONGLONG now = uce_now();
    const ULONGLONG vals[][2] = {
        { 0, 0 }, { now + UCE_DAY, now - UCE_DAY }, { now + 365 * UCE_DAY, 0 }, { 0, now - 30 * UCE_DAY },
        { 0x01D0000000000000ULL, 0x01C0000000000000ULL }, { 1, 1 }, { 0x7FFFFFFFFFFFFFFFULL, 0x0000000100000000ULL },
        { now - UCE_DAY, now + UCE_DAY },     /* already expired, lastmod in the future: stored verbatim */
    };
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) {
        const char *url = uce_url("ctime");
        char path[MAX_PATH]; DWORD err;
        BOOL r = uce_make_ex(url, "txt", "t", 1, NORMAL_CACHE_ENTRY, NULL, uce_ft(vals[k][0]), uce_ft(vals[k][1]), path, &err);
        CHECKF(r, "row %u err %lu", (unsigned)k, err);
        if (!r) continue;
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        if (i) {
            CHECKF(uce_u64(i->ExpireTime) == vals[k][0], "row %u expire %llx want %llx", (unsigned)k, uce_u64(i->ExpireTime), vals[k][0]);
            CHECKF(uce_u64(i->LastModifiedTime) == vals[k][1], "row %u mod %llx want %llx", (unsigned)k, uce_u64(i->LastModifiedTime), vals[k][1]);
            free(i);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_commit_w_times) {
    REQUIRE(U(CommitUrlCacheEntryW));
    const char *url = uce_url("cwtime"); const WCHAR *w = uce_w(url);
    FILETIME e = uce_ft(0x01D9000011112222ULL), m = uce_ft(0x01D8000033334444ULL);
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, e, m, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    DWORD err; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(w, NULL, &err);
    if (i) { EXPECT_EQ(uce_u64(i->ExpireTime), uce_u64(e)); EXPECT_EQ(uce_u64(i->LastModifiedTime), uce_u64(m)); free(i); } else CHECK(0);
    CHECK(U(DeleteUrlCacheEntryW)(w));
}

/* --------------------------------------------------------------- header info */
TEST(uce_commit_a_header_roundtrip) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("chdr");
    const char *hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-I7: 1\r\n\r\n";
    char path[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "body", 4, NORMAL_CACHE_ENTRY, hdr, uce_zero_ft, uce_zero_ft, path, &err));
    DWORD sz = 0;
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, &sz, &err);
    CHECK(i != NULL);
    if (i) {
        EXPECT_EQ(i->dwHeaderInfoSize, strlen(hdr));
        CHECK(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, hdr, strlen(hdr)));
        CHECK(uce_inside(i->lpHeaderInfo, i, sz));
        /* the buffer is zeroed first, so the header is NUL-terminated by padding when room is left [D memset] */
        free(i);
    }
    CHECK(uce_del(url));
}
TEST(uce_commit_a_header_binary_len) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* the A header is a byte blob of dwHeaderSize bytes (embedded NULs kept) [D: passed through unchanged] */
    const char *url = uce_url("chbin");
    const char blob[] = { 'a', 0, 'b', 0, 'c', 1, 2, 3 };
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (BYTE *)blob, sizeof blob, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwHeaderInfoSize, sizeof blob); CHECK(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, blob, sizeof blob)); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_a_header_len_zero) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* A with dwHeaderSize 0: nothing stored (no strlen) [D AddUrl: header column NULL when size 0] */
    const char *url = uce_url("chz");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (BYTE *)"X: y\r\n", 0, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwHeaderInfoSize, 0); EXPECT_EQ(i->lpHeaderInfo, NULL); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_a_header_partial_len) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("chpart");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (BYTE *)"ABCDEFGH", 3, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwHeaderInfoSize, 3); CHECK(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, "ABC", 3)); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_w_header_utf8) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(GetUrlCacheEntryInfoA));
    /* W header text is converted to UTF-8 (CP 0xfde9); length 0 -> wcslen [D CommitUrlCacheEntryW] */
    const char *url = uce_url("chw"); const WCHAR *w = uce_w(url);
    WCHAR hdr[] = L"X-Name: caf\x00e9\r\n";
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, hdr, 0, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    const char want[] = "X-Name: caf\xc3\xa9\r\n";
    if (i) {
        EXPECT_EQ(i->dwHeaderInfoSize, sizeof want - 1);
        CHECK(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, want, sizeof want - 1));
        free(i);
    } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_w_header_explicit_len) {
    REQUIRE(U(CommitUrlCacheEntryW));
    const char *url = uce_url("chwl"); const WCHAR *w = uce_w(url);
    WCHAR hdr[] = L"ABCDEFGH";
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, hdr, 4, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwHeaderInfoSize, 4); CHECK(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, "ABCD", 4)); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_w_header_empty_string) {
    REQUIRE(U(CommitUrlCacheEntryW));
    const char *url = uce_url("chwe"); const WCHAR *w = uce_w(url);
    WCHAR hdr[] = L"";
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, hdr, 0, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwHeaderInfoSize, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_w_header_readback_w) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("chww"); const WCHAR *w = uce_w(url);
    WCHAR hdr[] = L"HTTP/1.1 200 OK\r\nA: b\r\n\r\n";
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, hdr, 0, NULL, NULL));
    DWORD sz, e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(w, &sz, &e);
    if (i) {
        /* W info returns the stored header bytes; dwHeaderInfoSize unit noted */
        EXPECT_EQ(i->dwHeaderInfoSize, (DWORD)lstrlenW(hdr));   /* characters, header widened again [D ConvertCacheEntryInfoW] [W10] */
        CHECK(i->lpHeaderInfo != NULL);
        if (i->lpHeaderInfo) CHECK(uce_inside(i->lpHeaderInfo, i, sz));
        if (i->lpHeaderInfo && i->dwHeaderInfoSize == lstrlenW(hdr)) CHECK(!memcmp(i->lpHeaderInfo, hdr, lstrlenW(hdr) * 2));
        free(i);
    } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- extension and original URL */
TEST(uce_commit_ext_table) {
    REQUIRE(U(CommitUrlCacheEntryA));
    static const char *exts[] = { "txt", "htm", "a", "JPEG", "x.y", "" };
    for (size_t k = 0; k < sizeof exts / sizeof *exts; k++) {
        const char *url = uce_url("cext");
        BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, exts[k], NULL);
        CHECKF(r, "ext %s err %lu", exts[k], GetLastError());
        if (!r) continue;
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) {
            /* stored verbatim; "" stays "" (not NULL) [W10] */
            CHECKF(i->lpszFileExtension && !strcmp(i->lpszFileExtension, exts[k]), "ext %s got %s", exts[k], i->lpszFileExtension ? i->lpszFileExtension : "(null)");
            free(i);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_commit_original_url) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("corig"); const char *orig = uce_url("corigsrc");
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, orig);
    CHECK(r); EXPECT_ERR(0);
    CHECK(!uce_exists(orig));             /* the original URL is metadata only */
    if (r) CHECK(uce_del(url));
}
TEST(uce_commit_original_url_invalid) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("corigbad");
    SET_ERR(0xdeadbeef);
    /* the original URL goes through the same key conversion -> 12005 [D CommitUrlCacheEntryA 0x130] */
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, "http://"),
                ERROR_INTERNET_INVALID_URL);
    CHECK(!uce_exists(url));
}
TEST(uce_commit_invalid_url) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(CommitUrlCacheEntryW));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)("http:bad", NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL), ERROR_INTERNET_INVALID_URL);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryW)(L"https://", NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL), ERROR_INTERNET_INVALID_URL);
}

/* --------------------------------------------------------------- re-commit / replacement */
TEST(uce_commit_replace_entry) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("crepl");
    char p1[MAX_PATH], p2[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "first", 5, NORMAL_CACHE_ENTRY, "H: 1\r\n", uce_ft(1000), uce_ft(2000), p1, &err));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i1 = uce_info(url, NULL, &e);
    CHECK(uce_make_ex(url, "txt", "second!", 7, NORMAL_CACHE_ENTRY, "H: 22\r\n", uce_ft(3000), uce_ft(4000), p2, &err));
    INTERNET_CACHE_ENTRY_INFOA *i2 = uce_info(url, NULL, &e);
    CHECK(i1 && i2);
    if (i1 && i2) {
        CHECK(!_stricmp(i2->lpszLocalFileName, p2));
        EXPECT_EQ(i2->dwSizeLow, 7);
        EXPECT_EQ(uce_u64(i2->ExpireTime), 3000);
        EXPECT_EQ(uce_u64(i2->LastModifiedTime), 4000);
        EXPECT_EQ(i2->dwHeaderInfoSize, 7);
        /* replacement keeps counting: hit rate = old + 1 [D AddUrl local_fc + 1] [W10] */
        EXPECT_EQ(i1->dwHitRate, 1);
        EXPECT_EQ(i2->dwHitRate, 2);
        EXPECT_EQ(i2->dwUseCount, 0);
    }
    free(i1); free(i2);
    CHECK(!uce_file_exists(p1));         /* the replaced file is deleted [D DeleteEntryFile when names differ] */
    CHECK(uce_file_exists(p2));
    CHECK(uce_del(url));
    CHECK(!uce_file_exists(p2));
}
TEST(uce_commit_replace_same_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("crsame");
    char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "one", 3, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    CHECK(uce_write_file(p, "three", 5));
    /* re-committing the same file name keeps it [D _wcsicmp(old, new) == 0 -> no DeleteEntryFile] */
    CHECK(U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL));
    CHECK(uce_file_exists(p));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->dwSizeLow, 5); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_replace_file_with_none) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("crnone");
    char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "data", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->lpszLocalFileName, NULL); free(i); } else CHECK(0);
    CHECK(!uce_file_exists(p));
    CHECK(uce_del(url));
}
TEST(uce_commit_replace_type_change) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("crtype");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, NULL, 0, NULL, NULL));
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) { EXPECT_EQ(i->CacheEntryType, NORMAL_CACHE_ENTRY); EXPECT_EQ(i->dwExemptDelta, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_commit_over_locked_entry) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("clocked");
    char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "locked", 6, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    DWORD sz = 0;
    BOOL got = U(RetrieveUrlCacheEntryFileA)(url, NULL, &sz, 0);     /* -> 122 and NOT locked */
    CHECK(!got);
    char buf[4096]; INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)buf; sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, i, &sz, 0));
    char p2[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p2, 0));
    CHECK(uce_write_file(p2, "new", 3));
    SET_ERR(0xdeadbeef);
    /* replacing a locked entry -> HRESULT 0x80070020 [D AddUrl GetLockCount] */
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL), ERROR_SHARING_VIOLATION);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    /* the entry is unchanged */
    INTERNET_CACHE_ENTRY_INFOA *j = uce_info(url, NULL, &err);
    if (j) { EXPECT_EQ(j->dwSizeLow, 6); CHECK(!_stricmp(j->lpszLocalFileName, p)); free(j); } else CHECK(0);
    /* after unlock the commit works */
    CHECK(U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL));
    CHECK(uce_del(url));
    DeleteFileA(p2);
}
TEST(uce_commit_edited_replaced_by_normal) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* an EDITED entry with a non-empty file cannot be replaced by a non-EDITED commit [D VerifyReplaceEditedEntry] */
    const char *url = uce_url("cedrep");
    char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "edited", 6, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    char p2[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p2, 0));
    CHECK(uce_write_file(p2, "fresh", 5));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL), ERROR_SHARING_VIOLATION);
    /* another EDITED commit is allowed */
    CHECK(U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, NULL, 0, "txt", NULL));
    CHECK(uce_del(url));
    DeleteFileA(p); DeleteFileA(p2);
}
TEST(uce_commit_many_entries) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char urls[40][256]; int ok = 0;
    for (int k = 0; k < 40; k++) {
        strcpy(urls[k], uce_url("cmany"));
        char body[32]; int n = snprintf(body, sizeof body, "body %d", k); char p[MAX_PATH]; DWORD err;
        ok += uce_make_ex(urls[k], "txt", body, (DWORD)n, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err) ? 1 : 0;
    }
    EXPECT_EQ(ok, 40);
    for (int k = 0; k < 40; k++) {
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(urls[k], NULL, &e);
        if (i) {
            char body[32]; int n = snprintf(body, sizeof body, "body %d", k), got;
            char rb[64]; got = i->lpszLocalFileName ? uce_read_file(i->lpszLocalFileName, rb, sizeof rb) : -1;
            CHECKF(got == n && !memcmp(rb, body, n), "entry %d", k);
            free(i);
        } else CHECKF(0, "entry %d missing err %lu", k, e);
    }
    for (int k = 0; k < 40; k++) CHECK(uce_del(urls[k]));
}
