/* urlcache_entries / extra combinations: Ex flags on W, sparse entries, operations on locked entries, A<->W views.
 * Decomp references as in the other files (ConvertCacheEntryInfoW, GetUrlCacheEntryInfoExW@0xb9c0, UpdateUrl@0x2ac2c). */
#include "uce.h"

static BOOL mk(const char *url, const char *body, char *path) {
    DWORD err;
    return uce_make_ex(url, "txt", body, (DWORD)strlen(body), NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, path, &err);
}

TEST(uce_more_exw_fixed_only_flag) {
    REQUIRE(U(GetUrlCacheEntryInfoExW));
    const char *url = uce_url("mexw"); char p[MAX_PATH];
    CHECK(mk(url, "12345", p));
    unsigned char buf[0x100]; memset(buf, 0xCC, sizeof buf);
    DWORD sz = 0x70;
    SET_ERR(0xdeadbeef);
    BOOL r = U(GetUrlCacheEntryInfoExW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL, 0x1000);
    CHECK(r); EXPECT_ERR(0);
    INTERNET_CACHE_ENTRY_INFOW *i = (INTERNET_CACHE_ENTRY_INFOW *)buf;
    if (r) {
        EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
        EXPECT_EQ(i->lpszSourceUrlName, NULL);
        EXPECT_EQ(i->lpszLocalFileName, NULL);
        EXPECT_EQ(i->dwSizeLow, 5);
        CHECK(buf[0x70] == 0xCC);
    }
    sz = 0x6f;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL, 0x1000), ERROR_INSUFFICIENT_BUFFER);
    CHECK(uce_del(url));
}
TEST(uce_more_exw_matches_w) {
    REQUIRE(U(GetUrlCacheEntryInfoExW));
    const char *url = uce_url("mexw2"); char p[MAX_PATH];
    CHECK(mk(url, "abc", p));
    DWORD s1 = 0, s2 = 0;
    U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, &s1);
    U(GetUrlCacheEntryInfoExW)(uce_w(url), NULL, &s2, NULL, NULL, NULL, 0);
    EXPECT_EQ(s1, s2);
    CHECK(s1 > UCE_INFO_SIZE);
    SET_ERR(0xdeadbeef);
    CHECK(U(GetUrlCacheEntryInfoExW)(uce_w(url), NULL, NULL, NULL, NULL, NULL, 0));
    EXPECT_ERR(0);
    CHECK(uce_del(url));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExW)(uce_w(url), NULL, NULL, NULL, NULL, NULL, 0), ERROR_FILE_NOT_FOUND);
}
TEST(uce_more_exa_null_url) {
    REQUIRE(U(GetUrlCacheEntryInfoExA)); REQUIRE(U(GetUrlCacheEntryInfoExW));
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(NULL, NULL, &sz, NULL, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExW)(NULL, NULL, &sz, NULL, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    char buf[256]; sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(uce_url("mexz"), (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
}
TEST(uce_more_stream_w_sizes) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamW)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("msw"); char p[MAX_PATH];
    CHECK(mk(url, "stream", p));
    DWORD need = 0; U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, &need);
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamW)(uce_w(url), NULL, &sz, FALSE, 0);
    /* W: NULL buffer with *size 0 -> 122 and the requirement [D ConvertCacheEntryInfoW] */
    EXPECT_FAIL(h == NULL, ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, need);
    CHECK(uce_del(url));                 /* the failed retrieve left no lock */
}
TEST(uce_more_sparse_entry) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("msparse"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "sp", 2, SPARSE_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    /* hidden from GetUrlCacheEntryInfo but present for delete [W10] */
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    BOOL r = U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0);
    DWORD e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);   /* hidden from retrieve too [W10] */
    if (r) U(UnlockUrlCacheEntryFileA)(url, 0);
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_FILE_NOT_FOUND);
}
TEST(uce_more_set_while_locked) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("msetl"); char p[MAX_PATH];
    CHECK(mk(url, "lockedset", p));
    char buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.ExpireTime = uce_ft(0x01DB000000000000ULL);
    SET_ERR(0xdeadbeef);
    BOOL r = U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_EXPTIME_FC);
    CHECK(r); EXPECT_ERR(0);              /* Set ignores locks [W10] */
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    if (i) EXPECT_EQ(uce_u64(i->ExpireTime), 0x01DB000000000000ULL); else CHECK(0);
    free(i);
    CHECK(uce_del(url));
}
TEST(uce_more_get_does_not_lock) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("mgnl"); char p[MAX_PATH];
    CHECK(mk(url, "x", p));
    for (int k = 0; k < 5; k++) { DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e); if (i) { EXPECT_EQ(i->dwUseCount, 0); EXPECT_EQ(i->dwHitRate, 1); free(i); } else CHECK(0); }
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
}
TEST(uce_more_a_commit_w_read) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("maw"); char p[MAX_PATH]; DWORD err;
    ULONGLONG t = uce_now();
    CHECK(uce_make_ex(url, "png", "\x89PNG", 4, NORMAL_CACHE_ENTRY, "Content-Type: image/png\r\n", uce_ft(t + UCE_DAY), uce_ft(t), p, &err));
    DWORD sz; INTERNET_CACHE_ENTRY_INFOW *w = uce_infoW(uce_w(url), &sz, &err);
    CHECK(w != NULL);
    if (w) {
        EXPECT_WSTR(w->lpszSourceUrlName, uce_w(url));
        EXPECT_WSTR(w->lpszFileExtension, L"png");
        EXPECT_EQ(w->dwHeaderInfoSize, 25);
        CHECK(w->lpHeaderInfo && !memcmp(w->lpHeaderInfo, L"Content-Type: image/png\r\n", 50));
        EXPECT_EQ(w->dwSizeLow, 4);
        EXPECT_EQ(uce_u64(w->ExpireTime), t + UCE_DAY);
        CHECK(uce_inside(w->lpHeaderInfo, w, sz));
        free(w);
    }
    CHECK(U(DeleteUrlCacheEntryW)(uce_w(url)));
}
TEST(uce_more_w_commit_a_read) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(CreateUrlCacheEntryW));
    const char *url = uce_url("mwa"); const WCHAR *w = uce_w(url);
    WCHAR path[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryW)(w, 3, L"js", path, 0));
    CHECK(uce_write_fileW(path, "f()", 3));
    CHECK(U(CommitUrlCacheEntryW)(w, path, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, NULL, 0, L"js", NULL));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &err);
    if (a) {
        EXPECT_STR(a->lpszSourceUrlName, url);
        CHECK(!_stricmp(a->lpszLocalFileName, uce_a(path)));
        EXPECT_STR(a->lpszFileExtension, "js");
        EXPECT_EQ(a->CacheEntryType, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY);
        EXPECT_EQ(a->dwExemptDelta, 86400);
        free(a);
    } else CHECK(0);
    CHECK(uce_del(url));
    CHECK(!uce_file_existsW(path));
}
TEST(uce_more_commit_local_file_case) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* the container path is compared case-insensitively (WxVerifySameDirectory) */
    const char *url = uce_url("mcase"); char p[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p, 0));
    CHECK(uce_write_file(p, "Cc", 2));
    char up[MAX_PATH]; strcpy(up, p); CharUpperA(up);
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(url, up, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    CHECK(r); EXPECT_ERR(0);              /* [W10] */
    if (r) CHECK(uce_del(url)); else DeleteFileA(p);
}
TEST(uce_more_commit_file_in_container_root) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* a file directly in ...\INetCache\IE\ (not in one of the 8-char subdirectories) is refused [D VerifyCacheEntryPath] */
    const char *url = uce_url("mroot"); char p[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p, 0));
    char d[MAX_PATH]; uce_dirname(p, d); d[strlen(d) - 1] = 0; char *s = strrchr(d, '\\'); if (s) s[1] = 0;
    char q[MAX_PATH]; snprintf(q, sizeof q, "%s%s.txt", d, t_uniq("rootfile"));
    BOOL w = uce_write_file(q, "r", 1);
    if (!w) { DeleteFileA(p); t_skip("cannot create a file in %s", d); return; }
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(url, q, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    DWORD e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);   /* [D VerifyCacheEntryPath] [W10] */
    if (r) uce_del(url);
    DeleteFileA(q); DeleteFileA(p);
}
TEST(uce_more_delete_then_recommit) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("mrec"); char p[MAX_PATH], p2[MAX_PATH];
    CHECK(mk(url, "one", p));
    CHECK(uce_del(url));
    CHECK(mk(url, "two!", p2));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    /* a new entry: counters restart [W10 hit rate 1 on create] */
    if (i) { EXPECT_EQ(i->dwHitRate, 1); EXPECT_EQ(i->dwSizeLow, 4); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_more_info_after_file_grows_retrieve) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("mgrow"); char p[MAX_PATH];
    CHECK(mk(url, "abc", p));
    CHECK(uce_write_file(p, "abcdefgh", 8));
    char buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    EXPECT_EQ(((INTERNET_CACHE_ENTRY_INFOA *)buf)->dwSizeLow, 3);   /* committed size, file not re-read [W10] */
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    CHECK(uce_del(url));
}
TEST(uce_more_set_edited_relative_name) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    /* a non-EDITED entry stores its file relative to the container [D AddUrl: path + dir length unless (flags & 8)];
       flipping EDITED on with SetUrlCacheEntryInfo therefore exposes the bare leaf name [W10] */
    const char *url = uce_url("medit"); char p[MAX_PATH];
    CHECK(mk(url, "rel", p));
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.CacheEntryType = NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_ATTRIBUTE_FC));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
    const char *leaf = strrchr(p, '\\'); leaf = leaf ? leaf + 1 : p;
    if (i) { CHECKF(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, leaf), "%s", i->lpszLocalFileName ? i->lpszLocalFileName : "(null)"); free(i); } else CHECK(0);
    /* back to NORMAL: the full path is seen again, and delete removes the file */
    n.CacheEntryType = NORMAL_CACHE_ENTRY;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_ATTRIBUTE_FC));
    i = uce_info(url, NULL, &e);
    if (i) { CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p)); free(i); } else CHECK(0);
    CHECK(uce_del(url));
    CHECK(!uce_file_exists(p));
}
