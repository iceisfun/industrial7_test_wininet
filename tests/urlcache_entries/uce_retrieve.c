/* urlcache_entries / RetrieveUrlCacheEntryFileA/W + UnlockUrlCacheEntryFile(A/W), RetrieveUrlCacheEntryStreamA/W +
 * ReadUrlCacheEntryStream(Ex) + UnlockUrlCacheEntryStream, DeleteUrlCacheEntryA/W (incl. locked entries).
 * Decomp: RetrieveUrlCacheEntryFileA@0x1a1a20 / W@0x1a1c40 (NULL url/size -> 87, buffer with *size 0 -> 87,
 * dwReserved != 0 -> 87, conversion failure unlocks again), UnlockUrlCacheEntryFile@0x1a30d0 / W@0x1a3210,
 * RetrieveUrlCacheEntryStreamA@0x1a1e70 / W@0x1a20b0, ReadUrlCacheEntryStream@0x1a17d0 (NULL -> 6),
 * ReadUrlCacheEntryStreamHelper@0x1ab688 (seek to offset, ReadFile), UnlockUrlCacheEntryStreamHelper@0x6f8b0
 * (bad handle -> 6), DeleteUrlCacheEntry@0x2d3f0 / W@0x21c10, CCacheContainer::DeleteUrl@0x2b350 (locked -> 0x80070020). */
#include "uce.h"

UDECL(BOOL, ReadUrlCacheEntryStreamEx, (HANDLE, DWORDLONG, LPVOID, LPDWORD));

static const char g_body[] = "The quick brown fox jumps over the lazy dog. 0123456789";

static BOOL mk(const char *url, char *path) {
    DWORD err;
    return uce_make_ex(url, "txt", g_body, sizeof g_body - 1, NORMAL_CACHE_ENTRY, "HTTP/1.1 200 OK\r\n\r\n", uce_zero_ft, uce_zero_ft, path, &err);
}

/* --------------------------------------------------------------- RetrieveUrlCacheEntryFile: validation */
TEST(uce_retr_a_null_url) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0), ERROR_INVALID_PARAMETER);
}
TEST(uce_retr_a_null_size) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("rns"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char buf[1024];
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(url, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    CHECK(uce_del(url));     /* nothing was locked */
}
TEST(uce_retr_a_buffer_size_zero) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("rbz"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char buf[1024]; DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0), ERROR_INVALID_PARAMETER);
    CHECK(uce_del(url));
}
TEST(uce_retr_a_reserved_nonzero) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(RetrieveUrlCacheEntryFileW));
    const char *url = uce_url("rres"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char buf[2048]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 1), ERROR_INVALID_PARAMETER);
    sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, 0x80000000), ERROR_INVALID_PARAMETER);
    CHECK(uce_del(url));
}
TEST(uce_retr_w_null_args) {
    REQUIRE(U(RetrieveUrlCacheEntryFileW));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileW)(L"http://x.example/", (INTERNET_CACHE_ENTRY_INFOW *)buf, NULL, 0), ERROR_INVALID_PARAMETER);
    sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileW)(L"http://x.example/", (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, 0), ERROR_INVALID_PARAMETER);
}
TEST(uce_retr_missing_entry) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(RetrieveUrlCacheEntryFileW));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(uce_url("rmiss"), (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0), ERROR_FILE_NOT_FOUND);
    sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(uce_url("rmiss2"), NULL, &sz, 0), ERROR_FILE_NOT_FOUND);
    sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileW)(uce_w(uce_url("rmissw")), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, 0), ERROR_FILE_NOT_FOUND);
}
TEST(uce_retr_invalid_url) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)("http://", NULL, &sz, 0), ERROR_INTERNET_INVALID_URL);
}

/* --------------------------------------------------------------- RetrieveUrlCacheEntryFile: behaviour */
TEST(uce_retr_a_basic_and_unlock) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("rbasic"); char p[MAX_PATH];
    CHECK(mk(url, p));
    DWORD need = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(url, NULL, &need, 0), ERROR_INSUFFICIENT_BUFFER);
    DWORD info_need = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &info_need);
    EXPECT_EQ(need, info_need);        /* same ConvertCacheEntryInfoA sizing [D] */
    INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)calloc(1, need);
    DWORD sz = need;
    SET_ERR(0xdeadbeef);
    BOOL r = U(RetrieveUrlCacheEntryFileA)(url, i, &sz, 0);
    CHECK(r); EXPECT_ERR(0);
    if (r) {
        EXPECT_EQ(sz, need);
        EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
        EXPECT_STR(i->lpszSourceUrlName, url);
        CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p));
        char rb[256]; int n = i->lpszLocalFileName ? uce_read_file(i->lpszLocalFileName, rb, sizeof rb) : -1;
        CHECK(n == (int)sizeof g_body - 1 && !memcmp(rb, g_body, n));
        EXPECT_EQ(i->dwSizeLow, sizeof g_body - 1);
        SET_ERR(0xdeadbeef);
        CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
        EXPECT_ERR(0);
    }
    free(i);
    CHECK(uce_del(url));
}
TEST(uce_retr_w_basic_and_unlock) {
    REQUIRE(U(RetrieveUrlCacheEntryFileW)); REQUIRE(U(UnlockUrlCacheEntryFileW));
    const char *url = uce_url("rwbasic"); char p[MAX_PATH];
    CHECK(mk(url, p));
    const WCHAR *w = uce_w(url);
    DWORD need = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileW)(w, NULL, &need, 0), ERROR_INSUFFICIENT_BUFFER);
    DWORD info_need = 0; U(GetUrlCacheEntryInfoW)(w, NULL, &info_need);
    EXPECT_EQ(need, info_need);
    INTERNET_CACHE_ENTRY_INFOW *i = (INTERNET_CACHE_ENTRY_INFOW *)calloc(1, need);
    DWORD sz = need;
    BOOL r = U(RetrieveUrlCacheEntryFileW)(w, i, &sz, 0);
    CHECK(r);
    if (r) {
        EXPECT_WSTR(i->lpszSourceUrlName, w);
        CHECK(i->lpszLocalFileName && !lstrcmpiW(i->lpszLocalFileName, uce_w(p)));
        SET_ERR(0xdeadbeef);
        CHECK(U(UnlockUrlCacheEntryFileW)(w, 0));
        EXPECT_ERR(0);
    }
    free(i);
    CHECK(U(DeleteUrlCacheEntryW)(w));
}
TEST(uce_retr_small_buffer_not_locked) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("rsmall"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char buf[0x80]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0), ERROR_INSUFFICIENT_BUFFER);
    CHECK(sz > sizeof buf);
    /* a failed conversion releases the lock again [D UnlockUrlCacheEntryFileHelper on failure] */
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    CHECK(!uce_exists(url));
}
TEST(uce_retr_delete_while_locked) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("rdlock"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    SET_ERR(0xdeadbeef);
    BOOL d = uce_del(url);
    DWORD e = GetLastError();
    /* deleting a locked entry fails with 0x80070020 [D CCacheContainer::DeleteUrl] and leaves entry and file alone [W10] */
    CHECK(!d);
    EXPECT_EQ(e, ERROR_SHARING_VIOLATION);
    CHECK(uce_exists(url));
    CHECK(uce_file_exists(p));
    SET_ERR(0xdeadbeef);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    EXPECT_ERR(0);
    /* the refused delete is remembered: the last unlock removes entry and file [W10, 2 boots] */
    CHECK(!uce_exists(url));
    CHECK(!uce_file_exists(p));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_FILE_NOT_FOUND);
    CHECK(!uce_exists(url));
}
TEST(uce_retr_lock_counts) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("rcount"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char buf[4096]; DWORD sz;
    sz = sizeof buf; CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    sz = sizeof buf; CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    /* still locked once: a replacing commit is refused */
    char p2[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p2, 0)); CHECK(uce_write_file(p2, "x", 1));
    SET_ERR(0xdeadbeef);
    BOOL c = U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    DWORD e = GetLastError();
    /* locks are counted: one retrieve is still outstanding [W10] */
    CHECK(!c); EXPECT_EQ(e, ERROR_SHARING_VIOLATION);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    CHECK(U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL));
    CHECK(uce_del(url));
    DeleteFileA(p2);
}
TEST(uce_retr_updates_use_count) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("ruse"); char p[MAX_PATH];
    CHECK(mk(url, p));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *b = uce_info(url, NULL, &e);
    char buf[4096]; DWORD sz = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0));
    INTERNET_CACHE_ENTRY_INFOA *r1 = (INTERNET_CACHE_ENTRY_INFOA *)buf;
    INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a && b) {
        /* dwUseCount is the live lock count, dwHitRate counts retrievals [W10] */
        EXPECT_EQ(b->dwUseCount, 0); EXPECT_EQ(b->dwHitRate, 1);
        EXPECT_EQ(r1->dwUseCount, 1); EXPECT_EQ(r1->dwHitRate, 2);
        EXPECT_EQ(a->dwUseCount, 1); EXPECT_EQ(a->dwHitRate, 2);
        EXPECT_EQ(uce_u64(a->LastAccessTime), uce_u64(b->LastAccessTime));   /* retrieve does not touch it [W10, 2 boots] */
    } else CHECK(0);
    free(a); free(b);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    a = uce_info(url, NULL, &e);
    if (a) { EXPECT_EQ(a->dwUseCount, 0); EXPECT_EQ(a->dwHitRate, 2); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_retr_entry_without_file) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("rnofile");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    BOOL r = U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0);
    /* an entry without a local file can still be "retrieved" (lpszLocalFileName NULL) [W10] */
    CHECK(r); EXPECT_ERR(0);
    if (r) { EXPECT_EQ(((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszLocalFileName, NULL); CHECK(U(UnlockUrlCacheEntryFileA)(url, 0)); }
    CHECK(uce_del(url));
}
TEST(uce_retr_file_deleted_externally) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("rgone"); char p[MAX_PATH];
    CHECK(mk(url, p));
    CHECK(DeleteFileA(p));
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    BOOL r = U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, 0);
    /* the file is not checked: retrieve succeeds and returns the stale path [W10] */
    CHECK(r); EXPECT_ERR(0);
    if (r) { CHECK(!_stricmp(((INTERNET_CACHE_ENTRY_INFOA *)buf)->lpszLocalFileName, p)); CHECK(U(UnlockUrlCacheEntryFileA)(url, 0)); }
    CHECK(uce_exists(url));
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- UnlockUrlCacheEntryFile */
TEST(uce_unlock_null_and_reserved) {
    REQUIRE(U(UnlockUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileW)); REQUIRE(U(UnlockUrlCacheEntryFile));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileA)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileW)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFile)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileA)(uce_url("ures"), 1), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileW)(uce_w(uce_url("uresw")), 7), ERROR_INVALID_PARAMETER);
}
TEST(uce_unlock_alias_same_entry) {
    /* UnlockUrlCacheEntryFile and UnlockUrlCacheEntryFileA are one function (ordinals 392/393) [D] */
    FARPROC a = t_proc_in("wininet.dll", "UnlockUrlCacheEntryFile"), b = t_proc_in("wininet.dll", "UnlockUrlCacheEntryFileA");
    REQUIRE(a); REQUIRE(b);
    CHECK(a == b);
    FARPROC d1 = t_proc_in("wininet.dll", "DeleteUrlCacheEntry"), d2 = t_proc_in("wininet.dll", "DeleteUrlCacheEntryA");
    REQUIRE(d1); REQUIRE(d2);
    CHECK(d1 == d2);
}
TEST(uce_unlock_missing_entry) {
    REQUIRE(U(UnlockUrlCacheEntryFileA));
    SET_ERR(0xdeadbeef);
    BOOL r = U(UnlockUrlCacheEntryFileA)(uce_url("umiss"), 0);
    DWORD e = GetLastError();
    CHECK(!r);
    EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);
}
TEST(uce_unlock_not_locked) {
    REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("unl"); char p[MAX_PATH];
    CHECK(mk(url, p));
    SET_ERR(0xdeadbeef);
    BOOL r = U(UnlockUrlCacheEntryFileA)(url, 0);
    CHECK(r); EXPECT_ERR(0);              /* unlocking an unlocked entry is not an error [W10] */
    SET_ERR(0xdeadbeef);
    CHECK(U(UnlockUrlCacheEntryFileW)(uce_w(url), 0)); EXPECT_ERR(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- streams */
TEST(uce_stream_a_validation) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, FALSE, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    const char *url = uce_url("sval"); char p[MAX_PATH];
    CHECK(mk(url, p));
    SET_ERR(0xdeadbeef);
    h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, NULL, FALSE, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    sz = 0;
    SET_ERR(0xdeadbeef);
    h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, FALSE, 0);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, FALSE, 1);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    sz = 0;
    SET_ERR(0xdeadbeef);
    h = U(RetrieveUrlCacheEntryStreamA)(url, NULL, &sz, FALSE, 0);
    EXPECT_FAIL(h == NULL, ERROR_INSUFFICIENT_BUFFER);     /* the stream is closed again [D] */
    CHECK(sz > UCE_INFO_SIZE);
    CHECK(uce_del(url));
}
TEST(uce_stream_w_validation) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamW));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(U(RetrieveUrlCacheEntryStreamW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, FALSE, 0) == NULL, ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(U(RetrieveUrlCacheEntryStreamW)(L"http://a.example/", (INTERNET_CACHE_ENTRY_INFOW *)buf, NULL, FALSE, 0) == NULL, ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(U(RetrieveUrlCacheEntryStreamW)(L"http://a.example/", (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, FALSE, 2) == NULL, ERROR_INVALID_PARAMETER);
}
TEST(uce_stream_missing_entry) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(RetrieveUrlCacheEntryStreamW));
    char buf[1024]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(U(RetrieveUrlCacheEntryStreamA)(uce_url("smissa"), (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, FALSE, 0) == NULL, ERROR_FILE_NOT_FOUND);
    sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(U(RetrieveUrlCacheEntryStreamW)(uce_w(uce_url("smissw")), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, TRUE, 0) == NULL, ERROR_FILE_NOT_FOUND);
}
TEST(uce_stream_a_read_all) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("sread"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    CHECK(h != NULL); EXPECT_ERR(0);
    if (!h) { uce_del(url); return; }
    INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)ib;
    EXPECT_STR(i->lpszSourceUrlName, url);
    EXPECT_EQ(i->dwSizeLow, sizeof g_body - 1);
    char rb[256]; DWORD n = sizeof rb;
    SET_ERR(0xdeadbeef);
    CHECK(U(ReadUrlCacheEntryStream)(h, 0, rb, &n, 0));
    EXPECT_ERR(0);
    EXPECT_EQ(n, sizeof g_body - 1);
    CHECK(!memcmp(rb, g_body, sizeof g_body - 1));
    SET_ERR(0xdeadbeef);
    CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    EXPECT_ERR(0);
    CHECK(uce_del(url));
}
TEST(uce_stream_w_read_all) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamW)); REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("swread"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)ib, &sz, TRUE, 0);
    CHECK(h != NULL);
    if (!h) { uce_del(url); return; }
    EXPECT_WSTR(((INTERNET_CACHE_ENTRY_INFOW *)ib)->lpszSourceUrlName, uce_w(url));
    char rb[256]; DWORD n = sizeof rb;
    CHECK(U(ReadUrlCacheEntryStream)(h, 0, rb, &n, 0));
    EXPECT_EQ(n, sizeof g_body - 1);
    CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(uce_del(url));
}
TEST(uce_stream_offsets_table) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("soff"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, TRUE, 0);
    CHECK(h != NULL);
    if (!h) { uce_del(url); return; }
    const DWORD L = sizeof g_body - 1;
    /* offset, request -> bytes returned (ReadFile at the offset) [D ReadUrlCacheEntryStreamHelper] */
    const DWORD rows[][3] = { { 0, 4, 4 }, { 4, 6, 6 }, { 10, 1, 1 }, { 0, 1, 1 }, { L - 1, 10, 1 }, { L, 10, 0 }, { L + 100, 10, 0 },
                              { 20, 0, 0 }, { 3, L, L - 3 }, { 0, L, L }, { 0, 1000, L } };
    for (size_t k = 0; k < sizeof rows / sizeof *rows; k++) {
        char rb[1024]; memset(rb, 0, sizeof rb); DWORD n = rows[k][1];
        SET_ERR(0xdeadbeef);
        BOOL r = U(ReadUrlCacheEntryStream)(h, rows[k][0], rb, &n, 0);
        CHECKF(r, "row %u err %lu", (unsigned)k, GetLastError());
        CHECKF(n == rows[k][2], "row %u off %lu req %lu got %lu want %lu", (unsigned)k, rows[k][0], rows[k][1], n, rows[k][2]);
        if (r && n && rows[k][0] < L) CHECKF(!memcmp(rb, g_body + rows[k][0], n), "row %u data", (unsigned)k);
    }
    CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(uce_del(url));
}
TEST(uce_stream_sequential_reads) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("sseq"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    CHECK(h != NULL);
    if (!h) { uce_del(url); return; }
    char out[256]; DWORD tot = 0;
    for (int k = 0; k < 64 && tot < sizeof out; k++) {
        DWORD n = 7;
        if (!U(ReadUrlCacheEntryStream)(h, tot, out + tot, &n, 0)) { CHECK(0); break; }
        if (!n) break;
        tot += n;
    }
    EXPECT_EQ(tot, sizeof g_body - 1);
    CHECK(!memcmp(out, g_body, tot));
    CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(uce_del(url));
}
TEST(uce_stream_read_ex) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(UN(ReadUrlCacheEntryStreamEx)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("sex"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, TRUE, 0);
    CHECK(h != NULL);
    if (!h) { uce_del(url); return; }
    char rb[64]; DWORD n = 5;
    SET_ERR(0xdeadbeef);
    CHECK(UN(ReadUrlCacheEntryStreamEx)(h, 4, rb, &n));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 5);
    CHECK(!memcmp(rb, g_body + 4, 5));
    n = 5;
    CHECK(UN(ReadUrlCacheEntryStreamEx)(h, 0x100000000ULL, rb, &n));   /* 64-bit offset past EOF -> 0 bytes */
    EXPECT_EQ(n, 0);
    SET_ERR(0xdeadbeef);
    n = 5;
    EXPECT_FAIL(!UN(ReadUrlCacheEntryStreamEx)(NULL, 0, rb, &n), ERROR_INVALID_HANDLE);
    CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(uce_del(url));
}
TEST(uce_stream_read_null_handle) {
    REQUIRE(U(ReadUrlCacheEntryStream));
    char rb[16]; DWORD n = sizeof rb;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(ReadUrlCacheEntryStream)(NULL, 0, rb, &n, 0), ERROR_INVALID_HANDLE);
}
TEST(uce_stream_unlock_null_handle) {
    REQUIRE(U(UnlockUrlCacheEntryStream));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryStream)(NULL, 0), ERROR_INVALID_HANDLE);
}
TEST(uce_stream_stale_handle) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("sstale"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    CHECK(h != NULL);
    if (!h) { uce_del(url); return; }
    CHECK(((ULONG_PTR)h & 1) == 1);                  /* handle-table cookie, odd [D UnlockUrlCacheEntryStreamHelper] */
    CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    char rb[16]; DWORD n = sizeof rb;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(ReadUrlCacheEntryStream)(h, 0, rb, &n, 0), ERROR_INVALID_HANDLE);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryStream)(h, 0), ERROR_INVALID_HANDLE);
    CHECK(uce_del(url));
}
TEST(uce_stream_locks_entry) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("slock"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    CHECK(h != NULL);
    char p2[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p2, 0)); CHECK(uce_write_file(p2, "y", 1));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL), ERROR_SHARING_VIOLATION);
    if (h) CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(U(CommitUrlCacheEntryA)(url, p2, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL));
    CHECK(uce_del(url));
}
TEST(uce_stream_two_handles) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("s2h"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h1 = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, TRUE, 0);
    sz = sizeof ib;
    HANDLE h2 = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, TRUE, 0);
    CHECK(h1 && h2 && h1 != h2);
    char a[8], b[8]; DWORD na = 3, nb = 3;
    if (h1) CHECK(U(ReadUrlCacheEntryStream)(h1, 0, a, &na, 0));
    if (h2) CHECK(U(ReadUrlCacheEntryStream)(h2, 4, b, &nb, 0));
    CHECK(na == 3 && !memcmp(a, "The", 3));
    CHECK(nb == 3 && !memcmp(b, "qui", 3));
    if (h1) CHECK(U(UnlockUrlCacheEntryStream)(h1, 0));
    if (h2) CHECK(U(UnlockUrlCacheEntryStream)(h2, 0));
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- DeleteUrlCacheEntry */
TEST(uce_delete_null) {
    REQUIRE(U(DeleteUrlCacheEntryA)); REQUIRE(U(DeleteUrlCacheEntryW)); REQUIRE(U(DeleteUrlCacheEntry));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryA)(NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryW)(NULL), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntry)(NULL), ERROR_INVALID_PARAMETER);
}
TEST(uce_delete_missing) {
    REQUIRE(U(DeleteUrlCacheEntryA)); REQUIRE(U(DeleteUrlCacheEntryW));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryA)(uce_url("dmiss")), ERROR_FILE_NOT_FOUND);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryW)(uce_w(uce_url("dmissw"))), ERROR_FILE_NOT_FOUND);
}
TEST(uce_delete_invalid_url) {
    REQUIRE(U(DeleteUrlCacheEntryA)); REQUIRE(U(DeleteUrlCacheEntryW));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryA)("http://"), ERROR_INTERNET_INVALID_URL);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryW)(L"https:x"), ERROR_INTERNET_INVALID_URL);
}
TEST(uce_delete_twice) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    const char *url = uce_url("dtwice"); char p[MAX_PATH];
    CHECK(mk(url, p));
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_FILE_NOT_FOUND);
    CHECK(!uce_file_exists(p));
}
TEST(uce_delete_a_then_w_view) {
    REQUIRE(U(DeleteUrlCacheEntryW));
    const char *url = uce_url("daw"); char p[MAX_PATH];
    CHECK(mk(url, p));
    CHECK(U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, NULL));
    CHECK(U(DeleteUrlCacheEntryW)(uce_w(url)));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, NULL, NULL), ERROR_FILE_NOT_FOUND);
}
TEST(uce_delete_file_already_gone) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    const char *url = uce_url("dgone"); char p[MAX_PATH];
    CHECK(mk(url, p));
    CHECK(DeleteFileA(p));
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url));               /* the entry goes even if its file vanished */
    EXPECT_ERR(0);
    CHECK(!uce_exists(url));
}
TEST(uce_delete_entry_without_file) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    const char *url = uce_url("dnf");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, URLHISTORY_CACHE_ENTRY, NULL, 0, NULL, NULL));
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
}
TEST(uce_delete_sticky_and_edited) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    static const DWORD types[] = { NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, COOKIE_CACHE_ENTRY, SPARSE_CACHE_ENTRY };
    for (size_t k = 0; k < sizeof types / sizeof *types; k++) {
        const char *url = uce_url("dtype"); char p[MAX_PATH]; DWORD err;
        CHECK(uce_make_ex(url, "txt", "x", 1, types[k], NULL, uce_zero_ft, uce_zero_ft, p, &err));
        SET_ERR(0xdeadbeef);
        CHECKF(uce_del(url), "type 0x%lx err %lu", types[k], GetLastError());
        SET_ERR(0xdeadbeef);
        CHECKF(!uce_del(url) && GetLastError() == ERROR_FILE_NOT_FOUND, "type 0x%lx second delete", types[k]);   /* really gone (SPARSE is hidden from Get) */
        /* EDITED entries keep their file [D CContainerProps::DeleteEntryFile (type & 8)] */
        if (types[k] & EDITED_CACHE_ENTRY) CHECK(uce_file_exists(p)); else CHECK(!uce_file_exists(p));
        DeleteFileA(p);
    }
}
TEST(uce_delete_stream_locked) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(UnlockUrlCacheEntryStream)); REQUIRE(U(ReadUrlCacheEntryStream));
    const char *url = uce_url("dstream"); char p[MAX_PATH];
    CHECK(mk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    CHECK(h != NULL);
    SET_ERR(0xdeadbeef);
    BOOL d = uce_del(url);
    DWORD e = GetLastError();
    CHECK(!d); EXPECT_EQ(e, ERROR_SHARING_VIOLATION);
    /* the open stream still reads the data */
    char rb[8]; DWORD n = 3;
    if (h) { CHECK(U(ReadUrlCacheEntryStream)(h, 0, rb, &n, 0)); CHECK(n == 3 && !memcmp(rb, "The", 3)); }
    CHECK(uce_exists(url));               /* still visible while locked [W10] */
    if (h) CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(!uce_exists(url));              /* pending delete done at unlock [W10] */
    CHECK(!uce_file_exists(p));
    CHECK(!uce_exists(url));
}
