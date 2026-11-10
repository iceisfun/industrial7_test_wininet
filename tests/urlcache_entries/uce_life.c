/* urlcache_entries / lifecycle: expired entries, stream edge cases, threads, shared local files, prefixed keys
 * (Cookie:, Visited:), external file handles, cross-process stream/set/commit, CreateUrlCacheEntryExW variants.
 * Decomp: RetrieveUrlCacheEntryStreamA@0x1a1e70 (NULL url/size -> 87, buffer with *size 0 -> 87, dwReserved -> 87,
 * failure unlocks the stream again), ReadUrlCacheEntryStream@0x1a17d0 (NULL -> 6), ReadUrlCacheEntryStreamHelper@0x1ab688
 * (seek when the offset differs from the cached position, ReadFile(*len), position += bytes read),
 * CCacheContainer::DeleteUrl@0x2b350, CCacheContainer::AddUrl@0x7bef0.
 * Tags: [D] decomp + VM, [W10] VM-observed, [K] knowledge + VM. */
#include "uce.h"

UDECL(BOOL, ReadUrlCacheEntryStreamEx, (HANDLE, DWORDLONG, LPVOID, LPDWORD));
UDECL(BOOL, CreateUrlCacheEntryExW, (LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, BOOL));

static const char g_lbody[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
#define LBODY_LEN ((DWORD)(sizeof g_lbody - 1))

static BOOL lmk(const char *url, char *path) {
    DWORD err;
    return uce_make_ex(url, "txt", g_lbody, LBODY_LEN, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, path, &err);
}
static HANDLE lstream(const char *url, BOOL random) {
    char ib[4096]; DWORD sz = sizeof ib;
    return U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, random, 0);
}

/* --------------------------------------------------------------- expiry is not enforced by the entry APIs */
TEST(uce_life_expired_entry_visible) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("lexp"); char p[MAX_PATH]; DWORD err;
    ULONGLONG past = uce_now() - 30 * UCE_DAY;
    CHECK(uce_make_ex(url, "txt", "old", 3, NORMAL_CACHE_ENTRY, NULL, uce_ft(past), uce_ft(past - UCE_DAY), p, &err));
    /* Get/Retrieve/Stream do not look at ExpireTime [K] */
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(uce_u64(i->ExpireTime), past); free(i); } else CHECK(0);
    char b[4096]; DWORD sz = sizeof b;
    SET_ERR(0xdeadbeef);
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0)); EXPECT_ERR(0);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    if (h) CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(uce_del(url));
}
TEST(uce_life_future_lastmod_kept) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("lfut"); DWORD err;
    ULONGLONG fut = uce_now() + 3650 * UCE_DAY;
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(fut), uce_ft(fut), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(uce_u64(i->LastModifiedTime), fut); EXPECT_EQ(uce_u64(i->ExpireTime), fut); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_access_time_is_commit_time) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("lacc"); DWORD err;
    ULONGLONG before = uce_now();
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    ULONGLONG after = uce_now();
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) {
        ULONGLONG a = uce_u64(i->LastAccessTime), s = uce_u64(i->LastSyncTime);
        /* both stamped with the commit time [W10]; allow 2 s of slack for clock granularity */
        CHECKF(a + 2 * UCE_SEC >= before && a <= after + 2 * UCE_SEC, "access %llx window %llx..%llx", a, before, after);
        CHECKF(s + 2 * UCE_SEC >= before && s <= after + 2 * UCE_SEC, "sync %llx", s);
        free(i);
    } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_replace_resets_times) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("lrep"); DWORD err;
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(111), uce_ft(222), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(333), uce_ft(444), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) {
        EXPECT_EQ(uce_u64(i->ExpireTime), 333); EXPECT_EQ(uce_u64(i->LastModifiedTime), 444);
        EXPECT_EQ(i->dwHitRate, 2);    /* old + 1 on replace [D AddUrl] */
        free(i);
    } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_replace_keeps_set_fields) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("lrks"); DWORD err;
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.dwHitRate = 50;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_HITRATE_FC));
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwHitRate, 51); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_replace_drops_header_and_ext) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("lrdh"); DWORD err;
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (BYTE *)"H: 1\r\n", 6, "htm", NULL));
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    /* a replace is a fresh record: no header, no extension [K] */
    if (i) { EXPECT_EQ(i->dwHeaderInfoSize, 0); EXPECT_EQ(i->lpHeaderInfo, NULL); EXPECT_EQ(i->lpszFileExtension, NULL); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- streams */
TEST(uce_life_stream_read_zero_len) {
    REQUIRE(U(ReadUrlCacheEntryStream));
    const char *url = uce_url("lsz"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, TRUE);
    CHECK(h != NULL);
    if (h) {
        char b[8]; DWORD n = 0;
        SET_ERR(0xdeadbeef);
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0)); EXPECT_ERR(0);
        EXPECT_EQ(n, 0);
        n = 4;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));
        CHECK(n == 4 && !memcmp(b, "0123", 4));
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_read_longer_than_file) {
    REQUIRE(U(ReadUrlCacheEntryStream));
    const char *url = uce_url("lsl"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    if (h) {
        static const DWORD offs[] = { 0, 10, LBODY_LEN - 1, LBODY_LEN, LBODY_LEN + 1, 100000 };
        for (size_t k = 0; k < sizeof offs / sizeof *offs; k++) {
            char b[512]; DWORD n = sizeof b;
            SET_ERR(0xdeadbeef);
            BOOL r = U(ReadUrlCacheEntryStream)(h, offs[k], b, &n, 0);
            DWORD want = offs[k] >= LBODY_LEN ? 0 : LBODY_LEN - offs[k];
            CHECKF(r, "off %lu err %lu", offs[k], GetLastError());
            CHECKF(n == want, "off %lu got %lu want %lu", offs[k], n, want);
            if (r && n && n == want) CHECK(!memcmp(b, g_lbody + offs[k], n));
        }
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_backwards_reads) {
    REQUIRE(U(ReadUrlCacheEntryStream));
    const char *url = uce_url("lsb"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    /* reads at decreasing offsets: the helper seeks whenever the offset differs from its cached position [D] */
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    if (h) {
        int bad = 0;
        for (int off = (int)LBODY_LEN - 3; off >= 0; off -= 3) {
            char b[3]; DWORD n = 3;
            if (!U(ReadUrlCacheEntryStream)(h, (DWORD)off, b, &n, 0) || n != 3 || memcmp(b, g_lbody + off, 3)) bad++;
        }
        CHECKF(bad == 0, "%d reads wrong", bad);
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_byte_by_byte) {
    REQUIRE(U(ReadUrlCacheEntryStream));
    const char *url = uce_url("lsbb"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    if (h) {
        char out[128]; DWORD total = 0;
        for (DWORD off = 0; off < 200; off++) {
            char c; DWORD n = 1;
            if (!U(ReadUrlCacheEntryStream)(h, off, &c, &n, 0)) { CHECKF(0, "off %lu err %lu", off, GetLastError()); break; }
            if (n == 0) break;
            out[total++] = c;
        }
        EXPECT_EQ(total, LBODY_LEN);
        CHECK(!memcmp(out, g_lbody, LBODY_LEN));
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_ex_offsets) {
    REQUIRE(UN(ReadUrlCacheEntryStreamEx));
    const char *url = uce_url("lsx"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, TRUE);
    CHECK(h != NULL);
    if (h) {
        static const DWORDLONG offs[] = { 0, 1, 61, 62, 0x100000000ULL, 0x7FFFFFFFFFFFULL };
        for (size_t k = 0; k < sizeof offs / sizeof *offs; k++) {
            char b[16]; DWORD n = 4;
            SET_ERR(0xdeadbeef);
            BOOL r = UN(ReadUrlCacheEntryStreamEx)(h, offs[k], b, &n);
            DWORD want = offs[k] >= LBODY_LEN ? 0 : (LBODY_LEN - offs[k] < 4 ? (DWORD)(LBODY_LEN - offs[k]) : 4);
            CHECKF(r && n == want, "off %llx r %d n %lu err %lu", (unsigned long long)offs[k], r, n, GetLastError());
            if (r && n) CHECK(!memcmp(b, g_lbody + offs[k], n));
        }
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_ex_null_handle) {
    REQUIRE(UN(ReadUrlCacheEntryStreamEx));
    char b[4]; DWORD n = 4;
    SET_ERR(0xdeadbeef);
    BOOL r = UN(ReadUrlCacheEntryStreamEx)(NULL, 0, b, &n);
    DWORD e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
}
TEST(uce_life_stream_reserved_param) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(RetrieveUrlCacheEntryStreamW));
    const char *url = uce_url("lsr"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 1);
    DWORD e = GetLastError();
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);   /* [D dwReserved != 0 -> 87] */
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    h = U(RetrieveUrlCacheEntryStreamW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)ib, &sz, TRUE, 2);
    e = GetLastError();
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    CHECK(uce_del(url));
}
TEST(uce_life_stream_read_reserved_ignored) {
    REQUIRE(U(ReadUrlCacheEntryStream));
    const char *url = uce_url("lsrr"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, TRUE);
    CHECK(h != NULL);
    if (h) {
        char b[4]; DWORD n = 4;
        SET_ERR(0xdeadbeef);
        /* ReadUrlCacheEntryStream never looks at its last argument [D ReadUrlCacheEntryStream@0x1a17d0] */
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0x12345)); EXPECT_ERR(0);
        CHECK(n == 4 && !memcmp(b, "0123", 4));
        SET_ERR(0xdeadbeef);
        BOOL r = U(UnlockUrlCacheEntryStream)(h, 7);
        DWORD e = GetLastError();
        CHECK(r); EXPECT_EQ(e, 0);           /* dwReserved ignored by the unlock too [W10] */
        if (!r) CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_entry_without_file) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lsnf");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    DWORD e = GetLastError();
    /* no file name -> the open of the empty path fails with 3 [W10] */
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_PATH_NOT_FOUND);
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_stream_file_deleted) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lsfd"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    CHECK(DeleteFileA(p));
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    DWORD e = GetLastError();
    /* the stream has to open the file: no file -> no stream [K] */
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);   /* [W10] */
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else t_note("entry gone after failed stream: err %lu", err);
    uce_del(url);
}
TEST(uce_life_stream_and_file_lock_together) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lsfl"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, h ? 2 : 1); free(i); } else CHECK(0);
    if (h) CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 1); free(i); } else CHECK(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_SHARING_VIOLATION);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    /* the pending delete fires on the last unlock [W10] */
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    CHECK(!uce_file_exists(p));
}
TEST(uce_life_stream_unlock_by_file_api) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("lsuf"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    /* UnlockUrlCacheEntryFile drops one lock on the entry, whoever took it [K] */
    SET_ERR(0xdeadbeef);
    BOOL r = U(UnlockUrlCacheEntryFileA)(url, 0);
    DWORD e = GetLastError();
    CHECK(r); EXPECT_EQ(e, 0);   /* [W10] */
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);   /* the stream's lock is gone [W10] */
    if (h) {
        char b[4]; DWORD n = 4;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));     /* the stream's file handle is still open */
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); }
    uce_del(url);
}
TEST(uce_life_stream_many_handles) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lsmh"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    HANDLE h[8]; int n = 0;
    for (int k = 0; k < 8; k++) { h[k] = lstream(url, k & 1); if (h[k]) n++; }
    EXPECT_EQ(n, 8);
    int distinct = 1;
    for (int a = 0; a < 8; a++) for (int b = a + 1; b < 8; b++) if (h[a] && h[a] == h[b]) distinct = 0;
    CHECK(distinct);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, (DWORD)n); EXPECT_EQ(i->dwHitRate, (DWORD)(1 + n)); free(i); } else CHECK(0);
    for (int k = 0; k < 8; k++) {
        if (!h[k]) continue;
        char c; DWORD m = 1;
        CHECK(U(ReadUrlCacheEntryStream)(h[k], (DWORD)k, &c, &m, 0) && m == 1 && c == g_lbody[k]);
    }
    for (int k = 7; k >= 0; k--) if (h[k]) CHECK(U(UnlockUrlCacheEntryStream)(h[k], 0));
    i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_stream_double_unlock) {
    REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("lsdu"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    if (h) {
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
        SET_ERR(0xdeadbeef);
        /* the handle is gone from the table: a second unlock and a read both give 6 [D UnlockUrlCacheEntryStreamHelper] */
        EXPECT_FAIL(!U(UnlockUrlCacheEntryStream)(h, 0), ERROR_INVALID_HANDLE);
        char b[4]; DWORD n = 4;
        SET_ERR(0xdeadbeef);
        EXPECT_FAIL(!U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0), ERROR_INVALID_HANDLE);
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_handle_not_win32) {
    REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = uce_url("lsnw"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE h = lstream(url, FALSE);
    CHECK(h != NULL);
    if (h) {
        /* stream handles are cache-table cookies, not kernel handles [D ReadUrlCacheEntryStreamHelper: HandleManager::Map] */
        DWORD fl = 0;
        BOOL k = GetHandleInformation(h, &fl);
        t_note("GetHandleInformation(stream handle %p) -> %d", h, k);
        CHECK(((ULONG_PTR)h & 1) == 1);
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_life_stream_file_size_changed) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lslf"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    CHECK(uce_write_file(p, "REWRITTEN", 9));   /* change the file (and its size) behind the cache's back */
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    DWORD e = GetLastError();
    /* the stream refuses a file whose size no longer matches the committed size [W10]
       (RetrieveUrlCacheEntryFile does not look: uce_more_info_after_file_grows_retrieve) */
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_INVALID_DATA);   /* [W10] */
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else t_note("entry after the refused stream: err %lu", err);
    uce_del(url);
    DeleteFileA(p);
}
TEST(uce_life_stream_sees_same_size_rewrite) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lsss"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    char nb[sizeof g_lbody]; for (DWORD k = 0; k < LBODY_LEN; k++) nb[k] = (char)('z' - (k % 26));
    CHECK(uce_write_file(p, nb, LBODY_LEN));
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    DWORD e = GetLastError();
    CHECK(h != NULL); EXPECT_EQ(e, 0);   /* only the size is compared [W10] */
    if (h) {
        char b[128]; DWORD n = sizeof b;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));
        CHECK(n == LBODY_LEN && !memcmp(b, nb, LBODY_LEN));    /* ReadFile on the live file [D] */
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    uce_del(url);
    DeleteFileA(p);
}

/* --------------------------------------------------------------- threads */
typedef struct { int idx; int ok; int fail_step; DWORD err; } thr_arg;
static DWORD WINAPI thr_entries(LPVOID pv) {
    thr_arg *a = (thr_arg *)pv;
    a->ok = 0;
    for (int k = 0; k < 8; k++) {
        char url[256]; snprintf(url, sizeof url, "http://%s/t%dk%d.txt", t_uniq_host("lthr"), a->idx, k);
        t_cache_track(url);
        char p[MAX_PATH], body[32]; int bl = snprintf(body, sizeof body, "thread %d item %d", a->idx, k);
        if (!U(CreateUrlCacheEntryA)(url, (DWORD)bl, "txt", p, 0)) { a->fail_step = 1; a->err = GetLastError(); return 1; }
        if (!uce_write_file(p, body, (DWORD)bl)) { a->fail_step = 2; return 1; }
        if (!U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL)) { a->fail_step = 3; a->err = GetLastError(); return 1; }
        char b[4096]; DWORD sz = sizeof b;
        if (!U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0)) { a->fail_step = 4; a->err = GetLastError(); return 1; }
        char rb[64]; int n = uce_read_file(((INTERNET_CACHE_ENTRY_INFOA *)b)->lpszLocalFileName, rb, sizeof rb);
        U(UnlockUrlCacheEntryFileA)(url, 0);
        if (n != bl || memcmp(rb, body, n)) { a->fail_step = 5; return 1; }
        if (!U(DeleteUrlCacheEntryA)(url)) { a->fail_step = 6; a->err = GetLastError(); return 1; }
        a->ok++;
    }
    return 0;
}
TEST(uce_life_threads_independent_entries) {
    REQUIRE(U(CommitUrlCacheEntryA));
    HANDLE th[4]; thr_arg args[4];
    for (int k = 0; k < 4; k++) { memset(&args[k], 0, sizeof args[k]); args[k].idx = k; th[k] = CreateThread(NULL, 0, thr_entries, &args[k], 0, NULL); }
    DWORD w = WaitForMultipleObjects(4, th, TRUE, 30000);
    CHECK(w != WAIT_TIMEOUT);
    for (int k = 0; k < 4; k++) {
        CHECKF(args[k].ok == 8, "thread %d ok %d step %d err %lu", k, args[k].ok, args[k].fail_step, args[k].err);
        CloseHandle(th[k]);
    }
}
typedef struct { const char *url; int ok; } thr_lock_arg;
static DWORD WINAPI thr_lock(LPVOID pv) {
    thr_lock_arg *a = (thr_lock_arg *)pv;
    for (int k = 0; k < 25; k++) {
        char b[4096]; DWORD sz = sizeof b;
        if (!U(RetrieveUrlCacheEntryFileA)(a->url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0)) continue;
        if (U(UnlockUrlCacheEntryFileA)(a->url, 0)) a->ok++;
    }
    return 0;
}
TEST(uce_life_threads_shared_locks) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("lthl"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    HANDLE th[4]; thr_lock_arg args[4];
    for (int k = 0; k < 4; k++) { args[k].url = url; args[k].ok = 0; th[k] = CreateThread(NULL, 0, thr_lock, &args[k], 0, NULL); }
    CHECK(WaitForMultipleObjects(4, th, TRUE, 30000) != WAIT_TIMEOUT);
    int total = 0;
    for (int k = 0; k < 4; k++) { total += args[k].ok; CloseHandle(th[k]); }
    EXPECT_EQ(total, 100);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    /* balanced lock/unlock from four threads: no lock left, every retrieval counted [W10 hit counting] */
    if (i) { EXPECT_EQ(i->dwUseCount, 0); EXPECT_EQ(i->dwHitRate, 101); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- two entries, one file */
TEST(uce_life_two_urls_one_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *u1 = uce_url("l2u1"), *u2 = uce_url("l2u2"); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(u1, "txt", "shared", 6, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(u2, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    DWORD e = GetLastError();
    CHECK(r); EXPECT_EQ(e, 0);      /* no ownership check on the file [W10] */
    if (r) {
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(u2, NULL, &err);
        if (i) { CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p)); EXPECT_EQ(i->dwSizeLow, 6); free(i); } else CHECK(0);
        CHECK(uce_del(u1));
        /* the file is deleted with the first entry; the second keeps a dangling name [W10] */
        CHECK(!uce_file_exists(p));
        INTERNET_CACHE_ENTRY_INFOA *j = uce_info(u2, NULL, &err);
        if (j) { CHECK(j->lpszLocalFileName && !_stricmp(j->lpszLocalFileName, p)); free(j); } else CHECK(0);
        CHECK(uce_del(u2));
    } else CHECK(uce_del(u1));
    DeleteFileA(p);
}

/* --------------------------------------------------------------- external handles on the local file */
TEST(uce_life_delete_with_file_open) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    const char *url = uce_url("ldfo"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE f = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    SET_ERR(0xdeadbeef);
    BOOL r = uce_del(url);
    DWORD e = GetLastError();
    /* the index entry is what DeleteUrl checks (lock count); an open file handle is not a cache lock [K] */
    CHECK(r); EXPECT_EQ(e, 0);      /* [W10] the entry goes; the file delete fails quietly */
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    if (!r) uce_del(url);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    t_note("file after delete + close: %s", uce_file_exists(p) ? "still there" : "gone");
    DeleteFileA(p);
}
TEST(uce_life_retrieve_with_file_open_exclusive) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("lrfe"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    HANDLE f = CreateFileA(p, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    char b[4096]; DWORD sz = sizeof b;
    SET_ERR(0xdeadbeef);
    /* Retrieve does not open the file [W10: stale paths are returned without a check] */
    BOOL r = U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0);
    CHECK(r); EXPECT_ERR(0);
    if (r) CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    sz = sizeof b;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, FALSE, 0);
    DWORD e = GetLastError();
    /* the stream must open the file, which is held without sharing [K] */
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_SHARING_VIOLATION);   /* [W10] */
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- prefixed keys (other containers) */
TEST(uce_life_visited_prefix_entry) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char key[512]; snprintf(key, sizeof key, "Visited: i7user@http://%s/page.htm", t_uniq_host("lvis"));
    t_cache_track(key);
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(key, NULL, uce_zero_ft, uce_zero_ft, URLHISTORY_CACHE_ENTRY, NULL, 0, NULL, NULL);
    DWORD e = GetLastError();
    t_note("Visited: commit -> %d err %lu", r, e);
    if (!r) { t_skip("history container not available (err %lu)", e); return; }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(key, NULL, &err);
    if (i) {
        EXPECT_STR(i->lpszSourceUrlName, key);
        /* the history container adds no NORMAL bit: the type is exactly what was committed [W10] */
        EXPECT_EQ(i->CacheEntryType, URLHISTORY_CACHE_ENTRY);
        free(i);
    } else CHECKF(0, "info err %lu", err);
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(key)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(key), ERROR_FILE_NOT_FOUND);
}
TEST(uce_life_cookie_prefix_entry) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char key[512]; snprintf(key, sizeof key, "Cookie:i7user@%s/", t_uniq_host("lcook"));
    t_cache_track(key);
    char p[MAX_PATH] = "";
    SET_ERR(0xdeadbeef);
    BOOL c = U(CreateUrlCacheEntryA)(key, 0, "txt", p, 0);
    DWORD e = GetLastError();
    t_note("Cookie: create -> %d err %lu path %s", c, e, p);
    if (!c) { t_skip("cookie container not available (err %lu)", e); return; }
    CHECK(strstr(p, "\\INetCookies\\") != NULL);     /* cookie container [W10] */
    CHECK(uce_write_file(p, "name\nvalue\n", 11));
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(key, p, uce_zero_ft, uce_zero_ft, COOKIE_CACHE_ENTRY, NULL, 0, "txt", NULL);
    e = GetLastError();
    t_note("Cookie: commit -> %d err %lu", r, e);
    if (!r) { DeleteFileA(p); t_skip("cookie commit refused (err %lu)", e); return; }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(key, NULL, &err);
    if (i) {
        EXPECT_STR(i->lpszSourceUrlName, key);
        EXPECT_EQ(i->CacheEntryType, COOKIE_CACHE_ENTRY);   /* [W10] */
        CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p));
        free(i);
    } else CHECKF(0, "info err %lu", err);
    CHECK(uce_del(key));
    CHECK(!uce_file_exists(p));   /* [W10] */
    DeleteFileA(p);
}
TEST(uce_life_prefix_not_confused_with_http) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* an http entry and a Visited: entry that embeds the same URL are different keys [K] */
    const char *url = uce_url("lpfx");
    char key[512]; snprintf(key, sizeof key, "Visited: i7user@%s", url);
    t_cache_track(key);
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    SET_ERR(0xdeadbeef);
    BOOL v = uce_exists(key);
    DWORD e = GetLastError();
    CHECK(!v); EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- CreateUrlCacheEntryExW variants */
TEST(uce_life_create_exw_preserve_variants) {
    REQUIRE(UN(CreateUrlCacheEntryExW));
    /* the extension argument wins over the URL's; NULL keeps no extension and cuts the last dot part [W10] */
    static const struct { const char *leaf; const WCHAR *ext; BOOL preserve; const WCHAR *want; } rows[] = {
        { "hint.dat", L"bin", FALSE, L"hint[1].bin" }, { "hint.dat", L"bin", TRUE, L"hint[1].bin" },
        { "noext", L"txt", TRUE, L"noext[1].txt" }, { "a.b.c", NULL, TRUE, L"a.b[1]" },
    };
    for (size_t k = 0; k < sizeof rows / sizeof *rows; k++) {
        char url[512]; snprintf(url, sizeof url, "http://%s/%s", t_uniq_host("lcex"), rows[k].leaf);
        WCHAR p[MAX_PATH] = L"";
        SET_ERR(0xdeadbeef);
        BOOL r = UN(CreateUrlCacheEntryExW)(uce_w(url), 0, rows[k].ext, p, 0, rows[k].preserve);
        CHECKF(r, "row %u err %lu", (unsigned)k, GetLastError());
        if (!r) continue;
        EXPECT_ERR(0);
        CHECK(uce_file_existsW(p));
        const WCHAR *leaf = wcsrchr(p, L'\\'); leaf = leaf ? leaf + 1 : p;
        CHECKF(!lstrcmpiW(leaf, rows[k].want), "row %u got %s", (unsigned)k, uce_a(leaf));
        t_note("ExW(%s, ext %s, preserve %d) -> %s", rows[k].leaf, rows[k].ext ? uce_a(rows[k].ext) : "NULL", rows[k].preserve, uce_a(leaf));
        DeleteFileW(p);
    }
}
TEST(uce_life_create_exw_reserved) {
    REQUIRE(UN(CreateUrlCacheEntryExW));
    const char *url = uce_url("lcxr");
    WCHAR p[MAX_PATH] = L"";
    SET_ERR(0xdeadbeef);
    BOOL r = UN(CreateUrlCacheEntryExW)(uce_w(url), 0, L"txt", p, 0x55, FALSE);
    DWORD e = GetLastError();
    /* dwReserved is not validated (as for CreateUrlCacheEntryA/W) [D CreateUrlCacheEntryExW] */
    CHECK(r); EXPECT_EQ(e, 0);
    if (r) DeleteFileW(p);
}

/* --------------------------------------------------------------- unlock W */
TEST(uce_life_unlock_w_variants) {
    REQUIRE(U(UnlockUrlCacheEntryFileW)); REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("luw"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileW)(NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileW)(uce_w(url), 1), ERROR_INVALID_PARAMETER);
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    SET_ERR(0xdeadbeef);
    CHECK(U(UnlockUrlCacheEntryFileW)(uce_w(url), 0)); EXPECT_ERR(0);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(UnlockUrlCacheEntryFileW)(uce_w(uce_url("luwmiss")), 0), ERROR_FILE_NOT_FOUND);
    CHECK(uce_del(url));
}
TEST(uce_life_unlock_by_other_spelling) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    /* the lock is on the normalised key: unlocking through ":80" spelling releases it [D ConvertCacheUrlCharToInternal] */
    const char *host = t_uniq_host("luos");
    char url[256], alt[256];
    snprintf(url, sizeof url, "http://%s/x.txt", host); snprintf(alt, sizeof alt, "http://%s:80/x.txt", host);
    t_cache_track(url);
    char p[MAX_PATH];
    CHECK(lmk(url, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(alt, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    EXPECT_STR(((INTERNET_CACHE_ENTRY_INFOA *)b)->lpszSourceUrlName, url);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryA)(alt), ERROR_SHARING_VIOLATION);
    CHECK(U(UnlockUrlCacheEntryFileA)(alt, 0));
    /* the failed delete was remembered and fires on the unlock [W10] */
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
}

/* --------------------------------------------------------------- pending delete details */
TEST(uce_life_pending_delete_blocks_recommit) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("lpdr"); char p[MAX_PATH], p2[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_SHARING_VIOLATION);
    /* replacing a locked entry fails with 32 [D AddUrl], pending delete or not */
    BOOL r = uce_make_ex(url, "txt", "new", 3, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p2, &err);
    CHECK(!r); EXPECT_EQ(err, ERROR_SHARING_VIOLATION);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    /* afterwards the key is free again */
    CHECK(uce_make_ex(url, "txt", "new", 3, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p2, &err));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwSizeLow, 3); EXPECT_EQ(i->dwHitRate, 1); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_pending_delete_set_still_works) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("lpds"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_SHARING_VIOLATION);
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.dwHitRate = 77;
    SET_ERR(0xdeadbeef);
    BOOL r = U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_HITRATE_FC);
    CHECK(r); EXPECT_ERR(0);   /* [W10] */
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwHitRate, 77); EXPECT_EQ(i->dwUseCount, 1); free(i); } else CHECK(0);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
}
TEST(uce_life_pending_delete_second_retrieve) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("lpd2"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_SHARING_VIOLATION);
    sz = sizeof b;
    SET_ERR(0xdeadbeef);
    BOOL r = U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0);
    DWORD e = GetLastError();
    CHECK(r); EXPECT_EQ(e, 0);   /* a pending delete does not hide the entry [W10] */
    int locks = 1 + (r ? 1 : 0);
    while (locks-- > 0) CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    CHECK(!uce_file_exists(p));
}

/* --------------------------------------------------------------- across processes: streams and Set */
CHILD(uce_l_stream) {
    if (argc < 3) return 99;
    char ib[4096]; DWORD sz = sizeof ib;
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(argv[1], (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, TRUE, 0);
    if (!h) return 60;
    char b[256]; DWORD n = sizeof b;
    BOOL r = U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0);
    U(UnlockUrlCacheEntryStream)(h, 0);
    if (!r) return 61;
    return (n == strlen(argv[2]) && !memcmp(b, argv[2], n)) ? 0 : 62;
}
CHILD(uce_l_set_hitrate) {
    if (argc < 3) return 99;
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.dwHitRate = (DWORD)atoi(argv[2]);
    return U(SetUrlCacheEntryInfoA)(argv[1], &n, CACHE_ENTRY_HITRATE_FC) ? 0 : 70 + (int)(GetLastError() & 0xff);
}
CHILD(uce_l_stream_hold) {
    if (argc < 2) return 99;
    return lstream(argv[1], FALSE) ? 0 : 80;     /* exit without unlocking */
}
CHILD(uce_l_info_use) {
    if (argc < 2) return 99;
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(argv[1], NULL, &e);
    if (!i) return 90;
    int r = (int)i->dwUseCount; free(i); return r;
}
static char g_largs[1024];
static const char *largs(const char *a, const char *b) { snprintf(g_largs, sizeof g_largs, "\"%s\" \"%s\"", a, b ? b : ""); return g_largs; }

TEST(uce_life_xproc_child_streams) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lxs"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    { DWORD rc = t_run_child("uce_l_stream", largs(url, g_lbody), 20000); EXPECT_EQ(rc, 0); }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); EXPECT_EQ(i->dwHitRate, 2); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_life_xproc_child_sets_info) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("lxset"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    { DWORD rc = t_run_child("uce_l_set_hitrate", largs(url, "4242"), 20000); EXPECT_EQ(rc, 0); }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwHitRate, 4242); free(i); } else CHECK(0);
    CHECK(uce_del(url));
    { DWORD rc = t_run_child("uce_l_set_hitrate", largs(url, "1"), 20000); EXPECT_EQ(rc, 70 + ERROR_FILE_NOT_FOUND); }
}
TEST(uce_life_xproc_child_sees_parent_lock) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("lxlk"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    { DWORD rc = t_run_child("uce_l_info_use", largs(url, NULL), 20000); EXPECT_EQ(rc, 1); }
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    { DWORD rc = t_run_child("uce_l_info_use", largs(url, NULL), 20000); EXPECT_EQ(rc, 0); }
    CHECK(uce_del(url));
}
TEST(uce_life_xproc_child_stream_released_at_exit) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("lxsr"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    { DWORD rc = t_run_child("uce_l_stream_hold", largs(url, NULL), 20000); EXPECT_EQ(rc, 0); }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    /* like a file lock, a dead process' stream lock does not pin the entry [W10 for file locks] */
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);   /* [W10] */
    SET_ERR(0xdeadbeef);
    BOOL r = uce_del(url);
    DWORD e = GetLastError();
    CHECK(r); EXPECT_EQ(e, 0);
    if (!r) t_note("delete after dead stream holder: err %lu", e);
}

/* --------------------------------------------------------------- file allocation across URLs and processes */
TEST(uce_life_commit_file_of_other_url) {
    REQUIRE(U(CreateUrlCacheEntryA));
    /* the file is checked for existence and container membership only, not for the URL it was made for [D VerifyCacheEntryPath] */
    const char *u1 = uce_url("lfo1"), *u2 = uce_url("lfo2"); char p[MAX_PATH]; DWORD err;
    CHECK(U(CreateUrlCacheEntryA)(u1, 0, "txt", p, 0));
    CHECK(uce_write_file(p, "other", 5));
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryA)(u2, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL);
    CHECK(r); EXPECT_ERR(0);
    if (!r) { DeleteFileA(p); return; }
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(u1), ERROR_FILE_NOT_FOUND);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(u2, NULL, &err);
    if (i) { CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p)); EXPECT_EQ(i->dwSizeLow, 5); free(i); } else CHECK(0);
    CHECK(uce_del(u2));
    CHECK(!uce_file_exists(p));
}
CHILD(uce_l_create) {
    if (argc < 2) return 99;
    char p[MAX_PATH];
    if (!U(CreateUrlCacheEntryA)(argv[1], 0, "txt", p, 0)) return 1;
    printf("UCEPATH %s\n", p);    /* the parent only checks the exit code; the path goes to the log */
    return uce_file_exists(p) ? 0 : 2;
}
TEST(uce_life_create_unique_across_processes) {
    REQUIRE(U(CreateUrlCacheEntryA));
    const char *url = uce_url("lcxp"); char p1[MAX_PATH], p2[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p1, 0));
    { DWORD rc = t_run_child("uce_l_create", largs(url, NULL), 20000); EXPECT_EQ(rc, 0); }
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p2, 0));
    /* the child's file still exists, so the parent's second name skips it: [1], [2] taken -> a third, distinct name [D CreateUniqueCacheFile] */
    CHECK(_stricmp(p1, p2) != 0);
    { const char *lf = strrchr(p2, '\\'); CHECKF(lf && strncmp(lf + 1, "lcxp[", 5) == 0, "second parent name %s", p2); }   /* suffix varies: [3] or [2] seen [W10] */
    char d1[MAX_PATH], d2[MAX_PATH]; uce_dirname(p1, d1); uce_dirname(p2, d2);
    t_note("parent paths %s / %s", p1, p2);
    DeleteFileA(p1); DeleteFileA(p2);
    /* the child's file is left uncommitted in the container; remove it by pattern in every container subdirectory */
    char root[MAX_PATH]; strcpy(root, d1); root[strlen(root) - 1] = 0; { char *s = strrchr(root, '\\'); if (s) s[1] = 0; }
    char dpat[MAX_PATH]; snprintf(dpat, sizeof dpat, "%s*", root);
    WIN32_FIND_DATAA dd, fd; HANDLE dh = FindFirstFileA(dpat, &dd);
    int left = 0;
    if (dh != INVALID_HANDLE_VALUE) {
        do {
            if (!(dd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || dd.cFileName[0] == '.') continue;
            char pat[MAX_PATH]; snprintf(pat, sizeof pat, "%s%s\\lcxp*.txt", root, dd.cFileName);
            HANDLE fh = FindFirstFileA(pat, &fd);
            if (fh == INVALID_HANDLE_VALUE) continue;
            do { char q[MAX_PATH]; snprintf(q, sizeof q, "%s%s\\%s", root, dd.cFileName, fd.cFileName); if (DeleteFileA(q)) left++; } while (FindNextFileA(fh, &fd));
            FindClose(fh);
        } while (FindNextFileA(dh, &dd));
        FindClose(dh);
    }
    t_note("removed %d leftover child file(s) from %s", left, d1);
}

/* --------------------------------------------------------------- hit counting of failures, other containers, Ex flags */
TEST(uce_life_info_122_counts_no_hit) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("li122"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    for (int k = 0; k < 5; k++) {
        char b[16]; DWORD sz = sizeof b;
        SET_ERR(0xdeadbeef);
        EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz), ERROR_INSUFFICIENT_BUFFER);
    }
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwHitRate, 1); EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);   /* Get never counts [W10] */
    CHECK(uce_del(url));
}
TEST(uce_life_stream_122_hit_count) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("ls122"); char p[MAX_PATH]; DWORD err;
    CHECK(lmk(url, p));
    char b[16]; DWORD sz = sizeof b;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, FALSE, 0);
    DWORD e = GetLastError();
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_INSUFFICIENT_BUFFER);
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); EXPECT_EQ(i->dwHitRate, 2); free(i); } else CHECK(0);   /* counted, like the file retrieve [W10] */
    CHECK(uce_del(url));
}
TEST(uce_life_visited_entry_w_and_set) {
    REQUIRE(U(CommitUrlCacheEntryW)); REQUIRE(U(SetUrlCacheEntryInfoW));
    char key[512]; snprintf(key, sizeof key, "Visited: i7user@http://%s/w.htm", t_uniq_host("lvw"));
    t_cache_track(key);
    ULONGLONG t = 0x01DA000000000000ULL;
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryW)(uce_w(key), NULL, uce_ft(t), uce_ft(t), URLHISTORY_CACHE_ENTRY, NULL, 0, NULL, NULL);
    CHECK(r); EXPECT_ERR(0);
    if (!r) return;
    INTERNET_CACHE_ENTRY_INFOW n; memset(&n, 0, sizeof n); n.dwHitRate = 5;
    CHECK(U(SetUrlCacheEntryInfoW)(uce_w(key), &n, CACHE_ENTRY_HITRATE_FC));
    DWORD err; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(key), NULL, &err);
    if (i) {
        CHECK(i->lpszSourceUrlName && !lstrcmpW(i->lpszSourceUrlName, uce_w(key)));
        EXPECT_EQ(i->dwHitRate, 5);
        EXPECT_EQ(uce_u64(i->ExpireTime), t);
        EXPECT_EQ(i->lpszLocalFileName, NULL);
        EXPECT_EQ(i->CacheEntryType, URLHISTORY_CACHE_ENTRY);   /* [W10] */
        free(i);
    } else CHECKF(0, "info err %lu", err);
    CHECK(U(DeleteUrlCacheEntryW)(uce_w(key)));
}
TEST(uce_life_cookie_entry_retrieve) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    char key[512]; snprintf(key, sizeof key, "Cookie:i7user@%s/r/", t_uniq_host("lckr"));
    t_cache_track(key);
    char p[MAX_PATH] = "";
    CHECK(U(CreateUrlCacheEntryA)(key, 0, "txt", p, 0));
    if (!*p) return;
    CHECK(uce_write_file(p, "n\nv\n", 4));
    BOOL r = U(CommitUrlCacheEntryA)(key, p, uce_zero_ft, uce_zero_ft, COOKIE_CACHE_ENTRY, NULL, 0, "txt", NULL);
    CHECK(r);
    if (!r) { DeleteFileA(p); return; }
    char b[4096]; DWORD sz = sizeof b;
    SET_ERR(0xdeadbeef);
    BOOL rr = U(RetrieveUrlCacheEntryFileA)(key, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0);
    DWORD e = GetLastError();
    CHECK(rr); EXPECT_EQ(e, 0);   /* [W10] */
    if (rr) {
        EXPECT_EQ(((INTERNET_CACHE_ENTRY_INFOA *)b)->dwSizeLow, 4);
        CHECK(U(UnlockUrlCacheEntryFileA)(key, 0));
    }
    CHECK(uce_del(key));
    DeleteFileA(p);
}
TEST(uce_life_commit_w_original_url) {
    REQUIRE(U(CommitUrlCacheEntryW));
    const char *url = uce_url("lwo"), *orig = uce_url("lwosrc");
    SET_ERR(0xdeadbeef);
    BOOL r = U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, uce_w(orig));
    CHECK(r); EXPECT_ERR(0);
    CHECK(!uce_exists(orig));     /* metadata only [K, as for the A commit] */
    if (r) CHECK(uce_del(url));
    SET_ERR(0xdeadbeef);
    /* a malformed original URL fails the commit [D CommitUrlCacheEntryW converts it like the key] */
    BOOL b = U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, L"https://");
    DWORD e = GetLastError();
    CHECK(!b); EXPECT_EQ(e, ERROR_INTERNET_INVALID_URL);
    if (b) uce_del(url); else CHECK(!uce_exists(url));
}
TEST(uce_life_info_ex_flags_table) {
    REQUIRE(U(GetUrlCacheEntryInfoExA));
    const char *url = uce_url("lexf"); char p[MAX_PATH];
    CHECK(lmk(url, p));
    DWORD need = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &need);
    static const DWORD flags[] = { 0x1, 0x2, 0x4, 0x10, 0x100, 0x800, 0x2000, 0x10000, 0x80000000 };
    for (size_t k = 0; k < sizeof flags / sizeof *flags; k++) {
        char b[4096]; DWORD sz = sizeof b;
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, NULL, NULL, NULL, flags[k]);
        DWORD e = GetLastError();
        t_note("ExA flags 0x%lx -> %d err %lu size %lu (plain %lu)", flags[k], r, e, sz, need);
        /* unknown flags are ignored: same result as the plain call; 0x800 left *size as passed in boot 2 (note only) [W10] */
        if (flags[k] != 0x800) CHECKF(r && e == 0 && sz == need, "flags 0x%lx r %d e %lu sz %lu", flags[k], r, e, sz);
        else CHECKF(r && e == 0, "flags 0x800 r %d e %lu", r, e);
        if (r && ((INTERNET_CACHE_ENTRY_INFOA *)b)->dwUseCount) U(UnlockUrlCacheEntryFileA)(url, 0);
    }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); EXPECT_EQ(i->dwHitRate, 1); free(i); } else CHECK(0);   /* Ex never locks or counts [W10] */
    uce_del(url);
}
