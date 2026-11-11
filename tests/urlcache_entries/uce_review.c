/* urlcache_entries / review pass 4: EDITED entries keep their file on delete, the stream's file share mode,
 * stream-handle cookies vs the find-handle table, pending deletes over several streams, SPARSE via Set,
 * large files, URL leaves that need sanitising, hit-rate wrap.
 * Decomp: CContainerProps::DeleteEntryFile@0x79c20 ((type & 8) -> the file is not touched), DeleteCacheFile@0x1ddc4,
 * RetrieveUrlCacheEntryStreamHelper@0x80cf0 (CreateFileW(GENERIC_READ, FILE_SHARE_READ [| FILE_SHARE_DELETE when cache
 * file renaming is on], OPEN_EXISTING); GetFileSizeEx != committed size -> 0x8007000d),
 * CCacheClientHandleManager::Validate@0x35ebc (odd cookie, index < count, type mask; else 0x80070006),
 * Map@0x35dc4 (stream ops use mask 8), Free@0x35cf0 (FindCloseUrlCacheHelper uses mask 7),
 * UnlockUrlCacheEntryStreamHelper@0x6f8b0, ReadUrlCacheEntryStream@0x1a17d0 (offset truncated to 32 bits).
 * Tags: [D] decomp + VM, [W10] VM-observed, [K] knowledge + VM. VM_TIMEOUT: 120 */
#include "uce.h"

UDECL(BOOL, ReadUrlCacheEntryStreamEx, (HANDLE, DWORDLONG, LPVOID, LPDWORD));

static const char g_rbody[] = "review-body-0123456789";
#define RBODY_LEN ((DWORD)(sizeof g_rbody - 1))

static BOOL rmk(const char *url, DWORD type, char *path) {
    DWORD err;
    return uce_make_ex(url, "txt", g_rbody, RBODY_LEN, type, NULL, uce_zero_ft, uce_zero_ft, path, &err);
}
static HANDLE rstream(const char *url, DWORD *err) {
    char ib[4096]; DWORD sz = sizeof ib;
    SET_ERR(0xdeadbeef);
    HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)ib, &sz, FALSE, 0);
    if (err) *err = GetLastError();
    return h;
}
static DWORD ruse(const char *url) {
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (!i) return 0xFFFFFFFF;
    DWORD u = i->dwUseCount; free(i); return u;
}

/* --------------------------------------------------------------- EDITED entries: delete leaves the file */
TEST(uce_rv_delete_edited_keeps_container_file) {
    REQUIRE(U(DeleteUrlCacheEntryA));
    const char *url = uce_url("rvdek"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, p));
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    /* DeleteEntryFile returns before touching the file when the entry type has EDITED (8) [D] */
    CHECKF(uce_file_exists(p), "edited file %s was deleted", p);
    char b[64]; int n = uce_read_file(p, b, sizeof b);
    CHECK(n == (int)RBODY_LEN && !memcmp(b, g_rbody, RBODY_LEN));
    DeleteFileA(p);
}
TEST(uce_rv_delete_edited_keeps_outside_file) {
    REQUIRE(U(CommitUrlCacheEntryA));
    const char *url = uce_url("rvdeo");
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "rv_edited_out.txt");
    CHECK(uce_write_file(p, "keep me", 7));
    BOOL r = U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY, NULL, 0, "txt", NULL);
    CHECK(r);
    if (r) {
        SET_ERR(0xdeadbeef);
        CHECK(uce_del(url)); EXPECT_ERR(0);
        CHECK(uce_file_exists(p));     /* a file the cache does not own is never deleted [D DeleteEntryFile] */
    }
    DeleteFileA(p);
}
TEST(uce_rv_delete_edited_w_keeps_file) {
    REQUIRE(U(DeleteUrlCacheEntryW)); REQUIRE(U(CommitUrlCacheEntryW));
    const char *url = uce_url("rvdew"); char p[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", p, 0));
    CHECK(uce_write_file(p, "w", 1));
    BOOL r = U(CommitUrlCacheEntryW)(uce_w(url), uce_w(p), uce_zero_ft, uce_zero_ft, EDITED_CACHE_ENTRY, NULL, 0, L"txt", NULL);
    CHECK(r);
    if (r) { SET_ERR(0xdeadbeef); CHECK(U(DeleteUrlCacheEntryW)(uce_w(url))); EXPECT_ERR(0); CHECK(uce_file_exists(p)); }
    DeleteFileA(p);
}
TEST(uce_rv_set_edited_then_delete_keeps_file) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("rvsed"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.CacheEntryType = NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_ATTRIBUTE_FC));
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    /* the type stored at delete time decides: EDITED set by Set also keeps the file [D DeleteEntryFile] */
    CHECK(uce_file_exists(p));
    DeleteFileA(p);
}
/* --------------------------------------------------------------- the stream's own file handle */
TEST(uce_rv_stream_with_shared_reader) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvssr"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    HANDLE f = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    DWORD e; HANDLE h = rstream(url, &e);
    /* GENERIC_READ + FILE_SHARE_READ on both sides is compatible [D CreateFileW(0x80000000, 1|5)] */
    CHECKF(h != NULL, "err %lu", e);
    if (h) {
        char b[64]; DWORD n = sizeof b;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));
        CHECK(n == RBODY_LEN && !memcmp(b, g_rbody, n));
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    CHECK(uce_del(url));
}
TEST(uce_rv_stream_with_writer_open) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvswo"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    HANDLE f = CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(f != INVALID_HANDLE_VALUE);
    DWORD e; HANDLE h = rstream(url, &e);
    /* the stream does not share write access, so an open writer makes its CreateFileW fail [D] */
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_SHARING_VIOLATION);
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    EXPECT_EQ(ruse(url), 0);          /* the failure path unlocks again [D] */
    CHECK(uce_del(url));
}
TEST(uce_rv_open_stream_blocks_writers) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvsbw"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE h = rstream(url, &e);
    CHECKF(h != NULL, "err %lu", e);
    if (h) {
        SET_ERR(0xdeadbeef);
        HANDLE w = CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        DWORD we = GetLastError();
        CHECK(w == INVALID_HANDLE_VALUE); EXPECT_EQ(we, ERROR_SHARING_VIOLATION);   /* [D share mode READ (|DELETE)] */
        if (w != INVALID_HANDLE_VALUE) CloseHandle(w);
        HANDLE r = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(r != INVALID_HANDLE_VALUE);   /* other readers are fine */
        if (r != INVALID_HANDLE_VALUE) CloseHandle(r);
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
        /* the handle is closed by the unlock: writers can open the file again */
        w = CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(w != INVALID_HANDLE_VALUE);
        if (w != INVALID_HANDLE_VALUE) CloseHandle(w);
    }
    CHECK(uce_del(url));
}
TEST(uce_rv_open_stream_delete_file) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvsdf"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE h = rstream(url, &e);
    CHECKF(h != NULL, "err %lu", e);
    if (h) {
        /* FILE_SHARE_DELETE is only added when cache file renaming is enabled [D]: note what this machine does */
        SET_ERR(0xdeadbeef);
        BOOL d = DeleteFileA(p);
        t_note("DeleteFile under an open stream -> %d err %lu", d, GetLastError());
        char b[8]; DWORD n = 4;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));   /* the open handle keeps reading either way */
        CHECK(n == 4 && !memcmp(b, g_rbody, 4));
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    uce_del(url);
    DeleteFileA(p);
}

/* --------------------------------------------------------------- stream cookies and the handle table */
TEST(uce_rv_stream_bogus_cookies) {
    REQUIRE(U(ReadUrlCacheEntryStream)); REQUIRE(U(UnlockUrlCacheEntryStream));
    /* Validate never dereferences the value: even values, odd values past the table and -1 are all 6 [D] */
    static const ULONG_PTR vals[] = { 2, 4, 0x10, 0xFFFE, 0x1FFFFF, 0x7FFFFFF1, (ULONG_PTR)-1, (ULONG_PTR)-3 };
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) {
        HANDLE h = (HANDLE)vals[k];
        char b[4]; DWORD n = 4;
        SET_ERR(0xdeadbeef);
        BOOL r = U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INVALID_HANDLE, "read %p r %d e %lu", h, r, e);
        SET_ERR(0xdeadbeef);
        r = U(UnlockUrlCacheEntryStream)(h, 0);
        e = GetLastError();
        CHECKF(!r && e == ERROR_INVALID_HANDLE, "unlock %p r %d e %lu", h, r, e);
        if (UN(ReadUrlCacheEntryStreamEx)) {
            n = 4; SET_ERR(0xdeadbeef);
            r = UN(ReadUrlCacheEntryStreamEx)(h, 0, b, &n);
            e = GetLastError();
            CHECKF(!r && e == ERROR_INVALID_HANDLE, "readex %p r %d e %lu", h, r, e);
        }
    }
}
/* open a URL cache enumeration that is known to have at least one entry; NULL if none */
static HANDLE rfind(void) {
    DWORD cap = 256 * 1024; char *b = (char *)malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz);
    if (!h && GetLastError() == ERROR_INSUFFICIENT_BUFFER && sz < 16 * 1024 * 1024) {
        free(b); cap = sz; b = (char *)malloc(cap);
        h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz);
    }
    free(b);
    return h;
}
TEST(uce_rv_find_handle_is_not_a_stream) {
    REQUIRE(U(FindFirstUrlCacheEntryA)); REQUIRE(U(FindCloseUrlCache));
    const char *url = uce_url("rvfh"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));     /* at least one entry to enumerate */
    HANDLE f = rfind();
    if (!f) { t_skip("FindFirstUrlCacheEntryA gave no handle (err %lu)", GetLastError()); uce_del(url); return; }
    /* find handles live in the same cookie table with another type mask: stream ops reject them [D Map mask 8] */
    char b[4]; DWORD n = 4;
    SET_ERR(0xdeadbeef);
    BOOL r = U(ReadUrlCacheEntryStream)(f, 0, b, &n, 0);
    DWORD e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    SET_ERR(0xdeadbeef);
    r = U(UnlockUrlCacheEntryStream)(f, 0);
    e = GetLastError();
    CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
    CHECK(((ULONG_PTR)f & 1) == 1);     /* same odd-cookie scheme [D Validate] */
    SET_ERR(0xdeadbeef);
    CHECK(U(FindCloseUrlCache)(f)); EXPECT_ERR(0);   /* still a valid find handle */
    CHECK(uce_del(url));
}
TEST(uce_rv_stream_handle_is_not_a_find) {
    REQUIRE(U(FindCloseUrlCache)); REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvsnf"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE h = rstream(url, &e);
    CHECKF(h != NULL, "err %lu", e);
    if (h) {
        SET_ERR(0xdeadbeef);
        BOOL r = U(FindCloseUrlCache)(h);
        e = GetLastError();
        /* FindCloseUrlCacheHelper frees with type mask 7; a stream cookie has type 8 [D Free/Validate] */
        CHECK(!r); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        char b[8]; DWORD n = 4;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));   /* the stream survived */
        CHECK(n == 4 && !memcmp(b, g_rbody, 4));
        EXPECT_EQ(ruse(url), 1);
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
}
TEST(uce_rv_stream_cookies_reused) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvscr"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE a = rstream(url, &e);
    CHECK(a != NULL);
    if (a) {
        CHECK(U(UnlockUrlCacheEntryStream)(a, 0));
        HANDLE b = rstream(url, &e);
        CHECK(b != NULL);
        /* Free pushes the slot on a free list and Alloc pops it: the cookie comes back [D Free] */
        t_note("cookie %p then %p", a, b);
        if (b) {
            CHECK(((ULONG_PTR)b & 1) == 1);
            char c[4]; DWORD n = 4;
            CHECK(U(ReadUrlCacheEntryStream)(b, 0, c, &n, 0) && n == 4);
            CHECK(U(UnlockUrlCacheEntryStream)(b, 0));
            SET_ERR(0xdeadbeef);
            EXPECT_FAIL(!U(UnlockUrlCacheEntryStream)(b, 0), ERROR_INVALID_HANDLE);
        }
    }
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- pending deletes and streams */
TEST(uce_rv_two_streams_pending_delete) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rv2sp"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE h1 = rstream(url, &e), h2 = rstream(url, &e);
    CHECK(h1 && h2);
    EXPECT_EQ(ruse(url), 2);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_del(url), ERROR_SHARING_VIOLATION);
    if (h1) CHECK(U(UnlockUrlCacheEntryStream)(h1, 0));
    CHECK(uce_exists(url));                  /* one stream lock left [W10 lock counting] */
    EXPECT_EQ(ruse(url), 1);
    if (h2) {
        char b[8]; DWORD n = 4;
        CHECK(U(ReadUrlCacheEntryStream)(h2, 0, b, &n, 0) && n == 4);
        CHECK(U(UnlockUrlCacheEntryStream)(h2, 0));
    }
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);   /* the last unlock runs the pending delete [W10] */
    CHECK(!uce_file_exists(p));
}
TEST(uce_rv_pending_delete_w_api) {
    REQUIRE(U(DeleteUrlCacheEntryW)); REQUIRE(U(RetrieveUrlCacheEntryFileW)); REQUIRE(U(UnlockUrlCacheEntryFileW));
    const char *url = uce_url("rvpdw"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)b, &sz, 0));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(DeleteUrlCacheEntryW)(uce_w(url)), ERROR_SHARING_VIOLATION);
    CHECK(uce_exists(url));
    SET_ERR(0xdeadbeef);
    CHECK(U(UnlockUrlCacheEntryFileW)(uce_w(url), 0)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    CHECK(!uce_file_exists(p));
}
TEST(uce_rv_commit_over_stream_locked) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvcos"); char p[MAX_PATH], p2[MAX_PATH]; DWORD err;
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE h = rstream(url, &e);
    CHECK(h != NULL);
    /* a stream lock is a lock: the replacing commit fails with 32 [D AddUrl] */
    BOOL r = uce_make_ex(url, "txt", "new!", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p2, &err);
    CHECK(!r); EXPECT_EQ(err, ERROR_SHARING_VIOLATION);
    if (h) CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    CHECK(uce_make_ex(url, "txt", "new!", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p2, &err));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    /* hit rate: 1 at create, +1 for the stream retrieve, +1 for the replace [D AddUrl][W10] */
    if (i) { EXPECT_EQ(i->dwSizeLow, 4); EXPECT_EQ(i->dwHitRate, 3); EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
    CHECK(!uce_file_exists(p2));
}
TEST(uce_rv_delete_after_file_unlock_of_stream) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = uce_url("rvdfu"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    DWORD e; HANDLE h = rstream(url, &e);
    CHECK(h != NULL);
    /* UnlockUrlCacheEntryFile drops the stream's lock [W10], so the delete is not blocked */
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    SET_ERR(0xdeadbeef);
    BOOL d = uce_del(url);
    e = GetLastError();
    CHECK(d); EXPECT_EQ(e, 0);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!uce_exists(url), ERROR_FILE_NOT_FOUND);
    if (h) {
        char b[8]; DWORD n = 4;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0));     /* own file handle */
        CHECK(n == 4 && !memcmp(b, g_rbody, 4));
        SET_ERR(0xdeadbeef);
        BOOL u = U(UnlockUrlCacheEntryStream)(h, 0);
        t_note("stream unlock after its entry was deleted -> %d err %lu", u, GetLastError());
        SET_ERR(0xdeadbeef);
        /* whatever the unlock reported, the cookie is gone from the table [D UnlockUrlCacheEntryStreamHelper] */
        EXPECT_FAIL(!U(ReadUrlCacheEntryStream)(h, 0, b, &n, 0), ERROR_INVALID_HANDLE);
    }
    t_note("file after delete with the stream open: %s", uce_file_exists(p) ? "still there" : "gone");
    DeleteFileA(p);
}

/* --------------------------------------------------------------- SPARSE through Set, SPARSE streams */
TEST(uce_rv_sparse_stream_hidden) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvsps"); char p[MAX_PATH];
    CHECK(rmk(url, SPARSE_CACHE_ENTRY, p));
    DWORD e; HANDLE h = rstream(url, &e);
    CHECK(h == NULL); EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);   /* hidden like the file retrieve [W10] */
    if (h) U(UnlockUrlCacheEntryStream)(h, 0);
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    CHECK(!uce_file_exists(p));
}
TEST(uce_rv_set_sparse_hides_entry) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("rvssh"); char p[MAX_PATH];
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.CacheEntryType = NORMAL_CACHE_ENTRY | SPARSE_CACHE_ENTRY;
    SET_ERR(0xdeadbeef);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_ATTRIBUTE_FC)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    BOOL v = uce_exists(url);
    DWORD e = GetLastError();
    t_note("after Set(SPARSE): exists %d err %lu", v, e);
    CHECK(!v); EXPECT_EQ(e, ERROR_FILE_NOT_FOUND);    /* same filter as a committed SPARSE entry [W10] */
    n.CacheEntryType = NORMAL_CACHE_ENTRY;
    SET_ERR(0xdeadbeef);
    BOOL s = U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_ATTRIBUTE_FC);
    e = GetLastError();
    t_note("Set(NORMAL) on the hidden entry -> %d err %lu", s, e);
    if (s) CHECK(uce_exists(url));
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
    CHECK(!uce_file_exists(p));
}

/* --------------------------------------------------------------- counters */
TEST(uce_rv_hitrate_wrap) {
    REQUIRE(U(SetUrlCacheEntryInfoA)); REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = uce_url("rvhw"); char p[MAX_PATH]; DWORD err;
    CHECK(rmk(url, NORMAL_CACHE_ENTRY, p));
    INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.dwHitRate = 0xFFFFFFFF;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_HITRATE_FC));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwHitRate, 0xFFFFFFFF); free(i); } else CHECK(0);
    char b[4096]; DWORD sz = sizeof b;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    i = uce_info(url, NULL, &err);
    if (i) { t_note("hit rate after retrieve at 0xFFFFFFFF: 0x%lx", i->dwHitRate); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- large files */
TEST(uce_rv_large_file_stream_chunks) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA));
    const char *url = uce_url("rvlf"); char p[MAX_PATH] = ""; DWORD err;
    const DWORD len = 300000;
    unsigned char *data = (unsigned char *)malloc(len), *back = (unsigned char *)malloc(len + 65536);
    if (!data || !back) { free(data); free(back); CHECK(0); return; }
    for (DWORD k = 0; k < len; k++) data[k] = (unsigned char)((k * 131u + (k >> 9)) & 0xff);
    CHECK(uce_make_ex(url, "bin", data, len, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwSizeLow, len); EXPECT_EQ(i->dwSizeHigh, 0); free(i); } else CHECK(0);
    DWORD e; HANDLE h = rstream(url, &e);
    CHECKF(h != NULL, "err %lu", e);
    if (h) {
        DWORD off = 0; int bad = 0;
        while (off < len + 1) {
            DWORD n = 65536;
            if (!U(ReadUrlCacheEntryStream)(h, off, back + off, &n, 0)) { bad++; break; }
            if (n == 0) break;
            off += n;
            if (off > len) { bad++; break; }
        }
        CHECKF(!bad && off == len, "read %lu of %lu", off, len);
        CHECK(off == len && !memcmp(back, data, len));
        /* one read bigger than the file returns the whole file [D ReadFile(*len)] */
        DWORD n = len + 4096;
        CHECK(U(ReadUrlCacheEntryStream)(h, 0, back, &n, 0));
        EXPECT_EQ(n, len);
        CHECK(n == len && !memcmp(back, data, len));
        /* the last byte by offset */
        n = 16;
        CHECK(U(ReadUrlCacheEntryStream)(h, len - 1, back, &n, 0) && n == 1 && back[0] == data[len - 1]);
        CHECK(U(UnlockUrlCacheEntryStream)(h, 0));
    }
    CHECK(uce_del(url));
    CHECK(!uce_file_exists(p));
    free(data); free(back);
}

/* --------------------------------------------------------------- URL leaves that are awkward file names */
static int leaf_is_clean(const char *leaf) {
    for (const char *c = leaf; *c; c++) if (strchr("<>:\"/\\|?*", *c) || (unsigned char)*c < 0x20) return 0;
    return 1;
}
TEST(uce_rv_create_awkward_leaves) {
    REQUIRE(U(CreateUrlCacheEntryA));
    static const char *leaves[] = { "a%20b.txt", "x%3Ay.txt", "p%2Aq.txt", "dq%22.txt", "lt%3Cgt%3E.txt", "pct%25.txt",
                                    "semi;colon.txt", "co,ma.txt", "tilde~1.txt", "UPPER.TXT" };
    for (size_t k = 0; k < sizeof leaves / sizeof *leaves; k++) {
        char url[512]; snprintf(url, sizeof url, "http://%s/%s", t_uniq_host("rvaw"), leaves[k]);
        char path[MAX_PATH] = "";
        SET_ERR(0xdeadbeef);
        BOOL r = U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0);
        CHECKF(r, "%s err %lu", leaves[k], GetLastError());
        if (!r) continue;
        const char *leaf = strrchr(path, '\\'); leaf = leaf ? leaf + 1 : path;
        t_note("leaf %s -> %s", leaves[k], leaf);
        /* whatever the stem, the file is a plain file in the container: no stream or reserved characters */
        CHECKF(leaf_is_clean(leaf), "%s -> %s", leaves[k], leaf);
        CHECK(uce_file_exists(path));
        CHECK(strlen(leaf) > 4 && !_stricmp(leaf + strlen(leaf) - 4, ".txt"));
        DeleteFileA(path);
    }
}
TEST(uce_rv_create_unicode_leaf_w) {
    REQUIRE(U(CreateUrlCacheEntryW)); REQUIRE(U(CommitUrlCacheEntryW));
    WCHAR url[512]; swprintf(url, 512, L"http://%hs/caf\x00e9-\x4e2d.txt", t_uniq_host("rvuni"));
    { char u8[512]; WideCharToMultiByte(CP_UTF8, 0, url, -1, u8, sizeof u8, NULL, NULL); t_cache_track(u8); }   /* A keys are UTF-8 [D] */
    WCHAR path[MAX_PATH] = L"";
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryW)(url, 0, L"txt", path, 0);
    CHECK(r); EXPECT_ERR(0);
    if (!r) return;
    const WCHAR *leaf = wcsrchr(path, L'\\'); leaf = leaf ? leaf + 1 : path;
    { char u8[512]; WideCharToMultiByte(CP_UTF8, 0, leaf, -1, u8, sizeof u8, NULL, NULL); t_note("unicode leaf -> %s (utf-8)", u8); }
    CHECK(uce_file_existsW(path));
    CHECK(uce_write_fileW(path, "uni", 3));
    SET_ERR(0xdeadbeef);
    BOOL c = U(CommitUrlCacheEntryW)(url, path, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, L"txt", NULL);
    CHECK(c); EXPECT_ERR(0);
    if (c) {
        DWORD err; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(url, NULL, &err);
        if (i) {
            CHECK(i->lpszSourceUrlName && !lstrcmpW(i->lpszSourceUrlName, url));
            CHECK(i->lpszLocalFileName && !lstrcmpiW(i->lpszLocalFileName, path));
            EXPECT_EQ(i->dwSizeLow, 3);
            free(i);
        } else CHECKF(0, "info err %lu", err);
        CHECK(U(DeleteUrlCacheEntryW)(url));
        CHECK(!uce_file_existsW(path));
    } else DeleteFileW(path);
}
