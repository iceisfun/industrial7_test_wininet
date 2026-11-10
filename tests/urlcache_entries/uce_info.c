/* urlcache_entries / GetUrlCacheEntryInfoA/W/ExA/ExW buffer protocol and SetUrlCacheEntryInfoA/W.
 * Decomp: GetUrlCacheEntryInfoA@0x1a0c60, GetUrlCacheEntryInfoExA@0x1a0e30, GetUrlCacheEntryInfoExW@0xb9c0,
 * ConvertCacheEntryInfoA@0x92c0 / ConvertCacheEntryInfoW (size = 0x70 + 4-aligned url, file, ext, header slots, in that
 * order; *size always receives the required size; NULL A buffer -> 122), SetUrlCacheEntryInfoA@0xcba0 /
 * W@0x1a2970 (copies type, hit rate, 4 times, exempt delta; HEADERINFO_FC masked off), CCacheClientContainer::SetUrlInfo@0xcf34,
 * CCacheContainer::UpdateUrl@0x2ac2c (exempt delta clamped to 86400 and toggles STICKY). */
#include "uce.h"

/* a committed entry with every string present */
static BOOL mk_full(const char *url, const char *hdr, char *path) {
    DWORD err;
    return uce_make_ex(url, "txt", "payload", 7, NORMAL_CACHE_ENTRY, hdr, uce_zero_ft, uce_zero_ft, path, &err);
}
static DWORD req_a(const char *url, const char *path, const char *ext, size_t hdrlen) {
    return UCE_INFO_SIZE + uce_slot(strlen(url)) + (path ? uce_slot(strlen(path)) : 0) + (ext ? uce_slot(strlen(ext)) : 0)
           + (DWORD)((hdrlen + 3) & ~(size_t)3);
}

/* --------------------------------------------------------------- A: parameter validation */
TEST(uce_info_a_null_url) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    DWORD sz = 100; char buf[100];
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 100);
}
TEST(uce_info_a_buffer_without_size) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("ibns"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    char buf[1024];
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, NULL), ERROR_INVALID_PARAMETER);
    CHECK(uce_del(url));
}
TEST(uce_info_a_buffer_size_zero) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("ibz"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    char buf[1024]; DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    /* non-NULL buffer with *size == 0 -> 87, size untouched [D] */
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 0);
    CHECK(uce_del(url));
}
TEST(uce_info_a_existence_probe) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("iprobe"); char p[MAX_PATH];
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, NULL, NULL), ERROR_FILE_NOT_FOUND);
    CHECK(mk_full(url, NULL, p));
    SET_ERR(0xdeadbeef);
    /* NULL buffer and NULL size: just "does it exist" -> TRUE, error 0 [D: Helper(.., NULL) then lVar1 = 0] */
    CHECK(U(GetUrlCacheEntryInfoA)(url, NULL, NULL));
    EXPECT_ERR(0);
    CHECK(uce_del(url));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, NULL, NULL), ERROR_FILE_NOT_FOUND);
}
TEST(uce_info_a_missing_entry) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("imiss");
    char buf[2048]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz), ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(sz, sizeof buf);
    sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, NULL, &sz), ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(sz, 0);
}
TEST(uce_info_a_invalid_url) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)("http://", NULL, &sz), ERROR_INTERNET_INVALID_URL);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)("http:x", NULL, NULL), ERROR_INTERNET_INVALID_URL);
}

/* --------------------------------------------------------------- A: required size and layout */
TEST(uce_info_a_required_size_formula) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    static const char *hdrs[] = { NULL, "A", "AB", "ABC", "ABCD", "ABCDE", "HTTP/1.1 200 OK\r\n\r\n" };
    for (size_t k = 0; k < sizeof hdrs / sizeof *hdrs; k++) {
        const char *url = uce_url("ireq"); char p[MAX_PATH];
        if (!mk_full(url, hdrs[k], p)) { CHECK(0); continue; }
        DWORD sz = 0;
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoA)(url, NULL, &sz);
        CHECK(!r); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        DWORD want = req_a(url, p, "txt", hdrs[k] ? strlen(hdrs[k]) : 0);
        CHECKF(sz == want, "hdr %u: size %lu want %lu", (unsigned)k, sz, want);
        CHECK(uce_del(url));
    }
}
TEST(uce_info_a_url_length_padding) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    /* url slot = strlen+1 rounded up to 4: walk 4 consecutive lengths (no local file, no ext, no header) */
    const char *host = t_uniq_host("ipad");
    DWORD prev = 0;
    for (int extra = 0; extra < 8; extra++) {
        char url[512]; snprintf(url, sizeof url, "http://%s/p%.*s", host, extra, "xxxxxxxx");
        t_cache_track(url);
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        DWORD sz = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &sz);
        CHECKF(sz == UCE_INFO_SIZE + uce_slot(strlen(url)), "len %u size %lu", (unsigned)strlen(url), sz);
        CHECK(sz % 4 == 0);
        CHECK(sz >= prev); prev = sz;
        CHECK(uce_del(url));
    }
}
TEST(uce_info_a_null_buffer_large_size) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("inbl"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    DWORD sz = 100000;
    SET_ERR(0xdeadbeef);
    /* A: a NULL buffer is always 122, whatever *size says; *size gets the requirement [D ConvertCacheEntryInfoA] */
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, NULL, &sz), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, req_a(url, p, "txt", 0));
    CHECK(uce_del(url));
}
TEST(uce_info_a_small_buffers) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("ismall"); char p[MAX_PATH];
    CHECK(mk_full(url, "X-A: b\r\n", p));
    DWORD need = req_a(url, p, "txt", 8);
    DWORD sizes[] = { 1, 4, sizeof(INTERNET_CACHE_ENTRY_INFOA) - 1, sizeof(INTERNET_CACHE_ENTRY_INFOA), sizeof(INTERNET_CACHE_ENTRY_INFOA) + 1, need - 4, need - 1 };
    unsigned char buf[2048];
    for (size_t k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        memset(buf, 0xA5, sizeof buf);
        DWORD sz = sizes[k];
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "size %lu r=%d e=%lu", sizes[k], r, e);
        CHECKF(sz == need, "size %lu -> %lu want %lu", sizes[k], sz, need);
        int untouched = 1; for (size_t b = 0; b < sizeof buf; b++) if (buf[b] != 0xA5) { untouched = 0; break; }
        CHECKF(untouched, "buffer written for size %lu", sizes[k]);   /* nothing copied unless it fits [D] */
    }
    CHECK(uce_del(url));
}
TEST(uce_info_a_exact_and_larger) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("iexact"); char p[MAX_PATH];
    const char *hdr = "HTTP/1.1 200 OK\r\nServer: i7\r\n\r\n";
    CHECK(mk_full(url, hdr, p));
    DWORD need = req_a(url, p, "txt", strlen(hdr));
    DWORD sizes[] = { need, need + 1, need + 3, need + 4, need + 100, 8192 };
    for (size_t k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        unsigned char *buf = (unsigned char *)malloc(sizes[k] + 16); memset(buf, 0xA5, sizes[k] + 16);
        DWORD sz = sizes[k];
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz);
        CHECKF(r, "size %lu err %lu", sizes[k], GetLastError());
        EXPECT_ERR(0);
        CHECKF(sz == need, "in %lu out %lu want %lu", sizes[k], sz, need);   /* *size = required even on success [D] */
        INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)buf;
        if (r) {
            /* layout: struct, url, local file, extension, header [D] */
            unsigned char *u = buf + UCE_INFO_SIZE;
            CHECK((unsigned char *)i->lpszSourceUrlName == u);
            u += uce_slot(strlen(url));
            CHECK((unsigned char *)i->lpszLocalFileName == u);
            u += uce_slot(strlen(p));
            CHECK((unsigned char *)i->lpszFileExtension == u);
            u += uce_slot(3);
            CHECK((unsigned char *)i->lpHeaderInfo == u);
            EXPECT_STR(i->lpszSourceUrlName, url);
            EXPECT_STR(i->lpszFileExtension, "txt");
            /* bytes past the required size are untouched */
            int tail = 1; for (DWORD b = need; b < sizes[k] + 16; b++) if (buf[b] != 0xA5) { tail = 0; break; }
            CHECKF(tail, "bytes past %lu written (buffer %lu)", need, sizes[k]);
            /* padding inside the required size is zeroed [D memset(dst, 0, need)] */
            CHECK(buf[UCE_INFO_SIZE + strlen(url)] == 0);
            CHECK(buf[0x6c] == 0 && buf[0x6d] == 0 && buf[0x6e] == 0 && buf[0x6f] == 0);
        }
        free(buf);
    }
    CHECK(uce_del(url));
}
TEST(uce_info_a_struct_offsets) {
    /* x64 SDK layout used by the decomp (dwStructSize 0, url 8, file 0x10, type 0x18, use 0x1c, hit 0x20, size 0x24/0x28,
       times 0x2c/0x34/0x3c/0x44, header 0x50/0x58, ext 0x60, exempt 0x68) */
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, lpszSourceUrlName), 0x08);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, lpszLocalFileName), 0x10);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, CacheEntryType), 0x18);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, dwUseCount), 0x1c);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, dwHitRate), 0x20);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, dwSizeLow), 0x24);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, LastModifiedTime), 0x2c);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, ExpireTime), 0x34);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, LastAccessTime), 0x3c);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, LastSyncTime), 0x44);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, lpHeaderInfo), 0x50);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, dwHeaderInfoSize), 0x58);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, lpszFileExtension), 0x60);
    EXPECT_EQ(offsetof(INTERNET_CACHE_ENTRY_INFOA, dwExemptDelta), 0x68);
    EXPECT_EQ(sizeof(INTERNET_CACHE_ENTRY_INFOA), UCE_INFO_SIZE);
    EXPECT_EQ(sizeof(INTERNET_CACHE_ENTRY_INFOW), UCE_INFO_SIZE);
}
TEST(uce_info_a_struct_size_ignored_on_input) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    /* dwStructSize is an output: garbage in is fine [D: never read] */
    const char *url = uce_url("isz"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    char buf[2048]; INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)buf;
    DWORD vals[] = { 0, 1, 0x50, 0xFFFFFFFF };
    for (size_t k = 0; k < 4; k++) {
        memset(buf, 0, sizeof buf); i->dwStructSize = vals[k];
        DWORD sz = sizeof buf;
        CHECK(U(GetUrlCacheEntryInfoA)(url, i, &sz));
        EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
    }
    CHECK(uce_del(url));
}
TEST(uce_info_a_no_strings_entry) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("inostr");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    DWORD sz = 0;
    U(GetUrlCacheEntryInfoA)(url, NULL, &sz);
    EXPECT_EQ(sz, UCE_INFO_SIZE + uce_slot(strlen(url)));
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- W */
TEST(uce_info_w_null_args) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    char buf[256]; DWORD sz = sizeof buf;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz), ERROR_INVALID_PARAMETER);
    const char *url = uce_url("iwnull"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, NULL), ERROR_INVALID_PARAMETER);
    sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    CHECK(U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, NULL));
    EXPECT_ERR(0);
    CHECK(uce_del(url));
}
TEST(uce_info_w_missing_entry) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(uce_w(uce_url("iwmiss")), NULL, &sz), ERROR_FILE_NOT_FOUND);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(uce_w(uce_url("iwmiss2")), NULL, NULL), ERROR_FILE_NOT_FOUND);
}
TEST(uce_info_w_required_size) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("iwreq"); char p[MAX_PATH];
    const char *hdr = "HTTP/1.1 200 OK\r\nA: b\r\n\r\n";
    CHECK(mk_full(url, hdr, p));
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, &sz), ERROR_INSUFFICIENT_BUFFER);
    /* W slots: (chars+1)*2 rounded to 4; header converted UTF-8 -> UTF-16, size in characters [D ConvertCacheEntryInfoW] */
    DWORD want = UCE_INFO_SIZE + uce_slotw(strlen(url)) + uce_slotw(strlen(p)) + uce_slotw(3) + (DWORD)((strlen(hdr) * 2 + 3) & ~3u);
    CHECKF(sz == want, "W size %lu want %lu", sz, want);
    INTERNET_CACHE_ENTRY_INFOW *i = (INTERNET_CACHE_ENTRY_INFOW *)calloc(1, sz + 64);
    DWORD sz2 = sz + 64;
    CHECK(U(GetUrlCacheEntryInfoW)(uce_w(url), i, &sz2));
    EXPECT_EQ(sz2, sz);
    EXPECT_EQ(i->dwHeaderInfoSize, strlen(hdr));
    if (i->lpHeaderInfo) CHECK(!memcmp(i->lpHeaderInfo, uce_w(hdr), strlen(hdr) * 2));
    unsigned char *b = (unsigned char *)i;
    CHECK((unsigned char *)i->lpszSourceUrlName == b + UCE_INFO_SIZE);
    CHECK((unsigned char *)i->lpszLocalFileName == b + UCE_INFO_SIZE + uce_slotw(strlen(url)));
    CHECK((unsigned char *)i->lpszFileExtension == b + UCE_INFO_SIZE + uce_slotw(strlen(url)) + uce_slotw(strlen(p)));
    CHECK(i->lpszLocalFileName && !lstrcmpiW(i->lpszLocalFileName, uce_w(p)));
    free(i);
    CHECK(uce_del(url));
}
TEST(uce_info_w_null_buffer_large_size) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("iwnbl"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    DWORD sz = 100000;
    SET_ERR(0xdeadbeef);
    BOOL r = U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, &sz);
    DWORD e = GetLastError();
    t_note("W NULL buffer, size 100000: r=%d err=%lu size=%lu", r, e, sz);
    DWORD want = UCE_INFO_SIZE + uce_slotw(strlen(url)) + uce_slotw(strlen(p)) + uce_slotw(3);
    EXPECT_EQ(sz, want);
    CHECK(uce_del(url));
}
TEST(uce_info_w_small_buffer_untouched) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("iwsmall"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    unsigned char buf[512]; memset(buf, 0x5A, sizeof buf);
    DWORD sz = 0x70;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz), ERROR_INSUFFICIENT_BUFFER);
    CHECK(sz > 0x70);
    int same = 1; for (size_t k = 0; k < sizeof buf; k++) if (buf[k] != 0x5A) same = 0;
    CHECK(same);
    CHECK(uce_del(url));
}
TEST(uce_info_a_vs_w_fields) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = uce_url("iaw"); char p[MAX_PATH]; DWORD err;
    ULONGLONG t = uce_now();
    CHECK(uce_make_ex(url, "css", "a{}", 3, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, "H: v\r\n", uce_ft(t + UCE_DAY), uce_ft(t - UCE_DAY), p, &err));
    INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &err);
    INTERNET_CACHE_ENTRY_INFOW *w = uce_infoW(uce_w(url), NULL, &err);
    CHECK(a && w);
    if (a && w) {
        EXPECT_EQ(a->dwStructSize, w->dwStructSize);
        EXPECT_EQ(a->CacheEntryType, w->CacheEntryType);
        EXPECT_EQ(a->dwSizeLow, w->dwSizeLow);
        EXPECT_EQ(a->dwSizeHigh, w->dwSizeHigh);
        EXPECT_EQ(uce_u64(a->ExpireTime), uce_u64(w->ExpireTime));
        EXPECT_EQ(uce_u64(a->LastModifiedTime), uce_u64(w->LastModifiedTime));
        EXPECT_EQ(uce_u64(a->LastSyncTime), uce_u64(w->LastSyncTime));
        EXPECT_EQ(a->dwExemptDelta, w->dwExemptDelta);
        EXPECT_EQ(a->dwHitRate, w->dwHitRate);
        EXPECT_EQ(a->dwHeaderInfoSize, w->dwHeaderInfoSize);
        CHECK(!lstrcmpiW(w->lpszLocalFileName, uce_w(a->lpszLocalFileName)));
        CHECK(!lstrcmpW(w->lpszFileExtension, L"css"));
        t_note("use count A=%lu W=%lu", a->dwUseCount, w->dwUseCount);
    }
    free(a); free(w);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- Ex */
TEST(uce_info_exa_reserved_params) {
    REQUIRE(U(GetUrlCacheEntryInfoExA));
    const char *url = uce_url("iexr"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    char buf[2048]; DWORD sz = sizeof buf; char redir[256]; DWORD rl = sizeof redir; int dummy;
    SET_ERR(0xdeadbeef);
    /* lpszRedirectUrl, lpcbRedirectUrl and lpReserved must be NULL [D] */
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, redir, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, &rl, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, &dummy, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    CHECK(U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL, 0));
    EXPECT_ERR(0);
    CHECK(uce_del(url));
}
TEST(uce_info_exw_reserved_params) {
    REQUIRE(U(GetUrlCacheEntryInfoExW));
    const char *url = uce_url("iexwr"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    char buf[4096]; DWORD sz = sizeof buf; WCHAR redir[64]; DWORD rl = 64; int dummy;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, redir, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, &rl, NULL, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, &dummy, 0), ERROR_INVALID_PARAMETER);
    sz = sizeof buf;
    CHECK(U(GetUrlCacheEntryInfoExW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz, NULL, NULL, NULL, 0));
    CHECK(uce_del(url));
}
TEST(uce_info_exa_matches_plain) {
    REQUIRE(U(GetUrlCacheEntryInfoExA));
    const char *url = uce_url("iexm"); char p[MAX_PATH];
    CHECK(mk_full(url, "Q: r\r\n", p));
    DWORD s1 = 0, s2 = 0;
    U(GetUrlCacheEntryInfoA)(url, NULL, &s1);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, NULL, &s2, NULL, NULL, NULL, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(s1, s2);
    INTERNET_CACHE_ENTRY_INFOA *a = (INTERNET_CACHE_ENTRY_INFOA *)calloc(1, s2), *b = (INTERNET_CACHE_ENTRY_INFOA *)calloc(1, s1);
    CHECK(U(GetUrlCacheEntryInfoExA)(url, a, &s2, NULL, NULL, NULL, 0));
    CHECK(U(GetUrlCacheEntryInfoA)(url, b, &s1));
    EXPECT_STR(a->lpszSourceUrlName, b->lpszSourceUrlName);
    EXPECT_STR(a->lpszLocalFileName, b->lpszLocalFileName);
    EXPECT_EQ(a->dwSizeLow, b->dwSizeLow);
    EXPECT_EQ(a->dwHeaderInfoSize, b->dwHeaderInfoSize);
    free(a); free(b);
    SET_ERR(0xdeadbeef);
    CHECK(U(GetUrlCacheEntryInfoExA)(url, NULL, NULL, NULL, NULL, NULL, 0));
    EXPECT_ERR(0);
    CHECK(uce_del(url));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, NULL, NULL, NULL, NULL, NULL, 0), ERROR_FILE_NOT_FOUND);
}
TEST(uce_info_exa_fixed_only_flag) {
    REQUIRE(U(GetUrlCacheEntryInfoExA));
    /* flag 0x1000 -> fixed part only: needs >= 0x70, NULL buffer -> 87, no strings [D ConvertCacheEntryInfoA (flags & 8)] */
    const char *url = uce_url("iexfix"); char p[MAX_PATH];
    CHECK(mk_full(url, NULL, p));
    DWORD sz = 0x70;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, NULL, &sz, NULL, NULL, NULL, 0x1000), ERROR_INVALID_PARAMETER);
    unsigned char buf[0x100]; memset(buf, 0xCC, sizeof buf);
    sz = 0x6f;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL, 0x1000), ERROR_INSUFFICIENT_BUFFER);
    sz = 0x70;
    SET_ERR(0xdeadbeef);
    BOOL r = U(GetUrlCacheEntryInfoExA)(url, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz, NULL, NULL, NULL, 0x1000);
    CHECK(r); EXPECT_ERR(0);
    INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)buf;
    if (r) {
        EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
        EXPECT_EQ(i->lpszSourceUrlName, NULL);
        EXPECT_EQ(i->lpszLocalFileName, NULL);
        EXPECT_EQ(i->lpszFileExtension, NULL);
        EXPECT_EQ(i->lpHeaderInfo, NULL);
        EXPECT_EQ(i->dwSizeLow, 7);
        EXPECT_EQ(sz, 0x70);
        CHECK(buf[0x70] == 0xCC);
    }
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- SetUrlCacheEntryInfo */
TEST(uce_set_a_null_args) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    INTERNET_CACHE_ENTRY_INFOA i; memset(&i, 0, sizeof i);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoA)(NULL, &i, CACHE_ENTRY_HITRATE_FC), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoA)(uce_url("snull"), NULL, CACHE_ENTRY_HITRATE_FC), ERROR_INVALID_PARAMETER);
}
TEST(uce_set_w_null_args) {
    REQUIRE(U(SetUrlCacheEntryInfoW));
    INTERNET_CACHE_ENTRY_INFOW i; memset(&i, 0, sizeof i);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoW)(NULL, &i, CACHE_ENTRY_HITRATE_FC), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoW)(uce_w(uce_url("swnull")), NULL, CACHE_ENTRY_HITRATE_FC), ERROR_INVALID_PARAMETER);
}
TEST(uce_set_missing_entry) {
    REQUIRE(U(SetUrlCacheEntryInfoA)); REQUIRE(U(SetUrlCacheEntryInfoW));
    INTERNET_CACHE_ENTRY_INFOA i; memset(&i, 0, sizeof i); i.dwStructSize = sizeof i;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoA)(uce_url("smiss"), &i, CACHE_ENTRY_HITRATE_FC), ERROR_FILE_NOT_FOUND);
    INTERNET_CACHE_ENTRY_INFOW w; memset(&w, 0, sizeof w);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoW)(uce_w(uce_url("swmiss")), &w, CACHE_ENTRY_EXPTIME_FC), ERROR_FILE_NOT_FOUND);
    CHECK(!uce_exists(uce_url("smiss2")));
}
TEST(uce_set_invalid_url) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    INTERNET_CACHE_ENTRY_INFOA i; memset(&i, 0, sizeof i);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(SetUrlCacheEntryInfoA)("http://", &i, CACHE_ENTRY_HITRATE_FC), ERROR_INTERNET_INVALID_URL);
}

/* one field per flag (table): the flagged field changes, the others keep their committed values */
enum { F_TYPE, F_HIT, F_MOD, F_EXP, F_ACC, F_SYNC, F_EXEMPT };
static const struct { DWORD fc; int field; const char *name; } g_fc[] = {
    { CACHE_ENTRY_ATTRIBUTE_FC, F_TYPE, "ATTRIBUTE" }, { CACHE_ENTRY_HITRATE_FC, F_HIT, "HITRATE" },
    { CACHE_ENTRY_MODTIME_FC, F_MOD, "MODTIME" }, { CACHE_ENTRY_EXPTIME_FC, F_EXP, "EXPTIME" },
    { CACHE_ENTRY_ACCTIME_FC, F_ACC, "ACCTIME" }, { CACHE_ENTRY_SYNCTIME_FC, F_SYNC, "SYNCTIME" },
    { CACHE_ENTRY_EXEMPT_DELTA_FC, F_EXEMPT, "EXEMPT_DELTA" },
};
static void fill_new(INTERNET_CACHE_ENTRY_INFOA *n) {
    memset(n, 0, sizeof *n); n->dwStructSize = sizeof *n;
    n->CacheEntryType = NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY; n->dwHitRate = 77;
    n->LastModifiedTime = uce_ft(0x01D1111111111111ULL); n->ExpireTime = uce_ft(0x01D2222222222222ULL);
    n->LastAccessTime = uce_ft(0x01D3333333333333ULL); n->LastSyncTime = uce_ft(0x01D4444444444444ULL);
    n->dwExemptDelta = 3600;
}
TEST(uce_set_each_flag_table) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    for (size_t k = 0; k < sizeof g_fc / sizeof *g_fc; k++) {
        const char *url = uce_url("sflag");
        ULONGLONG t = uce_now();
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(t + UCE_DAY), uce_ft(t - UCE_DAY), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *b = uce_info(url, NULL, &e);
        INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n);
        SET_ERR(0xdeadbeef);
        BOOL r = U(SetUrlCacheEntryInfoA)(url, &n, g_fc[k].fc);
        CHECKF(r, "%s err %lu", g_fc[k].name, GetLastError());
        EXPECT_ERR(0);
        INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
        if (a && b) {
            int f = g_fc[k].field;
            if (f == F_TYPE) CHECKF(a->CacheEntryType == n.CacheEntryType, "%s type 0x%lx", g_fc[k].name, a->CacheEntryType);
            else CHECKF(a->CacheEntryType == b->CacheEntryType || f == F_EXEMPT, "%s type changed 0x%lx", g_fc[k].name, a->CacheEntryType);
            if (f == F_HIT) EXPECT_EQ(a->dwHitRate, 77); else CHECKF(a->dwHitRate == b->dwHitRate, "%s hitrate %lu->%lu", g_fc[k].name, b->dwHitRate, a->dwHitRate);
            if (f == F_MOD) EXPECT_EQ(uce_u64(a->LastModifiedTime), uce_u64(n.LastModifiedTime)); else CHECKF(uce_u64(a->LastModifiedTime) == uce_u64(b->LastModifiedTime), "%s mod changed", g_fc[k].name);
            if (f == F_EXP) EXPECT_EQ(uce_u64(a->ExpireTime), uce_u64(n.ExpireTime)); else CHECKF(uce_u64(a->ExpireTime) == uce_u64(b->ExpireTime), "%s exp changed", g_fc[k].name);
            if (f == F_ACC) EXPECT_EQ(uce_u64(a->LastAccessTime), uce_u64(n.LastAccessTime));
            if (f == F_SYNC) EXPECT_EQ(uce_u64(a->LastSyncTime), uce_u64(n.LastSyncTime)); else CHECKF(uce_u64(a->LastSyncTime) == uce_u64(b->LastSyncTime), "%s sync changed", g_fc[k].name);
            if (f == F_EXEMPT) { EXPECT_EQ(a->dwExemptDelta, 3600); CHECK(a->CacheEntryType & STICKY_CACHE_ENTRY); }
            else EXPECT_EQ(a->dwExemptDelta, b->dwExemptDelta);
        } else CHECKF(0, "%s info", g_fc[k].name);
        free(a); free(b);
        CHECK(uce_del(url));
    }
}
TEST(uce_set_all_flags) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("sall");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n);
    DWORD all = 0; for (size_t k = 0; k < sizeof g_fc / sizeof *g_fc; k++) all |= g_fc[k].fc;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, all));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a) {
        EXPECT_EQ(a->dwHitRate, 77);
        EXPECT_EQ(uce_u64(a->LastModifiedTime), uce_u64(n.LastModifiedTime));
        EXPECT_EQ(uce_u64(a->ExpireTime), uce_u64(n.ExpireTime));
        EXPECT_EQ(uce_u64(a->LastSyncTime), uce_u64(n.LastSyncTime));
        EXPECT_EQ(a->dwExemptDelta, 3600);
        CHECK(a->CacheEntryType & EDITED_CACHE_ENTRY);
        CHECK(a->CacheEntryType & STICKY_CACHE_ENTRY);
        free(a);
    } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_set_no_flags_noop) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("snone");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(5), uce_ft(6), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n);
    SET_ERR(0xdeadbeef);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, 0));
    EXPECT_ERR(0);
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a) { EXPECT_EQ(uce_u64(a->ExpireTime), 5); EXPECT_EQ(uce_u64(a->LastModifiedTime), 6); CHECK(!(a->CacheEntryType & EDITED_CACHE_ENTRY)); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_set_headerinfo_flag_ignored) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("shdr");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (BYTE *)"Old: 1\r\n", 8, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n); n.lpHeaderInfo = "New: 2\r\n"; n.dwHeaderInfoSize = 8;
    /* the public setters mask CACHE_ENTRY_HEADERINFO_FC (0x400) off [D param_3 & 0xfffffbff] */
    SET_ERR(0xdeadbeef);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_HEADERINFO_FC));
    EXPECT_ERR(0);
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a) { EXPECT_EQ(a->dwHeaderInfoSize, 8); CHECK(a->lpHeaderInfo && !memcmp(a->lpHeaderInfo, "Old: 1\r\n", 8)); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_set_unknown_flags_ignored) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("sunk");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(9), uce_ft(9), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n);
    SET_ERR(0xdeadbeef);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, 0x00000001 | 0x00000002 | 0x00000008 | 0x00000020 | 0x00002000 | 0x80000000));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a) { EXPECT_EQ(uce_u64(a->ExpireTime), 9); EXPECT_EQ(a->dwHitRate == 77, 0); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_set_attribute_alias_0x1000) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    /* (flags & 0x1004) selects the type field [D SetUrlInfo] */
    const char *url = uce_url("s1000");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n); n.CacheEntryType = NORMAL_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, 0x1000));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a) { EXPECT_EQ(a->CacheEntryType, NORMAL_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_set_exempt_delta_clamped) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    static const DWORD vals[][2] = { { 1, 1 }, { 60, 60 }, { 86399, 86399 }, { 86400, 86400 }, { 86401, 86400 }, { 1000000, 86400 }, { 0xFFFFFFFF, 86400 } };
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) {
        const char *url = uce_url("sexm");
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n); n.dwExemptDelta = vals[k][0];
        CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_EXEMPT_DELTA_FC));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
        if (a) {
            CHECKF(a->dwExemptDelta == vals[k][1], "set %lu got %lu want %lu", vals[k][0], a->dwExemptDelta, vals[k][1]);
            CHECKF(a->CacheEntryType & STICKY_CACHE_ENTRY, "set %lu not sticky 0x%lx", vals[k][0], a->CacheEntryType);
            free(a);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_set_exempt_zero_unsticks) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("sunst");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n); n.dwExemptDelta = 0;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_EXEMPT_DELTA_FC));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    /* exempt 0 clears STICKY unless a group pins the entry [D UpdateUrl] */
    if (a) { EXPECT_EQ(a->dwExemptDelta, 0); CHECK(!(a->CacheEntryType & STICKY_CACHE_ENTRY)); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
TEST(uce_set_type_table) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    static const DWORD types[] = { NORMAL_CACHE_ENTRY, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, EDITED_CACHE_ENTRY, COOKIE_CACHE_ENTRY,
                                   URLHISTORY_CACHE_ENTRY, SPARSE_CACHE_ENTRY | NORMAL_CACHE_ENTRY, 0 };
    for (size_t k = 0; k < sizeof types / sizeof *types; k++) {
        const char *url = uce_url("stype");
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n); n.CacheEntryType = types[k];
        CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_ATTRIBUTE_FC));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
        if (a) { CHECKF(a->CacheEntryType == types[k], "set 0x%lx got 0x%lx", types[k], a->CacheEntryType); free(a); } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_set_w_fields) {
    REQUIRE(U(SetUrlCacheEntryInfoW));
    const char *url = uce_url("swf"); const WCHAR *w = uce_w(url);
    CHECK(U(CommitUrlCacheEntryW)(w, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOW n; memset(&n, 0, sizeof n);
    n.dwHitRate = 5; n.ExpireTime = uce_ft(0x01DA000000000001ULL); n.LastModifiedTime = uce_ft(0x01DA000000000002ULL);
    SET_ERR(0xdeadbeef);
    CHECK(U(SetUrlCacheEntryInfoW)(w, &n, CACHE_ENTRY_HITRATE_FC | CACHE_ENTRY_EXPTIME_FC | CACHE_ENTRY_MODTIME_FC));
    EXPECT_ERR(0);
    DWORD e; INTERNET_CACHE_ENTRY_INFOW *a = uce_infoW(w, NULL, &e);
    if (a) { EXPECT_EQ(a->dwHitRate, 5); EXPECT_EQ(uce_u64(a->ExpireTime), 0x01DA000000000001ULL); EXPECT_EQ(uce_u64(a->LastModifiedTime), 0x01DA000000000002ULL); free(a); } else CHECK(0);
    CHECK(U(DeleteUrlCacheEntryW)(w));
}
TEST(uce_set_struct_size_not_checked) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("sss");
    CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n); n.dwStructSize = 0;
    SET_ERR(0xdeadbeef);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_HITRATE_FC));   /* dwStructSize never read [D] */
    EXPECT_ERR(0);
    CHECK(uce_del(url));
}
TEST(uce_set_does_not_change_strings) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    const char *url = uce_url("sstr"); char p[MAX_PATH];
    CHECK(mk_full(url, "K: v\r\n", p));
    INTERNET_CACHE_ENTRY_INFOA n; fill_new(&n);
    n.lpszLocalFileName = "C:\\nowhere.txt"; n.lpszFileExtension = "zzz"; n.lpszSourceUrlName = "http://other.example/";
    DWORD all = 0; for (size_t k = 0; k < sizeof g_fc / sizeof *g_fc; k++) all |= g_fc[k].fc;
    CHECK(U(SetUrlCacheEntryInfoA)(url, &n, all | CACHE_ENTRY_HEADERINFO_FC));
    DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
    if (a) { CHECK(!_stricmp(a->lpszLocalFileName, p)); EXPECT_STR(a->lpszFileExtension, "txt"); EXPECT_STR(a->lpszSourceUrlName, url); EXPECT_EQ(a->dwSizeLow, 7); free(a); } else CHECK(0);
    CHECK(uce_del(url));
}
