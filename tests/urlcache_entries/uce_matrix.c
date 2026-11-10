/* urlcache_entries / table-driven matrices: INTERNET_CACHE_ENTRY_INFOA/W layout over many (url, file, ext, header)
 * shapes, buffer-size sweeps (every size below the requirement), times, types, exempt deltas and hit rates over A and W.
 * Decomp: ConvertCacheEntryInfoA@0x92c0 / ConvertCacheEntryInfoW (string slots after the 0x70 fixed part, order url,
 * file, ext, header; requirement stored in *size on every path), CommitUrlCacheEntryA@0xdaa0 / W@0xd1820 (A header raw,
 * W header -> UTF-8), SetUrlCacheEntryInfoA@0xcba0 / W@0x1a2970, CCacheContainer::UpdateUrl@0x2ac2c.
 * Tags as in EVIDENCE.md: [D] decomp + VM, [W10] VM-observed, [K] knowledge + VM. */
#include "uce.h"

/* A requirement: 0x70 + slot(url) + slot(file) + slot(ext) + align4(header) [D ConvertCacheEntryInfoA] */
static DWORD mx_req_a(const char *url, const char *file, const char *ext, size_t hdr) {
    return UCE_INFO_SIZE + uce_slot(strlen(url)) + (file && *file ? uce_slot(strlen(file)) : 0) +
           (ext ? uce_slot(strlen(ext)) : 0) + (DWORD)((hdr + 3) & ~(size_t)3);
}
/* W requirement: slots in bytes, header widened (no terminator), rounded to 4 [D ConvertCacheEntryInfoW] */
static DWORD mx_req_w(const char *url, const char *file, const char *ext, size_t hdr) {
    return UCE_INFO_SIZE + uce_slotw(strlen(url)) + (file && *file ? uce_slotw(strlen(file)) : 0) +
           (ext ? uce_slotw(strlen(ext)) : 0) + (DWORD)((hdr * 2 + 3) & ~(size_t)3);
}
/* url "http://<uniq host>/<n x 'p'>" (tracked) */
static const char *mx_url(const char *tag, int n) {
    static char b[4][2400]; static int k; char *o = b[k++ & 3];
    int m = snprintf(o, 2400, "http://%s/", t_uniq_host(tag));
    for (int i = 0; i < n && m < 2390; i++) o[m++] = 'p';
    o[m] = 0; t_cache_track(o); return o;
}
static char g_hdrbuf[70000];
static const char *mx_hdr(size_t n) {
    for (size_t i = 0; i < n; i++) g_hdrbuf[i] = (char)('A' + (i % 26));
    g_hdrbuf[n] = 0; return g_hdrbuf;
}

/* --------------------------------------------------------------- layout tables */
static const struct { int path; const char *ext; int hdr; BOOL file; } g_shapes[] = {
    { 0, "txt", 0, TRUE },   { 1, "txt", 1, TRUE },   { 2, "a", 2, TRUE },    { 3, "ab", 3, TRUE },
    { 4, "abc", 4, TRUE },   { 5, "abcd", 5, TRUE },  { 6, "abcde", 6, TRUE }, { 7, "htm", 7, TRUE },
    { 8, "html", 8, TRUE },  { 9, "jpeg", 9, TRUE },  { 31, "json", 31, TRUE }, { 64, "x", 100, TRUE },
    { 1, NULL, 0, FALSE },   { 2, NULL, 3, FALSE },   { 3, "gif", 0, FALSE },  { 4, "z", 17, FALSE },
    { 200, "css", 513, TRUE }, { 1000, "js", 2048, TRUE },
};

TEST(uce_mx_layout_a_table) {
    REQUIRE(U(GetUrlCacheEntryInfoA)); REQUIRE(U(CommitUrlCacheEntryA));
    for (size_t k = 0; k < sizeof g_shapes / sizeof *g_shapes; k++) {
        const char *url = mx_url("mxla", g_shapes[k].path);
        const char *hdr = g_shapes[k].hdr ? mx_hdr((size_t)g_shapes[k].hdr) : NULL;
        char p[MAX_PATH] = ""; DWORD err = 0;
        BOOL ok = uce_make_ex(url, g_shapes[k].ext, g_shapes[k].file ? "body" : NULL, 4, NORMAL_CACHE_ENTRY, hdr,
                              uce_zero_ft, uce_zero_ft, p, &err);
        CHECKF(ok, "row %u commit err %lu", (unsigned)k, err);
        if (!ok) continue;
        DWORD want = mx_req_a(url, g_shapes[k].file ? p : NULL, g_shapes[k].ext, (size_t)g_shapes[k].hdr);
        DWORD sz = 0;
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoA)(url, NULL, &sz);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "row %u r %d e %lu", (unsigned)k, r, e);
        CHECKF(sz == want, "row %u size %lu want %lu", (unsigned)k, sz, want);
        unsigned char *b = (unsigned char *)calloc(1, sz + 32);
        DWORD sz2 = sz;
        r = U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz2);
        CHECKF(r, "row %u get err %lu", (unsigned)k, GetLastError());
        INTERNET_CACHE_ENTRY_INFOA *i = (INTERNET_CACHE_ENTRY_INFOA *)b;
        if (r) {
            EXPECT_EQ(sz2, sz);
            EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
            DWORD off = UCE_INFO_SIZE;
            CHECKF((unsigned char *)i->lpszSourceUrlName == b + off, "row %u url at %td", (unsigned)k, (unsigned char *)i->lpszSourceUrlName - b);
            EXPECT_STR(i->lpszSourceUrlName, url);
            off += uce_slot(strlen(url));
            if (g_shapes[k].file) {
                CHECKF((unsigned char *)i->lpszLocalFileName == b + off, "row %u file at %td", (unsigned)k, (unsigned char *)i->lpszLocalFileName - b);
                CHECK(i->lpszLocalFileName && !_stricmp(i->lpszLocalFileName, p));
                off += uce_slot(strlen(p));
                EXPECT_EQ(i->dwSizeLow, 4);
            } else {
                EXPECT_EQ(i->lpszLocalFileName, NULL);
                EXPECT_EQ(i->dwSizeLow, 0);
            }
            if (g_shapes[k].ext) {
                CHECKF((unsigned char *)i->lpszFileExtension == b + off, "row %u ext at %td", (unsigned)k, (unsigned char *)i->lpszFileExtension - b);
                EXPECT_STR(i->lpszFileExtension, g_shapes[k].ext);
                off += uce_slot(strlen(g_shapes[k].ext));
            } else EXPECT_EQ(i->lpszFileExtension, NULL);
            EXPECT_EQ(i->dwHeaderInfoSize, (DWORD)g_shapes[k].hdr);
            if (g_shapes[k].hdr) {
                CHECKF((unsigned char *)i->lpHeaderInfo == b + off, "row %u hdr at %td", (unsigned)k, (unsigned char *)i->lpHeaderInfo - b);
                CHECK(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, hdr, (size_t)g_shapes[k].hdr));
            } else EXPECT_EQ(i->lpHeaderInfo, NULL);
            EXPECT_EQ(i->dwSizeHigh, 0);
            EXPECT_EQ(i->dwUseCount, 0);
            EXPECT_EQ(i->dwHitRate, 1);
        }
        free(b);
        CHECKF(uce_del(url), "row %u delete err %lu", (unsigned)k, GetLastError());
        if (g_shapes[k].file) CHECK(!uce_file_exists(p));
    }
}

TEST(uce_mx_layout_w_table) {
    REQUIRE(U(GetUrlCacheEntryInfoW)); REQUIRE(U(CommitUrlCacheEntryA));
    for (size_t k = 0; k < sizeof g_shapes / sizeof *g_shapes; k++) {
        const char *url = mx_url("mxlw", g_shapes[k].path);
        const char *hdr = g_shapes[k].hdr ? mx_hdr((size_t)g_shapes[k].hdr) : NULL;
        char p[MAX_PATH] = ""; DWORD err = 0;
        BOOL ok = uce_make_ex(url, g_shapes[k].ext, g_shapes[k].file ? "body" : NULL, 4, NORMAL_CACHE_ENTRY, hdr,
                              uce_zero_ft, uce_zero_ft, p, &err);
        CHECKF(ok, "row %u commit err %lu", (unsigned)k, err);
        if (!ok) continue;
        WCHAR wurl[2400]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 2400);
        DWORD want = mx_req_w(url, g_shapes[k].file ? p : NULL, g_shapes[k].ext, (size_t)g_shapes[k].hdr);
        DWORD sz = 0;
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoW)(wurl, NULL, &sz);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "row %u r %d e %lu", (unsigned)k, r, e);
        CHECKF(sz == want, "row %u size %lu want %lu", (unsigned)k, sz, want);
        unsigned char *b = (unsigned char *)calloc(1, sz + 32);
        DWORD sz2 = sz;
        r = U(GetUrlCacheEntryInfoW)(wurl, (INTERNET_CACHE_ENTRY_INFOW *)b, &sz2);
        CHECKF(r, "row %u get err %lu", (unsigned)k, GetLastError());
        INTERNET_CACHE_ENTRY_INFOW *i = (INTERNET_CACHE_ENTRY_INFOW *)b;
        if (r) {
            EXPECT_EQ(sz2, sz);
            EXPECT_EQ(i->dwStructSize, UCE_INFO_SIZE);
            DWORD off = UCE_INFO_SIZE;
            CHECK((unsigned char *)i->lpszSourceUrlName == b + off);
            CHECK(i->lpszSourceUrlName && !lstrcmpW(i->lpszSourceUrlName, wurl));
            off += uce_slotw(strlen(url));
            if (g_shapes[k].file) {
                CHECK((unsigned char *)i->lpszLocalFileName == b + off);
                CHECK(i->lpszLocalFileName && !lstrcmpiW(i->lpszLocalFileName, uce_w(p)));
                off += uce_slotw(strlen(p));
            } else EXPECT_EQ(i->lpszLocalFileName, NULL);
            if (g_shapes[k].ext) {
                CHECK((unsigned char *)i->lpszFileExtension == b + off);
                CHECK(i->lpszFileExtension && !lstrcmpW(i->lpszFileExtension, uce_w(g_shapes[k].ext)));
                off += uce_slotw(strlen(g_shapes[k].ext));
            } else EXPECT_EQ(i->lpszFileExtension, NULL);
            EXPECT_EQ(i->dwHeaderInfoSize, (DWORD)g_shapes[k].hdr);
            if (g_shapes[k].hdr) {
                CHECK((unsigned char *)i->lpHeaderInfo == b + off);
                BOOL same = i->lpHeaderInfo != NULL;
                for (int c = 0; same && c < g_shapes[k].hdr; c++) same = ((WCHAR *)i->lpHeaderInfo)[c] == (WCHAR)(unsigned char)hdr[c];
                CHECKF(same, "row %u header text", (unsigned)k);
            } else EXPECT_EQ(i->lpHeaderInfo, NULL);
        }
        free(b);
        CHECK(uce_del(url));
    }
}

/* --------------------------------------------------------------- every too-small size */
TEST(uce_mx_sweep_a_sizes) {
    REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = mx_url("mxsa", 5); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "sweep", 5, NORMAL_CACHE_ENTRY, "Hdr: 1\r\n", uce_zero_ft, uce_zero_ft, p, &err));
    DWORD need = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &need);
    CHECK(need > UCE_INFO_SIZE);
    unsigned char *b = (unsigned char *)malloc(need + 8);
    int bad_ret = 0, bad_err = 0, bad_size = 0, touched = 0;
    for (DWORD s = 1; s < need; s++) {
        memset(b, 0xAB, need + 8);
        DWORD sz = s;
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz);
        if (r) bad_ret++;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) bad_err++;
        if (sz != need) bad_size++;
        for (DWORD q = 0; q < need + 8; q++) if (b[q] != 0xAB) { touched++; break; }
    }
    /* every size in [1, need) -> 122, *size = need, buffer untouched [D ConvertCacheEntryInfoA] */
    CHECKF(!bad_ret && !bad_err && !bad_size && !touched, "ret %d err %d size %d touched %d (need %lu)", bad_ret, bad_err, bad_size, touched, need);
    DWORD sz = need;
    CHECK(U(GetUrlCacheEntryInfoA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz));
    free(b);
    CHECK(uce_del(url));
}
TEST(uce_mx_sweep_w_sizes) {
    REQUIRE(U(GetUrlCacheEntryInfoW));
    const char *url = mx_url("mxsw", 5); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "sweep", 5, NORMAL_CACHE_ENTRY, "Hdr: 1\r\n", uce_zero_ft, uce_zero_ft, p, &err));
    DWORD need = 0; U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, &need);
    CHECK(need > UCE_INFO_SIZE);
    unsigned char *b = (unsigned char *)malloc(need + 8);
    int bad_ret = 0, bad_err = 0, bad_size = 0, touched = 0;
    for (DWORD s = 1; s < need; s++) {
        memset(b, 0xAB, need + 8);
        DWORD sz = s;
        SET_ERR(0xdeadbeef);
        BOOL r = U(GetUrlCacheEntryInfoW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)b, &sz);
        if (r) bad_ret++;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) bad_err++;
        if (sz != need) bad_size++;
        for (DWORD q = 0; q < need + 8; q++) if (b[q] != 0xAB) { touched++; break; }
    }
    CHECKF(!bad_ret && !bad_err && !bad_size && !touched, "ret %d err %d size %d touched %d (need %lu)", bad_ret, bad_err, bad_size, touched, need);
    free(b);
    CHECK(uce_del(url));
}
TEST(uce_mx_sweep_retrieve_no_lock) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA));
    const char *url = mx_url("mxsr", 3); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "retr", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    DWORD need = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &need);
    unsigned char b[1024];
    int bad = 0, tries = 0;
    for (DWORD s = 1; s < need && s < sizeof b; s += 3) {
        tries++;
        DWORD sz = s;
        SET_ERR(0xdeadbeef);
        BOOL r = U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0);
        if (r) { bad++; U(UnlockUrlCacheEntryFileA)(url, 0); continue; }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sz != need) bad++;
    }
    CHECKF(bad == 0, "%d sizes misbehaved", bad);
    /* failed retrieves leave no lock [D RetrieveUrlCacheEntryFileA unlocks on conversion failure], but each one was
       counted as a hit: the entry was found and locked before the 122 [W10] */
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); CHECKF(i->dwHitRate == (DWORD)(1 + tries), "hit %lu tries %d", i->dwHitRate, tries); free(i); } else CHECK(0);
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
}
TEST(uce_mx_sweep_stream_no_lock) {
    REQUIRE(U(RetrieveUrlCacheEntryStreamA)); REQUIRE(U(UnlockUrlCacheEntryStream));
    const char *url = mx_url("mxss", 3); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "strm", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    DWORD need = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &need);
    unsigned char b[1024];
    int bad = 0;
    for (DWORD s = 1; s < need && s < sizeof b; s += 5) {
        DWORD sz = s;
        SET_ERR(0xdeadbeef);
        HANDLE h = U(RetrieveUrlCacheEntryStreamA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, FALSE, 0);
        if (h) { bad++; U(UnlockUrlCacheEntryStream)(h, 0); continue; }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sz != need) bad++;
    }
    CHECKF(bad == 0, "%d sizes misbehaved", bad);
    INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
    if (i) { EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    CHECK(uce_del(url));
}

/* --------------------------------------------------------------- header sizes */
TEST(uce_mx_header_sizes_a) {
    REQUIRE(U(CommitUrlCacheEntryA));
    static const DWORD lens[] = { 1, 2, 3, 4, 5, 7, 8, 255, 256, 1023, 1024, 4095, 4096, 16384, 65000 };
    for (size_t k = 0; k < sizeof lens / sizeof *lens; k++) {
        const char *url = mx_url("mxha", 2);
        const char *hdr = mx_hdr(lens[k]);
        SET_ERR(0xdeadbeef);
        BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (BYTE *)hdr, lens[k], NULL, NULL);
        CHECKF(r, "len %lu err %lu", lens[k], GetLastError());
        if (!r) continue;
        DWORD sz = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &sz);
        CHECKF(sz == mx_req_a(url, NULL, NULL, lens[k]), "len %lu size %lu", lens[k], sz);
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) {
            CHECKF(i->dwHeaderInfoSize == lens[k], "len %lu got %lu", lens[k], i->dwHeaderInfoSize);
            CHECKF(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, hdr, lens[k]), "len %lu bytes", lens[k]);
            free(i);
        } else CHECKF(0, "len %lu info err %lu", lens[k], e);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_header_sizes_w) {
    REQUIRE(U(CommitUrlCacheEntryW));
    static const DWORD lens[] = { 1, 2, 3, 4, 5, 255, 256, 4096, 16000 };
    for (size_t k = 0; k < sizeof lens / sizeof *lens; k++) {
        const char *url = mx_url("mxhw", 2);
        const char *hdr = mx_hdr(lens[k]);
        WCHAR *wh = (WCHAR *)calloc(lens[k] + 1, sizeof(WCHAR));
        for (DWORD c = 0; c < lens[k]; c++) wh[c] = (WCHAR)hdr[c];
        SET_ERR(0xdeadbeef);
        BOOL r = U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, wh, lens[k], NULL, NULL);
        CHECKF(r, "len %lu err %lu", lens[k], GetLastError());
        if (r) {
            DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(url), NULL, &e);
            if (i) {
                CHECKF(i->dwHeaderInfoSize == lens[k], "len %lu got %lu", lens[k], i->dwHeaderInfoSize);
                CHECKF(i->lpHeaderInfo && !memcmp(i->lpHeaderInfo, wh, lens[k] * 2), "len %lu chars", lens[k]);
                free(i);
            } else CHECK(0);
            /* stored as UTF-8: the A view shows the same byte count for ASCII [D CommitUrlCacheEntryW] */
            INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
            if (a) { EXPECT_EQ(a->dwHeaderInfoSize, lens[k]); free(a); } else CHECK(0);
            CHECK(uce_del(url));
        }
        free(wh);
    }
}
TEST(uce_mx_header_utf8_table_w) {
    REQUIRE(U(CommitUrlCacheEntryW));
    /* W header -> UTF-8 bytes in the A view [D CommitUrlCacheEntryW: WideCharToMultiByte(CP_UTF8)] */
    static const struct { const WCHAR *w; const char *u8; } rows[] = {
        { L"X: \x00e9\r\n", "X: \xc3\xa9\r\n" },
        { L"X: \x20ac\r\n", "X: \xe2\x82\xac\r\n" },
        { L"\x4e2d\x6587", "\xe4\xb8\xad\xe6\x96\x87" },
        { L"\xd83d\xde00", "\xf0\x9f\x98\x80" },
        { L"plain", "plain" },
    };
    for (size_t k = 0; k < sizeof rows / sizeof *rows; k++) {
        const char *url = mx_url("mxu8", 3);
        CHECK(U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, (LPWSTR)rows[k].w, 0, NULL, NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
        if (a) {
            CHECKF(a->dwHeaderInfoSize == strlen(rows[k].u8), "row %u size %lu", (unsigned)k, a->dwHeaderInfoSize);
            CHECKF(a->lpHeaderInfo && !memcmp(a->lpHeaderInfo, rows[k].u8, strlen(rows[k].u8)), "row %u bytes", (unsigned)k);
            free(a);
        } else CHECKF(0, "row %u err %lu", (unsigned)k, e);
        INTERNET_CACHE_ENTRY_INFOW *w = uce_infoW(uce_w(url), NULL, &e);
        if (w) {
            CHECKF(w->dwHeaderInfoSize == (DWORD)lstrlenW(rows[k].w), "row %u wsize %lu", (unsigned)k, w->dwHeaderInfoSize);
            CHECKF(w->lpHeaderInfo && !memcmp(w->lpHeaderInfo, rows[k].w, lstrlenW(rows[k].w) * 2), "row %u wide", (unsigned)k);
            free(w);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}

/* --------------------------------------------------------------- times */
static const ULONGLONG g_times[] = {
    0, 1, 0xFFFFFFFFULL, 0x100000000ULL, 0x01D0000000000000ULL, 0x01DB2B3C4D5E6F70ULL, 0x7FFFFFFFFFFFFFFFULL,
    0x8000000000000000ULL, 0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,
};
TEST(uce_mx_times_commit_a) {
    REQUIRE(U(CommitUrlCacheEntryA));
    for (size_t k = 0; k < sizeof g_times / sizeof *g_times; k++) {
        const char *url = mx_url("mxta", 1);
        ULONGLONG ex = g_times[k], lm = g_times[(k + 3) % (sizeof g_times / sizeof *g_times)];
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_ft(ex), uce_ft(lm), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) {
            CHECKF(uce_u64(i->ExpireTime) == ex, "row %u expire %llx want %llx", (unsigned)k, uce_u64(i->ExpireTime), ex);
            CHECKF(uce_u64(i->LastModifiedTime) == lm, "row %u lastmod %llx want %llx", (unsigned)k, uce_u64(i->LastModifiedTime), lm);
            free(i);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_times_commit_w) {
    REQUIRE(U(CommitUrlCacheEntryW));
    for (size_t k = 0; k < sizeof g_times / sizeof *g_times; k++) {
        const char *url = mx_url("mxtw", 1);
        ULONGLONG ex = g_times[(k + 5) % (sizeof g_times / sizeof *g_times)], lm = g_times[k];
        CHECK(U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_ft(ex), uce_ft(lm), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(url), NULL, &e);
        if (i) {
            CHECKF(uce_u64(i->ExpireTime) == ex, "row %u expire %llx", (unsigned)k, uce_u64(i->ExpireTime));
            CHECKF(uce_u64(i->LastModifiedTime) == lm, "row %u lastmod %llx", (unsigned)k, uce_u64(i->LastModifiedTime));
            free(i);
        } else CHECK(0);
        CHECK(U(DeleteUrlCacheEntryW)(uce_w(url)));
    }
}
TEST(uce_mx_times_set_table) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    static const DWORD fc[] = { CACHE_ENTRY_MODTIME_FC, CACHE_ENTRY_EXPTIME_FC, CACHE_ENTRY_ACCTIME_FC, CACHE_ENTRY_SYNCTIME_FC };
    for (size_t f = 0; f < 4; f++) {
        for (size_t k = 0; k < sizeof g_times / sizeof *g_times; k++) {
            const char *url = mx_url("mxts", 1);
            CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
            INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n);
            FILETIME t = uce_ft(g_times[k]);
            n.LastModifiedTime = n.ExpireTime = n.LastAccessTime = n.LastSyncTime = t;
            SET_ERR(0xdeadbeef);
            CHECK(U(SetUrlCacheEntryInfoA)(url, &n, fc[f])); EXPECT_ERR(0);
            DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
            if (i) {
                FILETIME got = f == 0 ? i->LastModifiedTime : f == 1 ? i->ExpireTime : f == 2 ? i->LastAccessTime : i->LastSyncTime;
                CHECKF(uce_u64(got) == g_times[k], "fc 0x%lx row %u got %llx", fc[f], (unsigned)k, uce_u64(got));
                free(i);
            } else CHECK(0);
            CHECK(uce_del(url));
        }
    }
}
TEST(uce_mx_set_times_independent) {
    REQUIRE(U(SetUrlCacheEntryInfoW));
    /* each *_FC flag touches exactly its own field [D CCacheContainer::UpdateUrl] */
    static const DWORD fc[] = { CACHE_ENTRY_MODTIME_FC, CACHE_ENTRY_EXPTIME_FC, CACHE_ENTRY_ACCTIME_FC, CACHE_ENTRY_SYNCTIME_FC };
    for (size_t f = 0; f < 4; f++) {
        const char *url = mx_url("mxti", 1);
        ULONGLONG t0 = 0x01D9000000000000ULL;
        CHECK(U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_ft(t0 + 1), uce_ft(t0 + 2), NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOW *a = uce_infoW(uce_w(url), NULL, &e);
        INTERNET_CACHE_ENTRY_INFOW n; memset(&n, 0, sizeof n);
        n.LastModifiedTime = n.ExpireTime = n.LastAccessTime = n.LastSyncTime = uce_ft(0x0123456789ABCDEFULL);
        CHECK(U(SetUrlCacheEntryInfoW)(uce_w(url), &n, fc[f]));
        INTERNET_CACHE_ENTRY_INFOW *b = uce_infoW(uce_w(url), NULL, &e);
        if (a && b) {
            FILETIME *fa[4] = { &a->LastModifiedTime, &a->ExpireTime, &a->LastAccessTime, &a->LastSyncTime };
            FILETIME *fb[4] = { &b->LastModifiedTime, &b->ExpireTime, &b->LastAccessTime, &b->LastSyncTime };
            for (size_t g = 0; g < 4; g++) {
                if (g == f) CHECKF(uce_u64(*fb[g]) == 0x0123456789ABCDEFULL, "fc %u field %u", (unsigned)f, (unsigned)g);
                else CHECKF(uce_u64(*fb[g]) == uce_u64(*fa[g]), "fc %u field %u changed", (unsigned)f, (unsigned)g);
            }
            EXPECT_EQ(b->CacheEntryType, a->CacheEntryType);
            EXPECT_EQ(b->dwHitRate, a->dwHitRate);
            EXPECT_EQ(b->dwExemptDelta, a->dwExemptDelta);
        } else CHECK(0);
        free(a); free(b);
        CHECK(uce_del(url));
    }
}

/* --------------------------------------------------------------- types / exempt / hit rate (W side) */
static const DWORD g_wtypes[] = {
    NORMAL_CACHE_ENTRY, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, NORMAL_CACHE_ENTRY | EDITED_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | TRACK_OFFLINE_CACHE_ENTRY, NORMAL_CACHE_ENTRY | TRACK_ONLINE_CACHE_ENTRY,
    NORMAL_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY, NORMAL_CACHE_ENTRY | COOKIE_CACHE_ENTRY,
    STICKY_CACHE_ENTRY, EDITED_CACHE_ENTRY, 0,
};
TEST(uce_mx_types_commit_w) {
    REQUIRE(U(CommitUrlCacheEntryW));
    for (size_t k = 0; k < sizeof g_wtypes / sizeof *g_wtypes; k++) {
        const char *url = mx_url("mxty", 2);
        SET_ERR(0xdeadbeef);
        BOOL r = U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, g_wtypes[k], NULL, 0, NULL, NULL);
        CHECKF(r, "type 0x%lx err %lu", g_wtypes[k], GetLastError());
        if (!r) continue;
        DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(url), NULL, &e);
        if (i) {
            /* container NORMAL bit ORed in [W10, as for the A commit] */
            CHECKF(i->CacheEntryType == (g_wtypes[k] | NORMAL_CACHE_ENTRY), "type 0x%lx got 0x%lx", g_wtypes[k], i->CacheEntryType);
            CHECKF(i->dwExemptDelta == ((g_wtypes[k] & STICKY_CACHE_ENTRY) ? 86400u : 0u), "type 0x%lx exempt %lu", g_wtypes[k], i->dwExemptDelta);
            free(i);
        } else CHECKF(0, "type 0x%lx info err %lu", g_wtypes[k], e);
        CHECK(U(DeleteUrlCacheEntryW)(uce_w(url)));
    }
}
TEST(uce_mx_types_set_w) {
    REQUIRE(U(SetUrlCacheEntryInfoW));
    for (size_t k = 0; k < sizeof g_wtypes / sizeof *g_wtypes; k++) {
        const char *url = mx_url("mxtsw", 2);
        CHECK(U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        INTERNET_CACHE_ENTRY_INFOW n; memset(&n, 0, sizeof n); n.CacheEntryType = g_wtypes[k];
        SET_ERR(0xdeadbeef);
        CHECK(U(SetUrlCacheEntryInfoW)(uce_w(url), &n, CACHE_ENTRY_ATTRIBUTE_FC)); EXPECT_ERR(0);
        DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(url), NULL, &e);
        /* Set stores the type verbatim [W10] */
        if (i) { CHECKF(i->CacheEntryType == g_wtypes[k], "type 0x%lx got 0x%lx", g_wtypes[k], i->CacheEntryType); free(i); } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_exempt_table_w) {
    REQUIRE(U(SetUrlCacheEntryInfoW));
    static const DWORD vals[][2] = { { 0, 0 }, { 2, 2 }, { 3600, 3600 }, { 86400, 86400 }, { 86402, 86400 }, { 0x80000000, 86400 } };
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) {
        const char *url = mx_url("mxex", 2);
        CHECK(U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        INTERNET_CACHE_ENTRY_INFOW n; memset(&n, 0, sizeof n); n.dwExemptDelta = vals[k][0];
        CHECK(U(SetUrlCacheEntryInfoW)(uce_w(url), &n, CACHE_ENTRY_EXEMPT_DELTA_FC));
        DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(url), NULL, &e);
        if (i) {
            CHECKF(i->dwExemptDelta == vals[k][1], "set %lu got %lu", vals[k][0], i->dwExemptDelta);
            CHECKF(!!(i->CacheEntryType & STICKY_CACHE_ENTRY) == (vals[k][0] != 0), "set %lu type 0x%lx", vals[k][0], i->CacheEntryType);
            free(i);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_hitrate_set_table) {
    REQUIRE(U(SetUrlCacheEntryInfoA));
    static const DWORD vals[] = { 0, 1, 2, 100, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF };
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) {
        const char *url = mx_url("mxhr", 2);
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL));
        INTERNET_CACHE_ENTRY_INFOA n; memset(&n, 0, sizeof n); n.dwHitRate = vals[k];
        CHECK(U(SetUrlCacheEntryInfoA)(url, &n, CACHE_ENTRY_HITRATE_FC));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) { CHECKF(i->dwHitRate == vals[k], "set %lu got %lu", vals[k], i->dwHitRate); free(i); } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_hitrate_counts_retrievals) {
    REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    const char *url = mx_url("mxhc", 4); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "hits", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    for (int n = 1; n <= 6; n++) {
        char b[2048]; DWORD sz = sizeof b;
        CHECK(U(RetrieveUrlCacheEntryFileA)(url, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz, 0));
        /* the returned struct already carries the incremented hit rate and the lock [W10] */
        CHECKF(((INTERNET_CACHE_ENTRY_INFOA *)b)->dwHitRate == (DWORD)(1 + n), "retrieve %d returned hit %lu", n, ((INTERNET_CACHE_ENTRY_INFOA *)b)->dwHitRate);
        CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        if (i) { CHECKF(i->dwHitRate == (DWORD)(1 + n), "after %d got %lu", n, i->dwHitRate); EXPECT_EQ(i->dwUseCount, 0); free(i); } else CHECK(0);
    }
    CHECK(uce_del(url));
}
TEST(uce_mx_usecount_nested_locks) {
    REQUIRE(U(RetrieveUrlCacheEntryFileW)); REQUIRE(U(UnlockUrlCacheEntryFileW));
    const char *url = mx_url("mxuc", 4); char p[MAX_PATH]; DWORD err;
    CHECK(uce_make_ex(url, "txt", "uses", 4, NORMAL_CACHE_ENTRY, NULL, uce_zero_ft, uce_zero_ft, p, &err));
    int locked = 0;
    for (int n = 1; n <= 5; n++) {
        char b[4096]; DWORD sz = sizeof b;
        BOOL r = U(RetrieveUrlCacheEntryFileW)(uce_w(url), (INTERNET_CACHE_ENTRY_INFOW *)b, &sz, 0);
        CHECK(r); if (r) locked++;
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        if (i) { CHECKF(i->dwUseCount == (DWORD)locked, "after %d use %lu", n, i->dwUseCount); free(i); } else CHECK(0);
    }
    while (locked > 0) {
        CHECK(U(UnlockUrlCacheEntryFileW)(uce_w(url), 0)); locked--;
        INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &err);
        if (i) { CHECKF(i->dwUseCount == (DWORD)locked, "unlock -> use %lu want %d", i->dwUseCount, locked); free(i); } else CHECK(0);
    }
    SET_ERR(0xdeadbeef);
    CHECK(uce_del(url)); EXPECT_ERR(0);
}

/* --------------------------------------------------------------- extensions on commit */
TEST(uce_mx_commit_ext_lengths) {
    REQUIRE(U(CommitUrlCacheEntryA));
    char ext[80];
    for (int n = 1; n <= 64; n += (n < 8 ? 1 : 7)) {
        for (int c = 0; c < n; c++) ext[c] = (char)('a' + c % 26);
        ext[n] = 0;
        const char *url = mx_url("mxel", 1);
        SET_ERR(0xdeadbeef);
        BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, ext, NULL);
        CHECKF(r, "ext len %d err %lu", n, GetLastError());
        if (!r) continue;
        DWORD sz = 0; U(GetUrlCacheEntryInfoA)(url, NULL, &sz);
        CHECKF(sz == mx_req_a(url, NULL, ext, 0), "ext len %d size %lu", n, sz);
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) { EXPECT_STR(i->lpszFileExtension, ext); free(i); } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_commit_ext_verbatim) {
    REQUIRE(U(CommitUrlCacheEntryA));
    /* Commit stores the extension string as given; sanitising is a CreateUrlCacheEntry (file name) concern [K] */
    static const char *exts[] = { "TXT", "Html", ".txt", "a.b", "", "x y", "%41" };
    for (size_t k = 0; k < sizeof exts / sizeof *exts; k++) {
        const char *url = mx_url("mxev", 1);
        CHECK(U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, exts[k], NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) {
            if (*exts[k]) CHECKF(i->lpszFileExtension && !strcmp(i->lpszFileExtension, exts[k]), "row %u got %s", (unsigned)k, i->lpszFileExtension ? i->lpszFileExtension : "(null)");
            else CHECKF(i->lpszFileExtension && !*i->lpszFileExtension, "empty ext -> %s", i->lpszFileExtension ? "?" : "NULL");   /* [W10] */
            free(i);
        } else CHECK(0);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_commit_ext_w_table) {
    REQUIRE(U(CommitUrlCacheEntryW));
    static const WCHAR *exts[] = { L"txt", L"HTM", L"\x00e9x", L"json5" };
    for (size_t k = 0; k < sizeof exts / sizeof *exts; k++) {
        const char *url = mx_url("mxew", 1);
        CHECK(U(CommitUrlCacheEntryW)(uce_w(url), NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, exts[k], NULL));
        DWORD e; INTERNET_CACHE_ENTRY_INFOW *i = uce_infoW(uce_w(url), NULL, &e);
        if (i) { CHECKF(i->lpszFileExtension && !lstrcmpW(i->lpszFileExtension, exts[k]), "row %u", (unsigned)k); free(i); } else CHECK(0);
        CHECK(uce_del(url));
    }
}

/* --------------------------------------------------------------- url lengths */
TEST(uce_mx_url_lengths_roundtrip) {
    REQUIRE(U(CommitUrlCacheEntryA));
    static const int lens[] = { 1, 10, 100, 255, 256, 259, 260, 261, 500, 1000, 2047 };
    for (size_t k = 0; k < sizeof lens / sizeof *lens; k++) {
        const char *url = mx_url("mxul", lens[k]);
        SET_ERR(0xdeadbeef);
        BOOL r = U(CommitUrlCacheEntryA)(url, NULL, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, NULL, NULL);
        CHECKF(r, "len %u err %lu", (unsigned)strlen(url), GetLastError());
        if (!r) continue;
        DWORD e; INTERNET_CACHE_ENTRY_INFOA *i = uce_info(url, NULL, &e);
        if (i) { CHECK(i->lpszSourceUrlName && !strcmp(i->lpszSourceUrlName, url)); free(i); } else CHECKF(0, "len %u info %lu", (unsigned)strlen(url), e);
        static WCHAR wurl[2400]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 2400);
        INTERNET_CACHE_ENTRY_INFOW *w = uce_infoW(wurl, NULL, &e);
        if (w) { CHECK(w->lpszSourceUrlName && !lstrcmpW(w->lpszSourceUrlName, wurl)); free(w); } else CHECKF(0, "len %u W info %lu", (unsigned)strlen(url), e);
        CHECK(uce_del(url));
    }
}
TEST(uce_mx_create_url_lengths) {
    REQUIRE(U(CreateUrlCacheEntryA));
    static const int lens[] = { 1, 50, 150, 300, 1000, 2000 };
    for (size_t k = 0; k < sizeof lens / sizeof *lens; k++) {
        const char *url = mx_url("mxcl", lens[k]);
        char p[MAX_PATH] = "";
        SET_ERR(0xdeadbeef);
        BOOL r = U(CreateUrlCacheEntryA)(url, 0, "txt", p, 0);
        CHECKF(r, "len %u err %lu", (unsigned)strlen(url), GetLastError());
        if (!r) continue;
        /* the file name always fits MAX_PATH; long leaf names are cut [K] */
        CHECK(strlen(p) < MAX_PATH);
        CHECK(uce_file_exists(p));
        const char *leaf = strrchr(p, '\\');
        CHECK(leaf != NULL);
        if (leaf) {
            size_t ll = strlen(leaf + 1);
            /* short leaves keep the stem + "[1].txt"; very long ones get a random 8-char name + ".txt" [W10] */
            if (lens[k] <= 150) CHECKF(ll == (size_t)lens[k] + 7, "leaf %d -> %u", lens[k], (unsigned)ll);
            else if (lens[k] >= 300) CHECKF(ll == 12, "leaf %d -> %u", lens[k], (unsigned)ll);
            t_note("url leaf %d chars -> file leaf %u chars", lens[k], (unsigned)ll);
        }
        CHECK(uce_write_file(p, "L", 1));
        CHECK(U(CommitUrlCacheEntryA)(url, p, uce_zero_ft, uce_zero_ft, NORMAL_CACHE_ENTRY, NULL, 0, "txt", NULL));
        CHECK(uce_del(url));
        CHECK(!uce_file_exists(p));
    }
}

/* --------------------------------------------------------------- A/W cross table */
TEST(uce_mx_cross_aw_table) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(CommitUrlCacheEntryW));
    /* commit via A or W, read via A, W, ExA, ExW: same fields everywhere */
    for (int via = 0; via < 2; via++) {
        const char *url = mx_url(via ? "mxcw" : "mxca", 6);
        ULONGLONG t = 0x01DA112233445566ULL;
        char p[MAX_PATH]; WCHAR wp[MAX_PATH];
        if (via == 0) {
            CHECK(U(CreateUrlCacheEntryA)(url, 6, "bin", p, 0));
            CHECK(uce_write_file(p, "cross!", 6));
            CHECK(U(CommitUrlCacheEntryA)(url, p, uce_ft(t), uce_ft(t - 1), NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, (BYTE *)"H: v\r\n", 6, "bin", NULL));
        } else {
            CHECK(U(CreateUrlCacheEntryW)(uce_w(url), 6, L"bin", wp, 0));
            CHECK(uce_write_fileW(wp, "cross!", 6));
            CHECK(U(CommitUrlCacheEntryW)(uce_w(url), wp, uce_ft(t), uce_ft(t - 1), NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY, L"H: v\r\n", 6, L"bin", NULL));
            strcpy(p, uce_a(wp));
        }
        DWORD e, sa = 0, sw = 0, sxa = 0, sxw = 0;
        U(GetUrlCacheEntryInfoA)(url, NULL, &sa);
        U(GetUrlCacheEntryInfoW)(uce_w(url), NULL, &sw);
        U(GetUrlCacheEntryInfoExA)(url, NULL, &sxa, NULL, NULL, NULL, 0);
        U(GetUrlCacheEntryInfoExW)(uce_w(url), NULL, &sxw, NULL, NULL, NULL, 0);
        EXPECT_EQ(sa, sxa); EXPECT_EQ(sw, sxw);
        EXPECT_EQ(sa, mx_req_a(url, p, "bin", 6));
        EXPECT_EQ(sw, mx_req_w(url, p, "bin", 6));
        INTERNET_CACHE_ENTRY_INFOA *a = uce_info(url, NULL, &e);
        INTERNET_CACHE_ENTRY_INFOW *w = uce_infoW(uce_w(url), NULL, &e);
        if (a && w) {
            EXPECT_EQ(a->CacheEntryType, w->CacheEntryType);
            EXPECT_EQ(a->CacheEntryType, NORMAL_CACHE_ENTRY | STICKY_CACHE_ENTRY);
            EXPECT_EQ(a->dwSizeLow, 6); EXPECT_EQ(w->dwSizeLow, 6);
            EXPECT_EQ(uce_u64(a->ExpireTime), t); EXPECT_EQ(uce_u64(w->ExpireTime), t);
            EXPECT_EQ(uce_u64(a->LastModifiedTime), t - 1); EXPECT_EQ(uce_u64(w->LastModifiedTime), t - 1);
            EXPECT_EQ(uce_u64(a->LastAccessTime), uce_u64(w->LastAccessTime));
            EXPECT_EQ(uce_u64(a->LastSyncTime), uce_u64(w->LastSyncTime));
            EXPECT_EQ(a->dwHitRate, w->dwHitRate);
            EXPECT_EQ(a->dwExemptDelta, 86400); EXPECT_EQ(w->dwExemptDelta, 86400);
            EXPECT_EQ(a->dwHeaderInfoSize, 6); EXPECT_EQ(w->dwHeaderInfoSize, 6);
            CHECK(!_stricmp(a->lpszLocalFileName, p));
            CHECK(!lstrcmpiW(w->lpszLocalFileName, uce_w(p)));
        } else CHECK(0);
        free(a); free(w);
        CHECK(uce_del(url));
        CHECK(!uce_file_exists(p));
    }
}
