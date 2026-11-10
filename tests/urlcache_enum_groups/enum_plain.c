/* urlcache_enum_groups / enum_plain.c - FindFirstUrlCacheEntryA/W, FindNextUrlCacheEntryA/W, FindCloseUrlCache.
 * Evidence: [D] wininet decomp (FindFirstUrlCacheEntryA@0x19fc20, FindFirstUrlCacheEntryExAHelper@0x8500,
 * FindNextUrlCacheEntryA@0x1a0070, FindNextUrlCacheEntryHelper@0x8eb0, FindNextUrlCacheEntryCommitHelper@0x9aec,
 * FindCloseUrlCache@0x35b40, ConvertCacheEntryInfoA@0x92c0, ConvertCacheEntryInfoW@0x865c0), [VM] Win10 22H2 runs.
 * Whole-cache enumerations are bounded (UEG_ENUM_CAP) and only look for this process's unique URLs.
 * VM_TIMEOUT: 240 */
#include "ueg.h"
#include <stdlib.h>

#define REQ_FIND_A() do { REQUIRE(U(FindFirstUrlCacheEntryA)); REQUIRE(U(FindNextUrlCacheEntryA)); REQUIRE(U(FindCloseUrlCache)); } while (0)
#define REQ_FIND_W() do { REQUIRE(U(FindFirstUrlCacheEntryW)); REQUIRE(U(FindNextUrlCacheEntryW)); REQUIRE(U(FindCloseUrlCache)); } while (0)
#define MAKE_OR_SKIP(url) do { if (!ueg_make_simple(url)) { t_skip("could not create cache entry (%lu)", GetLastError()); return; } } while (0)

/* ------------------------------------------------------------------ FindFirstUrlCacheEntryA parameter validation */
TEST(ueg_ffa_null_size_87) {
    REQ_FIND_A();
    char buf[512];
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryA)(NULL, NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryA)("visited:", NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
}
TEST(ueg_ffa_buffer_with_zero_size_87) {
    REQ_FIND_A();
    char buf[512]; DWORD sz = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 0);                            /* rejected before anything is computed */
    sz = 0; SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryA)("cookie:", (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 0);
}
TEST(ueg_ffw_null_size_87) {
    REQ_FIND_W();
    char buf[512];
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryW)(L"visited:", NULL, NULL);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
}
TEST(ueg_ffw_buffer_with_zero_size_87) {
    REQ_FIND_W();
    char buf[512]; DWORD sz = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz);
    EXPECT_FAIL(h == NULL, ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 0);
}

/* NULL buffer + *size 0 is the documented size query: the first entry's required size comes back with 122 and the
 * enumeration handle is closed again (FindFirstUrlCacheEntryExAHelper frees it on a conversion failure). */
TEST(ueg_ffa_size_query_122) {
    REQ_FIND_A();
    const char *url = ueg_url("szq"); MAKE_OR_SKIP(url);
    DWORD sz = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, NULL, &sz);
    EXPECT_FAIL(h == NULL, ERROR_INSUFFICIENT_BUFFER);
    CHECKF(sz > UEG_ENTRY_A_FIXED && sz < 0x10000, "size %lu", sz);
    CHECK((sz & 3) == 0);                       /* every variable part is 4-aligned [D ConvertCacheEntryInfoA] */
    /* a buffer one byte short still fails with the same size */
    if (sz > UEG_ENTRY_A_FIXED && sz < 0x10000) {
        DWORD need = sz; char *b = calloc(1, need + 64); DWORD s2 = need - 1;
        SET_ERR(0xdead);
        h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &s2);
        if (h) { t_note("first entry changed between calls (size %lu -> ok with %lu)", need, s2); U(FindCloseUrlCache)(h); }
        else { EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); t_note("short-by-one size %lu -> %lu", need - 1, s2); }
        free(b);
    }
}
TEST(ueg_ffw_size_query_122) {
    REQ_FIND_W();
    const char *url = ueg_url("szqw"); MAKE_OR_SKIP(url);
    DWORD sz = 0;
    SET_ERR(0xdead);
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, NULL, &sz);
    EXPECT_FAIL(h == NULL, ERROR_INSUFFICIENT_BUFFER);
    CHECKF(sz > UEG_ENTRY_A_FIXED && sz < 0x20000, "size %lu", sz);
    CHECK((sz & 3) == 0);
}

/* After a size query, a buffer of exactly that size succeeds, *size reports the required size, the success path
 * sets the last error to 0 and the structure is self-consistent. */
TEST(ueg_ffa_exact_size_roundtrip) {
    REQ_FIND_A();
    const char *url = ueg_url("exact"); MAKE_OR_SKIP(url);
    DWORD sz = 0;
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, NULL, &sz);
    CHECK(h == NULL);
    if (!sz || sz > 0x10000) { t_skip("no size"); return; }
    DWORD cap = sz + 256; unsigned char *b = malloc(cap); memset(b, 0xCC, cap);
    DWORD s2 = sz;
    SET_ERR(0xdead);
    h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &s2);
    CHECK(h != NULL);
    if (h) {
        INTERNET_CACHE_ENTRY_INFOA *e = (INTERNET_CACHE_ENTRY_INFOA *)b;
        EXPECT_ERR(0);
        EXPECT_EQ(e->dwStructSize, UEG_ENTRY_A_FIXED);
        CHECK(e->lpszSourceUrlName == (LPSTR)(b + UEG_ENTRY_A_FIXED));
        EXPECT_EQ(s2, ueg_expected_size_a(e));
        if (s2 != sz) t_note("first entry changed between size query and fetch (%lu vs %lu)", sz, s2);
        /* bytes past the required size are untouched (memset covers only the required size) */
        int untouched = 1; for (DWORD i = s2; i < cap; i++) if (b[i] != 0xCC) untouched = 0;
        CHECK(untouched);
        CHECK(U(FindCloseUrlCache)(h));
    }
    free(b);
}

/* With a larger buffer, *size is rewritten to the required size (not left at the buffer size). */
TEST(ueg_ffa_success_reports_required_size) {
    REQ_FIND_A();
    const char *url = ueg_url("req"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; unsigned char *b = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)b, &sz);
    CHECK(h != NULL);
    if (h) {
        INTERNET_CACHE_ENTRY_INFOA *e = (INTERNET_CACHE_ENTRY_INFOA *)b;
        CHECK(sz < cap);
        EXPECT_EQ(sz, ueg_expected_size_a(e));
        int nn = 0;
        for (int i = 0; i < 200; i++) {
            DWORD s = cap;
            if (!U(FindNextUrlCacheEntryA)(h, e, &s)) { EXPECT_ERR(ERROR_NO_MORE_ITEMS); break; }
            nn++;
            if (s != ueg_expected_size_a(e)) { CHECKF(0, "entry %d size %lu != formula %lu (%s)", i, s, ueg_expected_size_a(e), e->lpszSourceUrlName); break; }
        }
        CHECK(nn >= 0);
        U(FindCloseUrlCache)(h);
    }
    free(b);
}

/* ------------------------------------------------------------------ whole-cache enumeration sees our entries */
TEST(ueg_plain_null_pattern_finds_entry) {
    REQ_FIND_A();
    const char *url = ueg_url("pnull"); MAKE_OR_SKIP(url);
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a(NULL, url, &n), 1);
    CHECK(n >= 1);
    t_note("FindFirstUrlCacheEntryA(NULL) enumerated %d entries", n);
}
TEST(ueg_plain_empty_pattern_finds_entry) {
    REQ_FIND_A();
    const char *url = ueg_url("pempty"); MAKE_OR_SKIP(url);
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a("", url, &n), 1);
    CHECK(n >= 1);
}
TEST(ueg_plain_http_pattern_is_not_a_filter) {
    REQ_FIND_A();
    /* An unknown non-':' pattern maps to the content container [D CCacheClientStore::GetContainer]: it is not a URL filter. */
    const char *url = ueg_url("phttp"); MAKE_OR_SKIP(url);
    int n = 0;
    int f = ueg_plain_contains_a("http://no.such.prefix.example/", url, &n);
    EXPECT_EQ(f, 1);
    t_note("pattern 'http://no.such.prefix.example/' enumerated %d entries", n);
}
TEST(ueg_plain_visited_pattern_excludes_content) {
    REQ_FIND_A();
    const char *url = ueg_url("pvis"); MAKE_OR_SKIP(url);
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a("visited:", url, &n), 0);
    t_note("'visited:' enumerated %d entries", n);
}
TEST(ueg_plain_cookie_pattern_excludes_content) {
    REQ_FIND_A();
    const char *url = ueg_url("pcook"); MAKE_OR_SKIP(url);
    int n = 0;
    EXPECT_EQ(ueg_plain_contains_a("cookie:", url, &n), 0);
    t_note("'cookie:' enumerated %d entries", n);
}
TEST(ueg_plain_w_null_finds_entry) {
    REQ_FIND_W();
    const char *url = ueg_url("wnull"); MAKE_OR_SKIP(url);
    const WCHAR *wurl = ueg_w(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, e, &sz);
    CHECK(h != NULL);
    int found = 0, n = 0;
    if (h) {
        do {
            n++;
            EXPECT_EQ(e->dwStructSize, 0x70);
            if (e->lpszSourceUrlName && !lstrcmpiW(e->lpszSourceUrlName, wurl)) {
                found++;
                CHECK(e->lpszLocalFileName != NULL);
                CHECK(e->lpszFileExtension && !lstrcmpW(e->lpszFileExtension, L"txt"));
                EXPECT_EQ(e->dwSizeLow, 5);
                EXPECT_EQ(e->dwSizeHigh, 0);
            }
            sz = cap;
        } while (n < UEG_ENUM_CAP && U(FindNextUrlCacheEntryW)(h, e, &sz));
        if (n < UEG_ENUM_CAP) EXPECT_ERR(ERROR_NO_MORE_ITEMS);
        U(FindCloseUrlCache)(h);
    }
    EXPECT_EQ(found, 1);
    free(e);
}

/* ------------------------------------------------------------------ the structure of an enumerated entry */
typedef struct { const char *url; int found; INTERNET_CACHE_ENTRY_INFOA *copy; DWORD size; } grab_ctx;
static int grab_cb(const INTERNET_CACHE_ENTRY_INFOA *e, DWORD size, void *c_) {
    grab_ctx *c = c_;
    if (e->lpszSourceUrlName && !lstrcmpiA(e->lpszSourceUrlName, c->url)) {
        c->found++;
        if (!c->copy) { c->copy = malloc(size); memcpy(c->copy, e, size); c->size = size;
            /* rebase pointers into the copy */
            ULONG_PTR d = (ULONG_PTR)c->copy - (ULONG_PTR)e;
            if (c->copy->lpszSourceUrlName) c->copy->lpszSourceUrlName += d;
            if (c->copy->lpszLocalFileName) c->copy->lpszLocalFileName += d;
            if (c->copy->lpszFileExtension) c->copy->lpszFileExtension += d;
            if (c->copy->lpHeaderInfo) c->copy->lpHeaderInfo = (void *)((char *)c->copy->lpHeaderInfo + d);
        }
    }
    return 1;
}
TEST(ueg_entry_fields_match_commit) {
    REQ_FIND_A();
    const char *url = ueg_url("fields");
    FILETIME exp = ueg_days(30), lm = ueg_days(-2);
    const char *hdr = "HTTP/1.1 200 OK\r\nX-Ueg: 1\r\n\r\n";
    if (!ueg_make_entry(url, NORMAL_CACHE_ENTRY, exp, lm, hdr, "htm", "0123456789")) { t_skip("commit failed %lu", GetLastError()); return; }
    grab_ctx c = { url, 0, NULL, 0 };
    ueg_enum_plain_a(NULL, grab_cb, &c, NULL);
    EXPECT_EQ(c.found, 1);
    if (!c.copy) return;
    INTERNET_CACHE_ENTRY_INFOA *e = c.copy;
    EXPECT_EQ(e->dwStructSize, UEG_ENTRY_A_FIXED);
    EXPECT_STR(e->lpszSourceUrlName, url);
    EXPECT_EQ(e->dwSizeLow, 10);
    EXPECT_EQ(e->dwSizeHigh, 0);
    CHECK(e->CacheEntryType & NORMAL_CACHE_ENTRY);
    EXPECT_EQ(ueg_u64(e->ExpireTime), ueg_u64(exp));
    EXPECT_EQ(ueg_u64(e->LastModifiedTime), ueg_u64(lm));
    CHECK(e->lpszFileExtension && !strcmp(e->lpszFileExtension, "htm"));
    EXPECT_EQ(e->dwHeaderInfoSize, (DWORD)strlen(hdr));
    CHECK(e->lpHeaderInfo && !memcmp(e->lpHeaderInfo, hdr, strlen(hdr)));
    CHECK(e->lpszLocalFileName && GetFileAttributesA(e->lpszLocalFileName) != INVALID_FILE_ATTRIBUTES);
    EXPECT_EQ(c.size, ueg_expected_size_a(e));
    /* layout: url, local file, extension, header follow the fixed part in this order */
    unsigned char *base = (unsigned char *)e;
    CHECK((unsigned char *)e->lpszSourceUrlName == base + 0x70);
    CHECK((unsigned char *)e->lpszLocalFileName == base + 0x70 + ueg_align4((DWORD)strlen(url) + 1));
    if (e->lpszLocalFileName && e->lpszFileExtension)
        CHECK((unsigned char *)e->lpszFileExtension == (unsigned char *)e->lpszLocalFileName + ueg_align4((DWORD)strlen(e->lpszLocalFileName) + 1));
    if (e->lpszFileExtension && e->lpHeaderInfo)
        CHECK((unsigned char *)e->lpHeaderInfo == (unsigned char *)e->lpszFileExtension + ueg_align4((DWORD)strlen(e->lpszFileExtension) + 1));
    /* the same entry seen through GetUrlCacheEntryInfoA */
    DWORD isz = 0; INTERNET_CACHE_ENTRY_INFOA *g = ueg_info_a(url, &isz);
    CHECK(g != NULL);
    if (g) {
        EXPECT_STR(g->lpszSourceUrlName, e->lpszSourceUrlName);
        EXPECT_STR(g->lpszLocalFileName, e->lpszLocalFileName);
        EXPECT_EQ(g->CacheEntryType, e->CacheEntryType);
        EXPECT_EQ(g->dwSizeLow, e->dwSizeLow);
        EXPECT_EQ(ueg_u64(g->ExpireTime), ueg_u64(e->ExpireTime));
        EXPECT_EQ(ueg_u64(g->LastModifiedTime), ueg_u64(e->LastModifiedTime));
        EXPECT_EQ(g->dwHeaderInfoSize, e->dwHeaderInfoSize);
        t_note("GetUrlCacheEntryInfoA size %lu, enumeration size %lu, use count %lu/%lu hit %lu/%lu", isz, c.size, g->dwUseCount, e->dwUseCount, g->dwHitRate, e->dwHitRate);
        free(g);
    }
    free(e);
}

/* No header, no extension: those pointers are NULL and contribute nothing to the size. */
TEST(ueg_entry_no_header_no_ext) {
    REQ_FIND_A();
    const char *url = ueg_url("bare");
    if (!ueg_make_entry(url, NORMAL_CACHE_ENTRY, ueg_days(30), ueg_days(-1), NULL, NULL, "abc")) { t_skip("commit failed %lu", GetLastError()); return; }
    grab_ctx c = { url, 0, NULL, 0 };
    ueg_enum_plain_a(NULL, grab_cb, &c, NULL);
    EXPECT_EQ(c.found, 1);
    if (!c.copy) return;
    INTERNET_CACHE_ENTRY_INFOA *e = c.copy;
    CHECK(e->lpHeaderInfo == NULL);
    EXPECT_EQ(e->dwHeaderInfoSize, 0);
    t_note("bare entry: ext=%s local=%s size=%lu", e->lpszFileExtension ? e->lpszFileExtension : "(null)", e->lpszLocalFileName ? e->lpszLocalFileName : "(null)", c.size);
    EXPECT_EQ(c.size, ueg_expected_size_a(e));
    EXPECT_EQ(e->dwSizeLow, 3);
    free(e);
}

/* ------------------------------------------------------------------ FindNextUrlCacheEntryA/W parameter validation */
static HANDLE open_any_a(INTERNET_CACHE_ENTRY_INFOA *e, DWORD cap) {
    DWORD sz = cap; return U(FindFirstUrlCacheEntryA)(NULL, e, &sz);
}
TEST(ueg_fna_null_handle_87) {
    REQ_FIND_A();
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(NULL, (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, sizeof buf);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(NULL, NULL, NULL), ERROR_INVALID_PARAMETER);
}
TEST(ueg_fnw_null_handle_87) {
    REQ_FIND_W();
    char buf[4096]; DWORD sz = sizeof buf;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindNextUrlCacheEntryW)(NULL, (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz), ERROR_INVALID_PARAMETER);
}
TEST(ueg_fna_null_size_and_zero_size_87) {
    REQ_FIND_A();
    const char *url = ueg_url("fnsz"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE h = open_any_a(e, cap);
    CHECK(h != NULL);
    if (h) {
        SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(h, e, NULL), ERROR_INVALID_PARAMETER);
        DWORD z = 0; SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(h, e, &z), ERROR_INVALID_PARAMETER);
        EXPECT_EQ(z, 0);
        CHECK(U(FindCloseUrlCache)(h));
    }
    free(e);
}
TEST(ueg_fnw_null_size_and_zero_size_87) {
    REQ_FIND_W();
    const char *url = ueg_url("fnszw"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, e, &sz);
    CHECK(h != NULL);
    if (h) {
        SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryW)(h, e, NULL), ERROR_INVALID_PARAMETER);
        DWORD z = 0; SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryW)(h, e, &z), ERROR_INVALID_PARAMETER);
        CHECK(U(FindCloseUrlCache)(h));
    }
    free(e);
}

/* Handles are table indices ((index << 1) | 1) validated against the handle table: values that do not name a live
 * entry-find handle fail with ERROR_INVALID_HANDLE [D FindNextUrlCacheEntryHelper]. These are not pointers. */
static const ULONG_PTR k_bogus_handles[] = { 2, 4, 0x100, 0x7ffffff1, 0x7fff0001, 0xfffffff };
TEST(ueg_fna_bogus_handle_values_6) {
    REQ_FIND_A();
    char buf[4096];
    for (size_t i = 0; i < sizeof k_bogus_handles / sizeof *k_bogus_handles; i++) {
        DWORD sz = sizeof buf; SET_ERR(0xdead);
        BOOL r = U(FindNextUrlCacheEntryA)((HANDLE)k_bogus_handles[i], (INTERNET_CACHE_ENTRY_INFOA *)buf, &sz);
        CHECKF(!r, "handle 0x%llx accepted", (unsigned long long)k_bogus_handles[i]);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_HANDLE, "handle 0x%llx err %lu", (unsigned long long)k_bogus_handles[i], e);
    }
}
TEST(ueg_fnw_bogus_handle_values_6) {
    REQ_FIND_W();
    char buf[4096];
    for (size_t i = 0; i < sizeof k_bogus_handles / sizeof *k_bogus_handles; i++) {
        DWORD sz = sizeof buf; SET_ERR(0xdead);
        BOOL r = U(FindNextUrlCacheEntryW)((HANDLE)k_bogus_handles[i], (INTERNET_CACHE_ENTRY_INFOW *)buf, &sz);
        CHECK(!r);
        EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
}

/* ------------------------------------------------------------------ FindCloseUrlCache */
TEST(ueg_findclose_null_6) {
    REQUIRE(U(FindCloseUrlCache));
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(FindCloseUrlCache)(NULL), ERROR_INVALID_HANDLE);
}
TEST(ueg_findclose_bogus_values_6) {
    REQUIRE(U(FindCloseUrlCache));
    for (size_t i = 0; i < sizeof k_bogus_handles / sizeof *k_bogus_handles; i++) {
        SET_ERR(0xdead);
        CHECK(!U(FindCloseUrlCache)((HANDLE)k_bogus_handles[i]));
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_HANDLE, "value 0x%llx err %lu", (unsigned long long)k_bogus_handles[i], e);
    }
}
TEST(ueg_findclose_success_sets_error_0) {
    REQ_FIND_A();
    const char *url = ueg_url("fc0"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE h = open_any_a(e, cap);
    CHECK(h != NULL);
    if (h) {
        CHECK(((ULONG_PTR)h & 1) == 1);          /* (index << 1) | 1 [D handle manager] */
        SET_ERR(0xdead);
        CHECK(U(FindCloseUrlCache)(h));
        EXPECT_ERR(0);
        SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindCloseUrlCache)(h), ERROR_INVALID_HANDLE);   /* double close */
        DWORD sz = cap; SET_ERR(0xdead);
        EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(h, e, &sz), ERROR_INVALID_HANDLE);   /* use after close */
    }
    free(e);
}
TEST(ueg_findclose_w_handle) {
    REQ_FIND_W();
    const char *url = ueg_url("fcw"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, e, &sz);
    CHECK(h != NULL);
    if (h) { CHECK(((ULONG_PTR)h & 1) == 1); SET_ERR(0xdead); CHECK(U(FindCloseUrlCache)(h)); EXPECT_ERR(0); }
    free(e);
}
/* An A handle can be continued with the W API and vice versa: the handle names the server enumeration only. */
TEST(ueg_find_handle_a_then_w) {
    REQ_FIND_A(); REQ_FIND_W();
    const char *u1 = ueg_url("aw1"), *u2 = ueg_url("aw2"); MAKE_OR_SKIP(u1); MAKE_OR_SKIP(u2);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, e, &sz);
    CHECK(h != NULL);
    if (h) {
        sz = cap; SET_ERR(0xdead);
        BOOL r = U(FindNextUrlCacheEntryW)(h, (INTERNET_CACHE_ENTRY_INFOW *)e, &sz);
        CHECK(r);
        if (r) { EXPECT_ERR(0); EXPECT_EQ(((INTERNET_CACHE_ENTRY_INFOW *)e)->dwStructSize, 0x70); CHECK(((INTERNET_CACHE_ENTRY_INFOW *)e)->lpszSourceUrlName != NULL); }
        U(FindCloseUrlCache)(h);
    }
    free(e);
}

/* ------------------------------------------------------------------ end of enumeration */
TEST(ueg_find_end_is_259_and_sticky) {
    REQ_FIND_A();
    const char *url = ueg_url("end"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE h = open_any_a(e, cap);
    CHECK(h != NULL);
    if (h) {
        int n = 1; DWORD sz;
        for (;;) { sz = cap; if (!U(FindNextUrlCacheEntryA)(h, e, &sz) || ++n >= UEG_ENUM_CAP) break; }
        if (n < UEG_ENUM_CAP) {
            EXPECT_ERR(ERROR_NO_MORE_ITEMS);
            for (int k = 0; k < 3; k++) {
                sz = cap; SET_ERR(0xdead);
                EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(h, e, &sz), ERROR_NO_MORE_ITEMS);
            }
            /* even the size query reports 259 once the enumeration is done */
            DWORD z = 0; SET_ERR(0xdead);
            EXPECT_FAIL(!U(FindNextUrlCacheEntryA)(h, NULL, &z), ERROR_NO_MORE_ITEMS);
        }
        CHECK(U(FindCloseUrlCache)(h));
    }
    free(e);
}

/* ------------------------------------------------------------------ FindNext buffer protocol */
/* A failed conversion does not advance the cursor [D FindNextUrlCacheEntryCommitHelper runs only on success]:
 * after 122 the same entry is returned with a big-enough buffer. */
TEST(ueg_fna_small_buffer_does_not_advance) {
    REQ_FIND_A();
    const char *u1 = ueg_url("adv1"), *u2 = ueg_url("adv2"), *u3 = ueg_url("adv3");
    MAKE_OR_SKIP(u1); MAKE_OR_SKIP(u2); MAKE_OR_SKIP(u3);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE h = open_any_a(e, cap);
    CHECK(h != NULL);
    int checked = 0;
    if (h) {
        for (int i = 0; i < 6; i++) {
            DWORD z = 0; SET_ERR(0xdead);
            BOOL r = U(FindNextUrlCacheEntryA)(h, NULL, &z);
            if (r) { CHECKF(0, "size query succeeded"); break; }
            DWORD er = GetLastError();
            if (er == ERROR_NO_MORE_ITEMS) break;
            EXPECT_EQ(er, ERROR_INSUFFICIENT_BUFFER);
            CHECK(z > UEG_ENTRY_A_FIXED);
            /* one byte short: still 122, same size */
            DWORD s1 = z - 1; SET_ERR(0xdead);
            CHECK(!U(FindNextUrlCacheEntryA)(h, e, &s1));
            EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
            EXPECT_EQ(s1, z);
            /* exact: succeeds, and it is the entry whose size was reported */
            DWORD s2 = z; SET_ERR(0xdead);
            CHECK(U(FindNextUrlCacheEntryA)(h, e, &s2));
            EXPECT_ERR(0);
            EXPECT_EQ(s2, z);
            EXPECT_EQ(ueg_expected_size_a(e), z);
            checked++;
        }
        U(FindCloseUrlCache)(h);
    }
    CHECK(checked >= 1);
    free(e);
}
TEST(ueg_fnw_small_buffer_does_not_advance) {
    REQ_FIND_W();
    const char *u1 = ueg_url("advw1"), *u2 = ueg_url("advw2"); MAKE_OR_SKIP(u1); MAKE_OR_SKIP(u2);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOW *e = malloc(cap); DWORD sz = cap;
    HANDLE h = U(FindFirstUrlCacheEntryW)(NULL, e, &sz);
    CHECK(h != NULL);
    int checked = 0;
    if (h) {
        for (int i = 0; i < 4; i++) {
            DWORD z = 0; SET_ERR(0xdead);
            BOOL r = U(FindNextUrlCacheEntryW)(h, NULL, &z);
            if (r) { t_note("W size query with NULL buffer and size 0 succeeded"); break; }
            DWORD er = GetLastError();
            if (er == ERROR_NO_MORE_ITEMS) break;
            EXPECT_EQ(er, ERROR_INSUFFICIENT_BUFFER);
            DWORD s1 = z - 4; SET_ERR(0xdead);
            CHECK(!U(FindNextUrlCacheEntryW)(h, e, &s1));
            EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
            EXPECT_EQ(s1, z);
            DWORD s2 = z; SET_ERR(0xdead);
            CHECK(U(FindNextUrlCacheEntryW)(h, e, &s2));
            EXPECT_EQ(s2, z);
            CHECK(e->lpszSourceUrlName == (LPWSTR)((char *)e + 0x70));
            checked++;
        }
        U(FindCloseUrlCache)(h);
    }
    CHECK(checked >= 1);
    free(e);
}
/* A size query through FindFirst closes the half-open enumeration; repeated queries do not leak handles
 * (bounded: 64 iterations, each leaves no handle behind since the API returns NULL). */
TEST(ueg_ffa_repeated_size_queries) {
    REQ_FIND_A();
    const char *url = ueg_url("rq"); MAKE_OR_SKIP(url);
    DWORD first = 0;
    for (int i = 0; i < 64; i++) {
        DWORD z = 0; SET_ERR(0xdead);
        HANDLE h = U(FindFirstUrlCacheEntryA)(NULL, NULL, &z);
        if (h) { CHECKF(0, "size query returned a handle"); U(FindCloseUrlCache)(h); break; }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) { CHECKF(0, "iteration %d err %lu", i, GetLastError()); break; }
        if (!first) first = z;
    }
    CHECK(first > UEG_ENTRY_A_FIXED);
}

/* ------------------------------------------------------------------ several concurrent enumerations */
TEST(ueg_find_two_handles_independent) {
    REQ_FIND_A();
    const char *u1 = ueg_url("two1"), *u2 = ueg_url("two2"); MAKE_OR_SKIP(u1); MAKE_OR_SKIP(u2);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *a = malloc(cap), *b = malloc(cap);
    HANDLE ha = open_any_a(a, cap), hb = open_any_a(b, cap);
    CHECK(ha != NULL); CHECK(hb != NULL);
    CHECK(ha != hb);
    if (ha && hb) {
        /* both start at the same first entry */
        CHECK(a->lpszSourceUrlName && b->lpszSourceUrlName && !strcmp(a->lpszSourceUrlName, b->lpszSourceUrlName));
        /* advancing one does not advance the other */
        DWORD sz = cap; BOOL ra = U(FindNextUrlCacheEntryA)(ha, a, &sz);
        sz = cap; BOOL ra2 = ra ? U(FindNextUrlCacheEntryA)(ha, a, &sz) : 0;
        sz = cap; BOOL rb = U(FindNextUrlCacheEntryA)(hb, b, &sz);
        if (ra && rb) {
            /* b's second entry must not equal a's third unless the cache repeats URLs (it does not) */
            if (ra2) CHECK(strcmp(a->lpszSourceUrlName, b->lpszSourceUrlName) != 0);
        }
        CHECK(U(FindCloseUrlCache)(ha));
        sz = cap; SET_ERR(0xdead);
        BOOL rb2 = U(FindNextUrlCacheEntryA)(hb, b, &sz);
        CHECK(rb2 || GetLastError() == ERROR_NO_MORE_ITEMS);   /* closing ha leaves hb usable */
        CHECK(U(FindCloseUrlCache)(hb));
    } else { if (ha) U(FindCloseUrlCache)(ha); if (hb) U(FindCloseUrlCache)(hb); }
    free(a); free(b);
}
/* Up to 32 simultaneous enumeration handles are all distinct and all closable. */
TEST(ueg_find_many_handles) {
    REQ_FIND_A();
    const char *url = ueg_url("many"); MAKE_OR_SKIP(url);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE hs[32]; int n = 0;
    for (int i = 0; i < 32; i++) { hs[i] = open_any_a(e, cap); if (hs[i]) n++; }
    EXPECT_EQ(n, 32);
    int dup = 0;
    for (int i = 0; i < 32; i++) for (int j = i + 1; j < 32; j++) if (hs[i] && hs[i] == hs[j]) dup++;
    EXPECT_EQ(dup, 0);
    int closed = 0;
    for (int i = 0; i < 32; i++) if (hs[i] && U(FindCloseUrlCache)(hs[i])) closed++;
    EXPECT_EQ(closed, n);
    free(e);
}

/* ------------------------------------------------------------------ entries deleted while enumerating */
TEST(ueg_find_delete_current_entry_continues) {
    REQ_FIND_A(); REQUIRE(U(DeleteUrlCacheEntryA));
    const char *u1 = ueg_url("del1"), *u2 = ueg_url("del2"), *u3 = ueg_url("del3");
    MAKE_OR_SKIP(u1); MAKE_OR_SKIP(u2); MAKE_OR_SKIP(u3);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE h = open_any_a(e, cap);
    CHECK(h != NULL);
    int n = 0, deleted = 0; DWORD sz; DWORD last = 0;
    if (h) {
        do {
            n++;
            if (e->lpszSourceUrlName && (!strcmp(e->lpszSourceUrlName, u1) || !strcmp(e->lpszSourceUrlName, u2) || !strcmp(e->lpszSourceUrlName, u3))) {
                SET_ERR(0xdead);
                BOOL r = U(DeleteUrlCacheEntryA)(e->lpszSourceUrlName);
                CHECK(r);
                deleted += r ? 1 : 0;
            }
            sz = cap;
        } while (n < UEG_ENUM_CAP && U(FindNextUrlCacheEntryA)(h, e, &sz));
        last = GetLastError();
        U(FindCloseUrlCache)(h);
    }
    if (n < UEG_ENUM_CAP) EXPECT_EQ(last, ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(deleted, 3);
    CHECK(!ueg_exists(u1)); CHECK(!ueg_exists(u2)); CHECK(!ueg_exists(u3));
    free(e);
}
TEST(ueg_find_entry_created_after_open) {
    REQ_FIND_A();
    const char *u0 = ueg_url("late0"); MAKE_OR_SKIP(u0);
    DWORD cap = 0x8000; INTERNET_CACHE_ENTRY_INFOA *e = malloc(cap);
    HANDLE h = open_any_a(e, cap);
    CHECK(h != NULL);
    const char *u1 = ueg_url("late1");
    int made = ueg_make_simple(u1);
    int n = 0, seen = 0; DWORD sz;
    if (h) {
        do { n++; if (e->lpszSourceUrlName && !strcmp(e->lpszSourceUrlName, u1)) seen++; sz = cap; }
        while (n < UEG_ENUM_CAP && U(FindNextUrlCacheEntryA)(h, e, &sz));
        U(FindCloseUrlCache)(h);
    }
    CHECK(made);
    CHECK(seen <= 1);
    t_note("entry created after FindFirst seen by that enumeration: %d (of %d entries)", seen, n);
}
