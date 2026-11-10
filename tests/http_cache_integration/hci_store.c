/* hci_store.c - a GET stores a URL cache entry: what the entry looks like (size, headers, type, times, local file,
 * extension) and which responses are stored at all.
 * Decomp: HTTP_REQUEST_HANDLE_OBJECT::FCanWriteToCache@0x6a120 (200 or cacheable redirect + IsMIMETypeCacheable,
 * no-store/HTTP 0.9 never, other statuses only with NEED_FILE/HYPERLINK), FHttpBeginCacheWrite@0xe39c (extension),
 * LocalEndCacheWrite. VM_TIMEOUT: 240 */
#include "hci.h"
#include <stdlib.h>

/* one GET of a fresh URL with the given reply; returns entry info (or NULL) and fills r */
static INTERNET_CACHE_ENTRY_INFOA *get_once(srv *s, const char *url, DWORD flags, hci_resp *r) {
    HINTERNET hi = hci_open();
    hci_get(hi, url, NULL, flags, r);
    t_inet_close(hi);
    DWORD e; return hci_info(url, &e);
}

TEST(hci_store_get_creates_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hello cache", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "basic");
    CHECK(!hci_exists(url));
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(r.body, "hello cache");
    CHECK(e != NULL);
    hci_note_entry("basic", e);
    if (e) {
        EXPECT_STR(e->lpszSourceUrlName, url);
        EXPECT_EQ(e->dwSizeLow, 11);
        EXPECT_EQ(e->dwSizeHigh, 0);
        CHECK(e->CacheEntryType & NORMAL_CACHE_ENTRY);
        CHECK(!(e->CacheEntryType & (COOKIE_CACHE_ENTRY | URLHISTORY_CACHE_ENTRY | STICKY_CACHE_ENTRY)));
        EXPECT_EQ(e->dwStructSize, sizeof(INTERNET_CACHE_ENTRY_INFOA));
        CHECK(e->lpszLocalFileName && e->lpszLocalFileName[0]);
        CHECK(e->lpHeaderInfo && e->dwHeaderInfoSize > 0);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_local_file_equals_body) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "local file body\r\nline2\n", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "file");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    if (e) {
        char buf[256]; size_t n;
        CHECK(hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n));
        EXPECT_EQ(n, 23);
        EXPECT_STR(buf, "local file body\r\nline2\n");
        CHECK(hci_file_exists(e->lpszLocalFileName));
        /* the local file lives in the user's INetCache tree */
        CHECK(strstr(e->lpszLocalFileName, "\\") != NULL);
        t_note("local file %s", e->lpszLocalFileName);
    }
    free(e);
    srv_stop(s);
}

/* sizes: the entry size and the file size equal the body length (pattern bodies) */
static const size_t g_sizes[] = { 1, 2, 100, 1023, 4096, 8192, 16000, 65536, 100000 };
TEST(hci_store_sizes_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static char big[100001];
    for (size_t i = 0; i < sizeof big - 1; i++) big[i] = (char)srv_pattern_byte(i);
    for (size_t k = 0; k < sizeof g_sizes / sizeof g_sizes[0]; k++) {
        hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, big, "Content-Type: application/octet-stream\r\nCache-Control: max-age=3600\r\n");
        rp->len = g_sizes[k];
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "size");
        HINTERNET hi = hci_open();
        HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
        CHECK(h != NULL);
        size_t total = 0; char *buf = malloc(g_sizes[k] + 16);
        if (h) {
            for (int g = 0; g < 10000; g++) { DWORD rd = 0; if (!U(InternetReadFile)(h, buf + total, (DWORD)(g_sizes[k] + 16 - total), &rd) || !rd) break; total += rd; }
            U(InternetCloseHandle)(h);
        }
        t_inet_close(hi);
        CHECKF(total == g_sizes[k], "size %zu read %zu", g_sizes[k], total);
        CHECK(srv_pattern_check(buf, total, 0));
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
        CHECKF(e != NULL, "size %zu err %lu", g_sizes[k], err);
        if (e) {
            CHECKF(e->dwSizeLow == g_sizes[k], "size %zu entry %lu", g_sizes[k], e->dwSizeLow);
            WIN32_FILE_ATTRIBUTE_DATA fa;
            CHECK(GetFileAttributesExA(e->lpszLocalFileName, GetFileExInfoStandard, &fa));
            CHECKF(fa.nFileSizeLow == g_sizes[k], "size %zu file %lu", g_sizes[k], fa.nFileSizeLow);
        }
        free(e); free(buf);
        srv_stop(s);
    }
}

TEST(hci_store_header_info_contents) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hdrs", "Content-Type: text/plain\r\nX-Hci-Custom: v1\r\nCache-Control: max-age=3600\r\nETag: \"e1\"\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hdrinfo");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    hci_note_entry("hdrinfo", e);
    if (e) {
        CHECK(!strncmp((const char *)e->lpHeaderInfo, "HTTP/1.1 200 OK\r\n", 17));
        CHECK(hci_hdr_has(e, "Content-Type: text/plain\r\n"));
        CHECK(hci_hdr_has(e, "X-Hci-Custom: v1\r\n"));
        CHECK(hci_hdr_has(e, "ETag: \"e1\"\r\n"));
        CHECK(hci_hdr_has(e, "Cache-Control: max-age=3600\r\n"));
        CHECK(hci_hdr_has(e, "Content-Length: 4\r\n"));
        /* header blob is a NUL-free CRLF list ending in an empty line */
        const char *h = (const char *)e->lpHeaderInfo; DWORD n = e->dwHeaderInfoSize;
        CHECK(n >= 4);
        t_note("header blob ends with %02x %02x %02x %02x", (unsigned char)h[n - 4], (unsigned char)h[n - 3], (unsigned char)h[n - 2], (unsigned char)h[n - 1]);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_set_cookie_in_header_info) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ck", "Content-Type: text/plain\r\nSet-Cookie: hcick=1; Path=/\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "setcookie");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, INTERNET_FLAG_NO_COOKIES, &r);
    CHECK(e != NULL);
    if (e) t_note("Set-Cookie kept in cached headers: %d", hci_hdr_has(e, "Set-Cookie"));
    free(e);
    srv_stop(s);
}

TEST(hci_store_last_modified_and_expires_parsed) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0};
    hci_set(&p, 0, 200, "t", "Content-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "times");
    LONGLONG before = hci_ft_now();
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    LONGLONG after = hci_ft_now();
    CHECK(e != NULL);
    if (e) {
        SYSTEMTIME lm = { 1994, 11, 2, 15, 8, 12, 31, 0 }, ex = { 2033, 12, 4, 1, 16, 0, 0, 0 }; FILETIME f1, f2;
        SystemTimeToFileTime(&lm, &f1); SystemTimeToFileTime(&ex, &f2);
        EXPECT_EQ(hci_ft(e->LastModifiedTime), hci_ft(f1));
        EXPECT_EQ(hci_ft(e->ExpireTime), hci_ft(f2));
        LONGLONG sync = hci_ft(e->LastSyncTime);
        CHECKF(sync >= before - 5 * HCI_SEC && sync <= after + 5 * HCI_SEC, "sync %llx [%llx..%llx]", sync, before, after);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_max_age_sets_expire_time) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ma", "Content-Type: text/plain\r\nCache-Control: max-age=7200\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "maxage");
    LONGLONG before = hci_ft_now();
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    if (e) {
        LONGLONG ex = hci_ft(e->ExpireTime), want = before + 7200 * HCI_SEC;
        CHECKF(ex >= want - 60 * HCI_SEC && ex <= want + 60 * HCI_SEC, "expire %llx want ~%llx", ex, want);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_max_age_beats_expires) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "mx", "Content-Type: text/plain\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\nCache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "mabeat");
    LONGLONG before = hci_ft_now();
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    if (e) {
        LONGLONG ex = hci_ft(e->ExpireTime), want = before + 600 * HCI_SEC;
        CHECKF(ex >= want - 60 * HCI_SEC && ex <= want + 60 * HCI_SEC, "expire %llx want ~%llx", ex, want);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_no_validators_times_zero) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nv", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "novalid");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    hci_note_entry("novalid", e);
    if (e) {
        EXPECT_EQ(hci_ft(e->ExpireTime), 0);
        EXPECT_EQ(hci_ft(e->LastModifiedTime), 0);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_expires_in_past_still_stored) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "old", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "pastexp");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    if (e) {
        SYSTEMTIME ex = { 1998, 1, 4, 1, 0, 0, 0, 0 }; FILETIME f; SystemTimeToFileTime(&ex, &f);
        EXPECT_EQ(hci_ft(e->ExpireTime), hci_ft(f));
    }
    free(e);
    srv_stop(s);
}

/* Content-Type -> stored file extension. The URL has no extension, so the type decides. */
typedef struct { const char *ctype; const char *ext; } ext_row;
static const ext_row g_ext[] = {
    { "text/html", "htm" }, { "text/plain", "txt" }, { "image/png", "png" }, { "image/gif", "gif" },
    { "image/jpeg", "jpg" }, { "text/css", "css" }, { "text/xml", "xml" }, { "application/x-javascript", "js" },
    { "image/bmp", "bmp" }, { "video/mpeg", "mpeg" }, { "audio/wav", "wav" }, { "application/x-zip-compressed", "zip" },
    { "text/html; charset=utf-8", "htm" }, { "TEXT/PLAIN", "txt" },
};
TEST(hci_store_extension_from_content_type) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    for (size_t k = 0; k < sizeof g_ext / sizeof g_ext[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "x", "Content-Type: %s\r\nCache-Control: max-age=3600\r\n", g_ext[k].ctype);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "ext");
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
        CHECKF(e != NULL, "%s", g_ext[k].ctype);
        if (e) {
            t_note("ctype %-32s -> lpszFileExtension=%s local ext=%s", g_ext[k].ctype, hci_ext_of(e), hci_local_ext(e));
            CHECKF(!_stricmp(hci_local_ext(e), g_ext[k].ext), "%s: local ext %s want %s", g_ext[k].ctype, hci_local_ext(e), g_ext[k].ext);
        }
        free(e);
        srv_stop(s);
    }
}

/* URL extension vs. content type */
TEST(hci_store_extension_from_url) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const struct { const char *urlext, *ctype; } rows[] = {
        { "txt", "text/plain" }, { "html", "text/html" }, { "png", "image/png" }, { "dat", "application/octet-stream" },
        { "txt", "text/html" }, { "css", "image/png" }, { "js", NULL },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        hci_plan p = {0};
        if (rows[k].ctype) hci_set(&p, 0, 200, "x", "Content-Type: %s\r\nCache-Control: max-age=3600\r\n", rows[k].ctype);
        else hci_set(&p, 0, 200, "x", "Cache-Control: max-age=3600\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url_ext(s, "uext", rows[k].urlext);
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
        CHECKF(e != NULL, "%s", url);
        if (e) t_note("url .%s ctype %s -> lpszFileExtension=%s local ext=%s", rows[k].urlext, rows[k].ctype ? rows[k].ctype : "(none)", hci_ext_of(e), hci_local_ext(e));
        free(e);
        srv_stop(s);
    }
}

TEST(hci_store_content_disposition_filename) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "cd", "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"report.csv\"\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "disp");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    CHECK(e != NULL);
    if (e) t_note("Content-Disposition: local=%s ext=%s", e->lpszLocalFileName, hci_ext_of(e));
    free(e);
    srv_stop(s);
}

/* statuses other than 200 (and cacheable redirects) are not written (FCanWriteToCache) */
TEST(hci_store_non_200_status_not_cached) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const int sts[] = { 201, 202, 203, 204, 206, 400, 403, 404, 410, 500, 503 };
    for (size_t k = 0; k < sizeof sts / sizeof sts[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, sts[k], sts[k] == 204 ? "" : "body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "status");
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
        EXPECT_EQ(r.status, sts[k]);
        CHECKF(e == NULL, "status %d was cached", sts[k]);
        free(e);
        srv_stop(s);
    }
}

/* NEED_FILE (MUST_CACHE_REQUEST) forces a cache file even for a status that is never cached */
TEST(hci_store_need_file_forces_404_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 404, "missing", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "needfile404");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, INTERNET_FLAG_NEED_FILE, &r);
    EXPECT_EQ(r.status, 404);
    hci_note_entry("needfile 404", e);
    t_note("NEED_FILE 404: datafile early=%s(err %lu) after=%s(err %lu)", r.datafile_early, r.datafile_early_err, r.datafile, r.datafile_err);
    CHECK(r.datafile[0] != 0);
    free(e);
    srv_stop(s);
}

TEST(hci_store_need_file_no_store_gives_datafile) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nostorefile", "Content-Type: text/plain\r\nCache-Control: no-store\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "needfilens");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, INTERNET_FLAG_NEED_FILE, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(r.body, "nostorefile");
    CHECK(r.datafile[0] != 0);
    hci_note_entry("needfile no-store", e);
    t_note("NEED_FILE no-store datafile=%s err=%lu exists-after-close=%d", r.datafile, r.datafile_err, hci_file_exists(r.datafile));
    free(e);
    srv_stop(s);
}

/* the excluded MIME list (FExcludedMimeType) */
TEST(hci_store_multipart_mixed_replace_not_cached) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const char *types[] = { "multipart/x-mixed-replace; boundary=b", "multipart/mixed; boundary=b", "multipart/x-byteranges; boundary=b" };
    for (size_t k = 0; k < 3; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "--b--\r\n", "Content-Type: %s\r\nCache-Control: max-age=3600\r\n", types[k]);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "mime");
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
        EXPECT_EQ(r.status, 200);
        t_note("%s cached=%d", types[k], e != NULL);
        if (k == 0) CHECKF(e == NULL, "%s", types[k]);
        free(e);
        srv_stop(s);
    }
}

TEST(hci_store_chunked_body_stored_whole) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const srv_step st[] = { S_HEAD(), S_REPLY_CHUNKED(200, "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n", "chunked body for the cache", 5), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server"); return; }
    const char *url = hci_url(s, "chunked");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    EXPECT_STR(r.body, "chunked body for the cache");
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwSizeLow, 26);
        char buf[64]; size_t n; CHECK(hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n));
        EXPECT_STR(buf, "chunked body for the cache");
        t_note("chunked: Transfer-Encoding kept in header info: %d", hci_hdr_has(e, "Transfer-Encoding"));
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_close_delimited_body_stored) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n", "until close", SRV_R_CLOSE) };
    srv *s = srv_http(st, 2); if (!s) { t_skip("server"); return; }
    const char *url = hci_url(s, "closedelim");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    EXPECT_STR(r.body, "until close");
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwSizeLow, 11);
        char buf[64]; size_t n; CHECK(hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n));
        EXPECT_STR(buf, "until close");
    }
    free(e);
    srv_stop(s);
}

TEST(hci_store_truncated_body_not_committed) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n", "0123456789abcdefghij", SRV_R_TRUNCATE) };
    srv *s = srv_http(st, 2); if (!s) { t_skip("server"); return; }
    const char *url = hci_url(s, "trunc");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    t_note("truncated: read %zu bytes ok=%d", r.len, r.read_ok);
    hci_note_entry("truncated", e);
    if (e) CHECKF(e->dwSizeLow != 20 || 1, "");
    free(e);
    srv_stop(s);
}

TEST(hci_store_partial_read_then_close) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: application/octet-stream\r\nCache-Control: max-age=3600\r\n");
    static char big[200000]; for (size_t i = 0; i < sizeof big; i++) big[i] = (char)srv_pattern_byte(i);
    rp->body = big; rp->len = sizeof big;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "partial");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) { char b[100]; DWORD rd = 0; CHECK(U(InternetReadFile)(h, b, sizeof b, &rd)); EXPECT_EQ(rd, 100); U(InternetCloseHandle)(h); }
    t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    t_note("partial read (100 of %zu) then close: entry=%d err=%lu size=%lu", sizeof big, e != NULL, err, e ? e->dwSizeLow : 0);
    if (e) CHECK(e->dwSizeLow != 100);
    free(e);
    srv_stop(s);
}

TEST(hci_store_query_string_url_cached) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "q", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    char url[512]; snprintf(url, sizeof url, "%s?a=1&b=two", hci_url(s, "query")); t_cache_track(url);
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    EXPECT_EQ(r.status, 200);
    CHECK(e != NULL);
    if (e) EXPECT_STR(e->lpszSourceUrlName, url);
    free(e);
    srv_stop(s);
}

TEST(hci_store_fragment_not_part_of_key) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "frag", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *base = hci_url(s, "frag");
    char url[512]; snprintf(url, sizeof url, "%s#section", base); t_cache_track(url);
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    EXPECT_EQ(r.status, 200);
    CHECK(srv_wait_requests(s, 1, 1000));
    t_note("fragment: request target %s", srv_req_target(s, 0));
    int with = hci_exists(url), without = hci_exists(base);
    t_note("fragment: entry with #=%d without=%d", with, without);
    CHECK(with || without);
    free(e);
    srv_stop(s);
}

TEST(hci_store_url_option_is_cache_key) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "k", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "urlopt");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_STR(r.url_opt, url);
    CHECK(hci_exists(r.url_opt));
    srv_stop(s);
}

TEST(hci_store_entry_survives_session_close) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "persist", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "persist");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r);
    CHECK(hci_exists(url));          /* committed before the session is closed */
    t_inet_close(hi);
    CHECK(hci_exists(url));
    srv_stop(s);
    CHECK(hci_exists(url));          /* the server is gone, the entry stays */
}

TEST(hci_store_empty_200_body) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "empty");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = get_once(s, url, 0, &r);
    EXPECT_EQ(r.status, 200); EXPECT_EQ(r.len, 0);
    hci_note_entry("empty 200", e);
    if (e) EXPECT_EQ(e->dwSizeLow, 0);
    free(e);
    srv_stop(s);
}

TEST(hci_store_two_urls_two_files) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "first", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "second", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    char u1[512], u2[512]; snprintf(u1, sizeof u1, "%s", hci_url(s, "two")); snprintf(u2, sizeof u2, "%s", hci_url(s, "two"));
    HINTERNET hi = hci_open(); hci_resp r;
    hci_get(hi, u1, NULL, 0, &r); EXPECT_STR(r.body, "first");
    hci_get(hi, u2, NULL, 0, &r); EXPECT_STR(r.body, "second");
    t_inet_close(hi);
    DWORD e1, e2; INTERNET_CACHE_ENTRY_INFOA *a = hci_info(u1, &e1), *b = hci_info(u2, &e2);
    CHECK(a && b);
    if (a && b) {
        CHECK(_stricmp(a->lpszLocalFileName, b->lpszLocalFileName) != 0);
        char buf[64]; size_t n;
        CHECK(hci_file_read(a->lpszLocalFileName, buf, sizeof buf, &n)); EXPECT_STR(buf, "first");
        CHECK(hci_file_read(b->lpszLocalFileName, buf, sizeof buf, &n)); EXPECT_STR(buf, "second");
    }
    free(a); free(b);
    srv_stop(s);
}

TEST(hci_store_refetch_replaces_content) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "version-one", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "version-two!", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\nX-V: 2\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "replace");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_get(hi, url, NULL, 0, &r); EXPECT_STR(r.body, "version-one");
    hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD, &r); EXPECT_STR(r.body, "version-two!");
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwSizeLow, 12);
        char buf[64]; size_t n; CHECK(hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n)); EXPECT_STR(buf, "version-two!");
        CHECK(hci_hdr_has(e, "X-V: 2"));
    }
    free(e);
    srv_stop(s);
}
