/* hci_api.c - the cache API's view of entries written by HTTP: the stored header blob (what is kept, order, exact
 * bytes), local file naming, InternetLockRequestFile/InternetUnlockRequestFile, use counts with open handles, reads
 * from a cache-served handle, and an interrupted download (sparse entries).
 * Decomp (wininet 10.0.19041): LocalEndCacheWrite@0xe6c0 (GenerateRawResponseHeadersForCache builds the blob,
 *   GenerateVaryRequestHeadersForCache, IsPartialResponseCacheable -> type 0x10000), GetFromCachePreNetIoLoop@0x87140
 *   (a sparse entry whose file size equals the entry size sends "Range: bytes=<size>-" plus If-Range).
 * VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

/* ---------------------------------------------------------------- the stored header blob */
TEST(hci_api_blob_exact_bytes) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hello", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "blob");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &r);
    CHECK(e != NULL);
    if (e) {
        static const char want[] = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n";
        EXPECT_EQ(e->dwHeaderInfoSize, sizeof want - 1);
        CHECK(e->dwHeaderInfoSize == sizeof want - 1 && !memcmp(e->lpHeaderInfo, want, sizeof want - 1));
        EXPECT_EQ(strlen((const char *)e->lpHeaderInfo), e->dwHeaderInfoSize);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_api_blob_header_order_and_case) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ord", "x-lower: 1\r\nX-UPPER: 2\r\nContent-Type: text/plain\r\nX-Mixed-Case: 3\r\nCache-Control: max-age=3600\r\nX-Last: 4\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "blobord");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &r);
    CHECK(e != NULL);
    if (e) {
        const char *h = (const char *)e->lpHeaderInfo;
        hci_note_entry("order", e);
        const char *a = strstr(h, "x-lower: 1\r\n"), *b = strstr(h, "X-UPPER: 2\r\n"), *c = strstr(h, "Content-Type: text/plain\r\n"),
                   *d = strstr(h, "X-Mixed-Case: 3\r\n"), *f = strstr(h, "X-Last: 4\r\n"), *g = strstr(h, "Content-Length: 3\r\n");
        CHECK(a && b && c && d && f && g);
        if (a && b && c && d && f && g) { CHECK(a < b); CHECK(b < c); CHECK(c < d); CHECK(d < f); CHECK(f < g); }
    }
    free(e);
    srv_stop(s);
}

/* which response headers are kept in the blob */
typedef struct { const char *line; int kept; } blobrow;     /* kept: 1 yes, 0 no, -1 note */
static const blobrow g_blob[] = {
    { "X-Custom: c", 1 }, { "ETag: \"b\"", 1 }, { "Last-Modified: Mon, 01 Jan 2001 00:00:00 GMT", -1 }, { "Expires: Thu, 01 Dec 2033 16:00:00 GMT", -1 },
    { "Date: Mon, 01 Jan 2001 00:00:00 GMT", -1 }, { "Server: i7", -1 }, { "Pragma: x-private", -1 }, { "Age: 5", -1 },
    { "Vary: X-Something", -1 }, { "Set-Cookie: hcib=1; Path=/blobtest", 0 }, { "Set-Cookie2: x=1", -1 }, { "Keep-Alive: timeout=5", -1 },
    { "Accept-Ranges: bytes", -1 }, { "P3P: CP=\"x\"", -1 }, { "Strict-Transport-Security: max-age=1", -1 }, { "X-Frame-Options: DENY", -1 },
    { "WWW-Authenticate: Basic realm=\"r\"", -1 }, { "Proxy-Connection: keep-alive", -1 }, { "Content-Language: en", -1 }, { "Content-Location: /x", -1 },
    { "Location: /elsewhere", -1 }, { "Refresh: 5", -1 }, { "Link: </s.css>; rel=preload", -1 }, { "Content-Disposition: inline", -1 },
};
TEST(hci_api_blob_kept_headers_table) {
    REQUIRE(U(InternetOpenUrlA));
    for (size_t k = 0; k < sizeof g_blob / sizeof g_blob[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "kept", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n%s\r\n", g_blob[k].line);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "blobkeep");
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, INTERNET_FLAG_NO_COOKIES, &r);
        CHECKF(e != NULL, "[%s] not stored", g_blob[k].line);
        if (e) {
            char line[200]; snprintf(line, sizeof line, "%s\r\n", g_blob[k].line);
            int kept = hci_hdr_has(e, line);
            t_note("blob keeps [%s]: %d", g_blob[k].line, kept);
            if (g_blob[k].kept >= 0) CHECKF(kept == g_blob[k].kept, "[%s] kept=%d", g_blob[k].line, kept);
            CHECKF(hci_hdr_has(e, "Content-Type: text/plain\r\n"), "[%s] Content-Type lost", g_blob[k].line);
            CHECKF(!hci_hdr_has(e, "Cache-Control"), "[%s] Cache-Control kept", g_blob[k].line);
        }
        free(e);
        srv_stop(s);
    }
}

TEST(hci_api_blob_content_length_regenerated) {
    REQUIRE(U(InternetOpenUrlA));
    /* close-delimited: no length on the wire; chunked: Transfer-Encoding on the wire */
    static const srv_step st1[] = { S_HEAD(), S_REPLYF(200, "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n", "closed-body", SRV_R_CLOSE) };
    srv *s = srv_http(st1, 2); if (!s) { t_skip("server"); return; }
    const char *url = hci_url(s, "cdlen");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &r);
    if (e) {
        hci_note_entry("close-delimited", e);
        t_note("close-delimited blob has Content-Length: 11 -> %d", hci_hdr_has(e, "Content-Length: 11"));
        EXPECT_EQ(e->dwSizeLow, 11);
    }
    CHECK(e != NULL);
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- local file names */
typedef struct { const char *path; const char *ctype; const char *leaf_prefix; const char *ext; } namerow;  /* NULL = note only */
TEST(hci_api_local_file_name_table) {
    REQUIRE(U(InternetOpenUrlA));
    static const namerow rows[] = {
        { "/d1/%s.txt", "text/plain", "%s[", "txt" },
        { "/d1/d2/%s.htm", "text/html", "%s[", "htm" },
        { "/%s.TXT", "text/plain", "%s[", NULL },
        { "/%s.tar.gz", "application/octet-stream", NULL, NULL },
        { "/%s", "application/octet-stream", NULL, NULL },
        { "/%s/", "text/html", NULL, NULL },
        { "/%s?x=1&y=2", "text/plain", NULL, "txt" },
        { "/%s.txt?x=1", "text/plain", NULL, "txt" },
        { "/a%%20b%s.txt", "text/plain", NULL, "txt" },
        { "/%s.json", "application/json", NULL, NULL },
        { "/%s.unknownext", "application/x-unknown-i7", NULL, NULL },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "named", "Content-Type: %s\r\nCache-Control: max-age=3600\r\n", rows[k].ctype);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *u = t_uniq("nm");
        char path[300], url[512]; snprintf(path, sizeof path, rows[k].path, u);
        snprintf(url, sizeof url, "%s", srv_url(s, path)); t_cache_track(url);
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &r);
        CHECKF(e != NULL, "%s not stored", path);
        if (e) {
            const char *leaf = strrchr(e->lpszLocalFileName, '\\'); leaf = leaf ? leaf + 1 : e->lpszLocalFileName;
            t_note("path %-28s ctype %-28s -> leaf %s", path, rows[k].ctype, leaf);
            CHECKF(hci_file_eq(e->lpszLocalFileName, "named", 5), "%s file content", path);
            if (rows[k].leaf_prefix) { char want[200]; snprintf(want, sizeof want, rows[k].leaf_prefix, u); CHECKF(!_strnicmp(leaf, want, strlen(want)), "%s leaf %s want %s*", path, leaf, want); }
            if (rows[k].ext) CHECKF(!_stricmp(hci_local_ext(e), rows[k].ext), "%s ext %s want %s", path, hci_local_ext(e), rows[k].ext);
            CHECK(strstr(e->lpszLocalFileName, "\\INetCache\\IE\\") != NULL);
            CHECK(!strchr(leaf, '?') && !strchr(leaf, '/') && !strchr(leaf, ':'));
        }
        free(e);
        srv_stop(s);
    }
}

TEST(hci_api_same_leaf_two_urls) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "first", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "second", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *u = t_uniq("leaf");
    char p1[200], p2[200], u1[512], u2[512];
    snprintf(p1, sizeof p1, "/x/%s.txt", u); snprintf(p2, sizeof p2, "/y/%s.txt", u);
    snprintf(u1, sizeof u1, "%s", srv_url(s, p1)); snprintf(u2, sizeof u2, "%s", srv_url(s, p2)); t_cache_track(u1); t_cache_track(u2);
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e1 = hci_fetch(u1, NULL, 0, &a), *e2 = hci_fetch(u2, NULL, 0, &b);
    CHECK(e1 && e2);
    if (e1 && e2) {
        t_note("same leaf: %s | %s", e1->lpszLocalFileName, e2->lpszLocalFileName);
        CHECK(_stricmp(e1->lpszLocalFileName, e2->lpszLocalFileName) != 0);
        CHECK(hci_file_eq(e1->lpszLocalFileName, "first", 5));
        CHECK(hci_file_eq(e2->lpszLocalFileName, "second", 6));
    }
    free(e1); free(e2);
    srv_stop(s);
}

TEST(hci_api_refetch_new_local_file) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "gen-one", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "gen-two", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "regen");
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e1 = hci_fetch(url, NULL, 0, &a);
    char f1[MAX_PATH + 1] = ""; if (e1) snprintf(f1, sizeof f1, "%s", e1->lpszLocalFileName);
    INTERNET_CACHE_ENTRY_INFOA *e2 = hci_fetch(url, NULL, INTERNET_FLAG_RELOAD, &b);
    CHECK(e1 && e2);
    if (e2) {
        t_note("refetch: %s -> %s; old file exists=%d", f1, e2->lpszLocalFileName, hci_file_exists(f1));
        CHECK(hci_file_eq(e2->lpszLocalFileName, "gen-two", 7));
        if (_stricmp(f1, e2->lpszLocalFileName)) { int gone = 0; for (int i = 0; i < 20 && !gone; i++) { gone = !hci_file_exists(f1); if (!gone) Sleep(50); } CHECK(gone); }
    }
    free(e1); free(e2);
    srv_stop(s);
}

/* ---------------------------------------------------------------- InternetLockRequestFile */
TEST(hci_api_lock_request_file_network) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetLockRequestFile)); REQUIRE(U(InternetUnlockRequestFile));
    hci_plan p = {0}; hci_set(&p, 0, 200, "locked-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "lockreq");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    HANDLE lock = NULL; char df[MAX_PATH + 1] = "";
    if (h) {
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        DWORD l = sizeof df; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, df, &l));
        SetLastError(0);
        CHECK(U(InternetLockRequestFile)(h, &lock));
        CHECK(lock != NULL);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    CHECK(hci_exists(url));
    CHECK(hci_file_eq(df, "locked-body", 11));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    if (e) { t_note("use count with a request-file lock after close: %lu", e->dwUseCount); EXPECT_EQ(e->dwUseCount, 1); }
    free(e);
    if (lock) {
        SetLastError(0); BOOL del = U(DeleteUrlCacheEntryA)(url); DWORD de = GetLastError();
        t_note("DeleteUrlCacheEntry with a request-file lock: ok=%d err=%lu; entry=%d file=%d", del, de, hci_exists(url), hci_file_exists(df));
        CHECK(!del); EXPECT_EQ(de, ERROR_SHARING_VIOLATION);
        CHECK(U(InternetUnlockRequestFile)(lock));
        t_note("after unlock: entry=%d file=%d", hci_exists(url), hci_file_exists(df));
    }
    srv_stop(s);
}

TEST(hci_api_lock_request_file_before_read) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetLockRequestFile));
    hci_plan p = {0}; hci_set(&p, 0, 200, "early-lock", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "lockearly");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        HANDLE lock = NULL; SetLastError(0);
        BOOL ok = U(InternetLockRequestFile)(h, &lock);
        t_note("lock before reading: ok=%d err=%lu", ok, GetLastError());
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
        if (ok && lock) { CHECK(U(InternetUnlockRequestFile)(lock)); }
    }
    t_inet_close(hi);
    CHECK(hci_exists(url));
    srv_stop(s);
}

TEST(hci_api_lock_request_file_no_cache_write) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetLockRequestFile));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nolock", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "locknocw");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    CHECK(h != NULL);
    if (h) {
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        HANDLE lock = (HANDLE)0x1; SetLastError(0);
        BOOL ok = U(InternetLockRequestFile)(h, &lock);
        DWORD e = GetLastError();
        t_note("lock on NO_CACHE_WRITE handle: ok=%d err=%lu lock=%p", ok, e, lock);
        if (ok && lock) U(InternetUnlockRequestFile)(lock);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_api_lock_request_file_cache_hit) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetLockRequestFile));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hit-lock", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "lockhit");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        HANDLE lock = NULL; CHECK(U(InternetLockRequestFile)(h, &lock));
        HANDLE lock2 = NULL; CHECK(U(InternetLockRequestFile)(h, &lock2));
        CHECK(lock != NULL && lock2 != NULL);
        U(InternetCloseHandle)(h);
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
        if (e) t_note("two request-file locks after close: use count %lu", e->dwUseCount);
        free(e);
        if (lock) CHECK(U(InternetUnlockRequestFile)(lock));
        if (lock2) CHECK(U(InternetUnlockRequestFile)(lock2));
        e = hci_info(url, &err);
        if (e) EXPECT_EQ(e->dwUseCount, 0);
        free(e);
    }
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_api_lock_request_file_bad_handles) {
    REQUIRE(U(InternetLockRequestFile)); REQUIRE(U(InternetUnlockRequestFile));
    HINTERNET hi = hci_open();
    HANDLE lock = NULL; SetLastError(0);
    CHECK(!U(InternetLockRequestFile)(hi, &lock));
    DWORD e1 = GetLastError();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    SetLastError(0); CHECK(!U(InternetLockRequestFile)(hc, &lock)); DWORD e2 = GetLastError();
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, 0, 0);
    SetLastError(0); BOOL r3 = U(InternetLockRequestFile)(hr, &lock); DWORD e3 = GetLastError();
    t_note("InternetLockRequestFile: session err=%lu connect err=%lu unsent request ok=%d err=%lu", e1, e2, r3, e3);
    CHECK(!r3);
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
}

/* ---------------------------------------------------------------- open handles and the use count */
TEST(hci_api_use_count_two_cache_handles) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "two-handles", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "use2");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = hci_open();
    HINTERNET h1 = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0), h2 = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h1 && h2);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    if (e) { t_note("use count with two cache-read handles: %lu", e->dwUseCount); EXPECT_EQ(e->dwUseCount, 2); }
    free(e);
    if (h1) U(InternetCloseHandle)(h1);
    e = hci_info(url, &err);
    if (e) EXPECT_EQ(e->dwUseCount, 1);
    free(e);
    if (h2) U(InternetCloseHandle)(h2);
    e = hci_info(url, &err);
    if (e) EXPECT_EQ(e->dwUseCount, 0);
    free(e);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_api_use_count_during_download) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: application/octet-stream\r\nCache-Control: max-age=3600\r\n");
    static char big[50000]; for (size_t i = 0; i < sizeof big; i++) big[i] = (char)srv_pattern_byte(i);
    rp->body = big; rp->len = sizeof big;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "usedl");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char b[1000]; DWORD rd = 0; CHECK(U(InternetReadFile)(h, b, sizeof b, &rd));
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
        t_note("entry while the download is in progress: exists=%d err=%lu", e != NULL, err);
        CHECK(e == NULL);
        free(e);
        SetLastError(0); BOOL del = U(DeleteUrlCacheEntryA)(url);
        t_note("DeleteUrlCacheEntry during the download: ok=%d err=%lu", del, GetLastError());
        size_t tot = rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) tot += rd;
        EXPECT_EQ(tot, sizeof big);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    t_note("after a delete during the download, entry exists=%d", e != NULL);
    if (e) EXPECT_EQ(e->dwSizeLow, sizeof big);
    free(e);
    srv_stop(s);
}

TEST(hci_api_retrieve_during_cache_read) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(RetrieveUrlCacheEntryFileA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "retr-open", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "retropen");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    char buf[4096]; INTERNET_CACHE_ENTRY_INFOA *e = (void *)buf; DWORD n = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, e, &n, 0));
    EXPECT_EQ(e->dwUseCount, 2);
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    if (h) U(InternetCloseHandle)(h);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *x = hci_info(url, &err);
    if (x) EXPECT_EQ(x->dwUseCount, 0);
    free(x);
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_api_unlock_without_lock) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nolock", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "unlockfree");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    SetLastError(0); BOOL ok = U(UnlockUrlCacheEntryFileA)(url, 0);
    t_note("UnlockUrlCacheEntryFile on an unlocked HTTP entry: ok=%d err=%lu", ok, GetLastError());
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) EXPECT_EQ(e->dwUseCount, 0);
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- reading from a cache-served handle */
TEST(hci_api_cache_read_small_pieces) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "abcdefghijklmnopqrstuvwxyz0123456789", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "pieces");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char all[64]; size_t tot = 0; DWORD rd = 0; int calls = 0;
        for (int g = 0; g < 100; g++) { if (!U(InternetReadFile)(h, all + tot, 1, &rd) || !rd) break; tot += rd; calls++; }
        all[tot] = 0;
        EXPECT_EQ(tot, 36); EXPECT_EQ(calls, 36);
        EXPECT_STR(all, "abcdefghijklmnopqrstuvwxyz0123456789");
        rd = 77; CHECK(U(InternetReadFile)(h, all, sizeof all, &rd)); EXPECT_EQ(rd, 0);
        DWORD av = 99; CHECK(U(InternetQueryDataAvailable)(h, &av, 0, 0)); EXPECT_EQ(av, 0);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_api_cache_read_large_body) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: application/octet-stream\r\nCache-Control: max-age=3600\r\n");
    static char big[150000]; for (size_t i = 0; i < sizeof big; i++) big[i] = (char)srv_pattern_byte(i);
    rp->body = big; rp->len = sizeof big;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "bigcache");
    hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a); free(e);
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        DWORD av = 0; CHECK(U(InternetQueryDataAvailable)(h, &av, 0, 0));
        t_note("cache-served 150000-byte body: first QueryDataAvailable=%lu", av);
        CHECK(av > 0 && av <= sizeof big);
        char *buf = malloc(sizeof big + 16); size_t tot = 0; DWORD rd;
        for (int g = 0; g < 10000; g++) { if (!U(InternetReadFile)(h, buf + tot, 7000, &rd) || !rd) break; tot += rd; }
        EXPECT_EQ(tot, sizeof big);
        CHECK(srv_pattern_check(buf, tot, 0));
        DWORD f = 0, l = sizeof f; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_REQUEST_FLAGS, &f, &l));
        CHECK(f & INTERNET_REQFLAG_FROM_CACHE);
        free(buf);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_api_cache_handle_read_ex) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetReadFileExA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "read-ex-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "readex");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char buf[64]; INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib); ib.dwStructSize = sizeof ib; ib.lpvBuffer = buf; ib.dwBufferLength = sizeof buf - 1;
        CHECK(U(InternetReadFileExA)(h, &ib, IRF_SYNC, 0));
        EXPECT_EQ(ib.dwBufferLength, 12);
        buf[ib.dwBufferLength] = 0; EXPECT_STR(buf, "read-ex-body");
        ib.dwBufferLength = sizeof buf - 1;
        CHECK(U(InternetReadFileExA)(h, &ib, IRF_SYNC, 0));
        EXPECT_EQ(ib.dwBufferLength, 0);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_api_cache_timestamps_on_handles) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ts", "Content-Type: text/plain\r\nLast-Modified: Mon, 01 Jan 2001 00:00:00 GMT\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "tsboth");
    HINTERNET hi = hci_open();
    for (int k = 0; k < 2; k++) {       /* 0: network download, 1: cache hit */
        HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
        CHECK(h != NULL);
        if (!h) continue;
        INTERNET_CACHE_TIMESTAMPS ts; memset(&ts, 0, sizeof ts); DWORD l = sizeof ts; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_CACHE_TIMESTAMPS, &ts, &l);
        t_note("CACHE_TIMESTAMPS (%s): ok=%d err=%lu len=%lu exp=%llx lm=%llx", k ? "cache" : "net", ok, GetLastError(), l, hci_ft(ts.ftExpires), hci_ft(ts.ftLastModified));
        CHECK(ok);
        EXPECT_EQ(hci_ft(ts.ftExpires), hci_ft_utc(2033, 12, 1, 16, 0, 0));
        EXPECT_EQ(hci_ft(ts.ftLastModified), hci_ft_utc(2001, 1, 1, 0, 0, 0));
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_api_cache_timestamps_no_headers) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nots", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "tsnone");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        INTERNET_CACHE_TIMESTAMPS ts; memset(&ts, 0x5a, sizeof ts); DWORD l = sizeof ts; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_CACHE_TIMESTAMPS, &ts, &l);
        t_note("CACHE_TIMESTAMPS without Expires/LM: ok=%d err=%lu len=%lu exp=%llx lm=%llx", ok, GetLastError(), l, hci_ft(ts.ftExpires), hci_ft(ts.ftLastModified));
        CHECK(ok);
        EXPECT_EQ(hci_ft(ts.ftExpires), 0);
        EXPECT_EQ(hci_ft(ts.ftLastModified), 0);
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_api_datafile_name_wide_matches) {
    REQUIRE(U(InternetOpenUrlW)); REQUIRE(U(InternetQueryOptionW));
    hci_plan p = {0}; hci_set(&p, 0, 200, "wide-df", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "widedf");
    WCHAR wurl[600]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 600);
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlW)(hi, wurl, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        WCHAR w[MAX_PATH + 1]; DWORD lw = sizeof w; CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_DATAFILE_NAME, w, &lw));
        EXPECT_EQ(lw, wcslen(w));
        char a[MAX_PATH + 1]; DWORD la = sizeof a; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, a, &la));
        char conv[MAX_PATH + 1]; WideCharToMultiByte(CP_ACP, 0, w, -1, conv, sizeof conv, NULL, NULL);
        EXPECT_STR(conv, a);
        WCHAR tiny[4]; DWORD lt = sizeof tiny; SetLastError(0);
        CHECK(!U(InternetQueryOptionW)(h, INTERNET_OPTION_DATAFILE_NAME, tiny, &lt));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        t_note("DATAFILE_NAME W too small: needed=%lu (wcslen %zu)", lt, wcslen(w));
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    CHECK(hci_exists(url));
    srv_stop(s);
}

/* ---------------------------------------------------------------- interrupted downloads */
TEST(hci_api_interrupted_download_resume) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: application/octet-stream\r\nAccept-Ranges: bytes\r\nETag: \"rng\"\r\nLast-Modified: Mon, 01 Jan 2001 00:00:00 GMT\r\nCache-Control: max-age=3600\r\n");
    static char big[300000]; for (size_t i = 0; i < sizeof big; i++) big[i] = (char)srv_pattern_byte(i);
    rp->body = big; rp->len = sizeof big;
    hci_reply *r2 = hci_set(&p, 1, 200, NULL, "Content-Type: application/octet-stream\r\nCache-Control: max-age=3600\r\n");
    r2->body = big; r2->len = sizeof big;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resume");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) { char b[4096]; DWORD rd = 0; CHECK(U(InternetReadFile)(h, b, sizeof b, &rd)); U(InternetCloseHandle)(h); }
    t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    hci_note_entry("interrupted download", e);
    t_note("interrupted download (Accept-Ranges + ETag): entry=%d type=0x%lx size=%lu", e != NULL, e ? e->CacheEntryType : 0, e ? e->dwSizeLow : 0);
    free(e);
    hci_resp r; HINTERNET h2 = hci_open(); hci_get(h2, url, NULL, 0, &r); t_inet_close(h2);
    hci_reqs(s, 2);
    t_note("second GET: requests=%d Range=%s If-Range=%s status=%d len=%zu", srv_req_count(s), hci_rh(s, 1, "Range") ? hci_rh(s, 1, "Range") : "-",
           hci_rh(s, 1, "If-Range") ? hci_rh(s, 1, "If-Range") : "-", r.status, r.len);
    EXPECT_EQ(r.status, 200);
    srv_stop(s);
}

/* an empty 200 still makes an entry with an empty local file */
TEST(hci_api_empty_body_entry_file) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "emptyf");
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwSizeLow, 0);
        CHECK(hci_file_exists(e->lpszLocalFileName));
        CHECK(hci_file_eq(e->lpszLocalFileName, "", 0));
        CHECK(hci_hdr_has(e, "Content-Length: 0\r\n"));
    }
    free(e);
    free(hci_fetch(url, NULL, 0, &b));
    t_note("second GET of an empty cached body: requests=%d status=%d len=%zu", hci_reqs(s, 0), b.status, b.len);
    EXPECT_EQ(b.status, 200);
    srv_stop(s);
}

/* GetUrlCacheEntryInfoEx on a cached 301 source */
TEST(hci_api_info_ex_redirect_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoExA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "ix301")); snprintf(dst, sizeof dst, "%s", hci_url(s, "ix301dst"));
    hci_set(&p, 0, 301, "", "Location: %s\r\n", dst);
    hci_set(&p, 1, 200, "dst", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_resp r; free(hci_fetch(src, NULL, 0, &r));
    char buf[8192]; INTERNET_CACHE_ENTRY_INFOA *e = (void *)buf; DWORD n = sizeof buf;
    char redir[1024] = ""; DWORD rl = sizeof redir; SetLastError(0);
    BOOL ok = U(GetUrlCacheEntryInfoExA)(src, e, &n, redir, &rl, NULL, 0);
    t_note("GetUrlCacheEntryInfoEx(301 source): ok=%d err=%lu url=%s type=0x%lx redirect=[%s] rl=%lu", ok, GetLastError(), ok ? e->lpszSourceUrlName : "", ok ? e->CacheEntryType : 0, redir, rl);
    CHECK(ok);
    if (ok) {
        EXPECT_STR(e->lpszSourceUrlName, src);
        EXPECT_EQ(e->CacheEntryType, 0x841);
        EXPECT_EQ(e->dwSizeLow, 0);
        EXPECT_EQ(hci_ft(e->ExpireTime), 0x7fffffffffffffffLL);
        CHECK(e->lpszLocalFileName == NULL || !e->lpszLocalFileName[0] || !strcmp(hci_local_ext(e), ""));
    }
    srv_stop(s);
}

/* redirect entry types for 308 and a 302 made cacheable */
TEST(hci_api_redirect_entry_fields) {
    REQUIRE(U(InternetOpenUrlA));
    static const struct { int st; const char *extra; } rows[] = { { 301, "" }, { 308, "" }, { 302, "Cache-Control: max-age=600\r\n" }, { 307, "Expires: Thu, 01 Dec 2033 16:00:00 GMT\r\n" } };
    for (size_t k = 0; k < 4; k++) {
        hci_plan p = {0};
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "rfld")); snprintf(dst, sizeof dst, "%s", hci_url(s, "rflddst"));
        hci_set(&p, 0, rows[k].st, "", "Location: %s\r\n%s", dst, rows[k].extra);
        hci_set(&p, 1, 200, "dst", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(src, NULL, 0, &r);
        CHECKF(e != NULL, "%d not cached", rows[k].st);
        hci_note_entry("redirect", e);
        if (e) {
            CHECKF(e->CacheEntryType & REDIRECT_CACHE_ENTRY, "%d type 0x%lx", rows[k].st, e->CacheEntryType);
            char loc[600]; snprintf(loc, sizeof loc, "Location: %s\r\n", dst);
            CHECKF(hci_hdr_has(e, loc), "%d Location missing", rows[k].st);
            CHECKF(e->dwSizeLow == 0, "%d size %lu", rows[k].st, e->dwSizeLow);
        }
        free(e);
        srv_stop(s);
    }
}

/* a cache hit counts in the hit rate whatever the flag that led to it */
TEST(hci_api_hit_rate_by_flag) {
    REQUIRE(U(InternetOpenUrlA));
    static const DWORD flags[] = { 0, INTERNET_FLAG_FROM_CACHE, INTERNET_FLAG_NO_CACHE_WRITE, INTERNET_FLAG_HYPERLINK, INTERNET_FLAG_PRAGMA_NOCACHE };
    for (size_t k = 0; k < 5; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "hr", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "hrflag");
        hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e0 = hci_fetch(url, NULL, 0, &a);
        INTERNET_CACHE_ENTRY_INFOA *e1 = hci_fetch(url, NULL, flags[k], &b);
        CHECKF(hci_reqs(s, 0) == 1, "flags 0x%lx requests %d", flags[k], srv_req_count(s));
        CHECKF(!strcmp(b.body, "hr"), "flags 0x%lx body %s", flags[k], b.body);
        CHECKF(e0 && e1 && e1->dwHitRate == e0->dwHitRate + 1, "flags 0x%lx hit %lu -> %lu", flags[k], e0 ? e0->dwHitRate : 0, e1 ? e1->dwHitRate : 0);
        CHECKF(hci_from_cache(&b), "flags 0x%lx reqflags 0x%lx", flags[k], b.reqflags);
        free(e0); free(e1);
        srv_stop(s);
    }
}

/* the header-info blob can be replaced through the API: does the cache-served response follow it? */
TEST(hci_api_set_header_info_affects_cache_response) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "blobswap", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\nX-Orig: 1\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hdrswap");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    static char nb[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Swapped: yes\r\nContent-Length: 8\r\n\r\n";
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci; ci.lpHeaderInfo = nb; ci.dwHeaderInfoSize = sizeof nb - 1;
    SetLastError(0); BOOL ok = U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_HEADERINFO_FC);
    DWORD err = GetLastError();
    free(hci_fetch(url, NULL, 0, &b));
    t_note("SetUrlCacheEntryInfo(HEADERINFO_FC): ok=%d err=%lu; next response X-Swapped=%d X-Orig=%d", ok, err, strstr(b.rawhdrs, "X-Swapped") != NULL, strstr(b.rawhdrs, "X-Orig") != NULL);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "blobswap");
    srv_stop(s);
}

/* a commit through the API over an HTTP entry replaces what HTTP serves */
TEST(hci_api_commit_over_http_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(CommitUrlCacheEntryA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "from-http", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "overhttp");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_seed(url, "from-api", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Api: 1\r\n\r\n", NORMAL_CACHE_ENTRY, 86400, 0));
    free(hci_fetch(url, NULL, 0, &b));
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "from-api");
    CHECK(strstr(b.rawhdrs, "X-Api: 1") != NULL);
    srv_stop(s);
}

/* entries are per URL string: the port is part of the key, the default port is not spelled out */
TEST(hci_api_key_includes_port) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "porty", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "porty");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    char other[512]; const char *path = strchr(url + 7, '/');
    snprintf(other, sizeof other, "http://127.0.0.1:1%s", path);
    CHECK(hci_exists(url));
    CHECK(!hci_exists(other));
    char host[512]; snprintf(host, sizeof host, "http://localhost:%u%s", srv_port(s), path);
    CHECK(!hci_exists(host));
    char upper[512]; snprintf(upper, sizeof upper, "HTTP://127.0.0.1:%u%s", srv_port(s), path);
    t_note("cache key lookups: upper-case scheme exists=%d", hci_exists(upper));
    srv_stop(s);
}

/* a request through a different host spelling makes a separate entry */
TEST(hci_api_localhost_separate_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "v4", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "named-host", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hostkey");
    const char *path = strchr(url + 7, '/');
    char lh[512]; snprintf(lh, sizeof lh, "%s", srv_url_host(s, "localhost", path)); t_cache_track(lh);
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a)); free(hci_fetch(lh, NULL, 0, &b));
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "named-host");
    CHECK(hci_exists(url)); CHECK(hci_exists(lh));
    srv_stop(s);
}
