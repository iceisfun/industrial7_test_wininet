/* hci_seed.c - the HTTP read path over entries created with the URL cache API (CreateUrlCacheEntry +
 * CommitUrlCacheEntry), and what a cache-served request handle answers (HttpQueryInfo, QueryDataAvailable,
 * InternetSetFilePointer, wide cache API views of HTTP-written entries).
 * Decomp: GetFromCachePreNetIO@0x27138 / IsExpired@0xc7d88 (ExpireTime decides freshness), CommitUrlCacheEntryW@0xd1820.
 * VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

/* create + commit an entry for url with body and raw header blob; expire = now + exp_sec (0 = none) */
static int seed(const char *url, const char *body, const char *hdrs, LONGLONG exp_sec, LONGLONG lm_sec) {
    char path[MAX_PATH + 1];
    if (!U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0)) return 0;
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD w; WriteFile(f, body, (DWORD)strlen(body), &w, NULL); CloseHandle(f);
    FILETIME ex = {0}, lm = {0};
    if (exp_sec) { LONGLONG t = hci_ft_now() + exp_sec * HCI_SEC; ex.dwLowDateTime = (DWORD)t; ex.dwHighDateTime = (DWORD)(t >> 32); }
    if (lm_sec) { LONGLONG t = hci_ft_now() + lm_sec * HCI_SEC; lm.dwLowDateTime = (DWORD)t; lm.dwHighDateTime = (DWORD)(t >> 32); }
    t_cache_track(url);
    return U(CommitUrlCacheEntryA)(url, path, ex, lm, NORMAL_CACHE_ENTRY, (BYTE *)hdrs, hdrs ? (DWORD)strlen(hdrs) : 0, "txt", NULL);
}

TEST(hci_seed_fresh_entry_served_without_network) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seedfresh");
    CHECK(seed(url, "seeded-body", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Seeded: yes\r\n\r\n", 86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 0);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(r.body, "seeded-body");
    CHECK(hci_from_cache(&r));
    CHECK(strstr(r.rawhdrs, "X-Seeded: yes") != NULL);
    srv_stop(s);
}

TEST(hci_seed_expired_entry_with_etag_revalidated) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "network", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seedexp");
    CHECK(seed(url, "seeded-stale", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nETag: \"seed\"\r\n\r\n", -86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 1), 1);
    /* VM: an ETag in a header blob committed through the cache API is not used for If-None-Match */
    if (srv_req_count(s) >= 1) CHECK(srv_req_header(s, 0, "If-None-Match") == NULL);
    EXPECT_EQ(p.cond_served, 0);
    EXPECT_STR(r.body, "network");
    srv_stop(s);
}

TEST(hci_seed_expired_entry_lm_if_modified_since) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "network", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seedlm");
    CHECK(seed(url, "seeded-lm", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\n\r\n", -86400, -86400LL * 1000));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 1), 1);
    const char *ims = srv_req_count(s) ? srv_req_header(s, 0, "If-Modified-Since") : NULL;
    t_note("seeded expired entry with LastModifiedTime: If-Modified-Since=%s", ims ? ims : "(none)");
    CHECK(ims != NULL);
    /* VM: the date comes from the entry's LastModifiedTime (not the blob) and carries "; length=<size>" */
    CHECK(ims && strstr(ims, " GMT; length=9") != NULL);
    CHECK(ims && !strstr(ims, "1994"));
    EXPECT_STR(r.body, "seeded-lm");
    srv_stop(s);
}

TEST(hci_seed_expired_no_validators_unconditional) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "network-copy", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seednov");
    CHECK(seed(url, "seeded-old", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n", -86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 1), 1);
    EXPECT_STR(r.body, "network-copy");
    if (srv_req_count(s)) { CHECK(!srv_req_header(s, 0, "If-None-Match")); CHECK(!srv_req_header(s, 0, "If-Modified-Since")); }
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    if (e) { char b[64]; size_t n; hci_file_read(e->lpszLocalFileName, b, sizeof b, &n); EXPECT_STR(b, "network-copy"); }
    free(e);
    srv_stop(s);
}

TEST(hci_seed_from_cache_serves_seeded_entry) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seedoffline");
    CHECK(seed(url, "offline-seed", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n", -86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_FROM_CACHE, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 0);
    EXPECT_STR(r.body, "offline-seed");
    EXPECT_EQ(r.status, 200);
    srv_stop(s);
}

TEST(hci_seed_status_from_stored_headers) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seedstatus");
    CHECK(seed(url, "partial-ish", "HTTP/1.1 203 Non-Authoritative Information\r\nContent-Type: text/plain\r\nX-A: 1\r\n\r\n", 86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 0);
    EXPECT_EQ(r.status, 203);
    EXPECT_STR(r.body, "partial-ish");
    srv_stop(s);
}

TEST(hci_seed_no_headers_entry) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seednohdr");
    CHECK(seed(url, "headerless", NULL, 86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    t_note("seeded entry without headers: ok=%d err=%lu status=%d body=%s requests=%d", r.ok, r.err, r.status, r.body, hci_reqs(s, 0));
    CHECK(r.ok);                                      /* VM: served, but no status line to query */
    EXPECT_EQ(r.status, 0);
    EXPECT_STR(r.body, "headerless");
    EXPECT_EQ(hci_reqs(s, 0), 0);
    srv_stop(s);
}

TEST(hci_seed_reload_ignores_seeded_entry) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "from-net", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seedreload");
    CHECK(seed(url, "seeded", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nETag: \"s\"\r\n\r\n", 86400, 0));
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 1), 1);
    EXPECT_STR(r.body, "from-net");
    if (srv_req_count(s)) CHECK(!srv_req_header(s, 0, "If-None-Match"));
    srv_stop(s);
}

/* ---------------------------------------------------------------- cache-served handle behaviour */
TEST(hci_seed_cached_handle_query_info) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "query-info-body", "Content-Type: text/html\r\nCache-Control: max-age=3600\r\nX-Q: abc\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "qinfo");
    HINTERNET hi = hci_open(); hci_resp a; hci_get(hi, url, NULL, 0, &a);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char v[256]; DWORD l = sizeof v;
        CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_CONTENT_TYPE, v, &l, NULL)); EXPECT_STR(v, "text/html");
        DWORD n = 0; l = sizeof n;
        CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &n, &l, NULL)); EXPECT_EQ(n, 15);
        l = sizeof v; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_CUSTOM, strcpy(v, "X-Q"), &l, NULL)); EXPECT_STR(v, "abc");
        l = sizeof v; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_STATUS_TEXT, v, &l, NULL)); EXPECT_STR(v, "OK");
        l = sizeof v; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_VERSION, v, &l, NULL)); EXPECT_STR(v, "HTTP/1.1");
        DWORD avail = 0; CHECK(U(InternetQueryDataAvailable)(h, &avail, 0, 0));
        t_note("cache-served QueryDataAvailable=%lu", avail);
        EXPECT_EQ(avail, 15);
        char buf[64]; DWORD rd = 0; CHECK(U(InternetReadFile)(h, buf, sizeof buf, &rd)); EXPECT_EQ(rd, 15);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_seed_cached_handle_set_file_pointer) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetSetFilePointer));
    hci_plan p = {0}; hci_set(&p, 0, 200, "0123456789abcdef", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seek");
    HINTERNET hi = hci_open(); hci_resp a; hci_get(hi, url, NULL, 0, &a);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char buf[32]; DWORD rd = 0;
        EXPECT_EQ(U(InternetSetFilePointer)(h, 10, NULL, FILE_BEGIN, 0), 10);
        CHECK(U(InternetReadFile)(h, buf, 3, &rd)); buf[rd] = 0; EXPECT_STR(buf, "abc");
        SetLastError(0); DWORD rc = U(InternetSetFilePointer)(h, -5, NULL, FILE_CURRENT, 0); DWORD ec = GetLastError();
        SetLastError(0); DWORD re = U(InternetSetFilePointer)(h, -2, NULL, FILE_END, 0); DWORD ee = GetLastError();
        t_note("cache handle: FILE_CURRENT -5 -> %ld err %lu; FILE_END -2 -> %ld err %lu", (long)rc, ec, (long)re, ee);
        EXPECT_EQ(rc, (DWORD)-1); EXPECT_EQ(ec, ERROR_NEGATIVE_SEEK);   /* VM: negative distances are refused */
        EXPECT_EQ(re, (DWORD)-1); EXPECT_EQ(ee, ERROR_NEGATIVE_SEEK);
        EXPECT_EQ(U(InternetSetFilePointer)(h, 8, NULL, FILE_BEGIN, 0), 8);
        CHECK(U(InternetReadFile)(h, buf, 2, &rd)); buf[rd] = 0; EXPECT_STR(buf, "89");
        EXPECT_EQ(U(InternetSetFilePointer)(h, 14, NULL, FILE_BEGIN, 0), 14);
        CHECK(U(InternetReadFile)(h, buf, 10, &rd)); buf[rd] = 0; EXPECT_STR(buf, "ef");
        EXPECT_EQ(U(InternetSetFilePointer)(h, 0, NULL, FILE_BEGIN, 0), 0);
        CHECK(U(InternetReadFile)(h, buf, 16, &rd)); EXPECT_EQ(rd, 16);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_seed_network_handle_set_file_pointer) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetSetFilePointer));
    hci_plan p = {0}; hci_set(&p, 0, 200, "0123456789abcdef", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "seeknet");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char buf[32]; DWORD rd = 0;
        CHECK(U(InternetReadFile)(h, buf, 16, &rd)); EXPECT_EQ(rd, 16);
        EXPECT_EQ(U(InternetSetFilePointer)(h, 4, NULL, FILE_BEGIN, 0), 4);
        CHECK(U(InternetReadFile)(h, buf, 4, &rd)); buf[rd] = 0; EXPECT_STR(buf, "4567");
        U(InternetCloseHandle)(h);
    }
    h = U(InternetOpenUrlA)(hi, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (h) {
        char buf[32]; DWORD rd = 0;
        CHECK(U(InternetReadFile)(h, buf, 16, &rd));
        SetLastError(0);
        DWORD r = U(InternetSetFilePointer)(h, 4, NULL, FILE_BEGIN, 0);
        DWORD e = GetLastError();
        t_note("SetFilePointer on NO_CACHE_WRITE handle after full read: %ld err=%lu", (long)r, e);
        EXPECT_EQ(r, (DWORD)-1); EXPECT_EQ(e, ERROR_INTERNET_INVALID_OPERATION);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_seed_wide_info_of_http_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoW));
    hci_plan p = {0}; hci_set(&p, 0, 200, "wide-view", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "wide");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    WCHAR wurl[600]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 600);
    DWORD n = 0; SetLastError(0);
    CHECK(!U(GetUrlCacheEntryInfoW)(wurl, NULL, &n)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    INTERNET_CACHE_ENTRY_INFOW *w = calloc(1, n + 16);
    CHECK(U(GetUrlCacheEntryInfoW)(wurl, w, &n));
    EXPECT_WSTR(w->lpszSourceUrlName, wurl);
    EXPECT_EQ(w->dwSizeLow, 9);
    CHECK(w->CacheEntryType & NORMAL_CACHE_ENTRY);
    char loc[MAX_PATH + 1]; WideCharToMultiByte(CP_ACP, 0, w->lpszLocalFileName, -1, loc, sizeof loc, NULL, NULL);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *a = hci_info(url, &err);
    if (a) EXPECT_STR(loc, a->lpszLocalFileName);
    free(a); free(w);
    srv_stop(s);
}

TEST(hci_seed_info_ex_of_http_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoExA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "info-ex", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "infoex");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    char buf[8192]; INTERNET_CACHE_ENTRY_INFOA *e = (void *)buf; DWORD n = sizeof buf;
    CHECK(U(GetUrlCacheEntryInfoExA)(url, e, &n, NULL, NULL, NULL, 0));
    EXPECT_STR(e->lpszSourceUrlName, url);
    EXPECT_EQ(e->dwSizeLow, 7);
    srv_stop(s);
}

TEST(hci_seed_set_entry_info_expire_makes_stale) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "v1", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "v2", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "setexp");
    HINTERNET hi = hci_open(); hci_resp a, b; hci_get(hi, url, NULL, 0, &a);
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci;
    LONGLONG t = hci_ft_now() - HCI_DAY; ci.ExpireTime.dwLowDateTime = (DWORD)t; ci.ExpireTime.dwHighDateTime = (DWORD)(t >> 32);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_EXPTIME_FC));
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "v2");
    srv_stop(s);
}

TEST(hci_seed_set_entry_info_expire_makes_fresh) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "v1", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    hci_set(&p, 1, 200, "v2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "setfresh");
    HINTERNET hi = hci_open(); hci_resp a, b; hci_get(hi, url, NULL, 0, &a);
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci;
    LONGLONG t = hci_ft_now() + HCI_DAY; ci.ExpireTime.dwLowDateTime = (DWORD)t; ci.ExpireTime.dwHighDateTime = (DWORD)(t >> 32);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_EXPTIME_FC));
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "v1");
    srv_stop(s);
}

TEST(hci_seed_httpopenrequest_get_cached_like_openurl) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "via-sendrequest", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "net", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "sendreq");
    HINTERNET hi = hci_open(); hci_resp a, b, c;
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &a);
    CHECK(hci_exists(url));
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &b);
    hci_get(hi, url, NULL, 0, &c);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "via-sendrequest");
    EXPECT_STR(c.body, "via-sendrequest");
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}

TEST(hci_seed_cached_response_headers_equal_stored) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "same", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\nX-One: 1\r\nX-Two: 2\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "samehdrs");
    HINTERNET hi = hci_open(); hci_resp a, b; hci_get(hi, url, NULL, 0, &a); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        char stored[4096]; size_t n = e->dwHeaderInfoSize < sizeof stored - 1 ? e->dwHeaderInfoSize : sizeof stored - 1;
        memcpy(stored, e->lpHeaderInfo, n); stored[n] = 0;
        t_note("stored=%zu raw(cache)=%zu raw(net)=%zu", strlen(stored), strlen(b.rawhdrs), strlen(a.rawhdrs));
        CHECK(strstr(b.rawhdrs, "X-One: 1\r\n") && strstr(b.rawhdrs, "X-Two: 2\r\n"));
        CHECK(!strncmp(b.rawhdrs, "HTTP/1.1 200 OK\r\n", 17));
    }
    free(e);
    srv_stop(s);
}
