/* hci_fresh.c - freshness and revalidation: Cache-Control max-age/no-cache/no-store, Expires, Pragma, heuristic
 * freshness from Last-Modified, conditional requests (If-None-Match / If-Modified-Since) and 304 handling.
 * Decomp: CheckCacheControlHeaders@0x6bc1c (no-cache/no-store/max-age tokens, case-insensitive, every
 * Cache-Control header), IsExpired@0xc7d88 (Expires, heuristic (download-LM)/10, session rule),
 * GetFromCachePostNetIO@0x6b8b8 (304: sync time, merged headers, UrlCacheSetEntryInfoEx). VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

/* GET url twice on one session; returns number of requests the server saw */
static int twice(srv *s, const char *url, DWORD f1, DWORD f2, hci_resp *r1, hci_resp *r2) {
    HINTERNET hi = hci_open();
    hci_get(hi, url, NULL, f1, r1);
    hci_get(hi, url, NULL, f2, r2);
    t_inet_close(hi);
    return hci_reqs(s, 0);
}

TEST(hci_fresh_max_age_served_from_cache) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "fresh", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "maxage");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(a.status, 200); EXPECT_EQ(b.status, 200);
    EXPECT_STR(b.body, "fresh");
    CHECK(!hci_from_cache(&a));
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}

TEST(hci_fresh_expires_future_served_from_cache) {
    REQUIRE(U(InternetOpenUrlA));
    char d[64]; hci_http_date(d, sizeof d, 86400 * 3);
    hci_plan p = {0}; hci_set(&p, 0, 200, "exp-future", "Content-Type: text/plain\r\nExpires: %s\r\n", d);
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "expfut");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 1);
    EXPECT_STR(b.body, "exp-future");
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}

TEST(hci_fresh_expires_past_goes_to_network) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "exp-past", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "exppast");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    EXPECT_STR(b.body, "network");
    CHECK(!hci_from_cache(&b));
    if (n >= 2) {
        t_note("expired, no validators: If-Modified-Since=%s If-None-Match=%s",
               srv_req_header(s, 1, "If-Modified-Since") ? srv_req_header(s, 1, "If-Modified-Since") : "(none)",
               srv_req_header(s, 1, "If-None-Match") ? srv_req_header(s, 1, "If-None-Match") : "(none)");
        CHECK(srv_req_header(s, 1, "If-None-Match") == NULL);
    }
    srv_stop(s);
}

TEST(hci_fresh_expires_equal_date_is_expired) {
    REQUIRE(U(InternetOpenUrlA));
    char d[64]; hci_http_date(d, sizeof d, -60);
    hci_plan p = {0}; hci_set(&p, 0, 200, "a", "Content-Type: text/plain\r\nDate: %s\r\nExpires: %s\r\n", d, d);
    hci_set(&p, 1, 200, "b", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "expeq");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    EXPECT_STR(b.body, "b");
    srv_stop(s);
}

TEST(hci_fresh_expires_zero_is_expired) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "a", "Content-Type: text/plain\r\nExpires: 0\r\n");
    hci_set(&p, 1, 200, "b", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "expzero");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    t_note("Expires: 0 -> requests=%d second body=%s", n, b.body);
    EXPECT_EQ(n, 2);                                  /* VM: an unparsable Expires is stale */
    EXPECT_STR(b.body, "b");
    hci_note_entry("expires 0", e);
    free(e);
    srv_stop(s);
}

TEST(hci_fresh_etag_revalidation_304) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "original", "Content-Type: text/plain\r\nETag: \"v1\"\r\nCache-Control: max-age=0\r\n");
    hci_set(&p, 1, 200, "unconditional", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "ETag: \"v1\"\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "etag304");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    if (n >= 2) EXPECT_STR(srv_req_header(s, 1, "If-None-Match"), "\"v1\"");
    EXPECT_EQ(p.cond_served, 1);
    EXPECT_STR(b.body, "original");
    EXPECT_EQ(b.status, 200);
    t_note("after 304: reqflags=0x%lx raw=%.60s", b.reqflags, b.rawhdrs);
    EXPECT_EQ(b.reqflags, INTERNET_REQFLAG_FROM_CACHE);   /* VM: a 304 is reported as served from the cache */
    CHECK(!strncmp(b.rawhdrs, "HTTP/1.1 200 OK\r\n", 17));
    srv_stop(s);
}

TEST(hci_fresh_weak_etag_sent_verbatim) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "weak", "Content-Type: text/plain\r\nETag: W/\"w-123\"\r\nCache-Control: max-age=0\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "weaketag");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    if (n >= 2) EXPECT_STR(srv_req_header(s, 1, "If-None-Match"), "W/\"w-123\"");
    EXPECT_STR(b.body, "weak");
    srv_stop(s);
}

TEST(hci_fresh_last_modified_revalidation_304) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "lm-body", "Content-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nCache-Control: max-age=0\r\n");
    hci_set(&p, 1, 200, "unconditional", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "lm304");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    if (n >= 2) {
        const char *ims = srv_req_header(s, 1, "If-Modified-Since");
        t_note("If-Modified-Since sent: %s", ims ? ims : "(none)");
        CHECK(ims && !strncmp(ims, "Tue, 15 Nov 1994 08:12:31 GMT", 29));
        CHECK(srv_req_header(s, 1, "If-None-Match") == NULL);
    }
    EXPECT_STR(b.body, "lm-body");
    EXPECT_EQ(b.status, 200);
    srv_stop(s);
}

TEST(hci_fresh_both_validators_sent) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "both", "Content-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nETag: \"b\"\r\nCache-Control: max-age=0\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "bothval");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    if (n >= 2) {
        EXPECT_STR(srv_req_header(s, 1, "If-None-Match"), "\"b\"");
        CHECK(srv_req_header(s, 1, "If-Modified-Since") != NULL);
        int i1 = srv_req_header_index(s, 1, "If-Modified-Since"), i2 = srv_req_header_index(s, 1, "If-None-Match");
        t_note("conditional header order: IMS@%d INM@%d; line=%s", i1, i2, srv_req_line(s, 1));
        for (int h = 0; h < srv_req_header_count(s, 1); h++) t_note("  cond hdr %d: %s: %s", h, srv_req_header_name(s, 1, h), srv_req_header_value(s, 1, h));
        EXPECT_EQ(i1, 2); EXPECT_EQ(i2, 3);           /* VM: User-Agent, Host, If-Modified-Since, If-None-Match */
    }
    EXPECT_STR(b.body, "both");
    srv_stop(s);
}

TEST(hci_fresh_revalidation_200_replaces_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "old-content", "Content-Type: text/plain\r\nETag: \"o\"\r\nCache-Control: max-age=0\r\n");
    hci_set(&p, 1, 200, "new-content-xyz", "Content-Type: text/plain\r\nETag: \"n\"\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);   /* no cond reply: the server answers the conditional GET with a full 200 */
    const char *url = hci_url(s, "reval200");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 2);
    EXPECT_STR(b.body, "new-content-xyz");
    CHECK(!hci_from_cache(&b));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwSizeLow, 15);
        CHECK(hci_hdr_has(e, "ETag: \"n\""));
        char buf[64]; size_t k; CHECK(hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &k)); EXPECT_STR(buf, "new-content-xyz");
    }
    free(e);
    srv_stop(s);
}

TEST(hci_fresh_304_updates_expiry_then_cache_hit) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "keep", "Content-Type: text/plain\r\nETag: \"k\"\r\nCache-Control: max-age=0\r\n");
    hci_set(&p, 1, 200, "unexpected", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "ETag: \"k\"\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "304exp");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_get(hi, url, NULL, 0, &r);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e0 = hci_info(url, &err);
    hci_get(hi, url, NULL, 0, &r); EXPECT_STR(r.body, "keep");
    INTERNET_CACHE_ENTRY_INFOA *e1 = hci_info(url, &err);
    hci_get(hi, url, NULL, 0, &r); EXPECT_STR(r.body, "keep");
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 2);      /* the third GET is served from the refreshed entry */
    EXPECT_EQ(p.cond_served, 1);
    CHECK(hci_from_cache(&r));
    CHECK(e0 && e1);
    if (e0 && e1) {
        hci_note_entry("before 304", e0); hci_note_entry("after 304", e1);
        CHECK(hci_ft(e1->ExpireTime) > hci_ft_now() + 3000 * HCI_SEC);
        CHECK(hci_ft(e1->LastSyncTime) >= hci_ft(e0->LastSyncTime));
        EXPECT_EQ(e1->dwHitRate, e0->dwHitRate + 1);  /* VM: a 304 counts as a hit */
        EXPECT_STR(e0->lpszLocalFileName, e1->lpszLocalFileName);   /* the file is reused */
    }
    free(e0); free(e1);
    srv_stop(s);
}

TEST(hci_fresh_304_merges_new_headers) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "merge", "Content-Type: text/plain\r\nETag: \"m\"\r\nCache-Control: max-age=0\r\nX-Old: 1\r\n");
    hci_set_cond(&p, 304, "ETag: \"m\"\r\nX-Fresh-Header: 2\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "304merge");
    hci_resp a, b; twice(s, url, 0, 0, &a, &b);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        CHECK(hci_hdr_has(e, "X-Old: 1"));
        t_note("304 merge: X-Fresh-Header stored=%d; response headers after 304 contain it=%d", hci_hdr_has(e, "X-Fresh-Header"), strstr(b.rawhdrs, "X-Fresh-Header") != NULL);
        CHECK(hci_hdr_has(e, "X-Fresh-Header: 2"));   /* VM: new 304 headers are merged into the blob and the response */
        CHECK(strstr(b.rawhdrs, "X-Fresh-Header: 2") != NULL);
        CHECK(strstr(b.rawhdrs, "X-Old: 1") != NULL);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_fresh_no_cache_stored_but_revalidated) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nc1", "Content-Type: text/plain\r\nCache-Control: no-cache\r\nETag: \"nc\"\r\n");
    hci_set(&p, 1, 200, "nc2", "Content-Type: text/plain\r\nCache-Control: no-cache\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "nocache");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    CHECK(hci_exists(url));
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    if (srv_req_count(s) >= 2) EXPECT_STR(srv_req_header(s, 1, "If-None-Match"), "\"nc\"");
    EXPECT_STR(b.body, "nc1");
    srv_stop(s);
}

TEST(hci_fresh_no_store_not_stored) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const char *vals[] = { "no-store", "NO-STORE", "private, no-store", "no-store, max-age=3600", "  no-store" };
    for (size_t k = 0; k < sizeof vals / sizeof vals[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "ns", "Content-Type: text/plain\r\nCache-Control: %s\r\n", vals[k]);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "nostore");
        hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
        EXPECT_STR(a.body, "ns");
        CHECKF(!hci_exists(url), "Cache-Control: %s cached", vals[k]);
        CHECKF(n == 2, "Cache-Control: %s requests %d", vals[k], n);
        srv_stop(s);
    }
}

TEST(hci_fresh_no_store_in_second_header_line) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ns2", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\nCache-Control: no-store\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "nostore2");
    hci_resp a, b; twice(s, url, 0, 0, &a, &b);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_fresh_no_store_deletes_existing_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "first", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "second", "Content-Type: text/plain\r\nCache-Control: no-store\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "nsdel");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_get(hi, url, NULL, 0, &r);
    CHECK(hci_exists(url));
    hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD, &r);
    EXPECT_STR(r.body, "second");
    t_inet_close(hi);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_fresh_no_cache_variants_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    static const struct { const char *cc; int stored; int second_hits_net; } rows[] = {
        { "no-cache", 1, 1 }, { "No-Cache", 1, 1 }, { "public, no-cache", 1, 1 }, { "no-cache=\"Set-Cookie\"", 1, 1 },
        { "private", 1, 0 }, { "public", 1, 0 }, { "public, max-age=3600", 1, 0 }, { "must-revalidate, max-age=3600", 1, 0 },
        { "max-age=3600, must-revalidate", 1, 0 }, { "MAX-AGE=3600", 1, 0 },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        char d[64]; hci_http_date(d, sizeof d, 86400 * 5);
        hci_plan p = {0}; hci_set(&p, 0, 200, "v1", "Content-Type: text/plain\r\nCache-Control: %s\r\nExpires: %s\r\n", rows[k].cc, d);
        hci_set(&p, 1, 200, "v2", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "ccvar");
        HINTERNET hi = hci_open(); hci_resp a, b;
        hci_get(hi, url, NULL, 0, &a);
        int stored = hci_exists(url);
        hci_get(hi, url, NULL, 0, &b);
        t_inet_close(hi);
        int n = hci_reqs(s, 0);
        t_note("Cache-Control: %-36s stored=%d requests=%d second=%s", rows[k].cc, stored, n, b.body);
        CHECKF(stored == rows[k].stored, "%s stored %d", rows[k].cc, stored);
        CHECKF((n == 2) == rows[k].second_hits_net, "%s requests %d", rows[k].cc, n);
        srv_stop(s);
    }
}

TEST(hci_fresh_pragma_no_cache_http_response) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "pragma", "Content-Type: text/plain\r\nPragma: no-cache\r\n");
    hci_set(&p, 1, 200, "pragma2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "pragma");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    int stored = hci_exists(url);
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    int n = hci_reqs(s, 0);
    t_note("HTTP Pragma: no-cache response: stored=%d requests=%d", stored, n);
    EXPECT_EQ(n, 1);                                  /* VM: Pragma in an HTTP response does not force revalidation */
    EXPECT_STR(b.body, "pragma");
    CHECK(stored);     /* FCanWriteToCache consults Pragma only for SECURE requests */
    srv_stop(s);
}

TEST(hci_fresh_heuristic_old_last_modified_is_fresh) {
    REQUIRE(U(InternetOpenUrlA));
    char lm[64]; hci_http_date(lm, sizeof lm, -86400LL * 365);
    hci_plan p = {0}; hci_set(&p, 0, 200, "heur", "Content-Type: text/plain\r\nLast-Modified: %s\r\n", lm);
    hci_set(&p, 1, 200, "net", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "heurold");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    EXPECT_EQ(n, 1);
    EXPECT_STR(b.body, "heur");
    srv_stop(s);
}

TEST(hci_fresh_heuristic_recent_last_modified) {
    REQUIRE(U(InternetOpenUrlA));
    char lm[64]; hci_http_date(lm, sizeof lm, -2);
    hci_plan p = {0}; hci_set(&p, 0, 200, "recent", "Content-Type: text/plain\r\nLast-Modified: %s\r\n", lm);
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "heurnew");
    Sleep(1200);
    hci_resp a, b; HINTERNET hi = hci_open();
    hci_get(hi, url, NULL, 0, &a); Sleep(1100); hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    int n = hci_reqs(s, 0);
    t_note("LM 2 s old: requests=%d cond=%ld (heuristic window (download-LM)/10)", n, p.cond_served);
    EXPECT_EQ(n, 2);                                  /* window ~0.3 s, second GET 1.1 s later: conditional */
    EXPECT_EQ(p.cond_served, 1);
    EXPECT_STR(b.body, "recent");
    srv_stop(s);
}

TEST(hci_fresh_no_validators_same_session) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nov1", "Content-Type: text/plain\r\n");
    hci_set(&p, 1, 200, "nov2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "noval");
    hci_resp a, b; int n = twice(s, url, 0, 0, &a, &b);
    t_note("no Expires/LM, same process: requests=%d second=%s from_cache=%d", n, b.body, hci_from_cache(&b));
    EXPECT_EQ(n, 1);
    srv_stop(s);
}

TEST(hci_fresh_resynchronize_sends_conditional) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "resync", "Content-Type: text/plain\r\nETag: \"r\"\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nCache-Control: max-age=3600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resync");
    hci_resp a, b; int n = twice(s, url, 0, INTERNET_FLAG_RESYNCHRONIZE, &a, &b);
    EXPECT_EQ(n, 2);
    if (n >= 2) {
        EXPECT_STR(srv_req_header(s, 1, "If-None-Match"), "\"r\"");
        const char *ims = srv_req_header(s, 1, "If-Modified-Since");
        CHECK(ims && !strncmp(ims, "Tue, 15 Nov 1994 08:12:31 GMT", 29));
    }
    EXPECT_EQ(p.cond_served, 1);
    EXPECT_STR(b.body, "resync");
    srv_stop(s);
}

TEST(hci_fresh_resynchronize_200_replaces) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "r-old", "Content-Type: text/plain\r\nETag: \"1\"\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "r-new", "Content-Type: text/plain\r\nETag: \"2\"\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resync200");
    hci_resp a, b, c; HINTERNET hi = hci_open();
    hci_get(hi, url, NULL, 0, &a);
    hci_get(hi, url, NULL, INTERNET_FLAG_RESYNCHRONIZE, &b);
    hci_get(hi, url, NULL, 0, &c);
    t_inet_close(hi);
    EXPECT_STR(b.body, "r-new");
    EXPECT_STR(c.body, "r-new");
    EXPECT_EQ(hci_reqs(s, 0), 2);
    srv_stop(s);
}

TEST(hci_fresh_resynchronize_without_entry_plain_get) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "plain", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resyncnone");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_RESYNCHRONIZE, &r); t_inet_close(hi);
    EXPECT_STR(r.body, "plain");
    CHECK(srv_wait_requests(s, 1, 1000));
    CHECK(srv_req_header(s, 0, "If-None-Match") == NULL);
    CHECK(srv_req_header(s, 0, "If-Modified-Since") == NULL);
    CHECK(hci_exists(url));
    srv_stop(s);
}

TEST(hci_fresh_app_conditional_header_passthrough) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 304, NULL, "ETag: \"app\"\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "appcond");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_get(hi, url, "If-None-Match: \"app\"\r\n", 0, &r);
    t_inet_close(hi);
    EXPECT_EQ(r.status, 304);
    CHECK(srv_wait_requests(s, 1, 1000));
    EXPECT_STR(srv_req_header(s, 0, "If-None-Match"), "\"app\"");
    EXPECT_EQ(r.len, 0);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_fresh_304_without_entry_returned_to_app) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 304, NULL, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "304noentry");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(r.status, 304);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_fresh_request_cache_control_header_from_app) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "first", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "second", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "appcc");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    hci_get(hi, url, "Cache-Control: no-cache\r\nPragma: no-cache\r\n", 0, &b);
    t_inet_close(hi);
    t_note("app-supplied Cache-Control/Pragma no-cache request headers: requests=%d second=%s", hci_reqs(s, 0), b.body);
    EXPECT_EQ(hci_reqs(s, 0), 1);                     /* VM: request headers from the app do not bypass the cache */
    EXPECT_STR(b.body, "first");
    srv_stop(s);
}

TEST(hci_fresh_cache_timestamps_option) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(InternetQueryOptionA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ts", "Content-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ts");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        INTERNET_CACHE_TIMESTAMPS ts; DWORD l = sizeof ts; memset(&ts, 0, sizeof ts);
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_CACHE_TIMESTAMPS, &ts, &l));
        t_note("CACHE_TIMESTAMPS returned length %lu", l);     /* VM boot 1: 0 (the length is not written back as 16) */
        SYSTEMTIME lm = { 1994, 11, 2, 15, 8, 12, 31, 0 }, ex = { 2033, 12, 4, 1, 16, 0, 0, 0 }; FILETIME f1, f2;
        SystemTimeToFileTime(&lm, &f1); SystemTimeToFileTime(&ex, &f2);
        EXPECT_EQ(hci_ft(ts.ftLastModified), hci_ft(f1));
        EXPECT_EQ(hci_ft(ts.ftExpires), hci_ft(f2));
        l = 15; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_CACHE_TIMESTAMPS, &ts, &l));
        EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}
