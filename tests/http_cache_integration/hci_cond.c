/* hci_cond.c - conditional requests built from a cache entry and what a 304 does to the entry and the response.
 * Decomp (wininet 10.0.19041):
 *   GetFromCachePreNetIoLoop@0x87140: an expired entry adds If-Modified-Since when its LastModifiedTime != 0
 *     (FAddIfModifiedSinceHeader@0x21a3c) and If-None-Match from the stored ETag (AddHeaderIfEtagFound@0x12254).
 *   FAddIfModifiedSinceHeader: the date is FFileTimetoHttpDateTime(entry LastModifiedTime) (RFC 1123), and
 *     "<date>; length=<size>" unless the entry type has bit 0x40 (HTTP-written entries are 0x41, VM).
 *   AddHeaderIfEtagFound: only for entries with type bit 0x40: ETag parsed from the stored header blob (buffer 0x200).
 *   GetFromCachePostNetIO@0x6b8b8: 304 -> served from the entry, headers merged, sync time updated.
 * VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

static void prime_then_expire(const char *url, hci_resp *a) {
    free(hci_fetch(url, NULL, 0, a));
    hci_set_times(url, -60, HCI_KEEP, HCI_KEEP);
}

TEST(hci_cond_request_header_order) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "order", "Content-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nETag: \"o\"\r\nCache-Control: max-age=0\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "order");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a)); free(hci_fetch(url, NULL, 0, &b));
    CHECK(hci_reqs(s, 2) == 2);
    if (srv_req_count(s) >= 2) {
        EXPECT_EQ(srv_req_header_count(s, 0), 2);
        EXPECT_EQ(srv_req_header_count(s, 1), 4);
        EXPECT_STR(srv_req_header_name(s, 1, 0), "User-Agent");
        EXPECT_STR(srv_req_header_name(s, 1, 1), "Host");
        EXPECT_STR(srv_req_header_name(s, 1, 2), "If-Modified-Since");
        EXPECT_STR(srv_req_header_name(s, 1, 3), "If-None-Match");
        EXPECT_STR(srv_req_header_value(s, 1, 2), "Tue, 15 Nov 1994 08:12:31 GMT");
        EXPECT_STR(srv_req_header_value(s, 1, 3), "\"o\"");
        EXPECT_STR(srv_req_line(s, 1), srv_req_line(s, 0));
        CHECK(!hci_rh(s, 1, "Cache-Control"));
        CHECK(!hci_rh(s, 1, "Pragma"));
        EXPECT_EQ(srv_req_header_occurrences(s, 1, "If-None-Match"), 1);
    }
    EXPECT_STR(b.body, "order");
    srv_stop(s);
}

/* ETag values are copied verbatim into If-None-Match */
static const struct { const char *etag; int verbatim; } g_etags[] = {
    { "\"a\"", 1 }, { "W/\"weak\"", 1 }, { "\"with space\"", 1 }, { "\"\"", 1 }, { "unquoted-tag", 1 },
    { "\"123456789012345678901234567890123456789012345678901234567890\"", 1 }, { "\"a,b\"", 1 }, { "\"x\", \"y\"", 0 },
    { "\"UPPER-lower-09\"", 1 }, { "w/\"lowerweak\"", 1 },
};
TEST(hci_cond_etag_values_table) {
    REQUIRE(U(InternetOpenUrlA));
    for (size_t k = 0; k < sizeof g_etags / sizeof g_etags[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "etagged", "Content-Type: text/plain\r\nETag: %s\r\nCache-Control: max-age=600\r\n", g_etags[k].etag);
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        hci_set_cond(&p, 304, "");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "etagtab");
        hci_resp a, b; prime_then_expire(url, &a); free(hci_fetch(url, NULL, 0, &b));
        int n = hci_reqs(s, 2);
        const char *inm = hci_rh(s, 1, "If-None-Match");
        t_note("ETag [%s] -> If-None-Match [%s] requests=%d body=%s", g_etags[k].etag, inm ? inm : "(none)", n, b.body);
        CHECKF(n == 2, "ETag [%s] requests %d", g_etags[k].etag, n);
        if (g_etags[k].verbatim) {
            CHECKF(inm && !strcmp(inm, g_etags[k].etag), "ETag [%s] INM [%s]", g_etags[k].etag, inm ? inm : "(none)");
            CHECKF(!strcmp(b.body, "etagged"), "ETag [%s] body %s", g_etags[k].etag, b.body);
            CHECKF(p.cond_served == 1, "ETag [%s] cond %ld", g_etags[k].etag, p.cond_served);
        }
        srv_stop(s);
    }
}

TEST(hci_cond_long_etag) {
    REQUIRE(U(InternetOpenUrlA));
    static const int lens[] = { 100, 400, 509, 600, 1000 };
    for (size_t k = 0; k < 5; k++) {
        char tag[1100]; tag[0] = '"'; for (int i = 1; i <= lens[k]; i++) tag[i] = (char)('a' + i % 26); tag[lens[k] + 1] = '"'; tag[lens[k] + 2] = 0;
        hci_plan p = {0}; hci_set(&p, 0, 200, "long", "Content-Type: text/plain\r\nETag: %s\r\nCache-Control: max-age=600\r\n", tag);
        hci_set_cond(&p, 304, "");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "longetag");
        hci_resp a, b; prime_then_expire(url, &a); free(hci_fetch(url, NULL, 0, &b));
        hci_reqs(s, 2);
        const char *inm = hci_rh(s, 1, "If-None-Match");
        t_note("ETag of %d chars -> If-None-Match %s (len %zu)", lens[k] + 2, inm ? "sent" : "absent", inm ? strlen(inm) : 0);
        if (lens[k] <= 400) CHECKF(inm && !strcmp(inm, tag), "len %d", lens[k]);
        srv_stop(s);
    }
}

/* If-Modified-Since is the entry's LastModifiedTime re-formatted as RFC 1123, whatever format the server used */
static const struct { const char *lm; const char *ims; } g_ims[] = {
    { "Tue, 15 Nov 1994 08:12:31 GMT", "Tue, 15 Nov 1994 08:12:31 GMT" },
    { "Tue Nov 15 08:12:31 1994",      "Tue, 15 Nov 1994 08:12:31 GMT" },
    { "Sat, 29 Feb 2020 23:59:59 GMT", "Sat, 29 Feb 2020 23:59:59 GMT" },
    { "Mon, 01 Jan 2001 00:00:00 GMT", "Mon, 01 Jan 2001 00:00:00 GMT" },
    { "Wed, 31 Dec 2025 12:00:00 GMT", "Wed, 31 Dec 2025 12:00:00 GMT" },
    { "Sun, 06 Nov 1994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 GMT" },
    { "garbage",                       NULL },
};
TEST(hci_cond_if_modified_since_format_table) {
    REQUIRE(U(InternetOpenUrlA));
    for (size_t k = 0; k < sizeof g_ims / sizeof g_ims[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "ims", "Content-Type: text/plain\r\nLast-Modified: %s\r\nCache-Control: max-age=600\r\n", g_ims[k].lm);
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        hci_set_cond(&p, 304, "");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "imstab");
        hci_resp a, b; prime_then_expire(url, &a); free(hci_fetch(url, NULL, 0, &b));
        int n = hci_reqs(s, 2);
        const char *ims = hci_rh(s, 1, "If-Modified-Since");
        t_note("LM [%s] -> IMS [%s]", g_ims[k].lm, ims ? ims : "(none)");
        CHECKF(n == 2, "LM [%s] requests %d", g_ims[k].lm, n);
        if (g_ims[k].ims) {
            CHECKF(ims && !strcmp(ims, g_ims[k].ims), "LM [%s] IMS [%s] want [%s]", g_ims[k].lm, ims ? ims : "(none)", g_ims[k].ims);
            CHECKF(!strcmp(b.body, "ims"), "LM [%s] body %s", g_ims[k].lm, b.body);
        } else {
            CHECKF(ims == NULL, "LM [%s] IMS sent [%s]", g_ims[k].lm, ims ? ims : "");
            CHECKF(!strcmp(b.body, "network"), "LM [%s] body %s", g_ims[k].lm, b.body);
        }
        CHECK(!hci_rh(s, 1, "If-None-Match"));
        srv_stop(s);
    }
}

/* the response handle after a 304 */
TEST(hci_cond_304_response_view) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "view-body", "Content-Type: text/html\r\nETag: \"v\"\r\nCache-Control: max-age=600\r\nX-Orig: 1\r\n");
    hci_set_cond(&p, 304, "ETag: \"v\"\r\nX-From-304: yes\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "view304");
    hci_resp a; prime_then_expire(url, &a);
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char v[512]; DWORD l, n = 0;
        l = sizeof n; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &n, &l, NULL)); EXPECT_EQ(n, 200);
        l = sizeof v; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_STATUS_TEXT, v, &l, NULL)); EXPECT_STR(v, "OK");
        l = sizeof v; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_CONTENT_TYPE, v, &l, NULL)); EXPECT_STR(v, "text/html");
        l = sizeof n; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &n, &l, NULL)); EXPECT_EQ(n, 9);
        l = sizeof v; CHECK(U(HttpQueryInfoA)(h, HTTP_QUERY_CUSTOM, strcpy(v, "X-Orig"), &l, NULL)); EXPECT_STR(v, "1");
        l = sizeof v; SetLastError(0); BOOL got = U(HttpQueryInfoA)(h, HTTP_QUERY_CUSTOM, strcpy(v, "X-From-304"), &l, NULL);
        t_note("after 304: X-From-304 visible=%d (%s)", got, got ? v : "");
        CHECK(got); if (got) EXPECT_STR(v, "yes");
        DWORD f = 0; l = sizeof f; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_REQUEST_FLAGS, &f, &l));
        EXPECT_EQ(f & INTERNET_REQFLAG_FROM_CACHE, INTERNET_REQFLAG_FROM_CACHE);
        char buf[64]; DWORD rd = 0; CHECK(U(InternetReadFile)(h, buf, sizeof buf - 1, &rd)); buf[rd] = 0;
        EXPECT_STR(buf, "view-body");
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    EXPECT_EQ(p.cond_served, 1);
    srv_stop(s);
}

TEST(hci_cond_304_rounds_hit_rate) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "rounds", "Content-Type: text/plain\r\nETag: \"r\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "rounds");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e0 = hci_info(url, &err);
    DWORD hit0 = e0 ? e0->dwHitRate : 0; free(e0);
    for (int i = 1; i <= 3; i++) {
        CHECK(hci_set_times(url, -60, HCI_KEEP, HCI_KEEP));
        hci_resp b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
        EXPECT_STR(b.body, "rounds");
        CHECKF(p.cond_served == i, "round %d cond %ld", i, p.cond_served);
        CHECKF(e && e->dwHitRate == hit0 + i, "round %d hit %lu (start %lu)", i, e ? e->dwHitRate : 0, hit0);
        CHECKF(e && e->dwSizeLow == 6, "round %d size", i);
        free(e);
    }
    EXPECT_EQ(hci_reqs(s, 4), 4);
    EXPECT_EQ(p.served, 1);
    srv_stop(s);
}

TEST(hci_cond_304_keeps_local_file) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "same-file", "Content-Type: text/plain\r\nETag: \"f\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "file304");
    hci_resp a, b; prime_then_expire(url, &a);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e0 = hci_info(url, &err);
    INTERNET_CACHE_ENTRY_INFOA *e1 = hci_fetch(url, NULL, 0, &b);
    CHECK(e0 && e1);
    if (e0 && e1) {
        EXPECT_STR(e1->lpszLocalFileName, e0->lpszLocalFileName);
        CHECK(hci_file_eq(e1->lpszLocalFileName, "same-file", 9));
        EXPECT_STR(b.datafile, e1->lpszLocalFileName);
        EXPECT_EQ(e1->CacheEntryType, HCI_HTTP_ENTRY);
    }
    free(e0); free(e1);
    srv_stop(s);
}

TEST(hci_cond_304_new_etag_stored) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "etag-upd", "Content-Type: text/plain\r\nETag: \"one\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "ETag: \"two\"\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "etagupd");
    hci_resp a, b, c; prime_then_expire(url, &a);
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
    if (e) t_note("after 304 with a new ETag: blob has one=%d two=%d", hci_hdr_has(e, "\"one\""), hci_hdr_has(e, "\"two\""));
    free(e);
    hci_set_times(url, -60, HCI_KEEP, HCI_KEEP);
    free(hci_fetch(url, NULL, 0, &c));
    hci_reqs(s, 3);
    const char *inm = hci_rh(s, 2, "If-None-Match");
    t_note("third request If-None-Match %s", inm ? inm : "(none)");
    EXPECT_EQ(p.cond_served, 2);
    EXPECT_STR(c.body, "etag-upd");
    srv_stop(s);
}

TEST(hci_cond_304_header_replaces_stored_value) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "repl", "Content-Type: text/plain\r\nETag: \"c\"\r\nCache-Control: max-age=600\r\nX-Val: old\r\n");
    hci_set_cond(&p, 304, "X-Val: new\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "repl304");
    hci_resp a, b; prime_then_expire(url, &a);
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
    CHECK(e != NULL);
    if (e) {
        t_note("304 X-Val: blob old=%d new=%d; response raw has old=%d new=%d", hci_hdr_has(e, "X-Val: old"), hci_hdr_has(e, "X-Val: new"),
               strstr(b.rawhdrs, "X-Val: old") != NULL, strstr(b.rawhdrs, "X-Val: new") != NULL);
        CHECK(hci_hdr_has(e, "X-Val: new"));
    }
    free(e);
    srv_stop(s);
}

TEST(hci_cond_304_content_type_change) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ct", "Content-Type: text/plain\r\nETag: \"t\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "Content-Type: text/html\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ct304");
    hci_resp a, b; prime_then_expire(url, &a);
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
    if (e) t_note("304 Content-Type: blob plain=%d html=%d local=%s", hci_hdr_has(e, "text/plain"), hci_hdr_has(e, "text/html"), e->lpszLocalFileName);
    EXPECT_STR(b.body, "ct");
    free(e);
    srv_stop(s);
}

TEST(hci_cond_304_with_no_store) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ns304", "Content-Type: text/plain\r\nETag: \"n\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "Cache-Control: no-store\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ns304");
    hci_resp a, b; prime_then_expire(url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    t_note("304 + no-store: status=%d body=%s entry exists=%d", b.status, b.body, hci_exists(url));
    EXPECT_EQ(b.status, 200);
    EXPECT_STR(b.body, "ns304");
    srv_stop(s);
}

TEST(hci_cond_conditional_answered_with_error_status) {
    REQUIRE(U(InternetOpenUrlA));
    static const int sts[] = { 404, 500, 412, 410 };
    for (size_t k = 0; k < 4; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "orig", "Content-Type: text/plain\r\nETag: \"e\"\r\nCache-Control: max-age=600\r\n");
        hci_set_cond(&p, sts[k], "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "conderr");
        hci_resp a, b; prime_then_expire(url, &a);
        HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
        int ex = hci_exists(url);
        t_note("conditional answered %d: app status=%d body=%s entry exists=%d", sts[k], b.status, b.body, ex);
        CHECKF(b.status == sts[k], "%d: status %d", sts[k], b.status);
        CHECKF(!hci_from_cache(&b), "%d from cache", sts[k]);
        srv_stop(s);
    }
}

/* an app-supplied If-None-Match next to the entry's own */
TEST(hci_cond_app_if_none_match_on_stale_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "app-inm", "Content-Type: text/plain\r\nETag: \"entry\"\r\nCache-Control: max-age=600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "appinm");
    hci_resp a, b; prime_then_expire(url, &a);
    free(hci_fetch(url, "If-None-Match: \"app\"\r\n", 0, &b));
    hci_reqs(s, 2);
    const char *inm = hci_rh(s, 1, "If-None-Match");
    t_note("app INM + stale entry: sent [%s] occurrences=%d status=%d body=%s", inm ? inm : "(none)", srv_req_count(s) > 1 ? srv_req_header_occurrences(s, 1, "If-None-Match") : -1, b.status, b.body);
    CHECK(inm != NULL);
    srv_stop(s);
}

TEST(hci_cond_app_if_modified_since_on_fresh_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "fresh-ims", "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n");
    hci_set(&p, 1, 304, NULL, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "appims");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    free(hci_fetch(url, "If-Modified-Since: Mon, 01 Jan 2001 00:00:00 GMT\r\n", 0, &b));
    t_note("app IMS + fresh entry: requests=%d status=%d body=%s from_cache=%d", hci_reqs(s, 0), b.status, b.body, hci_from_cache(&b));
    srv_stop(s);
}

/* RESYNCHRONIZE: conditional GET even when fresh; with no validators it is a plain GET */
TEST(hci_cond_resync_no_validators) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "first", "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n");
    hci_set(&p, 1, 200, "second", "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resyncnov");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, INTERNET_FLAG_RESYNCHRONIZE, &b);
    int n = hci_reqs(s, 2);
    t_note("RESYNCHRONIZE without validators: requests=%d body=%s", n, b.body);
    EXPECT_EQ(n, 2);
    CHECK(!hci_rh(s, 1, "If-Modified-Since"));
    CHECK(!hci_rh(s, 1, "If-None-Match"));
    EXPECT_STR(b.body, "second");
    if (e) CHECK(hci_file_eq(e->lpszLocalFileName, "second", 6));
    free(e);
    srv_stop(s);
}

TEST(hci_cond_resync_lm_only) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "lm-only", "Content-Type: text/plain\r\nLast-Modified: Mon, 01 Jan 2001 00:00:00 GMT\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resynclm");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a)); free(hci_fetch(url, NULL, INTERNET_FLAG_RESYNCHRONIZE, &b));
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(hci_rh(s, 1, "If-Modified-Since"), "Mon, 01 Jan 2001 00:00:00 GMT");
    CHECK(!hci_rh(s, 1, "If-None-Match"));
    EXPECT_EQ(p.cond_served, 1);
    EXPECT_STR(b.body, "lm-only");
    srv_stop(s);
}

TEST(hci_cond_resync_httpsendrequest) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hsr", "Content-Type: text/plain\r\nETag: \"h\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "resynchsr");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &a);
    hci_req(hi, s, "GET", url, INTERNET_FLAG_RESYNCHRONIZE, NULL, NULL, 0, NULL, NULL, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(hci_rh(s, 1, "If-None-Match"), "\"h\"");
    EXPECT_STR(b.body, "hsr");
    EXPECT_EQ(b.status, 200);
    srv_stop(s);
}

/* the request headers the handle reports after a conditional round trip */
static void q_reqhdrs(HINTERNET h, void *ctx) { (void)h; (void)ctx; }
TEST(hci_cond_request_headers_query_after_304) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "rq", "Content-Type: text/plain\r\nETag: \"q\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "rqhdr");
    hci_resp a; prime_then_expire(url, &a);
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc; char path[512]; uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof path;
    CHECK(U(InternetCrackUrlA)(url, 0, 0, &uc));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, 0, 0);
    CHECK(h != NULL);
    if (h) {
        CHECK(U(HttpSendRequestA)(h, NULL, 0, NULL, 0));
        char v[1024]; DWORD l = sizeof v;
        BOOL ok = U(HttpQueryInfoA)(h, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, v, &l, NULL);
        t_note("request headers after 304: ok=%d [%.300s]", ok, ok ? v : "");
        CHECK(ok && strstr(v, "If-None-Match: \"q\"") != NULL);
        l = sizeof v; ok = U(HttpQueryInfoA)(h, HTTP_QUERY_IF_NONE_MATCH | HTTP_QUERY_FLAG_REQUEST_HEADERS, v, &l, NULL);
        CHECK(ok); if (ok) EXPECT_STR(v, "\"q\"");
        char b[32]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hc); t_inet_close(hi);
    EXPECT_EQ(p.cond_served, 1);
    srv_stop(s);
}

/* seeded entries: type 0x40 decides ETag use and the "; length=" suffix */
typedef struct { DWORD type; int has_etag; int has_lm; } seedrow;
TEST(hci_cond_seeded_type_table) {
    REQUIRE(U(CommitUrlCacheEntryA)); REQUIRE(U(InternetOpenUrlA));
    static const seedrow rows[] = {
        { NORMAL_CACHE_ENTRY, 1, 1 }, { HCI_HTTP_ENTRY, 1, 1 }, { NORMAL_CACHE_ENTRY, 1, 0 }, { HCI_HTTP_ENTRY, 1, 0 },
        { NORMAL_CACHE_ENTRY, 0, 1 }, { HCI_HTTP_ENTRY, 0, 1 },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "network", "Content-Type: text/plain\r\n");
        hci_set_cond(&p, 304, "");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "seedtype");
        char hdrs[256]; snprintf(hdrs, sizeof hdrs, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n%s\r\n", rows[k].has_etag ? "ETag: \"sd\"\r\n" : "");
        CHECK(hci_seed(url, "seed-body", hdrs, rows[k].type, -86400, rows[k].has_lm ? -86400LL * 400 : 0));
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
        CHECKF(e && e->CacheEntryType == rows[k].type, "row %zu committed type 0x%lx", k, e ? e->CacheEntryType : 0);
        free(e);
        hci_resp r; HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
        hci_reqs(s, 1);
        const char *inm = hci_rh(s, 0, "If-None-Match"), *ims = hci_rh(s, 0, "If-Modified-Since");
        t_note("seeded type 0x%lx etag=%d lm=%d -> INM [%s] IMS [%s] body=%s", rows[k].type, rows[k].has_etag, rows[k].has_lm, inm ? inm : "-", ims ? ims : "-", r.body);
        int want_inm = rows[k].has_etag && (rows[k].type & 0x40);
        CHECKF((inm != NULL) == want_inm, "row %zu INM %s", k, inm ? inm : "-");
        if (want_inm) CHECKF(!strcmp(inm, "\"sd\""), "row %zu INM %s", k, inm);
        CHECKF((ims != NULL) == rows[k].has_lm, "row %zu IMS %s", k, ims ? ims : "-");
        if (ims) {
            int has_len = strstr(ims, "; length=9") != NULL;
            CHECKF(has_len == !(rows[k].type & 0x40), "row %zu IMS [%s]", k, ims);
        }
        int cond = want_inm || rows[k].has_lm;
        CHECKF(!strcmp(r.body, cond ? "seed-body" : "network"), "row %zu body %s", k, r.body);
        srv_stop(s);
    }
}

/* clearing bit 0x40 of an HTTP-written entry through the API */
TEST(hci_cond_cleared_http_bit_drops_etag) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "bit", "Content-Type: text/plain\r\nETag: \"bit\"\r\nLast-Modified: Mon, 01 Jan 2001 00:00:00 GMT\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "clrbit");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    BOOL ok = hci_set_type(url, NORMAL_CACHE_ENTRY);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    t_note("SetUrlCacheEntryInfo(ATTRIBUTE, 1) ok=%d -> type 0x%lx", ok, e ? e->CacheEntryType : 0);
    int cleared = e && !(e->CacheEntryType & 0x40);
    free(e);
    hci_set_times(url, -60, HCI_KEEP, HCI_KEEP);
    free(hci_fetch(url, NULL, 0, &b));
    hci_reqs(s, 2);
    const char *inm = hci_rh(s, 1, "If-None-Match"), *ims = hci_rh(s, 1, "If-Modified-Since");
    t_note("type bit cleared=%d -> INM [%s] IMS [%s]", cleared, inm ? inm : "-", ims ? ims : "-");
    if (cleared) {
        CHECK(inm == NULL);
        CHECK(ims && strstr(ims, "; length=3"));
    } else {
        CHECK(inm != NULL);
    }
    srv_stop(s);
}

/* a 200 to the conditional request with the same ETag: the new body replaces the old one */
TEST(hci_cond_full_200_same_etag_replaces) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "old-body", "Content-Type: text/plain\r\nETag: \"same\"\r\nCache-Control: max-age=600\r\n");
    hci_set(&p, 1, 200, "newer-body!", "Content-Type: text/plain\r\nETag: \"same\"\r\nCache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "same200");
    hci_resp a, b; prime_then_expire(url, &a);
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
    EXPECT_STR(b.body, "newer-body!");
    CHECK(!hci_from_cache(&b));
    CHECK(e && hci_file_eq(e->lpszLocalFileName, "newer-body!", 11));
    CHECK(e && e->dwSizeLow == 11);
    free(e);
    srv_stop(s);
}

/* conditional request on a keep-alive connection that served the original */
TEST(hci_cond_same_connection_reused) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ka", "Content-Type: text/plain\r\nETag: \"ka\"\r\nCache-Control: max-age=0\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ka304");
    HINTERNET hi = hci_open(); hci_resp a, b, c;
    hci_get(hi, url, NULL, 0, &a); hci_get(hi, url, NULL, 0, &b); hci_get(hi, url, NULL, 0, &c);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 3), 3);
    EXPECT_EQ(p.cond_served, 2);
    if (srv_req_count(s) >= 3) {
        EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 0));
        EXPECT_EQ(srv_req_conn(s, 2), srv_req_conn(s, 0));
    }
    EXPECT_STR(c.body, "ka");
    srv_stop(s);
}

/* 304 that closes the connection is still a cache hit */
TEST(hci_cond_304_connection_close) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "cl304", "Content-Type: text/plain\r\nETag: \"c\"\r\nCache-Control: max-age=0\r\n");
    hci_reply *c = hci_set_cond(&p, 304, ""); c->close = 1;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "cl304");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a)); free(hci_fetch(url, NULL, 0, &b));
    EXPECT_EQ(b.status, 200);
    EXPECT_STR(b.body, "cl304");
    EXPECT_EQ(p.cond_served, 1);
    srv_stop(s);
}

/* the conditional request is made for INTERNET_FLAG_NO_CACHE_WRITE too, and the 304 is served from the entry */
TEST(hci_cond_no_cache_write_still_revalidates) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ncw304", "Content-Type: text/plain\r\nETag: \"w\"\r\nCache-Control: max-age=600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ncw304");
    hci_resp a, b; prime_then_expire(url, &a);
    free(hci_fetch(url, NULL, INTERNET_FLAG_NO_CACHE_WRITE, &b));
    t_note("NO_CACHE_WRITE over stale entry: requests=%d INM=%s cond=%ld body=%s", hci_reqs(s, 2), hci_rh(s, 1, "If-None-Match") ? hci_rh(s, 1, "If-None-Match") : "-", p.cond_served, b.body);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    srv_stop(s);
}

/* PRAGMA_NOCACHE over a stale entry: is it still conditional? */
TEST(hci_cond_pragma_nocache_stale_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "pnc", "Content-Type: text/plain\r\nETag: \"p\"\r\nCache-Control: max-age=600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "pnc304");
    hci_resp a, b; prime_then_expire(url, &a);
    free(hci_fetch(url, NULL, INTERNET_FLAG_PRAGMA_NOCACHE, &b));
    hci_reqs(s, 2);
    t_note("PRAGMA_NOCACHE over stale entry: INM=%s Cache-Control=%s body=%s", hci_rh(s, 1, "If-None-Match") ? hci_rh(s, 1, "If-None-Match") : "-",
           hci_rh(s, 1, "Cache-Control") ? hci_rh(s, 1, "Cache-Control") : "-", b.body);
    EXPECT_EQ(srv_req_count(s), 2);
    srv_stop(s);
}
