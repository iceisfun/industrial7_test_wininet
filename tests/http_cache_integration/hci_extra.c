/* hci_extra.c - edge responses and cache-related request options: HTTP/0.9 and HTTP/1.0 responses, the cache stream
 * handle option, secondary key reuse, request-option state before send, large header blocks.
 * Decomp: FCanWriteToCache@0x6a120 (IsHttp09 -> never cached), InternetQueryOptionA case 0x1b (CACHE_STREAM_HANDLE),
 * SetSecondaryCacheKey@0x253d0. VM_TIMEOUT: 240 */
#include "hci.h"
#include <stdlib.h>

TEST(hci_extra_http09_response_not_cached) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_SEND("raw http/0.9 bytes"), S_CLOSE() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server"); return; }
    const char *url = hci_url(s, "http09");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    t_note("HTTP/0.9: ok=%d err=%lu status=%d body=%s", r.ok, r.err, r.status, r.body);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_extra_http10_response_cached) {
    REQUIRE(U(InternetOpenUrlA));
    static const srv_step st[] = { S_HEAD(), S_REPLYF(200, "Content-Type: text/plain\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\n", "one-oh", SRV_R_HTTP10 | SRV_R_CONN_CLOSE) };
    srv *s = srv_http(st, 2); if (!s) { t_skip("server"); return; }
    const char *url = hci_url(s, "http10");
    HINTERNET hi = hci_open(); hci_resp a, b; hci_get(hi, url, NULL, 0, &a); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_STR(a.body, "one-oh");
    EXPECT_STR(b.body, "one-oh");
    EXPECT_EQ(srv_req_count(s), 1);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) CHECK(hci_hdr_has(e, "HTTP/1.0 200"));
    free(e);
    srv_stop(s);
}

TEST(hci_extra_cache_stream_handle_option) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "stream", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "stream2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "stream"), *url2 = hci_url(s, "stream2");
    HINTERNET hi = hci_open(); hci_resp a; hci_get(hi, url, NULL, 0, &a);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);       /* from cache */
    CHECK(h != NULL);
    if (h) {
        HANDLE hs = NULL; DWORD l = sizeof hs; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_CACHE_STREAM_HANDLE, &hs, &l);
        t_note("CACHE_STREAM_HANDLE on cache-served handle: ok=%d err=%lu h=%p len=%lu", ok, GetLastError(), hs, l);
        U(InternetCloseHandle)(h);
    }
    h = U(InternetOpenUrlA)(hi, url2, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    CHECK(h != NULL);
    if (h) {
        HANDLE hs = NULL; DWORD l = sizeof hs; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_CACHE_STREAM_HANDLE, &hs, &l);
        t_note("CACHE_STREAM_HANDLE on NO_CACHE_WRITE handle: ok=%d err=%lu", ok, GetLastError());
        CHECK(!ok);
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

static void set_key_k(HINTERNET h, void *ctx) { U(InternetSetOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, ctx, (DWORD)strlen(ctx)); }

TEST(hci_extra_secondary_key_post_reuse) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "k1", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "k2", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 2, 200, "k3", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "keyreuse");
    char ka[600], kb[600]; snprintf(ka, sizeof ka, "%sA1", url); snprintf(kb, sizeof kb, "%sB2", url); t_cache_track(ka); t_cache_track(kb);
    HINTERNET hi = hci_open(); hci_resp r1, r2, r3;
    hci_req(hi, s, "POST", url, 0, NULL, "x=1", 3, set_key_k, "A1", &r1);
    hci_req(hi, s, "POST", url, 0, NULL, "x=1", 3, set_key_k, "A1", &r2);
    hci_req(hi, s, "POST", url, 0, NULL, "x=2", 3, set_key_k, "B2", &r3);
    t_inet_close(hi);
    t_note("POST key reuse: bodies %s/%s/%s requests=%d existsA=%d existsB=%d", r1.body, r2.body, r3.body, hci_reqs(s, 0), hci_exists(ka), hci_exists(kb));
    EXPECT_STR(r1.body, "k1");
    CHECK(hci_exists(ka));
    CHECK(hci_exists(kb));
    srv_stop(s);
}

TEST(hci_extra_secondary_key_post_from_cache) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "post-resp", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "keyoffline");
    char k[600]; snprintf(k, sizeof k, "%sOFF", url); t_cache_track(k);
    HINTERNET hi = hci_open(); hci_resp r1, r2;
    hci_req(hi, s, "POST", url, 0, NULL, "x=1", 3, set_key_k, "OFF", &r1);
    hci_req(hi, s, "POST", url, INTERNET_FLAG_FROM_CACHE, NULL, "x=1", 3, set_key_k, "OFF", &r2);
    t_inet_close(hi);
    t_note("POST FROM_CACHE with key: ok=%d err=%lu body=%s requests=%d", r2.ok, r2.err, r2.body, hci_reqs(s, 0));
    srv_stop(s);
}

TEST(hci_extra_request_flags_before_send) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    static const struct { DWORD f; const char *verb; } rows[] = {
        { 0, "GET" }, { INTERNET_FLAG_NO_CACHE_WRITE, "GET" }, { 0, "HEAD" }, { 0, "POST" }, { 0, "PUT" }, { INTERNET_FLAG_RELOAD, "GET" },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        HINTERNET hr = U(HttpOpenRequestA)(hc, rows[k].verb, "/x", NULL, NULL, NULL, rows[k].f, 0);
        CHECK(hr != NULL);
        DWORD v = 0, l = sizeof v; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &v, &l);
        t_note("before send %s flags 0x%lx: REQUEST_FLAGS ok=%d err=%lu val=0x%lx", rows[k].verb, rows[k].f, ok, GetLastError(), v);
        if (ok && (!strcmp(rows[k].verb, "HEAD") || !strcmp(rows[k].verb, "PUT") || rows[k].f == INTERNET_FLAG_NO_CACHE_WRITE))
            CHECKF(v & INTERNET_REQFLAG_CACHE_WRITE_DISABLED, "%s 0x%lx reqflags 0x%lx", rows[k].verb, rows[k].f, v);
        if (ok && rows[k].f == 0 && (!strcmp(rows[k].verb, "GET") || !strcmp(rows[k].verb, "POST")))
            CHECKF(!(v & INTERNET_REQFLAG_CACHE_WRITE_DISABLED), "%s reqflags 0x%lx", rows[k].verb, v);
        t_inet_close(hr);
    }
    t_inet_close(hc); t_inet_close(hi);
}

TEST(hci_extra_many_headers_stored) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, "many", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    size_t k = strlen(rp->hdrs);
    for (int i = 0; i < 20 && k < sizeof rp->hdrs - 40; i++) k += snprintf(rp->hdrs + k, sizeof rp->hdrs - k, "X-H%02d: value-%02d\r\n", i, i);
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "many");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        int all = 1; char n[32];
        for (int i = 0; i < 20; i++) { snprintf(n, sizeof n, "X-H%02d: value-%02d\r\n", i, i); if (!hci_hdr_has(e, n)) all = 0; }
        CHECK(all);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_extra_cache_hit_keeps_handle_type_and_url) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ht", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "htype");
    HINTERNET hi = hci_open(); hci_resp a; hci_get(hi, url, NULL, 0, &a);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        char u[600]; l = sizeof u; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_URL, u, &l)); EXPECT_STR(u, url);
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_extra_cached_entry_after_redirect_target_url_option) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "rsrc")); snprintf(dst, sizeof dst, "%s", hci_url(s, "rdst"));
    hci_set(&p, 0, 302, "", "Location: %s\r\n", dst);
    hci_set(&p, 1, 200, "dst-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 2, 302, "", "Location: %s\r\n", dst);
    hci_set(&p, 3, 200, "unexpected", "Content-Type: text/plain\r\n");
    HINTERNET hi = hci_open(); hci_resp a, b; hci_get(hi, src, NULL, 0, &a); hci_get(hi, src, NULL, 0, &b); t_inet_close(hi);
    EXPECT_STR(a.body, "dst-body");
    EXPECT_STR(b.body, "dst-body");
    EXPECT_STR(b.url_opt, dst);
    EXPECT_EQ(hci_reqs(s, 0), 3);       /* uncached 302 again, then the target from the cache */
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}
