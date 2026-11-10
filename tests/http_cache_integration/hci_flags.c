/* hci_flags.c - request flags and the cache: RELOAD, NO_CACHE_WRITE, PRAGMA_NOCACHE, FROM_CACHE/OFFLINE,
 * CACHE_IF_NET_FAIL, HYPERLINK, FORMS_SUBMIT, NEED_FILE, and the REQUEST_FLAGS option bits.
 * Decomp: CanRetrieveFromCache@0x14d8ec (no cache read when flags & (RELOAD|RESYNCHRONIZE) 0x80000800),
 * FCanWriteToCache@0x6a120 (NO_CACHE_WRITE 0x04000000), InitBeginSendRequest (OFFLINE miss -> 2),
 * GetFromCacheOffline@0x171318. VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

static void prime(srv *s, const char *url, hci_resp *r) {
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, r); t_inet_close(hi);
}

TEST(hci_flags_reload_bypasses_fresh_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "cached", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\nETag: \"x\"\r\n");
    hci_set(&p, 1, 200, "reloaded", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "reload");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "reloaded");
    CHECK(!hci_from_cache(&b));
    if (srv_req_count(s) >= 2) {
        CHECK(srv_req_header(s, 1, "If-None-Match") == NULL);
        CHECK(srv_req_header(s, 1, "If-Modified-Since") == NULL);
        const char *cc = srv_req_header(s, 1, "Cache-Control"), *pr = srv_req_header(s, 1, "Pragma");
        t_note("RELOAD request: Cache-Control=%s Pragma=%s", cc ? cc : "(none)", pr ? pr : "(none)");
    }
    EXPECT_EQ(p.cond_served, 0);
    srv_stop(s);
}

TEST(hci_flags_reload_still_writes_cache) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "written", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "reloadwrite");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD, &r); t_inet_close(hi);
    CHECK(hci_exists(url));
    srv_stop(s);
}

TEST(hci_flags_no_cache_write_no_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ncw", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ncw");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_NO_CACHE_WRITE, &r); t_inet_close(hi);
    EXPECT_STR(r.body, "ncw");
    CHECK(!hci_exists(url));
    t_note("NO_CACHE_WRITE: reqflags=0x%lx datafile err=%lu early err=%lu", r.reqflags, r.datafile_err, r.datafile_early_err);
    CHECK(r.reqflags_ok && (r.reqflags & INTERNET_REQFLAG_CACHE_WRITE_DISABLED));
    CHECK(r.datafile[0] == 0);
    EXPECT_EQ(r.datafile_err, ERROR_INTERNET_ITEM_NOT_FOUND);
    srv_stop(s);
}

TEST(hci_flags_no_cache_write_reads_existing_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "primed", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ncwread");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_NO_CACHE_WRITE, &b); t_inet_close(hi);
    t_note("NO_CACHE_WRITE with fresh entry: requests=%d body=%s from_cache=%d", hci_reqs(s, 0), b.body, hci_from_cache(&b));
    EXPECT_STR(b.body, "primed");
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_flags_reload_no_cache_write_keeps_old_entry) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "old-entry", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "fresh-from-net", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ncwkeep");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, &b); t_inet_close(hi);
    EXPECT_STR(b.body, "fresh-from-net");
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    t_note("RELOAD|NO_CACHE_WRITE over an existing entry: entry=%d", e != NULL);
    if (e) {
        char buf[64]; size_t n; hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n);
        t_note("  entry content now: %s", buf);
        EXPECT_STR(buf, "old-entry");
    }
    free(e);
    srv_stop(s);
}

TEST(hci_flags_tfresh_header_set) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "x", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "tfresh");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, T_INET_FRESH, &r); t_inet_close(hi);
    CHECK(srv_wait_requests(s, 1, 1000));
    EXPECT_STR(srv_req_header(s, 0, "Cache-Control"), "no-cache");
    CHECK(!hci_exists(url));
    srv_stop(s);
}

/* which flag produces the Cache-Control: no-cache / Pragma request header */
TEST(hci_flags_nocache_request_header_table) {
    REQUIRE(U(InternetOpenUrlA));
    static const struct { DWORD f; const char *name; } rows[] = {
        { 0, "0" }, { INTERNET_FLAG_RELOAD, "RELOAD" }, { INTERNET_FLAG_PRAGMA_NOCACHE, "PRAGMA_NOCACHE" },
        { INTERNET_FLAG_NO_CACHE_WRITE, "NO_CACHE_WRITE" }, { INTERNET_FLAG_RESYNCHRONIZE, "RESYNCHRONIZE" },
        { INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE, "RELOAD|PRAGMA" }, { INTERNET_FLAG_HYPERLINK, "HYPERLINK" },
        { INTERNET_FLAG_NEED_FILE, "NEED_FILE" }, { INTERNET_FLAG_FORMS_SUBMIT, "FORMS_SUBMIT" },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "x", "Content-Type: text/plain\r\nCache-Control: no-store\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "hdrtab");
        HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, rows[k].f, &r); t_inet_close(hi);
        CHECK(srv_wait_requests(s, 1, 1000));
        const char *cc = srv_req_header(s, 0, "Cache-Control"), *pr = srv_req_header(s, 0, "Pragma");
        t_note("flags %-16s -> Cache-Control=%s Pragma=%s nhdrs=%d", rows[k].name, cc ? cc : "-", pr ? pr : "-", srv_req_header_count(s, 0));
        if (rows[k].f == 0) CHECK(cc == NULL);
        srv_stop(s);
    }
}

TEST(hci_flags_pragma_nocache_reads_cache) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "cached", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "net", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "pragmaflag");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_PRAGMA_NOCACHE, &b); t_inet_close(hi);
    t_note("PRAGMA_NOCACHE with fresh entry: requests=%d body=%s", hci_reqs(s, 0), b.body);
    srv_stop(s);
}

TEST(hci_flags_from_cache_hit) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "offline-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fromcache");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_FROM_CACHE, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    CHECK(b.ok);
    EXPECT_EQ(b.status, 200);
    EXPECT_STR(b.body, "offline-body");
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}

TEST(hci_flags_from_cache_stale_entry_still_served) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "stale-offline", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fcstale");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_FROM_CACHE, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "stale-offline");
    srv_stop(s);
}

TEST(hci_flags_from_cache_miss_fails) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "never", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fcmiss");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_FROM_CACHE, &r); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 0);
    CHECK(!r.ok);
    EXPECT_EQ(r.err, ERROR_FILE_NOT_FOUND);
    srv_stop(s);
}

TEST(hci_flags_from_cache_miss_httpsendrequest) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "never", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fcmisssend");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "GET", url, INTERNET_FLAG_FROM_CACHE, NULL, NULL, 0, NULL, NULL, &r);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 0);
    CHECK(!r.ok);
    EXPECT_EQ(r.err, ERROR_FILE_NOT_FOUND);
    srv_stop(s);
}

TEST(hci_flags_offline_session_flag) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "sess-offline", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "sessoff"), *miss = hci_url(s, "sessoffmiss");
    hci_resp a, b, c; prime(s, url, &a);
    HINTERNET hi = t_inet_open_ex("hci-agent", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    CHECK(hi != NULL);
    hci_get(hi, url, NULL, 0, &b);
    hci_get(hi, miss, NULL, 0, &c);
    t_inet_close(hi);
    EXPECT_STR(b.body, "sess-offline");
    CHECK(!c.ok);
    EXPECT_EQ(c.err, ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_flags_from_cache_head_request) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "headbody", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fchead");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open();
    hci_req(hi, s, "HEAD", url, INTERNET_FLAG_FROM_CACHE, NULL, NULL, 0, NULL, NULL, &b);
    t_inet_close(hi);
    t_note("HEAD + FROM_CACHE with entry: ok=%d err=%lu status=%d len=%zu requests=%d", b.ok, b.err, b.status, b.len, hci_reqs(s, 0));
    srv_stop(s);
}

/* stop the server, keep the URL: the port refuses connections (about 2 s per refused connect, 04 F3) */
TEST(hci_flags_cache_if_net_fail_serves_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "net-fail-copy", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    char url[512]; snprintf(url, sizeof url, "%s", hci_url(s, "netfail"));
    hci_resp a, b, c; prime(s, url, &a);
    CHECK(hci_exists(url));
    srv_stop(s);
    HINTERNET hi = hci_open();
    hci_get(hi, url, NULL, INTERNET_FLAG_CACHE_IF_NET_FAIL, &b);
    hci_get(hi, url, NULL, 0, &c);
    t_inet_close(hi);
    CHECK(b.ok);
    EXPECT_EQ(b.status, 200);
    EXPECT_STR(b.body, "net-fail-copy");
    t_note("CACHE_IF_NET_FAIL: reqflags=0x%lx", b.reqflags);
    CHECK(!c.ok);
    EXPECT_EQ(c.err, ERROR_INTERNET_CANNOT_CONNECT);
}

TEST(hci_flags_cache_if_net_fail_no_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "x", "");
    srv *s; HCI_START(&p, s);
    char url[512]; snprintf(url, sizeof url, "%s", hci_url(s, "netfailnone"));
    srv_stop(s);
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_CACHE_IF_NET_FAIL, &r); t_inet_close(hi);
    CHECK(!r.ok);
    EXPECT_EQ(r.err, ERROR_INTERNET_CANNOT_CONNECT);
}

TEST(hci_flags_hyperlink_no_validators_reloads) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "h1", "Content-Type: text/plain\r\n");
    hci_set(&p, 1, 200, "h2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hyper");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_HYPERLINK, &b); t_inet_close(hi);
    t_note("HYPERLINK, entry without Expires/LM: requests=%d body=%s", hci_reqs(s, 0), b.body);
    EXPECT_EQ(hci_reqs(s, 0), 2);
    EXPECT_STR(b.body, "h2");
    srv_stop(s);
}

TEST(hci_flags_hyperlink_with_expires_uses_cache) {
    REQUIRE(U(InternetOpenUrlA));
    char d[64]; hci_http_date(d, sizeof d, 86400 * 2);
    hci_plan p = {0}; hci_set(&p, 0, 200, "hx1", "Content-Type: text/plain\r\nExpires: %s\r\n", d);
    hci_set(&p, 1, 200, "hx2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hyperexp");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_HYPERLINK, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "hx1");
    srv_stop(s);
}

TEST(hci_flags_hyperlink_with_old_last_modified) {
    REQUIRE(U(InternetOpenUrlA));
    char lm[64]; hci_http_date(lm, sizeof lm, -86400LL * 400);
    hci_plan p = {0}; hci_set(&p, 0, 200, "hl1", "Content-Type: text/plain\r\nLast-Modified: %s\r\n", lm);
    hci_set(&p, 1, 200, "hl2", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hyperlm");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_HYPERLINK, &b); t_inet_close(hi);
    t_note("HYPERLINK with old LM: requests=%d body=%s", hci_reqs(s, 0), b.body);
    EXPECT_STR(b.body, "hl1");
    srv_stop(s);
}

TEST(hci_flags_forms_submit_get) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "f1", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "f2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    char url[512]; snprintf(url, sizeof url, "%s?q=form", hci_url(s, "forms")); t_cache_track(url);
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, INTERNET_FLAG_FORMS_SUBMIT, &a);
    int stored = hci_exists(url);
    hci_get(hi, url, NULL, INTERNET_FLAG_FORMS_SUBMIT, &b);
    t_inet_close(hi);
    t_note("FORMS_SUBMIT GET with query: stored=%d requests=%d second=%s", stored, hci_reqs(s, 0), b.body);
    EXPECT_STR(a.body, "f1");
    srv_stop(s);
}

TEST(hci_flags_need_file_datafile_exists_during_read) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "need-file-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "needfile");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, INTERNET_FLAG_NEED_FILE, &r); t_inet_close(hi);
    CHECK(r.datafile[0] != 0);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) EXPECT_STR(r.datafile, e->lpszLocalFileName);
    free(e);
    srv_stop(s);
}

TEST(hci_flags_request_flags_option_bits) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "rf", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "reqflags");
    HINTERNET hi = hci_open(); hci_resp a, b, c;
    hci_get(hi, url, NULL, 0, &a);
    hci_get(hi, url, NULL, 0, &b);
    hci_get(hi, url, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, &c);
    t_inet_close(hi);
    t_note("REQUEST_FLAGS: net=0x%lx cache=0x%lx reload+ncw=0x%lx", a.reqflags, b.reqflags, c.reqflags);
    CHECK(a.reqflags_ok && b.reqflags_ok && c.reqflags_ok);
    EXPECT_EQ(a.reqflags & INTERNET_REQFLAG_FROM_CACHE, 0);
    EXPECT_EQ(b.reqflags & INTERNET_REQFLAG_FROM_CACHE, INTERNET_REQFLAG_FROM_CACHE);
    EXPECT_EQ(c.reqflags & INTERNET_REQFLAG_FROM_CACHE, 0);
    EXPECT_EQ(c.reqflags & INTERNET_REQFLAG_CACHE_WRITE_DISABLED, INTERNET_REQFLAG_CACHE_WRITE_DISABLED);
    EXPECT_EQ(a.reqflags & INTERNET_REQFLAG_CACHE_WRITE_DISABLED, 0);
    srv_stop(s);
}

TEST(hci_flags_from_cache_and_reload_together) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "both", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "net", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fcreload");
    hci_resp a, b; prime(s, url, &a);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_FROM_CACHE | INTERNET_FLAG_RELOAD, &b); t_inet_close(hi);
    t_note("FROM_CACHE|RELOAD with entry: ok=%d err=%lu body=%s requests=%d", b.ok, b.err, b.body, hci_reqs(s, 0));
    srv_stop(s);
}

TEST(hci_flags_cache_hit_no_connection_made) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nc", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "noconn");
    hci_resp a; prime(s, url, &a);
    int c0 = srv_conn_count(s);
    HINTERNET hi = hci_open(); hci_resp b; hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    Sleep(100);
    EXPECT_EQ(srv_conn_count(s), c0);
    EXPECT_EQ(srv_req_count(s), 1);
    srv_stop(s);
}
