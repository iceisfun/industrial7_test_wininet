/* hci_misc.c - methods (POST/HEAD/PUT), secondary cache key, redirects and ENABLE_REDIRECT_CACHE_READ, HTTPS rules,
 * Vary, Content-Encoding, DATAFILE_NAME and the file lock, deletion, use count / hit rate.
 * Decomp: HttpOpenRequest folds RELOAD|NO_CACHE_WRITE into non-GET/POST methods (02 3.2); FCanWriteToCache@0x6a120
 * (POST needs a secondary key; redirects 301..303/307/308; 302/303/307 need max-age or Expires; HTTPS + Pragma
 * no-cache); SetSecondaryCacheKey@0x253d0 (cache URL = URL + key, request handles only, else 12018);
 * InternetSetOptionA case 0x7a (ENABLE_REDIRECT_CACHE_READ: len 4, request handle). VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

/* ---------------------------------------------------------------- methods */
TEST(hci_misc_post_not_cached_under_url) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "posted", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "post");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "POST", url, 0, "Content-Type: application/x-www-form-urlencoded\r\n", "a=1", 3, NULL, NULL, &r);
    t_inet_close(hi);
    EXPECT_EQ(r.status, 200); EXPECT_STR(r.body, "posted");
    CHECK(!hci_exists(url));
    t_note("POST without secondary key: datafile=%s err=%lu reqflags=0x%lx", r.datafile, r.datafile_err, r.reqflags);
    EXPECT_EQ(r.datafile_err, ERROR_INTERNET_ITEM_NOT_FOUND);   /* VM */
    EXPECT_EQ(r.reqflags, INTERNET_REQFLAG_CACHE_WRITE_DISABLED);
    srv_stop(s);
}

TEST(hci_misc_post_does_not_serve_get_entry) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "get-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "post-body", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "postget");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    hci_req(hi, s, "POST", url, 0, NULL, "x", 1, NULL, NULL, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "post-body");
    if (srv_req_count(s) >= 2) EXPECT_STR(srv_req_method(s, 1), "POST");
    /* the GET entry is untouched */
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) { char buf[64]; size_t n; hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n); EXPECT_STR(buf, "get-body"); }
    free(e);
    srv_stop(s);
}

typedef struct { const char *key; BOOL set_ok; DWORD set_err; char q[256]; BOOL q_ok; DWORD q_err; } key_ctx;
static void set_key(HINTERNET h, void *ctx) {
    key_ctx *k = ctx;
    SetLastError(0);
    k->set_ok = U(InternetSetOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, (void *)k->key, (DWORD)strlen(k->key));
    k->set_err = GetLastError();
    DWORD l = sizeof k->q - 1; SetLastError(0);
    k->q_ok = U(InternetQueryOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, k->q, &l);
    k->q_err = GetLastError();
}

TEST(hci_misc_post_with_secondary_key_cached) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "post-cached", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "postkey");
    char keyed[600]; snprintf(keyed, sizeof keyed, "%s%s", url, "KEY123"); t_cache_track(keyed);
    key_ctx k = { "KEY123" };
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "POST", url, 0, NULL, "body=1", 6, set_key, &k, &r);
    t_inet_close(hi);
    CHECK(k.set_ok);
    CHECK(k.q_ok); EXPECT_STR(k.q, "KEY123");
    EXPECT_STR(r.body, "post-cached");
    t_note("POST + secondary key: url option=%s datafile=%s exists(url)=%d exists(url+key)=%d", r.url_opt, r.datafile, hci_exists(url), hci_exists(keyed));
    CHECK(!hci_exists(url));
    CHECK(hci_exists(keyed));
    EXPECT_STR(r.url_opt, url);                       /* VM: INTERNET_OPTION_URL is the plain URL after the send */
    CHECK(strstr(r.datafile, "postkeyKEY123[1]") != NULL);   /* VM: the key is part of the file name */
    srv_stop(s);
}

TEST(hci_misc_get_with_secondary_key) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "get-keyed", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "getkey");
    char keyed[600]; snprintf(keyed, sizeof keyed, "%s%s", url, "/K"); t_cache_track(keyed);
    key_ctx k = { "/K" };
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, set_key, &k, &r);
    t_inet_close(hi);
    CHECK(k.set_ok);
    CHECK(srv_wait_requests(s, 1, 1000));
    EXPECT_STR(srv_req_target(s, 0), strchr(url + 7, '/'));   /* the key never reaches the wire */
    t_note("GET + secondary key: url option=%s exists(url)=%d exists(url+key)=%d", r.url_opt, hci_exists(url), hci_exists(keyed));
    CHECK(hci_exists(keyed));
    CHECK(!hci_exists(url));
    EXPECT_STR(r.url_opt, url);
    srv_stop(s);
}

TEST(hci_misc_secondary_key_wrong_handle_types) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    SetLastError(0);
    CHECK(!U(InternetSetOptionA)(hi, INTERNET_OPTION_SECONDARY_CACHE_KEY, "k", 1));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0);
    CHECK(!U(InternetSetOptionA)(hc, INTERNET_OPTION_SECONDARY_CACHE_KEY, "k", 1));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    char q[64]; DWORD l = sizeof q; SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(hc, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof q; SetLastError(0);
    CHECK(!U(InternetQueryOptionA)(hi, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_inet_close(hc); t_inet_close(hi);
}

TEST(hci_misc_secondary_key_query_before_set) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, 0, 0);
    CHECK(hr != NULL);
    char q[64] = "unchanged"; DWORD l = sizeof q; SetLastError(0);
    BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l);
    t_note("SECONDARY_CACHE_KEY query before set: ok=%d err=%lu len=%lu val=%s", ok, GetLastError(), l, ok ? q : "");
    CHECK(ok); EXPECT_EQ(l, 0); EXPECT_STR(q, "");      /* VM: an empty string */
    /* set then query: A answers bytes incl. NUL? (02 7: W counts chars) */
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_SECONDARY_CACHE_KEY, "abc", 3));
    l = sizeof q; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l));
    EXPECT_STR(q, "abc");
    t_note("SECONDARY_CACHE_KEY query after set: len=%lu", l);
    EXPECT_EQ(l, 3);
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_SECONDARY_CACHE_KEY, "defg", 4));
    l = sizeof q; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l));
    EXPECT_STR(q, "defg");
    char url[512]; l = sizeof url; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_URL, url, &l));
    t_note("URL option after two keys: %s", url);
    l = sizeof q; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l)); EXPECT_EQ(l, 4);
    /* VM: before the send INTERNET_OPTION_URL is URL + the FIRST key; the default port is not spelled out */
    EXPECT_STR(url, "http://127.0.0.1/xabc");
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
}

TEST(hci_misc_head_not_cached) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "headbody", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "head");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "HEAD", url, 0, NULL, NULL, 0, NULL, NULL, &r);
    t_inet_close(hi);
    EXPECT_EQ(r.status, 200); EXPECT_EQ(r.len, 0);
    CHECK(!hci_exists(url));
    CHECK(r.reqflags_ok && (r.reqflags & INTERNET_REQFLAG_CACHE_WRITE_DISABLED));
    srv_stop(s);
}

TEST(hci_misc_head_ignores_and_keeps_get_entry) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "get-entry", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "head-body", "Content-Type: text/plain\r\nX-Head: 1\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "headkeep");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    hci_req(hi, s, "HEAD", url, 0, NULL, NULL, 0, NULL, NULL, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);       /* HEAD gets RELOAD folded in: never answered from the GET entry */
    if (srv_req_count(s) >= 2) EXPECT_STR(srv_req_method(s, 1), "HEAD");
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) { CHECK(!hci_hdr_has(e, "X-Head")); EXPECT_EQ(e->dwSizeLow, 9); }
    free(e);
    srv_stop(s);
}

TEST(hci_misc_other_methods_not_cached) {
    REQUIRE(U(HttpSendRequestA));
    static const char *verbs[] = { "PUT", "DELETE", "OPTIONS", "PATCH", "get" };
    for (size_t k = 0; k < sizeof verbs / sizeof verbs[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "verb", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "verb");
        HINTERNET hi = hci_open(); hci_resp r;
        hci_req(hi, s, verbs[k], url, 0, NULL, k == 0 ? "put" : NULL, k == 0 ? 3 : 0, NULL, NULL, &r);
        t_inet_close(hi);
        EXPECT_EQ(r.status, 200);
        CHECKF(!hci_exists(url), "%s cached", verbs[k]);
        CHECKF(r.reqflags & INTERNET_REQFLAG_CACHE_WRITE_DISABLED, "%s reqflags 0x%lx", verbs[k], r.reqflags);
        srv_stop(s);
    }
}

TEST(hci_misc_put_invalidates_entry) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "get", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "put-done", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "putinval");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    hci_req(hi, s, "PUT", url, 0, NULL, "new", 3, NULL, NULL, &b);
    t_inet_close(hi);
    t_note("GET entry after PUT to the same URL: exists=%d", hci_exists(url));
    CHECK(hci_exists(url));                           /* VM: a PUT does not invalidate the GET entry */
    EXPECT_EQ(hci_reqs(s, 2), 2);
    srv_stop(s);
}

/* ---------------------------------------------------------------- redirects */
TEST(hci_misc_redirect_301_cached) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "r301src")); snprintf(dst, sizeof dst, "%s", hci_url(s, "r301dst"));
    hci_set(&p, 0, 301, "", "Location: %s\r\n", dst);
    hci_set(&p, 1, 200, "landed", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 2, 200, "again", "Content-Type: text/plain\r\n");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, src, NULL, 0, &a);
    EXPECT_STR(a.body, "landed");
    EXPECT_STR(a.url_opt, dst);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *es = hci_info(src, &err), *ed = hci_info(dst, &err);
    hci_note_entry("301 source", es); hci_note_entry("301 target", ed);
    CHECK(es != NULL); CHECK(ed != NULL);
    if (es) {
        CHECK(es->CacheEntryType & REDIRECT_CACHE_ENTRY);
        CHECK(hci_hdr_has(es, "HTTP/1.1 301"));
        CHECK(hci_hdr_has(es, "Location: "));
    }
    hci_get(hi, src, NULL, 0, &b);
    t_inet_close(hi);
    t_note("second GET of 301 source: requests=%d body=%s url=%s", hci_reqs(s, 0), b.body, b.url_opt);
    /* VM: a cached redirect is only followed from the cache with ENABLE_REDIRECT_CACHE_READ; the source goes to the net */
    EXPECT_EQ(hci_reqs(s, 0), 3);
    EXPECT_STR(b.body, "again");
    EXPECT_STR(b.url_opt, src);
    free(es); free(ed);
    srv_stop(s);
}

TEST(hci_misc_redirect_status_table) {
    REQUIRE(U(InternetOpenUrlA));
    static const struct { int st; const char *extra; int cached; } rows[] = {
        { 301, "", 1 }, { 308, "", 1 }, { 302, "", 0 }, { 303, "", 0 }, { 307, "", 0 },
        { 302, "Cache-Control: max-age=600\r\n", 1 }, { 307, "Cache-Control: max-age=600\r\n", 1 },
        { 303, "Cache-Control: max-age=600\r\n", 1 },
        { 302, "Expires: Thu, 01 Dec 2033 16:00:00 GMT\r\n", 1 }, { 301, "Cache-Control: no-cache\r\n", 0 },
        { 301, "Cache-Control: no-store\r\n", 0 }, { 302, "Cache-Control: max-age=600, no-cache\r\n", 0 },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        hci_plan p = {0};
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "rtab")); snprintf(dst, sizeof dst, "%s", hci_url(s, "rtabdst"));
        hci_set(&p, 0, rows[k].st, "", "Location: %s\r\n%s", dst, rows[k].extra);
        hci_set(&p, 1, 200, "dst", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, src, NULL, 0, &r); t_inet_close(hi);
        EXPECT_STR(r.body, "dst");
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(src, &err);
        t_note("%d %-44s -> source cached=%d type=0x%lx", rows[k].st, rows[k].extra, e != NULL, e ? e->CacheEntryType : 0);
        CHECKF((e != NULL) == rows[k].cached, "%d %s cached=%d", rows[k].st, rows[k].extra, e != NULL);
        CHECK(hci_exists(dst));
        free(e);
        srv_stop(s);
    }
}

TEST(hci_misc_redirect_no_auto_redirect_not_followed_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "rnoauto")); snprintf(dst, sizeof dst, "%s", hci_url(s, "rnoautodst"));
    hci_set(&p, 0, 301, "moved", "Location: %s\r\nContent-Type: text/plain\r\n", dst);
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, src, NULL, INTERNET_FLAG_NO_AUTO_REDIRECT, &r); t_inet_close(hi);
    EXPECT_EQ(r.status, 301);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    CHECK(!hci_exists(dst));
    t_note("301 with NO_AUTO_REDIRECT: source cached=%d body=%s", hci_exists(src), r.body);
    CHECK(!hci_exists(src));                          /* VM: an unfollowed redirect is not cached */
    EXPECT_STR(r.body, "moved");
    srv_stop(s);
}

typedef struct { DWORD v; DWORD len; BOOL ok; DWORD err; } rcr_ctx;
static void set_rcr(HINTERNET h, void *ctx) {
    rcr_ctx *c = ctx; SetLastError(0);
    c->ok = U(InternetSetOptionA)(h, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &c->v, c->len);
    c->err = GetLastError();
}

TEST(hci_misc_redirect_cache_read_option_validation) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, 0, 0);
    DWORD v = 1;
    SetLastError(0); CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 4));
    SetLastError(0); CHECK(!U(InternetSetOptionA)(hr, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 2));
    EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    SetLastError(0); CHECK(!U(InternetSetOptionA)(hc, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 4));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SetLastError(0); CHECK(!U(InternetSetOptionA)(hi, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 4));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    v = 0; CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 4));
    DWORD q = 0x55, l = sizeof q; SetLastError(0);
    BOOL ok = U(InternetQueryOptionA)(hr, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &q, &l);
    DWORD qe = GetLastError();
    t_note("ENABLE_REDIRECT_CACHE_READ query: ok=%d err=%lu val=%lu", ok, qe, q);
    CHECK(!ok); EXPECT_EQ(qe, ERROR_INVALID_PARAMETER); EXPECT_EQ(q, 0x55);   /* VM: set-only option */
    SetLastError(0); ok = U(InternetSetOptionA)(NULL, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 4);
    DWORD ne = GetLastError();
    t_note("ENABLE_REDIRECT_CACHE_READ on NULL handle: ok=%d err=%lu", ok, ne);
    CHECK(!ok); EXPECT_EQ(ne, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
}

TEST(hci_misc_redirect_cache_read_follow) {
    REQUIRE(U(HttpSendRequestA));
    static const DWORD vals[] = { 0, 1 };
    for (int k = 0; k < 2; k++) {
        hci_plan p = {0};
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "rcr")); snprintf(dst, sizeof dst, "%s", hci_url(s, "rcrdst"));
        hci_set(&p, 0, 301, "", "Location: %s\r\n", dst);
        hci_set(&p, 1, 200, "target", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        hci_set(&p, 2, 200, "network-again", "Content-Type: text/plain\r\n");
        HINTERNET hi = hci_open(); hci_resp a, b;
        rcr_ctx c = { vals[k], 4 };
        hci_req(hi, s, "GET", src, 0, NULL, NULL, 0, set_rcr, &c, &a);
        CHECK(c.ok);
        rcr_ctx c2 = { vals[k], 4 };
        hci_req(hi, s, "GET", src, 0, NULL, NULL, 0, set_rcr, &c2, &b);
        t_inet_close(hi);
        t_note("ENABLE_REDIRECT_CACHE_READ=%lu: first=%d/%s second=%d/%s from_cache=%d requests=%d url=%s", vals[k], a.status, a.body, b.status, b.body,
               hci_from_cache(&b), hci_reqs(s, 0), b.url_opt);
        EXPECT_STR(a.body, "target");
        CHECK(c2.ok);
        /* VM: 0 -> the source is asked again and its answer (reply 2) is used; 1 -> the redirect entry is followed */
        CHECKF(hci_reqs(s, 0) == (vals[k] ? 2 : 3), "v=%lu requests %d", vals[k], srv_req_count(s));
        EXPECT_STR(b.body, vals[k] ? "target" : "network-again");
        CHECK(hci_from_cache(&b) == (vals[k] != 0));
        EXPECT_STR(b.url_opt, vals[k] ? dst : src);
        srv_stop(s);
    }
}

/* ---------------------------------------------------------------- HTTPS */
typedef struct { const char *hdrs; const char *body; } https_ctx;
static int https_fn(srv_conn *c, const srv_step *stp, void *user) {
    https_ctx *x = user; srv *s = srv_conn_server(c);
    for (int g = 0; g < 16; g++) {
        if (!hci_wait_request(c)) return -1;
        int ri = srv_conn_recv_head(c); if (ri < 0) return -1;
        char head[1024]; int n = snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\n%sContent-Length: %u\r\n\r\n%s", x->hdrs, (unsigned)strlen(x->body), x->body);
        if (srv_conn_send(c, head, n)) return -1;
    }
    return -1;
}
static srv *https_start(https_ctx *x) {
    static const srv_step st[] = { S_CALL(https_fn) };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.kind = SRV_HTTPS; cfg.scripts = sc; cfg.nscripts = 1; cfg.user = x; cfg.cert_profile = SRV_CERT_LOCALHOST; cfg.lifetime_ms = 30000;
    srv *s = NULL; if (srv_start(&cfg, &s) != SRV_OK) return NULL; return s;
}

TEST(hci_misc_https_cache_table) {
    REQUIRE(U(HttpSendRequestA));
    static const struct { const char *hdrs; int cached; } rows[] = {
        { "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n", 1 },
        { "Content-Type: text/plain\r\nCache-Control: public, max-age=3600\r\n", 1 },
        { "Content-Type: text/plain\r\nCache-Control: no-store\r\n", 0 },
        { "Content-Type: text/plain\r\nPragma: no-cache\r\n", 0 },
        { "Content-Type: text/plain\r\nCache-Control: private, max-age=3600\r\n", 1 },
        { "Content-Type: text/plain\r\n", 1 },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        https_ctx x = { rows[k].hdrs, "secure-body" };
        srv *s = https_start(&x); if (!s) { t_skip("https server unavailable"); return; }
        const char *url = hci_url(s, "https");
        CHECK(!strncmp(url, "https://", 8));
        HINTERNET hi = hci_open(); hci_resp r;
        hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &r);
        t_inet_close(hi);
        CHECKF(r.status == 200, "https status %d err %lu", r.status, r.err);
        EXPECT_STR(r.body, "secure-body");
        int ex = hci_exists(url);
        char esc[128]; size_t j = 0; for (const char *h = rows[k].hdrs; *h && j < sizeof esc - 1; h++) esc[j++] = (*h == '\r' || *h == '\n') ? ' ' : *h; esc[j] = 0;
        t_note("HTTPS [%s] -> cached=%d", esc, ex);
        CHECKF(ex == rows[k].cached, "https [%s] cached=%d", esc, ex);
        srv_stop(s);
    }
}

TEST(hci_misc_https_cache_hit) {
    REQUIRE(U(HttpSendRequestA));
    https_ctx x = { "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n", "tls-cached" };
    srv *s = https_start(&x); if (!s) { t_skip("https server unavailable"); return; }
    const char *url = hci_url(s, "httpshit");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &a);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    hci_note_entry("https entry", e);
    CHECK(e != NULL);
    free(e);
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &b);
    int n2 = hci_reqs(s, 0);
    hci_resp c; hci_req(hi, s, "GET", url, INTERNET_FLAG_FROM_CACHE, NULL, NULL, 0, NULL, NULL, &c);
    int n3 = hci_reqs(s, 0);
    t_inet_close(hi);
    EXPECT_STR(b.body, "tls-cached");
    /* VM boot 1: the second HTTPS GET (ignore-unknown-CA request) went to the network: 2 requests, 2 handshakes */
    t_note("HTTPS second GET: requests=%d from_cache=%d reqflags=0x%lx handshakes=%d; FROM_CACHE: ok=%d err=%lu body=%s requests=%d",
           n2, hci_from_cache(&b), b.reqflags, srv_count_events(s, SRV_EV_TLS_DONE), c.ok, c.err, c.body, n3);
    /* VM (2 boots): the HTTPS entry is written (type 0x41, fresh) but a request made with SECURITY_FLAG_IGNORE_UNKNOWN_CA
       (needed for the self-signed loopback certificate) never reads it: network again, and FROM_CACHE misses with 2 */
    EXPECT_EQ(n2, 2);
    CHECK(!hci_from_cache(&b));
    CHECK(!c.ok); EXPECT_EQ(c.err, ERROR_FILE_NOT_FOUND);
    EXPECT_EQ(n3, 2);
    srv_stop(s);
}

/* ---------------------------------------------------------------- Vary */
TEST(hci_misc_vary_table) {
    REQUIRE(U(InternetOpenUrlA));
    static const char *vary[] = { "Accept-Encoding", "User-Agent", "*", "Cookie", "X-Custom", "Accept-Language", "Accept-Encoding, User-Agent", "accept-encoding" };
    for (size_t k = 0; k < sizeof vary / sizeof vary[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "vary1", "Content-Type: text/plain\r\nVary: %s\r\nCache-Control: max-age=3600\r\n", vary[k]);
        hci_set(&p, 1, 200, "vary2", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "vary");
        HINTERNET hi = hci_open(); hci_resp a, b;
        hci_get(hi, url, NULL, 0, &a);
        int stored = hci_exists(url);
        hci_get(hi, url, NULL, 0, &b);
        t_inet_close(hi);
        t_note("Vary: %-28s stored=%d requests=%d second=%s", vary[k], stored, hci_reqs(s, 0), b.body);
        /* VM: Vary: * and Vary: Cookie are never stored; any other Vary is stored and served */
        int want = strcmp(vary[k], "*") && strcmp(vary[k], "Cookie");
        CHECKF(stored == want, "Vary %s stored %d", vary[k], stored);
        CHECKF(hci_reqs(s, 0) == (want ? 1 : 2), "Vary %s requests %d", vary[k], srv_req_count(s));
        CHECKF(!strcmp(b.body, want ? "vary1" : "vary2"), "Vary %s body %s", vary[k], b.body);
        srv_stop(s);
    }
}

/* ---------------------------------------------------------------- Content-Encoding */
TEST(hci_misc_gzip_stored_form_no_decoding) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: text/plain\r\nContent-Encoding: gzip\r\nCache-Control: max-age=3600\r\n");
    rp->body = srv_fox_gzip; rp->len = srv_fox_gzip_len;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "gzraw");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    EXPECT_EQ(r.len, srv_fox_gzip_len);
    CHECK(r.len == srv_fox_gzip_len && !memcmp(r.body, srv_fox_gzip, r.len));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        EXPECT_EQ(e->dwSizeLow, srv_fox_gzip_len);
        char buf[2048]; size_t n; CHECK(hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n));
        CHECK(n == srv_fox_gzip_len && !memcmp(buf, srv_fox_gzip, n));
        CHECK(hci_hdr_has(e, "Content-Encoding: gzip"));
    }
    free(e);
    srv_stop(s);
}

TEST(hci_misc_gzip_stored_form_with_decoding) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: text/plain\r\nContent-Encoding: gzip\r\nCache-Control: max-age=3600\r\n");
    rp->body = srv_fox_gzip; rp->len = srv_fox_gzip_len;
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "gzdec");
    HINTERNET hi = hci_open();
    BOOL on = TRUE; CHECK(U(InternetSetOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on));
    hci_resp a, b;
    hci_get(hi, url, "Accept-Encoding: gzip\r\n", 0, &a);
    hci_get(hi, url, "Accept-Encoding: gzip\r\n", 0, &b);
    t_inet_close(hi);
    EXPECT_EQ(a.len, SRV_FOX_LEN);
    CHECK(a.len == SRV_FOX_LEN && !memcmp(a.body, srv_fox_text(), SRV_FOX_LEN));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        char buf[2048]; size_t n; hci_file_read(e->lpszLocalFileName, buf, sizeof buf, &n);
        t_note("decoding on: cached size=%lu file=%zu (gzip %zu, plain %d) first bytes %02x %02x; blob keeps Content-Encoding=%d", e->dwSizeLow, n, srv_fox_gzip_len, SRV_FOX_LEN,
               (unsigned char)buf[0], (unsigned char)buf[1], hci_hdr_has(e, "Content-Encoding"));
        /* VM: with HTTP_DECODING on, the cache file holds the DECODED body */
        EXPECT_EQ(e->dwSizeLow, SRV_FOX_LEN);
        CHECK(hci_file_eq(e->lpszLocalFileName, srv_fox_text(), SRV_FOX_LEN));
    }
    t_note("decoding on, second GET: requests=%d len=%zu", hci_reqs(s, 0), b.len);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_EQ(b.len, SRV_FOX_LEN);
    CHECK(b.len == SRV_FOX_LEN && !memcmp(b.body, srv_fox_text(), SRV_FOX_LEN));
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- DATAFILE_NAME and the lock */
TEST(hci_misc_datafile_name_during_read) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "datafile-content", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "datafile");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    t_note("DATAFILE_NAME: early=%s (err %lu) after read=%s (err %lu)", r.datafile_early, r.datafile_early_err, r.datafile, r.datafile_err);
    CHECK(r.datafile[0] != 0);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        CHECK(!_stricmp(r.datafile, e->lpszLocalFileName));
        CHECK(!_stricmp(hci_local_ext(e), "txt"));
    }
    free(e);
    srv_stop(s);
}

TEST(hci_misc_datafile_name_from_cache) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "df-cache", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "dfcache");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    CHECK(hci_from_cache(&b));
    CHECK(b.datafile_early[0] != 0);
    EXPECT_STR(b.datafile_early, a.datafile);
    EXPECT_STR(b.datafile, a.datafile);
    srv_stop(s);
}

TEST(hci_misc_datafile_name_buffer_too_small) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "small", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "dfsmall");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char tiny[4]; DWORD l = sizeof tiny; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, tiny, &l));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        char full[MAX_PATH + 1]; DWORD l2 = sizeof full;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, full, &l2));
        t_note("DATAFILE_NAME: needed=%lu, success len=%lu strlen=%zu", l, l2, strlen(full));
        EXPECT_EQ(l, strlen(full) + 1);
        EXPECT_EQ(l2, strlen(full));
        WCHAR w[MAX_PATH + 1]; DWORD lw = sizeof w;
        CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_DATAFILE_NAME, w, &lw));
        t_note("DATAFILE_NAME W len=%lu (wcslen %zu)", lw, wcslen(w));
        EXPECT_EQ(lw, wcslen(w));
        char buf[64]; DWORD rd; while (U(InternetReadFile)(h, buf, sizeof buf, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_misc_datafile_wrong_handle_types) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/x", NULL, NULL, NULL, 0, 0);
    char b[MAX_PATH]; DWORD l = sizeof b;
    SetLastError(0); CHECK(!U(InternetQueryOptionA)(hi, INTERNET_OPTION_DATAFILE_NAME, b, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof b; SetLastError(0); CHECK(!U(InternetQueryOptionA)(hc, INTERNET_OPTION_DATAFILE_NAME, b, &l)); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    l = sizeof b; SetLastError(0); CHECK(!U(InternetQueryOptionA)(hr, INTERNET_OPTION_DATAFILE_NAME, b, &l)); EXPECT_ERR(ERROR_INTERNET_ITEM_NOT_FOUND);
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
}

TEST(hci_misc_entry_locked_while_handle_open) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(DeleteUrlCacheEntryA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "lock-me", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "lock");
    HINTERNET hi = hci_open(); hci_resp a; hci_get(hi, url, NULL, 0, &a);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);       /* served from cache, handle keeps the entry */
    CHECK(h != NULL);
    if (h) {
        char df[MAX_PATH + 1]; DWORD l = sizeof df; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, df, &l));
        SetLastError(0);
        BOOL del = U(DeleteUrlCacheEntryA)(url);
        DWORD derr = GetLastError();
        t_note("DeleteUrlCacheEntry while a cache-read handle is open: ok=%d err=%lu; file exists=%d entry exists=%d", del, derr, hci_file_exists(df), hci_exists(url));
        CHECK(!del); EXPECT_EQ(derr, ERROR_SHARING_VIOLATION);    /* VM: refused, but the delete is remembered */
        CHECK(hci_file_exists(df));
        char buf[64]; DWORD rd = 0; BOOL rok = U(InternetReadFile)(h, buf, sizeof buf - 1, &rd); buf[rd] = 0;
        t_note("  read after delete: ok=%d %s", rok, buf);
        CHECK(rok); EXPECT_STR(buf, "lock-me");
        U(InternetCloseHandle)(h);
        t_note("  after close: file exists=%d entry exists=%d", hci_file_exists(df), hci_exists(url));
        CHECK(!hci_exists(url));                      /* VM: the pending delete happens on the last unlock */
    }
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_misc_datafile_share_mode_while_open) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "share-mode", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "share");
    HINTERNET hi = hci_open();
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    CHECK(h != NULL);
    if (h) {
        char df[MAX_PATH + 1]; DWORD l = sizeof df; df[0] = 0;
        CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_DATAFILE_NAME, df, &l));
        HANDLE f1 = CreateFileA(df, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        DWORD e1 = GetLastError();
        HANDLE f2 = CreateFileA(df, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD e2 = GetLastError();
        t_note("cache file during download: open(share all)=%d err=%lu open(share read only)=%d err=%lu", f1 != INVALID_HANDLE_VALUE, e1, f2 != INVALID_HANDLE_VALUE, e2);
        CHECK(f1 != INVALID_HANDLE_VALUE);
        CHECK(f2 == INVALID_HANDLE_VALUE); EXPECT_EQ(e2, ERROR_SHARING_VIOLATION);   /* VM: wininet holds it open for writing */
        if (f1 != INVALID_HANDLE_VALUE) CloseHandle(f1);
        if (f2 != INVALID_HANDLE_VALUE) CloseHandle(f2);
        char buf[64]; DWORD rd; while (U(InternetReadFile)(h, buf, sizeof buf, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hi);
    srv_stop(s);
}

/* ---------------------------------------------------------------- deletion */
TEST(hci_misc_delete_entry_removes_file) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(DeleteUrlCacheEntryA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "delete-me", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "delete");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) {
        CHECK(hci_file_exists(e->lpszLocalFileName));
        CHECK(U(DeleteUrlCacheEntryA)(url));
        int gone = 0; for (int i = 0; i < 20 && !gone; i++) { gone = !hci_file_exists(e->lpszLocalFileName); if (!gone) Sleep(50); }
        CHECK(gone);
        DWORD e2; INTERNET_CACHE_ENTRY_INFOA *x = hci_info(url, &e2);
        CHECK(x == NULL); EXPECT_EQ(e2, ERROR_FILE_NOT_FOUND);
        free(x);
        SetLastError(0); CHECK(!U(DeleteUrlCacheEntryA)(url)); EXPECT_ERR(ERROR_FILE_NOT_FOUND);
    }
    free(e);
    srv_stop(s);
}

TEST(hci_misc_deleted_entry_refetched) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(DeleteUrlCacheEntryA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "one", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "two", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "delrefetch");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    CHECK(U(DeleteUrlCacheEntryA)(url));
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    EXPECT_STR(b.body, "two");
    EXPECT_EQ(hci_reqs(s, 2), 2);
    srv_stop(s);
}

TEST(hci_misc_deleted_file_behind_wininet) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "orig", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "refetched", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fileremoved");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_get(hi, url, NULL, 0, &a);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    CHECK(e != NULL);
    if (e) CHECK(DeleteFileA(e->lpszLocalFileName));
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    t_note("cache file deleted behind wininet: second body=%s requests=%d", b.body, hci_reqs(s, 0));
    EXPECT_EQ(hci_reqs(s, 0), 2);
    EXPECT_STR(b.body, "refetched");
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- use count / hit rate */
TEST(hci_misc_hit_rate_and_use_count) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hits", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hitrate");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_get(hi, url, NULL, 0, &r);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e0 = hci_info(url, &err);
    for (int i = 0; i < 3; i++) hci_get(hi, url, NULL, 0, &r);
    INTERNET_CACHE_ENTRY_INFOA *e1 = hci_info(url, &err);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    CHECK(e0 && e1);
    if (e0 && e1) {
        t_note("hit rate after download=%lu after 3 cache hits=%lu; use count %lu -> %lu; access %llx -> %llx",
               e0->dwHitRate, e1->dwHitRate, e0->dwUseCount, e1->dwUseCount, hci_ft(e0->LastAccessTime), hci_ft(e1->LastAccessTime));
        EXPECT_EQ(e1->dwHitRate, e0->dwHitRate + 3);
        EXPECT_EQ(e1->dwUseCount, 0);
        CHECK(hci_ft(e1->LastAccessTime) >= hci_ft(e0->LastAccessTime));
    }
    free(e0); free(e1);
    srv_stop(s);
}

TEST(hci_misc_use_count_while_reading) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "usecount", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "usecount");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r);
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, 0);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    if (e) t_note("use count with an open cache-read handle: %lu", e->dwUseCount);
    CHECK(e && e->dwUseCount == 1);
    if (h) U(InternetCloseHandle)(h);
    INTERNET_CACHE_ENTRY_INFOA *e2 = hci_info(url, &err);
    if (e2) t_note("use count after close: %lu", e2->dwUseCount);
    if (e2) EXPECT_EQ(e2->dwUseCount, 0);
    t_inet_close(hi);
    free(e); free(e2);
    srv_stop(s);
}

TEST(hci_misc_retrieve_file_after_http) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(RetrieveUrlCacheEntryFileA)); REQUIRE(U(UnlockUrlCacheEntryFileA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "retrieve", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "retrieve");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    char buf[4096]; INTERNET_CACHE_ENTRY_INFOA *e = (void *)buf; DWORD n = sizeof buf;
    CHECK(U(RetrieveUrlCacheEntryFileA)(url, e, &n, 0));
    EXPECT_EQ(e->dwUseCount, 1);
    char fb[64]; size_t k; CHECK(hci_file_read(e->lpszLocalFileName, fb, sizeof fb, &k)); EXPECT_STR(fb, "retrieve");
    CHECK(U(UnlockUrlCacheEntryFileA)(url, 0));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e2 = hci_info(url, &err);
    if (e2) EXPECT_EQ(e2->dwUseCount, 0);
    free(e2);
    srv_stop(s);
}

TEST(hci_misc_find_entry_enumeration) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(FindFirstUrlCacheEntryA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "enum", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "enum");
    HINTERNET hi = hci_open(); hci_resp r; hci_get(hi, url, NULL, 0, &r); t_inet_close(hi);
    char buf[16384]; INTERNET_CACHE_ENTRY_INFOA *e = (void *)buf; DWORD n = sizeof buf; int found = 0, seen = 0;
    HANDLE f = U(FindFirstUrlCacheEntryA)("http:", e, &n);
    CHECK(f != NULL);
    if (f) {
        do { seen++; if (!strcmp(e->lpszSourceUrlName, url)) found = 1; n = sizeof buf; } while (!found && seen < 20000 && U(FindNextUrlCacheEntryA)(f, e, &n));
        U(FindCloseUrlCache)(f);
    }
    t_note("enumeration saw %d entries before finding ours", seen);
    CHECK(found);
    srv_stop(s);
}
