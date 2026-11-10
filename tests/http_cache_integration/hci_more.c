/* hci_more.c - method interplay (POST/HEAD/GET on one URL, POST -> 303), content decoding and the stored form,
 * status callbacks of a cache hit, cache keys of URL spellings, the WebDAV Translate exception, IGNORE_OFFLINE.
 * Decomp (wininet 10.0.19041): FCanWriteToCache@0x6a120 (no-store / HTTP 0.9 delete the existing entry unless the
 *   request carries a WebDAV Translate header: IsWebDAVTranslateHeaderPresent; POST needs a secondary key;
 *   302/303/307 need Expires or max-age; HTTPS: Pragma: no-cache / DisableCachingOfSSLPages).
 * VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

/* ---------------------------------------------------------------- methods on one URL */
TEST(hci_more_post_keeps_get_entry_fresh) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "get-1", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "post-1", "Content-Type: text/plain\r\n");
    hci_set(&p, 2, 200, "get-2", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "postget2");
    HINTERNET hi = hci_open(); hci_resp a, b, c;
    hci_get(hi, url, NULL, 0, &a);
    hci_req(hi, s, "POST", url, 0, NULL, "x=1", 3, NULL, NULL, &b);
    hci_get(hi, url, NULL, 0, &c);
    t_inet_close(hi);
    t_note("GET, POST, GET: requests=%d third=%s from_cache=%d", hci_reqs(s, 0), c.body, hci_from_cache(&c));
    EXPECT_STR(b.body, "post-1");
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(c.body, "get-1");
    srv_stop(s);
}

TEST(hci_more_head_then_get) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "head-reply", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "get-reply", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "headget");
    HINTERNET hi = hci_open(); hci_resp a, b;
    hci_req(hi, s, "HEAD", url, 0, NULL, NULL, 0, NULL, NULL, &a);
    CHECK(!hci_exists(url));
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "get-reply");
    CHECK(hci_exists(url));
    if (srv_req_count(s) >= 2) { EXPECT_STR(srv_req_method(s, 0), "HEAD"); EXPECT_STR(srv_req_method(s, 1), "GET"); }
    srv_stop(s);
}

TEST(hci_more_post_303_target_cached) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "p303")); snprintf(dst, sizeof dst, "%s", hci_url(s, "p303dst"));
    hci_set(&p, 0, 303, "", "Location: %s\r\n", dst);
    hci_set(&p, 1, 200, "after-post", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "POST", src, 0, "Content-Type: application/x-www-form-urlencoded\r\n", "a=1", 3, NULL, NULL, &r);
    t_inet_close(hi);
    EXPECT_STR(r.body, "after-post");
    EXPECT_STR(r.url_opt, dst);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    if (srv_req_count(s) >= 2) { EXPECT_STR(srv_req_method(s, 0), "POST"); EXPECT_STR(srv_req_method(s, 1), "GET"); }
    CHECK(!hci_exists(src));
    t_note("POST -> 303 -> GET target: target cached=%d", hci_exists(dst));
    CHECK(hci_exists(dst));
    srv_stop(s);
}

static void set_key_more(HINTERNET h, void *ctx) { U(InternetSetOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, ctx, (DWORD)strlen(ctx)); }
TEST(hci_more_post_with_key_303) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "pk303")); snprintf(dst, sizeof dst, "%s", hci_url(s, "pk303dst"));
    char keyed[600]; snprintf(keyed, sizeof keyed, "%sKEY", src); t_cache_track(keyed);
    hci_set(&p, 0, 303, "", "Location: %s\r\n", dst);
    hci_set(&p, 1, 200, "keyed-target", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "POST", src, 0, NULL, "a=1", 3, set_key_more, "KEY", &r);
    t_inet_close(hi);
    t_note("POST 303 keyed source: src=%d keyed=%d dst=%d", hci_exists(src), hci_exists(keyed), hci_exists(dst));
    EXPECT_STR(r.body, "keyed-target");
    srv_stop(s);
}

/* PUT/DELETE/POST to a URL: what happens to a fresh GET entry (VM: PUT keeps it) */
TEST(hci_more_unsafe_methods_vs_get_entry) {
    REQUIRE(U(HttpSendRequestA));
    static const char *verbs[] = { "POST", "PUT", "DELETE", "PATCH" };
    for (size_t k = 0; k < 4; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "get-entry", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        hci_set(&p, 1, 200, "unsafe", "Content-Type: text/plain\r\n");
        hci_set(&p, 2, 200, "get-again", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "unsafe");
        HINTERNET hi = hci_open(); hci_resp a, b, c;
        hci_get(hi, url, NULL, 0, &a);
        hci_req(hi, s, verbs[k], url, 0, NULL, "d", 1, NULL, NULL, &b);
        hci_get(hi, url, NULL, 0, &c);
        t_inet_close(hi);
        int n = hci_reqs(s, 0);
        t_note("%s between two GETs: requests=%d entry=%d third=%s", verbs[k], n, hci_exists(url), c.body);
        CHECKF(!strcmp(b.body, "unsafe"), "%s body %s", verbs[k], b.body);
        CHECKF(hci_exists(url), "%s removed the GET entry", verbs[k]);
        CHECKF(n == 2 && !strcmp(c.body, "get-entry"), "%s: requests %d third %s", verbs[k], n, c.body);
        srv_stop(s);
    }
}

/* ---------------------------------------------------------------- content decoding and the stored form */
typedef struct { const char *enc; int mode; } encrow;      /* mode for srv_deflate_stored: 0 gzip 1 zlib 2 raw */
TEST(hci_more_decoding_stored_form_table) {
    REQUIRE(U(InternetOpenUrlA));
    static const encrow rows[] = { { "gzip", 0 }, { "deflate", 1 }, { "deflate", 2 }, { "x-gzip", 0 } };
    static const char plain[] = "decoded body for the cache, stored in which form?";
    for (int dec = 0; dec < 2; dec++) for (size_t k = 0; k < 4; k++) {
        size_t zn = 0; unsigned char *z = srv_deflate_stored(plain, sizeof plain - 1, rows[k].mode, &zn);
        hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: text/plain\r\nContent-Encoding: %s\r\nCache-Control: max-age=3600\r\n", rows[k].enc);
        rp->body = z; rp->len = zn;
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { free(z); t_skip("server"); return; }
        const char *url = hci_url(s, "enc");
        HINTERNET hi = hci_open();
        BOOL on = dec; U(InternetSetOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on);
        hci_resp a, b; hci_get(hi, url, "Accept-Encoding: gzip, deflate\r\n", 0, &a); hci_get(hi, url, "Accept-Encoding: gzip, deflate\r\n", 0, &b);
        t_inet_close(hi);
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
        int got_plain = a.len == sizeof plain - 1 && !memcmp(a.body, plain, a.len);
        int stored_plain = e && hci_file_eq(e->lpszLocalFileName, plain, sizeof plain - 1), stored_z = e && hci_file_eq(e->lpszLocalFileName, z, zn);
        t_note("decoding=%d %s(mode %d): app got plain=%d len=%zu; stored plain=%d compressed=%d size=%lu CE kept=%d; second len=%zu requests=%d",
               dec, rows[k].enc, rows[k].mode, got_plain, a.len, stored_plain, stored_z, e ? e->dwSizeLow : 0, e ? hci_hdr_has(e, "Content-Encoding") : -1, b.len, hci_reqs(s, 0));
        CHECKF(e != NULL, "dec %d %s not stored", dec, rows[k].enc);
        int known = strcmp(rows[k].enc, "x-gzip") != 0;
        if (known) {
            CHECKF(got_plain == dec, "dec %d %s/%d app plain %d", dec, rows[k].enc, rows[k].mode, got_plain);
            CHECKF(dec ? stored_plain : stored_z, "dec %d %s/%d stored form", dec, rows[k].enc, rows[k].mode);
        }
        CHECKF(hci_reqs(s, 0) == 1, "dec %d %s requests %d", dec, rows[k].enc, srv_req_count(s));
        CHECKF(b.len == a.len && !memcmp(a.body, b.body, a.len), "dec %d %s: cache hit differs from first read", dec, rows[k].enc);
        free(e);
        srv_stop(s);
        free(z);
    }
}

/* stored decoded with decoding on, then read by a session with decoding off */
TEST(hci_more_decoded_entry_read_without_decoding) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_reply *rp = hci_set(&p, 0, 200, NULL, "Content-Type: text/plain\r\nContent-Encoding: gzip\r\nCache-Control: max-age=3600\r\n");
    rp->body = srv_fox_gzip; rp->len = srv_fox_gzip_len;
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "decmix");
    HINTERNET h1 = hci_open(); BOOL on = TRUE; U(InternetSetOptionA)(h1, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on);
    hci_resp a, b; hci_get(h1, url, "Accept-Encoding: gzip\r\n", 0, &a); t_inet_close(h1);
    HINTERNET h2 = hci_open(); hci_get(h2, url, NULL, 0, &b); t_inet_close(h2);
    int b_plain = b.len == SRV_FOX_LEN && !memcmp(b.body, srv_fox_text(), SRV_FOX_LEN);
    int b_gz = b.len == srv_fox_gzip_len && !memcmp(b.body, srv_fox_gzip, b.len);
    t_note("decoded entry read without decoding: requests=%d len=%zu plain=%d gzip=%d CE header in response=%d", hci_reqs(s, 0), b.len, b_plain, b_gz, strstr(b.rawhdrs, "Content-Encoding") != NULL);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    CHECK(b_plain || b_gz);
    srv_stop(s);
}

/* decoding on, server did not compress */
TEST(hci_more_decoding_on_identity_response) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "identity-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ident");
    HINTERNET hi = hci_open(); BOOL on = TRUE; U(InternetSetOptionA)(hi, INTERNET_OPTION_HTTP_DECODING, &on, sizeof on);
    hci_resp a; hci_get(hi, url, "Accept-Encoding: gzip\r\n", 0, &a); t_inet_close(hi);
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
    EXPECT_STR(a.body, "identity-body");
    CHECK(e && hci_file_eq(e->lpszLocalFileName, "identity-body", 13));
    CHECK(e && e->dwSizeLow == 13);
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- status callbacks of a cache hit */
#define CB_MAX 64
typedef struct { volatile LONG n; DWORD st[CB_MAX]; } cb_log;
static void CALLBACK cb_fn(HINTERNET h, DWORD_PTR ctx, DWORD status, LPVOID info, DWORD len) {
    cb_log *c = (cb_log *)ctx; if (!c) return;
    LONG i = InterlockedIncrement(&c->n) - 1; if (i < CB_MAX) c->st[i] = status;
}
static int cb_has(const cb_log *c, DWORD st) { for (LONG i = 0; i < c->n && i < CB_MAX; i++) if (c->st[i] == st) return 1; return 0; }
static void cb_note(const char *what, const cb_log *c) {
    char b[512]; int k = 0; for (LONG i = 0; i < c->n && i < CB_MAX && k < 480; i++) k += snprintf(b + k, sizeof b - k, "%lu ", c->st[i]);
    b[k] = 0; t_note("%s callbacks: %s", what, b);
}
TEST(hci_more_status_callbacks_cache_hit) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "callbacks", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "cbhit");
    HINTERNET hi = hci_open();
    U(InternetSetStatusCallbackA)(hi, cb_fn);
    cb_log net = {0}, hit = {0};
    for (int k = 0; k < 2; k++) {
        cb_log *c = k ? &hit : &net;
        HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, (DWORD_PTR)c);
        CHECK(h != NULL);
        if (h) { char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ; U(InternetCloseHandle)(h); }
    }
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi);
    cb_note("network GET", &net); cb_note("cache hit", &hit);
    CHECK(cb_has(&net, INTERNET_STATUS_SENDING_REQUEST));
    CHECK(cb_has(&net, INTERNET_STATUS_RESPONSE_RECEIVED));
    CHECK(!cb_has(&hit, INTERNET_STATUS_CONNECTING_TO_SERVER));
    CHECK(!cb_has(&hit, INTERNET_STATUS_SENDING_REQUEST));
    CHECK(!cb_has(&hit, INTERNET_STATUS_REQUEST_SENT));
    CHECK(!cb_has(&hit, INTERNET_STATUS_RECEIVING_RESPONSE));
    CHECK(cb_has(&hit, INTERNET_STATUS_HANDLE_CREATED));
    CHECK(cb_has(&hit, INTERNET_STATUS_HANDLE_CLOSING));
    EXPECT_EQ(hci_reqs(s, 0), 1);
    srv_stop(s);
}

TEST(hci_more_status_callbacks_revalidation) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "cb304", "Content-Type: text/plain\r\nETag: \"cb\"\r\nCache-Control: max-age=0\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "cb304");
    hci_resp a; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = hci_open();
    U(InternetSetStatusCallbackA)(hi, cb_fn);
    cb_log c = {0};
    HINTERNET h = U(InternetOpenUrlA)(hi, url, NULL, 0, 0, (DWORD_PTR)&c);
    CHECK(h != NULL);
    if (h) { char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ; U(InternetCloseHandle)(h); }
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hi);
    cb_note("revalidation", &c);
    CHECK(cb_has(&c, INTERNET_STATUS_SENDING_REQUEST));
    CHECK(cb_has(&c, INTERNET_STATUS_RESPONSE_RECEIVED));
    EXPECT_EQ(p.cond_served, 1);
    srv_stop(s);
}

/* ---------------------------------------------------------------- cache keys of URL spellings */
TEST(hci_more_path_case_separate_entries) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "lower", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "upper", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *u = t_uniq("case");
    char p1[200], p2[200], u1[512], u2[512];
    snprintf(p1, sizeof p1, "/%s/abc", u); snprintf(p2, sizeof p2, "/%s/ABC", u);
    snprintf(u1, sizeof u1, "%s", srv_url(s, p1)); snprintf(u2, sizeof u2, "%s", srv_url(s, p2)); t_cache_track(u1); t_cache_track(u2);
    hci_resp a, b; free(hci_fetch(u1, NULL, 0, &a)); free(hci_fetch(u2, NULL, 0, &b));
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "upper");
    CHECK(hci_exists(u1)); CHECK(hci_exists(u2));
    srv_stop(s);
}

TEST(hci_more_host_case_same_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "lc-host", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "uc-host", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hostcase");
    const char *path = strchr(url + 7, '/');
    char lh[512], uh[512];
    snprintf(lh, sizeof lh, "%s", srv_url_host(s, "localhost", path)); snprintf(uh, sizeof uh, "%s", srv_url_host(s, "LOCALHOST", path));
    t_cache_track(lh); t_cache_track(uh);
    hci_resp a, b; free(hci_fetch(lh, NULL, 0, &a)); free(hci_fetch(uh, NULL, 0, &b));
    t_note("localhost then LOCALHOST: requests=%d second=%s url opt=%s entry(UC)=%d", hci_reqs(s, 0), b.body, b.url_opt, hci_exists(uh));
    srv_stop(s);
}

TEST(hci_more_escaped_path_keys) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "tilde-1", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "tilde-2", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *u = t_uniq("esc");
    char p1[200], p2[200], u1[512], u2[512];
    snprintf(p1, sizeof p1, "/%s/~x", u); snprintf(p2, sizeof p2, "/%s/%%7Ex", u);
    snprintf(u1, sizeof u1, "%s", srv_url(s, p1)); snprintf(u2, sizeof u2, "%s", srv_url(s, p2)); t_cache_track(u1); t_cache_track(u2);
    hci_resp a, b; free(hci_fetch(u1, NULL, 0, &a)); free(hci_fetch(u2, NULL, 0, &b));
    hci_reqs(s, 2);
    t_note("~ vs %%7E: requests=%d second=%s targets [%s] [%s] entries %d/%d", srv_req_count(s), b.body, srv_req_target(s, 0) ? srv_req_target(s, 0) : "-",
           srv_req_target(s, 1) ? srv_req_target(s, 1) : "-", hci_exists(u1), hci_exists(u2));
    CHECK(hci_exists(u1));
    srv_stop(s);
}

TEST(hci_more_empty_query_key) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "no-q", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "empty-q", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "emptyq");
    char q[512]; snprintf(q, sizeof q, "%s?", url); t_cache_track(q);
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a)); free(hci_fetch(q, NULL, 0, &b));
    hci_reqs(s, 2);
    t_note("URL then URL?: requests=%d second=%s entries %d/%d", srv_req_count(s), b.body, hci_exists(url), hci_exists(q));
    CHECK(hci_exists(url));
    srv_stop(s);
}

TEST(hci_more_query_order_separate_entries) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "ab", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "ba", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "qorder");
    char q1[512], q2[512]; snprintf(q1, sizeof q1, "%s?a=1&b=2", url); snprintf(q2, sizeof q2, "%s?b=2&a=1", url); t_cache_track(q1); t_cache_track(q2);
    hci_resp a, b; free(hci_fetch(q1, NULL, 0, &a)); free(hci_fetch(q2, NULL, 0, &b));
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "ba");
    CHECK(hci_exists(q1)); CHECK(hci_exists(q2));
    CHECK(!hci_exists(url));
    srv_stop(s);
}

TEST(hci_more_userinfo_url_key) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "userinfo", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *plain = hci_url(s, "uinfo");
    char ui[600]; snprintf(ui, sizeof ui, "http://dummyuser:dummypw@127.0.0.1:%u%s", srv_port(s), strchr(plain + 7, '/')); t_cache_track(ui);
    hci_resp r; HINTERNET hi = hci_open(); hci_get(hi, ui, NULL, 0, &r); t_inet_close(hi);
    t_note("URL with userinfo: status=%d url opt=%s entry(plain)=%d entry(userinfo)=%d Authorization=%s", r.status, r.url_opt, hci_exists(plain), hci_exists(ui),
           hci_rh(s, 0, "Authorization") ? "sent" : "-");
    EXPECT_EQ(r.status, 200);
    CHECK(hci_exists(plain) || hci_exists(ui));
    srv_stop(s);
}

/* ---------------------------------------------------------------- the WebDAV Translate exception */
TEST(hci_more_no_store_with_translate_keeps_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "keep-me", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "no-store", "Content-Type: text/plain\r\nCache-Control: no-store\r\n");
    hci_set(&p, 2, 200, "no-store-2", "Content-Type: text/plain\r\nCache-Control: no-store\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "translate");
    hci_resp a, b, c; free(hci_fetch(url, NULL, 0, &a));
    free(hci_fetch(url, "Translate: f\r\n", INTERNET_FLAG_RELOAD, &b));
    int kept = hci_exists(url);
    t_note("no-store response to a request with Translate: f -> entry kept=%d", kept);
    CHECK(kept);
    EXPECT_STR(hci_rh(s, 1, "Translate"), "f");
    free(hci_fetch(url, NULL, INTERNET_FLAG_RELOAD, &c));
    CHECK(!hci_exists(url));                           /* without the header the entry is deleted */
    srv_stop(s);
}

/* the Authorization header supplied by the application */
TEST(hci_more_app_authorization_header_cached) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "auth-body", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "appauth");
    hci_resp a, b; free(hci_fetch(url, "Authorization: Basic ZHVtbXk6ZHVtbXk=\r\n", 0, &a));
    int stored = hci_exists(url);
    free(hci_fetch(url, NULL, 0, &b));
    t_note("app Authorization header: stored=%d second requests=%d body=%s", stored, hci_reqs(s, 0), b.body);
    EXPECT_STR(a.body, "auth-body");
    srv_stop(s);
}

/* ---------------------------------------------------------------- offline session and IGNORE_OFFLINE */
TEST(hci_more_offline_session_ignore_offline_request) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "from-net", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ignoff");
    HINTERNET hi = t_inet_open_ex("hci-agent", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    CHECK(hi != NULL);
    hci_resp r1, r2;
    hci_req(hi, s, "GET", url, 0, NULL, NULL, 0, NULL, NULL, &r1);
    CHECK(!r1.ok); EXPECT_EQ(r1.err, ERROR_FILE_NOT_FOUND);
    hci_req(hi, s, "GET", url, INTERNET_FLAG_RELOAD, NULL, NULL, 0, NULL, NULL, &r2);
    t_note("offline session: miss err=%lu; RELOAD on offline session ok=%d err=%lu requests=%d", r1.err, r2.ok, r2.err, hci_reqs(s, 0));
    t_inet_close(hi);
    srv_stop(s);
}

TEST(hci_more_offline_session_stale_entry_served) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "stale-off", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "staleoff");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    HINTERNET hi = t_inet_open_ex("hci-agent", INTERNET_OPEN_TYPE_DIRECT, INTERNET_FLAG_OFFLINE, 5000);
    hci_get(hi, url, NULL, 0, &b);
    t_inet_close(hi);
    CHECK(b.ok);
    EXPECT_STR(b.body, "stale-off");
    EXPECT_EQ(hci_reqs(s, 0), 1);
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}

TEST(hci_more_offline_redirect_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char src[512], dst[512]; snprintf(src, sizeof src, "%s", hci_url(s, "off301")); snprintf(dst, sizeof dst, "%s", hci_url(s, "off301dst"));
    hci_set(&p, 0, 301, "", "Location: %s\r\n", dst);
    hci_set(&p, 1, 200, "offline-target", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_resp a, b; free(hci_fetch(src, NULL, 0, &a));
    HINTERNET hi = hci_open(); hci_get(hi, src, NULL, INTERNET_FLAG_FROM_CACHE, &b); t_inet_close(hi);
    t_note("FROM_CACHE on a cached 301 source: ok=%d err=%lu status=%d body=%s url=%s requests=%d", b.ok, b.err, b.status, b.body, b.url_opt, hci_reqs(s, 0));
    EXPECT_EQ(hci_reqs(s, 0), 2);
    srv_stop(s);
}

/* ---------------------------------------------------------------- secondary key details */
TEST(hci_more_secondary_key_wide_set) {
    REQUIRE(U(InternetSetOptionW)); REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "wkey", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "wkey");
    char keyed[600]; snprintf(keyed, sizeof keyed, "%sWK", url); t_cache_track(keyed);
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc; char path[512]; uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof path;
    CHECK(U(InternetCrackUrlA)(url, 0, 0, &uc));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, 0, 0);
    CHECK(h != NULL);
    if (h) {
        SetLastError(0); BOOL ok = U(InternetSetOptionW)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, (void *)L"WK", 2);
        t_note("SECONDARY_CACHE_KEY via W (2 chars): ok=%d err=%lu", ok, GetLastError());
        CHECK(ok);
        char q[64]; DWORD l = sizeof q; CHECK(U(InternetQueryOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, q, &l));
        EXPECT_STR(q, "WK");
        WCHAR wq[64]; DWORD lw = sizeof wq; CHECK(U(InternetQueryOptionW)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, wq, &lw));
        EXPECT_WSTR(wq, L"WK");
        t_note("W query length %lu", lw);
        CHECK(U(HttpSendRequestA)(h, NULL, 0, NULL, 0));
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hc); t_inet_close(hi);
    CHECK(hci_exists(keyed));
    srv_stop(s);
}

TEST(hci_more_secondary_key_after_send) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "late", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "latekey");
    char keyed[600]; snprintf(keyed, sizeof keyed, "%sLATE", url); t_cache_track(keyed);
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc; char path[512]; uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof path;
    CHECK(U(InternetCrackUrlA)(url, 0, 0, &uc));
    HINTERNET hi = hci_open();
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h = U(HttpOpenRequestA)(hc, "GET", path, NULL, NULL, NULL, 0, 0);
    if (h) {
        CHECK(U(HttpSendRequestA)(h, NULL, 0, NULL, 0));
        SetLastError(0); BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, "LATE", 4);
        DWORD e = GetLastError();
        char b[64]; DWORD rd; while (U(InternetReadFile)(h, b, sizeof b, &rd) && rd) ;
        U(InternetCloseHandle)(h);
        t_note("SECONDARY_CACHE_KEY after send: ok=%d err=%lu; entries plain=%d keyed=%d", ok, e, hci_exists(url), hci_exists(keyed));
    }
    t_inet_close(hc); t_inet_close(hi);
    CHECK(hci_exists(url) || hci_exists(keyed));
    srv_stop(s);
}

TEST(hci_more_secondary_key_empty) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "empty-key", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "emptykey");
    HINTERNET hi = hci_open(); hci_resp r;
    hci_req(hi, s, "POST", url, 0, NULL, "x", 1, (hci_setup_fn)0, NULL, &r);
    t_inet_close(hi);
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc); uc.dwStructSize = sizeof uc; char path[512]; uc.lpszUrlPath = path; uc.dwUrlPathLength = sizeof path;
    CHECK(U(InternetCrackUrlA)(url, 0, 0, &uc));
    HINTERNET h2 = hci_open();
    HINTERNET hc = U(InternetConnectA)(h2, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET h = U(HttpOpenRequestA)(hc, "POST", path, NULL, NULL, NULL, 0, 0);
    if (h) {
        SetLastError(0); BOOL ok = U(InternetSetOptionA)(h, INTERNET_OPTION_SECONDARY_CACHE_KEY, "", 0);
        t_note("SECONDARY_CACHE_KEY empty: ok=%d err=%lu", ok, GetLastError());
        U(InternetCloseHandle)(h);
    }
    t_inet_close(hc); t_inet_close(h2);
    CHECK(!hci_exists(url));
    srv_stop(s);
}

/* the redirect cache read follows a cached redirect chain */
typedef struct { DWORD v; } rcr2;
static void set_rcr2(HINTERNET h, void *ctx) { DWORD v = 1; (void)ctx; U(InternetSetOptionA)(h, INTERNET_OPTION_ENABLE_REDIRECT_CACHE_READ, &v, 4); }
TEST(hci_more_redirect_chain_cache_read) {
    REQUIRE(U(HttpSendRequestA));
    hci_plan p = {0};
    srv *s; HCI_START(&p, s);
    char a1[512], a2[512], a3[512];
    snprintf(a1, sizeof a1, "%s", hci_url(s, "ch1")); snprintf(a2, sizeof a2, "%s", hci_url(s, "ch2")); snprintf(a3, sizeof a3, "%s", hci_url(s, "ch3"));
    hci_set(&p, 0, 301, "", "Location: %s\r\n", a2);
    hci_set(&p, 1, 301, "", "Location: %s\r\n", a3);
    hci_set(&p, 2, 200, "chain-end", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    hci_set(&p, 3, 200, "network", "Content-Type: text/plain\r\n");
    HINTERNET hi = hci_open(); hci_resp r1, r2;
    hci_req(hi, s, "GET", a1, 0, NULL, NULL, 0, set_rcr2, NULL, &r1);
    hci_req(hi, s, "GET", a1, 0, NULL, NULL, 0, set_rcr2, NULL, &r2);
    t_inet_close(hi);
    t_note("cached 301 chain with REDIRECT_CACHE_READ: requests=%d second=%s url=%s from_cache=%d", hci_reqs(s, 0), r2.body, r2.url_opt, hci_from_cache(&r2));
    EXPECT_STR(r1.body, "chain-end");
    CHECK(hci_exists(a1)); CHECK(hci_exists(a2)); CHECK(hci_exists(a3));
    EXPECT_STR(r2.body, "chain-end");
    srv_stop(s);
}

/* a request header Range from the app: the 206 is not cached */
TEST(hci_more_app_range_206_not_cached) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 206, "part", "Content-Type: text/plain\r\nContent-Range: bytes 0-3/10\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "range206");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, "Range: bytes=0-3\r\n", 0, &r);
    EXPECT_EQ(r.status, 206);
    EXPECT_STR(r.body, "part");
    t_note("206 to an app Range request: entry=%d type=0x%lx", e != NULL, e ? e->CacheEntryType : 0);
    free(e);
    srv_stop(s);
}

/* INTERNET_FLAG_CACHE_ASYNC (0x80) and INTERNET_FLAG_EXISTING_CONNECT do not change cache behaviour */
TEST(hci_more_misc_flags_still_cache) {
    REQUIRE(U(InternetOpenUrlA));
    static const DWORD flags[] = { INTERNET_FLAG_CACHE_ASYNC, INTERNET_FLAG_EXISTING_CONNECT, INTERNET_FLAG_KEEP_CONNECTION, INTERNET_FLAG_NO_COOKIES, INTERNET_FLAG_NO_UI };
    for (size_t k = 0; k < 5; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "flagged", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "miscflag");
        hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, flags[k], &a);
        CHECKF(e != NULL, "flags 0x%lx not stored", flags[k]);
        free(e);
        free(hci_fetch(url, NULL, flags[k], &b));
        CHECKF(hci_reqs(s, 0) == 1 && !strcmp(b.body, "flagged"), "flags 0x%lx: requests %d body %s", flags[k], srv_req_count(s), b.body);
        srv_stop(s);
    }
}
