/* hci_expiry.c - how a response's headers become the entry's ExpireTime / LastModifiedTime, and how the stored times
 * decide freshness on the next request.
 * Decomp (wininet 10.0.19041):
 *   GetCacheTimeStampsFromHeaders@0x6bd80: every Cache-Control header, every token in order (case-insensitive):
 *     max-age=N (spaces/tabs allowed around '=', N clamped to 0x7fffffff): Expire = now + (N - age),
 *       age = max(Age header, now - Date); N - age < 1 -> Expire = now - 3600 s;
 *     stale-while-revalidate=S with a positive max-age: Expire += S;  no-cache (then end, ',' or '='): Expire = now - 3600 s;
 *     pre-check / post-check / must-revalidate / immutable are parsed too.
 *   Without max-age/no-cache: Expires; unparsable -> now - 3600 s; Expires <= Date -> now - 3600 s.
 *   Last-Modified -> LastModifiedTime (unparsable -> 0).
 *   IsExpired@0xc7d88(type, Expire, LM, Sync, ..., dwFlags, ...): dwFlags & 0x20 (INTERNET_FLAG_FWD_BACK) -> fresh;
 *     Expire != 0 -> expired iff Expire <= now; else (SyncMode automatic) LM != 0 -> fresh iff now <= Sync + (Sync - LM)/10;
 *     LM == 0: HYPERLINK -> expired, otherwise the session rule (Sync after the session start and within the default delta).
 * VM_TIMEOUT: 420 */
#include "hci.h"
#include <stdlib.h>

/* ---------------------------------------------------------------- ExpireTime from response headers */
typedef struct {
    const char *cc;      /* Cache-Control value, NULL = none */
    const char *extra;   /* extra header lines; "%D" -> Date line (date_off), "%A" literal not used */
    int date_off_set; LONGLONG date_off;  /* add Date: now+date_off */
    int kind;            /* 0: ExpireTime 0; 1: ExpireTime ~ now + want; 2: note only */
    LONGLONG want;
    int second;          /* requests expected after a second GET: 1 cache, 2 network, 0 unknown (note) */
} exp_row;

static const exp_row g_exp[] = {
    { "max-age=60",                NULL, 0, 0, 1, 60, 1 },
    { "max-age=86400",             NULL, 0, 0, 1, 86400, 1 },
    { "max-age = 600",             NULL, 0, 0, 1, 600, 1 },
    { "max-age=\t900",             NULL, 0, 0, 1, 900, 1 },
    { "MAX-AGE=1200",              NULL, 0, 0, 1, 1200, 1 },
    { "Max-Age=1300",              NULL, 0, 0, 1, 1300, 1 },
    { "max-age=0",                 NULL, 0, 0, 1, -3600, 2 },
    { "max-age=1",                 NULL, 0, 0, 2, 1, 0 },
    { "max-age=99999999999",       NULL, 0, 0, 1, 0x7fffffffLL, 1 },
    { "public, max-age=300",       NULL, 0, 0, 1, 300, 1 },
    { "max-age=300, private",      NULL, 0, 0, 1, 300, 1 },
    { "max-age=7200",              "Age: 3600\r\n", 0, 0, 1, 3600, 1 },
    { "max-age=7200",              "Age: 9000\r\n", 0, 0, 1, -3600, 2 },
    { "max-age=7200",              "Age: 7200\r\n", 0, 0, 1, -3600, 2 },
    { "max-age=7200",              NULL, 1, -1800, 1, 5400, 1 },
    { "max-age=7200",              NULL, 1, 1800, 1, 7200, 1 },
    { "max-age=7200",              "Age: 600\r\n", 1, -1800, 1, 5400, 1 },
    { "max-age=7200",              "Age: 2400\r\n", 1, -1800, 1, 4800, 1 },
    { "max-age=7200",              NULL, 1, -9000, 1, -3600, 2 },
    { "max-age=3600, stale-while-revalidate=1800", NULL, 0, 0, 1, 5400, 1 },
    { "max-age=abc",               NULL, 0, 0, 1, -3600, 2 },   /* VM: unparsable max-age counts as stale */
    { "max-age",                   NULL, 0, 0, 0, 0, 1 },
    { "no-cache",                  NULL, 0, 0, 1, -3600, 2 },
    { "no-cache=\"Set-Cookie\"",   NULL, 0, 0, 1, -3600, 2 },
    { "max-age=600, no-cache",     NULL, 0, 0, 1, -3600, 2 },
    { "no-cache, max-age=600",     NULL, 0, 0, 1, 600, 1 },     /* tokens in order: the later max-age wins */
    { "nocache",                   NULL, 0, 0, 0, 0, 1 },
    { "no-cachex",                 NULL, 0, 0, 0, 0, 1 },
    { "s-maxage=600",              NULL, 0, 0, 0, 0, 1 },
    { "immutable",                 NULL, 0, 0, 0, 0, 1 },
    { "must-revalidate",           NULL, 0, 0, 0, 0, 1 },
    { "max-age=600, immutable",    NULL, 0, 0, 1, 600, 1 },
    { "pre-check=600, post-check=300", NULL, 0, 0, 1, 600, 1 }, /* pre-check acts as max-age when there is no other */
    { "post-check=0, pre-check=0", NULL, 0, 0, 0, 0, 1 },
    { "max-age=900",               "Expires: Thu, 01 Dec 2033 16:00:00 GMT\r\n", 0, 0, 1, 900, 1 },
    { NULL,                        "Age: 100000\r\n", 0, 0, 0, 0, 1 },
};

TEST(hci_exp_expire_time_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    for (size_t k = 0; k < sizeof g_exp / sizeof g_exp[0]; k++) {
        const exp_row *w = &g_exp[k];
        char hdr[512] = "Content-Type: text/plain\r\n", d[64];
        if (w->cc) { strcat(hdr, "Cache-Control: "); strcat(hdr, w->cc); strcat(hdr, "\r\n"); }
        if (w->extra) strcat(hdr, w->extra);
        if (w->date_off_set) { hci_http_date(d, sizeof d, w->date_off); strcat(hdr, "Date: "); strcat(hdr, d); strcat(hdr, "\r\n"); }
        hci_plan p = {0}; hci_set(&p, 0, 200, "exp-row", "%s", hdr);
        hci_set(&p, 1, 200, "net-two", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "exptab");
        LONGLONG t0 = hci_ft_now();
        hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
        CHECKF(a.status == 200, "row %zu status %d", k, a.status);
        CHECKF(e != NULL, "row %zu (%s) not stored", k, w->cc ? w->cc : "-");
        LONGLONG ex = e ? hci_ft(e->ExpireTime) : -1;
        if (e) {
            LONGLONG rel = ex ? (ex - t0) / HCI_SEC : 0;
            t_note("CC [%s] extra [%s] date %lld -> ExpireTime %s now%+lld s", w->cc ? w->cc : "-", w->extra ? w->extra : "", w->date_off_set ? w->date_off : 0,
                   ex ? "" : "0", rel);
            if (w->kind == 0) CHECKF(ex == 0, "row %zu [%s]: ExpireTime %llx want 0", k, w->cc ? w->cc : "-", ex);
            if (w->kind == 1) CHECKF(hci_near(ex, t0 + w->want * HCI_SEC, 30), "row %zu [%s]: ExpireTime now%+lld want now%+lld", k, w->cc ? w->cc : "-", (ex - t0) / HCI_SEC, w->want);
            CHECKF(e->dwSizeLow == 7, "row %zu size %lu", k, e->dwSizeLow);
            CHECKF(!hci_hdr_has(e, "Cache-Control"), "row %zu Cache-Control kept in blob", k);
            /* VM: must-revalidate sets entry type bit 0x100 */
            DWORD wt = (w->cc && strstr(w->cc, "must-revalidate")) ? HCI_HTTP_ENTRY | 0x100 : HCI_HTTP_ENTRY;
            CHECKF(e->CacheEntryType == wt, "row %zu type 0x%lx want 0x%lx", k, e->CacheEntryType, wt);
        }
        HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
        int n = hci_reqs(s, 0);
        t_note("  second GET: requests=%d body=%s", n, b.body);
        if (w->second) CHECKF(n == w->second, "row %zu [%s]: requests %d want %d", k, w->cc ? w->cc : "-", n, w->second);
        if (w->second == 1) CHECKF(!strcmp(b.body, "exp-row"), "row %zu second body %s", k, b.body);
        if (w->second == 2) CHECKF(!strcmp(b.body, "net-two"), "row %zu second body %s", k, b.body);
        free(e);
        srv_stop(s);
    }
}

/* ---------------------------------------------------------------- Expires formats */
typedef struct { const char *v; int kind; int y, mo, d, h, mi, sc; } expires_row;   /* kind 1 exact, 2 note, 3 ~now (stale) */
static const expires_row g_expires[] = {
    { "Thu, 01 Dec 2033 16:00:00 GMT", 1, 2033, 12, 1, 16, 0, 0 },
    { "Fri, 31 Dec 2032 23:59:59 GMT", 1, 2032, 12, 31, 23, 59, 59 },
    { "Thu Dec  1 16:00:00 2033",      1, 2033, 12, 1, 16, 0, 0 },
    { "Thursday, 01-Dec-33 16:00:00 GMT", 1, 2033, 12, 1, 16, 0, 0 },
    { "thu, 01 dec 2033 16:00:00 gmt", 1, 2033, 12, 1, 16, 0, 0 },
    { "Thu, 01 Dec 2033 16:00:00",     1, 2033, 12, 1, 16, 0, 0 },
    { "Thu, 1 Dec 2033 16:00:00 GMT",  1, 2033, 12, 1, 16, 0, 0 },
    { "Thu, 01 Dec 2033 16:00:00 UTC", 1, 2033, 12, 1, 16, 0, 0 },
    { "Mon, 01 Jan 2001 00:00:00 GMT", 1, 2001, 1, 1, 0, 0, 0 },
    { "Thu, 01 Jan 1970 00:00:00 GMT", 1, 1970, 1, 1, 0, 0, 0 },
    { "garbage",                       3, 0 },
    { "0",                             3, 0 },
    { "-1",                            3, 0 },
    { "",                              3, 0 },
};
TEST(hci_exp_expires_formats_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    for (size_t k = 0; k < sizeof g_expires / sizeof g_expires[0]; k++) {
        const expires_row *w = &g_expires[k];
        hci_plan p = {0}; hci_set(&p, 0, 200, "expfmt", "Content-Type: text/plain\r\nExpires: %s\r\n", w->v);
        hci_set(&p, 1, 200, "net", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "expfmt");
        LONGLONG t0 = hci_ft_now();
        hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
        CHECKF(e != NULL, "Expires [%s] not stored", w->v);
        HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
        int n = hci_reqs(s, 0);
        if (e) {
            LONGLONG ex = hci_ft(e->ExpireTime), want = w->y ? hci_ft_utc(w->y, w->mo, w->d, w->h, w->mi, w->sc) : 0;
            t_note("Expires [%s] -> ExpireTime %llx (want %llx, now%+lld s) second GET requests=%d", w->v, ex, want, ex ? (ex - t0) / HCI_SEC : 0, n);
            if (w->kind == 1) {
                CHECKF(ex == want, "Expires [%s]: %llx want %llx", w->v, ex, want);
                int fresh = want > t0;
                CHECKF(n == (fresh ? 1 : 2), "Expires [%s]: requests %d", w->v, n);
            }
            if (w->kind == 3) {     /* VM: an unparsable Expires is stored as about "now": stale */
                CHECKF(hci_near(ex, t0, 60), "Expires [%s]: now%+lld", w->v, (ex - t0) / HCI_SEC);
                CHECKF(n == 2, "Expires [%s]: requests %d", w->v, n);
            }
        }
        free(e);
        srv_stop(s);
    }
}

TEST(hci_exp_expires_not_after_date_is_past) {
    REQUIRE(U(InternetOpenUrlA));
    char ex[64], dt[64]; hci_http_date(ex, sizeof ex, 2 * 86400); hci_http_date(dt, sizeof dt, 3 * 86400);
    hci_plan p = {0}; hci_set(&p, 0, 200, "a", "Content-Type: text/plain\r\nDate: %s\r\nExpires: %s\r\n", dt, ex);
    hci_set(&p, 1, 200, "b", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "exple");
    LONGLONG t0 = hci_ft_now();
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    if (e) CHECKF(hci_near(hci_ft(e->ExpireTime), t0 - 3600 * HCI_SEC, 30), "ExpireTime now%+lld", (hci_ft(e->ExpireTime) - t0) / HCI_SEC);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "b");
    free(e);
    srv_stop(s);
}

TEST(hci_exp_expires_after_date_kept) {
    REQUIRE(U(InternetOpenUrlA));
    char ex[64], dt[64]; hci_http_date(ex, sizeof ex, 3 * 86400); hci_http_date(dt, sizeof dt, 2 * 86400);
    hci_plan p = {0}; hci_set(&p, 0, 200, "a", "Content-Type: text/plain\r\nDate: %s\r\nExpires: %s\r\n", dt, ex);
    hci_set(&p, 1, 200, "b", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "expgt");
    LONGLONG t0 = hci_ft_now();
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    /* the header value is stored as is (no skew correction against Date) */
    if (e) CHECKF(hci_near(hci_ft(e->ExpireTime), t0 + 3 * HCI_DAY, 5), "ExpireTime now%+lld", (hci_ft(e->ExpireTime) - t0) / HCI_SEC);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "a");
    free(e);
    srv_stop(s);
}

TEST(hci_exp_expires_past_with_date_past) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "a", "Content-Type: text/plain\r\nDate: Mon, 01 Jan 2001 00:00:00 GMT\r\nExpires: Tue, 02 Jan 2001 00:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "exppd");
    hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    if (e) EXPECT_EQ(hci_ft(e->ExpireTime), hci_ft_utc(2001, 1, 2, 0, 0, 0));
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- Last-Modified formats */
static const expires_row g_lm[] = {
    { "Tue, 15 Nov 1994 08:12:31 GMT", 1, 1994, 11, 15, 8, 12, 31 },
    { "Tue Nov 15 08:12:31 1994",      1, 1994, 11, 15, 8, 12, 31 },
    { "Tuesday, 15-Nov-94 08:12:31 GMT", 2, 1994, 11, 15, 8, 12, 31 },
    { "Sat, 29 Feb 2020 23:59:59 GMT", 1, 2020, 2, 29, 23, 59, 59 },
    { "Mon, 01 Jan 2001 00:00:00 GMT", 1, 2001, 1, 1, 0, 0, 0 },
    { "garbage",                       3, 0 },
    { "",                              3, 0 },
};
TEST(hci_exp_last_modified_formats_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    for (size_t k = 0; k < sizeof g_lm / sizeof g_lm[0]; k++) {
        const expires_row *w = &g_lm[k];
        hci_plan p = {0}; hci_set(&p, 0, 200, "lmfmt", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\nLast-Modified: %s\r\n", w->v);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "lmfmt");
        hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
        CHECKF(e != NULL, "LM [%s] not stored", w->v);
        if (e) {
            LONGLONG lm = hci_ft(e->LastModifiedTime), want = w->y ? hci_ft_utc(w->y, w->mo, w->d, w->h, w->mi, w->sc) : 0;
            t_note("Last-Modified [%s] -> %llx (want %llx)", w->v, lm, want);
            if (w->kind == 1) CHECKF(lm == want, "LM [%s]: %llx want %llx", w->v, lm, want);
            if (w->kind == 3) CHECKF(hci_near(lm, hci_ft_now(), 120), "LM [%s]: %llx want ~now", w->v, lm);   /* VM: unparsable -> about now */
            CHECKF(!hci_hdr_has(e, "Last-Modified:"), "LM [%s] header kept in blob", w->v);   /* VM: stripped from the blob */
        }
        free(e);
        srv_stop(s);
    }
}

/* ---------------------------------------------------------------- FWD_BACK (dwFlags & 0x20) */
TEST(hci_exp_fwd_back_serves_expired_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "history-copy", "Content-Type: text/plain\r\nExpires: Thu, 01 Jan 1998 00:00:00 GMT\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fwdback");
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a); free(e);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_FWD_BACK, &b); t_inet_close(hi);
    t_note("FWD_BACK over an expired entry: ok=%d err=%lu body=%s requests=%d reqflags=0x%lx", b.ok, b.err, b.body, hci_reqs(s, 0), b.reqflags);
    CHECK(b.ok);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "history-copy");
    CHECK(hci_from_cache(&b));
    srv_stop(s);
}

TEST(hci_exp_fwd_back_no_cache_entry) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nc-history", "Content-Type: text/plain\r\nCache-Control: no-cache\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fwdbacknc");
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a); free(e);
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_FWD_BACK, &b); t_inet_close(hi);
    t_note("FWD_BACK over a no-cache entry: body=%s requests=%d", b.body, hci_reqs(s, 0));
    EXPECT_EQ(hci_reqs(s, 0), 1);                     /* VM: FWD_BACK overrides even no-cache */
    EXPECT_STR(b.body, "nc-history");
    srv_stop(s);
}

TEST(hci_exp_fwd_back_without_entry_downloads) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "first", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "fwdbacknone");
    hci_resp r; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, INTERNET_FLAG_FWD_BACK, &r);
    EXPECT_EQ(r.status, 200);
    EXPECT_STR(r.body, "first");
    EXPECT_EQ(hci_reqs(s, 1), 1);
    CHECK(e != NULL);
    free(e);
    srv_stop(s);
}

/* ---------------------------------------------------------------- stored times decide (SetUrlCacheEntryInfo) */
/* expire offsets: <= now expired, > now fresh */
TEST(hci_exp_set_expire_offsets_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    static const struct { LONGLONG off; int fresh; } rows[] = {
        { -86400 * 365LL, 0 }, { -3600, 0 }, { -60, 0 }, { -5, 0 }, { 120, 1 }, { 3600, 1 }, { 86400 * 365LL, 1 },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "stored", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "setexp");
        hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
        CHECK(hci_set_times(url, rows[k].off, HCI_KEEP, HCI_KEEP));
        DWORD err; INTERNET_CACHE_ENTRY_INFOA *e = hci_info(url, &err);
        if (e) CHECKF(hci_near(hci_ft(e->ExpireTime), hci_ft_now() + rows[k].off * HCI_SEC, 5), "off %lld", rows[k].off);
        free(e);
        HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
        int n = hci_reqs(s, rows[k].fresh ? 0 : 2);
        CHECKF(n == (rows[k].fresh ? 1 : 2), "expire now%+lld: requests %d", rows[k].off, n);
        CHECKF(!strcmp(b.body, rows[k].fresh ? "stored" : "network"), "expire now%+lld: body %s", rows[k].off, b.body);
        CHECKF(hci_from_cache(&b) == rows[k].fresh, "expire now%+lld: reqflags 0x%lx", rows[k].off, b.reqflags);
        srv_stop(s);
    }
}

/* the heuristic: LM = now - 100 days (header), then the sync time is moved; fresh iff now <= sync + (sync - LM)/10 */
TEST(hci_exp_heuristic_sync_table) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    static const struct { LONGLONG sync_days; int fresh; } rows[] = {
        { 0, 1 }, { -1, 1 }, { -5, 1 }, { -8, 1 }, { -12, 0 }, { -20, 0 }, { -60, 0 },
    };
    for (size_t k = 0; k < sizeof rows / sizeof rows[0]; k++) {
        char lm[64]; hci_http_date(lm, sizeof lm, -100 * 86400LL);
        hci_plan p = {0}; hci_set(&p, 0, 200, "heur", "Content-Type: text/plain\r\nLast-Modified: %s\r\n", lm);
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        hci_set_cond(&p, 304, "");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "heursync");
        hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
        CHECK(hci_set_times(url, HCI_KEEP, HCI_KEEP, rows[k].sync_days * 86400));
        HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
        int n = hci_reqs(s, rows[k].fresh ? 0 : 2);
        CHECKF(n == (rows[k].fresh ? 1 : 2), "sync %lld d: requests %d", rows[k].sync_days, n);
        CHECKF(!strcmp(b.body, "heur"), "sync %lld d: body %s", rows[k].sync_days, b.body);
        if (!rows[k].fresh) {
            CHECKF(p.cond_served == 1, "sync %lld d: conditional %ld", rows[k].sync_days, p.cond_served);
            const char *ims = hci_rh(s, 1, "If-Modified-Since");
            CHECKF(ims && !strcmp(ims, lm), "sync %lld d: IMS %s want %s", rows[k].sync_days, ims ? ims : "(none)", lm);
        }
        srv_stop(s);
    }
}

/* LastModifiedTime set through the API is what the heuristic and If-Modified-Since use */
TEST(hci_exp_api_lm_drives_if_modified_since) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "api-lm", "Content-Type: text/plain\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\nCache-Control: max-age=3600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "apilm");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    INTERNET_CACHE_ENTRY_INFOA ci; memset(&ci, 0, sizeof ci); ci.dwStructSize = sizeof ci;
    ci.LastModifiedTime = hci_ft_make(hci_ft_utc(2001, 2, 3, 4, 5, 6));
    ci.ExpireTime = hci_ft_off(-86400);
    CHECK(U(SetUrlCacheEntryInfoA)(url, &ci, CACHE_ENTRY_MODTIME_FC | CACHE_ENTRY_EXPTIME_FC));
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(hci_rh(s, 1, "If-Modified-Since"), "Sat, 03 Feb 2001 04:05:06 GMT");
    EXPECT_STR(b.body, "api-lm");
    EXPECT_EQ(p.cond_served, 1);
    srv_stop(s);
}

/* no Expires, no LM: the session rule. A sync time before this process' session start is stale. */
TEST(hci_exp_session_rule_old_sync_is_stale) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "session", "Content-Type: text/plain\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "sessold");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, HCI_KEEP, HCI_KEEP, -2 * 86400));
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(b.body, "network");
    CHECK(!hci_rh(s, 1, "If-Modified-Since"));
    CHECK(!hci_rh(s, 1, "If-None-Match"));
    srv_stop(s);
}

TEST(hci_exp_session_rule_current_sync_is_fresh) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "session", "Content-Type: text/plain\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "sessnow");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, HCI_KEEP, HCI_KEEP, 0));
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "session");
    srv_stop(s);
}

TEST(hci_exp_session_rule_etag_revalidates_old_sync) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "sess-etag", "Content-Type: text/plain\r\nETag: \"se\"\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "sessetag");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, HCI_KEEP, HCI_KEEP, -2 * 86400));
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    EXPECT_STR(hci_rh(s, 1, "If-None-Match"), "\"se\"");
    EXPECT_EQ(p.cond_served, 1);
    EXPECT_STR(b.body, "sess-etag");
    srv_stop(s);
}

/* HYPERLINK: LM == 0 and no Expires -> expired; an LM makes the heuristic apply */
TEST(hci_exp_hyperlink_with_api_lm_heuristic_fresh) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hl-api", "Content-Type: text/plain\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hlapi");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, HCI_KEEP, -400 * 86400LL, 0));
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_HYPERLINK, &b); t_inet_close(hi);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    EXPECT_STR(b.body, "hl-api");
    srv_stop(s);
}

TEST(hci_exp_hyperlink_expires_future_fresh_past_stale) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    for (int k = 0; k < 2; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "hl-exp", "Content-Type: text/plain\r\nCache-Control: max-age=3600\r\n");
        hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "hlexp");
        hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
        if (k) CHECK(hci_set_times(url, -60, HCI_KEEP, HCI_KEEP));
        HINTERNET hi = hci_open(); hci_get(hi, url, NULL, INTERNET_FLAG_HYPERLINK, &b); t_inet_close(hi);
        EXPECT_EQ(hci_reqs(s, k ? 2 : 0), k ? 2 : 1);
        EXPECT_STR(b.body, k ? "network" : "hl-exp");
        srv_stop(s);
    }
}

/* stored ExpireTime of no-cache / max-age=0 responses */
TEST(hci_exp_no_cache_entry_expire_minus_hour) {
    REQUIRE(U(InternetOpenUrlA));
    static const char *cc[] = { "no-cache", "max-age=0", "NO-CACHE", "private, no-cache" };
    for (size_t k = 0; k < 4; k++) {
        hci_plan p = {0}; hci_set(&p, 0, 200, "nc", "Content-Type: text/plain\r\nCache-Control: %s\r\n", cc[k]);
        srv *s = hci_plan_start(&p); if (!s) { t_skip("server"); return; }
        const char *url = hci_url(s, "ncexp");
        LONGLONG t0 = hci_ft_now();
        hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
        CHECKF(e != NULL, "%s not stored", cc[k]);
        if (e) CHECKF(hci_near(hci_ft(e->ExpireTime), t0 - 3600 * HCI_SEC, 30), "%s ExpireTime now%+lld", cc[k], (hci_ft(e->ExpireTime) - t0) / HCI_SEC);
        free(e);
        srv_stop(s);
    }
}

/* a no-cache entry whose ExpireTime is moved into the future through the API: the stored blob has no Cache-Control */
TEST(hci_exp_no_cache_entry_made_fresh_by_api) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "nc-api", "Content-Type: text/plain\r\nCache-Control: no-cache\r\n");
    hci_set(&p, 1, 200, "network", "Content-Type: text/plain\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ncapi");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, 86400, HCI_KEEP, HCI_KEEP));
    HINTERNET hi = hci_open(); hci_get(hi, url, NULL, 0, &b); t_inet_close(hi);
    t_note("no-cache entry with future ExpireTime: requests=%d body=%s", hci_reqs(s, 0), b.body);
    EXPECT_EQ(hci_reqs(s, 0), 1);                     /* VM: only the stored times count, no-cache is not remembered */
    EXPECT_STR(b.body, "nc-api");
    srv_stop(s);
}

/* Expires: in the future, then a max-age=0 refetch replaces the times */
TEST(hci_exp_refetch_updates_times) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "v1", "Content-Type: text/plain\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\nLast-Modified: Tue, 15 Nov 1994 08:12:31 GMT\r\n");
    hci_set(&p, 1, 200, "v2", "Content-Type: text/plain\r\nCache-Control: max-age=120\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "reftimes");
    hci_resp a, b; INTERNET_CACHE_ENTRY_INFOA *e1 = hci_fetch(url, NULL, 0, &a);
    LONGLONG t0 = hci_ft_now();
    INTERNET_CACHE_ENTRY_INFOA *e2 = hci_fetch(url, NULL, INTERNET_FLAG_RELOAD, &b);
    CHECK(e1 && e2);
    if (e1 && e2) {
        EXPECT_EQ(hci_ft(e1->ExpireTime), hci_ft_utc(2033, 12, 1, 16, 0, 0));
        EXPECT_EQ(hci_ft(e1->LastModifiedTime), hci_ft_utc(1994, 11, 15, 8, 12, 31));
        CHECK(hci_near(hci_ft(e2->ExpireTime), t0 + 120 * HCI_SEC, 30));
        EXPECT_EQ(hci_ft(e2->LastModifiedTime), 0);
        CHECK(hci_ft(e2->LastSyncTime) >= hci_ft(e1->LastSyncTime));
    }
    free(e1); free(e2);
    srv_stop(s);
}

/* LastSyncTime and LastAccessTime of a fresh download are "now" */
TEST(hci_exp_sync_and_access_time_now) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "now", "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "synctime");
    LONGLONG t0 = hci_ft_now();
    hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    LONGLONG t1 = hci_ft_now();
    CHECK(e != NULL);
    if (e) {
        CHECK(hci_ft(e->LastSyncTime) >= t0 - 2 * HCI_SEC && hci_ft(e->LastSyncTime) <= t1 + 2 * HCI_SEC);
        CHECK(hci_ft(e->LastAccessTime) >= t0 - 2 * HCI_SEC && hci_ft(e->LastAccessTime) <= t1 + 2 * HCI_SEC);
        CHECK(hci_ft(e->ExpireTime) > hci_ft(e->LastSyncTime));
        EXPECT_EQ(e->dwExemptDelta, 0);
    }
    free(e);
    srv_stop(s);
}

/* a cache hit does not move LastSyncTime (only the network does) */
TEST(hci_exp_cache_hit_keeps_sync_time) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "hit", "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "hitsync");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, HCI_KEEP, HCI_KEEP, -3600));
    DWORD err; INTERNET_CACHE_ENTRY_INFOA *e0 = hci_info(url, &err);
    INTERNET_CACHE_ENTRY_INFOA *e1 = hci_fetch(url, NULL, 0, &b);
    EXPECT_EQ(hci_reqs(s, 0), 1);
    CHECK(e0 && e1);
    if (e0 && e1) {
        EXPECT_EQ(hci_ft(e1->LastSyncTime), hci_ft(e0->LastSyncTime));
        EXPECT_EQ(e1->dwHitRate, e0->dwHitRate + 1);
        t_note("access time %llx -> %llx", hci_ft(e0->LastAccessTime), hci_ft(e1->LastAccessTime));
    }
    free(e0); free(e1);
    srv_stop(s);
}

/* RELOAD refreshes LastSyncTime */
TEST(hci_exp_reload_moves_sync_time) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "rl", "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "rlsync");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, HCI_KEEP, HCI_KEEP, -3600));
    LONGLONG t0 = hci_ft_now();
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, INTERNET_FLAG_RELOAD, &b);
    EXPECT_EQ(hci_reqs(s, 2), 2);
    if (e) CHECK(hci_ft(e->LastSyncTime) >= t0 - 2 * HCI_SEC);
    free(e);
    srv_stop(s);
}

/* revalidation (304) refreshes LastSyncTime too */
TEST(hci_exp_304_moves_sync_time) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "r304", "Content-Type: text/plain\r\nETag: \"s\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "Cache-Control: max-age=600\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "s304");
    hci_resp a, b; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, -60, HCI_KEEP, -3600));
    LONGLONG t0 = hci_ft_now();
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
    EXPECT_EQ(p.cond_served, 1);
    EXPECT_STR(b.body, "r304");
    CHECK(e != NULL);
    if (e) {
        t_note("after 304: sync now%+lld expire now%+lld", (hci_ft(e->LastSyncTime) - t0) / HCI_SEC, (hci_ft(e->ExpireTime) - t0) / HCI_SEC);
        CHECK(hci_ft(e->LastSyncTime) >= t0 - 2 * HCI_SEC);
        CHECK(hci_near(hci_ft(e->ExpireTime), t0 + 600 * HCI_SEC, 30));
    }
    free(e);
    srv_stop(s);
}

/* a 304 without freshness headers: what does the entry's ExpireTime become? */
TEST(hci_exp_304_without_freshness_headers) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(SetUrlCacheEntryInfoA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "plain304", "Content-Type: text/plain\r\nETag: \"p\"\r\nCache-Control: max-age=600\r\n");
    hci_set_cond(&p, 304, "");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "p304");
    hci_resp a, b, c; free(hci_fetch(url, NULL, 0, &a));
    CHECK(hci_set_times(url, -60, HCI_KEEP, HCI_KEEP));
    LONGLONG t0 = hci_ft_now();
    INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &b);
    EXPECT_EQ(p.cond_served, 1);
    if (e) t_note("304 without Cache-Control/Expires: expire now%+lld (0 = %d)", (hci_ft(e->ExpireTime) - t0) / HCI_SEC, hci_ft(e->ExpireTime) == 0);
    CHECK(e && hci_near(hci_ft(e->ExpireTime), t0 - 60 * HCI_SEC, 10));   /* VM: a bare 304 keeps the old ExpireTime */
    free(hci_fetch(url, NULL, 0, &c));
    t_note("third GET after a bare 304: requests=%d cond=%ld", hci_reqs(s, 0), p.cond_served);
    EXPECT_EQ(hci_reqs(s, 3), 3);
    EXPECT_EQ(p.cond_served, 2);
    free(e);
    srv_stop(s);
}

/* very old / far future Expires stored exactly */
TEST(hci_exp_far_future_expires) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "far", "Content-Type: text/plain\r\nExpires: Fri, 31 Dec 2099 23:59:59 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "farfut");
    hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    if (e) {
        t_note("Expires 2099 -> %llx (want %llx)", hci_ft(e->ExpireTime), hci_ft_utc(2099, 12, 31, 23, 59, 59));
        EXPECT_EQ(hci_ft(e->ExpireTime), hci_ft_utc(2099, 12, 31, 23, 59, 59));
    }
    free(e);
    srv_stop(s);
}

/* two Expires headers: which one counts */
TEST(hci_exp_duplicate_expires_first_wins) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "dup", "Content-Type: text/plain\r\nExpires: Thu, 01 Dec 2033 16:00:00 GMT\r\nExpires: Mon, 01 Jan 2001 00:00:00 GMT\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "dupexp");
    hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    if (e) {
        LONGLONG ex = hci_ft(e->ExpireTime);
        t_note("two Expires headers -> %s", ex == hci_ft_utc(2033, 12, 1, 16, 0, 0) ? "first" : ex == hci_ft_utc(2001, 1, 1, 0, 0, 0) ? "second" : "other");
        EXPECT_EQ(ex, hci_ft_utc(2033, 12, 1, 16, 0, 0));
    }
    free(e);
    srv_stop(s);
}

/* max-age in a second Cache-Control header line still counts (every header is scanned) */
TEST(hci_exp_max_age_in_second_header) {
    REQUIRE(U(InternetOpenUrlA));
    hci_plan p = {0}; hci_set(&p, 0, 200, "two", "Content-Type: text/plain\r\nCache-Control: public\r\nCache-Control: max-age=1800\r\n");
    srv *s; HCI_START(&p, s);
    const char *url = hci_url(s, "ma2nd");
    LONGLONG t0 = hci_ft_now();
    hci_resp a; INTERNET_CACHE_ENTRY_INFOA *e = hci_fetch(url, NULL, 0, &a);
    CHECK(e != NULL);
    if (e) CHECKF(hci_near(hci_ft(e->ExpireTime), t0 + 1800 * HCI_SEC, 30), "now%+lld", (hci_ft(e->ExpireTime) - t0) / HCI_SEC);
    free(e);
    srv_stop(s);
}
