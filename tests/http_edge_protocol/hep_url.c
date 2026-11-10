/* hep_url.c - URL-level edge cases as seen on the wire: very long URLs/objects/hosts (INTERNET_MAX_URL_LENGTH 2083 and
 * beyond), fragment stripping, spaces, %-escapes and non-ASCII paths through the A and W entry points (UTF-8 vs ACP,
 * INTERNET_OPTION_CODEPAGE_PATH / CODEPAGE_EXTRA / IDN), IDN hosts (punycode) in the proxy request line and the Host
 * header, URL userinfo in InternetOpenUrl, IPv6 literals to ::1, default-port handling in Host.
 * Hosts other than 127.0.0.1/::1 are only ever used through a PROXY session pointing at the loopback server, so no
 * name is resolved and no traffic leaves the guest. Expectations: Win10 VM observations (EVIDENCE.md). */
#include "hep.h"
#include <stdlib.h>

static char *mk_path(size_t len, char fill) {      /* "/" + fill... total len chars */
    char *p = (char *)malloc(len + 1); p[0] = '/';
    for (size_t i = 1; i < len; i++) p[i] = (i % 64 == 0) ? '/' : fill;
    p[len] = 0; return p;
}

/* ------------------------------------------------------------ long URLs through InternetOpenUrlA */
static void long_openurl(size_t total_len) {
    HEP_SRV(h, hep_start_ok());
    const char *base = srv_url(h->s, "");            /* http://127.0.0.1:P */
    size_t bl = strlen(base);
    size_t plen = total_len > bl + 1 ? total_len - bl : 1;
    char *path = mk_path(plen, 'u');
    char *url = (char *)malloc(bl + plen + 1); memcpy(url, base, bl); memcpy(url + bl, path, plen + 1);
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
    int got = r.ok && srv_wait_requests(h->s, 1, 2000);
    const char *tg = got ? srv_req_target(h->s, 0) : NULL;
    t_note("OBS openurl total=%zu -> %s target_len=%zu", strlen(url), hep_sig(&r, 0), tg ? strlen(tg) : 0);
    if (got && tg) { EXPECT_EQ(strlen(tg), plen); EXPECT_STR(tg, path); }
    t_inet_close(hi); free(url); free(path); hep_stop(h);
}
TEST(hep_url_openurl_len_2000)  { HEP_REQUIRE_HTTP(); long_openurl(2000); }
TEST(hep_url_openurl_len_2048)  { HEP_REQUIRE_HTTP(); long_openurl(2048); }
TEST(hep_url_openurl_len_2083)  { HEP_REQUIRE_HTTP(); long_openurl(2083); }
TEST(hep_url_openurl_len_2084)  { HEP_REQUIRE_HTTP(); long_openurl(2084); }
TEST(hep_url_openurl_len_2085)  { HEP_REQUIRE_HTTP(); long_openurl(2085); }
TEST(hep_url_openurl_len_4096)  { HEP_REQUIRE_HTTP(); long_openurl(4096); }
TEST(hep_url_openurl_len_8192)  { HEP_REQUIRE_HTTP(); long_openurl(8192); }
TEST(hep_url_openurl_len_32768) { HEP_REQUIRE_HTTP(); long_openurl(32768); }
TEST(hep_url_openurl_len_100000){ HEP_REQUIRE_HTTP(); long_openurl(100000); }

static void long_query_openurl(size_t qlen) {
    HEP_SRV(h, hep_start_ok());
    const char *base = srv_url(h->s, "/q?");
    size_t bl = strlen(base);
    char *url = (char *)malloc(bl + qlen + 1); memcpy(url, base, bl);
    for (size_t i = 0; i < qlen; i++) url[bl + i] = (i % 10 == 9) ? '&' : 'k';
    url[bl + qlen] = 0;
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
    int got = r.ok && srv_wait_requests(h->s, 1, 2000);
    const char *tg = got ? srv_req_target(h->s, 0) : NULL;
    t_note("OBS openurl query=%zu total=%zu -> %s target_len=%zu", qlen, strlen(url), hep_sig(&r, 0), tg ? strlen(tg) : 0);
    if (tg) EXPECT_EQ(strlen(tg), 3 + qlen);
    t_inet_close(hi); free(url); hep_stop(h);
}
TEST(hep_url_openurl_query_2100)  { HEP_REQUIRE_HTTP(); long_query_openurl(2100); }
TEST(hep_url_openurl_query_16000) { HEP_REQUIRE_HTTP(); long_query_openurl(16000); }

/* ------------------------------------------------------------ long objects through HttpOpenRequestA */
static void long_object(size_t len) {
    HEP_SRV(h, hep_start_ok());
    char *path = mk_path(len, 'o');
    hep_req rq = {0}; hep_res r; rq.obj = path;
    hep_do(h, &rq, &r);
    int got = r.ok && srv_wait_requests(h->s, 1, 2000);
    const char *tg = got ? srv_req_target(h->s, 0) : NULL;
    t_note("OBS object len=%zu -> %s target_len=%zu", len, hep_sig(&r, 0), tg ? strlen(tg) : 0);
    CHECKF(r.ok, "object %zu err %lu", len, r.err);
    if (tg) EXPECT_EQ(strlen(tg), len);
    free(path); hep_stop(h);
}
TEST(hep_url_object_len_2048)   { HEP_REQUIRE_HTTP(); long_object(2048); }
TEST(hep_url_object_len_2084)   { HEP_REQUIRE_HTTP(); long_object(2084); }
TEST(hep_url_object_len_8192)   { HEP_REQUIRE_HTTP(); long_object(8192); }
TEST(hep_url_object_len_65536)  { HEP_REQUIRE_HTTP(); long_object(65536); }
TEST(hep_url_object_len_200000) { HEP_REQUIRE_HTTP(); long_object(200000); }

/* ------------------------------------------------------------ long host names (via proxy: no DNS) */
static void long_host(size_t label, size_t total) {
    HEP_SRV(h, hep_start_ok());
    char host[1200]; size_t n = 0;
    while (n < total) {
        size_t l = label; if (n + l > total) l = total - n;
        for (size_t i = 0; i < l; i++) host[n++] = 'h';
        if (n < total) host[n++] = '.';
    }
    if (host[n - 1] == '.') host[n - 1] = 'x';
    host[n] = 0;
    char url[1400]; snprintf(url, sizeof url, "http://%s/lh", host);
    HINTERNET hi = hep_proxy_session(h, "hep-lh");
    hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
    int got = r.ok && srv_wait_requests(h->s, 1, 2000);
    t_note("OBS host label=%zu total=%zu -> %s target_len=%zu host_hdr_len=%zu", label, n, hep_sig(&r, 0),
           got ? strlen(srv_req_target(h->s, 0)) : 0, got && srv_req_header(h->s, 0, "Host") ? strlen(srv_req_header(h->s, 0, "Host")) : 0);
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_url_host_label_63)        { HEP_REQUIRE_HTTP(); long_host(63, 63); }
TEST(hep_url_host_label_64)        { HEP_REQUIRE_HTTP(); long_host(64, 64); }
TEST(hep_url_host_total_253)       { HEP_REQUIRE_HTTP(); long_host(50, 253); }
TEST(hep_url_host_total_256)       { HEP_REQUIRE_HTTP(); long_host(50, 256); }
TEST(hep_url_host_total_1000)      { HEP_REQUIRE_HTTP(); long_host(50, 1000); }

/* ------------------------------------------------------------ fragments */
typedef struct { const char *path; const char *want; } frag_case;
static const frag_case frags[] = {
    { "/f#frag", "/f" }, { "/f?q=1#frag", "/f?q=1" }, { "/f#", "/f" }, { "/#x", "/" }, { "/f#a#b", "/f" },
    { "/f#frag?notquery", "/f" }, { "/f%23notfrag", "/f%23notfrag" },
};
TEST(hep_url_fragment_stripped_openurl) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof frags / sizeof frags[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_session(NULL, 0);
        hep_res r; hep_openurl(hi, srv_url(h->s, frags[i].path), NULL, 0, NULL, &r);
        CHECKF(r.ok, "%s err %lu", frags[i].path, r.err);
        if (r.ok && srv_wait_requests(h->s, 1, 2000)) {
            t_note("OBS frag %s -> %s", frags[i].path, srv_req_target(h->s, 0));
            EXPECT_STR(srv_req_target(h->s, 0), frags[i].want);
        }
        t_inet_close(hi); hep_stop(h);
    }
}
TEST(hep_url_fragment_openurl_w) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetOpenUrlW));
    HEP_SRV(h, hep_start_ok());
    WCHAR url[128]; swprintf(url, 128, L"http://127.0.0.1:%u/fw?x=1#frag", srv_port(h->s));
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl_w(hi, url, 0, &r);
    CHECK(r.ok);
    if (r.ok && srv_wait_requests(h->s, 1, 2000)) EXPECT_STR(srv_req_target(h->s, 0), "/fw?x=1");
    t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ path bytes: A and W, openurl and openrequest */
typedef struct { const char *a; const WCHAR *w; const char *tag; } path_case;
static const path_case paths[] = {
    { "/a b", L"/a b", "space" },
    { "/a%20b", L"/a%20b", "pct20" },
    { "/sp ace?q=a b", L"/sp ace?q=a b", "space_query" },
    { "/%41", L"/%41", "pct41" },
    { "/%zz", L"/%zz", "pct_bad" },
    { "/%", L"/%", "pct_alone" },
    { "/%2f", L"/%2f", "pct2f_lower" },
    { "/%00", L"/%00", "pct00" },
    { "/a/../b", L"/a/../b", "dotdot" },
    { "/a/./b", L"/a/./b", "dot" },
    { "/a/%2e%2e/b", L"/a/%2e%2e/b", "pct_dotdot" },
    { "/a\\b", L"/a\\b", "backslash" },
    { "/t\tab", L"/t\tab", "tab" },
    { "/q\"<>", L"/q\"<>", "quote_lt_gt" },
    { "/\xe9", L"/\x00e9", "e_acute" },
    { "/\xc3\xa9", L"/\x00c3\x00a9", "utf8_bytes_as_latin1" },
    { NULL, L"/\x4e2d\x6587", "cjk" },
    { NULL, L"/\x20ac", "euro" },
    { NULL, L"/\xd83d\xde00", "emoji" },
    { NULL, L"/\x00e9?q=\x00e9", "e_acute_query" },
};
static void path_run(const path_case *c, int mode) {
    /* mode 0: InternetOpenUrlA, 1: InternetOpenUrlW, 2: HttpOpenRequestA, 3: HttpOpenRequestW */
    if ((mode == 0 || mode == 2) && !c->a) return;
    hep_srv *h = hep_start_ok(); if (!h) return;
    HINTERNET hi = hep_session(NULL, 0);
    BOOL ok = FALSE; DWORD err = 0;
    if (mode == 0) {
        char url[512]; snprintf(url, sizeof url, "http://127.0.0.1:%u%s", srv_port(h->s), c->a);
        hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r); ok = r.ok; err = r.err;
    } else if (mode == 1) {
        WCHAR url[512]; swprintf(url, 512, L"http://127.0.0.1:%u%ls", srv_port(h->s), c->w);
        hep_res r; hep_openurl_w(hi, url, 0, &r); ok = r.ok; err = r.err;
    } else {
        HINTERNET hc = hep_connect(hi, h);
        HINTERNET hr = mode == 2 ? U(HttpOpenRequestA)(hc, "GET", c->a, NULL, NULL, NULL, HEP_F, 0)
                                 : U(HttpOpenRequestW)(hc, L"GET", c->w, NULL, NULL, NULL, HEP_F, 0);
        if (hr) { ok = mode == 2 ? U(HttpSendRequestA)(hr, NULL, 0, NULL, 0) : U(HttpSendRequestW)(hr, NULL, 0, NULL, 0); err = ok ? 0 : GetLastError();
                  if (ok) { char b[8]; t_inet_read_all(hr, b, sizeof b, NULL); } U(InternetCloseHandle)(hr); }
        else err = GetLastError();
        U(InternetCloseHandle)(hc);
    }
    static const char *mn[] = { "OpenUrlA", "OpenUrlW", "OpenRequestA", "OpenRequestW" };
    const char *tg = ok && srv_wait_requests(h->s, 1, 2000) ? srv_req_target(h->s, 0) : NULL;
    t_note("OBS path %s %s -> ok=%d err=%lu target=%s", mn[mode], c->tag, ok, err, tg ? hep_esc(tg, strlen(tg)) : "-");
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_url_path_bytes_openurl_a)     { HEP_REQUIRE_HTTP(); for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) path_run(&paths[i], 0); }
TEST(hep_url_path_bytes_openurl_w)     { HEP_REQUIRE_HTTP(); REQUIRE(U(InternetOpenUrlW)); for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) path_run(&paths[i], 1); }
TEST(hep_url_path_bytes_openrequest_a) { HEP_REQUIRE_HTTP(); for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) path_run(&paths[i], 2); }
TEST(hep_url_path_bytes_openrequest_w) { HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); for (size_t i = 0; i < sizeof paths / sizeof paths[0]; i++) path_run(&paths[i], 3); }

TEST(hep_url_openrequest_w_object_is_utf8) {
    /* decomp HttpOpenRequestW@0xbea10: the object name is converted with CP_UTF8 */
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_session(NULL, 0), hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", L"/\x4e2d", NULL, NULL, NULL, HEP_F, 0);
    CHECK(hr != NULL);
    CHECK(U(HttpSendRequestW)(hr, NULL, 0, NULL, 0));
    CHECK(srv_wait_requests(h->s, 1, 2000));
    const char *tg = srv_req_target(h->s, 0);
    t_note("OBS OpenRequestW CJK object -> %s", tg ? hep_esc(tg, strlen(tg)) : "-");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ code page options */
TEST(hep_url_codepage_options_defaults) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = hep_session(NULL, 0);
    static const DWORD opts[] = { INTERNET_OPTION_CODEPAGE, INTERNET_OPTION_CODEPAGE_PATH, INTERNET_OPTION_CODEPAGE_EXTRA, INTERNET_OPTION_IDN };
    static const char *nm[] = { "CODEPAGE", "CODEPAGE_PATH", "CODEPAGE_EXTRA", "IDN" };
    for (int i = 0; i < 4; i++) {
        DWORD v = 0xdeadbeef, l = sizeof v;
        BOOL q = U(InternetQueryOptionA)(hi, opts[i], &v, &l);
        t_note("OBS session option %s: q=%d err=%lu v=%lu (0x%lx) len=%lu", nm[i], q, q ? 0 : GetLastError(), v, v, l);
        DWORD gv = 0xdeadbeef, gl = sizeof gv;
        BOOL gq = U(InternetQueryOptionA)(NULL, opts[i], &gv, &gl);
        t_note("OBS global option %s: q=%d err=%lu v=%lu", nm[i], gq, gq ? 0 : GetLastError(), gv);
    }
    t_inet_close(hi);
}
static void cp_case(DWORD opt, DWORD val, int on_session, const WCHAR *wpath, const char *tag) {
    hep_srv *h = hep_start_ok(); if (!h) return;
    HINTERNET hi = hep_session(NULL, 0);
    BOOL s = TRUE; DWORD se = 0;
    HINTERNET hc = hep_connect(hi, h);
    HINTERNET hr = U(HttpOpenRequestW)(hc, L"GET", wpath, NULL, NULL, NULL, HEP_F, 0);
    if (on_session) { s = U(InternetSetOptionA)(hi, opt, &val, sizeof val); se = s ? 0 : GetLastError(); }
    else { s = U(InternetSetOptionA)(hr, opt, &val, sizeof val); se = s ? 0 : GetLastError(); }
    BOOL ok = U(HttpSendRequestW)(hr, NULL, 0, NULL, 0);
    const char *tg = ok && srv_wait_requests(h->s, 1, 2000) ? srv_req_target(h->s, 0) : NULL;
    t_note("OBS codepage %s opt=%lu val=%lu %s set=%d/%lu -> ok=%d target=%s", tag, opt, val, on_session ? "session" : "request", s, se, ok,
           tg ? hep_esc(tg, strlen(tg)) : "-");
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi); hep_stop(h);
}
TEST(hep_url_codepage_path_option_effect) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(InternetSetOptionA));
    cp_case(INTERNET_OPTION_CODEPAGE_PATH, CP_UTF8, 0, L"/\x00e9", "path_utf8_req");
    cp_case(INTERNET_OPTION_CODEPAGE_PATH, 1252, 0, L"/\x00e9", "path_1252_req");
    cp_case(INTERNET_OPTION_CODEPAGE_PATH, 1252, 1, L"/\x00e9", "path_1252_session");
    cp_case(INTERNET_OPTION_CODEPAGE_EXTRA, 1252, 0, L"/p?q=\x00e9", "extra_1252_req");
    cp_case(INTERNET_OPTION_CODEPAGE, 1252, 0, L"/\x00e9", "codepage_1252_req");
}
TEST(hep_url_codepage_path_openurl_w) {
    /* set CODEPAGE_PATH / EXTRA on the session and use InternetOpenUrlW */
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetOpenUrlW)); REQUIRE(U(InternetSetOptionA));
    static const struct { DWORD opt, val; const char *tag; } cs[] = {
        { 0, 0, "none" }, { INTERNET_OPTION_CODEPAGE_PATH, CP_UTF8, "path_utf8" }, { INTERNET_OPTION_CODEPAGE_PATH, 1252, "path_1252" },
        { INTERNET_OPTION_CODEPAGE_EXTRA, 1252, "extra_1252" }, { INTERNET_OPTION_CODEPAGE_EXTRA, CP_UTF8, "extra_utf8" },
    };
    for (size_t i = 0; i < sizeof cs / sizeof cs[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_session(NULL, 0);
        BOOL s = TRUE; if (cs[i].opt) s = U(InternetSetOptionA)(hi, cs[i].opt, (void *)&cs[i].val, sizeof cs[i].val);
        DWORD se = s ? 0 : GetLastError();
        WCHAR url[256]; swprintf(url, 256, L"http://127.0.0.1:%u/\x00e9?q=\x00e9", srv_port(h->s));
        hep_res r; hep_openurl_w(hi, url, 0, &r);
        const char *tg = r.ok && srv_wait_requests(h->s, 1, 2000) ? srv_req_target(h->s, 0) : NULL;
        t_note("OBS openurlW codepage %s set=%d/%lu -> ok=%d err=%lu target=%s", cs[i].tag, s, se, r.ok, r.err, tg ? hep_esc(tg, strlen(tg)) : "-");
        t_inet_close(hi); hep_stop(h);
    }
}
TEST(hep_url_codepage_invalid_values) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = hep_session(NULL, 0);
    static const DWORD opts[] = { INTERNET_OPTION_CODEPAGE, INTERNET_OPTION_CODEPAGE_PATH, INTERNET_OPTION_CODEPAGE_EXTRA };
    static const DWORD vals[] = { 0, 1, 12345, 65000, 65001, 0xffffffff };
    for (int i = 0; i < 3; i++) for (int j = 0; j < 6; j++) {
        DWORD v = vals[j];
        SetLastError(0);
        BOOL s = U(InternetSetOptionA)(hi, opts[i], &v, sizeof v);
        t_note("OBS set opt %lu = %lu -> %d err %lu", opts[i], v, s, s ? 0 : GetLastError());
    }
    DWORD v = CP_UTF8; SetLastError(0);
    BOOL s = U(InternetSetOptionA)(hi, INTERNET_OPTION_CODEPAGE_PATH, &v, 2);
    t_note("OBS set CODEPAGE_PATH short buffer -> %d err %lu", s, s ? 0 : GetLastError());
    t_inet_close(hi);
}

/* ------------------------------------------------------------ IDN hosts through a proxy */
static void idn_case(const WCHAR *host, DWORD idn_opt, int set_idn, const char *tag) {
    hep_srv *h = hep_start_ok(); if (!h) return;
    HINTERNET hi = hep_proxy_session(h, "hep-idn");
    BOOL s = TRUE; DWORD se = 0;
    if (set_idn) { s = U(InternetSetOptionA)(hi, INTERNET_OPTION_IDN, &idn_opt, sizeof idn_opt); se = s ? 0 : GetLastError(); }
    WCHAR url[256]; swprintf(url, 256, L"http://%ls/idn", host);
    hep_res r; hep_openurl_w(hi, url, 0, &r);
    int got = r.ok && srv_wait_requests(h->s, 1, 2000);
    const char *tg = got ? srv_req_target(h->s, 0) : NULL, *hh = got ? srv_req_header(h->s, 0, "Host") : NULL;
    t_note("OBS idn %s idnopt=%s%lu set=%d/%lu -> ok=%d err=%lu target=%s host=%s", tag, set_idn ? "" : "(unset)", idn_opt, s, se, r.ok, r.err,
           tg ? hep_esc(tg, strlen(tg)) : "-", hh ? hep_esc(hh, strlen(hh)) : "-");
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_idn_openurl_w_default) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetOpenUrlW));
    idn_case(L"b\x00fc" L"cher.example", 0, 0, "buecher");
    idn_case(L"\x4e2d\x6587.example", 0, 0, "cjk");
    idn_case(L"M\x00dc" L"NCHEN.example", 0, 0, "upper");
    idn_case(L"xn--bcher-kva.example", 0, 0, "already_puny");
    idn_case(L"\x00e9.\x00e9.example", 0, 0, "two_labels");
}
TEST(hep_idn_option_values) {
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetOpenUrlW)); REQUIRE(U(InternetSetOptionA));
    idn_case(L"b\x00fc" L"cher.example", 0, 1, "idn0");
    idn_case(L"b\x00fc" L"cher.example", 1, 1, "idn1_direct");
    idn_case(L"b\x00fc" L"cher.example", 2, 1, "idn2_proxy");
    idn_case(L"b\x00fc" L"cher.example", 3, 1, "idn3");
}
TEST(hep_idn_openurl_a_high_bytes) {
    HEP_REQUIRE_HTTP();
    static const char *hosts[] = { "b\xfc" "cher.example", "b\xc3\xbc" "cher.example" };
    for (int i = 0; i < 2; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_proxy_session(h, "hep-idn");
        char url[256]; snprintf(url, sizeof url, "http://%s/idn", hosts[i]);
        hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
        int got = r.ok && srv_wait_requests(h->s, 1, 2000);
        const char *tg = got ? srv_req_target(h->s, 0) : NULL, *hh = got ? srv_req_header(h->s, 0, "Host") : NULL;
        t_note("OBS idn A %d -> ok=%d err=%lu target=%s host=%s", i, r.ok, r.err, tg ? hep_esc(tg, strlen(tg)) : "-", hh ? hep_esc(hh, strlen(hh)) : "-");
        t_inet_close(hi); hep_stop(h);
    }
}
TEST(hep_idn_connect_w_host_header) {
    /* InternetConnectW with a Unicode server name through the proxy: HostWCharToCharEx (IDN aware) per decomp */
    HEP_REQUIRE_HTTP(); REQUIRE(U(InternetConnectW)); REQUIRE(U(HttpOpenRequestW)); REQUIRE(U(HttpSendRequestW));
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_proxy_session(h, "hep-idn");
    HINTERNET hc = U(InternetConnectW)(hi, L"b\x00fc" L"cher.example", 8080, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    HINTERNET hr = hc ? U(HttpOpenRequestW)(hc, L"GET", L"/c", NULL, NULL, NULL, HEP_F, 0) : NULL;
    BOOL ok = hr && U(HttpSendRequestW)(hr, NULL, 0, NULL, 0);
    int got = ok && srv_wait_requests(h->s, 1, 2000);
    const char *tg = got ? srv_req_target(h->s, 0) : NULL, *hh = got ? srv_req_header(h->s, 0, "Host") : NULL;
    t_note("OBS ConnectW IDN -> ok=%d err=%lu target=%s host=%s", ok, ok ? 0 : GetLastError(), tg ? hep_esc(tg, strlen(tg)) : "-", hh ? hep_esc(hh, strlen(hh)) : "-");
    if (hr) U(InternetCloseHandle)(hr);
    if (hc) U(InternetCloseHandle)(hc);
    t_inet_close(hi); hep_stop(h);
}

/* ------------------------------------------------------------ default port and Host header (proxy: absolute form) */
typedef struct { const char *url; const char *want_target; const char *want_host; } dp_case;
static const dp_case dps[] = {
    { "http://dp.example/x", "http://dp.example/x", "dp.example" },
    { "http://dp.example:80/x", NULL, NULL },
    { "http://dp.example:8080/x", "http://dp.example:8080/x", "dp.example:8080" },
    { "http://dp.example:080/x", NULL, NULL },
    { "http://DP.Example/x", NULL, NULL },
    { "http://dp.example./x", NULL, NULL },
    { "http://dp.example:/x", NULL, NULL },
    { "http://dp.example", NULL, NULL },
    { "http://dp.example?q", NULL, NULL },
    { "http://dp.example:443/x", NULL, NULL },
};
TEST(hep_default_port_host_header_via_proxy) {
    HEP_REQUIRE_HTTP();
    for (size_t i = 0; i < sizeof dps / sizeof dps[0]; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_proxy_session(h, "hep-dp");
        hep_res r; hep_openurl(hi, dps[i].url, NULL, 0, NULL, &r);
        int got = r.ok && srv_wait_requests(h->s, 1, 2000);
        const char *tg = got ? srv_req_target(h->s, 0) : NULL, *hh = got ? srv_req_header(h->s, 0, "Host") : NULL;
        t_note("OBS dp %s -> ok=%d err=%lu target=%s host=%s", dps[i].url, r.ok, r.err, tg ? tg : "-", hh ? hh : "-");
        if (dps[i].want_target) { CHECK(got); if (got) { EXPECT_STR(tg, dps[i].want_target); EXPECT_STR(hh, dps[i].want_host); } }
        t_inet_close(hi); hep_stop(h);
    }
}
TEST(hep_default_port_connect_port_values_via_proxy) {
    HEP_REQUIRE_HTTP();
    static const INTERNET_PORT ports[] = { 0, 80, 443, 8080, 65535 };
    for (int i = 0; i < 5; i++) {
        hep_srv *h = hep_start_ok(); if (!h) return;
        HINTERNET hi = hep_proxy_session(h, "hep-dp");
        HINTERNET hc = U(InternetConnectA)(hi, "dp.example", ports[i], NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/p", NULL, NULL, NULL, HEP_F, 0) : NULL;
        BOOL ok = hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        int got = ok && srv_wait_requests(h->s, 1, 2000);
        t_note("OBS connect port %u -> ok=%d target=%s host=%s", ports[i], ok, got ? srv_req_target(h->s, 0) : "-", got ? srv_req_header(h->s, 0, "Host") : "-");
        if (i == 0 || i == 1) { CHECK(got); if (got) { EXPECT_STR(srv_req_target(h->s, 0), "http://dp.example/p"); EXPECT_HDR(h->s, 0, "Host", "dp.example"); } }
        if (hr) U(InternetCloseHandle)(hr);
        if (hc) U(InternetCloseHandle)(hc);
        t_inet_close(hi); hep_stop(h);
    }
}
TEST(hep_direct_host_header_has_port) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    hep_req rq = {0}; hep_res r; hep_do(h, &rq, &r);
    CHECK(r.ok);
    CHECK(srv_wait_requests(h->s, 1, 2000));
    EXPECT_HDR(h->s, 0, "Host", hep_hostport(h));
    hep_stop(h);
}

/* ------------------------------------------------------------ IPv6 literals */
TEST(hep_ipv6_openurl_brackets) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    if (!srv_has_v6(h->s)) { t_skip("no [::1] listener in this guest"); hep_stop(h); return; }
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl(hi, srv_url_host(h->s, "[::1]", "/v6"), NULL, 0, NULL, &r);
    CHECKF(r.ok, "err %lu", r.err);
    if (r.ok && srv_wait_requests(h->s, 1, 2000)) {
        char want[64]; snprintf(want, sizeof want, "[::1]:%u", srv_port(h->s));
        EXPECT_HDR(h->s, 0, "Host", want);
        EXPECT_STR(srv_req_target(h->s, 0), "/v6");
    }
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_ipv6_connect_forms) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    if (!srv_has_v6(h->s)) { t_skip("no [::1] listener in this guest"); hep_stop(h); return; }
    static const char *names[] = { "::1", "[::1]", "0:0:0:0:0:0:0:1", "[0:0:0:0:0:0:0:1]", "::ffff:127.0.0.1", "[::1%1]" };
    for (int i = 0; i < 6; i++) {
        HINTERNET hi = hep_session(NULL, 2000);
        HINTERNET hc = U(InternetConnectA)(hi, names[i], srv_port(h->s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/c6", NULL, NULL, NULL, HEP_F, 0) : NULL;
        int before = srv_req_count(h->s);
        BOOL ok = hr && U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
        DWORD e = ok ? 0 : GetLastError();
        if (ok) { char b[8]; t_inet_read_all(hr, b, sizeof b, NULL); }
        int got = ok && srv_wait_requests(h->s, before + 1, 2000);
        t_note("OBS connect [%s] -> ok=%d err=%lu host=%s", names[i], ok, e, got ? srv_req_header(h->s, before, "Host") : "-");
        if (i == 0 && got) { char want[64]; snprintf(want, sizeof want, "[::1]:%u", srv_port(h->s)); EXPECT_HDR(h->s, before, "Host", want); }
        if (hr) U(InternetCloseHandle)(hr);
        if (hc) U(InternetCloseHandle)(hc);
        t_inet_close(hi);
    }
    hep_stop(h);
}
TEST(hep_ipv6_openurl_variants) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    if (!srv_has_v6(h->s)) { t_skip("no [::1] listener in this guest"); hep_stop(h); return; }
    char urls[5][128];
    snprintf(urls[0], 128, "http://[::1]:%u", srv_port(h->s));
    snprintf(urls[1], 128, "http://[0:0:0:0:0:0:0:1]:%u/x", srv_port(h->s));
    snprintf(urls[2], 128, "http://[::1]:%u/x?y#z", srv_port(h->s));
    snprintf(urls[3], 128, "http://::1:%u/x", srv_port(h->s));
    snprintf(urls[4], 128, "http://[::1%%251]:%u/x", srv_port(h->s));
    for (int i = 0; i < 5; i++) {
        HINTERNET hi = hep_session(NULL, 2000);
        int before = srv_req_count(h->s);
        hep_res r; hep_openurl(hi, urls[i], NULL, 0, NULL, &r);
        int got = r.ok && srv_wait_requests(h->s, before + 1, 2000);
        t_note("OBS v6 url %s -> ok=%d err=%lu target=%s host=%s", urls[i], r.ok, r.err, got ? srv_req_target(h->s, before) : "-", got ? srv_req_header(h->s, before, "Host") : "-");
        t_inet_close(hi);
    }
    hep_stop(h);
}

/* ------------------------------------------------------------ userinfo in InternetOpenUrl */
static void userinfo_case(const char *ui, const char *tag) {
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "no"), S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    hep_srv *h = hep_start(st, 5); if (!h) return;
    char url[256]; snprintf(url, sizeof url, "http://%s@127.0.0.1:%u/ui", ui, srv_port(h->s));
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
    srv_wait_requests(h->s, 1, 1000);
    int nreq = srv_req_count(h->s);
    const char *a0 = nreq > 0 ? srv_req_header(h->s, 0, "Authorization") : NULL;
    const char *a1 = nreq > 1 ? srv_req_header(h->s, 1, "Authorization") : NULL;
    char dec[128] = "-";
    const char *a = a1 ? a1 : a0;
    if (a && !strncmp(a, "Basic ", 6)) { size_t n = 0; unsigned char *d = srv_unb64(a + 6, &n); if (d) { snprintf(dec, sizeof dec, "%s", hep_esc(d, n)); free(d); } }
    t_note("OBS userinfo %s [%s] -> %s reqs=%d auth0=%s auth1=%s decoded=%s target=%s", tag, ui, hep_sig(&r, 0), nreq, a0 ? a0 : "-", a1 ? a1 : "-", dec,
           nreq ? srv_req_target(h->s, 0) : "-");
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_userinfo_table) {
    HEP_REQUIRE_HTTP();
    userinfo_case("user:pass", "plain");
    userinfo_case("user", "user_only");
    userinfo_case("user:", "empty_pass");
    userinfo_case(":pass", "empty_user");
    userinfo_case("us%40er:p%3Ass", "pct_escaped");
    userinfo_case("u:p:q", "colon_in_pass");
    userinfo_case("d%5Cu:p", "domain_backslash");
}
TEST(hep_userinfo_basic_preemptive_or_challenge) {
    /* the userinfo credentials end up in a Basic Authorization header; record whether the first request carries it */
    HEP_REQUIRE_HTTP();
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "no"), S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    HEP_SRV(h, hep_start(st, 5));
    char url[256]; snprintf(url, sizeof url, "http://alice:secret@127.0.0.1:%u/ui", srv_port(h->s));
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
    CHECK(r.ok);
    EXPECT_EQ(r.status, 200);
    CHECK(srv_wait_requests(h->s, 1, 1000));
    /* "alice:secret" */
    int found = 0;
    for (int i = 0; i < srv_req_count(h->s); i++) { const char *a = srv_req_header(h->s, i, "Authorization"); if (a && !strcmp(a, "Basic YWxpY2U6c2VjcmV0")) found = 1; }
    CHECK(found);
    for (int i = 0; i < srv_req_count(h->s); i++) EXPECT_STR(srv_req_target(h->s, i), "/ui");
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_userinfo_not_in_host_header) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    char url[256]; snprintf(url, sizeof url, "http://u:p@127.0.0.1:%u/h", srv_port(h->s));
    HINTERNET hi = hep_session(NULL, 0);
    hep_res r; hep_openurl(hi, url, NULL, 0, NULL, &r);
    CHECK(r.ok);
    if (srv_wait_requests(h->s, 1, 2000)) {
        EXPECT_HDR(h->s, 0, "Host", hep_hostport(h));
        EXPECT_STR(srv_req_target(h->s, 0), "/h");
        t_note("OBS userinfo on 200 server: auth0=%s", srv_req_header(h->s, 0, "Authorization") ? srv_req_header(h->s, 0, "Authorization") : "-");
    }
    t_inet_close(hi); hep_stop(h);
}
TEST(hep_userinfo_via_proxy_absolute_form) {
    HEP_REQUIRE_HTTP();
    HEP_SRV(h, hep_start_ok());
    HINTERNET hi = hep_proxy_session(h, "hep-ui");
    hep_res r; hep_openurl(hi, "http://u:p@ui.example/z", NULL, 0, NULL, &r);
    int got = r.ok && srv_wait_requests(h->s, 1, 2000);
    t_note("OBS userinfo via proxy -> ok=%d target=%s host=%s auth=%s", r.ok, got ? srv_req_target(h->s, 0) : "-", got ? srv_req_header(h->s, 0, "Host") : "-",
           got && srv_req_header(h->s, 0, "Authorization") ? srv_req_header(h->s, 0, "Authorization") : "-");
    t_inet_close(hi); hep_stop(h);
}
