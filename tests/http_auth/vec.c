/* http_auth: table-driven credential vectors.
 *  - Basic: base64 of every padding class and length, A and W entry points, connect vs request option.
 *  - InternetOpenUrl userinfo: percent-decoding table.
 *  - Digest: challenge parameter variants; every 200 is a server-verified MD5 chain, recomputed again here.
 * Every row uses its own server (own port), so the process-wide credential cache never links two rows. */
#include "auth.h"
#include <stdlib.h>
#include <ctype.h>

#define CH_BV "WWW-Authenticate: Basic realm=\"i7vec\"\r\n"

/* ------------------------------------------------------------------ Basic length / padding sweep */
static int basic_row(const char *tag, const char *user, const char *pass, int mode) {
    /* mode 0 = InternetConnectA, 1 = request option A, 2 = InternetConnectW, 3 = request option W */
    gate g = {0}; g.challenge = CH_BV; g.accept[0] = a_basic(user, pass);
    char want[512]; snprintf(want, sizeof want, "%s", g.accept[0]);
    srv *s = gate_start(&g); if (!s) { t_note("%s: server unavailable", tag); return 0; }
    HINTERNET hi = t_inet_open(NULL), hc = NULL, hr = NULL;
    WCHAR wu[256], wp[256];
    MultiByteToWideChar(CP_ACP, 0, user, -1, wu, 256); MultiByteToWideChar(CP_ACP, 0, pass, -1, wp, 256);
    if (mode == 2) hc = U(InternetConnectW)(hi, L"127.0.0.1", srv_port(s), wu, wp, INTERNET_SERVICE_HTTP, 0, 0);
    else hc = a_connect(hi, s, mode == 0 ? user : NULL, mode == 0 ? pass : NULL);
    hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/vec/row", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    if (mode == 1) { U(InternetSetOptionA)(hr, INTERNET_OPTION_USERNAME, (void *)user, (DWORD)strlen(user)); U(InternetSetOptionA)(hr, INTERNET_OPTION_PASSWORD, (void *)pass, (DWORD)strlen(pass)); }
    if (mode == 3) { U(InternetSetOptionW)(hr, INTERNET_OPTION_USERNAME, wu, (DWORD)lstrlenW(wu)); U(InternetSetOptionW)(hr, INTERNET_OPTION_PASSWORD, wp, (DWORD)lstrlenW(wp)); }
    BOOL ok = hr ? U(HttpSendRequestA)(hr, NULL, 0, NULL, 0) : FALSE;
    DWORD st = ok ? a_status(hr) : 0;
    int n = srv_req_count(s);
    const char *a = n >= 2 ? REQ_AUTH(s, 1) : NULL;
    int good = ok && st == 200 && n == 2 && a && !strcmp(a, want);
    CHECKF(good, "%s mode %d: ok=%d status=%lu requests=%d auth=[%s] want [%s]", tag, mode, ok, st, n, a ? a : "(none)", want);
    a_close(hr); a_close(hc); t_inet_close(hi); srv_stop(s);
    return good;
}

static void sweep(int mode) {
    static const char U16[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", P16[] = "0123456789!$&*+-=?_~ghijklmnopqr";
    for (int n = 1; n <= 18; n++) {
        char u[40], p[40], tag[32];
        memcpy(u, U16, n); u[n] = 0;
        int pl = (n * 7) % 13 + 1; memcpy(p, P16, pl); p[pl] = 0;
        snprintf(tag, sizeof tag, "len%d", n);
        basic_row(tag, u, p, mode);
    }
}
TEST(auth_vec_basic_length_sweep_connect_a)  { REQUIRE(U(HttpSendRequestA)); sweep(0); }
TEST(auth_vec_basic_length_sweep_option_a)   { REQUIRE(U(HttpSendRequestA)); sweep(1); }
TEST(auth_vec_basic_length_sweep_connect_w)  { REQUIRE(U(InternetConnectW)); sweep(2); }
TEST(auth_vec_basic_length_sweep_option_w)   { REQUIRE(U(InternetSetOptionW)); sweep(3); }

typedef struct { const char *tag, *user, *pass; } bv;
static const bv g_bv[] = {
    { "rfc7617",      "Aladdin",           "open sesame" },
    { "colons",       "a",                 "::::" },
    { "lead_space",   " lead",             " trail " },
    { "tabs",         "t\tab",             "p\tw" },
    { "equals",       "x=y",               "==" },
    { "slashes",      "/u/",               "/p/" },
    { "quote",        "q\"u",              "p\"w" },
    { "percent",      "100%",              "%41%42" },
    { "plus",         "a+b",               "c+d" },
    { "semicolon",    "a;b",               "c;d" },
    { "comma",        "a,b",               "c,d" },
    { "brackets",     "[u]",               "{p}" },
    { "len64",        "0123456789012345678901234567890123456789012345678901234567890123", "x" },
    { "pw200",        "u",                 "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP" },
};
TEST(auth_vec_basic_punctuation_table) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof g_bv / sizeof g_bv[0]; i++) {
        basic_row(g_bv[i].tag, g_bv[i].user, g_bv[i].pass, (int)(i % 2));
    }
}

TEST(auth_vec_basic_known_base64_strings) {
    REQUIRE(U(HttpSendRequestA));
    /* fixed strings (computed independently of a_basic) */
    static const struct { const char *u, *p, *hdr; } k[] = {
        { "Aladdin", "open sesame", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" },
        { "a", "b", "Basic YTpi" },
        { "ab", "c", "Basic YWI6Yw==" },
        { "abc", "d", "Basic YWJjOmQ=" },
        { "user", "pa:ss", "Basic dXNlcjpwYTpzcw==" },
    };
    for (int i = 0; i < 5; i++) {
        EXPECT_STR(a_basic(k[i].u, k[i].p), k[i].hdr);
        gate g = {0}; g.challenge = CH_BV; g.accept[0] = k[i].hdr;
        srv *s = gate_start(&g); if (!s) { t_skip("server unavailable"); return; }
        areq q = {0}; q.cuser = k[i].u; q.cpass = k[i].p; ares r; a_once(s, &q, &r);
        CHECKF(r.status == 200, "%s: status %lu", k[i].hdr, r.status);
        const char *a = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
        CHECKF(a && !strcmp(a, k[i].hdr), "%s: sent %s", k[i].hdr, a ? a : "(none)");
        srv_stop(s);
    }
}

TEST(auth_vec_basic_ansi_high_bytes_a) {
    REQUIRE(U(HttpSendRequestA));
    /* A entry point with bytes >= 0x80: observe what goes on the wire (raw bytes vs ACP->UTF-8 conversion) */
    const char *user = "caf\xe9", *pass = "\xfc" "ber";
    gate g = {0}; g.challenge = CH_BV; g.accept[0] = a_basic(user, pass); g.accept[1] = a_basic("caf\xc3\xa9", "\xc3\xbc" "ber");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.cuser = user; q.cpass = pass; ares r; a_once(s, &q, &r);
    const char *a = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    t_note("ACP=%u: A high bytes sent as %s (raw=%s utf8=%s)", GetACP(), a ? a : "(none)", a_basic(user, pass), a_basic("caf\xc3\xa9", "\xc3\xbc" "ber"));
    if (GetACP() == 1252) {
        EXPECT_EQ(r.status, 200);
        EXPECT_STR(a, a_basic(user, pass));   /* ACP bytes, same as the W path (basic.c, Win10 VM) */
    }
    srv_stop(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl userinfo table */
typedef struct { const char *tag, *userinfo, *user, *pass; int expect_auth; } uv;
static const uv g_uv[] = {
    { "plain",        "ou:op",          "ou", "op", 1 },
    { "pct_at_pass",  "ou:p%40q",       "ou", "p@q", 1 },
    { "pct_space",    "o%20u:p%20q",    "o u", "p q", 1 },
    { "pct_percent",  "ou:100%25",      "ou", "100%", 1 },
    { "pct_letters",  "%6f%75:%6f%70",  "ou", "op", 1 },
    { "plus_kept",    "o+u:p+q",        "o+u", "p+q", 1 },
    { "pct_slash",    "ou:a%2Fb",       "ou", "a/b", 1 },
    { "pct_hash",     "ou:a%23b",       "ou", "a#b", 1 },
    { "pct_question", "ou:a%3Fb",       "ou", "a?b", 1 },
    { "user_only",    "ou",             "ou", "", 0 },
    { "empty_pass",   "ou:",            "ou", "", 0 },
};
static void open_url_row(const uv *v, int wide) {
    gate g = {0}; g.challenge = CH_BV; g.accept[0] = a_basic(v->user, v->pass);
    char want[256]; snprintf(want, sizeof want, "%s", g.accept[0]);
    srv *s = gate_start(&g); if (!s) { t_note("%s: server unavailable", v->tag); return; }
    HINTERNET hi = t_inet_open(NULL);
    char url[512]; snprintf(url, sizeof url, "http://%s@%s/ou/%s", v->userinfo, srv_hostport(s), v->tag);
    HINTERNET hr;
    if (wide) { WCHAR wurl[512]; MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 512); hr = U(InternetOpenUrlW)(hi, wurl, NULL, 0, T_INET_FRESH, 0); }
    else hr = U(InternetOpenUrlA)(hi, url, NULL, 0, T_INET_FRESH, 0);
    DWORD e = hr ? 0 : GetLastError();
    DWORD st = hr ? a_status(hr) : 0;
    int n = srv_req_count(s);
    const char *a0 = n >= 1 ? REQ_AUTH(s, 0) : NULL, *a = n >= 2 ? REQ_AUTH(s, 1) : NULL;
    if (v->expect_auth) {
        CHECKF(hr && st == 200 && n == 2 && a && !strcmp(a, want), "%s %c: err=%lu status=%lu n=%d auth0=%s auth1=%s want %s", v->tag, wide ? 'W' : 'A', e, st, n, a0 ? a0 : "-", a ? a : "-", want);
    } else {
        CHECKF(hr && st == 401 && n == 1, "%s %c: err=%lu status=%lu n=%d auth0=%s auth1=%s", v->tag, wide ? 'W' : 'A', e, st, n, a0 ? a0 : "-", a ? a : "-");
    }
    CHECKF(a0 == NULL, "%s: pre-emptive %s", v->tag, a0);
    a_close(hr); t_inet_close(hi); srv_stop(s);
}
TEST(auth_vec_open_url_userinfo_table_a) {
    REQUIRE(U(InternetOpenUrlA));
    for (size_t i = 0; i < sizeof g_uv / sizeof g_uv[0]; i++) open_url_row(&g_uv[i], 0);
}
TEST(auth_vec_open_url_userinfo_table_w) {
    REQUIRE(U(InternetOpenUrlW));
    for (size_t i = 0; i < sizeof g_uv / sizeof g_uv[0]; i++) open_url_row(&g_uv[i], 1);
}

/* ------------------------------------------------------------------ Digest challenge variants */
typedef struct {
    const char *tag, *challenge, *realm, *nonce, *user, *pass, *verb, *path, *want_qop; int sess;
} dv;
#define DN1 "a9f0c3d2b1e84756"
#define DN2 "MTIzNDU2Nzg5MDEyMzQ1Ng==/+x"
static const dv g_dv[] = {
    { "alg_lower",    "WWW-Authenticate: Digest realm=\"r1\", nonce=\"" DN1 "\", qop=\"auth\", algorithm=md5\r\n", "r1", DN1, "du", "dp", "GET", "/dv/a", "auth", 0 },
    { "alg_quoted",   "WWW-Authenticate: Digest realm=\"r2\", nonce=\"" DN1 "\", qop=\"auth\", algorithm=\"MD5\"\r\n", "r2", DN1, "du", "dp", "GET", "/dv/b", "auth", 0 },
    { "realm_comma",  "WWW-Authenticate: Digest realm=\"i7 realm, with comma\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "i7 realm, with comma", DN1, "du", "dp", "GET", "/dv/c", "auth", 0 },
    { "nonce_b64",    "WWW-Authenticate: Digest realm=\"r4\", nonce=\"" DN2 "\", qop=\"auth\"\r\n", "r4", DN2, "du", "dp", "GET", "/dv/d", "auth", 0 },
    { "no_opaque",    "WWW-Authenticate: Digest realm=\"r5\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r5", DN1, "du", "dp", "GET", "/dv/e", "auth", 0 },
    { "domain",       "WWW-Authenticate: Digest realm=\"r6\", domain=\"/dv /other\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r6", DN1, "du", "dp", "GET", "/dv/f", "auth", 0 },
    { "qop_unquoted", "WWW-Authenticate: Digest realm=\"r7\", nonce=\"" DN1 "\", qop=auth\r\n", "r7", DN1, "du", "dp", "GET", "/dv/g", "auth", 0 },
    { "qop_list_int", "WWW-Authenticate: Digest realm=\"r8\", nonce=\"" DN1 "\", qop=\"auth-int,auth\"\r\n", "r8", DN1, "du", "dp", "GET", "/dv/h", "auth", 0 },
    { "pct_uri",      "WWW-Authenticate: Digest realm=\"r9\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r9", DN1, "du", "dp", "GET", "/dv/a%20b/c?x=1&y=%2F", "auth", 0 },
    { "pw_colon",     "WWW-Authenticate: Digest realm=\"r10\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r10", DN1, "du", "p:a:s", "GET", "/dv/i", "auth", 0 },
    { "user_at",      "WWW-Authenticate: Digest realm=\"r11\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r11", DN1, "u@i7.test", "dp", "GET", "/dv/j", "auth", 0 },
    { "rfc2069_put",  "WWW-Authenticate: Digest realm=\"r12\", nonce=\"" DN1 "\"\r\n", "r12", DN1, "du", "dp", "PUT", "/dv/k", NULL, 0 },
    { "sess_post",    "WWW-Authenticate: Digest realm=\"r13\", nonce=\"" DN1 "\", qop=\"auth\", algorithm=MD5-sess\r\n", "r13", DN1, "du", "dp", "POST", "/dv/l", "auth", 1 },
    { "charset",      "WWW-Authenticate: Digest realm=\"r14\", nonce=\"" DN1 "\", qop=\"auth\", charset=UTF-8\r\n", "r14", DN1, "du", "dp", "GET", "/dv/m", "auth", 0 },
    { "stale_false",  "WWW-Authenticate: Digest realm=\"r15\", nonce=\"" DN1 "\", qop=\"auth\", stale=FALSE\r\n", "r15", DN1, "du", "dp", "GET", "/dv/n", "auth", 0 },
    { "extra_ws",     "WWW-Authenticate: Digest   realm = \"r16\" ,nonce=\"" DN1 "\",qop=\"auth\"\r\n", "r16", DN1, "du", "dp", "GET", "/dv/o", "auth", 0 },
    { "scheme_case",  "WWW-Authenticate: DIGEST realm=\"r17\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r17", DN1, "du", "dp", "GET", "/dv/p", "auth", 0 },
    { "empty_realm",  "WWW-Authenticate: Digest realm=\"\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "", DN1, "du", "dp", "GET", "/dv/q", "auth", 0 },
    { "delete",       "WWW-Authenticate: Digest realm=\"r19\", nonce=\"" DN1 "\", qop=\"auth\"\r\n", "r19", DN1, "du", "dp", "DELETE", "/dv/r", "auth", 0 },
};
static int digest_row(const dv *v, int *status_out) {
    gate g; dgate(&g, v->challenge, v->user, v->pass); g.realm = v->realm; g.nonce = v->nonce; g.sess = v->sess;
    srv *s = gate_start(&g); if (!s) { t_note("%s: server unavailable", v->tag); return 0; }
    areq q = {0}; q.verb = v->verb; q.path = v->path; q.cuser = v->user; q.cpass = v->pass;
    if (!strcmp(v->verb, "POST") || !strcmp(v->verb, "PUT")) { q.body = "digest"; q.body_len = 6; }
    ares r; a_once(s, &q, &r);
    *status_out = (int)r.status;
    CHECKF(r.status == 200, "%s: status %lu requests %d auth=%.160s", v->tag, r.status, srv_req_count(s), srv_req_count(s) >= 2 && REQ_AUTH(s, 1) ? REQ_AUTH(s, 1) : "(none)");
    CHECKF(srv_req_count(s) == 2, "%s: %d requests", v->tag, srv_req_count(s));
    int good = 0;
    if (srv_req_count(s) >= 2) good = digest_check_recorded(s, 1, v->user, v->realm, v->pass, v->sess, v->want_qop);
    if (!good) a_dump(s);
    srv_stop(s);
    return good;
}
TEST(auth_vec_digest_challenge_variants) {
    REQUIRE(U(HttpSendRequestA));
    for (size_t i = 0; i < sizeof g_dv / sizeof g_dv[0]; i++) { int st; digest_row(&g_dv[i], &st); }
}

/* specific Digest shapes on top of the table */
TEST(auth_vec_digest_no_opaque_not_sent) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\"\r\n", "nu", "np");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/dv/noopaque"; q.cuser = "nu"; q.cpass = "np"; ares r; a_once(s, &q, &r);
    EXPECT_EQ(r.status, 200);
    char v[64]; const char *hv = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    CHECK(hv != NULL);
    CHECK(!a_param(hv, "opaque", v, sizeof v));
    t_note("digest without opaque: %s", hv ? hv : "(none)");
    srv_stop(s);
}

TEST(auth_vec_digest_algorithm_echo) {
    REQUIRE(U(HttpSendRequestA));
    static const char *ch[] = {
        "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\"\r\n",
        "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=MD5\r\n",
        "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=md5\r\n",
    };
    for (int i = 0; i < 3; i++) {
        gate g; dgate(&g, ch[i], "ae", "ap");
        srv *s = gate_start(&g); if (!s) { t_skip("server unavailable"); return; }
        areq q = {0}; q.path = "/dv/algecho"; q.cuser = "ae"; q.cpass = "ap"; ares r; a_once(s, &q, &r);
        CHECKF(r.status == 200, "row %d status %lu", i, r.status);
        const char *hv = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
        char alg[32] = ""; int has = hv ? a_param(hv, "algorithm", alg, sizeof alg) : 0;
        t_note("challenge %d: response algorithm present=%d value=[%s]", i, has, alg);
        srv_stop(s);
    }
}

TEST(auth_vec_digest_cnonce_and_nc_shape) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\"\r\n", "cn", "cp");
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    HINTERNET hi = t_inet_open(NULL), hc = a_connect(hi, s, "cn", "cp");
    char prev_cn[128] = "";
    for (int i = 0; i < 3; i++) {
        areq q = {0}; q.path = i == 0 ? "/dvs/a" : (i == 1 ? "/dvs/b" : "/dvs/c"); ares r; a_send(hc, &q, &r, 0);
        CHECKF(r.status == 200, "req %d: status %lu", i, r.status);
    }
    a_dump(s);
    int n = srv_req_count(s);
    /* 401 + retry for the first, then pre-emptive Digest with incrementing nc (digest.c, Win10 VM: nc=00000002) */
    EXPECT_EQ(n, 4);
    for (int i = 1; i < n; i++) {
        const char *hv = REQ_AUTH(s, i); char nc[16] = "", cn[128] = "";
        CHECKF(hv && a_param(hv, "nc", nc, sizeof nc), "req %d nc", i);
        char want[16]; snprintf(want, sizeof want, "%08x", i);
        CHECKF(!strcmp(nc, want), "req %d: nc=%s want %s", i, nc, want);
        CHECK(hv && a_param(hv, "cnonce", cn, sizeof cn));
        size_t cl = strlen(cn); int hex = 1; for (size_t k = 0; k < cl; k++) if (!isxdigit((unsigned char)cn[k])) hex = 0;
        t_note("req %d cnonce=[%s] len=%zu hex=%d same_as_prev=%d", i, cn, cl, hex, !strcmp(cn, prev_cn));
        CHECK(cl > 0);
        snprintf(prev_cn, sizeof prev_cn, "%s", cn);
        if (hv) digest_check_recorded(s, i, "cn", "i7digest", "cp", 0, "auth");
    }
    a_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(auth_vec_digest_qop_auth_int_only) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth-int\"\r\n", "ai", "ap");
    g.deny_403_after = 4;
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/dv/authint"; q.cuser = "ai"; q.cpass = "ap"; ares r; a_once(s, &q, &r);
    a_dump(s);
    const char *hv = srv_req_count(s) >= 2 ? REQ_AUTH(s, 1) : NULL;
    char qop[32] = ""; if (hv) a_param(hv, "qop", qop, sizeof qop);
    t_note("qop=auth-int only: status=%lu requests=%d qop sent=[%s]", r.status, srv_req_count(s), qop);
    CHECK(srv_req_count(s) <= 3);
    CHECK(r.status == 200 || r.status == 401);
    srv_stop(s);
}

TEST(auth_vec_digest_sha256_then_md5) {
    REQUIRE(U(HttpSendRequestA));
    gate g; dgate(&g, "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=SHA-256\r\n"
                      "WWW-Authenticate: Digest realm=\"i7digest\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=MD5\r\n", "sh", "sp");
    g.deny_403_after = 4;
    srv *s = gate_start(&g); SRV_OR_SKIP(s);
    areq q = {0}; q.path = "/dv/sha"; q.cuser = "sh"; q.cpass = "sp"; ares r; a_once(s, &q, &r);
    a_dump(s);
    t_note("SHA-256 + MD5 challenges: status=%lu requests=%d", r.status, srv_req_count(s));
    CHECK(srv_req_count(s) <= 3);
    srv_stop(s);
}
