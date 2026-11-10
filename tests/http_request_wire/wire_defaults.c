/* wire_defaults.c - request line and default header set/order/casing that WinINet puts on the wire.
 * VM_TIMEOUT: 600
 * Evidence: docs/research/02 section 3-4 (InternalHttpOpenRequestA, InitBeginSendRequest decomp) and the Win10 VM
 * (results/win10/http_request_wire.txt). See EVIDENCE.md. */
#include "hrw.h"

/* ------------------------------------------------------------------ baseline */
TEST(hrw_def_get_request_line) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "hrw-agent/1.0", "GET", "/p", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_EQ(w.status, 200);
    EXPECT_STR(w.body, "ok");
    EXPECT_STR(srv_req_line(w.s, 0), "GET /p HTTP/1.1");
    EXPECT_STR(srv_req_method(w.s, 0), "GET");
    EXPECT_STR(srv_req_target(w.s, 0), "/p");
    hrw_dump(w.s, 0);
    hrw_done(&w);
}

TEST(hrw_def_get_header_order_reload) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "hrw-agent/1.0", "GET", "/p", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Cache-Control");
    EXPECT_HDR(w.s, 0, "User-Agent", "hrw-agent/1.0");
    EXPECT_HDR(w.s, 0, "Host", hrw_hostport(w.s));
    EXPECT_HDR(w.s, 0, "Cache-Control", "no-cache");
    EXPECT_NOHDR(w.s, 0, "Accept");
    EXPECT_NOHDR(w.s, 0, "Accept-Encoding");
    EXPECT_NOHDR(w.s, 0, "Content-Length");
    EXPECT_NOHDR(w.s, 0, "Cookie");
    EXPECT_NOHDR(w.s, 0, "Referer");
    EXPECT_NOHDR(w.s, 0, "DNT");
    hrw_done(&w);
}

TEST(hrw_def_get_raw_head_exact) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "raw/1", "GET", "/raw", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    char want[256];
    snprintf(want, sizeof want, "GET /raw HTTP/1.1\r\nUser-Agent: raw/1\r\nHost: %s\r\nCache-Control: no-cache\r\n\r\n", hrw_hostport(w.s));
    EXPECT_STR(hrw_raw(w.s, 0), want);
    hrw_done(&w);
}

/* Which request flags produce Cache-Control / Pragma (unique path so a cache read can only miss). */
static void flag_case(DWORD flags, const char *want_names, const char *want_cc, const char *want_pragma) {
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "fl/1", "GET", t_uniq("/fl"), NULL, NULL, NULL, flags));
    char path[128]; snprintf(path, sizeof path, "/%s", t_uniq("fl"));
    U(InternetCloseHandle)(w.hr);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", path, NULL, NULL, NULL, flags, 0);
    CHECK(w.hr != NULL);
    hrw_send(&w, NULL, 0, NULL, 0);
    CHECKF(w.ok, "flags 0x%lx err %lu", flags, w.err);
    hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    CHECKF(!strcmp(hrw_names(s, 0), want_names), "flags 0x%lx names got \"%s\" want \"%s\"", flags, hrw_names(s, 0), want_names);
    const char *cc = srv_req_header(s, 0, "Cache-Control"), *pr = srv_req_header(s, 0, "Pragma");
    CHECKF(want_cc ? (cc && !strcmp(cc, want_cc)) : !cc, "flags 0x%lx Cache-Control got %s", flags, cc ? cc : "(none)");
    CHECKF(want_pragma ? (pr && !strcmp(pr, want_pragma)) : !pr, "flags 0x%lx Pragma got %s", flags, pr ? pr : "(none)");
    U(InternetCloseHandle)(w.hr); w.hr = NULL;
    hrw_done(&w);
}
TEST(hrw_def_flags_reload_only) { HRW_REQUIRE_HTTP(); flag_case(INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI, "User-Agent|Host|Cache-Control", "no-cache", NULL); }
TEST(hrw_def_flags_pragma_nocache_only) { HRW_REQUIRE_HTTP(); flag_case(INTERNET_FLAG_PRAGMA_NOCACHE | HRW_F_NORL, "User-Agent|Host|Cache-Control", "no-cache", NULL); }
TEST(hrw_def_flags_reload_and_pragma) { HRW_REQUIRE_HTTP(); flag_case(T_INET_FRESH, "User-Agent|Host|Cache-Control", "no-cache", NULL); }
TEST(hrw_def_flags_no_reload) { HRW_REQUIRE_HTTP(); flag_case(HRW_F_NORL, "User-Agent|Host", NULL, NULL); }
TEST(hrw_def_flags_no_cache_write_only) { HRW_REQUIRE_HTTP(); flag_case(INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, "User-Agent|Host", NULL, NULL); }
TEST(hrw_def_flags_keep_connection) { HRW_REQUIRE_HTTP(); flag_case(HRW_F | INTERNET_FLAG_KEEP_CONNECTION, "User-Agent|Host|Connection|Cache-Control", "no-cache", NULL); }
TEST(hrw_def_flags_no_auto_redirect) { HRW_REQUIRE_HTTP(); flag_case(HRW_F | INTERNET_FLAG_NO_AUTO_REDIRECT, "User-Agent|Host|Cache-Control", "no-cache", NULL); }
TEST(hrw_def_flags_no_auth) { HRW_REQUIRE_HTTP(); flag_case(HRW_F | INTERNET_FLAG_NO_AUTH, "User-Agent|Host|Cache-Control", "no-cache", NULL); }
TEST(hrw_def_flags_resynchronize) { HRW_REQUIRE_HTTP(); flag_case(HRW_F_NORL | INTERNET_FLAG_RESYNCHRONIZE, "User-Agent|Host", NULL, NULL); }
TEST(hrw_def_flags_hyperlink) { HRW_REQUIRE_HTTP(); flag_case(HRW_F_NORL | INTERNET_FLAG_HYPERLINK, "User-Agent|Host", NULL, NULL); }

/* ------------------------------------------------------------------ verbs */
typedef struct { const char *verb; const char *line_verb; const char *cl; } verb_case;
static const verb_case g_verbs[] = {
    { "GET", "GET", NULL }, { "HEAD", "HEAD", NULL }, { "POST", "POST", "0" }, { "PUT", "PUT", "0" },
    { "DELETE", "DELETE", "0" }, { "OPTIONS", "OPTIONS", "0" }, { "PATCH", "PATCH", "0" }, { "MKCOL", "MKCOL", "0" },
    { "PROPFIND", "PROPFIND", "0" }, { "FOO", "FOO", "0" }, { "get", "get", "0" }, { "Post", "Post", "0" },
    { "  GET", "GET", NULL }, { "GET  ", "GET", NULL }, { "\tPUT\t", "PUT", "0" }, { "X-CUSTOM_VERB.1", "X-CUSTOM_VERB.1", "0" },
};
static void verb_test(const verb_case *vc) {
    hrw w; int r = hrw_simple(&w, "verb/1", vc->verb, "/v", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECKF(r, "verb '%s' not recorded (send ok=%d err=%lu)", vc->verb, w.ok, w.err);
    char want[128]; snprintf(want, sizeof want, "%s /v HTTP/1.1", vc->line_verb);
    CHECKF(srv_req_line(w.s, 0) && !strcmp(srv_req_line(w.s, 0), want), "verb '%s': line got \"%s\" want \"%s\"", vc->verb, srv_req_line(w.s, 0), want);
    const char *cl = srv_req_header(w.s, 0, "Content-Length");
    CHECKF(vc->cl ? (cl && !strcmp(cl, vc->cl)) : !cl, "verb '%s': Content-Length got %s want %s", vc->verb, cl ? cl : "(none)", vc->cl ? vc->cl : "(none)");
    EXPECT_EQ(w.status, 200);
    t_note("verb '%s': %s", vc->verb, hrw_names(w.s, 0));
    hrw_done(&w);
}
TEST(hrw_verb_get) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[0]); }
TEST(hrw_verb_head) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[1]); }
TEST(hrw_verb_post_nobody) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[2]); }
TEST(hrw_verb_put_nobody) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[3]); }
TEST(hrw_verb_delete) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[4]); }
TEST(hrw_verb_options) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[5]); }
TEST(hrw_verb_patch) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[6]); }
TEST(hrw_verb_mkcol) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[7]); }
TEST(hrw_verb_propfind) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[8]); }
TEST(hrw_verb_custom) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[9]); }
TEST(hrw_verb_lowercase_get) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[10]); }
TEST(hrw_verb_mixedcase_post) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[11]); }
TEST(hrw_verb_leading_space) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[12]); }
TEST(hrw_verb_trailing_space) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[13]); }
TEST(hrw_verb_tabs) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[14]); }
TEST(hrw_verb_token_chars) { HRW_REQUIRE_HTTP(); verb_test(&g_verbs[15]); }

TEST(hrw_verb_null_is_get) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "v/1", NULL, "/n", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r); EXPECT_STR(srv_req_line(w.s, 0), "GET /n HTTP/1.1");
    hrw_done(&w);
}
TEST(hrw_verb_empty_is_get) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "v/1", "", "/e", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r); EXPECT_STR(srv_req_line(w.s, 0), "GET /e HTTP/1.1");
    hrw_done(&w);
}

/* Verbs rejected by HttpOpenRequest never reach the wire. */
static void bad_verb(const char *verb, DWORD want) {
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open("bv/1");
    w.hc = U(InternetConnectA)(w.hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    SetLastError(0xdeadbeef);
    HINTERNET h = U(HttpOpenRequestA)(w.hc, verb, "/x", NULL, NULL, NULL, HRW_F, 0);
    DWORD e = GetLastError();
    CHECKF(h == NULL, "verb '%s' accepted", verb);
    CHECKF(e == want, "verb '%s' err %lu want %lu", verb, e, want);
    if (h) U(InternetCloseHandle)(h);
    Sleep(50);
    EXPECT_EQ(srv_conn_count(s), 0);
    hrw_done(&w);
}
TEST(hrw_verb_trace_rejected) { HRW_REQUIRE_HTTP(); bad_verb("TRACE", ERROR_INTERNET_INVALID_OPERATION); }
TEST(hrw_verb_track_rejected) { HRW_REQUIRE_HTTP(); bad_verb("track", ERROR_INTERNET_INVALID_OPERATION); }
TEST(hrw_verb_inner_space_rejected) { HRW_REQUIRE_HTTP(); bad_verb("GE T", ERROR_INVALID_PARAMETER); }
TEST(hrw_verb_crlf_rejected) { HRW_REQUIRE_HTTP(); bad_verb("GET\r\nX: y", ERROR_INVALID_PARAMETER); }
TEST(hrw_verb_blank_rejected) { HRW_REQUIRE_HTTP(); bad_verb("   ", ERROR_INVALID_PARAMETER); }

/* ------------------------------------------------------------------ object name / request target */
typedef struct { const char *obj; const char *target; } obj_case;
static void obj_test(const char *obj, const char *want) {
    hrw w; int r = hrw_simple(&w, "o/1", "GET", obj, NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECKF(r, "obj '%s': nothing recorded ok=%d err=%lu", obj ? obj : "(null)", w.ok, w.err);
    const char *t = srv_req_target(w.s, 0);
    CHECKF(t && !strcmp(t, want), "obj '%s': target got \"%s\" want \"%s\"", obj ? obj : "(null)", t ? t : "(null)", want);
    hrw_done(&w);
}
TEST(hrw_obj_null_is_slash) { HRW_REQUIRE_HTTP(); obj_test(NULL, "/"); }
TEST(hrw_obj_empty_is_slash) { HRW_REQUIRE_HTTP(); obj_test("", "/"); }
TEST(hrw_obj_query_kept) { HRW_REQUIRE_HTTP(); obj_test("/q?a=1&b=two&c", "/q?a=1&b=two&c"); }
TEST(hrw_obj_percent_kept) { HRW_REQUIRE_HTTP(); obj_test("/a%20b%2Fc", "/a%20b%2Fc"); }
TEST(hrw_obj_space_escaped) { HRW_REQUIRE_HTTP(); obj_test("/a b", "/a%20b"); }
TEST(hrw_obj_fragment) { HRW_REQUIRE_HTTP(); obj_test("/f#frag", "/f#frag"); }
TEST(hrw_obj_no_leading_slash) { HRW_REQUIRE_HTTP(); obj_test("rel/x", "/rel/x"); }
TEST(hrw_obj_dot_segments_removed) { HRW_REQUIRE_HTTP(); obj_test("/a/../b/./c", "/b/c"); }
TEST(hrw_obj_dot_segments_with_query) { HRW_REQUIRE_HTTP(); obj_test("/a/./b/../c?x=/../y", "/a/c?x=/../y"); }
TEST(hrw_obj_dotdot_above_root_kept) { HRW_REQUIRE_HTTP(); obj_test("/../x", "/../x"); }
TEST(hrw_obj_star) { HRW_REQUIRE_HTTP(); obj_test("*", "/*"); }
TEST(hrw_obj_absolute_uri_direct) { HRW_REQUIRE_HTTP(); obj_test("http://other.example/abs", "/http://other.example/abs"); }
TEST(hrw_obj_double_slash) { HRW_REQUIRE_HTTP(); obj_test("//x//y", "//x//y"); }
TEST(hrw_obj_utf8_bytes_a) { HRW_REQUIRE_HTTP(); obj_test("/caf\xc3\xa9", "/caf%C3%A9"); }
TEST(hrw_obj_high_ansi_a) { HRW_REQUIRE_HTTP(); obj_test("/x\xe9y", "/x%EF%BF%BDy")   /* invalid UTF-8 byte -> U+FFFD, percent-encoded */; }
TEST(hrw_obj_quote_and_angle) { HRW_REQUIRE_HTTP(); obj_test("/a\"b<c>", "/a\"b<c>"); }

TEST(hrw_obj_long_path) {
    HRW_REQUIRE_HTTP();
    char p[2100]; p[0] = '/'; for (int i = 1; i < 2000; i++) p[i] = (char)('a' + i % 26); p[2000] = 0;
    obj_test(p, p);
}

TEST(hrw_obj_w_unicode) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "w/1", "GET", "/", NULL, NULL, NULL, HRW_F));
    U(InternetCloseHandle)(w.hr);
    w.hr = U(HttpOpenRequestW)(w.hc, L"GET", L"/café/中", NULL, NULL, NULL, HRW_F, 0);
    CHECK(w.hr != NULL);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_target(s, 0), "/caf%C3%A9/%E4%B8%AD");
    hrw_done(&w);
}

TEST(hrw_obj_w_ascii_same_as_a) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "w/1", "GET", "/", NULL, NULL, NULL, HRW_F));
    U(InternetCloseHandle)(w.hr);
    w.hr = U(HttpOpenRequestW)(w.hc, L"PUT", L"/w?x=1", L"HTTP/1.1", L"http://ref.example/", NULL, HRW_F, 0);
    CHECK(w.hr != NULL);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_STR(srv_req_line(s, 0), "PUT /w?x=1 HTTP/1.1");
    EXPECT_HDR(s, 0, "Referer", "http://ref.example/");
    EXPECT_HDR(s, 0, "Content-Length", "0");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ version */
static void ver_test(const char *ver, const char *want_line, const char *want_names) {
    hrw w; int r = hrw_simple(&w, "ver/1", "GET", "/ver", ver, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECKF(r, "version '%s': nothing recorded ok=%d err=%lu", ver ? ver : "(null)", w.ok, w.err);
    const char *l = srv_req_line(w.s, 0);
    CHECKF(l && !strcmp(l, want_line), "version '%s': line got \"%s\" want \"%s\"", ver ? ver : "(null)", l ? l : "(null)", want_line);
    if (want_names) CHECKF(!strcmp(hrw_names(w.s, 0), want_names), "version '%s': names got \"%s\" want \"%s\"", ver ? ver : "(null)", hrw_names(w.s, 0), want_names);
    hrw_done(&w);
}
TEST(hrw_ver_null_is_11) { HRW_REQUIRE_HTTP(); ver_test(NULL, "GET /ver HTTP/1.1", "User-Agent|Host|Cache-Control"); }
TEST(hrw_ver_empty_is_11) { HRW_REQUIRE_HTTP(); ver_test("", "GET /ver HTTP/1.1", "User-Agent|Host|Cache-Control"); }
TEST(hrw_ver_explicit_11) { HRW_REQUIRE_HTTP(); ver_test("HTTP/1.1", "GET /ver HTTP/1.1", "User-Agent|Host|Cache-Control"); }
/* InternalHttpOpenRequestA: with GlobalEnableHttp1_1 (default on) a parsed version of 1.0 (or major 0) becomes the literal
 * "HTTP/1.1"; a string not starting with "HTTP/" (case-insensitive) counts as 1.0; other versions are sent verbatim. */
TEST(hrw_ver_10_upgraded_to_11) { HRW_REQUIRE_HTTP(); ver_test("HTTP/1.0", "GET /ver HTTP/1.1", "User-Agent|Host|Cache-Control"); }
TEST(hrw_ver_09_upgraded_to_11) { HRW_REQUIRE_HTTP(); ver_test("HTTP/0.9", "GET /ver HTTP/1.1", "User-Agent|Host|Cache-Control"); }
TEST(hrw_ver_12_verbatim) { HRW_REQUIRE_HTTP(); ver_test("HTTP/1.2", "GET /ver HTTP/1.2", "User-Agent|Host|Cache-Control"); }
TEST(hrw_ver_10_lowercase_upgraded) { HRW_REQUIRE_HTTP(); ver_test("http/1.0", "GET /ver HTTP/1.1", NULL); }
TEST(hrw_ver_10_upgraded_no_connection_header) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ver/1", "GET", "/ver", "HTTP/1.0", NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_STR(srv_req_line(w.s, 0), "GET /ver HTTP/1.1");
    EXPECT_NOHDR(w.s, 0, "Connection");
    EXPECT_NOHDR(w.s, 0, "Pragma");
    hrw_done(&w);
}
TEST(hrw_ver_20_text) { HRW_REQUIRE_HTTP(); ver_test("HTTP/2.0", "GET /ver HTTP/2.0", NULL); }
TEST(hrw_ver_lowercase) { HRW_REQUIRE_HTTP(); ver_test("http/1.1", "GET /ver http/1.1", NULL); }
/* "HTTP/" followed by text that ExtractDword cannot parse: HttpOpenRequest still succeeds on Win10 (VM). */
static void odd_version(const char *ver) {
    hrw w; int r = hrw_simple(&w, "ov/1", "GET", "/ver", ver, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECKF(r, "version '%s': nothing recorded ok=%d err=%lu", ver, w.ok, w.err);
    t_note("version '%s' -> line \"%s\"", ver, srv_req_line(w.s, 0));
    hrw_done(&w);
}
TEST(hrw_ver_malformed_number) { HRW_REQUIRE_HTTP(); odd_version("HTTP/a.b"); }
TEST(hrw_ver_prefix_only) { HRW_REQUIRE_HTTP(); odd_version("HTTP/"); }
TEST(hrw_ver_garbage) { HRW_REQUIRE_HTTP(); ver_test("FOO", "GET /ver HTTP/1.1", NULL); }

/* Global HTTP_VERSION option changes the default request version for later HttpOpenRequest calls. */
TEST(hrw_ver_global_option_10) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetQueryOptionA)); REQUIRE(U(InternetSetOptionA));
    HTTP_VERSION_INFO old = { 0, 0 }, v10 = { 1, 0 }; DWORD l = sizeof old;
    BOOL q = U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &old, &l);
    CHECK(q); EXPECT_EQ(old.dwMajorVersion, 1); EXPECT_EQ(old.dwMinorVersion, 1);
    if (!q) return;
    CHECK(U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &v10, sizeof v10));
    hrw w; int r = hrw_simple(&w, "gv/1", "GET", "/gv", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    U(InternetSetOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &old, sizeof old);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    /* GlobalEnableHttp1_1: a 1.0 version is replaced by "HTTP/1.1" in InternalHttpOpenRequestA */
    EXPECT_STR(srv_req_line(w.s, 0), "GET /gv HTTP/1.1");
    hrw_dump(w.s, 0);
    hrw_done(&w);
    HTTP_VERSION_INFO now = { 0, 0 }; l = sizeof now;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_HTTP_VERSION, &now, &l));
    EXPECT_EQ(now.dwMajorVersion, 1); EXPECT_EQ(now.dwMinorVersion, 1);
}

/* ------------------------------------------------------------------ Referer */
TEST(hrw_ref_header_sent) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ref/1", "GET", "/r", NULL, "http://ref.example/from?x=1", NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Referer", "http://ref.example/from?x=1");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Referer"), 1);
    EXPECT_NAMES(w.s, 0, "Referer|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_ref_empty_not_sent) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ref/1", "GET", "/r", NULL, "", NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r); EXPECT_NOHDR(w.s, 0, "Referer");
    EXPECT_NAMES(w.s, 0, "User-Agent|Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_ref_relative_text_kept) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "ref/1", "GET", "/r", NULL, "not a url", NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r); EXPECT_HDR(w.s, 0, "Referer", "not a url");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ Accept types */
static void accept_test(const char **types, const char *want, const char *names) {
    hrw w; int r = hrw_simple(&w, "acc/1", "GET", "/a", NULL, NULL, types, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    const char *a = srv_req_header(w.s, 0, "Accept");
    CHECKF(want ? (a && !strcmp(a, want)) : !a, "Accept got \"%s\" want \"%s\"", a ? a : "(none)", want ? want : "(none)");
    if (names) EXPECT_NAMES(w.s, 0, names);
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Accept"), want ? 1 : 0);
    hrw_done(&w);
}
TEST(hrw_accept_two_types) { HRW_REQUIRE_HTTP(); static const char *t[] = { "text/*", "image/gif", NULL }; accept_test(t, "text/*, image/gif", "Accept|User-Agent|Host|Cache-Control"); }
TEST(hrw_accept_star) { HRW_REQUIRE_HTTP(); static const char *t[] = { "*/*", NULL }; accept_test(t, "*/*", "Accept|User-Agent|Host|Cache-Control"); }
TEST(hrw_accept_empty_array) { HRW_REQUIRE_HTTP(); static const char *t[] = { NULL }; accept_test(t, NULL, "User-Agent|Host|Cache-Control"); }
TEST(hrw_accept_three_types_q) { HRW_REQUIRE_HTTP(); static const char *t[] = { "text/html", "application/xml;q=0.9", "*/*;q=0.8", NULL }; accept_test(t, "text/html, application/xml;q=0.9, */*;q=0.8", NULL); }
TEST(hrw_accept_duplicates_kept) { HRW_REQUIRE_HTTP(); static const char *t[] = { "a/b", "a/b", NULL }; accept_test(t, "a/b, a/b", NULL); }
TEST(hrw_accept_padded_entry) { HRW_REQUIRE_HTTP(); static const char *t[] = { "  text/plain  ", NULL }; accept_test(t, "text/plain", NULL); }
TEST(hrw_accept_empty_string_entry) { HRW_REQUIRE_HTTP(); static const char *t[] = { "", "x/y", NULL }; accept_test(t, "x/y", NULL); }

TEST(hrw_accept_with_referer_order) {
    HRW_REQUIRE_HTTP();
    static const char *t[] = { "text/plain", NULL };
    hrw w; int r = hrw_simple(&w, "ar/1", "GET", "/ar", NULL, "http://r.example/", t, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_NAMES(w.s, 0, "Referer|Accept|User-Agent|Host|Cache-Control");
    hrw_done(&w);
}

TEST(hrw_accept_w_types) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpOpenRequestW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "aw/1", "GET", "/", NULL, NULL, NULL, HRW_F));
    U(InternetCloseHandle)(w.hr);
    static const WCHAR *t[] = { L"text/html", L"image/png", NULL };
    w.hr = U(HttpOpenRequestW)(w.hc, NULL, L"/aw", NULL, NULL, t, HRW_F, 0);
    CHECK(w.hr != NULL);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Accept", "text/html, image/png");
    hrw_done(&w);
}

/* ------------------------------------------------------------------ User-Agent */
static void ua_test(const char *agent, const char *want) {
    hrw w; int r = hrw_simple(&w, agent, "GET", "/ua", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    const char *u = srv_req_header(w.s, 0, "User-Agent");
    CHECKF(want ? (u && !strcmp(u, want)) : !u, "UA got \"%s\" want \"%s\"", u ? u : "(none)", want ? want : "(none)");
    hrw_done(&w);
}
TEST(hrw_ua_plain) { HRW_REQUIRE_HTTP(); ua_test("Mozilla/4.0 (compatible; hrw)", "Mozilla/4.0 (compatible; hrw)"); }
TEST(hrw_ua_trimmed) { HRW_REQUIRE_HTTP(); ua_test("  \tpadded agent \t ", "padded agent"); }
TEST(hrw_ua_empty_absent) { HRW_REQUIRE_HTTP(); ua_test("", NULL); }
TEST(hrw_ua_blank_absent) { HRW_REQUIRE_HTTP(); ua_test("   ", NULL); }
TEST(hrw_ua_null_absent) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = U(InternetOpenA)(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(w.hi != NULL);
    w.hc = U(InternetConnectA)(w.hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/nua", NULL, NULL, NULL, HRW_F, 0);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_NOHDR(s, 0, "User-Agent");
    EXPECT_NAMES(s, 0, "Host|Cache-Control");
    hrw_done(&w);
}
TEST(hrw_ua_long) {
    HRW_REQUIRE_HTTP();
    char a[1100]; for (int i = 0; i < 1000; i++) a[i] = (char)('A' + i % 26); a[1000] = 0;
    ua_test(a, a);
}
TEST(hrw_ua_inner_spaces_kept) { HRW_REQUIRE_HTTP(); ua_test("a  b\tc", "a  b\tc"); }

TEST(hrw_ua_w_nonascii) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetOpenW));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = U(InternetOpenW)(L"agent-é", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(w.hi != NULL);
    w.hc = U(InternetConnectA)(w.hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/uw", NULL, NULL, NULL, HRW_F, 0);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    const char *u = srv_req_header(s, 0, "User-Agent");
    CHECKF(u && !strcmp(u, "agent-\xe9"), "UA bytes %s", u ? u : "(none)");   /* W agent -> ANSI code page (1252), not UTF-8 */
    hrw_dump(s, 0);
    hrw_done(&w);
}

/* INTERNET_OPTION_USER_AGENT set on the session after InternetOpen applies to requests opened later. */
TEST(hrw_ua_option_on_session) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; memset(&w, 0, sizeof w); w.s = s;
    w.hi = t_inet_open("before/1");
    static const char ua[] = "after/2";
    CHECK(U(InternetSetOptionA)(w.hi, INTERNET_OPTION_USER_AGENT, (void *)ua, sizeof ua - 1));
    w.hc = U(InternetConnectA)(w.hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    w.hr = U(HttpOpenRequestA)(w.hc, "GET", "/uo", NULL, NULL, NULL, HRW_F, 0);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "User-Agent", "after/2");
    hrw_done(&w);
}

/* Changing the session agent after the request handle exists: observed per Win10 run. */
TEST(hrw_ua_option_after_request_open) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetSetOptionA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "first/1", "GET", "/ua2", NULL, NULL, NULL, HRW_F));
    static const char ua[] = "second/2";
    CHECK(U(InternetSetOptionA)(w.hi, INTERNET_OPTION_USER_AGENT, (void *)ua, sizeof ua - 1));
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    const char *u = srv_req_header(s, 0, "User-Agent");
    t_note("UA after late session option: %s", u ? u : "(none)");
    CHECK(u && (!strcmp(u, "first/1") || !strcmp(u, "second/2")));
    hrw_done(&w);
}

/* ------------------------------------------------------------------ Host */
TEST(hrw_host_ipv4_port) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "h/1", "GET", "/h", NULL, NULL, NULL, HRW_F, NULL, NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Host", hrw_hostport(w.s));
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Host"), 1);
    EXPECT_EQ(srv_req_header_index(w.s, 0, "Host"), 1);
    hrw_done(&w);
}
static void host_case(const char *connect_host, const char *want_fmt) {
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; int o = hrw_open_host(&w, s, "h/1", connect_host, "GET", "/h", HRW_F);
    CHECKF(o, "open %s err %lu", connect_host, GetLastError());
    if (o) { hrw_send(&w, NULL, 0, NULL, 0); CHECKF(w.ok, "%s: err %lu", connect_host, w.err); if (w.ok) hrw_read(&w); }
    CHECK(srv_wait_requests(s, 1, 3000));
    char want[128]; snprintf(want, sizeof want, want_fmt, srv_port(s));
    const char *h = srv_req_header(s, 0, "Host");
    CHECKF(h && !strcmp(h, want), "connect '%s': Host got \"%s\" want \"%s\"", connect_host, h ? h : "(none)", want);
    hrw_done(&w);
}
TEST(hrw_host_localhost) { HRW_REQUIRE_HTTP(); host_case("localhost", "localhost:%u"); }
TEST(hrw_host_localhost_upper) { HRW_REQUIRE_HTTP(); host_case("LocalHost", "LocalHost:%u"); }
TEST(hrw_host_ipv6_literal) { HRW_REQUIRE_HTTP(); host_case("::1", "[::1]:%u"); }
TEST(hrw_host_ipv6_bracketed) { HRW_REQUIRE_HTTP(); host_case("[::1]", "[::1]:%u"); }

TEST(hrw_host_ipv6_openurl) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(InternetOpenUrlA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open("h6/1");
    char body[16]; size_t n; DWORD err;
    int st = t_http_get(hi, srv_url_host(s, "[::1]", "/v6"), NULL, HRW_F, body, sizeof body, &n, &err);
    CHECKF(st == 200, "st %d err %lu", st, err);
    CHECK(srv_wait_requests(s, 1, 3000));
    char want[64]; snprintf(want, sizeof want, "[::1]:%u", srv_port(s));
    EXPECT_HDR(s, 0, "Host", want);
    EXPECT_STR(srv_req_line(s, 0), "GET /v6 HTTP/1.1");
    t_inet_close(hi); srv_stop(s);
}

TEST(hrw_host_custom_header_wins) {
    HRW_REQUIRE_HTTP(); REQUIRE(U(HttpAddRequestHeadersA));
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "hc/1", "GET", "/hc", NULL, NULL, NULL, HRW_F));
    CHECK(U(HttpAddRequestHeadersA)(w.hr, "Host: virtual.example:8080", (DWORD)-1, HTTP_ADDREQ_FLAG_ADD));
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    EXPECT_HDR(s, 0, "Host", "virtual.example:8080");
    EXPECT_EQ(srv_req_header_occurrences(s, 0, "Host"), 1);
    hrw_dump(s, 0);
    hrw_done(&w);
}
TEST(hrw_host_custom_in_send_headers) {
    HRW_REQUIRE_HTTP();
    hrw w; int r = hrw_simple(&w, "hs/1", "GET", "/hs", NULL, NULL, NULL, HRW_F, "Host: other.example\r\n", NULL, 0);
    if (r < 0) { t_skip("server unavailable"); return; }
    CHECK(r);
    EXPECT_HDR(w.s, 0, "Host", "other.example");
    EXPECT_EQ(srv_req_header_occurrences(w.s, 0, "Host"), 1);
    hrw_done(&w);
}

/* ------------------------------------------------------------------ request handle reuse (re-send) */
TEST(hrw_resend_same_handle) {
    HRW_REQUIRE_HTTP();
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "rs/1", "GET", "/rs", NULL, NULL, NULL, HRW_F));
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    hrw_send(&w, NULL, 0, NULL, 0); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 2, 3000));
    EXPECT_STR(srv_req_line(s, 1), "GET /rs HTTP/1.1");
    EXPECT_NAMES(s, 0, "User-Agent|Host|Cache-Control");
    /* the re-send on the same handle carries an extra Connection header at the end */
    EXPECT_NAMES(s, 1, "User-Agent|Host|Cache-Control|Connection");
    EXPECT_HDR(s, 1, "Connection", "Keep-Alive");
    EXPECT_EQ(srv_req_header_occurrences(s, 1, "User-Agent"), 1);
    EXPECT_EQ(srv_req_header_occurrences(s, 1, "Host"), 1);
    EXPECT_EQ(srv_req_conn(s, 1), srv_req_conn(s, 0));
    hrw_done(&w);
}

/* ------------------------------------------------------------------ HttpQueryInfo request headers == wire */
TEST(hrw_queryinfo_request_headers_match_wire) {
    HRW_REQUIRE_HTTP();
    static const char *t[] = { "text/plain", NULL };
    srv *s = hrw_srv(); if (!s) { t_skip("server unavailable"); return; }
    hrw w; CHECK(hrw_open(&w, s, "qi/1", "POST", "/qi?z=1", NULL, "http://r.example/", t, HRW_F));
    hrw_send(&w, "X-One: 1\r\n", (DWORD)-1, "abc", 3); CHECK(w.ok); hrw_read(&w);
    CHECK(srv_wait_requests(s, 1, 3000));
    char buf[4096]; DWORD l = sizeof buf;
    BOOL q = U(HttpQueryInfoA)(w.hr, HTTP_QUERY_RAW_HEADERS_CRLF | HTTP_QUERY_FLAG_REQUEST_HEADERS, buf, &l, NULL);
    CHECK(q);
    if (q) { EXPECT_STR(buf, hrw_raw(s, 0)); EXPECT_EQ(l, strlen(hrw_raw(s, 0))); }
    hrw_done(&w);
}
