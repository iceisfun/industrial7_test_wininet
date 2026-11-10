/* session_handles / handle types, parents, contexts and per-type option rules for every handle-creating API:
 * InternetOpen, InternetConnect (HTTP/FTP), HttpOpenRequest (plain/SECURE), InternetOpenUrl (http, ftp file, ftp
 * directory with and without RAW_DATA, file:), FtpFindFirstFile, FtpOpenFile, FtpCommand data handles.
 * Evidence: [D InternetQueryOptionA@0x59730 case 9 (tag -> INTERNET_HANDLE_TYPE_*: 'Inet' 1, 'FCon' 2, 'HCon' 4,
 * 'FFnd' 5, 'FFnH' 6, 'FFil' 7, 'FFlH' 8, 'HReq' 13, 'HRlf' 14), case 0x15 (parent = this+0x70 -> +0x80), case 0x17
 * (REQUEST_FLAGS: 12018 on Inet/FCon/HCon/HRlf), case 0x22 (URL: HReq/FFnd/FFnH/FFil/FFlH only), case 0x1c-0x1d/0x2b-0x2c
 * (credentials: 12018 on NULL/Inet/HRlf), case 0x44 (CODEPAGE: not HRlf)], InternetSetOptionA case 2-8 (timeouts:
 * not HRlf -> 12018), case 0xc/0xd (buffer sizes). VM boots: EVIDENCE.md. */
#include "sh.h"

#define T_DIR_HTML 6   /* INTERNET_HANDLE_TYPE_FTP_FIND_HTML */
#define T_FILE_REQ 14  /* INTERNET_HANDLE_TYPE_FILE_REQUEST */

static HINTERNET sh_ftp_connect(HINTERNET s, srv *f, DWORD_PTR ctx) {
    return U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, ctx);
}

/* Create a scratch file and return its file:// URL in the form Win10 accepts (backslashes, see sh_conn_openurl_file_handle). */
static int sh_file_url(char *url, size_t cap, const char *leaf, const char *content) {
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, leaf);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w; WriteFile(h, content, (DWORD)strlen(content), &w, NULL); CloseHandle(h);
    snprintf(url, cap, "file://%s", path);
    return 1;
}

/* ------------------------------------------------------------------ type values per creating API */
TEST(sh_types_session_connect_values_a_and_w) {
    REQUIRE(U(InternetQueryOptionW));
    HINTERNET s = sh_open("types"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 1);
    HINTERNET r = c ? sh_request(c, "/t", 2) : NULL;
    HINTERNET hs[3] = { s, c, r }; const DWORD want[3] = { 1, 4, 13 };
    for (int k = 0; k < 3; k++) {
        if (!hs[k]) { CHECK(!"handle creation failed"); continue; }
        DWORD a = 0, w = 0, la = sizeof a, lw = sizeof w;
        CHECK(U(InternetQueryOptionA)(hs[k], INTERNET_OPTION_HANDLE_TYPE, &a, &la));
        CHECK(U(InternetQueryOptionW)(hs[k], INTERNET_OPTION_HANDLE_TYPE, &w, &lw));
        { int c_ = !!(a == want[k] && w == want[k]); t_check(c_, __FILE__, __LINE__, "a == want[k] && w == want[k]", "handle %d type A %lu W %lu want %lu", k, a, w, want[k]); }
        EXPECT_EQ(la, 4); EXPECT_EQ(lw, 4);
    }
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

/* HANDLE_TYPE buffer protocol: an 8-byte buffer gets 4 bytes, the rest untouched; 3 bytes -> 122 with 4. */
TEST(sh_types_handle_type_buffer_protocol) {
    HINTERNET s = sh_open("types-buf"); CHECK(s != NULL); if (!s) return;
    BYTE b[8]; memset(b, 0xab, sizeof b); DWORD len = sizeof b;
    SetLastError(0xdeadbeef);
    CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_HANDLE_TYPE, b, &len));
    EXPECT_EQ(len, 4); EXPECT_EQ(*(DWORD *)b, 1);
    CHECK(b[4] == 0xab && b[5] == 0xab && b[6] == 0xab && b[7] == 0xab);
    EXPECT_EQ(GetLastError(), 0);
    len = 3; SetLastError(0);
    EXPECT_FAIL(!U(InternetQueryOptionA)(s, INTERNET_OPTION_HANDLE_TYPE, b, &len), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(len, 4);
    len = 0; SetLastError(0);
    EXPECT_FAIL(!U(InternetQueryOptionW)(s, INTERNET_OPTION_HANDLE_TYPE, NULL, &len), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(len, 4);
    sh_close(s);
}

/* A SECURE request is still type 13; its URL is https and the port follows the connect (port 0 + SECURE -> 443). */
TEST(sh_types_secure_request) {
    HINTERNET s = sh_open("types-sec"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 0, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_SECURE, 0);
    HINTERNET r = c ? U(HttpOpenRequestA)(c, "GET", "/sec", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_SECURE, 0x31) : NULL;
    CHECK(r != NULL);
    if (r) {
        EXPECT_EQ(sh_htype(r, NULL), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        EXPECT_EQ(sh_parent(r, NULL), c);
        char u[128]; DWORD len, e;
        CHECK(sh_qstr(r, INTERNET_OPTION_URL, u, sizeof u, &len, &e)); EXPECT_STR(u, "https://127.0.0.1/sec");
        DWORD v;
        CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(v, INTERNET_REQFLAG_NO_HEADERS);
        CHECK(sh_qdw(r, INTERNET_OPTION_SECURITY_FLAGS, &v, &len, &e));
        EXPECT_EQ(v, 0);   /* VM: no ignore flags before the handshake */
        /* CERTIFICATE_STRUCT on an unsent SECURE request succeeds on Win10 (VM), unlike a plain-HTTP request (12016) */
        BYTE big[512]; DWORD bl = sizeof big; SetLastError(0);
        BOOL ok = U(InternetQueryOptionA)(r, INTERNET_OPTION_SECURITY_CERTIFICATE_STRUCT, big, &bl);
        CHECKF(ok, "unsent SECURE request CERTIFICATE_STRUCT: err %lu", GetLastError());   /* VM: answered (12016 only on plain-HTTP requests) */
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
}

/* Each handle reports its own dwContext; children never inherit the parent's. */
TEST(sh_types_contexts_are_per_handle) {
    HINTERNET s = sh_open("ctx"); CHECK(s != NULL); if (!s) return;
    ULONG_PTR v;
    CHECK(sh_qptr(s, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0);
    static const DWORD_PTR ctxs[] = { 0, 1, 0x7fffffff, 0x80000000u, (DWORD_PTR)0x123456789abcdef0ull, (DWORD_PTR)-1 };
    for (size_t i = 0; i < sizeof ctxs / sizeof *ctxs; i++) {
        HINTERNET c = sh_connect(s, "127.0.0.1", 80, ctxs[i]);
        HINTERNET r = c ? sh_request(c, "/", ctxs[(i + 1) % 6]) : NULL;
        CHECK(c && r);
        if (c) { CHECK(sh_qptr(c, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); { int c_ = !!(v == ctxs[i]); t_check(c_, __FILE__, __LINE__, "v == ctxs[i]", "connect ctx %llx got %llx", (unsigned long long)ctxs[i], (unsigned long long)v); } }
        if (r) { CHECK(sh_qptr(r, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); { int c_ = !!(v == ctxs[(i + 1) % 6]); t_check(c_, __FILE__, __LINE__, "v == ctxs[(i + 1) % 6]", "request ctx got %llx", (unsigned long long)v); } }
        if (r) sh_close(r);
        if (c) sh_close(c);
    }
    CHECK(sh_qptr(s, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0);
    sh_close(s);
}

/* The old CONTEXT_VALUE option number (10) and 45 read the same value; both are 8 bytes on x64. */
TEST(sh_types_context_old_and_new_option) {
    HINTERNET s = sh_open("ctx2"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0x5150);
    ULONG_PTR a = 0, b = 0; DWORD la, lb;
    if (c) {
        CHECK(sh_qptr(c, 10, &a, &la, NULL)); CHECK(sh_qptr(c, 45, &b, &lb, NULL));
        EXPECT_EQ(a, 0x5150); EXPECT_EQ(b, 0x5150); EXPECT_EQ(la, 8); EXPECT_EQ(lb, 8);
        ULONG_PTR nv = 0xfeed; DWORD e;
        CHECK(sh_set(c, INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv, &e));
        CHECK(sh_qptr(c, 10, &a, NULL, NULL)); EXPECT_EQ(a, 0xfeed);
        /* set through the old number: not settable that way */
        CHECK(!sh_set(c, 10, &nv, sizeof nv, &e)); EXPECT_EQ(e, ERROR_INTERNET_INVALID_OPTION);   /* VM: 12009 */
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl(http): hidden connect */
TEST(sh_types_openurl_http_hidden_connect_options) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("ou-hidden");
    HINTERNET r = s ? U(InternetOpenUrlA)(s, srv_url(sv, "/hid?q=1"), NULL, 0, T_INET_FRESH, 0x4411) : NULL;
    { int c_ = !!(r != NULL); t_check(c_, __FILE__, __LINE__, "r != NULL", "InternetOpenUrl err %lu", GetLastError()); }
    if (r) {
        HINTERNET hc = sh_parent(r, NULL);
        EXPECT_EQ(sh_htype(r, NULL), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        EXPECT_EQ(sh_htype(hc, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        EXPECT_EQ(sh_parent(hc, NULL), s);
        ULONG_PTR v;
        CHECK(sh_qptr(r, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0x4411);
        CHECK(sh_qptr(hc, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL));
        EXPECT_EQ(v, 0);   /* VM: the hidden connect does not get the OpenUrl context */
        char u[128]; DWORD len, e;
        CHECK(sh_qstr(r, INTERNET_OPTION_URL, u, sizeof u, &len, &e)); EXPECT_STR(u, srv_url(sv, "/hid?q=1"));
        DWORD f;
        CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &f, &len, &e));
        { int c_ = !!((f & INTERNET_REQFLAG_FROM_CACHE) == 0); t_check(c_, __FILE__, __LINE__, "(f & INTERNET_REQFLAG_FROM_CACHE) == 0", "REQUEST_FLAGS 0x%lx", f); }
        CHECK(!sh_qdw(hc, INTERNET_OPTION_REQUEST_FLAGS, &f, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        CHECK(sh_qdw(hc, INTERNET_OPTION_KEEP_CONNECTION, &f, &len, &e));
        /* the hidden connect has no credentials */
        CHECK(sh_qstr(hc, INTERNET_OPTION_USERNAME, u, sizeof u, &len, &e)); EXPECT_STR(u, ""); EXPECT_EQ(len, 0);
        char body[16]; t_inet_read_all(r, body, sizeof body, NULL);
        sh_close(r);
    }
    if (s) sh_close(s);
    srv_stop(sv);
}

/* Credentials in the URL land on the hidden connect (and so on the request). */
TEST(sh_types_openurl_http_url_credentials_on_hidden_connect) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("ou-cred");
    char url[128]; snprintf(url, sizeof url, "http://ouser:opass@127.0.0.1:%u/c", srv_port(sv));
    HINTERNET r = s ? U(InternetOpenUrlA)(s, url, NULL, 0, T_INET_FRESH, 1) : NULL;
    { int c_ = !!(r != NULL); t_check(c_, __FILE__, __LINE__, "r != NULL", "InternetOpenUrl err %lu", GetLastError()); }
    if (r) {
        HINTERNET hc = sh_parent(r, NULL);
        char b[64]; DWORD len, e;
        CHECK(sh_qstr(hc, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "ouser");
        CHECK(sh_qstr(hc, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "opass");
        CHECK(sh_qstr(r, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "ouser");
        CHECK(sh_qstr(r, INTERNET_OPTION_URL, b, sizeof b, &len, &e));
        { char want[96]; snprintf(want, sizeof want, "http://127.0.0.1:%u/c", srv_port(sv)); EXPECT_STR(b, want); }   /* VM: no userinfo in the URL option */
        if (srv_wait_requests(sv, 1, 3000)) {
            const char *az = srv_req_header(sv, 0, "Authorization");
            CHECKF(az == NULL, "Authorization sent pre-emptively: [%s]", az);   /* VM: credentials are only used after a 401 */
            EXPECT_STR(srv_req_target(sv, 0), "/c");
        }
        char body[16]; t_inet_read_all(r, body, sizeof body, NULL);
        sh_close(r);
    }
    if (s) sh_close(s);
    srv_stop(sv);
}

/* ------------------------------------------------------------------ file: handle (type 14) option rules */
TEST(sh_types_file_handle_option_rules) {
    REQUIRE(U(InternetOpenUrlA));
    char url[MAX_PATH + 16];
    if (!sh_file_url(url, sizeof url, "sh_types_file.txt", "file body")) { t_skip("cannot create scratch file"); return; }
    HINTERNET s = sh_open("file-rules"); CHECK(s != NULL); if (!s) return;
    HINTERNET f = U(InternetOpenUrlA)(s, url, NULL, 0, INTERNET_FLAG_NO_UI, 0x99);
    { int c_ = !!(f != NULL); t_check(c_, __FILE__, __LINE__, "f != NULL", "InternetOpenUrl(%s) err %lu", url, GetLastError()); }
    if (f) {
        EXPECT_EQ(sh_htype(f, NULL), T_FILE_REQ);
        EXPECT_EQ(sh_parent(f, NULL), s);
        ULONG_PTR cv; CHECK(sh_qptr(f, INTERNET_OPTION_CONTEXT_VALUE, &cv, NULL, NULL)); EXPECT_EQ(cv, 0x99);
        static const struct { DWORD opt; const char *name; } e18[] = {
            { INTERNET_OPTION_REQUEST_FLAGS, "REQUEST_FLAGS" }, { INTERNET_OPTION_URL, "URL" },
            { INTERNET_OPTION_USERNAME, "USERNAME" }, { INTERNET_OPTION_PASSWORD, "PASSWORD" },
            { INTERNET_OPTION_PROXY_USERNAME, "PROXY_USERNAME" }, { INTERNET_OPTION_PROXY_PASSWORD, "PROXY_PASSWORD" },
            { INTERNET_OPTION_CODEPAGE, "CODEPAGE" }, { INTERNET_OPTION_READ_BUFFER_SIZE, "READ_BUFFER_SIZE" },
            { INTERNET_OPTION_KEEP_CONNECTION, "KEEP_CONNECTION" }, { INTERNET_OPTION_SECURITY_FLAGS, "SECURITY_FLAGS" },
            { INTERNET_OPTION_USER_AGENT, "USER_AGENT" }, { INTERNET_OPTION_HTTP_DECODING, "HTTP_DECODING" },
            { INTERNET_OPTION_REQUEST_PRIORITY, "REQUEST_PRIORITY" },
        };
        for (size_t i = 0; i < sizeof e18 / sizeof *e18; i++) {
            BYTE b[256]; DWORD len = sizeof b; SetLastError(0);
            BOOL ok = U(InternetQueryOptionA)(f, e18[i].opt, b, &len);
            DWORD e = GetLastError();
            { int c_ = !!(!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "file handle query %s: ok=%d err %lu want 12018", e18[i].name, ok, ok ? 0 : e); }
        }
        /* timeouts: readable (per-handle or global value), but not settable on a file request [D set case 2-8 tag list] */
        DWORD v, len, e;
        CHECK(sh_qdw(f, INTERNET_OPTION_RECEIVE_TIMEOUT, &v, &len, &e)); EXPECT_EQ(len, 4);
        EXPECT_EQ(v, 30000);   /* VM: the session default */
        CHECK(!sh_setdw(f, INTERNET_OPTION_RECEIVE_TIMEOUT, 1234, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        CHECK(!sh_setdw(f, INTERNET_OPTION_READ_BUFFER_SIZE, 4096, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        CHECK(!sh_setdw(f, INTERNET_OPTION_HTTP_DECODING, 1, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        /* CONTEXT_VALUE is settable on any handle type */
        ULONG_PTR nc = 0x77; CHECK(sh_set(f, INTERNET_OPTION_CONTEXT_VALUE, &nc, sizeof nc, &e));
        CHECK(sh_qptr(f, INTERNET_OPTION_CONTEXT_VALUE, &cv, NULL, NULL)); EXPECT_EQ(cv, 0x77);
        char body[32]; size_t n = t_inet_read_all(f, body, sizeof body, NULL);
        EXPECT_EQ(n, 9); EXPECT_STR(body, "file body");
        sh_close(f);
    }
    sh_close(s);
}

/* A file request has no HTTP state: HttpQueryInfo gives 12018. */
TEST(sh_types_file_handle_http_apis_12018) {
    REQUIRE(U(InternetOpenUrlA)); REQUIRE(U(HttpQueryInfoA));
    char url[MAX_PATH + 16];
    if (!sh_file_url(url, sizeof url, "sh_types_file2.txt", "x")) { t_skip("cannot create scratch file"); return; }
    HINTERNET s = sh_open("file-http"); CHECK(s != NULL); if (!s) return;
    HINTERNET f = U(InternetOpenUrlA)(s, url, NULL, 0, INTERNET_FLAG_NO_UI, 1);
    CHECK(f != NULL);
    if (f) {
        char b[64]; DWORD len = sizeof b; SetLastError(0);
        BOOL ok = U(HttpQueryInfoA)(f, HTTP_QUERY_STATUS_CODE, b, &len, NULL);
        { int c_ = !!(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "HttpQueryInfo on file handle: ok=%d err %lu", ok, GetLastError()); }
        SetLastError(0);
        ok = U(HttpSendRequestA)(f, NULL, 0, NULL, 0);
        { int c_ = !!(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "HttpSendRequest on file handle: ok=%d err %lu", ok, GetLastError()); }
        SetLastError(0);
        HINTERNET bad = U(HttpOpenRequestA)(f, "GET", "/", NULL, NULL, NULL, 0, 0);
        { int c_ = !!(bad == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "bad == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "HttpOpenRequest on file handle: %p err %lu", bad, GetLastError()); }
        if (bad) sh_close(bad);
        SetLastError(0);
        HINTERNET bc = U(InternetConnectA)(f, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        { int c_ = !!(bc == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "bc == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "InternetConnect on file handle: %p err %lu", bc, GetLastError()); }
        if (bc) sh_close(bc);
        sh_close(f);
    }
    sh_close(s);
}

/* Closing the session closes a file request too. */
TEST(sh_types_file_handle_closed_with_session) {
    REQUIRE(U(InternetOpenUrlA));
    char url[MAX_PATH + 16];
    if (!sh_file_url(url, sizeof url, "sh_types_file3.txt", "abc")) { t_skip("cannot create scratch file"); return; }
    HINTERNET s = sh_open("file-close"); CHECK(s != NULL); if (!s) return;
    HINTERNET f = U(InternetOpenUrlA)(s, url, NULL, 0, INTERNET_FLAG_NO_UI, 1);
    CHECK(f != NULL);
    CHECK(sh_close(s));
    if (f) {
        DWORD e; sh_htype(f, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        SetLastError(0); EXPECT_FAIL(!sh_close(f), ERROR_INVALID_HANDLE);
    }
}

/* ------------------------------------------------------------------ FTP handle family */
TEST(sh_types_ftp_tree_parents_and_contexts) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(FtpOpenFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-tree");
    HINTERNET c = s ? sh_ftp_connect(s, f, 0xc0) : NULL;
    CHECK(c != NULL);
    if (c) {
        EXPECT_EQ(sh_htype(c, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        EXPECT_EQ(sh_parent(c, NULL), s);
        WIN32_FIND_DATAA fd;
        HINTERNET fh = U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 0xf0);
        CHECK(fh != NULL);
        if (fh) {
            EXPECT_EQ(sh_htype(fh, NULL), INTERNET_HANDLE_TYPE_FTP_FIND);
            EXPECT_EQ(sh_parent(fh, NULL), c);
            ULONG_PTR v; CHECK(sh_qptr(fh, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0xf0);
            char u[128]; DWORD len, e;
            CHECK(sh_qstr(fh, INTERNET_OPTION_URL, u, sizeof u, &len, &e));
            EXPECT_STR(u, ""); EXPECT_EQ(len, 0);   /* VM: FtpFindFirstFile handles have an empty URL */
            sh_close(fh);
        }
        HINTERNET fo = U(FtpOpenFileA)(c, "hello.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0xf1);
        CHECK(fo != NULL);
        if (fo) {
            EXPECT_EQ(sh_htype(fo, NULL), INTERNET_HANDLE_TYPE_FTP_FILE);
            EXPECT_EQ(sh_parent(fo, NULL), c);
            ULONG_PTR v; CHECK(sh_qptr(fo, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0xf1);
            char u[128]; DWORD len, e;
            CHECK(sh_qstr(fo, INTERNET_OPTION_URL, u, sizeof u, &len, &e));
            char want[96]; snprintf(want, sizeof want, "ftp://127.0.0.1:%u/hello.txt", srv_port(f));
            EXPECT_STR(u, want);
            char b[16]; size_t n = t_inet_read_all(fo, b, sizeof b, NULL); EXPECT_EQ(n, 5);
            sh_close(fo);
        }
        sh_close(c);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* InternetOpenUrl(ftp dir/): HTML listing handle (6) by default, raw find handle (5) with INTERNET_FLAG_RAW_DATA. */
TEST(sh_types_openurl_ftp_directory_types) {
    REQUIRE(U(InternetOpenUrlA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-dir");
    for (int raw = 0; s && raw < 2; raw++) {
        DWORD fl = INTERNET_FLAG_RELOAD | INTERNET_FLAG_PASSIVE | INTERNET_FLAG_NO_UI | (raw ? INTERNET_FLAG_RAW_DATA : 0);
        HINTERNET d = U(InternetOpenUrlA)(s, srv_url(f, "/pub/"), NULL, 0, fl, 0x60 + raw);
        { int c_ = !!(d != NULL); t_check(c_, __FILE__, __LINE__, "d != NULL", "OpenUrl(ftp dir, raw=%d) err %lu", raw, GetLastError()); }
        if (!d) continue;
        DWORD t = sh_htype(d, NULL);
        { int c_ = !!(t == (raw ? INTERNET_HANDLE_TYPE_FTP_FIND : T_DIR_HTML)); t_check(c_, __FILE__, __LINE__, "t == (raw ? INTERNET_HANDLE_TYPE_FTP_FIND : T_DIR_HTML)", "raw=%d type %lu", raw, t); }
        HINTERNET p = sh_parent(d, NULL);
        EXPECT_EQ(sh_htype(p, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        EXPECT_EQ(sh_parent(p, NULL), s);
        DWORD v, len, e;
        CHECK(sh_qdw(d, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); CHECKF(v == INTERNET_REQFLAG_NO_HEADERS, "ftp dir handle raw=%d REQUEST_FLAGS 0x%lx", raw, v);
        char u[128]; CHECK(sh_qstr(d, INTERNET_OPTION_URL, u, sizeof u, &len, &e)); EXPECT_STR(u, srv_url(f, "/pub/"));
        sh_close(d);
        DWORD e2; sh_htype(p, &e2); EXPECT_EQ(e2, ERROR_INVALID_HANDLE);   /* the hidden connect goes with it */
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* FtpCommand(fExpectResponse=TRUE) returns an FTP file handle (7) whose parent is the FTP connect. */
TEST(sh_types_ftp_command_data_handle) {
    REQUIRE(U(FtpCommandA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-cmd");
    HINTERNET c = s ? sh_ftp_connect(s, f, 1) : NULL;
    CHECK(c != NULL);
    if (c) {
        HINTERNET d = NULL;
        BOOL ok = U(FtpCommandA)(c, TRUE, FTP_TRANSFER_TYPE_ASCII, "NLST", 0xd0, &d);
        { int c_ = !!(ok && d != NULL); t_check(c_, __FILE__, __LINE__, "ok && d != NULL", "FtpCommand(NLST) ok=%d err %lu", ok, GetLastError()); }
        if (d) {
            DWORD t = sh_htype(d, NULL);
            EXPECT_EQ(t, INTERNET_HANDLE_TYPE_FTP_FILE);   /* VM: 7 */
            EXPECT_EQ(sh_parent(d, NULL), c);
            ULONG_PTR v; CHECK(sh_qptr(d, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0xd0);
            char b[256]; size_t n = t_inet_read_all(d, b, sizeof b, NULL);
            CHECK(n > 0 && strstr(b, "hello.txt") != NULL);
            sh_close(d);
        }
        sh_close(c);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* Option rules shared by every FTP handle kind: the HTTP-only options give 12018, timeouts and buffer sizes work. */
TEST(sh_types_ftp_set_rules) {
    REQUIRE(U(FtpFindFirstFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-set");
    HINTERNET c = s ? sh_ftp_connect(s, f, 1) : NULL;
    WIN32_FIND_DATAA fd;
    HINTERNET fh = c ? U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 2) : NULL;
    CHECK(c && fh);
    HINTERNET hs[2] = { c, fh }; const char *nm[2] = { "FCon", "FFnd" };
    for (int k = 0; k < 2; k++) {
        if (!hs[k]) continue;
        DWORD e, v;
        CHECK(sh_setdw(hs[k], INTERNET_OPTION_RECEIVE_TIMEOUT, 4321, &e));
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_RECEIVE_TIMEOUT, &v, NULL, &e)); { int c_ = !!(v == 4321); t_check(c_, __FILE__, __LINE__, "v == 4321", "%s RECEIVE_TIMEOUT %lu", nm[k], v); }
        { int c_ = !!(sh_setdw(hs[k], INTERNET_OPTION_READ_BUFFER_SIZE, 2048, &e)); t_check(c_, __FILE__, __LINE__, "sh_setdw(hs[k], INTERNET_OPTION_READ_BUFFER_SIZE, 2048, &e)", "%s READ_BUFFER_SIZE set err %lu", nm[k], e); }
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_READ_BUFFER_SIZE, &v, NULL, &e)); { int c_ = !!(v == 2048); t_check(c_, __FILE__, __LINE__, "v == 2048", "%s READ_BUFFER_SIZE %lu", nm[k], v); }
        { int c_ = !!(!sh_setdw(hs[k], INTERNET_OPTION_HTTP_DECODING, 1, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_setdw(hs[k], INTERNET_OPTION_HTTP_DECODING, 1, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "%s HTTP_DECODING err %lu", nm[k], e); }
        { int c_ = !!(!sh_setdw(hs[k], INTERNET_OPTION_SECURITY_FLAGS, 0x100, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_setdw(hs[k], INTERNET_OPTION_SECURITY_FLAGS, 0x100, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "%s SECURITY_FLAGS err %lu", nm[k], e); }
        { int c_ = !!(!sh_setdw(hs[k], INTERNET_OPTION_REQUEST_PRIORITY, 1, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_setdw(hs[k], INTERNET_OPTION_REQUEST_PRIORITY, 1, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "%s REQUEST_PRIORITY err %lu", nm[k], e); }
        char ua[] = "x";
        { int c_ = !!(!sh_set(hs[k], INTERNET_OPTION_USER_AGENT, ua, sizeof ua, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!sh_set(hs[k], INTERNET_OPTION_USER_AGENT, ua, sizeof ua, &e) && e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "%s USER_AGENT err %lu", nm[k], e); }
        { int c_ = !!(sh_setdw(hs[k], INTERNET_OPTION_CODEPAGE, 1252, &e)); t_check(c_, __FILE__, __LINE__, "sh_setdw(hs[k], INTERNET_OPTION_CODEPAGE, 1252, &e)", "%s CODEPAGE set err %lu", nm[k], e); }
        CHECK(sh_qdw(hs[k], INTERNET_OPTION_CODEPAGE, &v, NULL, &e)); { int c_ = !!(v == 1252); t_check(c_, __FILE__, __LINE__, "v == 1252", "%s CODEPAGE %lu", nm[k], v); }
    }
    if (fh) sh_close(fh);
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(f);
}

/* HTTP-only APIs on FTP handles and FTP-only APIs on HTTP handles give 12018. */
TEST(sh_types_cross_protocol_apis_12018) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(FtpGetCurrentDirectoryA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("cross");
    HINTERNET fc = s ? sh_ftp_connect(s, f, 1) : NULL;
    HINTERNET hc = s ? sh_connect(s, "127.0.0.1", 80, 1) : NULL;
    CHECK(fc && hc);
    if (fc) {
        SetLastError(0);
        HINTERNET r = U(HttpOpenRequestA)(fc, "GET", "/", NULL, NULL, NULL, 0, 0);
        { int c_ = !!(r == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "r == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "HttpOpenRequest(FCon) %p err %lu", r, GetLastError()); }
        if (r) sh_close(r);
    }
    if (hc) {
        WIN32_FIND_DATAA fd; SetLastError(0);
        HINTERNET fh = U(FtpFindFirstFileA)(hc, "*", &fd, 0, 0);
        { int c_ = !!(fh == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "fh == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "FtpFindFirstFile(HCon) %p err %lu", fh, GetLastError()); }
        if (fh) sh_close(fh);
        char d[64]; DWORD dl = sizeof d; SetLastError(0);
        BOOL ok = U(FtpGetCurrentDirectoryA)(hc, d, &dl);
        { int c_ = !!(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "FtpGetCurrentDirectory(HCon) ok=%d err %lu", ok, GetLastError()); }
    }
    if (s) {
        WIN32_FIND_DATAA fd; SetLastError(0);
        HINTERNET fh = U(FtpFindFirstFileA)(s, "*", &fd, 0, 0);
        { int c_ = !!(fh == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "fh == NULL && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "FtpFindFirstFile(session) %p err %lu", fh, GetLastError()); }
        if (fh) sh_close(fh);
        char b[8]; DWORD rd; SetLastError(0);
        BOOL ok = U(InternetReadFile)(s, b, sizeof b, &rd);
        { int c_ = !!(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "InternetReadFile(session) ok=%d err %lu", ok, GetLastError()); }
        DWORD avail; SetLastError(0);
        ok = U(InternetQueryDataAvailable)(s, &avail, 0, 0);
        { int c_ = !!(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "InternetQueryDataAvailable(session) ok=%d err %lu", ok, GetLastError()); }
    }
    if (hc) {
        char b[8]; DWORD rd; SetLastError(0);
        BOOL ok = U(InternetReadFile)(hc, b, sizeof b, &rd);
        { int c_ = !!(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE", "InternetReadFile(HCon) ok=%d err %lu", ok, GetLastError()); }
        DWORD w; SetLastError(0);
        ok = U(InternetWriteFile)(hc, "x", 1, &w);
        /* VM: InternetWriteFile rejects a non-writable handle type with 6, not 12018 */
        { int c_ = !!(!ok && GetLastError() == ERROR_INVALID_HANDLE); t_check(c_, __FILE__, __LINE__, "!ok && GetLastError() == ERROR_INVALID_HANDLE", "InternetWriteFile(HCon) ok=%d err %lu", ok, GetLastError()); }
    }
    if (s) {
        DWORD w; SetLastError(0);
        BOOL ok = U(InternetWriteFile)(s, "x", 1, &w);
        CHECKF(!ok && GetLastError() == ERROR_INVALID_HANDLE, "InternetWriteFile(session): ok=%d err %lu", ok, GetLastError());   /* VM: 6 */
        HINTERNET r = hc ? sh_request(hc, "/w", 0) : NULL;
        if (r) {
            SetLastError(0);
            ok = U(InternetWriteFile)(r, "x", 1, &w);
            CHECKF(!ok && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_STATE, "InternetWriteFile(unsent GET): ok=%d err %lu", ok, GetLastError());   /* VM: 12019 */
            sh_close(r);
        }
    }
    if (hc) sh_close(hc);
    if (fc) sh_close(fc);
    if (s) sh_close(s);
    srv_stop(f);
}

/* Option queries on an InternetOpenUrl(ftp file) handle: URL, USERNAME and the hidden FCon parent.
 * VM: USERNAME on the file handle reads "" (an explicit FTP connect without credentials reads "anonymous"). */
TEST(sh_types_openurl_ftp_file_options) {
    REQUIRE(U(InternetOpenUrlA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp-ou");
    HINTERNET d = s ? U(InternetOpenUrlA)(s, srv_url(f, "/hello.txt"), NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_PASSIVE | INTERNET_FLAG_NO_UI, 0x71) : NULL;
    { int c_ = !!(d != NULL); t_check(c_, __FILE__, __LINE__, "d != NULL", "OpenUrl(ftp file) err %lu", GetLastError()); }
    if (d) {
        EXPECT_EQ(sh_htype(d, NULL), INTERNET_HANDLE_TYPE_FTP_FILE);
        char b[128]; DWORD len, e;
        CHECK(sh_qstr(d, INTERNET_OPTION_URL, b, sizeof b, &len, &e)); EXPECT_STR(b, srv_url(f, "/hello.txt"));
        CHECK(sh_qstr(d, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        ULONG_PTR v; CHECK(sh_qptr(d, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0x71);
        HINTERNET p = sh_parent(d, NULL);
        EXPECT_EQ(sh_htype(p, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        char body[16]; size_t n = t_inet_read_all(d, body, sizeof body, NULL); EXPECT_EQ(n, 5); EXPECT_STR(body, "hello");
        sh_close(d);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

/* HTTP connect handles created with every service/port combination report the same type and the session parent. */
TEST(sh_types_http_connect_port_table_type) {
    HINTERNET s = sh_open("ports"); CHECK(s != NULL); if (!s) return;
    static const INTERNET_PORT ports[] = { 0, 1, 21, 25, 80, 443, 8080, 65535 };
    for (size_t i = 0; i < sizeof ports / sizeof *ports; i++) {
        for (int sec = 0; sec < 2; sec++) {
            HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", ports[i], NULL, NULL, INTERNET_SERVICE_HTTP, sec ? INTERNET_FLAG_SECURE : 0, 0);
            { int c_ = !!(c != NULL); t_check(c_, __FILE__, __LINE__, "c != NULL", "port %u sec %d err %lu", ports[i], sec, GetLastError()); }
            if (!c) continue;
            EXPECT_EQ(sh_htype(c, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
            EXPECT_EQ(sh_parent(c, NULL), s);
            sh_close(c);
        }
    }
    sh_close(s);
}
