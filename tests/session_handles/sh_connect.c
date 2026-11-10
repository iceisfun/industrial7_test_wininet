/* session_handles / InternetConnectA/W: service types, ports, server names, credentials, handle families
 * (HTTP connect, FTP connect, request, FTP find/file, InternetOpenUrl handles), handle-type and parent links.
 * Evidence: [D InternetConnectA@0x138070, InternetConnectW@0xc5a70, HttpConnect@0x5c250, InternetQueryOptionA case 9/0x15/0x1c].
 */
#include "sh.h"

/* ------------------------------------------------------------------ HTTP connect basics */
TEST(sh_conn_a_http_basic) {
    REQUIRE(U(InternetConnectA));
    HINTERNET s = sh_open("c"); CHECK(s != NULL); if (!s) return;
    SetLastError(0xdeadbeef);
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    EXPECT_EQ(GetLastError(), 0);
    if (c) {
        DWORD e;
        EXPECT_EQ(sh_htype(c, &e), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        EXPECT_EQ(sh_parent(c, &e), s);
        CHECK(c != s);
        CHECK(sh_close(c));
    }
    sh_close(s);
}

TEST(sh_conn_w_http_basic) {
    REQUIRE(U(InternetConnectW));
    HINTERNET s = sh_open("c"); CHECK(s != NULL); if (!s) return;
    SetLastError(0xdeadbeef);
    HINTERNET c = U(InternetConnectW)(s, L"127.0.0.1", 8080, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    EXPECT_EQ(GetLastError(), 0);
    if (c) {
        EXPECT_EQ(sh_htype(c, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        EXPECT_EQ(sh_parent(c, NULL), s);
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ service types */
static const DWORD sh_bad_services[] = { 0, 2 /* GOPHER */, 4, 5, 6, 7, 99, 0x100, 0x80000001u, 0xffffffffu };
TEST(sh_conn_service_type_table_a) {
    HINTERNET s = sh_open("svc"); CHECK(s != NULL); if (!s) return;
    for (size_t i = 0; i < sizeof sh_bad_services / sizeof *sh_bad_services; i++) {
        SetLastError(0);
        HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, sh_bad_services[i], 0, 0);
        DWORD e = GetLastError();
        CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "service %lu: h=%p err %lu", sh_bad_services[i], c, e);
        if (c) sh_close(c);
    }
    sh_close(s);
}
TEST(sh_conn_service_type_table_w) {
    HINTERNET s = sh_open("svc"); CHECK(s != NULL); if (!s) return;
    for (size_t i = 0; i < sizeof sh_bad_services / sizeof *sh_bad_services; i++) {
        SetLastError(0);
        HINTERNET c = U(InternetConnectW)(s, L"127.0.0.1", 80, NULL, NULL, sh_bad_services[i], 0, 0);
        DWORD e = GetLastError();
        CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "service %lu: h=%p err %lu", sh_bad_services[i], c, e);
        if (c) sh_close(c);
    }
    sh_close(s);
}
/* the service type is validated before the handle */
TEST(sh_conn_service_checked_before_handle) {
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(NULL, "127.0.0.1", 80, NULL, NULL, 2, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    c = U(InternetConnectA)(SH_GARBAGE1, "127.0.0.1", 80, NULL, NULL, 99, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ bad handles */
TEST(sh_conn_bad_handles) {
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(NULL, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_HANDLE);
    SetLastError(0);
    c = U(InternetConnectA)(SH_GARBAGE1, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_HANDLE);
    SetLastError(0);
    c = U(InternetConnectA)(SH_GARBAGE2, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_HANDLE);
    SetLastError(0);
    c = U(InternetConnectW)(NULL, L"127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_HANDLE);
    SetLastError(0);
    c = U(InternetConnectW)(SH_GARBAGE1, L"127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_HANDLE);
}

TEST(sh_conn_parent_wrong_type_12018) {
    HINTERNET s = sh_open("wt"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0); CHECK(c != NULL);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL; CHECK(r != NULL);
    if (c) {
        SetLastError(0);
        HINTERNET x = U(InternetConnectA)(c, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        EXPECT_FAIL(x == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); if (x) sh_close(x);
        SetLastError(0);
        x = U(InternetConnectW)(c, L"127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        EXPECT_FAIL(x == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); if (x) sh_close(x);
    }
    if (r) {
        SetLastError(0);
        HINTERNET x = U(InternetConnectA)(r, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        EXPECT_FAIL(x == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); if (x) sh_close(x);
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_conn_on_closed_session_6) {
    HINTERNET s = sh_open("cl"); CHECK(s != NULL); if (!s) return;
    CHECK(sh_close(s));
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_HANDLE);
    if (c) sh_close(c);
}

/* ------------------------------------------------------------------ server names */
TEST(sh_conn_null_server_87) {
    HINTERNET s = sh_open("ns"); CHECK(s != NULL); if (!s) return;
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(s, NULL, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    c = U(InternetConnectW)(s, NULL, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    c = U(InternetConnectA)(s, NULL, 21, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    c = U(InternetConnectW)(s, NULL, 21, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    sh_close(s);
}

/* the server name is validated before the handle (HttpConnect order) */
TEST(sh_conn_null_server_before_handle) {
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(SH_GARBAGE1, NULL, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    c = U(InternetConnectA)(NULL, "", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
}

TEST(sh_conn_empty_server) {
    HINTERNET s = sh_open("es"); CHECK(s != NULL); if (!s) return;
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(s, "", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_PARAMETER);
    if (c) sh_close(c);
    SetLastError(0);
    c = U(InternetConnectW)(s, L"", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    EXPECT_FAIL(c == NULL, ERROR_INVALID_NAME);
    if (c) sh_close(c);
    sh_close(s);
}

/* HTTP connect does no I/O: any syntactically plausible host name gives a handle */
static const char *const sh_hosts_ok[] = {
    "127.0.0.1", "localhost", "::1", "[::1]", "nohost.i7test.example", "a", "UPPER.Case.Example",
    "host-with-dash.example", "10.255.255.1", "xn--bcher-kva.example", "trailing.dot.example.",
};
TEST(sh_conn_http_hostnames_no_io) {
    HINTERNET s = sh_open("hn"); CHECK(s != NULL); if (!s) return;
    for (size_t i = 0; i < sizeof sh_hosts_ok / sizeof *sh_hosts_ok; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET c = U(InternetConnectA)(s, sh_hosts_ok[i], 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        DWORD e = GetLastError();
        CHECKF(c != NULL, "host [%s] err %lu", sh_hosts_ok[i], e);
        if (c) { EXPECT_EQ(e, 0); EXPECT_EQ(sh_htype(c, NULL), 4); sh_close(c); }
        WCHAR w[128]; MultiByteToWideChar(CP_ACP, 0, sh_hosts_ok[i], -1, w, 128);
        c = U(InternetConnectW)(s, w, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        CHECKF(c != NULL, "W host [%s] err %lu", sh_hosts_ok[i], GetLastError());
        if (c) sh_close(c);
    }
    sh_close(s);
}

TEST(sh_conn_http_long_hostname) {
    HINTERNET s = sh_open("lh"); CHECK(s != NULL); if (!s) return;
    static char host[600];
    memset(host, 'h', 599); host[599] = 0;
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(s, host, 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECKF(c != NULL, "InternetConnectA with a 599-char host: err %lu", GetLastError());
    if (c) {
        SetLastError(0);
        HINTERNET r = sh_request(c, "/", 0);
        t_note("HttpOpenRequest on it: h=%p err=%lu", r, r ? 0 : GetLastError());
        EXPECT_FAIL(r == NULL, ERROR_INSUFFICIENT_BUFFER);
        if (r) sh_close(r);
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ ports and the request URL */
typedef struct { INTERNET_PORT port; DWORD cflags; DWORD rflags; const char *url; } sh_port_row;
static const sh_port_row sh_port_tab[] = {
    { 0, 0, 0, "http://h.example/p" },
    { 80, 0, 0, "http://h.example/p" },
    { 8080, 0, 0, "http://h.example:8080/p" },
    { 1, 0, 0, "http://h.example:1/p" },
    { 65535, 0, 0, "http://h.example:65535/p" },
    { 443, 0, INTERNET_FLAG_SECURE, "https://h.example/p" },
    { 0, INTERNET_FLAG_SECURE, INTERNET_FLAG_SECURE, "https://h.example/p" },
    { 8443, 0, INTERNET_FLAG_SECURE, "https://h.example:8443/p" },
    { 80, 0, INTERNET_FLAG_SECURE, "https://h.example:80/p" },
    { 443, 0, 0, "http://h.example:443/p" },
    { 0, INTERNET_FLAG_SECURE, 0, "http://h.example:443/p" },
};
TEST(sh_conn_port_and_url_table) {
    REQUIRE(U(HttpOpenRequestA));
    HINTERNET s = sh_open("port"); CHECK(s != NULL); if (!s) return;
    for (size_t i = 0; i < sizeof sh_port_tab / sizeof *sh_port_tab; i++) {
        const sh_port_row *p = &sh_port_tab[i];
        HINTERNET c = U(InternetConnectA)(s, "h.example", p->port, NULL, NULL, INTERNET_SERVICE_HTTP, p->cflags, 0);
        CHECKF(c != NULL, "row %u port %u", (unsigned)i, p->port);
        if (!c) continue;
        HINTERNET r = U(HttpOpenRequestA)(c, "GET", "/p", NULL, NULL, NULL, p->rflags | INTERNET_FLAG_NO_UI, 0);
        CHECKF(r != NULL, "row %u request err %lu", (unsigned)i, GetLastError());
        if (r) {
            char url[256]; DWORD len, e;
            CHECK(sh_qstr(r, INTERNET_OPTION_URL, url, sizeof url, &len, &e));
            CHECKF(!strcmp(url, p->url), "row %u: url [%s] want [%s]", (unsigned)i, url, p->url);
            EXPECT_EQ(len, strlen(url));
            sh_close(r);
        }
        sh_close(c);
    }
    sh_close(s);
}

/* ------------------------------------------------------------------ credentials */
TEST(sh_conn_credentials_roundtrip_a) {
    HINTERNET s = sh_open("cred"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, "alice", "pw-123", INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    if (c) {
        char b[64]; DWORD len, e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "alice"); EXPECT_EQ(len, 5);
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "pw-123"); EXPECT_EQ(len, 6);
        /* size queries */
        len = 0; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(c, INTERNET_OPTION_USERNAME, NULL, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 6);
        len = 3; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(c, INTERNET_OPTION_PASSWORD, b, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 7);
        /* proxy credentials are separate and empty */
        CHECK(sh_qstr(c, INTERNET_OPTION_PROXY_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        CHECK(sh_qstr(c, INTERNET_OPTION_PROXY_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        sh_close(c);
    }
    sh_close(s);
}

TEST(sh_conn_credentials_roundtrip_w) {
    HINTERNET s = sh_open("credw"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = U(InternetConnectW)(s, L"127.0.0.1", 80, L"bob", L"secret9", INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(c != NULL);
    if (c) {
        WCHAR w[64]; DWORD len, e;
        CHECK(sh_qstrw(c, INTERNET_OPTION_USERNAME, w, sizeof w, &len, &e)); EXPECT_WSTR(w, L"bob"); EXPECT_EQ(len, 3);
        CHECK(sh_qstrw(c, INTERNET_OPTION_PASSWORD, w, sizeof w, &len, &e)); EXPECT_WSTR(w, L"secret9"); EXPECT_EQ(len, 7);
        len = 0; SetLastError(0);
        CHECK(!U(InternetQueryOptionW)(c, INTERNET_OPTION_USERNAME, NULL, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 8);
        char b[64];
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "bob");
        sh_close(c);
    }
    sh_close(s);
}

TEST(sh_conn_credentials_none_and_empty) {
    HINTERNET s = sh_open("cr0"); CHECK(s != NULL); if (!s) return;
    const char *users[] = { NULL, "" }, *pws[] = { NULL, "" };
    for (int i = 0; i < 2; i++) for (int j = 0; j < 2; j++) {
        HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, users[i], pws[j], INTERNET_SERVICE_HTTP, 0, 0);
        CHECK(c != NULL); if (!c) continue;
        char b[16]; DWORD len, e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, ""); EXPECT_EQ(len, 0);
        sh_close(c);
    }
    sh_close(s);
}

TEST(sh_conn_credentials_inherited_by_request) {
    HINTERNET s = sh_open("cri"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, "carol", "pw", INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        char b[32]; DWORD len, e;
        CHECK(sh_qstr(r, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "carol");
        CHECK(sh_qstr(r, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "pw");
        /* set on the request does not change the connect */
        char nu[] = "dave";
        CHECK(sh_set(r, INTERNET_OPTION_USERNAME, nu, sizeof nu, &e));
        CHECK(sh_qstr(r, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "dave");
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "carol");
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_conn_credentials_set_on_connect) {
    HINTERNET s = sh_open("crs"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0); CHECK(c != NULL);
    if (c) {
        char u[] = "erin", p[] = "pass-e", b[32]; DWORD len, e;
        CHECK(sh_set(c, INTERNET_OPTION_USERNAME, u, sizeof u, &e));
        CHECK(sh_set(c, INTERNET_OPTION_PASSWORD, p, sizeof p, &e));
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "erin");
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "pass-e");
        char pu[] = "proxyuser", pp[] = "proxypw";
        CHECK(sh_set(c, INTERNET_OPTION_PROXY_USERNAME, pu, sizeof pu, &e));
        CHECK(sh_set(c, INTERNET_OPTION_PROXY_PASSWORD, pp, sizeof pp, &e));
        CHECK(sh_qstr(c, INTERNET_OPTION_PROXY_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "proxyuser");
        CHECK(sh_qstr(c, INTERNET_OPTION_PROXY_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "proxypw");
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "erin");
        /* a request created afterwards sees them */
        HINTERNET r = sh_request(c, "/", 0);
        if (r) {
            CHECK(sh_qstr(r, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "erin");
            CHECK(sh_qstr(r, INTERNET_OPTION_PROXY_USERNAME, b, sizeof b, &len, &e));
            t_note("request PROXY_USERNAME after connect set: [%s]", b);
            sh_close(r);
        }
        sh_close(c);
    }
    sh_close(s);
}

TEST(sh_conn_credentials_on_session_12018) {
    HINTERNET s = sh_open("crs"); CHECK(s != NULL); if (!s) return;
    const DWORD opts[] = { INTERNET_OPTION_USERNAME, INTERNET_OPTION_PASSWORD, INTERNET_OPTION_PROXY_USERNAME, INTERNET_OPTION_PROXY_PASSWORD };
    for (int i = 0; i < 4; i++) {
        char b[32]; DWORD len, e;
        CHECK(!sh_qstr(s, opts[i], b, sizeof b, &len, &e));
        CHECKF(e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "query option %lu on session: err %lu", opts[i], e);
        char v[] = "x";
        CHECK(!sh_set(s, opts[i], v, sizeof v, &e));
        CHECKF(e == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "set option %lu on session: err %lu", opts[i], e);
    }
    sh_close(s);
}

/* the credentials are sent as Basic after a 401 challenge */
TEST(sh_conn_credentials_used_for_basic) {
    REQUIRE(U(HttpSendRequestA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(401, "WWW-Authenticate: Basic realm=\"r\"\r\n", "no"),
                                   S_HEAD(), S_REPLY(200, NULL, "yes"), S_LOOP_TO(2) };
    static const srv_script sc[] = { SRV_SCRIPT(st) };
    srv_config cfg = { SRV_HTTP, sc, 1 }; srv *s;
    SH_START_OR_SKIP(&cfg, &s);
    HINTERNET h = sh_open_to("basic");
    HINTERNET c = h ? U(InternetConnectA)(h, "127.0.0.1", srv_port(s), "user1", "pw1", INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/auth", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        BOOL ok = U(HttpSendRequestA)(r, NULL, 0, NULL, 0);
        CHECKF(ok, "send err %lu", GetLastError());
        DWORD st = 0, l = sizeof st;
        U(HttpQueryInfoA)(r, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &st, &l, NULL);
        EXPECT_EQ(st, 200);
        if (srv_wait_requests(s, 2, 3000)) {
            CHECK(srv_req_header(s, 0, "Authorization") == NULL);
            EXPECT_STR(srv_req_header(s, 1, "Authorization"), "Basic dXNlcjE6cHcx");
        } else CHECK(!"server saw fewer than 2 requests");
        sh_close(r);
    }
    if (c) sh_close(c);
    if (h) sh_close(h);
    srv_stop(s);
}

/* ------------------------------------------------------------------ context values */
TEST(sh_conn_context_value_from_param) {
    HINTERNET s = sh_open("ctx"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, (DWORD_PTR)0x1122334455667788ull);
    CHECK(c != NULL);
    HINTERNET r = c ? sh_request(c, "/", (DWORD_PTR)0xabcdef) : NULL;
    CHECK(r != NULL);
    ULONG_PTR v; DWORD len, e;
    if (c) { CHECK(sh_qptr(c, INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e)); EXPECT_EQ(v, (ULONG_PTR)0x1122334455667788ull); EXPECT_EQ(len, 8); }
    if (r) { CHECK(sh_qptr(r, INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e)); EXPECT_EQ(v, 0xabcdef); }
    /* the session context is unaffected */
    CHECK(sh_qptr(s, INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e)); EXPECT_EQ(v, 0);
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_conn_context_value_set_query) {
    HINTERNET s = sh_open("ctx2"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 5);
    HINTERNET r = c ? sh_request(c, "/", 6) : NULL;
    HINTERNET hs[3] = { s, c, r };
    for (int i = 0; i < 3; i++) {
        if (!hs[i]) { CHECK(hs[i] != NULL); continue; }
        DWORD_PTR nv = (DWORD_PTR)(0x5000 + i); DWORD e;
        CHECK(sh_set(hs[i], INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv, &e));
        ULONG_PTR v; DWORD len;
        CHECK(sh_qptr(hs[i], INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e)); EXPECT_EQ(v, 0x5000 + i);
        /* wrong length -> 12010 */
        DWORD four = 7;
        CHECK(!sh_set(hs[i], INTERNET_OPTION_CONTEXT_VALUE, &four, 4, &e)); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
        BYTE big[16] = { 0 };
        CHECK(!sh_set(hs[i], INTERNET_OPTION_CONTEXT_VALUE, big, 16, &e)); EXPECT_EQ(e, ERROR_INTERNET_BAD_OPTION_LENGTH);
        CHECK(sh_qptr(hs[i], INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e)); EXPECT_EQ(v, 0x5000 + i);
        /* short query buffer -> 122, len 8 */
        DWORD small = 0; len = 4; SetLastError(0);
        CHECK(!U(InternetQueryOptionA)(hs[i], INTERNET_OPTION_CONTEXT_VALUE, &small, &len));
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, 8);
    }
    /* children do not inherit a context set on the parent later */
    HINTERNET r2 = c ? sh_request(c, "/2", 0) : NULL;
    if (r2) { ULONG_PTR v; DWORD len, e; CHECK(sh_qptr(r2, INTERNET_OPTION_CONTEXT_VALUE, &v, &len, &e)); EXPECT_EQ(v, 0); sh_close(r2); }
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

/* ------------------------------------------------------------------ connect flags */
static const DWORD sh_conn_flags_tab[] = { 0, INTERNET_FLAG_PASSIVE, INTERNET_FLAG_ASYNC, INTERNET_FLAG_SECURE,
    INTERNET_FLAG_KEEP_CONNECTION, INTERNET_FLAG_EXISTING_CONNECT, 0xffffffffu };
TEST(sh_conn_http_flags_accepted) {
    HINTERNET s = sh_open("fl"); CHECK(s != NULL); if (!s) return;
    for (size_t i = 0; i < sizeof sh_conn_flags_tab / sizeof *sh_conn_flags_tab; i++) {
        SetLastError(0xdeadbeef);
        HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, sh_conn_flags_tab[i], 0);
        CHECKF(c != NULL, "flags 0x%lx err %lu", sh_conn_flags_tab[i], GetLastError());
        if (c) { EXPECT_EQ(sh_htype(c, NULL), 4); sh_close(c); }
    }
    sh_close(s);
}

TEST(sh_conn_many_under_one_session) {
    HINTERNET s = sh_open("many"); CHECK(s != NULL); if (!s) return;
    enum { N = 50 };
    HINTERNET c[N]; int ok = 0, parent_ok = 0;
    for (int i = 0; i < N; i++) {
        c[i] = sh_connect(s, "127.0.0.1", (INTERNET_PORT)(1000 + i), (DWORD_PTR)i + 1);
        if (c[i]) { ok++; if (sh_parent(c[i], NULL) == s) parent_ok++; }
    }
    EXPECT_EQ(ok, N); EXPECT_EQ(parent_ok, N);
    int ctx_ok = 0;
    for (int i = 0; i < N; i++) { ULONG_PTR v; if (c[i] && sh_qptr(c[i], INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL) && v == (ULONG_PTR)i + 1) ctx_ok++; }
    EXPECT_EQ(ctx_ok, N);
    for (int i = 0; i < N; i++) if (c[i]) sh_close(c[i]);
    sh_close(s);
}

/* ------------------------------------------------------------------ request handles */
TEST(sh_conn_request_type_and_parent) {
    HINTERNET s = sh_open("rq"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/x", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        DWORD e;
        EXPECT_EQ(sh_htype(r, &e), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        EXPECT_EQ(sh_parent(r, &e), c);
        EXPECT_EQ(sh_parent(sh_parent(r, NULL), NULL), s);
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_conn_request_on_wrong_parent) {
    HINTERNET s = sh_open("rq2"); CHECK(s != NULL); if (!s) return;
    SetLastError(0);
    HINTERNET r = U(HttpOpenRequestA)(s, "GET", "/", NULL, NULL, NULL, 0, 0);
    EXPECT_FAIL(r == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    if (r) sh_close(r);
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r1 = c ? sh_request(c, "/", 0) : NULL;
    if (r1) {
        SetLastError(0);
        r = U(HttpOpenRequestA)(r1, "GET", "/", NULL, NULL, NULL, 0, 0);
        EXPECT_FAIL(r == NULL, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        if (r) sh_close(r);
        sh_close(r1);
    }
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_conn_request_flags_option_unsent) {
    HINTERNET s = sh_open("rf"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    CHECK(r != NULL);
    DWORD v, len, e;
    CHECK(!sh_qdw(s, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    if (c) { CHECK(!sh_qdw(c, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (r) {
        CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(len, 4);
        EXPECT_EQ(v, INTERNET_REQFLAG_NO_HEADERS);     /* 8: no response headers yet */
        sh_close(r);
    }
    if (c) sh_close(c);
    sh_close(s);
}

/* after a network response REQUEST_FLAGS has no FROM_CACHE bit */
TEST(sh_conn_request_flags_after_network_get) {
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("rf2");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/rf", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        CHECK(U(HttpSendRequestA)(r, NULL, 0, NULL, 0));
        DWORD v, len, e;
        CHECK(sh_qdw(r, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e));
        t_note("REQUEST_FLAGS after a network GET: 0x%lx", v);
        EXPECT_EQ(v & INTERNET_REQFLAG_FROM_CACHE, 0);
        EXPECT_EQ(v & INTERNET_REQFLAG_NO_HEADERS, 0);
        EXPECT_EQ(v, INTERNET_REQFLAG_CACHE_WRITE_DISABLED);   /* request was opened with NO_CACHE_WRITE (T_INET_FRESH) */
        sh_close(r);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}

TEST(sh_conn_keep_connection_option) {
    HINTERNET s = sh_open("kc"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    DWORD v, len, e;
    CHECK(!sh_qdw(s, INTERNET_OPTION_KEEP_CONNECTION, &v, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    if (c) { CHECK(sh_qdw(c, INTERNET_OPTION_KEEP_CONNECTION, &v, &len, &e)); EXPECT_EQ(len, 4); t_note("KEEP_CONNECTION on HCon = %lu", v); }
    if (r) { CHECK(!sh_qdw(r, INTERNET_OPTION_KEEP_CONNECTION, &v, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (c) { CHECK(!sh_setdw(c, INTERNET_OPTION_KEEP_CONNECTION, 1, &e)); EXPECT_EQ(e, ERROR_INTERNET_OPTION_NOT_SETTABLE); }
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

/* ------------------------------------------------------------------ InternetOpenUrl handles */
TEST(sh_conn_openurl_http_handle_tree) {
    REQUIRE(U(InternetOpenUrlA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("ou");
    HINTERNET u = s ? U(InternetOpenUrlA)(s, srv_url(sv, "/ou"), NULL, 0, T_INET_FRESH, 0) : NULL;
    CHECKF(u != NULL, "InternetOpenUrl err %lu", GetLastError());
    if (u) {
        EXPECT_EQ(sh_htype(u, NULL), INTERNET_HANDLE_TYPE_HTTP_REQUEST);
        HINTERNET p = sh_parent(u, NULL);
        CHECK(p != NULL && p != s);
        EXPECT_EQ(sh_htype(p, NULL), INTERNET_HANDLE_TYPE_CONNECT_HTTP);
        EXPECT_EQ(sh_parent(p, NULL), s);
        char url[256]; DWORD len, e;
        CHECK(sh_qstr(u, INTERNET_OPTION_URL, url, sizeof url, &len, &e));
        EXPECT_STR(url, srv_url(sv, "/ou"));
        CHECK(sh_close(u));
        /* the implicit connect handle goes away with the request */
        DWORD e2; sh_htype(p, &e2);
        EXPECT_EQ(e2, ERROR_INVALID_HANDLE);
    }
    if (s) sh_close(s);
    srv_stop(sv);
}

TEST(sh_conn_openurl_file_handle) {
    REQUIRE(U(InternetOpenUrlA));
    char path[MAX_PATH]; t_tmpfile(path, sizeof path, "sh_file.txt");
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { t_skip("cannot create temp file"); return; }
    DWORD wr; WriteFile(f, "filedata", 8, &wr, NULL); CloseHandle(f);
    char lp[MAX_PATH]; if (!GetLongPathNameA(path, lp, sizeof lp)) strcpy(lp, path);
    char cand[3][MAX_PATH + 16];
    snprintf(cand[0], sizeof cand[0], "file:///"); snprintf(cand[1], sizeof cand[1], "file://%s", lp); snprintf(cand[2], sizeof cand[2], "file:///%s", lp);
    for (char *p = lp, *q = cand[0] + 8; ; p++, q++) { *q = *p == '\\' ? '/' : *p; if (!*p) break; }
    HINTERNET s = sh_open("fu"); CHECK(s != NULL); if (!s) return;
    /* Win10: "file:///C:/dir/x" (forward slashes) fails with 3 ERROR_PATH_NOT_FOUND; "file://C:\\dir\\x" opens */
    SetLastError(0);
    HINTERNET u0 = U(InternetOpenUrlA)(s, cand[0], NULL, 0, 0, 0);
    t_note("InternetOpenUrl(%s): h=%p err=%lu", cand[0], u0, u0 ? 0 : GetLastError());
    EXPECT_FAIL(u0 == NULL, ERROR_PATH_NOT_FOUND);
    if (u0) sh_close(u0);
    HINTERNET u2 = U(InternetOpenUrlA)(s, cand[2], NULL, 0, 0, 0);
    t_note("InternetOpenUrl(%s): h=%p err=%lu", cand[2], u2, u2 ? 0 : GetLastError());
    if (u2) sh_close(u2);
    HINTERNET u = U(InternetOpenUrlA)(s, cand[1], NULL, 0, 0, 0);
    CHECKF(u != NULL, "InternetOpenUrl(%s) err %lu", cand[1], GetLastError());
    if (u) {
        EXPECT_EQ(sh_htype(u, NULL), INTERNET_HANDLE_TYPE_FILE_REQUEST);
        char b[32]; int ok; size_t n = t_inet_read_all(u, b, sizeof b, &ok);
        CHECK(ok); EXPECT_EQ(n, 8); EXPECT_STR(b, "filedata");
        EXPECT_EQ(sh_parent(u, NULL), s);     /* no hidden connect handle for file: */
        DWORD v, len, e;
        CHECK(!sh_qdw(u, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        char un[16];
        CHECK(!sh_qstr(u, INTERNET_OPTION_USERNAME, un, sizeof un, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        CHECK(sh_close(u));
    }
    sh_close(s);
    DeleteFileA(path);
}

/* ------------------------------------------------------------------ FTP handles */
TEST(sh_conn_ftp_connect_basic) {
    REQUIRE(U(InternetConnectA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftp");
    SetLastError(0xdeadbeef);
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 7) : NULL;
    CHECKF(c != NULL, "ftp connect err %lu", GetLastError());
    if (c) {
        EXPECT_EQ(GetLastError(), 0);
        EXPECT_EQ(sh_htype(c, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        EXPECT_EQ(sh_parent(c, NULL), s);
        ULONG_PTR v; CHECK(sh_qptr(c, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 7);
        char b[64]; DWORD len, e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e));
        t_note("FTP connect without credentials: USERNAME=[%s]", b);
        DWORD dv;
        CHECK(!sh_qdw(c, INTERNET_OPTION_KEEP_CONNECTION, &dv, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        CHECK(!sh_qdw(c, INTERNET_OPTION_HTTP_DECODING, &dv, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        CHECK(sh_qdw(c, INTERNET_OPTION_READ_BUFFER_SIZE, &dv, &len, &e));
        sh_close(c);
        if (srv_wait_events(f, SRV_EV_FTP_CMD, 2, 3000)) {
            EXPECT_STR(srv_ftp_cmd(f, 0), "USER anonymous");
        } else CHECK(!"no FTP login seen");
    }
    if (s) sh_close(s);
    srv_stop(f);
}

TEST(sh_conn_ftp_credentials_sent) {
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftpc");
    HINTERNET c = s ? U(InternetConnectW)(s, L"127.0.0.1", srv_port(f), L"ftpuser", L"dummy", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    CHECKF(c != NULL, "ftp connect err %lu", GetLastError());
    if (c) {
        char b[64]; DWORD len, e;
        CHECK(sh_qstr(c, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e)); EXPECT_STR(b, "ftpuser");
        CHECK(sh_qstr(c, INTERNET_OPTION_PASSWORD, b, sizeof b, &len, &e)); EXPECT_STR(b, "dummy");
        sh_close(c);
        if (srv_wait_events(f, SRV_EV_FTP_CMD, 2, 3000)) {
            EXPECT_STR(srv_ftp_cmd(f, 0), "USER ftpuser");
            EXPECT_STR(srv_ftp_cmd(f, 1), "PASS ***");
        } else CHECK(!"no FTP login seen");
    }
    if (s) sh_close(s);
    srv_stop(f);
}

TEST(sh_conn_ftp_no_listener_12029) {
    unsigned short port = sh_dead_port();
    if (!port) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("ftpdead"); CHECK(s != NULL); if (!s) return;
    SetLastError(0);
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(c == NULL, ERROR_INTERNET_CANNOT_CONNECT);
    if (c) sh_close(c);
    /* an HTTP connect to the same dead port still succeeds: no I/O */
    c = sh_connect(s, "127.0.0.1", port, 0);
    CHECK(c != NULL); if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_conn_ftp_find_and_file_handles) {
    REQUIRE(U(FtpFindFirstFileA)); REQUIRE(U(FtpOpenFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftph");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    CHECK(c != NULL);
    if (c) {
        WIN32_FIND_DATAA fd;
        HINTERNET fh = U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 0x77);
        CHECKF(fh != NULL, "find err %lu", GetLastError());
        if (fh) {
            EXPECT_EQ(sh_htype(fh, NULL), INTERNET_HANDLE_TYPE_FTP_FIND);
            EXPECT_EQ(sh_parent(fh, NULL), c);
            ULONG_PTR v; CHECK(sh_qptr(fh, INTERNET_OPTION_CONTEXT_VALUE, &v, NULL, NULL)); EXPECT_EQ(v, 0x77);
            DWORD dv, len, e;
            CHECK(!sh_qdw(fh, INTERNET_OPTION_KEEP_CONNECTION, &dv, &len, &e)); EXPECT_EQ(e, ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
            CHECK(sh_qdw(fh, INTERNET_OPTION_REQUEST_FLAGS, &dv, &len, &e)); t_note("FTP find REQUEST_FLAGS 0x%lx", dv);
            char b[64];
            CHECK(sh_qstr(fh, INTERNET_OPTION_USERNAME, b, sizeof b, &len, &e));
            /* only one FTP data transfer per connect: a second find on the busy connect fails */
            WIN32_FIND_DATAA fd2;
            SetLastError(0);
            HINTERNET fh2 = U(FtpFindFirstFileA)(c, "*", &fd2, INTERNET_FLAG_RELOAD, 0);
            EXPECT_FAIL(fh2 == NULL, ERROR_FTP_TRANSFER_IN_PROGRESS);
            if (fh2) sh_close(fh2);
            CHECK(sh_close(fh));
        }
        HINTERNET fo = U(FtpOpenFileA)(c, "hello.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0x88);
        CHECKF(fo != NULL, "FtpOpenFile err %lu", GetLastError());
        if (fo) {
            EXPECT_EQ(sh_htype(fo, NULL), INTERNET_HANDLE_TYPE_FTP_FILE);
            EXPECT_EQ(sh_parent(fo, NULL), c);
            char b[16]; int ok; size_t n = t_inet_read_all(fo, b, sizeof b, &ok);
            EXPECT_EQ(n, 5); EXPECT_STR(b, "hello");
            char url[128]; DWORD len, e;
            CHECK(sh_qstr(fo, INTERNET_OPTION_URL, url, sizeof url, &len, &e));
            t_note("FTP file URL option: [%s]", url);
            CHECK(sh_close(fo));
        }
        sh_close(c);
    }
    if (s) sh_close(s);
    srv_stop(f);
}

TEST(sh_conn_openurl_ftp_handle) {
    REQUIRE(U(InternetOpenUrlA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftpu");
    HINTERNET u = s ? U(InternetOpenUrlA)(s, srv_url(f, "/data.bin"), NULL, 0, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_RELOAD, 0) : NULL;
    CHECKF(u != NULL, "InternetOpenUrl ftp err %lu", GetLastError());
    if (u) {
        DWORD t = sh_htype(u, NULL);
        CHECKF(t == INTERNET_HANDLE_TYPE_FTP_FILE || t == INTERNET_HANDLE_TYPE_FTP_FILE_HTML, "type %lu", t);
        t_note("InternetOpenUrl(ftp file) handle type %lu", t);
        HINTERNET p = sh_parent(u, NULL);
        EXPECT_EQ(sh_htype(p, NULL), INTERNET_HANDLE_TYPE_CONNECT_FTP);
        EXPECT_EQ(sh_parent(p, NULL), s);
        char b[32]; int ok; size_t n = t_inet_read_all(u, b, sizeof b, &ok);
        EXPECT_EQ(n, 10); EXPECT_STR(b, "0123456789");
        CHECK(sh_close(u));
    }
    if (s) sh_close(s);
    srv_stop(f);
}
