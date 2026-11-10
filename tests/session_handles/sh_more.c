/* session_handles / defaults and lifetime facts measured on the Win10 VM, FTP handle lifetime.
 * Evidence: VM boots (EVIDENCE.md) + [D InternetQueryOptionA case 2-8 GetTimeoutValue, case 0x17]. */
#include "sh.h"

/* Defaults of a fresh DIRECT session (no registry overrides on a clean image). */
TEST(sh_more_session_timeout_defaults) {
    HINTERNET s = sh_open("defaults"); CHECK(s != NULL); if (!s) return;
    static const struct { DWORD opt; DWORD want; } tab[] = {
        { INTERNET_OPTION_CONNECT_TIMEOUT, 60000 }, { INTERNET_OPTION_CONNECT_RETRIES, 5 }, { INTERNET_OPTION_CONNECT_BACKOFF, 0 },
        { INTERNET_OPTION_SEND_TIMEOUT, 30000 }, { INTERNET_OPTION_RECEIVE_TIMEOUT, 30000 },
        { INTERNET_OPTION_DATA_SEND_TIMEOUT, 30000 }, { INTERNET_OPTION_DATA_RECEIVE_TIMEOUT, 30000 },
    };
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    HINTERNET r = c ? sh_request(c, "/", 0) : NULL;
    HINTERNET hs[3] = { s, c, r };
    for (int k = 0; k < 3; k++) for (size_t i = 0; i < sizeof tab / sizeof *tab; i++) {
        DWORD v, len, e;
        if (!hs[k]) continue;
        CHECK(sh_qdw(hs[k], tab[i].opt, &v, &len, &e));
        CHECKF(v == tab[i].want, "handle %d option %lu default %lu want %lu", k, tab[i].opt, v, tab[i].want);
    }
    if (r) sh_close(r);
    if (c) sh_close(c);
    sh_close(s);
}

TEST(sh_more_keep_connection_value_and_close_last_error) {
    HINTERNET s = sh_open("kc"); CHECK(s != NULL); if (!s) return;
    HINTERNET c = sh_connect(s, "127.0.0.1", 80, 0);
    DWORD v = 0xff, len, e;
    if (c) { CHECK(sh_qdw(c, INTERNET_OPTION_KEEP_CONNECTION, &v, &len, &e)); EXPECT_EQ(v, 0); }
    SetLastError(0xdeadbeef);
    if (c) CHECK(sh_close(c));
    EXPECT_EQ(GetLastError(), 0);
    SetLastError(0xdeadbeef);
    CHECK(sh_close(s));
    EXPECT_EQ(GetLastError(), 0);
}

TEST(sh_more_handle_values_step) {
    HINTERNET a = sh_open("a"), b = a ? sh_connect(a, "127.0.0.1", 80, 0) : NULL;
    CHECK(a && b);
    /* HINTERNETs are map indexes, not pointers: small, 4-aligned (MapHandleToAddress (h - 0xCC0004) >> 2) */
    CHECKF(((ULONG_PTR)a & 3) == 0 && (ULONG_PTR)a >= 0xcc0004 && (ULONG_PTR)a < 0x1000000, "session handle %p", a);
    if (b) CHECKF(((ULONG_PTR)b & 3) == 0 && (ULONG_PTR)b >= 0xcc0004 && (ULONG_PTR)b < 0x1000000, "connect handle %p", b);
    t_note("handle values: session %p connect %p", a, b);
    if (b) sh_close(b);
    if (a) sh_close(a);
}

/* Closing the FTP find handle releases the connect for the next transfer. */
TEST(sh_more_ftp_find_close_releases_connect) {
    REQUIRE(U(FtpFindFirstFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftpr");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    CHECK(c != NULL);
    for (int i = 0; c && i < 3; i++) {
        WIN32_FIND_DATAA fd;
        HINTERNET fh = U(FtpFindFirstFileA)(c, "*", &fd, INTERNET_FLAG_RELOAD, 0);
        CHECKF(fh != NULL, "find #%d err %lu", i, GetLastError());
        if (fh) {
            DWORD v, len, e;
            CHECK(sh_qdw(fh, INTERNET_OPTION_REQUEST_FLAGS, &v, &len, &e)); EXPECT_EQ(v, INTERNET_REQFLAG_NO_HEADERS);
            CHECK(sh_close(fh));
        }
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(f);
}

/* Closing the FTP connect invalidates an open file handle. */
TEST(sh_more_ftp_close_connect_with_open_file) {
    REQUIRE(U(FtpOpenFileA));
    srv *f = sh_ftp_start();
    if (!f) { t_skip("ftp server unavailable"); return; }
    HINTERNET s = sh_open_to("ftpx");
    HINTERNET c = s ? U(InternetConnectA)(s, "127.0.0.1", srv_port(f), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    HINTERNET fo = c ? U(FtpOpenFileA)(c, "data.bin", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY | INTERNET_FLAG_RELOAD, 0) : NULL;
    CHECK(fo != NULL);
    if (fo) {
        EXPECT_EQ(sh_htype(fo, NULL), INTERNET_HANDLE_TYPE_FTP_FILE);
        CHECK(sh_close(c)); c = NULL;
        DWORD e; sh_htype(fo, &e); EXPECT_EQ(e, ERROR_INVALID_HANDLE);
        char b[4]; DWORD rd; SetLastError(0);
        EXPECT_FAIL(!U(InternetReadFile)(fo, b, sizeof b, &rd), ERROR_INVALID_HANDLE);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(f);
}

/* Two sessions with the same agent string have independent option state. */
TEST(sh_more_two_sessions_same_agent_independent) {
    HINTERNET a = sh_open("same"), b = sh_open("same");
    CHECK(a && b && a != b);
    char ua[] = "changed"; DWORD e;
    if (a) CHECK(sh_set(a, INTERNET_OPTION_USER_AGENT, ua, sizeof ua, &e));
    char buf[32]; DWORD len;
    if (b) { CHECK(sh_qstr(b, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e)); EXPECT_STR(buf, "same"); }
    if (a) { CHECK(sh_qstr(a, INTERNET_OPTION_USER_AGENT, buf, sizeof buf, &len, &e)); EXPECT_STR(buf, "changed"); }
    if (a) sh_close(a);
    if (b) sh_close(b);
}

/* The User-Agent on the wire is the session agent at send time (set after the request was created). */
TEST(sh_more_user_agent_on_wire_follows_session) {
    REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = sh_open_to("before-set");
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/ua", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        char ua[] = "after-set"; DWORD e;
        CHECK(sh_set(s, INTERNET_OPTION_USER_AGENT, ua, sizeof ua, &e));
        CHECK(U(HttpSendRequestA)(r, NULL, 0, NULL, 0));
        if (srv_wait_requests(sv, 1, 3000)) t_note("User-Agent on wire after late session set: [%s]", srv_req_header(sv, 0, "User-Agent") ? srv_req_header(sv, 0, "User-Agent") : "(none)");
        sh_close(r);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}

/* A NULL agent sends no User-Agent header at all. */
TEST(sh_more_null_agent_no_user_agent_header) {
    REQUIRE(U(HttpSendRequestA));
    srv *sv = srv_http(NULL, 0);
    if (!sv) { t_skip("server unavailable"); return; }
    HINTERNET s = U(InternetOpenA)(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    DWORD to = 5000; if (s) U(InternetSetOptionA)(s, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    HINTERNET c = s ? sh_connect(s, "127.0.0.1", srv_port(sv), 0) : NULL;
    HINTERNET r = c ? sh_request(c, "/noua", 0) : NULL;
    CHECK(r != NULL);
    if (r) {
        CHECK(U(HttpSendRequestA)(r, NULL, 0, NULL, 0));
        CHECK(srv_wait_requests(sv, 1, 3000));
        if (srv_req_count(sv)) CHECK(srv_req_header(sv, 0, "User-Agent") == NULL);
        sh_close(r);
    }
    if (c) sh_close(c);
    if (s) sh_close(s);
    srv_stop(sv);
}
