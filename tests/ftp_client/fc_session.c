/* fc_session.c - InternetConnect(INTERNET_SERVICE_FTP): login sequence on the wire, user/password defaults,
 * login failures (12013/12014/12015), banners, offline connect handles, connect handle properties, timeouts.
 * Decomp: FtpConnect, GetEmailNameAndPassword, wFtpMakeConnection, ReceiveFtpResponse, I_Command, wFtpDisconnect. */
#include "ftp.h"

/* ------------------------------------------------------------------ login sequence */
TEST(ftpc_conn_anonymous_wire) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_open(&x, NULL)) return;
    Sleep(150);   /* absence check: nothing but USER/PASS is sent by InternetConnect */
    EXPECT_EQ(fc_ncmd(&x), 2);
    EXPECT_STR(fc_cmd(&x, 0), "USER anonymous");
    EXPECT_STR(fc_cmd(&x, 1), "PASS ***");
    CHECK(fc_find(&x, "SYST", 0) < 0);
    CHECK(fc_find(&x, "FEAT", 0) < 0);
    CHECK(fc_find(&x, "OPTS", 0) < 0);
    CHECK(fc_find(&x, "PWD", 0) < 0);
    EXPECT_EQ(srv_conn_count(x.s), 1);
    fc_end(&x);
}

TEST(ftpc_conn_anonymous_password_is_email) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.record_pass = 1;
    fcx x; if (!fc_open(&x, &c)) return;
    const char *p = fc_cmd(&x, 1);
    CHECKF(!strncmp(p, "PASS ", 5) && strlen(p) > 5, "got %s", p);
    t_note("anonymous password sent: %s", p);
    fc_end(&x);
}

TEST(ftpc_conn_user_pass_wire) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.record_pass = 1;
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0xdead);
    HINTERNET hc = fc_connect(&x, "alice", "secret", INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_seq(&x, 0), "USER alice|PASS secret");
    fc_end(&x);
}

TEST(ftpc_conn_user_null_password_sends_empty_pass) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.record_pass = 1;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET hc = fc_connect(&x, "bob", NULL, INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_cmd(&x, 0), "USER bob");
    EXPECT_STR(fc_cmd(&x, 1), "PASS ");
    fc_end(&x);
}

TEST(ftpc_conn_user_empty_password_sends_empty_pass) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.record_pass = 1;
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET hc = fc_connect(&x, "bob", "", INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_seq(&x, 0), "USER bob|PASS ");
    fc_end(&x);
}

TEST(ftpc_conn_empty_user_and_password_is_anonymous) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hc = fc_connect(&x, "", "", INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_cmd(&x, 0), "USER anonymous");
    fc_end(&x);
}

TEST(ftpc_conn_password_without_user_is_87) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_start(&x, NULL)) return;
    static const char *users[] = { NULL, "" };
    for (int i = 0; i < 2; i++) {
        SetLastError(0);
        HINTERNET hc = fc_connect(&x, users[i], "pw", INTERNET_FLAG_PASSIVE);
        EXPECT_FAIL(hc == NULL, ERROR_INVALID_PARAMETER);
        if (hc) U(InternetCloseHandle)(hc);
        x.hc = NULL;
    }
    Sleep(100);
    EXPECT_EQ(srv_conn_count(x.s), 0);   /* validation happens before any connect */
    fc_end(&x);
}

TEST(ftpc_conn_null_or_empty_server_is_87) {
    REQUIRE(U(InternetConnectA));
    HINTERNET hi = t_inet_open("ftpc");
    if (!hi) { t_skip("InternetOpen failed"); return; }
    SetLastError(0);
    HINTERNET hc = U(InternetConnectA)(hi, NULL, 21, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(hc == NULL, ERROR_INVALID_PARAMETER);
    SetLastError(0);
    hc = U(InternetConnectA)(hi, "", 21, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(hc == NULL, ERROR_INVALID_PARAMETER);
    U(InternetCloseHandle)(hi);
}

TEST(ftpc_conn_wide_api) {
    REQUIRE(U(InternetConnectW)); REQUIRE(U(InternetOpenW));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hi = U(InternetOpenW)(L"ftpc", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(hi != NULL);
    HINTERNET hc = hi ? U(InternetConnectW)(hi, L"127.0.0.1", srv_port(x.s), L"wuser", L"wpass", INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0) : NULL;
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_seq(&x, 0), "USER wuser|PASS ***");
    if (hc) U(InternetCloseHandle)(hc);
    if (hi) U(InternetCloseHandle)(hi);
    fc_end(&x);
}

/* ------------------------------------------------------------------ connect handle properties */
TEST(ftpc_conn_handle_type_is_connect_ftp) {
    REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!fc_open(&x, NULL)) return;
    DWORD t = 0, l = sizeof t;
    CHECK(U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
    EXPECT_EQ(t, INTERNET_HANDLE_TYPE_CONNECT_FTP);
    EXPECT_EQ(l, 4);
    fc_end(&x);
}

TEST(ftpc_conn_parent_handle_is_session) {
    REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!fc_open(&x, NULL)) return;
    HINTERNET p = NULL; DWORD l = sizeof p;
    CHECK(U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_PARENT_HANDLE, &p, &l));
    EXPECT_EQ(p, x.hi);
    fc_end(&x);
}

TEST(ftpc_conn_username_password_options) {
    REQUIRE(U(InternetQueryOptionA));
    fcx x; if (!fc_start(&x, NULL)) return;
    if (!fc_connect(&x, "carol", "pw1", INTERNET_FLAG_PASSIVE)) { CHECKF(0, "connect %lu", GetLastError()); fc_end(&x); return; }
    char b[64] = ""; DWORD l = sizeof b;
    CHECK(U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_USERNAME, b, &l));
    EXPECT_STR(b, "carol");
    EXPECT_EQ(l, 5);
    char p[64] = ""; l = sizeof p;
    CHECK(U(InternetQueryOptionA)(x.hc, INTERNET_OPTION_PASSWORD, p, &l));
    EXPECT_STR(p, "pw1");
    fc_end(&x);
}

TEST(ftpc_conn_quit_sent_on_close) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_open(&x, NULL)) return;
    U(InternetCloseHandle)(x.hc); x.hc = NULL;
    CHECK(fc_wait_cmd(&x, "QUIT", 3000));
    EXPECT_STR(fc_seq(&x, 0), "USER anonymous|PASS ***|QUIT");
    fc_end(&x);
}

TEST(ftpc_conn_two_handles_two_control_connections) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c = FC_STD_CFG;
    fcx x; if (!fc_open(&x, &c)) return;
    HINTERNET hc2 = U(InternetConnectA)(x.hi, "127.0.0.1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    CHECKF(hc2 != NULL, "err=%lu", GetLastError());
    EXPECT_EQ(srv_conn_count(x.s), 2);
    EXPECT_EQ(fc_count(&x, "USER anonymous"), 2);
    /* both are usable independently */
    char d1[64] = "", d2[64] = ""; DWORD l1 = sizeof d1, l2 = sizeof d2;
    CHECK(U(FtpSetCurrentDirectoryA)(x.hc, "pub"));
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d1, &l1));
    CHECK(hc2 && U(FtpGetCurrentDirectoryA)(hc2, d2, &l2));
    EXPECT_STR(d1, "/pub");
    EXPECT_STR(d2, "/");
    if (hc2) U(InternetCloseHandle)(hc2);
    fc_end(&x);
}

TEST(ftpc_conn_existing_connect_flag) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET a = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_EXISTING_CONNECT);
    CHECKF(a != NULL, "err=%lu", GetLastError());
    HINTERNET b = U(InternetConnectA)(x.hi, "127.0.0.1", srv_port(x.s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_EXISTING_CONNECT, 0);
    CHECKF(b != NULL, "err=%lu", GetLastError());
    t_note("EXISTING_CONNECT: handles %p %p, control connections %d, commands %s", a, b, srv_conn_count(x.s), fc_seq(&x, 0));
    if (b) U(InternetCloseHandle)(b);
    fc_end(&x);
}

TEST(ftpc_conn_last_response_after_login) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    fcx x; if (!fc_open(&x, NULL)) return;
    DWORD e; const char *r = fc_resp(&e);
    t_note("last response after login: err=%lu text=[%s]", e, r);
    CHECKF(strstr(r, "230 User logged in.") != NULL, "resp=[%s]", r);
    fc_end(&x);
}

/* ------------------------------------------------------------------ banners */
TEST(ftpc_conn_banner_421_login_failure) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.banner = "421 Too many users, try later.";
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_LOGIN_FAILURE);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "421 Too many users") != NULL, "resp=[%s]", r);
    Sleep(100);
    EXPECT_EQ(fc_ncmd(&x), 0);    /* nothing is sent after a non-2xx greeting */
    fc_end(&x);
}

TEST(ftpc_conn_banner_120_login_failure) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c); c.banner = "120 Service ready in 5 minutes.";
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_LOGIN_FAILURE);
    fc_end(&x);
}

TEST(ftpc_conn_banner_multiline) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c);
    c.banner = "220-Welcome to the i7 test server\r\n220-second line\r\n 220 indented continuation\r\n220 ready";
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    EXPECT_STR(fc_seq(&x, 0), "USER anonymous|PASS ***");
    fc_end(&x);
}

TEST(ftpc_conn_banner_multiline_421_last_line) {
    REQUIRE(U(InternetConnectA));
    srv_ftp_config c; memset(&c, 0, sizeof c);
    c.banner = "421-Service not available\r\n421-closing control connection\r\n421 bye";
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_LOGIN_FAILURE);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "421-Service not available") && strstr(r, "421 bye"), "resp=[%s]", r);
    fc_end(&x);
}

/* ------------------------------------------------------------------ login replies */
TEST(ftpc_conn_user_230_skips_pass) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "USER", "230 Logged in, no password needed.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET hc = fc_connect(&x, "nopw", "ignored", INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    Sleep(100);
    EXPECT_STR(fc_seq(&x, 0), "USER nopw");
    fc_end(&x);
}

TEST(ftpc_conn_user_530_is_extended_error) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "USER", "530 User not allowed.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "mallory", "pw", INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    t_note("USER 530 -> %lu %s", err, t_inet_errname(err));
    EXPECT_EQ(err, ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "530 User not allowed.") != NULL, "resp=[%s]", r);
    Sleep(100);
    EXPECT_STR(fc_seq(&x, 0), "USER mallory");
    fc_end(&x);
}

TEST(ftpc_conn_user_1xx_incorrect_user_name) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "USER", "150 odd reply to USER", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_INCORRECT_USER_NAME);
    fc_end(&x);
}

TEST(ftpc_conn_pass_530_named_user_incorrect_password) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "PASS", "530 Login incorrect.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "alice", "wrong", INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_INCORRECT_PASSWORD);
    DWORD e; const char *r = fc_resp(&e);
    CHECKF(strstr(r, "530 Login incorrect.") != NULL, "resp=[%s]", r);
    Sleep(150);
    CHECK(fc_find(&x, "QUIT", 0) < 0);   /* a failed login drops the connection without QUIT */
    fc_end(&x);
}

TEST(ftpc_conn_pass_530_anonymous_login_failure) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "PASS", "530 Anonymous access denied.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_LOGIN_FAILURE);
    fc_end(&x);
}

TEST(ftpc_conn_pass_530_anonymous_any_case) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "PASS", "530 no.", 0 } };
    static const char *names[] = { "ANONYMOUS", "Anonymous", "anonymous" };
    for (int i = 0; i < 3; i++) {
        srv_ftp_config c = { NULL, 0, ov, NF(ov) };
        fcx x; if (!fc_start(&x, &c)) return;
        SetLastError(0);
        HINTERNET hc = fc_connect(&x, names[i], "me@x", INTERNET_FLAG_PASSIVE);
        CHECK(hc == NULL);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INTERNET_LOGIN_FAILURE, "%s -> %lu", names[i], e);
        fc_end(&x);
    }
}

TEST(ftpc_conn_pass_332_account_needed) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "PASS", "332 Need account for login.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "acct", "pw", INTERNET_FLAG_PASSIVE);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_INCORRECT_PASSWORD);
    Sleep(100);
    CHECK(fc_find(&x, "ACCT", 0) < 0);
    fc_end(&x);
}

TEST(ftpc_conn_pass_202_is_success) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "PASS", "202 Superfluous, but ok.", 0 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET hc = fc_connect(&x, "u2", "p2", INTERNET_FLAG_PASSIVE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    fc_end(&x);
}

TEST(ftpc_conn_login_retry_after_failure) {
    REQUIRE(U(InternetConnectA));
    static const srv_ftp_override ov[] = { { "PASS", "530 first try fails.", 1 } };
    srv_ftp_config c = { NULL, 0, ov, NF(ov) };
    fcx x; if (!fc_start(&x, &c)) return;
    HINTERNET h1 = fc_connect(&x, "rt", "pw", INTERNET_FLAG_PASSIVE);
    CHECK(h1 == NULL);
    HINTERNET h2 = fc_connect(&x, "rt", "pw", INTERNET_FLAG_PASSIVE);
    CHECKF(h2 != NULL, "err=%lu", GetLastError());
    EXPECT_EQ(srv_conn_count(x.s), 2);
    fc_end(&x);
}

/* ------------------------------------------------------------------ peer misbehaviour */
TEST(ftpc_conn_no_listener_cannot_connect) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_start(&x, NULL)) return;
    unsigned short port = srv_port(x.s);
    srv_stop(x.s); x.s = NULL;
    HINTERNET hi = t_inet_open("ftpc");
    SetLastError(0);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    EXPECT_FAIL(hc == NULL, ERROR_INTERNET_CANNOT_CONNECT);
    U(InternetCloseHandle)(hi);
}

TEST(ftpc_conn_silent_server_times_out) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(InternetSetOptionA));
    static const srv_step st[] = { S_SLEEP(4000), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    x.hi = t_inet_open("ftpc");
    DWORD to = 1000;
    CHECK(U(InternetSetOptionA)(x.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to));
    DWORD t0 = GetTickCount();
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError(), dt = GetTickCount() - t0;
    CHECK(hc == NULL);
    t_note("silent server: err=%lu %s after %lu ms", err, t_inet_errname(err), dt);
    EXPECT_EQ(err, ERROR_INTERNET_TIMEOUT);
    fc_end(&x);
}

TEST(ftpc_conn_server_closes_after_banner) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_SEND("220 hi\r\n"), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    CHECKF(err >= INTERNET_ERROR_BASE && err <= INTERNET_ERROR_LAST, "err=%lu", err);
    t_note("peer closed after banner: err=%lu %s", err, t_inet_errname(err));
    fc_end(&x);
}

TEST(ftpc_conn_server_closes_without_banner) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    CHECKF(err >= INTERNET_ERROR_BASE && err <= INTERNET_ERROR_LAST, "err=%lu", err);
    t_note("peer closed before banner: err=%lu %s", err, t_inet_errname(err));
    fc_end(&x);
}

TEST(ftpc_conn_http_peer_is_not_ftp) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_SEND("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    t_note("HTTP peer on FTP connect: err=%lu %s", err, t_inet_errname(err));
    fc_end(&x);
}

/* ------------------------------------------------------------------ offline connect handles */
TEST(ftpc_offline_connect_makes_no_connection) {
    REQUIRE(U(InternetConnectA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_OFFLINE);
    CHECKF(hc != NULL, "err=%lu", GetLastError());
    Sleep(150);
    EXPECT_EQ(srv_conn_count(x.s), 0);
    DWORD t = 0, l = sizeof t;
    CHECK(hc && U(InternetQueryOptionA)(hc, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
    EXPECT_EQ(t, INTERNET_HANDLE_TYPE_CONNECT_FTP);
    fc_end(&x);
}

TEST(ftpc_offline_write_operations_fail_19) {
    REQUIRE(U(FtpDeleteFileA)); REQUIRE(U(FtpRenameFileA)); REQUIRE(U(FtpCreateDirectoryA)); REQUIRE(U(FtpRemoveDirectoryA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_OFFLINE);
    if (!hc) { CHECKF(0, "offline connect failed %lu", GetLastError()); fc_end(&x); return; }
    SetLastError(0); EXPECT_FAIL(!U(FtpDeleteFileA)(hc, "a.txt"), ERROR_WRITE_PROTECT);
    SetLastError(0); EXPECT_FAIL(!U(FtpRenameFileA)(hc, "a.txt", "b.txt"), ERROR_WRITE_PROTECT);
    SetLastError(0); EXPECT_FAIL(!U(FtpCreateDirectoryA)(hc, "d"), ERROR_WRITE_PROTECT);
    SetLastError(0); EXPECT_FAIL(!U(FtpRemoveDirectoryA)(hc, "d"), ERROR_WRITE_PROTECT);
    const char *lp = fc_local("offput.txt"); fc_put_local(lp, "x", 1);
    SetLastError(0); EXPECT_FAIL(!U(FtpPutFileA)(hc, lp, "x.txt", FTP_TRANSFER_TYPE_BINARY, 0), ERROR_WRITE_PROTECT);
    fc_del_local(lp);
    EXPECT_EQ(srv_conn_count(x.s), 0);
    fc_end(&x);
}

TEST(ftpc_offline_command_no_direct_access) {
    REQUIRE(U(FtpCommandA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_OFFLINE);
    if (!hc) { CHECKF(0, "offline connect failed %lu", GetLastError()); fc_end(&x); return; }
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "NOOP", 0, NULL), ERROR_INTERNET_NO_DIRECT_ACCESS);
    fc_end(&x);
}

TEST(ftpc_offline_current_directory_is_local) {
    REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpSetCurrentDirectoryA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_OFFLINE);
    if (!hc) { CHECKF(0, "offline connect failed %lu", GetLastError()); fc_end(&x); return; }
    char d[256] = "?"; DWORD l = sizeof d;
    BOOL ok = U(FtpGetCurrentDirectoryA)(hc, d, &l);
    t_note("offline FtpGetCurrentDirectory: ok=%d err=%lu dir=[%s] len=%lu", ok, ok ? 0 : GetLastError(), d, l);
    CHECK(ok);
    BOOL ok2 = U(FtpSetCurrentDirectoryA)(hc, "/pub");
    t_note("offline FtpSetCurrentDirectory: ok=%d err=%lu", ok2, ok2 ? 0 : GetLastError());
    CHECK(ok2);
    l = sizeof d; d[0] = 0;
    CHECK(U(FtpGetCurrentDirectoryA)(hc, d, &l));
    t_note("offline cwd after set: [%s] len=%lu", d, l);
    EXPECT_EQ(srv_conn_count(x.s), 0);
    fc_end(&x);
}

TEST(ftpc_offline_open_file_not_cached) {
    REQUIRE(U(FtpOpenFileA));
    fcx x; if (!fc_start(&x, NULL)) return;
    HINTERNET hc = fc_connect(&x, NULL, NULL, INTERNET_FLAG_PASSIVE | INTERNET_FLAG_OFFLINE);
    if (!hc) { CHECKF(0, "offline connect failed %lu", GetLastError()); fc_end(&x); return; }
    char name[96]; snprintf(name, sizeof name, "%s.txt", t_uniq("offl"));
    SetLastError(0);
    HINTERNET hf = U(FtpOpenFileA)(hc, name, GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0);
    DWORD err = GetLastError();
    CHECK(hf == NULL);
    t_note("offline FtpOpenFile (no cache entry): err=%lu", err);
    EXPECT_EQ(err, ERROR_FILE_NOT_FOUND);
    if (hf) U(InternetCloseHandle)(hf);
    EXPECT_EQ(srv_conn_count(x.s), 0);
    fc_end(&x);
}
