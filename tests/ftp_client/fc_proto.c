/* fc_proto.c - FTP control-connection protocol details: how the client recognises the end of a reply
 * (ReceiveFtpResponse: a line whose first three characters are digits followed by a space ends the reply, any other
 * line is a continuation; the reply code is taken from that final line), reply classes outside 1..5, the exact bytes
 * of commands on the wire, and what happens when the server drops or stalls the control connection mid-session
 * (421 + close, EOF in a reply, partial reply line, receive timeout).
 *
 * Most tests use a raw scripted peer (fc_start_raw) that plays the FTP server byte for byte; logins there use
 * user "u" / password "p" so the command lengths are fixed ("USER u\r\n" and "PASS p\r\n" are 8 bytes each).
 * Decomp: ReceiveFtpResponse, GetReply, I_Command, I_SendCommand, wFtpMakeConnection. */
#include "ftp.h"

/* raw peer: banner + login with u/p (16 bytes of commands) */
#define RAW_LOGIN  S_SEND("220 raw peer\r\n"), S_BYTES(8), S_SEND("331 pw please\r\n"), S_BYTES(8), S_SEND("230 in\r\n")

static int raw_open(fcx *x, const srv_step *st, int n) {
    if (!U(InternetConnectA)) { t_skip("missing export InternetConnectA"); return 0; }
    if (!fc_start_raw(x, st, n)) return 0;
    if (!fc_connect(x, "u", "p", INTERNET_FLAG_PASSIVE)) {
        DWORD e = GetLastError();
        CHECKF(0, "InternetConnect(FTP, raw peer) failed: %lu %s", e, t_inet_errname(e));
        fc_end(x);
        return 0;
    }
    return 1;
}

/* the n-th SRV_EV_BYTES event (what the client sent for one S_BYTES step), "" if absent */
static const char *raw_bytes(fcx *x, int idx) {
    const srv_event *ev; int n = srv_events(x->s, &ev), k = 0;
    for (int i = 0; i < n; i++) if (ev[i].kind == SRV_EV_BYTES) { if (k == idx) return ev[i].data ? ev[i].data : ""; k++; }
    return "";
}

/* banner-only server config helper: connect anonymously, return success, *err */
static int banner_login(const char *banner, DWORD *err, fcx *x) {
    srv_ftp_config c; memset(&c, 0, sizeof c); c.banner = banner;
    if (!fc_start(x, &c)) return -1;
    SetLastError(0);
    HINTERNET hc = fc_connect(x, NULL, NULL, INTERNET_FLAG_PASSIVE);
    *err = hc ? 0 : GetLastError();
    return hc != NULL;
}

/* ------------------------------------------------------------------ end-of-reply recognition (banners) */
static const struct { const char *banner; int ok; const char *why; } banner_tab[] = {
    { "220 plain", 1, "single line" },
    { "120-wait a little\r\n220 ready now", 1, "code is taken from the terminating line (120- then 220)" },
    { "2200 four digits is not a terminator\r\n220 ok", 1, "4-digit line is a continuation" },
    { "hello there, no code\r\n220 ok", 1, "free text line before the code" },
    { "\r\n\r\n220 after blank lines", 1, "blank lines are continuations" },
    { " 220 indented is not a terminator\r\n220 ok", 1, "leading space: continuation" },
    { "220-multi\r\n220-still\r\n220 end", 1, "classic multi-line" },
    { "421-first\r\n220 last wins", 1, "a 4xx first line does not decide the class" },
    { "220-first\r\n421 last wins", 0, "terminating 421 -> login failure" },
    { "220-a\r\n330 b", 0, "terminating 3xx greeting -> login failure" },
    { "554 nope", 0, "5xx greeting" },
    { "220-x\r\n1201 y\r\n120 still waiting", 0, "terminating 1xx -> login failure" },
};

TEST(ftpc_proto_banner_terminator_table) {
    REQUIRE(U(InternetConnectA));
    for (int i = 0; i < NF(banner_tab); i++) {
        fcx x; DWORD err = 0;
        int r = banner_login(banner_tab[i].banner, &err, &x);
        if (r < 0) return;
        CHECKF(r == banner_tab[i].ok, "[%d] %s: ok=%d err=%lu", i, banner_tab[i].why, r, err);
        if (!banner_tab[i].ok) CHECKF(err == ERROR_INTERNET_LOGIN_FAILURE, "[%d] %s: err=%lu", i, banner_tab[i].why, err);
        if (banner_tab[i].ok) {
            Sleep(50);
            CHECKF(!strcmp(fc_seq(&x, 0), "USER anonymous|PASS ***"), "[%d] seq %s", i, fc_seq(&x, 0));
        } else {
            Sleep(50);
            CHECKF(fc_ncmd(&x) == 0, "[%d] %s: commands sent %s", i, banner_tab[i].why, fc_seq(&x, 0));
        }
        fc_end(&x);
    }
}

TEST(ftpc_proto_banner_text_is_last_response) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    fcx x; DWORD err = 0;
    int r = banner_login("220-line one\r\n220-line two\r\n220 line three", &err, &x);
    if (r < 0) return;
    CHECKF(r == 1, "err=%lu", err);
    /* after login the last response is the PASS reply; the banner is replaced */
    DWORD e; const char *t = fc_resp(&e);
    CHECKF(strstr(t, "230") != NULL, "resp=[%s]", t);
    /* Win10 (VM, triage 2026-11): the last-response buffer accumulates the banner and the USER/PASS replies */
    t_note("last response after login: [%s]", t);
    fc_end(&x);
}

TEST(ftpc_proto_banner_failure_text_keeps_all_lines) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    fcx x; DWORD err = 0;
    int r = banner_login("220-alpha\r\nbravo free text\r\n421 charlie", &err, &x);
    if (r < 0) return;
    CHECK(r == 0);
    EXPECT_EQ(err, ERROR_INTERNET_LOGIN_FAILURE);
    DWORD e; const char *t = fc_resp(&e);
    CHECKF(strstr(t, "220-alpha") && strstr(t, "bravo free text") && strstr(t, "421 charlie"), "resp=[%s]", t);
    fc_end(&x);
}

TEST(ftpc_proto_banner_bare_code_without_space_then_close) {
    REQUIRE(U(InternetConnectA));
    /* "220\r\n" has no space after the digits: not a terminating line; then EOF -> dropped */
    static const srv_step st[] = { S_SEND("220\r\n"), S_SLEEP(200), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    t_note("banner \"220\\r\\n\" then close: err=%lu %s", err, t_inet_errname(err));
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_banner_partial_line_then_close) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_SEND("220 no newline"), S_SLEEP(200), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    t_note("banner without line end then close: err=%lu %s", err, t_inet_errname(err));
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_banner_split_into_small_pieces) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_SPLIT("220-split\r\n220 banner arrives in pieces\r\n", 3, 10), S_BYTES(8), S_SEND("331 x\r\n"),
                                   S_BYTES(8), S_SEND("230 y\r\n"), S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    EXPECT_STR(raw_bytes(&x, 0), "USER u\r\n");
    EXPECT_STR(raw_bytes(&x, 1), "PASS p\r\n");
    fc_end(&x);
}

TEST(ftpc_proto_lf_only_line_ends) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(FtpCreateDirectoryA));
    static const srv_step st[] = { S_SEND("220 lf only\n"), S_BYTES(8), S_SEND("331 x\n"), S_BYTES(8), S_SEND("230 y\n"),
                                   S_BYTES(7), S_SEND("257 \"/d\" created\n"), S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    SetLastError(0);
    CHECKF(U(FtpCreateDirectoryA)(x.hc, "d"), "err=%lu", GetLastError());
    EXPECT_STR(raw_bytes(&x, 2), "MKD d\r\n");
    fc_end(&x);
}

TEST(ftpc_proto_cr_without_lf_is_not_line_end) {
    REQUIRE(U(InternetConnectA));
    /* only '\n' ends a line: "220 a\r" followed by more text keeps the reply open until the next '\n' */
    static const srv_step st[] = { S_SEND("120 waiting\r"), S_SLEEP(100), S_SEND("220 ready\r\n"), S_BYTES(8), S_SEND("331 x\r\n"),
                                   S_BYTES(8), S_SEND("230 y\r\n"), S_BYTES(0) };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    /* the whole "120 waiting\r220 ready\r\n" is one line starting "120 " -> class 1 greeting -> login failure */
    CHECK(hc == NULL);
    EXPECT_EQ(err, ERROR_INTERNET_LOGIN_FAILURE);
    fc_end(&x);
}

/* ------------------------------------------------------------------ exact command bytes */
TEST(ftpc_proto_login_bytes_exact) {
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    EXPECT_STR(raw_bytes(&x, 0), "USER u\r\n");
    EXPECT_STR(raw_bytes(&x, 1), "PASS p\r\n");
    fc_end(&x);
}

TEST(ftpc_proto_directory_command_bytes_exact) {
    REQUIRE(U(FtpCreateDirectoryA)); REQUIRE(U(FtpRemoveDirectoryA)); REQUIRE(U(FtpDeleteFileA)); REQUIRE(U(FtpSetCurrentDirectoryA));
    static const srv_step st[] = { RAW_LOGIN,
        S_BYTES(9),  S_SEND("257 \"/abc\" created\r\n"),
        S_BYTES(9),  S_SEND("250 removed\r\n"),
        S_BYTES(12), S_SEND("250 deleted\r\n"),
        S_BYTES(10), S_SEND("250 cwd ok\r\n"),
        S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    CHECKF(U(FtpCreateDirectoryA)(x.hc, "abc"), "mkd err=%lu", GetLastError());
    CHECKF(U(FtpRemoveDirectoryA)(x.hc, "abc"), "rmd err=%lu", GetLastError());
    CHECKF(U(FtpDeleteFileA)(x.hc, "f.txt"), "dele err=%lu", GetLastError());
    CHECKF(U(FtpSetCurrentDirectoryA)(x.hc, "/pub"), "cwd err=%lu", GetLastError());
    EXPECT_STR(raw_bytes(&x, 2), "MKD abc\r\n");
    EXPECT_STR(raw_bytes(&x, 3), "RMD abc\r\n");
    EXPECT_STR(raw_bytes(&x, 4), "DELE f.txt\r\n");
    EXPECT_STR(raw_bytes(&x, 5), "CWD /pub\r\n");
    fc_end(&x);
}

TEST(ftpc_proto_pwd_and_rename_bytes_exact) {
    REQUIRE(U(FtpGetCurrentDirectoryA)); REQUIRE(U(FtpRenameFileA));
    static const srv_step st[] = { RAW_LOGIN,
        S_BYTES(5),  S_SEND("257 \"/x y\" is cwd\r\n"),
        S_BYTES(12), S_SEND("350 ready\r\n"),
        S_BYTES(12), S_SEND("250 renamed\r\n"),
        S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    char d[64] = ""; DWORD l = sizeof d;
    CHECKF(U(FtpGetCurrentDirectoryA)(x.hc, d, &l), "pwd err=%lu", GetLastError());
    EXPECT_STR(d, "/x y");
    CHECKF(U(FtpRenameFileA)(x.hc, "a.txt", "b.txt"), "rename err=%lu", GetLastError());
    EXPECT_STR(raw_bytes(&x, 2), "PWD\r\n");
    EXPECT_STR(raw_bytes(&x, 3), "RNFR a.txt\r\n");
    EXPECT_STR(raw_bytes(&x, 4), "RNTO b.txt\r\n");
    fc_end(&x);
}

TEST(ftpc_proto_ftpcommand_bytes_exact) {
    REQUIRE(U(FtpCommandA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(11), S_SEND("200 fine\r\n"), S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    CHECKF(U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "SITE  x y", 0, NULL), "err=%lu", GetLastError());
    EXPECT_STR(raw_bytes(&x, 2), "SITE  x y\r\n");    /* verbatim, inner double space kept, CRLF appended */
    fc_end(&x);
}

/* ------------------------------------------------------------------ reply parsing on commands (srv_ftp overrides) */
static const struct { const char *reply; int ok; const char *why; } cwd_tab[] = {
    { "250 ok", 1, "plain 2xx" },
    { "550-first line says no\r\n250 last line says yes", 1, "code from terminating line" },
    { "250-first line says yes\r\n550 last line says no", 0, "code from terminating line" },
    { " 550 indented\r\n250 ok", 1, "indented line is a continuation" },
    { "5500 four digits\r\n250 ok", 1, "4-digit line is a continuation" },
    { "free text\r\nmore text\r\n250 ok", 1, "free text continuations" },
    { "650 class six", 0, "class 6 is not success" },
    { "050 class zero", 0, "class 0 is not success" },
    { "150 preliminary", 0, "CWD needs 2xx (I_Command accepts 1..3, wFtpSetCurrentDirectory does not)" },
    { "350 intermediate", 0, "CWD needs 2xx" },
    { "421 closing", 0, "4xx" },
    { "250-a\r\n250-b\r\n250-c\r\n250-d\r\n250 e", 1, "long multi-line" },
};

TEST(ftpc_proto_command_reply_parsing_table) {
    REQUIRE(U(FtpSetCurrentDirectoryA));
    for (int i = 0; i < NF(cwd_tab); i++) {
        srv_ftp_override ov[1] = { { "CWD", cwd_tab[i].reply, 0 } };
        srv_ftp_config c; memset(&c, 0, sizeof c); c.overrides = ov; c.noverrides = 1;
        fcx x; if (!fc_open(&x, &c)) return;
        SetLastError(0);
        BOOL ok = U(FtpSetCurrentDirectoryA)(x.hc, "somewhere");
        DWORD err = ok ? 0 : GetLastError();
        CHECKF(!!ok == cwd_tab[i].ok, "[%d] %s: ok=%d err=%lu", i, cwd_tab[i].why, ok, err);
        if (!cwd_tab[i].ok) CHECKF(err == ERROR_INTERNET_EXTENDED_ERROR, "[%d] %s: err=%lu", i, cwd_tab[i].why, err);
        /* the connection stays in sync: a following PWD works */
        char d[64] = ""; DWORD l = sizeof d;
        CHECKF(U(FtpGetCurrentDirectoryA)(x.hc, d, &l), "[%d] PWD after: err=%lu", i, GetLastError());
        fc_end(&x);
    }
}

TEST(ftpc_proto_multiline_reply_text_complete) {
    REQUIRE(U(FtpSetCurrentDirectoryA)); REQUIRE(U(InternetGetLastResponseInfoA));
    static const srv_ftp_override ov[] = { { "CWD", "550-line one\r\ntext two\r\n550 line three", 0 } };
    srv_ftp_config c; memset(&c, 0, sizeof c); c.overrides = ov; c.noverrides = 1;
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpSetCurrentDirectoryA)(x.hc, "nope"), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *t = fc_resp(&e);
    CHECKF(strstr(t, "550-line one") && strstr(t, "text two") && strstr(t, "550 line three"), "resp=[%s]", t);
    t_note("multi-line 550 response text: [%s] err field=%lu", t, e);
    fc_end(&x);
}

TEST(ftpc_proto_unsupported_feat_via_command) {
    REQUIRE(U(FtpCommandA));
    static const srv_ftp_override ov[] = { { "FEAT", "500 'FEAT': command not understood.", 0 } };
    srv_ftp_config c; memset(&c, 0, sizeof c); c.overrides = ov; c.noverrides = 1;
    fcx x; if (!fc_open(&x, &c)) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "FEAT", 0, NULL), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *t = fc_resp(&e);
    CHECKF(strstr(t, "500 'FEAT'") != NULL, "resp=[%s]", t);
    /* session still usable */
    char d[64] = ""; DWORD l = sizeof d;
    CHECK(U(FtpGetCurrentDirectoryA)(x.hc, d, &l));
    EXPECT_STR(d, "/");
    fc_end(&x);
}

TEST(ftpc_proto_feat_502_default_server) {
    REQUIRE(U(FtpCommandA));
    static const srv_ftp_override ov[] = { { "FEAT", "502 Command not implemented.", 0 } };
    srv_ftp_config c; memset(&c, 0, sizeof c); c.overrides = ov; c.noverrides = 1;
    fcx x; if (!fc_open(&x, &c)) return;
    /* nothing in the client depends on FEAT: transfers work against a server without it */
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCommandA)(x.hc, FALSE, FTP_TRANSFER_TYPE_ASCII, "FEAT", 0, NULL), ERROR_INTERNET_EXTENDED_ERROR);
    CHECK(fc_find(&x, "FEAT", 0) == 2);
    EXPECT_EQ(fc_count(&x, "FEAT"), 1);
    fc_end(&x);
}

/* ------------------------------------------------------------------ the server drops the control connection */
TEST(ftpc_proto_421_then_close_mid_session) {
    REQUIRE(U(FtpCreateDirectoryA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(7), S_SEND("421 Service not available, closing control connection.\r\n"), S_CLOSE() };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    SetLastError(0);
    EXPECT_FAIL(!U(FtpCreateDirectoryA)(x.hc, "d"), ERROR_INTERNET_EXTENDED_ERROR);
    DWORD e; const char *t = fc_resp(&e);
    CHECKF(strstr(t, "421 Service not available") != NULL, "resp=[%s]", t);
    Sleep(100);
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryA)(x.hc, "d");
    DWORD err = ok ? 0 : GetLastError();
    CHECK(!ok);
    t_note("command after 421+close: err=%lu %s", err, t_inet_errname(err));
    CHECKF(err >= INTERNET_ERROR_BASE && err <= INTERNET_ERROR_LAST, "err=%lu", err);
    fc_end(&x);
}

TEST(ftpc_proto_eof_instead_of_reply_is_dropped) {
    REQUIRE(U(FtpCreateDirectoryA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(7), S_CLOSE() };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryA)(x.hc, "d");
    DWORD err = ok ? 0 : GetLastError();
    CHECK(!ok);
    t_note("EOF instead of a reply: err=%lu %s", err, t_inet_errname(err));
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_partial_reply_then_eof_is_dropped) {
    REQUIRE(U(FtpCreateDirectoryA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(7), S_SEND("257 \"/d\" created"), S_SLEEP(100), S_CLOSE() };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryA)(x.hc, "d");
    DWORD err = ok ? 0 : GetLastError();
    CHECK(!ok);
    t_note("partial reply then EOF: err=%lu %s", err, t_inet_errname(err));
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_continuation_only_then_eof_is_dropped) {
    REQUIRE(U(FtpCreateDirectoryA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(7), S_SEND("257-started\r\n257-still going\r\n"), S_SLEEP(100), S_CLOSE() };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryA)(x.hc, "d");
    DWORD err = ok ? 0 : GetLastError();
    CHECK(!ok);
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_reset_instead_of_reply) {
    REQUIRE(U(FtpCreateDirectoryA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(7), S_RESET() };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryA)(x.hc, "d");
    DWORD err = ok ? 0 : GetLastError();
    CHECK(!ok);
    t_note("RST instead of a reply: err=%lu %s", err, t_inet_errname(err));
    CHECKF(err >= INTERNET_ERROR_BASE && err <= INTERNET_ERROR_LAST, "err=%lu", err);
    fc_end(&x);
}

TEST(ftpc_proto_drop_after_login_then_pwd) {
    REQUIRE(U(FtpGetCurrentDirectoryA));
    static const srv_step st[] = { RAW_LOGIN, S_CLOSE() };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    Sleep(200);   /* the peer has closed; the client does not know yet */
    char d[64] = "?"; DWORD l = sizeof d;
    SetLastError(0);
    BOOL ok = U(FtpGetCurrentDirectoryA)(x.hc, d, &l);
    DWORD err = ok ? 0 : GetLastError();
    CHECK(!ok);
    t_note("PWD on a control connection the peer closed: err=%lu %s", err, t_inet_errname(err));
    CHECKF(err >= INTERNET_ERROR_BASE && err <= INTERNET_ERROR_LAST, "err=%lu", err);
    fc_end(&x);
}

TEST(ftpc_proto_reply_timeout) {
    REQUIRE(U(FtpCreateDirectoryA)); REQUIRE(U(InternetSetOptionA));
    static const srv_step st[] = { RAW_LOGIN, S_BYTES(7), S_SLEEP(3500), S_SEND("257 late\r\n"), S_BYTES(0) };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    x.hi = t_inet_open("ftpc");
    DWORD to = 1000;
    CHECK(U(InternetSetOptionA)(x.hi, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to));
    if (!fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE)) { CHECKF(0, "connect %lu", GetLastError()); fc_end(&x); return; }
    DWORD t0 = GetTickCount();
    SetLastError(0);
    BOOL ok = U(FtpCreateDirectoryA)(x.hc, "d");
    DWORD err = ok ? 0 : GetLastError(), dt = GetTickCount() - t0;
    t_note("reply 3.5 s late with a 1 s receive timeout: ok=%d err=%lu %s after %lu ms", ok, err, t_inet_errname(err), dt);
    if (!ok) CHECKF(err >= INTERNET_ERROR_BASE && err <= INTERNET_ERROR_LAST, "err=%lu", err);
    fc_end(&x);
}

/* ------------------------------------------------------------------ login on a raw peer */
TEST(ftpc_proto_user_reply_multiline_331) {
    static const srv_step st[] = { S_SEND("220 hi\r\n"), S_BYTES(8), S_SEND("331-need\r\n331-a\r\n331 password\r\n"),
                                   S_BYTES(8), S_SEND("230-welcome\r\n230 in\r\n"), S_BYTES(0) };
    fcx x; if (!raw_open(&x, st, NF(st))) return;
    DWORD e; const char *t = fc_resp(&e);
    CHECKF(strstr(t, "230-welcome") && strstr(t, "230 in"), "resp=[%s]", t);
    fc_end(&x);
}

TEST(ftpc_proto_pass_reply_eof_is_dropped) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_SEND("220 hi\r\n"), S_BYTES(8), S_SEND("331 x\r\n"), S_BYTES(8), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    t_note("EOF after PASS: err=%lu %s", err, t_inet_errname(err));
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_user_reply_eof_is_dropped) {
    REQUIRE(U(InternetConnectA));
    static const srv_step st[] = { S_SEND("220 hi\r\n"), S_BYTES(8), S_CLOSE() };
    fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
    SetLastError(0);
    HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
    DWORD err = GetLastError();
    CHECK(hc == NULL);
    EXPECT_EQ(err, ERROR_FTP_DROPPED);
    fc_end(&x);
}

TEST(ftpc_proto_pass_reply_class_table) {
    REQUIRE(U(InternetConnectA));
    static const struct { const char *reply; DWORD err; } tab[] = {
        { "230 ok\r\n", 0 },
        { "202 not needed\r\n", 0 },
        { "250 odd but 2xx\r\n", 0 },
        { "530 no\r\n", ERROR_INTERNET_INCORRECT_PASSWORD },
        { "430 no\r\n", ERROR_INTERNET_INCORRECT_PASSWORD },
        { "332 account\r\n", ERROR_INTERNET_INCORRECT_PASSWORD },
    };
    for (int i = 0; i < NF(tab); i++) {
        srv_step st[] = { S_SEND("220 hi\r\n"), S_BYTES(8), S_SEND("331 x\r\n"), S_BYTES(8), S_SENDN(tab[i].reply, strlen(tab[i].reply)), S_BYTES(0) };
        fcx x; if (!fc_start_raw(&x, st, NF(st))) return;
        SetLastError(0);
        HINTERNET hc = fc_connect(&x, "u", "p", INTERNET_FLAG_PASSIVE);
        DWORD err = hc ? 0 : GetLastError();
        CHECKF(err == tab[i].err, "[%d] PASS reply %.20s -> err=%lu want %lu", i, tab[i].reply, err, tab[i].err);
        fc_end(&x);
    }
}
