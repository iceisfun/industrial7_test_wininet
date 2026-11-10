/* InternetGetLastResponseInfo(A|W) and InternetSetStatusCallback(A|W|plain) return-value protocol.
 * [D InternetGetLastResponseInfoA@0x1382f0]:
 *   NULL lpdwError or NULL lpdwBufferLength -> FALSE, 87.
 *   NULL buffer -> *len = 0 first (so a size query with text present is FALSE/122 with *len = text bytes incl NUL).
 *   No per-thread response text: TRUE, *len = 0, *lpdwError = the thread's response error, buffer[0] = 0 when *len != 0.
 *   Text present, buffer big enough: TRUE, copies text, *len = strlen. Too small: FALSE/122, copies *len-1 bytes + NUL,
 *   *len = text bytes incl NUL. SetLastError(result) on every path (0 on success).
 * [D InternetGetLastResponseInfoW@0x139060]: NULL buffer -> calls A with a NULL buffer, *len = 2 * A length (bytes);
 *   with a buffer of N chars: A gets a 2*(N+1)-byte scratch buffer; success -> *len = chars excl NUL;
 *   MultiByteToWideChar overflow -> FALSE/122 with *len = 2 * strlen; A overflow -> FALSE/122 with *len = 2 * (len incl NUL).
 * [D InternetSetStatusCallbackCore@0xcef20]: NULL handle -> INTERNET_INVALID_STATUS_CALLBACK, GLE 12018;
 *   unmapped handle -> INTERNET_INVALID_STATUS_CALLBACK, GLE 6; valid -> previous callback, GLE 0 (one slot per
 *   handle shared by A and W; the W flag only marks string conversions). */
#include "tm.h"
#include "srv.h"
#include "tnet.h"

/* ------------------------------------------------------------ last response info: arguments */
TEST(tlr_a_null_args) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    DWORD err = 0x77, len = 10; char buf[16];
    SET_ERR(0); CHECK(!U(InternetGetLastResponseInfoA)(NULL, buf, &len)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(len, 10);
    SET_ERR(0); CHECK(!U(InternetGetLastResponseInfoA)(&err, buf, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(err, 0x77);
    SET_ERR(0); CHECK(!U(InternetGetLastResponseInfoA)(NULL, NULL, NULL)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

typedef struct { int which; BOOL r; DWORD gle, err, len; char a[32]; WCHAR w[32]; int null_buf; DWORD inlen; } lr_probe;
static DWORD WINAPI lr_thread(void *p) {
    lr_probe *q = (lr_probe *)p;
    q->err = 0x5555; q->len = q->inlen;
    memset(q->a, 'Z', sizeof q->a); for (int i = 0; i < 32; i++) q->w[i] = L'Z';
    SetLastError(0xbeef);
    if (q->which == 0) q->r = U(InternetGetLastResponseInfoA)(&q->err, q->null_buf ? NULL : q->a, &q->len);
    else q->r = U(InternetGetLastResponseInfoW)(&q->err, q->null_buf ? NULL : q->w, &q->len);
    q->gle = GetLastError();
    return 0;
}
static void lr_fresh(lr_probe *q) {
    HANDLE h = CreateThread(NULL, 0, lr_thread, q, 0, NULL);
    CHECK(h != NULL);
    if (h) { CHECK(WaitForSingleObject(h, 10000) == WAIT_OBJECT_0); CloseHandle(h); }
}

TEST(tlr_a_fresh_thread_empty) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    lr_probe q = { 0 }; q.which = 0; q.inlen = sizeof q.a;
    lr_fresh(&q);
    CHECK(q.r); EXPECT_EQ(q.gle, 0); EXPECT_EQ(q.len, 0); EXPECT_EQ(q.a[0], 0); EXPECT_EQ(q.a[1], 'Z');
    t_note("fresh-thread A: err=%lu", q.err);
    EXPECT_EQ(q.err, 0);
}

TEST(tlr_a_fresh_thread_null_buffer) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    lr_probe q = { 0 }; q.which = 0; q.inlen = 77; q.null_buf = 1;
    lr_fresh(&q);
    CHECK(q.r); EXPECT_EQ(q.gle, 0); EXPECT_EQ(q.len, 0);
}

TEST(tlr_a_fresh_thread_zero_len) {
    REQUIRE(U(InternetGetLastResponseInfoA));
    lr_probe q = { 0 }; q.which = 0; q.inlen = 0;
    lr_fresh(&q);
    CHECK(q.r); EXPECT_EQ(q.gle, 0); EXPECT_EQ(q.len, 0);
    EXPECT_EQ(q.a[0], 'Z');                 /* *len == 0: the buffer is not touched [D] */
}

TEST(tlr_w_fresh_thread_empty) {
    REQUIRE(U(InternetGetLastResponseInfoW));
    lr_probe q = { 0 }; q.which = 1; q.inlen = 32;
    lr_fresh(&q);
    CHECK(q.r); EXPECT_EQ(q.gle, 0); EXPECT_EQ(q.len, 0); EXPECT_EQ(q.w[0], 0);
    EXPECT_EQ(q.err, 0);
}

TEST(tlr_w_fresh_thread_null_buffer) {
    REQUIRE(U(InternetGetLastResponseInfoW));
    lr_probe q = { 0 }; q.which = 1; q.inlen = 77; q.null_buf = 1;
    lr_fresh(&q);
    CHECK(q.r); EXPECT_EQ(q.gle, 0);
    t_note("fresh-thread W NULL buffer: len %lu (input 77)", q.len);
    EXPECT_EQ(q.len, 77);                   /* W does not write *len when A succeeds without text [D] */
}

/* ------------------------------------------------------------ last response info after FTP traffic */
static srv *ftp_start(void) {
    static const srv_ftp_file files[] = { { "/hello.txt", "hello", 5, "20200102030405" } };
    static srv_ftp_config fc; fc.files = files; fc.nfiles = 1;
    srv_config cfg; memset(&cfg, 0, sizeof cfg); cfg.kind = SRV_FTP; cfg.ftp = &fc;
    srv *s = NULL;
    int rc = srv_start(&cfg, &s);
    if (rc != SRV_OK) { t_skip("ftp server unavailable: %s", srv_strerror(rc)); return NULL; }
    return s;
}
static HINTERNET ftp_connect(HINTERNET hi, srv *s) {
    return U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
}

TEST(tlr_a_after_ftp_login) {
    REQUIRE(U(InternetGetLastResponseInfoA)); REQUIRE(U(InternetConnectA));
    srv *s = ftp_start(); if (!s) return;
    HINTERNET hi = t_inet_open("tlr"); HINTERNET hc = hi ? ftp_connect(hi, s) : NULL;
    CHECK(hc != NULL);
    if (hc) {
        DWORD err = 0x5555, len = 0;
        SET_ERR(0);
        BOOL r = U(InternetGetLastResponseInfoA)(&err, NULL, &len);
        DWORD gle = GetLastError();
        t_note("after login: size query r=%d gle=%lu len=%lu err=%lu", r, gle, len, err);
        CHECK(!r); EXPECT_EQ(gle, ERROR_INSUFFICIENT_BUFFER);
        CHECK(len > 3 && len < 4096);
        char *buf = (char *)calloc(1, len + 8);
        DWORD n = len;
        CHECK(U(InternetGetLastResponseInfoA)(&err, buf, &n));
        t_note("after login: text [%s] len=%lu err=%lu", buf, n, err);
        EXPECT_EQ(n, strlen(buf));
        EXPECT_EQ(n + 1, len);              /* size query reports bytes incl NUL, success reports strlen [D] */
        CHECK(strstr(buf, "230") != NULL);
        /* too small: truncated copy + NUL, FALSE/122, *len = full size */
        char small[8]; memset(small, 'Z', sizeof small); DWORD sn = 5;
        SET_ERR(0);
        CHECK(!U(InternetGetLastResponseInfoA)(&err, small, &sn)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(sn, len);
        CHECK(!memcmp(small, buf, 4) && small[4] == 0 && small[5] == 'Z');
        /* exactly strlen+1 fits */
        char *ex = (char *)calloc(1, len + 8); DWORD en = len;
        CHECK(U(InternetGetLastResponseInfoA)(&err, ex, &en)); EXPECT_EQ(en, len - 1); EXPECT_STR(ex, buf);
        /* strlen bytes do not */
        DWORD en2 = len - 1; SET_ERR(0);
        CHECK(!U(InternetGetLastResponseInfoA)(&err, ex, &en2)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(en2, len);
        free(ex); free(buf);
        /* response text is per thread */
        lr_probe q = { 0 }; q.which = 0; q.inlen = sizeof q.a; lr_fresh(&q);
        CHECK(q.r); EXPECT_EQ(q.len, 0);
    }
    t_inet_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(tlr_w_after_ftp_login) {
    REQUIRE(U(InternetGetLastResponseInfoW)); REQUIRE(U(InternetGetLastResponseInfoA)); REQUIRE(U(InternetConnectA));
    srv *s = ftp_start(); if (!s) return;
    HINTERNET hi = t_inet_open("tlrw"); HINTERNET hc = hi ? ftp_connect(hi, s) : NULL;
    CHECK(hc != NULL);
    if (hc) {
        DWORD err, alen = 0;
        U(InternetGetLastResponseInfoA)(&err, NULL, &alen);       /* bytes incl NUL */
        char abuf[512] = ""; DWORD an = sizeof abuf; U(InternetGetLastResponseInfoA)(&err, abuf, &an);
        DWORD len = 0;
        SET_ERR(0);
        BOOL r = U(InternetGetLastResponseInfoW)(&err, NULL, &len);
        DWORD gle = GetLastError();
        t_note("W size query r=%d gle=%lu len=%lu (A len incl NUL %lu)", r, gle, len, alen);
        CHECK(!r); EXPECT_EQ(gle, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(len, alen * 2);
        WCHAR w[512]; DWORD wn = 512;
        CHECK(U(InternetGetLastResponseInfoW)(&err, w, &wn));
        EXPECT_EQ(wn, an);                   /* chars excl NUL */
        WCHAR aw[512]; MultiByteToWideChar(CP_ACP, 0, abuf, -1, aw, 512);
        EXPECT_WSTR(w, aw);
        /* MultiByteToWideChar overflow: A fits the 2*(N+1)-byte scratch, W does not fit N chars */
        DWORD n2 = an;   /* strlen chars: no room for the NUL */
        SET_ERR(0);
        r = U(InternetGetLastResponseInfoW)(&err, w, &n2);
        gle = GetLastError();
        t_note("W N=strlen: r=%d gle=%lu len=%lu", r, gle, n2);
        CHECK(!r); EXPECT_EQ(gle, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(n2, an * 2);
        /* A overflow inside W: N tiny */
        DWORD n3 = 2;
        SET_ERR(0);
        r = U(InternetGetLastResponseInfoW)(&err, w, &n3);
        gle = GetLastError();
        t_note("W N=2: r=%d gle=%lu len=%lu", r, gle, n3);
        CHECK(!r); EXPECT_EQ(gle, ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(n3, alen * 2);
    }
    t_inet_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(tlr_after_ftp_command_failure) {
    REQUIRE(U(InternetGetLastResponseInfoA)); REQUIRE(U(FtpCommandA)); REQUIRE(U(InternetConnectA));
    srv *s = ftp_start(); if (!s) return;
    HINTERNET hi = t_inet_open("tlrc"); HINTERNET hc = hi ? ftp_connect(hi, s) : NULL;
    CHECK(hc != NULL);
    if (hc) {
        SET_ERR(0);
        BOOL r = U(FtpCommandA)(hc, FALSE, FTP_TRANSFER_TYPE_BINARY, "XYZZ", 0, NULL);
        DWORD gle = GetLastError();
        t_note("FtpCommand XYZZ r=%d gle=%lu", r, gle);
        CHECK(!r); EXPECT_EQ(gle, ERROR_INTERNET_EXTENDED_ERROR);
        char buf[512] = ""; DWORD n = sizeof buf, err = 0x5555;
        CHECK(U(InternetGetLastResponseInfoA)(&err, buf, &n));
        t_note("after 502: [%s] err=%lu", buf, err);
        CHECK(strstr(buf, "502") != NULL);
        CHECK(strstr(buf, "Command not implemented") != NULL);
        /* a successful command replaces the text */
        r = U(FtpCommandA)(hc, FALSE, FTP_TRANSFER_TYPE_BINARY, "NOOP", 0, NULL);
        CHECK(r);
        n = sizeof buf; buf[0] = 0;
        CHECK(U(InternetGetLastResponseInfoA)(&err, buf, &n));
        t_note("after NOOP: [%s] err=%lu", buf, err);
        CHECK(strstr(buf, "200") != NULL);
    }
    t_inet_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(tlr_after_ftp_missing_file) {
    REQUIRE(U(InternetGetLastResponseInfoA)); REQUIRE(U(FtpGetFileSize)); REQUIRE(U(FtpOpenFileA));
    srv *s = ftp_start(); if (!s) return;
    HINTERNET hi = t_inet_open("tlrm"); HINTERNET hc = hi ? ftp_connect(hi, s) : NULL;
    CHECK(hc != NULL);
    if (hc) {
        SET_ERR(0);
        HINTERNET hf = U(FtpOpenFileA)(hc, "missing.txt", GENERIC_READ, FTP_TRANSFER_TYPE_BINARY, 0);
        DWORD gle = GetLastError();
        t_note("FtpOpenFile missing: h=%p gle=%lu", hf, gle);
        CHECK(hf == NULL); EXPECT_EQ(gle, ERROR_INTERNET_EXTENDED_ERROR);
        char buf[512] = ""; DWORD n = sizeof buf, err = 0;
        CHECK(U(InternetGetLastResponseInfoA)(&err, buf, &n));
        t_note("text [%s] err=%lu", buf, err);
        CHECK(strstr(buf, "550") != NULL);
        if (hf) U(InternetCloseHandle)(hf);
    }
    t_inet_close(hc); t_inet_close(hi); srv_stop(s);
}

TEST(tlr_http_request_leaves_no_text) {
    /* HTTP transactions do not populate the per-thread response text [K]; record first */
    REQUIRE(U(InternetGetLastResponseInfoA));
    srv *s = srv_http(NULL, 0);
    if (!s) { t_skip("server unavailable"); return; }
    lr_probe q = { 0 };
    HINTERNET hi = t_inet_open("tlrh");
    char body[64]; size_t bn; DWORD e;
    EXPECT_EQ(t_http_get(hi, srv_url(s, "/x"), NULL, T_INET_FRESH, body, sizeof body, &bn, &e), 200);
    char buf[256] = "Z"; DWORD n = sizeof buf, err = 0x5555;
    BOOL r = U(InternetGetLastResponseInfoA)(&err, buf, &n);
    t_note("after HTTP GET (same thread as earlier tests): r=%d len=%lu err=%lu [%s]", r, n, err, buf);
    CHECK(r);
    t_inet_close(hi); srv_stop(s);
    (void)q;
}

/* ------------------------------------------------------------ status callback return values */
static void CALLBACK cb_a(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD n) { (void)h; (void)ctx; (void)st; (void)info; (void)n; }
static void CALLBACK cb_b(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD n) { (void)h; (void)ctx; (void)st; (void)info; (void)n; }

TEST(tcb_null_handle) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetSetStatusCallbackW));
    SET_ERR(0);
    CHECK(U(InternetSetStatusCallbackA)(NULL, cb_a) == INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    CHECK(U(InternetSetStatusCallbackW)(NULL, cb_a) == INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    SET_ERR(0);
    CHECK(U(InternetSetStatusCallbackA)(NULL, NULL) == INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}

TEST(tcb_plain_alias_null_handle) {
    REQUIRE(UN(InternetSetStatusCallback));
    SET_ERR(0);
    CHECK(UN(InternetSetStatusCallback)(NULL, cb_a) == INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}

TEST(tcb_unmapped_handles) {
    REQUIRE(U(InternetSetStatusCallbackA));
    static const ULONG_PTR hs[] = { 1, 4, 0x00CC0000, 0x00CC0004 + 4 * 50000, 0x7FFF0000 };
    for (int i = 0; i < 5; i++) {
        SET_ERR(0);
        INTERNET_STATUS_CALLBACK r = U(InternetSetStatusCallbackA)((HINTERNET)hs[i], cb_a);
        DWORD e = GetLastError();
        CHECKF(r == INTERNET_INVALID_STATUS_CALLBACK && e == ERROR_INVALID_HANDLE, "h=%p r=%p e=%lu", (void *)hs[i], (void *)r, e);
    }
}

TEST(tcb_session_exchange_sequence) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetSetStatusCallbackW));
    HINTERNET hi = t_inet_open("tcb");
    CHECK(hi != NULL); if (!hi) return;
    SET_ERR(0xdead);
    CHECK(U(InternetSetStatusCallbackA)(hi, cb_a) == NULL);   EXPECT_ERR(0);
    SET_ERR(0xdead);
    CHECK(U(InternetSetStatusCallbackA)(hi, cb_b) == cb_a);   EXPECT_ERR(0);
    SET_ERR(0xdead);
    CHECK(U(InternetSetStatusCallbackW)(hi, cb_a) == cb_b);   EXPECT_ERR(0);   /* shared slot */
    SET_ERR(0xdead);
    CHECK(U(InternetSetStatusCallbackA)(hi, NULL) == cb_a);   EXPECT_ERR(0);
    SET_ERR(0xdead);
    CHECK(U(InternetSetStatusCallbackW)(hi, NULL) == NULL);   EXPECT_ERR(0);
    CHECK(U(InternetSetStatusCallbackA)(hi, cb_a) == NULL);
    CHECK(U(InternetSetStatusCallbackA)(hi, cb_a) == cb_a);   /* same value again */
    CHECK(U(InternetSetStatusCallbackA)(hi, NULL) == cb_a);
    t_inet_close(hi);
}

TEST(tcb_closed_handle) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetCloseHandle));
    HINTERNET hi = t_inet_open("tcbc");
    CHECK(hi != NULL); if (!hi) return;
    CHECK(U(InternetCloseHandle)(hi));
    SET_ERR(0);
    CHECK(U(InternetSetStatusCallbackA)(hi, cb_a) == INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}

TEST(tcb_connect_and_request_handles) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetConnectA)); REQUIRE(U(HttpOpenRequestA));
    HINTERNET hi = t_inet_open("tcbr");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0) : NULL;
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, INTERNET_FLAG_NO_UI, 0) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        SET_ERR(0xdead); CHECK(U(InternetSetStatusCallbackA)(hc, cb_a) == NULL); EXPECT_ERR(0);
        SET_ERR(0xdead); CHECK(U(InternetSetStatusCallbackA)(hr, cb_b) == NULL); EXPECT_ERR(0);
        CHECK(U(InternetSetStatusCallbackA)(hr, NULL) == cb_b);
        CHECK(U(InternetSetStatusCallbackA)(hc, NULL) == cb_a);
        CHECK(U(InternetSetStatusCallbackA)(hi, NULL) == NULL);
    }
    t_inet_close(hr); t_inet_close(hc); t_inet_close(hi);
}

TEST(tcb_child_inherits_parent_callback) {
    /* a handle created after the parent got a callback starts with the parent's callback [K] */
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetConnectA));
    HINTERNET hi = t_inet_open("tcbi");
    CHECK(hi != NULL); if (!hi) return;
    CHECK(U(InternetSetStatusCallbackA)(hi, cb_a) == NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    CHECK(hc != NULL);
    if (hc) {
        INTERNET_STATUS_CALLBACK prev = U(InternetSetStatusCallbackA)(hc, cb_b);
        t_note("connect handle initial callback %s", prev == cb_a ? "== parent" : prev == NULL ? "NULL" : "other");
        CHECK(prev == cb_a);
        U(InternetSetStatusCallbackA)(hc, NULL);
    }
    U(InternetSetStatusCallbackA)(hi, NULL);
    t_inet_close(hc); t_inet_close(hi);
}

/* ------------------------------------------------------------ callbacks on the wire (stable subset) */
typedef struct { DWORD st[128]; DWORD_PTR ctx[128]; int n; char name_a[64]; WCHAR name_w[64]; int got_name; } cbrec;
static cbrec g_rec;
static void rec_common(DWORD_PTR ctx, DWORD st) { if (g_rec.n < 128) { g_rec.ctx[g_rec.n] = ctx; g_rec.st[g_rec.n++] = st; } }
static void CALLBACK rec_a(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD n) {
    (void)h; rec_common(ctx, st);
    if (st == INTERNET_STATUS_RESOLVING_NAME && info && !g_rec.got_name) {
        memcpy(g_rec.name_a, info, n < 63 ? n : 63); g_rec.got_name = (int)n ? (int)n : -1;
    }
}
static void CALLBACK rec_w(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD n) {
    (void)h; rec_common(ctx, st);
    if (st == INTERNET_STATUS_RESOLVING_NAME && info && !g_rec.got_name) {
        memcpy(g_rec.name_w, info, n < 126 ? n : 126); g_rec.got_name = (int)n ? (int)n : -1;
    }
}
static int rec_index(DWORD st) { for (int i = 0; i < g_rec.n; i++) if (g_rec.st[i] == st) return i; return -1; }

static void run_wire(int wide) {
    srv *s = srv_http(NULL, 0);
    if (!s) { t_skip("server unavailable"); return; }
    memset(&g_rec, 0, sizeof g_rec);
    HINTERNET hi = t_inet_open("tcbw");
    HINTERNET hc = hi ? U(InternetConnectA)(hi, "127.0.0.1", srv_port(s), NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0x11) : NULL;
    CHECK(hc != NULL);
    if (hc) {
        if (wide) U(InternetSetStatusCallbackW)(hc, rec_w); else U(InternetSetStatusCallbackA)(hc, rec_a);
        HINTERNET hr = U(HttpOpenRequestA)(hc, "GET", "/cb", NULL, NULL, NULL, T_INET_FRESH, 0x22);
        CHECK(hr != NULL);
        if (hr) {
            CHECK(U(HttpSendRequestA)(hr, NULL, 0, NULL, 0));
            char b[64]; DWORD rd = 0; U(InternetReadFile)(hr, b, sizeof b, &rd);
            U(InternetCloseHandle)(hr);
        }
        if (wide) U(InternetSetStatusCallbackW)(hc, NULL); else U(InternetSetStatusCallbackA)(hc, NULL);
    }
    char line[1024] = ""; size_t o = 0;
    for (int i = 0; i < g_rec.n && o < sizeof line - 16; i++) o += snprintf(line + o, sizeof line - o, "%lu/%lx ", g_rec.st[i], (unsigned long)g_rec.ctx[i]);
    t_note("%s callback sequence: %s", wide ? "W" : "A", line);
    int sending = rec_index(INTERNET_STATUS_SENDING_REQUEST), sent = rec_index(INTERNET_STATUS_REQUEST_SENT);
    int recv = rec_index(INTERNET_STATUS_RECEIVING_RESPONSE), rcvd = rec_index(INTERNET_STATUS_RESPONSE_RECEIVED);
    int closing = rec_index(INTERNET_STATUS_HANDLE_CLOSING);
    CHECK(sending >= 0 && sent > sending);
    CHECK(recv >= 0 && rcvd > recv && rcvd > sent);
    CHECK(closing > rcvd);
    for (int i = 0; i < g_rec.n; i++) if (g_rec.st[i] == INTERNET_STATUS_REQUEST_SENT) CHECKF(g_rec.ctx[i] == 0x22, "ctx %lx", (unsigned long)g_rec.ctx[i]);
    if (g_rec.got_name) {
        if (wide) t_note("RESOLVING_NAME W info len=%d", g_rec.got_name);
        else t_note("RESOLVING_NAME A info [%s] len=%d", g_rec.name_a, g_rec.got_name);
    } else t_note("no RESOLVING_NAME for an IP literal");
    t_inet_close(hc); t_inet_close(hi); srv_stop(s);
}
TEST(tcb_wire_sequence_a) { REQUIRE(U(InternetSetStatusCallbackA)); run_wire(0); }
TEST(tcb_wire_sequence_w) { REQUIRE(U(InternetSetStatusCallbackW)); run_wire(1); }
