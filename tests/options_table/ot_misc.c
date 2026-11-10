/* options_table: options whose value depends on what happened on the handle (socket info, extended error,
 * callback, cache file, per-connection list, request-state gates). Loopback servers only.
 * VM_TIMEOUT: 400 */
#include "ot.h"

static void CALLBACK cb(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) { (void)h; (void)ctx; (void)st; (void)info; (void)len; }

TEST(ot_misc_callback_pointer) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    void *p = (void *)1; DWORD l = sizeof p;
    CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_CALLBACK, &p, &l)); EXPECT_EQ(l, 8); EXPECT_EQ(p, NULL);
    INTERNET_STATUS_CALLBACK prev = U(InternetSetStatusCallbackA)(s, cb);
    EXPECT_EQ(prev, NULL);
    l = sizeof p; CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_CALLBACK, &p, &l)); CHECK(p == (void *)cb);
    l = sizeof p; CHECK(U(InternetQueryOptionW)(s, INTERNET_OPTION_CALLBACK, &p, &l)); CHECK(p == (void *)cb);
    HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (c) {
        l = sizeof p; CHECK(U(InternetQueryOptionA)(c, INTERNET_OPTION_CALLBACK, &p, &l));
        CHECKF(p == (void *)cb, "connect created after the callback was set: %p", p);
        U(InternetCloseHandle)(c);
    }
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_CALLBACK, &p, sizeof p), ERROR_INTERNET_OPTION_NOT_SETTABLE);
    l = 4; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(s, INTERNET_OPTION_CALLBACK, &p, &l), ERROR_INSUFFICIENT_BUFFER); EXPECT_EQ(l, 8);
    U(InternetSetStatusCallbackA)(s, NULL);
    U(InternetCloseHandle)(s);
}

TEST(ot_misc_diagnostic_socket_info) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx || !fx->h[OT_X]) { t_skip("fixture"); return; }
    INTERNET_DIAGNOSTIC_SOCKET_INFO di; DWORD l = sizeof di; memset(&di, 0xCC, sizeof di);
    BOOL r = U(InternetQueryOptionA)(fx->h[OT_X], INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l);
    /* X has been read to the end, so its connection went back to the pool: the request reports no socket
     * (INVALID_SOCKET, ports 0, flags 0) (VM, also on the unsent request R) */
    CHECKF(r, "err %lu", GetLastError());
    if (r) {
        EXPECT_EQ(l, sizeof di);
        CHECKF(di.Socket == (DWORD_PTR)~(DWORD_PTR)0 && di.SourcePort == 0 && di.DestPort == 0 && di.Flags == 0,
               "X socket info: socket=0x%llx src=%lu dst=%lu flags=0x%lx", (unsigned long long)di.Socket, di.SourcePort, di.DestPort, di.Flags);
    }
    l = sizeof di;
    SET_ERR(0); r = U(InternetQueryOptionA)(fx->h[OT_R], INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l);
    t_note("unsent R DIAGNOSTIC_SOCKET_INFO: r=%d err=%lu", r, r ? 0 : GetLastError());
    l = sizeof di;
    SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(fx->h[OT_S], INTERNET_OPTION_DIAGNOSTIC_SOCKET_INFO, &di, &l), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}

TEST(ot_misc_extended_error_after_refused_connect) {
    REQUIRE(U(HttpSendRequestA));
    /* a port that was listening a moment ago and is now closed: the connect is refused at once */
    srv *s = srv_http(NULL, 0); if (!s) { t_skip("server unavailable"); return; }
    unsigned short port = srv_port(s); srv_stop(s);
    HINTERNET hi = t_inet_open(NULL);
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH, 0) : NULL;
    if (!hr) { t_inet_close(hi); t_skip("handles"); return; }
    SET_ERR(0);
    BOOL ok = U(HttpSendRequestA)(hr, NULL, 0, NULL, 0);
    EXPECT_FAIL(!ok, ERROR_INTERNET_CANNOT_CONNECT);
    DWORD v = 0, l = sizeof v;
    CHECK(U(InternetQueryOptionA)(NULL, INTERNET_OPTION_EXTENDED_ERROR, &v, &l));
    EXPECT_EQ(l, 4);
    t_note("EXTENDED_ERROR (thread) after a refused connect: %lu", v);
    t_note("(the VM reports 997 ERROR_IO_PENDING here, not WSAECONNREFUSED)");
    l = sizeof v; CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_EXTENDED_ERROR, &v, &l));
    t_note("EXTENDED_ERROR via the request handle: %lu", v);
    DWORD z = 0;
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(NULL, INTERNET_OPTION_EXTENDED_ERROR, &z, 4), ERROR_INTERNET_INVALID_OPTION);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); t_inet_close(hi);
}

TEST(ot_misc_request_state_gates) {
    REQUIRE(U(InternetSetOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx || !fx->h[OT_X]) { t_skip("fixture"); return; }
    ot_trio t; if (!ot_trio_open(&t, 0)) { ot_trio_close(&t); t_skip("handles"); return; }
    /* SUPPRESS_SERVER_AUTH (104), 167, 182: buffer-less, request only, before the request is sent */
    static const DWORD opts[] = { 104, 167, 182 };
    for (int i = 0; i < 3; i++) {
        CHECK(U(InternetSetOptionA)(t.r, opts[i], NULL, 0));
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(fx->h[OT_X], opts[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_STATE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.c, opts[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
        SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(t.s, opts[i], NULL, 0), ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    ot_trio_close(&t);
}

TEST(ot_misc_per_connection_option_session) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET s = U(InternetOpenA)(OT_AGENT, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!s) { t_skip("InternetOpen"); return; }
    INTERNET_PER_CONN_OPTIONA o[1]; INTERNET_PER_CONN_OPTION_LISTA list;
    memset(o, 0, sizeof o); memset(&list, 0, sizeof list);
    o[0].dwOption = INTERNET_PER_CONN_FLAGS;
    list.dwSize = sizeof list; list.pszConnection = NULL; list.dwOptionCount = 1; list.pOptions = o;
    DWORD l = sizeof list;
    BOOL r = U(InternetQueryOptionA)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &l);
    CHECKF(r, "err %lu", GetLastError());
    if (r) { t_note("DIRECT session PER_CONN_FLAGS 0x%lx", o[0].Value.dwValue); CHECK(o[0].Value.dwValue & PROXY_TYPE_DIRECT); }
    /* argument checks (case 0x4b): NULL buffer 87, short length 122 or 12010 */
    l = sizeof list; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionA)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, &l), ERROR_INVALID_PARAMETER);
    l = 8; SET_ERR(0); r = U(InternetQueryOptionA)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &l);
    CHECK(!r); t_note("PER_CONNECTION_OPTION with len 8: err %lu len %lu", GetLastError(), l);
    /* set with a short list fails before anything is written */
    l = 8; SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, 8), ERROR_INTERNET_BAD_OPTION_LENGTH);
    SET_ERR(0); EXPECT_FAIL(!U(InternetSetOptionA)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, 0), ERROR_INVALID_PARAMETER);
    /* W */
    INTERNET_PER_CONN_OPTIONW ow[1]; INTERNET_PER_CONN_OPTION_LISTW lw;
    memset(ow, 0, sizeof ow); memset(&lw, 0, sizeof lw);
    ow[0].dwOption = INTERNET_PER_CONN_FLAGS; lw.dwSize = sizeof lw; lw.dwOptionCount = 1; lw.pOptions = ow;
    l = sizeof lw;
    r = U(InternetQueryOptionW)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, &lw, &l);
    CHECKF(r, "W err %lu", GetLastError());
    if (r) CHECK(ow[0].Value.dwValue & PROXY_TYPE_DIRECT);
    l = 0x1f; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, &lw, &l), ERROR_INTERNET_BAD_OPTION_LENGTH);
    l = sizeof lw; SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(s, INTERNET_OPTION_PER_CONNECTION_OPTION, NULL, &l), ERROR_INVALID_PARAMETER);
    U(InternetCloseHandle)(s);
}

TEST(ot_misc_datafile_name_cached_download) {
    REQUIRE(U(InternetQueryOptionA));
    REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n", "cached-body"), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    char path[96]; snprintf(path, sizeof path, "/%s.txt", t_uniq("dfn"));
    const char *url = srv_url(s, path);
    t_cache_track(url);
    HINTERNET hu = U(InternetOpenUrlA)(hi, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0);
    CHECK(hu != NULL);
    if (hu) {
        char b[64]; t_inet_read_all(hu, b, sizeof b, NULL);
        EXPECT_STR(b, "cached-body");
        char fn[MAX_PATH * 2]; DWORD l = 0;
        SET_ERR(0); BOOL r = U(InternetQueryOptionA)(hu, INTERNET_OPTION_DATAFILE_NAME, NULL, &l);
        if (!r && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            DWORD need = l; l = sizeof fn;
            CHECK(U(InternetQueryOptionA)(hu, INTERNET_OPTION_DATAFILE_NAME, fn, &l));
            CHECKF(l == need - 1 && strlen(fn) == l, "len %lu need %lu", l, need);
            CHECK(GetFileAttributesA(fn) != INVALID_FILE_ATTRIBUTES);
            t_note("DATAFILE_NAME '%s'", fn);
            WCHAR fw[MAX_PATH * 2]; DWORD lw = 0;
            SET_ERR(0); EXPECT_FAIL(!U(InternetQueryOptionW)(hu, INTERNET_OPTION_DATAFILE_NAME, NULL, &lw), ERROR_INSUFFICIENT_BUFFER);
            EXPECT_EQ(lw, need * 2);
            lw = sizeof fw; CHECK(U(InternetQueryOptionW)(hu, INTERNET_OPTION_DATAFILE_NAME, fw, &lw));
            EXPECT_EQ(lw, need - 1);
        } else t_note("DATAFILE_NAME NULL query: r=%d err=%lu len=%lu", r, GetLastError(), l);
        U(InternetCloseHandle)(hu);
    }
    /* a request that did not write the cache has no data file */
    ot_fx *fx = ot_fx_all();
    if (fx && fx->h[OT_X]) {
        char fn[MAX_PATH]; DWORD l = sizeof fn;
        SET_ERR(0); BOOL r = U(InternetQueryOptionA)(fx->h[OT_X], INTERNET_OPTION_DATAFILE_NAME, fn, &l);
        CHECK(!r); t_note("DATAFILE_NAME on a NO_CACHE_WRITE request: err %lu", GetLastError());
    }
    t_inet_close(hi);
    t_net_cleanup();
    srv_stop(s);
}

TEST(ot_misc_request_flags_from_cache) {
    REQUIRE(U(InternetQueryOptionA));
    REQUIRE(U(DeleteUrlCacheEntryA));
    static const srv_step st[] = { S_HEAD(), S_REPLY(200, "Content-Type: text/plain\r\nCache-Control: max-age=600\r\n", "cache-me"), S_LOOP() };
    srv *s = srv_http(st, 3); if (!s) { t_skip("server unavailable"); return; }
    HINTERNET hi = t_inet_open(NULL);
    char path[96]; snprintf(path, sizeof path, "/%s.txt", t_uniq("rqf"));
    const char *url = srv_url(s, path);
    t_cache_track(url);
    char b[64];
    HINTERNET h1 = U(InternetOpenUrlA)(hi, url, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0);
    if (h1) { t_inet_read_all(h1, b, sizeof b, NULL); DWORD f; CHECK(ot_qdw(h1, INTERNET_OPTION_REQUEST_FLAGS, &f)); t_note("network fetch REQUEST_FLAGS 0x%lx", f);
              CHECK(!(f & INTERNET_REQFLAG_FROM_CACHE)); U(InternetCloseHandle)(h1); }
    HINTERNET h2 = U(InternetOpenUrlA)(hi, url, NULL, 0, INTERNET_FLAG_FROM_CACHE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES, 0);
    if (h2) { t_inet_read_all(h2, b, sizeof b, NULL); EXPECT_STR(b, "cache-me");
              DWORD f; CHECK(ot_qdw(h2, INTERNET_OPTION_REQUEST_FLAGS, &f)); t_note("cache read REQUEST_FLAGS 0x%lx", f);
              CHECK(f & INTERNET_REQFLAG_FROM_CACHE); U(InternetCloseHandle)(h2); }
    else t_note("FROM_CACHE open failed %lu", GetLastError());
    CHECK(srv_req_count(s) == 1);
    t_inet_close(hi);
    t_net_cleanup();
    srv_stop(s);
}

TEST(ot_misc_keep_connection_connect_only) {
    REQUIRE(U(InternetQueryOptionA));
    ot_fx *fx = ot_fx_all(); if (!fx) { t_skip("fixture"); return; }
    DWORD v, l;
    for (int k = 0; k < OT_NK; k++) {
        if (k == OT_N || !fx->h[k]) continue;
        l = sizeof v; SET_ERR(0);
        BOOL r = U(InternetQueryOptionA)(fx->h[k], INTERNET_OPTION_KEEP_CONNECTION, &v, &l);
        if (k == OT_C) { CHECK(r); EXPECT_EQ(l, 4); t_note("HCon KEEP_CONNECTION %lu", v); }
        else CHECKF(!r && GetLastError() == ERROR_INTERNET_INCORRECT_HANDLE_TYPE, "kind %c r=%d err=%lu", OT_KINDS[k], r, GetLastError());
    }
}
