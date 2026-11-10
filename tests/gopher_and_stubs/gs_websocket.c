/* HttpWebSocket* exports: argument validation and wrong-handle paths only (no upgrade is ever completed: that needs
 * a 101 response, which belongs to a wire-level area). No other area of the corpus calls these exports.
 *
 * [D HttpWebSocketSend/Receive/Close/Shutdown/QueryCloseStatus @0x1788b0/0x178300/0x177830/0x178ba0/0x1779a0]
 *   BOOL wrappers: r = Internal...(); SetLastError(r) ALWAYS (so success leaves GLE 0); return r == 0.
 * [D InternalWebSocket*] buffer/length consistency checks come BEFORE the handle is mapped, so they win over a bad
 *   handle (87); then MapHandleToAddress (NULL / unknown -> ERROR_INVALID_HANDLE) and RIsHandleLocal with the
 *   web-socket tag (any other handle kind -> ERROR_INTERNET_INCORRECT_HANDLE_TYPE).
 * [D InternalWebSocketCompleteUpgrade] handle mapped as an HTTP request ('HReq'); a request that never received a
 *   101 -> ERROR_INTERNET_INCORRECT_HANDLE_STATE (0x2ef3); returns NULL with SetLastError on failure.
 * VM_TIMEOUT: 60 */
#include "gs.h"

UDECL(HINTERNET, HttpWebSocketCompleteUpgrade, (HINTERNET, DWORD_PTR));
UDECL(BOOL, HttpWebSocketSend, (HINTERNET, DWORD, PVOID, DWORD));
UDECL(BOOL, HttpWebSocketReceive, (HINTERNET, PVOID, DWORD, DWORD *, DWORD *));
UDECL(BOOL, HttpWebSocketClose, (HINTERNET, USHORT, PVOID, DWORD));
UDECL(BOOL, HttpWebSocketShutdown, (HINTERNET, USHORT, PVOID, DWORD));
UDECL(BOOL, HttpWebSocketQueryCloseStatus, (HINTERNET, USHORT *, PVOID, DWORD, DWORD *));

#define GS_WS_BINARY_MESSAGE 0
#define GS_WS_UTF8_MESSAGE   2
#define GS_WS_CLOSE          4

#define REQUIRE_WS() do { REQUIRE(UN(HttpWebSocketSend)); REQUIRE(UN(HttpWebSocketReceive)); REQUIRE(UN(HttpWebSocketClose)); \
    REQUIRE(UN(HttpWebSocketShutdown)); REQUIRE(UN(HttpWebSocketQueryCloseStatus)); REQUIRE(UN(HttpWebSocketCompleteUpgrade)); } while (0)

/* ================================================================== Send */
TEST(gs_ws_send_length_mismatch_first) {
    REQUIRE_WS();
    char b[8] = "abc";
    HINTERNET hs[2] = { NULL, gs_session() };
    for (int i = 0; i < 2; i++) {
        SET_ERR(0x4242);
        CHECK(!UN(HttpWebSocketSend)(hs[i], GS_WS_BINARY_MESSAGE, NULL, 5)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0x4242);
        CHECK(!UN(HttpWebSocketSend)(hs[i], GS_WS_UTF8_MESSAGE, b, 0));     EXPECT_ERR(ERROR_INVALID_PARAMETER);
        SET_ERR(0x4242);
        CHECK(!UN(HttpWebSocketSend)(hs[i], 0xFFFFFFFFu, NULL, 0xFFFFFFFFu)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
}

TEST(gs_ws_send_bad_handles) {
    REQUIRE_WS();
    char b[8] = "abc";
    SET_ERR(0);
    CHECK(!UN(HttpWebSocketSend)(NULL, GS_WS_BINARY_MESSAGE, b, 3)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    SET_ERR(0);
    CHECK(!UN(HttpWebSocketSend)(NULL, GS_WS_BINARY_MESSAGE, NULL, 0)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    HINTERNET s = gs_session(), c = gs_connect_http(s), r = gs_request(c, "/gs_ws");
    HINTERNET hs[3] = { s, c, r };
    for (int i = 0; i < 3; i++) {
        if (!hs[i]) continue;
        SET_ERR(0);
        CHECKF(!UN(HttpWebSocketSend)(hs[i], GS_WS_BINARY_MESSAGE, b, 3), "handle kind %d", i);
        EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
    }
    if (r) U(InternetCloseHandle)(r);
    if (c) U(InternetCloseHandle)(c);
    /* a closed handle is unknown again */
    if (r) { SET_ERR(0); CHECK(!UN(HttpWebSocketSend)(r, GS_WS_BINARY_MESSAGE, b, 3)); EXPECT_ERR(ERROR_INVALID_HANDLE); }
}

/* ================================================================== Receive: every out/buffer argument required */
TEST(gs_ws_receive_args) {
    REQUIRE_WS();
    char b[16]; DWORD n = 0xA5A5, t = 0xA5A5;
    for (int hk = 0; hk < 2; hk++) {
        HINTERNET h = hk ? gs_session() : NULL;
        for (int mask = 0; mask < 15; mask++) {           /* 15 = all four present: handled below */
            n = 0xA5A5; t = 0xA5A5;
            SET_ERR(0x4242);
            BOOL ok = UN(HttpWebSocketReceive)(h, (mask & 1) ? b : NULL, (mask & 2) ? (DWORD)sizeof b : 0,
                                               (mask & 4) ? &n : NULL, (mask & 8) ? &t : NULL);
            DWORD e = GetLastError();
            CHECKF(!ok && e == ERROR_INVALID_PARAMETER, "hk=%d mask=%d ok=%d e=%lu", hk, mask, ok, e);
            CHECK(n == 0xA5A5 && t == 0xA5A5);
        }
        SET_ERR(0);
        BOOL ok = UN(HttpWebSocketReceive)(h, b, sizeof b, &n, &t);
        DWORD e = GetLastError();
        CHECK(!ok);
        CHECKF(e == (hk ? ERROR_INTERNET_INCORRECT_HANDLE_TYPE : ERROR_INVALID_HANDLE), "hk=%d e=%lu", hk, e);
        CHECK(n == 0xA5A5 && t == 0xA5A5);
    }
}

/* ================================================================== Close / Shutdown
 * reason NULL with a length, or a reason with length 0 -> 87; length >= 124 -> 87; status < 1000 -> 87;
 * only then the handle. */
typedef BOOL (WINAPI *gs_ws_close_fn)(HINTERNET, USHORT, PVOID, DWORD);
static void gs_ws_close_table(gs_ws_close_fn f, const char *label) {
    char reason[200]; memset(reason, 'r', sizeof reason);
    static const struct { USHORT st; int has; DWORD len; DWORD want_null; } t[] = {
        { 1000, 0, 0, ERROR_INVALID_HANDLE },
        { 1000, 1, 5, ERROR_INVALID_HANDLE },
        { 1001, 1, 123, ERROR_INVALID_HANDLE },
        { 4999, 0, 0, ERROR_INVALID_HANDLE },
        { 65535, 1, 1, ERROR_INVALID_HANDLE },
        { 999, 0, 0, ERROR_INVALID_PARAMETER },
        { 0, 0, 0, ERROR_INVALID_PARAMETER },
        { 1, 1, 5, ERROR_INVALID_PARAMETER },
        { 1000, 1, 124, ERROR_INVALID_PARAMETER },
        { 1000, 1, 125, ERROR_INVALID_PARAMETER },
        { 1000, 1, 0xFFFFFFFFu, ERROR_INVALID_PARAMETER },
        { 1000, 0, 5, ERROR_INVALID_PARAMETER },
        { 1000, 1, 0, ERROR_INVALID_PARAMETER },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SET_ERR(0x4242);
        BOOL ok = f(NULL, t[i].st, t[i].has ? reason : NULL, t[i].len);
        DWORD e = GetLastError();
        CHECKF(!ok && e == t[i].want_null, "%s row %zu (st=%u len=%lu): ok=%d e=%lu want %lu", label, i, t[i].st, t[i].len, ok, e, t[i].want_null);
        /* a session handle: wrong type once the arguments are fine */
        SET_ERR(0x4242);
        ok = f(gs_session(), t[i].st, t[i].has ? reason : NULL, t[i].len);
        e = GetLastError();
        DWORD want = t[i].want_null == ERROR_INVALID_HANDLE ? ERROR_INTERNET_INCORRECT_HANDLE_TYPE : ERROR_INVALID_PARAMETER;
        CHECKF(!ok && e == want, "%s session row %zu: ok=%d e=%lu want %lu", label, i, ok, e, want);
    }
}
TEST(gs_ws_close_table)    { REQUIRE_WS(); gs_ws_close_table(UN(HttpWebSocketClose), "Close"); }
TEST(gs_ws_shutdown_table) { REQUIRE_WS(); gs_ws_close_table(UN(HttpWebSocketShutdown), "Shutdown"); }

/* ================================================================== QueryCloseStatus
 * status out and consumed-length out required; reason buffer/length consistent; then the handle. */
TEST(gs_ws_query_close_status_args) {
    REQUIRE_WS();
    USHORT st = 0xA5A5; char reason[64]; DWORD used = 0xA5A5;
    static const struct { int st, rs; DWORD len; int used; DWORD want; } t[] = {
        { 1, 1, 64, 1, ERROR_INVALID_HANDLE },
        { 1, 0, 0, 1, ERROR_INVALID_HANDLE },
        { 0, 1, 64, 1, ERROR_INVALID_PARAMETER },
        { 1, 1, 64, 0, ERROR_INVALID_PARAMETER },
        { 0, 0, 0, 0, ERROR_INVALID_PARAMETER },
        { 1, 0, 64, 1, ERROR_INVALID_PARAMETER },
        { 1, 1, 0, 1, ERROR_INVALID_PARAMETER },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        st = 0xA5A5; used = 0xA5A5;
        SET_ERR(0x4242);
        BOOL ok = UN(HttpWebSocketQueryCloseStatus)(NULL, t[i].st ? &st : NULL, t[i].rs ? reason : NULL, t[i].len, t[i].used ? &used : NULL);
        DWORD e = GetLastError();
        CHECKF(!ok && e == t[i].want, "row %zu: ok=%d e=%lu want %lu", i, ok, e, t[i].want);
        CHECK(st == 0xA5A5 && used == 0xA5A5);
    }
    SET_ERR(0);
    CHECK(!UN(HttpWebSocketQueryCloseStatus)(gs_session(), &st, reason, sizeof reason, &used));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}

/* ================================================================== CompleteUpgrade */
TEST(gs_ws_complete_upgrade_bad_handles) {
    REQUIRE_WS();
    SET_ERR(0);
    HINTERNET w = UN(HttpWebSocketCompleteUpgrade)(NULL, 0);
    CHECK(w == NULL); EXPECT_ERR(ERROR_INVALID_HANDLE);
    HINTERNET s = gs_session(), c = gs_connect_http(s);
    if (s) { SET_ERR(0); w = UN(HttpWebSocketCompleteUpgrade)(s, 1); CHECK(w == NULL); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (c) { SET_ERR(0); w = UN(HttpWebSocketCompleteUpgrade)(c, 1); CHECK(w == NULL); EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE); }
    if (c) U(InternetCloseHandle)(c);
}

TEST(gs_ws_complete_upgrade_unsent_request) {
    REQUIRE_WS();
    HINTERNET c = gs_connect_http(gs_session());
    HINTERNET r = gs_request(c, "/gs_ws_upgrade");
    if (!r) { t_skip("no request"); if (c) U(InternetCloseHandle)(c); return; }
    for (int i = 0; i < 2; i++) {
        SET_ERR(0);
        HINTERNET w = UN(HttpWebSocketCompleteUpgrade)(r, (DWORD_PTR)i);
        CHECK(w == NULL);
        EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_STATE);
        if (w) U(InternetCloseHandle)(w);
    }
    /* the request handle is still usable afterwards */
    DWORD t = 0, l = sizeof t;
    CHECK(U(InternetQueryOptionA)(r, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
    EXPECT_EQ(t, INTERNET_HANDLE_TYPE_HTTP_REQUEST);
    U(InternetCloseHandle)(r);
    U(InternetCloseHandle)(c);
}

/* a request that may upgrade: the WebSocket option exists and can be set before sending */
TEST(gs_ws_upgrade_option_on_request) {
    REQUIRE_WS(); REQUIRE(U(InternetSetOptionA));
    HINTERNET c = gs_connect_http(gs_session());
    HINTERNET r = gs_request(c, "/gs_ws_opt");
    if (!r) { t_skip("no request"); if (c) U(InternetCloseHandle)(c); return; }
    SET_ERR(0);
    BOOL ok = U(InternetSetOptionA)(r, 103 /* INTERNET_OPTION_UPGRADE_TO_WEB_SOCKET */, NULL, 0);
    t_note("INTERNET_OPTION_UPGRADE_TO_WEB_SOCKET on an unsent request: ok=%d e=%lu", ok, ok ? 0 : GetLastError());
    /* still not upgradable before a 101 */
    SET_ERR(0);
    CHECK(UN(HttpWebSocketCompleteUpgrade)(r, 0) == NULL);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_STATE);
    U(InternetCloseHandle)(r);
    U(InternetCloseHandle)(c);
}
