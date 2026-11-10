/* Gopher (removed in IE7+/WinINet 7) and the other exports folded onto the same stub.
 *
 * [D GopherCreateLocatorA@0x138810] one shared body for GopherCreateLocatorA/W, GopherFindFirstFileA/W,
 * GopherGetAttributeA/W, GopherGetLocatorTypeA/W, GopherOpenFileA/W, InternetWriteFileExA/W and
 * LoadUrlCacheContent:   SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return 0;
 * No argument is read, so the result is the same for every argument combination, every handle kind and
 * every thread, and no output buffer is written. Gopher is also gone from the protocol layer:
 * [D InternetConnectA@0x138070, InternetConnectW@0xc5a70] only INTERNET_SERVICE_FTP (1) and HTTP (3) are
 * accepted; anything else (GOPHER = 2) fails with ERROR_INVALID_PARAMETER before the handle is used.
 * VM_TIMEOUT: 120 */
#include "gs.h"

static const DWORD gs_gopher_types[] = {
    0, GOPHER_TYPE_TEXT_FILE, GOPHER_TYPE_DIRECTORY, GOPHER_TYPE_CSO, GOPHER_TYPE_ERROR, GOPHER_TYPE_MAC_BINHEX,
    GOPHER_TYPE_DOS_ARCHIVE, GOPHER_TYPE_UNIX_UUENCODED, GOPHER_TYPE_INDEX_SERVER, GOPHER_TYPE_TELNET,
    GOPHER_TYPE_BINARY, GOPHER_TYPE_REDUNDANT, GOPHER_TYPE_TN3270, GOPHER_TYPE_GIF, GOPHER_TYPE_IMAGE,
    GOPHER_TYPE_BITMAP, GOPHER_TYPE_MOVIE, GOPHER_TYPE_SOUND, GOPHER_TYPE_HTML, GOPHER_TYPE_PDF,
    GOPHER_TYPE_CALENDAR, GOPHER_TYPE_INLINE, GOPHER_TYPE_UNKNOWN, GOPHER_TYPE_ASK, GOPHER_TYPE_GOPHER_PLUS,
    GOPHER_TYPE_TEXT_FILE | GOPHER_TYPE_GOPHER_PLUS, 0xFFFFFFFFu,
};
#define NTYPES (sizeof gs_gopher_types / sizeof gs_gopher_types[0])

/* ------------------------------------------------------------------------------------------ presence */
TEST(gs_gopher_all_exports_resolve) {
    static const char *names[] = {
        "GopherCreateLocatorA", "GopherCreateLocatorW", "GopherFindFirstFileA", "GopherFindFirstFileW",
        "GopherGetAttributeA", "GopherGetAttributeW", "GopherGetLocatorTypeA", "GopherGetLocatorTypeW",
        "GopherOpenFileA", "GopherOpenFileW", "InternetWriteFileExA", "InternetWriteFileExW", "LoadUrlCacheContent",
    };
    FARPROC first = NULL;
    int same = 1;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        FARPROC p = t_proc_in("wininet.dll", names[i]);
        CHECKF(p != NULL, "%s missing", names[i]);
        if (!first) first = p; else if (p != first) same = 0;
    }
    /* linker folding is an implementation detail: note only */
    t_note("gopher/writefileex/loadurlcachecontent share one address: %s", same ? "yes" : "no");
}

TEST(gs_gopher_no_unicode_free_variants) {
    /* there are no undecorated Gopher names in the export table */
    static const char *absent[] = { "GopherCreateLocator", "GopherFindFirstFile", "GopherGetAttribute",
                                    "GopherGetLocatorType", "GopherOpenFile", "InternetWriteFileEx",
                                    "GopherFindNextFile", "GopherConnect" };
    for (size_t i = 0; i < sizeof absent / sizeof absent[0]; i++) {
        SET_ERR(0);
        CHECKF(GetProcAddress(t_module("wininet.dll"), absent[i]) == NULL, "%s unexpectedly exported", absent[i]);
        EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    }
}

/* ------------------------------------------------------------------------------- GopherCreateLocator */
TEST(gs_gopher_create_locator_a_types) {
    REQUIRE(U(GopherCreateLocatorA));
    for (size_t i = 0; i < NTYPES; i++) {
        char buf[256]; DWORD len = sizeof buf;
        gs_fill(buf, sizeof buf);
        SET_ERR(0);
        BOOL r = U(GopherCreateLocatorA)("127.0.0.1", 70, "display", "/selector", gs_gopher_types[i], buf, &len);
        CHECKF(!r, "type 0x%lx returned TRUE", gs_gopher_types[i]);
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        CHECKF(len == sizeof buf, "type 0x%lx len changed to %lu", gs_gopher_types[i], len);
        CHECKF(gs_untouched(buf, sizeof buf), "type 0x%lx wrote the buffer", gs_gopher_types[i]);
    }
}

TEST(gs_gopher_create_locator_w_types) {
    REQUIRE(U(GopherCreateLocatorW));
    for (size_t i = 0; i < NTYPES; i++) {
        WCHAR buf[128]; DWORD len = 128;
        gs_fill(buf, sizeof buf);
        SET_ERR(0);
        BOOL r = U(GopherCreateLocatorW)(L"127.0.0.1", 70, L"display", L"/selector", gs_gopher_types[i], buf, &len);
        CHECKF(!r, "type 0x%lx returned TRUE", gs_gopher_types[i]);
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        CHECKF(len == 128, "type 0x%lx len changed to %lu", gs_gopher_types[i], len);
        CHECKF(gs_untouched(buf, sizeof buf), "type 0x%lx wrote the buffer", gs_gopher_types[i]);
    }
}

typedef struct { const char *host; INTERNET_PORT port; const char *disp; const char *sel; int use_buf; DWORD len; int null_len; } gs_loc_case;
static const gs_loc_case gs_loc_cases[] = {
    { "127.0.0.1", 70, "d", "s", 1, 256, 0 },
    { "127.0.0.1", 0, NULL, NULL, 1, 256, 0 },
    { "127.0.0.1", 65535, "", "", 1, 256, 0 },
    { "", 70, "d", "s", 1, 256, 0 },
    { NULL, 70, "d", "s", 1, 256, 0 },
    { NULL, 0, NULL, NULL, 0, 0, 0 },
    { NULL, 0, NULL, NULL, 0, 0, 1 },
    { "127.0.0.1", 70, "d", "s", 0, 256, 0 },      /* size query */
    { "127.0.0.1", 70, "d", "s", 1, 0, 0 },        /* zero-length buffer */
    { "127.0.0.1", 70, "d", "s", 1, 1, 0 },        /* one byte */
    { "127.0.0.1", 70, "d", "s", 1, 256, 1 },      /* NULL length pointer */
    { "host.invalid", 7070, "a b c", "1/dir/x", 1, 256, 0 },
    { "[::1]", 70, "d", "s", 1, 256, 0 },
};

TEST(gs_gopher_create_locator_a_args) {
    REQUIRE(U(GopherCreateLocatorA));
    for (size_t i = 0; i < sizeof gs_loc_cases / sizeof gs_loc_cases[0]; i++) {
        const gs_loc_case *c = &gs_loc_cases[i];
        for (size_t s = 0; s < GS_NSEEDS; s++) {
            char buf[256]; DWORD len = c->len;
            gs_fill(buf, sizeof buf);
            SET_ERR(gs_seeds[s]);
            BOOL r = U(GopherCreateLocatorA)(c->host, c->port, c->disp, c->sel, GOPHER_TYPE_TEXT_FILE,
                                             c->use_buf ? buf : NULL, c->null_len ? NULL : &len);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "case %zu seed %lu: r=%d e=%lu", i, gs_seeds[s], r, e);
            CHECKF(len == c->len, "case %zu: len changed %lu", i, len);
            CHECKF(gs_untouched(buf, sizeof buf), "case %zu: buffer written", i);
        }
    }
}

TEST(gs_gopher_create_locator_w_args) {
    REQUIRE(U(GopherCreateLocatorW));
    static const WCHAR *hosts[] = { L"127.0.0.1", L"", NULL, L"host.invalid" };
    static const INTERNET_PORT ports[] = { 0, 70, 65535 };
    for (size_t h = 0; h < 4; h++)
        for (size_t p = 0; p < 3; p++)
            for (int nb = 0; nb < 2; nb++) {
                WCHAR buf[64]; DWORD len = nb ? 0 : 64;
                gs_fill(buf, sizeof buf);
                SET_ERR(0x4242);
                BOOL r = U(GopherCreateLocatorW)(hosts[h], ports[p], h & 1 ? NULL : L"disp", h & 2 ? NULL : L"sel",
                                                 GOPHER_TYPE_DIRECTORY, nb ? NULL : buf, &len);
                DWORD e = GetLastError();
                CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "h=%zu p=%zu nb=%d r=%d e=%lu", h, p, nb, r, e);
                CHECKF(len == (DWORD)(nb ? 0 : 64), "len changed %lu", len);
                CHECK(gs_untouched(buf, sizeof buf));
            }
}

/* ------------------------------------------------------------------------------ GopherGetLocatorType */
static const char *gs_locators_a[] = {
    "0Text\t/t.txt\t127.0.0.1\t70\r\n", "1Dir\t/\t127.0.0.1\t70\r\n", "", "x", "9bin\t/b\th\t70",
    "1\t\t\t", "+plus\t/p\th\t70\t+", NULL,
};
TEST(gs_gopher_get_locator_type_a) {
    REQUIRE(U(GopherGetLocatorTypeA));
    for (size_t i = 0; i < sizeof gs_locators_a / sizeof gs_locators_a[0]; i++) {
        for (int nullout = 0; nullout < 2; nullout++) {
            DWORD type = 0xA5A5A5A5u;
            SET_ERR(0);
            BOOL r = U(GopherGetLocatorTypeA)(gs_locators_a[i], nullout ? NULL : &type);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "locator %zu nullout=%d r=%d e=%lu", i, nullout, r, e);
            CHECKF(type == 0xA5A5A5A5u, "locator %zu: type written 0x%lx", i, type);
        }
    }
}

TEST(gs_gopher_get_locator_type_w) {
    REQUIRE(U(GopherGetLocatorTypeW));
    static const WCHAR *locs[] = { L"0Text\t/t.txt\t127.0.0.1\t70\r\n", L"1Dir\t/\th\t70", L"", L"x", NULL };
    for (size_t i = 0; i < sizeof locs / sizeof locs[0]; i++) {
        for (int nullout = 0; nullout < 2; nullout++) {
            DWORD type = 0xA5A5A5A5u;
            SET_ERR(87);
            BOOL r = U(GopherGetLocatorTypeW)(locs[i], nullout ? NULL : &type);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "locator %zu r=%d e=%lu", i, r, e);
            CHECK(type == 0xA5A5A5A5u);
        }
    }
}

/* ---------------------------------------------------------------- handle-taking Gopher functions */
/* hk: 0 = NULL, 1 = session handle, 2 = HTTP connect handle, 3 = request handle */
static HINTERNET gs_handle_kind(int hk, HINTERNET *owned_c, HINTERNET *owned_r) {
    *owned_c = *owned_r = NULL;
    if (hk == 0) return NULL;
    HINTERNET s = gs_session();
    if (hk == 1) return s;
    *owned_c = gs_connect_http(s);
    if (hk == 2) return *owned_c;
    *owned_r = gs_request(*owned_c, "/gs_gopher");
    return *owned_r;
}
static void gs_handle_release(HINTERNET c, HINTERNET r) {
    if (r) U(InternetCloseHandle)(r);
    if (c) U(InternetCloseHandle)(c);
}

TEST(gs_gopher_find_first_a_handles) {
    REQUIRE(U(GopherFindFirstFileA)); REQUIRE(U(InternetOpenA));
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) { t_note("handle kind %d unavailable", hk); continue; }
        static const char *locs[] = { NULL, "", "1Dir\t/\t127.0.0.1\t70" };
        static const char *search[] = { NULL, "", "query" };
        for (int l = 0; l < 3; l++) for (int q = 0; q < 3; q++) for (int fd = 0; fd < 2; fd++) {
            GOPHER_FIND_DATAA d; gs_fill(&d, sizeof d);
            SET_ERR(0);
            HINTERNET r = U(GopherFindFirstFileA)(h, locs[l], search[q], fd ? &d : NULL,
                                                 INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0x1234);
            DWORD e = GetLastError();
            CHECKF(r == NULL && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d l=%d q=%d fd=%d r=%p e=%lu", hk, l, q, fd, r, e);
            CHECKF(gs_untouched(&d, sizeof d), "hk=%d: find data written", hk);
        }
        gs_handle_release(c, rq);
    }
}

TEST(gs_gopher_find_first_w_handles) {
    REQUIRE(U(GopherFindFirstFileW)); REQUIRE(U(InternetOpenA));
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) { t_note("handle kind %d unavailable", hk); continue; }
        static const WCHAR *locs[] = { NULL, L"", L"1Dir\t/\t127.0.0.1\t70" };
        for (int l = 0; l < 3; l++) for (int fd = 0; fd < 2; fd++) {
            GOPHER_FIND_DATAW d; gs_fill(&d, sizeof d);
            SET_ERR(0x4242);
            HINTERNET r = U(GopherFindFirstFileW)(h, locs[l], l ? L"q" : NULL, fd ? &d : NULL, 0, 0);
            DWORD e = GetLastError();
            CHECKF(r == NULL && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d l=%d fd=%d r=%p e=%lu", hk, l, fd, r, e);
            CHECK(gs_untouched(&d, sizeof d));
        }
        gs_handle_release(c, rq);
    }
}

TEST(gs_gopher_find_first_flags_table) {
    REQUIRE(U(GopherFindFirstFileA));
    HINTERNET s = gs_session();
    static const DWORD flags[] = { 0, INTERNET_FLAG_RELOAD, INTERNET_FLAG_ASYNC, INTERNET_FLAG_NO_UI, INTERNET_FLAG_OFFLINE,
                                   INTERNET_FLAG_RESYNCHRONIZE, INTERNET_FLAG_HYPERLINK, INTERNET_FLAG_NEED_FILE,
                                   INTERNET_FLAG_NO_CACHE_WRITE, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++) {
        GOPHER_FIND_DATAA d; gs_fill(&d, sizeof d);
        SET_ERR(0);
        CHECKF(U(GopherFindFirstFileA)(s, "1x\t/\th\t70", NULL, &d, flags[i], 0) == NULL, "flags 0x%lx", flags[i]);
        EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        CHECK(gs_untouched(&d, sizeof d));
    }
}

TEST(gs_gopher_open_file_a) {
    REQUIRE(U(GopherOpenFileA)); REQUIRE(U(InternetOpenA));
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) continue;
        static const char *locs[] = { NULL, "", "0File\t/f.txt\t127.0.0.1\t70" };
        static const char *views[] = { NULL, "", "text/plain" };
        for (int l = 0; l < 3; l++) for (int v = 0; v < 3; v++) {
            SET_ERR(0xDEADBEEFu);
            HINTERNET r = U(GopherOpenFileA)(h, locs[l], views[v], INTERNET_FLAG_RELOAD, 7);
            DWORD e = GetLastError();
            CHECKF(r == NULL && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d l=%d v=%d r=%p e=%lu", hk, l, v, r, e);
        }
        gs_handle_release(c, rq);
    }
}

TEST(gs_gopher_open_file_w) {
    REQUIRE(U(GopherOpenFileW)); REQUIRE(U(InternetOpenA));
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) continue;
        static const WCHAR *locs[] = { NULL, L"", L"0File\t/f.txt\t127.0.0.1\t70" };
        for (int l = 0; l < 3; l++) for (int v = 0; v < 2; v++) {
            SET_ERR(0);
            HINTERNET r = U(GopherOpenFileW)(h, locs[l], v ? L"text/plain" : NULL, 0, 0);
            DWORD e = GetLastError();
            CHECKF(r == NULL && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d l=%d v=%d r=%p e=%lu", hk, l, v, r, e);
        }
        gs_handle_release(c, rq);
    }
}

static int gs_attr_cb_calls;
static BOOL CALLBACK gs_attr_cb(LPGOPHER_ATTRIBUTE_TYPE info, DWORD err) { (void)info; (void)err; gs_attr_cb_calls++; return TRUE; }

TEST(gs_gopher_get_attribute_a) {
    REQUIRE(U(GopherGetAttributeA)); REQUIRE(U(InternetOpenA));
    static const char *attrs[] = { NULL, "", GOPHER_INFO_CATEGORY, GOPHER_ADMIN_CATEGORY, GOPHER_VIEWS_CATEGORY,
                                   GOPHER_ABSTRACT_CATEGORY, GOPHER_VERONICA_CATEGORY, GOPHER_ADMIN_ATTRIBUTE,
                                   GOPHER_MOD_DATE_ATTRIBUTE, GOPHER_TTL_ATTRIBUTE, GOPHER_SCORE_ATTRIBUTE };
    gs_attr_cb_calls = 0;
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) continue;
        for (size_t a = 0; a < sizeof attrs / sizeof attrs[0]; a++) for (int cb = 0; cb < 2; cb++) {
            BYTE buf[128]; DWORD got = 0xA5A5A5A5u;
            gs_fill(buf, sizeof buf);
            SET_ERR(0);
            BOOL r = U(GopherGetAttributeA)(h, "1Dir\t/\t127.0.0.1\t70", attrs[a], cb ? NULL : buf, cb ? 0 : sizeof buf,
                                            &got, cb ? gs_attr_cb : NULL, 9);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d attr=%zu cb=%d r=%d e=%lu", hk, a, cb, r, e);
            CHECK(got == 0xA5A5A5A5u);
            CHECK(gs_untouched(buf, sizeof buf));
        }
        gs_handle_release(c, rq);
    }
    EXPECT_EQ(gs_attr_cb_calls, 0);
}

TEST(gs_gopher_get_attribute_w) {
    REQUIRE(U(GopherGetAttributeW)); REQUIRE(U(InternetOpenA));
    gs_attr_cb_calls = 0;
    static const WCHAR *attrs[] = { NULL, L"", L"+INFO", L"+ADMIN", L"Mod-Date" };
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) continue;
        for (size_t a = 0; a < sizeof attrs / sizeof attrs[0]; a++) {
            BYTE buf[64]; DWORD got = 0xA5A5A5A5u;
            gs_fill(buf, sizeof buf);
            SET_ERR(0x4242);
            BOOL r = U(GopherGetAttributeW)(h, L"1Dir\t/\th\t70", attrs[a], buf, sizeof buf, &got, gs_attr_cb, 0);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d attr=%zu r=%d e=%lu", hk, a, r, e);
            CHECK(got == 0xA5A5A5A5u);
            CHECK(gs_untouched(buf, sizeof buf));
        }
        gs_handle_release(c, rq);
    }
    EXPECT_EQ(gs_attr_cb_calls, 0);
}

TEST(gs_gopher_get_attribute_null_everything) {
    REQUIRE(U(GopherGetAttributeA)); REQUIRE(U(GopherGetAttributeW));
    SET_ERR(0);
    CHECK(!U(GopherGetAttributeA)(NULL, NULL, NULL, NULL, 0, NULL, NULL, 0)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    SET_ERR(0);
    CHECK(!U(GopherGetAttributeW)(NULL, NULL, NULL, NULL, 0, NULL, NULL, 0)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
}

/* -------------------------------------------------------------------- GLE always overwritten */
TEST(gs_gopher_gle_overwritten_for_every_seed) {
    REQUIRE(U(GopherCreateLocatorA)); REQUIRE(U(GopherGetLocatorTypeW)); REQUIRE(U(GopherOpenFileA));
    for (size_t s = 0; s < GS_NSEEDS; s++) {
        DWORD t;
        SET_ERR(gs_seeds[s]); U(GopherGetLocatorTypeW)(L"1", &t);              EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        SET_ERR(gs_seeds[s]); U(GopherOpenFileA)(NULL, "0", NULL, 0, 0);      EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        SET_ERR(gs_seeds[s]); U(GopherCreateLocatorA)(NULL, 0, NULL, NULL, 0, NULL, NULL); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    }
}

/* the stub must not leave any per-thread wininet error text behind */
TEST(gs_gopher_no_response_info) {
    REQUIRE(U(GopherOpenFileA)); REQUIRE(U(InternetGetLastResponseInfoA));
    SET_ERR(0);
    U(GopherOpenFileA)(gs_session(), "0x\t/x\th\t70", NULL, 0, 0);
    DWORD code = 0xA5A5A5A5u; char buf[64]; DWORD len = sizeof buf;
    gs_fill(buf, sizeof buf);
    BOOL r = U(InternetGetLastResponseInfoA)(&code, buf, &len);
    t_note("InternetGetLastResponseInfoA after gopher stub: r=%d code=%lu len=%lu", r, code, len);
    if (r) { EXPECT_EQ(len, 0); }
}

/* -------------------------------------------------------------------- threads */
typedef struct { volatile LONG bad; } gs_thr_ctx;
static DWORD WINAPI gs_gopher_thr(void *p) {
    gs_thr_ctx *c = (gs_thr_ctx *)p;
    for (int i = 0; i < 50; i++) {
        DWORD t;
        SetLastError(i);
        if (U(GopherGetLocatorTypeA)("1", &t) || GetLastError() != ERROR_CALL_NOT_IMPLEMENTED) InterlockedIncrement(&c->bad);
        SetLastError(0);
        if (U(GopherOpenFileW)(NULL, L"0", NULL, 0, 0) || GetLastError() != ERROR_CALL_NOT_IMPLEMENTED) InterlockedIncrement(&c->bad);
    }
    return 0;
}
TEST(gs_gopher_threads) {
    REQUIRE(U(GopherGetLocatorTypeA)); REQUIRE(U(GopherOpenFileW));
    gs_thr_ctx c = { 0 };
    HANDLE th[4];
    for (int i = 0; i < 4; i++) th[i] = CreateThread(NULL, 0, gs_gopher_thr, &c, 0, NULL);
    for (int i = 0; i < 4; i++) if (th[i]) { CHECK(WaitForSingleObject(th[i], 10000) == WAIT_OBJECT_0); CloseHandle(th[i]); }
    EXPECT_EQ(c.bad, 0);
}

/* the stubs never invalidate a handle that was passed to them */
TEST(gs_gopher_handles_survive) {
    REQUIRE(U(GopherFindFirstFileA)); REQUIRE(U(InternetOpenA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET s = U(InternetOpenA)("gs_survive", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    CHECK(s != NULL);
    if (!s) return;
    GOPHER_FIND_DATAA d;
    U(GopherFindFirstFileA)(s, NULL, NULL, &d, 0, 0);
    U(GopherOpenFileA)(s, "0", NULL, 0, 0);
    DWORD type = 0, len = sizeof type;
    CHECK(U(InternetQueryOptionA)(s, INTERNET_OPTION_HANDLE_TYPE, &type, &len));
    EXPECT_EQ(type, INTERNET_HANDLE_TYPE_INTERNET);
    SET_ERR(0);
    CHECK(U(InternetCloseHandle)(s));
}

/* ------------------------------------------------------------------- InternetWriteFileEx */
TEST(gs_writefileex_a_stub) {
    REQUIRE(UN(InternetWriteFileExA)); REQUIRE(U(InternetOpenA));
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) continue;
        static const DWORD flags[] = { 0, IRF_ASYNC, IRF_SYNC, IRF_USE_CONTEXT, IRF_NO_WAIT, 0xFFFFFFFFu };
        for (size_t f = 0; f < sizeof flags / sizeof flags[0]; f++) for (int nb = 0; nb < 2; nb++) {
            char data[8] = "payload";
            INTERNET_BUFFERSA ib; memset(&ib, 0, sizeof ib);
            ib.dwStructSize = sizeof ib; ib.lpvBuffer = data; ib.dwBufferLength = 7; ib.dwBufferTotal = 7;
            INTERNET_BUFFERSA copy = ib;
            SET_ERR(0);
            BOOL r = UN(InternetWriteFileExA)(h, nb ? NULL : &ib, flags[f], 5);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d flags=0x%lx nb=%d r=%d e=%lu", hk, flags[f], nb, r, e);
            CHECK(!memcmp(&ib, &copy, sizeof ib));
            EXPECT_STR(data, "payload");
        }
        gs_handle_release(c, rq);
    }
}

TEST(gs_writefileex_w_stub) {
    REQUIRE(UN(InternetWriteFileExW)); REQUIRE(U(InternetOpenA));
    for (int hk = 0; hk < 4; hk++) {
        HINTERNET c, rq; HINTERNET h = gs_handle_kind(hk, &c, &rq);
        if (hk && !h) continue;
        INTERNET_BUFFERSW ib; memset(&ib, 0, sizeof ib);
        ib.dwStructSize = sizeof ib;
        INTERNET_BUFFERSW copy = ib;
        for (size_t s = 0; s < GS_NSEEDS; s++) {
            SET_ERR(gs_seeds[s]);
            BOOL r = UN(InternetWriteFileExW)(h, &ib, 0, 0);
            DWORD e = GetLastError();
            CHECKF(!r && e == ERROR_CALL_NOT_IMPLEMENTED, "hk=%d seed=%lu r=%d e=%lu", hk, gs_seeds[s], r, e);
            CHECK(!memcmp(&ib, &copy, sizeof ib));
        }
        gs_handle_release(c, rq);
    }
}

/* the plain InternetWriteFile on a GET request that was never sent is a real API, not the stub */
TEST(gs_writefileex_vs_writefile) {
    REQUIRE(UN(InternetWriteFileExA)); REQUIRE(U(InternetWriteFile));
    HINTERNET c = gs_connect_http(gs_session());
    HINTERNET r = gs_request(c, "/gs_wfe");
    if (!r) { t_skip("no request handle"); gs_handle_release(c, NULL); return; }
    DWORD w = 0xA5A5;
    SET_ERR(0);
    BOOL ok = U(InternetWriteFile)(r, "x", 1, &w);
    DWORD e = GetLastError();
    CHECK(!ok);
    CHECKF(e != ERROR_CALL_NOT_IMPLEMENTED, "InternetWriteFile e=%lu", e);
    t_note("InternetWriteFile on an unsent GET: e=%lu (%s) written=%lu", e, e == 12019 ? "INCORRECT_HANDLE_STATE" : "?", w);
    INTERNET_BUFFERSA ib = { sizeof ib };
    SET_ERR(0);
    CHECK(!UN(InternetWriteFileExA)(r, &ib, 0, 0)); EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
    gs_handle_release(c, r);
}

/* ------------------------------------------------------------------- LoadUrlCacheContent */
TEST(gs_load_url_cache_content_stub) {
    REQUIRE(UN(LoadUrlCacheContent));
    for (size_t s = 0; s < GS_NSEEDS; s++)
        for (int rep = 0; rep < 3; rep++) {
            SET_ERR(gs_seeds[s]);
            CHECKF(!UN(LoadUrlCacheContent)(), "seed %lu rep %d", gs_seeds[s], rep);
            EXPECT_ERR(ERROR_CALL_NOT_IMPLEMENTED);
        }
}

/* ------------------------------------------------------------------- gopher in the protocol layer */
TEST(gs_gopher_connect_a_service_rejected) {
    REQUIRE(U(InternetConnectA));
    HINTERNET s = gs_session();
    if (!s) { t_skip("no session"); return; }
    for (size_t sd = 0; sd < GS_NSEEDS; sd++) {
        SET_ERR(gs_seeds[sd]);
        HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", INTERNET_DEFAULT_GOPHER_PORT, NULL, NULL, INTERNET_SERVICE_GOPHER, 0, 0);
        DWORD e = GetLastError();
        CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "seed %lu: c=%p e=%lu", gs_seeds[sd], c, e);
        if (c) U(InternetCloseHandle)(c);
    }
}

TEST(gs_gopher_connect_w_service_rejected) {
    REQUIRE(U(InternetConnectW));
    HINTERNET s = gs_session();
    if (!s) { t_skip("no session"); return; }
    SET_ERR(0);
    HINTERNET c = U(InternetConnectW)(s, L"127.0.0.1", 70, NULL, NULL, INTERNET_SERVICE_GOPHER, 0, 0);
    CHECK(c == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (c) U(InternetCloseHandle)(c);
    SET_ERR(0);
    c = U(InternetConnectW)(s, L"127.0.0.1", 70, L"user", L"pass", INTERNET_SERVICE_GOPHER, INTERNET_FLAG_PASSIVE, 1);
    CHECK(c == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    if (c) U(InternetCloseHandle)(c);
}

/* [D] the service check is the first thing InternetConnectA does: even a NULL session fails with 87 */
TEST(gs_connect_a_bad_service_table) {
    REQUIRE(U(InternetConnectA));
    static const DWORD svc[] = { 0, 2, 4, 5, 6, 7, 8, 0x10, 0x100, 0x7FFFFFFFu, 0x80000000u, 0x80000001u, 0x80000003u, 0xFFFFFFFFu };
    HINTERNET s = gs_session();
    for (size_t i = 0; i < sizeof svc / sizeof svc[0]; i++) {
        for (int ns = 0; ns < 2; ns++) {
            SET_ERR(0);
            HINTERNET c = U(InternetConnectA)(ns ? NULL : s, "127.0.0.1", 80, NULL, NULL, svc[i], 0, 0);
            DWORD e = GetLastError();
            CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "service 0x%lx nullsession=%d: c=%p e=%lu", svc[i], ns, c, e);
            if (c) U(InternetCloseHandle)(c);
        }
    }
}

TEST(gs_connect_w_bad_service_table) {
    REQUIRE(U(InternetConnectW));
    static const DWORD svc[] = { 0, 2, 4, 5, 0x80000001u, 0xFFFFFFFFu };
    HINTERNET s = gs_session();
    for (size_t i = 0; i < sizeof svc / sizeof svc[0]; i++) {
        SET_ERR(0);
        HINTERNET c = U(InternetConnectW)(s, L"127.0.0.1", 80, NULL, NULL, svc[i], 0, 0);
        DWORD e = GetLastError();
        CHECKF(c == NULL && e == ERROR_INVALID_PARAMETER, "service 0x%lx: c=%p e=%lu", svc[i], c, e);
        if (c) U(InternetCloseHandle)(c);
    }
}

/* the two services that remain are still accepted (no traffic: connect handles are lazy) */
TEST(gs_connect_valid_services_still_work) {
    REQUIRE(U(InternetConnectA)); REQUIRE(U(InternetQueryOptionA));
    HINTERNET s = gs_session();
    if (!s) { t_skip("no session"); return; }
    static const struct { DWORD svc; DWORD type; } ok[] = {
        { INTERNET_SERVICE_HTTP, INTERNET_HANDLE_TYPE_CONNECT_HTTP },
    };
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {
        HINTERNET c = U(InternetConnectA)(s, "127.0.0.1", 9, NULL, NULL, ok[i].svc, 0, 0);
        CHECKF(c != NULL, "service %lu", ok[i].svc);
        if (!c) continue;
        DWORD t = 0, l = sizeof t;
        CHECK(U(InternetQueryOptionA)(c, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
        EXPECT_EQ(t, ok[i].type);
        U(InternetCloseHandle)(c);
    }
}

typedef struct { const char *url; HINTERNET h; DWORD err; } gs_ou_ctx;
static void gs_ou_job(void *p) {
    gs_ou_ctx *c = (gs_ou_ctx *)p;
    SetLastError(0);
    c->h = U(InternetOpenUrlA)(gs_session(), c->url, NULL, 0,
                               INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES, 0);
    c->err = GetLastError();
}
/* gopher:// URLs: no gopher protocol handler. Port 1 on loopback so a mistaken connect cannot leave the box. */
TEST(gs_gopher_open_url_a) {
    REQUIRE(U(InternetOpenUrlA));
    static const char *urls[] = { "gopher://127.0.0.1:1/", "gopher://127.0.0.1:1/1/dir", "gopher://127.0.0.1:1/0/file.txt",
                                  "GOPHER://127.0.0.1:1/" };
    for (size_t i = 0; i < sizeof urls / sizeof urls[0]; i++) {
        gs_ou_ctx c = { urls[i], NULL, 0 };
        if (!gs_bounded(gs_ou_job, &c, 15000)) { CHECKF(0, "%s: InternetOpenUrlA hung", urls[i]); continue; }
        CHECKF(c.h == NULL, "%s: opened", urls[i]);
        CHECKF(c.err == ERROR_INTERNET_UNRECOGNIZED_SCHEME, "%s: err %lu", urls[i], c.err);
        if (c.h) U(InternetCloseHandle)(c.h);
    }
}

TEST(gs_gopher_open_url_w) {
    REQUIRE(U(InternetOpenUrlW));
    HINTERNET s = gs_session();
    SET_ERR(0);
    HINTERNET h = U(InternetOpenUrlW)(s, L"gopher://127.0.0.1:1/1/x", NULL, 0, INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD, 0);
    DWORD e = GetLastError();
    CHECK(h == NULL);
    CHECKF(e == ERROR_INTERNET_UNRECOGNIZED_SCHEME, "err %lu", e);
    if (h) U(InternetCloseHandle)(h);
}

/* URL helpers still know the scheme */
TEST(gs_gopher_crack_url_a) {
    REQUIRE(U(InternetCrackUrlA));
    static const struct { const char *url; WORD port; const char *path; } t[] = {
        /* [VM boot 3] no default port is filled in for gopher: nPort stays 0 when the URL has none */
        { "gopher://gopher.example/1/dir", 0, "/1/dir" },
        { "gopher://gopher.example:7070/0/f.txt", 7070, "/0/f.txt" },
        { "gopher://gopher.example:70/", 70, "/" },
        { "gopher://gopher.example/", 0, "/" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char host[64], path[64], scheme[16];
        URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc);
        uc.dwStructSize = sizeof uc;
        uc.lpszHostName = host; uc.dwHostNameLength = sizeof host;
        uc.lpszUrlPath = path;  uc.dwUrlPathLength = sizeof path;
        uc.lpszScheme = scheme; uc.dwSchemeLength = sizeof scheme;
        SET_ERR(0);
        BOOL r = U(InternetCrackUrlA)(t[i].url, 0, 0, &uc);
        CHECKF(r, "%s: e=%lu", t[i].url, GetLastError());
        if (!r) continue;
        EXPECT_EQ(uc.nScheme, INTERNET_SCHEME_GOPHER);
        EXPECT_STR(scheme, "gopher");
        EXPECT_STR(host, "gopher.example");
        CHECKF(uc.nPort == t[i].port, "%s: port %u", t[i].url, uc.nPort);
        EXPECT_STR(path, t[i].path);
    }
}

TEST(gs_gopher_crack_url_w) {
    REQUIRE(U(InternetCrackUrlW));
    WCHAR host[64], path[64];
    URL_COMPONENTSW uc; memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszHostName = host; uc.dwHostNameLength = 64;
    uc.lpszUrlPath = path;  uc.dwUrlPathLength = 64;
    uc.dwSchemeLength = 1;
    CHECK(U(InternetCrackUrlW)(L"gopher://h.example/1x", 0, 0, &uc));
    EXPECT_EQ(uc.nScheme, INTERNET_SCHEME_GOPHER);
    EXPECT_EQ(uc.nPort, 0);   /* [VM] not defaulted to 70 */
    EXPECT_EQ(uc.dwSchemeLength, 6);
    EXPECT_WSTR(host, L"h.example");
    EXPECT_WSTR(path, L"/1x");
}

TEST(gs_gopher_create_url_a) {
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.nScheme = INTERNET_SCHEME_GOPHER;
    uc.lpszHostName = (char *)"h.example";
    uc.nPort = INTERNET_DEFAULT_GOPHER_PORT;
    uc.lpszUrlPath = (char *)"/1/dir";
    char out[128]; DWORD len = sizeof out;
    SET_ERR(0);
    BOOL r = U(InternetCreateUrlA)(&uc, 0, out, &len);
    CHECKF(r, "e=%lu", GetLastError());
    /* [VM boot 3] gopher has no default port in the URL builder either: 70 is printed explicitly */
    if (r) { EXPECT_STR(out, "gopher://h.example:70/1/dir"); EXPECT_EQ(len, strlen("gopher://h.example:70/1/dir")); }
    uc.nPort = 0; len = sizeof out;
    r = U(InternetCreateUrlA)(&uc, 0, out, &len);
    CHECK(r);
    if (r) t_note("CreateUrl gopher port 0: %s", out);
    uc.nPort = 7070; len = sizeof out;
    r = U(InternetCreateUrlA)(&uc, 0, out, &len);
    CHECK(r);
    if (r) EXPECT_STR(out, "gopher://h.example:7070/1/dir");
}

TEST(gs_gopher_create_url_scheme_from_name) {
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA uc; memset(&uc, 0, sizeof uc);
    uc.dwStructSize = sizeof uc;
    uc.lpszScheme = (char *)"gopher";
    uc.nScheme = INTERNET_SCHEME_DEFAULT;
    uc.lpszHostName = (char *)"h.example";
    uc.lpszUrlPath = (char *)"/";
    char out[128]; DWORD len = sizeof out;
    BOOL r = U(InternetCreateUrlA)(&uc, 0, out, &len);
    t_note("CreateUrl scheme name 'gopher' + DEFAULT: r=%d out=%s e=%lu", r, r ? out : "", r ? 0 : GetLastError());
    if (r) CHECK(!strncmp(out, "gopher://h.example", 18));
}

/* INTERNET_OPTION queries do not know a gopher handle type: an HTTP connect handle never reports GOPHER */
TEST(gs_gopher_handle_type_never_gopher) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET c = gs_connect_http(gs_session());
    HINTERNET r = gs_request(c, "/gs_ht");
    DWORD t, l;
    if (c) { t = 0; l = sizeof t; CHECK(U(InternetQueryOptionA)(c, INTERNET_OPTION_HANDLE_TYPE, &t, &l)); CHECK(t != INTERNET_HANDLE_TYPE_CONNECT_GOPHER); }
    if (r) { t = 0; l = sizeof t; CHECK(U(InternetQueryOptionA)(r, INTERNET_OPTION_HANDLE_TYPE, &t, &l)); CHECK(t != INTERNET_HANDLE_TYPE_GOPHER_FIND && t != INTERNET_HANDLE_TYPE_GOPHER_FILE); EXPECT_EQ(t, INTERNET_HANDLE_TYPE_HTTP_REQUEST); }
    gs_handle_release(c, r);
}
