/* ac_setcb.c - InternetSetStatusCallback[A|W] semantics, inheritance, HANDLE_CREATED / HANDLE_CLOSING,
 * INTERNET_OPTION_CALLBACK / CONTEXT_VALUE. No network traffic (InternetConnect for HTTP does no I/O).
 *
 * Decomp grounding [D]:
 *  - InternetSetStatusCallbackCore@0xcef20: NULL handle -> returns INTERNET_INVALID_STATUS_CALLBACK, error 12018;
 *    MapHandleToAddress failure (garbage / closed) -> -1 and that error (6); success -> previous callback and
 *    SetLastError(0). No check of the new value (NULL and -1 are stored as given).
 *  - RExchangeStatusCallback@0xcefd4: any valid handle type ("Wild"); swaps object+0x220; the unicode flag is set
 *    only when the new callback is non-NULL.
 *  - InternetIndicateStatus@0x5e500: no delivery when the callback or the context is 0.
 *  - InternetIndicateStatusNewHandle@0x13c124: HANDLE_CREATED (60) carries the new handle value.
 */
#include "ac.h"

#define FAKE_H ((HINTERNET)(ULONG_PTR)0x00C0FFEEu)   /* a handle value that is never in the handle table */

static HINTERNET mk_con(HINTERNET hi, DWORD_PTR ctx) {
    return U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, ctx);
}
static HINTERNET mk_req(HINTERNET hc, DWORD_PTR ctx) {
    return U(HttpOpenRequestA)(hc, "GET", "/ac", NULL, NULL, NULL, T_INET_FRESH, ctx);
}

/* ------------------------------------------------------------------ return values / errors */
TEST(ac_setcb_null_handle_a) {
    REQUIRE(U(InternetSetStatusCallbackA));
    SetLastError(0xdeadbeef);
    INTERNET_STATUS_CALLBACK r = U(InternetSetStatusCallbackA)(NULL, ac_cb);
    EXPECT_EQ(r, INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}
TEST(ac_setcb_null_handle_w) {
    REQUIRE(U(InternetSetStatusCallbackW));
    SetLastError(0xdeadbeef);
    INTERNET_STATUS_CALLBACK r = U(InternetSetStatusCallbackW)(NULL, ac_cbw);
    EXPECT_EQ(r, INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}
TEST(ac_setcb_null_handle_plain_export) {
    REQUIRE(U(InternetSetStatusCallback));
    SetLastError(0xdeadbeef);
    INTERNET_STATUS_CALLBACK r = U(InternetSetStatusCallback)(NULL, NULL);
    EXPECT_EQ(r, INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}
TEST(ac_setcb_plain_export_is_ansi) {
    /* InternetSetStatusCallback and InternetSetStatusCallbackA share RVA 0xcee20 [D] */
    REQUIRE(U(InternetSetStatusCallback)); REQUIRE(U(InternetSetStatusCallbackA));
    EXPECT_EQ((void *)U(InternetSetStatusCallback), (void *)U(InternetSetStatusCallbackA));
    CHECK((void *)U(InternetSetStatusCallbackW) != (void *)U(InternetSetStatusCallbackA));
}
TEST(ac_setcb_garbage_handle) {
    REQUIRE(U(InternetSetStatusCallbackA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(FAKE_H, ac_cb), INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetStatusCallbackW)(FAKE_H, NULL), INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(ac_setcb_closed_handle) {
    REQUIRE(U(InternetSetStatusCallbackA));
    ac_begin();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    CHECK(U(InternetCloseHandle)(hi));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb), INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_ERR(ERROR_INVALID_HANDLE);
}
TEST(ac_setcb_first_returns_null_error_zero) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    SetLastError(0xdeadbeef);
    INTERNET_STATUS_CALLBACK r = U(InternetSetStatusCallbackA)(hi, ac_cb);
    EXPECT_EQ(r, NULL);
    EXPECT_ERR(0);
    U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_returns_previous_chain) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb), NULL);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb2), ac_cb);
    EXPECT_ERR(0);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb2), ac_cb2);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, NULL), ac_cb2);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, NULL), NULL);
    EXPECT_ERR(0);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb), NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, NULL), ac_cb);
    U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_mixed_a_w_returns_previous) {
    REQUIRE(U(InternetSetStatusCallbackA)); REQUIRE(U(InternetSetStatusCallbackW));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    EXPECT_EQ(U(InternetSetStatusCallbackW)(hi, ac_cbw), NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb), ac_cbw);
    EXPECT_EQ(U(InternetSetStatusCallbackW)(hi, ac_cbw), ac_cb);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetStatusCallbackW)(hi, NULL), ac_cbw);
    EXPECT_ERR(0);
    U(InternetCloseHandle)(hi);
}
/* The new value is not validated [D RExchangeStatusCallback]: INTERNET_INVALID_STATUS_CALLBACK is stored and
 * handed back by the next call (GetLastError 0 tells it apart from a failure). A session has context 0, so nothing
 * is ever delivered through it here. */
TEST(ac_setcb_invalid_value_stored) {
    REQUIRE(U(InternetSetStatusCallbackA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    SetLastError(0xdeadbeef);
    INTERNET_STATUS_CALLBACK r = U(InternetSetStatusCallbackA)(hi, INTERNET_INVALID_STATUS_CALLBACK);
    DWORD e = GetLastError();
    EXPECT_EQ(r, NULL);
    EXPECT_EQ(e, 0);
    SetLastError(0xdeadbeef);
    r = U(InternetSetStatusCallbackA)(hi, NULL);
    e = GetLastError();
    EXPECT_EQ(r, INTERNET_INVALID_STATUS_CALLBACK);
    EXPECT_EQ(e, 0);
    U(InternetCloseHandle)(hi);
}
/* each handle type accepts a callback ("Wild" type check) */
TEST(ac_setcb_every_handle_type) {
    REQ_ASYNC_API();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, 0), hr = hc ? mk_req(hc, 0) : NULL;
    CHECK(hc != NULL); CHECK(hr != NULL);
    HINTERNET hs[3] = { hi, hc, hr };
    for (int i = 0; i < 3; i++) {
        if (!hs[i]) continue;
        SetLastError(0xdeadbeef);
        EXPECT_EQ(U(InternetSetStatusCallbackA)(hs[i], ac_cb), NULL);
        EXPECT_ERR(0);
        EXPECT_EQ(U(InternetSetStatusCallbackA)(hs[i], ac_cb2), ac_cb);
        EXPECT_EQ(U(InternetSetStatusCallbackW)(hs[i], NULL), ac_cb2);
    }
    if (hr) U(InternetCloseHandle)(hr); if (hc) U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ inheritance */
TEST(ac_setcb_connect_inherits_session_cb) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, 0); CHECK(hc != NULL);
    if (hc) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, ac_cb), ac_cb); U(InternetCloseHandle)(hc); }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_connect_without_session_cb) {
    REQ_ASYNC_API();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    if (hc) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, NULL), NULL); U(InternetCloseHandle)(hc); }
    U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_request_inherits_connect_cb) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, 0); CHECK(hc != NULL); if (!hc) { U(InternetCloseHandle)(hi); return; }
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, ac_cb2), NULL);
    HINTERNET hr = mk_req(hc, 0); CHECK(hr != NULL);
    if (hr) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hr, NULL), ac_cb2); U(InternetCloseHandle)(hr); }
    /* the session is unaffected by a callback set on its child */
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, NULL), NULL);
    U(InternetSetStatusCallbackA)(hc, NULL);
    U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_inherit_is_snapshot) {
    REQ_ASYNC_API();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, 0); CHECK(hc != NULL);
    /* changing the session callback afterwards does not change the existing child */
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, ac_cb2), ac_cb);
    if (hc) {
        EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, ac_cb), ac_cb);
        HINTERNET hc2 = mk_con(hi, 0); CHECK(hc2 != NULL);
        if (hc2) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hc2, NULL), ac_cb2); U(InternetCloseHandle)(hc2); }
        EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, NULL), ac_cb);
        U(InternetCloseHandle)(hc);
    }
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, NULL), ac_cb2);
    U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_removed_on_session_not_inherited) {
    REQ_ASYNC_API();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hi, NULL), ac_cb);
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    if (hc) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, NULL), NULL); U(InternetCloseHandle)(hc); }
    U(InternetCloseHandle)(hi);
}
TEST(ac_setcb_w_inherited_by_child) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    EXPECT_EQ(U(InternetSetStatusCallbackW)(hi, ac_cbw), NULL);
    HINTERNET hc = mk_con(hi, 0); CHECK(hc != NULL);
    HINTERNET hr = hc ? mk_req(hc, 0) : NULL; CHECK(hr != NULL);
    if (hr) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hr, NULL), ac_cbw); U(InternetCloseHandle)(hr); }
    if (hc) { EXPECT_EQ(U(InternetSetStatusCallbackA)(hc, NULL), ac_cbw); U(InternetCloseHandle)(hc); }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ INTERNET_OPTION_CALLBACK */
TEST(ac_opt_callback_query) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    void *p = (void *)1; DWORD l = sizeof p;
    CHECK(U(InternetQueryOptionA)(hi, INTERNET_OPTION_CALLBACK, &p, &l));
    EXPECT_EQ(p, NULL); EXPECT_EQ(l, sizeof(void *));
    U(InternetSetStatusCallbackA)(hi, ac_cb);
    p = NULL; l = sizeof p;
    CHECK(U(InternetQueryOptionA)(hi, INTERNET_OPTION_CALLBACK, &p, &l));
    EXPECT_EQ(p, (void *)ac_cb); EXPECT_EQ(l, sizeof(void *));
    U(InternetSetStatusCallbackW)(hi, ac_cbw);
    p = NULL; l = sizeof p;
    CHECK(U(InternetQueryOptionW)(hi, INTERNET_OPTION_CALLBACK, &p, &l));
    EXPECT_EQ(p, (void *)ac_cbw);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_opt_callback_query_short_buffer) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    DWORD small = 0, l = sizeof small;
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(hi, INTERNET_OPTION_CALLBACK, &small, &l));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, sizeof(void *));
    l = 0;
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(hi, INTERNET_OPTION_CALLBACK, NULL, &l));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(l, sizeof(void *));
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_opt_callback_query_null_handle) {
    REQUIRE(U(InternetQueryOptionA));
    void *p = NULL; DWORD l = sizeof p;
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetQueryOptionA)(NULL, INTERNET_OPTION_CALLBACK, &p, &l));
    EXPECT_ERR(ERROR_INTERNET_INCORRECT_HANDLE_TYPE);
}
TEST(ac_opt_callback_set_readonly) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    INTERNET_STATUS_CALLBACK p = ac_cb;
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(hi, INTERNET_OPTION_CALLBACK, &p, sizeof p));
    EXPECT_ERR(ERROR_INTERNET_OPTION_NOT_SETTABLE);
    void *q = (void *)1; DWORD l = sizeof q;
    CHECK(U(InternetQueryOptionA)(hi, INTERNET_OPTION_CALLBACK, &q, &l));
    EXPECT_EQ(q, NULL);
    U(InternetCloseHandle)(hi);
}
TEST(ac_opt_callback_on_children) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, 0), hr = hc ? mk_req(hc, 0) : NULL;
    HINTERNET hs[2] = { hc, hr };
    for (int i = 0; i < 2; i++) {
        void *p = NULL; DWORD l = sizeof p;
        CHECK(hs[i] != NULL); if (!hs[i]) continue;
        CHECK(U(InternetQueryOptionA)(hs[i], INTERNET_OPTION_CALLBACK, &p, &l));
        EXPECT_EQ(p, (void *)ac_cb);
    }
    if (hr) { U(InternetSetStatusCallbackA)(hr, NULL); U(InternetCloseHandle)(hr); }
    if (hc) { U(InternetSetStatusCallbackA)(hc, NULL); U(InternetCloseHandle)(hc); }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ CONTEXT_VALUE */
TEST(ac_opt_context_value_defaults) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    struct { HINTERNET h; DWORD_PTR want; } t[] = { { hi, 0 }, { hc, CTX_CON }, { hr, CTX_REQ } };
    for (int i = 0; i < 3; i++) {
        DWORD_PTR v = 0x1111; DWORD l = sizeof v;
        if (!t[i].h) { CHECK(t[i].h != NULL); continue; }
        CHECKF(U(InternetQueryOptionA)(t[i].h, INTERNET_OPTION_CONTEXT_VALUE, &v, &l), "i=%d err=%lu", i, GetLastError());
        CHECKF(v == t[i].want, "i=%d got %llx", i, (unsigned long long)v);
        EXPECT_EQ(l, sizeof(DWORD_PTR));
    }
    if (hr) U(InternetCloseHandle)(hr); if (hc) U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
}
TEST(ac_opt_context_value_set_changes_delivery) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL); if (!hr) { U(InternetCloseHandle)(hi); return; }
    DWORD_PTR nv = CTX_ALT;
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_CONTEXT_VALUE, &nv, sizeof nv));
    DWORD_PTR q = 0; DWORD l = sizeof q;
    CHECK(U(InternetQueryOptionA)(hr, INTERNET_OPTION_CONTEXT_VALUE, &q, &l)); EXPECT_EQ(q, CTX_ALT);
    U(InternetCloseHandle)(hr);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_ALT, 1, 2000));
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 0);
    ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_opt_context_value_set_bad_length) {
    REQUIRE(U(InternetSetOptionA));
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    DWORD v4 = 5;
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetSetOptionA)(hi, INTERNET_OPTION_CONTEXT_VALUE, &v4, sizeof v4));
    EXPECT_ERR(ERROR_INTERNET_BAD_OPTION_LENGTH);
    U(InternetCloseHandle)(hi);
}
TEST(ac_opt_context_value_zero_silences) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL); if (!hr) { U(InternetCloseHandle)(hi); return; }
    DWORD_PTR zero = 0;
    CHECK(U(InternetSetOptionA)(hr, INTERNET_OPTION_CONTEXT_VALUE, &zero, sizeof zero));
    int n0 = ac_count();
    U(InternetCloseHandle)(hr);
    ac_quiesce(100, 500);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_HANDLE_CLOSING), 0);
    ac_close_wait(hc, CTX_CON);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ HANDLE_CREATED */
static void check_created(DWORD flags) {
    ac_begin();
    HINTERNET hi = ac_open_cb(flags, ac_cb); CHECK(hi != NULL); if (!hi) return;
    EXPECT_EQ(ac_count(), 0);                    /* InternetOpen itself: no callback was set yet */
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    /* delivered synchronously, before InternetConnect returns, on the calling thread */
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_CON), 1);
    int i = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_CON, 0);
    ac_ev e; memset(&e, 0, sizeof e);
    if (i >= 0 && ac_get(i, &e)) {
        EXPECT_EQ(e.tid, ac_main_tid);
        CHECK(e.has_info);
        EXPECT_EQ(ac_info_ptr(&e), hc);
        EXPECT_EQ(e.h, hi);                      /* [W10] hInternet is the parent handle */
        EXPECT_EQ(e.len, sizeof(HINTERNET));     /* [D] InternetIndicateStatusNewHandle passes the 8-byte handle */
    }
    HINTERNET hr = hc ? mk_req(hc, CTX_REQ) : NULL; CHECK(hr != NULL);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, CTX_REQ), 1);
    i = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_REQ, 0);
    if (i >= 0 && ac_get(i, &e)) {
        EXPECT_EQ(e.tid, ac_main_tid);
        EXPECT_EQ(ac_info_ptr(&e), hr);
        EXPECT_EQ(e.h, hc);
        EXPECT_EQ(e.len, sizeof(HINTERNET));
    }
    EXPECT_STR(ac_seq(0, NULL), "60,60");
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_created_sync_session) { REQ_ASYNC_API(); check_created(0); }
TEST(ac_created_async_session) { REQ_ASYNC_API(); check_created(INTERNET_FLAG_ASYNC); }

TEST(ac_created_len_and_handle_arg) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    ac_ev e;
    int i = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_CON, 0);
    if (i >= 0 && ac_get(i, &e)) {
        t_note("con: h=%p (hi %p hc %p) len=%lu", e.h, hi, hc, e.len);
        EXPECT_EQ(e.h, hi);
        EXPECT_EQ(e.len, sizeof(HINTERNET));
    } else CHECK(i >= 0);
    i = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_REQ, 0);
    if (i >= 0 && ac_get(i, &e)) {
        t_note("req: h=%p (hc %p hr %p) len=%lu", e.h, hc, hr, e.len);
        EXPECT_EQ(e.h, hc);
    } else CHECK(i >= 0);
    ac_dump("created");
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_created_context_zero_silent) {
    REQ_ASYNC_API();
    for (int async = 0; async < 2; async++) {
        ac_begin();
        HINTERNET hi = ac_open_cb(async ? INTERNET_FLAG_ASYNC : 0, ac_cb); CHECK(hi != NULL); if (!hi) return;
        HINTERNET hc = mk_con(hi, 0), hr = hc ? mk_req(hc, 0) : NULL;
        CHECK(hc != NULL); CHECK(hr != NULL);
        U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc);
        ac_quiesce(100, 500);
        CHECKF(ac_count() == 0, "async=%d events=%d seq=%s", async, ac_count(), ac_seq(0, NULL));
        U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
    }
}
TEST(ac_created_no_callback_no_events) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open(INTERNET_FLAG_ASYNC); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL);
    U(InternetCloseHandle)(hr); U(InternetCloseHandle)(hc); U(InternetCloseHandle)(hi);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count(), 0);
}
TEST(ac_created_w_callback) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    ac_begin();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    U(InternetSetStatusCallbackW)(hi, ac_cbw);
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    int i = ac_find(INTERNET_STATUS_HANDLE_CREATED, CTX_CON, 0); ac_ev e;
    CHECK(i >= 0);
    if (i >= 0 && ac_get(i, &e)) { EXPECT_EQ(e.wide, 1); EXPECT_EQ(ac_info_ptr(&e), hc); }
    ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_created_many_requests_contexts) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL); if (!hc) { U(InternetCloseHandle)(hi); return; }
    HINTERNET hr[16];
    for (int i = 0; i < 16; i++) {
        hr[i] = mk_req(hc, (DWORD_PTR)(0x1000 + i));
        CHECK(hr[i] != NULL);
        EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CREATED, 0x1000 + i), 1);
        int k = ac_find(INTERNET_STATUS_HANDLE_CREATED, 0x1000 + i, 0); ac_ev e;
        if (k >= 0 && ac_get(k, &e)) EXPECT_EQ(ac_info_ptr(&e), hr[i]);
    }
    for (int i = 15; i >= 0; i--) {
        if (!hr[i]) continue;
        U(InternetCloseHandle)(hr[i]);
        CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, 0x1000 + i, 1, 2000));
    }
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_HANDLE_CREATED), 17);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_HANDLE_CLOSING), 16);
    ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ HANDLE_CLOSING */
static void check_closing_single(DWORD flags) {
    ac_begin();
    HINTERNET hi = ac_open_cb(flags, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL); if (!hr) { U(InternetCloseHandle)(hi); return; }
    int n0 = ac_count();
    SetLastError(0xdeadbeef);
    CHECK(U(InternetCloseHandle)(hr));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 2000));
    int i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0); ac_ev e;
    if (i >= 0 && ac_get(i, &e)) {
        EXPECT_EQ(e.h, hr);
        CHECK(e.has_info);
        EXPECT_EQ(ac_info_ptr(&e), hr);
        EXPECT_EQ(e.len, sizeof(HINTERNET));
        t_note("HANDLE_CLOSING(req) flags=%lx tid=%s len=%lu", flags, e.tid == ac_main_tid ? "main" : "other", e.len);
    }
    ac_quiesce(50, 300);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    EXPECT_STR(ac_seq_range(0, n0, -1, NULL), "70");
    ac_close_wait(hc, CTX_CON);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 0);
    if (i >= 0 && ac_get(i, &e)) { EXPECT_EQ(e.h, hc); EXPECT_EQ(ac_info_ptr(&e), hc); }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_closing_sync) { REQ_ASYNC_API(); check_closing_single(0); }
TEST(ac_closing_async) { REQ_ASYNC_API(); check_closing_single(INTERNET_FLAG_ASYNC); }

TEST(ac_closing_session_closes_children) {
    REQ_ASYNC_API();
    for (int async = 0; async < 2; async++) {
        ac_begin();
        HINTERNET hi = ac_open_cb(async ? INTERNET_FLAG_ASYNC : 0, ac_cb); CHECK(hi != NULL); if (!hi) return;
        HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
        CHECK(hr != NULL);
        int n0 = ac_count();
        CHECK(U(InternetCloseHandle)(hi));
        CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 2000));
        CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 2000));
        ac_quiesce(50, 300);
        const char *s = ac_seq_range(0, n0, -1, NULL);
        EXPECT_STR(s, "70,70");
        int ir = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0), ic = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, n0);
        t_note("async=%d close order: req@%d con@%d", async, ir, ic);
        CHECKF(ir >= 0 && ic >= 0 && ir < ic, "async=%d child closes first: req@%d con@%d", async, ir, ic);
        /* the children are invalid now */
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetCloseHandle)(hr)); EXPECT_ERR(ERROR_INVALID_HANDLE);
        SetLastError(0xdeadbeef);
        CHECK(!U(InternetCloseHandle)(hc)); EXPECT_ERR(ERROR_INVALID_HANDLE);
    }
}
TEST(ac_closing_connect_closes_request) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr1 = hc ? mk_req(hc, CTX_REQ) : NULL, hr2 = hc ? mk_req(hc, CTX_ALT) : NULL;
    CHECK(hr1 && hr2);
    int n0 = ac_count();
    CHECK(U(InternetCloseHandle)(hc));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 2000));
    ac_quiesce(50, 300);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ), 1);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_ALT), 1);
    int ic = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, n0);
    int i1 = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, n0), i2 = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_ALT, n0);
    CHECKF(i1 < ic && i2 < ic, "req1@%d req2@%d con@%d", i1, i2, ic);
    t_note("connect close order: req1@%d req2@%d con@%d", i1, i2, ic);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_closing_session_context_zero_silent) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    CHECK(U(InternetCloseHandle)(hi));
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count(), 0);
}
TEST(ac_closing_session_with_context_value) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetOptionA));
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    DWORD_PTR c = CTX_SES;
    CHECK(U(InternetSetOptionA)(hi, INTERNET_OPTION_CONTEXT_VALUE, &c, sizeof c));
    CHECK(U(InternetCloseHandle)(hi));
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_SES, 1, 2000));
    int i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_SES, 0); ac_ev e;
    if (i >= 0 && ac_get(i, &e)) { EXPECT_EQ(e.h, hi); EXPECT_EQ(ac_info_ptr(&e), hi); }
    ac_quiesce(50, 300);
    EXPECT_STR(ac_seq(0, NULL), "70");
}
TEST(ac_closing_removed_callback_silent) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hr, NULL), ac_cb);
    int n0 = ac_count();
    U(InternetCloseHandle)(hr);
    ac_quiesce(100, 400);
    EXPECT_EQ(ac_count(), n0);
    ac_close_wait(hc, CTX_CON);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_closing_replaced_callback_receives) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hr, ac_cb2), ac_cb);
    U(InternetCloseHandle)(hr);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 2000));
    int i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 0); ac_ev e;
    if (i >= 0 && ac_get(i, &e)) EXPECT_EQ(e.wide, 2);
    EXPECT_EQ(ac_count_cb2(), 1);
    ac_close_wait(hc, CTX_CON);
    i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 0);
    if (i >= 0 && ac_get(i, &e)) EXPECT_EQ(e.wide, 0);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_closing_callback_only_on_request) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON), hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    CHECK(hr != NULL);
    EXPECT_EQ(ac_count(), 0);
    EXPECT_EQ(U(InternetSetStatusCallbackA)(hr, ac_cb), NULL);
    U(InternetCloseHandle)(hr);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_REQ, 1, 2000));
    U(InternetCloseHandle)(hc);
    ac_quiesce(100, 300);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 0);
    EXPECT_STR(ac_seq(0, NULL), "70");
    U(InternetCloseHandle)(hi);
}
TEST(ac_closing_w_callback) {
    REQ_ASYNC_API(); REQUIRE(U(InternetSetStatusCallbackW));
    ac_begin();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    U(InternetSetStatusCallbackW)(hi, ac_cbw);
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    U(InternetCloseHandle)(hc);
    /* UnicodeStatusCallbackWrapper drops 70 only when GlobalDisableUnicodeHandleClosingCallback is set [D] */
    int got = ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 1500);
    CHECK(got);
    int i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 0); ac_ev e;
    if (i >= 0 && ac_get(i, &e)) { EXPECT_EQ(e.wide, 1); EXPECT_EQ(ac_info_ptr(&e), hc); }
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_closing_double_close) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    CHECK(U(InternetCloseHandle)(hc));
    SetLastError(0xdeadbeef);
    CHECK(!U(InternetCloseHandle)(hc));
    EXPECT_ERR(ERROR_INVALID_HANDLE);
    ac_quiesce(50, 300);
    EXPECT_EQ(ac_count_st_ctx(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON), 1);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
/* the closing handle is still usable for queries from inside the HANDLE_CLOSING callback */
static volatile LONG g_inner_ok, g_inner_calls; static DWORD_PTR g_inner_ctx; static DWORD g_inner_err;
static void hook_query_in_closing(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (st != INTERNET_STATUS_HANDLE_CLOSING) return;
    InterlockedIncrement(&g_inner_calls);
    DWORD_PTR v = 0; DWORD l = sizeof v;
    DWORD t = 0, tl = sizeof t;
    SetLastError(0);
    BOOL a = U(InternetQueryOptionA)(h, INTERNET_OPTION_CONTEXT_VALUE, &v, &l);
    g_inner_err = GetLastError();
    BOOL b = U(InternetQueryOptionA)(h, INTERNET_OPTION_HANDLE_TYPE, &t, &tl);
    g_inner_ctx = v;
    if (a && b) InterlockedIncrement(&g_inner_ok);
}
TEST(ac_closing_query_inside_callback) {
    REQ_ASYNC_API(); REQUIRE(U(InternetQueryOptionA));
    ac_begin(); g_inner_ok = 0; g_inner_calls = 0; g_inner_ctx = 0;
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    ac_hook = hook_query_in_closing;
    U(InternetCloseHandle)(hc);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 2000));
    ac_hook = NULL;
    EXPECT_EQ(g_inner_calls, 1);
    /* [W10] the handle is already unusable for InternetQueryOption while its HANDLE_CLOSING is delivered */
    t_note("query inside HANDLE_CLOSING: ok=%ld ctx=%llx err=%lu", g_inner_ok, (unsigned long long)g_inner_ctx, g_inner_err);
    EXPECT_EQ(g_inner_ok, 0);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
/* InternetSetStatusCallback from inside a callback (re-entrant) */
static volatile LONG g_reent_done; static INTERNET_STATUS_CALLBACK g_reent_prev; static DWORD g_reent_err;
static void hook_setcb_in_created(HINTERNET h, DWORD_PTR ctx, DWORD st, LPVOID info, DWORD len) {
    if (st != INTERNET_STATUS_HANDLE_CREATED || g_reent_done) return;
    HINTERNET nh = NULL; if (info && len >= sizeof nh) memcpy(&nh, info, sizeof nh);
    SetLastError(0xdeadbeef);
    g_reent_prev = U(InternetSetStatusCallbackA)(nh, ac_cb2);
    g_reent_err = GetLastError();
    InterlockedExchange(&g_reent_done, 1);
}
TEST(ac_reentrant_setcb_inside_created) {
    REQ_ASYNC_API();
    ac_begin(); g_reent_done = 0; g_reent_prev = NULL; g_reent_err = 0;
    HINTERNET hi = ac_open_cb(0, ac_cb); CHECK(hi != NULL); if (!hi) return;
    ac_hook = hook_setcb_in_created;
    HINTERNET hc = mk_con(hi, CTX_CON); CHECK(hc != NULL);
    ac_hook = NULL;
    EXPECT_EQ(g_reent_done, 1);
    EXPECT_EQ(g_reent_prev, ac_cb);
    EXPECT_EQ(g_reent_err, 0);
    /* the new handle now reports to ac_cb2 */
    U(InternetCloseHandle)(hc);
    CHECK(ac_wait_st(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 1, 2000));
    int i = ac_find(INTERNET_STATUS_HANDLE_CLOSING, CTX_CON, 0); ac_ev e;
    if (i >= 0 && ac_get(i, &e)) EXPECT_EQ(e.wide, 2);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}

/* ------------------------------------------------------------------ async session: handle creation is synchronous */
TEST(ac_async_connect_http_returns_handle) {
    REQ_ASYNC_API();
    ac_begin();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb); CHECK(hi != NULL); if (!hi) return;
    SetLastError(0xdeadbeef);
    HINTERNET hc = mk_con(hi, CTX_CON);
    DWORD e = GetLastError();
    CHECK(hc != NULL);
    CHECKF(e == 0, "GetLastError after async InternetConnect = %lu", e);
    SetLastError(0xdeadbeef);
    HINTERNET hr = hc ? mk_req(hc, CTX_REQ) : NULL;
    e = GetLastError();
    CHECK(hr != NULL);
    CHECKF(e == 0, "GetLastError after async HttpOpenRequest = %lu", e);
    EXPECT_EQ(ac_count_st(INTERNET_STATUS_REQUEST_COMPLETE), 0);
    ac_close_wait(hr, CTX_REQ); ac_close_wait(hc, CTX_CON);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
TEST(ac_async_connect_context_zero_ok) {
    REQ_ASYNC_API();
    HINTERNET hi = ac_open_cb(INTERNET_FLAG_ASYNC, ac_cb); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = mk_con(hi, 0); CHECK(hc != NULL);
    HINTERNET hr = hc ? mk_req(hc, 0) : NULL; CHECK(hr != NULL);
    if (hr) U(InternetCloseHandle)(hr); if (hc) U(InternetCloseHandle)(hc);
    U(InternetSetStatusCallbackA)(hi, NULL); U(InternetCloseHandle)(hi);
}
/* INTERNET_FLAG_ASYNC is accepted in InternetConnect/HttpOpenRequest flags (masked, 02 sections 2 and 3.1) */
TEST(ac_async_flag_on_children_ignored) {
    REQ_ASYNC_API();
    HINTERNET hi = ac_open(0); CHECK(hi != NULL); if (!hi) return;
    HINTERNET hc = U(InternetConnectA)(hi, "127.0.0.1", 80, NULL, NULL, INTERNET_SERVICE_HTTP, INTERNET_FLAG_ASYNC, CTX_CON);
    CHECK(hc != NULL);
    HINTERNET hr = hc ? U(HttpOpenRequestA)(hc, "GET", "/", NULL, NULL, NULL, T_INET_FRESH | INTERNET_FLAG_ASYNC, CTX_REQ) : NULL;
    CHECK(hr != NULL);
    if (hr) {
        DWORD f = 0, l = sizeof f;
        if (U(InternetQueryOptionA)(hr, INTERNET_OPTION_REQUEST_FLAGS, &f, &l)) t_note("REQUEST_FLAGS=0x%lx", f);
        U(InternetCloseHandle)(hr);
    }
    if (hc) U(InternetCloseHandle)(hc);
    U(InternetCloseHandle)(hi);
}
TEST(ac_async_option_queries) {
    REQUIRE(U(InternetQueryOptionA));
    /* 15 ASYNC_ID, 16 ASYNC_PRIORITY, 30 ASYNC: not supported -> 120 [D] (queried on a real async handle) */
    HINTERNET hi = ac_open(INTERNET_FLAG_ASYNC); CHECK(hi != NULL); if (!hi) return;
    static const DWORD opts[] = { 16, 30 };
    for (unsigned i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        DWORD v = 0, l = sizeof v;
        SetLastError(0xdeadbeef);
        BOOL ok = U(InternetQueryOptionA)(hi, opts[i], &v, &l);
        DWORD e = GetLastError();
        t_note("query option %lu on async session: ok=%d err=%lu v=%lu", opts[i], ok, e, v);
        CHECKF(!ok && e == ERROR_CALL_NOT_IMPLEMENTED, "opt %lu ok=%d err=%lu", opts[i], ok, e);
    }
    U(InternetCloseHandle)(hi);
}
TEST(ac_async_session_handle_type) {
    REQUIRE(U(InternetQueryOptionA));
    HINTERNET hi = ac_open(INTERNET_FLAG_ASYNC); CHECK(hi != NULL); if (!hi) return;
    DWORD t = 0, l = sizeof t;
    CHECK(U(InternetQueryOptionA)(hi, INTERNET_OPTION_HANDLE_TYPE, &t, &l));
    EXPECT_EQ(t, INTERNET_HANDLE_TYPE_INTERNET);
    U(InternetCloseHandle)(hi);
}
