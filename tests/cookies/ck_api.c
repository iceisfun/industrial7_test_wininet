/* ck_api.c - InternetSetCookie(Ex)A/W and InternetGetCookie(Ex)A/W: argument validation, return values,
 * GetLastError, buffer/size protocol (A in bytes, W in chars on success but bytes on size queries / 122).
 * Decomp: InternetGetCookieExW@0xbeed0, InternetGetCookieExA@0x16a140, InternetGetCookieA@0x16a110,
 * InternetSetCookieA@0x16a4b0, InternetSetCookieW@0x16a590, InternetSetCookieExW@0x33a20,
 * InternalInternetSetCookie@0x6a7d0. VM_TIMEOUT: 120 */
#include "ck.h"

/* ------------------------------------------------------------------------------------------ set: arguments */
TEST(ck_set_a_null_url) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)(NULL, NULL, "a=1"), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_set_a_null_data) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)(ck_url(ck_host("nd"), "/"), "a", NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_set_a_null_both) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)(NULL, NULL, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_set_w_null_url) {
    REQUIRE(U(InternetSetCookieW));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieW)(NULL, NULL, L"a=1"), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_set_w_null_data) {
    REQUIRE(U(InternetSetCookieW));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieW)(ck_w(ck_url(ck_host("wnd"), "/")), L"a", NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_setex_a_null_url) {
    REQUIRE(U(InternetSetCookieExA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieExA)(NULL, NULL, "a=1", 0, 0), COOKIE_STATE_UNKNOWN);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_setex_a_null_data) {
    REQUIRE(U(InternetSetCookieExA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieExA)(ck_url(ck_host("xnd"), "/"), "n", NULL, 0, 0), COOKIE_STATE_UNKNOWN);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_setex_w_null_url) {
    REQUIRE(U(InternetSetCookieExW));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieExW)(NULL, NULL, L"a=1", 0, 0), COOKIE_STATE_UNKNOWN);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_setex_w_null_data) {
    REQUIRE(U(InternetSetCookieExW));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieExW)(ck_w(ck_url(ck_host("wxnd"), "/")), L"n", NULL, 0, 0), COOKIE_STATE_UNKNOWN);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_setex_p3p_evaluate_and_apply_rejected) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("p3p"), "/");
    DWORD gle, r = ck_setx(u, NULL, "a=1", INTERNET_COOKIE_EVALUATE_P3P | INTERNET_COOKIE_APPLY_P3P, &gle);
    EXPECT_EQ(r, COOKIE_STATE_UNKNOWN);
    EXPECT_EQ(gle, ERROR_INVALID_PARAMETER);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ set: return values */
TEST(ck_set_a_returns_one_and_clears_error) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("ret"), "/");
    ck_track(u, "a", NULL, 0);
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetCookieA)(u, NULL, "a=1");
    DWORD e = GetLastError();
    EXPECT_EQ(r, 1);
    EXPECT_EQ(e, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "a=1");
    ck_cleanup();
}
TEST(ck_set_w_returns_one_and_clears_error) {
    REQUIRE(U(InternetSetCookieW));
    const char *u = ck_url(ck_host("retw"), "/");
    ck_track(u, "a", NULL, 0);
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetCookieW)(ck_w(u), NULL, L"a=1");
    DWORD e = GetLastError();
    EXPECT_EQ(r, 1);
    EXPECT_EQ(e, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "a=1");
    ck_cleanup();
}
TEST(ck_setex_a_returns_accept) {
    REQUIRE(U(InternetSetCookieExA));
    const char *u = ck_url(ck_host("retx"), "/");
    DWORD gle, r = ck_setx(u, NULL, "a=1", 0, &gle);
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(gle, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "a=1");
    ck_cleanup();
}
TEST(ck_setex_w_returns_accept) {
    REQUIRE(U(InternetSetCookieExW));
    const char *u = ck_url(ck_host("retxw"), "/");
    ck_track(u, "a", NULL, 0);
    SetLastError(0xdeadbeef);
    DWORD r = U(InternetSetCookieExW)(ck_w(u), NULL, L"a=1", 0, 0);
    DWORD e = GetLastError();
    EXPECT_EQ(r, COOKIE_STATE_ACCEPT);
    EXPECT_EQ(e, 0);
    EXPECT_STR(ck_gets(u, NULL, 0), "a=1");
    ck_cleanup();
}
TEST(ck_setex_w_name_and_data) {
    REQUIRE(U(InternetSetCookieExW));
    const char *u = ck_url(ck_host("nmw"), "/");
    ck_track(u, "nm", NULL, 0);
    EXPECT_EQ(U(InternetSetCookieExW)(ck_w(u), L"nm", L"val", 0, 0), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "nm=val");
    ck_cleanup();
}
TEST(ck_set_w_name_and_data) {
    REQUIRE(U(InternetSetCookieW));
    const char *u = ck_url(ck_host("nmw2"), "/");
    ck_track(u, "nm", NULL, 0);
    EXPECT_EQ(U(InternetSetCookieW)(ck_w(u), L"nm", L"val"), TRUE);
    EXPECT_STR(ck_gets(u, NULL, 0), "nm=val");
    ck_cleanup();
}
TEST(ck_set_expired_nonexistent_returns_true) {
    REQUIRE(U(InternetSetCookieA));
    const char *u = ck_url(ck_host("expne"), "/");
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)(u, NULL, "nothere=1; " CK_PAST), TRUE);
    EXPECT_ERR(0);
    EXPECT_STR(ck_gets(u, NULL, 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
}
TEST(ck_setex_expired_nonexistent_returns_accept) {
    REQUIRE(U(InternetSetCookieExA));
    DWORD gle;
    EXPECT_EQ(U(InternetSetCookieExA)(ck_url(ck_host("expnex"), "/"), NULL, "nothere=1; " CK_PAST, 0, 0), COOKIE_STATE_ACCEPT);
    (void)gle;
}

/* ------------------------------------------------------------------------------------------ get: arguments */
TEST(ck_getex_a_null_url) {
    REQUIRE(U(InternetGetCookieExA));
    char b[64]; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(NULL, NULL, b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, sizeof b);   /* checked before *lpdwSize is touched */
}
TEST(ck_getex_a_null_size) {
    REQUIRE(U(InternetGetCookieExA));
    char b[64];
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(ck_url(ck_host("ns"), "/"), NULL, b, NULL, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_getex_w_null_url) {
    REQUIRE(U(InternetGetCookieExW));
    WCHAR b[64]; DWORD sz = 64;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(NULL, NULL, b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 64);
}
TEST(ck_getex_w_null_size) {
    REQUIRE(U(InternetGetCookieExW));
    WCHAR b[64];
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(ck_url(ck_host("nsw"), "/")), NULL, b, NULL, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_getex_w_reserved_nonnull) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("rsv"), "/");
    ck_set(u, NULL, "a=1");
    WCHAR b[64]; DWORD sz = 64; int dummy = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, &dummy), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(sz, 64);
    ck_cleanup();
}
TEST(ck_getex_a_reserved_nonnull) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("rsva"), "/");
    ck_set(u, NULL, "a=1");
    char b[64]; DWORD sz = sizeof b; int dummy = 0;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetCookieExA)(u, NULL, b, &sz, 0, &dummy);
    DWORD e = GetLastError();
    t_note("InternetGetCookieExA(lpReserved=&x): r=%d gle=%lu size=%lu data=%s", r, e, sz, r ? b : "-");
    EXPECT_EQ(r, TRUE);                 /* VM: the A form ignores lpReserved (only ...ExW checks it) */
    EXPECT_EQ(sz, 4);
    EXPECT_STR(r ? b : "", "a=1");
    ck_cleanup();
}
TEST(ck_get_a_null_url) {
    REQUIRE(U(InternetGetCookieA));
    char b[64]; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieA)(NULL, NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_get_w_null_url) {
    REQUIRE(U(InternetGetCookieW));
    WCHAR b[64]; DWORD sz = 64;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieW)(NULL, NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_get_a_null_size) {
    REQUIRE(U(InternetGetCookieA));
    char b[64];
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieA)(ck_url(ck_host("gns"), "/"), NULL, b, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_get_w_null_size) {
    REQUIRE(U(InternetGetCookieW));
    WCHAR b[64];
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieW)(ck_w(ck_url(ck_host("gnsw"), "/")), NULL, b, NULL), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------------------------------ get: no cookie */
TEST(ck_get_a_none_no_more_items) {
    REQUIRE(U(InternetGetCookieA));
    char b[64] = "untouched"; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieA)(ck_url(ck_host("none"), "/"), NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(sz, 0);
}
TEST(ck_get_w_none_no_more_items) {
    REQUIRE(U(InternetGetCookieW));
    WCHAR b[64]; DWORD sz = 64;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieW)(ck_w(ck_url(ck_host("nonew"), "/")), NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(sz, 0);
}
TEST(ck_getex_a_none_null_buffer) {
    REQUIRE(U(InternetGetCookieExA));
    DWORD sz = 77;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(ck_url(ck_host("nonenb"), "/"), NULL, NULL, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(sz, 0);
}
TEST(ck_getex_w_none_null_buffer) {
    REQUIRE(U(InternetGetCookieExW));
    DWORD sz = 77;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(ck_url(ck_host("nonenbw"), "/")), NULL, NULL, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(sz, 0);
}
TEST(ck_getex_none_by_name) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("nonenm"), "/");
    ck_set(u, NULL, "a=1");
    EXPECT_STR(ck_gets(u, "b", 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    EXPECT_EQ(ck_size, 0);
    EXPECT_STR(ck_gets(u, "a", 0), "a=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ buffer protocol A */
TEST(ck_getex_a_size_query_null_buffer) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("szq"), "/");
    ck_set(u, NULL, "abc=defg");
    DWORD sz = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, NULL, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 9);                 /* strlen("abc=defg") + 1 */
    EXPECT_ERR(0);
    sz = 1000;
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, NULL, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 9);
    ck_cleanup();
}
TEST(ck_get_a_size_query_null_buffer) {
    REQUIRE(U(InternetGetCookieA));
    const char *u = ck_url(ck_host("szqa"), "/");
    ck_set(u, NULL, "k=v");
    ck_set(u, NULL, "k2=v2");
    DWORD sz = 0;
    EXPECT_EQ(U(InternetGetCookieA)(u, NULL, NULL, &sz), TRUE);
    EXPECT_EQ(sz, strlen("k=v; k2=v2") + 1);
    ck_cleanup();
}
TEST(ck_getex_a_exact_buffer) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("exact"), "/");
    ck_set(u, NULL, "abc=defg");
    char b[9]; DWORD sz = 9;
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, b, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 9);
    EXPECT_STR(b, "abc=defg");
    ck_cleanup();
}
TEST(ck_getex_a_one_short) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("short"), "/");
    ck_set(u, NULL, "abc=defg");
    char b[16]; memset(b, 'Z', sizeof b); DWORD sz = 8;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, 9);
    EXPECT_EQ(b[0], 'Z');             /* nothing copied */
    ck_cleanup();
}
TEST(ck_getex_a_zero_size_nonnull_buffer) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("zero"), "/");
    ck_set(u, NULL, "abc=defg");
    char b[16] = "Z"; DWORD sz = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, 9);
    ck_cleanup();
}
TEST(ck_getex_a_large_buffer_size_out) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("large"), "/");
    ck_set(u, NULL, "abc=defg");
    char b[300]; DWORD sz = sizeof b;
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, b, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 9);                 /* A: bytes including the NUL */
    EXPECT_STR(b, "abc=defg");
    ck_cleanup();
}
TEST(ck_get_a_insufficient_then_retry) {
    REQUIRE(U(InternetGetCookieA));
    const char *u = ck_url(ck_host("retry"), "/");
    ck_set(u, NULL, "one=1111111111");
    ck_set(u, NULL, "two=2222222222");
    char b[8]; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieA)(u, NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    DWORD need = sz;
    EXPECT_EQ(need, strlen("one=1111111111; two=2222222222") + 1);
    char *big = malloc(need); DWORD sz2 = need;
    EXPECT_EQ(U(InternetGetCookieA)(u, NULL, big, &sz2), TRUE);
    EXPECT_EQ(sz2, need);
    EXPECT_EQ(strlen(big) + 1, need);
    free(big);
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ buffer protocol W */
TEST(ck_getex_w_size_query_null_buffer_bytes) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("wszq"), "/");
    ck_set(u, NULL, "abc=defg");
    DWORD sz = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, NULL, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 18);                /* (8 + 1) chars * 2: bytes */
    EXPECT_ERR(0);
    ck_cleanup();
}
TEST(ck_getex_w_success_size_chars) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("wsucc"), "/");
    ck_set(u, NULL, "abc=defg");
    WCHAR b[64]; DWORD sz = 64;
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 9);                 /* success: chars including NUL */
    EXPECT_WSTR(b, L"abc=defg");
    ck_cleanup();
}
TEST(ck_getex_w_exact_chars) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("wexact"), "/");
    ck_set(u, NULL, "abc=defg");
    WCHAR b[9]; DWORD sz = 9;         /* capacity in chars */
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 9);
    EXPECT_WSTR(b, L"abc=defg");
    ck_cleanup();
}
TEST(ck_getex_w_one_short_reports_bytes) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("wshort"), "/");
    ck_set(u, NULL, "abc=defg");
    WCHAR b[16]; b[0] = L'Z'; DWORD sz = 8;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, 18);                /* bytes */
    EXPECT_EQ(b[0], L'Z');
    ck_cleanup();
}
TEST(ck_get_w_size_query_and_fetch) {
    REQUIRE(U(InternetGetCookieW));
    const char *u = ck_url(ck_host("gwq"), "/");
    ck_set(u, NULL, "x=1");
    ck_set(u, NULL, "y=22");
    DWORD sz = 0;
    EXPECT_EQ(U(InternetGetCookieW)(ck_w(u), NULL, NULL, &sz), TRUE);
    EXPECT_EQ(sz, (strlen("x=1; y=22") + 1) * 2);
    WCHAR b[64]; sz = 64;
    EXPECT_EQ(U(InternetGetCookieW)(ck_w(u), NULL, b, &sz), TRUE);
    EXPECT_EQ(sz, strlen("x=1; y=22") + 1);
    EXPECT_WSTR(b, L"x=1; y=22");
    ck_cleanup();
}
TEST(ck_getex_w_zero_size_nonnull) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("wzero"), "/");
    ck_set(u, NULL, "q=1");
    WCHAR b[8]; DWORD sz = 0;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL), FALSE);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sz, 8);                 /* "q=1" + NUL = 4 chars = 8 bytes */
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ name argument */
TEST(ck_get_a_ignores_name) {
    REQUIRE(U(InternetGetCookieA));
    const char *u = ck_url(ck_host("ign"), "/");
    ck_set(u, NULL, "a=1");
    ck_set(u, NULL, "b=2");
    char b[128]; DWORD sz = sizeof b;
    EXPECT_EQ(U(InternetGetCookieA)(u, "a", b, &sz), TRUE);   /* InternetGetCookieA passes NULL name to ...ExA */
    EXPECT_STR(b, "a=1; b=2");
    sz = sizeof b;
    EXPECT_EQ(U(InternetGetCookieA)(u, "nosuch", b, &sz), TRUE);
    EXPECT_STR(b, "a=1; b=2");
    ck_cleanup();
}
TEST(ck_get_w_name_behaviour) {
    REQUIRE(U(InternetGetCookieW));
    const char *u = ck_url(ck_host("ignw"), "/");
    ck_set(u, NULL, "a=1");
    ck_set(u, NULL, "b=2");
    WCHAR b[128]; DWORD sz = 128;
    BOOL r = U(InternetGetCookieW)(ck_w(u), L"b", b, &sz);
    t_note("InternetGetCookieW(name=b): r=%d gle=%lu data=%s", r, GetLastError(), r ? ck_a(b) : "-");
    EXPECT_EQ(r, TRUE);
    EXPECT_WSTR(b, L"b=2");             /* VM: unlike InternetGetCookieA, the W form passes the name through */
    ck_cleanup();
}
TEST(ck_getex_a_name_filter) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("filt"), "/");
    ck_set(u, NULL, "a=1");
    ck_set(u, NULL, "b=2");
    ck_set(u, NULL, "c=3");
    EXPECT_STR(ck_gets(u, "b", 0), "b=2");
    EXPECT_EQ(ck_size, 4);
    EXPECT_STR(ck_gets(u, "c", 0), "c=3");
    EXPECT_STR(ck_gets(u, "a", 0), "a=1");
    EXPECT_STR(ck_gets(u, "", 0), "");
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    ck_cleanup();
}
TEST(ck_getex_a_name_filter_case_sensitive) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("filtci"), "/");
    ck_set(u, NULL, "MixCase=1");
    EXPECT_STR(ck_gets(u, "mixcase", 0), "");           /* lstrcmpA: case-sensitive (VM) */
    EXPECT_EQ(ck_gle, ERROR_NO_MORE_ITEMS);
    EXPECT_STR(ck_gets(u, "MIXCASE", 0), "");
    EXPECT_STR(ck_gets(u, "MixCase", 0), "MixCase=1");
    EXPECT_STR(ck_gets(u, "MixCas", 0), "");
    ck_cleanup();
}
TEST(ck_getex_w_name_filter) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("filtw"), "/");
    ck_set(u, NULL, "a=1");
    ck_set(u, NULL, "bb=22");
    WCHAR b[64]; DWORD sz = 64;
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), L"bb", b, &sz, 0, NULL), TRUE);
    EXPECT_WSTR(b, L"bb=22");
    EXPECT_EQ(sz, 6);
    sz = 0;
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), L"bb", NULL, &sz, 0, NULL), TRUE);
    EXPECT_EQ(sz, 12);
    ck_cleanup();
}
TEST(ck_getex_name_filter_nameless) {
    REQUIRE(U(InternetGetCookieExA));
    const char *u = ck_url(ck_host("filtnl"), "/");
    ck_set(u, NULL, "loneval");
    ck_set(u, NULL, "a=1");
    const char *all = ck_gets(u, NULL, 0);
    CHECKF(ck_has(all, "loneval") && ck_has(all, "a=1") && ck_count(all) == 2, "got '%s'", all);
    EXPECT_STR(ck_gets(u, "loneval", 0), "");     /* the value is not a name */
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ W conversions */
TEST(ck_w_roundtrip_ascii) {
    REQUIRE(U(InternetSetCookieW)); REQUIRE(U(InternetGetCookieW));
    const char *u = ck_url(ck_host("wrt"), "/");
    ck_track(u, "wname", NULL, 0);
    EXPECT_EQ(U(InternetSetCookieW)(ck_w(u), NULL, L"wname=wvalue"), TRUE);
    WCHAR b[64]; DWORD sz = 64;
    EXPECT_EQ(U(InternetGetCookieW)(ck_w(u), NULL, b, &sz), TRUE);
    EXPECT_WSTR(b, L"wname=wvalue");
    EXPECT_STR(ck_gets(u, NULL, 0), "wname=wvalue");
    ck_cleanup();
}
TEST(ck_w_value_latin1_acp) {
    REQUIRE(U(InternetSetCookieW)); REQUIRE(U(InternetGetCookieExW));
    UINT acp = GetACP();
    const char *u = ck_url(ck_host("wl1"), "/");
    ck_track(u, "lat", NULL, 0);
    EXPECT_EQ(U(InternetSetCookieW)(ck_w(u), NULL, L"lat=caf\x00e9"), TRUE);
    WCHAR b[64]; DWORD sz = 64;
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL), TRUE);
    if (acp == 1252) { EXPECT_WSTR(b, L"lat=caf\x00e9"); EXPECT_EQ(sz, 9); }
    else t_note("ACP %u: got %s", acp, ck_a(b));
    char a[64]; DWORD asz = sizeof a;
    EXPECT_EQ(U(InternetGetCookieExA)(u, NULL, a, &asz, 0, NULL), TRUE);
    if (acp == 1252) { EXPECT_STR(a, "lat=caf\xe9"); EXPECT_EQ(asz, 9); }
    ck_cleanup();
}
TEST(ck_a_set_w_get_mixed) {
    REQUIRE(U(InternetGetCookieExW));
    const char *u = ck_url(ck_host("mix"), "/p/");
    ck_set(u, NULL, "m1=v1");
    WCHAR b[64]; DWORD sz = 64;
    EXPECT_EQ(U(InternetGetCookieExW)(ck_w(u), NULL, b, &sz, 0, NULL), TRUE);
    EXPECT_WSTR(b, L"m1=v1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ URL validation */
TEST(ck_set_url_no_scheme) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetCookieA)("not a url", NULL, "a=1");
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    t_note("InternetSetCookieA(\"not a url\"): gle=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}
TEST(ck_get_url_no_scheme) {
    REQUIRE(U(InternetGetCookieA));
    char b[64]; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetCookieA)("not a url", NULL, b, &sz);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    t_note("InternetGetCookieA(\"not a url\"): gle=%lu %s", e, t_inet_errname(e));
    EXPECT_EQ(e, ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}
TEST(ck_set_url_empty) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetCookieA)("", NULL, "a=1");
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}
TEST(ck_get_url_empty) {
    REQUIRE(U(InternetGetCookieExA));
    char b[64]; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetGetCookieExA)("", NULL, b, &sz, 0, NULL);
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}
TEST(ck_set_url_ftp_scheme_invalid) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieA)("ftp://wininet-ck.i7test.example/x/", NULL, "a=1"), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);   /* PathAndRDomainFromURL accepts http, https, file only */
}
TEST(ck_get_url_ftp_scheme_invalid) {
    REQUIRE(U(InternetGetCookieA));
    char b[64]; DWORD sz = sizeof b;
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetGetCookieA)("ftp://wininet-ck.i7test.example/x/", NULL, b, &sz), FALSE);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(ck_set_url_host_bad_char) {
    REQUIRE(U(InternetSetCookieA));
    SetLastError(0xdeadbeef);
    BOOL r = U(InternetSetCookieA)("http://bad!host.i7test.example/", NULL, "a=1");
    DWORD e = GetLastError();
    EXPECT_EQ(r, FALSE);
    EXPECT_EQ(e, ERROR_INVALID_PARAMETER);
}
TEST(ck_set_url_uppercase_host_same_jar) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("upper");
    char up[256]; snprintf(up, sizeof up, "%s", h); for (char *p = up; *p; p++) *p = (char)toupper((unsigned char)*p);
    ck_set(ck_url(up, "/"), NULL, "u=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "u=1");     /* host is lower-cased */
    EXPECT_STR(ck_gets(ck_url(up, "/"), NULL, 0), "u=1");
    ck_cleanup();
}
TEST(ck_set_url_with_port_ignored) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("port");
    char pu[300]; snprintf(pu, sizeof pu, "http://%s:8123/", h);
    ck_set(pu, NULL, "p=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "p=1");
    char pu2[300]; snprintf(pu2, sizeof pu2, "http://%s:9/", h);
    EXPECT_STR(ck_gets(pu2, NULL, 0), "p=1");
    ck_cleanup();
}
TEST(ck_set_url_query_and_fragment) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("qf");
    ck_set(ck_url(h, "/q/?x=1#frag"), NULL, "qf=1; path=/q/");
    EXPECT_STR(ck_gets(ck_url(h, "/q/?y=2"), NULL, 0), "qf=1");
    EXPECT_STR(ck_gets(ck_url(h, "/q/#z"), NULL, 0), "qf=1");
    ck_cleanup();
}
TEST(ck_set_url_userinfo) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("ui");
    char uu[300]; snprintf(uu, sizeof uu, "http://user:pw@%s/", h);
    BOOL r = ck_set(uu, NULL, "ui=1");
    EXPECT_EQ(r, TRUE);
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "ui=1");
    ck_cleanup();
}
TEST(ck_set_https_get_http_same_jar) {
    REQUIRE(U(InternetSetCookieA));
    const char *h = ck_host("schemes");
    ck_set(ck_surl(h, "/"), NULL, "s=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "s=1");     /* not scheme-scoped unless Secure */
    EXPECT_STR(ck_gets(ck_surl(h, "/"), NULL, 0), "s=1");
    ck_cleanup();
}

/* ------------------------------------------------------------------------------------------ W-only checks */
TEST(ck_setex_w_url_conversion) {
    REQUIRE(U(InternetSetCookieExW));
    const char *h = ck_host("wconv");
    const char *u = ck_url(h, "/wc/");
    ck_track(u, "wc", NULL, 0);
    EXPECT_EQ(U(InternetSetCookieExW)(ck_w(u), L"wc", L"1; path=/wc/", 0, 0), COOKIE_STATE_ACCEPT);
    EXPECT_STR(ck_gets(u, NULL, 0), "wc=1");
    EXPECT_STR(ck_gets(ck_url(h, "/"), NULL, 0), "");
    ck_cleanup();
}
TEST(ck_set_w_httponly_rejected) {
    REQUIRE(U(InternetSetCookieW));
    const char *u = ck_url(ck_host("whttp"), "/");
    ck_track(u, "h", NULL, 0);
    SetLastError(0xdeadbeef);
    EXPECT_EQ(U(InternetSetCookieW)(ck_w(u), NULL, L"h=1; HttpOnly"), FALSE);
    EXPECT_ERR(ERROR_INVALID_OPERATION);
    ck_cleanup();
}
