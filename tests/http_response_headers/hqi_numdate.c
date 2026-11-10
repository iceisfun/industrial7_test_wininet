/* hqi_numdate.c - HTTP_QUERY_FLAG_NUMBER / NUMBER64 / SYSTEMTIME conversions.
 * VM_TIMEOUT: 240
 *
 * [D] _FormatAsDword -> _FormatAsUlonglong(value, len, strict=0): digits accumulate; the first non-digit ends the
 * number successfully (so "12abc" = 12 and "abc" = 0); an empty value -> 12154; 64-bit overflow -> 534
 * ERROR_ARITHMETIC_OVERFLOW; > 0xFFFFFFFF for the 32-bit form -> 12153 ERROR_HTTP_INVALID_HEADER.
 * NUMBER64 (_FindHeader inline loop): same rules, 8 bytes. SYSTEMTIME: FInternalParseHttpDate on a copy of the value;
 * a value of 128 bytes or more -> 12004 ERROR_INTERNET_INTERNAL_ERROR; unparsable -> 12154.
 * [W10 laneg task 65] lenient date parsing results (docs/research/03 A.2).
 */
#include "rh.h"

static const struct { const char *val; DWORD err; DWORD n; } num32[] = {
    { "0", 0, 0 }, { "1", 0, 1 }, { "42", 0, 42 }, { "007", 0, 7 }, { "000000000000000000000000000001", 0, 1 },
    { "65535", 0, 65535 }, { "2147483647", 0, 2147483647u }, { "2147483648", 0, 2147483648u }, { "4294967295", 0, 4294967295u },
    { "4294967296", ERROR_HTTP_INVALID_HEADER, 0 }, { "9999999999", ERROR_HTTP_INVALID_HEADER, 0 },
    { "18446744073709551615", ERROR_HTTP_INVALID_HEADER, 0 },
    { "18446744073709551616", ERROR_ARITHMETIC_OVERFLOW, 0 }, { "99999999999999999999999", ERROR_ARITHMETIC_OVERFLOW, 0 },
    { "12abc", 0, 12 }, { "1.5", 0, 1 }, { "1 2", 0, 1 }, { "3,4", 0, 3 }, { "5;q=1", 0, 5 },
    { "abc", 0, 0 }, { "-1", 0, 0 }, { "+5", 0, 0 }, { "0x10", 0, 0 }, { " 9", 0, 9 }, { "9 ", 0, 9 }, { "\xb2", 0, 0 },
};

static char g_resp[8192];
static size_t build_num_resp(void) {
    size_t o = 0;
    o += (size_t)snprintf(g_resp + o, sizeof g_resp - o, "HTTP/1.1 200 OK\r\n");
    for (size_t i = 0; i < sizeof num32 / sizeof num32[0]; i++) o += (size_t)snprintf(g_resp + o, sizeof g_resp - o, "X-N%u: %s\r\n", (unsigned)i, num32[i].val);
    o += (size_t)snprintf(g_resp + o, sizeof g_resp - o, "Content-Length: 0\r\nConnection: close\r\n\r\n");
    return o;
}

TEST(hqi_num_number32_table) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    rh_t c; if (!rh_raw(&c, "GET", g_resp, build_num_resp())) return; RH_SENT_OR_FAIL(&c);
    for (size_t i = 0; i < sizeof num32 / sizeof num32[0]; i++) {
        char nm[16]; snprintf(nm, sizeof nm, "X-N%u", (unsigned)i);
        DWORD n; BOOL ok = rh_qnumc(c.hr, nm, &n);
        if (num32[i].err) CHECKF(!ok && rh_err == num32[i].err, "\"%s\": ok=%d n=%lu err=%lu want err %lu", num32[i].val, ok, n, rh_err, num32[i].err);
        else CHECKF(ok && n == num32[i].n && rh_len == 4, "\"%s\": ok=%d n=%lu err=%lu want %lu", num32[i].val, ok, n, rh_err, num32[i].n);
        /* W: binary result copied raw */
        WCHAR w[32]; lstrcpyW(w, L"X-N"); { WCHAR d[8]; wsprintfW(d, L"%u", (unsigned)i); lstrcatW(w, d); }
        BOOL okw = rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, w, sizeof w, NULL);
        if (num32[i].err) CHECKF(!okw && rh_err == num32[i].err, "W \"%s\": err=%lu", num32[i].val, rh_err);
        else CHECKF(okw && *(DWORD *)w == num32[i].n && rh_len == 4, "W \"%s\": ok=%d err=%lu", num32[i].val, okw, rh_err);
    }
    rh_close(&c);
}

TEST(hqi_num_number64_table) {
    REQUIRE(U(HttpQueryInfoA));
    static const struct { const char *val; DWORD err; ULONGLONG n; } t[] = {
        { "0", 0, 0 }, { "4294967296", 0, 4294967296ull }, { "9007199254740993", 0, 9007199254740993ull },
        { "18446744073709551615", 0, 18446744073709551615ull }, { "18446744073709551616", ERROR_ARITHMETIC_OVERFLOW, 0 },
        { "184467440737095516150", ERROR_ARITHMETIC_OVERFLOW, 0 }, { "12abc", 0, 12 }, { "abc", 0, 0 }, { "-5", 0, 0 },
        { "00000000000000000000000000000000000000042", 0, 42 }, { "5000000000 bytes", 0, 5000000000ull },
    };
    char resp[4096]; size_t o = 0;
    o += (size_t)snprintf(resp + o, sizeof resp - o, "HTTP/1.1 200 OK\r\n");
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) o += (size_t)snprintf(resp + o, sizeof resp - o, "X-Q%u: %s\r\n", (unsigned)i, t[i].val);
    o += (size_t)snprintf(resp + o, sizeof resp - o, "X-Empty:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    rh_t c; if (!rh_raw(&c, "GET", resp, o)) return; RH_SENT_OR_FAIL(&c);
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char nm[16]; snprintf(nm, sizeof nm, "X-Q%u", (unsigned)i);
        ULONGLONG n; BOOL ok = rh_qnum64c(c.hr, nm, &n);
        if (t[i].err) CHECKF(!ok && rh_err == t[i].err, "\"%s\": ok=%d err=%lu want %lu", t[i].val, ok, rh_err, t[i].err);
        else CHECKF(ok && n == t[i].n && rh_len == 8, "\"%s\": ok=%d n=%llu err=%lu", t[i].val, ok, n, rh_err);
    }
    ULONGLONG n; CHECK(!rh_qnum64c(c.hr, "X-Empty", &n)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    CHECK(!rh_qnum64c(c.hr, "X-Absent", &n)); EXPECT_EQ(rh_err, ERROR_HTTP_HEADER_NOT_FOUND);
    rh_close(&c);
}

TEST(hqi_num_content_length_values) {
    REQUIRE(U(HttpQueryInfoA));
    static const struct { const char *cl; DWORD err32; DWORD n32; ULONGLONG n64; } t[] = {
        { "0", 0, 0, 0 }, { "12", 0, 12, 12 }, { "  77", 0, 77, 77 }, { "4294967295", 0, 4294967295u, 4294967295ull },
        { "4294967296", ERROR_HTTP_INVALID_HEADER, 0, 4294967296ull }, { "1099511627776", ERROR_HTTP_INVALID_HEADER, 0, 1099511627776ull },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        char resp[256]; int k = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\nContent-Length: %s\r\nConnection: close\r\n\r\n", t[i].cl);
        rh_t c; if (!rh_raw(&c, "HEAD", resp, (size_t)k)) return;
        CHECKF(c.sent, "CL %s: err=%lu", t[i].cl, c.err);
        if (c.sent) {
            DWORD n; BOOL ok = rh_qnum(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n);
            if (t[i].err32) CHECKF(!ok && rh_err == t[i].err32, "CL %s NUMBER: ok=%d err=%lu", t[i].cl, ok, rh_err);
            else CHECKF(ok && n == t[i].n32, "CL %s NUMBER: ok=%d n=%lu err=%lu", t[i].cl, ok, n, rh_err);
            ULONGLONG n64; ok = rh_qnum64(c.hr, HTTP_QUERY_CONTENT_LENGTH, &n64);
            CHECKF(ok && n64 == t[i].n64, "CL %s NUMBER64: ok=%d n=%llu err=%lu", t[i].cl, ok, n64, rh_err);
            const char *s = rh_qa(c.hr, HTTP_QUERY_CONTENT_LENGTH, NULL);
            const char *want = t[i].cl; while (*want == ' ') want++;
            EXPECT_STR(s, want);
        }
        rh_close(&c);
    }
}

/* NUMBER on a level whose mask lacks it (everything but Content-Length and STATUS_CODE) -> 12154 even for digits */
TEST(hqi_num_number_rejected_on_other_levels) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nAge: 30\r\nMax-Forwards: 5\r\nRetry-After: 120\r\nX-N: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    DWORD n;
    CHECK(!rh_qnum(c.hr, HTTP_QUERY_AGE, &n)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    CHECK(!rh_qnum(c.hr, HTTP_QUERY_MAX_FORWARDS, &n)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    CHECK(!rh_qnum(c.hr, HTTP_QUERY_RETRY_AFTER, &n)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    /* ...but by name through CUSTOM they convert */
    CHECK(rh_qnumc(c.hr, "Age", &n)); EXPECT_EQ(n, 30);
    CHECK(rh_qnumc(c.hr, "max-forwards", &n)); EXPECT_EQ(n, 5);
    CHECK(rh_qnumc(c.hr, "Retry-After", &n)); EXPECT_EQ(n, 120);
    EXPECT_QA(c.hr, HTTP_QUERY_AGE, "30");
    rh_close(&c);
}

/* ------------------------------------------------------------------ SYSTEMTIME */
typedef struct { const char *val; DWORD err; WORD y, mo, dow, d, h, mi, s; } date_case;
static const date_case dates[] = {
    { "Sun, 06 Nov 1994 08:49:37 GMT", 0, 1994, 11, 0, 6, 8, 49, 37 },
    { "Sunday, 06-Nov-94 08:49:37 GMT", 0, 1994, 11, 0, 6, 8, 49, 37 },
    { "Sun Nov  6 08:49:37 1994", 0, 1994, 11, 0, 6, 8, 49, 37 },
    { "Tue, 15 Nov 1994 12:45:26 GMT", 0, 1994, 11, 2, 15, 12, 45, 26 },
    { "Tuesday, 15-Nov-94 12:45:26 GMT", 0, 1994, 11, 2, 15, 12, 45, 26 },
    { "Tue Nov 15 12:45:26 1994", 0, 1994, 11, 2, 15, 12, 45, 26 },
    { "Tue, 15 Nov 1994 12:45:26", 0, 1994, 11, 2, 15, 12, 45, 26 },          /* no zone [W10 task 65] */
    { "Wed, 15 Nov 1994 12:45:26 GMT", 0, 1994, 11, 3, 15, 12, 45, 26 },      /* weekday name taken as is [W10] */
    { "Tue, 15 Nov 94 12:45:26 GMT", 0, 1994, 11, 2, 15, 12, 45, 26 },        /* 2-digit year [W10] */
    { "Tue, 15 Nov 1994 12:45:26 +0100", 0, 1994, 11, 2, 15, 12, 45, 26 },    /* numeric zone ignored [W10] */
    { "Tue,   15   Nov   1994   12:45:26   GMT", 0, 1994, 11, 2, 15, 12, 45, 26 },
    { "Tue, 15 Nov 1994", 0, 1994, 11, 2, 15, 0, 0, 0 },                      /* date only [W10] */
    { "Thu, 01 Jan 1970 00:00:00 GMT", 0, 1970, 1, 4, 1, 0, 0, 0 },
    { "Sat, 01 Jan 2000 00:00:00 GMT", 0, 2000, 1, 6, 1, 0, 0, 0 },
    { "Tue, 29 Feb 2000 23:59:59 GMT", 0, 2000, 2, 2, 29, 23, 59, 59 },
    { "Tue, 19 Jan 2038 03:14:08 GMT", 0, 2038, 1, 2, 19, 3, 14, 8 },
    { "Fri, 31 Dec 9999 23:59:59 GMT", 0, 9999, 12, 5, 31, 23, 59, 59 },
    { "Mon, 15 Jun 2026 07:08:09 GMT", 0, 2026, 6, 1, 15, 7, 8, 9 },
    { "not a date", ERROR_HTTP_INVALID_QUERY_REQUEST, 0 },                   /* [W10] 12154 */
    { "Mon, 32 Feb 2024 25:61:61 GMT", ERROR_HTTP_INVALID_QUERY_REQUEST, 0 }, /* [W10] 12154 */
};

static void check_date(const SYSTEMTIME *st, const date_case *d, const char *what) {
    CHECKF(st->wYear == d->y && st->wMonth == d->mo && st->wDayOfWeek == d->dow && st->wDay == d->d && st->wHour == d->h &&
           st->wMinute == d->mi && st->wSecond == d->s && st->wMilliseconds == 0,
           "%s \"%s\": got %04u-%02u-%02u dow%u %02u:%02u:%02u.%03u", what, d->val, st->wYear, st->wMonth, st->wDay, st->wDayOfWeek,
           st->wHour, st->wMinute, st->wSecond, st->wMilliseconds);
}

TEST(hqi_date_custom_table) {
    REQUIRE(U(HttpQueryInfoA)); REQUIRE(U(HttpQueryInfoW));
    char resp[8192]; size_t o = 0;
    o += (size_t)snprintf(resp + o, sizeof resp - o, "HTTP/1.1 200 OK\r\n");
    for (size_t i = 0; i < sizeof dates / sizeof dates[0]; i++) o += (size_t)snprintf(resp + o, sizeof resp - o, "X-D%u: %s\r\n", (unsigned)i, dates[i].val);
    o += (size_t)snprintf(resp + o, sizeof resp - o, "Content-Length: 0\r\nConnection: close\r\n\r\n");
    rh_t c; if (!rh_raw(&c, "GET", resp, o)) return; RH_SENT_OR_FAIL(&c);
    for (size_t i = 0; i < sizeof dates / sizeof dates[0]; i++) {
        char nm[16]; snprintf(nm, sizeof nm, "X-D%u", (unsigned)i);
        SYSTEMTIME st; BOOL ok = rh_qtimec(c.hr, nm, &st);
        if (dates[i].err) { CHECKF(!ok && rh_err == dates[i].err, "\"%s\": ok=%d err=%lu", dates[i].val, ok, rh_err); continue; }
        CHECKF(ok && rh_len == 16, "\"%s\": ok=%d err=%lu len=%lu", dates[i].val, ok, rh_err, rh_len);
        if (ok) check_date(&st, &dates[i], "A");
        WCHAR w[32]; wsprintfW(w, L"X-D%u", (unsigned)i);
        ok = rh_callW(c.hr, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_SYSTEMTIME, w, sizeof w, NULL);
        CHECKF(ok && rh_len == 16, "W \"%s\": ok=%d err=%lu", dates[i].val, ok, rh_err);
        if (ok) check_date((SYSTEMTIME *)w, &dates[i], "W");
        EXPECT_QC(c.hr, nm, dates[i].val);   /* the text form is untouched */
    }
    rh_close(&c);
}

/* the date levels whose mask has SYSTEMTIME: Date, Last-Modified, If-Modified-Since, Retry-After, If-Unmodified-Since, Expect */
TEST(hqi_date_levels_with_systemtime) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\n"
        "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\nLast-Modified: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
        "If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nRetry-After: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
        "If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\nExpect: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
        "Expires: Sun, 06 Nov 1994 08:49:37 GMT\r\nUnless-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    static const DWORD ok_lv[] = { HTTP_QUERY_DATE, HTTP_QUERY_LAST_MODIFIED, HTTP_QUERY_IF_MODIFIED_SINCE, HTTP_QUERY_RETRY_AFTER,
                                   HTTP_QUERY_IF_UNMODIFIED_SINCE, HTTP_QUERY_EXPECT };
    for (size_t i = 0; i < sizeof ok_lv / sizeof ok_lv[0]; i++) {
        SYSTEMTIME st; BOOL ok = rh_qtime(c.hr, ok_lv[i], &st);
        CHECKF(ok, "level %lu SYSTEMTIME err=%lu", ok_lv[i], rh_err);
        if (ok) check_date(&st, &dates[0], "level");
    }
    /* Expires and Unless-Modified-Since: mask without SYSTEMTIME -> 12154 although the text is a valid date [D] */
    SYSTEMTIME st;
    CHECK(!rh_qtime(c.hr, HTTP_QUERY_EXPIRES, &st)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    CHECK(!rh_qtime(c.hr, HTTP_QUERY_UNLESS_MODIFIED_SINCE, &st)); EXPECT_EQ(rh_err, ERROR_HTTP_INVALID_QUERY_REQUEST);
    EXPECT_QA(c.hr, HTTP_QUERY_EXPIRES, "Sun, 06 Nov 1994 08:49:37 GMT");
    /* the CUSTOM route for Expires converts */
    CHECK(rh_qtimec(c.hr, "Expires", &st)); check_date(&st, &dates[0], "CUSTOM Expires");
    rh_close(&c);
}

/* values of 128 bytes or more are not parsed: 12004 [D _FindHeader: uVar14 < 0x80] */
TEST(hqi_date_long_value) {
    REQUIRE(U(HttpQueryInfoA));
    char pad127[200], pad128[200];
    snprintf(pad127, sizeof pad127, "Sun, 06 Nov 1994 08:49:37 GMT%*s", 127 - 29 - 1, "");
    snprintf(pad128, sizeof pad128, "Sun, 06 Nov 1994 08:49:37 GMT%*sX", 127 - 29, "");
    char resp[1024]; int n = snprintf(resp, sizeof resp, "HTTP/1.1 200 OK\r\nX-D127: %s.\r\nX-D128: %s\r\nX-D500: %0500d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                      pad127, pad128, 7);
    rh_t c; if (!rh_raw(&c, "GET", resp, (size_t)n)) return; RH_SENT_OR_FAIL(&c);
    const char *v = rh_qac(c.hr, "X-D127", 0, NULL); CHECK(v && rh_len == 127);
    v = rh_qac(c.hr, "X-D128", 0, NULL); CHECK(v && rh_len == 128);
    SYSTEMTIME st;
    BOOL ok = rh_qtimec(c.hr, "X-D127", &st);
    t_note("127-byte date value (trailing padding then '.'): ok=%d err=%lu y=%u", ok, rh_err, ok ? st.wYear : 0);
    CHECK(!rh_qtimec(c.hr, "X-D128", &st)); EXPECT_EQ(rh_err, ERROR_INTERNET_INTERNAL_ERROR);
    CHECK(!rh_qtimec(c.hr, "X-D500", &st)); EXPECT_EQ(rh_err, ERROR_INTERNET_INTERNAL_ERROR);
    rh_close(&c);
}

/* clock-dependent results (laneg: a bare number or empty value gives "now"): only recorded */
TEST(hqi_date_clock_filled_values_recorded) {
    REQUIRE(U(HttpQueryInfoA));
    static const char resp[] = "HTTP/1.1 200 OK\r\nX-A: 15\r\nX-B:\r\nX-C: Tue, 15 Nov\r\nRetry-After: 120\r\nX-E: 15 Nov 1994 12:45:26 GMT\r\n"
                               "X-F: tue, 15 nov 1994 12:45:26 gmt\r\nX-G: 1994-11-15T12:45:26Z\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    rh_t c; if (!RH_RAW(&c, "GET", resp)) return; RH_SENT_OR_FAIL(&c);
    static const char *nm[] = { "X-A", "X-B", "X-C", "Retry-After", "X-E", "X-F", "X-G" };
    SYSTEMTIME now; GetSystemTime(&now);
    for (int i = 0; i < 7; i++) {
        SYSTEMTIME st; BOOL ok = rh_qtimec(c.hr, nm[i], &st);
        if (ok) t_note("%s -> %04u-%02u-%02u dow%u %02u:%02u:%02u (now %04u-%02u-%02u %02u:%02u)", nm[i], st.wYear, st.wMonth, st.wDay, st.wDayOfWeek,
                       st.wHour, st.wMinute, st.wSecond, now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute);
        else t_note("%s -> err %lu", nm[i], rh_err);
    }
    rh_close(&c);
}
