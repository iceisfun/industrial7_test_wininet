/* InternetTimeFromSystemTime(A|W) and the undecorated alias.
 * [D InternetTimeFromSystemTime@0x19ccd0 (= ...A)]:
 *   cbTime < 30                      -> FALSE, 122 (checked before anything else, buffer untouched)
 *   dwRFC != 0 / NULL st / NULL buf  -> FALSE, 87
 *   SystemTimeToFileTime(st) fails   -> FALSE, 87
 *   wDay > 6: st is normalised through FILETIME (real weekday); wDay <= 6: the caller's wDayOfWeek is printed
 *   StringCchPrintfA("%s, %02i %s %02i %02i:%02i:%02i GMT"); truncation -> FALSE, 122 (truncated text written)
 * [D InternetTimeFromSystemTimeW@0x19ce30]:
 *   cbTime < 60 -> 122; NULL buf -> 87; calls A with a cbTime-byte scratch buffer; then requires
 *   cbTime > 2 * (chars incl NUL) (`cmp rdi,rcx; ja`), else FALSE/122. */
#include "tm.h"

const char *const tm_wk[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const char *const tm_mon[13] = { "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static SYSTEMTIME mk(int y, int mo, int dow, int d, int h, int mi, int s, int ms) {
    SYSTEMTIME st; st.wYear = (WORD)y; st.wMonth = (WORD)mo; st.wDayOfWeek = (WORD)dow; st.wDay = (WORD)d;
    st.wHour = (WORD)h; st.wMinute = (WORD)mi; st.wSecond = (WORD)s; st.wMilliseconds = (WORD)ms; return st;
}
/* Reference rendering of the decomp's format, including the weekday rule. */
static void ref_fmt(const SYSTEMTIME *st, char *out, size_t cap) {
    int dow = st->wDay > 6 ? tm_weekday(st->wYear, st->wMonth, st->wDay) : st->wDayOfWeek;
    snprintf(out, cap, "%s, %02d %s %02d %02d:%02d:%02d GMT", tm_wk[dow], st->wDay, tm_mon[st->wMonth], st->wYear,
             st->wHour, st->wMinute, st->wSecond);
}

/* ------------------------------------------------------------ constants */
TEST(tmf_constants) {
    EXPECT_EQ(INTERNET_RFC1123_FORMAT, 0);
    EXPECT_EQ(INTERNET_RFC1123_BUFSIZE, 30);
}

TEST(tmf_alias_resolves) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    REQUIRE(UN(InternetTimeFromSystemTime));
    /* COMDAT-folded on Win10 [D]; a reimplementation may use separate code: note only. */
    t_note("InternetTimeFromSystemTime %s InternetTimeFromSystemTimeA",
           (void *)UN(InternetTimeFromSystemTime) == (void *)U(InternetTimeFromSystemTimeA) ? "==" : "!=");
}

/* ------------------------------------------------------------ A: basic */
TEST(tmf_a_rfc1123_example) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    char buf[64]; tm_fill(buf, sizeof buf);
    SET_ERR(0xdead);
    BOOL r = U(InternetTimeFromSystemTimeA)(&st, INTERNET_RFC1123_FORMAT, buf, sizeof buf);
    CHECK(r);
    EXPECT_STR(buf, "Sun, 06 Nov 1994 08:49:37 GMT");
    EXPECT_EQ(strlen(buf), 29);
    EXPECT_EQ((unsigned char)buf[30], 0xAB);    /* nothing written past the NUL */
}

TEST(tmf_a_success_leaves_lasterror) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(2001, 2, 6, 3, 4, 5, 6, 0);
    char buf[40];
    SET_ERR(0x1234);
    CHECK(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf));
    EXPECT_ERR(0x1234);   /* success path does not call SetLastError [D] */
    EXPECT_STR(buf, "Sat, 03 Feb 2001 04:05:06 GMT");
}

TEST(tmf_plain_name_is_ansi) {
    REQUIRE(UN(InternetTimeFromSystemTime));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    char buf[40];
    CHECK(UN(InternetTimeFromSystemTime)(&st, 0, buf, sizeof buf));
    EXPECT_STR(buf, "Sun, 06 Nov 1994 08:49:37 GMT");
}

/* ------------------------------------------------------------ A: buffer sizes */
TEST(tmf_a_bufsize_table) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    for (DWORD cb = 0; cb <= 40; cb++) {
        char buf[64]; tm_fill(buf, sizeof buf);
        SET_ERR(0);
        BOOL r = U(InternetTimeFromSystemTimeA)(&st, 0, buf, cb);
        if (cb < 30) {
            CHECKF(!r, "cb=%lu", cb); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
            CHECKF(tm_is_filled(buf, sizeof buf), "cb=%lu buffer touched", cb);
        } else {
            CHECKF(r, "cb=%lu", cb);
            EXPECT_STR(buf, "Sun, 06 Nov 1994 08:49:37 GMT");
        }
    }
}

TEST(tmf_a_small_buffer_beats_null_args) {
    /* cbTime < 30 is checked first: even NULL st / NULL buffer / bad dwRFC report 122 [D]. */
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    char buf[40];
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(NULL, 0, NULL, 0));  EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(NULL, 0, buf, 29));  EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(&st, 5, buf, 29));   EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(&st, 0, NULL, 1));   EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
}

TEST(tmf_a_null_args) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    char buf[40];
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(NULL, 0, buf, sizeof buf)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(&st, 0, NULL, 30));        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeA)(NULL, 0, NULL, 30));       EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tmf_a_rfc_values) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    static const DWORD bad[] = { 1, 2, 3, 0x10, 0x80000000u, 0xFFFFFFFFu };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char buf[40]; tm_fill(buf, sizeof buf);
        SET_ERR(0);
        CHECKF(!U(InternetTimeFromSystemTimeA)(&st, bad[i], buf, sizeof buf), "dwRFC=0x%lx", bad[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(tm_is_filled(buf, sizeof buf), "dwRFC=0x%lx buffer touched", bad[i]);
    }
}

/* ------------------------------------------------------------ A: invalid SYSTEMTIME */
TEST(tmf_a_invalid_systemtime_table) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    static const struct { int y, mo, d, h, mi, s, ms; const char *why; } t[] = {
        { 1994, 0, 6, 8, 49, 37, 0, "month 0" },      { 1994, 13, 6, 8, 49, 37, 0, "month 13" },
        { 1994, 11, 0, 8, 49, 37, 0, "day 0" },       { 1994, 11, 31, 8, 49, 37, 0, "Nov 31" },
        { 1994, 11, 32, 8, 49, 37, 0, "day 32" },     { 2023, 2, 29, 0, 0, 0, 0, "Feb 29 non-leap" },
        { 2100, 2, 29, 0, 0, 0, 0, "Feb 29 2100" },   { 2024, 2, 30, 0, 0, 0, 0, "Feb 30" },
        { 1994, 4, 31, 0, 0, 0, 0, "Apr 31" },        { 1994, 6, 31, 0, 0, 0, 0, "Jun 31" },
        { 1994, 9, 31, 0, 0, 0, 0, "Sep 31" },        { 1994, 11, 6, 24, 0, 0, 0, "hour 24" },
        { 1994, 11, 6, 8, 60, 0, 0, "minute 60" },    { 1994, 11, 6, 8, 49, 60, 0, "second 60" },
        { 1994, 11, 6, 8, 49, 37, 1000, "ms 1000" },  { 1600, 12, 31, 0, 0, 0, 0, "year 1600" },
        { 30828, 1, 1, 0, 0, 0, 0, "year 30828" },    { 0, 1, 1, 0, 0, 0, 0, "year 0" },
        { 1994, 0xFFFF, 6, 0, 0, 0, 0, "month 0xffff" }, { 1994, 11, 6, 0xFFFF, 0, 0, 0, "hour 0xffff" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SYSTEMTIME st = mk(t[i].y, t[i].mo, 0, t[i].d, t[i].h, t[i].mi, t[i].s, t[i].ms);
        char buf[40]; tm_fill(buf, sizeof buf);
        SET_ERR(0);
        CHECKF(!U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf), "%s", t[i].why);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(tm_is_filled(buf, sizeof buf), "%s: buffer touched", t[i].why);
    }
}

TEST(tmf_a_valid_edges) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    static const struct { int y, mo, dow, d, h, mi, s, ms; const char *want; } t[] = {
        { 1601, 1, 1, 1, 0, 0, 0, 0, "Mon, 01 Jan 1601 00:00:00 GMT" },
        { 2024, 2, 4, 29, 23, 59, 59, 999, "Thu, 29 Feb 2024 23:59:59 GMT" },
        { 2000, 2, 2, 29, 12, 0, 0, 0, "Tue, 29 Feb 2000 12:00:00 GMT" },
        { 1999, 12, 5, 31, 23, 59, 59, 0, "Fri, 31 Dec 1999 23:59:59 GMT" },
        { 2038, 1, 2, 19, 3, 14, 8, 0, "Tue, 19 Jan 2038 03:14:08 GMT" },
        { 9999, 12, 5, 31, 23, 59, 59, 0, "Fri, 31 Dec 9999 23:59:59 GMT" },
        { 1970, 1, 4, 1, 0, 0, 0, 0, "Thu, 01 Jan 1970 00:00:00 GMT" },
        { 2001, 9, 0, 9, 1, 46, 40, 0, "Sun, 09 Sep 2001 01:46:40 GMT" },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        SYSTEMTIME st = mk(t[i].y, t[i].mo, t[i].dow, t[i].d, t[i].h, t[i].mi, t[i].s, t[i].ms);
        char buf[40] = "";
        CHECKF(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf), "%s", t[i].want);
        EXPECT_STR(buf, t[i].want);
    }
}

TEST(tmf_a_five_digit_year_truncates) {
    /* 30 chars + NUL do not fit in 30: StringCchPrintfA truncates -> FALSE/122, truncated text written [D]. */
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(30827, 12, 0, 31, 23, 59, 59, 0);
    char buf[64]; tm_fill(buf, sizeof buf);
    SET_ERR(0);
    CHECK(!U(InternetTimeFromSystemTimeA)(&st, 0, buf, 30));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    t_note("30827 truncated to [%.40s]", buf);
    EXPECT_STR(buf, "Sun, 31 Dec 30827 23:59:59 GM");
    char big[64] = "";
    CHECK(U(InternetTimeFromSystemTimeA)(&st, 0, big, 31));
    EXPECT_STR(big, "Sun, 31 Dec 30827 23:59:59 GMT");
    st = mk(10000, 1, 0, 1, 0, 0, 0, 0);
    CHECK(U(InternetTimeFromSystemTimeA)(&st, 0, big, sizeof big));
    EXPECT_STR(big, "Sun, 01 Jan 10000 00:00:00 GMT");   /* wDay=1 <= 6: the caller's wDayOfWeek (0 = Sun) is printed */
}

/* ------------------------------------------------------------ A: weekday rule */
TEST(tmf_a_weekday_from_caller_when_day_le_6) {
    /* [D] `if (6 < wDay) normalise` : for days 1..6 the caller's wDayOfWeek is printed as is. */
    REQUIRE(U(InternetTimeFromSystemTimeA));
    for (int d = 1; d <= 6; d++)
        for (int dow = 0; dow < 7; dow++) {
            SYSTEMTIME st = mk(2024, 1, dow, d, 10, 20, 30, 0);
            char buf[40] = "", want[40];
            snprintf(want, sizeof want, "%s, %02d Jan 2024 10:20:30 GMT", tm_wk[dow], d);
            CHECKF(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf), "d=%d dow=%d", d, dow);
            CHECKF(!strcmp(buf, want), "d=%d dow=%d got [%s] want [%s]", d, dow, buf, want);
        }
}

TEST(tmf_a_weekday_recomputed_when_day_gt_6) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    for (int d = 7; d <= 31; d++)
        for (int dow = 0; dow < 7; dow += 3) {
            SYSTEMTIME st = mk(2024, 1, dow, d, 10, 20, 30, 0);
            char buf[40] = "", want[40];
            snprintf(want, sizeof want, "%s, %02d Jan 2024 10:20:30 GMT", tm_wk[tm_weekday(2024, 1, d)], d);
            CHECKF(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf), "d=%d dow=%d", d, dow);
            CHECKF(!strcmp(buf, want), "d=%d dow=%d got [%s] want [%s]", d, dow, buf, want);
        }
}

TEST(tmf_a_weekday_out_of_range_ignored_when_day_gt_6) {
    /* wDayOfWeek is not validated by SystemTimeToFileTime; with wDay > 6 the real weekday replaces it. */
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(1994, 11, 99, 7, 8, 49, 37, 0);
    char buf[40] = "";
    CHECK(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf));
    EXPECT_STR(buf, "Mon, 07 Nov 1994 08:49:37 GMT");
}

/* ------------------------------------------------------------ A: wide date sweep (reference formatter) */
static void sweep_year(int y) {
    for (int m = 1; m <= 12; m++)
        for (int d = 1; d <= tm_mdays(y, m); d++) {
            SYSTEMTIME st = mk(y, m, tm_weekday(y, m, d), d, (d * 7) % 24, (d * 13) % 60, (m * 5 + d) % 60, d * 10);
            char buf[40] = "", want[40];
            ref_fmt(&st, want, sizeof want);
            BOOL r = U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf);
            if (!r || strcmp(buf, want)) CHECKF(0, "%04d-%02d-%02d got [%s] want [%s]", y, m, d, buf, want);
            else CHECK(1);
        }
}
TEST(tmf_a_sweep_1994) { REQUIRE(U(InternetTimeFromSystemTimeA)); sweep_year(1994); }
TEST(tmf_a_sweep_2000) { REQUIRE(U(InternetTimeFromSystemTimeA)); sweep_year(2000); }
TEST(tmf_a_sweep_2024) { REQUIRE(U(InternetTimeFromSystemTimeA)); sweep_year(2024); }
TEST(tmf_a_sweep_2100) { REQUIRE(U(InternetTimeFromSystemTimeA)); sweep_year(2100); }
TEST(tmf_a_sweep_1601) { REQUIRE(U(InternetTimeFromSystemTimeA)); sweep_year(1601); }

TEST(tmf_a_years_sweep) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    static const int ys[] = { 1601, 1700, 1752, 1800, 1899, 1900, 1901, 1969, 1970, 1979, 1980, 1999, 2000, 2001,
                              2037, 2038, 2079, 2080, 2099, 2100, 2400, 3000, 5000, 9999 };
    for (size_t i = 0; i < sizeof ys / sizeof ys[0]; i++)
        for (int m = 1; m <= 12; m++) {
            int d = 10 + m;
            SYSTEMTIME st = mk(ys[i], m, 0, d, 1, 2, 3, 0);
            char buf[40] = "", want[40];
            ref_fmt(&st, want, sizeof want);
            CHECKF(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf), "%d-%d", ys[i], m);
            CHECKF(!strcmp(buf, want), "got [%s] want [%s]", buf, want);
        }
}

TEST(tmf_a_time_of_day_sweep) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    for (int h = 0; h < 24; h++)
        for (int mi = 0; mi < 60; mi += 7) {
            int s = (h * 3 + mi) % 60;
            SYSTEMTIME st = mk(2010, 7, 0, 18, h, mi, s, 500);
            char buf[40] = "", want[40];
            snprintf(want, sizeof want, "Sun, 18 Jul 2010 %02d:%02d:%02d GMT", h, mi, s);
            CHECK(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf));
            CHECKF(!strcmp(buf, want), "got [%s] want [%s]", buf, want);
        }
}

TEST(tmf_a_input_not_modified) {
    REQUIRE(U(InternetTimeFromSystemTimeA));
    SYSTEMTIME st = mk(2024, 1, 3, 15, 1, 2, 3, 4), copy = st;
    char buf[40];
    CHECK(U(InternetTimeFromSystemTimeA)(&st, 0, buf, sizeof buf));
    CHECK(!memcmp(&st, &copy, sizeof st));     /* normalisation goes to a local copy [D] */
    EXPECT_STR(buf, "Mon, 15 Jan 2024 01:02:03 GMT");
}

/* ------------------------------------------------------------ W */
TEST(tmf_w_example) {
    REQUIRE(U(InternetTimeFromSystemTimeW));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    WCHAR buf[64]; tm_fill(buf, sizeof buf);
    CHECK(U(InternetTimeFromSystemTimeW)(&st, 0, buf, sizeof buf));
    EXPECT_WSTR(buf, L"Sun, 06 Nov 1994 08:49:37 GMT");
}

TEST(tmf_w_bufsize_table) {
    /* [D] cb < 60 -> 122; then cb must exceed 2*(29+1)=60 bytes, so 60 itself is 122 too (`ja`). */
    REQUIRE(U(InternetTimeFromSystemTimeW));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    for (DWORD cb = 0; cb <= 70; cb++) {
        WCHAR buf[64]; tm_fill(buf, sizeof buf);
        SET_ERR(0);
        BOOL r = U(InternetTimeFromSystemTimeW)(&st, 0, buf, cb);
        DWORD e = GetLastError();
        if (cb <= 60) {
            CHECKF(!r && e == ERROR_INSUFFICIENT_BUFFER, "cb=%lu r=%d err=%lu", cb, r, e);
            if (cb < 60) CHECKF(tm_is_filled(buf, sizeof buf), "cb=%lu buffer touched", cb);
        } else {
            CHECKF(r, "cb=%lu err=%lu", cb, e);
            CHECKF(r && !lstrcmpW(buf, L"Sun, 06 Nov 1994 08:49:37 GMT"), "cb=%lu", cb);
        }
    }
}

TEST(tmf_w_null_buffer) {
    REQUIRE(U(InternetTimeFromSystemTimeW));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(&st, 0, NULL, 64)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(&st, 0, NULL, 0));  EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(NULL, 0, NULL, 59)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
}

TEST(tmf_w_errors_from_a) {
    REQUIRE(U(InternetTimeFromSystemTimeW));
    SYSTEMTIME st = mk(1994, 11, 0, 6, 8, 49, 37, 0), bad = mk(1994, 13, 0, 6, 8, 49, 37, 0);
    WCHAR buf[64];
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(NULL, 0, buf, sizeof buf)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(&st, 1, buf, sizeof buf));  EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(&bad, 0, buf, sizeof buf)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(tmf_w_five_digit_year) {
    /* 31 chars incl NUL: needs cb > 62 */
    REQUIRE(U(InternetTimeFromSystemTimeW));
    SYSTEMTIME st = mk(30827, 12, 0, 31, 23, 59, 59, 0);
    WCHAR buf[64];
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(&st, 0, buf, 60)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0); CHECK(!U(InternetTimeFromSystemTimeW)(&st, 0, buf, 62)); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    SET_ERR(0); CHECK(U(InternetTimeFromSystemTimeW)(&st, 0, buf, 63));
    EXPECT_WSTR(buf, L"Sun, 31 Dec 30827 23:59:59 GMT");
}

TEST(tmf_w_matches_a_sweep) {
    REQUIRE(U(InternetTimeFromSystemTimeW)); REQUIRE(U(InternetTimeFromSystemTimeA));
    for (int y = 1990; y <= 2030; y += 3)
        for (int m = 1; m <= 12; m++) {
            for (int d = 1; d <= tm_mdays(y, m); d += 5) {
                SYSTEMTIME st = mk(y, m, (d + m) % 7, d, m, d, y % 60, 0);
                char a[40] = ""; WCHAR w[40] = L""; WCHAR aw[40];
                BOOL ra = U(InternetTimeFromSystemTimeA)(&st, 0, a, sizeof a);
                BOOL rw = U(InternetTimeFromSystemTimeW)(&st, 0, w, sizeof w);
                MultiByteToWideChar(CP_ACP, 0, a, -1, aw, 40);
                CHECKF(ra && rw && !lstrcmpW(aw, w), "%d-%d-%d a=[%s]", y, m, d, a);
            }
        }
}

TEST(tmf_w_weekday_rule_same_as_a) {
    REQUIRE(U(InternetTimeFromSystemTimeW));
    SYSTEMTIME st = mk(2024, 1, 3, 1, 0, 0, 0, 0);   /* 2024-01-01 is a Monday; caller says Wed */
    WCHAR w[40] = L"";
    CHECK(U(InternetTimeFromSystemTimeW)(&st, 0, w, sizeof w));
    EXPECT_WSTR(w, L"Wed, 01 Jan 2024 00:00:00 GMT");
    st.wDay = 8; st.wDayOfWeek = 3;                    /* 2024-01-08 is a Monday: recomputed */
    CHECK(U(InternetTimeFromSystemTimeW)(&st, 0, w, sizeof w));
    EXPECT_WSTR(w, L"Mon, 08 Jan 2024 00:00:00 GMT");
}
