/* InternetTimeToSystemTime(A|W) and the undecorated alias.
 * [D InternetTimeToSystemTime@0x19cf70]: NULL string, NULL SYSTEMTIME, dwReserved != 0 or parse failure -> FALSE, 87.
 * [D FInternalParseHttpDate@0xbd930, MapDayMonthToDword@0xbdbe4] - the rules the table below is derived from:
 *  - Up to 8 fields. A digit run is a number (32-bit accumulate, the SYSTEMTIME gets its low WORD); a letter run is a
 *    word mapped by its first 1-3 letters (case-insensitive): Sun..Sat -> 0..6, Jan..Dec -> 1..12 ('N*' = 11,
 *    'O*' = 10, 'D*' = 12, 'W*' = 3), 'G*' and 'U*' -> zone marker (-3); anything else -> failure, except as the
 *    7th field (index 6) of the asctime layout. Every other byte is a separator.
 *  - Layout: a word in field 1 selects asctime (dow, mon, day, h, m, s, year); otherwise RFC 1123/850
 *    (dow, day, mon, year, h, m, s, zone). In asctime, a word at index 6 moves the year to index 7 and the
 *    result is converted from local time to UTC (SystemTimeToFileTime + LocalFileTimeToFileTime).
 *  - Year < 100: < 80 -> 20xx else 19xx. Fewer than 4 fields: h/m/s from GetSystemTime; fewer than 2: all from the clock.
 *  - Range check: dow > 6, day > 31, hour > 23, minute or second > 59 -> failure. Month is NOT checked.
 *  - 8 fields with a numeric zone: SystemTimeToFileTime must succeed (else failure); the zone is applied only
 *    to a FILETIME, never to the SYSTEMTIME result. wMilliseconds = 0. */
#include "tm.h"

enum { CLK_NONE = 0, CLK_TOD = 1, CLK_ALL = 2 };
typedef struct { const char *s; int ok; int y, mo, dow, d, h, mi, sec; int clk; } tcase;

#define OK7(str, y, mo, dow, d, h, mi, s) { str, 1, y, mo, dow, d, h, mi, s, CLK_NONE }
#define BAD(str)                          { str, 0, 0, 0, 0, 0, 0, 0, 0, CLK_NONE }
#define TOD(str, y, mo, dow, d)           { str, 1, y, mo, dow, d, 0, 0, 0, CLK_TOD }
#define NOW(str)                          { str, 1, 0, 0, 0, 0, 0, 0, 0, CLK_ALL }

static const tcase cases[] = {
    /* the three layouts of RFC 2616 3.3.1 */
    OK7("Sun, 06 Nov 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sunday, 06-Nov-94 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun Nov  6 08:49:37 1994", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun Nov 6 08:49:37 1994", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun Nov 06 08:49:37 1994", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun Nov 6 08:49:37 94", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun Nov 6 08:49:37 1994 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sunday, 06-Nov-1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    /* case */
    OK7("sun, 06 nov 1994 08:49:37 gmt", 1994, 11, 0, 6, 8, 49, 37),
    OK7("SUN, 06 NOV 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("sUnDaY, 06-nOv-94 08:49:37 gMt", 1994, 11, 0, 6, 8, 49, 37),
    OK7("sun nov 6 08:49:37 1994", 1994, 11, 0, 6, 8, 49, 37),
    /* zones */
    OK7("Sun, 06 Nov 1994 08:49:37", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 UTC", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 UT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 Greenwich", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 universal", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 +0000", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 +0100", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 -0800", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 +1400", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 -1200", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 0", 1994, 11, 0, 6, 8, 49, 37),
    BAD("Sun, 06 Nov 1994 08:49:37 PST"),
    BAD("Sun, 06 Nov 1994 08:49:37 EST"),
    BAD("Sun, 06 Nov 1994 08:49:37 CET"),
    BAD("Sun, 06 Nov 1994 08:49:37 MST"),
    BAD("Sun, 06 Nov 1994 08:49:37 BST"),
    BAD("Sun, 06 Nov 1994 08:49:37 Z"),
    BAD("Sun, 06 Nov 1994 08:49:37 Zulu"),
    /* anything after the 8th field is ignored */
    OK7("Sun, 06 Nov 1994 08:49:37 GMT xyz", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 GMT 12345", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 GMT+0100", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 GMT; foo=bar", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 08:49:37 +0000 PST", 1994, 11, 0, 6, 8, 49, 37),
    /* two-digit years */
    OK7("Thu, 01 Jan 70 00:00:00 GMT", 2070, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 79 00:00:00 GMT", 2079, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 80 00:00:00 GMT", 1980, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 99 00:00:00 GMT", 1999, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 00 00:00:00 GMT", 2000, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 0 00:00:00 GMT", 2000, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 5 00:00:00 GMT", 2005, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 100 00:00:00 GMT", 100, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 1601 00:00:00 GMT", 1601, 1, 4, 1, 0, 0, 0),
    OK7("Thu, 01 Jan 30827 00:00:00 GMT", 30827, 1, 4, 1, 0, 0, 0),
    OK7("Sun Nov 6 08:49:37 79", 2079, 11, 0, 6, 8, 49, 37),
    OK7("Sun Nov 6 08:49:37 80", 1980, 11, 0, 6, 8, 49, 37),
    /* weekday taken from the name, never recomputed */
    OK7("Mon, 06 Nov 1994 08:49:37 GMT", 1994, 11, 1, 6, 8, 49, 37),
    OK7("Tue, 06 Nov 1994 08:49:37 GMT", 1994, 11, 2, 6, 8, 49, 37),
    OK7("Wed, 06 Nov 1994 08:49:37 GMT", 1994, 11, 3, 6, 8, 49, 37),
    OK7("Thu, 06 Nov 1994 08:49:37 GMT", 1994, 11, 4, 6, 8, 49, 37),
    OK7("Fri, 06 Nov 1994 08:49:37 GMT", 1994, 11, 5, 6, 8, 49, 37),
    OK7("Sat, 06 Nov 1994 08:49:37 GMT", 1994, 11, 6, 6, 8, 49, 37),
    OK7("Monday, 06-Nov-94 08:49:37 GMT", 1994, 11, 1, 6, 8, 49, 37),
    OK7("Tuesday, 06-Nov-94 08:49:37 GMT", 1994, 11, 2, 6, 8, 49, 37),
    OK7("Wednesday, 06-Nov-94 08:49:37 GMT", 1994, 11, 3, 6, 8, 49, 37),
    OK7("Thursday, 06-Nov-94 08:49:37 GMT", 1994, 11, 4, 6, 8, 49, 37),
    OK7("Friday, 06-Nov-94 08:49:37 GMT", 1994, 11, 5, 6, 8, 49, 37),
    OK7("Saturday, 06-Nov-94 08:49:37 GMT", 1994, 11, 6, 6, 8, 49, 37),
    OK7("Wed Nov 6 08:49:37 1994", 1994, 11, 3, 6, 8, 49, 37),
    /* numeric weekday field */
    OK7("0, 06 Nov 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("6, 06 Nov 1994 08:49:37 GMT", 1994, 11, 6, 6, 8, 49, 37),
    BAD("7, 06 Nov 1994 08:49:37 GMT"),
    /* missing weekday: fields shift (dow=6, day=Nov=11, month=1994, year=8 -> hour=49) -> range failure */
    BAD("06 Nov 1994 08:49:37 GMT"),
    BAD("Nov 6 08:49:37 1994"),
    BAD("6 Nov 1994"),
    /* month names */
    OK7("Sun, 06 Jan 1994 08:49:37 GMT", 1994, 1, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Feb 1994 08:49:37 GMT", 1994, 2, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Mar 1994 08:49:37 GMT", 1994, 3, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Apr 1994 08:49:37 GMT", 1994, 4, 0, 6, 8, 49, 37),
    OK7("Sun, 06 May 1994 08:49:37 GMT", 1994, 5, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Jun 1994 08:49:37 GMT", 1994, 6, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Jul 1994 08:49:37 GMT", 1994, 7, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Aug 1994 08:49:37 GMT", 1994, 8, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Sep 1994 08:49:37 GMT", 1994, 9, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Oct 1994 08:49:37 GMT", 1994, 10, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Dec 1994 08:49:37 GMT", 1994, 12, 0, 6, 8, 49, 37),
    OK7("Sun, 06 January 1994 08:49:37 GMT", 1994, 1, 0, 6, 8, 49, 37),
    OK7("Sun, 06 February 1994 08:49:37 GMT", 1994, 2, 0, 6, 8, 49, 37),
    OK7("Sun, 06 March 1994 08:49:37 GMT", 1994, 3, 0, 6, 8, 49, 37),
    OK7("Sun, 06 April 1994 08:49:37 GMT", 1994, 4, 0, 6, 8, 49, 37),
    OK7("Sun, 06 June 1994 08:49:37 GMT", 1994, 6, 0, 6, 8, 49, 37),
    OK7("Sun, 06 July 1994 08:49:37 GMT", 1994, 7, 0, 6, 8, 49, 37),
    OK7("Sun, 06 August 1994 08:49:37 GMT", 1994, 8, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Sept 1994 08:49:37 GMT", 1994, 9, 0, 6, 8, 49, 37),
    OK7("Sun, 06 September 1994 08:49:37 GMT", 1994, 9, 0, 6, 8, 49, 37),
    OK7("Sun, 06 October 1994 08:49:37 GMT", 1994, 10, 0, 6, 8, 49, 37),
    OK7("Sun, 06 November 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 December 1994 08:49:37 GMT", 1994, 12, 0, 6, 8, 49, 37),
    OK7("Sun Jan 6 08:49:37 1994", 1994, 1, 0, 6, 8, 49, 37),
    OK7("Sun Jun 6 08:49:37 1994", 1994, 6, 0, 6, 8, 49, 37),
    OK7("Sun Jul 6 08:49:37 1994", 1994, 7, 0, 6, 8, 49, 37),
    OK7("Sun Dec 6 08:49:37 1994", 1994, 12, 0, 6, 8, 49, 37),
    /* the mapper looks at 1-3 letters only [D MapDayMonthToDword] */
    OK7("Sun, 06 Nonsense 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 N 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Oxx 1994 08:49:37 GMT", 1994, 10, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Dxx 1994 08:49:37 GMT", 1994, 12, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Mon 1994 08:49:37 GMT", 1994, 1, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Wed 1994 08:49:37 GMT", 1994, 3, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Fri 1994 08:49:37 GMT", 1994, 5, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Sat 1994 08:49:37 GMT", 1994, 6, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Thu 1994 08:49:37 GMT", 1994, 4, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Tue 1994 08:49:37 GMT", 1994, 2, 0, 6, 8, 49, 37),
    OK7("Jan, 06 Nov 1994 08:49:37 GMT", 1994, 11, 1, 6, 8, 49, 37),
    OK7("Feb, 06 Nov 1994 08:49:37 GMT", 1994, 11, 2, 6, 8, 49, 37),
    OK7("Jun, 06 Nov 1994 08:49:37 GMT", 1994, 11, 6, 6, 8, 49, 37),
    BAD("Jul, 06 Nov 1994 08:49:37 GMT"),
    BAD("Nov, 06 Nov 1994 08:49:37 GMT"),
    BAD("Sun, 06 J 1994 08:49:37 GMT"),
    BAD("Sun, 06 Ma 1994 08:49:37 GMT"),
    BAD("Sun, 06 Ju 1994 08:49:37 GMT"),
    BAD("Sun, 06 Xyz 1994 08:49:37 GMT"),
    BAD("Sun, 06 Lun 1994 08:49:37 GMT"),
    BAD("Son, 06 Nov 1994 08:49:37 GMT"),
    BAD("Sxx, 06 Nov 1994 08:49:37 GMT"),
    /* numeric month: not range-checked */
    OK7("Sun, 06 11 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 13 1994 08:49:37 GMT", 1994, 13, 0, 6, 8, 49, 37),
    OK7("Sun, 06 0 1994 08:49:37 GMT", 1994, 0, 0, 6, 8, 49, 37),
    OK7("Sun, 06 99 1994 08:49:37 GMT", 1994, 99, 0, 6, 8, 49, 37),
    BAD("Sun, 06 13 1994 08:49:37 +0000"),
    /* day / time ranges */
    OK7("Sun, 31 Nov 1994 08:49:37 GMT", 1994, 11, 0, 31, 8, 49, 37),
    OK7("Sun, 00 Nov 1994 08:49:37 GMT", 1994, 11, 0, 0, 8, 49, 37),
    BAD("Sun, 32 Nov 1994 08:49:37 GMT"),
    OK7("Sun, 06 Nov 1994 23:59:59 GMT", 1994, 11, 0, 6, 23, 59, 59),
    OK7("Sun, 06 Nov 1994 00:00:00 GMT", 1994, 11, 0, 6, 0, 0, 0),
    BAD("Sun, 06 Nov 1994 24:00:00 GMT"),
    BAD("Sun, 06 Nov 1994 23:60:00 GMT"),
    BAD("Sun, 06 Nov 1994 23:59:60 GMT"),
    BAD("Mon, 32 Feb 2024 25:61:61 GMT"),
    OK7("Fri, 30 Feb 2024 12:00:00 GMT", 2024, 2, 5, 30, 12, 0, 0),
    BAD("Fri, 30 Feb 2024 12:00:00 +0000"),
    OK7("Fri, 29 Feb 2024 12:00:00 +0000", 2024, 2, 5, 29, 12, 0, 0),
    OK7("Sun Nov 31 08:49:37 1994", 1994, 11, 0, 31, 8, 49, 37),
    BAD("Sun Nov 32 08:49:37 1994"),
    BAD("Sun Nov 6 24:49:37 1994"),
    /* single digits / leading zeros */
    OK7("Sun, 6 Nov 1994 8:9:7 GMT", 1994, 11, 0, 6, 8, 9, 7),
    OK7("Sun, 0006 Nov 001994 0008:0049:0037 GMT", 1994, 11, 0, 6, 8, 49, 37),
    /* separators: every non-alnum byte */
    OK7("Sun,,,06---Nov///1994   08::49::37   GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("  \t\r\nSun, 06 Nov 1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun.06.Nov.1994.08.49.37.GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun_06_Nov_1994_08_49_37_GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("(Sun) [06] {Nov} <1994> 08|49|37 \"GMT\"", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, -06 Nov -1994 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun,06Nov1994 08:49:37GMT", 1994, 11, 0, 6, 8, 49, 37),
    /* number overflow: the SYSTEMTIME gets the low 16 bits of a 32-bit accumulator */
    OK7("Sun, 65537 Nov 1994 08:49:37 GMT", 1994, 11, 0, 1, 8, 49, 37),
    OK7("Sun, 06 Nov 67530 08:49:37 GMT", 1994, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 99999 08:49:37 GMT", 34463, 11, 0, 6, 8, 49, 37),
    OK7("Sun, 06 Nov 1994 65559:49:37 GMT", 1994, 11, 0, 6, 23, 49, 37),
    BAD("Sun, 06 Nov 1994 65560:49:37 GMT"),
    OK7("Sun, 4294967297 Nov 1994 08:49:37 GMT", 1994, 11, 0, 1, 8, 49, 37),
    /* a word where a number belongs */
    BAD("Sun, 06 Nov 1994 08:49 GMT"),            /* GMT lands in the seconds slot (0xFFFD) */
    BAD("Sun Nov 6 08:49 1994"),                  /* asctime without seconds: second = 1994 */
    BAD("Sun Nov 6 PST 08:49:37 1994"),
    BAD("Sun Xyz 6 08:49:37 1994"),
    /* ISO 8601 and other foreign layouts */
    BAD("1994-11-06T08:49:37Z"),
    BAD("1994-11-06 08:49:37"),
    BAD("19941106T084937Z"),
    /* garbage */
    BAD("xyz"),
    BAD("hello world"),
    BAD("Garbage in"),
    /* short strings: clock fill */
    NOW(""),
    NOW("   "),
    NOW("15"),
    NOW("Sun"),
    NOW("Sun,"),
    NOW("garbage"),                                /* 'G' = zone marker, one field */
    NOW("utc"),
    NOW("---"),
    BAD("15 Nov"),                                 /* two fields: dow = 15 */
    TOD("Tue, 15 Nov", 2000, 11, 2, 15),
    TOD("Tue, 15", 2000, 0, 2, 15),
    TOD("Tue 15 Nov", 2000, 11, 2, 15),
    OK7("Tue, 15 Nov 1994", 1994, 11, 2, 15, 0, 0, 0),
    OK7("Tue, 15 Nov 1994 08", 1994, 11, 2, 15, 8, 0, 0),
    OK7("Tue, 15 Nov 1994 08:12", 1994, 11, 2, 15, 8, 12, 0),
    TOD("Tue Nov 15", 2000, 11, 2, 15),            /* asctime layout, 3 fields */
};

static int within_seconds_of_day(const SYSTEMTIME *st, const SYSTEMTIME *a, const SYSTEMTIME *b) {
    int v = st->wHour * 3600 + st->wMinute * 60 + st->wSecond;
    int lo = a->wHour * 3600 + a->wMinute * 60 + a->wSecond, hi = b->wHour * 3600 + b->wMinute * 60 + b->wSecond;
    if (lo <= hi) return v >= lo - 1 && v <= hi + 1;
    return v >= lo - 1 || v <= hi + 1;   /* midnight wrap */
}
static ULONGLONG ft64(const SYSTEMTIME *st) {
    FILETIME ft; if (!SystemTimeToFileTime(st, &ft)) return 0;
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

static void verify(const tcase *c0, BOOL r, const SYSTEMTIME *st, const SYSTEMTIME *before, const SYSTEMTIME *after,
                   DWORD err, const char *api) {
    const tcase *c = c0;
    if (!c->ok) {
        CHECKF(!r, "%s(\"%s\") unexpectedly succeeded: %u-%u-%u dow %u %u:%u:%u", api, c->s, st->wYear, st->wMonth,
               st->wDay, st->wDayOfWeek, st->wHour, st->wMinute, st->wSecond);
        CHECKF(err == ERROR_INVALID_PARAMETER, "%s(\"%s\") err %lu want 87", api, c->s, err);
        return;
    }
    CHECKF(r, "%s(\"%s\") failed err=%lu", api, c->s, err);
    if (!r) return;
    if (c->clk == CLK_ALL) {
        ULONGLONG v = ft64(st), lo = ft64(before), hi = ft64(after);
        CHECKF(v && v + 10000000ull * 2 >= lo && v <= hi + 10000000ull * 2, "%s(\"%s\") not 'now'", api, c->s);
        return;
    }
    CHECKF(st->wYear == c->y && st->wMonth == c->mo && st->wDayOfWeek == c->dow && st->wDay == c->d,
           "%s(\"%s\") date got %u-%u-%u dow %u want %d-%d-%d dow %d", api, c->s, st->wYear, st->wMonth, st->wDay,
           st->wDayOfWeek, c->y, c->mo, c->d, c->dow);
    if (c->clk == CLK_TOD) {
        CHECKF(within_seconds_of_day(st, before, after), "%s(\"%s\") time %u:%u:%u not from the clock", api, c->s,
               st->wHour, st->wMinute, st->wSecond);
    } else {
        CHECKF(st->wHour == c->h && st->wMinute == c->mi && st->wSecond == c->sec,
               "%s(\"%s\") time got %u:%u:%u want %d:%d:%d", api, c->s, st->wHour, st->wMinute, st->wSecond, c->h,
               c->mi, c->sec);
        CHECKF(st->wMilliseconds == 0, "%s(\"%s\") ms %u", api, c->s, st->wMilliseconds);
    }
}

TEST(tmt_a_table) {
    REQUIRE(U(InternetTimeToSystemTimeA));
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        SYSTEMTIME st, b, a; tm_fill(&st, sizeof st);
        GetSystemTime(&b);
        SET_ERR(0);
        BOOL r = U(InternetTimeToSystemTimeA)(cases[i].s, &st, 0);
        DWORD e = GetLastError();
        GetSystemTime(&a);
        verify(&cases[i], r, &st, &b, &a, e, "A");
    }
}

TEST(tmt_w_table) {
    REQUIRE(U(InternetTimeToSystemTimeW));
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        WCHAR w[128]; MultiByteToWideChar(CP_ACP, 0, cases[i].s, -1, w, 128);
        SYSTEMTIME st, b, a; tm_fill(&st, sizeof st);
        GetSystemTime(&b);
        SET_ERR(0);
        BOOL r = U(InternetTimeToSystemTimeW)(w, &st, 0);
        DWORD e = GetLastError();
        GetSystemTime(&a);
        verify(&cases[i], r, &st, &b, &a, e, "W");
    }
}

TEST(tmt_plain_alias_table) {
    REQUIRE(UN(InternetTimeToSystemTime));
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i += 3) {
        SYSTEMTIME st, b, a; tm_fill(&st, sizeof st);
        GetSystemTime(&b);
        SET_ERR(0);
        BOOL r = UN(InternetTimeToSystemTime)(cases[i].s, &st, 0);
        DWORD e = GetLastError();
        GetSystemTime(&a);
        verify(&cases[i], r, &st, &b, &a, e, "plain");
    }
}

/* ------------------------------------------------------------ argument checks */
TEST(tmt_a_args) {
    REQUIRE(U(InternetTimeToSystemTimeA));
    SYSTEMTIME st;
    SET_ERR(0); CHECK(!U(InternetTimeToSystemTimeA)(NULL, &st, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeToSystemTimeA)("Sun, 06 Nov 1994 08:49:37 GMT", NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeToSystemTimeA)(NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    static const DWORD res[] = { 1, 2, 0x80000000u, 0xFFFFFFFFu };
    for (size_t i = 0; i < 4; i++) {
        tm_fill(&st, sizeof st);
        SET_ERR(0);
        CHECKF(!U(InternetTimeToSystemTimeA)("Sun, 06 Nov 1994 08:49:37 GMT", &st, res[i]), "reserved=0x%lx", res[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        CHECKF(tm_is_filled(&st, sizeof st), "reserved=0x%lx: output touched", res[i]);
    }
}

TEST(tmt_w_args) {
    REQUIRE(U(InternetTimeToSystemTimeW));
    SYSTEMTIME st;
    SET_ERR(0); CHECK(!U(InternetTimeToSystemTimeW)(NULL, &st, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(InternetTimeToSystemTimeW)(L"Sun, 06 Nov 1994 08:49:37 GMT", NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    tm_fill(&st, sizeof st);
    SET_ERR(0); CHECK(!U(InternetTimeToSystemTimeW)(L"Sun, 06 Nov 1994 08:49:37 GMT", &st, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(tm_is_filled(&st, sizeof st));
}

TEST(tmt_a_success_leaves_lasterror) {
    REQUIRE(U(InternetTimeToSystemTimeA));
    SYSTEMTIME st;
    SET_ERR(0x4242);
    CHECK(U(InternetTimeToSystemTimeA)("Sun, 06 Nov 1994 08:49:37 GMT", &st, 0));
    EXPECT_ERR(0x4242);
}

/* ------------------------------------------------------------ output side effects on failure */
TEST(tmt_a_unknown_word_leaves_output_untouched) {
    /* the unknown-word failure returns before the SYSTEMTIME is written [D] */
    REQUIRE(U(InternetTimeToSystemTimeA));
    static const char *const s[] = { "xyz", "Sun, 06 Nov 1994 08:49:37 PST", "Sun, 06 Xyz 1994", "1994-11-06T08:49:37Z" };
    for (int i = 0; i < 4; i++) {
        SYSTEMTIME st; tm_fill(&st, sizeof st);
        CHECKF(!U(InternetTimeToSystemTimeA)(s[i], &st, 0), "%s", s[i]);
        CHECKF(tm_is_filled(&st, sizeof st), "\"%s\": output written", s[i]);
    }
}

TEST(tmt_a_range_failure_writes_fields) {
    /* the range check runs on the caller's SYSTEMTIME after it was filled [D] */
    REQUIRE(U(InternetTimeToSystemTimeA));
    SYSTEMTIME st; tm_fill(&st, sizeof st);
    CHECK(!U(InternetTimeToSystemTimeA)("Sun, 06 Nov 1994 25:00:00 GMT", &st, 0));
    EXPECT_EQ(st.wHour, 25); EXPECT_EQ(st.wYear, 1994); EXPECT_EQ(st.wMonth, 11); EXPECT_EQ(st.wDay, 6);
    EXPECT_EQ(st.wMilliseconds, 0);
}

/* ------------------------------------------------------------ asctime with a zone word: local -> UTC */
static void expect_local_to_utc(const char *in, int y, int mo, int d, int h, int mi, int s) {
    SYSTEMTIME l = { (WORD)y, (WORD)mo, 0, (WORD)d, (WORD)h, (WORD)mi, (WORD)s, 0 }, want, got;
    FILETIME lf, uf;
    CHECK(SystemTimeToFileTime(&l, &lf));
    CHECK(LocalFileTimeToFileTime(&lf, &uf));
    CHECK(FileTimeToSystemTime(&uf, &want));
    tm_fill(&got, sizeof got);
    BOOL r = U(InternetTimeToSystemTimeA)(in, &got, 0);
    CHECKF(r, "\"%s\" err %lu", in, GetLastError());
    if (!r) return;
    CHECKF(!memcmp(&got, &want, sizeof got), "\"%s\" got %u-%u-%u dow %u %u:%u:%u want %u-%u-%u dow %u %u:%u:%u", in,
           got.wYear, got.wMonth, got.wDay, got.wDayOfWeek, got.wHour, got.wMinute, got.wSecond, want.wYear,
           want.wMonth, want.wDay, want.wDayOfWeek, want.wHour, want.wMinute, want.wSecond);
}
TEST(tmt_a_asctime_zone_word_is_local_time) {
    REQUIRE(U(InternetTimeToSystemTimeA));
    TIME_ZONE_INFORMATION tz; DWORD k = GetTimeZoneInformation(&tz);
    t_note("guest time zone bias %ld min (mode %lu)", tz.Bias, k);
    expect_local_to_utc("Sun Nov 6 08:49:37 PST 1994", 1994, 11, 6, 8, 49, 37);
    expect_local_to_utc("Sun Nov 6 08:49:37 GMT 1994", 1994, 11, 6, 8, 49, 37);
    expect_local_to_utc("Sun Nov 6 08:49:37 EDT 1994", 1994, 11, 6, 8, 49, 37);
    expect_local_to_utc("Wed Jan 1 00:00:00 XYZ 2025", 2025, 1, 1, 0, 0, 0);
    expect_local_to_utc("Sat Dec 31 23:59:59 CET 2033", 2033, 12, 31, 23, 59, 59);
}

/* ------------------------------------------------------------ round trip with InternetTimeFromSystemTime */
TEST(tmt_roundtrip_sweep) {
    REQUIRE(U(InternetTimeToSystemTimeA)); REQUIRE(U(InternetTimeFromSystemTimeA));
    int n = 0;
    for (int y = 1980; y <= 2079; y += 7)
        for (int m = 1; m <= 12; m++)
            for (int d = 1; d <= tm_mdays(y, m); d += 4) {
                SYSTEMTIME in = { (WORD)y, (WORD)m, (WORD)tm_weekday(y, m, d), (WORD)d, (WORD)(d % 24), (WORD)((d * 7) % 60),
                                  (WORD)((m * 11) % 60), 0 }, out;
                char buf[40];
                if (!U(InternetTimeFromSystemTimeA)(&in, 0, buf, sizeof buf)) { CHECKF(0, "format %d-%d-%d", y, m, d); continue; }
                tm_fill(&out, sizeof out);
                BOOL r = U(InternetTimeToSystemTimeA)(buf, &out, 0);
                CHECKF(r && !memcmp(&in, &out, sizeof in), "roundtrip [%s]", buf);
                n++;
            }
    t_note("%d round trips", n);
}

TEST(tmt_w_roundtrip) {
    REQUIRE(U(InternetTimeToSystemTimeW)); REQUIRE(U(InternetTimeFromSystemTimeW));
    for (int y = 1601; y <= 9999; y += 397) {
        SYSTEMTIME in = { (WORD)y, 7, (WORD)tm_weekday(y, 7, 14), 14, 13, 14, 15, 0 }, out;
        WCHAR buf[64];
        CHECK(U(InternetTimeFromSystemTimeW)(&in, 0, buf, sizeof buf));
        tm_fill(&out, sizeof out);
        CHECKF(U(InternetTimeToSystemTimeW)(buf, &out, 0) && !memcmp(&in, &out, sizeof in), "year %d", y);
    }
}

/* ------------------------------------------------------------ W specifics */
TEST(tmt_w_non_ascii_is_separator_or_failure) {
    /* W converts with the ANSI code page first [D FastWideCharStringToMultiByteString]: a non-ASCII character
     * becomes a non-letter byte ('?' or a high byte), which the tokenizer treats as a separator. */
    REQUIRE(U(InternetTimeToSystemTimeW));
    SYSTEMTIME st;
    CHECK(U(InternetTimeToSystemTimeW)(L"Sun,\x2003" L"06 Nov 1994 08:49:37 GMT", &st, 0));
    EXPECT_EQ(st.wDay, 6); EXPECT_EQ(st.wYear, 1994);
    CHECK(U(InternetTimeToSystemTimeW)(L"Sun, 06 Nov 1994 08:49:37 GMT \x4e2d", &st, 0));
    EXPECT_EQ(st.wHour, 8);
}

TEST(tmt_long_input) {
    REQUIRE(U(InternetTimeToSystemTimeA));
    static char big[8192];
    strcpy(big, "Sun, 06 Nov 1994 08:49:37 GMT ");
    size_t n = strlen(big);
    memset(big + n, 'x', sizeof big - n - 1); big[sizeof big - 1] = 0;
    SYSTEMTIME st;
    CHECK(U(InternetTimeToSystemTimeA)(big, &st, 0));       /* parsing stops after 8 fields */
    EXPECT_EQ(st.wSecond, 37);
    memset(big, ' ', sizeof big - 1); big[sizeof big - 1] = 0;
    memcpy(big + 6000, "Sun, 06 Nov 1994 08:49:37 GMT", 29);
    CHECK(U(InternetTimeToSystemTimeA)(big, &st, 0));       /* leading separators are skipped */
    EXPECT_EQ(st.wMinute, 49);
}

TEST(tmt_all_weekday_month_words_lowercase) {
    REQUIRE(U(InternetTimeToSystemTimeA));
    static const char *const wk[7] = { "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday" };
    static const char *const mo[12] = { "january", "february", "march", "april", "may", "june", "july", "august",
                                        "september", "october", "november", "december" };
    for (int w = 0; w < 7; w++)
        for (int m = 0; m < 12; m++) {
            char s[96]; SYSTEMTIME st;
            snprintf(s, sizeof s, "%s, 15-%s-2015 10:11:12 gmt", wk[w], mo[m]);
            BOOL r = U(InternetTimeToSystemTimeA)(s, &st, 0);
            CHECKF(r && st.wDayOfWeek == w && st.wMonth == m + 1 && st.wDay == 15 && st.wYear == 2015, "%s", s);
        }
}
