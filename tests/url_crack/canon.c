/* url_crack: InternetCanonicalizeUrlA/W.
 * [D] InternetCanonicalizeUrlA@0x137930 / W@0xd48a0: NULL url, NULL buffer, NULL length or *len == 0 -> 87 (no
 * size-query mode); otherwise UrlCanonicalizeA/W(url, buf, len, dwFlags ^ ICU_NO_ENCODE | URL_WININET_COMPATIBILITY):
 * escaping of unsafe characters is ON unless ICU_NO_ENCODE is passed; ICU_ESCAPE (0x80000000) is the compat bit that
 * is always set, so it changes nothing. HRESULTs map through ICUHrToWin32Error: E_POINTER -> 122, others -> 87.
 * No dwFlags validation: unknown bits are passed to shlwapi.
 * The result tables (one TEST per input URL, every ICU_* flag) were observed on the Win10 22H2 VM. Highlights:
 *  - scheme and host are lower-cased, the path keeps its case; "http://host" gains "/"; ":80" on http is dropped.
 *  - dot segments are removed (not above the root) unless ICU_NO_META; ?query and #fragment are left alone.
 *  - '\' becomes '/' in http paths; file: URLs become "file://C:\a\b" with backslashes.
 *  - default: spaces and unsafe chars (<>"{}|^` DEL, bytes >= 0x80) are %XX-escaped (upper-case hex) in the path,
 *    but NOT in ?query/#fragment; ICU_ENCODE_SPACES_ONLY escapes spaces only, query/fragment included.
 *  - ICU_DECODE unescapes %XX (and then does not re-escape); ICU_ENCODE_PERCENT escapes '%' itself (%25).
 *  - an IPv6 literal host gets its brackets escaped ("%5B::1%5D") by the default mode.
 * VM_TIMEOUT: 120 */
#include "uc.h"

static int acp_is_1252(void) { return GetACP() == 1252; }

TEST(url_crack_canon_A_null_args) {
    REQUIRE(U(InternetCanonicalizeUrlA));
    char out[64]; DWORD n = sizeof out;
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlA)(NULL, out, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlA)("http://x/", NULL, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlA)("http://x/", out, NULL, 0), ERROR_INVALID_PARAMETER);
    n = 0; SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlA)("http://x/", out, &n, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(n, 0);
    n = 0; SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlA)("http://x/", NULL, &n, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(n, 0);
}
TEST(url_crack_canon_W_null_args) {
    REQUIRE(U(InternetCanonicalizeUrlW));
    WCHAR out[64]; DWORD n = 64;
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlW)(NULL, out, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlW)(L"http://x/", NULL, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlW)(L"http://x/", out, NULL, 0), ERROR_INVALID_PARAMETER);
    n = 0; SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCanonicalizeUrlW)(L"http://x/", out, &n, 0), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(n, 0);
}
TEST(url_crack_canon_A_buffer_protocol) {
    /* [W10] "http://www.example.com/x" (24 chars): 8 -> 122 need 25; 24 -> 122 need 25; 25 -> ok, 24 */
    REQUIRE(U(InternetCanonicalizeUrlA));
    const char *u = "http://www.example.com/x";
    char out[64]; DWORD n;
    n = 8; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCanonicalizeUrlA)(u, out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 25);
    n = 24; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCanonicalizeUrlA)(u, out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 25);
    n = 25; SET_ERR(0xdead);
    CHECK(U(InternetCanonicalizeUrlA)(u, out, &n, 0));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 24);
    EXPECT_STR(out, u);
    n = 1; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCanonicalizeUrlA)(u, out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 25);
}
TEST(url_crack_canon_W_buffer_protocol) {
    /* W lengths are characters (incl. NUL when too small) */
    REQUIRE(U(InternetCanonicalizeUrlW));
    const WCHAR *u = L"http://www.example.com/x";
    WCHAR out[64]; DWORD n;
    n = 8; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCanonicalizeUrlW)(u, out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 25);
    n = 24; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCanonicalizeUrlW)(u, out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 25);
    n = 25; SET_ERR(0xdead);
    CHECK(U(InternetCanonicalizeUrlW)(u, out, &n, 0));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 24);
    EXPECT_WSTR(out, u);
}
TEST(url_crack_canon_required_size_counts_escapes) {
    REQUIRE(U(InternetCanonicalizeUrlA));
    char out[64]; DWORD n = 4;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCanonicalizeUrlA)("http://host/a b c", out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 22);   /* "http://host/a%20b%20c" + NUL */
    n = 22;
    CHECK(U(InternetCanonicalizeUrlA)("http://host/a b c", out, &n, 0));
    EXPECT_EQ(n, 21);
    EXPECT_STR(out, "http://host/a%20b%20c");
}
TEST(url_crack_canon_unknown_flags_accepted) {
    /* no flag validation in the wrapper; [W10] 0x1 and 0xffffffff both succeed */
    REQUIRE(U(InternetCanonicalizeUrlA));
    char out[64]; DWORD n = sizeof out;
    SET_ERR(0xdead);
    CHECK(U(InternetCanonicalizeUrlA)("http://x/", out, &n, 1));
    EXPECT_ERR(0); EXPECT_STR(out, "http://x/"); EXPECT_EQ(n, 9);
    n = sizeof out;
    CHECK(U(InternetCanonicalizeUrlA)("http://x/", out, &n, 0xffffffff));
    EXPECT_STR(out, "http://x/");
}
TEST(url_crack_canon_last_error_zero_on_success) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    char out[64]; DWORD n = sizeof out;
    SET_ERR(4242); CHECK(U(InternetCanonicalizeUrlA)("http://x/a/../b", out, &n, 0)); EXPECT_ERR(0);
    EXPECT_STR(out, "http://x/b");
    WCHAR w[64]; n = 64;
    SET_ERR(4242); CHECK(U(InternetCanonicalizeUrlW)(L"http://x/a/../b", w, &n, 0)); EXPECT_ERR(0);
    EXPECT_WSTR(w, L"http://x/b");
}
TEST(url_crack_canon_A_utf8_bytes_escaped) {
    /* A escapes each byte >= 0x80 as %XX (upper-case hex) */
    REQUIRE(U(InternetCanonicalizeUrlA));
    CANON("http://host/\xc3\xa9", 0, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_NO_ENCODE, "http://host/\xc3\xa9");
    CANON("http://host/\xe9", 0, "http://host/%E9");
}
TEST(url_crack_canon_W_non_ascii) {
    /* [W10, ACP 1252] W escapes U+00E9 as %E9 (one byte, not UTF-8); ICU_NO_ENCODE keeps the character */
    REQUIRE(U(InternetCanonicalizeUrlW));
    WCHAR out[64]; DWORD n = 64;
    CHECK(U(InternetCanonicalizeUrlW)(L"http://host/\u00e9", out, &n, ICU_NO_ENCODE));
    EXPECT_WSTR(out, L"http://host/\u00e9");
    EXPECT_EQ(n, 13);
    n = 64;
    CHECK(U(InternetCanonicalizeUrlW)(L"http://host/\u00e9", out, &n, 0));
    if (acp_is_1252()) { EXPECT_WSTR(out, L"http://host/%E9"); EXPECT_EQ(n, 15); }
    else t_note("ACP %u: W canonicalize of U+00E9 -> %s", GetACP(), uc_a(out));
}
TEST(url_crack_canon_A_and_W_agree_ascii) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    static const char *v[] = { "HTTP://Host:80/A/./B/../C?x y#z w", "ftp://h/a b", "file:///C:/x/../y.txt", "foo://H/a/../b",
                               "http://h/%7e%41", "mailto:a b", "http://[::1]:81/", "http://u:p@H/" };
    static const DWORD f[] = { 0, ICU_NO_ENCODE, ICU_DECODE, ICU_NO_META, ICU_ENCODE_SPACES_ONLY, ICU_ENCODE_PERCENT, ICU_BROWSER_MODE };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++)
        for (unsigned j = 0; j < sizeof f / sizeof *f; j++) {
            char a[256]; DWORD na = sizeof a; WCHAR w[256]; DWORD nw = 256;
            BOOL ra = U(InternetCanonicalizeUrlA)(v[i], a, &na, f[j]);
            BOOL rw = U(InternetCanonicalizeUrlW)(uc_w(v[i]), w, &nw, f[j]);
            CHECKF(ra && rw && !strcmp(a, uc_a(w)) && na == nw, "%s 0x%08lx: A \"%s\" W \"%s\"", v[i], f[j], ra ? a : "-", rw ? uc_a(w) : "-");
        }
}

TEST(url_crack_canon_http_www_example_com) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://www.example.com/", 0, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_DECODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_NO_META, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_ENCODE_SPACES_ONLY, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_BROWSER_MODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_ENCODE_PERCENT, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_ESCAPE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_DECODE | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_NO_META | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com/", ICU_USERNAME, "http://www.example.com/");
}
TEST(url_crack_canon_http_www_example_com_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://www.example.com", 0, "http://www.example.com/");
    CANON("http://www.example.com", ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_DECODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_NO_META, "http://www.example.com/");
    CANON("http://www.example.com", ICU_ENCODE_SPACES_ONLY, "http://www.example.com/");
    CANON("http://www.example.com", ICU_BROWSER_MODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_ENCODE_PERCENT, "http://www.example.com/");
    CANON("http://www.example.com", ICU_ESCAPE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_DECODE | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_NO_META | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://www.example.com/");
    CANON("http://www.example.com", ICU_USERNAME, "http://www.example.com/");
}
TEST(url_crack_canon_http_www_example_com_path) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", 0, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_NO_ENCODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_DECODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_NO_META, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_ENCODE_SPACES_ONLY, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_BROWSER_MODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_ENCODE_PERCENT, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_ESCAPE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_DECODE | ICU_NO_ENCODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_NO_META | ICU_NO_ENCODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://www.example.com/PATH");
    CANON("HTTP://WWW.EXAMPLE.COM/PATH", ICU_USERNAME, "http://www.example.com/PATH");
}
TEST(url_crack_canon_http_host_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a b c", 0, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_NO_ENCODE, "http://host/a b c");
    CANON("http://host/a b c", ICU_DECODE, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_NO_META, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_ENCODE_SPACES_ONLY, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_BROWSER_MODE, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_ENCODE_PERCENT, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_ESCAPE, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_DECODE | ICU_NO_ENCODE, "http://host/a b c");
    CANON("http://host/a b c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a b c");
    CANON("http://host/a b c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%20b%20c");
    CANON("http://host/a b c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a b c");
    CANON("http://host/a b c", ICU_USERNAME, "http://host/a%20b%20c");
}
TEST(url_crack_canon_http_host_a_20b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a%20b", 0, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_NO_ENCODE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_DECODE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_NO_META, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_ENCODE_SPACES_ONLY, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_BROWSER_MODE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_ENCODE_PERCENT, "http://host/a%2520b");
    CANON("http://host/a%20b", ICU_ESCAPE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_DECODE | ICU_NO_ENCODE, "http://host/a b");
    CANON("http://host/a%20b", ICU_NO_META | ICU_NO_ENCODE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a%20b");
    CANON("http://host/a%20b", ICU_USERNAME, "http://host/a%20b");
}
TEST(url_crack_canon_http_host_a_2fb) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a%2fb", 0, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_NO_ENCODE, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_DECODE, "http://host/a/b");
    CANON("http://host/a%2fb", ICU_NO_META, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_ENCODE_SPACES_ONLY, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_BROWSER_MODE, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_ENCODE_PERCENT, "http://host/a%252fb");
    CANON("http://host/a%2fb", ICU_ESCAPE, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/b");
    CANON("http://host/a%2fb", ICU_NO_META | ICU_NO_ENCODE, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a%2fb");
    CANON("http://host/a%2fb", ICU_USERNAME, "http://host/a%2fb");
}
TEST(url_crack_canon_http_host_7euser) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/%7Euser", 0, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_NO_ENCODE, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_DECODE, "http://host/~user");
    CANON("http://host/%7Euser", ICU_NO_META, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_ENCODE_SPACES_ONLY, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_BROWSER_MODE, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_ENCODE_PERCENT, "http://host/%257Euser");
    CANON("http://host/%7Euser", ICU_ESCAPE, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_DECODE | ICU_NO_ENCODE, "http://host/~user");
    CANON("http://host/%7Euser", ICU_NO_META | ICU_NO_ENCODE, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/%7Euser");
    CANON("http://host/%7Euser", ICU_USERNAME, "http://host/%7Euser");
}
TEST(url_crack_canon_http_host_41_42) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/%41%42", 0, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_NO_ENCODE, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_DECODE, "http://host/AB");
    CANON("http://host/%41%42", ICU_NO_META, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_ENCODE_SPACES_ONLY, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_BROWSER_MODE, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_ENCODE_PERCENT, "http://host/%2541%2542");
    CANON("http://host/%41%42", ICU_ESCAPE, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_DECODE | ICU_NO_ENCODE, "http://host/AB");
    CANON("http://host/%41%42", ICU_NO_META | ICU_NO_ENCODE, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/%41%42");
    CANON("http://host/%41%42", ICU_USERNAME, "http://host/%41%42");
}
TEST(url_crack_canon_http_host_a_b_c_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/./b/../c", 0, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_DECODE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_NO_META, "http://host/a/./b/../c");
    CANON("http://host/a/./b/../c", ICU_ENCODE_SPACES_ONLY, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_BROWSER_MODE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_ENCODE_PERCENT, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_ESCAPE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/./b/../c");
    CANON("http://host/a/./b/../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host/a/./b/../c", ICU_USERNAME, "http://host/a/c");
}
TEST(url_crack_canon_http_host_a_b_c_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/b/../../../c", 0, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_DECODE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_NO_META, "http://host/a/b/../../../c");
    CANON("http://host/a/b/../../../c", ICU_ENCODE_SPACES_ONLY, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_BROWSER_MODE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_ENCODE_PERCENT, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_ESCAPE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_DECODE | ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/b/../../../c");
    CANON("http://host/a/b/../../../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a/b/../../../c", ICU_USERNAME, "http://host/c");
}
TEST(url_crack_canon_http_host) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/./", 0, "http://host/./");
    CANON("http://host/./", ICU_NO_ENCODE, "http://host/./");
    CANON("http://host/./", ICU_DECODE, "http://host/./");
    CANON("http://host/./", ICU_NO_META, "http://host/./");
    CANON("http://host/./", ICU_ENCODE_SPACES_ONLY, "http://host/./");
    CANON("http://host/./", ICU_BROWSER_MODE, "http://host/./");
    CANON("http://host/./", ICU_ENCODE_PERCENT, "http://host/./");
    CANON("http://host/./", ICU_ESCAPE, "http://host/./");
    CANON("http://host/./", ICU_DECODE | ICU_NO_ENCODE, "http://host/./");
    CANON("http://host/./", ICU_NO_META | ICU_NO_ENCODE, "http://host/./");
    CANON("http://host/./", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/./");
    CANON("http://host/./", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/./");
    CANON("http://host/./", ICU_USERNAME, "http://host/./");
}
TEST(url_crack_canon_http_host_a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/..", 0, "http://host/");
    CANON("http://host/a/..", ICU_NO_ENCODE, "http://host/");
    CANON("http://host/a/..", ICU_DECODE, "http://host/");
    CANON("http://host/a/..", ICU_NO_META, "http://host/a/..");
    CANON("http://host/a/..", ICU_ENCODE_SPACES_ONLY, "http://host/");
    CANON("http://host/a/..", ICU_BROWSER_MODE, "http://host/");
    CANON("http://host/a/..", ICU_ENCODE_PERCENT, "http://host/");
    CANON("http://host/a/..", ICU_ESCAPE, "http://host/");
    CANON("http://host/a/..", ICU_DECODE | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/a/..", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/..");
    CANON("http://host/a/..", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/a/..", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/a/..", ICU_USERNAME, "http://host/");
}
TEST(url_crack_canon_http_host_a_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/.", 0, "http://host/a/");
    CANON("http://host/a/.", ICU_NO_ENCODE, "http://host/a/");
    CANON("http://host/a/.", ICU_DECODE, "http://host/a/");
    CANON("http://host/a/.", ICU_NO_META, "http://host/a/.");
    CANON("http://host/a/.", ICU_ENCODE_SPACES_ONLY, "http://host/a/");
    CANON("http://host/a/.", ICU_BROWSER_MODE, "http://host/a/");
    CANON("http://host/a/.", ICU_ENCODE_PERCENT, "http://host/a/");
    CANON("http://host/a/.", ICU_ESCAPE, "http://host/a/");
    CANON("http://host/a/.", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/");
    CANON("http://host/a/.", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/.");
    CANON("http://host/a/.", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/");
    CANON("http://host/a/.", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/");
    CANON("http://host/a/.", ICU_USERNAME, "http://host/a/");
}
TEST(url_crack_canon_http_host_a_b_x_y) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/b/..?x/../y", 0, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_NO_ENCODE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_DECODE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_NO_META, "http://host/a/b/..?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_ENCODE_SPACES_ONLY, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_BROWSER_MODE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_ENCODE_PERCENT, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_ESCAPE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/b/..?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/?x/../y");
    CANON("http://host/a/b/..?x/../y", ICU_USERNAME, "http://host/a/?x/../y");
}
TEST(url_crack_canon_http_host_a_b_x_y_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/b/..#x/../y", 0, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_NO_ENCODE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_DECODE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_NO_META, "http://host/a/b/..#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_ENCODE_SPACES_ONLY, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_BROWSER_MODE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_ENCODE_PERCENT, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_ESCAPE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/b/..#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/#x/../y");
    CANON("http://host/a/b/..#x/../y", ICU_USERNAME, "http://host/a/#x/../y");
}
TEST(url_crack_canon_http_host_a_b_c_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host\\a\\b\\..\\c", 0, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_DECODE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_NO_META, "http://host/a/b/../c");
    CANON("http://host\\a\\b\\..\\c", ICU_ENCODE_SPACES_ONLY, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_BROWSER_MODE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_ENCODE_PERCENT, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_ESCAPE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/b/../c");
    CANON("http://host\\a\\b\\..\\c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/c");
    CANON("http://host\\a\\b\\..\\c", ICU_USERNAME, "http://host/a/c");
}
TEST(url_crack_canon_http_host_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a\\b", 0, "http://host/a/b");
    CANON("http://host/a\\b", ICU_NO_ENCODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_DECODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_NO_META, "http://host/a/b");
    CANON("http://host/a\\b", ICU_ENCODE_SPACES_ONLY, "http://host/a/b");
    CANON("http://host/a\\b", ICU_BROWSER_MODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_ENCODE_PERCENT, "http://host/a/b");
    CANON("http://host/a\\b", ICU_ESCAPE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/b");
    CANON("http://host/a\\b", ICU_USERNAME, "http://host/a/b");
}
TEST(url_crack_canon_http_host_a_b_c_5) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a?b c", 0, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_NO_ENCODE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_DECODE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_NO_META, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_ENCODE_SPACES_ONLY, "http://host/a?b%20c");
    CANON("http://host/a?b c", ICU_BROWSER_MODE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_ENCODE_PERCENT, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_ESCAPE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_DECODE | ICU_NO_ENCODE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a?b%20c");
    CANON("http://host/a?b c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a?b c");
    CANON("http://host/a?b c", ICU_USERNAME, "http://host/a?b c");
}
TEST(url_crack_canon_http_host_a_b_c_6) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a#b c", 0, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_NO_ENCODE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_DECODE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_NO_META, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_ENCODE_SPACES_ONLY, "http://host/a#b%20c");
    CANON("http://host/a#b c", ICU_BROWSER_MODE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_ENCODE_PERCENT, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_ESCAPE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_DECODE | ICU_NO_ENCODE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a#b%20c");
    CANON("http://host/a#b c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a#b c");
    CANON("http://host/a#b c", ICU_USERNAME, "http://host/a#b c");
}
TEST(url_crack_canon_http_host_a_b_20c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a?b%20c", 0, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_NO_ENCODE, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_DECODE, "http://host/a?b c");
    CANON("http://host/a?b%20c", ICU_NO_META, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_ENCODE_SPACES_ONLY, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_BROWSER_MODE, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_ENCODE_PERCENT, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_ESCAPE, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_DECODE | ICU_NO_ENCODE, "http://host/a?b c");
    CANON("http://host/a?b%20c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a?b%20c");
    CANON("http://host/a?b%20c", ICU_USERNAME, "http://host/a?b%20c");
}
TEST(url_crack_canon_http_host_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/<>\"{}|^`", 0, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
    CANON("http://host/<>\"{}|^`", ICU_NO_ENCODE, "http://host/<>\"{}|^`");
    CANON("http://host/<>\"{}|^`", ICU_DECODE, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
    CANON("http://host/<>\"{}|^`", ICU_NO_META, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
    CANON("http://host/<>\"{}|^`", ICU_ENCODE_SPACES_ONLY, "http://host/<>\"{}|^`");
    CANON("http://host/<>\"{}|^`", ICU_BROWSER_MODE, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
    CANON("http://host/<>\"{}|^`", ICU_ENCODE_PERCENT, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
    CANON("http://host/<>\"{}|^`", ICU_ESCAPE, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
    CANON("http://host/<>\"{}|^`", ICU_DECODE | ICU_NO_ENCODE, "http://host/<>\"{}|^`");
    CANON("http://host/<>\"{}|^`", ICU_NO_META | ICU_NO_ENCODE, "http://host/<>\"{}|^`");
    CANON("http://host/<>\"{}|^`", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/<>\"{}|^`");
    CANON("http://host/<>\"{}|^`", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/<>\"{}|^`");
    CANON("http://host/<>\"{}|^`", ICU_USERNAME, "http://host/%3C%3E%22%7B%7D%7C%5E%60");
}
TEST(url_crack_canon_http_host_a_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a%", 0, "http://host/a%");
    CANON("http://host/a%", ICU_NO_ENCODE, "http://host/a%");
    CANON("http://host/a%", ICU_DECODE, "http://host/a");
    CANON("http://host/a%", ICU_NO_META, "http://host/a%");
    CANON("http://host/a%", ICU_ENCODE_SPACES_ONLY, "http://host/a%");
    CANON("http://host/a%", ICU_BROWSER_MODE, "http://host/a%");
    CANON("http://host/a%", ICU_ENCODE_PERCENT, "http://host/a%25");
    CANON("http://host/a%", ICU_ESCAPE, "http://host/a%");
    CANON("http://host/a%", ICU_DECODE | ICU_NO_ENCODE, "http://host/a");
    CANON("http://host/a%", ICU_NO_META | ICU_NO_ENCODE, "http://host/a%");
    CANON("http://host/a%", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%");
    CANON("http://host/a%", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a%");
    CANON("http://host/a%", ICU_USERNAME, "http://host/a%");
}
TEST(url_crack_canon_http_host_a_2_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a%2", 0, "http://host/a%2");
    CANON("http://host/a%2", ICU_NO_ENCODE, "http://host/a%2");
    CANON("http://host/a%2", ICU_DECODE, "http://host/a");
    CANON("http://host/a%2", ICU_NO_META, "http://host/a%2");
    CANON("http://host/a%2", ICU_ENCODE_SPACES_ONLY, "http://host/a%2");
    CANON("http://host/a%2", ICU_BROWSER_MODE, "http://host/a%2");
    CANON("http://host/a%2", ICU_ENCODE_PERCENT, "http://host/a%252");
    CANON("http://host/a%2", ICU_ESCAPE, "http://host/a%2");
    CANON("http://host/a%2", ICU_DECODE | ICU_NO_ENCODE, "http://host/a");
    CANON("http://host/a%2", ICU_NO_META | ICU_NO_ENCODE, "http://host/a%2");
    CANON("http://host/a%2", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%2");
    CANON("http://host/a%2", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a%2");
    CANON("http://host/a%2", ICU_USERNAME, "http://host/a%2");
}
TEST(url_crack_canon_http_host_a_zz) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a%zz", 0, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_NO_ENCODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_DECODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_NO_META, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_ENCODE_SPACES_ONLY, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_BROWSER_MODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_ENCODE_PERCENT, "http://host/a%25zz");
    CANON("http://host/a%zz", ICU_ESCAPE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_DECODE | ICU_NO_ENCODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_NO_META | ICU_NO_ENCODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a%zz");
    CANON("http://host/a%zz", ICU_USERNAME, "http://host/a%zz");
}
TEST(url_crack_canon_http_host_25) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/%25", 0, "http://host/%25");
    CANON("http://host/%25", ICU_NO_ENCODE, "http://host/%25");
    CANON("http://host/%25", ICU_DECODE, "http://host/%");
    CANON("http://host/%25", ICU_NO_META, "http://host/%25");
    CANON("http://host/%25", ICU_ENCODE_SPACES_ONLY, "http://host/%25");
    CANON("http://host/%25", ICU_BROWSER_MODE, "http://host/%25");
    CANON("http://host/%25", ICU_ENCODE_PERCENT, "http://host/%2525");
    CANON("http://host/%25", ICU_ESCAPE, "http://host/%25");
    CANON("http://host/%25", ICU_DECODE | ICU_NO_ENCODE, "http://host/%");
    CANON("http://host/%25", ICU_NO_META | ICU_NO_ENCODE, "http://host/%25");
    CANON("http://host/%25", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/%25");
    CANON("http://host/%25", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/%25");
    CANON("http://host/%25", ICU_USERNAME, "http://host/%25");
}
TEST(url_crack_canon_http_host_a_25b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a%25b", 0, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_NO_ENCODE, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_DECODE, "http://host/a%b");
    CANON("http://host/a%25b", ICU_NO_META, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_ENCODE_SPACES_ONLY, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_BROWSER_MODE, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_ENCODE_PERCENT, "http://host/a%2525b");
    CANON("http://host/a%25b", ICU_ESCAPE, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_DECODE | ICU_NO_ENCODE, "http://host/a%b");
    CANON("http://host/a%25b", ICU_NO_META | ICU_NO_ENCODE, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a%25b");
    CANON("http://host/a%25b", ICU_USERNAME, "http://host/a%25b");
}
TEST(url_crack_canon_http_host_a_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a\x7f", 0, "http://host/a%7F");
    CANON("http://host/a\x7f", ICU_NO_ENCODE, "http://host/a\x7f");
    CANON("http://host/a\x7f", ICU_DECODE, "http://host/a%7F");
    CANON("http://host/a\x7f", ICU_NO_META, "http://host/a%7F");
    CANON("http://host/a\x7f", ICU_ENCODE_SPACES_ONLY, "http://host/a\x7f");
    CANON("http://host/a\x7f", ICU_BROWSER_MODE, "http://host/a%7F");
    CANON("http://host/a\x7f", ICU_ENCODE_PERCENT, "http://host/a%7F");
    CANON("http://host/a\x7f", ICU_ESCAPE, "http://host/a%7F");
    CANON("http://host/a\x7f", ICU_DECODE | ICU_NO_ENCODE, "http://host/a\x7f");
    CANON("http://host/a\x7f", ICU_NO_META | ICU_NO_ENCODE, "http://host/a\x7f");
    CANON("http://host/a\x7f", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a\x7f");
    CANON("http://host/a\x7f", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a\x7f");
    CANON("http://host/a\x7f", ICU_USERNAME, "http://host/a%7F");
}
TEST(url_crack_canon_http_host_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/\xc3\xa9", 0, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_NO_ENCODE, "http://host/\xc3\xa9");
    CANON("http://host/\xc3\xa9", ICU_DECODE, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_NO_META, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_ENCODE_SPACES_ONLY, "http://host/\xc3\xa9");
    CANON("http://host/\xc3\xa9", ICU_BROWSER_MODE, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_ENCODE_PERCENT, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_ESCAPE, "http://host/%C3%A9");
    CANON("http://host/\xc3\xa9", ICU_DECODE | ICU_NO_ENCODE, "http://host/\xc3\xa9");
    CANON("http://host/\xc3\xa9", ICU_NO_META | ICU_NO_ENCODE, "http://host/\xc3\xa9");
    CANON("http://host/\xc3\xa9", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/\xc3\xa9");
    CANON("http://host/\xc3\xa9", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/\xc3\xa9");
    CANON("http://host/\xc3\xa9", ICU_USERNAME, "http://host/%C3%A9");
}
TEST(url_crack_canon_http_host_a_5) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a#", 0, "http://host/a#");
    CANON("http://host/a#", ICU_NO_ENCODE, "http://host/a#");
    CANON("http://host/a#", ICU_DECODE, "http://host/a#");
    CANON("http://host/a#", ICU_NO_META, "http://host/a#");
    CANON("http://host/a#", ICU_ENCODE_SPACES_ONLY, "http://host/a#");
    CANON("http://host/a#", ICU_BROWSER_MODE, "http://host/a#");
    CANON("http://host/a#", ICU_ENCODE_PERCENT, "http://host/a#");
    CANON("http://host/a#", ICU_ESCAPE, "http://host/a#");
    CANON("http://host/a#", ICU_DECODE | ICU_NO_ENCODE, "http://host/a#");
    CANON("http://host/a#", ICU_NO_META | ICU_NO_ENCODE, "http://host/a#");
    CANON("http://host/a#", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a#");
    CANON("http://host/a#", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a#");
    CANON("http://host/a#", ICU_USERNAME, "http://host/a#");
}
TEST(url_crack_canon_http_host_a_6) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a?", 0, "http://host/a?");
    CANON("http://host/a?", ICU_NO_ENCODE, "http://host/a?");
    CANON("http://host/a?", ICU_DECODE, "http://host/a?");
    CANON("http://host/a?", ICU_NO_META, "http://host/a?");
    CANON("http://host/a?", ICU_ENCODE_SPACES_ONLY, "http://host/a?");
    CANON("http://host/a?", ICU_BROWSER_MODE, "http://host/a?");
    CANON("http://host/a?", ICU_ENCODE_PERCENT, "http://host/a?");
    CANON("http://host/a?", ICU_ESCAPE, "http://host/a?");
    CANON("http://host/a?", ICU_DECODE | ICU_NO_ENCODE, "http://host/a?");
    CANON("http://host/a?", ICU_NO_META | ICU_NO_ENCODE, "http://host/a?");
    CANON("http://host/a?", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a?");
    CANON("http://host/a?", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a?");
    CANON("http://host/a?", ICU_USERNAME, "http://host/a?");
}
TEST(url_crack_canon_http_host_80) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host:80/", 0, "http://host/");
    CANON("http://host:80/", ICU_NO_ENCODE, "http://host/");
    CANON("http://host:80/", ICU_DECODE, "http://host/");
    CANON("http://host:80/", ICU_NO_META, "http://host/");
    CANON("http://host:80/", ICU_ENCODE_SPACES_ONLY, "http://host/");
    CANON("http://host:80/", ICU_BROWSER_MODE, "http://host/");
    CANON("http://host:80/", ICU_ENCODE_PERCENT, "http://host/");
    CANON("http://host:80/", ICU_ESCAPE, "http://host/");
    CANON("http://host:80/", ICU_DECODE | ICU_NO_ENCODE, "http://host/");
    CANON("http://host:80/", ICU_NO_META | ICU_NO_ENCODE, "http://host/");
    CANON("http://host:80/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/");
    CANON("http://host:80/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/");
    CANON("http://host:80/", ICU_USERNAME, "http://host/");
}
TEST(url_crack_canon_http_host_8080_x) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host:8080/x", 0, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_NO_ENCODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_DECODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_NO_META, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_ENCODE_SPACES_ONLY, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_BROWSER_MODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_ENCODE_PERCENT, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_ESCAPE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_DECODE | ICU_NO_ENCODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_NO_META | ICU_NO_ENCODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host:8080/x");
    CANON("http://host:8080/x", ICU_USERNAME, "http://host:8080/x");
}
TEST(url_crack_canon_http_user_pass_host) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://user:pass@host/", 0, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_NO_ENCODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_DECODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_NO_META, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_ENCODE_SPACES_ONLY, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_BROWSER_MODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_ENCODE_PERCENT, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_ESCAPE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_DECODE | ICU_NO_ENCODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_NO_META | ICU_NO_ENCODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://user:pass@host/");
    CANON("http://user:pass@host/", ICU_USERNAME, "http://user:pass@host/");
}
TEST(url_crack_canon_http_host_a_b_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host//a//b", 0, "http://host//a//b");
    CANON("http://host//a//b", ICU_NO_ENCODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_DECODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_NO_META, "http://host//a//b");
    CANON("http://host//a//b", ICU_ENCODE_SPACES_ONLY, "http://host//a//b");
    CANON("http://host//a//b", ICU_BROWSER_MODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_ENCODE_PERCENT, "http://host//a//b");
    CANON("http://host//a//b", ICU_ESCAPE, "http://host//a//b");
    CANON("http://host//a//b", ICU_DECODE | ICU_NO_ENCODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_NO_META | ICU_NO_ENCODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host//a//b");
    CANON("http://host//a//b", ICU_USERNAME, "http://host//a//b");
}
TEST(url_crack_canon_file_c_a_b_c_txt) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a/b/../c.txt", 0, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_NO_ENCODE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_DECODE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_NO_META, "file://C:\\a\\b\\..\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_BROWSER_MODE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_ESCAPE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\..\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a\\c.txt");
    CANON("file:///C:/a/b/../c.txt", ICU_USERNAME, "file://C:\\a\\c.txt");
}
TEST(url_crack_canon_file_c_a_b_txt) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a b.txt", 0, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_NO_ENCODE, "file://C:\\a b.txt");
    CANON("file:///C:/a b.txt", ICU_DECODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_NO_META, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_BROWSER_MODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_ENCODE_PERCENT, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_ESCAPE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a b.txt");
    CANON("file:///C:/a b.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a b.txt");
    CANON("file:///C:/a b.txt", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a b.txt", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a b.txt");
    CANON("file:///C:/a b.txt", ICU_USERNAME, "file://C:\\a%20b.txt");
}
TEST(url_crack_canon_file_c_a_b_txt_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:\\a\\b.txt", 0, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_DECODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_NO_META, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_BROWSER_MODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_ESCAPE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file:///C:\\a\\b.txt", ICU_USERNAME, "file://C:\\a\\b.txt");
}
TEST(url_crack_canon_file_c_a_b_txt_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file://C:\\a\\b.txt", 0, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_DECODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_NO_META, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_BROWSER_MODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_ESCAPE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("file://C:\\a\\b.txt", ICU_USERNAME, "file://C:\\a\\b.txt");
}
TEST(url_crack_canon_c_a_b_txt) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("C:\\a\\b.txt", 0, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_DECODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_NO_META, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_BROWSER_MODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_ESCAPE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a\\b.txt");
    CANON("C:\\a\\b.txt", ICU_USERNAME, "file://C:\\a\\b.txt");
}
TEST(url_crack_canon_file_c_a_20b_txt) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a%20b.txt", 0, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_NO_ENCODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_DECODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_NO_META, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_BROWSER_MODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_ENCODE_PERCENT, "file://C:\\a%2520b.txt");
    CANON("file:///C:/a%20b.txt", ICU_ESCAPE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a b.txt");
    CANON("file:///C:/a%20b.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a%20b.txt");
    CANON("file:///C:/a%20b.txt", ICU_USERNAME, "file://C:\\a%20b.txt");
}
TEST(url_crack_canon_ftp_host_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://host/a b", 0, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_NO_ENCODE, "ftp://host/a b");
    CANON("ftp://host/a b", ICU_DECODE, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_NO_META, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_ENCODE_SPACES_ONLY, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_BROWSER_MODE, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_ENCODE_PERCENT, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_ESCAPE, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_DECODE | ICU_NO_ENCODE, "ftp://host/a b");
    CANON("ftp://host/a b", ICU_NO_META | ICU_NO_ENCODE, "ftp://host/a b");
    CANON("ftp://host/a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://host/a%20b");
    CANON("ftp://host/a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://host/a b");
    CANON("ftp://host/a b", ICU_USERNAME, "ftp://host/a%20b");
}
TEST(url_crack_canon_ftp_host_a_b_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://host/a/../b", 0, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_NO_ENCODE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_DECODE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_NO_META, "ftp://host/a/../b");
    CANON("ftp://host/a/../b", ICU_ENCODE_SPACES_ONLY, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_BROWSER_MODE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_ENCODE_PERCENT, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_ESCAPE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_DECODE | ICU_NO_ENCODE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_NO_META | ICU_NO_ENCODE, "ftp://host/a/../b");
    CANON("ftp://host/a/../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://host/b");
    CANON("ftp://host/a/../b", ICU_USERNAME, "ftp://host/b");
}
TEST(url_crack_canon_mailto_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("mailto:a b@c", 0, "mailto:a%20b@c");
    CANON("mailto:a b@c", ICU_NO_ENCODE, "mailto:a b@c");
    CANON("mailto:a b@c", ICU_DECODE, "mailto:a%20b@c");
    CANON("mailto:a b@c", ICU_NO_META, "mailto:a%20b@c");
    CANON("mailto:a b@c", ICU_ENCODE_SPACES_ONLY, "mailto:a b@c");
    CANON("mailto:a b@c", ICU_BROWSER_MODE, "mailto:a%20b@c");
    CANON("mailto:a b@c", ICU_ENCODE_PERCENT, "mailto:a%20b@c");
    CANON("mailto:a b@c", ICU_ESCAPE, "mailto:a%20b@c");
    CANON("mailto:a b@c", ICU_DECODE | ICU_NO_ENCODE, "mailto:a b@c");
    CANON("mailto:a b@c", ICU_NO_META | ICU_NO_ENCODE, "mailto:a b@c");
    CANON("mailto:a b@c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "mailto:a b@c");
    CANON("mailto:a b@c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "mailto:a b@c");
    CANON("mailto:a b@c", ICU_USERNAME, "mailto:a%20b@c");
}
TEST(url_crack_canon_javascript_alert_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("javascript:alert('a b')", 0, "javascript:alert('a%20b')");
    CANON("javascript:alert('a b')", ICU_NO_ENCODE, "javascript:alert('a b')");
    CANON("javascript:alert('a b')", ICU_DECODE, "javascript:alert('a%20b')");
    CANON("javascript:alert('a b')", ICU_NO_META, "javascript:alert('a%20b')");
    CANON("javascript:alert('a b')", ICU_ENCODE_SPACES_ONLY, "javascript:alert('a b')");
    CANON("javascript:alert('a b')", ICU_BROWSER_MODE, "javascript:alert('a%20b')");
    CANON("javascript:alert('a b')", ICU_ENCODE_PERCENT, "javascript:alert('a%20b')");
    CANON("javascript:alert('a b')", ICU_ESCAPE, "javascript:alert('a%20b')");
    CANON("javascript:alert('a b')", ICU_DECODE | ICU_NO_ENCODE, "javascript:alert('a b')");
    CANON("javascript:alert('a b')", ICU_NO_META | ICU_NO_ENCODE, "javascript:alert('a b')");
    CANON("javascript:alert('a b')", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "javascript:alert('a b')");
    CANON("javascript:alert('a b')", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "javascript:alert('a b')");
    CANON("javascript:alert('a b')", ICU_USERNAME, "javascript:alert('a%20b')");
}
TEST(url_crack_canon_about_blank) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("about:blank", 0, "about:blank");
    CANON("about:blank", ICU_NO_ENCODE, "about:blank");
    CANON("about:blank", ICU_DECODE, "about:blank");
    CANON("about:blank", ICU_NO_META, "about:blank");
    CANON("about:blank", ICU_ENCODE_SPACES_ONLY, "about:blank");
    CANON("about:blank", ICU_BROWSER_MODE, "about:blank");
    CANON("about:blank", ICU_ENCODE_PERCENT, "about:blank");
    CANON("about:blank", ICU_ESCAPE, "about:blank");
    CANON("about:blank", ICU_DECODE | ICU_NO_ENCODE, "about:blank");
    CANON("about:blank", ICU_NO_META | ICU_NO_ENCODE, "about:blank");
    CANON("about:blank", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "about:blank");
    CANON("about:blank", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "about:blank");
    CANON("about:blank", ICU_USERNAME, "about:blank");
}
TEST(url_crack_canon_foo_host_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("foo://host/a b/../c", 0, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_NO_ENCODE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_DECODE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_NO_META, "foo://host/a%20b/../c");
    CANON("foo://host/a b/../c", ICU_ENCODE_SPACES_ONLY, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_BROWSER_MODE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_ENCODE_PERCENT, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_ESCAPE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_DECODE | ICU_NO_ENCODE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_NO_META | ICU_NO_ENCODE, "foo://host/a b/../c");
    CANON("foo://host/a b/../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "foo://host/c");
    CANON("foo://host/a b/../c", ICU_USERNAME, "foo://host/a%20b/../c");
}
TEST(url_crack_canon_foo_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("foo:a b", 0, "foo:a%20b");
    CANON("foo:a b", ICU_NO_ENCODE, "foo:a b");
    CANON("foo:a b", ICU_DECODE, "foo:a%20b");
    CANON("foo:a b", ICU_NO_META, "foo:a%20b");
    CANON("foo:a b", ICU_ENCODE_SPACES_ONLY, "foo:a%20b");
    CANON("foo:a b", ICU_BROWSER_MODE, "foo:a%20b");
    CANON("foo:a b", ICU_ENCODE_PERCENT, "foo:a%20b");
    CANON("foo:a b", ICU_ESCAPE, "foo:a%20b");
    CANON("foo:a b", ICU_DECODE | ICU_NO_ENCODE, "foo:a b");
    CANON("foo:a b", ICU_NO_META | ICU_NO_ENCODE, "foo:a b");
    CANON("foo:a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "foo:a%20b");
    CANON("foo:a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "foo:a b");
    CANON("foo:a b", ICU_USERNAME, "foo:a%20b");
}
TEST(url_crack_canon_res_x_dll_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("res://x.dll/a b", 0, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_NO_ENCODE, "res://x.dll/a b");
    CANON("res://x.dll/a b", ICU_DECODE, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_NO_META, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_ENCODE_SPACES_ONLY, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_BROWSER_MODE, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_ENCODE_PERCENT, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_ESCAPE, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_DECODE | ICU_NO_ENCODE, "res://x.dll/a b");
    CANON("res://x.dll/a b", ICU_NO_META | ICU_NO_ENCODE, "res://x.dll/a b");
    CANON("res://x.dll/a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "res://x.dll/a%20b");
    CANON("res://x.dll/a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "res://x.dll/a b");
    CANON("res://x.dll/a b", ICU_USERNAME, "res://x.dll/a%20b");
}
TEST(url_crack_canon_http_host_a_2e_2e_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/%2e%2e/b", 0, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_NO_ENCODE, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_DECODE, "http://host/a/../b");
    CANON("http://host/a/%2e%2e/b", ICU_NO_META, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_ENCODE_SPACES_ONLY, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_BROWSER_MODE, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_ENCODE_PERCENT, "http://host/a/%252e%252e/b");
    CANON("http://host/a/%2e%2e/b", ICU_ESCAPE, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/../b");
    CANON("http://host/a/%2e%2e/b", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/%2e%2e/b");
    CANON("http://host/a/%2e%2e/b", ICU_USERNAME, "http://host/a/%2e%2e/b");
}
TEST(url_crack_canon_http_host_a_2e_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/%2E/b", 0, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_NO_ENCODE, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_DECODE, "http://host/a/./b");
    CANON("http://host/a/%2E/b", ICU_NO_META, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_ENCODE_SPACES_ONLY, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_BROWSER_MODE, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_ENCODE_PERCENT, "http://host/a/%252E/b");
    CANON("http://host/a/%2E/b", ICU_ESCAPE, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/./b");
    CANON("http://host/a/%2E/b", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/%2E/b");
    CANON("http://host/a/%2E/b", ICU_USERNAME, "http://host/a/%2E/b");
}
TEST(url_crack_canon_http_host_a_b_c_d) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/.b/..c/d", 0, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_NO_ENCODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_DECODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_NO_META, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_ENCODE_SPACES_ONLY, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_BROWSER_MODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_ENCODE_PERCENT, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_ESCAPE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/.b/..c/d");
    CANON("http://host/a/.b/..c/d", ICU_USERNAME, "http://host/a/.b/..c/d");
}
TEST(url_crack_canon_http_host_a_b_c_7) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a;b/../c", 0, "http://host/c");
    CANON("http://host/a;b/../c", ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_DECODE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_NO_META, "http://host/a;b/../c");
    CANON("http://host/a;b/../c", ICU_ENCODE_SPACES_ONLY, "http://host/c");
    CANON("http://host/a;b/../c", ICU_BROWSER_MODE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_ENCODE_PERCENT, "http://host/c");
    CANON("http://host/a;b/../c", ICU_ESCAPE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_DECODE | ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_NO_META | ICU_NO_ENCODE, "http://host/a;b/../c");
    CANON("http://host/a;b/../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/c");
    CANON("http://host/a;b/../c", ICU_USERNAME, "http://host/c");
}
TEST(url_crack_canon_http_host_a_b_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a+b", 0, "http://host/a+b");
    CANON("http://host/a+b", ICU_NO_ENCODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_DECODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_NO_META, "http://host/a+b");
    CANON("http://host/a+b", ICU_ENCODE_SPACES_ONLY, "http://host/a+b");
    CANON("http://host/a+b", ICU_BROWSER_MODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_ENCODE_PERCENT, "http://host/a+b");
    CANON("http://host/a+b", ICU_ESCAPE, "http://host/a+b");
    CANON("http://host/a+b", ICU_DECODE | ICU_NO_ENCODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_NO_META | ICU_NO_ENCODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a+b");
    CANON("http://host/a+b", ICU_USERNAME, "http://host/a+b");
}
TEST(url_crack_canon_http_host_a_7) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/~a", 0, "http://host/~a");
    CANON("http://host/~a", ICU_NO_ENCODE, "http://host/~a");
    CANON("http://host/~a", ICU_DECODE, "http://host/~a");
    CANON("http://host/~a", ICU_NO_META, "http://host/~a");
    CANON("http://host/~a", ICU_ENCODE_SPACES_ONLY, "http://host/~a");
    CANON("http://host/~a", ICU_BROWSER_MODE, "http://host/~a");
    CANON("http://host/~a", ICU_ENCODE_PERCENT, "http://host/~a");
    CANON("http://host/~a", ICU_ESCAPE, "http://host/~a");
    CANON("http://host/~a", ICU_DECODE | ICU_NO_ENCODE, "http://host/~a");
    CANON("http://host/~a", ICU_NO_META | ICU_NO_ENCODE, "http://host/~a");
    CANON("http://host/~a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/~a");
    CANON("http://host/~a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/~a");
    CANON("http://host/~a", ICU_USERNAME, "http://host/~a");
}
TEST(url_crack_canon_http_ho_st) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://ho st/", 0, "http://ho%20st/");
    CANON("http://ho st/", ICU_NO_ENCODE, "http://ho st/");
    CANON("http://ho st/", ICU_DECODE, "http://ho st/");
    CANON("http://ho st/", ICU_NO_META, "http://ho%20st/");
    CANON("http://ho st/", ICU_ENCODE_SPACES_ONLY, "http://ho%20st/");
    CANON("http://ho st/", ICU_BROWSER_MODE, "http://ho%20st/");
    CANON("http://ho st/", ICU_ENCODE_PERCENT, "http://ho%20st/");
    CANON("http://ho st/", ICU_ESCAPE, "http://ho%20st/");
    CANON("http://ho st/", ICU_DECODE | ICU_NO_ENCODE, "http://ho st/");
    CANON("http://ho st/", ICU_NO_META | ICU_NO_ENCODE, "http://ho st/");
    CANON("http://ho st/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://ho%20st/");
    CANON("http://ho st/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://ho st/");
    CANON("http://ho st/", ICU_USERNAME, "http://ho%20st/");
}
TEST(url_crack_canon_http_host_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/\x09", 0, "http://host/");
    CANON("http://host/\x09", ICU_NO_ENCODE, "http://host/");
    CANON("http://host/\x09", ICU_DECODE, "http://host/");
    CANON("http://host/\x09", ICU_NO_META, "http://host/");
    CANON("http://host/\x09", ICU_ENCODE_SPACES_ONLY, "http://host/");
    CANON("http://host/\x09", ICU_BROWSER_MODE, "http://host/");
    CANON("http://host/\x09", ICU_ENCODE_PERCENT, "http://host/");
    CANON("http://host/\x09", ICU_ESCAPE, "http://host/");
    CANON("http://host/\x09", ICU_DECODE | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/\x09", ICU_NO_META | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/\x09", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/\x09", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/\x09", ICU_USERNAME, "http://host/");
}
TEST(url_crack_canon_http_host_5) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("  http://host/  ", 0, "http://host/");
    CANON("  http://host/  ", ICU_NO_ENCODE, "http://host/");
    CANON("  http://host/  ", ICU_DECODE, "http://host/");
    CANON("  http://host/  ", ICU_NO_META, "http://host/");
    CANON("  http://host/  ", ICU_ENCODE_SPACES_ONLY, "http://host/");
    CANON("  http://host/  ", ICU_BROWSER_MODE, "http://host/");
    CANON("  http://host/  ", ICU_ENCODE_PERCENT, "http://host/");
    CANON("  http://host/  ", ICU_ESCAPE, "http://host/");
    CANON("  http://host/  ", ICU_DECODE | ICU_NO_ENCODE, "http://host/");
    CANON("  http://host/  ", ICU_NO_META | ICU_NO_ENCODE, "http://host/");
    CANON("  http://host/  ", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/");
    CANON("  http://host/  ", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/");
    CANON("  http://host/  ", ICU_USERNAME, "http://host/");
}
TEST(url_crack_canon_http_host_a_b_c_d_e_f) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a b?c d#e f", 0, "http://host/a%20b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_NO_ENCODE, "http://host/a b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_DECODE, "http://host/a%20b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_NO_META, "http://host/a%20b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_ENCODE_SPACES_ONLY, "http://host/a%20b?c%20d#e%20f");
    CANON("http://host/a b?c d#e f", ICU_BROWSER_MODE, "http://host/a%20b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_ENCODE_PERCENT, "http://host/a%20b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_ESCAPE, "http://host/a%20b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_DECODE | ICU_NO_ENCODE, "http://host/a b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_NO_META | ICU_NO_ENCODE, "http://host/a b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a%20b?c%20d#e%20f");
    CANON("http://host/a b?c d#e f", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a b?c d#e f");
    CANON("http://host/a b?c d#e f", ICU_USERNAME, "http://host/a%20b?c d#e f");
}
TEST(url_crack_canon_empty) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("", 0, "");
    CANON("", ICU_NO_ENCODE, "");
    CANON("", ICU_DECODE, "");
    CANON("", ICU_NO_META, "");
    CANON("", ICU_ENCODE_SPACES_ONLY, "");
    CANON("", ICU_BROWSER_MODE, "");
    CANON("", ICU_ENCODE_PERCENT, "");
    CANON("", ICU_ESCAPE, "");
    CANON("", ICU_DECODE | ICU_NO_ENCODE, "");
    CANON("", ICU_NO_META | ICU_NO_ENCODE, "");
    CANON("", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "");
    CANON("", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "");
    CANON("", ICU_USERNAME, "");
}
TEST(url_crack_canon_nocolon) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("nocolon", 0, "nocolon");
    CANON("nocolon", ICU_NO_ENCODE, "nocolon");
    CANON("nocolon", ICU_DECODE, "nocolon");
    CANON("nocolon", ICU_NO_META, "nocolon");
    CANON("nocolon", ICU_ENCODE_SPACES_ONLY, "nocolon");
    CANON("nocolon", ICU_BROWSER_MODE, "nocolon");
    CANON("nocolon", ICU_ENCODE_PERCENT, "nocolon");
    CANON("nocolon", ICU_ESCAPE, "nocolon");
    CANON("nocolon", ICU_DECODE | ICU_NO_ENCODE, "nocolon");
    CANON("nocolon", ICU_NO_META | ICU_NO_ENCODE, "nocolon");
    CANON("nocolon", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "nocolon");
    CANON("nocolon", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "nocolon");
    CANON("nocolon", ICU_USERNAME, "nocolon");
}
TEST(url_crack_canon_relative_path) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("/relative/path", 0, "/relative/path");
    CANON("/relative/path", ICU_NO_ENCODE, "/relative/path");
    CANON("/relative/path", ICU_DECODE, "/relative/path");
    CANON("/relative/path", ICU_NO_META, "/relative/path");
    CANON("/relative/path", ICU_ENCODE_SPACES_ONLY, "/relative/path");
    CANON("/relative/path", ICU_BROWSER_MODE, "/relative/path");
    CANON("/relative/path", ICU_ENCODE_PERCENT, "/relative/path");
    CANON("/relative/path", ICU_ESCAPE, "/relative/path");
    CANON("/relative/path", ICU_DECODE | ICU_NO_ENCODE, "/relative/path");
    CANON("/relative/path", ICU_NO_META | ICU_NO_ENCODE, "/relative/path");
    CANON("/relative/path", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "/relative/path");
    CANON("/relative/path", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "/relative/path");
    CANON("/relative/path", ICU_USERNAME, "/relative/path");
}
TEST(url_crack_canon_rel_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("rel a/b", 0, "rel%20a/b");
    CANON("rel a/b", ICU_NO_ENCODE, "rel a/b");
    CANON("rel a/b", ICU_DECODE, "rel%20a/b");
    CANON("rel a/b", ICU_NO_META, "rel%20a/b");
    CANON("rel a/b", ICU_ENCODE_SPACES_ONLY, "rel%20a/b");
    CANON("rel a/b", ICU_BROWSER_MODE, "rel%20a/b");
    CANON("rel a/b", ICU_ENCODE_PERCENT, "rel%20a/b");
    CANON("rel a/b", ICU_ESCAPE, "rel%20a/b");
    CANON("rel a/b", ICU_DECODE | ICU_NO_ENCODE, "rel a/b");
    CANON("rel a/b", ICU_NO_META | ICU_NO_ENCODE, "rel a/b");
    CANON("rel a/b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "rel%20a/b");
    CANON("rel a/b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "rel a/b");
    CANON("rel a/b", ICU_USERNAME, "rel%20a/b");
}
TEST(url_crack_canon_http_host_a_b_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http:host/a/../b", 0, "http:host/b");
    CANON("http:host/a/../b", ICU_NO_ENCODE, "http:host/b");
    CANON("http:host/a/../b", ICU_DECODE, "http:host%2Fb");
    CANON("http:host/a/../b", ICU_NO_META, "http:host/a/../b");
    CANON("http:host/a/../b", ICU_ENCODE_SPACES_ONLY, "http:host/b");
    CANON("http:host/a/../b", ICU_BROWSER_MODE, "http:host/b");
    CANON("http:host/a/../b", ICU_ENCODE_PERCENT, "http:host/b");
    CANON("http:host/a/../b", ICU_ESCAPE, "http:host/b");
    CANON("http:host/a/../b", ICU_DECODE | ICU_NO_ENCODE, "http:host/b");
    CANON("http:host/a/../b", ICU_NO_META | ICU_NO_ENCODE, "http:host/a/../b");
    CANON("http:host/a/../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http:host/b");
    CANON("http:host/a/../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http:host/b");
    CANON("http:host/a/../b", ICU_USERNAME, "http:host/b");
}
TEST(url_crack_canon_http_host_a_b_c_g) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/a/b/c/./../../g", 0, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_NO_ENCODE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_DECODE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_NO_META, "http://host/a/b/c/./../../g");
    CANON("http://host/a/b/c/./../../g", ICU_ENCODE_SPACES_ONLY, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_BROWSER_MODE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_ENCODE_PERCENT, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_ESCAPE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_DECODE | ICU_NO_ENCODE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_NO_META | ICU_NO_ENCODE, "http://host/a/b/c/./../../g");
    CANON("http://host/a/b/c/./../../g", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/a/g");
    CANON("http://host/a/b/c/./../../g", ICU_USERNAME, "http://host/a/g");
}
TEST(url_crack_canon_https_host_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("https://host/a/b/../c", 0, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_NO_ENCODE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_DECODE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_NO_META, "https://host/a/b/../c");
    CANON("https://host/a/b/../c", ICU_ENCODE_SPACES_ONLY, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_BROWSER_MODE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_ENCODE_PERCENT, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_ESCAPE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_DECODE | ICU_NO_ENCODE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_NO_META | ICU_NO_ENCODE, "https://host/a/b/../c");
    CANON("https://host/a/b/../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "https://host/a/c");
    CANON("https://host/a/b/../c", ICU_USERNAME, "https://host/a/c");
}
TEST(url_crack_canon_http_host_6) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://host/%", 0, "http://host/%");
    CANON("http://host/%", ICU_NO_ENCODE, "http://host/%");
    CANON("http://host/%", ICU_DECODE, "http://host/");
    CANON("http://host/%", ICU_NO_META, "http://host/%");
    CANON("http://host/%", ICU_ENCODE_SPACES_ONLY, "http://host/%");
    CANON("http://host/%", ICU_BROWSER_MODE, "http://host/%");
    CANON("http://host/%", ICU_ENCODE_PERCENT, "http://host/%25");
    CANON("http://host/%", ICU_ESCAPE, "http://host/%");
    CANON("http://host/%", ICU_DECODE | ICU_NO_ENCODE, "http://host/");
    CANON("http://host/%", ICU_NO_META | ICU_NO_ENCODE, "http://host/%");
    CANON("http://host/%", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://host/%");
    CANON("http://host/%", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://host/%");
    CANON("http://host/%", ICU_USERNAME, "http://host/%");
}
TEST(url_crack_canon_http_1_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://[::1]/a/../b", 0, "http://%5B::1%5D/b");
    CANON("http://[::1]/a/../b", ICU_NO_ENCODE, "http://[::1]/b");
    CANON("http://[::1]/a/../b", ICU_DECODE, "http://[::1]/b");
    CANON("http://[::1]/a/../b", ICU_NO_META, "http://%5B::1%5D/a/../b");
    CANON("http://[::1]/a/../b", ICU_ENCODE_SPACES_ONLY, "http://[::1]/b");
    CANON("http://[::1]/a/../b", ICU_BROWSER_MODE, "http://%5B::1%5D/b");
    CANON("http://[::1]/a/../b", ICU_ENCODE_PERCENT, "http://%5B::1%5D/b");
    CANON("http://[::1]/a/../b", ICU_ESCAPE, "http://%5B::1%5D/b");
    CANON("http://[::1]/a/../b", ICU_DECODE | ICU_NO_ENCODE, "http://[::1]/b");
    CANON("http://[::1]/a/../b", ICU_NO_META | ICU_NO_ENCODE, "http://[::1]/a/../b");
    CANON("http://[::1]/a/../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://[::1]/b");
    CANON("http://[::1]/a/../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://[::1]/b");
    CANON("http://[::1]/a/../b", ICU_USERNAME, "http://%5B::1%5D/b");
}
