/* url_crack: InternetCombineUrlA/W.
 * [D] InternetCombineUrlA@0x137f40 / W@0x35a70: NULL base, NULL relative or NULL length -> 87; a NULL output buffer is
 * allowed (shlwapi size query -> 122 with the required length incl. NUL); then UrlCombineA/W with
 * dwFlags ^ ICU_NO_ENCODE | URL_WININET_COMPATIBILITY, the result is canonicalized like InternetCanonicalizeUrl.
 * One TEST per (base, relative) pair, each with seven flag sets; every row observed on the Win10 22H2 VM.
 * Win10 facts worth knowing (they differ from RFC 3986):
 *  - "g:h" against an http base gives "file://g:h" (a one-letter scheme is a drive letter).
 *  - "http:g" against an http base is relative ("http://a/b/c/g"); "https:g" is absolute and opaque.
 *  - "/./g" and "/../g" keep their dot segments; "../../../g" stops at the root.
 *  - "?y" replaces the query but keeps ";p"; "" and "." both give the base directory ("http://a/b/c/").
 *  - ("http://a/b#y", "?z") gives "http://a/b#y?z" (the base fragment is not stripped; with ICU_DECODE the result
 *    is "http://a/b?z#y"); ("http://a/b?x#y", "#z") gives "http://a/b?x#z".
 *  - a fragment-only base with "" gives the directory: ("http://a/b/c#f", "") -> "http://a/b/".
 *  - scheme and host of the result are lower-cased; spaces in the relative part are escaped unless ICU_NO_ENCODE.
 * VM_TIMEOUT: 120 */
#include "uc.h"

TEST(url_crack_combine_A_null_args) {
    REQUIRE(U(InternetCombineUrlA));
    char out[64]; DWORD n = sizeof out;
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCombineUrlA)(NULL, "g", out, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b", NULL, out, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b", "g", out, NULL, 0), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_combine_W_null_args) {
    REQUIRE(U(InternetCombineUrlW));
    WCHAR out[64]; DWORD n = 64;
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCombineUrlW)(NULL, L"g", out, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCombineUrlW)(L"http://a/b", NULL, out, &n, 0), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCombineUrlW)(L"http://a/b", L"g", out, NULL, 0), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_combine_A_buffer_protocol) {
    /* [W10] ("http://a/b/c", "d/e/f") = "http://a/b/d/e/f" (16 chars) */
    REQUIRE(U(InternetCombineUrlA));
    char out[64]; DWORD n;
    n = 8; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b/c", "d/e/f", out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
    n = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b/c", "d/e/f", out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
    n = 16; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b/c", "d/e/f", out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
    n = 17; SET_ERR(0xdead);
    CHECK(U(InternetCombineUrlA)("http://a/b/c", "d/e/f", out, &n, 0));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 16);
    EXPECT_STR(out, "http://a/b/d/e/f");
}
TEST(url_crack_combine_A_null_buffer_size_query) {
    REQUIRE(U(InternetCombineUrlA));
    DWORD n = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b/c", "d/e/f", NULL, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
    n = 100; SET_ERR(0xdead);   /* a large length does not help without a buffer */
    EXPECT_FAIL(!U(InternetCombineUrlA)("http://a/b/c", "d/e/f", NULL, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
}
TEST(url_crack_combine_W_buffer_protocol) {
    REQUIRE(U(InternetCombineUrlW));
    WCHAR out[64]; DWORD n;
    n = 4; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlW)(L"http://a/b/c", L"d/e/f", out, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
    n = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCombineUrlW)(L"http://a/b/c", L"d/e/f", NULL, &n, 0), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 17);
    n = 17; SET_ERR(0xdead);
    CHECK(U(InternetCombineUrlW)(L"http://a/b/c", L"d/e/f", out, &n, 0));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 16);
    EXPECT_WSTR(out, L"http://a/b/d/e/f");
}
TEST(url_crack_combine_last_error_zero_on_success) {
    REQUIRE(U(InternetCombineUrlA));
    char out[64]; DWORD n = sizeof out;
    SET_ERR(4242);
    CHECK(U(InternetCombineUrlA)("http://a/b/c", "../d", out, &n, 0));
    EXPECT_ERR(0);
    EXPECT_STR(out, "http://a/d");
}

TEST(url_crack_combine_rfc_gcolonh) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g:h", 0, "file://g:h");
    COMBINE("http://a/b/c/d;p?q", "g:h", ICU_NO_ENCODE, "file://g:h");
    COMBINE("http://a/b/c/d;p?q", "g:h", ICU_DECODE, "file://g:h");
    COMBINE("http://a/b/c/d;p?q", "g:h", ICU_NO_META, "file://g:h");
    COMBINE("http://a/b/c/d;p?q", "g:h", ICU_ENCODE_SPACES_ONLY, "file://g:h");
    COMBINE("http://a/b/c/d;p?q", "g:h", ICU_BROWSER_MODE, "file://g:h");
    COMBINE("http://a/b/c/d;p?q", "g:h", ICU_ENCODE_PERCENT, "file://g:h");
}
TEST(url_crack_combine_rfc_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g", ICU_NO_META, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
}
TEST(url_crack_combine_rfc_dotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "./g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "./g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "./g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "./g", ICU_NO_META, "http://a/b/c/./g");
    COMBINE("http://a/b/c/d;p?q", "./g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "./g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "./g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
}
TEST(url_crack_combine_rfc_gs) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g/", 0, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "g/", ICU_NO_ENCODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "g/", ICU_DECODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "g/", ICU_NO_META, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "g/", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "g/", ICU_BROWSER_MODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "g/", ICU_ENCODE_PERCENT, "http://a/b/c/g/");
}
TEST(url_crack_combine_rfc_sg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "/g", 0, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "/g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "/g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "/g", ICU_NO_META, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "/g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "/g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "/g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_rfc_ssg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "//g", 0, "http://g/");
    COMBINE("http://a/b/c/d;p?q", "//g", ICU_NO_ENCODE, "http://g/");
    COMBINE("http://a/b/c/d;p?q", "//g", ICU_DECODE, "http://g/");
    COMBINE("http://a/b/c/d;p?q", "//g", ICU_NO_META, "http://g/");
    COMBINE("http://a/b/c/d;p?q", "//g", ICU_ENCODE_SPACES_ONLY, "http://g/");
    COMBINE("http://a/b/c/d;p?q", "//g", ICU_BROWSER_MODE, "http://g/");
    COMBINE("http://a/b/c/d;p?q", "//g", ICU_ENCODE_PERCENT, "http://g/");
}
TEST(url_crack_combine_rfc_qy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "?y", 0, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "?y", ICU_NO_ENCODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "?y", ICU_DECODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "?y", ICU_NO_META, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "?y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "?y", ICU_BROWSER_MODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "?y", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?y");
}
TEST(url_crack_combine_rfc_gqy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?y", 0, "http://a/b/c/g?y");
    COMBINE("http://a/b/c/d;p?q", "g?y", ICU_NO_ENCODE, "http://a/b/c/g?y");
    COMBINE("http://a/b/c/d;p?q", "g?y", ICU_DECODE, "http://a/b/c/g?y");
    COMBINE("http://a/b/c/d;p?q", "g?y", ICU_NO_META, "http://a/b/c/g?y");
    COMBINE("http://a/b/c/d;p?q", "g?y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?y");
    COMBINE("http://a/b/c/d;p?q", "g?y", ICU_BROWSER_MODE, "http://a/b/c/g?y");
    COMBINE("http://a/b/c/d;p?q", "g?y", ICU_ENCODE_PERCENT, "http://a/b/c/g?y");
}
TEST(url_crack_combine_rfc_frags) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "#s", 0, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "#s", ICU_NO_ENCODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "#s", ICU_DECODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "#s", ICU_NO_META, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "#s", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "#s", ICU_BROWSER_MODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "#s", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?q#s");
}
TEST(url_crack_combine_rfc_gfrags) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g#s", 0, "http://a/b/c/g#s");
    COMBINE("http://a/b/c/d;p?q", "g#s", ICU_NO_ENCODE, "http://a/b/c/g#s");
    COMBINE("http://a/b/c/d;p?q", "g#s", ICU_DECODE, "http://a/b/c/g#s");
    COMBINE("http://a/b/c/d;p?q", "g#s", ICU_NO_META, "http://a/b/c/g#s");
    COMBINE("http://a/b/c/d;p?q", "g#s", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g#s");
    COMBINE("http://a/b/c/d;p?q", "g#s", ICU_BROWSER_MODE, "http://a/b/c/g#s");
    COMBINE("http://a/b/c/d;p?q", "g#s", ICU_ENCODE_PERCENT, "http://a/b/c/g#s");
}
TEST(url_crack_combine_rfc_gqyfrags) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?y#s", 0, "http://a/b/c/g?y#s");
    COMBINE("http://a/b/c/d;p?q", "g?y#s", ICU_NO_ENCODE, "http://a/b/c/g?y#s");
    COMBINE("http://a/b/c/d;p?q", "g?y#s", ICU_DECODE, "http://a/b/c/g?y#s");
    COMBINE("http://a/b/c/d;p?q", "g?y#s", ICU_NO_META, "http://a/b/c/g?y#s");
    COMBINE("http://a/b/c/d;p?q", "g?y#s", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?y#s");
    COMBINE("http://a/b/c/d;p?q", "g?y#s", ICU_BROWSER_MODE, "http://a/b/c/g?y#s");
    COMBINE("http://a/b/c/d;p?q", "g?y#s", ICU_ENCODE_PERCENT, "http://a/b/c/g?y#s");
}
TEST(url_crack_combine_rfc_semix) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", ";x", 0, "http://a/b/c/;x");
    COMBINE("http://a/b/c/d;p?q", ";x", ICU_NO_ENCODE, "http://a/b/c/;x");
    COMBINE("http://a/b/c/d;p?q", ";x", ICU_DECODE, "http://a/b/c/;x");
    COMBINE("http://a/b/c/d;p?q", ";x", ICU_NO_META, "http://a/b/c/;x");
    COMBINE("http://a/b/c/d;p?q", ";x", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/;x");
    COMBINE("http://a/b/c/d;p?q", ";x", ICU_BROWSER_MODE, "http://a/b/c/;x");
    COMBINE("http://a/b/c/d;p?q", ";x", ICU_ENCODE_PERCENT, "http://a/b/c/;x");
}
TEST(url_crack_combine_rfc_gsemix) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g;x", 0, "http://a/b/c/g;x");
    COMBINE("http://a/b/c/d;p?q", "g;x", ICU_NO_ENCODE, "http://a/b/c/g;x");
    COMBINE("http://a/b/c/d;p?q", "g;x", ICU_DECODE, "http://a/b/c/g;x");
    COMBINE("http://a/b/c/d;p?q", "g;x", ICU_NO_META, "http://a/b/c/g;x");
    COMBINE("http://a/b/c/d;p?q", "g;x", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g;x");
    COMBINE("http://a/b/c/d;p?q", "g;x", ICU_BROWSER_MODE, "http://a/b/c/g;x");
    COMBINE("http://a/b/c/d;p?q", "g;x", ICU_ENCODE_PERCENT, "http://a/b/c/g;x");
}
TEST(url_crack_combine_rfc_gsemixqyfrags) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", 0, "http://a/b/c/g;x?y#s");
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", ICU_NO_ENCODE, "http://a/b/c/g;x?y#s");
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", ICU_DECODE, "http://a/b/c/g;x?y#s");
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", ICU_NO_META, "http://a/b/c/g;x?y#s");
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g;x?y#s");
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", ICU_BROWSER_MODE, "http://a/b/c/g;x?y#s");
    COMBINE("http://a/b/c/d;p?q", "g;x?y#s", ICU_ENCODE_PERCENT, "http://a/b/c/g;x?y#s");
}
TEST(url_crack_combine_rfc_empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "", 0, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "", ICU_NO_ENCODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "", ICU_DECODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "", ICU_NO_META, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "", ICU_BROWSER_MODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "", ICU_ENCODE_PERCENT, "http://a/b/c/");
}
TEST(url_crack_combine_rfc_dot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", ".", 0, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", ".", ICU_NO_ENCODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", ".", ICU_DECODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", ".", ICU_NO_META, "http://a/b/c/.");
    COMBINE("http://a/b/c/d;p?q", ".", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", ".", ICU_BROWSER_MODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", ".", ICU_ENCODE_PERCENT, "http://a/b/c/");
}
TEST(url_crack_combine_rfc_dots) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "./", 0, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "./", ICU_NO_ENCODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "./", ICU_DECODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "./", ICU_NO_META, "http://a/b/c/./");
    COMBINE("http://a/b/c/d;p?q", "./", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "./", ICU_BROWSER_MODE, "http://a/b/c/");
    COMBINE("http://a/b/c/d;p?q", "./", ICU_ENCODE_PERCENT, "http://a/b/c/");
}
TEST(url_crack_combine_rfc_dotdot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "..", 0, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "..", ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "..", ICU_DECODE, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "..", ICU_NO_META, "http://a/b/c/..");
    COMBINE("http://a/b/c/d;p?q", "..", ICU_ENCODE_SPACES_ONLY, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "..", ICU_BROWSER_MODE, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "..", ICU_ENCODE_PERCENT, "http://a/b/");
}
TEST(url_crack_combine_rfc_dotdots) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../", 0, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "../", ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "../", ICU_DECODE, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "../", ICU_NO_META, "http://a/b/c/../");
    COMBINE("http://a/b/c/d;p?q", "../", ICU_ENCODE_SPACES_ONLY, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "../", ICU_BROWSER_MODE, "http://a/b/");
    COMBINE("http://a/b/c/d;p?q", "../", ICU_ENCODE_PERCENT, "http://a/b/");
}
TEST(url_crack_combine_rfc_dotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../g", 0, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "../g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "../g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "../g", ICU_NO_META, "http://a/b/c/../g");
    COMBINE("http://a/b/c/d;p?q", "../g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "../g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "../g", ICU_ENCODE_PERCENT, "http://a/b/g");
}
TEST(url_crack_combine_rfc_dotdotsdotdot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../..", 0, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../..", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../..", ICU_DECODE, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../..", ICU_NO_META, "http://a/b/c/../..");
    COMBINE("http://a/b/c/d;p?q", "../..", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../..", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../..", ICU_ENCODE_PERCENT, "http://a/");
}
TEST(url_crack_combine_rfc_dotdotsdotdots) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../../", 0, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../../", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../../", ICU_DECODE, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../../", ICU_NO_META, "http://a/b/c/../../");
    COMBINE("http://a/b/c/d;p?q", "../../", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../../", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a/b/c/d;p?q", "../../", ICU_ENCODE_PERCENT, "http://a/");
}
TEST(url_crack_combine_rfc_dotdotsdotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../../g", 0, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../g", ICU_NO_META, "http://a/b/c/../../g");
    COMBINE("http://a/b/c/d;p?q", "../../g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_rfc_dotdotsdotdotsdotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../../../g", 0, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../g", ICU_NO_META, "http://a/b/c/../../../g");
    COMBINE("http://a/b/c/d;p?q", "../../../g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_rfc_dotdotsdotdotsdotdotsdotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "../../../../g", 0, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../../g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../../g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../../g", ICU_NO_META, "http://a/b/c/../../../../g");
    COMBINE("http://a/b/c/d;p?q", "../../../../g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../../g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "../../../../g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_rfc_sdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "/./g", 0, "http://a/./g");
    COMBINE("http://a/b/c/d;p?q", "/./g", ICU_NO_ENCODE, "http://a/./g");
    COMBINE("http://a/b/c/d;p?q", "/./g", ICU_DECODE, "http://a/./g");
    COMBINE("http://a/b/c/d;p?q", "/./g", ICU_NO_META, "http://a/./g");
    COMBINE("http://a/b/c/d;p?q", "/./g", ICU_ENCODE_SPACES_ONLY, "http://a/./g");
    COMBINE("http://a/b/c/d;p?q", "/./g", ICU_BROWSER_MODE, "http://a/./g");
    COMBINE("http://a/b/c/d;p?q", "/./g", ICU_ENCODE_PERCENT, "http://a/./g");
}
TEST(url_crack_combine_rfc_sdotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "/../g", 0, "http://a/../g");
    COMBINE("http://a/b/c/d;p?q", "/../g", ICU_NO_ENCODE, "http://a/../g");
    COMBINE("http://a/b/c/d;p?q", "/../g", ICU_DECODE, "http://a/../g");
    COMBINE("http://a/b/c/d;p?q", "/../g", ICU_NO_META, "http://a/../g");
    COMBINE("http://a/b/c/d;p?q", "/../g", ICU_ENCODE_SPACES_ONLY, "http://a/../g");
    COMBINE("http://a/b/c/d;p?q", "/../g", ICU_BROWSER_MODE, "http://a/../g");
    COMBINE("http://a/b/c/d;p?q", "/../g", ICU_ENCODE_PERCENT, "http://a/../g");
}
TEST(url_crack_combine_rfc_gdot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g.", 0, "http://a/b/c/g.");
    COMBINE("http://a/b/c/d;p?q", "g.", ICU_NO_ENCODE, "http://a/b/c/g.");
    COMBINE("http://a/b/c/d;p?q", "g.", ICU_DECODE, "http://a/b/c/g.");
    COMBINE("http://a/b/c/d;p?q", "g.", ICU_NO_META, "http://a/b/c/g.");
    COMBINE("http://a/b/c/d;p?q", "g.", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g.");
    COMBINE("http://a/b/c/d;p?q", "g.", ICU_BROWSER_MODE, "http://a/b/c/g.");
    COMBINE("http://a/b/c/d;p?q", "g.", ICU_ENCODE_PERCENT, "http://a/b/c/g.");
}
TEST(url_crack_combine_rfc_dotg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", ".g", 0, "http://a/b/c/.g");
    COMBINE("http://a/b/c/d;p?q", ".g", ICU_NO_ENCODE, "http://a/b/c/.g");
    COMBINE("http://a/b/c/d;p?q", ".g", ICU_DECODE, "http://a/b/c/.g");
    COMBINE("http://a/b/c/d;p?q", ".g", ICU_NO_META, "http://a/b/c/.g");
    COMBINE("http://a/b/c/d;p?q", ".g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/.g");
    COMBINE("http://a/b/c/d;p?q", ".g", ICU_BROWSER_MODE, "http://a/b/c/.g");
    COMBINE("http://a/b/c/d;p?q", ".g", ICU_ENCODE_PERCENT, "http://a/b/c/.g");
}
TEST(url_crack_combine_rfc_gdotdot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g..", 0, "http://a/b/c/g..");
    COMBINE("http://a/b/c/d;p?q", "g..", ICU_NO_ENCODE, "http://a/b/c/g..");
    COMBINE("http://a/b/c/d;p?q", "g..", ICU_DECODE, "http://a/b/c/g..");
    COMBINE("http://a/b/c/d;p?q", "g..", ICU_NO_META, "http://a/b/c/g..");
    COMBINE("http://a/b/c/d;p?q", "g..", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g..");
    COMBINE("http://a/b/c/d;p?q", "g..", ICU_BROWSER_MODE, "http://a/b/c/g..");
    COMBINE("http://a/b/c/d;p?q", "g..", ICU_ENCODE_PERCENT, "http://a/b/c/g..");
}
TEST(url_crack_combine_rfc_dotdotg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "..g", 0, "http://a/b/c/..g");
    COMBINE("http://a/b/c/d;p?q", "..g", ICU_NO_ENCODE, "http://a/b/c/..g");
    COMBINE("http://a/b/c/d;p?q", "..g", ICU_DECODE, "http://a/b/c/..g");
    COMBINE("http://a/b/c/d;p?q", "..g", ICU_NO_META, "http://a/b/c/..g");
    COMBINE("http://a/b/c/d;p?q", "..g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/..g");
    COMBINE("http://a/b/c/d;p?q", "..g", ICU_BROWSER_MODE, "http://a/b/c/..g");
    COMBINE("http://a/b/c/d;p?q", "..g", ICU_ENCODE_PERCENT, "http://a/b/c/..g");
}
TEST(url_crack_combine_rfc_dotsdotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "./../g", 0, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "./../g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "./../g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "./../g", ICU_NO_META, "http://a/b/c/./../g");
    COMBINE("http://a/b/c/d;p?q", "./../g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "./../g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "./../g", ICU_ENCODE_PERCENT, "http://a/b/g");
}
TEST(url_crack_combine_rfc_dotsgsdot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "./g/.", 0, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "./g/.", ICU_NO_ENCODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "./g/.", ICU_DECODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "./g/.", ICU_NO_META, "http://a/b/c/./g/.");
    COMBINE("http://a/b/c/d;p?q", "./g/.", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "./g/.", ICU_BROWSER_MODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/d;p?q", "./g/.", ICU_ENCODE_PERCENT, "http://a/b/c/g/");
}
TEST(url_crack_combine_rfc_gsdotsh) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g/./h", 0, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g/./h", ICU_NO_ENCODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g/./h", ICU_DECODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g/./h", ICU_NO_META, "http://a/b/c/g/./h");
    COMBINE("http://a/b/c/d;p?q", "g/./h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g/./h", ICU_BROWSER_MODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g/./h", ICU_ENCODE_PERCENT, "http://a/b/c/g/h");
}
TEST(url_crack_combine_rfc_gsdotdotsh) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g/../h", 0, "http://a/b/c/h");
    COMBINE("http://a/b/c/d;p?q", "g/../h", ICU_NO_ENCODE, "http://a/b/c/h");
    COMBINE("http://a/b/c/d;p?q", "g/../h", ICU_DECODE, "http://a/b/c/h");
    COMBINE("http://a/b/c/d;p?q", "g/../h", ICU_NO_META, "http://a/b/c/g/../h");
    COMBINE("http://a/b/c/d;p?q", "g/../h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/h");
    COMBINE("http://a/b/c/d;p?q", "g/../h", ICU_BROWSER_MODE, "http://a/b/c/h");
    COMBINE("http://a/b/c/d;p?q", "g/../h", ICU_ENCODE_PERCENT, "http://a/b/c/h");
}
TEST(url_crack_combine_rfc_gsemix_1sdotsy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", 0, "http://a/b/c/g;x=1/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", ICU_NO_ENCODE, "http://a/b/c/g;x=1/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", ICU_DECODE, "http://a/b/c/g;x=1/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", ICU_NO_META, "http://a/b/c/g;x=1/./y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g;x=1/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", ICU_BROWSER_MODE, "http://a/b/c/g;x=1/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/./y", ICU_ENCODE_PERCENT, "http://a/b/c/g;x=1/y");
}
TEST(url_crack_combine_rfc_gsemix_1sdotdotsy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", 0, "http://a/b/c/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", ICU_NO_ENCODE, "http://a/b/c/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", ICU_DECODE, "http://a/b/c/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", ICU_NO_META, "http://a/b/c/g;x=1/../y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", ICU_BROWSER_MODE, "http://a/b/c/y");
    COMBINE("http://a/b/c/d;p?q", "g;x=1/../y", ICU_ENCODE_PERCENT, "http://a/b/c/y");
}
TEST(url_crack_combine_rfc_gqysdotsx) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", 0, "http://a/b/c/g?y/./x");
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", ICU_NO_ENCODE, "http://a/b/c/g?y/./x");
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", ICU_DECODE, "http://a/b/c/g?y/./x");
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", ICU_NO_META, "http://a/b/c/g?y/./x");
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?y/./x");
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", ICU_BROWSER_MODE, "http://a/b/c/g?y/./x");
    COMBINE("http://a/b/c/d;p?q", "g?y/./x", ICU_ENCODE_PERCENT, "http://a/b/c/g?y/./x");
}
TEST(url_crack_combine_rfc_gqysdotdotsx) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", 0, "http://a/b/c/g?y/../x");
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", ICU_NO_ENCODE, "http://a/b/c/g?y/../x");
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", ICU_DECODE, "http://a/b/c/g?y/../x");
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", ICU_NO_META, "http://a/b/c/g?y/../x");
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?y/../x");
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", ICU_BROWSER_MODE, "http://a/b/c/g?y/../x");
    COMBINE("http://a/b/c/d;p?q", "g?y/../x", ICU_ENCODE_PERCENT, "http://a/b/c/g?y/../x");
}
TEST(url_crack_combine_rfc_gfragssdotsx) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", 0, "http://a/b/c/g#s/./x");
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", ICU_NO_ENCODE, "http://a/b/c/g#s/./x");
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", ICU_DECODE, "http://a/b/c/g#s/./x");
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", ICU_NO_META, "http://a/b/c/g#s/./x");
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g#s/./x");
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", ICU_BROWSER_MODE, "http://a/b/c/g#s/./x");
    COMBINE("http://a/b/c/d;p?q", "g#s/./x", ICU_ENCODE_PERCENT, "http://a/b/c/g#s/./x");
}
TEST(url_crack_combine_rfc_gfragssdotdotsx) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", 0, "http://a/b/c/g#s/../x");
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", ICU_NO_ENCODE, "http://a/b/c/g#s/../x");
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", ICU_DECODE, "http://a/b/c/g#s/../x");
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", ICU_NO_META, "http://a/b/c/g#s/../x");
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g#s/../x");
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", ICU_BROWSER_MODE, "http://a/b/c/g#s/../x");
    COMBINE("http://a/b/c/d;p?q", "g#s/../x", ICU_ENCODE_PERCENT, "http://a/b/c/g#s/../x");
}
TEST(url_crack_combine_rfc_httpcolong) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "http:g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "http:g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "http:g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "http:g", ICU_NO_META, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "http:g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "http:g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "http:g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
}
TEST(url_crack_combine_rfc_httpscolong) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "https:g", 0, "https:g");
    COMBINE("http://a/b/c/d;p?q", "https:g", ICU_NO_ENCODE, "https:g");
    COMBINE("http://a/b/c/d;p?q", "https:g", ICU_DECODE, "https:g");
    COMBINE("http://a/b/c/d;p?q", "https:g", ICU_NO_META, "https:g");
    COMBINE("http://a/b/c/d;p?q", "https:g", ICU_ENCODE_SPACES_ONLY, "https:g");
    COMBINE("http://a/b/c/d;p?q", "https:g", ICU_BROWSER_MODE, "https:g");
    COMBINE("http://a/b/c/d;p?q", "https:g", ICU_ENCODE_PERCENT, "https:g");
}
TEST(url_crack_combine_rfc_httpcolonssxsy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "http://x/y", 0, "http://x/y");
    COMBINE("http://a/b/c/d;p?q", "http://x/y", ICU_NO_ENCODE, "http://x/y");
    COMBINE("http://a/b/c/d;p?q", "http://x/y", ICU_DECODE, "http://x/y");
    COMBINE("http://a/b/c/d;p?q", "http://x/y", ICU_NO_META, "http://x/y");
    COMBINE("http://a/b/c/d;p?q", "http://x/y", ICU_ENCODE_SPACES_ONLY, "http://x/y");
    COMBINE("http://a/b/c/d;p?q", "http://x/y", ICU_BROWSER_MODE, "http://x/y");
    COMBINE("http://a/b/c/d;p?q", "http://x/y", ICU_ENCODE_PERCENT, "http://x/y");
}
TEST(url_crack_combine_rfc_ftpcolonssxsy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", 0, "ftp://x/y");
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", ICU_NO_ENCODE, "ftp://x/y");
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", ICU_DECODE, "ftp://x/y");
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", ICU_NO_META, "ftp://x/y");
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", ICU_ENCODE_SPACES_ONLY, "ftp://x/y");
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", ICU_BROWSER_MODE, "ftp://x/y");
    COMBINE("http://a/b/c/d;p?q", "ftp://x/y", ICU_ENCODE_PERCENT, "ftp://x/y");
}
TEST(url_crack_combine_rfc_gsph) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g h", 0, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g h", ICU_NO_ENCODE, "http://a/b/c/g h");
    COMBINE("http://a/b/c/d;p?q", "g h", ICU_DECODE, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g h", ICU_NO_META, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g h", ICU_BROWSER_MODE, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g h", ICU_ENCODE_PERCENT, "http://a/b/c/g%20h");
}
TEST(url_crack_combine_rfc_gpct20h) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g%20h", 0, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g%20h", ICU_NO_ENCODE, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g%20h", ICU_DECODE, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g%20h", ICU_NO_META, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g%20h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g%20h", ICU_BROWSER_MODE, "http://a/b/c/g%20h");
    COMBINE("http://a/b/c/d;p?q", "g%20h", ICU_ENCODE_PERCENT, "http://a/b/c/g%2520h");
}
TEST(url_crack_combine_rfc_bsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "\\g", 0, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "\\g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "\\g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "\\g", ICU_NO_META, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "\\g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "\\g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "\\g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_rfc_gbsh) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g\\h", 0, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g\\h", ICU_NO_ENCODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g\\h", ICU_DECODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g\\h", ICU_NO_META, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g\\h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g\\h", ICU_BROWSER_MODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g\\h", ICU_ENCODE_PERCENT, "http://a/b/c/g/h");
}
TEST(url_crack_combine_http_a_b_c_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/", "g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/", "g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/", "g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/", "g", ICU_NO_META, "http://a/b/c/g");
    COMBINE("http://a/b/c/", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/", "g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/", "g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
}
TEST(url_crack_combine_http_a_b_c_g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "g", 0, "http://a/b/g");
    COMBINE("http://a/b/c", "g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g", ICU_NO_META, "http://a/b/g");
    COMBINE("http://a/b/c", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c", "g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g", ICU_ENCODE_PERCENT, "http://a/b/g");
}
TEST(url_crack_combine_http_a_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", "g", 0, "http://a/g");
    COMBINE("http://a", "g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a", "g", ICU_DECODE, "http://a/g");
    COMBINE("http://a", "g", ICU_NO_META, "http://a/g");
    COMBINE("http://a", "g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a", "g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a", "g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_http_a_sg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", "/g", 0, "http://a/g");
    COMBINE("http://a", "/g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a", "/g", ICU_DECODE, "http://a/g");
    COMBINE("http://a", "/g", ICU_NO_META, "http://a/g");
    COMBINE("http://a", "/g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a", "/g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a", "/g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_http_a_dotdotsg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/", "../g", 0, "http://a/g");
    COMBINE("http://a/", "../g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/", "../g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/", "../g", ICU_NO_META, "http://a/../g");
    COMBINE("http://a/", "../g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/", "../g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/", "../g", ICU_ENCODE_PERCENT, "http://a/g");
}
TEST(url_crack_combine_http_a_b_x_y_fragz) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b?x#y", "#z", 0, "http://a/b?x#z");
    COMBINE("http://a/b?x#y", "#z", ICU_NO_ENCODE, "http://a/b?x#z");
    COMBINE("http://a/b?x#y", "#z", ICU_DECODE, "http://a/b?x#z");
    COMBINE("http://a/b?x#y", "#z", ICU_NO_META, "http://a/b?x#z");
    COMBINE("http://a/b?x#y", "#z", ICU_ENCODE_SPACES_ONLY, "http://a/b?x#z");
    COMBINE("http://a/b?x#y", "#z", ICU_BROWSER_MODE, "http://a/b?x#z");
    COMBINE("http://a/b?x#y", "#z", ICU_ENCODE_PERCENT, "http://a/b?x#z");
}
TEST(url_crack_combine_http_a_b_y_qz) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b#y", "?z", 0, "http://a/b#y?z");
    COMBINE("http://a/b#y", "?z", ICU_NO_ENCODE, "http://a/b#y?z");
    COMBINE("http://a/b#y", "?z", ICU_DECODE, "http://a/b?z#y");
    COMBINE("http://a/b#y", "?z", ICU_NO_META, "http://a/b#y?z");
    COMBINE("http://a/b#y", "?z", ICU_ENCODE_SPACES_ONLY, "http://a/b#y?z");
    COMBINE("http://a/b#y", "?z", ICU_BROWSER_MODE, "http://a/b#y?z");
    COMBINE("http://a/b#y", "?z", ICU_ENCODE_PERCENT, "http://a/b#y?z");
}
TEST(url_crack_combine_http_user_pw_a_81_b__d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://user:pw@a:81/b/c", "d", 0, "http://user:pw@a:81/b/d");
    COMBINE("http://user:pw@a:81/b/c", "d", ICU_NO_ENCODE, "http://user:pw@a:81/b/d");
    COMBINE("http://user:pw@a:81/b/c", "d", ICU_DECODE, "http://user:pw@a:81/b/d");
    COMBINE("http://user:pw@a:81/b/c", "d", ICU_NO_META, "http://user:pw@a:81/b/d");
    COMBINE("http://user:pw@a:81/b/c", "d", ICU_ENCODE_SPACES_ONLY, "http://user:pw@a:81/b/d");
    COMBINE("http://user:pw@a:81/b/c", "d", ICU_BROWSER_MODE, "http://user:pw@a:81/b/d");
    COMBINE("http://user:pw@a:81/b/c", "d", ICU_ENCODE_PERCENT, "http://user:pw@a:81/b/d");
}
TEST(url_crack_combine_http_user_pw_a_81_b__ssesf) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://user:pw@a:81/b/c", "//e/f", 0, "http://e/f");
    COMBINE("http://user:pw@a:81/b/c", "//e/f", ICU_NO_ENCODE, "http://e/f");
    COMBINE("http://user:pw@a:81/b/c", "//e/f", ICU_DECODE, "http://e/f");
    COMBINE("http://user:pw@a:81/b/c", "//e/f", ICU_NO_META, "http://e/f");
    COMBINE("http://user:pw@a:81/b/c", "//e/f", ICU_ENCODE_SPACES_ONLY, "http://e/f");
    COMBINE("http://user:pw@a:81/b/c", "//e/f", ICU_BROWSER_MODE, "http://e/f");
    COMBINE("http://user:pw@a:81/b/c", "//e/f", ICU_ENCODE_PERCENT, "http://e/f");
}
TEST(url_crack_combine_https_a_b_ssesf) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("https://a/b", "//e/f", 0, "https://e/f");
    COMBINE("https://a/b", "//e/f", ICU_NO_ENCODE, "https://e/f");
    COMBINE("https://a/b", "//e/f", ICU_DECODE, "https://e/f");
    COMBINE("https://a/b", "//e/f", ICU_NO_META, "https://e/f");
    COMBINE("https://a/b", "//e/f", ICU_ENCODE_SPACES_ONLY, "https://e/f");
    COMBINE("https://a/b", "//e/f", ICU_BROWSER_MODE, "https://e/f");
    COMBINE("https://a/b", "//e/f", ICU_ENCODE_PERCENT, "https://e/f");
}
TEST(url_crack_combine_ftp_a_b_c_d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("ftp://a/b/c", "d", 0, "ftp://a/b/d");
    COMBINE("ftp://a/b/c", "d", ICU_NO_ENCODE, "ftp://a/b/d");
    COMBINE("ftp://a/b/c", "d", ICU_DECODE, "ftp://a/b/d");
    COMBINE("ftp://a/b/c", "d", ICU_NO_META, "ftp://a/b/d");
    COMBINE("ftp://a/b/c", "d", ICU_ENCODE_SPACES_ONLY, "ftp://a/b/d");
    COMBINE("ftp://a/b/c", "d", ICU_BROWSER_MODE, "ftp://a/b/d");
    COMBINE("ftp://a/b/c", "d", ICU_ENCODE_PERCENT, "ftp://a/b/d");
}
TEST(url_crack_combine_ftp_a_b_c_dotdotsd) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("ftp://a/b/c", "../d", 0, "ftp://a/d");
    COMBINE("ftp://a/b/c", "../d", ICU_NO_ENCODE, "ftp://a/d");
    COMBINE("ftp://a/b/c", "../d", ICU_DECODE, "ftp://a/d");
    COMBINE("ftp://a/b/c", "../d", ICU_NO_META, "ftp://a/b/../d");
    COMBINE("ftp://a/b/c", "../d", ICU_ENCODE_SPACES_ONLY, "ftp://a/d");
    COMBINE("ftp://a/b/c", "../d", ICU_BROWSER_MODE, "ftp://a/d");
    COMBINE("ftp://a/b/c", "../d", ICU_ENCODE_PERCENT, "ftp://a/d");
}
TEST(url_crack_combine_file_c_a_b_txt_cdottxt) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b.txt", "c.txt", 0, "file://C:\\a\\c.txt");
    COMBINE("file:///C:/a/b.txt", "c.txt", ICU_NO_ENCODE, "file://C:\\a\\c.txt");
    COMBINE("file:///C:/a/b.txt", "c.txt", ICU_DECODE, "file://C:\\a\\c.txt");
    COMBINE("file:///C:/a/b.txt", "c.txt", ICU_NO_META, "file://C:\\a\\c.txt");
    COMBINE("file:///C:/a/b.txt", "c.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\c.txt");
    COMBINE("file:///C:/a/b.txt", "c.txt", ICU_BROWSER_MODE, "file://C:\\a\\c.txt");
    COMBINE("file:///C:/a/b.txt", "c.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\c.txt");
}
TEST(url_crack_combine_file_c_a_b_txt_dotdotscdottxt) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b.txt", "../c.txt", 0, "file://C:\\c.txt");
    COMBINE("file:///C:/a/b.txt", "../c.txt", ICU_NO_ENCODE, "file://C:\\c.txt");
    COMBINE("file:///C:/a/b.txt", "../c.txt", ICU_DECODE, "file://C:\\c.txt");
    COMBINE("file:///C:/a/b.txt", "../c.txt", ICU_NO_META, "file://C:\\a\\..\\c.txt");
    COMBINE("file:///C:/a/b.txt", "../c.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\c.txt");
    COMBINE("file:///C:/a/b.txt", "../c.txt", ICU_BROWSER_MODE, "file://C:\\c.txt");
    COMBINE("file:///C:/a/b.txt", "../c.txt", ICU_ENCODE_PERCENT, "file://C:\\c.txt");
}
TEST(url_crack_combine_file_c_a_b_txt_sddottxt) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b.txt", "/d.txt", 0, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b.txt", "/d.txt", ICU_NO_ENCODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b.txt", "/d.txt", ICU_DECODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b.txt", "/d.txt", ICU_NO_META, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b.txt", "/d.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b.txt", "/d.txt", ICU_BROWSER_MODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b.txt", "/d.txt", ICU_ENCODE_PERCENT, "file://C:\\d.txt");
}
TEST(url_crack_combine_file_c_a_b_txt_cdottxt_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file://C:/a/b.txt", "c.txt", 0, "file://C:\\a\\c.txt");
    COMBINE("file://C:/a/b.txt", "c.txt", ICU_NO_ENCODE, "file://C:\\a\\c.txt");
    COMBINE("file://C:/a/b.txt", "c.txt", ICU_DECODE, "file://C:\\a\\c.txt");
    COMBINE("file://C:/a/b.txt", "c.txt", ICU_NO_META, "file://C:\\a\\c.txt");
    COMBINE("file://C:/a/b.txt", "c.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\c.txt");
    COMBINE("file://C:/a/b.txt", "c.txt", ICU_BROWSER_MODE, "file://C:\\a\\c.txt");
    COMBINE("file://C:/a/b.txt", "c.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\c.txt");
}
TEST(url_crack_combine_mailto_a_b_c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("mailto:a@b", "c", 0, "mailto:a@bc");
    COMBINE("mailto:a@b", "c", ICU_NO_ENCODE, "mailto:a@bc");
    COMBINE("mailto:a@b", "c", ICU_DECODE, "mailto:a@bc");
    COMBINE("mailto:a@b", "c", ICU_NO_META, "mailto:a@bc");
    COMBINE("mailto:a@b", "c", ICU_ENCODE_SPACES_ONLY, "mailto:a@bc");
    COMBINE("mailto:a@b", "c", ICU_BROWSER_MODE, "mailto:a@bc");
    COMBINE("mailto:a@b", "c", ICU_ENCODE_PERCENT, "mailto:a@bc");
}
TEST(url_crack_combine_about_blank_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("about:blank", "x", 0, "about:blankx");
    COMBINE("about:blank", "x", ICU_NO_ENCODE, "about:blankx");
    COMBINE("about:blank", "x", ICU_DECODE, "about:blankx");
    COMBINE("about:blank", "x", ICU_NO_META, "about:blankx");
    COMBINE("about:blank", "x", ICU_ENCODE_SPACES_ONLY, "about:blankx");
    COMBINE("about:blank", "x", ICU_BROWSER_MODE, "about:blankx");
    COMBINE("about:blank", "x", ICU_ENCODE_PERCENT, "about:blankx");
}
TEST(url_crack_combine_foo_a_b_c_d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("foo://a/b/c", "d", 0, "foo://a/b/d");
    COMBINE("foo://a/b/c", "d", ICU_NO_ENCODE, "foo://a/b/d");
    COMBINE("foo://a/b/c", "d", ICU_DECODE, "foo://a/b/d");
    COMBINE("foo://a/b/c", "d", ICU_NO_META, "foo://a/b/d");
    COMBINE("foo://a/b/c", "d", ICU_ENCODE_SPACES_ONLY, "foo://a/b/d");
    COMBINE("foo://a/b/c", "d", ICU_BROWSER_MODE, "foo://a/b/d");
    COMBINE("foo://a/b/c", "d", ICU_ENCODE_PERCENT, "foo://a/b/d");
}
TEST(url_crack_combine_foo_bar_baz) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("foo:bar", "baz", 0, "foo:baz");
    COMBINE("foo:bar", "baz", ICU_NO_ENCODE, "foo:baz");
    COMBINE("foo:bar", "baz", ICU_DECODE, "foo:baz");
    COMBINE("foo:bar", "baz", ICU_NO_META, "foo:baz");
    COMBINE("foo:bar", "baz", ICU_ENCODE_SPACES_ONLY, "foo:baz");
    COMBINE("foo:bar", "baz", ICU_BROWSER_MODE, "foo:baz");
    COMBINE("foo:bar", "baz", ICU_ENCODE_PERCENT, "foo:baz");
}
TEST(url_crack_combine_http_a_b_c_foocolonbar) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "foo:bar", 0, "foo:bar");
    COMBINE("http://a/b/c", "foo:bar", ICU_NO_ENCODE, "foo:bar");
    COMBINE("http://a/b/c", "foo:bar", ICU_DECODE, "foo:bar");
    COMBINE("http://a/b/c", "foo:bar", ICU_NO_META, "foo:bar");
    COMBINE("http://a/b/c", "foo:bar", ICU_ENCODE_SPACES_ONLY, "foo:bar");
    COMBINE("http://a/b/c", "foo:bar", ICU_BROWSER_MODE, "foo:bar");
    COMBINE("http://a/b/c", "foo:bar", ICU_ENCODE_PERCENT, "foo:bar");
}
TEST(url_crack_combine_http_a_b_c_mailtocolonx_y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "mailto:x@y", 0, "mailto:x@y");
    COMBINE("http://a/b/c", "mailto:x@y", ICU_NO_ENCODE, "mailto:x@y");
    COMBINE("http://a/b/c", "mailto:x@y", ICU_DECODE, "mailto:x@y");
    COMBINE("http://a/b/c", "mailto:x@y", ICU_NO_META, "mailto:x@y");
    COMBINE("http://a/b/c", "mailto:x@y", ICU_ENCODE_SPACES_ONLY, "mailto:x@y");
    COMBINE("http://a/b/c", "mailto:x@y", ICU_BROWSER_MODE, "mailto:x@y");
    COMBINE("http://a/b/c", "mailto:x@y", ICU_ENCODE_PERCENT, "mailto:x@y");
}
TEST(url_crack_combine_http_a_b_c_javascriptcolonx) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "javascript:x", 0, "javascript:x");
    COMBINE("http://a/b/c", "javascript:x", ICU_NO_ENCODE, "javascript:x");
    COMBINE("http://a/b/c", "javascript:x", ICU_DECODE, "javascript:x");
    COMBINE("http://a/b/c", "javascript:x", ICU_NO_META, "javascript:x");
    COMBINE("http://a/b/c", "javascript:x", ICU_ENCODE_SPACES_ONLY, "javascript:x");
    COMBINE("http://a/b/c", "javascript:x", ICU_BROWSER_MODE, "javascript:x");
    COMBINE("http://a/b/c", "javascript:x", ICU_ENCODE_PERCENT, "javascript:x");
}
TEST(url_crack_combine_emptybase_httpcolonssxsy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("", "http://x/y", 0, "http://x/y");
    COMBINE("", "http://x/y", ICU_NO_ENCODE, "http://x/y");
    COMBINE("", "http://x/y", ICU_DECODE, "http://x/y");
    COMBINE("", "http://x/y", ICU_NO_META, "http://x/y");
    COMBINE("", "http://x/y", ICU_ENCODE_SPACES_ONLY, "http://x/y");
    COMBINE("", "http://x/y", ICU_BROWSER_MODE, "http://x/y");
    COMBINE("", "http://x/y", ICU_ENCODE_PERCENT, "http://x/y");
}
TEST(url_crack_combine_emptybase_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("", "g", 0, "g");
    COMBINE("", "g", ICU_NO_ENCODE, "g");
    COMBINE("", "g", ICU_DECODE, "g");
    COMBINE("", "g", ICU_NO_META, "g");
    COMBINE("", "g", ICU_ENCODE_SPACES_ONLY, "g");
    COMBINE("", "g", ICU_BROWSER_MODE, "g");
    COMBINE("", "g", ICU_ENCODE_PERCENT, "g");
}
TEST(url_crack_combine_g_h) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("g", "h", 0, "h");
    COMBINE("g", "h", ICU_NO_ENCODE, "h");
    COMBINE("g", "h", ICU_DECODE, "h");
    COMBINE("g", "h", ICU_NO_META, "h");
    COMBINE("g", "h", ICU_ENCODE_SPACES_ONLY, "h");
    COMBINE("g", "h", ICU_BROWSER_MODE, "h");
    COMBINE("g", "h", ICU_ENCODE_PERCENT, "h");
}
TEST(url_crack_combine_http_a_b_c_spspg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "  g", 0, "http://a/b/g");
    COMBINE("http://a/b/c", "  g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c", "  g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c", "  g", ICU_NO_META, "http://a/b/g");
    COMBINE("http://a/b/c", "  g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c", "  g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c", "  g", ICU_ENCODE_PERCENT, "http://a/b/g");
}
TEST(url_crack_combine_http_a_b_c_gspsp) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "g  ", 0, "http://a/b/g");
    COMBINE("http://a/b/c", "g  ", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g  ", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g  ", ICU_NO_META, "http://a/b/g");
    COMBINE("http://a/b/c", "g  ", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c", "g  ", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g  ", ICU_ENCODE_PERCENT, "http://a/b/g");
}
TEST(url_crack_combine_http_a_b_c_httpcolonssxsy) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "HTTP://X/Y", 0, "http://x/Y");
    COMBINE("http://a/b/c", "HTTP://X/Y", ICU_NO_ENCODE, "http://x/Y");
    COMBINE("http://a/b/c", "HTTP://X/Y", ICU_DECODE, "http://x/Y");
    COMBINE("http://a/b/c", "HTTP://X/Y", ICU_NO_META, "http://x/Y");
    COMBINE("http://a/b/c", "HTTP://X/Y", ICU_ENCODE_SPACES_ONLY, "http://x/Y");
    COMBINE("http://a/b/c", "HTTP://X/Y", ICU_BROWSER_MODE, "http://x/Y");
    COMBINE("http://a/b/c", "HTTP://X/Y", ICU_ENCODE_PERCENT, "http://x/Y");
}
TEST(url_crack_combine_http_a_b_c_d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("HTTP://A/B/C", "d", 0, "http://a/B/d");
    COMBINE("HTTP://A/B/C", "d", ICU_NO_ENCODE, "http://a/B/d");
    COMBINE("HTTP://A/B/C", "d", ICU_DECODE, "http://a/B/d");
    COMBINE("HTTP://A/B/C", "d", ICU_NO_META, "http://a/B/d");
    COMBINE("HTTP://A/B/C", "d", ICU_ENCODE_SPACES_ONLY, "http://a/B/d");
    COMBINE("HTTP://A/B/C", "d", ICU_BROWSER_MODE, "http://a/B/d");
    COMBINE("HTTP://A/B/C", "d", ICU_ENCODE_PERCENT, "http://a/B/d");
}
TEST(url_crack_combine_http_a_b_c_q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "?", 0, "http://a/b/c?");
    COMBINE("http://a/b/c", "?", ICU_NO_ENCODE, "http://a/b/c?");
    COMBINE("http://a/b/c", "?", ICU_DECODE, "http://a/b/c?");
    COMBINE("http://a/b/c", "?", ICU_NO_META, "http://a/b/c?");
    COMBINE("http://a/b/c", "?", ICU_ENCODE_SPACES_ONLY, "http://a/b/c?");
    COMBINE("http://a/b/c", "?", ICU_BROWSER_MODE, "http://a/b/c?");
    COMBINE("http://a/b/c", "?", ICU_ENCODE_PERCENT, "http://a/b/c?");
}
TEST(url_crack_combine_http_a_b_c_frag) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "#", 0, "http://a/b/c#");
    COMBINE("http://a/b/c", "#", ICU_NO_ENCODE, "http://a/b/c#");
    COMBINE("http://a/b/c", "#", ICU_DECODE, "http://a/b/c#");
    COMBINE("http://a/b/c", "#", ICU_NO_META, "http://a/b/c#");
    COMBINE("http://a/b/c", "#", ICU_ENCODE_SPACES_ONLY, "http://a/b/c#");
    COMBINE("http://a/b/c", "#", ICU_BROWSER_MODE, "http://a/b/c#");
    COMBINE("http://a/b/c", "#", ICU_ENCODE_PERCENT, "http://a/b/c#");
}
TEST(url_crack_combine_http_a_b_c_q_q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c?q", "?", 0, "http://a/b/c?");
    COMBINE("http://a/b/c?q", "?", ICU_NO_ENCODE, "http://a/b/c?");
    COMBINE("http://a/b/c?q", "?", ICU_DECODE, "http://a/b/c?");
    COMBINE("http://a/b/c?q", "?", ICU_NO_META, "http://a/b/c?");
    COMBINE("http://a/b/c?q", "?", ICU_ENCODE_SPACES_ONLY, "http://a/b/c?");
    COMBINE("http://a/b/c?q", "?", ICU_BROWSER_MODE, "http://a/b/c?");
    COMBINE("http://a/b/c?q", "?", ICU_ENCODE_PERCENT, "http://a/b/c?");
}
TEST(url_crack_combine_http_a_b_c_f_empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c#f", "", 0, "http://a/b/");
    COMBINE("http://a/b/c#f", "", ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c#f", "", ICU_DECODE, "http://a/b/");
    COMBINE("http://a/b/c#f", "", ICU_NO_META, "http://a/b/");
    COMBINE("http://a/b/c#f", "", ICU_ENCODE_SPACES_ONLY, "http://a/b/");
    COMBINE("http://a/b/c#f", "", ICU_BROWSER_MODE, "http://a/b/");
    COMBINE("http://a/b/c#f", "", ICU_ENCODE_PERCENT, "http://a/b/");
}
TEST(url_crack_combine_http_a_b_c_dotdotdot) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "...", 0, "http://a/b/...");
    COMBINE("http://a/b/c", "...", ICU_NO_ENCODE, "http://a/b/...");
    COMBINE("http://a/b/c", "...", ICU_DECODE, "http://a/b/...");
    COMBINE("http://a/b/c", "...", ICU_NO_META, "http://a/b/...");
    COMBINE("http://a/b/c", "...", ICU_ENCODE_SPACES_ONLY, "http://a/b/...");
    COMBINE("http://a/b/c", "...", ICU_BROWSER_MODE, "http://a/b/...");
    COMBINE("http://a/b/c", "...", ICU_ENCODE_PERCENT, "http://a/b/...");
}
TEST(url_crack_combine_http_a_b_c_pct2epct2esg) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "%2e%2e/g", 0, "http://a/b/%2e%2e/g");
    COMBINE("http://a/b/c", "%2e%2e/g", ICU_NO_ENCODE, "http://a/b/%2e%2e/g");
    COMBINE("http://a/b/c", "%2e%2e/g", ICU_DECODE, "http://a/b/../g");
    COMBINE("http://a/b/c", "%2e%2e/g", ICU_NO_META, "http://a/b/%2e%2e/g");
    COMBINE("http://a/b/c", "%2e%2e/g", ICU_ENCODE_SPACES_ONLY, "http://a/b/%2e%2e/g");
    COMBINE("http://a/b/c", "%2e%2e/g", ICU_BROWSER_MODE, "http://a/b/%2e%2e/g");
    COMBINE("http://a/b/c", "%2e%2e/g", ICU_ENCODE_PERCENT, "http://a/b/%252e%252e/g");
}
TEST(url_crack_combine_http_a_b_c_gpct) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "g%", 0, "http://a/b/g%");
    COMBINE("http://a/b/c", "g%", ICU_NO_ENCODE, "http://a/b/g%");
    COMBINE("http://a/b/c", "g%", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c", "g%", ICU_NO_META, "http://a/b/g%");
    COMBINE("http://a/b/c", "g%", ICU_ENCODE_SPACES_ONLY, "http://a/b/g%");
    COMBINE("http://a/b/c", "g%", ICU_BROWSER_MODE, "http://a/b/g%");
    COMBINE("http://a/b/c", "g%", ICU_ENCODE_PERCENT, "http://a/b/g%25");
}
TEST(url_crack_combine_http_a_b_c_empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c", "\xc3\xa9", 0, "http://a/b/%C3%A9");
    COMBINE("http://a/b/c", "\xc3\xa9", ICU_NO_ENCODE, "http://a/b/\xc3\xa9");
    COMBINE("http://a/b/c", "\xc3\xa9", ICU_DECODE, "http://a/b/%C3%A9");
    COMBINE("http://a/b/c", "\xc3\xa9", ICU_NO_META, "http://a/b/%C3%A9");
    COMBINE("http://a/b/c", "\xc3\xa9", ICU_ENCODE_SPACES_ONLY, "http://a/b/\xc3\xa9");
    COMBINE("http://a/b/c", "\xc3\xa9", ICU_BROWSER_MODE, "http://a/b/%C3%A9");
    COMBINE("http://a/b/c", "\xc3\xa9", ICU_ENCODE_PERCENT, "http://a/b/%C3%A9");
}
