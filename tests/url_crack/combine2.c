/* url_crack (widening pass 2): InternetCombineUrlA/W, more (base, relative) pairs with 9 flag combinations each
 * (bases with query/fragment/userinfo/port/IPv6, backslashes, control characters, scheme-relative forms,
 * file: and opaque bases)
 * Generated from the Win10 22H2 VM probe dump (boot ucprobe3-20261110-054841) by a throw-away generator; every row was observed on
 * genuine Windows 10 (wininet 11.0.19041.2193) and cross-read against the decomp named in EVIDENCE.md.
 * VM_TIMEOUT: 120 */
#include "uc.h"

TEST(url_crack_combine2_http_a_b_c__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/", "../g", 0, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_NO_META, "http://a/b/c/../g");
    COMBINE("http://a/b/c/", "../g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_ENCODE_PERCENT, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c/", "../g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/../g");
}
TEST(url_crack_combine2_http_a_b_c__g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/", "g/", 0, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_NO_ENCODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_DECODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_NO_META, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_BROWSER_MODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_ENCODE_PERCENT, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g/");
    COMBINE("http://a/b/c/", "g/", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g/");
}
TEST(url_crack_combine2_http_a_b_c__empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/", "./", 0, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_NO_ENCODE, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_DECODE, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_NO_META, "http://a/b/c/./");
    COMBINE("http://a/b/c/", "./", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_BROWSER_MODE, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_ENCODE_PERCENT, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/");
    COMBINE("http://a/b/c/", "./", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/./");
}
TEST(url_crack_combine2_http_a_b_c__empty_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/", "..", 0, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_DECODE, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_NO_META, "http://a/b/c/..");
    COMBINE("http://a/b/c/", "..", ICU_ENCODE_SPACES_ONLY, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_BROWSER_MODE, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_ENCODE_PERCENT, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c/", "..", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/..");
}
TEST(url_crack_combine2_http_a_b_c_x__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c?x", "g", 0, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_NO_META, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_ENCODE_PERCENT, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c?x", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/g");
}
TEST(url_crack_combine2_http_a_b_c_x__y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c?x", "?y", 0, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_NO_ENCODE, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_DECODE, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_NO_META, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_BROWSER_MODE, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_ENCODE_PERCENT, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c?y");
    COMBINE("http://a/b/c?x", "?y", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c?y");
}
TEST(url_crack_combine2_http_a_b_c_x__f) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c?x", "#f", 0, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_NO_ENCODE, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_DECODE, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_NO_META, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_ENCODE_SPACES_ONLY, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_BROWSER_MODE, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_ENCODE_PERCENT, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c?x#f");
    COMBINE("http://a/b/c?x", "#f", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c?x#f");
}
TEST(url_crack_combine2_http_a_b_c_x__empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c?x", "", 0, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_DECODE, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_NO_META, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_ENCODE_SPACES_ONLY, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_BROWSER_MODE, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_ENCODE_PERCENT, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/");
    COMBINE("http://a/b/c?x", "", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/");
}
TEST(url_crack_combine2_http_a_b_c_f__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c#f", "g", 0, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_NO_META, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_ENCODE_PERCENT, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c#f", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/g");
}
TEST(url_crack_combine2_http_a_b_c_f__g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c#f", "#g", 0, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_NO_ENCODE, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_DECODE, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_NO_META, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_BROWSER_MODE, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_ENCODE_PERCENT, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c#g");
    COMBINE("http://a/b/c#f", "#g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c#g");
}
TEST(url_crack_combine2_http_a_b_c_f__y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c#f", "?y", 0, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_NO_ENCODE, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_DECODE, "http://a/b/c?y#f");
    COMBINE("http://a/b/c#f", "?y", ICU_NO_META, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_BROWSER_MODE, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_ENCODE_PERCENT, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c#f?y");
    COMBINE("http://a/b/c#f", "?y", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c#f?y");
}
TEST(url_crack_combine2_http_a__q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", "?q", 0, "http://a/?q");
    COMBINE("http://a", "?q", ICU_NO_ENCODE, "http://a/?q");
    COMBINE("http://a", "?q", ICU_DECODE, "http://a/?q");
    COMBINE("http://a", "?q", ICU_NO_META, "http://a/?q");
    COMBINE("http://a", "?q", ICU_ENCODE_SPACES_ONLY, "http://a/?q");
    COMBINE("http://a", "?q", ICU_BROWSER_MODE, "http://a/?q");
    COMBINE("http://a", "?q", ICU_ENCODE_PERCENT, "http://a/?q");
    COMBINE("http://a", "?q", ICU_DECODE | ICU_NO_ENCODE, "http://a/?q");
    COMBINE("http://a", "?q", ICU_NO_META | ICU_NO_ENCODE, "http://a/?q");
}
TEST(url_crack_combine2_http_a__f) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", "#f", 0, "http://a/#f");
    COMBINE("http://a", "#f", ICU_NO_ENCODE, "http://a/#f");
    COMBINE("http://a", "#f", ICU_DECODE, "http://a/#f");
    COMBINE("http://a", "#f", ICU_NO_META, "http://a/#f");
    COMBINE("http://a", "#f", ICU_ENCODE_SPACES_ONLY, "http://a/#f");
    COMBINE("http://a", "#f", ICU_BROWSER_MODE, "http://a/#f");
    COMBINE("http://a", "#f", ICU_ENCODE_PERCENT, "http://a/#f");
    COMBINE("http://a", "#f", ICU_DECODE | ICU_NO_ENCODE, "http://a/#f");
    COMBINE("http://a", "#f", ICU_NO_META | ICU_NO_ENCODE, "http://a/#f");
}
TEST(url_crack_combine2_http_a__empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", "", 0, "http://a/");
    COMBINE("http://a", "", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a", "", ICU_DECODE, "http://a/");
    COMBINE("http://a", "", ICU_NO_META, "http://a/");
    COMBINE("http://a", "", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a", "", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a", "", ICU_ENCODE_PERCENT, "http://a/");
    COMBINE("http://a", "", ICU_DECODE | ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a", "", ICU_NO_META | ICU_NO_ENCODE, "http://a/");
}
TEST(url_crack_combine2_http_a__empty_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", ".", 0, "http://a/");
    COMBINE("http://a", ".", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a", ".", ICU_DECODE, "http://a/");
    COMBINE("http://a", ".", ICU_NO_META, "http://a/.");
    COMBINE("http://a", ".", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a", ".", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a", ".", ICU_ENCODE_PERCENT, "http://a/");
    COMBINE("http://a", ".", ICU_DECODE | ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a", ".", ICU_NO_META | ICU_NO_ENCODE, "http://a/.");
}
TEST(url_crack_combine2_http_a__empty_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a", "..", 0, "http://a/");
    COMBINE("http://a", "..", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a", "..", ICU_DECODE, "http://a/");
    COMBINE("http://a", "..", ICU_NO_META, "http://a/..");
    COMBINE("http://a", "..", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a", "..", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a", "..", ICU_ENCODE_PERCENT, "http://a/");
    COMBINE("http://a", "..", ICU_DECODE | ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a", "..", ICU_NO_META | ICU_NO_ENCODE, "http://a/..");
}
TEST(url_crack_combine2_http_a__empty_4) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/", "", 0, "http://a/");
    COMBINE("http://a/", "", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a/", "", ICU_DECODE, "http://a/");
    COMBINE("http://a/", "", ICU_NO_META, "http://a/");
    COMBINE("http://a/", "", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a/", "", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a/", "", ICU_ENCODE_PERCENT, "http://a/");
    COMBINE("http://a/", "", ICU_DECODE | ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a/", "", ICU_NO_META | ICU_NO_ENCODE, "http://a/");
}
TEST(url_crack_combine2_http_a__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/", "g", 0, "http://a/g");
    COMBINE("http://a/", "g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/", "g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/", "g", ICU_NO_META, "http://a/g");
    COMBINE("http://a/", "g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/", "g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/", "g", ICU_ENCODE_PERCENT, "http://a/g");
    COMBINE("http://a/", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/g");
}
TEST(url_crack_combine2_http_a__empty_5) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/", "/", 0, "http://a/");
    COMBINE("http://a/", "/", ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a/", "/", ICU_DECODE, "http://a/");
    COMBINE("http://a/", "/", ICU_NO_META, "http://a/");
    COMBINE("http://a/", "/", ICU_ENCODE_SPACES_ONLY, "http://a/");
    COMBINE("http://a/", "/", ICU_BROWSER_MODE, "http://a/");
    COMBINE("http://a/", "/", ICU_ENCODE_PERCENT, "http://a/");
    COMBINE("http://a/", "/", ICU_DECODE | ICU_NO_ENCODE, "http://a/");
    COMBINE("http://a/", "/", ICU_NO_META | ICU_NO_ENCODE, "http://a/");
}
TEST(url_crack_combine2_http_a__b) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/", "//b", 0, "http://b/");
    COMBINE("http://a/", "//b", ICU_NO_ENCODE, "http://b/");
    COMBINE("http://a/", "//b", ICU_DECODE, "http://b/");
    COMBINE("http://a/", "//b", ICU_NO_META, "http://b/");
    COMBINE("http://a/", "//b", ICU_ENCODE_SPACES_ONLY, "http://b/");
    COMBINE("http://a/", "//b", ICU_BROWSER_MODE, "http://b/");
    COMBINE("http://a/", "//b", ICU_ENCODE_PERCENT, "http://b/");
    COMBINE("http://a/", "//b", ICU_DECODE | ICU_NO_ENCODE, "http://b/");
    COMBINE("http://a/", "//b", ICU_NO_META | ICU_NO_ENCODE, "http://b/");
}
TEST(url_crack_combine2_http_a__b_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/", "///b", 0, "http:///b");
    COMBINE("http://a/", "///b", ICU_NO_ENCODE, "http:///b");
    COMBINE("http://a/", "///b", ICU_DECODE, "http:///b");
    COMBINE("http://a/", "///b", ICU_NO_META, "http:///b");
    COMBINE("http://a/", "///b", ICU_ENCODE_SPACES_ONLY, "http:///b");
    COMBINE("http://a/", "///b", ICU_BROWSER_MODE, "http:///b");
    COMBINE("http://a/", "///b", ICU_ENCODE_PERCENT, "http:///b");
    COMBINE("http://a/", "///b", ICU_DECODE | ICU_NO_ENCODE, "http:///b");
    COMBINE("http://a/", "///b", ICU_NO_META | ICU_NO_ENCODE, "http:///b");
}
TEST(url_crack_combine2_http_u_p_a_81_b_c__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://u:p@a:81/b/c", "/g", 0, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_NO_ENCODE, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_DECODE, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_NO_META, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_ENCODE_SPACES_ONLY, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_BROWSER_MODE, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_ENCODE_PERCENT, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_DECODE | ICU_NO_ENCODE, "http://u:p@a:81/g");
    COMBINE("http://u:p@a:81/b/c", "/g", ICU_NO_META | ICU_NO_ENCODE, "http://u:p@a:81/g");
}
TEST(url_crack_combine2_http_u_p_a_81_b_c__q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://u:p@a:81/b/c", "?q", 0, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_NO_ENCODE, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_DECODE, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_NO_META, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_ENCODE_SPACES_ONLY, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_BROWSER_MODE, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_ENCODE_PERCENT, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_DECODE | ICU_NO_ENCODE, "http://u:p@a:81/b/c?q");
    COMBINE("http://u:p@a:81/b/c", "?q", ICU_NO_META | ICU_NO_ENCODE, "http://u:p@a:81/b/c?q");
}
TEST(url_crack_combine2_http_u_p_a_81_b_c__x_y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://u:p@a:81/b/c", "//x/y", 0, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_NO_ENCODE, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_DECODE, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_NO_META, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_ENCODE_SPACES_ONLY, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_BROWSER_MODE, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_ENCODE_PERCENT, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_DECODE | ICU_NO_ENCODE, "http://x/y");
    COMBINE("http://u:p@a:81/b/c", "//x/y", ICU_NO_META | ICU_NO_ENCODE, "http://x/y");
}
TEST(url_crack_combine2_http_a_80_b_c__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a:80/b/c", "g", 0, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_NO_META, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_ENCODE_PERCENT, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a:80/b/c", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/g");
}
TEST(url_crack_combine2_https_a_443_b_c__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("https://a:443/b/c", "g", 0, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_NO_ENCODE, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_DECODE, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_NO_META, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_ENCODE_SPACES_ONLY, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_BROWSER_MODE, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_ENCODE_PERCENT, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_DECODE | ICU_NO_ENCODE, "https://a/b/g");
    COMBINE("https://a:443/b/c", "g", ICU_NO_META | ICU_NO_ENCODE, "https://a/b/g");
}
TEST(url_crack_combine2_https_a_b_c__http_x_y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("https://a/b/c", "http://x/y", 0, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_NO_ENCODE, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_DECODE, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_NO_META, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_ENCODE_SPACES_ONLY, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_BROWSER_MODE, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_ENCODE_PERCENT, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_DECODE | ICU_NO_ENCODE, "http://x/y");
    COMBINE("https://a/b/c", "http://x/y", ICU_NO_META | ICU_NO_ENCODE, "http://x/y");
}
TEST(url_crack_combine2_https_a_b_c__x_81_y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("https://a/b/c", "//x:81/y", 0, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_NO_ENCODE, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_DECODE, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_NO_META, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_ENCODE_SPACES_ONLY, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_BROWSER_MODE, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_ENCODE_PERCENT, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_DECODE | ICU_NO_ENCODE, "https://x:81/y");
    COMBINE("https://a/b/c", "//x:81/y", ICU_NO_META | ICU_NO_ENCODE, "https://x:81/y");
}
TEST(url_crack_combine2_ftp_a_b_c__x_y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("ftp://a/b/c", "//x/y", 0, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_NO_ENCODE, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_DECODE, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_NO_META, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_ENCODE_SPACES_ONLY, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_BROWSER_MODE, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_ENCODE_PERCENT, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_DECODE | ICU_NO_ENCODE, "ftp://x/y");
    COMBINE("ftp://a/b/c", "//x/y", ICU_NO_META | ICU_NO_ENCODE, "ftp://x/y");
}
TEST(url_crack_combine2_ftp_a_b_c__d_type_a) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("ftp://a/b/c", "/d;type=a", 0, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_NO_ENCODE, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_DECODE, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_NO_META, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_ENCODE_SPACES_ONLY, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_BROWSER_MODE, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_ENCODE_PERCENT, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_DECODE | ICU_NO_ENCODE, "ftp://a/d;type=a");
    COMBINE("ftp://a/b/c", "/d;type=a", ICU_NO_META | ICU_NO_ENCODE, "ftp://a/d;type=a");
}
TEST(url_crack_combine2_ftp_u_p_a_b_c__d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("ftp://u:p@a/b/c", "d", 0, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_NO_ENCODE, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_DECODE, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_NO_META, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_ENCODE_SPACES_ONLY, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_BROWSER_MODE, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_ENCODE_PERCENT, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_DECODE | ICU_NO_ENCODE, "ftp://u:p@a/b/d");
    COMBINE("ftp://u:p@a/b/c", "d", ICU_NO_META | ICU_NO_ENCODE, "ftp://u:p@a/b/d");
}
TEST(url_crack_combine2_http_1_b_c__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://[::1]/b/c", "g", 0, "http://%5B::1%5D/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_NO_ENCODE, "http://[::1]/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_DECODE, "http://[::1]/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_NO_META, "http://%5B::1%5D/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_ENCODE_SPACES_ONLY, "http://[::1]/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_BROWSER_MODE, "http://%5B::1%5D/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_ENCODE_PERCENT, "http://%5B::1%5D/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_DECODE | ICU_NO_ENCODE, "http://[::1]/b/g");
    COMBINE("http://[::1]/b/c", "g", ICU_NO_META | ICU_NO_ENCODE, "http://[::1]/b/g");
}
TEST(url_crack_combine2_http_1_81_b_c__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://[::1]:81/b/c", "/g", 0, "http://%5B::1%5D:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_NO_ENCODE, "http://[::1]:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_DECODE, "http://[::1]:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_NO_META, "http://%5B::1%5D:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_ENCODE_SPACES_ONLY, "http://[::1]:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_BROWSER_MODE, "http://%5B::1%5D:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_ENCODE_PERCENT, "http://%5B::1%5D:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_DECODE | ICU_NO_ENCODE, "http://[::1]:81/g");
    COMBINE("http://[::1]:81/b/c", "/g", ICU_NO_META | ICU_NO_ENCODE, "http://[::1]:81/g");
}
TEST(url_crack_combine2_http_1_b_c__2_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://[::1]/b/c", "//[::2]/g", 0, "http://%5B::2%5D/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_NO_ENCODE, "http://[::2]/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_DECODE, "http://[::2]/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_NO_META, "http://%5B::2%5D/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_ENCODE_SPACES_ONLY, "http://[::2]/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_BROWSER_MODE, "http://%5B::2%5D/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_ENCODE_PERCENT, "http://%5B::2%5D/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_DECODE | ICU_NO_ENCODE, "http://[::2]/g");
    COMBINE("http://[::1]/b/c", "//[::2]/g", ICU_NO_META | ICU_NO_ENCODE, "http://[::2]/g");
}
TEST(url_crack_combine2_http_a_b_c_d__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/../c/d", "g", 0, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_NO_ENCODE, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_DECODE, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_NO_META, "http://a/b/../c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_ENCODE_SPACES_ONLY, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_BROWSER_MODE, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_ENCODE_PERCENT, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/c/g");
    COMBINE("http://a/b/../c/d", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/../c/g");
}
TEST(url_crack_combine2_http_a_b_c_d__g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/./c/d", "../g", 0, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_NO_META, "http://a/b/./c/../g");
    COMBINE("http://a/b/./c/d", "../g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_ENCODE_PERCENT, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/./c/d", "../g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/./c/../g");
}
TEST(url_crack_combine2_http_a_b_c_d__g_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b c/d", "g", 0, "http://a/b%20c/g");
    COMBINE("http://a/b c/d", "g", ICU_NO_ENCODE, "http://a/b c/g");
    COMBINE("http://a/b c/d", "g", ICU_DECODE, "http://a/b%20c/g");
    COMBINE("http://a/b c/d", "g", ICU_NO_META, "http://a/b%20c/g");
    COMBINE("http://a/b c/d", "g", ICU_ENCODE_SPACES_ONLY, "http://a/b%20c/g");
    COMBINE("http://a/b c/d", "g", ICU_BROWSER_MODE, "http://a/b%20c/g");
    COMBINE("http://a/b c/d", "g", ICU_ENCODE_PERCENT, "http://a/b%20c/g");
    COMBINE("http://a/b c/d", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b c/g");
    COMBINE("http://a/b c/d", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b c/g");
}
TEST(url_crack_combine2_http_a_b_20c_d__g_h) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b%20c/d", "g h", 0, "http://a/b%20c/g%20h");
    COMBINE("http://a/b%20c/d", "g h", ICU_NO_ENCODE, "http://a/b%20c/g h");
    COMBINE("http://a/b%20c/d", "g h", ICU_DECODE, "http://a/b%20c/g%20h");
    COMBINE("http://a/b%20c/d", "g h", ICU_NO_META, "http://a/b%20c/g%20h");
    COMBINE("http://a/b%20c/d", "g h", ICU_ENCODE_SPACES_ONLY, "http://a/b%20c/g%20h");
    COMBINE("http://a/b%20c/d", "g h", ICU_BROWSER_MODE, "http://a/b%20c/g%20h");
    COMBINE("http://a/b%20c/d", "g h", ICU_ENCODE_PERCENT, "http://a/b%2520c/g%20h");
    COMBINE("http://a/b%20c/d", "g h", ICU_DECODE | ICU_NO_ENCODE, "http://a/b c/g h");
    COMBINE("http://a/b%20c/d", "g h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b%20c/g h");
}
TEST(url_crack_combine2_http_a_b_c__g_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://A/B/C", "g", 0, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_NO_ENCODE, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_DECODE, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_NO_META, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_ENCODE_SPACES_ONLY, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_BROWSER_MODE, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_ENCODE_PERCENT, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_DECODE | ICU_NO_ENCODE, "http://a/B/g");
    COMBINE("http://A/B/C", "g", ICU_NO_META | ICU_NO_ENCODE, "http://a/B/g");
}
TEST(url_crack_combine2_http_a_b_c__g_4) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("HTTP://a/b/c", "G", 0, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_NO_ENCODE, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_DECODE, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_NO_META, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_ENCODE_SPACES_ONLY, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_BROWSER_MODE, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_ENCODE_PERCENT, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/G");
    COMBINE("HTTP://a/b/c", "G", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/G");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_y_z) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?y?z", 0, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_NO_ENCODE, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_DECODE, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_NO_META, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_BROWSER_MODE, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_ENCODE_PERCENT, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g?y?z");
    COMBINE("http://a/b/c/d;p?q", "g?y?z", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g?y?z");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "./g:h", 0, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_NO_ENCODE, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_DECODE, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_NO_META, "http://a/b/c/./g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_BROWSER_MODE, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_ENCODE_PERCENT, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g:h");
    COMBINE("http://a/b/c/d;p?q", "./g:h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/./g:h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_2fh) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", 0, "http://a/b/c/g%2Fh");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_NO_ENCODE, "http://a/b/c/g%2Fh");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_DECODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_NO_META, "http://a/b/c/g%2Fh");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g%2Fh");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_BROWSER_MODE, "http://a/b/c/g%2Fh");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_ENCODE_PERCENT, "http://a/b/c/g%252Fh");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g/h");
    COMBINE("http://a/b/c/d;p?q", "g%2Fh", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g%2Fh");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "G", 0, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_NO_ENCODE, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_DECODE, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_NO_META, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_BROWSER_MODE, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_ENCODE_PERCENT, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/G");
    COMBINE("http://a/b/c/d;p?q", "G", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/G");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "\x09g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_NO_META, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "\x09g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", 0, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_NO_ENCODE, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_DECODE, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_NO_META, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_BROWSER_MODE, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_ENCODE_PERCENT, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/gh");
    COMBINE("http://a/b/c/d;p?q", "g\x0d\x0ah", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/gh");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "///g", 0, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_NO_ENCODE, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_DECODE, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_NO_META, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_ENCODE_SPACES_ONLY, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_BROWSER_MODE, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_ENCODE_PERCENT, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_DECODE | ICU_NO_ENCODE, "http:///g");
    COMBINE("http://a/b/c/d;p?q", "///g", ICU_NO_META | ICU_NO_ENCODE, "http:///g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", 0, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_NO_ENCODE, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_DECODE, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_NO_META, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_ENCODE_SPACES_ONLY, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_BROWSER_MODE, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_ENCODE_PERCENT, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\g\\h");
    COMBINE("http://a/b/c/d;p?q", "\\\\g\\h", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\g\\h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_4) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "..\\g", 0, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_DECODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_NO_META, "http://a/b/c/../g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_ENCODE_SPACES_ONLY, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_BROWSER_MODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_ENCODE_PERCENT, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/g");
    COMBINE("http://a/b/c/d;p?q", "..\\g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/../g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_5) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", ".\\g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_NO_META, "http://a/b/c/./g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", ".\\g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/./g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_4) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", 0, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_NO_ENCODE, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_DECODE, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_NO_META, "http://a/b/c/g/../../../../h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_ENCODE_SPACES_ONLY, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_BROWSER_MODE, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_ENCODE_PERCENT, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_DECODE | ICU_NO_ENCODE, "http://a/h");
    COMBINE("http://a/b/c/d;p?q", "g/../../../../h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g/../../../../h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_6) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?", 0, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_NO_ENCODE, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_DECODE, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_NO_META, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_BROWSER_MODE, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_ENCODE_PERCENT, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g?");
    COMBINE("http://a/b/c/d;p?q", "g?", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g?");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_7) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g#", 0, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_NO_ENCODE, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_DECODE, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_NO_META, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_BROWSER_MODE, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_ENCODE_PERCENT, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g#");
    COMBINE("http://a/b/c/d;p?q", "g#", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g#");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "?", 0, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_NO_ENCODE, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_DECODE, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_NO_META, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_BROWSER_MODE, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/d;p?");
    COMBINE("http://a/b/c/d;p?q", "?", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/d;p?");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__empty_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "#", 0, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_NO_ENCODE, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_DECODE, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_NO_META, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_BROWSER_MODE, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/d;p?q#");
    COMBINE("http://a/b/c/d;p?q", "#", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/d;p?q#");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__y_s) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "?y#s", 0, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_NO_ENCODE, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_DECODE, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_NO_META, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_BROWSER_MODE, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/d;p?y#s");
    COMBINE("http://a/b/c/d;p?q", "?y#s", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/d;p?y#s");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__empty_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", ";", 0, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_NO_ENCODE, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_DECODE, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_NO_META, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_BROWSER_MODE, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_ENCODE_PERCENT, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/;");
    COMBINE("http://a/b/c/d;p?q", ";", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/;");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_8) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g;", 0, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_NO_ENCODE, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_DECODE, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_NO_META, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_BROWSER_MODE, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_ENCODE_PERCENT, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g;");
    COMBINE("http://a/b/c/d;p?q", "g;", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g;");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__2e_2e_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", 0, "http://a/b/c/%2e%2e/g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_NO_ENCODE, "http://a/b/c/%2e%2e/g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_DECODE, "http://a/b/c/../g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_NO_META, "http://a/b/c/%2e%2e/g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/%2e%2e/g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_BROWSER_MODE, "http://a/b/c/%2e%2e/g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_ENCODE_PERCENT, "http://a/b/c/%252e%252e/g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/../g");
    COMBINE("http://a/b/c/d;p?q", "%2e%2e/g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/%2e%2e/g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__2e_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "%2E/g", 0, "http://a/b/c/%2E/g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_NO_ENCODE, "http://a/b/c/%2E/g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_DECODE, "http://a/b/c/./g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_NO_META, "http://a/b/c/%2E/g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/%2E/g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_BROWSER_MODE, "http://a/b/c/%2E/g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_ENCODE_PERCENT, "http://a/b/c/%252E/g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/./g");
    COMBINE("http://a/b/c/d;p?q", "%2E/g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/%2E/g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_2e_2e_h) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", 0, "http://a/b/c/g/%2e%2e/h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_NO_ENCODE, "http://a/b/c/g/%2e%2e/h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_DECODE, "http://a/b/c/g/../h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_NO_META, "http://a/b/c/g/%2e%2e/h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g/%2e%2e/h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_BROWSER_MODE, "http://a/b/c/g/%2e%2e/h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_ENCODE_PERCENT, "http://a/b/c/g/%252e%252e/h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g/../h");
    COMBINE("http://a/b/c/d;p?q", "g/%2e%2e/h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g/%2e%2e/h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_5) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g<h>", 0, "http://a/b/c/g%3Ch%3E");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_NO_ENCODE, "http://a/b/c/g<h>");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_DECODE, "http://a/b/c/g%3Ch%3E");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_NO_META, "http://a/b/c/g%3Ch%3E");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g<h>");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_BROWSER_MODE, "http://a/b/c/g%3Ch%3E");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_ENCODE_PERCENT, "http://a/b/c/g%3Ch%3E");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g<h>");
    COMBINE("http://a/b/c/d;p?q", "g<h>", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g<h>");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_6) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g\"h", 0, "http://a/b/c/g%22h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_NO_ENCODE, "http://a/b/c/g\"h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_DECODE, "http://a/b/c/g%22h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_NO_META, "http://a/b/c/g%22h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g\"h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_BROWSER_MODE, "http://a/b/c/g%22h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_ENCODE_PERCENT, "http://a/b/c/g%22h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g\"h");
    COMBINE("http://a/b/c/d;p?q", "g\"h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g\"h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_7) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g{h}", 0, "http://a/b/c/g%7Bh%7D");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_NO_ENCODE, "http://a/b/c/g{h}");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_DECODE, "http://a/b/c/g%7Bh%7D");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_NO_META, "http://a/b/c/g%7Bh%7D");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g{h}");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_BROWSER_MODE, "http://a/b/c/g%7Bh%7D");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_ENCODE_PERCENT, "http://a/b/c/g%7Bh%7D");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g{h}");
    COMBINE("http://a/b/c/d;p?q", "g{h}", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g{h}");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_8) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g|h", 0, "file://\\g%7Ch");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_NO_ENCODE, "file://g|h");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_DECODE, "file://\\g%7Ch");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_NO_META, "file://\\g%7Ch");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_ENCODE_SPACES_ONLY, "file://g|h");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_BROWSER_MODE, "file://\\g%7Ch");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_ENCODE_PERCENT, "file://\\g%7Ch");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_DECODE | ICU_NO_ENCODE, "file://g|h");
    COMBINE("http://a/b/c/d;p?q", "g|h", ICU_NO_META | ICU_NO_ENCODE, "file://g|h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_9) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g^h", 0, "http://a/b/c/g%5Eh");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_NO_ENCODE, "http://a/b/c/g^h");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_DECODE, "http://a/b/c/g%5Eh");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_NO_META, "http://a/b/c/g%5Eh");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g^h");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_BROWSER_MODE, "http://a/b/c/g%5Eh");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_ENCODE_PERCENT, "http://a/b/c/g%5Eh");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g^h");
    COMBINE("http://a/b/c/d;p?q", "g^h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g^h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_h_10) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g`h", 0, "http://a/b/c/g%60h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_NO_ENCODE, "http://a/b/c/g`h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_DECODE, "http://a/b/c/g%60h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_NO_META, "http://a/b/c/g%60h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g`h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_BROWSER_MODE, "http://a/b/c/g%60h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_ENCODE_PERCENT, "http://a/b/c/g%60h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g`h");
    COMBINE("http://a/b/c/d;p?q", "g`h", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g`h");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_2_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g%2", 0, "http://a/b/c/g%2");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_NO_ENCODE, "http://a/b/c/g%2");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_NO_META, "http://a/b/c/g%2");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g%2");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_BROWSER_MODE, "http://a/b/c/g%2");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_ENCODE_PERCENT, "http://a/b/c/g%252");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "g%2", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g%2");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_41) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g%41", 0, "http://a/b/c/g%41");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_NO_ENCODE, "http://a/b/c/g%41");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_DECODE, "http://a/b/c/gA");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_NO_META, "http://a/b/c/g%41");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g%41");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_BROWSER_MODE, "http://a/b/c/g%41");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_ENCODE_PERCENT, "http://a/b/c/g%2541");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/gA");
    COMBINE("http://a/b/c/d;p?q", "g%41", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g%41");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_a_b_c_d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", 0, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_NO_ENCODE, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_DECODE, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_NO_META, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g?a%20b#c%20d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_BROWSER_MODE, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_ENCODE_PERCENT, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g?a b#c d");
    COMBINE("http://a/b/c/d;p?q", "g?a b#c d", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g?a b#c d");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__g_20h_i_20j) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", 0, "http://a/b/c/g%20h?i%20j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_NO_ENCODE, "http://a/b/c/g%20h?i%20j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_DECODE, "http://a/b/c/g%20h?i j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_NO_META, "http://a/b/c/g%20h?i%20j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g%20h?i%20j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_BROWSER_MODE, "http://a/b/c/g%20h?i%20j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_ENCODE_PERCENT, "http://a/b/c/g%2520h?i%20j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g h?i j");
    COMBINE("http://a/b/c/d;p?q", "g%20h?i%20j", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g%20h?i%20j");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__empty_4) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", 0, "http://a/b/c/%C3%A9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_NO_ENCODE, "http://a/b/c/\xc3\xa9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_DECODE, "http://a/b/c/%C3%A9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_NO_META, "http://a/b/c/%C3%A9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/\xc3\xa9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_BROWSER_MODE, "http://a/b/c/%C3%A9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_ENCODE_PERCENT, "http://a/b/c/%C3%A9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/\xc3\xa9");
    COMBINE("http://a/b/c/d;p?q", "\xc3\xa9", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/\xc3\xa9");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__ftp_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "ftp:g", 0, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_NO_ENCODE, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_DECODE, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_NO_META, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_ENCODE_SPACES_ONLY, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_BROWSER_MODE, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_ENCODE_PERCENT, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_DECODE | ICU_NO_ENCODE, "ftp:g");
    COMBINE("http://a/b/c/d;p?q", "ftp:g", ICU_NO_META | ICU_NO_ENCODE, "ftp:g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__file_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "file:g", 0, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_NO_ENCODE, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_DECODE, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_NO_META, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_ENCODE_SPACES_ONLY, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_BROWSER_MODE, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_ENCODE_PERCENT, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_DECODE | ICU_NO_ENCODE, "file:g");
    COMBINE("http://a/b/c/d;p?q", "file:g", ICU_NO_META | ICU_NO_ENCODE, "file:g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__file_c_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", 0, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_NO_ENCODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_DECODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_NO_META, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_ENCODE_SPACES_ONLY, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_BROWSER_MODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_ENCODE_PERCENT, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "FILE:///C:/x", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\x");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__mailto_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "mailto:x", 0, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_NO_ENCODE, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_DECODE, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_NO_META, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_ENCODE_SPACES_ONLY, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_BROWSER_MODE, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_ENCODE_PERCENT, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_DECODE | ICU_NO_ENCODE, "mailto:x");
    COMBINE("http://a/b/c/d;p?q", "mailto:x", ICU_NO_META | ICU_NO_ENCODE, "mailto:x");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__about_blank) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "about:blank", 0, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_NO_ENCODE, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_DECODE, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_NO_META, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_ENCODE_SPACES_ONLY, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_BROWSER_MODE, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_ENCODE_PERCENT, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_DECODE | ICU_NO_ENCODE, "about:blank");
    COMBINE("http://a/b/c/d;p?q", "about:blank", ICU_NO_META | ICU_NO_ENCODE, "about:blank");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__foo_h_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", 0, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_NO_ENCODE, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_DECODE, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_NO_META, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_ENCODE_SPACES_ONLY, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_BROWSER_MODE, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_ENCODE_PERCENT, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_DECODE | ICU_NO_ENCODE, "foo://h/../x");
    COMBINE("http://a/b/c/d;p?q", "foo://h/../x", ICU_NO_META | ICU_NO_ENCODE, "foo://h/../x");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__http_g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", 0, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_DECODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_NO_META, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_BROWSER_MODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_ENCODE_PERCENT, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/g");
    COMBINE("http://a/b/c/d;p?q", "HTTP:g", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__http_g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "http:/g", 0, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_DECODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_NO_META, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_ENCODE_SPACES_ONLY, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_BROWSER_MODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_ENCODE_PERCENT, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_DECODE | ICU_NO_ENCODE, "http://a/g");
    COMBINE("http://a/b/c/d;p?q", "http:/g", ICU_NO_META | ICU_NO_ENCODE, "http://a/g");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__http_y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "http:?y", 0, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_NO_ENCODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_DECODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_NO_META, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_BROWSER_MODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/d;p?y");
    COMBINE("http://a/b/c/d;p?q", "http:?y", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/d;p?y");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__http_s) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "http:#s", 0, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_NO_ENCODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_DECODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_NO_META, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_ENCODE_SPACES_ONLY, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_BROWSER_MODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_ENCODE_PERCENT, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_DECODE | ICU_NO_ENCODE, "http://a/b/c/d;p?q#s");
    COMBINE("http://a/b/c/d;p?q", "http:#s", ICU_NO_META | ICU_NO_ENCODE, "http://a/b/c/d;p?q#s");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__http) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "http://", 0, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_NO_ENCODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_DECODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_NO_META, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_ENCODE_SPACES_ONLY, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_BROWSER_MODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_ENCODE_PERCENT, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_DECODE | ICU_NO_ENCODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "http://", ICU_NO_META | ICU_NO_ENCODE, "http:///");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__empty_5) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "//", 0, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_NO_ENCODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_DECODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_NO_META, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_ENCODE_SPACES_ONLY, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_BROWSER_MODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_ENCODE_PERCENT, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_DECODE | ICU_NO_ENCODE, "http:///");
    COMBINE("http://a/b/c/d;p?q", "//", ICU_NO_META | ICU_NO_ENCODE, "http:///");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__c_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "C:\\x", 0, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_NO_ENCODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_DECODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_NO_META, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_ENCODE_SPACES_ONLY, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_BROWSER_MODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_ENCODE_PERCENT, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:\\x", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\x");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__c_x_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "C:/x", 0, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_NO_ENCODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_DECODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_NO_META, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_ENCODE_SPACES_ONLY, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_BROWSER_MODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_ENCODE_PERCENT, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\x");
    COMBINE("http://a/b/c/d;p?q", "C:/x", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\x");
}
TEST(url_crack_combine2_http_a_b_c_d_p_q__server_share) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", 0, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_NO_ENCODE, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_DECODE, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_NO_META, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_ENCODE_SPACES_ONLY, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_BROWSER_MODE, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_ENCODE_PERCENT, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\server\\share");
    COMBINE("http://a/b/c/d;p?q", "\\\\server\\share", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\server\\share");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__d_txt) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", 0, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_NO_ENCODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_DECODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_NO_META, "file://C:\\a\\b\\..\\..\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_BROWSER_MODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_ENCODE_PERCENT, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../d.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\..\\..\\d.txt");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__d_txt_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", 0, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_NO_ENCODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_DECODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_NO_META, "file://C:\\a\\b\\..\\..\\..\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_BROWSER_MODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_ENCODE_PERCENT, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "../../../d.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\..\\..\\..\\d.txt");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__d_e_txt) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", 0, "file://C:\\a\\b\\d%20e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_NO_ENCODE, "file://C:\\a\\b\\d e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_DECODE, "file://C:\\a\\b\\d%20e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_NO_META, "file://C:\\a\\b\\d%20e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b\\d%20e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_BROWSER_MODE, "file://C:\\a\\b\\d%20e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\b\\d%20e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b\\d e.txt");
    COMBINE("file:///C:/a/b/c.txt", "d e.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\d e.txt");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "?q", 0, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_NO_ENCODE, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_DECODE, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_NO_META, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_BROWSER_MODE, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_ENCODE_PERCENT, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b\\c.txt?q");
    COMBINE("file:///C:/a/b/c.txt", "?q", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\c.txt?q");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__f) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "#f", 0, "file://C:\\a\\b\\c.txt%23f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_NO_ENCODE, "file://C:\\a\\b\\c.txt#f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_DECODE, "file://C:\\a\\b\\c.txt%23f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_NO_META, "file://C:\\a\\b\\c.txt%23f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b\\c.txt#f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_BROWSER_MODE, "file://C:\\a\\b\\c.txt%23f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_ENCODE_PERCENT, "file://C:\\a\\b\\c.txt%23f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b\\c.txt#f");
    COMBINE("file:///C:/a/b/c.txt", "#f", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\c.txt#f");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__server_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "//server/x", 0, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_NO_ENCODE, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_DECODE, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_NO_META, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_ENCODE_SPACES_ONLY, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_BROWSER_MODE, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_ENCODE_PERCENT, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\server\\x");
    COMBINE("file:///C:/a/b/c.txt", "//server/x", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\server\\x");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__d_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "D:/x", 0, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_NO_ENCODE, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_DECODE, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_NO_META, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_ENCODE_SPACES_ONLY, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_BROWSER_MODE, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_ENCODE_PERCENT, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_DECODE | ICU_NO_ENCODE, "file://D:\\x");
    COMBINE("file:///C:/a/b/c.txt", "D:/x", ICU_NO_META | ICU_NO_ENCODE, "file://D:\\x");
}
TEST(url_crack_combine2_file_c_a_b_c_txt__d_txt_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", 0, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_NO_ENCODE, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_DECODE, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_NO_META, "file://C:\\a\\b\\..\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_BROWSER_MODE, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_ENCODE_PERCENT, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\d.txt");
    COMBINE("file:///C:/a/b/c.txt", "..\\d.txt", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b\\..\\d.txt");
}
TEST(url_crack_combine2_file_server_share_a___c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file://server/share/a/b", "c", 0, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_NO_ENCODE, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_DECODE, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_NO_META, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_ENCODE_SPACES_ONLY, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_BROWSER_MODE, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_ENCODE_PERCENT, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\server\\share\\a\\c");
    COMBINE("file://server/share/a/b", "c", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\server\\share\\a\\c");
}
TEST(url_crack_combine2_file_server_share_a___c_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file://server/share/a/b", "../../c", 0, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_NO_ENCODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_DECODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_NO_META, "file://\\\\server\\share\\a\\..\\..\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_ENCODE_SPACES_ONLY, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_BROWSER_MODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_ENCODE_PERCENT, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "../../c", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\server\\share\\a\\..\\..\\c");
}
TEST(url_crack_combine2_file_server_share_a___c_3) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file://server/share/a/b", "/c", 0, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_NO_ENCODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_DECODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_NO_META, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_ENCODE_SPACES_ONLY, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_BROWSER_MODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_ENCODE_PERCENT, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\server\\c");
    COMBINE("file://server/share/a/b", "/c", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\server\\c");
}
TEST(url_crack_combine2_file_c_a__b) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/a/", "b", 0, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_NO_ENCODE, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_DECODE, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_NO_META, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_BROWSER_MODE, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_ENCODE_PERCENT, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b");
    COMBINE("file:///C:/a/", "b", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\b");
}
TEST(url_crack_combine2_file_c__empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("file:///C:/", "..", 0, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_NO_ENCODE, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_DECODE, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_NO_META, "file://C:\\..\\");
    COMBINE("file:///C:/", "..", ICU_ENCODE_SPACES_ONLY, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_BROWSER_MODE, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_ENCODE_PERCENT, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\");
    COMBINE("file:///C:/", "..", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\..\\");
}
TEST(url_crack_combine2_mailto_a_b__subject_x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("mailto:a@b", "?subject=x", 0, "mailto:a@b%3Fsubject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_NO_ENCODE, "mailto:a@b?subject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_DECODE, "mailto:a@b%3Fsubject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_NO_META, "mailto:a@b%3Fsubject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_ENCODE_SPACES_ONLY, "mailto:a@b?subject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_BROWSER_MODE, "mailto:a@b%3Fsubject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_ENCODE_PERCENT, "mailto:a@b%3Fsubject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_DECODE | ICU_NO_ENCODE, "mailto:a@b?subject=x");
    COMBINE("mailto:a@b", "?subject=x", ICU_NO_META | ICU_NO_ENCODE, "mailto:a@b?subject=x");
}
TEST(url_crack_combine2_mailto_a_b__mailto_c_d) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("mailto:a@b", "mailto:c@d", 0, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_NO_ENCODE, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_DECODE, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_NO_META, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_ENCODE_SPACES_ONLY, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_BROWSER_MODE, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_ENCODE_PERCENT, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_DECODE | ICU_NO_ENCODE, "mailto:c@d");
    COMBINE("mailto:a@b", "mailto:c@d", ICU_NO_META | ICU_NO_ENCODE, "mailto:c@d");
}
TEST(url_crack_combine2_news_a_b__c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("news:a.b", "c", 0, "news:c");
    COMBINE("news:a.b", "c", ICU_NO_ENCODE, "news:c");
    COMBINE("news:a.b", "c", ICU_DECODE, "news:c");
    COMBINE("news:a.b", "c", ICU_NO_META, "news:c");
    COMBINE("news:a.b", "c", ICU_ENCODE_SPACES_ONLY, "news:c");
    COMBINE("news:a.b", "c", ICU_BROWSER_MODE, "news:c");
    COMBINE("news:a.b", "c", ICU_ENCODE_PERCENT, "news:c");
    COMBINE("news:a.b", "c", ICU_DECODE | ICU_NO_ENCODE, "news:c");
    COMBINE("news:a.b", "c", ICU_NO_META | ICU_NO_ENCODE, "news:c");
}
TEST(url_crack_combine2_javascript_x__y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("javascript:x", "y", 0, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_NO_ENCODE, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_DECODE, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_NO_META, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_ENCODE_SPACES_ONLY, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_BROWSER_MODE, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_ENCODE_PERCENT, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_DECODE | ICU_NO_ENCODE, "javascript:xy");
    COMBINE("javascript:x", "y", ICU_NO_META | ICU_NO_ENCODE, "javascript:xy");
}
TEST(url_crack_combine2_about_blank__f) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("about:blank", "#f", 0, "about:blank%23f");
    COMBINE("about:blank", "#f", ICU_NO_ENCODE, "about:blank#f");
    COMBINE("about:blank", "#f", ICU_DECODE, "about:blank%23f");
    COMBINE("about:blank", "#f", ICU_NO_META, "about:blank%23f");
    COMBINE("about:blank", "#f", ICU_ENCODE_SPACES_ONLY, "about:blank#f");
    COMBINE("about:blank", "#f", ICU_BROWSER_MODE, "about:blank%23f");
    COMBINE("about:blank", "#f", ICU_ENCODE_PERCENT, "about:blank%23f");
    COMBINE("about:blank", "#f", ICU_DECODE | ICU_NO_ENCODE, "about:blank#f");
    COMBINE("about:blank", "#f", ICU_NO_META | ICU_NO_ENCODE, "about:blank#f");
}
TEST(url_crack_combine2_res_x_dll_a_b__c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("res://x.dll/a/b", "c", 0, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_NO_ENCODE, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_DECODE, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_NO_META, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_ENCODE_SPACES_ONLY, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_BROWSER_MODE, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_ENCODE_PERCENT, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_DECODE | ICU_NO_ENCODE, "res://x.dll/a/c");
    COMBINE("res://x.dll/a/b", "c", ICU_NO_META | ICU_NO_ENCODE, "res://x.dll/a/c");
}
TEST(url_crack_combine2_res_x_dll_a_b__c_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("res://x.dll/a/b", "../c", 0, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_NO_ENCODE, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_DECODE, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_NO_META, "res://x.dll/a/../c");
    COMBINE("res://x.dll/a/b", "../c", ICU_ENCODE_SPACES_ONLY, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_BROWSER_MODE, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_ENCODE_PERCENT, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_DECODE | ICU_NO_ENCODE, "res://x.dll/c");
    COMBINE("res://x.dll/a/b", "../c", ICU_NO_META | ICU_NO_ENCODE, "res://x.dll/a/../c");
}
TEST(url_crack_combine2_foo_h_a_b__c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("foo://h/a/b", "../../../c", 0, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_NO_ENCODE, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_DECODE, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_NO_META, "foo://h/a/../../../c");
    COMBINE("foo://h/a/b", "../../../c", ICU_ENCODE_SPACES_ONLY, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_BROWSER_MODE, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_ENCODE_PERCENT, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_DECODE | ICU_NO_ENCODE, "foo://h/c");
    COMBINE("foo://h/a/b", "../../../c", ICU_NO_META | ICU_NO_ENCODE, "foo://h/a/../../../c");
}
TEST(url_crack_combine2_foo_h_a_b__q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("foo://h/a/b", "?q", 0, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_NO_ENCODE, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_DECODE, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_NO_META, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_ENCODE_SPACES_ONLY, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_BROWSER_MODE, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_ENCODE_PERCENT, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_DECODE | ICU_NO_ENCODE, "foo://h/a/b?q");
    COMBINE("foo://h/a/b", "?q", ICU_NO_META | ICU_NO_ENCODE, "foo://h/a/b?q");
}
TEST(url_crack_combine2_foo_a_b__c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("foo:a/b", "c", 0, "foo:c");
    COMBINE("foo:a/b", "c", ICU_NO_ENCODE, "foo:c");
    COMBINE("foo:a/b", "c", ICU_DECODE, "foo:c");
    COMBINE("foo:a/b", "c", ICU_NO_META, "foo:c");
    COMBINE("foo:a/b", "c", ICU_ENCODE_SPACES_ONLY, "foo:c");
    COMBINE("foo:a/b", "c", ICU_BROWSER_MODE, "foo:c");
    COMBINE("foo:a/b", "c", ICU_ENCODE_PERCENT, "foo:c");
    COMBINE("foo:a/b", "c", ICU_DECODE | ICU_NO_ENCODE, "foo:c");
    COMBINE("foo:a/b", "c", ICU_NO_META | ICU_NO_ENCODE, "foo:c");
}
TEST(url_crack_combine2_foo_a_b__c_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("foo:a/b", "/c", 0, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_NO_ENCODE, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_DECODE, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_NO_META, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_ENCODE_SPACES_ONLY, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_BROWSER_MODE, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_ENCODE_PERCENT, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_DECODE | ICU_NO_ENCODE, "foo:/c");
    COMBINE("foo:a/b", "/c", ICU_NO_META | ICU_NO_ENCODE, "foo:/c");
}
TEST(url_crack_combine2_gopher_h_1_a__b) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("gopher://h/1/a", "b", 0, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_NO_ENCODE, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_DECODE, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_NO_META, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_ENCODE_SPACES_ONLY, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_BROWSER_MODE, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_ENCODE_PERCENT, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_DECODE | ICU_NO_ENCODE, "gopher://h/1/b");
    COMBINE("gopher://h/1/a", "b", ICU_NO_META | ICU_NO_ENCODE, "gopher://h/1/b");
}
TEST(url_crack_combine2_news_h_a_b__c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("news://h/a/b", "c", 0, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_NO_ENCODE, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_DECODE, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_NO_META, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_ENCODE_SPACES_ONLY, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_BROWSER_MODE, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_ENCODE_PERCENT, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_DECODE | ICU_NO_ENCODE, "news://h/a/c");
    COMBINE("news://h/a/b", "c", ICU_NO_META | ICU_NO_ENCODE, "news://h/a/c");
}
TEST(url_crack_combine2_ftp_h__x) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("ftp://h", "x", 0, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_NO_ENCODE, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_DECODE, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_NO_META, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_ENCODE_SPACES_ONLY, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_BROWSER_MODE, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_ENCODE_PERCENT, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_DECODE | ICU_NO_ENCODE, "ftp://h/x");
    COMBINE("ftp://h", "x", ICU_NO_META | ICU_NO_ENCODE, "ftp://h/x");
}
TEST(url_crack_combine2_https_h__q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("https://h", "?q", 0, "https://h/?q");
    COMBINE("https://h", "?q", ICU_NO_ENCODE, "https://h/?q");
    COMBINE("https://h", "?q", ICU_DECODE, "https://h/?q");
    COMBINE("https://h", "?q", ICU_NO_META, "https://h/?q");
    COMBINE("https://h", "?q", ICU_ENCODE_SPACES_ONLY, "https://h/?q");
    COMBINE("https://h", "?q", ICU_BROWSER_MODE, "https://h/?q");
    COMBINE("https://h", "?q", ICU_ENCODE_PERCENT, "https://h/?q");
    COMBINE("https://h", "?q", ICU_DECODE | ICU_NO_ENCODE, "https://h/?q");
    COMBINE("https://h", "?q", ICU_NO_META | ICU_NO_ENCODE, "https://h/?q");
}
TEST(url_crack_combine2_x__y) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("x:", "y", 0, "file://x:\\y");
    COMBINE("x:", "y", ICU_NO_ENCODE, "file://x:\\y");
    COMBINE("x:", "y", ICU_DECODE, "file://x:\\y");
    COMBINE("x:", "y", ICU_NO_META, "file://x:\\y");
    COMBINE("x:", "y", ICU_ENCODE_SPACES_ONLY, "file://x:\\y");
    COMBINE("x:", "y", ICU_BROWSER_MODE, "file://x:\\y");
    COMBINE("x:", "y", ICU_ENCODE_PERCENT, "file://x:\\y");
    COMBINE("x:", "y", ICU_DECODE | ICU_NO_ENCODE, "file://x:\\y");
    COMBINE("x:", "y", ICU_NO_META | ICU_NO_ENCODE, "file://x:\\y");
}
TEST(url_crack_combine2_empty__empty) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("", "", 0, "");
    COMBINE("", "", ICU_NO_ENCODE, "");
    COMBINE("", "", ICU_DECODE, "");
    COMBINE("", "", ICU_NO_META, "");
    COMBINE("", "", ICU_ENCODE_SPACES_ONLY, "");
    COMBINE("", "", ICU_BROWSER_MODE, "");
    COMBINE("", "", ICU_ENCODE_PERCENT, "");
    COMBINE("", "", ICU_DECODE | ICU_NO_ENCODE, "");
    COMBINE("", "", ICU_NO_META | ICU_NO_ENCODE, "");
}
TEST(url_crack_combine2_empty__q) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("", "?q", 0, "?q");
    COMBINE("", "?q", ICU_NO_ENCODE, "?q");
    COMBINE("", "?q", ICU_DECODE, "?q");
    COMBINE("", "?q", ICU_NO_META, "?q");
    COMBINE("", "?q", ICU_ENCODE_SPACES_ONLY, "?q");
    COMBINE("", "?q", ICU_BROWSER_MODE, "?q");
    COMBINE("", "?q", ICU_ENCODE_PERCENT, "?q");
    COMBINE("", "?q", ICU_DECODE | ICU_NO_ENCODE, "?q");
    COMBINE("", "?q", ICU_NO_META | ICU_NO_ENCODE, "?q");
}
TEST(url_crack_combine2_empty__f) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("", "#f", 0, "#f");
    COMBINE("", "#f", ICU_NO_ENCODE, "#f");
    COMBINE("", "#f", ICU_DECODE, "#f");
    COMBINE("", "#f", ICU_NO_META, "#f");
    COMBINE("", "#f", ICU_ENCODE_SPACES_ONLY, "#f");
    COMBINE("", "#f", ICU_BROWSER_MODE, "#f");
    COMBINE("", "#f", ICU_ENCODE_PERCENT, "#f");
    COMBINE("", "#f", ICU_DECODE | ICU_NO_ENCODE, "#f");
    COMBINE("", "#f", ICU_NO_META | ICU_NO_ENCODE, "#f");
}
TEST(url_crack_combine2_a_b__c) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("/a/b", "c", 0, "/a/c");
    COMBINE("/a/b", "c", ICU_NO_ENCODE, "/a/c");
    COMBINE("/a/b", "c", ICU_DECODE, "/a/c");
    COMBINE("/a/b", "c", ICU_NO_META, "/a/c");
    COMBINE("/a/b", "c", ICU_ENCODE_SPACES_ONLY, "/a/c");
    COMBINE("/a/b", "c", ICU_BROWSER_MODE, "/a/c");
    COMBINE("/a/b", "c", ICU_ENCODE_PERCENT, "/a/c");
    COMBINE("/a/b", "c", ICU_DECODE | ICU_NO_ENCODE, "/a/c");
    COMBINE("/a/b", "c", ICU_NO_META | ICU_NO_ENCODE, "/a/c");
}
TEST(url_crack_combine2_h_a__b) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("//h/a", "b", 0, "//h/b");
    COMBINE("//h/a", "b", ICU_NO_ENCODE, "//h/b");
    COMBINE("//h/a", "b", ICU_DECODE, "//h/b");
    COMBINE("//h/a", "b", ICU_NO_META, "//h/b");
    COMBINE("//h/a", "b", ICU_ENCODE_SPACES_ONLY, "//h/b");
    COMBINE("//h/a", "b", ICU_BROWSER_MODE, "//h/b");
    COMBINE("//h/a", "b", ICU_ENCODE_PERCENT, "//h/b");
    COMBINE("//h/a", "b", ICU_DECODE | ICU_NO_ENCODE, "//h/b");
    COMBINE("//h/a", "b", ICU_NO_META | ICU_NO_ENCODE, "//h/b");
}
TEST(url_crack_combine2_a_b__c_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("a/b", "c", 0, "c");
    COMBINE("a/b", "c", ICU_NO_ENCODE, "c");
    COMBINE("a/b", "c", ICU_DECODE, "c");
    COMBINE("a/b", "c", ICU_NO_META, "c");
    COMBINE("a/b", "c", ICU_ENCODE_SPACES_ONLY, "c");
    COMBINE("a/b", "c", ICU_BROWSER_MODE, "c");
    COMBINE("a/b", "c", ICU_ENCODE_PERCENT, "c");
    COMBINE("a/b", "c", ICU_DECODE | ICU_NO_ENCODE, "c");
    COMBINE("a/b", "c", ICU_NO_META | ICU_NO_ENCODE, "c");
}
TEST(url_crack_combine2_http__g) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http:", "g", 0, "http:g");
    COMBINE("http:", "g", ICU_NO_ENCODE, "http:g");
    COMBINE("http:", "g", ICU_DECODE, "http:g");
    COMBINE("http:", "g", ICU_NO_META, "http:g");
    COMBINE("http:", "g", ICU_ENCODE_SPACES_ONLY, "http:g");
    COMBINE("http:", "g", ICU_BROWSER_MODE, "http:g");
    COMBINE("http:", "g", ICU_ENCODE_PERCENT, "http:g");
    COMBINE("http:", "g", ICU_DECODE | ICU_NO_ENCODE, "http:g");
    COMBINE("http:", "g", ICU_NO_META | ICU_NO_ENCODE, "http:g");
}
TEST(url_crack_combine2_http__g_2) {
    REQUIRE(U(InternetCombineUrlA)); REQUIRE(U(InternetCombineUrlW));
    COMBINE("http://", "g", 0, "http:///g");
    COMBINE("http://", "g", ICU_NO_ENCODE, "http:///g");
    COMBINE("http://", "g", ICU_DECODE, "http:///g");
    COMBINE("http://", "g", ICU_NO_META, "http:///g");
    COMBINE("http://", "g", ICU_ENCODE_SPACES_ONLY, "http:///g");
    COMBINE("http://", "g", ICU_BROWSER_MODE, "http:///g");
    COMBINE("http://", "g", ICU_ENCODE_PERCENT, "http:///g");
    COMBINE("http://", "g", ICU_DECODE | ICU_NO_ENCODE, "http:///g");
    COMBINE("http://", "g", ICU_NO_META | ICU_NO_ENCODE, "http:///g");
}
