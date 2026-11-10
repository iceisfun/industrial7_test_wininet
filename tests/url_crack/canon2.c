/* url_crack (widening pass 2): InternetCanonicalizeUrlA/W, more inputs (dot segments, %-escapes of every class, every
 * printable special character, control characters, ports, IPv6, file:, opaque schemes, relative input)
 * with 16 flag combinations each
 * Generated from the Win10 22H2 VM probe dump (boot ucprobe3-20261110-054841) by a throw-away generator; every row was observed on
 * genuine Windows 10 (wininet 11.0.19041.2193) and cross-read against the decomp named in EVIDENCE.md.
 * VM_TIMEOUT: 120 */
#include "uc.h"

TEST(url_crack_canon2_http_h_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/b/../../..", 0, "http://h/");
    CANON("http://h/a/b/../../..", ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_DECODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_NO_META, "http://h/a/b/../../..");
    CANON("http://h/a/b/../../..", ICU_ENCODE_SPACES_ONLY, "http://h/");
    CANON("http://h/a/b/../../..", ICU_BROWSER_MODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/a/b/../../..", ICU_ESCAPE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_DECODE | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/b/../../..");
    CANON("http://h/a/b/../../..", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_USERNAME, "http://h/");
    CANON("http://h/a/b/../../..", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/a/b/../../..", ICU_BROWSER_MODE | ICU_DECODE, "http://h/");
    CANON("http://h/a/b/../../..", ICU_NO_META | ICU_DECODE, "http://h/a/b/../../../");
}
TEST(url_crack_canon2_http_h_a_b_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/b/../../../", 0, "http://h/");
    CANON("http://h/a/b/../../../", ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_DECODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_NO_META, "http://h/a/b/../../../");
    CANON("http://h/a/b/../../../", ICU_ENCODE_SPACES_ONLY, "http://h/");
    CANON("http://h/a/b/../../../", ICU_BROWSER_MODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/a/b/../../../", ICU_ESCAPE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_DECODE | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/b/../../../");
    CANON("http://h/a/b/../../../", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_USERNAME, "http://h/");
    CANON("http://h/a/b/../../../", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/a/b/../../../", ICU_BROWSER_MODE | ICU_DECODE, "http://h/");
    CANON("http://h/a/b/../../../", ICU_NO_META | ICU_DECODE, "http://h/a/b/../../../");
}
TEST(url_crack_canon2_http_h_a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/./a", 0, "http://h/./a");
    CANON("http://h/./a", ICU_NO_ENCODE, "http://h/./a");
    CANON("http://h/./a", ICU_DECODE, "http://h/./a");
    CANON("http://h/./a", ICU_NO_META, "http://h/./a");
    CANON("http://h/./a", ICU_ENCODE_SPACES_ONLY, "http://h/./a");
    CANON("http://h/./a", ICU_BROWSER_MODE, "http://h/./a");
    CANON("http://h/./a", ICU_ENCODE_PERCENT, "http://h/./a");
    CANON("http://h/./a", ICU_ESCAPE, "http://h/./a");
    CANON("http://h/./a", ICU_DECODE | ICU_NO_ENCODE, "http://h/./a");
    CANON("http://h/./a", ICU_NO_META | ICU_NO_ENCODE, "http://h/./a");
    CANON("http://h/./a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/./a");
    CANON("http://h/./a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/./a");
    CANON("http://h/./a", ICU_USERNAME, "http://h/./a");
    CANON("http://h/./a", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/./a");
    CANON("http://h/./a", ICU_BROWSER_MODE | ICU_DECODE, "http://h/./a");
    CANON("http://h/./a", ICU_NO_META | ICU_DECODE, "http://h/./a");
}
TEST(url_crack_canon2_http_h_a_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/../a", 0, "http://h/../a");
    CANON("http://h/../a", ICU_NO_ENCODE, "http://h/../a");
    CANON("http://h/../a", ICU_DECODE, "http://h/../a");
    CANON("http://h/../a", ICU_NO_META, "http://h/../a");
    CANON("http://h/../a", ICU_ENCODE_SPACES_ONLY, "http://h/../a");
    CANON("http://h/../a", ICU_BROWSER_MODE, "http://h/../a");
    CANON("http://h/../a", ICU_ENCODE_PERCENT, "http://h/../a");
    CANON("http://h/../a", ICU_ESCAPE, "http://h/../a");
    CANON("http://h/../a", ICU_DECODE | ICU_NO_ENCODE, "http://h/../a");
    CANON("http://h/../a", ICU_NO_META | ICU_NO_ENCODE, "http://h/../a");
    CANON("http://h/../a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/../a");
    CANON("http://h/../a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/../a");
    CANON("http://h/../a", ICU_USERNAME, "http://h/../a");
    CANON("http://h/../a", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/../a");
    CANON("http://h/../a", ICU_BROWSER_MODE | ICU_DECODE, "http://h/../a");
    CANON("http://h/../a", ICU_NO_META | ICU_DECODE, "http://h/../a");
}
TEST(url_crack_canon2_http_h_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/..b/c", 0, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_NO_ENCODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_DECODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_NO_META, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_ENCODE_SPACES_ONLY, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_BROWSER_MODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_ENCODE_PERCENT, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_ESCAPE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_USERNAME, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/..b/c");
    CANON("http://h/a/..b/c", ICU_NO_META | ICU_DECODE, "http://h/a/..b/c");
}
TEST(url_crack_canon2_http_h_a_b_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/b..", 0, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_NO_ENCODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_DECODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_NO_META, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_ENCODE_SPACES_ONLY, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_BROWSER_MODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_ENCODE_PERCENT, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_ESCAPE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_USERNAME, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/b..");
    CANON("http://h/a/b..", ICU_NO_META | ICU_DECODE, "http://h/a/b..");
}
TEST(url_crack_canon2_http_h_a_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/...", 0, "http://h/a/...");
    CANON("http://h/a/...", ICU_NO_ENCODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_DECODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_NO_META, "http://h/a/...");
    CANON("http://h/a/...", ICU_ENCODE_SPACES_ONLY, "http://h/a/...");
    CANON("http://h/a/...", ICU_BROWSER_MODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_ENCODE_PERCENT, "http://h/a/...");
    CANON("http://h/a/...", ICU_ESCAPE, "http://h/a/...");
    CANON("http://h/a/...", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_USERNAME, "http://h/a/...");
    CANON("http://h/a/...", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/...");
    CANON("http://h/a/...", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/...");
    CANON("http://h/a/...", ICU_NO_META | ICU_DECODE, "http://h/a/...");
}
TEST(url_crack_canon2_http_h_a_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/./", 0, "http://h/a/");
    CANON("http://h/a/./", ICU_NO_ENCODE, "http://h/a/");
    CANON("http://h/a/./", ICU_DECODE, "http://h/a/");
    CANON("http://h/a/./", ICU_NO_META, "http://h/a/./");
    CANON("http://h/a/./", ICU_ENCODE_SPACES_ONLY, "http://h/a/");
    CANON("http://h/a/./", ICU_BROWSER_MODE, "http://h/a/");
    CANON("http://h/a/./", ICU_ENCODE_PERCENT, "http://h/a/");
    CANON("http://h/a/./", ICU_ESCAPE, "http://h/a/");
    CANON("http://h/a/./", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/");
    CANON("http://h/a/./", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/./");
    CANON("http://h/a/./", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/");
    CANON("http://h/a/./", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/");
    CANON("http://h/a/./", ICU_USERNAME, "http://h/a/");
    CANON("http://h/a/./", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/");
    CANON("http://h/a/./", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/");
    CANON("http://h/a/./", ICU_NO_META | ICU_DECODE, "http://h/a/./");
}
TEST(url_crack_canon2_http_h_a_b_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a//../b", 0, "http://h/a/b");
    CANON("http://h/a//../b", ICU_NO_ENCODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_DECODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_NO_META, "http://h/a//../b");
    CANON("http://h/a//../b", ICU_ENCODE_SPACES_ONLY, "http://h/a/b");
    CANON("http://h/a//../b", ICU_BROWSER_MODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_ENCODE_PERCENT, "http://h/a/b");
    CANON("http://h/a//../b", ICU_ESCAPE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a//../b");
    CANON("http://h/a//../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_USERNAME, "http://h/a/b");
    CANON("http://h/a//../b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/b");
    CANON("http://h/a//../b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/b");
    CANON("http://h/a//../b", ICU_NO_META | ICU_DECODE, "http://h/a//../b");
}
TEST(url_crack_canon2_http_h_a_2e_2e) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/%2e%2e", 0, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_NO_ENCODE, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_DECODE, "http://h/a/../");
    CANON("http://h/a/%2e%2e", ICU_NO_META, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_ENCODE_SPACES_ONLY, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_BROWSER_MODE, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_ENCODE_PERCENT, "http://h/a/%252e%252e");
    CANON("http://h/a/%2e%2e", ICU_ESCAPE, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/..");
    CANON("http://h/a/%2e%2e", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_USERNAME, "http://h/a/%2e%2e");
    CANON("http://h/a/%2e%2e", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/../");
    CANON("http://h/a/%2e%2e", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/../");
    CANON("http://h/a/%2e%2e", ICU_NO_META | ICU_DECODE, "http://h/a/../");
}
TEST(url_crack_canon2_http_h_a_2e_2e_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/%2E%2E/b", 0, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_NO_ENCODE, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_DECODE, "http://h/a/../b");
    CANON("http://h/a/%2E%2E/b", ICU_NO_META, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_ENCODE_SPACES_ONLY, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_BROWSER_MODE, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_ENCODE_PERCENT, "http://h/a/%252E%252E/b");
    CANON("http://h/a/%2E%2E/b", ICU_ESCAPE, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/../b");
    CANON("http://h/a/%2E%2E/b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_USERNAME, "http://h/a/%2E%2E/b");
    CANON("http://h/a/%2E%2E/b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/../b");
    CANON("http://h/a/%2E%2E/b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/../b");
    CANON("http://h/a/%2E%2E/b", ICU_NO_META | ICU_DECODE, "http://h/a/../b");
}
TEST(url_crack_canon2_http_h_a_2e_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/.%2e/b", 0, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_NO_ENCODE, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_DECODE, "http://h/a/../b");
    CANON("http://h/a/.%2e/b", ICU_NO_META, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_ENCODE_SPACES_ONLY, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_BROWSER_MODE, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_ENCODE_PERCENT, "http://h/a/.%252e/b");
    CANON("http://h/a/.%2e/b", ICU_ESCAPE, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/../b");
    CANON("http://h/a/.%2e/b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_USERNAME, "http://h/a/.%2e/b");
    CANON("http://h/a/.%2e/b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/../b");
    CANON("http://h/a/.%2e/b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/../b");
    CANON("http://h/a/.%2e/b", ICU_NO_META | ICU_DECODE, "http://h/a/../b");
}
TEST(url_crack_canon2_http_h_2e_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%2e/b", 0, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_NO_ENCODE, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_DECODE, "http://h/./b");
    CANON("http://h/%2e/b", ICU_NO_META, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_ENCODE_SPACES_ONLY, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_BROWSER_MODE, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_ENCODE_PERCENT, "http://h/%252e/b");
    CANON("http://h/%2e/b", ICU_ESCAPE, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_DECODE | ICU_NO_ENCODE, "http://h/./b");
    CANON("http://h/%2e/b", ICU_NO_META | ICU_NO_ENCODE, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_USERNAME, "http://h/%2e/b");
    CANON("http://h/%2e/b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/./b");
    CANON("http://h/%2e/b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/./b");
    CANON("http://h/%2e/b", ICU_NO_META | ICU_DECODE, "http://h/./b");
}
TEST(url_crack_canon2_http_h_a_b_5) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a\\..\\b", 0, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_NO_ENCODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_DECODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_NO_META, "http://h/a/../b");
    CANON("http://h/a\\..\\b", ICU_ENCODE_SPACES_ONLY, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_BROWSER_MODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_ENCODE_PERCENT, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_ESCAPE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_DECODE | ICU_NO_ENCODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/../b");
    CANON("http://h/a\\..\\b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_USERNAME, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/b");
    CANON("http://h/a\\..\\b", ICU_NO_META | ICU_DECODE, "http://h/a/../b");
}
TEST(url_crack_canon2_http_h_a_b_c_d) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/b?c/../d", 0, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_NO_ENCODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_DECODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_NO_META, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_ENCODE_SPACES_ONLY, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_BROWSER_MODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_ENCODE_PERCENT, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_ESCAPE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_USERNAME, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/b?c/../d");
    CANON("http://h/a/b?c/../d", ICU_NO_META | ICU_DECODE, "http://h/a/b?c/../d");
}
TEST(url_crack_canon2_http_h_a_b_c_d_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a/b#c/../d", 0, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_NO_ENCODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_DECODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_NO_META, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_ENCODE_SPACES_ONLY, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_BROWSER_MODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_ENCODE_PERCENT, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_ESCAPE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_DECODE | ICU_NO_ENCODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_NO_META | ICU_NO_ENCODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_USERNAME, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a/b#c/../d");
    CANON("http://h/a/b#c/../d", ICU_NO_META | ICU_DECODE, "http://h/a/b#c/../d");
}
TEST(url_crack_canon2_http_h) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h:/", 0, "http://h:/");
    CANON("http://h:/", ICU_NO_ENCODE, "http://h:/");
    CANON("http://h:/", ICU_DECODE, "http://h:/");
    CANON("http://h:/", ICU_NO_META, "http://h:/");
    CANON("http://h:/", ICU_ENCODE_SPACES_ONLY, "http://h:/");
    CANON("http://h:/", ICU_BROWSER_MODE, "http://h:/");
    CANON("http://h:/", ICU_ENCODE_PERCENT, "http://h:/");
    CANON("http://h:/", ICU_ESCAPE, "http://h:/");
    CANON("http://h:/", ICU_DECODE | ICU_NO_ENCODE, "http://h:/");
    CANON("http://h:/", ICU_NO_META | ICU_NO_ENCODE, "http://h:/");
    CANON("http://h:/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h:/");
    CANON("http://h:/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h:/");
    CANON("http://h:/", ICU_USERNAME, "http://h:/");
    CANON("http://h:/", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h:/");
    CANON("http://h:/", ICU_BROWSER_MODE | ICU_DECODE, "http://h:/");
    CANON("http://h:/", ICU_NO_META | ICU_DECODE, "http://h:/");
}
TEST(url_crack_canon2_http_h_0080) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h:0080/", 0, "http://h:0080/");
    CANON("http://h:0080/", ICU_NO_ENCODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_DECODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_NO_META, "http://h:0080/");
    CANON("http://h:0080/", ICU_ENCODE_SPACES_ONLY, "http://h:0080/");
    CANON("http://h:0080/", ICU_BROWSER_MODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_ENCODE_PERCENT, "http://h:0080/");
    CANON("http://h:0080/", ICU_ESCAPE, "http://h:0080/");
    CANON("http://h:0080/", ICU_DECODE | ICU_NO_ENCODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_NO_META | ICU_NO_ENCODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_USERNAME, "http://h:0080/");
    CANON("http://h:0080/", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h:0080/");
    CANON("http://h:0080/", ICU_BROWSER_MODE | ICU_DECODE, "http://h:0080/");
    CANON("http://h:0080/", ICU_NO_META | ICU_DECODE, "http://h:0080/");
}
TEST(url_crack_canon2_https_h_443) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("https://h:443/", 0, "https://h/");
    CANON("https://h:443/", ICU_NO_ENCODE, "https://h/");
    CANON("https://h:443/", ICU_DECODE, "https://h/");
    CANON("https://h:443/", ICU_NO_META, "https://h/");
    CANON("https://h:443/", ICU_ENCODE_SPACES_ONLY, "https://h/");
    CANON("https://h:443/", ICU_BROWSER_MODE, "https://h/");
    CANON("https://h:443/", ICU_ENCODE_PERCENT, "https://h/");
    CANON("https://h:443/", ICU_ESCAPE, "https://h/");
    CANON("https://h:443/", ICU_DECODE | ICU_NO_ENCODE, "https://h/");
    CANON("https://h:443/", ICU_NO_META | ICU_NO_ENCODE, "https://h/");
    CANON("https://h:443/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "https://h/");
    CANON("https://h:443/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "https://h/");
    CANON("https://h:443/", ICU_USERNAME, "https://h/");
    CANON("https://h:443/", ICU_DECODE | ICU_ENCODE_PERCENT, "https://h/");
    CANON("https://h:443/", ICU_BROWSER_MODE | ICU_DECODE, "https://h/");
    CANON("https://h:443/", ICU_NO_META | ICU_DECODE, "https://h/");
}
TEST(url_crack_canon2_https_h_80) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("https://h:80/", 0, "https://h:80/");
    CANON("https://h:80/", ICU_NO_ENCODE, "https://h:80/");
    CANON("https://h:80/", ICU_DECODE, "https://h:80/");
    CANON("https://h:80/", ICU_NO_META, "https://h:80/");
    CANON("https://h:80/", ICU_ENCODE_SPACES_ONLY, "https://h:80/");
    CANON("https://h:80/", ICU_BROWSER_MODE, "https://h:80/");
    CANON("https://h:80/", ICU_ENCODE_PERCENT, "https://h:80/");
    CANON("https://h:80/", ICU_ESCAPE, "https://h:80/");
    CANON("https://h:80/", ICU_DECODE | ICU_NO_ENCODE, "https://h:80/");
    CANON("https://h:80/", ICU_NO_META | ICU_NO_ENCODE, "https://h:80/");
    CANON("https://h:80/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "https://h:80/");
    CANON("https://h:80/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "https://h:80/");
    CANON("https://h:80/", ICU_USERNAME, "https://h:80/");
    CANON("https://h:80/", ICU_DECODE | ICU_ENCODE_PERCENT, "https://h:80/");
    CANON("https://h:80/", ICU_BROWSER_MODE | ICU_DECODE, "https://h:80/");
    CANON("https://h:80/", ICU_NO_META | ICU_DECODE, "https://h:80/");
}
TEST(url_crack_canon2_ftp_h_21) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://h:21/", 0, "ftp://h/");
    CANON("ftp://h:21/", ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_DECODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_NO_META, "ftp://h/");
    CANON("ftp://h:21/", ICU_ENCODE_SPACES_ONLY, "ftp://h/");
    CANON("ftp://h:21/", ICU_BROWSER_MODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_ENCODE_PERCENT, "ftp://h/");
    CANON("ftp://h:21/", ICU_ESCAPE, "ftp://h/");
    CANON("ftp://h:21/", ICU_DECODE | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_NO_META | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_USERNAME, "ftp://h/");
    CANON("ftp://h:21/", ICU_DECODE | ICU_ENCODE_PERCENT, "ftp://h/");
    CANON("ftp://h:21/", ICU_BROWSER_MODE | ICU_DECODE, "ftp://h/");
    CANON("ftp://h:21/", ICU_NO_META | ICU_DECODE, "ftp://h/");
}
TEST(url_crack_canon2_ftp_h_2121) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://h:2121/", 0, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_NO_ENCODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_DECODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_NO_META, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_ENCODE_SPACES_ONLY, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_BROWSER_MODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_ENCODE_PERCENT, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_ESCAPE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_DECODE | ICU_NO_ENCODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_NO_META | ICU_NO_ENCODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_USERNAME, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_DECODE | ICU_ENCODE_PERCENT, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_BROWSER_MODE | ICU_DECODE, "ftp://h:2121/");
    CANON("ftp://h:2121/", ICU_NO_META | ICU_DECODE, "ftp://h:2121/");
}
TEST(url_crack_canon2_http_h_8080) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h:8080", 0, "http://h:8080/");
    CANON("http://h:8080", ICU_NO_ENCODE, "http://h:8080/");
    CANON("http://h:8080", ICU_DECODE, "http://h:8080/");
    CANON("http://h:8080", ICU_NO_META, "http://h:8080/");
    CANON("http://h:8080", ICU_ENCODE_SPACES_ONLY, "http://h:8080/");
    CANON("http://h:8080", ICU_BROWSER_MODE, "http://h:8080/");
    CANON("http://h:8080", ICU_ENCODE_PERCENT, "http://h:8080/");
    CANON("http://h:8080", ICU_ESCAPE, "http://h:8080/");
    CANON("http://h:8080", ICU_DECODE | ICU_NO_ENCODE, "http://h:8080/");
    CANON("http://h:8080", ICU_NO_META | ICU_NO_ENCODE, "http://h:8080/");
    CANON("http://h:8080", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h:8080/");
    CANON("http://h:8080", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h:8080/");
    CANON("http://h:8080", ICU_USERNAME, "http://h:8080/");
    CANON("http://h:8080", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h:8080/");
    CANON("http://h:8080", ICU_BROWSER_MODE | ICU_DECODE, "http://h:8080/");
    CANON("http://h:8080", ICU_NO_META | ICU_DECODE, "http://h:8080/");
}
TEST(url_crack_canon2_http_u_p_h_81_p) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("HTTP://U:P@H:81/P", 0, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_NO_ENCODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_DECODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_NO_META, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_ENCODE_SPACES_ONLY, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_BROWSER_MODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_ENCODE_PERCENT, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_ESCAPE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_DECODE | ICU_NO_ENCODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_NO_META | ICU_NO_ENCODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_USERNAME, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_DECODE | ICU_ENCODE_PERCENT, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_BROWSER_MODE | ICU_DECODE, "http://U:P@h:81/P");
    CANON("HTTP://U:P@H:81/P", ICU_NO_META | ICU_DECODE, "http://U:P@h:81/P");
}
TEST(url_crack_canon2_http_h_a_2fb) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/A%2fB", 0, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_NO_ENCODE, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_DECODE, "http://h/A/B");
    CANON("http://h/A%2fB", ICU_NO_META, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_ENCODE_SPACES_ONLY, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_BROWSER_MODE, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_ENCODE_PERCENT, "http://h/A%252fB");
    CANON("http://h/A%2fB", ICU_ESCAPE, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_DECODE | ICU_NO_ENCODE, "http://h/A/B");
    CANON("http://h/A%2fB", ICU_NO_META | ICU_NO_ENCODE, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_USERNAME, "http://h/A%2fB");
    CANON("http://h/A%2fB", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/A/B");
    CANON("http://h/A%2fB", ICU_BROWSER_MODE | ICU_DECODE, "http://h/A/B");
    CANON("http://h/A%2fB", ICU_NO_META | ICU_DECODE, "http://h/A/B");
}
TEST(url_crack_canon2_http_h_7e) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%7e", 0, "http://h/%7e");
    CANON("http://h/%7e", ICU_NO_ENCODE, "http://h/%7e");
    CANON("http://h/%7e", ICU_DECODE, "http://h/~");
    CANON("http://h/%7e", ICU_NO_META, "http://h/%7e");
    CANON("http://h/%7e", ICU_ENCODE_SPACES_ONLY, "http://h/%7e");
    CANON("http://h/%7e", ICU_BROWSER_MODE, "http://h/%7e");
    CANON("http://h/%7e", ICU_ENCODE_PERCENT, "http://h/%257e");
    CANON("http://h/%7e", ICU_ESCAPE, "http://h/%7e");
    CANON("http://h/%7e", ICU_DECODE | ICU_NO_ENCODE, "http://h/~");
    CANON("http://h/%7e", ICU_NO_META | ICU_NO_ENCODE, "http://h/%7e");
    CANON("http://h/%7e", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%7e");
    CANON("http://h/%7e", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%7e");
    CANON("http://h/%7e", ICU_USERNAME, "http://h/%7e");
    CANON("http://h/%7e", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/~");
    CANON("http://h/%7e", ICU_BROWSER_MODE | ICU_DECODE, "http://h/~");
    CANON("http://h/%7e", ICU_NO_META | ICU_DECODE, "http://h/~");
}
TEST(url_crack_canon2_http_h_7e_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%7E", 0, "http://h/%7E");
    CANON("http://h/%7E", ICU_NO_ENCODE, "http://h/%7E");
    CANON("http://h/%7E", ICU_DECODE, "http://h/~");
    CANON("http://h/%7E", ICU_NO_META, "http://h/%7E");
    CANON("http://h/%7E", ICU_ENCODE_SPACES_ONLY, "http://h/%7E");
    CANON("http://h/%7E", ICU_BROWSER_MODE, "http://h/%7E");
    CANON("http://h/%7E", ICU_ENCODE_PERCENT, "http://h/%257E");
    CANON("http://h/%7E", ICU_ESCAPE, "http://h/%7E");
    CANON("http://h/%7E", ICU_DECODE | ICU_NO_ENCODE, "http://h/~");
    CANON("http://h/%7E", ICU_NO_META | ICU_NO_ENCODE, "http://h/%7E");
    CANON("http://h/%7E", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%7E");
    CANON("http://h/%7E", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%7E");
    CANON("http://h/%7E", ICU_USERNAME, "http://h/%7E");
    CANON("http://h/%7E", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/~");
    CANON("http://h/%7E", ICU_BROWSER_MODE | ICU_DECODE, "http://h/~");
    CANON("http://h/%7E", ICU_NO_META | ICU_DECODE, "http://h/~");
}
TEST(url_crack_canon2_http_h_41) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%41", 0, "http://h/%41");
    CANON("http://h/%41", ICU_NO_ENCODE, "http://h/%41");
    CANON("http://h/%41", ICU_DECODE, "http://h/A");
    CANON("http://h/%41", ICU_NO_META, "http://h/%41");
    CANON("http://h/%41", ICU_ENCODE_SPACES_ONLY, "http://h/%41");
    CANON("http://h/%41", ICU_BROWSER_MODE, "http://h/%41");
    CANON("http://h/%41", ICU_ENCODE_PERCENT, "http://h/%2541");
    CANON("http://h/%41", ICU_ESCAPE, "http://h/%41");
    CANON("http://h/%41", ICU_DECODE | ICU_NO_ENCODE, "http://h/A");
    CANON("http://h/%41", ICU_NO_META | ICU_NO_ENCODE, "http://h/%41");
    CANON("http://h/%41", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%41");
    CANON("http://h/%41", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%41");
    CANON("http://h/%41", ICU_USERNAME, "http://h/%41");
    CANON("http://h/%41", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/A");
    CANON("http://h/%41", ICU_BROWSER_MODE | ICU_DECODE, "http://h/A");
    CANON("http://h/%41", ICU_NO_META | ICU_DECODE, "http://h/A");
}
TEST(url_crack_canon2_http_h_61_62) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%61%62", 0, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_NO_ENCODE, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_DECODE, "http://h/ab");
    CANON("http://h/%61%62", ICU_NO_META, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_ENCODE_SPACES_ONLY, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_BROWSER_MODE, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_ENCODE_PERCENT, "http://h/%2561%2562");
    CANON("http://h/%61%62", ICU_ESCAPE, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_DECODE | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/%61%62", ICU_NO_META | ICU_NO_ENCODE, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_USERNAME, "http://h/%61%62");
    CANON("http://h/%61%62", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/%61%62", ICU_BROWSER_MODE | ICU_DECODE, "http://h/ab");
    CANON("http://h/%61%62", ICU_NO_META | ICU_DECODE, "http://h/ab");
}
TEST(url_crack_canon2_http_h_e9) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%e9", 0, "http://h/%e9");
    CANON("http://h/%e9", ICU_NO_ENCODE, "http://h/%e9");
    CANON("http://h/%e9", ICU_DECODE, "http://h/%E9");
    CANON("http://h/%e9", ICU_NO_META, "http://h/%e9");
    CANON("http://h/%e9", ICU_ENCODE_SPACES_ONLY, "http://h/%e9");
    CANON("http://h/%e9", ICU_BROWSER_MODE, "http://h/%e9");
    CANON("http://h/%e9", ICU_ENCODE_PERCENT, "http://h/%25e9");
    CANON("http://h/%e9", ICU_ESCAPE, "http://h/%e9");
    CANON("http://h/%e9", ICU_DECODE | ICU_NO_ENCODE, "http://h/\xe9");
    CANON("http://h/%e9", ICU_NO_META | ICU_NO_ENCODE, "http://h/%e9");
    CANON("http://h/%e9", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%e9");
    CANON("http://h/%e9", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%e9");
    CANON("http://h/%e9", ICU_USERNAME, "http://h/%e9");
    CANON("http://h/%e9", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/%E9");
    CANON("http://h/%e9", ICU_BROWSER_MODE | ICU_DECODE, "http://h/%E9");
    CANON("http://h/%e9", ICU_NO_META | ICU_DECODE, "http://h/%E9");
}
TEST(url_crack_canon2_http_h_c3_a9) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%C3%A9", 0, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_NO_ENCODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_DECODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_NO_META, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_ENCODE_SPACES_ONLY, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_BROWSER_MODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_ENCODE_PERCENT, "http://h/%25C3%25A9");
    CANON("http://h/%C3%A9", ICU_ESCAPE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_DECODE | ICU_NO_ENCODE, "http://h/\xc3\xa9");
    CANON("http://h/%C3%A9", ICU_NO_META | ICU_NO_ENCODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_USERNAME, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_BROWSER_MODE | ICU_DECODE, "http://h/%C3%A9");
    CANON("http://h/%C3%A9", ICU_NO_META | ICU_DECODE, "http://h/%C3%A9");
}
TEST(url_crack_canon2_http_h_00) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%00", 0, "http://h/%00");
    CANON("http://h/%00", ICU_NO_ENCODE, "http://h/%00");
    CANON("http://h/%00", ICU_DECODE, "http://h/");
    CANON("http://h/%00", ICU_NO_META, "http://h/%00");
    CANON("http://h/%00", ICU_ENCODE_SPACES_ONLY, "http://h/%00");
    CANON("http://h/%00", ICU_BROWSER_MODE, "http://h/%00");
    CANON("http://h/%00", ICU_ENCODE_PERCENT, "http://h/%2500");
    CANON("http://h/%00", ICU_ESCAPE, "http://h/%00");
    CANON("http://h/%00", ICU_DECODE | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/%00", ICU_NO_META | ICU_NO_ENCODE, "http://h/%00");
    CANON("http://h/%00", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%00");
    CANON("http://h/%00", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%00");
    CANON("http://h/%00", ICU_USERNAME, "http://h/%00");
    CANON("http://h/%00", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/%00", ICU_BROWSER_MODE | ICU_DECODE, "http://h/");
    CANON("http://h/%00", ICU_NO_META | ICU_DECODE, "http://h/");
}
TEST(url_crack_canon2_http_h_0a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%0A", 0, "http://h/%0A");
    CANON("http://h/%0A", ICU_NO_ENCODE, "http://h/%0A");
    CANON("http://h/%0A", ICU_DECODE, "http://h/");
    CANON("http://h/%0A", ICU_NO_META, "http://h/%0A");
    CANON("http://h/%0A", ICU_ENCODE_SPACES_ONLY, "http://h/%0A");
    CANON("http://h/%0A", ICU_BROWSER_MODE, "http://h/%0A");
    CANON("http://h/%0A", ICU_ENCODE_PERCENT, "http://h/%250A");
    CANON("http://h/%0A", ICU_ESCAPE, "http://h/%0A");
    CANON("http://h/%0A", ICU_DECODE | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/%0A", ICU_NO_META | ICU_NO_ENCODE, "http://h/%0A");
    CANON("http://h/%0A", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%0A");
    CANON("http://h/%0A", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%0A");
    CANON("http://h/%0A", ICU_USERNAME, "http://h/%0A");
    CANON("http://h/%0A", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/%0A", ICU_BROWSER_MODE | ICU_DECODE, "http://h/");
    CANON("http://h/%0A", ICU_NO_META | ICU_DECODE, "http://h/");
}
TEST(url_crack_canon2_http_h_20) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%20", 0, "http://h/%20");
    CANON("http://h/%20", ICU_NO_ENCODE, "http://h/%20");
    CANON("http://h/%20", ICU_DECODE, "http://h/");
    CANON("http://h/%20", ICU_NO_META, "http://h/%20");
    CANON("http://h/%20", ICU_ENCODE_SPACES_ONLY, "http://h/%20");
    CANON("http://h/%20", ICU_BROWSER_MODE, "http://h/%20");
    CANON("http://h/%20", ICU_ENCODE_PERCENT, "http://h/%2520");
    CANON("http://h/%20", ICU_ESCAPE, "http://h/%20");
    CANON("http://h/%20", ICU_DECODE | ICU_NO_ENCODE, "http://h/");
    CANON("http://h/%20", ICU_NO_META | ICU_NO_ENCODE, "http://h/%20");
    CANON("http://h/%20", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%20");
    CANON("http://h/%20", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%20");
    CANON("http://h/%20", ICU_USERNAME, "http://h/%20");
    CANON("http://h/%20", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/");
    CANON("http://h/%20", ICU_BROWSER_MODE | ICU_DECODE, "http://h/");
    CANON("http://h/%20", ICU_NO_META | ICU_DECODE, "http://h/");
}
TEST(url_crack_canon2_http_h_2520) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/%2520", 0, "http://h/%2520");
    CANON("http://h/%2520", ICU_NO_ENCODE, "http://h/%2520");
    CANON("http://h/%2520", ICU_DECODE, "http://h/%20");
    CANON("http://h/%2520", ICU_NO_META, "http://h/%2520");
    CANON("http://h/%2520", ICU_ENCODE_SPACES_ONLY, "http://h/%2520");
    CANON("http://h/%2520", ICU_BROWSER_MODE, "http://h/%2520");
    CANON("http://h/%2520", ICU_ENCODE_PERCENT, "http://h/%252520");
    CANON("http://h/%2520", ICU_ESCAPE, "http://h/%2520");
    CANON("http://h/%2520", ICU_DECODE | ICU_NO_ENCODE, "http://h/%20");
    CANON("http://h/%2520", ICU_NO_META | ICU_NO_ENCODE, "http://h/%2520");
    CANON("http://h/%2520", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/%2520");
    CANON("http://h/%2520", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/%2520");
    CANON("http://h/%2520", ICU_USERNAME, "http://h/%2520");
    CANON("http://h/%2520", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/%2520");
    CANON("http://h/%2520", ICU_BROWSER_MODE | ICU_DECODE, "http://h/%20");
    CANON("http://h/%2520", ICU_NO_META | ICU_DECODE, "http://h/%20");
}
TEST(url_crack_canon2_http_h_a_2_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a%2", 0, "http://h/a%2");
    CANON("http://h/a%2", ICU_NO_ENCODE, "http://h/a%2");
    CANON("http://h/a%2", ICU_DECODE, "http://h/a");
    CANON("http://h/a%2", ICU_NO_META, "http://h/a%2");
    CANON("http://h/a%2", ICU_ENCODE_SPACES_ONLY, "http://h/a%2");
    CANON("http://h/a%2", ICU_BROWSER_MODE, "http://h/a%2");
    CANON("http://h/a%2", ICU_ENCODE_PERCENT, "http://h/a%252");
    CANON("http://h/a%2", ICU_ESCAPE, "http://h/a%2");
    CANON("http://h/a%2", ICU_DECODE | ICU_NO_ENCODE, "http://h/a");
    CANON("http://h/a%2", ICU_NO_META | ICU_NO_ENCODE, "http://h/a%2");
    CANON("http://h/a%2", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a%2");
    CANON("http://h/a%2", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a%2");
    CANON("http://h/a%2", ICU_USERNAME, "http://h/a%2");
    CANON("http://h/a%2", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a");
    CANON("http://h/a%2", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a");
    CANON("http://h/a%2", ICU_NO_META | ICU_DECODE, "http://h/a");
}
TEST(url_crack_canon2_http_h_a_g1) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a%g1", 0, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_NO_ENCODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_DECODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_NO_META, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_ENCODE_SPACES_ONLY, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_BROWSER_MODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_ENCODE_PERCENT, "http://h/a%25g1");
    CANON("http://h/a%g1", ICU_ESCAPE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_DECODE | ICU_NO_ENCODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_NO_META | ICU_NO_ENCODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_USERNAME, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%25g1");
    CANON("http://h/a%g1", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%g1");
    CANON("http://h/a%g1", ICU_NO_META | ICU_DECODE, "http://h/a%g1");
}
TEST(url_crack_canon2_http_h_a_b_6) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/?a b", 0, "http://h/?a b");
    CANON("http://h/?a b", ICU_NO_ENCODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_DECODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_NO_META, "http://h/?a b");
    CANON("http://h/?a b", ICU_ENCODE_SPACES_ONLY, "http://h/?a%20b");
    CANON("http://h/?a b", ICU_BROWSER_MODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_ENCODE_PERCENT, "http://h/?a b");
    CANON("http://h/?a b", ICU_ESCAPE, "http://h/?a b");
    CANON("http://h/?a b", ICU_DECODE | ICU_NO_ENCODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_NO_META | ICU_NO_ENCODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/?a%20b");
    CANON("http://h/?a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_USERNAME, "http://h/?a b");
    CANON("http://h/?a b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/?a b");
    CANON("http://h/?a b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/?a b");
    CANON("http://h/?a b", ICU_NO_META | ICU_DECODE, "http://h/?a b");
}
TEST(url_crack_canon2_http_h_a_20b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/?a%20b", 0, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_NO_ENCODE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_DECODE, "http://h/?a b");
    CANON("http://h/?a%20b", ICU_NO_META, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_ENCODE_SPACES_ONLY, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_BROWSER_MODE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_ENCODE_PERCENT, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_ESCAPE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_DECODE | ICU_NO_ENCODE, "http://h/?a b");
    CANON("http://h/?a%20b", ICU_NO_META | ICU_NO_ENCODE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_USERNAME, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/?a b");
    CANON("http://h/?a%20b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/?a%20b");
    CANON("http://h/?a%20b", ICU_NO_META | ICU_DECODE, "http://h/?a b");
}
TEST(url_crack_canon2_http_h_a_b_7) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/#a b", 0, "http://h/#a b");
    CANON("http://h/#a b", ICU_NO_ENCODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_DECODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_NO_META, "http://h/#a b");
    CANON("http://h/#a b", ICU_ENCODE_SPACES_ONLY, "http://h/#a%20b");
    CANON("http://h/#a b", ICU_BROWSER_MODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_ENCODE_PERCENT, "http://h/#a b");
    CANON("http://h/#a b", ICU_ESCAPE, "http://h/#a b");
    CANON("http://h/#a b", ICU_DECODE | ICU_NO_ENCODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_NO_META | ICU_NO_ENCODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/#a%20b");
    CANON("http://h/#a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_USERNAME, "http://h/#a b");
    CANON("http://h/#a b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/#a b");
    CANON("http://h/#a b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/#a b");
    CANON("http://h/#a b", ICU_NO_META | ICU_DECODE, "http://h/#a b");
}
TEST(url_crack_canon2_http_h_a_20b_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/#a%20b", 0, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_NO_ENCODE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_DECODE, "http://h/#a b");
    CANON("http://h/#a%20b", ICU_NO_META, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_ENCODE_SPACES_ONLY, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_BROWSER_MODE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_ENCODE_PERCENT, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_ESCAPE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_DECODE | ICU_NO_ENCODE, "http://h/#a b");
    CANON("http://h/#a%20b", ICU_NO_META | ICU_NO_ENCODE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_USERNAME, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/#a b");
    CANON("http://h/#a%20b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/#a%20b");
    CANON("http://h/#a%20b", ICU_NO_META | ICU_DECODE, "http://h/#a b");
}
TEST(url_crack_canon2_http_h_a_b_c_d_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a?b#c d", 0, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_NO_ENCODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_DECODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_NO_META, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_ENCODE_SPACES_ONLY, "http://h/a?b#c%20d");
    CANON("http://h/a?b#c d", ICU_BROWSER_MODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_ENCODE_PERCENT, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_ESCAPE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_DECODE | ICU_NO_ENCODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_NO_META | ICU_NO_ENCODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a?b#c%20d");
    CANON("http://h/a?b#c d", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_USERNAME, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a?b#c d");
    CANON("http://h/a?b#c d", ICU_NO_META | ICU_DECODE, "http://h/a?b#c d");
}
TEST(url_crack_canon2_http_h_a_b_8) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a\"b", 0, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_NO_ENCODE, "http://h/a\"b");
    CANON("http://h/a\"b", ICU_DECODE, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_NO_META, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_ENCODE_SPACES_ONLY, "http://h/a\"b");
    CANON("http://h/a\"b", ICU_BROWSER_MODE, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_ENCODE_PERCENT, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_ESCAPE, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a\"b");
    CANON("http://h/a\"b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a\"b");
    CANON("http://h/a\"b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a\"b");
    CANON("http://h/a\"b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a\"b");
    CANON("http://h/a\"b", ICU_USERNAME, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%22b");
    CANON("http://h/a\"b", ICU_NO_META | ICU_DECODE, "http://h/a%22b");
}
TEST(url_crack_canon2_http_h_a_b_9) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a'b", 0, "http://h/a'b");
    CANON("http://h/a'b", ICU_NO_ENCODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_DECODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_NO_META, "http://h/a'b");
    CANON("http://h/a'b", ICU_ENCODE_SPACES_ONLY, "http://h/a'b");
    CANON("http://h/a'b", ICU_BROWSER_MODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_ENCODE_PERCENT, "http://h/a'b");
    CANON("http://h/a'b", ICU_ESCAPE, "http://h/a'b");
    CANON("http://h/a'b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_USERNAME, "http://h/a'b");
    CANON("http://h/a'b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a'b");
    CANON("http://h/a'b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a'b");
    CANON("http://h/a'b", ICU_NO_META | ICU_DECODE, "http://h/a'b");
}
TEST(url_crack_canon2_http_h_a_b_10) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a`b", 0, "http://h/a%60b");
    CANON("http://h/a`b", ICU_NO_ENCODE, "http://h/a`b");
    CANON("http://h/a`b", ICU_DECODE, "http://h/a%60b");
    CANON("http://h/a`b", ICU_NO_META, "http://h/a%60b");
    CANON("http://h/a`b", ICU_ENCODE_SPACES_ONLY, "http://h/a`b");
    CANON("http://h/a`b", ICU_BROWSER_MODE, "http://h/a%60b");
    CANON("http://h/a`b", ICU_ENCODE_PERCENT, "http://h/a%60b");
    CANON("http://h/a`b", ICU_ESCAPE, "http://h/a%60b");
    CANON("http://h/a`b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a`b");
    CANON("http://h/a`b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a`b");
    CANON("http://h/a`b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a`b");
    CANON("http://h/a`b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a`b");
    CANON("http://h/a`b", ICU_USERNAME, "http://h/a%60b");
    CANON("http://h/a`b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%60b");
    CANON("http://h/a`b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%60b");
    CANON("http://h/a`b", ICU_NO_META | ICU_DECODE, "http://h/a%60b");
}
TEST(url_crack_canon2_http_h_a_b_11) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a{b}", 0, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_NO_ENCODE, "http://h/a{b}");
    CANON("http://h/a{b}", ICU_DECODE, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_NO_META, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_ENCODE_SPACES_ONLY, "http://h/a{b}");
    CANON("http://h/a{b}", ICU_BROWSER_MODE, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_ENCODE_PERCENT, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_ESCAPE, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_DECODE | ICU_NO_ENCODE, "http://h/a{b}");
    CANON("http://h/a{b}", ICU_NO_META | ICU_NO_ENCODE, "http://h/a{b}");
    CANON("http://h/a{b}", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a{b}");
    CANON("http://h/a{b}", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a{b}");
    CANON("http://h/a{b}", ICU_USERNAME, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%7Bb%7D");
    CANON("http://h/a{b}", ICU_NO_META | ICU_DECODE, "http://h/a%7Bb%7D");
}
TEST(url_crack_canon2_http_h_a_b_12) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a|b", 0, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_NO_ENCODE, "http://h/a|b");
    CANON("http://h/a|b", ICU_DECODE, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_NO_META, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_ENCODE_SPACES_ONLY, "http://h/a|b");
    CANON("http://h/a|b", ICU_BROWSER_MODE, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_ENCODE_PERCENT, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_ESCAPE, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a|b");
    CANON("http://h/a|b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a|b");
    CANON("http://h/a|b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a|b");
    CANON("http://h/a|b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a|b");
    CANON("http://h/a|b", ICU_USERNAME, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%7Cb");
    CANON("http://h/a|b", ICU_NO_META | ICU_DECODE, "http://h/a%7Cb");
}
TEST(url_crack_canon2_http_h_a_b_13) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a^b", 0, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_NO_ENCODE, "http://h/a^b");
    CANON("http://h/a^b", ICU_DECODE, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_NO_META, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_ENCODE_SPACES_ONLY, "http://h/a^b");
    CANON("http://h/a^b", ICU_BROWSER_MODE, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_ENCODE_PERCENT, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_ESCAPE, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a^b");
    CANON("http://h/a^b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a^b");
    CANON("http://h/a^b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a^b");
    CANON("http://h/a^b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a^b");
    CANON("http://h/a^b", ICU_USERNAME, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%5Eb");
    CANON("http://h/a^b", ICU_NO_META | ICU_DECODE, "http://h/a%5Eb");
}
TEST(url_crack_canon2_http_h_a_b_14) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a[b]", 0, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_NO_ENCODE, "http://h/a[b]");
    CANON("http://h/a[b]", ICU_DECODE, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_NO_META, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_ENCODE_SPACES_ONLY, "http://h/a[b]");
    CANON("http://h/a[b]", ICU_BROWSER_MODE, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_ENCODE_PERCENT, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_ESCAPE, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_DECODE | ICU_NO_ENCODE, "http://h/a[b]");
    CANON("http://h/a[b]", ICU_NO_META | ICU_NO_ENCODE, "http://h/a[b]");
    CANON("http://h/a[b]", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a[b]");
    CANON("http://h/a[b]", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a[b]");
    CANON("http://h/a[b]", ICU_USERNAME, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%5Bb%5D");
    CANON("http://h/a[b]", ICU_NO_META | ICU_DECODE, "http://h/a%5Bb%5D");
}
TEST(url_crack_canon2_http_h_a_b_c_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a;b=c", 0, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_NO_ENCODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_DECODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_NO_META, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_ENCODE_SPACES_ONLY, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_BROWSER_MODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_ENCODE_PERCENT, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_ESCAPE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_DECODE | ICU_NO_ENCODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_NO_META | ICU_NO_ENCODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_USERNAME, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a;b=c");
    CANON("http://h/a;b=c", ICU_NO_META | ICU_DECODE, "http://h/a;b=c");
}
TEST(url_crack_canon2_http_h_a_b_15) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a,b", 0, "http://h/a,b");
    CANON("http://h/a,b", ICU_NO_ENCODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_DECODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_NO_META, "http://h/a,b");
    CANON("http://h/a,b", ICU_ENCODE_SPACES_ONLY, "http://h/a,b");
    CANON("http://h/a,b", ICU_BROWSER_MODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_ENCODE_PERCENT, "http://h/a,b");
    CANON("http://h/a,b", ICU_ESCAPE, "http://h/a,b");
    CANON("http://h/a,b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_USERNAME, "http://h/a,b");
    CANON("http://h/a,b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a,b");
    CANON("http://h/a,b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a,b");
    CANON("http://h/a,b", ICU_NO_META | ICU_DECODE, "http://h/a,b");
}
TEST(url_crack_canon2_http_h_a_b_16) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a=b", 0, "http://h/a=b");
    CANON("http://h/a=b", ICU_NO_ENCODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_DECODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_NO_META, "http://h/a=b");
    CANON("http://h/a=b", ICU_ENCODE_SPACES_ONLY, "http://h/a=b");
    CANON("http://h/a=b", ICU_BROWSER_MODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_ENCODE_PERCENT, "http://h/a=b");
    CANON("http://h/a=b", ICU_ESCAPE, "http://h/a=b");
    CANON("http://h/a=b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_USERNAME, "http://h/a=b");
    CANON("http://h/a=b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a=b");
    CANON("http://h/a=b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a=b");
    CANON("http://h/a=b", ICU_NO_META | ICU_DECODE, "http://h/a=b");
}
TEST(url_crack_canon2_http_h_a_b_17) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a!b", 0, "http://h/a!b");
    CANON("http://h/a!b", ICU_NO_ENCODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_DECODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_NO_META, "http://h/a!b");
    CANON("http://h/a!b", ICU_ENCODE_SPACES_ONLY, "http://h/a!b");
    CANON("http://h/a!b", ICU_BROWSER_MODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_ENCODE_PERCENT, "http://h/a!b");
    CANON("http://h/a!b", ICU_ESCAPE, "http://h/a!b");
    CANON("http://h/a!b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_USERNAME, "http://h/a!b");
    CANON("http://h/a!b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a!b");
    CANON("http://h/a!b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a!b");
    CANON("http://h/a!b", ICU_NO_META | ICU_DECODE, "http://h/a!b");
}
TEST(url_crack_canon2_http_h_a_b_18) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a$b", 0, "http://h/a$b");
    CANON("http://h/a$b", ICU_NO_ENCODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_DECODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_NO_META, "http://h/a$b");
    CANON("http://h/a$b", ICU_ENCODE_SPACES_ONLY, "http://h/a$b");
    CANON("http://h/a$b", ICU_BROWSER_MODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_ENCODE_PERCENT, "http://h/a$b");
    CANON("http://h/a$b", ICU_ESCAPE, "http://h/a$b");
    CANON("http://h/a$b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_USERNAME, "http://h/a$b");
    CANON("http://h/a$b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a$b");
    CANON("http://h/a$b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a$b");
    CANON("http://h/a$b", ICU_NO_META | ICU_DECODE, "http://h/a$b");
}
TEST(url_crack_canon2_http_h_a_b_19) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a*b", 0, "http://h/a*b");
    CANON("http://h/a*b", ICU_NO_ENCODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_DECODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_NO_META, "http://h/a*b");
    CANON("http://h/a*b", ICU_ENCODE_SPACES_ONLY, "http://h/a*b");
    CANON("http://h/a*b", ICU_BROWSER_MODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_ENCODE_PERCENT, "http://h/a*b");
    CANON("http://h/a*b", ICU_ESCAPE, "http://h/a*b");
    CANON("http://h/a*b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_USERNAME, "http://h/a*b");
    CANON("http://h/a*b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a*b");
    CANON("http://h/a*b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a*b");
    CANON("http://h/a*b", ICU_NO_META | ICU_DECODE, "http://h/a*b");
}
TEST(url_crack_canon2_http_h_a_b_20) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a(b)", 0, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_NO_ENCODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_DECODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_NO_META, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_ENCODE_SPACES_ONLY, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_BROWSER_MODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_ENCODE_PERCENT, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_ESCAPE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_DECODE | ICU_NO_ENCODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_NO_META | ICU_NO_ENCODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_USERNAME, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a(b)");
    CANON("http://h/a(b)", ICU_NO_META | ICU_DECODE, "http://h/a(b)");
}
TEST(url_crack_canon2_http_h_a_b_21) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a@b", 0, "http://h/a@b");
    CANON("http://h/a@b", ICU_NO_ENCODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_DECODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_NO_META, "http://h/a@b");
    CANON("http://h/a@b", ICU_ENCODE_SPACES_ONLY, "http://h/a@b");
    CANON("http://h/a@b", ICU_BROWSER_MODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_ENCODE_PERCENT, "http://h/a@b");
    CANON("http://h/a@b", ICU_ESCAPE, "http://h/a@b");
    CANON("http://h/a@b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_USERNAME, "http://h/a@b");
    CANON("http://h/a@b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a@b");
    CANON("http://h/a@b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a@b");
    CANON("http://h/a@b", ICU_NO_META | ICU_DECODE, "http://h/a@b");
}
TEST(url_crack_canon2_http_h_a_b_22) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a:b", 0, "http://h/a:b");
    CANON("http://h/a:b", ICU_NO_ENCODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_DECODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_NO_META, "http://h/a:b");
    CANON("http://h/a:b", ICU_ENCODE_SPACES_ONLY, "http://h/a:b");
    CANON("http://h/a:b", ICU_BROWSER_MODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_ENCODE_PERCENT, "http://h/a:b");
    CANON("http://h/a:b", ICU_ESCAPE, "http://h/a:b");
    CANON("http://h/a:b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_USERNAME, "http://h/a:b");
    CANON("http://h/a:b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a:b");
    CANON("http://h/a:b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a:b");
    CANON("http://h/a:b", ICU_NO_META | ICU_DECODE, "http://h/a:b");
}
TEST(url_crack_canon2_http_h_a_b_23) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a&b", 0, "http://h/a%26b");
    CANON("http://h/a&b", ICU_NO_ENCODE, "http://h/a&b");
    CANON("http://h/a&b", ICU_DECODE, "http://h/a%26b");
    CANON("http://h/a&b", ICU_NO_META, "http://h/a%26b");
    CANON("http://h/a&b", ICU_ENCODE_SPACES_ONLY, "http://h/a&b");
    CANON("http://h/a&b", ICU_BROWSER_MODE, "http://h/a%26b");
    CANON("http://h/a&b", ICU_ENCODE_PERCENT, "http://h/a%26b");
    CANON("http://h/a&b", ICU_ESCAPE, "http://h/a%26b");
    CANON("http://h/a&b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a&b");
    CANON("http://h/a&b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a&b");
    CANON("http://h/a&b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a&b");
    CANON("http://h/a&b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a&b");
    CANON("http://h/a&b", ICU_USERNAME, "http://h/a%26b");
    CANON("http://h/a&b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a%26b");
    CANON("http://h/a&b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a%26b");
    CANON("http://h/a&b", ICU_NO_META | ICU_DECODE, "http://h/a%26b");
}
TEST(url_crack_canon2_http_h_a_b_24) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a~b", 0, "http://h/a~b");
    CANON("http://h/a~b", ICU_NO_ENCODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_DECODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_NO_META, "http://h/a~b");
    CANON("http://h/a~b", ICU_ENCODE_SPACES_ONLY, "http://h/a~b");
    CANON("http://h/a~b", ICU_BROWSER_MODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_ENCODE_PERCENT, "http://h/a~b");
    CANON("http://h/a~b", ICU_ESCAPE, "http://h/a~b");
    CANON("http://h/a~b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_USERNAME, "http://h/a~b");
    CANON("http://h/a~b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a~b");
    CANON("http://h/a~b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a~b");
    CANON("http://h/a~b", ICU_NO_META | ICU_DECODE, "http://h/a~b");
}
TEST(url_crack_canon2_http_h_a_b_25) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a_b", 0, "http://h/a_b");
    CANON("http://h/a_b", ICU_NO_ENCODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_DECODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_NO_META, "http://h/a_b");
    CANON("http://h/a_b", ICU_ENCODE_SPACES_ONLY, "http://h/a_b");
    CANON("http://h/a_b", ICU_BROWSER_MODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_ENCODE_PERCENT, "http://h/a_b");
    CANON("http://h/a_b", ICU_ESCAPE, "http://h/a_b");
    CANON("http://h/a_b", ICU_DECODE | ICU_NO_ENCODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_NO_META | ICU_NO_ENCODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_USERNAME, "http://h/a_b");
    CANON("http://h/a_b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a_b");
    CANON("http://h/a_b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a_b");
    CANON("http://h/a_b", ICU_NO_META | ICU_DECODE, "http://h/a_b");
}
TEST(url_crack_canon2_http_h_a_b_c_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a-b.c", 0, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_NO_ENCODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_DECODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_NO_META, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_ENCODE_SPACES_ONLY, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_BROWSER_MODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_ENCODE_PERCENT, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_ESCAPE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_DECODE | ICU_NO_ENCODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_NO_META | ICU_NO_ENCODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_USERNAME, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a-b.c");
    CANON("http://h/a-b.c", ICU_NO_META | ICU_DECODE, "http://h/a-b.c");
}
TEST(url_crack_canon2_http_h_a_b_26) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a\x09" "b", 0, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_DECODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_NO_META, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_ENCODE_SPACES_ONLY, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_BROWSER_MODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_ESCAPE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_DECODE | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_NO_META | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_USERNAME, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/ab");
    CANON("http://h/a\x09" "b", ICU_NO_META | ICU_DECODE, "http://h/ab");
}
TEST(url_crack_canon2_http_h_a_b_27) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a\x0d" "b", 0, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_DECODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_NO_META, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_ENCODE_SPACES_ONLY, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_BROWSER_MODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_ESCAPE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_DECODE | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_NO_META | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_USERNAME, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/ab");
    CANON("http://h/a\x0d" "b", ICU_NO_META | ICU_DECODE, "http://h/ab");
}
TEST(url_crack_canon2_http_h_a_b_28) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/a\x0a" "b", 0, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_DECODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_NO_META, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_ENCODE_SPACES_ONLY, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_BROWSER_MODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_ESCAPE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_DECODE | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_NO_META | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_USERNAME, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_BROWSER_MODE | ICU_DECODE, "http://h/ab");
    CANON("http://h/a\x0a" "b", ICU_NO_META | ICU_DECODE, "http://h/ab");
}
TEST(url_crack_canon2_http_h_a_5) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h\\a", 0, "http://h/a");
    CANON("http://h\\a", ICU_NO_ENCODE, "http://h/a");
    CANON("http://h\\a", ICU_DECODE, "http://h/a");
    CANON("http://h\\a", ICU_NO_META, "http://h/a");
    CANON("http://h\\a", ICU_ENCODE_SPACES_ONLY, "http://h/a");
    CANON("http://h\\a", ICU_BROWSER_MODE, "http://h/a");
    CANON("http://h\\a", ICU_ENCODE_PERCENT, "http://h/a");
    CANON("http://h\\a", ICU_ESCAPE, "http://h/a");
    CANON("http://h\\a", ICU_DECODE | ICU_NO_ENCODE, "http://h/a");
    CANON("http://h\\a", ICU_NO_META | ICU_NO_ENCODE, "http://h/a");
    CANON("http://h\\a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/a");
    CANON("http://h\\a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/a");
    CANON("http://h\\a", ICU_USERNAME, "http://h/a");
    CANON("http://h\\a", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/a");
    CANON("http://h\\a", ICU_BROWSER_MODE | ICU_DECODE, "http://h/a");
    CANON("http://h\\a", ICU_NO_META | ICU_DECODE, "http://h/a");
}
TEST(url_crack_canon2_http_h_example) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://H.EXAMPLE./", 0, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_NO_ENCODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_DECODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_NO_META, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_ENCODE_SPACES_ONLY, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_BROWSER_MODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_ENCODE_PERCENT, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_ESCAPE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_DECODE | ICU_NO_ENCODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_NO_META | ICU_NO_ENCODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_USERNAME, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_BROWSER_MODE | ICU_DECODE, "http://h.example./");
    CANON("http://H.EXAMPLE./", ICU_NO_META | ICU_DECODE, "http://h.example./");
}
TEST(url_crack_canon2_http_1_80) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://[::1]:80/", 0, "http://%5B::1%5D:80/");
    CANON("http://[::1]:80/", ICU_NO_ENCODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_DECODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_NO_META, "http://%5B::1%5D:80/");
    CANON("http://[::1]:80/", ICU_ENCODE_SPACES_ONLY, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_BROWSER_MODE, "http://%5B::1%5D:80/");
    CANON("http://[::1]:80/", ICU_ENCODE_PERCENT, "http://%5B::1%5D:80/");
    CANON("http://[::1]:80/", ICU_ESCAPE, "http://%5B::1%5D:80/");
    CANON("http://[::1]:80/", ICU_DECODE | ICU_NO_ENCODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_NO_META | ICU_NO_ENCODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_USERNAME, "http://%5B::1%5D:80/");
    CANON("http://[::1]:80/", ICU_DECODE | ICU_ENCODE_PERCENT, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_BROWSER_MODE | ICU_DECODE, "http://[::1]:80/");
    CANON("http://[::1]:80/", ICU_NO_META | ICU_DECODE, "http://[::1]:80/");
}
TEST(url_crack_canon2_http_fe80_1_a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://[FE80::1]/a", 0, "http://%5Bfe80::1%5D/a");
    CANON("http://[FE80::1]/a", ICU_NO_ENCODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_DECODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_NO_META, "http://%5Bfe80::1%5D/a");
    CANON("http://[FE80::1]/a", ICU_ENCODE_SPACES_ONLY, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_BROWSER_MODE, "http://%5Bfe80::1%5D/a");
    CANON("http://[FE80::1]/a", ICU_ENCODE_PERCENT, "http://%5Bfe80::1%5D/a");
    CANON("http://[FE80::1]/a", ICU_ESCAPE, "http://%5Bfe80::1%5D/a");
    CANON("http://[FE80::1]/a", ICU_DECODE | ICU_NO_ENCODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_NO_META | ICU_NO_ENCODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_USERNAME, "http://%5Bfe80::1%5D/a");
    CANON("http://[FE80::1]/a", ICU_DECODE | ICU_ENCODE_PERCENT, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_BROWSER_MODE | ICU_DECODE, "http://[fe80::1]/a");
    CANON("http://[FE80::1]/a", ICU_NO_META | ICU_DECODE, "http://[fe80::1]/a");
}
TEST(url_crack_canon2_http_h_x) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h?x", 0, "http://h/?x");
    CANON("http://h?x", ICU_NO_ENCODE, "http://h/?x");
    CANON("http://h?x", ICU_DECODE, "http://h/?x");
    CANON("http://h?x", ICU_NO_META, "http://h/?x");
    CANON("http://h?x", ICU_ENCODE_SPACES_ONLY, "http://h/?x");
    CANON("http://h?x", ICU_BROWSER_MODE, "http://h/?x");
    CANON("http://h?x", ICU_ENCODE_PERCENT, "http://h/?x");
    CANON("http://h?x", ICU_ESCAPE, "http://h/?x");
    CANON("http://h?x", ICU_DECODE | ICU_NO_ENCODE, "http://h/?x");
    CANON("http://h?x", ICU_NO_META | ICU_NO_ENCODE, "http://h/?x");
    CANON("http://h?x", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/?x");
    CANON("http://h?x", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/?x");
    CANON("http://h?x", ICU_USERNAME, "http://h/?x");
    CANON("http://h?x", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/?x");
    CANON("http://h?x", ICU_BROWSER_MODE | ICU_DECODE, "http://h/?x");
    CANON("http://h?x", ICU_NO_META | ICU_DECODE, "http://h/?x");
}
TEST(url_crack_canon2_http_h_x_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h#x", 0, "http://h/#x");
    CANON("http://h#x", ICU_NO_ENCODE, "http://h/#x");
    CANON("http://h#x", ICU_DECODE, "http://h/#x");
    CANON("http://h#x", ICU_NO_META, "http://h/#x");
    CANON("http://h#x", ICU_ENCODE_SPACES_ONLY, "http://h/#x");
    CANON("http://h#x", ICU_BROWSER_MODE, "http://h/#x");
    CANON("http://h#x", ICU_ENCODE_PERCENT, "http://h/#x");
    CANON("http://h#x", ICU_ESCAPE, "http://h/#x");
    CANON("http://h#x", ICU_DECODE | ICU_NO_ENCODE, "http://h/#x");
    CANON("http://h#x", ICU_NO_META | ICU_NO_ENCODE, "http://h/#x");
    CANON("http://h#x", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/#x");
    CANON("http://h#x", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/#x");
    CANON("http://h#x", ICU_USERNAME, "http://h/#x");
    CANON("http://h#x", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/#x");
    CANON("http://h#x", ICU_BROWSER_MODE | ICU_DECODE, "http://h/#x");
    CANON("http://h#x", ICU_NO_META | ICU_DECODE, "http://h/#x");
}
TEST(url_crack_canon2_http_h_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/?", 0, "http://h/?");
    CANON("http://h/?", ICU_NO_ENCODE, "http://h/?");
    CANON("http://h/?", ICU_DECODE, "http://h/?");
    CANON("http://h/?", ICU_NO_META, "http://h/?");
    CANON("http://h/?", ICU_ENCODE_SPACES_ONLY, "http://h/?");
    CANON("http://h/?", ICU_BROWSER_MODE, "http://h/?");
    CANON("http://h/?", ICU_ENCODE_PERCENT, "http://h/?");
    CANON("http://h/?", ICU_ESCAPE, "http://h/?");
    CANON("http://h/?", ICU_DECODE | ICU_NO_ENCODE, "http://h/?");
    CANON("http://h/?", ICU_NO_META | ICU_NO_ENCODE, "http://h/?");
    CANON("http://h/?", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/?");
    CANON("http://h/?", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/?");
    CANON("http://h/?", ICU_USERNAME, "http://h/?");
    CANON("http://h/?", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/?");
    CANON("http://h/?", ICU_BROWSER_MODE | ICU_DECODE, "http://h/?");
    CANON("http://h/?", ICU_NO_META | ICU_DECODE, "http://h/?");
}
TEST(url_crack_canon2_http_h_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/#", 0, "http://h/#");
    CANON("http://h/#", ICU_NO_ENCODE, "http://h/#");
    CANON("http://h/#", ICU_DECODE, "http://h/#");
    CANON("http://h/#", ICU_NO_META, "http://h/#");
    CANON("http://h/#", ICU_ENCODE_SPACES_ONLY, "http://h/#");
    CANON("http://h/#", ICU_BROWSER_MODE, "http://h/#");
    CANON("http://h/#", ICU_ENCODE_PERCENT, "http://h/#");
    CANON("http://h/#", ICU_ESCAPE, "http://h/#");
    CANON("http://h/#", ICU_DECODE | ICU_NO_ENCODE, "http://h/#");
    CANON("http://h/#", ICU_NO_META | ICU_NO_ENCODE, "http://h/#");
    CANON("http://h/#", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/#");
    CANON("http://h/#", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/#");
    CANON("http://h/#", ICU_USERNAME, "http://h/#");
    CANON("http://h/#", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/#");
    CANON("http://h/#", ICU_BROWSER_MODE | ICU_DECODE, "http://h/#");
    CANON("http://h/#", ICU_NO_META | ICU_DECODE, "http://h/#");
}
TEST(url_crack_canon2_https_h) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("https://h", 0, "https://h/");
    CANON("https://h", ICU_NO_ENCODE, "https://h/");
    CANON("https://h", ICU_DECODE, "https://h/");
    CANON("https://h", ICU_NO_META, "https://h/");
    CANON("https://h", ICU_ENCODE_SPACES_ONLY, "https://h/");
    CANON("https://h", ICU_BROWSER_MODE, "https://h/");
    CANON("https://h", ICU_ENCODE_PERCENT, "https://h/");
    CANON("https://h", ICU_ESCAPE, "https://h/");
    CANON("https://h", ICU_DECODE | ICU_NO_ENCODE, "https://h/");
    CANON("https://h", ICU_NO_META | ICU_NO_ENCODE, "https://h/");
    CANON("https://h", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "https://h/");
    CANON("https://h", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "https://h/");
    CANON("https://h", ICU_USERNAME, "https://h/");
    CANON("https://h", ICU_DECODE | ICU_ENCODE_PERCENT, "https://h/");
    CANON("https://h", ICU_BROWSER_MODE | ICU_DECODE, "https://h/");
    CANON("https://h", ICU_NO_META | ICU_DECODE, "https://h/");
}
TEST(url_crack_canon2_ftp_h) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://h", 0, "ftp://h/");
    CANON("ftp://h", ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h", ICU_DECODE, "ftp://h/");
    CANON("ftp://h", ICU_NO_META, "ftp://h/");
    CANON("ftp://h", ICU_ENCODE_SPACES_ONLY, "ftp://h/");
    CANON("ftp://h", ICU_BROWSER_MODE, "ftp://h/");
    CANON("ftp://h", ICU_ENCODE_PERCENT, "ftp://h/");
    CANON("ftp://h", ICU_ESCAPE, "ftp://h/");
    CANON("ftp://h", ICU_DECODE | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h", ICU_NO_META | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://h/");
    CANON("ftp://h", ICU_USERNAME, "ftp://h/");
    CANON("ftp://h", ICU_DECODE | ICU_ENCODE_PERCENT, "ftp://h/");
    CANON("ftp://h", ICU_BROWSER_MODE | ICU_DECODE, "ftp://h/");
    CANON("ftp://h", ICU_NO_META | ICU_DECODE, "ftp://h/");
}
TEST(url_crack_canon2_ftp_h_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://h/a/./b/../c", 0, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_NO_ENCODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_DECODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_NO_META, "ftp://h/a/./b/../c");
    CANON("ftp://h/a/./b/../c", ICU_ENCODE_SPACES_ONLY, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_BROWSER_MODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_ENCODE_PERCENT, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_ESCAPE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_DECODE | ICU_NO_ENCODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_NO_META | ICU_NO_ENCODE, "ftp://h/a/./b/../c");
    CANON("ftp://h/a/./b/../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_USERNAME, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_DECODE | ICU_ENCODE_PERCENT, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_BROWSER_MODE | ICU_DECODE, "ftp://h/a/c");
    CANON("ftp://h/a/./b/../c", ICU_NO_META | ICU_DECODE, "ftp://h/a/./b/../c");
}
TEST(url_crack_canon2_ftp_h_a_20b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("ftp://h/a%20b", 0, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_NO_ENCODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_DECODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_NO_META, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_ENCODE_SPACES_ONLY, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_BROWSER_MODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_ENCODE_PERCENT, "ftp://h/a%2520b");
    CANON("ftp://h/a%20b", ICU_ESCAPE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_DECODE | ICU_NO_ENCODE, "ftp://h/a b");
    CANON("ftp://h/a%20b", ICU_NO_META | ICU_NO_ENCODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_USERNAME, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_DECODE | ICU_ENCODE_PERCENT, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_BROWSER_MODE | ICU_DECODE, "ftp://h/a%20b");
    CANON("ftp://h/a%20b", ICU_NO_META | ICU_DECODE, "ftp://h/a%20b");
}
TEST(url_crack_canon2_file_c_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a/./b", 0, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_NO_ENCODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_DECODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_NO_META, "file://C:\\a\\.\\b");
    CANON("file:///C:/a/./b", ICU_ENCODE_SPACES_ONLY, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_BROWSER_MODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_ENCODE_PERCENT, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_ESCAPE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\.\\b");
    CANON("file:///C:/a/./b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_USERNAME, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\a\\b");
    CANON("file:///C:/a/./b", ICU_NO_META | ICU_DECODE, "file://C:\\a\\.\\b");
}
TEST(url_crack_canon2_file_c_a_b_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a/../../b", 0, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_NO_ENCODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_DECODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_NO_META, "file://C:\\a\\..\\..\\b");
    CANON("file:///C:/a/../../b", ICU_ENCODE_SPACES_ONLY, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_BROWSER_MODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_ENCODE_PERCENT, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_ESCAPE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a\\..\\..\\b");
    CANON("file:///C:/a/../../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_USERNAME, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\..\\b");
    CANON("file:///C:/a/../../b", ICU_NO_META | ICU_DECODE, "file://C:\\a\\..\\..\\b");
}
TEST(url_crack_canon2_file_c_a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///c|/a", 0, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_NO_ENCODE, "file://c|\\a");
    CANON("file:///c|/a", ICU_DECODE, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_NO_META, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_ENCODE_SPACES_ONLY, "file://c|\\a");
    CANON("file:///c|/a", ICU_BROWSER_MODE, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_ENCODE_PERCENT, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_ESCAPE, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_DECODE | ICU_NO_ENCODE, "file://c|\\a");
    CANON("file:///c|/a", ICU_NO_META | ICU_NO_ENCODE, "file://c|\\a");
    CANON("file:///c|/a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://c|\\a");
    CANON("file:///c|/a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://c|\\a");
    CANON("file:///c|/a", ICU_USERNAME, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_DECODE | ICU_ENCODE_PERCENT, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_BROWSER_MODE | ICU_DECODE, "file://\\c%7C\\a");
    CANON("file:///c|/a", ICU_NO_META | ICU_DECODE, "file://\\c%7C\\a");
}
TEST(url_crack_canon2_file_server_share_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file://server/share/a b", 0, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_NO_ENCODE, "file://\\\\server\\share\\a b");
    CANON("file://server/share/a b", ICU_DECODE, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_NO_META, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_ENCODE_SPACES_ONLY, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_BROWSER_MODE, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_ENCODE_PERCENT, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_ESCAPE, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_DECODE | ICU_NO_ENCODE, "file://\\\\server\\share\\a b");
    CANON("file://server/share/a b", ICU_NO_META | ICU_NO_ENCODE, "file://\\\\server\\share\\a b");
    CANON("file://server/share/a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://\\\\server\\share\\a b");
    CANON("file://server/share/a b", ICU_USERNAME, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_DECODE | ICU_ENCODE_PERCENT, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_BROWSER_MODE | ICU_DECODE, "file://\\\\server\\share\\a%20b");
    CANON("file://server/share/a b", ICU_NO_META | ICU_DECODE, "file://\\\\server\\share\\a%20b");
}
TEST(url_crack_canon2_file_c_a_2fb) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a%2fb", 0, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_NO_ENCODE, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_DECODE, "file://C:\\a\\b");
    CANON("file:///C:/a%2fb", ICU_NO_META, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_ENCODE_SPACES_ONLY, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_BROWSER_MODE, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_ENCODE_PERCENT, "file://C:\\a%252fb");
    CANON("file:///C:/a%2fb", ICU_ESCAPE, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a\\b");
    CANON("file:///C:/a%2fb", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_USERNAME, "file://C:\\a%2fb");
    CANON("file:///C:/a%2fb", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\a\\b");
    CANON("file:///C:/a%2fb", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\a\\b");
    CANON("file:///C:/a%2fb", ICU_NO_META | ICU_DECODE, "file://C:\\a\\b");
}
TEST(url_crack_canon2_file_c_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a?b c", 0, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_NO_ENCODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_DECODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_NO_META, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_ENCODE_SPACES_ONLY, "file://C:\\a?b%20c");
    CANON("file:///C:/a?b c", ICU_BROWSER_MODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_ENCODE_PERCENT, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_ESCAPE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a?b%20c");
    CANON("file:///C:/a?b c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_USERNAME, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\a?b c");
    CANON("file:///C:/a?b c", ICU_NO_META | ICU_DECODE, "file://C:\\a?b c");
}
TEST(url_crack_canon2_file_c_a_b_c_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///C:/a#b c", 0, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_NO_ENCODE, "file://C:\\a#b c");
    CANON("file:///C:/a#b c", ICU_DECODE, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_NO_META, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_ENCODE_SPACES_ONLY, "file://C:\\a#b%20c");
    CANON("file:///C:/a#b c", ICU_BROWSER_MODE, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_ENCODE_PERCENT, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_ESCAPE, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a#b c");
    CANON("file:///C:/a#b c", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a#b c");
    CANON("file:///C:/a#b c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a#b%20c");
    CANON("file:///C:/a#b c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a#b c");
    CANON("file:///C:/a#b c", ICU_USERNAME, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\a%23b%20c");
    CANON("file:///C:/a#b c", ICU_NO_META | ICU_DECODE, "file://C:\\a%23b%20c");
}
TEST(url_crack_canon2_file_c_a_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:C:/a", 0, "file://C:\\a");
    CANON("file:C:/a", ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:C:/a", ICU_DECODE, "file://C:\\a");
    CANON("file:C:/a", ICU_NO_META, "file://C:\\a");
    CANON("file:C:/a", ICU_ENCODE_SPACES_ONLY, "file://C:\\a");
    CANON("file:C:/a", ICU_BROWSER_MODE, "file://C:\\a");
    CANON("file:C:/a", ICU_ENCODE_PERCENT, "file://C:\\a");
    CANON("file:C:/a", ICU_ESCAPE, "file://C:\\a");
    CANON("file:C:/a", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:C:/a", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:C:/a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:C:/a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:C:/a", ICU_USERNAME, "file://C:\\a");
    CANON("file:C:/a", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\a");
    CANON("file:C:/a", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\a");
    CANON("file:C:/a", ICU_NO_META | ICU_DECODE, "file://C:\\a");
}
TEST(url_crack_canon2_file_c_a_3) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:/C:/a", 0, "file://C:\\a");
    CANON("file:/C:/a", ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_DECODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_NO_META, "file://C:\\a");
    CANON("file:/C:/a", ICU_ENCODE_SPACES_ONLY, "file://C:\\a");
    CANON("file:/C:/a", ICU_BROWSER_MODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_ENCODE_PERCENT, "file://C:\\a");
    CANON("file:/C:/a", ICU_ESCAPE, "file://C:\\a");
    CANON("file:/C:/a", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_USERNAME, "file://C:\\a");
    CANON("file:/C:/a", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\a");
    CANON("file:/C:/a", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\a");
    CANON("file:/C:/a", ICU_NO_META | ICU_DECODE, "file://C:\\a");
}
TEST(url_crack_canon2_file_etc_x) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("file:///etc/x", 0, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_NO_ENCODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_DECODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_NO_META, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_ENCODE_SPACES_ONLY, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_BROWSER_MODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_ENCODE_PERCENT, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_ESCAPE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_DECODE | ICU_NO_ENCODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_NO_META | ICU_NO_ENCODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_USERNAME, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_DECODE | ICU_ENCODE_PERCENT, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_BROWSER_MODE | ICU_DECODE, "file://\\etc\\x");
    CANON("file:///etc/x", ICU_NO_META | ICU_DECODE, "file://\\etc\\x");
}
TEST(url_crack_canon2_file_c_a_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("FILE:///C:/A", 0, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_NO_ENCODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_DECODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_NO_META, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_ENCODE_SPACES_ONLY, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_BROWSER_MODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_ENCODE_PERCENT, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_ESCAPE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_DECODE | ICU_NO_ENCODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_NO_META | ICU_NO_ENCODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_USERNAME, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_DECODE | ICU_ENCODE_PERCENT, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_BROWSER_MODE | ICU_DECODE, "file://C:\\A");
    CANON("FILE:///C:/A", ICU_NO_META | ICU_DECODE, "file://C:\\A");
}
TEST(url_crack_canon2_mailto_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("mailto:A@B", 0, "mailto:A@B");
    CANON("mailto:A@B", ICU_NO_ENCODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_DECODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_NO_META, "mailto:A@B");
    CANON("mailto:A@B", ICU_ENCODE_SPACES_ONLY, "mailto:A@B");
    CANON("mailto:A@B", ICU_BROWSER_MODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_ENCODE_PERCENT, "mailto:A@B");
    CANON("mailto:A@B", ICU_ESCAPE, "mailto:A@B");
    CANON("mailto:A@B", ICU_DECODE | ICU_NO_ENCODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_NO_META | ICU_NO_ENCODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_USERNAME, "mailto:A@B");
    CANON("mailto:A@B", ICU_DECODE | ICU_ENCODE_PERCENT, "mailto:A@B");
    CANON("mailto:A@B", ICU_BROWSER_MODE | ICU_DECODE, "mailto:A@B");
    CANON("mailto:A@B", ICU_NO_META | ICU_DECODE, "mailto:A@B");
}
TEST(url_crack_canon2_mailto_a_b_subject_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("mailto:a@b?subject=a b", 0, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_NO_ENCODE, "mailto:a@b?subject=a b");
    CANON("mailto:a@b?subject=a b", ICU_DECODE, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_NO_META, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_ENCODE_SPACES_ONLY, "mailto:a@b?subject=a b");
    CANON("mailto:a@b?subject=a b", ICU_BROWSER_MODE, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_ENCODE_PERCENT, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_ESCAPE, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_DECODE | ICU_NO_ENCODE, "mailto:a@b?subject=a b");
    CANON("mailto:a@b?subject=a b", ICU_NO_META | ICU_NO_ENCODE, "mailto:a@b?subject=a b");
    CANON("mailto:a@b?subject=a b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "mailto:a@b?subject=a b");
    CANON("mailto:a@b?subject=a b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "mailto:a@b?subject=a b");
    CANON("mailto:a@b?subject=a b", ICU_USERNAME, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_DECODE | ICU_ENCODE_PERCENT, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_BROWSER_MODE | ICU_DECODE, "mailto:a@b%3Fsubject=a%20b");
    CANON("mailto:a@b?subject=a b", ICU_NO_META | ICU_DECODE, "mailto:a@b%3Fsubject=a%20b");
}
TEST(url_crack_canon2_news_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("news:A B", 0, "news:A%20B");
    CANON("news:A B", ICU_NO_ENCODE, "news:A B");
    CANON("news:A B", ICU_DECODE, "news:A%20B");
    CANON("news:A B", ICU_NO_META, "news:A%20B");
    CANON("news:A B", ICU_ENCODE_SPACES_ONLY, "news:A%20B");
    CANON("news:A B", ICU_BROWSER_MODE, "news:A%20B");
    CANON("news:A B", ICU_ENCODE_PERCENT, "news:A%20B");
    CANON("news:A B", ICU_ESCAPE, "news:A%20B");
    CANON("news:A B", ICU_DECODE | ICU_NO_ENCODE, "news:A B");
    CANON("news:A B", ICU_NO_META | ICU_NO_ENCODE, "news:A B");
    CANON("news:A B", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "news:A%20B");
    CANON("news:A B", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "news:A B");
    CANON("news:A B", ICU_USERNAME, "news:A%20B");
    CANON("news:A B", ICU_DECODE | ICU_ENCODE_PERCENT, "news:A%20B");
    CANON("news:A B", ICU_BROWSER_MODE | ICU_DECODE, "news:A%20B");
    CANON("news:A B", ICU_NO_META | ICU_DECODE, "news:A%20B");
}
TEST(url_crack_canon2_javascript_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("javascript:a/../b", 0, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_NO_ENCODE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_DECODE, "javascript:a%2F..%2Fb");
    CANON("javascript:a/../b", ICU_NO_META, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_ENCODE_SPACES_ONLY, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_BROWSER_MODE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_ENCODE_PERCENT, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_ESCAPE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_DECODE | ICU_NO_ENCODE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_NO_META | ICU_NO_ENCODE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_USERNAME, "javascript:a/../b");
    CANON("javascript:a/../b", ICU_DECODE | ICU_ENCODE_PERCENT, "javascript:a%2F..%2Fb");
    CANON("javascript:a/../b", ICU_BROWSER_MODE | ICU_DECODE, "javascript:a%2F..%2Fb");
    CANON("javascript:a/../b", ICU_NO_META | ICU_DECODE, "javascript:a%2F..%2Fb");
}
TEST(url_crack_canon2_about_blank) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("about:Blank", 0, "about:Blank");
    CANON("about:Blank", ICU_NO_ENCODE, "about:Blank");
    CANON("about:Blank", ICU_DECODE, "about:Blank");
    CANON("about:Blank", ICU_NO_META, "about:Blank");
    CANON("about:Blank", ICU_ENCODE_SPACES_ONLY, "about:Blank");
    CANON("about:Blank", ICU_BROWSER_MODE, "about:Blank");
    CANON("about:Blank", ICU_ENCODE_PERCENT, "about:Blank");
    CANON("about:Blank", ICU_ESCAPE, "about:Blank");
    CANON("about:Blank", ICU_DECODE | ICU_NO_ENCODE, "about:Blank");
    CANON("about:Blank", ICU_NO_META | ICU_NO_ENCODE, "about:Blank");
    CANON("about:Blank", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "about:Blank");
    CANON("about:Blank", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "about:Blank");
    CANON("about:Blank", ICU_USERNAME, "about:Blank");
    CANON("about:Blank", ICU_DECODE | ICU_ENCODE_PERCENT, "about:Blank");
    CANON("about:Blank", ICU_BROWSER_MODE | ICU_DECODE, "about:Blank");
    CANON("about:Blank", ICU_NO_META | ICU_DECODE, "about:Blank");
}
TEST(url_crack_canon2_res_x_dll_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("res://x.dll/a/../b", 0, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_NO_ENCODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_DECODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_NO_META, "res://x.dll/a/../b");
    CANON("res://x.dll/a/../b", ICU_ENCODE_SPACES_ONLY, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_BROWSER_MODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_ENCODE_PERCENT, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_ESCAPE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_DECODE | ICU_NO_ENCODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_NO_META | ICU_NO_ENCODE, "res://x.dll/a/../b");
    CANON("res://x.dll/a/../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_USERNAME, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_DECODE | ICU_ENCODE_PERCENT, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_BROWSER_MODE | ICU_DECODE, "res://x.dll/b");
    CANON("res://x.dll/a/../b", ICU_NO_META | ICU_DECODE, "res://x.dll/a/../b");
}
TEST(url_crack_canon2_foo_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("foo:A/../B", 0, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_NO_ENCODE, "foo:A/../B");
    CANON("foo:A/../B", ICU_DECODE, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_NO_META, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_ENCODE_SPACES_ONLY, "foo:A/../B");
    CANON("foo:A/../B", ICU_BROWSER_MODE, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_ENCODE_PERCENT, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_ESCAPE, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_DECODE | ICU_NO_ENCODE, "foo:A/../B");
    CANON("foo:A/../B", ICU_NO_META | ICU_NO_ENCODE, "foo:A/../B");
    CANON("foo:A/../B", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "foo:A/../B");
    CANON("foo:A/../B", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "foo:A/../B");
    CANON("foo:A/../B", ICU_USERNAME, "foo:A/../B");
    CANON("foo:A/../B", ICU_DECODE | ICU_ENCODE_PERCENT, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_BROWSER_MODE | ICU_DECODE, "foo:A%2F..%2FB");
    CANON("foo:A/../B", ICU_NO_META | ICU_DECODE, "foo:A%2F..%2FB");
}
TEST(url_crack_canon2_foo_h_80_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("foo://H:80/a/./b", 0, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_NO_ENCODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_DECODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_NO_META, "foo://H:80/a/./b");
    CANON("foo://H:80/a/./b", ICU_ENCODE_SPACES_ONLY, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_BROWSER_MODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_ENCODE_PERCENT, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_ESCAPE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_DECODE | ICU_NO_ENCODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_NO_META | ICU_NO_ENCODE, "foo://H:80/a/./b");
    CANON("foo://H:80/a/./b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_USERNAME, "foo://H:80/a/./b");
    CANON("foo://H:80/a/./b", ICU_DECODE | ICU_ENCODE_PERCENT, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_BROWSER_MODE | ICU_DECODE, "foo://H:80/a/b");
    CANON("foo://H:80/a/./b", ICU_NO_META | ICU_DECODE, "foo://H:80/a/./b");
}
TEST(url_crack_canon2_foo_h_a_b_c_d) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("foo://h/a b?c d", 0, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_NO_ENCODE, "foo://h/a b?c d");
    CANON("foo://h/a b?c d", ICU_DECODE, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_NO_META, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_ENCODE_SPACES_ONLY, "foo://h/a%20b?c%20d");
    CANON("foo://h/a b?c d", ICU_BROWSER_MODE, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_ENCODE_PERCENT, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_ESCAPE, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_DECODE | ICU_NO_ENCODE, "foo://h/a b?c d");
    CANON("foo://h/a b?c d", ICU_NO_META | ICU_NO_ENCODE, "foo://h/a b?c d");
    CANON("foo://h/a b?c d", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "foo://h/a%20b?c%20d");
    CANON("foo://h/a b?c d", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "foo://h/a b?c d");
    CANON("foo://h/a b?c d", ICU_USERNAME, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_DECODE | ICU_ENCODE_PERCENT, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_BROWSER_MODE | ICU_DECODE, "foo://h/a%20b?c d");
    CANON("foo://h/a b?c d", ICU_NO_META | ICU_DECODE, "foo://h/a%20b?c d");
}
TEST(url_crack_canon2_x) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("x:", 0, "file://x:");
    CANON("x:", ICU_NO_ENCODE, "file://x:");
    CANON("x:", ICU_DECODE, "file://x:");
    CANON("x:", ICU_NO_META, "file://x:");
    CANON("x:", ICU_ENCODE_SPACES_ONLY, "file://x:");
    CANON("x:", ICU_BROWSER_MODE, "file://x:");
    CANON("x:", ICU_ENCODE_PERCENT, "file://x:");
    CANON("x:", ICU_ESCAPE, "file://x:");
    CANON("x:", ICU_DECODE | ICU_NO_ENCODE, "file://x:");
    CANON("x:", ICU_NO_META | ICU_NO_ENCODE, "file://x:");
    CANON("x:", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "file://x:");
    CANON("x:", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "file://x:");
    CANON("x:", ICU_USERNAME, "file://x:");
    CANON("x:", ICU_DECODE | ICU_ENCODE_PERCENT, "file://x:");
    CANON("x:", ICU_BROWSER_MODE | ICU_DECODE, "file://x:");
    CANON("x:", ICU_NO_META | ICU_DECODE, "file://x:");
}
TEST(url_crack_canon2_http) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http:", 0, "http:");
    CANON("http:", ICU_NO_ENCODE, "http:");
    CANON("http:", ICU_DECODE, "http:");
    CANON("http:", ICU_NO_META, "http:");
    CANON("http:", ICU_ENCODE_SPACES_ONLY, "http:");
    CANON("http:", ICU_BROWSER_MODE, "http:");
    CANON("http:", ICU_ENCODE_PERCENT, "http:");
    CANON("http:", ICU_ESCAPE, "http:");
    CANON("http:", ICU_DECODE | ICU_NO_ENCODE, "http:");
    CANON("http:", ICU_NO_META | ICU_NO_ENCODE, "http:");
    CANON("http:", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http:");
    CANON("http:", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http:");
    CANON("http:", ICU_USERNAME, "http:");
    CANON("http:", ICU_DECODE | ICU_ENCODE_PERCENT, "http:");
    CANON("http:", ICU_BROWSER_MODE | ICU_DECODE, "http:");
    CANON("http:", ICU_NO_META | ICU_DECODE, "http:");
}
TEST(url_crack_canon2_http_2) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://", 0, "http:///");
    CANON("http://", ICU_NO_ENCODE, "http:///");
    CANON("http://", ICU_DECODE, "http:///");
    CANON("http://", ICU_NO_META, "http:///");
    CANON("http://", ICU_ENCODE_SPACES_ONLY, "http:///");
    CANON("http://", ICU_BROWSER_MODE, "http:///");
    CANON("http://", ICU_ENCODE_PERCENT, "http:///");
    CANON("http://", ICU_ESCAPE, "http:///");
    CANON("http://", ICU_DECODE | ICU_NO_ENCODE, "http:///");
    CANON("http://", ICU_NO_META | ICU_NO_ENCODE, "http:///");
    CANON("http://", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http:///");
    CANON("http://", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http:///");
    CANON("http://", ICU_USERNAME, "http:///");
    CANON("http://", ICU_DECODE | ICU_ENCODE_PERCENT, "http:///");
    CANON("http://", ICU_BROWSER_MODE | ICU_DECODE, "http:///");
    CANON("http://", ICU_NO_META | ICU_DECODE, "http:///");
}
TEST(url_crack_canon2_http_a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http:///a", 0, "http:///a");
    CANON("http:///a", ICU_NO_ENCODE, "http:///a");
    CANON("http:///a", ICU_DECODE, "http:///a");
    CANON("http:///a", ICU_NO_META, "http:///a");
    CANON("http:///a", ICU_ENCODE_SPACES_ONLY, "http:///a");
    CANON("http:///a", ICU_BROWSER_MODE, "http:///a");
    CANON("http:///a", ICU_ENCODE_PERCENT, "http:///a");
    CANON("http:///a", ICU_ESCAPE, "http:///a");
    CANON("http:///a", ICU_DECODE | ICU_NO_ENCODE, "http:///a");
    CANON("http:///a", ICU_NO_META | ICU_NO_ENCODE, "http:///a");
    CANON("http:///a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http:///a");
    CANON("http:///a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http:///a");
    CANON("http:///a", ICU_USERNAME, "http:///a");
    CANON("http:///a", ICU_DECODE | ICU_ENCODE_PERCENT, "http:///a");
    CANON("http:///a", ICU_BROWSER_MODE | ICU_DECODE, "http:///a");
    CANON("http:///a", ICU_NO_META | ICU_DECODE, "http:///a");
}
TEST(url_crack_canon2_h_a) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("//h/a", 0, "//h/a");
    CANON("//h/a", ICU_NO_ENCODE, "//h/a");
    CANON("//h/a", ICU_DECODE, "//h/a");
    CANON("//h/a", ICU_NO_META, "//h/a");
    CANON("//h/a", ICU_ENCODE_SPACES_ONLY, "//h/a");
    CANON("//h/a", ICU_BROWSER_MODE, "//h/a");
    CANON("//h/a", ICU_ENCODE_PERCENT, "//h/a");
    CANON("//h/a", ICU_ESCAPE, "//h/a");
    CANON("//h/a", ICU_DECODE | ICU_NO_ENCODE, "//h/a");
    CANON("//h/a", ICU_NO_META | ICU_NO_ENCODE, "//h/a");
    CANON("//h/a", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "//h/a");
    CANON("//h/a", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "//h/a");
    CANON("//h/a", ICU_USERNAME, "//h/a");
    CANON("//h/a", ICU_DECODE | ICU_ENCODE_PERCENT, "//h/a");
    CANON("//h/a", ICU_BROWSER_MODE | ICU_DECODE, "//h/a");
    CANON("//h/a", ICU_NO_META | ICU_DECODE, "//h/a");
}
TEST(url_crack_canon2_h_a_b) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("h/a/../b", 0, "h/b");
    CANON("h/a/../b", ICU_NO_ENCODE, "h/b");
    CANON("h/a/../b", ICU_DECODE, "h/b");
    CANON("h/a/../b", ICU_NO_META, "h/a/../b");
    CANON("h/a/../b", ICU_ENCODE_SPACES_ONLY, "h/b");
    CANON("h/a/../b", ICU_BROWSER_MODE, "h/b");
    CANON("h/a/../b", ICU_ENCODE_PERCENT, "h/b");
    CANON("h/a/../b", ICU_ESCAPE, "h/b");
    CANON("h/a/../b", ICU_DECODE | ICU_NO_ENCODE, "h/b");
    CANON("h/a/../b", ICU_NO_META | ICU_NO_ENCODE, "h/a/../b");
    CANON("h/a/../b", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "h/b");
    CANON("h/a/../b", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "h/b");
    CANON("h/a/../b", ICU_USERNAME, "h/b");
    CANON("h/a/../b", ICU_DECODE | ICU_ENCODE_PERCENT, "h/b");
    CANON("h/a/../b", ICU_BROWSER_MODE | ICU_DECODE, "h/b");
    CANON("h/a/../b", ICU_NO_META | ICU_DECODE, "h/a/../b");
}
TEST(url_crack_canon2_a_b_c) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("/a/./b/../c", 0, "/a/c");
    CANON("/a/./b/../c", ICU_NO_ENCODE, "/a/c");
    CANON("/a/./b/../c", ICU_DECODE, "/a/c");
    CANON("/a/./b/../c", ICU_NO_META, "/a/./b/../c");
    CANON("/a/./b/../c", ICU_ENCODE_SPACES_ONLY, "/a/c");
    CANON("/a/./b/../c", ICU_BROWSER_MODE, "/a/c");
    CANON("/a/./b/../c", ICU_ENCODE_PERCENT, "/a/c");
    CANON("/a/./b/../c", ICU_ESCAPE, "/a/c");
    CANON("/a/./b/../c", ICU_DECODE | ICU_NO_ENCODE, "/a/c");
    CANON("/a/./b/../c", ICU_NO_META | ICU_NO_ENCODE, "/a/./b/../c");
    CANON("/a/./b/../c", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "/a/c");
    CANON("/a/./b/../c", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "/a/c");
    CANON("/a/./b/../c", ICU_USERNAME, "/a/c");
    CANON("/a/./b/../c", ICU_DECODE | ICU_ENCODE_PERCENT, "/a/c");
    CANON("/a/./b/../c", ICU_BROWSER_MODE | ICU_DECODE, "/a/c");
    CANON("/a/./b/../c", ICU_NO_META | ICU_DECODE, "/a/./b/../c");
}
TEST(url_crack_canon2_q) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("?q", 0, "?q");
    CANON("?q", ICU_NO_ENCODE, "?q");
    CANON("?q", ICU_DECODE, "?q");
    CANON("?q", ICU_NO_META, "?q");
    CANON("?q", ICU_ENCODE_SPACES_ONLY, "?q");
    CANON("?q", ICU_BROWSER_MODE, "?q");
    CANON("?q", ICU_ENCODE_PERCENT, "?q");
    CANON("?q", ICU_ESCAPE, "?q");
    CANON("?q", ICU_DECODE | ICU_NO_ENCODE, "?q");
    CANON("?q", ICU_NO_META | ICU_NO_ENCODE, "?q");
    CANON("?q", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "?q");
    CANON("?q", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "?q");
    CANON("?q", ICU_USERNAME, "?q");
    CANON("?q", ICU_DECODE | ICU_ENCODE_PERCENT, "?q");
    CANON("?q", ICU_BROWSER_MODE | ICU_DECODE, "?q");
    CANON("?q", ICU_NO_META | ICU_DECODE, "?q");
}
TEST(url_crack_canon2_f) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("#f", 0, "#f");
    CANON("#f", ICU_NO_ENCODE, "#f");
    CANON("#f", ICU_DECODE, "#f");
    CANON("#f", ICU_NO_META, "#f");
    CANON("#f", ICU_ENCODE_SPACES_ONLY, "#f");
    CANON("#f", ICU_BROWSER_MODE, "#f");
    CANON("#f", ICU_ENCODE_PERCENT, "#f");
    CANON("#f", ICU_ESCAPE, "#f");
    CANON("#f", ICU_DECODE | ICU_NO_ENCODE, "#f");
    CANON("#f", ICU_NO_META | ICU_NO_ENCODE, "#f");
    CANON("#f", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "#f");
    CANON("#f", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "#f");
    CANON("#f", ICU_USERNAME, "#f");
    CANON("#f", ICU_DECODE | ICU_ENCODE_PERCENT, "#f");
    CANON("#f", ICU_BROWSER_MODE | ICU_DECODE, "#f");
    CANON("#f", ICU_NO_META | ICU_DECODE, "#f");
}
TEST(url_crack_canon2_empty) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("\xe4\xb8\xad", 0, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_NO_ENCODE, "\xe4\xb8\xad");
    CANON("\xe4\xb8\xad", ICU_DECODE, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_NO_META, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_ENCODE_SPACES_ONLY, "\xe4\xb8\xad");
    CANON("\xe4\xb8\xad", ICU_BROWSER_MODE, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_ENCODE_PERCENT, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_ESCAPE, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_DECODE | ICU_NO_ENCODE, "\xe4\xb8\xad");
    CANON("\xe4\xb8\xad", ICU_NO_META | ICU_NO_ENCODE, "\xe4\xb8\xad");
    CANON("\xe4\xb8\xad", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "\xe4\xb8\xad");
    CANON("\xe4\xb8\xad", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "\xe4\xb8\xad");
    CANON("\xe4\xb8\xad", ICU_USERNAME, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_DECODE | ICU_ENCODE_PERCENT, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_BROWSER_MODE | ICU_DECODE, "%E4%B8%AD");
    CANON("\xe4\xb8\xad", ICU_NO_META | ICU_DECODE, "%E4%B8%AD");
}
TEST(url_crack_canon2_http_h_4) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://h/\xe4\xb8\xad", 0, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_NO_ENCODE, "http://h/\xe4\xb8\xad");
    CANON("http://h/\xe4\xb8\xad", ICU_DECODE, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_NO_META, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_ENCODE_SPACES_ONLY, "http://h/\xe4\xb8\xad");
    CANON("http://h/\xe4\xb8\xad", ICU_BROWSER_MODE, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_ENCODE_PERCENT, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_ESCAPE, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_DECODE | ICU_NO_ENCODE, "http://h/\xe4\xb8\xad");
    CANON("http://h/\xe4\xb8\xad", ICU_NO_META | ICU_NO_ENCODE, "http://h/\xe4\xb8\xad");
    CANON("http://h/\xe4\xb8\xad", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://h/\xe4\xb8\xad");
    CANON("http://h/\xe4\xb8\xad", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://h/\xe4\xb8\xad");
    CANON("http://h/\xe4\xb8\xad", ICU_USERNAME, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_DECODE | ICU_ENCODE_PERCENT, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_BROWSER_MODE | ICU_DECODE, "http://h/%E4%B8%AD");
    CANON("http://h/\xe4\xb8\xad", ICU_NO_META | ICU_DECODE, "http://h/%E4%B8%AD");
}
TEST(url_crack_canon2_http_example) {
    REQUIRE(U(InternetCanonicalizeUrlA)); REQUIRE(U(InternetCanonicalizeUrlW));
    CANON("http://\xc3\xa9.example/", 0, "http://%C3%A9.example/");
    CANON("http://\xc3\xa9.example/", ICU_NO_ENCODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_DECODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_NO_META, "http://%C3%A9.example/");
    CANON("http://\xc3\xa9.example/", ICU_ENCODE_SPACES_ONLY, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_BROWSER_MODE, "http://%C3%A9.example/");
    CANON("http://\xc3\xa9.example/", ICU_ENCODE_PERCENT, "http://%C3%A9.example/");
    CANON("http://\xc3\xa9.example/", ICU_ESCAPE, "http://%C3%A9.example/");
    CANON("http://\xc3\xa9.example/", ICU_DECODE | ICU_NO_ENCODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_NO_META | ICU_NO_ENCODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_ENCODE_SPACES_ONLY | ICU_NO_ENCODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_ENCODE_PERCENT | ICU_NO_ENCODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_USERNAME, "http://%C3%A9.example/");
    CANON("http://\xc3\xa9.example/", ICU_DECODE | ICU_ENCODE_PERCENT, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_BROWSER_MODE | ICU_DECODE, "http://\xc3\xa9.example/");
    CANON("http://\xc3\xa9.example/", ICU_NO_META | ICU_DECODE, "http://\xc3\xa9.example/");
}
