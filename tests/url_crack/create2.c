/* url_crack (widening pass 2): InternetCreateUrlA/W, more component sets (ports per scheme, opaque schemes, scheme strings, userinfo escaping
 * flags, ICU_ESCAPE on path/extra, host forms)
 * Generated from the Win10 22H2 VM probe dump (boot ucprobe3-20261110-054841) by a throw-away generator; every row was observed on
 * genuine Windows 10 (wininet 11.0.19041.2193) and cross-read against the decomp named in EVIDENCE.md.
 * CREATE checks A (size query + call) and, for ASCII input, W (size query in bytes + call).
 * VM_TIMEOUT: 120 */
#include "uc.h"

TEST(url_crack_create2_00_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h:0/x", 0, INTERNET_SCHEME_HTTP, NULL, "h", 0, NULL, NULL, "/x", NULL);
}
TEST(url_crack_create2_01_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h:443/x", 0, INTERNET_SCHEME_HTTP, NULL, "h", 443, NULL, NULL, "/x", NULL);
}
TEST(url_crack_create2_02_https) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("https://h:80/x", 0, INTERNET_SCHEME_HTTPS, NULL, "h", 80, NULL, NULL, "/x", NULL);
}
TEST(url_crack_create2_03_https) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("https://h/", 0, INTERNET_SCHEME_HTTPS, NULL, "h", 443, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_04_https) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("https://h:0/", 0, INTERNET_SCHEME_HTTPS, NULL, "h", 0, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_05_ftp) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("ftp://h/f", 0, INTERNET_SCHEME_FTP, NULL, "h", 21, NULL, NULL, "/f", NULL);
}
TEST(url_crack_create2_06_ftp) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("ftp://u:p@h:2121/f", 0, INTERNET_SCHEME_FTP, NULL, "h", 2121, "u", "p", "/f", NULL);
}
TEST(url_crack_create2_07_ftp) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("ftp://h:0", 0, INTERNET_SCHEME_FTP, NULL, "h", 0, NULL, NULL, NULL, NULL);
}
TEST(url_crack_create2_08_gopher) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("gopher://h:70/1", 0, INTERNET_SCHEME_GOPHER, NULL, "h", 70, NULL, NULL, "/1", NULL);
}
TEST(url_crack_create2_09_gopher) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("gopher://h/1", 0, INTERNET_SCHEME_GOPHER, NULL, "h", 0, NULL, NULL, "/1", NULL);
}
TEST(url_crack_create2_10_news) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("news://h/g", 0, INTERNET_SCHEME_NEWS, NULL, "h", 0, NULL, NULL, "/g", NULL);
}
TEST(url_crack_create2_11_news) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("news:g", 1, 0, INTERNET_SCHEME_NEWS, NULL, NULL, 0, NULL, NULL, "g", NULL);
}
TEST(url_crack_create2_12_mailto) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("mailto:a@b", 1, 0, INTERNET_SCHEME_MAILTO, NULL, NULL, 0, NULL, NULL, "a@b", NULL);
}
TEST(url_crack_create2_13_mailto) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("mailto:a@b", 0, INTERNET_SCHEME_MAILTO, NULL, "b", 0, "a", NULL, NULL, NULL);
}
TEST(url_crack_create2_14_javascript) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("javascript:x()", 1, 0, INTERNET_SCHEME_JAVASCRIPT, NULL, NULL, 0, NULL, NULL, "x()", NULL);
}
TEST(url_crack_create2_15_vbscript) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("vbscript:x", 1, 0, INTERNET_SCHEME_VBSCRIPT, NULL, NULL, 0, NULL, NULL, "x", NULL);
}
TEST(url_crack_create2_16_res) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("res://x.dll/1", 0, INTERNET_SCHEME_RES, NULL, "x.dll", 0, NULL, NULL, "/1", NULL);
}
TEST(url_crack_create2_17_socks) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("socks:h:1080/", 0, INTERNET_SCHEME_SOCKS, NULL, "h", 1080, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_18_socks) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("socks:h", 0, INTERNET_SCHEME_SOCKS, NULL, "h", 0, NULL, NULL, NULL, NULL);
}
TEST(url_crack_create2_19_file) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("file://C:\\a\\b.txt", 1, 0, INTERNET_SCHEME_FILE, NULL, NULL, 0, NULL, NULL, "C:\\a\\b.txt", NULL);
}
TEST(url_crack_create2_20_file) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("file:///C:/a", 0, INTERNET_SCHEME_FILE, NULL, NULL, 0, NULL, NULL, "/C:/a", NULL);
}
TEST(url_crack_create2_21_file) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("file://server/share/x", 0, INTERNET_SCHEME_FILE, NULL, "server", 0, NULL, NULL, "/share/x", NULL);
}
TEST(url_crack_create2_22_file) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("file:///C:/a b", ICU_ESCAPE, INTERNET_SCHEME_FILE, NULL, "", 0, NULL, NULL, "C:/a b", NULL);
}
TEST(url_crack_create2_23_unk) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("foo://h:12/p?q", 0, INTERNET_SCHEME_UNKNOWN, "foo", "h", 12, NULL, NULL, "/p", "?q");
}
TEST(url_crack_create2_24_unk) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("foo:bar", 1, 0, INTERNET_SCHEME_UNKNOWN, "foo", NULL, 0, NULL, NULL, "bar", NULL);
}
TEST(url_crack_create2_25_def) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("ws://h/x", 0, INTERNET_SCHEME_DEFAULT, "ws", "h", 0, NULL, NULL, "/x", NULL);
}
TEST(url_crack_create2_26_def) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("HTTP://h/x", 0, INTERNET_SCHEME_DEFAULT, "HTTP", "h", 80, NULL, NULL, "/x", NULL);
}
TEST(url_crack_create2_27_def) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("https://h/", 0, INTERNET_SCHEME_DEFAULT, "https", "h", 443, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_28_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("foo://h/x", 0, INTERNET_SCHEME_HTTP, "foo", "h", 0, NULL, NULL, "/x", NULL);
}
TEST(url_crack_create2_29_def) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("Http://h:0/", 0, INTERNET_SCHEME_DEFAULT, "Http", "h", 0, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_30_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u@h/", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u", NULL, "/", NULL);
}
TEST(url_crack_create2_31_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, "", "", "/", NULL);
}
TEST(url_crack_create2_32_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u:@h/", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u", "", "/", NULL);
}
TEST(url_crack_create2_33_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u:x:p@y@h/", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u:x", "p@y", "/", NULL);
}
TEST(url_crack_create2_34_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u:x:p%40y@h/", 0x2000, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u:x", "p@y", "/", NULL);
}
TEST(url_crack_create2_35_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u%20x:p%20y@h/", 0x2000, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u x", "p y", "/", NULL);
}
TEST(url_crack_create2_36_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u%25x:p%2Fy@h/", 0x2000, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u%x", "p/y", "/", NULL);
}
TEST(url_crack_create2_37_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u x:p y@h/", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u x", "p y", "/", NULL);
}
TEST(url_crack_create2_38_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u:p@h/", ICU_USERNAME, INTERNET_SCHEME_HTTP, NULL, "h", 80, "u", "p", "/", NULL);
}
TEST(url_crack_create2_39_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a b?c d#e f", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a b", "?c d#e f");
}
TEST(url_crack_create2_40_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a%20b?c%20d%23e%20f", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a b", "?c d#e f");
}
TEST(url_crack_create2_41_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a%2520b", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a%20b", NULL);
}
TEST(url_crack_create2_42_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a%3Cb%3E%22c?%7Bx%7D", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a<b>\"c", "?{x}");
}
TEST(url_crack_create2_43_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a/../b", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a/../b", NULL);
}
TEST(url_crack_create2_44_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a?b", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a?b", NULL);
}
TEST(url_crack_create2_45_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a%23b", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a#b", NULL);
}
TEST(url_crack_create2_46_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/%7F", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/\x7f", NULL);
}
TEST(url_crack_create2_47_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/a%09b", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "/a\x09" "b", NULL);
}
TEST(url_crack_create2_48_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/x", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "x", NULL);
}
TEST(url_crack_create2_49_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h/?q", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "", "?q");
}
TEST(url_crack_create2_50_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h#f", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, NULL, "#f");
}
TEST(url_crack_create2_51_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://hq", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, NULL, "q");
}
TEST(url_crack_create2_52_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h//x", 0, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, NULL, "//x", NULL);
}
TEST(url_crack_create2_53_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http:///", 0, INTERNET_SCHEME_HTTP, NULL, "", 80, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_54_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http:///", 0, INTERNET_SCHEME_HTTP, NULL, NULL, 80, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_55_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://[::1]/", 0, INTERNET_SCHEME_HTTP, NULL, "::1", 80, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_56_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://[::1]:81/", 0, INTERNET_SCHEME_HTTP, NULL, "[::1]", 81, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_57_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://[fe80::1%4]/", 0, INTERNET_SCHEME_HTTP, NULL, "fe80::1%4", 80, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_58_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://a:b/", 0, INTERNET_SCHEME_HTTP, NULL, "a:b", 80, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_59_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://H.EXAMPLE/P", 0, INTERNET_SCHEME_HTTP, NULL, "H.EXAMPLE", 80, NULL, NULL, "/P", NULL);
}
TEST(url_crack_create2_60_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h x/", ICU_ESCAPE, INTERNET_SCHEME_HTTP, NULL, "h x", 80, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_61_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://h:65535/", 0, INTERNET_SCHEME_HTTP, NULL, "h", 65535, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_62_unk) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE(":h/", 0, INTERNET_SCHEME_UNKNOWN, "", "h", 0, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_63_unk) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("a b://h/", 0, INTERNET_SCHEME_UNKNOWN, "a b", "h", 0, NULL, NULL, "/", NULL);
}
TEST(url_crack_create2_64_def) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("ftp://anonymous:x@y@h/", 0, INTERNET_SCHEME_DEFAULT, "ftp", "h", 21, "anonymous", "x@y", "/", NULL);
}
TEST(url_crack_create2_65_http) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_FAIL(87, 0x2000, INTERNET_SCHEME_HTTP, NULL, "h", 80, NULL, "p", "/", NULL);
}
TEST(url_crack_create2_66_https) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("https://u:p@h:8443/a?b#c", 0, INTERNET_SCHEME_HTTPS, NULL, "h", 8443, "u", "p", "/a", "?b#c");
}
