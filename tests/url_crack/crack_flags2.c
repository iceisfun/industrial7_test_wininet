/* url_crack (widening pass 2): InternetCrackUrlA/W with ICU_DECODE and ICU_ESCAPE: every probe URL whose result changes under a flag
 * Generated from the Win10 22H2 VM probe dump (boot ucprobe3-20261110-054841) by a throw-away generator; every row was observed on
 * genuine Windows 10 (wininet 11.0.19041.2193) and cross-read against the decomp named in EVIDENCE.md.
 * Lengths are explicit because ICU_DECODE reports the ESCAPED path/extra lengths (UrlUnescape runs after the copy)
 * while ICU_ESCAPE decodes before the split. W lengths are characters.
 * VM_TIMEOUT: 120 */
#include "uc.h"

static const uc_crack_fvec url_crack_flags2_a_decode_v[] = {
    { "http://h/%3F?x", 1, 0, 3, 80, "http", "h", "", "", "/?", 4, "?x", 2 },
    { "http://h/%23#x", 1, 0, 3, 80, "http", "h", "", "", "/#", 4, "#x", 2 },
    { "http://h/a%2Fb", 1, 0, 3, 80, "http", "h", "", "", "/a/b", 6, "", 0 },
    { "ftp://h/%2Fetc", 1, 0, 1, 21, "ftp", "h", "", "", "//etc", 7, "", 0 }
};
TEST(url_crack_flags2_a_decode) {
    REQUIRE(U(InternetCrackUrlA));
    for (unsigned i = 0; i < sizeof url_crack_flags2_a_decode_v / sizeof *url_crack_flags2_a_decode_v; i++) uc_check_crack_fvec(&url_crack_flags2_a_decode_v[i], ICU_DECODE, __FILE__, __LINE__);
}
static const uc_crack_fvec url_crack_flags2_w_decode_v[] = {
    { "http://h/%3F?x", 1, 0, 3, 80, "http", "h", "", "", "/?", 4, "?x", 2 },
    { "http://h/%23#x", 1, 0, 3, 80, "http", "h", "", "", "/#", 4, "#x", 2 },
    { "http://h/a%2Fb", 1, 0, 3, 80, "http", "h", "", "", "/a/b", 6, "", 0 },
    { "ftp://h/%2Fetc", 1, 0, 1, 21, "ftp", "h", "", "", "//etc", 7, "", 0 }
};
TEST(url_crack_flags2_w_decode) {
    REQUIRE(U(InternetCrackUrlW));
    for (unsigned i = 0; i < sizeof url_crack_flags2_w_decode_v / sizeof *url_crack_flags2_w_decode_v; i++) uc_check_crack_fvecW(&url_crack_flags2_w_decode_v[i], ICU_DECODE, __FILE__, __LINE__);
}
static const uc_crack_fvec url_crack_flags2_a_escape_v[] = {
    { "http://h/%3F?x", 1, 0, 3, 80, "http", "h", "", "", "/", 1, "??x", 3 },
    { "http://h/%23#x", 1, 0, 3, 80, "http", "h", "", "", "/", 1, "##x", 3 },
    { "http://h/a%2Fb", 1, 0, 3, 80, "http", "h", "", "", "/a/b", 4, "", 0 },
    { "file:///C:/a%2fb", 1, 0, 5, 0, "file", "", "", "", "C:\\a\\bfb", 8, "", 0 },
    { "file:///C:/%E9", 1, 0, 5, 0, "file", "", "", "", "C:\\\xe9" "E9", 6, "", 0 },
    { "file:///C:/a%20b%20c/d", 1, 0, 5, 0, "file", "", "", "", "C:\\a b c\\d0c\\d", 14, "", 0 },
    { "ftp://h/%2Fetc", 1, 0, 1, 21, "ftp", "h", "", "", "//etc", 5, "", 0 }
};
TEST(url_crack_flags2_a_escape) {
    REQUIRE(U(InternetCrackUrlA));
    for (unsigned i = 0; i < sizeof url_crack_flags2_a_escape_v / sizeof *url_crack_flags2_a_escape_v; i++) uc_check_crack_fvec(&url_crack_flags2_a_escape_v[i], ICU_ESCAPE, __FILE__, __LINE__);
}
static const uc_crack_fvec url_crack_flags2_w_escape_v[] = {
    { "http://h/%3F?x", 1, 0, 3, 80, "http", "h", "", "", "/", 1, "??x", 3 },
    { "http://h/%23#x", 1, 0, 3, 80, "http", "h", "", "", "/", 1, "##x", 3 },
    { "http://h/a%2Fb", 1, 0, 3, 80, "http", "h", "", "", "/a/b", 4, "", 0 },
    { "file:///C:/a%2fb", 1, 0, 5, 0, "file", "", "", "", "C:\\a\\bfb", 8, "", 0 },
    { "file:///C:/a%20b%20c/d", 1, 0, 5, 0, "file", "", "", "", "C:\\a b c\\d0c\\d", 14, "", 0 },
    { "ftp://h/%2Fetc", 1, 0, 1, 21, "ftp", "h", "", "", "//etc", 5, "", 0 }
};
TEST(url_crack_flags2_w_escape) {
    REQUIRE(U(InternetCrackUrlW));
    for (unsigned i = 0; i < sizeof url_crack_flags2_w_escape_v / sizeof *url_crack_flags2_w_escape_v; i++) uc_check_crack_fvecW(&url_crack_flags2_w_escape_v[i], ICU_ESCAPE, __FILE__, __LINE__);
}
