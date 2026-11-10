/* url_crack: InternetCrackUrlA/W argument validation and the component length protocol.
 * Evidence: [D] wininet!InternetCrackUrlW@0x2d690, InternetCrackUrlA@0x2d610, _InternetCrackUrlA@0x2dd88,
 * CrackUrl@0x60e70, GetUrlAddress@0x61d20; every expectation below also passed on the Win10 22H2 VM.
 * VM_TIMEOUT: 120 */
#include "uc.h"

static const char *U1 = "http://user:pass@host.example:8080/path/x?q=1#f";

static void zc(URL_COMPONENTSA *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }
static void zcw(URL_COMPONENTSW *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }

TEST(url_crack_struct_size_is_0x68) {
    /* [D] _InternetCrackUrlA compares dwStructSize against 0x68 = sizeof(URL_COMPONENTSA) on x64 */
    EXPECT_EQ(sizeof(URL_COMPONENTSA), 0x68);
    EXPECT_EQ(sizeof(URL_COMPONENTSW), 0x68);
}

TEST(url_crack_A_null_url) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; zc(&c);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)(NULL, 0, 0, &c), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_W_null_url) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; zcw(&c);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlW)(NULL, 0, 0, &c), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_A_null_components) {
    REQUIRE(U(InternetCrackUrlA));
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)(U1, 0, 0, NULL), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_W_null_components) {
    REQUIRE(U(InternetCrackUrlW));
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlW)(L"http://h/", 0, 0, NULL), ERROR_INVALID_PARAMETER);
}

TEST(url_crack_A_struct_size_validated) {
    REQUIRE(U(InternetCrackUrlA));
    static const DWORD bad[] = { 0, 1, 0x60, 0x67, 0x69, 0x70, 0x100, 0xffffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        URL_COMPONENTSA c; zc(&c); c.dwStructSize = bad[i];
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlA)(U1, 0, 0, &c);
        CHECKF(!r, "dwStructSize 0x%lx accepted", bad[i]);
        DWORD e = GetLastError();
        CHECKF(e == ERROR_INVALID_PARAMETER, "dwStructSize 0x%lx: err %lu", bad[i], e);
        CHECKF(c.dwStructSize == bad[i], "dwStructSize rewritten on failure");
    }
}

TEST(url_crack_W_struct_size_ignored_and_rewritten) {
    /* [D] W builds its own 0x68-byte A struct and never reads dwStructSize; on success it stores 0x68. */
    REQUIRE(U(InternetCrackUrlW));
    static const DWORD sizes[] = { 0, 1, 0x67, 0x69, 0x100 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        URL_COMPONENTSW c; WCHAR h[64];
        zcw(&c); c.dwStructSize = sizes[i]; c.lpszHostName = h; c.dwHostNameLength = 64;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(L"http://host.example:8080/x", 0, 0, &c);
        CHECKF(r, "W dwStructSize 0x%lx rejected (%lu)", sizes[i], GetLastError());
        EXPECT_EQ(c.dwStructSize, 0x68);
        EXPECT_WSTR(h, L"host.example");
        EXPECT_EQ(c.dwHostNameLength, 12);
        EXPECT_EQ(c.nPort, 8080);
    }
}

TEST(url_crack_A_invalid_flags) {
    /* [D] (dwFlags & 0x6fffffff) != 0 -> 87: only ICU_DECODE and ICU_ESCAPE are accepted */
    REQUIRE(U(InternetCrackUrlA));
    static const DWORD bad[] = { 1, 2, 0x1000, ICU_NO_ENCODE, ICU_USERNAME, ICU_NO_META, ICU_ENCODE_SPACES_ONLY,
                                 ICU_BROWSER_MODE, ICU_ENCODE_PERCENT, ICU_DECODE | 1, ICU_ESCAPE | ICU_NO_ENCODE, 0xffffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        URL_COMPONENTSA c; char h[64]; zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlA)(U1, 0, bad[i], &c);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INVALID_PARAMETER, "flags 0x%08lx: r=%d err=%lu", bad[i], r, e);
    }
}
TEST(url_crack_W_invalid_flags) {
    REQUIRE(U(InternetCrackUrlW));
    static const DWORD bad[] = { 1, ICU_NO_ENCODE, ICU_USERNAME, ICU_BROWSER_MODE, ICU_ENCODE_PERCENT, 0xffffffff };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        URL_COMPONENTSW c; WCHAR h[64]; zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 64;
        SET_ERR(0xdead);
        BOOL r = U(InternetCrackUrlW)(L"http://h/x", 0, bad[i], &c);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INVALID_PARAMETER, "flags 0x%08lx: r=%d err=%lu", bad[i], r, e);
    }
}

TEST(url_crack_A_decode_needs_a_buffer) {
    /* [D] with ICU_DECODE/ICU_ESCAPE at least one component must have pointer AND length, else 87 */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c;
    DWORD fl[] = { ICU_DECODE, ICU_ESCAPE, ICU_DECODE | ICU_ESCAPE };
    for (int i = 0; i < 3; i++) {
        zc(&c); SET_ERR(0xdead);
        CHECKF(!U(InternetCrackUrlA)(U1, 0, fl[i], &c), "no buffers, flags %08lx", fl[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        zc(&c); c.dwHostNameLength = 1; c.dwUrlPathLength = 1; SET_ERR(0xdead);   /* pointer mode only */
        CHECKF(!U(InternetCrackUrlA)(U1, 0, fl[i], &c), "pointer mode, flags %08lx", fl[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        char h[4]; zc(&c); c.lpszHostName = h; c.dwHostNameLength = 0; SET_ERR(0xdead);  /* pointer, zero length */
        CHECKF(!U(InternetCrackUrlA)(U1, 0, fl[i], &c), "zero-length buffer, flags %08lx", fl[i]);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    char x[64]; zc(&c); c.lpszExtraInfo = x; c.dwExtraInfoLength = sizeof x; SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlA)(U1, 0, ICU_DECODE, &c));
    EXPECT_STR(x, "?q=1#f");
}
TEST(url_crack_W_decode_needs_a_buffer) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; zcw(&c); SET_ERR(0xdead);
    CHECK(!U(InternetCrackUrlW)(L"http://h/a%20b", 0, ICU_DECODE, &c));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    WCHAR p[64]; zcw(&c); c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlW)(L"http://h/a%20b", 0, ICU_DECODE, &c));
    EXPECT_WSTR(p, L"/a b");
}

TEST(url_crack_A_nothing_requested) {
    /* all lengths 0: succeeds, fills nScheme/nPort only */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; zc(&c);
    SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlA)(U1, 0, 0, &c));
    EXPECT_ERR(0);
    EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTP);
    EXPECT_EQ(c.nPort, 8080);
    CHECK(c.lpszHostName == NULL && c.dwHostNameLength == 0);
    CHECK(c.lpszUrlPath == NULL && c.dwUrlPathLength == 0);
    CHECK(c.lpszScheme == NULL && c.dwSchemeLength == 0);
    EXPECT_EQ(c.dwStructSize, sizeof c);
}
TEST(url_crack_W_nothing_requested) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; zcw(&c);
    SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlW)(L"https://h/x", 0, 0, &c));
    EXPECT_ERR(0);
    EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTPS);
    EXPECT_EQ(c.nPort, 443);
}

TEST(url_crack_A_pointer_mode) {
    /* NULL pointer + nonzero length: pointer into the caller's string, length without NUL */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; zc(&c);
    c.dwSchemeLength = c.dwHostNameLength = c.dwUserNameLength = c.dwPasswordLength = c.dwUrlPathLength = c.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlA)(U1, 0, 0, &c));
    CHECK(c.lpszScheme == U1);            EXPECT_EQ(c.dwSchemeLength, 4);
    CHECK(c.lpszUserName == U1 + 7);      EXPECT_EQ(c.dwUserNameLength, 4);
    CHECK(c.lpszPassword == U1 + 12);     EXPECT_EQ(c.dwPasswordLength, 4);
    CHECK(c.lpszHostName == U1 + 17);     EXPECT_EQ(c.dwHostNameLength, 12);
    CHECK(c.lpszUrlPath == U1 + 34);      EXPECT_EQ(c.dwUrlPathLength, 7);
    CHECK(c.lpszExtraInfo == U1 + 41);    EXPECT_EQ(c.dwExtraInfoLength, 6);
    EXPECT_EQ(c.nPort, 8080);
}
TEST(url_crack_A_pointer_mode_path_without_extra) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; zc(&c); c.dwUrlPathLength = 1;
    CHECK(U(InternetCrackUrlA)(U1, 0, 0, &c));
    CHECK(c.lpszUrlPath == U1 + 34);
    EXPECT_EQ(c.dwUrlPathLength, 13);     /* "/path/x?q=1#f": not split without an extra-info request */
}
TEST(url_crack_A_pointer_mode_absent_components) {
    REQUIRE(U(InternetCrackUrlA));
    const char *u = "http://host/";
    URL_COMPONENTSA c; zc(&c); c.dwUserNameLength = c.dwPasswordLength = c.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    EXPECT_EQ(c.dwUserNameLength, 0);
    EXPECT_EQ(c.dwPasswordLength, 0);
    EXPECT_EQ(c.dwExtraInfoLength, 0);
    t_note("absent user ptr=%p pass ptr=%p extra ptr=%p (base %p)", c.lpszUserName, c.lpszPassword, c.lpszExtraInfo, u);
}
TEST(url_crack_W_pointer_mode) {
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://user:pass@host.example:8080/path/x?q=1#f";
    URL_COMPONENTSW c; zcw(&c);
    c.dwSchemeLength = c.dwHostNameLength = c.dwUserNameLength = c.dwPasswordLength = c.dwUrlPathLength = c.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlW)(u, 0, 0, &c));
    CHECK(c.lpszScheme == u);             EXPECT_EQ(c.dwSchemeLength, 4);
    CHECK(c.lpszUserName == u + 7);       EXPECT_EQ(c.dwUserNameLength, 4);
    CHECK(c.lpszPassword == u + 12);      EXPECT_EQ(c.dwPasswordLength, 4);
    CHECK(c.lpszHostName == u + 17);      EXPECT_EQ(c.dwHostNameLength, 12);
    CHECK(c.lpszUrlPath == u + 34);       EXPECT_EQ(c.dwUrlPathLength, 7);
    CHECK(c.lpszExtraInfo == u + 41);     EXPECT_EQ(c.dwExtraInfoLength, 6);
}
TEST(url_crack_W_pointer_mode_non_ascii_offsets) {
    /* [D] FixStrings maps the UTF-8 offsets back to WCHAR offsets in the caller's string */
    REQUIRE(U(InternetCrackUrlW));
    const WCHAR *u = L"http://hé/é中?x";
    URL_COMPONENTSW c; zcw(&c); c.dwHostNameLength = 1; c.dwUrlPathLength = 1; c.dwExtraInfoLength = 1;
    CHECK(U(InternetCrackUrlW)(u, 0, 0, &c));
    CHECK(c.lpszHostName == u + 7);   EXPECT_EQ(c.dwHostNameLength, 2);
    CHECK(c.lpszUrlPath == u + 9);    EXPECT_EQ(c.dwUrlPathLength, 3);
    CHECK(c.lpszExtraInfo == u + 12); EXPECT_EQ(c.dwExtraInfoLength, 2);
}

TEST(url_crack_A_buffer_too_small) {
    /* [D] buffer length <= component length -> *len = needed incl. NUL, call fails 122 after every component */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char h[5], p[64], s[16];
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 5; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    c.lpszScheme = s; c.dwSchemeLength = 16; memset(h, 'Z', sizeof h);
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)(U1, 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwHostNameLength, 13);
    EXPECT_EQ(h[0], 0);                         /* first char cleared on entry */
    EXPECT_STR(p, "/path/x?q=1#f");             /* the components that fit are still copied */
    EXPECT_EQ(c.dwUrlPathLength, 13);
    EXPECT_STR(s, "http");
    EXPECT_EQ(c.nPort, 8080);
    EXPECT_EQ(c.nScheme, INTERNET_SCHEME_HTTP);
}
TEST(url_crack_A_buffer_exact_boundary) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char h[32];
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 12;          /* == strlen("host.example"): no room for NUL */
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)(U1, 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwHostNameLength, 13);
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 13;
    SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlA)(U1, 0, 0, &c));
    EXPECT_ERR(0);
    EXPECT_STR(h, "host.example");
    EXPECT_EQ(c.dwHostNameLength, 12);
}
TEST(url_crack_A_buffer_one_byte) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char h[4] = "abc", u[4] = "abc";
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 1; c.lpszUserName = u; c.dwUserNameLength = 1;
    SET_ERR(0xdead);
    /* user "" fits in one byte; host does not */
    EXPECT_FAIL(!U(InternetCrackUrlA)("http://host/", 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwHostNameLength, 5);
    EXPECT_EQ(h[0], 0);
    EXPECT_EQ(u[0], 0);
    EXPECT_EQ(c.dwUserNameLength, 0);
}
TEST(url_crack_A_several_too_small) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char s[2], h[2], us[2], pw[2], p[2], x[2];
    zc(&c);
    c.lpszScheme = s; c.dwSchemeLength = 2; c.lpszHostName = h; c.dwHostNameLength = 2;
    c.lpszUserName = us; c.dwUserNameLength = 2; c.lpszPassword = pw; c.dwPasswordLength = 2;
    c.lpszUrlPath = p; c.dwUrlPathLength = 2; c.lpszExtraInfo = x; c.dwExtraInfoLength = 2;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)(U1, 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwSchemeLength, 5);
    EXPECT_EQ(c.dwHostNameLength, 13);
    EXPECT_EQ(c.dwUserNameLength, 5);
    EXPECT_EQ(c.dwPasswordLength, 5);
    EXPECT_EQ(c.dwUrlPathLength, 8);
    EXPECT_EQ(c.dwExtraInfoLength, 7);
}
TEST(url_crack_W_buffer_too_small_keeps_lengths) {
    /* [D] W gives the internal A call (len+1)*3-byte buffers; when THAT call fails with 122 the W wrapper returns
     * 122 without copying any length back, so the caller's lengths stay as passed. [W10] host buffer 3 -> 3. */
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR h[3], p[64];
    zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 3; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlW)(L"http://host.example:8080/x", 0, 0, &c), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(c.dwHostNameLength, 3);
    EXPECT_EQ(c.dwUrlPathLength, 64);
}
TEST(url_crack_W_buffer_too_small_ascii_fits_internal) {
    /* host of 5 chars, W buffer 3: the internal A buffer (12 bytes) is big enough, so the failure comes from the
     * UTF-8 -> UTF-16 copy-back (FixStrings). Record what Win10 reports. */
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR h[8];
    zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 3;
    SET_ERR(0xdead);
    BOOL r = U(InternetCrackUrlW)(L"http://hosts/x", 0, 0, &c);
    DWORD e = GetLastError();
    CHECK(!r);
    t_note("W host \"hosts\" into 3 WCHARs: r=%d err=%lu len=%lu", r, e, c.dwHostNameLength);
}

TEST(url_crack_A_explicit_length) {
    /* [D] dwUrlLength != 0: cracked up to that count (or the first NUL inside it) */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char h[64], p[64];
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)(U1, 24, 0, &c));           /* "http://user:pass@host.ex" */
    EXPECT_STR(h, "host.ex");
    EXPECT_STR(p, "");
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)(U1, 39, 0, &c));           /* up to "/path" */
    EXPECT_STR(h, "host.example");
    EXPECT_STR(p, "/path");
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)(U1, 1000, 0, &c));         /* longer than the string: stops at the NUL */
    EXPECT_STR(p, "/path/x?q=1#f");
    zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64;
    SET_ERR(0xdead);
    CHECK(!U(InternetCrackUrlA)(U1, 4, 0, &c));           /* "http": no ':' inside the count */
    EXPECT_ERR(ERROR_INTERNET_UNRECOGNIZED_SCHEME);
}
TEST(url_crack_W_explicit_length) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR h[64], p[64];
    zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlW)(L"http://host.example/abc/def", 23, 0, &c));
    EXPECT_WSTR(h, L"host.example");
    EXPECT_WSTR(p, L"/abc");
}

TEST(url_crack_long_path_65k) {
    REQUIRE(U(InternetCrackUrlA));
    static char big[66000], bp[66000];
    strcpy(big, "http://host/"); memset(big + 12, 'a', 65000); big[65012] = 0;
    URL_COMPONENTSA c; zc(&c); c.lpszUrlPath = bp; c.dwUrlPathLength = sizeof bp;
    SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlA)(big, 0, 0, &c));
    EXPECT_EQ(c.dwUrlPathLength, 65001);
    CHECK(bp[0] == '/' && bp[65000] == 'a' && bp[65001] == 0);
}
TEST(url_crack_long_host) {
    REQUIRE(U(InternetCrackUrlA));
    static char big[4000], bh[4000];
    strcpy(big, "http://"); memset(big + 7, 'h', 3000); strcpy(big + 3007, "/x");
    URL_COMPONENTSA c; zc(&c); c.lpszHostName = bh; c.dwHostNameLength = sizeof bh;
    SET_ERR(0xdead);
    BOOL r = U(InternetCrackUrlA)(big, 0, 0, &c);
    DWORD e = GetLastError();
    t_note("3000-char host: r=%d err=%lu len=%lu", r, e, c.dwHostNameLength);
    CHECK(r);
    EXPECT_EQ(c.dwHostNameLength, 3000);
}

TEST(url_crack_extra_split_only_when_requested) {
    REQUIRE(U(InternetCrackUrlA));
    uc_crack_t o;
    uc_crackA("http://h/a/b?c=d#e", 0, 0, &o);
    CHECK(o.r); EXPECT_STR(o.path, "/a/b?c=d#e");
    uc_crackA("http://h/a/b?c=d#e", 0, 1, &o);
    CHECK(o.r); EXPECT_STR(o.path, "/a/b"); EXPECT_STR(o.extra, "?c=d#e");
    uc_crackA("http://h/a/b#e?x", 0, 1, &o);
    CHECK(o.r); EXPECT_STR(o.path, "/a/b"); EXPECT_STR(o.extra, "#e?x");
}

TEST(url_crack_decode_path_and_extra) {
    /* [D] ICU_DECODE (alone) runs UrlUnescapeA in place on path and extra; host/user/password are %-decoded by
     * GetUrlAddress in every mode (crack_inplace.c) */
    REQUIRE(U(InternetCrackUrlA));
    uc_crack_t o;
    uc_crackA("http://us%41r:p%41ss@h%41st/a%20b?c%20d", ICU_DECODE, 1, &o);
    CHECK(o.r);
    EXPECT_STR(o.path, "/a b");
    EXPECT_STR(o.extra, "?c d");
    EXPECT_STR(o.user, "usAr");
    EXPECT_STR(o.pass, "pAss");
    EXPECT_STR(o.host, "hAst");
    uc_crackA("http://us%41r:p%41ss@h%41st/a%20b?c%20d", 0, 1, &o);
    CHECK(o.r);
    EXPECT_STR(o.path, "/a%20b");
    EXPECT_STR(o.extra, "?c%20d");
    EXPECT_STR(o.user, "usAr");
    EXPECT_STR(o.host, "hAst");
}
TEST(url_crack_decode_length_is_undecoded) {
    /* [D] the length stored for path/extra under ICU_DECODE is the escaped length (unescape runs after) */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char p[64];
    zc(&c); c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)("http://h/a%20b%41", 0, ICU_DECODE, &c));
    EXPECT_STR(p, "/a bA");
    EXPECT_EQ(c.dwUrlPathLength, 9);
}
TEST(url_crack_escape_flag_decodes_before_split) {
    /* [D] ICU_ESCAPE -> CrackUrl flag 8: DecodeUrlInSitu on the path before the ?/# split */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char p[64], x[64];
    zc(&c); c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)("http://h/a%20b%41", 0, ICU_ESCAPE, &c));
    EXPECT_STR(p, "/a bA");
    EXPECT_EQ(c.dwUrlPathLength, 5);
    zc(&c); c.lpszUrlPath = p; c.dwUrlPathLength = 64; c.lpszExtraInfo = x; c.dwExtraInfoLength = 64;
    CHECK(U(InternetCrackUrlA)("http://h/a%3Fb", 0, ICU_ESCAPE, &c));
    EXPECT_STR(p, "/a");
    EXPECT_STR(x, "?b");
    zc(&c); c.lpszUrlPath = p; c.dwUrlPathLength = 64; c.lpszExtraInfo = x; c.dwExtraInfoLength = 64;
    CHECK(U(InternetCrackUrlA)("http://h/a%3Fb", 0, ICU_DECODE, &c));
    EXPECT_STR(p, "/a?b");
    EXPECT_STR(x, "");
}
TEST(url_crack_escape_flag_input_not_modified) {
    /* ICU_ESCAPE decodes a private copy (NewString); the caller's string is untouched */
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://h/a%20b";
    URL_COMPONENTSA c; char p[64]; zc(&c); c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)(u, 0, ICU_ESCAPE, &c));
    EXPECT_STR(u, "http://h/a%20b");
}

TEST(url_crack_last_error_cleared_on_success) {
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSA c; zc(&c); SET_ERR(12345);
    CHECK(U(InternetCrackUrlA)("http://h/", 0, 0, &c)); EXPECT_ERR(0);
    URL_COMPONENTSW w; zcw(&w); SET_ERR(12345);
    CHECK(U(InternetCrackUrlW)(L"http://h/", 0, 0, &w)); EXPECT_ERR(0);
}

TEST(url_crack_W_non_ascii_host_and_path) {
    REQUIRE(U(InternetCrackUrlW));
    URL_COMPONENTSW c; WCHAR h[64], p[64];
    zcw(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlW)(L"http://hést.example/é中?x", 0, 0, &c));
    EXPECT_WSTR(h, L"hést.example");
    EXPECT_EQ(c.dwHostNameLength, 12);
    EXPECT_WSTR(p, L"/é中?x");
    EXPECT_EQ(c.dwUrlPathLength, 5);
}

TEST(url_crack_A_W_agree_on_errors) {
    REQUIRE(U(InternetCrackUrlA)); REQUIRE(U(InternetCrackUrlW));
    static const char *v[] = { "nocolon", "", "http://host:99999/", "http://host:12ab/", "http://[::1/", "http:host" };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        uc_crack_t a, w;
        uc_crackA(v[i], 0, 1, &a); uc_crackW(v[i], 0, 1, &w);
        CHECKF(a.r == w.r && a.err == w.err, "\"%s\": A r=%d err=%lu, W r=%d err=%lu", v[i], a.r, a.err, w.r, w.err);
    }
}

TEST(url_crack_repeatable_and_input_const) {
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://user:pass@host:81/p?q#f";
    uc_crack_t a, b;
    uc_crackA(u, 0, 1, &a); uc_crackA(u, 0, 1, &b);
    CHECK(a.r && b.r);
    EXPECT_STR(a.host, b.host); EXPECT_STR(a.path, b.path); EXPECT_STR(a.extra, b.extra);
    EXPECT_STR(u, "http://user:pass@host:81/p?q#f");
}

TEST(url_crack_A_failure_state_of_components) {
    /* [D] every supplied buffer gets its first char cleared on entry; on a parse error the lengths are untouched.
     * [W10] "http://host:99999/" -> 12005, all buffers "", lengths unchanged. */
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char s[16] = "xx", h[16] = "xx", p[16] = "xx", x[16] = "xx";
    zc(&c); c.lpszScheme = s; c.dwSchemeLength = 16; c.lpszHostName = h; c.dwHostNameLength = 15;
    c.lpszUrlPath = p; c.dwUrlPathLength = 14; c.lpszExtraInfo = x; c.dwExtraInfoLength = 13;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)("http://host:99999/", 0, 0, &c), ERROR_INTERNET_INVALID_URL);
    EXPECT_EQ(s[0], 0); EXPECT_EQ(h[0], 0); EXPECT_EQ(p[0], 0); EXPECT_EQ(x[0], 0);
    EXPECT_EQ(c.dwSchemeLength, 16); EXPECT_EQ(c.dwHostNameLength, 15);
    EXPECT_EQ(c.dwUrlPathLength, 14); EXPECT_EQ(c.dwExtraInfoLength, 13);
}
TEST(url_crack_A_unrecognized_scheme_state) {
    REQUIRE(U(InternetCrackUrlA));
    URL_COMPONENTSA c; char s[16] = "xx";
    zc(&c); c.lpszScheme = s; c.dwSchemeLength = 16;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCrackUrlA)("nocolon", 0, 0, &c), ERROR_INTERNET_UNRECOGNIZED_SCHEME);
    EXPECT_EQ(s[0], 0);
    EXPECT_EQ(c.dwSchemeLength, 16);
}
TEST(url_crack_port_parsing) {
    /* [D] GetUrlAddress: decimal digits only, value <= 65535, leading zeros fine, empty port = default */
    REQUIRE(U(InternetCrackUrlA));
    static const struct { const char *u; int ok; unsigned port; } v[] = {
        { "http://h:1/", 1, 1 }, { "http://h:00001/", 1, 1 }, { "http://h:65535/", 1, 65535 }, { "http://h:065535/", 1, 65535 },
        { "http://h:65536/", 0, 0 }, { "http://h:4294967376/", 0, 0 }, { "http://h:/", 1, 80 }, { "https://h:/", 1, 443 },
        { "ftp://h:/", 1, 21 }, { "http://h:0/", 1, 0 }, { "https://h:0", 1, 0 }, { "http://h:8a/", 0, 0 },
        { "http://h:0x10/", 0, 0 }, { "http://h:-0/", 0, 0 }, { "http://h:80 /", 0, 0 }, { "http://h:8080?x", 1, 8080 },
        { "http://h:8080#x", 1, 8080 }, { "gopher://h:70/", 1, 70 }, { "foo://h:1234/", 1, 1234 }, { "foo://h/", 1, 0 },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        uc_crack_t o; uc_crackA(v[i].u, 0, 1, &o);
        if (v[i].ok) CHECKF(o.r && o.port == v[i].port, "%s: r=%d err=%lu port=%u want %u", v[i].u, o.r, o.err, o.port, v[i].port);
        else CHECKF(!o.r && o.err == ERROR_INTERNET_INVALID_URL, "%s: r=%d err=%lu want 12005", v[i].u, o.r, o.err);
    }
}
TEST(url_crack_scheme_numbers) {
    /* [D] scheme table at wininet+0x1f3f60, matched case-insensitively; numbering = INTERNET_SCHEME */
    REQUIRE(U(InternetCrackUrlA));
    static const struct { const char *u; int ns; } v[] = {
        { "ftp://h/", INTERNET_SCHEME_FTP }, { "gopher://h/", INTERNET_SCHEME_GOPHER }, { "http://h/", INTERNET_SCHEME_HTTP },
        { "https://h/", INTERNET_SCHEME_HTTPS }, { "file:///C:/x", INTERNET_SCHEME_FILE }, { "news:x", INTERNET_SCHEME_NEWS },
        { "mailto:a@b", INTERNET_SCHEME_MAILTO }, { "javascript:x", INTERNET_SCHEME_JAVASCRIPT },
        { "vbscript:x", INTERNET_SCHEME_VBSCRIPT }, { "res://x.dll/1", INTERNET_SCHEME_RES }, { "foo://h/", INTERNET_SCHEME_UNKNOWN },
        { "about:blank", INTERNET_SCHEME_UNKNOWN }, { "GOPHER://h/", INTERNET_SCHEME_GOPHER }, { "NEWS:x", INTERNET_SCHEME_NEWS },
        { "MailTo:a@b", INTERNET_SCHEME_MAILTO }, { "RES://x.dll/1", INTERNET_SCHEME_RES }, { "httpx://h/", INTERNET_SCHEME_UNKNOWN },
        { "htt://h/", INTERNET_SCHEME_UNKNOWN }, { "https2://h/", INTERNET_SCHEME_UNKNOWN },
    };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        uc_crack_t o; uc_crackA(v[i].u, 0, 1, &o);
        CHECKF(o.r && o.ns == v[i].ns, "%s: r=%d err=%lu nScheme=%d want %d", v[i].u, o.r, o.err, o.ns, v[i].ns);
    }
}
