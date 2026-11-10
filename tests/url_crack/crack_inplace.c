/* url_crack: InternetCrackUrlA decodes %XX in the authority IN THE CALLER'S STRING.
 * [D] InternetCrackUrlA@0x2d610 calls _InternetCrackUrlA(..., decodeAuthority=1, ...). With dwFlags == 0 no private
 * copy is made (NewString only runs for ICU_DECODE/ICU_ESCAPE), and GetUrlAddress@0x61d20 calls
 * DecodeUrlInSitu@0x25a28 on the host, user and password spans of the input buffer. DecodeUrl shrinks each span in
 * place and leaves the freed tail bytes as they were.
 * [W10 VM] a read-only string literal "http://us%40er:pa%3Ass@host/" crashes InternetCrackUrlA with 0xC0000005
 * (flags 0), works with ICU_DECODE/ICU_ESCAPE, and InternetCrackUrlW never touches the caller's string (it cracks a
 * UTF-8 copy). Tests here use writable buffers only.
 * VM_TIMEOUT: 60 */
#include "uc.h"

static void zc(URL_COMPONENTSA *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; }

TEST(url_crack_inplace_userinfo_decoded) {
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://us%40er:pa%3Ass@host/";
    char us[64], pw[64], h[64], p[64];
    URL_COMPONENTSA c; zc(&c);
    c.lpszUserName = us; c.dwUserNameLength = 64; c.lpszPassword = pw; c.dwPasswordLength = 64;
    c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    SET_ERR(0xdead);
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    EXPECT_ERR(0);
    EXPECT_STR(us, "us@er");   EXPECT_EQ(c.dwUserNameLength, 5);
    EXPECT_STR(pw, "pa:ss");   EXPECT_EQ(c.dwPasswordLength, 5);
    EXPECT_STR(h, "host");
    EXPECT_STR(p, "/");
    /* each span shrank by two bytes in place; the stale tail bytes stay */
    EXPECT_STR(u, "http://us@erer:pa:ssss@host/");
}

TEST(url_crack_inplace_pointer_mode_points_at_decoded_bytes) {
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://us%40er:pa%3Ass@host/";
    URL_COMPONENTSA c; zc(&c);
    c.dwUserNameLength = 1; c.dwPasswordLength = 1; c.dwHostNameLength = 1;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    CHECK(c.lpszUserName == u + 7);   EXPECT_EQ(c.dwUserNameLength, 5);
    CHECK(c.lpszPassword == u + 15);  EXPECT_EQ(c.dwPasswordLength, 5);
    CHECK(c.lpszHostName == u + 23);  EXPECT_EQ(c.dwHostNameLength, 4);
    CHECK(c.lpszUserName && !strncmp(c.lpszUserName, "us@er", 5));
    CHECK(c.lpszPassword && !strncmp(c.lpszPassword, "pa:ss", 5));
}

TEST(url_crack_inplace_host_decoded) {
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://h%41st/p%41th";
    char h[64], p[64];
    URL_COMPONENTSA c; zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64; c.lpszUrlPath = p; c.dwUrlPathLength = 64;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    EXPECT_STR(h, "hAst"); EXPECT_EQ(c.dwHostNameLength, 4);
    EXPECT_STR(p, "/p%41th");                /* the path is not decoded without a flag */
    EXPECT_STR(u, "http://hAstst/p%41th");
}

TEST(url_crack_inplace_ipv6_zone) {
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://[fe80::1%25eth0]/";
    char h[64];
    URL_COMPONENTSA c; zc(&c); c.lpszHostName = h; c.dwHostNameLength = 64;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    EXPECT_STR(h, "[fe80::1%eth0]");
    EXPECT_EQ(c.dwHostNameLength, 14);
    EXPECT_EQ(c.nPort, 80);
}

TEST(url_crack_inplace_untouched_without_escapes) {
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://user:pass@host:81/a%20b?c%20d";
    uc_crack_t o;
    URL_COMPONENTSA c; char us[16], h[16]; zc(&c);
    c.lpszUserName = us; c.dwUserNameLength = 16; c.lpszHostName = h; c.dwHostNameLength = 16;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    EXPECT_STR(u, "http://user:pass@host:81/a%20b?c%20d");
    (void)o;
}

TEST(url_crack_inplace_not_with_flags) {
    /* ICU_DECODE / ICU_ESCAPE crack a NewString copy: the caller's buffer is unchanged, the components decoded */
    REQUIRE(U(InternetCrackUrlA));
    DWORD fl[] = { ICU_DECODE, ICU_ESCAPE };
    for (int i = 0; i < 2; i++) {
        char u[] = "http://us%40er:pa%3Ass@h%41st/";
        char us[64], pw[64], h[64];
        URL_COMPONENTSA c; zc(&c);
        c.lpszUserName = us; c.dwUserNameLength = 64; c.lpszPassword = pw; c.dwPasswordLength = 64;
        c.lpszHostName = h; c.dwHostNameLength = 64;
        CHECKF(U(InternetCrackUrlA)(u, 0, fl[i], &c), "flags %08lx err %lu", fl[i], GetLastError());
        EXPECT_STR(us, "us@er");
        EXPECT_STR(pw, "pa:ss");
        EXPECT_STR(h, "hAst");
        EXPECT_STR(u, "http://us%40er:pa%3Ass@h%41st/");
    }
}

TEST(url_crack_inplace_W_never_modifies_input) {
    REQUIRE(U(InternetCrackUrlW));
    WCHAR u[] = L"http://us%40er:pa%3Ass@h%41st/";
    WCHAR us[64], pw[64], h[64];
    URL_COMPONENTSW c; memset(&c, 0, sizeof c); c.dwStructSize = sizeof c;
    c.lpszUserName = us; c.dwUserNameLength = 64; c.lpszPassword = pw; c.dwPasswordLength = 64;
    c.lpszHostName = h; c.dwHostNameLength = 64;
    CHECK(U(InternetCrackUrlW)(u, 0, 0, &c));
    EXPECT_WSTR(us, L"us@er"); EXPECT_EQ(c.dwUserNameLength, 5);
    EXPECT_WSTR(pw, L"pa:ss"); EXPECT_EQ(c.dwPasswordLength, 5);
    EXPECT_WSTR(h, L"hAst");   EXPECT_EQ(c.dwHostNameLength, 4);
    EXPECT_WSTR(u, L"http://us%40er:pa%3Ass@h%41st/");
}

TEST(url_crack_inplace_W_readonly_literal_ok) {
    /* W cracks a heap copy, so a read-only literal is fine */
    REQUIRE(U(InternetCrackUrlW));
    WCHAR us[64];
    URL_COMPONENTSW c; memset(&c, 0, sizeof c); c.dwStructSize = sizeof c;
    c.lpszUserName = us; c.dwUserNameLength = 64;
    CHECK(U(InternetCrackUrlW)(L"http://us%40er@host/", 0, 0, &c));
    EXPECT_WSTR(us, L"us@er");
}

TEST(url_crack_inplace_A_decode_flag_readonly_literal_ok) {
    REQUIRE(U(InternetCrackUrlA));
    char us[64];
    URL_COMPONENTSA c; zc(&c); c.lpszUserName = us; c.dwUserNameLength = 64;
    CHECK(U(InternetCrackUrlA)("http://us%40er@host/", 0, ICU_DECODE, &c));
    EXPECT_STR(us, "us@er");
}

TEST(url_crack_inplace_decoded_at_sign_does_not_resplit) {
    /* userinfo is split on the raw '@' before decoding: "%40" inside the user stays part of the user */
    REQUIRE(U(InternetCrackUrlA));
    char u[] = "http://a%40b@host/";
    char us[64], h[64];
    URL_COMPONENTSA c; zc(&c); c.lpszUserName = us; c.dwUserNameLength = 64; c.lpszHostName = h; c.dwHostNameLength = 64;
    CHECK(U(InternetCrackUrlA)(u, 0, 0, &c));
    EXPECT_STR(us, "a@b");
    EXPECT_STR(h, "host");
}
