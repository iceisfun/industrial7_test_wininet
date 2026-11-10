/* url_crack: InternetCreateUrlA/W.
 * [D] _InternetCreateUrlA@0x61380, InternetCreateUrlW@0x607f0. Every CREATE() line below runs four calls: A size query
 * (NULL buffer -> 122 + bytes incl. NUL), A into a big buffer (*len = chars, no NUL), W size query (-> 122 + BYTES
 * incl. NUL) and W into a big buffer (*len = chars). All results observed on the Win10 22H2 VM.
 * Win10 facts pinned here (several surprise reimplementers):
 *  - the port is written whenever nPort differs from the scheme default (http 80, https 443, ftp 21, others 0), so
 *    nPort = 0 with http gives "http://host:0/p"; only nPort == default omits it.
 *  - lpszScheme (with a length or NUL-terminated) wins over nScheme; nScheme 0 (DEFAULT) means "http"; nScheme -1
 *    without a scheme string, or > 11, or < -1 -> 87.
 *  - a path without a leading '/' gets one after an authority; opaque schemes (mailto, news without host, file
 *    without host, javascript, vbscript) use "scheme:" and no '/', but the size query still counts that '/'
 *    (CREATE_Q: required = strlen + 2).
 *  - extra info is appended verbatim (no '?' added); a password without a user name -> 87.
 *  - a host with two or more ':' that is not already bracketed is emitted as "[...]".
 *  - dwFlags: only ICU_ESCAPE, ICU_USERNAME and 0x2000 are accepted, anything else -> 87.
 *    ICU_ESCAPE escapes the path and extra (spaces, unsafe chars, '%', bytes >= 0x80, upper-case hex);
 *    0x2000 escapes user name and password (upper-case hex, ':' kept in the password).
 * VM_TIMEOUT: 120 */
#include "uc.h"

#define H INTERNET_SCHEME_HTTP
#define HS INTERNET_SCHEME_HTTPS
#define F INTERNET_SCHEME_FTP

TEST(url_crack_create_http_default_port_omitted) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host/p", 0, H, NULL, "host", 80, NULL, NULL, "/p", NULL);
    CREATE("https://host/p", 0, HS, NULL, "host", 443, NULL, NULL, "/p", NULL);
    CREATE("ftp://host/p", 0, F, NULL, "host", 21, NULL, NULL, "/p", NULL);
    CREATE("gopher://g/1", 0, INTERNET_SCHEME_GOPHER, NULL, "g", 0, NULL, NULL, "/1", NULL);
}
TEST(url_crack_create_port_zero_is_written) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host:0/p", 0, H, NULL, "host", 0, NULL, NULL, "/p", NULL);
    CREATE("https://host:0/p", 0, HS, NULL, "host", 0, NULL, NULL, "/p", NULL);
    CREATE("ftp://host:0/p", 0, F, NULL, "host", 0, NULL, NULL, "/p", NULL);
    CREATE("http://host:0", 0, H, NULL, "host", 0, NULL, NULL, NULL, NULL);
}
TEST(url_crack_create_non_default_ports) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host:8080/p", 0, H, NULL, "host", 8080, NULL, NULL, "/p", NULL);
    CREATE("http://host:443/p", 0, H, NULL, "host", 443, NULL, NULL, "/p", NULL);
    CREATE("https://host:80/p", 0, HS, NULL, "host", 80, NULL, NULL, "/p", NULL);
    CREATE("ftp://host:2121/p", 0, F, NULL, "host", 2121, NULL, NULL, "/p", NULL);
    CREATE("gopher://g:70/1", 0, INTERNET_SCHEME_GOPHER, NULL, "g", 70, NULL, NULL, "/1", NULL);
    CREATE("http://h:1", 0, H, NULL, "h", 1, NULL, NULL, NULL, NULL);
    CREATE("http://h:65535/", 0, H, NULL, "h", 65535, NULL, NULL, "/", NULL);
    CREATE("http://h:10000/", 0, H, NULL, "h", 10000, NULL, NULL, "/", NULL);
    CREATE("http://h:9999/", 0, H, NULL, "h", 9999, NULL, NULL, "/", NULL);
    CREATE("http://h:10/", 0, H, NULL, "h", 10, NULL, NULL, "/", NULL);
}
TEST(url_crack_create_userinfo) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u:p@host/x", 0, H, NULL, "host", 80, "u", "p", "/x", NULL);
    CREATE("http://u:p@host:0/x", 0, H, NULL, "host", 0, "u", "p", "/x", NULL);
    CREATE("http://u@host:0/x", 0, H, NULL, "host", 0, "u", NULL, "/x", NULL);
    CREATE("http://u:p@host:81/x", 0, H, NULL, "host", 81, "u", "p", "/x", NULL);
    CREATE("http://:p@h:0/", 0, H, NULL, "h", 0, "", "p", "/", NULL);
    CREATE("http://u:@h:0/", 0, H, NULL, "h", 0, "u", "", "/", NULL);
    CREATE("ftp://user:pw@h/d/", 0, F, NULL, "h", 21, "user", "pw", "/d/", NULL);
    CREATE("http://u@x:p:w@host:0/", 0, H, NULL, "host", 0, "u@x", "p:w", "/", NULL);
}
TEST(url_crack_create_password_without_user) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_FAIL(ERROR_INVALID_PARAMETER, 0, H, NULL, "host", 0, NULL, "p", "/x", NULL);
}
TEST(url_crack_create_extra_info) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host:0/x?a=b#c", 0, H, NULL, "host", 0, NULL, NULL, "/x", "?a=b#c");
    CREATE("http://host:0/xa=b", 0, H, NULL, "host", 0, NULL, NULL, "/x", "a=b");
    CREATE("http://h:0?q", 0, H, NULL, "h", 0, NULL, NULL, NULL, "?q");
    CREATE("http://h/p#f", 0, H, NULL, "h", 80, NULL, NULL, "/p", "#f");
}
TEST(url_crack_create_path_forms) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host:0/p", 0, H, NULL, "host", 0, NULL, NULL, "p", NULL);           /* '/' inserted */
    CREATE("http://host:0", 0, H, NULL, "host", 0, NULL, NULL, NULL, NULL);
    CREATE("http://host/a b", 0, H, NULL, "host", 80, NULL, NULL, "/a b", NULL);        /* no escaping without a flag */
    CREATE("http://HoSt:0/PaTh", 0, H, NULL, "HoSt", 0, NULL, NULL, "/PaTh", NULL);     /* case kept */
    CREATE("http://h/a\\b", 0, H, NULL, "h", 80, NULL, NULL, "/a\\b", NULL);
}
TEST(url_crack_create_host_forms) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http:///p", 0, H, NULL, NULL, 0, NULL, NULL, "/p", NULL);                  /* no host: no port either */
    CREATE("http://:0/p", 0, H, NULL, "", 0, NULL, NULL, "/p", NULL);
    CREATE("http://[::1]:0/", 0, H, NULL, "::1", 0, NULL, NULL, "/", NULL);             /* bracketed: two ':' */
    CREATE("http://[::1]:8080/", 0, H, NULL, "[::1]", 8080, NULL, NULL, "/", NULL);     /* already bracketed */
    CREATE("http://[fe80::1]/", 0, H, NULL, "fe80::1", 80, NULL, NULL, "/", NULL);
    CREATE("http://a:b:0/", 0, H, NULL, "a:b", 0, NULL, NULL, "/", NULL);               /* one ':' is not IPv6 */
}
TEST(url_crack_create_scheme_selection) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host:0/p", 0, INTERNET_SCHEME_DEFAULT, NULL, "host", 0, NULL, NULL, "/p", NULL);
    CREATE("http://host:8080/p", 0, INTERNET_SCHEME_DEFAULT, NULL, "host", 8080, NULL, NULL, "/p", NULL);
    CREATE("http://host/p", 0, INTERNET_SCHEME_DEFAULT, NULL, "host", 80, NULL, NULL, "/p", NULL);
    CREATE("foo://host/p", 0, INTERNET_SCHEME_UNKNOWN, "foo", "host", 0, NULL, NULL, "/p", NULL);
    CREATE("foo://host:99/p", 0, INTERNET_SCHEME_UNKNOWN, "foo", "host", 99, NULL, NULL, "/p", NULL);
    CREATE("foo://host/p", 0, H, "foo", "host", 0, NULL, NULL, "/p", NULL);            /* the string wins */
    CREATE("HTTP://host/p", 0, INTERNET_SCHEME_DEFAULT, "HTTP", "host", 80, NULL, NULL, "/p", NULL);
    CREATE("http://", 0, INTERNET_SCHEME_DEFAULT, NULL, NULL, 0, NULL, NULL, NULL, NULL);
}
TEST(url_crack_create_bad_scheme_number) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_FAIL(ERROR_INVALID_PARAMETER, 0, INTERNET_SCHEME_UNKNOWN, NULL, "host", 0, NULL, NULL, "/p", NULL);
    CREATE_FAIL(ERROR_INVALID_PARAMETER, 0, (INTERNET_SCHEME)12, NULL, "h", 0, NULL, NULL, "/", NULL);
    CREATE_FAIL(ERROR_INVALID_PARAMETER, 0, (INTERNET_SCHEME)-2, NULL, "h", 0, NULL, NULL, "/", NULL);
}
TEST(url_crack_create_opaque_schemes) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("mailto:a@b", 1, 0, INTERNET_SCHEME_MAILTO, NULL, NULL, 0, NULL, NULL, "a@b", NULL);
    CREATE_Q("mailto:hosta@b", 1, 0, INTERNET_SCHEME_MAILTO, NULL, "host", 0, NULL, NULL, "a@b", NULL);
    CREATE_Q("news:comp.x", 1, 0, INTERNET_SCHEME_NEWS, NULL, NULL, 0, NULL, NULL, "comp.x", NULL);
    CREATE("news://h/comp.x", 0, INTERNET_SCHEME_NEWS, NULL, "h", 0, NULL, NULL, "/comp.x", NULL);
    CREATE_Q("javascript:alert(1)", 1, 0, INTERNET_SCHEME_JAVASCRIPT, NULL, NULL, 0, NULL, NULL, "alert(1)", NULL);
    CREATE_Q("vbscript:x", 1, 0, INTERNET_SCHEME_VBSCRIPT, NULL, NULL, 0, NULL, NULL, "x", NULL);
    CREATE("res://x.dll/1", 0, INTERNET_SCHEME_RES, NULL, "x.dll", 0, NULL, NULL, "/1", NULL);
    CREATE("socks:p:1080", 0, INTERNET_SCHEME_SOCKS, NULL, "p", 1080, NULL, NULL, NULL, NULL);
}
TEST(url_crack_create_file_urls) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_Q("file://C:/a.txt", 1, 0, INTERNET_SCHEME_FILE, NULL, NULL, 0, NULL, NULL, "C:/a.txt", NULL);
    CREATE("file:///C:/a.txt", 0, INTERNET_SCHEME_FILE, NULL, NULL, 0, NULL, NULL, "/C:/a.txt", NULL);
    CREATE("file://srv/share/a.txt", 0, INTERNET_SCHEME_FILE, NULL, "srv", 0, NULL, NULL, "/share/a.txt", NULL);
    CREATE_Q("file://C:\\a\\b.txt", 1, 0, INTERNET_SCHEME_FILE, NULL, NULL, 0, NULL, NULL, "C:\\a\\b.txt", NULL);
}
TEST(url_crack_create_escape_path_and_extra) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://host:0/a%20b", ICU_ESCAPE, H, NULL, "host", 0, NULL, NULL, "/a b", NULL);
    CREATE("http://host:0/a?b%20c", ICU_ESCAPE, H, NULL, "host", 0, NULL, NULL, "/a", "?b c");
    CREATE("http://host:0/a%2520b", ICU_ESCAPE, H, NULL, "host", 0, NULL, NULL, "/a%20b", NULL);
    CREATE("http://host:0/%3C%3E%22%7B%7D%7C%5E%60", ICU_ESCAPE, H, NULL, "host", 0, NULL, NULL, "/<>\"{}|^`", NULL);
    CREATE("http://u@x y:p:w/@host:0/", ICU_ESCAPE, H, NULL, "host", 0, "u@x y", "p:w/", "/", NULL);  /* userinfo untouched */
}
TEST(url_crack_create_escape_authority_flag) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE("http://u%40x%20y:p:w%2F@host:0/", 0x2000, H, NULL, "host", 0, "u@x y", "p:w/", "/", NULL);
    CREATE("http://u:p@host:0/", ICU_USERNAME, H, NULL, "host", 0, "u", "p", "/", NULL);
}
TEST(url_crack_create_invalid_flags) {
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    CREATE_FAIL(ERROR_INVALID_PARAMETER, ICU_DECODE, H, NULL, "host", 0, NULL, NULL, "/", NULL);
    CREATE_FAIL(ERROR_INVALID_PARAMETER, 1, H, NULL, "host", 0, NULL, NULL, "/", NULL);
    CREATE_FAIL(ERROR_INVALID_PARAMETER, ICU_NO_ENCODE, H, NULL, "host", 0, NULL, NULL, "/", NULL);
}
TEST(url_crack_create_A_utf8_bytes) {
    /* A copies bytes verbatim; ICU_ESCAPE escapes each byte >= 0x80 */
    REQUIRE(U(InternetCreateUrlA));
    CREATE("http://h:0/\xc3\xa9", 0, H, NULL, "h", 0, NULL, NULL, "/\xc3\xa9", NULL);
    CREATE("http://h:0/%C3%A9", ICU_ESCAPE, H, NULL, "h", 0, NULL, NULL, "/\xc3\xa9", NULL);
}
TEST(url_crack_create_W_non_ascii) {
    /* [D] W converts the path with the ANSI code page first (WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS)).
     * [W10, ACP 1252] U+00E9 -> "http://h:0/\u00e9" (12 chars), size query 26 bytes; with ICU_ESCAPE -> "%E9". */
    REQUIRE(U(InternetCreateUrlW));
    URL_COMPONENTSW w; WCHAR out[64]; DWORD n;
    memset(&w, 0, sizeof w); w.dwStructSize = sizeof w; w.nScheme = H; w.lpszHostName = L"h"; w.lpszUrlPath = L"/\u00e9";
    n = 64; CHECK(U(InternetCreateUrlW)(&w, 0, out, &n));
    EXPECT_WSTR(out, L"http://h:0/\u00e9");
    EXPECT_EQ(n, 12);
    n = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlW)(&w, 0, NULL, &n), ERROR_INSUFFICIENT_BUFFER);
    n = 64; CHECK(U(InternetCreateUrlW)(&w, ICU_ESCAPE, out, &n));
    if (GetACP() == 1252) EXPECT_WSTR(out, L"http://h:0/%E9");
    else t_note("ACP %u: W ICU_ESCAPE of U+00E9 -> %s", GetACP(), uc_a(out));
}

/* ---- argument validation and the length protocol ---- */

static void zc(URL_COMPONENTSA *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; c->nScheme = H; c->lpszHostName = "h"; c->lpszUrlPath = "/"; }
static void zcw(URL_COMPONENTSW *c) { memset(c, 0, sizeof *c); c->dwStructSize = sizeof *c; c->nScheme = H; c->lpszHostName = L"h"; c->lpszUrlPath = L"/"; }

TEST(url_crack_create_A_null_args) {
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA c; zc(&c); char o[64]; DWORD n = 64;
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCreateUrlA)(NULL, 0, o, &n), ERROR_INVALID_PARAMETER);
    EXPECT_EQ(n, 64);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCreateUrlA)(&c, 0, o, NULL), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_create_W_null_args) {
    REQUIRE(U(InternetCreateUrlW));
    URL_COMPONENTSW c; zcw(&c); WCHAR o[64]; DWORD n = 64;
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCreateUrlW)(NULL, 0, o, &n), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdead); EXPECT_FAIL(!U(InternetCreateUrlW)(&c, 0, o, NULL), ERROR_INVALID_PARAMETER);
}
TEST(url_crack_create_struct_size_validated) {
    /* unlike InternetCrackUrlW, both A and W of CreateUrl require dwStructSize == 0x68 */
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCreateUrlW));
    static const DWORD bad[] = { 0, 1, 0x67, 0x69, 0x100 };
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        URL_COMPONENTSA c; zc(&c); c.dwStructSize = bad[i]; char o[64]; DWORD n = 64;
        SET_ERR(0xdead);
        CHECKF(!U(InternetCreateUrlA)(&c, 0, o, &n) && GetLastError() == ERROR_INVALID_PARAMETER, "A size 0x%lx", bad[i]);
        EXPECT_EQ(n, 64);
        URL_COMPONENTSW w; zcw(&w); w.dwStructSize = bad[i]; WCHAR wo[64]; n = 64;
        SET_ERR(0xdead);
        CHECKF(!U(InternetCreateUrlW)(&w, 0, wo, &n) && GetLastError() == ERROR_INVALID_PARAMETER, "W size 0x%lx", bad[i]);
    }
}
TEST(url_crack_create_A_buffer_protocol) {
    /* "http://h:0/" = 11 chars: any buffer < 12 -> 122 with 12 (bytes incl. NUL); 12 -> ok, *len 11 */
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA c; zc(&c); char o[64]; DWORD n;
    static const DWORD small[] = { 1, 3, 9, 10, 11 };
    for (unsigned i = 0; i < sizeof small / sizeof *small; i++) {
        memset(o, 'Z', sizeof o); n = small[i]; SET_ERR(0xdead);
        CHECKF(!U(InternetCreateUrlA)(&c, 0, o, &n), "len %lu succeeded", small[i]);
        EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
        EXPECT_EQ(n, 12);
        CHECKF(o[0] == 'Z', "buffer written on 122 (len %lu)", small[i]);
    }
    n = 12; SET_ERR(0xdead);
    CHECK(U(InternetCreateUrlA)(&c, 0, o, &n));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 11);
    EXPECT_STR(o, "http://h:0/");
}
TEST(url_crack_create_A_null_buffer_zeroes_length) {
    /* [D] a NULL buffer zeroes *len first, so any input length is a pure size query */
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA c; zc(&c); DWORD n = 100;
    SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlA)(&c, 0, NULL, &n), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 12);
}
TEST(url_crack_create_W_buffer_protocol) {
    /* [D] W gives the inner A call a (len+1)*2-byte buffer. If THAT fails, W reports A's need x 2 (bytes incl. NUL);
     * if A fits but the UTF-16 copy does not, W reports A's length x 2 WITHOUT the NUL.
     * [W10] "http://h:0/": len 3 -> 24, len 9 and 10 -> 22, len 11 -> 22, len 12 -> ok (11). */
    REQUIRE(U(InternetCreateUrlW));
    URL_COMPONENTSW c; zcw(&c); WCHAR o[64]; DWORD n;
    n = 3; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlW)(&c, 0, o, &n), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 24);
    n = 9; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlW)(&c, 0, o, &n), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 22);
    n = 10; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlW)(&c, 0, o, &n), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 22);
    n = 11; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlW)(&c, 0, o, &n), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 22);
    n = 12; SET_ERR(0xdead);
    CHECK(U(InternetCreateUrlW)(&c, 0, o, &n));
    EXPECT_ERR(0);
    EXPECT_EQ(n, 11);
    EXPECT_WSTR(o, L"http://h:0/");
    n = 0; SET_ERR(0xdead);
    EXPECT_FAIL(!U(InternetCreateUrlW)(&c, 0, NULL, &n), ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(n, 24);
}
TEST(url_crack_create_component_lengths_honoured) {
    /* nonzero dwXxxLength limits how much of the string is used */
    REQUIRE(U(InternetCreateUrlA));
    URL_COMPONENTSA c; zc(&c); char o[64]; DWORD n = 64;
    c.lpszHostName = "host"; c.dwHostNameLength = 2;
    CHECK(U(InternetCreateUrlA)(&c, 0, o, &n));
    EXPECT_STR(o, "http://ho:0/");
    zc(&c); c.lpszScheme = "https-x"; c.dwSchemeLength = 5; c.nScheme = INTERNET_SCHEME_DEFAULT; c.nPort = 443; n = 64;
    CHECK(U(InternetCreateUrlA)(&c, 0, o, &n));
    EXPECT_STR(o, "https://h/");
    zc(&c); c.lpszUrlPath = "/abcdef"; c.dwUrlPathLength = 3; c.nPort = 80; n = 64;
    CHECK(U(InternetCreateUrlA)(&c, 0, o, &n));
    EXPECT_STR(o, "http://h/ab");
    zc(&c); c.lpszUserName = "userXX"; c.dwUserNameLength = 4; c.lpszPassword = "pwXX"; c.dwPasswordLength = 2; c.nPort = 80; n = 64;
    CHECK(U(InternetCreateUrlA)(&c, 0, o, &n));
    EXPECT_STR(o, "http://user:pw@h/");
    zc(&c); c.lpszExtraInfo = "?a=1&b=2"; c.dwExtraInfoLength = 4; c.nPort = 80; n = 64;
    CHECK(U(InternetCreateUrlA)(&c, 0, o, &n));
    EXPECT_STR(o, "http://h/?a=1");
}
TEST(url_crack_create_crack_roundtrip) {
    /* crack -> create with the cracked port reproduces the URL */
    REQUIRE(U(InternetCreateUrlA)); REQUIRE(U(InternetCrackUrlA));
    static const char *v[] = { "http://user:pass@host.example:8080/p/q?x=1#y", "https://h/a", "ftp://u@f.example:2121/d/f.txt",
                               "http://h/", "https://h:8443/x", "gopher://g:70/1/x" };
    for (unsigned i = 0; i < sizeof v / sizeof *v; i++) {
        char s[32], h[64], us[32], pw[32], p[128], x[128], o[256]; DWORD n = sizeof o;
        URL_COMPONENTSA c; memset(&c, 0, sizeof c); c.dwStructSize = sizeof c;
        c.lpszScheme = s; c.dwSchemeLength = 32; c.lpszHostName = h; c.dwHostNameLength = 64;
        c.lpszUserName = us; c.dwUserNameLength = 32; c.lpszPassword = pw; c.dwPasswordLength = 32;
        c.lpszUrlPath = p; c.dwUrlPathLength = 128; c.lpszExtraInfo = x; c.dwExtraInfoLength = 128;
        char ub[256]; strcpy(ub, v[i]);
        CHECKF(U(InternetCrackUrlA)(ub, 0, 0, &c), "crack %s", v[i]);
        if (!us[0]) c.lpszUserName = NULL;
        if (!pw[0]) c.lpszPassword = NULL;
        c.dwSchemeLength = c.dwHostNameLength = c.dwUserNameLength = c.dwPasswordLength = c.dwUrlPathLength = c.dwExtraInfoLength = 0;
        CHECKF(U(InternetCreateUrlA)(&c, 0, o, &n), "create %s err %lu", v[i], GetLastError());
        CHECKF(!strcmp(o, v[i]), "roundtrip \"%s\" -> \"%s\"", v[i], o);
    }
}
