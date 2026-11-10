/* urlcache_entries / CreateUrlCacheEntryA/W/ExW: local file allocation in the content container.
 * Decomp: CreateUrlCacheEntryA@0xdca0, CreateUrlCacheEntryExW@0xd180 (CreateUrlCacheEntryW tail-calls it),
 * CreateUrlCacheEntryHelper@0xe1b4, CreateUniqueCacheFile@0xf9bc, _ProcessExtension@0xfd48,
 * _CreateFileWithSuffix@0x10530 ("<name>[%d].<ext>"). VM_TIMEOUT: 240 */
#include "uce.h"

UDECL(BOOL, CreateUrlCacheEntryExW, (LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, BOOL));

/* --------------------------------------------------------------- parameter validation */
TEST(uce_create_a_null_url) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char path[MAX_PATH]; strcpy(path, "untouched");
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryA)(NULL, 0, "txt", path, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
    EXPECT_STR(path, "untouched");       /* checked before anything is written [D] */
}
TEST(uce_create_a_null_filename) {
    REQUIRE(U(CreateUrlCacheEntryA));
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryA)(uce_url("cnf"), 0, "txt", NULL, 0);
    EXPECT_FAIL(!r, ERROR_INVALID_PARAMETER);
}
TEST(uce_create_a_both_null) {
    REQUIRE(U(CreateUrlCacheEntryA));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CreateUrlCacheEntryA)(NULL, 0, NULL, NULL, 0), ERROR_INVALID_PARAMETER);
}
TEST(uce_create_w_null_url) {
    REQUIRE(U(CreateUrlCacheEntryW));
    WCHAR path[MAX_PATH]; lstrcpyW(path, L"untouched");
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CreateUrlCacheEntryW)(NULL, 0, L"txt", path, 0), ERROR_INVALID_PARAMETER);
    EXPECT_WSTR(path, L"untouched");
}
TEST(uce_create_w_null_filename) {
    REQUIRE(U(CreateUrlCacheEntryW));
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CreateUrlCacheEntryW)(uce_w(uce_url("cwnf")), 0, L"txt", NULL, 0), ERROR_INVALID_PARAMETER);
}
TEST(uce_create_exw_null_args) {
    REQUIRE(UN(CreateUrlCacheEntryExW));
    WCHAR path[MAX_PATH];
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!UN(CreateUrlCacheEntryExW)(NULL, 0, L"txt", path, 0, FALSE), ERROR_INVALID_PARAMETER);
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!UN(CreateUrlCacheEntryExW)(uce_w(uce_url("exnull")), 0, L"txt", NULL, 0, FALSE), ERROR_INVALID_PARAMETER);
}

/* --------------------------------------------------------------- the created file */
TEST(uce_create_a_basic_file) {
    REQUIRE(U(CreateUrlCacheEntryA));
    const char *url = uce_url("cbasic");
    char path[MAX_PATH]; memset(path, 'X', sizeof path); path[MAX_PATH - 1] = 0;
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0);
    CHECK(r);
    EXPECT_ERR(0);                       /* SetLastError(WX_WIN32_FROM_HR(S_OK)) [D] */
    if (!r) return;
    t_note("created %s", path);
    CHECK(strlen(path) > 3 && strlen(path) < MAX_PATH);
    CHECK(path[1] == ':' && path[2] == '\\');                        /* absolute path */
    DWORD a = GetFileAttributesA(path);
    CHECK(a != INVALID_FILE_ATTRIBUTES);                             /* the file exists already [D handle created] */
    CHECK(!(a & FILE_ATTRIBUTE_DIRECTORY));
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fa)) { EXPECT_EQ(fa.nFileSizeLow, 0); EXPECT_EQ(fa.nFileSizeHigh, 0); }
    const char *dot = strrchr(path, '.');
    CHECK(dot && !_stricmp(dot, ".txt"));
    CHECK(strstr(path, "[1].txt") != NULL || strstr(path, "].txt") != NULL);   /* name[N].ext [D _CreateFileWithSuffix] */
    CHECK(strstr(path, "\\cbasic[") != NULL);                        /* base name comes from the URL file name */
    /* the caller can write it */
    CHECK(uce_write_file(path, "hello", 5));
    CHECK(!uce_exists(url));                                         /* no entry until commit */
    CHECK(DeleteFileA(path));
}
TEST(uce_create_w_basic_file) {
    REQUIRE(U(CreateUrlCacheEntryW));
    const char *url = uce_url("cwbasic");
    WCHAR path[MAX_PATH] = {0};
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryW)(uce_w(url), 0, L"htm", path, 0);
    CHECK(r); EXPECT_ERR(0);
    if (!r) return;
    t_note("created %s", uce_a(path));
    CHECK(uce_file_existsW(path));
    const WCHAR *dot = wcsrchr(path, L'.');
    CHECK(dot && !lstrcmpiW(dot, L".htm"));
    CHECK(wcsstr(path, L"\\cwbasic[") != NULL);
    CHECK(DeleteFileW(path));
}
TEST(uce_create_a_w_same_directory) {
    REQUIRE(U(CreateUrlCacheEntryA)); REQUIRE(U(CreateUrlCacheEntryW));
    char pa[MAX_PATH], da[MAX_PATH], dw[MAX_PATH]; WCHAR pw[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(uce_url("sdira"), 0, "txt", pa, 0));
    CHECK(U(CreateUrlCacheEntryW)(uce_w(uce_url("sdirw")), 0, L"txt", pw, 0));
    uce_dirname(pa, da); uce_dirname(uce_a(pw), dw);
    /* both in the same INetCache container (one of its 8-char subdirectories) */
    char *s1 = strrchr(da, '\\'); *s1 = 0; s1 = strrchr(da, '\\'); if (s1) s1[1] = 0;
    char *s2 = strrchr(dw, '\\'); *s2 = 0; s2 = strrchr(dw, '\\'); if (s2) s2[1] = 0;
    CHECKF(!_stricmp(da, dw), "%s vs %s", da, dw);
    t_note("container %s", da);
    DeleteFileA(pa); DeleteFileW(pw);
}
TEST(uce_create_path_in_inetcache) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char path[MAX_PATH];
    if (!U(CreateUrlCacheEntryA)(uce_url("inet"), 0, "txt", path, 0)) { CHECK(0); return; }
    char up[MAX_PATH]; strcpy(up, path); CharUpperA(up);
    /* Win10: %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\<8 chars>\name[1].ext [K] */
    CHECKF(strstr(up, "\\INETCACHE\\") != NULL, "%s", path);
    char la[MAX_PATH]; DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", la, sizeof la);
    if (n && n < sizeof la) { CharUpperA(la); CHECKF(!strncmp(up, la, strlen(la)), "%s not under %s", path, la); }
    /* the parent directory name is 8 characters (container subdirectory) */
    char d[MAX_PATH]; uce_dirname(path, d); d[strlen(d) - 1] = 0;
    const char *leaf = strrchr(d, '\\');
    CHECKF(leaf && strlen(leaf + 1) == 8, "subdir %s", leaf ? leaf + 1 : "(none)");
    DeleteFileA(path);
}
TEST(uce_create_unique_paths) {
    REQUIRE(U(CreateUrlCacheEntryA));
    const char *url = uce_url("uniq");
    char p[6][MAX_PATH]; int ok = 0;
    for (int i = 0; i < 6; i++) { p[i][0] = 0; ok += U(CreateUrlCacheEntryA)(url, 0, "txt", p[i], 0) ? 1 : 0; }
    EXPECT_EQ(ok, 6);
    for (int i = 0; i < 6; i++) for (int j = i + 1; j < 6; j++) CHECKF(_stricmp(p[i], p[j]) != 0, "%d==%d %s", i, j, p[i]);
    for (int i = 0; i < 6; i++) { CHECK(uce_file_exists(p[i])); t_note("unique[%d] %s", i, p[i]); }
    for (int i = 0; i < 6; i++) DeleteFileA(p[i]);
}
TEST(uce_create_suffix_increments) {
    REQUIRE(U(CreateUrlCacheEntryA));
    /* two creates landing in the same subdirectory get [1] then [2]; directories rotate, so only note */
    const char *url = uce_url("sfx");
    char a[MAX_PATH], b[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", a, 0));
    CHECK(U(CreateUrlCacheEntryA)(url, 0, "txt", b, 0));
    char da[MAX_PATH], db[MAX_PATH]; uce_dirname(a, da); uce_dirname(b, db);
    if (!_stricmp(da, db)) { CHECK(strstr(a, "sfx[1].txt") != NULL); CHECK(strstr(b, "sfx[2].txt") != NULL); }
    else { CHECK(strstr(a, "sfx[1].txt") != NULL); t_note("second create used another directory: %s", b); }
    DeleteFileA(a); DeleteFileA(b);
}
TEST(uce_create_large_expected_size) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char path[MAX_PATH];
    /* > 0x1000 only pre-allocates (SetFileInformationByHandle FileAllocationInfo) [D]; logical size stays 0 */
    BOOL r = U(CreateUrlCacheEntryA)(uce_url("big"), 1u << 20, "bin", path, 0);
    CHECK(r);
    if (!r) return;
    WIN32_FILE_ATTRIBUTE_DATA fa;
    CHECK(GetFileAttributesExA(path, GetFileExInfoStandard, &fa));
    EXPECT_EQ(fa.nFileSizeLow, 0);
    DeleteFileA(path);
}
TEST(uce_create_reserved_ignored) {
    REQUIRE(U(CreateUrlCacheEntryA)); REQUIRE(U(CreateUrlCacheEntryW));
    /* dwReserved is never read by either entry point [D] */
    char pa[MAX_PATH]; WCHAR pw[MAX_PATH];
    SET_ERR(0xdeadbeef);
    CHECK(U(CreateUrlCacheEntryA)(uce_url("resa"), 0, "txt", pa, 0x12345678)); EXPECT_ERR(0);
    SET_ERR(0xdeadbeef);
    CHECK(U(CreateUrlCacheEntryW)(uce_w(uce_url("resw")), 0, L"txt", pw, 0xFFFFFFFF)); EXPECT_ERR(0);
    DeleteFileA(pa); DeleteFileW(pw);
}

/* --------------------------------------------------------------- extensions (table driven) */
static const struct { const char *ext; const char *suffix; } g_ext[] = {
    { "txt", ".txt" }, { "htm", ".htm" }, { "html", ".html" }, { "gif", ".gif" }, { "js", ".js" }, { "css", ".css" },
    { "jpeg", ".jpeg" }, { "json", ".json" }, { "x", ".x" }, { "TXT", ".TXT" }, { "a1b2", ".a1b2" },
    { "longextension", ".longextension" }, { "tar.gz", ".tar.gz" },
};
TEST(uce_create_ext_table_a) {
    REQUIRE(U(CreateUrlCacheEntryA));
    for (size_t i = 0; i < sizeof g_ext / sizeof *g_ext; i++) {
        char path[MAX_PATH] = "";
        BOOL r = U(CreateUrlCacheEntryA)(uce_url("exta"), 0, g_ext[i].ext, path, 0);
        CHECKF(r, "ext %s err %lu", g_ext[i].ext, GetLastError());
        if (!r) continue;
        size_t lp = strlen(path), ls = strlen(g_ext[i].suffix);
        CHECKF(lp > ls && !strcmp(path + lp - ls, g_ext[i].suffix), "ext %s -> %s", g_ext[i].ext, path);
        CHECKF(lp > ls + 1 && path[lp - ls - 1] == ']', "%s", path);
        DeleteFileA(path);
    }
}
TEST(uce_create_ext_table_w) {
    REQUIRE(U(CreateUrlCacheEntryW));
    for (size_t i = 0; i < sizeof g_ext / sizeof *g_ext; i++) {
        WCHAR path[MAX_PATH] = {0};
        BOOL r = U(CreateUrlCacheEntryW)(uce_w(uce_url("extw")), 0, uce_w(g_ext[i].ext), path, 0);
        CHECKF(r, "ext %s err %lu", g_ext[i].ext, GetLastError());
        if (!r) continue;
        const char *pa = uce_a(path);
        size_t lp = strlen(pa), ls = strlen(g_ext[i].suffix);
        CHECKF(lp > ls && !strcmp(pa + lp - ls, g_ext[i].suffix), "ext %s -> %s", g_ext[i].ext, pa);
        DeleteFileW(path);
    }
}
/* characters that cannot appear in a file name are replaced by '_' [D _ProcessExtension: <>\"/:|?* and < 0x20 and ' '] */
static const struct { const char *ext; const char *suffix; } g_ext_bad[] = {
    { "a<b", ".a_b" }, { "a>b", ".a_b" }, { "a\"b", ".a_b" }, { "a|b", ".a_b" }, { "a?b", ".a_b" }, { "a*b", ".a_b" },
    { "a:b", ".a_b" }, { "a/b", ".a_b" }, { "a\\b", ".a_b" }, { "a b", ".a_b" }, { "a\tb", ".a_b" },
    { "  pad  ", ".pad" },
};
TEST(uce_create_ext_sanitized) {
    REQUIRE(U(CreateUrlCacheEntryA));
    for (size_t i = 0; i < sizeof g_ext_bad / sizeof *g_ext_bad; i++) {
        char path[MAX_PATH] = "";
        BOOL r = U(CreateUrlCacheEntryA)(uce_url("exts"), 0, g_ext_bad[i].ext, path, 0);
        CHECKF(r, "ext [%s] err %lu", g_ext_bad[i].ext, GetLastError());
        if (!r) continue;
        size_t lp = strlen(path), ls = strlen(g_ext_bad[i].suffix);
        CHECKF(lp > ls && !strcmp(path + lp - ls, g_ext_bad[i].suffix), "ext [%s] -> %s", g_ext_bad[i].ext, path);
        DeleteFileA(path);
    }
}
TEST(uce_create_ext_percent_decoded) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char path[MAX_PATH] = "";
    /* _DecodePercentEncodedString on the extension [D] */
    BOOL r = U(CreateUrlCacheEntryA)(uce_url("extpct"), 0, "t%78t", path, 0);
    CHECK(r);
    if (r) { t_note("t%%78t -> %s", path); CHECK(strlen(path) > 4 && !strcmp(path + strlen(path) - 4, ".txt")); DeleteFileA(path); }
}
TEST(uce_create_ext_null_and_empty) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char p1[MAX_PATH] = "", p2[MAX_PATH] = "";
    CHECK(U(CreateUrlCacheEntryA)(uce_url("extnull"), 0, NULL, p1, 0));
    CHECK(U(CreateUrlCacheEntryA)(uce_url("extempty"), 0, "", p2, 0));
    t_note("NULL ext -> %s", p1); t_note("\"\" ext -> %s", p2);
    /* no extension: the name ends in "[N]" [D _CreateFileWithSuffix "[%d]"] */
    CHECKF(p1[0] && p1[strlen(p1) - 1] == ']', "%s", p1);
    CHECKF(p2[0] && p2[strlen(p2) - 1] == ']', "%s", p2);
    DeleteFileA(p1); DeleteFileA(p2);
}
TEST(uce_create_ext_leading_dot) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char path[MAX_PATH] = "";
    BOOL r = U(CreateUrlCacheEntryA)(uce_url("extdot"), 0, ".txt", path, 0);
    CHECK(r);
    if (r) { t_note(".txt -> %s", path); CHECK(strstr(path, ".txt") != NULL); DeleteFileA(path); }
}
TEST(uce_create_ext_too_long_w) {
    REQUIRE(U(CreateUrlCacheEntryW));
    /* CreateUniqueCacheFile: extension of >= 260 characters -> E_INVALIDARG [D] */
    WCHAR ext[300]; for (int i = 0; i < 299; i++) ext[i] = L'e'; ext[299] = 0;
    WCHAR path[MAX_PATH];
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(CreateUrlCacheEntryW)(uce_w(uce_url("extlong")), 0, ext, path, 0), ERROR_INVALID_PARAMETER);
}
TEST(uce_create_ext_too_long_a) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char ext[300]; memset(ext, 'e', 299); ext[299] = 0;
    char path[MAX_PATH];
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryA)(uce_url("extlonga"), 0, ext, path, 0);
    DWORD e = GetLastError();
    CHECK(!r);
    t_note("A ext 299 chars: r=%d err=%lu", r, e);
    CHECK(e != 0);
    if (r) DeleteFileA(path);
}

/* --------------------------------------------------------------- base names derived from the URL */
static const struct { const char *path; const char *stem; } g_names[] = {
    { "/dir/page.html", "page" }, { "/a/b/c/leaf.txt", "leaf" }, { "/noext", "noext" }, { "/x.y.z", "x.y" },
    { "/q.txt?a=1&b=2", "q" }, { "/f.txt#frag", "f" },
};
TEST(uce_create_name_from_url) {
    REQUIRE(U(CreateUrlCacheEntryA));
    for (size_t i = 0; i < sizeof g_names / sizeof *g_names; i++) {
        char url[512]; snprintf(url, sizeof url, "http://%s%s", t_uniq_host("nm"), g_names[i].path);
        char path[MAX_PATH] = "";
        BOOL r = U(CreateUrlCacheEntryA)(url, 0, "dat", path, 0);
        CHECKF(r, "%s err %lu", url, GetLastError());
        if (!r) continue;
        const char *leaf = strrchr(path, '\\'); leaf = leaf ? leaf + 1 : path;
        t_note("%s -> %s", g_names[i].path, leaf);
        char want[128]; snprintf(want, sizeof want, "%s[", g_names[i].stem);
        CHECKF(!_strnicmp(leaf, want, strlen(want)), "%s -> %s (want %s...)", g_names[i].path, leaf, want);
        CHECK(strlen(leaf) > 4 && !strcmp(leaf + strlen(leaf) - 4, ".dat"));
        DeleteFileA(path);
    }
}
TEST(uce_create_name_root_url) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char url[300]; snprintf(url, sizeof url, "http://%s/", t_uniq_host("root"));
    char path[MAX_PATH] = "";
    BOOL r = U(CreateUrlCacheEntryA)(url, 0, "htm", path, 0);
    CHECK(r);
    if (r) { t_note("root url -> %s", path); CHECK(uce_file_exists(path)); CHECK(strstr(path, ".htm") != NULL); DeleteFileA(path); }
}
TEST(uce_create_name_cookie_url_random) {
    REQUIRE(U(CreateUrlCacheEntryA));
    /* "Cookie:" URLs get a random file name [D CreateUniqueCacheFile _wcsnicmp(url, L"Cookie:", 7)] */
    char url[300]; snprintf(url, sizeof url, "Cookie:%s@%s/", t_uniq("u"), t_uniq_host("ck"));
    char path[MAX_PATH] = "";
    BOOL r = U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0);
    t_note("cookie url create r=%d err=%lu path=%s", r, r ? 0 : GetLastError(), path);
    if (r) { CHECK(uce_file_exists(path)); DeleteFileA(path); }
}
TEST(uce_create_name_non_http_scheme) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char url[300]; snprintf(url, sizeof url, "ftp://%s/pub/file.bin", t_uniq_host("ftp"));
    char path[MAX_PATH] = "";
    BOOL r = U(CreateUrlCacheEntryA)(url, 0, "bin", path, 0);
    CHECK(r);
    if (r) { t_note("ftp url -> %s", path); CHECK(strstr(path, "file[") != NULL); DeleteFileA(path); }
}

/* --------------------------------------------------------------- invalid URLs */
TEST(uce_create_invalid_http_urls) {
    REQUIRE(U(CreateUrlCacheEntryA));
    /* http(s) keys are parsed (ConvertCacheHttpUrlWCharToInternal): missing "//", empty host, bad port ->
       ERROR_INTERNET_INVALID_URL (0x2ee5) [D] */
    static const char *bad[] = { "http:noslashes", "http:/one", "http://", "http:///path", "https://", "http://host:99999/x",
                                 "http://host:12ab/x", "http://[::1/x" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        char path[MAX_PATH]; strcpy(path, "keep");
        SET_ERR(0xdeadbeef);
        BOOL r = U(CreateUrlCacheEntryA)(bad[i], 0, "txt", path, 0);
        DWORD e = GetLastError();
        CHECKF(!r, "%s accepted -> %s", bad[i], path);
        CHECKF(e == ERROR_INTERNET_INVALID_URL, "%s err %lu", bad[i], e);
        CHECKF(!strcmp(path, "keep"), "%s path written: %s", bad[i], path);   /* *path = 0 only after the key converts [D] */
        if (r) DeleteFileA(path);
    }
}
TEST(uce_create_invalid_http_urls_w) {
    REQUIRE(U(CreateUrlCacheEntryW));
    static const WCHAR *bad[] = { L"http:noslashes", L"http://", L"https:///x", L"http://h:70000/" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        WCHAR path[MAX_PATH];
        SET_ERR(0xdeadbeef);
        BOOL r = U(CreateUrlCacheEntryW)(bad[i], 0, L"txt", path, 0);
        DWORD e = GetLastError();
        CHECKF(!r && e == ERROR_INTERNET_INVALID_URL, "%s r=%d err %lu", uce_a(bad[i]), r, e);
        if (r) DeleteFileW(path);
    }
}
TEST(uce_create_empty_url) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char path[MAX_PATH]; strcpy(path, "keep");
    SET_ERR(0xdeadbeef);
    BOOL r = U(CreateUrlCacheEntryA)("", 0, "txt", path, 0);
    DWORD e = GetLastError();
    t_note("empty url: r=%d err=%lu path=%s", r, e, path);
    if (r) DeleteFileA(path);
}
TEST(uce_create_unknown_scheme_ok) {
    REQUIRE(U(CreateUrlCacheEntryA));
    /* keys that are not http/https/cookie are taken verbatim [D ConvertCacheUrlCharToInternal] */
    char url[300]; snprintf(url, sizeof url, "i7test:%s/opaque", t_uniq("os"));
    char path[MAX_PATH] = "";
    BOOL r = U(CreateUrlCacheEntryA)(url, 0, "txt", path, 0);
    t_note("opaque scheme create r=%d err=%lu path=%s", r, r ? 0 : GetLastError(), path);
    if (r) DeleteFileA(path);
}

/* --------------------------------------------------------------- CreateUrlCacheEntryExW */
TEST(uce_create_exw_matches_w) {
    REQUIRE(UN(CreateUrlCacheEntryExW));
    WCHAR path[MAX_PATH] = {0};
    SET_ERR(0xdeadbeef);
    BOOL r = UN(CreateUrlCacheEntryExW)(uce_w(uce_url("exw")), 0, L"txt", path, 0, FALSE);
    CHECK(r); EXPECT_ERR(0);
    if (r) { CHECK(wcsstr(path, L"\\exw[") != NULL); CHECK(uce_file_existsW(path)); DeleteFileW(path); }
}
TEST(uce_create_exw_filename_hint) {
    REQUIRE(UN(CreateUrlCacheEntryExW));
    /* fPreserveIncomingFileName: the incoming buffer is the requested file name [D: param_6 != 0 passes lpszFileName] */
    WCHAR path[MAX_PATH]; lstrcpyW(path, L"hinted.dat");
    BOOL r = UN(CreateUrlCacheEntryExW)(uce_w(uce_url("exhint")), 0, L"txt", path, 0, TRUE);
    DWORD e = GetLastError();
    t_note("ExW preserve: r=%d err=%lu path=%s", r, e, uce_a(path));
    if (r) { CHECK(wcsstr(path, L"hinted") != NULL); DeleteFileW(path); }
}

/* --------------------------------------------------------------- create without commit leaves no entry */
TEST(uce_create_without_commit_no_entry) {
    REQUIRE(U(CreateUrlCacheEntryA)); REQUIRE(U(GetUrlCacheEntryInfoA));
    const char *url = uce_url("nocommit");
    char path[MAX_PATH];
    CHECK(U(CreateUrlCacheEntryA)(url, 100, "txt", path, 0));
    DWORD sz = 0;
    SET_ERR(0xdeadbeef);
    EXPECT_FAIL(!U(GetUrlCacheEntryInfoA)(url, NULL, &sz), ERROR_FILE_NOT_FOUND);
    DeleteFileA(path);
}
TEST(uce_create_many_distinct_urls) {
    REQUIRE(U(CreateUrlCacheEntryA));
    char p[24][MAX_PATH]; int ok = 0;
    for (int i = 0; i < 24; i++) { char tag[16]; snprintf(tag, sizeof tag, "many%d", i); ok += U(CreateUrlCacheEntryA)(uce_url(tag), 0, "txt", p[i], 0) ? 1 : 0; }
    EXPECT_EQ(ok, 24);
    for (int i = 0; i < 24; i++) { char want[24]; snprintf(want, sizeof want, "\\many%d[", i); CHECKF(strstr(p[i], want) != NULL, "%s", p[i]); }
    for (int i = 0; i < 24; i++) DeleteFileA(p[i]);
}
